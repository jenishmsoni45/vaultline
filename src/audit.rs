//! The audit log: records, the head, appending, verifying and anchors
//! (`docs/vault-format.md` §5, `docs/design.md` §9, D-015, D-016, D-030,
//! D-034, D-047, D-053).
//!
//! - **Records** are 105 bytes each with no length fields. Record `i` holds the
//!   SHA-256 of record `i - 1` (of the file header for `i = 0`) and an
//!   HMAC-SHA-256 under the audit key, so any edit, deletion or reordering
//!   breaks the chain or a MAC.
//! - **The head** (`audit.head`) holds how many records exist and the hash of
//!   the last one, MAC'd under the audit key. It catches truncation. An anchor
//!   saved outside the vault directory (`count:hash`) catches a rollback of
//!   the log and the head together.
//! - **Appending** happens under the writer lock. Every record is written and
//!   flushed, then the head is replaced, before the next record is written, so
//!   after a crash the log is at most one record ahead of the head (D-053).
//!   Before it writes anything, an append checks the tail of the log and the
//!   head, and refuses to go on if they disagree (D-047). Without that check
//!   the next command would hide a truncation by appending to the short log
//!   and replacing the head.
//! - **The failed-unlock counter** (`unlock-failures`) is eight unauthenticated
//!   bytes, because no key exists before an unlock succeeds.
//!
//! Records never hold secret values, names or passphrases (D-016). This is a
//! parser module: it reads files an attacker may have edited, so it never
//! unwraps, indexes or does unchecked arithmetic on what it reads.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::fmt;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use nix::errno::Errno;
use nix::fcntl::OFlag;

use crate::paths::{self, FILE_MODE, PathError};
use crate::secret::Key;
use crate::vault::crypto::{self, ID_LEN, MAC_LEN};
use crate::vault::{self, store, store::WriterLock};

/// The log's file name inside the vault directory.
pub const LOG_FILE: &str = "audit.log";
/// The head's file name.
pub const HEAD_FILE: &str = "audit.head";
/// The failed-unlock counter's file name.
pub const COUNTER_FILE: &str = "unlock-failures";
/// Prefix of the temporary files used to replace the head and the counter.
pub const TMP_PREFIX: &str = ".audit.head.tmp-";

/// Bytes in the log's file header (`vault-format.md` §5.1).
pub const HEADER_LEN: usize = 26;
/// Bytes in one record (§5.2).
pub const RECORD_LEN: usize = 105;
/// Bytes in the head file (§5.4).
pub const HEAD_LEN: usize = 98;
/// What `audit_version` is, in the log header and the head.
pub const AUDIT_VERSION: u16 = 1;
/// What the counter holds when it can't be read (§5.3, event 5).
pub const COUNTER_UNREADABLE: u64 = u64::MAX;

const HEADER_LEN_U64: u64 = 26;
const RECORD_LEN_U64: u64 = 105;
/// The part of a record that its MAC covers: everything before the MAC.
const RECORD_SIGNED_LEN: usize = 73;
/// The part of the head that its MAC covers.
const HEAD_SIGNED_LEN: usize = 66;

const LOG_MAGIC: [u8; 8] = *b"vlaudit\0";
const HEAD_MAGIC: [u8; 8] = *b"vlahead\0";
const LABEL_RECORD: &[u8] = b"vaultline v1 audit-record";
const LABEL_HEAD: &[u8] = b"vaultline v1 audit-head";
const NO_ITEM: [u8; ID_LEN] = [0; ID_LEN];

const HINT: &str = "run `vaultline audit verify` to see what is wrong";

/// What went wrong. No variant carries a secret.
#[derive(Debug)]
#[non_exhaustive]
pub enum AuditError {
    /// The log or the head isn't there. Other commands never recreate them.
    Missing(&'static str),
    /// The log or the head fails one of the checks that come before an append.
    Damaged(String),
    /// An anchor that isn't `<count>:<64 lowercase hex digits>`.
    BadAnchor,
    /// Another writer held the lock for more than 10 seconds.
    Busy,
    /// The directory or one of the files fails the ownership, mode or symlink
    /// checks.
    Path(PathError),
    /// An I/O error.
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    /// The MAC machinery failed.
    Crypto,
    /// A change was made, but the record of it couldn't be written.
    Recording(Box<AuditError>),
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditError::Missing(what) => write!(f, "the {what} is missing; {HINT}"),
            AuditError::Damaged(why) => write!(f, "the audit log is damaged: {why}; {HINT}"),
            AuditError::BadAnchor => f.write_str(
                "an anchor looks like COUNT:HASH, a number, a colon and 64 lowercase hex digits \
                 (`vaultline audit head` prints one)",
            ),
            AuditError::Busy => f.write_str("another vaultline is writing; try again in a moment"),
            AuditError::Path(e) => e.fmt(f),
            AuditError::Io {
                action,
                path,
                source,
            } => write!(f, "couldn't {action} {}: {source}", path.display()),
            AuditError::Crypto => f.write_str("the audit MAC could not be computed"),
            AuditError::Recording(why) => write!(
                f,
                "the change was made, but its audit record could not be written: {why}"
            ),
        }
    }
}

impl std::error::Error for AuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AuditError::Path(e) => Some(e),
            AuditError::Io { source, .. } => Some(source),
            AuditError::Recording(why) => Some(&**why),
            _ => None,
        }
    }
}

impl From<PathError> for AuditError {
    fn from(e: PathError) -> Self {
        AuditError::Path(e)
    }
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> AuditError {
    if source.raw_os_error() == Some(Errno::ELOOP as i32) {
        return AuditError::Path(PathError::Symlink(path.to_path_buf()));
    }
    AuditError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

/// The writer lock, with its errors in this module's terms.
pub fn lock(dir: &Path) -> Result<WriterLock, AuditError> {
    store::lock(dir).map_err(|e| match e {
        vault::Error::Busy => AuditError::Busy,
        vault::Error::Path(p) => AuditError::Path(p),
        vault::Error::Io {
            action,
            path,
            source,
        } => AuditError::Io {
            action,
            path,
            source,
        },
        other => AuditError::Io {
            action: "take the writer lock in",
            path: dir.to_path_buf(),
            source: io::Error::other(other.to_string()),
        },
    })
}

/// Seconds since the Unix epoch, or 0 if the clock is before it. Timestamps
/// are for information only (§5.2).
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What happened (§5.3). The numbers are the codes in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Init = 1,
    Unlock = 2,
    Lock = 3,
    IdleTimeout = 4,
    FailedUnlocks = 5,
    Read = 6,
    Set = 7,
    Rm = 8,
    Passwd = 9,
    Rotate = 10,
    Verify = 11,
}

impl Event {
    /// The event for a code, or `None` for a code audit format 1 doesn't have.
    pub fn from_code(code: u8) -> Option<Event> {
        Some(match code {
            1 => Event::Init,
            2 => Event::Unlock,
            3 => Event::Lock,
            4 => Event::IdleTimeout,
            5 => Event::FailedUnlocks,
            6 => Event::Read,
            7 => Event::Set,
            8 => Event::Rm,
            9 => Event::Passwd,
            10 => Event::Rotate,
            11 => Event::Verify,
            _ => return None,
        })
    }

    /// The code written to the file.
    pub fn code(self) -> u8 {
        self as u8
    }
}

/// `detail` of an `unlock` record: unlocked inside a command (§5.3).
pub const UNLOCK_BY_COMMAND: u64 = 0;
/// `detail` of an `unlock` record: unlocked by the agent.
pub const UNLOCK_BY_AGENT: u64 = 1;
/// `detail` of a `lock` record: `vaultline lock`.
pub const LOCK_BY_COMMAND: u64 = 0;
/// `detail` of a `lock` record: the agent stopped.
pub const LOCK_BY_STOP: u64 = 1;

/// What to append: an event, the item it concerns, and its detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub event: Event,
    pub item_id: [u8; ID_LEN],
    pub detail: u64,
}

impl Entry {
    /// An entry that concerns no item.
    pub fn new(event: Event, detail: u64) -> Entry {
        Entry {
            event,
            item_id: NO_ITEM,
            detail,
        }
    }

    /// An entry that concerns one item.
    pub fn for_item(event: Event, item_id: [u8; ID_LEN], detail: u64) -> Entry {
        Entry {
            event,
            item_id,
            detail,
        }
    }
}

/// One record as it is in the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub seq: u64,
    pub time: u64,
    pub event: Event,
    pub item_id: [u8; ID_LEN],
    pub detail: u64,
    pub prev_hash: [u8; MAC_LEN],
    pub mac: [u8; MAC_LEN],
}

/// `N` bytes at `at`, or `None` if the slice is too short.
fn field<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    let end = at.checked_add(N)?;
    bytes.get(at..end)?.try_into().ok()
}

impl Record {
    /// A record, signed under `key`.
    fn sign(
        key: &Key,
        seq: u64,
        time: u64,
        entry: Entry,
        prev_hash: [u8; MAC_LEN],
    ) -> Result<Record, AuditError> {
        let mut record = Record {
            seq,
            time,
            event: entry.event,
            item_id: entry.item_id,
            detail: entry.detail,
            prev_hash,
            mac: [0; MAC_LEN],
        };
        let signed = record.signed_bytes();
        record.mac =
            crypto::hmac_sha256(key, &[LABEL_RECORD, &signed]).map_err(|_| AuditError::Crypto)?;
        Ok(record)
    }

    /// The first 73 bytes: everything the MAC covers.
    fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECORD_LEN);
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.time.to_le_bytes());
        out.push(self.event.code());
        out.extend_from_slice(&self.item_id);
        out.extend_from_slice(&self.detail.to_le_bytes());
        out.extend_from_slice(&self.prev_hash);
        out
    }

    /// All 105 bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.signed_bytes();
        out.extend_from_slice(&self.mac);
        out
    }

    /// Parses exactly one record. The only things checked here are the length
    /// and that the event is one audit format 1 has; the chain and the MAC are
    /// checked by the caller.
    pub fn decode(bytes: &[u8]) -> Result<Record, &'static str> {
        if bytes.len() != RECORD_LEN {
            return Err("it is not 105 bytes long");
        }
        let (Some(seq), Some(time), Some(code), Some(item_id), Some(detail), Some(prev), Some(mac)) = (
            field::<8>(bytes, 0),
            field::<8>(bytes, 8),
            field::<1>(bytes, 16),
            field::<ID_LEN>(bytes, 17),
            field::<8>(bytes, 33),
            field::<MAC_LEN>(bytes, 41),
            field::<MAC_LEN>(bytes, RECORD_SIGNED_LEN),
        ) else {
            return Err("it is cut short");
        };
        let [code] = code;
        let Some(event) = Event::from_code(code) else {
            return Err("it has an event code that audit format 1 doesn't have");
        };
        Ok(Record {
            seq: u64::from_le_bytes(seq),
            time: u64::from_le_bytes(time),
            event,
            item_id,
            detail: u64::from_le_bytes(detail),
            prev_hash: prev,
            mac,
        })
    }

    /// Whether the MAC verifies under `key`, in constant time.
    fn mac_ok(&self, key: &Key) -> bool {
        let signed = self.signed_bytes();
        crypto::verify_hmac_sha256(key, &[LABEL_RECORD, &signed], &self.mac).is_ok()
    }

    /// SHA-256 of the whole record: the next record's `prev_hash`.
    pub fn hash(&self) -> [u8; MAC_LEN] {
        crypto::sha256(&[&self.encode()])
    }
}

/// The head: how many records the log has, and the hash of the last one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub vault_id: [u8; ID_LEN],
    pub count: u64,
    pub last_hash: [u8; MAC_LEN],
    pub mac: [u8; MAC_LEN],
}

impl Head {
    fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEAD_LEN);
        out.extend_from_slice(&HEAD_MAGIC);
        out.extend_from_slice(&AUDIT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.count.to_le_bytes());
        out.extend_from_slice(&self.last_hash);
        out
    }

    fn sign(
        key: &Key,
        vault_id: [u8; ID_LEN],
        count: u64,
        last_hash: [u8; MAC_LEN],
    ) -> Result<Head, AuditError> {
        let mut head = Head {
            vault_id,
            count,
            last_hash,
            mac: [0; MAC_LEN],
        };
        let signed = head.signed_bytes();
        head.mac =
            crypto::hmac_sha256(key, &[LABEL_HEAD, &signed]).map_err(|_| AuditError::Crypto)?;
        Ok(head)
    }

    /// All 98 bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.signed_bytes();
        out.extend_from_slice(&self.mac);
        out
    }

    /// Parses the head and checks its magic, version, `vault_id` and MAC
    /// (§5.6 check 4).
    pub fn decode(bytes: &[u8], key: &Key, vault_id: &[u8; ID_LEN]) -> Result<Head, &'static str> {
        if bytes.len() != HEAD_LEN {
            return Err("the head is not 98 bytes long");
        }
        let (Some(magic), Some(version), Some(id), Some(count), Some(last_hash), Some(mac)) = (
            field::<8>(bytes, 0),
            field::<2>(bytes, 8),
            field::<ID_LEN>(bytes, 10),
            field::<8>(bytes, 26),
            field::<MAC_LEN>(bytes, 34),
            field::<MAC_LEN>(bytes, HEAD_SIGNED_LEN),
        ) else {
            return Err("the head is cut short");
        };
        if magic != HEAD_MAGIC {
            return Err("the head's magic bytes are wrong");
        }
        if u16::from_le_bytes(version) != AUDIT_VERSION {
            return Err("the head has an unsupported audit version");
        }
        if id != *vault_id {
            return Err("the head belongs to a different vault");
        }
        let head = Head {
            vault_id: id,
            count: u64::from_le_bytes(count),
            last_hash,
            mac,
        };
        let signed = head.signed_bytes();
        crypto::verify_hmac_sha256(key, &[LABEL_HEAD, &signed], &head.mac)
            .map_err(|_| "the head's MAC is wrong")?;
        Ok(head)
    }

    /// The anchor for this head.
    pub fn anchor(&self) -> Anchor {
        Anchor {
            count: self.count,
            hash: self.last_hash,
        }
    }
}

/// `<count>:<hash in lowercase hex>`: what `audit head` prints and
/// `audit verify --expect` checks (§5.4, D-015).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    pub count: u64,
    pub hash: [u8; MAC_LEN],
}

impl fmt::Display for Anchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.count)?;
        self.hash.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl Anchor {
    /// Parses `<count>:<64 lowercase hex digits>`. Anything else is
    /// [`AuditError::BadAnchor`]; there is no leniency, so a mistyped anchor
    /// can't be mistaken for a different one.
    pub fn parse(text: &str) -> Result<Anchor, AuditError> {
        let (count, hex) = text.split_once(':').ok_or(AuditError::BadAnchor)?;
        let digits = !count.is_empty() && count.bytes().all(|b| b.is_ascii_digit());
        if !digits || hex.len() != MAC_LEN.saturating_mul(2) {
            return Err(AuditError::BadAnchor);
        }
        let count = count.parse::<u64>().map_err(|_| AuditError::BadAnchor)?;
        let mut hash = [0u8; MAC_LEN];
        for (slot, pair) in hash.iter_mut().zip(hex.as_bytes().chunks(2)) {
            let lowercase = pair
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b));
            if !lowercase {
                return Err(AuditError::BadAnchor);
            }
            let pair = std::str::from_utf8(pair).map_err(|_| AuditError::BadAnchor)?;
            *slot = u8::from_str_radix(pair, 16).map_err(|_| AuditError::BadAnchor)?;
        }
        Ok(Anchor { count, hash })
    }
}

/// The outcome of `audit verify`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// Every check of §5.6 passed.
    pub passed: bool,
    /// One line: what was checked, or the first check that failed.
    pub report: String,
}

impl Verdict {
    fn failed(report: impl Into<String>) -> Verdict {
        Verdict {
            passed: false,
            report: report.into(),
        }
    }
}

/// Opens a file of the vault directory without following a symlink, and checks
/// it through its own descriptor (D-041).
fn open_file(dir: &Path, name: &str, what: &'static str, write: bool) -> Result<File, AuditError> {
    let path = dir.join(name);
    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(OFlag::O_NOFOLLOW.bits())
        .open(&path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                AuditError::Missing(what)
            } else {
                io_error("open", &path, e)
            }
        })?;
    let meta = file.metadata().map_err(|e| io_error("inspect", &path, e))?;
    paths::check_file(&path, &meta)?;
    Ok(file)
}

/// Fills `buf` from `offset`.
fn read_at(file: &mut File, offset: u64, buf: &mut [u8], path: &Path) -> Result<(), AuditError> {
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.read_exact(buf))
        .map_err(|e| io_error("read", path, e))
}

/// Where record `index` starts.
fn record_offset(index: u64) -> Option<u64> {
    index
        .checked_mul(RECORD_LEN_U64)?
        .checked_add(HEADER_LEN_U64)
}

/// A name for a new temporary file next to the file it replaces.
fn temp_name() -> Result<String, AuditError> {
    let suffix: [u8; 8] = crypto::random_array().map_err(|_| AuditError::Crypto)?;
    let hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{TMP_PREFIX}{hex}"))
}

/// Removes temporary files a crashed writer left behind. Best effort.
fn remove_stale_temps(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry
            .file_name()
            .as_encoded_bytes()
            .starts_with(TMP_PREFIX.as_bytes())
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Replaces `dir/name` with `bytes` atomically: a new file with mode 0600, in
/// the same directory, flushed and renamed over the old one. Needs the writer
/// lock.
fn replace_file(
    dir: &Path,
    _lock: &WriterLock,
    name: &str,
    bytes: &[u8],
) -> Result<(), AuditError> {
    remove_stale_temps(dir);
    let tmp = dir.join(temp_name()?);
    let target = dir.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .custom_flags(OFlag::O_NOFOLLOW.bits())
        .open(&tmp)
        .map_err(|e| io_error("create", &tmp, e))?;
    let written = file
        .set_permissions(Permissions::from_mode(FILE_MODE))
        .and_then(|()| file.write_all(bytes))
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(io_error("write", &tmp, e));
    }
    if let Err(e) = fs::rename(&tmp, &target) {
        let _ = fs::remove_file(&tmp);
        return Err(io_error("replace", &target, e));
    }
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| io_error("flush", dir, e))
}

/// What the log looks like at its end: how many records, and the hash the next
/// record must carry as `prev_hash`.
struct Tail {
    count: u64,
    header_hash: [u8; MAC_LEN],
    last_hash: [u8; MAC_LEN],
}

/// A handle on one vault's audit log. It holds the audit key by reference, so
/// the key is wiped when its owner is.
pub struct Audit<'a> {
    dir: &'a Path,
    vault_id: [u8; ID_LEN],
    key: &'a Key,
}

impl<'a> Audit<'a> {
    pub fn new(dir: &'a Path, vault_id: [u8; ID_LEN], key: &'a Key) -> Audit<'a> {
        Audit { dir, vault_id, key }
    }

    fn log_path(&self) -> PathBuf {
        self.dir.join(LOG_FILE)
    }

    /// Creates the log, with one `init` record, and its head. Called by
    /// `Vault::create` under the writer lock it already holds. If a log is
    /// already there it belongs to an `init` that crashed before the vault was
    /// written, and it is replaced.
    pub fn create(&self, lock: &WriterLock) -> Result<(), AuditError> {
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(&LOG_MAGIC);
        header.extend_from_slice(&AUDIT_VERSION.to_le_bytes());
        header.extend_from_slice(&self.vault_id);
        let header_hash = crypto::sha256(&[&header]);
        let first = Record::sign(self.key, 0, now(), Entry::new(Event::Init, 0), header_hash)?;
        let mut log = header;
        log.extend_from_slice(&first.encode());
        replace_file(self.dir, lock, LOG_FILE, &log)?;
        self.write_head(lock, 1, first.hash())
    }

    fn write_head(
        &self,
        lock: &WriterLock,
        count: u64,
        last_hash: [u8; MAC_LEN],
    ) -> Result<(), AuditError> {
        let head = Head::sign(self.key, self.vault_id, count, last_hash)?;
        replace_file(self.dir, lock, HEAD_FILE, &head.encode())
    }

    /// Reads the head and checks it (§5.6 check 4).
    fn read_head(&self) -> Result<Head, AuditError> {
        let path = self.dir.join(HEAD_FILE);
        let mut file = open_file(self.dir, HEAD_FILE, "audit head", false)?;
        let mut bytes = Vec::with_capacity(HEAD_LEN);
        // One byte more than the head can be, so a long file is noticed.
        (&mut file)
            .take(HEAD_LEN_PLUS_ONE)
            .read_to_end(&mut bytes)
            .map_err(|e| io_error("read", &path, e))?;
        Head::decode(&bytes, self.key, &self.vault_id)
            .map_err(|why| AuditError::Damaged(why.into()))
    }

    /// The hash of record `index`, or of the header for `None`.
    fn hash_of(&self, log: &mut File, index: Option<u64>) -> Result<[u8; MAC_LEN], AuditError> {
        let path = self.log_path();
        match index {
            None => {
                let mut header = [0u8; HEADER_LEN];
                read_at(log, 0, &mut header, &path)?;
                Ok(crypto::sha256(&[&header]))
            }
            Some(index) => {
                let offset = record_offset(index)
                    .ok_or_else(|| AuditError::Damaged("a record index overflows".into()))?;
                let mut bytes = [0u8; RECORD_LEN];
                read_at(log, offset, &mut bytes, &path)?;
                Ok(crypto::sha256(&[&bytes]))
            }
        }
    }

    /// Checks the log's header and its end: aligned length, valid last
    /// record, and a `prev_hash` that matches the record before it.
    fn read_tail(&self, log: &mut File) -> Result<Tail, AuditError> {
        let path = self.log_path();
        let len = log
            .metadata()
            .map_err(|e| io_error("inspect", &path, e))?
            .len();
        let Some(body) = len.checked_sub(HEADER_LEN_U64) else {
            return Err(AuditError::Damaged(
                "the log is shorter than its header".into(),
            ));
        };
        let mut header = [0u8; HEADER_LEN];
        read_at(log, 0, &mut header, &path)?;
        self.check_header(&header)?;
        if body.checked_rem(RECORD_LEN_U64) != Some(0) {
            return Err(AuditError::Damaged(
                "the log ends in the middle of a record".into(),
            ));
        }
        let count = body.checked_div(RECORD_LEN_U64).unwrap_or(0);
        let header_hash = crypto::sha256(&[&header]);
        let Some(last) = count.checked_sub(1) else {
            return Ok(Tail {
                count,
                header_hash,
                last_hash: header_hash,
            });
        };
        let offset = record_offset(last)
            .ok_or_else(|| AuditError::Damaged("a record index overflows".into()))?;
        let mut bytes = [0u8; RECORD_LEN];
        read_at(log, offset, &mut bytes, &path)?;
        let record = Record::decode(&bytes)
            .map_err(|why| AuditError::Damaged(format!("the last record: {why}")))?;
        if record.seq != last {
            return Err(AuditError::Damaged(
                "the last record is out of sequence".into(),
            ));
        }
        if !record.mac_ok(self.key) {
            return Err(AuditError::Damaged("the last record's MAC is wrong".into()));
        }
        let before = self.hash_of(log, last.checked_sub(1))?;
        if record.prev_hash != before {
            return Err(AuditError::Damaged(
                "the last record doesn't follow the one before it".into(),
            ));
        }
        Ok(Tail {
            count,
            header_hash,
            last_hash: crypto::sha256(&[&bytes]),
        })
    }

    fn check_header(&self, header: &[u8]) -> Result<(), AuditError> {
        let (Some(magic), Some(version), Some(id)) = (
            field::<8>(header, 0),
            field::<2>(header, 8),
            field::<ID_LEN>(header, 10),
        ) else {
            return Err(AuditError::Damaged("the log's header is cut short".into()));
        };
        if magic != LOG_MAGIC {
            return Err(AuditError::Damaged(
                "the log's magic bytes are wrong".into(),
            ));
        }
        if u16::from_le_bytes(version) != AUDIT_VERSION {
            return Err(AuditError::Damaged(
                "the log has an unsupported audit version".into(),
            ));
        }
        if id != self.vault_id {
            return Err(AuditError::Damaged(
                "the log belongs to a different vault".into(),
            ));
        }
        Ok(())
    }

    /// The head must cover all the records, or all but the last one: the
    /// second case is a crash between writing a record and replacing the head
    /// (D-053). The record it names must hash to its `last_hash`.
    fn check_head(&self, head: &Head, tail: &Tail, log: &mut File) -> Result<(), AuditError> {
        if head.count > tail.count {
            return Err(AuditError::Damaged(
                "the head covers more records than the log has".into(),
            ));
        }
        if head.count.checked_add(1).is_none_or(|c| c < tail.count) {
            return Err(AuditError::Damaged("the head is older than the log".into()));
        }
        let covered = match head.count.checked_sub(1) {
            None => tail.header_hash,
            Some(_) if head.count == tail.count => tail.last_hash,
            Some(index) => self.hash_of(log, Some(index))?,
        };
        if covered != head.last_hash {
            return Err(AuditError::Damaged(
                "the head doesn't match the record it names".into(),
            ));
        }
        Ok(())
    }

    /// The checks every append makes first (D-047). They read only the end of
    /// the log and the head, so they cost the same however long the log is.
    /// The head is read before the log: a writer can only add to the log, so
    /// a head read first is never ahead of a log read second.
    pub fn check(&self) -> Result<(), AuditError> {
        self.checked_tail().map(|_| ())
    }

    fn checked_tail(&self) -> Result<(Tail, File), AuditError> {
        let head = self.read_head()?;
        let mut log = open_file(self.dir, LOG_FILE, "audit log", true)?;
        let tail = self.read_tail(&mut log)?;
        self.check_head(&head, &tail, &mut log)?;
        Ok((tail, log))
    }

    /// Appends `entries` one at a time: write the record, flush it, replace
    /// the head. Checks first, and writes nothing if a check fails.
    pub fn append(&self, lock: &WriterLock, entries: &[Entry]) -> Result<(), AuditError> {
        let (mut tail, mut log) = self.checked_tail()?;
        let path = self.log_path();
        for entry in entries {
            let record = Record::sign(self.key, tail.count, now(), *entry, tail.last_hash)?;
            log.seek(SeekFrom::End(0))
                .and_then(|_| log.write_all(&record.encode()))
                .and_then(|()| log.sync_data())
                .map_err(|e| io_error("append to", &path, e))?;
            tail.count = tail
                .count
                .checked_add(1)
                .ok_or_else(|| AuditError::Damaged("the log has too many records".into()))?;
            tail.last_hash = record.hash();
            self.write_head(lock, tail.count, tail.last_hash)?;
        }
        Ok(())
    }

    /// [`Audit::append`] under a writer lock taken here.
    pub fn append_locked(&self, entries: &[Entry]) -> Result<(), AuditError> {
        let lock = lock(self.dir)?;
        self.append(&lock, entries)
    }

    /// The current anchor, after checking the head's MAC and `vault_id`.
    pub fn anchor(&self) -> Result<Anchor, AuditError> {
        Ok(self.read_head()?.anchor())
    }

    /// Everything §5.6 asks for, in order: the log's header, its length,
    /// every record, the head, how far the head is behind the log, and with
    /// `expect` the anchor. The first failure is the report. A damaged file
    /// is a failed [`Verdict`], not an error; only an unreadable one is.
    pub fn verify(&self, expect: Option<Anchor>) -> Result<Verdict, AuditError> {
        let path = self.log_path();
        let mut log = match open_file(self.dir, LOG_FILE, "audit log", false) {
            Ok(log) => log,
            Err(AuditError::Missing(_)) => return Ok(Verdict::failed("audit log missing")),
            Err(e) => return Err(e),
        };
        let len = log
            .metadata()
            .map_err(|e| io_error("inspect", &path, e))?
            .len();
        let Some(body) = len.checked_sub(HEADER_LEN_U64) else {
            return Ok(Verdict::failed("the log is shorter than its header"));
        };
        let mut header = [0u8; HEADER_LEN];
        read_at(&mut log, 0, &mut header, &path)?;
        if let Err(AuditError::Damaged(why)) = self.check_header(&header) {
            return Ok(Verdict::failed(why));
        }
        if body.checked_rem(RECORD_LEN_U64) != Some(0) {
            return Ok(Verdict::failed(
                "the log ends in the middle of a record (its length is not 26 plus a multiple of 105)",
            ));
        }
        let count = body.checked_div(RECORD_LEN_U64).unwrap_or(0);
        let header_hash = crypto::sha256(&[&header]);

        // The head is read first, but judged after the records (§5.6).
        let head = match self.read_head() {
            Ok(head) => Ok(head),
            Err(AuditError::Missing(_)) => Err("audit head missing".to_string()),
            Err(AuditError::Damaged(why)) => Err(why),
            Err(e) => return Err(e),
        };
        let head_index = head.as_ref().ok().and_then(|h| h.count.checked_sub(1));
        let expect_index = expect.and_then(|a| a.count.checked_sub(1));
        let mut head_hash = None;
        let mut expect_hash = None;

        log.seek(SeekFrom::Start(HEADER_LEN_U64))
            .map_err(|e| io_error("read", &path, e))?;
        let mut reader = BufReader::new(log);
        let mut previous = header_hash;
        for index in 0..count {
            let mut bytes = [0u8; RECORD_LEN];
            reader
                .read_exact(&mut bytes)
                .map_err(|e| io_error("read", &path, e))?;
            let record = match Record::decode(&bytes) {
                Ok(record) => record,
                Err(why) => return Ok(Verdict::failed(format!("record {index}: {why}"))),
            };
            if record.seq != index {
                return Ok(Verdict::failed(format!(
                    "record {index}: its sequence number is {}",
                    record.seq
                )));
            }
            if record.prev_hash != previous {
                return Ok(Verdict::failed(format!(
                    "record {index}: it doesn't follow the record before it"
                )));
            }
            if !record.mac_ok(self.key) {
                return Ok(Verdict::failed(format!("record {index}: its MAC is wrong")));
            }
            previous = crypto::sha256(&[&bytes]);
            if head_index == Some(index) {
                head_hash = Some(previous);
            }
            if expect_index == Some(index) {
                expect_hash = Some(previous);
            }
        }

        let head = match head {
            Ok(head) => head,
            Err(why) => return Ok(Verdict::failed(why)),
        };
        if head.count > count {
            return Ok(Verdict::failed(format!(
                "the head covers {} records but the log has {count}: the log was truncated",
                head.count
            )));
        }
        if head.count.checked_add(1).is_none_or(|c| c < count) {
            return Ok(Verdict::failed(format!(
                "the head covers only {} of the log's {count} records: the head is older than the log",
                head.count
            )));
        }
        let covered = if head.count == 0 {
            Some(header_hash)
        } else {
            head_hash
        };
        if covered != Some(head.last_hash) {
            return Ok(Verdict::failed(
                "the head doesn't match the record it names",
            ));
        }
        if let Some(anchor) = expect {
            if anchor.count > count {
                return Ok(Verdict::failed(format!(
                    "the log has {count} records, fewer than the anchor's {}: it was rolled back",
                    anchor.count
                )));
            }
            let at_anchor = if anchor.count == 0 {
                Some(header_hash)
            } else {
                expect_hash
            };
            if at_anchor != Some(anchor.hash) {
                return Ok(Verdict::failed(
                    "the log no longer holds the anchor's record at its position",
                ));
            }
        }
        let anchored = match expect {
            Some(anchor) => format!("; it still holds the anchor {anchor}"),
            None => String::new(),
        };
        Ok(Verdict {
            passed: true,
            report: format!(
                "audit log verified: {count} records, the head covers {}{anchored}",
                head.count
            ),
        })
    }

    /// Verifies, then appends a `verify` record with the result, all under
    /// one writer lock (§5.6). If the log can't be appended to, the record is
    /// skipped and the report says so (D-047).
    pub fn verify_and_record(&self, expect: Option<Anchor>) -> Result<Verdict, AuditError> {
        let lock = lock(self.dir)?;
        let mut verdict = self.verify(expect)?;
        let detail = u64::from(!verdict.passed);
        match self.append(&lock, &[Entry::new(Event::Verify, detail)]) {
            Ok(()) => {}
            Err(AuditError::Missing(_) | AuditError::Damaged(_)) => {
                verdict.report.push_str(
                    "; no verify record was written because the log can't be appended to",
                );
            }
            Err(e) => return Err(e),
        }
        Ok(verdict)
    }
}

/// One byte more than a head is long.
const HEAD_LEN_PLUS_ONE: u64 = 99;

/// How many unlocks have failed since the last good one. 0 if there is no
/// counter file; [`COUNTER_UNREADABLE`] if it can't be read, isn't a regular
/// file of ours, or isn't exactly 8 bytes (§5.5).
pub fn read_counter(dir: &Path) -> u64 {
    let path = dir.join(COUNTER_FILE);
    let mut file = match open_file(dir, COUNTER_FILE, "failed-unlock counter", false) {
        Ok(file) => file,
        Err(AuditError::Missing(_)) => return 0,
        Err(_) => return COUNTER_UNREADABLE,
    };
    let mut bytes = Vec::with_capacity(9);
    let read = (&mut file).take(9).read_to_end(&mut bytes);
    match (read, <[u8; 8]>::try_from(bytes.as_slice())) {
        (Ok(_), Ok(count)) => u64::from_le_bytes(count),
        _ => {
            let _ = path;
            COUNTER_UNREADABLE
        }
    }
}

/// Counts one failed unlock, under the writer lock (§5.5). An unreadable
/// counter stays unreadable: it saturates instead of restarting from zero.
pub fn note_failed_unlock(dir: &Path) -> Result<(), AuditError> {
    let lock = lock(dir)?;
    let count = read_counter(dir).saturating_add(1);
    replace_file(dir, &lock, COUNTER_FILE, &count.to_le_bytes())
}

/// Sets the counter back to 0 after a good unlock has recorded it.
pub fn reset_counter(dir: &Path, lock: &WriterLock) -> Result<(), AuditError> {
    replace_file(dir, lock, COUNTER_FILE, &0u64.to_le_bytes())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests;
