//! Reading and replacing the vault file, and the writer lock
//! (`docs/vault-format.md` §4.7–§4.8, `docs/design.md` §11, D-027).
//!
//! - Reads open the file without following symlinks, check it through its own
//!   descriptor, and check its size before reading a byte of it.
//! - Every write happens under the writer lock: `flock` on `lock`, waiting up
//!   to 10 seconds (NFR-13).
//! - A write goes to a new temporary file in the same directory, which is
//!   flushed to disk and renamed over the vault; the directory is then
//!   flushed too. A crash leaves the old vault intact (NFR-12). The temporary
//!   file only ever holds ciphertext, and a leftover one is removed by the
//!   next writer.

use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg, OFlag};

use super::Error;
use super::format;
use crate::paths::{self, FILE_MODE, PathError};

/// The vault file's name inside the vault directory.
pub const VAULT_FILE: &str = "vault";
/// The writer lock's name inside the vault directory.
pub const LOCK_FILE: &str = "lock";
/// The agent's lock file: held with `flock` for as long as an agent runs.
pub const AGENT_LOCK_FILE: &str = "agent.lock";
/// Prefix of the temporary files used by the atomic replace.
pub const TMP_PREFIX: &str = ".vault.tmp-";
/// How long a writer waits for the lock before giving up (D-037).
pub const LOCK_WAIT: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(20);

/// Proof that this process holds the writer lock. Dropping it releases the
/// lock.
pub struct WriterLock {
    _lock: Flock<File>,
}

fn no_follow() -> i32 {
    OFlag::O_NOFOLLOW.bits()
}

fn io(action: &'static str, path: &Path, source: io::Error) -> Error {
    if source.raw_os_error() == Some(Errno::ELOOP as i32) {
        return Error::Path(PathError::Symlink(path.to_path_buf()));
    }
    Error::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

/// A failed open: "permission denied" usually means the file belongs to
/// someone else, so report the ownership or mode problem, with its fix, when
/// the path check finds one.
fn open_error(action: &'static str, path: &Path, err: io::Error) -> Error {
    if err.kind() == io::ErrorKind::PermissionDenied {
        if let Ok(meta) = fs::symlink_metadata(path) {
            if let Err(problem) = paths::check_file(path, &meta) {
                return Error::Path(problem);
            }
        }
    }
    io(action, path, err)
}

/// Opens `path` without following a symlink, creating it with mode 0600 if
/// it is missing, and checks it.
fn open_or_create_private(path: &Path) -> Result<File, Error> {
    let created = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .custom_flags(no_follow())
        .open(path);
    let file = match created {
        Ok(file) => {
            file.set_permissions(Permissions::from_mode(FILE_MODE))
                .map_err(|e| io("set the mode of", path, e))?;
            file
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(no_follow())
            .open(path)
            .map_err(|e| open_error("open", path, e))?,
        Err(e) => return Err(open_error("create", path, e)),
    };
    let meta = file.metadata().map_err(|e| io("inspect", path, e))?;
    paths::check_file(path, &meta)?;
    Ok(file)
}

/// Takes the writer lock, waiting up to [`LOCK_WAIT`]. Fails with
/// [`Error::Busy`] ("another vaultline is writing") after that.
pub fn lock(dir: &Path) -> Result<WriterLock, Error> {
    lock_with_wait(dir, LOCK_WAIT)
}

fn lock_with_wait(dir: &Path, wait: Duration) -> Result<WriterLock, Error> {
    let path = dir.join(LOCK_FILE);
    let mut file = open_or_create_private(&path)?;
    let deadline = Instant::now() + wait;
    loop {
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => return Ok(WriterLock { _lock: lock }),
            Err((f, errno)) if errno == Errno::EWOULDBLOCK || errno == Errno::EINTR => {
                if Instant::now() >= deadline {
                    return Err(Error::Busy);
                }
                file = f;
                thread::sleep(LOCK_POLL);
            }
            Err((_, errno)) => return Err(io("lock", &path, io::Error::from(errno))),
        }
    }
}

/// Proof that this process is the one agent for a vault directory. The lock
/// is released when it is dropped, or when the process ends, however it ends.
pub struct AgentLock {
    _lock: Flock<File>,
}

/// Takes `agent.lock` without waiting (design §8). `None` means another agent
/// holds it. Whoever holds this lock is the only process allowed to remove a
/// stale `agent.sock`, which settles any race over it.
pub fn try_lock_agent(dir: &Path) -> Result<Option<AgentLock>, Error> {
    let path = dir.join(AGENT_LOCK_FILE);
    let file = open_or_create_private(&path)?;
    match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(lock) => Ok(Some(AgentLock { _lock: lock })),
        Err((_, errno)) if errno == Errno::EWOULDBLOCK => Ok(None),
        Err((_, errno)) => Err(io("lock", &path, io::Error::from(errno))),
    }
}

/// Whether a vault file (or anything else) exists at the vault path.
pub fn vault_exists(dir: &Path) -> Result<bool, Error> {
    let path = dir.join(VAULT_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io("inspect", &path, e)),
    }
}

/// Reads the vault file. The size is checked from the open descriptor before
/// any byte is read (§4.7 step 1), and reading stops one byte past the limit
/// in case the file grew in between.
pub fn read_vault(dir: &Path) -> Result<Vec<u8>, Error> {
    let path = dir.join(VAULT_FILE);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(no_follow())
        .open(&path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                Error::Missing(dir.to_path_buf())
            } else {
                open_error("open", &path, e)
            }
        })?;
    let meta = file.metadata().map_err(|e| io("inspect", &path, e))?;
    paths::check_file(&path, &meta)?;
    format::check_file_len(meta.len())?;
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    file.take(format::MAX_FILE_LEN.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| io("read", &path, e))?;
    format::check_file_len(u64::try_from(bytes.len()).unwrap_or(u64::MAX))?;
    Ok(bytes)
}

/// Replaces the vault file atomically with `bytes`, which are ciphertext.
/// Needs the writer lock.
pub fn replace_vault(dir: &Path, _lock: &WriterLock, bytes: &[u8]) -> Result<(), Error> {
    remove_stale_temps(dir);
    let suffix: [u8; 8] = super::crypto::random_array().map_err(|_| Error::Random)?;
    let name: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let tmp = dir.join(format!("{TMP_PREFIX}{name}"));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .custom_flags(no_follow())
        .open(&tmp)
        .map_err(|e| io("create", &tmp, e))?;
    match write_and_rename(file, &tmp, dir, bytes) {
        Ok(()) => Ok(()),
        Err(Failure::KeepFiles(e)) => Err(e),
        Err(Failure::RemoveTemp(e)) => {
            // The rename never happened: the old vault is intact.
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

enum Failure {
    /// The rename didn't happen: remove the temporary file, report the error.
    RemoveTemp(Error),
    /// Report the error and touch nothing: either the rename already
    /// happened, or an injected crash wants the files left as they are.
    KeepFiles(Error),
}

fn remove_temp<'a>(action: &'static str, path: &'a Path) -> impl FnOnce(io::Error) -> Failure + 'a {
    move |e| Failure::RemoveTemp(io(action, path, e))
}

fn write_and_rename(mut file: File, tmp: &Path, dir: &Path, bytes: &[u8]) -> Result<(), Failure> {
    file.set_permissions(Permissions::from_mode(FILE_MODE))
        .map_err(remove_temp("set the mode of", tmp))?;
    match faults::take() {
        Some(Fault::FailMidWrite) => {
            let half = bytes.get(..bytes.len() / 2).unwrap_or_default();
            file.write_all(half).map_err(remove_temp("write", tmp))?;
            return Err(Failure::RemoveTemp(io(
                "write",
                tmp,
                io::Error::other("injected I/O failure"),
            )));
        }
        Some(Fault::CrashBeforeRename) => {
            file.write_all(bytes).map_err(remove_temp("write", tmp))?;
            file.sync_all().map_err(remove_temp("flush", tmp))?;
            return Err(Failure::KeepFiles(io(
                "replace",
                tmp,
                io::Error::other("injected crash before the rename"),
            )));
        }
        None => {}
    }
    file.write_all(bytes).map_err(remove_temp("write", tmp))?;
    file.sync_all().map_err(remove_temp("flush", tmp))?;
    drop(file);
    let vault: PathBuf = dir.join(VAULT_FILE);
    fs::rename(tmp, &vault).map_err(remove_temp("replace", &vault))?;
    // The new vault is in place; a failure from here on is reported, but
    // there is no temporary file left to remove.
    let sync_dir = File::open(dir).and_then(|d| d.sync_all());
    sync_dir.map_err(|e| Failure::KeepFiles(io("flush", dir, e)))
}

/// Removes temporary files left by a writer that crashed. Best effort: they
/// only ever hold ciphertext.
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

/// Faults a test can inject into the next [`replace_vault`] on the same
/// thread (P2-10). Without the `test-support` feature nothing can be
/// injected and `take` always returns `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Write half the bytes, then fail like a full disk would.
    FailMidWrite,
    /// Write and flush the temporary file, then stop as a crash would:
    /// no rename and no clean-up.
    CrashBeforeRename,
}

#[cfg(feature = "test-support")]
pub(crate) mod faults {
    use super::Fault;
    use std::cell::Cell;

    thread_local! {
        static NEXT: Cell<Option<Fault>> = const { Cell::new(None) };
    }

    pub(crate) fn inject(fault: Fault) {
        NEXT.set(Some(fault));
    }

    pub(crate) fn take() -> Option<Fault> {
        NEXT.take()
    }
}

#[cfg(not(feature = "test-support"))]
mod faults {
    use super::Fault;

    pub(super) fn take() -> Option<Fault> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_dir() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), Permissions::from_mode(0o700)).unwrap();
        tmp
    }

    #[test]
    fn replace_writes_a_private_file_and_leaves_no_temporary_file() {
        let tmp = private_dir();
        let lock = lock(tmp.path()).unwrap();
        replace_vault(tmp.path(), &lock, &[7; 300]).unwrap();
        replace_vault(tmp.path(), &lock, &[8; 300]).unwrap();
        assert_eq!(read_vault(tmp.path()).unwrap(), vec![8; 300]);
        let mode = fs::metadata(tmp.path().join(VAULT_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let names: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(
            names.iter().all(|n| !n.starts_with(TMP_PREFIX)),
            "{names:?}"
        );
    }

    #[test]
    fn a_second_lock_waits_and_then_gives_up() {
        let tmp = private_dir();
        let _held = lock(tmp.path()).unwrap();
        let start = Instant::now();
        let second = lock_with_wait(tmp.path(), Duration::from_millis(200));
        assert!(matches!(second, Err(Error::Busy)));
        assert!(start.elapsed() >= Duration::from_millis(200));
    }

    #[test]
    fn the_lock_is_released_on_drop() {
        let tmp = private_dir();
        drop(lock(tmp.path()).unwrap());
        assert!(lock_with_wait(tmp.path(), Duration::ZERO).is_ok());
    }

    #[test]
    fn the_agent_lock_is_exclusive_and_released_on_drop() {
        let tmp = private_dir();
        let first = try_lock_agent(tmp.path()).unwrap();
        assert!(first.is_some());
        assert!(try_lock_agent(tmp.path()).unwrap().is_none());
        drop(first);
        assert!(try_lock_agent(tmp.path()).unwrap().is_some());
    }

    #[test]
    fn the_agent_lock_is_independent_of_the_writer_lock() {
        let tmp = private_dir();
        let _agent = try_lock_agent(tmp.path()).unwrap().unwrap();
        assert!(lock_with_wait(tmp.path(), Duration::ZERO).is_ok());
        assert!(tmp.path().join(AGENT_LOCK_FILE).exists());
    }

    #[test]
    fn a_missing_vault_is_reported_as_missing() {
        let tmp = private_dir();
        assert!(matches!(read_vault(tmp.path()), Err(Error::Missing(_))));
    }
}
