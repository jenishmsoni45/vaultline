//! The v1 vault encoder and decoder, byte for byte as `docs/vault-format.md`
//! §4.1–§4.4 specifies.
//!
//! Everything here treats its input as hostile (S10): no `unwrap`, `expect`,
//! indexing, `panic` or unchecked arithmetic, enforced by the lints below.
//! Lengths are checked against the bytes that are actually there before
//! anything is allocated. The functions are public so the `vault_file` fuzz
//! target can call them directly, without Argon2 in the way.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::fmt;

use super::crypto::{ID_LEN, KdfParams, MAC_LEN, NONCE_LEN, SALT_LEN, TAG_LEN, WRAPPED_KEY_LEN};
use crate::secret::{SecretBytes, SecretValue};

/// `"vaultln"` followed by a NUL byte (§4.1).
pub const MAGIC: [u8; 8] = *b"vaultln\0";
/// The only format version this binary reads and writes.
pub const FORMAT_VERSION: u16 = 1;
/// Bytes `0..54`: magic to `kdf_salt`, the part of the header that the
/// master-key wrap authenticates (§4.5).
pub const HEADER_PREFIX_LEN: usize = 54;
/// Offset of `item_count`, the last field of the fixed header.
pub const ITEM_COUNT_OFFSET: usize = 198;
/// Length of the fixed header, `item_count` included.
pub const HEADER_LEN: usize = 202;
/// Length of an empty vault: the fixed header plus the file MAC.
pub const MIN_FILE_LEN: usize = 234;
/// Largest vault file accepted or written: 64 MiB (D-027).
pub const MAX_FILE_LEN: u64 = 64 * 1024 * 1024;
/// Length of an item record without its `payload_box`.
pub const RECORD_FIXED_LEN: usize = 116;
/// Smallest possible item record: a `payload_box` holding only its tag.
pub const MIN_RECORD_LEN: usize = 132;
/// Longest project, item or field name in bytes.
pub const MAX_NAME_LEN: usize = 64;
/// Longest field value in bytes: 64 KiB (D-027).
pub const MAX_VALUE_LEN: usize = 65_536;

/// Why some bytes are not a valid v1 vault, or can't be written as one.
/// Messages describe structure only and never contain secret values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    /// `format_version` is not one this binary knows (§6, rule 4).
    UnsupportedVersion(u16),
    /// The bytes don't follow `docs/vault-format.md`.
    Malformed(&'static str),
    /// Encoding the vault would exceed [`MAX_FILE_LEN`].
    TooLarge,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::UnsupportedVersion(v) => write!(
                f,
                "unsupported format version {v}; a newer vaultline wrote this file"
            ),
            FormatError::Malformed(why) => write!(f, "the vault file is malformed: {why}"),
            FormatError::TooLarge => f.write_str("the vault would be larger than the 64 MiB limit"),
        }
    }
}

impl std::error::Error for FormatError {}

/// A project, item or field name: 1–64 bytes from `A–Z a–z 0–9 . _ -`,
/// case-sensitive (§4.3, D-027). Names are metadata, not secrets: they are
/// encrypted in the file but may be printed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

/// Why a string is not a valid [`Name`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    /// The name is empty.
    Empty,
    /// The name is longer than 64 bytes.
    TooLong,
    /// The name contains a byte outside `A–Z a–z 0–9 . _ -`.
    BadByte,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NameError::Empty => "a name can't be empty",
            NameError::TooLong => "a name can be at most 64 bytes long",
            NameError::BadByte => "a name may only use the characters A-Z a-z 0-9 . _ -",
        })
    }
}

impl std::error::Error for NameError {}

impl Name {
    /// Validates a name.
    pub fn new(name: &str) -> Result<Self, NameError> {
        Self::from_bytes(name.as_bytes())
    }

    /// Validates a name given as bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NameError> {
        if bytes.is_empty() {
            return Err(NameError::Empty);
        }
        if bytes.len() > MAX_NAME_LEN {
            return Err(NameError::TooLong);
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(NameError::BadByte);
        }
        // Every byte is ASCII, so this can't fail; map the error anyway.
        String::from_utf8(bytes.to_vec())
            .map(Name)
            .map_err(|_| NameError::BadByte)
    }

    /// The name as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn len_u8(&self) -> u8 {
        // At most 64 bytes, checked in `from_bytes`.
        u8::try_from(self.0.len()).unwrap_or(u8::MAX)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The fixed header, bytes `0..198` (§4.1). `item_count` is read with the
/// records, after the file MAC has been checked (§4.7 step 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub vault_id: [u8; ID_LEN],
    pub kdf: KdfParams,
    pub kdf_salt: [u8; SALT_LEN],
    pub mk_nonce: [u8; NONCE_LEN],
    pub mk_box: [u8; WRAPPED_KEY_LEN],
    pub ak_nonce: [u8; NONCE_LEN],
    pub ak_box: [u8; WRAPPED_KEY_LEN],
}

impl Header {
    /// Bytes `0..54` of this header: what the master-key wrap authenticates.
    pub fn prefix(&self) -> [u8; HEADER_PREFIX_LEN] {
        encode_prefix(&self.vault_id, self.kdf, &self.kdf_salt)
    }
}

/// Encodes bytes `0..54`: magic, version, `vault_id`, the Argon2id
/// parameters and the salt.
pub fn encode_prefix(
    vault_id: &[u8; ID_LEN],
    kdf: KdfParams,
    kdf_salt: &[u8; SALT_LEN],
) -> [u8; HEADER_PREFIX_LEN] {
    let version = FORMAT_VERSION.to_le_bytes();
    let m = kdf.m_kib.to_le_bytes();
    let t = kdf.t.to_le_bytes();
    let p = kdf.p.to_le_bytes();
    let mut out = [0u8; HEADER_PREFIX_LEN];
    let fields = MAGIC
        .iter()
        .chain(&version)
        .chain(vault_id)
        .chain(&m)
        .chain(&t)
        .chain(&p)
        .chain(kdf_salt);
    for (dst, src) in out.iter_mut().zip(fields) {
        *dst = *src;
    }
    out
}

/// One item record (§4.2). Everything in it is ciphertext or random.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub item_id: [u8; ID_LEN],
    pub ik_nonce: [u8; NONCE_LEN],
    pub ik_box: [u8; WRAPPED_KEY_LEN],
    pub payload_nonce: [u8; NONCE_LEN],
    pub payload_box: Vec<u8>,
}

/// The plaintext inside a `payload_box` (§4.3). Fields are kept in ascending
/// name order by the map.
pub struct Payload {
    pub project: Name,
    pub item: Name,
    pub fields: BTreeMap<Name, SecretValue>,
}

/// §4.7 step 1: a file under 234 bytes or over 64 MiB is a format error.
pub fn check_file_len(len: u64) -> Result<(), FormatError> {
    if len > MAX_FILE_LEN {
        return Err(FormatError::Malformed("the file is larger than 64 MiB"));
    }
    if len < MIN_FILE_LEN as u64 {
        return Err(FormatError::Malformed(
            "the file is shorter than an empty vault (234 bytes)",
        ));
    }
    Ok(())
}

fn file_len(file: &[u8]) -> Result<(), FormatError> {
    check_file_len(u64::try_from(file.len()).unwrap_or(u64::MAX))
}

/// §4.7 steps 1–2: checks the size, the magic, the version and the Argon2id
/// bounds, and reads the fixed header. Argon2id hasn't run yet, so the bounds
/// keep a tampered header from making an unlock allocate past the ceiling.
pub fn parse_header(file: &[u8]) -> Result<Header, FormatError> {
    file_len(file)?;
    let mut r = Reader::new(file);
    if r.array::<8>("magic")? != MAGIC {
        return Err(FormatError::Malformed(
            "bad magic bytes; this is not a vaultline vault",
        ));
    }
    let version = r.u16("format_version")?;
    if version != FORMAT_VERSION {
        return Err(FormatError::UnsupportedVersion(version));
    }
    let vault_id = r.array("vault_id")?;
    let kdf = KdfParams {
        m_kib: r.u32("kdf_m_kib")?,
        t: r.u32("kdf_t")?,
        p: r.u32("kdf_p")?,
    };
    kdf.check().map_err(FormatError::Malformed)?;
    Ok(Header {
        vault_id,
        kdf,
        kdf_salt: r.array("kdf_salt")?,
        mk_nonce: r.array("mk_nonce")?,
        mk_box: r.array("mk_box")?,
        ak_nonce: r.array("ak_nonce")?,
        ak_box: r.array("ak_box")?,
    })
}

/// §4.7 step 6: reads `item_count` and the item records. `item_count` is
/// checked against what the file can hold before anything is allocated, every
/// length must fit, records must be in strictly ascending `item_id` order,
/// and the parse must end exactly where the file MAC starts.
pub fn parse_records(file: &[u8]) -> Result<Vec<Record>, FormatError> {
    file_len(file)?;
    let body_end = file
        .len()
        .checked_sub(MAC_LEN)
        .ok_or(FormatError::Malformed("the file is too short"))?;
    let body = file
        .get(ITEM_COUNT_OFFSET..body_end)
        .ok_or(FormatError::Malformed("the file is too short"))?;
    let mut r = Reader::new(body);
    let count = usize::try_from(r.u32("item_count")?).unwrap_or(usize::MAX);
    let room = file
        .len()
        .checked_sub(MIN_FILE_LEN)
        .and_then(|n| n.checked_div(MIN_RECORD_LEN))
        .unwrap_or(0);
    if count > room {
        return Err(FormatError::Malformed(
            "item_count is larger than the file can hold",
        ));
    }
    let mut records = Vec::new();
    let mut previous: Option<[u8; ID_LEN]> = None;
    for _ in 0..count {
        let item_id = r.array("item_id")?;
        let ik_nonce = r.array("ik_nonce")?;
        let ik_box = r.array("ik_box")?;
        let payload_nonce = r.array("payload_nonce")?;
        let payload_len = usize::try_from(r.u32("payload_len")?).unwrap_or(usize::MAX);
        if payload_len < TAG_LEN {
            return Err(FormatError::Malformed("payload_len is shorter than a tag"));
        }
        let payload_box = r
            .take(payload_len, "payload_box runs past the file MAC")?
            .to_vec();
        if previous.is_some_and(|p| item_id <= p) {
            return Err(FormatError::Malformed(
                "item records are not in strictly ascending item_id order",
            ));
        }
        previous = Some(item_id);
        records.push(Record {
            item_id,
            ik_nonce,
            ik_box,
            payload_nonce,
            payload_box,
        });
    }
    if !r.is_empty() {
        return Err(FormatError::Malformed(
            "bytes are left over before the file MAC",
        ));
    }
    Ok(records)
}

/// The length of a whole vault file holding records with these payload
/// lengths, MAC included, or `None` on overflow.
pub fn encoded_len(payload_lens: impl IntoIterator<Item = usize>) -> Option<usize> {
    payload_lens
        .into_iter()
        .try_fold(MIN_FILE_LEN, |total, len| {
            total.checked_add(RECORD_FIXED_LEN)?.checked_add(len)
        })
}

/// Encodes everything but the file MAC, canonically (§4.8). The buffer has
/// room left for the MAC, which the caller appends.
pub fn encode_body(header: &Header, records: &[Record]) -> Result<Vec<u8>, FormatError> {
    let total =
        encoded_len(records.iter().map(|r| r.payload_box.len())).ok_or(FormatError::TooLarge)?;
    if u64::try_from(total).unwrap_or(u64::MAX) > MAX_FILE_LEN {
        return Err(FormatError::TooLarge);
    }
    let count = u32::try_from(records.len()).map_err(|_| FormatError::TooLarge)?;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&header.prefix());
    out.extend_from_slice(&header.mk_nonce);
    out.extend_from_slice(&header.mk_box);
    out.extend_from_slice(&header.ak_nonce);
    out.extend_from_slice(&header.ak_box);
    out.extend_from_slice(&count.to_le_bytes());
    let mut previous: Option<&[u8; ID_LEN]> = None;
    for record in records {
        if previous.is_some_and(|p| record.item_id <= *p) {
            return Err(FormatError::Malformed(
                "item records are not in strictly ascending item_id order",
            ));
        }
        previous = Some(&record.item_id);
        if record.payload_box.len() < TAG_LEN {
            return Err(FormatError::Malformed("payload_len is shorter than a tag"));
        }
        let payload_len =
            u32::try_from(record.payload_box.len()).map_err(|_| FormatError::TooLarge)?;
        out.extend_from_slice(&record.item_id);
        out.extend_from_slice(&record.ik_nonce);
        out.extend_from_slice(&record.ik_box);
        out.extend_from_slice(&record.payload_nonce);
        out.extend_from_slice(&payload_len.to_le_bytes());
        out.extend_from_slice(&record.payload_box);
    }
    Ok(out)
}

/// Decodes a decrypted payload (§4.3): names follow the name rule, there is at
/// least one field, fields are in strictly ascending name order, every value
/// is at most 64 KiB, and nothing follows the last field.
pub fn decode_payload(plain: &[u8]) -> Result<Payload, FormatError> {
    let mut r = Reader::new(plain);
    let project = read_name(&mut r, "project")?;
    let item = read_name(&mut r, "item")?;
    let count = r.u16("field_count")?;
    if count == 0 {
        return Err(FormatError::Malformed("an item has no fields"));
    }
    let mut fields = BTreeMap::new();
    let mut previous: Option<Name> = None;
    for _ in 0..count {
        let name = read_name(&mut r, "field name")?;
        let value_len = usize::try_from(r.u32("value_len")?).unwrap_or(usize::MAX);
        if value_len > MAX_VALUE_LEN {
            return Err(FormatError::Malformed("a value is longer than 64 KiB"));
        }
        let value = r.take(value_len, "a value runs past the end of the payload")?;
        if previous.as_ref().is_some_and(|p| name <= *p) {
            return Err(FormatError::Malformed(
                "fields are not in strictly ascending name order",
            ));
        }
        previous = Some(name.clone());
        fields.insert(name, SecretValue::new(value));
    }
    if !r.is_empty() {
        return Err(FormatError::Malformed(
            "bytes are left over after the last field",
        ));
    }
    Ok(Payload {
        project,
        item,
        fields,
    })
}

/// Encodes a payload canonically (§4.3, §4.8) into a buffer whose exact size
/// is reserved first, so the plaintext is never reallocated.
pub fn encode_payload(payload: &Payload) -> Result<SecretBytes, FormatError> {
    let count = u16::try_from(payload.fields.len())
        .map_err(|_| FormatError::Malformed("an item can have at most 65,535 fields"))?;
    if count == 0 {
        return Err(FormatError::Malformed("an item has no fields"));
    }
    let mut total = 1usize
        .checked_add(payload.project.as_str().len())
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_add(payload.item.as_str().len()))
        .and_then(|n| n.checked_add(2))
        .ok_or(FormatError::TooLarge)?;
    for (name, value) in &payload.fields {
        if value.len() > MAX_VALUE_LEN {
            return Err(FormatError::Malformed("a value is longer than 64 KiB"));
        }
        total = total
            .checked_add(1)
            .and_then(|n| n.checked_add(name.as_str().len()))
            .and_then(|n| n.checked_add(4))
            .and_then(|n| n.checked_add(value.len()))
            .ok_or(FormatError::TooLarge)?;
    }
    let mut out = SecretBytes::with_capacity(total);
    out.extend_from_slice(&[payload.project.len_u8()]);
    out.extend_from_slice(payload.project.as_str().as_bytes());
    out.extend_from_slice(&[payload.item.len_u8()]);
    out.extend_from_slice(payload.item.as_str().as_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    for (name, value) in &payload.fields {
        // At most 64 KiB, checked above.
        let value_len = u32::try_from(value.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&[name.len_u8()]);
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(&value_len.to_le_bytes());
        out.extend_from_slice(value.expose());
    }
    Ok(out)
}

fn read_name(r: &mut Reader<'_>, what: &'static str) -> Result<Name, FormatError> {
    let len = usize::from(r.u8(what)?);
    if len == 0 || len > MAX_NAME_LEN {
        return Err(FormatError::Malformed("a name length is outside 1-64"));
    }
    let bytes = r.take(len, "a name runs past the end of the payload")?;
    Name::from_bytes(bytes)
        .map_err(|_| FormatError::Malformed("a name contains a byte outside A-Z a-z 0-9 . _ -"))
}

/// A cursor over untrusted bytes. Every read is bounds-checked.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { rest: bytes }
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], FormatError> {
        let (head, tail) = self
            .rest
            .split_at_checked(n)
            .ok_or(FormatError::Malformed(what))?;
        self.rest = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], FormatError> {
        self.take(N, what)?
            .try_into()
            .map_err(|_| FormatError::Malformed(what))
    }

    fn u8(&mut self, what: &'static str) -> Result<u8, FormatError> {
        Ok(u8::from_le_bytes(self.array(what)?))
    }

    fn u16(&mut self, what: &'static str) -> Result<u16, FormatError> {
        Ok(u16::from_le_bytes(self.array(what)?))
    }

    fn u32(&mut self, what: &'static str) -> Result<u32, FormatError> {
        Ok(u32::from_le_bytes(self.array(what)?))
    }

    fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn name(s: &str) -> Name {
        Name::new(s).unwrap()
    }

    fn header() -> Header {
        Header {
            vault_id: [0x11; ID_LEN],
            kdf: KdfParams {
                m_kib: 64,
                t: 2,
                p: 2,
            },
            kdf_salt: [0x22; SALT_LEN],
            mk_nonce: [0x33; NONCE_LEN],
            mk_box: [0x44; WRAPPED_KEY_LEN],
            ak_nonce: [0x55; NONCE_LEN],
            ak_box: [0x66; WRAPPED_KEY_LEN],
        }
    }

    fn record(id: u8, payload_len: usize) -> Record {
        Record {
            item_id: [id; ID_LEN],
            ik_nonce: [0x77; NONCE_LEN],
            ik_box: [0x88; WRAPPED_KEY_LEN],
            payload_nonce: [0x99; NONCE_LEN],
            payload_box: vec![0xAA; payload_len],
        }
    }

    /// A whole file: body plus a dummy MAC (the format layer never checks it).
    fn file(header: &Header, records: &[Record]) -> Vec<u8> {
        let mut bytes = encode_body(header, records).unwrap();
        bytes.extend_from_slice(&[0xEE; MAC_LEN]);
        bytes
    }

    fn put_u32(bytes: &mut [u8], at: usize, v: u32) {
        bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn layout_offsets_match_the_spec() {
        let bytes = file(&header(), &[]);
        assert_eq!(bytes.len(), MIN_FILE_LEN, "an empty vault is 234 bytes");
        assert_eq!(&bytes[0..8], b"vaultln\0");
        assert_eq!(&bytes[8..10], &[1, 0]);
        assert_eq!(&bytes[10..26], &[0x11; 16]);
        assert_eq!(&bytes[26..30], &64u32.to_le_bytes());
        assert_eq!(&bytes[30..34], &2u32.to_le_bytes());
        assert_eq!(&bytes[34..38], &2u32.to_le_bytes());
        assert_eq!(&bytes[38..54], &[0x22; 16]);
        assert_eq!(&bytes[54..78], &[0x33; 24]);
        assert_eq!(&bytes[78..126], &[0x44; 48]);
        assert_eq!(&bytes[126..150], &[0x55; 24]);
        assert_eq!(&bytes[150..198], &[0x66; 48]);
        assert_eq!(&bytes[198..202], &0u32.to_le_bytes());
        assert_eq!(header().prefix().as_slice(), &bytes[..HEADER_PREFIX_LEN]);
    }

    #[test]
    fn record_layout_matches_the_spec() {
        let bytes = file(&header(), &[record(1, TAG_LEN)]);
        assert_eq!(bytes.len(), MIN_FILE_LEN + MIN_RECORD_LEN);
        let rec = &bytes[HEADER_LEN..];
        assert_eq!(&rec[0..16], &[1; 16]);
        assert_eq!(&rec[16..40], &[0x77; 24]);
        assert_eq!(&rec[40..88], &[0x88; 48]);
        assert_eq!(&rec[88..112], &[0x99; 24]);
        assert_eq!(&rec[112..116], &16u32.to_le_bytes());
        assert_eq!(&rec[116..132], &[0xAA; 16]);
        assert_eq!(&bytes[198..202], &1u32.to_le_bytes());
    }

    #[test]
    fn header_and_records_round_trip() {
        let records = vec![record(1, 16), record(2, 40), record(9, 300)];
        let bytes = file(&header(), &records);
        assert_eq!(parse_header(&bytes).unwrap(), header());
        assert_eq!(parse_records(&bytes).unwrap(), records);
        assert_eq!(
            encoded_len(records.iter().map(|r| r.payload_box.len())),
            Some(bytes.len())
        );
    }

    #[test]
    fn size_limits_are_checked_first() {
        assert!(check_file_len(233).is_err());
        assert!(check_file_len(234).is_ok());
        assert!(check_file_len(MAX_FILE_LEN).is_ok());
        assert!(check_file_len(MAX_FILE_LEN + 1).is_err());
        assert!(parse_header(&[0; 233]).is_err());
        assert!(parse_records(&[0; 100]).is_err());
    }

    #[test]
    fn bad_magic_and_unknown_versions_are_rejected() {
        let mut bytes = file(&header(), &[]);
        bytes[3] ^= 1;
        assert_eq!(
            parse_header(&bytes),
            Err(FormatError::Malformed(
                "bad magic bytes; this is not a vaultline vault"
            ))
        );
        for version in [0u16, 2, 0x0100, u16::MAX] {
            let mut bytes = file(&header(), &[]);
            bytes[8..10].copy_from_slice(&version.to_le_bytes());
            assert_eq!(
                parse_header(&bytes),
                Err(FormatError::UnsupportedVersion(version))
            );
        }
    }

    #[test]
    fn kdf_parameters_outside_the_bounds_are_rejected() {
        let cases = [
            (
                KdfParams {
                    m_kib: 8,
                    t: 1,
                    p: 1,
                },
                true,
            ),
            (
                KdfParams {
                    m_kib: 1_048_576,
                    t: 10,
                    p: 8,
                },
                true,
            ),
            (
                KdfParams {
                    m_kib: 64,
                    t: 1,
                    p: 8,
                },
                true,
            ),
            (
                KdfParams {
                    m_kib: 63,
                    t: 1,
                    p: 8,
                },
                false,
            ),
            (
                KdfParams {
                    m_kib: 7,
                    t: 1,
                    p: 1,
                },
                false,
            ),
            (
                KdfParams {
                    m_kib: 1_048_577,
                    t: 1,
                    p: 1,
                },
                false,
            ),
            (
                KdfParams {
                    m_kib: u32::MAX,
                    t: 1,
                    p: 1,
                },
                false,
            ),
            (
                KdfParams {
                    m_kib: 64,
                    t: 0,
                    p: 1,
                },
                false,
            ),
            (
                KdfParams {
                    m_kib: 64,
                    t: 11,
                    p: 1,
                },
                false,
            ),
            (
                KdfParams {
                    m_kib: 64,
                    t: 1,
                    p: 0,
                },
                false,
            ),
            (
                KdfParams {
                    m_kib: 64,
                    t: 1,
                    p: 9,
                },
                false,
            ),
            (
                KdfParams {
                    m_kib: u32::MAX,
                    t: u32::MAX,
                    p: u32::MAX,
                },
                false,
            ),
        ];
        for (kdf, ok) in cases {
            let bytes = file(&Header { kdf, ..header() }, &[]);
            assert_eq!(parse_header(&bytes).is_ok(), ok, "{kdf:?}");
        }
    }

    #[test]
    fn item_count_beyond_the_file_is_rejected_before_allocation() {
        let mut bytes = file(&header(), &[record(1, 16)]);
        put_u32(&mut bytes, ITEM_COUNT_OFFSET, 2);
        assert_eq!(
            parse_records(&bytes),
            Err(FormatError::Malformed(
                "item_count is larger than the file can hold"
            ))
        );
        put_u32(&mut bytes, ITEM_COUNT_OFFSET, u32::MAX);
        assert!(parse_records(&bytes).is_err());
    }

    #[test]
    fn record_framing_errors_are_rejected() {
        let records = [record(1, 16), record(2, 16)];
        let good = file(&header(), &records);
        let first_len = HEADER_LEN + 112;

        let mut short = good.clone();
        put_u32(&mut short, first_len, 15);
        assert!(parse_records(&short).is_err(), "payload_len below 16");

        let mut overrun = good.clone();
        put_u32(&mut overrun, first_len, 10_000);
        assert!(parse_records(&overrun).is_err(), "payload_len overruns");

        let mut fewer = good.clone();
        put_u32(&mut fewer, ITEM_COUNT_OFFSET, 1);
        assert_eq!(
            parse_records(&fewer),
            Err(FormatError::Malformed(
                "bytes are left over before the file MAC"
            ))
        );

        let mut swapped = good.clone();
        swapped[HEADER_LEN..HEADER_LEN + 16].copy_from_slice(&[3; 16]);
        assert!(parse_records(&swapped).is_err(), "descending ids");

        let mut duplicate = good.clone();
        let second = HEADER_LEN + MIN_RECORD_LEN;
        duplicate[second..second + 16].copy_from_slice(&[1; 16]);
        assert!(parse_records(&duplicate).is_err(), "duplicate ids");
    }

    #[test]
    fn encode_rejects_unsorted_records_and_oversized_vaults() {
        assert!(encode_body(&header(), &[record(2, 16), record(1, 16)]).is_err());
        assert!(encode_body(&header(), &[record(1, 16), record(1, 16)]).is_err());
        assert!(encode_body(&header(), &[record(1, 15)]).is_err());
        let limit = usize::try_from(MAX_FILE_LEN).unwrap();
        let fits = limit - MIN_FILE_LEN - RECORD_FIXED_LEN;
        assert_eq!(encoded_len([fits]), Some(limit));
        assert_eq!(encoded_len([usize::MAX]), None);
    }

    fn payload(fields: &[(&str, &[u8])]) -> Payload {
        Payload {
            project: name("proj"),
            item: name("item"),
            fields: fields
                .iter()
                .map(|(n, v)| (name(n), SecretValue::new(v)))
                .collect(),
        }
    }

    #[test]
    fn payload_round_trips_with_exact_bytes() {
        let p = payload(&[("b", b""), ("a", b"fake-value")]);
        let bytes = encode_payload(&p).unwrap();
        let expected: Vec<u8> = [
            &[4u8][..],
            b"proj",
            &[4],
            b"item",
            &2u16.to_le_bytes(),
            &[1],
            b"a",
            &10u32.to_le_bytes(),
            b"fake-value",
            &[1],
            b"b",
            &0u32.to_le_bytes(),
        ]
        .concat();
        assert_eq!(bytes.expose(), expected.as_slice());
        let back = decode_payload(bytes.expose()).unwrap();
        assert_eq!(back.project, p.project);
        assert_eq!(back.item, p.item);
        let fields: Vec<(&str, &[u8])> = back
            .fields
            .iter()
            .map(|(n, v)| (n.as_str(), v.expose()))
            .collect();
        assert_eq!(fields, [("a", &b"fake-value"[..]), ("b", &b""[..])]);
    }

    #[test]
    fn payload_errors_are_rejected() {
        let good = encode_payload(&payload(&[("a", b"x"), ("b", b"y")]))
            .unwrap()
            .expose()
            .to_vec();
        assert!(decode_payload(&good).is_ok());

        let mut trailing = good.clone();
        trailing.push(0);
        assert!(decode_payload(&trailing).is_err(), "leftover byte");
        assert!(
            decode_payload(&good[..good.len() - 1]).is_err(),
            "truncated"
        );

        let mut zero_fields = good.clone();
        zero_fields[10..12].copy_from_slice(&0u16.to_le_bytes());
        assert!(decode_payload(&zero_fields).is_err(), "field_count 0");

        let mut unsorted = good.clone();
        let b_name = 12 + 1 + 1 + 4 + 1 + 1;
        unsorted[13] = b'b';
        unsorted[b_name] = b'a';
        assert!(decode_payload(&unsorted).is_err(), "descending field names");

        let mut duplicate = good.clone();
        duplicate[b_name] = b'a';
        assert!(decode_payload(&duplicate).is_err(), "duplicate field names");

        let mut bad_byte = good.clone();
        bad_byte[1] = b'/';
        assert!(decode_payload(&bad_byte).is_err(), "bad name byte");

        let mut empty_name = good.clone();
        empty_name[0] = 0;
        assert!(decode_payload(&empty_name).is_err(), "empty name");

        let mut long_name = good.clone();
        long_name[0] = 65;
        assert!(decode_payload(&long_name).is_err(), "65-byte name");
    }

    #[test]
    fn values_up_to_64_kib_are_accepted_and_longer_ones_rejected() {
        let max = vec![b'v'; MAX_VALUE_LEN];
        let bytes = encode_payload(&payload(&[("big", &max)])).unwrap();
        assert!(decode_payload(bytes.expose()).is_ok());

        let mut too_long = bytes.expose().to_vec();
        let len_at = 1 + 4 + 1 + 4 + 2 + 1 + 3;
        too_long[len_at..len_at + 4].copy_from_slice(&65_537u32.to_le_bytes());
        too_long.push(b'v');
        assert_eq!(
            decode_payload(&too_long).err(),
            Some(FormatError::Malformed("a value is longer than 64 KiB"))
        );
        let over = vec![b'v'; MAX_VALUE_LEN + 1];
        assert!(encode_payload(&payload(&[("big", &over)])).is_err());
    }

    #[test]
    fn names_follow_the_name_rule() {
        assert!(Name::new("Az09._-").is_ok());
        assert!(Name::new(&"a".repeat(64)).is_ok());
        assert_eq!(Name::new(""), Err(NameError::Empty));
        assert_eq!(Name::new(&"a".repeat(65)), Err(NameError::TooLong));
        for bad in ["a/b", "a b", "é", "a\0", "a:b", "a+b"] {
            assert_eq!(Name::new(bad), Err(NameError::BadByte), "{bad:?}");
        }
        assert!(name("B") < name("a"), "names compare as bytes");
    }
}
