//! The vault library: create, open, get, set, rm, list, passwd and rotate
//! (`docs/vault-format.md` §4, `docs/architecture.md` §1).
//!
//! A [`Vault`] holds only the unlocked master key and where the vault lives.
//! Every operation re-reads the file and re-verifies it under that key, and
//! every change happens under the writer lock as read, modify, replace. Two
//! writers therefore take turns and never lose each other's changes, and a
//! file swapped underneath is noticed.

pub mod crypto;
pub mod format;
pub mod store;
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod testing;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crypto::{CryptoError, ID_LEN, MAC_LEN, Subkeys};
use format::{HEADER_PREFIX_LEN, Header, Payload, Record};

pub use crypto::KdfParams;
pub use format::{FormatError, MAX_VALUE_LEN, Name, NameError};

use crate::paths::{self, PathError};
use crate::secret::{Key, Passphrase, SecretValue};

/// Everything that can go wrong. No variant carries a secret, so these can be
/// printed as they are.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The file doesn't follow the format (S2), or has an unknown version.
    Format(FormatError),
    /// The master key didn't unwrap: wrong passphrase, or a modified header
    /// (S4). The two can't be told apart.
    Unlock,
    /// An AEAD tag or the file MAC didn't verify (S2, S3).
    Auth(&'static str),
    /// No secret at this reference.
    NotFound(String),
    /// A value longer than 64 KiB.
    ValueTooLarge,
    /// The change would make the vault larger than 64 MiB.
    VaultTooLarge,
    /// Argon2id parameters outside the bounds of `docs/vault-format.md` §4.4.
    BadParams(&'static str),
    /// `create` found a vault already there.
    Exists(PathBuf),
    /// There is no vault in this directory.
    Missing(PathBuf),
    /// Another writer held the lock for more than 10 seconds.
    Busy,
    /// The vault directory or one of its files fails the ownership, mode or
    /// symlink checks.
    Path(PathError),
    /// An I/O error.
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    /// The OS random number generator failed.
    Random,
    /// Argon2id or HKDF failed.
    Kdf,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Format(e) => e.fmt(f),
            Error::Unlock => f.write_str("wrong passphrase, or the vault header was modified"),
            Error::Auth(what) => write!(f, "the vault failed authentication: {what}"),
            Error::NotFound(reference) => write!(f, "no secret at vault://{reference}"),
            Error::ValueTooLarge => f.write_str("a value can be at most 64 KiB"),
            Error::VaultTooLarge => {
                f.write_str("this change would make the vault larger than the 64 MiB limit")
            }
            Error::BadParams(why) => write!(f, "invalid Argon2id parameters: {why}"),
            Error::Exists(dir) => write!(f, "a vault already exists in {}", dir.display()),
            Error::Missing(dir) => write!(
                f,
                "there is no vault in {}; create one with `vaultline init`",
                dir.display()
            ),
            Error::Busy => f.write_str("another vaultline is writing; try again in a moment"),
            Error::Path(e) => e.fmt(f),
            Error::Io {
                action,
                path,
                source,
            } => write!(f, "couldn't {action} {}: {source}", path.display()),
            Error::Random => f.write_str("the operating system's random number generator failed"),
            Error::Kdf => f.write_str("key derivation failed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Format(e) => Some(e),
            Error::Path(e) => Some(e),
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<FormatError> for Error {
    fn from(e: FormatError) -> Self {
        match e {
            FormatError::TooLarge => Error::VaultTooLarge,
            other => Error::Format(other),
        }
    }
}

impl From<PathError> for Error {
    fn from(e: PathError) -> Self {
        match e {
            PathError::Io { path, source } if source.kind() == io::ErrorKind::NotFound => {
                Error::Missing(path)
            }
            other => Error::Path(other),
        }
    }
}

impl From<CryptoError> for Error {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::Random => Error::Random,
            CryptoError::Kdf => Error::Kdf,
            CryptoError::Aead => Error::Auth("a ciphertext did not verify"),
            CryptoError::Mac => Error::Auth("the file MAC does not match"),
        }
    }
}

/// One decrypted item. It holds secret values, so it implements neither
/// `Debug` nor `Display`.
pub struct Item {
    /// The record's random ID (§4.2).
    pub item_id: [u8; ID_LEN],
    pub project: Name,
    pub item: Name,
    /// Field values, in ascending name order.
    pub fields: BTreeMap<Name, SecretValue>,
}

/// One `project/item/field` name, as `list` returns it. No value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Entry {
    pub project: Name,
    pub item: Name,
    pub field: Name,
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.project, self.item, self.field)
    }
}

/// What `rm` removed (D-028).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removed {
    /// A field; the item still has others.
    Field,
    /// The item's last field, so the whole record went.
    Item,
}

/// An unlocked vault.
pub struct Vault {
    dir: PathBuf,
    vault_id: [u8; ID_LEN],
    kdf: KdfParams,
    master_key: Key,
}

/// A file that passed §4.7 steps 1–7 under a known master key.
struct Verified {
    header: Header,
    records: Vec<Record>,
    subkeys: Subkeys,
    audit_key: Key,
}

/// One record's item key and payload, decrypted (§4.7 step 8).
struct Decrypted {
    item_key: Key,
    payload: Payload,
}

/// §4.7 steps 1–4: size, header and bounds, Argon2id, then the master key.
fn unlock(file: &[u8], passphrase: &Passphrase) -> Result<(Header, Key), Error> {
    let header = format::parse_header(file)?;
    let kek = crypto::derive_kek(passphrase, &header.kdf_salt, header.kdf)?;
    let prefix: &[u8; HEADER_PREFIX_LEN] = file
        .get(..HEADER_PREFIX_LEN)
        .and_then(|p| p.try_into().ok())
        .ok_or(FormatError::Malformed("the file is too short"))?;
    let master_key = crypto::unwrap_key(
        &kek,
        &header.mk_nonce,
        &crypto::aad_master_key(prefix),
        &header.mk_box,
    )
    .map_err(|_| Error::Unlock)?;
    Ok((header, master_key))
}

/// §4.7 steps 5–7: subkeys, the file MAC in constant time, the records, then
/// the audit key. Nothing past the header is parsed before the MAC passes.
fn verify(file: &[u8], header: Header, master_key: &Key) -> Result<Verified, Error> {
    let subkeys = crypto::derive_subkeys(master_key, &header.vault_id)?;
    let body_len = file
        .len()
        .checked_sub(MAC_LEN)
        .ok_or(FormatError::Malformed("the file is too short"))?;
    let (body, mac) = file
        .split_at_checked(body_len)
        .ok_or(FormatError::Malformed("the file is too short"))?;
    crypto::verify_file_mac(&subkeys.mac, body, mac)
        .map_err(|_| Error::Auth("the file MAC does not match"))?;
    let records = format::parse_records(file)?;
    let audit_key = crypto::unwrap_key(
        &subkeys.wrap,
        &header.ak_nonce,
        &crypto::aad_audit_key(&header.vault_id),
        &header.ak_box,
    )
    .map_err(|_| Error::Auth("the audit key does not decrypt"))?;
    Ok(Verified {
        header,
        records,
        subkeys,
        audit_key,
    })
}

impl Verified {
    /// §4.7 step 8 for every record, then the uniqueness check of §4.3, which
    /// can only run once the names are decrypted.
    fn decrypt_all(&self) -> Result<Vec<Decrypted>, Error> {
        let vault_id = &self.header.vault_id;
        let mut seen = BTreeSet::new();
        let mut out = Vec::with_capacity(self.records.len());
        for record in &self.records {
            let item_key = crypto::unwrap_key(
                &self.subkeys.wrap,
                &record.ik_nonce,
                &crypto::aad_item_key(vault_id, &record.item_id),
                &record.ik_box,
            )
            .map_err(|_| Error::Auth("an item key does not decrypt"))?;
            let plain = crypto::open(
                &item_key,
                &record.payload_nonce,
                &crypto::aad_item(vault_id, &record.item_id),
                &record.payload_box,
            )
            .map_err(|_| Error::Auth("an item does not decrypt"))?;
            let payload = format::decode_payload(plain.expose())?;
            if !seen.insert((payload.project.clone(), payload.item.clone())) {
                return Err(
                    FormatError::Malformed("two records hold the same project and item").into(),
                );
            }
            out.push(Decrypted { item_key, payload });
        }
        Ok(out)
    }

    fn items(&self) -> Result<Vec<Item>, Error> {
        Ok(self
            .decrypt_all()?
            .into_iter()
            .zip(&self.records)
            .map(|(d, r)| Item {
                item_id: r.item_id,
                project: d.payload.project,
                item: d.payload.item,
                fields: d.payload.fields,
            })
            .collect())
    }
}

/// The whole vault file: the body, then the MAC under `K_mac`.
fn seal_file(header: &Header, records: &[Record], k_mac: &Key) -> Result<Vec<u8>, Error> {
    let mut bytes = format::encode_body(header, records)?;
    let mac = crypto::file_mac(k_mac, &bytes)?;
    bytes.extend_from_slice(&mac);
    Ok(bytes)
}

/// Wraps `master_key` under a KEK derived from `passphrase` with a new salt
/// and nonce. Returns the header fields that change: salt, nonce and box.
fn wrap_master_key(
    vault_id: &[u8; ID_LEN],
    kdf: KdfParams,
    passphrase: &Passphrase,
    master_key: &Key,
) -> Result<Header, Error> {
    let kdf_salt = crypto::random_array()?;
    let kek = crypto::derive_kek(passphrase, &kdf_salt, kdf)?;
    let mk_nonce = crypto::random_array()?;
    let prefix = format::encode_prefix(vault_id, kdf, &kdf_salt);
    let mk_box = crypto::wrap_key(
        &kek,
        &mk_nonce,
        &crypto::aad_master_key(&prefix),
        master_key,
    )?;
    Ok(Header {
        vault_id: *vault_id,
        kdf,
        kdf_salt,
        mk_nonce,
        mk_box,
        ak_nonce: [0; crypto::NONCE_LEN],
        ak_box: [0; crypto::WRAPPED_KEY_LEN],
    })
}

/// Seals a payload under its item key with a fresh nonce.
fn seal_payload(
    vault_id: &[u8; ID_LEN],
    item_id: &[u8; ID_LEN],
    item_key: &Key,
    payload: &Payload,
) -> Result<([u8; crypto::NONCE_LEN], Vec<u8>), Error> {
    let plain = format::encode_payload(payload)?;
    let nonce = crypto::random_array()?;
    let sealed = crypto::seal(
        item_key,
        &nonce,
        &crypto::aad_item(vault_id, item_id),
        plain.expose(),
    )?;
    Ok((nonce, sealed))
}

/// Wraps an item key under `K_wrap` with a fresh nonce.
fn wrap_item_key(
    subkeys: &Subkeys,
    vault_id: &[u8; ID_LEN],
    item_id: &[u8; ID_LEN],
    item_key: &Key,
) -> Result<([u8; crypto::NONCE_LEN], [u8; crypto::WRAPPED_KEY_LEN]), Error> {
    let nonce = crypto::random_array()?;
    let wrapped = crypto::wrap_key(
        &subkeys.wrap,
        &nonce,
        &crypto::aad_item_key(vault_id, item_id),
        item_key,
    )?;
    Ok((nonce, wrapped))
}

/// Runs §4.7 steps 1–8 on a vault image in memory and returns every item.
/// Nothing is read from or written to disk.
pub fn decrypt_bytes(file: &[u8], passphrase: &Passphrase) -> Result<Vec<Item>, Error> {
    let (header, master_key) = unlock(file, passphrase)?;
    verify(file, header, &master_key)?.items()
}

/// Reads and fully verifies the vault in `dir` with a passphrase: the start
/// of `passwd` and `rotate`, which always ask for the current passphrase.
fn unlock_dir(dir: &Path, passphrase: &Passphrase) -> Result<(Verified, Key), Error> {
    paths::check_dir(dir)?;
    let file = store::read_vault(dir)?;
    let (header, master_key) = unlock(&file, passphrase)?;
    Ok((verify(&file, header, &master_key)?, master_key))
}

/// Changes the passphrase (§4.8, D-004): a new salt, the default Argon2id
/// parameters, a new KEK, and the same master key wrapped again. The audit
/// key's box and every record keep their exact bytes.
pub fn passwd(dir: &Path, current: &Passphrase, new: &Passphrase) -> Result<(), Error> {
    paths::check_dir(dir)?;
    let lock = store::lock(dir)?;
    let (old, master_key) = unlock_dir(dir, current)?;
    let header = Header {
        ak_nonce: old.header.ak_nonce,
        ak_box: old.header.ak_box,
        ..wrap_master_key(&old.header.vault_id, KdfParams::DEFAULT, new, &master_key)?
    };
    let bytes = seal_file(&header, &old.records, &old.subkeys.mac)?;
    store::replace_vault(dir, &lock, &bytes)
}

/// Rotates every key (§4.8, D-004, D-034): a new salt, the default Argon2id
/// parameters, a new master key and new item keys, and every payload
/// encrypted again with fresh nonces. `vault_id`, every `item_id` and the
/// audit key stay the same; the audit key is wrapped again under the new
/// master key.
pub fn rotate(dir: &Path, passphrase: &Passphrase) -> Result<(), Error> {
    paths::check_dir(dir)?;
    let lock = store::lock(dir)?;
    let (old, _old_master_key) = unlock_dir(dir, passphrase)?;
    let decrypted = old.decrypt_all()?;
    let vault_id = old.header.vault_id;

    let master_key = crypto::random_key()?;
    let subkeys = crypto::derive_subkeys(&master_key, &vault_id)?;
    let ak_nonce = crypto::random_array()?;
    let ak_box = crypto::wrap_key(
        &subkeys.wrap,
        &ak_nonce,
        &crypto::aad_audit_key(&vault_id),
        &old.audit_key,
    )?;
    let header = Header {
        ak_nonce,
        ak_box,
        ..wrap_master_key(&vault_id, KdfParams::DEFAULT, passphrase, &master_key)?
    };
    let mut records = Vec::with_capacity(decrypted.len());
    for (record, item) in old.records.iter().zip(&decrypted) {
        let item_key = crypto::random_key()?;
        let (ik_nonce, ik_box) = wrap_item_key(&subkeys, &vault_id, &record.item_id, &item_key)?;
        let (payload_nonce, payload_box) =
            seal_payload(&vault_id, &record.item_id, &item_key, &item.payload)?;
        records.push(Record {
            item_id: record.item_id,
            ik_nonce,
            ik_box,
            payload_nonce,
            payload_box,
        });
    }
    let bytes = seal_file(&header, &records, &subkeys.mac)?;
    store::replace_vault(dir, &lock, &bytes)
}

impl Vault {
    /// Creates an empty vault with fresh keys in `dir`, creating `dir` with
    /// mode 0700 if it is missing. Refuses if a vault is already there.
    ///
    /// `kdf` exists so tests can use cheap parameters (D-001); the CLI's
    /// `init` always passes [`KdfParams::DEFAULT`].
    pub fn create(dir: &Path, passphrase: &Passphrase, kdf: KdfParams) -> Result<Vault, Error> {
        kdf.check().map_err(Error::BadParams)?;
        // Not through `From`: a missing parent here is not "no vault yet".
        paths::ensure_dir(dir).map_err(Error::Path)?;
        let lock = store::lock(dir)?;
        if store::vault_exists(dir)? {
            return Err(Error::Exists(dir.to_path_buf()));
        }
        let vault_id = crypto::random_array()?;
        let master_key = crypto::random_key()?;
        let audit_key = crypto::random_key()?;
        let subkeys = crypto::derive_subkeys(&master_key, &vault_id)?;
        let ak_nonce = crypto::random_array()?;
        let ak_box = crypto::wrap_key(
            &subkeys.wrap,
            &ak_nonce,
            &crypto::aad_audit_key(&vault_id),
            &audit_key,
        )?;
        let header = Header {
            ak_nonce,
            ak_box,
            ..wrap_master_key(&vault_id, kdf, passphrase, &master_key)?
        };
        let bytes = seal_file(&header, &[], &subkeys.mac)?;
        store::replace_vault(dir, &lock, &bytes)?;
        Ok(Vault {
            dir: dir.to_path_buf(),
            vault_id,
            kdf,
            master_key,
        })
    }

    /// Opens the vault in `dir`: §4.7 steps 1–7.
    pub fn open(dir: &Path, passphrase: &Passphrase) -> Result<Vault, Error> {
        let (verified, master_key) = unlock_dir(dir, passphrase)?;
        Ok(Vault {
            dir: dir.to_path_buf(),
            vault_id: verified.header.vault_id,
            kdf: verified.header.kdf,
            master_key,
        })
    }

    /// The directory this vault lives in.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The vault's permanent random ID.
    pub fn vault_id(&self) -> [u8; ID_LEN] {
        self.vault_id
    }

    /// The Argon2id parameters in the header when the vault was opened. If
    /// [`KdfParams::below_defaults`], the CLI warns and suggests `passwd`.
    pub fn kdf_params(&self) -> KdfParams {
        self.kdf
    }

    /// Re-reads the file and verifies it under the master key held since
    /// `open`. A file that now belongs to another vault, or was rotated
    /// elsewhere, fails here.
    fn load(&self) -> Result<Verified, Error> {
        paths::check_dir(&self.dir)?;
        let file = store::read_vault(&self.dir)?;
        let header = format::parse_header(&file)?;
        if header.vault_id != self.vault_id {
            return Err(Error::Auth(
                "the vault file now belongs to a different vault",
            ));
        }
        verify(&file, header, &self.master_key)
    }

    /// Every item, decrypted, in record order.
    pub fn items(&self) -> Result<Vec<Item>, Error> {
        self.load()?.items()
    }

    /// Every `project/item/field` name, sorted, optionally for one project
    /// only. Never values.
    pub fn list(&self, project: Option<&Name>) -> Result<Vec<Entry>, Error> {
        let mut entries: Vec<Entry> = self
            .items()?
            .into_iter()
            .filter(|item| project.is_none_or(|p| *p == item.project))
            .flat_map(|item| {
                let Item {
                    project,
                    item,
                    fields,
                    ..
                } = item;
                fields.into_keys().map(move |field| Entry {
                    project: project.clone(),
                    item: item.clone(),
                    field,
                })
            })
            .collect();
        entries.sort();
        Ok(entries)
    }

    /// The value at `project/item/field`.
    pub fn get(&self, project: &Name, item: &Name, field: &Name) -> Result<SecretValue, Error> {
        self.items()?
            .iter()
            .find(|i| i.project == *project && i.item == *item)
            .and_then(|i| i.fields.get(field))
            .map(SecretValue::duplicate)
            .ok_or_else(|| Error::NotFound(format!("{project}/{item}/{field}")))
    }

    /// Sets `project/item/field`, creating the item if needed (§4.8). An
    /// existing item keeps its item key and gets its payload encrypted again
    /// with a fresh nonce; a new item gets a new `item_id` and item key.
    pub fn set(
        &self,
        project: &Name,
        item: &Name,
        field: &Name,
        value: &SecretValue,
    ) -> Result<(), Error> {
        if value.len() > MAX_VALUE_LEN {
            return Err(Error::ValueTooLarge);
        }
        let lock = store::lock(&self.dir)?;
        let current = self.load()?;
        let mut decrypted = current.decrypt_all()?;
        let mut records = current.records.clone();
        let vault_id = &self.vault_id;
        let found = decrypted
            .iter()
            .position(|d| d.payload.project == *project && d.payload.item == *item);
        match found {
            Some(index) => {
                let (Some(entry), Some(record)) =
                    (decrypted.get_mut(index), records.get_mut(index))
                else {
                    return Err(Error::Auth("records and items are out of step"));
                };
                entry
                    .payload
                    .fields
                    .insert(field.clone(), value.duplicate());
                let (nonce, sealed) =
                    seal_payload(vault_id, &record.item_id, &entry.item_key, &entry.payload)?;
                record.payload_nonce = nonce;
                record.payload_box = sealed;
            }
            None => {
                let (item_id, index) = fresh_item_id(&records)?;
                let item_key = crypto::random_key()?;
                let (ik_nonce, ik_box) =
                    wrap_item_key(&current.subkeys, vault_id, &item_id, &item_key)?;
                let payload = Payload {
                    project: project.clone(),
                    item: item.clone(),
                    fields: BTreeMap::from([(field.clone(), value.duplicate())]),
                };
                let (payload_nonce, payload_box) =
                    seal_payload(vault_id, &item_id, &item_key, &payload)?;
                records.insert(
                    index,
                    Record {
                        item_id,
                        ik_nonce,
                        ik_box,
                        payload_nonce,
                        payload_box,
                    },
                );
            }
        }
        let bytes = seal_file(&current.header, &records, &current.subkeys.mac)?;
        store::replace_vault(&self.dir, &lock, &bytes)
    }

    /// Removes `project/item/field`. Removing an item's last field removes
    /// the whole record (D-028).
    pub fn rm(&self, project: &Name, item: &Name, field: &Name) -> Result<Removed, Error> {
        let lock = store::lock(&self.dir)?;
        let current = self.load()?;
        let mut decrypted = current.decrypt_all()?;
        let mut records = current.records.clone();
        let not_found = || Error::NotFound(format!("{project}/{item}/{field}"));
        let index = decrypted
            .iter()
            .position(|d| d.payload.project == *project && d.payload.item == *item)
            .ok_or_else(not_found)?;
        let (Some(entry), Some(record)) = (decrypted.get_mut(index), records.get_mut(index)) else {
            return Err(Error::Auth("records and items are out of step"));
        };
        entry.payload.fields.remove(field).ok_or_else(not_found)?;
        let removed = if entry.payload.fields.is_empty() {
            records.remove(index);
            Removed::Item
        } else {
            let (nonce, sealed) = seal_payload(
                &self.vault_id,
                &record.item_id,
                &entry.item_key,
                &entry.payload,
            )?;
            record.payload_nonce = nonce;
            record.payload_box = sealed;
            Removed::Field
        };
        let bytes = seal_file(&current.header, &records, &current.subkeys.mac)?;
        store::replace_vault(&self.dir, &lock, &bytes)?;
        Ok(removed)
    }
}

/// A random `item_id` not already in `records`, and where it goes to keep
/// the records sorted.
fn fresh_item_id(records: &[Record]) -> Result<([u8; ID_LEN], usize), Error> {
    for _ in 0..8 {
        let id: [u8; ID_LEN] = crypto::random_array()?;
        if let Err(index) = records.binary_search_by(|r| r.item_id.cmp(&id)) {
            return Ok((id, index));
        }
    }
    // Eight 128-bit collisions in a row: the generator is broken.
    Err(Error::Random)
}

#[cfg(test)]
mod tests;
