//! Test-only hooks, compiled only with the `test-support` feature, which only
//! this crate's own tests turn on (`Cargo.toml`). A normal build of the
//! library or the binary contains none of this.

use super::crypto::{self, MAC_LEN};
use super::format::FormatError;
use super::{Error, store};
use crate::secret::Passphrase;

pub use super::store::Fault;

/// Makes the next vault write on this thread fail at `fault` (P2-10).
pub fn inject_fault(fault: Fault) {
    store::faults::inject(fault);
}

/// How many times Argon2id has started on this thread (P2-8).
pub fn kdf_calls() -> u64 {
    crypto::testing::kdf_calls()
}

/// The re-MAC helper of `docs/design.md` §2 (S3): unlocks the master key with
/// `passphrase`, then recomputes `file_mac` over everything before it. This
/// lets a test edit records and still get past the file MAC, so the AEAD
/// layer is tested on its own.
pub fn remac(file: &[u8], passphrase: &Passphrase) -> Result<Vec<u8>, Error> {
    let (header, master_key) = super::unlock(file, passphrase)?;
    let subkeys = crypto::derive_subkeys(&master_key, &header.vault_id)?;
    let body = file
        .len()
        .checked_sub(MAC_LEN)
        .and_then(|len| file.get(..len))
        .ok_or(FormatError::Malformed("the file is too short"))?;
    let mac = crypto::file_mac(&subkeys.mac, body)?;
    let mut out = body.to_vec();
    out.extend_from_slice(&mac);
    Ok(out)
}
