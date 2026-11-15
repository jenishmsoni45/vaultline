//! Secret wrapper types (`docs/design.md` §10, D-017, D-039).
//!
//! Every type here wipes its memory when dropped and implements neither
//! `Debug` nor `Display`, so a secret can't end up in an error message, a panic
//! message or a log line. The `secrecy` and `zeroize` types used inside them do
//! implement `Debug`. The pinned versions print no secret (secrecy's prints
//! `[REDACTED]`, and `Zeroizing`'s prints `Zeroizing { .. }`), but a later
//! release could change that, so they never appear on their own in a public
//! signature (D-061).
//! `tests/adversarial/secret_types.rs` checks all of this with static
//! assertions.
//!
//! Keys and values live on the heap behind `SecretBox`, so moving a wrapper
//! moves a pointer and leaves no stray copy of the secret on the stack.

use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use zeroize::Zeroizing;

/// Length in bytes of every key vaultline uses.
pub const KEY_LEN: usize = 32;

/// A 256-bit key: a KEK, the master key, a subkey, the audit key or an item key.
pub struct Key(SecretBox<[u8; KEY_LEN]>);

impl Key {
    /// A fresh key from the OS random number generator.
    pub(crate) fn random() -> Result<Self, rand_core::Error> {
        let mut key = Self::zeroed();
        OsRng.try_fill_bytes(key.as_mut_bytes())?;
        Ok(key)
    }

    /// An all-zero key, to be filled in place by a KDF or a decryption.
    pub(crate) fn zeroed() -> Self {
        Key(SecretBox::init_with_mut(|_: &mut [u8; KEY_LEN]| {}))
    }

    /// Copies a key out of a decrypted buffer. Returns `None` unless the buffer
    /// is exactly [`KEY_LEN`] bytes long.
    pub(crate) fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != KEY_LEN {
            return None;
        }
        let mut key = Self::zeroed();
        key.as_mut_bytes().copy_from_slice(bytes);
        Some(key)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        self.0.expose_secret()
    }

    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8; KEY_LEN] {
        self.0.expose_secret_mut()
    }
}

/// A passphrase, kept exactly as entered: no Unicode normalisation and no
/// trimming (`docs/vault-format.md` §3).
pub struct Passphrase(SecretBox<[u8]>);

impl Passphrase {
    /// Copies the passphrase. The caller wipes its own copy.
    pub fn new(bytes: &[u8]) -> Self {
        Passphrase(SecretBox::new(Box::from(bytes)))
    }

    /// The passphrase bytes.
    pub fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

/// A field value: arbitrary bytes, at most 64 KiB in a vault.
pub struct SecretValue(SecretBox<[u8]>);

impl SecretValue {
    /// Copies the value. The caller wipes its own copy.
    pub fn new(bytes: &[u8]) -> Self {
        SecretValue(SecretBox::new(Box::from(bytes)))
    }

    /// The value bytes.
    pub fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Length of the value in bytes.
    pub fn len(&self) -> usize {
        self.expose().len()
    }

    /// Whether the value is empty.
    pub fn is_empty(&self) -> bool {
        self.expose().is_empty()
    }

    /// A second copy of the value, also wiped on drop.
    pub fn duplicate(&self) -> Self {
        Self::new(self.expose())
    }
}

/// A plaintext buffer, such as a decrypted item payload. Its capacity is
/// reserved up front, so it never reallocates and leaves no unwiped copy
/// behind.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// An empty buffer that can hold `capacity` bytes without reallocating.
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        SecretBytes(Zeroizing::new(Vec::with_capacity(capacity)))
    }

    /// Appends bytes. Callers reserve enough capacity first; going past it
    /// would leave a stale copy in the old allocation, so debug builds check.
    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) {
        debug_assert!(
            self.0.capacity() - self.0.len() >= bytes.len(),
            "SecretBytes would reallocate"
        );
        self.0.extend_from_slice(bytes);
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }

    /// The plaintext bytes.
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}
