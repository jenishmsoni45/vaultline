//! Argon2id, HKDF-SHA-256, XChaCha20-Poly1305 and HMAC-SHA-256, wired
//! exactly as `docs/vault-format.md` §2–§4.5 specifies.
//!
//! vaultline implements no primitive (NFR-1). This module only chooses
//! parameters, builds associated data, draws nonces and keys from the OS
//! random number generator, and makes sure every secret buffer it creates is
//! wiped on drop (D-017).

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::format::{FORMAT_VERSION, HEADER_PREFIX_LEN};
use crate::secret::{KEY_LEN, Key, Passphrase, SecretBytes};

/// XChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// A wrapped 32-byte key followed by its tag.
pub const WRAPPED_KEY_LEN: usize = 48;
/// Length of `vault_id` and of every `item_id`.
pub const ID_LEN: usize = 16;
/// Length of `kdf_salt`.
pub const SALT_LEN: usize = 16;
/// HMAC-SHA-256 output length.
pub const MAC_LEN: usize = 32;

const LABEL_MASTER_KEY: &[u8] = b"vaultline v1 master-key";
const LABEL_AUDIT_KEY: &[u8] = b"vaultline v1 audit-key";
const LABEL_ITEM_KEY: &[u8] = b"vaultline v1 item-key";
const LABEL_ITEM: &[u8] = b"vaultline v1 item";
const INFO_WRAP: &[u8] = b"vaultline v1 wrap";
const INFO_FILE_MAC: &[u8] = b"vaultline v1 file-mac";

type HmacSha256 = Hmac<Sha256>;

/// A failure inside this module. None of them carries data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// The OS random number generator failed.
    Random,
    /// Argon2id or HKDF rejected its input.
    Kdf,
    /// An AEAD tag didn't verify, or a length was wrong.
    Aead,
    /// A MAC didn't verify.
    Mac,
}

/// Argon2id parameters as stored in the vault header (§4.4, D-001).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Iterations.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl KdfParams {
    /// What `init`, `passwd` and `rotate` write: 256 MiB, t=3, p=4 (D-001).
    pub const DEFAULT: KdfParams = KdfParams {
        m_kib: 262_144,
        t: 3,
        p: 4,
    };
    /// Largest memory the parser accepts: 1 GiB.
    pub const MAX_M_KIB: u32 = 1_048_576;
    /// Most iterations the parser accepts.
    pub const MAX_T: u32 = 10;
    /// Most lanes the parser accepts.
    pub const MAX_P: u32 = 8;

    /// Checks the bounds in §4.4: `kdf_p` 1–8, `kdf_t` 1–10 and `kdf_m_kib`
    /// from 8 × `kdf_p` up to 1 GiB.
    pub fn check(&self) -> Result<(), &'static str> {
        if !(1..=Self::MAX_P).contains(&self.p) {
            return Err("kdf_p is outside 1-8");
        }
        if !(1..=Self::MAX_T).contains(&self.t) {
            return Err("kdf_t is outside 1-10");
        }
        let min_m = self.p.saturating_mul(8);
        if !(min_m..=Self::MAX_M_KIB).contains(&self.m_kib) {
            return Err("kdf_m_kib is outside 8 x kdf_p to 1 GiB");
        }
        Ok(())
    }

    /// Whether any parameter is below the defaults. Opening such a vault
    /// should print a warning that suggests `vaultline passwd` (§4.4).
    pub fn below_defaults(&self) -> bool {
        self.m_kib < Self::DEFAULT.m_kib || self.t < Self::DEFAULT.t || self.p < Self::DEFAULT.p
    }
}

/// `N` bytes from the OS random number generator, for IDs, salts and nonces.
pub fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| CryptoError::Random)?;
    Ok(bytes)
}

/// A fresh random key.
pub fn random_key() -> Result<Key, CryptoError> {
    Key::random().map_err(|_| CryptoError::Random)
}

/// KEK = Argon2id(passphrase, salt, m, t, p), version 0x13, 32 bytes (§3).
///
/// The bounds are checked again here, so no caller can run Argon2id past the
/// ceiling. The working memory is allocated here and wiped before it is
/// freed: argon2's own allocating path frees its blocks without wiping them,
/// even with its `zeroize` feature on.
pub fn derive_kek(
    passphrase: &Passphrase,
    salt: &[u8; SALT_LEN],
    kdf: KdfParams,
) -> Result<Key, CryptoError> {
    kdf.check().map_err(|_| CryptoError::Kdf)?;
    let params =
        Params::new(kdf.m_kib, kdf.t, kdf.p, Some(KEY_LEN)).map_err(|_| CryptoError::Kdf)?;
    let blocks = params.block_count();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut memory = Zeroizing::new(vec![Block::new(); blocks]);
    let mut kek = Key::zeroed();
    #[cfg(feature = "test-support")]
    testing::count_kdf_call();
    argon2
        .hash_password_into_with_memory(
            passphrase.expose(),
            salt,
            kek.as_mut_bytes(),
            memory.as_mut_slice(),
        )
        .map_err(|_| CryptoError::Kdf)?;
    Ok(kek)
}

/// `K_wrap` and `K_mac`, derived from the master key (§3).
pub struct Subkeys {
    pub(crate) wrap: Key,
    pub(crate) mac: Key,
}

/// HKDF-SHA-256 with salt = `vault_id` and IKM = the master key, expanded
/// under two different `info` labels (§3).
pub fn derive_subkeys(master_key: &Key, vault_id: &[u8; ID_LEN]) -> Result<Subkeys, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(vault_id), master_key.as_bytes());
    let mut wrap = Key::zeroed();
    hkdf.expand(INFO_WRAP, wrap.as_mut_bytes())
        .map_err(|_| CryptoError::Kdf)?;
    let mut mac = Key::zeroed();
    hkdf.expand(INFO_FILE_MAC, mac.as_mut_bytes())
        .map_err(|_| CryptoError::Kdf)?;
    Ok(Subkeys { wrap, mac })
}

fn cipher(key: &Key) -> Result<XChaCha20Poly1305, CryptoError> {
    XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::Aead)
}

/// XChaCha20-Poly1305: returns the ciphertext followed by its 16-byte tag.
/// The plaintext is copied into a wiped buffer and encrypted in place there.
pub fn seal(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = cipher(key)?;
    let mut buffer = SecretBytes::with_capacity(plaintext.len());
    buffer.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_inout_detached(&XNonce::from(*nonce), aad, buffer.as_mut_slice().into())
        .map_err(|_| CryptoError::Aead)?;
    let len = plaintext
        .len()
        .checked_add(TAG_LEN)
        .ok_or(CryptoError::Aead)?;
    let mut sealed = Vec::with_capacity(len);
    sealed.extend_from_slice(buffer.expose());
    sealed.extend_from_slice(&tag);
    Ok(sealed)
}

/// Verifies the tag, then decrypts into a wiped buffer.
pub fn open(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    sealed: &[u8],
) -> Result<SecretBytes, CryptoError> {
    let ct_len = sealed.len().checked_sub(TAG_LEN).ok_or(CryptoError::Aead)?;
    let (ciphertext, tag) = sealed.split_at_checked(ct_len).ok_or(CryptoError::Aead)?;
    let tag = Tag::try_from(tag).map_err(|_| CryptoError::Aead)?;
    let cipher = cipher(key)?;
    let mut buffer = SecretBytes::with_capacity(ct_len);
    buffer.extend_from_slice(ciphertext);
    cipher
        .decrypt_inout_detached(
            &XNonce::from(*nonce),
            aad,
            buffer.as_mut_slice().into(),
            &tag,
        )
        .map_err(|_| CryptoError::Aead)?;
    Ok(buffer)
}

/// Wraps a 32-byte key: the 48-byte `*_box` of §4.1 and §4.2.
pub fn wrap_key(
    kek: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    key: &Key,
) -> Result<[u8; WRAPPED_KEY_LEN], CryptoError> {
    seal(kek, nonce, aad, key.as_bytes())?
        .try_into()
        .map_err(|_| CryptoError::Aead)
}

/// Unwraps a 48-byte `*_box` into a key.
pub fn unwrap_key(
    kek: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    wrapped: &[u8; WRAPPED_KEY_LEN],
) -> Result<Key, CryptoError> {
    let plain = open(kek, nonce, aad, wrapped)?;
    Key::from_slice(plain.expose()).ok_or(CryptoError::Aead)
}

fn hmac(key: &Key) -> Result<HmacSha256, CryptoError> {
    <HmacSha256 as KeyInit>::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::Mac)
}

/// `file_mac` = HMAC-SHA-256(`K_mac`, every byte before it) (§4.1).
pub fn file_mac(k_mac: &Key, body: &[u8]) -> Result<[u8; MAC_LEN], CryptoError> {
    let mut mac = hmac(k_mac)?;
    mac.update(body);
    Ok(mac.finalize().into_bytes().into())
}

/// Checks `file_mac` in constant time (§4.7 step 5).
pub fn verify_file_mac(k_mac: &Key, body: &[u8], expected: &[u8]) -> Result<(), CryptoError> {
    let mut mac = hmac(k_mac)?;
    mac.update(body);
    mac.verify_slice(expected).map_err(|_| CryptoError::Mac)
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let len = parts
        .iter()
        .map(|p| p.len())
        .fold(0usize, usize::saturating_add);
    let mut out = Vec::with_capacity(len);
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

/// AAD for `mk_box`: `"vaultline v1 master-key"` ‖ file[0..54) (77 bytes).
pub fn aad_master_key(header_prefix: &[u8; HEADER_PREFIX_LEN]) -> Vec<u8> {
    concat(&[LABEL_MASTER_KEY, header_prefix])
}

/// AAD for `ak_box`: `"vaultline v1 audit-key"` ‖ version ‖ `vault_id` (40 bytes).
pub fn aad_audit_key(vault_id: &[u8; ID_LEN]) -> Vec<u8> {
    concat(&[LABEL_AUDIT_KEY, &FORMAT_VERSION.to_le_bytes(), vault_id])
}

/// AAD for `ik_box`: `"vaultline v1 item-key"` ‖ version ‖ `vault_id` ‖
/// `item_id` (55 bytes).
pub fn aad_item_key(vault_id: &[u8; ID_LEN], item_id: &[u8; ID_LEN]) -> Vec<u8> {
    concat(&[
        LABEL_ITEM_KEY,
        &FORMAT_VERSION.to_le_bytes(),
        vault_id,
        item_id,
    ])
}

/// AAD for `payload_box`: `"vaultline v1 item"` ‖ version ‖ `vault_id` ‖
/// `item_id` (51 bytes).
pub fn aad_item(vault_id: &[u8; ID_LEN], item_id: &[u8; ID_LEN]) -> Vec<u8> {
    concat(&[LABEL_ITEM, &FORMAT_VERSION.to_le_bytes(), vault_id, item_id])
}

/// Test-only counter of Argon2id runs on the current thread (P2-8).
#[cfg(feature = "test-support")]
pub(crate) mod testing {
    use std::cell::Cell;

    thread_local! {
        static KDF_CALLS: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn count_kdf_call() {
        KDF_CALLS.set(KDF_CALLS.get().saturating_add(1));
    }

    pub(crate) fn kdf_calls() -> u64 {
        KDF_CALLS.get()
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

    const CHEAP: KdfParams = KdfParams {
        m_kib: 8,
        t: 1,
        p: 1,
    };

    fn key(byte: u8) -> Key {
        Key::from_slice(&[byte; KEY_LEN]).unwrap()
    }

    #[test]
    fn associated_data_has_the_specified_bytes_and_lengths() {
        let prefix = [0xAB; HEADER_PREFIX_LEN];
        let vid = [1; ID_LEN];
        let iid = [2; ID_LEN];

        let mk = aad_master_key(&prefix);
        assert_eq!(mk.len(), 77);
        assert_eq!(&mk[..23], b"vaultline v1 master-key");
        assert_eq!(&mk[23..], &prefix);

        let ak = aad_audit_key(&vid);
        assert_eq!(ak.len(), 40);
        assert_eq!(ak, [&b"vaultline v1 audit-key"[..], &[1, 0], &vid].concat());

        let ik = aad_item_key(&vid, &iid);
        assert_eq!(ik.len(), 55);
        assert_eq!(
            ik,
            [&b"vaultline v1 item-key"[..], &[1, 0], &vid, &iid].concat()
        );

        let item = aad_item(&vid, &iid);
        assert_eq!(item.len(), 51);
        assert_eq!(
            item,
            [&b"vaultline v1 item"[..], &[1, 0], &vid, &iid].concat()
        );
    }

    #[test]
    fn seal_then_open_round_trips_and_binds_key_nonce_and_aad() {
        let k = key(7);
        let nonce = [9; NONCE_LEN];
        let sealed = seal(&k, &nonce, b"aad", b"fake-plaintext").unwrap();
        assert_eq!(sealed.len(), 14 + TAG_LEN);
        assert_ne!(&sealed[..14], b"fake-plaintext");
        assert_eq!(
            open(&k, &nonce, b"aad", &sealed).unwrap().expose(),
            b"fake-plaintext"
        );

        assert_eq!(
            open(&key(8), &nonce, b"aad", &sealed).err(),
            Some(CryptoError::Aead)
        );
        assert_eq!(
            open(&k, &[0; NONCE_LEN], b"aad", &sealed).err(),
            Some(CryptoError::Aead)
        );
        assert_eq!(
            open(&k, &nonce, b"aad2", &sealed).err(),
            Some(CryptoError::Aead)
        );
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert_eq!(
                open(&k, &nonce, b"aad", &bad).err(),
                Some(CryptoError::Aead)
            );
        }
        assert_eq!(
            open(&k, &nonce, b"aad", &sealed[..15]).err(),
            Some(CryptoError::Aead)
        );
    }

    #[test]
    fn wrapped_keys_are_48_bytes_and_unwrap() {
        let kek = key(1);
        let wrapped = wrap_key(&kek, &[3; NONCE_LEN], b"x", &key(5)).unwrap();
        assert_eq!(wrapped.len(), WRAPPED_KEY_LEN);
        let back = unwrap_key(&kek, &[3; NONCE_LEN], b"x", &wrapped).unwrap();
        assert_eq!(back.as_bytes(), &[5; KEY_LEN]);
    }

    #[test]
    fn subkeys_are_distinct_and_depend_on_master_key_and_vault_id() {
        let a = derive_subkeys(&key(1), &[0; ID_LEN]).unwrap();
        assert_ne!(a.wrap.as_bytes(), a.mac.as_bytes());
        let b = derive_subkeys(&key(1), &[1; ID_LEN]).unwrap();
        assert_ne!(a.wrap.as_bytes(), b.wrap.as_bytes());
        assert_ne!(a.mac.as_bytes(), b.mac.as_bytes());
        let c = derive_subkeys(&key(2), &[0; ID_LEN]).unwrap();
        assert_ne!(a.wrap.as_bytes(), c.wrap.as_bytes());
        let again = derive_subkeys(&key(1), &[0; ID_LEN]).unwrap();
        assert_eq!(a.wrap.as_bytes(), again.wrap.as_bytes());
    }

    #[test]
    fn hkdf_matches_rfc_5869_extract_then_expand() {
        // Cross-check the wiring against HMAC directly: PRK = HMAC(salt, IKM),
        // T(1) = HMAC(PRK, info || 0x01).
        let mk = key(0x42);
        let vid = [0x24; ID_LEN];
        let mut prk = <HmacSha256 as KeyInit>::new_from_slice(&vid).unwrap();
        prk.update(mk.as_bytes());
        let prk = prk.finalize().into_bytes();
        let mut t1 = <HmacSha256 as KeyInit>::new_from_slice(&prk).unwrap();
        t1.update(b"vaultline v1 wrap\x01");
        let expected: [u8; 32] = t1.finalize().into_bytes().into();
        let subkeys = derive_subkeys(&mk, &vid).unwrap();
        assert_eq!(subkeys.wrap.as_bytes(), &expected);
    }

    #[test]
    fn file_mac_verifies_and_rejects_changes() {
        let k = key(4);
        let mac = file_mac(&k, b"body").unwrap();
        assert!(verify_file_mac(&k, b"body", &mac).is_ok());
        assert_eq!(verify_file_mac(&k, b"bodY", &mac), Err(CryptoError::Mac));
        assert_eq!(
            verify_file_mac(&key(5), b"body", &mac),
            Err(CryptoError::Mac)
        );
        assert_eq!(
            verify_file_mac(&k, b"body", &mac[..31]),
            Err(CryptoError::Mac)
        );
    }

    #[test]
    fn kek_depends_on_passphrase_salt_and_parameters() {
        let p = Passphrase::new(b"fake-passphrase-one");
        let a = derive_kek(&p, &[1; SALT_LEN], CHEAP).unwrap();
        let again = derive_kek(&p, &[1; SALT_LEN], CHEAP).unwrap();
        assert_eq!(a.as_bytes(), again.as_bytes());
        let other_salt = derive_kek(&p, &[2; SALT_LEN], CHEAP).unwrap();
        assert_ne!(a.as_bytes(), other_salt.as_bytes());
        let other_t = derive_kek(&p, &[1; SALT_LEN], KdfParams { t: 2, ..CHEAP }).unwrap();
        assert_ne!(a.as_bytes(), other_t.as_bytes());
        let other_pass = derive_kek(
            &Passphrase::new(b"fake-passphrase-two"),
            &[1; SALT_LEN],
            CHEAP,
        )
        .unwrap();
        assert_ne!(a.as_bytes(), other_pass.as_bytes());
    }

    #[test]
    fn kek_refuses_parameters_outside_the_bounds() {
        let p = Passphrase::new(b"fake-passphrase");
        let over = KdfParams {
            m_kib: KdfParams::MAX_M_KIB + 1,
            t: 1,
            p: 1,
        };
        assert_eq!(
            derive_kek(&p, &[0; SALT_LEN], over).err(),
            Some(CryptoError::Kdf)
        );
        let zero = KdfParams {
            m_kib: 8,
            t: 0,
            p: 1,
        };
        assert_eq!(
            derive_kek(&p, &[0; SALT_LEN], zero).err(),
            Some(CryptoError::Kdf)
        );
    }

    #[test]
    fn below_defaults_flags_any_cheaper_parameter() {
        assert!(!KdfParams::DEFAULT.below_defaults());
        assert!(CHEAP.below_defaults());
        assert!(
            KdfParams {
                t: 2,
                ..KdfParams::DEFAULT
            }
            .below_defaults()
        );
        assert!(KdfParams::DEFAULT.check().is_ok());
    }

    #[test]
    fn random_values_differ() {
        let a: [u8; 24] = random_array().unwrap();
        let b: [u8; 24] = random_array().unwrap();
        assert_ne!(a, b);
        assert_ne!(
            random_key().unwrap().as_bytes(),
            random_key().unwrap().as_bytes()
        );
    }
}
