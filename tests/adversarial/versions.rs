//! P2-14, US-9 AC3: an unknown `format_version` gives "unsupported format
//! version N", before Argon2id runs.

use vaultline::vault::format::{self, FormatError};
use vaultline::vault::testing::kdf_calls;
use vaultline::vault::{Error, Vault};

use crate::common::{TestVault, install};

fn with_version(file: &[u8], version: u16) -> Vec<u8> {
    let mut bytes = file.to_vec();
    bytes[8..10].copy_from_slice(&version.to_le_bytes());
    bytes
}

#[test]
fn unknown_versions_are_refused_by_name() {
    let v = TestVault::new("fake-passphrase-versions");
    let file = v.bytes();
    for version in [0u16, 2, 3, 255, 256, u16::MAX] {
        let bytes = with_version(&file, version);
        assert_eq!(
            format::parse_header(&bytes),
            Err(FormatError::UnsupportedVersion(version))
        );
        let (_tmp, dir) = install(&bytes);
        let before = kdf_calls();
        let err = Vault::open(&dir, &v.passphrase())
            .err()
            .expect("open must fail");
        assert_eq!(kdf_calls(), before, "Argon2id must not run");
        assert!(matches!(err, Error::Format(FormatError::UnsupportedVersion(n)) if n == version));
        assert_eq!(
            err.to_string(),
            format!("unsupported format version {version}; a newer vaultline wrote this file")
        );
    }
}

#[test]
fn bad_magic_is_a_format_error_before_the_version_is_read() {
    let v = TestVault::new("fake-passphrase-magic");
    let mut bytes = with_version(&v.bytes(), 7);
    bytes[0] = b'V';
    assert!(matches!(
        format::parse_header(&bytes),
        Err(FormatError::Malformed(m)) if m.contains("magic")
    ));
}
