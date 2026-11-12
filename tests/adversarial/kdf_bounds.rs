//! P2-8: a header whose Argon2id parameters are outside the bounds of
//! `docs/vault-format.md` §4.4 is a format error, and Argon2id never runs.
//! `parse_header` is tested directly, and `open` is shown to return before
//! the KDF by the test-only KDF counter.

use vaultline::vault::format::{self, FormatError};
use vaultline::vault::testing::kdf_calls;
use vaultline::vault::{Error, KdfParams, Vault};

use crate::common::{TestVault, install};

fn with_kdf(file: &[u8], kdf: KdfParams) -> Vec<u8> {
    let mut bytes = file.to_vec();
    bytes[26..30].copy_from_slice(&kdf.m_kib.to_le_bytes());
    bytes[30..34].copy_from_slice(&kdf.t.to_le_bytes());
    bytes[34..38].copy_from_slice(&kdf.p.to_le_bytes());
    bytes
}

const OUT_OF_BOUNDS: [KdfParams; 9] = [
    KdfParams {
        m_kib: 1_048_577,
        t: 1,
        p: 1,
    },
    KdfParams {
        m_kib: u32::MAX,
        t: 1,
        p: 1,
    },
    KdfParams {
        m_kib: 64,
        t: 11,
        p: 1,
    },
    KdfParams {
        m_kib: 64,
        t: u32::MAX,
        p: 1,
    },
    KdfParams {
        m_kib: 128,
        t: 1,
        p: 9,
    },
    KdfParams {
        m_kib: 64,
        t: 0,
        p: 1,
    },
    KdfParams {
        m_kib: 64,
        t: 1,
        p: 0,
    },
    KdfParams {
        m_kib: 7,
        t: 1,
        p: 1,
    },
    KdfParams {
        m_kib: 31,
        t: 1,
        p: 4,
    },
];

#[test]
fn parse_header_rejects_parameters_outside_the_bounds() {
    let file = TestVault::new("fake-passphrase-kdf").bytes();
    for kdf in OUT_OF_BOUNDS {
        let result = format::parse_header(&with_kdf(&file, kdf));
        assert!(matches!(result, Err(FormatError::Malformed(_))), "{kdf:?}");
    }
}

#[test]
fn parse_header_accepts_the_bounds_themselves() {
    let file = TestVault::new("fake-passphrase-kdf-edges").bytes();
    for kdf in [
        KdfParams {
            m_kib: 1_048_576,
            t: 10,
            p: 8,
        },
        KdfParams {
            m_kib: 8,
            t: 1,
            p: 1,
        },
        KdfParams {
            m_kib: 64,
            t: 1,
            p: 8,
        },
        KdfParams::DEFAULT,
    ] {
        let header = format::parse_header(&with_kdf(&file, kdf)).unwrap();
        assert_eq!(header.kdf, kdf);
    }
}

#[test]
fn open_refuses_out_of_bounds_parameters_without_running_argon2() {
    let v = TestVault::new("fake-passphrase-kdf-open");
    for kdf in OUT_OF_BOUNDS {
        let (_tmp, dir) = install(&with_kdf(&v.bytes(), kdf));
        let before = kdf_calls();
        let result = Vault::open(&dir, &v.passphrase());
        assert_eq!(kdf_calls(), before, "Argon2id ran for {kdf:?}");
        assert!(matches!(result, Err(Error::Format(_))), "{kdf:?}");
    }
}

#[test]
fn parameters_changed_within_the_bounds_fail_to_unlock() {
    // The parameters feed the KEK and the master-key wrap's associated data.
    let v = TestVault::new("fake-passphrase-kdf-auth");
    let (_tmp, dir) = install(&with_kdf(
        &v.bytes(),
        KdfParams {
            m_kib: 8,
            t: 2,
            p: 1,
        },
    ));
    assert!(matches!(
        Vault::open(&dir, &v.passphrase()),
        Err(Error::Unlock)
    ));
}
