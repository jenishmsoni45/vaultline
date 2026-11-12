//! P2-9, NFR-11: size limits. A file over 64 MiB is rejected before it is
//! read, a value over 64 KiB is rejected, and an `item_count` larger than the
//! file can hold is rejected before anything is allocated. Names are 1–64
//! bytes.

use std::fs::OpenOptions;

use vaultline::vault::format::{self, FormatError, MAX_FILE_LEN, MAX_VALUE_LEN};
use vaultline::vault::testing::{kdf_calls, remac};
use vaultline::vault::{Error, Name, NameError, Vault};

use crate::common::{TestVault, install, name, value};

#[test]
fn a_file_over_64_mib_is_rejected_before_it_is_read() {
    let v = TestVault::new("fake-passphrase-big-file");
    // A sparse file: 64 MiB + 1 byte long, taking no space on disk.
    let file = OpenOptions::new().write(true).open(v.path()).unwrap();
    file.set_len(MAX_FILE_LEN + 1).unwrap();
    drop(file);
    let before = kdf_calls();
    let err = Vault::open(&v.dir, &v.passphrase())
        .err()
        .expect("open must fail");
    assert_eq!(kdf_calls(), before);
    assert!(
        matches!(err, Error::Format(FormatError::Malformed(m)) if m.contains("larger than 64 MiB")),
        "{err}"
    );
    assert!(format::check_file_len(MAX_FILE_LEN).is_ok());
}

#[test]
fn a_file_shorter_than_an_empty_vault_is_rejected() {
    let v = TestVault::new("fake-passphrase-short-file");
    for len in [0, 1, 54, 202, 233] {
        let (_tmp, dir) = install(&v.bytes()[..len]);
        let err = Vault::open(&dir, &v.passphrase())
            .err()
            .expect("open must fail");
        assert!(matches!(err, Error::Format(_)), "{len}: {err}");
    }
}

#[test]
fn values_are_limited_to_64_kib() {
    let v = TestVault::new("fake-passphrase-big-value");
    let max = vec![b'v'; MAX_VALUE_LEN];
    v.vault
        .set(&name("p"), &name("i"), &name("max"), &value(&max))
        .unwrap();
    let got = v.vault.get(&name("p"), &name("i"), &name("max")).unwrap();
    assert_eq!(got.len(), MAX_VALUE_LEN);

    let before = v.bytes();
    let over = vec![b'v'; MAX_VALUE_LEN + 1];
    let err = v
        .vault
        .set(&name("p"), &name("i"), &name("over"), &value(&over));
    assert!(matches!(err, Err(Error::ValueTooLarge)));
    assert_eq!(v.bytes(), before, "nothing was written");
}

#[test]
fn an_item_count_beyond_the_file_is_rejected_before_allocation() {
    let v = TestVault::new("fake-passphrase-item-count");
    v.set("proj", "item", "field", b"fake-item-count-value");
    for count in [2u32, 1_000, u32::MAX] {
        let mut bytes = v.bytes();
        bytes[198..202].copy_from_slice(&count.to_le_bytes());
        assert_eq!(
            format::parse_records(&bytes),
            Err(FormatError::Malformed(
                "item_count is larger than the file can hold"
            ))
        );
        // Through the whole open path, with the file MAC recomputed so the
        // record parser is reached.
        let (_tmp, dir) = install(&remac(&bytes, &v.passphrase()).unwrap());
        let err = Vault::open(&dir, &v.passphrase())
            .err()
            .expect("open must fail");
        assert!(
            matches!(err, Error::Format(FormatError::Malformed(m)) if m.contains("item_count")),
            "{err}"
        );
    }
}

#[test]
fn names_are_one_to_64_allowed_bytes() {
    assert!(Name::new(&"n".repeat(64)).is_ok());
    assert_eq!(Name::new(&"n".repeat(65)), Err(NameError::TooLong));
    assert_eq!(Name::new(""), Err(NameError::Empty));
    assert_eq!(Name::new("has space"), Err(NameError::BadByte));
}
