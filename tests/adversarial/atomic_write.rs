//! P2-10, NFR-12: a write that fails partway leaves the old vault byte for
//! byte intact; temporary files never contain plaintext; files are 0600 and
//! the directory 0700.
//!
//! Failures are injected into the next write on the test's own thread with
//! the test-only fault hook.

use std::fs;
use std::path::{Path, PathBuf};

use vaultline::vault::testing::{Fault, inject_fault};
use vaultline::vault::{Error, Vault, decrypt_bytes};

use crate::common::{TestVault, contains, marker, mode, name, value};

fn temp_files(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".vault.tmp-")
        })
        .collect()
}

#[test]
fn a_write_that_fails_partway_leaves_the_old_vault_intact() {
    let v = TestVault::new("fake-passphrase-atomic");
    v.set("proj", "item", "field", b"fake-original-value");
    let before = v.bytes();

    inject_fault(Fault::FailMidWrite);
    let err = v.vault.set(
        &name("proj"),
        &name("item"),
        &name("field"),
        &value(b"fake-new-value"),
    );
    assert!(
        matches!(err, Err(Error::Io { .. })),
        "the injected failure is reported"
    );
    assert_eq!(v.bytes(), before, "the old vault is byte-for-byte intact");
    assert!(
        temp_files(&v.dir).is_empty(),
        "the half-written file is removed"
    );

    let reopened = Vault::open(&v.dir, &v.passphrase()).unwrap();
    let got = reopened
        .get(&name("proj"), &name("item"), &name("field"))
        .unwrap();
    assert_eq!(got.expose(), b"fake-original-value");
}

#[test]
fn a_crash_before_the_rename_leaves_only_ciphertext_behind() {
    let v = TestVault::new("fake-passphrase-crash");
    v.set("proj", "item", "field", b"fake-original-value");
    let before = v.bytes();
    let secret = marker("crash-value");
    let field = "field-name-after-crash";

    inject_fault(Fault::CrashBeforeRename);
    let err = v.vault.set(
        &name("proj"),
        &name("item"),
        &name(field),
        &value(secret.as_bytes()),
    );
    assert!(err.is_err());
    assert_eq!(v.bytes(), before, "the old vault is byte-for-byte intact");

    let temps = temp_files(&v.dir);
    assert_eq!(temps.len(), 1, "the crash left its temporary file");
    let temp = fs::read(&temps[0]).unwrap();
    assert_eq!(mode(&temps[0]), 0o600);
    for plaintext in [secret.as_bytes(), field.as_bytes(), b"fake-original-value"] {
        assert!(
            !contains(&temp, plaintext),
            "the temporary file holds plaintext"
        );
    }
    // It is a complete encrypted vault image: the new value is in there,
    // encrypted.
    let items = decrypt_bytes(&temp, &v.passphrase()).unwrap();
    assert_eq!(items[0].fields[&name(field)].expose(), secret.as_bytes());

    // The next writer removes the leftover.
    v.set("proj", "item", "other", b"fake-later-value");
    assert!(temp_files(&v.dir).is_empty());
}

#[test]
fn files_are_0600_and_the_directory_0700() {
    let v = TestVault::new("fake-passphrase-modes");
    v.set("proj", "item", "field", b"fake-mode-value");
    assert_eq!(mode(&v.dir), 0o700);
    assert_eq!(mode(&v.dir.join("vault")), 0o600);
    assert_eq!(mode(&v.dir.join("lock")), 0o600);
}
