//! S4 (P2-4): a wrong passphrase gives the single unlock error, and neither
//! the wrong passphrase nor the right one appears in the error.

use vaultline::vault::{Error, Vault, decrypt_bytes};

use crate::common::{TestVault, fixture_bytes, pass};

const RIGHT: &str = "fake-passphrase-s4-right";
const UNLOCK_MESSAGE: &str = "wrong passphrase, or the vault header was modified";

fn assert_clean_unlock_error(err: Error, wrong: &str) {
    assert!(
        matches!(err, Error::Unlock),
        "expected the unlock error, got: {err}"
    );
    let shown = format!("{err} {err:?}");
    assert_eq!(err.to_string(), UNLOCK_MESSAGE);
    for secret in [wrong, RIGHT] {
        if !secret.is_empty() {
            assert!(
                !shown.contains(secret),
                "the error shows a passphrase: {shown}"
            );
        }
    }
}

#[test]
fn wrong_passphrases_give_the_unlock_error() {
    let v = TestVault::new(RIGHT);
    v.set("proj", "item", "field", b"fake-s4-value");
    let wrongs = [
        "",
        "fake-passphrase-s4-wrong",
        "fake-passphrase-s4-righ",
        "fake-passphrase-s4-right!",
        "fake-passphrase-s4-right\n",
        "Fake-passphrase-s4-right",
        " fake-passphrase-s4-right",
    ];
    for wrong in wrongs {
        let err = Vault::open(&v.dir, &pass(wrong))
            .err()
            .expect("open must fail");
        assert_clean_unlock_error(err, wrong);
        let err = decrypt_bytes(&v.bytes(), &pass(wrong))
            .err()
            .expect("decrypt must fail");
        assert_clean_unlock_error(err, wrong);
    }
    assert!(Vault::open(&v.dir, &pass(RIGHT)).is_ok());
}

#[test]
fn a_fixture_with_a_wrong_passphrase_gives_the_unlock_error() {
    let err = decrypt_bytes(
        &fixture_bytes("basic.vault"),
        &pass("fake-not-the-passphrase"),
    )
    .err()
    .expect("decrypt must fail");
    assert_clean_unlock_error(err, "fake-not-the-passphrase");
}
