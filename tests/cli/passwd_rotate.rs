//! P3-5 (US-6 AC1–4) and P3-6 (US-7 AC1, AC2): `passwd` and `rotate`.
//!
//! `passwd` and `rotate` always write the default Argon2id parameters, 256 MiB
//! (D-040), so each has exactly one test that runs them for real. They take a
//! lock and never run at the same time. Every other test here fails before the
//! key derivation or leaves the vault alone.
//!
//! US-6 AC1 is "asks for the current passphrase even when an agent is
//! unlocked". There is no agent until Phase 4, so what is tested here is that
//! the current passphrase is always required; the agent half arrives with it.

use std::sync::Mutex;

use vaultline::vault::KdfParams;
use vaultline::vault::format::{self, HEADER_LEN};

use crate::common::cli::{Sandbox, assert_no_plaintext_under};

/// Held by the two tests that use the default parameters.
static HEAVY: Mutex<()> = Mutex::new(());

const NEW_PASSPHRASE: &str = "a-new-fake-passphrase";

fn stdin(first: &str, second: &str) -> Vec<u8> {
    format!("{first}\n{second}\n").into_bytes()
}

/// The records region of a vault file: after the header and `item_count`,
/// before the file MAC.
fn records_region(file: &[u8]) -> &[u8] {
    &file[HEADER_LEN..file.len() - 32]
}

/// AC1–AC4 of US-6, with the real parameters.
#[test]
fn passwd_changes_the_passphrase_and_leaves_every_record_alone() {
    let _heavy = HEAVY.lock().unwrap_or_else(|e| e.into_inner());
    let sb = Sandbox::with_vault();
    let first = sb.secret("one", "demo", "db", "password");
    let second = sb.secret("two", "demo", "api", "key");
    sb.register(NEW_PASSPHRASE);
    let before = sb.vault_bytes();
    let header_before = format::parse_header(&before).unwrap();
    assert_ne!(
        header_before.kdf,
        KdfParams::DEFAULT,
        "the test vault is cheap"
    );

    sb.run(&["passwd"], &stdin(&sb.passphrase, NEW_PASSPHRASE))
        .ok();

    // AC4: the default parameters and a new salt.
    let after = sb.vault_bytes();
    let header_after = format::parse_header(&after).unwrap();
    assert_eq!(header_after.kdf, KdfParams::DEFAULT);
    assert_ne!(header_after.kdf_salt, header_before.kdf_salt);
    assert_eq!(header_after.vault_id, header_before.vault_id);
    // AC2: the bytes of every item record are unchanged, and so is the wrapped
    // audit key (D-034).
    assert_eq!(records_region(&after), records_region(&before));
    assert_eq!(header_after.ak_box, header_before.ak_box);
    assert_eq!(header_after.ak_nonce, header_before.ak_nonce);
    // The master key wrap is new.
    assert_ne!(header_after.mk_box, header_before.mk_box);

    // AC2: the old passphrase fails and the new one works.
    sb.run(
        &["get", "demo/db/password"],
        format!("{}\n", sb.passphrase).as_bytes(),
    )
    .fails_with("wrong passphrase");
    let ran = sb.run(
        &["get", "demo/db/password"],
        format!("{NEW_PASSPHRASE}\n").as_bytes(),
    );
    ran.ok();
    assert_eq!(ran.stdout_str(), first);
    let ran = sb.run(
        &["get", "demo/api/key"],
        format!("{NEW_PASSPHRASE}\n").as_bytes(),
    );
    assert_eq!(ran.stdout_str(), second);
}

/// AC3: the new passphrase must be at least 12 characters.
#[test]
fn passwd_refuses_a_new_passphrase_under_12_characters() {
    let sb = Sandbox::with_vault();
    sb.secret("one", "demo", "db", "password");
    let before = sb.vault_bytes();
    for short in ["", "short", "elevenchars"] {
        sb.register(short);
        sb.run(&["passwd"], &stdin(&sb.passphrase, short))
            .fails_with("at least 12 characters");
        assert_eq!(sb.vault_bytes(), before, "{short:?}");
    }
    // D-046: characters, and valid UTF-8.
    let eleven = "\u{20ac}".repeat(11);
    sb.run(&["passwd"], &stdin(&sb.passphrase, &eleven))
        .fails_with("at least 12 characters");
    let mut input = format!("{}\n", sb.passphrase).into_bytes();
    input.extend_from_slice(&[0xff; 20]);
    input.push(b'\n');
    sb.run(&["passwd"], &input).fails_with("valid UTF-8");
    assert_eq!(sb.vault_bytes(), before);
}

/// AC1: the current passphrase is always asked for, and a wrong one changes
/// nothing.
#[test]
fn passwd_needs_the_current_passphrase() {
    let sb = Sandbox::with_vault();
    sb.secret("one", "demo", "db", "password");
    sb.register("wrong-passphrase-fake");
    let before = sb.vault_bytes();
    sb.run(&["passwd"], &stdin("wrong-passphrase-fake", NEW_PASSPHRASE))
        .fails_with("wrong passphrase");
    assert_eq!(sb.vault_bytes(), before);
    // Standard input must hold both lines.
    sb.run(&["passwd"], format!("{}\n", sb.passphrase).as_bytes())
        .fails_with("standard input ended");
    assert_eq!(sb.vault_bytes(), before);
}

#[test]
fn passwd_and_rotate_without_a_vault_say_to_run_init() {
    let sb = Sandbox::new();
    sb.run(&["passwd"], &stdin(&sb.passphrase, NEW_PASSPHRASE))
        .fails_with("vaultline init");
    sb.run_pass(&["rotate"], b"").fails_with("vaultline init");
    assert!(!sb.dir.exists());
}

/// US-7 AC1, with the real parameters. Afterwards the whole sandbox is scanned
/// for the secrets (S6), which covers `rotate` (the one place it runs,
/// D-040).
#[test]
fn rotate_replaces_every_key_and_encrypts_everything_again() {
    let _heavy = HEAVY.lock().unwrap_or_else(|e| e.into_inner());
    let sb = Sandbox::with_vault();
    let secrets = [
        sb.secret("one", "demo", "db", "password"),
        sb.secret("two", "demo", "api", "key"),
        sb.secret("three", "other", "item", "field"),
    ];
    let before = sb.vault_bytes();
    let header_before = format::parse_header(&before).unwrap();
    let records_before = format::parse_records(&before).unwrap();
    assert_eq!(records_before.len(), 3);

    sb.run_pass(&["rotate"], b"").ok();

    let after = sb.vault_bytes();
    let header_after = format::parse_header(&after).unwrap();
    let records_after = format::parse_records(&after).unwrap();
    // The identities stay.
    assert_eq!(header_after.vault_id, header_before.vault_id);
    assert_eq!(records_after.len(), records_before.len());
    // Everything else is new: the master key wrap, the audit key wrap, and for
    // every item its wrapped key and its payload, each with a fresh nonce.
    assert_eq!(header_after.kdf, KdfParams::DEFAULT);
    assert_ne!(header_after.kdf_salt, header_before.kdf_salt);
    assert_ne!(header_after.mk_box, header_before.mk_box);
    assert_ne!(header_after.ak_box, header_before.ak_box);
    assert_ne!(header_after.ak_nonce, header_before.ak_nonce);
    for (old, new) in records_before.iter().zip(&records_after) {
        assert_eq!(new.item_id, old.item_id, "an item_id changed");
        assert_ne!(new.ik_box, old.ik_box, "an item key was not replaced");
        assert_ne!(new.ik_nonce, old.ik_nonce);
        assert_ne!(
            new.payload_box, old.payload_box,
            "a payload was not encrypted again"
        );
        assert_ne!(new.payload_nonce, old.payload_nonce);
    }

    // The same passphrase still opens it, and every value is intact.
    for (reference, secret) in [
        ("demo/db/password", &secrets[0]),
        ("demo/api/key", &secrets[1]),
        ("other/item/field", &secrets[2]),
    ] {
        let ran = sb.run_pass(&["get", reference], b"");
        ran.ok();
        assert_eq!(&ran.stdout_str(), secret);
    }

    // S6 after rotate: no secret in any file the commands touched.
    let secret_refs: Vec<&str> = secrets.iter().map(String::as_str).collect();
    assert_no_plaintext_under(&[sb.tmp.path()], &secret_refs);
}

#[test]
fn rotate_needs_the_passphrase_and_a_wrong_one_changes_nothing() {
    let sb = Sandbox::with_vault();
    sb.secret("one", "demo", "db", "password");
    sb.register("wrong-passphrase-fake");
    let before = sb.vault_bytes();
    sb.run(&["rotate"], b"wrong-passphrase-fake\n")
        .fails_with("wrong passphrase");
    sb.run(&["rotate"], b"").fails_with("standard input ended");
    assert_eq!(sb.vault_bytes(), before);
}
