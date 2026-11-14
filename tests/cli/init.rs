//! P3-1 (US-1 AC2–5, and AC1) and P4-1 (US-1 AC1, the audit files):
//! `vaultline init`.
//!
//! The first test is the one `init` test that runs Argon2id with the default
//! parameters, 256 MiB (D-020). Every other test fails before the key
//! derivation or uses a cheap vault.

use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;

use vaultline::audit::{Audit, Event};
use vaultline::vault::format;
use vaultline::vault::{KdfParams, Vault};

use crate::common::cli::{PASSPHRASE, Sandbox};
use crate::common::{CHEAP, mode, pass};

/// AC1 (directory 0700, `vault` 0600), AC4 (the default parameters) and AC5
/// (`VAULTLINE_DIR` chooses the directory).
#[test]
fn init_creates_a_private_vault_with_the_default_parameters() {
    let sb = Sandbox::new();
    assert!(!sb.dir.exists());

    let ran = sb.run_pass(&["init"], b"");
    ran.ok();
    assert!(
        ran.stdout.is_empty(),
        "init prints nothing on standard output"
    );

    assert_eq!(mode(&sb.dir), 0o700);
    assert_eq!(mode(&sb.vault_path()), 0o600);
    let bytes = sb.vault_bytes();
    let header = format::parse_header(&bytes).expect("a valid header");
    assert_eq!(header.kdf, KdfParams::DEFAULT);
    assert_eq!(
        (header.kdf.m_kib, header.kdf.t, header.kdf.p),
        (262_144, 3, 4)
    );
    assert_eq!(bytes.len(), 234, "an empty vault is 234 bytes");

    // It is the directory VAULTLINE_DIR names, not the default one.
    assert!(!sb.home.join(".vaultline").exists());
    // The passphrase opens it.
    let vault =
        Vault::open(&sb.dir, &pass(PASSPHRASE)).expect("the passphrase opens the new vault");

    // P4-1, US-1 AC1: `audit.log` and `audit.head` exist (0600) and hold a
    // single `init` record, which verifies.
    assert_eq!(mode(&sb.dir.join("audit.log")), 0o600);
    assert_eq!(mode(&sb.dir.join("audit.head")), 0o600);
    let records = sb.audit_records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].event, Event::Init);
    assert_eq!((records[0].seq, records[0].detail), (0, 0));
    assert_eq!(records[0].item_id, [0; 16], "no item, and no name");
    let key = vault.audit_key().expect("the audit key");
    let audit = Audit::new(&sb.dir, vault.vault_id(), &key);
    let anchor = audit.anchor().expect("the head");
    assert_eq!(anchor.count, 1);
    let verdict = audit.verify(None).expect("verify");
    assert!(verdict.passed, "{}", verdict.report);
}

/// AC5: without `VAULTLINE_DIR` the directory is `~/.vaultline`.
#[test]
fn the_default_directory_is_dot_vaultline_in_home() {
    let sb = Sandbox::new();
    let dir = sb.home.join(".vaultline");
    let vault = Vault::create(&dir, &pass(PASSPHRASE), CHEAP).expect("a vault in HOME");
    vault
        .set(
            &crate::common::name("demo"),
            &crate::common::name("item"),
            &crate::common::name("field"),
            &crate::common::value(b"fake-default-dir-value"),
        )
        .expect("set");

    let mut command = sb.command();
    command
        .env_remove("VAULTLINE_DIR")
        .args(["--passphrase-stdin", "list"]);
    let ran = sb.run_command(command, format!("{PASSPHRASE}\n").as_bytes());
    ran.ok();
    assert_eq!(ran.stdout_str(), "demo/item/field\n");
}

#[test]
fn without_vaultline_dir_or_home_it_says_what_to_set() {
    let sb = Sandbox::new();
    let mut command = sb.command();
    command
        .env_remove("VAULTLINE_DIR")
        .env_remove("HOME")
        .args(["--passphrase-stdin", "init"]);
    let ran = sb.run_command(command, format!("{PASSPHRASE}\n").as_bytes());
    ran.fails_with("HOME is not set");
}

/// AC2: fewer than 12 characters fails, and nothing is created.
#[test]
fn a_passphrase_shorter_than_12_characters_fails_and_creates_nothing() {
    for short in ["", "short", "elevenchars"] {
        let sb = Sandbox::new();
        sb.register(short);
        let ran = sb.run(&["init"], format!("{short}\n").as_bytes());
        ran.fails_with("at least 12 characters");
        assert!(!sb.dir.exists(), "{short:?} created the directory");
    }
}

/// D-046: the 12 counts characters, not bytes.
#[test]
fn the_twelve_counts_characters_not_bytes() {
    let sb = Sandbox::new();
    // Eleven characters of three bytes each: 33 bytes, still too short.
    let eleven = "\u{20ac}".repeat(11);
    sb.register(&eleven);
    sb.run(&["init"], format!("{eleven}\n").as_bytes())
        .fails_with("at least 12 characters");
    assert!(!sb.dir.exists());
}

/// D-046: a new passphrase must be valid UTF-8, so its characters can be
/// counted.
#[test]
fn a_passphrase_that_is_not_utf8_is_refused_for_a_new_vault() {
    let sb = Sandbox::new();
    let mut stdin = vec![0xffu8; 20];
    stdin.push(b'\n');
    sb.run(&["init"], &stdin).fails_with("valid UTF-8");
    assert!(!sb.dir.exists());
}

#[test]
fn init_without_a_passphrase_on_stdin_says_so() {
    let sb = Sandbox::new();
    sb.run(&["init"], b"").fails_with("standard input ended");
    assert!(!sb.dir.exists());
}

/// AC3: init refuses when a vault exists, and leaves it untouched.
#[test]
fn init_fails_when_a_vault_exists_and_leaves_it_untouched() {
    let sb = Sandbox::with_vault();
    sb.set("demo", "item", "field", b"fake-existing-value");
    let before = sb.vault_bytes();
    let modified = fs::metadata(sb.vault_path()).unwrap().modified().unwrap();

    sb.run_pass(&["init"], b"").fails_with("already exists");

    assert_eq!(sb.vault_bytes(), before);
    assert_eq!(
        fs::metadata(sb.vault_path()).unwrap().modified().unwrap(),
        modified
    );
}

#[test]
fn init_refuses_a_directory_that_others_can_read() {
    let sb = Sandbox::new();
    fs::create_dir(&sb.dir).unwrap();
    fs::set_permissions(&sb.dir, Permissions::from_mode(0o755)).unwrap();
    sb.run_pass(&["init"], b"").fails_with("chmod 700");
    assert!(!sb.vault_path().exists());
}
