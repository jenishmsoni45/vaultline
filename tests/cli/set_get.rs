//! P3-2 (US-2 AC1–3, AC7, AC8, and S4 through the command line): `set` and
//! `get`.
//!
//! The hidden terminal prompt can't be driven without a pseudo-terminal
//! (D-009), so every test supplies values and passphrases on standard input.

use crate::common::cli::{PASSPHRASE, Sandbox};
use vaultline::vault::MAX_VALUE_LEN;

fn get(sb: &Sandbox, reference: &str) -> Vec<u8> {
    let ran = sb.run_pass(&["get", reference], b"");
    ran.ok();
    ran.stdout
}

/// AC1: the value comes from stdin, and one trailing newline is removed.
#[test]
fn set_reads_the_value_from_stdin_and_strips_one_trailing_newline() {
    let sb = Sandbox::with_vault();
    sb.register("fake-stdin-value");
    sb.run_pass(&["set", "demo/api/key"], b"fake-stdin-value\n")
        .ok();
    assert_eq!(get(&sb, "demo/api/key"), b"fake-stdin-value");

    // Only one newline goes.
    sb.run_pass(&["set", "demo/api/two"], b"fake-two\n\n").ok();
    assert_eq!(get(&sb, "demo/api/two"), b"fake-two\n");
    // No newline at all is fine.
    sb.run_pass(&["set", "demo/api/none"], b"fake-none").ok();
    assert_eq!(get(&sb, "demo/api/none"), b"fake-none");
}

#[test]
fn raw_keeps_the_trailing_newline() {
    let sb = Sandbox::with_vault();
    sb.run_pass(&["set", "--raw", "demo/api/raw"], b"fake-raw\n")
        .ok();
    assert_eq!(get(&sb, "demo/api/raw"), b"fake-raw\n");
    sb.run_pass(&["set", "demo/api/raw2", "--raw"], b"\n").ok();
    assert_eq!(get(&sb, "demo/api/raw2"), b"\n");
}

/// AC2: with `--passphrase-stdin` the first line is the passphrase and the rest
/// is the value, newlines inside it included.
#[test]
fn the_first_line_is_the_passphrase_and_the_rest_is_the_value() {
    let sb = Sandbox::with_vault();
    let stdin = format!("{PASSPHRASE}\nfake-line-one\nfake-line-two\n");
    sb.run(&["set", "demo/api/multi"], stdin.as_bytes()).ok();
    assert_eq!(get(&sb, "demo/api/multi"), b"fake-line-one\nfake-line-two");
}

#[test]
fn a_value_may_hold_any_bytes() {
    let sb = Sandbox::with_vault();
    let bytes: Vec<u8> = (0..=255u8).collect();
    sb.run_pass(&["set", "--raw", "demo/api/binary"], &bytes)
        .ok();
    assert_eq!(get(&sb, "demo/api/binary"), bytes);
}

/// AC3: `get` writes exactly the stored bytes, with no newline added.
#[test]
fn get_writes_exactly_the_stored_bytes() {
    let sb = Sandbox::with_vault();
    for (field, bytes) in [
        ("plain", &b"fake-plain-value"[..]),
        ("newline", b"fake-with-newline\n"),
        ("empty", b""),
        ("binary", b"\x00\xff\r\n\x01 fake"),
    ] {
        sb.set("demo", "api", field, bytes);
        assert_eq!(get(&sb, &format!("demo/api/{field}")), bytes, "{field}");
    }
}

/// A value given as an argument is a usage error (D-011), and nothing changes.
#[test]
fn a_value_given_as_an_argument_is_a_usage_error() {
    let sb = Sandbox::with_vault();
    let before = sb.vault_bytes();
    // clap repeats an unexpected argument in its usage message (threat model
    // R13), so this value is deliberately not registered for the stderr check.
    sb.run_pass(&["set", "demo/api/key", "fake-argument"], b"fake-stdin\n")
        .code(2);
    assert_eq!(sb.vault_bytes(), before);
}

/// AC7: bad names fail and change nothing.
#[test]
fn names_outside_the_allowed_characters_or_length_fail() {
    let sb = Sandbox::with_vault();
    sb.set("demo", "api", "key", b"fake-existing");
    let before = sb.vault_bytes();
    let long = "n".repeat(65);
    for reference in [
        "demo/api/ke y",
        "demo/api/k\u{e9}y",
        "demo/api/key!",
        "demo//key",
        "/api/key",
        "demo/api/",
        "demo/api",
        "demo",
        "demo/api/key/more",
        "vault://demo/api",
        &format!("{long}/api/key"),
        &format!("demo/{long}/key"),
        &format!("demo/api/{long}"),
    ] {
        sb.run_pass(&["set", reference], b"fake-new\n")
            .fails_with("not a valid reference");
        sb.run_pass(&["get", reference], b"")
            .fails_with("not a valid reference");
    }
    assert_eq!(sb.vault_bytes(), before);
}

#[test]
fn names_of_64_bytes_and_every_allowed_character_work() {
    let sb = Sandbox::with_vault();
    let longest = "n".repeat(64);
    let reference = format!("{longest}/A.b_c-9/{longest}");
    sb.run_pass(&["set", &reference], b"fake-long-names\n").ok();
    assert_eq!(get(&sb, &reference), b"fake-long-names");
}

/// AC7: a value is at most 64 KiB.
#[test]
fn a_value_over_64_kib_fails_and_64_kib_works() {
    let sb = Sandbox::with_vault();
    let max = vec![b'v'; MAX_VALUE_LEN];
    sb.run_pass(&["set", "--raw", "demo/api/max"], &max).ok();
    assert_eq!(get(&sb, "demo/api/max").len(), MAX_VALUE_LEN);

    let before = sb.vault_bytes();
    let over = vec![b'v'; MAX_VALUE_LEN + 1];
    sb.run_pass(&["set", "--raw", "demo/api/over"], &over)
        .fails_with("at most 64 KiB");
    assert_eq!(sb.vault_bytes(), before);
    // One trailing newline doesn't count against the limit unless it is kept.
    let mut with_newline = max.clone();
    with_newline.push(b'\n');
    sb.run_pass(&["set", "demo/api/max2"], &with_newline).ok();
    assert_eq!(get(&sb, "demo/api/max2").len(), MAX_VALUE_LEN);
}

/// AC8: both forms are accepted.
#[test]
fn both_the_long_and_the_short_reference_forms_work() {
    let sb = Sandbox::with_vault();
    sb.run_pass(&["set", "vault://demo/api/long"], b"fake-long-form\n")
        .ok();
    sb.run_pass(&["set", "demo/api/short"], b"fake-short-form\n")
        .ok();
    assert_eq!(get(&sb, "demo/api/long"), b"fake-long-form");
    assert_eq!(get(&sb, "vault://demo/api/long"), b"fake-long-form");
    assert_eq!(get(&sb, "demo/api/short"), b"fake-short-form");
    assert_eq!(get(&sb, "vault://demo/api/short"), b"fake-short-form");
}

#[test]
fn set_creates_what_is_missing_and_replaces_what_is_there() {
    let sb = Sandbox::with_vault();
    sb.run_pass(&["set", "newproject/newitem/field"], b"fake-first\n")
        .ok();
    sb.run_pass(&["set", "newproject/newitem/field"], b"fake-second\n")
        .ok();
    sb.run_pass(&["set", "newproject/newitem/other"], b"fake-other\n")
        .ok();
    assert_eq!(get(&sb, "newproject/newitem/field"), b"fake-second");
    assert_eq!(get(&sb, "newproject/newitem/other"), b"fake-other");
}

#[test]
fn get_of_a_missing_reference_names_it() {
    let sb = Sandbox::with_vault();
    sb.set("demo", "api", "key", b"fake-existing");
    let ran = sb.run_pass(&["get", "demo/api/missing"], b"");
    ran.fails_with("vault://demo/api/missing");
    assert!(ran.stdout.is_empty());
}

/// S4 through the command line: a wrong passphrase is a clean error.
#[test]
fn a_wrong_passphrase_gives_a_clean_error_and_prints_no_value() {
    let sb = Sandbox::with_vault();
    sb.secret("value", "demo", "api", "key");
    sb.register("wrong-passphrase-fake");
    let ran = sb.run(&["get", "demo/api/key"], b"wrong-passphrase-fake\n");
    ran.fails_with("wrong passphrase");
    assert!(ran.stdout.is_empty());
    let before = sb.vault_bytes();
    sb.run(
        &["set", "demo/api/key"],
        b"wrong-passphrase-fake\nfake-new\n",
    )
    .fails_with("wrong passphrase");
    assert_eq!(sb.vault_bytes(), before);
}

#[test]
fn without_a_passphrase_on_stdin_the_error_says_how_it_is_read() {
    let sb = Sandbox::with_vault();
    sb.run(&["get", "demo/api/key"], b"")
        .fails_with("standard input ended before a passphrase line");
}

#[test]
fn with_no_vault_the_error_says_to_run_init() {
    let sb = Sandbox::new();
    for args in [&["get", "demo/api/key"][..], &["set", "demo/api/key"]] {
        sb.run_pass(args, b"fake-value\n")
            .fails_with("vaultline init");
    }
    assert!(!sb.dir.exists(), "nothing is created");
}

/// A vault with weaker parameters than the defaults prints a warning that
/// suggests `passwd` (`vault-format.md` §4.4).
#[test]
fn a_vault_with_weak_parameters_warns_and_suggests_passwd() {
    let sb = Sandbox::with_vault();
    sb.set("demo", "api", "key", b"fake-value");
    let ran = sb.run_pass(&["get", "demo/api/key"], b"");
    ran.ok();
    let stderr = ran.stderr_str();
    assert!(stderr.contains("weaker Argon2id parameters"), "{stderr}");
    assert!(stderr.contains("vaultline passwd"), "{stderr}");
    assert_eq!(ran.stdout, b"fake-value");
}
