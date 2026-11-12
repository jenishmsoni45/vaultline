//! P3-3 (US-3 AC1, AC2, AC3, AC5, AC6, AC8): `vaultline run`.
//!
//! Children are `sh -c` scripts that test what they received and print only
//! `ok`, so a test can check the environment without printing a secret.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use nix::sys::signal::Signal;

use crate::common::cli::{Live, Ran, Sandbox};

/// `vaultline --passphrase-stdin run <args>` with extra environment
/// variables, the passphrase as the first line of standard input and `rest`
/// after it.
fn run_with(sb: &Sandbox, env: &[(&str, &str)], args: &[&str], rest: &[u8]) -> Ran {
    let mut command = sb.command();
    command.arg("--passphrase-stdin").arg("run").args(args);
    for (name, value) in env {
        command.env(name, value);
    }
    let mut stdin = format!("{}\n", sb.passphrase).into_bytes();
    stdin.extend_from_slice(rest);
    sb.run_command(command, &stdin)
}

fn started(sb: &Sandbox) -> bool {
    sb.work.join("started").exists()
}

/// AC1: inherited variables whose whole value is a reference are resolved;
/// other variables pass through unchanged.
#[test]
fn inherited_references_are_resolved_and_other_variables_pass_through() {
    let sb = Sandbox::with_vault();
    let key = sb.secret("key", "demo", "stripe", "key");
    let ran = run_with(
        &sb,
        &[
            ("API", "vault://demo/stripe/key"),
            ("EXPECT", &key),
            ("PLAIN", "hello"),
            ("EMBEDDED", "prefix-vault://demo/stripe/key"),
            ("URLISH", "https://example.com/vault://demo/stripe/key"),
            ("BLANK", ""),
        ],
        &[
            "--",
            "sh",
            "-c",
            "test \"$API\" = \"$EXPECT\" && test \"$PLAIN\" = hello \
             && test \"$EMBEDDED\" = prefix-vault://demo/stripe/key \
             && test \"$URLISH\" = https://example.com/vault://demo/stripe/key \
             && test -z \"$BLANK\" && echo ok",
        ],
        b"",
    );
    ran.ok();
    assert_eq!(ran.stdout_str(), "ok\n");
}

/// AC2: `--env-file` adds `NAME=value` lines and resolves references; the file
/// wins over the environment, and stderr names the variable but not its value.
#[test]
fn an_env_file_adds_variables_and_wins_over_the_environment() {
    let sb = Sandbox::with_vault();
    let url = sb.secret("url", "demo", "db", "url");
    let other = sb.secret("other", "demo", "db", "other");
    sb.register("inherited-value-fake");
    sb.register("file-value-fake");
    fs::write(
        sb.work.join("app.env"),
        "# a comment\n\
         DB_URL=vault://demo/db/url\n\
         \n\
         LITERAL=a literal  value\n\
         QUOTED=\"kept as it is\"\n\
         OVERRIDDEN=file-value-fake\n\
         OVERRIDDEN_REF=vault://demo/db/other\n",
    )
    .unwrap();
    let ran = run_with(
        &sb,
        &[
            ("OVERRIDDEN", "inherited-value-fake"),
            ("OVERRIDDEN_REF", "vault://demo/db/url"),
            ("EXPECT_URL", &url),
            ("EXPECT_OTHER", &other),
        ],
        &[
            "--env-file",
            "app.env",
            "--",
            "sh",
            "-c",
            "test \"$DB_URL\" = \"$EXPECT_URL\" \
             && test \"$LITERAL\" = 'a literal  value' \
             && test \"$QUOTED\" = '\"kept as it is\"' \
             && test \"$OVERRIDDEN\" = file-value-fake \
             && test \"$OVERRIDDEN_REF\" = \"$EXPECT_OTHER\" \
             && echo ok",
        ],
        b"",
    );
    ran.ok();
    assert_eq!(ran.stdout_str(), "ok\n");
    let stderr = ran.stderr_str();
    assert!(stderr.contains("OVERRIDDEN is set in the environment and in the env file"));
    assert!(stderr.contains("OVERRIDDEN_REF is set in the environment and in the env file"));
}

/// AC3: a malformed or unresolvable reference means the child never starts,
/// and the error names the reference.
#[test]
fn a_bad_reference_means_the_child_is_not_started() {
    let sb = Sandbox::with_vault();
    sb.secret("key", "demo", "stripe", "key");
    let child = ["--", "sh", "-c", "touch started"];

    let ran = run_with(
        &sb,
        &[
            ("GOOD", "vault://demo/stripe/key"),
            ("BAD", "vault://demo/stripe"),
        ],
        &child,
        b"",
    );
    ran.fails_with("BAD");
    assert!(ran.stderr_str().contains("vault://demo/stripe"));
    assert!(!started(&sb));

    let ran = run_with(
        &sb,
        &[
            ("GOOD", "vault://demo/stripe/key"),
            ("GONE", "vault://demo/stripe/gone"),
        ],
        &child,
        b"",
    );
    ran.fails_with("vault://demo/stripe/gone");
    assert!(ran.stderr_str().contains("nothing was started"));
    assert!(!started(&sb));
}

#[test]
fn a_bad_reference_in_the_env_file_means_the_child_is_not_started() {
    let sb = Sandbox::with_vault();
    sb.secret("key", "demo", "stripe", "key");
    let child = ["--env-file", "bad.env", "--", "sh", "-c", "touch started"];

    fs::write(sb.work.join("bad.env"), "OK=1\nBAD=vault://demo/stripe\n").unwrap();
    run_with(&sb, &[], &child, b"").fails_with("line 2");
    assert!(!started(&sb));

    fs::write(
        sb.work.join("bad.env"),
        "MISSING=vault://demo/stripe/gone\n",
    )
    .unwrap();
    run_with(&sb, &[], &child, b"").fails_with("vault://demo/stripe/gone");
    assert!(!started(&sb));

    for (text, expected) in [
        ("A=1\r\n", "carriage return"),
        ("A=1\nA=2\n", "assigned more than once"),
        ("not an assignment\n", "expected NAME=value"),
    ] {
        fs::write(sb.work.join("bad.env"), text).unwrap();
        run_with(&sb, &[], &child, b"").fails_with(expected);
        assert!(!started(&sb));
    }
}

#[test]
fn a_missing_env_file_is_reported() {
    let sb = Sandbox::with_vault();
    run_with(&sb, &[], &["--env-file", "nope.env", "--", "true"], b"")
        .fails_with("can't read the env file");
}

/// AC5: a secret shorter than 8 bytes triggers a warning that names its
/// reference, and shows no value.
#[test]
fn a_short_secret_triggers_a_warning_naming_its_reference() {
    let sb = Sandbox::with_vault();
    sb.set("demo", "pin", "code", b"tiny");
    sb.set("demo", "pin", "seven", b"1234567");
    sb.set("demo", "pin", "eight", b"12345678");
    sb.register("tiny");
    sb.register("1234567");
    let ran = run_with(
        &sb,
        &[
            ("SHORT", "vault://demo/pin/code"),
            ("SEVEN", "vault://demo/pin/seven"),
            ("EIGHT", "vault://demo/pin/eight"),
        ],
        &["--", "true"],
        b"",
    );
    ran.ok();
    let stderr = ran.stderr_str();
    assert!(stderr.contains("vault://demo/pin/code"), "{stderr}");
    assert!(stderr.contains("vault://demo/pin/seven"), "{stderr}");
    assert!(!stderr.contains("vault://demo/pin/eight"), "{stderr}");
    assert!(stderr.contains("shorter than 8 bytes"), "{stderr}");
}

/// An empty value is injected, but there is nothing to mask and nothing to warn
/// about.
#[test]
fn an_empty_value_is_injected_without_a_warning() {
    let sb = Sandbox::with_vault();
    sb.set("demo", "api", "blank", b"");
    let ran = run_with(
        &sb,
        &[("EMPTY", "vault://demo/api/blank")],
        &["--", "sh", "-c", "test -z \"${EMPTY-unset}\" && echo empty"],
        b"",
    );
    ran.ok();
    assert_eq!(ran.stdout_str(), "empty\n");
    assert!(!ran.stderr_str().contains("shorter than"));
}

/// AC6: `run` exits with the child's code.
#[test]
fn run_exits_with_the_childs_code() {
    let sb = Sandbox::new();
    for code in [0, 1, 3, 42, 255] {
        let script = format!("exit {code}");
        run_with(&sb, &[], &["--", "sh", "-c", &script], b"").code(code);
    }
}

/// AC6: 127 if the command isn't found.
#[test]
fn run_exits_127_when_the_command_is_not_found() {
    let sb = Sandbox::new();
    let ran = run_with(&sb, &[], &["--", "no-such-command-vaultline"], b"");
    ran.code(127);
    assert!(ran.stderr_str().contains("command not found"));
}

/// AC6: 126 if it isn't executable.
#[test]
fn run_exits_126_when_the_command_is_not_executable() {
    let sb = Sandbox::new();
    let script = sb.work.join("not-executable");
    fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o644)).unwrap();
    let ran = run_with(&sb, &[], &["--", "./not-executable"], b"");
    ran.code(126);
    assert!(ran.stderr_str().contains("not executable"));
}

/// AC6: 128 + N if the child is killed by signal N.
#[test]
fn run_exits_128_plus_n_when_the_child_is_killed_by_signal_n() {
    let sb = Sandbox::new();
    for (signal, expected) in [("KILL", 137), ("TERM", 143), ("HUP", 129), ("SEGV", 139)] {
        let script = format!("kill -{signal} $$");
        run_with(&sb, &[], &["--", "sh", "-c", &script], b"").code(expected);
    }
}

/// AC8: `--no-mask` passes output through unmasked and prints a warning.
#[test]
fn no_mask_passes_output_through_and_warns() {
    let sb = Sandbox::with_vault();
    let key = sb.secret("key", "demo", "stripe", "key");
    let env = [("API", "vault://demo/stripe/key")];
    let script = ["sh", "-c", "echo \"$API\""];

    let mut args = vec!["--no-mask", "--"];
    args.extend(script);
    let ran = run_with(&sb, &env, &args, b"");
    ran.ok();
    assert_eq!(ran.stdout_str(), format!("{key}\n"));
    assert!(ran.stderr_str().contains("--no-mask"));

    // Without it, the same child prints only the marker.
    let mut args = vec!["--"];
    args.extend(script);
    let ran = run_with(&sb, &env, &args, b"");
    ran.ok();
    assert_eq!(ran.stdout_str(), "<concealed by vaultline>\n");
    assert!(!ran.stderr_str().contains("--no-mask"));
}

/// Standard output and standard error are each masked.
#[test]
fn both_output_streams_are_masked() {
    let sb = Sandbox::with_vault();
    sb.secret("key", "demo", "stripe", "key");
    let ran = run_with(
        &sb,
        &[("API", "vault://demo/stripe/key")],
        &["--", "sh", "-c", "echo \"out $API\"; echo \"err $API\" >&2"],
        b"",
    );
    ran.ok();
    assert_eq!(ran.stdout_str(), "out <concealed by vaultline>\n");
    assert!(ran.stderr_str().contains("err <concealed by vaultline>\n"));
}

/// D-037: after the passphrase line, the rest of standard input belongs to the
/// child.
#[test]
fn the_child_reads_what_follows_the_passphrase_line() {
    let sb = Sandbox::with_vault();
    sb.secret("key", "demo", "stripe", "key");
    let ran = run_with(
        &sb,
        &[("API", "vault://demo/stripe/key")],
        &["--", "cat"],
        b"input for the child\nsecond line\n",
    );
    ran.ok();
    assert_eq!(ran.stdout_str(), "input for the child\nsecond line\n");
}

/// With nothing to resolve there is nothing to unlock: no vault is needed, no
/// passphrase line is consumed, and the child sees all of standard input.
#[test]
fn without_references_there_is_no_unlock_and_stdin_is_untouched() {
    let sb = Sandbox::new();
    let ran = sb.run(&["run", "--", "cat"], b"first line\nsecond line\n");
    ran.ok();
    assert_eq!(ran.stdout_str(), "first line\nsecond line\n");
}

#[test]
fn a_wrong_passphrase_means_the_child_is_not_started() {
    let sb = Sandbox::with_vault();
    sb.secret("key", "demo", "stripe", "key");
    sb.register("wrong-passphrase-fake");
    let mut command = sb.command();
    command.env("API", "vault://demo/stripe/key").args([
        "--passphrase-stdin",
        "run",
        "--",
        "sh",
        "-c",
        "touch started",
    ]);
    let ran = sb.run_command(command, b"wrong-passphrase-fake\n");
    ran.fails_with("wrong passphrase");
    assert!(!started(&sb));
}

#[test]
fn arguments_reach_the_child_unchanged() {
    let sb = Sandbox::new();
    let ran = run_with(
        &sb,
        &[],
        &[
            "--",
            "sh",
            "-c",
            "printf '%s|' \"$@\"",
            "sh",
            "a b",
            "",
            "$HOME",
            "--flag",
        ],
        b"",
    );
    ran.ok();
    assert_eq!(ran.stdout_str(), "a b||$HOME|--flag|");
}

/// A value with a NUL byte can't be put in an environment. That is an error of
/// vaultline's, not a missing command.
#[test]
fn a_value_that_cannot_be_an_environment_variable_is_an_error() {
    let sb = Sandbox::with_vault();
    sb.set("demo", "api", "nul", b"before\0after");
    let ran = run_with(
        &sb,
        &[("API", "vault://demo/api/nul")],
        &["--", "sh", "-c", "touch started"],
        b"",
    );
    ran.fails_with("can't start sh");
    assert!(!started(&sb));
}

/// Standard output redirected to a file is not refused for `run`: the file
/// receives the masked output.
#[test]
fn run_into_a_file_writes_masked_output() {
    use std::process::Stdio;
    let sb = Sandbox::with_vault();
    sb.secret("key", "demo", "stripe", "key");
    let out = sb.work.join("out.txt");
    let mut command = sb.command();
    command
        .env("API", "vault://demo/stripe/key")
        .args([
            "--passphrase-stdin",
            "run",
            "--",
            "sh",
            "-c",
            "echo \"$API\"",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::from(fs::File::create(&out).unwrap()))
        .stderr(Stdio::piped());
    let ran = crate::common::cli::run_to_end(command, format!("{}\n", sb.passphrase).as_bytes());
    sb.assert_no_leak(&ran);
    ran.ok();
    assert_eq!(
        fs::read_to_string(&out).unwrap(),
        "<concealed by vaultline>\n"
    );
}

/// §7 step 6: when what reads vaultline's output goes away, the child sees the
/// broken pipe too, and `run` ends instead of hanging.
#[test]
fn a_broken_pipe_reaches_the_child() {
    let sb = Sandbox::new();
    let mut command = sb.command();
    command.args(["run", "--", "yes"]);
    let mut live = Live::start(command);
    live.read_stdout_until("y\ny\ny\n");
    // The reader goes away, as `| head` would.
    drop(live.child.stdout.take());
    let ran = live.finish();
    // `yes` died of SIGPIPE (13), so `run` exits with 128 + 13.
    ran.code(141);
}

/// Dropping a `Live` that is still running must not leave anything behind.
#[test]
fn a_live_command_is_cleaned_up_on_drop() {
    let sb = Sandbox::new();
    let mut command = sb.command();
    command.args(["run", "--", "sleep", "30"]);
    let live = Live::start(command);
    let pid = live.pid();
    live.signal(Signal::SIGTERM);
    drop(live);
    assert!(
        nix::sys::signal::kill(pid, None).is_err(),
        "the process outlived its guard"
    );
}
