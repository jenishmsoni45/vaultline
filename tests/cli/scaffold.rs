//! Phase 1 scaffold checks: P1-2 and P1-3 in `docs/phases.md`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Every command path that must answer `--help`, including the hidden one.
const HELP: &[&[&str]] = &[
    &[],
    &["init"],
    &["set"],
    &["get"],
    &["list"],
    &["rm"],
    &["passwd"],
    &["rotate"],
    &["run"],
    &["inject"],
    &["unlock"],
    &["lock"],
    &["agent"],
    &["agent", "stop"],
    &["agent", "serve"],
    &["audit"],
    &["audit", "verify"],
    &["audit", "head"],
];

fn vaultline(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vaultline"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("the vaultline binary should start")
}

fn repo_file(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn read(path: &str) -> String {
    fs::read_to_string(repo_file(path)).unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
}

#[test]
fn forbid_unsafe_at_crate_roots() {
    for root in ["src/lib.rs", "src/main.rs"] {
        let has_attribute = read(root)
            .lines()
            .any(|line| line.trim() == "#![forbid(unsafe_code)]");
        assert!(has_attribute, "{root} must contain #![forbid(unsafe_code)]");
    }
}

#[test]
fn non_unix_targets_fail_to_compile() {
    for root in ["src/lib.rs", "src/main.rs"] {
        let source = read(root);
        assert!(
            source.contains("#[cfg(not(unix))]") && source.contains("compile_error!"),
            "{root} must refuse to build on non-Unix targets (D-021)"
        );
    }
}

/// Phase 4 replaced the stubs: the agent and audit commands are real. In an
/// empty sandbox, with no vault and no agent, each one says what is missing.
/// (The Phase 1 version of this test ran them against the real environment;
/// these commands now act on a vault, so they run in a sandbox.)
#[test]
fn the_agent_and_audit_commands_are_implemented() {
    use crate::common::cli::Sandbox;
    let sb = Sandbox::new();
    for args in [
        &["unlock"][..],
        &["unlock", "--idle-timeout", "5m"],
        &["audit", "verify"],
        &["audit", "head"],
    ] {
        let ran = sb.run(args, b"");
        ran.fails_with("there is no vault");
        assert!(!ran.stderr_str().contains("not implemented"), "{args:?}");
    }
    for args in [&["lock"][..], &["agent", "stop"]] {
        let ran = sb.run(args, b"");
        ran.ok();
        assert!(ran.stderr_str().contains("no agent is running"), "{args:?}");
    }
    // A mistyped anchor is refused before anything else happens.
    sb.run(&["audit", "verify", "--expect", "1:00"], b"")
        .fails_with("an anchor looks like COUNT:HASH");
    // `agent serve` with nothing on stdin reports its failure and exits 1.
    let ran = sb.run(&["agent", "serve"], b"");
    ran.code(1);
    assert_eq!(ran.stdout, [1], "the status byte is 1: not ready");
    assert!(!ran.stderr_str().contains("not implemented"));
    assert!(!sb.dir.join("agent.sock").exists());
}

#[test]
fn every_command_answers_help() {
    for path in HELP {
        let mut args = path.to_vec();
        args.push("--help");
        let out = vaultline(&args);
        assert_eq!(out.status.code(), Some(0), "exit code of {args:?}");
        assert!(!out.stdout.is_empty(), "{args:?} printed no help");
    }
}

#[test]
fn usage_errors_exit_2() {
    for args in [
        &["no-such-command"][..],
        &["run"],
        &["get"],
        &["set"],
        &["init", "--no-such-option"],
    ] {
        let out = vaultline(args);
        assert_eq!(out.status.code(), Some(2), "exit code of {args:?}");
    }
}

#[test]
fn hidden_command_is_not_listed_in_help() {
    let out = vaultline(&["agent", "--help"]);
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("stop"), "agent help: {help}");
    assert!(
        !help.contains("serve"),
        "agent help lists the hidden command: {help}"
    );
}

/// The command names in the `docs/design.md` §4 table, such as `run` or
/// `agent stop`: the leading words of each backticked entry in the first column.
fn documented_commands() -> Vec<Vec<String>> {
    let design = read("docs/design.md");
    let section: String = design
        .lines()
        .skip_while(|line| !line.starts_with("## 4. Commands"))
        .skip(1)
        .take_while(|line| !line.starts_with("## "))
        .map(|line| format!("{line}\n"))
        .collect();
    section
        .lines()
        .filter_map(|line| line.strip_prefix("| `"))
        .filter_map(|rest| rest.split('`').next())
        .map(|entry| {
            entry
                .split_whitespace()
                .take_while(|word| !word.starts_with(['<', '[', '-']))
                .map(str::to_owned)
                .collect()
        })
        .collect()
}

#[test]
fn every_documented_command_exists() {
    let documented = documented_commands();
    assert!(
        documented.len() >= 15,
        "expected the §4 command table, found {documented:?}"
    );
    for command in &documented {
        let known = HELP
            .iter()
            .any(|path| path.iter().copied().eq(command.iter().map(String::as_str)));
        assert!(
            known,
            "design.md documents `{}` but the tests do not cover it",
            command.join(" ")
        );
        let mut args: Vec<&str> = command.iter().map(String::as_str).collect();
        args.push("--help");
        assert_eq!(vaultline(&args).status.code(), Some(0), "{args:?}");
    }
}
