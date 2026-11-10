//! P1-4 in `docs/phases.md`: without the tools, `make audit` and `make fuzz`
//! print SKIPPED and succeed; with `CI=true` a missing tool is an error.
//!
//! The tools are made "missing" by running make with an empty directory as its
//! whole `PATH`, so the result does not depend on what is installed.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

fn find_make() -> PathBuf {
    let path = env::var_os("PATH").expect("PATH should be set");
    env::split_paths(&path)
        .map(|dir| dir.join("make"))
        .find(|candidate| candidate.is_file())
        .expect("make should be on the PATH")
}

fn make(target: &str, ci: bool) -> Output {
    let empty_bin = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("empty-path");
    fs::create_dir_all(&empty_bin).expect("the empty PATH directory should be created");
    let mut command = Command::new(find_make());
    command
        .arg(target)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("PATH", &empty_bin)
        .env_remove("CI");
    if ci {
        command.env("CI", "true");
    }
    command.output().expect("make should start")
}

#[test]
fn audit_and_fuzz_skip_when_tools_are_missing() {
    for target in ["audit", "fuzz"] {
        let out = make(target, false);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "make {target} failed: {out:?}");
        assert!(
            stdout.contains("SKIPPED:") && stdout.contains("this check runs in CI"),
            "make {target} printed: {stdout}"
        );
    }
}

#[test]
fn audit_and_fuzz_fail_in_ci_when_tools_are_missing() {
    for target in ["audit", "fuzz"] {
        let out = make(target, true);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "make {target} should fail with CI=true"
        );
        assert!(
            stderr.contains("is not installed"),
            "make {target} printed: {stderr}"
        );
    }
}
