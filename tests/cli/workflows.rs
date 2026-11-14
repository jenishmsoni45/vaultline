//! P1-5 to P1-7 in `docs/phases.md`: the policy files and the CI workflow have
//! the shape the design requires. The checks that need cargo-deny and
//! cargo-fuzz themselves run in CI.

use std::fs;
use std::path::Path;

fn read(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
}

/// The lines of one job in the workflow: from `  <name>:` to the next job.
fn job(workflow: &str, name: &str) -> String {
    let header = format!("  {name}:");
    workflow
        .lines()
        .skip_while(|line| *line != header)
        .enumerate()
        .take_while(|(i, line)| *i == 0 || line.is_empty() || line.starts_with("    "))
        .map(|(_, line)| format!("{line}\n"))
        .collect()
}

#[test]
fn linux_runs_on_push_and_macos_on_pull_requests_only() {
    let ci = read(".github/workflows/ci.yml");
    assert!(job(&ci, "linux").contains("if: github.event_name == 'push'"));
    assert!(job(&ci, "macos").contains("if: github.event_name == 'pull_request'"));
    let linux = job(&ci, "linux");
    for step in ["make lint", "make test", "make audit", "make fuzz"] {
        assert!(linux.contains(step), "the Linux job must run `{step}`");
    }
    let macos = job(&ci, "macos");
    for step in ["make lint", "make test"] {
        assert!(macos.contains(step), "the macOS job must run `{step}`");
    }
    for tool in ["make audit", "make fuzz"] {
        assert!(!macos.contains(tool), "the macOS job must not run `{tool}`");
    }
}

#[test]
fn workflows_are_read_only_and_pin_actions_by_sha() {
    for file in [
        ".github/workflows/ci.yml",
        ".github/workflows/fuzz-campaign.yml",
    ] {
        let workflow = read(file);
        assert!(
            workflow.contains("permissions:\n  contents: read\n"),
            "{file} must set `contents: read` for the whole workflow"
        );
        let uses: Vec<&str> = workflow
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix("- uses: ")
                    .or_else(|| line.trim().strip_prefix("uses: "))
            })
            .collect();
        assert!(!uses.is_empty(), "{file} should use at least one action");
        for entry in uses {
            let reference = entry.split(['@', ' ']).nth(1).unwrap_or("");
            assert!(
                reference.len() == 40 && reference.chars().all(|c| c.is_ascii_hexdigit()),
                "{file}: `{entry}` must be pinned to a full commit SHA"
            );
        }
    }
}

#[test]
fn ci_pins_rust_1_86_and_uses_nightly_only_for_fuzzing() {
    let ci = read(".github/workflows/ci.yml");
    assert!(ci.contains("RUST_VERSION: \"1.86\""));
    assert_eq!(
        ci.matches("toolchain install nightly").count(),
        1,
        "nightly is installed once, for cargo-fuzz"
    );
    assert!(
        !Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("rust-toolchain.toml")
            .exists()
    );
    assert!(read("Cargo.toml").contains("rust-version = \"1.86\""));
}

/// P1-7, updated by Phase 2: the `vault_file` target replaces the `smoke`
/// placeholder (D-035, P2-16).
#[test]
fn fuzz_crate_is_outside_the_workspace_with_the_vault_file_target() {
    let manifest = read("fuzz/Cargo.toml");
    assert!(
        manifest.contains("\n[workspace]\n"),
        "fuzz/ must be its own workspace"
    );
    assert!(manifest.contains("name = \"vault_file\""));
    assert!(
        !manifest.contains("name = \"smoke\""),
        "Phase 2 removes smoke"
    );
    assert!(!read("Cargo.toml").contains("[workspace]"));
    let targets = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/fuzz_targets");
    assert!(targets.join("vault_file.rs").is_file());
    assert!(!targets.join("smoke.rs").exists());
}

/// P3-12: the `reference` and `template` targets exist next to `vault_file`,
/// and are registered in the fuzz crate. `make fuzz` runs every target that
/// `cargo fuzz list` finds, so CI smoke-tests them for 60 seconds each.
#[test]
fn fuzz_crate_has_the_reference_and_template_targets() {
    let manifest = read("fuzz/Cargo.toml");
    let targets = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/fuzz_targets");
    for target in ["vault_file", "reference", "template"] {
        assert!(
            manifest.contains(&format!("name = \"{target}\"")),
            "fuzz/Cargo.toml must register {target}"
        );
        assert!(
            manifest.contains(&format!("path = \"fuzz_targets/{target}.rs\"")),
            "fuzz/Cargo.toml must point {target} at its file"
        );
        let source = fs::read_to_string(targets.join(format!("{target}.rs")))
            .unwrap_or_else(|e| panic!("cannot read the {target} target: {e}"));
        assert!(
            source.contains("fuzz_target!"),
            "{target} is not a fuzz target"
        );
    }
    assert!(read("Makefile").contains("cargo +nightly fuzz list"));
}

/// The tests that need another user's files run in CI only, where both jobs
/// set `VAULTLINE_CI_SUDO=1` (docs/design.md section 12.2).
#[test]
fn both_ci_jobs_enable_the_sudo_tests() {
    let ci = read(".github/workflows/ci.yml");
    for name in ["linux", "macos"] {
        assert!(
            job(&ci, name).contains("VAULTLINE_CI_SUDO: \"1\""),
            "the {name} job must set VAULTLINE_CI_SUDO"
        );
    }
}

#[test]
fn deny_policy_covers_advisories_licenses_sources_and_networking() {
    let deny = read("deny.toml");
    for section in ["[advisories]", "[licenses]", "[bans]", "[sources]"] {
        assert!(deny.contains(section), "deny.toml lacks {section}");
    }
    assert!(deny.contains("unknown-registry = \"deny\""));
    assert!(deny.contains("unknown-git = \"deny\""));
    for banned in ["reqwest", "hyper", "openssl", "rustls", "tokio"] {
        assert!(
            deny.contains(&format!("crate = \"{banned}\"")),
            "deny.toml must ban {banned} (NFR-6)"
        );
    }
}

#[test]
fn license_files_exist_and_the_license_field_is_set() {
    assert!(read("Cargo.toml").contains("license = \"MIT OR Apache-2.0\""));
    assert!(read("LICENSE-MIT").starts_with("MIT License"));
    assert!(read("LICENSE-APACHE").contains("Apache License"));
}

// ---------------------------------------------------------------------------
// Phase 4: the agent_message target, the fuzz campaign workflow, and the CI
// check that no agent outlives the tests.

/// The four targets of the campaign (D-018, D-035).
const TARGETS: [&str; 4] = ["vault_file", "reference", "template", "agent_message"];

/// P4-10: the `agent_message` target is registered and is a fuzz target. The
/// 60-second smoke run happens in CI, because `make fuzz` runs every target
/// that `cargo fuzz list` finds.
#[test]
fn fuzz_crate_has_the_agent_message_target() {
    let manifest = read("fuzz/Cargo.toml");
    assert!(manifest.contains("name = \"agent_message\""));
    assert!(manifest.contains("path = \"fuzz_targets/agent_message.rs\""));
    let source = read("fuzz/fuzz_targets/agent_message.rs");
    assert!(source.contains("fuzz_target!"));
    // It decodes arbitrary bytes as requests and as responses.
    assert!(source.contains("decode_request") && source.contains("decode_response"));
}

/// P4-11: `fuzz-campaign.yml` exists, triggers only on `workflow_dispatch`, and
/// has one job per target with `timeout-minutes` of 360 or less (D-035).
#[test]
fn the_campaign_starts_only_by_hand_with_one_job_per_target() {
    let campaign = read(".github/workflows/fuzz-campaign.yml");

    // The triggers: `on:` holds `workflow_dispatch` and nothing else.
    let on: Vec<&str> = campaign
        .lines()
        .skip_while(|line| *line != "on:")
        .skip(1)
        .take_while(|line| line.starts_with("  ") || line.is_empty())
        .filter(|line| line.starts_with("  ") && !line.starts_with("   "))
        .collect();
    assert_eq!(on, ["  workflow_dispatch:"], "no other trigger");
    for trigger in ["push:", "pull_request", "schedule:", "cron:"] {
        assert!(
            !campaign.contains(trigger),
            "the campaign must not use {trigger}"
        );
    }

    // D-051: a duration input that defaults to, and is capped at, 20,400 s.
    assert!(campaign.contains("default: \"20400\""));
    assert!(campaign.contains("MAX_SECONDS: \"20400\""));

    for target in TARGETS {
        let job = job(&campaign, target);
        assert!(!job.is_empty(), "no job for {target}");
        let timeouts: Vec<u32> = job
            .lines()
            .filter_map(|line| line.trim().strip_prefix("timeout-minutes: "))
            .map(|n| n.parse().expect("a number"))
            .collect();
        assert_eq!(timeouts.len(), 1, "{target} needs one timeout-minutes");
        assert!(timeouts[0] <= 360, "{target}: {} minutes", timeouts[0]);
        assert!(
            job.contains(&format!("cargo +nightly fuzz run {target} ")),
            "{target} must fuzz itself"
        );
        // The corpus, the crashes and the measured time are uploaded even if
        // the fuzzer failed.
        for what in ["corpus", "crashes", "time"] {
            assert!(
                job.contains(&format!("name: fuzz-{what}-{target}")),
                "{target} must upload its {what}"
            );
        }
        assert_eq!(job.matches("if: always()").count(), 3, "{target}");
    }

    // One job per target, plus the summary: nothing else.
    let jobs = campaign
        .lines()
        .skip_while(|line| *line != "jobs:")
        .filter(|line| line.starts_with("  ") && !line.starts_with("   ") && line.ends_with(':'))
        .count();
    assert_eq!(jobs, TARGETS.len() + 1);

    // The summary runs the script on the downloaded times.
    let summary = job(&campaign, "summary");
    assert!(summary.contains("scripts/fuzz-cpu-hours.sh"));
    assert!(summary.contains("fuzz-time-*"));
    assert!(summary.contains("if: always()"));
}

/// A step after the tests fails if any `vaultline agent serve` is still
/// running, in both CI jobs (P4-12, `docs/phases.md` rule 3).
#[test]
fn both_ci_jobs_fail_if_an_agent_outlives_the_tests() {
    let ci = read(".github/workflows/ci.yml");
    for name in ["linux", "macos"] {
        let job = job(&ci, name);
        let test = job.find("run: make test").expect("a test step");
        let check = job
            .find("pgrep -fl '[v]aultline agent serve'")
            .unwrap_or_else(|| panic!("the {name} job has no leftover-agent check"));
        assert!(check > test, "the {name} check must come after the tests");
        assert!(job.contains("No agent outlives the tests"));
    }
}

/// The script that adds up CPU-hours (D-052): seconds times cores over 3600
/// per target, and the total, and it refuses what it can't read.
#[test]
fn the_cpu_hours_script_adds_up_what_the_jobs_measured() {
    use std::process::Command;
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/fuzz-cpu-hours.sh");
    let run = |dir: &Path| {
        Command::new("sh")
            .arg(&script)
            .arg(dir)
            .output()
            .expect("sh should start")
    };
    let write = |root: &Path, target: &str, seconds: &str, cores: &str| {
        let dir = root.join(format!("fuzz-time-{target}"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("seconds"), format!("{seconds}\n")).unwrap();
        fs::write(dir.join("cores"), format!("{cores}\n")).unwrap();
    };

    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "vault_file", "3600", "4");
    write(tmp.path(), "template", "1800", "4");
    write(tmp.path(), "agent_message", "20400", "4");
    let out = run(tmp.path());
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("vault_file: 3600 s on 4 cores = 4.00 CPU-hours"),
        "{text}"
    );
    assert!(
        text.contains("template: 1800 s on 4 cores = 2.00 CPU-hours"),
        "{text}"
    );
    assert!(
        text.contains("agent_message: 20400 s on 4 cores = 22.67 CPU-hours"),
        "{text}"
    );
    assert!(
        text.trim_end().ends_with("total: 28.67 CPU-hours"),
        "{text}"
    );

    // Nothing to add up, and files that aren't numbers, are errors.
    let empty = tempfile::tempdir().unwrap();
    assert!(!run(empty.path()).status.success());
    for bad in ["", "abc", "12.5", "-3"] {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "reference", bad, "4");
        let out = run(dir.path());
        assert!(!out.status.success(), "{bad:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("whole number"),
            "{bad:?}"
        );
        assert!(out.stdout.is_empty(), "no partial figure for {bad:?}");
    }
    // A missing file is an error too.
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("fuzz-time-template")).unwrap();
    assert!(!run(dir.path()).status.success());
    // And so is a missing directory, or none given.
    assert!(!run(Path::new("/nonexistent-fuzz-times")).status.success());
    assert!(
        !Command::new("sh")
            .arg(&script)
            .output()
            .unwrap()
            .status
            .success()
    );
}
