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
    for file in [".github/workflows/ci.yml"] {
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
