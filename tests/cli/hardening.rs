//! P3-10 (NFR-7, C11): every vaultline process has a core-dump limit of 0, and
//! on Linux is non-dumpable.

use crate::common::cli::Sandbox;

fn run_sh(script: &str) -> crate::common::cli::Ran {
    let sb = Sandbox::new();
    sb.run(&["run", "--", "sh", "-c", script], b"")
}

/// `run` sets the limit for itself and the child inherits it (`design.md` §7
/// step 7). This works the same on macOS and Linux.
#[test]
fn the_core_dump_limit_is_zero() {
    let ran = run_sh("ulimit -c");
    ran.ok();
    assert_eq!(ran.stdout_str(), "0\n");
}

#[test]
fn the_hard_core_dump_limit_is_zero_too_so_the_child_cannot_raise_it() {
    let ran = run_sh("ulimit -Hc");
    ran.ok();
    assert_eq!(ran.stdout_str(), "0\n");
    // Raising the soft limit above the hard limit is refused.
    let ran = run_sh("ulimit -c 1000 2>/dev/null && echo raised || echo refused");
    assert_eq!(ran.stdout_str(), "refused\n");
}

/// On Linux vaultline is non-dumpable, which makes `/proc/<pid>/environ`
/// unreadable to other processes of the same user, the child included. The
/// child's parent is vaultline itself.
#[cfg(target_os = "linux")]
#[test]
fn a_child_cannot_read_the_proc_environ_of_vaultline_on_linux() {
    let ran = run_sh("cat /proc/$PPID/environ > /dev/null");
    assert_ne!(ran.code, Some(0), "stderr: {}", ran.stderr_str());
    assert!(
        ran.stderr_str().contains("Permission denied"),
        "stderr: {}",
        ran.stderr_str()
    );
}

/// The control for the test above: the child can read its own environment, so
/// the denial really comes from vaultline being non-dumpable.
#[cfg(target_os = "linux")]
#[test]
fn a_child_can_read_its_own_proc_environ_on_linux() {
    run_sh("cat /proc/$$/environ > /dev/null").ok();
}

/// The hardening applies to every invocation, not only to `run`: it happens
/// before the command line is looked at, so even a usage error runs after it.
/// Here a command that opens a vault shows the limit through a child.
#[test]
fn hardening_applies_when_a_vault_is_opened_too() {
    let sb = Sandbox::with_vault();
    sb.secret("key", "demo", "api", "key");
    let mut command = sb.command();
    command.env("API", "vault://demo/api/key").args([
        "--passphrase-stdin",
        "run",
        "--",
        "sh",
        "-c",
        "ulimit -c",
    ]);
    let ran = sb.run_command(command, format!("{}\n", sb.passphrase).as_bytes());
    ran.ok();
    assert_eq!(ran.stdout_str(), "0\n");
}

/// P4-9, NFR-7, C11: on Linux the agent's core-dump limit is 0 and it is
/// non-dumpable, which makes its `/proc/<pid>/environ` unreadable to other
/// processes of the same user, this test included. (macOS has no such
/// interface, so the limit is checked there through the child of `run`, above.)
#[cfg(target_os = "linux")]
#[test]
fn the_agent_has_no_core_dumps_and_is_non_dumpable_on_linux() {
    let sb = Sandbox::with_vault();
    sb.secret("key", "demo", "api", "key");
    sb.unlock(&[]).ok();
    let pid = sb.agent_pid().expect("the agent");

    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).expect("limits");
    let core = limits
        .lines()
        .find(|line| line.starts_with("Max core file size"))
        .expect("a core file size line");
    let numbers: Vec<&str> = core.split_whitespace().skip(4).take(2).collect();
    assert_eq!(numbers, ["0", "0"], "{core}");

    let denied = std::fs::read(format!("/proc/{pid}/environ"));
    assert_eq!(
        denied.map_err(|e| e.kind()),
        Err(std::io::ErrorKind::PermissionDenied),
        "the agent's environment is readable"
    );
    // The control: this process can read its own.
    std::fs::read("/proc/self/environ").expect("our own environment");
}
