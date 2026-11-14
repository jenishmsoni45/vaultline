//! P3-11 (C12): no secret appears in vaultline's arguments, and `set` has no
//! value argument.

use std::process::Command;

use crate::common::cli::{Live, Sandbox};

/// `set` takes a reference and `--raw`, nothing else.
#[test]
fn set_has_no_value_argument() {
    let sb = Sandbox::new();
    let ran = sb.run(&["set", "--help"], b"");
    ran.ok();
    let help = ran.stdout_str();
    assert!(help.contains("<REFERENCE>"), "{help}");
    assert!(help.contains("--raw"), "{help}");
    assert!(!help.to_uppercase().contains("<VALUE>"), "{help}");
    // A second positional argument is a usage error, with exit code 2.
    let sb = Sandbox::with_vault();
    sb.run_pass(
        &["set", "demo/api/key", "fake-extra-argument"],
        b"fake-stdin\n",
    )
    .code(2);
    sb.run_pass(&["set", "demo/api/key", "--value", "fake"], b"fake-stdin\n")
        .code(2);
}

/// No command line option takes a passphrase or a value: the only global
/// option is the flag that says to read passphrases from stdin.
#[test]
fn the_passphrase_has_no_command_line_option() {
    let sb = Sandbox::new();
    let help = sb.run(&["--help"], b"").stdout_str();
    assert!(help.contains("--passphrase-stdin"));
    for forbidden in [
        "--passphrase ",
        "--passphrase=",
        "--password",
        "--secret",
        "--value",
    ] {
        assert!(!help.contains(forbidden), "{forbidden}: {help}");
    }
}

/// While `run` is running, its command line, as `ps` shows it to every user,
/// holds neither the passphrase nor any secret.
#[test]
fn a_running_vaultline_shows_no_secret_in_its_arguments() {
    let sb = Sandbox::with_vault();
    let secret = sb.secret("argv", "demo", "api", "key");
    let mut command = sb.command();
    command.env("API", "vault://demo/api/key").args([
        "--passphrase-stdin",
        "run",
        "--",
        "sh",
        "-c",
        "echo ready; sleep 30",
    ]);
    let mut live = Live::start(command);
    live.write_stdin(format!("{}\n", sb.passphrase).as_bytes());
    live.read_stdout_until("ready");

    let pid = live.pid().to_string();
    let ps = Command::new("ps")
        .args(["-o", "args=", "-p", &pid])
        .output()
        .expect("ps should run");
    let shown = String::from_utf8_lossy(&ps.stdout).into_owned();
    assert!(shown.contains("vaultline"), "ps showed: {shown:?}");
    assert!(!shown.contains(&secret), "the secret is in the arguments");
    assert!(
        !shown.contains(&sb.passphrase),
        "the passphrase is in the arguments"
    );
    // The reference stays in the environment, never in the arguments either.
    assert!(!shown.contains("vault://"), "{shown}");
}

/// P4-9, C12: the agent's arguments contain no passphrase. The passphrase
/// reaches it through its standard input pipe, and `ps` shows only the
/// arguments. On macOS `ps -E` shows the environment too, and it holds no
/// passphrase either. (On Linux the agent is non-dumpable, which hides its
/// environment even from its owner; `hardening.rs` checks that.)
#[test]
fn the_agent_has_no_passphrase_in_its_arguments_or_environment() {
    let sb = Sandbox::with_vault();
    sb.secret("v", "demo", "db", "password");
    sb.unlock(&["--idle-timeout", "10m"]).ok();
    let pid = sb.agent_pid().expect("the agent");

    let ps = |extra: &[&str]| {
        let output = Command::new("ps")
            .args(extra)
            .args(["-ww", "-o", "args=", "-p", &pid.to_string()])
            .output()
            .expect("ps should start");
        assert!(output.status.success(), "ps failed");
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let args = ps(&[]);
    assert!(args.contains("agent serve"), "{args}");
    assert!(args.contains("--idle-timeout 600s"), "{args}");
    assert!(
        !args.contains(&sb.passphrase),
        "the passphrase is in the arguments"
    );

    #[cfg(target_os = "macos")]
    {
        let with_environment = ps(&["-E"]);
        assert!(
            with_environment.contains("agent serve"),
            "{with_environment}"
        );
        assert!(
            !with_environment.contains(&sb.passphrase),
            "the passphrase is in the agent's environment"
        );
    }
}
