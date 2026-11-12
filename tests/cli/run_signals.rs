//! P3-3 (US-3 AC7, D-036): signals and `run`.
//!
//! The child is a shell script that records every signal it receives in a log
//! file, one line each, so a test can count deliveries. It prints `ready`
//! after its traps are installed, and the test waits for that before sending
//! anything.
//!
//! Each test starts `run` in its own process group, so a signal sent to the
//! group, as the terminal does for Ctrl-C, can't reach the test runner.

use std::fs;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::Signal;

use crate::common::cli::{Live, Sandbox};

/// Logs INT, QUIT, TERM and HUP. TERM and HUP end the script; INT and QUIT
/// don't, so a second delivery of either would be seen.
const SCRIPT: &str = r#"
log="$1"
trap 'echo TERM >> "$log"; exit 0' TERM
trap 'echo HUP >> "$log"; exit 0' HUP
trap 'echo INT >> "$log"' INT
trap 'echo QUIT >> "$log"' QUIT
echo ready
while :; do sleep 0.05; done
"#;

fn start(sb: &Sandbox) -> (Live, std::path::PathBuf) {
    let log = sb.work.join("signals.log");
    let mut command = sb.command();
    command.args(["run", "--", "sh", "-c", SCRIPT, "sh", log.to_str().unwrap()]);
    let mut live = Live::start(command);
    live.read_stdout_until("ready");
    (live, log)
}

fn lines(log: &Path) -> Vec<String> {
    fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn wait_for_lines(log: &Path, count: usize) {
    let started = Instant::now();
    while lines(log).len() < count {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "timed out waiting for {count} signal(s); log: {:?}",
            lines(log)
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// Long enough for a second, wrongly forwarded signal to have arrived.
fn settle() {
    thread::sleep(Duration::from_millis(600));
}

/// AC7: SIGTERM and SIGHUP sent to `run` reach the child, once.
#[test]
fn sigterm_and_sighup_sent_to_run_reach_the_child_once() {
    for (signal, name) in [(Signal::SIGTERM, "TERM"), (Signal::SIGHUP, "HUP")] {
        let sb = Sandbox::new();
        let (live, log) = start(&sb);
        live.signal(signal);
        let ran = live.finish();
        // The child's trap exits 0, and `run` passes that on.
        ran.code(0);
        assert_eq!(lines(&log), [name], "{name} must arrive exactly once");
    }
}

/// AC7: SIGINT and SIGQUIT sent to the process group, as Ctrl-C does, reach the
/// child exactly once, because `run` ignores them while the child runs. `run`
/// itself survives them.
#[test]
fn sigint_and_sigquit_sent_to_the_group_reach_the_child_exactly_once() {
    for (signal, name) in [(Signal::SIGINT, "INT"), (Signal::SIGQUIT, "QUIT")] {
        let sb = Sandbox::new();
        let (mut live, log) = start(&sb);

        live.signal_group(signal);
        wait_for_lines(&log, 1);
        settle();
        assert_eq!(lines(&log), [name], "{name} must arrive exactly once");
        assert!(
            live.child.try_wait().unwrap().is_none(),
            "run must survive {name} while the child runs"
        );

        // Now end it with a SIGTERM to `run` alone.
        live.signal(Signal::SIGTERM);
        let ran = live.finish();
        ran.code(0);
        assert_eq!(lines(&log), [name, "TERM"]);
    }
}

/// D-036's known limit: `kill -INT` aimed at `run` alone doesn't reach the
/// child; send SIGTERM instead. This test documents the behaviour.
#[test]
fn sigint_sent_to_run_alone_does_not_reach_the_child() {
    let sb = Sandbox::new();
    let (mut live, log) = start(&sb);
    live.signal(Signal::SIGINT);
    settle();
    assert!(lines(&log).is_empty(), "log: {:?}", lines(&log));
    assert!(live.child.try_wait().unwrap().is_none(), "run survives it");
    live.signal(Signal::SIGTERM);
    live.finish().code(0);
    assert_eq!(lines(&log), ["TERM"]);
}

/// A child that is killed by the signal `run` forwarded is reported as
/// 128 + N, not as a vaultline failure.
#[test]
fn a_forwarded_sigterm_that_kills_the_child_gives_143() {
    let sb = Sandbox::new();
    let mut command = sb.command();
    // `exec`, so that the child is the sleeping process itself and no orphan is
    // left holding the output pipe open after it dies.
    command.args(["run", "--", "sh", "-c", "echo ready; exec sleep 60"]);
    let mut live = Live::start(command);
    live.read_stdout_until("ready");
    live.signal(Signal::SIGTERM);
    live.finish().code(143);
}
