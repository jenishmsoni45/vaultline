//! P4-2 (US-5 AC1 and AC6, US-7 AC4), and the routing rules of
//! `architecture.md` §2 and D-050, D-054.
//!
//! Every test that starts an agent does it through [`Sandbox::unlock`], so the
//! sandbox stops the agent when it is dropped, even if the test fails.
//!
//! A test never reaches the terminal prompt. When an unlocked agent serves a
//! command, `--passphrase-stdin` still reads a passphrase line and throws it
//! away (D-054), so these tests give every command a *wrong* passphrase line:
//! if a command used it, it would fail.

use nix::sys::signal::{Signal, kill, killpg};
use nix::unistd::getpgid;
use vaultline::agent::client;
use vaultline::audit::Event;

use crate::common::cli::{HEAVY, Live, Sandbox, TIMEOUT};

const WRONG: &str = "this-is-not-the-passphrase";

fn wrong(rest: &[u8]) -> Vec<u8> {
    let mut stdin = format!("{WRONG}\n").into_bytes();
    stdin.extend_from_slice(rest);
    stdin
}

/// A sandbox with two secrets and a running, unlocked agent.
fn unlocked() -> (Sandbox, String, String) {
    let sb = Sandbox::with_vault();
    let db = sb.secret("db", "demo", "db", "password");
    let api = sb.secret("api", "demo", "api", "key");
    sb.unlock(&[]).ok();
    (sb, db, api)
}

fn status(sb: &Sandbox) -> client::Status {
    client::status(&sb.dir)
        .expect("ask the agent")
        .expect("an agent is running")
}

/// US-5 AC1: after `unlock`, `get`, `set`, `list`, `rm`, `run`, `inject` and
/// `audit` work without a passphrase.
#[test]
fn after_unlock_every_command_works_without_the_passphrase() {
    let (sb, db, api) = unlocked();
    assert!(status(&sb).unlocked);

    let ran = sb.run(&["get", "demo/db/password"], &wrong(b""));
    assert_eq!(ran.ok().stdout_str(), db);

    let fresh = sb.secret("new", "demo", "extra", "token");
    // `secret` stored it through the library; a value stored by the agent:
    let stored = "fake-stored-through-the-agent";
    sb.register(stored);
    sb.run(&["set", "demo/extra/other"], &wrong(stored.as_bytes()))
        .ok();
    let ran = sb.run(&["get", "vault://demo/extra/other"], &wrong(b""));
    assert_eq!(ran.ok().stdout_str(), stored);
    let ran = sb.run(&["get", "demo/extra/token"], &wrong(b""));
    assert_eq!(ran.ok().stdout_str(), fresh);

    let ran = sb.run(&["list"], &wrong(b""));
    assert_eq!(
        ran.ok().stdout_str(),
        "demo/api/key\ndemo/db/password\ndemo/extra/other\ndemo/extra/token\n"
    );
    let ran = sb.run(&["list", "demo"], &wrong(b""));
    assert!(ran.ok().stdout_str().contains("demo/db/password"));

    sb.run(&["rm", "demo/extra/other"], &wrong(b"")).ok();
    sb.run(&["get", "demo/extra/other"], &wrong(b""))
        .fails_with("no such secret");

    // run: the child sees the value, and its output is masked.
    let mut command = sb.command();
    command.env("DB", "vault://demo/db/password").args([
        "--passphrase-stdin",
        "run",
        "--",
        "sh",
        "-c",
        "echo \"$DB\"",
    ]);
    let ran = sb.run_command(command, &wrong(b""));
    assert_eq!(ran.ok().stdout_str(), "<concealed by vaultline>\n");
    assert!(!ran.stdout_str().contains(&db));

    // inject: a template on stdin after the passphrase line.
    let template = b"key={{ vault://demo/api/key }}\n";
    let ran = sb.run(&["inject"], &wrong(template));
    assert_eq!(ran.ok().stdout_str(), format!("key={api}\n"));

    // audit verify and audit head.
    let ran = sb.run(&["audit", "verify"], &wrong(b""));
    assert!(ran.ok().stdout_str().contains("audit log verified"));
    let ran = sb.run(&["audit", "head"], &wrong(b""));
    assert!(ran.ok().stdout_str().contains(':'));

    // The agent stayed unlocked, and no command asked for the passphrase.
    assert!(status(&sb).unlocked);
}

/// D-054: through an unlocked agent the passphrase line is read and thrown
/// away, so what follows it is the command's input, exactly as without an
/// agent, and the line never reaches the child.
#[test]
fn the_passphrase_line_is_discarded_and_never_reaches_the_child() {
    let (sb, _db, _api) = unlocked();
    let mut command = sb.command();
    command
        .env("DB", "vault://demo/db/password")
        .args(["--passphrase-stdin", "run", "--", "cat"]);
    let ran = sb.run_command(command, &wrong(b"the child's own input"));
    assert_eq!(ran.ok().stdout_str(), "the child's own input");
    assert!(!ran.stdout_str().contains(WRONG));

    // Without an agent the same command lays stdin out the same way.
    let sb = Sandbox::with_vault();
    sb.secret("db", "demo", "db", "password");
    let mut command = sb.command();
    command
        .env("DB", "vault://demo/db/password")
        .args(["--passphrase-stdin", "run", "--", "cat"]);
    let ran = sb.run_command(
        command,
        format!("{}\nthe child's own input", sb.passphrase).as_bytes(),
    );
    assert_eq!(ran.ok().stdout_str(), "the child's own input");
}

/// With `--passphrase-stdin` and an unlocked agent, a missing line is still an
/// error: the layout of stdin doesn't depend on whether an agent is up.
#[test]
fn a_missing_passphrase_line_is_an_error_even_with_an_agent() {
    let (sb, _db, _api) = unlocked();
    sb.run(&["get", "demo/db/password"], b"")
        .fails_with("passphrase");
}

/// Architecture §2: a locked agent stays locked, and the command does its own
/// work and asks for the passphrase.
#[test]
fn a_locked_agent_stays_locked_and_commands_use_the_passphrase() {
    let (sb, db, _api) = unlocked();
    let pid = sb.agent_pid().expect("the agent");
    sb.run(&["lock"], b"").ok();
    assert!(!status(&sb).unlocked);

    // A wrong passphrase now fails, because the command opens the vault itself.
    sb.run(&["get", "demo/db/password"], &wrong(b""))
        .fails_with("wrong passphrase");
    // The right one works, and leaves the agent locked and running.
    let ran = sb.run_pass(&["get", "demo/db/password"], b"");
    assert_eq!(ran.ok().stdout_str(), db);
    assert!(!status(&sb).unlocked);
    assert!(kill(pid, None).is_ok(), "the agent is still running");
    assert!(sb.socket().exists());
}

#[test]
fn unlock_on_a_locked_agent_unlocks_it_and_twice_says_so() {
    let (sb, db, _api) = unlocked();
    let pid = sb.agent_pid().expect("the agent");
    sb.run(&["lock"], b"").ok();
    sb.run_pass(&["unlock"], b"").ok();
    assert!(status(&sb).unlocked);
    assert_eq!(sb.agent_pid(), Some(pid), "the same agent, not a new one");
    let ran = sb.run(&["get", "demo/db/password"], &wrong(b""));
    assert_eq!(ran.ok().stdout_str(), db);

    let ran = sb.run_pass(&["unlock"], b"");
    ran.ok();
    assert!(
        ran.stderr_str().contains("already unlocked"),
        "{}",
        ran.stderr_str()
    );
}

/// D-050: the Unlock message has no timeout, so the flag is refused when an
/// agent is running, before any passphrase is read.
#[test]
fn the_idle_timeout_flag_is_refused_when_an_agent_is_running() {
    let (sb, _db, _api) = unlocked();
    for locked in [false, true] {
        if locked {
            sb.run(&["lock"], b"").ok();
        }
        // No stdin at all: the refusal comes before a passphrase is asked for.
        let ran = sb.run(&["unlock", "--idle-timeout", "5m"], b"");
        ran.fails_with("agent stop");
        assert_eq!(status(&sb).unlocked, !locked);
    }
}

#[test]
fn a_bad_idle_timeout_is_an_error_and_starts_no_agent() {
    let sb = Sandbox::with_vault();
    for bad in ["0s", "25h", "1441m", "5", "5x", "1.5h", ""] {
        let ran = sb.run_pass(&["unlock", "--idle-timeout", bad], b"");
        ran.fails_with("idle timeout");
        assert!(!sb.socket().exists(), "{bad:?}");
    }
}

#[test]
fn a_wrong_passphrase_starts_no_agent_and_says_so() {
    let sb = Sandbox::with_vault();
    let ran = sb.run(&["unlock"], b"definitely-not-it\n");
    ran.fails_with("wrong passphrase");
    assert!(
        ran.stderr_str().contains("didn't start"),
        "{}",
        ran.stderr_str()
    );
    assert!(!sb.socket().exists());
    assert!(sb.agent_pid().is_none());
}

#[test]
fn lock_and_agent_stop_with_no_agent_are_not_errors() {
    let sb = Sandbox::with_vault();
    for args in [&["lock"][..], &["agent", "stop"]] {
        let ran = sb.run(args, b"");
        ran.ok();
        assert!(ran.stderr_str().contains("no agent is running"));
    }
}

/// The agent re-reads and re-verifies the vault on every request, so a write
/// from another process is seen (design §8).
#[test]
fn the_agent_sees_writes_made_by_other_processes() {
    let (sb, _db, _api) = unlocked();
    // `secret` stores through the library, in this process, not the agent's.
    let later = sb.secret("later", "demo", "late", "value");
    let ran = sb.run(&["get", "demo/late/value"], &wrong(b""));
    assert_eq!(ran.ok().stdout_str(), later);
}

/// US-5 AC6: Ctrl-C in the terminal that ran `unlock` doesn't stop the agent,
/// because it runs in its own process group. SIGHUP is ignored too. SIGINT
/// sent to the agent itself does stop it.
#[test]
fn ctrl_c_in_the_terminal_does_not_stop_the_agent() {
    let sb = Sandbox::with_vault();
    sb.secret("db", "demo", "db", "password");
    let mut command = sb.command();
    command.args(["--passphrase-stdin", "unlock"]);
    let mut unlock = Live::start(command);
    let unlock_group = unlock.pid();
    unlock.write_stdin(format!("{}\n", sb.passphrase).as_bytes());
    // Remembered at once, so that the sandbox stops the agent even if an
    // assertion below fails.
    let pid = {
        let started = std::time::Instant::now();
        loop {
            if let Some(pid) = sb.track_agent() {
                break pid;
            }
            assert!(started.elapsed() < TIMEOUT, "the agent never appeared");
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    };
    unlock.finish().ok();

    let agent_group = getpgid(Some(pid)).expect("the agent's process group");
    assert_ne!(agent_group, unlock_group, "the agent has its own group");
    assert_eq!(agent_group, pid, "and leads it");

    // What the terminal does on Ctrl-C: SIGINT to the group of `unlock`.
    let _ = killpg(unlock_group, Signal::SIGINT);
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(kill(pid, None).is_ok(), "the agent is still running");
    assert!(status(&sb).unlocked);

    // SIGHUP is ignored.
    kill(pid, Signal::SIGHUP).expect("signal the agent");
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(kill(pid, None).is_ok(), "the agent ignored SIGHUP");
    assert!(status(&sb).unlocked);

    // SIGINT aimed at the agent itself wipes the key and ends it.
    kill(pid, Signal::SIGINT).expect("signal the agent");
    sb.wait_for_agent_exit(pid);
}

/// US-7 AC4: `rotate` locks a running agent, because its key is out of date.
/// The agent has no audit key to log it with (D-048), so the `rotate` record
/// is the only trace, and the agent keeps running, locked. One of the two
/// tests that run Argon2id at 256 MiB for `rotate` (D-040).
#[test]
fn rotate_locks_a_running_agent() {
    let _heavy = HEAVY.lock().unwrap_or_else(|e| e.into_inner());
    let (sb, db, _api) = unlocked();
    let pid = sb.agent_pid().expect("the agent");
    assert!(status(&sb).unlocked);

    let ran = sb.run_pass(&["rotate"], b"");
    ran.ok();
    assert!(
        ran.stderr_str().contains("agent was locked"),
        "{}",
        ran.stderr_str()
    );

    // Locked, but still there.
    assert!(!status(&sb).unlocked);
    assert!(kill(pid, None).is_ok());
    // D-048: no `lock` record after `rotate`.
    let events = sb.audit_events();
    assert_eq!(events.last(), Some(&Event::Rotate), "{events:?}");

    // The commands now do their own work, with the same passphrase.
    let ran = sb.run_pass(&["get", "demo/db/password"], b"");
    assert_eq!(ran.ok().stdout_str(), db);
    // And the agent can be unlocked again, with the rotated vault.
    sb.run_pass(&["unlock"], b"").ok();
    assert!(status(&sb).unlocked);
    let ran = sb.run(&["get", "demo/db/password"], &wrong(b""));
    assert_eq!(ran.ok().stdout_str(), db);
}

/// US-6 AC1: `passwd` asks for the current passphrase even when an agent is
/// unlocked, so nobody at an unlocked terminal can change the keys.
#[test]
fn passwd_asks_for_the_current_passphrase_even_when_an_agent_is_unlocked() {
    let (sb, ..) = unlocked();
    let before = sb.vault_bytes();
    // A wrong current passphrase fails before anything is written.
    let ran = sb.run(
        &["passwd"],
        format!("{WRONG}\nbrand-new-passphrase\n").as_bytes(),
    );
    ran.fails_with("wrong passphrase");
    assert_eq!(sb.vault_bytes(), before);
    assert!(status(&sb).unlocked, "the agent is untouched");
}

/// `init`, `passwd` and `rotate` don't use the agent, and the agent isn't
/// asked about them.
#[test]
fn rotate_with_a_wrong_passphrase_fails_and_leaves_the_agent_unlocked() {
    let (sb, ..) = unlocked();
    let before = sb.vault_bytes();
    sb.run(&["rotate"], format!("{WRONG}\n").as_bytes())
        .fails_with("wrong passphrase");
    assert_eq!(sb.vault_bytes(), before);
    assert!(status(&sb).unlocked);
}
