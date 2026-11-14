//! S9 (`docs/design.md` §2, §12.5): the agent refuses other UIDs, and forgets
//! the key after lock or idle timeout.
//!
//! - The peer decision is unit-tested with injected user IDs in
//!   `src/agent/mod.rs` and `src/agent/server/tests.rs`.
//! - Another UID, for real, runs in CI only (`VAULTLINE_CI_SUDO=1`): the agent
//!   runs as the CI user, root connects through `sudo`, and the agent refuses
//!   before it reads anything. Root is another user, and root can get past the
//!   directory's permissions, so this exercises the peer check itself.
//! - Idle timeout, lock, stop and signals run against the real binary.
//! - Wiping is trusted to `zeroize` (the key holder is a zeroize-on-drop type,
//!   checked in `adversarial/secret_types.rs`); what is tested here is that the
//!   agent can no longer decrypt.

use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use vaultline::agent::client::{self, AgentError};
use vaultline::audit::{Event, Record};
use vaultline::inject::reference::Reference;

use crate::common::cli::Sandbox;
use crate::common::{ci_sudo, sudo_chown_root};

fn reference(text: &str) -> Reference {
    Reference::parse(text.as_bytes()).expect("a reference")
}

fn unlocked(extra: &[&str]) -> (Sandbox, String) {
    let sb = Sandbox::with_vault();
    let secret = sb.secret("key", "demo", "db", "password");
    sb.unlock(extra).ok();
    (sb, secret)
}

fn events(sb: &Sandbox) -> Vec<(Event, u64)> {
    sb.audit_records()
        .iter()
        .map(|r: &Record| (r.event, r.detail))
        .collect()
}

fn resolve(sb: &Sandbox) -> Result<(), AgentError> {
    client::resolve(&sb.dir, &[&reference("vault://demo/db/password")]).map(|_| ())
}

/// US-5 AC2 with 2 seconds: after the timeout the socket is gone, the process
/// has exited, and an `idle-timeout` record exists.
#[test]
fn the_idle_timeout_wipes_the_key_and_ends_the_agent() {
    let (sb, _secret) = unlocked(&["--idle-timeout", "2s"]);
    let pid = sb.agent_pid().expect("the agent");
    resolve(&sb).expect("unlocked until the timeout");
    sb.wait_for_agent_exit(pid);
    let events = events(&sb);
    assert_eq!(
        &events[events.len() - 2..],
        [(Event::Read, 0), (Event::IdleTimeout, 0)],
        "{events:?}"
    );
    // The first record the agent wrote was its unlock, with the agent as origin.
    assert!(events.contains(&(Event::Unlock, 1)), "{events:?}");
    // And nothing answers any more.
    assert!(matches!(resolve(&sb), Err(AgentError::NoAgent)));
}

/// Only Resolve, Set, Remove, List, AuditVerify and AuditHead reset the idle
/// timer. Status and Lock don't, so polling never keeps the agent unlocked
/// (design §8). A request that does reset it keeps the agent up.
#[test]
fn only_real_requests_reset_the_idle_timer() {
    let (sb, _secret) = unlocked(&["--idle-timeout", "3s"]);
    let pid = sb.agent_pid().expect("the agent");
    let started = Instant::now();
    // Polling Status for 2 seconds changes nothing...
    while started.elapsed() < Duration::from_millis(2000) {
        let status = client::status(&sb.dir).expect("status").expect("running");
        assert!(status.unlocked);
        sleep(Duration::from_millis(100));
    }
    // ...but a read now moves the deadline to 3 seconds from now (about 5 s in).
    resolve(&sb).expect("still unlocked at 2 s");
    sleep(Duration::from_millis(2000));
    // 4 s in: past the original deadline, so only the reset explains this.
    assert!(
        client::status(&sb.dir)
            .expect("status")
            .expect("running")
            .unlocked
    );
    sb.wait_for_agent_exit(pid);
    assert!(
        started.elapsed() >= Duration::from_millis(4900),
        "{:?}",
        started.elapsed()
    );
}

/// The same timer runs for a locked agent. It has no key to log with, so it
/// exits quietly (D-049).
#[test]
fn a_locked_agent_also_times_out_and_exits_without_a_record() {
    let (sb, _secret) = unlocked(&["--idle-timeout", "2s"]);
    let pid = sb.agent_pid().expect("the agent");
    sb.run(&["lock"], b"").ok();
    sb.wait_for_agent_exit(pid);
    let events = events(&sb);
    assert_eq!(events.last(), Some(&(Event::Lock, 0)), "{events:?}");
    assert!(!events.iter().any(|(e, _)| *e == Event::IdleTimeout));
}

/// US-5 AC3: after `lock`, Status reports locked, Resolve fails, and a `lock`
/// record exists. The agent stays up.
#[test]
fn lock_wipes_the_key_so_the_agent_can_no_longer_decrypt() {
    let (sb, _secret) = unlocked(&[]);
    let pid = sb.agent_pid().expect("the agent");
    resolve(&sb).expect("unlocked");
    sb.run(&["lock"], b"").ok();

    let status = client::status(&sb.dir).expect("status").expect("running");
    assert!(!status.unlocked);
    assert!(matches!(resolve(&sb), Err(AgentError::Locked(_))));
    assert!(matches!(
        client::list(&sb.dir, None),
        Err(AgentError::Locked(_))
    ));
    assert!(matches!(
        client::set(
            &sb.dir,
            &reference("vault://demo/db/other"),
            &vaultline::secret::SecretValue::new(b"fake")
        ),
        Err(AgentError::Locked(_))
    ));
    assert_eq!(events(&sb).last(), Some(&(Event::Lock, 0)));
    assert!(kill(pid, None).is_ok(), "the agent keeps running");
    // Locking twice is harmless and logs nothing more.
    let count = events(&sb).len();
    sb.run(&["lock"], b"").ok();
    assert_eq!(events(&sb).len(), count);
}

/// US-5 AC4: after `agent stop`, the process has exited and the socket is gone.
#[test]
fn stop_ends_the_agent_and_removes_the_socket() {
    let (sb, _secret) = unlocked(&[]);
    let pid = sb.agent_pid().expect("the agent");
    sb.run(&["agent", "stop"], b"").ok();
    sb.wait_for_agent_exit(pid);
    assert_eq!(events(&sb).last(), Some(&(Event::Lock, 1)));
    assert!(matches!(resolve(&sb), Err(AgentError::NoAgent)));
}

/// SIGTERM sent to the agent wipes the key and ends it, like `stop`.
#[test]
fn sigterm_wipes_the_key_and_ends_the_agent() {
    let (sb, _secret) = unlocked(&[]);
    let pid = sb.agent_pid().expect("the agent");
    kill(pid, Signal::SIGTERM).expect("signal the agent");
    sb.wait_for_agent_exit(pid);
    assert_eq!(events(&sb).last(), Some(&(Event::Lock, 1)));
}

/// Stopping a locked agent leaves no record: there is no key to write one.
#[test]
fn stopping_a_locked_agent_logs_nothing() {
    let (sb, _secret) = unlocked(&[]);
    let pid = sb.agent_pid().expect("the agent");
    sb.run(&["lock"], b"").ok();
    let count = events(&sb).len();
    sb.run(&["agent", "stop"], b"").ok();
    sb.wait_for_agent_exit(pid);
    assert_eq!(events(&sb).len(), count);
}

/// Another UID, for real (CI only): root connects to the agent's socket and
/// sends a Lock request. The agent closes the connection without reading it,
/// so it stays unlocked and logs no `lock`.
#[test]
fn a_connection_from_another_uid_is_refused_before_any_byte_is_read() {
    if !ci_sudo() {
        return;
    }
    let (sb, secret) = unlocked(&[]);
    // The agent may close the connection before root's request is even sent,
    // so a failed send is expected (and is the refusal), as is a failed read.
    const SCRIPT: &str = "import socket, sys\n\
        s = socket.socket(socket.AF_UNIX)\n\
        s.connect(sys.argv[1])\n\
        try:\n\
        \x20   s.sendall(b'\\x02\\x00\\x00\\x00\\x01\\x06')\n\
        except OSError:\n\
        \x20   pass\n\
        try:\n\
        \x20   data = s.recv(100)\n\
        except OSError:\n\
        \x20   data = b''\n\
        print(len(data))\n";
    let output = Command::new("sudo")
        .args(["-n", "python3", "-c", SCRIPT])
        .arg(sb.socket())
        .output()
        .expect("sudo should start");
    assert!(
        output.status.success(),
        "root couldn't even connect: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "0",
        "no answer is sent"
    );

    // The Lock request was never read, let alone served.
    let status = client::status(&sb.dir).expect("status").expect("running");
    assert!(status.unlocked, "the agent was locked by root's request");
    assert!(!events(&sb).iter().any(|(e, _)| *e == Event::Lock));
    let ran = sb.run(&["get", "demo/db/password"], b"anything\n");
    assert_eq!(ran.ok().stdout_str(), secret);
}

/// The other direction (CI only): the client refuses an agent whose socket is
/// owned by another user, before it connects.
#[test]
fn the_client_refuses_a_socket_owned_by_another_uid() {
    if !ci_sudo() {
        return;
    }
    let (sb, _secret) = unlocked(&[]);
    let _back = sudo_chown_root(&sb.socket());
    match client::status(&sb.dir) {
        Err(AgentError::Refused(why)) => assert!(why.contains("owned by uid 0"), "{why}"),
        other => panic!(
            "expected a refusal, got {:?}",
            other.map(|_| ()).map_err(|e| e.to_string())
        ),
    }
}
