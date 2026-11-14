//! P4-7 and P4-8 (`docs/phases.md`): sockets that aren't the agent's, stale
//! sockets, a second agent, a path that is too long, and hostile frames
//! (`docs/design.md` §8, §11, §12.1).
//!
//! Every agent is started through [`Sandbox`], which stops it again when the
//! test ends. The tests that need another user (a socket owned by root) run
//! only when `VAULTLINE_CI_SUDO=1`, which only CI sets.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use vaultline::agent::client::{self, AgentError};
use vaultline::agent::protocol::{
    self, MAX_FRAME, PROTO_VERSION, Reply, Request, Response, code, decode_response, encode_request,
};
use vaultline::vault::store;

use crate::common::cli::Sandbox;
use crate::common::{ci_sudo, sudo_chown_root};

fn status_text(sb: &Sandbox) -> String {
    match client::status(&sb.dir) {
        Ok(Some(s)) => format!("running, unlocked: {}", s.unlocked),
        Ok(None) => "no agent".into(),
        Err(e) => format!("error: {e}"),
    }
}

/// What a crashed agent leaves behind: a socket file with no process behind
/// it. The socket is bound but never listens, so connecting always fails with
/// "connection refused". (A real listener that is dropped would do the same,
/// except that another test's `fork` could briefly hold a copy of it open.)
fn stale_socket(sb: &Sandbox) {
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, UnixAddr, bind, socket};
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .expect("create a socket");
    bind(
        std::os::fd::AsRawFd::as_raw_fd(&fd),
        &UnixAddr::new(&sb.socket()).expect("an address"),
    )
    .expect("bind the socket");
    drop(fd);
    assert!(sb.socket().exists());
}

// ---------------------------------------------------------------------------
// P4-7: sockets that aren't ours.

/// A socket owned by another UID is refused by the client before any byte is
/// sent, and before it even connects (CI only).
#[test]
fn a_socket_owned_by_another_uid_is_refused_before_a_connection_is_made() {
    if !ci_sudo() {
        return;
    }
    let sb = Sandbox::with_vault();
    sb.secret("key", "demo", "db", "password");
    let listener = UnixListener::bind(sb.socket()).expect("bind");
    listener.set_nonblocking(true).expect("non-blocking");
    let _back = sudo_chown_root(&sb.socket());

    // Every command that would use the agent refuses, and says why.
    for args in [
        &["get", "demo/db/password"][..],
        &["list"],
        &["lock"],
        &["unlock"],
    ] {
        let ran = sb.run_pass(args, b"");
        ran.fails_with("owned by uid 0");
    }
    // Nobody connected: not a byte, not even a connection.
    let accepted = listener.accept();
    assert!(
        matches!(&accepted, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "the client connected to a socket that isn't its own"
    );
}

#[test]
fn a_symlink_in_the_sockets_place_is_refused() {
    let sb = Sandbox::with_vault();
    symlink("/dev/null", sb.socket()).expect("plant a symlink");
    let ran = sb.run_pass(&["get", "demo/db/password"], b"");
    ran.fails_with("is a symlink");
    // And `unlock` doesn't start an agent over it.
    sb.run_pass(&["unlock"], b"").fails_with("is a symlink");
    assert!(sb.agent_pid().is_none());
}

#[test]
fn a_file_that_is_not_a_socket_is_refused_by_the_client_and_by_the_agent() {
    let sb = Sandbox::with_vault();
    fs::write(sb.socket(), b"not a socket").expect("plant a file");
    fs::set_permissions(sb.socket(), fs::Permissions::from_mode(0o600)).unwrap();
    sb.run_pass(&["get", "demo/db/password"], b"")
        .fails_with("is not a socket");
    sb.run_pass(&["unlock"], b"").fails_with("is not a socket");
    // The agent never removes something that isn't a socket.
    assert_eq!(fs::read(sb.socket()).unwrap(), b"not a socket");
}

#[test]
fn a_vault_directory_open_to_others_is_refused_for_the_agent_too() {
    let sb = Sandbox::with_vault();
    fs::set_permissions(&sb.dir, fs::Permissions::from_mode(0o755)).unwrap();
    for args in [&["unlock"][..], &["lock"], &["agent", "stop"]] {
        let ran = sb.run_pass(args, b"");
        ran.fails_with("chmod 700");
    }
    assert!(sb.agent_pid().is_none());
    fs::set_permissions(&sb.dir, fs::Permissions::from_mode(0o700)).unwrap();
}

// ---------------------------------------------------------------------------
// P4-8: stale sockets, a second agent, a long path.

#[test]
fn a_stale_socket_means_no_agent_and_commands_fall_back_to_the_passphrase() {
    let sb = Sandbox::with_vault();
    let secret = sb.secret("key", "demo", "db", "password");
    stale_socket(&sb);
    assert_eq!(status_text(&sb), "no agent");
    let ran = sb.run_pass(&["get", "demo/db/password"], b"");
    assert_eq!(ran.ok().stdout_str(), secret);
    sb.run(&["lock"], b"").ok();
}

/// A stale socket is replaced by a new agent, which holds `agent.lock`.
#[test]
fn a_new_agent_replaces_a_stale_socket() {
    let sb = Sandbox::with_vault();
    let secret = sb.secret("key", "demo", "db", "password");
    stale_socket(&sb);
    sb.unlock(&[]).ok();
    assert!(
        sb.agent_pid().is_some(),
        "the agent took the socket's place"
    );
    let ran = sb.run(&["get", "demo/db/password"], b"wrong\n");
    assert_eq!(ran.ok().stdout_str(), secret);
}

/// Only the holder of `agent.lock` may remove a socket. With the lock held by
/// someone else, a second agent doesn't touch the socket and doesn't start.
#[test]
fn a_stale_socket_is_removed_only_by_the_holder_of_the_agent_lock() {
    let sb = Sandbox::with_vault();
    stale_socket(&sb);
    let held = store::try_lock_agent(&sb.dir)
        .expect("the lock file")
        .expect("the lock");
    let before = fs::symlink_metadata(sb.socket()).unwrap();

    let ran = sb.run_pass(&["unlock"], b"");
    ran.fails_with("already running");
    assert!(
        sb.socket().exists(),
        "the socket was removed without the lock"
    );
    let after = fs::symlink_metadata(sb.socket()).unwrap();
    assert_eq!(
        std::os::unix::fs::MetadataExt::ino(&before),
        std::os::unix::fs::MetadataExt::ino(&after)
    );

    // Once the lock is free, the same command goes through.
    drop(held);
    sb.unlock(&[]).ok();
    assert!(sb.agent_pid().is_some());
}

/// A second agent can't start while one runs, and the first is untouched.
#[test]
fn a_second_agent_cannot_start() {
    let sb = Sandbox::with_vault();
    let secret = sb.secret("key", "demo", "db", "password");
    sb.unlock(&[]).ok();
    let pid = sb.agent_pid().expect("the first agent");

    let mut command = sb.command();
    command
        .args(["agent", "serve"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("start a second agent");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(sb.passphrase.as_bytes())
        .unwrap();
    let output = child.wait_with_output().expect("the second agent exits");
    assert!(!output.status.success());
    assert_eq!(output.stdout, [1], "the status byte says it didn't start");
    assert!(String::from_utf8_lossy(&output.stderr).contains("already running"));

    assert_eq!(
        sb.agent_pid(),
        Some(pid),
        "the first agent is still the one"
    );
    let ran = sb.run(&["get", "demo/db/password"], b"wrong\n");
    assert_eq!(ran.ok().stdout_str(), secret);
}

/// A socket path longer than `sun_path` gives a clear error that suggests a
/// shorter `VAULTLINE_DIR`, and no agent is left behind.
#[test]
fn a_socket_path_that_is_too_long_gives_a_clear_error() {
    let sb = Sandbox::with_vault_in(&"d".repeat(140));
    let ran = sb.run_pass(&["unlock"], b"");
    ran.fails_with("shorter");
    assert!(
        ran.stderr_str().contains("VAULTLINE_DIR"),
        "{}",
        ran.stderr_str()
    );
    assert!(!sb.socket().exists());
    assert!(sb.agent_pid().is_none());
    // The vault itself is fine: commands work without an agent.
    sb.run_pass(&["list"], b"").ok();
}

// ---------------------------------------------------------------------------
// Hostile frames (design §12.1: oversized frames).

fn connect(sb: &Sandbox) -> UnixStream {
    let stream = UnixStream::connect(sb.socket()).expect("connect to the agent");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("a read timeout");
    stream
}

/// What the agent sends back before closing: nothing, or one frame.
fn answer(mut stream: UnixStream) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    out
}

fn assert_bad_request(reply: &[u8]) {
    let body = protocol::read_frame(&mut &reply[..]).expect("an error frame");
    match decode_response(protocol::Kind::Status, &body).expect("a response") {
        Response::Err { code: c, .. } => assert_eq!(c, code::BAD_REQUEST),
        Response::Ok(_) => panic!("garbage was accepted"),
    }
}

fn agent_is_fine(sb: &Sandbox) {
    let status = client::status(&sb.dir)
        .expect("ask the agent")
        .expect("running");
    assert!(status.unlocked, "the agent is still unlocked");
}

#[test]
fn frames_that_are_too_long_or_empty_or_garbage_are_dropped_and_the_agent_carries_on() {
    let sb = Sandbox::with_vault();
    sb.unlock(&[]).ok();

    for length in [0u32, MAX_FRAME as u32 + 1, u32::MAX] {
        let mut stream = connect(&sb);
        stream.write_all(&length.to_le_bytes()).unwrap();
        // The body is never read: the agent answers with a bad-request error
        // (or just closes), and nothing happens.
        let reply = answer(stream);
        if !reply.is_empty() {
            assert_bad_request(&reply);
        }
        agent_is_fine(&sb);
    }

    // A frame whose body is garbage gets a bad-request error, not a crash.
    for body in [
        &[9u8, 9][..],
        &[PROTO_VERSION, 200],
        &[PROTO_VERSION, 1],
        &[1, 6, 0xff],
    ] {
        let mut stream = connect(&sb);
        let mut frame = (body.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(body);
        stream.write_all(&frame).unwrap();
        assert_bad_request(&answer(stream));
        agent_is_fine(&sb);
    }

    // A frame cut short, then the peer goes away.
    let mut stream = connect(&sb);
    stream.write_all(&100u32.to_le_bytes()).unwrap();
    stream.write_all(&[1, 2, 3]).unwrap();
    drop(stream);
    agent_is_fine(&sb);

    // A well-formed request still works afterwards.
    let frame = encode_request(&Request::Status).unwrap();
    let mut stream = connect(&sb);
    stream.write_all(&frame).unwrap();
    let reply = answer(stream);
    let body = protocol::read_frame(&mut reply.as_slice()).unwrap();
    assert!(matches!(
        decode_response(protocol::Kind::Status, &body).unwrap(),
        Response::Ok(Reply::Status { unlocked: true, .. })
    ));
}

/// A connection that sends nothing for 5 seconds is closed (design §8), and a
/// peer that dribbles a byte at a time can't hold the agent for longer than
/// that: the deadline is for the whole message.
#[test]
fn a_connection_that_stalls_or_dribbles_is_closed_after_5_seconds() {
    let sb = Sandbox::with_vault();
    sb.unlock(&[]).ok();

    // Silence.
    let started = Instant::now();
    assert!(answer(connect(&sb)).is_empty());
    let silent = started.elapsed();
    assert!(
        silent >= Duration::from_millis(4500) && silent < Duration::from_secs(8),
        "closed after {silent:?}"
    );

    // One byte of a frame every second.
    let mut stream = connect(&sb);
    stream.write_all(&100u32.to_le_bytes()).unwrap();
    let started = Instant::now();
    let mut closed = false;
    while started.elapsed() < Duration::from_secs(12) {
        sleep(Duration::from_secs(1));
        if stream.write_all(&[0]).is_err() {
            closed = true;
            break;
        }
        stream
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let mut byte = [0u8; 1];
        if let Ok(0) = stream.read(&mut byte) {
            closed = true;
            break;
        }
    }
    let held = started.elapsed();
    assert!(closed, "the agent was held for {held:?}");
    assert!(held < Duration::from_secs(8), "held for {held:?}");
    agent_is_fine(&sb);
}

/// The agent serves one connection at a time, but a refused or dead one never
/// blocks the next: a connection that is closed straight away is dropped.
#[test]
fn a_connection_closed_at_once_does_not_disturb_the_agent() {
    let sb = Sandbox::with_vault();
    sb.unlock(&[]).ok();
    for _ in 0..20 {
        drop(UnixStream::connect(sb.socket()).expect("connect"));
    }
    agent_is_fine(&sb);
    let _ = Command::new("true").status();
    assert!(matches!(
        client::resolve(&sb.dir, &[]),
        Ok(values) if values.is_empty()
    ));
    assert!(!matches!(
        client::status(&sb.dir),
        Err(AgentError::Refused(_))
    ));
}
