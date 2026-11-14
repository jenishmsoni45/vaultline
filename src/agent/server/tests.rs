//! Unit tests of the agent's request handling, in one process, with the peer's
//! user ID injected (S9: "unit tests of the peer decision").

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;

use static_assertions::assert_not_impl_any;

use super::*;
use crate::agent::protocol::{Kind, encode_request};
use crate::secret::SecretValue;
use crate::vault::KdfParams;

assert_not_impl_any!(Agent: std::fmt::Debug, std::fmt::Display);

const CHEAP: KdfParams = KdfParams {
    m_kib: 8,
    t: 1,
    p: 1,
};
const PASSPHRASE: &[u8] = b"fake-passphrase-for-server-tests";

struct Fixture {
    tmp: tempfile::TempDir,
    agent: Agent,
}

impl Fixture {
    /// A vault with one secret, and an agent that holds its key.
    fn unlocked() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), Permissions::from_mode(0o700)).unwrap();
        let passphrase = Passphrase::new(PASSPHRASE);
        let vault = Vault::create(tmp.path(), &passphrase, CHEAP).unwrap();
        vault
            .set(
                &Name::new("demo").unwrap(),
                &Name::new("db").unwrap(),
                &Name::new("password").unwrap(),
                &SecretValue::new(b"fake-secret-value"),
            )
            .unwrap();
        let mut agent = Agent::new(tmp.path(), Duration::from_secs(60));
        agent.unlock(&passphrase).unwrap();
        Fixture { tmp, agent }
    }

    fn euid(&self) -> u32 {
        self.agent.euid
    }

    /// Sends `request` over a socket pair and returns what the agent did.
    fn exchange(&mut self, request: &Request, peer: io::Result<u32>) -> (Option<Response>, Flow) {
        let (client, server) = UnixStream::pair().unwrap();
        // Before the server end goes: macOS refuses socket options on a
        // socket whose peer has closed.
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        (&client)
            .write_all(&encode_request(request).unwrap())
            .unwrap();
        let flow = self.agent.serve_connection(server, peer);
        // The server end is gone, so reading ends at the answer.
        let mut reply = Vec::new();
        let _ = (&client).read_to_end(&mut reply);
        if reply.is_empty() {
            return (None, flow);
        }
        let body = protocol::read_frame(&mut reply.as_slice()).unwrap();
        (
            Some(protocol::decode_response(request.kind(), &body).unwrap()),
            flow,
        )
    }

    fn ask(&mut self, request: &Request) -> Response {
        let euid = self.euid();
        self.exchange(request, Ok(euid)).0.expect("an answer")
    }
}

fn is_error(response: &Response, wanted: u16) -> bool {
    matches!(response, Response::Err { code, .. } if *code == wanted)
}

#[test]
fn a_connection_from_another_uid_is_closed_without_reading_a_byte() {
    let mut f = Fixture::unlocked();
    let other = f.euid().wrapping_add(1);
    // A Lock request that, if it were read, would wipe the key.
    let (answer, flow) = f.exchange(&Request::Lock, Ok(other));
    assert!(answer.is_none(), "nothing is sent back");
    assert_eq!(flow, Flow::Continue);
    assert!(f.agent.is_unlocked(), "the request was not served");
    // Root is another user, and gets no exception.
    if f.euid() != 0 {
        let (answer, _) = f.exchange(&Request::Stop, Ok(0));
        assert!(answer.is_none());
        assert!(f.agent.is_unlocked());
    }
}

#[test]
fn a_connection_whose_peer_cannot_be_identified_is_closed_without_reading() {
    let mut f = Fixture::unlocked();
    let (answer, flow) = f.exchange(&Request::Stop, Err(io::Error::other("no credentials")));
    assert!(answer.is_none());
    assert_eq!(flow, Flow::Continue);
    assert!(f.agent.is_unlocked());
}

#[test]
fn the_same_uid_is_served() {
    let mut f = Fixture::unlocked();
    match f.ask(&Request::Status) {
        Response::Ok(Reply::Status {
            unlocked,
            idle_secs,
        }) => {
            assert!(unlocked);
            assert!(idle_secs <= 60);
        }
        _ => panic!("expected a status"),
    }
}

#[test]
fn resolve_returns_values_in_request_order_and_duplicates_work() {
    let mut f = Fixture::unlocked();
    let one = b"vault://demo/db/password".to_vec();
    let reply = f.ask(&Request::Resolve(vec![one.clone(), one]));
    match reply {
        Response::Ok(Reply::Values(values)) => {
            assert_eq!(values.len(), 2);
            assert!(values.iter().all(|v| v.expose() == b"fake-secret-value"));
        }
        _ => panic!("expected values"),
    }
}

#[test]
fn a_missing_reference_is_not_found_and_names_it() {
    let mut f = Fixture::unlocked();
    let reply = f.ask(&Request::Resolve(vec![b"vault://demo/db/nothing".to_vec()]));
    match reply {
        Response::Err { code, message } => {
            assert_eq!(code, code::NOT_FOUND);
            assert_eq!(message, "vault://demo/db/nothing");
        }
        _ => panic!("expected an error"),
    }
}

#[test]
fn a_malformed_reference_is_a_bad_request_that_does_not_echo_unbounded_bytes() {
    let mut f = Fixture::unlocked();
    let reply = f.ask(&Request::Resolve(vec![vec![b'x'; 5000]]));
    match reply {
        Response::Err { code, message } => {
            assert_eq!(code, code::BAD_REQUEST);
            assert!(message.len() < 600, "{} bytes", message.len());
        }
        _ => panic!("expected an error"),
    }
    assert!(
        f.agent.is_unlocked(),
        "a bad request doesn't lock the agent"
    );
}

#[test]
fn lock_wipes_the_key_and_later_requests_say_locked() {
    let mut f = Fixture::unlocked();
    assert!(matches!(f.ask(&Request::Lock), Response::Ok(Reply::Done)));
    assert!(!f.agent.is_unlocked());
    for request in [
        Request::Resolve(vec![b"vault://demo/db/password".to_vec()]),
        Request::List(None),
        Request::Remove(b"vault://demo/db/password".to_vec()),
        Request::AuditHead,
        Request::AuditVerify(None),
    ] {
        assert!(
            is_error(&f.ask(&request), code::LOCKED),
            "{:?}",
            request.kind()
        );
    }
    // Locking again is harmless.
    assert!(matches!(f.ask(&Request::Lock), Response::Ok(Reply::Done)));
}

#[test]
fn unlock_when_unlocked_is_a_bad_request_and_when_locked_needs_the_right_passphrase() {
    let mut f = Fixture::unlocked();
    let again = Request::Unlock(Passphrase::new(PASSPHRASE));
    assert!(is_error(&f.ask(&again), code::BAD_REQUEST));
    f.ask(&Request::Lock);
    let wrong = Request::Unlock(Passphrase::new(b"not-the-passphrase"));
    assert!(is_error(&f.ask(&wrong), code::VAULT));
    assert!(!f.agent.is_unlocked());
    let right = Request::Unlock(Passphrase::new(PASSPHRASE));
    assert!(matches!(f.ask(&right), Response::Ok(Reply::Done)));
    assert!(f.agent.is_unlocked());
}

#[test]
fn stop_answers_and_ends_the_loop_and_removes_the_socket() {
    let mut f = Fixture::unlocked();
    let socket = f.tmp.path().join(SOCKET_FILE);
    fs::write(&socket, b"stand-in for the socket").unwrap();
    let (answer, flow) = f.exchange(&Request::Stop, Ok(f.euid()));
    assert!(matches!(answer, Some(Response::Ok(Reply::Done))));
    assert_eq!(flow, Flow::Stop);
    assert!(!f.agent.is_unlocked());
    assert!(!socket.exists(), "the socket is gone before the answer");
}

#[test]
fn only_the_six_requests_reset_the_idle_timer() {
    let mut f = Fixture::unlocked();
    let reset = |f: &mut Fixture| {
        f.agent.deadline = Instant::now() + Duration::from_secs(1);
    };
    for request in [Request::Status, Request::Lock] {
        reset(&mut f);
        let before = f.agent.deadline;
        f.ask(&request);
        assert_eq!(
            f.agent.deadline,
            before,
            "{:?} moved the timer",
            request.kind()
        );
        if request.kind() == Kind::Lock {
            f.agent.unlock(&Passphrase::new(PASSPHRASE)).unwrap();
        }
    }
    for request in [
        Request::Resolve(vec![b"vault://demo/db/password".to_vec()]),
        Request::List(None),
        Request::AuditHead,
        Request::AuditVerify(None),
        Request::Set {
            reference: b"vault://demo/db/other".to_vec(),
            value: SecretValue::new(b"fake"),
        },
        Request::Remove(b"vault://demo/db/other".to_vec()),
    ] {
        reset(&mut f);
        let before = f.agent.deadline;
        f.ask(&request);
        assert!(
            f.agent.deadline > before,
            "{:?} didn't reset the timer",
            request.kind()
        );
    }
}

/// Design §8: if the file stops verifying under the agent's key, for example
/// after `rotate` elsewhere, the agent locks itself and says so. It writes no
/// `lock` record, because it can't have the audit key any more (D-048).
#[test]
fn a_vault_changed_under_the_agent_locks_it() {
    let mut f = Fixture::unlocked();
    crate::vault::rotate(f.tmp.path(), &Passphrase::new(PASSPHRASE)).unwrap();
    let reply = f.ask(&Request::Resolve(vec![
        b"vault://demo/db/password".to_vec(),
    ]));
    match reply {
        Response::Err { code, message } => {
            assert_eq!(code, code::LOCKED);
            assert!(message.contains("locked itself"), "{message}");
        }
        _ => panic!("expected an error"),
    }
    assert!(!f.agent.is_unlocked());
}

#[test]
fn a_request_the_server_cannot_decode_gets_a_bad_request() {
    let f = Fixture::unlocked();
    let mut agent = f.agent;
    let (client, server) = UnixStream::pair().unwrap();
    (&client).write_all(&2u32.to_le_bytes()).unwrap();
    (&client).write_all(&[7, 7]).unwrap();
    let euid = agent.euid;
    agent.serve_connection(server, Ok(euid));
    let mut reply = Vec::new();
    (&client).read_to_end(&mut reply).unwrap();
    let body = protocol::read_frame(&mut reply.as_slice()).unwrap();
    let response = protocol::decode_response(Kind::Status, &body).unwrap();
    assert!(is_error(&response, code::BAD_REQUEST));
    assert!(agent.is_unlocked());
}

#[test]
fn a_stale_socket_is_cleared_but_nothing_else_is() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join(SOCKET_FILE);
    // Nothing there: fine.
    assert!(clear_stale_socket(&path).is_ok());
    // A socket file: removed.
    drop(UnixListener::bind(&path).unwrap());
    assert!(path.exists());
    clear_stale_socket(&path).unwrap();
    assert!(!path.exists());
    // A regular file or a symlink: refused, and left alone.
    fs::write(&path, b"data").unwrap();
    assert!(matches!(
        clear_stale_socket(&path),
        Err(ServeError::NotASocket(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), b"data");
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink("/dev/null", &path).unwrap();
    assert!(matches!(
        clear_stale_socket(&path),
        Err(ServeError::NotASocket(_))
    ));
    assert!(fs::symlink_metadata(&path).is_ok());
}
