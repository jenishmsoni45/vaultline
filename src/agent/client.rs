//! The agent's client (`docs/design.md` §8, `docs/architecture.md` §2, D-013,
//! D-037).
//!
//! Every request opens a fresh connection, because the agent serves one
//! request per connection. Before it sends a byte, the client checks:
//!
//! 1. the vault directory (not a symlink, ours, private);
//! 2. the socket itself: a real socket, owned by the same user, so that a
//!    socket planted by someone else is never even connected to;
//! 3. after connecting, the user ID of the process at the other end.
//!
//! Any of them failing is a refusal, not a fall-back to an in-process unlock:
//! an agent that isn't ours may be after a passphrase or a value. A socket
//! that nothing listens on is different. It is a stale leftover, and means
//! there is no agent.

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::protocol::{
    self, ProtocolError, Reply, Request, Response, code, decode_response, encode_request,
};
use super::{CONNECTION_TIMEOUT, SOCKET_FILE, peer_allowed, peer_uid};
use crate::audit::{Anchor, Verdict};
use crate::inject::reference::Reference;
use crate::paths::{self, PathError};
use crate::secret::{Passphrase, SecretValue};
use crate::vault::Name;

/// How long the client waits for an answer. Unlocking runs Argon2id, which
/// takes a moment, so this is generous.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(120);

/// What went wrong talking to the agent.
#[derive(Debug)]
pub enum AgentError {
    /// There is no agent: no socket, or a stale one.
    NoAgent,
    /// The client refused to talk before sending anything. The text says why
    /// and what to do.
    Refused(String),
    /// The vault directory fails its checks.
    Path(PathError),
    /// The agent is locked, or locked itself.
    Locked(String),
    /// The agent says this reference names nothing.
    NotFound(String),
    /// Any other error the agent reported, with its message.
    Remote { code: u16, message: String },
    /// The agent's answer isn't one this client understands.
    Protocol(ProtocolError),
    Io {
        action: &'static str,
        source: io::Error,
    },
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentError::NoAgent => f.write_str("no agent is running"),
            AgentError::Refused(why) => f.write_str(why),
            AgentError::Path(e) => e.fmt(f),
            AgentError::Locked(message) => f.write_str(message),
            AgentError::NotFound(reference) => {
                write!(f, "can't resolve {reference}: no such secret")
            }
            AgentError::Remote { message, .. } => f.write_str(message),
            AgentError::Protocol(e) => write!(f, "the agent's answer was not understood: {e}"),
            AgentError::Io { action, source } => write!(f, "couldn't {action}: {source}"),
        }
    }
}

impl std::error::Error for AgentError {}

impl From<PathError> for AgentError {
    fn from(e: PathError) -> Self {
        AgentError::Path(e)
    }
}

impl From<ProtocolError> for AgentError {
    fn from(e: ProtocolError) -> Self {
        AgentError::Protocol(e)
    }
}

fn io_error(action: &'static str) -> impl FnOnce(io::Error) -> AgentError {
    move |source| AgentError::Io { action, source }
}

/// What the client looks at before it connects.
#[derive(Debug, Clone, Copy)]
pub struct SocketFacts {
    pub is_symlink: bool,
    pub is_socket: bool,
    pub uid: u32,
}

/// The decision about the socket's file, separated out so it can be tested
/// with any owner: a symlink, a non-socket, or a socket owned by another user
/// is refused before a connection is made (P4-7).
pub fn judge_socket(path: &Path, facts: SocketFacts, euid: u32) -> Result<(), AgentError> {
    if facts.is_symlink {
        return Err(AgentError::Refused(format!(
            "{} is a symlink, so it is not the agent's socket; remove it",
            path.display()
        )));
    }
    if !facts.is_socket {
        return Err(AgentError::Refused(format!(
            "{} is not a socket; remove it",
            path.display()
        )));
    }
    if !peer_allowed(facts.uid, euid) {
        return Err(AgentError::Refused(format!(
            "{} is owned by uid {}, not by you (uid {euid}), so vaultline won't talk to it; \
             if you didn't start that agent, remove the socket as its owner",
            path.display(),
            facts.uid
        )));
    }
    Ok(())
}

/// Connects to the agent after all the checks, or says there is none.
fn connect(dir: &Path) -> Result<UnixStream, AgentError> {
    match paths::check_dir(dir) {
        Ok(()) => {}
        Err(PathError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            return Err(AgentError::NoAgent);
        }
        Err(e) => return Err(e.into()),
    }
    let path: PathBuf = dir.join(SOCKET_FILE);
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(AgentError::NoAgent),
        Err(e) => return Err(io_error("inspect the agent's socket")(e)),
    };
    let euid = nix::unistd::geteuid().as_raw();
    judge_socket(
        &path,
        SocketFacts {
            is_symlink: meta.file_type().is_symlink(),
            is_socket: meta.file_type().is_socket(),
            uid: meta.uid(),
        },
        euid,
    )?;
    let stream = match UnixStream::connect(&path) {
        Ok(stream) => stream,
        // A socket file that nothing listens on is left over from an agent
        // that didn't clean up.
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) =>
        {
            return Err(AgentError::NoAgent);
        }
        Err(e) => return Err(io_error("connect to the agent")(e)),
    };
    // The file could have been replaced between the check and the connect, so
    // the process that answered is checked too, before anything is sent.
    let peer = peer_uid(&stream).map_err(io_error("check who the agent is"))?;
    if !peer_allowed(peer, euid) {
        return Err(AgentError::Refused(format!(
            "the agent on {} runs as uid {peer}, not as you (uid {euid}), so vaultline won't \
             talk to it",
            path.display()
        )));
    }
    stream
        .set_read_timeout(Some(ANSWER_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(CONNECTION_TIMEOUT)))
        .map_err(io_error("set up the connection to the agent"))?;
    Ok(stream)
}

/// Sends one request and returns the agent's reply.
pub fn call(dir: &Path, request: &Request) -> Result<Reply, AgentError> {
    let mut stream = connect(dir)?;
    let frame = encode_request(request)?;
    stream
        .write_all(&frame)
        .and_then(|()| stream.flush())
        .map_err(io_error("send the request to the agent"))?;
    drop(frame);
    let body = protocol::read_frame(&mut stream)?;
    match decode_response(request.kind(), &body)? {
        Response::Ok(reply) => Ok(reply),
        Response::Err { code: c, message } => Err(match c {
            code::LOCKED => AgentError::Locked(message),
            code::NOT_FOUND => AgentError::NotFound(message),
            _ => AgentError::Remote { code: c, message },
        }),
    }
}

/// A reply of the wrong shape for the request: the agent is not speaking this
/// protocol.
fn unexpected() -> AgentError {
    AgentError::Protocol(ProtocolError::Truncated)
}

/// The agent's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    pub unlocked: bool,
    pub idle_secs: u32,
}

/// Asks whether an agent is running, and whether it holds the key. `None`
/// means there is no agent. A refusal is an error, not `None`.
pub fn status(dir: &Path) -> Result<Option<Status>, AgentError> {
    match call(dir, &Request::Status) {
        Ok(Reply::Status {
            unlocked,
            idle_secs,
        }) => Ok(Some(Status {
            unlocked,
            idle_secs,
        })),
        Ok(_) => Err(unexpected()),
        Err(AgentError::NoAgent) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The values of `references`, in the same order.
pub fn resolve(dir: &Path, references: &[&Reference]) -> Result<Vec<SecretValue>, AgentError> {
    let request = Request::Resolve(
        references
            .iter()
            .map(|r| r.to_string().into_bytes())
            .collect(),
    );
    match call(dir, &request)? {
        Reply::Values(values) if values.len() == references.len() => Ok(values),
        _ => Err(unexpected()),
    }
}

pub fn set(dir: &Path, reference: &Reference, value: &SecretValue) -> Result<(), AgentError> {
    let request = Request::Set {
        reference: reference.to_string().into_bytes(),
        value: value.duplicate(),
    };
    expect_done(call(dir, &request)?)
}

pub fn remove(dir: &Path, reference: &Reference) -> Result<(), AgentError> {
    expect_done(call(
        dir,
        &Request::Remove(reference.to_string().into_bytes()),
    )?)
}

pub fn list(dir: &Path, project: Option<&Name>) -> Result<Vec<String>, AgentError> {
    let request = Request::List(project.map(|p| p.to_string().into_bytes()));
    match call(dir, &request)? {
        Reply::Names(names) => Ok(names),
        _ => Err(unexpected()),
    }
}

/// Unlocks a running, locked agent.
pub fn unlock(dir: &Path, passphrase: &Passphrase) -> Result<(), AgentError> {
    expect_done(call(
        dir,
        &Request::Unlock(Passphrase::new(passphrase.expose())),
    )?)
}

/// Locks the agent. `false` means there was no agent.
pub fn lock(dir: &Path) -> Result<bool, AgentError> {
    finish(call(dir, &Request::Lock))
}

/// Stops the agent. `false` means there was no agent.
pub fn stop(dir: &Path) -> Result<bool, AgentError> {
    finish(call(dir, &Request::Stop))
}

fn finish(result: Result<Reply, AgentError>) -> Result<bool, AgentError> {
    match result {
        Ok(reply) => expect_done(reply).map(|()| true),
        Err(AgentError::NoAgent) => Ok(false),
        Err(e) => Err(e),
    }
}

pub fn audit_verify(dir: &Path, expect: Option<Anchor>) -> Result<Verdict, AgentError> {
    let request = Request::AuditVerify(expect.map(|a| a.to_string().into_bytes()));
    match call(dir, &request)? {
        Reply::Verdict { passed, report } => Ok(Verdict { passed, report }),
        _ => Err(unexpected()),
    }
}

pub fn audit_head(dir: &Path) -> Result<String, AgentError> {
    match call(dir, &Request::AuditHead)? {
        Reply::Anchor(anchor) => Ok(anchor),
        _ => Err(unexpected()),
    }
}

fn expect_done(reply: Reply) -> Result<(), AgentError> {
    match reply {
        Reply::Done => Ok(()),
        _ => Err(unexpected()),
    }
}
