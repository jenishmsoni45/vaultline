//! The agent process (`docs/design.md` §8, `docs/architecture.md` §4, D-013,
//! D-014, D-037, D-048, D-049).
//!
//! One thread, with `poll` on the listening socket and a pipe that signal
//! handlers write to, and the idle timer as the timeout. One request per
//! connection.
//!
//! What it holds: the master key, inside a [`Vault`] that wipes it when
//! dropped. Subkeys and decrypted items exist only for the length of one
//! request, and nothing decrypted is kept. The key is wiped on `Lock`, on
//! `Stop`, on SIGTERM and SIGINT, when the idle timer runs out, and when the
//! vault turns out to have changed under it.
//!
//! The peer check comes first: a connection from another user ID is closed
//! before a byte of it is read.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::stat::{Mode, umask};
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};

use super::protocol::{
    self, ProtocolError, Reply, Request, Response, code, decode_request, encode_response,
};
use super::{CONNECTION_TIMEOUT, SOCKET_FILE, check_socket_path, peer_allowed, peer_uid};
use crate::audit::{Anchor, Verdict};
use crate::inject::reference::{Reference, escape};
use crate::paths::{self, PathError};
use crate::secret::Passphrase;
use crate::session::{LockEvent, Origin, ResolveError, Session, open};
use crate::vault::{Error, Name, Vault, store};

/// Why the agent couldn't start. The message says how to fix it.
#[derive(Debug)]
pub enum ServeError {
    /// Another agent holds `agent.lock`.
    AlreadyRunning,
    /// The socket's path is longer than `sun_path` allows.
    PathTooLong { path: PathBuf, length: usize },
    /// Something other than a socket is in the socket's place.
    NotASocket(PathBuf),
    /// The directory fails its checks.
    Path(PathError),
    /// The vault wouldn't open: wrong passphrase, a damaged vault or log.
    Vault(Error),
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl fmt::Display for ServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServeError::AlreadyRunning => f.write_str(
                "another agent is already running for this vault (`vaultline agent stop` ends it)",
            ),
            ServeError::PathTooLong { path, length } => write!(
                f,
                "the socket path {} is {length} bytes, more than the {} this system allows; \
                 point VAULTLINE_DIR at a shorter path",
                path.display(),
                super::MAX_SOCKET_PATH
            ),
            ServeError::NotASocket(path) => write!(
                f,
                "{} is in the agent's socket's place and is not a socket; remove it",
                path.display()
            ),
            ServeError::Path(e) => e.fmt(f),
            ServeError::Vault(e) => e.fmt(f),
            ServeError::Io {
                action,
                path,
                source,
            } => write!(f, "couldn't {action} {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for ServeError {}

impl From<Error> for ServeError {
    fn from(e: Error) -> Self {
        ServeError::Vault(e)
    }
}

impl From<PathError> for ServeError {
    fn from(e: PathError) -> Self {
        ServeError::Path(e)
    }
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> ServeError {
    ServeError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

/// The pipe that the signal handlers write to. SIGTERM and SIGINT stop the
/// agent. SIGHUP gets a handler that does nothing, which is how a process
/// ignores a signal without `unsafe` code (design §8).
struct Signals {
    stop: UnixStream,
}

impl Signals {
    fn install() -> io::Result<Signals> {
        let (read, write) = UnixStream::pair()?;
        read.set_nonblocking(true)?;
        write.set_nonblocking(true)?;
        signal_hook::low_level::pipe::register(SIGTERM, write.try_clone()?)?;
        signal_hook::low_level::pipe::register(SIGINT, write)?;
        let ignored = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        signal_hook::flag::register(SIGHUP, ignored)?;
        Ok(Signals { stop: read })
    }

    /// Empties the pipe and says whether a stopping signal arrived.
    fn arrived(&self) -> bool {
        let mut any = false;
        let mut buf = [0u8; 16];
        while let Ok(n) = (&self.stop).read(&mut buf) {
            if n == 0 {
                break;
            }
            any = true;
        }
        any
    }
}

/// Reads from a stream with a deadline for the whole message, not for each
/// read, so a peer that sends a byte every few seconds can't hold the one
/// thread forever.
struct Deadline<'a> {
    stream: &'a UnixStream,
    until: Instant,
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self
            .until
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "the request took too long"))?;
        self.stream.set_read_timeout(Some(left))?;
        (self.stream).read(buf)
    }
}

/// What to do after a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Continue,
    Stop,
}

/// Why the loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exit {
    Idle,
    Signal,
}

/// The agent's state: the unlocked vault, if any, and the idle timer.
pub struct Agent {
    dir: PathBuf,
    euid: u32,
    idle: Duration,
    deadline: Instant,
    vault: Option<Vault>,
}

impl Agent {
    /// An agent for the vault in `dir`, locked, with the timer running.
    pub fn new(dir: &Path, idle: Duration) -> Agent {
        Agent {
            dir: dir.to_path_buf(),
            euid: nix::unistd::geteuid().as_raw(),
            idle,
            deadline: Instant::now() + idle,
            vault: None,
        }
    }

    /// Whether the agent holds the key.
    pub fn is_unlocked(&self) -> bool {
        self.vault.is_some()
    }

    fn reset_idle(&mut self) {
        self.deadline = Instant::now() + self.idle;
    }

    /// Unlocks with `passphrase`. Appends `unlock` with the agent as origin.
    pub fn unlock(&mut self, passphrase: &Passphrase) -> Result<(), Error> {
        let vault = open(&self.dir, passphrase, Origin::Agent)?;
        self.vault = Some(vault);
        self.reset_idle();
        Ok(())
    }

    /// Wipes the key. The record goes first, while the key can still read the
    /// audit key; it is best effort (D-048), and the wipe happens whatever the
    /// record's fate. Returns the record's error, if it had one.
    fn wipe(&mut self, event: LockEvent) -> Result<(), Error> {
        let Some(vault) = self.vault.take() else {
            return Ok(());
        };
        let recorded = Session::new(&vault).record_lock(event);
        drop(vault);
        recorded.map(|_| ())
    }

    /// Serves one connection, after the peer check. `peer` is the other end's
    /// user ID, or the error from asking for it; a connection whose peer isn't
    /// us, or can't be told, is dropped without a byte being read.
    fn serve_connection(&mut self, stream: UnixStream, peer: io::Result<u32>) -> Flow {
        match peer {
            Ok(uid) if peer_allowed(uid, self.euid) => {}
            _ => return Flow::Continue,
        }
        let until = Instant::now() + CONNECTION_TIMEOUT;
        let mut reader = Deadline {
            stream: &stream,
            until,
        };
        let request = match protocol::read_frame(&mut reader) {
            Ok(body) => decode_request(&body),
            Err(e) => Err(e),
        };
        let (response, flow) = match request {
            Ok(request) => self.handle(request),
            Err(ProtocolError::Io(_)) => return Flow::Continue,
            Err(e) => (
                Response::error(code::BAD_REQUEST, format!("bad request: {e}")),
                Flow::Continue,
            ),
        };
        let frame = encode_response(&response).or_else(|_| {
            encode_response(&Response::error(
                code::TOO_LARGE,
                "the answer is larger than the agent's 1 MiB message limit",
            ))
        });
        if let Ok(frame) = frame {
            let _ = stream.set_write_timeout(Some(CONNECTION_TIMEOUT));
            let _ = (&stream).write_all(&frame);
        }
        flow
    }

    fn handle(&mut self, request: Request) -> (Response, Flow) {
        match request {
            Request::Status => {
                let idle_secs = self
                    .deadline
                    .checked_duration_since(Instant::now())
                    .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX));
                (
                    Response::Ok(Reply::Status {
                        unlocked: self.is_unlocked(),
                        idle_secs,
                    }),
                    Flow::Continue,
                )
            }
            Request::Lock => (done(self.wipe(LockEvent::Locked)), Flow::Continue),
            Request::Stop => {
                let recorded = self.wipe(LockEvent::Stopped);
                // The socket goes before the answer, so that a command that
                // has seen the answer can rely on it being gone.
                remove_socket(&self.dir);
                (done(recorded), Flow::Stop)
            }
            Request::Unlock(passphrase) => {
                if self.is_unlocked() {
                    return (
                        Response::error(code::BAD_REQUEST, "the agent is already unlocked"),
                        Flow::Continue,
                    );
                }
                (done(self.unlock(&passphrase)), Flow::Continue)
            }
            other => (self.serve_unlocked(other), Flow::Continue),
        }
    }

    /// The six requests that need the key, and that reset the idle timer
    /// (design §8).
    fn serve_unlocked(&mut self, request: Request) -> Response {
        let Some(vault) = self.vault.as_ref() else {
            return Response::error(code::LOCKED, "the agent is locked; run `vaultline unlock`");
        };
        let outcome = answer(&Session::new(vault), request);
        self.reset_idle();
        match outcome {
            Ok(reply) => Response::Ok(reply),
            Err(failure) => {
                if failure.vault_changed {
                    // The file doesn't verify under this key any more, for
                    // example after `rotate`: forget the key (design §8).
                    self.vault = None;
                }
                failure.response
            }
        }
    }

    /// The loop: wait for a connection, a signal or the timer.
    fn run(&mut self, listener: &UnixListener, signals: &Signals) -> Exit {
        loop {
            let Some(left) = self
                .deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
            else {
                return Exit::Idle;
            };
            let chunk = u16::try_from(left.as_millis().min(60_000)).unwrap_or(u16::MAX);
            let mut fds = [
                PollFd::new(listener.as_fd(), PollFlags::POLLIN),
                PollFd::new(signals.stop.as_fd(), PollFlags::POLLIN),
            ];
            match poll(&mut fds, PollTimeout::from(chunk)) {
                Ok(_) => {}
                Err(Errno::EINTR) => continue,
                Err(_) => return Exit::Signal,
            }
            let ready = |fd: &PollFd<'_>| {
                fd.revents().is_some_and(|r| {
                    r.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
                })
            };
            let (connection, signal) = match fds.as_slice() {
                [connection, signal] => (ready(connection), ready(signal)),
                _ => (false, false),
            };
            if signal && signals.arrived() {
                return Exit::Signal;
            }
            if connection {
                // A connection that vanished already makes accept fail or
                // block-free `WouldBlock`; either way go round again.
                if let Ok((stream, _)) = listener.accept() {
                    // On macOS an accepted socket inherits the listener's
                    // non-blocking mode; the deadline logic needs blocking.
                    if stream.set_nonblocking(false).is_err() {
                        continue;
                    }
                    let peer = peer_uid(&stream);
                    if self.serve_connection(stream, peer) == Flow::Stop {
                        return Exit::Signal;
                    }
                }
            }
        }
    }

    /// What happens when the loop ends: the key goes, with a record if the
    /// vault still lets one be written, and the socket goes.
    fn finish(&mut self, exit: Exit) {
        let event = match exit {
            Exit::Idle => LockEvent::IdleTimeout,
            Exit::Signal => LockEvent::Stopped,
        };
        let _ = self.wipe(event);
        remove_socket(&self.dir);
    }
}

fn done(result: Result<(), Error>) -> Response {
    match result {
        Ok(()) => Response::Ok(Reply::Done),
        Err(e) => failure(&e).response,
    }
}

/// A failed request: the answer, and whether the vault changed under the key.
struct Failure {
    response: Response,
    vault_changed: bool,
}

fn failure(e: &Error) -> Failure {
    match e {
        Error::Auth(_) => Failure {
            response: Response::error(
                code::LOCKED,
                format!(
                    "the vault changed since the agent unlocked it (for example by `vaultline \
                     rotate`), so the agent locked itself: {e}; run `vaultline unlock`"
                ),
            ),
            vault_changed: true,
        },
        Error::Busy => Failure {
            response: Response::error(code::BUSY, e.to_string()),
            vault_changed: false,
        },
        Error::ValueTooLarge => Failure {
            response: Response::error(code::TOO_LARGE, e.to_string()),
            vault_changed: false,
        },
        _ => Failure {
            response: Response::error(code::VAULT, e.to_string()),
            vault_changed: false,
        },
    }
}

fn bad_request(message: String) -> Failure {
    Failure {
        response: Response::error(code::BAD_REQUEST, message),
        vault_changed: false,
    }
}

fn reference(bytes: &[u8]) -> Result<Reference, Failure> {
    Reference::parse(bytes)
        .map_err(|why| bad_request(format!("{} is not a valid reference: {why}", escape(bytes))))
}

fn text(bytes: &[u8], what: &str) -> Result<String, Failure> {
    String::from_utf8(bytes.to_vec()).map_err(|_| bad_request(format!("the {what} is not text")))
}

/// Answers one of the six requests that need the key.
fn answer(session: &Session<'_>, request: Request) -> Result<Reply, Failure> {
    match request {
        Request::Resolve(references) => {
            let parsed: Vec<Reference> = references
                .iter()
                .map(|r| reference(r))
                .collect::<Result<_, _>>()?;
            let wanted: BTreeSet<&Reference> = parsed.iter().collect();
            let resolved = session.resolve(&wanted).map_err(|e| match e {
                ResolveError::Missing(r) => Failure {
                    response: Response::error(code::NOT_FOUND, r.to_string()),
                    vault_changed: false,
                },
                ResolveError::Failed(e) => failure(&e),
            })?;
            let values = parsed
                .iter()
                .filter_map(|r| resolved.get(r).map(|v| v.duplicate()))
                .collect();
            Ok(Reply::Values(values))
        }
        Request::Set {
            reference: r,
            value,
        } => {
            session
                .set(&reference(&r)?, &value)
                .map_err(|e| failure(&e))?;
            Ok(Reply::Done)
        }
        Request::Remove(r) => {
            session.rm(&reference(&r)?).map_err(|e| failure(&e))?;
            Ok(Reply::Done)
        }
        Request::List(project) => {
            let project = project
                .map(|p| {
                    let name = text(&p, "project name")?;
                    Name::new(&name).map_err(|why| {
                        bad_request(format!(
                            "{} is not a valid project name: {why}",
                            escape(name.as_bytes())
                        ))
                    })
                })
                .transpose()?;
            let entries = session.list(project.as_ref()).map_err(|e| failure(&e))?;
            Ok(Reply::Names(
                entries.iter().map(ToString::to_string).collect(),
            ))
        }
        Request::AuditVerify(expect) => {
            let expect = expect
                .map(|a| {
                    let a = text(&a, "anchor")?;
                    Anchor::parse(&a).map_err(|e| bad_request(e.to_string()))
                })
                .transpose()?;
            let Verdict { passed, report } =
                session.audit_verify(expect).map_err(|e| failure(&e))?;
            Ok(Reply::Verdict { passed, report })
        }
        Request::AuditHead => {
            let anchor = session.audit_head().map_err(|e| failure(&e))?;
            Ok(Reply::Anchor(anchor.to_string()))
        }
        Request::Unlock(_) | Request::Lock | Request::Stop | Request::Status => Err(bad_request(
            "that request doesn't take this path".to_string(),
        )),
    }
}

/// Removes the agent's socket. Called only while holding `agent.lock`, so
/// nobody else's socket can be in the way.
fn remove_socket(dir: &Path) {
    let _ = fs::remove_file(dir.join(SOCKET_FILE));
}

/// Takes a stale socket's place: the holder of `agent.lock` removes whatever
/// socket is left by an agent that didn't clean up, and refuses anything that
/// isn't a socket (design §8).
fn clear_stale_socket(path: &Path) -> Result<(), ServeError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            fs::remove_file(path).map_err(|e| io_error("remove the stale socket", path, e))
        }
        Ok(_) => Err(ServeError::NotASocket(path.to_path_buf())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_error("inspect", path, e)),
    }
}

/// Binds the socket with a umask of 077, so it is never reachable by anyone
/// else, not even for an instant.
fn bind(path: &Path) -> Result<UnixListener, ServeError> {
    let before = umask(Mode::from_bits_truncate(0o077));
    let bound = UnixListener::bind(path);
    umask(before);
    let listener = bound.map_err(|e| io_error("bind", path, e))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| io_error("configure", path, e))?;
    Ok(listener)
}

/// Runs the agent until it stops (`vaultline agent serve`).
///
/// `passphrase` came through the agent's stdin pipe. `ready` runs once the
/// socket is bound, and tells the `unlock` that started the agent. If anything
/// fails before that, the error comes back and nothing is left behind.
pub fn run(
    dir: &Path,
    idle: Duration,
    passphrase: &Passphrase,
    ready: impl FnOnce() -> io::Result<()>,
) -> Result<(), ServeError> {
    paths::check_dir(dir)?;
    let socket = dir.join(SOCKET_FILE);
    check_socket_path(&socket).map_err(|length| ServeError::PathTooLong {
        path: socket.clone(),
        length,
    })?;
    let _agent_lock = store::try_lock_agent(dir)?.ok_or(ServeError::AlreadyRunning)?;
    let signals = Signals::install().map_err(|e| io_error("handle signals in", dir, e))?;

    let mut agent = Agent::new(dir, idle);
    agent.unlock(passphrase)?;
    clear_stale_socket(&socket)?;
    let listener = bind(&socket)?;
    if let Err(e) = ready() {
        agent.finish(Exit::Signal);
        return Err(io_error("report that the agent is ready in", dir, e));
    }
    // From here the timer counts from the moment the agent is ready.
    agent.reset_idle();
    let exit = agent.run(&listener, &signals);
    agent.finish(exit);
    Ok(())
}

#[cfg(test)]
mod tests;
