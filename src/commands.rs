//! What each command does (`docs/design.md` §4, §4.1, `docs/architecture.md` §2).
//!
//! A command that needs the vault goes to the agent if one is running and
//! unlocked, and otherwise works in its own process: it asks for the
//! passphrase, opens the vault, does the work and drops the key when it
//! returns. A locked agent stays locked. `init`, `passwd` and `rotate` never
//! use the agent, so that nobody at an unlocked terminal can change the keys.
//! Both paths run the same code (`crate::session`) and leave the same audit
//! records.
//!
//! Every command follows the same order:
//!
//! 1. parse everything that came from the user (references, templates, env
//!    files), so that a typo costs no passphrase and no Argon2id run;
//! 2. refuse early if the output would be a regular file;
//! 3. open the vault, which asks for the passphrase;
//! 4. resolve every reference, all or nothing, before anything is written or
//!    started (§4.1).
//!
//! Errors say what failed and how to fix it, and never contain a secret value
//! or a passphrase (NFR-20).

use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use zeroize::Zeroizing;

use crate::agent::client::{self, AgentError};
use crate::agent::server::{self, ServeError};
use crate::agent::{DEFAULT_IDLE_TIMEOUT, IdleError, parse_idle_timeout};
use crate::audit::{Anchor, AuditError};
use crate::hardening::HardeningError;
use crate::inject::envfile::{self, EnvFileError, MAX_ENV_FILE_LEN};
use crate::inject::mask::MaskError;
use crate::inject::output::{self, OutputError, raw_stdout, say};
use crate::inject::reference::{Reference, ReferenceError, escape};
use crate::inject::run::{self, RunError};
use crate::inject::template::{MAX_TEMPLATE_LEN, Resolved, Template, TemplateError};
use crate::input::{self, InputError, MAX_PASSPHRASE_LEN, Passphrases, Stdin};
use crate::paths::{self, PathError};
use crate::secret::{Passphrase, SecretValue};
use crate::session::{self, Origin, ResolveError, Session};
use crate::vault::{self, KdfParams, Name, NameError, Vault, store};

/// Everything that can make a command fail. Each one prints as a single line
/// that says what went wrong and, where there is one, how to fix it.
#[derive(Debug)]
pub enum CliError {
    Hardening(HardeningError),
    Vault(vault::Error),
    Input(InputError),
    Output(OutputError),
    Path(PathError),
    /// A reference typed on the command line.
    BadReference {
        text: String,
        why: ReferenceError,
    },
    /// A project name typed on the command line.
    BadProject {
        text: String,
        why: NameError,
    },
    Template(TemplateError),
    EnvFile {
        path: PathBuf,
        why: EnvFileError,
    },
    /// A file or standard input couldn't be read.
    Read {
        what: &'static str,
        source: io::Error,
    },
    /// A file or standard input is over its size limit.
    TooLarge {
        what: &'static str,
    },
    /// A reference names nothing in the vault.
    Unresolved {
        reference: Reference,
        consequence: &'static str,
    },
    Run(RunError),
    Mask(MaskError),
    /// Writing to standard output failed.
    Stdout(io::Error),
    /// The agent refused, or couldn't be reached.
    Agent(AgentError),
    /// The agent process couldn't start, or said why it stopped.
    Serve(ServeError),
    /// An audit anchor that doesn't parse.
    Audit(AuditError),
    /// `--idle-timeout` isn't `<n>s`, `<n>m` or `<n>h` from 1s to 24h.
    Idle(IdleError),
    /// `unlock --idle-timeout` while an agent is already running (D-050).
    AgentAlreadyRunning,
    /// The agent process couldn't be started.
    Spawn(io::Error),
    /// The agent process reported a startup failure, or none at all.
    AgentStartup(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Hardening(e) => e.fmt(f),
            CliError::Vault(e) => e.fmt(f),
            CliError::Input(e) => e.fmt(f),
            CliError::Output(e) => e.fmt(f),
            CliError::Path(e) => e.fmt(f),
            CliError::BadReference { text, why } => write!(
                f,
                "{text} is not a valid reference: {why} (for example vault://project/item/field)"
            ),
            CliError::BadProject { text, why } => {
                write!(f, "{text} is not a valid project name: {why}")
            }
            CliError::Template(e) => write!(f, "the template is not valid: {e}"),
            CliError::EnvFile { path, why } => {
                write!(f, "the env file {} is not valid: {why}", path.display())
            }
            CliError::Read { what, source } => write!(f, "can't read the {what}: {source}"),
            CliError::TooLarge { what } => {
                write!(f, "the {what} is larger than the 16 MiB limit")
            }
            CliError::Unresolved {
                reference,
                consequence,
            } => write!(
                f,
                "can't resolve {reference}: no such secret (`vaultline list` shows what is \
                 stored); {consequence}"
            ),
            CliError::Run(e) => e.fmt(f),
            CliError::Mask(e) => e.fmt(f),
            CliError::Stdout(e) => write!(f, "can't write to standard output: {e}"),
            CliError::Agent(e) => e.fmt(f),
            CliError::Serve(e) => e.fmt(f),
            CliError::Audit(e) => e.fmt(f),
            CliError::Idle(e) => e.fmt(f),
            CliError::AgentAlreadyRunning => f.write_str(
                "an agent is already running, and its idle timeout can't be changed while it \
                 runs; run `vaultline agent stop`, then `vaultline unlock --idle-timeout ...`",
            ),
            CliError::Spawn(e) => write!(f, "can't start the agent: {e}"),
            CliError::AgentStartup(why) => write!(f, "the agent didn't start: {why}"),
        }
    }
}

impl std::error::Error for CliError {}

macro_rules! from_error {
    ($($variant:ident($ty:ty)),* $(,)?) => {
        $(impl From<$ty> for CliError {
            fn from(e: $ty) -> Self { CliError::$variant(e) }
        })*
    };
}

from_error! {
    Hardening(HardeningError),
    Vault(vault::Error),
    Input(InputError),
    Output(OutputError),
    Path(PathError),
    Template(TemplateError),
    Run(RunError),
    Mask(MaskError),
    Agent(AgentError),
    Serve(ServeError),
    Audit(AuditError),
    Idle(IdleError),
}

/// A reference typed as a command-line argument: with or without `vault://`.
fn parse_reference(text: &str) -> Result<Reference, CliError> {
    Reference::parse_cli(text).map_err(|why| CliError::BadReference {
        text: escape(text.as_bytes()),
        why,
    })
}

/// The vault directory, after the checks that don't need the passphrase: it
/// is a private directory, and it holds a vault.
fn existing_vault_dir() -> Result<PathBuf, CliError> {
    let dir = paths::vault_dir()?;
    paths::check_dir(&dir).map_err(vault::Error::from)?;
    if !store::vault_exists(&dir)? {
        return Err(vault::Error::Missing(dir).into());
    }
    Ok(dir)
}

/// Opens the vault with an already-entered passphrase, and warns if its
/// Argon2id parameters are weaker than today's defaults (`vault-format.md`
/// §4.4). A wrong passphrase is counted, and a right one is recorded
/// (`crate::session::open`).
fn open_with(dir: &Path, passphrase: &Passphrase) -> Result<Vault, CliError> {
    let vault = session::open(dir, passphrase, Origin::Command)?;
    if vault.kdf_params().below_defaults() {
        say(
            "vaultline: warning: this vault uses weaker Argon2id parameters than the current \
             defaults; run `vaultline passwd` to upgrade it",
        );
    }
    Ok(vault)
}

/// How a command proves it may open the vault.
enum Auth {
    /// An unlocked agent will answer. No passphrase is needed.
    Agent,
    Passphrase(Passphrase),
}

/// What opening the vault is for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    /// Reading or changing secrets: the audit log must be in order.
    Use,
    /// `audit verify` and `audit head`: they must run on a damaged log too.
    Inspect,
}

/// Looks for an unlocked agent, and otherwise asks for the passphrase
/// (architecture §2). With an agent and `--passphrase-stdin`, the passphrase
/// line is read and thrown away (D-054). An agent that is locked, or not there,
/// is not used, and a locked one is left locked. An agent that fails the UID
/// check, or sits in a directory that fails its checks, is a refusal.
fn authenticate(passphrases: &mut Passphrases) -> Result<Auth, CliError> {
    let dir = paths::vault_dir()?;
    if client::status(&dir)?.is_some_and(|s| s.unlocked) {
        passphrases.discard()?;
        return Ok(Auth::Agent);
    }
    Ok(Auth::Passphrase(passphrases.ask("Passphrase: ")?))
}

/// Where a command's requests are answered.
enum Backend {
    Agent(PathBuf),
    Local(Vault),
}

impl Backend {
    fn open(dir: &Path, auth: Auth, purpose: Purpose) -> Result<Backend, CliError> {
        Ok(match auth {
            Auth::Agent => Backend::Agent(dir.to_path_buf()),
            Auth::Passphrase(passphrase) if purpose == Purpose::Inspect => {
                Backend::Local(session::open_inspecting(dir, &passphrase)?)
            }
            Auth::Passphrase(passphrase) => Backend::Local(open_with(dir, &passphrase)?),
        })
    }

    /// Finds the directory, authenticates, and opens.
    fn connect(passphrases: &mut Passphrases) -> Result<Backend, CliError> {
        Self::connect_for(passphrases, Purpose::Use)
    }

    fn connect_for(passphrases: &mut Passphrases, purpose: Purpose) -> Result<Backend, CliError> {
        let dir = existing_vault_dir()?;
        let auth = authenticate(passphrases)?;
        Backend::open(&dir, auth, purpose)
    }

    /// Looks every reference up, all or nothing (§4.1). Either all of them
    /// resolve, or the first one that doesn't is named and nothing is
    /// returned. One `read` is recorded per distinct item.
    fn resolve(
        &self,
        references: &BTreeSet<&Reference>,
        consequence: &'static str,
    ) -> Result<Resolved, CliError> {
        let unresolved = |reference: &Reference| CliError::Unresolved {
            reference: reference.clone(),
            consequence,
        };
        match self {
            Backend::Local(vault) => Session::new(vault)
                .resolve(references)
                .map_err(|e| match e {
                    ResolveError::Missing(reference) => unresolved(&reference),
                    ResolveError::Failed(e) => e.into(),
                }),
            Backend::Agent(dir) => {
                let wanted: Vec<&Reference> = references.iter().copied().collect();
                if wanted.is_empty() {
                    return Ok(Resolved::new());
                }
                let values = client::resolve(dir, &wanted).map_err(|e| match e {
                    AgentError::NotFound(text) => match Reference::parse(text.as_bytes()) {
                        Ok(reference) => unresolved(&reference),
                        Err(_) => AgentError::NotFound(text).into(),
                    },
                    other => other.into(),
                })?;
                Ok(wanted.into_iter().cloned().zip(values).collect())
            }
        }
    }
}

/// Reads at most `limit` bytes from `reader`, and fails if there are more.
fn read_bounded(reader: impl Read, limit: usize, what: &'static str) -> Result<Vec<u8>, CliError> {
    let mut data = Vec::new();
    let cap = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    reader
        .take(cap)
        .read_to_end(&mut data)
        .map_err(|source| CliError::Read { what, source })?;
    if data.len() > limit {
        return Err(CliError::TooLarge { what });
    }
    Ok(data)
}

fn read_file(path: &Path, limit: usize, what: &'static str) -> Result<Vec<u8>, CliError> {
    let file = File::open(path).map_err(|source| CliError::Read { what, source })?;
    read_bounded(file, limit, what)
}

/// `init` (US-1): creates the directory, an empty vault with the default
/// Argon2id parameters, and the audit log with its `init` record.
pub fn init(passphrases: &mut Passphrases) -> Result<(), CliError> {
    let dir = paths::vault_dir()?;
    // Refuse before asking for a passphrase twice. `create` checks again
    // under the writer lock.
    match store::vault_exists(&dir) {
        Ok(true) => return Err(vault::Error::Exists(dir).into()),
        Ok(false) | Err(vault::Error::Missing(_)) => {}
        Err(e) => return Err(e.into()),
    }
    let passphrase = passphrases.ask_new("New passphrase (at least 12 characters): ")?;
    Vault::create(&dir, &passphrase, KdfParams::DEFAULT)?;
    say(format!("vaultline: created a vault in {}", dir.display()));
    Ok(())
}

/// `set <ref>` (US-2 AC1, AC2, AC7, AC8).
pub fn set(passphrases: &mut Passphrases, reference: &str, raw: bool) -> Result<(), CliError> {
    let reference = parse_reference(reference)?;
    let backend = Backend::connect(passphrases)?;
    let value = if passphrases.reads_stdin() || !Stdin::is_terminal() {
        input::read_value(&mut Stdin::open().map_err(stdin_error)?, raw)?
    } else {
        let bytes = input::prompt_hidden(&format!("Value for {reference}: "))?;
        SecretValue::new(&bytes)
    };
    match &backend {
        Backend::Local(vault) => Session::new(vault).set(&reference, &value)?,
        Backend::Agent(dir) => client::set(dir, &reference, &value)?,
    }
    Ok(())
}

fn stdin_error(source: io::Error) -> CliError {
    CliError::Input(InputError::Io(source))
}

/// `get <ref>` (US-2 AC3, AC4): the stored bytes to stdout, nothing added.
pub fn get(passphrases: &mut Passphrases, reference: &str) -> Result<(), CliError> {
    output::refuse_regular_file_stdout()?;
    let reference = parse_reference(reference)?;
    let backend = Backend::connect(passphrases)?;
    let wanted = BTreeSet::from([&reference]);
    let values = backend.resolve(&wanted, "nothing was printed")?;
    let value = values
        .get(&reference)
        .ok_or_else(|| vault::Error::NotFound(reference.to_string()))?;
    let mut out = raw_stdout().map_err(CliError::Stdout)?;
    out.write_all(value.expose()).map_err(CliError::Stdout)?;
    out.flush().map_err(CliError::Stdout)
}

/// `list [project]` (US-2 AC5): names, one per line, sorted. Never values.
pub fn list(passphrases: &mut Passphrases, project: Option<&str>) -> Result<(), CliError> {
    let project = project
        .map(|text| {
            Name::new(text).map_err(|why| CliError::BadProject {
                text: escape(text.as_bytes()),
                why,
            })
        })
        .transpose()?;
    let backend = Backend::connect(passphrases)?;
    let names: Vec<String> = match &backend {
        Backend::Local(vault) => Session::new(vault)
            .list(project.as_ref())?
            .iter()
            .map(ToString::to_string)
            .collect(),
        Backend::Agent(dir) => client::list(dir, project.as_ref())?,
    };
    let mut out = BufWriter::new(raw_stdout().map_err(CliError::Stdout)?);
    for name in names {
        writeln!(out, "{name}").map_err(CliError::Stdout)?;
    }
    out.flush().map_err(CliError::Stdout)
}

/// `rm <ref>` (US-2 AC6).
pub fn rm(passphrases: &mut Passphrases, reference: &str) -> Result<(), CliError> {
    let reference = parse_reference(reference)?;
    let backend = Backend::connect(passphrases)?;
    match &backend {
        Backend::Local(vault) => {
            Session::new(vault).rm(&reference)?;
        }
        Backend::Agent(dir) => client::remove(dir, &reference)?,
    }
    Ok(())
}

/// `passwd` (US-6): always asks for the current passphrase, then the new one,
/// and never goes through the agent.
pub fn passwd(passphrases: &mut Passphrases) -> Result<(), CliError> {
    let dir = existing_vault_dir()?;
    let current = passphrases.ask("Current passphrase: ")?;
    let new = passphrases.ask_new("New passphrase (at least 12 characters): ")?;
    let vault = session::open(&dir, &current, Origin::Command)?;
    Session::new(&vault).passwd(&new)?;
    say(
        "vaultline: the passphrase was changed. The master key is the same; if the old \
         passphrase may have been seen, run `vaultline rotate` too.",
    );
    Ok(())
}

/// `rotate` (US-7 AC1, AC2, AC4): new master key and item keys, everything
/// encrypted again, and then a running agent is told to lock, because its key
/// is out of date. It never goes through the agent.
pub fn rotate(passphrases: &mut Passphrases) -> Result<(), CliError> {
    let dir = existing_vault_dir()?;
    let passphrase = passphrases.ask("Passphrase: ")?;
    let vault = session::open(&dir, &passphrase, Origin::Command)?;
    Session::new(&vault).rotate(&passphrase)?;
    drop(vault);
    say("vaultline: every key was replaced and every item encrypted again");
    match client::lock(&dir) {
        Ok(true) => say("vaultline: the running agent was locked; run `vaultline unlock` again"),
        Ok(false) => {}
        // The vault is rotated, so this is a warning, not a failure.
        Err(e) => say(format!(
            "vaultline: warning: couldn't tell the running agent to lock: {e}"
        )),
    }
    Ok(())
}

/// `inject [-i F]` (US-4): the template to stdout, every `{{ vault://... }}`
/// replaced.
pub fn inject(passphrases: &mut Passphrases, input: Option<&Path>) -> Result<(), CliError> {
    output::refuse_regular_file_stdout()?;
    // With --passphrase-stdin and the template on stdin too, the passphrase is
    // the first line and the template is the rest (D-037), so the passphrase
    // has to be read first.
    let early = if input.is_none() && passphrases.reads_stdin() {
        Some(authenticate(passphrases)?)
    } else {
        None
    };
    let bytes = match input {
        Some(path) => read_file(path, MAX_TEMPLATE_LEN, "template")?,
        None => read_bounded(
            Stdin::open().map_err(stdin_error)?,
            MAX_TEMPLATE_LEN,
            "template",
        )?,
    };
    let template = Template::parse(&bytes)?;
    let references = template.references();
    let values = if references.is_empty() {
        Resolved::new()
    } else {
        let dir = existing_vault_dir()?;
        let auth = match early {
            Some(auth) => auth,
            None => authenticate(passphrases)?,
        };
        Backend::open(&dir, auth, Purpose::Use)?.resolve(&references, "nothing was written")?
    };
    // Straight from the wiped-on-drop values to the descriptor: the output is
    // never collected in memory.
    let mut out = BufWriter::new(raw_stdout().map_err(CliError::Stdout)?);
    template
        .render(&values, &mut out)
        .map_err(CliError::Stdout)?;
    out.flush().map_err(CliError::Stdout)
}

/// `run [--env-file F] [--no-mask] -- <cmd>` (US-3): returns the exit code
/// for the process to exit with.
pub fn run(
    passphrases: &mut Passphrases,
    env_file: Option<&Path>,
    no_mask: bool,
    command: &[String],
) -> Result<u8, CliError> {
    let file = match env_file {
        Some(path) => {
            let bytes = read_file(path, MAX_ENV_FILE_LEN, "env file")?;
            envfile::parse(&bytes).map_err(|why| CliError::EnvFile {
                path: path.to_path_buf(),
                why,
            })?
        }
        None => Vec::new(),
    };
    let plan = run::plan_env(std::env::vars_os(), file)?;
    let references = plan.references();
    // With nothing to resolve there is nothing to unlock, and no passphrase
    // line is read from standard input.
    let values = if references.is_empty() {
        Resolved::new()
    } else {
        Backend::connect(passphrases)?.resolve(&references, "nothing was started")?
    };
    for line in run::warnings(&plan, &values, no_mask) {
        say(line);
    }
    Ok(run::execute(&plan, values, command, no_mask)?)
}

// ---------------------------------------------------------------------------
// The agent (US-5, design §4, §8).

/// How long `unlock` waits for a new agent to unlock the vault and bind its
/// socket. Argon2id takes about a second at the default parameters.
const AGENT_START_TIMEOUT: Duration = Duration::from_secs(120);

/// `unlock [--idle-timeout D]` (US-5): starts the agent, or unlocks a running
/// one that is locked.
pub fn unlock(passphrases: &mut Passphrases, idle_timeout: Option<&str>) -> Result<(), CliError> {
    let idle = idle_timeout.map(parse_idle_timeout).transpose()?;
    let dir = existing_vault_dir()?;
    match client::status(&dir)? {
        Some(status) => {
            // The Unlock message has no timeout in it (D-050), so a timeout
            // can't be applied to an agent that is already running. Refuse
            // before asking for anything, whether or not it is unlocked.
            if idle.is_some() {
                return Err(CliError::AgentAlreadyRunning);
            }
            if status.unlocked {
                say("vaultline: the agent is already unlocked");
                return Ok(());
            }
            let passphrase = passphrases.ask("Passphrase: ")?;
            client::unlock(&dir, &passphrase)?;
            say("vaultline: unlocked");
        }
        None => {
            let passphrase = passphrases.ask("Passphrase: ")?;
            let idle = idle.unwrap_or(DEFAULT_IDLE_TIMEOUT);
            spawn_agent(&dir, idle, &passphrase)?;
            say(format!(
                "vaultline: unlocked; the agent forgets the key after {} idle seconds",
                idle.as_secs()
            ));
        }
    }
    Ok(())
}

/// Starts `vaultline agent serve` as a background process in its own process
/// group (so Ctrl-C in this terminal doesn't reach it), hands it the
/// passphrase on its standard input, and waits for its one-byte answer: 0
/// when it is unlocked and listening. The passphrase is never in its
/// arguments or environment (D-012, D-014).
fn spawn_agent(dir: &Path, idle: Duration, passphrase: &Passphrase) -> Result<(), CliError> {
    let exe = std::env::current_exe().map_err(CliError::Spawn)?;
    let mut child = Command::new(exe)
        .args(["agent", "serve", "--idle-timeout"])
        .arg(format!("{}s", idle.as_secs()))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(CliError::Spawn)?;
    let answer = start_handshake(&mut child, passphrase);
    match answer {
        Ok(true) => Ok(()),
        Ok(false) => {
            let mut why = String::new();
            if let Some(mut stderr) = child.stderr.take() {
                let mut text = Vec::new();
                let _ = (&mut stderr).take(4096).read_to_end(&mut text);
                why = String::from_utf8_lossy(&text).trim().to_string();
            }
            let _ = child.wait();
            if why.is_empty() {
                why = format!(
                    "it exited without saying why; look for problems in {}",
                    dir.display()
                );
            }
            Err(CliError::AgentStartup(why))
        }
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(e)
        }
    }
}

/// Writes the passphrase to the agent and reads its status byte. `Ok(true)`
/// means ready.
fn start_handshake(child: &mut Child, passphrase: &Passphrase) -> Result<bool, CliError> {
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| CliError::Spawn(io::Error::other("the agent's stdin is not a pipe")))?;
    stdin
        .write_all(passphrase.expose())
        .map_err(CliError::Spawn)?;
    // Closing stdin tells the agent the passphrase is complete.
    drop(stdin);
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| CliError::Spawn(io::Error::other("the agent's stdout is not a pipe")))?;
    let timeout = PollTimeout::try_from(AGENT_START_TIMEOUT).unwrap_or(PollTimeout::MAX);
    let mut fds = [PollFd::new(stdout.as_fd(), PollFlags::POLLIN)];
    loop {
        match poll(&mut fds, timeout) {
            Ok(0) => {
                return Err(CliError::AgentStartup(
                    "it didn't answer within two minutes".into(),
                ));
            }
            Ok(_) => break,
            Err(nix::errno::Errno::EINTR) => {}
            Err(e) => return Err(CliError::Spawn(io::Error::from(e))),
        }
    }
    let mut byte = [0u8; 1];
    match stdout.read(&mut byte) {
        Ok(1) => Ok(byte[0] == 0),
        // The agent closed its output without answering: it died.
        Ok(_) => Ok(false),
        Err(e) => Err(CliError::Spawn(e)),
    }
}

/// `lock` (US-5 AC3): wipes the agent's key and leaves the agent running.
pub fn lock() -> Result<(), CliError> {
    let dir = paths::vault_dir()?;
    if client::lock(&dir)? {
        say("vaultline: locked");
    } else {
        say("vaultline: no agent is running");
    }
    Ok(())
}

/// `agent stop` (US-5 AC4): wipes the key, removes the socket, exits.
pub fn agent_stop() -> Result<(), CliError> {
    let dir = paths::vault_dir()?;
    if client::stop(&dir)? {
        say("vaultline: the agent stopped");
    } else {
        say("vaultline: no agent is running");
    }
    Ok(())
}

/// `agent serve` (hidden): the agent itself. Reads the passphrase from its
/// standard input until the end, runs until it is stopped, and answers `unlock`
/// with one byte on standard output: 0 for ready, 1 for a failure whose reason
/// is on standard error.
pub fn agent_serve(idle_timeout: Option<&str>) -> Result<(), CliError> {
    let idle = match idle_timeout {
        Some(text) => parse_idle_timeout(text)?,
        None => DEFAULT_IDLE_TIMEOUT,
    };
    let dir = paths::vault_dir()?;
    let passphrase = read_passphrase_to_end()?;
    let result = server::run(&dir, idle, &passphrase, || {
        let mut out = raw_stdout()?;
        out.write_all(&[0])?;
        out.flush()
    });
    if let Err(e) = &result {
        // Best effort: if `unlock` is gone there is nobody to tell.
        if let Ok(mut out) = raw_stdout() {
            let _ = out.write_all(&[1]);
            let _ = out.flush();
        }
        say(e);
    }
    result.map_err(CliError::Serve)
}

/// The passphrase the agent was started with: everything on its standard
/// input, exactly as it is, up to 64 KiB. The buffer is reserved in advance,
/// so no copy of the passphrase is left behind by growing it.
fn read_passphrase_to_end() -> Result<Passphrase, CliError> {
    let mut data = Zeroizing::new(Vec::with_capacity(MAX_PASSPHRASE_LEN.saturating_add(1)));
    let cap = u64::try_from(MAX_PASSPHRASE_LEN)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    Stdin::open()
        .map_err(stdin_error)?
        .take(cap)
        .read_to_end(&mut data)
        .map_err(|source| CliError::Read {
            what: "passphrase",
            source,
        })?;
    if data.len() > MAX_PASSPHRASE_LEN {
        return Err(CliError::TooLarge { what: "passphrase" });
    }
    Ok(Passphrase::new(&data))
}

// ---------------------------------------------------------------------------
// The audit log (US-8, design §9).

/// `audit verify [--expect COUNT:HASH]` (US-8 AC2, AC3): returns the exit code
/// for the process to exit with, 0 if the log verified and 1 if not.
pub fn audit_verify(passphrases: &mut Passphrases, expect: Option<&str>) -> Result<u8, CliError> {
    // A mistyped anchor costs no passphrase.
    let expect = expect.map(Anchor::parse).transpose()?;
    let verdict = match Backend::connect_for(passphrases, Purpose::Inspect)? {
        Backend::Local(vault) => Session::new(&vault).audit_verify(expect)?,
        Backend::Agent(dir) => client::audit_verify(&dir, expect)?,
    };
    if verdict.passed {
        let mut out = raw_stdout().map_err(CliError::Stdout)?;
        writeln!(out, "{}", verdict.report).map_err(CliError::Stdout)?;
        Ok(0)
    } else {
        say(format!(
            "vaultline: audit verification failed: {}",
            verdict.report
        ));
        Ok(1)
    }
}

/// `audit head` (US-8 AC3): prints the current anchor, `count:hash`.
pub fn audit_head(passphrases: &mut Passphrases) -> Result<(), CliError> {
    let anchor = match Backend::connect_for(passphrases, Purpose::Inspect)? {
        Backend::Local(vault) => Session::new(&vault).audit_head()?.to_string(),
        Backend::Agent(dir) => client::audit_head(&dir)?,
    };
    let mut out = raw_stdout().map_err(CliError::Stdout)?;
    writeln!(out, "{anchor}").map_err(CliError::Stdout)
}
