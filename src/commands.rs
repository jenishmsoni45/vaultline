//! What each command does, in-process (`docs/design.md` §4, §4.1).
//!
//! Phase 3 runs everything in the command's own process: it asks for the
//! passphrase, opens the vault, does the work and drops the key when it
//! returns. The agent (Phase 4) will answer the same requests without a
//! prompt.
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
use std::path::{Path, PathBuf};

use crate::hardening::HardeningError;
use crate::inject::envfile::{self, EnvFileError, MAX_ENV_FILE_LEN};
use crate::inject::mask::MaskError;
use crate::inject::output::{self, OutputError, raw_stdout};
use crate::inject::reference::{Reference, ReferenceError, escape};
use crate::inject::run::{self, RunError};
use crate::inject::template::{MAX_TEMPLATE_LEN, Resolved, Template, TemplateError};
use crate::input::{self, InputError, Passphrases, Stdin};
use crate::paths::{self, PathError};
use crate::secret::{Passphrase, SecretValue};
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
/// §4.4).
fn open_with(dir: &Path, passphrase: &Passphrase) -> Result<Vault, CliError> {
    let vault = Vault::open(dir, passphrase)?;
    if vault.kdf_params().below_defaults() {
        eprintln!(
            "vaultline: warning: this vault uses weaker Argon2id parameters than the current \
             defaults; run `vaultline passwd` to upgrade it"
        );
    }
    Ok(vault)
}

/// Asks for the passphrase and opens the vault.
fn open_vault(passphrases: &mut Passphrases) -> Result<Vault, CliError> {
    let dir = existing_vault_dir()?;
    let passphrase = passphrases.ask("Passphrase: ")?;
    open_with(&dir, &passphrase)
}

/// Looks every reference up in the vault. Either all of them resolve, or the
/// first one that doesn't is named and nothing is returned (§4.1).
fn resolve(
    vault: &Vault,
    references: &BTreeSet<&Reference>,
    consequence: &'static str,
) -> Result<Resolved, CliError> {
    let mut resolved = Resolved::new();
    if references.is_empty() {
        return Ok(resolved);
    }
    let items = vault.items()?;
    for reference in references {
        let value = items
            .iter()
            .find(|i| i.project == reference.project && i.item == reference.item)
            .and_then(|i| i.fields.get(&reference.field))
            .ok_or_else(|| CliError::Unresolved {
                reference: (*reference).clone(),
                consequence,
            })?;
        resolved.insert((*reference).clone(), value.duplicate());
    }
    Ok(resolved)
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

/// `init` (US-1): creates the directory and an empty vault with the default
/// Argon2id parameters.
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
    eprintln!("vaultline: created a vault in {}", dir.display());
    Ok(())
}

/// `set <ref>` (US-2 AC1, AC2, AC7, AC8).
pub fn set(passphrases: &mut Passphrases, reference: &str, raw: bool) -> Result<(), CliError> {
    let reference = parse_reference(reference)?;
    let vault = open_vault(passphrases)?;
    let value = if passphrases.reads_stdin() || !Stdin::is_terminal() {
        input::read_value(&mut Stdin::open().map_err(stdin_error)?, raw)?
    } else {
        let bytes = input::prompt_hidden(&format!("Value for {reference}: "))?;
        SecretValue::new(&bytes)
    };
    vault.set(
        &reference.project,
        &reference.item,
        &reference.field,
        &value,
    )?;
    Ok(())
}

fn stdin_error(source: io::Error) -> CliError {
    CliError::Input(InputError::Io(source))
}

/// `get <ref>` (US-2 AC3, AC4): the stored bytes to stdout, nothing added.
pub fn get(passphrases: &mut Passphrases, reference: &str) -> Result<(), CliError> {
    output::refuse_regular_file_stdout()?;
    let reference = parse_reference(reference)?;
    let vault = open_vault(passphrases)?;
    let value = vault.get(&reference.project, &reference.item, &reference.field)?;
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
    let vault = open_vault(passphrases)?;
    let entries = vault.list(project.as_ref())?;
    let mut out = BufWriter::new(raw_stdout().map_err(CliError::Stdout)?);
    for entry in entries {
        writeln!(out, "{entry}").map_err(CliError::Stdout)?;
    }
    out.flush().map_err(CliError::Stdout)
}

/// `rm <ref>` (US-2 AC6).
pub fn rm(passphrases: &mut Passphrases, reference: &str) -> Result<(), CliError> {
    let reference = parse_reference(reference)?;
    let vault = open_vault(passphrases)?;
    vault.rm(&reference.project, &reference.item, &reference.field)?;
    Ok(())
}

/// `passwd` (US-6): always asks for the current passphrase, then the new one.
pub fn passwd(passphrases: &mut Passphrases) -> Result<(), CliError> {
    let dir = existing_vault_dir()?;
    let current = passphrases.ask("Current passphrase: ")?;
    let new = passphrases.ask_new("New passphrase (at least 12 characters): ")?;
    vault::passwd(&dir, &current, &new)?;
    eprintln!(
        "vaultline: the passphrase was changed. The master key is the same; if the old \
         passphrase may have been seen, run `vaultline rotate` too."
    );
    Ok(())
}

/// `rotate` (US-7 AC1, AC2): new master key and item keys, everything
/// encrypted again.
pub fn rotate(passphrases: &mut Passphrases) -> Result<(), CliError> {
    let dir = existing_vault_dir()?;
    let passphrase = passphrases.ask("Passphrase: ")?;
    vault::rotate(&dir, &passphrase)?;
    eprintln!("vaultline: every key was replaced and every item encrypted again");
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
        Some(passphrases.ask("Passphrase: ")?)
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
        let passphrase = match early {
            Some(passphrase) => passphrase,
            None => passphrases.ask("Passphrase: ")?,
        };
        let vault = open_with(&dir, &passphrase)?;
        resolve(&vault, &references, "nothing was written")?
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
        let vault = open_vault(passphrases)?;
        resolve(&vault, &references, "nothing was started")?
    };
    for line in run::warnings(&plan, &values, no_mask) {
        eprintln!("{line}");
    }
    Ok(run::execute(&plan, values, command, no_mask)?)
}
