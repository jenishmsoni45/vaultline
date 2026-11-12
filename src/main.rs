//! The `vaultline` command line.
//!
//! The command tree is `docs/design.md` §4. `init`, `set`, `get`, `list`, `rm`,
//! `passwd`, `rotate`, `run` and `inject` work in-process (Phase 3, in
//! `vaultline::commands`). The agent and audit commands are stubs that print
//! `not implemented yet` and exit 1 until Phase 4.

#![forbid(unsafe_code)]

#[cfg(not(unix))]
compile_error!("vaultline supports Unix only (macOS and Linux); Windows is not supported (D-021)");

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use vaultline::commands::{self, CliError};
use vaultline::hardening;
use vaultline::inject::output::say;
use vaultline::input::Passphrases;

/// Exit code for any vaultline error (`docs/design.md` §4). clap itself exits
/// with 2 for a usage error.
const EXIT_ERROR: u8 = 1;

#[derive(Parser)]
#[command(
    name = "vaultline",
    version,
    about = "An encrypted local vault that injects secrets into child processes and templates"
)]
struct Cli {
    /// Read passphrases from stdin, one per line, instead of prompting
    #[arg(long, global = true)]
    passphrase_stdin: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
// The agent commands carry options that Phase 4 reads.
#[allow(dead_code)]
enum Command {
    /// Create the vault directory and an empty vault
    Init,

    /// Store a value read from a hidden prompt or from stdin
    Set {
        /// Reference to the field: vault://project/item/field or project/item/field
        reference: String,
        /// Keep the trailing newline of a value read from stdin
        #[arg(long)]
        raw: bool,
    },

    /// Print a value to stdout
    Get {
        /// Reference to the field: vault://project/item/field or project/item/field
        reference: String,
    },

    /// List project/item/field names, never values
    List {
        /// Only list this project
        project: Option<String>,
    },

    /// Remove a field
    Rm {
        /// Reference to the field: vault://project/item/field or project/item/field
        reference: String,
    },

    /// Change the passphrase
    Passwd,

    /// Replace the master key and every item key
    Rotate,

    /// Run a command with vault:// references in its environment resolved
    Run {
        /// File of NAME=value lines; values that are vault:// references are resolved
        #[arg(long, value_name = "FILE")]
        env_file: Option<PathBuf>,
        /// Do not mask secrets in the child's output
        #[arg(long)]
        no_mask: bool,
        /// The command to run, after `--`
        #[arg(last = true, required = true, value_name = "CMD")]
        command: Vec<String>,
    },

    /// Render a template to stdout, replacing {{ vault://... }}
    Inject {
        /// Template file; stdin if not given
        #[arg(short = 'i', value_name = "FILE")]
        input: Option<PathBuf>,
    },

    /// Start the agent, or unlock a running one
    Unlock {
        /// Wipe the key after this much idle time: <n>s, <n>m or <n>h
        #[arg(long, value_name = "DURATION")]
        idle_timeout: Option<String>,
    },

    /// Wipe the agent's key and leave the agent running
    Lock,

    /// Control the agent
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },

    /// Check or anchor the audit log
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
}

#[derive(Subcommand)]
enum AgentCommand {
    /// Wipe the key, remove the socket and exit
    Stop,

    /// The agent process itself, started by `unlock`
    #[command(hide = true)]
    Serve,
}

#[derive(Subcommand)]
#[allow(dead_code)]
enum AuditCommand {
    /// Verify the chain, the MACs and the head
    Verify {
        /// Also check that the log still holds this anchor (COUNT:HASH)
        #[arg(long, value_name = "COUNT:HASH")]
        expect: Option<String>,
    },

    /// Print the current anchor
    Head,
}

/// Where the passphrases come from for this invocation.
fn passphrases(from_stdin: bool) -> Result<Passphrases, CliError> {
    if from_stdin {
        Passphrases::from_stdin().map_err(|e| CliError::Input(vaultline::input::InputError::Io(e)))
    } else {
        Ok(Passphrases::prompting())
    }
}

/// Runs a command that succeeds with exit code 0.
fn done(result: Result<(), CliError>) -> Result<u8, CliError> {
    result.map(|()| 0)
}

fn dispatch(cli: Cli) -> Result<u8, CliError> {
    let from_stdin = cli.passphrase_stdin;
    match cli.command {
        Command::Init => done(commands::init(&mut passphrases(from_stdin)?)),
        Command::Set { reference, raw } => done(commands::set(
            &mut passphrases(from_stdin)?,
            &reference,
            raw,
        )),
        Command::Get { reference } => {
            done(commands::get(&mut passphrases(from_stdin)?, &reference))
        }
        Command::List { project } => done(commands::list(
            &mut passphrases(from_stdin)?,
            project.as_deref(),
        )),
        Command::Rm { reference } => done(commands::rm(&mut passphrases(from_stdin)?, &reference)),
        Command::Passwd => done(commands::passwd(&mut passphrases(from_stdin)?)),
        Command::Rotate => done(commands::rotate(&mut passphrases(from_stdin)?)),
        Command::Run {
            env_file,
            no_mask,
            command,
        } => commands::run(
            &mut passphrases(from_stdin)?,
            env_file.as_deref(),
            no_mask,
            &command,
        ),
        Command::Inject { input } => done(commands::inject(
            &mut passphrases(from_stdin)?,
            input.as_deref(),
        )),
        Command::Unlock { .. } | Command::Lock | Command::Agent { .. } | Command::Audit { .. } => {
            say("vaultline: not implemented yet");
            Ok(EXIT_ERROR)
        }
    }
}

fn main() -> ExitCode {
    // Before anything else, in every invocation (docs/design.md section 10).
    if let Err(e) = hardening::apply() {
        say(format!("vaultline: {e}"));
        return ExitCode::from(EXIT_ERROR);
    }
    match dispatch(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            say(format!("vaultline: {e}"));
            ExitCode::from(EXIT_ERROR)
        }
    }
}
