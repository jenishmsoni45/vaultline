//! The `vaultline` command line.
//!
//! Phase 1 defines the whole command tree from `docs/design.md` §4. Every
//! command is a stub that prints `not implemented yet` and exits 1; later
//! phases give the commands their behaviour.

#![forbid(unsafe_code)]

#[cfg(not(unix))]
compile_error!("vaultline supports Unix only (macOS and Linux); Windows is not supported (D-021)");

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Exit code for any vaultline error (`docs/design.md` §4). clap itself exits
/// with 2 for a usage error.
const EXIT_ERROR: u8 = 1;

#[derive(Parser)]
#[command(
    name = "vaultline",
    version,
    about = "An encrypted local vault that injects secrets into child processes and templates"
)]
// The fields are read once the commands are implemented (Phases 2 to 4).
#[allow(dead_code)]
struct Cli {
    /// Read passphrases from stdin, one per line, instead of prompting
    #[arg(long, global = true)]
    passphrase_stdin: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
// The fields are read once the commands are implemented (Phases 2 to 4).
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

fn main() -> ExitCode {
    let _cli = Cli::parse();
    eprintln!("vaultline: not implemented yet");
    ExitCode::from(EXIT_ERROR)
}
