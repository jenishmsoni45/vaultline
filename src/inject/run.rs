//! `vaultline run`: build the child's environment, start it, mask its output,
//! pass signals on and report how it ended (`docs/design.md` §7, D-008, D-009,
//! D-028, D-036).
//!
//! The steps, in the order the commands use them:
//!
//! 1. [`plan_env`] decides what each variable becomes, from the inherited
//!    environment and the env file. It only parses; it touches no secret.
//! 2. The command resolves every reference, all or nothing (§4.1).
//! 3. [`warnings`] lists what stderr should say before the child starts.
//! 4. [`execute`] starts the child with the resolved values, runs one masker per
//!    output stream, forwards SIGTERM and SIGHUP, and returns the exit code.
//!
//! Signals follow POSIX `system()` (D-036). While the child runs vaultline
//! catches SIGINT and SIGQUIT and does nothing with them, which has the effect
//! of ignoring them; Ctrl-C reaches the child directly, exactly once, because
//! the child shares the terminal's foreground process group. A caught signal
//! goes back to its default action when the child starts a new program, so the
//! child is not left ignoring Ctrl-C the way a real `SIG_IGN` would leave it.
//! SIGTERM and SIGHUP are forwarded.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, BufWriter, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use signal_hook::iterator::Signals;
use zeroize::Zeroizing;

use super::envfile::{Assignment, EnvValue};
use super::mask::{MaskError, Masker};
use super::output::{raw_stderr, raw_stdout};
use super::reference::{Reference, ReferenceError, SCHEME, escape};
use super::template::Resolved;

/// Secrets shorter than this many bytes get a warning (D-028).
pub const SHORT_SECRET_LEN: usize = 8;

/// Exit code when the command can't be found.
pub const EXIT_NOT_FOUND: u8 = 127;
/// Exit code when the command can't be run.
pub const EXIT_NOT_EXECUTABLE: u8 = 126;
/// Exit code for an error of vaultline's own.
pub const EXIT_ERROR: u8 = 1;

/// What one variable becomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// Set to these bytes, which come from the env file and are not secrets
    /// of the vault.
    Literal(Vec<u8>),
    /// Set to the secret at this reference.
    Reference(Reference),
}

/// Why `run` can't go ahead.
#[derive(Debug)]
pub enum RunError {
    /// An inherited variable's value starts with `vault://` but isn't a valid
    /// reference.
    BadEnvReference {
        name: OsString,
        text: String,
        why: ReferenceError,
    },
    /// The command line holds no command.
    NoCommand,
    /// The command can't be started, for a reason other than "not found" or
    /// "not executable", such as a value that can't be put in the
    /// environment.
    Spawn { program: String, source: io::Error },
    /// The masker couldn't be built.
    Mask(MaskError),
    /// Something else went wrong with the child or its pipes.
    Io(io::Error),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunError::BadEnvReference { name, text, why } => write!(
                f,
                "environment variable {}: {text} is not a valid reference: {why}",
                escape(name.as_bytes())
            ),
            RunError::NoCommand => f.write_str("no command to run; give one after --"),
            RunError::Spawn { program, source } => {
                write!(f, "can't start {program}: {source}")
            }
            RunError::Mask(why) => why.fmt(f),
            RunError::Io(source) => write!(f, "{source}"),
        }
    }
}

impl std::error::Error for RunError {}

/// The variables `run` changes in the child's environment. Every variable not
/// in the plan passes through unchanged.
#[derive(Debug, Default)]
pub struct EnvPlan {
    entries: BTreeMap<OsString, Source>,
    overrides: Vec<OsString>,
}

/// Works out the child's environment (§7 step 1): inherited variables whose
/// whole value is a reference are resolved, a value that starts with
/// `vault://` and isn't a valid reference is an error, and the env file is
/// applied last and wins. Inherited variables are visited in name order, so
/// the first error is always the same one.
pub fn plan_env(
    inherited: impl IntoIterator<Item = (OsString, OsString)>,
    file: Vec<Assignment>,
) -> Result<EnvPlan, RunError> {
    let inherited: BTreeMap<OsString, OsString> = inherited.into_iter().collect();
    let mut plan = EnvPlan::default();
    for (name, value) in &inherited {
        let bytes = value.as_bytes();
        if bytes.starts_with(SCHEME) {
            let reference = Reference::parse(bytes).map_err(|why| RunError::BadEnvReference {
                name: name.clone(),
                text: escape(bytes),
                why,
            })?;
            plan.entries
                .insert(name.clone(), Source::Reference(reference));
        }
    }
    for assignment in file {
        let name = OsString::from(assignment.name);
        if inherited.contains_key(&name) {
            plan.overrides.push(name.clone());
        }
        let source = match assignment.value {
            EnvValue::Literal(bytes) => Source::Literal(bytes),
            EnvValue::Reference(reference) => Source::Reference(reference),
        };
        plan.entries.insert(name, source);
    }
    Ok(plan)
}

impl EnvPlan {
    /// The distinct references to resolve, sorted.
    pub fn references(&self) -> BTreeSet<&Reference> {
        self.entries
            .values()
            .filter_map(|source| match source {
                Source::Reference(reference) => Some(reference),
                Source::Literal(_) => None,
            })
            .collect()
    }

    /// The inherited variables the env file overrides, by name.
    pub fn overrides(&self) -> &[OsString] {
        &self.overrides
    }

    /// The variables the plan sets, by name and source.
    pub fn entries(&self) -> &BTreeMap<OsString, Source> {
        &self.entries
    }
}

/// What stderr says before the child starts (§6 step 1, §7): which inherited
/// variables the env file overrides, which secrets are short enough that
/// masking may garble output, and, with `--no-mask`, that nothing is masked.
/// Names and references only, never values.
pub fn warnings(plan: &EnvPlan, values: &Resolved, no_mask: bool) -> Vec<String> {
    let mut lines = Vec::new();
    for name in plan.overrides() {
        lines.push(format!(
            "vaultline: note: {} is set in the environment and in the env file; the env file wins",
            escape(name.as_bytes())
        ));
    }
    if no_mask {
        lines.push(
            "vaultline: warning: --no-mask: the command's output is not masked, \
             so a secret it prints will be visible"
                .to_string(),
        );
    } else {
        for (reference, value) in values {
            if !value.is_empty() && value.len() < SHORT_SECRET_LEN {
                lines.push(format!(
                    "vaultline: warning: the secret at {reference} is shorter than \
                     {SHORT_SECRET_LEN} bytes; masking it can garble the command's output"
                ));
            }
        }
    }
    lines
}

/// Starts `command` with the plan applied, masks its output unless `no_mask`,
/// and returns its exit code: the child's own, 126 or 127 if it can't be
/// started, or 128 plus the signal that killed it.
///
/// `values` holds every reference of the plan, resolved. It is wiped when this
/// returns.
pub fn execute(
    plan: &EnvPlan,
    values: Resolved,
    command: &[String],
    no_mask: bool,
) -> Result<u8, RunError> {
    let (program, args) = command.split_first().ok_or(RunError::NoCommand)?;

    let mut maskers = None;
    if !no_mask {
        let secrets = || values.values().map(|v| v.expose());
        let stdout = Masker::new(secrets()).map_err(RunError::Mask)?;
        let stderr = Masker::new(secrets()).map_err(RunError::Mask)?;
        maskers = Some((stdout, stderr));
    }

    let mut cmd = Command::new(program);
    cmd.args(args);
    for (name, source) in plan.entries() {
        let bytes: &[u8] = match source {
            Source::Literal(bytes) => bytes,
            Source::Reference(reference) => values
                .get(reference)
                .map(|v| v.expose())
                .ok_or_else(|| RunError::Io(io::Error::other("a reference was not resolved")))?,
        };
        cmd.env(name, OsStr::from_bytes(bytes));
    }
    cmd.stdin(Stdio::inherit());
    if maskers.is_some() {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    } else {
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    }

    // Handlers go in before the child exists, so a signal that arrives in the
    // meantime is queued and forwarded, never lost.
    let mut signals = Signals::new([SIGINT, SIGQUIT, SIGTERM, SIGHUP]).map_err(RunError::Io)?;
    let signal_handle = signals.handle();

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(source) => return spawn_failure(program, source),
    };
    // std keeps its own copy of the environment block until the Command is
    // gone (threat model R6).
    drop(cmd);

    let pid = i32::try_from(child.id())
        .map(Pid::from_raw)
        .map_err(|_| RunError::Io(io::Error::other("the child's process ID is out of range")))?;
    // `Some` while the child has not been reaped. A signal is only forwarded
    // under this lock and only while it holds the pid, so a pid that the
    // system could reuse is never signalled.
    let live = Arc::new(Mutex::new(Some(pid)));
    let forwarder = {
        let live = Arc::clone(&live);
        thread::spawn(move || {
            for signal in signals.forever() {
                let forward = match signal {
                    SIGTERM => Signal::SIGTERM,
                    SIGHUP => Signal::SIGHUP,
                    // SIGINT and SIGQUIT are ignored: the terminal already
                    // delivered them to the child (D-036).
                    _ => continue,
                };
                if let Ok(guard) = live.lock() {
                    if let Some(pid) = *guard {
                        let _ = kill(pid, forward);
                    }
                }
            }
        })
    };

    let mut pumps = Vec::new();
    if let Some((stdout_masker, stderr_masker)) = maskers {
        if let Some(pipe) = child.stdout.take() {
            let out = raw_stdout().map_err(RunError::Io)?;
            pumps.push((
                "standard output",
                thread::spawn(move || pump(pipe, stdout_masker, out)),
            ));
        }
        if let Some(pipe) = child.stderr.take() {
            let err = raw_stderr().map_err(RunError::Io)?;
            pumps.push((
                "standard error",
                thread::spawn(move || pump(pipe, stderr_masker, err)),
            ));
        }
    }

    let status = child.wait();
    if let Ok(mut guard) = live.lock() {
        *guard = None;
    }
    signal_handle.close();
    let _ = forwarder.join();

    for (stream, pump) in pumps {
        match pump.join() {
            Ok(Ok(())) => {}
            // The reader of our own output went away. The pipe to the child
            // was closed when the pump returned, so the child saw the broken
            // pipe too (§7 step 6). Nothing to report.
            Ok(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe => {}
            Ok(Err(e)) => eprintln!("vaultline: couldn't pass on the command's {stream}: {e}"),
            Err(_) => eprintln!("vaultline: the {stream} masker stopped unexpectedly"),
        }
    }
    drop(values);

    Ok(exit_code(status.map_err(RunError::Io)?))
}

/// Copies one of the child's output pipes through a masker to `out`,
/// flushing after every chunk so output isn't held up. Returns when the pipe
/// reaches the end or `out` fails; either way the pipe is dropped, which
/// closes it.
fn pump<R: Read, W: Write>(mut pipe: R, mut masker: Masker, out: W) -> io::Result<()> {
    let mut out = BufWriter::with_capacity(64 * 1024, out);
    // The chunk holds the child's output before masking, which may be a
    // secret, so it is wiped after use.
    let mut chunk = Zeroizing::new(vec![0u8; 64 * 1024]);
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                masker.push(chunk.get(..n).unwrap_or_default(), &mut out)?;
                out.flush()?;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    masker.finish(&mut out)?;
    out.flush()
}

/// Turns a failed spawn into an exit code, or an error when it isn't about the
/// command itself.
fn spawn_failure(program: &str, source: io::Error) -> Result<u8, RunError> {
    match source.kind() {
        io::ErrorKind::NotFound => {
            eprintln!("vaultline: command not found: {program}");
            Ok(EXIT_NOT_FOUND)
        }
        io::ErrorKind::PermissionDenied => {
            eprintln!("vaultline: can't run {program}: permission denied or not executable");
            Ok(EXIT_NOT_EXECUTABLE)
        }
        // A NUL byte in an argument or a value can't be passed on.
        io::ErrorKind::InvalidInput => Err(RunError::Spawn {
            program: program.to_string(),
            source,
        }),
        _ => {
            eprintln!("vaultline: can't run {program}: {source}");
            Ok(EXIT_NOT_EXECUTABLE)
        }
    }
}

/// The child's exit code, or 128 plus the signal that killed it.
fn exit_code(status: ExitStatus) -> u8 {
    if let Some(code) = status.code() {
        return u8::try_from(code).unwrap_or(EXIT_ERROR);
    }
    status
        .signal()
        .and_then(|signal| u8::try_from(signal.saturating_add(128)).ok())
        .unwrap_or(EXIT_ERROR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretValue;
    use std::os::unix::ffi::OsStringExt;

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    fn inherited(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs.iter().map(|(k, v)| (os(k), os(v))).collect()
    }

    fn reference(text: &str) -> Reference {
        Reference::parse(text.as_bytes()).unwrap()
    }

    fn file(text: &str) -> Vec<Assignment> {
        super::super::envfile::parse(text.as_bytes()).unwrap()
    }

    #[test]
    fn only_whole_value_references_are_resolved() {
        let plan = plan_env(
            inherited(&[
                ("A", "vault://p/i/a"),
                ("B", "plain"),
                ("C", "prefix vault://p/i/c"),
                ("D", "https://example.com"),
                ("E", ""),
            ]),
            vec![],
        )
        .unwrap();
        let names: Vec<&OsString> = plan.entries().keys().collect();
        assert_eq!(names, [&os("A")]);
        assert_eq!(plan.references().len(), 1);
    }

    #[test]
    fn a_value_that_starts_with_the_scheme_but_is_not_a_reference_is_an_error() {
        for bad in [
            "vault://",
            "vault://p/i",
            "vault://p/i/f/g",
            "vault://p/i/f ",
            "vault://p/i/f\n",
        ] {
            let err = plan_env(inherited(&[("TOKEN", bad)]), vec![]).unwrap_err();
            assert!(matches!(err, RunError::BadEnvReference { .. }), "{bad:?}");
            let message = err.to_string();
            assert!(message.contains("TOKEN"), "{message}");
        }
    }

    #[test]
    fn the_first_bad_variable_by_name_is_the_one_reported() {
        let err = plan_env(
            inherited(&[("Z", "vault://z"), ("B", "vault://b"), ("M", "vault://m")]),
            vec![],
        )
        .unwrap_err();
        assert!(err.to_string().contains("variable B:"), "{err}");
    }

    #[test]
    fn an_env_file_adds_variables_and_resolves_references() {
        let plan = plan_env(
            inherited(&[("KEEP", "x")]),
            file("LIT=value\nREF=vault://p/i/f\n"),
        )
        .unwrap();
        assert_eq!(
            plan.entries().get(&os("LIT")),
            Some(&Source::Literal(b"value".to_vec()))
        );
        assert_eq!(
            plan.entries().get(&os("REF")),
            Some(&Source::Reference(reference("vault://p/i/f")))
        );
        assert!(plan.overrides().is_empty());
        assert!(!plan.entries().contains_key(&os("KEEP")));
    }

    #[test]
    fn the_env_file_wins_over_the_environment_and_the_override_is_named() {
        let plan = plan_env(
            inherited(&[("DB", "vault://old/old/old"), ("LOG", "debug")]),
            file("DB=vault://new/new/new\nLOG=info\nOTHER=1\n"),
        )
        .unwrap();
        assert_eq!(
            plan.entries().get(&os("DB")),
            Some(&Source::Reference(reference("vault://new/new/new")))
        );
        assert_eq!(
            plan.entries().get(&os("LOG")),
            Some(&Source::Literal(b"info".to_vec()))
        );
        assert_eq!(plan.overrides(), [os("DB"), os("LOG")]);
        // The reference that lost is not resolved.
        let refs: Vec<String> = plan.references().iter().map(|r| r.to_string()).collect();
        assert_eq!(refs, ["vault://new/new/new"]);
    }

    #[test]
    fn a_bad_inherited_reference_that_the_file_overrides_still_fails() {
        // Every inherited reference is checked before the file is applied.
        let err = plan_env(inherited(&[("DB", "vault://bad")]), file("DB=ok")).unwrap_err();
        assert!(matches!(err, RunError::BadEnvReference { .. }));
    }

    fn resolved(pairs: &[(&str, &str)]) -> Resolved {
        pairs
            .iter()
            .map(|(r, v)| (reference(r), SecretValue::new(v.as_bytes())))
            .collect()
    }

    #[test]
    fn warnings_name_overrides_and_short_secrets_but_never_values() {
        let plan = plan_env(
            inherited(&[("DB", "x")]),
            file("DB=vault://p/i/short\nLONG=vault://p/i/long\nEMPTY=vault://p/i/empty\n"),
        )
        .unwrap();
        let values = resolved(&[
            ("vault://p/i/short", "tiny"),
            ("vault://p/i/long", "long-enough-secret"),
            ("vault://p/i/empty", ""),
        ]);
        let lines = warnings(&plan, &values, false);
        let text = lines.join("\n");
        assert!(text.contains("DB is set in the environment and in the env file"));
        assert!(text.contains("vault://p/i/short"));
        assert!(!text.contains("vault://p/i/long"));
        assert!(
            !text.contains("vault://p/i/empty"),
            "an empty value has nothing to mask"
        );
        assert!(!text.contains("tiny"));
        assert!(!text.contains("long-enough-secret"));
    }

    #[test]
    fn a_secret_of_exactly_eight_bytes_gets_no_warning() {
        let plan = plan_env(vec![], file("A=vault://p/i/f")).unwrap();
        let seven = warnings(&plan, &resolved(&[("vault://p/i/f", "1234567")]), false);
        let eight = warnings(&plan, &resolved(&[("vault://p/i/f", "12345678")]), false);
        assert_eq!(seven.len(), 1);
        assert!(eight.is_empty());
    }

    #[test]
    fn no_mask_warns_that_output_is_not_masked() {
        let plan = EnvPlan::default();
        let lines = warnings(&plan, &Resolved::new(), true);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("--no-mask"));
        assert!(warnings(&plan, &Resolved::new(), false).is_empty());
    }

    #[test]
    fn exit_codes_follow_the_child() {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(exit_code(ExitStatus::from_raw(0)), 0);
        assert_eq!(exit_code(ExitStatus::from_raw(7 << 8)), 7);
        assert_eq!(exit_code(ExitStatus::from_raw(255 << 8)), 255);
        // Killed by SIGTERM (15) and SIGKILL (9).
        assert_eq!(exit_code(ExitStatus::from_raw(15)), 143);
        assert_eq!(exit_code(ExitStatus::from_raw(9)), 137);
    }

    #[test]
    fn a_pump_masks_and_flushes_what_it_reads() {
        let secret = b"fake-secret-value-1234";
        let masker = Masker::new([&secret[..]]).unwrap();
        let input = b"before fake-secret-value-1234 after\n".to_vec();
        let mut out = Vec::new();
        pump(io::Cursor::new(input), masker, &mut out).unwrap();
        assert_eq!(out, b"before <concealed by vaultline> after\n");
    }

    #[test]
    fn a_pump_returns_the_error_of_a_broken_output() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
        let masker = Masker::new([&b"abc"[..]]).unwrap();
        let err = pump(io::Cursor::new(b"hello".to_vec()), masker, Broken).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn os_strings_with_odd_bytes_are_handled() {
        let odd = OsString::from_vec(vec![b'V', 0xff, b'=']);
        let plan = plan_env(vec![(odd, os("vault://p"))], vec![]).unwrap_err();
        assert!(plan.to_string().contains("\\xff"));
    }
}
