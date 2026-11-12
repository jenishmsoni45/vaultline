//! Refusing to write secrets into a regular file (`docs/design.md` §4, D-010,
//! D-011).
//!
//! `get` and `inject` check where standard output goes before they resolve
//! anything. If it is a regular file, which is what `> config.yml` makes it,
//! they stop with an error and write nothing, so a secret never reaches the
//! disk by accident. Pipes, terminals, `/dev/null` and process substitution
//! (`>(...)`) are all fine.
//!
//! This guards against accidents, not against intent: `| cat > file` gets past
//! it, and the threat model says so (R8).

use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::AsFd;

/// Standard output is a regular file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegularFile;

impl fmt::Display for RegularFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "standard output is a regular file, so secrets would be written to disk; \
             pipe the output to the program that needs it (for example `| program`, or \
             `>(program)` in bash and zsh) instead of redirecting it to a file",
        )
    }
}

impl std::error::Error for RegularFile {}

/// Why the check itself failed, as opposed to refusing.
#[derive(Debug)]
pub enum OutputError {
    /// Standard output is a regular file.
    Refused(RegularFile),
    /// Standard output couldn't be inspected, for example because it is
    /// closed.
    Io(io::Error),
}

impl fmt::Display for OutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputError::Refused(refusal) => refusal.fmt(f),
            OutputError::Io(source) => write!(f, "can't inspect standard output: {source}"),
        }
    }
}

impl std::error::Error for OutputError {}

/// Whether `fd` is a regular file, found through `fstat` on a duplicate of the
/// descriptor, so the check applies to exactly the file that would be written.
pub fn is_regular_file(fd: impl AsFd) -> io::Result<bool> {
    let file = File::from(fd.as_fd().try_clone_to_owned()?);
    Ok(file.metadata()?.is_file())
}

/// Fails unless standard output is something other than a regular file.
pub fn refuse_regular_file_stdout() -> Result<(), OutputError> {
    match is_regular_file(io::stdout()) {
        Ok(false) => Ok(()),
        Ok(true) => Err(OutputError::Refused(RegularFile)),
        Err(source) => Err(OutputError::Io(source)),
    }
}

/// A writer on standard output that goes straight to the descriptor, with no
/// buffering of its own. Callers add a `BufWriter` where they want one and
/// flush it themselves.
pub fn raw_stdout() -> io::Result<File> {
    Ok(File::from(io::stdout().as_fd().try_clone_to_owned()?))
}

/// The same for standard error.
pub fn raw_stderr() -> io::Result<File> {
    Ok(File::from(io::stderr().as_fd().try_clone_to_owned()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_regular_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = File::create(dir.path().join("out")).unwrap();
        assert!(is_regular_file(&file).unwrap());
    }

    #[test]
    fn a_pipe_and_a_device_are_not_regular_files() {
        // A socket pair stands in for a pipe: neither is a regular file.
        let (one, two) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(!is_regular_file(&one).unwrap());
        assert!(!is_regular_file(&two).unwrap());
        let null = File::options().write(true).open("/dev/null").unwrap();
        assert!(!is_regular_file(&null).unwrap());
    }

    #[test]
    fn the_refusal_explains_why_and_what_to_do() {
        let message = RegularFile.to_string();
        assert!(message.contains("regular file"));
        assert!(message.contains("pipe"));
    }
}
