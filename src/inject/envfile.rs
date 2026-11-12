//! The `--env-file` parser (`docs/design.md` §5.2, D-037).
//!
//! ```text
//! file     = *( line LF ) [ line ]
//! line     = blank / comment / assign
//! blank    = *( SP / HTAB )
//! comment  = *( SP / HTAB ) "#" *( any byte except LF )
//! assign   = envname "=" value
//! envname  = ( ALPHA / "_" ) *( ALPHA / DIGIT / "_" )
//! value    = *( any byte except LF and CR )
//! ```
//!
//! Values are literal: no quoting, no trimming and no `$VAR` expansion. A value
//! that starts with `vault://` must be a complete, valid reference, or the
//! whole file is rejected. The file is rejected too when it holds a carriage
//! return anywhere, a name twice, a malformed line, or more than 16 MiB.
//!
//! The file is untrusted input (S10): no `unwrap`, `expect`, indexing, `panic`
//! or unchecked arithmetic, enforced by the lints below. Errors name the line
//! and the problem, and never repeat the value.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeSet;
use std::fmt;

use super::reference::{Reference, ReferenceError, SCHEME};

/// The largest env file, in bytes (NFR-11).
pub const MAX_ENV_FILE_LEN: usize = 16 * 1024 * 1024;

/// What an assignment sets the variable to.
#[derive(Clone, PartialEq, Eq)]
pub enum EnvValue {
    /// Passed to the child exactly as written. Not resolved, not masked.
    Literal(Vec<u8>),
    /// Replaced by the secret at this reference.
    Reference(Reference),
}

// A literal is whatever the user typed in the file. It is not a vault secret,
// but nothing needs to print it, so Debug leaves it out.
impl fmt::Debug for EnvValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvValue::Literal(bytes) => write!(f, "Literal({} bytes)", bytes.len()),
            EnvValue::Reference(reference) => write!(f, "Reference({reference})"),
        }
    }
}

/// One `NAME=value` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    pub name: String,
    pub value: EnvValue,
}

/// Why the file was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvFileErrorKind {
    /// More than 16 MiB. Reported with line 0, since nothing was read.
    TooLarge,
    /// A carriage return, so probably a Windows line ending.
    CarriageReturn,
    /// Not blank, not a comment and not `NAME=value`.
    Malformed,
    /// The name before `=` is not `[A-Za-z_][A-Za-z0-9_]*`.
    BadName,
    /// The same name is assigned twice.
    Duplicate(String),
    /// A value starts with `vault://` but is not a valid reference.
    BadReference(ReferenceError),
}

/// A rejected env file: what is wrong, and on which line (counted from 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvFileError {
    pub line: usize,
    pub kind: EnvFileErrorKind,
}

impl fmt::Display for EnvFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            EnvFileErrorKind::TooLarge => {
                f.write_str("the env file is larger than the 16 MiB limit")
            }
            EnvFileErrorKind::CarriageReturn => write!(
                f,
                "line {}: the env file contains a carriage return; use \\n line endings",
                self.line
            ),
            EnvFileErrorKind::Malformed => write!(
                f,
                "line {}: expected NAME=value, a # comment or a blank line",
                self.line
            ),
            EnvFileErrorKind::BadName => write!(
                f,
                "line {}: a variable name starts with a letter or _ and then uses letters, digits and _",
                self.line
            ),
            EnvFileErrorKind::Duplicate(name) => {
                write!(f, "line {}: {name} is assigned more than once", self.line)
            }
            EnvFileErrorKind::BadReference(why) => write!(
                f,
                "line {}: a value that starts with vault:// must be a valid reference: {why}",
                self.line
            ),
        }
    }
}

impl std::error::Error for EnvFileError {}

/// Parses an env file. The assignments come back in file order.
pub fn parse(bytes: &[u8]) -> Result<Vec<Assignment>, EnvFileError> {
    if bytes.len() > MAX_ENV_FILE_LEN {
        return Err(EnvFileError {
            line: 0,
            kind: EnvFileErrorKind::TooLarge,
        });
    }
    let mut assignments = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, line) in bytes.split(|b| *b == b'\n').enumerate() {
        let number = index.saturating_add(1);
        let fail = |kind| EnvFileError { line: number, kind };
        if line.contains(&b'\r') {
            return Err(fail(EnvFileErrorKind::CarriageReturn));
        }
        let content = skip_blanks(line);
        if content.is_empty() || content.first() == Some(&b'#') {
            continue;
        }
        let (name, value) =
            split_assignment(line).ok_or_else(|| fail(EnvFileErrorKind::Malformed))?;
        if !is_env_name(name) {
            return Err(fail(EnvFileErrorKind::BadName));
        }
        // The name is ASCII, so this can't fail; the error is only for the type.
        let name = String::from_utf8(name.to_vec()).map_err(|_| fail(EnvFileErrorKind::BadName))?;
        if !seen.insert(name.clone()) {
            return Err(fail(EnvFileErrorKind::Duplicate(name)));
        }
        let value = if value.starts_with(SCHEME) {
            EnvValue::Reference(
                Reference::parse(value).map_err(|why| fail(EnvFileErrorKind::BadReference(why)))?,
            )
        } else {
            EnvValue::Literal(value.to_vec())
        };
        assignments.push(Assignment { name, value });
    }
    Ok(assignments)
}

/// The line without its leading spaces and tabs.
fn skip_blanks(line: &[u8]) -> &[u8] {
    let blanks = line
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t'))
        .unwrap_or(line.len());
    line.get(blanks..).unwrap_or_default()
}

/// Splits `NAME=value` at the first `=`. An assignment has no leading blanks.
fn split_assignment(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let equals = line.iter().position(|b| *b == b'=')?;
    let (name, rest) = line.split_at_checked(equals)?;
    Some((name, rest.get(1..)?))
}

fn is_env_name(name: &[u8]) -> bool {
    let mut bytes = name.iter();
    matches!(bytes.next(), Some(b) if b.is_ascii_alphabetic() || *b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn parse_str(text: &str) -> Result<Vec<Assignment>, EnvFileError> {
        parse(text.as_bytes())
    }

    fn literal(bytes: &[u8]) -> EnvValue {
        EnvValue::Literal(bytes.to_vec())
    }

    #[test]
    fn assignments_come_back_in_file_order() {
        let parsed = parse_str("B=2\nA=1\n_C9=3").unwrap();
        let names: Vec<&str> = parsed.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["B", "A", "_C9"]);
        assert_eq!(parsed[0].value, literal(b"2"));
    }

    #[test]
    fn blank_lines_and_comments_are_skipped() {
        let parsed = parse_str("\n  \t\n# a comment\n   # indented comment\nA=1\n#B=2\n").unwrap();
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn the_last_line_needs_no_newline_and_an_empty_file_is_fine() {
        assert_eq!(parse_str("A=1").unwrap().len(), 1);
        assert!(parse_str("").unwrap().is_empty());
        assert!(parse_str("\n\n").unwrap().is_empty());
    }

    #[test]
    fn values_are_literal() {
        let parsed =
            parse_str("A=\"quoted\"\nB= spaced \nC=$HOME ${X}\nD=a=b=c\nE=\nF='x'").unwrap();
        assert_eq!(parsed[0].value, literal(b"\"quoted\""));
        assert_eq!(parsed[1].value, literal(b" spaced "));
        assert_eq!(parsed[2].value, literal(b"$HOME ${X}"));
        assert_eq!(parsed[3].value, literal(b"a=b=c"));
        assert_eq!(parsed[4].value, literal(b""));
        assert_eq!(parsed[5].value, literal(b"'x'"));
    }

    #[test]
    fn a_value_is_not_limited_to_text() {
        let parsed = parse(b"A=\xff\xfe\x00\x01\n").unwrap();
        assert_eq!(parsed[0].value, literal(b"\xff\xfe\x00\x01"));
    }

    #[test]
    fn a_value_that_starts_with_the_scheme_must_be_a_reference() {
        let parsed = parse_str("A=vault://p/i/f").unwrap();
        assert_eq!(
            parsed[0].value,
            EnvValue::Reference(Reference::parse(b"vault://p/i/f").unwrap())
        );
        for bad in [
            "A=vault://",
            "A=vault://p/i",
            "A=vault://p/i/f/g",
            "A=vault://p/i/f ",
            "A=vault://p/i/f#c",
            "A=vault://p/i/$X",
        ] {
            let err = parse_str(bad).unwrap_err();
            assert!(
                matches!(err.kind, EnvFileErrorKind::BadReference(_)),
                "{bad:?}: {err:?}"
            );
        }
    }

    #[test]
    fn other_values_that_mention_vault_are_literal() {
        let parsed = parse_str("A=x vault://p/i/f\nB= vault://p/i/f\nC=VAULT://p/i/f").unwrap();
        assert!(
            parsed
                .iter()
                .all(|a| matches!(a.value, EnvValue::Literal(_)))
        );
    }

    #[test]
    fn a_carriage_return_anywhere_rejects_the_file() {
        for bad in ["A=1\r\n", "A=1\rB=2", "# note\r\nA=1", "\r\n", "A=\r"] {
            let err = parse_str(bad).unwrap_err();
            assert_eq!(err.kind, EnvFileErrorKind::CarriageReturn, "{bad:?}");
        }
    }

    #[test]
    fn a_duplicate_name_rejects_the_file() {
        let err = parse_str("A=1\nB=2\nA=3").unwrap_err();
        assert_eq!(err.kind, EnvFileErrorKind::Duplicate("A".into()));
        assert_eq!(err.line, 3);
        // Names are case-sensitive.
        assert!(parse_str("A=1\na=2").is_ok());
    }

    #[test]
    fn a_malformed_line_rejects_the_file_with_its_line_number() {
        for (bad, line) in [
            ("A=1\nnot an assignment\n", 2),
            ("A=1\n\n  A2=1", 3),
            ("export A=1", 1),
            ("=value", 1),
            ("1A=x", 1),
            ("A-B=x", 1),
            ("A B=x", 1),
            ("\u{e9}=x", 1),
        ] {
            let err = parse_str(bad).unwrap_err();
            assert_eq!(err.line, line, "{bad:?}");
            assert!(
                matches!(
                    err.kind,
                    EnvFileErrorKind::Malformed | EnvFileErrorKind::BadName
                ),
                "{bad:?}: {err:?}"
            );
        }
    }

    #[test]
    fn a_file_over_16_mib_is_rejected() {
        let ok = vec![b'#'; MAX_ENV_FILE_LEN];
        assert!(parse(&ok).unwrap().is_empty());
        let too_big = vec![b'#'; MAX_ENV_FILE_LEN + 1];
        assert_eq!(
            parse(&too_big).unwrap_err().kind,
            EnvFileErrorKind::TooLarge
        );
    }

    #[test]
    fn error_messages_never_repeat_the_value() {
        let secret = "fake-secret-value-9f3a";
        for bad in [
            format!("A={secret}\nA={secret}"),
            format!("A=vault://p/{secret}"),
            secret.to_string(),
        ] {
            let message = parse_str(&bad).unwrap_err().to_string();
            assert!(!message.contains(secret), "{message}");
        }
    }

    proptest! {
        /// S10: no input panics. Raw bytes first, then text built from the
        /// pieces of the grammar so the interesting branches are reached.
        #[test]
        fn parsing_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse(&bytes);
        }

        #[test]
        fn parsing_never_panics_on_grammar_like_text(
            lines in proptest::collection::vec(
                prop_oneof![
                    "[ \t]*",
                    "[ \t]*#[ -~]*",
                    "[A-Za-z_][A-Za-z0-9_]*=[ -~]*",
                    "[A-Za-z_]*=vault://[A-Za-z0-9._/-]*",
                    "[ -~\r]*",
                ],
                0..12,
            )
        ) {
            let _ = parse(lines.join("\n").as_bytes());
        }

        /// What the parser accepts is what the grammar says: every accepted
        /// assignment has a valid name, and names are unique.
        #[test]
        fn accepted_files_hold_valid_unique_names(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            if let Ok(parsed) = parse(&bytes) {
                let mut names = BTreeSet::new();
                for a in &parsed {
                    prop_assert!(is_env_name(a.name.as_bytes()));
                    prop_assert!(names.insert(a.name.clone()));
                }
            }
        }
    }
}
