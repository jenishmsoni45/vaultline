//! The `vault://project/item/field` reference (`docs/design.md` §5.1, D-026,
//! D-027).
//!
//! ```text
//! reference = "vault://" name "/" name "/" name
//! name      = 1*64( ALPHA / DIGIT / "." / "_" / "-" )   ; case-sensitive
//! ```
//!
//! References come from the environment, from env files and from templates,
//! so every byte is untrusted (S10): no `unwrap`, `expect`, indexing, `panic`
//! or unchecked arithmetic, enforced by the lints below. A reference names a
//! secret; it is not one, so it may be printed. Anything printed from
//! untrusted bytes goes through [`escape`], which keeps the text on one line
//! and short.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::fmt;

use crate::vault::{Name, NameError};

/// The scheme every reference starts with.
pub const SCHEME: &[u8] = b"vault://";

/// The longest text [`escape`] prints before cutting it off.
const ESCAPE_LIMIT: usize = 80;

/// A parsed reference: exactly one field of one item of one project.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reference {
    pub project: Name,
    pub item: Name,
    pub field: Name,
}

/// Why some bytes are not a reference. The message never repeats the bytes;
/// callers print them through [`escape`] when they want to show them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceError {
    /// The text doesn't start with `vault://`.
    NoScheme,
    /// There are not exactly three names separated by `/`.
    WrongShape,
    /// One of the names is not valid.
    BadName(NameError),
}

impl fmt::Display for ReferenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReferenceError::NoScheme => f.write_str("a reference starts with vault://"),
            ReferenceError::WrongShape => {
                f.write_str("a reference is vault://project/item/field, with three names")
            }
            ReferenceError::BadName(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for ReferenceError {}

impl Reference {
    /// Parses `vault://project/item/field`. The whole input must be the
    /// reference: nothing before it, nothing after it.
    pub fn parse(bytes: &[u8]) -> Result<Reference, ReferenceError> {
        let rest = bytes.strip_prefix(SCHEME).ok_or(ReferenceError::NoScheme)?;
        Self::parse_path(rest)
    }

    /// Parses a reference as typed on the command line: with or without the
    /// `vault://` scheme (US-2 AC8).
    pub fn parse_cli(text: &str) -> Result<Reference, ReferenceError> {
        let bytes = text.as_bytes();
        Self::parse_path(bytes.strip_prefix(SCHEME).unwrap_or(bytes))
    }

    /// `project/item/field`.
    fn parse_path(path: &[u8]) -> Result<Reference, ReferenceError> {
        let mut parts = path.split(|b| *b == b'/');
        let (Some(project), Some(item), Some(field), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(ReferenceError::WrongShape);
        };
        let name = |bytes: &[u8]| Name::from_bytes(bytes).map_err(ReferenceError::BadName);
        Ok(Reference {
            project: name(project)?,
            item: name(item)?,
            field: name(field)?,
        })
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vault://{}/{}/{}", self.project, self.item, self.field)
    }
}

/// Untrusted bytes in a form that is safe to print in an error message: printable
/// ASCII as it is, every other byte as `\xNN`, cut off after 80 bytes.
pub fn escape(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes.iter().take(ESCAPE_LIMIT) {
        if byte.is_ascii_graphic() || *byte == b' ' {
            out.push(char::from(*byte));
        } else {
            out.push_str(&format!("\\x{byte:02x}"));
        }
    }
    if bytes.len() > ESCAPE_LIMIT {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Reference, ReferenceError> {
        Reference::parse(text.as_bytes())
    }

    #[test]
    fn a_valid_reference_parses_and_prints_back_the_same() {
        let reference = parse("vault://acme/stripe/live_key").unwrap();
        assert_eq!(reference.project.as_str(), "acme");
        assert_eq!(reference.item.as_str(), "stripe");
        assert_eq!(reference.field.as_str(), "live_key");
        assert_eq!(reference.to_string(), "vault://acme/stripe/live_key");
    }

    #[test]
    fn names_may_use_letters_digits_dot_underscore_and_hyphen() {
        assert!(parse("vault://A.b_c-9/x/y").is_ok());
    }

    #[test]
    fn names_are_case_sensitive() {
        assert_ne!(
            parse("vault://A/b/c").unwrap(),
            parse("vault://a/b/c").unwrap()
        );
    }

    #[test]
    fn a_name_is_one_to_sixty_four_bytes() {
        let longest = "n".repeat(64);
        assert!(parse(&format!("vault://{longest}/{longest}/{longest}")).is_ok());
        let too_long = "n".repeat(65);
        assert_eq!(
            parse(&format!("vault://{too_long}/b/c")),
            Err(ReferenceError::BadName(NameError::TooLong))
        );
        assert_eq!(
            parse("vault:///b/c"),
            Err(ReferenceError::BadName(NameError::Empty))
        );
        assert_eq!(
            parse("vault://a/b/"),
            Err(ReferenceError::BadName(NameError::Empty))
        );
    }

    #[test]
    fn a_name_outside_the_allowed_characters_is_rejected() {
        for bad in ["a b", "a:b", "a\\b", "\u{e9}", "a\nb", "a*"] {
            assert_eq!(
                parse(&format!("vault://{bad}/b/c")),
                Err(ReferenceError::BadName(NameError::BadByte)),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_wrong_number_of_names_is_rejected() {
        for bad in [
            "vault://",
            "vault://a",
            "vault://a/b",
            "vault://a/b/c/d",
            "vault://a/b/c/",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_scheme_is_required_and_case_sensitive() {
        assert_eq!(parse("a/b/c"), Err(ReferenceError::NoScheme));
        assert_eq!(parse("VAULT://a/b/c"), Err(ReferenceError::NoScheme));
        assert_eq!(parse("vault:/a/b/c"), Err(ReferenceError::NoScheme));
        assert_eq!(parse(""), Err(ReferenceError::NoScheme));
    }

    #[test]
    fn nothing_may_come_before_or_after_the_reference() {
        for bad in [
            " vault://a/b/c",
            "vault://a/b/c ",
            "vault://a/b/c\n",
            "x vault://a/b/c",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn bytes_that_are_not_text_are_rejected_without_panicking() {
        assert!(Reference::parse(b"vault://a/b/\xff").is_err());
        assert!(Reference::parse(&[0xff, 0xfe, 0x00]).is_err());
        assert!(Reference::parse(b"vault://\0/\0/\0").is_err());
    }

    #[test]
    fn the_command_line_form_works_with_or_without_the_scheme() {
        let long = Reference::parse_cli("vault://p/i/f").unwrap();
        let short = Reference::parse_cli("p/i/f").unwrap();
        assert_eq!(long, short);
        assert!(Reference::parse_cli("p/i").is_err());
        assert!(Reference::parse_cli("vault://p/i").is_err());
        assert!(Reference::parse_cli("").is_err());
    }

    proptest::proptest! {
        /// The properties the `reference` fuzz target checks, so that a bug in
        /// the harness shows up here and not only in CI.
        #[test]
        fn the_grammar_is_canonical_and_never_panics(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64),
            text in "(vault://)?[A-Za-z0-9._/-]{0,24}",
        ) {
            for input in [bytes.as_slice(), text.as_bytes()] {
                if let Ok(reference) = Reference::parse(input) {
                    let printed = reference.to_string();
                    proptest::prop_assert_eq!(printed.as_bytes(), input);
                    let as_text = std::str::from_utf8(input).unwrap();
                    proptest::prop_assert_eq!(Reference::parse_cli(as_text), Ok(reference));
                }
                let shown = escape(input);
                proptest::prop_assert!(!shown.contains('\n') && shown.len() <= 80 * 4 + 3);
            }
            if let Ok(as_text) = std::str::from_utf8(&bytes) {
                let _ = Reference::parse_cli(as_text);
            }
        }
    }

    #[test]
    fn escape_keeps_printable_text_and_hides_everything_else() {
        assert_eq!(escape(b"vault://a/b/c"), "vault://a/b/c");
        assert_eq!(escape(b"a\nb\x00\xff"), "a\\x0ab\\x00\\xff");
        let long = escape(&[b'a'; 500]);
        assert_eq!(long.len(), 83);
        assert!(long.ends_with("..."));
        // Bytes that are escaped take four characters each.
        let worst = escape(&[0u8; 500]);
        assert_eq!(worst.len(), 80 * 4 + 3);
        assert!(!worst.contains('\n'));
    }
}
