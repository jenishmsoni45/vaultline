//! The `inject` template parser and renderer (`docs/design.md` §5.3, D-026).
//!
//! ```text
//! ref-tag = "{{" *( SP / HTAB ) reference *( SP / HTAB ) "}}"
//! ```
//!
//! How a template is scanned:
//!
//! 1. Bytes are copied until `{{` turns up.
//! 2. If `{{` is followed, after optional spaces and tabs, by `vault://`, it
//!    starts a ref-tag. The tag must be a valid reference, optional blanks and
//!    `}}`; if it isn't, the whole template is rejected, with the line and
//!    column of the `{{`.
//! 3. Otherwise one `{` is copied and scanning goes on from the next byte, so
//!    other `{{ }}` syntax (Helm, Jinja) passes through unchanged.
//!
//! There is no escape syntax. Templates are limited to 16 MiB.
//!
//! The template is untrusted input (S10): no `unwrap`, `expect`, indexing,
//! `panic` or unchecked arithmetic, enforced by the lints below. Parsing
//! copies nothing; a [`Template`] borrows the bytes it was parsed from.
//! Error messages say where and why, and never repeat template text.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Write};

use super::reference::{Reference, ReferenceError, SCHEME};
use crate::secret::SecretValue;

/// The largest template, in bytes (NFR-11).
pub const MAX_TEMPLATE_LEN: usize = 16 * 1024 * 1024;

/// Values by reference, as resolved for one command.
pub type Resolved = BTreeMap<Reference, SecretValue>;

/// What is wrong with a ref-tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateErrorKind {
    /// More than 16 MiB. Reported with line 0 and column 0.
    TooLarge,
    /// `{{ vault://` is not followed by a valid reference.
    BadReference(ReferenceError),
    /// The reference is not followed by optional blanks and `}}`.
    NotClosed,
}

/// A rejected template. `line` and `column` count from 1, and the column
/// counts bytes. They point at the `{{` that starts the bad tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemplateError {
    pub line: usize,
    pub column: usize,
    pub kind: TemplateErrorKind,
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            TemplateErrorKind::TooLarge => {
                f.write_str("the template is larger than the 16 MiB limit")
            }
            TemplateErrorKind::BadReference(why) => write!(
                f,
                "line {}, column {}: the tag is not a valid reference: {why}",
                self.line, self.column
            ),
            TemplateErrorKind::NotClosed => write!(
                f,
                "line {}, column {}: the reference must be followed by }}}}",
                self.line, self.column
            ),
        }
    }
}

impl std::error::Error for TemplateError {}

/// A piece of a template.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Part<'a> {
    /// Bytes copied to the output as they are.
    Literal(&'a [u8]),
    /// Replaced by the value at this reference.
    Reference(Reference),
}

/// A parsed template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template<'a> {
    parts: Vec<Part<'a>>,
}

impl<'a> Template<'a> {
    /// Parses `bytes`, or says where the first bad tag is.
    pub fn parse(bytes: &'a [u8]) -> Result<Template<'a>, TemplateError> {
        if bytes.len() > MAX_TEMPLATE_LEN {
            return Err(TemplateError {
                line: 0,
                column: 0,
                kind: TemplateErrorKind::TooLarge,
            });
        }
        let mut parts = Vec::new();
        let mut literal_start = 0usize;
        let mut scan = 0usize;
        while let Some(open) = find_open(bytes, scan) {
            let fail = |kind| {
                let (line, column) = position(bytes, open);
                TemplateError { line, column, kind }
            };
            let after_open = open.saturating_add(2);
            let blanks = count_blanks(bytes.get(after_open..).unwrap_or_default());
            let ref_start = after_open.saturating_add(blanks);
            let tail = bytes.get(ref_start..).unwrap_or_default();
            if !tail.starts_with(SCHEME) {
                // Not a ref-tag: copy one `{` and look again from the next byte.
                scan = open.saturating_add(1);
                continue;
            }
            let path_len = tail
                .get(SCHEME.len()..)
                .unwrap_or_default()
                .iter()
                .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
                .count();
            let ref_end = ref_start
                .saturating_add(SCHEME.len())
                .saturating_add(path_len);
            let reference = Reference::parse(bytes.get(ref_start..ref_end).unwrap_or_default())
                .map_err(|why| fail(TemplateErrorKind::BadReference(why)))?;
            let after_ref = bytes.get(ref_end..).unwrap_or_default();
            let closing = after_ref.get(count_blanks(after_ref)..).unwrap_or_default();
            if !closing.starts_with(b"}}") {
                return Err(fail(TemplateErrorKind::NotClosed));
            }
            // `closing` is the end of the template, so its start is its offset.
            let close_start = bytes.len().saturating_sub(closing.len());
            let close_end = close_start.saturating_add(2);
            if let Some(literal) = bytes.get(literal_start..open).filter(|l| !l.is_empty()) {
                parts.push(Part::Literal(literal));
            }
            parts.push(Part::Reference(reference));
            literal_start = close_end;
            scan = close_end;
        }
        if let Some(literal) = bytes.get(literal_start..).filter(|l| !l.is_empty()) {
            parts.push(Part::Literal(literal));
        }
        Ok(Template { parts })
    }

    /// The distinct references in the template, sorted.
    pub fn references(&self) -> BTreeSet<&Reference> {
        self.parts
            .iter()
            .filter_map(|part| match part {
                Part::Reference(reference) => Some(reference),
                Part::Literal(_) => None,
            })
            .collect()
    }

    /// Writes the template with every tag replaced by its value. Every
    /// reference must be in `values`: the commands resolve all of them first
    /// (D-028), so nothing is written for a template that can't be rendered.
    /// Values are written straight from their wiped-on-drop buffers; the
    /// output is never collected in memory.
    pub fn render<W: Write>(&self, values: &Resolved, out: &mut W) -> io::Result<()> {
        for part in &self.parts {
            match part {
                Part::Literal(bytes) => out.write_all(bytes)?,
                Part::Reference(reference) => {
                    let value = values.get(reference).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "a reference was not resolved")
                    })?;
                    out.write_all(value.expose())?;
                }
            }
        }
        Ok(())
    }
}

/// The offset of the next `{{` at or after `from`.
fn find_open(bytes: &[u8], from: usize) -> Option<usize> {
    let mut at = from;
    loop {
        let tail = bytes.get(at..)?;
        let brace = at.saturating_add(tail.iter().position(|b| *b == b'{')?);
        if bytes.get(brace.saturating_add(1)) == Some(&b'{') {
            return Some(brace);
        }
        at = brace.saturating_add(1);
    }
}

/// How many spaces and tabs `bytes` starts with.
fn count_blanks(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .take_while(|b| matches!(b, b' ' | b'\t'))
        .count()
}

/// Line and column, both counted from 1, of the byte at `offset`.
fn position(bytes: &[u8], offset: usize) -> (usize, usize) {
    let before = bytes.get(..offset).unwrap_or_default();
    let line = before
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        .saturating_add(1);
    let line_start = before
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |newline| newline.saturating_add(1));
    (line, offset.saturating_sub(line_start).saturating_add(1))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn value(bytes: &[u8]) -> SecretValue {
        SecretValue::new(bytes)
    }

    fn reference(text: &str) -> Reference {
        Reference::parse(text.as_bytes()).unwrap()
    }

    fn values(pairs: &[(&str, &str)]) -> Resolved {
        pairs
            .iter()
            .map(|(r, v)| (reference(r), value(v.as_bytes())))
            .collect()
    }

    fn render(template: &str, pairs: &[(&str, &str)]) -> String {
        let parsed = Template::parse(template.as_bytes()).unwrap();
        let mut out = Vec::new();
        parsed.render(&values(pairs), &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    fn error(template: &str) -> TemplateError {
        Template::parse(template.as_bytes()).unwrap_err()
    }

    #[test]
    fn a_tag_is_replaced_by_its_value() {
        assert_eq!(
            render("key={{ vault://p/i/f }}!", &[("vault://p/i/f", "S3CR3T")]),
            "key=S3CR3T!"
        );
    }

    #[test]
    fn whitespace_inside_the_braces_is_optional() {
        for tag in [
            "{{vault://p/i/f}}",
            "{{ vault://p/i/f }}",
            "{{\tvault://p/i/f\t}}",
            "{{   vault://p/i/f}}",
            "{{vault://p/i/f   }}",
        ] {
            assert_eq!(render(tag, &[("vault://p/i/f", "V")]), "V", "{tag:?}");
        }
    }

    #[test]
    fn other_text_is_copied_unchanged() {
        let text = "plain {{ .Values.x }} {{- if y -}} {{ other }} { } {{}} }} {{\n\nvault:// vault://p/i/f";
        assert_eq!(render(text, &[]), text);
    }

    #[test]
    fn text_that_mentions_the_scheme_without_braces_is_not_replaced() {
        let text = "url: vault://p/i/f";
        assert_eq!(render(text, &[]), text);
    }

    #[test]
    fn a_tag_can_sit_inside_a_url_or_a_quoted_string() {
        let pairs = [("vault://db/main/password", "pw")];
        assert_eq!(
            render(
                "postgres://user:{{ vault://db/main/password }}@host/db",
                &pairs
            ),
            "postgres://user:pw@host/db"
        );
        assert_eq!(render("\"{{vault://db/main/password}}\"", &pairs), "\"pw\"");
    }

    #[test]
    fn adjacent_and_repeated_tags_all_work() {
        let pairs = [("vault://p/i/a", "1"), ("vault://p/i/b", "2")];
        assert_eq!(
            render(
                "{{vault://p/i/a}}{{vault://p/i/b}}{{ vault://p/i/a }}",
                &pairs
            ),
            "121"
        );
    }

    #[test]
    fn extra_braces_before_a_tag_are_copied_and_the_tag_is_replaced() {
        let pairs = [("vault://p/i/f", "V")];
        assert_eq!(render("{{{ vault://p/i/f }}", &pairs), "{V");
        assert_eq!(render("{{{{vault://p/i/f}}}}", &pairs), "{{V}}");
    }

    #[test]
    fn a_value_is_written_as_it_is_even_if_it_looks_like_a_tag() {
        let pairs = [("vault://p/i/f", "{{ vault://p/i/f }}")];
        assert_eq!(render("{{vault://p/i/f}}", &pairs), "{{ vault://p/i/f }}");
    }

    #[test]
    fn a_template_does_not_have_to_be_text() {
        let parsed = Template::parse(b"\xff\x00{{vault://p/i/f}}\xfe").unwrap();
        let mut out = Vec::new();
        parsed
            .render(&values(&[("vault://p/i/f", "V")]), &mut out)
            .unwrap();
        assert_eq!(out, b"\xff\x00V\xfe");
    }

    #[test]
    fn an_empty_template_renders_nothing() {
        assert_eq!(render("", &[]), "");
    }

    #[test]
    fn references_lists_each_reference_once_in_order() {
        let template =
            Template::parse(b"{{vault://b/b/b}} {{vault://a/a/a}} {{ vault://b/b/b }}").unwrap();
        let listed: Vec<String> = template
            .references()
            .iter()
            .map(|r| r.to_string())
            .collect();
        assert_eq!(listed, ["vault://a/a/a", "vault://b/b/b"]);
    }

    #[test]
    fn a_malformed_tag_is_rejected_with_its_line_and_column() {
        let cases: [(&str, usize, usize); 6] = [
            ("{{ vault://p/i }}", 1, 1),
            ("abc {{ vault://p/i/f/g }}", 1, 5),
            ("a\nb\n  {{vault://bad name/i/f}}", 3, 3),
            ("ok {{vault://p/i/f}}\n{{ vault:// }}", 2, 1),
            ("line1\n\u{e9}{{ vault://p/i/ }}", 2, 3),
            ("{{vault://p/i/f", 1, 1),
        ];
        for (template, line, column) in cases {
            let err = error(template);
            assert_eq!((err.line, err.column), (line, column), "{template:?}");
        }
    }

    #[test]
    fn a_tag_that_is_not_closed_properly_is_rejected() {
        for template in [
            "{{ vault://p/i/f",
            "{{ vault://p/i/f }",
            "{{ vault://p/i/f x }}",
            "{{ vault://p/i/f\n}}",
            "{{ vault://p/i/f}",
            "{{ vault://p/i/f} }",
        ] {
            assert_eq!(
                error(template).kind,
                TemplateErrorKind::NotClosed,
                "{template:?}"
            );
        }
    }

    #[test]
    fn a_bad_reference_inside_a_tag_is_rejected() {
        for template in [
            "{{ vault:// }}",
            "{{ vault://p }}",
            "{{ vault://p/i }}",
            "{{ vault://p/i/f/g }}",
            "{{ vault://p//f }}",
            "{{ vault://p/i/f$ }}",
        ] {
            let kind = error(template).kind;
            assert!(
                matches!(
                    kind,
                    TemplateErrorKind::BadReference(_) | TemplateErrorKind::NotClosed
                ),
                "{template:?}: {kind:?}"
            );
        }
    }

    #[test]
    fn the_first_bad_tag_is_the_one_reported() {
        let err = error("{{vault://a/b/c}} {{ vault://x }} {{ vault://y }}");
        assert_eq!((err.line, err.column), (1, 19));
    }

    #[test]
    fn a_missing_value_is_an_error_not_a_panic() {
        let parsed = Template::parse(b"{{vault://p/i/f}}").unwrap();
        let mut out = Vec::new();
        let err = parsed.render(&Resolved::new(), &mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn a_template_over_16_mib_is_rejected() {
        let ok = vec![b'x'; MAX_TEMPLATE_LEN];
        assert!(Template::parse(&ok).is_ok());
        let too_big = vec![b'x'; MAX_TEMPLATE_LEN + 1];
        assert_eq!(
            Template::parse(&too_big).unwrap_err().kind,
            TemplateErrorKind::TooLarge
        );
    }

    #[test]
    fn error_messages_never_repeat_template_text() {
        let secret = "fake-secret-value-9f3a";
        let template = format!("{secret} {{{{ vault://{secret} }}}}");
        let message = error(&template).to_string();
        assert!(!message.contains(secret), "{message}");
    }

    #[test]
    fn scanning_stays_fast_on_hostile_templates() {
        let started = std::time::Instant::now();
        for pattern in ["{{ ", "{{", "{", "{{ vault://a/b/c ", "{{\t{{\t"] {
            let mut template = pattern.repeat(1_000_000 / pattern.len()).into_bytes();
            let _ = Template::parse(&template);
            template.extend_from_slice(b"}}");
            let _ = Template::parse(&template);
        }
        assert!(started.elapsed().as_secs() < 20, "scanning is not linear");
    }

    proptest! {
        /// S10: no input panics, and what parses renders to exactly the
        /// input when every tag's value is the tag itself.
        #[test]
        fn parsing_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = Template::parse(&bytes);
        }

        #[test]
        fn parsing_never_panics_on_template_like_text(
            pieces in proptest::collection::vec(
                prop_oneof![
                    Just("{{".to_string()),
                    Just("}}".to_string()),
                    Just("{".to_string()),
                    Just(" ".to_string()),
                    Just("\t".to_string()),
                    Just("\n".to_string()),
                    Just("vault://".to_string()),
                    "[A-Za-z0-9._/-]{0,10}",
                    "[ -~]{0,5}",
                ],
                0..24,
            )
        ) {
            let text = pieces.concat();
            let _ = Template::parse(text.as_bytes());
        }

        #[test]
        fn a_template_renders_back_to_itself_when_values_equal_their_tags(
            pieces in proptest::collection::vec(
                prop_oneof![
                    Just("{{ vault://a/b/c }}".to_string()),
                    Just("{{vault://x/y/z}}".to_string()),
                    Just("{{ other }}".to_string()),
                    Just("{".to_string()),
                    "[ -~\n]{0,8}",
                ],
                0..16,
            )
        ) {
            let text = pieces.concat();
            let values = values(&[
                ("vault://a/b/c", "{{ vault://a/b/c }}"),
                ("vault://x/y/z", "{{vault://x/y/z}}"),
            ]);
            if let Ok(template) = Template::parse(text.as_bytes()) {
                let mut out = Vec::new();
                template.render(&values, &mut out).unwrap();
                // Tags are written with the spelling they had, so the output
                // equals the input.
                prop_assert_eq!(out, text.as_bytes());
            }
        }
    }
}
