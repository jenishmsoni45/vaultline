//! Reads the fixture blocks in `tests/fixtures/v1/README.md`.
//!
//! The tests and `examples/generate_v1_fixtures.rs` both use this, so the
//! README is the only place the fixture contents are defined. The format is
//! described in the README itself. This is test code: a malformed README
//! panics with a message saying what is wrong.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use vaultline::vault::KdfParams;

/// One fixture block.
pub struct FixtureSpec {
    pub file: String,
    pub passphrase: String,
    pub kdf: KdfParams,
    pub fields: Vec<FieldSpec>,
}

/// One `vault://project/item/field = value` line.
pub struct FieldSpec {
    pub project: String,
    pub item: String,
    pub field: String,
    pub value: ValueSpec,
}

/// How a value is written in the README.
pub enum ValueSpec {
    /// `"<text>"`
    Text(String),
    /// `repeat("<pattern>", <n>)`
    Repeat(String, usize),
    /// `bytes(0..256)`
    ByteRamp,
}

impl ValueSpec {
    /// The value's bytes.
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            ValueSpec::Text(text) => text.as_bytes().to_vec(),
            ValueSpec::Repeat(pattern, len) => pattern.bytes().cycle().take(*len).collect(),
            ValueSpec::ByteRamp => (0..=255u8).collect(),
        }
    }

    /// Whether the value is obviously fake: empty, labelled `fake`, or the
    /// byte ramp, which is not a secret of any kind.
    pub fn is_obviously_fake(&self) -> bool {
        match self {
            ValueSpec::Text(text) => text.is_empty() || text.contains("fake"),
            ValueSpec::Repeat(pattern, _) => pattern.contains("fake"),
            ValueSpec::ByteRamp => true,
        }
    }
}

impl FieldSpec {
    /// `project/item/field`.
    pub fn reference(&self) -> String {
        format!("{}/{}/{}", self.project, self.item, self.field)
    }
}

/// The directory that holds the v1 fixtures and their README.
pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1")
}

/// Every fixture block in the README, in order.
pub fn load() -> Vec<FixtureSpec> {
    let path = fixtures_dir().join("README.md");
    let readme =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    parse(&readme)
}

/// Parses every ```` ```text ```` block.
pub fn parse(readme: &str) -> Vec<FixtureSpec> {
    let mut specs = Vec::new();
    let mut block: Option<Vec<&str>> = None;
    for line in readme.lines() {
        match (&mut block, line.trim()) {
            (None, "```text") => block = Some(Vec::new()),
            (Some(lines), "```") => {
                specs.push(parse_block(lines));
                block = None;
            }
            (Some(lines), _) => lines.push(line),
            (None, _) => {}
        }
    }
    assert!(block.is_none(), "README: unterminated ```text block");
    assert!(!specs.is_empty(), "README: no fixture blocks found");
    specs
}

fn parse_block(lines: &[&str]) -> FixtureSpec {
    let mut file = None;
    let mut passphrase = None;
    let mut kdf = None;
    let mut fields = Vec::new();
    for line in lines {
        if let Some(rest) = line.strip_prefix("fixture: ") {
            file = Some(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("passphrase: ") {
            passphrase = Some(quoted(rest, line));
        } else if let Some(rest) = line.strip_prefix("kdf: ") {
            kdf = Some(parse_kdf(rest, line));
        } else if let Some(rest) = line.strip_prefix("vault://") {
            fields.push(parse_field(rest, line));
        } else {
            panic!("README: unexpected line in a fixture block: {line:?}");
        }
    }
    FixtureSpec {
        file: file.expect("README: a block has no `fixture:` line"),
        passphrase: passphrase.expect("README: a block has no `passphrase:` line"),
        kdf: kdf.expect("README: a block has no `kdf:` line"),
        fields,
    }
}

fn quoted(text: &str, line: &str) -> String {
    let inner = text
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .unwrap_or_else(|| panic!("README: expected a quoted string in {line:?}"));
    assert!(
        !inner.contains(['"', '\\']),
        "README: quoted strings can't contain quotes or backslashes: {line:?}"
    );
    inner.to_string()
}

fn parse_kdf(text: &str, line: &str) -> KdfParams {
    let mut m = None;
    let mut t = None;
    let mut p = None;
    for part in text.split_whitespace() {
        let (key, value) = part
            .split_once('=')
            .unwrap_or_else(|| panic!("README: bad kdf part in {line:?}"));
        let value: u32 = value
            .parse()
            .unwrap_or_else(|_| panic!("README: bad kdf number in {line:?}"));
        match key {
            "m" => m = Some(value),
            "t" => t = Some(value),
            "p" => p = Some(value),
            _ => panic!("README: unknown kdf key in {line:?}"),
        }
    }
    KdfParams {
        m_kib: m.expect("README: kdf has no m"),
        t: t.expect("README: kdf has no t"),
        p: p.expect("README: kdf has no p"),
    }
}

fn parse_field(text: &str, line: &str) -> FieldSpec {
    let (reference, value) = text
        .split_once(" = ")
        .unwrap_or_else(|| panic!("README: expected `vault://p/i/f = value` in {line:?}"));
    let parts: Vec<&str> = reference.split('/').collect();
    let [project, item, field] = parts.as_slice() else {
        panic!("README: a reference needs exactly three names: {line:?}");
    };
    let value = if value == "bytes(0..256)" {
        ValueSpec::ByteRamp
    } else if let Some(args) = value
        .strip_prefix("repeat(")
        .and_then(|v| v.strip_suffix(')'))
    {
        let (pattern, len) = args
            .rsplit_once(", ")
            .unwrap_or_else(|| panic!("README: expected repeat(\"p\", n) in {line:?}"));
        let len = len
            .parse()
            .unwrap_or_else(|_| panic!("README: bad repeat length in {line:?}"));
        ValueSpec::Repeat(quoted(pattern, line), len)
    } else {
        ValueSpec::Text(quoted(value, line))
    };
    FieldSpec {
        project: project.to_string(),
        item: item.to_string(),
        field: field.to_string(),
        value,
    }
}
