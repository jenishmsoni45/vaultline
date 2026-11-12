//! Fuzzes the `vault://` reference parser with arbitrary bytes (S10, NFR-5,
//! `docs/design.md` §12.1).
//!
//! Besides "never panics", it checks that the grammar is canonical: whatever
//! parses prints back as exactly the bytes it was parsed from, and the
//! command-line form parses to the same reference.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultline::inject::reference::{Reference, escape};

fuzz_target!(|data: &[u8]| {
    if let Ok(reference) = Reference::parse(data) {
        assert_eq!(reference.to_string().as_bytes(), data);
        let text = std::str::from_utf8(data).expect("a reference is ASCII");
        assert_eq!(Reference::parse_cli(text), Ok(reference));
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = Reference::parse_cli(text);
    }
    // Error messages print untrusted bytes through `escape`: one line, short.
    let shown = escape(data);
    assert!(!shown.contains('\n') && shown.len() <= 83 + 3);
});
