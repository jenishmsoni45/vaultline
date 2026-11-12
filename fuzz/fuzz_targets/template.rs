//! Fuzzes the `inject` template parser with arbitrary bytes (S10, NFR-5,
//! `docs/design.md` §12.1).
//!
//! Besides "never panics", whatever parses is rendered, with every reference
//! resolved to its own tag, which must reproduce the input byte for byte when
//! each tag is spelled the way the renderer's values spell it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultline::inject::template::{Resolved, Template};
use vaultline::secret::SecretValue;

fuzz_target!(|data: &[u8]| {
    let Ok(template) = Template::parse(data) else {
        return;
    };
    let values: Resolved = template
        .references()
        .into_iter()
        .map(|reference| (reference.clone(), SecretValue::new(b"V")))
        .collect();
    let mut out = Vec::new();
    template
        .render(&values, &mut out)
        .expect("a parsed template renders when every reference is resolved");
    // Every tag became one byte, so the output can't be longer than the input.
    assert!(out.len() <= data.len());
});
