//! Placeholder target. It proves that cargo-fuzz and the nightly toolchain work
//! in CI (P1-7 in `docs/phases.md`). Phase 2 removes it.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Touches the input so the harness has something to run; checks nothing.
    let _ = data.len();
});
