//! Invariants S1–S5 (`docs/design.md` §2), proven against the vault library.
//! Each file in this directory is a module of this one test binary; later
//! phases add S6–S10.

#[path = "../common/mod.rs"]
mod common;

mod s1_roundtrip;
mod s2_tamper;
mod s3_swap;
mod s4_wrong_passphrase;
mod s5_fixtures;
