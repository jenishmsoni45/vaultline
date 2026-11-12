//! Invariants S1–S7 (`docs/design.md` §2). S1–S5 are proven against the vault
//! library, S6 and S7 through the built binary and the masker. Each file in
//! this directory is a module of this one test binary; later phases add
//! S8–S10.

#[path = "../common/mod.rs"]
mod common;

mod s1_roundtrip;
mod s2_tamper;
mod s3_swap;
mod s4_wrong_passphrase;
mod s5_fixtures;
mod s6_no_plaintext_on_disk;
mod s7_masking;
