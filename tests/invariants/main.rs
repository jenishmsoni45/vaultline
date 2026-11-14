//! Invariants S1–S9 (`docs/design.md` §2). S1–S5 and S8 are proven against the
//! vault and audit libraries, S6, S7 and S9 through the built binary. Each file in
//! this directory is a module of this one test binary. Phase 4 adds S8 (the
//! audit log) and S9 (the agent).

#[path = "../common/mod.rs"]
mod common;

mod s1_roundtrip;
mod s2_tamper;
mod s3_swap;
mod s4_wrong_passphrase;
mod s5_fixtures;
mod s6_no_plaintext_on_disk;
mod s7_masking;
mod s8_audit_tamper;
mod s9_agent;
