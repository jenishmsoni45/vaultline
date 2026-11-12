//! vaultline: an encrypted local vault that injects secrets into child
//! processes and templates without writing plaintext to disk.
//!
//! The design lives in `docs/`. Phase 4 (the agent and the audit log) is the
//! only part still missing: `agent` and `audit` are placeholders.

#![forbid(unsafe_code)]

#[cfg(not(unix))]
compile_error!("vaultline supports Unix only (macOS and Linux); Windows is not supported (D-021)");

pub mod agent;
pub mod audit;
pub mod commands;
pub mod hardening;
pub mod inject;
pub mod input;
pub mod paths;
pub mod secret;
pub mod vault;
