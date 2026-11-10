//! vaultline: an encrypted local vault that injects secrets into child
//! processes and templates without writing plaintext to disk.
//!
//! The design lives in `docs/`. Phase 1 is an empty skeleton: every module
//! below is a placeholder that a later phase fills in.

#![forbid(unsafe_code)]

#[cfg(not(unix))]
compile_error!("vaultline supports Unix only (macOS and Linux); Windows is not supported (D-021)");

pub mod agent;
pub mod audit;
pub mod hardening;
pub mod inject;
pub mod paths;
pub mod secret;
pub mod vault;
