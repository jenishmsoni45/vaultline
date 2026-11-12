//! End-to-end tests of the built `vaultline` binary (`docs/design.md` §12.1).
//! Each file in this directory is a module of this one test binary.

#[path = "../common/mod.rs"]
mod common;

mod hardening;
mod init;
mod inject;
mod list_rm;
mod makefile;
mod no_secret_in_argv;
mod output_refusal;
mod passwd_rotate;
mod run;
mod run_signals;
mod scaffold;
mod set_get;
mod workflows;
