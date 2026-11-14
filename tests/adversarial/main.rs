//! Crafted inputs and hostile conditions against the vault library
//! (`docs/design.md` §12.1). Each file in this directory is a module of this
//! one test binary.

#[path = "../common/mod.rs"]
mod common;

mod atomic_write;
mod concurrency;
mod kdf_bounds;
mod limits;
mod no_plaintext_in_vault;
mod permissions;
mod planted_socket;
mod secret_types;
mod versions;
