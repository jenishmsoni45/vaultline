//! Writes the v1 known-answer fixtures in `tests/fixtures/v1/` from the blocks
//! in that directory's README.
//!
//! It ran once, in Phase 2. After the Phase 2 PR merges it must never run
//! again: the fixtures are frozen (`docs/vault-format.md` §6, rule 6). It
//! refuses to overwrite a fixture that already exists. It stays in the repo
//! so anyone can see exactly how the fixtures were made.
//!
//! ```text
//! cargo run --example generate_v1_fixtures
//! ```
//!
//! `default-params.vault` runs Argon2id at 256 MiB, a few times.

#[path = "../tests/common/fixture_readme.rs"]
mod fixture_readme;

use std::error::Error;
use std::fs;

use vaultline::secret::{Passphrase, SecretValue};
use vaultline::vault::{Name, Vault};

fn main() -> Result<(), Box<dyn Error>> {
    let dir = fixture_readme::fixtures_dir();
    let specs = fixture_readme::load();
    for spec in &specs {
        let target = dir.join(&spec.file);
        if target.exists() {
            return Err(format!(
                "{} already exists; v1 fixtures are never regenerated",
                target.display()
            )
            .into());
        }
    }
    for spec in &specs {
        let tmp = tempfile::tempdir()?;
        let vault_dir = tmp.path().join("vaultline");
        let passphrase = Passphrase::new(spec.passphrase.as_bytes());
        let vault = Vault::create(&vault_dir, &passphrase, spec.kdf)?;
        for field in &spec.fields {
            vault.set(
                &Name::new(&field.project)?,
                &Name::new(&field.item)?,
                &Name::new(&field.field)?,
                &SecretValue::new(&field.value.bytes()),
            )?;
        }
        fs::copy(vault_dir.join("vault"), dir.join(&spec.file))?;
        println!("wrote {} ({} fields)", spec.file, spec.fields.len());
    }
    Ok(())
}
