//! Helpers shared by the integration test binaries. Every passphrase and
//! value is fake, and every vault lives in its own temporary directory
//! (`docs/design.md` §12.2).

#![allow(dead_code)]

pub mod cli;
pub mod fixture_readme;

use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};
use tempfile::TempDir;
use vaultline::secret::{Passphrase, SecretValue};
use vaultline::vault::{Error, KdfParams, Name, Vault};

/// The cheapest Argon2id parameters the parser accepts (D-001, D-020).
pub const CHEAP: KdfParams = KdfParams {
    m_kib: 8,
    t: 1,
    p: 1,
};

pub fn pass(s: &str) -> Passphrase {
    Passphrase::new(s.as_bytes())
}

pub fn name(s: &str) -> Name {
    Name::new(s).unwrap_or_else(|e| panic!("bad test name {s:?}: {e}"))
}

pub fn value(bytes: &[u8]) -> SecretValue {
    SecretValue::new(bytes)
}

/// `fake-<tag>-<16 random hex digits>`: a value that can't be in a vault file
/// by chance, and is obviously not a real secret.
pub fn marker(tag: &str) -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("fake-{tag}-{hex}")
}

/// Whether `needle` occurs in `haystack`.
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|w| w == needle)
}

/// The permission bits of a path, without following a final symlink.
pub fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .unwrap_or_else(|e| panic!("cannot stat {}: {e}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

/// The errors S2 allows: a format error or an authentication error. The
/// unlock error is the authentication error of the master-key wrap
/// (`docs/vault-format.md` §1).
pub fn is_format_or_auth(err: &Error) -> bool {
    matches!(err, Error::Format(_) | Error::Auth(_) | Error::Unlock)
}

/// A vault with cheap parameters in a fresh temporary directory.
pub struct TestVault {
    pub tmp: TempDir,
    pub dir: PathBuf,
    pub vault: Vault,
    pub passphrase: String,
}

impl TestVault {
    pub fn new(passphrase: &str) -> Self {
        let tmp = tempfile::tempdir().expect("a temporary directory");
        let dir = tmp.path().join("vaultline");
        let vault = Vault::create(&dir, &pass(passphrase), CHEAP).expect("a new vault");
        TestVault {
            tmp,
            dir,
            vault,
            passphrase: passphrase.to_string(),
        }
    }

    pub fn set(&self, project: &str, item: &str, field: &str, val: &[u8]) {
        self.vault
            .set(&name(project), &name(item), &name(field), &value(val))
            .expect("set");
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join("vault")
    }

    pub fn bytes(&self) -> Vec<u8> {
        fs::read(self.path()).expect("read the vault")
    }

    pub fn write_bytes(&self, bytes: &[u8]) {
        fs::write(self.path(), bytes).expect("write the vault");
    }

    pub fn passphrase(&self) -> Passphrase {
        pass(&self.passphrase)
    }
}

/// Puts `bytes` in a fresh vault directory (0700) as its vault file (0600).
pub fn install(bytes: &[u8]) -> (TempDir, PathBuf) {
    let tmp = tempfile::tempdir().expect("a temporary directory");
    let dir = tmp.path().join("vaultline");
    fs::create_dir(&dir).expect("create the vault directory");
    fs::set_permissions(&dir, Permissions::from_mode(0o700)).expect("chmod 700");
    let file = dir.join("vault");
    fs::write(&file, bytes).expect("write the vault");
    fs::set_permissions(&file, Permissions::from_mode(0o600)).expect("chmod 600");
    (tmp, dir)
}

/// The bytes of a v1 fixture.
pub fn fixture_bytes(file: &str) -> Vec<u8> {
    let path = fixture_readme::fixtures_dir().join(file);
    fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The passphrase of a v1 fixture, from its README.
pub fn fixture_passphrase(file: &str) -> Passphrase {
    let spec = fixture_readme::load()
        .into_iter()
        .find(|s| s.file == file)
        .unwrap_or_else(|| panic!("{file} is not in the fixture README"));
    pass(&spec.passphrase)
}
