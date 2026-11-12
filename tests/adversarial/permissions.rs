//! P2-10 and threat model C13 (D-041): the vault directory must be a real
//! directory owned by the user with no group or other access, and its vault
//! and lock files must be regular files with the same owner and no group or
//! other access. Every refusal says how to fix it.
//!
//! A directory or file owned by another user can't be made without root. The
//! decision itself is unit-tested with injected owners in `src/paths.rs`;
//! the tests here that use `sudo` run only when `VAULTLINE_CI_SUDO=1`, which
//! only CI sets (`docs/design.md` §12.2).

use std::fs::{self, Permissions};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use vaultline::paths::PathError;
use vaultline::vault::{Error, Vault};

use crate::common::{TestVault, mode, name, pass, value};

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
}

fn path_error(result: Result<Vault, Error>) -> PathError {
    match result {
        Err(Error::Path(e)) => e,
        Err(e) => panic!("expected a path error, got: {e}"),
        Ok(_) => panic!("expected a path error, but the vault opened"),
    }
}

#[test]
fn a_directory_open_to_group_or_others_is_refused() {
    let v = TestVault::new("fake-passphrase-dir-mode");
    for bad in [0o710, 0o750, 0o770, 0o701, 0o705, 0o777] {
        chmod(&v.dir, bad);
        let err = path_error(Vault::open(&v.dir, &v.passphrase()));
        assert!(
            matches!(err, PathError::Accessible { .. }),
            "{bad:o}: {err}"
        );
        assert!(err.to_string().contains("chmod 700"), "{err}");
        // An already-open vault checks again before every use.
        let set = v
            .vault
            .set(&name("p"), &name("i"), &name("f"), &value(b"fake-x"));
        assert!(
            matches!(set, Err(Error::Path(PathError::Accessible { .. }))),
            "{bad:o}"
        );
    }
    chmod(&v.dir, 0o700);
    assert!(Vault::open(&v.dir, &v.passphrase()).is_ok());
}

#[test]
fn a_symlinked_directory_is_refused() {
    let v = TestVault::new("fake-passphrase-dir-link");
    let link = v.tmp.path().join("link");
    symlink(&v.dir, &link).unwrap();
    let err = path_error(Vault::open(&link, &v.passphrase()));
    assert!(matches!(err, PathError::Symlink(_)), "{err}");
    let created = Vault::create(&link, &pass("fake-passphrase-new"), crate::common::CHEAP);
    assert!(matches!(created, Err(Error::Path(PathError::Symlink(_)))));
}

#[test]
fn a_file_where_the_directory_should_be_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let not_dir = tmp.path().join("vaultline");
    fs::write(&not_dir, b"not a directory").unwrap();
    chmod(&not_dir, 0o600);
    let err = path_error(Vault::open(&not_dir, &pass("fake-passphrase")));
    assert!(matches!(err, PathError::NotDirectory(_)), "{err}");
}

#[test]
fn a_vault_file_open_to_group_or_others_is_refused() {
    let v = TestVault::new("fake-passphrase-file-mode");
    let file = v.path();
    for bad in [0o640, 0o604, 0o644, 0o666] {
        chmod(&file, bad);
        let err = path_error(Vault::open(&v.dir, &v.passphrase()));
        assert!(
            matches!(err, PathError::Accessible { .. }),
            "{bad:o}: {err}"
        );
        assert!(err.to_string().contains("chmod 600"), "{err}");
    }
    chmod(&file, 0o600);
    assert!(Vault::open(&v.dir, &v.passphrase()).is_ok());
}

#[test]
fn a_vault_file_the_owner_cannot_open_is_explained() {
    // Mode 0044: the open fails with "permission denied", and the error says
    // why and how to fix it rather than only reporting the I/O error.
    let v = TestVault::new("fake-passphrase-unreadable");
    chmod(&v.path(), 0o044);
    let err = path_error(Vault::open(&v.dir, &v.passphrase()));
    chmod(&v.path(), 0o600);
    assert!(matches!(err, PathError::Accessible { .. }), "{err}");
    assert!(err.to_string().contains("chmod 600"), "{err}");
}

#[test]
fn a_symlinked_vault_file_is_refused() {
    let v = TestVault::new("fake-passphrase-file-link");
    let real = v.tmp.path().join("elsewhere");
    fs::rename(v.path(), &real).unwrap();
    symlink(&real, v.path()).unwrap();
    let err = path_error(Vault::open(&v.dir, &v.passphrase()));
    assert!(matches!(err, PathError::Symlink(_)), "{err}");
}

#[test]
fn a_lock_file_open_to_others_is_refused() {
    let v = TestVault::new("fake-passphrase-lock-mode");
    chmod(&v.dir.join("lock"), 0o644);
    let set = v
        .vault
        .set(&name("p"), &name("i"), &name("f"), &value(b"fake-x"));
    assert!(matches!(
        set,
        Err(Error::Path(PathError::Accessible { .. }))
    ));
}

#[test]
fn create_makes_a_private_directory_and_files() {
    let v = TestVault::new("fake-passphrase-create-modes");
    assert_eq!(mode(&v.dir), 0o700);
    assert_eq!(mode(&v.path()), 0o600);
    assert_eq!(mode(&v.dir.join("lock")), 0o600);
}

/// Gives `path` back to the test user when dropped, even if the test fails,
/// so the temporary directory can be cleaned up.
struct ChownBack(PathBuf);

impl Drop for ChownBack {
    fn drop(&mut self) {
        let me = nix::unistd::geteuid().as_raw().to_string();
        let _ = Command::new("sudo")
            .args(["-n", "chown", &me])
            .arg(&self.0)
            .status();
    }
}

fn sudo_chown_root(path: &Path) -> ChownBack {
    let status = Command::new("sudo")
        .args(["-n", "chown", "0"])
        .arg(path)
        .status()
        .expect("sudo should start");
    assert!(status.success(), "sudo chown failed");
    ChownBack(path.to_path_buf())
}

fn ci_sudo() -> bool {
    if std::env::var("VAULTLINE_CI_SUDO").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipped: needs VAULTLINE_CI_SUDO=1, which only CI sets");
    false
}

#[test]
fn a_directory_owned_by_another_user_is_refused() {
    if !ci_sudo() {
        return;
    }
    let v = TestVault::new("fake-passphrase-dir-owner");
    let _back = sudo_chown_root(&v.dir);
    let err = path_error(Vault::open(&v.dir, &v.passphrase()));
    assert!(
        matches!(err, PathError::WrongOwner { owner: 0, .. }),
        "{err}"
    );
    assert!(err.to_string().contains("chown"), "{err}");
}

#[test]
fn a_vault_file_owned_by_another_user_is_refused() {
    if !ci_sudo() {
        return;
    }
    let v = TestVault::new("fake-passphrase-file-owner");
    let _back = sudo_chown_root(&v.path());
    let err = path_error(Vault::open(&v.dir, &v.passphrase()));
    assert!(
        matches!(err, PathError::WrongOwner { owner: 0, .. }),
        "{err}"
    );
}
