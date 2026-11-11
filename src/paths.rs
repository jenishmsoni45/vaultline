//! Where the vault directory is, and the checks that keep it private
//! (`docs/architecture.md` §7, D-025, D-027, D-041).
//!
//! The directory must not be a symlink, must be owned by the effective UID,
//! and must give group and others no access. Files inside it must be regular
//! files (not symlinks) with the same owner and no group or other access.
//! Every refusal says how to fix it.

use std::ffi::OsString;
use std::fmt;
use std::fs::{self, DirBuilder, Metadata, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Environment variable that points vaultline at another directory. It holds
/// a path, never a secret.
pub const DIR_ENV: &str = "VAULTLINE_DIR";
/// Directory name under `$HOME` when `VAULTLINE_DIR` isn't set.
pub const DEFAULT_DIR_NAME: &str = ".vaultline";
/// Mode of the vault directory.
pub const DIR_MODE: u32 = 0o700;
/// Mode of every file vaultline creates.
pub const FILE_MODE: u32 = 0o600;

/// Why a path can't be used. The messages name the path and the fix, and
/// never contain a secret.
#[derive(Debug)]
pub enum PathError {
    /// Neither `VAULTLINE_DIR` nor `HOME` is set.
    NoHome,
    /// `VAULTLINE_DIR` is set to the empty string.
    EmptyDirVar,
    /// The path is a symlink.
    Symlink(PathBuf),
    /// The vault directory path exists but is not a directory.
    NotDirectory(PathBuf),
    /// A vault file path exists but is not a regular file.
    NotRegularFile(PathBuf),
    /// The path is owned by another user.
    WrongOwner {
        path: PathBuf,
        owner: u32,
        euid: u32,
    },
    /// Group or others have some access to the path.
    Accessible {
        path: PathBuf,
        mode: u32,
        wanted: u32,
    },
    /// The path couldn't be inspected or created.
    Io { path: PathBuf, source: io::Error },
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathError::NoHome => write!(
                f,
                "HOME is not set, so the vault directory can't be found; set HOME or {DIR_ENV}"
            ),
            PathError::EmptyDirVar => {
                write!(
                    f,
                    "{DIR_ENV} is set but empty; unset it or give it a directory"
                )
            }
            PathError::Symlink(path) => write!(
                f,
                "{} is a symlink; vaultline only uses a real directory and real files \
                 (point {DIR_ENV} at the target instead)",
                path.display()
            ),
            PathError::NotDirectory(path) => write!(f, "{} is not a directory", path.display()),
            PathError::NotRegularFile(path) => {
                write!(f, "{} is not a regular file", path.display())
            }
            PathError::WrongOwner { path, owner, euid } => write!(
                f,
                "{} is owned by uid {owner}, not by you (uid {euid}); fix it with: chown {euid} {:?}",
                path.display(),
                path
            ),
            PathError::Accessible { path, mode, wanted } => write!(
                f,
                "{} is accessible by group or others (mode {mode:03o}); fix it with: chmod {wanted:o} {:?}",
                path.display(),
                path
            ),
            PathError::Io { path, source } => write!(f, "can't use {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for PathError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PathError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// The vault directory: `$VAULTLINE_DIR`, or `$HOME/.vaultline` (D-025).
pub fn vault_dir() -> Result<PathBuf, PathError> {
    resolve_vault_dir(std::env::var_os(DIR_ENV), std::env::var_os("HOME"))
}

/// [`vault_dir`] with the environment passed in, so it can be tested without
/// changing the process environment.
pub fn resolve_vault_dir(
    dir_var: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf, PathError> {
    match dir_var {
        Some(dir) if dir.is_empty() => Err(PathError::EmptyDirVar),
        Some(dir) => Ok(PathBuf::from(dir)),
        None => match home {
            Some(home) if !home.is_empty() => Ok(PathBuf::from(home).join(DEFAULT_DIR_NAME)),
            _ => Err(PathError::NoHome),
        },
    }
}

/// What the checks look at, separated out so the decision can be tested with
/// any owner, including ones a test can't create.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Facts {
    pub(crate) is_symlink: bool,
    pub(crate) is_dir: bool,
    pub(crate) is_file: bool,
    pub(crate) uid: u32,
    pub(crate) mode: u32,
}

impl Facts {
    fn of(meta: &Metadata) -> Self {
        let kind = meta.file_type();
        Facts {
            is_symlink: kind.is_symlink(),
            is_dir: kind.is_dir(),
            is_file: kind.is_file(),
            uid: meta.uid(),
            mode: meta.mode() & 0o7777,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Dir,
    File,
}

/// The decision itself: symlink, type, owner, then group and other access.
pub(crate) fn judge(path: &Path, facts: Facts, kind: Kind, euid: u32) -> Result<(), PathError> {
    if facts.is_symlink {
        return Err(PathError::Symlink(path.to_path_buf()));
    }
    match kind {
        Kind::Dir if !facts.is_dir => return Err(PathError::NotDirectory(path.to_path_buf())),
        Kind::File if !facts.is_file => {
            return Err(PathError::NotRegularFile(path.to_path_buf()));
        }
        _ => {}
    }
    if facts.uid != euid {
        return Err(PathError::WrongOwner {
            path: path.to_path_buf(),
            owner: facts.uid,
            euid,
        });
    }
    if facts.mode & 0o077 != 0 {
        return Err(PathError::Accessible {
            path: path.to_path_buf(),
            mode: facts.mode,
            wanted: if kind == Kind::Dir {
                DIR_MODE
            } else {
                FILE_MODE
            },
        });
    }
    Ok(())
}

fn euid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

fn io_error(path: &Path, source: io::Error) -> PathError {
    PathError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Checks the vault directory with `lstat`, so a symlink is seen as one.
/// A missing directory is reported as `PathError::Io` with `NotFound`.
pub fn check_dir(path: &Path) -> Result<(), PathError> {
    let meta = fs::symlink_metadata(path).map_err(|e| io_error(path, e))?;
    judge(path, Facts::of(&meta), Kind::Dir, euid())
}

/// Checks an already opened file through its own descriptor (`fstat`), so
/// the check applies to exactly the file that will be read or locked.
pub fn check_file(path: &Path, meta: &Metadata) -> Result<(), PathError> {
    judge(path, Facts::of(meta), Kind::File, euid())
}

/// Creates the vault directory with mode 0700 if it is missing, then checks
/// it. Parent directories are not created.
pub fn ensure_dir(path: &Path) -> Result<(), PathError> {
    match fs::symlink_metadata(path) {
        Ok(_) => return check_dir(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_error(path, e)),
    }
    DirBuilder::new()
        .mode(DIR_MODE)
        .create(path)
        .map_err(|e| io_error(path, e))?;
    // The umask can only remove bits; set the mode exactly anyway.
    fs::set_permissions(path, Permissions::from_mode(DIR_MODE)).map_err(|e| io_error(path, e))?;
    check_dir(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: u32 = 501;

    fn dir(mode: u32) -> Facts {
        Facts {
            is_symlink: false,
            is_dir: true,
            is_file: false,
            uid: ME,
            mode,
        }
    }

    fn file(mode: u32) -> Facts {
        Facts {
            is_dir: false,
            is_file: true,
            ..dir(mode)
        }
    }

    fn judge_dir(facts: Facts) -> Result<(), PathError> {
        judge(Path::new("/x/vault dir"), facts, Kind::Dir, ME)
    }

    #[test]
    fn a_private_directory_owned_by_the_user_passes() {
        assert!(judge_dir(dir(0o700)).is_ok());
        assert!(judge_dir(dir(0o500)).is_ok());
    }

    #[test]
    fn group_or_other_access_is_refused_with_a_chmod_hint() {
        for mode in [
            0o710, 0o750, 0o770, 0o701, 0o705, 0o707, 0o777, 0o740, 0o704,
        ] {
            let err = judge_dir(dir(mode)).unwrap_err();
            assert!(matches!(err, PathError::Accessible { .. }), "{mode:o}");
            let msg = err.to_string();
            assert!(msg.contains("chmod 700 \"/x/vault dir\""), "{msg}");
            assert!(msg.contains(&format!("{mode:03o}")), "{msg}");
        }
    }

    #[test]
    fn another_owner_is_refused_with_a_chown_hint() {
        for owner in [0, 502, u32::MAX] {
            let err = judge_dir(Facts {
                uid: owner,
                ..dir(0o700)
            })
            .unwrap_err();
            let msg = err.to_string();
            assert!(matches!(err, PathError::WrongOwner { .. }));
            assert!(
                msg.contains(&format!("chown {ME} \"/x/vault dir\"")),
                "{msg}"
            );
        }
    }

    #[test]
    fn symlinks_and_wrong_types_are_refused() {
        let link = Facts {
            is_symlink: true,
            is_dir: false,
            ..dir(0o700)
        };
        assert!(matches!(judge_dir(link), Err(PathError::Symlink(_))));
        assert!(matches!(
            judge_dir(file(0o700)),
            Err(PathError::NotDirectory(_))
        ));
        let as_file = judge(Path::new("/x/vault"), dir(0o700), Kind::File, ME);
        assert!(matches!(as_file, Err(PathError::NotRegularFile(_))));
    }

    #[test]
    fn files_must_be_private_too() {
        let check = |facts| judge(Path::new("/x/vault"), facts, Kind::File, ME);
        assert!(check(file(0o600)).is_ok());
        assert!(check(file(0o400)).is_ok());
        let err = check(file(0o644)).unwrap_err();
        assert!(err.to_string().contains("chmod 600 \"/x/vault\""), "{err}");
        assert!(matches!(
            check(Facts {
                uid: 0,
                ..file(0o600)
            }),
            Err(PathError::WrongOwner { .. })
        ));
    }

    #[test]
    fn the_directory_comes_from_vaultline_dir_or_home() {
        let custom = resolve_vault_dir(Some("/tmp/v".into()), Some("/home/u".into())).unwrap();
        assert_eq!(custom, PathBuf::from("/tmp/v"));
        let default = resolve_vault_dir(None, Some("/home/u".into())).unwrap();
        assert_eq!(default, PathBuf::from("/home/u/.vaultline"));
        assert!(matches!(
            resolve_vault_dir(Some("".into()), Some("/home/u".into())),
            Err(PathError::EmptyDirVar)
        ));
        assert!(matches!(
            resolve_vault_dir(None, None),
            Err(PathError::NoHome)
        ));
        assert!(matches!(
            resolve_vault_dir(None, Some("".into())),
            Err(PathError::NoHome)
        ));
    }
}
