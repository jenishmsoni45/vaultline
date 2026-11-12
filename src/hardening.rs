//! Process hardening (`docs/design.md` §10, D-017, NFR-7, C11).
//!
//! Every invocation of vaultline, the agent included, calls [`apply`] before
//! it does anything else:
//!
//! - the core-dump limit goes to 0, soft and hard, so a crash can't write a
//!   core file holding keys or secrets;
//! - on Linux the process becomes non-dumpable (`PR_SET_DUMPABLE`), which stops
//!   other processes of the same user from attaching with ptrace or reading
//!   `/proc/<pid>/mem` and `/proc/<pid>/environ`.
//!
//! Both settings change only vaultline's own processes, never a system
//! setting. A child started by `run` inherits the core-dump limit of 0; that is
//! intended, because the child holds secrets (`docs/design.md` §7).

use std::fmt;

use nix::sys::resource::{Resource, setrlimit};

/// A hardening step failed. vaultline stops rather than run without it.
#[derive(Debug)]
pub struct HardeningError {
    what: &'static str,
    source: nix::Error,
}

impl fmt::Display for HardeningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "couldn't {}: {}", self.what, self.source)
    }
}

impl std::error::Error for HardeningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Sets the core-dump limit to 0 and, on Linux, makes the process
/// non-dumpable.
pub fn apply() -> Result<(), HardeningError> {
    setrlimit(Resource::RLIMIT_CORE, 0, 0).map_err(|source| HardeningError {
        what: "turn off core dumps",
        source,
    })?;
    #[cfg(target_os = "linux")]
    nix::sys::prctl::set_dumpable(false).map_err(|source| HardeningError {
        what: "make the process non-dumpable",
        source,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::resource::getrlimit;

    #[test]
    fn apply_sets_the_core_limit_to_zero_and_can_be_repeated() {
        apply().unwrap();
        apply().unwrap();
        assert_eq!(getrlimit(Resource::RLIMIT_CORE).unwrap(), (0, 0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn apply_makes_the_process_non_dumpable_on_linux() {
        apply().unwrap();
        assert!(!nix::sys::prctl::get_dumpable().unwrap());
    }
}
