//! The optional agent: protocol, server and client (`docs/design.md` §8,
//! `docs/architecture.md` §4, D-012, D-013, D-014, D-037, D-049, D-050).
//!
//! The agent is the same binary running `agent serve`. It holds the master key
//! of one vault, and answers one request per connection on a Unix socket in
//! the vault directory. Both ends check the other's user ID before they send
//! or read a byte.

use std::io;
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub mod client;
pub mod protocol;
pub mod server;

/// The agent's socket, inside the vault directory.
pub const SOCKET_FILE: &str = "agent.sock";
/// The idle timeout when `--idle-timeout` isn't given (D-013).
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// The shortest `--idle-timeout`.
pub const MIN_IDLE_TIMEOUT: Duration = Duration::from_secs(1);
/// The longest `--idle-timeout`.
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
/// How long a connection may take to send its request before the agent closes
/// it (design §8).
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// The longest path `sun_path` can hold, without its terminating NUL byte:
/// 104 bytes on macOS and 108 on Linux, each including the NUL.
#[cfg(target_os = "macos")]
pub const MAX_SOCKET_PATH: usize = 103;
#[cfg(not(target_os = "macos"))]
pub const MAX_SOCKET_PATH: usize = 107;

/// Why an idle timeout was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleError {
    /// Not `<n>s`, `<n>m` or `<n>h`.
    Format,
    /// Under 1 second or over 24 hours.
    Range,
}

impl std::fmt::Display for IdleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdleError::Format => f.write_str(
                "an idle timeout is a whole number followed by s, m or h, such as 30s, 15m or 2h",
            ),
            IdleError::Range => {
                f.write_str("an idle timeout can be from 1 second (1s) to 24 hours (24h)")
            }
        }
    }
}

impl std::error::Error for IdleError {}

/// Parses `<n>s`, `<n>m` or `<n>h`, from 1 second to 24 hours (design §4).
pub fn parse_idle_timeout(text: &str) -> Result<Duration, IdleError> {
    let unit = match text.chars().last() {
        Some('s') => 1u64,
        Some('m') => 60,
        Some('h') => 3600,
        _ => return Err(IdleError::Format),
    };
    let digits = text.get(..text.len().saturating_sub(1)).unwrap_or("");
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(IdleError::Format);
    }
    // A number too big for a u64 is certainly out of range.
    let count: u64 = digits.parse().map_err(|_| IdleError::Range)?;
    let seconds = count.checked_mul(unit).ok_or(IdleError::Range)?;
    let timeout = Duration::from_secs(seconds);
    if timeout < MIN_IDLE_TIMEOUT || timeout > MAX_IDLE_TIMEOUT {
        return Err(IdleError::Range);
    }
    Ok(timeout)
}

/// The decision of the peer check (S9): a caller is served only if it runs as
/// the same effective user as the agent. Root is another user, and gets no
/// exception.
pub fn peer_allowed(peer_uid: u32, own_euid: u32) -> bool {
    peer_uid == own_euid
}

/// The user ID of the process at the other end of a connected Unix socket:
/// `SO_PEERCRED` on Linux and `getpeereid` on macOS, both through `nix`.
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
        let credentials = getsockopt(stream, PeerCredentials).map_err(io::Error::from)?;
        Ok(credentials.uid())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (uid, _gid) = nix::unistd::getpeereid(stream).map_err(io::Error::from)?;
        Ok(uid.as_raw())
    }
}

/// Fails with a clear error if a socket in `path` couldn't be bound because
/// the path is longer than the platform allows.
pub fn check_socket_path(path: &std::path::Path) -> Result<(), usize> {
    use std::os::unix::ffi::OsStrExt;
    let len = path.as_os_str().as_bytes().len();
    if len > MAX_SOCKET_PATH {
        Err(len)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_timeouts_parse_in_seconds_minutes_and_hours() {
        assert_eq!(parse_idle_timeout("1s"), Ok(Duration::from_secs(1)));
        assert_eq!(parse_idle_timeout("2s"), Ok(Duration::from_secs(2)));
        assert_eq!(parse_idle_timeout("90s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_idle_timeout("15m"), Ok(Duration::from_secs(900)));
        assert_eq!(parse_idle_timeout("24h"), Ok(Duration::from_secs(86_400)));
        assert_eq!(parse_idle_timeout("1440m"), Ok(Duration::from_secs(86_400)));
        assert_eq!(
            parse_idle_timeout("86400s"),
            Ok(Duration::from_secs(86_400))
        );
    }

    #[test]
    fn idle_timeouts_outside_one_second_to_24_hours_are_refused() {
        for text in [
            "0s",
            "0m",
            "0h",
            "25h",
            "1441m",
            "86401s",
            "99999999999999999999h",
        ] {
            assert_eq!(parse_idle_timeout(text), Err(IdleError::Range), "{text}");
        }
    }

    #[test]
    fn anything_that_is_not_a_number_and_a_unit_is_refused() {
        for text in [
            "", "s", "m", "15", "1.5h", "-1s", "+1s", " 1s", "1s ", "1 s", "1d", "1S", "١s", "1ms",
            "0x10s",
        ] {
            assert_eq!(parse_idle_timeout(text), Err(IdleError::Format), "{text:?}");
        }
    }

    /// The peer decision (S9), with injected user IDs.
    #[test]
    fn only_the_same_user_is_served_and_root_gets_no_exception() {
        assert!(peer_allowed(501, 501));
        assert!(peer_allowed(0, 0));
        assert!(!peer_allowed(0, 501), "root is another user");
        assert!(!peer_allowed(502, 501));
        assert!(!peer_allowed(501, 0));
        assert!(!peer_allowed(u32::MAX, 0));
    }

    #[test]
    fn the_peer_of_a_socket_pair_is_this_process() {
        let (one, two) = UnixStream::pair().unwrap();
        let me = nix::unistd::geteuid().as_raw();
        assert_eq!(peer_uid(&one).unwrap(), me);
        assert_eq!(peer_uid(&two).unwrap(), me);
    }

    #[test]
    fn a_path_over_the_socket_limit_is_caught() {
        let ok = std::path::PathBuf::from(format!("/{}", "a".repeat(MAX_SOCKET_PATH - 1)));
        assert_eq!(check_socket_path(&ok), Ok(()));
        let long = std::path::PathBuf::from(format!("/{}", "a".repeat(MAX_SOCKET_PATH)));
        assert_eq!(check_socket_path(&long), Err(MAX_SOCKET_PATH + 1));
    }
}
