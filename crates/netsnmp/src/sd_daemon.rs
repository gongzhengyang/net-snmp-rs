//! systemd socket-activation helpers (`sd-daemon.c` equivalent).
//!
//! When a service is started under systemd with `ListenDatagram=` (or via
//! `systemd-socket-activate -l`), systemd binds the listening socket(s) ahead of
//! time and passes them to the service as open file descriptors, starting at
//! [`SD_LISTEN_FDS_START`]. The count is carried in the `LISTEN_FDS` environment
//! variable and (to guard against accidental inheritance by a non-systemd
//! parent) gated by `LISTEN_PID`, which must equal the current process id.
//!
//! This module mirrors the env-parsing half of `sd_listen_fds(0)`: it reads
//! those two variables and tells the caller how many pre-bound sockets were
//! inherited. It deliberately performs **no** `unsafe` I/O: taking ownership of
//! the raw file descriptors via [`std::os::fd::FromRawFd::from_raw_fd`] is
//! `unsafe` (it lets a safe function close/arbitrarily own a kernel resource),
//! and the `netsnmp` crate is `#![forbid(unsafe_code)]`. Callers — typically the
//! `snmpd` binary in `netsnmp-apps`, which is **not** `forbid(unsafe_code)` —
//! perform that conversion themselves with the count reported here. See the
//! `--sd` flag in `snmpd`.
//!
//! Reference: `sd-daemon.c` (`sd_listen_fds`), `sd_listen_fds_with_names`.

/// The first file descriptor systemd passes to an activated service.
///
/// systemd pre-binds listening sockets and dup2's them onto the lowest
/// available descriptors starting at 3 (0/1/2 are stdin/stdout/stderr, which
/// it leaves alone). This constant matches `SD_LISTEN_FDS_START` in
/// `<systemd/sd-daemon.h>`.
pub const SD_LISTEN_FDS_START: std::os::fd::RawFd = 3;

/// Parse a `(LISTEN_FDS, LISTEN_PID)` pair against `pid` (the current process
/// id when called from [`listen_fds_env`]).
///
/// Returns `Some(count)` only when both values are present, `fds` parses as a
/// non-negative integer, `pid` parses as a `u32`, and `pid` equals the supplied
/// `expected` pid (so a set of inherited fds that were really meant for a
/// *parent* process is ignored — this is the race `LISTEN_PID` exists to close).
/// Returns `None` when the service was not socket-activated.
fn parse_listen_env(fds: Option<&str>, pid: Option<&str>, expected: u32) -> Option<usize> {
    let fds = fds?;
    let pid = pid?;
    let count: usize = fds.trim().parse().ok()?;
    let pid: u32 = pid.trim().parse().ok()?;
    if pid != expected {
        return None;
    }
    Some(count)
}

/// Parse the `LISTEN_FDS` / `LISTEN_PID` environment variables.
///
/// Returns `Some((count, pid))` only when both variables are present, the count
/// is a non-negative integer, and `LISTEN_PID` equals the current process id
/// (so a set of inherited fds that were really meant for a *parent* process is
/// ignored — this is the race `LISTEN_PID` exists to close). Returns `None`
/// when the service was not socket-activated.
///
/// This is the safe, side-effect-free counterpart of `sd_listen_fds(0)`: it
/// does **not** set `FD_CLOEXEC` on the descriptors (the caller is expected to
/// take ownership of them, which clears the systemd-inherited flag), and it
/// does not consume them.
pub fn listen_fds_env() -> Option<(usize, u32)> {
    let expected = std::process::id();
    let count = parse_listen_env(
        std::env::var("LISTEN_FDS").ok().as_deref(),
        std::env::var("LISTEN_PID").ok().as_deref(),
        expected,
    )?;
    Some((count, expected))
}

/// True when this process was launched under systemd socket activation.
///
/// Equivalent to `listen_fds_env().is_some()` with a non-zero count: both
/// `LISTEN_FDS` and `LISTEN_PID` are present, the pid matches, and at least one
/// file descriptor was passed.
pub fn socket_activated() -> bool {
    listen_fds_env()
        .map(|(count, _)| count > 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pure parsing logic is tested against injected values, avoiding any
    /// mutation of the real process environment (which is `unsafe` under the
    /// 2024 edition and forbidden by `#![forbid(unsafe_code)]`). The thin
    /// [`listen_fds_env`] wrapper is exercised by the `parse_listen_env` cases
    /// below covering every branch.
    #[test]
    fn none_when_unset() {
        let self_pid = std::process::id();
        assert_eq!(parse_listen_env(None, None, self_pid), None);
        assert_eq!(parse_listen_env(Some("1"), None, self_pid), None);
        assert_eq!(parse_listen_env(None, Some(&self_pid.to_string()), self_pid), None);
    }

    #[test]
    fn some_when_pid_matches() {
        let self_pid = std::process::id();
        let got = parse_listen_env(Some("1"), Some(&self_pid.to_string()), self_pid);
        assert_eq!(got, Some(1));
    }

    #[test]
    fn none_when_pid_mismatches() {
        let self_pid = std::process::id();
        // A pid that is almost certainly not us.
        let got = parse_listen_env(Some("2"), Some("4294967295"), self_pid);
        assert_eq!(got, None);
    }

    #[test]
    fn none_when_count_non_numeric() {
        let self_pid = std::process::id();
        let got = parse_listen_env(Some("soon"), Some(&self_pid.to_string()), self_pid);
        assert_eq!(got, None);
    }

    #[test]
    fn zero_count_parses() {
        let self_pid = std::process::id();
        let got = parse_listen_env(Some("0"), Some(&self_pid.to_string()), self_pid);
        assert_eq!(got, Some(0));
    }

    #[test]
    fn whitespace_tolerant() {
        // systemd-socket-activate emits the values without surrounding
        // whitespace, but be forgiving (matches sd_listen_fds).
        let self_pid = std::process::id();
        let got = parse_listen_env(Some(" 3 "), Some(&format!(" {} ", self_pid)), self_pid);
        assert_eq!(got, Some(3));
    }

    #[test]
    fn negative_count_rejected() {
        let self_pid = std::process::id();
        // `usize` parse rejects a leading '-': no negative counts.
        let got = parse_listen_env(Some("-1"), Some(&self_pid.to_string()), self_pid);
        assert_eq!(got, None);
    }
}
