//! `snmptrapd` format-string expansion (`-F FORMAT`).
//!
//! Counterpart of the `snmptrapd` `-F` option: a `%`-escape format string that
//! controls how each received notification is rendered. Mirrors the upstream
//! `snmptrapd` format codes (a subset covering the common cases):
//!
//! | Specifier | Meaning                                             |
//! |-----------|-----------------------------------------------------|
//! | `%Y`      | 4-digit year                                        |
//! | `%m`      | 2-digit month (01-12)                               |
//! | `%d`      | 2-digit day of month (01-31)                        |
//! | `%H`      | 2-digit hour (00-23)                                |
//! | `%M`      | 2-digit minute (00-59)                              |
//! | `%S`      | 2-digit second (00-59)                              |
//! | `%t`      | numeric datetime (seconds since epoch)              |
//! | `%T`      | `sysUpTime` (the notification's own uptime value)   |
//! | `%W`      | peer hostname (the source `SocketAddr`)             |
//! | `%v`      | varbind list, each `name = value` joined by `, `    |
//! | `%N`      | trap name (symbolic, via `MibRegistry::format_oid`) |
//! | `%q`      | trap OID numeric (dotted)                           |
//! | `%%`      | literal `%`                                         |
//!
//! Unknown `%X` specifiers are emitted literally (the `%` and the `X`), so a
//! typo never silently drops output.

use std::net::SocketAddr;

use chrono::Local;
use netsnmp::mib::MibRegistry;
use netsnmp::trap::Notification;

use super::ReceivedNotification;

/// Expand a `snmptrapd`-style format string for one received notification.
///
/// `fmt` is the `-F` value; `notif` is the parsed notification; `mib` supplies
/// symbolic OID names; `peer` is the source transport address. The current
/// local wall-clock time is used for the date/time specifiers (`%Y` etc.).
pub fn format_notification(
    fmt: &str,
    notif: &ReceivedNotification,
    mib: &MibRegistry,
    peer: SocketAddr,
) -> String {
    let now = Local::now();
    let notification = &notif.notification;
    let mut out = String::with_capacity(fmt.len() + 32);
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        // We saw a `%`; the next char names the specifier.
        let Some(spec) = chars.next() else {
            // Trailing `%` with no following char: emit it literally.
            out.push('%');
            break;
        };
        match spec {
            'Y' => out.push_str(&now.format("%Y").to_string()),
            'm' => out.push_str(&now.format("%m").to_string()),
            'd' => out.push_str(&now.format("%d").to_string()),
            'H' => out.push_str(&now.format("%H").to_string()),
            'M' => out.push_str(&now.format("%M").to_string()),
            'S' => out.push_str(&now.format("%S").to_string()),
            't' => out.push_str(&now.timestamp().to_string()),
            'T' => out.push_str(&format_uptime(notification)),
            'W' => out.push_str(&peer.to_string()),
            'v' => out.push_str(&format_varbinds(mib, notification)),
            'N' => out.push_str(&mib.format_oid(&notification.trap_oid)),
            'q' => out.push_str(&notification.trap_oid.to_string()),
            '%' => out.push('%'),
            // Unknown specifier: emit the `%` and the char verbatim.
            other => {
                out.push('%');
                out.push(other);
            }
        }
    }
    out
}

/// Render the notification's `sysUpTime` as `Timeticks: (N)` (matching the
/// default `snmptrapd` `%T` output).
fn format_uptime(notification: &Notification) -> String {
    format!("Timeticks: ({})", notification.sys_uptime)
}

/// Render the notification's varbinds (excluding the two mandatory
/// `sysUpTime.0`/`snmpTrapOID.0` leading varbinds) as
/// `name = value` pairs joined by `, `.
fn format_varbinds(mib: &MibRegistry, notification: &Notification) -> String {
    notification
        .varbinds
        .iter()
        .map(|vb| format!("{} = {}", mib.format_oid(&vb.oid), vb.value))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use netsnmp::oid::Oid;
    use netsnmp::pdu::VarBind;
    use netsnmp::trap::Notification;
    use netsnmp::value::Value;
    use crate::trap::NotifyVersion;

    /// A synthetic notification for format-string testing.
    fn sample() -> ReceivedNotification {
        ReceivedNotification {
            version: NotifyVersion::Community,
            security_name: None,
            confirmed: false,
            notification: Notification {
                sys_uptime: 4242,
                trap_oid: "1.3.6.1.6.3.1.1.5.1".parse().unwrap(),
                varbinds: vec![VarBind::new(
                    "1.3.6.1.2.1.1.5.0".parse().unwrap(),
                    Value::OctetString(b"host-a".to_vec()),
                )],
            },
        }
    }

    fn mib() -> MibRegistry {
        MibRegistry::new()
    }

    fn peer() -> SocketAddr {
        "127.0.0.1:12345".parse().unwrap()
    }

    #[test]
    fn literal_percent() {
        let s = format_notification("100%% done", &sample(), &mib(), peer());
        assert_eq!(s, "100% done");
    }

    #[test]
    fn unknown_specifier_is_literal() {
        let s = format_notification("hello %Z world", &sample(), &mib(), peer());
        assert_eq!(s, "hello %Z world");
    }

    #[test]
    fn trap_oid_numeric() {
        let s = format_notification("trap=%q", &sample(), &mib(), peer());
        assert_eq!(s, "trap=.1.3.6.1.6.3.1.1.5.1");
    }

    #[test]
    fn trap_name_via_mib() {
        // With an empty MIB the name falls back to the numeric OID.
        let s = format_notification("name=%N", &sample(), &mib(), peer());
        assert_eq!(s, "name=.1.3.6.1.6.3.1.1.5.1");
    }

    #[test]
    fn uptime_specifier() {
        let s = format_notification("up=%T", &sample(), &mib(), peer());
        assert_eq!(s, "up=Timeticks: (4242)");
    }

    #[test]
    fn peer_hostname() {
        let s = format_notification("from=%W", &sample(), &mib(), peer());
        assert_eq!(s, "from=127.0.0.1:12345");
    }

    #[test]
    fn varbind_list() {
        let s = format_notification("vars=%v", &sample(), &mib(), peer());
        // Empty MIB -> numeric OID for the varbind name. The `=` is literal in
        // the format string; `%v` produces `name = value`.
        assert_eq!(s, "vars=.1.3.6.1.2.1.1.5.0 = STRING: host-a");
    }

    #[test]
    fn datetime_specifiers_are_numeric() {
        let s = format_notification("%Y-%m-%d %H:%M:%S", &sample(), &mib(), peer());
        // The exact value depends on the wall clock; assert the shape.
        let re = regex_lite(&s);
        assert!(re, "expected a `YYYY-MM-DD HH:MM:SS` shape, got {s:?}");
    }

    /// Cheap shape check without pulling in the `regex` crate: split on the
    /// literal separators and confirm each field is numeric.
    fn regex_lite(s: &str) -> bool {
        let parts: Vec<&str> = s.split(|c: char| c == '-' || c == ' ' || c == ':').collect();
        if parts.len() != 6 {
            return false;
        }
        parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    }

    #[test]
    fn epoch_datetime_specifier() {
        let s = format_notification("epoch=%t", &sample(), &mib(), peer());
        assert!(s.starts_with("epoch="));
        let n = &s["epoch=".len()..];
        assert!(!n.is_empty() && n.chars().all(|c| c.is_ascii_digit() || c == '-'));
    }

    #[test]
    fn combined_format() {
        let s = format_notification("%N: %v", &sample(), &mib(), peer());
        assert_eq!(s, ".1.3.6.1.6.3.1.1.5.1: .1.3.6.1.2.1.1.5.0 = STRING: host-a");
    }

    #[test]
    fn empty_varbind_list() {
        let mut n = sample();
        n.notification.varbinds.clear();
        let s = format_notification("vars=%v", &n, &mib(), peer());
        assert_eq!(s, "vars=");
    }

    #[test]
    fn trap_oid_with_extra_varbinds() {
        let n = ReceivedNotification {
            version: NotifyVersion::Community,
            security_name: None,
            confirmed: false,
            notification: Notification {
                sys_uptime: 0,
                trap_oid: Oid::new(netsnmp::trap::SNMP_TRAPS_OID.to_vec()),
                varbinds: vec![
                    VarBind::new(
                        "1.3.6.1.2.1.1.5.0".parse().unwrap(),
                        Value::OctetString(b"a".to_vec()),
                    ),
                    VarBind::new(
                        "1.3.6.1.2.1.1.6.0".parse().unwrap(),
                        Value::OctetString(b"b".to_vec()),
                    ),
                ],
            },
        };
        let s = format_notification("%v", &n, &mib(), peer());
        assert!(s.contains("STRING: a"));
        assert!(s.contains("STRING: b"));
        assert!(s.contains(", "));
    }
}
