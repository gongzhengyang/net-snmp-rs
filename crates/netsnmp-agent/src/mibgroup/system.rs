//! mibII system group (`SNMPv2-MIB::system`), backed by real system data.
//!
//! Counterpart of `agent/mibgroup/mibII/system_mib.c` and `sysORTable.c`. The
//! dynamic objects (`sysDescr`, `sysUpTime`) are read live; the configurable
//! objects (`sysContact`, `sysName`, `sysLocation`) are writable scalars seeded
//! from the host where possible.

use crate::handler::MibHandler;
use crate::scalar::{FnHandler, ScalarHandler};
use netsnmp::oid::Oid;
use netsnmp::value::Value;
use std::sync::Arc;
use std::time::Instant;
use sysinfo::System;

/// `system` group root: `1.3.6.1.2.1.1`.
const SYSTEM: [u32; 7] = [1, 3, 6, 1, 2, 1, 1];

/// Net-SNMP's Linux agent identity, used for `sysObjectID`.
/// `netSnmpAgentOIDs.10` = `1.3.6.1.4.1.8072.3.2.10`.
const SYS_OBJECT_ID: [u32; 10] = [1, 3, 6, 1, 4, 1, 8072, 3, 2, 10];

/// Format a `uname -a`-style `sysDescr` string from its components.
pub fn format_sysdescr(
    ostype: &str,
    hostname: &str,
    osrelease: &str,
    version: &str,
    arch: &str,
) -> String {
    format!("{ostype} {hostname} {osrelease} {version} {arch}")
}

/// Build the `sysDescr` string from cross-platform [`sysinfo`] data.
pub fn system_description() -> String {
    let os = System::name().unwrap_or_else(|| "Unknown".to_string());
    let release = System::os_version()
        .or_else(System::kernel_version)
        .unwrap_or_else(|| "unknown".to_string());
    let version = System::long_os_version()
        .or_else(System::kernel_version)
        .unwrap_or_else(|| "unknown".to_string());
    format_sysdescr(
        &os,
        &host_name(),
        &release,
        &version,
        &System::cpu_arch(),
    )
}

/// The host name reported by the OS (used to seed `sysName`).
pub fn host_name() -> String {
    System::host_name().unwrap_or_else(|| "localhost".to_string())
}

/// Build all system-group handlers.
///
/// `contact` and `location` seed the writable `sysContact`/`sysLocation`
/// objects. `start` is the agent start instant used to compute `sysUpTime`.
pub fn system_handlers(contact: &str, location: &str, start: Instant) -> Vec<Arc<dyn MibHandler>> {
    system_handlers_with_persistables(contact, location, start).0
}

/// Like [`system_handlers`] but also returns the writable scalar handlers
/// (`sysContact`, `sysName`, `sysLocation`) so callers (e.g. `snmpd`) can wrap
/// them in a [`Persistable`](crate::Persistable) for state that survives
/// restarts. Returns `(all_handlers, writable_scalars)`.
pub fn system_handlers_with_persistables(
    contact: &str,
    location: &str,
    start: Instant,
) -> (Vec<Arc<dyn MibHandler>>, Vec<Arc<ScalarHandler>>) {
    let base = Oid::new(SYSTEM.to_vec());

    let sys_descr = Arc::new(FnHandler::scalar(base.child(1), || {
        Value::OctetString(system_description().into_bytes())
    }));
    let sys_object_id = Arc::new(ScalarHandler::new(
        base.child(2),
        Value::Oid(Oid::new(SYS_OBJECT_ID.to_vec())),
    ));
    let sys_uptime = Arc::new(FnHandler::scalar(base.child(3), move || {
        let centis = start.elapsed().as_millis() / 10;
        Value::TimeTicks(centis.min(u32::MAX as u128) as u32)
    }));
    let sys_contact = Arc::new(
        ScalarHandler::new(
            base.child(4),
            Value::OctetString(contact.as_bytes().to_vec()),
        )
        .writable(),
    );
    let sys_name = Arc::new(
        ScalarHandler::new(base.child(5), Value::OctetString(host_name().into_bytes())).writable(),
    );
    let sys_location = Arc::new(
        ScalarHandler::new(
            base.child(6),
            Value::OctetString(location.as_bytes().to_vec()),
        )
        .writable(),
    );
    // sysServices: physical(1)+datalink(2)+internet(4)+end-to-end(8)+app(64) = 72.
    let sys_services = Arc::new(ScalarHandler::new(base.child(7), Value::Integer(72)));

    let handlers: Vec<Arc<dyn MibHandler>> = vec![
        sys_descr,
        sys_object_id,
        sys_uptime,
        Arc::clone(&sys_contact) as Arc<dyn MibHandler>,
        Arc::clone(&sys_name) as Arc<dyn MibHandler>,
        Arc::clone(&sys_location) as Arc<dyn MibHandler>,
        sys_services,
    ];
    (handlers, vec![sys_contact, sys_name, sys_location])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_sysdescr() {
        let d = format_sysdescr("Linux", "box", "6.6.0", "#1 SMP", "x86_64");
        assert_eq!(d, "Linux box 6.6.0 #1 SMP x86_64");
    }

    #[test]
    fn registers_seven_objects() {
        let hs = system_handlers("admin <a@b.c>", "lab", Instant::now());
        assert_eq!(hs.len(), 7);
        // sysContact (.4) is writable.
        let contact = &hs[3];
        assert!(
            contact
                .set(
                    &"1.3.6.1.2.1.1.4.0".parse().unwrap(),
                    &Value::OctetString(b"new".to_vec())
                )
                .is_ok()
        );
    }
}
