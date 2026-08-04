//! NET-SNMP-MIB agent-version scalars.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/agent/nsDebug.c` /
//! `agent/mibgroup/mibII/vacm_context.c` version-info objects that live at the
//! top of the `1.3.6.1.4.1.8072` enterprise tree. This module exposes the
//! agent's version string as a walkable scalar, complementing the
//! NET-SNMP-AGENT-MIB self-management objects in [`super::netsnmp_agent`].
//!
//! | Object            | OID                  | Source               |
//! |-------------------|----------------------|----------------------|
//! | `nsVersionString.0` | `8072.1.0.1.0`     | crate version macro |
//! | `nsCacheEnabled.0`  | `8072.1.6.1.0`     | (served by nsCache) |
//!
//! Only `nsVersionString.0` is owned here; the `nsCache*` objects that share
//! the `8072.1` subtree are served by [`super::netsnmp_agent`].

use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;

/// The version string reported by `nsVersionString.0`. Compiled in from the
/// crate's Cargo package version so it tracks the release automatically.
fn version_string() -> String {
    format!("net-snmp-rs {}", env!("CARGO_PKG_VERSION"))
}

/// Build the NET-SNMP-MIB version-info handlers.
///
/// Currently exposes a single scalar, `nsVersionString.0`
/// (`1.3.6.1.4.1.8072.1.0.1.0`), reporting `"net-snmp-rs <version>"`. This is
/// the agent's analogue of the `NET-SNMP-MIB::nsVersionString` object that
/// `snmpd` advertises so a manager can identify the implementation and version.
pub fn netsnmp_system_handlers() -> Vec<Arc<dyn MibHandler>> {
    vec![Arc::new(FnHandler::scalar(
        // 1.3.6.1.4.1.8072.1.0.1 — nsVersionString node; instance .0.
        Oid::new([1, 3, 6, 1, 4, 1, 8072, 1, 0, 1].to_vec()),
        || Value::OctetString(version_string().into_bytes()),
    ))]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_scalar_reports_crate_version() {
        let handlers = netsnmp_system_handlers();
        assert_eq!(handlers.len(), 1);
        let h = &handlers[0];
        let inst: Oid = "1.3.6.1.4.1.8072.1.0.1.0".parse().unwrap();
        let v = h.get(&inst).expect("version value");
        let expected = format!("net-snmp-rs {}", env!("CARGO_PKG_VERSION"));
        assert_eq!(v, Value::OctetString(expected.into_bytes()));
    }

    #[test]
    fn version_scalar_getnext_lands_on_instance() {
        let handlers = netsnmp_system_handlers();
        let h = &handlers[0];
        let root: Oid = "1.3.6.1.4.1.8072.1.0.1".parse().unwrap();
        let r = h.get_next(&root).expect("successor");
        let inst: Oid = "1.3.6.1.4.1.8072.1.0.1.0".parse().unwrap();
        assert_eq!(r.oid, inst);
    }
}
