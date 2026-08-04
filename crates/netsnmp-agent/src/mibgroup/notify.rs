//! SNMP-TARGET-MIB (`1.3.6.1.6.3.12`) and SNMP-NOTIFICATION-MIB (`1.3.6.1.6.3.13`)
//! live tables, backed by a shared [`NotifyConfig`](crate::notify::NotifyConfig).
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/target/` and `agent/mibgroup/
//! notification/` modules. Exposes the three configuration tables the
//! notification originator uses as walkable (read-only) MIB handlers:
//!
//! | Table                       | OID                  |
//! |-----------------------------|----------------------|
//! | `snmpTargetAddrTable`       | `1.3.6.1.6.3.12.1.2` |
//! | `snmpTargetParamsTable`     | `1.3.6.1.6.3.12.1.3` |
//! | `snmpNotifyTable`           | `1.3.6.1.6.3.13.1.1` |
//!
//! The handlers rebuild their cell snapshot on each read via
//! [`NotifyConfig`]'s snapshot accessors, so targets added or removed at
//! runtime (e.g. by `from_config_directives` or future writable-RowStatus
//! support) are immediately visible to walkers. Column numbers and index
//! encodings match the RFC 3413 MIB.
//!
//! All rows are reported as `volatile(2)` / `active(1)`; a future writable
//! RowStatus implementation (Task 5.8) can layer SET support on top.

use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::notify::NotifyConfig;
use crate::scalar::FnHandler;

/// `snmpTargetAddrEntry`: `1.3.6.1.6.3.12.1.2.1`.
const TARGET_ADDR_ENTRY: &[u32] = &[1, 3, 6, 1, 6, 3, 12, 1, 2, 1];
/// `snmpTargetParamsEntry`: `1.3.6.1.6.3.12.1.3.1`.
const TARGET_PARAMS_ENTRY: &[u32] = &[1, 3, 6, 1, 6, 3, 12, 1, 3, 1];
/// `snmpNotifyEntry`: `1.3.6.1.6.3.13.1.1.1`.
const NOTIFY_ENTRY: &[u32] = &[1, 3, 6, 1, 6, 3, 13, 1, 1, 1];

// Column numbers (from SNMP-TARGET-MIB / SNMP-NOTIFICATION-MIB).
/// `snmpTargetAddrTDomain` (col 2 of snmpTargetAddrEntry).
const ADDR_TDOMAIN: u32 = 2;
/// `snmpTargetAddrTAddress` (col 3).
const ADDR_TADDRESS: u32 = 3;
/// `snmpTargetAddrTimeout` (col 4).
const ADDR_TIMEOUT: u32 = 4;
/// `snmpTargetAddrRetryCount` (col 5).
const ADDR_RETRY: u32 = 5;
/// `snmpTargetAddrTagList` (col 6).
const ADDR_TAG_LIST: u32 = 6;
/// `snmpTargetAddrParams` (col 7).
const ADDR_PARAMS: u32 = 7;
/// `snmpTargetAddrStorageType` (col 8).
const ADDR_STORAGE_TYPE: u32 = 8;
/// `snmpTargetAddrRowStatus` (col 9).
const ADDR_STATUS: u32 = 9;

/// `snmpTargetParamsMPModel` (col 2 of snmpTargetParamsEntry).
const PARAMS_MP_MODEL: u32 = 2;
/// `snmpTargetParamsSecurityModel` (col 3).
const PARAMS_SEC_MODEL: u32 = 3;
/// `snmpTargetParamsSecurityName` (col 4).
const PARAMS_SEC_NAME: u32 = 4;
/// `snmpTargetParamsSecurityLevel` (col 5).
const PARAMS_SEC_LEVEL: u32 = 5;
/// `snmpTargetParamsStorageType` (col 6).
const PARAMS_STORAGE_TYPE: u32 = 6;
/// `snmpTargetParamsRowStatus` (col 7).
const PARAMS_STATUS: u32 = 7;

/// `snmpNotifyTag` (col 2 of snmpNotifyEntry).
const NOTIFY_TAG: u32 = 2;
/// `snmpNotifyType` (col 3).
const NOTIFY_TYPE: u32 = 3;
/// `snmpNotifyStorageType` (col 4).
const NOTIFY_STORAGE_TYPE: u32 = 4;
/// `snmpNotifyRowStatus` (col 5).
const NOTIFY_STATUS: u32 = 5;

/// The conventional `StorageType` reported for rows created from
/// configuration: `volatile(2)`.
const STORAGE_VOLATILE: i64 = 2;
/// The `RowStatus` reported for active rows: `active(1)`.
const STATUS_ACTIVE: i64 = 1;

/// The standard `snmpUDPDomain` transport-domain OID (`1.3.6.1.6.1.1`).
const SNMP_UDP_DOMAIN: &[u32] = &[1, 3, 6, 1, 6, 1, 1];

/// Encode a variable-length OCTET STRING index (length-prefixed), matching the
/// non-IMPLIED INDEX encoding used by these tables.
fn string_index(bytes: &[u8]) -> Vec<u32> {
    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.push(bytes.len() as u32);
    out.extend(bytes.iter().map(|&b| b as u32));
    out
}

/// Encode a `host:port` TAddress as a 4-byte IPv4 address followed by a 2-byte
/// port (the `snmpUDPAddress` textual convention). Falls back to an empty
/// octet string for non-IPv4 hosts (minimal: only the loopback test path and
/// numeric `host:port` are exercised here).
fn udp_address(host_port: &str) -> Vec<u8> {
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h, p),
        None => return Vec::new(),
    };
    let Ok(ip) = host.parse::<std::net::Ipv4Addr>() else {
        return Vec::new();
    };
    let Ok(port) = port.parse::<u16>() else {
        return Vec::new();
    };
    let octets = ip.octets();
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&octets);
    out.extend_from_slice(&port.to_be_bytes());
    out
}

/// Build the `snmpTargetAddrTable` cells. INDEX is `snmpTargetAddrName`
/// (length-prefixed OCTET STRING). Columns: TDomain(2), TAddress(3), Timeout(4),
/// RetryCount(5), TagList(6), Params(7), StorageType(8), RowStatus(9).
fn target_addr_cells(config: &NotifyConfig) -> Vec<(Oid, Value)> {
    let entry = Oid::new(TARGET_ADDR_ENTRY.to_vec());
    let mut cells = Vec::new();
    for t in config.targets() {
        let idx = string_index(t.name.as_bytes());
        let cell = |col: u32| {
            let mut p = entry.as_slice().to_vec();
            p.push(col);
            p.extend_from_slice(&idx);
            Oid::new(p)
        };
        cells.push((cell(ADDR_TDOMAIN), Value::Oid(Oid::new(SNMP_UDP_DOMAIN.to_vec()))));
        cells.push((cell(ADDR_TADDRESS), Value::OctetString(udp_address(&t.address))));
        // Timeout is in hundredths of a second (the MIB's TimeTicks-ish unit).
        cells.push((cell(ADDR_TIMEOUT), Value::TimeTicks(
            (t.timeout.as_millis() / 10) as u32,
        )));
        cells.push((cell(ADDR_RETRY), Value::Integer(t.retries as i64)));
        // The tag list mirrors the target's own name (simple 1:1 config).
        cells.push((cell(ADDR_TAG_LIST), Value::OctetString(t.name.as_bytes().to_vec())));
        cells.push((cell(ADDR_PARAMS), Value::OctetString(t.params_name.as_bytes().to_vec())));
        cells.push((cell(ADDR_STORAGE_TYPE), Value::Integer(STORAGE_VOLATILE)));
        cells.push((cell(ADDR_STATUS), Value::Integer(STATUS_ACTIVE)));
    }
    cells
}

/// Build the `snmpTargetParamsTable` cells. INDEX is `snmpTargetParamsName`
/// (length-prefixed). Columns: MPModel(2), SecurityModel(3), SecurityName(4),
/// SecurityLevel(5), StorageType(6), RowStatus(7).
fn target_params_cells(config: &NotifyConfig) -> Vec<(Oid, Value)> {
    let entry = Oid::new(TARGET_PARAMS_ENTRY.to_vec());
    let mut cells = Vec::new();
    for p in config.params() {
        let idx = string_index(p.name.as_bytes());
        let cell = |col: u32| {
            let mut o = entry.as_slice().to_vec();
            o.push(col);
            o.extend_from_slice(&idx);
            Oid::new(o)
        };
        cells.push((cell(PARAMS_MP_MODEL), Value::Integer(p.mp_model as i64)));
        cells.push((cell(PARAMS_SEC_MODEL), Value::Integer(p.security_model as i64)));
        cells.push((cell(PARAMS_SEC_NAME), Value::OctetString(p.security_name.clone())));
        cells.push((cell(PARAMS_SEC_LEVEL), Value::Integer(p.security_level as i64)));
        cells.push((cell(PARAMS_STORAGE_TYPE), Value::Integer(STORAGE_VOLATILE)));
        cells.push((cell(PARAMS_STATUS), Value::Integer(STATUS_ACTIVE)));
    }
    cells
}

/// Build the `snmpNotifyTable` cells. INDEX is `snmpNotifyName`
/// (length-prefixed). Columns: Tag(2), Type(3), StorageType(4), RowStatus(5).
fn notify_cells(config: &NotifyConfig) -> Vec<(Oid, Value)> {
    let entry = Oid::new(NOTIFY_ENTRY.to_vec());
    let mut cells = Vec::new();
    for n in config.notifies() {
        let idx = string_index(n.name.as_bytes());
        let cell = |col: u32| {
            let mut o = entry.as_slice().to_vec();
            o.push(col);
            o.extend_from_slice(&idx);
            Oid::new(o)
        };
        cells.push((cell(NOTIFY_TAG), Value::OctetString(n.tag.as_bytes().to_vec())));
        cells.push((cell(NOTIFY_TYPE), Value::Integer(n.typ.as_int())));
        cells.push((cell(NOTIFY_STORAGE_TYPE), Value::Integer(STORAGE_VOLATILE)));
        cells.push((cell(NOTIFY_STATUS), Value::Integer(STATUS_ACTIVE)));
    }
    cells
}

/// Build the read-only SNMP-TARGET-MIB + SNMP-NOTIFICATION-MIB handlers, backed
/// by the shared `config`. Returns one handler per table so each subtree is
/// served independently (and GETNEXT walks across them in OID order).
///
/// The handlers rebuild their cell snapshot on each read via
/// [`NotifyConfig`]'s snapshot accessors, so configuration changes take effect
/// immediately for walkers. All rows are reported as `volatile(2)` /
/// `active(1)`.
pub fn notify_handlers(config: Arc<NotifyConfig>) -> Vec<Arc<dyn MibHandler>> {
    let c1 = Arc::clone(&config);
    let c2 = Arc::clone(&config);
    let c3 = config;
    vec![
        Arc::new(FnHandler::new(
            Oid::new(TARGET_ADDR_ENTRY.to_vec()),
            move || target_addr_cells(&c1),
        )),
        Arc::new(FnHandler::new(
            Oid::new(TARGET_PARAMS_ENTRY.to_vec()),
            move || target_params_cells(&c2),
        )),
        Arc::new(FnHandler::new(
            Oid::new(NOTIFY_ENTRY.to_vec()),
            move || notify_cells(&c3),
        )),
    ]
}

/// Register the SNMP-TARGET-MIB and SNMP-NOTIFICATION-MIB live tables into
/// `registry`, backed by `config`.
///
/// Convenience wrapper around [`notify_handlers`] for callers that already hold
/// a `&mut Registry` (e.g. the `register_framework_mibs`-style setup).
pub fn register_notify_mibs(registry: &mut crate::registry::Registry, config: Arc<NotifyConfig>) {
    for handler in notify_handlers(config) {
        registry.register(handler);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::{NotifyEntry, NotifyType, TargetAddr, TargetParams};
    use std::time::Duration;

    /// A minimal config with one target/params/notify row.
    fn sample_config() -> Arc<NotifyConfig> {
        let config = NotifyConfig::new();
        config.add_params(TargetParams {
            name: "t1".to_string(),
            mp_model: 1,
            security_model: 2,
            security_name: b"public".to_vec(),
            security_level: 0,
            usm_user: None,
        });
        config.add_target(TargetAddr {
            name: "t1".to_string(),
            transport: "udp".to_string(),
            address: "127.0.0.1:162".to_string(),
            timeout: Duration::from_secs(5),
            retries: 2,
            params_name: "t1".to_string(),
        });
        config.add_notify(NotifyEntry {
            name: "t1".to_string(),
            tag: "t1".to_string(),
            typ: NotifyType::Trap,
            params_name: "t1".to_string(),
        });
        config
    }

    #[test]
    fn target_addr_table_exposes_row() {
        let config = sample_config();
        let handlers = notify_handlers(config);
        let addr_handler = &handlers[0];
        // snmpTargetAddrTAddress for "t1": entry.3.<len=2>'t''1'
        let oid: Oid = "1.3.6.1.6.3.12.1.2.1.3.2.116.49".parse().unwrap();
        let got = addr_handler.get(&oid);
        // 127.0.0.1:162 -> octets [127,0,0,1, 0,162]
        assert_eq!(
            got,
            Some(Value::OctetString(vec![127, 0, 0, 1, 0, 162]))
        );
    }

    #[test]
    fn target_params_table_exposes_security_name() {
        let config = sample_config();
        let handlers = notify_handlers(config);
        let params_handler = &handlers[1];
        // snmpTargetParamsSecurityName for "t1": entry.4.<len=2>'t''1'
        let oid: Oid = "1.3.6.1.6.3.12.1.3.1.4.2.116.49".parse().unwrap();
        let got = params_handler.get(&oid);
        assert_eq!(got, Some(Value::OctetString(b"public".to_vec())));
    }

    #[test]
    fn notify_table_exposes_type() {
        let config = sample_config();
        let handlers = notify_handlers(config);
        let notify_handler = &handlers[2];
        // snmpNotifyType for "t1": entry.3.<len=2>'t''1' = trap(1)
        let oid: Oid = "1.3.6.1.6.3.13.1.1.1.3.2.116.49".parse().unwrap();
        let got = notify_handler.get(&oid);
        assert_eq!(got, Some(Value::Integer(1)));
    }

    #[test]
    fn getnext_from_table_root_lands_on_first_cell() {
        let config = sample_config();
        let handlers = notify_handlers(config);
        let notify_handler = &handlers[2];
        let root: Oid = "1.3.6.1.6.3.13.1.1.1".parse().unwrap();
        let first = notify_handler.get_next(&root).expect("first successor");
        assert!(first.oid > root);
    }
}
