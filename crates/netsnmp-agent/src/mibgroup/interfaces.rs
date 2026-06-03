//! IF-MIB / mibII interfaces group, backed by cross-platform [`sysinfo`] data.
//!
//! Counterpart of `agent/mibgroup/if-mib/` and `mibII/interfaces.c`. The
//! per-interface data (name, MAC, MTU, cumulative byte/packet/error counters)
//! comes from the shared [`HostCollector`](super::collector::HostCollector).
//!
//! Objects exposed:
//! * `ifNumber` (`2.1`) — the interface count.
//! * `ifTable`  (`2.2`) — the classic 32-bit interface table.
//! * `ifXTable` (`31.1.1`) — high-capacity (64-bit) counters, `ifName`,
//!   `ifHighSpeed` and `ifAlias`.

use std::collections::BTreeMap;
use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use super::collector::HostCollector;
use crate::scalar::FnHandler;

/// `interfaces` group root: `1.3.6.1.2.1.2`.
const INTERFACES: [u32; 7] = [1, 3, 6, 1, 2, 1, 2];
/// `ifMIB` root: `1.3.6.1.2.1.31` (home of `ifXTable`).
const IF_MIB: [u32; 7] = [1, 3, 6, 1, 2, 1, 31];

/// Per-interface traffic counters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IfStat {
    /// Interface name (e.g. `eth0`, `lo`).
    pub name: String,
    /// Total bytes received.
    pub rx_bytes: u64,
    /// Total packets received.
    pub rx_packets: u64,
    /// Receive errors.
    pub rx_errs: u64,
    /// Receive packets dropped.
    pub rx_drop: u64,
    /// Total bytes transmitted.
    pub tx_bytes: u64,
    /// Total packets transmitted.
    pub tx_packets: u64,
    /// Transmit errors.
    pub tx_errs: u64,
    /// Transmit packets dropped.
    pub tx_drop: u64,
}

/// A fully resolved interface row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    /// `ifIndex`, the 1-based table row identifier.
    pub index: u32,
    /// `ifType` (IANAifType): 6 = ethernetCsmacd, 24 = softwareLoopback, …
    pub if_type: i64,
    /// `ifMtu`.
    pub mtu: i64,
    /// `ifSpeed` in bits per second (0 when unknown).
    pub speed_bps: u32,
    /// `ifPhysAddress` (MAC) as raw octets.
    pub phys_address: Vec<u8>,
    /// Whether the interface is administratively up.
    pub admin_up: bool,
    /// Whether the interface is operationally up.
    pub oper_up: bool,
    /// Traffic counters.
    pub stat: IfStat,
}

/// Parse a colon-separated MAC address (e.g. `aa:bb:cc:dd:ee:ff`) into octets.
pub fn parse_mac(s: &str) -> Vec<u8> {
    s.trim()
        .split(':')
        .filter_map(|b| u8::from_str_radix(b, 16).ok())
        .collect()
}

/// Build the `ifTable` instance cells (OID -> value) for the given interfaces.
///
/// Cell OID layout: `ifEntry(.1).column(.C).ifIndex(.N)` under `ifTable`.
pub fn interface_cells(interfaces: &[Interface]) -> Vec<(Oid, Value)> {
    let entry = Oid::new(INTERFACES.to_vec()).child(2).child(1); // ifTable.ifEntry
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    for iface in interfaces {
        let idx = iface.index;
        let mut put = |col: u32, value: Value| {
            cells.insert(entry.child(col).child(idx), value);
        };
        put(1, Value::Integer(idx as i64)); // ifIndex
        put(2, Value::OctetString(iface.stat.name.clone().into_bytes())); // ifDescr
        put(3, Value::Integer(iface.if_type)); // ifType
        put(4, Value::Integer(iface.mtu)); // ifMtu
        put(5, Value::Gauge32(iface.speed_bps)); // ifSpeed
        put(6, Value::OctetString(iface.phys_address.clone())); // ifPhysAddress
        put(7, Value::Integer(if iface.admin_up { 1 } else { 2 })); // ifAdminStatus
        put(8, Value::Integer(if iface.oper_up { 1 } else { 2 })); // ifOperStatus
        put(9, Value::TimeTicks(0)); // ifLastChange
        put(10, Value::Counter32(iface.stat.rx_bytes as u32)); // ifInOctets
        put(11, Value::Counter32(iface.stat.rx_packets as u32)); // ifInUcastPkts
        put(13, Value::Counter32(iface.stat.rx_drop as u32)); // ifInDiscards
        put(14, Value::Counter32(iface.stat.rx_errs as u32)); // ifInErrors
        put(16, Value::Counter32(iface.stat.tx_bytes as u32)); // ifOutOctets
        put(17, Value::Counter32(iface.stat.tx_packets as u32)); // ifOutUcastPkts
        put(19, Value::Counter32(iface.stat.tx_drop as u32)); // ifOutDiscards
        put(20, Value::Counter32(iface.stat.tx_errs as u32)); // ifOutErrors
    }
    cells.into_iter().collect()
}

/// Build the `ifXTable` instance cells (high-capacity 64-bit counters plus
/// `ifName`, `ifHighSpeed`, `ifAlias`).
///
/// Cell OID layout: `ifXEntry(31.1.1.1).column(.C).ifIndex(.N)`.
pub fn if_xtable_cells(interfaces: &[Interface]) -> Vec<(Oid, Value)> {
    let entry = Oid::new(IF_MIB.to_vec()).child(1).child(1).child(1); // ifXEntry
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    for iface in interfaces {
        let idx = iface.index;
        let mut put = |col: u32, value: Value| {
            cells.insert(entry.child(col).child(idx), value);
        };
        put(1, Value::OctetString(iface.stat.name.clone().into_bytes())); // ifName
        put(2, Value::Counter32(0)); // ifInMulticastPkts
        put(3, Value::Counter32(0)); // ifInBroadcastPkts
        put(4, Value::Counter32(0)); // ifOutMulticastPkts
        put(5, Value::Counter32(0)); // ifOutBroadcastPkts
        put(6, Value::Counter64(iface.stat.rx_bytes)); // ifHCInOctets
        put(7, Value::Counter64(iface.stat.rx_packets)); // ifHCInUcastPkts
        put(10, Value::Counter64(iface.stat.tx_bytes)); // ifHCOutOctets
        put(11, Value::Counter64(iface.stat.tx_packets)); // ifHCOutUcastPkts
        put(15, Value::Gauge32(iface.speed_bps / 1_000_000)); // ifHighSpeed (Mbit/s)
        put(
            18,
            Value::OctetString(iface.stat.name.clone().into_bytes()),
        ); // ifAlias
    }
    cells.into_iter().collect()
}

/// `ifNumber` handler (`1.3.6.1.2.1.2.1`).
pub fn if_number_handler(collector: Arc<HostCollector>) -> Arc<FnHandler> {
    let root = Oid::new(INTERFACES.to_vec()).child(1);
    Arc::new(FnHandler::scalar(root, move || {
        Value::Integer(collector.snapshot().interfaces.len() as i64)
    }))
}

/// `ifTable` handler (`1.3.6.1.2.1.2.2`).
pub fn if_table_handler(collector: Arc<HostCollector>) -> Arc<FnHandler> {
    let root = Oid::new(INTERFACES.to_vec()).child(2);
    Arc::new(FnHandler::new(root, move || {
        interface_cells(&collector.snapshot().interfaces)
    }))
}

/// `ifXTable` handler (`1.3.6.1.2.1.31`).
pub fn if_xtable_handler(collector: Arc<HostCollector>) -> Arc<FnHandler> {
    let root = Oid::new(IF_MIB.to_vec());
    Arc::new(FnHandler::new(root, move || {
        if_xtable_cells(&collector.snapshot().interfaces)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ifaces() -> Vec<Interface> {
        vec![
            Interface {
                index: 1,
                if_type: 24,
                mtu: 65536,
                speed_bps: 0,
                phys_address: vec![],
                admin_up: true,
                oper_up: true,
                stat: IfStat {
                    name: "lo".into(),
                    rx_bytes: 100,
                    rx_packets: 2,
                    ..Default::default()
                },
            },
            Interface {
                index: 2,
                if_type: 6,
                mtu: 1500,
                speed_bps: 1_000_000_000,
                phys_address: vec![0, 1, 2, 3, 4, 5],
                admin_up: true,
                oper_up: false,
                stat: IfStat {
                    name: "eth0".into(),
                    tx_bytes: 50,
                    ..Default::default()
                },
            },
        ]
    }

    #[test]
    fn parses_mac() {
        assert_eq!(
            parse_mac("aa:bb:cc:dd:ee:ff"),
            vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert_eq!(parse_mac("00:00:00:00:00:00"), vec![0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn builds_ordered_table_cells() {
        let cells = interface_cells(&sample_ifaces());
        // ifDescr.1 (column 2, instance 1) = "lo".
        let descr1 = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.2.2.1.2.1")
            .map(|(_, v)| v.clone());
        assert_eq!(descr1, Some(Value::OctetString(b"lo".to_vec())));
        // ifOperStatus.2 (column 8, instance 2) = down(2).
        let oper2 = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.2.2.1.8.2")
            .map(|(_, v)| v.clone());
        assert_eq!(oper2, Some(Value::Integer(2)));
        // Cells must be sorted by OID.
        let mut sorted = cells.clone();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(cells, sorted);
    }

    #[test]
    fn builds_ifx_high_capacity_counters() {
        let cells = if_xtable_cells(&sample_ifaces());
        // ifName.1 = "lo".
        let name1 = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.31.1.1.1.1.1")
            .map(|(_, v)| v.clone());
        assert_eq!(name1, Some(Value::OctetString(b"lo".to_vec())));
        // ifHCInOctets.1 (column 6) = 100 as Counter64.
        let hc_in1 = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.31.1.1.1.6.1")
            .map(|(_, v)| v.clone());
        assert_eq!(hc_in1, Some(Value::Counter64(100)));
        // ifHighSpeed.2 (column 15) = 1000 Mbit/s.
        let hs2 = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.31.1.1.1.15.2")
            .map(|(_, v)| v.clone());
        assert_eq!(hs2, Some(Value::Gauge32(1000)));
    }
}
