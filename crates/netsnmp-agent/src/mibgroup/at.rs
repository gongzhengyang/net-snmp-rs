//! `at` table (`1.3.6.1.2.1.3.1`) — the address-translation table of RFC 1213.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/mibII/at.c`. In modern stacks the
//! `at` table is a deprecated view of the IPv4 ARP cache, so this module simply
//! re-parses `/proc/net/arp` (the same source as [`super::ip`]'s
//! `ipNetToMediaTable`) and reports the rows under the `at` OID tree.
//!
//! Objects exposed:
//! * `atTable` (`1.3.6.1.2.1.3.1`) — `atEntry` rows with `atIfIndex`,
//!   `atPhysAddress`, `atNetAddress`.

use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;

use super::ip::{parse_arp_entries, ArpEntry};

/// `at` group root: `1.3.6.1.2.1.3`.
const AT: [u32; 7] = [1, 3, 6, 1, 2, 1, 3];

/// Build the `atTable` instance cells (OID -> value) for the given ARP rows.
///
/// Cell OID layout: `atEntry(3.1.1.1).column(.C).ifindex.netaddr` — column
/// first, then the row index. Per the RFC 1213 INDEX convention `ifindex` is a
/// single sub-identifier and `netaddr` (an IpAddress) is encoded as four
/// sub-identifiers (one per octet, network order). The `at` table deprecates
/// `ipNetToMediaTable`; the column numbers differ (1=`atIfIndex`,
/// 2=`atPhysAddress`, 3=`atNetAddress`).
pub fn at_cells(entries: &[ArpEntry]) -> Vec<(Oid, Value)> {
    let entry = Oid::new(AT.to_vec()).child(1).child(1).child(1); // atTable.atEntry
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    for e in entries {
        let mut index: Vec<u32> = vec![e.if_index];
        index.extend(e.net_address.octets().iter().map(|&b| b as u32));
        let mut put = |col: u32, value: Value| {
            let mut oid = entry.as_slice().to_vec();
            oid.push(col);
            oid.extend_from_slice(&index);
            cells.insert(Oid::new(oid), value);
        };
        put(1, Value::Integer(e.if_index as i64));
        put(2, Value::OctetString(e.phys_address.clone()));
        put(3, Value::IpAddress(e.net_address));
    }
    cells.into_iter().collect()
}

fn read_proc(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn at_all_cells() -> Vec<(Oid, Value)> {
    let arp = parse_arp_entries(&read_proc("/proc/net/arp"));
    at_cells(&arp)
}

/// Build the `at` table handler rooted at `1.3.6.1.2.1.3.1`.
///
/// The handler is empty (but walkable) on platforms without `/proc/net/arp`.
pub fn at_handler() -> Arc<dyn MibHandler> {
    // Rooted at atTable (3.1) so GETNEXT from 3.1 lands on the first row.
    let root = Oid::new(AT.to_vec()).child(1);
    Arc::new(FnHandler::new(root, || at_all_cells()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const ARP_SAMPLE: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.5      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.1      0x1         0x6         00:11:22:33:44:55     *        eth0
10.0.0.99        0x1         0x0         00:00:00:00:00:00     *        eth1
";

    #[test]
    fn at_cells_encode_index() {
        let entries = parse_arp_entries(ARP_SAMPLE);
        let cells = at_cells(&entries);
        // atPhysAddress for 192.168.1.5 on ifIndex 1:
        // 3.1.1.1.2.1.192.168.1.5
        let oid: Oid = ".1.3.6.1.2.1.3.1.1.1.2.1.192.168.1.5".parse().unwrap();
        let mac = cells
            .iter()
            .find(|(o, _)| o == &oid)
            .map(|(_, v)| v.clone());
        assert_eq!(
            mac,
            Some(Value::OctetString(vec![
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
            ]))
        );
        // atNetAddress column 3.
        let net_oid: Oid = ".1.3.6.1.2.1.3.1.1.1.3.1.192.168.1.5".parse().unwrap();
        let net = cells
            .iter()
            .find(|(o, _)| o == &net_oid)
            .map(|(_, v)| v.clone());
        assert_eq!(net, Some(Value::IpAddress(Ipv4Addr::new(192, 168, 1, 5))));
    }

    #[test]
    fn handler_empty_without_proc() {
        let cells: Vec<(Oid, Value)> = at_cells(&parse_arp_entries(""));
        assert!(cells.is_empty());
    }

    #[test]
    fn handler_is_walkable() {
        let handler = at_handler();
        let root: Oid = "1.3.6.1.2.1.3.1".parse().unwrap();
        // With no /proc the handler serves no cells; get_next returns None but
        // must not panic. (When /proc is present it returns the first row.)
        let _ = handler.get_next(&root);
    }
}
