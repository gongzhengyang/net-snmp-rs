//! `ipRouteTable` (`1.3.6.1.2.1.4.21.1`) — the IPv4 unicast routing table of
//! RFC 1213.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/mibII/route_write.c` /
//! `route_headers.h`. The table is read from `/proc/net/route` on Linux. On any
//! platform where `/proc` is unavailable — or the parse fails — the table is
//! empty, so the handler never panics.
//!
//! Objects exposed:
//! * `ipRouteTable` (`4.21.1`) — `ipRouteEntry` rows with `ipRouteDest`,
//!   `ipRouteIfIndex`, `ipRouteMetric1..4`, `ipRouteNextHop`, `ipRouteType`,
//!   `ipRouteProto`, `ipRouteMask`.
//!
//! The high-capacity `inetCidrRouteTable` (IP-FORWARD-MIB) is intentionally
//! left empty: its index encoding is considerably more involved and the classic
//! `ipRouteTable` is sufficient for `snmpnetstat -r`.

use std::collections::BTreeMap;
use std::fs;
use std::net::Ipv4Addr;
use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;

/// `ip` group root: `1.3.6.1.2.1.4`.
const IP: [u32; 7] = [1, 3, 6, 1, 2, 1, 4];

/// A single routing-table row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteEntry {
    /// `ipRouteDest` — destination network.
    pub dest: Ipv4Addr,
    /// `ipRouteIfIndex` — interface index (1-based). `/proc/net/route` carries
    /// the device name; we map it to a stable 1-based index.
    pub if_index: i64,
    /// `ipRouteMetric1` (the primary metric; -1 when unknown).
    pub metric1: i64,
    /// `ipRouteMetric2`.
    pub metric2: i64,
    /// `ipRouteMetric3`.
    pub metric3: i64,
    /// `ipRouteMetric4`.
    pub metric4: i64,
    /// `ipRouteNextHop`.
    pub next_hop: Ipv4Addr,
    /// `ipRouteType` — 1=other, 2=invalid, 3=direct, 4=indirect.
    pub route_type: i64,
    /// `ipRouteProto` — 1=other, 2=local, 4=netmgmt, 8=icmp, 13=egp, 14=ggp,
    /// 16=hello, 17=rip, 18=isIs, 19=esIs, 20=ciscoIgrp, 22=bayVls,
    /// 23=ospf, 24=bgp, 25=idpr, 26=ciscoEigrp, 27=dvmrp.
    pub route_proto: i64,
    /// `ipRouteMask`.
    pub mask: Ipv4Addr,
}

fn parse_hex_ipv4(s: &str) -> Option<Ipv4Addr> {
    let s = s.trim();
    if s.len() != 8 {
        return None;
    }
    let word = u32::from_str_radix(s, 16).ok()?;
    Some(Ipv4Addr::from(word.swap_bytes()))
}

/// Parse `/proc/net/route`-style content into routing-table rows.
///
/// Columns (whitespace-separated, after the header line):
/// `Iface`, `Destination`, `Gateway`, `Flags`, `RefCnt`, `Use`, `Metric`,
/// `Mask`, `MTU`, `Window`, `IRTT`. Only the columns needed for the MIB are
/// consumed; everything else is ignored. Malformed rows are silently skipped.
///
/// `route_type` is derived from the `Flags` field: the `G` (gateway) bit
/// (`0x0002`) being set means `indirect(4)`, otherwise `direct(3)`.
/// `route_proto` is reported as `local(2)` for the loopback interface and
/// `other(1)` otherwise (Linux does not expose the routing protocol in
/// `/proc/net/route`).
pub fn parse_route_entries(route: &str) -> Vec<RouteEntry> {
    let mut devices: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for line in route.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        let iface = fields[0].to_string();
        let dest = match parse_hex_ipv4(fields[1]) {
            Some(a) => a,
            None => continue,
        };
        let gateway = match parse_hex_ipv4(fields[2]) {
            Some(a) => a,
            None => continue,
        };
        let flags = u32::from_str_radix(fields[3].trim_start_matches("0x"), 16).unwrap_or(0);
        let metric: i64 = fields[6].parse().unwrap_or(-1);
        let mask = match parse_hex_ipv4(fields[7]) {
            Some(a) => a,
            None => continue,
        };
        if !devices.contains(&iface) {
            devices.push(iface.clone());
        }
        let if_index = (devices.iter().position(|d| d == &iface).unwrap() + 1) as i64;
        let route_type = if flags & 0x0002 != 0 { 4 } else { 3 };
        let route_proto = if iface == "lo" { 2 } else { 1 };
        out.push(RouteEntry {
            dest,
            if_index,
            metric1: metric,
            metric2: -1,
            metric3: -1,
            metric4: -1,
            next_hop: gateway,
            route_type,
            route_proto,
            mask,
        });
    }
    out
}

fn read_proc(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

/// Build the `ipRouteTable` instance cells (OID -> value) for the given rows.
///
/// Cell OID layout: `ipRouteEntry(4.21.1.1).column(.C).dest` — column first,
/// then the row index. Per the RFC 1213 INDEX convention `dest` (an IpAddress)
/// is encoded as four sub-identifiers (one per octet, network order).
pub fn route_cells(entries: &[RouteEntry]) -> Vec<(Oid, Value)> {
    let entry = Oid::new(IP.to_vec()).child(21).child(1).child(1);
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    for r in entries {
        let index: Vec<u32> = r.dest.octets().iter().map(|&b| b as u32).collect();
        let mut put = |col: u32, value: Value| {
            let mut oid = entry.as_slice().to_vec();
            oid.push(col);
            oid.extend_from_slice(&index);
            cells.insert(Oid::new(oid), value);
        };
        put(1, Value::IpAddress(r.dest));
        put(2, Value::Integer(r.if_index));
        put(3, Value::Integer(r.metric1));
        put(4, Value::Integer(r.metric2));
        put(5, Value::Integer(r.metric3));
        put(6, Value::Integer(r.metric4));
        put(7, Value::IpAddress(r.next_hop));
        put(8, Value::Integer(r.route_type));
        put(9, Value::Integer(r.route_proto));
        put(11, Value::IpAddress(r.mask));
    }
    cells.into_iter().collect()
}

fn route_all_cells() -> Vec<(Oid, Value)> {
    let entries = parse_route_entries(&read_proc("/proc/net/route"));
    route_cells(&entries)
}

/// Build the `ipRouteTable` handler rooted at `1.3.6.1.2.1.4.21.1`.
///
/// The handler is empty (but walkable) on platforms without `/proc/net/route`.
pub fn route_handler() -> Arc<dyn MibHandler> {
    let root = Oid::new(IP.to_vec()).child(21).child(1);
    Arc::new(FnHandler::new(root, || route_all_cells()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE_SAMPLE: &str = "\
Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask            MTU     Window  IRTT
eth0    00000000        0100A8C0        0003    0       0       100     00000000        0       0       0
eth0    0001A8C0        00000000        0001    0       0       0       00FFFFFF        0       0       0
lo      0000007F        00000000        0001    0       0       1       0000007F        0       0       0
";

    #[test]
    fn parses_route_entries() {
        let entries = parse_route_entries(ROUTE_SAMPLE);
        assert_eq!(entries.len(), 3);
        // Default route: dest 0.0.0.0, gw 192.168.0.1, via eth0 (ifIndex 1).
        assert_eq!(entries[0].dest, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(entries[0].next_hop, Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(entries[0].if_index, 1);
        assert_eq!(entries[0].metric1, 100);
        // Gateway flag set -> indirect(4).
        assert_eq!(entries[0].route_type, 4);
        assert_eq!(entries[0].mask, Ipv4Addr::new(0, 0, 0, 0));
        // 192.168.1.0/24 direct route.
        assert_eq!(entries[1].dest, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(entries[1].route_type, 3); // direct
        assert_eq!(entries[1].mask, Ipv4Addr::new(255, 255, 255, 0));
        // Loopback route: dest 127.0.0.0/8, proto local(2).
        assert_eq!(entries[2].dest, Ipv4Addr::new(127, 0, 0, 0));
        assert_eq!(entries[2].route_proto, 2);
    }

    #[test]
    fn route_cells_encode_index() {
        let entries = parse_route_entries(ROUTE_SAMPLE);
        let cells = route_cells(&entries);
        // ipRouteNextHop for the default route: 4.21.1.1.7.0.0.0.0
        let oid: Oid = ".1.3.6.1.2.1.4.21.1.1.7.0.0.0.0".parse().unwrap();
        let gw = cells
            .iter()
            .find(|(o, _)| o == &oid)
            .map(|(_, v)| v.clone());
        assert_eq!(gw, Some(Value::IpAddress(Ipv4Addr::new(192, 168, 0, 1))));
        // ipRouteMask column 11 for 192.168.1.0.
        let mask_oid: Oid = ".1.3.6.1.2.1.4.21.1.1.11.192.168.1.0".parse().unwrap();
        let mask = cells
            .iter()
            .find(|(o, _)| o == &mask_oid)
            .map(|(_, v)| v.clone());
        assert_eq!(mask, Some(Value::IpAddress(Ipv4Addr::new(255, 255, 255, 0))));
        // sorted
        let mut sorted = cells.clone();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(cells, sorted);
    }

    #[test]
    fn handler_empty_without_proc() {
        let cells: Vec<(Oid, Value)> = route_cells(&parse_route_entries(""));
        assert!(cells.is_empty());
    }

    #[test]
    fn handler_is_walkable() {
        let handler = route_handler();
        let root: Oid = "1.3.6.1.2.1.4.21.1".parse().unwrap();
        let _ = handler.get_next(&root);
    }
}
