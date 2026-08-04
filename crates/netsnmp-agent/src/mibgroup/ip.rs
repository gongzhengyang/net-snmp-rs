//! IP-MIB (`1.3.6.1.2.1.4`) — the `ip` group, `ipAddrTable` and
//! `ipNetToMediaTable` (the ARP cache).
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/mibII/ip.c`, `ipAddr.c` and
//! `ipNetToMedia.c`. The scalar counters (`ipInReceives`, `ipInHdrErrors`, …)
//! are read from the `Ip:` line of `/proc/net/snmp` on Linux; the ARP cache
//! (`ipNetToMediaTable`) is read from `/proc/net/arp`. The `ipAddrTable` is
//! kept minimal (empty) because synthesising it correctly requires the
//! interface address set, which is already exposed under IF-MIB.
//!
//! On any platform where `/proc` is unavailable — or the parse fails — the
//! scalars report zero and the tables are empty, so the handlers never panic.
//!
//! Objects exposed:
//! * `ip` scalars (`4.1`–`4.23`) — forwarding, TTL and the 19 traffic counters.
//! * `ipAddrTable` (`4.20.1`) — reported empty (see above).
//! * `ipNetToMediaTable` (`4.22.1`) — the IPv4 ARP cache.

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

/// Parsed IP scalar counters from the `Ip:` line of `/proc/net/snmp`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpScalars {
    /// `ipForwarding` (1 = forwarding, 2 = not forwarding).
    pub forwarding: i64,
    /// `ipDefaultTTL`.
    pub default_ttl: i64,
    /// `ipInReceives`.
    pub in_receives: u32,
    /// `ipInHdrErrors`.
    pub in_hdr_errors: u32,
    /// `ipInAddrErrors`.
    pub in_addr_errors: u32,
    /// `ipForwDatagrams`.
    pub forw_datagrams: u32,
    /// `ipInUnknownProtos`.
    pub in_unknown_protos: u32,
    /// `ipInDiscards`.
    pub in_discards: u32,
    /// `ipInDelivers`.
    pub in_delivers: u32,
    /// `ipOutRequests`.
    pub out_requests: u32,
    /// `ipOutDiscards`.
    pub out_discards: u32,
    /// `ipOutNoRoutes`.
    pub out_no_routes: u32,
    /// `ipReasmTimeout`.
    pub reasm_timeout: i64,
    /// `ipReasmReqds`.
    pub reasm_reqds: u32,
    /// `ipReasmOKs`.
    pub reasm_oks: u32,
    /// `ipReasmFails`.
    pub reasm_fails: u32,
    /// `ipFragOKs`.
    pub frag_oks: u32,
    /// `ipFragFails`.
    pub frag_fails: u32,
    /// `ipFragCreates`.
    pub frag_creates: u32,
}

/// A single ARP-cache row (`ipNetToMediaTable` / `at` table).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArpEntry {
    /// Interface index. `/proc/net/arp` does not record this; we use a stable
    /// 1-based index derived from the device name ordering, or 0 when unknown.
    pub if_index: u32,
    /// MAC address octets.
    pub phys_address: Vec<u8>,
    /// IPv4 address.
    pub net_address: Ipv4Addr,
    /// `ipNetToMediaType`: 1=other, 2=invalid, 3=dynamic, 4=static.
    pub media_type: i64,
}

/// Parse the `Ip:` scalars out of a `/proc/net/snmp`-style document.
///
/// Returns [`IpScalars::default`] when no `Ip:` data line is found. The
/// `Forwarding` field in `/proc/net/snmp` uses Linux conventions (1 =
/// forwarding, 2 = not forwarding), which already matches RFC 1213.
pub fn parse_ip_scalars(snmp: &str) -> IpScalars {
    let mut lines = snmp.lines().filter(|l| l.starts_with("Ip:"));
    let header = match lines.next() {
        Some(h) => h,
        None => return IpScalars::default(),
    };
    let data = match lines.next() {
        Some(d) => d,
        None => return IpScalars::default(),
    };
    let names: Vec<&str> = header["Ip:".len()..].split_whitespace().collect();
    let vals: Vec<&str> = data["Ip:".len()..].split_whitespace().collect();
    let mut out = IpScalars {
        // Defaults that /proc does not always carry.
        reasm_timeout: 0,
        ..IpScalars::default()
    };
    for (name, val) in names.iter().zip(vals.iter()) {
        let parsed_i: i64 = val.parse().unwrap_or(0);
        let parsed_u: u32 = val.parse().unwrap_or(0);
        match *name {
            "Forwarding" => out.forwarding = parsed_i,
            "DefaultTTL" => out.default_ttl = parsed_i,
            "InReceives" => out.in_receives = parsed_u,
            "InHdrErrors" => out.in_hdr_errors = parsed_u,
            "InAddrErrors" => out.in_addr_errors = parsed_u,
            "ForwDatagrams" => out.forw_datagrams = parsed_u,
            "InUnknownProtos" => out.in_unknown_protos = parsed_u,
            "InDiscards" => out.in_discards = parsed_u,
            "InDelivers" => out.in_delivers = parsed_u,
            "OutRequests" => out.out_requests = parsed_u,
            "OutDiscards" => out.out_discards = parsed_u,
            "OutNoRoutes" => out.out_no_routes = parsed_u,
            "ReasmTimeout" => out.reasm_timeout = parsed_i,
            "ReasmReqds" => out.reasm_reqds = parsed_u,
            "ReasmOKs" => out.reasm_oks = parsed_u,
            "ReasmFails" => out.reasm_fails = parsed_u,
            "FragOKs" => out.frag_oks = parsed_u,
            "FragFails" => out.frag_fails = parsed_u,
            "FragCreates" => out.frag_creates = parsed_u,
            _ => {}
        }
    }
    out
}

/// Parse a colon-separated MAC address (e.g. `aa:bb:cc:dd:ee:ff`) into octets.
/// Returns an empty vector on failure.
pub fn parse_mac(s: &str) -> Vec<u8> {
    s.trim()
        .split(':')
        .filter_map(|b| u8::from_str_radix(b, 16).ok())
        .collect()
}

/// Parse `/proc/net/arp`-style content into ARP rows.
///
/// Columns used: IP address (0), HW type (1, ignored), flags (2, ignored),
/// HW address (3), mask (4, ignored), device (5). The device name is mapped to
/// a 1-based interface index by sorting the distinct device names; rows whose
/// MAC is `00:00:00:00:00:00` (incomplete entries) are skipped. Static entries
/// (flag bit `0x2` set, i.e. ATF_COM) are reported as `static(4)`, otherwise
/// `dynamic(3)`.
pub fn parse_arp_entries(arp: &str) -> Vec<ArpEntry> {
    let mut rows: Vec<ArpEntry> = Vec::new();
    // Collect device names first to assign stable ifIndex values.
    let mut devices: Vec<String> = Vec::new();
    for line in arp.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let net_address: Ipv4Addr = match fields[0].parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let phys_address = parse_mac(fields[3]);
        if phys_address.len() != 6 || phys_address.iter().all(|&b| b == 0) {
            continue; // incomplete entry (no/zero MAC)
        }
        let device = fields[5].to_string();
        if !devices.contains(&device) {
            devices.push(device.clone());
        }
        let flags = u32::from_str_radix(fields[2].trim_start_matches("0x"), 16).unwrap_or(0);
        let media_type = if flags & 0x2 != 0 { 4 } else { 3 };
        rows.push(ArpEntry {
            if_index: 0, // filled in after sorting devices
            phys_address,
            net_address,
            media_type,
        });
        // Remember the device against the row for the second pass.
        // We stash it in if_index temporarily as a sentinel via a side map.
        // Simpler: rebuild below by re-pairing; instead track device inline.
        // To keep ArpEntry lean, we re-derive index by device order here.
        let idx = (devices.iter().position(|d| d == &device).unwrap() + 1) as u32;
        rows.last_mut().unwrap().if_index = idx;
    }
    rows
}

fn read_proc(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

/// Build the `ip` scalar instance cells (OID -> value) for the given counters.
pub fn ip_scalar_cells(scalars: &IpScalars) -> Vec<(Oid, Value)> {
    let root = Oid::new(IP.to_vec());
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    let mut put = |col: u32, value: Value| {
        cells.insert(root.child(col).child(0), value);
    };
    put(1, Value::Integer(scalars.forwarding));
    put(2, Value::Integer(scalars.default_ttl));
    put(3, Value::Counter32(scalars.in_receives));
    put(4, Value::Counter32(scalars.in_hdr_errors));
    put(5, Value::Counter32(scalars.in_addr_errors));
    put(6, Value::Counter32(scalars.forw_datagrams));
    put(7, Value::Counter32(scalars.in_unknown_protos));
    put(8, Value::Counter32(scalars.in_discards));
    put(9, Value::Counter32(scalars.in_delivers));
    put(10, Value::Counter32(scalars.out_requests));
    put(11, Value::Counter32(scalars.out_discards));
    put(12, Value::Counter32(scalars.out_no_routes));
    put(13, Value::Integer(scalars.reasm_timeout));
    put(14, Value::Counter32(scalars.reasm_reqds));
    put(15, Value::Counter32(scalars.reasm_oks));
    put(16, Value::Counter32(scalars.reasm_fails));
    put(17, Value::Counter32(scalars.frag_oks));
    put(18, Value::Counter32(scalars.frag_fails));
    put(19, Value::Counter32(scalars.frag_creates));
    cells.into_iter().collect()
}

/// Build the `ipNetToMediaTable` instance cells (OID -> value) for the given ARP
/// rows.
///
/// Cell OID layout: `ipNetToMediaEntry(4.22.1.1).column(.C).ifindex.netaddr` —
/// column first, then the row index. Per the RFC 1213 INDEX convention
/// `ifindex` is a single sub-identifier and `netaddr` (an IpAddress) is encoded
/// as four sub-identifiers (one per octet, network order).
pub fn ip_net_to_media_cells(entries: &[ArpEntry]) -> Vec<(Oid, Value)> {
    let entry = Oid::new(IP.to_vec()).child(22).child(1).child(1);
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
        put(4, Value::Integer(e.media_type));
    }
    cells.into_iter().collect()
}

fn ip_all_cells() -> Vec<(Oid, Value)> {
    let scalars = parse_ip_scalars(&read_proc("/proc/net/snmp"));
    let arp = parse_arp_entries(&read_proc("/proc/net/arp"));
    let mut cells = ip_scalar_cells(&scalars);
    cells.extend(ip_net_to_media_cells(&arp));
    cells
}

/// Build the IP-MIB handlers rooted at `1.3.6.1.2.1.4`.
///
/// A single [`FnHandler`] serves the `ip` scalars and `ipNetToMediaTable`
/// together. The `ipAddrTable` is intentionally empty (its data overlaps
/// IF-MIB, which already exposes interface addresses).
pub fn ip_handlers() -> Vec<Arc<dyn MibHandler>> {
    let root = Oid::new(IP.to_vec());
    vec![Arc::new(FnHandler::new(root, || ip_all_cells()))]
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNMP_SAMPLE: &str = "\
Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates
Ip: 2 64 12345 0 1 0 0 0 12000 9000 0 0 0 0 0 0 0 0 0
Tcp: 1 200 120000 -1 100 200 5 10 3 5000 6000 7 2 9
";

    const ARP_SAMPLE: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.5      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.1      0x1         0x6         00:11:22:33:44:55     *        eth0
10.0.0.99        0x1         0x0         00:00:00:00:00:00     *        eth1
";

    #[test]
    fn parses_ip_scalars_from_snmp() {
        let s = parse_ip_scalars(SNMP_SAMPLE);
        assert_eq!(s.forwarding, 2);
        assert_eq!(s.default_ttl, 64);
        assert_eq!(s.in_receives, 12345);
        assert_eq!(s.in_hdr_errors, 0);
        assert_eq!(s.in_addr_errors, 1);
        assert_eq!(s.in_delivers, 12000);
        assert_eq!(s.out_requests, 9000);
    }

    #[test]
    fn parses_missing_ip_scalars_as_default() {
        assert_eq!(parse_ip_scalars("Tcp: 1\n"), IpScalars::default());
        assert_eq!(parse_ip_scalars("Ip: Forwarding\n"), IpScalars::default());
    }

    #[test]
    fn parses_arp_entries() {
        let entries = parse_arp_entries(ARP_SAMPLE);
        // The incomplete entry (all-zero MAC) is skipped.
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].net_address, Ipv4Addr::new(192, 168, 1, 5));
        assert_eq!(entries[0].phys_address, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        // flags 0x2 -> static(4)
        assert_eq!(entries[0].media_type, 4);
        // flags 0x6 -> static(4) (ATF_COM set)
        assert_eq!(entries[1].media_type, 4);
        assert_eq!(entries[0].if_index, 1); // eth0 is first device
    }

    #[test]
    fn ip_scalar_cells_cover_columns() {
        let s = IpScalars {
            forwarding: 2,
            default_ttl: 64,
            in_receives: 12345,
            ..Default::default()
        };
        let cells = ip_scalar_cells(&s);
        let get = |col: u32| {
            cells
                .iter()
                .find(|(o, _)| o.to_string() == format!(".1.3.6.1.2.1.4.{col}.0"))
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get(1), Some(Value::Integer(2))); // ipForwarding
        assert_eq!(get(2), Some(Value::Integer(64))); // ipDefaultTTL
        assert_eq!(get(3), Some(Value::Counter32(12345))); // ipInReceives
    }

    #[test]
    fn ip_net_to_media_cells_encode_index() {
        let entries = parse_arp_entries(ARP_SAMPLE);
        let cells = ip_net_to_media_cells(&entries);
        // ipNetToMediaPhysAddress for 192.168.1.5 on ifIndex 1:
        // 4.22.1.1.2.1.192.168.1.5
        let oid: Oid = ".1.3.6.1.2.1.4.22.1.1.2.1.192.168.1.5".parse().unwrap();
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
    }

    #[test]
    fn handler_returns_zero_scalars_without_proc() {
        let cells: Vec<(Oid, Value)> = {
            let scalars = parse_ip_scalars("");
            let arp = parse_arp_entries("");
            let mut out = ip_scalar_cells(&scalars);
            out.extend(ip_net_to_media_cells(&arp));
            out
        };
        let fwd = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.4.1.0")
            .map(|(_, v)| v.clone());
        assert_eq!(fwd, Some(Value::Integer(0)));
    }

    #[test]
    fn handler_serves_cells() {
        let handlers = ip_handlers();
        assert_eq!(handlers.len(), 1);
        let root: Oid = "1.3.6.1.2.1.4".parse().unwrap();
        let first = handlers[0].get_next(&root).expect("first successor");
        assert!(first.oid > root);
    }
}
