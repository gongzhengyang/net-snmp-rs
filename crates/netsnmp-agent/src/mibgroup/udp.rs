//! UDP-MIB (`1.3.6.1.2.1.7`) — the `udp` group and `udpTable`.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/mibII/udp.c` and `udpTable.c`. The
//! scalar counters (`udpInDatagrams`, `udpNoPorts`, …) and the listener table
//! are read from `/proc/net/snmp` and `/proc/net/udp` respectively on Linux. On
//! any platform where `/proc` is unavailable — or the parse fails — the scalars
//! report zero and the table is empty, so the handler never panics.
//!
//! Objects exposed:
//! * `udp` scalars (`7.1`–`7.4`) — datagram counters.
//! * `udpTable` (`7.5.1`) — the classic IPv4 UDP listener table.

use std::collections::BTreeMap;
use std::fs;
use std::net::Ipv4Addr;
use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;

/// `udp` group root: `1.3.6.1.2.1.7`.
const UDP: [u32; 7] = [1, 3, 6, 1, 2, 1, 7];

/// Parsed UDP scalar counters from the `Udp:` line of `/proc/net/snmp`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UdpScalars {
    /// `udpInDatagrams`
    pub in_datagrams: u32,
    /// `udpNoPorts`
    pub no_ports: u32,
    /// `udpInErrors`
    pub in_errors: u32,
    /// `udpOutDatagrams`
    pub out_datagrams: u32,
}

/// A single UDP listener row (IPv4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpEntry {
    /// Local IPv4 address.
    pub local_addr: Ipv4Addr,
    /// Local port.
    pub local_port: u16,
}

fn parse_hex_ipv4(s: &str) -> Option<Ipv4Addr> {
    let s = s.trim();
    if s.len() != 8 {
        return None;
    }
    let word = u32::from_str_radix(s, 16).ok()?;
    Some(Ipv4Addr::from(word.swap_bytes()))
}

fn parse_hex_port(s: &str) -> Option<u16> {
    u16::from_str_radix(s.trim(), 16).ok()
}

/// Parse the `Udp:` scalars out of a `/proc/net/snmp`-style document.
///
/// Returns [`UdpScalars::default`] when no `Udp:` data line is found.
pub fn parse_udp_scalars(snmp: &str) -> UdpScalars {
    let mut lines = snmp.lines().filter(|l| l.starts_with("Udp:"));
    let header = match lines.next() {
        Some(h) => h,
        None => return UdpScalars::default(),
    };
    let data = match lines.next() {
        Some(d) => d,
        None => return UdpScalars::default(),
    };
    let names: Vec<&str> = header["Udp:".len()..].split_whitespace().collect();
    let vals: Vec<&str> = data["Udp:".len()..].split_whitespace().collect();
    let mut out = UdpScalars::default();
    for (name, val) in names.iter().zip(vals.iter()) {
        let v: u32 = val.parse().unwrap_or(0);
        match *name {
            "InDatagrams" => out.in_datagrams = v,
            "NoPorts" => out.no_ports = v,
            "InErrors" => out.in_errors = v,
            "OutDatagrams" => out.out_datagrams = v,
            _ => {}
        }
    }
    out
}

/// Parse `/proc/net/udp`-style content into listener rows.
///
/// Only `local_address` (column index 1, `addr:port`) is required; everything
/// else is ignored. Malformed rows are silently skipped.
pub fn parse_udp_entries(udp: &str) -> Vec<UdpEntry> {
    let mut out = Vec::new();
    for line in udp.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let (addr, port) = match fields[1].split_once(':') {
            Some(p) => p,
            None => continue,
        };
        let local_addr = match parse_hex_ipv4(addr) {
            Some(a) => a,
            None => continue,
        };
        let local_port = match parse_hex_port(port) {
            Some(p) => p,
            None => continue,
        };
        out.push(UdpEntry {
            local_addr,
            local_port,
        });
    }
    out
}

fn read_proc(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

/// Build the `udp` scalar instance cells (OID -> value) for the given counters.
pub fn udp_scalar_cells(scalars: &UdpScalars) -> Vec<(Oid, Value)> {
    let root = Oid::new(UDP.to_vec());
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    let mut put = |col: u32, value: Value| {
        cells.insert(root.child(col).child(0), value);
    };
    put(1, Value::Counter32(scalars.in_datagrams));
    put(2, Value::Counter32(scalars.no_ports));
    put(3, Value::Counter32(scalars.in_errors));
    put(4, Value::Counter32(scalars.out_datagrams));
    cells.into_iter().collect()
}

/// Build the `udpTable` instance cells (OID -> value) for the given rows.
///
/// Cell OID layout: `udpEntry(7.5.1.1).column(.C).localaddr.localport` —
/// column first, then the row index. Per the RFC 1213 INDEX convention the
/// IPv4 address is encoded as four sub-identifiers (one per octet, network
/// order) and the port as a single sub-identifier.
pub fn udp_entry_cells(entries: &[UdpEntry]) -> Vec<(Oid, Value)> {
    let entry = Oid::new(UDP.to_vec()).child(5).child(1).child(1);
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    for e in entries {
        let mut index: Vec<u32> = e
            .local_addr
            .octets()
            .iter()
            .map(|&b| b as u32)
            .collect();
        index.push(e.local_port as u32);
        let mut put = |col: u32, value: Value| {
            let mut oid = entry.as_slice().to_vec();
            oid.push(col);
            oid.extend_from_slice(&index);
            cells.insert(Oid::new(oid), value);
        };
        put(1, Value::IpAddress(e.local_addr));
        put(2, Value::Integer(e.local_port as i64));
    }
    cells.into_iter().collect()
}

fn udp_all_cells() -> Vec<(Oid, Value)> {
    let scalars = parse_udp_scalars(&read_proc("/proc/net/snmp"));
    let entries = parse_udp_entries(&read_proc("/proc/net/udp"));
    let mut cells = udp_scalar_cells(&scalars);
    cells.extend(udp_entry_cells(&entries));
    cells
}

/// Build the UDP-MIB handlers rooted at `1.3.6.1.2.1.7`.
///
/// A single [`FnHandler`] serves the scalars and `udpTable` together.
pub fn udp_handlers() -> Vec<Arc<dyn MibHandler>> {
    let root = Oid::new(UDP.to_vec());
    vec![Arc::new(FnHandler::new(root, || udp_all_cells()))]
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNMP_SAMPLE: &str = "\
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts
Tcp: 1 200 120000 -1 100 200 5 10 3 5000 6000 7 2 9
Udp: InDatagrams NoPorts InErrors OutDatagrams
Udp: 300 4 0 295
";

    const UDP_SAMPLE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:82F0 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 22222 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn parses_udp_scalars_from_snmp() {
        let s = parse_udp_scalars(SNMP_SAMPLE);
        assert_eq!(s.in_datagrams, 300);
        assert_eq!(s.no_ports, 4);
        assert_eq!(s.in_errors, 0);
        assert_eq!(s.out_datagrams, 295);
    }

    #[test]
    fn parses_missing_udp_scalars_as_default() {
        assert_eq!(parse_udp_scalars("Tcp: 1\n"), UdpScalars::default());
        assert_eq!(parse_udp_scalars("Udp: InDatagrams\n"), UdpScalars::default());
    }

    #[test]
    fn parses_udp_entries() {
        let entries = parse_udp_entries(UDP_SAMPLE);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].local_addr, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(entries[0].local_port, 0x82F0);
        assert_eq!(entries[1].local_addr, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(entries[1].local_port, 53);
    }

    #[test]
    fn udp_scalar_cells_cover_columns() {
        let s = UdpScalars {
            in_datagrams: 300,
            no_ports: 4,
            in_errors: 0,
            out_datagrams: 295,
        };
        let cells = udp_scalar_cells(&s);
        let get = |col: u32| {
            cells
                .iter()
                .find(|(o, _)| o.to_string() == format!(".1.3.6.1.2.1.7.{col}.0"))
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get(1), Some(Value::Counter32(300)));
        assert_eq!(get(2), Some(Value::Counter32(4)));
        assert_eq!(get(3), Some(Value::Counter32(0)));
        assert_eq!(get(4), Some(Value::Counter32(295)));
    }

    #[test]
    fn udp_entry_cells_encode_index() {
        let entries = parse_udp_entries(UDP_SAMPLE);
        let cells = udp_entry_cells(&entries);
        // udpLocalAddress for the DNS listener: 7.5.1.1.1.127.0.0.1.53
        let oid: Oid = ".1.3.6.1.2.1.7.5.1.1.1.127.0.0.1.53".parse().unwrap();
        let addr = cells
            .iter()
            .find(|(o, _)| o == &oid)
            .map(|(_, v)| v.clone());
        assert_eq!(addr, Some(Value::IpAddress(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn handler_returns_zero_scalars_without_proc() {
        let cells: Vec<(Oid, Value)> = {
            let scalars = parse_udp_scalars("");
            let entries = parse_udp_entries("");
            let mut out = udp_scalar_cells(&scalars);
            out.extend(udp_entry_cells(&entries));
            out
        };
        // All four scalars present at zero.
        let get = |col: u32| {
            cells
                .iter()
                .find(|(o, _)| o.to_string() == format!(".1.3.6.1.2.1.7.{col}.0"))
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get(1), Some(Value::Counter32(0)));
        assert_eq!(get(4), Some(Value::Counter32(0)));
    }

    #[test]
    fn handler_serves_cells() {
        let handlers = udp_handlers();
        assert_eq!(handlers.len(), 1);
        let root: Oid = "1.3.6.1.2.1.7".parse().unwrap();
        let first = handlers[0].get_next(&root).expect("first successor");
        assert!(first.oid > root);
    }
}
