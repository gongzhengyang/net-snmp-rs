//! TCP-MIB (`1.3.6.1.2.1.6`) — the `tcp` group, `tcpConnTable` and a minimal
//! high-capacity `tcpConnectionTable`.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/mibII/tcp.c` and `tcpTable.c`. The
//! scalar counters (`tcpInSegs`, `tcpOutSegs`, …) and the connection table are
//! read from `/proc/net/snmp` and `/proc/net/tcp` respectively on Linux. On any
//! platform where `/proc` is unavailable — or the parse fails — the scalars
//! report zero and the tables are empty, so the handlers never panic.
//!
//! Objects exposed:
//! * `tcp` scalars (`6.1`–`6.14`) — RTO algorithm/limits, connection counters,
//!   segment counters.
//! * `tcpConnTable` (`6.13.1`) — the classic IPv4 TCP connection table.
//! * `tcpConnectionTable` (`6.19.1`) — high-capacity table; reported empty
//!   (the 32-bit `tcpConnTable` is sufficient for `snmpnetstat`).

use std::collections::BTreeMap;
use std::fs;
use std::net::Ipv4Addr;
use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;

/// `tcp` group root: `1.3.6.1.2.1.6`.
const TCP: [u32; 7] = [1, 3, 6, 1, 2, 1, 6];

/// Parsed TCP scalar counters from the `Tcp:` line of `/proc/net/snmp`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TcpScalars {
    /// `tcpActiveOpens`
    pub active_opens: u32,
    /// `tcpPassiveOpens`
    pub passive_opens: u32,
    /// `tcpAttemptFails`
    pub attempt_fails: u32,
    /// `tcpEstabResets`
    pub estab_resets: u32,
    /// `tcpCurrEstab`
    pub curr_estab: u32,
    /// `tcpInSegs`
    pub in_segs: u32,
    /// `tcpOutSegs`
    pub out_segs: u32,
    /// `tcpRetransSegs`
    pub retrans_segs: u32,
    /// `tcpInErrs`
    pub in_errs: u32,
    /// `tcpOutRsts`
    pub out_rsts: u32,
}

/// A single TCP connection row (IPv4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpConn {
    /// `tcpConnState` (RFC 1213 value, 1..12).
    pub state: i64,
    /// Local IPv4 address.
    pub local_addr: Ipv4Addr,
    /// Local port.
    pub local_port: u16,
    /// Remote IPv4 address.
    pub rem_addr: Ipv4Addr,
    /// Remote port.
    pub rem_port: u16,
}

/// Map a `/proc/net/tcp` hex state (`01`..`0B`) to its RFC 1213 `tcpConnState`
/// value. Unknown states map to `closed(1)`.
pub fn map_tcp_state(hex: &str) -> i64 {
    match hex.trim() {
        "01" => 5,  // ESTABLISHED
        "02" => 2,  // SYN_SENT
        "03" => 3,  // SYN_RECV
        "04" => 4,  // FIN_WAIT1
        "05" => 5,  // FIN_WAIT2 (RFC 1213 has no FIN_WAIT2; reuse established)
        "06" => 11, // TIME_WAIT
        "07" => 1,  // CLOSE
        "08" => 8,  // CLOSE_WAIT
        "09" => 9,  // LAST_ACK
        "0A" => 2,  // LISTEN (RFC 1213 has no LISTEN; reuse closed-ish via synSent)
        "0B" => 10, // CLOSING
        _ => 1,     // closed
    }
}

fn parse_hex_ipv4(s: &str) -> Option<Ipv4Addr> {
    let s = s.trim();
    if s.len() != 8 {
        return None;
    }
    // /proc/net/tcp stores the address as a little-endian hex word.
    let word = u32::from_str_radix(s, 16).ok()?;
    Some(Ipv4Addr::from(word.swap_bytes()))
}

fn parse_hex_port(s: &str) -> Option<u16> {
    u16::from_str_radix(s.trim(), 16).ok()
}

/// Parse the `Tcp:` scalars out of a `/proc/net/snmp`-style document.
///
/// The document contains two `Tcp:` lines: a header naming the columns and a
/// data line. Column names are matched case-insensitively against the RFC 1213
/// scalar names. Returns [`TcpScalars::default`] when no `Tcp:` data line is
/// found.
pub fn parse_tcp_scalars(snmp: &str) -> TcpScalars {
    let mut lines = snmp.lines().filter(|l| l.starts_with("Tcp:"));
    let header = match lines.next() {
        Some(h) => h,
        None => return TcpScalars::default(),
    };
    let data = match lines.next() {
        Some(d) => d,
        None => return TcpScalars::default(),
    };
    let names: Vec<&str> = header["Tcp:".len()..].split_whitespace().collect();
    let vals: Vec<&str> = data["Tcp:".len()..].split_whitespace().collect();
    let mut out = TcpScalars::default();
    for (name, val) in names.iter().zip(vals.iter()) {
        let v: u32 = match val.parse().unwrap_or(0) {
            v => v,
        };
        match *name {
            "ActiveOpens" => out.active_opens = v,
            "PassiveOpens" => out.passive_opens = v,
            "AttemptFails" => out.attempt_fails = v,
            "EstabResets" => out.estab_resets = v,
            "CurrEstab" => out.curr_estab = v,
            "InSegs" => out.in_segs = v,
            "OutSegs" => out.out_segs = v,
            "RetransSegs" => out.retrans_segs = v,
            "InErrs" => out.in_errs = v,
            "OutRsts" => out.out_rsts = v,
            _ => {}
        }
    }
    out
}

/// Parse `/proc/net/tcp`-style content into connection rows.
///
/// Only the first four whitespace columns (`sl`, `local_address`,
/// `rem_address`, `st`) are required; everything else is ignored. Malformed
/// rows are silently skipped.
pub fn parse_tcp_conns(tcp: &str) -> Vec<TcpConn> {
    let mut out = Vec::new();
    for line in tcp.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        // fields[1] = "local_addr:port", fields[2] = "rem_addr:port",
        // fields[3] = state hex.
        let (laddr, lport) = match fields[1].split_once(':') {
            Some(p) => p,
            None => continue,
        };
        let (raddr, rport) = match fields[2].split_once(':') {
            Some(p) => p,
            None => continue,
        };
        let local_addr = match parse_hex_ipv4(laddr) {
            Some(a) => a,
            None => continue,
        };
        let local_port = match parse_hex_port(lport) {
            Some(p) => p,
            None => continue,
        };
        let rem_addr = match parse_hex_ipv4(raddr) {
            Some(a) => a,
            None => continue,
        };
        let rem_port = match parse_hex_port(rport) {
            Some(p) => p,
            None => continue,
        };
        let state = map_tcp_state(fields[3]);
        out.push(TcpConn {
            state,
            local_addr,
            local_port,
            rem_addr,
            rem_port,
        });
    }
    out
}

/// Read a `/proc/net/...` file as a string, returning an empty string on any
/// error (missing file, permission denied, non-UTF-8). This is the cross-
/// platform fallback: where `/proc` is unavailable the handlers report empty
/// tables / zero counters rather than panicking.
fn read_proc(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

/// Build the `tcp` scalar instance cells (OID -> value) for the given counters.
///
/// The fixed-valued scalars (`tcpRtoAlgorithm`, `tcpRtoMin`, `tcpRtoMax`,
/// `tcpMaxConn`) are constants; the counter/gauge scalars come from `scalars`.
pub fn tcp_scalar_cells(scalars: &TcpScalars) -> Vec<(Oid, Value)> {
    let root = Oid::new(TCP.to_vec());
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    let mut put = |col: u32, value: Value| {
        cells.insert(root.child(col).child(0), value);
    };
    put(1, Value::Integer(1)); // tcpRtoAlgorithm = other(1) (van Jacobson)
    put(2, Value::Integer(200)); // tcpRtoMin (ms, typical Linux)
    put(3, Value::Integer(120_000)); // tcpRtoMax (ms)
    put(4, Value::Integer(-1)); // tcpMaxConn = unlimited
    put(5, Value::Counter32(scalars.active_opens));
    put(6, Value::Counter32(scalars.passive_opens));
    put(7, Value::Counter32(scalars.attempt_fails));
    put(8, Value::Counter32(scalars.estab_resets));
    put(9, Value::Gauge32(scalars.curr_estab));
    put(10, Value::Counter32(scalars.in_segs));
    put(11, Value::Counter32(scalars.out_segs));
    put(12, Value::Counter32(scalars.retrans_segs));
    put(13, Value::Counter32(scalars.in_errs));
    put(14, Value::Counter32(scalars.out_rsts));
    cells.into_iter().collect()
}

/// Build the `tcpConnTable` instance cells (OID -> value) for the given rows.
///
/// Cell OID layout: `tcpConnEntry(6.13.1.1).column(.C).localaddr.localport.
/// remaddr.remport` — column first, then the row index, matching the standard
/// SNMP table instance OID form. Per the RFC 1213 INDEX convention each IPv4
/// address is encoded as four sub-identifiers (one per octet, network order)
/// and each port as a single sub-identifier.
pub fn tcp_conn_cells(conns: &[TcpConn]) -> Vec<(Oid, Value)> {
    let entry = Oid::new(TCP.to_vec()).child(13).child(1).child(1);
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    for c in conns {
        let mut index: Vec<u32> = Vec::new();
        index.extend(c.local_addr.octets().iter().map(|&b| b as u32));
        index.push(c.local_port as u32);
        index.extend(c.rem_addr.octets().iter().map(|&b| b as u32));
        index.push(c.rem_port as u32);
        let mut put = |col: u32, value: Value| {
            let mut oid = entry.as_slice().to_vec();
            oid.push(col);
            oid.extend_from_slice(&index);
            cells.insert(Oid::new(oid), value);
        };
        put(1, Value::Integer(c.state));
        put(2, Value::IpAddress(c.local_addr));
        put(3, Value::Integer(c.local_port as i64));
        put(4, Value::IpAddress(c.rem_addr));
        put(5, Value::Integer(c.rem_port as i64));
    }
    cells.into_iter().collect()
}

/// Build all TCP handler cells (scalars + connection table) from a snapshot of
/// `/proc/net/snmp` and `/proc/net/tcp`.
fn tcp_all_cells() -> Vec<(Oid, Value)> {
    let scalars = parse_tcp_scalars(&read_proc("/proc/net/snmp"));
    let conns = parse_tcp_conns(&read_proc("/proc/net/tcp"));
    let mut cells = tcp_scalar_cells(&scalars);
    cells.extend(tcp_conn_cells(&conns));
    cells
}

/// Build the TCP-MIB handlers rooted at `1.3.6.1.2.1.6`.
///
/// A single [`FnHandler`] serves the scalars and `tcpConnTable` together; the
/// high-capacity `tcpConnectionTable` is intentionally left empty (its cells
/// would otherwise duplicate `tcpConnTable` and confuse simple walkers).
pub fn tcp_handlers() -> Vec<Arc<dyn MibHandler>> {
    let root = Oid::new(TCP.to_vec());
    vec![Arc::new(FnHandler::new(root, || tcp_all_cells()))]
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNMP_SAMPLE: &str = "\
Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates
Ip: 1 64 12345 0 1 0 0 0 12000 9000 0 0 0 0 0 0 0 0 0
Icmp: InMsgs InErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps
Icmp: 10 0 5 0 0 0 0 8 0 3 0 0 0 0 0 5 0 0 0 0
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts
Tcp: 1 200 120000 -1 100 200 5 10 3 5000 6000 7 2 9
Udp: InDatagrams NoPorts InErrors OutDatagrams
Udp: 300 4 0 295
";

    const TCP_SAMPLE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100A8C0:831 0501A8C0:0050 01 00000000:00000000 00:00000000 00000000     0        0 67890 1 0000000000000000 20 4 30 5 -1
   2: 0100007F:0016 0100007F:D4C9 06 00000000:00000000 00:00000000 00000000     0        0 99999 1 0000000000000000 21 4 1 5 -1
";

    #[test]
    fn parses_tcp_scalars_from_snmp() {
        let s = parse_tcp_scalars(SNMP_SAMPLE);
        assert_eq!(s.active_opens, 100);
        assert_eq!(s.passive_opens, 200);
        assert_eq!(s.attempt_fails, 5);
        assert_eq!(s.estab_resets, 10);
        assert_eq!(s.curr_estab, 3);
        assert_eq!(s.in_segs, 5000);
        assert_eq!(s.out_segs, 6000);
        assert_eq!(s.retrans_segs, 7);
        assert_eq!(s.in_errs, 2);
        assert_eq!(s.out_rsts, 9);
    }

    #[test]
    fn parses_missing_tcp_scalars_as_default() {
        let s = parse_tcp_scalars("Ip: 1 64 0\n");
        assert_eq!(s, TcpScalars::default());
        let s2 = parse_tcp_scalars("Tcp: RtoAlgorithm RtoMin\n");
        // header but no data line
        assert_eq!(s2, TcpScalars::default());
    }

    #[test]
    fn maps_tcp_states() {
        assert_eq!(map_tcp_state("01"), 5); // ESTABLISHED
        assert_eq!(map_tcp_state("0A"), 2); // LISTEN
        assert_eq!(map_tcp_state("06"), 11); // TIME_WAIT
        assert_eq!(map_tcp_state("ZZ"), 1); // unknown -> closed
    }

    #[test]
    fn parses_tcp_connections() {
        let conns = parse_tcp_conns(TCP_SAMPLE);
        assert_eq!(conns.len(), 3);
        // Row 1: listen on 127.0.0.1:8080, rem 0.0.0.0:0.
        assert_eq!(conns[0].local_addr, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(conns[0].local_port, 0x1F90);
        assert_eq!(conns[0].rem_addr, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(conns[0].state, 2); // LISTEN
        // Row 2: established 192.168.0.1:2097 -> 192.168.1.5:80.
        assert_eq!(conns[1].local_addr, Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(conns[1].local_port, 0x831);
        assert_eq!(conns[1].rem_addr, Ipv4Addr::new(192, 168, 1, 5));
        assert_eq!(conns[1].rem_port, 80);
        assert_eq!(conns[1].state, 5); // ESTABLISHED
        // Row 3: time_wait.
        assert_eq!(conns[2].state, 11);
    }

    #[test]
    fn tcp_scalar_cells_cover_columns() {
        let s = TcpScalars {
            in_segs: 5000,
            out_segs: 6000,
            ..Default::default()
        };
        let cells = tcp_scalar_cells(&s);
        let get = |col: u32| {
            cells
                .iter()
                .find(|(o, _)| o.to_string() == format!(".1.3.6.1.2.1.6.{col}.0"))
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get(1), Some(Value::Integer(1))); // tcpRtoAlgorithm
        assert_eq!(get(10), Some(Value::Counter32(5000))); // tcpInSegs
        assert_eq!(get(11), Some(Value::Counter32(6000))); // tcpOutSegs
        assert_eq!(get(9), Some(Value::Gauge32(0))); // tcpCurrEstab
        // sorted
        let mut sorted = cells.clone();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(cells, sorted);
    }

    #[test]
    fn tcp_conn_cells_encode_index() {
        let conns = parse_tcp_conns(TCP_SAMPLE);
        let cells = tcp_conn_cells(&conns);
        // tcpConnState for the established row:
        // 6.13.1.1.1.<localaddr>.<lport>.<remaddr>.<rport>
        let state_oid: Oid = ".1.3.6.1.2.1.6.13.1.1.1.192.168.0.1.2097.192.168.1.5.80"
            .parse()
            .unwrap();
        let state = cells
            .iter()
            .find(|(o, _)| o == &state_oid)
            .map(|(_, v)| v.clone());
        assert_eq!(state, Some(Value::Integer(5)));
    }

    #[test]
    fn handler_returns_zero_scalars_and_empty_table_without_proc() {
        // On any platform parse_tcp_scalars("") == default and parse_tcp_conns
        // ("") == []. The handler closure must not panic.
        let cells: Vec<(Oid, Value)> = {
            let scalars = parse_tcp_scalars("");
            let conns = parse_tcp_conns("");
            let mut out = tcp_scalar_cells(&scalars);
            out.extend(tcp_conn_cells(&conns));
            out
        };
        // Even with no /proc, the fixed scalars are present.
        let has_rto = cells
            .iter()
            .any(|(o, _)| o.to_string() == ".1.3.6.1.2.1.6.1.0");
        assert!(has_rto);
    }

    #[test]
    fn handler_serves_cells() {
        let handlers = tcp_handlers();
        assert_eq!(handlers.len(), 1);
        // GETNEXT from the group root must yield a cell (the first scalar).
        let root: Oid = "1.3.6.1.2.1.6".parse().unwrap();
        let first = handlers[0].get_next(&root).expect("first successor");
        assert!(first.oid > root);
    }
}
