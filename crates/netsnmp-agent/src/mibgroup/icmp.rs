//! ICMP-MIB (`1.3.6.1.2.1.5`) — the `icmp` group of RFC 1213.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/mibII/icmp.c`. The 28 ICMP
//! counters are read from the `Icmp:` line of `/proc/net/snmp` on Linux. On any
//! platform where `/proc` is unavailable — or the parse fails — every counter
//! reports zero, so the handler never panics.
//!
//! Modern Linux kernels (`/proc/net/snmp`) carry an extended `Icmp:` line with
//! many more columns than RFC 1213 defines; only the RFC 1213 columns are
//! matched by name and reported here.

use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;

/// `icmp` group root: `1.3.6.1.2.1.5`.
const ICMP: [u32; 7] = [1, 3, 6, 1, 2, 1, 5];

/// Parsed ICMP scalar counters from the `Icmp:` line of `/proc/net/snmp`.
///
/// All 28 RFC 1213 counters are present. Fields that `/proc/net/snmp` does not
/// expose (or that are absent from the document) remain zero.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IcmpScalars {
    /// `icmpInMsgs`
    pub in_msgs: u32,
    /// `icmpInErrors`
    pub in_errors: u32,
    /// `icmpInDestUnreachs`
    pub in_dest_unreachs: u32,
    /// `icmpInTimeExcds`
    pub in_time_excds: u32,
    /// `icmpInParmProbs`
    pub in_parm_probs: u32,
    /// `icmpInSrcQuenchs`
    pub in_src_quenchs: u32,
    /// `icmpInRedirects`
    pub in_redirects: u32,
    /// `icmpInEchos`
    pub in_echos: u32,
    /// `icmpInEchoReps`
    pub in_echo_reps: u32,
    /// `icmpInTimestamps`
    pub in_timestamps: u32,
    /// `icmpInTimestampReps`
    pub in_timestamp_reps: u32,
    /// `icmpInAddrMasks`
    pub in_addr_masks: u32,
    /// `icmpInAddrMaskReps`
    pub in_addr_mask_reps: u32,
    /// `icmpOutMsgs`
    pub out_msgs: u32,
    /// `icmpOutErrors`
    pub out_errors: u32,
    /// `icmpOutDestUnreachs`
    pub out_dest_unreachs: u32,
    /// `icmpOutTimeExcds`
    pub out_time_excds: u32,
    /// `icmpOutParmProbs`
    pub out_parm_probs: u32,
    /// `icmpOutSrcQuenchs`
    pub out_src_quenchs: u32,
    /// `icmpOutRedirects`
    pub out_redirects: u32,
    /// `icmpOutEchos`
    pub out_echos: u32,
    /// `icmpOutEchoReps`
    pub out_echo_reps: u32,
    /// `icmpOutTimestamps`
    pub out_timestamps: u32,
    /// `icmpOutTimestampReps`
    pub out_timestamp_reps: u32,
    /// `icmpOutAddrMasks`
    pub out_addr_masks: u32,
    /// `icmpOutAddrMaskReps`
    pub out_addr_mask_reps: u32,
}

/// `(column, name, target)` triples mapping `/proc/net/snmp` column names to
/// the RFC 1213 scalar column number and the field of [`IcmpScalars`] it sets.
const COLUMN_MAP: &[(u32, &str, &str)] = &[
    // In counters (columns 1..13).
    (1, "InMsgs", "in_msgs"),
    (2, "InErrors", "in_errors"),
    (3, "InDestUnreachs", "in_dest_unreachs"),
    (4, "InTimeExcds", "in_time_excds"),
    (5, "InParmProbs", "in_parm_probs"),
    (6, "InSrcQuenchs", "in_src_quenchs"),
    (7, "InRedirects", "in_redirects"),
    (8, "InEchos", "in_echos"),
    (9, "InEchoReps", "in_echo_reps"),
    (10, "InTimestamps", "in_timestamps"),
    (11, "InTimestampReps", "in_timestamp_reps"),
    (12, "InAddrMasks", "in_addr_masks"),
    (13, "InAddrMaskReps", "in_addr_mask_reps"),
    // Out counters (columns 14..26).
    (14, "OutMsgs", "out_msgs"),
    (15, "OutErrors", "out_errors"),
    (16, "OutDestUnreachs", "out_dest_unreachs"),
    (17, "OutTimeExcds", "out_time_excds"),
    (18, "OutParmProbs", "out_parm_probs"),
    (19, "OutSrcQuenchs", "out_src_quenchs"),
    (20, "OutRedirects", "out_redirects"),
    (21, "OutEchos", "out_echos"),
    (22, "OutEchoReps", "out_echo_reps"),
    (23, "OutTimestamps", "out_timestamps"),
    (24, "OutTimestampReps", "out_timestamp_reps"),
    (25, "OutAddrMasks", "out_addr_masks"),
    (26, "OutAddrMaskReps", "out_addr_mask_reps"),
];

/// Parse the `Icmp:` scalars out of a `/proc/net/snmp`-style document.
///
/// Returns [`IcmpScalars::default`] when no `Icmp:` data line is found.
pub fn parse_icmp_scalars(snmp: &str) -> IcmpScalars {
    let mut lines = snmp.lines().filter(|l| l.starts_with("Icmp:"));
    let header = match lines.next() {
        Some(h) => h,
        None => return IcmpScalars::default(),
    };
    let data = match lines.next() {
        Some(d) => d,
        None => return IcmpScalars::default(),
    };
    let names: Vec<&str> = header["Icmp:".len()..].split_whitespace().collect();
    let vals: Vec<&str> = data["Icmp:".len()..].split_whitespace().collect();
    let mut out = IcmpScalars::default();
    for (name, val) in names.iter().zip(vals.iter()) {
        let v: u32 = val.parse().unwrap_or(0);
        for &(_, expected, field) in COLUMN_MAP {
            if *name == expected {
                set_field(&mut out, field, v);
                break;
            }
        }
    }
    out
}

/// Set a named field of `s` to `v`. Helper for [`parse_icmp_scalars`].
fn set_field(s: &mut IcmpScalars, field: &str, v: u32) {
    match field {
        "in_msgs" => s.in_msgs = v,
        "in_errors" => s.in_errors = v,
        "in_dest_unreachs" => s.in_dest_unreachs = v,
        "in_time_excds" => s.in_time_excds = v,
        "in_parm_probs" => s.in_parm_probs = v,
        "in_src_quenchs" => s.in_src_quenchs = v,
        "in_redirects" => s.in_redirects = v,
        "in_echos" => s.in_echos = v,
        "in_echo_reps" => s.in_echo_reps = v,
        "in_timestamps" => s.in_timestamps = v,
        "in_timestamp_reps" => s.in_timestamp_reps = v,
        "in_addr_masks" => s.in_addr_masks = v,
        "in_addr_mask_reps" => s.in_addr_mask_reps = v,
        "out_msgs" => s.out_msgs = v,
        "out_errors" => s.out_errors = v,
        "out_dest_unreachs" => s.out_dest_unreachs = v,
        "out_time_excds" => s.out_time_excds = v,
        "out_parm_probs" => s.out_parm_probs = v,
        "out_src_quenchs" => s.out_src_quenchs = v,
        "out_redirects" => s.out_redirects = v,
        "out_echos" => s.out_echos = v,
        "out_echo_reps" => s.out_echo_reps = v,
        "out_timestamps" => s.out_timestamps = v,
        "out_timestamp_reps" => s.out_timestamp_reps = v,
        "out_addr_masks" => s.out_addr_masks = v,
        "out_addr_mask_reps" => s.out_addr_mask_reps = v,
        _ => {}
    }
}

fn read_proc(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

/// Build the `icmp` scalar instance cells (OID -> value) for the given
/// counters, in RFC 1213 column order (1..26).
pub fn icmp_scalar_cells(scalars: &IcmpScalars) -> Vec<(Oid, Value)> {
    let root = Oid::new(ICMP.to_vec());
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    let values: [(u32, u32); 26] = [
        (1, scalars.in_msgs),
        (2, scalars.in_errors),
        (3, scalars.in_dest_unreachs),
        (4, scalars.in_time_excds),
        (5, scalars.in_parm_probs),
        (6, scalars.in_src_quenchs),
        (7, scalars.in_redirects),
        (8, scalars.in_echos),
        (9, scalars.in_echo_reps),
        (10, scalars.in_timestamps),
        (11, scalars.in_timestamp_reps),
        (12, scalars.in_addr_masks),
        (13, scalars.in_addr_mask_reps),
        (14, scalars.out_msgs),
        (15, scalars.out_errors),
        (16, scalars.out_dest_unreachs),
        (17, scalars.out_time_excds),
        (18, scalars.out_parm_probs),
        (19, scalars.out_src_quenchs),
        (20, scalars.out_redirects),
        (21, scalars.out_echos),
        (22, scalars.out_echo_reps),
        (23, scalars.out_timestamps),
        (24, scalars.out_timestamp_reps),
        (25, scalars.out_addr_masks),
        (26, scalars.out_addr_mask_reps),
    ];
    for (col, v) in values {
        cells.insert(root.child(col).child(0), Value::Counter32(v));
    }
    cells.into_iter().collect()
}

fn icmp_all_cells() -> Vec<(Oid, Value)> {
    let scalars = parse_icmp_scalars(&read_proc("/proc/net/snmp"));
    icmp_scalar_cells(&scalars)
}

/// Build the ICMP-MIB handlers rooted at `1.3.6.1.2.1.5`.
pub fn icmp_handlers() -> Vec<Arc<dyn MibHandler>> {
    let root = Oid::new(ICMP.to_vec());
    vec![Arc::new(FnHandler::new(root, || icmp_all_cells()))]
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNMP_SAMPLE: &str = "\
Icmp: InMsgs InErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps
Icmp: 10 0 5 0 0 0 0 0 5 0 0 0 0 8 0 3 0 0 0 0 0 5 0 0 0 0
";

    #[test]
    fn parses_icmp_scalars_from_snmp() {
        let s = parse_icmp_scalars(SNMP_SAMPLE);
        assert_eq!(s.in_msgs, 10);
        assert_eq!(s.in_errors, 0);
        assert_eq!(s.in_dest_unreachs, 5);
        assert_eq!(s.in_echo_reps, 5);
        assert_eq!(s.out_msgs, 8);
        assert_eq!(s.out_dest_unreachs, 3);
        assert_eq!(s.out_echo_reps, 5);
        assert_eq!(s.out_addr_mask_reps, 0);
    }

    #[test]
    fn parses_missing_icmp_scalars_as_default() {
        assert_eq!(parse_icmp_scalars("Tcp: 1\n"), IcmpScalars::default());
        assert_eq!(parse_icmp_scalars("Icmp: InMsgs\n"), IcmpScalars::default());
    }

    #[test]
    fn icmp_scalar_cells_cover_all_columns() {
        let s = parse_icmp_scalars(SNMP_SAMPLE);
        let cells = icmp_scalar_cells(&s);
        assert_eq!(cells.len(), 26);
        let get = |col: u32| {
            cells
                .iter()
                .find(|(o, _)| o.to_string() == format!(".1.3.6.1.2.1.5.{col}.0"))
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get(1), Some(Value::Counter32(10))); // icmpInMsgs
        assert_eq!(get(3), Some(Value::Counter32(5))); // icmpInDestUnreachs
        assert_eq!(get(14), Some(Value::Counter32(8))); // icmpOutMsgs
        assert_eq!(get(22), Some(Value::Counter32(5))); // icmpOutEchoReps
        // sorted
        let mut sorted = cells.clone();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(cells, sorted);
    }

    #[test]
    fn handler_returns_zero_scalars_without_proc() {
        let cells: Vec<(Oid, Value)> = {
            let scalars = parse_icmp_scalars("");
            icmp_scalar_cells(&scalars)
        };
        assert_eq!(cells.len(), 26);
        let get = |col: u32| {
            cells
                .iter()
                .find(|(o, _)| o.to_string() == format!(".1.3.6.1.2.1.5.{col}.0"))
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get(1), Some(Value::Counter32(0)));
    }

    #[test]
    fn handler_serves_cells() {
        let handlers = icmp_handlers();
        assert_eq!(handlers.len(), 1);
        let root: Oid = "1.3.6.1.2.1.5".parse().unwrap();
        let first = handlers[0].get_next(&root).expect("first successor");
        assert!(first.oid > root);
    }
}
