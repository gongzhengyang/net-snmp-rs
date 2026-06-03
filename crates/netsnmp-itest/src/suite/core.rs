//! Core operations: GET, GETNEXT, WALK and SET.

use crate::check::Check;

use super::{Params, v2};

pub(super) fn checks(p: &Params) -> Vec<Check> {
    vec![
        // snmpget
        Check::new("snmpget", "GET multiple scalars", "snmpget")
            .args(v2(p, &["sysDescr.0", "sysName.0", "sysUpTime.0"]))
            .contains("sysDescr")
            .min_lines(3)
            .hint("Agent should serve the system group; check snmpd is registering mibII."),
        Check::new("snmpget", "GET by numeric OID", "snmpget")
            .args(v2(p, &["1.3.6.1.2.1.1.1.0"]))
            .contains("="),
        Check::new("snmpget", "GET nonexistent object", "snmpget")
            .args(v2(p, &["1.3.6.1.2.1.1.99.0"]))
            .best_effort()
            .contains_any(["no such", "nosuch"]),
        Check::new("snmpget", "reject malformed OID", "snmpget")
            .args(v2(p, &["this..is..not..an..oid"]))
            .offline()
            .expect_fail()
            .hint("snmpget should report an OID parse error, not crash."),
        // snmpgetnext
        Check::new("snmpgetnext", "GETNEXT walks forward", "snmpgetnext")
            .args(v2(p, &["sysDescr"]))
            .contains("sysdescr.0"),
        Check::new("snmpgetnext", "GETNEXT by numeric OID", "snmpgetnext")
            .args(v2(p, &["1.3.6.1.2.1.1.1"]))
            .contains("="),
        // snmpwalk
        Check::new("snmpwalk", "walk system group", "snmpwalk")
            .args(v2(p, &["1.3.6.1.2.1.1"]))
            .contains("sysDescr")
            .min_lines(5)
            .hint("The system group should expose ~7 scalars."),
        Check::new("snmpwalk", "walk ifTable", "snmpwalk")
            .args(v2(p, &["1.3.6.1.2.1.2.2"]))
            .min_lines(3),
        Check::new("snmpwalk", "walk full mib-2 subtree", "snmpwalk")
            .args(v2(p, &["1.3.6.1.2.1"]))
            .min_lines(8)
            .timeout_secs(30),
        // snmpset (writable scalars)
        Check::new("snmpset", "SET sysLocation", "snmpset")
            .args(v2(p, &["sysLocation.0", "s", "itest rack 9"]))
            .contains("sysLocation"),
        Check::new("snmpset", "SET sysContact", "snmpset")
            .args(v2(p, &["sysContact.0", "s", "itest@example.com"]))
            .contains("sysContact"),
        Check::new("snmpset", "reject non-triple arguments", "snmpset")
            .args(v2(p, &["sysName.0", "s"]))
            .offline()
            .expect_fail()
            .hint("Arguments must come in OID TYPE VALUE triples."),
    ]
}
