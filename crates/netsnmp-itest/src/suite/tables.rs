//! Tabular and summary tools: `snmptable`, `snmpstatus`, `snmpdf`, `snmpps`
//! and `snmpnetstat`.

use crate::check::Check;

use super::{Params, v2};

pub(super) fn checks(p: &Params) -> Vec<Check> {
    vec![
        // snmptable
        Check::new("snmptable", "render ifTable", "snmptable")
            .args(v2(p, &["1.3.6.1.2.1.2.2.1"]))
            .contains("index")
            .min_lines(2)
            .hint("Needs at least one ifTable row from the agent."),
        // snmpstatus
        Check::new("snmpstatus", "device summary", "snmpstatus")
            .args(v2(p, &[]))
            .min_lines(1),
        // disk / process / netstat
        Check::new("snmpdf", "disk usage (hrStorageTable)", "snmpdf")
            .args(v2(p, &[]))
            .best_effort()
            .min_lines(1),
        Check::new("snmpps", "process list (hrSWRunTable)", "snmpps")
            .args(v2(p, &[]))
            .best_effort()
            .min_lines(1),
        Check::new("snmpnetstat", "connections (all protocols)", "snmpnetstat").args(v2(p, &[])),
        Check::new("snmpnetstat", "TCP table only", "snmpnetstat").args([
            "-v",
            "2c",
            "-c",
            p.community.as_str(),
            "--protocol",
            "tcp",
            p.agent.as_str(),
        ]),
        Check::new("snmpnetstat", "UDP table only", "snmpnetstat").args([
            "-v",
            "2c",
            "-c",
            p.community.as_str(),
            "--protocol",
            "udp",
            p.agent.as_str(),
        ]),
    ]
}
