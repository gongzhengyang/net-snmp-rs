//! GETBULK-based tools: `snmpbulkget` and `snmpbulkwalk`.

use crate::check::Check;

use super::{Params, v2};

pub(super) fn checks(p: &Params) -> Vec<Check> {
    vec![
        Check::new("snmpbulkget", "GETBULK repetitions", "snmpbulkget")
            .args(v2(p, &["--max-repetitions", "5", "1.3.6.1.2.1.2.2.1.2"]))
            .min_lines(1),
        Check::new("snmpbulkget", "GETBULK with non-repeaters", "snmpbulkget")
            .args(v2(
                p,
                &[
                    "--non-repeaters",
                    "1",
                    "--max-repetitions",
                    "3",
                    "sysDescr.0",
                    "1.3.6.1.2.1.2.2.1.2",
                ],
            ))
            .min_lines(2),
        Check::new("snmpbulkget", "reject GETBULK over SNMPv1", "snmpbulkget")
            .args([
                "-v",
                "1",
                "-c",
                p.community.as_str(),
                p.agent.as_str(),
                "1.3.6.1.2.1.2.2.1.2",
            ])
            .expect_fail()
            .hint("GETBULK requires SNMPv2c or v3; v1 must be refused."),
        Check::new("snmpbulkwalk", "bulk-walk ifTable", "snmpbulkwalk")
            .args(v2(p, &["1.3.6.1.2.1.2.2"]))
            .min_lines(3),
    ]
}
