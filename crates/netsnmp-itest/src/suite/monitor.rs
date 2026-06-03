//! Time-sampling and interactive tools: `snmpdelta` and `snmptest`.

use crate::check::Check;

use super::{Params, v2};

pub(super) fn checks(p: &Params) -> Vec<Check> {
    vec![
        // snmpdelta
        Check::new("snmpdelta", "sample deltas over time", "snmpdelta")
            .args(v2(
                p,
                &["--period", "1", "--iterations", "2", "sysUpTime.0"],
            ))
            .timeout_secs(15)
            .min_lines(1),
        // snmptest (interactive)
        Check::new("snmptest", "interactive GET", "snmptest")
            .args(v2(p, &[]))
            .stdin("sysDescr.0\n$q\n")
            .contains("sysdescr"),
        Check::new("snmptest", "interactive GETNEXT + SET", "snmptest")
            .args(v2(p, &[]))
            .stdin("$N\nifDescr\n$G\n$S sysLocation.0 s itest-interactive\n$q\n")
            .contains_any(["ifdescr", "syslocation"]),
    ]
}
