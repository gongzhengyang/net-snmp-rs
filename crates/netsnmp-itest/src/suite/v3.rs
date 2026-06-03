//! SNMPv3 authPriv read path, exercising the full USM stack end to end.

use crate::check::Check;

use super::{Params, v3};

pub(super) fn checks(p: &Params) -> Vec<Check> {
    vec![
        Check::new("snmpv3", "GET over authPriv", "snmpget")
            .args(v3(p, &["sysDescr.0"]))
            .contains("sysDescr")
            .hint("Check the v3 user exists on the agent (createUser in snmpd.conf) and the auth/priv passphrases match."),
        Check::new("snmpv3", "walk system over authPriv", "snmpwalk")
            .args(v3(p, &["1.3.6.1.2.1.1"]))
            .min_lines(3),
        Check::new("snmpv3", "bulk-walk ifTable over authPriv", "snmpbulkwalk")
            .args(v3(p, &["1.3.6.1.2.1.2.2"]))
            .min_lines(3),
    ]
}
