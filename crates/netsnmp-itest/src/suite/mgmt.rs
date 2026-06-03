//! Remote management tools: `snmpusm` and `snmpvacm`. This agent does not
//! implement writable USM/VACM tables, so the SET-based operations are
//! expected to be rejected.

use crate::check::Check;

use super::{Params, v2, v3};

pub(super) fn checks(p: &Params) -> Vec<Check> {
    vec![
        // snmpusm
        Check::new("snmpusm", "delete user (rejected)", "snmpusm")
            .args(v3(p, &["delete", "bob"]))
            .expect_fail()
            .contains_any(["notwritable", "error"])
            .hint("This agent does not implement a writable usmUserTable; rejection is expected."),
        Check::new("snmpusm", "create user (rejected)", "snmpusm")
            .args(v3(p, &["create", "newuser", "bob"]))
            .expect_fail(),
        Check::new("snmpusm", "missing engine id (v2c)", "snmpusm")
            .args(v2(p, &["delete", "bob"]))
            .expect_fail()
            .contains_any(["engine", "id"])
            .hint("USM management needs an engine ID; supply -v 3 or --engine-id."),
        Check::new("snmpusm", "unknown operation", "snmpusm")
            .args(v3(p, &["frobnicate", "bob"]))
            .expect_fail()
            .contains("unknown operation"),
        // snmpvacm
        Check::new("snmpvacm", "create view (rejected)", "snmpvacm")
            .args(v3(p, &["createview", "itestview", "1.3.6.1.2.1"]))
            .expect_fail()
            .contains_any(["notwritable", "error"])
            .hint("This agent does not implement writable vacm*Tables; rejection is expected."),
        Check::new("snmpvacm", "create sec2group (rejected)", "snmpvacm")
            .args(v3(p, &["createsec2group", "3", "bob", "itestgroup"]))
            .expect_fail(),
    ]
}
