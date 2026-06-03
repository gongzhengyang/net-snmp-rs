//! Offline OID translation: `snmptranslate`.

use crate::check::Check;

use super::Params;

pub(super) fn checks(_p: &Params) -> Vec<Check> {
    vec![
        Check::new("snmptranslate", "name → numeric (-On)", "snmptranslate")
            .args(["-On", "sysName.0"])
            .offline()
            .contains("1.3.6.1.2.1.1.5"),
        Check::new("snmptranslate", "numeric → name", "snmptranslate")
            .args(["1.3.6.1.2.1.1.1.0"])
            .offline()
            .contains_any(["sysdescr", "1.3.6.1.2.1.1.1"]),
    ]
}
