//! SNMP-VIEW-BASED-ACM-MIB (`1.3.6.1.6.3.16`) live tables.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/mibII/vacm_conf.c` table-serving
//! portion. Exposes the four VACM tables as walkable (read-only) MIB handlers
//! backed by a shared [`Arc<Vacm>`](crate::vacm::Vacm):
//!
//! | Table                          | OID                       |
//! |--------------------------------|---------------------------|
//! | `vacmContextTable`             | `1.3.6.1.6.3.16.1.1`      |
//! | `vacmSecurityToGroupTable`     | `1.3.6.1.6.3.16.1.2`      |
//! | `vacmAccessTable`              | `1.3.6.1.6.3.16.1.4`      |
//! | `vacmViewTreeFamilyTable`      | `1.3.6.1.6.3.16.1.5`      |
//!
//! The handlers rebuild their cell snapshot on each read, so rows added or
//! removed through the [`Vacm`] API (e.g. by a future writable-RowStatus
//! implementation, or by `from_config_directives`) are immediately visible to
//! walkers. Column numbers and index encodings match the RFC 3415 MIB and the
//! SET constructors in `netsnmp-apps::mgmt` (so `snmpvacm` walks of this agent
//! produce the same OIDs it would SET).

use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;
use crate::vacm::{ContextMatch, Vacm};

/// `vacmContextEntry`: `1.3.6.1.6.3.16.1.1`.
const VACM_CONTEXT_ENTRY: [u32; 9] = [1, 3, 6, 1, 6, 3, 16, 1, 1];
/// `vacmSecurityToGroupEntry`: `1.3.6.1.6.3.16.1.2.1`.
const VACM_S2G_ENTRY: [u32; 10] = [1, 3, 6, 1, 6, 3, 16, 1, 2, 1];
/// `vacmAccessEntry`: `1.3.6.1.6.3.16.1.4.1`.
const VACM_ACCESS_ENTRY: [u32; 10] = [1, 3, 6, 1, 6, 3, 16, 1, 4, 1];
/// `vacmViewTreeFamilyEntry`: `1.3.6.1.6.3.16.1.5.2.1`.
const VACM_VIEW_ENTRY: [u32; 11] = [1, 3, 6, 1, 6, 3, 16, 1, 5, 2, 1];

// Column numbers inside each entry (from SNMP-VIEW-BASED-ACM-MIB).
/// `vacmContextName` (col 1 of vacmContextEntry; also the index).
const CTX_NAME: u32 = 1;
/// `vacmGroupName` (col 3 of vacmSecurityToGroupEntry).
const S2G_GROUP_NAME: u32 = 3;
/// `vacmSecurityToGroupStorageType` (col 4).
const S2G_STORAGE_TYPE: u32 = 4;
/// `vacmSecurityToGroupStatus` (col 5).
const S2G_STATUS: u32 = 5;
/// `vacmAccessContextMatch` (col 4 of vacmAccessEntry).
const ACC_CONTEXT_MATCH: u32 = 4;
/// `vacmAccessReadViewName` (col 5).
const ACC_READ_VIEW: u32 = 5;
/// `vacmAccessWriteViewName` (col 6).
const ACC_WRITE_VIEW: u32 = 6;
/// `vacmAccessNotifyViewName` (col 7).
const ACC_NOTIFY_VIEW: u32 = 7;
/// `vacmAccessStorageType` (col 8).
const ACC_STORAGE_TYPE: u32 = 8;
/// `vacmAccessStatus` (col 9).
const ACC_STATUS: u32 = 9;
/// `vacmViewTreeFamilyMask` (col 3 of vacmViewTreeFamilyEntry).
const VIEW_MASK: u32 = 3;
/// `vacmViewTreeFamilyType` (col 4).
const VIEW_TYPE: u32 = 4;
/// `vacmViewTreeFamilyStorageType` (col 5).
const VIEW_STORAGE_TYPE: u32 = 5;
/// `vacmViewTreeFamilyStatus` (col 6).
const VIEW_STATUS: u32 = 6;

/// The conventional `StorageType` value reported for VACM rows created from
/// configuration: `volatile(2)`. A future writable-RowStatus implementation
/// would let a manager change this; for now every row is read-only volatile.
const STORAGE_VOLATILE: i64 = 2;
/// The `RowStatus` value reported for active VACM rows: `active(1)`.
const STATUS_ACTIVE: i64 = 1;

/// Encode a variable-length OCTET STRING index as MIB sub-identifiers: a
/// leading length octet followed by one sub-identifier per byte. Matches the
/// ` IMPLIED`-free INDEX encoding used by `netsnmp-apps::mgmt::string_index`.
fn string_index(bytes: &[u8]) -> Vec<u32> {
    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.push(bytes.len() as u32);
    out.extend(bytes.iter().map(|&b| b as u32));
    out
}

/// Encode an OBJECT IDENTIFIER index (length-prefixed), for
/// `vacmViewTreeFamilySubtree`. Matches `netsnmp-apps::mgmt::oid_index`.
fn oid_index(oid: &Oid) -> Vec<u32> {
    let mut out = Vec::with_capacity(oid.len() + 1);
    out.push(oid.len() as u32);
    out.extend_from_slice(oid.as_slice());
    out
}

/// Build the `vacmContextTable` cells. Each registered context name yields a
/// single `vacmContextName` cell (the context name is the table's index, and
/// is the only column).
fn context_cells(vacm: &Vacm) -> Vec<(Oid, Value)> {
    let entry = Oid::new(VACM_CONTEXT_ENTRY.to_vec());
    vacm.contexts()
        .into_iter()
        .map(|ctx| {
            let idx = string_index(&ctx);
            let oid = {
                let mut p = entry.as_slice().to_vec();
                p.push(CTX_NAME);
                p.extend_from_slice(&idx);
                Oid::new(p)
            };
            (oid, Value::OctetString(ctx))
        })
        .collect()
}

/// Build the `vacmSecurityToGroupTable` cells. INDEX is
/// `{ vacmSecurityModel, vacmSecurityName }` (model as a plain sub-identifier,
/// name length-prefixed). Columns: groupName(3), storageType(4), status(5).
fn s2g_cells(vacm: &Vacm) -> Vec<(Oid, Value)> {
    let entry = Oid::new(VACM_S2G_ENTRY.to_vec());
    let mut cells = Vec::new();
    for g in vacm.groups() {
        let mut idx = vec![g.security_model as u32];
        idx.extend(string_index(&g.security_name));
        let cell = |col: u32| {
            let mut p = entry.as_slice().to_vec();
            p.push(col);
            p.extend_from_slice(&idx);
            Oid::new(p)
        };
        cells.push((cell(S2G_GROUP_NAME), Value::OctetString(g.group.clone())));
        cells.push((cell(S2G_STORAGE_TYPE), Value::Integer(STORAGE_VOLATILE)));
        cells.push((cell(S2G_STATUS), Value::Integer(STATUS_ACTIVE)));
    }
    cells
}

/// Build the `vacmAccessTable` cells. INDEX is
/// `{ vacmGroupName, vacmAccessContextPrefix, vacmAccessSecurityModel,
///    vacmAccessSecurityLevel }` (the two strings length-prefixed, the two
/// integers as plain sub-identifiers). Columns: contextMatch(4), readView(5),
/// writeView(6), notifyView(7), storageType(8), status(9).
fn access_cells(vacm: &Vacm) -> Vec<(Oid, Value)> {
    let entry = Oid::new(VACM_ACCESS_ENTRY.to_vec());
    let mut cells = Vec::new();
    for a in vacm.access() {
        let mut idx = string_index(&a.group);
        idx.extend(string_index(&a.context_prefix));
        idx.push(a.security_model as u32);
        idx.push(a.security_level as u32);
        let cell = |col: u32| {
            let mut p = entry.as_slice().to_vec();
            p.push(col);
            p.extend_from_slice(&idx);
            Oid::new(p)
        };
        let context_match = match a.context_match {
            ContextMatch::Exact => 1i64,
            ContextMatch::Prefix => 2,
        };
        let view_or_empty = |v: &Option<Vec<u8>>| match v {
            Some(name) => Value::OctetString(name.clone()),
            None => Value::OctetString(Vec::new()),
        };
        cells.push((cell(ACC_CONTEXT_MATCH), Value::Integer(context_match)));
        cells.push((cell(ACC_READ_VIEW), view_or_empty(&a.read_view)));
        cells.push((cell(ACC_WRITE_VIEW), view_or_empty(&a.write_view)));
        cells.push((cell(ACC_NOTIFY_VIEW), view_or_empty(&a.notify_view)));
        cells.push((cell(ACC_STORAGE_TYPE), Value::Integer(STORAGE_VOLATILE)));
        cells.push((cell(ACC_STATUS), Value::Integer(STATUS_ACTIVE)));
    }
    cells
}

/// Build the `vacmViewTreeFamilyTable` cells. INDEX is
/// `{ vacmViewTreeFamilyViewName, vacmViewTreeFamilySubtree }` (the name
/// length-prefixed, the subtree length-prefixed). Columns: mask(3), type(4),
/// storageType(5), status(6). The subtree (col 1) and view name (col 2) are
/// part of the index and not separately exposed.
fn view_cells(vacm: &Vacm) -> Vec<(Oid, Value)> {
    let entry = Oid::new(VACM_VIEW_ENTRY.to_vec());
    let mut cells = Vec::new();
    for (view_name, rows) in vacm.views() {
        for row in rows {
            let mut idx = string_index(&view_name);
            idx.extend(oid_index(&row.subtree));
            let cell = |col: u32| {
                let mut p = entry.as_slice().to_vec();
                p.push(col);
                p.extend_from_slice(&idx);
                Oid::new(p)
            };
            cells.push((cell(VIEW_MASK), Value::OctetString(row.mask.clone())));
            cells.push((cell(VIEW_TYPE), Value::Integer(row.typ.code())));
            cells.push((cell(VIEW_STORAGE_TYPE), Value::Integer(STORAGE_VOLATILE)));
            cells.push((cell(VIEW_STATUS), Value::Integer(STATUS_ACTIVE)));
        }
    }
    cells
}

/// Build the read-only VACM MIB handlers rooted at `1.3.6.1.6.3.16`, backed by
/// the shared `vacm` state. Returns one handler per table so each subtree is
/// served independently (and GETNEXT walks across them in OID order).
///
/// The handlers rebuild their cell snapshot on each read via [`Vacm`]'s
/// snapshot accessors, so configuration changes take effect immediately for
/// walkers. All rows are reported as `volatile(2)` / `active(1)`; a future
/// writable-RowStatus implementation (Task 5.8) can layer SET support on top.
pub fn vacm_handlers(vacm: Arc<Vacm>) -> Vec<Arc<dyn MibHandler>> {
    // Each handler clones the Arc<Vacm> into its closure so it survives
    // independently of the caller's handle.
    let v1 = Arc::clone(&vacm);
    let v2 = Arc::clone(&vacm);
    let v3 = Arc::clone(&vacm);
    let v4 = vacm;
    vec![
        Arc::new(FnHandler::new(
            Oid::new(VACM_CONTEXT_ENTRY.to_vec()),
            move || context_cells(&v1),
        )),
        Arc::new(FnHandler::new(
            Oid::new(VACM_S2G_ENTRY.to_vec()),
            move || s2g_cells(&v2),
        )),
        Arc::new(FnHandler::new(
            Oid::new(VACM_ACCESS_ENTRY.to_vec()),
            move || access_cells(&v3),
        )),
        Arc::new(FnHandler::new(
            Oid::new(VACM_VIEW_ENTRY.to_vec()),
            move || view_cells(&v4),
        )),
    ]
}

/// Register the VACM live MIB tables into `registry`, backed by `vacm`.
///
/// Convenience wrapper around [`vacm_handlers`] for callers that already hold a
/// `&mut Registry` (e.g. `register_framework_mibs`-style setup).
pub fn register_vacm_mibs(registry: &mut crate::registry::Registry, vacm: Arc<Vacm>) {
    for handler in vacm_handlers(vacm) {
        registry.register(handler);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vacm::ViewTreeFamilyType;

    /// A `Vacm` with one context, one group, one access entry and one view row,
    /// mirroring a minimal `rocommunity public` configuration.
    fn sample_vacm() -> Arc<Vacm> {
        let vacm = Arc::new(Vacm::new());
        vacm.add_context(b"".to_vec());
        vacm.add_context(b"ctxA".to_vec());
        vacm.add_group(crate::vacm::VacmGroup {
            security_model: 2,
            security_name: b"public".to_vec(),
            group: b"g1".to_vec(),
        });
        vacm.add_access(crate::vacm::VacmAccess {
            group: b"g1".to_vec(),
            context_prefix: b"".to_vec(),
            security_model: 0,
            security_level: 0,
            context_match: ContextMatch::Prefix,
            read_view: Some(b"all".to_vec()),
            write_view: None,
            notify_view: None,
        });
        vacm.add_view(
            b"all".to_vec(),
            crate::vacm::VacmView {
                subtree: "1.3.6.1.2.1".parse().unwrap(),
                mask: vec![0xfe],
                typ: ViewTreeFamilyType::Included,
            },
        );
        vacm
    }

    #[test]
    fn context_table_exposes_registered_contexts() {
        let vacm = sample_vacm();
        let handler = &vacm_handlers(Arc::clone(&vacm))[0];
        // vacmContextName for the empty context: entry.1.<len=0>
        let oid: Oid = "1.3.6.1.6.3.16.1.1.1.0".parse().unwrap();
        assert_eq!(handler.get(&oid), Some(Value::OctetString(Vec::new())));
        // vacmContextName for "ctxA": entry.1.4.99.116.120.65
        let oid_a: Oid = "1.3.6.1.6.3.16.1.1.1.4.99.116.120.65".parse().unwrap();
        assert_eq!(
            handler.get(&oid_a),
            Some(Value::OctetString(b"ctxA".to_vec()))
        );
    }

    #[test]
    fn s2g_table_exposes_group_name() {
        let vacm = sample_vacm();
        let handler = &vacm_handlers(Arc::clone(&vacm))[1];
        // INDEX: model=2, name="public" -> [2, 6, 112,117,98,108,105,99].
        // vacmGroupName = col 3.
        // OID: ...1.2.1.3.2.6.112.117.98.108.105.99
        let oid: Oid = "1.3.6.1.6.3.16.1.2.1.3.2.6.112.117.98.108.105.99"
            .parse()
            .unwrap();
        assert_eq!(
            handler.get(&oid),
            Some(Value::OctetString(b"g1".to_vec()))
        );
        // storageType (col 4) and status (col 5) are present too.
        let st_oid: Oid = "1.3.6.1.6.3.16.1.2.1.4.2.6.112.117.98.108.105.99"
            .parse()
            .unwrap();
        assert_eq!(handler.get(&st_oid), Some(Value::Integer(2)));
        let status_oid: Oid = "1.3.6.1.6.3.16.1.2.1.5.2.6.112.117.98.108.105.99"
            .parse()
            .unwrap();
        assert_eq!(handler.get(&status_oid), Some(Value::Integer(1)));
    }

    #[test]
    fn access_table_exposes_views_and_context_match() {
        let vacm = sample_vacm();
        let handler = &vacm_handlers(Arc::clone(&vacm))[2];
        // INDEX: group="g1" -> [2, 103,49]; context="" -> [0]; model=0; level=0.
        // contextMatch = col 4; readView = col 5.
        let ctx_match_oid: Oid =
            "1.3.6.1.6.3.16.1.4.1.4.2.103.49.0.0.0".parse().unwrap();
        // prefix(2)
        assert_eq!(handler.get(&ctx_match_oid), Some(Value::Integer(2)));
        let read_oid: Oid =
            "1.3.6.1.6.3.16.1.4.1.5.2.103.49.0.0.0".parse().unwrap();
        assert_eq!(
            handler.get(&read_oid),
            Some(Value::OctetString(b"all".to_vec()))
        );
        // writeView is empty (None -> empty octet string).
        let write_oid: Oid =
            "1.3.6.1.6.3.16.1.4.1.6.2.103.49.0.0.0".parse().unwrap();
        assert_eq!(handler.get(&write_oid), Some(Value::OctetString(Vec::new())));
    }

    #[test]
    fn view_table_exposes_mask_and_type() {
        let vacm = sample_vacm();
        let handler = &vacm_handlers(Arc::clone(&vacm))[3];
        // INDEX: viewName="all" -> [3, 97,108,108]; subtree="1.3.6.1.2.1" ->
        // [6, 1,3,6,1,2,1]. mask = col 3; type = col 4.
        let mask_oid: Oid =
            "1.3.6.1.6.3.16.1.5.2.1.3.3.97.108.108.6.1.3.6.1.2.1"
                .parse()
                .unwrap();
        assert_eq!(handler.get(&mask_oid), Some(Value::OctetString(vec![0xfe])));
        let type_oid: Oid =
            "1.3.6.1.6.3.16.1.5.2.1.4.3.97.108.108.6.1.3.6.1.2.1"
                .parse()
                .unwrap();
        // Included = 1
        assert_eq!(handler.get(&type_oid), Some(Value::Integer(1)));
    }

    #[test]
    fn handlers_are_walkable_in_oid_order() {
        let vacm = sample_vacm();
        let handler = &vacm_handlers(Arc::clone(&vacm))[0];
        // GETNEXT from below the context table lands on the first context cell.
        let root: Oid = "1.3.6.1.6.3.16.1.1".parse().unwrap();
        let first = handler.get_next(&root).expect("first successor");
        assert!(first.oid > root);
        // The first context (empty, sorted before "ctxA") is at ...1.0.
        assert!(first.oid.to_string().starts_with(".1.3.6.1.6.3.16.1.1.1."));
    }

    #[test]
    fn register_into_registry_makes_tables_walkable() {
        use crate::registry::Registry;
        let vacm = sample_vacm();
        let mut reg = Registry::new();
        register_vacm_mibs(&mut reg, Arc::clone(&vacm));
        // GET on the vacmGroupName cell via the registry dispatch.
        let oid: Oid = "1.3.6.1.6.3.16.1.2.1.3.2.6.112.117.98.108.105.99"
            .parse()
            .unwrap();
        let pdu = netsnmp::pdu::Pdu::new(netsnmp::pdu::PduType::Get, 1).with_null_var(oid);
        let resp = reg.process(&pdu);
        assert_eq!(
            resp.variables[0].value,
            Value::OctetString(b"g1".to_vec())
        );
    }
}
