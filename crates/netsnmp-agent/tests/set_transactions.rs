//! Integration tests for Wave 3: SET 4-phase transactions (Task 5.7),
//! RowStatus row lifecycle (Task 5.8) and the table helpers toolbox
//! (Task 5.9).
//!
//! These tests drive the agent's [`Registry`] directly with hand-built PDUs
//! (no socket) so they are fast and deterministic. The end-to-end SET path
//! over UDP is covered separately by `end_to_end.rs` / `v3_end_to_end.rs`,
//! which must remain green.

use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::pdu::{ErrorStatus, Pdu, PduType, VarBind};
use netsnmp::value::Value;
use netsnmp_agent::{
    helpers, read_only, MibHandler, Registry, RowStatus, ScalarHandler, TableDataSet, TableHandler,
};

/// Register two writable scalars A and B. SET [A=X, B=illegal-value]. The
/// response must report the error on varbind 2, and a subsequent GET of A
/// must return the OLD value: nothing was committed.
#[test]
fn multi_varbind_set_atomicity() {
    let mut reg = Registry::new();
    let a: Oid = "1.3.6.1.2.1.99.1".parse().unwrap();
    let b: Oid = "1.3.6.1.2.1.99.2".parse().unwrap();
    reg.register(Arc::new(
        ScalarHandler::new(a.clone(), Value::OctetString(b"old-a".to_vec())).writable(),
    ));
    reg.register(Arc::new(
        ScalarHandler::new(b.clone(), Value::OctetString(b"old-b".to_vec())).writable(),
    ));

    let mut pdu = Pdu::new(PduType::Set, 1);
    pdu.variables.push(VarBind::new(
        a.child(0),
        Value::OctetString(b"new-a".to_vec()),
    ));
    // Wrong type for B (Integer onto OctetString scalar): reserve fails.
    pdu.variables
        .push(VarBind::new(b.child(0), Value::Integer(99)));
    let resp = reg.process(&pdu);
    assert_eq!(resp.status(), ErrorStatus::WrongType);
    assert_eq!(resp.error_index, 2);

    // A retains its old value: no commit happened.
    let get_a = Pdu::new(PduType::Get, 2).with_null_var(a.child(0));
    let resp_a = reg.process(&get_a);
    assert_eq!(
        resp_a.variables[0].value,
        Value::OctetString(b"old-a".to_vec())
    );
}

/// SET a single writable scalar; GET returns the new value. This exercises
/// the happy path of reserve1 + reserve2 + commit.
#[test]
fn reserve_then_commit_visible() {
    let mut reg = Registry::new();
    let s: Oid = "1.3.6.1.2.1.99.3".parse().unwrap();
    reg.register(Arc::new(
        ScalarHandler::new(s.clone(), Value::OctetString(b"before".to_vec())).writable(),
    ));

    let mut pdu = Pdu::new(PduType::Set, 1);
    pdu.variables.push(VarBind::new(
        s.child(0),
        Value::OctetString(b"after".to_vec()),
    ));
    let resp = reg.process(&pdu);
    assert_eq!(resp.status(), ErrorStatus::NoError);

    let get = Pdu::new(PduType::Get, 2).with_null_var(s.child(0));
    let resp = reg.process(&get);
    assert_eq!(
        resp.variables[0].value,
        Value::OctetString(b"after".to_vec())
    );
}

/// A TableHandler with rows that skip some columns; GETNEXT walks the
/// lexicographic successors correctly without emitting `noSuchInstance` mid
/// walk.
#[test]
fn table_handler_getnext_sparse_columns() {
    let root: Oid = "1.3.6.1.2.1.555".parse().unwrap();
    let start = root.clone();
    let h = TableHandler::new(root, vec![1, 2, 3], || {
        vec![
            helpers::Row::new(vec![10])
                .with(1, Value::Integer(110))
                .with(3, Value::Integer(130)),
            // Row 20 only has column 2.
            helpers::Row::new(vec![20]).with(2, Value::Integer(220)),
        ]
    });
    let mut reg = Registry::new();
    reg.register(Arc::new(h));

    let mut current = start;
    let mut walk = Vec::new();
    loop {
        let pdu = Pdu::new(PduType::GetNext, 1).with_null_var(current);
        let resp = reg.process(&pdu);
        let vb = &resp.variables[0];
        if vb.value == Value::EndOfMibView {
            break;
        }
        walk.push((vb.oid.to_string(), vb.value.clone()));
        current = vb.oid.clone();
    }

    // Column-major lexicographic order, skipping the sparse cells:
    //  .1.10 (col1,row10) .2.20 (col2,row20) .3.10 (col3,row10)
    assert_eq!(
        walk,
        vec![
            (
                ".1.3.6.1.2.1.555.1.10".to_string(),
                Value::Integer(110)
            ),
            (
                ".1.3.6.1.2.1.555.2.20".to_string(),
                Value::Integer(220)
            ),
            (
                ".1.3.6.1.2.1.555.3.10".to_string(),
                Value::Integer(130)
            ),
        ]
    );
}

/// A TableDataSet with a RowStatus column + required columns; SET
/// rowStatus=createAndGo with required cols present -> row appears (GET
/// returns values); SET createAndGo without required cols ->
/// inconsistentName.
#[test]
fn rowstatus_create_and_go() {
    let root: Oid = "1.3.6.1.2.1.556".parse().unwrap();
    let table: Arc<dyn MibHandler> = Arc::new(
        TableDataSet::new(root, vec![1, 2, 3])
            .with_row_status_column(1)
            .with_required_columns(&[2]),
    );
    let mut reg = Registry::new();
    reg.register(table);

    // Pre-stage the name (col 2), then createAndGo (col 1 = 4).
    let name_oid: Oid = "1.3.6.1.2.1.556.2.5".parse().unwrap();
    let status_oid: Oid = "1.3.6.1.2.1.556.1.5".parse().unwrap();

    let stage = Pdu::new(PduType::Set, 1).with_var(
        name_oid.clone(),
        Value::OctetString(b"alpha".to_vec()),
    );
    let resp = reg.process(&stage);
    assert_eq!(resp.status(), ErrorStatus::NoError);

    let create = Pdu::new(PduType::Set, 2).with_var(status_oid.clone(), Value::Integer(4));
    let resp = reg.process(&create);
    assert_eq!(resp.status(), ErrorStatus::NoError);

    // RowStatus reads back as active(1), name as "alpha".
    let get = Pdu::new(PduType::Get, 3)
        .with_null_var(status_oid.clone())
        .with_null_var(name_oid.clone());
    let resp = reg.process(&get);
    assert_eq!(resp.variables[0].value, Value::Integer(1));
    assert_eq!(
        resp.variables[1].value,
        Value::OctetString(b"alpha".to_vec())
    );

    // createAndGo on a fresh index WITHOUT the required column ->
    // inconsistentName.
    let bad_status: Oid = "1.3.6.1.2.1.556.1.6".parse().unwrap();
    let create_bad = Pdu::new(PduType::Set, 4).with_var(bad_status, Value::Integer(4));
    let resp = reg.process(&create_bad);
    assert_eq!(resp.status(), ErrorStatus::InconsistentName);
}

/// SET destroy on a RowStatus row -> row gone (GET -> noSuchInstance).
#[test]
fn rowstatus_destroy() {
    let root: Oid = "1.3.6.1.2.1.557".parse().unwrap();
    let table = Arc::new(
        TableDataSet::new(root, vec![1, 2])
            .with_row_status_column(1)
            .with_required_columns(&[2]),
    );
    // Keep a typed Arc for direct runtime access via `put`, register a clone.
    let for_table = Arc::clone(&table);
    let mut reg = Registry::new();
    reg.register(for_table as Arc<dyn MibHandler>);

    // Build a row directly via the runtime API, then destroy via SET.
    table.put(1, &[7], Value::Integer(1)); // active
    table.put(2, &[7], Value::OctetString(b"hi".to_vec()));

    let status_oid: Oid = "1.3.6.1.2.1.557.1.7".parse().unwrap();
    let name_oid: Oid = "1.3.6.1.2.1.557.2.7".parse().unwrap();

    let destroy = Pdu::new(PduType::Set, 1).with_var(status_oid.clone(), Value::Integer(6));
    let resp = reg.process(&destroy);
    assert_eq!(resp.status(), ErrorStatus::NoError);

    // The row is gone: GET -> noSuchInstance.
    let get = Pdu::new(PduType::Get, 2)
        .with_null_var(status_oid)
        .with_null_var(name_oid);
    let resp = reg.process(&get);
    assert_eq!(resp.variables[0].value, Value::NoSuchInstance);
    assert_eq!(resp.variables[1].value, Value::NoSuchInstance);
}

/// Wrap a writable handler in `read_only`; SET -> NotWritable.
#[test]
fn read_only_wrapper_blocks_set() {
    let mut reg = Registry::new();
    let s: Oid = "1.3.6.1.2.1.99.4".parse().unwrap();
    let inner: Arc<dyn MibHandler> = Arc::new(
        ScalarHandler::new(s.clone(), Value::OctetString(b"v".to_vec())).writable(),
    );
    reg.register(read_only(inner));

    let mut pdu = Pdu::new(PduType::Set, 1);
    pdu.variables.push(VarBind::new(
        s.child(0),
        Value::OctetString(b"new".to_vec()),
    ));
    let resp = reg.process(&pdu);
    assert_eq!(resp.status(), ErrorStatus::NotWritable);
    assert_eq!(resp.error_index, 1);

    // GET still works through the wrapper.
    let get = Pdu::new(PduType::Get, 2).with_null_var(s.child(0));
    let resp = reg.process(&get);
    assert_eq!(
        resp.variables[0].value,
        Value::OctetString(b"v".to_vec())
    );
}

/// A MapHandler integrated with the RowStatus state machine at the row level:
/// exercises `RowStatus::transition` directly for an existing row taken out
/// of service and back.
#[test]
fn rowstatus_active_notinservice_roundtrip() {
    // Use the transition() function directly on a row we model as a Map.
    let _ = RowStatus::Active; // sanity: the type is re-exported.
    let active_to_nis = netsnmp_agent::row::transition(
        Some(RowStatus::Active),
        RowStatus::NotInService,
        true,
    )
    .unwrap();
    assert_eq!(active_to_nis, Some(RowStatus::NotInService));
    let nis_to_active = netsnmp_agent::row::transition(
        Some(RowStatus::NotInService),
        RowStatus::Active,
        true,
    )
    .unwrap();
    assert_eq!(nis_to_active, Some(RowStatus::Active));
}
