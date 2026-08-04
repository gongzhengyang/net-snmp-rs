//! End-to-end integration tests for VACM (RFC 3415) access control.
//!
//! A real `netsnmp` v2c client talks to a real `netsnmp-agent` over a UDP
//! loopback socket. The agent is configured with a [`Vacm`] that grants or
//! denies the `public` community read/write access to specific subtrees, and
//! the tests assert the on-the-wire behaviour matches RFC 3415 / net-snmp:
//!
//! * GET on an inaccessible OID returns `noAccess`.
//! * GETNEXT skips inaccessible OIDs (no leak).
//! * A walk of a fully-denied subtree returns empty.
//! * An empty VACM is permissive (backwards compatible).

use std::sync::Arc;
use std::time::Duration;

use netsnmp::oid::Oid;
use netsnmp::pdu::VarBind;
use netsnmp::session::{Session, SessionConfig};
use netsnmp::value::Value;
use netsnmp_agent::{
    AccessView, Agent, AgentConfig, ContextMatch, Registry, ScalarHandler, Vacm, VacmAccess,
    VacmGroup, VacmView, ViewTreeFamilyType,
};

/// A `Vacm` that grants community `public` read access to *only* the `system`
/// group (`1.3.6.1.2.1.1`) and write access to `sysName` (`1.3.6.1.2.1.1.5`).
/// Everything else (interfaces, etc.) is invisible to `public`.
fn restricted_vacm() -> Arc<Vacm> {
    let vacm = Arc::new(Vacm::new());
    vacm.add_group(VacmGroup {
        security_model: 2,
        security_name: b"public".to_vec(),
        group: b"g1".to_vec(),
    });
    vacm.add_access(VacmAccess {
        group: b"g1".to_vec(),
        context_prefix: Vec::new(),
        security_model: 0,
        security_level: 0,
        context_match: ContextMatch::Prefix,
        read_view: Some(b"system".to_vec()),
        write_view: Some(b"sysname".to_vec()),
        notify_view: None,
    });
    vacm.add_view(
        b"system".to_vec(),
        VacmView {
            subtree: "1.3.6.1.2.1.1".parse().unwrap(),
            mask: Vec::new(),
            typ: ViewTreeFamilyType::Included,
        },
    );
    vacm.add_view(
        b"sysname".to_vec(),
        VacmView {
            subtree: "1.3.6.1.2.1.1.5".parse().unwrap(),
            mask: Vec::new(),
            typ: ViewTreeFamilyType::Included,
        },
    );
    vacm
}

/// Spawn an agent on an ephemeral loopback port with the given VACM state and
/// return its bound address. The agent serves a sysDescr and a sysName scalar
/// plus two interface rows, exactly as the end_to_end fixture does.
async fn spawn_agent_with_vacm(vacm: Arc<Vacm>) -> String {
    let mut reg = Registry::new();
    reg.register(Arc::new(ScalarHandler::new(
        "1.3.6.1.2.1.1.1".parse().unwrap(),
        Value::OctetString(b"vacm agent".to_vec()),
    )));
    reg.register(Arc::new(
        ScalarHandler::new(
            "1.3.6.1.2.1.1.5".parse().unwrap(),
            Value::OctetString(b"host-a".to_vec()),
        )
        .writable(),
    ));
    let if_descr: Oid = "1.3.6.1.2.1.2.2.1.2".parse().unwrap();
    reg.register(Arc::new(
        netsnmp_agent::MapHandler::new(if_descr.clone())
            .with(if_descr.child(1), Value::OctetString(b"lo".to_vec()))
            .with(if_descr.child(2), Value::OctetString(b"eth0".to_vec())),
    ));

    let config = AgentConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        community: b"public".to_vec(),
        vacm: Some(vacm),
        ..AgentConfig::default()
    };
    let agent = Agent::new(reg, config);
    let socket = agent.bind().await.unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let _ = agent.serve_on(socket).await;
    });
    addr
}

async fn client(addr: &str) -> Session {
    Session::open_udp(
        addr,
        SessionConfig {
            timeout: Duration::from_secs(2),
            retries: 2,
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn empty_vacm_is_permissive() {
    // An agent with an empty (but present) VACM must behave exactly as before:
    // every authenticated request succeeds.
    let vacm = Arc::new(Vacm::new());
    let addr = spawn_agent_with_vacm(vacm).await;
    let session = client(&addr).await;

    // GET on sysDescr succeeds (would be denied under a configured VACM).
    let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
    let value = session.get_one(&oid).await.unwrap();
    assert_eq!(value, Value::OctetString(b"vacm agent".to_vec()));

    // GET on an interface row also succeeds (no view restriction).
    let if_oid: Oid = "1.3.6.1.2.1.2.2.1.2.1".parse().unwrap();
    let value = session.get_one(&if_oid).await.unwrap();
    assert_eq!(value, Value::OctetString(b"lo".to_vec()));
}

#[tokio::test]
async fn community_allowed_by_view() {
    let addr = spawn_agent_with_vacm(restricted_vacm()).await;
    let session = client(&addr).await;

    // sysDescr is inside the granted `system` read view -> GET succeeds.
    let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
    let value = session.get_one(&oid).await.unwrap();
    assert_eq!(value, Value::OctetString(b"vacm agent".to_vec()));

    // sysName is also inside `system` -> GET succeeds.
    let name_oid: Oid = "1.3.6.1.2.1.1.5.0".parse().unwrap();
    let value = session.get_one(&name_oid).await.unwrap();
    assert_eq!(value, Value::OctetString(b"host-a".to_vec()));
}

#[tokio::test]
async fn community_denied_by_view() {
    let addr = spawn_agent_with_vacm(restricted_vacm()).await;
    let session = client(&addr).await;

    // ifDescr.1 is OUTSIDE the `system` read view -> GET returns noAccess.
    let if_oid: Oid = "1.3.6.1.2.1.2.2.1.2.1".parse().unwrap();
    let err = session.get_one(&if_oid).await.unwrap_err();
    match err {
        netsnmp::Error::SnmpError { status, .. } => {
            assert_eq!(
                status,
                netsnmp::pdu::ErrorStatus::NoAccess,
                "expected noAccess, got {status:?}"
            );
        }
        other => panic!("expected SnmpError(noAccess), got {other:?}"),
    }
}

#[tokio::test]
async fn getnext_skips_inaccessible() {
    let addr = spawn_agent_with_vacm(restricted_vacm()).await;
    let session = client(&addr).await;

    // GETNEXT from below the system group returns the first accessible OID
    // (sysDescr.0), not an interface row.
    let start: Oid = "1.3.6.1.2.1.1".parse().unwrap();
    let vars = session.get_next(&[start]).await.unwrap();
    assert_eq!(vars[0].oid.to_string(), ".1.3.6.1.2.1.1.1.0");
    assert_eq!(vars[0].value, Value::OctetString(b"vacm agent".to_vec()));

    // GETNEXT from sysName.0 (the last accessible system row) reaches the end
    // of the accessible view: EndOfMibView, with no interface OID leaked.
    let after_name: Oid = "1.3.6.1.2.1.1.5.0".parse().unwrap();
    let vars = session.get_next(&[after_name]).await.unwrap();
    assert_eq!(vars[0].value, Value::EndOfMibView);
    // The returned OID must not be an interface OID (no leak).
    assert!(
        !vars[0].oid.as_slice().starts_with(&[1, 3, 6, 1, 2, 1, 2]),
        "leaked inaccessible OID {}",
        vars[0].oid
    );
}

#[tokio::test]
async fn snmpwalk_returns_empty_under_deny() {
    let addr = spawn_agent_with_vacm(restricted_vacm()).await;
    let session = client(&addr).await;

    // A walk of the fully-denied interfaces subtree returns empty (the first
    // GETNEXT yields EndOfMibView), proving hidden OIDs are not leaked.
    let if_root: Oid = "1.3.6.1.2.1.2.2.1.2".parse().unwrap();
    let results = session.walk(&if_root).await.unwrap();
    assert!(
        results.is_empty(),
        "expected empty walk of denied subtree, got {results:?}"
    );

    // Contrast: a walk of the granted system subtree returns both scalars.
    let sys_root: Oid = "1.3.6.1.2.1.1".parse().unwrap();
    let results = session.walk(&sys_root).await.unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].oid.to_string(), ".1.3.6.1.2.1.1.1.0");
    assert_eq!(results[1].oid.to_string(), ".1.3.6.1.2.1.1.5.0");
}

#[tokio::test]
async fn set_denied_by_write_view() {
    let addr = spawn_agent_with_vacm(restricted_vacm()).await;
    let session = client(&addr).await;

    // ifDescr.1 is not in the write view -> SET returns noAccess (before any
    // handler reservation / NotWritable check).
    let if_oid: Oid = "1.3.6.1.2.1.2.2.1.2.1".parse().unwrap();
    let err = session
        .set(vec![VarBind::new(
            if_oid,
            Value::OctetString(b"x".to_vec()),
        )])
        .await
        .unwrap_err();
    match err {
        netsnmp::Error::SnmpError { status, .. } => {
            assert_eq!(status, netsnmp::pdu::ErrorStatus::NoAccess);
        }
        other => panic!("expected SnmpError(noAccess), got {other:?}"),
    }

    // sysName.0 IS in the write view -> SET succeeds (the scalar is writable).
    let name_oid: Oid = "1.3.6.1.2.1.1.5.0".parse().unwrap();
    session
        .set(vec![VarBind::new(
            name_oid.clone(),
            Value::OctetString(b"renamed".to_vec()),
        )])
        .await
        .unwrap();
    let value = session.get_one(&name_oid).await.unwrap();
    assert_eq!(value, Value::OctetString(b"renamed".to_vec()));
}

#[tokio::test]
async fn rocommunity_config_directive_grants_read_only() {
    // An agent built from `rocommunity public` config: `public` gets read
    // access to the whole tree but no write access.
    let dirs = netsnmp::config::parse_str("rocommunity public default .1.3.6.1.2.1");
    let vacm = Vacm::from_config_directives(&dirs);
    let addr = spawn_agent_with_vacm(vacm).await;
    let session = client(&addr).await;

    // GET on sysDescr succeeds.
    let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
    let value = session.get_one(&oid).await.unwrap();
    assert_eq!(value, Value::OctetString(b"vacm agent".to_vec()));

    // SET on sysName is denied (rocommunity grants no write view).
    let name_oid: Oid = "1.3.6.1.2.1.1.5.0".parse().unwrap();
    let err = session
        .set(vec![VarBind::new(
            name_oid,
            Value::OctetString(b"x".to_vec()),
        )])
        .await
        .unwrap_err();
    match err {
        netsnmp::Error::SnmpError { status, .. } => {
            assert_eq!(status, netsnmp::pdu::ErrorStatus::NoAccess);
        }
        other => panic!("expected SnmpError(noAccess), got {other:?}"),
    }

    // Sanity-check the AccessView enum is exported and usable.
    let _ = AccessView::Read;
}
