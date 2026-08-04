//! SMUX-MIB (`1.3.6.1.2.1.20`) — RFC 1227 §4.
//!
//! The SMUX-MIB exposes the set of peer daemons currently registered with the
//! local SMUX server and the subtrees each owns. The agent serves it from the
//! live [`SmuxServer`](crate::smux::SmuxServer) state, so a walk reflects the
//! peers connected *now*.
//!
//! Only the minimal walkable objects are implemented (the `smuxTree`
//! conceptual table flattened to scalars, plus a `smuxSnmpdAgentID`-style
//! peer count). The full MIB is larger; this covers what `snmpwalk` needs to
//! confirm SMUX is wired up.
//!
//! Objects exposed:
//! * `smuxSnmpdAgentID.0` (`20.1`) — a notional scalar (peer count).
//! * `smuxTreeTable` (`20.3`) — one row per registered subtree, with
//!   `smuxTreeSubtree`, `smuxTreePeerIdentity`, `smuxTreeStatus`.

use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;
use crate::smux::SmuxServer;

/// SMUX-MIB root: `1.3.6.1.2.1.20`.
const SMUX_MIB: [u32; 7] = [1, 3, 6, 1, 2, 1, 20];

/// Build the live `(OID, value)` cells for the SMUX-MIB from `server`'s state.
///
/// Layout:
/// * `smuxSnmpdAgentID.0` (`20.1.0`) — number of registered subtrees (Integer).
/// * `smuxTreeTable` row `i` under `20.3.1.1.{i}`:
///   * `.1` `smuxTreeSubtree` — the registered OID,
///   * `.2` `smuxTreePeerIdentity` — the owning peer's identity OID,
///   * `.5` `smuxTreeStatus` — RowStatus `active(1)`.
pub fn smux_mib_cells(server: &SmuxServer) -> Vec<(Oid, Value)> {
    let root = Oid::new(SMUX_MIB.to_vec());
    let subtrees = server.registered_subtrees();
    let peers = server
        .peers
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    let mut cells = Vec::new();
    // smuxSnmpdAgentID.0 = peer count.
    cells.push((
        root.child(1).child(0),
        Value::Integer(peers.len() as i64),
    ));

    // smuxTreeTable: one row per registered subtree, indexed 1..
    let row_entry = root.child(3).child(1).child(1);
    for (i, (sub, peer_id)) in subtrees.iter().enumerate() {
        let idx = (i + 1) as u32;
        let identity = peers
            .get(peer_id)
            .map(|p| p.identity.clone())
            .unwrap_or_else(Oid::null);
        cells.push((row_entry.child(1).child(idx), Value::Oid(sub.clone())));
        cells.push((row_entry.child(2).child(idx), Value::Oid(identity)));
        cells.push((row_entry.child(5).child(idx), Value::Integer(1)));
    }
    cells
}

/// Build the [`MibHandler`] set for the SMUX-MIB. One [`FnHandler`] serves the
/// whole `1.3.6.1.2.1.20` subtree from the live [`SmuxServer`] state.
pub fn smux_mib_handlers(server: Arc<SmuxServer>) -> Vec<Arc<dyn MibHandler>> {
    let root = Oid::new(SMUX_MIB.to_vec());
    let handler = FnHandler::new(root, move || smux_mib_cells(&server));
    vec![Arc::new(handler)]
}

/// Register the SMUX-MIB into `registry` using the supplied live `server`.
///
/// Convenience wrapper kept in the mibgroup module so callers can install it
/// alongside the other protocol MIBs. Mirrors the shape of the per-MIB
/// `register_*` helpers used elsewhere.
pub fn register_smux_mibs(registry: &mut crate::registry::Registry, server: Arc<SmuxServer>) {
    for handler in smux_mib_handlers(server) {
        registry.register(handler);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smux::{SmuxPeer, SmuxServer};

    use std::sync::RwLock;

    fn server_with_one_peer(identity: &str, subtree: &str) -> Arc<SmuxServer> {
        let server = SmuxServer::new_default();
        // Synthesise a peer + subtree registration directly (no TCP needed).
        // The MIB handler never touches the stream halves, so a throwaway
        // loopback pair is sufficient to satisfy the struct.
        let (read_half, write_half) = dummy_stream().into_split();
        // The MIB handler never touches the stream halves, so drop the read
        // half and keep a throwaway write half + empty response slot.
        drop(read_half);
        let peer = Arc::new(SmuxPeer {
            writer: Arc::new(tokio::sync::Mutex::new(write_half)),
            pending_response: Arc::new(tokio::sync::Mutex::new(None)),
            identity: identity.parse().unwrap(),
            description: "test".into(),
            subtrees: RwLock::new(vec![subtree.parse().unwrap()]),
        });
        let mut peers = server.peers.write().unwrap();
        peers.insert(1, peer);
        drop(peers);
        let mut subs = server.subtrees.write().unwrap();
        subs.push((subtree.parse().unwrap(), 1));
        drop(subs);
        server
    }

    // We cannot construct a `TcpStream` without connecting, but the SMUX-MIB
    // handler never reads the stream. We build a real loopback connection pair
    // (the listener side is dropped immediately) and split it. The socket is
    // set non-blocking so `tokio::net::TcpStream::from_std` succeeds inside the
    // tokio runtime.
    fn dummy_stream() -> tokio::net::TcpStream {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let join = std::thread::spawn(move || listener.accept().unwrap());
        let s = std::net::TcpStream::connect(addr).unwrap();
        let _ = join.join().unwrap();
        s.set_nonblocking(true).unwrap();
        tokio::net::TcpStream::from_std(s).unwrap()
    }

    #[tokio::test]
    async fn smux_mib_exposes_peer_count_and_subtree() {
        let server =
            server_with_one_peer("1.3.6.1.4.1.9999", "1.3.6.1.4.1.9999.1");
        let cells = smux_mib_cells(&server);
        // smuxSnmpdAgentID.0 = 1 peer.
        let count = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.20.1.0")
            .map(|(_, v)| v.clone());
        assert_eq!(count, Some(Value::Integer(1)));
        // smuxTreeSubtree.1 = the registered OID.
        let sub = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.20.3.1.1.1.1")
            .map(|(_, v)| v.clone());
        match sub {
            Some(Value::Oid(o)) => assert_eq!(o.to_string(), ".1.3.6.1.4.1.9999.1"),
            other => panic!("expected subtree OID, got {other:?}"),
        }
        // smuxTreeStatus.1 = active(1).
        let status = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.20.3.1.1.5.1")
            .map(|(_, v)| v.clone());
        assert_eq!(status, Some(Value::Integer(1)));
    }

    #[tokio::test]
    async fn handler_walks_smux_mib_subtree() {
        let server =
            server_with_one_peer("1.3.6.1.4.1.9999", "1.3.6.1.4.1.9999.1");
        let handlers = smux_mib_handlers(Arc::clone(&server));
        assert_eq!(handlers.len(), 1);
        let handler = &handlers[0];
        let root: Oid = "1.3.6.1.2.1.20".parse().unwrap();
        // GETNEXT from the root lands on the first cell (the peer-count scalar).
        let first = handler.get_next(&root).expect("first cell");
        assert_eq!(first.oid.to_string(), ".1.3.6.1.2.1.20.1.0");
    }

    #[test]
    fn empty_server_has_zero_peer_count() {
        let server = SmuxServer::new_default();
        let cells = smux_mib_cells(&server);
        let count = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.20.1.0")
            .map(|(_, v)| v.clone());
        assert_eq!(count, Some(Value::Integer(0)));
    }
}
