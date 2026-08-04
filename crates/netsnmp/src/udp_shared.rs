//! A shared UDP socket multiplexer for client sessions.
//!
//! Each [`crate::transport::UdpTransport`] dedicates one file descriptor to a
//! single peer. A daemon that fans out many SNMP polls (e.g. a management
//! station talking to thousands of devices) therefore opens thousands of
//! sockets, which is wasteful of file descriptors and kernel state. The
//! `snmpUDPsharedDomain` analogue in C Net-SNMP is a single bound socket shared
//! across sessions, with responses routed back to the originating request by
//! `request-id`.
//!
//! [`UdpShared`] is that shared socket: it binds once, then a background task
//! reads incoming datagrams and dispatches each to the [`UdpSharedTransport`]
//! handle whose outstanding request-id matches the response's id. Each handle
//! implements [`crate::transport::Transport`], so a [`crate::session::Session`]
//! can be built directly on top of it via
//! [`Session::with_transport`](crate::session::Session::with_transport).
//!
//! # Limitation
//!
//! A single [`UdpSharedTransport`] handle carries **one outstanding request at
//! a time**: [`Transport::send`](crate::transport::Transport::send) registers a
//! route for the request's id and stashes the response receiver;
//! [`Transport::receive`](crate::transport::Transport::receive) consumes that
//! receiver. This matches the request/reply cadence of
//! [`Session::request`](crate::session::Session::request) (send one, await one),
//! so a `Session<UdpSharedTransport>` behaves exactly like a
//! `Session<UdpTransport>`. For concurrent requests against different agents,
//! create one handle per agent (all sharing the same [`UdpShared`]); for
//! concurrent requests against the *same* agent, use one handle per in-flight
//! request.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, oneshot};
use tracing::{debug, trace, warn};

use crate::error::{Error, Result};
use crate::message::Message;
use crate::transport::{MAX_DATAGRAM, Transport};
use crate::v3;

/// A shared UDP socket that routes incoming responses to the handle awaiting
/// them, by `request-id` (v1/v2c) or `msgId` (v3).
///
/// The socket is bound once at construction and a background receive task runs
/// for the lifetime of the [`Arc<UdpShared>`]. Each outstanding request
/// registers a one-shot channel under its id; when a datagram arrives whose
/// decoded id matches, the bytes are forwarded down that channel. Datagram ids
/// that do not match any registered route are dropped (logged at `debug`),
/// matching the behaviour of `snmpUDPsharedDomain`.
pub struct UdpShared {
    /// The single bound socket all handles send through.
    socket: Arc<UdpSocket>,
    /// Outstanding request-id → response receiver. A request is "in flight"
    /// while its entry lives here; the receive task removes the entry when it
    /// dispatches the matching response (or the sender is dropped on timeout).
    routes: Mutex<HashMap<i32, oneshot::Sender<Bytes>>>,
}

impl UdpShared {
    /// Bind a shared UDP socket to `local` (e.g. `"0.0.0.0:0"` for an
    /// ephemeral client port) and start the background receive task.
    ///
    /// The returned [`Arc<UdpShared>`] is shared by every
    /// [`UdpSharedTransport`] handle. The receive task is detached and runs
    /// until all clones of the [`Arc`] are dropped (which drops the inner
    /// socket and ends `recv_from`).
    pub async fn bind(local: &str) -> std::io::Result<Arc<Self>> {
        let socket = Arc::new(UdpSocket::bind(local).await?);
        let shared = Arc::new(UdpShared {
            socket,
            routes: Mutex::new(HashMap::new()),
        });
        shared.spawn_recv_task();
        Ok(shared)
    }

    /// Borrow the underlying socket (handles send through it directly).
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Register a route for `request_id`, returning the receiver that will be
    /// signalled when the matching response datagram arrives.
    ///
    /// If `request_id` is already registered (e.g. a previous request timed
    /// out without calling [`unroute`](Self::unroute)), the old route is
    /// replaced and its pending receiver is dropped — the previous waiter will
    /// observe a closed channel. This is logged at `warn`; under normal use the
    /// caller calls `unroute` on timeout so the slot is already free.
    pub async fn route(&self, request_id: i32) -> oneshot::Receiver<Bytes> {
        let (tx, rx) = oneshot::channel();
        let mut routes = self.routes.lock().await;
        if let Some(old) = routes.insert(request_id, tx) {
            warn!(
                request_id,
                "replaced in-flight route on shared UDP socket (previous waiter dropped)"
            );
            // `old` is dropped here; its receiver observes a closed channel.
            drop(old);
        }
        rx
    }

    /// Remove a previously registered route (e.g. after the response arrived or
    /// the request timed out). No-op if `request_id` is not registered.
    pub async fn unroute(&self, request_id: i32) {
        self.routes.lock().await.remove(&request_id);
    }

    /// Spawn the background task that reads datagrams and dispatches them to
    /// registered routes. Runs until the socket is closed (all `Arc`s dropped).
    fn spawn_recv_task(self: &Arc<Self>) {
        let shared = Arc::clone(self);
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                match shared.socket.recv_from(&mut buf).await {
                    Ok((n, peer)) => {
                        let data = &buf[..n];
                        match peek_request_id(data) {
                            Some(id) => {
                                let mut routes = shared.routes.lock().await;
                                if let Some(tx) = routes.remove(&id) {
                                    trace!(request_id = id, %peer, bytes = n, "routed response");
                                    // The receiver may have been dropped (caller
                                    // timed out); sending then fails silently.
                                    let _ = tx.send(Bytes::copy_from_slice(data));
                                } else {
                                    debug!(
                                        request_id = id,
                                        %peer, bytes = n,
                                        "no route for response id, dropping"
                                    );
                                }
                            }
                            None => {
                                debug!(
                                    %peer, bytes = n,
                                    "could not extract request-id from datagram, dropping"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        // A benign error here is socket closure (all Arcs
                        // dropped) — log and exit. Anything else is unexpected.
                        if e.kind() == std::io::ErrorKind::UnexpectedEof {
                            break;
                        }
                        warn!(error = %e, "shared UDP recv_from error, exiting receive task");
                        break;
                    }
                }
            }
        });
    }
}

/// A client-side handle into a [`UdpShared`] socket, bound to a single peer.
///
/// Implements [`Transport`] so it can be handed to
/// [`Session::with_transport`](crate::session::Session::with_transport). One
/// outstanding request per handle at a time (see the [module docs](self)).
pub struct UdpSharedTransport {
    /// The shared socket (and route table) this handle sends through.
    shared: Arc<UdpShared>,
    /// The single remote peer all datagrams are sent to.
    peer: SocketAddr,
    /// The receiver stashed by the last `send`, awaiting the matching
    /// response. `None` until `send` is called; consumed by `receive`. A
    /// second `send` before `receive` replaces this (dropping the prior
    /// receiver, which closes the route's sender — the receive task will then
    /// find no live route for that id and drop the late response).
    pending: Mutex<Option<(i32, oneshot::Receiver<Bytes>)>>,
}

impl UdpSharedTransport {
    /// Create a handle into `shared` that sends to `peer`.
    pub fn new(shared: Arc<UdpShared>, peer: SocketAddr) -> Self {
        UdpSharedTransport {
            shared,
            peer,
            pending: Mutex::new(None),
        }
    }

    /// The remote peer this handle is bound to.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Borrow the shared socket (e.g. to query the local address).
    pub fn socket(&self) -> &UdpSocket {
        self.shared.socket()
    }
}

impl Transport for UdpSharedTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        // Extract the request-id (v1/v2c) or msgId (v3) so the receive task can
        // route the response back to us. Failure to extract is fatal here:
        // without an id we cannot pair the response, so we refuse to send
        // rather than emit an unroutable datagram.
        let request_id = peek_request_id(data).ok_or_else(|| {
            Error::Protocol("could not extract request-id from outgoing message".into())
        })?;

        // Register the route first, then send: if a fast response beats us to
        // the route table it will simply find no live route yet (the receiver
        // is created here). Registering before send avoids a race where the
        // response arrives between send() returning and the route being added.
        let rx = self.shared.route(request_id).await;

        // Stash the receiver for receive() to consume. If a previous request
        // was never received (e.g. timed out), replace it — the old route's
        // sender is dropped, which the receive task tolerates (send-to-closed
        // channel is a silent no-op).
        {
            let mut pending = self.pending.lock().await;
            *pending = Some((request_id, rx));
        }

        self.shared
            .socket()
            .send_to(data, self.peer)
            .await
            .map_err(|e| Error::Protocol(format!("UDP send_to failed: {e}")))?;
        Ok(())
    }

    async fn receive(&self) -> Result<Bytes> {
        // Take the stashed receiver (left by send). The caller must send before
        // receive — this matches the Session usage pattern. The request-id is
        // stashed alongside only so a second send can replace (and thus
        // abandon) the prior in-flight route; receive does not need it.
        let rx = {
            let mut pending = self.pending.lock().await;
            pending
                .take()
                .ok_or_else(|| Error::Protocol("receive called before send".into()))?
        };
        let (_id, rx) = rx;

        // If the route was replaced (a later send superseded us) or the shared
        // socket was dropped, the sender is gone and we get a RecvError. Map
        // that to a Protocol error so the Session retry loop surfaces it.
        rx.await
            .map_err(|_| Error::Protocol("response route closed before datagram arrived".into()))
    }
}

/// Extract the routing id from an SNMP datagram without a full decode.
///
/// For community messages (v1/v2c) this is the PDU `request-id`; for v3 it is
/// the `msgId` from `msgGlobalData` (the value v3 uses to correlate requests
/// and responses at the message layer — `request-id` may be encrypted inside
/// the ScopedPDU and thus unavailable to an unprivileged router).
///
/// Decoding is best-effort: a malformed datagram yields `None` and is dropped
/// by the receive task. We try the cheap `peek_security` path first (which
/// reads only the v3 header, not the possibly-encrypted payload); on
/// `UnsupportedVersion` we fall back to a full community decode.
fn peek_request_id(data: &[u8]) -> Option<i32> {
    // v3: read msgId from the header without touching the (possibly encrypted)
    // ScopedPDU. peek_security returns UnsupportedVersion for community msgs,
    // which we handle below.
    match v3::peek_security(data) {
        Ok((header, _usm)) => return Some(header.msg_id),
        Err(Error::UnsupportedVersion(_)) => {}
        Err(_) => {
            // Not a v3 message we can peek; fall through to community decode.
        }
    }

    // v1/v2c: full decode is cheap (no crypto) and gives the PDU request-id.
    Message::decode(data)
        .ok()
        .map(|msg| msg.pdu.request_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Message, Version};
    use crate::pdu::{Pdu, PduType, VarBind};
    use crate::value::Value;
    use std::time::Duration;

    /// Resolve `127.0.0.1:0` to a concrete ephemeral SocketAddr by binding a
    /// throwaway socket. Returns (bound_socket, local_addr).
    async fn ephemeral() -> (UdpSocket, SocketAddr) {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a = s.local_addr().unwrap();
        (s, a)
    }

    /// Build a v2c Response PDU echoing `request_id` with a single OctetString
    /// varbind, encoded to wire bytes.
    fn v2c_response_bytes(request_id: i32, value: &[u8]) -> Vec<u8> {
        let mut pdu = Pdu::new(PduType::Response, request_id);
        pdu.variables.push(VarBind::new(
            "1.3.6.1.2.1.1.1.0".parse().unwrap(),
            Value::OctetString(value.to_vec()),
        ));
        Message::new(Version::V2c, b"public".to_vec(), pdu)
            .encode()
            .unwrap()
    }

    /// Build a v2c GetRequest with the given request-id.
    fn v2c_get_bytes(request_id: i32) -> Vec<u8> {
        let pdu = Pdu::new(PduType::Get, request_id)
            .with_null_var("1.3.6.1.2.1.1.1.0".parse().unwrap());
        Message::new(Version::V2c, b"public".to_vec(), pdu)
            .encode()
            .unwrap()
    }

    #[tokio::test]
    async fn peek_request_id_v2c() {
        let bytes = v2c_get_bytes(12345);
        assert_eq!(peek_request_id(&bytes), Some(12345));
    }

    #[tokio::test]
    async fn peek_request_id_v3_msgid() {
        // A v3 discovery message carries msgId in the cleartext header.
        let bytes = crate::v3::build_discovery(777, 1).unwrap();
        assert_eq!(peek_request_id(&bytes), Some(777));
    }

    #[tokio::test]
    async fn peek_request_id_garbage_is_none() {
        assert_eq!(peek_request_id(&[0x30, 0x02, 0xff, 0xff]), None);
        assert_eq!(peek_request_id(&[]), None);
    }

    /// A full send/receive round-trip through the shared socket against an
    /// in-process echo responder.
    #[tokio::test]
    async fn send_receive_roundtrip() {
        let (responder, peer) = ephemeral().await;
        let shared = UdpShared::bind("127.0.0.1:0").await.unwrap();
        let transport = UdpSharedTransport::new(shared, peer);

        // Responder: read one datagram, echo back a Response with the same id.
        let resp_task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            let (n, from) = responder.recv_from(&mut buf).await.unwrap();
            let req = Message::decode(&buf[..n]).unwrap();
            let reply = v2c_response_bytes(req.pdu.request_id, b"hello-shared");
            responder.send_to(&reply, from).await.unwrap();
        });

        let req = v2c_get_bytes(4242);
        transport.send(&req).await.unwrap();
        // Bounded wait so a broken receive path fails the test instead of hang.
        let raw = tokio::time::timeout(Duration::from_secs(2), transport.receive())
            .await
            .expect("receive timed out")
            .unwrap();
        resp_task.await.unwrap();

        let resp = Message::decode(&raw).unwrap();
        assert_eq!(resp.pdu.request_id, 4242);
        assert_eq!(
            resp.pdu.variables[0].value,
            Value::OctetString(b"hello-shared".to_vec())
        );
    }

    /// Two concurrent handles with distinct request-ids each get their own
    /// response, proving the routing table dispatches by id (not by arrival).
    #[tokio::test]
    async fn concurrent_routing_by_id() {
        let (responder, peer) = ephemeral().await;
        let shared = UdpShared::bind("127.0.0.1:0").await.unwrap();

        // Responder: answer two requests, but reply in REVERSE order of arrival
        // to ensure the client doesn't depend on datagram ordering.
        let responder_task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            let mut seen = Vec::new();
            for _ in 0..2 {
                let (n, from) = responder.recv_from(&mut buf).await.unwrap();
                let req = Message::decode(&buf[..n]).unwrap();
                seen.push((from, req.pdu.request_id));
            }
            // Reply to the second request first.
            let (from2, id2) = seen.pop().unwrap();
            let (from1, id1) = seen.pop().unwrap();
            responder
                .send_to(&v2c_response_bytes(id2, b"second"), from2)
                .await
                .unwrap();
            responder
                .send_to(&v2c_response_bytes(id1, b"first"), from1)
                .await
                .unwrap();
        });

        let t1 = UdpSharedTransport::new(Arc::clone(&shared), peer);
        let t2 = UdpSharedTransport::new(Arc::clone(&shared), peer);

        // Send both requests first so both routes are registered, then race the
        // receives. Each handle's receiver only resolves on its own id.
        t1.send(&v2c_get_bytes(111)).await.unwrap();
        t2.send(&v2c_get_bytes(222)).await.unwrap();

        let (r1, r2) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(2), t1.receive()),
            tokio::time::timeout(Duration::from_secs(2), t2.receive()),
        );
        let r1 = r1.expect("t1 timed out").unwrap();
        let r2 = r2.expect("t2 timed out").unwrap();
        responder_task.await.unwrap();

        let m1 = Message::decode(&r1).unwrap();
        let m2 = Message::decode(&r2).unwrap();
        assert_eq!(m1.pdu.request_id, 111);
        assert_eq!(
            m1.pdu.variables[0].value,
            Value::OctetString(b"first".to_vec())
        );
        assert_eq!(m2.pdu.request_id, 222);
        assert_eq!(
            m2.pdu.variables[0].value,
            Value::OctetString(b"second".to_vec())
        );
    }

    /// A datagram whose id matches no registered route is dropped, not panicked.
    #[tokio::test]
    async fn unmatched_datagram_dropped() {
        let (responder, peer) = ephemeral().await;
        let shared = UdpShared::bind("127.0.0.1:0").await.unwrap();
        let transport = UdpSharedTransport::new(Arc::clone(&shared), peer);

        // Send a real request to register route 999, then have the responder
        // ALSO send an unsolicited datagram for id 4321 (no route). The real
        // response (999) must still arrive; the bogus one is silently dropped.
        let bogus = v2c_response_bytes(4321, b"nobody");
        let responder_task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            let (n, from) = responder.recv_from(&mut buf).await.unwrap();
            let req = Message::decode(&buf[..n]).unwrap();
            // Unsolicited datagram for an id nobody is waiting for.
            responder.send_to(&bogus, from).await.unwrap();
            // Then the real reply.
            responder
                .send_to(&v2c_response_bytes(req.pdu.request_id, b"real"), from)
                .await
                .unwrap();
        });

        transport.send(&v2c_get_bytes(999)).await.unwrap();
        let raw = tokio::time::timeout(Duration::from_secs(2), transport.receive())
            .await
            .expect("receive timed out")
            .unwrap();
        responder_task.await.unwrap();

        let m = Message::decode(&raw).unwrap();
        assert_eq!(m.pdu.request_id, 999);
        assert_eq!(
            m.pdu.variables[0].value,
            Value::OctetString(b"real".to_vec())
        );
    }

    /// receive() before send() is a usage error, not a hang.
    #[tokio::test]
    async fn receive_before_send_errors() {
        let (_r, peer) = ephemeral().await;
        let shared = UdpShared::bind("127.0.0.1:0").await.unwrap();
        let transport = UdpSharedTransport::new(shared, peer);
        let err = transport.receive().await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
    }
}
