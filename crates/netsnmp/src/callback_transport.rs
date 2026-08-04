//! In-process loopback transport for tests and embedded agents.
//!
//! [`CallbackTransport`] is the Rust analogue of Net-SNMP's
//! `snmpCallbackDomain` (the C `transports/snmpCallbackDomain.c`): two ends of
//! an in-memory, asynchronous channel that exchange complete SNMP messages
//! without touching the network. It is the foundation for unit-testing the
//! session/agent stack and for embedding a "remote" agent directly in the same
//! process.
//!
//! [`CallbackTransport::pair`] creates two linked transports `a` and `b` such
//! that bytes sent on one are received on the other (and vice-versa), mirroring
//! how the session tests in [`crate::session`] wire a request/response loopback
//! with `tokio::sync::mpsc` channels.

use crate::error::{Error, Result};
use crate::transport::Transport;
use bytes::Bytes;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;

/// One end of an in-process, asynchronous SNMP message channel.
///
/// Holds a send half (writes to the channel the peer reads from) and a receive
/// half (reads from the channel the peer writes to). See
/// [`CallbackTransport::pair`] for construction.
pub struct CallbackTransport {
    /// Outbound side: pushes message bytes into the peer's receiver.
    tx: UnboundedSender<Bytes>,
    /// Inbound side: a `tokio::sync::mpsc::UnboundedReceiver` awaited inside
    /// [`Transport::receive`]. Wrapped in a `tokio` mutex because the guard is
    /// held across the `.recv().await`; a `std::sync::Mutex` guard must not be
    /// held across an await point.
    rx: Mutex<UnboundedReceiver<Bytes>>,
}

impl std::fmt::Debug for CallbackTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackTransport").finish()
    }
}

impl CallbackTransport {
    /// Create a pair of linked callback transports `(a, b)`.
    ///
    /// A message sent on `a` is delivered by `b.receive()`, and vice-versa, so
    /// the two halves form a full-duplex in-process loopback. Each transport is
    /// `Send + Sync` and can be moved freely between tasks.
    ///
    /// Must be called from within a `tokio` runtime context only if you intend
    /// to immediately `await` on the returned transports; constructing the pair
    /// itself performs no IO.
    pub fn pair() -> (CallbackTransport, CallbackTransport) {
        let (tx_a, rx_a) = mpsc::unbounded_channel::<Bytes>();
        let (tx_b, rx_b) = mpsc::unbounded_channel::<Bytes>();
        // a's sender feeds b's receiver and vice-versa.
        (
            CallbackTransport {
                tx: tx_a,
                rx: Mutex::new(rx_b),
            },
            CallbackTransport {
                tx: tx_b,
                rx: Mutex::new(rx_a),
            },
        )
    }
}

impl Transport for CallbackTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        // `send` on an unbounded channel is infallible unless the receiver was
        // dropped (peer gone); surface that as an I/O-style EOF so callers see
        // a consistent "broken pipe" error.
        self.tx
            .send(Bytes::copy_from_slice(data))
            .map_err(|_| Error::UnexpectedEof)
    }

    async fn receive(&self) -> Result<Bytes> {
        let mut rx = self.rx.lock().await;
        rx.recv().await.ok_or(Error::UnexpectedEof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pair_round_trips_both_directions() {
        let (a, b) = CallbackTransport::pair();

        // a -> b
        a.send(b"hello-b").await.unwrap();
        let got = b.receive().await.unwrap();
        assert_eq!(&got[..], b"hello-b");

        // b -> a
        b.send(b"hello-a").await.unwrap();
        let got = a.receive().await.unwrap();
        assert_eq!(&got[..], b"hello-a");
    }

    #[tokio::test]
    async fn multiple_messages_preserve_order() {
        let (a, b) = CallbackTransport::pair();
        let payloads: &[&[u8]] = &[b"one", b"two", b"three"];
        for p in payloads {
            a.send(p).await.unwrap();
        }
        for p in payloads {
            let got = b.receive().await.unwrap();
            assert_eq!(&got[..], *p);
        }
    }

    #[tokio::test]
    async fn closed_peer_surfaces_eof() {
        let (a, b) = CallbackTransport::pair();
        drop(b);
        // A send to a dropped peer is a broken pipe (UnexpectedEof here).
        assert!(a.send(b"x").await.is_err());
    }
}
