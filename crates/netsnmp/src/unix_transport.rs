//! SNMP over Unix-domain sockets.
//!
//! [`UnixTransport`] carries SNMP messages over a connected
//! [`tokio::net::UnixStream`], framing messages by their BER `SEQUENCE` length
//! exactly as [`crate::transport::TcpTransport`] does for `snmpTCPDomain`
//! (RFC 3430 framing over a stream). The only difference is the addressing:
//! instead of an IP `SocketAddr`, the peer is identified by a filesystem path,
//! which is how Net-SNMP's `snmpALGDomain`/`unix:` transports work for
//! local-only, side-channel-free agent access.
//!
//! Because there is no equivalent of TCP's `SocketAddr` to record, this
//! transport stores the read and write halves directly (each under its own
//! [`tokio::sync::Mutex`]) rather than going through the generic
//! [`StreamTransport`](crate::transport::StreamTransport).

use crate::error::Result;
use crate::transport::{Transport, read_ber_message};
use tokio::io::AsyncWriteExt;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

/// A connected Unix-domain socket transport that frames SNMP messages by their
/// BER length.
///
/// Built on a [`tokio::net::UnixStream`]; see [`UnixTransport::connect`].
pub struct UnixTransport {
    /// The stream's read half, guarded so concurrent receives serialize on one
    /// message at a time (the `read_ber_message` framing is not re-entrant).
    read: Mutex<OwnedReadHalf>,
    /// The stream's write half, guarded so concurrent sends do not interleave
    /// partial messages on the wire.
    write: Mutex<OwnedWriteHalf>,
}

impl std::fmt::Debug for UnixTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnixTransport").finish()
    }
}

impl UnixTransport {
    /// Connect a Unix-domain socket transport to the agent at `path`
    /// (a filesystem socket path such as `/var/run/snmp.sock`).
    pub async fn connect(path: impl AsRef<str>) -> Result<Self> {
        let path = path.as_ref();
        let stream = UnixStream::connect(path).await?;
        let (read, write) = stream.into_split();
        Ok(UnixTransport {
            read: Mutex::new(read),
            write: Mutex::new(write),
        })
    }

    /// Parse a Unix-domain address string.
    ///
    /// Accepts either a bare absolute path (`/var/run/snmp.sock`) or one with
    /// an optional `unix:` scheme prefix (`unix:/var/run/snmp.sock`); both yield
    /// the absolute path. Returns `None` for relative paths or empty input,
    /// since Unix-domain socket addresses must be absolute.
    pub fn parse_unix_addr(s: &str) -> Option<String> {
        let stripped = s.strip_prefix("unix:").unwrap_or(s);
        if stripped.starts_with('/') {
            Some(stripped.to_string())
        } else {
            None
        }
    }
}

impl Transport for UnixTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        let mut write = self.write.lock().await;
        write.write_all(data).await?;
        write.flush().await?;
        Ok(())
    }

    async fn receive(&self) -> Result<bytes::Bytes> {
        let mut read = self.read.lock().await;
        read_ber_message(&mut *read).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn parse_unix_addr_canonical_and_bare() {
        assert_eq!(
            UnixTransport::parse_unix_addr("unix:/tmp/x"),
            Some("/tmp/x".to_string())
        );
        assert_eq!(
            UnixTransport::parse_unix_addr("/var/run/y"),
            Some("/var/run/y".to_string())
        );
        assert_eq!(UnixTransport::parse_unix_addr("relative"), None);
        assert_eq!(UnixTransport::parse_unix_addr(""), None);
        assert_eq!(UnixTransport::parse_unix_addr("unix:relative"), None);
    }

    #[tokio::test]
    async fn unix_transport_round_trips_framed_message() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "snmp-unix-{}-{}.sock",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        // Clean up any stale socket from a previous, crashed run.
        let _ = std::fs::remove_file(&path);

        let listener = tokio::net::UnixListener::bind(&path).expect("bind unix listener");

        // Server task: accept one connection, read a framed message, echo it
        // back, then close. This exercises both directions of the transport.
        let server_path = path.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (mut rd, mut wr) = stream.into_split();
            let msg = read_ber_message(&mut rd).await.expect("server read");
            wr.write_all(&msg).await.expect("server write");
            wr.flush().await.expect("server flush");
            drop(server_path);
        });

        // Give the listener a tick to be ready, then connect as a client.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let transport = UnixTransport::connect(path.to_str().unwrap())
            .await
            .expect("client connect");

        // A minimal valid BER SEQUENCE: tag 0x30, length 3, content {02 01 05}.
        let message: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x05];
        transport.send(message).await.expect("client send");
        let echoed = transport.receive().await.expect("client receive");
        assert_eq!(&echoed[..], message);

        // Make sure the server task completes (and drops its side) cleanly.
        server.await.expect("server task panicked");

        // Clean up the socket file.
        let _ = std::fs::remove_file(&path);
    }
}
