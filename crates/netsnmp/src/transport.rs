//! Async transport abstraction and the built-in transport domains.
//!
//! Mirrors `snmplib/snmp_transport.c` (the domain abstraction) plus the
//! per-domain implementations under `transports/`:
//!
//! | Rust type                  | C domain                              |
//! |----------------------------|---------------------------------------|
//! | [`UdpTransport`]           | `snmpUDPDomain` / `snmpUDPIPv6Domain` |
//! | [`TcpTransport`]           | `snmpTCPDomain` (RFC 3430)            |
//! | [`StreamTransport`]        | shared stream framing for TCP/TLS     |
//! | [`crate::tls`] (TLS)       | `snmpTLSTCPDomain` (RFC 6353 channel) |
//!
//! A [`Transport`] exchanges complete SNMP messages; message (de)serialization
//! lives one layer up in [`crate::session`]. Datagram domains (UDP) preserve
//! message boundaries naturally; stream domains (TCP/TLS) carry SNMP messages
//! back-to-back, so [`StreamTransport`] frames them by reading the BER
//! `SEQUENCE` length header (the self-delimiting framing of RFC 3430). All IO is
//! asynchronous and built on `tokio`.

use crate::error::{Error, Result};
use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;

/// The largest datagram an SNMP message may occupy.
pub const MAX_DATAGRAM: usize = 65535;

/// Upper bound on a single SNMP message read from a stream transport (TCP/TLS),
/// guarding against a malicious or corrupt length header.
pub const MAX_STREAM_MESSAGE: usize = 16 * 1024 * 1024;

/// An async datagram transport capable of sending and receiving raw SNMP
/// messages. Timeouts are applied by the caller (see [`crate::session`]).
///
/// Auto-trait bounds (`Send`) are intentionally left unspecified so in-process
/// mock transports can hold `!Sync` state; the concrete [`UdpTransport`] is
/// `Send + Sync`.
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// Send an encoded message to the peer.
    async fn send(&self, data: &[u8]) -> Result<()>;

    /// Await the next datagram, returning the payload bytes.
    ///
    /// The payload is returned as [`Bytes`] so callers can cheaply retain or
    /// share it (reference-counted, clone is `O(1)`) without copying the
    /// datagram; it derefs to `&[u8]` for decoding.
    async fn receive(&self) -> Result<Bytes>;
}

/// A connected UDP transport bound to a single remote peer.
///
/// Works over both IPv4 and IPv6 depending on the resolved peer address,
/// covering the roles of `snmpUDPDomain` and `snmpUDPIPv6Domain`.
#[derive(Debug)]
pub struct UdpTransport {
    socket: UdpSocket,
    /// Reusable receive scratch buffer, kept allocated for the life of the
    /// transport so [`receive`](Transport::receive) does not allocate and zero a
    /// fresh `MAX_DATAGRAM`-sized buffer on every datagram (hot on the client
    /// path, e.g. repeated GETNEXTs during a walk). Guarded by a `Mutex` because
    /// `receive` takes `&self`; held across the `recv` await, which serializes
    /// concurrent receives on the same socket (a single-peer client session
    /// receives serially).
    recv_buf: Mutex<Box<[u8]>>,
}

impl UdpTransport {
    /// The default SNMP agent port.
    pub const DEFAULT_PORT: u16 = 161;
    /// The default SNMP trap port.
    pub const TRAP_PORT: u16 = 162;

    /// Connect to `peer` (e.g. `"127.0.0.1:161"`), binding an ephemeral local
    /// socket of the matching address family.
    pub async fn connect(peer: &str) -> Result<Self> {
        let addr = tokio::net::lookup_host(peer)
            .await?
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address"))?;
        let bind_addr = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(addr).await?;
        Ok(UdpTransport::from_socket(socket))
    }

    /// Bind a server socket to `local` for receiving requests/traps.
    pub async fn bind(local: &str) -> Result<Self> {
        let socket = UdpSocket::bind(local).await?;
        Ok(UdpTransport::from_socket(socket))
    }

    /// Wrap an already-bound/connected socket, allocating the receive scratch
    /// buffer once.
    fn from_socket(socket: UdpSocket) -> Self {
        UdpTransport {
            socket,
            recv_buf: Mutex::new(vec![0u8; MAX_DATAGRAM].into_boxed_slice()),
        }
    }

    /// Borrow the underlying socket (for agent-side recv_from/send_to use).
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// The local address the socket is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }
}

impl Transport for UdpTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        self.socket.send(data).await?;
        Ok(())
    }

    async fn receive(&self) -> Result<Bytes> {
        let mut scratch = self.recv_buf.lock().await;
        let n = self.socket.recv(&mut scratch).await?;
        // Copy out only the bytes that arrived (typically far below
        // MAX_DATAGRAM) into a right-sized buffer; the large scratch buffer is
        // retained for reuse.
        Ok(Bytes::copy_from_slice(&scratch[..n]))
    }
}

/// Read exactly one BER-framed SNMP message from a byte stream.
///
/// SNMP messages are an outer ASN.1 `SEQUENCE`, which is self-delimiting: the
/// tag byte is followed by a definite-length field (short or long form) that
/// gives the content length. We read the header, decode the length, then read
/// the content, returning the complete `tag || length || content` bytes so the
/// caller can decode it as it would a datagram. This is the framing used by
/// `snmpTCPDomain` (RFC 3430) and by SNMP-over-TLS.
pub async fn read_ber_message<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Bytes> {
    let mut header = Vec::with_capacity(6);

    let mut tag = [0u8; 1];
    reader.read_exact(&mut tag).await?;
    header.push(tag[0]);

    let mut first = [0u8; 1];
    reader.read_exact(&mut first).await?;
    header.push(first[0]);

    let content_len = if first[0] & 0x80 == 0 {
        first[0] as usize
    } else {
        let n = (first[0] & 0x7f) as usize;
        // Indefinite length (n == 0) is forbidden in SNMP; cap long form at 4
        // octets (u32) to bound the allocation.
        if n == 0 || n > 4 {
            return Err(Error::InvalidLength);
        }
        let mut lenbuf = [0u8; 4];
        reader.read_exact(&mut lenbuf[..n]).await?;
        header.extend_from_slice(&lenbuf[..n]);
        let mut len = 0usize;
        for b in &lenbuf[..n] {
            len = (len << 8) | (*b as usize);
        }
        len
    };

    if content_len > MAX_STREAM_MESSAGE {
        return Err(Error::InvalidLength);
    }

    let header_len = header.len();
    let mut message = BytesMut::from(&header[..]);
    message.resize(header_len + content_len, 0);
    reader.read_exact(&mut message[header_len..]).await?;
    Ok(message.freeze())
}

/// A connection-oriented, stream-based transport that frames SNMP messages by
/// their BER length. Generic over any async byte stream, so it backs both the
/// plaintext TCP domain ([`TcpTransport`]) and the TLS domain (see
/// [`crate::tls`]).
pub struct StreamTransport<S> {
    read: Mutex<ReadHalf<S>>,
    write: Mutex<WriteHalf<S>>,
    peer: Option<SocketAddr>,
}

impl<S> StreamTransport<S>
where
    S: AsyncRead + AsyncWrite + Send,
{
    /// Wrap an established stream (e.g. a connected `TcpStream` or `TlsStream`).
    /// `peer` is recorded for diagnostics when known.
    pub fn new(stream: S, peer: Option<SocketAddr>) -> Self {
        let (read, write) = split(stream);
        StreamTransport {
            read: Mutex::new(read),
            write: Mutex::new(write),
            peer,
        }
    }

    /// The remote peer address, if it was known at construction time.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }
}

impl<S> Transport for StreamTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn send(&self, data: &[u8]) -> Result<()> {
        let mut write = self.write.lock().await;
        write.write_all(data).await?;
        write.flush().await?;
        Ok(())
    }

    async fn receive(&self) -> Result<Bytes> {
        let mut read = self.read.lock().await;
        read_ber_message(&mut *read).await
    }
}

/// A connected TCP transport bound to a single remote peer (`snmpTCPDomain`,
/// RFC 3430). SNMP messages are length-framed by [`StreamTransport`].
pub type TcpTransport = StreamTransport<TcpStream>;

impl StreamTransport<TcpStream> {
    /// Connect to `peer` (e.g. `"127.0.0.1:161"`) over TCP.
    pub async fn connect(peer: &str) -> Result<Self> {
        let stream = TcpStream::connect(peer).await?;
        stream.set_nodelay(true).ok();
        let addr = stream.peer_addr().ok();
        Ok(StreamTransport::new(stream, addr))
    }
}

/// A TCP listener that accepts inbound SNMP-over-TCP connections, yielding a
/// [`TcpTransport`] per accepted peer. Counterpart of the server side of
/// `snmpTCPDomain`.
#[derive(Debug)]
pub struct TcpServer {
    listener: TcpListener,
}

impl TcpServer {
    /// Bind a TCP listener to `local` (e.g. `"0.0.0.0:161"`).
    pub async fn bind(local: &str) -> Result<Self> {
        let listener = TcpListener::bind(local).await?;
        Ok(TcpServer { listener })
    }

    /// The local address the listener is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Accept the next connection, returning a framed transport and the peer.
    pub async fn accept(&self) -> Result<(TcpTransport, SocketAddr)> {
        let (stream, peer) = self.listener.accept().await?;
        stream.set_nodelay(true).ok();
        Ok((StreamTransport::new(stream, Some(peer)), peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn frames_short_form_message() {
        // SEQUENCE, length 3, content {0x02,0x01,0x05}.
        let bytes = [0x30u8, 0x03, 0x02, 0x01, 0x05];
        let mut cur = Cursor::new(bytes.to_vec());
        let msg = read_ber_message(&mut cur).await.unwrap();
        assert_eq!(&msg[..], &bytes[..]);
    }

    #[tokio::test]
    async fn frames_long_form_and_stops_at_boundary() {
        // SEQUENCE, long-form length 0x81 0x80 (= 128 bytes of content), then a
        // trailing byte that belongs to the *next* message and must not be read.
        let mut bytes = vec![0x30u8, 0x81, 0x80];
        bytes.extend(std::iter::repeat_n(0xAB, 128));
        bytes.push(0x99); // start of a second message
        let mut cur = Cursor::new(bytes.clone());
        let msg = read_ber_message(&mut cur).await.unwrap();
        assert_eq!(msg.len(), 3 + 128);
        assert_eq!(&msg[..3], &[0x30, 0x81, 0x80]);
        // The trailing byte is still available for the next read.
        assert_eq!(cur.position(), (3 + 128) as u64);
    }

    #[tokio::test]
    async fn rejects_indefinite_length() {
        let bytes = [0x30u8, 0x80];
        let mut cur = Cursor::new(bytes.to_vec());
        assert!(matches!(
            read_ber_message(&mut cur).await,
            Err(Error::InvalidLength)
        ));
    }

    #[tokio::test]
    async fn truncated_content_is_eof() {
        // Claims 4 content bytes but only supplies 2.
        let bytes = [0x30u8, 0x04, 0x01, 0x02];
        let mut cur = Cursor::new(bytes.to_vec());
        assert!(read_ber_message(&mut cur).await.is_err());
    }
}
