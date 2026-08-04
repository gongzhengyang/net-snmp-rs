//! # netsnmp — core SNMP protocol library
//!
//! A pure-Rust reimplementation of the core of Net-SNMP's `libnetsnmp`
//! (`snmplib/`). It provides the protocol stack used by client tools and the
//! agent:
//!
//! | Layer            | Module          | C counterpart                |
//! |------------------|-----------------|------------------------------|
//! | Error handling   | [`error`]       | `SNMPERR_*` in `snmp_api.c`  |
//! | OID handling     | [`oid`]         | `mib.c`, `tools.c`           |
//! | Typed values     | [`value`]       | `asn1.c`, `snmp.c`           |
//! | PDU / varbind    | [`pdu`]         | `snmp_api.c`, `snmp.h`       |
//! | Message framing  | [`message`]     | `snmp_api.c` (v1/v2c)        |
//! | SNMPv3 USM crypto | [`usm`]        | `snmpusm.c`, `keytools.c`    |
//! | SNMPv3 messages  | [`v3`]          | `snmpv3.c`, `snmp_api.c`     |
//! | Async transport  | [`transport`]   | `snmp_transport.c`, UDP/TCP  |
//! | TLS transport    | [`tls`]         | `snmpTLSTCPDomain.c` (chan.) |
//! | Session / client | [`session`]     | `snmp_client.c`, synch API   |
//! | MIB name lookup  | [`mib`]         | `parse.c`, `mib.c` (subset)  |
//! | Config files     | [`config`]      | `read_config.c` (snmp.conf)  |
//!
//! ## Quick start
//!
//! All IO is asynchronous and runs on `tokio`:
//!
//! ```no_run
//! use netsnmp::{Session, SessionConfig, Oid};
//!
//! # async fn run() -> Result<(), netsnmp::Error> {
//! let session = Session::open_udp("127.0.0.1:161", SessionConfig::default()).await?;
//! let oid: Oid = "1.3.6.1.2.1.1.1.0".parse()?;
//! let value = session.get_one(&oid).await?;
//! tracing::info!("sysDescr.0 = {value}");
//! # Ok(())
//! # }
//! ```
//!
//! ## Scope
//!
//! This crate implements the community-based models (SNMPv1 and SNMPv2c) and
//! SNMPv3/USM (HMAC-MD5/SHA/SHA-256 authentication and AES-128-CFB privacy)
//! end-to-end, atop async (`tokio`) transports: UDP (`snmpUDPDomain`), TCP
//! (`snmpTCPDomain`, RFC 3430) and TLS (`snmpTLSTCPDomain`, the RFC 6353 secure
//! channel via rustls, behind the default `tls` feature). USM cryptography is
//! provided by the audited RustCrypto crates. The remaining transport domains
//! (DTLS/SSH/IPX/…) and the full RFC 6353 Transport Security Model remain out
//! of scope.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod alarm;
pub mod callback_transport;
pub mod config;
mod convert;
pub mod default_store;
pub mod error;
pub mod message;
pub mod mib;
pub mod oid;
pub mod pdu;
pub mod session;
pub mod smi;
#[cfg(feature = "tls")]
pub mod tls;
pub mod transport;
pub mod trap;
pub mod unix_transport;
pub mod usm;
pub mod v3;
pub mod value;

pub use alarm::{Alarm, AlarmId, AlarmRegistry};
pub use callback_transport::CallbackTransport;
pub use config::{Directive, read_app_config};
pub use default_store::{DsCategory, DsValue, DefaultStore, default_store};
pub use error::{Error, Result};
pub use message::{Message, Version};
pub use mib::MibRegistry;
pub use oid::Oid;
pub use pdu::{ErrorStatus, Pdu, PduType, VarBind, V1Trap, v1_generic_trap};
pub use session::{Session, SessionConfig, V3Session};
#[cfg(feature = "tls")]
pub use tls::{TlsClient, TlsClientTransport, TlsServer, TlsServerTransport};
pub use transport::{StreamTransport, TcpServer, TcpTransport, Transport, UdpTransport};
pub use trap::{
    Notification, V1Notification, build_v1_trap, parse_v1_trap, v1_generic_trap_to_oid,
};
pub use unix_transport::UnixTransport;
pub use usm::{AuthProtocol, PrivProtocol, SecurityLevel, UsmUser};
pub use v3::{EngineParams, ScopedPdu};
pub use value::Value;
