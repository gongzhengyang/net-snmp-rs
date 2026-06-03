//! Async client session API for community (v1/v2c) and USM (v3) sessions.
//!
//! This is the Rust analogue of the high-level `snmp_sess_*` / `snmp_synch_*`
//! routines in `snmplib/snmp_api.c` and `snmp_client.c`: it owns a transport,
//! tracks the request-id counter and retry/timeout policy, and exposes typed
//! `get` / `get_next` / `get_bulk` / `set` / `walk` operations.
//!
//! [`Session`] (in [`community`](mod@self::community)) handles SNMPv1/v2c.
//! [`V3Session`] (in [`secure`](mod@self::secure)) handles SNMPv3/USM, performing
//! RFC 3414 engine discovery and time synchronization on top of [`crate::v3`].
//! Shared helpers (request-id source, status shim) live in
//! [`common`](mod@self::common).

mod common;
mod community;
mod config;
mod secure;

pub use common::ensure_ok;
pub use community::Session;
pub use config::SessionConfig;
pub use secure::V3Session;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{Error, Result};
    use crate::message::{Message, Version};
    use crate::oid::Oid;
    use crate::pdu::{ErrorStatus, Pdu, PduType, VarBind};
    use crate::transport::Transport;
    use crate::usm::UsmUser;
    use crate::v3::{self, EngineParams};
    use crate::value::Value;
    use std::sync::Mutex;
    use std::time::Duration;

    /// A loopback transport that answers each request from a scripted closure.
    struct MockTransport {
        last_sent: Mutex<Vec<u8>>,
        responder: Box<dyn Fn(Pdu) -> Pdu + Send + Sync>,
    }

    impl Transport for MockTransport {
        async fn send(&self, data: &[u8]) -> Result<()> {
            *self.last_sent.lock().unwrap() = data.to_vec();
            Ok(())
        }
        async fn receive(&self) -> Result<bytes::Bytes> {
            let sent = self.last_sent.lock().unwrap().clone();
            let req = Message::decode(&sent)?;
            let resp_pdu = (self.responder)(req.pdu);
            let encoded = Message::new(Version::V2c, b"public".to_vec(), resp_pdu).encode()?;
            Ok(bytes::Bytes::from(encoded))
        }
    }

    #[tokio::test]
    async fn get_returns_value() {
        let transport = MockTransport {
            last_sent: Mutex::new(Vec::new()),
            responder: Box::new(|req| {
                let mut resp = Pdu::new(PduType::Response, req.request_id);
                resp.variables = vec![VarBind::new(
                    req.variables[0].oid.clone(),
                    Value::OctetString(b"Linux test".to_vec()),
                )];
                resp
            }),
        };
        let session = Session::with_transport(transport, SessionConfig::default());
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let value = session.get_one(&oid).await.unwrap();
        assert_eq!(value, Value::OctetString(b"Linux test".to_vec()));
    }

    #[tokio::test]
    async fn error_status_propagates() {
        let transport = MockTransport {
            last_sent: Mutex::new(Vec::new()),
            responder: Box::new(|req| {
                let mut resp = Pdu::new(PduType::Response, req.request_id);
                resp.error_status = ErrorStatus::NoSuchName.code();
                resp.error_index = 1;
                resp.variables = req.variables;
                resp
            }),
        };
        let session = Session::with_transport(transport, SessionConfig::default());
        let oid: Oid = "1.3.6.1.2.1.99.0".parse().unwrap();
        let err = session.get(&[oid]).await.unwrap_err();
        assert!(matches!(
            err,
            Error::SnmpError {
                status: ErrorStatus::NoSuchName,
                index: 1
            }
        ));
    }

    /// A v3 loopback that decrypts/verifies the request as an authoritative
    /// engine and echoes back an authenticated, encrypted Response.
    struct V3MockEngine {
        last_sent: Mutex<Vec<u8>>,
        user: UsmUser,
        engine: EngineParams,
    }

    impl Transport for V3MockEngine {
        async fn send(&self, data: &[u8]) -> Result<()> {
            *self.last_sent.lock().unwrap() = data.to_vec();
            Ok(())
        }
        async fn receive(&self) -> Result<bytes::Bytes> {
            let sent = self.last_sent.lock().unwrap().clone();
            let msg = v3::parse(&sent, Some(&self.user))?;
            let mut resp = Pdu::new(PduType::Response, msg.scoped.pdu.request_id);
            resp.variables = vec![VarBind::new(
                msg.scoped.pdu.variables[0].oid.clone(),
                Value::OctetString(b"v3-ok".to_vec()),
            )];
            let encoded =
                v3::build_request(msg.header.msg_id, &self.user, &self.engine, &[], resp)?;
            Ok(bytes::Bytes::from(encoded))
        }
    }

    #[tokio::test]
    async fn v3_auth_priv_request_roundtrip() {
        let user = UsmUser::auth_priv(
            "tester",
            crate::usm::AuthProtocol::HmacSha1,
            "authpassword",
            crate::usm::PrivProtocol::AesCfb128,
            "privpassword",
        );
        let engine = EngineParams {
            engine_id: vec![0x80, 0, 0, 0, 1, 0xab, 0xcd, 0xef],
            engine_boots: 3,
            engine_time: 600,
        };
        let transport = V3MockEngine {
            last_sent: Mutex::new(Vec::new()),
            user: user.clone(),
            engine: engine.clone(),
        };
        let mut session =
            V3Session::with_transport(transport, user, engine, Duration::from_secs(1), 1);
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let value = session.get_one(&oid).await.unwrap();
        assert_eq!(value, Value::OctetString(b"v3-ok".to_vec()));
    }
}
