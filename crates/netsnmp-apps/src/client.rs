//! A version-agnostic async SNMP [`Client`] and the connection helpers that
//! open one for a set of [`CommonArgs`].

use netsnmp::message::Version;
use netsnmp::oid::Oid;
use netsnmp::pdu::{Pdu, VarBind};
use netsnmp::session::{Session, V3Session};
use netsnmp::transport::UdpTransport;
use netsnmp::v3::EngineParams;
use netsnmp::value::Value;

use crate::addr::normalize_agent_port;
use crate::cli::CommonArgs;

/// A version-agnostic async SNMP client wrapping either a community session
/// (v1/v2c) or a USM session (v3). Tools use this so a single code path serves
/// every protocol version.
pub enum Client {
    /// SNMPv1 / SNMPv2c community session.
    Community(Session),
    /// SNMPv3 / USM session.
    V3(Box<V3Session>),
}

impl Client {
    /// GET one or more OIDs.
    pub async fn get(&mut self, oids: &[Oid]) -> netsnmp::Result<Vec<VarBind>> {
        match self {
            Client::Community(s) => s.get(oids).await,
            Client::V3(s) => s.get(oids).await,
        }
    }

    /// GETNEXT one or more OIDs.
    pub async fn get_next(&mut self, oids: &[Oid]) -> netsnmp::Result<Vec<VarBind>> {
        match self {
            Client::Community(s) => s.get_next(oids).await,
            Client::V3(s) => s.get_next(oids).await,
        }
    }

    /// SET the given bindings.
    pub async fn set(&mut self, bindings: Vec<VarBind>) -> netsnmp::Result<Vec<VarBind>> {
        match self {
            Client::Community(s) => s.set(bindings).await,
            Client::V3(s) => s.set(bindings).await,
        }
    }

    /// Walk the subtree rooted at `root`, invoking `on` for each varbind **as it
    /// arrives**, so callers can print results incrementally instead of waiting
    /// for the whole subtree. Returns the number of varbinds yielded.
    ///
    /// Uses repeated GETNEXT; stops at the end of the MIB view, on leaving the
    /// subtree, or when a non-conforming agent makes no forward progress.
    pub async fn walk_each<F>(&mut self, root: &Oid, mut on: F) -> netsnmp::Result<usize>
    where
        F: FnMut(VarBind),
    {
        let mut current = root.clone();
        let mut count = 0;
        loop {
            let vars = self.get_next(std::slice::from_ref(&current)).await?;
            let Some(vb) = vars.into_iter().next() else {
                break;
            };
            if matches!(
                vb.value,
                Value::EndOfMibView | Value::NoSuchObject | Value::NoSuchInstance
            ) || !root.is_prefix_of(&vb.oid)
                || vb.oid <= current
            {
                break;
            }
            current = vb.oid.clone();
            on(vb);
            count += 1;
        }
        Ok(count)
    }

    /// Walk the subtree rooted at `root`, collecting every varbind. Convenience
    /// wrapper over [`walk_each`](Self::walk_each) for callers that need the full
    /// set (e.g. tabular output).
    pub async fn walk(&mut self, root: &Oid) -> netsnmp::Result<Vec<VarBind>> {
        let mut out = Vec::new();
        self.walk_each(root, |vb| out.push(vb)).await?;
        Ok(out)
    }

    /// GETBULK: fetch `non_repeaters` scalars once, then repeat the remaining
    /// OIDs up to `max_repetitions` times. Requires SNMPv2c or v3.
    pub async fn get_bulk(
        &mut self,
        non_repeaters: u32,
        max_repetitions: u32,
        oids: &[Oid],
    ) -> netsnmp::Result<Vec<VarBind>> {
        match self {
            Client::Community(s) => s.get_bulk(non_repeaters, max_repetitions, oids).await,
            Client::V3(s) => s.get_bulk(non_repeaters, max_repetitions, oids).await,
        }
    }

    /// The authoritative engine ID for a v3 session (discovered during the
    /// handshake), or `None` for a community session. Needed to build
    /// `usmUserTable` row indices.
    pub fn engine_id(&self) -> Option<Vec<u8>> {
        match self {
            Client::Community(_) => None,
            Client::V3(s) => Some(s.engine().engine_id.clone()),
        }
    }

    /// Returns `true` when the session can issue GETBULK (v2c/v3). SNMPv1 has no
    /// GETBULK PDU.
    pub fn supports_bulk(&self) -> bool {
        match self {
            Client::Community(s) => s.config().version != Version::V1,
            Client::V3(_) => true,
        }
    }

    /// Walk the subtree rooted at `root` using GETBULK for efficiency, invoking
    /// `on` for each varbind **as it arrives** (so callers can print results
    /// incrementally per round-trip). Falls back to the GETNEXT-based
    /// [`walk_each`](Self::walk_each) on SNMPv1. Returns the varbind count.
    pub async fn bulk_walk_each<F>(
        &mut self,
        root: &Oid,
        max_repetitions: u32,
        mut on: F,
    ) -> netsnmp::Result<usize>
    where
        F: FnMut(VarBind),
    {
        if !self.supports_bulk() {
            return self.walk_each(root, on).await;
        }
        let max_reps = max_repetitions.max(1);
        let mut current = root.clone();
        let mut count = 0;
        loop {
            let vars = self
                .get_bulk(0, max_reps, std::slice::from_ref(&current))
                .await?;
            if vars.is_empty() {
                break;
            }
            let mut progressed = false;
            let mut finished = false;
            for vb in vars {
                if matches!(
                    vb.value,
                    Value::EndOfMibView | Value::NoSuchObject | Value::NoSuchInstance
                ) {
                    finished = true;
                    break;
                }
                // Out of the requested subtree, or no forward progress (guards
                // against a non-conforming agent looping us forever).
                if !root.is_prefix_of(&vb.oid) || vb.oid <= current {
                    finished = true;
                    break;
                }
                current = vb.oid.clone();
                on(vb);
                count += 1;
                progressed = true;
            }
            if finished || !progressed {
                break;
            }
        }
        Ok(count)
    }

    /// Walk the subtree rooted at `root` using GETBULK, collecting every varbind.
    /// Convenience wrapper over [`bulk_walk_each`](Self::bulk_walk_each). Mirrors
    /// `snmpbulkwalk`.
    pub async fn bulk_walk(
        &mut self,
        root: &Oid,
        max_repetitions: u32,
    ) -> netsnmp::Result<Vec<VarBind>> {
        let mut results = Vec::new();
        self.bulk_walk_each(root, max_repetitions, |vb| results.push(vb))
            .await?;
        Ok(results)
    }

    /// Send an unconfirmed SNMPv2-Trap (fire-and-forget).
    pub async fn send_trap(
        &mut self,
        sys_uptime: u32,
        trap_oid: &Oid,
        varbinds: Vec<VarBind>,
    ) -> netsnmp::Result<()> {
        match self {
            Client::Community(s) => s.send_trap(sys_uptime, trap_oid, varbinds).await,
            Client::V3(s) => s.send_trap(sys_uptime, trap_oid, varbinds).await,
        }
    }

    /// Send a confirmed InformRequest and await the acknowledging Response.
    pub async fn send_inform(
        &mut self,
        sys_uptime: u32,
        trap_oid: &Oid,
        varbinds: Vec<VarBind>,
    ) -> netsnmp::Result<Pdu> {
        match self {
            Client::Community(s) => s.send_inform(sys_uptime, trap_oid, varbinds).await,
            Client::V3(s) => s.send_inform(sys_uptime, trap_oid, varbinds).await,
        }
    }
}

/// Open a [`Client`] for the parsed arguments, performing v3 engine discovery
/// when a USM user was configured.
pub async fn connect(args: &CommonArgs) -> netsnmp::Result<Client> {
    if let Some(user) = &args.v3_user {
        let session = V3Session::open_udp(
            &args.agent,
            user.clone(),
            args.config.timeout,
            args.config.retries,
        )
        .await?;
        Ok(Client::V3(Box::new(session)))
    } else {
        let session = Session::open_udp(&args.agent, args.config.clone()).await?;
        Ok(Client::Community(session))
    }
}

/// A locally-generated `snmpEngineID` used by `snmptrap` when originating
/// SNMPv3 traps. As a notification originator the sender is itself the
/// authoritative engine; any engine id works as long as the receiver verifies
/// with the same user key localized to it. Format follows RFC 3411 §5
/// (enterprise 8072 = Net-SNMP, text "rsnt").
fn notifier_engine() -> EngineParams {
    EngineParams {
        engine_id: vec![0x80, 0x00, 0x1f, 0x88, 0x04, b'r', b's', b'n', b't'],
        engine_boots: 1,
        engine_time: 0,
    }
}

/// Open a [`Client`] aimed at a *notification receiver* (port 162 by default).
///
/// For confirmed informs the receiver is authoritative, so v3 performs engine
/// discovery exactly like [`connect`]. For unconfirmed traps the sender is the
/// authoritative engine: v3 skips discovery and stamps its own engine id.
pub async fn connect_notifier(
    raw_agent: &str,
    args: &CommonArgs,
    confirmed: bool,
) -> netsnmp::Result<Client> {
    let target = normalize_agent_port(raw_agent, UdpTransport::TRAP_PORT);
    if let Some(user) = &args.v3_user {
        let session = if confirmed {
            V3Session::open_udp(
                &target,
                user.clone(),
                args.config.timeout,
                args.config.retries,
            )
            .await?
        } else {
            V3Session::open_udp_notifier(
                &target,
                user.clone(),
                notifier_engine(),
                args.config.timeout,
                args.config.retries,
            )
            .await?
        };
        Ok(Client::V3(Box::new(session)))
    } else {
        let session = Session::open_udp(&target, args.config.clone()).await?;
        Ok(Client::Community(session))
    }
}
