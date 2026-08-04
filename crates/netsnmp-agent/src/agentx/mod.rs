//! AgentX protocol (RFC 2741) — master agent, subagent and PDU codec.
//!
//! Counterpart of `agent/mibgroup/agentx/` in Net-SNMP. This module provides a
//! self-contained AgentX master agent, a subagent client, and the PDU wire
//! codec defined by RFC 2741. Everything lives behind the `agentx` feature-free
//! submodule so the rest of the agent is unaffected.
//!
//! See the [`protocol`] module for the wire format and the [`master`] / [`subagent`]
//! modules for the two halves of a deployment.

pub mod master;
pub mod protocol;
pub mod subagent;

pub use master::{AgentxMaster, Registration};
pub use protocol::{
    AgentxData, AgentxError, AgentxHeader, AgentxVarBind, BulkBody, CapsBody, CleanupBody,
    CloseBody, CloseReason, IndexBody, NotifyBody, OpenBody, Pdu, PduBody, PduType, PingBody,
    RegisterBody, ResponseBody, SearchBody, SetBody, UnregisterBody,
};
pub use subagent::{Subagent, SubagentHandler};
