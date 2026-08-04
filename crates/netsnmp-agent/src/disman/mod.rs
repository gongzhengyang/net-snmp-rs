//! DISMAN (Distributed Management) MIBs.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/disman/` directory. This module
//! groups together the five RFC-defined DISMAN MIBs that the agent can serve:
//!
//! | Module        | RFC      | OID                  |
//! |---------------|----------|----------------------|
//! | [`event`]     | RFC 2981 | `1.3.6.1.2.1.88`     |
//! | [`schedule`]  | RFC 2591 | `1.3.6.1.2.1.63`     |
//! | [`expr`]      | RFC 2982 | `1.3.6.1.2.1.90`     |
//! | [`ping`]      | RFC 2925 | `1.3.6.1.2.1.80`     |
//! | [`traceroute`]| RFC 2925 | `1.3.6.1.2.1.81`     |
//! | [`nslookup`]  | RFC 2925 | `1.3.6.1.2.1.82`     |
//!
//! Each engine is a cohesive struct that owns the in-memory tables for its MIB
//! plus a way to schedule background work ([`netsnmp::alarm::AlarmRegistry`])
//! and emit notifications ([`crate::notify::NotificationOriginator`]). The
//! engines expose their tables via `*_handlers()` functions that return
//! `Arc<dyn MibHandler>` instances suitable for registration with a
//! [`crate::registry::Registry`].
//!
//! # Internal queries (iquery)
//!
//! DISMAN-EVENT and DISMAN-SCHEDULE need to read MIB values from the agent's own
//! tree (e.g. to sample a trigger target OID or evaluate an expression). In C
//! this is done by the `iquery` mechanism: the agent opens an internal session
//! using a configured `agentSecName` identity so that VACM is honoured. Here the
//! engines accept an optional `Arc<dyn MibHandler>` (typically the agent's own
//! registry, or a `Registry` shared by `Arc::clone` if you can obtain one). When
//! present, samples are read directly from that handler — much cheaper than a
//! loopback session and sufficient for the in-process case. The `agent_sec_name`
//! is recorded for VACM auditing and is applied to any notification varbinds the
//! engine emits.

pub mod event;
pub mod expr;
pub mod nslookup;
pub mod ping;
pub mod schedule;
pub mod traceroute;

pub use event::{DismanEvent, EventAction, Trigger, TriggerType};
pub use expr::{ExpressionEngine, ExprError};
pub use nslookup::NsLookupEngine;
pub use ping::PingEngine;
pub use schedule::{DismanSchedule, SchedAction, SchedEntry, SchedType};
pub use traceroute::TracerouteEngine;

use std::sync::Arc;

use crate::handler::MibHandler;
use crate::notify::NotificationOriginator;
use crate::registry::Registry;
use netsnmp::alarm::AlarmRegistry;

/// Convenience: register every DISMAN MIB handler from a single engine bundle
/// into `registry`, returning the owning engines so they can be `start()`-ed.
///
/// Each engine is constructed against the supplied [`AlarmRegistry`] and
/// optional [`NotificationOriginator`]; `self_query` is the handler the engines
/// will read MIB values from (typically the same registry, shared via
/// `Arc::clone`). The `agent_sec_name` is the iquery identity the engines use
/// when emitting notifications.
///
/// This helper does **not** modify any existing registration: it only calls
/// `registry.register(...)`, mirroring the other `register_*_mibs` helpers.
pub fn register_disman_mibs(
    registry: &mut Registry,
    alarms: Arc<AlarmRegistry>,
    notify: Option<Arc<NotificationOriginator>>,
    self_query: Option<Arc<dyn MibHandler>>,
    agent_sec_name: String,
) -> DismanBundle {
    let event = DismanEvent::new(alarms.clone(), notify.clone(), agent_sec_name.clone());
    let schedule = DismanSchedule::new(alarms.clone(), notify.clone(), agent_sec_name.clone());
    let expr = ExpressionEngine::new(self_query.clone());
    let ping = PingEngine::new();
    let traceroute = TracerouteEngine::new();
    let nslookup = NsLookupEngine::new();

    for h in DismanEvent::handlers(Arc::clone(&event)) {
        registry.register(h);
    }
    for h in DismanSchedule::handlers(Arc::clone(&schedule)) {
        registry.register(h);
    }
    for h in ExpressionEngine::handlers(Arc::clone(&expr)) {
        registry.register(h);
    }
    for h in PingEngine::handlers(Arc::clone(&ping)) {
        registry.register(h);
    }
    for h in TracerouteEngine::handlers(Arc::clone(&traceroute)) {
        registry.register(h);
    }
    for h in NsLookupEngine::handlers(Arc::clone(&nslookup)) {
        registry.register(h);
    }

    DismanBundle {
        event,
        schedule,
        expr,
        ping,
        traceroute,
        nslookup,
    }
}

/// The owning bundle of all DISMAN engines registered by
/// [`register_disman_mibs`]. Hold on to this so the engines are not dropped
/// (which would tear down their handler state) and so `start()` can be called
/// to launch background polling tasks.
pub struct DismanBundle {
    /// The DISMAN-EVENT-MIB engine (triggers, events, objects).
    pub event: Arc<DismanEvent>,
    /// The DISMAN-SCHEDULE-MIB engine.
    pub schedule: Arc<DismanSchedule>,
    /// The DISMAN-EXPRESSION-MIB engine.
    pub expr: Arc<ExpressionEngine>,
    /// The DISMAN-PING-MIB engine.
    pub ping: Arc<PingEngine>,
    /// The DISMAN-TRACEROUTE-MIB engine.
    pub traceroute: Arc<TracerouteEngine>,
    /// The DISMAN-NSLOOKUP-MIB engine.
    pub nslookup: Arc<NsLookupEngine>,
}

impl DismanBundle {
    /// Start every engine's background polling. Must be called from within a
    /// tokio runtime context (the engines register periodic alarms).
    pub async fn start(&self) {
        self.event.start().await;
        self.schedule.start().await;
    }
}
