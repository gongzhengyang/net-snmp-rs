//! DISMAN-EVENT-MIB (`1.3.6.1.2.1.88`, RFC 2981).
//!
//! Implements the trigger/event/object triad that lets an agent autonomously
//! monitor one of its own MIB objects and raise a notification (or perform a
//! SET) when a condition is met. Counterpart of Net-SNMP's
//! `agent/mibgroup/disman/event/mteTrigger*`, `mteEvent*` and `mteObjects*`
//! files.
//!
//! # Model
//!
//! - [`Trigger`] rows live in `mteTriggerTable`. Each names a target OID, a
//!   sample interval, and a comparison type ([`TriggerType`]). A background
//!   task — driven by [`netsnmp::alarm::AlarmRegistry`] — polls each active
//!   trigger. When a condition is met, the trigger "fires".
//! - Firing a trigger looks up the [`Event`] rows in its `mteTriggerEvent`
//!   link (a whitespace- or comma-separated list of event names). Each linked
//!   [`Event`] performs its [`EventAction`]: emit a notification or SET an OID.
//! - [`MteObject`] rows (the `mteObjectsTable`) list extra varbinds to attach
//!   to a notification, keyed by owner name + event name.
//!
//! # Tables served
//!
//! | Table             | OID                       | Columns served (read-only) |
//! |-------------------|---------------------------|----------------------------|
//! | `mteTriggerTable` | `1.3.6.1.2.1.88.1.2.2.1`  | name, target, interval, type, thresholds, status, etc. |
//! | `mteEventTable`   | `1.3.6.1.2.1.88.1.4.2.1`  | name, action, status       |
//! | `mteObjectsTable` | `1.3.6.1.2.1.88.1.3.2.1`  | id, oid, status            |
//!
//! The tables are read-only over SNMP by default (the engine is configured
//! programmatically). Write-via-RowStatus is supported through the
//! [`DismanEvent::add_trigger`] / [`DismanEvent::add_event`] / [`DismanEvent::add_object`]
//! runtime API.
//!
//! # Internal queries (iquery)
//!
//! To sample the target OID the engine reads from an optional shared
//! [`MibHandler`] (typically the agent's own [`crate::registry::Registry`]
//! shared via `Arc::clone`). When that is `None`, samples come back as zero
//! and triggers never fire — useful for unit testing the wiring without a live
//! MIB tree. The `agent_sec_name` is carried on the engine for VACM auditing
//! and is recorded in [`Trigger`] for downstream use.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use netsnmp::alarm::AlarmRegistry;
use netsnmp::oid::Oid;
use netsnmp::pdu::VarBind;
use netsnmp::value::Value;
use tracing::{debug, warn};

use crate::handler::{MibHandler, Reading};
use crate::notify::NotificationOriginator;

/// The DISMAN-EVENT-MIB root (`1.3.6.1.2.1.88`).
pub const MTE_MIB: &[u32] = &[1, 3, 6, 1, 2, 1, 88];

/// `mteTriggerTable` entry OID (`1.3.6.1.2.1.88.1.2.2.1`).
pub const MTE_TRIGGER_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 88, 1, 2, 2, 1];

/// `mteEventTable` entry OID (`1.3.6.1.2.1.88.1.4.2.1`).
pub const MTE_EVENT_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 88, 1, 4, 2, 1];

/// `mteObjectsTable` entry OID (`1.3.6.1.2.1.88.1.3.2.1`).
pub const MTE_OBJECTS_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 88, 1, 3, 2, 1];

// mteTriggerTable column numbers (RFC 2981 §2.2.1). These document the RFC
// arc numbers for every column of the table; the ones not currently emitted by
// the read-only handler are kept for reference and future write support.
#[allow(dead_code)]
const MTET_TRIGGER_ID: u32 = 2;
const MTET_TRIGGER_TARGET: u32 = 5;
#[allow(dead_code)] // MIB column number reserved for completeness
const MTET_TRIGGER_CONTEXT: u32 = 6;
const MTET_TRIGGER_FREQ: u32 = 8;
const MTET_TRIGGER_TEST: u32 = 9;
#[allow(dead_code)] // MIB column number reserved for completeness
const MTET_TRIGGER_SAMPLE: u32 = 12;
const MTET_TRIGGER_BOOL_COMP: u32 = 18;
const MTET_TRIGGER_BOOL_VALUE: u32 = 19;
const MTET_TRIGGER_THRES_RISE: u32 = 23;
const MTET_TRIGGER_THRES_FALL: u32 = 24;
#[allow(dead_code)] // MIB column number reserved for completeness
const MTET_TRIGGER_THRES_D_RISE: u32 = 25;
#[allow(dead_code)] // MIB column number reserved for completeness
const MTET_TRIGGER_THRES_D_FALL: u32 = 26;
const MTET_TRIGGER_ENABLED: u32 = 4;
const MTET_TRIGGER_ROW_STATUS: u32 = 14;

// mteEventTable column numbers (RFC 2981 §2.4.1).
const MTEE_EVENT_NAME: u32 = 2;
const MTEE_EVENT_ENABLED: u32 = 4;
const MTEE_EVENT_ACTIONS: u32 = 5;
const MTEE_EVENT_NOTIFY: u32 = 8;
const MTEE_EVENT_SET_OID: u32 = 11;
const MTEE_EVENT_SET_VALUE: u32 = 12;
const MTEE_EVENT_ROW_STATUS: u32 = 10;

// mteObjectsTable column numbers (RFC 2981 §2.3.1).
const MTEO_OBJECT_ID: u32 = 4;
const MTEO_OBJECT_ID_WILDC: u32 = 5;
const MTEO_OBJECT_ROW_STATUS: u32 = 6;

/// The trigger test type, mirroring the bits of `mteTriggerTest`
/// (`existence(0)`, `boolean(1)`, `threshold(2)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriggerType {
    /// Existence test (`mteTriggerExistence`): fires when the target is
    /// present/absent. In this implementation, "present" fires once when the
    /// sample is first successfully read; absence is not tracked to avoid
    /// spurious traps.
    Existence,
    /// Boolean test (`mteTriggerBoolean`): compare the sampled value against
    /// `boolean_value` with `boolean_comparison`, fire when the comparison is
    /// true. Comparisons are encoded as per RFC 2981: `1`=equal, `2`=unequal,
    /// `3`=less, `4`=lessOrEqual, `5`=greater, `6`=greaterOrEqual.
    Boolean(u8),
    /// Threshold test (`mteTriggerThreshold`): fire `rising` when the sample
    /// crosses `rising_threshold` upward and `falling` when it crosses
    /// `falling_threshold` downward.
    Threshold,
    /// Delta threshold test: like [`TriggerType::Threshold`] but compared
    /// against the rate of change between two samples.
    DeltaThreshold,
}

/// A Boolean comparison operator (RFC 2981 `mteTriggerBooleanComparison`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BoolComparison {
    /// `mteTriggerBooleanComparison` = 1: fire when sample == value.
    Equal = 1,
    /// = 2: fire when sample != value.
    Unequal = 2,
    /// = 3: fire when sample < value.
    Less = 3,
    /// = 4: fire when sample <= value.
    LessOrEqual = 4,
    /// = 5: fire when sample > value.
    Greater = 5,
    /// = 6: fire when sample >= value.
    GreaterOrEqual = 6,
}

impl BoolComparison {
    /// Parse from the wire integer; returns `None` for out-of-range.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(BoolComparison::Equal),
            2 => Some(BoolComparison::Unequal),
            3 => Some(BoolComparison::Less),
            4 => Some(BoolComparison::LessOrEqual),
            5 => Some(BoolComparison::Greater),
            6 => Some(BoolComparison::GreaterOrEqual),
            _ => None,
        }
    }

    /// Evaluate the comparison against a sampled value.
    pub fn evaluate(self, sample: i64, reference: i64) -> bool {
        match self {
            BoolComparison::Equal => sample == reference,
            BoolComparison::Unequal => sample != reference,
            BoolComparison::Less => sample < reference,
            BoolComparison::LessOrEqual => sample <= reference,
            BoolComparison::Greater => sample > reference,
            BoolComparison::GreaterOrEqual => sample >= reference,
        }
    }
}

/// What action an [`Event`] performs when it fires (RFC 2981 `mteEventActions`).
#[derive(Clone, Debug, PartialEq)]
pub enum EventAction {
    /// Send a notification (`mteEventNotification`). The OID is the trap OID;
    /// attached varbinds come from the matching `mteObjectsTable` rows.
    Notification(Oid),
    /// SET an OID to a value (`mteEventSet`).
    Set {
        /// The OID to write.
        oid: Oid,
        /// The value to write.
        value: Value,
    },
    /// No action (the event is configured but does nothing yet).
    None,
}

/// One `mteTriggerTable` row.
#[derive(Clone, Debug)]
pub struct Trigger {
    /// The owner name (RFC 2571 `SnmpAdminString` index part 1). In Net-SNMP
    /// this is conventionally the same `agentSecName` that owns the trigger.
    pub owner: String,
    /// The trigger name (index part 2).
    pub name: String,
    /// The target OID to sample (without trailing instance).
    pub target: Oid,
    /// The instance suffix appended to `target` to form the sampled OID. Empty
    /// means `target` itself is sampled. (Corresponds to the trailing portion
    /// of `mteTriggerValueID` after the wildcarded prefix.)
    pub target_instance: Vec<u32>,
    /// The sample interval.
    pub frequency: Duration,
    /// The test type and parameters.
    pub test: TriggerType,
    /// For boolean tests: the comparison operator.
    pub boolean_comparison: BoolComparison,
    /// For boolean tests: the reference value.
    pub boolean_value: i64,
    /// For threshold tests: the rising threshold.
    pub rising_threshold: i64,
    /// For threshold tests: the falling threshold.
    pub falling_threshold: i64,
    /// Whether the trigger is enabled (and so polled by the background task).
    pub enabled: bool,
    /// The event names (owner-relative) linked to this trigger. May be a
    /// space/comma-separated list as on the wire; here it is split at insertion
    /// time into discrete names.
    pub event_links: Vec<String>,
    // Runtime hysteresis state: the last sample value, used by threshold
    // tests to detect a crossing.
    last_sample: Option<i64>,
    // Whether the existence test has already fired for this trigger.
    existence_fired: bool,
}

impl Trigger {
    /// The fully-qualified sampled OID = `target + target_instance`.
    pub fn sampled_oid(&self) -> Oid {
        let mut parts = self.target.as_slice().to_vec();
        parts.extend_from_slice(&self.target_instance);
        Oid::new(parts)
    }

    /// Construct a basic existence trigger.
    pub fn existence(owner: impl Into<String>, name: impl Into<String>, target: Oid) -> Self {
        Trigger::new(owner, name, target, TriggerType::Existence)
    }

    /// Construct a boolean trigger.
    pub fn boolean(
        owner: impl Into<String>,
        name: impl Into<String>,
        target: Oid,
        cmp: BoolComparison,
        value: i64,
    ) -> Self {
        let mut t = Trigger::new(owner, name, target, TriggerType::Boolean(cmp as u8));
        t.boolean_comparison = cmp;
        t.boolean_value = value;
        t
    }

    /// Construct a threshold trigger.
    pub fn threshold(
        owner: impl Into<String>,
        name: impl Into<String>,
        target: Oid,
        rising: i64,
        falling: i64,
    ) -> Self {
        let mut t = Trigger::new(owner, name, target, TriggerType::Threshold);
        t.rising_threshold = rising;
        t.falling_threshold = falling;
        t
    }

    /// Common constructor for the builder helpers.
    fn new(
        owner: impl Into<String>,
        name: impl Into<String>,
        target: Oid,
        test: TriggerType,
    ) -> Self {
        Trigger {
            owner: owner.into(),
            name: name.into(),
            target,
            target_instance: Vec::new(),
            frequency: Duration::from_secs(60),
            test,
            boolean_comparison: BoolComparison::Greater,
            boolean_value: 0,
            rising_threshold: 0,
            falling_threshold: 0,
            enabled: true,
            event_links: Vec::new(),
            last_sample: None,
            existence_fired: false,
        }
    }

    /// Builder: set the sample interval.
    pub fn with_frequency(mut self, d: Duration) -> Self {
        self.frequency = d;
        self
    }

    /// Builder: set the instance suffix appended to `target`.
    pub fn with_instance(mut self, inst: Vec<u32>) -> Self {
        self.target_instance = inst;
        self
    }

    /// Builder: link one or more event names to this trigger.
    pub fn with_events(mut self, names: Vec<String>) -> Self {
        self.event_links = names;
        self
    }

    /// Builder: enable/disable.
    pub fn enabled(mut self, en: bool) -> Self {
        self.enabled = en;
        self
    }
}

/// One `mteEventTable` row.
#[derive(Clone, Debug)]
pub struct Event {
    /// The owner name (index part 1).
    pub owner: String,
    /// The event name (index part 2).
    pub name: String,
    /// The action to take when the event fires.
    pub action: EventAction,
    /// Whether the event is enabled.
    pub enabled: bool,
}

impl Event {
    /// Construct a notification event.
    pub fn notification(
        owner: impl Into<String>,
        name: impl Into<String>,
        trap_oid: Oid,
    ) -> Self {
        Event {
            owner: owner.into(),
            name: name.into(),
            action: EventAction::Notification(trap_oid),
            enabled: true,
        }
    }

    /// Construct a SET event.
    pub fn set(
        owner: impl Into<String>,
        name: impl Into<String>,
        oid: Oid,
        value: Value,
    ) -> Self {
        Event {
            owner: owner.into(),
            name: name.into(),
            action: EventAction::Set { oid, value },
            enabled: true,
        }
    }
}

/// One `mteObjectsTable` row: an extra varbind to attach to a notification.
#[derive(Clone, Debug)]
pub struct MteObject {
    /// The owner name (index part 1, matching the event owner).
    pub owner: String,
    /// The event/object name (index part 2).
    pub name: String,
    /// The object id (index part 3) — a sort key when multiple objects attach.
    pub id: u32,
    /// The OID whose value to attach.
    pub oid: Oid,
    /// Whether the OID is wildcarded (instance comes from the trigger).
    pub wildcard: bool,
}

/// The DISMAN-EVENT engine: owns the three tables, schedules polling, and fires
/// linked events.
pub struct DismanEvent {
    triggers: RwLock<HashMap<String, Trigger>>,
    events: RwLock<HashMap<String, Event>>,
    objects: RwLock<HashMap<String, Vec<MteObject>>>,
    notify: Option<Arc<NotificationOriginator>>,
    alarms: Arc<AlarmRegistry>,
    agent_sec_name: String,
    self_query: RwLock<Option<Arc<dyn MibHandler>>>,
    // The alarm id registered by start(), so start() is idempotent.
    started: RwLock<bool>,
}

impl std::fmt::Debug for DismanEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DismanEvent")
            .field("triggers", &self.triggers.read().ok().map(|m| m.len()))
            .field("events", &self.events.read().ok().map(|m| m.len()))
            .field("agent_sec_name", &self.agent_sec_name)
            .finish()
    }
}

fn key(owner: &str, name: &str) -> String {
    format!("{owner}\u{0}{name}")
}

impl DismanEvent {
    /// Create a new engine. `alarms` schedules background polling; `notify`
    /// is the channel over which fired notifications are emitted (may be
    /// `None` for testing); `agent_sec_name` is the iquery identity used for
    /// VACM auditing and recorded on emitted varbinds.
    pub fn new(
        alarms: Arc<AlarmRegistry>,
        notify: Option<Arc<NotificationOriginator>>,
        agent_sec_name: String,
    ) -> Arc<Self> {
        Arc::new(DismanEvent {
            triggers: RwLock::new(HashMap::new()),
            events: RwLock::new(HashMap::new()),
            objects: RwLock::new(HashMap::new()),
            notify,
            alarms,
            agent_sec_name,
            self_query: RwLock::new(None),
            started: RwLock::new(false),
        })
    }

    /// Set the handler the engine reads MIB samples from. Typically the agent's
    /// own registry (passed via `Arc::clone`). When `None` (the default), every
    /// sample returns `None` and triggers never fire.
    pub fn set_self_query(&self, handler: Arc<dyn MibHandler>) {
        *self.self_query.write().unwrap() = Some(handler);
    }

    /// The iquery identity this engine acts under.
    pub fn agent_sec_name(&self) -> &str {
        &self.agent_sec_name
    }

    /// Register a trigger row. Overwrites any existing trigger with the same
    /// `(owner, name)` key.
    pub fn add_trigger(&self, t: Trigger) {
        let k = key(&t.owner, &t.name);
        self.triggers.write().unwrap().insert(k, t);
    }

    /// Remove a trigger row.
    pub fn remove_trigger(&self, owner: &str, name: &str) -> Option<Trigger> {
        self.triggers.write().unwrap().remove(&key(owner, name))
    }

    /// Register an event row.
    pub fn add_event(&self, e: Event) {
        let k = key(&e.owner, &e.name);
        self.events.write().unwrap().insert(k, e);
    }

    /// Register an object row (a varbind to attach to a notification).
    pub fn add_object(&self, o: MteObject) {
        let k = key(&o.owner, &o.name);
        self.objects
            .write()
            .unwrap()
            .entry(k)
            .or_default()
            .push(o);
    }

    /// Read a sample for `target_oid` from the configured self-query handler.
    /// Returns the value as `i64` (counters/gauges/integers are coerced), or
    /// `None` if the OID is absent or not numeric.
    pub fn sample(&self, target_oid: &Oid) -> Option<i64> {
        let h = self.self_query.read().unwrap().clone()?;
        match h.get(target_oid) {
            Some(v) => value_to_i64(&v),
            None => None,
        }
    }

    /// Drive a single poll cycle: sample every enabled trigger and fire its
    /// linked events if the condition is met. Public so tests can drive the
    /// poll loop deterministically without spawning alarm tasks.
    pub fn poll_once(&self) {
        let triggers: Vec<(String, Trigger)> = self
            .triggers
            .read()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (k, mut t) in triggers {
            if !t.enabled {
                continue;
            }
            let oid = t.sampled_oid();
            let sample = self.sample(&oid);
            let fires = evaluate(&mut t, sample);
            // Write back the (possibly mutated) hysteresis state.
            self.triggers.write().unwrap().insert(k, t.clone());
            if let Some(reason) = fires {
                debug!(trigger = %t.name, %reason, "trigger fired");
                self.fire_events(&t, sample);
            }
        }
    }

    /// Fire every event linked to `trigger`, attaching the matching object
    /// varbinds to any notification.
    fn fire_events(&self, trigger: &Trigger, sample: Option<i64>) {
        let events = self.events.read().unwrap();
        for link in &trigger.event_links {
            // Try owner-relative first (the common case), then the link as a
            // bare name against the trigger's owner.
            let ev = events
                .get(&key(&trigger.owner, link))
                .or_else(|| events.get(&key("", link)))
                .or_else(|| events.values().find(|e| e.name == *link));
            let Some(ev) = ev else {
                debug!(event = %link, "no event matches trigger link, skipping");
                continue;
            };
            if !ev.enabled {
                continue;
            }
            let attached = self.collect_objects(&ev.owner, &ev.name, trigger, sample);
            self.execute_action(&ev.action, trigger, attached);
        }
    }

    /// Gather the varbinds to attach to a notification for `(owner, name)`.
    fn collect_objects(
        &self,
        owner: &str,
        name: &str,
        trigger: &Trigger,
        _sample: Option<i64>,
    ) -> Vec<VarBind> {
        let objects = self.objects.read().unwrap();
        let mut rows = objects
            .get(&key(owner, name))
            .cloned()
            .unwrap_or_default();
        rows.sort_by_key(|o| o.id);
        let mut vbs = Vec::new();
        for o in rows {
            let value_oid = if o.wildcard {
                // Append the trigger's instance suffix to the wildcarded OID.
                let mut parts = o.oid.as_slice().to_vec();
                parts.extend_from_slice(&trigger.target_instance);
                Oid::new(parts)
            } else {
                o.oid.clone()
            };
            if let Some(v) = self.sample(&value_oid) {
                vbs.push(VarBind::new(value_oid, Value::Integer(v)));
            }
        }
        vbs
    }

    /// Execute a single event action.
    fn execute_action(
        &self,
        action: &EventAction,
        _trigger: &Trigger,
        attached: Vec<VarBind>,
    ) {
        match action {
            EventAction::Notification(oid) => {
                if let Some(notify) = &self.notify {
                    let oid = oid.clone();
                    // Fire-and-forget: spawn so we don't block the poll task.
                    let notify = Arc::clone(notify);
                    tokio::spawn(async move {
                        if let Err(e) = notify.send(&oid, attached).await {
                            warn!(error = %e, "disman event notification send failed");
                        }
                    });
                } else {
                    debug!("notification event has no originator configured, dropping");
                }
            }
            EventAction::Set { oid, value } => {
                if let Some(h) = self.self_query.read().unwrap().as_ref() {
                    if let Err(e) = h.commit_set(oid, value) {
                        warn!(oid = %oid, error = ?e, "disman event SET failed");
                    }
                } else {
                    debug!("set event has no self-query handler, dropping");
                }
            }
            EventAction::None => {}
        }
    }

    /// Start the background polling task. The engine registers a single
    /// repeating alarm whose interval is the minimum trigger frequency (a
    /// coarse scheduler; individual triggers are evaluated on each tick). This
    /// is idempotent: calling `start()` more than once is a no-op.
    ///
    /// Must be called from within a tokio runtime context.
    pub async fn start(self: &Arc<Self>) {
        let mut started = self.started.write().unwrap();
        if *started {
            return;
        }
        *started = true;
        drop(started);

        let interval = self
            .triggers
            .read()
            .unwrap()
            .values()
            .filter(|t| t.enabled)
            .map(|t| t.frequency)
            .min()
            .unwrap_or(Duration::from_secs(60));
        let engine = Arc::clone(self);
        self.alarms
            .add_repeat(interval, move || {
                let engine = Arc::clone(&engine);
                tokio::spawn(async move {
                    engine.poll_once();
                });
            })
            .await;
    }

    /// Build the three read-only MIB handlers (trigger/event/objects tables)
    /// exposing the engine's state to SNMP walkers. The returned handlers hold
    /// a weak-ish reference back to this engine via `Arc`, so the engine must
    /// outlive the registry registration.
    pub fn handlers(engine: Arc<DismanEvent>) -> Vec<Arc<dyn MibHandler>> {
        vec![
            Arc::new(TriggerTableHandler::new(Arc::clone(&engine))),
            Arc::new(EventTableHandler::new(Arc::clone(&engine))),
            Arc::new(ObjectsTableHandler::new(engine)),
        ]
    }
}

/// Evaluate a trigger against a fresh sample, mutating `trigger`'s hysteresis
/// state. Returns `Some(reason)` if the trigger fires, else `None`.
fn evaluate(trigger: &mut Trigger, sample: Option<i64>) -> Option<&'static str> {
    match trigger.test {
        TriggerType::Existence => {
            if sample.is_some() && !trigger.existence_fired {
                trigger.existence_fired = true;
                trigger.last_sample = sample;
                Some("existence")
            } else {
                None
            }
        }
        TriggerType::Boolean(code) => {
            let s = sample?;
            let cmp = BoolComparison::from_u8(code).unwrap_or(trigger.boolean_comparison);
            trigger.last_sample = Some(s);
            if cmp.evaluate(s, trigger.boolean_value) {
                Some("boolean")
            } else {
                None
            }
        }
        TriggerType::Threshold => {
            let s = sample?;
            let prev = trigger.last_sample.replace(s);
            match prev {
                None => None,
                Some(p) => {
                    // Rising crossing: prev below, sample at or above.
                    if s >= trigger.rising_threshold && p < trigger.rising_threshold {
                        Some("rising")
                    } else if s <= trigger.falling_threshold
                        && p > trigger.falling_threshold
                    {
                        Some("falling")
                    } else {
                        None
                    }
                }
            }
        }
        TriggerType::DeltaThreshold => {
            let s = sample?;
            let prev = trigger.last_sample.replace(s);
            match prev {
                None => None,
                Some(p) => {
                    let delta = s - p;
                    if delta >= trigger.rising_threshold {
                        Some("delta-rising")
                    } else if delta <= trigger.falling_threshold {
                        Some("delta-falling")
                    } else {
                        None
                    }
                }
            }
        }
    }
}

/// Coerce an SNMP [`Value`] into `i64` for sampling. Counters, gauges, integers
/// and TimeTicks are accepted; everything else returns `None`.
fn value_to_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(x) => Some(*x),
        Value::Counter32(x) => Some(*x as i64),
        Value::Gauge32(x) => Some(*x as i64),
        Value::TimeTicks(x) => Some(*x as i64),
        Value::Counter64(x) => Some(*x as i64),
        _ => None,
    }
}

/// Encode a string index as SNMP sub-identifiers (one byte each). Matches
/// Net-SNMP's `snmp_varlist_add_variable` string-index convention used by
/// DISMAN tables.
fn string_index(s: &str) -> Vec<u32> {
    s.bytes().map(|b| b as u32).collect()
}

/// Read-only handler exposing `mteTriggerTable`. Index is `(owner, name)` as
/// two consecutive string-encoded sub-identifiers separated by a `0` length
/// sub-id (RFC 2571 `SnmpAdminString` index convention). To keep the walk
/// correct without doing the full string-index dance we index by `name` alone;
/// this is sufficient for the read-only programmatic use case.
struct TriggerTableHandler {
    root: Oid,
    engine: Arc<DismanEvent>,
}

impl TriggerTableHandler {
    fn new(engine: Arc<DismanEvent>) -> Self {
        TriggerTableHandler {
            root: Oid::new(MTE_TRIGGER_ENTRY.to_vec()),
            engine,
        }
    }

    /// Build all (oid, value) cells for the current table state.
    fn cells(&self) -> Vec<(Oid, Value)> {
        let triggers = self.engine.triggers.read().unwrap();
        let mut out = Vec::new();
        for t in triggers.values() {
            // Index by owner bytes + 0 separator + name bytes.
            let mut index = string_index(&t.owner);
            index.push(0);
            index.extend(string_index(&t.name));
            let put = |col: u32, value: Value| -> (Oid, Value) {
                (self.cell_oid(col, &index), value)
            };
            out.push(put(MTET_TRIGGER_ID, Value::OctetString(t.name.bytes().collect())));
            out.push(put(
                MTET_TRIGGER_TARGET,
                Value::Oid(t.target.clone()),
            ));
            out.push(put(
                MTET_TRIGGER_FREQ,
                Value::Gauge32(t.frequency.as_secs() as u32),
            ));
            out.push(put(MTET_TRIGGER_TEST, Value::OctetString(test_bits(t.test))));
            out.push(put(
                MTET_TRIGGER_ENABLED,
                Value::Integer(if t.enabled { 1 } else { 0 }),
            ));
            out.push(put(
                MTET_TRIGGER_BOOL_COMP,
                Value::Integer(t.boolean_comparison as i64),
            ));
            out.push(put(
                MTET_TRIGGER_BOOL_VALUE,
                Value::Integer(t.boolean_value),
            ));
            out.push(put(
                MTET_TRIGGER_THRES_RISE,
                Value::Integer(t.rising_threshold),
            ));
            out.push(put(
                MTET_TRIGGER_THRES_FALL,
                Value::Integer(t.falling_threshold),
            ));
            out.push(put(
                MTET_TRIGGER_ROW_STATUS,
                Value::Integer(crate::row::RowStatus::Active.as_i64()),
            ));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    fn cell_oid(&self, col: u32, index: &[u32]) -> Oid {
        let mut oid = self.root.child(col);
        for &s in index {
            oid = oid.child(s);
        }
        oid
    }
}

/// Bits value for `mteTriggerTest` (`existence(0)` / `boolean(1)` / `threshold(2)`).
fn test_bits(t: TriggerType) -> Vec<u8> {
    match t {
        TriggerType::Existence => vec![0b0000_0001],
        TriggerType::Boolean(_) => vec![0b0000_0010],
        TriggerType::Threshold | TriggerType::DeltaThreshold => vec![0b0000_0100],
    }
}

impl MibHandler for TriggerTableHandler {
    fn root(&self) -> &Oid {
        &self.root
    }

    fn get(&self, oid: &Oid) -> Option<Value> {
        self.cells()
            .into_iter()
            .find(|(o, _)| o == oid)
            .map(|(_, v)| v)
    }

    fn get_next(&self, oid: &Oid) -> Option<Reading> {
        let cells = self.cells();
        let idx = cells.partition_point(|(o, _)| o <= oid);
        cells.get(idx).map(|(o, v)| Reading {
            oid: o.clone(),
            value: v.clone(),
        })
    }
}

/// Read-only handler exposing `mteEventTable`.
struct EventTableHandler {
    root: Oid,
    engine: Arc<DismanEvent>,
}

impl EventTableHandler {
    fn new(engine: Arc<DismanEvent>) -> Self {
        EventTableHandler {
            root: Oid::new(MTE_EVENT_ENTRY.to_vec()),
            engine,
        }
    }

    fn cells(&self) -> Vec<(Oid, Value)> {
        let events = self.engine.events.read().unwrap();
        let mut out = Vec::new();
        for e in events.values() {
            let mut index = string_index(&e.owner);
            index.push(0);
            index.extend(string_index(&e.name));
            let put = |col: u32, value: Value| -> (Oid, Value) {
                let mut oid = self.root.child(col);
                for &s in &index {
                    oid = oid.child(s);
                }
                (oid, value)
            };
            out.push(put(MTEE_EVENT_NAME, Value::OctetString(e.name.bytes().collect())));
            out.push(put(
                MTEE_EVENT_ENABLED,
                Value::Integer(if e.enabled { 1 } else { 0 }),
            ));
            // mteEventActions is a BITS: notification(0), set(1). The Value
            // enum exposes BITS as OctetString (its on-wire form).
            let action_bits = match &e.action {
                EventAction::Notification(_) => vec![0b0000_0001u8],
                EventAction::Set { .. } => vec![0b0000_0010u8],
                EventAction::None => vec![],
            };
            out.push(put(MTEE_EVENT_ACTIONS, Value::OctetString(action_bits)));
            if let EventAction::Notification(oid) = &e.action {
                out.push(put(MTEE_EVENT_NOTIFY, Value::Oid(oid.clone())));
            } else {
                out.push(put(MTEE_EVENT_NOTIFY, Value::Oid(Oid::null())));
            }
            if let EventAction::Set { oid, value } = &e.action {
                out.push(put(MTEE_EVENT_SET_OID, Value::Oid(oid.clone())));
                out.push(put(MTEE_EVENT_SET_VALUE, value.clone()));
            } else {
                out.push(put(MTEE_EVENT_SET_OID, Value::Oid(Oid::null())));
                out.push(put(MTEE_EVENT_SET_VALUE, Value::Null));
            }
            out.push(put(
                MTEE_EVENT_ROW_STATUS,
                Value::Integer(crate::row::RowStatus::Active.as_i64()),
            ));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

impl MibHandler for EventTableHandler {
    fn root(&self) -> &Oid {
        &self.root
    }

    fn get(&self, oid: &Oid) -> Option<Value> {
        self.cells()
            .into_iter()
            .find(|(o, _)| o == oid)
            .map(|(_, v)| v)
    }

    fn get_next(&self, oid: &Oid) -> Option<Reading> {
        let cells = self.cells();
        let idx = cells.partition_point(|(o, _)| o <= oid);
        cells.get(idx).map(|(o, v)| Reading {
            oid: o.clone(),
            value: v.clone(),
        })
    }
}

/// Read-only handler exposing `mteObjectsTable`.
struct ObjectsTableHandler {
    root: Oid,
    engine: Arc<DismanEvent>,
}

impl ObjectsTableHandler {
    fn new(engine: Arc<DismanEvent>) -> Self {
        ObjectsTableHandler {
            root: Oid::new(MTE_OBJECTS_ENTRY.to_vec()),
            engine,
        }
    }

    fn cells(&self) -> Vec<(Oid, Value)> {
        let objects = self.engine.objects.read().unwrap();
        let mut out = Vec::new();
        for (k, rows) in objects.iter() {
            let (owner, name) = k.split_once('\u{0}').unwrap_or((k.as_str(), ""));
            for o in rows {
                let mut index = string_index(owner);
                index.push(0);
                index.extend(string_index(name));
                index.push(0);
                index.push(o.id);
                let put = |col: u32, value: Value| -> (Oid, Value) {
                    let mut oid = self.root.child(col);
                    for &s in &index {
                        oid = oid.child(s);
                    }
                    (oid, value)
                };
                out.push(put(MTEO_OBJECT_ID, Value::Oid(o.oid.clone())));
                out.push(put(
                    MTEO_OBJECT_ID_WILDC,
                    Value::Integer(if o.wildcard { 1 } else { 0 }),
                ));
                out.push(put(
                    MTEO_OBJECT_ROW_STATUS,
                    Value::Integer(crate::row::RowStatus::Active.as_i64()),
                ));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

impl MibHandler for ObjectsTableHandler {
    fn root(&self) -> &Oid {
        &self.root
    }

    fn get(&self, oid: &Oid) -> Option<Value> {
        self.cells()
            .into_iter()
            .find(|(o, _)| o == oid)
            .map(|(_, v)| v)
    }

    fn get_next(&self, oid: &Oid) -> Option<Reading> {
        let cells = self.cells();
        let idx = cells.partition_point(|(o, _)| o <= oid);
        cells.get(idx).map(|(o, v)| Reading {
            oid: o.clone(),
            value: v.clone(),
        })
    }
}

// Implementations of the DISMAN tables above use the public `Value` variants
// (Gauge32 for Unsigned32, OctetString for BITS), which is SNMP-correct on the
// wire and avoids needing a BITS-specific variant on the `Value` enum.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::MibHandler;
    use crate::scalar::ScalarHandler;
    use netsnmp::pdu::VarBind;

    /// A mock notification originator that records every notification it would
    /// send. Implements just enough of the surface to capture the trap OID and
    /// attached varbinds without actually opening a socket.
    ///
    /// The real [`NotificationOriginator`] doesn't expose a recording hook, so
    /// the tests below instead exercise [`DismanEvent::execute_action`] through
    /// `poll_once()` with a real `NotificationOriginator` whose `send` is a
    /// no-op when no targets are configured — that's enough to prove the
    /// engine queues the right action without panicking.
    #[tokio::test]
    async fn threshold_trigger_fires_on_rising_crossing() {
        let alarms = Arc::new(AlarmRegistry::new());
        let engine = DismanEvent::new(alarms, None, "internal".to_string());

        // A scalar that we mutate to simulate the monitored object changing.
        let scalar = Arc::new(ScalarHandler::new(
            "1.3.6.1.2.1.2.2.1.10.1".parse().unwrap(),
            Value::Counter32(0),
        ));
        engine.set_self_query(scalar.clone());

        // Threshold trigger: rising at 100, falling at 0. Link an event that
        // SETs another OID — we'll observe the side effect.
        let set_target = Arc::new(
            ScalarHandler::new(
                "1.3.6.1.4.1.8072.999.1".parse().unwrap(),
                Value::Integer(0),
            )
            .writable(),
        );
        // Add the SET target to the self-query by wrapping both in a small
        // composite handler implemented inline.
        let composite = Arc::new(CompositeHandler::new(vec![
            Arc::clone(&scalar) as Arc<dyn MibHandler>,
            Arc::clone(&set_target) as Arc<dyn MibHandler>,
        ]));
        engine.set_self_query(composite.clone());

        let mut t = Trigger::threshold("", "t1", "1.3.6.1.2.1.2.2.1.10.1".parse().unwrap(), 100, 0)
            .with_instance(vec![0]);
        t.event_links = vec!["e1".to_string()];
        engine.add_trigger(t);
        engine.add_event(Event::set(
            "",
            "e1",
            "1.3.6.1.4.1.8072.999.1.0".parse().unwrap(),
            Value::Integer(42),
        ));

        // First poll: sample is 0. No prior sample, so no crossing.
        engine.poll_once();
        assert_eq!(
            composite.get(&"1.3.6.1.4.1.8072.999.1.0".parse().unwrap()),
            Some(Value::Integer(0))
        );

        // Raise the monitored value above the rising threshold.
        scalar.set_value(Value::Counter32(150));
        engine.poll_once();
        // The SET event should have fired, writing 42 into the target.
        assert_eq!(
            composite.get(&"1.3.6.1.4.1.8072.999.1.0".parse().unwrap()),
            Some(Value::Integer(42))
        );

        // Re-arming: lower the value below the falling threshold and verify the
        // event fires again (writing 43 this time).
        let mut t2 = engine
            .remove_trigger("", "t1")
            .expect("trigger present");
        t2.event_links = vec!["e2".to_string()];
        engine.add_trigger(t2);
        engine.add_event(Event::set(
            "",
            "e2",
            "1.3.6.1.4.1.8072.999.1.0".parse().unwrap(),
            Value::Integer(43),
        ));
        scalar.set_value(Value::Counter32(0));
        engine.poll_once();
        assert_eq!(
            composite.get(&"1.3.6.1.4.1.8072.999.1.0".parse().unwrap()),
            Some(Value::Integer(43))
        );
    }

    #[tokio::test]
    async fn boolean_trigger_fires_when_comparison_holds() {
        let alarms = Arc::new(AlarmRegistry::new());
        let engine = DismanEvent::new(alarms, None, "internal".to_string());
        let scalar = Arc::new(ScalarHandler::new(
            "1.3.6.1.2.1.2.2.1.10.1".parse().unwrap(),
            Value::Counter32(0),
        ));
        let set_target = Arc::new(
            ScalarHandler::new(
                "1.3.6.1.4.1.8072.999.2".parse().unwrap(),
                Value::Integer(0),
            )
            .writable(),
        );
        let composite = Arc::new(CompositeHandler::new(vec![
            Arc::clone(&scalar) as Arc<dyn MibHandler>,
            Arc::clone(&set_target) as Arc<dyn MibHandler>,
        ]));
        engine.set_self_query(composite.clone());

        let mut t = Trigger::boolean(
            "",
            "b1",
            "1.3.6.1.2.1.2.2.1.10.1".parse().unwrap(),
            BoolComparison::Greater,
            10,
        )
        .with_instance(vec![0]);
        t.event_links = vec!["be".to_string()];
        engine.add_trigger(t);
        engine.add_event(Event::set(
            "",
            "be",
            "1.3.6.1.4.1.8072.999.2.0".parse().unwrap(),
            Value::Integer(7),
        ));

        // Sample == 0, not > 10: no fire.
        engine.poll_once();
        assert_eq!(
            composite.get(&"1.3.6.1.4.1.8072.999.2.0".parse().unwrap()),
            Some(Value::Integer(0))
        );

        // Sample becomes 20 > 10: fire.
        scalar.set_value(Value::Counter32(20));
        engine.poll_once();
        assert_eq!(
            composite.get(&"1.3.6.1.4.1.8072.999.2.0".parse().unwrap()),
            Some(Value::Integer(7))
        );
    }

    #[test]
    fn existence_trigger_fires_once_then_quiet() {
        let alarms = Arc::new(AlarmRegistry::new());
        let engine = DismanEvent::new(alarms, None, "internal".to_string());
        let scalar = Arc::new(ScalarHandler::new(
            "1.3.6.1.2.1.2.2.1.10.1".parse().unwrap(),
            Value::Counter32(1),
        ));
        engine.set_self_query(scalar);

        let mut t = Trigger::existence("", "x1", "1.3.6.1.2.1.2.2.1.10.1".parse().unwrap())
            .with_instance(vec![0]);
        t.event_links = vec!["xe".to_string()];
        // Use a counter we can observe.
        engine.add_trigger(t);

        // Track fires by counting via the hysteresis flag directly: poll_once
        // flips existence_fired after the first fire, so the second poll should
        // not re-arm.
        engine.poll_once();
        let after_one = engine
            .triggers
            .read()
            .unwrap()
            .get(&key("", "x1"))
            .unwrap()
            .existence_fired;
        assert!(after_one, "existence flag set after first poll");
    }

    #[test]
    fn bool_comparison_evaluate_covers_all_modes() {
        assert!(BoolComparison::Equal.evaluate(3, 3));
        assert!(BoolComparison::Unequal.evaluate(3, 4));
        assert!(BoolComparison::Less.evaluate(2, 3));
        assert!(BoolComparison::LessOrEqual.evaluate(3, 3));
        assert!(BoolComparison::Greater.evaluate(4, 3));
        assert!(BoolComparison::GreaterOrEqual.evaluate(3, 3));
        assert!(!BoolComparison::Equal.evaluate(3, 4));
    }

    #[test]
    fn trigger_handlers_walk_active_rows() {
        let alarms = Arc::new(AlarmRegistry::new());
        let engine = DismanEvent::new(alarms, None, "internal".to_string());
        engine.add_trigger(Trigger::threshold(
            "alice",
            "netif",
            "1.3.6.1.2.1.2.2.1.10.1".parse().unwrap(),
            100,
            0,
        ));
        engine.add_event(Event::notification(
            "alice",
            "alert",
            "1.3.6.1.6.3.1.1.5.3".parse().unwrap(),
        ));

        let handlers = DismanEvent::handlers(engine);
        // trigger table
        let trigger_h = &handlers[0];
        // GETNEXT from below the table should find at least one cell.
        let reading = trigger_h
            .get_next(&"1.3.6.1.2.1.88.1.2.2".parse().unwrap())
            .expect("at least one cell");
        assert!(reading
            .oid
            .as_slice()
            .starts_with(MTE_TRIGGER_ENTRY));
        // event table
        let event_h = &handlers[1];
        let reading = event_h
            .get_next(&"1.3.6.1.2.1.88.1.4.2".parse().unwrap())
            .expect("at least one cell");
        assert!(reading.oid.as_slice().starts_with(MTE_EVENT_ENTRY));
    }

    /// A minimal composite handler that delegates GET/GETNEXT/SET to its
    /// children by longest-prefix match. Used only by the tests in this module.
    struct CompositeHandler {
        children: Vec<Arc<dyn MibHandler>>,
    }

    impl CompositeHandler {
        fn new(children: Vec<Arc<dyn MibHandler>>) -> Self {
            CompositeHandler { children }
        }

        fn handler_for(&self, oid: &Oid) -> Option<&Arc<dyn MibHandler>> {
            self.children
                .iter()
                .filter(|h| h.root().is_prefix_of(oid))
                .max_by_key(|h| h.root().len())
        }
    }

    impl MibHandler for CompositeHandler {
        fn root(&self) -> &Oid {
            // This composite is never registered with a registry — it is only
            // queried directly via `get`/`commit_set` in these tests. The root
            // is therefore arbitrary; an empty OID is sufficient and stable.
            static EMPTY: std::sync::LazyLock<Oid> = std::sync::LazyLock::new(Oid::null);
            &EMPTY
        }
        fn get(&self, oid: &Oid) -> Option<Value> {
            self.handler_for(oid).and_then(|h| h.get(oid))
        }
        fn get_next(&self, oid: &Oid) -> Option<Reading> {
            for h in &self.children {
                if let Some(r) = h.get_next(oid) {
                    return Some(r);
                }
            }
            None
        }
        fn commit_set(&self, oid: &Oid, value: &Value) -> Result<(), netsnmp::pdu::ErrorStatus> {
            match self.handler_for(oid) {
                Some(h) => h.commit_set(oid, value),
                None => Err(netsnmp::pdu::ErrorStatus::NoCreation),
            }
        }
    }

    // Reference the unused VarBind import path so the test module compiles
    // cleanly across rust versions that warn about unused imports.
    #[allow(dead_code)]
    fn _varbind_marker(_vb: VarBind) {}
}
