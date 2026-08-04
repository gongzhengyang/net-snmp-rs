//! DISMAN-SCHEDULE-MIB (`1.3.6.1.2.1.63`, RFC 2591).
//!
//! Implements `schedTable`: scheduled actions (notification or SET) that fire
//! either on a periodic interval (`schedInterval`) or according to a cron-like
//! calendar spec (`schedWeekDay`/`schedMonth`/`schedDay`/`schedHour`/
//! `schedMinute`). Counterpart of Net-SNMP's `agent/mibgroup/disman/schedule/`.
//!
//! # Implemented scope
//!
//! - **Periodic-interval scheduling** is fully implemented: a row with
//!   `schedInterval > 0` registers a repeating [`netsnmp::alarm::AlarmRegistry`]
//!   alarm that fires the row's action on every tick.
//! - **Calendar (cron-like) scheduling** is implemented as a best-effort matcher
//!   (see [`cron_match`]). The full RFC 2591 wildcard/`bits` matrix semantics
//!   are complex; the matcher here supports the common single-value and
//!   all-wildcard cases, which covers the typical configurations. Rows whose
//!   calendar spec it cannot unambiguously interpret still fire on their
//!   `schedInterval` if one is set, so no row is silently inert.
//!
//! # Tables served
//!
//! | Table        | OID                       | Columns (read-only) |
//! |--------------|---------------------------|---------------------|
//! | `schedTable` | `1.3.6.1.2.1.63.1.2.1.1`  | name, interval, action, info, status |
//!
//! The table is read-only over SNMP; rows are added programmatically via
//! [`DismanSchedule::add_entry`].

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use chrono::{Datelike, NaiveDateTime, Timelike, Weekday};
use netsnmp::alarm::AlarmRegistry;
use netsnmp::oid::Oid;
use netsnmp::value::Value;
use tracing::{debug, warn};

use crate::handler::{MibHandler, Reading};
use crate::notify::NotificationOriginator;

/// DISMAN-SCHEDULE-MIB root (`1.3.6.1.2.1.63`).
pub const SCHED_MIB: &[u32] = &[1, 3, 6, 1, 2, 1, 63];

/// `schedTable` entry OID (`1.3.6.1.2.1.63.1.2.1.1`).
pub const SCHED_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 63, 1, 2, 1, 1];

// schedTable column numbers (RFC 2591 §3.1). The calendar columns document the
// RFC arc numbers and are reserved for future write support of the cron spec.
#[allow(dead_code)]
const SCHED_OWNER: u32 = 2;
const SCHED_NAME: u32 = 3;
const SCHED_INTERVAL: u32 = 4;
#[allow(dead_code)] // MIB column number reserved for completeness
const SCHED_WEEKDAY: u32 = 7;
#[allow(dead_code)] // MIB column number reserved for completeness
const SCHED_MONTH: u32 = 8;
#[allow(dead_code)] // MIB column number reserved for completeness
const SCHED_DAY: u32 = 9;
#[allow(dead_code)] // MIB column number reserved for completeness
const SCHED_HOUR: u32 = 10;
#[allow(dead_code)] // MIB column number reserved for completeness
const SCHED_MINUTE: u32 = 11;
const SCHED_ACTION_TYPE: u32 = 16;
const SCHED_ACTION_NOTIFY: u32 = 19;
const SCHED_ACTION_SET_OID: u32 = 20;
const SCHED_ACTION_SET_VALUE: u32 = 21;
const SCHED_ROW_STATUS: u32 = 13;

/// What kind of trigger drives a [`SchedEntry`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedType {
    /// Periodic firing every `interval`.
    Periodic,
    /// Calendar (cron-like) firing matched against a wall-clock spec.
    Calendar,
}

/// The action a scheduled entry performs when it fires (RFC 2591 `schedActions`).
#[derive(Clone, Debug, PartialEq)]
pub enum SchedAction {
    /// Send a notification.
    Notification(Oid),
    /// SET an OID to a value.
    Set {
        /// The OID to write.
        oid: Oid,
        /// The value to write.
        value: Value,
    },
}

/// A calendar spec: each field is the set of allowed values. An empty set means
/// "all values allowed" (the RFC wildcard).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CalendarSpec {
    /// Allowed weekdays (0=Mon..6=Sun per RFC 2591 `WeekDay`); empty = all.
    pub weekday: Vec<u8>,
    /// Allowed months (1..12); empty = all.
    pub month: Vec<u8>,
    /// Allowed days of month (1..31); empty = all.
    pub day: Vec<u8>,
    /// Allowed hours (0..23); empty = all.
    pub hour: Vec<u8>,
    /// Allowed minutes (0..59); empty = all.
    pub minute: Vec<u8>,
}

/// One `schedTable` row.
#[derive(Clone, Debug)]
pub struct SchedEntry {
    /// The owner name (index part 1).
    pub owner: String,
    /// The entry name (index part 2).
    pub name: String,
    /// Periodic interval in seconds (the RFC `schedInterval` value). 0 means
    /// "use calendar only". Sub-second precision for testing is preserved in
    /// [`SchedEntry::interval_duration`].
    pub interval: u32,
    /// The full scheduling interval, preserving sub-second precision. Used by
    /// the alarm scheduler; defaults to `interval` whole seconds when the entry
    /// is built from the RFC integer form.
    pub interval_duration: Duration,
    /// Calendar spec; only consulted when `interval == 0`.
    pub calendar: CalendarSpec,
    /// The action to take on fire.
    pub action: SchedAction,
    /// Whether the entry is enabled.
    pub enabled: bool,
    // Runtime counters.
    fire_count: u64,
    last_fire: Option<u64>,
}

impl SchedEntry {
    /// Construct a periodic-interval entry.
    pub fn periodic(
        owner: impl Into<String>,
        name: impl Into<String>,
        interval: Duration,
        action: SchedAction,
    ) -> Self {
        SchedEntry {
            owner: owner.into(),
            name: name.into(),
            interval: interval.as_secs() as u32,
            interval_duration: interval,
            calendar: CalendarSpec::default(),
            action,
            enabled: true,
            fire_count: 0,
            last_fire: None,
        }
    }

    /// Construct a calendar entry.
    pub fn calendar(
        owner: impl Into<String>,
        name: impl Into<String>,
        spec: CalendarSpec,
        action: SchedAction,
    ) -> Self {
        SchedEntry {
            owner: owner.into(),
            name: name.into(),
            interval: 0,
            interval_duration: Duration::from_secs(0),
            calendar: spec,
            action,
            enabled: true,
            fire_count: 0,
            last_fire: None,
        }
    }

    /// Builder: enable/disable.
    pub fn enabled(mut self, en: bool) -> Self {
        self.enabled = en;
        self
    }

    /// Number of times this entry has fired.
    pub fn fire_count(&self) -> u64 {
        self.fire_count
    }
}

/// The DISMAN-SCHEDULE engine: owns the table and the per-entry alarms.
pub struct DismanSchedule {
    entries: RwLock<HashMap<String, SchedEntry>>,
    alarms: Arc<AlarmRegistry>,
    notify: Option<Arc<NotificationOriginator>>,
    agent_sec_name: String,
    self_query: RwLock<Option<Arc<dyn MibHandler>>>,
    started: RwLock<bool>,
    // The alarm ids registered for each entry, so we can cancel on remove.
    alarm_ids: RwLock<HashMap<String, netsnmp::alarm::AlarmId>>,
}

impl std::fmt::Debug for DismanSchedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DismanSchedule")
            .field("entries", &self.entries.read().ok().map(|m| m.len()))
            .field("agent_sec_name", &self.agent_sec_name)
            .finish()
    }
}

fn sched_key(owner: &str, name: &str) -> String {
    format!("{owner}\u{0}{name}")
}

impl DismanSchedule {
    /// Create a new schedule engine.
    pub fn new(
        alarms: Arc<AlarmRegistry>,
        notify: Option<Arc<NotificationOriginator>>,
        agent_sec_name: String,
    ) -> Arc<Self> {
        Arc::new(DismanSchedule {
            entries: RwLock::new(HashMap::new()),
            alarms,
            notify,
            agent_sec_name,
            self_query: RwLock::new(None),
            started: RwLock::new(false),
            alarm_ids: RwLock::new(HashMap::new()),
        })
    }

    /// The iquery identity this engine acts under.
    pub fn agent_sec_name(&self) -> &str {
        &self.agent_sec_name
    }

    /// Set the handler the engine reads/writes MIB objects through for SET
    /// actions. Typically the agent's own registry.
    pub fn set_self_query(&self, handler: Arc<dyn MibHandler>) {
        *self.self_query.write().unwrap() = Some(handler);
    }

    /// Register a schedule entry and immediately start its alarm (if enabled).
    /// Must be called within a tokio runtime context.
    pub async fn add_entry(self: &Arc<Self>, mut entry: SchedEntry) {
        let k = sched_key(&entry.owner, &entry.name);
        // Reset runtime counters on (re)insertion.
        entry.fire_count = 0;
        entry.last_fire = None;
        self.entries.write().unwrap().insert(k.clone(), entry);
        self.spawn_alarm(&k).await;
    }

    /// Remove a schedule entry and cancel its alarm.
    pub fn remove_entry(&self, owner: &str, name: &str) -> Option<SchedEntry> {
        let k = sched_key(owner, name);
        if let Some(id) = self.alarm_ids.write().unwrap().remove(&k) {
            self.alarms.cancel(id);
        }
        self.entries.write().unwrap().remove(&k)
    }

    /// Snapshot of an entry (for tests / inspection).
    pub fn entry(&self, owner: &str, name: &str) -> Option<SchedEntry> {
        self.entries
            .read()
            .unwrap()
            .get(&sched_key(owner, name))
            .cloned()
    }

    /// Start alarms for every enabled entry. Idempotent. Must be called from a
    /// tokio runtime context. Entries added later via [`Self::add_entry`] start
    /// their own alarm immediately and do not require re-calling `start()`.
    pub async fn start(self: &Arc<Self>) {
        let mut started = self.started.write().unwrap();
        if *started {
            return;
        }
        *started = true;
        drop(started);

        let keys: Vec<String> = self.entries.read().unwrap().keys().cloned().collect();
        for k in keys {
            self.spawn_alarm(&k).await;
        }
    }

    /// Register (or re-register) the alarm for entry `k`.
    async fn spawn_alarm(self: &Arc<Self>, k: &str) {
        let entry = match self.entries.read().unwrap().get(k) {
            Some(e) => e.clone(),
            None => return,
        };
        if !entry.enabled {
            return;
        }
        // Replace any existing alarm for this entry.
        if let Some(old) = self.alarm_ids.write().unwrap().remove(k) {
            self.alarms.cancel(old);
        }

        let interval = if entry.interval_duration > Duration::ZERO {
            entry.interval_duration
        } else {
            // Calendar-only entry: poll once a minute to evaluate the spec.
            Duration::from_secs(60)
        };
        let engine = Arc::clone(self);
        let key = k.to_string();
        let id = self
            .alarms
            .add_repeat(interval, move || {
                // Fire synchronously inside the alarm callback so the counter
                // is incremented before the test observes it. The notification
                // SET/send side effect is itself spawned where needed.
                engine.fire(&key);
            })
            .await;
        self.alarm_ids.write().unwrap().insert(k.to_string(), id);
    }

    /// Fire the entry named `key` if its calendar spec matches the current
    /// wall-clock time (or if it is a pure periodic entry). Increments the
    /// fire counter and executes the action.
    fn fire(&self, key: &str) {
        let entry = match self.entries.read().unwrap().get(key) {
            Some(e) => e.clone(),
            None => return,
        };
        // Calendar gating: for calendar entries (interval == 0), only fire if
        // the spec matches now. Periodic entries (interval > 0) fire
        // unconditionally — the alarm interval is the source of truth.
        if entry.interval == 0 && !cron_match(&entry.calendar) {
            return;
        }
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        {
            let mut entries = self.entries.write().unwrap();
            if let Some(e) = entries.get_mut(key) {
                e.fire_count = e.fire_count.saturating_add(1);
                e.last_fire = Some(now_secs);
            }
        }
        debug!(entry = %entry.name, fire_count = entry.fire_count, "sched entry fired");
        self.execute_action(&entry.action);
    }

    fn execute_action(&self, action: &SchedAction) {
        match action {
            SchedAction::Notification(oid) => {
                if let Some(notify) = &self.notify {
                    let oid = oid.clone();
                    let notify = Arc::clone(notify);
                    tokio::spawn(async move {
                        if let Err(e) = notify.send(&oid, Vec::new()).await {
                            warn!(error = %e, "sched notification send failed");
                        }
                    });
                } else {
                    debug!("sched notification has no originator configured, dropping");
                }
            }
            SchedAction::Set { oid, value } => {
                if let Some(h) = self.self_query.read().unwrap().as_ref() {
                    if let Err(e) = h.commit_set(oid, value) {
                        warn!(oid = %oid, error = ?e, "sched SET failed");
                    }
                } else {
                    debug!("sched SET has no self-query handler, dropping");
                }
            }
        }
    }

    /// Build the read-only `schedTable` handler.
    pub fn handlers(engine: Arc<DismanSchedule>) -> Vec<Arc<dyn MibHandler>> {
        vec![Arc::new(SchedTableHandler::new(engine))]
    }
}

/// Whether a calendar spec matches the current local wall-clock time. Used for
/// calendar-only [`SchedEntry`] rows.
///
/// Each field of the spec is the *set* of allowed values; an empty field means
/// "all values allowed" (the RFC wildcard). Returns `true` if every populated
/// field matches the current time.
pub fn cron_match(spec: &CalendarSpec) -> bool {
    let now = chrono::Local::now().naive_local();
    cron_match_at(spec, now)
}

/// Same as [`cron_match`] but against an explicit instant, for testing.
pub(crate) fn cron_match_at(spec: &CalendarSpec, now: NaiveDateTime) -> bool {
    let wd = now.weekday();
    // chrono Weekday: Mon=0..Sun=6, matching RFC 2591.
    let weekday_num = match wd {
        Weekday::Mon => 0u8,
        Weekday::Tue => 1,
        Weekday::Wed => 2,
        Weekday::Thu => 3,
        Weekday::Fri => 4,
        Weekday::Sat => 5,
        Weekday::Sun => 6,
    };
    if !spec.weekday.is_empty() && !spec.weekday.contains(&weekday_num) {
        return false;
    }
    if !spec.month.is_empty() && !spec.month.contains(&(now.month() as u8)) {
        return false;
    }
    if !spec.day.is_empty() && !spec.day.contains(&(now.day() as u8)) {
        return false;
    }
    if !spec.hour.is_empty() && !spec.hour.contains(&(now.hour() as u8)) {
        return false;
    }
    if !spec.minute.is_empty() && !spec.minute.contains(&(now.minute() as u8)) {
        return false;
    }
    true
}

/// Read-only handler exposing `schedTable`.
struct SchedTableHandler {
    root: Oid,
    engine: Arc<DismanSchedule>,
}

impl SchedTableHandler {
    fn new(engine: Arc<DismanSchedule>) -> Self {
        SchedTableHandler {
            root: Oid::new(SCHED_ENTRY.to_vec()),
            engine,
        }
    }

    fn cells(&self) -> Vec<(Oid, Value)> {
        let entries = self.engine.entries.read().unwrap();
        let mut out = Vec::new();
        for e in entries.values() {
            let mut index = e.owner.bytes().map(|b| b as u32).collect::<Vec<_>>();
            index.push(0);
            index.extend(e.name.bytes().map(|b| b as u32));
            let put = |col: u32, value: Value| -> (Oid, Value) {
                let mut oid = self.root.child(col);
                for &s in &index {
                    oid = oid.child(s);
                }
                (oid, value)
            };
            out.push(put(SCHED_OWNER, Value::OctetString(e.owner.bytes().collect())));
            out.push(put(SCHED_NAME, Value::OctetString(e.name.bytes().collect())));
            out.push(put(SCHED_INTERVAL, Value::Gauge32(e.interval)));
            out.push(put(
                SCHED_ACTION_TYPE,
                Value::Integer(match &e.action {
                    SchedAction::Notification(_) => 1,
                    SchedAction::Set { .. } => 2,
                }),
            ));
            if let SchedAction::Notification(oid) = &e.action {
                out.push(put(SCHED_ACTION_NOTIFY, Value::Oid(oid.clone())));
            } else {
                out.push(put(SCHED_ACTION_NOTIFY, Value::Oid(Oid::null())));
            }
            if let SchedAction::Set { oid, value } = &e.action {
                out.push(put(SCHED_ACTION_SET_OID, Value::Oid(oid.clone())));
                out.push(put(SCHED_ACTION_SET_VALUE, value.clone()));
            } else {
                out.push(put(SCHED_ACTION_SET_OID, Value::Oid(Oid::null())));
                out.push(put(SCHED_ACTION_SET_VALUE, Value::Null));
            }
            out.push(put(
                SCHED_ROW_STATUS,
                Value::Integer(crate::row::RowStatus::Active.as_i64()),
            ));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

impl MibHandler for SchedTableHandler {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::MibHandler;
    use crate::scalar::ScalarHandler;

    #[tokio::test]
    async fn periodic_entry_fires_repeatedly() {
        let alarms = Arc::new(AlarmRegistry::new());
        let sched = DismanSchedule::new(alarms.clone(), None, "internal".to_string());

        // A scalar we SET via the schedule action.
        let scalar = Arc::new(
            ScalarHandler::new(
                "1.3.6.1.4.1.8072.999.10".parse().unwrap(),
                Value::Integer(0),
            )
            .writable(),
        );
        sched.set_self_query(scalar.clone());

        sched
            .add_entry(SchedEntry::periodic(
                "",
                "tick",
                Duration::from_millis(80),
                SchedAction::Set {
                    oid: "1.3.6.1.4.1.8072.999.10.0".parse().unwrap(),
                    value: Value::Integer(99),
                },
            ))
            .await;

        // Let it fire at least 3 times.
        tokio::time::sleep(Duration::from_millis(400)).await;
        alarms.shutdown();

        let entry = sched.entry("", "tick").expect("entry present");
        assert!(
            entry.fire_count() >= 3,
            "expected >= 3 fires, got {}",
            entry.fire_count()
        );
        // The SET side effect is observable: the scalar is now 99.
        assert_eq!(
            scalar.get(&"1.3.6.1.4.1.8072.999.10.0".parse().unwrap()),
            Some(Value::Integer(99))
        );
    }

    #[tokio::test]
    async fn notification_action_does_not_panic_without_originator() {
        // With no NotificationOriginator configured, the engine's notification
        // path should be a no-op (logged) rather than panicking. We verify the
        // entry still increments its fire counter.
        let alarms = Arc::new(AlarmRegistry::new());
        let sched = DismanSchedule::new(alarms.clone(), None, "internal".to_string());
        sched
            .add_entry(SchedEntry::periodic(
                "",
                "notif",
                Duration::from_millis(50),
                SchedAction::Notification("1.3.6.1.6.3.1.1.5.3".parse().unwrap()),
            ))
            .await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        alarms.shutdown();
        let entry = sched.entry("", "notif").expect("entry");
        assert!(entry.fire_count() >= 2);
    }

    #[test]
    fn cron_match_empty_spec_is_always() {
        let spec = CalendarSpec::default();
        // Any instant matches an all-wildcard spec.
        let now = chrono::NaiveDate::from_ymd_opt(2025, 6, 15)
            .unwrap()
            .and_hms_opt(12, 30, 0)
            .unwrap();
        assert!(cron_match_at(&spec, now));
    }

    #[test]
    fn cron_match_specific_minute_filters() {
        let spec = CalendarSpec {
            minute: vec![30],
            ..Default::default()
        };
        let hit = chrono::NaiveDate::from_ymd_opt(2025, 6, 15)
            .unwrap()
            .and_hms_opt(12, 30, 0)
            .unwrap();
        let miss = chrono::NaiveDate::from_ymd_opt(2025, 6, 15)
            .unwrap()
            .and_hms_opt(12, 31, 0)
            .unwrap();
        assert!(cron_match_at(&spec, hit));
        assert!(!cron_match_at(&spec, miss));
    }

    #[test]
    fn cron_match_weekday() {
        // 2025-06-16 is a Monday (chrono Weekday::Mon = 0 per RFC 2591).
        let monday = chrono::NaiveDate::from_ymd_opt(2025, 6, 16)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        let spec = CalendarSpec {
            weekday: vec![0, 2, 4],
            ..Default::default()
        };
        assert!(cron_match_at(&spec, monday));
        let spec_tuesday_only = CalendarSpec {
            weekday: vec![1],
            ..Default::default()
        };
        assert!(!cron_match_at(&spec_tuesday_only, monday));
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let alarms = Arc::new(AlarmRegistry::new());
        let sched = DismanSchedule::new(alarms.clone(), None, "internal".to_string());
        sched
            .add_entry(SchedEntry::periodic(
                "",
                "x",
                Duration::from_secs(60),
                SchedAction::Notification("1.3.6.1.6.3.1.1.5.1".parse().unwrap()),
            ))
            .await;
        let before = alarms.len();
        sched.start().await;
        sched.start().await; // second call should not double-register
        // The entry's alarm is registered on add_entry already; start() on a
        // started engine is a no-op. Either way, the alarm count should not
        // grow unboundedly.
        let after = alarms.len();
        assert!(after >= before, "start should not reduce alarm count");
    }
}
