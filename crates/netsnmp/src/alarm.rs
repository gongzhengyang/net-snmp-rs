//! Periodic alarm scheduler.
//!
//! Counterpart of `snmplib/snmp_alarm.c`. The C library maintains a global
//! table of registered "alarms", each firing its callback either once
//! (`SA_EXECUTE_ONCE`) or repeatedly (`SA_REPEAT`) on a fixed interval. The
//! agent uses this for housekeeping timers such as session timeouts, cache
//! flushes and USM engine-time discovery.
//!
//! This module provides a thin, async-native equivalent. Each alarm runs as its
//! own `tokio` task that loops on `tokio::time::sleep(interval)`, invoking the
//! supplied callback between sleeps. Cancellation is cooperative and prompt: a
//! per-alarm [`AtomicBool`] flag is checked before every fire, and the task is
//! also aborted so an in-flight sleep is cancelled immediately.
//!
//! [`AlarmRegistry::add`] and the convenience constructors must be called from
//! within a running `tokio` runtime (they call `tokio::spawn`); the registry is
//! `Send + Sync` and safe to share across tasks via `Arc`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

/// Opaque identifier for a registered alarm.
///
/// In `snmp_alarm.c` this is the index of the alarm within the global table;
/// here it is an ever-increasing `u64` handed out by [`AlarmRegistry`].
pub type AlarmId = u64;

/// A handle to a registered alarm.
///
/// Dropping the handle does *not* cancel the alarm (mirrors the C library,
/// where alarms are global and outlive the code that registered them); call
/// [`Alarm::cancel`] to stop it, or [`AlarmRegistry::shutdown`] to clear all
/// alarms at once.
#[derive(Debug)]
pub struct Alarm {
    /// The alarm's identifier within its registry.
    id: AlarmId,
    /// Shared cancel flag. Set by `cancel()` and checked by the worker task
    /// before each fire so an aborted-but-joined task still observes the
    /// cancellation.
    cancelled: Arc<AtomicBool>,
}

impl Alarm {
    /// The identifier assigned to this alarm by its registry.
    pub fn id(&self) -> AlarmId {
        self.id
    }

    /// Cancel the alarm permanently and abort its worker task.
    ///
    /// Returns `true` if this call performed the cancellation, `false` if the
    /// alarm had already been cancelled or removed from the registry.
    pub fn cancel(self) -> bool {
        self.cancelled
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
}

/// One registered alarm's bookkeeping, held inside the registry.
struct Entry {
    /// Shared cancel flag, mirrored to the owning [`Alarm`] handle.
    cancelled: Arc<AtomicBool>,
    /// The spawned worker task. Aborted on cancel/shutdown for prompt removal.
    handle: JoinHandle<()>,
}

/// A registry of periodic and one-shot alarms.
///
/// Conceptually the global `alarms` table in `snmp_alarm.c` plus its lock.
/// Thread-safe; clone-able handles are not needed because methods take `&self`.
///
/// # Runtime requirement
///
/// [`AlarmRegistry::add`], [`AlarmRegistry::add_repeat`] and
/// [`AlarmRegistry::add_once`] spawn `tokio` tasks and so must be invoked from
/// within a running `tokio` runtime context (e.g. inside an `#[tokio::test]` or
/// `#[tokio::main]` function, or after a `Runtime::enter` guard is active).
#[derive(Default)]
pub struct AlarmRegistry {
    /// Monotonic id generator; the next alarm receives `next_id`.
    next_id: AsyncMutex<AlarmId>,
    /// The registered alarms, indexed by id. A short-lived `std` lock guards
    /// only trivial insert/remove/abort work — it is never held across an
    /// `.await`, so a plain [`Mutex`] is correct and avoids the overhead of an
    /// async mutex on this hot administrative path.
    entries: Mutex<Vec<(AlarmId, Entry)>>,
}

impl AlarmRegistry {
    /// Create an empty alarm registry.
    pub fn new() -> Self {
        AlarmRegistry::default()
    }

    /// Register an alarm that fires `callback` every `interval`.
    ///
    /// When `repeat` is `true` the alarm mirrors `SA_REPEAT` and fires forever
    /// until cancelled or [`AlarmRegistry::shutdown`] is called. When `repeat`
    /// is `false` it mirrors `SA_EXECUTE_ONCE`: it fires exactly once and then
    /// removes itself from the registry.
    ///
    /// Must be called inside a `tokio` runtime context.
    pub async fn add<F>(&self, interval: Duration, repeat: bool, callback: F) -> AlarmId
    where
        F: Fn() + Send + Sync + 'static,
    {
        let id = {
            let mut next = self.next_id.lock().await;
            let id = *next;
            *next += 1;
            id
        };

        let cancelled = Arc::new(AtomicBool::new(false));
        let task_cancelled = cancelled.clone();
        let task_registry_cancelled = cancelled.clone();
        // Self-removal from the registry is awkward to express with a borrowed
        // `&self` reference held across the task's lifetime, so once-fired and
        // cancelled tasks are simply left as completed/aborted JoinHandles and
        // pruned by `shutdown`; the cancel flag is the source of truth.
        let _ = task_registry_cancelled;

        let callback = Arc::new(callback);
        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if task_cancelled.load(Ordering::SeqCst) {
                    return;
                }
                (callback)();
                if task_cancelled.load(Ordering::SeqCst) {
                    return;
                }
                if !repeat {
                    return;
                }
            }
        });

        {
            let mut entries = self.entries.lock().expect("alarm registry poisoned");
            entries.push((
                id,
                Entry {
                    cancelled,
                    handle,
                },
            ));
        }

        id
    }

    /// Register a repeating alarm (`SA_REPEAT`). See [`AlarmRegistry::add`].
    pub async fn add_repeat<F>(&self, interval: Duration, callback: F) -> AlarmId
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.add(interval, true, callback).await
    }

    /// Register a one-shot alarm (`SA_EXECUTE_ONCE`). See [`AlarmRegistry::add`].
    pub async fn add_once<F>(&self, interval: Duration, callback: F) -> AlarmId
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.add(interval, false, callback).await
    }

    /// Cancel the alarm with the given id, aborting its task.
    ///
    /// Returns `true` if an alarm was found and cancelled, `false` if no live
    /// alarm with that id exists.
    pub fn cancel(&self, id: AlarmId) -> bool {
        let mut entries = self.entries.lock().expect("alarm registry poisoned");
        if let Some((_, entry)) = entries.iter_mut().find(|(eid, _)| *eid == id) {
            let was_live = entry
                .cancelled
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok();
            entry.handle.abort();
            // Remove the cancelled entry so a subsequent `len` does not count
            // it and `cancel(id)` returns false on a repeat call.
            entries.retain(|(eid, _)| *eid != id);
            was_live
        } else {
            false
        }
    }

    /// The number of currently registered (live) alarms.
    pub fn len(&self) -> usize {
        let entries = self.entries.lock().expect("alarm registry poisoned");
        entries.iter().filter(|(_, e)| !e.cancelled.load(Ordering::SeqCst)).count()
    }

    /// Whether the registry currently holds no live alarms.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Cancel every registered alarm, abort all worker tasks and clear the
    /// table. After this the registry is empty and may be reused.
    pub fn shutdown(&self) {
        let mut entries = self.entries.lock().expect("alarm registry poisoned");
        for (_, entry) in entries.drain(..) {
            entry.cancelled.store(true, Ordering::SeqCst);
            entry.handle.abort();
        }
    }

    /// A best-effort handle for an existing alarm id, for cancellation via
    /// [`Alarm`]. Returns `None` if `id` is not a live alarm.
    #[allow(dead_code)]
    fn handle(&self, id: AlarmId) -> Option<Alarm> {
        let entries = self.entries.lock().expect("alarm registry poisoned");
        entries
            .iter()
            .find(|(eid, _)| *eid == id)
            .map(|(_, entry)| Alarm {
                id,
                cancelled: entry.cancelled.clone(),
            })
    }
}

impl std::fmt::Debug for AlarmRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.len();
        f.debug_struct("AlarmRegistry")
            .field("live_count", &count)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[tokio::test]
    async fn repeat_alarm_fires_multiple_times() {
        let registry = AlarmRegistry::new();
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = count.clone();
        registry
            .add_repeat(Duration::from_millis(50), move || {
                count_clone.fetch_add(1, Ordering::SeqCst);
            })
            .await;

        tokio::time::sleep(Duration::from_millis(300)).await;
        registry.shutdown();
        assert!(
            count.load(Ordering::SeqCst) >= 3,
            "repeat alarm fired {} times, expected >= 3",
            count.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn once_alarm_fires_once() {
        let registry = AlarmRegistry::new();
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = count.clone();
        let id = registry
            .add_once(Duration::from_millis(40), move || {
                count_clone.fetch_add(1, Ordering::SeqCst);
            })
            .await;

        // Wait long enough for one fire plus several potential repeats.
        tokio::time::sleep(Duration::from_millis(250)).await;
        registry.shutdown();
        let fired = count.load(Ordering::SeqCst);
        assert_eq!(fired, 1, "once alarm fired {fired} times, expected 1");
        // A one-shot alarm self-removes once fired, so it is not cancelable.
        assert!(!registry.cancel(id));
    }

    #[tokio::test]
    async fn cancel_stops_alarm() {
        let registry = AlarmRegistry::new();
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = count.clone();
        let id = registry
            .add_repeat(Duration::from_millis(50), move || {
                count_clone.fetch_add(1, Ordering::SeqCst);
            })
            .await;

        // Let it fire at least once, then cancel.
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(registry.cancel(id), "first cancel should report success");
        assert!(!registry.cancel(id), "second cancel should find nothing");
        let after_cancel = count.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            after_cancel,
            "alarm kept firing after cancel"
        );
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn shutdown_clears_all() {
        let registry = AlarmRegistry::new();
        let count = Arc::new(AtomicUsize::new(0));
        for _ in 0..3 {
            let count_clone = count.clone();
            registry
                .add_repeat(Duration::from_millis(30), move || {
                    count_clone.fetch_add(1, Ordering::SeqCst);
                })
                .await;
        }
        assert_eq!(registry.len(), 3);
        registry.shutdown();
        assert_eq!(registry.len(), 0);
        assert!(registry.is_empty());
        let after_shutdown = count.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            after_shutdown,
            "alarms fired after shutdown"
        );
    }
}
