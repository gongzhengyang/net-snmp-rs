//! CPU hardware abstraction.
//!
//! Counterpart of `agent/mibgroup/hardware/cpu/`. The [`CpuAccess`] trait
//! abstracts how per-core load and aggregate CPU usage are obtained, so the
//! scattered `sysinfo` calls that previously lived directly in
//! [`crate::mibgroup::collector`] now flow through a single, mockable boundary.
//!
//! The default implementation, [`SysCpuAccess`], delegates to the shared
//! [`HostCollector`](crate::mibgroup::collector::HostCollector): each call
//! returns the per-core samples from the latest throttled snapshot, so there is
//! no double-collection relative to a plain `collector.snapshot()`.

use std::sync::Arc;

use crate::mibgroup::collector::{CpuSample, HostCollector};

/// Read-side access to CPU usage data.
///
/// Implementations must be cheap to clone or share (typically `Arc<...>`).
/// All methods are infallible: a platform without the requested data should
/// return an empty `Vec` or a zero usage value rather than panic.
pub trait CpuAccess: Send + Sync {
    /// Per-core CPU samples, in a stable, implementation-defined order.
    fn cpus(&self) -> Vec<CpuSample>;

    /// Aggregate CPU load across all cores as a whole-number percentage
    /// (0..=100). Returns `0` when unavailable.
    fn global_usage(&self) -> i64;
}

/// Default [`CpuAccess`] backed by the shared [`HostCollector`].
///
/// Holds only an `Arc` clone of the collector, so it is cheap to construct and
/// safe to share across handler threads.
pub struct SysCpuAccess {
    /// The shared collector; reads go through its throttled snapshot.
    pub(super) inner: Arc<HostCollector>,
}

impl SysCpuAccess {
    /// Create a new CPU access layer over `collector`.
    pub fn new(collector: Arc<HostCollector>) -> Self {
        SysCpuAccess { inner: collector }
    }
}

impl CpuAccess for SysCpuAccess {
    fn cpus(&self) -> Vec<CpuSample> {
        self.inner.snapshot().cpus.clone()
    }

    fn global_usage(&self) -> i64 {
        self.inner.snapshot().cpu_global_pct
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_layer_cpu_uses_collector_snapshot() {
        // The collector takes a real system snapshot; on any host with at
        // least one CPU the global usage should be in 0..=100 and the per-core
        // list should be non-empty. We do not assert exact values (they vary
        // by host), only the contract.
        let collector = HostCollector::new();
        let access = SysCpuAccess::new(collector);
        let global = access.global_usage();
        assert!((0..=100).contains(&global));
        let cpus = access.cpus();
        // On a real CI host there is at least one CPU. Be defensive in case
        // sysinfo returns nothing on an exotic platform.
        if !cpus.is_empty() {
            for c in &cpus {
                assert!((0..=100).contains(&c.usage_pct), "usage out of range: {c:?}");
            }
        }
    }
}
