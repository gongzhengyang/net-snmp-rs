//! Memory hardware abstraction.
//!
//! Counterpart of `agent/mibgroup/hardware/memory/`. The [`MemoryAccess`]
//! trait abstracts how physical-memory and swap totals are obtained, giving the
//! HOST-RESOURCES-MIB `hrStorage` group and the UCD-SNMP `memory` group a
//! single, mockable source.
//!
//! The default implementation, [`SysMemoryAccess`], delegates to the shared
//! [`HostCollector`](crate::mibgroup::collector::HostCollector): each call
//! returns the memory fields from the latest throttled snapshot, so there is no
//! double-collection relative to a plain `collector.snapshot()`.

use std::sync::Arc;

use crate::mibgroup::collector::HostCollector;

/// Physical-memory totals (in bytes).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemInfo {
    /// Total physical memory in bytes.
    pub total: u64,
    /// Used physical memory in bytes.
    pub used: u64,
    /// Free physical memory in bytes.
    pub free: u64,
    /// Available physical memory in bytes (free + reclaimable).
    pub available: u64,
}

/// Swap totals (in bytes).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SwapInfo {
    /// Total swap in bytes.
    pub total: u64,
    /// Used swap in bytes.
    pub used: u64,
    /// Free swap in bytes.
    pub free: u64,
}

/// Read-side access to physical-memory and swap data.
pub trait MemoryAccess: Send + Sync {
    /// Physical-memory totals.
    fn memory(&self) -> MemInfo;
    /// Swap totals.
    fn swap(&self) -> SwapInfo;
}

/// Default [`MemoryAccess`] backed by the shared [`HostCollector`].
pub struct SysMemoryAccess {
    /// The shared collector; reads go through its throttled snapshot.
    pub(super) inner: Arc<HostCollector>,
}

impl SysMemoryAccess {
    /// Create a new memory access layer over `collector`.
    pub fn new(collector: Arc<HostCollector>) -> Self {
        SysMemoryAccess { inner: collector }
    }
}

impl MemoryAccess for SysMemoryAccess {
    fn memory(&self) -> MemInfo {
        let s = self.inner.snapshot();
        MemInfo {
            total: s.mem_total,
            used: s.mem_used,
            free: s.mem_free,
            available: s.mem_available,
        }
    }

    fn swap(&self) -> SwapInfo {
        let s = self.inner.snapshot();
        SwapInfo {
            total: s.swap_total,
            used: s.swap_used,
            free: s.swap_free,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_layer_memory_reads_snapshot() {
        let collector = HostCollector::new();
        let access = SysMemoryAccess::new(collector);
        let mem = access.memory();
        // Total >= used on any sane platform.
        assert!(mem.total >= mem.used);
        // Swap totals are non-negative (may be zero if no swap configured).
        let swap = access.swap();
        assert!(swap.total >= swap.used);
    }
}
