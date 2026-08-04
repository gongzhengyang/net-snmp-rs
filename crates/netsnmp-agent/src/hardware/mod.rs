//! Hardware abstraction layer.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/hardware/` tree. This module
//! defines trait-based boundaries for the four hardware data sources the agent
//! cares about — CPU, filesystems, memory and sensors — so the scattered
//! `sysinfo` calls that previously lived in
//! [`crate::mibgroup::collector`] flow through a single, mockable layer.
//!
//! ## Layout
//!
//! | Submodule   | Trait           | Default impl            |
//! |-------------|-----------------|-------------------------|
//! | [`cpu`]     | [`CpuAccess`]   | [`SysCpuAccess`]        |
//! | [`fsys`]    | [`FsysAccess`]  | [`SysFsysAccess`]       |
//! | [`memory`]  | [`MemoryAccess`]| [`SysMemoryAccess`]     |
//! | [`sensors`] | [`SensorAccess`]| [`HwmonSensorAccess`]   |
//!
//! ## `HardwareLayer`
//!
//! [`HardwareLayer`] bundles one `Arc<dyn ...>` per trait so a caller can pass
//! a single value around. [`HardwareLayer::default_layer`] builds a layer whose
//! CPU/filesystem/memory defaults delegate to a shared
//! [`HostCollector`](crate::mibgroup::collector::HostCollector) (no
//! double-collection — they read its throttled snapshot) and whose sensor
//! default reads Linux `/sys/class/hwmon` (empty on other platforms).

pub mod cpu;
pub mod fsys;
pub mod memory;
pub mod sensors;

use std::sync::Arc;

use crate::mibgroup::collector::HostCollector;

pub use cpu::{CpuAccess, SysCpuAccess};
pub use fsys::{FsType, FsysAccess, SysFsysAccess};
pub use memory::{MemInfo, MemoryAccess, SwapInfo, SysMemoryAccess};
pub use sensors::{HwmonSensorAccess, SensorAccess, SensorReading, StaticSensorAccess};

/// A bundled set of hardware-access traits.
///
/// Each field is an `Arc<dyn Trait>`, so the layer is cheap to clone and
/// threads through the agent registration paths without lifetime gymnastics.
/// Callers may substitute any of the four with a custom (mock) implementation.
pub struct HardwareLayer {
    /// CPU access.
    pub cpu: Arc<dyn CpuAccess>,
    /// Filesystem access.
    pub fsys: Arc<dyn FsysAccess>,
    /// Memory access.
    pub memory: Arc<dyn MemoryAccess>,
    /// Sensor access.
    pub sensors: Arc<dyn SensorAccess>,
}

impl HardwareLayer {
    /// Build a default [`HardwareLayer`] over `collector`:
    ///
    /// * CPU/filesystem/memory default to the `Sys*` implementations that read
    ///   the collector's throttled snapshot.
    /// * Sensors default to [`HwmonSensorAccess`] (Linux `/sys/class/hwmon`;
    ///   empty elsewhere).
    pub fn default_layer(collector: Arc<HostCollector>) -> Arc<Self> {
        Arc::new(HardwareLayer {
            cpu: Arc::new(SysCpuAccess::new(Arc::clone(&collector))),
            fsys: Arc::new(SysFsysAccess::new(Arc::clone(&collector))),
            memory: Arc::new(SysMemoryAccess::new(collector)),
            sensors: Arc::new(HwmonSensorAccess::default()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_layer_builds_from_collector() {
        let collector = HostCollector::new();
        let layer = HardwareLayer::default_layer(collector);
        // Each trait object must answer without panicking.
        let _global = layer.cpu.global_usage();
        let _cpus = layer.cpu.cpus();
        let _disks = layer.fsys.filesystems();
        let _mem = layer.memory.memory();
        let _swap = layer.memory.swap();
        // Sensors: on a non-Linux-CI host or one without hwmon these are
        // empty, but must not error.
        let _temps = layer.sensors.temperatures();
        let _fans = layer.sensors.fans();
        let _volts = layer.sensors.voltages();
    }
}
