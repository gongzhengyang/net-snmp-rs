//! Hardware-sensor abstraction.
//!
//! Counterpart of `agent/mibgroup/hardware/sensors/`. The [`SensorAccess`]
//! trait abstracts how temperature, fan and voltage readings are obtained, so
//! the LM-SENSORS-MIB tables (`lmTempSensorsTable`, `lmFanSensorsTable`,
//! `lmVoltSensorsTable`) have a single, mockable data source.
//!
//! ## Linux `hwmon` reader
//!
//! The default implementation, [`HwmonSensorAccess`], reads the Linux
//! `/sys/class/hwmon/` sysfs tree directly via [`std::fs`] (no `unsafe`, no
//! extra crates). Each `hwmonN/` directory exposes one or more "channels":
//!
//! * `tempM_input` — temperature in millidegrees Celsius (divide by 1000).
//! * `fanM_input` — fan speed in RPM.
//! * `inM_input` — voltage in millivolts (divide by 1000).
//!
//! Each channel optionally has a sibling `tempM_label` / `fanM_label` /
//! `inM_label` file giving a human-readable name; otherwise the name is
//! synthesised from the channel file name. The `name` file at the `hwmonN`
//! root (e.g. `coretemp`, `nct6775`) is used as a prefix when present.
//!
//! On non-Linux platforms, or when `/sys/class/hwmon` does not exist, every
//! method returns an empty `Vec` (no panic). This keeps the LM-SENSORS tables
//! empty-but-valid on hosts without sensors, matching upstream behaviour.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

/// A single sensor reading (temperature, fan speed or voltage).
#[derive(Clone, Debug, PartialEq)]
pub struct SensorReading {
    /// Human-readable sensor name (e.g. `coretemp:Core 0`).
    pub name: String,
    /// The reading value in the sensor's natural unit:
    /// * temperature — degrees Celsius,
    /// * fan — RPM,
    /// * voltage — volts.
    pub value: f64,
    /// Unit string (`"C"`, `"RPM"`, `"V"`).
    pub unit: String,
}

/// Read-side access to hardware-sensor data.
pub trait SensorAccess: Send + Sync {
    /// Temperature readings (degrees Celsius).
    fn temperatures(&self) -> Vec<SensorReading>;
    /// Fan-speed readings (RPM).
    fn fans(&self) -> Vec<SensorReading>;
    /// Voltage readings (volts).
    fn voltages(&self) -> Vec<SensorReading>;
}

/// Linux `/sys/class/hwmon/` sensor reader.
///
/// Construct with [`HwmonSensorAccess::default`] (reads the real
/// `/sys/class/hwmon`) or [`HwmonSensorAccess::with_root`] for tests, pointing
/// at a temp directory laid out like `hwmon`.
pub struct HwmonSensorAccess {
    /// Root of the `hwmon` tree (normally `/sys/class/hwmon`).
    root: PathBuf,
}

impl HwmonSensorAccess {
    /// Create a reader over the real `/sys/class/hwmon`.
    pub fn default() -> Self {
        HwmonSensorAccess {
            root: PathBuf::from("/sys/class/hwmon"),
        }
    }

    /// Create a reader over `root` (a directory laid out like
    /// `/sys/class/hwmon`). Primarily for tests.
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        HwmonSensorAccess {
            root: root.into(),
        }
    }

    /// Read every `temp*_input` / `fan*_input` / `in*_input` channel under
    /// `root`, returning the readings of the requested kind.
    ///
    /// `kind` is one of `"temp"`, `"fan"`, `"in"`; `unit` is the human unit
    /// string; `scale` divides the raw millivalue (1e-3 for temp/voltage,
    /// 1.0 for fans which are already in RPM).
    fn read_channels(&self, kind: &str, unit: &str, scale: f64) -> Vec<SensorReading> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(_) => return out,
        };
        // Collect and sort hwmonN directory names for stable ordering.
        let mut dirs: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.is_dir()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with("hwmon"))
                        .unwrap_or(false)
            })
            .collect();
        dirs.sort();

        for hwmon in dirs {
            let chip = fs::read_to_string(hwmon.join("name"))
                .ok()
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            let mut channel_files: Vec<(String, PathBuf)> = match fs::read_dir(&hwmon) {
                Ok(e) => e
                    .filter_map(|e| {
                        let p = e.ok()?.path();
                        let name = p.file_name()?.to_string_lossy().into_owned();
                        Some((name, p))
                    })
                    .collect(),
                Err(_) => continue,
            };
            channel_files.sort_by(|a, b| a.0.cmp(&b.0));

            for (fname, fpath) in channel_files {
                // Match exactly `<kind>N_input`, e.g. `temp1_input`,
                // `fan2_input`, `in3_input`. Reject `_max`/`_label` siblings.
                let stripped = match fname
                    .strip_prefix(kind)
                    .and_then(|rest| rest.strip_suffix("_input"))
                {
                    Some(mid) if mid.chars().all(|c| c.is_ascii_digit()) => mid,
                    _ => continue,
                };
                let raw = match fs::read_to_string(&fpath) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let raw_val: f64 = match raw.trim().parse() {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let value = raw_val * scale;

                // Look for a sibling label file: `<kind>N_label`.
                let label_file = hwmon.join(format!("{kind}{stripped}_label"));
                let label = fs::read_to_string(&label_file)
                    .ok()
                    .map(|s| s.trim().to_string());
                let name = match (label, chip.as_str()) {
                    (Some(l), c) if !c.is_empty() => format!("{c}:{l}"),
                    (Some(l), _) => l,
                    (None, c) if !c.is_empty() => format!("{c}:{kind}{stripped}"),
                    (None, _) => format!("{kind}{stripped}"),
                };
                out.push(SensorReading {
                    name,
                    value,
                    unit: unit.to_string(),
                });
            }
        }
        out
    }
}

impl SensorAccess for HwmonSensorAccess {
    fn temperatures(&self) -> Vec<SensorReading> {
        self.read_channels("temp", "C", 1e-3)
    }

    fn fans(&self) -> Vec<SensorReading> {
        self.read_channels("fan", "RPM", 1.0)
    }

    fn voltages(&self) -> Vec<SensorReading> {
        self.read_channels("in", "V", 1e-3)
    }
}

/// A trivial in-memory [`SensorAccess`] used by tests and as a default when no
/// real sensors are available. Returns the readings it was constructed with.
#[derive(Clone, Default)]
pub struct StaticSensorAccess {
    /// Temperatures to report.
    pub temps: Vec<SensorReading>,
    /// Fans to report.
    pub fans: Vec<SensorReading>,
    /// Voltages to report.
    pub voltages: Vec<SensorReading>,
}

impl SensorAccess for StaticSensorAccess {
    fn temperatures(&self) -> Vec<SensorReading> {
        self.temps.clone()
    }
    fn fans(&self) -> Vec<SensorReading> {
        self.fans.clone()
    }
    fn voltages(&self) -> Vec<SensorReading> {
        self.voltages.clone()
    }
}

impl StaticSensorAccess {
    /// Build a [`StaticSensorAccess`] from raw `(name, value, unit)` triples.
    #[allow(dead_code)]
    pub fn from_temps(temps: impl IntoIterator<Item = (String, f64, String)>) -> Self {
        StaticSensorAccess {
            temps: temps
                .into_iter()
                .map(|(name, value, unit)| SensorReading { name, value, unit })
                .collect(),
            fans: Vec::new(),
            voltages: Vec::new(),
        }
    }
}

/// Wrap any [`SensorAccess`] in an `Arc<dyn SensorAccess>`.
pub fn shared(access: impl SensorAccess + 'static) -> Arc<dyn SensorAccess> {
    Arc::new(access)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Create a temp `hwmon` tree and return its root path.
    fn make_hwmon_tree() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netsnmp-hwmon-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // hwmon0: coretemp with two temp channels, one labelled.
        let h0 = dir.join("hwmon0");
        fs::create_dir_all(&h0).unwrap();
        fs::write(h0.join("name"), "coretemp\n").unwrap();
        fs::write(h0.join("temp1_input"), "45000\n").unwrap();
        fs::write(h0.join("temp1_label"), "Package id 0\n").unwrap();
        fs::write(h0.join("temp2_input"), "30000\n").unwrap();
        // temp2 has no label -> synthesised name.
        // A `_max` sibling that must NOT be treated as a reading.
        fs::write(h0.join("temp1_max"), "100000\n").unwrap();

        // hwmon1: a fan + a voltage, no `name` file.
        let h1 = dir.join("hwmon1");
        fs::create_dir_all(&h1).unwrap();
        fs::write(h1.join("fan1_input"), "2400\n").unwrap();
        fs::write(h1.join("fan1_label"), "CPU_FAN\n").unwrap();
        fs::write(h1.join("in0_input"), "12000\n").unwrap();
        // in0 has no label.

        dir
    }

    #[test]
    fn reads_temperatures_from_hwmon_tree() {
        let root = make_hwmon_tree();
        let access = HwmonSensorAccess::with_root(&root);
        let temps = access.temperatures();
        assert_eq!(temps.len(), 2, "got {temps:?}");
        // Labelled channel.
        let pkg = temps
            .iter()
            .find(|t| t.name.contains("Package"))
            .expect("labelled temp present");
        assert_eq!(pkg.value, 45.0);
        assert_eq!(pkg.unit, "C");
        // Unlabelled channel -> synthesised name with chip prefix.
        let synth = temps
            .iter()
            .find(|t| t.name == "coretemp:temp2")
            .expect("synthesised temp name");
        assert_eq!(synth.value, 30.0);
        // Clean up.
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn reads_fans_and_voltages() {
        let root = make_hwmon_tree();
        let access = HwmonSensorAccess::with_root(&root);
        let fans = access.fans();
        assert_eq!(fans.len(), 1);
        assert_eq!(fans[0].value, 2400.0);
        assert_eq!(fans[0].unit, "RPM");
        assert_eq!(fans[0].name, "CPU_FAN");

        let volts = access.voltages();
        assert_eq!(volts.len(), 1);
        assert_eq!(volts[0].value, 12.0);
        assert_eq!(volts[0].unit, "V");
        assert_eq!(volts[0].name, "in0");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_when_dir_absent() {
        let access = HwmonSensorAccess::with_root("/no/such/hwmon/path/xyz");
        assert!(access.temperatures().is_empty());
        assert!(access.fans().is_empty());
        assert!(access.voltages().is_empty());
    }

    #[test]
    fn ignores_max_siblings() {
        let root = make_hwmon_tree();
        let access = HwmonSensorAccess::with_root(&root);
        let temps = access.temperatures();
        // temp1_max must not appear as a reading.
        assert!(temps.iter().all(|t| !t.name.contains("max")));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn static_access_returns_constructed_readings() {
        let access = StaticSensorAccess::from_temps([("Core0".to_string(), 42.0, "C".to_string())]);
        let temps = access.temperatures();
        assert_eq!(temps.len(), 1);
        assert_eq!(temps[0].name, "Core0");
        assert_eq!(temps[0].value, 42.0);
        assert!(access.fans().is_empty());
    }
}
