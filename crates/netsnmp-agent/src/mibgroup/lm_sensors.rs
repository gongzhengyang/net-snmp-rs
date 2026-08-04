//! LM-SENSORS-MIB (`1.3.6.1.4.1.2021.13`), backed by the hardware sensor layer.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/ucd-snmp/lmSensors.c`. The three
//! sensor tables are populated from any [`SensorAccess`] implementation
//! (default: Linux `/sys/class/hwmon`). When no sensors are present the tables
//! are simply empty — `GETNEXT` walks past them and `GET` returns
//! `noSuchInstance`, matching the upstream "no error, no rows" behaviour.
//!
//! Objects exposed (all under `1.3.6.1.4.1.2021.13.16`):
//!
//! * `lmTempSensorsTable` (`.16.2`): `lmTempSensorsIndex(1)`,
//!   `lmTempSensorsDevice(2)`, `lmTempSensorsValue(3)`,
//!   `lmTempSensorsCritical(4)`.
//! * `lmFanSensorsTable` (`.16.3`): `lmFanSensorsIndex(1)`,
//!   `lmFanSensorsDevice(2)`, `lmFanSensorsValue(3)`,
//!   `lmFanSensorsCritical(4)`.
//! * `lmVoltSensorsTable` (`.16.4`): `lmVoltSensorsIndex(1)`,
//!   `lmVoltSensorsDevice(2)`, `lmVoltSensorsValue(3)`,
//!   `lmVoltSensorsCritical(4)`.
//!
//! `lmXxxSensorsCritical` is always 0 here: the Linux `hwmon` `_crit` files
//! are not always present and parsing them safely across chip families is out
//! of scope; the column is reported as `0` (unknown) rather than omitted, so
//! walks of the table stay regular.

use std::collections::BTreeMap;
use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::hardware::SensorAccess;
use crate::hardware::SensorReading;
use crate::scalar::FnHandler;

/// `lmSensors` subgroup root: `1.3.6.1.4.1.2021.13`.
const LM_SENSORS: [u32; 8] = [1, 3, 6, 1, 4, 1, 2021, 13];
/// `lmSensors` table root: `1.3.6.1.4.1.2021.13.16`.
const LM_SENSORS_TABLES: [u32; 9] = [1, 3, 6, 1, 4, 1, 2021, 13, 16];

/// Table sub-identifier for `lmTempSensorsTable` (under `.13.16`).
const TEMP_TABLE: u32 = 2;
/// Table sub-identifier for `lmFanSensorsTable` (under `.13.16`).
const FAN_TABLE: u32 = 3;
/// Table sub-identifier for `lmVoltSensorsTable` (under `.13.16`).
const VOLT_TABLE: u32 = 4;

/// Build one sensor table's cells.
///
/// Cell OID layout: `lmXxxSensorsEntry(.16.T.1).column(.C).index(.N)` where `T`
/// is the table sub-id (`2`/`3`/`4`) and `N` is the 1-based row index.
fn sensor_table_cells(table_id: u32, readings: &[SensorReading]) -> Vec<(Oid, Value)> {
    let entry = Oid::new(LM_SENSORS_TABLES.to_vec())
        .child(table_id)
        .child(1); // lmXxxSensorsEntry
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    for (i, r) in readings.iter().enumerate() {
        let idx = (i + 1) as u32;
        cells.insert(entry.child(1).child(idx), Value::Integer(idx as i64)); // index
        cells.insert(
            entry.child(2).child(idx),
            Value::OctetString(r.name.clone().into_bytes()),
        ); // device
        // Value: report the reading rounded to a whole-number Gauge32, matching
        // the INTEGER type the C agent uses for these columns. Negative
        // readings (sub-zero temperatures) are preserved via Integer.
        cells.insert(
            entry.child(3).child(idx),
            Value::Integer(r.value.round() as i64),
        ); // value
        cells.insert(entry.child(4).child(idx), Value::Integer(0)); // critical (unknown)
    }
    cells.into_iter().collect()
}

/// Build all three LM-SENSORS-MIB table cells from `sensors`.
fn lm_sensors_cells(sensors: &dyn SensorAccess) -> Vec<(Oid, Value)> {
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    for (table_id, readings) in [
        (TEMP_TABLE, sensors.temperatures()),
        (FAN_TABLE, sensors.fans()),
        (VOLT_TABLE, sensors.voltages()),
    ] {
        for (oid, value) in sensor_table_cells(table_id, &readings) {
            cells.insert(oid, value);
        }
    }
    cells.into_iter().collect()
}

/// LM-SENSORS-MIB handler rooted at `1.3.6.1.4.1.2021.13`.
///
/// Serves all three sensor tables from the supplied [`SensorAccess`]. Returns
/// an [`FnHandler`] so the readings are re-read (and re-sorted) on each
/// refresh, with a short cache window so a full walk stays cheap.
pub fn lm_sensors_handler(sensors: Arc<dyn SensorAccess>) -> Arc<FnHandler> {
    let root = Oid::new(LM_SENSORS.to_vec());
    Arc::new(FnHandler::new(root, move || {
        lm_sensors_cells(&*sensors)
    }))
}

/// Convenience: build the three sensor-table cells for a slice of temperature
/// readings (pure/testable, exposed for unit tests).
pub fn temp_sensor_cells(readings: &[SensorReading]) -> Vec<(Oid, Value)> {
    sensor_table_cells(TEMP_TABLE, readings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::MibHandler;
    use crate::hardware::StaticSensorAccess;

    fn sample_readings() -> Vec<SensorReading> {
        vec![
            SensorReading {
                name: "coretemp:Core 0".to_string(),
                value: 45.0,
                unit: "C".to_string(),
            },
            SensorReading {
                name: "coretemp:Core 1".to_string(),
                value: -5.0,
                unit: "C".to_string(),
            },
        ]
    }

    #[test]
    fn temp_table_cells_layout() {
        let cells = temp_sensor_cells(&sample_readings());
        // lmTempSensorsIndex.1
        let idx1 = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.13.16.2.1.1.1")
            .map(|(_, v)| v.clone());
        assert_eq!(idx1, Some(Value::Integer(1)));
        // lmTempSensorsDevice.1 = "coretemp:Core 0"
        let dev1 = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.13.16.2.1.2.1")
            .map(|(_, v)| v.clone());
        assert_eq!(
            dev1,
            Some(Value::OctetString(b"coretemp:Core 0".to_vec()))
        );
        // lmTempSensorsValue.2 = -5 (negative temp preserved)
        let val2 = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.13.16.2.1.3.2")
            .map(|(_, v)| v.clone());
        assert_eq!(val2, Some(Value::Integer(-5)));
        // lmTempSensorsCritical.1 = 0 (unknown)
        let crit1 = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.13.16.2.1.4.1")
            .map(|(_, v)| v.clone());
        assert_eq!(crit1, Some(Value::Integer(0)));
    }

    #[test]
    fn handler_serves_all_three_tables() {
        let access: Arc<dyn SensorAccess> = Arc::new(StaticSensorAccess {
            temps: sample_readings(),
            fans: vec![SensorReading {
                name: "CPU_FAN".to_string(),
                value: 2400.0,
                unit: "RPM".to_string(),
            }],
            voltages: vec![SensorReading {
                name: "in0".to_string(),
                value: 12.0,
                unit: "V".to_string(),
            }],
        });
        let handler = lm_sensors_handler(access);
        // GET a temperature device cell.
        let temp_dev1: Oid = ".1.3.6.1.4.1.2021.13.16.2.1.2.1".parse().unwrap();
        assert_eq!(
            handler.get(&temp_dev1),
            Some(Value::OctetString(b"coretemp:Core 0".to_vec()))
        );
        // GET a fan value cell.
        let fan_val1: Oid = ".1.3.6.1.4.1.2021.13.16.3.1.3.1".parse().unwrap();
        assert_eq!(handler.get(&fan_val1), Some(Value::Integer(2400)));
        // GET a voltage value cell.
        let volt_val1: Oid = ".1.3.6.1.4.1.2021.13.16.4.1.3.1".parse().unwrap();
        assert_eq!(handler.get(&volt_val1), Some(Value::Integer(12)));
    }

    #[test]
    fn handler_empty_when_no_sensors() {
        let access: Arc<dyn SensorAccess> = Arc::new(StaticSensorAccess::default());
        let handler = lm_sensors_handler(access);
        let root: Oid = ".1.3.6.1.4.1.2021.13.16.2".parse().unwrap();
        // No successor: the tables are empty.
        assert!(handler.get_next(&root).is_none());
    }

    #[test]
    fn handler_getnext_walks_in_order() {
        let access: Arc<dyn SensorAccess> = Arc::new(StaticSensorAccess {
            temps: sample_readings(),
            ..Default::default()
        });
        let handler = lm_sensors_handler(access);
        let start: Oid = ".1.3.6.1.4.1.2021.13.16.2.1.1".parse().unwrap();
        let first = handler.get_next(&start).expect("first cell");
        // First cell of the table is lmTempSensorsIndex.1
        assert_eq!(first.oid.to_string(), ".1.3.6.1.4.1.2021.13.16.2.1.1.1");
        assert_eq!(first.value, Value::Integer(1));
    }
}
