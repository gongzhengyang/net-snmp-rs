//! RowStatus textual-convention state machine (RFC 2579 §2).
//!
//! The `RowStatus` TC governs the lifecycle of conceptual rows in SNMP
//! tables. A manager creates, suspends, activates and destroys rows by SETting
//! the RowStatus column to one of six values. This module implements that
//! state machine as a pure function so that any table handler
//! ([`crate::helpers::table_dataset::TableDataSet`], a custom handler, or a
//! future AgentX sub-agent) can drive row lifecycle consistently.
//!
//! The implemented transitions follow RFC 2579 §2 and the Net-SNMP
//! `table_dataset` helper. `transition` takes the row's current status (or
//! `None` if the row does not yet exist), the status requested by the manager,
//! and whether every required column already has a value, and returns either
//! the new status of the row (`None` means the row has been destroyed) or an
//! SNMP error-status describing why the request is rejected.

use netsnmp::pdu::ErrorStatus;
use netsnmp::value::Value;
use std::fmt;

/// The six values of the RowStatus textual convention (RFC 2579 §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RowStatus {
    /// The row is available for use by the managed device.
    Active = 1,
    /// The row exists but is not available for use; column values may be
    /// modified in this state.
    NotInService = 2,
    /// The row exists but is missing values for one or more required columns.
    NotReady = 3,
    /// Supplied by a manager creating a row: reserve the row and, if all
    /// required columns are present, atomically transition to `active`.
    CreateAndGo = 4,
    /// Supplied by a manager creating a row: reserve the row and leave it
    /// `notInService` (or `notReady` if required columns are missing) so it
    /// can be configured before being activated.
    CreateAndWait = 5,
    /// Supplied by a manager to delete the row.
    Destroy = 6,
}

impl RowStatus {
    /// Parse a `RowStatus` from an SNMP integer value, returning `None` for
    /// values outside the 1..=6 range defined by RFC 2579.
    pub fn from_i64(v: i64) -> Option<Self> {
        match v {
            1 => Some(RowStatus::Active),
            2 => Some(RowStatus::NotInService),
            3 => Some(RowStatus::NotReady),
            4 => Some(RowStatus::CreateAndGo),
            5 => Some(RowStatus::CreateAndWait),
            6 => Some(RowStatus::Destroy),
            _ => None,
        }
    }

    /// Extract a `RowStatus` from an SNMP `Value`, accepting only the integer
    /// encoding used for RowStatus on the wire.
    pub fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Integer(v) => RowStatus::from_i64(*v),
            // Some agents encode RowStatus as Gauge32/Unsigned32; accept it.
            Value::Gauge32(v) => RowStatus::from_i64(*v as i64),
            _ => None,
        }
    }

    /// The integer value carried on the wire.
    pub fn as_i64(self) -> i64 {
        self as i64
    }

    /// Whether this status represents a creation verb (`createAndGo` or
    /// `createAndWait`).
    pub fn is_create(self) -> bool {
        matches!(self, RowStatus::CreateAndGo | RowStatus::CreateAndWait)
    }
}

impl fmt::Display for RowStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            RowStatus::Active => "active",
            RowStatus::NotInService => "notInService",
            RowStatus::NotReady => "notReady",
            RowStatus::CreateAndGo => "createAndGo",
            RowStatus::CreateAndWait => "createAndWait",
            RowStatus::Destroy => "destroy",
        };
        write!(f, "{s}({})", self.as_i64())
    }
}

/// Compute the new row status resulting from a manager's RowStatus SET, per
/// RFC 2579 §2.
///
/// `current` is `None` if the row does not yet exist (the common case for
/// `createAndGo`/`createAndWait`/`destroy`) and `Some(s)` if the row already
/// exists with status `s`. `required_columns_satisfied` indicates whether all
/// required (non-DEFVAL'd) columns of the row currently have values; it is
/// only consulted for the `createAndGo`, `createAndWait` and `active`
/// transitions.
///
/// On success, `Ok(None)` means the row should be destroyed, `Ok(Some(s))`
/// means the row should be left in status `s`. On failure the appropriate SNMP
/// `ErrorStatus` is returned.
///
/// # Reference (RFC 2579 §2, abridged)
///
/// | requested            | row absent                      | row present                         |
/// |----------------------|---------------------------------|-------------------------------------|
/// | `active(1)`          | `inconsistentName`              | ok if was `notInService`/`active`   |
/// | `notInService(2)`    | `inconsistentName`              | ok if was `active`/`notInService`   |
/// | `notReady(3)`        | `inconsistentName`              | ok if was `notInService`/`notReady` |
/// | `createAndGo(4)`     | -> `active` (or `inconsistentName` if required cols missing) | `inconsistentValue` |
/// | `createAndWait(5)`   | -> `notInService`/`notReady`    | `inconsistentValue`                 |
/// | `destroy(6)`         | -> destroy (or `inconsistentValue`) | -> destroy                      |
pub fn transition(
    current: Option<RowStatus>,
    requested: RowStatus,
    required_columns_satisfied: bool,
) -> Result<Option<RowStatus>, ErrorStatus> {
    match requested {
        RowStatus::CreateAndGo => {
            if current.is_some() {
                // Row already exists: cannot create again.
                return Err(ErrorStatus::InconsistentValue);
            }
            if !required_columns_satisfied {
                // All required columns must be present to go straight to
                // active in a single SET.
                return Err(ErrorStatus::InconsistentName);
            }
            Ok(Some(RowStatus::Active))
        }
        RowStatus::CreateAndWait => {
            if current.is_some() {
                return Err(ErrorStatus::InconsistentValue);
            }
            if required_columns_satisfied {
                Ok(Some(RowStatus::NotInService))
            } else {
                Ok(Some(RowStatus::NotReady))
            }
        }
        RowStatus::Destroy => {
            match current {
                Some(_) => Ok(None),
                // Destroying a non-existent row: Net-SNMP treats this as a
                // no-op success (returning noSuchInstance at GET, but the SET
                // itself does not error). Other stacks reject it; we follow
                // the permissive Net-SNMP behaviour documented in the spec.
                None => Ok(None),
            }
        }
        RowStatus::Active => match current {
            // Row must exist to be activated; and only `notInService`/`notReady`
            // rows may transition to active (re-activating an already-active
            // row is permitted as a no-op per Net-SNMP).
            Some(RowStatus::NotInService) | Some(RowStatus::NotReady) | Some(RowStatus::Active)
                if required_columns_satisfied =>
            {
                Ok(Some(RowStatus::Active))
            }
            Some(RowStatus::NotInService) | Some(RowStatus::NotReady)
                if !required_columns_satisfied =>
            {
                // Cannot go active without all required columns.
                Err(ErrorStatus::InconsistentValue)
            }
            Some(RowStatus::Active) if !required_columns_satisfied => {
                Err(ErrorStatus::InconsistentValue)
            }
            Some(_) => Err(ErrorStatus::InconsistentValue),
            None => Err(ErrorStatus::InconsistentName),
        },
        RowStatus::NotInService => match current {
            // Only an existing active/notInService row can be taken out of
            // service.
            Some(RowStatus::Active) | Some(RowStatus::NotInService) => {
                Ok(Some(RowStatus::NotInService))
            }
            Some(_) => Err(ErrorStatus::InconsistentValue),
            None => Err(ErrorStatus::InconsistentName),
        },
        RowStatus::NotReady => match current {
            // `notReady` is normally only ever set by the agent itself when a
            // row loses a required column. A manager SETting it is unusual;
            // accept it on an existing notInService/notReady row.
            Some(RowStatus::NotInService) | Some(RowStatus::NotReady) => {
                Ok(Some(RowStatus::NotReady))
            }
            Some(_) => Err(ErrorStatus::InconsistentValue),
            None => Err(ErrorStatus::InconsistentName),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_i64_roundtrips() {
        for v in 1..=6i64 {
            let rs = RowStatus::from_i64(v).unwrap();
            assert_eq!(rs.as_i64(), v);
        }
        assert!(RowStatus::from_i64(0).is_none());
        assert!(RowStatus::from_i64(7).is_none());
        assert!(RowStatus::from_i64(-1).is_none());
    }

    #[test]
    fn from_value_accepts_integer_and_gauge() {
        assert_eq!(
            RowStatus::from_value(&Value::Integer(4)),
            Some(RowStatus::CreateAndGo)
        );
        assert_eq!(
            RowStatus::from_value(&Value::Gauge32(6)),
            Some(RowStatus::Destroy)
        );
        assert_eq!(RowStatus::from_value(&Value::OctetString(vec![1])), None);
    }

    #[test]
    fn create_and_go_creates_active_row() {
        let next = transition(None, RowStatus::CreateAndGo, true).unwrap();
        assert_eq!(next, Some(RowStatus::Active));
    }

    #[test]
    fn create_and_go_missing_required_is_inconsistent_name() {
        let err = transition(None, RowStatus::CreateAndGo, false).unwrap_err();
        assert_eq!(err, ErrorStatus::InconsistentName);
    }

    #[test]
    fn create_and_go_on_existing_is_inconsistent_value() {
        let err = transition(
            Some(RowStatus::Active),
            RowStatus::CreateAndGo,
            true,
        )
        .unwrap_err();
        assert_eq!(err, ErrorStatus::InconsistentValue);
    }

    #[test]
    fn create_and_wait_yields_not_in_service_when_complete() {
        let next = transition(None, RowStatus::CreateAndWait, true).unwrap();
        assert_eq!(next, Some(RowStatus::NotInService));
    }

    #[test]
    fn create_and_wait_yields_not_ready_when_incomplete() {
        let next = transition(None, RowStatus::CreateAndWait, false).unwrap();
        assert_eq!(next, Some(RowStatus::NotReady));
    }

    #[test]
    fn destroy_removes_existing_row() {
        let next = transition(Some(RowStatus::Active), RowStatus::Destroy, true).unwrap();
        assert_eq!(next, None);
    }

    #[test]
    fn destroy_absent_is_no_op_success() {
        let next = transition(None, RowStatus::Destroy, true).unwrap();
        assert_eq!(next, None);
    }

    #[test]
    fn active_activates_not_in_service_row() {
        let next = transition(
            Some(RowStatus::NotInService),
            RowStatus::Active,
            true,
        )
        .unwrap();
        assert_eq!(next, Some(RowStatus::Active));
    }

    #[test]
    fn active_on_absent_row_is_inconsistent_name() {
        let err = transition(None, RowStatus::Active, true).unwrap_err();
        assert_eq!(err, ErrorStatus::InconsistentName);
    }

    #[test]
    fn active_with_missing_required_is_inconsistent_value() {
        let err = transition(
            Some(RowStatus::NotInService),
            RowStatus::Active,
            false,
        )
        .unwrap_err();
        assert_eq!(err, ErrorStatus::InconsistentValue);
    }

    #[test]
    fn not_in_service_takes_active_row_offline() {
        let next = transition(Some(RowStatus::Active), RowStatus::NotInService, true).unwrap();
        assert_eq!(next, Some(RowStatus::NotInService));
    }

    #[test]
    fn not_in_service_on_not_ready_is_inconsistent_value() {
        let err = transition(
            Some(RowStatus::NotReady),
            RowStatus::NotInService,
            false,
        )
        .unwrap_err();
        assert_eq!(err, ErrorStatus::InconsistentValue);
    }

    #[test]
    fn display_includes_name_and_value() {
        assert_eq!(RowStatus::Active.to_string(), "active(1)");
        assert_eq!(RowStatus::CreateAndGo.to_string(), "createAndGo(4)");
    }
}
