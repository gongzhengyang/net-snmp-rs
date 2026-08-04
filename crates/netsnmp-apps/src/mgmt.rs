//! USM and VACM management helpers.
//!
//! These build the SNMP SET variable-bindings that create, modify and destroy
//! rows in the SNMP-USER-BASED-SM-MIB (`usmUserTable`) and SNMP-VIEW-BASED-ACM-MIB
//! (`vacmSecurityToGroupTable`, `vacmAccessTable`, `vacmViewTreeFamilyTable`).
//! Counterpart of `apps/snmpusm.c` and `apps/snmpvacm.c`.
//!
//! The functions are pure (no I/O) so they can be unit-tested; the binaries
//! send the resulting bindings via an SNMP SET. End-to-end use requires an
//! agent that implements management of these MIB tables.

use netsnmp::oid::Oid;
use netsnmp::pdu::VarBind;
use netsnmp::value::Value;

use crate::table::cell_oid;

/// SNMPv2-TC RowStatus enumeration values.
pub mod row_status {
    pub const ACTIVE: i64 = 1;
    pub const NOT_IN_SERVICE: i64 = 2;
    pub const CREATE_AND_GO: i64 = 4;
    pub const CREATE_AND_WAIT: i64 = 5;
    pub const DESTROY: i64 = 6;
}

/// SNMPv2-TC StorageType enumeration values (used by `usmUserStorageType` and
/// the VACM tables).
pub mod storage_type {
    /// `other(1)`.
    pub const OTHER: i64 = 1;
    /// `volatile(2)`.
    pub const VOLATILE: i64 = 2;
    /// `nonVolatile(3)`.
    pub const NON_VOLATILE: i64 = 3;
    /// `permanent(4)`.
    pub const PERMANENT: i64 = 4;
    /// `readOnly(5)`.
    pub const READ_ONLY: i64 = 5;
}

// ---------------------------------------------------------------------------
// Table entry OIDs
// ---------------------------------------------------------------------------

/// `usmUserEntry` OID (`1.3.6.1.6.3.15.1.2.2.1`) — root of `usmUserTable`.
/// Public so the tools can issue GETNEXT walks for `list`.
pub const USM_USER_ENTRY_OID: &str = "1.3.6.1.6.3.15.1.2.2.1";
/// `vacmSecurityToGroupEntry` OID (`1.3.6.1.6.3.16.1.2.1`) — root of
/// `vacmSecurityToGroupTable`.
pub const VACM_SEC2GROUP_ENTRY_OID: &str = "1.3.6.1.6.3.16.1.2.1";
/// `vacmAccessEntry` OID (`1.3.6.1.6.3.16.1.4.1`) — root of `vacmAccessTable`.
pub const VACM_ACCESS_ENTRY_OID: &str = "1.3.6.1.6.3.16.1.4.1";
/// `vacmViewTreeFamilyEntry` OID (`1.3.6.1.6.3.16.1.5.2.1`) — root of
/// `vacmViewTreeFamilyTable`.
pub const VACM_VIEW_ENTRY_OID: &str = "1.3.6.1.6.3.16.1.5.2.1";

const USM_USER_ENTRY: &str = USM_USER_ENTRY_OID;
const VACM_SEC2GROUP_ENTRY: &str = VACM_SEC2GROUP_ENTRY_OID;
const VACM_ACCESS_ENTRY: &str = VACM_ACCESS_ENTRY_OID;
const VACM_VIEW_ENTRY: &str = VACM_VIEW_ENTRY_OID;

fn entry(s: &str) -> Oid {
    s.parse().expect("valid table entry OID")
}

/// Encode a variable-length OCTET STRING as MIB index sub-identifiers:
/// a leading length octet followed by one sub-identifier per byte.
pub fn string_index(bytes: &[u8]) -> Vec<u32> {
    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.push(bytes.len() as u32);
    out.extend(bytes.iter().map(|&b| b as u32));
    out
}

/// Encode an OBJECT IDENTIFIER index (length-prefixed sub-identifiers), used by
/// `vacmViewTreeFamilySubtree`.
pub fn oid_index(oid: &Oid) -> Vec<u32> {
    let mut out = Vec::with_capacity(oid.len() + 1);
    out.push(oid.len() as u32);
    out.extend_from_slice(oid.as_slice());
    out
}

// ---------------------------------------------------------------------------
// usmUserTable (SNMP-USER-BASED-SM-MIB)
// ---------------------------------------------------------------------------

// Column numbers inside usmUserEntry (see SNMP-USER-BASED-SM-MIB):
//   2 = usmUserName        (not-accessible, part of the index)
//   3 = usmUserSecurityName (read-only)
//   4 = usmUserCloneFrom
//   5 = usmUserAuthProtocol
//   8 = usmUserPrivProtocol
//   6 = usmUserStorageType
//  13 = usmUserStatus
const USM_SECURITY_NAME: u32 = 3;
const USM_CLONE_FROM: u32 = 4;
const USM_AUTH_PROTOCOL: u32 = 5;
const USM_PRIV_PROTOCOL: u32 = 8;
const USM_STATUS: u32 = 13;

/// The `usmUserSecurityName` column number, exposed for tools that walk
/// `usmUserTable` and label rows.
pub const USM_SECURITY_NAME_COL: u32 = USM_SECURITY_NAME;
/// The `usmUserAuthProtocol` column number.
pub const USM_AUTH_PROTOCOL_COL: u32 = USM_AUTH_PROTOCOL;
/// The `usmUserPrivProtocol` column number.
pub const USM_PRIV_PROTOCOL_COL: u32 = USM_PRIV_PROTOCOL;
/// The `usmUserStatus` column number.
pub const USM_STATUS_COL: u32 = USM_STATUS;

/// INDEX for `usmUserTable`: { usmUserEngineID, usmUserName }, both
/// variable-length OCTET STRINGs.
pub fn usm_user_index(engine_id: &[u8], user: &str) -> Vec<u32> {
    let mut idx = string_index(engine_id);
    idx.extend(string_index(user.as_bytes()));
    idx
}

/// Best-effort extraction of the `usmUserName` portion from a `usmUserTable`
/// row index — the trailing ASCII bytes after the length-prefixed
/// `usmUserEngineID`. The index layout is:
/// `engineId_len engineId... user_len user_bytes...`. Returns the user name as
/// a lossy UTF-8 string, or `None` when the index is too short to be valid.
pub fn parse_usm_user_name(index: &[u32]) -> Option<String> {
    if index.is_empty() {
        return None;
    }
    let engine_len = index[0] as usize;
    let need = engine_len.checked_add(1)?;
    if index.len() < need {
        return None;
    }
    let rest = &index[need..];
    if rest.is_empty() {
        return None;
    }
    let name_len = rest[0] as usize;
    let name_end = 1usize.checked_add(name_len)?;
    if rest.len() < name_end {
        return None;
    }
    let bytes: Vec<u8> = rest[1..name_end].iter().map(|&v| v as u8).collect();
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Build the SET bindings to create a USM user by cloning an existing template
/// user: point `usmUserCloneFrom` at the template's `usmUserSecurityName`
/// instance and create the row with `createAndGo`.
pub fn usm_create(engine_id: &[u8], user: &str, clone_from: &str) -> Vec<VarBind> {
    let entry = entry(USM_USER_ENTRY);
    let index = usm_user_index(engine_id, user);
    vec![
        VarBind::new(
            cell_oid(&entry, USM_CLONE_FROM, &index),
            Value::Oid(usm_security_name_oid(engine_id, clone_from)),
        ),
        VarBind::new(
            cell_oid(&entry, USM_STATUS, &index),
            Value::Integer(row_status::CREATE_AND_GO),
        ),
    ]
}

/// The OID a freshly cloned user's `usmUserCloneFrom` should point at: the
/// `usmUserSecurityName` (column 3) instance of the template user.
pub fn usm_security_name_oid(engine_id: &[u8], template_user: &str) -> Oid {
    let entry = entry(USM_USER_ENTRY);
    cell_oid(&entry, 3, &usm_user_index(engine_id, template_user))
}

/// Build the SET binding to point a (yet to be created) user's
/// `usmUserCloneFrom` at the `usmUserSecurityName` instance of an existing
/// template user. Used as the first step of the explicit `cloneFrom` operation;
/// the caller follows up with a `usm_set_status(createAndGo)`.
pub fn usm_clone_from(engine_id: &[u8], user: &str, template_sec_name_oid: Oid) -> VarBind {
    let entry = entry(USM_USER_ENTRY);
    let index = usm_user_index(engine_id, user);
    VarBind::new(
        cell_oid(&entry, USM_CLONE_FROM, &index),
        Value::Oid(template_sec_name_oid),
    )
}

/// `usmUserStorageType` — column 6 of `usmUserEntry` (see
/// SNMP-USER-BASED-SM-MIB). Build the SET binding for `lock` (readOnly = 5) /
/// `unlock` (volatile = 2) and similar storage-type transitions.
pub const USM_STORAGE_TYPE: u32 = 6;

/// Build the SET binding that writes a USM user's `usmUserStorageType`.
///
/// Typical values follow SNMPv2-TC `StorageType`: `2` = volatile (unlock),
/// `5` = readOnly (lock).
pub fn usm_storage_type(engine_id: &[u8], user: &str, value: i64) -> VarBind {
    let entry = entry(USM_USER_ENTRY);
    let index = usm_user_index(engine_id, user);
    VarBind::new(
        cell_oid(&entry, USM_STORAGE_TYPE, &index),
        Value::Integer(value),
    )
}

/// Build the SET binding to remotely change a user's localized auth or privacy
/// key, writing the RFC 3414 KeyChange value to `column` (e.g.
/// `usmUserAuthKeyChange` = 6, `usmUserPrivKeyChange` = 9).
pub fn usm_key_change(
    engine_id: &[u8],
    user: &str,
    column: u32,
    key_change_value: Vec<u8>,
) -> VarBind {
    let entry = entry(USM_USER_ENTRY);
    let index = usm_user_index(engine_id, user);
    VarBind::new(
        cell_oid(&entry, column, &index),
        Value::OctetString(key_change_value),
    )
}

/// Build the SET that sets a USM user's RowStatus (create/activate/destroy).
pub fn usm_set_status(engine_id: &[u8], user: &str, status: i64) -> VarBind {
    let entry = entry(USM_USER_ENTRY);
    let index = usm_user_index(engine_id, user);
    VarBind::new(cell_oid(&entry, USM_STATUS, &index), Value::Integer(status))
}

// ---------------------------------------------------------------------------
// VACM tables (SNMP-VIEW-BASED-ACM-MIB)
// ---------------------------------------------------------------------------
const VACM_GROUP_NAME: u32 = 3;
const VACM_S2G_STATUS: u32 = 5;

const VACM_ACCESS_READ_VIEW: u32 = 5;
const VACM_ACCESS_WRITE_VIEW: u32 = 6;
const VACM_ACCESS_NOTIFY_VIEW: u32 = 7;
const VACM_ACCESS_STATUS: u32 = 9;

const VACM_VIEW_MASK: u32 = 3;
const VACM_VIEW_TYPE: u32 = 4;
const VACM_VIEW_STATUS: u32 = 6;

/// Column numbers used by the VACM `list` walks. Exposed so the tools can label
/// cells without re-deriving them.
pub mod vacm_cols {
    use super::*;
    /// `vacmSecurityToGroupGroupName` (col 3 of vacmSecurityToGroupEntry).
    pub const S2G_GROUP_NAME: u32 = VACM_GROUP_NAME;
    /// `vacmViewTreeFamilySubtree` is part of the index.
    /// `vacmViewTreeFamilyType` (col 4 of vacmViewTreeFamilyEntry).
    pub const VIEW_TYPE: u32 = VACM_VIEW_TYPE;
    /// `vacmAccessContextMatch` (col 4), `vacmAccessReadViewName` (col 5),
    /// `vacmAccessWriteViewName` (col 6), `vacmAccessNotifyViewName` (col 7).
    pub const ACCESS_READ_VIEW: u32 = VACM_ACCESS_READ_VIEW;
    pub const ACCESS_WRITE_VIEW: u32 = VACM_ACCESS_WRITE_VIEW;
    pub const ACCESS_NOTIFY_VIEW: u32 = VACM_ACCESS_NOTIFY_VIEW;
}

/// View tree family type: included or excluded.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ViewType {
    Included = 1,
    Excluded = 2,
}

/// Build the SET bindings to map a (securityModel, securityName) to a group.
pub fn vacm_create_sec2group(model: i64, sec_name: &str, group: &str) -> Vec<VarBind> {
    let entry = entry(VACM_SEC2GROUP_ENTRY);
    let mut index = vec![model as u32];
    index.extend(string_index(sec_name.as_bytes()));
    vec![
        VarBind::new(
            cell_oid(&entry, VACM_GROUP_NAME, &index),
            Value::OctetString(group.as_bytes().to_vec()),
        ),
        VarBind::new(
            cell_oid(&entry, VACM_S2G_STATUS, &index),
            Value::Integer(row_status::CREATE_AND_GO),
        ),
    ]
}

/// Build the SET binding to destroy a security-to-group mapping.
pub fn vacm_delete_sec2group(model: i64, sec_name: &str) -> VarBind {
    let entry = entry(VACM_SEC2GROUP_ENTRY);
    let mut index = vec![model as u32];
    index.extend(string_index(sec_name.as_bytes()));
    VarBind::new(
        cell_oid(&entry, VACM_S2G_STATUS, &index),
        Value::Integer(row_status::DESTROY),
    )
}

/// INDEX for `vacmAccessTable`:
/// { vacmGroupName, vacmAccessContextPrefix, vacmAccessSecurityModel,
///   vacmAccessSecurityLevel }.
pub fn vacm_access_index(group: &str, context: &str, model: i64, level: i64) -> Vec<u32> {
    let mut idx = string_index(group.as_bytes());
    idx.extend(string_index(context.as_bytes()));
    idx.push(model as u32);
    idx.push(level as u32);
    idx
}

/// Build the SET bindings granting a group read/write/notify views.
pub fn vacm_create_access(
    group: &str,
    context: &str,
    model: i64,
    level: i64,
    read: &str,
    write: &str,
    notify: &str,
) -> Vec<VarBind> {
    let entry = entry(VACM_ACCESS_ENTRY);
    let index = vacm_access_index(group, context, model, level);
    vec![
        VarBind::new(
            cell_oid(&entry, VACM_ACCESS_READ_VIEW, &index),
            Value::OctetString(read.as_bytes().to_vec()),
        ),
        VarBind::new(
            cell_oid(&entry, VACM_ACCESS_WRITE_VIEW, &index),
            Value::OctetString(write.as_bytes().to_vec()),
        ),
        VarBind::new(
            cell_oid(&entry, VACM_ACCESS_NOTIFY_VIEW, &index),
            Value::OctetString(notify.as_bytes().to_vec()),
        ),
        VarBind::new(
            cell_oid(&entry, VACM_ACCESS_STATUS, &index),
            Value::Integer(row_status::CREATE_AND_GO),
        ),
    ]
}

/// Build the SET binding to destroy an access row.
pub fn vacm_delete_access(group: &str, context: &str, model: i64, level: i64) -> VarBind {
    let entry = entry(VACM_ACCESS_ENTRY);
    let index = vacm_access_index(group, context, model, level);
    VarBind::new(
        cell_oid(&entry, VACM_ACCESS_STATUS, &index),
        Value::Integer(row_status::DESTROY),
    )
}

/// INDEX for `vacmViewTreeFamilyTable`: { vacmViewTreeFamilyViewName (string),
/// vacmViewTreeFamilySubtree (OID) }.
pub fn vacm_view_index(view: &str, subtree: &Oid) -> Vec<u32> {
    let mut idx = string_index(view.as_bytes());
    idx.extend(oid_index(subtree));
    idx
}

/// Build the SET bindings to create a view-tree-family entry.
pub fn vacm_create_view(
    view: &str,
    subtree: &Oid,
    mask: &[u8],
    view_type: ViewType,
) -> Vec<VarBind> {
    let entry = entry(VACM_VIEW_ENTRY);
    let index = vacm_view_index(view, subtree);
    vec![
        VarBind::new(
            cell_oid(&entry, VACM_VIEW_MASK, &index),
            Value::OctetString(mask.to_vec()),
        ),
        VarBind::new(
            cell_oid(&entry, VACM_VIEW_TYPE, &index),
            Value::Integer(view_type as i64),
        ),
        VarBind::new(
            cell_oid(&entry, VACM_VIEW_STATUS, &index),
            Value::Integer(row_status::CREATE_AND_GO),
        ),
    ]
}

/// Build the SET binding to destroy a view-tree-family entry.
pub fn vacm_delete_view(view: &str, subtree: &Oid) -> VarBind {
    let entry = entry(VACM_VIEW_ENTRY);
    let index = vacm_view_index(view, subtree);
    VarBind::new(
        cell_oid(&entry, VACM_VIEW_STATUS, &index),
        Value::Integer(row_status::DESTROY),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use netsnmp::usm::AuthProtocol;

    #[test]
    fn string_index_is_length_prefixed() {
        assert_eq!(string_index(b"abc"), vec![3, 97, 98, 99]);
        assert_eq!(string_index(b""), vec![0]);
    }

    #[test]
    fn usm_index_concatenates_engine_and_name() {
        // engine "EE" (2 bytes) then user "u" (1 byte).
        let idx = usm_user_index(b"EE", "u");
        assert_eq!(idx, vec![2, 69, 69, 1, 117]);
    }

    #[test]
    fn usm_delete_targets_status_column_with_destroy() {
        let vb = usm_set_status(b"EE", "u", row_status::DESTROY);
        // ...15.1.2.2.1 .13 <index>
        let s = vb.oid.to_string();
        assert!(s.contains(".15.1.2.2.1.13."), "got {s}");
        assert_eq!(vb.value, Value::Integer(row_status::DESTROY));
    }

    #[test]
    fn vacm_view_index_has_string_then_oid() {
        let subtree: Oid = "1.3.6.1.2.1".parse().unwrap();
        let idx = vacm_view_index("all", &subtree);
        // "all" -> [3, a, l, l], then subtree -> [6, 1,3,6,1,2,1]
        assert_eq!(idx, vec![3, 97, 108, 108, 6, 1, 3, 6, 1, 2, 1]);
    }

    #[test]
    fn key_change_is_random_then_xored_delta() {
        // The leading bytes are exactly the random block; total is random ++ delta.
        let random = [0u8; 16];
        let kc = AuthProtocol::HmacMd5.key_change(
            b"old-pass-1234",
            b"new-pass-1234",
            b"engine",
            &random,
        );
        assert_eq!(kc.len(), 32, "16 random + 16 delta for MD5");
        assert_eq!(&kc[..16], &random);
    }
}
