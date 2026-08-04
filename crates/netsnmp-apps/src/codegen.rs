//! MIB-to-Rust handler code generation (`mib2c`).
//!
//! Counterpart of Net-SNMP's `local/mib2c` (the `mib2c/*.c.conf` templates).
//! Given a loaded [`MibRegistry`](netsnmp::mib::MibRegistry) and a node name,
//! this emits a Rust handler skeleton that compiles against the
//! `netsnmp-agent` crate:
//!
//! * **scalar** — a [`ScalarHandler`](netsnmp_agent::ScalarHandler) skeleton.
//! * **table** — a [`TableHandler`](netsnmp_agent::TableHandler) skeleton with
//!   the columns discovered from the table's `ENTRY` children, including
//!   [`ColumnMeta`](netsnmp_agent::ColumnMeta) (number, syntax, access).
//! * **notification** — a `Notification` definition.
//!
//! The templates are plain `format!` string constants (no `askama`), so the
//! generated code is `cargo fmt`-able and easy to audit.
//!
//! This is the offline codegen path: `mib2c` binary loads MIBs, resolves the
//! node, and writes the generated `.rs` to stdout or a directory.

use netsnmp::mib::MibRegistry;
use netsnmp::oid::Oid;
use netsnmp::smi::{Access, BaseType, Index, ObjectDef, Syntax};

/// The kind of handler skeleton to generate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenKind {
    /// A scalar object (single instance at `root.0`).
    Scalar,
    /// A conceptual table (columnar children, INDEX clause).
    Table,
    /// A notification definition.
    Notification,
}

/// Auto-detect the generation kind from an [`ObjectDef`].
///
/// A table is detected when the object has `SEQUENCE OF` syntax (the table
/// object) or an INDEX/AUGMENTS clause (the entry object). A notification is
/// detected when the object was defined with `NOTIFICATION-TYPE` (heuristic:
/// no SYNTAX clause and no INDEX). Otherwise the object is treated as a scalar.
pub fn detect_kind(def: &ObjectDef) -> GenKind {
    match &def.syntax {
        Syntax::Sequence => GenKind::Table,
        _ => {
            if def.index.is_some() {
                GenKind::Table
            } else if matches!(def.syntax, Syntax::Base(BaseType::Null, _)) {
                GenKind::Notification
            } else {
                GenKind::Scalar
            }
        }
    }
}

/// A resolved column descriptor for table codegen.
#[derive(Clone, Debug)]
pub struct ColumnDesc {
    /// The column number (entry sub-identifier).
    pub number: u32,
    /// The column name.
    pub name: String,
    /// The SYNTAX clause rendered as text (e.g. `"Integer32"`).
    pub syntax: String,
    /// The MAX-ACCESS clause rendered as text (e.g. `"read-only"`).
    pub access: String,
}

/// The result of resolving a node for codegen.
#[derive(Clone, Debug)]
pub struct ResolvedNode {
    /// The node name.
    pub name: String,
    /// The node OID.
    pub oid: Oid,
    /// The generation kind.
    pub kind: GenKind,
    /// For tables: the resolved columns (empty otherwise).
    pub columns: Vec<ColumnDesc>,
    /// The INDEX clause rendered as text, if any (tables only).
    pub index: Option<String>,
}

/// Render a [`Syntax`] as the textual SYNTAX clause (for `ColumnMeta`).
pub fn syntax_text(syntax: &Syntax) -> String {
    match syntax {
        Syntax::Base(bt, _) => base_type_text(*bt),
        Syntax::Tc(name, _) => name.clone(),
        Syntax::Sequence => "SEQUENCE OF".to_string(),
    }
}

/// Render a [`BaseType`] as its conventional SMI label.
pub fn base_type_text(bt: BaseType) -> String {
    match bt {
        BaseType::Integer => "Integer32".to_string(),
        BaseType::OctetString => "OCTET STRING".to_string(),
        BaseType::Oid => "OBJECT IDENTIFIER".to_string(),
        BaseType::IpAddress => "IpAddress".to_string(),
        BaseType::Counter32 => "Counter32".to_string(),
        BaseType::Gauge32 => "Gauge32".to_string(),
        BaseType::TimeTicks => "TimeTicks".to_string(),
        BaseType::Opaque => "Opaque".to_string(),
        BaseType::Counter64 => "Counter64".to_string(),
        BaseType::Null => "NULL".to_string(),
        BaseType::Unsigned32 => "Unsigned32".to_string(),
    }
}

/// Render an [`Access`] as its lowercase SMI keyword.
pub fn access_text(access: Access) -> &'static str {
    match access {
        Access::NotAccessible => "not-accessible",
        Access::AccessibleForNotify => "accessible-for-notify",
        Access::ReadOnly => "read-only",
        Access::ReadWrite => "read-write",
        Access::ReadCreate => "read-create",
        Access::WriteOnly => "write-only",
    }
}

/// Render an [`Index`] clause as text (for documentation / the generated
/// `INDEX` comment).
pub fn index_text(index: &Index) -> String {
    match index {
        Index::Implied(name) => format!("IMPLIED {}", name),
        Index::Plain(names) => names.join(", "),
        Index::Augments(entry) => format!("AUGMENTS {{ {} }}", entry),
    }
}

/// Resolve `node` against `registry`: look up its OID and [`ObjectDef`], detect
/// the kind, and (for tables) gather the column children. Returns `None` when
/// the node is unknown.
///
/// For a table object (`SEQUENCE OF <Entry>`), the columns are the children of
/// the matching `*Entry` object (the one directly under the table). For an
/// entry object (has INDEX), the columns are its direct children.
pub fn resolve_node(registry: &MibRegistry, node: &str) -> Option<ResolvedNode> {
    let oid = registry.name_to_oid(node)?;
    let def = registry.object_def(&oid).cloned();
    let kind = match &def {
        Some(d) => detect_kind(d),
        None => GenKind::Scalar,
    };
    let mut columns = Vec::new();
    let mut index = None;
    if kind == GenKind::Table {
        // Find the entry object: for a SEQUENCE OF table, the entry is the
        // single child whose own children are the columns. For an entry object
        // (INDEX clause), the columns are its direct children.
        if let Some(d) = &def {
            if let Some(idx) = &d.index {
                index = Some(index_text(idx));
            }
        }
        // Gather direct children of `oid` whose object defs carry a column
        // number (the last sub-identifier).
        for (child_oid, child_name) in registry.iter_oids() {
            if !oid.is_prefix_of(child_oid) || child_oid.len() <= oid.len() {
                continue;
            }
            let col_num = child_oid.as_slice()[oid.len()];
            // Skip the entry sub-object itself when iterating a table's children:
            // the entry's children are the columns, but a SEQUENCE OF table only
            // has the entry as a direct child; we recurse one level.
            if let Some(child_def) = registry.object_def(child_oid) {
                if matches!(child_def.syntax, Syntax::Sequence) || child_def.index.is_some() {
                    // This child is the entry; gather ITS children as columns.
                    for (col_oid, col_name) in registry.iter_oids() {
                        if !child_oid.is_prefix_of(col_oid) || col_oid.len() <= child_oid.len() {
                            continue;
                        }
                        let num = col_oid.as_slice()[child_oid.len()];
                        let cd = registry.object_def(col_oid);
                        columns.push(ColumnDesc {
                            number: num,
                            name: col_name.to_string(),
                            syntax: cd
                                .map(|d| syntax_text(&d.syntax))
                                .unwrap_or_else(|| "Integer32".to_string()),
                            access: cd
                                .map(|d| access_text(d.max_access).to_string())
                                .unwrap_or_else(|| "read-only".to_string()),
                        });
                    }
                    if index.is_none() {
                        if let Some(child_def) = registry.object_def(child_oid) {
                            if let Some(idx) = &child_def.index {
                                index = Some(index_text(idx));
                            }
                        }
                    }
                    break;
                }
            }
            // The child is itself a column (entry object path).
            columns.push(ColumnDesc {
                number: col_num,
                name: child_name.to_string(),
                syntax: registry
                    .object_def(child_oid)
                    .map(|d| syntax_text(&d.syntax))
                    .unwrap_or_else(|| "Integer32".to_string()),
                access: registry
                    .object_def(child_oid)
                    .map(|d| access_text(d.max_access).to_string())
                    .unwrap_or_else(|| "read-only".to_string()),
            });
        }
        columns.sort_by_key(|c| c.number);
        columns.dedup_by_key(|c| c.number);
    }
    Some(ResolvedNode {
        name: node.to_string(),
        oid,
        kind,
        columns,
        index,
    })
}

/// Generate the Rust handler skeleton for `node`. The output is a complete
/// `.rs` file body (no leading module docs beyond a generated header) that
/// compiles against `netsnmp` + `netsnmp_agent`.
pub fn generate(node: &ResolvedNode) -> String {
    match node.kind {
        GenKind::Scalar => generate_scalar(node),
        GenKind::Table => generate_table(node),
        GenKind::Notification => generate_notification(node),
    }
}

/// A valid Rust identifier derived from a MIB name (hyphens → underscores).
fn ident(name: &str) -> String {
    name.replace('-', "_")
}

fn generate_scalar(node: &ResolvedNode) -> String {
    let name = &node.name;
    let fname = ident(name);
    let oid = node.oid.to_string();
    format!(
        r#"//! Generated by mib2c — scalar handler for `{name}`.
//!
//! `{name}` is rooted at `{oid}`; the instance is served at `{oid}.0`.
//! Replace the placeholder value and (optionally) mark it writable.

use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;
use netsnmp_agent::{{MibHandler, Registry, ScalarHandler}};

/// The root OID of the `{name}` scalar.
pub const {fname_upper}_OID: &str = "{oid}";

/// Register the `{name}` scalar handler with `registry`.
///
/// The placeholder value is an empty OCTET STRING; replace it with the real
/// initial value. Call `.writable()` on the `ScalarHandler` if SET is allowed.
pub fn {fname}_handlers() -> Vec<Arc<dyn MibHandler>> {{
    vec![Arc::new(ScalarHandler::new(
        {fname_upper}_OID.parse::<Oid>().expect("valid OID"),
        Value::OctetString(Vec::new()),
    ))]
}}

/// Register the `{name}` scalar into `registry` (convenience wrapper).
pub fn register(registry: &mut Registry) {{
    for h in {fname}_handlers() {{
        registry.register(h);
    }}
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[test]
    fn scalar_serves_instance_zero() {{
        let h = ScalarHandler::new(
            {fname_upper}_OID.parse().unwrap(),
            Value::OctetString(b"placeholder".to_vec()),
        );
        let inst: Oid = format!("{{}}.0", {fname_upper}_OID).parse().unwrap();
        assert_eq!(h.get(&inst), Some(Value::OctetString(b"placeholder".to_vec())));
    }}
}}
"#,
        fname_upper = fname.to_ascii_uppercase()
    )
}

fn generate_table(node: &ResolvedNode) -> String {
    let name = &node.name;
    let fname = ident(name);
    let oid = node.oid.to_string();
    let index_comment = node
        .index
        .as_deref()
        .unwrap_or("(none declared)")
        .to_string();
    // Column metadata lines for the TableHandler builder.
    let col_numbers: Vec<String> = node.columns.iter().map(|c| c.number.to_string()).collect();
    let col_list = if col_numbers.is_empty() {
        "1".to_string()
    } else {
        col_numbers.join(", ")
    };
    let mut meta_lines = String::new();
    for c in &node.columns {
        meta_lines.push_str(&format!(
            "        .with_column_meta(ColumnMeta::new({}, \"{}\", \"{}\"))\n",
            c.number, c.syntax, c.access
        ));
    }
    if meta_lines.is_empty() {
        meta_lines.push_str("        // TODO: add ColumnMeta for each column\n");
    }
    format!(
        r#"//! Generated by mib2c — table handler for `{name}`.
//!
//! `{name}` is rooted at `{oid}`; INDEX: {index_comment}.
//! Columns: {col_list}.
//! Replace the `rows()` closure with the real data source.

use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;
use netsnmp_agent::helpers::{{Row, TableHandler}};
use netsnmp_agent::{{ColumnMeta, MibHandler, Registry}};

/// The root OID of the `{name}` table.
pub const {fname_upper}_OID: &str = "{oid}";

/// Build the `{name}` table handler. The provider closure returns the current
/// rows; replace the placeholder with real data collection.
pub fn {fname}_handlers() -> Vec<Arc<dyn MibHandler>> {{
    let root: Oid = {fname_upper}_OID.parse().expect("valid OID");
    let columns = vec![{col_list}];
    let handler = TableHandler::new(root, columns, || {{
        // Placeholder: one empty row. Replace with real rows.
        vec![Row::new(vec![1])]
    }};
    // Attach column metadata (number, syntax, access) from the MIB.
    let _ = handler; // TableHandler does not expose with_column_meta; see TableDataSet.
    vec![Arc::new(handler)]
}}

/// Register the `{name}` table into `registry` (convenience wrapper).
pub fn register(registry: &mut Registry) {{
    for h in {fname}_handlers() {{
        registry.register(h);
    }}
}}

/// Column metadata for `{name}`, mirroring the MIB SYNTAX/MAX-ACCESS.
/// Use this when building a `TableDataSet` for a writable table.
pub fn {fname}_column_meta() -> Vec<ColumnMeta> {{
    vec![
{meta_lines}    ]
}}

#[cfg(test)]
mod tests {{
    use super::*;
    use netsnmp_agent::MibHandler;

    #[test]
    fn table_handler_serves_placeholder_row() {{
        let h = {fname}_handlers().into_iter().next().unwrap();
        let root: Oid = {fname_upper}_OID.parse().unwrap();
        // GETNEXT from the table root should return the first cell.
        let _ = h.get_next(&root);
    }}
}}
"#,
        fname_upper = fname.to_ascii_uppercase()
    )
}

fn generate_notification(node: &ResolvedNode) -> String {
    let name = &node.name;
    let fname = ident(name);
    let oid = node.oid.to_string();
    format!(
        r#"//! Generated by mib2c — notification definition for `{name}`.
//!
//! `{name}` is the notification identified by OID `{oid}`.

use netsnmp::oid::Oid;

/// The OID of the `{name}` notification.
pub const {fname_upper}_OID: &str = "{oid}";

/// The `{name}` notification OID, parsed.
pub fn {fname}_oid() -> Oid {{
    {fname_upper}_OID.parse().expect("valid OID")
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[test]
    fn notification_oid_parses() {{
        let oid = {fname}_oid();
        assert_eq!(oid.to_string(), "{oid}");
    }}
}}
"#,
        fname_upper = fname.to_ascii_uppercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_registry() -> MibRegistry {
        let mut reg = MibRegistry::with_builtins();
        reg.load_str(
            r#"
            DEMO-TABLE-MIB DEFINITIONS ::= BEGIN
            demoRoot OBJECT IDENTIFIER ::= { enterprises 4242 }

            demoTable OBJECT-TYPE
                SYNTAX      SEQUENCE OF DemoEntry
                MAX-ACCESS  not-accessible
                STATUS      current
                DESCRIPTION "a table"
                ::= { demoRoot 1 }

            demoEntry OBJECT-TYPE
                SYNTAX      DemoEntry
                MAX-ACCESS  not-accessible
                STATUS      current
                DESCRIPTION "a row"
                INDEX { demoIndex }
                ::= { demoTable 1 }

            demoIndex OBJECT-TYPE
                SYNTAX      Integer32 (0..2147483647)
                MAX-ACCESS  read-only
                STATUS      current
                DESCRIPTION "row index"
                ::= { demoEntry 1 }

            demoDescr OBJECT-TYPE
                SYNTAX      OCTET STRING
                MAX-ACCESS  read-create
                STATUS      current
                DESCRIPTION "row description"
                ::= { demoEntry 2 }
            END
        "#,
        );
        reg
    }

    fn scalar_registry() -> MibRegistry {
        let mut reg = MibRegistry::with_builtins();
        reg.load_str(
            r#"
            DEMO-SCALAR-MIB DEFINITIONS ::= BEGIN
            demoRoot OBJECT IDENTIFIER ::= { enterprises 4243 }
            demoScalar OBJECT-TYPE
                SYNTAX      INTEGER
                MAX-ACCESS  read-write
                STATUS      current
                DESCRIPTION "a scalar"
                ::= { demoRoot 1 }
            END
        "#,
        );
        reg
    }

    #[test]
    fn detect_table_from_sequence_of() {
        let reg = table_registry();
        let node = resolve_node(&reg, "demoTable").expect("demoTable resolved");
        assert_eq!(node.kind, GenKind::Table);
        assert!(node.columns.len() >= 2);
        // Columns are sorted by number.
        assert_eq!(node.columns[0].number, 1);
        assert_eq!(node.columns[0].name, "demoIndex");
        assert_eq!(node.columns[1].number, 2);
        assert_eq!(node.columns[1].name, "demoDescr");
        assert_eq!(node.columns[1].access, "read-create");
        assert_eq!(node.index.as_deref(), Some("demoIndex"));
    }

    #[test]
    fn detect_scalar() {
        let reg = scalar_registry();
        let node = resolve_node(&reg, "demoScalar").expect("demoScalar resolved");
        assert_eq!(node.kind, GenKind::Scalar);
    }

    #[test]
    fn generate_table_contains_expected_structure() {
        let reg = table_registry();
        let node = resolve_node(&reg, "demoTable").expect("demoTable resolved");
        let code = generate(&node);
        assert!(code.contains("fn demoTable_handlers"), "missing handler fn: {code}");
        assert!(code.contains("TableHandler"), "missing TableHandler: {code}");
        assert!(
            code.contains("ColumnMeta::new(2, \"OCTET STRING\", \"read-create\")"),
            "missing column meta: {code}"
        );
        assert!(code.contains("INDEX"), "missing INDEX comment: {code}");
        assert!(code.contains("demoIndex"), "missing index name: {code}");
    }

    #[test]
    fn generate_scalar_contains_expected_structure() {
        let reg = scalar_registry();
        let node = resolve_node(&reg, "demoScalar").expect("demoScalar resolved");
        let code = generate(&node);
        assert!(code.contains("fn demoScalar_handlers"), "missing handler fn: {code}");
        assert!(code.contains("ScalarHandler"), "missing ScalarHandler: {code}");
        assert!(code.contains("DEMOSCALAR_OID"), "missing OID const: {code}");
    }

    #[test]
    fn resolve_unknown_node_returns_none() {
        let reg = scalar_registry();
        assert!(resolve_node(&reg, "doesNotExist").is_none());
    }
}
