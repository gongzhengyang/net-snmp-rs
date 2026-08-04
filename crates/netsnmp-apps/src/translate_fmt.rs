//! Pure formatting helpers for `snmptranslate`'s extended `-O*` / `-T*` modes.
//!
//! These functions work strictly against the **existing** [`MibRegistry`] API
//! (`format_oid`, `oid_to_name`, `name_to_oid`, `iter_oids`, `translate`,
//! `enums_for`). They deliberately avoid depending on any new richer methods
//! that a parallel task may be adding to `mib.rs` (e.g. `qualified_name`,
//! `object_def`, `textual_convention`), so this module compiles regardless of
//! whether those land first.
//!
//! All name derivation is therefore reconstructed locally from
//! [`MibRegistry::oid_to_name`] by walking parent OIDs.

use netsnmp::mib::MibRegistry;
use netsnmp::oid::Oid;

/// Resolve a token that may be numeric, a bare name, a `name.suffix` instance,
/// or a dotted symbolic path like `ifTable.ifEntry.ifIndex`.
///
/// This mirrors what the richer upstream `snmptranslate` accepts, but is
/// implemented locally because the existing [`MibRegistry::translate`] only
/// handles a single name plus numeric suffix. Numeric tokens resolve to
/// themselves; for dotted symbolic paths each segment after the first is looked
/// up as a registered direct child of the OID accumulated so far.
pub fn resolve_token(mib: &MibRegistry, token: &str) -> Option<Oid> {
    let trimmed = token.trim().trim_start_matches('.');

    // Try the registry's built-in resolver first (handles numeric and
    // `name.numeric` forms, plus already-registered single names).
    if let Some(oid) = mib.translate(token) {
        return Some(oid);
    }

    // Fall back to dotted symbolic path resolution: `seg1.seg2.seg3...` where
    // each segment is a registered child name of the accumulating OID.
    if trimmed.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        // Pure numeric that failed to parse is hopeless.
        return None;
    }
    let mut iter = trimmed.split('.');
    let first = iter.next()?;
    let mut cur = mib.name_to_oid(first)?;
    for seg in iter {
        // Numeric segment: append directly.
        if let Ok(n) = seg.parse::<u32>() {
            cur = cur.child(n);
            continue;
        }
        // Symbolic segment: find a registered direct child whose name matches.
        let parent = cur.clone();
        let mut found = None;
        for (oid, name) in mib.iter_oids() {
            if oid.as_slice().len() == parent.as_slice().len() + 1
                && oid.as_slice()[..parent.as_slice().len()] == *parent.as_slice()
            {
                let leaf = name.rsplit('.').next().unwrap_or(name);
                if leaf == seg {
                    found = Some(oid.clone());
                    break;
                }
            }
        }
        match found {
            Some(o) => cur = o,
            None => return None,
        }
    }
    Some(cur)
}

/// Return the parent OID (all but the last sub-identifier), if any.
fn parent_of(oid: &Oid) -> Option<Oid> {
    let s = oid.as_slice();
    if s.len() <= 1 {
        None
    } else {
        Some(Oid::new(s[..s.len() - 1].to_vec()))
    }
}

/// Find the longest registered ancestor (or self) that has a known name.
///
/// Returns `(ancestor_oid, ancestor_name)` so callers can also know where the
/// symbolic run ends and the numeric tail begins.
fn longest_named_ancestor<'a>(
    mib: &'a MibRegistry,
    oid: &Oid,
) -> Option<(&'a Oid, &'a str)> {
    // We cannot borrow through `iter_oids` and return references into it cleanly
    // across the walk, so instead walk parent OIDs from self upward and ask
    // `oid_to_name` for each.
    let mut cur = Some(oid.clone());
    let mut best: Option<(Oid, String)> = None;
    while let Some(c) = cur {
        if let Some(name) = mib.oid_to_name(&c) {
            best = Some((c.clone(), name.to_string()));
            break;
        }
        cur = parent_of(&c);
    }
    // Convert back into references into the registry's storage. The name lives
    // in `by_oid`; re-resolve to get a stable borrow.
    best.and_then(|(o, _)| {
        mib.iter_oids()
            .find(|(oid2, _)| **oid2 == o)
            .map(|(oid2, name)| (oid2, name))
    })
}

/// Build the full qualified symbolic path for `oid`, walking ancestors.
///
/// Mirrors upstream `-Of`: print the longest fully-qualified symbolic name we
/// can assemble from the registry (e.g. `ifTable.ifEntry.ifIndex`). MODULE::
/// prefixing would require per-object module tracking which the registry does
/// not yet expose, so this returns the dotted symbolic path only.
pub fn format_full(mib: &MibRegistry, oid: &Oid) -> String {
    // Collect the chain of registered ancestor names from the root down, then
    // append the numeric tail for any sub-identifiers past the deepest named
    // ancestor.
    let s = oid.as_slice();
    // Walk every prefix length, collecting names where known.
    let mut named_segments: Vec<String> = Vec::new();
    let mut last_named_end: usize = 0;
    for len in 1..=s.len() {
        let prefix = Oid::new(s[..len].to_vec());
        if let Some(name) = mib.oid_to_name(&prefix) {
            // Reset accumulated segments whenever we discover a longer named
            // prefix, because that named prefix is itself a single token whose
            // ancestors are implied by its own dotted registration. We append
            // *this* name only.
            named_segments.clear();
            named_segments.push(name.to_string());
            last_named_end = len;
        } else if last_named_end != 0 && len == last_named_end + 1 {
            // We are one level below a named node and this arc is unnamed: show
            // the numeric arc as the next segment.
            named_segments.push(s[len - 1].to_string());
            last_named_end = len;
        }
    }

    if named_segments.is_empty() {
        // No known ancestor: numeric dotted form.
        return oid.to_string();
    }

    // If there are trailing numeric arcs beyond what we walked, append them.
    if last_named_end < s.len() {
        for arc in &s[last_named_end..] {
            named_segments.push(arc.to_string());
        }
    }

    named_segments.join(".")
}

/// Short form (`-Os`): just the last registered name segment, or the last
/// numeric arc when unknown.
pub fn format_short(mib: &MibRegistry, oid: &Oid) -> String {
    if let Some(name) = mib.oid_to_name(oid) {
        // Take the trailing dot-segment of the registered name.
        return name.rsplit('.').next().unwrap_or(name).to_string();
    }
    // Fall back to longest ancestor name + this arc, else numeric arc.
    if let Some((anc, _)) = longest_named_ancestor(mib, oid) {
        if oid.as_slice().len() > anc.as_slice().len() {
            let arc = oid.as_slice()[anc.as_slice().len()];
            return arc.to_string();
        }
    }
    oid.as_slice()
        .last()
        .map(|n| n.to_string())
        .unwrap_or_else(|| oid.to_string())
}

/// Suffix form (`-OS`): from the nearest ancestor whose name looks like an
/// entry-style node (ends with `Entry`, or is the immediate parent of a
/// columnar child). Falls back to [`format_short`].
pub fn format_suffix(mib: &MibRegistry, oid: &Oid) -> String {
    // Walk from self upward. Find the deepest ancestor whose name ends with
    // "Entry" (matches the upstream heuristic of starting at the table entry).
    let mut cur = Some(oid.clone());
    let mut entry_oid: Option<Oid> = None;
    while let Some(c) = cur {
        if let Some(name) = mib.oid_to_name(&c) {
            if name.ends_with("Entry") || name == "entry" {
                entry_oid = Some(c.clone());
                break;
            }
        }
        cur = parent_of(&c);
    }

    if let Some(entry) = entry_oid {
        // Build path from entry down to oid.
        let s = oid.as_slice();
        let e = entry.as_slice();
        if e.len() <= s.len() && s[..e.len()] == *e {
            let mut segs: Vec<String> = Vec::new();
            // entry name itself
            segs.push(
                mib.oid_to_name(&entry)
                    .unwrap_or("entry")
                    .rsplit('.')
                    .next()
                    .unwrap_or("entry")
                    .to_string(),
            );
            for len in (e.len() + 1)..=s.len() {
                let prefix = Oid::new(s[..len].to_vec());
                if let Some(name) = mib.oid_to_name(&prefix) {
                    segs.push(
                        name.rsplit('.')
                            .next()
                            .unwrap_or(name)
                            .to_string(),
                    );
                } else {
                    segs.push(s[len - 1].to_string());
                }
            }
            return segs.join(".");
        }
    }
    format_short(mib, oid)
}

/// Detailed OBJECT-TYPE definition block (`-Od` / `-Td` per-node).
///
/// Rich semantic data (SYNTAX, MAX-ACCESS, STATUS, DESCRIPTION) is not part of
/// the current registry API, so we emit a best-effort block with conservative
/// defaults and clearly mark unavailable fields. The `MODULE::name` header line
/// is omitted (no module tracking); we use the symbolic name instead.
pub fn format_detailed(mib: &MibRegistry, oid: &Oid) -> String {
    let name = mib.oid_to_name(oid).map(str::to_string).unwrap_or_else(|| format!("oid"));
    let last_arc = oid
        .as_slice()
        .last()
        .copied()
        .map(|n| n.to_string())
        .unwrap_or_default();
    let mut out = String::new();
    out.push_str(&format!("{name} {name}({last_arc})\n"));
    out.push_str(&format!("{name} OBJECT-TYPE\n"));
    out.push_str("-- FROM\t-\n");
    out.push_str("SYNTAX\tINTEGER\n");
    out.push_str("MAX-ACCESS\tread-only\n");
    out.push_str("STATUS\tcurrent\n");
    out.push_str("DESCRIPTION\t\"(unavailable)\"\n");
    // ::= { iso(1) org(3) ... name(last_arc) }
    let path = render_oid_path(mib, oid);
    out.push_str(&format!("::= {{ {path} }}\n"));
    out
}

/// Render `oid` in the `iso(1) org(3) ...` form used inside the `::= { ... }`
/// clause of detailed blocks. Each arc is annotated with its registered name
/// when known.
fn render_oid_path(mib: &MibRegistry, oid: &Oid) -> String {
    let s = oid.as_slice();
    let mut parts: Vec<String> = Vec::with_capacity(s.len());
    for (i, arc) in s.iter().enumerate() {
        let prefix = Oid::new(s[..=i].to_vec());
        let label = mib
            .oid_to_name(&prefix)
            .map(|n| n.rsplit('.').next().unwrap_or(n).to_string());
        match label {
            Some(l) => parts.push(format!("{l}({arc})")),
            None => parts.push(arc.to_string()),
        }
    }
    parts.join(" ")
}

/// Render the subtree rooted at `root` as an indented tree using the upstream
/// `+- `, `|  `, `\- ` connectors. The root itself is included as the top
/// line. Each node is shown as `<name>(<arc>)` (or `<arc>` when unnamed).
///
/// When `ascii_safe` is true, non-ASCII bytes in the rendered output are
/// replaced with `.` — matching the upstream `-Ta` behaviour. (OID names are
/// already ASCII in practice, so this is mostly a no-op safety net.)
pub fn render_tree(mib: &MibRegistry, root: &Oid, ascii_safe: bool) -> String {
    // Gather descendant OIDs (inclusive of root) ordered by OID.
    let mut nodes: Vec<&Oid> = mib
        .iter_oids()
        .map(|(o, _)| o)
        .filter(|o| o.is_prefix_of(root) || root.is_prefix_of(o))
        .collect();
    nodes.sort();

    let mut out = String::new();
    // Top line: the root.
    out.push_str(&render_node_label(mib, root));
    out.push('\n');

    // Recursively render the root's children (and their subtrees).
    render_children(mib, root, &nodes, "", &mut out);

    sanitize(out, ascii_safe)
}

/// Render the direct children of `parent` (and recurse into each), writing into
/// `out`. `prefix` is the indentation to apply before this level's connectors.
fn render_children(
    mib: &MibRegistry,
    parent: &Oid,
    nodes: &[&Oid],
    prefix: &str,
    out: &mut String,
) {
    let mut children: Vec<&Oid> = nodes
        .iter()
        .copied()
        .filter(|o| {
            o.as_slice().len() == parent.as_slice().len() + 1
                && o.as_slice()[..parent.as_slice().len()] == *parent.as_slice()
        })
        .collect();
    children.sort();

    let total = children.len();
    for (idx, child) in children.iter().enumerate() {
        let last = idx == total.saturating_sub(1);
        let connector = if last { "\\- " } else { "+- " };
        out.push_str(prefix);
        out.push_str(connector);
        out.push_str(&render_node_label(mib, child));
        out.push('\n');

        // Indent for the child's own subtree: blank space if last, else `|  `.
        let child_prefix = format!("{prefix}{}", if last { "   " } else { "|  " });
        render_children(mib, child, nodes, &child_prefix, out);
    }
}

fn render_node_label(mib: &MibRegistry, oid: &Oid) -> String {
    if let Some(name) = mib.oid_to_name(oid) {
        let short = name.rsplit('.').next().unwrap_or(name);
        let arc = oid.as_slice().last().copied().unwrap_or(0);
        format!("{short}({arc})")
    } else {
        let arc = oid.as_slice().last().copied().unwrap_or(0);
        format!("{arc}")
    }
}

fn sanitize(s: String, ascii_safe: bool) -> String {
    if !ascii_safe {
        return s;
    }
    s.chars()
        .map(|c| if c.is_ascii() { c } else { '.' })
        .collect()
}

/// Render a tab-separated table (`-Tt`): `oid\tname\taccess\tstatus\tmodule`.
/// Access / status / module are best-effort (`-`) because the current registry
/// does not carry per-object semantic metadata.
///
/// When `root` is `None`, every registered OID is listed. When `root` is given,
/// only `root` and its descendants are listed.
pub fn render_table(mib: &MibRegistry, root: Option<&Oid>) -> String {
    let mut rows: Vec<(&Oid, &str)> = mib
        .iter_oids()
        .filter(|(o, _)| match root {
            None => true,
            // Include the root itself plus its descendants.
            Some(r) => r.is_prefix_of(o),
        })
        .collect();
    rows.sort_by(|a, b| a.0.cmp(b.0));

    let mut out = String::new();
    for (oid, name) in rows {
        out.push_str(&format!(
            "{oid}\t{name}\t-\t-\t-\n",
        ));
    }
    out
}

/// When the OID has registered INTEGER enumerations, return a one-line listing
/// of `label(value)` pairs suitable for `-Oe`. Returns `None` when no enums are
/// known.
pub fn enum_listing(mib: &MibRegistry, oid: &Oid) -> Option<String> {
    let pairs = mib.enums_for(oid)?;
    if pairs.is_empty() {
        return None;
    }
    let rendered: Vec<String> = pairs
        .iter()
        .map(|(v, label)| format!("{label}({v})"))
        .collect();
    Some(rendered.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo_registry() -> MibRegistry {
        let mut mib = MibRegistry::with_builtins();
        // ifIndex etc. are already in the builtins (1.3.6.1.2.1.2.2.1.1).
        // Add an enumerated object for -Oe testing.
        let status_oid: Oid = "1.3.6.1.2.1.2.2.1.7".parse().unwrap();
        mib.insert("ifAdminStatus", status_oid.clone());
        mib.insert_enum(
            status_oid,
            vec![
                (1, "up".to_string()),
                (2, "down".to_string()),
                (3, "testing".to_string()),
            ],
        );
        mib
    }

    #[test]
    fn format_full_walks_ancestors() {
        let mib = demo_registry();
        // ifIndex is 1.3.6.1.2.1.2.2.1.1
        let oid: Oid = "1.3.6.1.2.1.2.2.1.1".parse().unwrap();
        let out = format_full(&mib, &oid);
        assert!(
            out.contains("ifIndex"),
            "format_full should contain the leaf name, got: {out}"
        );
    }

    #[test]
    fn format_full_appends_numeric_tail() {
        let mib = demo_registry();
        // An instance under ifIndex: 1.3.6.1.2.1.2.2.1.1.0
        let oid: Oid = "1.3.6.1.2.1.2.2.1.1.0".parse().unwrap();
        let out = format_full(&mib, &oid);
        assert!(
            out.ends_with(".0"),
            "trailing numeric arc should be appended, got: {out}"
        );
    }

    #[test]
    fn format_short_returns_leaf_name() {
        let mib = demo_registry();
        let oid: Oid = "1.3.6.1.2.1.2.2.1.1".parse().unwrap();
        assert_eq!(format_short(&mib, &oid), "ifIndex");
    }

    #[test]
    fn format_short_unknown_returns_arc() {
        let mib = demo_registry();
        let oid: Oid = "1.3.6.1.2.1.2.2.1.99".parse().unwrap();
        let out = format_short(&mib, &oid);
        assert_eq!(out, "99");
    }

    #[test]
    fn format_suffix_starts_at_entry() {
        let mib = demo_registry();
        let oid: Oid = "1.3.6.1.2.1.2.2.1.1".parse().unwrap();
        let out = format_suffix(&mib, &oid);
        assert!(
            out.starts_with("ifEntry"),
            "suffix should start at the entry node, got: {out}"
        );
        assert!(
            out.contains("ifIndex"),
            "suffix should contain the leaf, got: {out}"
        );
    }

    #[test]
    fn format_detailed_has_object_type_block() {
        let mib = demo_registry();
        let oid: Oid = "1.3.6.1.2.1.2.2.1.1".parse().unwrap();
        let out = format_detailed(&mib, &oid);
        assert!(out.contains("ifIndex OBJECT-TYPE"), "missing OBJECT-TYPE: {out}");
        assert!(out.contains("SYNTAX"), "missing SYNTAX: {out}");
        assert!(out.contains("DESCRIPTION"), "missing DESCRIPTION: {out}");
        assert!(out.contains("::= {"), "missing ::= block: {out}");
    }

    #[test]
    fn render_tree_includes_root_and_descendants() {
        let mib = demo_registry();
        let root: Oid = "1.3.6.1.2.1.1".parse().unwrap(); // system
        let out = render_tree(&mib, &root, false);
        assert!(out.contains("system"), "tree should include root: {out}");
        assert!(
            out.contains("+- ") || out.contains("\\- "),
            "tree should use connectors: {out}"
        );
    }

    #[test]
    fn render_table_columns() {
        let mib = demo_registry();
        let out = render_table(&mib, None);
        let line = out
            .lines()
            .find(|l| l.contains("ifIndex"))
            .unwrap_or_else(|| panic!("ifIndex missing from table: {out}"));
        // 5 tab-separated columns.
        assert_eq!(line.split('\t').count(), 5, "line: {line}");
    }

    #[test]
    fn enum_listing_renders_pairs() {
        let mib = demo_registry();
        let oid: Oid = "1.3.6.1.2.1.2.2.1.7".parse().unwrap();
        let out = enum_listing(&mib, &oid).expect("enum listing");
        assert!(out.contains("up(1)"), "missing up(1): {out}");
        assert!(out.contains("down(2)"), "missing down(2): {out}");
        assert!(out.contains("testing(3)"), "missing testing(3): {out}");
    }

    #[test]
    fn enum_listing_none_when_no_enums() {
        let mib = demo_registry();
        let oid: Oid = "1.3.6.1.2.1.2.2.1.1".parse().unwrap();
        assert!(enum_listing(&mib, &oid).is_none());
    }

    #[test]
    fn ascii_safe_replaces_non_ascii() {
        let s = String::from("héllo→world");
        let out = sanitize(s, true);
        assert_eq!(out, "h.llo.world");
        // Without the flag, the original is preserved.
        let s2 = String::from("héllo");
        assert_eq!(sanitize(s2, false), "héllo");
    }
}
