//! Stage 2 of the MIB parser: scan the token stream for labelled definitions.
//!
//! The crucial observation is that an OID *value* is exactly the token pattern
//! `::=` immediately followed by `{`, which unambiguously separates OID
//! assignments from enumerations (`INTEGER { up(1) }`), SEQUENCE types
//! (`::= SEQUENCE { … }`) and `MACRO` bodies.

use super::lex::Tok;

/// A single component inside an OID value brace list.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Comp {
    /// A bare number, e.g. `1`.
    Number(u32),
    /// A symbolic parent name, e.g. `mib-2`.
    Name(String),
    /// A named number, e.g. `dod(6)`.
    Named(String, u32),
}

/// A raw, unresolved definition extracted from a module.
#[derive(Clone, Debug)]
pub struct RawDef {
    /// The object name (label).
    pub name: String,
    /// The OID value components (first may be symbolic).
    pub(super) spec: Vec<Comp>,
    /// Optional INTEGER enumeration (value → label).
    pub enums: Option<Vec<(i64, String)>>,
}

/// Keywords that follow a label and introduce a definition ending in `::= { oid }`.
const MACRO_KEYWORDS: &[&str] = &[
    "OBJECT-TYPE",
    "MODULE-IDENTITY",
    "OBJECT-IDENTITY",
    "NOTIFICATION-TYPE",
    "OBJECT-GROUP",
    "NOTIFICATION-GROUP",
    "MODULE-COMPLIANCE",
    "AGENT-CAPABILITIES",
];

/// Parse a token stream (one or more modules) into raw definitions.
pub fn parse_module(toks: &[Tok]) -> Vec<RawDef> {
    let mut defs = Vec::new();
    let mut i = 0;
    let n = toks.len();
    let mut current_label: Option<String> = None;
    // Enum captured for the current labelled definition, if any.
    let mut current_enum: Option<Vec<(i64, String)>> = None;

    while i < n {
        // Skip MACRO definitions entirely: `<name> MACRO ::= BEGIN ... END`.
        if let Tok::Ident(_) = &toks[i]
            && matches!(toks.get(i + 1), Some(Tok::Ident(k)) if k == "MACRO")
        {
            // advance to matching END
            i += 2;
            while i < n {
                if matches!(&toks[i], Tok::Ident(k) if k == "END") {
                    i += 1;
                    break;
                }
                i += 1;
            }
            current_label = None;
            current_enum = None;
            continue;
        }

        // (a) `<label> <MACRO-KEYWORD>` — start of a labelled macro definition.
        if let Tok::Ident(name) = &toks[i]
            && let Some(Tok::Ident(kw)) = toks.get(i + 1)
            && MACRO_KEYWORDS.contains(&kw.as_str())
        {
            current_label = Some(name.clone());
            current_enum = None;
            i += 2;
            continue;
        }

        // (b) Pure OID assignment: `<label> OBJECT IDENTIFIER ::= { ... }`.
        if let Tok::Ident(name) = &toks[i]
            && matches!(toks.get(i + 1), Some(Tok::Ident(k)) if k == "OBJECT")
            && matches!(toks.get(i + 2), Some(Tok::Ident(k)) if k == "IDENTIFIER")
            && matches!(toks.get(i + 3), Some(Tok::Assign))
            && matches!(toks.get(i + 4), Some(Tok::LBrace))
            && let Some((spec, next)) = parse_oid_body(toks, i + 5)
        {
            defs.push(RawDef {
                name: name.clone(),
                spec,
                enums: None,
            });
            i = next;
            current_label = None;
            current_enum = None;
            continue;
        }

        // Enum capture: a brace list whose entries are all `Ident ( Num )`.
        if matches!(&toks[i], Tok::LBrace)
            && current_label.is_some()
            && current_enum.is_none()
            && let Some((pairs, next)) = parse_enum_body(toks, i + 1)
        {
            current_enum = Some(pairs);
            i = next;
            continue;
        }

        // (a)-completion: the macro definition's value `::= { oid }`.
        if matches!(&toks[i], Tok::Assign) && matches!(toks.get(i + 1), Some(Tok::LBrace)) {
            if let Some(label) = current_label.take()
                && let Some((spec, next)) = parse_oid_body(toks, i + 2)
            {
                defs.push(RawDef {
                    name: label,
                    spec,
                    enums: current_enum.take(),
                });
                i = next;
                current_enum = None;
                continue;
            }
            current_enum = None;
        }

        i += 1;
    }

    defs
}

/// Parse an OID brace body starting just after `{`. Returns the components and
/// the index just past the closing `}`, or `None` if the body is not a valid
/// OID value (e.g. it contains commas — a SEQUENCE or OBJECTS list).
fn parse_oid_body(toks: &[Tok], mut i: usize) -> Option<(Vec<Comp>, usize)> {
    let mut comps = Vec::new();
    let n = toks.len();
    while i < n {
        match &toks[i] {
            Tok::RBrace => return Some((comps, i + 1)),
            Tok::Num(v) => {
                comps.push(Comp::Number((*v).max(0) as u32));
                i += 1;
            }
            Tok::Ident(name) => {
                // Possibly a named number: ident ( num )
                if matches!(toks.get(i + 1), Some(Tok::LParen))
                    && matches!(toks.get(i + 2), Some(Tok::Num(_)))
                    && matches!(toks.get(i + 3), Some(Tok::RParen))
                {
                    if let Some(Tok::Num(v)) = toks.get(i + 2) {
                        comps.push(Comp::Named(name.clone(), (*v).max(0) as u32));
                    }
                    i += 4;
                } else {
                    comps.push(Comp::Name(name.clone()));
                    i += 1;
                }
            }
            // Commas or other tokens mean this is not an OID value.
            _ => return None,
        }
    }
    None
}

/// Parse an enumeration body starting just after `{`. Succeeds only if every
/// comma-separated entry has the form `Ident ( Num )`. Returns the pairs and
/// the index past the closing `}`.
fn parse_enum_body(toks: &[Tok], mut i: usize) -> Option<(Vec<(i64, String)>, usize)> {
    let mut pairs = Vec::new();
    loop {
        // Expect: Ident ( Num )
        let name = match toks.get(i) {
            Some(Tok::Ident(s)) => s.clone(),
            _ => return None,
        };
        if !matches!(toks.get(i + 1), Some(Tok::LParen)) {
            return None;
        }
        let val = match toks.get(i + 2) {
            Some(Tok::Num(v)) => *v,
            _ => return None,
        };
        if !matches!(toks.get(i + 3), Some(Tok::RParen)) {
            return None;
        }
        pairs.push((val, name));
        i += 4;
        match toks.get(i) {
            Some(Tok::Comma) => i += 1,
            Some(Tok::RBrace) => return Some((pairs, i + 1)),
            _ => return None,
        }
    }
}

// ---------------------------------------------------------------------------
// Structured (semantic) MIB parsing — Task 5.17.
//
// `parse_module` above intentionally stays OID/enum-only so the existing
// fast path is untouched. The types and functions below add a *separate*,
// best-effort richer parse that extracts OBJECT-TYPE clauses (SYNTAX /
// UNITS / MAX-ACCESS / STATUS / DESCRIPTION / REFERENCE / INDEX / AUGMENTS
// / DEFVAL), TEXTUAL-CONVENTION macros, and SIZE/range constraints. They
// re-tokenize the input via [`crate::smi::lex`] (which now emits
// [`Tok::Str`] for quoted strings). Failures degrade gracefully: an
// unparseable clause leaves the corresponding field at its default rather
// than aborting the whole object.
// ---------------------------------------------------------------------------

use crate::oid::Oid;

/// SMI base (application/ASN.1 primitive) type for an OBJECT-TYPE SYNTAX.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BaseType {
    /// INTEGER / Integer32.
    #[default]
    Integer,
    /// OCTET STRING.
    OctetString,
    /// OBJECT IDENTIFIER.
    Oid,
    /// IpAddress.
    IpAddress,
    /// Counter32.
    Counter32,
    /// Gauge32.
    Gauge32,
    /// TimeTicks.
    TimeTicks,
    /// Opaque.
    Opaque,
    /// Counter64.
    Counter64,
    /// NULL.
    Null,
    /// Unsigned32 (alias of Gauge32).
    Unsigned32,
}

/// Parsed SYNTAX clause: a base type, a textual-convention reference, or a
/// `SEQUENCE OF <RowType>` (table) marker.
#[derive(Debug, Clone, PartialEq)]
pub enum Syntax {
    /// A base SMI type, optionally carrying a constraint.
    Base(BaseType, Option<Constraint>),
    /// A textual-convention / named type reference (e.g. `DisplayString`,
    /// `InterfaceIndex`), optionally with an inline constraint.
    Tc(String, Option<Constraint>),
    /// `SEQUENCE OF <RowType>` — a conceptual table.
    Sequence,
}

impl Default for Syntax {
    fn default() -> Self {
        Syntax::Base(BaseType::Integer, None)
    }
}

/// MAX-ACCESS / MIN-ACCESS value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Access {
    /// `not-accessible`.
    #[default]
    NotAccessible,
    /// `accessible-for-notify`.
    AccessibleForNotify,
    /// `read-only`.
    ReadOnly,
    /// `read-write`.
    ReadWrite,
    /// `read-create`.
    ReadCreate,
    /// `write-only` (SMIv1 legacy).
    WriteOnly,
}

/// STATUS value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Status {
    /// `current`.
    #[default]
    Current,
    /// `deprecated`.
    Deprecated,
    /// `obsolete`.
    Obsolete,
}

/// An INDEX/AUGMENTS clause for a conceptual row.
#[derive(Debug, Clone, PartialEq)]
pub enum Index {
    /// `INDEX { IMPLIED ident }`.
    Implied(String),
    /// `INDEX { a, b, c }`.
    Plain(Vec<String>),
    /// `AUGMENTS { entry }`.
    Augments(String),
}

/// A value range / SIZE constraint extracted from a SYNTAX clause.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Constraint {
    /// Integer subranges `(lower, upper)`; `None` means open-ended.
    pub ranges: Vec<(Option<i64>, Option<i64>)>,
    /// Octet-string `SIZE (a..b)` pairs (inclusive bounds).
    pub sizes: Vec<(usize, usize)>,
}

impl Constraint {
    /// True if the constraint carries any range or size restriction.
    pub fn has_any(&self) -> bool {
        !self.ranges.is_empty() || !self.sizes.is_empty()
    }

    /// Validate a signed integer against the range subranges, if any.
    pub fn check_int(&self, n: i64) -> bool {
        if self.ranges.is_empty() {
            return true;
        }
        self.ranges.iter().any(|(lo, hi)| {
            let ok_lo = lo.map_or(true, |l| n >= l);
            let ok_hi = hi.map_or(true, |h| n <= h);
            ok_lo && ok_hi
        })
    }

    /// Validate an octet-string length against the SIZE subranges, if any.
    pub fn check_size(&self, len: usize) -> bool {
        if self.sizes.is_empty() {
            return true;
        }
        self.sizes.iter().any(|(lo, hi)| len >= *lo && len <= *hi)
    }
}

/// Structured OBJECT-TYPE / OBJECT-IDENTITY / NOTIFICATION-TYPE definition.
#[derive(Debug, Clone, Default)]
pub struct ObjectDef {
    /// The object label.
    pub name: String,
    /// Numeric OID (may be empty if unresolvable from a single module).
    pub oid: Oid,
    /// Parsed SYNTAX.
    pub syntax: Syntax,
    /// `UNITS "..."`.
    pub units: Option<String>,
    /// MAX-ACCESS value.
    pub max_access: Access,
    /// STATUS value.
    pub status: Status,
    /// `DESCRIPTION "..."`.
    pub description: Option<String>,
    /// `REFERENCE "..."`.
    pub reference: Option<String>,
    /// INDEX / AUGMENTS clause, if any.
    pub index: Option<Index>,
    /// Raw inner text of `DEFVAL { ... }` (best-effort, unquoted).
    pub defval: Option<String>,
    /// INTEGER enumeration pairs captured from the SYNTAX, if any.
    pub enums: Vec<(i64, String)>,
    /// Defining module name, if known.
    pub module: Option<String>,
}

/// Parsed TEXTUAL-CONVENTION macro invocation.
#[derive(Debug, Clone, Default)]
pub struct TextualConvention {
    /// The TC name.
    pub name: String,
    /// Underlying SYNTAX (base type / TC reference + optional constraint).
    pub base: Syntax,
    /// `DISPLAY-HINT "..."`.
    pub display_hint: Option<String>,
    /// STATUS value.
    pub status: Status,
    /// `DESCRIPTION "..."`.
    pub description: Option<String>,
    /// `REFERENCE "..."`.
    pub reference: Option<String>,
}

/// Parse OBJECT-TYPE / OBJECT-IDENTITY / NOTIFICATION-TYPE definitions from
/// MIB module text. OIDs are best-effort: a symbolic parent that resolves to
/// a numeric arc within the same text (or one of the well-known roots) is
/// expanded; otherwise the OID is left empty. This never panics — unparseable
/// clauses are skipped, keeping the OID-only path authoritative.
pub fn parse_object_defs(text: &str) -> Vec<ObjectDef> {
    parse_object_defs_with_seeds(text, &std::collections::HashMap::new())
}

/// Like [`parse_object_defs`] but additionally resolves against a set of
/// already-known `name → OID` bindings (e.g. a [`crate::mib::MibRegistry`]'s
/// current names). This lets a module that anchors at `enterprises` /
/// `mib-2` resolve its object OIDs even when those roots are defined in a
/// different file and not present in `text`.
pub fn parse_object_defs_with_seeds(
    text: &str,
    seeds: &std::collections::HashMap<String, Oid>,
) -> Vec<ObjectDef> {
    let toks = super::lex::lex(text);
    let names = name_map(&toks);
    parse_object_defs_from_tokens(&toks, &names, seeds)
}

/// Parse TEXTUAL-CONVENTION macro invocations from MIB module text.
pub fn parse_textual_conventions(text: &str) -> Vec<TextualConvention> {
    let toks = super::lex::lex(text);
    parse_tc_from_tokens(&toks)
}

/// Parse a constraint from a SYNTAX fragment such as
/// `INTEGER (0..255)`, `Integer32 (1..2147483647)`, or
/// `OCTET STRING (SIZE (0..32))`. Returns `None` when no parenthesised
/// constraint is present.
pub fn parse_constraint(syntax_text: &str) -> Option<Constraint> {
    let toks = super::lex::lex(syntax_text);
    let lparen_idx = toks.iter().position(|t| matches!(t, Tok::LParen))?;
    parse_constraint_tokens(&toks, lparen_idx).map(|(c, _)| c)
}

// -- helpers ---------------------------------------------------------------

/// Build a name→spec index from `OBJECT IDENTIFIER` / macro assignments so a
/// per-object parent like `ifEntry` can be resolved inline. This is a
/// lightweight single-pass scan reusing the OID-body logic.
fn name_map(toks: &[Tok]) -> std::collections::HashMap<String, Vec<Comp>> {
    let mut map = std::collections::HashMap::new();
    let mut i = 0;
    let n = toks.len();
    let mut current_label: Option<String> = None;
    while i < n {
        if let Tok::Ident(_) = &toks[i]
            && matches!(toks.get(i + 1), Some(Tok::Ident(k)) if k == "MACRO")
        {
            i += 2;
            while i < n {
                if matches!(&toks[i], Tok::Ident(k) if k == "END") {
                    i += 1;
                    break;
                }
                i += 1;
            }
            current_label = None;
            continue;
        }
        if let Tok::Ident(name) = &toks[i]
            && let Some(Tok::Ident(kw)) = toks.get(i + 1)
            && MACRO_KEYWORDS.contains(&kw.as_str())
        {
            current_label = Some(name.clone());
            i += 2;
            continue;
        }
        if let Tok::Ident(name) = &toks[i]
            && matches!(toks.get(i + 1), Some(Tok::Ident(k)) if k == "OBJECT")
            && matches!(toks.get(i + 2), Some(Tok::Ident(k)) if k == "IDENTIFIER")
            && matches!(toks.get(i + 3), Some(Tok::Assign))
            && matches!(toks.get(i + 4), Some(Tok::LBrace))
            && let Some((spec, next)) = parse_oid_body(toks, i + 5)
        {
            map.entry(name.clone()).or_insert(spec);
            i = next;
            current_label = None;
            continue;
        }
        if matches!(&toks[i], Tok::Assign) && matches!(toks.get(i + 1), Some(Tok::LBrace)) {
            if let Some(label) = current_label.take()
                && let Some((spec, next)) = parse_oid_body(toks, i + 2)
            {
                map.entry(label).or_insert(spec);
                i = next;
                continue;
            }
        }
        i += 1;
    }
    map
}

/// Resolve a spec (`{ parent n }`) into a numeric OID using `names`, the
/// well-known roots, and any caller-supplied `seeds`.
fn resolve_inline(
    spec: &[Comp],
    names: &std::collections::HashMap<String, Vec<Comp>>,
    seeds: &std::collections::HashMap<String, Oid>,
) -> Option<Oid> {
    let iso = vec![Comp::Number(1)];
    let well_known = |n: &str| -> Option<Vec<Comp>> {
        match n {
            "iso" => Some(iso.clone()),
            "ccitt" | "itu" | "itu-t" => Some(vec![Comp::Number(0)]),
            "joint-iso-ccitt" | "joint-iso-itu-t" => Some(vec![Comp::Number(2)]),
            _ => None,
        }
    };
    let resolve_head = |name: &str| -> Option<Oid> {
        names
            .get(name)
            .and_then(|s| resolve_inline(s, names, seeds))
            .or_else(|| well_known(name).and_then(|s| resolve_inline(&s, names, seeds)))
            .or_else(|| seeds.get(name).cloned())
    };
    let mut parts: Vec<u32> = Vec::new();
    for (idx, comp) in spec.iter().enumerate() {
        match comp {
            Comp::Number(v) => parts.push(*v),
            Comp::Named(name, v) => {
                if idx == 0 {
                    if let Some(base) = resolve_head(name) {
                        parts.extend_from_slice(base.as_slice());
                    } else {
                        parts.push(*v);
                    }
                } else {
                    parts.push(*v);
                }
            }
            Comp::Name(name) => {
                if idx == 0 {
                    let base = resolve_head(name)?;
                    parts.extend_from_slice(base.as_slice());
                } else {
                    return None;
                }
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(Oid::new(parts))
    }
}

/// Tokenise-and-parse OBJECT-TYPE definitions.
fn parse_object_defs_from_tokens(
    toks: &[Tok],
    names: &std::collections::HashMap<String, Vec<Comp>>,
    seeds: &std::collections::HashMap<String, Oid>,
) -> Vec<ObjectDef> {
    let mut defs = Vec::new();
    let mut i = 0;
    let n = toks.len();

    while i < n {
        if let Tok::Ident(_) = &toks[i]
            && matches!(toks.get(i + 1), Some(Tok::Ident(k)) if k == "MACRO")
        {
            i += 2;
            while i < n {
                if matches!(&toks[i], Tok::Ident(k) if k == "END") {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }

        if let Tok::Ident(name) = &toks[i]
            && let Some(Tok::Ident(kw)) = toks.get(i + 1)
            && matches!(kw.as_str(), "OBJECT-TYPE" | "OBJECT-IDENTITY" | "NOTIFICATION-TYPE")
        {
            let body_start = i + 2;
            if let Some(def) = parse_one_object_def(toks, body_start, name, names, seeds) {
                defs.push(def);
            }
            if let Some((_, next)) = find_oid_assignment(toks, body_start) {
                i = next;
            } else {
                i += 2;
            }
            continue;
        }

        i += 1;
    }

    defs
}

/// Locate the `::= { ... }` that terminates an OBJECT-TYPE body, returning
/// the resolved spec and the index just past the closing brace.
fn find_oid_assignment(toks: &[Tok], from: usize) -> Option<(Vec<Comp>, usize)> {
    let n = toks.len();
    let mut i = from;
    let mut depth = 0i32;
    while i < n {
        match &toks[i] {
            Tok::Assign if depth == 0 => {
                if matches!(toks.get(i + 1), Some(Tok::LBrace))
                    && let Some((spec, next)) = parse_oid_body(toks, i + 2)
                {
                    return Some((spec, next));
                }
            }
            Tok::LBrace => depth += 1,
            Tok::RBrace => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    None
}

/// Parse a single OBJECT-TYPE body (clauses) starting at `body_start`.
fn parse_one_object_def(
    toks: &[Tok],
    body_start: usize,
    name: &str,
    names: &std::collections::HashMap<String, Vec<Comp>>,
    seeds: &std::collections::HashMap<String, Oid>,
) -> Option<ObjectDef> {
    let (spec, _next) = find_oid_assignment(toks, body_start)?;
    let oid = resolve_inline(&spec, names, seeds).unwrap_or_default();

    let mut def = ObjectDef {
        name: name.to_string(),
        oid,
        ..Default::default()
    };

    let mut i = body_start;
    let n = toks.len();
    while i < n {
        match &toks[i] {
            Tok::Assign => break,
            Tok::Ident(kw) => {
                let k = kw.as_str();
                if k.eq_ignore_ascii_case("SYNTAX") {
                    if let Some((syntax, enums, next)) = parse_syntax(toks, i + 1) {
                        def.syntax = syntax;
                        if !enums.is_empty() {
                            def.enums = enums;
                        }
                        i = next;
                        continue;
                    }
                } else if k.eq_ignore_ascii_case("UNITS") {
                    if let Some(Tok::Str(s)) = toks.get(i + 1) {
                        def.units = Some(s.clone());
                        i += 2;
                        continue;
                    }
                } else if k.eq_ignore_ascii_case("MAX-ACCESS")
                    || k.eq_ignore_ascii_case("ACCESS")
                {
                    if let Some(Tok::Ident(a)) = toks.get(i + 1) {
                        def.max_access = parse_access(a);
                        i += 2;
                        continue;
                    }
                } else if k.eq_ignore_ascii_case("MIN-ACCESS") {
                    if def.max_access == Access::default()
                        && let Some(Tok::Ident(a)) = toks.get(i + 1)
                    {
                        def.max_access = parse_access(a);
                        i += 2;
                        continue;
                    }
                } else if k.eq_ignore_ascii_case("STATUS") {
                    if let Some(Tok::Ident(s)) = toks.get(i + 1) {
                        def.status = parse_status(s);
                        i += 2;
                        continue;
                    }
                } else if k.eq_ignore_ascii_case("DESCRIPTION") {
                    if let Some(Tok::Str(s)) = toks.get(i + 1) {
                        def.description = Some(s.clone());
                        i += 2;
                        continue;
                    }
                } else if k.eq_ignore_ascii_case("REFERENCE") {
                    if let Some(Tok::Str(s)) = toks.get(i + 1) {
                        def.reference = Some(s.clone());
                        i += 2;
                        continue;
                    }
                } else if k.eq_ignore_ascii_case("INDEX") {
                    if let Some(idx) = parse_index(toks, i + 1) {
                        def.index = Some(idx);
                    }
                } else if k.eq_ignore_ascii_case("AUGMENTS") {
                    if let Some(entry) = parse_augments(toks, i + 1) {
                        def.index = Some(Index::Augments(entry));
                    }
                } else if k.eq_ignore_ascii_case("DEFVAL") {
                    if let Some(raw) = parse_defval(toks, i + 1) {
                        def.defval = Some(raw);
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }

    Some(def)
}

/// Parse a SYNTAX clause. Returns `(syntax, enums, next_index)`.
fn parse_syntax(
    toks: &[Tok],
    start: usize,
) -> Option<(Syntax, Vec<(i64, String)>, usize)> {
    let n = toks.len();
    let mut i = start;

    if matches!(toks.get(i), Some(Tok::Ident(s)) if s.eq_ignore_ascii_case("SEQUENCE"))
        && matches!(toks.get(i + 1), Some(Tok::Ident(s)) if s.eq_ignore_ascii_case("OF"))
    {
        return Some((Syntax::Sequence, Vec::new(), i + 4));
    }
    if matches!(toks.get(i), Some(Tok::Ident(s)) if s.eq_ignore_ascii_case("SEQUENCE"))
        && matches!(toks.get(i + 1), Some(Tok::LBrace))
    {
        let mut depth = 1;
        let mut j = i + 2;
        while j < n && depth > 0 {
            match &toks[j] {
                Tok::LBrace => depth += 1,
                Tok::RBrace => depth -= 1,
                _ => {}
            }
            j += 1;
        }
        return Some((Syntax::Sequence, Vec::new(), j));
    }

    let (base_or_tc, advance) = match toks.get(i)? {
        Tok::Ident(name) => {
            let lower = name.to_ascii_lowercase();
            if name.eq_ignore_ascii_case("OCTET")
                && matches!(toks.get(i + 1), Some(Tok::Ident(s)) if s.eq_ignore_ascii_case("STRING"))
            {
                (BaseOrTc::Base(BaseType::OctetString), 2)
            } else if name.eq_ignore_ascii_case("OBJECT")
                && matches!(toks.get(i + 1), Some(Tok::Ident(s)) if s.eq_ignore_ascii_case("IDENTIFIER"))
            {
                (BaseOrTc::Base(BaseType::Oid), 2)
            } else if let Some(bt) = match_base_type(&lower) {
                (BaseOrTc::Base(bt), 1)
            } else {
                (BaseOrTc::Tc(name.clone()), 1)
            }
        }
        _ => return None,
    };
    i += advance;

    let mut enums = Vec::new();
    if matches!(toks.get(i), Some(Tok::LBrace))
        && let Some((pairs, next)) = parse_enum_body(toks, i + 1)
    {
        enums = pairs;
        i = next;
    }

    let mut constraint = None;
    if matches!(toks.get(i), Some(Tok::LParen))
        && let Some((c, next)) = parse_constraint_tokens(toks, i)
    {
        constraint = Some(c);
        i = next;
    }

    let syntax = match base_or_tc {
        BaseOrTc::Base(bt) => Syntax::Base(bt, constraint),
        BaseOrTc::Tc(name) => Syntax::Tc(name, constraint),
    };
    Some((syntax, enums, i))
}

#[derive(Debug)]
enum BaseOrTc {
    Base(BaseType),
    Tc(String),
}

/// Map a single lower-cased type keyword to a [`BaseType`], if recognised.
fn match_base_type(lower: &str) -> Option<BaseType> {
    match lower {
        "integer" | "integer32" => Some(BaseType::Integer),
        "octet" => Some(BaseType::OctetString),
        "object" => Some(BaseType::Oid),
        "ipaddress" => Some(BaseType::IpAddress),
        "counter32" => Some(BaseType::Counter32),
        "gauge32" | "gauge" => Some(BaseType::Gauge32),
        "timeticks" => Some(BaseType::TimeTicks),
        "opaque" => Some(BaseType::Opaque),
        "counter64" => Some(BaseType::Counter64),
        "unsigned32" => Some(BaseType::Unsigned32),
        "null" => Some(BaseType::Null),
        "networkaddress" => Some(BaseType::Oid),
        _ => None,
    }
}

/// Parse an ACCESS/MAX-ACCESS keyword.
fn parse_access(s: &str) -> Access {
    match s.to_ascii_lowercase().as_str() {
        "not-accessible" | "notaccessible" => Access::NotAccessible,
        "accessible-for-notify" | "accessiblefornotify" => Access::AccessibleForNotify,
        "read-only" | "readonly" => Access::ReadOnly,
        "read-write" | "readwrite" => Access::ReadWrite,
        "read-create" | "readcreate" => Access::ReadCreate,
        "write-only" | "writeonly" => Access::WriteOnly,
        _ => Access::default(),
    }
}

/// Parse a STATUS keyword.
fn parse_status(s: &str) -> Status {
    match s.to_ascii_lowercase().as_str() {
        "current" => Status::Current,
        "deprecated" => Status::Deprecated,
        "obsolete" => Status::Obsolete,
        _ => Status::default(),
    }
}

/// Parse `INDEX { ... }` starting at the token after `INDEX`.
fn parse_index(toks: &[Tok], start: usize) -> Option<Index> {
    if !matches!(toks.get(start), Some(Tok::LBrace)) {
        return None;
    }
    let mut idents: Vec<String> = Vec::new();
    let mut implied = false;
    let mut j = start + 1;
    loop {
        match toks.get(j) {
            Some(Tok::Ident(s)) => {
                if s.eq_ignore_ascii_case("IMPLIED") && idents.is_empty() && !implied {
                    implied = true;
                    j += 1;
                    continue;
                }
                idents.push(s.clone());
                j += 1;
            }
            Some(Tok::Comma) => j += 1,
            Some(Tok::RBrace) => break,
            _ => return None,
        }
    }
    if implied {
        if let Some(last) = idents.last().cloned() {
            return Some(Index::Implied(last));
        }
    }
    Some(Index::Plain(idents))
}

/// Parse `AUGMENTS { entry }` starting at the token after `AUGMENTS`.
fn parse_augments(toks: &[Tok], start: usize) -> Option<String> {
    if !matches!(toks.get(start), Some(Tok::LBrace)) {
        return None;
    }
    let entry = match toks.get(start + 1) {
        Some(Tok::Ident(s)) => s.clone(),
        _ => return None,
    };
    if !matches!(toks.get(start + 2), Some(Tok::RBrace)) {
        return None;
    }
    Some(entry)
}

/// Parse `DEFVAL { ... }` returning the raw inner text (best-effort).
fn parse_defval(toks: &[Tok], start: usize) -> Option<String> {
    if !matches!(toks.get(start), Some(Tok::LBrace)) {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    let mut depth = 1;
    let mut j = start + 1;
    while depth > 0 {
        match toks.get(j)? {
            Tok::LBrace => {
                depth += 1;
                parts.push("{".to_string());
            }
            Tok::RBrace => {
                depth -= 1;
                if depth > 0 {
                    parts.push("}".to_string());
                }
            }
            Tok::Str(s) => parts.push(format!("\"{s}\"")),
            Tok::Num(n) => parts.push(n.to_string()),
            Tok::Ident(s) => parts.push(s.clone()),
            Tok::Comma => parts.push(",".to_string()),
            _ => {}
        }
        j += 1;
    }
    Some(parts.join(" "))
}

/// Parse a parenthesised constraint starting at the `(`. Handles both
/// integer ranges `(0..255)` / `(0..65535 | 1000000..)` and
/// `SIZE (0..32)` forms. Accepts alternation with `|`.
fn parse_constraint_tokens(toks: &[Tok], lparen_idx: usize) -> Option<(Constraint, usize)> {
    let mut c = Constraint::default();
    let mut i = lparen_idx;
    if !matches!(toks.get(i), Some(Tok::LParen)) {
        return None;
    }
    i += 1;

    let mut is_size = false;
    if matches!(toks.get(i), Some(Tok::Ident(s)) if s.eq_ignore_ascii_case("SIZE")) {
        is_size = true;
        i += 1;
        if !matches!(toks.get(i), Some(Tok::LParen)) {
            return None;
        }
        i += 1;
    }

    loop {
        let (lo, hi, next) = parse_range(toks, i)?;
        if is_size {
            let l = lo.unwrap_or(0).max(0) as usize;
            let h = hi.unwrap_or(0).max(l as i64) as usize;
            c.sizes.push((l, h));
        } else {
            c.ranges.push((lo, hi));
        }
        i = next;
        match toks.get(i) {
            Some(Tok::Pipe) => i += 1,
            Some(Tok::RParen) => {
                i += 1;
                break;
            }
            _ => return None,
        }
    }
    if !c.has_any() {
        None
    } else {
        Some((c, i))
    }
}

/// Parse one `(lo..hi)` or `(n)` subrange. Returns `(lo, hi, next)`.
fn parse_range(toks: &[Tok], i: usize) -> Option<(Option<i64>, Option<i64>, usize)> {
    if let Some(Tok::Num(n)) = toks.get(i)
        && !matches!(toks.get(i + 1), Some(Tok::DotDot))
    {
        return Some((Some(*n), Some(*n), i + 1));
    }
    let (lo, after_lo) = match toks.get(i) {
        Some(Tok::Num(n)) => (Some(*n), i + 1),
        Some(Tok::Ident(s)) if s == "MIN" => (None, i + 1),
        _ => return None,
    };
    if !matches!(toks.get(after_lo), Some(Tok::DotDot)) {
        return None;
    }
    let after_dots = after_lo + 1;
    let (hi, after_hi) = match toks.get(after_dots) {
        Some(Tok::Num(n)) => (Some(*n), after_dots + 1),
        Some(Tok::Ident(s)) if s == "MAX" => (None, after_dots + 1),
        _ => return None,
    };
    Some((lo, hi, after_hi))
}

// -- TEXTUAL-CONVENTION parsing --------------------------------------------

fn parse_tc_from_tokens(toks: &[Tok]) -> Vec<TextualConvention> {
    let mut out = Vec::new();
    let mut i = 0;
    let n = toks.len();
    while i < n {
        if let Tok::Ident(name) = &toks[i] {
            let tc_idx = if matches!(toks.get(i + 1), Some(Tok::Assign))
                && matches!(toks.get(i + 2), Some(Tok::Ident(k)) if k.eq_ignore_ascii_case("TEXTUAL-CONVENTION"))
            {
                Some(i + 3)
            } else if matches!(toks.get(i + 1), Some(Tok::Ident(k)) if k.eq_ignore_ascii_case("TEXTUAL-CONVENTION"))
            {
                Some(i + 2)
            } else {
                None
            };
            if let Some(body_start) = tc_idx {
                if let Some(tc) = parse_one_tc(toks, body_start, name) {
                    out.push(tc);
                }
                i = skip_to_syntax_end(toks, body_start);
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Parse a single TEXTUAL-CONVENTION body up to and including its SYNTAX.
fn parse_one_tc(toks: &[Tok], body_start: usize, name: &str) -> Option<TextualConvention> {
    let mut tc = TextualConvention {
        name: name.to_string(),
        ..Default::default()
    };
    let n = toks.len();
    let mut i = body_start;
    let mut syntax_done = false;
    while i < n {
        match &toks[i] {
            Tok::Ident(kw) if kw.eq_ignore_ascii_case("DISPLAY-HINT") => {
                if let Some(Tok::Str(s)) = toks.get(i + 1) {
                    tc.display_hint = Some(s.clone());
                    i += 2;
                    continue;
                }
            }
            Tok::Ident(kw) if kw.eq_ignore_ascii_case("STATUS") => {
                if let Some(Tok::Ident(s)) = toks.get(i + 1) {
                    tc.status = parse_status(s);
                    i += 2;
                    continue;
                }
            }
            Tok::Ident(kw) if kw.eq_ignore_ascii_case("DESCRIPTION") => {
                if let Some(Tok::Str(s)) = toks.get(i + 1) {
                    tc.description = Some(s.clone());
                    i += 2;
                    continue;
                }
            }
            Tok::Ident(kw) if kw.eq_ignore_ascii_case("REFERENCE") => {
                if let Some(Tok::Str(s)) = toks.get(i + 1) {
                    tc.reference = Some(s.clone());
                    i += 2;
                    continue;
                }
            }
            Tok::Ident(kw) if kw.eq_ignore_ascii_case("SYNTAX") => {
                if let Some((syntax, _enums, next)) = parse_syntax(toks, i + 1) {
                    tc.base = syntax;
                    i = next;
                    syntax_done = true;
                    continue;
                }
            }
            _ => {}
        }
        if syntax_done {
            break;
        }
        i += 1;
    }
    Some(tc)
}

/// Return the index just past the end of the current TC's SYNTAX clause.
fn skip_to_syntax_end(toks: &[Tok], from: usize) -> usize {
    let n = toks.len();
    let mut i = from;
    while i < n {
        if let Tok::Ident(kw) = &toks[i]
            && kw.eq_ignore_ascii_case("SYNTAX")
            && let Some((_, _, next)) = parse_syntax(toks, i + 1)
        {
            return next;
        }
        if matches!(&toks[i], Tok::Assign) {
            return i + 1;
        }
        i += 1;
    }
    n
}

#[cfg(test)]
mod semantic_tests {
    use super::*;

    const IFADMIN_SNIPPET: &str = r#"
        IF-MIB DEFINITIONS ::= BEGIN
        ifEntry OBJECT IDENTIFIER ::= { iso 2 }
        ifAdminStatus OBJECT-TYPE
            SYNTAX  INTEGER {
                        up(1),
                        down(2),
                        testing(3)
                    }
            MAX-ACCESS  read-write
            STATUS      current
            DESCRIPTION "The desired state of the interface."
            ::= { ifEntry 7 }
        END
    "#;

    #[test]
    fn parses_if_admin_status() {
        let defs = parse_object_defs(IFADMIN_SNIPPET);
        let admin = defs.iter().find(|d| d.name == "ifAdminStatus").unwrap();
        assert_eq!(admin.oid.to_string(), ".1.2.7");
        assert_eq!(admin.max_access, Access::ReadWrite);
        assert_eq!(admin.status, Status::Current);
        assert_eq!(
            admin.enums,
            vec![
                (1, "up".to_string()),
                (2, "down".to_string()),
                (3, "testing".to_string()),
            ]
        );
        assert!(matches!(
            &admin.syntax,
            Syntax::Base(BaseType::Integer, None)
        ));
        assert_eq!(
            admin.description.as_deref(),
            Some("The desired state of the interface.")
        );
    }

    const IFINDEX_SNIPPET: &str = r#"
        IF-MIB DEFINITIONS ::= BEGIN
        ifEntry OBJECT IDENTIFIER ::= { iso 2 }
        ifIndex OBJECT-TYPE
            SYNTAX      InterfaceIndex
            MAX-ACCESS  read-only
            STATUS      current
            DESCRIPTION "A unique value, greater than zero."
            ::= { ifEntry 1 }
        END
    "#;

    #[test]
    fn parses_if_index_read_only_with_tc() {
        let defs = parse_object_defs(IFINDEX_SNIPPET);
        let idx = defs.iter().find(|d| d.name == "ifIndex").unwrap();
        assert_eq!(idx.oid.to_string(), ".1.2.1");
        assert_eq!(idx.max_access, Access::ReadOnly);
        assert_eq!(idx.status, Status::Current);
        assert!(matches!(
            &idx.syntax,
            Syntax::Tc(name, None) if name == "InterfaceIndex"
        ));
    }

    const DISPLAY_STRING_SNIPPET: &str = r#"
        SNMPv2-TC DEFINITIONS ::= BEGIN
        DisplayString ::= TEXTUAL-CONVENTION
            DISPLAY-HINT "255a"
            STATUS       current
            DESCRIPTION  " textual info "
            SYNTAX       OCTET STRING (SIZE (0..255))
        END
    "#;

    #[test]
    fn parses_display_string_tc() {
        let tcs = parse_textual_conventions(DISPLAY_STRING_SNIPPET);
        let ds = tcs.iter().find(|t| t.name == "DisplayString").unwrap();
        assert_eq!(ds.display_hint.as_deref(), Some("255a"));
        assert_eq!(ds.status, Status::Current);
        match &ds.base {
            Syntax::Base(BaseType::OctetString, Some(c)) => {
                assert_eq!(c.sizes, vec![(0, 255)]);
            }
            other => panic!("unexpected base {other:?}"),
        }
    }

    #[test]
    fn constraint_integer_range() {
        let c = parse_constraint("INTEGER (0..255)").expect("some constraint");
        assert_eq!(c.ranges, vec![(Some(0), Some(255))]);
        assert!(c.check_int(0));
        assert!(c.check_int(255));
        assert!(!c.check_int(256));
        assert!(!c.check_int(-1));
    }

    #[test]
    fn constraint_octet_size() {
        let c = parse_constraint("OCTET STRING (SIZE (0..32))").expect("some constraint");
        assert_eq!(c.sizes, vec![(0, 32)]);
        assert!(c.check_size(0));
        assert!(c.check_size(32));
        assert!(!c.check_size(33));
    }

    #[test]
    fn constraint_fixed_size() {
        let c = parse_constraint("OCTET STRING (SIZE (6))").expect("some constraint");
        assert_eq!(c.sizes, vec![(6, 6)]);
        assert!(c.check_size(6));
        assert!(!c.check_size(5));
    }

    #[test]
    fn constraint_none_when_absent() {
        assert!(parse_constraint("INTEGER").is_none());
        assert!(parse_constraint("OCTET STRING").is_none());
    }

    #[test]
    fn index_plain_and_augments() {
        let text = r#"
            DEMO DEFINITIONS ::= BEGIN
            baseEntry OBJECT-TYPE
                SYNTAX RowType
                MAX-ACCESS not-accessible
                STATUS current
                DESCRIPTION "x"
                INDEX { ifIndex }
                ::= { iso 1 }
            augEntry OBJECT-TYPE
                SYNTAX RowType
                MAX-ACCESS not-accessible
                STATUS current
                DESCRIPTION "x"
                AUGMENTS { ifEntry }
                ::= { iso 2 }
            END
        "#;
        let defs = parse_object_defs(text);
        let base = defs.iter().find(|d| d.name == "baseEntry").unwrap();
        assert_eq!(
            base.index.as_ref().unwrap(),
            &Index::Plain(vec!["ifIndex".into()])
        );
        let aug = defs.iter().find(|d| d.name == "augEntry").unwrap();
        assert_eq!(
            aug.index.as_ref().unwrap(),
            &Index::Augments("ifEntry".into())
        );
    }

    #[test]
    fn defval_is_captured() {
        let text = r#"
            DEMO DEFINITIONS ::= BEGIN
            obj OBJECT-TYPE
                SYNTAX INTEGER { volatile(2) }
                MAX-ACCESS read-create
                STATUS current
                DESCRIPTION "x"
                DEFVAL { volatile }
                ::= { iso 1 }
            END
        "#;
        let defs = parse_object_defs(text);
        let obj = defs.iter().find(|d| d.name == "obj").unwrap();
        assert_eq!(obj.defval.as_deref(), Some("volatile"));
    }

    #[test]
    fn quoted_string_escape_decoded() {
        let toks = super::super::lex::lex(r#"x "a ""b" c""#);
        let s = toks
            .iter()
            .find_map(|t| match t {
                Tok::Str(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(s, r#"a "b"#);
    }
}
