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
