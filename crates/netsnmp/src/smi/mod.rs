//! SMIv1/SMIv2 MIB file parser.
//!
//! Rust counterpart of `snmplib/parse.c`. It reads MIB module text (the
//! `mibs/*.txt` files) and extracts the object tree: every labelled OID
//! assignment (`OBJECT IDENTIFIER`, `OBJECT-TYPE`, `MODULE-IDENTITY`,
//! `OBJECT-IDENTITY`, `NOTIFICATION-TYPE`, `OBJECT-GROUP`, …) together with
//! INTEGER enumerations used for symbolic value display.
//!
//! ## Design
//!
//! The parser is a three-stage pipeline, one stage per submodule:
//!
//! 1. [`lex`] turns text into a flat [`Tok`] stream ([`lex`](mod@self::lex)).
//! 2. [`parse_module`] scans the token stream for labelled definitions
//!    ([`parse`](mod@self::parse)).
//! 3. [`resolve`] performs a fixed-point cross-module name resolution pass,
//!    turning `{ mib-2 1 }` into a numeric OID even when `mib-2` is defined in
//!    another file ([`resolve`](mod@self::resolve)).

mod lex;
mod parse;
mod resolve;

use std::collections::HashMap;

use crate::oid::Oid;

pub use lex::{Tok, lex};
pub use parse::{
    Access, BaseType, Constraint, Index, ObjectDef, RawDef, Status, Syntax, TextualConvention,
    parse_constraint, parse_module, parse_object_defs, parse_object_defs_with_seeds,
    parse_textual_conventions,
};
pub use resolve::{MibObject, resolve, resolve_with_seeds};

/// Convenience: parse and resolve a single module's text.
pub fn parse_text(input: &str) -> Vec<MibObject> {
    resolve(parse_module(&lex(input)))
}

/// Parse and resolve module text, seeding with already-known names.
pub fn parse_text_with_seeds(input: &str, seeds: &HashMap<String, Oid>) -> Vec<MibObject> {
    resolve_with_seeds(parse_module(&lex(input)), seeds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lex_basic() {
        let toks = lex("org OBJECT IDENTIFIER ::= { iso 3 } -- comment\n");
        assert_eq!(toks[0], Tok::Ident("org".into()));
        assert!(toks.contains(&Tok::Assign));
        assert!(toks.contains(&Tok::LBrace));
        assert!(toks.contains(&Tok::Num(3)));
    }

    #[test]
    fn hyphenated_identifier_and_comment() {
        let toks = lex("mib-2 OBJECT IDENTIFIER ::= { mgmt 1 } --  x = 1\n");
        assert_eq!(toks[0], Tok::Ident("mib-2".into()));
    }

    #[test]
    fn resolve_chain() {
        let text = r#"
            Test DEFINITIONS ::= BEGIN
            org OBJECT IDENTIFIER ::= { iso 3 }
            dod OBJECT IDENTIFIER ::= { org 6 }
            internet OBJECT IDENTIFIER ::= { dod 1 }
            mgmt OBJECT IDENTIFIER ::= { internet 2 }
            mib-2 OBJECT IDENTIFIER ::= { mgmt 1 }
            END
        "#;
        let objs = parse_text(text);
        let mib2 = objs.iter().find(|o| o.name == "mib-2").unwrap();
        assert_eq!(mib2.oid.to_string(), ".1.3.6.1.2.1");
    }

    #[test]
    fn embedded_named_numbers() {
        let text = r#"
            Test DEFINITIONS ::= BEGIN
            internet OBJECT IDENTIFIER ::= { iso org(3) dod(6) 1 }
            END
        "#;
        let objs = parse_text(text);
        let internet = objs.iter().find(|o| o.name == "internet").unwrap();
        assert_eq!(internet.oid.to_string(), ".1.3.6.1");
    }

    #[test]
    fn object_type_with_enum() {
        let text = r#"
            Test DEFINITIONS ::= BEGIN
            ifEntry OBJECT IDENTIFIER ::= { iso 2 }
            ifOperStatus OBJECT-TYPE
                SYNTAX  INTEGER {
                    up(1),
                    down(2),
                    testing(3)
                }
                MAX-ACCESS  read-only
                STATUS      current
                DESCRIPTION "the status"
                ::= { ifEntry 8 }
            END
        "#;
        let objs = parse_text(text);
        let status = objs.iter().find(|o| o.name == "ifOperStatus").unwrap();
        assert_eq!(status.oid.to_string(), ".1.2.8");
        let enums = status.enums.as_ref().unwrap();
        assert_eq!(
            enums,
            &vec![
                (1, "up".to_string()),
                (2, "down".to_string()),
                (3, "testing".to_string())
            ]
        );
    }

    #[test]
    fn object_with_oid_syntax_is_not_mislabelled() {
        // Regression: `SYNTAX OBJECT IDENTIFIER` must not be taken as a label.
        let text = r#"
            Test DEFINITIONS ::= BEGIN
            system OBJECT IDENTIFIER ::= { iso 1 }
            sysObjectID OBJECT-TYPE
                SYNTAX      OBJECT IDENTIFIER
                MAX-ACCESS  read-only
                STATUS      current
                DESCRIPTION "vendor id"
                ::= { system 2 }
            END
        "#;
        let objs = parse_text(text);
        assert!(
            objs.iter()
                .any(|o| o.name == "sysObjectID" && o.oid.to_string() == ".1.1.2")
        );
        assert!(!objs.iter().any(|o| o.name == "SYNTAX"));
    }

    #[test]
    fn sequence_type_is_skipped() {
        let text = r#"
            Test DEFINITIONS ::= BEGIN
            ifTable OBJECT IDENTIFIER ::= { iso 2 }
            IfEntry ::= SEQUENCE { ifIndex INTEGER, ifDescr OCTET STRING }
            realThing OBJECT-TYPE
                SYNTAX IfEntry
                MAX-ACCESS not-accessible
                STATUS current
                DESCRIPTION "x"
                ::= { ifTable 1 }
            END
        "#;
        let objs = parse_text(text);
        assert!(!objs.iter().any(|o| o.name == "IfEntry"));
        assert!(
            objs.iter()
                .any(|o| o.name == "realThing" && o.oid.to_string() == ".1.2.1")
        );
    }
}
