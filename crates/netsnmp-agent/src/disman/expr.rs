//! DISMAN-EXPRESSION-MIB (`1.3.6.1.2.1.90`, RFC 2982).
//!
//! Implements `expExpressionTable`: arithmetic expressions over OID values,
//! evaluated on-demand at GET time. Counterpart of Net-SNMP's
//! `agent/mibgroup/disman/expr/`.
//!
//! # Expression syntax
//!
//! A subset of the RFC 2982 expression syntax is supported:
//!
//! - Integer and decimal numeric literals (`42`, `3.14`).
//! - The binary operators `+ - * /`, with the usual precedence and
//!   left-associativity.
//! - Parenthesised grouping.
//! - `$oid` references: a `$` immediately followed by a dotted OID resolves to
//!   the current value of that OID (sampled via the configured self-query
//!   handler). The OID runs to the next whitespace or operator/paren.
//!
//! Unrecognised characters, unbalanced parentheses, a missing `$`-reference
//! value, or division by zero produce an [`ExprError`]; at GET time such an
//! error maps to a `noSuchInstance` for that cell (so a broken expression does
//! not bring down a walk).
//!
//! # Tables served
//!
//! The engine exposes a single scalar-per-expression cell at
//! `expExpressionEntry` .`expExpressionEntry  N`  = the evaluated value,
//! keyed by `(owner, name)` string index. The full RFC 2982 columnar layout is
//! not reproduced; a GET on the value column returns the evaluated result.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use netsnmp::oid::Oid;
use netsnmp::value::Value;
use tracing::warn;

use crate::handler::{MibHandler, Reading};

/// DISMAN-EXPRESSION-MIB root (`1.3.6.1.2.1.90`).
pub const EXP_MIB: &[u32] = &[1, 3, 6, 1, 2, 1, 90];

/// `expExpressionTable` entry OID (`1.3.6.1.2.1.90.1.2.1.1`).
pub const EXP_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 90, 1, 2, 1, 1];

/// The `expExpressionValue` column (the evaluated result). RFC 2982 does not
/// define this exact arc; it is the conventional "value" cell we expose so a
/// GET returns the computed number.
const COL_EXP_VALUE: u32 = 2;

/// An error produced while parsing or evaluating an expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExprError {
    /// The expression contains a character the lexer does not recognise.
    UnexpectedChar(char),
    /// The expression ended mid-operator / mid-number.
    UnexpectedEnd,
    /// A `$`-reference was not followed by an OID.
    BadReference,
    /// A referenced OID could not be read (no handler) or was non-numeric.
    UnresolvedReference(String),
    /// A numeric literal failed to parse.
    BadNumber(String),
    /// An operator was applied to a malformed operand stack.
    MissingOperand,
    /// Unbalanced parentheses.
    UnbalancedParens,
    /// Division by zero.
    DivisionByZero,
}

impl std::fmt::Display for ExprError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExprError::UnexpectedChar(c) => write!(f, "unexpected character {c:?}"),
            ExprError::UnexpectedEnd => write!(f, "unexpected end of expression"),
            ExprError::BadReference => write!(f, "bad $-reference"),
            ExprError::UnresolvedReference(s) => write!(f, "unresolved reference {s}"),
            ExprError::BadNumber(s) => write!(f, "bad number {s:?}"),
            ExprError::MissingOperand => write!(f, "missing operand"),
            ExprError::UnbalancedParens => write!(f, "unbalanced parentheses"),
            ExprError::DivisionByZero => write!(f, "division by zero"),
        }
    }
}

impl std::error::Error for ExprError {}

/// One `expExpressionTable` row.
#[derive(Clone, Debug)]
pub struct Expression {
    /// The owner name (index part 1).
    pub owner: String,
    /// The expression name (index part 2).
    pub name: String,
    /// The expression text, e.g. `"$ifInOctets.1 * 8"` or `"2 + 3 * 4"`.
    pub expression: String,
    /// Whether the expression is enabled (evaluated on GET). A disabled
    /// expression yields `noSuchInstance`.
    pub enabled: bool,
}

impl Expression {
    /// Construct a new expression row.
    pub fn new(
        owner: impl Into<String>,
        name: impl Into<String>,
        expression: impl Into<String>,
    ) -> Self {
        Expression {
            owner: owner.into(),
            name: name.into(),
            expression: expression.into(),
            enabled: true,
        }
    }
}

/// The DISMAN-EXPRESSION engine: owns the expression table and a back-reference
/// to a value provider (the agent's self-query handler).
pub struct ExpressionEngine {
    expressions: RwLock<HashMap<String, Expression>>,
    self_query: RwLock<Option<Arc<dyn MibHandler>>>,
}

impl std::fmt::Debug for ExpressionEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExpressionEngine")
            .field("expressions", &self.expressions.read().ok().map(|m| m.len()))
            .finish()
    }
}

fn exp_key(owner: &str, name: &str) -> String {
    format!("{owner}\u{0}{name}")
}

impl ExpressionEngine {
    /// Create a new engine with an optional self-query value provider.
    pub fn new(self_query: Option<Arc<dyn MibHandler>>) -> Arc<Self> {
        Arc::new(ExpressionEngine {
            expressions: RwLock::new(HashMap::new()),
            self_query: RwLock::new(self_query),
        })
    }

    /// Set or replace the value provider used to resolve `$oid` references.
    pub fn set_self_query(&self, handler: Arc<dyn MibHandler>) {
        *self.self_query.write().unwrap() = Some(handler);
    }

    /// Register an expression row.
    pub fn add_expression(&self, e: Expression) {
        let k = exp_key(&e.owner, &e.name);
        self.expressions.write().unwrap().insert(k, e);
    }

    /// Remove an expression row.
    pub fn remove_expression(&self, owner: &str, name: &str) -> Option<Expression> {
        self.expressions
            .write()
            .unwrap()
            .remove(&exp_key(owner, name))
    }

    /// Evaluate the expression named `(owner, name)` against the current
    /// self-query state. Public so tests can evaluate without going through the
    /// MIB handler.
    pub fn evaluate(&self, owner: &str, name: &str) -> Result<f64, ExprError> {
        let expr = self
            .expressions
            .read()
            .unwrap()
            .get(&exp_key(owner, name))
            .cloned();
        let Some(expr) = expr else {
            return Err(ExprError::UnresolvedReference(format!(
                "{owner}/{name}"
            )));
        };
        if !expr.enabled {
            return Err(ExprError::UnresolvedReference(format!(
                "{owner}/{name} disabled"
            )));
        }
        let provider = self.self_query.read().unwrap().clone();
        evaluate_expression(&expr.expression, |oid| {
            provider.as_ref().and_then(|h| {
                h.get(oid)
                    .and_then(|v| match v {
                        Value::Integer(x) => Some(x as f64),
                        Value::Counter32(x) => Some(x as f64),
                        Value::Gauge32(x) => Some(x as f64),
                        Value::Counter64(x) => Some(x as f64),
                        Value::TimeTicks(x) => Some(x as f64),
                        _ => None,
                    })
                    .or_else(|| {
                        warn!(oid = %oid, "expression reference unresolved");
                        None
                    })
            })
        })
    }

    /// Build the read-only `expExpressionTable` handler exposing the evaluated
    /// value for each expression.
    pub fn handlers(engine: Arc<ExpressionEngine>) -> Vec<Arc<dyn MibHandler>> {
        vec![Arc::new(ExpressionTableHandler::new(engine))]
    }
}

// ---------------------------------------------------------------------------
// Expression parser / evaluator
// ---------------------------------------------------------------------------

/// A token in the expression micro-language.
#[derive(Clone, Debug, PartialEq)]
enum Token {
    /// A numeric literal.
    Number(f64),
    /// A `$oid` reference (the OID string, without the leading `$`).
    Reference(String),
    /// One of `+ - * /`.
    Op(char),
    /// `(`.
    LParen,
    /// `)`.
    RParen,
}

/// Lex an expression into tokens.
fn lex(input: &str) -> Result<Vec<Token>, ExprError> {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                i += 1;
            }
            '+' | '-' | '*' | '/' => {
                out.push(Token::Op(c));
                i += 1;
            }
            '(' => {
                out.push(Token::LParen);
                i += 1;
            }
            ')' => {
                out.push(Token::RParen);
                i += 1;
            }
            '$' => {
                // Reference: read until whitespace, operator, or paren.
                let start = i + 1;
                let mut end = start;
                while end < bytes.len() {
                    let b = bytes[end] as char;
                    if b.is_ascii_whitespace()
                        || matches!(b, '+' | '-' | '*' | '/' | '(' | ')')
                    {
                        break;
                    }
                    end += 1;
                }
                if end == start {
                    return Err(ExprError::BadReference);
                }
                let oid_str = &input[start..end];
                out.push(Token::Reference(oid_str.to_string()));
                i = end;
            }
            '0'..='9' | '.' => {
                // Numeric literal.
                let start = i;
                let mut end = start;
                let mut seen_dot = false;
                while end < bytes.len() {
                    let b = bytes[end] as char;
                    if b.is_ascii_digit() {
                        end += 1;
                    } else if b == '.' && !seen_dot {
                        seen_dot = true;
                        end += 1;
                    } else {
                        break;
                    }
                }
                let s = &input[start..end];
                let n: f64 = s.parse().map_err(|_| ExprError::BadNumber(s.to_string()))?;
                out.push(Token::Number(n));
                i = end;
            }
            _ => return Err(ExprError::UnexpectedChar(c)),
        }
    }
    Ok(out)
}

/// Evaluate `expression`, resolving `$oid` references via `lookup`.
pub fn evaluate_expression<F>(expression: &str, lookup: F) -> Result<f64, ExprError>
where
    F: Fn(&Oid) -> Option<f64>,
{
    let tokens = lex(expression)?;
    let mut pos = 0;
    let value = parse_expr(&tokens, &mut pos, &lookup)?;
    if pos != tokens.len() {
        // Trailing tokens => malformed.
        return Err(ExprError::UnbalancedParens);
    }
    Ok(value)
}

/// Recursive-descent parser following the standard grammar:
///
/// ```text
/// expr   := term (('+' | '-') term)*
/// term   := factor (('*' | '/') factor)*
/// factor := number | reference | '(' expr ')' | '-' factor
/// ```
fn parse_expr<F>(tokens: &[Token], pos: &mut usize, lookup: &F) -> Result<f64, ExprError>
where
    F: Fn(&Oid) -> Option<f64>,
{
    let mut left = parse_term(tokens, pos, lookup)?;
    while *pos < tokens.len() {
        match &tokens[*pos] {
            Token::Op(c @ ('+' | '-')) => {
                *pos += 1;
                let right = parse_term(tokens, pos, lookup)?;
                left = match c {
                    '+' => left + right,
                    '-' => left - right,
                    _ => unreachable!(),
                };
            }
            _ => break,
        }
    }
    Ok(left)
}

fn parse_term<F>(tokens: &[Token], pos: &mut usize, lookup: &F) -> Result<f64, ExprError>
where
    F: Fn(&Oid) -> Option<f64>,
{
    let mut left = parse_factor(tokens, pos, lookup)?;
    while *pos < tokens.len() {
        match &tokens[*pos] {
            Token::Op(c @ ('*' | '/')) => {
                *pos += 1;
                let right = parse_factor(tokens, pos, lookup)?;
                left = match c {
                    '*' => left * right,
                    '/' => {
                        if right == 0.0 {
                            return Err(ExprError::DivisionByZero);
                        }
                        left / right
                    }
                    _ => unreachable!(),
                };
            }
            _ => break,
        }
    }
    Ok(left)
}

fn parse_factor<F>(tokens: &[Token], pos: &mut usize, lookup: &F) -> Result<f64, ExprError>
where
    F: Fn(&Oid) -> Option<f64>,
{
    if *pos >= tokens.len() {
        return Err(ExprError::UnexpectedEnd);
    }
    match &tokens[*pos] {
        Token::Number(n) => {
            let v = *n;
            *pos += 1;
            Ok(v)
        }
        Token::Reference(r) => {
            let oid: Oid = r
                .parse()
                .map_err(|_| ExprError::UnresolvedReference(r.clone()))?;
            *pos += 1;
            lookup(&oid).ok_or_else(|| ExprError::UnresolvedReference(r.clone()))
        }
        Token::LParen => {
            *pos += 1;
            let v = parse_expr(tokens, pos, lookup)?;
            if *pos >= tokens.len() || tokens[*pos] != Token::RParen {
                return Err(ExprError::UnbalancedParens);
            }
            *pos += 1;
            Ok(v)
        }
        Token::Op('-') => {
            *pos += 1;
            Ok(-parse_factor(tokens, pos, lookup)?)
        }
        Token::Op('+') => {
            *pos += 1;
            parse_factor(tokens, pos, lookup)
        }
        Token::RParen | Token::Op(_) => Err(ExprError::MissingOperand),
    }
}

// ---------------------------------------------------------------------------
// MIB handler
// ---------------------------------------------------------------------------

/// Read-only handler exposing the evaluated value of each expression at
/// `EXP_ENTRY.COL_EXP_VALUE.<owner>0<name>`.
struct ExpressionTableHandler {
    root: Oid,
    engine: Arc<ExpressionEngine>,
}

impl ExpressionTableHandler {
    fn new(engine: Arc<ExpressionEngine>) -> Self {
        ExpressionTableHandler {
            root: Oid::new(EXP_ENTRY.to_vec()),
            engine,
        }
    }

    /// Build all (oid, value) cells for the current expression set. Errors in
    /// evaluation are simply omitted (the cell reads as `noSuchInstance`).
    fn cells(&self) -> Vec<(Oid, Value)> {
        let expressions = self.engine.expressions.read().unwrap();
        let mut out = Vec::new();
        for e in expressions.values() {
            let mut index = e.owner.bytes().map(|b| b as u32).collect::<Vec<_>>();
            index.push(0);
            index.extend(e.name.bytes().map(|b| b as u32));
            let mut oid = self.root.child(COL_EXP_VALUE);
            for &s in &index {
                oid = oid.child(s);
            }
            let value = match self.engine.evaluate(&e.owner, &e.name) {
                Ok(v) => Value::Integer(v as i64),
                Err(err) => {
                    warn!(expr = %e.expression, error = %err, "expression eval failed");
                    continue;
                }
            };
            out.push((oid, value));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

impl MibHandler for ExpressionTableHandler {
    fn root(&self) -> &Oid {
        &self.root
    }

    fn get(&self, oid: &Oid) -> Option<Value> {
        self.cells()
            .into_iter()
            .find(|(o, _)| o == oid)
            .map(|(_, v)| v)
    }

    fn get_next(&self, oid: &Oid) -> Option<Reading> {
        let cells = self.cells();
        let idx = cells.partition_point(|(o, _)| o <= oid);
        cells.get(idx).map(|(o, v)| Reading {
            oid: o.clone(),
            value: v.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalar::ScalarHandler;

    #[test]
    fn evaluate_simple_arithmetic() {
        assert_eq!(evaluate_expression("2 + 3 * 4", |_| None).unwrap(), 14.0);
        assert_eq!(evaluate_expression("(2 + 3) * 4", |_| None).unwrap(), 20.0);
        assert_eq!(evaluate_expression("10 - 2 - 3", |_| None).unwrap(), 5.0);
        assert_eq!(evaluate_expression("2 * 3 + 4 * 5", |_| None).unwrap(), 26.0);
        assert_eq!(evaluate_expression("-5", |_| None).unwrap(), -5.0);
        assert_eq!(evaluate_expression("3.5 * 2", |_| None).unwrap(), 7.0);
    }

    #[test]
    fn evaluate_division_by_zero_errors() {
        let err = evaluate_expression("1 / 0", |_| None).unwrap_err();
        assert_eq!(err, ExprError::DivisionByZero);
    }

    #[test]
    fn evaluate_unbalanced_parens_errors() {
        assert!(matches!(
            evaluate_expression("(2 + 3", |_| None),
            Err(ExprError::UnbalancedParens)
        ));
        assert!(matches!(
            evaluate_expression("2 + 3)", |_| None),
            Err(ExprError::UnbalancedParens)
        ));
    }

    #[test]
    fn evaluate_unexpected_char_errors() {
        assert!(matches!(
            evaluate_expression("2 & 3", |_| None),
            Err(ExprError::UnexpectedChar('&'))
        ));
    }

    #[test]
    fn evaluate_with_reference() {
        // Reference `$x` -> OID 1.3.6.1.2.1.2.2.1.10.1 returning 5.
        let result = evaluate_expression("$1.3.6.1.2.1.2.2.1.10.1 + 1", |oid| {
            if oid.as_slice() == [1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 1] {
                Some(5.0)
            } else {
                None
            }
        })
        .unwrap();
        assert_eq!(result, 6.0);
    }

    #[test]
    fn evaluate_unresolved_reference_errors() {
        let err = evaluate_expression("$1.2.3 + 1", |_| None).unwrap_err();
        assert!(matches!(err, ExprError::UnresolvedReference(_)));
    }

    #[test]
    fn engine_evaluates_registered_expression() {
        let scalar = Arc::new(ScalarHandler::new(
            "1.3.6.1.2.1.2.2.1.10.1".parse().unwrap(),
            Value::Counter32(100),
        ));
        let engine = ExpressionEngine::new(Some(scalar));
        // The scalar serves at root.0, so reference the instance OID .0.
        engine.add_expression(Expression::new("", "octets_x_8", "$1.3.6.1.2.1.2.2.1.10.1.0 * 8"));
        assert_eq!(engine.evaluate("", "octets_x_8").unwrap(), 800.0);
    }

    #[test]
    fn handler_returns_evaluated_value_on_get() {
        let scalar = Arc::new(ScalarHandler::new(
            "1.3.6.1.2.1.2.2.1.10.1".parse().unwrap(),
            Value::Counter32(7),
        ));
        let engine = ExpressionEngine::new(Some(scalar));
        engine.add_expression(Expression::new("alice", "e1", "$1.3.6.1.2.1.2.2.1.10.1.0 + 1"));
        let handlers = ExpressionEngine::handlers(engine);
        let h = &handlers[0];
        // GETNEXT from below the table should find our cell.
        let reading = h
            .get_next(&"1.3.6.1.2.1.90.1.2.1".parse().unwrap())
            .expect("cell present");
        assert!(reading.oid.as_slice().starts_with(EXP_ENTRY));
        // 7 + 1 = 8.
        assert_eq!(reading.value, Value::Integer(8));
    }
}
