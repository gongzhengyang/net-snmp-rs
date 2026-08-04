//! Stage 1 of the MIB parser: tokenizer.
//!
//! Turns MIB module text into a flat [`Tok`] stream, applying the ASN.1 comment
//! rule (`--` … `--`/EOL), the identifier rule (embedded single hyphens), and
//! capturing quoted strings as [`Tok::Str`] (bit-string literals are skipped).

/// A lexical token from a MIB file. Quoted strings are captured (with the
/// surrounding quotes removed) as [`Tok::Str`]; the ASN.1 `""` escape is
/// decoded back into a single `"` inside the captured content.
#[derive(Clone, Debug, PartialEq)]
pub enum Tok {
    /// An identifier or keyword (e.g. `sysDescr`, `OBJECT-TYPE`, `mib-2`).
    Ident(String),
    /// A non-negative integer literal.
    Num(i64),
    /// A double-quoted string literal (contents, with `""` decoded).
    Str(String),
    /// `{`
    LBrace,
    /// `}`
    RBrace,
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `,`
    Comma,
    /// `;`
    Semi,
    /// `|`
    Pipe,
    /// `::=`
    Assign,
    /// `..`
    DotDot,
}

/// Tokenize MIB module text into a [`Tok`] stream.
pub fn lex(input: &str) -> Vec<Tok> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut out = Vec::new();

    let is_ident_start = |c: u8| c.is_ascii_alphabetic() || c == b'_';
    let is_ident_part = |c: u8| c.is_ascii_alphanumeric() || c == b'_';

    while i < len {
        let c = bytes[i];
        match c {
            // Whitespace.
            b' ' | b'\t' | b'\r' | b'\n' => {
                i += 1;
            }
            // Comment: `--` to the next `--` or end of line (ASN.1 rule).
            b'-' if i + 1 < len && bytes[i + 1] == b'-' => {
                i += 2;
                while i < len {
                    if bytes[i] == b'\n' {
                        break;
                    }
                    if bytes[i] == b'-' && i + 1 < len && bytes[i + 1] == b'-' {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
            }
            // Quoted string: capture contents, decoding the ASN.1 `""` escape
            // (two adjacent double-quotes inside a string → one literal `"`).
            b'"' => {
                i += 1;
                let mut content = String::new();
                loop {
                    if i >= len {
                        break;
                    }
                    if bytes[i] == b'"' {
                        // `""` inside the string is an escaped quote.
                        if i + 1 < len && bytes[i + 1] == b'"' {
                            content.push('"');
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    // Consume one UTF-8 char boundary so non-ASCII text
                    // (common in DESCRIPTIONs) is preserved correctly.
                    let ch_start = i;
                    let width = utf8_len(bytes[i]);
                    let ch_end = (ch_start + width).min(len);
                    match std::str::from_utf8(&bytes[ch_start..ch_end]) {
                        Ok(s) => content.push_str(s),
                        Err(_) => content.push('\u{FFFD}'),
                    }
                    i = ch_end;
                }
                i += 1; // closing quote (or EOF)
                out.push(Tok::Str(content));
            }
            // Binary/hex string literal: '...'H or '...'B — skip.
            b'\'' => {
                i += 1;
                while i < len && bytes[i] != b'\'' {
                    i += 1;
                }
                i += 1;
                if i < len
                    && (bytes[i] == b'H'
                        || bytes[i] == b'h'
                        || bytes[i] == b'B'
                        || bytes[i] == b'b')
                {
                    i += 1;
                }
            }
            // `::=`
            b':' if i + 2 < len && bytes[i + 1] == b':' && bytes[i + 2] == b'=' => {
                out.push(Tok::Assign);
                i += 3;
            }
            // `..`
            b'.' if i + 1 < len && bytes[i + 1] == b'.' => {
                out.push(Tok::DotDot);
                i += 2;
            }
            b'.' => {
                i += 1; // stray dot, ignore
            }
            b'{' => {
                out.push(Tok::LBrace);
                i += 1;
            }
            b'}' => {
                out.push(Tok::RBrace);
                i += 1;
            }
            b'(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            b')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            b',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            b';' => {
                out.push(Tok::Semi);
                i += 1;
            }
            b'|' => {
                out.push(Tok::Pipe);
                i += 1;
            }
            // Number.
            c if c.is_ascii_digit() => {
                let start = i;
                while i < len && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let s = &input[start..i];
                // Values can exceed i64 in odd cases; clamp via parse fallback.
                let n = s.parse::<i64>().unwrap_or(0);
                out.push(Tok::Num(n));
            }
            // Identifier (letters, digits, `_`, and embedded single hyphens).
            c if is_ident_start(c) => {
                let start = i;
                i += 1;
                while i < len {
                    let ch = bytes[i];
                    if is_ident_part(ch) {
                        i += 1;
                    } else if ch == b'-' && i + 1 < len && is_ident_part(bytes[i + 1]) {
                        // Embedded single hyphen (e.g. `mib-2`, `OBJECT-TYPE`).
                        i += 2;
                    } else {
                        break;
                    }
                }
                out.push(Tok::Ident(input[start..i].to_string()));
            }
            // Anything else: skip.
            _ => {
                i += 1;
            }
        }
    }

    out
}

/// Return the expected UTF-8 byte width of a code point given its leading byte.
/// Values 0x80–0xBF are continuation bytes (treated as width 1 to recover).
fn utf8_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first < 0xC0 {
        1 // stray continuation byte
    } else if first < 0xE0 {
        2
    } else if first < 0xF0 {
        3
    } else {
        4
    }
}
