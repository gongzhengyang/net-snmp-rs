//! Word tokenization with quote and backslash-escape handling.
//!
//! Mirrors `copy_nword` in `read_config.c`.

/// Read a single word from `input`, honoring quotes and `\` escapes, returning
/// the decoded word and the remaining input (with leading whitespace trimmed).
///
/// A leading `"` or `'` quotes the word until the matching close quote;
/// otherwise the word runs to the next whitespace. A backslash copies the
/// following character literally.
pub fn read_word(input: &str) -> Option<(String, &str)> {
    let s = input.trim_start();
    let first = s.chars().next()?;
    let mut word = String::new();
    let end_byte;

    if first == '"' || first == '\'' {
        // Quoted: consume until the matching quote (skip the opening quote).
        let mut end = s.len();
        let mut escaped = false;
        for (i, c) in s.char_indices().skip(1) {
            if escaped {
                word.push(c);
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == first {
                end = i + c.len_utf8();
                break;
            } else {
                word.push(c);
            }
        }
        end_byte = end;
    } else {
        // Unquoted: run to the next whitespace.
        let mut end = s.len();
        let mut escaped = false;
        for (i, c) in s.char_indices() {
            if escaped {
                word.push(c);
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c.is_whitespace() {
                end = i;
                break;
            } else {
                word.push(c);
            }
        }
        end_byte = end;
    }

    let rest = s.get(end_byte..).unwrap_or("").trim_start();
    Some((word, rest))
}

/// Tokenize a string into words using [`read_word`] semantics.
pub fn parse_words(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = input;
    while let Some((word, next)) = read_word(rest) {
        out.push(word);
        rest = next;
    }
    out
}
