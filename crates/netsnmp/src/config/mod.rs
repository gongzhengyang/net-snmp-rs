//! Configuration-file parsing (`snmp.conf` / `snmpd.conf` compatible).
//!
//! Counterpart of `snmplib/read_config.c`. Net-SNMP configuration files are
//! line-oriented: each non-blank, non-comment line starts with a *token*
//! (directive) followed by arguments. This module reproduces that grammar:
//!
//! * **Comments** — a line whose first non-blank character is `#` is ignored,
//!   as are blank lines. (Net-SNMP only honors whole-line comments, never
//!   trailing ones, so `#` mid-line is literal.)
//! * **Tokenizing** — words are whitespace-separated; a word may be wrapped in
//!   single or double quotes to embed spaces, and `\` escapes the next
//!   character ([`word`](mod@self::word)).
//! * **Section headers** — `[name]` switches the active application context
//!   (e.g. `[snmp]`, `[snmpd]`). `[name] token args...` applies to that one
//!   line only ([`parse`](mod@self::parse)).
//! * **Includes** — `includeFile <path>`, `includeDir <dir>` and
//!   `includeSearch <name>` pull in further files (resolved by [`parse_file`]).
//! * **Search paths** — [`config_directories`] reproduces the `SNMPCONFPATH`
//!   lookup, and [`read_app_config`] reads `<app>.conf` and `<app>.local.conf`
//!   from each directory, in order ([`search`](mod@self::search)).
//!
//! The parser is intentionally policy-free: it returns a flat list of
//! [`Directive`]s. Mapping tokens such as `rocommunity` or `defVersion` onto
//! typed settings is left to the application layer (see `netsnmp-apps`).

mod parse;
mod search;
mod word;

use std::path::PathBuf;

pub use parse::{parse_file, parse_str};
pub use search::{
    config_directories, config_files, config_files_in, read_app_config, read_app_config_in,
};
pub use word::{parse_words, read_word};

/// A single parsed configuration directive: a token plus its arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Directive {
    /// The directive keyword (first word on the line), e.g. `rocommunity`.
    pub token: String,
    /// The remaining words, tokenized with quote/escape handling.
    pub args: Vec<String>,
    /// The raw remainder of the line after the token (leading space trimmed).
    /// Useful for free-form directives like `sysLocation` that take the rest of
    /// the line verbatim rather than as discrete words.
    pub rest: String,
    /// The active `[section]`, if any (the application/context name).
    pub section: Option<String>,
    /// The file this directive came from, when parsed from a file.
    pub source: Option<PathBuf>,
    /// 1-based line number within `source`.
    pub line_no: usize,
}

impl Directive {
    /// Case-insensitive comparison of the token against `name`.
    pub fn is(&self, name: &str) -> bool {
        self.token.eq_ignore_ascii_case(name)
    }

    /// The argument at `index`, if present.
    pub fn arg(&self, index: usize) -> Option<&str> {
        self.args.get(index).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn tokenizes_quotes_and_escapes() {
        assert_eq!(
            parse_words("rocommunity public"),
            vec!["rocommunity", "public"]
        );
        assert_eq!(
            parse_words(r#"syslocation "Server Room 1""#),
            vec!["syslocation", "Server Room 1"]
        );
        assert_eq!(parse_words(r"a\ b c"), vec!["a b", "c"]);
        assert_eq!(
            parse_words("'quoted word' tail"),
            vec!["quoted word", "tail"]
        );
        assert!(parse_words("   ").is_empty());
    }

    #[test]
    fn skips_comments_and_blanks() {
        let content = "\
# a comment
   # indented comment

rocommunity public 10.0.0.0/8
syslocation   My  Office
";
        let d = parse_str(content);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].token, "rocommunity");
        assert_eq!(d[0].args, vec!["public", "10.0.0.0/8"]);
        // `rest` preserves the verbatim remainder for free-form directives.
        assert_eq!(d[1].token, "syslocation");
        assert_eq!(d[1].rest, "My  Office");
    }

    #[test]
    fn hash_is_literal_mid_line() {
        // Only a leading '#' starts a comment; mid-line '#' is part of a word.
        let d = parse_str("syscontact admin#example.org");
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].args, vec!["admin#example.org"]);
    }

    #[test]
    fn sections_switch_and_override() {
        let content = "\
[snmp]
defVersion 2c
[snmpd] rocommunity secret
syslocation here
";
        let d = parse_str(content);
        assert_eq!(d[0].token, "defVersion");
        assert_eq!(d[0].section.as_deref(), Some("snmp"));
        // One-line override applies only to that line.
        assert_eq!(d[1].token, "rocommunity");
        assert_eq!(d[1].section.as_deref(), Some("snmpd"));
        // Subsequent line reverts to the section set by the standalone header.
        assert_eq!(d[2].token, "syslocation");
        assert_eq!(d[2].section.as_deref(), Some("snmp"));
    }

    #[test]
    fn case_insensitive_token_match() {
        let d = parse_str("RoCommunity public");
        assert!(d[0].is("rocommunity"));
        assert_eq!(d[0].arg(0), Some("public"));
    }

    #[test]
    fn search_path_files_layout() {
        let dirs = vec![PathBuf::from("/etc/snmp"), PathBuf::from("/home/u/.snmp")];
        let files = config_files_in(&dirs, "snmpd");
        assert_eq!(
            files,
            vec![
                PathBuf::from("/etc/snmp/snmpd.conf"),
                PathBuf::from("/etc/snmp/snmpd.local.conf"),
                PathBuf::from("/home/u/.snmp/snmpd.conf"),
                PathBuf::from("/home/u/.snmp/snmpd.local.conf"),
            ]
        );
    }

    #[test]
    fn parses_file_with_include() {
        let dir = std::env::temp_dir().join(format!("netsnmp-cfg-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let main = dir.join("main.conf");
        let inc = dir.join("extra.conf");
        fs::write(&inc, "rwcommunity private\n").unwrap();
        fs::write(&main, "rocommunity public\nincludeFile extra.conf\n").unwrap();

        let d = parse_file(&main).unwrap();
        let tokens: Vec<&str> = d.iter().map(|x| x.token.as_str()).collect();
        assert_eq!(tokens, vec!["rocommunity", "rwcommunity"]);
        assert_eq!(d[1].source.as_ref().unwrap(), &inc);

        let _ = fs::remove_dir_all(&dir);
    }
}
