//! `encode_keychange` — offline generator for a USM `KeyChange` value.
//!
//! Rust counterpart of `apps/encode_keychange.c`. Given an engine ID, an auth
//! protocol, and the old + new passphrases, it emits the RFC 3414 §A.2
//! KeyChange octet string (`random ‖ digest`) as lowercase hex on its own
//! line. The value is what a manager would write to `usmUserAuthKeyChange`
//! (column 6 of `usmUserTable`) to roll a remote user's key without speaking
//! SNMP itself — useful for seeding an agent's persistent config or for
//! scripting a key rotation entirely out-of-band.
//!
//! This tool performs no network I/O. Key localization and the KeyChange digest
//! are computed entirely locally by `netsnmp::usm::AuthProtocol`.
//!
//! Common usage (copy a whole line and run it):
//!
//!   encode_keychange -e 0x80001f8880 -a SHA -E oldpass -N newpass
//!   encode_keychange -e 80001f8880 -a SHA-256 -E oldpass -N newpass -m
//!
//! Typical output (SHA / SHA-1: digest length 20, so 40 bytes → 80 hex chars):
//!
//!   9f4c2b...80 hex chars total...a0
//!
//! With `-m` only the random half is printed (20 bytes → 40 hex chars for
//! SHA-1; 16 → 32 for MD5; 32 → 64 for SHA-256).

use clap::Parser;
use netsnmp_apps::{AppError, init_tracing, parse_auth_proto, parse_hex_string};

/// Offline generator for a USM `KeyChange` value (RFC 3414 §A.2).
#[derive(Parser, Debug)]
#[command(
    name = "encode_keychange",
    about = "Generate a USM KeyChange value from old + new passphrases"
)]
struct Cli {
    /// Authoritative engine ID as hex (optional leading `0x`/`0X`; embedded
    /// whitespace tolerated), e.g. `80001f8880` or `0x80001f8880`.
    #[arg(short = 'e', long = "engine-id", value_name = "HEX")]
    engine_id: String,
    /// Authentication protocol: `MD5`, `SHA`, or `SHA-256`.
    #[arg(short = 'a', long = "auth-proto", value_name = "PROTO")]
    auth_proto: String,
    /// Old passphrase.
    #[arg(short = 'E', long = "old-pass", value_name = "PASS")]
    old_pass: String,
    /// New passphrase.
    #[arg(short = 'N', long = "new-pass", value_name = "PASS")]
    new_pass: String,
    /// Print only the random half of the KeyChange value. Upstream `-m`
    /// treats the `-E`/`-N` operands as already-localized keys given as hex;
    /// this tool instead takes passphrases (it localizes them itself) and, with
    /// `-m`, simply truncates its normal `random ‖ digest` output to the random
    /// portion.
    #[arg(short = 'm', long = "master")]
    master: bool,
}

fn main() -> Result<(), AppError> {
    init_tracing();

    let cli = Cli::parse();

    // Auth protocol first: a bad token is an argument error.
    let auth = parse_auth_proto(&cli.auth_proto)?;

    // Engine ID: accept an optional leading `0x`/`0X`, then reuse the shared
    // whitespace-tolerant hex parser.
    let engine_id = parse_engine_id(&cli.engine_id)?;

    // Fresh random material of the protocol's key length. `key_change` does its
    // own localization internally, so the raw passphrases are passed straight
    // through. `key_change` requires `random.len() >= localized_key_len`, and
    // that localized key length equals the protocol's *full digest* length
    // (MD5=16, SHA-1=20, SHA-256=32) rather than the wire `mac_len`. Derive the
    // exact length from one localization pass so the buffer always satisfies the
    // `# Panics` contract and the output is exactly `2 * key_len` octets.
    let key_len = auth.localized_key(cli.old_pass.as_bytes(), &engine_id).len();
    let random: Vec<u8> = (0..key_len).map(|_| rand::random::<u8>()).collect();

    let kc = auth.key_change(cli.old_pass.as_bytes(), cli.new_pass.as_bytes(), &engine_id, &random);

    let out = if cli.master {
        // The leading `key_len` octets are the random half.
        &kc[..key_len]
    } else {
        &kc[..]
    };

    println!("{}", to_lower_hex(out));
    Ok(())
}

/// Parse an engine-ID hex string, tolerating an optional leading `0x`/`0X`
/// prefix and embedded whitespace.
fn parse_engine_id(raw: &str) -> Result<Vec<u8>, AppError> {
    let stripped = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    let bytes = parse_hex_string(stripped).map_err(AppError::msg)?;
    if bytes.is_empty() {
        return Err(AppError::msg("engine ID cannot be empty"));
    }
    Ok(bytes)
}

/// Lowercase hex encoding of `bytes` (no separators, no `0x` prefix).
fn to_lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // `u8` hex formatting cannot fail for a growable String.
        let _ = write!(out, "{b:02x}");
    }
    out
}
