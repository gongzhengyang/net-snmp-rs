//! Integration tests for the management tools `snmpusm` and `snmpvacm`.
//!
//! The in-process test agent does not implement remote management of the USM /
//! VACM MIB tables, so these tests focus on argument handling and on confirming
//! that the tools build and transmit a SET (which the agent then rejects). The
//! happy-path variable-binding construction is covered by unit tests in
//! `netsnmp_apps::mgmt`.
//!
//! Also covers `encode_keychange`, an offline tool that needs no agent.

mod common;

use common::{run, run_async, spawn_rich_agent};

#[tokio::test]
async fn snmpusm_requires_engine_id_without_v3() {
    let addr = spawn_rich_agent("public").await;
    let out = run_async(
        "snmpusm",
        &["-v", "2c", "-c", "public", &addr, "delete", "bob"],
        &[],
    )
    .await;
    out.assert_failure("snmpusm without engine id");
    assert!(
        out.combined().to_lowercase().contains("engine id"),
        "got: {}",
        out.combined()
    );
}

#[tokio::test]
async fn snmpusm_unknown_operation() {
    let addr = spawn_rich_agent("public").await;
    let out = run_async(
        "snmpusm",
        &[
            "-v",
            "2c",
            "-c",
            "public",
            "--engine-id",
            "8000000001",
            &addr,
            "frobnicate",
            "bob",
        ],
        &[],
    )
    .await;
    out.assert_failure("snmpusm unknown op");
    assert!(
        out.combined().contains("unknown operation"),
        "got: {}",
        out.combined()
    );
}

#[tokio::test]
async fn snmpusm_delete_transmits_set_and_agent_rejects() {
    let addr = spawn_rich_agent("public").await;
    // The agent has no usmUserTable, so the SET is rejected — but this proves
    // the tool parsed the op, built the binding and sent the request.
    let out = run_async(
        "snmpusm",
        &[
            "-v",
            "2c",
            "-c",
            "public",
            "--engine-id",
            "8000000001",
            &addr,
            "delete",
            "bob",
        ],
        &[],
    )
    .await;
    out.assert_failure("snmpusm delete rejected by agent");
}

#[tokio::test]
async fn snmpusm_bad_engine_id_hex() {
    let addr = spawn_rich_agent("public").await;
    let out = run_async(
        "snmpusm",
        &[
            "-v",
            "2c",
            "-c",
            "public",
            "--engine-id",
            "xyz",
            &addr,
            "delete",
            "bob",
        ],
        &[],
    )
    .await;
    out.assert_failure("snmpusm bad hex");
}

#[tokio::test]
async fn snmpvacm_unknown_operation() {
    let addr = spawn_rich_agent("public").await;
    let out = run_async(
        "snmpvacm",
        &["-v", "2c", "-c", "public", &addr, "frobnicate"],
        &[],
    )
    .await;
    out.assert_failure("snmpvacm unknown op");
    assert!(
        out.combined().contains("unknown operation"),
        "got: {}",
        out.combined()
    );
}

#[tokio::test]
async fn snmpvacm_createview_missing_args() {
    let addr = spawn_rich_agent("public").await;
    let out = run_async(
        "snmpvacm",
        &["-v", "2c", "-c", "public", &addr, "createview", "onlyname"],
        &[],
    )
    .await;
    out.assert_failure("snmpvacm createview missing subtree");
    assert!(
        out.combined().to_lowercase().contains("usage"),
        "got: {}",
        out.combined()
    );
}

#[tokio::test]
async fn snmpvacm_createaccess_rejects_non_integer_model() {
    let addr = spawn_rich_agent("public").await;
    let out = run_async(
        "snmpvacm",
        &[
            "-v",
            "2c",
            "-c",
            "public",
            &addr,
            "createaccess",
            "grp",
            "ctx",
            "notanumber",
            "3",
            "all",
            "all",
            "none",
        ],
        &[],
    )
    .await;
    out.assert_failure("snmpvacm bad model");
    assert!(
        out.combined().contains("expected an integer"),
        "got: {}",
        out.combined()
    );
}

// ---------------------------------------------------------------------------
// encode_keychange — offline USM KeyChange value generator (no agent needed).
// ---------------------------------------------------------------------------

/// The single non-empty stdout line of a successful `encode_keychange` run.
fn keychange_hex_line(out: &common::CliOutput) -> String {
    out.stdout
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or_default()
        .to_string()
}

#[test]
fn encode_keychange_outputs_hex_of_correct_length() {
    // SHA (HMAC-SHA-96): the localized key is the full SHA-1 digest (20 bytes),
    // so KeyChange = 40 bytes = 80 hex chars. (`mac_len` truncates to 12, but
    // `key_change` operates on the full digest-length localized key.)
    let out = run(
        "encode_keychange",
        &["-e", "0x80001f8880", "-a", "SHA", "-E", "oldpass", "-N", "newpass"],
        &[],
    );
    out.assert_success("encode_keychange SHA");
    let hex = keychange_hex_line(&out);
    assert!(
        hex.len() == 80 && hex.chars().all(|c| c.is_ascii_hexdigit()),
        "expected 80 lowercase hex chars for SHA (digest 20 -> 40 bytes), \
         got len {} ({} bytes): {hex}",
        hex.len(),
        hex.len() / 2,
    );
    assert_eq!(
        hex.to_ascii_lowercase(),
        hex,
        "output should already be lowercase hex"
    );
}

#[test]
fn encode_keychange_md5_length_matches_digest_len() {
    // MD5 localized key is the full 16-byte digest → 32 bytes → 64 hex chars.
    let out = run(
        "encode_keychange",
        &["-e", "80001f8880", "-a", "MD5", "-E", "oldpass", "-N", "newpass"],
        &[],
    );
    out.assert_success("encode_keychange MD5 (no 0x prefix)");
    let hex = keychange_hex_line(&out);
    assert_eq!(
        hex.len(),
        64,
        "MD5 KeyChange should be 64 hex chars (32 bytes); got: {hex}"
    );
}

#[test]
fn encode_keychange_sha256_is_double_length() {
    // SHA-256 localized key is the full 32-byte digest → 64 bytes → 128 hex chars.
    let out = run(
        "encode_keychange",
        &[
            "-e",
            "0x80001f8880",
            "-a",
            "SHA-256",
            "-E",
            "oldpass",
            "-N",
            "newpass",
        ],
        &[],
    );
    out.assert_success("encode_keychange SHA-256");
    let hex = keychange_hex_line(&out);
    assert_eq!(
        hex.len(),
        128,
        "SHA-256 KeyChange should be 128 hex chars (64 bytes); got: {hex}"
    );
}

#[test]
fn encode_keychange_master_flag_prints_only_random_half() {
    // With -m only the random half is printed: SHA → 20 bytes → 40 hex chars.
    let out = run(
        "encode_keychange",
        &[
            "-e",
            "0x80001f8880",
            "-a",
            "SHA",
            "-E",
            "oldpass",
            "-N",
            "newpass",
            "-m",
        ],
        &[],
    );
    out.assert_success("encode_keychange -m");
    let hex = keychange_hex_line(&out);
    assert_eq!(
        hex.len(),
        40,
        "-m should print only the random half (40 hex chars for SHA); got: {hex}"
    );
}

#[test]
fn encode_keychange_rejects_bad_auth_proto() {
    let out = run(
        "encode_keychange",
        &["-e", "0x80001f8880", "-a", "FOO", "-E", "old", "-N", "new"],
        &[],
    );
    out.assert_failure("encode_keychange bad auth proto");
    assert!(
        out.combined()
            .to_ascii_lowercase()
            .contains("unsupported auth protocol"),
        "got: {}",
        out.combined()
    );
}

#[test]
fn encode_keychange_rejects_bad_hex() {
    let out = run(
        "encode_keychange",
        &["-e", "nothex", "-a", "SHA", "-E", "old", "-N", "new"],
        &[],
    );
    out.assert_failure("encode_keychange bad hex");
    assert!(
        out.combined().to_ascii_lowercase().contains("hex"),
        "got: {}",
        out.combined()
    );
}

#[test]
fn encode_keychange_rejects_empty_engine_id() {
    let out = run(
        "encode_keychange",
        &["-e", "0x", "-a", "SHA", "-E", "old", "-N", "new"],
        &[],
    );
    out.assert_failure("encode_keychange empty engine id");
    assert!(
        out.combined().to_ascii_lowercase().contains("engine id"),
        "got: {}",
        out.combined()
    );
}

// ---------------------------------------------------------------------------
// snmpconf — offline config generator (interactive + answers-file mode).
// ---------------------------------------------------------------------------

/// Interactive mode: choosing type `1` (snmp) and answering the first two
/// questions, leaving the rest at their defaults/skipped, emits `defVersion`
/// and `defCommunity` lines.
#[test]
fn snmpconf_interactive_snmp_writes_defversion() {
    // "1" selects snmp; then 9 answers: "2c", "public", and 7 empty lines
    // (defaults for the rest, with no-default keys skipped).
    let stdin = "1\n2c\npublic\n\n\n\n\n\n\n\n";
    let out = common::run_stdin("snmpconf", &[], &[], stdin);
    out.assert_success("snmpconf interactive snmp");
    let combined = out.combined();
    assert!(
        combined.contains("defVersion 2c"),
        "expected 'defVersion 2c' in output:\n{combined}"
    );
    assert!(
        combined.contains("defCommunity public"),
        "expected 'defCommunity public' in output:\n{combined}"
    );
}

/// Interactive mode: choosing type `2` (snmpd) emits the `rocommunity` line.
#[test]
fn snmpconf_interactive_snmpd_writes_rocommunity() {
    // "2" selects snmpd; then 7 answers: "public" (rocommunity), and 6 empty
    // lines for the remaining questions (defaults/skipped).
    let stdin = "2\npublic\n\n\n\n\n\n\n";
    let out = common::run_stdin("snmpconf", &[], &[], stdin);
    out.assert_success("snmpconf interactive snmpd");
    let combined = out.combined();
    assert!(
        combined.contains("rocommunity public"),
        "expected 'rocommunity public' in output:\n{combined}"
    );
}

/// File mode (`-f`): a `key=value` answers file emits known directives, with
/// unknown keys passed through and empty recognized keys dropped.
#[test]
fn snmpconf_file_mode_emits_known_directives() {
    let dir = std::env::temp_dir().join(format!(
        "snmpconf-file-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("answers.txt");
    std::fs::write(&path, "defVersion=3\ndefSecurityName=alice\n").unwrap();

    let out = run("snmpconf", &["-f", path.to_str().unwrap(), "-t", "snmp"], &[]);

    // Clean up the temp dir regardless of the test outcome.
    let _ = std::fs::remove_dir_all(&dir);

    out.assert_success("snmpconf file mode");
    let combined = out.combined();
    assert!(
        combined.contains("defVersion 3"),
        "expected 'defVersion 3' in output:\n{combined}"
    );
    assert!(
        combined.contains("defSecurityName alice"),
        "expected 'defSecurityName alice' in output:\n{combined}"
    );
}

/// The generated config round-trips through `netsnmp::config::parse_str` into
/// directives with the expected tokens and argument lists.
#[test]
fn snmpconf_output_is_parseable() {
    let stdin = "1\n2c\npublic\n\n\n\n\n\n\n\n";
    let out = common::run_stdin("snmpconf", &[], &[], stdin);
    out.assert_success("snmpconf round-trip run");
    let dirs = netsnmp::config::parse_str(&out.stdout);
    let tokens: Vec<&str> = dirs.iter().map(|d| d.token.as_str()).collect();
    assert!(
        tokens.contains(&"defVersion"),
        "expected a defVersion directive, got tokens: {tokens:?}"
    );
    assert!(
        tokens.contains(&"defCommunity"),
        "expected a defCommunity directive, got tokens: {tokens:?}"
    );
    // Verify the argument lists round-trip correctly.
    let dv = dirs
        .iter()
        .find(|d| d.token == "defVersion")
        .expect("defVersion directive present");
    assert_eq!(dv.args, vec!["2c"]);
    let dc = dirs
        .iter()
        .find(|d| d.token == "defCommunity")
        .expect("defCommunity directive present");
    assert_eq!(dc.args, vec!["public"]);
}

/// `-t bogus` is rejected (failure exit).
#[test]
fn snmpconf_rejects_bad_type() {
    let out = run("snmpconf", &["-t", "bogus"], &[]);
    out.assert_failure("snmpconf bad type");
}

