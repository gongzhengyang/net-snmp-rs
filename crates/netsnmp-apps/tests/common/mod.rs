//! Shared helpers for the `netsnmp-apps` integration tests.
//!
//! These tests drive the *actual compiled CLI binaries* (via the
//! `CARGO_BIN_EXE_*` paths Cargo provides to integration tests) against an
//! in-process [`netsnmp-agent`] / [`TrapReceiver`] running on a loopback UDP
//! port. That exercises the whole tool: clap argument parsing, MIB name
//! resolution, the async SNMP session, and result formatting — the same path a
//! user hits on the command line.

#![allow(dead_code)]

use std::process::{Command, Stdio};
use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;
use netsnmp_agent::{Agent, AgentConfig, MapHandler, Registry, ScalarHandler};

/// Absolute path to a compiled binary of this package.
pub fn bin(name: &str) -> &'static str {
    match name {
        "snmpget" => env!("CARGO_BIN_EXE_snmpget"),
        "snmpgetnext" => env!("CARGO_BIN_EXE_snmpgetnext"),
        "snmpwalk" => env!("CARGO_BIN_EXE_snmpwalk"),
        "snmpset" => env!("CARGO_BIN_EXE_snmpset"),
        "snmptranslate" => env!("CARGO_BIN_EXE_snmptranslate"),
        "snmptrap" => env!("CARGO_BIN_EXE_snmptrap"),
        "snmptrapd" => env!("CARGO_BIN_EXE_snmptrapd"),
        "snmpd" => env!("CARGO_BIN_EXE_snmpd"),
        "snmpbulkget" => env!("CARGO_BIN_EXE_snmpbulkget"),
        "snmpbulkwalk" => env!("CARGO_BIN_EXE_snmpbulkwalk"),
        "snmptable" => env!("CARGO_BIN_EXE_snmptable"),
        "snmpstatus" => env!("CARGO_BIN_EXE_snmpstatus"),
        "snmpdelta" => env!("CARGO_BIN_EXE_snmpdelta"),
        "snmpdf" => env!("CARGO_BIN_EXE_snmpdf"),
        "snmpps" => env!("CARGO_BIN_EXE_snmpps"),
        "snmpnetstat" => env!("CARGO_BIN_EXE_snmpnetstat"),
        "snmptest" => env!("CARGO_BIN_EXE_snmptest"),
        "snmpusm" => env!("CARGO_BIN_EXE_snmpusm"),
        "snmpvacm" => env!("CARGO_BIN_EXE_snmpvacm"),
        other => panic!("unknown test binary: {other}"),
    }
}

/// Captured result of running a CLI tool to completion.
pub struct CliOutput {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CliOutput {
    /// stdout and stderr concatenated; assertions search this so they do not
    /// depend on whether a line was logged (stdout) or an error printed
    /// (stderr).
    pub fn combined(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }

    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// Assert the run succeeded, with a helpful message on failure.
    pub fn assert_success(&self, context: &str) {
        assert!(
            self.success(),
            "{context}: expected success but exit={:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.code,
            self.stdout,
            self.stderr
        );
    }

    /// Assert the run failed (non-zero exit), with a helpful message.
    pub fn assert_failure(&self, context: &str) {
        assert!(
            !self.success(),
            "{context}: expected failure but it succeeded\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.stdout,
            self.stderr
        );
    }
}

/// Run a CLI tool synchronously, isolated from any host configuration.
///
/// The child's environment is scrubbed of anything that could make the result
/// non-deterministic: `RUST_LOG=info` (so result lines at `info` are emitted),
/// and `SNMPCONFPATH` / `SNMP_PERSISTENT_DIR` / `MIBDIRS` pointed at
/// non-existent locations so no real `snmp.conf` / MIBs leak in. Pass `envs` to
/// override (e.g. to point `SNMPCONFPATH` at a fixture directory).
pub fn run(name: &str, args: &[&str], envs: &[(&str, &str)]) -> CliOutput {
    let mut cmd = Command::new(bin(name));
    cmd.args(args)
        .env("RUST_LOG", "info")
        .env("SNMPCONFPATH", "/nonexistent-netsnmp-test-conf")
        .env("SNMP_PERSISTENT_DIR", "/nonexistent-netsnmp-test-persist")
        .env("MIBDIRS", "")
        .stdin(Stdio::null());
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let out = cmd.output().expect("failed to spawn CLI binary");
    CliOutput {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Like [`run`], but feeds `stdin_data` to the child's standard input (used by
/// the interactive `snmptest` console).
pub fn run_stdin(name: &str, args: &[&str], envs: &[(&str, &str)], stdin_data: &str) -> CliOutput {
    use std::io::Write;
    let mut cmd = Command::new(bin(name));
    cmd.args(args)
        .env("RUST_LOG", "info")
        .env("SNMPCONFPATH", "/nonexistent-netsnmp-test-conf")
        .env("SNMP_PERSISTENT_DIR", "/nonexistent-netsnmp-test-persist")
        .env("MIBDIRS", "")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let mut child = cmd.spawn().expect("failed to spawn CLI binary");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(stdin_data.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait for CLI binary");
    CliOutput {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Async wrapper around [`run`] that does the blocking process I/O on the
/// blocking pool, so a concurrently-running in-process agent keeps serving.
pub async fn run_async(name: &str, args: &[&str], envs: &[(&str, &str)]) -> CliOutput {
    let name = name.to_string();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let envs: Vec<(String, String)> = envs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    tokio::task::spawn_blocking(move || {
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let env_refs: Vec<(&str, &str)> =
            envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        run(&name, &arg_refs, &env_refs)
    })
    .await
    .expect("blocking CLI task panicked")
}

/// Async wrapper around [`run_stdin`].
pub async fn run_async_stdin(
    name: &str,
    args: &[&str],
    envs: &[(&str, &str)],
    stdin_data: &str,
) -> CliOutput {
    let name = name.to_string();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let envs: Vec<(String, String)> = envs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let stdin_data = stdin_data.to_string();
    tokio::task::spawn_blocking(move || {
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let env_refs: Vec<(&str, &str)> =
            envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        run_stdin(&name, &arg_refs, &env_refs, &stdin_data)
    })
    .await
    .expect("blocking CLI task panicked")
}

/// OIDs served by the in-process test agent.
pub const SYS_DESCR: &str = "1.3.6.1.2.1.1.1.0";
pub const SYS_NAME: &str = "1.3.6.1.2.1.1.5.0";
pub const SYS_SERVICES: &str = "1.3.6.1.2.1.1.7.0";
pub const IF_DESCR: &str = "1.3.6.1.2.1.2.2.1.2";

pub const SYS_DESCR_VALUE: &str = "integration agent";
pub const SYS_NAME_VALUE: &str = "host-a";

/// Spawn an SNMP agent on an ephemeral loopback port and return its address.
///
/// Serves a handful of well-known objects: `sysDescr.0` (read-only string),
/// `sysName.0` (writable string), `sysServices.0` (writable integer), and a
/// two-row `ifDescr` column (`lo`, `eth0`).
pub async fn spawn_agent(community: &str) -> String {
    let mut reg = Registry::new();

    reg.register(Arc::new(ScalarHandler::new(
        "1.3.6.1.2.1.1.1".parse().unwrap(),
        Value::OctetString(SYS_DESCR_VALUE.as_bytes().to_vec()),
    )));
    reg.register(Arc::new(
        ScalarHandler::new(
            "1.3.6.1.2.1.1.5".parse().unwrap(),
            Value::OctetString(SYS_NAME_VALUE.as_bytes().to_vec()),
        )
        .writable(),
    ));
    reg.register(Arc::new(
        ScalarHandler::new("1.3.6.1.2.1.1.7".parse().unwrap(), Value::Integer(72)).writable(),
    ));

    let if_descr: Oid = IF_DESCR.parse().unwrap();
    reg.register(Arc::new(
        MapHandler::new(if_descr.clone())
            .with(if_descr.child(1), Value::OctetString(b"lo".to_vec()))
            .with(if_descr.child(2), Value::OctetString(b"eth0".to_vec())),
    ));

    let config = AgentConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        community: community.as_bytes().to_vec(),
        ..AgentConfig::default()
    };
    let agent = Agent::new(reg, config);
    let socket = agent.bind().await.unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let _ = agent.serve_on(socket).await;
    });
    addr
}

/// Spawn an agent serving a richer object set used by the table/status tools:
/// status scalars (`sysUpTime`, `ifNumber`, packet counters), an `ifTable`,
/// `hrStorageTable`, `hrSWRunTable`, `tcpConnTable` and `udpTable`.
pub async fn spawn_rich_agent(community: &str) -> String {
    let mut reg = Registry::new();

    // System scalars used by snmpstatus.
    reg.register(Arc::new(ScalarHandler::new(
        "1.3.6.1.2.1.1.1".parse().unwrap(),
        Value::OctetString(b"rich test agent".to_vec()),
    )));
    reg.register(Arc::new(ScalarHandler::new(
        "1.3.6.1.2.1.1.3".parse().unwrap(),
        Value::TimeTicks(12_345),
    )));
    reg.register(Arc::new(ScalarHandler::new(
        "1.3.6.1.2.1.2.1".parse().unwrap(),
        Value::Integer(2),
    )));
    reg.register(Arc::new(ScalarHandler::new(
        "1.3.6.1.2.1.11.1".parse().unwrap(),
        Value::Counter32(100),
    )));
    reg.register(Arc::new(ScalarHandler::new(
        "1.3.6.1.2.1.11.2".parse().unwrap(),
        Value::Counter32(90),
    )));

    // ifTable / ifEntry (1.3.6.1.2.1.2.2.1): columns ifIndex, ifDescr, ifType.
    let if_entry: Oid = "1.3.6.1.2.1.2.2.1".parse().unwrap();
    let mut if_map = MapHandler::new(if_entry.clone());
    for (i, descr, kind) in [(1u32, "lo", 24i64), (2, "eth0", 6)] {
        if_map = if_map
            .with(col(&if_entry, 1, i), Value::Integer(i as i64))
            .with(
                col(&if_entry, 2, i),
                Value::OctetString(descr.as_bytes().to_vec()),
            )
            .with(col(&if_entry, 3, i), Value::Integer(kind));
    }
    reg.register(Arc::new(if_map));

    // hrStorageTable / hrStorageEntry (1.3.6.1.2.1.25.2.3.1), one row.
    let storage: Oid = "1.3.6.1.2.1.25.2.3.1".parse().unwrap();
    reg.register(Arc::new(
        MapHandler::new(storage.clone())
            .with(col(&storage, 3, 1), Value::OctetString(b"/".to_vec()))
            .with(col(&storage, 4, 1), Value::Integer(1024))
            .with(col(&storage, 5, 1), Value::Integer(1000))
            .with(col(&storage, 6, 1), Value::Integer(250)),
    ));

    // hrSWRunTable / hrSWRunEntry (1.3.6.1.2.1.25.4.2.1), two rows.
    let swrun: Oid = "1.3.6.1.2.1.25.4.2.1".parse().unwrap();
    let mut sw_map = MapHandler::new(swrun.clone());
    for (i, name, path) in [(1u32, "init", "/sbin/init"), (2, "bash", "/bin/bash")] {
        sw_map = sw_map
            .with(
                col(&swrun, 2, i),
                Value::OctetString(name.as_bytes().to_vec()),
            )
            .with(
                col(&swrun, 4, i),
                Value::OctetString(path.as_bytes().to_vec()),
            )
            .with(col(&swrun, 6, i), Value::Integer(4))
            .with(col(&swrun, 7, i), Value::Integer(1));
    }
    reg.register(Arc::new(sw_map));

    // tcpConnTable / tcpConnEntry (1.3.6.1.2.1.6.13.1), one listening row.
    let tcp: Oid = "1.3.6.1.2.1.6.13.1".parse().unwrap();
    let tcp_index = [127, 0, 0, 1, 80, 0, 0, 0, 0, 0];
    reg.register(Arc::new(
        MapHandler::new(tcp.clone())
            .with(col_idx(&tcp, 1, &tcp_index), Value::Integer(2)) // listen
            .with(
                col_idx(&tcp, 2, &tcp_index),
                Value::IpAddress("127.0.0.1".parse().unwrap()),
            )
            .with(col_idx(&tcp, 3, &tcp_index), Value::Integer(80))
            .with(
                col_idx(&tcp, 4, &tcp_index),
                Value::IpAddress("0.0.0.0".parse().unwrap()),
            )
            .with(col_idx(&tcp, 5, &tcp_index), Value::Integer(0)),
    ));

    // udpTable / udpEntry (1.3.6.1.2.1.7.5.1), one listener row.
    let udp: Oid = "1.3.6.1.2.1.7.5.1".parse().unwrap();
    let udp_index = [0, 0, 0, 0, 161];
    reg.register(Arc::new(
        MapHandler::new(udp.clone())
            .with(
                col_idx(&udp, 1, &udp_index),
                Value::IpAddress("0.0.0.0".parse().unwrap()),
            )
            .with(col_idx(&udp, 2, &udp_index), Value::Integer(161)),
    ));

    let config = AgentConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        community: community.as_bytes().to_vec(),
        ..AgentConfig::default()
    };
    let agent = Agent::new(reg, config);
    let socket = agent.bind().await.unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let _ = agent.serve_on(socket).await;
    });
    addr
}

/// `entry.column.index` cell OID (scalar single-element index).
fn col(entry: &Oid, column: u32, index: u32) -> Oid {
    entry.child(column).child(index)
}

/// `entry.column.<multi-element index>` cell OID.
fn col_idx(entry: &Oid, column: u32, index: &[u32]) -> Oid {
    let mut parts = entry.as_slice().to_vec();
    parts.push(column);
    parts.extend_from_slice(index);
    Oid::new(parts)
}

/// Reserve an ephemeral UDP port on loopback and return `127.0.0.1:<port>`.
///
/// The socket is closed before returning, so a freshly-spawned process can bind
/// it. There is a small TOCTOU window, acceptable for loopback test use.
pub fn reserve_udp_addr() -> String {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    drop(sock);
    addr.to_string()
}
