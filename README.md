# net-snmp-rs

A **pure-Rust, fully-async reimplementation of the Net-SNMP protocol stack** —
the core library, an agent framework, and the full suite of `snmp*`
command-line tools, structured to mirror Net-SNMP's own three-library model.


| Crate                                   | Net-SNMP equivalent                             | Responsibility                                                                                                                                                                                                                                                                                                   |
| --------------------------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `[netsnmp](crates/netsnmp)`             | `libnetsnmp` (`snmplib/`)                       | Core protocol: OID & typed values, PDUs, message framing, SNMPv3/USM crypto, async transports (UDP/TCP/TLS), client sessions, the SMI MIB parser + name registry, and the `snmp.conf`/`snmpd.conf` parser. Wire (de)serialization is delegated to the `[rasn](https://github.com/librasn/rasn)` ASN.1 ecosystem. |
| `[netsnmp-agent](crates/netsnmp-agent)` | `libnetsnmpagent` / `libnetsnmpmibs` (`agent/`) | Handler framework, MIB-subtree registry, request dispatch, the async `snmpd` run-loop, the `snmptrapd` notification receiver, and live, **cross-platform** system-data MIB modules.                                                                                                                              |
| `[netsnmp-apps](crates/netsnmp-apps)`   | `apps/`                                         | The 19 command-line tools: `snmpget`, `snmpgetnext`, `snmpwalk`, `snmpset`, `snmpbulkget`, `snmpbulkwalk`, `snmptable`, `snmpstatus`, `snmpdelta`, `snmpdf`, `snmpps`, `snmpnetstat`, `snmptest`, `snmpusm`, `snmpvacm`, `snmptranslate`, `snmptrap`, `snmptrapd`, `snmpd`.                                      |
| `[netsnmp-itest](crates/netsnmp-itest)` | —                                               | End-to-end integration-test runner (`snmp-itest`) that drives the real compiled tools against a live agent; runs in CI and in the Docker Compose stack.                                                                                                                                                          |
| `[examples](examples)`                  | —                                               | Runnable, self-contained programs showing how to build on the libraries.                                                                                                                                                                                                                                         |


> **100% safe Rust** — every crate declares `#![forbid(unsafe_code)]`.
> **Rust 2024 edition**, MSRV **1.96.0** (uses `if let` let-chains).

### Technology choices

- **Async IO on `[tokio](https://tokio.rs)`** — UDP/TCP/TLS transports, the agent
run-loop, and even MIB-file loading are async. Filesystem work goes through
`tokio::fs`, and the MIB loader reads a directory's files **concurrently**
with a bounded `[futures](https://docs.rs/futures)` stream pipeline.
- **ASN.1 / SMI via the `[rasn](https://github.com/librasn/rasn)` ecosystem**
(`rasn`, `rasn-smi`, `rasn-snmp`) — net-snmp-rs keeps its own ergonomic domain
types and bridges them to the audited `rasn` codecs for all BER on the wire.
- `**[bytes](https://docs.rs/bytes)`** — reference-counted receive buffers avoid
re-allocating a 64 KiB scratch buffer per datagram and make slicing cheap.
- `**[sysinfo](https://docs.rs/sysinfo)**` — the live MIB modules read real OS
data through one cross-platform crate, so the agent works on Linux, macOS and
Windows (no `/proc` scraping).
- **[RustCrypto](https://github.com/RustCrypto)** (`md-5`, `sha1`, `sha2`,
`hmac`, `aes`, `cfb-mode`) for SNMPv3/USM, **[rustls](https://github.com/rustls/rustls)**
for TLS, `**thiserror`** for errors, and `**tracing**` for all output.

---

## Status & scope

A faithful, working foundation rather than a line-for-line port of all ~400k
lines of C. Implemented end-to-end:

- ✅ **ASN.1 BER** for every SNMP value type — Integer, OctetString, OID,
IpAddress, Counter32/64, Gauge32, TimeTicks, Opaque, Null, and the SNMPv2
exception markers — via the `rasn` codecs.
- ✅ **PDUs**: Get, GetNext, GetBulk, Set, Response (+ error-status/index).
- ✅ **Message framing** for **SNMPv1 / SNMPv2c** (community) and **SNMPv3**.
- ✅ **SNMPv3 / USM** (`snmpv3.c` / `snmpusm.c` / `keytools.c`):
  - `Ku`/`Kul` key derivation (RFC 3414 §A; checked against the RFC vectors)
  - Auth: **HMAC-MD5-96**, **HMAC-SHA-96**, **HMAC-192-SHA-256** (RFC 7860)
  - Privacy: **AES-128-CFB** (RFC 3826)
  - Engine discovery + time-window re-sync, HMAC verify, decrypt (RFC 3414)
- ✅ **Async transports** on tokio, with timeout/retry:
  - **UDP** (IPv4 + IPv6) — `snmpUDPDomain`
  - **TCP** — `snmpTCPDomain` (RFC 3430), with BER `SEQUENCE`-length framing
  - **TLS** — `snmpTLSTCPDomain` (RFC 6353) via **rustls** (`ring` provider,
  behind the default `tls` feature): server + optional client cert auth
- ✅ **Async client sessions**: `get` / `get_next` / `get_bulk` / `set` / `walk`
for both community (`Session`) and USM (`V3Session`), transport-agnostic with
`open_udp` / `open_tcp` / `open_tls` constructors.
- ✅ **Agent**: handler trait, scalar / in-memory-table / function handlers,
subtree registry, GET/GETNEXT/GETBULK/SET semantics, async UDP serve loop.
  - **v1/v2c** community auth
  - **v3/USM authoritative engine**: engine discovery, USM user store, HMAC
  verify + AES decrypt, RFC 3414 time-window enforcement, authenticated and
  encrypted responses, `usmStats` Reports for unknown engine/user/decrypt
- ✅ **Notifications**: build & send **SNMPv2-Trap** and confirmed
**InformRequest** (auto `sysUpTime.0` / `snmpTrapOID.0`) over community v2c or
**v3/USM** (auth+priv); the `TrapReceiver` decodes, authenticates, decrypts
and acknowledges informs.
- ✅ **SMI MIB-file parser** (`parse.c`): loads real `mibs/*.txt`, resolves
names↔OIDs across modules and extracts INTEGER enumerations (parses the full
upstream distribution — **~3286 objects**). Directory loads read files
**concurrently** via `tokio::fs` + `futures`.
- ✅ **Live, cross-platform system-data MIBs** (via `sysinfo`):
  - mibII **system** group
  - **IF-MIB** `ifNumber`, `ifTable`, and the high-capacity `ifXTable`
  - **HOST-RESOURCES** `hrSystem`, `hrStorageTable`, `hrDeviceTable`,
  `hrSWRunTable` / `hrSWRunPerfTable`
  - **UCD-SNMP-MIB** load averages, memory, per-filesystem usage and CPU summary
- ✅ **Config files** (`read_config.c`): a `snmp.conf`/`snmpd.conf`-compatible
parser — quote/`\`-escape tokenizing, whole-line `#` comments, `[section]`
contexts, `includeFile`/`includeDir`/`includeSearch`, and the `SNMPCONFPATH`
search path. Clients honor `defVersion`/`defCommunity`/`def`* v3 defaults and
`mibdirs`; `snmpd` honors `rocommunity`/`rwcommunity`/`sysLocation`/
`sysContact`/`agentAddress`/`createUser`. Precedence: **CLI > conf > built-in**.
- ✅ **CLI tools** with familiar Net-SNMP option syntax, plus modern conveniences:
every flag has a **short and a long form**, common ones read an **environment
variable** (e.g. `SNMP_COMMUNITY`, `MIBDIRS`), `snmpwalk`/`snmpbulkwalk`
**stream results as they arrive**, and `snmptranslate -Tl` dumps every loaded
OID.
- ✅ **Unit + integration + doc tests**: community and v3/USM client↔agent
loopback over UDP, v2c/v3 trap & inform loopback, TCP & TLS end-to-end
(self-signed handshake + untrusted-cert rejection), RFC 3414 key vectors,
config-parser tests, a real `mibs/*.txt` parse test, and **CLI end-to-end
tests that run the actual compiled tools** against an in-process agent.

Deliberately **out of scope** for this foundation:

- ⛔ **VACM** view-based access control enforcement (`vacm.c`) — the agent does
community/USM authentication but not per-view ACLs (the `snmpvacm` *client*
for managing remote agents is provided).
- ⛔ **DES** privacy (legacy/insecure — only AES-128-CFB is provided).
- 🟡 **SMI semantic checks** — names/OIDs/enums are parsed, but type/range/SIZE
validation, TEXTUAL-CONVENTION display hints, and INDEX semantics are not.
- 🟡 **Transports**: UDP/TCP/TLS are implemented; **DTLS** and **SSH/Unix/IPX**
are not.
- ⛔ **RFC 6353 Transport Security Model (TSM)** — TLS provides the secure
channel, but `tlstmCertToTSN` certificate→securityName mapping is not modelled.
- 🟡 Most concrete **MIB modules** beyond the system/IF/HOST-RESOURCES/UCD
subsets above.
- ⛔ Language bindings (`perl/`, `python/`).

---

## Layout

```
net-snmp-rs/
├── Cargo.toml                  # workspace
├── Justfile                    # build / test / docker task runner
├── Dockerfile                  # copy-only image: static musl binaries -> alpine
├── docker-compose.yml          # snmpd agent + snmp-itest tester stack
├── examples/                   # runnable library examples (crate: netsnmp-examples)
├── mibs/                       # bundled Net-SNMP MIB text files
└── crates/
    ├── netsnmp/                # core library (libnetsnmp)
    │   └── src/
    │       ├── oid.rs          # Oid type
    │       ├── value.rs        # typed values
    │       ├── convert.rs      # domain <-> rasn wire-type bridges
    │       ├── pdu.rs          # PDU & varbind
    │       ├── message.rs      # v1/v2c framing
    │       ├── usm/            # USM crypto: level/auth/privacy/user
    │       ├── v3/             # v3 messages: wire/types/build/parse
    │       ├── transport.rs    # async UDP/TCP + BER framing (bytes buffers)
    │       ├── tls.rs          # TLS secure channel
    │       ├── session/        # async client + V3Session
    │       ├── smi/            # SMI MIB parser: lex/parse/resolve
    │       ├── config/         # snmp.conf/snmpd.conf parser
    │       └── mib.rs          # name registry + value formatting (async loader)
    ├── netsnmp-agent/          # agent framework (libnetsnmpagent)
    │   └── src/
    │       ├── handler.rs       # MibHandler trait
    │       ├── scalar.rs        # scalar / table / fn helpers
    │       ├── registry.rs      # dispatch
    │       ├── agent.rs         # serve loop (snmpd)
    │       ├── trap/            # notification receiver (snmptrapd)
    │       └── mibgroup/        # live system-data MIBs (via sysinfo)
    │           ├── collector.rs # shared, throttled sysinfo snapshot
    │           ├── system.rs    # mibII system group
    │           ├── interfaces.rs# IF-MIB ifTable + ifXTable
    │           ├── host.rs      # HOST-RESOURCES tables
    │           └── ucd.rs       # UCD-SNMP-MIB
    ├── netsnmp-apps/           # CLI tools (apps/) — src/bin/snmp*.rs
    └── netsnmp-itest/          # end-to-end CLI integration runner (snmp-itest)
```

---

## Build & test

The workspace targets the **Rust 2024 edition** with an MSRV of **1.96.0**
(declared in the workspace `Cargo.toml`).

```bash
cd net-snmp-rs
cargo build --release       # build all crates + binaries
cargo test --workspace      # unit + integration + doctests
cargo clippy --all-targets  # lint (clean)
```

### Task runner (`just`)

A `[Justfile](Justfile)` wraps the common workflows. Run `just` with no
arguments to list every recipe:


| Command                    | What it does                                                                                                                  |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `just check`               | Local CI gate: `build`, `fmt`, `check`, `clippy -D warnings`, `doc`, and the full `cargo test --workspace --locked`.          |
| `just build-musl`          | Build static `x86_64-unknown-linux-musl` release binaries (installs the target on demand).                                    |
| `just docker-build`        | `build-musl`, then assemble the copy-only Docker image via `docker compose build`.                                            |
| `just docker-build-mirror` | Like `docker-build` but passes an `apk` mirror (`APK_MIRROR`) for faster builds in some regions.                              |
| `just docker-up`           | Build and start the `snmpd` agent container (detached).                                                                       |
| `just docker-test`         | Build, then run the `snmp-itest` integration suite in containers; the test exit code is propagated (CI fails on any failure). |
| `just docker-down`         | Stop and remove the compose stack (containers, network, volumes).                                                             |
| `just clean`               | `cargo clean` and tear down any running docker stack.                                                                         |


The container image performs **no compilation**: `build-musl` produces fully
static binaries on the host that are copied onto a minimal `alpine` base (see
`[Dockerfile](Dockerfile)`). MIB and config files for the agent live under
`[docker/etc-snmp](docker/etc-snmp)`.

---

## Logging

All output and diagnostics go through `[tracing](https://docs.rs/tracing)` (no
`println!`/`eprintln!`). Tool results and status are at `info`, protocol detail
at `debug`/`trace`, failures at `error`. Verbosity is controlled by `RUST_LOG`
(default `info`):

```bash
snmpget -c public 127.0.0.1:11611 sysDescr.0                  # info: just the result
RUST_LOG=debug snmpget -c public 127.0.0.1:11611 sysDescr.0   # + request lifecycle
# scope trace to the library while keeping result rows at info:
RUST_LOG=info,netsnmp=trace snmpwalk -c public 127.0.0.1:11611 system
```

## Try it

Start the agent (serves live, cross-platform system data on UDP):

```bash
./target/release/snmpd 127.0.0.1:11611        # community defaults to "public"
```

In another shell:

```bash
# GET scalars — real OS description and host name
./target/release/snmpget -c public 127.0.0.1:11611 sysDescr.0 sysName.0

# WALK subtrees (results stream as they arrive)
./target/release/snmpwalk -c public 127.0.0.1:11611 system
./target/release/snmpwalk -c public 127.0.0.1:11611 1.3.6.1.2.1.2.2   # ifTable
./target/release/snmpwalk -c public 127.0.0.1:11611 ifDescr

# Real memory / storage figures (HOST-RESOURCES / UCD-SNMP-MIB)
./target/release/snmpget -c public 127.0.0.1:11611 1.3.6.1.2.1.25.2.2.0

# SET a writable object, then read it back
./target/release/snmpset -c public 127.0.0.1:11611 sysName.0 s rust-box
./target/release/snmpget -c public 127.0.0.1:11611 sysName.0
# sysName.0 = STRING: rust-box

# SNMPv3 with auth + privacy (USM). Start snmpd with a v3 user:
#   ./target/release/snmpd -u myuser -a SHA -A authpassword \
#       -x AES -X privpassword 127.0.0.1:11611
# then query it (the client performs engine discovery automatically):
./target/release/snmpget -v 3 -u myuser \
    -a SHA -A authpassword -x AES -X privpassword -l authPriv \
    127.0.0.1:11611 sysDescr.0

# Notifications: receive with snmptrapd, send with snmptrap
./target/release/snmptrapd -c public -u notifier -a SHA-256 -A authpassword \
    -x AES -X privpassword 127.0.0.1:1162 &
./target/release/snmptrap -v 2c -c public 127.0.0.1:1162 \
    1000 1.3.6.1.6.3.1.1.5.1 sysName.0 s sensor-A
./target/release/snmptrap -v 2c -c public --inform 127.0.0.1:1162 2000 coldStart
./target/release/snmptrap -v 3 -u notifier -a SHA-256 -A authpassword \
    -x AES -X privpassword -l authPriv \
    127.0.0.1:1162 3000 1.3.6.1.6.3.1.1.5.1 sysLocation.0 s rack-9

# GETBULK: many variables per round-trip (v2c/v3)
./target/release/snmpbulkget  -c public --max-repetitions 10 127.0.0.1:11611 ifDescr
./target/release/snmpbulkwalk -c public 127.0.0.1:11611 1.3.6.1.2.1.2.2

# Tabular / status / disk / process / netstat views
./target/release/snmptable    -c public 127.0.0.1:11611 1.3.6.1.2.1.2.2.1
./target/release/snmpstatus   -c public 127.0.0.1:11611
./target/release/snmpdelta    -c public --period 1 --iterations 5 127.0.0.1:11611 ifInOctets.2
./target/release/snmpdf       -c public 127.0.0.1:11611
./target/release/snmpps       -c public 127.0.0.1:11611
./target/release/snmpnetstat  -c public --protocol tcp 127.0.0.1:11611

# Interactive console: type OIDs (or $G/$N/$S/$q) on stdin
echo -e "sysDescr.0\n\$N\nifDescr\n\$q" | ./target/release/snmptest -c public 127.0.0.1:11611

# Offline name<->OID translation (no network)
./target/release/snmptranslate sysDescr.0          # -> sysDescr.0
./target/release/snmptranslate -On sysName.0       # -> .1.3.6.1.2.1.1.5.0

# Load the real MIB files for full symbolic coverage (-M dir, or MIBDIRS env)
./target/release/snmptranslate -M ./mibs ifOperStatus           # -> ifOperStatus
./target/release/snmptranslate -M ./mibs -On tcpConnState       # -> .1.3.6.1.2.1.6.13.1.1
./target/release/snmptranslate -Tl -M ./mibs                    # dump every loaded OID
```

Configuration files (`snmp.conf` / `snmpd.conf`, found via `SNMPCONFPATH`, else
`/etc/snmp`, `/usr/share/snmp`, `/usr/lib/snmp`, `$HOME/.snmp`):

```bash
export SNMPCONFPATH=/etc/snmp

# /etc/snmp/snmpd.conf — agent settings
cat > /etc/snmp/snmpd.conf <<'EOF'
rocommunity s3cr3t
syslocation "Rack 9, Server Room"
syscontact ops@example.org
createUser alice SHA authpass AES privpass    # same as: snmpd -u alice -a SHA ...
EOF

# /etc/snmp/snmp.conf — client defaults
cat > /etc/snmp/snmp.conf <<'EOF'
defVersion 2c
defCommunity s3cr3t
EOF

./target/release/snmpd 127.0.0.1:11611                   # picks up rocommunity / sysLocation / createUser
./target/release/snmpget 127.0.0.1:11611 sysLocation.0   # uses defCommunity (no -c needed)
```

---

## Library usage

All IO is async (`tokio`).

```rust
use netsnmp::{Session, SessionConfig, Oid};

# async fn run() -> Result<(), netsnmp::Error> {
let session = Session::open_udp("127.0.0.1:161", SessionConfig::default()).await?;
let oid: Oid = "1.3.6.1.2.1.1.1.0".parse()?;
tracing::info!("sysDescr.0 = {}", session.get_one(&oid).await?);
# Ok(())
# }
```

The same session API runs over TCP (`snmpTCPDomain`) or a TLS secure channel
(`snmpTLSTCPDomain`) — only the constructor changes:

```rust
use netsnmp::{Session, SessionConfig, Oid, TlsClient};

# async fn run(ca_pem: &[u8]) -> Result<(), netsnmp::Error> {
let tcp = Session::open_tcp("127.0.0.1:161", SessionConfig::default()).await?;

// TLS: trust the peer's CA (or a pinned self-signed cert) and validate its name.
let client = TlsClient::from_root_ca_pem("agent.example.org", ca_pem)?;
let tls = Session::open_tls(&client, "agent.example.org:10161", SessionConfig::default()).await?;

let oid: Oid = "1.3.6.1.2.1.1.1.0".parse()?;
tracing::info!("over TLS: {}", tls.get_one(&oid).await?);
# let _ = tcp;
# Ok(())
# }
```

SNMPv3 / USM (engine discovery happens automatically on `open_udp`):

```rust
use std::time::Duration;
use netsnmp::{Oid, V3Session, UsmUser, AuthProtocol, PrivProtocol};

# async fn run() -> Result<(), netsnmp::Error> {
let user = UsmUser::auth_priv(
    "myuser",
    AuthProtocol::HmacSha1, "authpassword",
    PrivProtocol::AesCfb128, "privpassword",
);
let mut session = V3Session::open_udp("127.0.0.1:161", user, Duration::from_secs(5), 2).await?;
let oid: Oid = "1.3.6.1.2.1.1.1.0".parse()?;
tracing::info!("sysDescr.0 = {}", session.get_one(&oid).await?);
# Ok(())
# }
```

Loading MIBs (the directory is read concurrently via `tokio::fs`):

```rust
use netsnmp::mib::MibRegistry;

# async fn run() -> std::io::Result<()> {
let mut mib = MibRegistry::with_builtins();
let added = mib.load_dir("./mibs").await?;     // parse every *.txt MIB
tracing::info!("{added} objects");              // ~3286 for the full distribution
let _oid = mib.name_to_oid("ifOperStatus").unwrap();
# Ok(())
# }
```

Building an agent:

```rust
use std::sync::Arc;
use netsnmp_agent::{Agent, AgentConfig, Registry, ScalarHandler};
use netsnmp::value::Value;

# async fn run() -> Result<(), netsnmp::Error> {
let mut registry = Registry::new();
registry.register(Arc::new(ScalarHandler::new(
    "1.3.6.1.2.1.1.1".parse().unwrap(),
    Value::OctetString(b"my agent".to_vec()),
)));
Agent::new(registry, AgentConfig::default()).serve_forever().await?;
# Ok(())
# }
```

## Examples

The `[examples/](examples)` directory holds runnable programs that build on the
`netsnmp` / `netsnmp-agent` libraries. Run any of them with:

```bash
cargo run -p netsnmp-examples --example <name>
```


| Example          | What it demonstrates                                                                                                                                                                                                        |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `loopback`       | **Start here.** Self-contained: builds a custom agent (scalar + writable + table handlers), serves it on an ephemeral port, then drives GET / WALK / SET via the client `Session` — the full loop in one process, no setup. |
| `client`         | Community (v1/v2c) client against a live agent: `get` / `get_next` / `walk`. Args: `<agent> [community]`.                                                                                                                   |
| `v3_client`      | SNMPv3/USM client (authPriv) with automatic engine discovery via `V3Session`. Args: `<agent> <user> <authPass> <privPass>`.                                                                                                 |
| `bulkwalk`       | `GETBULK` for many rows per round-trip, plus a `snmpbulkwalk`-style loop.                                                                                                                                                   |
| `agent`          | A standalone agent: installs the live system-data MIBs plus a custom enterprise object, then `serve_forever`.                                                                                                               |
| `trap_roundtrip` | Self-contained notifications: runs a `TrapReceiver` in the background and sends it a v2c trap and a confirmed inform.                                                                                                       |
| `mib`            | Offline `MibRegistry` use: name↔OID translation and pretty-printing. Optionally pass a MIB directory to load.                                                                                                               |
| `asn1`           | Wire-level work: build/parse full `Message`/`Pdu`/`Value`s (BER via `rasn`) and inspect the bytes.                                                                                                                          |


`loopback`, `trap_roundtrip`, `mib` and `asn1` need no network; the rest connect
to an agent (start one with the `agent` example or `snmpd`).

---

## CLI option compatibility

Every client tool accepts the common Net-SNMP options. Each flag has a short and
a long form, and the most-used ones also read an environment variable (CLI value
wins over env). Where an option is omitted entirely, the client falls back to
`snmp.conf` and then the built-in default — **command line > env > snmp.conf >
built-in**.


| Short | Long                | Env                    | Meaning                                               | Default  |
| ----- | ------------------- | ---------------------- | ----------------------------------------------------- | -------- |
| `-v`  | `--version`         | `SNMP_VERSION`         | protocol version `1`/`2c`/`3`                         | `2c`     |
| `-c`  | `--community`       | `SNMP_COMMUNITY`       | community string (v1/v2c)                             | `public` |
| `-u`  | `--user`            | `SNMP_SECNAME`         | USM security name (v3)                                | —        |
| `-a`  | `--auth-protocol`   | —                      | USM auth: `MD5`/`SHA`/`SHA-256` (v3)                  | `SHA`    |
| `-A`  | `--auth-passphrase` | `SNMP_AUTH_PASSPHRASE` | USM auth passphrase (v3)                              | —        |
| `-x`  | `--priv-protocol`   | —                      | USM privacy: `AES` (v3)                               | `AES`    |
| `-X`  | `--priv-passphrase` | `SNMP_PRIV_PASSPHRASE` | USM privacy passphrase (v3)                           | —        |
| `-l`  | `--level`           | —                      | security level `noAuthNoPriv`/`authNoPriv`/`authPriv` | inferred |
| `-t`  | `--timeout`         | `SNMP_TIMEOUT`         | per-request timeout (seconds)                         | `5`      |
| `-r`  | `--retries`         | `SNMP_RETRIES`         | retries after the first try                           | `2`      |
| `-M`  | `--mib-dirs`        | `MIBDIRS`              | MIB directories to load (`:`/`,` lists)               | none     |


`snmp.conf` keys consulted as fallbacks: `defVersion`, `defCommunity`,
`defSecurityName`, `defAuthType`/`defAuthPassphrase`,
`defPrivType`/`defPrivPassphrase`, `defSecurityLevel`, `mibdirs`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))
- MIT license ([LICENSE-MIT](LICENSE-MIT) or [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.