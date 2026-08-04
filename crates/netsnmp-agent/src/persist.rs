//! Persistence layer for writable agent state.
//!
//! Counterpart of Net-SNMP's `read_config.c` PERSISTENT mechanism: writable
//! scalars (`sysContact`/`sysName`/`sysLocation`) and `snmpEngineBoots` survive
//! agent restarts by being serialized to a file in the persistent directory and
//! replayed at startup.
//!
//! # Design
//!
//! Each piece of persistable state implements [`Persistable`]: it advertises a
//! `key` (used as the directive token and, for engine boots, the file name) and
//! can [`Persistable::snapshot`] itself as a list of
//! [`Directive`](netsnmp::config::Directive)s and
//! [`Persistable::restore`] from a list. A [`Persistence`] registry owns a set
//! of `Arc<dyn Persistable>` items and writes/reads a single
//! `snmpd.persist` file containing every item's directives, one per line.
//!
//! The on-disk format is plain `snmpd.conf`-style lines (`token args...`),
//! parsed back with [`netsnmp::config::parse::parse_str`]. Each item claims the
//! directives whose token equals its `key`. The format is intentionally simple
//! and self-consistent (round-trippable), not a faithful reproduction of
//! net-snmp's per-engine `.conf` files.
//!
//! # Engine boots
//!
//! [`EngineBootsPersistable`] (and the free functions
//! [`load_engine_boots`]/[`save_engine_boots`]) persist a single integer in
//! `<engine_id_hex>.boots`. On load the stored value is returned as-is; the
//! caller is expected to increment it on a *clean* startup and write it back on
//! a clean shutdown. Detecting a crash (and thus withholding the increment) is
//! not modelled here — see the module-level docs of [`EngineBootsPersistable`].

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use netsnmp::config::Directive;
use netsnmp::value::Value;
use tracing::{debug, warn};

use crate::scalar::ScalarHandler;

/// The default file name (under the persistent directory) holding all scalar
/// persistence directives.
const PERSIST_FILE: &str = "snmpd.persist";

/// A piece of agent state that can be saved to and restored from the
/// persistent directory.
///
/// Implementors advertise a `key` (the directive token they own) and provide a
/// [`Persistable::snapshot`]/[`Persistable::restore`] pair. The format is
/// self-consistent: whatever `snapshot` emits must be parseable by the config
/// parser and consumable by `restore`.
pub trait Persistable: Send + Sync {
    /// The directive token this item claims (e.g. `"sysContact"`). Directives
    /// in the persist file whose token equals this are routed to
    /// [`Persistable::restore`].
    fn key(&self) -> &str;

    /// Snapshot the current state as a list of directives. Each directive's
    /// token should equal [`key`](Persistable::key) so it round-trips.
    fn snapshot(&self) -> Vec<Directive>;

    /// Restore state from the directives addressed to this item (those whose
    /// token equals [`key`](Persistable::key)).
    fn restore(&self, dirs: &[Directive]);
}

/// A registry of [`Persistable`] items that loads/saves them all from/to one
/// file in the persistent directory.
///
/// Created once per agent and shared (via [`Arc`]) between the startup load
/// path and the on-shutdown save path. The directory is *not* created here;
/// callers should ensure it exists (or accept that [`Persistence::save`] will
/// fail with `NotFound`).
pub struct Persistence {
    dir: PathBuf,
    items: RwLock<Vec<Arc<dyn Persistable>>>,
}

impl std::fmt::Debug for Persistence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.items.read().unwrap_or_else(|e| e.into_inner()).len();
        f.debug_struct("Persistence")
            .field("dir", &self.dir)
            .field("items", &format!("{count} persistable(s)"))
            .finish()
    }
}

impl Persistence {
    /// Create a persistence registry rooted at `dir`. The directory need not
    /// exist yet; [`Persistence::save`] will create it (best-effort).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Persistence {
            dir: dir.into(),
            items: RwLock::new(Vec::new()),
        }
    }

    /// Register a persistable item. Items added after [`Persistence::load`] ran
    /// will take part in the next [`Persistence::save`].
    pub fn register(&self, item: Arc<dyn Persistable>) {
        let mut items = self.items.write().unwrap_or_else(|e| e.into_inner());
        // Replace an existing item with the same key (last-writer-wins) so a
        // restart that rebuilds handlers doesn't accumulate duplicates.
        if let Some(slot) = items
            .iter_mut()
            .find(|i| i.key() == item.key())
        {
            *slot = item;
        } else {
            items.push(item);
        }
    }

    /// The persistent directory this registry writes to.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Save every registered item to `<dir>/snmpd.persist`, one directive per
    /// line. The file is written atomically: a temp file is filled then
    /// renamed over the target. Returns `Ok(())` even if there are no items
    /// (the file is still created, empty, so a later load is a no-op).
    pub fn save(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let items = self.items.read().unwrap_or_else(|e| e.into_inner());
        let mut text = String::new();
        for item in items.iter() {
            for dir in item.snapshot() {
                text.push_str(&serialize_directive(&dir));
                text.push('\n');
            }
        }
        let target = self.dir.join(PERSIST_FILE);
        let tmp = self.dir.join(format!("{PERSIST_FILE}.tmp"));
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &target)?;
        debug!(path = %target.display(), items = items.len(), "persisted agent state");
        Ok(())
    }

    /// Load and replay every directive in `<dir>/snmpd.persist` into the
    /// matching registered items. Missing file is `Ok(())` (fresh start);
    /// unparseable lines are warned and skipped. Directives whose token matches
    /// no registered item are silently ignored.
    pub fn load(&self) -> io::Result<()> {
        let path = self.dir.join(PERSIST_FILE);
        let Ok(content) = std::fs::read_to_string(&path) else {
            // No prior state: nothing to restore.
            return Ok(());
        };
        let directives = netsnmp::config::parse_str(&content);
        let items = self.items.read().unwrap_or_else(|e| e.into_inner());
        for item in items.iter() {
            let owned: Vec<Directive> = directives
                .iter()
                .filter(|d| d.token == item.key())
                .cloned()
                .collect();
            if owned.is_empty() {
                continue;
            }
            item.restore(&owned);
        }
        debug!(path = %path.display(), directives = directives.len(), "restored agent state");
        Ok(())
    }
}

/// The persistent directory honoured by the agent: the `SNMP_PERSISTENT_DIR`
/// environment variable if set, otherwise `/var/lib/snmp` (matching Net-SNMP's
/// `get_persistent_directory` and the `DEFAULT_PERSISTENT_DIR` constant in
/// `netsnmp::config::search`).
pub fn default_persistent_dir() -> PathBuf {
    match std::env::var("SNMP_PERSISTENT_DIR") {
        Ok(s) if !s.is_empty() => PathBuf::from(s),
        _ => PathBuf::from("/var/lib/snmp"),
    }
}

/// Serialize a [`Directive`] as a single `snmpd.conf`-style line (without the
/// trailing newline). Arguments are joined with spaces; any argument containing
/// whitespace or a quote is double-quoted with `\`-escapes so the line is
/// round-trippable by [`parse_words`].
fn serialize_directive(dir: &Directive) -> String {
    let mut out = String::new();
    out.push_str(&dir.token);
    for arg in &dir.args {
        out.push(' ');
        out.push_str(&quote_word(arg));
    }
    out
}

/// Quote a single argument word for round-trip parsing. Bare words (no
/// whitespace, quotes or backslashes) are emitted verbatim; everything else is
/// wrapped in double quotes with `\` escapes for `"`, `\` and newline.
fn quote_word(s: &str) -> String {
    let needs_quote = s.is_empty()
        || s.chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '\'' || c == '\\');
    if !needs_quote {
        return s.to_string();
    }
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' | '\\' | '\n' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A [`Persistable`] wrapper around a [`ScalarHandler`].
///
/// Snapshots the scalar's current [`Value`] as a `scalar <key> <type> <value>`
/// directive and restores it by parsing that triple back. The value encoding
/// covers every [`Value`] variant; see [`encode_value`]/[`decode_value`].
pub struct ScalarPersistable {
    key: String,
    handler: Arc<ScalarHandler>,
}

impl ScalarPersistable {
    /// Wrap `handler` so its value persists under `key` (e.g. `"sysContact"`).
    pub fn new(key: impl Into<String>, handler: Arc<ScalarHandler>) -> Arc<Self> {
        Arc::new(ScalarPersistable {
            key: key.into(),
            handler,
        })
    }
}

impl Persistable for ScalarPersistable {
    fn key(&self) -> &str {
        &self.key
    }

    fn snapshot(&self) -> Vec<Directive> {
        let value = self.handler.get_value();
        let (type_tag, encoded) = encode_value(&value);
        let encoded = encoded.to_string();
        vec![Directive {
            token: self.key.clone(),
            args: vec![type_tag.to_string(), encoded.clone()],
            rest: format!("{type_tag} {encoded}"),
            section: None,
            source: None,
            line_no: 0,
        }]
    }

    fn restore(&self, dirs: &[Directive]) {
        for d in dirs {
            // Expect `<key> <type> <value>`; tolerate `<key> <value>` (treat
            // the sole arg as an OctetString, the most common scalar type).
            let args = &d.args;
            let (type_tag, encoded) = match args.len() {
                0 => continue,
                1 => ("s", args[0].as_str()),
                _ => (args[0].as_str(), args[1].as_str()),
            };
            if let Some(value) = decode_value(type_tag, encoded) {
                self.handler.set_value(value);
            } else {
                warn!(key = %self.key, type_tag, "unrecognized persisted scalar value, skipping");
            }
        }
    }
}

/// Persist `snmpEngineBoots` as its own small `<engine_id_hex>.boots` file
/// containing a single integer.
///
/// This implements [`Persistable`] with the key `engineBoots` but writes a
/// *separate* file rather than a line in `snmpd.persist`, because engine boots
/// is keyed by engine ID (one file per authoritative engine) and is consulted
/// before the registry of scalar items exists. The convenience free functions
/// [`load_engine_boots`] and [`save_engine_boots`] do the file I/O directly;
/// this struct wraps an `Arc<RwLock<u32>>` so the live agent can update the
/// counter and a single [`Persistence::save`] flushes it.
///
/// # Clean-shutdown detection
///
/// Net-SNMP increments `snmpEngineBoots` only on a *clean* restart: a
/// crash-then-restart leaves the counter unchanged so peers notice the
/// out-of-window state. This implementation does **not** model that: the
/// stored value is whatever was last written via [`EngineBootsPersistable::set`]
/// (or read at startup plus one — see [`EngineBootsPersistable::load_and_bump`]).
/// Callers wanting strict RFC 3414 §2.1.2 semantics should arrange their own
/// "previous shutdown was clean" marker (e.g. a sentinel file removed on
/// clean exit) before bumping.
pub struct EngineBootsPersistable {
    boots: Arc<RwLock<u32>>,
    engine_id: Vec<u8>,
}

impl EngineBootsPersistable {
    /// Create a new wrapper holding `engine_id` and an initial `boots` value.
    pub fn new(engine_id: Vec<u8>, boots: u32) -> Arc<Self> {
        Arc::new(EngineBootsPersistable {
            boots: Arc::new(RwLock::new(boots)),
            engine_id,
        })
    }

    /// Shared handle to the boots counter, so the agent's v3 path and the
    /// persistence path see the same value.
    pub fn handle(&self) -> Arc<RwLock<u32>> {
        Arc::clone(&self.boots)
    }

    /// Read the persisted boots value from `<dir>/<engine_id_hex>.boots` and
    /// return it, incrementing by one to model a clean restart. If the file is
    /// absent or unreadable, returns the supplied `fallback` (typically `1`).
    pub fn load_and_bump(dir: &Path, engine_id: &[u8], fallback: u32) -> u32 {
        let stored = load_engine_boots(dir, engine_id).unwrap_or(fallback);
        stored.saturating_add(1)
    }

    /// Set the in-memory boots counter (e.g. from the loaded value).
    pub fn set(&self, boots: u32) {
        *self.boots.write().unwrap_or_else(|e| e.into_inner()) = boots;
    }

    /// The current in-memory boots counter.
    pub fn get(&self) -> u32 {
        *self.boots.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Write the current boots counter to `<dir>/<engine_id_hex>.boots`, using
    /// this wrapper's stored engine ID. Convenience wrapper over
    /// [`save_engine_boots`].
    pub fn save_to(&self, dir: &Path) -> io::Result<()> {
        save_engine_boots(dir, &self.engine_id, self.get())
    }

    /// The engine ID this wrapper persists boots for.
    pub fn engine_id(&self) -> &[u8] {
        &self.engine_id
    }
}

impl Persistable for EngineBootsPersistable {
    fn key(&self) -> &str {
        "engineBoots"
    }

    fn snapshot(&self) -> Vec<Directive> {
        let boots = self.get();
        vec![Directive {
            token: "engineBoots".to_string(),
            args: vec![boots.to_string()],
            rest: boots.to_string(),
            section: None,
            source: None,
            line_no: 0,
        }]
    }

    fn restore(&self, dirs: &[Directive]) {
        for d in dirs {
            if let Some(arg) = d.arg(0)
                && let Ok(b) = arg.parse::<u32>()
            {
                self.set(b);
            }
        }
    }
}

/// The hex-encoded file name used to persist `snmpEngineBoots` for `engine_id`:
/// `<engine_id_hex>.boots`.
pub fn engine_boots_file(dir: &Path, engine_id: &[u8]) -> PathBuf {
    dir.join(format!("{}.boots", hex_encode(engine_id)))
}

/// Read the persisted `snmpEngineBoots` for `engine_id` from
/// `<dir>/<engine_id_hex>.boots`. Returns `None` if the file is absent or
/// unparseable (a fresh engine).
pub fn load_engine_boots(dir: &Path, engine_id: &[u8]) -> Option<u32> {
    let path = engine_boots_file(dir, engine_id);
    let content = std::fs::read_to_string(&path).ok()?;
    let trimmed = content.trim();
    let boots = trimmed.parse::<u32>().ok()?;
    Some(boots)
}

/// Write `boots` to `<dir>/<engine_id_hex>.boots` (atomic temp-then-rename).
pub fn save_engine_boots(dir: &Path, engine_id: &[u8], boots: u32) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let target = engine_boots_file(dir, engine_id);
    let tmp = dir.join(format!("{}.boots.tmp", hex_encode(engine_id)));
    {
        let mut f = std::fs::File::create(&tmp)?;
        writeln!(f, "{boots}")?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &target)?;
    Ok(())
}

/// Lowercase hex encoding of a byte slice (no `0x` prefix). Used to build a
/// safe file name from an opaque engine ID.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Encode a [`Value`] as a `(type_tag, string)` pair for the persist file.
///
/// The tags are short mnemonic codes (`s`/`i`/`u`/`c`/`t`/`o`/`a`/`x`/`6`)
/// mirroring `snmpcmd`'s `-TYPE` notation where useful. Octet strings that are
/// printable UTF-8 are stored as `s "..."` (quoted so spaces survive); binary
/// octet strings fall back to `x` hex.
fn encode_value(value: &Value) -> (&'static str, String) {
    match value {
        Value::OctetString(b) => {
            // Prefer the human-readable `s` form when the bytes are printable
            // UTF-8 with no control characters. Newlines/tabs would break the
            // one-line-per-directive format or be mangled by `read_word`'s
            // escape handling, so such values fall back to `x`. Quotes and
            // backslashes are fine here: `quote_word` escapes them.
            if let Ok(s) = std::str::from_utf8(b)
                && s.chars().all(|c| !c.is_control())
            {
                ("s", s.to_string())
            } else {
                ("x", b.iter().map(|b| format!("{b:02x}")).collect::<String>())
            }
        }
        Value::Integer(v) => ("i", v.to_string()),
        Value::Counter32(v) => ("c", v.to_string()),
        Value::Gauge32(v) => ("u", v.to_string()),
        Value::TimeTicks(v) => ("t", v.to_string()),
        Value::Counter64(v) => ("6", v.to_string()),
        Value::Oid(o) => ("o", o.to_string()),
        Value::IpAddress(ip) => ("a", ip.to_string()),
        Value::Opaque(b) => ("x", b.iter().map(|b| format!("{b:02x}")).collect::<String>()),
        Value::Null => ("n", String::new()),
        // Exceptions are not meaningfully persistable: store Null so a restore
        // leaves the scalar empty rather than corrupting it.
        Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView => ("n", String::new()),
    }
}

/// Decode a `(type_tag, string)` pair back into a [`Value`]. Returns `None`
/// for an unrecognized tag or a malformed payload (the caller logs and skips).
fn decode_value(type_tag: &str, payload: &str) -> Option<Value> {
    match type_tag {
        "s" => Some(Value::OctetString(payload.as_bytes().to_vec())),
        "x" => {
            let hex = payload.replace(' ', "");
            if hex.len() % 2 != 0 {
                return None;
            }
            let bytes: Option<Vec<u8>> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
                .collect();
            Some(Value::OctetString(bytes?))
        }
        "i" => payload.parse::<i64>().ok().map(Value::Integer),
        "c" => payload.parse::<u32>().ok().map(Value::Counter32),
        "u" => payload.parse::<u32>().ok().map(Value::Gauge32),
        "t" => payload.parse::<u32>().ok().map(Value::TimeTicks),
        "6" => payload.parse::<u64>().ok().map(Value::Counter64),
        "o" => payload.parse().ok().map(Value::Oid),
        "a" => payload.parse().ok().map(Value::IpAddress),
        "n" => Some(Value::Null),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netsnmp::oid::Oid;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netsnmp-persist-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn scalar_round_trip_through_file() {
        let dir = temp_dir();
        let root: Oid = "1.3.6.1.2.1.1.4".parse().unwrap();
        let handler = Arc::new(
            ScalarHandler::new(root.clone(), Value::OctetString(b"old".to_vec())).writable(),
        );
        handler.set_value(Value::OctetString(b"ops <ops@example.org>".to_vec()));

        // Save.
        let p1 = Persistence::new(&dir);
        p1.register(ScalarPersistable::new("sysContact", Arc::clone(&handler)));
        p1.save().unwrap();

        // The file is parseable by the config parser.
        let text = std::fs::read_to_string(dir.join(PERSIST_FILE)).unwrap();
        let dirs = netsnmp::config::parse_str(&text);
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0].token, "sysContact");

        // Simulate a restart: a fresh handler + fresh registry pointing at the
        // same dir, then load.
        let handler2 = Arc::new(
            ScalarHandler::new(root, Value::OctetString(b"default".to_vec())).writable(),
        );
        let p2 = Persistence::new(&dir);
        p2.register(ScalarPersistable::new("sysContact", Arc::clone(&handler2)));
        p2.load().unwrap();
        assert_eq!(
            handler2.get_value(),
            Value::OctetString(b"ops <ops@example.org>".to_vec())
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn value_encode_decode_round_trips() {
        let cases = [
            Value::OctetString(b"plain".to_vec()),
            Value::OctetString(b"with spaces and <>".to_vec()),
            Value::OctetString(vec![0x00, 0xff, 0x10]),
            Value::Integer(-5),
            Value::Counter32(42),
            Value::Gauge32(7),
            Value::TimeTicks(123),
            Value::Counter64(u64::MAX),
            Value::Oid("1.3.6.1.2.1.1.5".parse().unwrap()),
            Value::IpAddress("10.0.0.1".parse().unwrap()),
            Value::Null,
        ];
        for v in cases {
            let (tag, enc) = encode_value(&v);
            let back = decode_value(tag, &enc).expect("decode");
            assert_eq!(v, back, "mismatch for tag {tag}: {enc}");
        }
    }

    #[test]
    fn quote_word_survives_parse_words() {
        // `quote_word` round-trips any printable string through `parse_words`.
        // Control characters (newline/tab) are intentionally NOT covered here:
        // the persist layer routes octet strings containing them through the
        // hex `x` encoding instead, avoiding one-line-format breakage.
        for s in [
            "simple",
            "",
            "with space",
            "quote\"inside",
            "back\\slash",
            "tab here",
            "ops <ops@example.org>",
        ] {
            let quoted = quote_word(s);
            let parsed = netsnmp::config::parse_words(&format!("t {quoted}"));
            assert_eq!(parsed, vec!["t".to_string(), s.to_string()], "input: {s:?}");
        }
    }

    #[test]
    fn engine_boots_round_trip() {
        let dir = temp_dir();
        let engine_id = vec![0x80u8, 0x00, 0x1f, 0x88, 0x04];
        assert_eq!(load_engine_boots(&dir, &engine_id), None);
        save_engine_boots(&dir, &engine_id, 7).unwrap();
        assert_eq!(load_engine_boots(&dir, &engine_id), Some(7));
        // load_and_bump increments.
        assert_eq!(EngineBootsPersistable::load_and_bump(&dir, &engine_id, 1), 8);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn engine_boots_persistable_snapshot_restore() {
        let eb = EngineBootsPersistable::new(vec![0x80, 0x01], 3);
        let dirs = eb.snapshot();
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0].token, "engineBoots");
        assert_eq!(dirs[0].arg(0), Some("3"));
        // Restore into a fresh wrapper.
        let eb2 = EngineBootsPersistable::new(vec![0x80, 0x01], 0);
        eb2.restore(&dirs);
        assert_eq!(eb2.get(), 3);
    }

    #[test]
    fn load_missing_file_is_ok() {
        let dir = temp_dir();
        let p = Persistence::new(&dir.join("does-not-exist"));
        // load tolerates a missing directory/file.
        assert!(p.load().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
