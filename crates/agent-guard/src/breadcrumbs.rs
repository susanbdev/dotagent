#![forbid(unsafe_code)]

//! Tamper-evident local flight recorder (`<dir>/.breadcrumbs.jsonl`) and
//! crash-consistent CRC32 session spools (`[u32 len][u32 crc32][json]\n`).
//!
//! Addresses hostile audit findings:
//! - `F02`: Full-record length-delimited `HMAC-SHA256` binds `repo_sha256`,
//!   `plan_sha256`, `session_id`, `task_id`, `seq_no`, `prev_event_mac`, `op`,
//!   `canonical_rel_path`, `line_range`, and `doc_sha256`.
//! - `F14`: Binary `[u32 len][u32 crc32][json]\n` spool quarantines torn crash
//!   tails without corrupting valid prefix events.
//! - `F16`: Registers `.breadcrumbs.jsonl` via `git rev-parse --git-path info/exclude`
//!   so linked `git worktree` checkouts stay clean.
//! - `F17`: Idempotent `event_id` (`record_mac`) deduplication on flush.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::json::JsonValue;
use crate::swarm_contracts::{
    AUTH_EVENT_SCHEMA_V1, AuthenticatedEvent, EventOp, hex_decode_32, hex_encode,
};
use crate::traversal_ledger::state_base_dir;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBreadcrumbRecord {
    pub event: AuthenticatedEvent,
    pub record_mac: [u8; 32],
}

impl SignedBreadcrumbRecord {
    pub fn event_id_hex(&self) -> String {
        hex_encode(&self.record_mac)
    }

    pub fn to_json_line(&self) -> String {
        let line_start = self
            .event
            .line_range
            .map(|(s, _)| JsonValue::Number(s as f64))
            .unwrap_or(JsonValue::Null);
        let line_end = self
            .event
            .line_range
            .map(|(_, e)| JsonValue::Number(e as f64))
            .unwrap_or(JsonValue::Null);
        let obj = JsonValue::Object(vec![
            (
                "schema_version".to_string(),
                JsonValue::Number(f64::from(self.event.schema_version)),
            ),
            ("event_id".to_string(), JsonValue::Str(self.event_id_hex())),
            (
                "repo_sha256".to_string(),
                JsonValue::Str(hex_encode(&self.event.repo_sha256)),
            ),
            (
                "plan_sha256".to_string(),
                JsonValue::Str(hex_encode(&self.event.plan_sha256)),
            ),
            (
                "session_id".to_string(),
                JsonValue::Str(self.event.session_id.clone()),
            ),
            (
                "task_id".to_string(),
                JsonValue::Str(self.event.task_id.clone()),
            ),
            (
                "seq_no".to_string(),
                JsonValue::Number(self.event.seq_no as f64),
            ),
            (
                "prev_event_mac".to_string(),
                JsonValue::Str(hex_encode(&self.event.prev_event_mac)),
            ),
            (
                "op".to_string(),
                JsonValue::Str(self.event.op.as_str().to_string()),
            ),
            (
                "canonical_rel_path".to_string(),
                JsonValue::Str(self.event.canonical_rel_path.clone()),
            ),
            ("line_start".to_string(), line_start),
            ("line_end".to_string(), line_end),
            (
                "doc_sha256".to_string(),
                JsonValue::Str(hex_encode(&self.event.doc_sha256)),
            ),
            (
                "record_mac".to_string(),
                JsonValue::Str(hex_encode(&self.record_mac)),
            ),
        ]);
        obj.to_json_string()
    }

    pub fn from_json_line(line: &str) -> Result<Self, String> {
        let v = JsonValue::parse(line).map_err(|e| format!("invalid breadcrumb JSON: {e}"))?;
        let schema_version =
            v.get("schema_version")
                .and_then(JsonValue::as_u64)
                .ok_or_else(|| "missing schema_version".to_string())? as u16;
        if schema_version != AUTH_EVENT_SCHEMA_V1 {
            return Err(format!("unsupported schema_version {schema_version}"));
        }
        let repo_sha256 = hex_decode_32(
            v.get("repo_sha256")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing repo_sha256".to_string())?,
        )?;
        let plan_sha256 = hex_decode_32(
            v.get("plan_sha256")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing plan_sha256".to_string())?,
        )?;
        let session_id = v
            .get("session_id")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "missing session_id".to_string())?
            .to_string();
        let task_id = v
            .get("task_id")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "missing task_id".to_string())?
            .to_string();
        let seq_no = v
            .get("seq_no")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| "missing seq_no".to_string())?;
        let prev_event_mac = hex_decode_32(
            v.get("prev_event_mac")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing prev_event_mac".to_string())?,
        )?;
        let op_str = v
            .get("op")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "missing op".to_string())?;
        let op =
            EventOp::from_str_id(op_str).ok_or_else(|| format!("unknown event op '{op_str}'"))?;
        let canonical_rel_path = v
            .get("canonical_rel_path")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "missing canonical_rel_path".to_string())?
            .to_string();
        let line_range = match (
            v.get("line_start").and_then(JsonValue::as_u64),
            v.get("line_end").and_then(JsonValue::as_u64),
        ) {
            (Some(s), Some(e)) => Some((s, e)),
            (None, None) => None,
            _ => return Err("partial line_start/line_end range".to_string()),
        };
        let doc_sha256 = hex_decode_32(
            v.get("doc_sha256")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing doc_sha256".to_string())?,
        )?;
        let record_mac = hex_decode_32(
            v.get("record_mac")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing record_mac".to_string())?,
        )?;

        Ok(Self {
            event: AuthenticatedEvent {
                schema_version,
                repo_sha256,
                plan_sha256,
                session_id,
                task_id,
                seq_no,
                prev_event_mac,
                op,
                canonical_rel_path,
                line_range,
                doc_sha256,
            },
            record_mac,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoolRecoveryReport {
    pub valid_records: Vec<SignedBreadcrumbRecord>,
    pub quarantined_tail_bytes: usize,
    pub quarantine_path: Option<PathBuf>,
}

/// Computes SHA-256 bytes using audited `sha2` crate.
pub fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Fast read-only probe returning `Some(dir)` only when Swarm state has already been
/// initialized for `repo_root` (avoiding `mkdir`, `chmod`, `canonicalize`, and `SHA-256`
/// on every standard non-Swarm hook invocation).
pub fn swarm_state_dir_if_exists(repo_root: &Path) -> Option<PathBuf> {
    let base = state_base_dir();
    let parent = if base.file_name().is_some_and(|n| n == "sessions") {
        base.parent().unwrap_or(&base)
    } else {
        base.as_path()
    };
    let swarm_root = parent.join("swarm");
    if !swarm_root.is_dir() {
        return None;
    }
    let canon = crate::resolve_common_repo_root(repo_root);
    let repo_hash = hex_encode(&sha256_digest(canon.to_string_lossy().as_bytes()));
    let dir = swarm_root.join(&repo_hash[..24]);
    if dir.is_dir() { Some(dir) } else { None }
}

/// Repo-isolated Swarm state directory inside `~/.local/state/agent-guard` (or `AGENT_GUARD_STATE_DIR`).
pub fn swarm_state_dir(repo_root: &Path) -> Result<PathBuf, String> {
    let base = state_base_dir();
    let parent = if base.file_name().is_some_and(|n| n == "sessions") {
        base.parent().unwrap_or(&base).to_path_buf()
    } else {
        base
    };
    let canon = crate::resolve_common_repo_root(repo_root);
    let repo_hash = hex_encode(&sha256_digest(canon.to_string_lossy().as_bytes()));
    let dir = parent.join("swarm").join(&repo_hash[..24]);
    if !dir.is_dir() {
        fs::create_dir_all(&dir)
            .map_err(|e| format!("failed creating swarm state dir '{}': {e}", dir.display()))?;
        set_dir_0700(&dir);
    }
    Ok(dir)
}

/// Out-of-repo lock directory (`~/.local/state/agent-guard/locks`) so exclusive file locks
/// never create or unlink transient `.lock` files inside Landlocked repository directories.
pub fn swarm_locks_dir() -> Result<PathBuf, String> {
    let base = state_base_dir();
    let parent = if base.file_name().is_some_and(|n| n == "sessions") {
        base.parent().unwrap_or(&base).to_path_buf()
    } else {
        base
    };
    let dir = parent.join("locks");
    if !dir.is_dir() {
        fs::create_dir_all(&dir)
            .map_err(|e| format!("failed creating swarm locks dir '{}': {e}", dir.display()))?;
        set_dir_0700(&dir);
    }
    Ok(dir)
}

pub fn hex_decode_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let trimmed = hex.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err("odd-length hex string".to_string());
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let bytes = trimmed.as_bytes();
    let val = |b: u8| -> Result<u8, String> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(format!("invalid hex byte 0x{b:02x}")),
        }
    };
    let mut i = 0usize;
    while i < bytes.len() {
        out.push((val(bytes[i])? << 4) | val(bytes[i + 1])?);
        i += 2;
    }
    Ok(out)
}

pub fn vault_hmac_key_path(repo_root: &Path) -> Result<PathBuf, String> {
    let base = swarm_state_dir(repo_root)?;
    let vault_dir = base.join("vault");
    fs::create_dir_all(&vault_dir).map_err(|e| {
        format!(
            "failed creating swarm vault dir '{}': {e}",
            vault_dir.display()
        )
    })?;
    set_dir_0700(&vault_dir);
    Ok(vault_dir.join("hmac.key"))
}

/// Host-only vault HMAC key loader/initializer (`<swarm_state_dir>/vault/hmac.key`).
/// Refuses direct filesystem access when `AGENT_GUARD_IN_SANDBOX=1` (additionally enforced
/// by Linux Landlock / macOS Seatbelt omitting `vault/`).
pub fn load_or_init_vault_hmac_key(repo_root: &Path) -> Result<[u8; 32], String> {
    if std::env::var("AGENT_GUARD_IN_SANDBOX").ok().as_deref() == Some("1") {
        return Err(
            "VAULT_KEY_ISOLATED: direct vault/hmac.key access is forbidden inside exec-sandbox; use coordinator socket"
                .to_string(),
        );
    }
    let dir = swarm_state_dir(repo_root)?;
    let legacy_path = dir.join("hmac.key");
    let key_path = vault_hmac_key_path(repo_root)?;

    if !key_path.exists() && legacy_path.exists() {
        if let Ok(hex) = fs::read_to_string(&legacy_path) {
            if let Ok(parsed) = hex_decode_32(&hex) {
                if fs::hard_link(&legacy_path, &key_path).is_ok() || key_path.exists() {
                    set_file_0600(&key_path);
                    let _ = fs::remove_file(&legacy_path);
                }
                return Ok(parsed);
            }
        }
    }

    if key_path.exists() {
        let hex = fs::read_to_string(&key_path)
            .map_err(|e| format!("failed reading vault/hmac.key: {e}"))?;
        return hex_decode_32(&hex);
    }

    let mut key = [0u8; 32];
    let mut rng = File::open("/dev/urandom")
        .map_err(|e| format!("failed opening /dev/urandom for HMAC key generation: {e}"))?;
    rng.read_exact(&mut key)
        .map_err(|e| format!("failed reading 32 bytes from /dev/urandom: {e}"))?;
    if key.iter().all(|&b| b == 0) {
        return Err("CSPRNG returned all-zero key; failing closed".to_string());
    }

    let vault_dir = key_path.parent().unwrap_or(&dir);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let staging_path = vault_dir.join(format!(".hmac.key.init.{}_{}", std::process::id(), nanos));
    let mut encoded = format!("{}\n", hex_encode(&key));
    {
        let mut stage_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging_path)
            .map_err(|e| format!("failed creating staging vault/hmac.key: {e}"))?;
        stage_file
            .write_all(encoded.as_bytes())
            .map_err(|e| format!("failed writing staging vault/hmac.key: {e}"))?;
        stage_file
            .sync_all()
            .map_err(|e| format!("failed fsyncing staging vault/hmac.key: {e}"))?;
    }
    // Overwrite and clear the hex-encoded staging buffer immediately after writing
    clear_secret_string(&mut encoded);
    set_file_0600(&staging_path);

    let link_res = fs::hard_link(&staging_path, &key_path);
    let _ = fs::remove_file(&staging_path);
    match link_res {
        Ok(()) => {
            let fmt_path = vault_dir.join("hmac.format");
            let _ = fs::write(&fmt_path, b"bijective-v2\n");
            set_file_0600(&fmt_path);
            Ok(key)
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            crate::crypto::zeroize_slice(&mut key);
            let hex = fs::read_to_string(&key_path)
                .map_err(|re| format!("failed reading existing vault/hmac.key after race: {re}"))?;
            hex_decode_32(&hex)
        }
        Err(e) => {
            crate::crypto::zeroize_slice(&mut key);
            Err(format!("failed atomically publishing vault/hmac.key: {e}"))
        }
    }
}

fn clear_secret_string(s: &mut String) {
    let cap = s.capacity();
    s.clear();
    for _ in 0..cap {
        s.push('\0');
    }
    std::hint::black_box(s.as_str());
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    s.clear();
}

pub const BREADCRUMB_EVENT_HMAC_DOMAIN: &[u8] = b"DOTAGENT_SWARM_V2_BREADCRUMB_EVENT_V2";

pub fn load_or_init_hmac_key(repo_root: &Path) -> Result<[u8; 32], String> {
    load_or_init_vault_hmac_key(repo_root)
}

pub fn compute_event_mac(key: &[u8; 32], event: &AuthenticatedEvent) -> Result<[u8; 32], String> {
    let canonical = event.encode_canonical();
    crate::coordinator::compute_domain_tag_raw(key, BREADCRUMB_EVENT_HMAC_DOMAIN, &canonical)
}

pub fn verify_event_mac(
    key: &[u8; 32],
    event: &AuthenticatedEvent,
    expected_mac: &[u8; 32],
) -> Result<(), String> {
    let canonical = event.encode_canonical();
    let actual =
        crate::coordinator::compute_domain_tag_raw(key, BREADCRUMB_EVENT_HMAC_DOMAIN, &canonical)?;
    if constant_time_eq_bytes(&actual, expected_mac) {
        Ok(())
    } else if crate::coordinator::is_legacy_v1_unprefixed_domain_tag(
        key,
        BREADCRUMB_EVENT_HMAC_DOMAIN,
        &canonical,
        expected_mac,
    ) {
        Err(
            "LEGACY_HMAC_V1_STATE_INVALIDATED: breadcrumb record uses pre-v2 unprefixed HMAC encoding; run `dotagent activate` or `dotagent session-reset --all` to reset pre-v2 swarm state"
                .to_string(),
        )
    } else {
        Err("HMAC-SHA256 authentication tag mismatch (tampered field or path swap)".to_string())
    }
}

pub fn compute_event_mac_for_repo(
    repo_root: &Path,
    event: &AuthenticatedEvent,
) -> Result<[u8; 32], String> {
    let canonical = event.encode_canonical();
    if std::env::var("AGENT_GUARD_IN_SANDBOX").ok().as_deref() == Some("1") {
        return crate::coordinator::rpc_compute_raw_hmac_bytes(repo_root, &canonical);
    }
    match load_or_init_vault_hmac_key(repo_root) {
        Ok(raw_key) => {
            let zkey = crate::crypto::ZeroizingKey::new(raw_key);
            compute_event_mac(&zkey, event)
        }
        Err(_) => crate::coordinator::rpc_compute_raw_hmac_bytes(repo_root, &canonical),
    }
}

pub fn constant_time_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    crate::crypto::constant_time_eq_bytes(a, b)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_NOFOLLOW_BITS: i32 = 0o400_000;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const O_NOFOLLOW_BITS: i32 = 0o100_000;
#[cfg(target_os = "macos")]
const O_NOFOLLOW_BITS: i32 = 0x0100;

/// Opens `path` for append without following symlinks (`O_NOFOLLOW` + `(dev, ino)` verification).
pub fn open_append_nofollow(path: &Path) -> Result<File, String> {
    if let Some(parent) = path.parent()
        && let Ok(pmeta) = fs::symlink_metadata(parent)
        && pmeta.file_type().is_symlink()
    {
        return Err(format!(
            "SYMLINK_REJECTED: refusing symlink parent directory '{}'",
            parent.display()
        ));
    }
    if let Ok(meta) = fs::symlink_metadata(path)
        && (meta.file_type().is_symlink() || !meta.file_type().is_file())
    {
        return Err(format!(
            "SYMLINK_REJECTED: '{}' must be a regular non-symlink file",
            path.display()
        ));
    }

    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        target_os = "macos"
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(O_NOFOLLOW_BITS);
    }
    let file = opts
        .open(path)
        .map_err(|e| format!("failed opening '{}' (O_NOFOLLOW): {e}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let fmeta = file
            .metadata()
            .map_err(|e| format!("failed stating open fd '{}': {e}", path.display()))?;
        let lmeta = fs::symlink_metadata(path)
            .map_err(|e| format!("failed lstating '{}': {e}", path.display()))?;
        if lmeta.file_type().is_symlink()
            || !fmeta.file_type().is_file()
            || fmeta.dev() != lmeta.dev()
            || fmeta.ino() != lmeta.ino()
        {
            return Err(format!(
                "SYMLINK_REJECTED: TOCTOU or symlink mismatch detected on '{}'",
                path.display()
            ));
        }
    }

    Ok(file)
}

pub fn ensure_regular_non_symlink_file(path: &Path) -> Result<(), String> {
    let meta =
        fs::symlink_metadata(path).map_err(|e| format!("cannot stat '{}': {e}", path.display()))?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(format!(
            "SYMLINK_REJECTED: '{}' must be a regular non-symlink file",
            path.display()
        ));
    }
    Ok(())
}

pub fn verify_event_mac_for_repo(
    repo_root: &Path,
    event: &AuthenticatedEvent,
    expected_mac: &[u8; 32],
) -> Result<(), String> {
    if std::env::var("AGENT_GUARD_IN_SANDBOX").ok().as_deref() == Some("1") {
        let canonical = event.encode_canonical();
        let valid = crate::coordinator::rpc_verify_event_mac(repo_root, &canonical, expected_mac)?;
        return if valid {
            Ok(())
        } else {
            Err("HMAC-SHA256 authentication tag mismatch (tampered field or path swap)".to_string())
        };
    }
    match load_or_init_vault_hmac_key(repo_root) {
        Ok(raw_key) => {
            let zkey = crate::crypto::ZeroizingKey::new(raw_key);
            verify_event_mac(&zkey, event, expected_mac)
        }
        Err(_) => {
            let canonical = event.encode_canonical();
            let valid =
                crate::coordinator::rpc_verify_event_mac(repo_root, &canonical, expected_mac)?;
            if valid {
                Ok(())
            } else {
                Err(
                    "HMAC-SHA256 authentication tag mismatch (tampered field or path swap)"
                        .to_string(),
                )
            }
        }
    }
}

pub fn compute_arbitrary_hmac_hex(
    repo_root: &Path,
    domain: &[u8],
    payload: &[u8],
) -> Result<String, String> {
    if std::env::var("AGENT_GUARD_IN_SANDBOX").ok().as_deref() == Some("1") {
        return crate::coordinator::rpc_compute_domain_hmac_hex(repo_root, domain, payload);
    }
    match load_or_init_vault_hmac_key(repo_root) {
        Ok(raw_key) => {
            let zkey = crate::crypto::ZeroizingKey::new(raw_key);
            let tag = crate::coordinator::compute_domain_tag_raw(zkey.as_bytes(), domain, payload)?;
            Ok(hex_encode(&tag))
        }
        Err(_) => crate::coordinator::rpc_compute_domain_hmac_hex(repo_root, domain, payload),
    }
}

pub fn verify_arbitrary_hmac_hex(
    repo_root: &Path,
    domain: &[u8],
    payload: &[u8],
    expected_hex: &str,
) -> Result<(), String> {
    let trimmed = expected_hex.trim();
    if trimmed.len() != 64 {
        return Err("HMAC authentication tag length mismatch".to_string());
    }
    if std::env::var("AGENT_GUARD_IN_SANDBOX").ok().as_deref() == Some("1") {
        let valid =
            crate::coordinator::rpc_verify_domain_hmac(repo_root, domain, payload, trimmed)?;
        return if valid {
            Ok(())
        } else {
            Err("HMAC authentication tag mismatch".to_string())
        };
    }
    match load_or_init_vault_hmac_key(repo_root) {
        Ok(raw_key) => {
            let zkey = crate::crypto::ZeroizingKey::new(raw_key);
            let expected_bytes = hex_decode_bytes(trimmed)?;
            let actual =
                crate::coordinator::compute_domain_tag_raw(zkey.as_bytes(), domain, payload)?;
            if constant_time_eq_bytes(&actual, &expected_bytes) {
                Ok(())
            } else if crate::coordinator::is_legacy_v1_unprefixed_domain_tag(
                zkey.as_bytes(),
                domain,
                payload,
                &expected_bytes,
            ) {
                Err(
                    "LEGACY_HMAC_V1_STATE_INVALIDATED: persisted record uses pre-v2 unprefixed HMAC encoding; run `dotagent activate` or `dotagent session-reset --all` to reset pre-v2 swarm state"
                        .to_string(),
                )
            } else {
                Err("HMAC authentication tag mismatch".to_string())
            }
        }
        Err(_) => {
            let valid =
                crate::coordinator::rpc_verify_domain_hmac(repo_root, domain, payload, trimmed)?;
            if valid {
                Ok(())
            } else {
                Err("HMAC authentication tag mismatch".to_string())
            }
        }
    }
}

pub fn spool_file_path(repo_root: &Path, session_id: &str) -> Result<PathBuf, String> {
    let dir = swarm_state_dir(repo_root)?.join("spools");
    fs::create_dir_all(&dir).map_err(|e| format!("failed creating spools dir: {e}"))?;
    set_dir_0700(&dir);
    let safe_sid: String = session_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
        .take(80)
        .collect();
    if safe_sid.is_empty() {
        return Err("empty session_id for spool".to_string());
    }
    Ok(dir.join(format!("{safe_sid}.spool")))
}

/// Appends a binary `[u32 be_len][u32 be_crc32][json_bytes]\n` frame to the session spool
/// under an exclusive advisory lock and `O_NOFOLLOW`.
pub fn append_spool_frame(
    spool_path: &Path,
    record: &SignedBreadcrumbRecord,
) -> Result<(), String> {
    let _spool_lock = ExclusiveFileLockGuard::acquire(spool_path)?;
    append_spool_frame_unlocked(spool_path, record)
}

fn append_spool_frame_unlocked(
    spool_path: &Path,
    record: &SignedBreadcrumbRecord,
) -> Result<(), String> {
    append_spool_frames_batch_unlocked(spool_path, std::slice::from_ref(record))
}

fn append_spool_frames_batch_unlocked(
    spool_path: &Path,
    records: &[SignedBreadcrumbRecord],
) -> Result<(), String> {
    if records.is_empty() {
        return Ok(());
    }
    let mut buf = Vec::with_capacity(records.len().saturating_mul(384));
    for record in records {
        let json_bytes = record.to_json_line().into_bytes();
        let len = u32::try_from(json_bytes.len())
            .map_err(|_| "breadcrumb record exceeds u32 frame limit".to_string())?;
        let crc = crc32fast::hash(&json_bytes);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&crc.to_be_bytes());
        buf.extend_from_slice(&json_bytes);
        buf.push(b'\n');
    }

    let mut file = open_append_nofollow(spool_path)?;
    file.write_all(&buf)
        .map_err(|e| format!("failed writing spool frame: {e}"))?;
    file.sync_data()
        .map_err(|e| format!("failed fsyncing spool frame: {e}"))?;
    set_file_0600(spool_path);
    Ok(())
}

/// Reads `[u32 len][u32 crc32][json]\n` frames:
/// - Quarantines ONLY genuinely incomplete/truncated crash tails at EOF (`frame_end > raw.len()`).
/// - Fails closed (`Err`) on any complete frame with a bad delimiter, CRC32 mismatch, invalid UTF-8,
///   or malformed record JSON (`HIGH-DA-05`), preventing silent history truncation.
pub fn recover_spool_frames(spool_path: &Path) -> Result<SpoolRecoveryReport, String> {
    if fs::symlink_metadata(spool_path).is_err() {
        return Ok(SpoolRecoveryReport {
            valid_records: Vec::new(),
            quarantined_tail_bytes: 0,
            quarantine_path: None,
        });
    }
    ensure_regular_non_symlink_file(spool_path)?;

    let raw = fs::read(spool_path)
        .map_err(|e| format!("failed reading spool '{}': {e}", spool_path.display()))?;
    let mut offset = 0usize;
    let mut valid_records = Vec::new();

    while offset < raw.len() {
        if offset + 8 > raw.len() {
            break;
        }
        let len = u32::from_be_bytes([
            raw[offset],
            raw[offset + 1],
            raw[offset + 2],
            raw[offset + 3],
        ]) as usize;
        let expected_crc = u32::from_be_bytes([
            raw[offset + 4],
            raw[offset + 5],
            raw[offset + 6],
            raw[offset + 7],
        ]);
        let frame_end = offset
            .saturating_add(8)
            .saturating_add(len)
            .saturating_add(1);
        if frame_end > raw.len() {
            // Genuinely truncated EOF write (e.g., SIGKILL mid-write): quarantine tail
            break;
        }
        if raw[frame_end - 1] != b'\n' {
            return Err(format!(
                "CORRUPT_SPOOL_FRAME: missing newline framing at byte offset {offset} in '{}'",
                spool_path.display()
            ));
        }
        let payload = &raw[offset + 8..offset + 8 + len];
        let actual_crc = crc32fast::hash(payload);
        if actual_crc != expected_crc {
            return Err(format!(
                "CORRUPT_SPOOL_FRAME: CRC32 mismatch at byte offset {offset} in '{}' (expected {expected_crc:#010x}, got {actual_crc:#010x})",
                spool_path.display()
            ));
        }
        let line_str = std::str::from_utf8(payload).map_err(|e| {
            format!(
                "CORRUPT_SPOOL_FRAME: non-UTF8 payload at byte offset {offset} in '{}': {e}",
                spool_path.display()
            )
        })?;
        let rec = SignedBreadcrumbRecord::from_json_line(line_str).map_err(|e| {
            format!(
                "CORRUPT_SPOOL_FRAME: malformed record at byte offset {offset} in '{}': {e}",
                spool_path.display()
            )
        })?;
        valid_records.push(rec);
        offset = frame_end;
    }

    if offset < raw.len() {
        let torn = &raw[offset..];
        let qpath = spool_path.with_extension("spool.quarantine");
        if fs::symlink_metadata(&qpath).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(format!(
                "SYMLINK_REJECTED: quarantine path '{}' is a symlink",
                qpath.display()
            ));
        }
        fs::write(&qpath, torn)
            .map_err(|e| format!("failed writing quarantine tail '{}': {e}", qpath.display()))?;
        set_file_0600(&qpath);
        fs::write(spool_path, &raw[..offset])
            .map_err(|e| format!("failed truncating recovered spool: {e}"))?;
        return Ok(SpoolRecoveryReport {
            valid_records,
            quarantined_tail_bytes: torn.len(),
            quarantine_path: Some(qpath),
        });
    }

    Ok(SpoolRecoveryReport {
        valid_records,
        quarantined_tail_bytes: 0,
        quarantine_path: None,
    })
}

type PendingOutcomeSlot = Arc<(
    Mutex<Option<Result<SignedBreadcrumbRecord, String>>>,
    Condvar,
)>;

struct PendingBreadcrumb {
    session_id: String,
    task_id: String,
    plan_sha256: [u8; 32],
    op: EventOp,
    canonical_rel_path: String,
    trail_path: PathBuf,
    line_range: Option<(u64, u64)>,
    doc_sha256: [u8; 32],
    slot: PendingOutcomeSlot,
}

struct SpoolGroupQueue {
    mu: Mutex<(VecDeque<PendingBreadcrumb>, bool)>,
}

struct GroupLeaderGuard<'a> {
    group: &'a SpoolGroupQueue,
    active: bool,
}

impl Drop for GroupLeaderGuard<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut st = self.group.mu.lock().unwrap_or_else(|e| e.into_inner());
        let drained: Vec<PendingBreadcrumb> = st.0.drain(..).collect();
        st.1 = false;
        drop(st);
        for item in drained {
            deliver_pending_outcome(
                &item.slot,
                Err("breadcrumb group leader aborted unexpectedly".to_string()),
            );
        }
    }
}

fn deliver_pending_outcome(
    slot: &PendingOutcomeSlot,
    outcome: Result<SignedBreadcrumbRecord, String>,
) {
    let (mu, cv) = &**slot;
    let mut g = mu.lock().unwrap_or_else(|e| e.into_inner());
    *g = Some(outcome);
    drop(g);
    cv.notify_one();
}

fn spool_group_queue(key: &(PathBuf, PathBuf, PathBuf)) -> Arc<SpoolGroupQueue> {
    type GroupMap = BTreeMap<(PathBuf, PathBuf, PathBuf), Arc<SpoolGroupQueue>>;
    static GROUPS: OnceLock<Mutex<GroupMap>> = OnceLock::new();
    let map_mu = GROUPS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut map = map_mu.lock().unwrap_or_else(|e| e.into_inner());
    Arc::clone(map.entry(key.clone()).or_insert_with(|| {
        Arc::new(SpoolGroupQueue {
            mu: Mutex::new((VecDeque::new(), false)),
        })
    }))
}

/// Appends a signed event to the session spool AND flushes idempotently (`event_id` dedup)
/// into `<parent_dir>/.breadcrumbs.jsonl`, ensuring `.breadcrumbs.jsonl` is listed in
/// `git rev-parse --git-path info/exclude` (`F16` worktree-safe).
///
/// Concurrent in-process writers targeting the same `(common_repo, local_root, spool_path)`
/// coalesce via group commit under the cross-process `ExclusiveFileLockGuard(&spool_path)`,
/// preserving cross-process exclusion, contiguous `seq_no`, MAC-chain continuity, and
/// ordered `.breadcrumbs.jsonl` trail projection with a single `fdatasync` pair per batch.
#[allow(clippy::too_many_arguments)]
pub fn append_breadcrumb_for_path(
    repo_root: &Path,
    session_id: &str,
    task_id: &str,
    plan_sha256: [u8; 32],
    op: EventOp,
    canonical_rel_path: &str,
    line_range: Option<(u64, u64)>,
    doc_sha256: [u8; 32],
) -> Result<SignedBreadcrumbRecord, String> {
    let local_root = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let common_repo = crate::resolve_common_repo_root(&local_root);
    let spool_path = spool_file_path(&common_repo, session_id)?;
    let trail_path = trail_path_for_rel_path(&local_root, canonical_rel_path)?;
    let _ = ensure_git_info_exclude(&local_root);

    let slot: PendingOutcomeSlot = Arc::new((Mutex::new(None), Condvar::new()));
    let pending = PendingBreadcrumb {
        session_id: session_id.to_string(),
        task_id: task_id.to_string(),
        plan_sha256,
        op,
        canonical_rel_path: canonical_rel_path.to_string(),
        trail_path,
        line_range,
        doc_sha256,
        slot: Arc::clone(&slot),
    };

    let group_key = (common_repo.clone(), local_root.clone(), spool_path.clone());
    let group = spool_group_queue(&group_key);
    let become_leader = {
        let mut st = group.mu.lock().unwrap_or_else(|e| e.into_inner());
        st.0.push_back(pending);
        if st.1 {
            false
        } else {
            st.1 = true;
            true
        }
    };

    if become_leader {
        let mut leader_guard = GroupLeaderGuard {
            group: &group,
            active: true,
        };
        let repo_sha256 = sha256_digest(common_repo.to_string_lossy().as_bytes());
        let in_sandbox = std::env::var("AGENT_GUARD_IN_SANDBOX").ok().as_deref() == Some("1");
        let root_trail = local_root.join(".breadcrumbs.jsonl");

        loop {
            let spool_lock_res = ExclusiveFileLockGuard::acquire(&spool_path);
            let batch: Vec<PendingBreadcrumb> = {
                let mut st = group.mu.lock().unwrap_or_else(|e| e.into_inner());
                if st.0.is_empty() {
                    st.1 = false;
                    leader_guard.active = false;
                    break;
                }
                let take_n = st.0.len().min(64);
                st.0.drain(..take_n).collect()
            };

            let spool_lock = match spool_lock_res {
                Ok(lk) => lk,
                Err(e) => {
                    for item in batch {
                        deliver_pending_outcome(&item.slot, Err(e.clone()));
                    }
                    continue;
                }
            };

            let batch_outcomes = process_breadcrumb_batch_locked(
                &common_repo,
                &spool_path,
                &root_trail,
                repo_sha256,
                in_sandbox,
                &batch,
            );
            drop(spool_lock);

            for (item, outcome) in batch.into_iter().zip(batch_outcomes) {
                deliver_pending_outcome(&item.slot, outcome);
            }

            let mut st = group.mu.lock().unwrap_or_else(|e| e.into_inner());
            if st.0.is_empty() {
                st.1 = false;
                leader_guard.active = false;
                break;
            }
        }
    }

    let (mu, cv) = &*slot;
    let mut ready = mu.lock().unwrap_or_else(|e| e.into_inner());
    while ready.is_none() {
        ready = cv.wait(ready).unwrap_or_else(|e| e.into_inner());
    }
    ready
        .take()
        .unwrap_or_else(|| Err("missing breadcrumb batch outcome".to_string()))
}

fn process_breadcrumb_batch_locked(
    common_repo: &Path,
    spool_path: &Path,
    root_trail: &Path,
    repo_sha256: [u8; 32],
    in_sandbox: bool,
    batch: &[PendingBreadcrumb],
) -> Vec<Result<SignedBreadcrumbRecord, String>> {
    let recovery = match recover_spool_frames(spool_path) {
        Ok(r) => r,
        Err(e) => return vec![Err(e); batch.len()],
    };
    let (mut seq_no, mut prev_event_mac) = match recovery.valid_records.last() {
        Some(prev) => (prev.event.seq_no.saturating_add(1), prev.record_mac),
        None => (1, [0u8; 32]),
    };

    let cached_key = if !in_sandbox {
        load_or_init_vault_hmac_key(common_repo)
            .ok()
            .map(crate::crypto::ZeroizingKey::new)
    } else {
        None
    };

    let mut signed_batch = Vec::with_capacity(batch.len());
    for item in batch {
        let event = AuthenticatedEvent {
            schema_version: AUTH_EVENT_SCHEMA_V1,
            repo_sha256,
            plan_sha256: item.plan_sha256,
            session_id: item.session_id.clone(),
            task_id: item.task_id.clone(),
            seq_no,
            prev_event_mac,
            op: item.op,
            canonical_rel_path: item.canonical_rel_path.clone(),
            line_range: item.line_range,
            doc_sha256: item.doc_sha256,
        };
        let mac_res = match cached_key.as_ref() {
            Some(zkey) => compute_event_mac(zkey, &event),
            None => compute_event_mac_for_repo(common_repo, &event),
        };
        let record_mac = match mac_res {
            Ok(m) => m,
            Err(e) => return vec![Err(e); batch.len()],
        };
        seq_no = seq_no.saturating_add(1);
        prev_event_mac = record_mac;
        signed_batch.push(SignedBreadcrumbRecord { event, record_mac });
    }

    if let Err(e) = append_spool_frames_batch_unlocked(spool_path, &signed_batch) {
        return vec![Err(e); batch.len()];
    }

    let mut trail_order: Vec<PathBuf> = Vec::new();
    for item in batch {
        if !trail_order.contains(&item.trail_path) {
            trail_order.push(item.trail_path.clone());
        }
    }
    let mut trail_errors: BTreeMap<PathBuf, String> = BTreeMap::new();
    for tp in &trail_order {
        let for_trail: Vec<SignedBreadcrumbRecord> = batch
            .iter()
            .zip(&signed_batch)
            .filter(|(it, _)| &it.trail_path == tp)
            .map(|(_, s)| s.clone())
            .collect();
        if let Err(e) = flush_records_idempotent(tp, &for_trail) {
            if in_sandbox && tp != root_trail {
                if let Err(re) = flush_records_idempotent(root_trail, &for_trail) {
                    trail_errors.insert(tp.clone(), re);
                }
            } else {
                trail_errors.insert(tp.clone(), e);
            }
        }
    }

    batch
        .iter()
        .zip(signed_batch)
        .map(|(it, signed)| match trail_errors.get(&it.trail_path) {
            Some(err) => Err(err.clone()),
            None => Ok(signed),
        })
        .collect()
}

pub fn record_quorum_approval_breadcrumb(
    repo_root: &Path,
    reviewer_session_id: &str,
    task_id: &str,
    target_rel_path: &str,
) -> Result<SignedBreadcrumbRecord, String> {
    let local_root = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let common_repo = crate::resolve_common_repo_root(&local_root);
    let cap = crate::role_sandbox::load_session_capability(&common_repo, reviewer_session_id)?;
    if cap.malicious_flags != 0
        || !matches!(
            cap.role,
            crate::swarm_contracts::SwarmRole::AdversarialReviewer
                | crate::swarm_contracts::SwarmRole::QaEngineer
                | crate::swarm_contracts::SwarmRole::Master
        )
    {
        return Err(format!(
            "session '{reviewer_session_id}' is not an untainted reviewer capability"
        ));
    }
    let repo_sha256 = sha256_digest(common_repo.to_string_lossy().as_bytes());
    let plan_sha256 = hex_decode_32(&cap.plan_sha256).unwrap_or([0u8; 32]);
    let spool_path = spool_file_path(&common_repo, reviewer_session_id)?;
    let _spool_lock = ExclusiveFileLockGuard::acquire(&spool_path)?;
    let recovery = recover_spool_frames(&spool_path)?;
    let (seq_no, prev_event_mac) = match recovery.valid_records.last() {
        Some(prev) => (prev.event.seq_no.saturating_add(1), prev.record_mac),
        None => (1, [0u8; 32]),
    };
    let raw_rel = target_rel_path.trim();
    let (clean_rel, doc_sha256) = if raw_rel == "*" {
        if cap.role != crate::swarm_contracts::SwarmRole::Master
            && !cap.assigned_read_paths.is_empty()
            && !cap
                .assigned_read_paths
                .iter()
                .any(|p| matches!(p.trim(), "*" | "**"))
        {
            return Err(format!(
                "reviewer '{reviewer_session_id}' lacks wildcard assigned_read_paths scope"
            ));
        }
        ("*".to_string(), [0u8; 32])
    } else {
        let (target_full, norm_rel) =
            crate::stop_receipt::clean_smoke_rel_nonsymlink(&local_root, raw_rel)?;
        if cap.role != crate::swarm_contracts::SwarmRole::Master
            && !cap.assigned_read_paths.is_empty()
            && !cap.assigned_read_paths.iter().any(|p| {
                let cp = p.trim().trim_start_matches("./");
                cp == "*" || cp == "**" || crate::path_policy::glob_match_path(cp, &norm_rel)
            })
        {
            return Err(format!(
                "quorum target '{norm_rel}' is outside reviewer '{reviewer_session_id}' assigned_read_paths"
            ));
        }
        let tmeta = fs::symlink_metadata(&target_full)
            .map_err(|e| format!("quorum approval target '{norm_rel}' must exist on disk: {e}"))?;
        if tmeta.file_type().is_symlink() || !tmeta.file_type().is_file() {
            return Err(format!(
                "quorum approval target '{norm_rel}' must be a regular non-symlink file"
            ));
        }
        let bytes = fs::read(&target_full)
            .map_err(|e| format!("failed reading quorum target '{norm_rel}': {e}"))?;
        (norm_rel, sha256_digest(&bytes))
    };
    let event = AuthenticatedEvent {
        schema_version: AUTH_EVENT_SCHEMA_V1,
        repo_sha256,
        plan_sha256,
        session_id: reviewer_session_id.to_string(),
        task_id: task_id.to_string(),
        seq_no,
        prev_event_mac,
        op: EventOp::ReviewApprove,
        canonical_rel_path: clean_rel.clone(),
        line_range: None,
        doc_sha256,
    };
    let record_mac = compute_event_mac_for_repo(&common_repo, &event)?;
    let signed = SignedBreadcrumbRecord { event, record_mac };
    append_spool_frame_unlocked(&spool_path, &signed)?;
    let _ = ensure_git_info_exclude(&local_root);
    let root_trail = local_root.join(".breadcrumbs.jsonl");
    let target_trail = trail_path_for_rel_path(&local_root, &clean_rel)
        .ok()
        .filter(|tp| tp.parent().is_some_and(Path::is_dir))
        .unwrap_or_else(|| root_trail.clone());
    if flush_records_idempotent(&target_trail, std::slice::from_ref(&signed)).is_err() {
        flush_records_idempotent(&root_trail, std::slice::from_ref(&signed))?;
    }
    Ok(signed)
}

pub fn count_verified_quorum_approvals(
    repo_root: &Path,
    actor_session_id: &str,
    target_rel_paths: &[String],
    allowed_roles: &[String],
) -> usize {
    use crate::role_sandbox::load_session_capability;
    use crate::swarm_contracts::SwarmRole;
    use crate::traversal_ledger::SessionLedger;

    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let common_repo = crate::resolve_common_repo_root(&canon_repo);
    let expected_repo_sha = sha256_digest(common_repo.to_string_lossy().as_bytes());
    let Ok(actor_cap) = load_session_capability(&common_repo, actor_session_id) else {
        return 0;
    };
    if actor_cap.malicious_flags != 0 || actor_cap.task_id.trim().is_empty() {
        return 0;
    }
    let targets: Vec<&str> = if target_rel_paths.is_empty() {
        vec!["*"]
    } else {
        target_rel_paths.iter().map(String::as_str).collect()
    };
    let mut min_verified: Option<usize> = None;
    for target in targets {
        let raw_t = target.trim();
        let (clean_t, expected_doc) = if raw_t == "*" {
            ("*".to_string(), [0u8; 32])
        } else {
            let Ok((tf, norm_t)) =
                crate::stop_receipt::clean_smoke_rel_nonsymlink(&canon_repo, raw_t)
            else {
                return 0;
            };
            let Ok(tm) = fs::symlink_metadata(&tf) else {
                return 0;
            };
            if tm.file_type().is_symlink() || !tm.file_type().is_file() {
                return 0;
            }
            let Ok(bytes) = fs::read(&tf) else {
                return 0;
            };
            (norm_t, sha256_digest(&bytes))
        };
        let mut trails = vec![canon_repo.join(".breadcrumbs.jsonl")];
        if clean_t != "*"
            && let Ok(tp) = trail_path_for_rel_path(&canon_repo, &clean_t)
            && !trails.contains(&tp)
        {
            trails.push(tp);
        }
        let mut approvers = BTreeSet::new();
        for trail in trails {
            let Ok(meta) = fs::symlink_metadata(&trail) else {
                continue;
            };
            if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                continue;
            }
            let Ok(raw) = fs::read_to_string(&trail) else {
                continue;
            };
            for line in raw.lines().map(str::trim).filter(|l| !l.is_empty()) {
                let Ok(rec) = SignedBreadcrumbRecord::from_json_line(line) else {
                    continue;
                };
                if rec.event.op != EventOp::ReviewApprove
                    || rec.event.repo_sha256 != expected_repo_sha
                    || rec.event.session_id == actor_session_id
                    || rec.event.canonical_rel_path != clean_t
                    || rec.event.task_id.trim().is_empty()
                    || rec.event.doc_sha256 != expected_doc
                {
                    continue;
                }
                if verify_event_mac_for_repo(&common_repo, &rec.event, &rec.record_mac).is_err() {
                    continue;
                }
                if SessionLedger::load_or_create(repo_root, &rec.event.session_id).tainted {
                    continue;
                }
                let Ok(cap) = load_session_capability(&common_repo, &rec.event.session_id) else {
                    continue;
                };
                let exp_plan = hex_decode_32(&cap.plan_sha256).unwrap_or([0u8; 32]);
                if rec.event.task_id != cap.task_id
                    || rec.event.plan_sha256 != exp_plan
                    || rec.event.task_id != actor_cap.task_id
                    || cap.plan_sha256 != actor_cap.plan_sha256
                {
                    continue;
                }
                if cap.role != SwarmRole::Master
                    && !cap.assigned_read_paths.is_empty()
                    && !cap.assigned_read_paths.iter().any(|p| {
                        let cp = p.trim().trim_start_matches("./");
                        cp == "*"
                            || cp == "**"
                            || (clean_t != "*" && crate::path_policy::glob_match_path(cp, &clean_t))
                    })
                {
                    continue;
                }
                let role_ok = cap.malicious_flags == 0
                    && if allowed_roles.is_empty() {
                        matches!(
                            cap.role,
                            SwarmRole::AdversarialReviewer
                                | SwarmRole::QaEngineer
                                | SwarmRole::Master
                        )
                    } else {
                        allowed_roles
                            .iter()
                            .filter_map(|r| SwarmRole::from_str_id(r))
                            .any(|r| r == cap.role)
                    };
                if !role_ok {
                    continue;
                }
                approvers.insert(rec.event.session_id);
            }
        }
        min_verified = Some(min_verified.map_or(approvers.len(), |m| m.min(approvers.len())));
    }
    min_verified.unwrap_or(0)
}

/// Resolves the validated `<parent_dir>/.breadcrumbs.jsonl` trail path for `canonical_rel_path`,
/// refusing symlinks or path traversal outside `repo_root`.
pub fn trail_path_for_rel_path(
    repo_root: &Path,
    canonical_rel_path: &str,
) -> Result<PathBuf, String> {
    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let clean = canonical_rel_path.trim().trim_start_matches("./");
    if clean.is_empty() || Path::new(clean).is_absolute() {
        return Err(format!(
            "invalid breadcrumb relative path '{canonical_rel_path}'"
        ));
    }
    let mut acc = canon_repo.clone();
    let rel_path = Path::new(clean);
    if let Some(parent) = rel_path.parent() {
        for comp in parent.components() {
            match comp {
                std::path::Component::Normal(seg) => {
                    acc.push(seg);
                    if let Ok(meta) = fs::symlink_metadata(&acc) {
                        if meta.file_type().is_symlink() {
                            return Err(format!(
                                "refusing symlink directory '{}' in breadcrumb trail path",
                                acc.display()
                            ));
                        }
                    }
                }
                std::path::Component::CurDir => {}
                _ => {
                    return Err(format!(
                        "disallowed traversal component in breadcrumb path '{canonical_rel_path}'"
                    ));
                }
            }
        }
    }
    let trail_dir = if acc.starts_with(&canon_repo) && acc.is_dir() {
        acc
    } else {
        canon_repo
    };
    Ok(trail_dir.join(".breadcrumbs.jsonl"))
}

struct FifoWaiterState {
    locked: bool,
    next_id: u64,
    waiters: VecDeque<u64>,
    last_released: Option<Instant>,
}

struct FifoWaiterQueue {
    mu: Mutex<FifoWaiterState>,
    cv: Condvar,
}

struct InProcFifoGuard {
    queue: Arc<FifoWaiterQueue>,
}

impl Drop for InProcFifoGuard {
    fn drop(&mut self) {
        let mut st = self.queue.mu.lock().unwrap_or_else(|e| e.into_inner());
        st.locked = false;
        st.last_released = Some(Instant::now());
        drop(st);
        self.queue.cv.notify_all();
    }
}

fn in_proc_fifo_queue(lock_path: &Path) -> Arc<FifoWaiterQueue> {
    static QUEUES: OnceLock<Mutex<BTreeMap<PathBuf, Arc<FifoWaiterQueue>>>> = OnceLock::new();
    let map_mu = QUEUES.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut map = map_mu.lock().unwrap_or_else(|e| e.into_inner());
    Arc::clone(map.entry(lock_path.to_path_buf()).or_insert_with(|| {
        Arc::new(FifoWaiterQueue {
            mu: Mutex::new(FifoWaiterState {
                locked: false,
                next_id: 1,
                waiters: VecDeque::new(),
                last_released: None,
            }),
            cv: Condvar::new(),
        })
    }))
}

fn acquire_in_proc_fifo(
    lock_path: &Path,
    deadline: Instant,
) -> Result<(InProcFifoGuard, bool), String> {
    let queue = in_proc_fifo_queue(lock_path);
    let mut st = queue.mu.lock().unwrap_or_else(|e| e.into_inner());
    if !st.locked && st.waiters.is_empty() {
        st.locked = true;
        let hot_reacquire = st
            .last_released
            .is_some_and(|t| t.elapsed() < Duration::from_micros(350));
        drop(st);
        return Ok((InProcFifoGuard { queue }, hot_reacquire));
    }

    let my_id = st.next_id;
    st.next_id = st.next_id.wrapping_add(1);
    st.waiters.push_back(my_id);
    loop {
        if !st.locked && st.waiters.front() == Some(&my_id) {
            st.waiters.pop_front();
            st.locked = true;
            drop(st);
            return Ok((InProcFifoGuard { queue }, false));
        }
        let now = Instant::now();
        if now >= deadline {
            st.waiters.retain(|&w| w != my_id);
            drop(st);
            queue.cv.notify_all();
            return Err(format!(
                "timed out acquiring exclusive lock '{}'",
                lock_path.display()
            ));
        }
        let rem = deadline.saturating_duration_since(now);
        let (next_st, _) = queue
            .cv
            .wait_timeout(st, rem)
            .unwrap_or_else(|e| e.into_inner());
        st = next_st;
    }
}

pub struct ExclusiveFileLockGuard {
    lock_path: PathBuf,
    _in_proc: InProcFifoGuard,
}

impl ExclusiveFileLockGuard {
    pub fn acquire(target_path: &Path) -> Result<Self, String> {
        let locks_dir = swarm_locks_dir()?;
        let norm = match target_path.parent().and_then(|p| fs::canonicalize(p).ok()) {
            Some(canon_parent) => match target_path.file_name() {
                Some(fname) => canon_parent.join(fname),
                None => canon_parent,
            },
            None => target_path.to_path_buf(),
        };
        let digest_hex = hex_encode(&sha256_digest(norm.to_string_lossy().as_bytes()));
        let lock_path = locks_dir.join(format!("{}.lock", &digest_hex[..32]));
        let want_path = locks_dir.join(format!("{}.want", &digest_hex[..32]));
        let started = Instant::now();
        let deadline = started + Duration::from_secs(3);

        let (in_proc, hot_reacquire) = acquire_in_proc_fifo(&lock_path, deadline)?;
        if hot_reacquire && fs::symlink_metadata(&want_path).is_ok() {
            // Another OS process is actively waiting on this lock: yield long enough for its
            // sub-millisecond seniority poll to win `create_new` cleanly (preventing process hogging).
            thread::sleep(Duration::from_millis(4));
        }

        let self_pid = std::process::id();
        let self_proc_tok = proc_instance_token_for_pid(self_pid);
        let mut registered_want = false;
        loop {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(mut f) => {
                    match &self_proc_tok {
                        Some(tok) => {
                            let _ = writeln!(f, "pid={self_pid} proc={tok}");
                        }
                        None => {
                            let _ = writeln!(f, "pid={self_pid}");
                        }
                    }
                    if registered_want {
                        let _ = fs::remove_file(&want_path);
                    }
                    return Ok(Self {
                        lock_path,
                        _in_proc: in_proc,
                    });
                }
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    if !registered_want {
                        let _ = OpenOptions::new()
                            .create(true)
                            .write(true)
                            .truncate(false)
                            .open(&want_path);
                        registered_want = true;
                    }
                    let min_reclaim_age = if cfg!(target_os = "linux") {
                        Duration::from_millis(250)
                    } else {
                        Duration::from_secs(30)
                    };
                    if let Ok(meta) = fs::metadata(&lock_path)
                        && let Ok(modified) = meta.modified()
                        && let Ok(age) = modified.elapsed()
                        && age > min_reclaim_age
                        && is_lock_holder_dead(&lock_path, age)
                    {
                        let reclaim_tmp =
                            locks_dir.join(format!(".reclaim.{}.{}", &digest_hex[..16], self_pid));
                        if fs::rename(&lock_path, &reclaim_tmp).is_ok() {
                            let _ = fs::remove_file(&reclaim_tmp);
                            continue;
                        }
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        if registered_want {
                            let _ = fs::remove_file(&want_path);
                        }
                        return Err(format!(
                            "timed out acquiring exclusive lock '{}'",
                            lock_path.display()
                        ));
                    }
                    // Seniority-priority polling: longer-waiting processes poll faster than
                    // newly arrived contenders so cross-process acquisition approximates FIFO.
                    let waited = now.saturating_duration_since(started);
                    let step_wait = if waited >= Duration::from_millis(120) {
                        Duration::from_micros(80)
                    } else if waited >= Duration::from_millis(40) {
                        Duration::from_micros(180)
                    } else if waited >= Duration::from_millis(12) {
                        Duration::from_micros(450)
                    } else {
                        Duration::from_millis(1)
                    };
                    thread::sleep(step_wait.min(deadline.saturating_duration_since(now)));
                }
                Err(e) => {
                    if registered_want {
                        let _ = fs::remove_file(&want_path);
                    }
                    return Err(format!(
                        "failed creating exclusive lock '{}': {e}",
                        lock_path.display()
                    ));
                }
            }
        }
    }
}

impl Drop for ExclusiveFileLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn proc_instance_token_for_pid(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let proc_dir = PathBuf::from(format!("/proc/{pid}"));
        let meta = fs::metadata(&proc_dir).ok()?;
        let stat_raw = fs::read_to_string(proc_dir.join("stat")).ok()?;
        let after_comm = stat_raw.rsplit_once(')')?.1;
        // Field 3 is right after ") ", so index 19 (0-based) is field 22 (`starttime`).
        let start_ticks = after_comm.split_whitespace().nth(19)?;
        Some(format!("{}:{}:{}", meta.dev(), meta.ino(), start_ticks))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

fn is_lock_holder_dead(lock_path: &Path, age: Duration) -> bool {
    let Ok(raw) = fs::read_to_string(lock_path) else {
        return true;
    };
    let mut parts = raw.split_whitespace();
    let Some(pid_kv) = parts.next() else {
        return true;
    };
    let Some(pid_str) = pid_kv.strip_prefix("pid=") else {
        return true;
    };
    let Ok(pid) = pid_str.parse::<u32>() else {
        return true;
    };
    if pid == 0 || pid == std::process::id() {
        // Because `acquire_in_proc_fifo` serializes all threads in `std::process::id()`,
        // seeing our own PID in an on-disk lock file proves a dead PID-namespace/PID-reuse orphan.
        return true;
    }
    let recorded_proc = parts.next().and_then(|s| s.strip_prefix("proc="));
    #[cfg(target_os = "linux")]
    {
        let Some(live_tok) = proc_instance_token_for_pid(pid) else {
            return true;
        };
        match recorded_proc {
            Some(exp_tok) => exp_tok != live_tok,
            None => age > Duration::from_secs(30),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (recorded_proc, age);
        true
    }
}

/// Idempotently flushes signed records into `<dir>/.breadcrumbs.jsonl` (`F17` dedup by `event_id`),
/// serialized across concurrent processes via `<trail>.lock`.
pub fn flush_records_idempotent(
    trail_path: &Path,
    records: &[SignedBreadcrumbRecord],
) -> Result<usize, String> {
    if records.is_empty() {
        return Ok(0);
    }
    let _lock = ExclusiveFileLockGuard::acquire(trail_path)?;

    let mut existing_ids = BTreeSet::new();
    if fs::symlink_metadata(trail_path).is_ok() {
        ensure_regular_non_symlink_file(trail_path)?;
        let content = fs::read_to_string(trail_path)
            .map_err(|e| format!("failed reading '{}': {e}", trail_path.display()))?;
        for line in content.lines() {
            if let Ok(rec) = SignedBreadcrumbRecord::from_json_line(line) {
                existing_ids.insert(rec.event_id_hex());
            }
        }
    }

    let mut to_append = Vec::new();
    for rec in records {
        let id = rec.event_id_hex();
        if existing_ids.insert(id) {
            to_append.push(rec.to_json_line());
        }
    }
    if to_append.is_empty() {
        return Ok(0);
    }

    let mut file = open_append_nofollow(trail_path)?;
    for line in &to_append {
        writeln!(file, "{line}").map_err(|e| format!("failed appending breadcrumb line: {e}"))?;
    }
    file.sync_data()
        .map_err(|e| format!("failed fsyncing '{}': {e}", trail_path.display()))?;
    Ok(to_append.len())
}

fn load_verified_session_spool_chain(
    repo_root: &Path,
    session_id: &str,
) -> Result<Option<BTreeMap<u64, SignedBreadcrumbRecord>>, String> {
    let spool_path = spool_file_path(repo_root, session_id)?;
    if !spool_path.exists() {
        return Ok(None);
    }
    let report = recover_spool_frames(&spool_path)?;
    let mut expected_seq = 1u64;
    let mut expected_prev = [0u8; 32];
    let mut map = BTreeMap::new();
    for rec in report.valid_records {
        if rec.event.session_id != session_id {
            return Err(format!(
                "spool '{}' contains foreign session '{}'",
                spool_path.display(),
                rec.event.session_id
            ));
        }
        verify_event_mac_for_repo(repo_root, &rec.event, &rec.record_mac)?;
        if rec.event.seq_no != expected_seq || rec.event.prev_event_mac != expected_prev {
            return Err(format!(
                "spool '{}' broken sequence/MAC continuity at seq_no={} (expected {})",
                spool_path.display(),
                rec.event.seq_no,
                expected_seq
            ));
        }
        expected_prev = rec.record_mac;
        map.insert(expected_seq, rec);
        expected_seq = expected_seq.saturating_add(1);
    }
    Ok(Some(map))
}

/// Verifies every record, monotonic sequence continuity, and `prev_event_mac` link in a
/// `.breadcrumbs.jsonl` file (bridging legitimate cross-directory hops only via a verified
/// contiguous session spool chain, and rejecting skipped, duplicate, or reordered records).
pub fn verify_breadcrumbs_file(repo_root: &Path, trail_path: &Path) -> Result<usize, String> {
    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let canon_trail = fs::canonicalize(trail_path).unwrap_or_else(|_| trail_path.to_path_buf());
    let trail_dir = canon_trail
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| canon_repo.clone());
    let content = fs::read_to_string(trail_path)
        .map_err(|e| format!("cannot read '{}': {e}", trail_path.display()))?;

    let mut per_session_prev: BTreeMap<String, (u64, [u8; 32])> = BTreeMap::new();
    let mut spool_cache: BTreeMap<String, Option<BTreeMap<u64, SignedBreadcrumbRecord>>> =
        BTreeMap::new();
    let mut count = 0usize;

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let rec = SignedBreadcrumbRecord::from_json_line(trimmed)
            .map_err(|e| format!("line {}: {e}", idx + 1))?;
        verify_event_mac_for_repo(&canon_repo, &rec.event, &rec.record_mac)
            .map_err(|e| format!("line {} (session={}): {e}", idx + 1, rec.event.session_id))?;

        let rec_expected_trail =
            trail_path_for_rel_path(&canon_repo, &rec.event.canonical_rel_path)?;
        let rec_expected_dir = fs::canonicalize(&rec_expected_trail)
            .unwrap_or(rec_expected_trail)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| canon_repo.clone());
        if rec_expected_dir != trail_dir {
            return Err(format!(
                "line {}: foreign-directory breadcrumb '{}' placed inside '{}'",
                idx + 1,
                rec.event.canonical_rel_path,
                trail_path.display()
            ));
        }

        if rec.event.seq_no == 0 {
            return Err(format!(
                "line {}: invalid seq_no=0 for session '{}'",
                idx + 1,
                rec.event.session_id
            ));
        }
        if rec.event.seq_no == 1 && rec.event.prev_event_mac != [0u8; 32] {
            return Err(format!(
                "line {}: seq_no=1 must have all-zero prev_event_mac for session '{}'",
                idx + 1,
                rec.event.session_id
            ));
        }
        if rec.event.seq_no > 1 && rec.event.prev_event_mac == [0u8; 32] {
            return Err(format!(
                "line {}: seq_no={} cannot have all-zero prev_event_mac for session '{}'",
                idx + 1,
                rec.event.seq_no,
                rec.event.session_id
            ));
        }

        let (last_seq, last_mac) = per_session_prev
            .get(&rec.event.session_id)
            .copied()
            .unwrap_or((0, [0u8; 32]));

        if rec.event.seq_no <= last_seq {
            return Err(format!(
                "line {}: duplicate or out-of-order seq_no={} after seq_no={} for session '{}'",
                idx + 1,
                rec.event.seq_no,
                last_seq,
                rec.event.session_id
            ));
        }

        if rec.event.seq_no == last_seq.saturating_add(1) {
            if rec.event.prev_event_mac != last_mac {
                return Err(format!(
                    "line {}: broken prev_event_mac chain at seq_no={} for session '{}'",
                    idx + 1,
                    rec.event.seq_no,
                    rec.event.session_id
                ));
            }
        } else {
            // Cross-directory gap: require an authenticated contiguous session spool chain
            // proving that every omitted seq_no belonged to a DIFFERENT directory trail!
            if !spool_cache.contains_key(&rec.event.session_id) {
                let loaded = load_verified_session_spool_chain(&canon_repo, &rec.event.session_id)?;
                spool_cache.insert(rec.event.session_id.clone(), loaded);
            }
            let Some(Some(spool_chain)) = spool_cache.get(&rec.event.session_id) else {
                return Err(format!(
                    "line {}: sequence gap ({} -> {}) without authenticated session spool for '{}'",
                    idx + 1,
                    last_seq,
                    rec.event.seq_no,
                    rec.event.session_id
                ));
            };
            for missing_seq in (last_seq + 1)..rec.event.seq_no {
                let Some(intervening) = spool_chain.get(&missing_seq) else {
                    return Err(format!(
                        "line {}: missing seq_no={} in session '{}' chain",
                        idx + 1,
                        missing_seq,
                        rec.event.session_id
                    ));
                };
                if let Ok(expected_trail) =
                    trail_path_for_rel_path(&canon_repo, &intervening.event.canonical_rel_path)
                {
                    let canon_exp_dir = fs::canonicalize(&expected_trail)
                        .unwrap_or(expected_trail)
                        .parent()
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| canon_repo.clone());
                    if canon_exp_dir == trail_dir {
                        return Err(format!(
                            "line {}: omitted in-directory event seq_no={} for '{}' in '{}'",
                            idx + 1,
                            missing_seq,
                            rec.event.session_id,
                            trail_path.display()
                        ));
                    }
                }
            }
            let Some(prev_in_spool) = spool_chain.get(&(rec.event.seq_no - 1)) else {
                return Err(format!(
                    "line {}: missing predecessor seq_no={} in session '{}' spool",
                    idx + 1,
                    rec.event.seq_no - 1,
                    rec.event.session_id
                ));
            };
            if rec.event.prev_event_mac != prev_in_spool.record_mac {
                return Err(format!(
                    "line {}: broken cross-directory prev_event_mac at seq_no={} for session '{}'",
                    idx + 1,
                    rec.event.seq_no,
                    rec.event.session_id
                ));
            }
            if spool_chain
                .get(&rec.event.seq_no)
                .is_none_or(|s| s.record_mac != rec.record_mac)
            {
                return Err(format!(
                    "line {}: record_mac at seq_no={} disagrees with authenticated session spool",
                    idx + 1,
                    rec.event.seq_no
                ));
            }
        }

        per_session_prev.insert(
            rec.event.session_id.clone(),
            (rec.event.seq_no, rec.record_mac),
        );
        count += 1;
    }

    Ok(count)
}

/// Uses a zero-subprocess path when `.git` is a regular directory or standard `gitdir:` worktree
/// pointer, falling back to ceiling-bounded `git rev-parse --git-path info/exclude` so linked
/// `git worktree` repos resolve their shared gitdir exclude file without escaping `repo_root` (`F16`).
pub fn ensure_git_info_exclude(repo_root: &Path) -> Result<Option<PathBuf>, String> {
    let dot_git = repo_root.join(".git");
    let Ok(meta) = fs::symlink_metadata(&dot_git) else {
        return Ok(None);
    };
    if meta.file_type().is_symlink() {
        return Err(format!(
            "refusing symlink .git entry '{}'",
            dot_git.display()
        ));
    }

    let exclude_path = if meta.file_type().is_dir() {
        let direct_exclude = dot_git.join("info").join("exclude");
        if let Ok(existing) = fs::read_to_string(&direct_exclude)
            && existing.lines().any(|l| l.trim() == ".breadcrumbs.jsonl")
        {
            return Ok(Some(direct_exclude));
        }
        direct_exclude
    } else if meta.file_type().is_file() {
        if let Some(wt_exclude) = resolve_worktree_exclude_path(repo_root, &dot_git) {
            if let Ok(existing) = fs::read_to_string(&wt_exclude)
                && existing.lines().any(|l| l.trim() == ".breadcrumbs.jsonl")
            {
                return Ok(Some(wt_exclude));
            }
            wt_exclude
        } else {
            let mut cmd = Command::new("git");
            cmd.arg("-C")
                .arg(repo_root)
                .args(["rev-parse", "--git-path", "info/exclude"]);
            if let Some(parent) = repo_root.parent() {
                cmd.env("GIT_CEILING_DIRECTORIES", parent);
            }
            match cmd.output() {
                Ok(o) if o.status.success() => {
                    let raw = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if raw.is_empty() {
                        return Ok(None);
                    }
                    let p = PathBuf::from(&raw);
                    if p.is_absolute() {
                        p
                    } else {
                        repo_root.join(p)
                    }
                }
                _ => return Ok(None),
            }
        }
    } else {
        return Ok(None);
    };

    if let Some(parent) = exclude_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed creating git info dir '{}': {e}", parent.display()))?;
    }
    let _exclude_lock = ExclusiveFileLockGuard::acquire(&exclude_path)?;
    let existing = fs::read_to_string(&exclude_path).unwrap_or_default();
    if !existing.lines().any(|l| l.trim() == ".breadcrumbs.jsonl") {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&exclude_path)
            .map_err(|e| format!("failed updating '{}': {e}", exclude_path.display()))?;
        if !existing.is_empty() && !existing.ends_with('\n') {
            let _ = writeln!(f);
        }
        writeln!(f, ".breadcrumbs.jsonl")
            .map_err(|e| format!("failed writing exclude rule: {e}"))?;
    }
    Ok(Some(exclude_path))
}

fn resolve_worktree_exclude_path(repo_root: &Path, dot_git_file: &Path) -> Option<PathBuf> {
    let raw = fs::read_to_string(dot_git_file).ok()?;
    let gitdir_raw = raw
        .lines()
        .find_map(|l| l.trim().strip_prefix("gitdir:"))?
        .trim();
    if gitdir_raw.is_empty() {
        return None;
    }
    let gitdir = {
        let p = PathBuf::from(gitdir_raw);
        if p.is_absolute() {
            p
        } else {
            repo_root.join(p)
        }
    };
    if !gitdir.is_dir() {
        return None;
    }
    let common_dir = match fs::read_to_string(gitdir.join("commondir")) {
        Ok(cd) => {
            let trimmed = cd.trim();
            if trimmed.is_empty() {
                gitdir
            } else {
                let cp = PathBuf::from(trimmed);
                if cp.is_absolute() {
                    cp
                } else {
                    gitdir.join(cp)
                }
            }
        }
        Err(_) => gitdir,
    };
    common_dir
        .is_dir()
        .then(|| common_dir.join("info").join("exclude"))
}

fn set_dir_0700(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
}

fn set_file_0600(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
}
