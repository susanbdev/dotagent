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

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::json::JsonValue;
use crate::swarm_contracts::{
    AUTH_EVENT_SCHEMA_V1, AuthenticatedEvent, EventOp, hex_decode_32, hex_encode,
};
use crate::traversal_ledger::state_base_dir;

type HmacSha256 = Hmac<Sha256>;

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

/// Repo-isolated Swarm state directory inside `~/.local/state/agent-guard` (or `AGENT_GUARD_STATE_DIR`).
pub fn swarm_state_dir(repo_root: &Path) -> Result<PathBuf, String> {
    let base = state_base_dir();
    let parent = if base.file_name().is_some_and(|n| n == "sessions") {
        base.parent().unwrap_or(&base).to_path_buf()
    } else {
        base
    };
    let canon = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let repo_hash = hex_encode(&sha256_digest(canon.to_string_lossy().as_bytes()));
    let dir = parent.join("swarm").join(&repo_hash[..24]);
    fs::create_dir_all(&dir)
        .map_err(|e| format!("failed creating swarm state dir '{}': {e}", dir.display()))?;
    set_dir_0700(&dir);
    Ok(dir)
}

pub fn load_or_init_hmac_key(repo_root: &Path) -> Result<[u8; 32], String> {
    let dir = swarm_state_dir(repo_root)?;
    let key_path = dir.join("hmac.key");
    if key_path.exists() {
        let hex =
            fs::read_to_string(&key_path).map_err(|e| format!("failed reading hmac.key: {e}"))?;
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

    fs::write(&key_path, format!("{}\n", hex_encode(&key)))
        .map_err(|e| format!("failed writing hmac.key: {e}"))?;
    set_file_0600(&key_path);
    Ok(key)
}

pub fn compute_event_mac(key: &[u8; 32], event: &AuthenticatedEvent) -> Result<[u8; 32], String> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| format!("HMAC key init failure: {e}"))?;
    mac.update(&event.encode_canonical());
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    Ok(out)
}

pub fn verify_event_mac(
    key: &[u8; 32],
    event: &AuthenticatedEvent,
    expected_mac: &[u8; 32],
) -> Result<(), String> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| format!("HMAC key init failure: {e}"))?;
    mac.update(&event.encode_canonical());
    mac.verify_slice(expected_mac).map_err(|_| {
        "HMAC-SHA256 authentication tag mismatch (tampered field or path swap)".to_string()
    })
}

pub fn compute_arbitrary_hmac_hex(
    repo_root: &Path,
    domain: &[u8],
    payload: &[u8],
) -> Result<String, String> {
    let key = load_or_init_hmac_key(repo_root)?;
    let mut mac =
        HmacSha256::new_from_slice(&key).map_err(|e| format!("HMAC key init failure: {e}"))?;
    mac.update(domain);
    mac.update(&(payload.len() as u64).to_be_bytes());
    mac.update(payload);
    Ok(hex_encode(&mac.finalize().into_bytes()))
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

/// Appends a binary `[u32 be_len][u32 be_crc32][json_bytes]\n` frame to the session spool.
pub fn append_spool_frame(
    spool_path: &Path,
    record: &SignedBreadcrumbRecord,
) -> Result<(), String> {
    let json_bytes = record.to_json_line().into_bytes();
    let len = u32::try_from(json_bytes.len())
        .map_err(|_| "breadcrumb record exceeds u32 frame limit".to_string())?;
    let crc = crc32fast::hash(&json_bytes);

    let mut frame = Vec::with_capacity(8 + json_bytes.len() + 1);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&crc.to_be_bytes());
    frame.extend_from_slice(&json_bytes);
    frame.push(b'\n');

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(spool_path)
        .map_err(|e| format!("failed opening spool '{}': {e}", spool_path.display()))?;
    file.write_all(&frame)
        .map_err(|e| format!("failed writing spool frame: {e}"))?;
    file.sync_data()
        .map_err(|e| format!("failed fsyncing spool frame: {e}"))?;
    set_file_0600(spool_path);
    Ok(())
}

/// Reads `[u32 len][u32 crc32][json]\n` frames, cleanly quarantining any torn crash tail (`F14`).
pub fn recover_spool_frames(spool_path: &Path) -> Result<SpoolRecoveryReport, String> {
    if !spool_path.exists() {
        return Ok(SpoolRecoveryReport {
            valid_records: Vec::new(),
            quarantined_tail_bytes: 0,
            quarantine_path: None,
        });
    }

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
        if frame_end > raw.len() || raw[frame_end - 1] != b'\n' {
            break;
        }
        let payload = &raw[offset + 8..offset + 8 + len];
        let actual_crc = crc32fast::hash(payload);
        if actual_crc != expected_crc {
            break;
        }
        let Ok(line_str) = std::str::from_utf8(payload) else {
            break;
        };
        let Ok(rec) = SignedBreadcrumbRecord::from_json_line(line_str) else {
            break;
        };
        valid_records.push(rec);
        offset = frame_end;
    }

    if offset < raw.len() {
        let torn = &raw[offset..];
        let qpath = spool_path.with_extension("spool.quarantine");
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

/// Appends a signed event to the session spool AND flushes idempotently (`event_id` dedup)
/// into `<parent_dir>/.breadcrumbs.jsonl`, ensuring `.breadcrumbs.jsonl` is listed in
/// `git rev-parse --git-path info/exclude` (`F16` worktree-safe).
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
    let key = load_or_init_hmac_key(repo_root)?;
    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let repo_sha256 = sha256_digest(canon_repo.to_string_lossy().as_bytes());

    let spool_path = spool_file_path(&canon_repo, session_id)?;
    let recovery = recover_spool_frames(&spool_path)?;
    let (seq_no, prev_event_mac) = match recovery.valid_records.last() {
        Some(prev) => (prev.event.seq_no.saturating_add(1), prev.record_mac),
        None => (1, [0u8; 32]),
    };

    let event = AuthenticatedEvent {
        schema_version: AUTH_EVENT_SCHEMA_V1,
        repo_sha256,
        plan_sha256,
        session_id: session_id.to_string(),
        task_id: task_id.to_string(),
        seq_no,
        prev_event_mac,
        op,
        canonical_rel_path: canonical_rel_path.to_string(),
        line_range,
        doc_sha256,
    };
    let record_mac = compute_event_mac(&key, &event)?;
    let signed = SignedBreadcrumbRecord { event, record_mac };

    append_spool_frame(&spool_path, &signed)?;
    ensure_git_info_exclude(&canon_repo)?;

    let target_file = canon_repo.join(canonical_rel_path);
    let trail_dir = target_file
        .parent()
        .filter(|p| p.starts_with(&canon_repo) && p.exists())
        .unwrap_or(&canon_repo);
    let trail_path = trail_dir.join(".breadcrumbs.jsonl");
    flush_records_idempotent(&trail_path, std::slice::from_ref(&signed))?;

    Ok(signed)
}

/// Idempotently flushes signed records into `<dir>/.breadcrumbs.jsonl` (`F17` dedup by `event_id`).
pub fn flush_records_idempotent(
    trail_path: &Path,
    records: &[SignedBreadcrumbRecord],
) -> Result<usize, String> {
    let mut existing_ids = BTreeSet::new();
    if trail_path.exists() {
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

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(trail_path)
        .map_err(|e| format!("failed opening '{}': {e}", trail_path.display()))?;
    for line in &to_append {
        writeln!(file, "{line}").map_err(|e| format!("failed appending breadcrumb line: {e}"))?;
    }
    file.sync_data()
        .map_err(|e| format!("failed fsyncing '{}': {e}", trail_path.display()))?;
    Ok(to_append.len())
}

/// Verifies every record and `prev_event_mac` link in a `.breadcrumbs.jsonl` file.
pub fn verify_breadcrumbs_file(repo_root: &Path, trail_path: &Path) -> Result<usize, String> {
    let key = load_or_init_hmac_key(repo_root)?;
    let content = fs::read_to_string(trail_path)
        .map_err(|e| format!("cannot read '{}': {e}", trail_path.display()))?;

    let mut per_session_prev: std::collections::BTreeMap<String, (u64, [u8; 32])> =
        std::collections::BTreeMap::new();
    let mut count = 0usize;

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let rec = SignedBreadcrumbRecord::from_json_line(trimmed)
            .map_err(|e| format!("line {}: {e}", idx + 1))?;
        verify_event_mac(&key, &rec.event, &rec.record_mac)
            .map_err(|e| format!("line {} (session={}): {e}", idx + 1, rec.event.session_id))?;

        if let Some((last_seq, last_mac)) = per_session_prev.get(&rec.event.session_id) {
            if rec.event.seq_no == last_seq.saturating_add(1)
                && rec.event.prev_event_mac != *last_mac
            {
                return Err(format!(
                    "line {}: broken prev_event_mac chain for session '{}'",
                    idx + 1,
                    rec.event.session_id
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

/// Uses `git rev-parse --git-path info/exclude` so linked `git worktree` repos
/// resolve their shared gitdir exclude file properly (`F16`).
pub fn ensure_git_info_exclude(repo_root: &Path) -> Result<Option<PathBuf>, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["rev-parse", "--git-path", "info/exclude"])
        .output();

    let exclude_path = match out {
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
        _ => {
            let dot_git = repo_root.join(".git");
            if dot_git.is_dir() {
                dot_git.join("info").join("exclude")
            } else {
                return Ok(None);
            }
        }
    };

    if let Some(parent) = exclude_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed creating git info dir '{}': {e}", parent.display()))?;
    }
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
