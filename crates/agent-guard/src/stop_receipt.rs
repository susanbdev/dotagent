#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! Asymmetric Ed25519 `StopReceipt` Admission-Control Attestation (`spec.md` Section 3.4).
//!
//! Emits a detached Ed25519-signed receipt on clean `on-stop` execution binding:
//! `(repo_id, head_commit_oid, work_tree_oid, bundle_manifest_sha256, ledger_clean_summary, epoch_id, issued_at_unix)`
//! so CI/PR gates (`dotagent verify-receipt`) can cryptographically verify clean agent execution.
//!
//! Security Invariants:
//! 1. **Zero Sandbox Minting**: Processes inside `exec-sandbox` (`AGENT_GUARD_IN_SANDBOX=1`) or
//!    locked worker slots (`AGENT_GUARD_WORKER_LOCK=1`) are hard-blocked from minting receipts.
//! 2. **Vault Key Isolation**: The 32-byte Ed25519 seed lives in `<swarm_state_dir>/vault/stop_receipt_ed25519.key`
//!    with `0600` permissions (outside worker Landlock/Seatbelt VFS rulesets) wrapped in `ZeroizingKey`,
//!    while the 32-byte verifying key is exported to `<swarm_state_dir>/ipc/stop_receipt_ed25519.pub`.
//! 3. **Bijective Length-Prefixed Canonical Encoding**: Every variable-length field in the signed
//!    message under `STOP_RECEIPT_DOMAIN` (`DOTAGENT_STOP_RECEIPT_ED25519_V2`) is `u32` big-endian
//!    length-prefixed to eliminate delimiter-collision attacks.

use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::breadcrumbs::{ExclusiveFileLockGuard, swarm_locks_dir, swarm_state_dir};
use crate::crypto::{
    ZeroizingKey, constant_time_eq_bytes, hex_decode_32, hex_decode_bytes, hex_encode, sha256_hex,
};
use crate::json::JsonValue;
use crate::traversal_ledger::{SessionLedger, state_base_dir};
use crate::{audit_repository, resolve_repo_root};

pub const STOP_RECEIPT_SCHEMA: &str = "dotagent.stop_receipt.v2";
pub const STOP_RECEIPT_DOMAIN: &[u8] = b"DOTAGENT_STOP_RECEIPT_ED25519_V2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerCleanSummary {
    pub session_id: String,
    pub halted: bool,
    pub tainted: bool,
    pub file_reads: usize,
    pub tool_calls: usize,
    pub cumulative_tokens: usize,
    pub epoch_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopReceipt {
    pub schema: String,
    pub repo_id: String,
    pub head_commit_oid: String,
    pub work_tree_oid: String,
    pub bundle_manifest_sha256: String,
    pub smoke_gate_digest: String,
    pub ledger: LedgerCleanSummary,
    pub issued_at_unix: u64,
    pub pubkey_ed25519_hex: String,
    pub signature_ed25519_hex: String,
}

impl StopReceipt {
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(448);
        push_lp_bytes(&mut buf, STOP_RECEIPT_DOMAIN);
        push_lp_str(&mut buf, &self.schema);
        push_lp_str(&mut buf, &self.repo_id);
        push_lp_str(&mut buf, &self.head_commit_oid);
        push_lp_str(&mut buf, &self.work_tree_oid);
        push_lp_str(&mut buf, &self.bundle_manifest_sha256);
        push_lp_str(&mut buf, &self.smoke_gate_digest);
        push_lp_str(&mut buf, &self.ledger.session_id);
        buf.push(u8::from(self.ledger.halted));
        buf.push(u8::from(self.ledger.tainted));
        buf.extend_from_slice(&(self.ledger.file_reads as u64).to_be_bytes());
        buf.extend_from_slice(&(self.ledger.tool_calls as u64).to_be_bytes());
        buf.extend_from_slice(&(self.ledger.cumulative_tokens as u64).to_be_bytes());
        buf.extend_from_slice(&self.ledger.epoch_id.to_be_bytes());
        buf.extend_from_slice(&self.issued_at_unix.to_be_bytes());
        push_lp_str(&mut buf, &self.pubkey_ed25519_hex);
        buf
    }

    pub fn to_json_value(&self) -> JsonValue {
        JsonValue::Object(vec![
            ("schema".to_string(), JsonValue::Str(self.schema.clone())),
            ("repo_id".to_string(), JsonValue::Str(self.repo_id.clone())),
            (
                "head_commit_oid".to_string(),
                JsonValue::Str(self.head_commit_oid.clone()),
            ),
            (
                "work_tree_oid".to_string(),
                JsonValue::Str(self.work_tree_oid.clone()),
            ),
            (
                "bundle_manifest_sha256".to_string(),
                JsonValue::Str(self.bundle_manifest_sha256.clone()),
            ),
            (
                "smoke_gate_digest".to_string(),
                JsonValue::Str(self.smoke_gate_digest.clone()),
            ),
            (
                "ledger_clean_summary".to_string(),
                JsonValue::Object(vec![
                    (
                        "session_id".to_string(),
                        JsonValue::Str(self.ledger.session_id.clone()),
                    ),
                    ("halted".to_string(), JsonValue::Bool(self.ledger.halted)),
                    ("tainted".to_string(), JsonValue::Bool(self.ledger.tainted)),
                    (
                        "file_reads".to_string(),
                        JsonValue::Uint(self.ledger.file_reads as u64),
                    ),
                    (
                        "tool_calls".to_string(),
                        JsonValue::Uint(self.ledger.tool_calls as u64),
                    ),
                    (
                        "cumulative_tokens".to_string(),
                        JsonValue::Uint(self.ledger.cumulative_tokens as u64),
                    ),
                    (
                        "epoch_id".to_string(),
                        JsonValue::Uint(self.ledger.epoch_id),
                    ),
                ]),
            ),
            (
                "issued_at_unix".to_string(),
                JsonValue::Uint(self.issued_at_unix),
            ),
            (
                "pubkey_ed25519_hex".to_string(),
                JsonValue::Str(self.pubkey_ed25519_hex.clone()),
            ),
            (
                "signature_ed25519_hex".to_string(),
                JsonValue::Str(self.signature_ed25519_hex.clone()),
            ),
        ])
    }

    pub fn from_json_str(raw: &str) -> Result<Self, String> {
        let v = JsonValue::parse(raw).map_err(|e| format!("invalid StopReceipt JSON: {e}"))?;
        let req_str = |obj: &JsonValue, key: &str| -> Result<String, String> {
            obj.get(key)
                .and_then(JsonValue::as_str)
                .map(String::from)
                .ok_or_else(|| format!("missing string field '{key}' in StopReceipt"))
        };
        let req_u64 = |obj: &JsonValue, key: &str| -> Result<u64, String> {
            obj.get(key)
                .and_then(JsonValue::as_u64)
                .ok_or_else(|| format!("missing u64 field '{key}' in StopReceipt"))
        };
        let req_usize = |obj: &JsonValue, key: &str| -> Result<usize, String> {
            let val = req_u64(obj, key)?;
            usize::try_from(val)
                .map_err(|_| format!("integer overflow in field '{key}' of StopReceipt"))
        };
        let req_bool = |obj: &JsonValue, key: &str| -> Result<bool, String> {
            obj.get(key)
                .and_then(JsonValue::as_bool)
                .ok_or_else(|| format!("missing bool field '{key}' in StopReceipt"))
        };

        let schema = req_str(&v, "schema")?;
        if schema != STOP_RECEIPT_SCHEMA {
            return Err(format!(
                "unsupported StopReceipt schema '{schema}' (expected '{STOP_RECEIPT_SCHEMA}')"
            ));
        }
        let summary = v
            .get("ledger_clean_summary")
            .ok_or_else(|| "missing object 'ledger_clean_summary' in StopReceipt".to_string())?;

        Ok(Self {
            schema,
            repo_id: req_str(&v, "repo_id")?,
            head_commit_oid: req_str(&v, "head_commit_oid")?,
            work_tree_oid: req_str(&v, "work_tree_oid")?,
            bundle_manifest_sha256: req_str(&v, "bundle_manifest_sha256")?,
            smoke_gate_digest: req_str(&v, "smoke_gate_digest")?,
            ledger: LedgerCleanSummary {
                session_id: req_str(summary, "session_id")?,
                halted: req_bool(summary, "halted")?,
                tainted: req_bool(summary, "tainted")?,
                file_reads: req_usize(summary, "file_reads")?,
                tool_calls: req_usize(summary, "tool_calls")?,
                cumulative_tokens: req_usize(summary, "cumulative_tokens")?,
                epoch_id: req_u64(summary, "epoch_id")?,
            },
            issued_at_unix: req_u64(&v, "issued_at_unix")?,
            pubkey_ed25519_hex: req_str(&v, "pubkey_ed25519_hex")?,
            signature_ed25519_hex: req_str(&v, "signature_ed25519_hex")?,
        })
    }

    pub fn verify_signature(&self, expected_pubkey_hex: &str) -> Result<(), String> {
        if self.ledger.halted {
            return Err("RECEIPT_LEDGER_HALTED: StopReceipt cannot attest a halted ledger".into());
        }
        let exp_bytes = hex_decode_32(expected_pubkey_hex.trim())
            .map_err(|e| format!("invalid expected Ed25519 pubkey hex: {e}"))?;
        let rec_bytes = hex_decode_32(&self.pubkey_ed25519_hex)
            .map_err(|e| format!("invalid receipt pubkey_ed25519_hex: {e}"))?;
        if !constant_time_eq_bytes(&exp_bytes, &rec_bytes) {
            return Err(
                "RECEIPT_PUBKEY_MISMATCH: receipt signer key does not match pinned pubkey"
                    .to_string(),
            );
        }
        let verifying_key = VerifyingKey::from_bytes(&exp_bytes)
            .map_err(|e| format!("invalid Ed25519 public key point: {e}"))?;
        let sig_vec = hex_decode_bytes(&self.signature_ed25519_hex)
            .map_err(|e| format!("invalid signature_ed25519_hex: {e}"))?;
        let sig_arr: [u8; 64] = sig_vec
            .try_into()
            .map_err(|_| "Ed25519 signature must be exactly 64 bytes".to_string())?;
        let sig = Signature::from_bytes(&sig_arr);
        let msg = self.canonical_signing_bytes();
        verifying_key
            .verify(&msg, &sig)
            .map_err(|_| "RECEIPT_SIGNATURE_INVALID: Ed25519 signature verification failed".into())
    }
}

fn push_lp_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn push_lp_str(buf: &mut Vec<u8>, s: &str) {
    push_lp_bytes(buf, s.as_bytes());
}

pub fn receipt_pubkey_path(repo_root: &Path) -> Result<PathBuf, String> {
    let vault_dir = swarm_state_dir(repo_root)?.join("vault");
    if let Ok(meta) = fs::symlink_metadata(&vault_dir)
        && meta.file_type().is_symlink()
    {
        return Err("VAULT_SYMLINK_TAMPER: vault directory is a symlink".to_string());
    }
    fs::create_dir_all(&vault_dir)
        .map_err(|e| format!("failed creating vault dir '{}': {e}", vault_dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&vault_dir, fs::Permissions::from_mode(0o700));
    }
    Ok(vault_dir.join("stop_receipt_ed25519.pub"))
}

pub fn default_latest_receipt_path(repo_root: &Path) -> PathBuf {
    let canon = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let repo_hash = &sha256_hex(canon.to_string_lossy().as_bytes())[..24];
    state_base_dir()
        .join("receipts")
        .join(repo_hash)
        .join("latest.receipt.json")
}

/// Loads or initializes the vault-isolated `0600` Ed25519 signing seed and exports the
/// corresponding verifying key hex to `<swarm_state_dir>/vault/stop_receipt_ed25519.pub`.
pub fn load_or_init_ed25519_signing_key(repo_root: &Path) -> Result<ZeroizingKey, String> {
    if std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() == Ok("1")
        || std::env::var("AGENT_GUARD_WORKER_LOCK").as_deref() == Ok("1")
    {
        return Err(
            "STOP_RECEIPT_SANDBOX_MINT_DENIED: sandboxed or worker processes cannot access Ed25519 signing keys"
                .to_string(),
        );
    }

    if let Ok(explicit_seed) = std::env::var("DOTAGENT_RECEIPT_SEED_HEX") {
        let trimmed = explicit_seed.trim();
        if !trimmed.is_empty() {
            let mut seed = hex_decode_32(trimmed)
                .map_err(|e| format!("invalid DOTAGENT_RECEIPT_SEED_HEX: {e}"))?;
            let zk = ZeroizingKey::new(seed);
            crate::crypto::zeroize_slice(&mut seed);
            return Ok(zk);
        }
    }

    let lock_path = swarm_locks_dir()?.join("stop_receipt_ed25519_vault.lock");
    let _guard = ExclusiveFileLockGuard::acquire(&lock_path)?;

    let vault_dir = swarm_state_dir(repo_root)?.join("vault");
    if let Ok(meta) = fs::symlink_metadata(&vault_dir)
        && meta.file_type().is_symlink()
    {
        return Err("VAULT_SYMLINK_TAMPER: vault directory is a symlink".to_string());
    }
    fs::create_dir_all(&vault_dir)
        .map_err(|e| format!("failed creating vault dir '{}': {e}", vault_dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&vault_dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("failed setting 0700 on vault dir: {e}"))?;
    }

    let key_file = vault_dir.join("stop_receipt_ed25519.key");
    if let Ok(meta) = fs::symlink_metadata(&key_file)
        && meta.file_type().is_symlink()
    {
        return Err("VAULT_SYMLINK_TAMPER: stop_receipt_ed25519.key is a symlink".to_string());
    }

    let seed = if key_file.is_file() {
        let raw = fs::read_to_string(&key_file)
            .map_err(|e| format!("failed reading stop_receipt_ed25519.key: {e}"))?;
        hex_decode_32(raw.trim())
            .map_err(|e| format!("corrupt stop_receipt_ed25519.key hex: {e}"))?
    } else {
        let mut fresh = generate_os_csprng_seed()?;
        let fresh_zk = ZeroizingKey::new(fresh);
        crate::crypto::zeroize_slice(&mut fresh);
        let hex_line = format!("{}\n", hex_encode(fresh_zk.as_bytes()));
        crate::coordinator::write_atomic_private_0600(&key_file, hex_line.as_bytes())?;
        *fresh_zk.as_bytes()
    };

    let zk = ZeroizingKey::new(seed);
    let signing_key = SigningKey::from_bytes(zk.as_bytes());
    let pub_hex = format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes()));
    let pub_path = receipt_pubkey_path(repo_root)?;
    write_atomic_nonsymlink(&pub_path, pub_hex.as_bytes(), 0o600)?;
    Ok(zk)
}

fn generate_os_csprng_seed() -> Result<[u8; 32], String> {
    #[cfg(unix)]
    {
        let mut f = fs::File::open("/dev/urandom")
            .map_err(|e| format!("failed opening /dev/urandom for Ed25519 keygen: {e}"))?;
        let mut seed = [0u8; 32];
        f.read_exact(&mut seed)
            .map_err(|e| format!("failed reading 32 bytes from /dev/urandom: {e}"))?;
        Ok(seed)
    }
    #[cfg(not(unix))]
    {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut material = Vec::with_capacity(64);
        material.extend_from_slice(&nanos.to_le_bytes());
        material.extend_from_slice(&std::process::id().to_le_bytes());
        Ok(crate::crypto::sha256_bytes(&material))
    }
}

fn write_atomic_nonsymlink(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(format!(
            "SYMLINK_TAMPER_DETECTED: refusing to write symlink '{}'",
            path.display()
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("missing parent directory for '{}'", path.display()))?;
    if let Ok(pmeta) = fs::symlink_metadata(parent)
        && pmeta.file_type().is_symlink()
    {
        return Err(format!(
            "SYMLINK_TAMPER_DETECTED: parent '{}' is a symlink",
            parent.display()
        ));
    }
    fs::create_dir_all(parent)
        .map_err(|e| format!("failed creating parent '{}': {e}", parent.display()))?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("receipt.tmp");
    let tmp_path = parent.join(format!(".{fname}.tmp.{}.{nanos}", std::process::id()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .open(&tmp_path)
            .map_err(|e| format!("failed creating atomic temp '{}': {e}", tmp_path.display()))?;
        if let Err(e) = f.write_all(data).and_then(|()| f.sync_all()) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("failed syncing '{}': {e}", tmp_path.display()));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        fs::write(&tmp_path, data)
            .map_err(|e| format!("failed writing '{}': {e}", tmp_path.display()))?;
    }
    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("failed renaming onto '{}': {e}", path.display()));
    }
    Ok(())
}

fn normalize_remote_origin_for_repo_id(raw_url: &str) -> Option<String> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return None;
    }
    let without_scheme = if let Some(rest) = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .or_else(|| trimmed.strip_prefix("ssh://"))
    {
        match rest.rfind('@') {
            Some(at) => &rest[at + 1..],
            None => rest,
        }
    } else if let Some(at) = trimmed.find('@')
        && let Some(colon) = trimmed[at + 1..].find(':')
    {
        // SCP-like git@github.com:owner/repo.git -> github.com/owner/repo
        let host = &trimmed[at + 1..at + 1 + colon];
        let path = &trimmed[at + 1 + colon + 1..];
        let clean_path = path.trim_end_matches('/').trim_end_matches(".git");
        return Some(format!(
            "{}/{}",
            host.to_ascii_lowercase(),
            clean_path.trim_start_matches('/')
        ));
    } else {
        return None;
    };
    let clean = without_scheme
        .trim_end_matches('/')
        .trim_end_matches(".git");
    if let Some(slash) = clean.find('/') {
        let host = clean[..slash].to_ascii_lowercase();
        let path = &clean[slash + 1..];
        if !host.is_empty() && !path.is_empty() {
            return Some(format!("{host}/{path}"));
        }
    }
    None
}

pub(crate) fn derive_portable_repo_id(canon_repo: &Path) -> String {
    if let Ok(explicit) = std::env::var("DOTAGENT_REPO_ID") {
        let t = explicit.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    if let Some(raw_origin) = run_git_capture(canon_repo, &["config", "--get", "remote.origin.url"])
        && let Some(norm) = normalize_remote_origin_for_repo_id(&raw_origin)
    {
        return format!("origin-sha256:{}", sha256_hex(norm.as_bytes()));
    }
    format!(
        "sha256:{}",
        sha256_hex(canon_repo.to_string_lossy().as_bytes())
    )
}

fn stream_sha256_file(path: &Path) -> Result<[u8; 32], String> {
    let f = File::open(path).map_err(|e| format!("failed opening '{}': {e}", path.display()))?;
    let mut reader = BufReader::new(f);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 16_384];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("failed reading '{}': {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn parse_porcelain_v1_z_paths(porcelain_z: &[u8]) -> Vec<String> {
    let mut paths = Vec::new();
    let mut parts = porcelain_z.split(|&b| b == 0);
    while let Some(entry) = parts.next() {
        if entry.len() < 4 {
            continue;
        }
        let x = entry[0];
        let y = entry[1];
        let rel = String::from_utf8_lossy(&entry[3..]).into_owned();
        paths.push(rel);
        if matches!(x, b'R' | b'C') || matches!(y, b'R' | b'C') {
            // Consume original path token emitted by `git status --porcelain=v1 -z`
            let _ = parts.next();
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

pub(crate) fn clean_smoke_rel_nonsymlink(
    canon_repo: &Path,
    rel: &str,
) -> Result<(PathBuf, String), String> {
    use std::path::Component;
    let trimmed = rel.trim().trim_start_matches("./");
    if trimmed.is_empty() || Path::new(trimmed).is_absolute() {
        return Err(format!("SMOKE_ARTIFACT_MISSING: invalid path '{rel}'"));
    }
    let (mut cur, mut norm) = (canon_repo.to_path_buf(), Vec::new());
    for comp in Path::new(trimmed).components() {
        match comp {
            Component::CurDir => {}
            Component::Normal(seg) => {
                let s = seg.to_string_lossy().into_owned();
                cur.push(&s);
                if fs::symlink_metadata(&cur).is_ok_and(|m| m.file_type().is_symlink()) {
                    return Err(format!("SMOKE_ARTIFACT_MISSING: symlink '{rel}'"));
                }
                norm.push(s);
            }
            _ => return Err(format!("SMOKE_ARTIFACT_MISSING: traversal '{rel}'")),
        }
    }
    Ok((cur, norm.join("/")))
}

pub(crate) fn verify_smoke_artifact(
    canon: &Path,
    rel: &str,
    hint: &str,
    out: &mut std::collections::BTreeMap<String, String>,
) -> Result<PathBuf, String> {
    use std::io::Read as _;
    let (full, norm) = clean_smoke_rel_nonsymlink(canon, rel)?;
    let meta = fs::symlink_metadata(&full)
        .map_err(|_| format!("SMOKE_ARTIFACT_MISSING: '{norm}' ({hint}) missing"))?;
    if meta.file_type().is_symlink()
        || !meta.file_type().is_file()
        || meta.len() == 0
        || meta.len() > 268_435_456
    {
        return Err(format!(
            "SMOKE_ARTIFACT_MISSING: '{norm}' ({hint}) empty, oversized, or non-regular"
        ));
    }
    let mut f =
        fs::File::open(&full).map_err(|e| format!("SMOKE_ARTIFACT_MISSING: '{norm}': {e}"))?;
    let mut head = Vec::with_capacity(8);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65_536];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("SMOKE_ARTIFACT_MISSING: '{norm}': {e}"))?;
        if n == 0 {
            break;
        }
        if head.len() < 8 {
            let take = (8 - head.len()).min(n);
            head.extend_from_slice(&buf[..take]);
        }
        hasher.update(&buf[..n]);
    }
    if norm.ends_with(".wasm") && head.as_slice() != b"\0asm\x01\0\0\0" {
        return Err(format!(
            "SMOKE_WASM_MAGIC_INVALID: '{norm}' lacks valid Wasm v1 magic"
        ));
    }
    out.insert(norm, crate::crypto::hex_encode(&hasher.finalize()));
    Ok(full)
}

pub(crate) fn recent_or_dirty_repo_paths(canon_repo: &Path) -> Result<Vec<String>, String> {
    let mut set = std::collections::BTreeSet::new();
    if canon_repo.join(".git").exists() {
        let raw = run_git_capture_raw(canon_repo, &["status", "--porcelain=v1", "-z", "-uall"])
            .ok_or_else(|| "SMOKE_CONFIG_INVALID: git status failed".to_string())?;
        for p in parse_porcelain_v1_z_paths(&raw) {
            set.insert(p);
        }
        if let Some(head_raw) = run_git_capture_raw(
            canon_repo,
            &[
                "diff-tree",
                "--root",
                "--no-commit-id",
                "--name-only",
                "-z",
                "-r",
                "HEAD",
            ],
        ) {
            for entry in head_raw.split(|&b| b == 0).filter(|s| !s.is_empty()) {
                set.insert(String::from_utf8_lossy(entry).into_owned());
            }
        }
    }
    Ok(set.into_iter().collect())
}

pub(crate) fn strip_code_comments_preserve_lines(src: &str, allow_hash: bool) -> String {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let (mut i, mut in_str, mut str_delim, mut in_block) = (0usize, false, b'"', false);
    while i < bytes.len() {
        let b = bytes[i];
        if in_block {
            if b == b'\n' {
                out.push('\n');
                i += 1;
            } else if b == b'*' && bytes.get(i + 1) == Some(&b'/') {
                in_block = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if in_str {
            out.push(b as char);
            if b == b'\\' && i + 1 < bytes.len() {
                out.push(bytes[i + 1] as char);
                i += 2;
                continue;
            }
            if b == str_delim {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if b == b'"' || b == b'\'' {
            in_str = true;
            str_delim = b;
            out.push(b as char);
            i += 1;
            continue;
        }
        if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            in_block = true;
            i += 2;
            continue;
        }
        if (b == b'/' && bytes.get(i + 1) == Some(&b'/')) || (allow_hash && b == b'#') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        out.push(b as char);
        i += 1;
    }
    out
}

/// Computes canonical `(repo_id, head_commit_oid, work_tree_oid, bundle_manifest_sha256)`
/// directly from the local repository without modifying `.git/index`.
pub fn snapshot_repo_attestation_digests(
    repo_root: &Path,
) -> Result<(String, String, String, String), String> {
    let canon = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let repo_id = derive_portable_repo_id(&canon);

    let head_commit_oid = run_git_capture(&canon, &["rev-parse", "--verify", "HEAD"])
        .unwrap_or_else(|| "UNBORN".to_string());
    let head_tree_oid = run_git_capture(&canon, &["rev-parse", "--verify", "HEAD^{tree}"])
        .unwrap_or_else(|| "EMPTY_TREE".to_string());

    // Bind both committed `HEAD^{tree}` AND deterministic streaming digest of ALL dirty/untracked
    // porcelain `-z` paths (including symlinks and >4 MiB files) so post-receipt working-tree edits
    // immediately invalidate verification!
    let status_porcelain =
        run_git_capture_raw(&canon, &["status", "--porcelain=v1", "-z", "-uall"])
            .unwrap_or_default();
    let mut tree_material = Vec::with_capacity(128 + status_porcelain.len());
    push_lp_str(&mut tree_material, &head_tree_oid);
    push_lp_bytes(&mut tree_material, &status_porcelain);
    for rel in parse_porcelain_v1_z_paths(&status_porcelain) {
        let p = canon.join(&rel);
        push_lp_str(&mut tree_material, &rel);
        match fs::symlink_metadata(&p) {
            Ok(meta) if meta.file_type().is_symlink() => {
                tree_material.push(b'L');
                let target = fs::read_link(&p)
                    .map(|t| t.to_string_lossy().into_owned())
                    .unwrap_or_default();
                push_lp_str(&mut tree_material, &target);
            }
            Ok(meta) if meta.file_type().is_file() => {
                tree_material.push(b'F');
                let file_sha = stream_sha256_file(&p)?;
                tree_material.extend_from_slice(&file_sha);
            }
            Ok(_) => {
                tree_material.push(b'O');
            }
            Err(_) => {
                tree_material.push(b'D');
            }
        }
    }
    let work_tree_oid = if status_porcelain.is_empty() && head_tree_oid != "EMPTY_TREE" {
        head_tree_oid
    } else {
        format!("dirty-tree-sha256:{}", sha256_hex(&tree_material))
    };

    let manifest_candidates = [
        canon.join("dist/manifest.sha256"),
        canon.join("dist-verify/manifest.sha256"),
        canon.join("AGENTS.md"),
    ];
    let mut bundle_manifest_sha256 = "NONE".to_string();
    for cand in &manifest_candidates {
        if let Ok(meta) = fs::symlink_metadata(cand)
            && meta.file_type().is_file()
            && !meta.file_type().is_symlink()
            && let Ok(digest) = stream_sha256_file(cand)
        {
            bundle_manifest_sha256 = hex_encode(&digest);
            break;
        }
    }

    Ok((
        repo_id,
        head_commit_oid,
        work_tree_oid,
        bundle_manifest_sha256,
    ))
}

fn run_git_capture(repo_root: &Path, git_args: &[&str]) -> Option<String> {
    let out = run_git_capture_raw(repo_root, git_args)?;
    let s = String::from_utf8(out).ok()?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn run_git_capture_raw(repo_root: &Path, git_args: &[&str]) -> Option<Vec<u8>> {
    let out = Command::new("git")
        .current_dir(repo_root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(git_args)
        .output()
        .ok()?;
    if out.status.success() {
        Some(out.stdout)
    } else {
        None
    }
}

/// Mints and signs an asymmetric Ed25519 `StopReceipt` on the trusted host after independently
/// re-verifying repository audit cleanliness and non-halted session ledger state.
pub fn issue_verified_stop_receipt(
    repo_root: &Path,
    explicit_out: Option<&Path>,
) -> Result<(StopReceipt, PathBuf), String> {
    if std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() == Ok("1")
        || std::env::var("AGENT_GUARD_WORKER_LOCK").as_deref() == Ok("1")
    {
        return Err(
            "STOP_RECEIPT_SANDBOX_MINT_DENIED: StopReceipt attestation can only be minted outside exec-sandbox"
                .to_string(),
        );
    }

    let canon = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    if let Err(errs) = audit_repository(&canon) {
        return Err(format!(
            "STOP_RECEIPT_AUDIT_FAILED: cannot attest dirty repository: {}",
            errs.join("; ")
        ));
    }

    let sid = std::env::var("AGENT_GUARD_SESSION_ID").unwrap_or_else(|_| "default".to_string());
    let _session_lock = SessionLedger::acquire_lock(&canon, &sid);
    let ledger = SessionLedger::load_or_create(&canon, &sid);
    if ledger.halted {
        return Err(format!(
            "STOP_RECEIPT_LEDGER_HALTED: session '{sid}' circuit breaker is tripped ({})",
            ledger.halt_reason.as_deref().unwrap_or("halted")
        ));
    }
    if ledger.tainted {
        return Err(format!(
            "STOP_RECEIPT_LEDGER_TAINTED: session '{sid}' is tainted by untrusted provenance ({})",
            ledger.taint_reason.as_deref().unwrap_or("tainted")
        ));
    }

    let epoch_id = crate::coordinator::current_hmac_epoch_id(&canon).unwrap_or(1);
    let smoke = crate::smoke_gate::verify_repo_smoke_gate(&canon)?;
    let (repo_id, head_commit_oid, work_tree_oid, bundle_manifest_sha256) =
        snapshot_repo_attestation_digests(&canon)?;

    let seed_key = load_or_init_ed25519_signing_key(&canon)?;
    let signing_key = SigningKey::from_bytes(seed_key.as_bytes());
    let pubkey_ed25519_hex = hex_encode(signing_key.verifying_key().as_bytes());
    let issued_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut receipt = StopReceipt {
        schema: STOP_RECEIPT_SCHEMA.to_string(),
        repo_id,
        head_commit_oid,
        work_tree_oid,
        bundle_manifest_sha256,
        smoke_gate_digest: smoke.smoke_gate_digest,
        ledger: LedgerCleanSummary {
            session_id: sid,
            halted: ledger.halted,
            tainted: ledger.tainted,
            file_reads: ledger.file_reads,
            tool_calls: ledger.tool_calls,
            cumulative_tokens: ledger.cumulative_tokens,
            epoch_id,
        },
        issued_at_unix,
        pubkey_ed25519_hex,
        signature_ed25519_hex: String::new(),
    };

    let msg = receipt.canonical_signing_bytes();
    let sig = signing_key.sign(&msg);
    receipt.signature_ed25519_hex = hex_encode(&sig.to_bytes());

    let out_path = explicit_out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_latest_receipt_path(&canon));
    let json_text = format!("{}\n", receipt.to_json_value().to_json_string());
    write_atomic_nonsymlink(&out_path, json_text.as_bytes(), 0o600)?;

    Ok((receipt, out_path))
}

/// CLI: `dotagent verify-receipt <receipt.json> [--pubkey <hex|path>] [--repo <dir>] [--repo-id <id>] [--require-untainted | --allow-tainted]`
pub fn run_verify_receipt_cli(args: &[String], cwd: &Path) -> ExitCode {
    let mut receipt_arg: Option<PathBuf> = None;
    let mut pubkey_arg: Option<String> = None;
    let mut repo_arg: Option<PathBuf> = None;
    let mut repo_id_override: Option<String> = None;
    let mut require_untainted = true;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--pubkey" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[AGENT-GUARD] verify-receipt: missing value after --pubkey");
                    return ExitCode::from(2);
                };
                pubkey_arg = Some(v.clone());
                i += 2;
            }
            "--repo" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[AGENT-GUARD] verify-receipt: missing path after --repo");
                    return ExitCode::from(2);
                };
                repo_arg = Some(PathBuf::from(v));
                i += 2;
            }
            "--repo-id" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[AGENT-GUARD] verify-receipt: missing value after --repo-id");
                    return ExitCode::from(2);
                };
                repo_id_override = Some(v.clone());
                i += 2;
            }
            "--require-untainted" => {
                require_untainted = true;
                i += 1;
            }
            "--allow-tainted" => {
                require_untainted = false;
                i += 1;
            }
            other if !other.starts_with('-') && receipt_arg.is_none() => {
                receipt_arg = Some(PathBuf::from(other));
                i += 1;
            }
            other => {
                eprintln!("[AGENT-GUARD] verify-receipt: unrecognized argument '{other}'");
                return ExitCode::from(2);
            }
        }
    }

    let target_repo = repo_arg.unwrap_or_else(|| resolve_repo_root(cwd));
    let receipt_path = receipt_arg.unwrap_or_else(|| default_latest_receipt_path(&target_repo));
    if let Ok(meta) = fs::symlink_metadata(&receipt_path)
        && meta.file_type().is_symlink()
    {
        eprintln!(
            "[AGENT-GUARD RECEIPT FAIL] SYMLINK_TAMPER_DETECTED: StopReceipt '{}' is a symlink",
            receipt_path.display()
        );
        return ExitCode::from(2);
    }
    let raw = match fs::read_to_string(&receipt_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[AGENT-GUARD RECEIPT FAIL] could not read StopReceipt '{}': {e}",
                receipt_path.display()
            );
            return ExitCode::from(2);
        }
    };

    let receipt = match StopReceipt::from_json_str(&raw) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[AGENT-GUARD RECEIPT FAIL] {e}");
            return ExitCode::from(2);
        }
    };

    let effective_pubkey_arg = pubkey_arg.or_else(|| {
        std::env::var("DOTAGENT_RECEIPT_PUBKEY")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    });

    let pinned_pubkey = match effective_pubkey_arg {
        Some(ref s) if Path::new(s).exists() => {
            match fs::symlink_metadata(s) {
                Ok(m) if m.file_type().is_symlink() || !m.file_type().is_file() => {
                    eprintln!(
                        "[AGENT-GUARD RECEIPT FAIL] pubkey file '{s}' must be a regular non-symlink file"
                    );
                    return ExitCode::from(2);
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!("[AGENT-GUARD RECEIPT FAIL] failed stat on pubkey file '{s}': {e}");
                    return ExitCode::from(2);
                }
            }
            match fs::read_to_string(s) {
                Ok(k) => Some(k.trim().to_string()),
                Err(e) => {
                    eprintln!("[AGENT-GUARD RECEIPT FAIL] failed reading pubkey file '{s}': {e}");
                    return ExitCode::from(2);
                }
            }
        }
        Some(s) => Some(s),
        None => receipt_pubkey_path(&target_repo).ok().and_then(|p| {
            let meta = fs::symlink_metadata(&p).ok()?;
            if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                return None;
            }
            fs::read_to_string(&p)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        }),
    };

    let Some(expected_pubkey_hex) = pinned_pubkey else {
        eprintln!(
            "[AGENT-GUARD RECEIPT FAIL] RECEIPT_PUBKEY_REQUIRED: no trusted Ed25519 verifying key found; pass `--pubkey <hex|path>` or set `DOTAGENT_RECEIPT_PUBKEY` (self-signed receipts without a pinned key are rejected)."
        );
        return ExitCode::from(2);
    };

    if let Err(e) = receipt.verify_signature(&expected_pubkey_hex) {
        eprintln!("[AGENT-GUARD RECEIPT FAIL] {e}");
        return ExitCode::from(2);
    }

    if require_untainted && receipt.ledger.tainted {
        eprintln!(
            "[AGENT-GUARD RECEIPT FAIL] RECEIPT_TAINTED_SESSION: session '{}' was marked tainted",
            receipt.ledger.session_id
        );
        return ExitCode::from(2);
    }

    match snapshot_repo_attestation_digests(&target_repo) {
        Ok((live_repo_id, live_head, live_tree_oid, live_bundle)) => {
            let expected_repo_id = repo_id_override.as_deref().unwrap_or(&live_repo_id);
            if receipt.repo_id != expected_repo_id {
                eprintln!(
                    "[AGENT-GUARD RECEIPT FAIL] RECEIPT_REPO_MISMATCH: receipt repo_id '{}' != expected '{}'",
                    receipt.repo_id, expected_repo_id
                );
                return ExitCode::from(2);
            }
            if receipt.head_commit_oid != live_head {
                eprintln!(
                    "[AGENT-GUARD RECEIPT FAIL] RECEIPT_HEAD_DRIFT: receipt head_commit_oid '{}' != live '{}'",
                    receipt.head_commit_oid, live_head
                );
                return ExitCode::from(2);
            }
            if receipt.work_tree_oid != live_tree_oid {
                eprintln!(
                    "[AGENT-GUARD RECEIPT FAIL] RECEIPT_WORKTREE_DRIFT: receipt tree '{}' != live '{}'",
                    receipt.work_tree_oid, live_tree_oid
                );
                return ExitCode::from(2);
            }
            if receipt.bundle_manifest_sha256 != live_bundle {
                eprintln!(
                    "[AGENT-GUARD RECEIPT FAIL] RECEIPT_BUNDLE_DRIFT: receipt bundle_manifest_sha256 '{}' != live '{}'",
                    receipt.bundle_manifest_sha256, live_bundle
                );
                return ExitCode::from(2);
            }
        }
        Err(e) => {
            eprintln!("[AGENT-GUARD RECEIPT FAIL] failed snapshotting live repo: {e}");
            return ExitCode::from(2);
        }
    }

    match crate::smoke_gate::verify_repo_smoke_gate(&target_repo) {
        Ok(live_smoke) if receipt.smoke_gate_digest == live_smoke.smoke_gate_digest => {}
        Ok(live_smoke) => {
            eprintln!(
                "[AGENT-GUARD RECEIPT FAIL] RECEIPT_SMOKE_GATE_DRIFT: receipt smoke_gate_digest '{}' != live '{}'",
                receipt.smoke_gate_digest, live_smoke.smoke_gate_digest
            );
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("[AGENT-GUARD RECEIPT FAIL] {e}");
            return ExitCode::from(2);
        }
    }

    println!(
        "[AGENT-GUARD RECEIPT VERIFIED] repo_id={} head={} tree={} epoch={} pubkey={}",
        receipt.repo_id,
        receipt.head_commit_oid,
        receipt.work_tree_oid,
        receipt.ledger.epoch_id,
        receipt.pubkey_ed25519_hex
    );
    ExitCode::SUCCESS
}

/// CLI: `dotagent receipt-pubkey [--repo <dir>] [<dir>]`
pub fn run_receipt_pubkey_cli(args: &[String], cwd: &Path) -> ExitCode {
    let mut repo_arg: Option<PathBuf> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--repo" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[AGENT-GUARD] receipt-pubkey: missing path after --repo");
                    return ExitCode::from(2);
                };
                repo_arg = Some(PathBuf::from(v));
                i += 2;
            }
            other if !other.starts_with('-') && repo_arg.is_none() => {
                repo_arg = Some(PathBuf::from(other));
                i += 1;
            }
            other => {
                eprintln!("[AGENT-GUARD] receipt-pubkey: unrecognized argument '{other}'");
                return ExitCode::from(2);
            }
        }
    }
    let target_repo = repo_arg.unwrap_or_else(|| resolve_repo_root(cwd));
    match load_or_init_ed25519_signing_key(&target_repo) {
        Ok(zk) => {
            let sk = SigningKey::from_bytes(zk.as_bytes());
            println!("{}", hex_encode(sk.verifying_key().as_bytes()));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("[AGENT-GUARD RECEIPT KEY ERROR] {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_stop_receipt_roundtrip_and_tamper_rejection() {
        let seed = [0x42u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pub_hex = hex_encode(sk.verifying_key().as_bytes());

        let mut rec = StopReceipt {
            schema: STOP_RECEIPT_SCHEMA.to_string(),
            repo_id: "origin-sha256:0123456789abcdef".to_string(),
            head_commit_oid: "88e93a5".to_string(),
            work_tree_oid: "tree1234".to_string(),
            bundle_manifest_sha256: "bundle5678".to_string(),
            smoke_gate_digest: "smoke9abc".to_string(),
            ledger: LedgerCleanSummary {
                session_id: "default".to_string(),
                halted: false,
                tainted: false,
                file_reads: 3,
                tool_calls: 7,
                cumulative_tokens: 920,
                epoch_id: 2,
            },
            issued_at_unix: 1_795_000_000,
            pubkey_ed25519_hex: pub_hex.clone(),
            signature_ed25519_hex: String::new(),
        };
        let sig = sk.sign(&rec.canonical_signing_bytes());
        rec.signature_ed25519_hex = hex_encode(&sig.to_bytes());

        let serialized = rec.to_json_value().to_json_string();
        let parsed = StopReceipt::from_json_str(&serialized).expect("valid JSON");
        assert!(parsed.verify_signature(&pub_hex).is_ok());

        // Tamper with work_tree_oid or smoke_gate_digest -> must fail Ed25519 verification
        let mut tampered = parsed.clone();
        tampered.work_tree_oid = "tree_forged".to_string();
        assert!(tampered.verify_signature(&pub_hex).is_err());

        let mut tampered_smoke = parsed.clone();
        tampered_smoke.smoke_gate_digest = "smoke_forged".to_string();
        assert!(tampered_smoke.verify_signature(&pub_hex).is_err());

        // Wrong pinned pubkey -> must fail
        let wrong_sk = SigningKey::from_bytes(&[0x99u8; 32]);
        let wrong_pub = hex_encode(wrong_sk.verifying_key().as_bytes());
        assert!(parsed.verify_signature(&wrong_pub).is_err());
    }
}
