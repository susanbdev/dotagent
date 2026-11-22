#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! Append-Only Signed GitHub Queue Sync & Airlocked 6-Stage Constitutional Loop (`dotagent v2.1`).
//!
//! Security Architecture:
//! 1. **Append-Only Ed25519-Signed Queue (`sync-github`)**: Fleet nodes never mutate GitHub Issue
//!    bodies (eliminating cross-VM Read-Modify-Write races and HTML-comment injection). Each sync
//!    appends a discrete `dotagent:sync-sig:v2` Ed25519-signed batch comment.
//! 2. **Cryptographic Queue Rehydration & Swarm Quorum (`run-loop`)**: Ignores issue bodies and
//!    unsigned/untrusted comments; verifies `dotagent:sync-sig:v2` signatures against
//!    `config/telemetry_verify_keys.pub` (plus optional `DOTAGENT_TELEMETRY_VERIFY_KEY`), requiring
//!    `>= 3` unique root-session votes across `>= 2` `(repo_id, utc_day)` buckets and enforcing a
//!    2-strike circuit breaker per
//!    `(cluster_key, main_tree_hash)` (`friction-escalated-human`).
//! 3. **Credential & Prompt Airlock (`Command::env_clear()`)**: GitHub token stays exclusively in
//!    parent Rust process memory. Stage 1-4 subprocesses run with `Command::env_clear()`. Raw
//!    ballot notes stop at Stage 1 (Auditor, `--deny-net`), which emits a strictly validated
//!    `Ring2RemediationSpec` JSON with zero free-form prose passed to Stage 3 (`--implementer-cmd`).
//! 4. **Structural Copilot Gate & Post-Fix Stale Thread Resolution**: Verifies the required CI
//!    checks and `Ring-0 & Copilot Gate`, confirms `copilot-pull-request-reviewer[bot]`
//!    reviewed `head_sha` with `0` inline review comments, and resolves stale threads from prior
//!    commits *only after* a fresh `0`-comment Copilot review lands on the new `head_sha`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::breadcrumbs::ExclusiveFileLockGuard;
use crate::crypto::{
    ZeroizingKey, hex_decode_32, hex_decode_bytes, hex_encode, sha256_hex, zeroize_slice,
};
use crate::feedback::{
    AGENTPI_EVENT_SCHEMA, AggregatedFrictionCluster, MAX_AGENTPI_EXPORT_INPUT_BYTES,
    aggregate_verified_clusters, clean_single_line_ascii, compute_cluster_key,
    current_host_spool_id, feedback_state_dir, is_ring0_constitutional_code, is_valid_cluster_key,
    load_verified_ballots,
};
use crate::github_governance::{DOTAGENT_REQUIRED_CHECKS, validate_github_ident};
use crate::json::JsonValue;
use crate::resolve_repo_root;
use crate::ring0_ratchet::{validate_git_ref_arg, verify_ring0_ratchet};
use crate::sanitizer::wrap_spotlight_envelope;
use crate::telemetry::AGENT_SANDBOX_AND_HARNESS_MARKERS;
use crate::telemetry::protocol::Kind;
use crate::telemetry::runtime::{note_invalid_export, submit_record};
use crate::traversal_ledger::ensure_nonsymlink_state_dir;

pub const SYNC_BATCH_SCHEMA_V2: &str = "dotagent.sync_batch.v2";
pub const SYNC_SIG_DOMAIN_V2: &[u8] = b"dotagent:sync-sig:v2";
const COMMENT_SIG_MARKER: &str = "<!-- dotagent:sync-sig:v2 -->";
const ATTEMPT_MARKER_PREFIX: &str = "<!-- dotagent:loop-attempt:v2 ";

struct ZeroizingToken(Vec<u8>);

impl ZeroizingToken {
    fn from_env_and_scrub() -> Option<Self> {
        if let Ok(path_str) = std::env::var("DOTAGENT_LOOP_GITHUB_TOKEN_FILE") {
            let trimmed_path = path_str.trim();
            if !trimmed_path.is_empty() {
                let p = Path::new(trimmed_path);
                let is_regular = fs::symlink_metadata(p)
                    .map(|m| m.file_type().is_file() && !m.file_type().is_symlink())
                    .unwrap_or(false);
                if is_regular {
                    let raw = fs::read_to_string(p).ok();
                    let _ = fs::write(p, [0u8; 128]);
                    let _ = fs::remove_file(p);
                    if let Some(s) = raw {
                        let t = s.trim();
                        if !t.is_empty() {
                            return Some(Self(t.as_bytes().to_vec()));
                        }
                    }
                } else {
                    let _ = fs::remove_file(p);
                }
            }
        }
        let mut found: Option<String> = None;
        for var in ["DOTAGENT_LOOP_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"] {
            if let Ok(v) = std::env::var(var) {
                let t = v.trim();
                if !t.is_empty() && found.is_none() {
                    found = Some(t.to_string());
                }
            }
        }
        found.map(|s| Self(s.into_bytes()))
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or("")
    }
}

impl Drop for ZeroizingToken {
    fn drop(&mut self) {
        zeroize_slice(&mut self.0);
    }
}

pub fn verify_feedback_operator_or_ci_loop(cmd_label: &str) -> Result<(), String> {
    for hard_sandbox in [
        "AGENT_GUARD_IN_SANDBOX",
        "AGENT_GUARD_WORKER_LOCK",
        "AGENT_GUARD_ROLE",
    ] {
        if let Ok(v) = std::env::var(hard_sandbox)
            && !v.trim().is_empty()
            && v.trim() != "0"
            && !v.trim().eq_ignore_ascii_case("false")
        {
            return Err(format!(
                "FEEDBACK_OPERATOR_ONLY: `{cmd_label}` is blocked inside sandboxed/role worker ('{hard_sandbox}' is active)"
            ));
        }
    }

    if std::env::var("DOTAGENT_AUTONOMOUS_LOOP").as_deref() == Ok("1")
        && std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
        && std::env::var("GITHUB_WORKFLOW_REF")
            .map(|r| r.contains("/.github/workflows/friction-loop.yml@"))
            .unwrap_or(false)
    {
        return Ok(());
    }

    for &marker in AGENT_SANDBOX_AND_HARNESS_MARKERS {
        if let Ok(v) = std::env::var(marker)
            && !v.trim().is_empty()
            && v.trim() != "0"
            && !v.trim().eq_ignore_ascii_case("false")
        {
            return Err(format!(
                "FEEDBACK_OPERATOR_ONLY: `{cmd_label}` is blocked inside AI agent harness ('{marker}' is active; agents may only call `dotagent feedback submit`)"
            ));
        }
    }
    Ok(())
}

const TRUSTED_EXEC_PATH: &str =
    "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin:/opt/antigravity/bin";

fn trusted_command_path(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().find_map(|candidate| {
        let path = Path::new(candidate);
        if !crate::coordinator::has_trusted_executable_ancestors(path) {
            return None;
        }
        let canonical = fs::canonicalize(path).ok()?;
        if !crate::coordinator::is_trusted_executable_file(&canonical) {
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(&canonical).ok()?.permissions().mode() & 0o111 == 0 {
                return None;
            }
        }
        Some(canonical)
    })
}

fn trusted_git_bin() -> Option<PathBuf> {
    trusted_command_path(&[
        "/usr/bin/git",
        "/bin/git",
        "/usr/local/bin/git",
        "/opt/homebrew/bin/git",
    ])
}

/// Returns an approved GitHub CLI path or an empty path when no candidate passes validation.
pub fn resolve_gh_bin() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = std::env::var_os("DOTAGENT_FEEDBACK_TEST_GH") {
        return PathBuf::from(path);
    }
    trusted_command_path(&[
        "/usr/bin/gh",
        "/usr/local/bin/gh",
        "/opt/homebrew/bin/gh",
        "/opt/antigravity/bin/gh",
    ])
    .unwrap_or_default()
}

pub fn validate_owner_repo(full_repo: &str) -> Result<(String, String), String> {
    let (owner, repo) = full_repo
        .trim()
        .split_once('/')
        .ok_or_else(|| format!("invalid repository '{full_repo}' (expected <owner>/<repo>)"))?;
    if repo.contains('/') {
        return Err(format!(
            "invalid repository '{full_repo}' (expected single '/' separator)"
        ));
    }
    validate_github_ident(owner)?;
    validate_github_ident(repo)?;
    Ok((owner.to_string(), repo.to_string()))
}

fn github_origin_identity(url: &str) -> Option<(String, String)> {
    if url
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return None;
    }
    let url = url.trim_end_matches('/').to_ascii_lowercase();
    let authority = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("ssh://git@github.com/"))
        .or_else(|| url.strip_prefix("git@github.com:"))?;
    let slug = authority.strip_suffix(".git").unwrap_or(authority);
    validate_owner_repo(slug).ok()
}

fn verify_checkout_matches_target_repo(repo_root: &Path, target_repo: &str) -> Result<(), String> {
    let (owner, name) = validate_owner_repo(target_repo)?;
    let out = hardened_git_cmd(repo_root)
        .args([
            "config",
            "--no-includes",
            "--local",
            "--null",
            "--get-all",
            "remote.origin.url",
        ])
        .output()
        .map_err(|e| {
            format!("SYNC_REPO_MISMATCH: unable to read checkout origin with trusted Git: {e}")
        })?;
    if !out.status.success() {
        return Err("SYNC_REPO_MISMATCH: checkout must have a GitHub origin".to_string());
    }
    let raw = std::str::from_utf8(&out.stdout)
        .map_err(|_| "SYNC_REPO_MISMATCH: checkout origin is invalid".to_string())?;
    let origin = raw.strip_suffix('\0').and_then(github_origin_identity);
    if !origin.is_some_and(|(actual_owner, actual_name)| {
        actual_owner.eq_ignore_ascii_case(&owner) && actual_name.eq_ignore_ascii_case(&name)
    }) {
        return Err(format!(
            "SYNC_REPO_MISMATCH: checkout must have one verified GitHub origin matching '{target_repo}'"
        ));
    }
    Ok(())
}

fn push_lp_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
    buf.extend_from_slice(b);
}

fn push_lp_str(buf: &mut Vec<u8>, s: &str) {
    push_lp_bytes(buf, s.as_bytes());
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSyncBatchV2 {
    pub schema: String,
    pub node_id: String,
    pub cluster_key: String,
    pub category: String,
    pub deny_code: Option<String>,
    pub target_bin_or_tool: String,
    pub canonical_shape: String,
    pub voter_entries: Vec<(String, String)>, // (voter_token, repo_day_bucket)
    pub raw_submissions: usize,
    pub tainted_attempts: usize,
    pub loop_anomalies: usize,
    pub scrubbed_notes: Vec<String>,
    pub ts_unix: u64,
    pub pubkey_ed25519_hex: String,
    pub signature_ed25519_hex: String,
}

impl SignedSyncBatchV2 {
    /// Signing bytes are bound to the lowercase `owner/repo` queue the batch is posted to, so a
    /// valid batch cannot be replayed into a different repository's friction queue.
    pub fn canonical_signing_bytes(&self, target_repo: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        push_lp_bytes(&mut out, SYNC_SIG_DOMAIN_V2);
        push_lp_str(&mut out, &target_repo.to_ascii_lowercase());
        push_lp_str(&mut out, &self.schema);
        push_lp_str(&mut out, &self.node_id);
        push_lp_str(&mut out, &self.cluster_key);
        push_lp_str(&mut out, &self.category);
        push_lp_str(&mut out, self.deny_code.as_deref().unwrap_or(""));
        push_lp_str(&mut out, &self.target_bin_or_tool);
        push_lp_str(&mut out, &self.canonical_shape);
        out.extend_from_slice(&(self.voter_entries.len() as u32).to_be_bytes());
        for (vt, bucket) in &self.voter_entries {
            push_lp_str(&mut out, vt);
            push_lp_str(&mut out, bucket);
        }
        out.extend_from_slice(&(self.raw_submissions as u64).to_be_bytes());
        out.extend_from_slice(&(self.tainted_attempts as u64).to_be_bytes());
        out.extend_from_slice(&(self.loop_anomalies as u64).to_be_bytes());
        out.extend_from_slice(&(self.scrubbed_notes.len() as u32).to_be_bytes());
        for n in &self.scrubbed_notes {
            push_lp_str(&mut out, n);
        }
        out.extend_from_slice(&self.ts_unix.to_be_bytes());
        push_lp_str(&mut out, &self.pubkey_ed25519_hex);
        out
    }

    pub fn to_json_value(&self) -> JsonValue {
        let voters: Vec<JsonValue> = self
            .voter_entries
            .iter()
            .map(|(vt, b)| {
                JsonValue::Object(vec![
                    ("voter_token".to_string(), JsonValue::Str(vt.clone())),
                    ("repo_day_bucket".to_string(), JsonValue::Str(b.clone())),
                ])
            })
            .collect();
        let notes: Vec<JsonValue> = self
            .scrubbed_notes
            .iter()
            .map(|n| JsonValue::Str(n.clone()))
            .collect();
        JsonValue::Object(vec![
            ("schema".to_string(), JsonValue::Str(self.schema.clone())),
            ("node_id".to_string(), JsonValue::Str(self.node_id.clone())),
            (
                "cluster_key".to_string(),
                JsonValue::Str(self.cluster_key.clone()),
            ),
            (
                "category".to_string(),
                JsonValue::Str(self.category.clone()),
            ),
            (
                "deny_code".to_string(),
                self.deny_code
                    .as_ref()
                    .map_or(JsonValue::Null, |c| JsonValue::Str(c.clone())),
            ),
            (
                "target_bin_or_tool".to_string(),
                JsonValue::Str(self.target_bin_or_tool.clone()),
            ),
            (
                "canonical_shape".to_string(),
                JsonValue::Str(self.canonical_shape.clone()),
            ),
            ("voter_entries".to_string(), JsonValue::Array(voters)),
            (
                "raw_submissions".to_string(),
                JsonValue::Uint(self.raw_submissions as u64),
            ),
            (
                "tainted_attempts".to_string(),
                JsonValue::Uint(self.tainted_attempts as u64),
            ),
            (
                "loop_anomalies".to_string(),
                JsonValue::Uint(self.loop_anomalies as u64),
            ),
            ("scrubbed_notes".to_string(), JsonValue::Array(notes)),
            ("ts_unix".to_string(), JsonValue::Uint(self.ts_unix)),
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

    pub fn from_json_value(v: &JsonValue) -> Result<Self, String> {
        let req_str = |k: &str| -> Result<String, String> {
            v.get(k)
                .and_then(JsonValue::as_str)
                .map(String::from)
                .ok_or_else(|| format!("missing '{k}' in SignedSyncBatchV2"))
        };
        let schema = req_str("schema")?;
        if schema != SYNC_BATCH_SCHEMA_V2 {
            return Err(format!("unsupported sync batch schema '{schema}'"));
        }
        let cluster_key = req_str("cluster_key")?;
        if !is_valid_cluster_key(&cluster_key) {
            return Err(format!("invalid cluster_key '{cluster_key}'"));
        }
        let category = clean_single_line_ascii(&req_str("category")?, 48);
        let deny_code = v
            .get("deny_code")
            .and_then(JsonValue::as_str)
            .map(|s| clean_single_line_ascii(s, 64))
            .filter(|s| !s.is_empty());
        let target_bin_or_tool = clean_single_line_ascii(&req_str("target_bin_or_tool")?, 48);
        let canonical_shape = clean_single_line_ascii(&req_str("canonical_shape")?, 120);

        let expected_ck = compute_cluster_key(&category, deny_code.as_deref(), &canonical_shape);
        if cluster_key != expected_ck {
            return Err(format!(
                "cluster_key '{cluster_key}' does not match recomputed '{expected_ck}'"
            ));
        }

        let mut voter_entries = Vec::new();
        if let Some(arr) = v.get("voter_entries").and_then(JsonValue::as_array) {
            for item in arr.iter().take(512) {
                if let (Some(vt), Some(b)) = (
                    item.get("voter_token").and_then(JsonValue::as_str),
                    item.get("repo_day_bucket").and_then(JsonValue::as_str),
                ) && vt.len() == 24
                    && vt.bytes().all(|c| c.is_ascii_hexdigit())
                    && !b.is_empty()
                    && b.len() <= 32
                {
                    voter_entries.push((vt.to_string(), clean_single_line_ascii(b, 32)));
                }
            }
        }

        let mut scrubbed_notes = Vec::new();
        if let Some(arr) = v.get("scrubbed_notes").and_then(JsonValue::as_array) {
            for n in arr.iter().take(4) {
                if let Some(s) = n.as_str() {
                    let c = clean_single_line_ascii(s, 180);
                    if !c.is_empty() {
                        scrubbed_notes.push(c);
                    }
                }
            }
        }

        Ok(Self {
            schema,
            node_id: clean_single_line_ascii(&req_str("node_id")?, 48),
            cluster_key,
            category,
            deny_code,
            target_bin_or_tool,
            canonical_shape,
            voter_entries,
            raw_submissions: v
                .get("raw_submissions")
                .and_then(JsonValue::as_u64)
                .unwrap_or(0) as usize,
            tainted_attempts: v
                .get("tainted_attempts")
                .and_then(JsonValue::as_u64)
                .unwrap_or(0) as usize,
            loop_anomalies: v
                .get("loop_anomalies")
                .and_then(JsonValue::as_u64)
                .unwrap_or(0) as usize,
            scrubbed_notes,
            ts_unix: v.get("ts_unix").and_then(JsonValue::as_u64).unwrap_or(0),
            pubkey_ed25519_hex: req_str("pubkey_ed25519_hex")?,
            signature_ed25519_hex: req_str("signature_ed25519_hex")?,
        })
    }

    pub fn verify_signature(
        &self,
        trusted_pubkeys_hex: &BTreeSet<String>,
        target_repo: &str,
    ) -> Result<(), String> {
        let pub_lower = self.pubkey_ed25519_hex.trim().to_ascii_lowercase();
        if !trusted_pubkeys_hex.contains(&pub_lower) {
            return Err(format!(
                "UNTRUSTED_SYNC_PUBKEY: pubkey '{pub_lower}' is not enrolled in config/telemetry_verify_keys.pub"
            ));
        }
        let pk_bytes = hex_decode_32(&pub_lower)?;
        let vk = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| format!("invalid Ed25519 pubkey: {e}"))?;
        let sig_raw = hex_decode_bytes(&self.signature_ed25519_hex)?;
        let sig =
            Signature::from_slice(&sig_raw).map_err(|e| format!("invalid Ed25519 sig: {e}"))?;
        vk.verify(&self.canonical_signing_bytes(target_repo), &sig)
            .map_err(|e| format!("SYNC_BATCH_SIGNATURE_INVALID: {e}"))
    }

    pub fn format_as_github_comment(&self) -> String {
        format!(
            "{COMMENT_SIG_MARKER}\n```json\n{}\n```\n",
            self.to_json_value().to_json_string()
        )
    }

    pub fn parse_from_github_comment(body: &str) -> Option<Result<Self, String>> {
        let idx = body.find(COMMENT_SIG_MARKER)?;
        let after = &body[idx + COMMENT_SIG_MARKER.len()..];
        let json_start = after.find('{')?;
        let json_end = after.rfind('}')?;
        if json_end < json_start {
            return Some(Err(
                "malformed JSON block in signed sync comment".to_string()
            ));
        }
        let raw_json = &after[json_start..=json_end];
        Some(
            JsonValue::parse(raw_json)
                .map_err(|e| format!("invalid sync batch JSON: {e}"))
                .and_then(|v| Self::from_json_value(&v)),
        )
    }
}

pub fn load_or_init_telemetry_signing_key() -> Result<(ZeroizingKey, String), String> {
    if let Ok(env_hex) = std::env::var("DOTAGENT_TELEMETRY_SIGNING_KEY") {
        let trimmed = env_hex.trim();
        if !trimmed.is_empty() {
            let seed = hex_decode_32(trimmed)?;
            let zk = ZeroizingKey::new(seed);
            let sk = SigningKey::from_bytes(zk.as_bytes());
            let pub_hex = hex_encode(sk.verifying_key().as_bytes());
            return Ok((zk, pub_hex));
        }
    }

    let vault_dir = feedback_state_dir()?.join("vault");
    ensure_nonsymlink_state_dir(&vault_dir)?;
    let key_path = vault_dir.join("telemetry_ed25519.key");
    let pub_path = vault_dir.join("telemetry_ed25519.pub");
    let lock_path = vault_dir.join("telemetry_ed25519.lock");
    let _guard = ExclusiveFileLockGuard::acquire(&lock_path)?;

    if let Ok(meta) = fs::symlink_metadata(&key_path) {
        if meta.file_type().is_symlink() {
            return Err("telemetry_ed25519.key must not be a symlink".to_string());
        }
        if meta.file_type().is_file() {
            let raw = fs::read_to_string(&key_path)
                .map_err(|e| format!("failed reading telemetry_ed25519.key: {e}"))?;
            let mut seed = hex_decode_32(raw.trim())?;
            let zk = ZeroizingKey::new(seed);
            zeroize_slice(&mut seed);
            let sk = SigningKey::from_bytes(zk.as_bytes());
            let pub_hex = hex_encode(sk.verifying_key().as_bytes());
            return Ok((zk, pub_hex));
        }
    }

    let mut seed = [0u8; 32];
    #[cfg(unix)]
    {
        let mut f = fs::File::open("/dev/urandom")
            .map_err(|e| format!("failed opening /dev/urandom: {e}"))?;
        f.read_exact(&mut seed)
            .map_err(|e| format!("failed reading /dev/urandom: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        seed = crate::crypto::sha256_bytes(&nanos.to_le_bytes());
    }
    let zk = ZeroizingKey::new(seed);
    zeroize_slice(&mut seed);
    let sk = SigningKey::from_bytes(zk.as_bytes());
    let pub_hex = hex_encode(sk.verifying_key().as_bytes());

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut kf = opts
        .open(&key_path)
        .map_err(|e| format!("failed creating telemetry_ed25519.key: {e}"))?;
    writeln!(kf, "{}", hex_encode(zk.as_bytes()))
        .and_then(|()| kf.sync_all())
        .map_err(|e| format!("failed writing telemetry_ed25519.key: {e}"))?;
    let _ = fs::write(&pub_path, format!("{pub_hex}\n"));
    Ok((zk, pub_hex))
}

pub fn load_trusted_telemetry_verify_pubkeys(repo_root: &Path) -> Result<BTreeSet<String>, String> {
    let mut keys = BTreeSet::new();
    let cfg_path = repo_root.join("config/telemetry_verify_keys.pub");
    if let Ok(meta) = fs::symlink_metadata(&cfg_path) {
        if meta.file_type().is_symlink() {
            return Err("config/telemetry_verify_keys.pub must not be a symlink".to_string());
        }
        if meta.file_type().is_file() {
            let text = fs::read_to_string(&cfg_path)
                .map_err(|e| format!("failed reading config/telemetry_verify_keys.pub: {e}"))?;
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let hex_candidate = trimmed
                    .split_whitespace()
                    .last()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if hex_candidate.len() == 64 && hex_candidate.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    keys.insert(hex_candidate);
                }
            }
        }
    }

    if let Ok(env_vk) = std::env::var("DOTAGENT_TELEMETRY_VERIFY_KEY") {
        for part in env_vk.split(',') {
            let clean = part.trim().to_ascii_lowercase();
            if clean.len() == 64 && clean.bytes().all(|b| b.is_ascii_hexdigit()) {
                keys.insert(clean);
            }
        }
    }

    // Local operator convenience when running `sync-github` + `run-loop` on the same fleet host
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        && let Ok(dir) = feedback_state_dir()
    {
        let local_pub = dir.join("vault/telemetry_ed25519.pub");
        if let Ok(meta) = fs::symlink_metadata(&local_pub)
            && !meta.file_type().is_symlink()
            && meta.file_type().is_file()
            && let Ok(raw) = fs::read_to_string(&local_pub)
        {
            let clean = raw.trim().to_ascii_lowercase();
            if clean.len() == 64 && clean.bytes().all(|b| b.is_ascii_hexdigit()) {
                keys.insert(clean);
            }
        }
    }

    Ok(keys)
}

/// Strictly typed Stage 1 -> Stage 2 -> Stage 3 airlock schema (`Proposal 3C`).
/// Zero free-form untrusted issue/ballot prose ever crosses into Stage 3 (`--implementer-cmd`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemediationAction {
    BlockConstitutional,
    DiagnosticHintOnly,
    AllowSafeFlag,
}

impl RemediationAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BlockConstitutional => "BLOCK_CONSTITUTIONAL",
            Self::DiagnosticHintOnly => "DIAGNOSTIC_HINT_ONLY",
            Self::AllowSafeFlag => "ALLOW_SAFE_FLAG",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "BLOCK_CONSTITUTIONAL" | "WONTFIX_CONSTITUTIONAL" | "REJECT" => {
                Some(Self::BlockConstitutional)
            }
            "DIAGNOSTIC_HINT_ONLY" | "APPROVE_DIAGNOSTIC_ONLY" => Some(Self::DiagnosticHintOnly),
            "ALLOW_SAFE_FLAG" | "APPROVE" | "APPROVE_RING2" => Some(Self::AllowSafeFlag),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ring2RemediationSpec {
    pub cluster_key: String,
    pub action: RemediationAction,
    pub target_file: String,
    pub binary_or_tool: String,
    pub allowed_flag_pattern: String,
    pub required_abuse_neighbors: Vec<String>,
}

fn is_strict_binary_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 48
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn is_strict_flag_pattern(s: &str) -> bool {
    if s == "NONE" {
        return true;
    }
    s.starts_with('-')
        && s.len() >= 2
        && s.len() <= 48
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'='))
}

fn is_strict_neighbor_vector_pattern(s: &str) -> bool {
    if s.is_empty() || s.len() > 80 {
        return false;
    }
    let words: Vec<&str> = s.split(' ').collect();
    if words.is_empty() || words.len() > 8 {
        return false;
    }
    words.iter().all(|w| {
        !w.is_empty()
            && w.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/' | b':' | b'=')
            })
    })
}

/// A neighbor vector must exercise the exact tool the spec relaxes: for `cmd_policy.rs` the first
/// word is the binary and some later word is flag- or path-like; for `mcp_policy.rs` the first
/// word is an `mcp__` tool name.
fn neighbor_targets_spec_tool(neighbor: &str, binary_or_tool: &str, is_mcp_target: bool) -> bool {
    let words: Vec<&str> = neighbor.split(' ').collect();
    let Some(first) = words.first() else {
        return false;
    };
    if is_mcp_target {
        // Neighbors must stay on the same MCP server: `mcp__<server>__<tool>`.
        let server = binary_or_tool
            .strip_prefix("mcp__")
            .and_then(|rest| rest.split("__").next())
            .unwrap_or(binary_or_tool);
        return !server.is_empty() && first.starts_with(&format!("mcp__{server}__"));
    }
    *first == binary_or_tool
        && words.len() >= 2
        && words[1..]
            .iter()
            .any(|w| w.starts_with('-') || w.contains('/') || w.contains('='))
}

impl Ring2RemediationSpec {
    pub fn validate_and_parse(
        v: &JsonValue,
        expected_cluster_key: &str,
        ring0_locked: bool,
    ) -> Result<Self, String> {
        let act_str = v
            .get("action")
            .or_else(|| v.get("verdict"))
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "Auditor JSON missing 'action'".to_string())?;
        let mut action = RemediationAction::parse(act_str)
            .ok_or_else(|| format!("invalid remediation action '{act_str}'"))?;
        if ring0_locked && action == RemediationAction::AllowSafeFlag {
            action = RemediationAction::DiagnosticHintOnly;
        }
        if action == RemediationAction::BlockConstitutional {
            return Ok(Self {
                cluster_key: expected_cluster_key.to_string(),
                action,
                target_file: "NONE".to_string(),
                binary_or_tool: "none".to_string(),
                allowed_flag_pattern: "NONE".to_string(),
                required_abuse_neighbors: Vec::new(),
            });
        }

        let target_file = v
            .get("target_file")
            .and_then(JsonValue::as_str)
            .unwrap_or("crates/agent-guard/src/cmd_policy.rs")
            .trim()
            .to_string();
        if !matches!(
            target_file.as_str(),
            "crates/agent-guard/src/cmd_policy.rs"
                | "crates/agent-guard/src/mcp_policy.rs"
                | "crates/agent-guard/src/diagnostics.rs"
        ) {
            return Err(format!(
                "Ring2RemediationSpec target_file '{target_file}' outside allowed Ring-2 source files"
            ));
        }
        if ring0_locked && target_file != "crates/agent-guard/src/diagnostics.rs" {
            return Err(
                "ring0_locked cluster may only target crates/agent-guard/src/diagnostics.rs"
                    .to_string(),
            );
        }

        let binary_or_tool = v
            .get("binary_or_tool")
            .and_then(JsonValue::as_str)
            .unwrap_or("guard")
            .trim()
            .to_ascii_lowercase();
        if !is_strict_binary_ident(&binary_or_tool) {
            return Err(format!(
                "Ring2RemediationSpec binary_or_tool '{binary_or_tool}' failed strict token check"
            ));
        }

        let allowed_flag_pattern = v
            .get("allowed_flag_pattern")
            .and_then(JsonValue::as_str)
            .unwrap_or("NONE")
            .trim()
            .to_string();
        if !is_strict_flag_pattern(&allowed_flag_pattern) {
            return Err(format!(
                "Ring2RemediationSpec allowed_flag_pattern '{allowed_flag_pattern}' failed strict flag check"
            ));
        }

        let mut neighbors = Vec::new();
        if let Some(arr) = v
            .get("required_abuse_neighbors")
            .and_then(JsonValue::as_array)
        {
            let is_mcp_target = target_file == "crates/agent-guard/src/mcp_policy.rs";
            for item in arr.iter().take(6) {
                let Some(s) = item.as_str() else {
                    return Err("required_abuse_neighbors items must be strings".to_string());
                };
                let trimmed = s.trim();
                if !is_strict_neighbor_vector_pattern(trimmed) {
                    return Err(format!(
                        "required_abuse_neighbors item '{trimmed}' failed token-only airlock regex"
                    ));
                }
                if !neighbor_targets_spec_tool(trimmed, &binary_or_tool, is_mcp_target) {
                    return Err(format!(
                        "required_abuse_neighbors item '{trimmed}' must invoke '{binary_or_tool}' with a flag- or path-like abuse argument"
                    ));
                }
                if !neighbors.iter().any(|n: &String| n == trimmed) {
                    neighbors.push(trimmed.to_string());
                }
            }
        }
        if action == RemediationAction::DiagnosticHintOnly {
            // Diagnostic-only remediations never touch policy, so abuse neighbors are meaningless.
            neighbors.clear();
        }
        if matches!(
            target_file.as_str(),
            "crates/agent-guard/src/cmd_policy.rs" | "crates/agent-guard/src/mcp_policy.rs"
        ) && neighbors.len() < 2
        {
            return Err(
                "Ring2RemediationSpec touching cmd_policy.rs/mcp_policy.rs must specify >= 2 required_abuse_neighbors"
                    .to_string(),
            );
        }

        Ok(Self {
            cluster_key: expected_cluster_key.to_string(),
            action,
            target_file,
            binary_or_tool,
            allowed_flag_pattern,
            required_abuse_neighbors: neighbors,
        })
    }

    pub fn to_json_value(&self) -> JsonValue {
        let neigh: Vec<JsonValue> = self
            .required_abuse_neighbors
            .iter()
            .map(|n| JsonValue::Str(n.clone()))
            .collect();
        JsonValue::Object(vec![
            (
                "schema".to_string(),
                JsonValue::Str("dotagent.ring2_spec.v2".to_string()),
            ),
            (
                "cluster_key".to_string(),
                JsonValue::Str(self.cluster_key.clone()),
            ),
            (
                "action".to_string(),
                JsonValue::Str(self.action.as_str().to_string()),
            ),
            (
                "target_file".to_string(),
                JsonValue::Str(self.target_file.clone()),
            ),
            (
                "binary_or_tool".to_string(),
                JsonValue::Str(self.binary_or_tool.clone()),
            ),
            (
                "allowed_flag_pattern".to_string(),
                JsonValue::Str(self.allowed_flag_pattern.clone()),
            ),
            (
                "required_abuse_neighbors".to_string(),
                JsonValue::Array(neigh),
            ),
        ])
    }
}

pub fn run_feedback_status_cli(args: &[String], cwd: &Path) -> ExitCode {
    if let Err(e) = verify_feedback_operator_or_ci_loop("dotagent feedback status") {
        eprintln!("[AGENT-GUARD HARD DENY] {e}");
        return ExitCode::from(2);
    }
    let json_mode = args.iter().any(|a| a == "--json");
    let repo_root = resolve_repo_root(cwd);
    let ballots = match load_verified_ballots(&repo_root) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[dotagent feedback status] HARD DENY: {e}");
            return ExitCode::from(2);
        }
    };
    let clusters = aggregate_verified_clusters(&ballots);
    if json_mode {
        let arr: Vec<JsonValue> = clusters.iter().map(cluster_to_json).collect();
        let out = JsonValue::Object(vec![
            (
                "total_ballots".to_string(),
                JsonValue::Uint(ballots.len() as u64),
            ),
            (
                "cluster_count".to_string(),
                JsonValue::Uint(clusters.len() as u64),
            ),
            ("clusters".to_string(), JsonValue::Array(arr)),
        ]);
        println!("{}", out.to_json_string());
    } else {
        println!(
            "[dotagent feedback] verified_ballots={} clusters={}",
            ballots.len(),
            clusters.len()
        );
        for c in &clusters {
            println!(
                "  - {} [{}] code={} target={} votes={} buckets={} raw={} max_agent_retries={} tainted={} ring0={}",
                c.cluster_key,
                c.category,
                c.deny_code.as_deref().unwrap_or("NONE"),
                c.target_bin_or_tool,
                c.unique_votes,
                c.distinct_repo_day_buckets,
                c.total_raw_submissions,
                c.max_single_agent_retries,
                c.tainted_attempts,
                c.ring0_locked
            );
        }
    }
    ExitCode::SUCCESS
}

fn cluster_to_json(c: &AggregatedFrictionCluster) -> JsonValue {
    let notes: Vec<JsonValue> = c
        .scrubbed_notes
        .iter()
        .map(|s| JsonValue::Str(s.clone()))
        .collect();
    JsonValue::Object(vec![
        (
            "cluster_key".to_string(),
            JsonValue::Str(c.cluster_key.clone()),
        ),
        ("category".to_string(), JsonValue::Str(c.category.clone())),
        (
            "deny_code".to_string(),
            c.deny_code
                .as_ref()
                .map_or(JsonValue::Null, |d| JsonValue::Str(d.clone())),
        ),
        (
            "target_bin_or_tool".to_string(),
            JsonValue::Str(c.target_bin_or_tool.clone()),
        ),
        (
            "canonical_shape".to_string(),
            JsonValue::Str(c.canonical_shape.clone()),
        ),
        ("ring0_locked".to_string(), JsonValue::Bool(c.ring0_locked)),
        (
            "unique_votes".to_string(),
            JsonValue::Uint(c.unique_votes as u64),
        ),
        (
            "distinct_repo_day_buckets".to_string(),
            JsonValue::Uint(c.distinct_repo_day_buckets as u64),
        ),
        (
            "total_raw_submissions".to_string(),
            JsonValue::Uint(c.total_raw_submissions as u64),
        ),
        (
            "max_single_agent_retries".to_string(),
            JsonValue::Uint(u64::from(c.max_single_agent_retries)),
        ),
        (
            "tainted_attempts".to_string(),
            JsonValue::Uint(c.tainted_attempts as u64),
        ),
        (
            "loop_anomaly_agents".to_string(),
            JsonValue::Uint(c.loop_anomaly_agents as u64),
        ),
        ("scrubbed_notes".to_string(), JsonValue::Array(notes)),
    ])
}

fn gh_cmd_with_token(gh: &Path, tok: Option<&ZeroizingToken>) -> Command {
    let mut cmd = Command::new(gh);
    cmd.env_clear().env("PATH", TRUSTED_EXEC_PATH);
    for safe_var in [
        "HOME",
        "USER",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "GIT_SSL_CAINFO",
        "SYSTEMROOT",
    ] {
        if let Ok(val) = std::env::var(safe_var) {
            cmd.env(safe_var, val);
        }
    }
    #[cfg(test)]
    for mock_var in ["MOCK_GH_STATE", "MOCK_BARE_ORIGIN"] {
        if let Ok(val) = std::env::var(mock_var) {
            cmd.env(mock_var, val);
        }
    }
    cmd.env("GH_HOST", "github.com")
        .env("GH_CONFIG_DIR", "/dev/null")
        .env("GH_PROMPT_DISABLED", "1")
        .env("NO_COLOR", "1");
    if let Some(t) = tok {
        cmd.env("GH_TOKEN", t.as_str());
    }
    cmd
}

fn load_synced_ballot_ids() -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let Ok(dir) = feedback_state_dir() else {
        return set;
    };
    let path = dir.join("synced_ballot_ids.txt");
    if let Ok(meta) = fs::symlink_metadata(&path)
        && !meta.file_type().is_symlink()
        && meta.file_type().is_file()
        && let Ok(raw) = fs::read_to_string(&path)
    {
        for line in raw.lines() {
            let t = line.trim();
            if !t.is_empty() {
                set.insert(t.to_string());
            }
        }
    }
    set
}

fn record_synced_ballot_ids(ids: &[String]) -> Result<(), String> {
    if ids.is_empty() {
        return Ok(());
    }
    let dir = feedback_state_dir()?;
    let path = dir.join("synced_ballot_ids.txt");
    let lock = dir.join("synced_ballot_ids.lock");
    let _g = ExclusiveFileLockGuard::acquire(&lock)?;
    if let Ok(meta) = fs::symlink_metadata(&path)
        && meta.file_type().is_symlink()
    {
        return Err("synced_ballot_ids.txt must not be a symlink".to_string());
    }
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&path)
        .map_err(|e| format!("failed opening synced_ballot_ids.txt: {e}"))?;
    for id in ids {
        writeln!(f, "{id}").map_err(|e| format!("failed writing synced_ballot_ids.txt: {e}"))?;
    }
    Ok(())
}

pub fn run_feedback_sync_github_cli(args: &[String], cwd: &Path) -> ExitCode {
    if let Err(e) = verify_feedback_operator_or_ci_loop("dotagent feedback sync-github") {
        eprintln!("[AGENT-GUARD HARD DENY] {e}");
        return ExitCode::from(2);
    }

    let mut target_repo = String::from("susanbdev/dotagent");
    let mut dry_run = false;
    let mut json_mode = false;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--repo" if i + 1 < args.len() => {
                target_repo = args[i + 1].clone();
                i += 2;
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            "--json" => {
                json_mode = true;
                i += 1;
            }
            "--min-votes" if i + 1 < args.len() => {
                // Accepted for CLI compatibility; quorum is enforced server-side during `run-loop`
                i += 2;
            }
            other => {
                eprintln!("[dotagent feedback sync-github] unrecognized argument '{other}'");
                return ExitCode::from(2);
            }
        }
    }

    if let Err(e) = validate_owner_repo(&target_repo) {
        eprintln!("[dotagent feedback sync-github] HARD DENY: {e}");
        return ExitCode::from(2);
    }

    let repo_root = resolve_repo_root(cwd);
    if let Err(e) = verify_checkout_matches_target_repo(&repo_root, &target_repo) {
        eprintln!("[dotagent feedback sync-github] HARD DENY: {e}");
        return ExitCode::from(2);
    }
    let all_ballots = match load_verified_ballots(&repo_root) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[dotagent feedback sync-github] HARD DENY: {e}");
            return ExitCode::from(2);
        }
    };
    let already_synced = load_synced_ballot_ids();
    let unsynced: Vec<_> = all_ballots
        .into_iter()
        .filter(|b| !already_synced.contains(&b.ballot_id))
        .collect();
    let clusters = aggregate_verified_clusters(&unsynced);

    let (signing_zk, pubkey_hex) = match load_or_init_telemetry_signing_key() {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("[dotagent feedback sync-github] signing key error: {e}");
            return ExitCode::from(2);
        }
    };
    let sk = SigningKey::from_bytes(signing_zk.as_bytes());
    let node_id = current_host_spool_id().unwrap_or_else(|_| "node_unknown".to_string());
    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut signed_batches = Vec::with_capacity(clusters.len());
    for c in &clusters {
        let mut batch = SignedSyncBatchV2 {
            schema: SYNC_BATCH_SCHEMA_V2.to_string(),
            node_id: node_id.clone(),
            cluster_key: c.cluster_key.clone(),
            category: c.category.clone(),
            deny_code: c.deny_code.clone(),
            target_bin_or_tool: c.target_bin_or_tool.clone(),
            canonical_shape: c.canonical_shape.clone(),
            voter_entries: c.voter_entries.clone(),
            raw_submissions: c.total_raw_submissions,
            tainted_attempts: c.tainted_attempts,
            loop_anomalies: c.loop_anomaly_agents,
            scrubbed_notes: c.scrubbed_notes.clone(),
            ts_unix: now_ts,
            pubkey_ed25519_hex: pubkey_hex.clone(),
            signature_ed25519_hex: String::new(),
        };
        let sig = sk.sign(&batch.canonical_signing_bytes(&target_repo));
        batch.signature_ed25519_hex = hex_encode(&sig.to_bytes());
        signed_batches.push((c, batch));
    }

    if dry_run {
        if json_mode {
            let arr: Vec<JsonValue> = signed_batches
                .iter()
                .map(|(_, b)| b.to_json_value())
                .collect();
            println!(
                "{}",
                JsonValue::Object(vec![
                    ("dry_run".to_string(), JsonValue::Bool(true)),
                    ("repo".to_string(), JsonValue::Str(target_repo)),
                    ("pubkey_ed25519_hex".to_string(), JsonValue::Str(pubkey_hex)),
                    ("signed_batches".to_string(), JsonValue::Array(arr)),
                ])
                .to_json_string()
            );
        } else {
            println!(
                "[dotagent feedback sync-github --dry-run] Prepared {} signed append-only batch comment(s) for {target_repo} (pubkey={})",
                signed_batches.len(),
                &pubkey_hex[..16]
            );
        }
        return ExitCode::SUCCESS;
    }

    let gh = resolve_gh_bin();
    if gh.as_os_str().is_empty() {
        eprintln!("[dotagent feedback sync-github] trusted GitHub CLI unavailable");
        return ExitCode::from(2);
    }
    let tok = ZeroizingToken::from_env_and_scrub();
    if let Err(e) = ensure_friction_labels(&gh, tok.as_ref(), &target_repo) {
        eprintln!("[dotagent feedback sync-github] label setup failed: {e}");
        return ExitCode::from(2);
    }

    let mut appended = 0usize;
    for (cluster, batch) in &signed_batches {
        let issue_num = match find_or_create_cluster_issue(&gh, tok.as_ref(), &target_repo, cluster)
        {
            Ok(Some(n)) => n,
            Ok(None) => {
                eprintln!(
                    "[dotagent feedback sync-github] cluster {} was closed wontfix-constitutional; not recreating",
                    cluster.cluster_key
                );
                continue;
            }
            Err(e) => {
                eprintln!("[dotagent feedback sync-github] issue lookup/create failed: {e}");
                return ExitCode::from(2);
            }
        };
        let comment_body = batch.format_as_github_comment();
        if let Err(e) =
            append_issue_comment(&gh, tok.as_ref(), &target_repo, issue_num, &comment_body)
        {
            eprintln!("[dotagent feedback sync-github] comment append failed on #{issue_num}: {e}");
            return ExitCode::from(2);
        }
        appended += 1;
        // Persist per cluster immediately after its comment lands so a later failure never
        // causes already-appended clusters to be re-posted (raw-submission double counting).
        let cluster_ids: Vec<String> = unsynced
            .iter()
            .filter(|b| b.cluster_key == cluster.cluster_key)
            .map(|b| b.ballot_id.clone())
            .collect();
        if let Err(e) = record_synced_ballot_ids(&cluster_ids) {
            eprintln!("[dotagent feedback sync-github] failed persisting synced ballot ids: {e}");
            return ExitCode::from(2);
        }
    }
    if json_mode {
        println!(
            "{}",
            JsonValue::Object(vec![
                ("ok".to_string(), JsonValue::Bool(true)),
                ("repo".to_string(), JsonValue::Str(target_repo)),
                (
                    "appended_signed_comments".to_string(),
                    JsonValue::Uint(appended as u64)
                ),
            ])
            .to_json_string()
        );
    } else {
        println!(
            "[dotagent feedback sync-github] Appended {appended} Ed25519-signed batch comment(s) to {target_repo}"
        );
    }
    ExitCode::SUCCESS
}

fn ensure_friction_labels(
    gh: &Path,
    tok: Option<&ZeroizingToken>,
    repo: &str,
) -> Result<(), String> {
    for &(name, color, desc) in crate::github_governance::GOVERNANCE_LABELS {
        let _ = gh_cmd_with_token(gh, tok)
            .args([
                "label",
                "create",
                name,
                "-R",
                repo,
                "--color",
                color,
                "--description",
                desc,
                "--force",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    Ok(())
}

fn find_or_create_cluster_issue(
    gh: &Path,
    tok: Option<&ZeroizingToken>,
    repo: &str,
    cluster: &AggregatedFrictionCluster,
) -> Result<Option<u64>, String> {
    let prefix_tag = format!("[Friction {}]", cluster.cluster_key);
    let out = gh_cmd_with_token(gh, tok)
        .args([
            "issue",
            "list",
            "-R",
            repo,
            "--state",
            "all",
            "--label",
            "dotagent-friction",
            "--limit",
            "500",
            "--json",
            "number,title,state,labels",
        ])
        .output()
        .map_err(|e| format!("gh issue list failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "gh issue list failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let val = JsonValue::parse(String::from_utf8_lossy(&out.stdout).trim())
        .map_err(|e| format!("invalid gh issue list JSON: {e}"))?;
    if let Some(arr) = val.as_array() {
        for item in arr {
            let title = item.get("title").and_then(JsonValue::as_str).unwrap_or("");
            if !title.starts_with(&prefix_tag) {
                continue;
            }
            let wontfix = item
                .get("labels")
                .and_then(JsonValue::as_array)
                .is_some_and(|ls| {
                    ls.iter().any(|l| {
                        l.get("name").and_then(JsonValue::as_str) == Some("wontfix-constitutional")
                    })
                });
            if wontfix {
                // Constitutional rejections are permanent: never reopen or recreate the cluster.
                return Ok(None);
            }
            let is_open = item
                .get("state")
                .and_then(JsonValue::as_str)
                .is_some_and(|st| st.eq_ignore_ascii_case("open"));
            if is_open && let Some(num) = item.get("number").and_then(JsonValue::as_u64) {
                return Ok(Some(num));
            }
        }
    }

    let title = format!(
        "{prefix_tag} {}: {} ({})",
        cluster.category,
        cluster.deny_code.as_deref().unwrap_or("NONE"),
        cluster.target_bin_or_tool
    );
    let initial_body = format!(
        "## Zero-Trust Agent Friction Queue (`{}`)\n\n\
         - **Cluster Key**: `{}`\n\
         - **Category**: `{}`\n\
         - **Kernel Deny Code**: `{}`\n\
         - **Target Binary / Tool**: `{}`\n\
         - **Ring-0 Constitutional Lock**: `{}`\n\n\
         > **Security Notice**: Issue body text is untrusted display metadata only. `dotagent feedback run-loop` \
         computes quorum exclusively from detached Ed25519-signed `dotagent:sync-sig:v2` batch comments below.\n",
        cluster.cluster_key,
        cluster.cluster_key,
        cluster.category,
        cluster.deny_code.as_deref().unwrap_or("NONE"),
        cluster.target_bin_or_tool,
        cluster.ring0_locked
    );

    let mut labels = vec!["dotagent-friction"];
    if cluster.ring0_locked {
        labels.push("ring0:constitutional-review");
    }
    if cluster.loop_anomaly_agents > 0 {
        labels.push("signal:agent-loop-anomaly");
    }
    if cluster.tainted_attempts > 0 {
        labels.push("signal:tainted-quarantine");
    }

    let mut cmd = gh_cmd_with_token(gh, tok);
    cmd.args([
        "issue",
        "create",
        "-R",
        repo,
        "--title",
        &title,
        "--body-file",
        "-",
    ]);
    for l in labels {
        cmd.args(["--label", l]);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("gh issue create spawn failed: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(initial_body.as_bytes())
            .map_err(|e| format!("gh issue create stdin write failed: {e}"))?;
    }
    let created = child
        .wait_with_output()
        .map_err(|e| format!("gh issue create wait failed: {e}"))?;
    if !created.status.success() {
        return Err(format!(
            "gh issue create failed: {}",
            String::from_utf8_lossy(&created.stderr).trim()
        ));
    }
    let url = String::from_utf8_lossy(&created.stdout);
    let num_str = url
        .trim()
        .rsplit('/')
        .next()
        .ok_or_else(|| "missing issue number in gh issue create output".to_string())?;
    num_str
        .parse::<u64>()
        .map(Some)
        .map_err(|_| format!("unable to parse issue number from '{}'", url.trim()))
}

fn append_issue_comment(
    gh: &Path,
    tok: Option<&ZeroizingToken>,
    repo: &str,
    issue_num: u64,
    body: &str,
) -> Result<(), String> {
    let mut child = gh_cmd_with_token(gh, tok)
        .args([
            "issue",
            "comment",
            &issue_num.to_string(),
            "-R",
            repo,
            "--body-file",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("gh issue comment spawn failed: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(body.as_bytes())
            .map_err(|e| format!("gh issue comment stdin write failed: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("gh issue comment wait failed: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct LoopRunnerConfig {
    pub target_repo: String,
    pub base_branch: String,
    pub min_votes: usize,
    pub min_buckets: usize,
    pub max_merges_per_run: usize,
    pub dry_run: bool,
    pub auditor_cmd: String,
    pub security_cmd: String,
    pub implementer_cmd: String,
    pub adversarial_cmd: String,
    pub ci_poll_secs: u64,
    pub ci_timeout_secs: u64,
}

fn default_stage_cmd(runner: &str, role_prompt: &str) -> String {
    match runner {
        "codex" => format!("codex exec --full-auto \"{role_prompt}\""),
        "gemini" => format!("gemini -p \"{role_prompt}\""),
        _ => format!("claude -p \"{role_prompt}\" --output-format text"),
    }
}

pub fn run_feedback_loop_cli(args: &[String], cwd: &Path) -> ExitCode {
    if let Err(e) = verify_feedback_operator_or_ci_loop("dotagent feedback run-loop") {
        eprintln!("[AGENT-GUARD HARD DENY] {e}");
        return ExitCode::from(2);
    }

    let mut target_repo = String::from("susanbdev/dotagent");
    let mut base_branch = String::from("main");
    let mut min_votes = 3usize;
    let mut min_buckets = 2usize;
    let mut max_merges_per_run = 1usize;
    let mut dry_run = false;
    let mut runner = String::from("claude");
    let mut auditor_cmd: Option<String> = std::env::var("DOTAGENT_AUDITOR_CMD").ok();
    let mut security_cmd: Option<String> = std::env::var("DOTAGENT_SECURITY_CMD").ok();
    let mut implementer_cmd: Option<String> = std::env::var("DOTAGENT_IMPLEMENTER_CMD").ok();
    let mut adversarial_cmd: Option<String> = std::env::var("DOTAGENT_ADVERSARIAL_CMD").ok();
    let mut ci_poll_secs = 15u64;
    let mut ci_timeout_secs = 1200u64;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--repo" if i + 1 < args.len() => {
                target_repo = args[i + 1].clone();
                i += 2;
            }
            "--base" if i + 1 < args.len() => {
                base_branch = args[i + 1].clone();
                i += 2;
            }
            "--min-votes" if i + 1 < args.len() => {
                min_votes = args[i + 1].parse::<usize>().unwrap_or(3).max(1);
                i += 2;
            }
            "--min-buckets" if i + 1 < args.len() => {
                min_buckets = args[i + 1].parse::<usize>().unwrap_or(2).max(1);
                i += 2;
            }
            "--max-merges-per-run" | "--max-items" if i + 1 < args.len() => {
                // Hard cap: at most one autonomous merge per run so every merge re-bases the
                // next attempt on a freshly gated main.
                let requested = args[i + 1].parse::<usize>().unwrap_or(1);
                if requested > 1 {
                    eprintln!(
                        "[dotagent feedback run-loop] --max-merges-per-run {requested} capped to 1"
                    );
                }
                max_merges_per_run = 1;
                i += 2;
            }
            "--runner" if i + 1 < args.len() => {
                runner = args[i + 1].clone();
                i += 2;
            }
            "--auditor-cmd" if i + 1 < args.len() => {
                auditor_cmd = Some(args[i + 1].clone());
                i += 2;
            }
            "--security-cmd" if i + 1 < args.len() => {
                security_cmd = Some(args[i + 1].clone());
                i += 2;
            }
            "--implementer-cmd" if i + 1 < args.len() => {
                implementer_cmd = Some(args[i + 1].clone());
                i += 2;
            }
            "--adversarial-cmd" if i + 1 < args.len() => {
                adversarial_cmd = Some(args[i + 1].clone());
                i += 2;
            }
            "--ci-poll-secs" if i + 1 < args.len() => {
                ci_poll_secs = args[i + 1].parse::<u64>().unwrap_or(15).max(1);
                i += 2;
            }
            "--ci-timeout-secs" if i + 1 < args.len() => {
                ci_timeout_secs = args[i + 1].parse::<u64>().unwrap_or(1200).max(5);
                i += 2;
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            other => {
                eprintln!("[dotagent feedback run-loop] unrecognized argument '{other}'");
                return ExitCode::from(2);
            }
        }
    }

    if let Err(e) = validate_owner_repo(&target_repo) {
        eprintln!("[dotagent feedback run-loop] HARD DENY: {e}");
        return ExitCode::from(2);
    }
    if let Err(e) = validate_git_ref_arg(&base_branch) {
        eprintln!("[dotagent feedback run-loop] HARD DENY: {e}");
        return ExitCode::from(2);
    }

    let cfg = LoopRunnerConfig {
        target_repo,
        base_branch,
        min_votes,
        min_buckets,
        max_merges_per_run,
        dry_run,
        auditor_cmd: auditor_cmd.unwrap_or_else(|| {
            default_stage_cmd(
                &runner,
                "Stage 1 Read-Only Auditor: Output ONLY strict Ring2RemediationSpec JSON {action, target_file, binary_or_tool, allowed_flag_pattern, required_abuse_neighbors}. Never copy untrusted prose.",
            )
        }),
        security_cmd: security_cmd.unwrap_or_else(|| {
            default_stage_cmd(
                &runner,
                "Stage 2 Hostile Security Gate: Verify Ring2RemediationSpec preserves AGENTS.md Pillars 1-5; output JSON {verdict: APPROVE | WONTFIX_CONSTITUTIONAL}.",
            )
        }),
        implementer_cmd: implementer_cmd.unwrap_or_else(|| {
            default_stage_cmd(
                &runner,
                "Stage 3 Ring-2 Implementer: Implement Ring2RemediationSpec on stdin touching ONLY the 5 Ring-2 allowlist files and appending >=2 target-matched Deny vectors to tests/bypass_corpus.toml.",
            )
        }),
        adversarial_cmd: adversarial_cmd.unwrap_or_else(|| {
            default_stage_cmd(
                &runner,
                "Stage 4 Hostile Adversarial Reviewer: Audit git diff against Ring2RemediationSpec; output JSON {medium_plus_defects: <uint>, findings: [...]}.",
            )
        }),
        ci_poll_secs,
        ci_timeout_secs,
    };

    let repo_root = resolve_repo_root(cwd);
    if let Err(e) = verify_checkout_matches_target_repo(&repo_root, &cfg.target_repo) {
        eprintln!("[dotagent feedback run-loop] HARD DENY: {e}");
        return ExitCode::from(2);
    }
    let gh_tok = ZeroizingToken::from_env_and_scrub();
    // Scrub GitHub credentials from current process env so NO child process can ever inherit them even accidentally!
    // (Parent passes `gh_tok` explicitly only to `gh_cmd_with_token`.)
    let _telemetry = crate::telemetry::runtime::start_host();
    match execute_autonomous_loop(&repo_root, &cfg, gh_tok.as_ref()) {
        Ok(merged) => {
            println!(
                "[dotagent feedback run-loop] Completed cleanly (merged_prs={merged}, dry_run={})",
                cfg.dry_run
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("[dotagent feedback run-loop] FAILED: {e}");
            ExitCode::from(2)
        }
    }
}

#[derive(Debug)]
struct RehydratedIssueItem {
    issue_number: u64,
    failed_attempts_on_main: usize,
    cluster: AggregatedFrictionCluster,
}

fn resolve_allowed_comment_authors(
    gh: &Path,
    tok: Option<&ZeroizingToken>,
    owner: &str,
) -> BTreeSet<String> {
    let mut allowed = BTreeSet::new();
    allowed.insert(owner.to_ascii_lowercase());
    // `[bot]` logins are additionally required to carry `user.type == "Bot"` at use sites.
    allowed.insert("dotagent-loop[bot]".to_string());
    allowed.insert("github-actions[bot]".to_string());
    if let Ok(out) = gh_cmd_with_token(gh, tok).args(["api", "user"]).output()
        && out.status.success()
        && let Ok(v) = JsonValue::parse(String::from_utf8_lossy(&out.stdout).trim())
        && let Some(login) = v.get("login").and_then(JsonValue::as_str)
    {
        allowed.insert(login.to_ascii_lowercase());
    }
    allowed
}

fn current_main_tree_hash(repo_root: &Path, base_branch: &str) -> String {
    for spec in [
        format!("origin/{base_branch}^{{tree}}"),
        format!("{base_branch}^{{tree}}"),
        "HEAD^{tree}".to_string(),
    ] {
        if let Ok(out) = hardened_git_cmd(repo_root)
            .args(["rev-parse", "--verify", "--end-of-options", &spec])
            .output()
            && out.status.success()
        {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return s;
            }
        }
    }
    "unknown_tree".to_string()
}

fn rehydrate_cryptographic_queue(
    gh: &Path,
    tok: Option<&ZeroizingToken>,
    repo_root: &Path,
    cfg: &LoopRunnerConfig,
    main_tree: &str,
) -> Result<Vec<RehydratedIssueItem>, String> {
    let (owner, repo_name) = validate_owner_repo(&cfg.target_repo)?;
    let trusted_pubkeys = load_trusted_telemetry_verify_pubkeys(repo_root)?;
    if trusted_pubkeys.is_empty() {
        eprintln!(
            "[dotagent feedback run-loop] WARNING: telemetry verify keyring is empty; no signed batches can reach quorum"
        );
    }
    let allowed_authors = resolve_allowed_comment_authors(gh, tok, &owner);

    let out = gh_cmd_with_token(gh, tok)
        .args([
            "issue",
            "list",
            "-R",
            &cfg.target_repo,
            "--state",
            "open",
            "--label",
            "dotagent-friction",
            "--limit",
            "200",
            "--json",
            "number,title,labels",
        ])
        .output()
        .map_err(|e| format!("gh issue list failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "gh issue list failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let list_val = JsonValue::parse(String::from_utf8_lossy(&out.stdout).trim())
        .map_err(|e| format!("invalid gh issue list JSON: {e}"))?;
    let mut items = Vec::new();
    let Some(arr) = list_val.as_array() else {
        return Ok(items);
    };

    let fail_marker = format!("{ATTEMPT_MARKER_PREFIX}main_tree={main_tree} status=failed");

    for iss in arr {
        let Some(num) = iss.get("number").and_then(JsonValue::as_u64) else {
            continue;
        };
        let mut skip_issue = false;
        if let Some(lbls) = iss.get("labels").and_then(JsonValue::as_array) {
            for l in lbls {
                let lname = l.get("name").and_then(JsonValue::as_str).unwrap_or("");
                if matches!(
                    lname,
                    "wontfix-constitutional" | "friction-escalated-human" | "automated-pr-open"
                ) {
                    skip_issue = true;
                }
            }
        }
        if skip_issue {
            continue;
        }

        let comments_ep = format!("repos/{owner}/{repo_name}/issues/{num}/comments");
        let c_out = gh_cmd_with_token(gh, tok)
            .args(["api", "--paginate", "--slurp", &comments_ep])
            .output()
            .map_err(|e| format!("gh api '{comments_ep}' failed: {e}"))?;
        if !c_out.status.success() {
            continue;
        }
        let Ok(pages_val) = JsonValue::parse(String::from_utf8_lossy(&c_out.stdout).trim()) else {
            continue;
        };

        let mut verified_batches: Vec<SignedSyncBatchV2> = Vec::new();
        let mut failed_attempts_on_main = 0usize;

        let mut flat_comments = Vec::new();
        if let Some(outer) = pages_val.as_array() {
            for entry in outer {
                if let Some(page) = entry.as_array() {
                    flat_comments.extend(page.iter());
                } else if entry.as_object().is_some() {
                    flat_comments.push(entry);
                }
            }
        }

        for c_obj in flat_comments {
            let author = c_obj
                .get("user")
                .and_then(|u| u.get("login"))
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            if !allowed_authors.contains(&author) {
                continue;
            }
            let author_type = c_obj
                .get("user")
                .and_then(|u| u.get("type"))
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            if author.ends_with("[bot]") != author_type.eq_ignore_ascii_case("Bot") {
                // Bot logins must be real GitHub Apps; human allowlisted logins must be Users.
                continue;
            }
            let body = c_obj.get("body").and_then(JsonValue::as_str).unwrap_or("");
            if body.contains(&fail_marker) {
                failed_attempts_on_main += 1;
            }
            if let Some(Ok(batch)) = SignedSyncBatchV2::parse_from_github_comment(body)
                && batch
                    .verify_signature(&trusted_pubkeys, &cfg.target_repo)
                    .is_ok()
            {
                verified_batches.push(batch);
            }
        }

        let Some(first) = verified_batches.first().cloned() else {
            continue;
        };
        let target_ck = first.cluster_key.clone();
        let mut seen_voters = BTreeSet::new();
        let mut seen_buckets = BTreeSet::new();
        let mut voter_entries = Vec::new();
        let mut raw_subs = 0usize;
        let mut tainted = 0usize;
        let mut loops = 0usize;
        let mut notes = Vec::new();
        let mut last_ts = 0u64;

        for b in verified_batches
            .into_iter()
            .filter(|b| b.cluster_key == target_ck)
        {
            raw_subs = raw_subs.saturating_add(b.raw_submissions);
            tainted = tainted.saturating_add(b.tainted_attempts);
            loops = loops.saturating_add(b.loop_anomalies);
            for (vt, bkt) in b.voter_entries {
                if seen_voters.insert(vt.clone()) {
                    seen_buckets.insert(bkt.clone());
                    voter_entries.push((vt, bkt));
                }
            }
            for n in b.scrubbed_notes {
                if notes.len() < 4 && !notes.contains(&n) {
                    notes.push(n);
                }
            }
            if b.ts_unix > last_ts {
                last_ts = b.ts_unix;
            }
        }

        let ring0_locked = first
            .deny_code
            .as_deref()
            .is_some_and(is_ring0_constitutional_code);
        items.push(RehydratedIssueItem {
            issue_number: num,
            failed_attempts_on_main,
            cluster: AggregatedFrictionCluster {
                cluster_key: target_ck,
                category: first.category.clone(),
                deny_code: first.deny_code.clone(),
                target_bin_or_tool: first.target_bin_or_tool.clone(),
                canonical_shape: first.canonical_shape.clone(),
                ring0_locked,
                unique_votes: seen_voters.len(),
                voter_entries,
                distinct_repo_day_buckets: seen_buckets.len(),
                total_raw_submissions: raw_subs,
                max_single_agent_retries: 0,
                tainted_attempts: tainted,
                loop_anomaly_agents: loops,
                scrubbed_notes: notes,
                last_ts_unix: last_ts,
            },
        });
    }

    items.sort_by(|a, b| {
        b.cluster
            .unique_votes
            .cmp(&a.cluster.unique_votes)
            .then_with(|| {
                b.cluster
                    .distinct_repo_day_buckets
                    .cmp(&a.cluster.distinct_repo_day_buckets)
            })
            .then_with(|| a.issue_number.cmp(&b.issue_number))
    });
    Ok(items)
}

fn generate_csprng_nonce_hex() -> String {
    let mut entropy = [0u8; 16];
    #[cfg(unix)]
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut entropy);
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut seed = Vec::with_capacity(32);
    seed.extend_from_slice(&entropy);
    seed.extend_from_slice(&nanos.to_le_bytes());
    sha256_hex(&seed)[..32].to_string()
}

/// Builds a `git` invocation with dangerous environment overrides stripped and hooks, attributes,
/// and fsmonitor disabled via `GIT_CONFIG_*` environment variables (never `git -c`).
fn hardened_git_cmd(cwd: &Path) -> Command {
    let mut cmd = Command::new(trusted_git_bin().unwrap_or_default());
    cmd.current_dir(cwd)
        .env_clear()
        .env("PATH", TRUSTED_EXEC_PATH);
    for key in [
        "HOME",
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
    ] {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_COUNT", "3")
        .env("GIT_CONFIG_KEY_0", "core.fsmonitor")
        .env("GIT_CONFIG_VALUE_0", "false")
        .env("GIT_CONFIG_KEY_1", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_1", "/dev/null")
        .env("GIT_CONFIG_KEY_2", "core.attributesFile")
        .env("GIT_CONFIG_VALUE_2", "/dev/null");
    cmd
}

/// Spawns a subprocess inside a strict `Command::env_clear()` credential airlock (`Proposal 3C`).
/// LLM provider API keys are forwarded ONLY to stages that require network access (`include_llm_keys == true`);
/// offline `--deny-net` stages and Cargo verification steps never receive LLM keys or GitHub tokens.
fn build_airlocked_command(program: &Path, cwd: &Path, include_llm_keys: bool) -> Command {
    let mut cmd = Command::new(program);
    cmd.current_dir(cwd);
    cmd.env_clear();
    for safe_var in [
        "PATH",
        "HOME",
        "USER",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "NODE_EXTRA_CA_CERTS",
    ] {
        if let Ok(val) = std::env::var(safe_var) {
            cmd.env(safe_var, val);
        }
    }
    if include_llm_keys {
        for llm_key in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"] {
            if let Ok(val) = std::env::var(llm_key) {
                cmd.env(llm_key, val);
            }
        }
    }
    cmd.env("LANG", "C");
    cmd.env("LC_ALL", "C");
    cmd.env("GIT_CONFIG_NOSYSTEM", "1");
    cmd.env("GH_CONFIG_DIR", "/dev/null");
    cmd
}

fn resolve_sibling_agent_guard_bin() -> Result<PathBuf, String> {
    #[cfg(test)]
    if let Some(path) = std::env::var_os("DOTAGENT_FEEDBACK_TEST_GUARD") {
        return Ok(PathBuf::from(path));
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("agent-guard")))
        .filter(|p| {
            fs::symlink_metadata(p)
                .is_ok_and(|m| m.file_type().is_file() && !m.file_type().is_symlink())
                && crate::coordinator::is_trusted_executable_file(p)
        })
        .ok_or_else(|| {
            "STAGE_SANDBOX_UNAVAILABLE: trusted non-symlink sibling agent-guard binary not found; refusing unsandboxed execution"
                .to_string()
        })
}

/// Runs a worktree verification step (`cargo test`, `clippy`, `dotagent-harness`, or custom verify)
/// inside `agent-guard exec-sandbox --deny-net` with zero LLM keys and `CARGO_NET_OFFLINE=true`.
fn run_verify_shell(shell_cmd: &str, work_dir: &Path) -> Result<String, String> {
    let gbin = resolve_sibling_agent_guard_bin()?;
    let mut cmd = build_airlocked_command(&gbin, work_dir, false);
    cmd.env("CARGO_NET_OFFLINE", "true");
    cmd.arg("exec-sandbox")
        .arg("--deny-net")
        .arg("--cwd")
        .arg(work_dir)
        .args(["--", shell_cmd]);
    let out = cmd
        .output()
        .map_err(|e| format!("failed spawning verification sandbox: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "verification command exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn run_stage_shell(
    shell_cmd: &str,
    work_dir: &Path,
    stdin_payload: &str,
    read_only_deny_net: bool,
) -> Result<String, String> {
    let pre_status = if read_only_deny_net {
        hardened_git_cmd(work_dir)
            .args(["status", "--porcelain=v1", "-z", "-uall"])
            .output()
            .ok()
            .map(|o| o.stdout)
    } else {
        None
    };

    // Every stage (including the Stage 3 implementer) runs inside `agent-guard exec-sandbox`;
    // there is no unsandboxed `bash -c` fallback. Read-only stages add `--read-only` and
    // `--deny-net` (the latter may be relaxed for hosted-LLM CLIs via
    // `DOTAGENT_LOOP_STAGE_ALLOW_NET=1`, which still keeps `--read-only`).
    let gbin = resolve_sibling_agent_guard_bin()?;
    let allow_net = std::env::var("DOTAGENT_LOOP_STAGE_ALLOW_NET").as_deref() == Ok("1");
    let include_llm_keys = !read_only_deny_net || allow_net;
    let mut cmd = build_airlocked_command(&gbin, work_dir, include_llm_keys);
    cmd.arg("exec-sandbox");
    if read_only_deny_net {
        cmd.arg("--read-only");
        if !allow_net {
            cmd.arg("--deny-net");
        }
    }
    cmd.arg("--cwd").arg(work_dir).args(["--", shell_cmd]);

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed spawning stage command: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(stdin_payload.as_bytes());
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("failed waiting on stage command: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "stage command exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    if let Some(before) = pre_status
        && let Ok(after_out) = hardened_git_cmd(work_dir)
            .args(["status", "--porcelain=v1", "-z", "-uall"])
            .output()
        && after_out.stdout != before
    {
        return Err(
            "READONLY_STAGE_MUTATION_DETECTED: read-only stage modified working tree".to_string(),
        );
    }

    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn extract_json_object_from_text(raw: &str) -> Result<JsonValue, String> {
    if let Ok(v) = JsonValue::parse(raw.trim()) {
        return Ok(v);
    }
    let start = raw
        .find('{')
        .ok_or_else(|| format!("stage output contained no JSON object: '{raw}'"))?;
    let end = raw
        .rfind('}')
        .ok_or_else(|| format!("stage output contained unclosed JSON object: '{raw}'"))?;
    if end < start {
        return Err("malformed JSON braces in stage output".to_string());
    }
    JsonValue::parse(&raw[start..=end]).map_err(|e| format!("stage JSON parse error: {e}"))
}

fn execute_autonomous_loop(
    repo_root: &Path,
    cfg: &LoopRunnerConfig,
    tok: Option<&ZeroizingToken>,
) -> Result<usize, String> {
    let gh = resolve_gh_bin();
    if gh.as_os_str().is_empty() {
        return Err("trusted GitHub CLI unavailable".to_string());
    }
    if !cfg.dry_run {
        let _ = ensure_friction_labels(&gh, tok, &cfg.target_repo);
    }
    let main_tree = current_main_tree_hash(repo_root, &cfg.base_branch);
    let queue = rehydrate_cryptographic_queue(&gh, tok, repo_root, cfg, &main_tree)?;

    let mut merged_count = 0usize;
    for item in queue {
        if merged_count >= cfg.max_merges_per_run {
            break;
        }

        let meets_quorum = item.cluster.unique_votes >= cfg.min_votes
            && item.cluster.distinct_repo_day_buckets >= cfg.min_buckets;
        if !meets_quorum {
            continue;
        }

        // 2-Strike Circuit Breaker per `(cluster_key, main_tree_hash)` (`Proposal 4C`)
        if item.failed_attempts_on_main >= 2 {
            if !cfg.dry_run {
                let _ = gh_cmd_with_token(&gh, tok)
                    .args([
                        "issue",
                        "edit",
                        &item.issue_number.to_string(),
                        "-R",
                        &cfg.target_repo,
                        "--add-label",
                        "friction-escalated-human",
                    ])
                    .status();
            }
            continue;
        }

        if cfg.dry_run {
            println!(
                "[run-loop --dry-run] Eligible issue #{}: {} (votes={}, buckets={}, ring0_locked={})",
                item.issue_number,
                item.cluster.cluster_key,
                item.cluster.unique_votes,
                item.cluster.distinct_repo_day_buckets,
                item.cluster.ring0_locked
            );
            continue;
        }

        match process_single_issue_six_stages(&gh, tok, repo_root, cfg, &item, &main_tree) {
            Ok(true) => {
                merged_count += 1;
            }
            Ok(false) => {}
            Err(stage_err) => {
                eprintln!(
                    "[run-loop] issue #{} ({}) attempt failed: {stage_err}",
                    item.issue_number, item.cluster.cluster_key
                );
                let marker = format!(
                    "{ATTEMPT_MARKER_PREFIX}main_tree={main_tree} status=failed -->\n\
                     Autonomous loop attempt `{}` on `main` tree `{}` halted safely: `{}`",
                    item.failed_attempts_on_main + 1,
                    &main_tree[..main_tree.len().min(12)],
                    clean_single_line_ascii(&stage_err, 180)
                );
                let _ =
                    append_issue_comment(&gh, tok, &cfg.target_repo, item.issue_number, &marker);
                if item.failed_attempts_on_main + 1 >= 2 {
                    let _ = gh_cmd_with_token(&gh, tok)
                        .args([
                            "issue",
                            "edit",
                            &item.issue_number.to_string(),
                            "-R",
                            &cfg.target_repo,
                            "--add-label",
                            "friction-escalated-human",
                        ])
                        .status();
                }
            }
        }
    }

    Ok(merged_count)
}

fn process_single_issue_six_stages(
    gh: &Path,
    tok: Option<&ZeroizingToken>,
    repo_root: &Path,
    cfg: &LoopRunnerConfig,
    item: &RehydratedIssueItem,
    _main_tree: &str,
) -> Result<bool, String> {
    let cluster = &item.cluster;
    if !is_valid_cluster_key(&cluster.cluster_key) {
        return Err("invalid cluster_key format".to_string());
    }

    // --- STAGE 1: Read-Only Auditor (`--deny-net`) -> Emits Typed `Ring2RemediationSpec` ---
    // Raw `scrubbed_notes` are visible ONLY here inside a 128-bit CSPRNG spotlight envelope and
    // are permanently discarded before Stages 2, 3, and 4 (`Proposal 3C`).
    let stage1_nonce = generate_csprng_nonce_hex();
    let stage1_input = wrap_spotlight_envelope(
        &cluster_to_json(cluster).to_json_string(),
        &stage1_nonce,
        "friction_cluster_stage1_only",
    );
    let auditor_raw = run_stage_shell(&cfg.auditor_cmd, repo_root, &stage1_input, true)?;
    let auditor_json = extract_json_object_from_text(&auditor_raw)?;
    let spec = Ring2RemediationSpec::validate_and_parse(
        &auditor_json,
        &cluster.cluster_key,
        cluster.ring0_locked,
    )?;

    if spec.action == RemediationAction::BlockConstitutional {
        mark_issue_wontfix_and_close(
            gh,
            tok,
            &cfg.target_repo,
            item.issue_number,
            "Auditor classified cluster as constitutional block",
        )?;
        return Ok(false);
    }

    // --- STAGE 2: Hostile Security Gate (`--deny-net`, Typed Spec Only -- Zero Raw Prose) ---
    let spec_json_str = spec.to_json_value().to_json_string();
    let sec_raw = run_stage_shell(&cfg.security_cmd, repo_root, &spec_json_str, true)?;
    let sec_json = extract_json_object_from_text(&sec_raw)?;
    let sec_verdict = sec_json
        .get("verdict")
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .trim();
    if sec_verdict.eq_ignore_ascii_case("WONTFIX_CONSTITUTIONAL")
        || sec_verdict.eq_ignore_ascii_case("REJECT")
    {
        mark_issue_wontfix_and_close(
            gh,
            tok,
            &cfg.target_repo,
            item.issue_number,
            "Hostile Security Gate rejected Ring2RemediationSpec under AGENTS.md Pillars 1-5",
        )?;
        return Ok(false);
    }
    if !sec_verdict.eq_ignore_ascii_case("APPROVE") {
        return Err(format!(
            "STAGE2_INVALID_VERDICT: hostile security gate returned '{sec_verdict}' (expected exact 'APPROVE' or 'WONTFIX_CONSTITUTIONAL')"
        ));
    }

    // --- STAGE 3: Credential-Cleared Isolated Git Worktree Implementation ---
    let branch_name = format!("auto/friction-{}", cluster.cluster_key);
    if has_existing_open_pr_for_branch(gh, tok, &cfg.target_repo, &branch_name)? {
        return Ok(false);
    }

    let wt_parent = repo_root.join("target").join("friction-worktrees");
    fs::create_dir_all(&wt_parent).map_err(|e| format!("failed creating worktree parent: {e}"))?;
    let canon_wt_parent = fs::canonicalize(&wt_parent)
        .map_err(|e| format!("failed canonicalizing worktree parent: {e}"))?;
    let wt_dir = canon_wt_parent.join(&cluster.cluster_key);
    verify_safe_worktree_child(&canon_wt_parent, &wt_dir)?;
    cleanup_worktree(repo_root, &canon_wt_parent, &wt_dir);

    let base_ref = resolve_local_or_origin_base(repo_root, &cfg.base_branch);
    let wt_add = hardened_git_cmd(repo_root)
        .args(["worktree", "add", "-B", &branch_name])
        .arg(&wt_dir)
        .arg(&base_ref)
        .output()
        .map_err(|e| format!("git worktree add failed: {e}"))?;
    if !wt_add.status.success() {
        return Err(format!(
            "git worktree add failed: {}",
            String::from_utf8_lossy(&wt_add.stderr).trim()
        ));
    }

    let outcome = run_worktree_adversarial_copilot_and_merge(
        gh,
        tok,
        repo_root,
        &wt_dir,
        &base_ref,
        &branch_name,
        cfg,
        item.issue_number,
        &spec,
    );
    cleanup_worktree(repo_root, &canon_wt_parent, &wt_dir);
    outcome
}

fn verify_safe_worktree_child(canon_parent: &Path, wt_dir: &Path) -> Result<(), String> {
    let rel = wt_dir
        .strip_prefix(canon_parent)
        .map_err(|_| "worktree path escaped parent".to_string())?;
    let comps: Vec<_> = rel.components().collect();
    if comps.len() != 1 || !matches!(comps[0], Component::Normal(_)) {
        return Err("worktree path must be a single normal child component".to_string());
    }
    Ok(())
}

fn has_existing_open_pr_for_branch(
    gh: &Path,
    tok: Option<&ZeroizingToken>,
    repo: &str,
    branch_name: &str,
) -> Result<bool, String> {
    let out = gh_cmd_with_token(gh, tok)
        .args([
            "pr",
            "list",
            "-R",
            repo,
            "--head",
            branch_name,
            "--state",
            "open",
            "--json",
            "number",
        ])
        .output()
        .map_err(|e| format!("gh pr list failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "gh pr list --head '{branch_name}' failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let val = JsonValue::parse(String::from_utf8_lossy(&out.stdout).trim())
        .map_err(|e| format!("invalid JSON from gh pr list: {e}"))?;
    let arr = val
        .as_array()
        .ok_or_else(|| "gh pr list did not return a JSON array".to_string())?;
    Ok(!arr.is_empty())
}

#[allow(clippy::too_many_arguments)]
fn run_worktree_adversarial_copilot_and_merge(
    gh: &Path,
    tok: Option<&ZeroizingToken>,
    _repo_root: &Path,
    wt_dir: &Path,
    base_ref: &str,
    branch_name: &str,
    cfg: &LoopRunnerConfig,
    issue_number: u64,
    spec: &Ring2RemediationSpec,
) -> Result<bool, String> {
    let mut impl_input = spec.to_json_value().to_json_string();

    // --- STAGE 3 & STAGE 4: Implementation + Ratchet-First Verification + Adversarial Loop (<= 3 rounds) ---
    let mut adv_clean = false;
    for round in 1..=3 {
        let _ = run_stage_shell(&cfg.implementer_cmd, wt_dir, &impl_input, false)?;
        run_worktree_verification(wt_dir, base_ref)?;

        let diff_str = collect_staged_diff_against_base(wt_dir, base_ref)?;
        if diff_str.trim().is_empty() {
            return Err("implementer produced an empty diff".to_string());
        }

        let adv_payload = JsonValue::Object(vec![
            ("round".to_string(), JsonValue::Uint(round)),
            ("spec".to_string(), spec.to_json_value()),
            ("diff".to_string(), JsonValue::Str(diff_str)),
        ])
        .to_json_string();
        let adv_raw = run_stage_shell(&cfg.adversarial_cmd, wt_dir, &adv_payload, true)?;
        let adv_json = extract_json_object_from_text(&adv_raw)?;
        let med_plus = adv_json
            .get("medium_plus_defects")
            .and_then(JsonValue::as_u64)
            .unwrap_or(1);
        if med_plus == 0 {
            adv_clean = true;
            break;
        }
        let adv_nonce = generate_csprng_nonce_hex();
        let findings_wrapped =
            wrap_spotlight_envelope(&adv_json.to_json_string(), &adv_nonce, "adversarial_round");
        impl_input = JsonValue::Object(vec![
            ("spec".to_string(), spec.to_json_value()),
            (
                "adversarial_remediation".to_string(),
                JsonValue::Str(findings_wrapped),
            ),
        ])
        .to_json_string();
    }
    if !adv_clean {
        return Err("Adversarial review still reported Medium+ defects after 3 rounds".to_string());
    }

    commit_and_push_worktree(
        wt_dir,
        &cfg.target_repo,
        branch_name,
        &format!(
            "fix(guard): resolve friction {} ({})",
            spec.cluster_key, spec.binary_or_tool
        ),
        tok,
    )?;

    // Stage 5 verifies required CI checks and Copilot review on the pull request.
    let pr_title = format!(
        "fix(guard): resolve friction {} ({})",
        spec.cluster_key, spec.binary_or_tool
    );
    let pr_body = format!(
        "Closes #{issue_number}\n\n\
         ## Autonomous Constitutional Ring-2 Improvement (`{}`)\n\
         - **Target File**: `{}`\n\
         - **Binary / Tool**: `{}`\n\
         - **Action**: `{}`\n\
         - **Gates Verified Locally**: Strict 5-file Ring-2 allowlist ratchet, `dotagent-compiler verify`, `clippy -D warnings`, `cargo test`, `dotagent-harness --suite all`, and Adversarial Review (`0` Medium+).\n",
        spec.cluster_key,
        spec.target_file,
        spec.binary_or_tool,
        spec.action.as_str()
    );

    let mut pr_create = gh_cmd_with_token(gh, tok)
        .current_dir(wt_dir)
        .args([
            "pr",
            "create",
            "-R",
            &cfg.target_repo,
            "--base",
            &cfg.base_branch,
            "--head",
            branch_name,
            "--title",
            &pr_title,
            "--label",
            "automated-friction-fix",
            "--body-file",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("gh pr create spawn failed: {e}"))?;
    if let Some(mut stdin) = pr_create.stdin.take() {
        let _ = stdin.write_all(pr_body.as_bytes());
    }
    let pr_out = pr_create
        .wait_with_output()
        .map_err(|e| format!("gh pr create wait failed: {e}"))?;
    if !pr_out.status.success() {
        return Err(format!(
            "gh pr create failed: {}",
            String::from_utf8_lossy(&pr_out.stderr).trim()
        ));
    }
    let pr_url = String::from_utf8_lossy(&pr_out.stdout).trim().to_string();
    let pr_number: u64 = pr_url
        .rsplit('/')
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| format!("unable to parse PR number from '{pr_url}'"))?;

    let _ = gh_cmd_with_token(gh, tok)
        .args([
            "issue",
            "edit",
            &issue_number.to_string(),
            "-R",
            &cfg.target_repo,
            "--add-label",
            "automated-pr-open",
        ])
        .status();

    request_copilot_reviewer(gh, tok, &cfg.target_repo, pr_number);

    let mut copilot_round = 0usize;
    loop {
        let mut status = wait_for_pr_ci_and_copilot(
            gh,
            tok,
            &cfg.target_repo,
            pr_number,
            cfg.ci_poll_secs,
            cfg.ci_timeout_secs,
        )?;
        let local_head_sha = local_git_head_sha(wt_dir)?;
        if status.head_sha != local_head_sha {
            return Err(format!(
                "PR_HEAD_MISMATCH: remote PR head '{}' differs from verified worktree HEAD '{local_head_sha}'",
                status.head_sha
            ));
        }

        if !status.ci_all_green {
            return Err(format!(
                "PR #{pr_number} required status checks failed on commit {}",
                status.head_sha
            ));
        }

        // Fail closed immediately if any non-Copilot human left an unresolved review thread!
        if status.has_human_unresolved_thread {
            return Err(format!(
                "PR #{pr_number} has unresolved human review thread(s); refusing autonomous resolution or merge"
            ));
        }

        // Post-Fresh-Review Stale Thread Resolution (`Proposal 4A`):
        // ONLY after a fresh `0`-inline-comment Copilot review has landed on the new `head_sha`
        // may stale Copilot threads from *prior* commits (`commit_oid != head_sha`) be resolved!
        if status.copilot_zero_inline_on_head && !status.unresolved_threads.is_empty() {
            let all_stale = status
                .unresolved_threads
                .iter()
                .all(|t| t.commit_oid != status.head_sha);
            if all_stale {
                for stale in &status.unresolved_threads {
                    resolve_copilot_thread(gh, tok, &stale.thread_id)?;
                }
                status.unresolved_threads.clear();
            }
        }

        if status.copilot_zero_inline_on_head && status.unresolved_threads.is_empty() {
            // Stage 6 rechecks the ratchet and all gates before merging the verified head.
            verify_ring0_ratchet(wt_dir, base_ref, true)?;
            wait_for_required_checks_green(
                gh,
                tok,
                &cfg.target_repo,
                pr_number,
                &status.head_sha,
                cfg.ci_poll_secs,
                cfg.ci_timeout_secs,
            )?;
            let merge_out = gh_cmd_with_token(gh, tok)
                .args([
                    "pr",
                    "merge",
                    &pr_number.to_string(),
                    "-R",
                    &cfg.target_repo,
                    "--squash",
                    "--delete-branch",
                    "--match-head-commit",
                    &status.head_sha,
                ])
                .output()
                .map_err(|e| format!("gh pr merge failed: {e}"))?;
            if !merge_out.status.success() {
                return Err(format!(
                    "gh pr merge #{pr_number} failed: {}",
                    String::from_utf8_lossy(&merge_out.stderr).trim()
                ));
            }

            if spec.cluster_key.len() <= MAX_AGENTPI_EXPORT_INPUT_BYTES
                && status.head_sha.len() <= MAX_AGENTPI_EXPORT_INPUT_BYTES
            {
                let _ = submit_record(Kind::Merge, || {
                    JsonValue::Object(vec![
                        (
                            "schema".to_string(),
                            JsonValue::Str(AGENTPI_EVENT_SCHEMA.to_string()),
                        ),
                        (
                            "event_type".to_string(),
                            JsonValue::Str("loop_merge".to_string()),
                        ),
                        ("severity".to_string(), JsonValue::Str("INFO".to_string())),
                        ("cluster_key".to_string(), JsonValue::Str(spec.cluster_key.clone())),
                        ("issue_number".to_string(), JsonValue::Uint(issue_number)),
                        ("pr_number".to_string(), JsonValue::Uint(pr_number)),
                        ("head_sha".to_string(), JsonValue::Str(status.head_sha)),
                    ])
                });
            } else {
                note_invalid_export();
            }
            return Ok(true);
        }

        copilot_round += 1;
        if copilot_round > 2 {
            return Err(format!(
                "PR #{pr_number} still had Copilot inline review findings after 2 remediation rounds"
            ));
        }

        let copilot_nonce = generate_csprng_nonce_hex();
        let threads_json: Vec<JsonValue> = status
            .unresolved_threads
            .iter()
            .map(|t| {
                JsonValue::Object(vec![
                    ("path".to_string(), JsonValue::Str(t.path.clone())),
                    (
                        "body".to_string(),
                        JsonValue::Str(wrap_spotlight_envelope(
                            &t.body,
                            &copilot_nonce,
                            "copilot_review_thread",
                        )),
                    ),
                ])
            })
            .collect();
        let fix_prompt = JsonValue::Object(vec![
            ("spec".to_string(), spec.to_json_value()),
            (
                "copilot_threads".to_string(),
                JsonValue::Array(threads_json),
            ),
        ])
        .to_json_string();

        let _ = run_stage_shell(&cfg.implementer_cmd, wt_dir, &fix_prompt, false)?;
        run_worktree_verification(wt_dir, base_ref)?;
        let diff_str = collect_staged_diff_against_base(wt_dir, base_ref)?;
        let adv_check = JsonValue::Object(vec![
            ("round".to_string(), JsonValue::Uint(copilot_round as u64)),
            ("spec".to_string(), spec.to_json_value()),
            ("diff".to_string(), JsonValue::Str(diff_str)),
        ])
        .to_json_string();
        let adv_raw = run_stage_shell(&cfg.adversarial_cmd, wt_dir, &adv_check, true)?;
        let adv_json = extract_json_object_from_text(&adv_raw)?;
        if adv_json
            .get("medium_plus_defects")
            .and_then(JsonValue::as_u64)
            .unwrap_or(1)
            != 0
        {
            return Err("Copilot remediation round failed adversarial check".to_string());
        }

        commit_and_push_worktree(
            wt_dir,
            &cfg.target_repo,
            branch_name,
            &format!(
                "fix(guard): address Copilot review on {} (round {copilot_round})",
                spec.cluster_key
            ),
            tok,
        )?;
        request_copilot_reviewer(gh, tok, &cfg.target_repo, pr_number);
    }
}

fn collect_staged_diff_against_base(wt_dir: &Path, base_ref: &str) -> Result<String, String> {
    let add = hardened_git_cmd(wt_dir)
        .args(["add", "-A"])
        .output()
        .map_err(|e| format!("git add -A in worktree failed: {e}"))?;
    if !add.status.success() {
        return Err("git add -A failed in worktree before adversarial diff".to_string());
    }
    let diff_out = hardened_git_cmd(wt_dir)
        .args([
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--end-of-options",
            base_ref,
        ])
        .output()
        .map_err(|e| format!("git diff --cached in worktree failed: {e}"))?;
    if !diff_out.status.success() {
        return Err(format!(
            "git diff --cached failed: {}",
            String::from_utf8_lossy(&diff_out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&diff_out.stdout).into_owned())
}

fn local_git_head_sha(wt_dir: &Path) -> Result<String, String> {
    let out = hardened_git_cmd(wt_dir)
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .map_err(|e| format!("git rev-parse HEAD failed: {e}"))?;
    if !out.status.success() {
        return Err("git rev-parse HEAD failed in worktree".to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Cargo config keys that can redirect compilation to attacker-chosen programs.
const CARGO_CONFIG_TRAP_KEYS: &[&str] = &[
    "rustc-wrapper",
    "rustc-workspace-wrapper",
    "rustc",
    "linker",
    "runner",
    "rustflags",
    "rustdocflags",
    "target-dir",
    "[alias]",
    "[env]",
    "credential-provider",
];

fn cargo_config_has_trap(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    CARGO_CONFIG_TRAP_KEYS.iter().copied().find(|k| {
        lower.lines().any(|l| {
            let t = l.trim_start();
            if k.starts_with('[') {
                t.starts_with(k)
            } else {
                t.strip_prefix(k)
                    .is_some_and(|rest| rest.trim_start().starts_with('='))
                    || t.contains(&format!(".{k}"))
            }
        })
    })
}

fn audit_cargo_config_hierarchy(wt_dir: &Path) -> Result<(), String> {
    // 1. The worktree itself may never carry Cargo configs or toolchain pins.
    for rel in [
        ".cargo/config",
        ".cargo/config.toml",
        "rust-toolchain",
        "rust-toolchain.toml",
    ] {
        if fs::symlink_metadata(wt_dir.join(rel)).is_ok() {
            return Err(format!(
                "PREBUILD_TRAP_BLOCKED: '{rel}' present in worktree"
            ));
        }
    }
    // 2. Ancestor directories and CARGO_HOME are walked by Cargo config discovery.
    if let Some(home) = crate::cmd_policy::cargo_home_for_directory(wt_dir) {
        crate::cmd_policy::inspect_cargo_config_dir(&home)
            .map_err(|error| format!("PREBUILD_TRAP_BLOCKED: {}", error.detail))?;
    }
    for d in wt_dir.ancestors().skip(1) {
        let base = d.join(".cargo");
        for name in ["config", "config.toml"] {
            let p = base.join(name);
            let Ok(meta) = fs::symlink_metadata(&p) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "PREBUILD_TRAP_BLOCKED: symlinked cargo config '{}'",
                    p.display()
                ));
            }
            let text = fs::read_to_string(&p).map_err(|e| {
                format!(
                    "PREBUILD_TRAP_BLOCKED: unreadable cargo config '{}': {e}",
                    p.display()
                )
            })?;
            if let Some(k) = cargo_config_has_trap(&text) {
                return Err(format!(
                    "PREBUILD_TRAP_BLOCKED: cargo config '{}' sets '{k}'",
                    p.display()
                ));
            }
        }
    }
    Ok(())
}

fn audit_worktree_prebuild_traps(wt_dir: &Path) -> Result<(), String> {
    audit_cargo_config_hierarchy(wt_dir)?;
    for rel in [
        ".cargo/config",
        ".cargo/config.toml",
        "rust-toolchain",
        "rust-toolchain.toml",
        ".gitattributes",
        "build.rs",
    ] {
        let p = wt_dir.join(rel);
        if let Ok(meta) = fs::symlink_metadata(&p)
            && meta.file_type().is_symlink()
        {
            return Err(format!("PREBUILD_TRAP_BLOCKED: symlink at '{rel}'"));
        }
    }
    Ok(())
}

fn run_worktree_verification(wt_dir: &Path, base_ref: &str) -> Result<(), String> {
    // 1. Audit pre-build traps + enforce strict 5-file Ring-2 allowlist ratchet BEFORE running Cargo!
    audit_worktree_prebuild_traps(wt_dir)?;
    verify_ring0_ratchet(wt_dir, base_ref, true)?;

    #[cfg(test)]
    if let Ok(custom_verify) = std::env::var("DOTAGENT_LOOP_VERIFY_CMD")
        && !custom_verify.trim().is_empty()
    {
        let _ = run_verify_shell(custom_verify.trim(), wt_dir)?;
        audit_worktree_prebuild_traps(wt_dir)?;
        verify_ring0_ratchet(wt_dir, base_ref, true)?;
        return Ok(());
    }

    let steps: &[(&str, &str)] = &[
        (
            "dotagent-compiler verify",
            "cargo run -q --locked -p dotagent-compiler -- verify .",
        ),
        ("cargo fmt --check", "cargo fmt --all -- --check"),
        (
            "cargo clippy",
            "cargo clippy --workspace --all-targets --locked -- -D warnings",
        ),
        ("cargo test", "cargo test --workspace --locked"),
        (
            "dotagent-harness --suite all",
            "cargo run -q --locked -p dotagent-harness -- --suite all",
        ),
    ];

    for (label, shell_cmd) in steps {
        run_verify_shell(shell_cmd, wt_dir)
            .map_err(|e| format!("worktree verification step '{label}' failed: {e}"))?;
    }
    audit_worktree_prebuild_traps(wt_dir)?;
    verify_ring0_ratchet(wt_dir, base_ref, true)?;
    Ok(())
}

/// Rejects local/worktree `.git/config` keys that could hijack `git push`, exfiltrate the
/// extraheader token, or execute arbitrary helper binaries if a sandboxed stage tampered with
/// `.git/config`.
fn audit_worktree_git_config_before_push(wt_dir: &Path) -> Result<(), String> {
    let worktree_config = hardened_git_cmd(wt_dir)
        .args([
            "config",
            "--no-includes",
            "--local",
            "--type=bool",
            "--get",
            "extensions.worktreeConfig",
        ])
        .output()
        .map_err(|e| format!("could not determine Git worktree config scope: {e}"))?;
    let worktree_config_enabled = match (
        worktree_config.status.code(),
        worktree_config.stdout.as_slice(),
    ) {
        (Some(0), b"true\n") => true,
        (Some(0), b"false\n") => false,
        (Some(1), b"") if worktree_config.stderr.is_empty() => false,
        _ => return Err("could not determine Git worktree config scope".to_string()),
    };
    for scope_flag in ["--local", "--worktree"] {
        if scope_flag == "--worktree" && !worktree_config_enabled {
            continue;
        }
        let out = hardened_git_cmd(wt_dir)
            .args([
                "config",
                "--no-includes",
                "--null",
                "--name-only",
                "--list",
                scope_flag,
            ])
            .output()
            .map_err(|e| format!("could not audit Git config ({scope_flag}): {e}"))?;
        if !out.status.success() {
            return Err(format!("could not audit Git config ({scope_flag})"));
        }
        let text = std::str::from_utf8(&out.stdout)
            .map_err(|_| format!("invalid Git config names ({scope_flag})"))?;
        for raw_key in text.split_terminator('\0') {
            let key = raw_key.to_ascii_lowercase();
            let forbidden = key.starts_with("http.")
                || key.starts_with("url.")
                || key.starts_with("credential.")
                || key.starts_with("include.")
                || key.starts_with("includeif.")
                || key.starts_with("protocol.")
                || key.starts_with("alias.")
                || key.starts_with("filter.")
                || key.starts_with("diff.")
                || matches!(
                    key.as_str(),
                    "core.sshcommand"
                        | "core.hookspath"
                        | "core.fsmonitor"
                        | "core.gitproxy"
                        | "core.askpass"
                        | "core.pager"
                        | "core.editor"
                        | "core.attributesfile"
                )
                || (key.starts_with("remote.") && key.ends_with(".pushurl"))
                || (key.starts_with("remote.") && key.ends_with(".proxy"));
            if forbidden {
                return Err(format!(
                    "GIT_CONFIG_TRAP_DETECTED: forbidden git config key '{key}' in worktree ({scope_flag})"
                ));
            }
        }
    }
    Ok(())
}

fn resolve_push_target(target_repo: &str) -> Result<String, String> {
    let (owner, repo) = validate_owner_repo(target_repo)?;
    #[cfg(test)]
    if let Ok(v) = std::env::var("MOCK_BARE_ORIGIN") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            let p = Path::new(trimmed);
            let is_local_dir = p.is_absolute()
                && !trimmed.contains("://")
                && !trimmed.contains('@')
                && fs::symlink_metadata(p)
                    .is_ok_and(|m| m.file_type().is_dir() && !m.file_type().is_symlink());
            if !is_local_dir {
                return Err(
                    "MOCK_BARE_ORIGIN must be an absolute non-symlink local directory".to_string(),
                );
            }
            return Ok(trimmed.to_string());
        }
    }
    Ok(format!("https://github.com/{owner}/{repo}.git"))
}

fn commit_and_push_worktree(
    wt_dir: &Path,
    target_repo: &str,
    branch_name: &str,
    msg: &str,
    tok: Option<&ZeroizingToken>,
) -> Result<(), String> {
    audit_worktree_git_config_before_push(wt_dir)?;
    let add = hardened_git_cmd(wt_dir)
        .args(["add", "-A"])
        .output()
        .map_err(|e| format!("git add failed: {e}"))?;
    if !add.status.success() {
        return Err("git add -A failed in worktree".to_string());
    }
    let status = hardened_git_cmd(wt_dir)
        .args(["status", "--porcelain"])
        .output()
        .map_err(|e| format!("git status failed: {e}"))?;
    if !String::from_utf8_lossy(&status.stdout).trim().is_empty() {
        let commit = hardened_git_cmd(wt_dir)
            .args(["commit", "-m", msg])
            .output()
            .map_err(|e| format!("git commit failed: {e}"))?;
        if !commit.status.success() {
            return Err(format!(
                "git commit failed: {}",
                String::from_utf8_lossy(&commit.stderr).trim()
            ));
        }
    }
    audit_worktree_git_config_before_push(wt_dir)?;
    let push_target = resolve_push_target(target_repo)?;
    let refspec = format!("HEAD:refs/heads/{branch_name}");
    // `git push` runs in a cleared environment against an explicit destination URL (never trusting
    // a mutable `remote.origin.url`): hooks/fsmonitor/credential helpers are disabled and the token
    // is supplied only as a scoped `http.https://github.com/.extraheader` via GIT_CONFIG_* env.
    let git = trusted_git_bin().ok_or_else(|| "trusted Git executable unavailable".to_string())?;
    let mut push_cmd = Command::new(git);
    push_cmd
        .current_dir(wt_dir)
        .env_clear()
        .env("PATH", TRUSTED_EXEC_PATH);
    for safe_var in [
        "HOME",
        "USER",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "GIT_SSL_CAINFO",
    ] {
        if let Ok(val) = std::env::var(safe_var) {
            push_cmd.env(safe_var, val);
        }
    }
    push_cmd
        .env("GIT_ALLOW_PROTOCOL", "https")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_KEY_0", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_0", "/dev/null")
        .env("GIT_CONFIG_KEY_1", "core.fsmonitor")
        .env("GIT_CONFIG_VALUE_1", "false")
        .env("GIT_CONFIG_KEY_2", "credential.helper")
        .env("GIT_CONFIG_VALUE_2", "");
    #[cfg(test)]
    if Path::new(&push_target).is_absolute() {
        push_cmd.env("GIT_ALLOW_PROTOCOL", "file");
    }
    if let Some(t) = tok {
        let basic = base64_std_encode(format!("x-access-token:{}", t.as_str()).as_bytes());
        push_cmd
            .env("GIT_CONFIG_COUNT", "4")
            .env("GIT_CONFIG_KEY_3", "http.https://github.com/.extraheader")
            .env(
                "GIT_CONFIG_VALUE_3",
                format!("AUTHORIZATION: basic {basic}"),
            );
    } else {
        push_cmd.env("GIT_CONFIG_COUNT", "3");
    }
    let push = push_cmd
        .args(["push", "--end-of-options", &push_target, &refspec])
        .output()
        .map_err(|e| format!("git push failed: {e}"))?;
    if !push.status.success() {
        return Err(format!(
            "git push '{branch_name}' failed: {}",
            String::from_utf8_lossy(&push.stderr).trim()
        ));
    }
    Ok(())
}

fn base64_std_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(char::from(ALPHABET[((n >> 18) & 63) as usize]));
        out.push(char::from(ALPHABET[((n >> 12) & 63) as usize]));
        if chunk.len() > 1 {
            out.push(char::from(ALPHABET[((n >> 6) & 63) as usize]));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(char::from(ALPHABET[(n & 63) as usize]));
        } else {
            out.push('=');
        }
    }
    out
}

fn request_copilot_reviewer(gh: &Path, tok: Option<&ZeroizingToken>, repo: &str, pr_number: u64) {
    let endpoint = format!("repos/{repo}/pulls/{pr_number}/requested_reviewers");
    let _ = gh_cmd_with_token(gh, tok)
        .args([
            "api",
            "-X",
            "POST",
            &endpoint,
            "-f",
            "reviewers[]=copilot-pull-request-reviewer[bot]",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[derive(Debug, Clone)]
struct UnresolvedReviewThread {
    thread_id: String,
    commit_oid: String,
    path: String,
    body: String,
}

#[derive(Debug)]
struct PrGateStatus {
    head_sha: String,
    ci_all_green: bool,
    copilot_zero_inline_on_head: bool,
    has_human_unresolved_thread: bool,
    unresolved_threads: Vec<UnresolvedReviewThread>,
}

fn wait_for_pr_ci_and_copilot(
    gh: &Path,
    tok: Option<&ZeroizingToken>,
    repo: &str,
    pr_number: u64,
    poll_secs: u64,
    timeout_secs: u64,
) -> Result<PrGateStatus, String> {
    let started = Instant::now();
    let is_dotagent_repo = repo.ends_with("/dotagent");
    loop {
        let view = gh_cmd_with_token(gh, tok)
            .args([
                "pr",
                "view",
                &pr_number.to_string(),
                "-R",
                repo,
                "--json",
                "headRefOid,statusCheckRollup",
            ])
            .output()
            .map_err(|e| format!("gh pr view failed: {e}"))?;
        if !view.status.success() {
            return Err(format!(
                "gh pr view #{pr_number} failed: {}",
                String::from_utf8_lossy(&view.stderr).trim()
            ));
        }
        let pr_json = JsonValue::parse(String::from_utf8_lossy(&view.stdout).trim())
            .map_err(|e| format!("invalid gh pr view JSON: {e}"))?;
        let head_sha = pr_json
            .get("headRefOid")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string();

        // The Ring-0 & Copilot status can remain pending until stale review threads are resolved.
        // This phase checks CI and the exact-head Copilot review.
        let (ci_done, ci_green) =
            evaluate_status_rollup(pr_json.get("statusCheckRollup"), is_dotagent_repo, false);
        let (copilot_reviewed_head, copilot_zero_inline) =
            check_copilot_structural_review_on_head(gh, tok, repo, pr_number, &head_sha)?;

        if ci_done && (!ci_green || copilot_reviewed_head) {
            let (unresolved_threads, has_human) =
                fetch_unresolved_threads(gh, tok, repo, pr_number)?;
            return Ok(PrGateStatus {
                head_sha,
                ci_all_green: ci_green,
                copilot_zero_inline_on_head: copilot_zero_inline,
                has_human_unresolved_thread: has_human,
                unresolved_threads,
            });
        }

        if started.elapsed() >= Duration::from_secs(timeout_secs) {
            return Err(format!(
                "timed out after {timeout_secs}s waiting for required CI checks and Copilot review on PR #{pr_number}"
            ));
        }
        thread::sleep(Duration::from_secs(poll_secs));
    }
}

const COPILOT_GATE_STATUS_CONTEXT: &str = "Ring-0 & Copilot Gate";
const COPILOT_GATE_AUX_CHECK_RUN: &str = "Evaluate Ring-0 & Copilot Gate Status";

/// Polls until the required checks, including the `Ring-0 & Copilot Gate` commit status, are
/// green on `expected_head`. Any failure, head drift, or timeout fails closed.
fn wait_for_required_checks_green(
    gh: &Path,
    tok: Option<&ZeroizingToken>,
    repo: &str,
    pr_number: u64,
    expected_head: &str,
    poll_secs: u64,
    timeout_secs: u64,
) -> Result<(), String> {
    let started = Instant::now();
    let is_dotagent_repo = repo.ends_with("/dotagent");
    let gate = if is_dotagent_repo {
        format!(
            "{} required checks ({})",
            DOTAGENT_REQUIRED_CHECKS.len(),
            DOTAGENT_REQUIRED_CHECKS.join(", ")
        )
    } else {
        "required repository checks".to_string()
    };
    loop {
        let view = gh_cmd_with_token(gh, tok)
            .args([
                "pr",
                "view",
                &pr_number.to_string(),
                "-R",
                repo,
                "--json",
                "headRefOid,statusCheckRollup",
            ])
            .output()
            .map_err(|e| format!("gh pr view failed: {e}"))?;
        if !view.status.success() {
            return Err(format!(
                "gh pr view #{pr_number} failed: {}",
                String::from_utf8_lossy(&view.stderr).trim()
            ));
        }
        let pr_json = JsonValue::parse(String::from_utf8_lossy(&view.stdout).trim())
            .map_err(|e| format!("invalid gh pr view JSON: {e}"))?;
        let head_sha = pr_json
            .get("headRefOid")
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        if head_sha != expected_head {
            return Err(format!(
                "PR_HEAD_MISMATCH: PR #{pr_number} head moved to '{head_sha}' while awaiting {gate}"
            ));
        }
        let (done, green) =
            evaluate_status_rollup(pr_json.get("statusCheckRollup"), is_dotagent_repo, true);
        if done {
            if green {
                return Ok(());
            }
            return Err(format!(
                "PR #{pr_number} {gate} failed on commit {expected_head}"
            ));
        }
        if started.elapsed() >= Duration::from_secs(timeout_secs) {
            return Err(format!(
                "timed out after {timeout_secs}s waiting for {gate} on PR #{pr_number}"
            ));
        }
        thread::sleep(Duration::from_secs(poll_secs));
    }
}

fn evaluate_status_rollup(
    rollup_opt: Option<&JsonValue>,
    require_dotagent_checks: bool,
    include_copilot_gate: bool,
) -> (bool, bool) {
    let Some(arr) = rollup_opt.and_then(JsonValue::as_array) else {
        return (false, false);
    };
    if arr.is_empty() {
        return (false, false);
    }

    let mut latest_by_name: BTreeMap<String, (bool, bool)> = BTreeMap::new();
    for item in arr {
        let name = item
            .get("name")
            .or_else(|| item.get("context"))
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        if name == "Copilot" || name == COPILOT_GATE_AUX_CHECK_RUN {
            // Dynamic Copilot run and the auxiliary gate-evaluator check run are not gates; the
            // required gate is the `Ring-0 & Copilot Gate` commit status.
            continue;
        }
        if !include_copilot_gate && name == COPILOT_GATE_STATUS_CONTEXT {
            continue;
        }
        if let Some(status) = item.get("status").and_then(JsonValue::as_str) {
            // CheckRun
            if status != "COMPLETED" {
                return (false, false);
            }
            let conclusion = item
                .get("conclusion")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            let ok = conclusion == "SUCCESS";
            latest_by_name.insert(name.to_string(), (true, ok));
        } else if let Some(state) = item.get("state").and_then(JsonValue::as_str) {
            // StatusContext (`Ring-0 & Copilot Gate`)
            if matches!(state, "PENDING" | "EXPECTED") {
                return (false, false);
            }
            let ok = state == "SUCCESS";
            latest_by_name.insert(name.to_string(), (true, ok));
        }
    }

    if latest_by_name.values().any(|(_, ok)| !*ok) {
        return (true, false);
    }

    if require_dotagent_checks {
        for &req_name in DOTAGENT_REQUIRED_CHECKS {
            if !include_copilot_gate && req_name == COPILOT_GATE_STATUS_CONTEXT {
                continue;
            }
            match latest_by_name.get(req_name) {
                Some((true, true)) => {}
                Some((true, false)) => return (true, false),
                _ => return (false, false),
            }
        }
    } else if latest_by_name.is_empty() {
        return (false, false);
    }

    (true, true)
}

fn is_verified_copilot_bot(login: &str, user_type: &str) -> bool {
    let l = login.trim();
    l == "copilot-pull-request-reviewer[bot]"
        || (l == "copilot-pull-request-reviewer" && user_type.eq_ignore_ascii_case("Bot"))
}

/// Verifies via REST (`pulls/{pr}/reviews` + `pulls/{pr}/reviews/{id}/comments`) that
/// `copilot-pull-request-reviewer[bot]` reviewed `head_sha` with `0` inline review comments (`Proposal 4A`).
fn check_copilot_structural_review_on_head(
    gh: &Path,
    tok: Option<&ZeroizingToken>,
    repo: &str,
    pr_number: u64,
    head_sha: &str,
) -> Result<(bool, bool), String> {
    let endpoint = format!("repos/{repo}/pulls/{pr_number}/reviews");
    let out = gh_cmd_with_token(gh, tok)
        .args(["api", "--paginate", "--slurp", &endpoint])
        .output()
        .map_err(|e| format!("gh api reviews failed: {e}"))?;
    if !out.status.success() {
        return Ok((false, false));
    }
    let pages = JsonValue::parse(String::from_utf8_lossy(&out.stdout).trim())
        .unwrap_or(JsonValue::Array(Vec::new()));
    let mut flat = Vec::new();
    if let Some(outer) = pages.as_array() {
        for entry in outer {
            if let Some(arr) = entry.as_array() {
                flat.extend(arr.iter());
            } else if entry.as_object().is_some() {
                flat.push(entry);
            }
        }
    }

    let mut latest_review_id_on_head: Option<(u64, String)> = None;
    for rev in flat {
        let user_obj = rev.get("user");
        let login = user_obj
            .and_then(|u| u.get("login"))
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        let utype = user_obj
            .and_then(|u| u.get("type"))
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        let commit_id = rev
            .get("commit_id")
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        let state = rev.get("state").and_then(JsonValue::as_str).unwrap_or("");
        if is_verified_copilot_bot(login, utype)
            && commit_id == head_sha
            && let Some(rid) = rev.get("id").and_then(JsonValue::as_u64)
            && latest_review_id_on_head
                .as_ref()
                .is_none_or(|(prev_id, _)| rid >= *prev_id)
        {
            latest_review_id_on_head = Some((rid, state.to_string()));
        }
    }

    let Some((review_id, state)) = latest_review_id_on_head else {
        return Ok((false, false));
    };
    if state.eq_ignore_ascii_case("DISMISSED") {
        // A dismissed review invalidates prior approvals on this head SHA; wait for a fresh review.
        return Ok((false, false));
    }
    if state.eq_ignore_ascii_case("CHANGES_REQUESTED") {
        return Ok((true, false));
    }

    let comments_ep = format!("repos/{repo}/pulls/{pr_number}/reviews/{review_id}/comments");
    let c_out = gh_cmd_with_token(gh, tok)
        .args(["api", "--paginate", "--slurp", &comments_ep])
        .output()
        .map_err(|e| format!("gh api review comments failed: {e}"))?;
    if !c_out.status.success() {
        return Err("failed querying inline comments on Copilot review".to_string());
    }
    let c_pages = JsonValue::parse(String::from_utf8_lossy(&c_out.stdout).trim())
        .map_err(|e| format!("invalid Copilot review comments JSON: {e}"))?;
    let mut inline_count = 0usize;
    if let Some(outer) = c_pages.as_array() {
        for entry in outer {
            if let Some(arr) = entry.as_array() {
                inline_count += arr.len();
            } else if entry.as_object().is_some() {
                inline_count += 1;
            }
        }
    }
    Ok((true, inline_count == 0))
}

fn fetch_unresolved_threads(
    gh: &Path,
    tok: Option<&ZeroizingToken>,
    repo: &str,
    pr_number: u64,
) -> Result<(Vec<UnresolvedReviewThread>, bool), String> {
    let (owner, name) = validate_owner_repo(repo)?;
    let query = "query($owner: String!, $name: String!, $pr: Int!) { \
        repository(owner: $owner, name: $name) { \
          pullRequest(number: $pr) { \
            reviewThreads(first: 100) { \
              pageInfo { hasNextPage } \
              nodes { \
                id isResolved path \
                comments(first: 50) { \
                  pageInfo { hasNextPage } \
                  nodes { body author { __typename login } originalCommit { oid } } \
                } \
              } \
            } \
          } \
        } \
      }";
    let out = gh_cmd_with_token(gh, tok)
        .args([
            "api",
            "graphql",
            "-f",
            &format!("query={query}"),
            "--raw-field",
            &format!("owner={owner}"),
            "--raw-field",
            &format!("name={name}"),
            "-F",
            &format!("pr={pr_number}"),
        ])
        .output()
        .map_err(|e| format!("gh api graphql failed: {e}"))?;
    if !out.status.success() {
        return Err("failed querying PR reviewThreads via GraphQL".to_string());
    }
    let v = JsonValue::parse(String::from_utf8_lossy(&out.stdout).trim())
        .map_err(|e| format!("invalid GraphQL JSON: {e}"))?;
    if graphql_has_errors(&v) {
        return Err("GraphQL reviewThreads query returned errors; failing closed".to_string());
    }
    let Some(threads_obj) = v
        .get("data")
        .and_then(|d| d.get("repository"))
        .and_then(|r| r.get("pullRequest"))
        .and_then(|p| p.get("reviewThreads"))
    else {
        return Err("GraphQL response missing reviewThreads; failing closed".to_string());
    };
    if threads_obj
        .get("pageInfo")
        .and_then(|pi| pi.get("hasNextPage"))
        .and_then(JsonValue::as_bool)
        != Some(false)
    {
        return Err("PR has > 100 review threads (or unknown paging); failing closed".to_string());
    }
    let Some(nodes) = threads_obj.get("nodes").and_then(JsonValue::as_array) else {
        return Err("GraphQL reviewThreads.nodes missing; failing closed".to_string());
    };

    let mut threads = Vec::new();
    let mut has_human = false;
    for n in nodes {
        if n.get("isResolved").and_then(JsonValue::as_bool) == Some(true) {
            continue;
        }
        let tid = n.get("id").and_then(JsonValue::as_str).unwrap_or("");
        let path = n.get("path").and_then(JsonValue::as_str).unwrap_or("");
        let comments = n.get("comments");
        let more_comments = comments
            .and_then(|c| c.get("pageInfo"))
            .and_then(|pi| pi.get("hasNextPage"))
            .and_then(JsonValue::as_bool)
            != Some(false);
        let comment_nodes: &[JsonValue] = comments
            .and_then(|c| c.get("nodes"))
            .and_then(JsonValue::as_array)
            .unwrap_or(&[]);
        // A thread is Copilot-only iff every comment is authored by the Copilot Bot; any human
        // reply, unknown author, empty thread, or truncated comment page marks it as human.
        let all_copilot = !comment_nodes.is_empty()
            && comment_nodes.iter().all(|c| {
                let author = c.get("author");
                let login = author
                    .and_then(|a| a.get("login"))
                    .and_then(JsonValue::as_str)
                    .unwrap_or("");
                let typename = author
                    .and_then(|a| a.get("__typename"))
                    .and_then(JsonValue::as_str)
                    .unwrap_or("");
                typename == "Bot" && is_verified_copilot_bot(login, typename)
            });
        if more_comments || !all_copilot || tid.is_empty() {
            has_human = true;
        }
        let first_c = comment_nodes.first();
        let body = first_c
            .and_then(|c| c.get("body"))
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        let commit_oid = first_c
            .and_then(|c| c.get("originalCommit"))
            .and_then(|oc| oc.get("oid"))
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        if !tid.is_empty() {
            threads.push(UnresolvedReviewThread {
                thread_id: tid.to_string(),
                commit_oid: commit_oid.to_string(),
                path: path.to_string(),
                body: body.to_string(),
            });
        }
    }
    Ok((threads, has_human))
}

fn graphql_has_errors(v: &JsonValue) -> bool {
    match v.get("errors") {
        None | Some(JsonValue::Null) => false,
        Some(JsonValue::Array(a)) => !a.is_empty(),
        Some(_) => true,
    }
}

fn resolve_copilot_thread(
    gh: &Path,
    tok: Option<&ZeroizingToken>,
    thread_id: &str,
) -> Result<(), String> {
    if !thread_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'='))
    {
        return Err("invalid GraphQL thread_id".to_string());
    }
    let mutation = "mutation($tid: ID!) { resolveReviewThread(input: {threadId: $tid}) { thread { isResolved } } }";
    let out = gh_cmd_with_token(gh, tok)
        .args([
            "api",
            "graphql",
            "-f",
            &format!("query={mutation}"),
            "--raw-field",
            &format!("tid={thread_id}"),
        ])
        .output()
        .map_err(|e| format!("resolveReviewThread failed: {e}"))?;
    if !out.status.success() {
        return Err("GraphQL resolveReviewThread failed".to_string());
    }
    let v = JsonValue::parse(String::from_utf8_lossy(&out.stdout).trim())
        .map_err(|e| format!("invalid resolveReviewThread JSON: {e}"))?;
    let resolved = v
        .get("data")
        .and_then(|d| d.get("resolveReviewThread"))
        .and_then(|r| r.get("thread"))
        .and_then(|t| t.get("isResolved"))
        .and_then(JsonValue::as_bool);
    if graphql_has_errors(&v) || resolved != Some(true) {
        return Err(format!(
            "resolveReviewThread did not confirm isResolved=true for thread '{thread_id}'"
        ));
    }
    Ok(())
}

fn mark_issue_wontfix_and_close(
    gh: &Path,
    tok: Option<&ZeroizingToken>,
    repo: &str,
    issue_num: u64,
    rationale: &str,
) -> Result<(), String> {
    let clean_rat = clean_single_line_ascii(rationale, 200);
    let _ = gh_cmd_with_token(gh, tok)
        .args([
            "issue",
            "edit",
            &issue_num.to_string(),
            "-R",
            repo,
            "--add-label",
            "wontfix-constitutional",
        ])
        .status();
    let _ = gh_cmd_with_token(gh, tok)
        .args([
            "issue",
            "close",
            &issue_num.to_string(),
            "-R",
            repo,
            "--comment",
            &format!(
                "Closed automatically by `dotagent` Constitutional Gate (`wontfix-constitutional`): {clean_rat}"
            ),
        ])
        .status();
    Ok(())
}

fn resolve_local_or_origin_base(repo_root: &Path, base_branch: &str) -> String {
    let origin_candidate = format!("origin/{base_branch}");
    if let Ok(out) = hardened_git_cmd(repo_root)
        .args([
            "rev-parse",
            "--verify",
            "--end-of-options",
            &origin_candidate,
        ])
        .output()
        && out.status.success()
    {
        return origin_candidate;
    }
    base_branch.to_string()
}

fn cleanup_worktree(repo_root: &Path, canon_parent: &Path, wt_dir: &Path) {
    if verify_safe_worktree_child(canon_parent, wt_dir).is_err() {
        return;
    }
    let _ = hardened_git_cmd(repo_root)
        .args(["worktree", "remove", "--force"])
        .arg(wt_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if let Ok(meta) = fs::symlink_metadata(wt_dir)
        && !meta.file_type().is_symlink()
        && meta.file_type().is_dir()
    {
        let _ = fs::remove_dir_all(wt_dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_fixture_ballot_time(repo: &Path, timestamp: u64) {
        use crate::coordinator::compute_domain_tag_for_feedback;
        use crate::feedback::{
            FEEDBACK_BALLOT_HMAC_DOMAIN, load_or_init_global_feedback_key, utc_day_yyyymmdd,
        };

        let key = load_or_init_global_feedback_key().expect("fixture ballot key");
        let mut ballots = load_verified_ballots(repo).expect("signed fixture ballots");
        let latest = ballots.last_mut().expect("newly submitted fixture ballot");
        let (repo_prefix, _) = latest
            .repo_day_bucket
            .split_once(':')
            .expect("fixture ballot bucket");
        latest.repo_day_bucket = format!("{repo_prefix}:{}", utc_day_yyyymmdd(timestamp));
        latest.ts_unix = timestamp;
        latest.mac_hex = hex_encode(
            &compute_domain_tag_for_feedback(
                key.as_bytes(),
                FEEDBACK_BALLOT_HMAC_DOMAIN,
                &latest.canonical_mac_bytes(),
            )
            .expect("sign fixture ballot timeline"),
        );
        let mut spool = fs::File::create(
            feedback_state_dir()
                .expect("fixture feedback state")
                .join("ballots.jsonl"),
        )
        .expect("write fixture ballot spool");
        for ballot in ballots {
            writeln!(spool, "{}", ballot.to_json_value().to_json_string())
                .expect("write dated fixture ballot");
        }
    }

    #[test]
    #[ignore = "separate process entry point for the feedback integration fixture"]
    fn feedback_cli_fixture_driver() {
        let raw = std::env::var("DOTAGENT_FEEDBACK_TEST_CLI_ARGS").expect("fixture arguments");
        let json = JsonValue::parse(&raw).expect("valid fixture arguments");
        let args: Vec<_> = json
            .as_array()
            .expect("fixture argument array")
            .iter()
            .map(|arg| arg.as_str().expect("fixture argument string").to_string())
            .collect();
        let cwd = std::env::current_dir().expect("fixture checkout");
        let exit = match args.split_first() {
            Some((command, [timestamp])) if command == "set-fixture-ballot-time" => {
                set_fixture_ballot_time(&cwd, timestamp.parse().expect("fixture UNIX timestamp"));
                ExitCode::SUCCESS
            }
            Some((command, args)) if command == "sync-github" => {
                run_feedback_sync_github_cli(args, &cwd)
            }
            Some((command, args)) if command == "run-loop" => run_feedback_loop_cli(args, &cwd),
            _ => panic!("unknown fixture command"),
        };
        assert_eq!(exit, ExitCode::SUCCESS);
    }

    #[test]
    fn github_origin_identity_requires_a_supported_github_authority() {
        for url in [
            "https://github.com/Owner/Repo.git",
            "ssh://git@github.com/Owner/Repo",
            "git@github.com:Owner/Repo.git",
        ] {
            assert_eq!(
                github_origin_identity(url),
                Some(("owner".into(), "repo".into()))
            );
        }
        for url in [
            "http://github.com/Owner/Repo",
            "https://example.com/Owner/Repo",
            "https://github.com/Owner/Repo/issues",
            "/work/Repo",
        ] {
            assert_eq!(github_origin_identity(url), None);
        }
    }

    #[test]
    fn abuse_neighbors_must_target_the_relaxed_tool() {
        assert!(neighbor_targets_spec_tool("git push --force", "git", false));
        assert!(neighbor_targets_spec_tool("git -c core.x=y", "git", false));
        assert!(!neighbor_targets_spec_tool("rm -rf /", "git", false));
        assert!(!neighbor_targets_spec_tool("git status", "git", false));
        assert!(!neighbor_targets_spec_tool("git", "git", false));
        assert!(neighbor_targets_spec_tool(
            "mcp__github__delete_repository",
            "mcp__github__list_repos",
            true
        ));
        assert!(!neighbor_targets_spec_tool(
            "mcp__slack__post",
            "mcp__github__list_repos",
            true
        ));
        assert!(neighbor_targets_spec_tool("mcp__github__x", "github", true));
    }

    #[test]
    fn verifies_signed_sync_batch_and_rejects_prose_smuggling_in_ring2_spec() {
        let seed = [0x42u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pub_hex = hex_encode(sk.verifying_key().as_bytes());
        let ck = compute_cluster_key(
            "missing_safe_flag",
            Some("GIT_UNSAFE_ARG"),
            "git log --stat",
        );

        let mut batch = SignedSyncBatchV2 {
            schema: SYNC_BATCH_SCHEMA_V2.to_string(),
            node_id: "node_01".to_string(),
            cluster_key: ck.clone(),
            category: "missing_safe_flag".to_string(),
            deny_code: Some("GIT_UNSAFE_ARG".to_string()),
            target_bin_or_tool: "git".to_string(),
            canonical_shape: "git log --stat".to_string(),
            voter_entries: vec![(
                "0123456789abcdef01234567".to_string(),
                "abc:20261121".to_string(),
            )],
            raw_submissions: 1,
            tainted_attempts: 0,
            loop_anomalies: 0,
            scrubbed_notes: vec!["need --stat".to_string()],
            ts_unix: 1_795_000_000,
            pubkey_ed25519_hex: pub_hex.clone(),
            signature_ed25519_hex: String::new(),
        };
        let sig = sk.sign(&batch.canonical_signing_bytes("susanbdev/dotagent"));
        batch.signature_ed25519_hex = hex_encode(&sig.to_bytes());

        let comment = batch.format_as_github_comment();
        let parsed = SignedSyncBatchV2::parse_from_github_comment(&comment)
            .expect("comment marker")
            .expect("valid batch");
        let mut trusted = BTreeSet::new();
        trusted.insert(pub_hex);
        assert!(
            parsed
                .verify_signature(&trusted, "susanbdev/dotagent")
                .is_ok()
        );
        assert!(
            parsed
                .verify_signature(&trusted, "attacker/dotagent")
                .is_err(),
            "signed batch must not verify when replayed into a different repository queue"
        );

        // Tampered vote count fails Ed25519 signature check!
        let mut forged = parsed.clone();
        forged.voter_entries.push((
            "fedcba9876543210fedcba98".to_string(),
            "def:20261122".to_string(),
        ));
        assert!(
            forged
                .verify_signature(&trusted, "susanbdev/dotagent")
                .is_err()
        );

        // Prose injection inside Ring2RemediationSpec fails strict token validation!
        let bad_spec = JsonValue::parse(
            r#"{"action":"ALLOW_SAFE_FLAG","target_file":"crates/agent-guard/src/cmd_policy.rs","binary_or_tool":"git","allowed_flag_pattern":"--stat; curl evil","required_abuse_neighbors":["git --exec-path=/tmp","git -c core.sshCommand=evil"]}"#,
        )
        .expect("json");
        assert!(Ring2RemediationSpec::validate_and_parse(&bad_spec, &ck, false).is_err());
    }
}
