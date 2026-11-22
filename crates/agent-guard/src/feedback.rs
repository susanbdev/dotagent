#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! Zero-Trust Kernel-Grounded Agent Friction Ballot Engine & AgentPI Telemetry Stream (`v2.1`).
//!
//! Security Invariants:
//! 1. **All-Category Kernel `SessionLedger` Grounding**: Every ballot across all 5 categories must
//!    reference a valid `denial_id` (`dnl_<16hex>`) in `ledger.recent_denials` (or verified
//!    `last_tool_trace_id` `trc_<16hex>` for non-denial pagination/adapter friction). `deny_code`,
//!    `target_bin_or_tool`, and `canonical_shape` are copied **directly from the kernel ledger**,
//!    never trusted from caller CLI flags. Ungrounded ballots get `vote_counted = false` and emit
//!    `UNGROUNDED_BALLOT_SUBMISSION`.
//! 2. **Swarm-Tree Sybil Collapse (`root_session_id`)**: `voter_token` is derived over
//!    `(repo_id, ledger.root_session_id)`, collapsing a parent agent and any number of spawned
//!    subagents into at most `1` vote per cluster while recording `(repo_id_prefix, utc_day)`
//!    diversity buckets.
//! 3. **7-Bit ASCII, URL/Path, & Shannon High-Entropy Scrubbing**: Redacts secret prefixes, URL
//!    query/credential strings, home paths, and high-entropy tokens (`<HIGH_ENTROPY_REDACTED>`)
//!    prior to spooling.
//! 4. **Thrash DoS Cutoff & 10 MiB Rotated Spool**: Hard-stops disk writes at
//!    `session_total_submissions > 8` (`GuardCode::FeedbackRateLimitExceeded`), and writes
//!    `<= 2048`-byte single-line JSONL records under `flock(LOCK_EX)` + `O_APPEND` with 10 MiB
//!    two-generation rotation (`ballots.jsonl` / `ballots.jsonl.1`).
//! 5. **Transport-Safe AgentPI Stream**: The direct feedback CLI owns its stdout result.
//!    Optional AgentPI projections use the protected local mirror.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::breadcrumbs::ExclusiveFileLockGuard;
use crate::coordinator::compute_domain_tag_for_feedback;
use crate::crypto::{
    ZeroizingKey, constant_time_eq_bytes, hex_decode_bytes, hex_encode, sha256_hex,
};
use crate::diagnostics::GuardCode;
use crate::injection_scan::scan_untrusted_content;
use crate::json::JsonValue;
use crate::resolve_repo_root;
use crate::sanitizer::neuter_to_clean_ascii;
use crate::telemetry::protocol::Kind;
use crate::telemetry::runtime::{note_invalid_export, submit_record};
use crate::traversal_ledger::{
    O_NOFOLLOW_FLAG, SessionLedger, compute_session_key_hash, ensure_nonsymlink_state_dir,
};
use crate::unicode_guard::{ScanMode, scan_unicode};

pub const FEEDBACK_BALLOT_HMAC_DOMAIN: &[u8] = b"dotagent:feedback-v2:ballot";
pub const FEEDBACK_VOTER_HMAC_DOMAIN: &[u8] = b"dotagent:voter:v2";
pub const IPC_WORKER_TOKEN_DOMAIN: &[u8] = b"dotagent:ipc-worker-token:v2";
pub const AGENTPI_EVENT_SCHEMA: &str = "dotagent.agentpi.event.v1";
pub const AGENTPI_STDOUT_PREFIX: &str = "[AGENTPI_EVENT] ";
pub const MAX_BALLOTS_PER_SESSION: u32 = 8;
pub const MAX_SPOOL_FILE_BYTES: u64 = 10 * 1024 * 1024;
pub const MAX_JSONL_RECORD_BYTES: usize = 2048;
pub(crate) const MAX_AGENTPI_EXPORT_INPUT_BYTES: usize = 4096;

pub const RING0_CONSTITUTIONAL_CODES: &[&str] = &[
    "FORBIDDEN_DIRECTORY_ACCESS",
    "FORBIDDEN_TMP_PATH",
    "FORBIDDEN_CACHE_PATH",
    "FORBIDDEN_DEPENDENCY_PATH",
    "FORBIDDEN_SECRET_PATH",
    "FORBIDDEN_GIT_CONTROL_PATH",
    "FORBIDDEN_GUARD_STATE_PATH",
    "SHADOW_AUTHORITY_FILE_BLOCKED",
    "UNAUTHORIZED_INSTRUCTION_FILE",
    "POISONED_POINTER_DETECTED",
    "HARDCODED_SECRET_LITERAL",
    "PROMPT_INJECTION_DETECTED",
    "TROJAN_BIDI_CONTROL",
    "UNICODE_TAG_SMUGGLING",
    "NETWORK_EXFILTRATION_BLOCKED",
    "UNTRUSTED_WEB_FETCH_BLOCKED",
    "UNVETTED_MCP_SERVER_BLOCKED",
    "CONFUSED_DEPUTY_BLOCKED",
    "CONFUSED_DEPUTY_TAINTED_SESSION",
    "CONFUSED_DEPUTY_WORKSPACE_CLI",
    "TAINTED_EXTERNAL_MUTATION_BLOCKED",
    "PRIVILEGE_ESCALATION_BLOCKED",
    "SELF_TAMPERING_BLOCKED",
    "GIT_HOOK_EXECUTION_BLOCKED",
    "DESTRUCTIVE_GIT_BLOCKED",
    "DANGEROUS_ENV_OVERRIDE",
    "SYMLINK_ESCAPE_BLOCKED",
    "CROSS_REPOSITORY_ESCAPE",
    "IMMUTABLE_CONTROL_PLANE",
    "RING0_RATCHET_VIOLATION",
    "ROLE_CAPABILITY_MISMATCH",
    "UNMINTED_CAPABILITY_DENIED",
];

pub fn is_ring0_constitutional_code(code: &str) -> bool {
    let up = code.trim().to_ascii_uppercase();
    RING0_CONSTITUTIONAL_CODES.contains(&up.as_str())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitSink {
    CliStdout,
    /// Keeps existing caller behavior for the result while optional events use the mirror.
    HookOrMcpStderr,
    Silent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedbackSubmitError {
    RateLimitExceeded(String),
    InvalidBallot(String),
}

impl FeedbackSubmitError {
    pub fn guard_code(&self) -> GuardCode {
        match self {
            Self::RateLimitExceeded(_) => GuardCode::FeedbackRateLimitExceeded,
            Self::InvalidBallot(_) => GuardCode::InvalidFeedbackBallot,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::RateLimitExceeded(m) | Self::InvalidBallot(m) => m.as_str(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedbackCategory {
    FalsePositiveBlock,
    MissingSafeFlag,
    PaginationOrBudgetFriction,
    UnclearRemediation,
    AdapterOrWorkflowBug,
}

impl FeedbackCategory {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "false_positive" | "false_positive_block" => Some(Self::FalsePositiveBlock),
            "missing_flag" | "missing_safe_flag" => Some(Self::MissingSafeFlag),
            "pagination_friction" | "budget_friction" | "pagination_or_budget_friction" => {
                Some(Self::PaginationOrBudgetFriction)
            }
            "unclear_remediation" | "diagnostic_clarity" => Some(Self::UnclearRemediation),
            "workflow_friction" | "adapter_bug" | "adapter_or_workflow_bug" => {
                Some(Self::AdapterOrWorkflowBug)
            }
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FalsePositiveBlock => "false_positive_block",
            Self::MissingSafeFlag => "missing_safe_flag",
            Self::PaginationOrBudgetFriction => "pagination_or_budget_friction",
            Self::UnclearRemediation => "unclear_remediation",
            Self::AdapterOrWorkflowBug => "adapter_or_workflow_bug",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BallotRequest {
    pub denial_id: Option<String>,
    pub category: FeedbackCategory,
    pub reason_code: Option<String>,
    pub note_ascii: Option<String>,
    pub session_id: String,
    pub root_session_id: Option<String>,
    pub role: String,
    pub task_id: Option<String>,
}

impl BallotRequest {
    pub fn to_json_value(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "denial_id".to_string(),
                self.denial_id
                    .as_ref()
                    .map_or(JsonValue::Null, |d| JsonValue::Str(d.clone())),
            ),
            (
                "category".to_string(),
                JsonValue::Str(self.category.as_str().to_string()),
            ),
            (
                "reason_code".to_string(),
                self.reason_code
                    .as_ref()
                    .map_or(JsonValue::Null, |r| JsonValue::Str(r.clone())),
            ),
            (
                "note_ascii".to_string(),
                self.note_ascii
                    .as_ref()
                    .map_or(JsonValue::Null, |n| JsonValue::Str(n.clone())),
            ),
            (
                "session_id".to_string(),
                JsonValue::Str(self.session_id.clone()),
            ),
            (
                "root_session_id".to_string(),
                self.root_session_id
                    .as_ref()
                    .map_or(JsonValue::Null, |p| JsonValue::Str(p.clone())),
            ),
            ("role".to_string(), JsonValue::Str(self.role.clone())),
            (
                "task_id".to_string(),
                self.task_id
                    .as_ref()
                    .map_or(JsonValue::Null, |t| JsonValue::Str(t.clone())),
            ),
        ])
    }

    pub fn from_json_value(v: &JsonValue) -> Result<Self, String> {
        let cat_str = v
            .get("category")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "missing category in BallotRequest".to_string())?;
        let category = FeedbackCategory::parse(cat_str)
            .ok_or_else(|| format!("unknown feedback category '{cat_str}'"))?;
        let session_id = v
            .get("session_id")
            .and_then(JsonValue::as_str)
            .unwrap_or("default")
            .to_string();
        let role = v
            .get("role")
            .and_then(JsonValue::as_str)
            .unwrap_or("coding-agent")
            .to_string();
        Ok(Self {
            denial_id: v
                .get("denial_id")
                .and_then(JsonValue::as_str)
                .map(String::from),
            category,
            reason_code: v
                .get("reason_code")
                .and_then(JsonValue::as_str)
                .map(String::from),
            note_ascii: v
                .get("note_ascii")
                .and_then(JsonValue::as_str)
                .map(String::from),
            session_id,
            root_session_id: v
                .get("root_session_id")
                .and_then(JsonValue::as_str)
                .map(String::from),
            role,
            task_id: v
                .get("task_id")
                .and_then(JsonValue::as_str)
                .map(String::from),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SignedBallotRecord {
    pub schema: String,
    pub ballot_id: String,
    pub cluster_key: String,
    pub category: String,
    pub deny_code: Option<String>,
    pub target_bin_or_tool: String,
    pub canonical_shape: String,
    pub reason_code: String,
    pub scrubbed_note: String,
    pub repo_id: String,
    pub repo_day_bucket: String,
    pub voter_token: String,
    pub display_session_hash: String,
    pub role: String,
    pub task_id: Option<String>,
    pub session_tainted: bool,
    pub grounded: bool,
    pub vote_counted: bool,
    pub deduplicated_retry: bool,
    pub quarantined: bool,
    pub session_cluster_submissions: u32,
    pub session_total_submissions: u32,
    pub risk_flags: Vec<String>,
    pub ts_unix: u64,
    pub mac_hex: String,
}

impl SignedBallotRecord {
    pub fn canonical_mac_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        push_lp(&mut out, &self.schema);
        push_lp(&mut out, &self.ballot_id);
        push_lp(&mut out, &self.cluster_key);
        push_lp(&mut out, &self.category);
        push_lp(&mut out, self.deny_code.as_deref().unwrap_or(""));
        push_lp(&mut out, &self.target_bin_or_tool);
        push_lp(&mut out, &self.canonical_shape);
        push_lp(&mut out, &self.reason_code);
        push_lp(&mut out, &self.scrubbed_note);
        push_lp(&mut out, &self.repo_id);
        push_lp(&mut out, &self.repo_day_bucket);
        push_lp(&mut out, &self.voter_token);
        push_lp(&mut out, &self.display_session_hash);
        push_lp(&mut out, &self.role);
        push_lp(&mut out, self.task_id.as_deref().unwrap_or(""));
        out.push(u8::from(self.session_tainted));
        out.push(u8::from(self.grounded));
        out.push(u8::from(self.vote_counted));
        out.push(u8::from(self.deduplicated_retry));
        out.push(u8::from(self.quarantined));
        out.extend_from_slice(&self.session_cluster_submissions.to_be_bytes());
        out.extend_from_slice(&self.session_total_submissions.to_be_bytes());
        out.extend_from_slice(&(self.risk_flags.len() as u32).to_be_bytes());
        for rf in &self.risk_flags {
            push_lp(&mut out, rf);
        }
        out.extend_from_slice(&self.ts_unix.to_be_bytes());
        out
    }

    pub fn to_json_value(&self) -> JsonValue {
        let flags: Vec<JsonValue> = self
            .risk_flags
            .iter()
            .map(|f| JsonValue::Str(f.clone()))
            .collect();
        JsonValue::Object(vec![
            ("schema".to_string(), JsonValue::Str(self.schema.clone())),
            (
                "ballot_id".to_string(),
                JsonValue::Str(self.ballot_id.clone()),
            ),
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
            (
                "reason_code".to_string(),
                JsonValue::Str(self.reason_code.clone()),
            ),
            (
                "scrubbed_note".to_string(),
                JsonValue::Str(self.scrubbed_note.clone()),
            ),
            ("repo_id".to_string(), JsonValue::Str(self.repo_id.clone())),
            (
                "repo_day_bucket".to_string(),
                JsonValue::Str(self.repo_day_bucket.clone()),
            ),
            (
                "voter_token".to_string(),
                JsonValue::Str(self.voter_token.clone()),
            ),
            (
                "display_session_hash".to_string(),
                JsonValue::Str(self.display_session_hash.clone()),
            ),
            ("role".to_string(), JsonValue::Str(self.role.clone())),
            (
                "task_id".to_string(),
                self.task_id
                    .as_ref()
                    .map_or(JsonValue::Null, |t| JsonValue::Str(t.clone())),
            ),
            (
                "session_tainted".to_string(),
                JsonValue::Bool(self.session_tainted),
            ),
            ("grounded".to_string(), JsonValue::Bool(self.grounded)),
            (
                "vote_counted".to_string(),
                JsonValue::Bool(self.vote_counted),
            ),
            (
                "deduplicated_retry".to_string(),
                JsonValue::Bool(self.deduplicated_retry),
            ),
            ("quarantined".to_string(), JsonValue::Bool(self.quarantined)),
            (
                "session_cluster_submissions".to_string(),
                JsonValue::Uint(u64::from(self.session_cluster_submissions)),
            ),
            (
                "session_total_submissions".to_string(),
                JsonValue::Uint(u64::from(self.session_total_submissions)),
            ),
            ("risk_flags".to_string(), JsonValue::Array(flags)),
            ("ts_unix".to_string(), JsonValue::Uint(self.ts_unix)),
            ("mac_hex".to_string(), JsonValue::Str(self.mac_hex.clone())),
        ])
    }

    pub fn from_json_value(v: &JsonValue) -> Result<Self, String> {
        let str_req = |k: &str| -> Result<String, String> {
            v.get(k)
                .and_then(JsonValue::as_str)
                .map(String::from)
                .ok_or_else(|| format!("missing string '{k}' in SignedBallotRecord"))
        };
        let bool_req = |k: &str| -> Result<bool, String> {
            v.get(k)
                .and_then(JsonValue::as_bool)
                .ok_or_else(|| format!("missing bool '{k}' in SignedBallotRecord"))
        };
        let mut risk_flags = Vec::new();
        if let Some(arr) = v.get("risk_flags").and_then(JsonValue::as_array) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    risk_flags.push(s.to_string());
                }
            }
        }
        Ok(Self {
            schema: str_req("schema")?,
            ballot_id: str_req("ballot_id")?,
            cluster_key: str_req("cluster_key")?,
            category: str_req("category")?,
            deny_code: v
                .get("deny_code")
                .and_then(JsonValue::as_str)
                .map(String::from),
            target_bin_or_tool: str_req("target_bin_or_tool")?,
            canonical_shape: str_req("canonical_shape")?,
            reason_code: str_req("reason_code")?,
            scrubbed_note: str_req("scrubbed_note")?,
            repo_id: str_req("repo_id")?,
            repo_day_bucket: str_req("repo_day_bucket")?,
            voter_token: str_req("voter_token")?,
            display_session_hash: str_req("display_session_hash")?,
            role: str_req("role")?,
            task_id: v
                .get("task_id")
                .and_then(JsonValue::as_str)
                .map(String::from),
            session_tainted: bool_req("session_tainted")?,
            grounded: bool_req("grounded")?,
            vote_counted: bool_req("vote_counted")?,
            deduplicated_retry: bool_req("deduplicated_retry")?,
            quarantined: bool_req("quarantined")?,
            session_cluster_submissions: v
                .get("session_cluster_submissions")
                .and_then(JsonValue::as_u64)
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| "missing session_cluster_submissions".to_string())?,
            session_total_submissions: v
                .get("session_total_submissions")
                .and_then(JsonValue::as_u64)
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| "missing session_total_submissions".to_string())?,
            risk_flags,
            ts_unix: v
                .get("ts_unix")
                .and_then(JsonValue::as_u64)
                .ok_or_else(|| "missing ts_unix".to_string())?,
            mac_hex: str_req("mac_hex")?,
        })
    }

    /// Public redacted AgentPI telemetry frame (never exposes `mac_hex` or keyed `voter_token`).
    pub fn to_agentpi_event_json(&self) -> JsonValue {
        let severity = if self.quarantined
            || self.risk_flags.iter().any(|f| {
                matches!(
                    f.as_str(),
                    "TAINTED_SESSION_BALLOT_ATTEMPT"
                        | "BALLOT_UNICODE_SMUGGLING"
                        | "BALLOT_INJECTION_ATTEMPT"
                )
            }) {
            "HIGH"
        } else if !self.risk_flags.is_empty() {
            "MEDIUM"
        } else {
            "INFO"
        };
        let flags: Vec<JsonValue> = self
            .risk_flags
            .iter()
            .map(|f| JsonValue::Str(f.clone()))
            .collect();
        JsonValue::Object(vec![
            (
                "schema".to_string(),
                JsonValue::Str(AGENTPI_EVENT_SCHEMA.to_string()),
            ),
            (
                "event_type".to_string(),
                JsonValue::Str("friction_ballot".to_string()),
            ),
            ("severity".to_string(), JsonValue::Str(severity.to_string())),
            (
                "ballot_id".to_string(),
                JsonValue::Str(self.ballot_id.clone()),
            ),
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
            (
                "session_hash".to_string(),
                JsonValue::Str(self.display_session_hash.clone()),
            ),
            ("role".to_string(), JsonValue::Str(self.role.clone())),
            (
                "session_tainted".to_string(),
                JsonValue::Bool(self.session_tainted),
            ),
            ("grounded".to_string(), JsonValue::Bool(self.grounded)),
            (
                "vote_counted".to_string(),
                JsonValue::Bool(self.vote_counted),
            ),
            (
                "deduplicated_retry".to_string(),
                JsonValue::Bool(self.deduplicated_retry),
            ),
            ("quarantined".to_string(), JsonValue::Bool(self.quarantined)),
            (
                "session_cluster_submissions".to_string(),
                JsonValue::Uint(u64::from(self.session_cluster_submissions)),
            ),
            (
                "session_total_submissions".to_string(),
                JsonValue::Uint(u64::from(self.session_total_submissions)),
            ),
            ("risk_flags".to_string(), JsonValue::Array(flags)),
            ("ts_unix".to_string(), JsonValue::Uint(self.ts_unix)),
        ])
    }
}

#[derive(Debug, Clone)]
pub struct AggregatedFrictionCluster {
    pub cluster_key: String,
    pub category: String,
    pub deny_code: Option<String>,
    pub target_bin_or_tool: String,
    pub canonical_shape: String,
    pub ring0_locked: bool,
    pub unique_votes: usize,
    pub voter_entries: Vec<(String, String)>, // (voter_token, repo_day_bucket)
    pub distinct_repo_day_buckets: usize,
    pub total_raw_submissions: usize,
    pub max_single_agent_retries: u32,
    pub tainted_attempts: usize,
    pub loop_anomaly_agents: usize,
    pub scrubbed_notes: Vec<String>,
    pub last_ts_unix: u64,
}

fn push_lp(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
}

pub fn compute_cluster_key(
    category: &str,
    deny_code: Option<&str>,
    canonical_shape: &str,
) -> String {
    let dc = deny_code.unwrap_or("NONE").trim().to_ascii_uppercase();
    let seed = format!(
        "dotagent:cluster:v2:{}:{}:{}",
        category.trim().to_ascii_lowercase(),
        dc,
        canonical_shape.trim()
    );
    format!("fbk_{}", &sha256_hex(seed.as_bytes())[..16])
}

pub fn is_valid_cluster_key(k: &str) -> bool {
    k.len() == 20
        && k.starts_with("fbk_")
        && k.as_bytes()[4..]
            .iter()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub fn is_valid_denial_or_trace_id(id: &str) -> bool {
    (id.starts_with("dnl_") || id.starts_with("trc_"))
        && id.len() == 20
        && id.as_bytes()[4..]
            .iter()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub fn is_valid_reason_code_token(tok: &str) -> bool {
    !tok.is_empty()
        && tok.len() <= 64
        && tok
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

pub fn clean_single_line_ascii(raw: &str, max_bytes: usize) -> String {
    let neutered = neuter_to_clean_ascii(raw).clean_ascii;
    let mut collapsed = String::with_capacity(neutered.len().min(max_bytes));
    let mut prev_space = false;
    for ch in neutered.chars() {
        if ch.is_ascii_whitespace() || ch.is_ascii_control() {
            if !prev_space && !collapsed.is_empty() {
                collapsed.push(' ');
                prev_space = true;
            }
        } else if ch.is_ascii() {
            collapsed.push(ch);
            prev_space = false;
        }
        if collapsed.len() >= max_bytes {
            break;
        }
    }
    collapsed.trim().to_string()
}

fn shannon_entropy_bits(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 128];
    let mut n = 0u32;
    for &b in s.as_bytes() {
        if b < 128 {
            counts[b as usize] += 1;
            n += 1;
        }
    }
    if n == 0 {
        return 0.0;
    }
    let total = f64::from(n);
    let mut ent = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = f64::from(c) / total;
            ent -= p * p.log2();
        }
    }
    ent
}

fn segment_is_high_entropy(seg: &str) -> bool {
    if seg.len() < 20
        || !seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return false;
    }
    let has_upper = seg.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = seg.bytes().any(|b| b.is_ascii_lowercase());
    let has_digit = seg.bytes().any(|b| b.is_ascii_digit());
    let classes = u8::from(has_upper) + u8::from(has_lower) + u8::from(has_digit);
    let bits = shannon_entropy_bits(seg);
    (classes >= 2 && bits >= 3.85) || (seg.len() >= 24 && bits >= 4.0)
}

fn looks_like_secret_or_high_entropy_token(tok: &str) -> bool {
    let trimmed = tok.trim_matches(|c: char| {
        matches!(
            c,
            '"' | '\'' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}'
        )
    });
    if trimmed.len() < 16 {
        return false;
    }
    if is_valid_denial_or_trace_id(trimmed) || is_valid_cluster_key(trimmed) {
        return false;
    }
    for prefix in [
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "sk-",
        "sk_live_",
        "AKIA",
        "ASIA",
        "xoxb-",
        "xoxp-",
        "AIza",
    ] {
        if trimmed.starts_with(prefix) {
            return true;
        }
    }
    // JWT three-segment header (`eyJ...`)
    if trimmed.starts_with("eyJ") && trimmed.matches('.').count() >= 2 {
        return true;
    }
    // Raw 32+ char hex key/digest
    if trimmed.len() >= 32 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return true;
    }
    // Entropy screening runs on every segment BEFORE path/flag exemptions so secrets embedded in
    // `--token=<secret>` or `x/<secret>.md` shapes are still caught.
    for seg in trimmed.split(['/', '.', '=', ':', '@']) {
        let seg = seg.trim_matches('-');
        if segment_is_high_entropy(seg) {
            return true;
        }
    }
    // Skip ordinary repo paths and long flag names (`crates/agent-guard/src/...`, `--allow-something`)
    if trimmed.starts_with("--")
        || trimmed.starts_with("crates/")
        || trimmed.starts_with("tests/")
        || trimmed.starts_with("scripts/")
        || trimmed.ends_with(".rs")
        || trimmed.ends_with(".toml")
        || trimmed.ends_with(".json")
        || trimmed.ends_with(".md")
    {
        return false;
    }
    if trimmed.len() >= 20 {
        let has_upper = trimmed.bytes().any(|b| b.is_ascii_uppercase());
        let has_lower = trimmed.bytes().any(|b| b.is_ascii_lowercase());
        let has_digit = trimmed.bytes().any(|b| b.is_ascii_digit());
        let classes = u8::from(has_upper) + u8::from(has_lower) + u8::from(has_digit);
        if classes >= 2 && shannon_entropy_bits(trimmed) >= 3.85 {
            return true;
        }
    }
    false
}

/// Scrubs URLs with credentials/query strings, home directory paths, secret prefixes, and
/// high-entropy bearer/JWT/hex tokens before writing to local spool or GitHub sync batches.
pub fn scrub_high_entropy_and_secrets(raw: &str, max_bytes: usize) -> (String, Vec<&'static str>) {
    let single = clean_single_line_ascii(raw, max_bytes.saturating_mul(2).max(256));
    let mut flags: Vec<&'static str> = Vec::new();
    let mut out_words = Vec::new();
    // 0 = idle, 1 = after `authorization:` (scheme or credential next), 2 = credential next
    let mut auth_state = 0u8;
    let push_flag = |flags: &mut Vec<&'static str>, f: &'static str| {
        if !flags.contains(&f) {
            flags.push(f);
        }
    };

    for word in single.split(' ') {
        if word.is_empty() {
            continue;
        }
        let core = word.trim_matches(|c: char| {
            matches!(
                c,
                '(' | ')' | '<' | '>' | '"' | '\'' | ',' | ';' | '[' | ']' | '{' | '}' | '`' | '.'
            )
        });
        if auth_state == 1 {
            let is_scheme = !core.is_empty()
                && core.len() <= 24
                && core.bytes().all(|b| b.is_ascii_alphabetic() || b == b'-')
                && !looks_like_secret_or_high_entropy_token(core);
            if is_scheme {
                auth_state = 2;
                out_words.push(word.to_string());
                continue;
            }
            auth_state = 0;
            push_flag(&mut flags, "HIGH_ENTROPY_TOKEN_SCRUBBED");
            out_words.push("<HIGH_ENTROPY_REDACTED>".to_string());
            continue;
        }
        if auth_state == 2 {
            auth_state = 0;
            push_flag(&mut flags, "HIGH_ENTROPY_TOKEN_SCRUBBED");
            out_words.push("<HIGH_ENTROPY_REDACTED>".to_string());
            continue;
        }
        if core.eq_ignore_ascii_case("bearer") {
            auth_state = 2;
            out_words.push(word.to_string());
            continue;
        }
        if core.eq_ignore_ascii_case("authorization:")
            || core.eq_ignore_ascii_case("proxy-authorization:")
        {
            auth_state = 1;
            out_words.push(word.to_string());
            continue;
        }
        let lower = core.to_ascii_lowercase();
        if let Some(pos) = lower.find("http://").or_else(|| lower.find("https://")) {
            let url = &core[pos..];
            if url.contains('?') || url.contains('@') || url.contains('#') || url.len() > 36 {
                push_flag(&mut flags, "URL_QUERY_OR_CRED_SCRUBBED");
                out_words.push("<URL_REDACTED>".to_string());
                continue;
            }
        }
        let path_norm = normalize_home_prefix(core);
        if let Some((lhs, rhs)) = path_norm.split_once('=') {
            let lhs_lower = lhs.to_ascii_lowercase();
            if looks_like_secret_or_high_entropy_token(rhs)
                || rhs.split('=').any(looks_like_secret_or_high_entropy_token)
                || [
                    "token", "secret", "password", "passwd", "apikey", "api_key", "auth", "cred",
                ]
                .iter()
                .any(|k| lhs_lower.contains(k))
            {
                push_flag(&mut flags, "HIGH_ENTROPY_TOKEN_SCRUBBED");
                out_words.push(format!("{lhs}=<HIGH_ENTROPY_REDACTED>"));
                continue;
            }
        }
        if looks_like_secret_or_high_entropy_token(&path_norm) {
            push_flag(&mut flags, "HIGH_ENTROPY_TOKEN_SCRUBBED");
            out_words.push("<HIGH_ENTROPY_REDACTED>".to_string());
            continue;
        }
        if path_norm != core {
            out_words.push(path_norm);
        } else {
            out_words.push(word.to_string());
        }
    }

    let mut joined = out_words.join(" ");
    if joined.len() > max_bytes {
        joined.truncate(max_bytes);
        joined = joined.trim_end().to_string();
    }
    (joined, flags)
}

/// Replaces every `/home/<user>` and `/Users/<user>` segment anywhere inside a token with `<HOME>`.
fn normalize_home_prefix(token: &str) -> String {
    let mut out = String::with_capacity(token.len());
    let mut rest = token;
    loop {
        let hit = ["/home/", "/Users/"]
            .iter()
            .filter_map(|p| rest.find(p).map(|i| (i, p.len())))
            .min_by_key(|(i, _)| *i);
        let Some((idx, plen)) = hit else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..idx]);
        let after = &rest[idx + plen..];
        let seg_end = after.find('/').unwrap_or(after.len());
        if seg_end == 0 {
            out.push_str(&rest[idx..idx + plen]);
            rest = after;
            continue;
        }
        out.push_str("<HOME>");
        rest = &after[seg_end..];
    }
    out
}

pub fn utc_day_yyyymmdd(ts_unix: u64) -> String {
    // Civil-from-days algorithm (Howard Hinnant, public domain) for deterministic UTC YYYY-MM-DD
    let z = (ts_unix / 86_400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}{m:02}{d:02}")
}

pub fn feedback_state_dir() -> Result<PathBuf, String> {
    feedback_dir_under(&crate::traversal_ledger::state_root_dir())
}

fn feedback_dir_under(root: &Path) -> Result<PathBuf, String> {
    ensure_nonsymlink_state_dir(root)?;
    let fb = root.join("feedback");
    ensure_nonsymlink_state_dir(&fb)?;
    Ok(fb)
}

pub fn load_or_init_global_feedback_key() -> Result<ZeroizingKey, String> {
    let vault_dir = feedback_state_dir()?.join("vault");
    ensure_nonsymlink_state_dir(&vault_dir)?;
    let key_path = vault_dir.join("hmac.key");
    let lock_path = vault_dir.join("hmac.lock");
    let _lock = ExclusiveFileLockGuard::acquire(&lock_path)?;

    if let Ok(meta) = fs::symlink_metadata(&key_path) {
        if meta.file_type().is_symlink() {
            return Err(
                "FEEDBACK_VAULT_SYMLINK_TAMPER: feedback/vault/hmac.key is a symlink".to_string(),
            );
        }
        if meta.file_type().is_file() {
            let raw_hex = fs::read_to_string(&key_path)
                .map_err(|e| format!("failed reading feedback hmac.key: {e}"))?;
            let decoded = hex_decode_bytes(raw_hex.trim())?;
            if decoded.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&decoded);
                let zk = ZeroizingKey::new(arr);
                crate::crypto::zeroize_slice(&mut arr);
                return Ok(zk);
            }
        }
    }

    let mut fresh = [0u8; 32];
    #[cfg(unix)]
    {
        let mut f = fs::File::open("/dev/urandom")
            .map_err(|e| format!("failed opening /dev/urandom: {e}"))?;
        f.read_exact(&mut fresh)
            .map_err(|e| format!("failed reading /dev/urandom: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        fresh = crate::crypto::sha256_bytes(&nanos.to_le_bytes());
    }
    let zk = ZeroizingKey::new(fresh);
    crate::crypto::zeroize_slice(&mut fresh);

    let tmp_path = vault_dir.join(format!(".hmac.key.tmp.{}", std::process::id()));
    let _ = fs::remove_file(&tmp_path);
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&tmp_path)
        .map_err(|e| format!("failed creating feedback key temp: {e}"))?;
    writeln!(f, "{}", hex_encode(zk.as_bytes()))
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("failed writing feedback key temp: {e}"))?;
    drop(f);
    fs::rename(&tmp_path, &key_path)
        .map_err(|e| format!("failed installing feedback hmac.key: {e}"))?;
    Ok(zk)
}

pub fn current_host_spool_id() -> Result<String, String> {
    let key = load_or_init_global_feedback_key()?;
    let tag =
        compute_domain_tag_for_feedback(key.as_bytes(), b"dotagent:feedback:node-id:v2", b"host")?;
    Ok(format!("node_{}", &hex_encode(&tag)[..16]))
}

/// Mints a short-lived HMAC-authenticated worker token before `exec-sandbox` enters Landlock/Seatbelt
/// so `coord.sock` can bind IPC ballots strictly to the daemon-verified `(session_id, root_session_id, role)`.
pub fn mint_ipc_worker_token(
    swarm_key: &[u8; 32],
    canon_repo: &Path,
    session_id: &str,
    root_session_id: &str,
    role: &str,
    now_unix: u64,
) -> Result<String, String> {
    let repo_sha = sha256_hex(canon_repo.to_string_lossy().as_bytes());
    let exp_unix = now_unix.saturating_add(900);
    let mut payload = Vec::with_capacity(192);
    push_lp(&mut payload, &repo_sha);
    push_lp(&mut payload, session_id);
    push_lp(&mut payload, root_session_id);
    push_lp(&mut payload, role);
    payload.extend_from_slice(&exp_unix.to_be_bytes());
    let tag = compute_domain_tag_for_feedback(swarm_key, IPC_WORKER_TOKEN_DOMAIN, &payload)?;
    Ok(format!("{}.{}", hex_encode(&payload), hex_encode(&tag)))
}

pub fn verify_ipc_worker_token(
    swarm_key: &[u8; 32],
    canon_repo: &Path,
    token: &str,
    now_unix: u64,
) -> Result<(String, String, String), String> {
    let (payload_hex, tag_hex) = token
        .trim()
        .split_once('.')
        .ok_or_else(|| "UNAUTHENTICATED_IPC_BALLOT: missing worker token signature".to_string())?;
    let payload = hex_decode_bytes(payload_hex)?;
    let given_tag = hex_decode_bytes(tag_hex)?;
    let expected_tag =
        compute_domain_tag_for_feedback(swarm_key, IPC_WORKER_TOKEN_DOMAIN, &payload)?;
    if !constant_time_eq_bytes(&expected_tag, &given_tag) {
        return Err(
            "FORGED_IPC_WORKER_TOKEN: worker token failed coordinator vault HMAC check".to_string(),
        );
    }

    let mut pos = 0usize;
    let read_str = |buf: &[u8], p: &mut usize| -> Result<String, String> {
        let len_slice = buf
            .get(*p..*p + 4)
            .ok_or_else(|| "truncated worker token length".to_string())?;
        *p += 4;
        let len =
            u32::from_be_bytes([len_slice[0], len_slice[1], len_slice[2], len_slice[3]]) as usize;
        let s_slice = buf
            .get(*p..*p + len)
            .ok_or_else(|| "truncated worker token string".to_string())?;
        *p += len;
        std::str::from_utf8(s_slice)
            .map(String::from)
            .map_err(|_| "non-UTF-8 worker token field".to_string())
    };
    let repo_sha = read_str(&payload, &mut pos)?;
    let sid = read_str(&payload, &mut pos)?;
    let root_sid = read_str(&payload, &mut pos)?;
    let role = read_str(&payload, &mut pos)?;
    let exp_slice = payload
        .get(pos..pos + 8)
        .ok_or_else(|| "truncated worker token expiry".to_string())?;
    let exp_unix = u64::from_be_bytes([
        exp_slice[0],
        exp_slice[1],
        exp_slice[2],
        exp_slice[3],
        exp_slice[4],
        exp_slice[5],
        exp_slice[6],
        exp_slice[7],
    ]);
    let expected_repo_sha = sha256_hex(canon_repo.to_string_lossy().as_bytes());
    if repo_sha != expected_repo_sha {
        return Err(
            "CROSS_REPO_IPC_WORKER_TOKEN: worker token bound to different repository".to_string(),
        );
    }
    if now_unix > exp_unix {
        return Err("EXPIRED_IPC_WORKER_TOKEN: worker token expired".to_string());
    }
    Ok((sid, root_sid, role))
}

fn append_bounded_rotated_jsonl(
    path: &Path,
    line_json: &str,
    acquire_lock: fn(&Path) -> Result<ExclusiveFileLockGuard, String>,
    sync_mirror: bool,
) -> Result<(), String> {
    if line_json.len() + 1 > MAX_JSONL_RECORD_BYTES {
        return Err(format!(
            "ballot/telemetry record {} bytes exceeds {MAX_JSONL_RECORD_BYTES}-byte atomic ceiling",
            line_json.len() + 1
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| "spool file missing parent dir".to_string())?;
    ensure_nonsymlink_state_dir(parent)?;
    let lock_path = path.with_extension("lock");
    let _guard = acquire_lock(&lock_path)?;

    if let Ok(meta) = fs::symlink_metadata(path) {
        #[cfg(unix)]
        if sync_mirror {
            use std::os::unix::fs::MetadataExt;
            if !meta.is_file() || meta.nlink() != 1 || meta.mode() & 0o777 != 0o600 {
                return Err("invalid mirror destination".into());
            }
        }
        if meta.file_type().is_symlink() {
            return Err(format!(
                "SPOOL_SYMLINK_REJECTED: refusing symlinked spool '{}'",
                path.display()
            ));
        }
        if meta.len() >= MAX_SPOOL_FILE_BYTES {
            let gen1 = PathBuf::from(format!("{}.1", path.display()));
            if let Ok(gmeta) = fs::symlink_metadata(&gen1)
                && gmeta.file_type().is_symlink()
            {
                return Err(format!(
                    "SPOOL_SYMLINK_REJECTED: refusing symlinked rotated spool '{}'",
                    gen1.display()
                ));
            }
            fs::rename(path, &gen1).map_err(|e| {
                format!(
                    "SPOOL_ROTATION_FAILED: cannot rotate '{}' (refusing unbounded growth): {e}",
                    path.display()
                )
            })?;
        }
    }

    let mut opts = OpenOptions::new();
    opts.create(true).write(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos"
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let nonblocking = if cfg!(target_os = "linux") { 0o4000 } else { 4 };
        opts.custom_flags(O_NOFOLLOW_FLAG | if sync_mirror { nonblocking } else { 0 });
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("failed opening spool '{}': {e}", path.display()))?;
    if sync_mirror {
        let meta = f.metadata().map_err(|e| e.to_string())?;
        if !meta.is_file() {
            return Err("invalid mirror file".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.nlink() != 1 || meta.mode() & 0o777 != 0o600 {
                return Err("invalid mirror file permissions or link count".into());
            }
        }
    }
    let mut framed = String::with_capacity(line_json.len() + 1);
    framed.push_str(line_json);
    framed.push('\n');
    f.write_all(framed.as_bytes())
        .map_err(|e| format!("failed appending spool '{}': {e}", path.display()))?;
    if sync_mirror {
        f.sync_all()
            .and_then(|()| fs::File::open(parent)?.sync_all())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub(crate) fn write_agentpi_mirror(event_json: &JsonValue) -> bool {
    let encoded = event_json.to_json_string();
    feedback_dir_under(&crate::traversal_ledger::observation_state_root_dir())
        .and_then(|dir| {
            append_bounded_rotated_jsonl(
                &dir.join("agentpi_events.jsonl"),
                &encoded,
                ExclusiveFileLockGuard::acquire_observation,
                true,
            )
        })
        .is_ok()
}

fn publish_agentpi_result(event_json: &JsonValue, sink: EmitSink) {
    if sink == EmitSink::CliStdout {
        println!("{AGENTPI_STDOUT_PREFIX}{}", event_json.to_json_string());
    }
}

/// Queues the observational AgentPI guard-denial event for the protected mirror.
pub fn record_guard_denial_agentpi_signal(
    repo_root: &Path,
    session_id: &str,
    tool: &str,
    code: &str,
    detail: &str,
    halted: bool,
    ts_unix: u64,
) {
    if repo_root.as_os_str().len() > MAX_AGENTPI_EXPORT_INPUT_BYTES
        || [session_id, tool, code, detail]
            .into_iter()
            .any(|value| value.len() > MAX_AGENTPI_EXPORT_INPUT_BYTES)
    {
        note_invalid_export();
        return;
    }
    let _ = submit_record(Kind::Denial, || {
        guard_denial_agentpi_event(
            repo_root,
            session_id,
            crate::telemetry::protocol::tool_class(tool),
            code,
            if detail.is_empty() { "" } else { "[redacted]" },
            halted,
            ts_unix,
        )
    });
}

fn guard_denial_agentpi_event(
    repo_root: &Path,
    session_id: &str,
    tool: &str,
    code: &str,
    detail: &str,
    halted: bool,
    ts_unix: u64,
) -> JsonValue {
    let repo_id = sha256_hex(repo_root.to_string_lossy().as_bytes());
    let session_hash = compute_session_key_hash(repo_root, session_id);
    let code = crate::traversal_ledger::audit_ascii(code, 128);
    let detail = crate::traversal_ledger::audit_ascii(detail, 240);
    let (clean_detail, _) = scrub_high_entropy_and_secrets(&detail, 160);
    let severity = if halted || is_ring0_constitutional_code(&code) {
        "HIGH"
    } else {
        "INFO"
    };
    JsonValue::Object(vec![
        (
            "schema".to_string(),
            JsonValue::Str(AGENTPI_EVENT_SCHEMA.to_string()),
        ),
        (
            "event_type".to_string(),
            JsonValue::Str("guard_denial".to_string()),
        ),
        ("severity".to_string(), JsonValue::Str(severity.to_string())),
        (
            "repo_id".to_string(),
            JsonValue::Str(repo_id[..16].to_string()),
        ),
        (
            "session_hash".to_string(),
            JsonValue::Str(session_hash[..16].to_string()),
        ),
        (
            "tool".to_string(),
            JsonValue::Str(clean_single_line_ascii(tool, 48)),
        ),
        ("code".to_string(), JsonValue::Str(code)),
        ("halted".to_string(), JsonValue::Bool(halted)),
        ("detail".to_string(), JsonValue::Str(clean_detail)),
        ("ts_unix".to_string(), JsonValue::Uint(ts_unix)),
    ])
}

/// Opens a spool file read-only with `O_NOFOLLOW` (where supported) after an lstat regular-file
/// check, closing the lstat/open TOCTOU window against symlink swaps.
fn open_spool_nofollow(candidate: &Path) -> Option<fs::File> {
    let meta = fs::symlink_metadata(candidate).ok()?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return None;
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos"
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(O_NOFOLLOW_FLAG);
    }
    let f = opts.open(candidate).ok()?;
    let fmeta = f.metadata().ok()?;
    if !fmeta.is_file() {
        return None;
    }
    Some(f)
}

fn already_voted_in_spool(voter_token: &str, cluster_key: &str) -> bool {
    let Ok(dir) = feedback_state_dir() else {
        return false;
    };
    for candidate in [dir.join("ballots.jsonl"), dir.join("ballots.jsonl.1")] {
        let Some(f) = open_spool_nofollow(&candidate) else {
            continue;
        };
        let reader = BufReader::new(f.take(MAX_SPOOL_FILE_BYTES));
        for line in reader.lines().map_while(Result::ok) {
            if !line.contains(cluster_key) || !line.contains(voter_token) {
                continue;
            }
            if let Ok(v) = JsonValue::parse(&line)
                && v.get("cluster_key").and_then(JsonValue::as_str) == Some(cluster_key)
                && v.get("voter_token").and_then(JsonValue::as_str) == Some(voter_token)
                && v.get("vote_counted").and_then(JsonValue::as_bool) == Some(true)
            {
                return true;
            }
        }
    }
    false
}

/// Host-side ballot commit engine called either directly on host or over authenticated `coord.sock`.
pub fn commit_ballot_on_host_redacted(
    repo_root: &Path,
    req: &BallotRequest,
    from_ipc: bool,
    sink: EmitSink,
) -> Result<JsonValue, FeedbackSubmitError> {
    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let mut sid = req.session_id.trim().to_string();
    if sid.is_empty() {
        sid = "default".to_string();
    }

    let reason_code = match req
        .reason_code
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(rc) => {
            if !is_valid_reason_code_token(rc) {
                return Err(FeedbackSubmitError::InvalidBallot(format!(
                    "invalid --reason-code '{rc}' (expected 1..=64 ASCII [A-Za-z0-9_.-] characters)"
                )));
            }
            rc.to_string()
        }
        None => "unspecified".to_string(),
    };

    if let Some(ref did) = req.denial_id
        && !did.trim().is_empty()
        && !is_valid_denial_or_trace_id(did.trim())
    {
        return Err(FeedbackSubmitError::InvalidBallot(format!(
            "invalid --denial-id '{}' (expected 'dnl_<16-lower-hex>' or 'trc_<16-lower-hex>' from guard output)",
            did.trim()
        )));
    }

    let mut effective_role = clean_single_line_ascii(&req.role, 32);
    let mut effective_task_id = req
        .task_id
        .as_deref()
        .map(|t| clean_single_line_ascii(t, 48));
    if let Ok(cap) = crate::role_sandbox::load_session_capability(&canon_repo, &sid) {
        effective_role = cap.role.as_str_id().to_string();
        effective_task_id = Some(cap.task_id);
    } else if from_ipc && !crate::traversal_ledger::session_ledger_path(&canon_repo, &sid).is_file()
    {
        return Err(FeedbackSubmitError::InvalidBallot(format!(
            "UNMINTED_IPC_SESSION: unknown session '{sid}' rejected over coord.sock"
        )));
    }

    let _session_lock = SessionLedger::acquire_lock(&canon_repo, &sid).ok_or_else(|| {
        FeedbackSubmitError::InvalidBallot("failed acquiring session ledger lock".to_string())
    })?;
    let mut ledger = SessionLedger::load_or_create(&canon_repo, &sid);

    // Hard Disk DoS Cutoff (`session_total_submissions > 8`): zero further spool disk writes!
    if ledger.ballot_submissions >= MAX_BALLOTS_PER_SESSION {
        if ledger.ballot_submissions == MAX_BALLOTS_PER_SESSION {
            ledger.ballot_submissions = ledger.ballot_submissions.saturating_add(1);
            let _ = ledger.save_locked(&canon_repo);
        }
        return Err(FeedbackSubmitError::RateLimitExceeded(format!(
            "session '{sid}' exceeded maximum {} friction ballots per session (disk spool writes halted)",
            MAX_BALLOTS_PER_SESSION
        )));
    }

    if let Some(ref caller_root) = req.root_session_id {
        let trimmed = caller_root.trim();
        // Only the coordinator (IPC, capability-verified) may assert a swarm root. Host CLI callers
        // inherit the root that PostToolUse hooks recorded from the harness payload; an
        // env/argv-supplied root is ignored so Sybil collapse cannot be opted out of or hijacked.
        if !trimmed.is_empty() && from_ipc {
            let clean_root: String = trimmed
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .take(64)
                .collect();
            if !clean_root.is_empty() {
                ledger.root_session_id = clean_root;
            }
        }
    }

    let mut risk_flags: Vec<String> = Vec::new();
    let mut hostile_note = false;
    let raw_note_str = req.note_ascii.as_deref().unwrap_or("");
    if !raw_note_str.is_empty() {
        if raw_note_str.len() > 360 {
            return Err(FeedbackSubmitError::InvalidBallot(
                "note_ascii exceeds 360 raw byte pre-scrub limit".to_string(),
            ));
        }
        if !scan_unicode(raw_note_str, ScanMode::UntrustedContent).is_empty() {
            hostile_note = true;
            risk_flags.push("BALLOT_UNICODE_SMUGGLING".to_string());
        }
        let inj = scan_untrusted_content(raw_note_str, &canon_repo, &canon_repo, false);
        if inj
            .findings
            .iter()
            .any(|f| f.code == "HARDCODED_SECRET_LITERAL")
        {
            risk_flags.push("HARDCODED_SECRET_SCRUBBED".to_string());
        }
        if inj.first_halt().is_some()
            || inj
                .findings
                .iter()
                .any(|f| f.code != "HARDCODED_SECRET_LITERAL")
        {
            hostile_note = true;
            risk_flags.push("BALLOT_INJECTION_ATTEMPT".to_string());
        }
    }
    let (scrubbed_note, scrub_flags) = scrub_high_entropy_and_secrets(raw_note_str, 180);
    for sf in scrub_flags {
        if !risk_flags.iter().any(|existing| existing == sf) {
            risk_flags.push(sf.to_string());
        }
    }

    // Mandatory Kernel Grounding Across ALL Categories (`Proposal 3A & 3B`)
    let (grounded, deny_code, target_bin_or_tool, canonical_shape) = match req
        .denial_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(did) if did.starts_with("dnl_") => {
            if let Some(rec) = ledger.lookup_denial_by_id(did) {
                (
                    true,
                    Some(rec.code.clone()),
                    rec.target_bin_or_tool.clone(),
                    rec.canonical_shape.clone(),
                )
            } else {
                risk_flags.push("UNGROUNDED_BALLOT_SUBMISSION".to_string());
                (
                    false,
                    None,
                    "ungrounded".to_string(),
                    format!("ungrounded:{reason_code}"),
                )
            }
        }
        Some(tid)
            if tid.starts_with("trc_")
                && matches!(
                    req.category,
                    FeedbackCategory::PaginationOrBudgetFriction
                        | FeedbackCategory::AdapterOrWorkflowBug
                )
                && ledger.lookup_trace_by_id(tid).is_some() =>
        {
            let tool = ledger
                .lookup_trace_by_id(tid)
                .map(str::to_string)
                .unwrap_or_else(|| "trace".to_string());
            (
                true,
                Some("TRACE_GROUNDED".to_string()),
                tool.clone(),
                // Shape derives from the ledger-recorded tool, never caller text, so one trace
                // cannot ground arbitrary clusters.
                format!("trace:{tool}"),
            )
        }
        _ => {
            risk_flags.push("UNGROUNDED_BALLOT_SUBMISSION".to_string());
            (
                false,
                None,
                "ungrounded".to_string(),
                format!("ungrounded:{reason_code}"),
            )
        }
    };

    if let Some(ref dc) = deny_code
        && is_ring0_constitutional_code(dc)
    {
        risk_flags.push("RING0_CONSTITUTIONAL_PROBE".to_string());
    }

    let session_tainted = ledger.tainted || ledger.halted;
    if session_tainted {
        risk_flags.push("TAINTED_SESSION_BALLOT_ATTEMPT".to_string());
    }

    let cluster_key = compute_cluster_key(
        req.category.as_str(),
        deny_code.as_deref(),
        &canonical_shape,
    );
    let (cluster_subs, total_subs) = ledger.record_ballot_submission(&cluster_key);
    ledger
        .save_locked(&canon_repo)
        .map_err(|e| FeedbackSubmitError::InvalidBallot(format!("failed saving ledger: {e}")))?;

    if cluster_subs >= 3 || total_subs >= 6 {
        risk_flags.push("AGENT_BALLOT_LOOP_ANOMALY".to_string());
    }

    let fb_key = load_or_init_global_feedback_key().map_err(FeedbackSubmitError::InvalidBallot)?;
    let common_repo = crate::resolve_common_repo_root(&canon_repo);
    let repo_id = sha256_hex(common_repo.to_string_lossy().as_bytes());
    let voter_payload = format!("{repo_id}:{}", ledger.root_session_id);
    let voter_tag = compute_domain_tag_for_feedback(
        fb_key.as_bytes(),
        FEEDBACK_VOTER_HMAC_DOMAIN,
        voter_payload.as_bytes(),
    )
    .map_err(FeedbackSubmitError::InvalidBallot)?;
    let voter_token = hex_encode(&voter_tag)[..24].to_string();

    let display_session_hash = compute_session_key_hash(&canon_repo, &sid)[..16].to_string();
    let ts_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let repo_day_bucket = format!("{}:{}", &repo_id[..12], utc_day_yyyymmdd(ts_unix));

    let quarantined = session_tainted || hostile_note;
    let commit_dir = feedback_state_dir().map_err(FeedbackSubmitError::InvalidBallot)?;
    ensure_nonsymlink_state_dir(&commit_dir).map_err(FeedbackSubmitError::InvalidBallot)?;
    // Held until return: serializes check-then-append so concurrent root-session submissions
    // cannot both observe "not yet voted" and double-count.
    let _commit_guard = ExclusiveFileLockGuard::acquire(&commit_dir.join("ballot_commit.lock"))
        .map_err(FeedbackSubmitError::InvalidBallot)?;
    let prior_root_vote = already_voted_in_spool(&voter_token, &cluster_key);
    let deduplicated_retry = cluster_subs > 1 || prior_root_vote;
    let vote_counted = !quarantined && grounded && !prior_root_vote;

    let ballot_seed = format!(
        "dotagent:ballot:v2:{repo_id}:{display_session_hash}:{cluster_key}:{total_subs}:{ts_unix}"
    );
    let ballot_id = format!("blt_{}", &sha256_hex(ballot_seed.as_bytes())[..16]);

    let mut rec = SignedBallotRecord {
        schema: "dotagent.feedback.ballot.v2".to_string(),
        ballot_id,
        cluster_key,
        category: req.category.as_str().to_string(),
        deny_code,
        target_bin_or_tool,
        canonical_shape,
        reason_code,
        scrubbed_note,
        repo_id: repo_id[..24].to_string(),
        repo_day_bucket,
        voter_token,
        display_session_hash,
        role: effective_role,
        task_id: effective_task_id,
        session_tainted,
        grounded,
        vote_counted,
        deduplicated_retry,
        quarantined,
        session_cluster_submissions: cluster_subs,
        session_total_submissions: total_subs,
        risk_flags,
        ts_unix,
        mac_hex: String::new(),
    };

    let mac_bytes = compute_domain_tag_for_feedback(
        fb_key.as_bytes(),
        FEEDBACK_BALLOT_HMAC_DOMAIN,
        &rec.canonical_mac_bytes(),
    )
    .map_err(FeedbackSubmitError::InvalidBallot)?;
    rec.mac_hex = hex_encode(&mac_bytes);

    let dir = feedback_state_dir().map_err(FeedbackSubmitError::InvalidBallot)?;
    // Ungrounded, tainted, or injection-quarantined ballots go to `quarantine.jsonl` so they can
    // never rotate valid grounded votes out of `ballots.jsonl`. Grounded untainted deduplicated
    // retries (capped at <= 8 per session) remain in `ballots.jsonl` for swarm thrash telemetry.
    let target_spool = if rec.quarantined || !rec.grounded || rec.session_tainted {
        dir.join("quarantine.jsonl")
    } else {
        dir.join("ballots.jsonl")
    };
    append_bounded_rotated_jsonl(
        &target_spool,
        &rec.to_json_value().to_json_string(),
        ExclusiveFileLockGuard::acquire,
        false,
    )
    .map_err(FeedbackSubmitError::InvalidBallot)?;

    let agentpi_ev = rec.to_agentpi_event_json();
    publish_agentpi_result(&agentpi_ev, sink);
    // The signed ballot journal already bounds the source fields of this projection.
    let _ = submit_record(Kind::Ballot, || {
        let mut projection = agentpi_ev.clone();
        if let JsonValue::Object(fields) = &mut projection {
            for (key, value) in fields {
                if key == "canonical_shape" {
                    *value = JsonValue::Str("[redacted]".into());
                } else if key == "target_bin_or_tool" {
                    *value = JsonValue::Str(
                        crate::telemetry::protocol::tool_class(value.as_str().unwrap_or("")).into(),
                    );
                }
            }
        }
        projection
    });
    Ok(agentpi_ev)
}

pub fn submit_friction_ballot_with_sink(
    repo_root: &Path,
    req: &BallotRequest,
    sink: EmitSink,
) -> Result<JsonValue, FeedbackSubmitError> {
    if std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() == Ok("1") {
        let resp = crate::coordinator::rpc_submit_friction_ballot(repo_root, &req.to_json_value())
            .map_err(|e| {
                if e.contains("FEEDBACK_RATE_LIMIT_EXCEEDED") {
                    FeedbackSubmitError::RateLimitExceeded(e)
                } else {
                    FeedbackSubmitError::InvalidBallot(e)
                }
            })?;
        let ev = resp.get("agentpi_event").cloned().ok_or_else(|| {
            FeedbackSubmitError::InvalidBallot("missing agentpi_event".to_string())
        })?;
        // The coordinator owns the local mirror of sandboxed ballot results.
        publish_agentpi_result(&ev, sink);
        return Ok(ev);
    }
    commit_ballot_on_host_redacted(repo_root, req, false, sink)
}

pub fn submit_friction_ballot(
    repo_root: &Path,
    req: &BallotRequest,
) -> Result<JsonValue, FeedbackSubmitError> {
    submit_friction_ballot_with_sink(repo_root, req, EmitSink::CliStdout)
}

pub fn compute_repo_id_prefix(repo_root: &Path) -> Result<String, String> {
    let meta = fs::symlink_metadata(repo_root).map_err(|e| {
        format!(
            "INVALID_BALLOT_REPO_ROOT: cannot stat '{}': {e}",
            repo_root.display()
        )
    })?;
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Err(format!(
            "INVALID_BALLOT_REPO_ROOT: '{}' must be a non-symlink directory",
            repo_root.display()
        ));
    }
    let canon = fs::canonicalize(repo_root)
        .map_err(|e| format!("failed canonicalizing '{}': {e}", repo_root.display()))?;
    let common_repo = crate::resolve_common_repo_root(&canon);
    let full_hash = sha256_hex(common_repo.to_string_lossy().as_bytes());
    Ok(full_hash[..24].to_string())
}

pub fn load_verified_ballots_for_repo(repo_root: &Path) -> Result<Vec<SignedBallotRecord>, String> {
    load_verified_ballots(repo_root)
}

pub fn load_verified_ballots(repo_root: &Path) -> Result<Vec<SignedBallotRecord>, String> {
    let expected_repo_id = compute_repo_id_prefix(repo_root)?;
    let dir = feedback_state_dir()?;
    let fb_key = load_or_init_global_feedback_key()?;
    let mut verified = Vec::new();
    // Read `.1` generation first so chronological order is preserved across 10 MiB rotations
    for path in [dir.join("ballots.jsonl.1"), dir.join("ballots.jsonl")] {
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            return Err(format!(
                "SPOOL_SYMLINK_REJECTED: '{}' is a symlink",
                path.display()
            ));
        }
        if !meta.file_type().is_file() {
            continue;
        }
        let mut opts = OpenOptions::new();
        opts.read(true);
        #[cfg(any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            target_os = "macos"
        ))]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(O_NOFOLLOW_FLAG);
        }
        let f = opts
            .open(&path)
            .map_err(|e| format!("failed opening '{}': {e}", path.display()))?;
        let reader = BufReader::new(f.take(MAX_SPOOL_FILE_BYTES + 4096));
        for (idx, line_res) in reader.lines().enumerate() {
            let line = line_res.map_err(|e| format!("read error at line {}: {e}", idx + 1))?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let val = JsonValue::parse(trimmed)
                .map_err(|e| format!("corrupt ballot JSON at line {}: {e}", idx + 1))?;
            let rec = SignedBallotRecord::from_json_value(&val)
                .map_err(|e| format!("invalid ballot schema at line {}: {e}", idx + 1))?;
            let expected_mac = compute_domain_tag_for_feedback(
                fb_key.as_bytes(),
                FEEDBACK_BALLOT_HMAC_DOMAIN,
                &rec.canonical_mac_bytes(),
            )?;
            let given_mac = hex_decode_bytes(&rec.mac_hex)?;
            if !constant_time_eq_bytes(&expected_mac, &given_mac) {
                return Err(format!(
                    "BALLOT_HMAC_VERIFICATION_FAILED: ballot '{}' at line {} failed MAC check",
                    rec.ballot_id,
                    idx + 1
                ));
            }
            if rec.repo_id != expected_repo_id {
                continue;
            }
            verified.push(rec);
        }
    }
    Ok(verified)
}

pub fn load_quarantined_ballot_counts_by_cluster() -> BTreeMap<String, usize> {
    let mut map = BTreeMap::new();
    let Ok(dir) = feedback_state_dir() else {
        return map;
    };
    let Ok(fb_key) = load_or_init_global_feedback_key() else {
        return map;
    };
    for path in [dir.join("quarantine.jsonl.1"), dir.join("quarantine.jsonl")] {
        let Some(f) = open_spool_nofollow(&path) else {
            continue;
        };
        let reader = BufReader::new(f.take(MAX_SPOOL_FILE_BYTES + 4096));
        for line in reader.lines().map_while(Result::ok) {
            if let Ok(val) = JsonValue::parse(line.trim())
                && let Ok(rec) = SignedBallotRecord::from_json_value(&val)
                && let Ok(exp) = compute_domain_tag_for_feedback(
                    fb_key.as_bytes(),
                    FEEDBACK_BALLOT_HMAC_DOMAIN,
                    &rec.canonical_mac_bytes(),
                )
                && let Ok(given) = hex_decode_bytes(&rec.mac_hex)
                && constant_time_eq_bytes(&exp, &given)
            {
                *map.entry(rec.cluster_key).or_insert(0) += 1;
            }
        }
    }
    map
}

pub fn aggregate_verified_clusters(
    ballots: &[SignedBallotRecord],
) -> Vec<AggregatedFrictionCluster> {
    let quarantine_counts = load_quarantined_ballot_counts_by_cluster();
    let mut by_key: BTreeMap<String, AggregatedFrictionCluster> = BTreeMap::new();
    let mut seen_voters: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut seen_buckets: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut loop_sessions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for b in ballots {
        let entry =
            by_key
                .entry(b.cluster_key.clone())
                .or_insert_with(|| AggregatedFrictionCluster {
                    cluster_key: b.cluster_key.clone(),
                    category: b.category.clone(),
                    deny_code: b.deny_code.clone(),
                    target_bin_or_tool: b.target_bin_or_tool.clone(),
                    canonical_shape: b.canonical_shape.clone(),
                    ring0_locked: b
                        .deny_code
                        .as_deref()
                        .is_some_and(is_ring0_constitutional_code),
                    unique_votes: 0,
                    voter_entries: Vec::new(),
                    distinct_repo_day_buckets: 0,
                    total_raw_submissions: 0,
                    max_single_agent_retries: 0,
                    tainted_attempts: *quarantine_counts.get(&b.cluster_key).unwrap_or(&0),
                    loop_anomaly_agents: 0,
                    scrubbed_notes: Vec::new(),
                    last_ts_unix: 0,
                });
        entry.total_raw_submissions += 1;
        if b.session_cluster_submissions > entry.max_single_agent_retries {
            entry.max_single_agent_retries = b.session_cluster_submissions;
        }
        if b.session_tainted {
            entry.tainted_attempts += 1;
        }
        if b.risk_flags
            .iter()
            .any(|rf| rf == "AGENT_BALLOT_LOOP_ANOMALY")
        {
            loop_sessions
                .entry(b.cluster_key.clone())
                .or_default()
                .insert(b.display_session_hash.clone());
        }
        if b.vote_counted
            && seen_voters
                .entry(b.cluster_key.clone())
                .or_default()
                .insert(b.voter_token.clone())
        {
            entry.unique_votes += 1;
            entry
                .voter_entries
                .push((b.voter_token.clone(), b.repo_day_bucket.clone()));
            seen_buckets
                .entry(b.cluster_key.clone())
                .or_default()
                .insert(b.repo_day_bucket.clone());
        }
        if !b.scrubbed_note.is_empty()
            && entry.scrubbed_notes.len() < 4
            && !entry.scrubbed_notes.contains(&b.scrubbed_note)
        {
            entry.scrubbed_notes.push(b.scrubbed_note.clone());
        }
        if b.ts_unix > entry.last_ts_unix {
            entry.last_ts_unix = b.ts_unix;
        }
    }

    let mut out: Vec<AggregatedFrictionCluster> = by_key
        .into_values()
        .map(|mut c| {
            c.distinct_repo_day_buckets = seen_buckets.get(&c.cluster_key).map_or(0, BTreeSet::len);
            c.loop_anomaly_agents = loop_sessions.get(&c.cluster_key).map_or(0, BTreeSet::len);
            c
        })
        .collect();
    out.sort_by(|a, b| {
        b.unique_votes
            .cmp(&a.unique_votes)
            .then_with(|| {
                b.distinct_repo_day_buckets
                    .cmp(&a.distinct_repo_day_buckets)
            })
            .then_with(|| b.total_raw_submissions.cmp(&a.total_raw_submissions))
            .then_with(|| a.cluster_key.cmp(&b.cluster_key))
    });
    out
}

pub fn run_feedback_cli(args: &[String], cwd: &Path) -> ExitCode {
    let sub = args.first().map(String::as_str).unwrap_or("--help");
    match sub {
        "submit" => run_feedback_submit_cli(&args[1..], cwd),
        "status" => crate::feedback_loop::run_feedback_status_cli(&args[1..], cwd),
        "sync-github" => crate::feedback_loop::run_feedback_sync_github_cli(&args[1..], cwd),
        "triage" => crate::telemetry::run_operator_feedback_triage_cli(&args[1..], cwd),
        "run-loop" => crate::feedback_loop::run_feedback_loop_cli(&args[1..], cwd),
        "--help" | "-h" | "help" => {
            println!(
                "Usage:\n  \
                   dotagent feedback submit --denial-id <dnl_hex|trc_hex> --category <false_positive_block|missing_safe_flag|pagination_or_budget_friction|unclear_remediation|adapter_or_workflow_bug> [--reason-code <token>] [--json]\n  \
                   dotagent feedback triage [--min-votes 2] [--sshsig <path>] [--json]\n  \
                   dotagent feedback status [--json]\n  \
                   dotagent feedback sync-github [--repo <owner/repo>] [--dry-run] [--json]\n  \
                   dotagent feedback run-loop [--repo <owner/repo>] [--min-votes 3] [--min-buckets 2] [--max-merges-per-run 1] [--dry-run]"
            );
            ExitCode::SUCCESS
        }
        other => {
            eprintln!(
                "[AGENT-GUARD HARD DENY :: UNKNOWN_SUBCOMMAND] unrecognized `dotagent feedback` subcommand '{other}'"
            );
            ExitCode::from(2)
        }
    }
}

fn run_feedback_submit_cli(args: &[String], cwd: &Path) -> ExitCode {
    let mut denial_id: Option<String> = None;
    let mut category_str: Option<String> = None;
    let mut reason_code: Option<String> = None;
    let mut note_stdin = false;
    let mut json_only = false;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--denial-id" if i + 1 < args.len() => {
                denial_id = Some(args[i + 1].clone());
                i += 2;
            }
            "--category" | "-c" if i + 1 < args.len() => {
                category_str = Some(args[i + 1].clone());
                i += 2;
            }
            "--reason-code" if i + 1 < args.len() => {
                reason_code = Some(args[i + 1].clone());
                i += 2;
            }
            "--note-stdin" => {
                note_stdin = true;
                i += 1;
            }
            "--json" => {
                json_only = true;
                i += 1;
            }
            other => {
                eprintln!(
                    "[AGENT-GUARD HARD DENY :: INVALID_FEEDBACK_BALLOT] unrecognized or disallowed CLI flag '{other}' (use `--denial-id <id> --category <cat> [--reason-code <token>]`)"
                );
                return ExitCode::from(2);
            }
        }
    }

    let Some(cat_raw) = category_str else {
        eprintln!(
            "[AGENT-GUARD HARD DENY :: INVALID_FEEDBACK_BALLOT] missing required `--category <false_positive_block|missing_safe_flag|pagination_or_budget_friction|unclear_remediation|adapter_or_workflow_bug>`"
        );
        return ExitCode::from(2);
    };
    let Some(category) = FeedbackCategory::parse(&cat_raw) else {
        eprintln!(
            "[AGENT-GUARD HARD DENY :: INVALID_FEEDBACK_BALLOT] unknown category '{cat_raw}'"
        );
        return ExitCode::from(2);
    };

    let note_ascii = if note_stdin {
        let mut buf = String::new();
        let _ = std::io::stdin().take(240).read_to_string(&mut buf);
        Some(buf)
    } else {
        None
    };

    let session_id =
        std::env::var("AGENT_GUARD_SESSION_ID").unwrap_or_else(|_| "default".to_string());
    let root_session_id = std::env::var("AGENT_GUARD_ROOT_SESSION_ID")
        .ok()
        .or_else(|| std::env::var("AGENT_GUARD_PARENT_SESSION_ID").ok());
    let role = std::env::var("AGENT_GUARD_ROLE").unwrap_or_else(|_| "coding-agent".to_string());
    let task_id = std::env::var("DOTAGENT_TASK_ID").ok();
    let repo_root = resolve_repo_root(cwd);

    let req = BallotRequest {
        denial_id,
        category,
        reason_code,
        note_ascii,
        session_id,
        root_session_id,
        role,
        task_id,
    };

    let sink = if json_only {
        EmitSink::Silent
    } else {
        EmitSink::CliStdout
    };
    match submit_friction_ballot_with_sink(&repo_root, &req, sink) {
        Ok(ev) => {
            if json_only {
                println!("{}", ev.to_json_string());
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            let code = err.guard_code().as_str();
            eprintln!("[AGENT-GUARD HARD DENY :: {code}] {}", err.message());
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod scrubber_tests {
    use super::*;

    #[test]
    fn scrubs_urls_auth_headers_and_home_paths() {
        let (out, _) = scrub_high_entropy_and_secrets(
            "fetch https://svc.internal/api?token=abc123 failed",
            240,
        );
        assert!(
            !out.contains("token=abc123"),
            "query-string URL leaked: {out}"
        );

        let (out, _) = scrub_high_entropy_and_secrets("Authorization: Bearer s3cr3tVal", 240);
        assert!(
            !out.contains("s3cr3tVal"),
            "bearer credential leaked: {out}"
        );

        let (out, _) = scrub_high_entropy_and_secrets("api_key=hunter2hunter2", 240);
        assert!(!out.contains("hunter2hunter2"), "api_key rhs leaked: {out}");

        let (out, _) = scrub_high_entropy_and_secrets("cannot read /home/alice/project/x.rs", 240);
        assert!(!out.contains("alice"), "home username leaked: {out}");
        assert!(out.contains("<HOME>"), "home prefix not normalized: {out}");

        // Exempt-looking shapes still get segment entropy screening.
        let (out, _) = scrub_high_entropy_and_secrets("--key=Zx9Qm2Lp7Rt4Wv8Ys3Nb6Hd1 flag", 240);
        assert!(
            !out.contains("Zx9Qm2Lp7Rt4Wv8Ys3Nb6Hd1"),
            "flag-embedded secret leaked: {out}"
        );
        let (out, _) = scrub_high_entropy_and_secrets("qzxwvkjhgfpmtbnrclsdyuae", 240);
        assert!(
            !out.contains("qzxwvkjhgfpmtbnrclsdyuae"),
            "lowercase secret leaked: {out}"
        );

        // Plain prose mentioning the word token is not over-redacted.
        let (out, _) = scrub_high_entropy_and_secrets("the token budget was exceeded", 240);
        assert!(out.contains("budget"), "prose over-redacted: {out}");
    }
}
