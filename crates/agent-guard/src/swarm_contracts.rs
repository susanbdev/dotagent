#![forbid(unsafe_code)]

//! Shared contracts, deterministic schemas, and length-delimited cryptographic
//! event encodings for `susanbdev/dotagent` Zero-Trust Swarm v2.

use crate::json::JsonValue;

/// Immutable cap on Adversarial Reviewer <-> Grunt iterations before automatic
/// escalation to `Master` / human (`F21` anti-infinite-loop invariant).
pub const MAX_ADVERSARIAL_ROUNDS: u8 = 2;

/// Deep read-only directory walk allowance granted exclusively to `Investigator`
/// inside validated repository boundaries (`F06` / Law 3 controlled lift).
pub const INVESTIGATOR_MAX_WALK_DEPTH: usize = 20;

/// Maximum pure-ASCII token budget for a single `Investigator` scout packet.
pub const MAX_INVESTIGATOR_PACKET_TOKENS: usize = 200;

/// Schema version for `AuthenticatedEvent` canonical MAC records.
pub const AUTH_EVENT_SCHEMA_V1: u16 = 1;

/// Domain-separation prefix for `AuthenticatedEvent` HMAC-SHA256 records (`F02`).
pub const AUTH_EVENT_DOMAIN_TAG: &[u8] = b"DOTAGENT_SWARM_V2_EVENT_V1";

/// Specialized swarm roles enforced by `agent-guard` and equipped by `swarm-tool`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SwarmRole {
    Master,
    Investigator,
    QaEngineer,
    Grunt,
    AdversarialReviewer,
    ForensicCoroner,
    StandardCoding,
}

impl SwarmRole {
    pub fn from_str_id(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "master" | "swarm-master" | "supervisor" => Some(Self::Master),
            "investigator" | "swarm-investigator" | "scout" => Some(Self::Investigator),
            "qa" | "qa-engineer" | "qa_engineer" | "swarm-qa-engineer" => Some(Self::QaEngineer),
            "grunt" | "swarm-grunt" | "executor" => Some(Self::Grunt),
            "reviewer"
            | "adversarial-reviewer"
            | "adversarial_reviewer"
            | "swarm-adversarial-reviewer" => Some(Self::AdversarialReviewer),
            "coroner" | "forensic-coroner" | "forensic_coroner" | "swarm-forensic-coroner" => {
                Some(Self::ForensicCoroner)
            }
            "standard" | "coding" | "coding-agent" | "" => Some(Self::StandardCoding),
            _ => None,
        }
    }

    pub fn as_str_id(self) -> &'static str {
        match self {
            Self::Master => "master",
            Self::Investigator => "investigator",
            Self::QaEngineer => "qa-engineer",
            Self::Grunt => "grunt",
            Self::AdversarialReviewer => "adversarial-reviewer",
            Self::ForensicCoroner => "forensic-coroner",
            Self::StandardCoding => "standard",
        }
    }

    pub fn skill_dir_name(self) -> Option<&'static str> {
        match self {
            Self::Master => Some("swarm-master"),
            Self::Investigator => Some("swarm-investigator"),
            Self::QaEngineer => Some("swarm-qa-engineer"),
            Self::Grunt => Some("swarm-grunt"),
            Self::AdversarialReviewer => Some("swarm-adversarial-reviewer"),
            Self::ForensicCoroner => Some("swarm-forensic-coroner"),
            Self::StandardCoding => None,
        }
    }

    pub fn all_swarm_roles() -> [Self; 6] {
        [
            Self::Master,
            Self::Investigator,
            Self::QaEngineer,
            Self::Grunt,
            Self::AdversarialReviewer,
            Self::ForensicCoroner,
        ]
    }
}

/// Explicit triggers requiring `Master` to halt automated delegation and ask the human.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscalationTrigger {
    AmbiguousRequirement { detail: String },
    ConflictingConstraints { detail: String },
    OutOfScopeBoundaryRequired { path: String, reason: String },
    RoundCapExceeded { task_id: String, rounds: u8 },
}

impl EscalationTrigger {
    pub fn code(&self) -> &'static str {
        match self {
            Self::AmbiguousRequirement { .. } => "AMBIGUOUS_REQUIREMENT",
            Self::ConflictingConstraints { .. } => "CONFLICTING_CONSTRAINTS",
            Self::OutOfScopeBoundaryRequired { .. } => "OUT_OF_SCOPE_BOUNDARY",
            Self::RoundCapExceeded { .. } => "ADVERSARIAL_ROUND_CAP_EXCEEDED",
        }
    }
}

/// Strictly typed worker-to-Master communication packets (`F10` fix: worker prose
/// cannot directly mutate `PLAN.lock.json` without an explicit human-approved amendment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerPacket {
    ObservedFact {
        session_id: String,
        task_id: String,
        claim: String,
        evidence_slices: Vec<String>,
    },
    WorkerHypothesis {
        session_id: String,
        task_id: String,
        missing_path: String,
        hypothesis: String,
    },
    PlanAmendmentProposal {
        session_id: String,
        task_id: String,
        proposed_change: String,
        justification: String,
    },
}

/// Domain risk classification used as a floor in QA coverage calculations (`F20`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainRisk {
    Standard,
    StatefulCore,
    SecurityCritical,
}

impl DomainRisk {
    pub fn from_str_id(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "security" | "security_critical" | "crypto" | "auth" | "guard" => {
                Self::SecurityCritical
            }
            "stateful" | "stateful_core" | "storage" | "concurrency" => Self::StatefulCore,
            _ => Self::Standard,
        }
    }

    pub fn coverage_floor_pct(self) -> u8 {
        match self {
            Self::SecurityCritical => 92,
            Self::StatefulCore => 80,
            Self::Standard => 50,
        }
    }
}

/// Task node inside a locked Swarm wave DAG (`PLAN.lock.json`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagTaskSpec {
    pub task_id: String,
    pub wave_id: String,
    pub depends_on: Vec<String>,
    pub domain_risk: DomainRisk,
    pub assigned_read_paths: Vec<String>,
    pub allowed_write_paths: Vec<String>,
    pub assigned_tests: Vec<String>,
}

/// Validated, SHA-256-pinned execution plan (`PLAN.lock.json`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedPlan {
    pub plan_id: String,
    pub plan_sha256: String,
    pub tasks: Vec<DagTaskSpec>,
}

/// Task-bound session capability minted by `swarm-tool master mint-session`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCapability {
    pub session_id: String,
    pub role: SwarmRole,
    pub task_id: String,
    pub attempt: u32,
    pub repo_sha256: String,
    pub plan_sha256: String,
    pub assigned_read_paths: Vec<String>,
    pub allowed_write_paths: Vec<String>,
    pub assigned_tests: Vec<String>,
    pub last_green_tree_oid: Option<String>,
    pub consecutive_test_failures: u32,
    pub blocked_scope_attempts: u32,
    pub malicious_flags: u32,
}

/// Operation tag recorded in `AuthenticatedEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventOp {
    SessionMint,
    FileRead,
    FileEdit,
    TestGreen,
    TestFail,
    LedgerSubmit,
}

impl EventOp {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SessionMint => "session_mint",
            Self::FileRead => "file_read",
            Self::FileEdit => "file_edit",
            Self::TestGreen => "test_green",
            Self::TestFail => "test_fail",
            Self::LedgerSubmit => "ledger_submit",
        }
    }

    pub fn from_str_id(s: &str) -> Option<Self> {
        match s {
            "session_mint" => Some(Self::SessionMint),
            "file_read" => Some(Self::FileRead),
            "file_edit" => Some(Self::FileEdit),
            "test_green" => Some(Self::TestGreen),
            "test_fail" => Some(Self::TestFail),
            "ledger_submit" => Some(Self::LedgerSubmit),
            _ => None,
        }
    }
}

/// Full-field length-delimited provenance event (`F02` fix: binds repo, plan,
/// session, task, sequence, prev MAC, operation, canonical relative path,
/// optional line range, and document SHA-256).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedEvent {
    pub schema_version: u16,
    pub repo_sha256: [u8; 32],
    pub plan_sha256: [u8; 32],
    pub session_id: String,
    pub task_id: String,
    pub seq_no: u64,
    pub prev_event_mac: [u8; 32],
    pub op: EventOp,
    pub canonical_rel_path: String,
    pub line_range: Option<(u64, u64)>,
    pub doc_sha256: [u8; 32],
}

impl AuthenticatedEvent {
    /// Deterministic, unambiguous length-prefixed binary encoding so no field
    /// boundary collision or identical-content path swap (`F02`) is possible.
    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        push_len_bytes(&mut buf, AUTH_EVENT_DOMAIN_TAG);
        buf.extend_from_slice(&self.schema_version.to_be_bytes());
        buf.extend_from_slice(&self.repo_sha256);
        buf.extend_from_slice(&self.plan_sha256);
        push_len_bytes(&mut buf, self.session_id.as_bytes());
        push_len_bytes(&mut buf, self.task_id.as_bytes());
        buf.extend_from_slice(&self.seq_no.to_be_bytes());
        buf.extend_from_slice(&self.prev_event_mac);
        push_len_bytes(&mut buf, self.op.as_str().as_bytes());
        push_len_bytes(&mut buf, self.canonical_rel_path.as_bytes());
        match self.line_range {
            Some((start, end)) => {
                buf.push(1);
                buf.extend_from_slice(&start.to_be_bytes());
                buf.extend_from_slice(&end.to_be_bytes());
            }
            None => {
                buf.push(0);
            }
        }
        buf.extend_from_slice(&self.doc_sha256);
        buf
    }
}

fn push_len_bytes(buf: &mut Vec<u8>, slice: &[u8]) {
    let len = u32::try_from(slice.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(slice);
}

/// Per-test fault attribution rule from `test_attribution.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestAttributionRule {
    pub test_name: String,
    pub primary_suspect: String,
    pub secondary_suspects: Vec<String>,
    pub boundary_interfaces: Vec<String>,
}

/// Deterministic QA fault-triangulation verdict (`F27`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuspectVerdict {
    SuspectIsolated {
        primary_suspect: String,
        failing_tests: Vec<String>,
    },
    BlockedByNeighbor {
        victim: String,
        neighbor_suspect: String,
        boundary_test: String,
    },
    SeamOrSpecConflict {
        task_a: String,
        task_b: String,
        boundary_test: String,
    },
    InconclusiveAskMaster {
        reason: String,
    },
}

/// Zero-LLM heuristic smell buckets (`W1.D`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SmellBucket {
    Malicious,
    OffTask,
    Confused,
    Risky,
}

impl SmellBucket {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malicious => "MALICIOUS",
            Self::OffTask => "OFF_TASK",
            Self::Confused => "CONFUSED",
            Self::Risky => "RISKY",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmellBadge {
    pub bucket: SmellBucket,
    pub signal: String,
}

/// Validated `2+2`-sentence pure-ASCII task completion receipt in `WORK_LEDGER.jsonl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkLedgerEntry {
    pub session_id: String,
    pub task_id: String,
    pub attempt: u32,
    pub git_tree_oid: String,
    pub event_ids: Vec<String>,
    pub what_changed: String,
    pub why_changed: String,
    pub smell_badges: Vec<SmellBadge>,
    pub record_mac_hex: String,
}

impl WorkLedgerEntry {
    pub fn to_json_value(&self) -> JsonValue {
        let badges = self
            .smell_badges
            .iter()
            .map(|b| JsonValue::Str(format!("{}:{}", b.bucket.as_str(), b.signal)))
            .collect();
        let events = self.event_ids.iter().cloned().map(JsonValue::Str).collect();
        JsonValue::Object(vec![
            (
                "session_id".to_string(),
                JsonValue::Str(self.session_id.clone()),
            ),
            ("task_id".to_string(), JsonValue::Str(self.task_id.clone())),
            (
                "attempt".to_string(),
                JsonValue::Number(f64::from(self.attempt)),
            ),
            (
                "git_tree_oid".to_string(),
                JsonValue::Str(self.git_tree_oid.clone()),
            ),
            ("event_ids".to_string(), JsonValue::Array(events)),
            (
                "what_changed".to_string(),
                JsonValue::Str(self.what_changed.clone()),
            ),
            (
                "why_changed".to_string(),
                JsonValue::Str(self.why_changed.clone()),
            ),
            ("smell_badges".to_string(), JsonValue::Array(badges)),
            (
                "record_mac".to_string(),
                JsonValue::Str(self.record_mac_hex.clone()),
            ),
        ])
    }
}

/// Outcome of `swarm-tool reviewer verdict` (`MAX_ADVERSARIAL_ROUNDS = 2` enforced).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewVerdictOutcome {
    Approved {
        task_id: String,
        round: u8,
    },
    RetryCleanSlate {
        task_id: String,
        round: u8,
        next_attempt: u32,
    },
    EscalateToMaster {
        trigger: EscalationTrigger,
    },
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

pub fn hex_decode_32(hex: &str) -> Result<[u8; 32], String> {
    let trimmed = hex.trim();
    if trimmed.len() != 64 {
        return Err(format!(
            "expected 64-char hex digest, got {} chars",
            trimmed.len()
        ));
    }
    let mut out = [0u8; 32];
    for (idx, slot) in out.iter_mut().enumerate() {
        let pair = &trimmed[idx * 2..idx * 2 + 2];
        *slot = u8::from_str_radix(pair, 16)
            .map_err(|_| format!("invalid hex byte '{pair}' at index {idx}"))?;
    }
    Ok(out)
}
