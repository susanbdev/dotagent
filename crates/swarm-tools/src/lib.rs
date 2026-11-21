#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! `swarm-tools` Library & Active Multi-Worktree DAG Wave Supervisor (`Pillar 1`).
//!
//! Provides:
//! 1. **Deterministic Topological Wave Scheduler**: Parses `swarm_v2.dag.json` (`waves`, `parallel`,
//!    `isolation_policy`, `recommended_model_tier`) and schedules waves outside LLM control.
//! 2. **True Parallel Capability Slots + Ephemeral Git Worktrees**: Keys capabilities by
//!    `(plan_id, task_id, attempt)` while provisioning RAII `git worktree add --detach` checkouts
//!    and isolated per-worker `CARGO_TARGET_DIR` directories.
//! 3. **Mechanical Worktree Reconciler & Coverage-Driven QA Triangulation**: Enforces strict
//!    `allowed_write_paths` subset invariants over `git status`/`git diff`, enforces wall-clock,
//!    token, and `MAX_ADVERSARIAL_ROUNDS = 2` retry caps, auto-hashes `doc_sha256` on `emit-fact`,
//!    ingests `cargo llvm-cov --json` & structured test reports, and performs conflict-free wave merges.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agent_guard::budget_guard::estimate_bpe_tokens;
use agent_guard::coordinator::rotate_vault_hmac_epoch;
use agent_guard::crypto::{constant_time_eq_bytes, hex_decode_32, sha256_bytes, sha256_hex};
use agent_guard::json::JsonValue;
use agent_guard::path_policy::{PathAccess, validate_path};
use agent_guard::qa_suspects::{
    compute_task_coverage_targets, parse_and_validate_dag_json, save_locked_plan,
};
use agent_guard::role_sandbox::{close_open_session, mint_session_capability};
use agent_guard::swarm_contracts::{
    DagTaskSpec, EscalationTrigger, LockedPlan, MAX_ADVERSARIAL_ROUNDS, SwarmRole,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelTierRoute {
    Frontier,
    Local7bOrMid,
}

impl ModelTierRoute {
    pub fn from_str_opt(raw: Option<&str>) -> Self {
        match raw
            .unwrap_or("frontier")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "local_7b_or_mid" | "mid" | "local" | "small" => Self::Local7bOrMid,
            _ => Self::Frontier,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Frontier => "frontier",
            Self::Local7bOrMid => "local_7b_or_mid",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DagIsolationPolicy {
    pub per_task_git_worktree: bool,
    pub private_cargo_target_dir: bool,
    pub enforce_observed_writes_subset: bool,
}

impl Default for DagIsolationPolicy {
    fn default() -> Self {
        Self {
            per_task_git_worktree: true,
            private_cargo_target_dir: true,
            enforce_observed_writes_subset: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScheduledWave {
    pub wave_id: String,
    pub parallel: bool,
    pub tasks: Vec<ScheduledTask>,
}

#[derive(Debug, Clone)]
pub struct ScheduledTask {
    pub spec: DagTaskSpec,
    pub model_tier: ModelTierRoute,
    pub required_coverage_pct: u8,
}

#[derive(Debug, Clone)]
pub struct SwarmDagExecutionPlan {
    pub locked_plan: LockedPlan,
    pub isolation: DagIsolationPolicy,
    pub waves: Vec<ScheduledWave>,
}

#[derive(Debug, Clone)]
pub struct WaveSupervisorConfig {
    pub worker_cmd: Option<String>,
    pub frontier_cmd: Option<String>,
    pub mid_cmd: Option<String>,
    pub test_cmd: Option<String>,
    pub reviewer_cmd: Option<String>,
    pub llvm_cov_json: Option<PathBuf>,
    pub task_timeout_ms: u64,
    pub max_task_tokens: usize,
    pub dry_run: bool,
    pub rotate_epoch: bool,
    pub allow_amend: bool,
}

impl Default for WaveSupervisorConfig {
    fn default() -> Self {
        Self {
            worker_cmd: None,
            frontier_cmd: None,
            mid_cmd: None,
            test_cmd: None,
            reviewer_cmd: None,
            llvm_cov_json: None,
            task_timeout_ms: 120_000,
            max_task_tokens: 16_000,
            dry_run: false,
            rotate_epoch: false,
            allow_amend: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TaskAttemptOutcome {
    pub task_id: String,
    pub wave_id: String,
    pub session_id: String,
    pub attempt: u32,
    pub model_tier: ModelTierRoute,
    pub modified_files: Vec<String>,
    pub output_tokens: usize,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone)]
pub struct WaveRunReport {
    pub plan_id: String,
    pub plan_sha256: String,
    pub epoch_id: Option<u64>,
    pub waves_completed: usize,
    pub tasks_completed: Vec<TaskAttemptOutcome>,
}

impl WaveRunReport {
    pub fn to_json_value(&self) -> JsonValue {
        let tasks_arr: Vec<JsonValue> = self
            .tasks_completed
            .iter()
            .map(|t| {
                JsonValue::Object(vec![
                    ("task_id".to_string(), JsonValue::Str(t.task_id.clone())),
                    ("wave_id".to_string(), JsonValue::Str(t.wave_id.clone())),
                    (
                        "session_id".to_string(),
                        JsonValue::Str(t.session_id.clone()),
                    ),
                    ("attempt".to_string(), JsonValue::Uint(u64::from(t.attempt))),
                    (
                        "model_tier".to_string(),
                        JsonValue::Str(t.model_tier.as_str().to_string()),
                    ),
                    (
                        "modified_files".to_string(),
                        JsonValue::Array(
                            t.modified_files
                                .iter()
                                .cloned()
                                .map(JsonValue::Str)
                                .collect(),
                        ),
                    ),
                    (
                        "output_tokens".to_string(),
                        JsonValue::Uint(t.output_tokens as u64),
                    ),
                    ("elapsed_ms".to_string(), JsonValue::Uint(t.elapsed_ms)),
                ])
            })
            .collect();

        JsonValue::Object(vec![
            (
                "status".to_string(),
                JsonValue::Str("SWARM_DAG_COMPLETED".to_string()),
            ),
            ("plan_id".to_string(), JsonValue::Str(self.plan_id.clone())),
            (
                "plan_sha256".to_string(),
                JsonValue::Str(self.plan_sha256.clone()),
            ),
            (
                "epoch_id".to_string(),
                self.epoch_id.map_or(JsonValue::Null, JsonValue::Uint),
            ),
            (
                "waves_completed".to_string(),
                JsonValue::Uint(self.waves_completed as u64),
            ),
            ("tasks".to_string(), JsonValue::Array(tasks_arr)),
        ])
    }
}

fn paths_overlap_or_prefix(a: &str, b: &str) -> bool {
    let na = a.trim_matches('/');
    let nb = b.trim_matches('/');
    if na.is_empty() || nb.is_empty() {
        return true;
    }
    na == nb || na.starts_with(&format!("{nb}/")) || nb.starts_with(&format!("{na}/"))
}

/// Parses and topologically validates a Swarm DAG JSON file into a wave-ordered execution schedule.
pub fn parse_swarm_dag_execution_plan(raw_json: &str) -> Result<SwarmDagExecutionPlan, String> {
    let locked_plan = parse_and_validate_dag_json(raw_json)?;
    let root = JsonValue::parse(raw_json).map_err(|e| format!("invalid DAG JSON: {e}"))?;

    let iso_obj = root.get("isolation_policy");
    let isolation = DagIsolationPolicy {
        per_task_git_worktree: iso_obj
            .and_then(|o| o.get("per_task_git_worktree"))
            .and_then(JsonValue::as_bool)
            .unwrap_or(true),
        private_cargo_target_dir: iso_obj
            .and_then(|o| o.get("private_cargo_target_dir"))
            .and_then(JsonValue::as_bool)
            .unwrap_or(true),
        enforce_observed_writes_subset: iso_obj
            .and_then(|o| o.get("enforce_observed_writes_subset"))
            .and_then(JsonValue::as_bool)
            .unwrap_or(true),
    };

    let cov_targets: BTreeMap<String, u8> = compute_task_coverage_targets(&locked_plan)
        .into_iter()
        .map(|t| (t.task_id, t.required_coverage_pct))
        .collect();

    let mut tier_by_task: BTreeMap<String, ModelTierRoute> = BTreeMap::new();
    let mut explicit_cov_by_task: BTreeMap<String, u8> = BTreeMap::new();
    if let Some(arr) = root.get("tasks").and_then(JsonValue::as_array) {
        for item in arr {
            if let Some(tid) = item
                .get("id")
                .or_else(|| item.get("task_id"))
                .and_then(JsonValue::as_str)
            {
                let tier = ModelTierRoute::from_str_opt(
                    item.get("recommended_model_tier")
                        .and_then(JsonValue::as_str),
                );
                tier_by_task.insert(tid.to_string(), tier);
                if let Some(mc) = item.get("min_coverage_pct").and_then(JsonValue::as_u64) {
                    explicit_cov_by_task.insert(tid.to_string(), (mc.min(100)) as u8);
                }
            }
        }
    }

    let task_by_id: BTreeMap<String, DagTaskSpec> = locked_plan
        .tasks
        .iter()
        .map(|t| (t.task_id.clone(), t.clone()))
        .collect();

    let mut wave_order: Vec<(String, bool, Vec<String>)> = Vec::new();
    if let Some(waves_arr) = root.get("waves").and_then(JsonValue::as_array) {
        for w in waves_arr {
            let wid = w
                .get("wave_id")
                .or_else(|| w.get("id"))
                .and_then(JsonValue::as_str)
                .unwrap_or("W0")
                .to_string();
            let parallel = w
                .get("parallel")
                .and_then(JsonValue::as_bool)
                .unwrap_or(false);
            let mut node_ids = Vec::new();
            if let Some(nodes) = w.get("nodes").and_then(JsonValue::as_array) {
                for n in nodes {
                    if let Some(s) = n.as_str() {
                        node_ids.push(s.to_string());
                    }
                }
            } else if let Some(wtasks) = w.get("tasks").and_then(JsonValue::as_array) {
                for t in wtasks {
                    if let Some(tid) = t
                        .get("id")
                        .or_else(|| t.get("task_id"))
                        .and_then(JsonValue::as_str)
                    {
                        node_ids.push(tid.to_string());
                    }
                }
            }
            if node_ids.is_empty() {
                for t in &locked_plan.tasks {
                    if t.wave_id == wid {
                        node_ids.push(t.task_id.clone());
                    }
                }
            }
            wave_order.push((wid, parallel, node_ids));
        }
    } else {
        let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for t in &locked_plan.tasks {
            grouped
                .entry(t.wave_id.clone())
                .or_default()
                .push(t.task_id.clone());
        }
        for (wid, ids) in grouped {
            let par = ids.len() > 1 && isolation.per_task_git_worktree;
            wave_order.push((wid, par, ids));
        }
    }

    let mut completed_before_task = BTreeSet::new();
    let mut scheduled_waves = Vec::with_capacity(wave_order.len());
    for (wid, parallel, node_ids) in wave_order {
        if parallel && node_ids.len() > 1 && !isolation.per_task_git_worktree {
            return Err(format!(
                "PARALLEL_WAVE_REQUIRES_WORKTREE_ISOLATION: parallel wave '{wid}' requires `isolation_policy.per_task_git_worktree = true`"
            ));
        }
        let mut wave_tasks = Vec::with_capacity(node_ids.len());
        let mut wave_write_owners: Vec<(String, String)> = Vec::new();

        for tid in &node_ids {
            let spec = task_by_id
                .get(tid)
                .ok_or_else(|| format!("wave '{wid}' references unknown task '{tid}'"))?
                .clone();
            for dep in &spec.depends_on {
                if !completed_before_task.contains(dep) {
                    return Err(format!(
                        "DAG_TOPOLOGY_VIOLATION: task '{tid}' in wave '{wid}' depends on '{dep}', which is not completed before '{tid}'"
                    ));
                }
            }
            if parallel {
                for wp in &spec.allowed_write_paths {
                    for (existing_wp, prev_owner) in &wave_write_owners {
                        if prev_owner != tid && paths_overlap_or_prefix(wp, existing_wp) {
                            return Err(format!(
                                "PARALLEL_WAVE_WRITE_CONFLICT: parallel wave '{wid}' tasks '{prev_owner}' ('{existing_wp}') and '{tid}' ('{wp}') have overlapping write scopes"
                            ));
                        }
                    }
                    wave_write_owners.push((wp.clone(), tid.clone()));
                }
            }
            let calc_cov = cov_targets.get(tid).copied().unwrap_or(50);
            let exp_cov = explicit_cov_by_task.get(tid).copied().unwrap_or(0);
            wave_tasks.push(ScheduledTask {
                spec,
                model_tier: tier_by_task
                    .get(tid)
                    .copied()
                    .unwrap_or(ModelTierRoute::Frontier),
                required_coverage_pct: calc_cov.max(exp_cov),
            });
            if !parallel {
                completed_before_task.insert(tid.clone());
            }
        }
        if parallel {
            for tid in node_ids {
                completed_before_task.insert(tid);
            }
        }
        scheduled_waves.push(ScheduledWave {
            wave_id: wid,
            parallel,
            tasks: wave_tasks,
        });
    }

    Ok(SwarmDagExecutionPlan {
        locked_plan,
        isolation,
        waves: scheduled_waves,
    })
}

/// Automatically validates in-repo evidence slice paths and computes on-disk SHA-256 digests
/// (`doc_sha256` / `doc_sha256_map`) for `swarm-tool investigator emit-fact`.
pub fn compute_and_verify_fact_doc_digests(
    repo_root: &Path,
    slices: &[String],
    explicit_doc: Option<&str>,
    expected_doc_sha256: Option<&str>,
) -> Result<(Option<String>, BTreeMap<String, String>), String> {
    let mut digests = BTreeMap::new();
    let mut primary_sha: Option<String> = None;

    if let Some(doc_raw) = explicit_doc {
        let valid = validate_path(repo_root, repo_root, doc_raw, PathAccess::Read)
            .map_err(|pv| format!("{}: {}", pv.code, pv.detail))?;
        let bytes = fs::read(&valid.canonical_or_norm)
            .map_err(|e| format!("cannot read '{}': {e}", valid.repo_rel))?;
        let actual_hex = sha256_hex(&bytes);
        primary_sha = Some(actual_hex.clone());
        digests.insert(valid.repo_rel, actual_hex);
    }

    for sl in slices {
        let p = sl.split(':').next().unwrap_or(sl.as_str());
        let valid = validate_path(repo_root, repo_root, p, PathAccess::Read)
            .map_err(|pv| format!("invalid evidence slice '{sl}': {}", pv.detail))?;
        if valid.canonical_or_norm.is_file() {
            let bytes = fs::read(&valid.canonical_or_norm)
                .map_err(|e| format!("cannot read slice '{}': {e}", valid.repo_rel))?;
            let hex = sha256_hex(&bytes);
            if primary_sha.is_none() {
                primary_sha = Some(hex.clone());
            }
            digests.insert(valid.repo_rel, hex);
        }
    }

    if let Some(exp) = expected_doc_sha256.filter(|s| !s.is_empty() && *s != "auto") {
        let exp_arr =
            hex_decode_32(exp).map_err(|e| format!("invalid --doc-sha256 hex '{exp}': {e}"))?;
        match &primary_sha {
            Some(actual_hex) => {
                let actual_arr = hex_decode_32(actual_hex)
                    .map_err(|e| format!("internal digest hex error: {e}"))?;
                if !constant_time_eq_bytes(&actual_arr, &exp_arr) {
                    return Err(format!(
                        "DOC_SHA256_MISMATCH: on-disk sha256 {actual_hex} != claimed {exp}"
                    ));
                }
            }
            None => {
                return Err(
                    "DOC_SHA256_UNBOUND: --doc-sha256 requires --doc <path> or a concrete file --slice"
                        .to_string(),
                );
            }
        }
    }

    Ok((primary_sha, digests))
}

/// Re-verifies any `doc_sha256_map` bound inside an `ObservedFact` packet against live files on disk.
pub fn verify_ingested_packet_doc_digests(
    repo_root: &Path,
    raw_packet_json: &str,
) -> Result<(), String> {
    let Ok(val) = JsonValue::parse(raw_packet_json) else {
        return Ok(());
    };
    let Some(JsonValue::Object(entries)) = val.get("doc_sha256_map") else {
        return Ok(());
    };
    for (rel_path, sha_val) in entries {
        let Some(claimed_hex) = sha_val.as_str() else {
            return Err(format!(
                "non-string sha256 for '{rel_path}' in doc_sha256_map"
            ));
        };
        let valid = validate_path(repo_root, repo_root, rel_path, PathAccess::Read)
            .map_err(|pv| format!("PACKET_DOC_PATH_INVALID: {}: {}", pv.code, pv.detail))?;
        let bytes = fs::read(&valid.canonical_or_norm)
            .map_err(|e| format!("PACKET_DOC_MISSING: cannot read '{}': {e}", valid.repo_rel))?;
        let actual_arr = sha256_bytes(&bytes);
        let exp_arr = hex_decode_32(claimed_hex)
            .map_err(|e| format!("PACKET_DOC_BAD_SHA256: '{rel_path}': {e}"))?;
        if !constant_time_eq_bytes(&actual_arr, &exp_arr) {
            return Err(format!(
                "PACKET_DOC_SHA256_MISMATCH: '{}' on-disk digest does not match packet claim '{}'",
                valid.repo_rel, claimed_hex
            ));
        }
    }
    Ok(())
}

/// Parses `cargo llvm-cov --json` output into per-file line coverage percentages (`0.0..=100.0`).
pub fn parse_llvm_cov_file_percentages(raw_json: &str) -> Result<BTreeMap<String, f64>, String> {
    let root = JsonValue::parse(raw_json).map_err(|e| format!("invalid llvm-cov JSON: {e}"))?;
    let mut map = BTreeMap::new();
    let Some(data_arr) = root.get("data").and_then(JsonValue::as_array) else {
        return Err("llvm-cov JSON missing top-level 'data' array".to_string());
    };
    for entry in data_arr {
        if let Some(files) = entry.get("files").and_then(JsonValue::as_array) {
            for f in files {
                let Some(fname) = f.get("filename").and_then(JsonValue::as_str) else {
                    continue;
                };
                let pct_opt = f.get("summary").and_then(|s| s.get("lines")).and_then(|l| {
                    l.get("percent").and_then(|p| match p {
                        JsonValue::Number(n) => Some(*n),
                        JsonValue::Uint(u) => Some(*u as f64),
                        JsonValue::Int(i) => Some(*i as f64),
                        _ => None,
                    })
                });
                if let Some(pct) = pct_opt {
                    map.insert(fname.to_string(), pct);
                }
            }
        }
    }
    Ok(map)
}

/// Enforces that every file in `target_files` meets or exceeds `required_pct` in `cov_map`.
pub fn verify_llvm_cov_meets_target(
    cov_map: &BTreeMap<String, f64>,
    target_files: &[String],
    required_pct: u8,
) -> Result<(), String> {
    let threshold = f64::from(required_pct);
    for target in target_files {
        let norm = target.trim_start_matches("./").replace('\\', "/");
        let suffix = format!("/{norm}");
        let found = cov_map
            .iter()
            .find(|(k, _)| {
                let nk = k.replace('\\', "/");
                nk == norm || nk.ends_with(&suffix)
            })
            .map(|(_, &pct)| pct);
        match found {
            Some(pct) if pct + 1e-6 >= threshold => {}
            Some(pct) => {
                return Err(format!(
                    "COVERAGE_BELOW_TARGET: file '{norm}' line coverage {pct:.2}% < required {required_pct}%"
                ));
            }
            None => {
                return Err(format!(
                    "COVERAGE_MISSING_FILE: file '{norm}' absent from llvm-cov report (required >= {required_pct}%)"
                ));
            }
        }
    }
    Ok(())
}

/// Parses either a structured test report JSON object (`{"failing":[...],"passing":[...]}`) or
/// Cargo/libtest JSON-lines (`{"type":"test","name":"...","event":"ok"|"failed"}`) into
/// `(failing_tests, passing_tests)`.
pub fn parse_structured_test_report(raw: &str) -> Result<(Vec<String>, Vec<String>), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    if let Ok(single) = JsonValue::parse(trimmed)
        && (single.get("failing").is_some() || single.get("passing").is_some())
    {
        let extract = |k: &str| -> Vec<String> {
            single
                .get(k)
                .and_then(JsonValue::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(JsonValue::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default()
        };
        return Ok((extract("failing"), extract("passing")));
    }

    let mut failing = Vec::new();
    let mut passing = Vec::new();
    for line in trimmed.lines() {
        let l = line.trim();
        if !l.starts_with('{') {
            continue;
        }
        let Ok(obj) = JsonValue::parse(l) else {
            continue;
        };
        if obj.get("type").and_then(JsonValue::as_str) == Some("test")
            && let Some(name) = obj.get("name").and_then(JsonValue::as_str)
        {
            match obj.get("event").and_then(JsonValue::as_str) {
                Some("failed") => failing.push(name.to_string()),
                Some("ok") => passing.push(name.to_string()),
                _ => {}
            }
        }
    }
    Ok((failing, passing))
}

static WORKTREE_GIT_LOCK: Mutex<()> = Mutex::new(());

const MAX_RECONCILE_FILE_BYTES: u64 = 4 * 1024 * 1024;

const ALLOWED_BASE_ENV_KEYS: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "TERM",
    "RUSTUP_HOME",
    "CARGO_HOME",
    "LLVM_PROFILE_FILE",
    "AGENT_GUARD_STATE_DIR",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
];

struct OpenSessionGuard<'a> {
    canon_repo: &'a Path,
    session_id: String,
}

impl<'a> OpenSessionGuard<'a> {
    fn new(canon_repo: &'a Path, session_id: String) -> Self {
        Self {
            canon_repo,
            session_id,
        }
    }
}

impl Drop for OpenSessionGuard<'_> {
    fn drop(&mut self) {
        let _ = close_open_session(self.canon_repo, Some(&self.session_id));
    }
}

fn resolve_git_common_dir(base_repo: &Path) -> Result<PathBuf, String> {
    let out = Command::new("git")
        .current_dir(base_repo)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(["rev-parse", "--git-common-dir"])
        .output()
        .map_err(|e| format!("failed invoking git rev-parse --git-common-dir: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git rev-parse --git-common-dir failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let p = Path::new(&raw);
    if p.is_absolute() {
        Ok(p.to_path_buf())
    } else {
        Ok(base_repo.join(p))
    }
}

fn ensure_common_git_exclude(base_repo: &Path) -> Result<(), String> {
    let _guard = WORKTREE_GIT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let common_dir = resolve_git_common_dir(base_repo)?;
    let info_dir = common_dir.join("info");
    fs::create_dir_all(&info_dir)
        .map_err(|e| format!("failed creating '{}': {e}", info_dir.display()))?;
    let exclude_path = info_dir.join("exclude");
    let existing = fs::read_to_string(&exclude_path).unwrap_or_default();
    let required = [
        "/.swarm-cargo-target/",
        "/target/swarm-worktrees/",
        "/target/swarm-targets/",
        "/.breadcrumbs.jsonl",
        ".breadcrumbs.jsonl",
        "/PLAN.lock.json",
        "/WORK_LEDGER.jsonl",
        ".env",
        ".env.*",
        ".env*",
        "*.pem",
        "*.key",
        "*.p12",
        "*.pfx",
        "*.kdbx",
        ".netrc",
        "audit.jsonl",
        "/tmp/",
        "/.tmp/",
        "/temp/",
        "/.temp/",
        "/.cache/",
        "/node_modules/",
        "/vendor/",
        "/.venv/",
    ];
    let mut updated = existing.clone();
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    let mut changed = false;
    for pat in required {
        if !existing.lines().any(|l| l.trim() == pat) {
            updated.push_str(pat);
            updated.push('\n');
            changed = true;
        }
    }
    if changed {
        fs::write(&exclude_path, updated)
            .map_err(|e| format!("failed updating '{}': {e}", exclude_path.display()))?;
    }
    Ok(())
}

/// Captures the base repository's tracked working tree (initial wave base) or strictly the
/// validated wave deltas (`explicit_deltas`) into an unreachable ephemeral git commit object
/// via a private `GIT_INDEX_FILE` inside `<git-common-dir>` without mutating `HEAD` or `.git/index`
/// and without ever staging untracked host `.env*` / secret files.
fn snapshot_repo_worktree_as_ephemeral_commit(
    base_repo: &Path,
    parent_oid_opt: Option<&str>,
    explicit_deltas: Option<&[String]>,
) -> Result<String, String> {
    let _guard = WORKTREE_GIT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let common_dir = resolve_git_common_dir(base_repo)?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temp_index = common_dir.join(format!(
        "swarm-ephemeral-index-{}-{nanos}",
        std::process::id()
    ));
    let _ = fs::remove_file(&temp_index);

    let effective_parent = match parent_oid_opt {
        Some(p) if !p.is_empty() => Some(p.to_string()),
        _ => {
            let head_out = Command::new("git")
                .current_dir(base_repo)
                .env("GIT_OPTIONAL_LOCKS", "0")
                .args(["rev-parse", "--verify", "HEAD"])
                .output()
                .ok();
            head_out.and_then(|o| {
                if o.status.success() {
                    let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if s.is_empty() { None } else { Some(s) }
                } else {
                    None
                }
            })
        }
    };

    let result = (|| -> Result<String, String> {
        if let Some(ref p_oid) = effective_parent {
            let rt_out = Command::new("git")
                .current_dir(base_repo)
                .env("GIT_INDEX_FILE", &temp_index)
                .env("GIT_OPTIONAL_LOCKS", "0")
                .args(["read-tree", p_oid])
                .output()
                .map_err(|e| format!("failed spawning git read-tree on ephemeral index: {e}"))?;
            if !rt_out.status.success() {
                return Err(format!(
                    "git read-tree on ephemeral index failed: {}",
                    String::from_utf8_lossy(&rt_out.stderr).trim()
                ));
            }
        }

        match explicit_deltas {
            None => {
                // Stage tracked modifications/deletions ONLY; never stage untracked host secrets!
                if effective_parent.is_some() {
                    let add_out = Command::new("git")
                        .current_dir(base_repo)
                        .env("GIT_INDEX_FILE", &temp_index)
                        .env("GIT_OPTIONAL_LOCKS", "0")
                        .args(["add", "-u"])
                        .output()
                        .map_err(|e| {
                            format!("failed spawning git add -u on ephemeral index: {e}")
                        })?;
                    if !add_out.status.success() {
                        return Err(format!(
                            "git add -u on ephemeral index failed: {}",
                            String::from_utf8_lossy(&add_out.stderr).trim()
                        ));
                    }
                }
            }
            Some(paths) => {
                let mut to_remove: Vec<&str> = Vec::new();
                let mut to_add: Vec<&str> = Vec::new();
                for rel in paths {
                    ensure_safe_rel_components_and_zero_symlinks(base_repo, rel)?;
                    validate_path(base_repo, base_repo, rel, PathAccess::Write).map_err(|v| {
                        format!(
                            "OBSERVED_WRITE_FORBIDDEN_PATH: ephemeral snapshot refused '{rel}': {}: {}",
                            v.code, v.detail
                        )
                    })?;
                    if base_repo.join(rel).is_file() {
                        to_add.push(rel.as_str());
                    } else {
                        to_remove.push(rel.as_str());
                    }
                }
                for rel in to_remove {
                    let rm_out = Command::new("git")
                        .current_dir(base_repo)
                        .env("GIT_INDEX_FILE", &temp_index)
                        .env("GIT_OPTIONAL_LOCKS", "0")
                        .args(["rm", "--cached", "--ignore-unmatch", "--", rel])
                        .output()
                        .map_err(|e| format!("failed removing '{rel}' on ephemeral index: {e}"))?;
                    if !rm_out.status.success() {
                        return Err(format!(
                            "git rm --cached '{rel}' on ephemeral index failed: {}",
                            String::from_utf8_lossy(&rm_out.stderr).trim()
                        ));
                    }
                }
                for rel in to_add {
                    let add_out = Command::new("git")
                        .current_dir(base_repo)
                        .env("GIT_INDEX_FILE", &temp_index)
                        .env("GIT_OPTIONAL_LOCKS", "0")
                        .args(["add", "-f", "--", rel])
                        .output()
                        .map_err(|e| format!("failed staging '{rel}' on ephemeral index: {e}"))?;
                    if !add_out.status.success() {
                        return Err(format!(
                            "git add '{rel}' on ephemeral index failed: {}",
                            String::from_utf8_lossy(&add_out.stderr).trim()
                        ));
                    }
                }
            }
        }

        let tree_out = Command::new("git")
            .current_dir(base_repo)
            .env("GIT_INDEX_FILE", &temp_index)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .arg("write-tree")
            .output()
            .map_err(|e| format!("failed spawning git write-tree: {e}"))?;
        if !tree_out.status.success() {
            return Err(format!(
                "git write-tree failed: {}",
                String::from_utf8_lossy(&tree_out.stderr).trim()
            ));
        }
        let tree_oid = String::from_utf8_lossy(&tree_out.stdout).trim().to_string();

        let mut ct = Command::new("git");
        ct.current_dir(base_repo)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_AUTHOR_NAME", "dotagent-swarm")
            .env("GIT_AUTHOR_EMAIL", "swarm@dotagent.local")
            .env("GIT_COMMITTER_NAME", "dotagent-swarm")
            .env("GIT_COMMITTER_EMAIL", "swarm@dotagent.local")
            .arg("commit-tree")
            .arg(&tree_oid);
        if let Some(ref p_oid) = effective_parent {
            ct.arg("-p").arg(p_oid);
        }
        ct.arg("-m").arg("dotagent-swarm-ephemeral-wave-base");
        let commit_out = ct
            .output()
            .map_err(|e| format!("failed spawning git commit-tree: {e}"))?;
        if !commit_out.status.success() {
            return Err(format!(
                "git commit-tree failed: {}",
                String::from_utf8_lossy(&commit_out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&commit_out.stdout)
            .trim()
            .to_string())
    })();

    let _ = fs::remove_file(&temp_index);
    result
}

fn prune_worktrees_once(base_repo: &Path) {
    let _guard = WORKTREE_GIT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _ = Command::new("git")
        .current_dir(base_repo)
        .args(["worktree", "prune"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

struct EphemeralWorktreeGuard {
    base_repo: PathBuf,
    worktree_dir: PathBuf,
}

impl EphemeralWorktreeGuard {
    fn provision(
        base_repo: &Path,
        plan_slug: &str,
        slot_slug: &str,
        base_oid: &str,
    ) -> Result<Self, String> {
        let _guard = WORKTREE_GIT_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let wt_root = base_repo
            .join("target")
            .join("swarm-worktrees")
            .join(plan_slug);
        fs::create_dir_all(&wt_root).map_err(|e| {
            format!(
                "failed creating worktree parent '{}': {e}",
                wt_root.display()
            )
        })?;
        let wt_dir = wt_root.join(slot_slug);
        if wt_dir.exists() {
            let _ = Command::new("git")
                .current_dir(base_repo)
                .args(["worktree", "remove", "--force"])
                .arg(&wt_dir)
                .output();
            let _ = fs::remove_dir_all(&wt_dir);
        }
        let out = Command::new("git")
            .current_dir(base_repo)
            .args(["worktree", "add", "--detach"])
            .arg(&wt_dir)
            .arg(base_oid)
            .output()
            .map_err(|e| format!("failed spawning git worktree add: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git worktree add failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(Self {
            base_repo: base_repo.to_path_buf(),
            worktree_dir: wt_dir,
        })
    }
}

impl Drop for EphemeralWorktreeGuard {
    fn drop(&mut self) {
        let _guard = WORKTREE_GIT_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = Command::new("git")
            .current_dir(&self.base_repo)
            .args(["worktree", "remove", "--force"])
            .arg(&self.worktree_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = fs::remove_dir_all(&self.worktree_dir);
    }
}

fn sanitize_slug(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn ensure_safe_rel_components_and_zero_symlinks(
    root_dir: &Path,
    rel_path: &str,
) -> Result<(), String> {
    if rel_path.is_empty()
        || rel_path.starts_with('/')
        || rel_path.contains('\\')
        || rel_path.bytes().any(|b| b < 0x20 || b == 0x7f)
    {
        return Err(format!(
            "OBSERVED_WRITE_FORBIDDEN_PATH: invalid relative path '{rel_path}'"
        ));
    }
    let mut cur = root_dir.to_path_buf();
    for comp in Path::new(rel_path).components() {
        match comp {
            Component::Normal(seg) => {
                cur.push(seg);
                if let Ok(meta) = fs::symlink_metadata(&cur)
                    && meta.file_type().is_symlink()
                {
                    return Err(format!(
                        "OBSERVED_SYMLINK_FORBIDDEN: symlink detected at '{}' under '{}'",
                        rel_path,
                        root_dir.display()
                    ));
                }
            }
            _ => {
                return Err(format!(
                    "OBSERVED_WRITE_FORBIDDEN_PATH: non-normal path component in '{rel_path}'"
                ));
            }
        }
    }
    Ok(())
}

fn parse_porcelain_v1_z_paths(raw: &[u8]) -> Result<BTreeSet<String>, String> {
    let mut observed = BTreeSet::new();
    let mut fields = raw.split(|&b| b == 0);
    while let Some(entry) = fields.next() {
        if entry.is_empty() {
            continue;
        }
        if entry.len() < 4 || entry[2] != b' ' {
            return Err("git status --porcelain=v1 -z emitted malformed record".to_string());
        }
        let x = entry[0];
        let path_bytes = &entry[3..];
        let path_str = std::str::from_utf8(path_bytes).map_err(|_| {
            "OBSERVED_WRITE_FORBIDDEN_PATH: non-UTF-8 filename in worktree".to_string()
        })?;
        if !path_str.is_empty() {
            observed.insert(path_str.to_string());
        }
        if x == b'R' || x == b'C' {
            if let Some(orig_bytes) = fields.next()
                && !orig_bytes.is_empty()
            {
                let orig_str = std::str::from_utf8(orig_bytes).map_err(|_| {
                    "OBSERVED_WRITE_FORBIDDEN_PATH: non-UTF-8 rename source in worktree".to_string()
                })?;
                observed.insert(orig_str.to_string());
            }
        }
    }
    Ok(observed)
}

/// Verifies that every modified/untracked/deleted path in `worktree_dir` has zero symlinks,
/// passes `agent_guard::path_policy::validate_path(..., PathAccess::Write)`, and is a strict
/// subset of `allowed_write_paths` (when `enforce_subset` is true), returning the sorted paths.
pub fn verify_worktree_diff_subset(
    worktree_dir: &Path,
    allowed_write_paths: &[String],
) -> Result<Vec<String>, String> {
    let (paths, _) = collect_and_verify_worktree_deltas(worktree_dir, allowed_write_paths, true)?;
    Ok(paths)
}

type FileSnapshotList = Vec<(String, Option<Vec<u8>>)>;

struct AttemptStageSuccess {
    session_id: String,
    modified_files: Vec<String>,
    snapshots: FileSnapshotList,
    output_tokens: usize,
}

fn collect_and_verify_worktree_deltas(
    worktree_dir: &Path,
    allowed_write_paths: &[String],
    enforce_subset: bool,
) -> Result<(Vec<String>, FileSnapshotList), String> {
    let out = Command::new("git")
        .current_dir(worktree_dir)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(["status", "--porcelain=v1", "-z", "-uall"])
        .output()
        .map_err(|e| format!("failed inspecting worktree status: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git status failed in worktree: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    let observed = parse_porcelain_v1_z_paths(&out.stdout)?;
    let mut paths = Vec::with_capacity(observed.len());
    let mut snapshots = Vec::with_capacity(observed.len());

    for path in observed {
        ensure_safe_rel_components_and_zero_symlinks(worktree_dir, &path)?;
        validate_path(worktree_dir, worktree_dir, &path, PathAccess::Write)
            .map_err(|v| format!("OBSERVED_WRITE_FORBIDDEN_PATH: {}: {}", v.code, v.detail))?;

        if enforce_subset {
            let permitted = allowed_write_paths.iter().any(|allow| {
                let norm = allow.trim_matches('/');
                path == norm || path.starts_with(&format!("{norm}/"))
            });
            if !permitted {
                return Err(format!(
                    "OBSERVED_WRITE_OUTSIDE_SCOPE: worker modified '{path}', which is outside allowed_write_paths {:?}",
                    allowed_write_paths
                ));
            }
        }

        let full = worktree_dir.join(&path);
        match fs::symlink_metadata(&full) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(format!(
                        "OBSERVED_SYMLINK_FORBIDDEN: worker created symlink '{path}'"
                    ));
                }
                if !meta.file_type().is_file() {
                    return Err(format!(
                        "OBSERVED_WRITE_FORBIDDEN_PATH: non-regular file entry '{path}'"
                    ));
                }
                if meta.len() > MAX_RECONCILE_FILE_BYTES {
                    return Err(format!(
                        "OBSERVED_WRITE_FORBIDDEN_PATH: file '{path}' exceeds {} byte ceiling",
                        MAX_RECONCILE_FILE_BYTES
                    ));
                }
                let bytes =
                    fs::read(&full).map_err(|e| format!("failed snapshotting '{path}': {e}"))?;
                snapshots.push((path.clone(), Some(bytes)));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                snapshots.push((path.clone(), None));
            }
            Err(e) => {
                return Err(format!("failed statting '{path}': {e}"));
            }
        }
        paths.push(path);
    }

    Ok((paths, snapshots))
}

fn is_trusted_bin_candidate(p: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(p) else {
        return false;
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn resolve_sibling_agent_guard_bin() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("DOTAGENT_AGENT_GUARD_BIN") {
        let p = PathBuf::from(explicit.trim());
        if is_trusted_bin_candidate(&p) {
            return Some(p);
        }
    }
    let bin_name = if cfg!(windows) {
        "agent-guard.exe"
    } else {
        "agent-guard"
    };
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let direct = dir.join(bin_name);
        if is_trusted_bin_candidate(&direct) {
            return Some(direct);
        }
        for anc in dir.ancestors().skip(1).take(5) {
            if (anc.join("deps").is_dir() || anc.join("build").is_dir())
                && is_trusted_bin_candidate(&anc.join(bin_name))
            {
                return Some(anc.join(bin_name));
            }
        }
    }
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let cand = dir.join(bin_name);
            if is_trusted_bin_candidate(&cand) {
                return Some(cand);
            }
        }
    }
    None
}

fn drain_pipe_capped<R: Read>(mut reader: R, cap: usize) -> Vec<u8> {
    let mut kept = Vec::with_capacity(cap.min(8_192));
    let _ = (&mut reader).take(cap as u64).read_to_end(&mut kept);
    let _ = std::io::copy(&mut reader, &mut std::io::sink());
    kept
}

fn kill_process_group_best_effort(pid: u32) {
    #[cfg(unix)]
    {
        if pid > 1 {
            let neg_pgid = format!("-{pid}");
            for bin in ["/bin/kill", "/usr/bin/kill"] {
                if Path::new(bin).is_file() {
                    let _ = Command::new(bin)
                        .args(["-s", "KILL", &neg_pgid])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                    break;
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
    }
}

fn exit_status_to_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        if let Some(sig) = status.signal() {
            return 128 + (sig & 0x7f);
        }
    }
    1
}

fn execute_command_with_wallclock_cap(
    cmd_str: &str,
    cwd: &Path,
    envs: &[(&str, String)],
    timeout_ms: u64,
) -> Result<(i32, String), String> {
    let Some(ag_bin) = resolve_sibling_agent_guard_bin() else {
        return Err(
            "SWARM_SANDBOX_BINARY_MISSING: trusted 'agent-guard' binary not found alongside current executable, in DOTAGENT_AGENT_GUARD_BIN, or on PATH; refusing unsandboxed worker execution"
                .to_string(),
        );
    };
    let mut cmd = Command::new(ag_bin);
    cmd.arg("exec-sandbox")
        .arg("--deny-net")
        .arg("--cwd")
        .arg(cwd)
        .arg("--")
        .arg(cmd_str);

    #[cfg(unix)]
    cmd.process_group(0);

    cmd.current_dir(cwd)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for &key in ALLOWED_BASE_ENV_KEYS {
        if let Ok(val) = std::env::var(key) {
            cmd.env(key, val);
        }
    }
    cmd.env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PIP_NO_CACHE_DIR", "1")
        .env("NPM_CONFIG_IGNORE_SCRIPTS", "true")
        .env("PAGER", "cat")
        .env("GIT_PAGER", "cat");

    for (k, v) in envs {
        cmd.env(k, v);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed spawning worker command: {e}"))?;
    let child_pid = child.id();

    let stdout_handle = child
        .stdout
        .take()
        .map(|out| std::thread::spawn(move || drain_pipe_capped(out, 65_536)));
    let stderr_handle = child
        .stderr
        .take()
        .map(|err| std::thread::spawn(move || drain_pipe_capped(err, 65_536)));

    let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(50));
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if Instant::now() >= deadline {
                    kill_process_group_best_effort(child_pid);
                    let _ = child.kill();
                    let _ = child.wait();
                    if let Some(h) = stdout_handle {
                        let _ = h.join();
                    }
                    if let Some(h) = stderr_handle {
                        let _ = h.join();
                    }
                    return Err(format!(
                        "TASK_WALLCLOCK_TIMEOUT_EXCEEDED: worker exceeded {timeout_ms} ms deadline"
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                kill_process_group_best_effort(child_pid);
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("failed polling worker process: {e}"));
            }
        }
    };

    let mut combined = stdout_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    let err_bytes = stderr_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    if !err_bytes.is_empty() {
        if !combined.is_empty() && !combined.ends_with(b"\n") {
            combined.push(b'\n');
        }
        combined.extend_from_slice(&err_bytes);
    }

    Ok((
        exit_status_to_code(status),
        String::from_utf8_lossy(&combined).into_owned(),
    ))
}

#[derive(Debug)]
struct StagedTaskResult {
    outcome: TaskAttemptOutcome,
    file_snapshots: Vec<(String, Option<Vec<u8>>)>,
}

/// Active deterministic Rust Wave Supervisor (`dotagent swarm run <dag.json>`).
pub fn run_swarm_dag_supervisor(
    repo_root: &Path,
    raw_dag_json: &str,
    cfg: &WaveSupervisorConfig,
) -> Result<WaveRunReport, String> {
    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let epoch_id = if cfg.rotate_epoch && !cfg.dry_run {
        Some(rotate_vault_hmac_epoch(&canon_repo)?)
    } else {
        None
    };

    let exec_plan = parse_swarm_dag_execution_plan(raw_dag_json)?;
    if !cfg.dry_run {
        let _ = save_locked_plan(&canon_repo, &exec_plan.locked_plan, cfg.allow_amend)?;
        ensure_common_git_exclude(&canon_repo)?;
    }

    let plan_slug = sanitize_slug(&exec_plan.locked_plan.plan_id);
    let mut completed_outcomes = Vec::new();
    let mut current_base_oid = if !cfg.dry_run && exec_plan.isolation.per_task_git_worktree {
        Some(snapshot_repo_worktree_as_ephemeral_commit(
            &canon_repo,
            None,
            None,
        )?)
    } else {
        None
    };

    for wave in &exec_plan.waves {
        if cfg.dry_run {
            for t in &wave.tasks {
                completed_outcomes.push(TaskAttemptOutcome {
                    task_id: t.spec.task_id.clone(),
                    wave_id: wave.wave_id.clone(),
                    session_id: format!("dryrun_{}", sanitize_slug(&t.spec.task_id)),
                    attempt: 1,
                    model_tier: t.model_tier,
                    modified_files: Vec::new(),
                    output_tokens: 0,
                    elapsed_ms: 0,
                });
            }
            continue;
        }

        if wave.parallel && wave.tasks.len() > 1 {
            let base_oid_str = current_base_oid.as_deref().unwrap_or("HEAD");
            let staged: Vec<StagedTaskResult> = std::thread::scope(|s| {
                let mut handles = Vec::with_capacity(wave.tasks.len());
                for task in &wave.tasks {
                    let repo_ref = &canon_repo;
                    let p_slug = plan_slug.as_str();
                    let iso = exec_plan.isolation;
                    handles.push(s.spawn(move || {
                        execute_single_task_with_retry_cap(
                            repo_ref,
                            p_slug,
                            &wave.wave_id,
                            task,
                            iso,
                            base_oid_str,
                            cfg,
                        )
                    }));
                }
                let mut collected = Vec::with_capacity(handles.len());
                for h in handles {
                    let res = h
                        .join()
                        .map_err(|_| "worker supervisor thread panicked".to_string())??;
                    collected.push(res);
                }
                Ok::<Vec<StagedTaskResult>, String>(collected)
            })?;

            reconcile_disjoint_wave_deltas(&canon_repo, &wave.wave_id, &staged)?;
            prune_worktrees_once(&canon_repo);
            if exec_plan.isolation.per_task_git_worktree {
                let wave_deltas: Vec<String> = staged
                    .iter()
                    .flat_map(|it| it.outcome.modified_files.iter().cloned())
                    .collect();
                current_base_oid = Some(snapshot_repo_worktree_as_ephemeral_commit(
                    &canon_repo,
                    current_base_oid.as_deref(),
                    Some(&wave_deltas),
                )?);
            }
            for item in staged {
                completed_outcomes.push(item.outcome);
            }
        } else {
            for task in &wave.tasks {
                let base_oid_str = current_base_oid.as_deref().unwrap_or("HEAD");
                let staged_single = execute_single_task_with_retry_cap(
                    &canon_repo,
                    &plan_slug,
                    &wave.wave_id,
                    task,
                    exec_plan.isolation,
                    base_oid_str,
                    cfg,
                )?;
                if exec_plan.isolation.per_task_git_worktree {
                    reconcile_disjoint_wave_deltas(
                        &canon_repo,
                        &wave.wave_id,
                        std::slice::from_ref(&staged_single),
                    )?;
                    prune_worktrees_once(&canon_repo);
                    current_base_oid = Some(snapshot_repo_worktree_as_ephemeral_commit(
                        &canon_repo,
                        current_base_oid.as_deref(),
                        Some(&staged_single.outcome.modified_files),
                    )?);
                }
                completed_outcomes.push(staged_single.outcome);
            }
        }
    }

    if !cfg.dry_run && exec_plan.isolation.per_task_git_worktree {
        prune_worktrees_once(&canon_repo);
    }

    Ok(WaveRunReport {
        plan_id: exec_plan.locked_plan.plan_id,
        plan_sha256: exec_plan.locked_plan.plan_sha256,
        epoch_id,
        waves_completed: exec_plan.waves.len(),
        tasks_completed: completed_outcomes,
    })
}

fn precreate_allowed_write_subdirs(exec_dir: &Path, allowed_write_paths: &[String]) {
    for raw in allowed_write_paths {
        let clean = raw.trim_matches('/');
        if clean.is_empty() {
            continue;
        }
        if validate_path(exec_dir, exec_dir, clean, PathAccess::Write).is_ok() {
            let target = exec_dir.join(clean);
            if raw.ends_with('/') {
                let _ = fs::create_dir_all(&target);
            } else if let Some(parent) = target.parent()
                && parent != exec_dir
            {
                let _ = fs::create_dir_all(parent);
            }
        }
    }
}

fn execute_single_task_with_retry_cap(
    canon_repo: &Path,
    plan_slug: &str,
    wave_id: &str,
    task: &ScheduledTask,
    isolation: DagIsolationPolicy,
    base_oid: &str,
    cfg: &WaveSupervisorConfig,
) -> Result<StagedTaskResult, String> {
    let max_rounds = u32::from(MAX_ADVERSARIAL_ROUNDS);
    let mut last_err = String::new();

    for attempt in 1..=max_rounds {
        let started = Instant::now();
        let slot_slug = format!("{}_a{}", sanitize_slug(&task.spec.task_id), attempt);

        let wt_opt = if isolation.per_task_git_worktree {
            Some(EphemeralWorktreeGuard::provision(
                canon_repo, plan_slug, &slot_slug, base_oid,
            )?)
        } else {
            None
        };
        let exec_dir = wt_opt
            .as_ref()
            .map_or(canon_repo, |g| g.worktree_dir.as_path());

        precreate_allowed_write_subdirs(exec_dir, &task.spec.allowed_write_paths);

        let cargo_target_dir = if isolation.private_cargo_target_dir {
            let tdir = if isolation.per_task_git_worktree {
                exec_dir.join(".swarm-cargo-target")
            } else {
                canon_repo
                    .join(".swarm-cargo-target")
                    .join(plan_slug)
                    .join(&slot_slug)
            };
            let _ = fs::create_dir_all(&tdir);
            Some(tdir)
        } else {
            None
        };

        let routed_cmd = match task.model_tier {
            ModelTierRoute::Frontier => cfg.frontier_cmd.as_ref().or(cfg.worker_cmd.as_ref()),
            ModelTierRoute::Local7bOrMid => cfg.mid_cmd.as_ref().or(cfg.worker_cmd.as_ref()),
        };

        let build_stage_env = |role_name: &str, session_id: &str| -> Vec<(&'static str, String)> {
            let mut pairs = vec![
                ("AGENT_GUARD_ROLE", role_name.to_string()),
                ("AGENT_GUARD_SESSION_ID", session_id.to_string()),
                ("DOTAGENT_TASK_ID", task.spec.task_id.clone()),
                ("DOTAGENT_WAVE_ID", wave_id.to_string()),
                ("DOTAGENT_ATTEMPT", attempt.to_string()),
                ("DOTAGENT_MODEL_TIER", task.model_tier.as_str().to_string()),
                (
                    "DOTAGENT_REQUIRED_COVERAGE_PCT",
                    task.required_coverage_pct.to_string(),
                ),
            ];
            if let Some(ref ctd) = cargo_target_dir {
                pairs.push(("CARGO_TARGET_DIR", ctd.to_string_lossy().into_owned()));
            }
            pairs
        };

        let attempt_res = (|| -> Result<AttemptStageSuccess, String> {
            let grunt_cap =
                mint_session_capability(canon_repo, SwarmRole::Grunt, &task.spec.task_id, attempt)?;
            let grunt_session_id = grunt_cap.session_id.clone();
            let mut out_tokens = 0usize;
            {
                let _grunt_guard = OpenSessionGuard::new(canon_repo, grunt_cap.session_id.clone());
                let env_pairs = build_stage_env("grunt", &grunt_cap.session_id);
                if let Some(cmd_str) = routed_cmd {
                    let (code, output) = execute_command_with_wallclock_cap(
                        cmd_str,
                        exec_dir,
                        &env_pairs,
                        cfg.task_timeout_ms,
                    )?;
                    out_tokens = estimate_bpe_tokens(&output);
                    if out_tokens > cfg.max_task_tokens {
                        return Err(format!(
                            "TASK_TOKEN_CAP_EXCEEDED: task '{}' emitted {} tokens (> {} cap)",
                            task.spec.task_id, out_tokens, cfg.max_task_tokens
                        ));
                    }
                    if code != 0 {
                        return Err(format!(
                            "worker command exited {code} on task '{}': {}",
                            task.spec.task_id,
                            output.trim()
                        ));
                    }
                }
            }

            // Verify worker writes immediately before running QA or Reviewer stages.
            let _ = collect_and_verify_worktree_deltas(
                exec_dir,
                &task.spec.allowed_write_paths,
                isolation.enforce_observed_writes_subset,
            )?;

            if let Some(ref test_cmd) = cfg.test_cmd {
                let qa_cap = mint_session_capability(
                    canon_repo,
                    SwarmRole::QaEngineer,
                    &task.spec.task_id,
                    attempt,
                )?;
                let _qa_guard = OpenSessionGuard::new(canon_repo, qa_cap.session_id.clone());
                let qa_env = build_stage_env("qa_engineer", &qa_cap.session_id);
                let (tcode, tout) = execute_command_with_wallclock_cap(
                    test_cmd,
                    exec_dir,
                    &qa_env,
                    cfg.task_timeout_ms,
                )?;
                if tcode != 0 {
                    return Err(format!(
                        "QA test gate failed ({tcode}) on task '{}': {}",
                        task.spec.task_id,
                        tout.trim()
                    ));
                }
            }

            if let Some(ref rev_cmd) = cfg.reviewer_cmd {
                let rev_cap = mint_session_capability(
                    canon_repo,
                    SwarmRole::AdversarialReviewer,
                    &task.spec.task_id,
                    attempt,
                )?;
                let _rev_guard = OpenSessionGuard::new(canon_repo, rev_cap.session_id.clone());
                let rev_env = build_stage_env("adversarial_reviewer", &rev_cap.session_id);
                let (rcode, rout) = execute_command_with_wallclock_cap(
                    rev_cmd,
                    exec_dir,
                    &rev_env,
                    cfg.task_timeout_ms,
                )?;
                if rcode != 0 {
                    return Err(format!(
                        "adversarial reviewer rejected attempt {attempt} on task '{}': {}",
                        task.spec.task_id,
                        rout.trim()
                    ));
                }
            }

            let (modified, snapshots) = collect_and_verify_worktree_deltas(
                exec_dir,
                &task.spec.allowed_write_paths,
                isolation.enforce_observed_writes_subset,
            )?;

            if let Some(ref cov_path) = cfg.llvm_cov_json {
                let resolved_cov = if cov_path.is_absolute() {
                    cov_path.clone()
                } else {
                    exec_dir.join(cov_path)
                };
                let raw_cov = fs::read_to_string(&resolved_cov).map_err(|e| {
                    format!(
                        "COVERAGE_REPORT_UNREADABLE: failed reading '{}': {e}",
                        resolved_cov.display()
                    )
                })?;
                let cov_map = parse_llvm_cov_file_percentages(&raw_cov)?;
                let cov_targets: Vec<String> = snapshots
                    .iter()
                    .filter_map(|(rel, content_opt)| {
                        if content_opt.is_some() && rel.ends_with(".rs") {
                            Some(rel.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                if !cov_targets.is_empty() {
                    verify_llvm_cov_meets_target(
                        &cov_map,
                        &cov_targets,
                        task.required_coverage_pct,
                    )?;
                }
            }

            if let Some(ref ctd) = cargo_target_dir
                && isolation.per_task_git_worktree
            {
                let _ = fs::remove_dir_all(ctd);
            }

            Ok(AttemptStageSuccess {
                session_id: grunt_session_id,
                modified_files: modified,
                snapshots,
                output_tokens: out_tokens,
            })
        })();

        match attempt_res {
            Ok(AttemptStageSuccess {
                session_id,
                modified_files,
                snapshots,
                output_tokens,
            }) => {
                return Ok(StagedTaskResult {
                    outcome: TaskAttemptOutcome {
                        task_id: task.spec.task_id.clone(),
                        wave_id: wave_id.to_string(),
                        session_id,
                        attempt,
                        model_tier: task.model_tier,
                        modified_files,
                        output_tokens,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    },
                    file_snapshots: snapshots,
                });
            }
            Err(err) => {
                // Out-of-scope / symlink / forbidden-path violations are immediate security halts (zero retry!)
                if err.starts_with("OBSERVED_WRITE_OUTSIDE_SCOPE:")
                    || err.starts_with("OBSERVED_SYMLINK_FORBIDDEN:")
                    || err.starts_with("OBSERVED_WRITE_FORBIDDEN_PATH:")
                {
                    return Err(err);
                }
                last_err = err;
            }
        }
    }

    let esc = EscalationTrigger::RoundCapExceeded {
        task_id: task.spec.task_id.clone(),
        rounds: MAX_ADVERSARIAL_ROUNDS,
    };
    Err(format!(
        "{}: task '{}' exhausted {MAX_ADVERSARIAL_ROUNDS} adversarial rounds; escalating to ForensicCoroner/Master ({last_err})",
        esc.code(),
        task.spec.task_id
    ))
}

fn write_reconciled_file_atomic(dst: &Path, bytes: &[u8], nonce_idx: usize) -> Result<(), String> {
    let Some(parent) = dst.parent() else {
        return Err(format!("invalid reconcile destination '{}'", dst.display()));
    };
    fs::create_dir_all(parent)
        .map_err(|e| format!("reconciler failed mkdir '{}': {e}", parent.display()))?;
    if let Ok(meta) = fs::symlink_metadata(dst)
        && meta.file_type().is_symlink()
    {
        return Err(format!(
            "OBSERVED_SYMLINK_FORBIDDEN: destination '{}' is a symlink",
            dst.display()
        ));
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_path = parent.join(format!(
        ".dotagent_reconcile_{}_{nonce_idx}_{nanos}.tmp",
        std::process::id()
    ));
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .map_err(|e| {
            format!(
                "reconciler failed creating temp '{}': {e}",
                tmp_path.display()
            )
        })?;
    if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!(
            "reconciler failed writing '{}': {e}",
            dst.display()
        ));
    }
    drop(f);
    if let Err(e) = fs::rename(&tmp_path, dst) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!(
            "reconciler failed renaming '{}': {e}",
            dst.display()
        ));
    }
    Ok(())
}

fn reconcile_disjoint_wave_deltas(
    base_repo: &Path,
    wave_id: &str,
    staged: &[StagedTaskResult],
) -> Result<(), String> {
    let mut seen: Vec<(&str, &str)> = Vec::new();
    for item in staged {
        let tid = item.outcome.task_id.as_str();
        for (rel, _) in &item.file_snapshots {
            for &(prev_rel, prev_tid) in &seen {
                if prev_tid != tid && paths_overlap_or_prefix(prev_rel, rel) {
                    return Err(format!(
                        "WAVE_MERGE_OVERLAP_CONFLICT: wave '{wave_id}' tasks '{prev_tid}' ('{prev_rel}') and '{tid}' ('{rel}') modified overlapping paths"
                    ));
                }
            }
            seen.push((rel.as_str(), tid));
        }
    }

    let mut deletions: Vec<&str> = Vec::new();
    let mut writes: Vec<(&str, &[u8])> = Vec::new();
    for item in staged {
        for (rel, content_opt) in &item.file_snapshots {
            ensure_safe_rel_components_and_zero_symlinks(base_repo, rel)?;
            validate_path(base_repo, base_repo, rel, PathAccess::Write).map_err(|v| {
                format!(
                    "OBSERVED_WRITE_FORBIDDEN_PATH: reconciler refused '{rel}': {}: {}",
                    v.code, v.detail
                )
            })?;
            match content_opt {
                Some(bytes) => writes.push((rel.as_str(), bytes.as_slice())),
                None => deletions.push(rel.as_str()),
            }
        }
    }

    // Apply deletions deepest-first and prune emptied parent directories strictly beneath `base_repo`
    // before writing new files so file<->directory replacements never collide.
    deletions.sort_by(|a, b| {
        b.matches('/')
            .count()
            .cmp(&a.matches('/').count())
            .then_with(|| a.cmp(b))
    });
    for rel in deletions {
        let dst = base_repo.join(rel);
        if let Ok(meta) = fs::symlink_metadata(&dst) {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "OBSERVED_SYMLINK_FORBIDDEN: destination '{}' is a symlink",
                    dst.display()
                ));
            }
            let _ = fs::remove_file(&dst);
        }
        let mut cur_parent = dst.parent();
        while let Some(dir) = cur_parent {
            if dir == base_repo || !dir.starts_with(base_repo) {
                break;
            }
            if fs::remove_dir(dir).is_err() {
                break;
            }
            cur_parent = dir.parent();
        }
    }

    for (idx, (rel, bytes)) in writes.into_iter().enumerate() {
        let dst = base_repo.join(rel);
        write_reconciled_file_atomic(&dst, bytes, idx + 1)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_swarm_v2_dag_and_enforces_parallel_write_disjointness() {
        let sample_dag = r#"{
  "schema": "dotagent.plan_dag.v2.0",
  "plan_id": "TEST-SWARM-V3",
  "isolation_policy": {
    "per_task_git_worktree": true,
    "private_cargo_target_dir": true,
    "enforce_observed_writes_subset": true
  },
  "waves": [
    { "wave_id": "W0", "parallel": false, "nodes": ["T0"] },
    { "wave_id": "W1", "parallel": true, "nodes": ["T1A", "T1B"] }
  ],
  "tasks": [
    {
      "id": "T0",
      "wave": "W0",
      "depends_on": [],
      "allowed_write_paths": ["src/base.rs"],
      "assigned_read_paths": ["src/base.rs"],
      "recommended_model_tier": "frontier"
    },
    {
      "id": "T1A",
      "wave": "W1",
      "depends_on": ["T0"],
      "allowed_write_paths": ["src/mod_a.rs"],
      "assigned_read_paths": ["src/base.rs"],
      "recommended_model_tier": "local_7b_or_mid"
    },
    {
      "id": "T1B",
      "wave": "W1",
      "depends_on": ["T0"],
      "allowed_write_paths": ["src/mod_b.rs"],
      "assigned_read_paths": ["src/base.rs"],
      "recommended_model_tier": "frontier"
    }
  ]
}"#;
        let plan = parse_swarm_dag_execution_plan(sample_dag).expect("valid DAG");
        assert_eq!(plan.waves.len(), 2);
        assert!(plan.waves[1].parallel);
        assert_eq!(
            plan.waves[1].tasks[0].model_tier,
            ModelTierRoute::Local7bOrMid
        );
        assert_eq!(plan.waves[1].tasks[1].model_tier, ModelTierRoute::Frontier);
    }

    #[test]
    fn parses_llvm_cov_and_libtest_json_streams() {
        let cov_json = r#"{"data":[{"files":[{"filename":"src/calc.rs","summary":{"lines":{"percent":96.5}}}]}]}"#;
        let pcts = parse_llvm_cov_file_percentages(cov_json).expect("valid llvm-cov");
        assert!((pcts["src/calc.rs"] - 96.5).abs() < 1e-6);

        let libtest = concat!(
            r#"{"type":"test","name":"tests::pass_one","event":"ok"}"#,
            "\n",
            r#"{"type":"test","name":"tests::fail_two","event":"failed"}"#,
            "\n"
        );
        let (failing, passing) = parse_structured_test_report(libtest).expect("parse libtest");
        assert_eq!(failing, vec!["tests::fail_two".to_string()]);
        assert_eq!(passing, vec!["tests::pass_one".to_string()]);
    }
}
