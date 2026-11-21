#![forbid(unsafe_code)]

//! DAG locking, domain-floored QA coverage calculation (`F20`), `test_attribution.toml`
//! schema verifier, and deterministic fault-triangulation solver (`F27`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::breadcrumbs::{
    ExclusiveFileLockGuard, compute_arbitrary_hmac_hex, sha256_digest, swarm_state_dir,
    verify_arbitrary_hmac_hex,
};
use crate::json::JsonValue;
use crate::path_policy::{PathAccess, check_forbidden_zones_lexical, validate_path_with_max_depth};
use crate::swarm_contracts::{
    DagTaskSpec, DomainRisk, LockedPlan, SuspectVerdict, TestAttributionRule, hex_encode,
};
use crate::unicode_guard::{ScanMode, scan_unicode};

const PLAN_LOCK_HMAC_DOMAIN: &[u8] = b"dotagent-plan-lock-v1";
const MAX_TEST_SOURCE_DEPTH: usize = 4;
const MAX_TEST_SCAN_ENTRIES: usize = 4096;
const MAX_TEST_SCAN_FILES: usize = 512;
const MAX_TEST_SOURCE_BYTES: usize = 512 * 1024;
const MAX_TEST_SCAN_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCoverageTarget {
    pub task_id: String,
    pub domain_floor_pct: u8,
    pub downstream_dependents: usize,
    pub required_coverage_pct: u8,
}

pub fn plan_lock_state_path(repo_root: &Path) -> Result<PathBuf, String> {
    let dir = swarm_state_dir(repo_root)?.join("ledger");
    if !dir.is_dir() {
        fs::create_dir_all(&dir)
            .map_err(|e| format!("failed creating swarm ledger dir '{}': {e}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
    }
    Ok(dir.join("PLAN.lock.json"))
}

/// Parses a wave DAG JSON document (supporting both `{ "waves": [ { "wave_id", "tasks": [...] } ] }`
/// and flat `{ "tasks": [...] }`), verifies acyclicity + parallel write-set disjointness,
/// and computes `plan_sha256`.
pub fn parse_and_validate_dag_json(raw_json: &str) -> Result<LockedPlan, String> {
    let uni = scan_unicode(raw_json, ScanMode::UntrustedContent);
    if let Some(first) = uni.first() {
        return Err(format!(
            "DAG JSON failed ASCII/Unicode check: {}",
            first.detail
        ));
    }

    let root = JsonValue::parse(raw_json).map_err(|e| format!("invalid DAG JSON: {e}"))?;
    let plan_id = root
        .get("plan_id")
        .or_else(|| root.get("dag_id"))
        .and_then(JsonValue::as_str)
        .unwrap_or("SWARM-PLAN")
        .to_string();

    let mut tasks = Vec::new();
    if let Some(flat_tasks) = root.get("tasks").and_then(JsonValue::as_array) {
        for t in flat_tasks {
            let wid = t
                .get("wave_id")
                .or_else(|| t.get("wave"))
                .and_then(JsonValue::as_str)
                .unwrap_or("W0")
                .to_string();
            tasks.push(parse_task_node(t, &wid)?);
        }
    } else if let Some(waves) = root.get("waves").and_then(JsonValue::as_array) {
        for wave in waves {
            let wid = wave
                .get("wave_id")
                .or_else(|| wave.get("id"))
                .and_then(JsonValue::as_str)
                .unwrap_or("W0")
                .to_string();
            if let Some(wtasks) = wave.get("tasks").and_then(JsonValue::as_array) {
                for t in wtasks {
                    tasks.push(parse_task_node(t, &wid)?);
                }
            }
        }
    }

    if tasks.is_empty() {
        return Err("DAG plan contains zero tasks".to_string());
    }

    validate_dag_invariants(&tasks)?;

    let canonical = serialize_locked_tasks_canonical(&plan_id, &tasks);
    let plan_sha256 = hex_encode(&sha256_digest(canonical.as_bytes()));

    Ok(LockedPlan {
        plan_id,
        plan_sha256,
        tasks,
    })
}

fn parse_task_node(v: &JsonValue, default_wave: &str) -> Result<DagTaskSpec, String> {
    let task_id = v
        .get("task_id")
        .or_else(|| v.get("id"))
        .and_then(JsonValue::as_str)
        .ok_or_else(|| "task missing task_id".to_string())?
        .trim()
        .to_string();
    if task_id.is_empty() {
        return Err("empty task_id in DAG".to_string());
    }

    let wave_id = v
        .get("wave_id")
        .or_else(|| v.get("wave"))
        .and_then(JsonValue::as_str)
        .unwrap_or(default_wave)
        .to_string();

    let depends_on = extract_str_vec(v, &["depends_on", "deps"]);
    let assigned_read_paths = extract_str_vec(v, &["assigned_read_paths", "reads", "owned_files"]);
    let allowed_write_paths = extract_str_vec(v, &["allowed_write_paths", "writes", "owned_files"]);
    let assigned_tests = extract_str_vec(v, &["assigned_tests", "tests", "verification_tests"]);

    let domain_risk = if let Some(risk_raw) = v.get("domain_risk").and_then(JsonValue::as_str) {
        DomainRisk::from_str_id(risk_raw)
    } else if let Some(floor_num) = v.get("domain_floor").and_then(JsonValue::as_u64) {
        if floor_num >= 9 {
            DomainRisk::SecurityCritical
        } else if floor_num >= 7 {
            DomainRisk::StatefulCore
        } else {
            DomainRisk::Standard
        }
    } else {
        DomainRisk::from_str_id(infer_domain_risk(&task_id, &allowed_write_paths))
    };

    Ok(DagTaskSpec {
        task_id,
        wave_id,
        depends_on,
        domain_risk,
        assigned_read_paths,
        allowed_write_paths,
        assigned_tests,
    })
}

fn infer_domain_risk<'a>(task_id: &str, writes: &[String]) -> &'a str {
    let joined = format!(
        "{} {}",
        task_id.to_ascii_lowercase(),
        writes.join(" ").to_ascii_lowercase()
    );
    if joined.contains("sandbox")
        || joined.contains("policy")
        || joined.contains("crypto")
        || joined.contains("hmac")
        || joined.contains("breadcrumb")
        || joined.contains("auth")
        || joined.contains("adversarial")
    {
        "security_critical"
    } else if joined.contains("ledger") || joined.contains("spool") || joined.contains("state") {
        "stateful_core"
    } else {
        "standard"
    }
}

fn extract_str_vec(v: &JsonValue, keys: &[&str]) -> Vec<String> {
    for k in keys {
        if let Some(arr) = v.get(k).and_then(JsonValue::as_array) {
            return arr
                .iter()
                .filter_map(JsonValue::as_str)
                .map(|s| s.trim().trim_start_matches("./").to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    Vec::new()
}

fn validate_dag_invariants(tasks: &[DagTaskSpec]) -> Result<(), String> {
    let mut by_id: BTreeMap<&str, &DagTaskSpec> = BTreeMap::new();
    for t in tasks {
        if by_id.insert(t.task_id.as_str(), t).is_some() {
            return Err(format!("duplicate task_id '{}' in DAG", t.task_id));
        }
    }

    // 1. Verify all dependencies exist & build indegree map for Kahn cycle check
    let mut indegree: BTreeMap<&str, usize> = BTreeMap::new();
    let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for t in tasks {
        indegree.entry(t.task_id.as_str()).or_insert(0);
        for dep in &t.depends_on {
            if !by_id.contains_key(dep.as_str()) {
                return Err(format!(
                    "task '{}' depends on unknown task '{}'",
                    t.task_id, dep
                ));
            }
            if dep == &t.task_id {
                return Err(format!("task '{}' has self-dependency cycle", t.task_id));
            }
            *indegree.entry(t.task_id.as_str()).or_insert(0) += 1;
            adj.entry(dep.as_str())
                .or_default()
                .push(t.task_id.as_str());
        }
    }

    let mut queue: Vec<&str> = indegree
        .iter()
        .filter_map(|(&k, &deg)| if deg == 0 { Some(k) } else { None })
        .collect();
    let mut visited = 0usize;
    while let Some(node) = queue.pop() {
        visited += 1;
        if let Some(children) = adj.get(node) {
            for &ch in children {
                if let Some(deg) = indegree.get_mut(ch) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push(ch);
                    }
                }
            }
        }
    }
    if visited != tasks.len() {
        return Err("DAG contains a dependency cycle".to_string());
    }

    // 2. Verify disjoint `allowed_write_paths` (including prefix and glob overlaps)
    //    for concurrent tasks in the same wave (`MEDIUM-DA-06`).
    let is_dep_ordered = |a: &str, b: &str| -> bool {
        let mut seen = BTreeSet::new();
        let mut stack = vec![a];
        while let Some(cur) = stack.pop() {
            if cur == b {
                return true;
            }
            if seen.insert(cur)
                && let Some(t) = by_id.get(cur)
            {
                for dep in &t.depends_on {
                    stack.push(dep.as_str());
                }
            }
        }
        false
    };

    for i in 0..tasks.len() {
        for j in (i + 1)..tasks.len() {
            let ta = &tasks[i];
            let tb = &tasks[j];
            if ta.wave_id != tb.wave_id
                || ta.task_id == tb.task_id
                || is_dep_ordered(&ta.task_id, &tb.task_id)
                || is_dep_ordered(&tb.task_id, &ta.task_id)
            {
                continue;
            }
            for wa in &ta.allowed_write_paths {
                for wb in &tb.allowed_write_paths {
                    if write_scopes_overlap(wa, wb) {
                        return Err(format!(
                            "PARALLEL_WRITE_CONFLICT in wave '{}': tasks '{}' ('{}') and '{}' ('{}') have overlapping write scopes",
                            ta.wave_id, ta.task_id, wa, tb.task_id, wb
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

fn normalize_scope_pattern(raw: &str) -> String {
    let mut s = raw.trim().replace('\\', "/");
    while let Some(stripped) = s.strip_prefix("./") {
        s = stripped.to_string();
    }
    while s.len() > 1 && s.ends_with('/') {
        s.pop();
    }
    s
}

fn static_dir_prefix_before_glob(pat: &str) -> &str {
    match pat.find(['*', '?', '[']) {
        Some(idx) => pat[..idx].trim_end_matches('/'),
        None => pat,
    }
}

fn write_scopes_overlap(raw_a: &str, raw_b: &str) -> bool {
    let a = normalize_scope_pattern(raw_a);
    let b = normalize_scope_pattern(raw_b);
    if a.is_empty() || b.is_empty() {
        return false;
    }
    if a == b || a == "*" || b == "*" {
        return true;
    }
    if crate::role_sandbox::path_matches_any_scope(&a, std::slice::from_ref(&b))
        || crate::role_sandbox::path_matches_any_scope(&b, std::slice::from_ref(&a))
    {
        return true;
    }
    let a_has_glob = a.contains(['*', '?', '[']);
    let b_has_glob = b.contains(['*', '?', '[']);
    if !a_has_glob && !b_has_glob {
        return a.starts_with(&format!("{b}/")) || b.starts_with(&format!("{a}/"));
    }
    let pa = static_dir_prefix_before_glob(&a);
    let pb = static_dir_prefix_before_glob(&b);
    if pa.is_empty() || pb.is_empty() {
        return true;
    }
    pa == pb || pa.starts_with(&format!("{pb}/")) || pb.starts_with(&format!("{pa}/"))
}

fn serialize_locked_tasks_canonical(plan_id: &str, tasks: &[DagTaskSpec]) -> String {
    let task_vals: Vec<JsonValue> = tasks
        .iter()
        .map(|t| {
            JsonValue::Object(vec![
                ("task_id".to_string(), JsonValue::Str(t.task_id.clone())),
                ("wave_id".to_string(), JsonValue::Str(t.wave_id.clone())),
                (
                    "depends_on".to_string(),
                    JsonValue::Array(t.depends_on.iter().cloned().map(JsonValue::Str).collect()),
                ),
                (
                    "domain_risk".to_string(),
                    JsonValue::Str(match t.domain_risk {
                        DomainRisk::SecurityCritical => "security_critical".to_string(),
                        DomainRisk::StatefulCore => "stateful_core".to_string(),
                        DomainRisk::Standard => "standard".to_string(),
                    }),
                ),
                (
                    "assigned_read_paths".to_string(),
                    JsonValue::Array(
                        t.assigned_read_paths
                            .iter()
                            .cloned()
                            .map(JsonValue::Str)
                            .collect(),
                    ),
                ),
                (
                    "allowed_write_paths".to_string(),
                    JsonValue::Array(
                        t.allowed_write_paths
                            .iter()
                            .cloned()
                            .map(JsonValue::Str)
                            .collect(),
                    ),
                ),
                (
                    "assigned_tests".to_string(),
                    JsonValue::Array(
                        t.assigned_tests
                            .iter()
                            .cloned()
                            .map(JsonValue::Str)
                            .collect(),
                    ),
                ),
            ])
        })
        .collect();
    JsonValue::Object(vec![
        ("plan_id".to_string(), JsonValue::Str(plan_id.to_string())),
        ("tasks".to_string(), JsonValue::Array(task_vals)),
    ])
    .to_json_string()
}

pub fn save_locked_plan(
    repo_root: &Path,
    plan: &LockedPlan,
    allow_amend_with_human_approval: bool,
) -> Result<PathBuf, String> {
    save_locked_plan_inner(
        repo_root,
        plan,
        allow_amend_with_human_approval,
        PlanWriteEpoch::Current,
    )
}

/// Re-signs the plan, active Master, and session registry before installing the replacement key.
pub fn save_locked_plan_with_epoch_rotation(
    repo_root: &Path,
    plan: &LockedPlan,
    allow_amend_with_human_approval: bool,
    master_session_id: Option<&str>,
) -> Result<PathBuf, String> {
    save_locked_plan_inner(
        repo_root,
        plan,
        allow_amend_with_human_approval,
        PlanWriteEpoch::Rotate(master_session_id),
    )
}

enum PlanWriteEpoch<'a> {
    Current,
    Rotate(Option<&'a str>),
}

fn save_locked_plan_inner(
    repo_root: &Path,
    plan: &LockedPlan,
    allow_amend_with_human_approval: bool,
    epoch: PlanWriteEpoch<'_>,
) -> Result<PathBuf, String> {
    let lock_path = plan_lock_state_path(repo_root)?;
    let _guard = ExclusiveFileLockGuard::acquire(&lock_path)?;

    let canonical = serialize_locked_tasks_canonical(&plan.plan_id, &plan.tasks);
    let recomputed_sha = hex_encode(&sha256_digest(canonical.as_bytes()));
    if recomputed_sha != plan.plan_sha256 {
        return Err(format!(
            "PLAN_LOCK_TAMPERED: in-memory plan_sha256 '{}' does not match canonical digest '{recomputed_sha}'",
            plan.plan_sha256
        ));
    }
    let parsed_tasks = JsonValue::parse(&canonical).map_err(|e| e.to_string())?;
    let encode = |record_mac| {
        let wrapper = JsonValue::Object(vec![
            ("plan_id".to_string(), JsonValue::Str(plan.plan_id.clone())),
            (
                "plan_sha256".to_string(),
                JsonValue::Str(plan.plan_sha256.clone()),
            ),
            (
                "tasks".to_string(),
                parsed_tasks
                    .get("tasks")
                    .cloned()
                    .unwrap_or(JsonValue::Array(Vec::new())),
            ),
            ("record_mac".to_string(), JsonValue::Str(record_mac)),
        ]);
        format!("{}\n", wrapper.to_json_string()).into_bytes()
    };
    let validate_existing = || {
        let existing_len = match fs::symlink_metadata(&lock_path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(format!(
                    "SYMLINK_REJECTED: PLAN.lock.json path '{}' is a symlink",
                    lock_path.display()
                ));
            }
            Ok(meta) if meta.is_file() => meta.len(),
            Ok(_) => return Err("PLAN_LOCK_TAMPERED: PLAN.lock.json must be a regular file".into()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0,
            Err(err) => return Err(format!("failed inspecting PLAN.lock.json: {err}")),
        };
        if existing_len > 0 && !allow_amend_with_human_approval {
            let existing = load_locked_plan_unlocked(repo_root, &lock_path)?;
            if existing.plan_sha256 != plan.plan_sha256 {
                return Err(format!(
                    "PLAN_LOCK_IMMUTABLE: PLAN.lock.json already pinned at {}; pass --amend --human-approved to re-lock",
                    &existing.plan_sha256[..16]
                ));
            }
        }
        Ok(())
    };
    match epoch {
        PlanWriteEpoch::Current => {
            validate_existing()?;
            let mac =
                compute_arbitrary_hmac_hex(repo_root, PLAN_LOCK_HMAC_DOMAIN, canonical.as_bytes())?;
            crate::traversal_ledger::atomic_write_nonsymlink_state_file(&lock_path, &encode(mac))
                .map_err(|e| format!("failed writing PLAN.lock.json: {e}"))?;
        }
        PlanWriteEpoch::Rotate(master_session_id) => {
            crate::role_sandbox::rotate_closed_session_epoch(
                repo_root,
                master_session_id,
                &lock_path,
                |key| {
                    validate_existing()?;
                    let mac = crate::coordinator::compute_domain_tag_raw(
                        key,
                        PLAN_LOCK_HMAC_DOMAIN,
                        canonical.as_bytes(),
                    )?;
                    Ok(encode(hex_encode(&mac)))
                },
            )?;
        }
    }
    Ok(lock_path)
}

pub fn load_locked_plan(repo_root: &Path) -> Result<LockedPlan, String> {
    let lock_path = plan_lock_state_path(repo_root)?;
    let _guard = ExclusiveFileLockGuard::acquire(&lock_path)?;
    load_locked_plan_unlocked(repo_root, &lock_path)
}

fn load_locked_plan_unlocked(repo_root: &Path, lock_path: &Path) -> Result<LockedPlan, String> {
    if fs::symlink_metadata(lock_path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(format!(
            "PLAN_LOCK_TAMPERED: PLAN.lock.json path '{}' is a symlink",
            lock_path.display()
        ));
    }
    let raw = fs::read_to_string(lock_path)
        .map_err(|e| format!("no locked plan found at '{}': {e}", lock_path.display()))?;
    if raw.trim().is_empty() {
        return Err(format!(
            "no locked plan found at '{}': PLAN.lock.json is empty",
            lock_path.display()
        ));
    }
    let root = JsonValue::parse(&raw)
        .map_err(|e| format!("PLAN_LOCK_TAMPERED: corrupt PLAN.lock.json JSON: {e}"))?;
    let persisted_sha = root
        .get("plan_sha256")
        .and_then(JsonValue::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| "PLAN_LOCK_TAMPERED: missing plan_sha256 in PLAN.lock.json".to_string())?;
    let recorded_mac = root
        .get("record_mac")
        .and_then(JsonValue::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| "PLAN_LOCK_TAMPERED: missing record_mac in PLAN.lock.json".to_string())?;

    let recomputed =
        parse_and_validate_dag_json(&raw).map_err(|e| format!("PLAN_LOCK_TAMPERED: {e}"))?;
    if recomputed.plan_sha256 != persisted_sha {
        return Err(format!(
            "PLAN_LOCK_TAMPERED: persisted plan_sha256 '{}' does not match canonical task graph digest '{}'",
            persisted_sha, recomputed.plan_sha256
        ));
    }

    let canonical = serialize_locked_tasks_canonical(&recomputed.plan_id, &recomputed.tasks);
    verify_arbitrary_hmac_hex(
        repo_root,
        PLAN_LOCK_HMAC_DOMAIN,
        canonical.as_bytes(),
        recorded_mac,
    )
    .map_err(|e| format!("PLAN_LOCK_TAMPERED: PLAN.lock.json HMAC verification failed: {e}"))?;

    Ok(recomputed)
}

/// Computes `max(domain_risk_floor, dag_fanout)` bounded to `50%..95%` (`F20`).
pub fn compute_task_coverage_targets(plan: &LockedPlan) -> Vec<TaskCoverageTarget> {
    let mut reverse_adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for t in &plan.tasks {
        for dep in &t.depends_on {
            reverse_adj
                .entry(dep.as_str())
                .or_default()
                .push(t.task_id.as_str());
        }
    }

    plan.tasks
        .iter()
        .map(|t| {
            let mut visited = BTreeSet::new();
            let mut stack = vec![t.task_id.as_str()];
            while let Some(cur) = stack.pop() {
                if let Some(children) = reverse_adj.get(cur) {
                    for &ch in children {
                        if visited.insert(ch) {
                            stack.push(ch);
                        }
                    }
                }
            }
            let downstream = visited.len();
            let fanout_pct = (50usize.saturating_add(downstream.saturating_mul(12))).min(95) as u8;
            let floor = t.domain_risk.coverage_floor_pct();
            TaskCoverageTarget {
                task_id: t.task_id.clone(),
                domain_floor_pct: floor,
                downstream_dependents: downstream,
                required_coverage_pct: floor.max(fanout_pct).clamp(50, 95),
            }
        })
        .collect()
}

/// Parses `test_attribution.toml` blocks (`[[tests]]`) enforcing `1` `primary_suspect`,
/// `0..=2` `secondary_suspects`, and `0..=N` `boundary_interfaces`.
pub fn parse_attribution_toml(raw_toml: &str) -> Result<Vec<TestAttributionRule>, String> {
    let uni = scan_unicode(raw_toml, ScanMode::UntrustedContent);
    if let Some(first) = uni.first() {
        return Err(format!(
            "test_attribution.toml failed ASCII/Unicode hygiene: {}",
            first.detail
        ));
    }

    let mut rules = Vec::new();
    let mut cur_name: Option<String> = None;
    let mut cur_primary: Option<String> = None;
    let mut cur_secondary: Vec<String> = Vec::new();
    let mut cur_boundaries: Vec<String> = Vec::new();
    let mut in_block = false;

    let flush_current = |name: Option<String>,
                         primary: Option<String>,
                         secondary: Vec<String>,
                         boundaries: Vec<String>,
                         out: &mut Vec<TestAttributionRule>|
     -> Result<(), String> {
        let test_name = name.ok_or_else(|| "[[tests]] entry missing 'name'".to_string())?;
        let primary_suspect = primary
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("test '{test_name}' missing required primary_suspect"))?;
        if secondary.len() > 2 {
            return Err(format!(
                "test '{test_name}' declares {} secondary_suspects (max 2 allowed)",
                secondary.len()
            ));
        }
        out.push(TestAttributionRule {
            test_name,
            primary_suspect,
            secondary_suspects: secondary,
            boundary_interfaces: boundaries,
        });
        Ok(())
    };

    for raw_line in raw_toml.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[tests]]" {
            if in_block {
                flush_current(
                    cur_name.take(),
                    cur_primary.take(),
                    std::mem::take(&mut cur_secondary),
                    std::mem::take(&mut cur_boundaries),
                    &mut rules,
                )?;
            }
            in_block = true;
            continue;
        }
        if !in_block {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            let val = v.trim();
            match key {
                "name" | "test" => cur_name = Some(parse_toml_str(val)?),
                "primary_suspect" => cur_primary = Some(parse_toml_str(val)?),
                "secondary_suspects" => cur_secondary = parse_toml_str_array(val)?,
                "boundary_interfaces" => cur_boundaries = parse_toml_str_array(val)?,
                _ => {}
            }
        }
    }

    if in_block {
        flush_current(
            cur_name,
            cur_primary,
            cur_secondary,
            cur_boundaries,
            &mut rules,
        )?;
    }

    if rules.is_empty() {
        return Err("test_attribution.toml contains zero [[tests]] rules".to_string());
    }
    Ok(rules)
}

pub fn verify_attribution_against_plan(
    rules: &[TestAttributionRule],
    plan: &LockedPlan,
) -> Result<(), String> {
    let known_tasks: BTreeSet<&str> = plan.tasks.iter().map(|t| t.task_id.as_str()).collect();
    for r in rules {
        if !known_tasks.contains(r.primary_suspect.as_str()) {
            return Err(format!(
                "test '{}' references unknown primary_suspect '{}'",
                r.test_name, r.primary_suspect
            ));
        }
        for sec in &r.secondary_suspects {
            if !known_tasks.contains(sec.as_str()) {
                return Err(format!(
                    "test '{}' references unknown secondary_suspect '{}'",
                    r.test_name, sec
                ));
            }
        }
    }
    Ok(())
}

/// Enforces live-contract QA discipline before unlocking `Grunt` waves:
/// 1. Validates `rules` against `plan` (`verify_attribution_against_plan`).
/// 2. Scans `tests/` to reject `#[ignore]`, `test.skip(...)`, or `it.skip(...)` on attributed tests.
/// 3. Requires every `SecurityCritical` or `StatefulCore` task in `plan` to have at least one
///    attributed test declaration with a body under `tests/`.
pub fn verify_live_integration_contracts(
    repo_root: &Path,
    rules: &[TestAttributionRule],
    plan: &LockedPlan,
) -> Result<(), String> {
    verify_attribution_against_plan(rules, plan)?;

    let canon_repo = fs::canonicalize(repo_root)
        .map_err(|e| format!("LIVE_TEST_SCAN_FAILED: cannot resolve repository: {e}"))?;
    let tests_dir = canon_repo.join("tests");
    let attributed_names: BTreeSet<&str> = rules.iter().map(|r| r.test_name.as_str()).collect();
    let mut names_found_in_tests_dir = BTreeSet::new();

    match fs::symlink_metadata(&tests_dir) {
        Ok(meta) if meta.is_dir() => {
            let mut scan = TestSourceScan::new(&canon_repo, &tests_dir);
            scan.walk(&tests_dir, 0, &mut |path, language, content| {
                for (name, skipped) in test_declarations(content, language) {
                    if let Some(&attributed_name) = attributed_names.get(name) {
                        if skipped {
                            return Err(format!(
                                "SKIPPED_ATTRIBUTED_TEST_FORBIDDEN: attributed test '{name}' is marked ignored/skipped in '{}'",
                                path.display()
                            ));
                        }
                        names_found_in_tests_dir.insert(attributed_name);
                    }
                }
                Ok(())
            })?;
        }
        Ok(_) => {
            return Err("LIVE_TEST_SCAN_FAILED: tests/ must be a non-symlink directory".into());
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!("LIVE_TEST_SCAN_FAILED: cannot inspect tests/: {e}"));
        }
    }

    for task in &plan.tasks {
        if !matches!(
            task.domain_risk,
            DomainRisk::SecurityCritical | DomainRisk::StatefulCore
        ) {
            continue;
        }
        let has_live_or_integration = rules.iter().any(|r| {
            let covers_task = r.primary_suspect == task.task_id
                || r.secondary_suspects.iter().any(|s| s == &task.task_id);
            covers_task && names_found_in_tests_dir.contains(r.test_name.as_str())
        });
        if !has_live_or_integration {
            return Err(format!(
                "MISSING_LIVE_INTEGRATION_CONTRACT: high-risk task '{}' ({:?}) has no attributed on-disk integration/e2e test in tests/",
                task.task_id, task.domain_risk
            ));
        }
    }

    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TestSourceLanguage {
    Rust,
    Python,
    JavaScript,
}

impl TestSourceLanguage {
    fn from_path(path: &Path) -> Option<Self> {
        Some(match path.extension()?.to_str()? {
            "rs" => Self::Rust,
            "py" => Self::Python,
            "js" | "mjs" | "cjs" | "jsx" | "ts" | "mts" | "cts" | "tsx" => Self::JavaScript,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SourceToken<'a> {
    pub(crate) text: &'a str,
    pub(crate) line: usize,
    pub(crate) offset: usize,
    column: usize,
    literal: bool,
}

impl SourceToken<'_> {
    pub(crate) fn is(self, text: &str) -> bool {
        !self.literal && self.text == text
    }

    fn identifier(self) -> bool {
        !self.literal
            && self
                .text
                .starts_with(|c: char| c == '_' || c.is_alphabetic())
    }
}

pub(crate) fn rust_source_tokens(source: &str) -> Vec<SourceToken<'_>> {
    source_tokens(source, TestSourceLanguage::Rust)
}

fn source_tokens(source: &str, language: TestSourceLanguage) -> Vec<SourceToken<'_>> {
    let mut tokens: Vec<SourceToken<'_>> = Vec::new();
    let mut offset = 0;
    let mut line = 1;
    let mut line_start = 0;
    while let Some(first) = source[offset..].chars().next() {
        let rest = &source[offset..];
        let comment_len = if rest.starts_with("//") && language != TestSourceLanguage::Python
            || first == '#' && language == TestSourceLanguage::Python
        {
            Some(rest.find('\n').unwrap_or(rest.len()))
        } else if rest.starts_with("/*") && language != TestSourceLanguage::Python {
            Some(block_comment_len(
                rest,
                language == TestSourceLanguage::Rust,
            ))
        } else {
            None
        };
        let len = if let Some(len) = comment_len {
            len
        } else if first.is_whitespace() {
            first.len_utf8()
        } else {
            let literal_len = source_literal_len(rest, language, tokens.last().copied());
            let len = literal_len.unwrap_or_else(|| {
                if language == TestSourceLanguage::Rust
                    && let Some(identifier) = rest.strip_prefix("r#")
                    && identifier.starts_with(|c: char| c == '_' || c.is_alphabetic())
                {
                    return 2 + identifier
                        .find(|c: char| !source_identifier_char(c, language))
                        .unwrap_or(identifier.len());
                }
                if source_identifier_char(first, language) {
                    rest.find(|c: char| !source_identifier_char(c, language))
                        .unwrap_or(rest.len())
                } else {
                    first.len_utf8()
                }
            });
            tokens.push(SourceToken {
                text: &rest[..len],
                line,
                offset,
                column: offset - line_start,
                literal: literal_len.is_some(),
            });
            len
        };
        let consumed = &rest[..len];
        if let Some(last_newline) = consumed.rfind('\n') {
            line += consumed.bytes().filter(|&b| b == b'\n').count();
            line_start = offset + last_newline + 1;
        }
        offset += len;
    }
    tokens
}

fn source_identifier_char(c: char, language: TestSourceLanguage) -> bool {
    c.is_alphanumeric()
        || c == '_'
        || c == '$' && language == TestSourceLanguage::JavaScript
        || !c.is_ascii() && !c.is_whitespace()
}

fn block_comment_len(source: &str, nested: bool) -> usize {
    let mut depth = 1;
    let mut offset = 2;
    let bytes = source.as_bytes();
    while offset + 1 < bytes.len() {
        match &bytes[offset..offset + 2] {
            b"*/" => {
                depth -= 1;
                offset += 2;
                if depth == 0 {
                    return offset;
                }
            }
            b"/*" if nested => {
                depth += 1;
                offset += 2;
            }
            _ => offset += 1,
        }
    }
    source.len()
}

fn source_literal_len(
    source: &str,
    language: TestSourceLanguage,
    previous: Option<SourceToken<'_>>,
) -> Option<usize> {
    let bytes = source.as_bytes();
    let first = bytes[0];
    if language == TestSourceLanguage::Rust {
        let raw = source.strip_prefix(['b', 'c']).unwrap_or(source);
        if let Some(rest) = raw.strip_prefix('r') {
            let hashes = rest.bytes().take_while(|&b| b == b'#').count();
            if rest.as_bytes().get(hashes) == Some(&b'"') {
                let opening = source.len() - rest.len() + hashes + 1;
                return Some(delimited_len(bytes, opening, b'"', hashes, false));
            }
        }
        if first == b'\'' {
            // A lifetime has no closing apostrophe after a single character.
            let character = source[1..].chars().next()?;
            if character == '\\' {
                return Some(delimited_len(bytes, 1, b'\'', 0, true));
            }
            let end = 1 + character.len_utf8();
            return (bytes.get(end) == Some(&b'\'')).then_some(end + 1);
        }
    }
    let quote = first == b'"'
        || first == b'\'' && language != TestSourceLanguage::Rust
        || first == 0x60 && language == TestSourceLanguage::JavaScript;
    if quote {
        let extra_quotes = if language == TestSourceLanguage::Python
            && bytes.get(1) == Some(&first)
            && bytes.get(2) == Some(&first)
        {
            2
        } else {
            0
        };
        return Some(delimited_len(
            bytes,
            1 + extra_quotes,
            first,
            extra_quotes,
            true,
        ));
    }
    if first == b'/'
        && language == TestSourceLanguage::JavaScript
        && previous.is_none_or(|p| {
            ["=", "(", ",", "{", ";", ":", "return", ">", "[", "!", "?"]
                .iter()
                .any(|s| p.is(s))
        })
    {
        return javascript_regex_len(bytes);
    }
    None
}

fn delimited_len(
    bytes: &[u8],
    mut offset: usize,
    delimiter: u8,
    suffix: usize,
    escapes: bool,
) -> usize {
    let suffix_byte = if escapes { delimiter } else { b'#' };
    while let Some(&byte) = bytes.get(offset) {
        if byte == delimiter
            && bytes
                .get(offset + 1..offset + 1 + suffix)
                .is_some_and(|tail| tail.iter().all(|&b| b == suffix_byte))
        {
            return offset + 1 + suffix;
        }
        offset += if escapes && byte == b'\\' { 2 } else { 1 };
    }
    bytes.len()
}

fn javascript_regex_len(bytes: &[u8]) -> Option<usize> {
    let mut offset = 1;
    let mut in_class = false;
    while let Some(&byte) = bytes.get(offset) {
        match byte {
            b'\n' | b'\r' => return None,
            b'/' if !in_class => return Some(offset + 1),
            b'[' => in_class = true,
            b']' => in_class = false,
            b'\\' => offset += 1,
            _ => {}
        }
        offset += 1;
    }
    None
}

fn token_is(tokens: &[SourceToken<'_>], index: usize, value: &str) -> bool {
    tokens.get(index).is_some_and(|token| token.is(value))
}

fn group_end(
    tokens: &[SourceToken<'_>],
    start: usize,
    opener: &str,
    closer: &str,
) -> Option<usize> {
    if !token_is(tokens, start, opener) {
        return None;
    }
    let mut depth = 1;
    for (index, token) in tokens.iter().enumerate().skip(start + 1) {
        if token.is(opener) {
            depth += 1;
        } else if token.is(closer) {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn test_declarations(source: &str, language: TestSourceLanguage) -> Vec<(&str, bool)> {
    let tokens = source_tokens(source, language);
    match language {
        TestSourceLanguage::Rust => rust_test_declarations(&tokens),
        TestSourceLanguage::Python => python_test_declarations(&tokens),
        TestSourceLanguage::JavaScript => javascript_test_declarations(&tokens),
    }
}

fn rust_test_declarations<'a>(tokens: &[SourceToken<'a>]) -> Vec<(&'a str, bool)> {
    let mut tests = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let mut annotated_test = false;
        let mut ignored = false;
        while token_is(tokens, index, "#") {
            let Some(end) = group_end(tokens, index + 1, "[", "]") else {
                break;
            };
            let attr = &tokens[index + 2..end];
            annotated_test |= attr.len() == 1 && token_is(attr, 0, "test")
                || attr.first().is_some_and(|a| {
                    a.is("tokio") || a.is("async_std") || a.is("actix_rt") || a.is("actix_web")
                }) && token_is(attr, 1, ":")
                    && token_is(attr, 2, ":")
                    && token_is(attr, 3, "test");
            ignored |= token_is(attr, 0, "ignore") && (attr.len() == 1 || token_is(attr, 1, "="));
            index = end + 1;
        }
        if token_is(tokens, index, "pub") {
            index = group_end(tokens, index + 1, "(", ")").map_or(index + 1, |end| end + 1);
        }
        while matches!(
            tokens.get(index).map(|t| t.text),
            Some("async" | "unsafe" | "const")
        ) {
            index += 1;
        }
        if token_is(tokens, index, "mod") && token_is(tokens, index + 2, "{") {
            index += 3;
            continue;
        }
        if token_is(tokens, index, "fn")
            && let Some(name) = tokens.get(index + 1).filter(|name| name.identifier())
            && let Some(args_end) = group_end(tokens, index + 2, "(", ")")
            && let Some(body) = tokens
                .iter()
                .enumerate()
                .skip(args_end + 1)
                .find_map(|(i, token)| (token.is("{") || token.is(";")).then_some(i))
            && let Some(body_end) = group_end(tokens, body, "{", "}")
        {
            if annotated_test && args_end == index + 3 && (ignored || body_end > body + 1) {
                tests.push((name.text.strip_prefix("r#").unwrap_or(name.text), ignored));
            }
            index = body_end + 1;
            continue;
        }
        let group = [("(", ")"), ("[", "]"), ("{", "}")]
            .into_iter()
            .find_map(|(open, close)| group_end(tokens, index, open, close));
        index = group.map_or(index + 1, |end| end + 1);
    }
    tests
}

fn python_test_declarations<'a>(tokens: &[SourceToken<'a>]) -> Vec<(&'a str, bool)> {
    let mut tests = Vec::new();
    let mut index = 0;
    let mut skipped = false;
    let mut class_body = None;
    while let Some(start) = tokens.get(index) {
        let first_on_line = index == 0 || tokens[index - 1].line < start.line;
        if first_on_line && start.column == 0 {
            class_body = None;
        }
        if !first_on_line
            || start.column != 0 && !class_body.is_some_and(|(indent, _)| indent == start.column)
        {
            index += 1;
            continue;
        }
        if start.is("@") {
            skipped |= (token_is(tokens, index + 1, "unittest")
                && token_is(tokens, index + 2, ".")
                && ["skip", "skipIf", "skipUnless"]
                    .iter()
                    .any(|name| token_is(tokens, index + 3, name)))
                || (token_is(tokens, index + 1, "pytest")
                    && token_is(tokens, index + 2, ".")
                    && token_is(tokens, index + 3, "mark")
                    && token_is(tokens, index + 4, ".")
                    && ["skip", "skipif"]
                        .iter()
                        .any(|name| token_is(tokens, index + 5, name)));
            while tokens
                .get(index)
                .is_some_and(|token| token.line == start.line)
            {
                index = group_end(tokens, index, "(", ")").map_or(index + 1, |end| end + 1);
            }
            continue;
        }
        if start.column == 0 && start.is("class") {
            let parents_end = group_end(tokens, index + 2, "(", ")");
            let valid_base = parents_end
                .is_some_and(|end| tokens[index + 3..end].iter().any(|t| t.is("TestCase")));
            let test_class = tokens[index + 1..]
                .first()
                .is_some_and(|t| t.identifier() && t.text.starts_with("Test"))
                || valid_base;
            let colon = parents_end.map_or(index + 2, |end| end + 1);
            if test_class
                && token_is(tokens, colon, ":")
                && let Some(body) = tokens
                    .get(colon + 1)
                    .filter(|body| body.line > tokens[colon].line && body.column > 0)
            {
                class_body = Some((body.column, skipped));
                index = colon + 1;
                skipped = false;
                continue;
            }
        }
        let def = index + usize::from(start.is("async"));
        if token_is(tokens, def, "def")
            && let Some(name) = tokens
                .get(def + 1)
                .filter(|t| t.identifier() && t.text.starts_with("test_"))
            && let Some(args_end) = group_end(tokens, def + 2, "(", ")")
            && let Some(colon) = python_body_colon(tokens, args_end + 1)
        {
            let mut body_end = colon + 1;
            while tokens
                .get(body_end)
                .is_some_and(|t| t.line == tokens[colon].line || t.column > start.column)
            {
                body_end += 1;
            }
            let body = &tokens[colon + 1..body_end];
            let skipped_in_body = body.windows(4).any(|t| {
                (t[0].is("self") && t[2].is("skipTest") || t[0].is("pytest") && t[2].is("skip"))
                    && t[1].is(".")
                    && t[3].is("(")
            });
            let skipped_test =
                skipped || skipped_in_body || class_body.is_some_and(|(_, skipped)| skipped);
            if skipped_test
                || body
                    .iter()
                    .any(|t| !t.literal && !t.is("pass") && !t.is("."))
            {
                tests.push((name.text, skipped_test));
            }
            index = body_end;
            skipped = false;
            continue;
        }
        skipped = false;
        index += 1;
    }
    tests
}

fn python_body_colon(tokens: &[SourceToken<'_>], start: usize) -> Option<usize> {
    let mut index = start;
    while let Some(token) = tokens
        .get(index)
        .filter(|token| token.line == tokens[start - 1].line)
    {
        if token.is(":") {
            return Some(index);
        }
        index = group_end(tokens, index, "[", "]").map_or(index + 1, |end| end + 1);
    }
    None
}

fn javascript_test_declarations<'a>(tokens: &[SourceToken<'a>]) -> Vec<(&'a str, bool)> {
    let mut tests = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if !(token.is("test") || token.is("it")) || index > 0 && token_is(tokens, index - 1, ".") {
            continue;
        }
        let (call, skipped) = if token_is(tokens, index + 1, ".") {
            match tokens.get(index + 2).map(|t| t.text) {
                Some("skip" | "todo" | "fixme") => (index + 3, true),
                Some("only") => (index + 3, false),
                _ => continue,
            }
        } else {
            (index + 1, false)
        };
        let Some(end) = group_end(tokens, call, "(", ")") else {
            continue;
        };
        let Some(name) = tokens.get(call + 1).filter(|t| t.literal).and_then(|t| {
            t.text
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .or_else(|| t.text.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        }) else {
            continue;
        };
        if skipped
            || token_is(tokens, call + 2, ",") && javascript_test_body(&tokens[call + 3..end])
        {
            tests.push((name, skipped));
        }
    }
    tests
}

fn javascript_test_body(tokens: &[SourceToken<'_>]) -> bool {
    let start = usize::from(token_is(tokens, 0, "async"));
    if token_is(tokens, start, "function") {
        return tokens.iter().enumerate().skip(start + 1).any(|(index, t)| {
            t.is("{") && group_end(tokens, index, "{", "}").is_some_and(|end| end > index + 1)
        });
    }
    let params_end = group_end(tokens, start, "(", ")").unwrap_or(start);
    token_is(tokens, params_end + 1, "=")
        && token_is(tokens, params_end + 2, ">")
        && tokens.get(params_end + 3).is_some_and(|t| {
            if t.is("{") {
                group_end(tokens, params_end + 3, "{", "}").is_some_and(|end| end > params_end + 4)
            } else {
                !t.literal
            }
        })
}

struct TestSourceScan<'a> {
    repo: &'a Path,
    root: &'a Path,
    entries_left: usize,
    files_left: usize,
    bytes_left: usize,
}

impl<'a> TestSourceScan<'a> {
    fn new(repo: &'a Path, root: &'a Path) -> Self {
        Self {
            repo,
            root,
            entries_left: MAX_TEST_SCAN_ENTRIES,
            files_left: MAX_TEST_SCAN_FILES,
            bytes_left: MAX_TEST_SCAN_BYTES,
        }
    }

    fn walk(
        &mut self,
        dir: &Path,
        depth: usize,
        visit: &mut impl FnMut(&Path, TestSourceLanguage, &str) -> Result<(), String>,
    ) -> Result<(), String> {
        if !self.path_allowed(
            dir,
            PathAccess::ListSearch {
                requested_depth: Some(1),
            },
        )? {
            return Ok(());
        }
        let entries = fs::read_dir(dir).map_err(|e| test_source_error(dir, e))?;
        for entry in entries {
            self.entries_left = self
                .entries_left
                .checked_sub(1)
                .ok_or("LIVE_TEST_SCAN_LIMIT: tests/ exceeds the directory-entry budget")?;
            let entry = entry.map_err(|e| test_source_error(dir, e))?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|e| test_source_error(&path, e))?;
            if file_type.is_dir() && depth < MAX_TEST_SOURCE_DEPTH {
                self.walk(&path, depth + 1, visit)?;
            } else if file_type.is_file()
                && let Some(language) = TestSourceLanguage::from_path(&path)
                && self.path_allowed(&path, PathAccess::Read)?
            {
                self.files_left = self
                    .files_left
                    .checked_sub(1)
                    .ok_or("LIVE_TEST_SCAN_LIMIT: tests/ exceeds the source-file budget")?;
                let limit = self.bytes_left.min(MAX_TEST_SOURCE_BYTES);
                let content = read_scoped_test_source(&path, limit)?;
                self.bytes_left -= content.len();
                visit(&path, language, &content)?;
            }
        }
        Ok(())
    }

    fn path_allowed(&self, path: &Path, access: PathAccess) -> Result<bool, String> {
        let Some(raw) = path.to_str() else {
            return Ok(false);
        };
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case(".git"))
            || check_forbidden_zones_lexical(raw, raw).is_err()
        {
            return Ok(false);
        }
        let canonical = fs::canonicalize(path).map_err(|e| test_source_error(path, e))?;
        if canonical != path || !canonical.starts_with(self.root) {
            return Err(test_source_error(
                path,
                "source escaped the canonical tests/ path",
            ));
        }
        Ok(
            validate_path_with_max_depth(self.repo, self.repo, raw, access, MAX_TEST_SOURCE_DEPTH)
                .is_ok_and(|validated| validated.canonical_or_norm == canonical),
        )
    }
}

fn test_source_error(path: &Path, detail: impl std::fmt::Display) -> String {
    format!("LIVE_TEST_SCAN_FAILED: '{}': {detail}", path.display())
}

fn read_scoped_test_source(path: &Path, limit: usize) -> Result<String, String> {
    let bound = limit as u64;
    let size_error = || {
        format!(
            "LIVE_TEST_SCAN_LIMIT: source '{}' exceeds the per-file or aggregate byte budget",
            path.display()
        )
    };
    let before = fs::symlink_metadata(path).map_err(|e| test_source_error(path, e))?;
    if !before.is_file() {
        return Err(test_source_error(
            path,
            "source is no longer a regular file",
        ));
    }
    if before.len() > bound {
        return Err(size_error());
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let nofollow = crate::traversal_ledger::O_NOFOLLOW_FLAG;
        if nofollow == 0 {
            return Err(test_source_error(
                path,
                "non-symlink source reads are unsupported",
            ));
        }
        let nonblocking = if cfg!(target_os = "macos") {
            0x4
        } else {
            0o4000
        };
        options.custom_flags(nofollow | nonblocking);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path).map_err(|e| test_source_error(path, e))?;
    let opened = file.metadata().map_err(|e| test_source_error(path, e))?;
    let canonical = fs::canonicalize(path).map_err(|e| test_source_error(path, e))?;
    let named = fs::symlink_metadata(path).map_err(|e| test_source_error(path, e))?;
    if canonical != path || !opened.is_file() || !named.is_file() || opened.len() != before.len() {
        return Err(test_source_error(path, "source changed while opening"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened_identity = (opened.dev(), opened.ino());
        if opened_identity != (before.dev(), before.ino())
            || opened_identity != (named.dev(), named.ino())
            || opened.nlink() != 1
        {
            return Err(test_source_error(
                path,
                "source identity is shared or changed while opening",
            ));
        }
    }
    let mut source = String::new();
    (&mut file)
        .take(bound + 1)
        .read_to_string(&mut source)
        .map_err(|e| test_source_error(path, e))?;
    if source.len() > limit {
        return Err(size_error());
    }
    if source.len() as u64 != opened.len() {
        return Err(test_source_error(path, "source changed while reading"));
    }
    Ok(source)
}

/// Deterministic fault-isolation solver (`F27`).
pub fn triangulate_faults(
    rules: &[TestAttributionRule],
    failing_tests: &[String],
    passing_tests: &[String],
) -> SuspectVerdict {
    let fail_set: BTreeSet<&str> = failing_tests.iter().map(String::as_str).collect();
    let pass_set: BTreeSet<&str> = passing_tests.iter().map(String::as_str).collect();

    let failing_rules: Vec<&TestAttributionRule> = rules
        .iter()
        .filter(|r| fail_set.contains(r.test_name.as_str()))
        .collect();

    if failing_rules.is_empty() {
        return SuspectVerdict::InconclusiveAskMaster {
            reason: "no failing tests matched test_attribution.toml rules".to_string(),
        };
    }

    // Track isolated (non-boundary) unit test failures & passes per task
    let mut isolated_failures_by_task: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut isolated_passes_by_task: BTreeSet<&str> = BTreeSet::new();

    for r in rules {
        let is_isolated = r.secondary_suspects.is_empty() && r.boundary_interfaces.is_empty();
        if is_isolated {
            if fail_set.contains(r.test_name.as_str()) {
                isolated_failures_by_task
                    .entry(r.primary_suspect.as_str())
                    .or_default()
                    .push(r.test_name.clone());
            } else if pass_set.contains(r.test_name.as_str()) {
                isolated_passes_by_task.insert(r.primary_suspect.as_str());
            }
        }
    }

    // Case 1: Boundary test failed; check whether any secondary neighbor broke or seam conflicted
    for r in &failing_rules {
        if !r.secondary_suspects.is_empty() {
            let primary_isolated_failed =
                isolated_failures_by_task.contains_key(r.primary_suspect.as_str());
            let failing_secondaries: Vec<&String> = r
                .secondary_suspects
                .iter()
                .filter(|sec| isolated_failures_by_task.contains_key(sec.as_str()))
                .collect();

            if !primary_isolated_failed && let Some(sec) = failing_secondaries.first() {
                return SuspectVerdict::BlockedByNeighbor {
                    victim: r.primary_suspect.clone(),
                    neighbor_suspect: (*sec).clone(),
                    boundary_test: r.test_name.clone(),
                };
            }

            let all_isolated_green = !primary_isolated_failed
                && failing_secondaries.is_empty()
                && isolated_passes_by_task.contains(r.primary_suspect.as_str())
                && r.secondary_suspects
                    .iter()
                    .all(|s| isolated_passes_by_task.contains(s.as_str()));
            if all_isolated_green && !r.boundary_interfaces.is_empty() {
                let task_b = if r.secondary_suspects.len() == 1 {
                    r.secondary_suspects[0].clone()
                } else {
                    r.secondary_suspects.join("+")
                };
                return SuspectVerdict::SeamOrSpecConflict {
                    task_a: r.primary_suspect.clone(),
                    task_b,
                    boundary_test: r.test_name.clone(),
                };
            }
        }
    }

    // Case 2: All failing tests point to a single primary suspect AND every secondary
    // suspect on any failing boundary test has been cleared by a passing standalone test
    let primaries: BTreeSet<&str> = failing_rules
        .iter()
        .map(|r| r.primary_suspect.as_str())
        .collect();
    let uneliminated_secondaries: BTreeSet<&str> = failing_rules
        .iter()
        .flat_map(|r| r.secondary_suspects.iter().map(String::as_str))
        .filter(|sec| !isolated_passes_by_task.contains(sec))
        .collect();

    if primaries.len() == 1 && uneliminated_secondaries.is_empty() {
        let suspect = (*primaries.iter().next().unwrap_or(&"")).to_string();
        return SuspectVerdict::SuspectIsolated {
            primary_suspect: suspect,
            failing_tests: failing_rules.iter().map(|r| r.test_name.clone()).collect(),
        };
    }

    if !uneliminated_secondaries.is_empty() {
        return SuspectVerdict::InconclusiveAskMaster {
            reason: format!(
                "boundary test failed without standalone pass/fail disambiguation across primary ({}) and secondary ({}) suspects",
                primaries.into_iter().collect::<Vec<_>>().join(", "),
                uneliminated_secondaries
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
    }

    SuspectVerdict::InconclusiveAskMaster {
        reason: format!(
            "multiple disjoint primary suspects implicated ({})",
            primaries.into_iter().collect::<Vec<_>>().join(", ")
        ),
    }
}

fn parse_toml_str(raw: &str) -> Result<String, String> {
    let t = raw.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        Ok(t[1..t.len() - 1].to_string())
    } else {
        Err(format!("expected quoted string, got '{t}'"))
    }
}

fn parse_toml_str_array(raw: &str) -> Result<Vec<String>, String> {
    let t = raw.trim();
    if !(t.starts_with('[') && t.ends_with(']')) {
        return Err(format!("expected [...] array, got '{t}'"));
    }
    let inner = t[1..t.len() - 1].trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for item in inner.split(',') {
        let trimmed = item.trim();
        if !trimmed.is_empty() {
            out.push(parse_toml_str(trimmed)?);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod source_declaration_tests {
    use super::{MAX_TEST_SOURCE_BYTES, TestSourceLanguage, TestSourceScan, test_declarations};
    use std::fs;
    use std::path::PathBuf;

    struct ScanFixture(PathBuf);

    impl ScanFixture {
        fn new(prefix: &str) -> Self {
            let repo = std::env::current_dir()
                .expect("test cwd")
                .join(format!("live-test-scan-{prefix}-{}", std::process::id()));
            fs::create_dir(&repo).expect("new scan fixture");
            let fixture = Self(repo);
            fs::create_dir(fixture.0.join("tests")).expect("tests directory");
            fixture
        }
    }

    impl Drop for ScanFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn scanner_visits_supported_sources_only_in_allowed_directories() {
        let fixture = ScanFixture::new("paths");
        let tests = fixture.0.join("tests");
        for dir in ["vendor", ".cache", "node_modules", "integration"] {
            let path = tests.join(dir);
            fs::create_dir(&path).expect("fixture subdirectory");
            fs::write(path.join("example.rs"), "const COUNT: usize = 3;\n")
                .expect("fixture source");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let fixture_dir = fixture.0.join("other");
            fs::create_dir(&fixture_dir).expect("non-test directory");
            fs::write(fixture_dir.join("outside.rs"), "").expect("fixture source");
            symlink(fixture_dir, tests.join("alias")).expect("fixture directory alias");
        }
        let mut scan = TestSourceScan::new(&fixture.0, &tests);
        let mut visited = Vec::new();
        scan.walk(&tests, 0, &mut |path, _, _| {
            visited.push(path.to_path_buf());
            Ok(())
        })
        .expect("bounded in-scope scan");
        assert_eq!(visited, [tests.join("integration/example.rs")]);
    }

    #[test]
    fn scanner_enforces_entry_file_and_byte_budgets_before_visiting() {
        let fixture = ScanFixture::new("limits");
        let tests = fixture.0.join("tests");
        for filename in ["one.rs", "two.rs"] {
            fs::write(tests.join(filename), "1234").expect("fixture source");
        }
        for (entries, files, bytes) in [(1, 2, 8), (2, 1, 8), (2, 2, 4)] {
            let mut scan = TestSourceScan {
                entries_left: entries,
                files_left: files,
                bytes_left: bytes,
                ..TestSourceScan::new(&fixture.0, &tests)
            };
            let mut visited = 0;
            let error = scan
                .walk(&tests, 0, &mut |_, _, _| {
                    visited += 1;
                    Ok(())
                })
                .expect_err("scan budget must fail closed");
            assert!(error.starts_with("LIVE_TEST_SCAN_LIMIT"), "{error}");
            assert_eq!(visited, 1);
        }
        let oversized = tests.join("oversized.rs");
        fs::File::create(&oversized)
            .expect("oversized source fixture")
            .set_len(MAX_TEST_SOURCE_BYTES as u64 + 1)
            .expect("oversized fixture length");
        let mut scan = TestSourceScan::new(&fixture.0, &tests);
        let error = scan
            .walk(&tests, 0, &mut |path, _, _| {
                assert_ne!(path, oversized);
                Ok(())
            })
            .expect_err("per-file cap must fail closed");
        assert!(error.starts_with("LIVE_TEST_SCAN_LIMIT"), "{error}");
    }

    #[test]
    fn rust_requires_an_attributed_function_body() {
        let source = r##"
            //! Unit tests in this module.
            const DESCRIPTION: &str = r#"Documentation for example_test"#;
            fn helper() { assert_eq!(2 + 2, 4); }
            #[test]
            fn example_test() { helper(); }
            #[test]
            #[ignore = "needs hardware"]
            fn hardware_test() { helper(); }
        "##;
        assert_eq!(
            test_declarations(source, TestSourceLanguage::Rust),
            vec![("example_test", false), ("hardware_test", true)],
        );
    }

    #[test]
    fn python_recognizes_functions_and_testcase_methods() {
        let source = r#"
"""Integration checks for arithmetic."""

def test_arithmetic():
    assert 2 + 2 == 4

@unittest.skip("needs hardware")
class HardwareCases(unittest.TestCase):
    def test_hardware(self):
        self.assertTrue(connected())
"#;
        assert_eq!(
            test_declarations(source, TestSourceLanguage::Python),
            vec![("test_arithmetic", false), ("test_hardware", true)],
        );
    }

    #[test]
    fn javascript_matches_the_registration_name() {
        let source = r#"
            const help = "Example math test";
            test("arithmetic", () => { expect(2 + 2).toBe(4); });
            it.skip("hardware", () => { expect(connected()).toBe(true); });
        "#;
        assert_eq!(
            test_declarations(source, TestSourceLanguage::JavaScript),
            vec![("arithmetic", false), ("hardware", true)],
        );
    }
}
