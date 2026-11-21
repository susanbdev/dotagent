#![forbid(unsafe_code)]

//! DAG locking, domain-floored QA coverage calculation (`F20`), `test_attribution.toml`
//! schema verifier, and deterministic fault-triangulation solver (`F27`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::breadcrumbs::{
    ExclusiveFileLockGuard, compute_arbitrary_hmac_hex, sha256_digest, swarm_state_dir,
    verify_arbitrary_hmac_hex,
};
use crate::json::JsonValue;
use crate::swarm_contracts::{
    DagTaskSpec, DomainRisk, LockedPlan, SuspectVerdict, TestAttributionRule, hex_encode,
};
use crate::unicode_guard::{ScanMode, scan_unicode};

const PLAN_LOCK_HMAC_DOMAIN: &[u8] = b"dotagent-plan-lock-v1";

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
    let lock_path = plan_lock_state_path(repo_root)?;
    let _guard = ExclusiveFileLockGuard::acquire(&lock_path)?;

    if lock_path.exists()
        && fs::metadata(&lock_path).is_ok_and(|m| m.len() > 0)
        && !allow_amend_with_human_approval
    {
        let existing = load_locked_plan_unlocked(repo_root, &lock_path)?;
        if existing.plan_sha256 != plan.plan_sha256 {
            return Err(format!(
                "PLAN_LOCK_IMMUTABLE: PLAN.lock.json already pinned at {}; pass --amend --human-approved to re-lock",
                &existing.plan_sha256[..16]
            ));
        }
    }

    let canonical = serialize_locked_tasks_canonical(&plan.plan_id, &plan.tasks);
    let recomputed_sha = hex_encode(&sha256_digest(canonical.as_bytes()));
    if recomputed_sha != plan.plan_sha256 {
        return Err(format!(
            "PLAN_LOCK_TAMPERED: in-memory plan_sha256 '{}' does not match canonical digest '{recomputed_sha}'",
            plan.plan_sha256
        ));
    }
    let record_mac =
        compute_arbitrary_hmac_hex(repo_root, PLAN_LOCK_HMAC_DOMAIN, canonical.as_bytes())?;
    let parsed_tasks = JsonValue::parse(&canonical).map_err(|e| e.to_string())?;
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
    if fs::symlink_metadata(&lock_path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(format!(
            "SYMLINK_REJECTED: PLAN.lock.json path '{}' is a symlink",
            lock_path.display()
        ));
    }
    fs::write(&lock_path, format!("{}\n", wrapper.to_json_string()))
        .map_err(|e| format!("failed writing PLAN.lock.json: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600));
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
///    attributed integration/boundary test (`boundary_interfaces` non-empty, `e2e`/`integration`/`live`
///    test name, or test body located under `tests/`).
pub fn verify_live_integration_contracts(
    repo_root: &Path,
    rules: &[TestAttributionRule],
    plan: &LockedPlan,
) -> Result<(), String> {
    verify_attribution_against_plan(rules, plan)?;

    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let mut test_files = Vec::new();
    let tests_dir = canon_repo.join("tests");
    if let Ok(meta) = fs::symlink_metadata(&tests_dir)
        && !meta.file_type().is_symlink()
        && meta.file_type().is_dir()
    {
        collect_integration_test_sources(&tests_dir, 0, &mut test_files);
    }

    let attributed_names: BTreeSet<&str> = rules.iter().map(|r| r.test_name.as_str()).collect();
    let mut names_found_in_tests_dir = BTreeSet::new();

    for (rel_path, content) in &test_files {
        let mut prev_ignored = false;
        for raw_line in content.lines() {
            let trimmed = raw_line.trim();
            if trimmed.starts_with("#[ignore")
                || trimmed.starts_with("@unittest.skip")
                || trimmed.starts_with("@pytest.mark.skip")
            {
                prev_ignored = true;
                continue;
            }
            for &tname in &attributed_names {
                if trimmed.contains(tname) {
                    names_found_in_tests_dir.insert(tname.to_string());
                    let is_js_or_py_inline_skip = (trimmed.contains("test.skip(")
                        || trimmed.contains("it.skip(")
                        || trimmed.contains("self.skipTest(")
                        || trimmed.contains("pytest.skip("))
                        && trimmed.contains(tname);
                    let is_annotated_skip = prev_ignored
                        && (trimmed.contains(&format!("fn {tname}"))
                            || trimmed.contains(&format!("def {tname}")));
                    if is_js_or_py_inline_skip || is_annotated_skip {
                        return Err(format!(
                            "SKIPPED_ATTRIBUTED_TEST_FORBIDDEN: attributed test '{tname}' is marked ignored/skipped in '{rel_path}'"
                        ));
                    }
                }
            }
            if !trimmed.is_empty()
                && !trimmed.starts_with("#[")
                && !trimmed.starts_with('@')
                && !trimmed.starts_with("//")
                && !trimmed.starts_with('#')
            {
                prev_ignored = false;
            }
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
            covers_task && names_found_in_tests_dir.contains(&r.test_name)
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

fn collect_integration_test_sources(dir: &Path, depth: usize, out: &mut Vec<(String, String)>) {
    if depth > 4 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            collect_integration_test_sources(&p, depth + 1, out);
        } else if ft.is_file() {
            let ext = p
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if matches!(ext.as_str(), "toml" | "json" | "md" | "lock" | "txt") {
                continue;
            }
            if let Ok(text) = fs::read_to_string(&p) {
                out.push((p.to_string_lossy().into_owned(), text));
            }
        }
    }
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
