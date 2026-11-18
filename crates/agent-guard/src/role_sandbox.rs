#![forbid(unsafe_code)]

//! Role-isolated execution sandboxes (`Master`, `Investigator`, `QaEngineer`,
//! `Grunt`, `AdversarialReviewer`, `ForensicCoroner`) and deterministic Rust
//! support routines for `swarm-tool`.
//!
//! Addresses hostile audit findings:
//! - `F06`: `Investigator` gets `depth <= 20` walk inside `realpath`-validated
//!   repo boundaries while keeping `/tmp`, caches, `node_modules`, `.venv`,
//!   `.env*`, and symlinks outside `repo_root` hard-blocked (`exit 2`).
//! - `F08`: `AdversarialReviewer` has zero arbitrary URL access; dependency
//!   verification runs offline against local lockfiles (`lookup_pinned_package_doc`).
//! - `F10`: Worker outputs parse strictly as typed `WorkerPacket` variants so
//!   worker prose cannot silently mutate `PLAN.lock.json`.
//! - `F21`: `MAX_ADVERSARIAL_ROUNDS = 2` enforced as an immutable Rust constant.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use crate::Decision;
use crate::breadcrumbs::{
    ExclusiveFileLockGuard, append_breadcrumb_for_path, compute_arbitrary_hmac_hex, sha256_digest,
    swarm_state_dir, verify_arbitrary_hmac_hex,
};
use crate::budget_guard::estimate_bpe_tokens;
use crate::json::JsonValue;
use crate::path_policy::{PathAccess, check_forbidden_zones_lexical, validate_path_with_max_depth};
use crate::qa_suspects::load_locked_plan;
use crate::swarm_contracts::{
    EscalationTrigger, EventOp, INVESTIGATOR_MAX_WALK_DEPTH, MAX_ADVERSARIAL_ROUNDS,
    MAX_INVESTIGATOR_PACKET_TOKENS, ReviewVerdictOutcome, SessionCapability, SwarmRole,
    WorkerPacket, hex_decode_32, hex_encode,
};
use crate::unicode_guard::{ScanMode, scan_unicode};

const CAPABILITY_HMAC_DOMAIN: &[u8] = b"DOTAGENT_SESSION_CAPABILITY_V1";
const ACTIVE_SLOT_HMAC_DOMAIN: &[u8] = b"DOTAGENT_ACTIVE_SESSIONS_REGISTRY_V2";

#[derive(Debug, Clone, Default)]
struct ActiveSessionRegistry {
    open_sessions: Vec<String>,
    hook_bindings: BTreeMap<String, String>,
}

fn encode_registry_mac_payload(reg: &ActiveSessionRegistry) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(reg.open_sessions.len() as u32).to_be_bytes());
    for sid in &reg.open_sessions {
        buf.extend_from_slice(&(sid.len() as u32).to_be_bytes());
        buf.extend_from_slice(sid.as_bytes());
    }
    buf.extend_from_slice(&(reg.hook_bindings.len() as u32).to_be_bytes());
    for (k, v) in &reg.hook_bindings {
        buf.extend_from_slice(&(k.len() as u32).to_be_bytes());
        buf.extend_from_slice(k.as_bytes());
        buf.extend_from_slice(&(v.len() as u32).to_be_bytes());
        buf.extend_from_slice(v.as_bytes());
    }
    buf
}

fn compute_capability_mac_hex(repo_root: &Path, cap: &SessionCapability) -> Result<String, String> {
    let mut payload = Vec::with_capacity(256);
    let push_str = |buf: &mut Vec<u8>, s: &str| {
        buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
        buf.extend_from_slice(s.as_bytes());
    };
    let push_vec = |buf: &mut Vec<u8>, items: &[String]| {
        buf.extend_from_slice(&(items.len() as u32).to_be_bytes());
        for item in items {
            buf.extend_from_slice(&(item.len() as u32).to_be_bytes());
            buf.extend_from_slice(item.as_bytes());
        }
    };

    push_str(&mut payload, &cap.session_id);
    push_str(&mut payload, cap.role.as_str_id());
    push_str(&mut payload, &cap.task_id);
    payload.extend_from_slice(&cap.attempt.to_be_bytes());
    push_str(&mut payload, &cap.repo_sha256);
    push_str(&mut payload, &cap.plan_sha256);
    push_vec(&mut payload, &cap.assigned_read_paths);
    push_vec(&mut payload, &cap.allowed_write_paths);
    push_vec(&mut payload, &cap.assigned_tests);
    match &cap.last_green_tree_oid {
        Some(oid) => {
            payload.push(1);
            push_str(&mut payload, oid);
        }
        None => payload.push(0),
    }
    payload.extend_from_slice(&cap.consecutive_test_failures.to_be_bytes());
    payload.extend_from_slice(&cap.blocked_scope_attempts.to_be_bytes());
    payload.extend_from_slice(&cap.malicious_flags.to_be_bytes());

    compute_arbitrary_hmac_hex(repo_root, CAPABILITY_HMAC_DOMAIN, &payload)
}

pub fn sessions_dir(repo_root: &Path) -> Result<PathBuf, String> {
    let dir = swarm_state_dir(repo_root)?.join("sessions");
    if !dir.is_dir() {
        fs::create_dir_all(&dir).map_err(|e| format!("failed creating swarm sessions dir: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
    }
    Ok(dir)
}

pub fn active_session_slot_path(repo_root: &Path) -> Result<PathBuf, String> {
    Ok(sessions_dir(repo_root)?.join("active_sessions.json"))
}

fn load_registry_unlocked(repo_root: &Path, path: &Path) -> Result<ActiveSessionRegistry, String> {
    if !path.exists() {
        return Ok(ActiveSessionRegistry::default());
    }
    let raw = fs::read_to_string(path).map_err(|e| {
        format!("FORGED_ACTIVE_SESSION_SLOT: cannot read active_sessions.json: {e}")
    })?;
    if raw.trim().is_empty() {
        return Ok(ActiveSessionRegistry::default());
    }
    let v = JsonValue::parse(&raw)
        .map_err(|e| format!("FORGED_ACTIVE_SESSION_SLOT: corrupt active_sessions.json: {e}"))?;
    let open_arr = v
        .get("open_sessions")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| {
            "FORGED_ACTIVE_SESSION_SLOT: missing open_sessions array in active_sessions.json"
                .to_string()
        })?;
    let mut open_sessions = Vec::with_capacity(open_arr.len());
    for item in open_arr {
        let s = item
            .as_str()
            .filter(|x| !x.trim().is_empty())
            .ok_or_else(|| {
                "FORGED_ACTIVE_SESSION_SLOT: invalid session_id in open_sessions".to_string()
            })?;
        open_sessions.push(s.to_string());
    }

    let mut hook_bindings = BTreeMap::new();
    if let Some(JsonValue::Object(entries)) = v.get("hook_bindings") {
        for (k, val) in entries {
            let target = val.as_str().ok_or_else(|| {
                "FORGED_ACTIVE_SESSION_SLOT: invalid hook_bindings target".to_string()
            })?;
            hook_bindings.insert(k.clone(), target.to_string());
        }
    }

    let recorded_mac = v
        .get("record_mac")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            "FORGED_ACTIVE_SESSION_SLOT: missing record_mac in active_sessions.json".to_string()
        })?;
    let reg = ActiveSessionRegistry {
        open_sessions,
        hook_bindings,
    };
    let payload = encode_registry_mac_payload(&reg);
    verify_arbitrary_hmac_hex(repo_root, ACTIVE_SLOT_HMAC_DOMAIN, &payload, recorded_mac).map_err(
        |_| {
            "FORGED_ACTIVE_SESSION_SLOT: active_sessions.json HMAC authentication failed"
                .to_string()
        },
    )?;
    Ok(reg)
}

fn save_registry_unlocked(
    repo_root: &Path,
    path: &Path,
    reg: &ActiveSessionRegistry,
) -> Result<(), String> {
    let payload = encode_registry_mac_payload(reg);
    let mac = compute_arbitrary_hmac_hex(repo_root, ACTIVE_SLOT_HMAC_DOMAIN, &payload)?;
    let bindings_obj = JsonValue::Object(
        reg.hook_bindings
            .iter()
            .map(|(k, v)| (k.clone(), JsonValue::Str(v.clone())))
            .collect(),
    );
    let obj = JsonValue::Object(vec![
        (
            "open_sessions".to_string(),
            JsonValue::Array(
                reg.open_sessions
                    .iter()
                    .cloned()
                    .map(JsonValue::Str)
                    .collect(),
            ),
        ),
        ("hook_bindings".to_string(), bindings_obj),
        ("record_mac".to_string(), JsonValue::Str(mac)),
    ]);
    fs::write(path, format!("{}\n", obj.to_json_string()))
        .map_err(|e| format!("failed writing active_sessions.json: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Registers an open non-Master session capability WITHOUT clobbering concurrent parallel-wave sessions.
pub fn set_active_session_slot(repo_root: &Path, session_id: &str) -> Result<(), String> {
    let path = active_session_slot_path(repo_root)?;
    let _guard = ExclusiveFileLockGuard::acquire(&path)?;
    let mut reg = load_registry_unlocked(repo_root, &path)?;
    if !reg.open_sessions.iter().any(|s| s == session_id) {
        reg.open_sessions.push(session_id.to_string());
    }
    save_registry_unlocked(repo_root, &path, &reg)
}

/// Closes a single open session (`Some(sid)`) or all open sessions (`None`), preserving concurrent siblings.
pub fn close_open_session(repo_root: &Path, session_id: Option<&str>) -> Result<(), String> {
    let path = active_session_slot_path(repo_root)?;
    let _guard = ExclusiveFileLockGuard::acquire(&path)?;
    if !path.exists() {
        return Ok(());
    }
    let mut reg = load_registry_unlocked(repo_root, &path)?;
    match session_id {
        Some(sid) => {
            reg.open_sessions.retain(|s| s != sid);
            reg.hook_bindings.retain(|_, v| v != sid);
        }
        None => {
            reg.open_sessions.clear();
            reg.hook_bindings.clear();
        }
    }
    save_registry_unlocked(repo_root, &path, &reg)
}

pub fn clear_active_session_slot(repo_root: &Path) -> Result<(), String> {
    close_open_session(repo_root, None)
}

pub fn bind_hook_session_to_swarm_session(
    repo_root: &Path,
    hook_session_id: &str,
    swarm_session_id: &str,
) -> Result<(), String> {
    let hs = hook_session_id.trim();
    if hs.is_empty() || hs == "default" || hs.starts_with("swm_") {
        return Ok(());
    }
    let path = active_session_slot_path(repo_root)?;
    let _guard = ExclusiveFileLockGuard::acquire(&path)?;
    let mut reg = load_registry_unlocked(repo_root, &path)?;
    if reg.open_sessions.iter().any(|s| s == swarm_session_id)
        && reg.hook_bindings.get(hs).map(String::as_str) != Some(swarm_session_id)
    {
        reg.hook_bindings
            .insert(hs.to_string(), swarm_session_id.to_string());
        save_registry_unlocked(repo_root, &path, &reg)?;
    }
    Ok(())
}

/// Loads all currently open non-Master session capabilities in deterministic registration order.
pub fn load_open_session_capabilities(repo_root: &Path) -> Result<Vec<SessionCapability>, String> {
    let path = active_session_slot_path(repo_root)?;
    let _guard = ExclusiveFileLockGuard::acquire(&path)?;
    let reg = load_registry_unlocked(repo_root, &path)?;
    let mut out = Vec::with_capacity(reg.open_sessions.len());
    for sid in &reg.open_sessions {
        out.push(load_session_capability(repo_root, sid)?);
    }
    Ok(out)
}

fn lookup_bound_hook_capability(
    repo_root: &Path,
    hook_session_id: &str,
) -> Result<Option<SessionCapability>, String> {
    let hs = hook_session_id.trim();
    if hs.is_empty() || hs == "default" || hs.starts_with("swm_") {
        return Ok(None);
    }
    let path = active_session_slot_path(repo_root)?;
    let _guard = ExclusiveFileLockGuard::acquire(&path)?;
    let reg = load_registry_unlocked(repo_root, &path)?;
    if let Some(target_sid) = reg.hook_bindings.get(hs)
        && reg.open_sessions.iter().any(|s| s == target_sid)
    {
        return Ok(Some(load_session_capability(repo_root, target_sid)?));
    }
    Ok(None)
}

/// Returns `Ok(None)` when 0 worker sessions are open, `Ok(Some(cap))` when exactly 1 is open,
/// and fails closed (`AMBIGUOUS_CONCURRENT_SWARM_SESSIONS`) when `>= 2` sessions are open concurrently
/// without an explicit `session_id`.
pub fn load_active_session_slot(repo_root: &Path) -> Result<Option<SessionCapability>, String> {
    let mut open = load_open_session_capabilities(repo_root)?;
    match open.len() {
        0 => Ok(None),
        1 => Ok(open.pop()),
        _ => {
            let ids: Vec<&str> = open.iter().map(|c| c.session_id.as_str()).collect();
            Err(format!(
                "AMBIGUOUS_CONCURRENT_SWARM_SESSIONS: {} concurrent worker sessions [{}] are open; pass --session <swm_id> or set AGENT_GUARD_SESSION_ID",
                open.len(),
                ids.join(", ")
            ))
        }
    }
}

pub fn session_capability_path(repo_root: &Path, session_id: &str) -> Result<PathBuf, String> {
    let safe: String = session_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
        .take(96)
        .collect();
    if safe.is_empty() {
        return Err("empty session_id".to_string());
    }
    Ok(sessions_dir(repo_root)?.join(format!("{safe}.json")))
}

pub fn mint_session_capability(
    repo_root: &Path,
    role: SwarmRole,
    task_id: &str,
    attempt: u32,
) -> Result<SessionCapability, String> {
    if role == SwarmRole::StandardCoding {
        return Err("mint-session requires an explicit swarm role".to_string());
    }
    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let repo_sha256 = hex_encode(&sha256_digest(canon_repo.to_string_lossy().as_bytes()));

    let locked = load_locked_plan(&canon_repo)?;
    let task_spec = locked
        .tasks
        .iter()
        .find(|t| t.task_id == task_id)
        .ok_or_else(|| format!("task '{task_id}' not found in locked PLAN.lock.json"))?;

    let seed = format!(
        "{}:{}:{}:{}:{}",
        repo_sha256,
        locked.plan_sha256,
        role.as_str_id(),
        task_id,
        attempt
    );
    let short_tag = &hex_encode(&sha256_digest(seed.as_bytes()))[..10];
    let clean_task: String = task_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let session_id = format!(
        "swm_{}_{}_a{}_{}",
        role.as_str_id().replace('-', ""),
        clean_task,
        attempt.max(1),
        short_tag
    );

    let cap = SessionCapability {
        session_id: session_id.clone(),
        role,
        task_id: task_id.to_string(),
        attempt: attempt.max(1),
        repo_sha256,
        plan_sha256: locked.plan_sha256.clone(),
        assigned_read_paths: task_spec.assigned_read_paths.clone(),
        allowed_write_paths: task_spec.allowed_write_paths.clone(),
        assigned_tests: task_spec.assigned_tests.clone(),
        last_green_tree_oid: None,
        consecutive_test_failures: 0,
        blocked_scope_attempts: 0,
        malicious_flags: 0,
    };
    save_session_capability(&canon_repo, &cap)?;
    if role != SwarmRole::Master {
        set_active_session_slot(&canon_repo, &session_id)?;
    }

    let plan_bytes = hex_decode_32(&locked.plan_sha256).unwrap_or([0u8; 32]);
    let _ = append_breadcrumb_for_path(
        &canon_repo,
        &session_id,
        task_id,
        plan_bytes,
        EventOp::SessionMint,
        "PLAN.lock.json",
        None,
        plan_bytes,
    );

    Ok(cap)
}

pub fn save_session_capability(repo_root: &Path, cap: &SessionCapability) -> Result<(), String> {
    let path = session_capability_path(repo_root, &cap.session_id)?;
    let record_mac = compute_capability_mac_hex(repo_root, cap)?;
    let obj = JsonValue::Object(vec![
        (
            "session_id".to_string(),
            JsonValue::Str(cap.session_id.clone()),
        ),
        (
            "role".to_string(),
            JsonValue::Str(cap.role.as_str_id().to_string()),
        ),
        ("task_id".to_string(), JsonValue::Str(cap.task_id.clone())),
        (
            "attempt".to_string(),
            JsonValue::Number(f64::from(cap.attempt)),
        ),
        (
            "repo_sha256".to_string(),
            JsonValue::Str(cap.repo_sha256.clone()),
        ),
        (
            "plan_sha256".to_string(),
            JsonValue::Str(cap.plan_sha256.clone()),
        ),
        (
            "assigned_read_paths".to_string(),
            JsonValue::Array(
                cap.assigned_read_paths
                    .iter()
                    .cloned()
                    .map(JsonValue::Str)
                    .collect(),
            ),
        ),
        (
            "allowed_write_paths".to_string(),
            JsonValue::Array(
                cap.allowed_write_paths
                    .iter()
                    .cloned()
                    .map(JsonValue::Str)
                    .collect(),
            ),
        ),
        (
            "assigned_tests".to_string(),
            JsonValue::Array(
                cap.assigned_tests
                    .iter()
                    .cloned()
                    .map(JsonValue::Str)
                    .collect(),
            ),
        ),
        (
            "last_green_tree_oid".to_string(),
            cap.last_green_tree_oid
                .clone()
                .map(JsonValue::Str)
                .unwrap_or(JsonValue::Null),
        ),
        (
            "consecutive_test_failures".to_string(),
            JsonValue::Number(f64::from(cap.consecutive_test_failures)),
        ),
        (
            "blocked_scope_attempts".to_string(),
            JsonValue::Number(f64::from(cap.blocked_scope_attempts)),
        ),
        (
            "malicious_flags".to_string(),
            JsonValue::Number(f64::from(cap.malicious_flags)),
        ),
        ("record_mac".to_string(), JsonValue::Str(record_mac)),
    ]);
    fs::write(&path, format!("{}\n", obj.to_json_string()))
        .map_err(|e| format!("failed writing session capability: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn load_session_capability(
    repo_root: &Path,
    session_id: &str,
) -> Result<SessionCapability, String> {
    let path = session_capability_path(repo_root, session_id)?;
    let raw = fs::read_to_string(&path)
        .map_err(|e| format!("session capability '{}' not found: {e}", session_id))?;
    let v = JsonValue::parse(&raw).map_err(|e| format!("corrupt session JSON: {e}"))?;
    let role_str = v
        .get("role")
        .and_then(JsonValue::as_str)
        .unwrap_or("standard");
    let role =
        SwarmRole::from_str_id(role_str).ok_or_else(|| format!("unknown role '{role_str}'"))?;

    let read_arr = |key: &str| -> Vec<String> {
        v.get(key)
            .and_then(JsonValue::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(JsonValue::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default()
    };

    let cap = SessionCapability {
        session_id: v
            .get("session_id")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string(),
        role,
        task_id: v
            .get("task_id")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string(),
        attempt: v.get("attempt").and_then(JsonValue::as_u64).unwrap_or(1) as u32,
        repo_sha256: v
            .get("repo_sha256")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string(),
        plan_sha256: v
            .get("plan_sha256")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string(),
        assigned_read_paths: read_arr("assigned_read_paths"),
        allowed_write_paths: read_arr("allowed_write_paths"),
        assigned_tests: read_arr("assigned_tests"),
        last_green_tree_oid: v
            .get("last_green_tree_oid")
            .and_then(JsonValue::as_str)
            .map(String::from),
        consecutive_test_failures: v
            .get("consecutive_test_failures")
            .and_then(JsonValue::as_u64)
            .unwrap_or(0) as u32,
        blocked_scope_attempts: v
            .get("blocked_scope_attempts")
            .and_then(JsonValue::as_u64)
            .unwrap_or(0) as u32,
        malicious_flags: v
            .get("malicious_flags")
            .and_then(JsonValue::as_u64)
            .unwrap_or(0) as u32,
    };

    if cap.session_id != session_id {
        return Err(format!(
            "FORGED_SESSION_CAPABILITY: session_id mismatch (expected '{session_id}', found '{}')",
            cap.session_id
        ));
    }
    let recorded_mac = v
        .get("record_mac")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            format!("FORGED_SESSION_CAPABILITY: missing record_mac on session '{session_id}'")
        })?;
    let expected_mac = compute_capability_mac_hex(repo_root, &cap)?;
    if recorded_mac != expected_mac {
        return Err(format!(
            "FORGED_SESSION_CAPABILITY: HMAC verification failed for session '{session_id}'"
        ));
    }

    Ok(cap)
}

pub fn list_session_capabilities(repo_root: &Path) -> Result<Vec<SessionCapability>, String> {
    let dir = sessions_dir(repo_root)?;
    let mut out = Vec::new();
    let entries = fs::read_dir(&dir).map_err(|e| e.to_string())?;
    for entry in entries.flatten() {
        let p = entry.path();
        if p.extension().is_some_and(|e| e == "json")
            && let Some(stem) = p.file_stem().and_then(|s| s.to_str())
            && stem.starts_with("swm_")
        {
            out.push(load_session_capability(repo_root, stem)?);
        }
    }
    out.sort_by(|a, b| a.session_id.cmp(&b.session_id));
    Ok(out)
}

/// Resolves active `SwarmRole` and optional minted `SessionCapability` for a hook turn:
/// 1. Explicit Swarm `session_id` (`AGENT_GUARD_SESSION_ID` or `"swm_*"` hook ID) -> fail-closed HMAC check
///    (and binds non-default hook UUID `session_id` to that Swarm session).
/// 2. Explicit hook-UUID binding in `active_sessions.json` (`lookup_bound_hook_capability`).
/// 3. Active repo-scoped capability registry (`active_sessions.json`):
///    - Supervising `AGENT_GUARD_ROLE=master` remains operational even when `>= 2` parallel-wave workers are open.
///    - Exactly `1` open worker session -> enforces worker jail automatically with zero env friction.
///    - `>= 2` open worker sessions without explicit `session_id` -> fails closed (`AMBIGUOUS_CONCURRENT_SWARM_SESSIONS`).
/// 4. Ambient `AGENT_GUARD_ROLE`, defaulting to `StandardCoding` when no Swarm session is active.
pub fn resolve_active_role(
    repo_root: &Path,
    session_id: &str,
) -> Result<(SwarmRole, Option<SessionCapability>), String> {
    let env_role = match std::env::var("AGENT_GUARD_ROLE") {
        Ok(raw_role) if !raw_role.trim().is_empty() => {
            let trimmed = raw_role.trim();
            Some(
                SwarmRole::from_str_id(trimmed)
                    .ok_or_else(|| format!("unrecognized AGENT_GUARD_ROLE '{trimmed}'"))?,
            )
        }
        _ => None,
    };

    let explicit_sid = std::env::var("AGENT_GUARD_SESSION_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let hs = session_id.trim();
            if hs.starts_with("swm_") {
                Some(hs.to_string())
            } else {
                None
            }
        });

    if let Some(sid) = explicit_sid {
        let cap = load_session_capability(repo_root, &sid)?;
        if let Some(er) = env_role
            && er != cap.role
        {
            return Err(format!(
                "ROLE_CAPABILITY_MISMATCH: AGENT_GUARD_ROLE '{}' conflicts with minted session '{}' capability role '{}'",
                er.as_str_id(),
                c_id(&cap),
                cap.role.as_str_id()
            ));
        }
        let _ = bind_hook_session_to_swarm_session(repo_root, session_id, &cap.session_id);
        return Ok((cap.role, Some(cap)));
    }

    if let Some(bound_cap) = lookup_bound_hook_capability(repo_root, session_id)? {
        match env_role {
            None => return Ok((bound_cap.role, Some(bound_cap))),
            Some(er) if er == bound_cap.role => return Ok((bound_cap.role, Some(bound_cap))),
            Some(SwarmRole::Master) => return Ok((SwarmRole::Master, None)),
            Some(er) => {
                return Err(format!(
                    "ROLE_CAPABILITY_MISMATCH: AGENT_GUARD_ROLE '{}' conflicts with bound session '{}' capability role '{}'",
                    er.as_str_id(),
                    bound_cap.session_id,
                    bound_cap.role.as_str_id()
                ));
            }
        }
    }

    if env_role == Some(SwarmRole::Master) {
        let _ = load_open_session_capabilities(repo_root)?;
        return Ok((SwarmRole::Master, None));
    }

    if let Some(slot_cap) = load_active_session_slot(repo_root)? {
        match env_role {
            None => return Ok((slot_cap.role, Some(slot_cap))),
            Some(er) if er == slot_cap.role => return Ok((slot_cap.role, Some(slot_cap))),
            Some(SwarmRole::Master) => return Ok((SwarmRole::Master, None)),
            Some(er) => {
                return Err(format!(
                    "ROLE_CAPABILITY_MISMATCH: AGENT_GUARD_ROLE '{}' conflicts with active repo capability slot '{}' (role '{}')",
                    er.as_str_id(),
                    slot_cap.session_id,
                    slot_cap.role.as_str_id()
                ));
            }
        }
    }

    if let Some(er) = env_role {
        return Ok((er, None));
    }
    Ok((SwarmRole::StandardCoding, None))
}

fn c_id(cap: &SessionCapability) -> &str {
    &cap.session_id
}

/// Returns the permitted directory walk depth for `role` (`20` for `Investigator`, `2` otherwise).
pub fn max_walk_depth_for_role(role: SwarmRole) -> usize {
    match role {
        SwarmRole::Investigator => INVESTIGATOR_MAX_WALK_DEPTH,
        _ => crate::path_policy::MAX_DIRECTORY_WALK_DEPTH,
    }
}

/// Enforces role-specific tool, path, search, and network sandboxes BEFORE execution.
pub fn enforce_role_pre_tool(
    role: SwarmRole,
    cap: Option<&SessionCapability>,
    tool_name: &str,
    input: &JsonValue,
    repo_root: &Path,
    cwd: &Path,
) -> Option<Decision> {
    if role == SwarmRole::StandardCoding {
        return None;
    }

    let norm = tool_name.to_ascii_lowercase();
    let is_read_tool = matches!(
        norm.as_str(),
        "read" | "view_file" | "read_file" | "notebookread" | "beforereadfile" | "open_file"
    );
    let is_write_tool = matches!(
        norm.as_str(),
        "write"
            | "edit"
            | "multiedit"
            | "write_file"
            | "write_to_file"
            | "replace"
            | "replace_file_content"
            | "multi_replace_file_content"
            | "notebookedit"
            | "apply_patch"
            | "patch"
    );
    let is_search_tool = matches!(
        norm.as_str(),
        "grep" | "glob" | "ls" | "grep_search" | "find_by_name" | "list_dir" | "list_directory"
    );
    let is_web_tool = matches!(
        norm.as_str(),
        "webfetch" | "web_fetch" | "fetch" | "browse" | "google_browse"
    );
    let is_shell_tool = matches!(
        norm.as_str(),
        "bash"
            | "sh"
            | "shell"
            | "run_command"
            | "run_shell_command"
            | "execute_command"
            | "beforeshellexecution"
    ) || (norm.is_empty()
        && (input.get("command").is_some() || input.get("CommandLine").is_some()));

    if is_shell_tool {
        if let Some(cmd) = extract_cmd_arg(input) {
            if let Some(ns_denial) = check_role_swarm_tool_namespace(role, cmd) {
                return Some(ns_denial);
            }
        }
    }

    match role {
        SwarmRole::Master => {
            if is_write_tool {
                return Some(Decision::deny(
                    "MASTER_WRITE_FORBIDDEN",
                    "Swarm Master cannot write or edit repository files directly; delegate to QA Engineer or Grunt.",
                    false,
                ));
            }
            if is_search_tool {
                return Some(Decision::deny(
                    "MASTER_SEARCH_FORBIDDEN",
                    "Swarm Master is blind to raw source search; delegate exploration to Investigator (`swarm-investigator`).",
                    false,
                ));
            }
            if is_read_tool {
                if let Some(raw_p) = extract_path_arg(input) {
                    if let Ok(valid) =
                        validate_path_with_max_depth(repo_root, cwd, raw_p, PathAccess::Read, 2)
                    {
                        if !is_master_readable_doc_or_skill(&valid.repo_rel) {
                            return Some(Decision::deny(
                                "MASTER_SOURCE_READ_FORBIDDEN",
                                format!(
                                    "Swarm Master cannot read source file '{}' directly; delegate to Investigator.",
                                    valid.repo_rel
                                ),
                                false,
                            ));
                        }
                    }
                }
            }
            if is_shell_tool {
                if let Some(cmd) = extract_cmd_arg(input) {
                    if !is_allowed_master_shell(cmd) {
                        return Some(Decision::deny(
                            "MASTER_SHELL_RESTRICTED",
                            "Swarm Master shell access is restricted to single unchained `swarm-tool master ...`, `git status`, or `git log` commands.",
                            false,
                        ));
                    }
                }
            }
            None
        }

        SwarmRole::Investigator => {
            if is_write_tool {
                return Some(Decision::deny(
                    "INVESTIGATOR_WRITE_FORBIDDEN",
                    "Swarm Investigator is strictly read-only (`0` writes permitted).",
                    false,
                ));
            }
            if is_web_tool {
                return Some(Decision::deny(
                    "INVESTIGATOR_WEB_FORBIDDEN",
                    "Swarm Investigator operates strictly inside the local repository airlock.",
                    false,
                ));
            }
            None
        }

        SwarmRole::QaEngineer => {
            if is_write_tool {
                let targets = extract_all_write_targets(&norm, input);
                if targets.is_empty() {
                    return Some(Decision::deny(
                        "MISSING_WRITE_TARGETS",
                        "QA Engineer write/patch invocation missing recognizable target file paths.",
                        false,
                    ));
                }
                for raw_p in &targets {
                    if let Ok(valid) =
                        validate_path_with_max_depth(repo_root, cwd, raw_p, PathAccess::Write, 2)
                    {
                        if !is_qa_writable_path(&valid.repo_rel) {
                            return Some(Decision::deny(
                                "QA_PRODUCTION_WRITE_FORBIDDEN",
                                format!(
                                    "QA Engineer may only write test files and `test_attribution.toml`; production path '{}' is forbidden.",
                                    valid.repo_rel
                                ),
                                false,
                            ));
                        }
                    }
                }
            }
            None
        }

        SwarmRole::Grunt => {
            if is_search_tool {
                return Some(Decision::deny(
                    "GRUNT_SEARCH_FORBIDDEN",
                    "Swarm Grunt has zero repo-wide search access; work within `assigned_read_paths` or run `swarm-tool grunt report-blocker`.",
                    false,
                ));
            }
            if is_shell_tool {
                if let Some(cmd) = extract_cmd_arg(input) {
                    if shell_contains_search_binary(cmd) {
                        return Some(Decision::deny(
                            "GRUNT_SEARCH_FORBIDDEN",
                            "Swarm Grunt cannot invoke `rg`, `grep`, `find`, or `fd`; request missing context via `swarm-tool grunt report-blocker`.",
                            false,
                        ));
                    }
                }
            }
            let Some(c) = cap else {
                return Some(Decision::deny(
                    "GRUNT_MISSING_CAPABILITY",
                    "Swarm Grunt requires a Master-minted SessionCapability (`swarm-tool master mint-session --role grunt ...`) before invoking tools.",
                    true,
                ));
            };
            if is_read_tool {
                if let Some(raw_p) = extract_path_arg(input) {
                    if let Ok(valid) =
                        validate_path_with_max_depth(repo_root, cwd, raw_p, PathAccess::Read, 2)
                    {
                        if !is_grunt_path_in_read_scope(&valid.repo_rel, c) {
                            bump_blocked_scope(repo_root, c);
                            return Some(Decision::deny(
                                "GRUNT_READ_OUT_OF_SCOPE",
                                format!(
                                    "Path '{}' is outside session '{}' assigned_read_paths.",
                                    valid.repo_rel, c.session_id
                                ),
                                false,
                            ));
                        }
                    }
                }
            }
            if is_write_tool {
                let targets = extract_all_write_targets(&norm, input);
                if targets.is_empty() {
                    return Some(Decision::deny(
                        "MISSING_WRITE_TARGETS",
                        "Grunt write/patch invocation missing recognizable target file paths.",
                        false,
                    ));
                }
                for raw_p in &targets {
                    if let Ok(valid) =
                        validate_path_with_max_depth(repo_root, cwd, raw_p, PathAccess::Write, 2)
                    {
                        if !path_matches_any_scope(&valid.repo_rel, &c.allowed_write_paths) {
                            bump_blocked_scope(repo_root, c);
                            return Some(Decision::deny(
                                "GRUNT_WRITE_OUT_OF_SCOPE",
                                format!(
                                    "Path '{}' is outside session '{}' allowed_write_paths.",
                                    valid.repo_rel, c.session_id
                                ),
                                false,
                            ));
                        }
                    }
                }
            }
            None
        }

        SwarmRole::AdversarialReviewer => {
            if is_write_tool {
                return Some(Decision::deny(
                    "REVIEWER_WRITE_FORBIDDEN",
                    "Adversarial Reviewer is strictly zero-write (`0` mutations permitted).",
                    false,
                ));
            }
            if is_web_tool {
                return Some(Decision::deny(
                    "REVIEWER_EXFILTRATION_URL_BLOCKED",
                    "Adversarial Reviewer cannot fetch arbitrary URLs (`F08` exfiltration guard); use `swarm-tool reviewer lookup-doc`.",
                    true,
                ));
            }
            if is_shell_tool {
                if let Some(cmd) = extract_cmd_arg(input) {
                    let lower = cmd.to_ascii_lowercase();
                    if lower.contains("http://") || lower.contains("https://") {
                        return Some(Decision::deny(
                            "REVIEWER_EXFILTRATION_URL_BLOCKED",
                            "Adversarial Reviewer shell commands cannot contain raw URLs (`F08` exfiltration guard); use `swarm-tool reviewer lookup-doc`.",
                            true,
                        ));
                    }
                }
            }
            None
        }

        SwarmRole::ForensicCoroner => {
            if is_write_tool {
                return Some(Decision::deny(
                    "CORONER_WRITE_FORBIDDEN",
                    "Forensic Coroner is strictly zero-write (`0` mutations permitted).",
                    false,
                ));
            }
            if is_web_tool {
                return Some(Decision::deny(
                    "CORONER_WEB_FORBIDDEN",
                    "Forensic Coroner operates strictly offline on local spools and breadcrumbs.",
                    false,
                ));
            }
            None
        }

        SwarmRole::StandardCoding => None,
    }
}

pub fn check_role_shell_write_scope(
    role: SwarmRole,
    cap: Option<&SessionCapability>,
    write_rel_paths: &[String],
    repo_root: &Path,
) -> Result<(), Decision> {
    if write_rel_paths.is_empty() {
        return Ok(());
    }
    match role {
        SwarmRole::Master
        | SwarmRole::Investigator
        | SwarmRole::AdversarialReviewer
        | SwarmRole::ForensicCoroner => Err(Decision::deny(
            "ROLE_SHELL_WRITE_FORBIDDEN",
            format!(
                "Role '{}' has zero file-write privileges (attempted shell write to '{}').",
                role.as_str_id(),
                write_rel_paths[0]
            ),
            false,
        )),
        SwarmRole::QaEngineer => {
            for rel in write_rel_paths {
                if !is_qa_writable_path(rel) {
                    return Err(Decision::deny(
                        "QA_PRODUCTION_WRITE_FORBIDDEN",
                        format!(
                            "QA Engineer shell command attempted write to non-test path '{rel}'."
                        ),
                        false,
                    ));
                }
            }
            Ok(())
        }
        SwarmRole::Grunt => {
            let Some(c) = cap else {
                return Err(Decision::deny(
                    "GRUNT_MISSING_CAPABILITY",
                    "Swarm Grunt shell write requires a Master-minted SessionCapability.",
                    true,
                ));
            };
            for rel in write_rel_paths {
                if !path_matches_any_scope(rel, &c.allowed_write_paths) {
                    bump_blocked_scope(repo_root, c);
                    return Err(Decision::deny(
                        "GRUNT_WRITE_OUT_OF_SCOPE",
                        format!(
                            "Grunt shell write '{rel}' is outside session '{}' allowed_write_paths.",
                            c.session_id
                        ),
                        false,
                    ));
                }
            }
            Ok(())
        }
        SwarmRole::StandardCoding => Ok(()),
    }
}

pub fn check_role_shell_read_scope(
    role: SwarmRole,
    cap: Option<&SessionCapability>,
    read_rel_paths: &[String],
    repo_root: &Path,
) -> Result<(), Decision> {
    if read_rel_paths.is_empty() {
        return Ok(());
    }
    match role {
        SwarmRole::Master => {
            for rel in read_rel_paths {
                if !is_master_readable_doc_or_skill(rel) {
                    return Err(Decision::deny(
                        "MASTER_SOURCE_READ_FORBIDDEN",
                        format!(
                            "Swarm Master shell command attempted to read source file '{rel}'."
                        ),
                        false,
                    ));
                }
            }
            Ok(())
        }
        SwarmRole::Grunt => {
            let Some(c) = cap else {
                return Err(Decision::deny(
                    "GRUNT_MISSING_CAPABILITY",
                    "Swarm Grunt shell read requires a Master-minted SessionCapability.",
                    true,
                ));
            };
            for rel in read_rel_paths {
                if !is_grunt_path_in_read_scope(rel, c) {
                    bump_blocked_scope(repo_root, c);
                    return Err(Decision::deny(
                        "GRUNT_READ_OUT_OF_SCOPE",
                        format!(
                            "Grunt shell read '{rel}' is outside session '{}' assigned_read_paths.",
                            c.session_id
                        ),
                        false,
                    ));
                }
            }
            Ok(())
        }
        SwarmRole::Investigator
        | SwarmRole::QaEngineer
        | SwarmRole::AdversarialReviewer
        | SwarmRole::ForensicCoroner
        | SwarmRole::StandardCoding => Ok(()),
    }
}

/// Validates typed worker packets (`F10` fix) and checks escalation triggers.
pub fn parse_and_validate_worker_packet(
    raw_json: &str,
) -> Result<(WorkerPacket, Option<EscalationTrigger>), String> {
    let uni = scan_unicode(raw_json, ScanMode::UntrustedContent);
    if let Some(first) = uni.first() {
        return Err(format!(
            "worker packet failed 7-bit ASCII/Unicode hygiene: {}",
            first.detail
        ));
    }
    let v = JsonValue::parse(raw_json).map_err(|e| format!("invalid packet JSON: {e}"))?;
    let kind = v
        .get("packet_type")
        .or_else(|| v.get("kind"))
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            "UNTYPED_WORKER_OUTPUT_REJECTED: missing 'packet_type' (expected ObservedFact, WorkerHypothesis, or PlanAmendmentProposal)".to_string()
        })?;
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

    match kind {
        "ObservedFact" => {
            let claim = v
                .get("claim")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "ObservedFact missing 'claim'".to_string())?
                .to_string();
            let evidence_slices: Vec<String> = v
                .get("evidence_slices")
                .and_then(JsonValue::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(JsonValue::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            let total_tokens = estimate_bpe_tokens(&claim)
                + evidence_slices
                    .iter()
                    .map(|s| estimate_bpe_tokens(s))
                    .sum::<usize>();
            if total_tokens > MAX_INVESTIGATOR_PACKET_TOKENS {
                return Err(format!(
                    "ObservedFact exceeds {MAX_INVESTIGATOR_PACKET_TOKENS}-token airlock cap ({total_tokens} tokens)"
                ));
            }
            Ok((
                WorkerPacket::ObservedFact {
                    session_id,
                    task_id,
                    claim,
                    evidence_slices,
                },
                None,
            ))
        }
        "WorkerHypothesis" => {
            let missing_path = v
                .get("missing_path")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string();
            let hypothesis = v
                .get("hypothesis")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "WorkerHypothesis missing 'hypothesis'".to_string())?
                .to_string();
            let trigger = if !missing_path.is_empty() {
                Some(EscalationTrigger::OutOfScopeBoundaryRequired {
                    path: missing_path.clone(),
                    reason: hypothesis.clone(),
                })
            } else {
                None
            };
            Ok((
                WorkerPacket::WorkerHypothesis {
                    session_id,
                    task_id,
                    missing_path,
                    hypothesis,
                },
                trigger,
            ))
        }
        "PlanAmendmentProposal" => {
            let proposed_change = v
                .get("proposed_change")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "PlanAmendmentProposal missing 'proposed_change'".to_string())?
                .to_string();
            let justification = v
                .get("justification")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "PlanAmendmentProposal missing 'justification'".to_string())?
                .to_string();
            let trigger = Some(EscalationTrigger::ConflictingConstraints {
                detail: format!(
                    "Task '{task_id}' proposed plan amendment requiring human approval: {proposed_change}"
                ),
            });
            Ok((
                WorkerPacket::PlanAmendmentProposal {
                    session_id,
                    task_id,
                    proposed_change,
                    justification,
                },
                trigger,
            ))
        }
        other => Err(format!(
            "UNTYPED_WORKER_OUTPUT_REJECTED: unknown packet_type '{other}'"
        )),
    }
}

/// Deep `realpath`-jailed codebase signature scout for `swarm-tool investigator scout`.
pub fn scout_repo_signatures(
    repo_root: &Path,
    start_rel: &str,
    max_depth: usize,
    filter: Option<&str>,
) -> Result<Vec<String>, String> {
    let capped_depth = max_depth.clamp(1, INVESTIGATOR_MAX_WALK_DEPTH);
    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let valid_start = validate_path_with_max_depth(
        &canon_repo,
        &canon_repo,
        if start_rel.trim().is_empty() {
            "."
        } else {
            start_rel
        },
        PathAccess::ListSearch {
            requested_depth: Some(capped_depth),
        },
        INVESTIGATOR_MAX_WALK_DEPTH,
    )
    .map_err(|pv| format!("{}: {}", pv.code, pv.detail))?;

    let mut hits = Vec::new();
    walk_scout_dir(
        &canon_repo,
        &valid_start.canonical_or_norm,
        0,
        capped_depth,
        filter,
        &mut hits,
    )?;
    hits.sort();
    hits.truncate(80);
    Ok(hits)
}

fn walk_scout_dir(
    canon_repo: &Path,
    dir: &Path,
    depth: usize,
    max_depth: usize,
    filter: Option<&str>,
    hits: &mut Vec<String>,
) -> Result<(), String> {
    if depth > max_depth || hits.len() >= 80 {
        return Ok(());
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    let mut sorted: Vec<_> = entries.flatten().collect();
    sorted.sort_by_key(|e| e.file_name());

    for entry in sorted {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with('.') || name_str == "target" || name_str == "dist" {
            continue;
        }
        let full = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        if check_forbidden_zones_lexical(&full.to_string_lossy(), &name_str).is_err() {
            continue;
        }
        let Ok(canon_child) = fs::canonicalize(&full) else {
            continue;
        };
        if !canon_child.starts_with(canon_repo) {
            continue;
        }

        if ft.is_dir() {
            if depth < max_depth {
                walk_scout_dir(canon_repo, &canon_child, depth + 1, max_depth, filter, hits)?;
            }
        } else if ft.is_file() && is_source_ext(&name_str) {
            const MAX_SCOUT_FILE_BYTES: u64 = 256 * 1024;
            const MAX_SCOUT_FILE_LINES: usize = 2_000;
            let rel = canon_child
                .strip_prefix(canon_repo)
                .unwrap_or(&canon_child)
                .to_string_lossy()
                .replace('\\', "/");
            if let Ok(file) = File::open(&canon_child) {
                let reader = BufReader::new(file.take(MAX_SCOUT_FILE_BYTES));
                for (idx, line_res) in reader.lines().take(MAX_SCOUT_FILE_LINES).enumerate() {
                    let Ok(line) = line_res else {
                        break;
                    };
                    let trimmed = line.trim();
                    if is_signature_line(trimmed) {
                        if let Some(pat) = filter
                            && !trimmed.contains(pat)
                            && !rel.contains(pat)
                        {
                            continue;
                        }
                        let clean_sig: String = trimmed
                            .chars()
                            .filter(|c| c.is_ascii() && !c.is_ascii_control())
                            .take(100)
                            .collect();
                        hits.push(format!("{rel}:{}: {clean_sig}", idx + 1));
                        if hits.len() >= 80 {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn is_exact_semver_pin(ver: &str) -> bool {
    let trimmed = ver.trim();
    if trimmed.is_empty() || !trimmed.as_bytes()[0].is_ascii_digit() {
        return false;
    }
    let core = trimmed.split(['-', '+']).next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// Offline lockfile-verified package check for `AdversarialReviewer` (`F08` fix:
/// rejects any URL, query string, or path traversal so secrets cannot be exfiltrated
/// via `https://docs.rs/<encoded_secret>`).
pub fn lookup_pinned_package_doc(
    repo_root: &Path,
    ecosystem: &str,
    package: &str,
    version: &str,
    symbol: Option<&str>,
) -> Result<String, String> {
    for (label, val) in [
        ("ecosystem", ecosystem),
        ("package", package),
        ("version", version),
        ("symbol", symbol.unwrap_or("")),
    ] {
        let lower = val.to_ascii_lowercase();
        if lower.contains("http://")
            || lower.contains("https://")
            || val.contains('/')
            || val.contains('\\')
            || val.contains("..")
            || val.contains('?')
            || val.contains('&')
            || val.contains('@')
        {
            return Err(format!(
                "DOC_BROKER_URL_EXFIL_BLOCKED: illegal URL or path characters in {label} '{val}'"
            ));
        }
        if !val
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
        {
            return Err(format!(
                "DOC_BROKER_INVALID_IDENTIFIER: {label} '{val}' must be strict ASCII package identifier"
            ));
        }
    }

    if !is_exact_semver_pin(version) {
        return Err(format!(
            "UNPINNED_DEPENDENCY: requested version '{version}' for '{package}' is not an exact X.Y.Z semver pin"
        ));
    }

    let sym_note = symbol
        .filter(|s| !s.is_empty())
        .map(|s| format!(" (symbol query: {s})"))
        .unwrap_or_default();

    let eco = ecosystem.to_ascii_lowercase();
    match eco.as_str() {
        "cargo" | "rust" => {
            let lock_path = repo_root.join("Cargo.lock");
            let lock_raw = fs::read_to_string(&lock_path)
                .map_err(|_| "Cargo.lock not present in repository root".to_string())?;
            let needle_name = format!("name = \"{package}\"");
            let needle_ver = format!("version = \"{version}\"");
            let mut found_exact = false;
            let mut found_versions = Vec::new();
            for block in lock_raw.split("[[package]]").skip(1) {
                if block.contains(&needle_name) {
                    if block.contains(&needle_ver) {
                        found_exact = true;
                    }
                    for line in block.lines() {
                        let t = line.trim();
                        if let Some(rest) = t.strip_prefix("version = \"")
                            && let Some(v) = rest.strip_suffix('"')
                        {
                            found_versions.push(v.to_string());
                        }
                    }
                }
            }
            if found_exact {
                Ok(format!(
                    "VERIFIED_LOCKFILE_PIN: cargo crate '{package}' v{version} is pinned in Cargo.lock{sym_note}."
                ))
            } else if !found_versions.is_empty() {
                Err(format!(
                    "LOCKFILE_VERSION_MISMATCH: crate '{package}' is pinned at [{}], not '{version}'",
                    found_versions.join(", ")
                ))
            } else {
                Err(format!(
                    "UNPINNED_DEPENDENCY: crate '{package}' does not exist in Cargo.lock"
                ))
            }
        }
        "npm" | "node" => {
            let lock_path = repo_root.join("package-lock.json");
            if lock_path.exists() {
                let lock_raw = fs::read_to_string(&lock_path)
                    .map_err(|e| format!("failed reading package-lock.json: {e}"))?;
                let lock_json = JsonValue::parse(&lock_raw)
                    .map_err(|e| format!("invalid package-lock.json JSON: {e}"))?;
                let mut found_versions = Vec::new();
                let direct_key = format!("node_modules/{package}");
                let nested_suffix = format!("/node_modules/{package}");
                if let Some(pkgs) = lock_json.get("packages").and_then(JsonValue::as_object) {
                    for (k, entry) in pkgs {
                        if (k == &direct_key || k.ends_with(&nested_suffix))
                            && let Some(v) = entry.get("version").and_then(JsonValue::as_str)
                            && !found_versions.iter().any(|existing| existing == v)
                        {
                            found_versions.push(v.to_string());
                        }
                    }
                }
                if let Some(deps) = lock_json.get("dependencies").and_then(JsonValue::as_object)
                    && let Some((_, entry)) = deps.iter().find(|(k, _)| k == package)
                    && let Some(v) = entry.get("version").and_then(JsonValue::as_str)
                    && !found_versions.iter().any(|existing| existing == v)
                {
                    found_versions.push(v.to_string());
                }
                if found_versions.iter().any(|v| v == version) {
                    return Ok(format!(
                        "VERIFIED_LOCKFILE_PIN: npm package '{package}' v{version} is pinned in package-lock.json{sym_note}."
                    ));
                } else if !found_versions.is_empty() {
                    return Err(format!(
                        "LOCKFILE_VERSION_MISMATCH: npm package '{package}' is pinned at [{}], not '{version}'",
                        found_versions.join(", ")
                    ));
                } else {
                    return Err(format!(
                        "UNPINNED_DEPENDENCY: npm package '{package}' does not exist in package-lock.json"
                    ));
                }
            }

            let pkg_path = repo_root.join("package.json");
            let raw = fs::read_to_string(&pkg_path)
                .map_err(|_| "package.json not present in repository root".to_string())?;
            let pkg_json =
                JsonValue::parse(&raw).map_err(|e| format!("invalid package.json JSON: {e}"))?;

            let mut declared_specs: Vec<String> = Vec::new();
            for section in [
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            ] {
                if let Some(spec) = pkg_json
                    .get(section)
                    .and_then(|sec| sec.get(package))
                    .and_then(JsonValue::as_str)
                {
                    declared_specs.push(spec.trim().to_string());
                }
            }

            if declared_specs.is_empty() {
                return Err(format!(
                    "UNPINNED_DEPENDENCY: npm package '{package}' not declared in package.json dependencies"
                ));
            }
            for spec in &declared_specs {
                if !is_exact_semver_pin(spec) {
                    return Err(format!(
                        "UNPINNED_DEPENDENCY: npm package '{package}' uses non-exact range '{spec}' in package.json (exact pin or package-lock.json required)"
                    ));
                }
            }
            if declared_specs.iter().any(|spec| spec == version) {
                Ok(format!(
                    "VERIFIED_PACKAGE_PIN: npm package '{package}' ({version}) is pinned in package.json{sym_note}."
                ))
            } else {
                Err(format!(
                    "LOCKFILE_VERSION_MISMATCH: npm package '{package}' is pinned at [{}] in package.json, not '{version}'",
                    declared_specs.join(", ")
                ))
            }
        }
        _ => Err(format!(
            "unsupported ecosystem '{ecosystem}' (expected 'cargo' or 'npm')"
        )),
    }
}

/// Enforces `MAX_ADVERSARIAL_ROUNDS = 2` (`F21`).
pub fn evaluate_reviewer_verdict(
    task_id: &str,
    round: u8,
    approved: bool,
    current_attempt: u32,
) -> Result<ReviewVerdictOutcome, String> {
    if round == 0 || round > MAX_ADVERSARIAL_ROUNDS {
        return Err(format!(
            "ADVERSARIAL_ROUND_CAP_VIOLATION: round {round} outside permitted 1..={MAX_ADVERSARIAL_ROUNDS}"
        ));
    }
    if approved {
        return Ok(ReviewVerdictOutcome::Approved {
            task_id: task_id.to_string(),
            round,
        });
    }
    if round >= MAX_ADVERSARIAL_ROUNDS {
        return Ok(ReviewVerdictOutcome::EscalateToMaster {
            trigger: EscalationTrigger::RoundCapExceeded {
                task_id: task_id.to_string(),
                rounds: round,
            },
        });
    }
    Ok(ReviewVerdictOutcome::RetryCleanSlate {
        task_id: task_id.to_string(),
        round,
        next_attempt: current_attempt.saturating_add(1),
    })
}

fn is_master_readable_doc_or_skill(repo_rel: &str) -> bool {
    repo_rel == "AGENTS.md"
        || repo_rel == "PLAN.lock.json"
        || repo_rel == "WORK_LEDGER.jsonl"
        || repo_rel.starts_with("docs/")
        || repo_rel.starts_with("skills/")
}

pub fn is_qa_writable_path(repo_rel: &str) -> bool {
    let lower = repo_rel.to_ascii_lowercase();
    let fname = lower.rsplit('/').next().unwrap_or(&lower);
    lower == "test_attribution.toml"
        || lower.ends_with("/test_attribution.toml")
        || lower == "tests/swarm_v2_attribution.toml"
        || lower.starts_with("tests/")
        || lower.contains("/tests/")
        || lower.starts_with("__tests__/")
        || lower.contains("/__tests__/")
        || fname.ends_with("_test.rs")
        || fname.ends_with("_tests.rs")
        || fname.ends_with("_test.go")
        || fname.ends_with(".test.ts")
        || fname.ends_with(".spec.ts")
        || fname.ends_with(".test.tsx")
        || fname.ends_with(".spec.tsx")
        || fname.ends_with(".test.js")
        || fname.ends_with(".spec.js")
        || (fname.starts_with("test_") && fname.ends_with(".py"))
}

fn is_grunt_path_in_read_scope(repo_rel: &str, cap: &SessionCapability) -> bool {
    if repo_rel == "AGENTS.md"
        || repo_rel == "skills/swarm-grunt/SKILL.md"
        || repo_rel == "skills/swarm-grunt/ROLE_GUIDE.md"
    {
        return true;
    }
    path_matches_any_scope(repo_rel, &cap.assigned_read_paths)
        || path_matches_any_scope(repo_rel, &cap.allowed_write_paths)
        || path_matches_any_scope(repo_rel, &cap.assigned_tests)
}

pub fn path_matches_any_scope(repo_rel: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return false;
    }
    let clean = repo_rel.trim_start_matches("./");
    for pat in patterns {
        let p = pat.trim().trim_start_matches("./");
        if p == clean {
            return true;
        }
        if let Some(prefix) = p.strip_suffix("/**") {
            if clean == prefix || clean.starts_with(&format!("{prefix}/")) {
                return true;
            }
        } else if let Some(prefix) = p.strip_suffix("/*") {
            if let Some(rest) = clean.strip_prefix(&format!("{prefix}/")) {
                if !rest.contains('/') {
                    return true;
                }
            }
        } else if clean.starts_with(&format!("{p}/")) {
            return true;
        }
    }
    false
}

fn tokenize_unchained_shell_words(cmd: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = cmd.chars().peekable();
    let mut quote: Option<char> = None;

    while let Some(ch) = chars.next() {
        if ch == '\0' || ch == '\r' || ch == '\n' {
            return None;
        }
        match quote {
            Some('\'') => {
                if ch == '\'' {
                    quote = None;
                } else {
                    cur.push(ch);
                }
            }
            Some('"') => {
                if ch == '"' {
                    quote = None;
                } else if ch == '$' || ch == '`' {
                    return None;
                } else if ch == '\\' {
                    let next = chars.next()?;
                    cur.push(next);
                } else {
                    cur.push(ch);
                }
            }
            Some(_) => return None,
            None => match ch {
                '\'' | '"' => {
                    quote = Some(ch);
                    in_word = true;
                }
                c if c.is_ascii_whitespace() => {
                    if in_word {
                        words.push(std::mem::take(&mut cur));
                        in_word = false;
                    }
                }
                ';' | '|' | '&' | '<' | '>' | '(' | ')' | '`' | '$' => return None,
                '\\' => {
                    let next = chars.next()?;
                    if next == '\n' || next == '\r' {
                        return None;
                    }
                    in_word = true;
                    cur.push(next);
                }
                other => {
                    in_word = true;
                    cur.push(other);
                }
            },
        }
    }

    if quote.is_some() {
        return None;
    }
    if in_word {
        words.push(cur);
    }
    if words.is_empty() { None } else { Some(words) }
}

fn is_allowed_master_shell(cmd: &str) -> bool {
    let Some(tokens) = tokenize_unchained_shell_words(cmd.trim()) else {
        return false;
    };
    let first_base = tokens[0].rsplit('/').next().unwrap_or(tokens[0].as_str());
    if first_base == "swarm-tool" {
        return tokens.get(1).is_some_and(|sub| sub == "master");
    }
    if tokens.len() >= 6
        && tokens[0] == "cargo"
        && tokens[1] == "run"
        && ((tokens[2] == "-p" && tokens[3] == "swarm-tools")
            || (tokens[2] == "--bin" && tokens[3] == "swarm-tool"))
        && tokens[4] == "--"
        && tokens[5] == "master"
    {
        return true;
    }
    if tokens[0] == "git" && tokens.get(1).is_some_and(|s| s == "status") {
        return tokens[2..]
            .iter()
            .all(|t| t.starts_with('-') && !t.starts_with("--output"));
    }
    if tokens[0] == "git" && tokens.get(1).is_some_and(|s| s == "log") {
        return tokens[2..].iter().all(|t| {
            (t.starts_with('-') && !t.starts_with("--output"))
                || t.chars().all(|c| c.is_ascii_digit())
        });
    }
    false
}

fn check_role_swarm_tool_namespace(role: SwarmRole, cmd: &str) -> Option<Decision> {
    let expected_ns = match role {
        SwarmRole::Master => "master",
        SwarmRole::Investigator => "investigator",
        SwarmRole::QaEngineer => "qa",
        SwarmRole::Grunt => "grunt",
        SwarmRole::AdversarialReviewer => "reviewer",
        SwarmRole::ForensicCoroner => "coroner",
        SwarmRole::StandardCoding => return None,
    };

    for seg in cmd.split(['|', ';', '&', '\n', '(', '`']) {
        let words: Vec<&str> = seg.split_whitespace().collect();
        if words.is_empty() {
            continue;
        }
        // Skip leading `env`, flags to `env`, or `KEY=VAL` assignments
        let mut idx = 0usize;
        while idx < words.len() {
            let w = words[idx].trim_matches(['"', '\'']);
            let base = w.rsplit('/').next().unwrap_or(w);
            if base == "env" {
                idx += 1;
                while idx < words.len() {
                    let ew = words[idx].trim_matches(['"', '\'']);
                    if ew == "-u" || ew == "--unset" {
                        idx += 2;
                    } else if ew.starts_with('-') || ew.contains('=') {
                        idx += 1;
                    } else {
                        break;
                    }
                }
                continue;
            }
            if w.contains('=') && !w.starts_with('-') {
                idx += 1;
                continue;
            }
            break;
        }
        if idx >= words.len() {
            continue;
        }
        let bin = words[idx].trim_matches(['"', '\'']);
        let base = bin.rsplit('/').next().unwrap_or(bin);
        let invoked_ns = if base == "swarm-tool" {
            words.get(idx + 1).map(|s| s.trim_matches(['"', '\'']))
        } else if base == "cargo"
            && words.get(idx + 1).copied() == Some("run")
            && seg.contains("swarm-tool")
        {
            words
                .iter()
                .skip(idx + 2)
                .position(|&w| w == "--")
                .and_then(|rel_sep| words.get(idx + 2 + rel_sep + 1))
                .map(|s| s.trim_matches(['"', '\'']))
        } else {
            None
        };

        if let Some(ns) = invoked_ns {
            if !matches!(ns, "--help" | "-h" | "help") && ns != expected_ns {
                return Some(Decision::deny(
                    "ROLE_NAMESPACE_ESCALATION_BLOCKED",
                    format!(
                        "Role '{}' cannot invoke `swarm-tool {ns}` (permitted namespace: `swarm-tool {expected_ns}`).",
                        role.as_str_id()
                    ),
                    true,
                ));
            }
        }
    }
    None
}

fn extract_all_write_targets(norm_tool: &str, v: &JsonValue) -> Vec<String> {
    if matches!(norm_tool, "apply_patch" | "patch") {
        for k in [
            "patch",
            "input",
            "diff",
            "content",
            "raw_patch",
            "patchText",
        ] {
            if let Some(body) = v.get(k).and_then(JsonValue::as_str) {
                return crate::extract_patch_target_paths(body);
            }
        }
        return Vec::new();
    }
    let mut out = Vec::new();
    if let Some(p) = extract_path_arg(v) {
        out.push(p.to_string());
    }
    crate::collect_nested_path_fields(v, &mut out);
    out
}

fn shell_contains_search_binary(cmd: &str) -> bool {
    for seg in cmd.split(['|', ';', '&', '\n']) {
        let first = seg
            .split_whitespace()
            .find(|tok| !tok.contains('='))
            .unwrap_or("");
        let base = first.rsplit('/').next().unwrap_or(first);
        if matches!(
            base,
            "rg" | "ripgrep" | "grep" | "egrep" | "fgrep" | "find" | "fd" | "fdfind"
        ) {
            return true;
        }
    }
    false
}

fn bump_blocked_scope(repo_root: &Path, cap: &SessionCapability) {
    let mut updated = cap.clone();
    updated.blocked_scope_attempts = updated.blocked_scope_attempts.saturating_add(1);
    let _ = save_session_capability(repo_root, &updated);
}

fn extract_path_arg(v: &JsonValue) -> Option<&str> {
    for k in [
        "file_path",
        "AbsolutePath",
        "TargetFile",
        "path",
        "target_file",
        "notebook_path",
    ] {
        if let Some(s) = v.get(k).and_then(JsonValue::as_str) {
            return Some(s);
        }
    }
    None
}

fn extract_cmd_arg(v: &JsonValue) -> Option<&str> {
    for k in ["command", "CommandLine", "cmd", "script"] {
        if let Some(s) = v.get(k).and_then(JsonValue::as_str) {
            return Some(s);
        }
    }
    None
}

fn is_source_ext(name: &str) -> bool {
    matches!(
        Path::new(name).extension().and_then(|e| e.to_str()),
        Some("rs" | "ts" | "tsx" | "js" | "py" | "go" | "toml" | "rego")
    )
}

fn is_signature_line(trimmed: &str) -> bool {
    trimmed.starts_with("pub fn ")
        || trimmed.starts_with("fn ")
        || trimmed.starts_with("pub struct ")
        || trimmed.starts_with("struct ")
        || trimmed.starts_with("pub enum ")
        || trimmed.starts_with("enum ")
        || trimmed.starts_with("pub trait ")
        || trimmed.starts_with("export function ")
        || trimmed.starts_with("export interface ")
        || trimmed.starts_with("export type ")
        || trimmed.starts_with("def ")
        || trimmed.starts_with("class ")
}
