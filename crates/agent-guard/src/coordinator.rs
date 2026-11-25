#![forbid(unsafe_code)]

//! External Host Coordinator Privilege-Separated Monitor & Client (`spec.md` Section 3.3).
//!
//! Isolates `<swarm_state_dir>/vault/hmac.key` outside `exec-sandbox` (Linux Landlock LSM /
//! macOS Seatbelt) so untrusted child processes (`cargo test`, `build.rs`, `pytest`, `awk`)
//! never have filesystem access to HMAC key material.
//!
//! Security Invariants:
//! 1. **Zero Signing Oracle on Verification**: `verify_event_mac` and `verify_domain_hmac`
//!    perform constant-time MAC verification inside the coordinator and return `bool` only -- never
//!    exposing raw tags to callers.
//! 2. **Privilege-Separated Signing Policy**:
//!    - `PLAN_LOCK_HMAC_DOMAIN` (`dotagent-plan-lock-v1`) signing is **hard-blocked** over IPC
//!      (restricted exclusively to host-side `Master` with direct vault possession).
//!    - `CAPABILITY_HMAC_DOMAIN` (`DOTAGENT_SESSION_CAPABILITY_V1`) signing **hard-blocks**
//!      `role == "master"`, unminted `session_id`s, and any mutation of immutable scope fields
//!      (`task_id`, `attempt`, `repo_sha256`, `plan_sha256`, `assigned_read_paths`,
//!      `allowed_write_paths`, `assigned_tests`), permitting only counter/`last_green_tree_oid`
//!      transitions on an already-minted worker capability.
//! 3. **Domain Separation & Zeroization**: Event MACs use `BREADCRUMB_EVENT_HMAC_DOMAIN`,
//!    key bytes live in `ZeroizingKey`, and client streams run on bounded worker threads so
//!    stalled connections cannot head-of-line block parallel Swarm waves.

use std::fs;
#[cfg(target_os = "linux")]
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::breadcrumbs::{
    BREADCRUMB_EVENT_HMAC_DOMAIN, ExclusiveFileLockGuard, hex_decode_bytes,
    load_or_init_vault_hmac_key, swarm_state_dir,
};
use crate::crypto::{ZeroizingKey, constant_time_eq_bytes, hex_encode};
use crate::json::JsonValue;

type HmacSha256 = Hmac<Sha256>;

const MAX_RPC_LINE_BYTES: usize = 65_536;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 45;
const MAX_CONCURRENT_IPC_CLIENTS: usize = 16;

const PLAN_LOCK_DOMAIN_BYTES: &[u8] = b"dotagent-plan-lock-v1";
const CAPABILITY_DOMAIN_BYTES: &[u8] = b"DOTAGENT_SESSION_CAPABILITY_V1";
const ACTIVE_SLOT_DOMAIN_BYTES: &[u8] = b"DOTAGENT_ACTIVE_SESSIONS_REGISTRY_V2";
const LEDGER_DOMAIN_BYTES: &[u8] = b"DOTAGENT_SWARM_V2_WORK_LEDGER_V2";
const REVIEW_STATE_DOMAIN_BYTES: &[u8] = b"DOTAGENT_SWARM_V2_REVIEW_STATE_V1";

/// Directory containing ONLY the coordinator Unix domain socket (`coord.sock`),
/// kept strictly separate from `<swarm_state_dir>/vault/hmac.key`.
pub fn coordinator_ipc_dir(repo_root: &Path) -> Result<PathBuf, String> {
    let dir = swarm_state_dir(repo_root)?.join("ipc");
    fs::create_dir_all(&dir).map_err(|e| {
        format!(
            "failed creating coordinator ipc dir '{}': {e}",
            dir.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    Ok(dir)
}

pub fn coordinator_socket_path(repo_root: &Path) -> Result<PathBuf, String> {
    if let Ok(explicit) = std::env::var("AGENT_GUARD_COORDINATOR_SOCK") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let p = PathBuf::from(trimmed);
            if !p.is_absolute()
                || p.file_name().is_none()
                || p.components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(
                    "INVALID_COORDINATOR_SOCK: AGENT_GUARD_COORDINATOR_SOCK must be a normalized absolute path"
                        .to_string(),
                );
            }
            let parent = p.parent().ok_or_else(|| {
                "INVALID_COORDINATOR_SOCK: AGENT_GUARD_COORDINATOR_SOCK missing parent directory"
                    .to_string()
            })?;
            let pmeta = fs::symlink_metadata(parent).map_err(|e| {
                format!(
                    "INVALID_COORDINATOR_SOCK: parent directory '{}' inaccessible: {e}",
                    parent.display()
                )
            })?;
            if pmeta.file_type().is_symlink() || !pmeta.file_type().is_dir() {
                return Err(format!(
                    "INVALID_COORDINATOR_SOCK: parent '{}' must be a regular non-symlink directory",
                    parent.display()
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                let mode = pmeta.permissions().mode();
                if (mode & 0o077) != 0 {
                    return Err(format!(
                        "INVALID_COORDINATOR_SOCK: parent '{}' has mode {:04o}; custom socket directory must have 0700 private permissions",
                        parent.display(),
                        mode & 0o777
                    ));
                }
                let ref_dir = swarm_state_dir(repo_root)?;
                let expected_uid = fs::symlink_metadata(&ref_dir)
                    .map(|m| m.uid())
                    .map_err(|e| format!("failed inspecting swarm state dir owner: {e}"))?;
                if pmeta.uid() != expected_uid {
                    return Err(format!(
                        "INVALID_COORDINATOR_SOCK: parent '{}' uid {} does not match current user uid {expected_uid}",
                        parent.display(),
                        pmeta.uid()
                    ));
                }
            }
            return Ok(p);
        }
    }
    Ok(coordinator_ipc_dir(repo_root)?.join("coord.sock"))
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn shorten_unix_socket_via_cwd(sock_path: &Path) -> PathBuf {
    let Ok(cwd) = std::env::current_dir() else {
        return sock_path.to_path_buf();
    };
    let canon_cwd = fs::canonicalize(&cwd).unwrap_or(cwd);
    let canon_sock = sock_path
        .parent()
        .and_then(|p| fs::canonicalize(p).ok())
        .and_then(|cp| sock_path.file_name().map(|f| cp.join(f)))
        .unwrap_or_else(|| sock_path.to_path_buf());
    let cwd_comps: Vec<_> = canon_cwd.components().collect();
    let sock_comps: Vec<_> = canon_sock.components().collect();
    let common = cwd_comps
        .iter()
        .zip(sock_comps.iter())
        .take_while(|(a, b)| a == b)
        .count();
    if common == 0 {
        return sock_path.to_path_buf();
    }
    let mut rel = PathBuf::new();
    for _ in common..cwd_comps.len() {
        rel.push("..");
    }
    for comp in &sock_comps[common..] {
        rel.push(comp.as_os_str());
    }
    if rel.as_os_str().len() < sock_path.as_os_str().len() {
        rel
    } else {
        sock_path.to_path_buf()
    }
}

#[cfg(unix)]
pub fn connect_unix_short_path(sock_path: &Path) -> std::io::Result<UnixStream> {
    if sock_path.as_os_str().len() <= 95 {
        return UnixStream::connect(sock_path);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let parent = sock_path
            .parent()
            .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidInput, "missing socket parent"))?;
        let fname = sock_path
            .file_name()
            .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidInput, "missing socket name"))?;
        let dir_file = File::open(parent)?;
        let short = format!(
            "/proc/self/fd/{}/{}",
            dir_file.as_raw_fd(),
            fname.to_string_lossy()
        );
        UnixStream::connect(short)
    }
    #[cfg(not(target_os = "linux"))]
    {
        UnixStream::connect(shorten_unix_socket_via_cwd(sock_path))
    }
}

#[cfg(unix)]
fn bind_unix_short_path(sock_path: &Path) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let parent = sock_path
        .parent()
        .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidInput, "missing socket parent"))?;
    let pmeta = fs::symlink_metadata(parent)?;
    if pmeta.file_type().is_symlink() || !pmeta.file_type().is_dir() {
        return Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            "coordinator socket parent must be a regular non-symlink directory",
        ));
    }
    if (pmeta.permissions().mode() & 0o077) != 0 {
        return Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            "coordinator socket parent directory must have 0700 private permissions",
        ));
    }
    if sock_path.as_os_str().len() <= 95 {
        return UnixListener::bind(sock_path);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let fname = sock_path
            .file_name()
            .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidInput, "missing socket name"))?;
        let dir_file = File::open(parent)?;
        let short = format!(
            "/proc/self/fd/{}/{}",
            dir_file.as_raw_fd(),
            fname.to_string_lossy()
        );
        UnixListener::bind(short)
    }
    #[cfg(not(target_os = "linux"))]
    {
        UnixListener::bind(shorten_unix_socket_via_cwd(sock_path))
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(unix)]
fn send_rpc_request(sock_path: &Path, req: &JsonValue) -> Result<JsonValue, String> {
    let mut stream = connect_unix_short_path(sock_path)
        .map_err(|e| format!("coordinator socket connect failed: {e}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));

    let mut line = req.to_json_string();
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("coordinator write failed: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("coordinator flush failed: {e}"))?;

    let mut reader = BufReader::new(stream.take(MAX_RPC_LINE_BYTES as u64));
    let mut resp_line = String::new();
    reader
        .read_line(&mut resp_line)
        .map_err(|e| format!("coordinator read failed: {e}"))?;
    if resp_line.trim().is_empty() {
        return Err("empty response from coordinator".to_string());
    }
    let parsed = JsonValue::parse(resp_line.trim())
        .map_err(|e| format!("invalid coordinator JSON response: {e}"))?;
    if parsed.get("ok").and_then(JsonValue::as_bool) != Some(true) {
        let err_msg = parsed
            .get("error")
            .and_then(JsonValue::as_str)
            .unwrap_or("unknown coordinator error");
        return Err(format!("COORDINATOR_DENIED: {err_msg}"));
    }
    Ok(parsed)
}

pub fn ping_coordinator(repo_root: &Path) -> bool {
    #[cfg(unix)]
    {
        let Ok(sock_path) = coordinator_socket_path(repo_root) else {
            return false;
        };
        let req = JsonValue::Object(vec![("op".to_string(), JsonValue::Str("ping".to_string()))]);
        send_rpc_request(&sock_path, &req).is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = repo_root;
        false
    }
}

pub(crate) fn has_trusted_executable_ancestors(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        for ancestor in path.ancestors().skip(1) {
            if ancestor.as_os_str().is_empty() {
                continue;
            }
            let Ok(metadata) = fs::symlink_metadata(ancestor) else {
                return false;
            };
            if metadata.is_dir() && (metadata.permissions().mode() & 0o022) != 0 {
                return false;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    true
}

pub fn is_trusted_executable_file(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        // Reject both group-writable (0o020) and world-writable (0o002) binaries.
        if (mode & 0o022) != 0 {
            return false;
        }
        // Check every pre-canonicalization directory component so symlinked parent components
        // inside a group- or world-writable directory cannot redirect to another binary.
        if !has_trusted_executable_ancestors(path) {
            return false;
        }
        let Ok(canon) = fs::canonicalize(path) else {
            return false;
        };
        let Ok(cmeta) = fs::symlink_metadata(&canon) else {
            return false;
        };
        if !cmeta.file_type().is_file() || (cmeta.permissions().mode() & 0o022) != 0 {
            return false;
        }
        for anc in canon.ancestors().skip(1) {
            if anc.as_os_str().is_empty() {
                continue;
            }
            let Ok(ameta) = fs::metadata(anc) else {
                return false;
            };
            if !ameta.is_dir() || (ameta.permissions().mode() & 0o022) != 0 {
                return false;
            }
        }
    }
    true
}

fn find_agent_guard_binary() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(name) = exe.file_name().and_then(|s| s.to_str()) {
            if name == "agent-guard" || name == "dotagent" {
                return Some(exe);
            }
            if matches!(
                name,
                "swarm-tool" | "dotagent-harness" | "dotagent-compiler"
            ) {
                let sibling = exe.with_file_name("agent-guard");
                if is_trusted_executable_file(&sibling) {
                    return Some(sibling);
                }
                let dotagent_sib = exe.with_file_name("dotagent");
                if is_trusted_executable_file(&dotagent_sib) {
                    return Some(dotagent_sib);
                }
            }
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let local_bin = PathBuf::from(home).join(".local/bin");
        for bin_name in ["agent-guard", "dotagent"] {
            let pinned = local_bin.join(bin_name);
            if is_trusted_executable_file(&pinned) {
                return Some(pinned);
            }
        }
    }
    if let Some(path_os) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_os) {
            if !dir.is_absolute() {
                continue;
            }
            let candidate = dir.join("agent-guard");
            if is_trusted_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// Ensures an out-of-sandbox `agent-guard coordinator` daemon is listening for `repo_root`.
/// Must be called from the host side (outside `exec-sandbox`) before spawning sandboxed
/// `swarm-tool` invocations.
pub fn ensure_coordinator_daemon(repo_root: &Path) -> Result<PathBuf, String> {
    let sock_path = coordinator_socket_path(repo_root)?;
    if ping_coordinator(repo_root) {
        return Ok(sock_path);
    }
    if std::env::var("AGENT_GUARD_IN_SANDBOX").ok().as_deref() == Some("1") {
        return Err(
            "COORDINATOR_UNAVAILABLE_IN_SANDBOX: host coordinator socket is not reachable from sandbox"
                .to_string(),
        );
    }

    let Some(bin) = find_agent_guard_binary() else {
        return Err("agent-guard binary not found to spawn coordinator daemon".to_string());
    };
    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let ipc_dir = coordinator_ipc_dir(&canon_repo)?;
    let spawn_lock_target = ipc_dir.join("coordinator.spawn");
    let _spawn_lock = ExclusiveFileLockGuard::acquire(&spawn_lock_target)?;

    if ping_coordinator(&canon_repo) {
        return Ok(sock_path);
    }

    let mut cmd = Command::new(bin);
    cmd.current_dir(&ipc_dir)
        .arg("coordinator")
        .arg("--repo")
        .arg(&canon_repo)
        .arg("--idle-secs")
        .arg(DEFAULT_IDLE_TIMEOUT_SECS.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Ok(state_override) = std::env::var("AGENT_GUARD_STATE_DIR") {
        cmd.env("AGENT_GUARD_STATE_DIR", state_override);
    }
    cmd.env_remove("AGENT_GUARD_IN_SANDBOX");
    cmd.spawn()
        .map_err(|e| format!("failed spawning agent-guard coordinator daemon: {e}"))?;

    let deadline = Instant::now() + Duration::from_millis(800);
    while Instant::now() < deadline {
        if ping_coordinator(&canon_repo) {
            return Ok(sock_path);
        }
        std::thread::sleep(Duration::from_millis(15));
    }

    Err("timed out waiting for agent-guard coordinator daemon socket readiness".to_string())
}

pub fn rpc_compute_domain_hmac_hex(
    repo_root: &Path,
    domain: &[u8],
    payload: &[u8],
) -> Result<String, String> {
    #[cfg(unix)]
    {
        let sock_path = coordinator_socket_path(repo_root)?;
        let req = JsonValue::Object(vec![
            ("op".to_string(), JsonValue::Str("domain_hmac".to_string())),
            ("domain_hex".to_string(), JsonValue::Str(hex_encode(domain))),
            (
                "payload_hex".to_string(),
                JsonValue::Str(hex_encode(payload)),
            ),
        ]);
        let resp = send_rpc_request(&sock_path, &req)?;
        resp.get("mac_hex")
            .and_then(JsonValue::as_str)
            .map(String::from)
            .ok_or_else(|| "missing mac_hex in coordinator response".to_string())
    }
    #[cfg(not(unix))]
    {
        let _ = (repo_root, domain, payload);
        Err("Unix domain sockets unsupported on this platform".to_string())
    }
}

/// Sends `ACTIVE_SLOT_HMAC_DOMAIN` candidate payload to the coordinator daemon (`op = "domain_hmac"`),
/// where `commit_ipc_active_slot_update` acquires `ExclusiveFileLockGuard(&slot_file)`, verifies
/// `candidate_rev == existing_rev + 1` CAS and non-escalation subset rules, signs the new record,
/// and atomically persists `<swarm_state_dir>/sessions/active_sessions.json` on the host side.
pub fn rpc_commit_active_sessions_cas(
    repo_root: &Path,
    domain: &[u8],
    payload: &[u8],
) -> Result<String, String> {
    rpc_compute_domain_hmac_hex(repo_root, domain, payload)
}

pub fn rpc_verify_domain_hmac(
    repo_root: &Path,
    domain: &[u8],
    payload: &[u8],
    expected_mac_hex: &str,
) -> Result<bool, String> {
    #[cfg(unix)]
    {
        let sock_path = coordinator_socket_path(repo_root)?;
        let req = JsonValue::Object(vec![
            (
                "op".to_string(),
                JsonValue::Str("verify_domain_hmac".to_string()),
            ),
            ("domain_hex".to_string(), JsonValue::Str(hex_encode(domain))),
            (
                "payload_hex".to_string(),
                JsonValue::Str(hex_encode(payload)),
            ),
            (
                "expected_mac_hex".to_string(),
                JsonValue::Str(expected_mac_hex.trim().to_string()),
            ),
        ]);
        let resp = send_rpc_request(&sock_path, &req)?;
        resp.get("valid")
            .and_then(JsonValue::as_bool)
            .ok_or_else(|| "missing valid boolean in coordinator response".to_string())
    }
    #[cfg(not(unix))]
    {
        let _ = (repo_root, domain, payload, expected_mac_hex);
        Err("Unix domain sockets unsupported on this platform".to_string())
    }
}

pub fn load_or_init_feedback_vault_key(repo_root: &Path) -> Result<ZeroizingKey, String> {
    let raw = load_or_init_vault_hmac_key(repo_root)?;
    Ok(ZeroizingKey::new(raw))
}

pub fn compute_domain_tag_for_feedback(
    key: &[u8; 32],
    domain: &[u8],
    payload: &[u8],
) -> Result<[u8; 32], String> {
    compute_domain_tag_raw(key, domain, payload)
}

pub fn rpc_submit_friction_ballot(
    repo_root: &Path,
    ballot_req: &JsonValue,
) -> Result<JsonValue, String> {
    #[cfg(unix)]
    {
        let sock_path = coordinator_socket_path(repo_root)?;
        let worker_token = std::env::var("AGENT_GUARD_IPC_WORKER_TOKEN").unwrap_or_default();
        let req = JsonValue::Object(vec![
            (
                "op".to_string(),
                JsonValue::Str("submit_friction_ballot".to_string()),
            ),
            ("worker_token".to_string(), JsonValue::Str(worker_token)),
            ("ballot_req".to_string(), ballot_req.clone()),
        ]);
        send_rpc_request(&sock_path, &req)
    }
    #[cfg(not(unix))]
    {
        let _ = (repo_root, ballot_req);
        Err("Unix domain sockets unsupported on this platform".to_string())
    }
}

pub fn rpc_compute_raw_hmac_bytes(
    repo_root: &Path,
    canonical_bytes: &[u8],
) -> Result<[u8; 32], String> {
    #[cfg(unix)]
    {
        let sock_path = coordinator_socket_path(repo_root)?;
        let req = JsonValue::Object(vec![
            ("op".to_string(), JsonValue::Str("event_mac".to_string())),
            (
                "canonical_hex".to_string(),
                JsonValue::Str(hex_encode(canonical_bytes)),
            ),
        ]);
        let resp = send_rpc_request(&sock_path, &req)?;
        let mac_hex = resp
            .get("mac_hex")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "missing mac_hex in coordinator response".to_string())?;
        let raw = hex_decode_bytes(mac_hex)?;
        if raw.len() != 32 {
            return Err("coordinator event_mac returned non-32-byte tag".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        Ok(arr)
    }
    #[cfg(not(unix))]
    {
        let _ = (repo_root, canonical_bytes);
        Err("Unix domain sockets unsupported on this platform".to_string())
    }
}

pub fn rpc_verify_event_mac(
    repo_root: &Path,
    canonical_bytes: &[u8],
    expected_mac: &[u8; 32],
) -> Result<bool, String> {
    #[cfg(unix)]
    {
        let sock_path = coordinator_socket_path(repo_root)?;
        let req = JsonValue::Object(vec![
            (
                "op".to_string(),
                JsonValue::Str("verify_event_mac".to_string()),
            ),
            (
                "canonical_hex".to_string(),
                JsonValue::Str(hex_encode(canonical_bytes)),
            ),
            (
                "expected_mac_hex".to_string(),
                JsonValue::Str(hex_encode(expected_mac)),
            ),
        ]);
        let resp = send_rpc_request(&sock_path, &req)?;
        resp.get("valid")
            .and_then(JsonValue::as_bool)
            .ok_or_else(|| "missing valid boolean in coordinator response".to_string())
    }
    #[cfg(not(unix))]
    {
        let _ = (repo_root, canonical_bytes, expected_mac);
        Err("Unix domain sockets unsupported on this platform".to_string())
    }
}

/// Returns the active vault HMAC key epoch counter (`>= 1`) for `repo_root`.
pub fn current_hmac_epoch_id(repo_root: &Path) -> Result<u64, String> {
    let epoch_file = swarm_state_dir(repo_root)?.join("vault/hmac_epoch.json");
    let Ok(raw) = fs::read_to_string(&epoch_file) else {
        return Ok(1);
    };
    let Ok(val) = JsonValue::parse(&raw) else {
        return Ok(1);
    };
    Ok(val
        .get("epoch_id")
        .and_then(JsonValue::as_u64)
        .unwrap_or(1)
        .max(1))
}

static ATOMIC_TMP_COUNTER: AtomicU64 = AtomicU64::new(1);

pub(crate) fn write_atomic_private_0600(path: &Path, body: &[u8]) -> Result<(), String> {
    let staged = stage_atomic_private_0600(path, body)?;
    if let Err(e) = fs::rename(&staged, path) {
        let _ = fs::remove_file(&staged);
        return Err(format!(
            "failed renaming atomic temp onto '{}': {e}",
            path.display()
        ));
    }
    Ok(())
}

fn atomic_private_sibling(path: &Path, suffix: &str) -> Result<PathBuf, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("missing parent directory for '{}'", path.display()))?;
    let seq = ATOMIC_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("atomic.dat");
    Ok(parent.join(format!(".{name}.{suffix}.{}.{seq}", std::process::id())))
}

fn stage_atomic_private_0600(path: &Path, body: &[u8]) -> Result<PathBuf, String> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(format!(
            "SYMLINK_TAMPER_DETECTED: refusing to overwrite symlink '{}'",
            path.display()
        ));
    }
    let tmp_path = atomic_private_sibling(path, "tmp")?;
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp_path)
        .map_err(|e| format!("failed creating atomic temp '{}': {e}", tmp_path.display()))?;
    if let Err(e) = file.write_all(body).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&tmp_path);
        return Err(format!(
            "failed syncing atomic temp '{}': {e}",
            tmp_path.display()
        ));
    }
    Ok(tmp_path)
}

pub(crate) enum EpochFileUpdate {
    Replace(PathBuf, Vec<u8>),
    Retire(PathBuf),
}

struct StagedEpochFile {
    path: PathBuf,
    replacement: Option<PathBuf>,
    backup: Option<PathBuf>,
}

impl StagedEpochFile {
    fn stage(update: EpochFileUpdate) -> Result<Self, String> {
        let (path, body) = match update {
            EpochFileUpdate::Replace(path, body) => (path, Some(body)),
            EpochFileUpdate::Retire(path) => (path, None),
        };
        let parent = path.parent().ok_or("epoch state file has no parent")?;
        crate::traversal_ledger::ensure_nonsymlink_state_dir(parent)?;
        let mut staged = Self {
            path,
            replacement: None,
            backup: None,
        };
        match fs::symlink_metadata(&staged.path) {
            Ok(meta) if meta.is_file() => {
                let backup = atomic_private_sibling(&staged.path, "epoch-backup")?;
                fs::hard_link(&staged.path, &backup).map_err(|e| {
                    format!(
                        "failed preserving epoch state '{}': {e}",
                        staged.path.display()
                    )
                })?;
                staged.backup = Some(backup);
            }
            Ok(_) => {
                return Err(format!(
                    "epoch state '{}' must be a regular file",
                    staged.path.display()
                ));
            }
            Err(e) if e.kind() == ErrorKind::NotFound && body.is_some() => {}
            Err(e) => {
                return Err(format!(
                    "failed inspecting epoch state '{}': {e}",
                    staged.path.display()
                ));
            }
        }
        if let Some(body) = body {
            staged.replacement = Some(stage_atomic_private_0600(&staged.path, &body)?);
        }
        Ok(staged)
    }

    fn publish(&self) -> std::io::Result<()> {
        match &self.replacement {
            Some(replacement) => fs::rename(replacement, &self.path),
            None => fs::remove_file(&self.path),
        }
    }

    fn restore(&mut self) -> Result<(), String> {
        if let Some(backup) = self.backup.take() {
            fs::rename(&backup, &self.path).map_err(|e| {
                format!(
                    "failed restoring '{}' from '{}': {e}",
                    self.path.display(),
                    backup.display()
                )
            })
        } else {
            fs::remove_file(&self.path).map_err(|e| {
                format!(
                    "failed removing new epoch state '{}': {e}",
                    self.path.display()
                )
            })
        }
    }
}

impl Drop for StagedEpochFile {
    fn drop(&mut self) {
        for path in self.replacement.iter().chain(self.backup.iter()) {
            let _ = fs::remove_file(path);
        }
    }
}

fn publish_staged_epoch(mut staged: Vec<StagedEpochFile>) -> Result<(), String> {
    for index in 0..staged.len() {
        if let Err(e) = staged[index].publish() {
            let mut failure = format!(
                "failed publishing epoch state '{}': {e}",
                staged[index].path.display()
            );
            for file in staged[..index].iter_mut().rev() {
                if let Err(restore_error) = file.restore() {
                    failure.push_str("\nEPOCH_ROTATION_RECOVERY_REQUIRED: ");
                    failure.push_str(&restore_error);
                }
            }
            return Err(failure);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn socket_dev_ino(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::symlink_metadata(path).ok()?;
    Some((m.dev(), m.ino()))
}

#[cfg(unix)]
fn unlink_if_same_inode(path: &Path, expected_id: Option<(u64, u64)>) {
    if let Some(exp) = expected_id {
        if socket_dev_ino(path) == Some(exp) {
            let _ = fs::remove_file(path);
        }
    }
}

/// Rotates `<swarm_state_dir>/vault/hmac.key` to a fresh 256-bit OS CSPRNG key (`0600`),
/// increments `vault/hmac_epoch.json`, and retires any active `coord.sock` bound to the old epoch.
/// Strictly host-only: hard-denied inside `exec-sandbox` or worker locks.
pub fn rotate_vault_hmac_epoch(repo_root: &Path) -> Result<u64, String> {
    rotate_vault_hmac_epoch_with_files(repo_root, |_| Ok(Vec::new()))
}

/// Prepares dependent records under the epoch lock and replaces the active key only after all
/// other writes succeed. Callers hold the locks protecting their own dependent records.
pub(crate) fn rotate_vault_hmac_epoch_with_files(
    repo_root: &Path,
    prepare: impl FnOnce(&[u8; 32]) -> Result<Vec<EpochFileUpdate>, String>,
) -> Result<u64, String> {
    if std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() == Ok("1")
        || std::env::var("AGENT_GUARD_WORKER_LOCK").as_deref() == Ok("1")
    {
        return Err(
            "EPOCH_ROTATION_DENIED_IN_SANDBOX: vault HMAC rotation requires trusted host authority"
                .to_string(),
        );
    }
    let lock_path = crate::breadcrumbs::swarm_locks_dir()?.join("vault_hmac_epoch.lock");
    let _guard = ExclusiveFileLockGuard::acquire(&lock_path)?;

    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let key_file = crate::breadcrumbs::vault_hmac_key_path(&canon_repo)?;
    let epoch_file = key_file.with_file_name("hmac_epoch.json");

    if let Ok(meta) = fs::symlink_metadata(&key_file)
        && meta.file_type().is_symlink()
    {
        return Err("VAULT_SYMLINK_TAMPER: vault/hmac.key is a symlink".to_string());
    }
    if let Ok(meta) = fs::symlink_metadata(&epoch_file)
        && meta.file_type().is_symlink()
    {
        return Err("VAULT_SYMLINK_TAMPER: vault/hmac_epoch.json is a symlink".to_string());
    }
    // Preserve the bootstrap and legacy migration behavior when a caller rotates before jobs run.
    drop(ZeroizingKey::new(load_or_init_vault_hmac_key(&canon_repo)?));

    let next_epoch = current_hmac_epoch_id(&canon_repo)?.saturating_add(1);
    let mut fresh_key = [0u8; 32];
    #[cfg(unix)]
    {
        let mut urandom = fs::File::open("/dev/urandom")
            .map_err(|e| format!("failed opening /dev/urandom for epoch rotation: {e}"))?;
        urandom
            .read_exact(&mut fresh_key)
            .map_err(|e| format!("failed reading 32 CSPRNG bytes: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        fresh_key = crate::crypto::sha256_bytes(&nanos.to_le_bytes());
    }

    let fresh_zk = ZeroizingKey::new(fresh_key);
    zeroize_raw_arr(&mut fresh_key);
    let meta_json = JsonValue::Object(vec![
        ("epoch_id".to_string(), JsonValue::Uint(next_epoch)),
        (
            "rotated_at_unix".to_string(),
            JsonValue::Uint(now_epoch_secs()),
        ),
    ])
    .to_json_string();
    let mut updates = prepare(fresh_zk.as_bytes())?;
    updates.push(EpochFileUpdate::Replace(
        epoch_file,
        format!("{meta_json}\n").into_bytes(),
    ));
    let mut staged = updates
        .into_iter()
        .map(StagedEpochFile::stage)
        .collect::<Result<Vec<_>, _>>()?;
    let mut key_body = format!("{}\n", hex_encode(fresh_zk.as_bytes())).into_bytes();
    let key_update = stage_atomic_private_0600(&key_file, &key_body);
    crate::crypto::zeroize_slice(&mut key_body);
    // The final rename commits the new epoch. Until it succeeds the original key is untouched.
    staged.push(StagedEpochFile {
        path: key_file,
        replacement: Some(key_update?),
        backup: None,
    });
    publish_staged_epoch(staged)?;

    // Unlink existing socket path so the next coordinator call binds with the rotated key
    if let Ok(sock) = coordinator_socket_path(&canon_repo) {
        let _ = fs::remove_file(sock);
    }
    Ok(next_epoch)
}

fn zeroize_raw_arr(buf: &mut [u8; 32]) {
    crate::crypto::zeroize_slice(buf);
}

/// Returns the host-only warm hook daemon socket path (`~/.local/state/agent-guard/daemon/hook.sock`).
/// This path resides inside `state_base_dir()`, which is hard-blocked by Landlock, Seatbelt, and
/// `path_policy.rs`, ensuring sandboxed worker subprocesses can NEVER connect to `hook.sock`.
pub fn hook_daemon_socket_path() -> Result<PathBuf, String> {
    let base = crate::traversal_ledger::state_base_dir();
    let daemon_dir = base.join("daemon");
    if let Ok(meta) = fs::symlink_metadata(&daemon_dir)
        && meta.file_type().is_symlink()
    {
        return Err("HOOK_DAEMON_SYMLINK_TAMPER: daemon directory is a symlink".to_string());
    }
    fs::create_dir_all(&daemon_dir).map_err(|e| {
        format!(
            "failed creating hook daemon dir '{}': {e}",
            daemon_dir.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&daemon_dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("failed setting 0700 on hook daemon dir: {e}"))?;
    }
    Ok(daemon_dir.join("hook.sock"))
}

pub fn ping_hook_daemon() -> bool {
    #[cfg(unix)]
    {
        let Ok(sock_path) = hook_daemon_socket_path() else {
            return false;
        };
        let req = JsonValue::Object(vec![("op".to_string(), JsonValue::Str("ping".to_string()))]);
        send_rpc_request(&sock_path, &req).is_ok()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn write_auto_warm_marker(daemon_dir: &Path) {
    let marker = daemon_dir.join("auto_warm.enabled");
    if fs::symlink_metadata(&marker).is_ok_and(|m| m.file_type().is_symlink()) {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(crate::traversal_ledger::O_NOFOLLOW_FLAG)
            .open(&marker)
        {
            let _ = f.write_all(b"1\n");
            let _ = fs::set_permissions(&marker, fs::Permissions::from_mode(0o600));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = fs::write(&marker, b"1\n");
    }
}

fn spawn_hook_daemon_process(sock_path: &Path) -> Result<(), String> {
    let Some(bin) = find_agent_guard_binary() else {
        return Err("agent-guard binary not found to spawn hook daemon".to_string());
    };
    let parent = sock_path
        .parent()
        .ok_or_else(|| "missing hook.sock parent".to_string())?;
    let spawn_lock = parent.join("hook_daemon.spawn");
    let _guard = ExclusiveFileLockGuard::acquire(&spawn_lock)?;
    if ping_hook_daemon() {
        return Ok(());
    }
    let mut daemon_cmd = std::process::Command::new(bin);
    daemon_cmd
        .arg("hook-daemon")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    for scrub_key in [
        "AGENT_GUARD_ALLOW_SWARM",
        "AGENT_GUARD_ALLOW_DEPUTY",
        "AGENT_GUARD_ALLOW_INTERPRETER",
        "AGENT_GUARD_WRAP_BASH_ASCII",
        "AGENT_GUARD_DIRECT_EXPLORE",
        "AGENT_GUARD_PROFILE",
        "AGENT_GUARD_ROLE",
        "AGENT_GUARD_SESSION_ID",
        "AGENT_GUARD_ROOT_SESSION_ID",
        "AGENT_GUARD_PARENT_SESSION_ID",
        "AGENT_GUARD_REPO_ROOT",
    ] {
        daemon_cmd.env_remove(scrub_key);
    }
    let _child = daemon_cmd
        .spawn()
        .map_err(|e| format!("failed spawning hook-daemon: {e}"))?;
    Ok(())
}

pub fn ensure_hook_daemon() -> Result<PathBuf, String> {
    if std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() == Ok("1")
        || std::env::var("AGENT_GUARD_WORKER_LOCK").as_deref() == Ok("1")
    {
        return Err("HOOK_DAEMON_DENIED_IN_SANDBOX: warm hook daemon is host-only".to_string());
    }
    let sock_path = hook_daemon_socket_path()?;
    if ping_hook_daemon() {
        return Ok(sock_path);
    }
    spawn_hook_daemon_process(&sock_path)?;
    for _ in 0..40 {
        if ping_hook_daemon() {
            return Ok(sock_path);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err("timed out waiting for hook-daemon socket".to_string())
}

/// Auto-spawns the warm host hook daemon (`hook.sock`) and marks the state namespace for lazy
/// background re-warming after idle timeouts, unless disabled by `DOTAGENT_NO_AUTO_COORD=1`.
pub fn ensure_hot_hook_daemon() -> Result<PathBuf, String> {
    if std::env::var("DOTAGENT_NO_AUTO_COORD").as_deref() == Ok("1") {
        return Err("HOOK_DAEMON_AUTO_DISABLED: DOTAGENT_NO_AUTO_COORD=1".to_string());
    }
    let sock_path = ensure_hook_daemon()?;
    if let Some(parent) = sock_path.parent() {
        write_auto_warm_marker(parent);
    }
    Ok(sock_path)
}

/// Spawns `agent-guard hook-daemon` detached without waiting for socket readiness so lazy wakeup
/// in `eval_hook_preferring_hot_coord` never blocks cold CLI latency.
pub fn spawn_hot_hook_daemon_detached() -> Result<PathBuf, String> {
    if std::env::var("DOTAGENT_NO_AUTO_COORD").as_deref() == Ok("1") {
        return Err("HOOK_DAEMON_AUTO_DISABLED: DOTAGENT_NO_AUTO_COORD=1".to_string());
    }
    if std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() == Ok("1")
        || std::env::var("AGENT_GUARD_WORKER_LOCK").as_deref() == Ok("1")
    {
        return Err("HOOK_DAEMON_DENIED_IN_SANDBOX: warm hook daemon is host-only".to_string());
    }
    let sock_path = hook_daemon_socket_path()?;
    if let Some(parent) = sock_path.parent() {
        write_auto_warm_marker(parent);
    }
    spawn_hook_daemon_process(&sock_path)?;
    Ok(sock_path)
}

pub fn maybe_auto_warm_on_activate() {
    #[cfg(test)]
    if std::env::var("DOTAGENT_FORCE_TEST_AUTO_COORD").as_deref() != Ok("1") {
        return;
    }
    if std::env::var("DOTAGENT_NO_AUTO_COORD").as_deref() == Ok("1")
        || std::env::var("AGENT_GUARD_HOT_COORD").as_deref() == Ok("0")
    {
        return;
    }
    let _ = ensure_hot_hook_daemon();
}

/// Removes `daemon/auto_warm.enabled` and `daemon/hook.sock` so any warm `hook-daemon` in the
/// active state namespace detects socket unlink, drops `HostTelemetry`, and terminates cleanly.
pub fn stop_hot_hook_daemon() {
    let base_dir = crate::traversal_ledger::state_base_dir();
    let daemon_dir = base_dir.join("daemon");
    let sock_path = daemon_dir.join("hook.sock");
    let was_present = fs::symlink_metadata(&sock_path).is_ok()
        || fs::symlink_metadata(daemon_dir.join("auto_warm.enabled")).is_ok();
    let _ = fs::remove_file(daemon_dir.join("auto_warm.enabled"));
    let _ = fs::remove_file(&sock_path);
    if was_present {
        let route_path = base_dir.join("observations/route");
        let deadline = Instant::now() + Duration::from_millis(350);
        while Instant::now() < deadline {
            if !ping_hook_daemon() && fs::symlink_metadata(&route_path).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Determines whether `eval_hook_preferring_hot_coord` should use or lazily warm `hook.sock`.
/// Preserves strict absent-state isolation for unactivated cold workspaces when `daemon/` is absent.
pub fn should_auto_warm_hook_daemon(repo_root: &Path) -> bool {
    if std::env::var("DOTAGENT_NO_AUTO_COORD").as_deref() == Ok("1")
        || std::env::var("AGENT_GUARD_HOT_COORD").as_deref() == Ok("0")
        || std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() == Ok("1")
        || std::env::var("AGENT_GUARD_WORKER_LOCK").as_deref() == Ok("1")
    {
        return false;
    }
    if std::env::var("AGENT_GUARD_HOT_COORD").as_deref() == Ok("1") {
        return true;
    }
    let daemon_dir = crate::traversal_ledger::state_base_dir().join("daemon");
    if fs::symlink_metadata(daemon_dir.join("hook.sock")).is_ok()
        || fs::symlink_metadata(daemon_dir.join("auto_warm.enabled")).is_ok()
    {
        return true;
    }
    if crate::enforcement_state::is_attested_sims_microvm() {
        return true;
    }
    fs::symlink_metadata(repo_root.join(".claude/settings.json")).is_ok()
        || fs::symlink_metadata(repo_root.join(".cursor/hooks.json")).is_ok()
        || fs::symlink_metadata(repo_root.join(".agents/hooks.json")).is_ok()
}

/// Evaluates `pre-tool` or `post-tool` over the host-only `hook.sock` daemon (`< 150 us` steady-state
/// with hot in-memory `SessionLedger` write-through cache). Never touches worker `coord.sock` and
/// hard-rejects `user-prompt` / `pre-compact`, sandboxed callers, or custom per-process override flags.
pub fn rpc_eval_hook(
    repo_root: &Path,
    phase: &str,
    hook_payload: &str,
    cwd: &Path,
) -> Result<crate::Decision, String> {
    rpc_eval_hook_with_mode(repo_root, phase, hook_payload, cwd, true).map(|(d, _)| d)
}

pub fn rpc_eval_hook_with_mode(
    repo_root: &Path,
    phase: &str,
    hook_payload: &str,
    cwd: &Path,
    wait_for_spawn: bool,
) -> Result<(crate::Decision, u64), String> {
    if std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() == Ok("1")
        || std::env::var("AGENT_GUARD_WORKER_LOCK").as_deref() == Ok("1")
    {
        return Err("HOOK_DAEMON_DENIED_IN_SANDBOX".to_string());
    }
    if !matches!(phase, "pre-tool" | "post-tool") {
        return Err(format!(
            "UNSUPPORTED_HOOK_DAEMON_PHASE: '{phase}' must execute in-process"
        ));
    }
    // Any non-default per-process override flag executes in-process so `hook-daemon` stays 100% privilege-neutral.
    for custom_flag in [
        "AGENT_GUARD_ALLOW_SWARM",
        "AGENT_GUARD_ALLOW_DEPUTY",
        "AGENT_GUARD_ALLOW_INTERPRETER",
        "AGENT_GUARD_WRAP_BASH_ASCII",
        "AGENT_GUARD_REPO_ROOT",
    ] {
        if std::env::var_os(custom_flag).is_some() {
            return Err("HOOK_DAEMON_CUSTOM_ENV_INPROC".to_string());
        }
    }
    #[cfg(unix)]
    {
        let sock_path = hook_daemon_socket_path()?;
        let caller_sid = std::env::var("AGENT_GUARD_SESSION_ID").ok();
        let caller_root_sid = std::env::var("AGENT_GUARD_ROOT_SESSION_ID")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                std::env::var("AGENT_GUARD_PARENT_SESSION_ID")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
            });
        let caller_profile = std::env::var("AGENT_GUARD_PROFILE").ok();
        let caller_role = std::env::var("AGENT_GUARD_ROLE").ok();
        let caller_direct_explore = std::env::var("AGENT_GUARD_DIRECT_EXPLORE").ok();
        let caller_traceparent = std::env::var("TRACEPARENT")
            .ok()
            .or_else(|| std::env::var("W3C_TRACEPARENT").ok());
        let req = JsonValue::Object(vec![
            ("op".to_string(), JsonValue::Str("eval_hook".to_string())),
            ("phase".to_string(), JsonValue::Str(phase.to_string())),
            (
                "payload".to_string(),
                JsonValue::Str(hook_payload.to_string()),
            ),
            (
                "repo_root".to_string(),
                JsonValue::Str(repo_root.to_string_lossy().into_owned()),
            ),
            (
                "cwd".to_string(),
                JsonValue::Str(cwd.to_string_lossy().into_owned()),
            ),
            (
                "caller_session_id".to_string(),
                caller_sid.map_or(JsonValue::Null, JsonValue::Str),
            ),
            (
                "caller_root_session_id".to_string(),
                caller_root_sid.map_or(JsonValue::Null, JsonValue::Str),
            ),
            (
                "caller_profile".to_string(),
                caller_profile.map_or(JsonValue::Null, JsonValue::Str),
            ),
            (
                "caller_role".to_string(),
                caller_role.map_or(JsonValue::Null, JsonValue::Str),
            ),
            (
                "caller_direct_explore".to_string(),
                caller_direct_explore.map_or(JsonValue::Null, JsonValue::Str),
            ),
            (
                "caller_traceparent".to_string(),
                caller_traceparent.map_or(JsonValue::Null, JsonValue::Str),
            ),
        ]);
        let ipc_t0 = Instant::now();
        let resp = match send_rpc_request(&sock_path, &req) {
            Ok(r) => r,
            Err(_) if wait_for_spawn => {
                let fresh_sock = ensure_hot_hook_daemon()?;
                send_rpc_request(&fresh_sock, &req)?
            }
            Err(_) => {
                let _ = spawn_hot_hook_daemon_detached();
                return Err("LAZY_WARM_SPAWNED_FALLBACK_INPROC".to_string());
            }
        };
        let coord_ipc_ns = u64::try_from(ipc_t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let allow = resp
            .get("allow")
            .and_then(JsonValue::as_bool)
            .ok_or_else(|| "missing allow boolean in eval_hook response".to_string())?;
        let decision = if allow {
            crate::Decision::Allow {
                advisory: resp
                    .get("advisory")
                    .and_then(JsonValue::as_str)
                    .map(String::from),
                updated_input_json: resp
                    .get("updated_input_json")
                    .and_then(JsonValue::as_str)
                    .map(String::from),
                updated_bash_cmd: resp
                    .get("updated_bash_cmd")
                    .and_then(JsonValue::as_str)
                    .map(String::from),
            }
        } else {
            let code_str = resp
                .get("code")
                .and_then(JsonValue::as_str)
                .unwrap_or("COORDINATOR_HOOK_DENY");
            let reason = resp
                .get("reason")
                .and_then(JsonValue::as_str)
                .unwrap_or("Denied by hook daemon")
                .to_string();
            let halt_session = resp
                .get("halt_session")
                .and_then(JsonValue::as_bool)
                .unwrap_or(false);
            crate::Decision::Deny {
                code: intern_known_guard_code(code_str),
                reason,
                halt_session,
            }
        };
        Ok((decision, coord_ipc_ns))
    }
    #[cfg(not(unix))]
    {
        let _ = (repo_root, phase, hook_payload, cwd, wait_for_spawn);
        Err("Unix domain sockets unsupported on this platform".to_string())
    }
}

fn is_valid_guard_reason_token(code: &str) -> bool {
    let bytes = code.as_bytes();
    if !(2..=96).contains(&bytes.len()) || !bytes[0].is_ascii_uppercase() {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

pub fn intern_known_guard_code(code: &str) -> &'static str {
    if let Some(gc) = crate::diagnostics::GuardCode::from_code_str(code) {
        return gc.as_str();
    }
    if !is_valid_guard_reason_token(code) {
        return "COORDINATOR_HOOK_DENY";
    }
    static DYNAMIC_REASON_POOL: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<String, &'static str>>,
    > = std::sync::OnceLock::new();
    let pool = DYNAMIC_REASON_POOL
        .get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let Ok(mut guard) = pool.lock() else {
        return "COORDINATOR_HOOK_DENY";
    };
    if let Some(&existing) = guard.get(code) {
        return existing;
    }
    if guard.len() >= 4096 {
        return "COORDINATOR_HOOK_DENY";
    }
    let leaked: &'static str = Box::leak(code.to_string().into_boxed_str());
    guard.insert(code.to_string(), leaked);
    leaked
}

/// CLI entrypoint for host-only `agent-guard hook-daemon [--idle-secs <N>]`.
pub fn run_hook_daemon_cli(args: &[String]) -> ExitCode {
    if std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() == Ok("1")
        || std::env::var("AGENT_GUARD_WORKER_LOCK").as_deref() == Ok("1")
    {
        eprintln!(
            "[agent-guard hook-daemon] HARD DENY: hook-daemon is restricted to host authority."
        );
        return ExitCode::from(2);
    }
    #[cfg(not(unix))]
    {
        let _ = args;
        eprintln!("[agent-guard hook-daemon] Unix domain sockets require a Unix host.");
        ExitCode::from(2)
    }
    #[cfg(unix)]
    {
        let mut idle_secs = DEFAULT_IDLE_TIMEOUT_SECS;
        let mut idx = 0usize;
        while idx < args.len() {
            if args[idx] == "--idle-secs" && idx + 1 < args.len() {
                if let Ok(v) = args[idx + 1].parse::<u64>() {
                    idle_secs = v.clamp(2, 3600);
                }
                idx += 2;
            } else {
                idx += 1;
            }
        }

        let sock_path = match hook_daemon_socket_path() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[agent-guard hook-daemon] socket path error: {e}");
                return ExitCode::from(2);
            }
        };
        if ping_hook_daemon() {
            return ExitCode::SUCCESS;
        }
        let _ = fs::remove_file(&sock_path);
        let listener = match bind_unix_short_path(&sock_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[agent-guard hook-daemon] bind error: {e}");
                return ExitCode::from(2);
            }
        };
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o600));
        }
        let bound_inode = socket_dev_ino(&sock_path);
        let _ = listener.set_nonblocking(true);

        let hot_cache: Arc<crate::traversal_ledger::HotLedgerCache> =
            Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
        let last_activity = Arc::new(AtomicU64::new(now_epoch_secs()));
        let active_clients = Arc::new(AtomicUsize::new(0));
        let mut empty_polls: u32 = 0;
        loop {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    empty_polls = 0;
                    last_activity.store(now_epoch_secs(), Ordering::Relaxed);
                    if active_clients.load(Ordering::Relaxed) >= MAX_CONCURRENT_IPC_CLIENTS {
                        drop(stream);
                        continue;
                    }
                    active_clients.fetch_add(1, Ordering::AcqRel);
                    let cache_ref = Arc::clone(&hot_cache);
                    let active_ref = Arc::clone(&active_clients);
                    std::thread::spawn(move || {
                        let _ = handle_hook_daemon_client(stream, &cache_ref);
                        active_ref.fetch_sub(1, Ordering::AcqRel);
                    });
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    empty_polls = empty_polls.saturating_add(1);
                    if empty_polls <= 64 {
                        std::thread::yield_now();
                        continue;
                    }
                    let socket_replaced = socket_dev_ino(&sock_path) != bound_inode;
                    let elapsed =
                        now_epoch_secs().saturating_sub(last_activity.load(Ordering::Relaxed));
                    if (socket_replaced || elapsed >= idle_secs)
                        && active_clients.load(Ordering::Acquire) == 0
                    {
                        unlink_if_same_inode(&sock_path, bound_inode);
                        return ExitCode::SUCCESS;
                    }
                    if empty_polls <= 2_500 {
                        std::thread::sleep(Duration::from_micros(100));
                    } else {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
}

#[cfg(unix)]
fn handle_hook_daemon_client(
    mut stream: UnixStream,
    hot_cache: &crate::traversal_ledger::HotLedgerCache,
) -> Result<(), String> {
    let ipc_t0 = Instant::now();
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

    let mut line = String::new();
    {
        let mut reader = BufReader::new((&mut stream).take(MAX_RPC_LINE_BYTES as u64));
        reader
            .read_line(&mut line)
            .map_err(|e| format!("read error: {e}"))?;
    }
    let ipc_read_ns = u64::try_from(ipc_t0.elapsed().as_nanos()).ok();
    let resp = match process_hook_daemon_line_with_ipc(line.trim(), hot_cache, ipc_read_ns) {
        Ok(val) => val,
        Err(err) => JsonValue::Object(vec![
            ("ok".to_string(), JsonValue::Bool(false)),
            ("error".to_string(), JsonValue::Str(err)),
        ]),
    };
    let mut encoded = resp.to_json_string();
    encoded.push('\n');
    stream
        .write_all(encoded.as_bytes())
        .map_err(|e| format!("write error: {e}"))?;
    let _ = stream.flush();
    Ok(())
}

fn process_hook_daemon_line_with_ipc(
    raw: &str,
    hot_cache: &crate::traversal_ledger::HotLedgerCache,
    coord_ipc_ns: Option<u64>,
) -> Result<JsonValue, String> {
    let req = JsonValue::parse(raw).map_err(|e| format!("invalid JSON: {e}"))?;
    let op = req
        .get("op")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| "missing op field".to_string())?;
    match op {
        "ping" => Ok(JsonValue::Object(vec![(
            "ok".to_string(),
            JsonValue::Bool(true),
        )])),
        "eval_hook" => {
            let phase = req
                .get("phase")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing phase field".to_string())?;
            if !matches!(phase, "pre-tool" | "post-tool") {
                return Err(format!(
                    "UNSUPPORTED_HOOK_DAEMON_PHASE: phase '{phase}' is forbidden over hook.sock"
                ));
            }
            let payload = req
                .get("payload")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing payload field".to_string())?;
            let raw_repo = req
                .get("repo_root")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing repo_root field".to_string())?;
            let canon_repo = fs::canonicalize(raw_repo).unwrap_or_else(|_| PathBuf::from(raw_repo));
            let raw_cwd = req
                .get("cwd")
                .and_then(JsonValue::as_str)
                .map(PathBuf::from)
                .unwrap_or_else(|| canon_repo.clone());
            let checked_cwd = fs::canonicalize(&raw_cwd).unwrap_or(raw_cwd);
            if !checked_cwd.starts_with(&canon_repo) {
                return Err(
                    "EVAL_HOOK_OUTSIDE_REPO_DENIED: cwd must reside within repository".to_string(),
                );
            }
            let caller_ctx = crate::HookCallerContext {
                session_id: req
                    .get("caller_session_id")
                    .and_then(JsonValue::as_str)
                    .map(String::from),
                root_session_id: req
                    .get("caller_root_session_id")
                    .and_then(JsonValue::as_str)
                    .map(String::from),
                profile_id: req
                    .get("caller_profile")
                    .and_then(JsonValue::as_str)
                    .map(String::from),
                role_id: req
                    .get("caller_role")
                    .and_then(JsonValue::as_str)
                    .map(String::from),
                direct_explore: req
                    .get("caller_direct_explore")
                    .and_then(JsonValue::as_str)
                    .map(String::from),
            };
            let caller_traceparent = req.get("caller_traceparent").and_then(JsonValue::as_str);
            let decision = match phase {
                "pre-tool" => crate::handle_pre_tool_hook_with_context_and_ipc(
                    payload,
                    &checked_cwd,
                    &caller_ctx,
                    Some(hot_cache),
                    coord_ipc_ns,
                    caller_traceparent,
                ),
                "post-tool" => crate::handle_post_tool_hook_with_context(
                    payload,
                    &checked_cwd,
                    &caller_ctx,
                    Some(hot_cache),
                ),
                _ => return Err(format!("unsupported hook phase '{phase}'")),
            };
            match decision {
                crate::Decision::Allow {
                    advisory,
                    updated_input_json,
                    updated_bash_cmd,
                } => Ok(JsonValue::Object(vec![
                    ("ok".to_string(), JsonValue::Bool(true)),
                    ("allow".to_string(), JsonValue::Bool(true)),
                    (
                        "advisory".to_string(),
                        advisory.map_or(JsonValue::Null, JsonValue::Str),
                    ),
                    (
                        "updated_input_json".to_string(),
                        updated_input_json.map_or(JsonValue::Null, JsonValue::Str),
                    ),
                    (
                        "updated_bash_cmd".to_string(),
                        updated_bash_cmd.map_or(JsonValue::Null, JsonValue::Str),
                    ),
                ])),
                crate::Decision::Deny {
                    code,
                    reason,
                    halt_session,
                } => Ok(JsonValue::Object(vec![
                    ("ok".to_string(), JsonValue::Bool(true)),
                    ("allow".to_string(), JsonValue::Bool(false)),
                    ("code".to_string(), JsonValue::Str(code.to_string())),
                    ("reason".to_string(), JsonValue::Str(reason)),
                    ("halt_session".to_string(), JsonValue::Bool(halt_session)),
                ])),
            }
        }
        other => Err(format!("unknown hook-daemon op '{other}'")),
    }
}

/// CLI entrypoint for `agent-guard coordinator [rotate-epoch|epoch-status] [--repo <path>] [--idle-secs <N>]`.
pub fn run_coordinator_cli(args: &[String], default_cwd: &Path) -> ExitCode {
    if let Some(sub @ ("rotate-epoch" | "epoch-status")) = args.first().map(String::as_str) {
        let mut repo_root = crate::resolve_repo_root(default_cwd);
        let mut i = 1usize;
        while i < args.len() {
            if args[i] == "--repo" && i + 1 < args.len() {
                repo_root = PathBuf::from(&args[i + 1]);
                i += 2;
            } else {
                i += 1;
            }
        }
        if sub == "epoch-status" {
            match current_hmac_epoch_id(&repo_root) {
                Ok(ep) => {
                    println!(r#"{{"status":"OK","epoch_id":{ep}}}"#);
                    return ExitCode::SUCCESS;
                }
                Err(e) => {
                    eprintln!("[agent-guard coordinator] {e}");
                    return ExitCode::from(2);
                }
            }
        }
        match rotate_vault_hmac_epoch(&repo_root) {
            Ok(ep) => {
                println!(r#"{{"status":"HMAC_EPOCH_ROTATED","epoch_id":{ep}}}"#);
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("[agent-guard coordinator] HARD DENY: {e}");
                return ExitCode::from(2);
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = (args, default_cwd);
        eprintln!("[agent-guard coordinator] Unix domain sockets require a Unix host.");
        ExitCode::from(2)
    }
    #[cfg(unix)]
    {
        let mut repo_root = default_cwd.to_path_buf();
        let mut idle_secs = DEFAULT_IDLE_TIMEOUT_SECS;
        let mut idx = 0usize;
        while idx < args.len() {
            match args[idx].as_str() {
                "--repo" if idx + 1 < args.len() => {
                    repo_root = PathBuf::from(&args[idx + 1]);
                    idx += 2;
                }
                "--idle-secs" if idx + 1 < args.len() => {
                    if let Ok(v) = args[idx + 1].parse::<u64>() {
                        idle_secs = v.clamp(2, 3600);
                    }
                    idx += 2;
                }
                _ => {
                    idx += 1;
                }
            }
        }

        let canon_repo = Arc::new(fs::canonicalize(&repo_root).unwrap_or(repo_root));
        let bound_epoch = match current_hmac_epoch_id(&canon_repo) {
            Ok(ep) => ep,
            Err(e) => {
                eprintln!("[agent-guard coordinator] epoch read error: {e}");
                return ExitCode::from(2);
            }
        };
        let key = match load_or_init_vault_hmac_key(&canon_repo) {
            Ok(k) => Arc::new(ZeroizingKey::new(k)),
            Err(e) => {
                eprintln!("[agent-guard coordinator] vault key error: {e}");
                return ExitCode::from(2);
            }
        };
        let sock_path = match coordinator_socket_path(&canon_repo) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[agent-guard coordinator] socket path error: {e}");
                return ExitCode::from(2);
            }
        };

        if ping_coordinator(&canon_repo) {
            return ExitCode::SUCCESS;
        }
        let _ = fs::remove_file(&sock_path);

        let listener = match bind_unix_short_path(&sock_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[agent-guard coordinator] bind error: {e}");
                return ExitCode::from(2);
            }
        };
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o600));
        }
        let bound_inode = socket_dev_ino(&sock_path);
        let _ = listener.set_nonblocking(true);

        let last_activity = Arc::new(AtomicU64::new(now_epoch_secs()));
        let active_clients = Arc::new(AtomicUsize::new(0));
        let mut empty_polls: u32 = 0;
        loop {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    empty_polls = 0;
                    if current_hmac_epoch_id(&canon_repo).unwrap_or(bound_epoch) != bound_epoch {
                        drop(stream);
                        if active_clients.load(Ordering::Acquire) == 0 {
                            unlink_if_same_inode(&sock_path, bound_inode);
                            return ExitCode::SUCCESS;
                        }
                        continue;
                    }
                    last_activity.store(now_epoch_secs(), Ordering::Relaxed);
                    if active_clients.load(Ordering::Relaxed) >= MAX_CONCURRENT_IPC_CLIENTS {
                        // Drop excess connection immediately to prevent fd/thread exhaustion
                        drop(stream);
                        continue;
                    }
                    active_clients.fetch_add(1, Ordering::AcqRel);
                    let key_ref = Arc::clone(&key);
                    let repo_ref = Arc::clone(&canon_repo);
                    let active_ref = Arc::clone(&active_clients);
                    std::thread::spawn(move || {
                        let _ = handle_coordinator_client(
                            stream,
                            key_ref.as_bytes(),
                            &repo_ref,
                            bound_epoch,
                        );
                        active_ref.fetch_sub(1, Ordering::AcqRel);
                    });
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    empty_polls = empty_polls.saturating_add(1);
                    if empty_polls <= 64 {
                        std::thread::yield_now();
                        continue;
                    }
                    let epoch_retired =
                        current_hmac_epoch_id(&canon_repo).unwrap_or(bound_epoch) != bound_epoch;
                    let socket_replaced = socket_dev_ino(&sock_path) != bound_inode;
                    let elapsed =
                        now_epoch_secs().saturating_sub(last_activity.load(Ordering::Relaxed));
                    if (epoch_retired || socket_replaced || elapsed >= idle_secs)
                        && active_clients.load(Ordering::Acquire) == 0
                    {
                        unlink_if_same_inode(&sock_path, bound_inode);
                        return ExitCode::SUCCESS;
                    }
                    if empty_polls <= 2_500 {
                        std::thread::sleep(Duration::from_micros(100));
                    } else {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
}

#[cfg(unix)]
fn handle_coordinator_client(
    mut stream: UnixStream,
    key: &[u8; 32],
    canon_repo: &Path,
    bound_epoch: u64,
) -> Result<(), String> {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

    let mut line = String::new();
    {
        let mut reader = BufReader::new((&mut stream).take(MAX_RPC_LINE_BYTES as u64));
        reader
            .read_line(&mut line)
            .map_err(|e| format!("read error: {e}"))?;
    }
    let live_epoch = current_hmac_epoch_id(canon_repo).unwrap_or(bound_epoch);
    let resp = if live_epoch != bound_epoch {
        JsonValue::Object(vec![
            ("ok".to_string(), JsonValue::Bool(false)),
            (
                "error".to_string(),
                JsonValue::Str(
                    "STALE_COORDINATOR_EPOCH: coordinator daemon bound to retired epoch"
                        .to_string(),
                ),
            ),
        ])
    } else {
        match process_rpc_line(line.trim(), key, canon_repo) {
            Ok(val) => val,
            Err(err) => JsonValue::Object(vec![
                ("ok".to_string(), JsonValue::Bool(false)),
                ("error".to_string(), JsonValue::Str(err)),
            ]),
        }
    };
    let mut encoded = resp.to_json_string();
    encoded.push('\n');
    stream
        .write_all(encoded.as_bytes())
        .map_err(|e| format!("write error: {e}"))?;
    let _ = stream.flush();
    Ok(())
}

pub(crate) fn compute_domain_tag_raw(
    key: &[u8; 32],
    domain: &[u8],
    payload: &[u8],
) -> Result<[u8; 32], String> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| format!("HMAC init error: {e}"))?;
    mac.update(&(domain.len() as u64).to_be_bytes());
    mac.update(domain);
    mac.update(&(payload.len() as u64).to_be_bytes());
    mac.update(payload);
    let bytes = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Checks whether a failed bijective v2 tag matches the pre-v2 unprefixed HMAC encoding.
/// Never accepts legacy tags--used strictly to emit `LEGACY_HMAC_V1_STATE_INVALIDATED`
/// upgrade guidance instead of an opaque tamper error.
pub(crate) fn is_legacy_v1_unprefixed_domain_tag(
    key: &[u8; 32],
    domain: &[u8],
    payload: &[u8],
    candidate_tag: &[u8],
) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    mac.update(domain);
    mac.update(&(payload.len() as u64).to_be_bytes());
    mac.update(payload);
    let legacy = mac.finalize().into_bytes();
    constant_time_eq_bytes(&legacy, candidate_tag)
}

/// Parses the immutable scope prefix length of a `CAPABILITY_HMAC_DOMAIN` payload
/// (`session_id`, `role`, `task_id`, `attempt`, `repo_sha256`, `plan_sha256`,
/// `assigned_read_paths`, `allowed_write_paths`, `assigned_tests`) and returns
/// `(session_id, role, immutable_prefix_slice)`.
fn parse_capability_immutable_prefix(payload: &[u8]) -> Result<(String, String, &[u8]), String> {
    let mut pos = 0usize;
    let read_u32 = |buf: &[u8], p: &mut usize| -> Result<u32, String> {
        let slice = buf
            .get(*p..*p + 4)
            .ok_or_else(|| "truncated capability payload u32".to_string())?;
        *p += 4;
        Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
    };
    let read_str = |buf: &[u8], p: &mut usize| -> Result<String, String> {
        let len = read_u32(buf, p)? as usize;
        let slice = buf
            .get(*p..*p + len)
            .ok_or_else(|| "truncated capability payload string".to_string())?;
        *p += len;
        std::str::from_utf8(slice)
            .map(String::from)
            .map_err(|_| "non-UTF-8 string in capability payload".to_string())
    };
    let skip_vec = |buf: &[u8], p: &mut usize| -> Result<(), String> {
        let count = read_u32(buf, p)? as usize;
        for _ in 0..count {
            let _ = read_str(buf, p)?;
        }
        Ok(())
    };

    let session_id = read_str(payload, &mut pos)?;
    let role = read_str(payload, &mut pos)?;
    let _task_id = read_str(payload, &mut pos)?;
    let _attempt = read_u32(payload, &mut pos)?;
    let _repo_sha = read_str(payload, &mut pos)?;
    let _plan_sha = read_str(payload, &mut pos)?;
    skip_vec(payload, &mut pos)?;
    skip_vec(payload, &mut pos)?;
    skip_vec(payload, &mut pos)?;

    Ok((session_id, role, &payload[..pos]))
}

/// Enforces privilege-separated signing rules before signing any `CAPABILITY_HMAC_DOMAIN`
/// update over `coord.sock`:
/// 1. `role == "master"` is hard-blocked (`PRIVILEGED_ROLE_DENIED`).
/// 2. `<swarm_state_dir>/sessions/<session_id>.json` must ALREADY exist on disk with a valid
///    `CAPABILITY_HMAC_DOMAIN` tag under `key` (workers can never mint brand-new capabilities).
/// 3. The immutable scope prefix (`session_id..assigned_tests`) must match the on-disk minted
///    capability byte-for-byte (workers can never widen `allowed_write_paths`, `assigned_read_paths`,
///    `role`, `task_id`, or `plan_sha256`--only update runtime counters / `last_green_tree_oid`).
fn authorize_ipc_capability_resign(
    key: &[u8; 32],
    canon_repo: &Path,
    candidate_payload: &[u8],
) -> Result<(), String> {
    let (session_id, role, candidate_immutable) =
        parse_capability_immutable_prefix(candidate_payload)?;
    if role == "master" {
        return Err(
            "PRIVILEGED_ROLE_DENIED: master capability minting/signing is forbidden over coordinator IPC"
                .to_string(),
        );
    }
    if session_id.is_empty()
        || session_id
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
    {
        return Err("INVALID_CAPABILITY_SESSION_ID".to_string());
    }
    let cap_file = swarm_state_dir(canon_repo)?
        .join("sessions")
        .join(format!("{session_id}.json"));
    let raw_disk = fs::read_to_string(&cap_file).map_err(|_| {
        format!(
            "UNMINTED_CAPABILITY_DENIED: coordinator refuses to mint unknown session '{session_id}' over IPC"
        )
    })?;
    let (existing, recorded_mac_hex) =
        crate::role_sandbox::parse_session_capability_record_json(&raw_disk, &session_id).map_err(
            |e| format!("CORRUPT_ON_DISK_CAPABILITY: existing session '{session_id}' invalid: {e}"),
        )?;
    let existing_payload = crate::role_sandbox::encode_capability_mac_payload(&existing);
    let expected_existing_tag =
        compute_domain_tag_raw(key, CAPABILITY_DOMAIN_BYTES, &existing_payload)?;
    let recorded_existing_bytes = hex_decode_bytes(&recorded_mac_hex)
        .map_err(|_| "invalid hex on existing capability".to_string())?;
    if !constant_time_eq_bytes(&expected_existing_tag, &recorded_existing_bytes) {
        if is_legacy_v1_unprefixed_domain_tag(
            key,
            CAPABILITY_DOMAIN_BYTES,
            &existing_payload,
            &recorded_existing_bytes,
        ) {
            return Err(
                "LEGACY_HMAC_V1_STATE_INVALIDATED: session capability uses pre-v2 unprefixed HMAC encoding; run `dotagent activate` or `dotagent session-reset --all`"
                    .to_string(),
            );
        }
        return Err(
            "FORGED_ON_DISK_CAPABILITY: existing capability failed vault MAC check".to_string(),
        );
    }
    let (_ex_sid, _ex_role, existing_immutable) =
        parse_capability_immutable_prefix(&existing_payload)?;
    if !constant_time_eq_bytes(candidate_immutable, existing_immutable) {
        return Err(
            "CAPABILITY_SCOPE_ESCALATION_DENIED: worker IPC cannot alter role, task, plan, or path scopes"
                .to_string(),
        );
    }
    Ok(())
}

type ParsedActiveSlotPayload = (u64, Vec<String>, Vec<(String, String)>);

fn parse_active_slot_payload(payload: &[u8]) -> Result<ParsedActiveSlotPayload, String> {
    if payload.get(..4) != Some(b"REV2") {
        return Err(
            "LEGACY_HMAC_V1_STATE_INVALIDATED: active_sessions payload missing REV2 generation header"
                .to_string(),
        );
    }
    let rev_bytes = payload
        .get(4..12)
        .ok_or_else(|| "truncated active_sessions payload revision".to_string())?;
    let revision = u64::from_be_bytes([
        rev_bytes[0],
        rev_bytes[1],
        rev_bytes[2],
        rev_bytes[3],
        rev_bytes[4],
        rev_bytes[5],
        rev_bytes[6],
        rev_bytes[7],
    ]);
    let mut pos = 12usize;
    let read_u32 = |buf: &[u8], p: &mut usize| -> Result<u32, String> {
        let slice = buf
            .get(*p..*p + 4)
            .ok_or_else(|| "truncated active_sessions payload u32".to_string())?;
        *p += 4;
        Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
    };
    let read_str = |buf: &[u8], p: &mut usize| -> Result<String, String> {
        let len = read_u32(buf, p)? as usize;
        let slice = buf
            .get(*p..*p + len)
            .ok_or_else(|| "truncated active_sessions payload string".to_string())?;
        *p += len;
        std::str::from_utf8(slice)
            .map(String::from)
            .map_err(|_| "non-UTF-8 string in active_sessions payload".to_string())
    };
    let open_count = read_u32(payload, &mut pos)? as usize;
    let mut open_sessions = Vec::with_capacity(open_count.min(256));
    for _ in 0..open_count {
        open_sessions.push(read_str(payload, &mut pos)?);
    }
    let bind_count = read_u32(payload, &mut pos)? as usize;
    let mut bindings = Vec::with_capacity(bind_count.min(256));
    for _ in 0..bind_count {
        let k = read_str(payload, &mut pos)?;
        let v = read_str(payload, &mut pos)?;
        bindings.push((k, v));
    }
    if pos != payload.len() {
        return Err("trailing bytes in active_sessions payload".to_string());
    }
    Ok((revision, open_sessions, bindings))
}

/// Acquires the registry `ExclusiveFileLockGuard`, verifies monotonic `revision` CAS
/// (`candidate_rev == existing_rev + 1`) and non-escalation subset rules, signs the new
/// payload, and atomically persists `active_sessions.json` under the held lock.
fn commit_ipc_active_slot_update(
    key: &[u8; 32],
    canon_repo: &Path,
    candidate_payload: &[u8],
) -> Result<[u8; 32], String> {
    let (candidate_rev, candidate_open, candidate_bindings) =
        parse_active_slot_payload(candidate_payload)?;
    let slot_file = swarm_state_dir(canon_repo)?
        .join("sessions")
        .join("active_sessions.json");
    if !slot_file.exists() {
        return Err(
            "UNINITIALIZED_ACTIVE_SESSIONS_DENIED: coordinator refuses to initialize active_sessions.json over IPC"
                .to_string(),
        );
    }
    let _slot_lock = ExclusiveFileLockGuard::acquire(&slot_file)?;
    let raw_disk = fs::read_to_string(&slot_file).map_err(|_| {
        "UNINITIALIZED_ACTIVE_SESSIONS_DENIED: coordinator refuses to initialize active_sessions.json over IPC"
            .to_string()
    })?;
    let v =
        JsonValue::parse(&raw_disk).map_err(|e| format!("CORRUPT_ACTIVE_SESSIONS_ON_DISK: {e}"))?;
    let Some(existing_rev) = v.get("revision").and_then(JsonValue::as_u64) else {
        return Err(
            "LEGACY_HMAC_V1_STATE_INVALIDATED: on-disk active_sessions.json missing v2 revision field; run `dotagent activate` or `dotagent session-reset --all`"
                .to_string(),
        );
    };
    let open_arr = v
        .get("open_sessions")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| "CORRUPT_ACTIVE_SESSIONS_ON_DISK: missing open_sessions".to_string())?;
    let mut existing_open = Vec::with_capacity(open_arr.len());
    for item in open_arr {
        let s = item
            .as_str()
            .ok_or_else(|| "CORRUPT_ACTIVE_SESSIONS_ON_DISK: non-string session".to_string())?;
        existing_open.push(s.to_string());
    }
    let mut existing_bindings = std::collections::BTreeMap::new();
    if let Some(JsonValue::Object(entries)) = v.get("hook_bindings") {
        for (k, val) in entries {
            let t = val
                .as_str()
                .ok_or_else(|| "CORRUPT_ACTIVE_SESSIONS_ON_DISK: non-string binding".to_string())?;
            existing_bindings.insert(k.clone(), t.to_string());
        }
    }
    let recorded_mac_hex = v
        .get("record_mac")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| "CORRUPT_ACTIVE_SESSIONS_ON_DISK: missing record_mac".to_string())?;

    let mut existing_buf = Vec::new();
    existing_buf.extend_from_slice(b"REV2");
    existing_buf.extend_from_slice(&existing_rev.to_be_bytes());
    existing_buf.extend_from_slice(&(existing_open.len() as u32).to_be_bytes());
    for sid in &existing_open {
        existing_buf.extend_from_slice(&(sid.len() as u32).to_be_bytes());
        existing_buf.extend_from_slice(sid.as_bytes());
    }
    existing_buf.extend_from_slice(&(existing_bindings.len() as u32).to_be_bytes());
    for (k, t) in &existing_bindings {
        existing_buf.extend_from_slice(&(k.len() as u32).to_be_bytes());
        existing_buf.extend_from_slice(k.as_bytes());
        existing_buf.extend_from_slice(&(t.len() as u32).to_be_bytes());
        existing_buf.extend_from_slice(t.as_bytes());
    }
    let expected_tag = compute_domain_tag_raw(key, ACTIVE_SLOT_DOMAIN_BYTES, &existing_buf)?;
    let recorded_bytes = hex_decode_bytes(recorded_mac_hex)
        .map_err(|_| "invalid hex on active_sessions.json".to_string())?;
    if !constant_time_eq_bytes(&expected_tag, &recorded_bytes) {
        if is_legacy_v1_unprefixed_domain_tag(
            key,
            ACTIVE_SLOT_DOMAIN_BYTES,
            &existing_buf,
            &recorded_bytes,
        ) {
            return Err(
                "LEGACY_HMAC_V1_STATE_INVALIDATED: active_sessions.json uses pre-v2 unprefixed HMAC encoding; run `dotagent activate` or `dotagent session-reset --all`"
                    .to_string(),
            );
        }
        return Err("FORGED_ACTIVE_SESSIONS_ON_DISK: vault MAC mismatch".to_string());
    }

    if Some(candidate_rev) != existing_rev.checked_add(1) {
        return Err(format!(
            "STALE_ACTIVE_SESSIONS_CAS_CONFLICT: candidate revision {candidate_rev} does not match expected revision {}",
            existing_rev.saturating_add(1)
        ));
    }

    for sid in &candidate_open {
        if !existing_open.iter().any(|ex| ex == sid) {
            return Err(format!(
                "ACTIVE_SESSION_ESCALATION_DENIED: worker IPC cannot open or re-open session '{sid}'"
            ));
        }
    }
    if candidate_open != existing_open {
        return Err(
            "ACTIVE_SESSION_DELETION_DENIED: worker IPC cannot close or reorder open sessions; session lifecycle requires host authority"
                .to_string(),
        );
    }

    let mut candidate_bindings_map = std::collections::BTreeMap::new();
    for (hook_sid, target_sid) in candidate_bindings {
        if candidate_bindings_map
            .insert(hook_sid.clone(), target_sid.clone())
            .is_some()
        {
            return Err(format!(
                "ACTIVE_SESSION_ESCALATION_DENIED: duplicate hook binding key '{hook_sid}'"
            ));
        }
        if !existing_open.iter().any(|ex| ex == &target_sid) {
            return Err(format!(
                "ACTIVE_SESSION_ESCALATION_DENIED: worker IPC cannot bind hook to closed/unminted session '{target_sid}'"
            ));
        }
    }
    for (ex_hook, ex_target) in &existing_bindings {
        if candidate_bindings_map.get(ex_hook) != Some(ex_target) {
            return Err(format!(
                "ACTIVE_SESSION_DELETION_DENIED: worker IPC cannot delete or overwrite existing hook binding '{ex_hook}'"
            ));
        }
    }

    let new_tag = compute_domain_tag_raw(key, ACTIVE_SLOT_DOMAIN_BYTES, candidate_payload)?;
    let new_mac_hex = hex_encode(&new_tag);
    let body = crate::role_sandbox::serialize_active_sessions_json(
        candidate_rev,
        &candidate_open,
        &candidate_bindings_map,
        &new_mac_hex,
    );
    write_atomic_private_0600(&slot_file, body.as_bytes())
        .map_err(|e| format!("failed committing active_sessions.json: {e}"))?;
    Ok(new_tag)
}

pub(crate) fn process_rpc_line(
    raw: &str,
    key: &[u8; 32],
    canon_repo: &Path,
) -> Result<JsonValue, String> {
    let req = JsonValue::parse(raw).map_err(|e| format!("invalid JSON: {e}"))?;
    let op = req
        .get("op")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| "missing op field".to_string())?;
    match op {
        "ping" => Ok(JsonValue::Object(vec![(
            "ok".to_string(),
            JsonValue::Bool(true),
        )])),
        "event_mac" => {
            let canonical_hex = req
                .get("canonical_hex")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing canonical_hex".to_string())?;
            let bytes = hex_decode_bytes(canonical_hex)?;
            let tag = compute_domain_tag_raw(key, BREADCRUMB_EVENT_HMAC_DOMAIN, &bytes)?;
            Ok(JsonValue::Object(vec![
                ("ok".to_string(), JsonValue::Bool(true)),
                ("mac_hex".to_string(), JsonValue::Str(hex_encode(&tag))),
            ]))
        }
        "verify_event_mac" => {
            let canonical_hex = req
                .get("canonical_hex")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing canonical_hex".to_string())?;
            let expected_hex = req
                .get("expected_mac_hex")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing expected_mac_hex".to_string())?;
            let bytes = hex_decode_bytes(canonical_hex)?;
            let expected = hex_decode_bytes(expected_hex)?;
            let actual = compute_domain_tag_raw(key, BREADCRUMB_EVENT_HMAC_DOMAIN, &bytes)?;
            let valid = constant_time_eq_bytes(&actual, &expected);
            if !valid
                && is_legacy_v1_unprefixed_domain_tag(
                    key,
                    BREADCRUMB_EVENT_HMAC_DOMAIN,
                    &bytes,
                    &expected,
                )
            {
                return Err(
                    "LEGACY_HMAC_V1_STATE_INVALIDATED: breadcrumb record uses pre-v2 unprefixed HMAC encoding; run `dotagent activate` or `dotagent session-reset --all`"
                        .to_string(),
                );
            }
            Ok(JsonValue::Object(vec![
                ("ok".to_string(), JsonValue::Bool(true)),
                ("valid".to_string(), JsonValue::Bool(valid)),
            ]))
        }
        "domain_hmac" => {
            let domain_hex = req
                .get("domain_hex")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing domain_hex".to_string())?;
            let payload_hex = req
                .get("payload_hex")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing payload_hex".to_string())?;
            let domain = hex_decode_bytes(domain_hex)?;
            let payload = hex_decode_bytes(payload_hex)?;

            let tag = match domain.as_slice() {
                PLAN_LOCK_DOMAIN_BYTES => {
                    return Err(
                        "PRIVILEGED_DOMAIN_DENIED: plan lock signing requires direct host Master vault possession"
                            .to_string(),
                    );
                }
                CAPABILITY_DOMAIN_BYTES => {
                    authorize_ipc_capability_resign(key, canon_repo, &payload)?;
                    compute_domain_tag_raw(key, &domain, &payload)?
                }
                ACTIVE_SLOT_DOMAIN_BYTES => {
                    commit_ipc_active_slot_update(key, canon_repo, &payload)?
                }
                LEDGER_DOMAIN_BYTES | REVIEW_STATE_DOMAIN_BYTES => {
                    compute_domain_tag_raw(key, &domain, &payload)?
                }
                _ => {
                    return Err(
                        "UNRECOGNIZED_HMAC_DOMAIN_DENIED: coordinator refuses to sign unknown or unpermitted HMAC domain"
                            .to_string(),
                    );
                }
            };

            Ok(JsonValue::Object(vec![
                ("ok".to_string(), JsonValue::Bool(true)),
                ("mac_hex".to_string(), JsonValue::Str(hex_encode(&tag))),
            ]))
        }
        "verify_domain_hmac" => {
            let domain_hex = req
                .get("domain_hex")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing domain_hex".to_string())?;
            let payload_hex = req
                .get("payload_hex")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing payload_hex".to_string())?;
            let expected_hex = req
                .get("expected_mac_hex")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing expected_mac_hex".to_string())?;
            let domain = hex_decode_bytes(domain_hex)?;
            if !matches!(
                domain.as_slice(),
                PLAN_LOCK_DOMAIN_BYTES
                    | CAPABILITY_DOMAIN_BYTES
                    | ACTIVE_SLOT_DOMAIN_BYTES
                    | LEDGER_DOMAIN_BYTES
                    | REVIEW_STATE_DOMAIN_BYTES
                    | BREADCRUMB_EVENT_HMAC_DOMAIN
            ) {
                return Err(
                    "UNRECOGNIZED_HMAC_DOMAIN_DENIED: coordinator refuses unknown HMAC domain"
                        .to_string(),
                );
            }
            let payload = hex_decode_bytes(payload_hex)?;
            let expected = hex_decode_bytes(expected_hex)?;
            let actual = compute_domain_tag_raw(key, &domain, &payload)?;
            let valid = constant_time_eq_bytes(&actual, &expected);
            if !valid && is_legacy_v1_unprefixed_domain_tag(key, &domain, &payload, &expected) {
                return Err(
                    "LEGACY_HMAC_V1_STATE_INVALIDATED: persisted record uses pre-v2 unprefixed HMAC encoding; run `dotagent activate` or `dotagent session-reset --all`"
                        .to_string(),
                );
            }
            Ok(JsonValue::Object(vec![
                ("ok".to_string(), JsonValue::Bool(true)),
                ("valid".to_string(), JsonValue::Bool(valid)),
            ]))
        }
        "epoch_status" => {
            let ep = current_hmac_epoch_id(canon_repo)?;
            Ok(JsonValue::Object(vec![
                ("ok".to_string(), JsonValue::Bool(true)),
                ("epoch_id".to_string(), JsonValue::Uint(ep)),
            ]))
        }
        "submit_friction_ballot" => {
            let worker_tok = req
                .get("worker_token")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "UNAUTHENTICATED_IPC_BALLOT: missing worker_token".to_string())?;
            let (verified_sid, verified_root_sid, verified_role) =
                crate::feedback::verify_ipc_worker_token(
                    key,
                    canon_repo,
                    worker_tok,
                    now_epoch_secs(),
                )?;
            let ballot_req_val = req
                .get("ballot_req")
                .ok_or_else(|| "missing ballot_req in submit_friction_ballot".to_string())?;
            let mut ballot_req = crate::feedback::BallotRequest::from_json_value(ballot_req_val)?;
            if !ballot_req.session_id.is_empty()
                && ballot_req.session_id != "default"
                && ballot_req.session_id != verified_sid
            {
                return Err(format!(
                    "FORGED_IPC_SESSION_DENIED: caller asserted session_id '{}' but worker token is bound to '{verified_sid}'",
                    ballot_req.session_id
                ));
            }
            ballot_req.session_id = verified_sid;
            ballot_req.root_session_id = Some(verified_root_sid);
            ballot_req.role = verified_role;
            let agentpi_ev = crate::feedback::commit_ballot_on_host_redacted(
                canon_repo,
                &ballot_req,
                true,
                crate::feedback::EmitSink::Silent,
            )
            .map_err(|e| format!("{}: {}", e.guard_code().as_str(), e.message()))?;
            Ok(JsonValue::Object(vec![
                ("ok".to_string(), JsonValue::Bool(true)),
                ("agentpi_event".to_string(), agentpi_ev),
            ]))
        }
        "eval_hook" => Err(
            "EVAL_HOOK_FORBIDDEN_ON_WORKER_SOCKET: eval_hook is restricted to host-only hook.sock"
                .to_string(),
        ),
        other => Err(format!("unknown coordinator op '{other}'")),
    }
}

#[cfg(test)]
mod epoch_file_tests {
    use super::*;

    #[test]
    fn epoch_publication_restores_existing_state_on_failed_final_rename() {
        let sequence = ATOMIC_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let fixture = std::env::temp_dir().join(format!(
            "dotagent-epoch-file-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&fixture).unwrap();
        let existing = fixture.join("existing.json");
        let retired = fixture.join("retired.json");
        let added = fixture.join("added.json");
        let final_file = fixture.join("final.txt");
        fs::write(&existing, b"previous").unwrap();
        fs::write(&retired, b"retained on failure").unwrap();
        fs::write(&final_file, b"previous").unwrap();

        let files = vec![
            StagedEpochFile::stage(EpochFileUpdate::Replace(existing.clone(), b"next".to_vec()))
                .unwrap(),
            StagedEpochFile::stage(EpochFileUpdate::Retire(retired.clone())).unwrap(),
            StagedEpochFile::stage(EpochFileUpdate::Replace(added.clone(), b"next".to_vec()))
                .unwrap(),
            StagedEpochFile {
                path: final_file.clone(),
                replacement: Some(fixture.join("missing-stage-file")),
                backup: None,
            },
        ];

        assert!(publish_staged_epoch(files).is_err());
        assert_eq!(fs::read(existing).unwrap(), b"previous");
        assert_eq!(fs::read(retired).unwrap(), b"retained on failure");
        assert_eq!(fs::read(final_file).unwrap(), b"previous");
        assert!(!added.exists());
        fs::remove_dir_all(fixture).unwrap();
    }
}
