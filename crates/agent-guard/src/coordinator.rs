#![forbid(unsafe_code)]

//! External Host Coordinator Privilege-Separated Monitor & Client (`spec.md` Section 3.3).
//!
//! Isolates `<swarm_state_dir>/vault/hmac.key` outside `exec-sandbox` (Linux Landlock LSM /
//! macOS Seatbelt) so untrusted child processes (`cargo test`, `build.rs`, `pytest`, `awk`)
//! never have filesystem access to HMAC key material.
//!
//! Security Invariants:
//! 1. **Zero Signing Oracle on Verification**: `verify_event_mac` and `verify_domain_hmac`
//!    perform constant-time MAC verification inside the coordinator and return `bool` only—never
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
fn shorten_unix_socket_via_cwd(sock_path: &Path) -> PathBuf {
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
        for anc in path.ancestors().skip(1) {
            if anc.as_os_str().is_empty() {
                continue;
            }
            let Ok(ameta) = fs::symlink_metadata(anc) else {
                return false;
            };
            if ameta.file_type().is_dir() && (ameta.permissions().mode() & 0o022) != 0 {
                return false;
            }
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
            if name == "swarm-tool" {
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
    cmd.arg("coordinator")
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

/// CLI entrypoint for `agent-guard coordinator --repo <path> [--idle-secs <N>]`.
pub fn run_coordinator_cli(args: &[String], default_cwd: &Path) -> ExitCode {
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
        let _ = listener.set_nonblocking(true);

        let last_activity = Arc::new(AtomicU64::new(now_epoch_secs()));
        let active_clients = Arc::new(AtomicUsize::new(0));
        loop {
            match listener.accept() {
                Ok((stream, _addr)) => {
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
                        let _ = handle_coordinator_client(stream, key_ref.as_bytes(), &repo_ref);
                        active_ref.fetch_sub(1, Ordering::AcqRel);
                    });
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    let elapsed =
                        now_epoch_secs().saturating_sub(last_activity.load(Ordering::Relaxed));
                    if elapsed >= idle_secs && active_clients.load(Ordering::Acquire) == 0 {
                        let _ = fs::remove_file(&sock_path);
                        return ExitCode::SUCCESS;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(20));
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
    let resp = match process_rpc_line(line.trim(), key, canon_repo) {
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
    for (hook_sid, target_sid) in &candidate_bindings {
        let unchanged = existing_bindings
            .get(hook_sid)
            .is_some_and(|ex_target| ex_target == target_sid);
        if !unchanged && !existing_open.iter().any(|ex| ex == target_sid) {
            return Err(format!(
                "ACTIVE_SESSION_ESCALATION_DENIED: worker IPC cannot bind hook to closed/unminted session '{target_sid}'"
            ));
        }
    }

    let new_tag = compute_domain_tag_raw(key, ACTIVE_SLOT_DOMAIN_BYTES, candidate_payload)?;
    let new_mac_hex = hex_encode(&new_tag);
    let mut candidate_bindings_map = std::collections::BTreeMap::new();
    for (k, t) in candidate_bindings {
        candidate_bindings_map.insert(k, t);
    }
    let body = crate::role_sandbox::serialize_active_sessions_json(
        candidate_rev,
        &candidate_open,
        &candidate_bindings_map,
        &new_mac_hex,
    );
    fs::write(&slot_file, body)
        .map_err(|e| format!("failed committing active_sessions.json: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&slot_file, fs::Permissions::from_mode(0o600));
    }
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
        other => Err(format!("unknown coordinator op '{other}'")),
    }
}
