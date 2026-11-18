//! External Host Coordinator Unix-Socket Daemon & Client (`spec.md` Section 3.3).
//!
//! Isolates `<swarm_state_dir>/vault/hmac.key` outside `exec-sandbox` (Linux Landlock LSM /
//! macOS Seatbelt) so untrusted child processes (`cargo test`, `build.rs`, `pytest`, `awk`)
//! never have filesystem access to HMAC key material. Privileged Swarm provenance signing and
//! verification route over `<swarm_state_dir>/ipc/coord.sock` to the host coordinator process.

use std::fs::{self, File};
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::breadcrumbs::{
    ExclusiveFileLockGuard, hex_decode_bytes, load_or_init_vault_hmac_key, swarm_state_dir,
};
use crate::json::JsonValue;
use crate::swarm_contracts::hex_encode;

type HmacSha256 = Hmac<Sha256>;

const MAX_RPC_LINE_BYTES: usize = 65_536;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 45;

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
            return Ok(PathBuf::from(trimmed));
        }
    }
    Ok(coordinator_ipc_dir(repo_root)?.join("coord.sock"))
}

#[cfg(unix)]
fn connect_unix_short_path(sock_path: &Path) -> std::io::Result<UnixStream> {
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
        UnixStream::connect(sock_path)
    }
}

#[cfg(unix)]
fn bind_unix_short_path(sock_path: &Path) -> std::io::Result<UnixListener> {
    if sock_path.as_os_str().len() <= 95 {
        return UnixListener::bind(sock_path);
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
        UnixListener::bind(short)
    }
    #[cfg(not(target_os = "linux"))]
    {
        UnixListener::bind(sock_path)
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

fn find_agent_guard_binary() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(name) = exe.file_name().and_then(|s| s.to_str()) {
            if name == "agent-guard" {
                return Some(exe);
            }
            if name == "swarm-tool" {
                let sibling = exe.with_file_name("agent-guard");
                if sibling.is_file() {
                    return Some(sibling);
                }
            }
        }
    }
    if let Some(path_os) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_os) {
            let candidate = dir.join("agent-guard");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Ensures an out-of-sandbox `agent-guard coordinator` daemon is listening for `repo_root`.
/// Must be called from the host side (outside `exec-sandbox`) before spawning sandboxed
/// `swarm-tool` invocations, or lazily by host-side `swarm-tool` calls.
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
        let decoded = hex_decode_bytes(mac_hex)?;
        if decoded.len() != 32 {
            return Err("invalid 32-byte MAC length from coordinator".to_string());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&decoded);
        Ok(out)
    }
    #[cfg(not(unix))]
    {
        let _ = (repo_root, canonical_bytes);
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

        let canon_repo = fs::canonicalize(&repo_root).unwrap_or(repo_root);
        let key = match load_or_init_vault_hmac_key(&canon_repo) {
            Ok(k) => Arc::new(k),
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
        loop {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    last_activity.store(now_epoch_secs(), Ordering::Relaxed);
                    let key_ref = Arc::clone(&key);
                    let _ = handle_coordinator_client(stream, &key_ref);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    let elapsed =
                        now_epoch_secs().saturating_sub(last_activity.load(Ordering::Relaxed));
                    if elapsed >= idle_secs {
                        let _ = fs::remove_file(&sock_path);
                        return ExitCode::SUCCESS;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
        }
    }
}

#[cfg(unix)]
fn handle_coordinator_client(mut stream: UnixStream, key: &[u8; 32]) -> Result<(), String> {
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
    let resp = match process_rpc_line(line.trim(), key) {
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

fn process_rpc_line(raw: &str, key: &[u8; 32]) -> Result<JsonValue, String> {
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
            let mut mac =
                HmacSha256::new_from_slice(key).map_err(|e| format!("HMAC init error: {e}"))?;
            mac.update(&bytes);
            let tag = hex_encode(&mac.finalize().into_bytes());
            Ok(JsonValue::Object(vec![
                ("ok".to_string(), JsonValue::Bool(true)),
                ("mac_hex".to_string(), JsonValue::Str(tag)),
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
            let mut mac =
                HmacSha256::new_from_slice(key).map_err(|e| format!("HMAC init error: {e}"))?;
            mac.update(&domain);
            mac.update(&(payload.len() as u64).to_be_bytes());
            mac.update(&payload);
            let tag = hex_encode(&mac.finalize().into_bytes());
            Ok(JsonValue::Object(vec![
                ("ok".to_string(), JsonValue::Bool(true)),
                ("mac_hex".to_string(), JsonValue::Str(tag)),
            ]))
        }
        other => Err(format!("unknown coordinator op '{other}'")),
    }
}
