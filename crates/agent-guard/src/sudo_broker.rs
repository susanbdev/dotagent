#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! Privilege-Separated Out-of-Band Human-TTY `sudo` Broker (`sudo-request` / `approve` / `sudo-result`).
//!
//! Enables an unprivileged AI agent (`PR_SET_NO_NEW_PRIVS = 1`) to help configure a local machine
//! WITHOUT ever elevating the agent's own process tree, inheriting a `sudo` timestamp ticket, or
//! invoking `/bin/sh -c` under root:
//! 1. **Agent Proposes (`dotagent sudo-request --reason "..." -- <bin> <args...>`)**:
//!    - Blocked when `SessionLedger` is tainted or halted.
//!    - Hard-blocks shells, eval/interpreter wrappers (`bash`, `sh`, `python`, `env`, `xargs`, `find`),
//!      credential/auth-plane paths (`/etc/sudoers`, `/etc/shadow`, `/etc/pam.d`, `.ssh`, `.env`, `AGENTS.md`),
//!      and setuid/setgid bit creation.
//!    - Pins the exact `argv: Vec<String>` + SHA-256 digests of any referenced local files into an
//!      HMAC-authenticated ticket (`TTL = 300s`) inside `~/.local/state/agent-guard/sudo-broker/`.
//! 2. **Human Approves in Separate Terminal (`dotagent approve [req_id | --watch | --list | --reject <id>]`)**:
//!    - Enforces triple human-presence lock (`isatty`, `!AGENT_GUARD_IN_SANDBOX`, `0` AI-harness env vars)
//!      and reads confirmation directly from `/dev/tty`.
//!    - Re-verifies every pinned file's SHA-256 (`SUDO_FILE_TOCTOU_MISMATCH` on race/tamper) and executes
//!      `Command::new("sudo").arg("--").args(&argv)` directly (`execvp`, zero shell parsing).
//!    - Sanitizes `stdout`/`stderr` to bounded 7-bit ASCII and scrubs accidental secret literals before
//!      writing the result receipt.
//! 3. **Agent Reads Receipt (`dotagent sudo-result <req_id>`)**:
//!    - Returns clean 7-bit ASCII exit code and sanitized output without touching privileged descriptors.

use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::thread;
use std::time::Duration;

use crate::json::JsonValue;
use crate::sanitizer::{
    DEFAULT_COMPACT_STREAM_MAX_BYTES, DEFAULT_COMPACT_STREAM_MAX_LINES, sanitize_and_compact_bytes,
};
use crate::traversal_ledger::state_base_dir;
use crate::unicode_guard::{ScanMode, scan_unicode};

pub const SUDO_TICKET_TTL_SECS: u64 = 300; // 5-minute approval window

const FORBIDDEN_SUDO_BINARIES: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "fish",
    "su",
    "sudo",
    "doas",
    "pkexec",
    "DZDO",
    "chroot",
    "nsenter",
    "unshare",
    "env",
    "xargs",
    "find",
    "fd",
    "fdfind",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "perl",
    "ruby",
    "php",
    "lua",
    "node",
    "nodejs",
    "deno",
    "bun",
    "python",
    "python2",
    "python3",
    "uv",
    "uvx",
    "pipx",
    "npx",
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "ssh",
    "scp",
    "sftp",
    "dd",
    "shred",
    "wipefs",
    "mkfs",
    "fdisk",
    "parted",
    "insmod",
    "modprobe",
    "rmmod",
    "agent-guard",
    "agent-guard-sh",
    "dotagent",
];

const FORBIDDEN_SUDO_ARG_SUBSTRINGS: &[&str] = &[
    "/etc/sudoers",
    "sudoers.d",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/passwd",
    "/etc/master.passwd",
    "/etc/pam.d",
    "/etc/security",
    "sshd_config",
    "authorized_keys",
    "/.ssh",
    "/.aws",
    "/.gnupg",
    "/.netrc",
    "/.git-credentials",
    "/.config/gh",
    "agent-guard",
    "/opt/dotagent",
    "agents.md",
    "claude.md",
    ".cursorrules",
    ".claude/",
    ".cursor/",
    ".codex/",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedFileDigest {
    pub abs_path: String,
    pub sha256_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedSudoRequest {
    pub reason: String,
    pub argv: Vec<String>,
    pub pinned_files: Vec<PinnedFileDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedSudoTicket {
    pub req_id: String,
    pub repo_root: String,
    pub cwd: String,
    pub reason: String,
    pub argv: Vec<String>,
    pub pinned_files: Vec<PinnedFileDigest>,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SudoExecutionReceipt {
    pub req_id: String,
    pub exit_code: i32,
    pub sanitized_output: String,
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sudo_broker_dir() -> PathBuf {
    let sessions = state_base_dir();
    sessions
        .parent()
        .map(|p| p.join("sudo-broker"))
        .unwrap_or_else(|| sessions.join("sudo-broker"))
}

fn reject_if_symlink(p: &Path, label: &str) -> Result<(), String> {
    if let Ok(meta) = fs::symlink_metadata(p)
        && meta.file_type().is_symlink()
    {
        return Err(format!("refusing symlinked {label} '{}'", p.display()));
    }
    Ok(())
}

fn load_or_create_broker_key(dir: &Path) -> Result<[u8; 32], String> {
    reject_if_symlink(dir, "sudo-broker directory")?;
    fs::create_dir_all(dir)
        .map_err(|e| format!("failed creating sudo-broker dir '{}': {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    let key_path = dir.join("host.key");
    reject_if_symlink(&key_path, "sudo-broker host.key")?;
    if key_path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::symlink_metadata(&key_path)
                .map_err(|e| format!("stat sudo-broker host.key: {e}"))?;
            if !meta.file_type().is_file() || (meta.permissions().mode() & 0o077) != 0 {
                return Err(
                    "SUDO_KEY_UNSAFE_PERMISSIONS: host.key must be a regular 0600 file".to_string(),
                );
            }
        }
        let raw = fs::read(&key_path).map_err(|e| format!("read host.key: {e}"))?;
        if raw.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&raw);
            return Ok(k);
        }
    }
    let mut k = [0u8; 32];
    let mut f = fs::File::open("/dev/urandom").map_err(|e| format!("open /dev/urandom: {e}"))?;
    f.read_exact(&mut k)
        .map_err(|e| format!("read /dev/urandom: {e}"))?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(&key_path) {
        Ok(mut kf) => {
            kf.write_all(&k)
                .map_err(|e| format!("write host.key: {e}"))?;
            Ok(k)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let raw = fs::read(&key_path).map_err(|re| format!("read host.key: {re}"))?;
            if raw.len() == 32 {
                k.copy_from_slice(&raw);
                Ok(k)
            } else {
                Err("corrupt sudo-broker host.key".to_string())
            }
        }
        Err(e) => Err(format!("create host.key: {e}")),
    }
}

fn compute_ticket_mac(key: &[u8; 32], t: &StagedSudoTicket) -> [u8; 32] {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(b"dotagent.sudo_ticket.v1\0");
    buf.extend_from_slice(key);
    for field in [&t.req_id, &t.repo_root, &t.cwd, &t.reason, &t.status] {
        buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
        buf.extend_from_slice(field.as_bytes());
    }
    buf.extend_from_slice(&(t.argv.len() as u32).to_be_bytes());
    for a in &t.argv {
        buf.extend_from_slice(&(a.len() as u32).to_be_bytes());
        buf.extend_from_slice(a.as_bytes());
    }
    buf.extend_from_slice(&(t.pinned_files.len() as u32).to_be_bytes());
    for pf in &t.pinned_files {
        buf.extend_from_slice(&(pf.abs_path.len() as u32).to_be_bytes());
        buf.extend_from_slice(pf.abs_path.as_bytes());
        buf.extend_from_slice(&(pf.sha256_hex.len() as u32).to_be_bytes());
        buf.extend_from_slice(pf.sha256_hex.as_bytes());
    }
    buf.extend_from_slice(&t.created_at_unix.to_be_bytes());
    buf.extend_from_slice(&t.expires_at_unix.to_be_bytes());
    crate::crypto::sha256_bytes(&buf)
}

pub fn validate_request_id(raw: &str) -> Result<&str, (&'static str, String)> {
    let trimmed = raw.trim();
    let Some(hex_part) = trimmed.strip_prefix("req_") else {
        return Err((
            "INVALID_SUDO_REQUEST_ID",
            format!("Expected request ID matching `req_<16-lowercase-hex>`, got '{trimmed}'."),
        ));
    };
    if hex_part.len() != 16
        || !hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err((
            "INVALID_SUDO_REQUEST_ID",
            format!("Expected request ID matching `req_<16-lowercase-hex>`, got '{trimmed}'."),
        ));
    }
    Ok(trimmed)
}

pub fn parse_and_validate_sudo_request(
    args: &[String],
    repo_root: &Path,
    cwd: &Path,
) -> Result<ValidatedSudoRequest, (&'static str, String, bool)> {
    let mut reason = String::from("Local host configuration task");
    let mut cmd_argv: Vec<String> = Vec::new();
    let mut i = 0usize;
    let mut after_sep = false;

    while i < args.len() {
        if after_sep {
            cmd_argv.push(args[i].clone());
            i += 1;
            continue;
        }
        match args[i].as_str() {
            "--" => {
                after_sep = true;
                i += 1;
            }
            "--reason" | "-r" => {
                let Some(r) = args.get(i + 1) else {
                    return Err((
                        "MISSING_COMMAND",
                        "`sudo-request --reason` missing description string.".to_string(),
                        false,
                    ));
                };
                reason = r.trim().to_string();
                i += 2;
            }
            other if other.starts_with('-') => {
                return Err((
                    "UNEXPECTED_SHELL_TOKEN",
                    format!(
                        "Unrecognized `sudo-request` option '{other}' (pass `--` before the target command)."
                    ),
                    false,
                ));
            }
            _ => {
                cmd_argv.extend_from_slice(&args[i..]);
                break;
            }
        }
    }

    if cmd_argv.is_empty() || cmd_argv[0].trim().is_empty() {
        return Err((
            "MISSING_COMMAND",
            "Usage: `dotagent sudo-request [--reason \"<ascii>\"] -- <binary> [args...]`."
                .to_string(),
            false,
        ));
    }

    if reason.is_empty() || reason.len() > 240 || !reason.is_ascii() {
        return Err((
            "SUDO_INVALID_REASON",
            "`sudo-request --reason` must be 1..=240 pure 7-bit ASCII characters.".to_string(),
            false,
        ));
    }
    if let Some(u) = scan_unicode(&reason, ScanMode::StrictPathOrCommand).first() {
        return Err((u.code, u.detail.clone(), true));
    }

    for token in &cmd_argv {
        if !token.is_ascii() || token.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err((
                "SUDO_NON_ASCII_ARG_BLOCKED",
                "Every `sudo-request` argument must be printable 7-bit ASCII without control bytes."
                    .to_string(),
                true,
            ));
        }
        if let Some(u) = scan_unicode(token, ScanMode::StrictPathOrCommand).first() {
            return Err((u.code, u.detail.clone(), true));
        }
    }

    let raw_bin = cmd_argv[0].trim();
    let base_bin = raw_bin
        .rsplit('/')
        .next()
        .unwrap_or(raw_bin)
        .to_ascii_lowercase();
    if FORBIDDEN_SUDO_BINARIES
        .iter()
        .any(|b| b.eq_ignore_ascii_case(&base_bin))
        || base_bin.starts_with("python")
        || base_bin.starts_with("mkfs")
    {
        return Err((
            "SUDO_SHELL_OR_EVAL_FORBIDDEN",
            format!(
                "`sudo-request` forbids shell, interpreter, privilege-switcher, or destructive binary '{raw_bin}'; propose the direct target utility (e.g. `apt-get`, `systemctl`, `sysctl`, `ufw`, `install`)."
            ),
            false,
        ));
    }

    // Block setuid/setgid bit creation on `chmod` / `install` (including `--mode=4755`, `u=s`, `06755`)
    if matches!(base_bin.as_str(), "chmod" | "install") {
        for arg in &cmd_argv[1..] {
            let mode_val = arg
                .strip_prefix("--mode=")
                .or_else(|| arg.strip_prefix("-m"))
                .unwrap_or(arg.as_str());
            if is_setuid_or_setgid_mode(mode_val) {
                return Err((
                    "SUDO_SENSITIVE_TARGET_FORBIDDEN",
                    format!("Setting setuid/setgid mode '{arg}' via `sudo-request` is forbidden."),
                    true,
                ));
            }
        }
    }

    let mut pinned_files = Vec::new();
    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());

    for arg in &cmd_argv {
        let lower = arg.to_ascii_lowercase();
        for bad in FORBIDDEN_SUDO_ARG_SUBSTRINGS {
            if lower.contains(bad) {
                return Err((
                    "SUDO_SENSITIVE_TARGET_FORBIDDEN",
                    format!(
                        "`sudo-request` argument '{arg}' touches protected credential/auth/guard path '{bad}'."
                    ),
                    true,
                ));
            }
        }
        if lower == ".env"
            || lower.ends_with("/.env")
            || lower.contains("/.env.")
            || lower.ends_with(".pem")
            || lower.ends_with(".key")
            || lower.ends_with(".p12")
            || lower.ends_with(".pfx")
        {
            return Err((
                "SUDO_SENSITIVE_TARGET_FORBIDDEN",
                format!("`sudo-request` argument '{arg}' references a secret/key file."),
                true,
            ));
        }

        // Pin SHA-256 of any existing local file inside `repo_root` (including `--opt=path`) to defeat TOCTOU swaps!
        let path_operand = if arg.starts_with('-') {
            arg.split_once('=').map(|(_, v)| v)
        } else {
            Some(arg.as_str())
        };
        if let Some(op) = path_operand
            && !op.is_empty()
        {
            let candidate = if Path::new(op).is_absolute() {
                PathBuf::from(op)
            } else {
                cwd.join(op)
            };
            // Component-wise symlink check from `repo_root` downward when inside repo
            let mut cur = PathBuf::new();
            for comp in candidate.components() {
                cur.push(comp);
                if let Ok(m) = fs::symlink_metadata(&cur)
                    && m.file_type().is_symlink()
                    && (cur.starts_with(repo_root) || cur == candidate)
                {
                    return Err((
                        "SYMLINK_ESCAPE_BLOCKED",
                        format!(
                            "`sudo-request` refuses symlinked path component '{}'.",
                            cur.display()
                        ),
                        true,
                    ));
                }
            }
            if let Ok(meta) = fs::symlink_metadata(&candidate)
                && meta.file_type().is_file()
            {
                let canon_f = fs::canonicalize(&candidate).unwrap_or(candidate);
                if !Path::new(op).is_absolute() && !canon_f.starts_with(&canon_repo) {
                    return Err((
                        "SYMLINK_ESCAPE_BLOCKED",
                        format!(
                            "`sudo-request` relative operand '{}' escapes repository root '{}'.",
                            op,
                            canon_repo.display()
                        ),
                        true,
                    ));
                }
                let bytes = fs::read(&canon_f).map_err(|e| {
                    (
                        "FILE_READ_ERROR",
                        format!("Failed hashing staged file '{}': {e}", canon_f.display()),
                        false,
                    )
                })?;
                if bytes.len() > 262_144 {
                    return Err((
                        "FILE_BYTE_BUDGET_EXCEEDED",
                        format!(
                            "Staged `sudo-request` file '{}' exceeds 256 KiB cap.",
                            canon_f.display()
                        ),
                        false,
                    ));
                }
                let abs_s = canon_f.to_string_lossy().into_owned();
                if !pinned_files
                    .iter()
                    .any(|p: &PinnedFileDigest| p.abs_path == abs_s)
                {
                    pinned_files.push(PinnedFileDigest {
                        abs_path: abs_s,
                        sha256_hex: crate::crypto::sha256_hex(&bytes),
                    });
                }
            }
        }
    }

    Ok(ValidatedSudoRequest {
        reason,
        argv: cmd_argv,
        pinned_files,
    })
}

fn is_setuid_or_setgid_mode(raw: &str) -> bool {
    let lower = raw.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    if lower.contains("+s") || lower.contains("=s") {
        return true;
    }
    let digits = lower.trim_start_matches('0');
    // 4-digit octal mode whose leading special-bits digit has setuid (4) or setgid (2) set
    digits.len() == 4
        && digits.bytes().all(|b| (b'0'..=b'7').contains(&b))
        && matches!(
            digits.as_bytes()[0],
            b'2' | b'3' | b'4' | b'5' | b'6' | b'7'
        )
}

pub fn stage_sudo_request(
    req: &ValidatedSudoRequest,
    repo_root: &Path,
    cwd: &Path,
) -> Result<StagedSudoTicket, String> {
    let dir = sudo_broker_dir();
    let key = load_or_create_broker_key(&dir)?;
    let mut rand_bytes = [0u8; 8];
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut rand_bytes);
    }
    let req_id = format!("req_{}", crate::crypto::hex_encode(&rand_bytes));
    let now = current_unix_secs();
    let canon_repo = fs::canonicalize(repo_root)
        .unwrap_or_else(|_| repo_root.to_path_buf())
        .to_string_lossy()
        .into_owned();
    let canon_cwd = fs::canonicalize(cwd)
        .unwrap_or_else(|_| cwd.to_path_buf())
        .to_string_lossy()
        .into_owned();

    let ticket = StagedSudoTicket {
        req_id: req_id.clone(),
        repo_root: canon_repo,
        cwd: canon_cwd,
        reason: req.reason.clone(),
        argv: req.argv.clone(),
        pinned_files: req.pinned_files.clone(),
        created_at_unix: now,
        expires_at_unix: now.saturating_add(SUDO_TICKET_TTL_SECS),
        status: "pending".to_string(),
    };
    save_signed_ticket(&dir, &key, &ticket)?;
    Ok(ticket)
}

fn save_signed_ticket(dir: &Path, key: &[u8; 32], ticket: &StagedSudoTicket) -> Result<(), String> {
    let mac = compute_ticket_mac(key, ticket);
    let mac_hex = crate::crypto::hex_encode(&mac);
    let argv_json: Vec<JsonValue> = ticket
        .argv
        .iter()
        .map(|s| JsonValue::Str(s.clone()))
        .collect();
    let pinned_json: Vec<JsonValue> = ticket
        .pinned_files
        .iter()
        .map(|pf| {
            JsonValue::Object(vec![
                ("abs_path".to_string(), JsonValue::Str(pf.abs_path.clone())),
                (
                    "sha256_hex".to_string(),
                    JsonValue::Str(pf.sha256_hex.clone()),
                ),
            ])
        })
        .collect();

    let doc = JsonValue::Object(vec![
        (
            "schema".to_string(),
            JsonValue::Str("dotagent.sudo_ticket.v1".to_string()),
        ),
        ("req_id".to_string(), JsonValue::Str(ticket.req_id.clone())),
        (
            "repo_root".to_string(),
            JsonValue::Str(ticket.repo_root.clone()),
        ),
        ("cwd".to_string(), JsonValue::Str(ticket.cwd.clone())),
        ("reason".to_string(), JsonValue::Str(ticket.reason.clone())),
        ("argv".to_string(), JsonValue::Array(argv_json)),
        ("pinned_files".to_string(), JsonValue::Array(pinned_json)),
        (
            "created_at_unix".to_string(),
            JsonValue::Uint(ticket.created_at_unix),
        ),
        (
            "expires_at_unix".to_string(),
            JsonValue::Uint(ticket.expires_at_unix),
        ),
        ("status".to_string(), JsonValue::Str(ticket.status.clone())),
        ("mac".to_string(), JsonValue::Str(mac_hex)),
    ]);

    let path = dir.join(format!("{}.json", ticket.req_id));
    reject_if_symlink(&path, "sudo ticket")?;
    fs::write(&path, doc.to_json_string().as_bytes())
        .map_err(|e| format!("write sudo ticket '{}': {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn load_verified_ticket(req_id: &str) -> Result<StagedSudoTicket, String> {
    load_verified_ticket_in_dir(&sudo_broker_dir(), req_id)
}

pub fn load_verified_ticket_in_dir(dir: &Path, req_id: &str) -> Result<StagedSudoTicket, String> {
    let valid_id = validate_request_id(req_id).map_err(|(_, msg)| msg)?;
    let key = load_or_create_broker_key(dir)?;
    let path = dir.join(format!("{valid_id}.json"));
    reject_if_symlink(&path, "sudo ticket")?;
    let raw = fs::read_to_string(&path)
        .map_err(|_| format!("Unknown sudo request '{valid_id}' (no ticket found)."))?;
    let v = JsonValue::parse(&raw).map_err(|e| format!("Corrupt sudo ticket JSON: {e}"))?;

    let raw_argv = v
        .get("argv")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| "missing argv".to_string())?;
    let mut argv: Vec<String> = Vec::with_capacity(raw_argv.len());
    for item in raw_argv {
        let s = item
            .as_str()
            .ok_or_else(|| "non-string element in argv".to_string())?;
        argv.push(s.to_string());
    }
    if argv.is_empty() {
        return Err("empty argv in sudo ticket".to_string());
    }
    let mut pinned_files = Vec::new();
    if let Some(arr) = v.get("pinned_files").and_then(JsonValue::as_array) {
        for item in arr {
            let abs_path = item
                .get("abs_path")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing pinned abs_path".to_string())?
                .to_string();
            let sha256_hex = item
                .get("sha256_hex")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing pinned sha256_hex".to_string())?
                .to_string();
            pinned_files.push(PinnedFileDigest {
                abs_path,
                sha256_hex,
            });
        }
    }

    let ticket = StagedSudoTicket {
        req_id: v
            .get("req_id")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "missing req_id".to_string())?
            .to_string(),
        repo_root: v
            .get("repo_root")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "missing repo_root".to_string())?
            .to_string(),
        cwd: v
            .get("cwd")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "missing cwd".to_string())?
            .to_string(),
        reason: v
            .get("reason")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "missing reason".to_string())?
            .to_string(),
        argv,
        pinned_files,
        created_at_unix: v
            .get("created_at_unix")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| "missing created_at_unix".to_string())?,
        expires_at_unix: v
            .get("expires_at_unix")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| "missing expires_at_unix".to_string())?,
        status: v
            .get("status")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "missing status".to_string())?
            .to_string(),
    };

    let stored_mac = crate::crypto::hex_decode_32(
        v.get("mac")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "missing mac".to_string())?,
    )?;
    let expected_mac = compute_ticket_mac(&key, &ticket);
    if !crate::crypto::constant_time_eq_bytes(&stored_mac, &expected_mac) {
        return Err("FORGED_SUDO_TICKET: ticket MAC verification failed (fail-closed)".to_string());
    }
    Ok(ticket)
}

pub fn reject_sudo_ticket(req_id: &str) -> Result<(), String> {
    let dir = sudo_broker_dir();
    let key = load_or_create_broker_key(&dir)?;
    let mut ticket = load_verified_ticket_in_dir(&dir, req_id)?;
    if ticket.status != "pending" {
        return Err(format!(
            "Ticket '{}' is already '{}' and cannot be rejected.",
            ticket.req_id, ticket.status
        ));
    }
    ticket.status = "rejected".to_string();
    save_signed_ticket(&dir, &key, &ticket)
}

pub fn verify_and_execute_sudo_ticket(
    req_id: &str,
    runner_override_for_test: Option<&str>,
) -> Result<SudoExecutionReceipt, String> {
    verify_and_execute_sudo_ticket_in_dir(&sudo_broker_dir(), req_id, runner_override_for_test)
}

struct TicketLockGuard {
    lock_path: PathBuf,
}

impl Drop for TicketLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn acquire_ticket_lock(dir: &Path, valid_id: &str) -> Result<TicketLockGuard, String> {
    let lock_path = dir.join(format!("{valid_id}.lock"));
    reject_if_symlink(&lock_path, "sudo ticket lock")?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(&lock_path).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            format!(
                "Ticket '{valid_id}' is currently locked by another `dotagent approve` process."
            )
        } else {
            format!("acquire sudo ticket lock: {e}")
        }
    })?;
    Ok(TicketLockGuard { lock_path })
}

fn compute_result_mac(key: &[u8; 32], req_id: &str, exit_code: i64, output: &str) -> [u8; 32] {
    let mut buf = Vec::with_capacity(64 + output.len());
    buf.extend_from_slice(b"dotagent.sudo_result.v1\0");
    buf.extend_from_slice(key);
    buf.extend_from_slice(&(req_id.len() as u32).to_be_bytes());
    buf.extend_from_slice(req_id.as_bytes());
    buf.extend_from_slice(&exit_code.to_be_bytes());
    buf.extend_from_slice(&(output.len() as u32).to_be_bytes());
    buf.extend_from_slice(output.as_bytes());
    crate::crypto::sha256_bytes(&buf)
}

pub fn verify_and_execute_sudo_ticket_in_dir(
    dir: &Path,
    req_id: &str,
    runner_override_for_test: Option<&str>,
) -> Result<SudoExecutionReceipt, String> {
    let valid_id = validate_request_id(req_id).map_err(|(_, msg)| msg)?;
    let key = load_or_create_broker_key(dir)?;
    let _lock = acquire_ticket_lock(dir, valid_id)?;
    let mut ticket = load_verified_ticket_in_dir(dir, valid_id)?;
    let now = current_unix_secs();

    if ticket.status != "pending" {
        return Err(format!(
            "Ticket '{}' is already '{}' and cannot be replayed.",
            ticket.req_id, ticket.status
        ));
    }
    if now > ticket.expires_at_unix {
        ticket.status = "expired".to_string();
        let _ = save_signed_ticket(dir, &key, &ticket);
        return Err(format!(
            "Ticket '{}' expired (5-minute approval TTL elapsed).",
            ticket.req_id
        ));
    }

    // TOCTOU verification on all pinned local files!
    for pf in &ticket.pinned_files {
        let p = Path::new(&pf.abs_path);
        let meta = fs::symlink_metadata(p).map_err(|e| {
            format!(
                "SUDO_FILE_TOCTOU_MISMATCH: staged file '{}' disappeared: {e}",
                pf.abs_path
            )
        })?;
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            return Err(format!(
                "SUDO_FILE_TOCTOU_MISMATCH: staged file '{}' became a symlink or non-regular file!",
                pf.abs_path
            ));
        }
        let actual_bytes = fs::read(p)
            .map_err(|e| format!("SUDO_FILE_TOCTOU_MISMATCH: read '{}': {e}", pf.abs_path))?;
        let actual_sha = crate::crypto::sha256_hex(&actual_bytes);
        if actual_sha != pf.sha256_hex {
            return Err(format!(
                "SUDO_FILE_TOCTOU_MISMATCH: staged file '{}' changed after request (expected {}, got {})! Aborting.",
                pf.abs_path, pf.sha256_hex, actual_sha
            ));
        }
    }

    // Claim ticket before spawning `sudo` to prevent concurrent double-execution.
    ticket.status = "executing".to_string();
    save_signed_ticket(dir, &key, &ticket)?;

    let mut cmd = if let Some(test_runner) = runner_override_for_test {
        let mut c = Command::new(test_runner);
        c.args(&ticket.argv);
        c
    } else {
        let mut c = Command::new("sudo");
        c.arg("--").args(&ticket.argv);
        c
    };
    cmd.current_dir(&ticket.cwd);

    let out = cmd
        .output()
        .map_err(|e| format!("failed spawning privileged runner: {e}"))?;
    let exit_code = out.status.code().unwrap_or(1);

    let mut combined = Vec::with_capacity(out.stdout.len() + out.stderr.len() + 2);
    combined.extend_from_slice(&out.stdout);
    if !out.stderr.is_empty() {
        if !combined.is_empty() && !combined.ends_with(b"\n") {
            combined.push(b'\n');
        }
        combined.extend_from_slice(&out.stderr);
    }

    let compacted = sanitize_and_compact_bytes(
        &combined,
        DEFAULT_COMPACT_STREAM_MAX_LINES,
        DEFAULT_COMPACT_STREAM_MAX_BYTES,
    );
    let safe_output = if let Some(secret_kind) =
        crate::scan_accidental_secret_literal(&compacted.clean_ascii)
    {
        format!(
            "[REDACTED_SECRET_IN_SUDO_OUTPUT: command output contained a potential {secret_kind} and was withheld from agent context]"
        )
    } else {
        compacted.clean_ascii
    };

    ticket.status = "executed".to_string();
    save_signed_ticket(dir, &key, &ticket)?;

    let res_mac = compute_result_mac(&key, &ticket.req_id, exit_code as i64, &safe_output);
    let res_doc = JsonValue::Object(vec![
        ("req_id".to_string(), JsonValue::Str(ticket.req_id.clone())),
        ("exit_code".to_string(), JsonValue::Number(exit_code as f64)),
        ("output".to_string(), JsonValue::Str(safe_output.clone())),
        (
            "mac".to_string(),
            JsonValue::Str(crate::crypto::hex_encode(&res_mac)),
        ),
    ]);
    let res_path = dir.join(format!("{}.result.json", ticket.req_id));
    reject_if_symlink(&res_path, "sudo result")?;
    fs::write(&res_path, res_doc.to_json_string().as_bytes())
        .map_err(|e| format!("write sudo result: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&res_path, fs::Permissions::from_mode(0o600));
    }

    Ok(SudoExecutionReceipt {
        req_id: ticket.req_id,
        exit_code,
        sanitized_output: safe_output,
    })
}

pub fn read_sudo_result_banner(req_id: &str) -> Result<String, (&'static str, String)> {
    let valid_id = validate_request_id(req_id)?;
    let ticket = load_verified_ticket(valid_id).map_err(|e| ("UNKNOWN_SUDO_TICKET", e))?;
    let now = current_unix_secs();

    if ticket.status == "pending" {
        if now > ticket.expires_at_unix {
            return Ok(format!(
                "[DOTAGENT SUDO-RESULT :: {valid_id}] STATUS=EXPIRED (5-minute human approval window elapsed)."
            ));
        }
        return Ok(format!(
            "[DOTAGENT SUDO-RESULT :: {valid_id}] STATUS=PENDING_HUMAN_APPROVAL (waiting for human to run `dotagent approve {valid_id}` in their terminal)."
        ));
    }
    if ticket.status == "rejected" {
        return Ok(format!(
            "[DOTAGENT SUDO-RESULT :: {valid_id}] STATUS=REJECTED_BY_HUMAN."
        ));
    }
    if ticket.status == "executing" {
        return Ok(format!(
            "[DOTAGENT SUDO-RESULT :: {valid_id}] STATUS=EXECUTING_IN_HUMAN_TTY (wait for `dotagent approve` to finish)."
        ));
    }
    if ticket.status == "expired" {
        return Ok(format!(
            "[DOTAGENT SUDO-RESULT :: {valid_id}] STATUS=EXPIRED (5-minute human approval window elapsed)."
        ));
    }

    let dir = sudo_broker_dir();
    let key = load_or_create_broker_key(&dir).map_err(|e| ("SUDO_RESULT_READ_ERROR", e))?;
    let res_path = dir.join(format!("{valid_id}.result.json"));
    reject_if_symlink(&res_path, "sudo result").map_err(|e| ("SUDO_RESULT_READ_ERROR", e))?;
    let raw = fs::read_to_string(&res_path)
        .map_err(|e| ("SUDO_RESULT_READ_ERROR", format!("read result: {e}")))?;
    let parsed = JsonValue::parse(&raw)
        .map_err(|e| ("SUDO_RESULT_READ_ERROR", format!("parse result: {e}")))?;
    let res_req_id = parsed
        .get("req_id")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            (
                "SUDO_RESULT_READ_ERROR",
                "missing result req_id".to_string(),
            )
        })?;
    if res_req_id != valid_id {
        return Err((
            "SUDO_RESULT_READ_ERROR",
            "result req_id mismatch (fail-closed)".to_string(),
        ));
    }
    let code = parsed
        .get("exit_code")
        .and_then(JsonValue::as_i64)
        .ok_or_else(|| {
            (
                "SUDO_RESULT_READ_ERROR",
                "missing result exit_code".to_string(),
            )
        })?;
    let output = parsed
        .get("output")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            (
                "SUDO_RESULT_READ_ERROR",
                "missing result output".to_string(),
            )
        })?;
    let mac_hex = parsed
        .get("mac")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| ("SUDO_RESULT_READ_ERROR", "missing result mac".to_string()))?;
    let stored_mac = crate::crypto::hex_decode_32(mac_hex)
        .map_err(|e| ("SUDO_RESULT_READ_ERROR", format!("invalid result mac: {e}")))?;
    let expected_mac = compute_result_mac(&key, valid_id, code, output);
    if !crate::crypto::constant_time_eq_bytes(&stored_mac, &expected_mac) {
        return Err((
            "SUDO_RESULT_READ_ERROR",
            "FORGED_SUDO_RESULT: result MAC verification failed (fail-closed)".to_string(),
        ));
    }
    Ok(format!(
        "[DOTAGENT SUDO-RESULT :: {valid_id}] STATUS=EXECUTED exit_code={code}\n{output}"
    ))
}

pub fn format_queued_banner(t: &StagedSudoTicket) -> String {
    format!(
        "[DOTAGENT SUDO-REQUEST QUEUED :: {}] argv={:?}\nAsk the human operator to run `dotagent approve {}` (or keep `dotagent approve --watch` open in a separate terminal), then read the sanitized output via `dotagent sudo-result {}`.",
        t.req_id, t.argv, t.req_id, t.req_id
    )
}

fn list_pending_tickets() -> Vec<StagedSudoTicket> {
    let dir = sudo_broker_dir();
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let now = current_unix_secs();
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(s) = name.to_str() else {
            continue;
        };
        if !s.starts_with("req_") || !s.ends_with(".json") || s.ends_with(".result.json") {
            continue;
        }
        let req_id = s.trim_end_matches(".json");
        if let Ok(t) = load_verified_ticket(req_id)
            && t.status == "pending"
            && t.expires_at_unix >= now
        {
            out.push(t);
        }
    }
    out.sort_by_key(|t| t.created_at_unix);
    out
}

pub fn run_sudo_request_cli(args: &[String], cwd: &Path) -> ExitCode {
    if std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() == Ok("1") {
        eprintln!(
            "[AGENT-GUARD] Invoke `dotagent sudo-request` directly as a top-level Bash command so PreToolUse brokers the ticket outside Landlock."
        );
        return ExitCode::from(2);
    }
    let repo_root = crate::resolve_repo_root(cwd);
    let validated = match parse_and_validate_sudo_request(args, &repo_root, cwd) {
        Ok(v) => v,
        Err((code, detail, _)) => {
            eprintln!("[AGENT-GUARD HARD DENY :: {code}] {detail}");
            return ExitCode::from(2);
        }
    };
    match stage_sudo_request(&validated, &repo_root, cwd) {
        Ok(ticket) => {
            println!("{}", format_queued_banner(&ticket));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("[sudo-request] failed staging ticket: {e}");
            ExitCode::from(2)
        }
    }
}

pub fn run_sudo_result_cli(args: &[String]) -> ExitCode {
    let Some(req_id) = args.first() else {
        eprintln!("Usage: `dotagent sudo-result <req_id>`");
        return ExitCode::from(2);
    };
    match read_sudo_result_banner(req_id) {
        Ok(banner) => {
            println!("{banner}");
            ExitCode::SUCCESS
        }
        Err((code, detail)) => {
            eprintln!("[AGENT-GUARD HARD DENY :: {code}] {detail}");
            ExitCode::from(2)
        }
    }
}

/// Interactive human-TTY-only approval broker (`dotagent approve [req_id | --list | --watch | --reject <id>]`).
pub fn run_approve_cli(args: &[String]) -> ExitCode {
    if std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() == Ok("1")
        || std::env::var("AGENT_GUARD_WORKER_LOCK").as_deref() == Ok("1")
    {
        eprintln!(
            "[AGENT-GUARD HARD DENY :: SUDO_APPROVE_DENIED_IN_SANDBOX] `dotagent approve` cannot be invoked from inside exec-sandbox or a worker."
        );
        return ExitCode::from(2);
    }

    for &marker in crate::telemetry::AGENT_SANDBOX_AND_HARNESS_MARKERS {
        if std::env::var(marker)
            .ok()
            .is_some_and(|v| !v.trim().is_empty())
        {
            eprintln!(
                "[AGENT-GUARD HARD DENY :: SUDO_APPROVE_DENIED_IN_HARNESS] `dotagent approve` must be run by a human in a standalone terminal (`{marker}` detected)."
            );
            return ExitCode::from(2);
        }
    }

    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        eprintln!(
            "[AGENT-GUARD HARD DENY :: SUDO_APPROVE_REQUIRES_HUMAN_TTY] `dotagent approve` requires an interactive human terminal (stdin/stdout TTY)."
        );
        return ExitCode::from(2);
    }

    if args.first().map(String::as_str) == Some("--list") {
        let pending = list_pending_tickets();
        if pending.is_empty() {
            println!("[dotagent approve] 0 pending sudo requests.");
        } else {
            let now = current_unix_secs();
            for t in pending {
                println!(
                    "{}  (expires in {}s)  reason=\"{}\"  argv={:?}",
                    t.req_id,
                    t.expires_at_unix.saturating_sub(now),
                    t.reason,
                    t.argv
                );
            }
        }
        return ExitCode::SUCCESS;
    }

    if args.first().map(String::as_str) == Some("--reject") {
        let Some(id) = args.get(1) else {
            eprintln!("Usage: `dotagent approve --reject <req_id>`");
            return ExitCode::from(2);
        };
        return match reject_sudo_ticket(id) {
            Ok(()) => {
                println!("[dotagent approve] Rejected ticket '{id}'.");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[dotagent approve] {e}");
                ExitCode::from(2)
            }
        };
    }

    let watch_mode = args.first().map(String::as_str) == Some("--watch");
    if watch_mode {
        println!(
            "[dotagent approve --watch] Watching for agent `sudo-request` proposals (Ctrl-C to exit)..."
        );
        loop {
            for t in list_pending_tickets() {
                let _ = prompt_and_handle_ticket(&t.req_id);
            }
            thread::sleep(Duration::from_millis(750));
        }
    }

    let target_id = if let Some(explicit) = args.first() {
        explicit.clone()
    } else if let Some(latest) = list_pending_tickets().pop() {
        latest.req_id
    } else {
        println!("[dotagent approve] No pending sudo requests.");
        return ExitCode::SUCCESS;
    };

    match prompt_and_handle_ticket(&target_id) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[dotagent approve] {e}");
            ExitCode::from(2)
        }
    }
}

fn prompt_and_handle_ticket(req_id: &str) -> Result<(), String> {
    let t = load_verified_ticket(req_id)?;
    let now = current_unix_secs();
    println!("========================================================================");
    println!(" DOTAGENT PRIVILEGED SUDO REQUEST :: {}", t.req_id);
    println!("========================================================================");
    println!("  Reason:     {}", t.reason);
    println!("  Directory:  {}", t.cwd);
    println!("  Expires in: {}s", t.expires_at_unix.saturating_sub(now));
    println!("  Exact argv ({} args):", t.argv.len());
    for (idx, arg) in t.argv.iter().enumerate() {
        println!("    argv[{idx}] = {arg:?}");
    }
    for pf in &t.pinned_files {
        println!("  Pinned SHA: {}  {}", &pf.sha256_hex[..16], pf.abs_path);
    }
    print!("Approve and execute via local `sudo`? [y/N]: ");
    let _ = io::stdout().flush();

    let tty = fs::File::open("/dev/tty").map_err(|e| format!("open /dev/tty: {e}"))?;
    let mut reader = io::BufReader::new(tty);
    let mut answer = String::new();
    reader
        .read_line(&mut answer)
        .map_err(|e| format!("read /dev/tty: {e}"))?;
    if matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
        let receipt = verify_and_execute_sudo_ticket(req_id, None)?;
        println!(
            "[dotagent approve] Completed '{}' (exit_code={}). Sanitized receipt ready for `dotagent sudo-result {}`.",
            receipt.req_id, receipt.exit_code, receipt.req_id
        );
    } else {
        reject_sudo_ticket(req_id)?;
        println!("[dotagent approve] Rejected '{}'.", t.req_id);
    }
    Ok(())
}
