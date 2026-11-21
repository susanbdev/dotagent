#![forbid(unsafe_code)]

//! OS-level execution sandbox (`agent-guard exec-sandbox`) wrapping child shell commands.
//!
//! Enforces defense-in-depth containment beneath `PreToolUse` AST validation:
//! 1. Scrubs dangerous dynamic-linker, OpenSSL engine, compiler-wrapper, Git override, and
//!    interpreter hijack env vars (`LD_PRELOAD`, `OPENSSL_CONF`, `RUSTC_WRAPPER`, `CARGO_TARGET_*`,
//!    `GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_COUNT`, `NODE_OPTIONS`, `PYTHONPATH`, `BASH_ENV`, ...).
//! 2. Locks down inherited Git configuration (`core.hooksPath=/dev/null`, `core.attributesFile=/dev/null`,
//!    `core.fsmonitor=false`, `protocol.allow=never`, `protocol.https.allow=always`, `submodule.recurse=false`)
//!    via `GIT_CONFIG_COUNT` when `GIT_CONFIG_GLOBAL` is not already pinned.
//! 3. Allocates a private, per-invocation ephemeral `TMPDIR` outside `/tmp`, `/var/tmp`, and `/dev/shm`,
//!    removing it automatically on process exit so compilers/test runners work seamlessly with zero
//!    shared-`/tmp` snooping.
//! 4. Drains child `stdout`/`stderr` completely to EOF into bounded head+tail buffers so chatty builds
//!    (`> 24 KiB`) never die from premature `SIGPIPE` while memory remains strictly bounded, running
//!    children in an isolated process group (`process_group(0)`).
//! 5. Applies OS kernel VFS + TCP sandboxing:
//!    - **Linux**: Landlock LSM (`ABI::V5` best-effort down to `V1`, plus `AccessNet` TCP port blocking
//!      when `network_access = "none"` or `--deny-net` is active) granting `ReadDir`-only on `repo_root`,
//!      omitting `.env*`, `*.pem`, `*.key`, `node_modules`, `.venv`, `vendor`, `.git/hooks`, `audit.jsonl`,
//!      `~/.ssh`, `~/.aws`, `~/.local/state/agent-guard`, and `/tmp`, locking control-plane files read-only,
//!      and honoring read-only runtime profiles (`enable_write_tools = false`).
//!    - **macOS**: Darwin Seatbelt (`/usr/bin/sandbox-exec`) profile with backslash-safe SBPL escaping,
//!      `writes_allowed` and `deny_net` parity, Keychain/secret/tmp/guard-state blocks, and control-file locks.

use std::env;
use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::budget_guard::load_active_profile;
use crate::crypto::sha256_bytes;
use crate::resolve_repo_root;
use crate::sanitizer::{
    DEFAULT_COMPACT_STREAM_MAX_BYTES, DEFAULT_COMPACT_STREAM_MAX_LINES, sanitize_and_compact_bytes,
};

const STREAM_HEAD_CAP_BYTES: usize = 16_384;
const STREAM_TAIL_CAP_BYTES: usize = 16_384;

const SCRUBBED_ENV_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "OPENSSL_CONF",
    "OPENSSL_ENGINES",
    "OPENSSL_MODULES",
    "RUSTC",
    "RUSTDOC",
    "RUSTFLAGS",
    "RUSTDOCFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
    "UV_INDEX_URL",
    "UV_EXTRA_INDEX_URL",
    "PERL5OPT",
    "PERL5LIB",
    "RUBYOPT",
    "RUBYLIB",
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
    "SHELLOPTS",
    "BASHOPTS",
    "CDPATH",
    "IFS",
    "GIT_SSH_COMMAND",
    "GIT_SSH",
    "GIT_EXTERNAL_DIFF",
    "GIT_ASKPASS",
    "GIT_EXEC_PATH",
    "GIT_TEMPLATE_DIR",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_CEILING_DIRECTORIES",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "SSH_ASKPASS",
    "AGENT_GUARD_ALLOW_SWARM",
    "AGENT_GUARD_ALLOW_INTERPRETER",
    "AGENT_GUARD_ALLOW_DEPUTY",
    "AGENT_GUARD_INTERNAL_SBX_TOKEN",
    "DOTAGENT_RECEIPT_SEED_HEX",
    "DOTAGENT_AUTONOMOUS_LOOP",
    "DOTAGENT_GH_BIN",
    "DOTAGENT_AUDITOR_CMD",
    "DOTAGENT_SECURITY_CMD",
    "DOTAGENT_IMPLEMENTER_CMD",
    "DOTAGENT_ADVERSARIAL_CMD",
    "DOTAGENT_LOOP_VERIFY_CMD",
    "AGENT_GUARD_IPC_WORKER_TOKEN",
    "DOTAGENT_TELEMETRY_SIGNING_KEY",
    "DOTAGENT_TELEMETRY_VERIFY_KEY",
    "DOTAGENT_LOOP_APP_PRIVATE_KEY",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelSandboxMode {
    LinuxLandlockEnforced,
    LinuxLandlockPartiallyEnforced,
    MacosSeatbeltEnforced,
    FallbackEnvAndAstOnly,
}

impl KernelSandboxMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LinuxLandlockEnforced => "linux-landlock-enforced",
            Self::LinuxLandlockPartiallyEnforced => "linux-landlock-partial",
            Self::MacosSeatbeltEnforced => "macos-seatbelt-enforced",
            Self::FallbackEnvAndAstOnly => "fallback-env-and-ast-only",
        }
    }

    pub fn is_kernel_enforced(self) -> bool {
        !matches!(self, Self::FallbackEnvAndAstOnly)
    }
}

#[derive(Debug, Clone, Copy)]
struct SandboxPolicyOpts {
    writes_allowed: bool,
    deny_net: bool,
    invokes_git: bool,
    invokes_swarm_tool: bool,
    invokes_feedback_submit: bool,
}

/// Formats a shell command to execute through `agent-guard exec-sandbox` with optional
/// in-process pre-buffer 7-bit ASCII stream sanitization and line compaction.
pub fn wrap_bash_with_exec_sandbox(cmd_str: &str, sanitize_stream: bool) -> String {
    wrap_bash_with_exec_sandbox_session(cmd_str, sanitize_stream, None)
}

pub fn wrap_bash_with_exec_sandbox_session(
    cmd_str: &str,
    sanitize_stream: bool,
    session_id: Option<&str>,
) -> String {
    let quoted = shell_quote_single(cmd_str);
    let sid_flag = session_id
        .map(str::trim)
        .filter(|s| {
            !s.is_empty()
                && *s != "default"
                && s.len() <= 128
                && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
        })
        .map(|s| format!(" --session-id {}", shell_quote_single(s)))
        .unwrap_or_default();
    if sanitize_stream {
        format!("agent-guard exec-sandbox --sanitize-stream{sid_flag} -- {quoted}")
    } else {
        format!("agent-guard exec-sandbox{sid_flag} -- {quoted}")
    }
}

/// Returns `true` ONLY when `cmd_str` is already an exact, single-command
/// `agent-guard exec-sandbox --sanitize-stream [--session-id '<sid>'] -- '<single-quoted-payload>'` wrapper
/// with zero trailing comments, pipelines, redirections, or chained commands.
pub fn is_canonical_exec_sandbox_wrapper(cmd_str: &str) -> bool {
    let trimmed = cmd_str.trim();
    if let Some(rest) = trimmed.strip_prefix("agent-guard exec-sandbox --sanitize-stream -- ") {
        return is_exact_single_quoted_literal(rest);
    }
    if let Some(after_ss) =
        trimmed.strip_prefix("agent-guard exec-sandbox --sanitize-stream --session-id ")
    {
        if let Some((sid_lit, rest)) = after_ss.split_once(" -- ") {
            return is_exact_single_quoted_literal(sid_lit) && is_exact_single_quoted_literal(rest);
        }
    }
    false
}

fn is_exact_single_quoted_literal(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'\'' {
        return false;
    }
    let mut i = 1usize;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            if bytes.get(i + 1..i + 4) == Some(b"\\''") {
                i += 4;
                continue;
            }
            return i + 1 == bytes.len();
        }
        i += 1;
    }
    false
}

pub fn shell_quote_single(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

struct EphemeralTmpDir {
    path: PathBuf,
}

impl EphemeralTmpDir {
    fn create() -> Option<Self> {
        let base = env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/run")))?;
        let container = base.join("agent-guard-ephemeral");
        fs::create_dir_all(&container).ok()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&container, fs::Permissions::from_mode(0o700));
        }
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = container.join(format!("sbx_{}_{}", std::process::id(), nanos));
        fs::create_dir(&dir).ok()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
        Some(Self { path: dir })
    }
}

impl Drop for EphemeralTmpDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Probes host OS kernel sandbox enforcement without mutating the current process.
pub fn probe_host_sandbox_mode() -> KernelSandboxMode {
    #[cfg(target_os = "linux")]
    {
        if let Ok(exe) = env::current_exe() {
            let mut candidates = Vec::new();
            for anc in exe.ancestors().skip(1).take(5) {
                for name in ["agent-guard", "dotagent"] {
                    let cand = anc.join(name);
                    if cand != exe && cand.is_file() && !candidates.contains(&cand) {
                        candidates.push(cand);
                    }
                }
            }
            candidates.push(exe);
            for bin in candidates {
                if let Ok(out) = Command::new(bin).arg("--probe-landlock-child").output()
                    && out.status.success()
                {
                    let text = String::from_utf8_lossy(&out.stdout);
                    if text.contains("linux-landlock-enforced") {
                        return KernelSandboxMode::LinuxLandlockEnforced;
                    }
                    if text.contains("linux-landlock-partial") {
                        return KernelSandboxMode::LinuxLandlockPartiallyEnforced;
                    }
                    if text.contains("fallback-env-and-ast-only") {
                        return KernelSandboxMode::FallbackEnvAndAstOnly;
                    }
                }
            }
        }
        KernelSandboxMode::FallbackEnvAndAstOnly
    }
    #[cfg(target_os = "macos")]
    {
        if Path::new("/usr/bin/sandbox-exec").is_file() {
            KernelSandboxMode::MacosSeatbeltEnforced
        } else {
            KernelSandboxMode::FallbackEnvAndAstOnly
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        KernelSandboxMode::FallbackEnvAndAstOnly
    }
}

/// Probes whether OS-level kernel filesystem sandboxing is supported on the current host.
pub fn run_sandbox_status_cli() -> ExitCode {
    let mode = probe_host_sandbox_mode();
    println!(
        "[AGENT-GUARD SANDBOX STATUS] mode={} kernel_enforced={}",
        mode.as_str(),
        mode.is_kernel_enforced()
    );
    ExitCode::SUCCESS
}

/// Internal subprocess probe (`agent-guard --probe-landlock-child`) safely testing Landlock ABI.
pub fn run_probe_landlock_child() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        use landlock::{
            ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, Ruleset, RulesetAttr,
            RulesetCreatedAttr, RulesetStatus,
        };
        let abi = ABI::V5;
        let res = Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(abi))
            .and_then(|r| r.handle_access(AccessNet::from_all(abi)))
            .and_then(|r| r.create())
            .and_then(|c| {
                c.add_rules(landlock::path_beneath_rules(
                    ["/usr", "/bin", "/lib"],
                    AccessFs::from_read(abi),
                ))
            })
            .and_then(|c| c.restrict_self());
        match res {
            Ok(st) => {
                let m = match st.ruleset {
                    RulesetStatus::FullyEnforced => KernelSandboxMode::LinuxLandlockEnforced,
                    RulesetStatus::PartiallyEnforced => {
                        KernelSandboxMode::LinuxLandlockPartiallyEnforced
                    }
                    RulesetStatus::NotEnforced => KernelSandboxMode::FallbackEnvAndAstOnly,
                };
                println!("{}", m.as_str());
                ExitCode::SUCCESS
            }
            Err(_) => {
                println!("{}", KernelSandboxMode::FallbackEnvAndAstOnly.as_str());
                ExitCode::SUCCESS
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        println!("{}", KernelSandboxMode::FallbackEnvAndAstOnly.as_str());
        ExitCode::SUCCESS
    }
}

/// Drains `reader` completely to EOF so the child process never receives a premature `SIGPIPE`
/// on `> 24 KiB` output, retaining at most `STREAM_HEAD_CAP_BYTES + STREAM_TAIL_CAP_BYTES` in RAM.
fn drain_stream_bounded<R: Read>(mut reader: R) -> Vec<u8> {
    let mut head = Vec::with_capacity(STREAM_HEAD_CAP_BYTES);
    let mut tail_ring = Vec::with_capacity(STREAM_TAIL_CAP_BYTES * 2);
    let mut omitted_bytes: usize = 0;
    let mut chunk = [0u8; 8192];

    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let mut slice = &chunk[..n];
                if head.len() < STREAM_HEAD_CAP_BYTES {
                    let take_head = (STREAM_HEAD_CAP_BYTES - head.len()).min(slice.len());
                    head.extend_from_slice(&slice[..take_head]);
                    slice = &slice[take_head..];
                }
                if !slice.is_empty() {
                    if slice.len() >= STREAM_TAIL_CAP_BYTES {
                        omitted_bytes = omitted_bytes.saturating_add(
                            tail_ring.len() + (slice.len() - STREAM_TAIL_CAP_BYTES),
                        );
                        tail_ring.clear();
                        tail_ring.extend_from_slice(&slice[slice.len() - STREAM_TAIL_CAP_BYTES..]);
                    } else {
                        tail_ring.extend_from_slice(slice);
                        if tail_ring.len() > STREAM_TAIL_CAP_BYTES {
                            let drop_n = tail_ring.len() - STREAM_TAIL_CAP_BYTES;
                            omitted_bytes = omitted_bytes.saturating_add(drop_n);
                            tail_ring.drain(..drop_n);
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }

    if tail_ring.is_empty() {
        return head;
    }
    if omitted_bytes > 0 {
        if !head.ends_with(b"\n") {
            head.push(b'\n');
        }
        head.extend_from_slice(
            format!("[... exec-sandbox drained {omitted_bytes} middle stream bytes ...]\n")
                .as_bytes(),
        );
    }
    head.extend_from_slice(&tail_ring);
    head
}

/// CLI entrypoint for `agent-guard exec-sandbox [--sanitize-stream] [--require-kernel] [--deny-net] [--read-only] [--session-id <sid>] [--cwd <dir>] -- <cmd>`
pub fn run_exec_sandbox_cli(args: &[String], default_cwd: &Path) -> ExitCode {
    let mut sanitize_stream = false;
    let mut require_kernel = false;
    let mut explicit_deny_net = false;
    let mut explicit_read_only = false;
    let mut cli_session_id: Option<String> = None;
    let mut custom_cwd: Option<PathBuf> = None;
    let mut cmd_parts: Vec<String> = Vec::new();
    let mut after_sep = false;

    let mut i = 0usize;
    while i < args.len() {
        if after_sep {
            cmd_parts.push(args[i].clone());
            i += 1;
            continue;
        }
        match args[i].as_str() {
            "--" => {
                after_sep = true;
                i += 1;
            }
            "--sanitize-stream" => {
                sanitize_stream = true;
                i += 1;
            }
            "--require-kernel" => {
                require_kernel = true;
                i += 1;
            }
            "--deny-net" => {
                explicit_deny_net = true;
                i += 1;
            }
            "--read-only" => {
                explicit_read_only = true;
                i += 1;
            }
            "--session-id" => {
                if let Some(sid_arg) = args.get(i + 1) {
                    let trimmed = sid_arg.trim();
                    if trimmed.is_empty()
                        || trimmed.len() > 128
                        || !trimmed.bytes().all(|b| (0x21..=0x7e).contains(&b))
                    {
                        eprintln!("[AGENT-GUARD] exec-sandbox: invalid --session-id value");
                        return ExitCode::from(2);
                    }
                    cli_session_id = Some(trimmed.to_string());
                    i += 2;
                } else {
                    eprintln!("[AGENT-GUARD] exec-sandbox: missing value after --session-id");
                    return ExitCode::from(2);
                }
            }
            "--cwd" => {
                if let Some(dir) = args.get(i + 1) {
                    custom_cwd = Some(PathBuf::from(dir));
                    i += 2;
                } else {
                    eprintln!("[AGENT-GUARD] exec-sandbox: missing path after --cwd");
                    return ExitCode::from(2);
                }
            }
            other if !other.starts_with('-') => {
                cmd_parts.push(other.to_string());
                after_sep = true;
                i += 1;
            }
            other => {
                eprintln!("[AGENT-GUARD] exec-sandbox: unrecognized flag '{other}'");
                return ExitCode::from(2);
            }
        }
    }

    if cmd_parts.is_empty() {
        eprintln!(
            "[AGENT-GUARD] usage: agent-guard exec-sandbox [--sanitize-stream] [--require-kernel] [--deny-net] [--read-only] [--session-id <sid>] [--cwd <dir>] -- \"<command>\""
        );
        return ExitCode::from(2);
    }

    let shell_script = if cmd_parts.len() == 1 {
        cmd_parts[0].clone()
    } else {
        cmd_parts
            .iter()
            .map(|p| shell_quote_single(p))
            .collect::<Vec<_>>()
            .join(" ")
    };

    let cwd = custom_cwd.unwrap_or_else(|| default_cwd.to_path_buf());
    let repo_root = resolve_repo_root(&cwd);
    let active_prof = match load_active_profile(&repo_root) {
        Ok(p) => p,
        Err(bv) => {
            eprintln!("[AGENT-GUARD HARD DENY :: {}] {}", bv.code, bv.detail);
            return ExitCode::from(2);
        }
    };
    let writes_allowed = !explicit_read_only && active_prof.enable_write_tools;
    let profile_denies_net = active_prof.network_access_none;
    let invokes_git = is_atomic_leading_command(&shell_script, "git");
    let invokes_swarm_tool = is_atomic_leading_command(&shell_script, "swarm-tool");
    let invokes_feedback_submit = is_atomic_feedback_submit_command(&shell_script);
    let opts = SandboxPolicyOpts {
        writes_allowed,
        deny_net: explicit_deny_net || profile_denies_net,
        invokes_git,
        invokes_swarm_tool,
        invokes_feedback_submit,
    };

    let common_repo = crate::resolve_common_repo_root(&repo_root);
    let env_session_id = env::var("AGENT_GUARD_SESSION_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let effective_session_id = env_session_id
        .clone()
        .or_else(|| cli_session_id.clone())
        .unwrap_or_else(|| "default".to_string());
    let has_swarm_session = effective_session_id.starts_with("swm_");

    // Snapshot `.git/config` bytes (<= 256 KiB) and SHA-256 digest prior to execution so any
    // `.git` lockfile access (or non-Landlock fallback execution) can never tamper with `.git/config`.
    const MAX_GIT_CFG_SNAPSHOT_BYTES: usize = 262_144;
    let git_cfg_path = common_repo.join(".git/config");
    let has_git_dir = common_repo.join(".git").is_dir();
    let (pre_git_cfg_existed, pre_git_cfg_digest, pre_git_cfg_bytes, pre_git_cfg_mode) = if opts
        .writes_allowed
        && has_git_dir
    {
        match fs::symlink_metadata(&git_cfg_path) {
            Ok(m) => {
                if m.file_type().is_symlink()
                    || !m.file_type().is_file()
                    || m.len() > MAX_GIT_CFG_SNAPSHOT_BYTES as u64
                {
                    eprintln!(
                        "[AGENT-GUARD HARD DENY :: GIT_CONFIG_UNSAFE] .git/config is a symlink, non-regular, or exceeds {MAX_GIT_CFG_SNAPSHOT_BYTES} bytes"
                    );
                    return ExitCode::from(2);
                }
                #[cfg(unix)]
                let mode_bits = {
                    use std::os::unix::fs::PermissionsExt;
                    m.permissions().mode() & 0o777
                };
                #[cfg(not(unix))]
                let mode_bits = 0o644u32;
                match fs::read(&git_cfg_path) {
                    Ok(bytes) if bytes.len() <= MAX_GIT_CFG_SNAPSHOT_BYTES => {
                        let digest = sha256_bytes(&bytes);
                        (true, Some(digest), Some(bytes), mode_bits)
                    }
                    _ => {
                        eprintln!(
                            "[AGENT-GUARD HARD DENY :: GIT_CONFIG_UNSAFE] failed reading .git/config prior to sandbox execution"
                        );
                        return ExitCode::from(2);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (false, None, None, 0o644),
            Err(e) => {
                eprintln!(
                    "[AGENT-GUARD HARD DENY :: GIT_CONFIG_UNSAFE] cannot stat .git/config: {e}"
                );
                return ExitCode::from(2);
            }
        }
    } else {
        (false, None, None, 0o644)
    };

    // Pre-launch the out-of-sandbox Vault Coordinator daemon BEFORE `restrict_self()` so
    // `swarm-tool` or `dotagent feedback submit` can communicate via `ipc/coord.sock`
    // while `vault/hmac.key` and `feedback/` stay 100% kernel-inaccessible (`EACCES`)!
    if opts.invokes_swarm_tool || has_swarm_session || opts.invokes_feedback_submit {
        let _ = crate::coordinator::ensure_coordinator_daemon(&common_repo);
        if let Ok(sdir) = crate::breadcrumbs::swarm_state_dir(&common_repo) {
            for sub in ["ipc", "sessions", "spools", "ledger"] {
                let p = sdir.join(sub);
                let _ = fs::create_dir_all(&p);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o700));
                }
            }
        }
        let _ = crate::breadcrumbs::swarm_locks_dir();
    } else if opts.invokes_feedback_submit {
        let _ = crate::coordinator::ensure_coordinator_daemon(&common_repo);
        if let Ok(sdir) = crate::breadcrumbs::swarm_state_dir(&common_repo) {
            let p = sdir.join("ipc");
            let _ = fs::create_dir_all(&p);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o700));
            }
        }
    }
    if opts.invokes_swarm_tool {
        precreate_swarm_tool_sandbox_targets(&repo_root, &shell_script);
    }

    // Mint `AGENT_GUARD_IPC_WORKER_TOKEN` STRICTLY for atomic `dotagent feedback submit`
    // invocations -- never for general `cargo test`/`pytest` processes in `swm_*` sessions!
    let minted_ipc_worker_token = if opts.invokes_feedback_submit {
        let mut ledger = crate::traversal_ledger::SessionLedger::load_or_create(
            &common_repo,
            &effective_session_id,
        );
        ledger.apply_root_session_override(None);
        let role = env::var("AGENT_GUARD_ROLE")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "coding-agent".to_string());
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Ok(mut skey) = crate::breadcrumbs::load_or_init_vault_hmac_key(&common_repo) {
            let tok = crate::feedback::mint_ipc_worker_token(
                &skey,
                &common_repo,
                &effective_session_id,
                &ledger.root_session_id,
                &role,
                now_secs,
            )
            .ok();
            crate::crypto::zeroize_slice(&mut skey);
            tok
        } else {
            None
        }
    } else {
        None
    };

    let ephemeral_tmp = EphemeralTmpDir::create();
    let tmp_dir_path = ephemeral_tmp.as_ref().map(|t| t.path.as_path());

    // Apply OS kernel sandbox to THIS process prior to spawning `bash` on Linux (inherited across fork/exec!).
    let (mode, net_filter_res) = apply_current_process_sandbox(&repo_root, tmp_dir_path, opts);
    if require_kernel && !mode.is_kernel_enforced() {
        eprintln!(
            "[AGENT-GUARD HARD DENY :: KERNEL_SANDBOX_UNAVAILABLE] Host kernel does not enforce Landlock/Seatbelt VFS containment (mode={}).",
            mode.as_str()
        );
        return ExitCode::from(2);
    }
    if opts.deny_net
        && let Err(seccomp_err) = net_filter_res
    {
        eprintln!(
            "[AGENT-GUARD HARD DENY :: KERNEL_NET_SANDBOX_FAILED] Failed installing kernel network filter: {seccomp_err}"
        );
        return ExitCode::from(2);
    }

    let mut child_cmd =
        build_child_command(&shell_script, &repo_root, &cwd, tmp_dir_path, opts, mode);
    if env_session_id.is_none()
        && let Some(ref sid_override) = cli_session_id
    {
        child_cmd.env("AGENT_GUARD_SESSION_ID", sid_override);
    }
    if let Some(tok) = minted_ipc_worker_token {
        child_cmd.env("AGENT_GUARD_IPC_WORKER_TOKEN", tok);
    }

    let exit_code = if sanitize_stream {
        let mut child = match child_cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[AGENT-GUARD EXEC ERROR] failed spawning sandboxed bash: {e}");
                return ExitCode::from(126);
            }
        };

        let stdout_handle = child
            .stdout
            .take()
            .map(|out| std::thread::spawn(move || drain_stream_bounded(out)));
        let stderr_handle = child
            .stderr
            .take()
            .map(|err| std::thread::spawn(move || drain_stream_bounded(err)));

        let status = match child.wait() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[AGENT-GUARD EXEC ERROR] failed waiting on sandboxed bash: {e}");
                return ExitCode::from(126);
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

        let san = sanitize_and_compact_bytes(
            &combined,
            DEFAULT_COMPACT_STREAM_MAX_LINES,
            DEFAULT_COMPACT_STREAM_MAX_BYTES,
        );
        if !san.clean_ascii.is_empty() {
            print!("{}", san.clean_ascii);
            if !san.clean_ascii.ends_with('\n') {
                println!();
            }
        }

        exit_code_from_status(status)
    } else {
        match child_cmd.status() {
            Ok(s) => exit_code_from_status(s),
            Err(e) => {
                eprintln!("[AGENT-GUARD EXEC ERROR] failed executing sandboxed bash: {e}");
                return ExitCode::from(126);
            }
        }
    };

    if let Some(expected_digest) = pre_git_cfg_digest {
        let post_digest = fs::symlink_metadata(&git_cfg_path)
            .ok()
            .filter(|m| !m.file_type().is_symlink() && m.file_type().is_file())
            .and_then(|_| fs::read(&git_cfg_path).ok())
            .map(|b| sha256_bytes(&b));
        if post_digest != Some(expected_digest) {
            let restored_ok = pre_git_cfg_bytes.as_deref().is_some_and(|orig_bytes| {
                restore_git_config_atomic(&git_cfg_path, orig_bytes, pre_git_cfg_mode).is_ok()
                    && fs::symlink_metadata(&git_cfg_path)
                        .ok()
                        .filter(|m| !m.file_type().is_symlink() && m.file_type().is_file())
                        .and_then(|_| fs::read(&git_cfg_path).ok())
                        .is_some_and(|b| sha256_bytes(&b) == expected_digest)
            });
            if !restored_ok {
                let mut ledger = crate::traversal_ledger::SessionLedger::load_or_create(
                    &common_repo,
                    &effective_session_id,
                );
                ledger.trip_circuit_breaker(
                    "GIT_CONFIG_RESTORE_FAILED: .git/config tampered and atomic restore failed"
                        .to_string(),
                );
                let _ = ledger.save_locked(&common_repo);
                eprintln!(
                    "[AGENT-GUARD HARD DENY :: GIT_CONFIG_RESTORE_FAILED] .git/config changed during sandbox execution and atomic restore failed; session halted!"
                );
                return ExitCode::from(2);
            }
            eprintln!(
                "[AGENT-GUARD HARD DENY :: GIT_CONFIG_TAMPERED] .git/config changed during sandbox execution; atomically restored!"
            );
            return ExitCode::from(2);
        }
    } else if opts.writes_allowed
        && has_git_dir
        && !pre_git_cfg_existed
        && fs::symlink_metadata(&git_cfg_path).is_ok()
    {
        if let Ok(meta) = fs::symlink_metadata(&git_cfg_path) {
            if meta.file_type().is_dir() && !meta.file_type().is_symlink() {
                let _ = fs::remove_dir_all(&git_cfg_path);
            } else {
                let _ = fs::remove_file(&git_cfg_path);
            }
        }
        if fs::symlink_metadata(&git_cfg_path).is_ok() {
            let mut ledger = crate::traversal_ledger::SessionLedger::load_or_create(
                &common_repo,
                &effective_session_id,
            );
            ledger.trip_circuit_breaker(
                "GIT_CONFIG_RESTORE_FAILED: unauthorized .git/config could not be removed"
                    .to_string(),
            );
            let _ = ledger.save_locked(&common_repo);
            eprintln!(
                "[AGENT-GUARD HARD DENY :: GIT_CONFIG_RESTORE_FAILED] unauthorized .git/config created and removal failed; session halted!"
            );
            return ExitCode::from(2);
        }
        eprintln!(
            "[AGENT-GUARD HARD DENY :: GIT_CONFIG_TAMPERED] unauthorized .git/config created during sandbox execution!"
        );
        return ExitCode::from(2);
    }

    exit_code
}

fn restore_git_config_atomic(
    git_cfg_path: &Path,
    orig_bytes: &[u8],
    orig_mode: u32,
) -> Result<(), String> {
    use std::io::Write as _;
    let parent = git_cfg_path
        .parent()
        .ok_or_else(|| "missing .git parent".to_string())?;
    let pmeta = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
    if pmeta.file_type().is_symlink() || !pmeta.file_type().is_dir() {
        return Err(".git parent is symlink or non-directory".to_string());
    }
    if let Ok(meta) = fs::symlink_metadata(git_cfg_path) {
        if meta.file_type().is_symlink() {
            let _ = fs::remove_file(git_cfg_path);
        } else if meta.file_type().is_dir() {
            let _ = fs::remove_dir_all(git_cfg_path);
        }
    }
    let objs_dir = parent.join("objects");
    let staging_dir = if fs::symlink_metadata(&objs_dir)
        .is_ok_and(|m| !m.file_type().is_symlink() && m.file_type().is_dir())
    {
        objs_dir.as_path()
    } else {
        parent
    };
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = staging_dir.join(format!(
        ".config.dotagent-restore.{}.{nanos}.tmp",
        std::process::id()
    ));
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)
        .map_err(|e| e.to_string())?;
    if let Err(e) = f.write_all(orig_bytes).and_then(|()| f.sync_all()) {
        let _ = fs::remove_file(&tmp);
        return Err(e.to_string());
    }
    drop(f);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(orig_mode & 0o777));
    }
    #[cfg(not(unix))]
    let _ = orig_mode;
    if let Err(e) = fs::rename(&tmp, git_cfg_path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.to_string());
    }
    Ok(())
}

fn exit_code_from_status(status: std::process::ExitStatus) -> ExitCode {
    if let Some(code) = status.code() {
        if let Ok(byte) = u8::try_from(code) {
            return ExitCode::from(byte);
        }
        return ExitCode::from(1);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            let sig_low = u8::try_from(sig & 0x7f).unwrap_or(1);
            return ExitCode::from(128u8.saturating_add(sig_low));
        }
    }
    ExitCode::from(1)
}

/// Returns true ONLY if `script` is a single atomic command (zero unquoted compound operators,
/// pipes, redirections, subshells, or command substitutions) whose leading executable basename
/// equals `target_bin`.
fn is_atomic_leading_command(script: &str, target_bin: &str) -> bool {
    let trimmed = script.trim();
    if trimmed.is_empty() {
        return false;
    }
    let bytes = trimmed.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut first_token = String::new();
    let mut first_done = false;

    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if escaped {
            if !first_done {
                first_token.push(b as char);
            }
            escaped = false;
            i += 1;
            continue;
        }
        if in_single {
            if b == b'\'' {
                in_single = false;
            } else if !first_done {
                first_token.push(b as char);
            }
            i += 1;
            continue;
        }
        if in_double {
            match b {
                b'\\' => {
                    escaped = true;
                }
                b'"' => {
                    in_double = false;
                }
                b'`' => return false,
                b'$' if bytes.get(i + 1) == Some(&b'(') => return false,
                _ => {
                    if !first_done {
                        first_token.push(b as char);
                    }
                }
            }
            i += 1;
            continue;
        }

        match b {
            b'\\' => {
                escaped = true;
            }
            b'\'' => {
                in_single = true;
            }
            b'"' => {
                in_double = true;
            }
            b';' | b'|' | b'&' | b'\n' | b'\r' | b'`' | b'<' | b'>' | b'(' | b')' => {
                return false;
            }
            b' ' | b'\t' => {
                if !first_token.is_empty() {
                    first_done = true;
                }
            }
            _ => {
                if !first_done {
                    first_token.push(b as char);
                }
            }
        }
        i += 1;
    }

    if in_single || in_double || escaped || first_token.is_empty() {
        return false;
    }
    if first_token == target_bin {
        return true;
    }
    if first_token.ends_with(&format!("/{target_bin}")) {
        let p = Path::new(&first_token);
        return p.is_absolute() && crate::coordinator::is_trusted_executable_file(p);
    }
    false
}

pub(crate) fn is_atomic_feedback_submit_command(script: &str) -> bool {
    if !is_atomic_leading_command(script, "dotagent")
        && !is_atomic_leading_command(script, "agent-guard")
    {
        return false;
    }
    let mut toks = Vec::new();
    let mut cur = String::new();
    let mut in_s = false;
    let mut in_d = false;
    let mut esc = false;
    for b in script.trim().bytes() {
        if esc {
            cur.push(b as char);
            esc = false;
            continue;
        }
        if in_s {
            if b == b'\'' {
                in_s = false;
            } else {
                cur.push(b as char);
            }
            continue;
        }
        if in_d {
            match b {
                b'\\' => esc = true,
                b'"' => in_d = false,
                b'`' | b'$' => return false,
                _ => cur.push(b as char),
            }
            continue;
        }
        match b {
            b'\\' => esc = true,
            b'\'' => in_s = true,
            b'"' => in_d = true,
            b';' | b'|' | b'&' | b'\n' | b'\r' | b'`' | b'<' | b'>' | b'(' | b')' | b'$' => {
                return false;
            }
            b' ' | b'\t' => {
                if !cur.is_empty() {
                    toks.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(b as char),
        }
    }
    if in_s || in_d || esc {
        return false;
    }
    if !cur.is_empty() {
        toks.push(cur);
    }
    let tail_start = if toks.get(1).map(String::as_str) == Some("feedback")
        && toks.get(2).map(String::as_str) == Some("submit")
    {
        3usize
    } else if toks.get(1).map(String::as_str) == Some("guard")
        && toks.get(2).map(String::as_str) == Some("feedback")
        && toks.get(3).map(String::as_str) == Some("submit")
    {
        4usize
    } else {
        return false;
    };
    let mut idx = tail_start;
    while idx < toks.len() {
        match toks[idx].as_str() {
            "--note-stdin" | "--json" => idx += 1,
            "--denial-id" | "--trace-id" | "--category" | "-c" | "--reason-code" | "--note"
            | "--summary" => {
                if idx + 1 >= toks.len() {
                    return false;
                }
                idx += 2;
            }
            _ => return false,
        }
    }
    true
}

fn precreate_swarm_tool_sandbox_targets(repo_root: &Path, _shell_script: &str) {
    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    if let Ok(sdir) = crate::breadcrumbs::swarm_state_dir(&canon_repo) {
        for sub in ["ipc", "sessions", "spools", "ledger"] {
            let p = sdir.join(sub);
            let _ = fs::create_dir_all(&p);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o700));
            }
        }
    }
    let _ = crate::breadcrumbs::swarm_locks_dir();
    let _ = crate::breadcrumbs::ensure_git_info_exclude(&canon_repo);

    // Pre-open `.breadcrumbs.jsonl` before Landlock `restrict_self()` (which deliberately withholds
    // `MakeReg` on `canon_repo` to keep `AGENTS.md` and `.env*` kernel-immutable).
    let bc = canon_repo.join(".breadcrumbs.jsonl");
    if !bc.exists() {
        let _ = fs::OpenOptions::new().create(true).append(true).open(&bc);
    }
}

fn build_child_command(
    shell_script: &str,
    repo_root: &Path,
    cwd: &Path,
    ephemeral_tmp: Option<&Path>,
    opts: SandboxPolicyOpts,
    mode: KernelSandboxMode,
) -> Command {
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let _ = mode;
        if Path::new("/usr/bin/sandbox-exec").is_file() {
            let profile = render_macos_seatbelt_profile(repo_root, ephemeral_tmp, opts);
            let mut c = Command::new("/usr/bin/sandbox-exec");
            c.arg("-p")
                .arg(profile)
                .arg("/bin/bash")
                .arg("--norc")
                .arg("--noprofile")
                .arg("-o")
                .arg("pipefail")
                .arg("-c")
                .arg(shell_script);
            c
        } else {
            let mut c = Command::new("bash");
            c.arg("--norc")
                .arg("--noprofile")
                .arg("-o")
                .arg("pipefail")
                .arg("-c")
                .arg(shell_script);
            c
        }
    };

    #[cfg(target_os = "linux")]
    let mut cmd = {
        let _ = repo_root;
        // Only wrap with `/usr/bin/unshare --user --net` when Landlock VFS restriction did NOT
        // restrict `/proc/self/uid_map` / `/proc/self/setgroups` (under Landlock, seccomp-bpf
        // already blocks all non-AF_UNIX/non-AF_NETLINK socket creation in-kernel).
        if opts.deny_net
            && mode == KernelSandboxMode::FallbackEnvAndAstOnly
            && probe_linux_unshare_netns()
        {
            let mut c = Command::new("/usr/bin/unshare");
            c.arg("--user")
                .arg("--net")
                .arg("--")
                .arg("bash")
                .arg("--norc")
                .arg("--noprofile")
                .arg("-o")
                .arg("pipefail")
                .arg("-c")
                .arg(shell_script);
            c
        } else {
            let mut c = Command::new("bash");
            c.arg("--norc")
                .arg("--noprofile")
                .arg("-o")
                .arg("pipefail")
                .arg("-c")
                .arg(shell_script);
            c
        }
    };

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let mut cmd = {
        let _ = (repo_root, mode);
        let mut c = Command::new("bash");
        c.arg("--norc")
            .arg("--noprofile")
            .arg("-o")
            .arg("pipefail")
            .arg("-c")
            .arg(shell_script);
        c
    };

    #[cfg(unix)]
    cmd.process_group(0);

    cmd.current_dir(cwd);
    for var in SCRUBBED_ENV_VARS {
        cmd.env_remove(var);
    }
    let has_swarm_session =
        env::var("AGENT_GUARD_SESSION_ID").is_ok_and(|s| s.trim().starts_with("swm_"));
    if !opts.invokes_swarm_tool && !has_swarm_session && !opts.invokes_feedback_submit {
        cmd.env_remove("AGENT_GUARD_COORDINATOR_SOCK");
    }
    if let Ok(raw_ctd) = env::var("CARGO_TARGET_DIR") {
        let ctd_trim = raw_ctd.trim();
        let has_unsafe_meta = ctd_trim.is_empty()
            || ctd_trim
                .bytes()
                .any(|b| matches!(b, b'$' | b'*' | b'?' | b'[' | b'{' | b'`'));
        if !opts.writes_allowed
            || has_unsafe_meta
            || crate::path_policy::validate_path(
                repo_root,
                cwd,
                ctd_trim,
                crate::path_policy::PathAccess::Write,
            )
            .is_err()
        {
            cmd.env_remove("CARGO_TARGET_DIR");
        }
    }
    // Scrub dynamic Cargo runner/linker/alias/source overrides (`CARGO_TARGET_*`, `CARGO_ALIAS_*`, ...)
    for (env_k, _) in env::vars_os() {
        if let Some(ks) = env_k.to_str() {
            let up = ks.to_ascii_uppercase();
            if (up.starts_with("CARGO_TARGET_") && up != "CARGO_TARGET_DIR")
                || up.starts_with("CARGO_ALIAS_")
                || up.starts_with("CARGO_REGISTRIES_")
                || up.starts_with("CARGO_SOURCE_")
                || up.starts_with("GIT_CONFIG_KEY_")
                || up.starts_with("GIT_CONFIG_VALUE_")
            {
                cmd.env_remove(&env_k);
            }
        }
    }

    cmd.env("AGENT_GUARD_IN_SANDBOX", "1");
    cmd.env("PYTHONDONTWRITEBYTECODE", "1");
    cmd.env("PIP_NO_CACHE_DIR", "1");
    cmd.env("NPM_CONFIG_IGNORE_SCRIPTS", "true");
    cmd.env("HISTFILE", "/dev/null");
    cmd.env("PAGER", "cat");
    cmd.env("GIT_PAGER", "cat");

    let canon_ws = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    if let Some(os_path) = env::var_os("PATH") {
        let filtered: Vec<PathBuf> = env::split_paths(&os_path)
            .filter(|d| {
                !d.as_os_str().is_empty()
                    && d.is_absolute()
                    && !d.starts_with(repo_root)
                    && !d.starts_with(cwd)
                    && !fs::canonicalize(d).is_ok_and(|c| c.starts_with(&canon_ws))
            })
            .collect();
        if filtered.is_empty() {
            cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin");
        } else if let Ok(joined) = env::join_paths(filtered) {
            cmd.env("PATH", joined);
        }
    }

    if let Some(tmp) = ephemeral_tmp {
        cmd.env("TMPDIR", tmp);
        cmd.env("TEMP", tmp);
        cmd.env("TMP", tmp);
    }

    // Unconditionally inject hermetic Git lockdown at CONFIG_SCOPE_COMMAND so even a custom
    // GIT_CONFIG_GLOBAL can never re-enable hooks, fsmonitor, attributes, or file/ext protocols.
    let pairs: &[(&str, &str)] = &[
        ("core.hooksPath", "/dev/null"),
        ("core.attributesFile", "/dev/null"),
        ("core.fsmonitor", "false"),
        ("core.protectHFS", "true"),
        ("core.protectNTFS", "true"),
        ("gc.auto", "0"),
        ("protocol.allow", "never"),
        ("protocol.https.allow", "always"),
        ("protocol.file.allow", "never"),
        ("protocol.ext.allow", "never"),
        ("protocol.git.allow", "never"),
        ("submodule.recurse", "false"),
    ];
    cmd.env("GIT_CONFIG_COUNT", pairs.len().to_string());
    for (idx, (k, v)) in pairs.iter().enumerate() {
        cmd.env(format!("GIT_CONFIG_KEY_{idx}"), k);
        cmd.env(format!("GIT_CONFIG_VALUE_{idx}"), v);
    }

    cmd
}

#[cfg(target_os = "linux")]
fn is_secret_or_forbidden_entry(
    name: &str,
    depth: usize,
    full_path: &Path,
    verified_dist_files: &[PathBuf],
) -> bool {
    if depth > 0 && verified_dist_files.iter().any(|p| p == full_path) {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    lower == ".env"
        || lower.starts_with(".env.")
        || lower == ".envrc"
        || lower.ends_with(".pem")
        || lower.ends_with(".key")
        || lower.ends_with(".p12")
        || lower.ends_with(".pfx")
        || lower.ends_with(".kdbx")
        || lower == ".netrc"
        || lower == ".pypirc"
        || lower == "audit.jsonl"
        || lower.starts_with(".agent-guard")
        || (depth > 0 && lower == "agents.md")
        || matches!(
            lower.as_str(),
            "tmp"
                | ".tmp"
                | "temp"
                | ".temp"
                | ".cache"
                | "__pycache__"
                | ".pytest_cache"
                | ".mypy_cache"
                | ".ruff_cache"
                | ".next"
                | ".nuxt"
                | ".turbo"
                | ".parcel-cache"
                | ".vite"
                | "node_modules"
                | "vendor"
                | ".venv"
                | "venv"
                | "site-packages"
                | "claude.md"
                | "claude.local.md"
                | "agents.override.md"
                | "gemini.md"
                | ".cursorrules"
                | ".windsurfrules"
                | ".clinerules"
                | ".roorules"
        )
}

#[cfg(target_os = "linux")]
fn collect_verified_dist_authority_files(canon_repo: &Path) -> Vec<PathBuf> {
    let manifest = canon_repo.join("dist-verify/manifest.sha256");
    let Ok(raw) = fs::read_to_string(&manifest) else {
        return Vec::new();
    };
    let root_agents_hex = fs::read(canon_repo.join("AGENTS.md"))
        .ok()
        .map(|b| crate::crypto::sha256_hex(&b));
    let mut out = Vec::new();
    for line in raw.lines() {
        let Some((hash, rel)) = line.split_once("  ") else {
            continue;
        };
        let (h, r) = (hash.trim(), rel.trim());
        if h.len() != 64 || !matches!(r, "dist/AGENTS.md" | "dist/gemini/GEMINI.md") {
            continue;
        }
        let full = canon_repo.join(r);
        let Ok(bytes) = fs::read(&full) else {
            continue;
        };
        let actual = crate::crypto::sha256_hex(&bytes);
        let valid = actual == h
            && match r {
                "dist/AGENTS.md" => root_agents_hex.as_deref() == Some(actual.as_str()),
                "dist/gemini/GEMINI.md" => actual == crate::CANONICAL_DIST_GEMINI_SHA256,
                _ => false,
            };
        if valid {
            out.push(full);
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn is_heavy_cargo_build_subdir(canon_repo: &Path, dir: &Path, depth: usize) -> bool {
    if depth < 2 || !dir.starts_with(canon_repo.join("target")) {
        return false;
    }
    dir.file_name().and_then(|s| s.to_str()).is_some_and(|n| {
        matches!(
            n,
            "deps" | "incremental" | "build" | ".fingerprint" | "examples"
        )
    })
}

#[cfg(target_os = "linux")]
fn dir_has_forbidden_descendant(
    dir: &Path,
    depth: usize,
    max_depth: usize,
    scan_budget: &mut usize,
    canon_repo: &Path,
    verified_dist: &[PathBuf],
) -> bool {
    if is_heavy_cargo_build_subdir(canon_repo, dir, depth) {
        return false;
    }
    if depth > max_depth || *scan_budget == 0 {
        return true;
    }
    *scan_budget -= 1;
    let Ok(entries) = fs::read_dir(dir) else {
        return true;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if is_secret_or_forbidden_entry(&name, depth, &path, verified_dist) {
            return true;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.file_type().is_symlink()
            && meta.file_type().is_dir()
            && dir_has_forbidden_descendant(
                &path,
                depth + 1,
                max_depth,
                scan_budget,
                canon_repo,
                verified_dist,
            )
        {
            return true;
        }
    }
    false
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn add_filtered_repo_tree(
    dir: &Path,
    depth: usize,
    max_depth: usize,
    writes_allowed: bool,
    canon_repo: &Path,
    verified_dist: &[PathBuf],
    ro_access: landlock::BitFlags<landlock::AccessFs>,
    rw_access: landlock::BitFlags<landlock::AccessFs>,
    rules: &mut Vec<Result<landlock::PathBeneath<landlock::PathFd>, landlock::RulesetError>>,
) {
    use landlock::{AccessFs, BitFlags};
    let mut scan_budget = 4_096usize;
    if !dir_has_forbidden_descendant(
        dir,
        depth,
        max_depth,
        &mut scan_budget,
        canon_repo,
        verified_dist,
    ) {
        let acc = if writes_allowed { rw_access } else { ro_access };
        rules.extend(landlock::path_beneath_rules([dir], acc));
        return;
    }
    let dirty_dir_access = if writes_allowed {
        AccessFs::ReadDir | AccessFs::MakeReg | AccessFs::MakeDir
    } else {
        BitFlags::from(AccessFs::ReadDir)
    };
    rules.extend(landlock::path_beneath_rules([dir], dirty_dir_access));
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink()
            || is_secret_or_forbidden_entry(&name, depth, &path, verified_dist)
        {
            continue;
        }
        if meta.file_type().is_dir() {
            if depth < max_depth {
                add_filtered_repo_tree(
                    &path,
                    depth + 1,
                    max_depth,
                    writes_allowed,
                    canon_repo,
                    verified_dist,
                    ro_access,
                    rw_access,
                    rules,
                );
            } else {
                rules.extend(landlock::path_beneath_rules(
                    [&path],
                    BitFlags::from(AccessFs::ReadDir),
                ));
            }
        } else {
            let f_acc = if writes_allowed {
                AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate
            } else {
                BitFlags::from(AccessFs::ReadFile)
            };
            rules.extend(landlock::path_beneath_rules([&path], f_acc));
        }
    }
}

#[cfg(target_os = "linux")]
fn is_swarm_mutable_root_artifact(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "plan.lock.json" | "work_ledger.jsonl" | ".breadcrumbs.jsonl"
    )
}

#[cfg(target_os = "linux")]
fn is_immutable_control_root_entry(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "agents.md"
            | "review.md"
            | "profiles"
            | ".dotagent-smoke.toml"
            | ".claude"
            | ".codex"
            | ".cursor"
            | ".github"
            | ".guard"
            | ".cargo"
            | ".yarn"
            | ".gitattributes"
            | ".npmrc"
            | ".yarnrc"
            | ".yarnrc.yml"
            | "rust-toolchain"
            | "rust-toolchain.toml"
    )
}

#[cfg(target_os = "linux")]
pub fn probe_linux_unshare_netns() -> bool {
    static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        let bin = Path::new("/usr/bin/unshare");
        if !bin.is_file() {
            return false;
        }
        Command::new(bin)
            .args(["--user", "--net", "--", "/bin/true"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

/// Installs an unprivileged kernel `seccomp-bpf` socket allowlist filter permitting ONLY
/// `AF_UNIX` (1, required for local privilege-separated `coord.sock` IPC) and `AF_NETLINK`
/// (16, required by `glibc` interface enumeration) while denying EVERY other address family
/// (`AF_INET`, `AF_INET6`, `AF_PACKET`, `AF_VSOCK`, `AF_XDP`, `AF_BLUETOOTH`, `AF_CAN`, etc.)
/// with `EPERM` (1).
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub fn apply_linux_seccomp_net_filter() -> Result<(), String> {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch, apply_filter,
    };
    use std::collections::BTreeMap;

    #[cfg(target_arch = "x86_64")]
    let (arch, sys_socket, sys_socketpair) = (TargetArch::x86_64, 41i64, 53i64);
    #[cfg(target_arch = "aarch64")]
    let (arch, sys_socket, sys_socketpair) = (TargetArch::aarch64, 198i64, 199i64);

    const AF_UNIX_DOMAIN: u64 = 1;
    const AF_NETLINK_DOMAIN: u64 = 16;

    let build_non_local_deny_rule = || -> Result<Vec<SeccompRule>, String> {
        let not_unix =
            SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, AF_UNIX_DOMAIN)
                .map_err(|e| format!("seccomp AF_UNIX condition error: {e}"))?;
        let not_netlink = SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Ne,
            AF_NETLINK_DOMAIN,
        )
        .map_err(|e| format!("seccomp AF_NETLINK condition error: {e}"))?;
        let rule = SeccompRule::new(vec![not_unix, not_netlink])
            .map_err(|e| format!("seccomp allowlist rule error: {e}"))?;
        Ok(vec![rule])
    };

    let mut rules_map = BTreeMap::new();
    rules_map.insert(sys_socket, build_non_local_deny_rule()?);
    rules_map.insert(sys_socketpair, build_non_local_deny_rule()?);
    #[cfg(target_arch = "x86_64")]
    {
        // Also gate Linux x32 ABI (`__X32_SYSCALL_BIT = 0x4000_0000`) which shares `AUDIT_ARCH_X86_64`.
        const X32_BIT: i64 = 0x4000_0000;
        rules_map.insert(X32_BIT | 41, build_non_local_deny_rule()?);
        rules_map.insert(X32_BIT | 53, build_non_local_deny_rule()?);
    }

    // `seccompiler::SeccompFilter::new(rules, mismatch_action, match_action, target_arch)`:
    // - `mismatch_action = Allow`: permits syscalls not in `rules_map` and `AF_UNIX`/`AF_NETLINK` sockets.
    // - `match_action = Errno(1)` (`EPERM`): denies any `socket`/`socketpair` call matching `domain != AF_UNIX && domain != AF_NETLINK`.
    let mismatch_action = SeccompAction::Allow;
    let match_action = SeccompAction::Errno(1);
    let filter = SeccompFilter::new(rules_map, mismatch_action, match_action, arch)
        .map_err(|e| format!("seccomp filter init error: {e}"))?;

    let bpf: BpfProgram = filter
        .try_into()
        .map_err(|e| format!("seccomp BPF compilation error: {e}"))?;
    apply_filter(&bpf).map_err(|e| format!("seccomp apply_filter error: {e}"))
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
pub fn apply_linux_seccomp_net_filter() -> Result<(), String> {
    Err("seccomp socket filter unsupported on this CPU architecture".to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn resolve_linked_worktree_git_dirs(canon_repo: &Path) -> Option<(PathBuf, PathBuf)> {
    let dot_git = canon_repo.join(".git");
    let meta = fs::symlink_metadata(&dot_git).ok()?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() || meta.len() > 4_096 {
        return None;
    }
    let raw = fs::read_to_string(&dot_git).ok()?;
    let rest = raw.trim().strip_prefix("gitdir:")?.trim();
    let target_raw = Path::new(rest);
    let resolved = if target_raw.is_absolute() {
        target_raw.to_path_buf()
    } else {
        canon_repo.join(target_raw)
    };
    let canon_gitdir = fs::canonicalize(&resolved).unwrap_or(resolved);
    let worktrees_dir = canon_gitdir.parent()?;
    if worktrees_dir.file_name().and_then(|s| s.to_str()) != Some("worktrees") {
        return None;
    }
    let common_git_dir = worktrees_dir.parent()?;
    if common_git_dir.file_name().and_then(|s| s.to_str()) != Some(".git") {
        return None;
    }
    let common_git_buf = common_git_dir.to_path_buf();
    Some((canon_gitdir, common_git_buf))
}

fn apply_current_process_sandbox(
    repo_root: &Path,
    ephemeral_tmp: Option<&Path>,
    opts: SandboxPolicyOpts,
) -> (KernelSandboxMode, Result<(), String>) {
    #[cfg(target_os = "linux")]
    {
        if opts.deny_net {
            let _ = probe_linux_unshare_netns();
        }
        let mode = apply_linux_landlock(repo_root, ephemeral_tmp, opts);
        let net_res = if opts.deny_net {
            apply_linux_seccomp_net_filter()
        } else {
            Ok(())
        };
        (mode, net_res)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (repo_root, ephemeral_tmp, opts);
        let mode = if Path::new("/usr/bin/sandbox-exec").is_file() {
            KernelSandboxMode::MacosSeatbeltEnforced
        } else {
            KernelSandboxMode::FallbackEnvAndAstOnly
        };
        (mode, Ok(()))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (repo_root, ephemeral_tmp, opts);
        (KernelSandboxMode::FallbackEnvAndAstOnly, Ok(()))
    }
}

#[cfg(target_os = "linux")]
fn apply_linux_landlock(
    repo_root: &Path,
    ephemeral_tmp: Option<&Path>,
    opts: SandboxPolicyOpts,
) -> KernelSandboxMode {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus,
    };

    let abi = ABI::V5;
    let ro_access = AccessFs::from_read(abi);
    let rw_access = AccessFs::from_all(abi);
    let file_ro_access = BitFlags::from(AccessFs::ReadFile);
    let dir_list_access = BitFlags::from(AccessFs::ReadDir);

    let base_ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(rw_access);
    let with_net = if opts.deny_net {
        // Landlock ABI V4+ (`Linux 6.7+`): handling `AccessNet::from_all` with zero `NetPort`
        // rules blocks all outbound `ConnectTcp` and listening `BindTcp` sockets at the LSM layer!
        base_ruleset.and_then(|r| r.handle_access(AccessNet::from_all(abi)))
    } else {
        base_ruleset
    };
    let Ok(created) = with_net.and_then(|r| r.create()) else {
        return KernelSandboxMode::FallbackEnvAndAstOnly;
    };

    let mut rules = Vec::new();
    let mut add_path = |p: &Path, access: BitFlags<AccessFs>| {
        rules.extend(landlock::path_beneath_rules([p], access));
    };

    // 1. Safe OS runtime & toolchain read-only roots (excludes /tmp, /var/tmp, /dev/shm, /etc/shadow, ~/.ssh, ~/.aws)
    for sys_ro in [
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/lib32",
        "/opt",
        "/etc/alternatives",
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
        "/etc/ssl",
        "/etc/ca-certificates",
        "/etc/pki",
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/nsswitch.conf",
        "/etc/passwd",
        "/etc/group",
        "/etc/localtime",
        "/proc/self/fd",
        "/proc/self/stat",
        "/proc/self/maps",
        "/proc/cpuinfo",
        "/proc/meminfo",
        "/proc/stat",
        "/proc/version",
        "/proc/filesystems",
        "/sys/devices/system/cpu",
    ] {
        let p = Path::new(sys_ro);
        if p.exists() {
            add_path(p, ro_access);
        }
    }

    let home_opt = env::var_os("HOME").map(PathBuf::from);

    // Allow read+execute on the directory containing `agent-guard` itself (e.g. `target/debug`),
    // guarding strictly against `/` and `$HOME` so placing the binary in `$HOME` never exposes `~/.ssh`!
    if let Ok(exe) = env::current_exe()
        && let Some(exe_dir) = exe.parent()
        && exe_dir != Path::new("/")
        && home_opt.as_deref() != Some(exe_dir)
        && exe_dir.is_dir()
    {
        add_path(exe_dir, ro_access);
    }

    // 2. Safe pseudo-devices & validated non-symlink GIT_CONFIG_GLOBAL read access
    for dev_rw in ["/dev/null", "/dev/zero", "/dev/urandom", "/dev/random"] {
        let p = Path::new(dev_rw);
        if p.exists() {
            add_path(
                p,
                AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate,
            );
        }
    }
    if let Some(git_cfg) = env::var_os("GIT_CONFIG_GLOBAL") {
        let p = PathBuf::from(git_cfg);
        let is_safe_gitconfig_name = p
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| matches!(n, ".gitconfig" | "gitconfig" | "gitconfig.hardened"));
        let is_non_symlink_file = fs::symlink_metadata(&p)
            .is_ok_and(|m| m.file_type().is_file() && !m.file_type().is_symlink());
        if is_safe_gitconfig_name && is_non_symlink_file {
            add_path(&p, file_ro_access);
        }
    }

    // 3. User-space toolchain directories (Rustup, Cargo, NVM/Volta/fnm) WITHOUT exposing ~/.ssh, ~/.aws, ~/.local/state/agent-guard
    if let Some(ref home) = home_opt {
        let rustup = env::var_os("RUSTUP_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".rustup"));
        if rustup.exists() {
            add_path(&rustup, ro_access);
        }
        let cargo_home = env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".cargo"));
        if cargo_home.exists() {
            let cargo_bin = cargo_home.join("bin");
            if cargo_bin.exists() {
                add_path(&cargo_bin, ro_access);
            }
            for sub in ["registry", "git", ".package-cache", ".package-cache-mutate"] {
                let sp = cargo_home.join(sub);
                if sp.exists() {
                    add_path(
                        &sp,
                        if opts.writes_allowed {
                            rw_access
                        } else {
                            ro_access
                        },
                    );
                }
            }
        }
        let home_gitconfig = home.join(".gitconfig");
        if fs::symlink_metadata(&home_gitconfig)
            .is_ok_and(|m| m.file_type().is_file() && !m.file_type().is_symlink())
        {
            add_path(&home_gitconfig, file_ro_access);
        }
        for ro_tool in [
            ".nvm",
            ".volta",
            ".fnm",
            ".bun",
            ".deno",
            ".local/bin",
            ".local/share/uv",
        ] {
            let tp = home.join(ro_tool);
            if tp.exists() {
                add_path(&tp, ro_access);
            }
        }
    }

    // 4. Private per-invocation ephemeral TMPDIR (isolated from /tmp, /var/tmp, /dev/shm)
    if let Some(tmp) = ephemeral_tmp {
        add_path(tmp, rw_access);
    }

    // 4b. Granular Swarm state access:
    //     `<swarm_state_dir>/vault` (`hmac.key`, `stop_receipt_ed25519.pub`) is UNCONDITIONALLY OMITTED (`EACCES`)!
    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let has_swarm_session =
        env::var("AGENT_GUARD_SESSION_ID").is_ok_and(|s| s.trim().starts_with("swm_"));
    if opts.invokes_swarm_tool {
        if let Ok(sdir) = crate::breadcrumbs::swarm_state_dir(&canon_repo) {
            for allowed_sub in ["ipc", "sessions", "spools", "ledger"] {
                let sub_p = sdir.join(allowed_sub);
                if sub_p.is_dir() {
                    add_path(&sub_p, rw_access);
                }
            }
        }
        if let Ok(locks_dir) = crate::breadcrumbs::swarm_locks_dir()
            && locks_dir.is_dir()
        {
            add_path(&locks_dir, rw_access);
        }
    } else if has_swarm_session {
        if let Ok(sdir) = crate::breadcrumbs::swarm_state_dir(&canon_repo) {
            for rw_sub in ["ipc", "spools", "ledger"] {
                let sub_p = sdir.join(rw_sub);
                if sub_p.is_dir() {
                    add_path(&sub_p, rw_access);
                }
            }
            let sess_p = sdir.join("sessions");
            if sess_p.is_dir() {
                add_path(&sess_p, ro_access);
            }
        }
        if let Ok(locks_dir) = crate::breadcrumbs::swarm_locks_dir()
            && locks_dir.is_dir()
        {
            add_path(&locks_dir, rw_access);
        }
    } else if opts.invokes_feedback_submit
        && let Ok(sdir) = crate::breadcrumbs::swarm_state_dir(&canon_repo)
    {
        let ipc_p = sdir.join("ipc");
        if ipc_p.is_dir() {
            add_path(&ipc_p, rw_access);
        }
    }

    // 4c. Linked Git worktree support (`git worktree add --detach`):
    //     Grant read-only access to `<common_repo>/.git` (omitting `hooks/`, keeping `config` read-only,
    //     and isolating `worktrees/` strictly to THIS worktree's `<wt_gitdir>`).
    if let Some((wt_gitdir, common_git_dir)) = resolve_linked_worktree_git_dirs(&canon_repo) {
        add_path(&common_git_dir, dir_list_access);
        if let Ok(git_entries) = fs::read_dir(&common_git_dir) {
            for ge in git_entries.flatten() {
                let gpath = ge.path();
                let Ok(gmeta) = fs::symlink_metadata(&gpath) else {
                    continue;
                };
                if gmeta.file_type().is_symlink() {
                    continue;
                }
                let gname = ge.file_name().to_string_lossy().into_owned();
                if gname.eq_ignore_ascii_case("hooks") {
                    continue;
                }
                if gname.eq_ignore_ascii_case("config") {
                    add_path(&gpath, file_ro_access);
                    continue;
                }
                if gname.eq_ignore_ascii_case("worktrees") {
                    add_path(&gpath, dir_list_access);
                    let wt_acc = if opts.invokes_git && opts.writes_allowed {
                        rw_access
                    } else {
                        ro_access
                    };
                    add_path(&wt_gitdir, wt_acc);
                    continue;
                }
                let g_access = if (opts.invokes_git
                    && opts.writes_allowed
                    && gname.eq_ignore_ascii_case("objects"))
                    || ((opts.invokes_swarm_tool || has_swarm_session)
                        && gname.eq_ignore_ascii_case("info"))
                {
                    rw_access
                } else if gmeta.file_type().is_dir() {
                    ro_access
                } else {
                    file_ro_access
                };
                add_path(&gpath, g_access);
            }
        }
        if let Some(common_repo) = common_git_dir.parent() {
            for art in ["PLAN.lock.json", "WORK_LEDGER.jsonl", ".breadcrumbs.jsonl"] {
                let art_p = common_repo.join(art);
                if let Ok(ameta) = fs::symlink_metadata(&art_p)
                    && !ameta.file_type().is_symlink()
                    && ameta.file_type().is_file()
                {
                    let art_acc = if opts.invokes_swarm_tool
                        || (has_swarm_session && art != "PLAN.lock.json")
                    {
                        AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate
                    } else {
                        file_ro_access
                    };
                    add_path(&art_p, art_acc);
                }
            }
        }
    }

    // 5. Granular `repo_root` rules with depth-3 recursive secret exclusion:
    //    - `repo_root` itself gets `ReadDir` ONLY so unlisted/secret root files (`.env*`) cannot be read
    //      and immutable root control files (`AGENTS.md`) cannot be overwritten or unlinked!
    rules.extend(landlock::path_beneath_rules([&canon_repo], dir_list_access));

    // Pre-create `target` if writes are allowed and `Cargo.toml` exists so `cargo` can build even
    // on a fresh clean checkout where `target/` did not yet exist prior to `restrict_self()`.
    if opts.writes_allowed && canon_repo.join("Cargo.toml").is_file() {
        let target_dir = canon_repo.join("target");
        if !target_dir.exists() {
            let _ = fs::create_dir(&target_dir);
        }
    }

    let verified_dist = collect_verified_dist_authority_files(&canon_repo);

    if let Ok(entries) = fs::read_dir(&canon_repo) {
        for entry in entries.flatten() {
            let name_os = entry.file_name();
            let name = name_os.to_string_lossy();
            let entry_path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&entry_path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }

            if is_secret_or_forbidden_entry(&name, 0, &entry_path, &verified_dist) {
                // OMITTED: 0 kernel access (`EACCES` on open/read/write)!
                continue;
            }

            if name == ".git" {
                if meta.file_type().is_dir() {
                    if opts.invokes_git && opts.writes_allowed {
                        for gsub in ["objects", "refs", "logs"] {
                            let gp = entry_path.join(gsub);
                            if !gp.exists() {
                                let _ = fs::create_dir_all(&gp);
                            }
                        }
                        // Vetted atomic `git` commands (`git add`, `git commit`, `git checkout -b`)
                        // require `.git/index.lock` and `.git/HEAD.lock` creation/rename inside `.git/`;
                        // `cmd_policy` blocks `git config`/`remote`/`hook`/`-c`, `GIT_CONFIG_COUNT`
                        // overrides `.git/config`, and `run_exec_sandbox_cli` atomically restores
                        // `pre_git_cfg_bytes` via temp+rename on any `.git/config` digest drift!
                        rules.extend(landlock::path_beneath_rules(
                            [&entry_path],
                            AccessFs::ReadDir
                                | AccessFs::MakeReg
                                | AccessFs::RemoveFile
                                | AccessFs::Refer,
                        ));
                    } else {
                        rules.extend(landlock::path_beneath_rules([&entry_path], dir_list_access));
                    }
                    if let Ok(git_entries) = fs::read_dir(&entry_path) {
                        for ge in git_entries.flatten() {
                            let gname = ge.file_name().to_string_lossy().into_owned();
                            let gpath = ge.path();
                            if gname.eq_ignore_ascii_case("hooks") {
                                continue; // 0 access to .git/hooks
                            }
                            if gname.eq_ignore_ascii_case("config") {
                                rules
                                    .extend(landlock::path_beneath_rules([&gpath], file_ro_access));
                                continue;
                            }
                            let g_access = if (opts.invokes_git && opts.writes_allowed)
                                || ((opts.invokes_swarm_tool || has_swarm_session)
                                    && gname.eq_ignore_ascii_case("info"))
                            {
                                rw_access
                            } else if gpath.is_dir() {
                                ro_access
                            } else {
                                file_ro_access
                            };
                            rules.extend(landlock::path_beneath_rules([&gpath], g_access));
                        }
                    }
                } else {
                    rules.extend(landlock::path_beneath_rules([&entry_path], file_ro_access));
                }
                continue;
            }

            if is_swarm_mutable_root_artifact(&name) {
                let sw_acc = if opts.invokes_swarm_tool
                    || (has_swarm_session && !name.eq_ignore_ascii_case("PLAN.lock.json"))
                {
                    AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate
                } else {
                    file_ro_access
                };
                rules.extend(landlock::path_beneath_rules([&entry_path], sw_acc));
                continue;
            }

            if is_immutable_control_root_entry(&name) {
                let ctl_acc = if meta.file_type().is_dir() {
                    ro_access
                } else {
                    file_ro_access
                };
                rules.extend(landlock::path_beneath_rules([&entry_path], ctl_acc));
                continue;
            }

            if meta.file_type().is_dir() {
                add_filtered_repo_tree(
                    &entry_path,
                    1,
                    24,
                    opts.writes_allowed,
                    &canon_repo,
                    &verified_dist,
                    ro_access,
                    rw_access,
                    &mut rules,
                );
            } else {
                let f_acc = if opts.writes_allowed {
                    AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate
                } else {
                    file_ro_access
                };
                rules.extend(landlock::path_beneath_rules([&entry_path], f_acc));
            }
        }
    }

    match created.add_rules(rules).and_then(|r| r.restrict_self()) {
        Ok(status) => match status.ruleset {
            RulesetStatus::FullyEnforced => KernelSandboxMode::LinuxLandlockEnforced,
            RulesetStatus::PartiallyEnforced => KernelSandboxMode::LinuxLandlockPartiallyEnforced,
            RulesetStatus::NotEnforced => KernelSandboxMode::FallbackEnvAndAstOnly,
        },
        Err(_) => KernelSandboxMode::FallbackEnvAndAstOnly,
    }
}

#[cfg(target_os = "macos")]
fn escape_sbpl_literal(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 8);
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' | '\r' | '\0' => {}
            other => out.push(other),
        }
    }
    out
}

#[cfg(target_os = "macos")]
fn render_macos_seatbelt_profile(
    repo_root: &Path,
    ephemeral_tmp: Option<&Path>,
    opts: SandboxPolicyOpts,
) -> String {
    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let repo_s = escape_sbpl_literal(&canon_repo.to_string_lossy());
    let home_s = escape_sbpl_literal(&env::var("HOME").unwrap_or_default());
    let has_swarm_session =
        env::var("AGENT_GUARD_SESSION_ID").is_ok_and(|s| s.trim().starts_with("swm_"));
    let mut p = String::from("(version 1)\n(allow default)\n");

    if opts.deny_net {
        p.push_str("(deny network*)\n");
    }

    // Default-deny arbitrary filesystem writes outside `repo_root` and `ephemeral_tmp`
    p.push_str("(deny file-write*)\n");
    p.push_str("(allow file-write* (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/urandom\") (literal \"/dev/random\"))\n");
    if opts.writes_allowed {
        p.push_str(&format!("(allow file-write* (subpath \"{repo_s}\"))\n"));
    }

    if let Some(tmp) = ephemeral_tmp {
        let canon_tmp = fs::canonicalize(tmp).unwrap_or_else(|_| tmp.to_path_buf());
        let tmp_s = escape_sbpl_literal(&canon_tmp.to_string_lossy());
        p.push_str(&format!(
            "(deny file-read* file-write* (subpath \"/tmp\") (subpath \"/private/tmp\") (subpath \"/var/tmp\") (subpath \"/private/var/tmp\"))\n(allow file-read* file-write* (subpath \"{tmp_s}\"))\n"
        ));
    }
    if !home_s.is_empty() {
        p.push_str(&format!(
            "(deny file-read* file-write* (subpath \"{home_s}/.ssh\") (subpath \"{home_s}/.aws\") (subpath \"{home_s}/.gnupg\") (subpath \"{home_s}/.config/gh\") (subpath \"{home_s}/.config/dotagent\") (subpath \"{home_s}/Library/Keychains\") (subpath \"{home_s}/.local/state/agent-guard\"))\n"
        ));
    }
    let raw_state_base = crate::traversal_ledger::state_base_dir();
    let active_state_root = if raw_state_base.file_name().is_some_and(|n| n == "sessions") {
        raw_state_base
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or(raw_state_base)
    } else {
        raw_state_base
    };
    let canon_state_base = fs::canonicalize(&active_state_root).unwrap_or(active_state_root);
    let sb_s = escape_sbpl_literal(&canon_state_base.to_string_lossy());
    if !sb_s.is_empty() {
        p.push_str(&format!(
            "(deny file-read* file-write* (subpath \"{sb_s}\"))\n"
        ));
    }
    if opts.invokes_swarm_tool {
        if !sb_s.is_empty() {
            p.push_str(&format!(
                "(allow file-read-metadata (subpath \"{sb_s}\"))\n"
            ));
        }
        if let Ok(raw_sdir) = crate::breadcrumbs::swarm_state_dir(&canon_repo) {
            let sdir = fs::canonicalize(&raw_sdir).unwrap_or(raw_sdir);
            for sub in ["ipc", "sessions", "spools", "ledger"] {
                let sub_path = sdir.join(sub);
                let canon_sub = fs::canonicalize(&sub_path).unwrap_or(sub_path);
                let sp = escape_sbpl_literal(&canon_sub.to_string_lossy());
                p.push_str(&format!(
                    "(allow file-read* file-write* (subpath \"{sp}\"))\n"
                ));
                if sub == "ipc" && opts.deny_net {
                    p.push_str(&format!(
                        "(allow network-outbound (remote unix-socket (subpath \"{sp}\")))\n"
                    ));
                }
            }
            let vault_dir = sdir.join("vault");
            let canon_vault = fs::canonicalize(&vault_dir).unwrap_or(vault_dir);
            let vp = escape_sbpl_literal(&canon_vault.to_string_lossy());
            p.push_str(&format!(
                "(deny file-read* file-read-metadata file-write* (subpath \"{vp}\"))\n"
            ));
        }
        if let Ok(raw_locks) = crate::breadcrumbs::swarm_locks_dir() {
            let locks_dir = fs::canonicalize(&raw_locks).unwrap_or(raw_locks);
            let lp = escape_sbpl_literal(&locks_dir.to_string_lossy());
            p.push_str(&format!(
                "(allow file-read* file-write* (subpath \"{lp}\"))\n"
            ));
        }
    } else if has_swarm_session {
        if !sb_s.is_empty() {
            p.push_str(&format!(
                "(allow file-read-metadata (subpath \"{sb_s}\"))\n"
            ));
        }
        if let Ok(raw_sdir) = crate::breadcrumbs::swarm_state_dir(&canon_repo) {
            let sdir = fs::canonicalize(&raw_sdir).unwrap_or(raw_sdir);
            for rw_sub in ["ipc", "spools", "ledger"] {
                let sub_path = sdir.join(rw_sub);
                let canon_sub = fs::canonicalize(&sub_path).unwrap_or(sub_path);
                let sp = escape_sbpl_literal(&canon_sub.to_string_lossy());
                p.push_str(&format!(
                    "(allow file-read* file-write* (subpath \"{sp}\"))\n"
                ));
                if rw_sub == "ipc" && opts.deny_net {
                    p.push_str(&format!(
                        "(allow network-outbound (remote unix-socket (subpath \"{sp}\")))\n"
                    ));
                }
            }
            let sess_path = sdir.join("sessions");
            let canon_sess = fs::canonicalize(&sess_path).unwrap_or(sess_path);
            let sess_s = escape_sbpl_literal(&canon_sess.to_string_lossy());
            p.push_str(&format!("(allow file-read* (subpath \"{sess_s}\"))\n"));
            let vault_dir = sdir.join("vault");
            let canon_vault = fs::canonicalize(&vault_dir).unwrap_or(vault_dir);
            let vp = escape_sbpl_literal(&canon_vault.to_string_lossy());
            p.push_str(&format!(
                "(deny file-read* file-read-metadata file-write* (subpath \"{vp}\"))\n"
            ));
        }
        if let Ok(raw_locks) = crate::breadcrumbs::swarm_locks_dir() {
            let locks_dir = fs::canonicalize(&raw_locks).unwrap_or(raw_locks);
            let lp = escape_sbpl_literal(&locks_dir.to_string_lossy());
            p.push_str(&format!(
                "(allow file-read* file-write* (subpath \"{lp}\"))\n"
            ));
        }
        p.push_str(&format!(
            "(deny file-write* (literal \"{repo_s}/PLAN.lock.json\"))\n"
        ));
    } else if opts.invokes_feedback_submit {
        if !sb_s.is_empty() {
            p.push_str(&format!(
                "(allow file-read-metadata (subpath \"{sb_s}\"))\n"
            ));
        }
        if let Ok(raw_sdir) = crate::breadcrumbs::swarm_state_dir(&canon_repo) {
            let sdir = fs::canonicalize(&raw_sdir).unwrap_or(raw_sdir);
            let ipc_path = sdir.join("ipc");
            let canon_ipc = fs::canonicalize(&ipc_path).unwrap_or(ipc_path);
            let sp = escape_sbpl_literal(&canon_ipc.to_string_lossy());
            p.push_str(&format!(
                "(allow file-read* file-write* (subpath \"{sp}\"))\n"
            ));
            if opts.deny_net {
                p.push_str(&format!(
                    "(allow network-outbound (remote unix-socket (subpath \"{sp}\")))\n"
                ));
            }
            let vault_dir = sdir.join("vault");
            let canon_vault = fs::canonicalize(&vault_dir).unwrap_or(vault_dir);
            let vp = escape_sbpl_literal(&canon_vault.to_string_lossy());
            p.push_str(&format!(
                "(deny file-read* file-read-metadata file-write* (subpath \"{vp}\"))\n"
            ));
        }
        p.push_str(&format!(
            "(deny file-write* (literal \"{repo_s}/PLAN.lock.json\") (literal \"{repo_s}/WORK_LEDGER.jsonl\") (literal \"{repo_s}/.breadcrumbs.jsonl\"))\n"
        ));
    } else {
        if opts.invokes_feedback_submit
            && let Ok(raw_sdir) = crate::breadcrumbs::swarm_state_dir(&canon_repo)
        {
            if !sb_s.is_empty() {
                p.push_str(&format!(
                    "(allow file-read-metadata (subpath \"{sb_s}\"))\n"
                ));
            }
            let sdir = fs::canonicalize(&raw_sdir).unwrap_or(raw_sdir);
            let ipc_path = sdir.join("ipc");
            let canon_ipc = fs::canonicalize(&ipc_path).unwrap_or(ipc_path);
            let ip = escape_sbpl_literal(&canon_ipc.to_string_lossy());
            p.push_str(&format!(
                "(allow file-read* file-write* (subpath \"{ip}\"))\n"
            ));
            if opts.deny_net {
                p.push_str(&format!(
                    "(allow network-outbound (remote unix-socket (subpath \"{ip}\")))\n"
                ));
            }
        }
        p.push_str(&format!(
            "(deny file-write* (literal \"{repo_s}/PLAN.lock.json\") (literal \"{repo_s}/WORK_LEDGER.jsonl\") (literal \"{repo_s}/.breadcrumbs.jsonl\"))\n"
        ));
    }
    let is_linked_worktree = if let Some((wt_gitdir, common_git_dir)) =
        resolve_linked_worktree_git_dirs(&canon_repo)
    {
        let cg_s = escape_sbpl_literal(&common_git_dir.to_string_lossy());
        let wt_s = escape_sbpl_literal(&wt_gitdir.to_string_lossy());
        p.push_str(&format!(
                "(deny file-read* file-write* (subpath \"{cg_s}/hooks\"))\n(deny file-write* (literal \"{cg_s}/config\"))\n"
            ));
        if opts.invokes_git && opts.writes_allowed {
            p.push_str(&format!(
                "(allow file-write* (subpath \"{wt_s}\") (subpath \"{cg_s}/objects\"))\n"
            ));
        }
        if opts.invokes_swarm_tool || has_swarm_session {
            p.push_str(&format!("(allow file-write* (subpath \"{cg_s}/info\"))\n"));
            if let Some(common_repo) = common_git_dir.parent() {
                let cr_s = escape_sbpl_literal(&common_repo.to_string_lossy());
                if opts.invokes_swarm_tool {
                    p.push_str(&format!(
                            "(allow file-write* (literal \"{cr_s}/PLAN.lock.json\") (literal \"{cr_s}/WORK_LEDGER.jsonl\") (literal \"{cr_s}/.breadcrumbs.jsonl\"))\n"
                        ));
                } else {
                    p.push_str(&format!(
                            "(allow file-write* (literal \"{cr_s}/WORK_LEDGER.jsonl\") (literal \"{cr_s}/.breadcrumbs.jsonl\"))\n"
                        ));
                }
            }
        }
        true
    } else {
        false
    };
    if !opts.invokes_git {
        p.push_str(&format!(
            "(deny file-write* (subpath \"{repo_s}/.git\") (literal \"{repo_s}/.git\"))\n"
        ));
    } else if is_linked_worktree {
        // Keep linked-worktree `.git` (`gitdir:` pointer) kernel-immutable even during `git` writes!
        p.push_str(&format!("(deny file-write* (literal \"{repo_s}/.git\"))\n"));
    }
    p.push_str(&format!(
        "(deny file-read* file-write* (regex #\"/\\.env($|\\.)\") (regex #\"\\.(pem|key|p12|pfx)$\") (regex #\"/audit\\.jsonl$\") (subpath \"{repo_s}/.git/hooks\") (subpath \"{repo_s}/node_modules\") (subpath \"{repo_s}/.venv\") (subpath \"{repo_s}/vendor\"))\n"
    ));
    p.push_str(&format!(
        "(deny file-write* (literal \"{repo_s}/AGENTS.md\") (literal \"{repo_s}/.dotagent-smoke.toml\") (literal \"{repo_s}/.git/config\") (subpath \"{repo_s}/profiles\") (subpath \"{repo_s}/.guard\") (subpath \"{repo_s}/.claude\") (subpath \"{repo_s}/.codex\") (subpath \"{repo_s}/.cursor\") (subpath \"{repo_s}/.github\") (subpath \"{repo_s}/.cargo\") (literal \"{repo_s}/.gitattributes\") (literal \"{repo_s}/.npmrc\"))\n"
    ));
    p
}

#[cfg(test)]
mod tests {
    use super::drain_stream_bounded;
    use std::io::Cursor;

    #[test]
    fn drain_stream_bounded_reads_full_eof_without_truncating_pipe() {
        let mut big = Vec::new();
        big.extend_from_slice(b"HEAD_MARKER\n");
        big.extend(std::iter::repeat_n(b'x', 80_000));
        big.extend_from_slice(b"\nTAIL_MARKER\n");
        let drained = drain_stream_bounded(Cursor::new(big));
        let text = String::from_utf8_lossy(&drained);
        assert!(text.starts_with("HEAD_MARKER\n"));
        assert!(text.ends_with("TAIL_MARKER\n"));
        assert!(text.contains("exec-sandbox drained"));
        assert!(drained.len() < 36_000);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn depth3_landlock_tree_detects_nested_secrets_while_keeping_clean_siblings_fast() {
        use super::{dir_has_forbidden_descendant, is_secret_or_forbidden_entry};
        use std::fs;
        use std::path::{Path, PathBuf};

        let ws = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("ws")
            .join("target/test-workspaces/landlock-tree-unit");
        let _ = fs::remove_dir_all(&ws);
        fs::create_dir_all(ws.join("apps/web/src")).expect("web/src");
        fs::create_dir_all(ws.join("apps/api")).expect("api");
        let dotenv = format!("{}{}", ".", "env");
        let env_path = ws.join("apps/web").join(&dotenv);
        fs::write(&env_path, "PORT=1\n").expect("env");
        fs::write(ws.join("apps/web/src/main.ts"), "export {};\n").expect("main.ts");
        fs::write(ws.join("apps/api/lib.ts"), "export {};\n").expect("lib.ts");

        assert!(is_secret_or_forbidden_entry(&dotenv, 2, &env_path, &[]));
        assert!(is_secret_or_forbidden_entry(
            "AGENTS.md",
            1,
            &ws.join("apps/AGENTS.md"),
            &[]
        ));
        assert!(!is_secret_or_forbidden_entry(
            "AGENTS.md",
            0,
            &ws.join("AGENTS.md"),
            &[]
        ));
        assert!(dir_has_forbidden_descendant(
            &ws.join("apps"),
            1,
            24,
            &mut 4096,
            &ws,
            &[]
        ));
        assert!(dir_has_forbidden_descendant(
            &ws.join("apps/web"),
            2,
            24,
            &mut 4096,
            &ws,
            &[]
        ));
        assert!(!dir_has_forbidden_descendant(
            &ws.join("apps/web/src"),
            3,
            24,
            &mut 4096,
            &ws,
            &[]
        ));
        assert!(!dir_has_forbidden_descendant(
            &ws.join("apps/api"),
            2,
            24,
            &mut 4096,
            &ws,
            &[]
        ));
    }
}
