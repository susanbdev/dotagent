#![forbid(unsafe_code)]

//! OS-level execution sandbox (`agent-guard exec-sandbox`) wrapping child shell commands.
//!
//! Enforces defense-in-depth containment beneath `PreToolUse` AST validation:
//! 1. Scrubs dangerous dynamic-linker, compiler-wrapper, and interpreter hijack env vars
//!    (`LD_PRELOAD`, `RUSTC_WRAPPER`, `NODE_OPTIONS`, `PYTHONPATH`, `BASH_ENV`, `GIT_SSH_COMMAND`, ...).
//! 2. Locks down inherited Git configuration (`core.hooksPath=/dev/null`, `core.attributesFile=/dev/null`,
//!    `core.fsmonitor=false`, `protocol.allow=never`, `protocol.https.allow=always`, `submodule.recurse=false`)
//!    via `GIT_CONFIG_COUNT` when `GIT_CONFIG_GLOBAL` is not already pinned.
//! 3. Allocates a private, per-invocation ephemeral `TMPDIR` outside `/tmp`, `/var/tmp`, and `/dev/shm`,
//!    removing it automatically on process exit so compilers/test runners work seamlessly with zero
//!    shared-`/tmp` snooping.
//! 4. Applies OS kernel VFS sandboxing:
//!    - **Linux**: Landlock LSM (`ABI::V5` best-effort down to `V1`) granting `ReadDir`-only on `repo_root`,
//!      omitting `.env*`, `*.pem`, `*.key`, `.git/hooks`, `audit.jsonl`, `~/.ssh`, `~/.aws`,
//!      `~/.local/state/agent-guard`, and `/tmp`, locking `AGENTS.md`, `.claude/`, `.codex/`, `.cursor/`,
//!      `.github/`, `.cargo/`, and `.git/config` to read-only (`EACCES` on write), and honoring read-only
//!      runtime profiles (`enable_write_tools = false`) across the entire workspace.
//!    - **macOS**: Darwin Seatbelt (`/usr/bin/sandbox-exec`) profile denying secret/tmp/guard-state reads
//!      and control-file writes.

use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::budget_guard::{MAX_SLICED_FILE_BYTES, load_active_profile};
use crate::resolve_repo_root;
use crate::sanitizer::{
    DEFAULT_COMPACT_STREAM_MAX_BYTES, DEFAULT_COMPACT_STREAM_MAX_LINES, sanitize_and_compact_bytes,
};

const SCRUBBED_ENV_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "NODE_OPTIONS",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PERL5OPT",
    "PERL5LIB",
    "RUBYOPT",
    "RUBYLIB",
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
    "GIT_SSH_COMMAND",
    "GIT_SSH",
    "GIT_EXTERNAL_DIFF",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "AGENT_GUARD_ALLOW_SWARM",
    "AGENT_GUARD_ALLOW_INTERPRETER",
    "AGENT_GUARD_ALLOW_DEPUTY",
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

/// Formats a shell command to execute through `agent-guard exec-sandbox` with optional
/// in-process pre-buffer 7-bit ASCII stream sanitization and line compaction.
pub fn wrap_bash_with_exec_sandbox(cmd_str: &str, sanitize_stream: bool) -> String {
    let quoted = shell_quote_single(cmd_str);
    if sanitize_stream {
        format!("agent-guard exec-sandbox --sanitize-stream -- {quoted}")
    } else {
        format!("agent-guard exec-sandbox -- {quoted}")
    }
}

fn shell_quote_single(s: &str) -> String {
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

/// Probes whether OS-level kernel filesystem sandboxing is supported on the current host.
/// Note: on Linux, `restrict_self` mutates the calling process permanently, so `probe_kernel_sandbox_support`
/// checks `/proc/sys` / kernel ABI via a short-lived self subprocess (`--probe-landlock-child`) when needed.
pub fn run_sandbox_status_cli() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        if let Ok(exe) = env::current_exe()
            && let Ok(out) = Command::new(exe).arg("--probe-landlock-child").output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            println!("{}", text.trim());
            return if out.status.success() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            };
        }
        println!("mode=fallback-env-and-ast-only");
        ExitCode::SUCCESS
    }
    #[cfg(target_os = "macos")]
    {
        if Path::new("/usr/bin/sandbox-exec").is_file() {
            println!("mode=macos-seatbelt-enforced");
        } else {
            println!("mode=fallback-env-and-ast-only");
        }
        ExitCode::SUCCESS
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        println!("mode=fallback-env-and-ast-only");
        ExitCode::SUCCESS
    }
}

pub fn run_probe_landlock_child() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        use landlock::{
            ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr,
            RulesetCreatedAttr, RulesetStatus,
        };
        let abi = ABI::V5;
        let status = Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(abi))
            .and_then(|r| r.create())
            .and_then(|r| {
                r.add_rules(landlock::path_beneath_rules(
                    ["/usr"],
                    AccessFs::from_read(abi),
                ))
            })
            .and_then(|r| r.restrict_self());
        match status {
            Ok(s) => {
                match s.ruleset {
                    RulesetStatus::FullyEnforced => {
                        println!("mode={}", KernelSandboxMode::LinuxLandlockEnforced.as_str());
                    }
                    RulesetStatus::PartiallyEnforced => {
                        println!(
                            "mode={}",
                            KernelSandboxMode::LinuxLandlockPartiallyEnforced.as_str()
                        );
                    }
                    RulesetStatus::NotEnforced => {
                        println!("mode={}", KernelSandboxMode::FallbackEnvAndAstOnly.as_str());
                    }
                }
                ExitCode::SUCCESS
            }
            Err(_) => {
                println!("mode={}", KernelSandboxMode::FallbackEnvAndAstOnly.as_str());
                ExitCode::SUCCESS
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        println!("mode={}", KernelSandboxMode::FallbackEnvAndAstOnly.as_str());
        ExitCode::SUCCESS
    }
}

/// CLI entrypoint for `agent-guard exec-sandbox [--sanitize-stream] [--require-kernel] [--cwd <dir>] -- <cmd>`
pub fn run_exec_sandbox_cli(args: &[String], default_cwd: &Path) -> ExitCode {
    let mut sanitize_stream = false;
    let mut require_kernel = false;
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
            "[AGENT-GUARD] usage: agent-guard exec-sandbox [--sanitize-stream] [--require-kernel] [--cwd <dir>] -- \"<command>\""
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
    let writes_allowed = load_active_profile(&repo_root)
        .map(|p| p.enable_write_tools)
        .unwrap_or(true);
    let invokes_git = is_atomic_leading_command(&shell_script, "git");
    let invokes_swarm_tool = is_atomic_leading_command(&shell_script, "swarm-tool");

    // Pre-launch the out-of-sandbox Vault Coordinator daemon BEFORE `restrict_self()` so
    // `swarm-tool` can sign/verify provenance via `ipc/coord.sock` while `vault/hmac.key`
    // stays 100% kernel-inaccessible (`EACCES`) inside Landlock/Seatbelt!
    if invokes_swarm_tool {
        let _ = crate::coordinator::ensure_coordinator_daemon(&repo_root);
        precreate_swarm_tool_sandbox_targets(&repo_root, &shell_script);
    }

    let ephemeral_tmp = EphemeralTmpDir::create();
    let tmp_dir_path = ephemeral_tmp.as_ref().map(|t| t.path.as_path());

    // Apply OS kernel sandbox to THIS process prior to spawning `bash` on Linux (inherited across fork/exec!).
    let mode = apply_current_process_sandbox(
        &repo_root,
        tmp_dir_path,
        writes_allowed,
        invokes_git,
        invokes_swarm_tool,
    );
    if require_kernel && !mode.is_kernel_enforced() {
        eprintln!(
            "[AGENT-GUARD HARD DENY :: KERNEL_SANDBOX_UNAVAILABLE] Host kernel does not enforce Landlock/Seatbelt VFS containment (mode={}).",
            mode.as_str()
        );
        return ExitCode::from(2);
    }

    let mut child_cmd = build_child_command(
        &shell_script,
        &repo_root,
        &cwd,
        tmp_dir_path,
        invokes_swarm_tool,
    );

    if sanitize_stream {
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

        let stdout_handle = child.stdout.take().map(|out| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = out.take(MAX_SLICED_FILE_BYTES).read_to_end(&mut buf);
                buf
            })
        });
        let stderr_handle = child.stderr.take().map(|err| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = err.take(MAX_SLICED_FILE_BYTES).read_to_end(&mut buf);
                buf
            })
        });

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

        let code = status.code().unwrap_or(1) as u8;
        ExitCode::from(code)
    } else {
        match child_cmd.status() {
            Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
            Err(e) => {
                eprintln!("[AGENT-GUARD EXEC ERROR] failed executing sandboxed bash: {e}");
                ExitCode::from(126)
            }
        }
    }
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
    first_token == target_bin || first_token.ends_with(&format!("/{target_bin}"))
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
    invokes_swarm_tool: bool,
) -> Command {
    #[cfg(target_os = "macos")]
    let mut cmd = if Path::new("/usr/bin/sandbox-exec").is_file() {
        let profile = render_macos_seatbelt_profile(repo_root, ephemeral_tmp, invokes_swarm_tool);
        let mut c = Command::new("/usr/bin/sandbox-exec");
        c.arg("-p")
            .arg(profile)
            .arg("/bin/bash")
            .arg("-o")
            .arg("pipefail")
            .arg("-c")
            .arg(shell_script);
        c
    } else {
        let mut c = Command::new("bash");
        c.arg("-o").arg("pipefail").arg("-c").arg(shell_script);
        c
    };

    #[cfg(not(target_os = "macos"))]
    let mut cmd = {
        let _ = (repo_root, invokes_swarm_tool);
        let mut c = Command::new("bash");
        c.arg("-o").arg("pipefail").arg("-c").arg(shell_script);
        c
    };

    cmd.current_dir(cwd);
    for var in SCRUBBED_ENV_VARS {
        cmd.env_remove(var);
    }
    cmd.env("AGENT_GUARD_IN_SANDBOX", "1");
    cmd.env("PYTHONDONTWRITEBYTECODE", "1");
    cmd.env("PIP_NO_CACHE_DIR", "1");
    cmd.env("NPM_CONFIG_IGNORE_SCRIPTS", "true");
    cmd.env("HISTFILE", "/dev/null");
    cmd.env("PAGER", "cat");
    cmd.env("GIT_PAGER", "cat");

    if let Some(tmp) = ephemeral_tmp {
        cmd.env("TMPDIR", tmp);
        cmd.env("TEMP", tmp);
        cmd.env("TMP", tmp);
    }

    // Inject hermetic Git lockdown via GIT_CONFIG_COUNT when GIT_CONFIG_GLOBAL is not already pinned
    if env::var_os("GIT_CONFIG_GLOBAL").is_none() && env::var_os("GIT_CONFIG_COUNT").is_none() {
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
    }

    cmd
}

fn is_secret_or_forbidden_root_entry(name: &str) -> bool {
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
        || matches!(
            lower.as_str(),
            "tmp"
                | ".tmp"
                | "temp"
                | ".temp"
                | ".cache"
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

fn is_swarm_mutable_root_artifact(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "plan.lock.json" | "work_ledger.jsonl" | ".breadcrumbs.jsonl"
    )
}

fn is_immutable_control_root_entry(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "agents.md"
            | "review.md"
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

fn apply_current_process_sandbox(
    repo_root: &Path,
    ephemeral_tmp: Option<&Path>,
    writes_allowed: bool,
    invokes_git: bool,
    invokes_swarm_tool: bool,
) -> KernelSandboxMode {
    #[cfg(target_os = "linux")]
    {
        apply_linux_landlock(
            repo_root,
            ephemeral_tmp,
            writes_allowed,
            invokes_git,
            invokes_swarm_tool,
        )
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (
            repo_root,
            ephemeral_tmp,
            writes_allowed,
            invokes_git,
            invokes_swarm_tool,
        );
        if Path::new("/usr/bin/sandbox-exec").is_file() {
            KernelSandboxMode::MacosSeatbeltEnforced
        } else {
            KernelSandboxMode::FallbackEnvAndAstOnly
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (
            repo_root,
            ephemeral_tmp,
            writes_allowed,
            invokes_git,
            invokes_swarm_tool,
        );
        KernelSandboxMode::FallbackEnvAndAstOnly
    }
}

#[cfg(target_os = "linux")]
fn apply_linux_landlock(
    repo_root: &Path,
    ephemeral_tmp: Option<&Path>,
    writes_allowed: bool,
    invokes_git: bool,
    invokes_swarm_tool: bool,
) -> KernelSandboxMode {
    use landlock::{
        ABI, Access, AccessFs, BitFlags, CompatLevel, Compatible, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus,
    };

    let abi = ABI::V5;
    let ro_access = AccessFs::from_read(abi);
    let rw_access = AccessFs::from_all(abi);
    let file_ro_access = BitFlags::from(AccessFs::ReadFile);
    let dir_list_access = BitFlags::from(AccessFs::ReadDir);

    let Ok(created) = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(rw_access)
        .and_then(|r| r.create())
    else {
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
        "/proc/self",
        "/sys/devices/system/cpu",
    ] {
        let p = Path::new(sys_ro);
        if p.exists() {
            add_path(p, ro_access);
        }
    }

    // Allow read+execute on the directory containing `agent-guard` itself so sibling `swarm-tool`
    // binaries in non-installed build directories (e.g. `target/debug/swarm-tool`) can execute.
    if let Ok(exe) = env::current_exe()
        && let Some(exe_dir) = exe.parent()
        && exe_dir != Path::new("/")
        && exe_dir.is_dir()
    {
        add_path(exe_dir, ro_access);
    }

    // 2. Safe pseudo-devices & optional GIT_CONFIG_GLOBAL read access
    for dev_rw in ["/dev/null", "/dev/zero", "/dev/urandom", "/dev/random"] {
        let p = Path::new(dev_rw);
        if p.exists() {
            add_path(
                p,
                AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate,
            );
        }
    }
    if Path::new("/dev/fd").exists() {
        add_path(Path::new("/dev/fd"), ro_access);
    }
    if let Some(git_cfg) = env::var_os("GIT_CONFIG_GLOBAL") {
        let p = PathBuf::from(git_cfg);
        if p.is_file() {
            add_path(&p, file_ro_access);
        }
    }

    // 3. User-space toolchain directories (Rustup, Cargo, NVM/Volta/fnm) WITHOUT exposing ~/.ssh, ~/.aws, ~/.local/state/agent-guard
    if let Some(home_os) = env::var_os("HOME") {
        let home = PathBuf::from(home_os);
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
                    add_path(&sp, if writes_allowed { rw_access } else { ro_access });
                }
            }
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

    // 4b. Granular Swarm state access ONLY for atomic `swarm-tool` invocations:
    //     `<swarm_state_dir>/vault` (`hmac.key`) is UNCONDITIONALLY OMITTED (`EACCES`)!
    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    if invokes_swarm_tool {
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
    }

    // 5. Granular `repo_root` rules:
    //    - `repo_root` itself gets `ReadDir` ONLY so unlisted/secret root files (`.env*`) cannot be read
    //      and immutable root control files (`AGENTS.md`) cannot be overwritten or unlinked!
    add_path(&canon_repo, dir_list_access);

    // Pre-create `target` if writes are allowed and `Cargo.toml` exists so `cargo` can build even
    // on a fresh clean checkout where `target/` did not yet exist prior to `restrict_self()`.
    if writes_allowed && canon_repo.join("Cargo.toml").is_file() {
        let target_dir = canon_repo.join("target");
        if !target_dir.exists() {
            let _ = fs::create_dir(&target_dir);
        }
    }

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

            if is_secret_or_forbidden_root_entry(&name) {
                // OMITTED: 0 kernel access (`EACCES` on open/read/write)!
                continue;
            }

            if name == ".git" {
                if meta.file_type().is_dir() {
                    add_path(&entry_path, dir_list_access);
                    if let Ok(git_entries) = fs::read_dir(&entry_path) {
                        for ge in git_entries.flatten() {
                            let gname = ge.file_name().to_string_lossy().into_owned();
                            let gpath = ge.path();
                            if gname.eq_ignore_ascii_case("hooks") {
                                continue; // 0 access to .git/hooks
                            }
                            if gname.eq_ignore_ascii_case("config") {
                                add_path(&gpath, file_ro_access); // Read-only .git/config
                                continue;
                            }
                            let g_access = if (invokes_git && writes_allowed)
                                || (invokes_swarm_tool && gname.eq_ignore_ascii_case("info"))
                            {
                                rw_access
                            } else if gpath.is_dir() {
                                ro_access
                            } else {
                                file_ro_access
                            };
                            add_path(&gpath, g_access);
                        }
                    }
                } else {
                    add_path(&entry_path, file_ro_access);
                }
                continue;
            }

            if is_swarm_mutable_root_artifact(&name) {
                if invokes_swarm_tool {
                    add_path(
                        &entry_path,
                        AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate,
                    );
                } else {
                    add_path(&entry_path, file_ro_access);
                }
                continue;
            }

            if is_immutable_control_root_entry(&name) {
                if meta.file_type().is_dir() {
                    add_path(&entry_path, ro_access);
                } else {
                    add_path(&entry_path, file_ro_access);
                }
                continue;
            }

            let normal_access = if writes_allowed {
                if meta.file_type().is_dir() {
                    rw_access
                } else {
                    AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate
                }
            } else if meta.file_type().is_dir() {
                ro_access
            } else {
                file_ro_access
            };
            add_path(&entry_path, normal_access);
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
fn render_macos_seatbelt_profile(
    repo_root: &Path,
    ephemeral_tmp: Option<&Path>,
    invokes_swarm_tool: bool,
) -> String {
    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let repo_s = canon_repo.to_string_lossy().replace('"', "\\\"");
    let home_s = env::var("HOME").unwrap_or_default().replace('"', "\\\"");
    let mut p = String::from("(version 1)\n(allow default)\n");
    if let Some(tmp) = ephemeral_tmp {
        let tmp_s = tmp.to_string_lossy().replace('"', "\\\"");
        p.push_str(&format!(
            "(deny file-read* file-write* (subpath \"/tmp\") (subpath \"/private/tmp\") (subpath \"/var/tmp\") (subpath \"/private/var/tmp\"))\n(allow file-read* file-write* (subpath \"{tmp_s}\"))\n"
        ));
    }
    if !home_s.is_empty() {
        p.push_str(&format!(
            "(deny file-read* file-write* (subpath \"{home_s}/.ssh\") (subpath \"{home_s}/.aws\") (subpath \"{home_s}/.gnupg\") (subpath \"{home_s}/.config/gh\") (subpath \"{home_s}/.local/state/agent-guard\"))\n"
        ));
    }
    if invokes_swarm_tool {
        if let Ok(sdir) = crate::breadcrumbs::swarm_state_dir(&canon_repo) {
            for sub in ["ipc", "sessions", "spools", "ledger"] {
                let sp = sdir.join(sub).to_string_lossy().replace('"', "\\\"");
                p.push_str(&format!(
                    "(allow file-read* file-write* (subpath \"{sp}\"))\n"
                ));
            }
            let vp = sdir.join("vault").to_string_lossy().replace('"', "\\\"");
            p.push_str(&format!(
                "(deny file-read* file-write* (subpath \"{vp}\"))\n"
            ));
        }
        if let Ok(locks_dir) = crate::breadcrumbs::swarm_locks_dir() {
            let lp = locks_dir.to_string_lossy().replace('"', "\\\"");
            p.push_str(&format!(
                "(allow file-read* file-write* (subpath \"{lp}\"))\n"
            ));
        }
    } else {
        p.push_str(&format!(
            "(deny file-write* (literal \"{repo_s}/PLAN.lock.json\") (literal \"{repo_s}/WORK_LEDGER.jsonl\") (literal \"{repo_s}/.breadcrumbs.jsonl\"))\n"
        ));
    }
    p.push_str(&format!(
        "(deny file-read* file-write* (regex #\"/\\.env($|\\.)\") (regex #\"\\.(pem|key|p12|pfx)$\") (regex #\"/audit\\.jsonl$\") (subpath \"{repo_s}/.git/hooks\"))\n"
    ));
    p.push_str(&format!(
        "(deny file-write* (literal \"{repo_s}/AGENTS.md\") (literal \"{repo_s}/.git/config\") (subpath \"{repo_s}/.claude\") (subpath \"{repo_s}/.codex\") (subpath \"{repo_s}/.cursor\") (subpath \"{repo_s}/.github\") (subpath \"{repo_s}/.cargo\") (literal \"{repo_s}/.gitattributes\") (literal \"{repo_s}/.npmrc\"))\n"
    ));
    p
}
