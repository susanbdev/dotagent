//! Zero-friction operator commands: `doctor`, `session-reset`, `activate`, and `deactivate`.
//!
//! Designed for instant diagnostic visibility and non-destructive onboarding while keeping
//! security boundaries strictly fail-closed:
//! - `doctor`: 7-check live health & enforcement report (`--json` supported).
//! - `session-reset`: Interactive human-TTY-only circuit-breaker reset (hard-blocked in pipes and sandboxes).
//! - `activate` / `deactivate`: Non-destructive workspace & global harness activation with `.dotagent.bak`
//!   backups, JSON user-preference preservation, absolute hook binary path pinning for GUI IDEs,
//!   `bash` + `zsh` (`~/.zshenv`) `PATH` setup, 19-key Git lockdown, and target-workspace `audit-repo`.

use std::fs;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::budget_guard::load_active_profile;
use crate::coordinator::{coordinator_socket_path, ping_coordinator};
use crate::exec_sandbox::probe_host_sandbox_mode;
use crate::json::JsonValue;
use crate::qa_suspects::plan_lock_state_path;
use crate::traversal_ledger::{SessionLedger, compute_session_key_hash, state_base_dir};
use crate::{audit_repository, resolve_repo_root, verify_global_git_hardening};

const REQUIRED_GIT_SETTINGS: &[(&str, &str)] = &[
    ("core.hooksPath", "/dev/null"),
    ("core.attributesFile", "/dev/null"),
    ("core.fsmonitor", "false"),
    ("core.pager", "cat"),
    ("core.symlinks", "false"),
    ("core.autocrlf", "input"),
    ("core.protectHFS", "true"),
    ("core.protectNTFS", "true"),
    ("gc.auto", "0"),
    ("protocol.allow", "never"),
    ("protocol.https.allow", "always"),
    ("protocol.file.allow", "never"),
    ("protocol.ext.allow", "never"),
    ("protocol.git.allow", "never"),
    ("submodule.recurse", "false"),
    ("submodule.fetchJobs", "0"),
    ("transfer.fsckObjects", "true"),
    ("fetch.fsckObjects", "true"),
    ("receive.fsckObjects", "true"),
];

const AGENT_MD_FILES: &[&str] = &[
    "research-airlock.md",
    "swarm-master.md",
    "swarm-investigator.md",
    "swarm-qa-engineer.md",
    "swarm-grunt.md",
    "swarm-adversarial-reviewer.md",
    "swarm-forensic-coroner.md",
];

#[derive(Debug, Clone)]
struct DoctorCheck {
    name: &'static str,
    ok: bool,
    detail: String,
}

pub fn run_doctor_cli(args: &[String], cwd: &Path) -> ExitCode {
    let json_mode = args.iter().any(|a| a == "--json");
    let target_dir = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(PathBuf::from)
        .unwrap_or_else(|| resolve_repo_root(cwd));

    let mut checks = Vec::with_capacity(7);

    // 1. Binary integrity & 0555 permissions check
    checks.push(check_binaries_health());

    // 2. OS Kernel VFS + TCP sandbox readiness
    let sbx_mode = probe_host_sandbox_mode();
    checks.push(DoctorCheck {
        name: "kernel_sandbox",
        ok: true,
        detail: format!(
            "mode={} kernel_enforced={} (use --require-kernel in CI/production to mandate kernel VFS isolation)",
            sbx_mode.as_str(),
            sbx_mode.is_kernel_enforced()
        ),
    });

    // 3. Global Git 19-key lockdown
    match verify_global_git_hardening() {
        Ok(()) => checks.push(DoctorCheck {
            name: "global_git_lockdown",
            ok: true,
            detail: "all 19 global git hardening keys enforced (hooks=/dev/null, https-only, fsckObjects=true)".to_string(),
        }),
        Err(e) => checks.push(DoctorCheck {
            name: "global_git_lockdown",
            ok: false,
            detail: format!("{e} (remediation: run `dotagent activate`)"),
        }),
    }

    // 4. Repository hygiene & root authority audit
    match audit_repository(&target_dir) {
        Ok(passed) => checks.push(DoctorCheck {
            name: "repository_audit",
            ok: true,
            detail: format!(
                "clean ({} audit invariants verified on '{}')",
                passed.len(),
                target_dir.display()
            ),
        }),
        Err(errs) => checks.push(DoctorCheck {
            name: "repository_audit",
            ok: false,
            detail: errs.join("; "),
        }),
    }

    // 5. Runtime profile validation
    match load_active_profile(&target_dir) {
        Ok(prof) => checks.push(DoctorCheck {
            name: "runtime_profile",
            ok: true,
            detail: format!(
                "profile='{}' writes={} net_none={} max_turn_tokens={}",
                prof.profile_id,
                prof.enable_write_tools,
                prof.network_access_none,
                prof.max_turn_tokens
            ),
        }),
        Err(bv) => checks.push(DoctorCheck {
            name: "runtime_profile",
            ok: false,
            detail: format!("{}: {}", bv.code, bv.detail),
        }),
    }

    // 6. State directory & active session circuit-breaker health
    checks.push(check_session_state_health(&target_dir));

    // 7. Swarm coordinator & plan lock status (informational)
    let plan_locked = plan_lock_state_path(&target_dir)
        .map(|p| p.is_file())
        .unwrap_or(false);
    let coord_live = ping_coordinator(&target_dir);
    let sock_display = coordinator_socket_path(&target_dir)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unavailable>".to_string());
    checks.push(DoctorCheck {
        name: "swarm_coordinator",
        ok: true,
        detail: format!(
            "plan_locked={plan_locked} coordinator_live={coord_live} sock='{sock_display}'"
        ),
    });

    let all_ok = checks.iter().all(|c| c.ok);
    if json_mode {
        let items: Vec<JsonValue> = checks
            .iter()
            .map(|c| {
                JsonValue::Object(vec![
                    ("check".to_string(), JsonValue::Str(c.name.to_string())),
                    ("ok".to_string(), JsonValue::Bool(c.ok)),
                    ("detail".to_string(), JsonValue::Str(c.detail.clone())),
                ])
            })
            .collect();
        let report = JsonValue::Object(vec![
            ("healthy".to_string(), JsonValue::Bool(all_ok)),
            (
                "workspace".to_string(),
                JsonValue::Str(target_dir.display().to_string()),
            ),
            ("checks".to_string(), JsonValue::Array(items)),
        ]);
        println!("{}", report.to_json_string());
    } else {
        println!(
            "dotagent doctor {} - workspace '{}'",
            env!("CARGO_PKG_VERSION"),
            target_dir.display()
        );
        for c in &checks {
            let tag = if c.ok { "[PASS]" } else { "[FAIL]" };
            println!("  {tag} {:<22} {}", c.name, c.detail);
        }
        if all_ok {
            println!("Result: HEALTHY (all required zero-trust controls verified)");
        } else {
            eprintln!(
                "Result: UNHEALTHY (one or more required security controls failed; run `dotagent explain <CODE>` for guidance)"
            );
        }
    }

    if all_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

fn check_binaries_health() -> DoctorCheck {
    let exe_info = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    if let Ok(home) = std::env::var("HOME") {
        let bin_dir = PathBuf::from(home).join(".local/bin");
        let mut present = Vec::new();
        let mut writable = Vec::new();
        for name in ["agent-guard", "dotagent-compiler", "swarm-tool", "dotagent"] {
            let p = bin_dir.join(name);
            if let Ok(meta) = fs::symlink_metadata(&p) {
                if meta.file_type().is_symlink() {
                    return DoctorCheck {
                        name: "binary_integrity",
                        ok: false,
                        detail: format!("installed binary '{}' must not be a symlink", p.display()),
                    };
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = meta.permissions().mode() & 0o777;
                    if mode & 0o222 != 0 {
                        writable.push(format!("{name}({mode:04o})"));
                    }
                }
                present.push(name);
            }
        }
        if !writable.is_empty() {
            return DoctorCheck {
                name: "binary_integrity",
                ok: false,
                detail: format!(
                    "installed binaries in ~/.local/bin are writable (expected 0555): {}",
                    writable.join(", ")
                ),
            };
        }
        if !present.is_empty() {
            return DoctorCheck {
                name: "binary_integrity",
                ok: true,
                detail: format!(
                    "installed 0555 binaries=[{}] (active_exe='{}')",
                    present.join(", "),
                    exe_info
                ),
            };
        }
    }
    DoctorCheck {
        name: "binary_integrity",
        ok: true,
        detail: format!(
            "running from '{}' (~/.local/bin not yet populated)",
            exe_info
        ),
    }
}

fn check_session_state_health(repo_root: &Path) -> DoctorCheck {
    let base = state_base_dir();
    if let Ok(meta) = fs::symlink_metadata(&base)
        && meta.file_type().is_symlink()
    {
        return DoctorCheck {
            name: "session_state",
            ok: false,
            detail: format!("state directory '{}' is a symlink", base.display()),
        };
    }
    let sid = std::env::var("AGENT_GUARD_SESSION_ID").unwrap_or_else(|_| "default".to_string());
    let key_hash = compute_session_key_hash(repo_root, &sid);
    let session_file = base.join("sessions").join(format!("{key_hash}.json"));
    if !session_file.exists() {
        return DoctorCheck {
            name: "session_state",
            ok: true,
            detail: format!("clean (session='{sid}', no active halts)"),
        };
    }
    let ledger = SessionLedger::load_or_create(repo_root, &sid);
    if ledger.halted {
        DoctorCheck {
            name: "session_state",
            ok: false,
            detail: format!(
                "SESSION_CIRCUIT_BREAKER_TRIPPED on session '{sid}': {} (run `dotagent session-reset` from a human TTY)",
                ledger.halt_reason.as_deref().unwrap_or("halted")
            ),
        }
    } else {
        DoctorCheck {
            name: "session_state",
            ok: true,
            detail: format!(
                "healthy (session='{sid}', tainted={}, tokens={}, reads={}, calls={})",
                ledger.tainted, ledger.cumulative_tokens, ledger.file_reads, ledger.tool_calls
            ),
        }
    }
}

/// Interactive human-TTY-gated circuit breaker reset (`dotagent session-reset [--session <id>] [--all]`).
pub fn run_session_reset_cli(args: &[String], cwd: &Path) -> ExitCode {
    if std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() == Ok("1")
        || std::env::var("AGENT_GUARD_WORKER_LOCK").as_deref() == Ok("1")
    {
        eprintln!(
            "[AGENT-GUARD HARD DENY :: SESSION_RESET_DENIED_IN_SANDBOX] session-reset cannot be invoked from inside exec-sandbox or a locked worker."
        );
        return ExitCode::from(2);
    }

    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        eprintln!(
            "[AGENT-GUARD HARD DENY :: SESSION_RESET_REQUIRES_HUMAN_TTY] session-reset requires an interactive human terminal (stdin/stdout TTY) so AI agents cannot self-clear circuit breakers."
        );
        return ExitCode::from(2);
    }

    let repo_root = resolve_repo_root(cwd);
    let reset_all = args.iter().any(|a| a == "--all");
    let mut explicit_sid: Option<String> = None;
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == "--session" {
            explicit_sid = args.get(i + 1).cloned();
            i += 2;
        } else {
            i += 1;
        }
    }

    if reset_all {
        let sessions_dir = state_base_dir().join("sessions");
        let mut removed = 0usize;
        if let Ok(entries) = fs::read_dir(&sessions_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().is_some_and(|e| e == "json") && fs::remove_file(&p).is_ok() {
                    removed += 1;
                }
            }
        }
        println!(
            "[AGENT-GUARD SESSION RESET] Cleared {removed} session ledger file(s) from interactive human TTY."
        );
        return ExitCode::SUCCESS;
    }

    let sid = explicit_sid
        .or_else(|| std::env::var("AGENT_GUARD_SESSION_ID").ok())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "default".to_string());

    let _lock = SessionLedger::acquire_lock(&repo_root, &sid);
    let key_hash = compute_session_key_hash(&repo_root, &sid);
    let session_file = state_base_dir()
        .join("sessions")
        .join(format!("{key_hash}.json"));
    if session_file.exists()
        && let Err(e) = fs::remove_file(&session_file)
    {
        eprintln!(
            "[AGENT-GUARD] failed removing session state '{}': {e}",
            session_file.display()
        );
        return ExitCode::from(2);
    }
    let fresh = SessionLedger::new(&repo_root, &sid);
    if let Err(e) = fresh.save(&repo_root) {
        eprintln!("[AGENT-GUARD] failed writing fresh session state: {e}");
        return ExitCode::from(2);
    }
    println!(
        "[AGENT-GUARD SESSION RESET] Reset halted/tainted state and rotated 128-bit spotlight nonce for session '{sid}' on '{}'.",
        repo_root.display()
    );
    ExitCode::SUCCESS
}

pub fn run_activate_cli(args: &[String], cwd: &Path) -> ExitCode {
    let mut workspace: Option<PathBuf> = None;
    let mut dotagent_root: Option<PathBuf> = None;
    let mut bin_dir: Option<PathBuf> = None;
    let mut dry_run = false;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--workspace" | "-w" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[activate] missing path after --workspace");
                    return ExitCode::from(2);
                };
                workspace = Some(PathBuf::from(v));
                i += 2;
            }
            "--dotagent-root" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[activate] missing path after --dotagent-root");
                    return ExitCode::from(2);
                };
                dotagent_root = Some(PathBuf::from(v));
                i += 2;
            }
            "--bin-dir" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[activate] missing path after --bin-dir");
                    return ExitCode::from(2);
                };
                bin_dir = Some(PathBuf::from(v));
                i += 2;
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            other if !other.starts_with('-') && workspace.is_none() => {
                workspace = Some(PathBuf::from(other));
                i += 1;
            }
            other => {
                eprintln!("[activate] unrecognized argument '{other}'");
                return ExitCode::from(2);
            }
        }
    }

    let Ok(home_raw) = std::env::var("HOME") else {
        eprintln!("[activate] HARD DENY: HOME environment variable is not set");
        return ExitCode::from(2);
    };
    let home = PathBuf::from(home_raw);
    let resolved_bin_dir = bin_dir.unwrap_or_else(|| home.join(".local/bin"));
    let resolved_dotagent = match dotagent_root.or_else(|| locate_dotagent_bundle_root(cwd)) {
        Some(p) => p,
        None => {
            eprintln!(
                "[activate] HARD DENY: could not locate dotagent dist/ bundle (pass --dotagent-root <path>)"
            );
            return ExitCode::from(2);
        }
    };
    let target_ws = workspace.unwrap_or_else(|| home.clone());

    match execute_activate(
        &home,
        &resolved_bin_dir,
        &resolved_dotagent,
        &target_ws,
        dry_run,
    ) {
        Ok(summary) => {
            for line in summary {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("[activate] HARD DENY: {err}");
            ExitCode::from(2)
        }
    }
}

pub fn run_deactivate_cli(args: &[String], _cwd: &Path) -> ExitCode {
    let mut workspace: Option<PathBuf> = None;
    let mut dry_run = false;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--workspace" | "-w" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[deactivate] missing path after --workspace");
                    return ExitCode::from(2);
                };
                workspace = Some(PathBuf::from(v));
                i += 2;
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            other if !other.starts_with('-') && workspace.is_none() => {
                workspace = Some(PathBuf::from(other));
                i += 1;
            }
            other => {
                eprintln!("[deactivate] unrecognized argument '{other}'");
                return ExitCode::from(2);
            }
        }
    }

    let Ok(home_raw) = std::env::var("HOME") else {
        eprintln!("[deactivate] HARD DENY: HOME is not set");
        return ExitCode::from(2);
    };
    let home = PathBuf::from(home_raw);
    let target_ws = workspace.unwrap_or_else(|| home.clone());

    match execute_deactivate(&home, &target_ws, dry_run) {
        Ok(lines) => {
            for l in lines {
                println!("{l}");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("[deactivate] HARD DENY: {err}");
            ExitCode::from(2)
        }
    }
}

fn locate_dotagent_bundle_root(cwd: &Path) -> Option<PathBuf> {
    let candidate = resolve_repo_root(cwd);
    if candidate.join("dist/AGENTS.md").is_file()
        && candidate.join("dist-verify/manifest.sha256").is_file()
    {
        return Some(candidate);
    }
    None
}

fn reject_if_symlink(path: &Path, label: &str) -> Result<(), String> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(format!("refusing symlinked {label} '{}'", path.display()));
    }
    Ok(())
}

fn backup_path_for(target: &Path) -> PathBuf {
    let mut os = target.as_os_str().to_os_string();
    os.push(".dotagent.bak");
    PathBuf::from(os)
}

/// Preserves a pre-existing user file into `<file>.dotagent.bak` once (never overwriting an
/// existing `.dotagent.bak` on repeated idempotent `activate` runs) whenever its bytes differ
/// from `new_bytes`.
fn write_with_nondestructive_backup(
    target: &Path,
    new_bytes: &[u8],
    mode: u32,
    use_cp_semantics: bool,
    dry_run: bool,
    log: &mut Vec<String>,
) -> Result<(), String> {
    reject_if_symlink(target, "target")?;
    let bak = backup_path_for(target);
    reject_if_symlink(&bak, "backup file")?;

    if target.is_file()
        && let Ok(existing) = fs::read(target)
        && existing != new_bytes
        && !bak.exists()
    {
        if dry_run {
            log.push(format!(
                "[dry-run] would back up '{}' -> '{}'",
                target.display(),
                bak.display()
            ));
        } else {
            fs::write(&bak, &existing).map_err(|e| {
                format!(
                    "failed backing up '{}' to '{}': {e}",
                    target.display(),
                    bak.display()
                )
            })?;
            log.push(format!(
                "[backup] saved pre-existing '{}' -> '{}'",
                target.display(),
                bak.display()
            ));
        }
    }

    if dry_run {
        log.push(format!(
            "[dry-run] would deploy '{}' (mode {:04o}, {} bytes)",
            target.display(),
            mode,
            new_bytes.len()
        ));
        return Ok(());
    }

    if use_cp_semantics {
        // FUSE / virtiofs persistent mounts (like ~/.gemini) may disallow chmod; write in place cleanly.
        fs::write(target, new_bytes)
            .map_err(|e| format!("failed writing '{}': {e}", target.display()))?;
    } else {
        if target.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(target, fs::Permissions::from_mode(0o600));
            }
            let _ = fs::remove_file(target);
        }
        fs::write(target, new_bytes)
            .map_err(|e| format!("failed writing '{}': {e}", target.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(target, fs::Permissions::from_mode(mode)).map_err(|e| {
                format!(
                    "failed setting mode {:04o} on '{}': {e}",
                    mode,
                    target.display()
                )
            })?;
        }
    }
    Ok(())
}

/// Rewrites bare `"agent-guard ..."` hook commands to `"<abs_guard_bin> ..."` when deploying
/// outside the canonical `dotagent` source repo so GUI IDEs (Cursor, VS Code, Claude Desktop)
/// that do not source interactive shell rc files still execute `agent-guard` deterministically
/// and cannot be hijacked via mutable `PATH` entries.
fn pin_hook_binary_in_json(val: &JsonValue, abs_guard_bin: Option<&Path>) -> JsonValue {
    let Some(bin) = abs_guard_bin else {
        return val.clone();
    };
    let bin_str = bin.to_string_lossy();
    // Only pin if path contains no shell-special quotes/spaces that could break hook command splitting
    if !bin_str
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.'))
    {
        return val.clone();
    }
    match val {
        JsonValue::Str(s) => {
            if let Some(rest) = s.strip_prefix("agent-guard ") {
                JsonValue::Str(format!("{bin_str} {rest}"))
            } else if s == "agent-guard" {
                JsonValue::Str(bin_str.into_owned())
            } else {
                JsonValue::Str(s.clone())
            }
        }
        JsonValue::Array(items) => JsonValue::Array(
            items
                .iter()
                .map(|v| pin_hook_binary_in_json(v, abs_guard_bin))
                .collect(),
        ),
        JsonValue::Object(entries) => JsonValue::Object(
            entries
                .iter()
                .map(|(k, v)| (k.clone(), pin_hook_binary_in_json(v, abs_guard_bin)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Merges `template_json` over an optional pre-existing `existing_json`, preserving harmless
/// user-specific top-level preferences (`theme`, `model`, `statusLine`, `preferredNotifChannel`, etc.)
/// while unconditionally enforcing `dotagent`'s security-critical keys (`hooks`, `permissions`,
/// `mcpServers`, `autoMemoryEnabled`, `context`, `tools`, `security`, `env`).
fn merge_settings_json_preserving_user_prefs(
    existing_raw: Option<&str>,
    template_raw: &str,
    abs_guard_bin: Option<&Path>,
) -> Result<String, String> {
    let template_parsed = JsonValue::parse(template_raw)
        .map_err(|e| format!("invalid dist settings JSON template: {e}"))?;
    let pinned_template = pin_hook_binary_in_json(&template_parsed, abs_guard_bin);
    let Some(template_obj) = pinned_template.as_object() else {
        return Ok(format!("{}\n", pinned_template.to_json_string()));
    };

    let mut merged: Vec<(String, JsonValue)> = Vec::new();
    if let Some(raw) = existing_raw
        && let Ok(existing_val) = JsonValue::parse(raw)
        && let Some(existing_obj) = existing_val.as_object()
    {
        for (k, v) in existing_obj {
            if !template_obj.iter().any(|(tk, _)| tk == k) {
                merged.push((k.clone(), v.clone()));
            }
        }
    }
    for (tk, tv) in template_obj {
        merged.push((tk.clone(), tv.clone()));
    }
    Ok(format!("{}\n", JsonValue::Object(merged).to_json_string()))
}

fn ensure_shell_rc_path(
    home: &Path,
    bin_dir: &Path,
    dry_run: bool,
    log: &mut Vec<String>,
) -> Result<(), String> {
    let snippet = "\n# dotagent zero-trust CLI PATH\nexport PATH=\"$HOME/.local/bin:$PATH\"\n";
    let default_local_bin = home.join(".local/bin");
    if bin_dir != default_local_bin {
        return Ok(());
    }
    for rc_name in [".bashrc", ".zshenv"] {
        let rc_path = home.join(rc_name);
        reject_if_symlink(&rc_path, rc_name)?;
        if rc_name == ".bashrc" && !rc_path.exists() {
            continue;
        }
        let existing = fs::read_to_string(&rc_path).unwrap_or_default();
        if existing.contains(".local/bin") {
            continue;
        }
        if dry_run {
            log.push(format!(
                "[dry-run] would add ~/.local/bin PATH export to '{}'",
                rc_path.display()
            ));
        } else {
            let mut updated = existing;
            updated.push_str(snippet);
            fs::write(&rc_path, updated)
                .map_err(|e| format!("failed updating '{}': {e}", rc_path.display()))?;
            log.push(format!(
                "[path] configured ~/.local/bin in '{}'",
                rc_path.display()
            ));
        }
    }
    Ok(())
}

fn enforce_global_git_settings(dry_run: bool, log: &mut Vec<String>) -> Result<(), String> {
    for &(key, expected) in REQUIRED_GIT_SETTINGS {
        let cur = Command::new("git")
            .args(["config", "--global", "--get", key])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        if cur != expected {
            if dry_run {
                log.push(format!(
                    "[dry-run] would set git config --global {key}={expected}"
                ));
                continue;
            }
            let st = Command::new("git")
                .args(["config", "--global", key, expected])
                .status()
                .map_err(|e| format!("failed running git config --global {key}: {e}"))?;
            if !st.success() {
                return Err(format!(
                    "git config --global {key}={expected} exited non-zero"
                ));
            }
        }
        if !dry_run {
            let verified = Command::new("git")
                .args(["config", "--global", "--get", key])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            if verified != expected {
                return Err(format!(
                    "failed to enforce git config --global {key}={expected} (got '{verified}')"
                ));
            }
        }
    }
    Ok(())
}

fn deploy_workspace_bundle(
    dotagent_root: &Path,
    target_root: &Path,
    mode: u32,
    is_external: bool,
    abs_guard_bin: Option<&Path>,
    dry_run: bool,
    log: &mut Vec<String>,
) -> Result<(), String> {
    let dirs = [
        target_root.to_path_buf(),
        target_root.join(".claude"),
        target_root.join(".claude/agents"),
        target_root.join(".cursor"),
        target_root.join(".cursor/agents"),
        target_root.join(".codex"),
        target_root.join(".codex/agents"),
    ];
    for d in &dirs {
        reject_if_symlink(d, "harness directory")?;
    }

    let mut check_targets = vec![
        target_root.join("AGENTS.md"),
        target_root.join(".ignore"),
        target_root.join(".cursorignore"),
        target_root.join(".claude/settings.json"),
        target_root.join(".cursor/hooks.json"),
        target_root.join(".codex/config.toml"),
    ];
    for af in AGENT_MD_FILES {
        check_targets.push(target_root.join(".claude/agents").join(af));
        check_targets.push(target_root.join(".cursor/agents").join(af));
        check_targets.push(target_root.join(".codex/agents").join(af));
    }
    for t in &check_targets {
        reject_if_symlink(t, "harness target")?;
    }

    if !dry_run {
        for sub in [".claude/agents", ".cursor/agents", ".codex/agents"] {
            fs::create_dir_all(target_root.join(sub)).map_err(|e| {
                format!("failed creating '{}': {e}", target_root.join(sub).display())
            })?;
        }
    }

    let copy_pairs: &[(&str, &str)] = &[
        ("dist/AGENTS.md", "AGENTS.md"),
        ("dist/.ignore", ".ignore"),
        ("dist/cursor/.cursorignore", ".cursorignore"),
        ("dist/codex/config.toml", ".codex/config.toml"),
    ];
    for &(src_rel, dst_rel) in copy_pairs {
        let bytes = fs::read(dotagent_root.join(src_rel))
            .map_err(|e| format!("missing '{}': {e}", src_rel))?;
        write_with_nondestructive_backup(
            &target_root.join(dst_rel),
            &bytes,
            mode,
            false,
            dry_run,
            log,
        )?;
    }

    // Claude settings.json: preserve custom user top-level preferences & pin absolute binary on external workspaces
    let claude_tpl = fs::read_to_string(dotagent_root.join("dist/claude/settings.json"))
        .map_err(|e| format!("missing dist/claude/settings.json: {e}"))?;
    let claude_dst = target_root.join(".claude/settings.json");
    let claude_bytes = if is_external {
        let existing_raw = fs::read_to_string(&claude_dst).ok();
        merge_settings_json_preserving_user_prefs(
            existing_raw.as_deref(),
            &claude_tpl,
            abs_guard_bin,
        )?
        .into_bytes()
    } else {
        claude_tpl.into_bytes()
    };
    write_with_nondestructive_backup(&claude_dst, &claude_bytes, mode, false, dry_run, log)?;

    // Cursor hooks.json: pin absolute binary on external workspaces so GUI Cursor finds agent-guard without ~/.bashrc
    let cursor_tpl = fs::read_to_string(dotagent_root.join("dist/cursor/hooks.json"))
        .map_err(|e| format!("missing dist/cursor/hooks.json: {e}"))?;
    let cursor_dst = target_root.join(".cursor/hooks.json");
    let cursor_bytes = if is_external && abs_guard_bin.is_some() {
        let parsed = JsonValue::parse(&cursor_tpl)
            .map_err(|e| format!("invalid dist/cursor/hooks.json: {e}"))?;
        format!(
            "{}\n",
            pin_hook_binary_in_json(&parsed, abs_guard_bin).to_json_string()
        )
        .into_bytes()
    } else {
        cursor_tpl.into_bytes()
    };
    write_with_nondestructive_backup(&cursor_dst, &cursor_bytes, mode, false, dry_run, log)?;

    for af in AGENT_MD_FILES {
        for (dist_sub, dst_sub) in [
            ("dist/claude/agents", ".claude/agents"),
            ("dist/cursor/agents", ".cursor/agents"),
            ("dist/codex/agents", ".codex/agents"),
        ] {
            let bytes = fs::read(dotagent_root.join(dist_sub).join(af))
                .map_err(|e| format!("missing '{dist_sub}/{af}': {e}"))?;
            write_with_nondestructive_backup(
                &target_root.join(dst_sub).join(af),
                &bytes,
                mode,
                false,
                dry_run,
                log,
            )?;
        }
    }

    Ok(())
}

fn execute_activate(
    home: &Path,
    bin_dir: &Path,
    dotagent_root: &Path,
    target_ws: &Path,
    dry_run: bool,
) -> Result<Vec<String>, String> {
    let mut log = Vec::new();
    reject_if_symlink(&dotagent_root.join("AGENTS.md"), "root AGENTS.md")?;

    // 1. State directory (0700) & shell PATH wiring (.bashrc + .zshenv)
    let state_sessions = home.join(".local/state/agent-guard/sessions");
    if !dry_run {
        fs::create_dir_all(&state_sessions)
            .map_err(|e| format!("failed creating '{}': {e}", state_sessions.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let state_root = home.join(".local/state/agent-guard");
            let _ = fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700));
            let _ = fs::set_permissions(&state_sessions, fs::Permissions::from_mode(0o700));
        }
    }
    ensure_shell_rc_path(home, bin_dir, dry_run, &mut log)?;

    // 2. Enforce all 19 global Git hardening keys (preserving user.name & user.email)
    enforce_global_git_settings(dry_run, &mut log)?;

    // Resolve installed absolute `agent-guard` binary path (falling back to current_exe if invoked standalone)
    let installed_guard = bin_dir.join("agent-guard");
    let fallback_exe = std::env::current_exe().ok().filter(|p| {
        p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == "agent-guard" || n == "dotagent")
    });
    let abs_guard_opt = if installed_guard.is_file() {
        Some(installed_guard.as_path())
    } else {
        fallback_exe.as_deref()
    };

    // 3. Deploy ~/.gemini global constitution, merged settings.json, and 7 subagents
    let gemini_dir = home.join(".gemini");
    let gemini_agents = gemini_dir.join("agents");
    for gp in [
        gemini_dir.clone(),
        gemini_agents.clone(),
        gemini_dir.join("GEMINI.md"),
        gemini_dir.join("settings.json"),
    ] {
        reject_if_symlink(&gp, "Gemini path")?;
    }
    if !dry_run {
        fs::create_dir_all(&gemini_agents)
            .map_err(|e| format!("failed creating '{}': {e}", gemini_agents.display()))?;
    }
    for af in AGENT_MD_FILES {
        let dst = gemini_agents.join(af);
        reject_if_symlink(&dst, "Gemini agent")?;
        let bytes = fs::read(dotagent_root.join("dist/gemini/agents").join(af))
            .map_err(|e| format!("missing dist/gemini/agents/{af}: {e}"))?;
        write_with_nondestructive_backup(&dst, &bytes, 0o644, true, dry_run, &mut log)?;
    }
    let gemini_md = fs::read(dotagent_root.join("dist/gemini/GEMINI.md"))
        .map_err(|e| format!("missing dist/gemini/GEMINI.md: {e}"))?;
    write_with_nondestructive_backup(
        &gemini_dir.join("GEMINI.md"),
        &gemini_md,
        0o644,
        true,
        dry_run,
        &mut log,
    )?;

    let gemini_settings_tpl = fs::read_to_string(dotagent_root.join("dist/gemini/settings.json"))
        .map_err(|e| format!("missing dist/gemini/settings.json: {e}"))?;
    let gemini_settings_dst = gemini_dir.join("settings.json");
    let existing_gemini = fs::read_to_string(&gemini_settings_dst).ok();
    let merged_gemini = merge_settings_json_preserving_user_prefs(
        existing_gemini.as_deref(),
        &gemini_settings_tpl,
        abs_guard_opt,
    )?;
    write_with_nondestructive_backup(
        &gemini_settings_dst,
        merged_gemini.as_bytes(),
        0o644,
        true,
        dry_run,
        &mut log,
    )?;

    // 4. Deploy canonical mirrors in dotagent_root (0644, unpinned so manifest SHA-256 stays exact)
    deploy_workspace_bundle(
        dotagent_root,
        dotagent_root,
        0o644,
        false,
        None,
        dry_run,
        &mut log,
    )?;

    // 5. Deploy external target_ws (0444 read-only control plane, non-destructive backups + pinned binary path)
    let canon_dotagent =
        fs::canonicalize(dotagent_root).unwrap_or_else(|_| dotagent_root.to_path_buf());
    let canon_target = fs::canonicalize(target_ws).unwrap_or_else(|_| target_ws.to_path_buf());
    if canon_target != canon_dotagent {
        deploy_workspace_bundle(
            dotagent_root,
            target_ws,
            0o444,
            true,
            abs_guard_opt,
            dry_run,
            &mut log,
        )?;
    }

    // 6. Live repository security audit on dotagent_root AND target_ws (if target_ws is a git repo)
    if !dry_run {
        if let Err(errs) = audit_repository(dotagent_root) {
            return Err(format!(
                "dotagent repository audit failed: {}",
                errs.join("; ")
            ));
        }
        if canon_target != canon_dotagent && target_ws.join(".git").exists() {
            if let Err(errs) = audit_repository(target_ws) {
                return Err(format!(
                    "target workspace '{}' failed security audit: {}",
                    target_ws.display(),
                    errs.join("; ")
                ));
            }
        }
    }

    log.push(format!(
        "[activate] Zero-trust guards, non-destructive backups, pinned GUI hooks, zsh/bash PATH, 19-key git lockdown, and read-only control plane active for '{}'.",
        target_ws.display()
    ));
    Ok(log)
}

fn execute_deactivate(home: &Path, target_ws: &Path, dry_run: bool) -> Result<Vec<String>, String> {
    let mut log = Vec::new();
    let mut managed = vec![
        target_ws.join("AGENTS.md"),
        target_ws.join(".ignore"),
        target_ws.join(".cursorignore"),
        target_ws.join(".claude/settings.json"),
        target_ws.join(".cursor/hooks.json"),
        target_ws.join(".codex/config.toml"),
        home.join(".gemini/GEMINI.md"),
        home.join(".gemini/settings.json"),
    ];
    for af in AGENT_MD_FILES {
        managed.push(target_ws.join(".claude/agents").join(af));
        managed.push(target_ws.join(".cursor/agents").join(af));
        managed.push(target_ws.join(".codex/agents").join(af));
        managed.push(home.join(".gemini/agents").join(af));
    }

    for target in managed {
        reject_if_symlink(&target, "managed file")?;
        let bak = backup_path_for(&target);
        reject_if_symlink(&bak, "backup file")?;

        if bak.is_file() {
            if dry_run {
                log.push(format!(
                    "[dry-run] would restore backup '{}' -> '{}'",
                    bak.display(),
                    target.display()
                ));
            } else {
                #[cfg(unix)]
                if target.exists() {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&target, fs::Permissions::from_mode(0o644));
                }
                let bytes = fs::read(&bak)
                    .map_err(|e| format!("failed reading backup '{}': {e}", bak.display()))?;
                fs::write(&target, bytes)
                    .map_err(|e| format!("failed restoring '{}': {e}", target.display()))?;
                let _ = fs::remove_file(&bak);
                log.push(format!(
                    "[restore] restored pre-existing '{}' from backup",
                    target.display()
                ));
            }
        } else if target.is_file() {
            #[cfg(unix)]
            let is_deployed_ro = {
                use std::os::unix::fs::PermissionsExt;
                fs::metadata(&target)
                    .map(|m| (m.permissions().mode() & 0o777) == 0o444)
                    .unwrap_or(false)
            };
            #[cfg(not(unix))]
            let is_deployed_ro = false;

            if is_deployed_ro {
                if dry_run {
                    log.push(format!(
                        "[dry-run] would remove deployed 0444 file '{}'",
                        target.display()
                    ));
                } else {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(&target, fs::Permissions::from_mode(0o600));
                    }
                    fs::remove_file(&target)
                        .map_err(|e| format!("failed removing '{}': {e}", target.display()))?;
                    log.push(format!("[remove] removed deployed '{}'", target.display()));
                }
            }
        }
    }

    log.push(format!(
        "[deactivate] Completed non-destructive deactivation for '{}'.",
        target_ws.display()
    ));
    Ok(log)
}
