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
use crate::traversal_ledger::{SessionLedger, state_base_dir};
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
    let allow_degraded = args.iter().any(|a| a == "--allow-degraded");
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
        ok: sbx_mode.is_kernel_enforced() || allow_degraded,
        detail: format!(
            "mode={} kernel_enforced={} allow_degraded={} (pass --allow-degraded to permit non-kernel environments)",
            sbx_mode.as_str(),
            sbx_mode.is_kernel_enforced(),
            allow_degraded
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
        for name in [
            "agent-guard",
            "agent-guard-sh",
            "dotagent-compiler",
            "swarm-tool",
            "dotagent",
        ] {
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
    let session_file = crate::traversal_ledger::session_ledger_path(repo_root, &sid);
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

fn consume_sshsig_once(pem: &str) -> Result<(), crate::sshsig_touch::GuardError> {
    use crate::breadcrumbs::ExclusiveFileLockGuard;
    use crate::sshsig_touch::GuardError;
    use std::io::Write as _;
    let (_, rest) = pem
        .split_once("-----BEGIN SSH SIGNATURE-----")
        .ok_or_else(|| GuardError::new("SSHSIG_MALFORMED", "missing BEGIN SSH SIGNATURE"))?;
    let (body_b64, _) = rest
        .split_once("-----END SSH SIGNATURE-----")
        .ok_or_else(|| GuardError::new("SSHSIG_MALFORMED", "missing END SSH SIGNATURE"))?;
    let wire_bytes = crate::crypto::base64_decode_clean(body_b64, 16_384)
        .map_err(|m| GuardError::new("SSHSIG_MALFORMED", m))?;
    let digest = crate::crypto::sha256_hex(&wire_bytes);
    let dir = crate::feedback::feedback_state_dir().map_err(|e| GuardError::new("SSHSIG_IO", e))?;
    let _lock = ExclusiveFileLockGuard::acquire(&dir.join("consumed_sshsig.lock"))
        .map_err(|e| GuardError::new("SSHSIG_IO", e))?;
    let log_path = dir.join("consumed_sshsig.log");
    let pre_meta = match fs::symlink_metadata(&log_path) {
        Ok(m) => {
            if m.file_type().is_symlink() || !m.file_type().is_file() {
                return Err(GuardError::new(
                    "SSHSIG_SYMLINK_TAMPER",
                    "consumed_sshsig.log is symlink or non-regular file",
                ));
            }
            Some(m)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(GuardError::new("SSHSIG_IO", e.to_string())),
    };
    let existing = crate::traversal_ledger::read_nonsymlink_state_file(&log_path)
        .map_err(|e| GuardError::new("SSHSIG_SYMLINK_TAMPER", e))?
        .unwrap_or_default();
    if existing.lines().any(|l| l.trim() == digest) {
        return Err(GuardError::new(
            "SSHSIG_REPLAY_DETECTED",
            "SSHSIG signature was already consumed",
        ));
    }
    let mut opts = fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos"
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(crate::traversal_ledger::O_NOFOLLOW_FLAG);
    }
    let mut f = opts
        .open(&log_path)
        .map_err(|e| GuardError::new("SSHSIG_SYMLINK_TAMPER", e.to_string()))?;
    let post_meta = f
        .metadata()
        .map_err(|e| GuardError::new("SSHSIG_IO", e.to_string()))?;
    if !post_meta.is_file() {
        return Err(GuardError::new(
            "SSHSIG_SYMLINK_TAMPER",
            "consumed_sshsig.log opened non-regular file",
        ));
    }
    #[cfg(unix)]
    if let Some(pm) = pre_meta {
        use std::os::unix::fs::MetadataExt;
        if pm.dev() != post_meta.dev() || pm.ino() != post_meta.ino() {
            return Err(GuardError::new(
                "SSHSIG_SYMLINK_TAMPER",
                "consumed_sshsig.log inode changed during open",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = pre_meta;
    writeln!(f, "{digest}")
        .and_then(|()| f.sync_all())
        .map_err(|e| GuardError::new("SSHSIG_IO", e.to_string()))
}

pub(crate) fn verify_plugin_human_touch(
    repo_root: &Path,
    session_id: &str,
    tool_name: &str,
    target_rel_paths: &[String],
) -> bool {
    use crate::coordinator::current_hmac_epoch_id;
    use crate::sshsig_touch::{load_operator_sk_keys_from_home, verify_fido2_sshsig_ed25519};
    use crate::stop_receipt::derive_portable_repo_id;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Ok(sig_path_raw) = std::env::var("AGENT_GUARD_PLUGIN_SSHSIG") else {
        return false;
    };
    let sig_path = Path::new(&sig_path_raw);
    let Ok(meta) = fs::symlink_metadata(sig_path) else {
        return false;
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() || meta.len() > 16_384 {
        return false;
    }
    let Ok(pem) = fs::read_to_string(sig_path) else {
        return false;
    };
    let Ok(home_raw) = std::env::var("HOME") else {
        return false;
    };
    let Ok(Some(keys)) = load_operator_sk_keys_from_home(Path::new(&home_raw)) else {
        return false;
    };
    let canon = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let repo_id = derive_portable_repo_id(&canon);
    let epoch_id = current_hmac_epoch_id(&canon).unwrap_or(0);
    let paths_hash = &crate::crypto::sha256_hex(target_rel_paths.join("\0").as_bytes())[..16];
    let now_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let floor_now = (now_s / 60) * 60;
    let c0 = format!(
        "dotagent:plugin-touch:v1:{repo_id}:{epoch_id}:{session_id}:{tool_name}:{paths_hash}:{floor_now}"
    );
    let c1 = format!(
        "dotagent:plugin-touch:v1:{repo_id}:{epoch_id}:{session_id}:{tool_name}:{paths_hash}:{}",
        floor_now.saturating_sub(60)
    );
    let verified =
        verify_fido2_sshsig_ed25519("dotagent-plugin-touch-v1", c0.as_bytes(), &pem, &keys)
            .or_else(|_| {
                verify_fido2_sshsig_ed25519("dotagent-plugin-touch-v1", c1.as_bytes(), &pem, &keys)
            })
            .is_ok();
    verified && consume_sshsig_once(&pem).is_ok()
}

pub(crate) fn verify_operator_sshsig_gate(
    repo_root: &Path,
    action: &str,
    sshsig_file: Option<&Path>,
) -> Result<(), crate::sshsig_touch::GuardError> {
    use crate::coordinator::current_hmac_epoch_id;
    use crate::sshsig_touch::{
        GuardError, OPERATOR_SSHSIG_NAMESPACE, format_operator_challenge,
        load_operator_sk_keys_from_home, verify_fido2_sshsig_ed25519,
    };
    use crate::stop_receipt::derive_portable_repo_id;
    use std::io::Read as _;
    use std::time::{SystemTime, UNIX_EPOCH};

    let home_raw = std::env::var("HOME")
        .map_err(|_| GuardError::new("SSHSIG_CONFIG_INVALID", "HOME is not set"))?;
    let Some(keys) = load_operator_sk_keys_from_home(Path::new(&home_raw))? else {
        return Ok(());
    };
    let canon = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let repo_id = derive_portable_repo_id(&canon);
    let epoch_id = current_hmac_epoch_id(&canon).unwrap_or(0);
    let now_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let floor_now = (now_s / 60) * 60;
    let c0 = format_operator_challenge(action, &repo_id, epoch_id, floor_now);
    let pem = if let Some(p) = sshsig_file {
        let m = fs::symlink_metadata(p).map_err(|e| {
            GuardError::new("SSHSIG_REQUIRED", format!("cannot stat --sshsig: {e}"))
        })?;
        if m.file_type().is_symlink() || !m.file_type().is_file() || m.len() > 16_384 {
            return Err(GuardError::new(
                "SSHSIG_MALFORMED",
                "--sshsig must be a regular file <= 16 KiB",
            ));
        }
        fs::read_to_string(p).map_err(|e| GuardError::new("SSHSIG_IO", e.to_string()))?
    } else if io::stdin().is_terminal() {
        eprintln!(
            "[DOTAGENT FIDO2 TOUCH] Paste SSHSIG for challenge '{c0}' (namespace='{OPERATOR_SSHSIG_NAMESPACE}'):"
        );
        let mut buf = String::new();
        io::stdin()
            .take(16_384)
            .read_to_string(&mut buf)
            .map_err(|e| GuardError::new("SSHSIG_IO", e.to_string()))?;
        buf
    } else {
        return Err(GuardError::new(
            "SSHSIG_REQUIRED",
            format!("operator_sk_keys configured; pass --sshsig <file> over challenge '{c0}'"),
        ));
    };
    let c1 = format_operator_challenge(action, &repo_id, epoch_id, floor_now.saturating_sub(60));
    verify_fido2_sshsig_ed25519(OPERATOR_SSHSIG_NAMESPACE, c0.as_bytes(), &pem, &keys).or_else(
        |_| verify_fido2_sshsig_ed25519(OPERATOR_SSHSIG_NAMESPACE, c1.as_bytes(), &pem, &keys),
    )?;
    consume_sshsig_once(&pem)
}

/// Interactive human-TTY-gated circuit breaker reset (`dotagent session-reset [--session <id>] [--sshsig <file>] [--all]`).
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
    let mut sshsig_file: Option<PathBuf> = None;
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == "--session" {
            explicit_sid = args.get(i + 1).cloned();
            i += 2;
        } else if args[i] == "--sshsig" {
            sshsig_file = args.get(i + 1).map(PathBuf::from);
            i += 2;
        } else {
            i += 1;
        }
    }

    if let Err(ge) =
        verify_operator_sshsig_gate(&repo_root, "session-reset", sshsig_file.as_deref())
    {
        eprintln!("[AGENT-GUARD HARD DENY :: {}] {}", ge.code, ge.detail);
        return ExitCode::from(2);
    }

    if reset_all {
        let sessions_dir = state_base_dir();
        let mut removed = 0usize;
        if let Ok(entries) = fs::read_dir(&sessions_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().is_some_and(|e| e == "json") && fs::remove_file(&p).is_ok() {
                    removed += 1;
                }
            }
        }
        let mut upgrade_notes = Vec::new();
        let _ = invalidate_or_purge_swarm_state(&repo_root, true, false, &mut upgrade_notes);
        for note in upgrade_notes {
            println!("{note}");
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
    let session_file = crate::traversal_ledger::session_ledger_path(&repo_root, &sid);
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
    if let Err(e) = fresh.save_locked(&repo_root) {
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
    if std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() == Ok("1")
        || std::env::var("AGENT_GUARD_WORKER_LOCK").as_deref() == Ok("1")
    {
        eprintln!(
            "[AGENT-GUARD HARD DENY :: ACTIVATE_DENIED_IN_SANDBOX] activate cannot be invoked from inside exec-sandbox or a locked worker."
        );
        return ExitCode::from(2);
    }
    let mut workspace: Option<PathBuf> = None;
    let mut dotagent_root: Option<PathBuf> = None;
    let mut bin_dir: Option<PathBuf> = None;
    let mut dry_run = false;
    let mut antigravity_only = false;
    let mut workspace_only = false;

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
            "--antigravity" => {
                antigravity_only = true;
                workspace_only = true;
                i += 1;
            }
            "--workspace-only" => {
                workspace_only = true;
                i += 1;
            }
            "--scope" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[activate] missing value after --scope (expected workspace|all)");
                    return ExitCode::from(2);
                };
                match v.as_str() {
                    "workspace" => workspace_only = true,
                    "all" => workspace_only = false,
                    other => {
                        eprintln!(
                            "[activate] unsupported --scope '{other}' (expected workspace|all)"
                        );
                        return ExitCode::from(2);
                    }
                }
                i += 2;
            }
            "--target" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[activate] missing value after --target (expected antigravity|all)");
                    return ExitCode::from(2);
                };
                match v.as_str() {
                    "antigravity" => {
                        antigravity_only = true;
                        workspace_only = true;
                    }
                    "all" => antigravity_only = false,
                    other => {
                        eprintln!(
                            "[activate] unsupported --target '{other}' (expected antigravity|all)"
                        );
                        return ExitCode::from(2);
                    }
                }
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

    let resolved_dotagent = match dotagent_root.or_else(|| locate_dotagent_bundle_root(cwd)) {
        Some(p) => p,
        None => {
            eprintln!(
                "[activate] HARD DENY: could not locate dotagent dist/ bundle (pass --dotagent-root <path>)"
            );
            return ExitCode::from(2);
        }
    };

    if antigravity_only {
        let resolved_bin_dir = match bin_dir {
            Some(b) => b,
            None => std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".local/bin"))
                .unwrap_or_else(|_| PathBuf::from(".local/bin")),
        };
        let target_ws = workspace.unwrap_or_else(|| resolve_repo_root(cwd));
        return match execute_antigravity_activate(
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
        };
    }

    if workspace_only {
        let resolved_bin_dir = match bin_dir {
            Some(b) => b,
            None => std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".local/bin"))
                .unwrap_or_else(|_| PathBuf::from(".local/bin")),
        };
        let target_ws = workspace.unwrap_or_else(|| resolve_repo_root(cwd));
        return match activate_workspace_scoped_all(
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
        };
    }

    let Ok(home_raw) = std::env::var("HOME") else {
        eprintln!("[activate] HARD DENY: HOME environment variable is not set");
        return ExitCode::from(2);
    };
    let home = PathBuf::from(home_raw);
    let resolved_bin_dir = bin_dir.unwrap_or_else(|| home.join(".local/bin"));
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

pub fn run_deactivate_cli(args: &[String], cwd: &Path) -> ExitCode {
    if std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() == Ok("1")
        || std::env::var("AGENT_GUARD_WORKER_LOCK").as_deref() == Ok("1")
    {
        eprintln!(
            "[AGENT-GUARD HARD DENY :: DEACTIVATE_DENIED_IN_SANDBOX] deactivate cannot be invoked from inside exec-sandbox or a locked worker."
        );
        return ExitCode::from(2);
    }

    let mut workspace: Option<PathBuf> = None;
    let mut sshsig_file: Option<PathBuf> = None;
    let mut dry_run = false;
    let mut antigravity_only = false;
    let mut workspace_only = false;
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
            "--sshsig" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[deactivate] missing path after --sshsig");
                    return ExitCode::from(2);
                };
                sshsig_file = Some(PathBuf::from(v));
                i += 2;
            }
            "--antigravity" => {
                antigravity_only = true;
                workspace_only = true;
                i += 1;
            }
            "--workspace-only" => {
                workspace_only = true;
                i += 1;
            }
            "--scope" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[deactivate] missing value after --scope (expected workspace|all)");
                    return ExitCode::from(2);
                };
                match v.as_str() {
                    "workspace" => workspace_only = true,
                    "all" => workspace_only = false,
                    other => {
                        eprintln!(
                            "[deactivate] unsupported --scope '{other}' (expected workspace|all)"
                        );
                        return ExitCode::from(2);
                    }
                }
                i += 2;
            }
            "--target" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!(
                        "[deactivate] missing value after --target (expected antigravity|all)"
                    );
                    return ExitCode::from(2);
                };
                match v.as_str() {
                    "antigravity" => {
                        antigravity_only = true;
                        workspace_only = true;
                    }
                    "all" => antigravity_only = false,
                    other => {
                        eprintln!(
                            "[deactivate] unsupported --target '{other}' (expected antigravity|all)"
                        );
                        return ExitCode::from(2);
                    }
                }
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
    for marker in [
        "CLAUDECODE",
        "GEMINI_CLI",
        "ANTIGRAVITY_AGENT",
        "CURSOR_TRACE_ID",
        "CODEX_SANDBOX",
    ] {
        if std::env::var(marker)
            .ok()
            .is_some_and(|v| !v.trim().is_empty())
        {
            eprintln!(
                "[AGENT-GUARD HARD DENY :: DEACTIVATE_DENIED_IN_HARNESS] deactivate cannot be invoked from inside AI agent harness '{marker}'."
            );
            return ExitCode::from(2);
        }
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        eprintln!(
            "[AGENT-GUARD HARD DENY :: DEACTIVATE_REQUIRES_HUMAN_TTY] deactivate requires an interactive human terminal (stdin/stdout TTY)."
        );
        return ExitCode::from(2);
    }

    let target_ws = workspace.unwrap_or_else(|| {
        if antigravity_only || workspace_only {
            resolve_repo_root(cwd)
        } else {
            home.clone()
        }
    });
    let repo_root = resolve_repo_root(if target_ws != home { &target_ws } else { cwd });

    if let Err(ge) = verify_operator_sshsig_gate(&repo_root, "deactivate", sshsig_file.as_deref()) {
        eprintln!("[AGENT-GUARD HARD DENY :: {}] {}", ge.code, ge.detail);
        return ExitCode::from(2);
    }

    let res = if antigravity_only {
        execute_antigravity_deactivate(&target_ws, dry_run)
    } else if workspace_only {
        execute_workspace_only_deactivate(&target_ws, dry_run)
    } else {
        execute_deactivate(&home, &target_ws, dry_run)
    };

    match res {
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

    if is_external {
        deploy_antigravity_workspace_plane(
            dotagent_root,
            target_root,
            abs_guard_bin,
            mode,
            dry_run,
            log,
        )?;
    }

    Ok(())
}

pub(crate) fn execute_activate(
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

    // 6. Explicitly invalidate any pre-v2 unprefixed HMAC swarm state on upgrade
    invalidate_or_purge_swarm_state(dotagent_root, false, dry_run, &mut log)?;
    if canon_target != canon_dotagent {
        invalidate_or_purge_swarm_state(target_ws, false, dry_run, &mut log)?;
    }

    // 7. Live repository security audit on dotagent_root AND target_ws (if target_ws is a git repo)
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

/// Deploys the `0444` read-only control plane + swarm state invalidation + repository security audit
/// onto a single external workspace without touching `$HOME` or `dotagent_root`, enabling safe
/// multi-threaded `dotagent fleet sync` across sibling repositories.
pub(crate) fn activate_external_workspace_only(
    bin_dir: &Path,
    dotagent_root: &Path,
    target_ws: &Path,
    dry_run: bool,
) -> Result<Vec<String>, String> {
    let mut log = Vec::new();
    let canon_dotagent =
        fs::canonicalize(dotagent_root).unwrap_or_else(|_| dotagent_root.to_path_buf());
    let canon_target = fs::canonicalize(target_ws).unwrap_or_else(|_| target_ws.to_path_buf());
    if canon_target == canon_dotagent {
        return Ok(log);
    }

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

    deploy_workspace_bundle(
        dotagent_root,
        target_ws,
        0o444,
        true,
        abs_guard_opt,
        dry_run,
        &mut log,
    )?;
    invalidate_or_purge_swarm_state(target_ws, false, dry_run, &mut log)?;
    if !dry_run && target_ws.join(".git").exists() {
        if let Err(errs) = audit_repository(target_ws) {
            return Err(format!(
                "target workspace '{}' failed security audit: {}",
                target_ws.display(),
                errs.join("; ")
            ));
        }
    }
    Ok(log)
}

fn invalidate_or_purge_swarm_state(
    repo_root: &Path,
    force_purge_sessions: bool,
    dry_run: bool,
    log: &mut Vec<String>,
) -> Result<(), String> {
    let Ok(sdir) = crate::breadcrumbs::swarm_state_dir(repo_root) else {
        return Ok(());
    };
    let key_path = sdir.join("vault/hmac.key");
    let fmt_path = sdir.join("vault/hmac.format");
    let is_legacy_v1 = key_path.is_file()
        && fs::read_to_string(&fmt_path)
            .map(|s| !s.contains("bijective-v2"))
            .unwrap_or(true);

    if !is_legacy_v1 && !force_purge_sessions {
        return Ok(());
    }
    if dry_run {
        if is_legacy_v1 {
            log.push(format!(
                "[dry-run] would invalidate pre-v2 HMAC swarm state for '{}'",
                repo_root.display()
            ));
        }
        return Ok(());
    }

    let subdirs: &[&str] = if is_legacy_v1 {
        &["sessions", "spools", "ledger"]
    } else {
        &["sessions"]
    };
    let mut cleared = 0usize;
    for sub in subdirs {
        let dir = sdir.join(sub);
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() && fs::remove_file(&p).is_ok() {
                    cleared += 1;
                }
            }
        }
    }

    if is_legacy_v1 {
        for repo_file in ["WORK_LEDGER.jsonl", ".breadcrumbs.jsonl"] {
            let fp = repo_root.join(repo_file);
            if let Ok(meta) = fs::symlink_metadata(&fp)
                && meta.file_type().is_file()
            {
                let bak = repo_root.join(format!("{repo_file}.v1.bak"));
                if !bak.exists() {
                    let _ = fs::rename(&fp, &bak);
                } else {
                    let _ = fs::remove_file(&fp);
                }
                cleared += 1;
            }
        }
        if let Some(vault_dir) = fmt_path.parent() {
            let _ = fs::create_dir_all(vault_dir);
        }
        let _ = fs::write(&fmt_path, b"bijective-v2\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&fmt_path, fs::Permissions::from_mode(0o600));
        }
        log.push(format!(
            "[upgrade] invalidated {cleared} pre-v2 HMAC swarm artifact(s) for '{}' and enabled bijective-v2 format",
            repo_root.display()
        ));
    }
    Ok(())
}

pub fn execute_deactivate(
    home: &Path,
    target_ws: &Path,
    dry_run: bool,
) -> Result<Vec<String>, String> {
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

    let mut log = deactivate_managed_list(&managed, dry_run)?;
    let ag_lines = execute_antigravity_deactivate(target_ws, dry_run)?;
    log.extend(ag_lines);
    log.push(format!(
        "[deactivate] Completed non-destructive deactivation for '{}'.",
        target_ws.display()
    ));
    Ok(log)
}

pub fn execute_workspace_only_deactivate(
    target_ws: &Path,
    dry_run: bool,
) -> Result<Vec<String>, String> {
    let mut managed = vec![
        target_ws.join("AGENTS.md"),
        target_ws.join(".ignore"),
        target_ws.join(".cursorignore"),
        target_ws.join(".claude/settings.json"),
        target_ws.join(".cursor/hooks.json"),
        target_ws.join(".codex/config.toml"),
    ];
    for af in AGENT_MD_FILES {
        managed.push(target_ws.join(".claude/agents").join(af));
        managed.push(target_ws.join(".cursor/agents").join(af));
        managed.push(target_ws.join(".codex/agents").join(af));
    }
    let mut log = deactivate_managed_list(&managed, dry_run)?;
    let ag_lines = execute_antigravity_deactivate(target_ws, dry_run)?;
    log.extend(ag_lines);
    log.push(format!(
        "[deactivate] Completed workspace-only deactivation for '{}'.",
        target_ws.display()
    ));
    Ok(log)
}

fn deactivate_managed_list(managed: &[PathBuf], dry_run: bool) -> Result<Vec<String>, String> {
    let mut log = Vec::new();
    for target in managed {
        reject_if_symlink(target, "managed file")?;
        let bak = backup_path_for(target);
        reject_if_symlink(&bak, "backup file")?;

        if let Ok(bmeta) = fs::symlink_metadata(&bak) {
            if !bmeta.file_type().is_file() {
                return Err(format!(
                    "refusing unexpected non-regular backup object '{}'",
                    bak.display()
                ));
            }
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
                    let _ = fs::set_permissions(target, fs::Permissions::from_mode(0o600));
                }
                let bytes = fs::read(&bak)
                    .map_err(|e| format!("failed reading backup '{}': {e}", bak.display()))?;
                fs::write(target, bytes)
                    .map_err(|e| format!("failed restoring '{}': {e}", target.display()))?;
                #[cfg(unix)]
                {
                    let _ = fs::set_permissions(target, bmeta.permissions());
                }
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
                fs::metadata(target)
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
                        let _ = fs::set_permissions(target, fs::Permissions::from_mode(0o600));
                    }
                    fs::remove_file(target)
                        .map_err(|e| format!("failed removing '{}': {e}", target.display()))?;
                    log.push(format!("[remove] removed deployed '{}'", target.display()));
                }
            }
        }
    }
    Ok(log)
}

/// Documented Antigravity workspace customization directory names (`https://antigravity.google/docs/customization-discovery/`).
pub const ANTIGRAVITY_CUSTOMIZATION_DIRS: &[&str] = &[".agents", ".agent", "_agents", "_agent"];

fn is_safe_unquoted_path_str(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.'))
}

fn validate_existing_regular_dir_lstat(path: &Path, label: &str) -> Result<(), String> {
    let meta = fs::symlink_metadata(path)
        .map_err(|e| format!("{label} '{}' does not exist: {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!("refusing symlinked {label} '{}'", path.display()));
    }
    if !meta.file_type().is_dir() {
        return Err(format!(
            "refusing unexpected non-directory object at {label} '{}'",
            path.display()
        ));
    }
    Ok(())
}

fn validate_optional_dir_lstat(path: &Path, label: &str) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("cannot stat {label} '{}': {e}", path.display())),
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(format!("refusing symlinked {label} '{}'", path.display()));
            }
            if !meta.file_type().is_dir() {
                return Err(format!(
                    "refusing unexpected non-directory filesystem object at {label} '{}'",
                    path.display()
                ));
            }
            Ok(true)
        }
    }
}

fn validate_optional_regular_file_lstat(
    path: &Path,
    label: &str,
) -> Result<Option<fs::Metadata>, String> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot stat {label} '{}': {e}", path.display())),
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(format!("refusing symlinked {label} '{}'", path.display()));
            }
            if !meta.file_type().is_file() {
                return Err(format!(
                    "refusing unexpected non-regular filesystem object at {label} '{}'",
                    path.display()
                ));
            }
            Ok(Some(meta))
        }
    }
}

/// Detects the supported Antigravity customization directory inside `target_ws` without following symlinks.
pub fn detect_antigravity_workspace_dir(target_ws: &Path) -> Result<PathBuf, String> {
    validate_existing_regular_dir_lstat(target_ws, "target workspace")?;

    let mut existing_dirs = Vec::new();
    for cand in ANTIGRAVITY_CUSTOMIZATION_DIRS {
        let p = target_ws.join(cand);
        if validate_optional_dir_lstat(&p, "Antigravity customization directory")? {
            existing_dirs.push(p);
        }
    }

    if existing_dirs.is_empty() {
        return Ok(target_ws.join(".agents"));
    }
    if existing_dirs.len() == 1 {
        return Ok(existing_dirs.remove(0));
    }

    let mut with_hooks = Vec::new();
    for d in &existing_dirs {
        let hp = d.join("hooks.json");
        if validate_optional_regular_file_lstat(&hp, "existing Antigravity hooks.json")?.is_some() {
            with_hooks.push(d.clone());
        }
    }
    if with_hooks.len() > 1 {
        return Err(format!(
            "ambiguous Antigravity customization layout in '{}': multiple customization directories contain hooks.json",
            target_ws.display()
        ));
    }
    if with_hooks.len() == 1 {
        return Ok(with_hooks.remove(0));
    }

    let preferred = target_ws.join(".agents");
    if existing_dirs.iter().any(|d| d == &preferred) {
        return Ok(preferred);
    }
    Err(format!(
        "ambiguous Antigravity customization directories in '{}'; consolidate onto '.agents'",
        target_ws.display()
    ))
}

fn verify_guard_binary_path(candidate: &Path) -> Result<PathBuf, String> {
    let abs = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("cannot resolve current_dir for guard binary: {e}"))?
            .join(candidate)
    };
    if let Some(parent) = abs.parent() {
        validate_existing_regular_dir_lstat(parent, "guard binary directory")?;
    }
    let Some(meta) = validate_optional_regular_file_lstat(&abs, "agent-guard binary")? else {
        return Err(format!(
            "verified agent-guard binary not found at '{}'",
            abs.display()
        ));
    };
    if meta.len() == 0 {
        return Err(format!("agent-guard binary '{}' is empty", abs.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o111 == 0 {
            return Err(format!(
                "agent-guard binary '{}' is not executable (mode {:04o})",
                abs.display(),
                mode
            ));
        }
        if mode & 0o002 != 0 {
            return Err(format!(
                "refusing world-writable agent-guard binary '{}' (mode {:04o})",
                abs.display(),
                mode
            ));
        }
    }
    let abs_s = abs.to_string_lossy();
    if !is_safe_unquoted_path_str(&abs_s) {
        return Err(format!(
            "agent-guard binary path '{}' contains unsafe shell characters",
            abs.display()
        ));
    }
    Ok(abs)
}

fn resolve_verified_guard_binary(bin_dir: &Path) -> Result<PathBuf, String> {
    let primary = bin_dir.join("agent-guard");
    if fs::symlink_metadata(&primary).is_ok() {
        return verify_guard_binary_path(&primary);
    }
    let secondary = bin_dir.join("dotagent");
    if fs::symlink_metadata(&secondary).is_ok() {
        return verify_guard_binary_path(&secondary);
    }
    if let Ok(cur_exe) = std::env::current_exe()
        && cur_exe
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == "agent-guard" || n == "dotagent")
    {
        return verify_guard_binary_path(&cur_exe);
    }
    Err(format!(
        "verified 'agent-guard' binary not found in '{}' (build and install binaries first or pass --bin-dir <dir>)",
        bin_dir.display()
    ))
}

type AntigravityDistBundle = (String, Vec<(&'static str, Vec<u8>)>);

fn verify_dist_antigravity_sources(dotagent_root: &Path) -> Result<AntigravityDistBundle, String> {
    validate_existing_regular_dir_lstat(dotagent_root, "dotagent bundle root")?;
    let dist_dir = dotagent_root.join("dist");
    validate_existing_regular_dir_lstat(&dist_dir, "dist directory")?;
    let ag_dist = dist_dir.join("antigravity");
    validate_existing_regular_dir_lstat(&ag_dist, "dist/antigravity directory")?;
    let ag_agents_dist = ag_dist.join("agents");
    validate_existing_regular_dir_lstat(&ag_agents_dist, "dist/antigravity/agents directory")?;

    let manifest_path = dotagent_root.join("dist-verify/manifest.sha256");
    let mut expected_hashes = std::collections::BTreeMap::new();
    if let Some(_mmeta) =
        validate_optional_regular_file_lstat(&manifest_path, "dist-verify/manifest.sha256")?
    {
        let raw_manifest = fs::read_to_string(&manifest_path)
            .map_err(|e| format!("failed reading '{}': {e}", manifest_path.display()))?;
        for line in raw_manifest.lines() {
            let mut parts = line.split_whitespace();
            if let (Some(h), Some(rel)) = (parts.next(), parts.next()) {
                expected_hashes.insert(rel.to_string(), h.to_string());
            }
        }
    }

    let hooks_rel = "dist/antigravity/hooks.json";
    let hooks_path = dotagent_root.join(hooks_rel);
    if validate_optional_regular_file_lstat(&hooks_path, hooks_rel)?.is_none() {
        return Err(format!("missing bundle artifact '{hooks_rel}'"));
    }
    let hooks_bytes =
        fs::read(&hooks_path).map_err(|e| format!("failed reading '{hooks_rel}': {e}"))?;
    if !expected_hashes.is_empty() {
        let Some(exp) = expected_hashes.get(hooks_rel) else {
            return Err(format!(
                "bundle manifest missing required SHA-256 entry for '{hooks_rel}'"
            ));
        };
        let actual = crate::crypto::sha256_hex(&hooks_bytes);
        if &actual != exp {
            return Err(format!(
                "bundle integrity mismatch on '{hooks_rel}': expected {exp}, got {actual}"
            ));
        }
    }
    let hooks_tpl =
        String::from_utf8(hooks_bytes).map_err(|_| format!("non-UTF-8 bytes in '{hooks_rel}'"))?;

    let mut agent_blobs = Vec::with_capacity(AGENT_MD_FILES.len());
    for &af in AGENT_MD_FILES {
        let rel = format!("dist/antigravity/agents/{af}");
        let p = dotagent_root.join(&rel);
        if validate_optional_regular_file_lstat(&p, &rel)?.is_none() {
            return Err(format!("missing bundle artifact '{rel}'"));
        }
        let bytes = fs::read(&p).map_err(|e| format!("failed reading '{rel}': {e}"))?;
        if !expected_hashes.is_empty() {
            let Some(exp) = expected_hashes.get(&rel) else {
                return Err(format!(
                    "bundle manifest missing required SHA-256 entry for '{rel}'"
                ));
            };
            let actual = crate::crypto::sha256_hex(&bytes);
            if &actual != exp {
                return Err(format!(
                    "bundle integrity mismatch on '{rel}': expected {exp}, got {actual}"
                ));
            }
        }
        agent_blobs.push((af, bytes));
    }

    Ok((hooks_tpl, agent_blobs))
}

fn format_json_pretty_2space(val: &JsonValue, indent: usize, out: &mut String) {
    let pad = "  ".repeat(indent);
    let child_pad = "  ".repeat(indent + 1);
    match val {
        JsonValue::Object(entries) => {
            if entries.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{\n");
            for (idx, (k, v)) in entries.iter().enumerate() {
                out.push_str(&child_pad);
                out.push_str(&JsonValue::Str(k.clone()).to_json_string());
                out.push_str(": ");
                format_json_pretty_2space(v, indent + 1, out);
                if idx + 1 < entries.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push('}');
        }
        JsonValue::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (idx, item) in items.iter().enumerate() {
                out.push_str(&child_pad);
                format_json_pretty_2space(item, indent + 1, out);
                if idx + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push(']');
        }
        other => out.push_str(&other.to_json_string()),
    }
}

fn pin_antigravity_command_tree(
    val: &JsonValue,
    abs_guard_bin: Option<&Path>,
    abs_workspace: Option<&Path>,
) -> JsonValue {
    let Some(bin) = abs_guard_bin else {
        return val.clone();
    };
    let bin_s = bin.to_string_lossy();
    if !is_safe_unquoted_path_str(&bin_s) {
        return val.clone();
    }
    let ws_suffix = abs_workspace
        .map(|w| w.to_string_lossy().into_owned())
        .filter(|s| is_safe_unquoted_path_str(s))
        .map(|s| format!(" --workspace {s}"))
        .unwrap_or_default();

    match val {
        JsonValue::Str(s) => {
            if let Some(rest) = s.strip_prefix("agent-guard antigravity-hook ") {
                JsonValue::Str(format!("{bin_s} antigravity-hook {rest}{ws_suffix}"))
            } else if let Some(rest) = s.strip_prefix("agent-guard ") {
                JsonValue::Str(format!("{bin_s} {rest}"))
            } else if s == "agent-guard" {
                JsonValue::Str(bin_s.into_owned())
            } else {
                JsonValue::Str(s.clone())
            }
        }
        JsonValue::Array(items) => JsonValue::Array(
            items
                .iter()
                .map(|v| pin_antigravity_command_tree(v, abs_guard_bin, abs_workspace))
                .collect(),
        ),
        JsonValue::Object(entries) => JsonValue::Object(
            entries
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        pin_antigravity_command_tree(v, abs_guard_bin, abs_workspace),
                    )
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Merges `dist/antigravity/hooks.json` into an optional pre-existing `.agents/hooks.json` without
/// discarding unrelated user hook groups, while pinning the verified `agent-guard` binary path.
pub fn merge_antigravity_hooks_json(
    existing_raw: Option<&str>,
    template_raw: &str,
    abs_guard_bin: Option<&Path>,
    abs_workspace: Option<&Path>,
) -> Result<String, String> {
    let template_parsed = JsonValue::parse(template_raw)
        .map_err(|e| format!("invalid dist/antigravity/hooks.json template: {e}"))?;
    let pinned_template =
        pin_antigravity_command_tree(&template_parsed, abs_guard_bin, abs_workspace);
    let Some(template_obj) = pinned_template.as_object() else {
        return Err("dist/antigravity/hooks.json root must be a JSON object".to_string());
    };

    let mut merged: Vec<(String, JsonValue)> = Vec::new();
    if let Some(raw) = existing_raw {
        let existing_val = JsonValue::parse(raw).map_err(|e| {
            format!("existing Antigravity hooks.json is malformed JSON (refusing destructive overwrite): {e}")
        })?;
        let Some(existing_obj) = existing_val.as_object() else {
            return Err(
                "existing Antigravity hooks.json root must be a JSON object (refusing destructive overwrite)"
                    .to_string(),
            );
        };
        for (k, v) in existing_obj {
            if !template_obj.iter().any(|(tk, _)| tk == k) {
                merged.push((k.clone(), v.clone()));
            }
        }
    }
    for (tk, tv) in template_obj {
        merged.push((tk.clone(), tv.clone()));
    }

    let mut pretty = String::new();
    format_json_pretty_2space(&JsonValue::Object(merged), 0, &mut pretty);
    pretty.push('\n');
    Ok(pretty)
}

#[derive(Default)]
struct RollbackJournal {
    created_dirs: Vec<PathBuf>,
    created_files: Vec<PathBuf>,
    created_backups: Vec<PathBuf>,
    overwritten_files: Vec<(PathBuf, Vec<u8>, Option<u32>)>,
}

impl RollbackJournal {
    fn rollback(&mut self) {
        for (path, orig_bytes, orig_mode) in self.overwritten_files.drain(..).rev() {
            #[cfg(unix)]
            if path.exists() {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
            }
            let _ = fs::write(&path, orig_bytes);
            #[cfg(unix)]
            if let Some(m) = orig_mode {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(m));
            }
        }
        for path in self.created_files.drain(..).rev() {
            #[cfg(unix)]
            if path.exists() {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
            }
            let _ = fs::remove_file(&path);
        }
        for bak in self.created_backups.drain(..).rev() {
            #[cfg(unix)]
            if bak.exists() {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&bak, fs::Permissions::from_mode(0o600));
            }
            let _ = fs::remove_file(&bak);
        }
        for dir in self.created_dirs.drain(..).rev() {
            let _ = fs::remove_dir(&dir);
        }
    }
}

fn write_transactional_file_with_backup(
    target: &Path,
    new_bytes: &[u8],
    default_new_mode: u32,
    preserve_existing_mode: bool,
    journal: &mut RollbackJournal,
    log: &mut Vec<String>,
) -> Result<(), String> {
    let existing_meta = validate_optional_regular_file_lstat(target, "target file")?;
    let bak = backup_path_for(target);
    let existing_bak = validate_optional_regular_file_lstat(&bak, "backup file")?;

    #[cfg(unix)]
    let orig_mode = existing_meta.as_ref().map(|m| {
        use std::os::unix::fs::PermissionsExt;
        m.permissions().mode() & 0o777
    });
    #[cfg(not(unix))]
    let orig_mode: Option<u32> = None;

    let effective_mode = if preserve_existing_mode {
        orig_mode.map(|m| m | 0o400).unwrap_or(default_new_mode)
    } else {
        default_new_mode
    };

    if let Some(_meta) = &existing_meta {
        let existing_bytes =
            fs::read(target).map_err(|e| format!("failed reading '{}': {e}", target.display()))?;
        if existing_bytes == new_bytes {
            return Ok(());
        }
        if existing_bak.is_none() {
            fs::write(&bak, &existing_bytes).map_err(|e| {
                format!(
                    "failed backing up '{}' to '{}': {e}",
                    target.display(),
                    bak.display()
                )
            })?;
            #[cfg(unix)]
            if let Some(m) = orig_mode {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&bak, fs::Permissions::from_mode(m)).map_err(|e| {
                    format!(
                        "failed preserving mode {:04o} on backup '{}': {e}",
                        m,
                        bak.display()
                    )
                })?;
            }
            journal.created_backups.push(bak.clone());
            log.push(format!(
                "[backup] saved pre-existing '{}' -> '{}'",
                target.display(),
                bak.display()
            ));
        }
        journal
            .overwritten_files
            .push((target.to_path_buf(), existing_bytes, orig_mode));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(target, fs::Permissions::from_mode(0o600));
        }
    } else {
        journal.created_files.push(target.to_path_buf());
    }

    fs::write(target, new_bytes)
        .map_err(|e| format!("failed writing '{}': {e}", target.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(target, fs::Permissions::from_mode(effective_mode)).map_err(|e| {
            format!(
                "failed setting mode {:04o} on '{}': {e}",
                effective_mode,
                target.display()
            )
        })?;
    }
    log.push(format!(
        "[deploy] installed '{}' (mode {:04o}, {} bytes)",
        target.display(),
        effective_mode,
        new_bytes.len()
    ));
    Ok(())
}

fn deploy_antigravity_workspace_plane(
    dotagent_root: &Path,
    target_ws: &Path,
    abs_guard_bin: Option<&Path>,
    default_new_mode: u32,
    dry_run: bool,
    log: &mut Vec<String>,
) -> Result<(), String> {
    let (hooks_tpl, agent_blobs) = verify_dist_antigravity_sources(dotagent_root)?;
    let verified_bin = match abs_guard_bin {
        Some(p) => Some(verify_guard_binary_path(p)?),
        None => None,
    };
    let abs_ws = if target_ws.is_absolute() {
        target_ws.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("cannot resolve current_dir: {e}"))?
            .join(target_ws)
    };

    let ag_dir = detect_antigravity_workspace_dir(&abs_ws)?;
    let ag_agents_dir = ag_dir.join("agents");
    let ag_dir_exists = validate_optional_dir_lstat(&ag_dir, "Antigravity directory")?;
    let ag_agents_exists =
        validate_optional_dir_lstat(&ag_agents_dir, "Antigravity agents directory")?;

    let hooks_dst = ag_dir.join("hooks.json");
    let hooks_bak = backup_path_for(&hooks_dst);
    let existing_hooks_meta =
        validate_optional_regular_file_lstat(&hooks_dst, "Antigravity hooks.json")?;
    let _ = validate_optional_regular_file_lstat(&hooks_bak, "Antigravity hooks.json backup")?;

    for &(af, _) in &agent_blobs {
        let dst = ag_agents_dir.join(af);
        let bak = backup_path_for(&dst);
        let _ = validate_optional_regular_file_lstat(&dst, "Antigravity agent file")?;
        let _ = validate_optional_regular_file_lstat(&bak, "Antigravity agent backup")?;
    }

    let existing_hooks_raw = if existing_hooks_meta.is_some() {
        Some(
            fs::read_to_string(&hooks_dst)
                .map_err(|e| format!("failed reading '{}': {e}", hooks_dst.display()))?,
        )
    } else {
        None
    };

    let merged_hooks = merge_antigravity_hooks_json(
        existing_hooks_raw.as_deref(),
        &hooks_tpl,
        verified_bin.as_deref(),
        if verified_bin.is_some() {
            Some(abs_ws.as_path())
        } else {
            None
        },
    )?;

    if dry_run {
        if !ag_dir_exists {
            log.push(format!(
                "[dry-run] would create directory '{}'",
                ag_dir.display()
            ));
        }
        if !ag_agents_exists {
            log.push(format!(
                "[dry-run] would create directory '{}'",
                ag_agents_dir.display()
            ));
        }
        if existing_hooks_raw
            .as_deref()
            .is_some_and(|old| old != merged_hooks)
            && !hooks_bak.exists()
        {
            log.push(format!(
                "[dry-run] would back up '{}' -> '{}'",
                hooks_dst.display(),
                hooks_bak.display()
            ));
        }
        log.push(format!(
            "[dry-run] would deploy '{}' ({} bytes)",
            hooks_dst.display(),
            merged_hooks.len()
        ));
        for &(af, ref bytes) in &agent_blobs {
            let dst = ag_agents_dir.join(af);
            log.push(format!(
                "[dry-run] would deploy '{}' ({} bytes)",
                dst.display(),
                bytes.len()
            ));
        }
        return Ok(());
    }

    let mut journal = RollbackJournal::default();
    let tx_res = (|| -> Result<(), String> {
        if !ag_dir_exists {
            fs::create_dir(&ag_dir)
                .map_err(|e| format!("failed creating '{}': {e}", ag_dir.display()))?;
            journal.created_dirs.push(ag_dir.clone());
        }
        if !ag_agents_exists {
            fs::create_dir(&ag_agents_dir)
                .map_err(|e| format!("failed creating '{}': {e}", ag_agents_dir.display()))?;
            journal.created_dirs.push(ag_agents_dir.clone());
        }

        write_transactional_file_with_backup(
            &hooks_dst,
            merged_hooks.as_bytes(),
            default_new_mode,
            true,
            &mut journal,
            log,
        )?;

        for &(af, ref bytes) in &agent_blobs {
            let dst = ag_agents_dir.join(af);
            write_transactional_file_with_backup(
                &dst,
                bytes,
                default_new_mode,
                true,
                &mut journal,
                log,
            )?;
        }
        Ok(())
    })();

    if let Err(err) = tx_res {
        journal.rollback();
        return Err(err);
    }
    Ok(())
}

/// Standalone workspace-scoped Antigravity activation:
/// - Requires ZERO global Git config changes, ZERO shell startup edits, and ZERO `~/.gemini` mutations.
/// - Verifies `agent-guard` binary integrity & pins its absolute path in `<workspace>/.agents/hooks.json`.
/// - Preserves unrelated user hooks, creates `.dotagent.bak` backups with preserved permissions,
///   validates non-symlink object types via `lstat`, and rolls back completely on partial failure.
pub fn execute_antigravity_activate(
    bin_dir: &Path,
    dotagent_root: &Path,
    target_ws: &Path,
    dry_run: bool,
) -> Result<Vec<String>, String> {
    validate_existing_regular_dir_lstat(target_ws, "target workspace")?;
    let verified_guard = resolve_verified_guard_binary(bin_dir)?;

    let ws_audit_failures = crate::antigravity_adapter::audit_workspace_scoped(target_ws);
    if !ws_audit_failures.is_empty() {
        return Err(format!(
            "target workspace '{}' failed security pre-check: {}",
            target_ws.display(),
            ws_audit_failures.join("; ")
        ));
    }

    let mut log = Vec::new();
    deploy_antigravity_workspace_plane(
        dotagent_root,
        target_ws,
        Some(verified_guard.as_path()),
        0o444,
        dry_run,
        &mut log,
    )?;

    log.push(format!(
        "[activate] Workspace-scoped Antigravity hooks active for '{}' (pinned binary='{}', global config untouched).",
        target_ws.display(),
        verified_guard.display()
    ));
    Ok(log)
}

fn activate_workspace_scoped_all(
    bin_dir: &Path,
    dotagent_root: &Path,
    target_ws: &Path,
    dry_run: bool,
) -> Result<Vec<String>, String> {
    validate_existing_regular_dir_lstat(target_ws, "target workspace")?;
    let verified_guard = resolve_verified_guard_binary(bin_dir)?;
    let mut log = Vec::new();
    deploy_workspace_bundle(
        dotagent_root,
        target_ws,
        0o444,
        true,
        Some(verified_guard.as_path()),
        dry_run,
        &mut log,
    )?;
    invalidate_or_purge_swarm_state(target_ws, false, dry_run, &mut log)?;
    if !dry_run {
        let failures = crate::antigravity_adapter::audit_workspace_scoped(target_ws);
        if !failures.is_empty() {
            return Err(format!(
                "target workspace '{}' failed workspace-scoped security audit: {}",
                target_ws.display(),
                failures.join("; ")
            ));
        }
    }
    log.push(format!(
        "[activate] Workspace-scoped harness bundle active for '{}' (global config untouched).",
        target_ws.display()
    ));
    Ok(log)
}

/// Reversible workspace-scoped Antigravity deactivation:
/// - Restores `.dotagent.bak` files with original permissions where backups exist.
/// - Removes only `"dotagent-guard"` if unrelated user hooks exist in `hooks.json` without a backup.
/// - Removes deployed Antigravity files and cleans empty `.agents/agents` / `.agents` directories
///   without touching unrelated user files.
pub fn execute_antigravity_deactivate(
    target_ws: &Path,
    dry_run: bool,
) -> Result<Vec<String>, String> {
    validate_existing_regular_dir_lstat(target_ws, "target workspace")?;
    let ag_dir = detect_antigravity_workspace_dir(target_ws)?;
    if !validate_optional_dir_lstat(&ag_dir, "Antigravity customization directory")? {
        return Ok(vec![format!(
            "[deactivate] No Antigravity customization directory present in '{}'.",
            target_ws.display()
        )]);
    }

    let mut log = Vec::new();
    let hooks_path = ag_dir.join("hooks.json");
    let hooks_bak = backup_path_for(&hooks_path);
    let hooks_meta = validate_optional_regular_file_lstat(&hooks_path, "Antigravity hooks.json")?;
    let hooks_bak_meta =
        validate_optional_regular_file_lstat(&hooks_bak, "Antigravity hooks.json backup")?;

    if let Some(bmeta) = hooks_bak_meta {
        if dry_run {
            log.push(format!(
                "[dry-run] would restore '{}' -> '{}'",
                hooks_bak.display(),
                hooks_path.display()
            ));
        } else {
            #[cfg(unix)]
            if hooks_meta.is_some() {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&hooks_path, fs::Permissions::from_mode(0o600));
            }
            let bytes = fs::read(&hooks_bak)
                .map_err(|e| format!("failed reading '{}': {e}", hooks_bak.display()))?;
            fs::write(&hooks_path, bytes)
                .map_err(|e| format!("failed restoring '{}': {e}", hooks_path.display()))?;
            #[cfg(unix)]
            {
                fs::set_permissions(&hooks_path, bmeta.permissions()).map_err(|e| {
                    format!(
                        "failed restoring permissions on '{}': {e}",
                        hooks_path.display()
                    )
                })?;
            }
            fs::remove_file(&hooks_bak)
                .map_err(|e| format!("failed removing backup '{}': {e}", hooks_bak.display()))?;
            log.push(format!(
                "[restore] restored pre-existing '{}' from backup",
                hooks_path.display()
            ));
        }
    } else if let Some(hmeta) = hooks_meta {
        let raw = fs::read_to_string(&hooks_path)
            .map_err(|e| format!("failed reading '{}': {e}", hooks_path.display()))?;
        let parsed = JsonValue::parse(&raw).map_err(|e| {
            format!(
                "cannot safely deactivate malformed '{}': {e}",
                hooks_path.display()
            )
        })?;
        let Some(entries) = parsed.as_object() else {
            return Err(format!(
                "cannot safely deactivate non-object '{}'",
                hooks_path.display()
            ));
        };
        let has_dotagent = entries.iter().any(|(k, _)| k == "dotagent-guard");
        if has_dotagent {
            let remaining: Vec<(String, JsonValue)> = entries
                .iter()
                .filter(|(k, _)| k != "dotagent-guard")
                .cloned()
                .collect();
            if remaining.is_empty() {
                if dry_run {
                    log.push(format!(
                        "[dry-run] would remove deployed '{}'",
                        hooks_path.display()
                    ));
                } else {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(&hooks_path, fs::Permissions::from_mode(0o600));
                    }
                    fs::remove_file(&hooks_path)
                        .map_err(|e| format!("failed removing '{}': {e}", hooks_path.display()))?;
                    log.push(format!(
                        "[remove] removed deployed '{}'",
                        hooks_path.display()
                    ));
                }
            } else if dry_run {
                log.push(format!(
                    "[dry-run] would remove 'dotagent-guard' entry from '{}' while preserving {} user hook(s)",
                    hooks_path.display(),
                    remaining.len()
                ));
            } else {
                let mut updated = String::new();
                format_json_pretty_2space(&JsonValue::Object(remaining), 0, &mut updated);
                updated.push('\n');
                #[cfg(unix)]
                let orig_perms = hmeta.permissions();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&hooks_path, fs::Permissions::from_mode(0o600));
                }
                fs::write(&hooks_path, updated)
                    .map_err(|e| format!("failed updating '{}': {e}", hooks_path.display()))?;
                #[cfg(unix)]
                {
                    let _ = fs::set_permissions(&hooks_path, orig_perms);
                }
                log.push(format!(
                    "[update] removed 'dotagent-guard' from '{}' while preserving unrelated user hooks",
                    hooks_path.display()
                ));
            }
        }
    }

    let ag_agents_dir = ag_dir.join("agents");
    if validate_optional_dir_lstat(&ag_agents_dir, "Antigravity agents directory")? {
        for af in AGENT_MD_FILES {
            let target = ag_agents_dir.join(af);
            let bak = backup_path_for(&target);
            let tmeta = validate_optional_regular_file_lstat(&target, "Antigravity agent file")?;
            let bmeta = validate_optional_regular_file_lstat(&bak, "Antigravity agent backup")?;

            if let Some(bm) = bmeta {
                if dry_run {
                    log.push(format!(
                        "[dry-run] would restore '{}' -> '{}'",
                        bak.display(),
                        target.display()
                    ));
                } else {
                    #[cfg(unix)]
                    if tmeta.is_some() {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(&target, fs::Permissions::from_mode(0o600));
                    }
                    let bytes = fs::read(&bak)
                        .map_err(|e| format!("failed reading '{}': {e}", bak.display()))?;
                    fs::write(&target, bytes)
                        .map_err(|e| format!("failed restoring '{}': {e}", target.display()))?;
                    #[cfg(unix)]
                    {
                        let _ = fs::set_permissions(&target, bm.permissions());
                    }
                    let _ = fs::remove_file(&bak);
                    log.push(format!(
                        "[restore] restored pre-existing '{}' from backup",
                        target.display()
                    ));
                }
            } else if let Some(tm) = tmeta {
                #[cfg(unix)]
                let is_ro = {
                    use std::os::unix::fs::PermissionsExt;
                    (tm.permissions().mode() & 0o777) == 0o444
                };
                #[cfg(not(unix))]
                let is_ro = {
                    let _ = tm;
                    true
                };
                let is_managed_agent = fs::read_to_string(&target)
                    .map(|s| {
                        s.contains("enable_subagent_tools: false")
                            && s.contains("workspace: inherit")
                    })
                    .unwrap_or(false);
                if is_ro || is_managed_agent {
                    if dry_run {
                        log.push(format!(
                            "[dry-run] would remove deployed '{}'",
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
        if !dry_run
            && fs::read_dir(&ag_agents_dir)
                .map(|mut it| it.next().is_none())
                .unwrap_or(false)
        {
            let _ = fs::remove_dir(&ag_agents_dir);
        }
    }

    if !dry_run
        && fs::read_dir(&ag_dir)
            .map(|mut it| it.next().is_none())
            .unwrap_or(false)
    {
        let _ = fs::remove_dir(&ag_dir);
    }

    Ok(log)
}

pub const DEFAULT_ELEVATE_TTL_SECS: u64 = 1_800; // 30 minutes default
pub const MAX_ELEVATE_TTL_SECS: u64 = 14_400; // 4 hours hard ceiling

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElevatedLease {
    pub repo_root: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

impl ElevatedLease {
    pub fn remaining_secs(&self, now_unix: u64) -> u64 {
        self.expires_at_unix.saturating_sub(now_unix)
    }
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn elevated_state_dir() -> PathBuf {
    let sessions = state_base_dir();
    sessions
        .parent()
        .map(|p| p.join("elevated"))
        .unwrap_or_else(|| sessions.join("elevated"))
}

fn canonical_repo_key(repo_root: &Path) -> (String, String) {
    let canon = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let canon_s = canon.to_string_lossy().into_owned();
    let hash = crate::crypto::sha256_hex(canon_s.as_bytes());
    (canon_s, hash)
}

fn load_or_create_elevated_host_key(dir: &Path) -> Result<[u8; 32], String> {
    reject_if_symlink(dir, "elevated state directory")?;
    fs::create_dir_all(dir).map_err(|e| {
        format!(
            "failed creating elevated state dir '{}': {e}",
            dir.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    let key_path = dir.join("host.key");
    reject_if_symlink(&key_path, "elevated host key")?;
    if key_path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::symlink_metadata(&key_path)
                .map_err(|e| format!("stat elevated host.key: {e}"))?;
            if !meta.file_type().is_file() || (meta.permissions().mode() & 0o077) != 0 {
                return Err(
                    "ELEVATED_KEY_UNSAFE_PERMISSIONS: host.key must be a regular 0600 file"
                        .to_string(),
                );
            }
        }
        let raw = fs::read(&key_path).map_err(|e| format!("failed reading host.key: {e}"))?;
        if raw.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&raw);
            return Ok(key);
        }
    }
    let mut key = [0u8; 32];
    let mut urandom =
        fs::File::open("/dev/urandom").map_err(|e| format!("open /dev/urandom: {e}"))?;
    std::io::Read::read_exact(&mut urandom, &mut key)
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
            std::io::Write::write_all(&mut kf, &key).map_err(|e| format!("write host.key: {e}"))?;
            Ok(key)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let raw = fs::read(&key_path).map_err(|re| format!("failed reading host.key: {re}"))?;
            if raw.len() == 32 {
                key.copy_from_slice(&raw);
                Ok(key)
            } else {
                Err("corrupt elevated host.key".to_string())
            }
        }
        Err(e) => Err(format!("create host.key: {e}")),
    }
}

fn compute_elevated_lease_mac(
    key: &[u8; 32],
    repo_canon: &str,
    issued_at_unix: u64,
    expires_at_unix: u64,
) -> [u8; 32] {
    let mut payload = Vec::with_capacity(repo_canon.len() + 64);
    payload.extend_from_slice(b"dotagent.elevated.v1\0");
    payload.extend_from_slice(key);
    payload.push(0);
    payload.extend_from_slice(repo_canon.as_bytes());
    payload.push(0);
    payload.extend_from_slice(&issued_at_unix.to_be_bytes());
    payload.extend_from_slice(&expires_at_unix.to_be_bytes());
    crate::crypto::sha256_bytes(&payload)
}

pub fn issue_elevated_lease(repo_root: &Path, ttl_secs: u64) -> Result<ElevatedLease, String> {
    if ttl_secs == 0 || ttl_secs > MAX_ELEVATE_TTL_SECS {
        return Err(format!(
            "TTL must be between 1 and {MAX_ELEVATE_TTL_SECS} seconds (max 240 minutes)"
        ));
    }
    let dir = elevated_state_dir();
    let key = load_or_create_elevated_host_key(&dir)?;
    let (repo_canon, repo_hash) = canonical_repo_key(repo_root);
    let now = current_unix_secs();
    let expires = now.saturating_add(ttl_secs);
    let mac = compute_elevated_lease_mac(&key, &repo_canon, now, expires);
    let mac_hex = crate::crypto::hex_encode(&mac);

    let doc = JsonValue::Object(vec![
        (
            "schema".to_string(),
            JsonValue::Str("dotagent.elevated.v1".to_string()),
        ),
        ("repo_root".to_string(), JsonValue::Str(repo_canon.clone())),
        ("issued_at_unix".to_string(), JsonValue::Uint(now)),
        ("expires_at_unix".to_string(), JsonValue::Uint(expires)),
        ("mac".to_string(), JsonValue::Str(mac_hex)),
    ]);
    let lease_path = dir.join(format!("{repo_hash}.json"));
    reject_if_symlink(&lease_path, "elevated lease file")?;
    fs::write(&lease_path, doc.to_json_string().as_bytes())
        .map_err(|e| format!("failed writing elevated lease: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&lease_path, fs::Permissions::from_mode(0o600));
    }
    Ok(ElevatedLease {
        repo_root: repo_canon,
        issued_at_unix: now,
        expires_at_unix: expires,
    })
}

pub fn revoke_elevated_lease(repo_root: &Path) -> Result<bool, String> {
    let dir = elevated_state_dir();
    let (_, repo_hash) = canonical_repo_key(repo_root);
    let lease_path = dir.join(format!("{repo_hash}.json"));
    reject_if_symlink(&lease_path, "elevated lease file")?;
    if lease_path.exists() {
        fs::remove_file(&lease_path).map_err(|e| format!("failed removing lease: {e}"))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn active_elevated_lease_at(repo_root: &Path, now_unix: u64) -> Option<ElevatedLease> {
    let dir = elevated_state_dir();
    let dir_meta = fs::symlink_metadata(&dir).ok()?;
    if dir_meta.file_type().is_symlink() || !dir_meta.file_type().is_dir() {
        return None;
    }
    let key_path = dir.join("host.key");
    let key_meta = fs::symlink_metadata(&key_path).ok()?;
    if key_meta.file_type().is_symlink() || !key_meta.file_type().is_file() {
        return None;
    }
    let raw_key = fs::read(&key_path).ok()?;
    if raw_key.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw_key);

    let (repo_canon, repo_hash) = canonical_repo_key(repo_root);
    let lease_path = dir.join(format!("{repo_hash}.json"));
    let meta = fs::symlink_metadata(&lease_path).ok()?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return None;
    }
    let raw = fs::read_to_string(&lease_path).ok()?;
    let parsed = JsonValue::parse(&raw).ok()?;
    let stored_repo = parsed.get("repo_root")?.as_str()?;
    if stored_repo != repo_canon {
        return None;
    }
    let issued = parsed.get("issued_at_unix")?.as_u64()?;
    let expires = parsed.get("expires_at_unix")?.as_u64()?;
    if expires <= now_unix || expires.saturating_sub(issued) > MAX_ELEVATE_TTL_SECS {
        let _ = fs::remove_file(&lease_path);
        return None;
    }
    let stored_mac = crate::crypto::hex_decode_32(parsed.get("mac")?.as_str()?).ok()?;
    let expected_mac = compute_elevated_lease_mac(&key, &repo_canon, issued, expires);
    if !crate::crypto::constant_time_eq_bytes(&stored_mac, &expected_mac) {
        return None;
    }
    Some(ElevatedLease {
        repo_root: repo_canon,
        issued_at_unix: issued,
        expires_at_unix: expires,
    })
}

pub fn active_elevated_lease(repo_root: &Path) -> Option<ElevatedLease> {
    active_elevated_lease_at(repo_root, current_unix_secs())
}

pub fn has_active_elevated_lease(repo_root: &Path) -> bool {
    active_elevated_lease(repo_root).is_some()
}

/// Interactive human-TTY-only time-boxed local power-user mode (`dotagent elevate [--ttl <min>|--status|--off]`).
/// Lifts ergonomic caps (discovery cap, depth 2->20, slice 150->2000L, hop A->B->10, local python/node, subagents)
/// while preserving catastrophic zero-trust walls (`0` sudo, `0` secrets/.env/~/.ssh, `0` force-push/reset --hard, `0` Bidi/injection).
pub fn run_elevate_cli(args: &[String], cwd: &Path) -> ExitCode {
    if std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() == Ok("1")
        || std::env::var("AGENT_GUARD_WORKER_LOCK").as_deref() == Ok("1")
    {
        eprintln!(
            "[AGENT-GUARD HARD DENY :: ELEVATE_DENIED_IN_SANDBOX] `dotagent elevate` cannot be invoked from inside exec-sandbox or a locked worker."
        );
        return ExitCode::from(2);
    }

    for &marker in crate::telemetry::AGENT_SANDBOX_AND_HARNESS_MARKERS {
        if std::env::var(marker)
            .ok()
            .is_some_and(|v| !v.trim().is_empty())
        {
            eprintln!(
                "[AGENT-GUARD HARD DENY :: ELEVATE_DENIED_IN_HARNESS] `dotagent elevate` is restricted to a standalone human terminal (`{marker}` detected)."
            );
            return ExitCode::from(2);
        }
    }

    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        eprintln!(
            "[AGENT-GUARD HARD DENY :: ELEVATE_REQUIRES_HUMAN_TTY] `dotagent elevate` requires an interactive human terminal (stdin/stdout TTY) so AI agents cannot self-elevate."
        );
        return ExitCode::from(2);
    }

    let mut status_only = false;
    let mut revoke = false;
    let mut json_mode = false;
    let mut ttl_mins: u64 = 30;
    let mut target_dir: Option<PathBuf> = None;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--status" | "status" => {
                status_only = true;
                i += 1;
            }
            "--off" | "--revoke" | "off" | "revoke" => {
                revoke = true;
                i += 1;
            }
            "--json" => {
                json_mode = true;
                i += 1;
            }
            "--ttl" | "-t" => {
                let Some(raw) = args.get(i + 1) else {
                    eprintln!("[elevate] missing minutes after --ttl (e.g. `--ttl 30`)");
                    return ExitCode::from(2);
                };
                let trimmed = raw.trim().trim_end_matches('m');
                let Ok(parsed_mins) = trimmed.parse::<u64>() else {
                    eprintln!("[elevate] invalid --ttl '{raw}' (expected integer minutes 1..=240)");
                    return ExitCode::from(2);
                };
                ttl_mins = parsed_mins;
                i += 2;
            }
            other if !other.starts_with('-') && target_dir.is_none() => {
                target_dir = Some(PathBuf::from(other));
                i += 1;
            }
            other => {
                eprintln!(
                    "[elevate] unrecognized argument '{other}' (usage: `dotagent elevate [--ttl <1..240>|--status|--off] [--json] [repo]`)"
                );
                return ExitCode::from(2);
            }
        }
    }

    let base = target_dir.as_deref().unwrap_or(cwd);
    let repo_root = resolve_repo_root(base);

    if revoke {
        match revoke_elevated_lease(&repo_root) {
            Ok(removed) => {
                if json_mode {
                    println!(
                        "{{\"elevated\":false,\"revoked\":{},\"repo_root\":\"{}\"}}",
                        removed,
                        repo_root.display()
                    );
                } else if removed {
                    println!(
                        "[DOTAGENT ELEVATE OFF] Revoked elevated lease for '{}'; strict micro-window & subagent airlock restored.",
                        repo_root.display()
                    );
                } else {
                    println!(
                        "[DOTAGENT ELEVATE OFF] No active elevated lease on '{}'.",
                        repo_root.display()
                    );
                }
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("[elevate] error revoking lease: {e}");
                return ExitCode::from(2);
            }
        }
    }

    if status_only {
        let now = current_unix_secs();
        if let Some(lease) = active_elevated_lease_at(&repo_root, now) {
            let rem = lease.remaining_secs(now);
            if json_mode {
                println!(
                    "{{\"elevated\":true,\"remaining_secs\":{rem},\"expires_at_unix\":{},\"repo_root\":\"{}\"}}",
                    lease.expires_at_unix, lease.repo_root
                );
            } else {
                println!(
                    "[DOTAGENT ELEVATED ACTIVE] {}m {}s remaining on '{}' (walk<=20, slice<=2000L, step<=64k, hops<=10, local python/node+subagents enabled; sudo/secrets/force-push still hard-blocked).",
                    rem / 60,
                    rem % 60,
                    lease.repo_root
                );
            }
        } else if json_mode {
            println!(
                "{{\"elevated\":false,\"remaining_secs\":0,\"repo_root\":\"{}\"}}",
                repo_root.display()
            );
        } else {
            println!(
                "[DOTAGENT STANDARD MODE] No active elevated lease on '{}'.",
                repo_root.display()
            );
        }
        return ExitCode::SUCCESS;
    }

    if !(1..=240).contains(&ttl_mins) {
        eprintln!("[elevate] --ttl must be between 1 and 240 minutes");
        return ExitCode::from(2);
    }

    match issue_elevated_lease(&repo_root, ttl_mins * 60) {
        Ok(lease) => {
            if json_mode {
                println!(
                    "{{\"elevated\":true,\"ttl_minutes\":{ttl_mins},\"expires_at_unix\":{},\"repo_root\":\"{}\"}}",
                    lease.expires_at_unix, lease.repo_root
                );
            } else {
                println!(
                    "[DOTAGENT ELEVATED GRANTED] {ttl_mins}-minute local power-user lease active on '{}'.\n\
                     Lifted: direct discovery cap, walk depth (2 -> 20), read slices (150 -> 2000 lines / 256 KiB), step budget (16k -> 64k), hop chain (2 -> 10), local python3/uv/node, & subagents.\n\
                     Preserved: 0 sudo/su, 0 ~/.ssh|~/.aws|.env* secrets, 0 git reset --hard/push --force/.git/hooks, 0 curl/wget exfil, 0 Bidi/injection.\n\
                     Revoke anytime with: `dotagent elevate --off`",
                    lease.repo_root
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("[elevate] failed issuing lease: {e}");
            ExitCode::from(2)
        }
    }
}
