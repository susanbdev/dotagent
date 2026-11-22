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
    let mut json_mode = false;
    let mut allow_degraded = false;
    let mut require_host_enforced = false;
    let mut adapter_id = "antigravity".to_string();
    let mut mode_override: Option<String> = None;
    let mut bin_dir_opt: Option<PathBuf> = None;
    let mut trace_log_opt: Option<PathBuf> = None;
    let mut session_override: Option<String> = None;
    let mut target_dir_opt: Option<PathBuf> = None;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => {
                json_mode = true;
                i += 1;
            }
            "--allow-degraded" => {
                allow_degraded = true;
                i += 1;
            }
            "--require-host-enforced" | "--require-mediation" => {
                require_host_enforced = true;
                i += 1;
            }
            "--adapter" => {
                let Some(aid) = args.get(i + 1) else {
                    eprintln!("[doctor] missing value after --adapter");
                    return ExitCode::from(2);
                };
                adapter_id = aid.clone();
                i += 2;
            }
            "--execution-mode" => {
                let Some(em) = args.get(i + 1) else {
                    eprintln!("[doctor] missing value after --execution-mode");
                    return ExitCode::from(2);
                };
                mode_override = Some(em.clone());
                i += 2;
            }
            "--bin-dir" => {
                let Some(bd) = args.get(i + 1) else {
                    eprintln!("[doctor] missing path after --bin-dir");
                    return ExitCode::from(2);
                };
                bin_dir_opt = Some(PathBuf::from(bd));
                i += 2;
            }
            "--trace-log" => {
                let Some(tp) = args.get(i + 1) else {
                    eprintln!("[doctor] missing path after --trace-log");
                    return ExitCode::from(2);
                };
                trace_log_opt = Some(PathBuf::from(tp));
                i += 2;
            }
            "--session" => {
                let Some(sid) = args.get(i + 1) else {
                    eprintln!("[doctor] missing session id after --session");
                    return ExitCode::from(2);
                };
                session_override = Some(sid.clone());
                i += 2;
            }
            other if !other.starts_with('-') && target_dir_opt.is_none() => {
                target_dir_opt = Some(PathBuf::from(other));
                i += 1;
            }
            other => {
                eprintln!(
                    "[doctor] unrecognized argument '{other}' (usage: `dotagent doctor [--json] [--allow-degraded] [--require-host-enforced] [--adapter <id>] [--execution-mode <mode>] [--bin-dir <dir>] [--trace-log <path>] [--session <id>] [workspace]`)"
                );
                return ExitCode::from(2);
            }
        }
    }
    let target_dir = target_dir_opt.unwrap_or_else(|| resolve_repo_root(cwd));

    let probe_snapshot =
        match crate::enforcement_state::ProbeSnapshot::probe_live(mode_override.as_deref()) {
            Ok(s) => s,
            Err(msg) => {
                eprintln!("[doctor] {msg}");
                return ExitCode::from(2);
            }
        };

    let mut checks = Vec::with_capacity(7);

    // 1. Binary integrity & 0555 permissions check
    checks.push(check_binaries_health(bin_dir_opt.as_deref()));

    // 2. OS Kernel VFS + seccomp-bpf readiness
    let sbx_mode = probe_snapshot.kernel_fs_mode;
    let seccomp_label = match probe_snapshot.seccomp_net {
        Some(true) => "verified",
        Some(false) => "unavailable",
        None => "not_applicable",
    };
    checks.push(DoctorCheck {
        name: "kernel_sandbox",
        ok: sbx_mode.is_kernel_enforced() || allow_degraded,
        detail: format!(
            "mode={} kernel_enforced={} seccomp={} allow_degraded={} (pass --allow-degraded to permit non-kernel environments)",
            sbx_mode.as_str(),
            sbx_mode.is_kernel_enforced(),
            seccomp_label,
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
    checks.push(check_session_state_health(
        &target_dir,
        session_override.as_deref(),
    ));

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

    let bin_dir = bin_dir_opt.unwrap_or_else(|| {
        if let Ok(home) = std::env::var("HOME") {
            let cand = PathBuf::from(home).join(".local/bin");
            if cand.is_dir() {
                return cand;
            }
        }
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from(".local/bin"))
    });
    let enf_report = crate::enforcement_state::evaluate_enforcement_report(
        &target_dir,
        &bin_dir,
        &adapter_id,
        trace_log_opt.as_deref(),
        session_override.as_deref(),
        &probe_snapshot,
    );

    let static_ok = checks.iter().all(|c| c.ok);
    let runtime_protected = static_ok && enf_report.mandatory_protection_verified;
    let overall_ok = if require_host_enforced {
        runtime_protected
    } else {
        static_ok
    };

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
            ("healthy".to_string(), JsonValue::Bool(overall_ok)),
            (
                "static_controls_healthy".to_string(),
                JsonValue::Bool(static_ok),
            ),
            (
                "mandatory_protection_verified".to_string(),
                JsonValue::Bool(enf_report.mandatory_protection_verified),
            ),
            ("enforcement".to_string(), enf_report.to_json_value()),
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
        if static_ok {
            println!(
                "Static controls: HEALTHY (local binary/policy/repo invariants passed; does not prove live host enforcement)"
            );
        } else {
            eprintln!(
                "Static controls: UNHEALTHY (one or more required security controls failed; run `dotagent explain <CODE>` for guidance)"
            );
        }
        print!("{}", enf_report.format_human());
    }

    if overall_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

fn check_binaries_health(explicit_bin_dir: Option<&Path>) -> DoctorCheck {
    let exe_info = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    if let Some(exp_dir) = explicit_bin_dir {
        return match crate::enforcement_state::evaluate_install_state(
            exp_dir,
            env!("CARGO_PKG_VERSION"),
        ) {
            crate::enforcement_state::InstallState::Verified {
                binary_path,
                binary_sha256,
                ..
            } => DoctorCheck {
                name: "binary_integrity",
                ok: true,
                detail: format!(
                    "verified binary='{}' sha256={} (active_exe='{}')",
                    binary_path,
                    &binary_sha256[..16],
                    exe_info
                ),
            },
            other => DoctorCheck {
                name: "binary_integrity",
                ok: false,
                detail: format!(
                    "explicit --bin-dir '{}' failed verification: {other:?}",
                    exp_dir.display()
                ),
            },
        };
    }
    if let Ok(home) = std::env::var("HOME") {
        let bin_dir = PathBuf::from(home).join(".local/bin");
        if let Ok(dmeta) = fs::symlink_metadata(&bin_dir)
            && dmeta.file_type().is_symlink()
        {
            return DoctorCheck {
                name: "binary_integrity",
                ok: false,
                detail: format!(
                    "binary directory '{}' must not be a symlink",
                    bin_dir.display()
                ),
            };
        }
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
                if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                    return DoctorCheck {
                        name: "binary_integrity",
                        ok: false,
                        detail: format!(
                            "installed binary '{}' must be a regular non-symlink file",
                            p.display()
                        ),
                    };
                }
                let Ok(bytes) = fs::read(&p) else {
                    return DoctorCheck {
                        name: "binary_integrity",
                        ok: false,
                        detail: format!("installed binary '{}' is unreadable", p.display()),
                    };
                };
                if !crate::enforcement_state::is_valid_host_native_executable(&bytes) {
                    return DoctorCheck {
                        name: "binary_integrity",
                        ok: false,
                        detail: format!(
                            "installed binary '{}' is not a valid native host executable",
                            p.display()
                        ),
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

fn resolve_doctor_session_id(session_override: Option<&str>) -> String {
    match session_override {
        Some(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => std::env::var("AGENT_GUARD_SESSION_ID").unwrap_or_else(|_| "default".to_string()),
    }
}

fn check_session_state_health(repo_root: &Path, session_override: Option<&str>) -> DoctorCheck {
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
    let sid = resolve_doctor_session_id(session_override);
    let session_file = crate::traversal_ledger::session_ledger_path(repo_root, &sid);
    if !session_file.exists() {
        return DoctorCheck {
            name: "session_state",
            ok: true,
            detail: format!("clean (session='{sid}', no active halts, mediated_calls=0)"),
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
    let mut trace_log: Option<PathBuf> = None;
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
            "--trace-log" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[activate] missing path after --trace-log");
                    return ExitCode::from(2);
                };
                trace_log = Some(PathBuf::from(v));
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
        return match execute_antigravity_activate_with_trace(
            &resolved_bin_dir,
            &resolved_dotagent,
            &target_ws,
            trace_log.as_deref(),
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
/// and cannot be hijacked via mutable `PATH` entries. Fails closed if `abs_guard_bin` cannot be
/// safely quoted rather than silently falling back to an unpinned command.
fn pin_hook_binary_in_json(
    val: &JsonValue,
    abs_guard_bin: Option<&Path>,
    adapter_tag: Option<&str>,
) -> Result<JsonValue, String> {
    let Some(bin) = abs_guard_bin else {
        return Ok(val.clone());
    };
    let bin_q = quote_antigravity_path_arg(bin, "agent-guard binary path")?;

    fn rewrite(node: &JsonValue, bin_q: &str, adapter_tag: Option<&str>) -> JsonValue {
        match node {
            JsonValue::Str(s) => {
                if let Some(rest) = s.strip_prefix("agent-guard ") {
                    let trimmed = rest.trim();
                    if let Some(ad) = adapter_tag
                        && matches!(
                            trimmed,
                            "pre-tool"
                                | "post-tool"
                                | "user-prompt"
                                | "pre-compact"
                                | "post-edit"
                                | "on-stop"
                        )
                    {
                        JsonValue::Str(format!("{bin_q} {trimmed} --adapter {ad}"))
                    } else {
                        JsonValue::Str(format!("{bin_q} {rest}"))
                    }
                } else if s == "agent-guard" {
                    JsonValue::Str(bin_q.to_string())
                } else {
                    JsonValue::Str(s.clone())
                }
            }
            JsonValue::Array(items) => JsonValue::Array(
                items
                    .iter()
                    .map(|v| rewrite(v, bin_q, adapter_tag))
                    .collect(),
            ),
            JsonValue::Object(entries) => JsonValue::Object(
                entries
                    .iter()
                    .map(|(k, v)| (k.clone(), rewrite(v, bin_q, adapter_tag)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    Ok(rewrite(val, &bin_q, adapter_tag))
}

fn pin_codex_notify_toml(tpl: &str, abs_guard_bin: Option<&Path>) -> Result<String, String> {
    let Some(bin) = abs_guard_bin else {
        return Ok(tpl.to_string());
    };
    if !bin.is_absolute() {
        return Err(format!(
            "agent-guard binary path '{}' must be an absolute path",
            bin.display()
        ));
    }
    let Some(s) = bin.to_str() else {
        return Err(format!(
            "agent-guard binary path '{}' must be valid UTF-8",
            bin.display()
        ));
    };
    if s.is_empty() || s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(format!(
            "agent-guard binary path '{}' contains disallowed control characters",
            bin.display()
        ));
    }
    let bin_lit = JsonValue::Str(s.to_string()).to_json_string();
    let replacement = format!("notify = [{bin_lit}, \"on-stop\", \"--adapter\", \"codex\"]");
    if !tpl.contains("notify = [\"agent-guard\", \"on-stop\"]") {
        return Err("dist/codex/config.toml missing canonical notify array".to_string());
    }
    Ok(tpl.replacen("notify = [\"agent-guard\", \"on-stop\"]", &replacement, 1))
}

fn first_shell_executable_name(cmd: &str) -> Option<String> {
    let s = cmd.trim_start();
    if s.is_empty() {
        return None;
    }
    let bytes = s.as_bytes();
    let mut tok = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            break;
        }
        if b == b'\'' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'\'' {
                tok.push(bytes[i] as char);
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
        } else if b == b'"' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 1;
                }
                tok.push(bytes[i] as char);
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
        } else {
            tok.push(b as char);
            i += 1;
        }
    }
    Path::new(&tok)
        .file_name()
        .and_then(|n| n.to_str())
        .map(ToString::to_string)
}

fn is_agent_guard_hook_item(item: &JsonValue) -> bool {
    if item
        .get("name")
        .and_then(JsonValue::as_str)
        .is_some_and(|n| n == "agent-guard" || n.starts_with("agent-guard-"))
    {
        return true;
    }
    item.get("command")
        .and_then(JsonValue::as_str)
        .and_then(first_shell_executable_name)
        .is_some_and(|exe| exe == "agent-guard" || exe == "dotagent")
}

fn strip_agent_guard_from_grouped_event(arr: &[JsonValue]) -> Result<Vec<JsonValue>, String> {
    let mut out = Vec::new();
    for g in arr {
        let Some(g_obj) = g.as_object() else {
            return Err(
                "existing settings JSON contains a non-object hook group entry (refusing destructive overwrite)"
                    .to_string(),
            );
        };
        let Some(inner) = g.get("hooks").and_then(JsonValue::as_array) else {
            return Err(
                "existing settings JSON hook group is missing 'hooks' array (refusing destructive overwrite)"
                    .to_string(),
            );
        };
        let rem_inner: Vec<JsonValue> = inner
            .iter()
            .filter(|it| !is_agent_guard_hook_item(it))
            .cloned()
            .collect();
        if !rem_inner.is_empty() {
            let mut new_g = Vec::with_capacity(g_obj.len());
            for (k, v) in g_obj {
                if k == "hooks" {
                    new_g.push((k.clone(), JsonValue::Array(rem_inner.clone())));
                } else {
                    new_g.push((k.clone(), v.clone()));
                }
            }
            out.push(JsonValue::Object(new_g));
        }
    }
    Ok(out)
}

fn strip_agent_guard_from_cursor_event(arr: &[JsonValue]) -> Result<Vec<JsonValue>, String> {
    let mut out = Vec::new();
    for item in arr {
        if item.as_object().is_none() || item.get("command").and_then(JsonValue::as_str).is_none() {
            return Err(
                "existing Cursor hooks.json contains a malformed hook entry (refusing destructive overwrite)"
                    .to_string(),
            );
        }
        if !is_agent_guard_hook_item(item) {
            out.push(item.clone());
        }
    }
    Ok(out)
}

/// Merges `template_raw` over an optional pre-existing `existing_raw` (`settings.json`),
/// failing closed on malformed/non-object JSON, preserving user top-level preferences AND
/// pre-existing sibling hook entries inside `hooks`, while enforcing `dotagent`'s security keys.
fn merge_settings_json_preserving_user_prefs(
    existing_raw: Option<&str>,
    template_raw: &str,
    abs_guard_bin: Option<&Path>,
    adapter_tag: Option<&str>,
) -> Result<(String, JsonValue), String> {
    let template_parsed = JsonValue::parse(template_raw)
        .map_err(|e| format!("invalid dist settings JSON template: {e}"))?;
    let pinned_template = pin_hook_binary_in_json(&template_parsed, abs_guard_bin, adapter_tag)?;
    let Some(template_obj) = pinned_template.as_object() else {
        return Err("dist settings JSON template root must be a JSON object".to_string());
    };

    let mut existing_hooks_opt: Option<Vec<(String, JsonValue)>> = None;
    let mut merged: Vec<(String, JsonValue)> = Vec::new();
    if let Some(raw) = existing_raw {
        let existing_val = JsonValue::parse(raw).map_err(|e| {
            format!("existing settings JSON is malformed (refusing destructive overwrite): {e}")
        })?;
        let Some(existing_obj) = existing_val.as_object() else {
            return Err(
                "existing settings JSON root must be a JSON object (refusing destructive overwrite)"
                    .to_string(),
            );
        };
        for (k, v) in existing_obj {
            if k == "hooks" {
                let Some(h_obj) = v.as_object() else {
                    return Err(
                        "existing settings JSON 'hooks' must be a JSON object (refusing destructive overwrite)"
                            .to_string(),
                    );
                };
                existing_hooks_opt = Some(h_obj.to_vec());
            } else if !template_obj.iter().any(|(tk, _)| tk == k) {
                merged.push((k.clone(), v.clone()));
            }
        }
    }

    for (tk, tv) in template_obj {
        if tk == "hooks"
            && let Some(tpl_hooks) = tv.as_object()
            && let Some(ref ex_hooks) = existing_hooks_opt
        {
            let mut merged_hooks: Vec<(String, JsonValue)> = Vec::new();
            for (ev, tpl_ev_val) in tpl_hooks {
                let mut combined = tpl_ev_val
                    .as_array()
                    .map(<[JsonValue]>::to_vec)
                    .unwrap_or_default();
                if let Some((_, ex_ev_val)) = ex_hooks.iter().find(|(k, _)| k == ev) {
                    let Some(ex_arr) = ex_ev_val.as_array() else {
                        return Err(format!(
                            "existing settings JSON 'hooks.{ev}' must be an array (refusing destructive overwrite)"
                        ));
                    };
                    combined.extend(strip_agent_guard_from_grouped_event(ex_arr)?);
                }
                merged_hooks.push((ev.clone(), JsonValue::Array(combined)));
            }
            for (ex_ev, ex_ev_val) in ex_hooks {
                if !tpl_hooks.iter().any(|(ev, _)| ev == ex_ev) {
                    let Some(ex_arr) = ex_ev_val.as_array() else {
                        return Err(format!(
                            "existing settings JSON 'hooks.{ex_ev}' must be an array (refusing destructive overwrite)"
                        ));
                    };
                    let rem = strip_agent_guard_from_grouped_event(ex_arr)?;
                    if !rem.is_empty() {
                        merged_hooks.push((ex_ev.clone(), JsonValue::Array(rem)));
                    }
                }
            }
            merged.push((tk.clone(), JsonValue::Object(merged_hooks)));
        } else {
            merged.push((tk.clone(), tv.clone()));
        }
    }

    let mut pretty = String::new();
    format_json_pretty_2space(&JsonValue::Object(merged), 0, &mut pretty);
    pretty.push('\n');
    Ok((pretty, pinned_template))
}

fn merge_cursor_hooks_json_preserving_siblings(
    existing_raw: Option<&str>,
    template_raw: &str,
    abs_guard_bin: Option<&Path>,
) -> Result<(String, JsonValue), String> {
    let template_parsed = JsonValue::parse(template_raw)
        .map_err(|e| format!("invalid dist/cursor/hooks.json: {e}"))?;
    let pinned_template = pin_hook_binary_in_json(&template_parsed, abs_guard_bin, Some("cursor"))?;
    let Some(template_obj) = pinned_template.as_object() else {
        return Err("dist/cursor/hooks.json root must be a JSON object".to_string());
    };
    let Some(tpl_hooks) = pinned_template.get("hooks").and_then(JsonValue::as_object) else {
        return Err("dist/cursor/hooks.json missing 'hooks' object".to_string());
    };

    let mut extra_top: Vec<(String, JsonValue)> = Vec::new();
    let mut existing_hooks_opt: Option<Vec<(String, JsonValue)>> = None;
    if let Some(raw) = existing_raw {
        let existing_val = JsonValue::parse(raw).map_err(|e| {
            format!("existing Cursor hooks.json is malformed (refusing destructive overwrite): {e}")
        })?;
        let Some(existing_obj) = existing_val.as_object() else {
            return Err(
                "existing Cursor hooks.json root must be a JSON object (refusing destructive overwrite)"
                    .to_string(),
            );
        };
        for (k, v) in existing_obj {
            if k == "hooks" {
                let Some(h_obj) = v.as_object() else {
                    return Err(
                        "existing Cursor hooks.json 'hooks' must be a JSON object (refusing destructive overwrite)"
                            .to_string(),
                    );
                };
                existing_hooks_opt = Some(h_obj.to_vec());
            } else if !template_obj.iter().any(|(tk, _)| tk == k) {
                extra_top.push((k.clone(), v.clone()));
            }
        }
    }

    let mut merged_hooks: Vec<(String, JsonValue)> = Vec::new();
    for (ev, tpl_ev_val) in tpl_hooks {
        let mut combined = tpl_ev_val
            .as_array()
            .map(<[JsonValue]>::to_vec)
            .unwrap_or_default();
        if let Some(ref ex_hooks) = existing_hooks_opt
            && let Some((_, ex_ev_val)) = ex_hooks.iter().find(|(k, _)| k == ev)
        {
            let Some(ex_arr) = ex_ev_val.as_array() else {
                return Err(format!(
                    "existing Cursor hooks.json 'hooks.{ev}' must be an array (refusing destructive overwrite)"
                ));
            };
            combined.extend(strip_agent_guard_from_cursor_event(ex_arr)?);
        }
        merged_hooks.push((ev.clone(), JsonValue::Array(combined)));
    }
    if let Some(ref ex_hooks) = existing_hooks_opt {
        for (ex_ev, ex_ev_val) in ex_hooks {
            if !tpl_hooks.iter().any(|(ev, _)| ev == ex_ev) {
                let Some(ex_arr) = ex_ev_val.as_array() else {
                    return Err(format!(
                        "existing Cursor hooks.json 'hooks.{ex_ev}' must be an array (refusing destructive overwrite)"
                    ));
                };
                let rem = strip_agent_guard_from_cursor_event(ex_arr)?;
                if !rem.is_empty() {
                    merged_hooks.push((ex_ev.clone(), JsonValue::Array(rem)));
                }
            }
        }
    }

    let mut out_obj = Vec::new();
    for (tk, tv) in template_obj {
        if tk == "hooks" {
            for (ek, ev) in &extra_top {
                out_obj.push((ek.clone(), ev.clone()));
            }
            out_obj.push(("hooks".to_string(), JsonValue::Object(merged_hooks.clone())));
        } else {
            out_obj.push((tk.clone(), tv.clone()));
        }
    }

    let mut pretty = String::new();
    format_json_pretty_2space(&JsonValue::Object(out_obj), 0, &mut pretty);
    pretty.push('\n');
    Ok((pretty, pinned_template))
}

fn extract_user_part_from_merged_json(
    parsed: &JsonValue,
    managed_tpl: &JsonValue,
    is_cursor_hooks: bool,
) -> Result<Vec<(String, JsonValue)>, String> {
    let Some(cur_obj) = parsed.as_object() else {
        return Err("JSON root must be an object".to_string());
    };
    let Some(tpl_obj) = managed_tpl.as_object() else {
        return Err("managed template root must be an object".to_string());
    };

    let mut user_top: Vec<(String, JsonValue)> = Vec::new();
    let mut rem_hooks: Vec<(String, JsonValue)> = Vec::new();
    for (k, v) in cur_obj {
        if k == "hooks" {
            let Some(h_obj) = v.as_object() else {
                return Err("'hooks' must be an object".to_string());
            };
            for (ev, ev_val) in h_obj {
                let Some(arr) = ev_val.as_array() else {
                    return Err(format!("'hooks.{ev}' must be an array"));
                };
                let rem = if is_cursor_hooks {
                    strip_agent_guard_from_cursor_event(arr)?
                } else {
                    strip_agent_guard_from_grouped_event(arr)?
                };
                if !rem.is_empty() {
                    rem_hooks.push((ev.clone(), JsonValue::Array(rem)));
                }
            }
        } else if !tpl_obj.iter().any(|(tk, _)| tk == k) {
            user_top.push((k.clone(), v.clone()));
        }
    }

    if is_cursor_hooks {
        if user_top.is_empty() && rem_hooks.is_empty() {
            Ok(Vec::new())
        } else {
            let mut out = vec![("version".to_string(), JsonValue::Uint(1))];
            out.extend(user_top);
            out.push(("hooks".to_string(), JsonValue::Object(rem_hooks)));
            Ok(out)
        }
    } else {
        if !rem_hooks.is_empty() {
            user_top.push(("hooks".to_string(), JsonValue::Object(rem_hooks)));
        }
        Ok(user_top)
    }
}

fn verify_managed_json_intact_and_extract_user_part(
    current_bytes: &[u8],
    managed_tpl: &JsonValue,
    is_cursor_hooks: bool,
    target: &Path,
) -> Result<Vec<(String, JsonValue)>, String> {
    let raw = std::str::from_utf8(current_bytes).map_err(|_| {
        format!(
            "managed JSON '{}' contains non-UTF-8 bytes",
            target.display()
        )
    })?;
    let parsed = JsonValue::parse(raw)
        .map_err(|e| format!("managed JSON '{}' is malformed: {e}", target.display()))?;
    let Some(cur_obj) = parsed.as_object() else {
        return Err(format!(
            "managed JSON '{}' root was modified to non-object",
            target.display()
        ));
    };
    let Some(tpl_obj) = managed_tpl.as_object() else {
        return Err("invalid managed_group in provenance manifest".to_string());
    };

    for (tk, tv) in tpl_obj {
        if tk == "hooks" {
            let Some(tpl_hooks) = tv.as_object() else {
                continue;
            };
            let Some(cur_hooks) = cur_obj
                .iter()
                .find(|(k, _)| k == "hooks")
                .and_then(|(_, v)| v.as_object())
            else {
                return Err(format!(
                    "managed 'hooks' section in '{}' was removed or modified externally",
                    target.display()
                ));
            };
            for (ev, tpl_ev_val) in tpl_hooks {
                let Some(tpl_arr) = tpl_ev_val.as_array() else {
                    continue;
                };
                let Some(cur_arr) = cur_hooks
                    .iter()
                    .find(|(k, _)| k == ev)
                    .and_then(|(_, v)| v.as_array())
                else {
                    return Err(format!(
                        "managed 'hooks.{ev}' array in '{}' was removed externally",
                        target.display()
                    ));
                };
                for req_item in tpl_arr {
                    if !cur_arr.iter().any(|x| x == req_item) {
                        return Err(format!(
                            "managed 'agent-guard' hook in '{}' ('hooks.{ev}') was modified or removed externally",
                            target.display()
                        ));
                    }
                }
                if is_cursor_hooks {
                    for item in cur_arr {
                        if is_agent_guard_hook_item(item) && !tpl_arr.iter().any(|x| x == item) {
                            return Err(format!(
                                "managed 'agent-guard' hook in '{}' ('hooks.{ev}') was altered externally",
                                target.display()
                            ));
                        }
                    }
                } else {
                    for g in cur_arr {
                        if let Some(inner) = g.get("hooks").and_then(JsonValue::as_array)
                            && inner.iter().any(is_agent_guard_hook_item)
                            && !tpl_arr.iter().any(|x| x == g)
                        {
                            return Err(format!(
                                "managed 'agent-guard' hook group in '{}' ('hooks.{ev}') was altered externally",
                                target.display()
                            ));
                        }
                    }
                }
            }
        } else {
            let cur_v = cur_obj.iter().find(|(k, _)| k == tk).map(|(_, v)| v);
            if cur_v != Some(tv) {
                return Err(format!(
                    "managed security setting '{tk}' in '{}' was modified or removed externally",
                    target.display()
                ));
            }
        }
    }

    extract_user_part_from_merged_json(&parsed, managed_tpl, is_cursor_hooks)
        .map_err(|e| format!("invalid structure in '{}': {e}", target.display()))
}

const BUNDLE_PROVENANCE_FILE: &str = ".dotagent-manifest.json";
const BUNDLE_PROVENANCE_FORMAT: &str = "dotagent.bundle.provenance.v1";

#[derive(Debug, Clone, PartialEq)]
struct BundleProvenanceManifest {
    created_dirs: Vec<String>,
    entries: Vec<FileProvenanceEntry>,
}

fn is_valid_created_dir_rel(rel: &str) -> bool {
    rel.is_empty() || is_safe_manifest_rel_path(rel)
}

impl BundleProvenanceManifest {
    fn parse(raw: &str, allowed_rels: &[String]) -> Result<Self, String> {
        let parsed = JsonValue::parse(raw)
            .map_err(|e| format!("invalid bundle provenance manifest JSON: {e}"))?;
        if parsed.get("format").and_then(JsonValue::as_str) != Some(BUNDLE_PROVENANCE_FORMAT) {
            return Err("unrecognized bundle provenance manifest format".to_string());
        }
        let dirs_arr = parsed
            .get("created_dirs")
            .and_then(JsonValue::as_array)
            .ok_or("missing 'created_dirs' array in bundle provenance manifest")?;
        let mut created_dirs = Vec::with_capacity(dirs_arr.len());
        for d in dirs_arr {
            let s = d
                .as_str()
                .filter(|s| is_valid_created_dir_rel(s))
                .ok_or("invalid directory entry in 'created_dirs'")?;
            created_dirs.push(s.to_string());
        }
        let arr = parsed
            .get("entries")
            .and_then(JsonValue::as_array)
            .ok_or("missing 'entries' array in bundle provenance manifest")?;
        if arr.is_empty() {
            return Err("bundle provenance manifest 'entries' cannot be empty".to_string());
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut entries = Vec::with_capacity(arr.len());
        for item in arr {
            let rel_path = item
                .get("rel_path")
                .and_then(JsonValue::as_str)
                .filter(|s| is_safe_manifest_rel_path(s) && allowed_rels.iter().any(|a| a == *s))
                .ok_or("invalid or unexpected 'rel_path' in bundle provenance manifest")?
                .to_string();
            if !seen.insert(rel_path.clone()) {
                return Err(format!(
                    "duplicate provenance entry for '{rel_path}' in manifest"
                ));
            }
            let pre_existing = item
                .get("pre_existing")
                .and_then(JsonValue::as_bool)
                .ok_or("missing boolean 'pre_existing' in provenance manifest")?;
            let orig_mode = match item.get("orig_mode") {
                None | Some(JsonValue::Null) => None,
                Some(v) => {
                    let m = v
                        .as_u64()
                        .filter(|&m| m <= 0o777)
                        .ok_or("invalid 'orig_mode' in provenance manifest")?;
                    Some(m as u32)
                }
            };
            let orig_sha256 = match item.get("orig_sha256") {
                None | Some(JsonValue::Null) => None,
                Some(v) => {
                    let s = v
                        .as_str()
                        .filter(|s| is_valid_sha256_hex(s))
                        .ok_or("invalid 'orig_sha256' in provenance manifest")?;
                    Some(s.to_ascii_lowercase())
                }
            };
            if pre_existing && orig_sha256.is_none() {
                return Err(format!(
                    "pre-existing provenance entry '{rel_path}' is missing 'orig_sha256'"
                ));
            }
            let deployed_sha256 = item
                .get("deployed_sha256")
                .and_then(JsonValue::as_str)
                .filter(|s| is_valid_sha256_hex(s))
                .ok_or("invalid 'deployed_sha256' in provenance manifest")?
                .to_ascii_lowercase();
            let managed_group = match item.get("managed_group") {
                None | Some(JsonValue::Null) => None,
                Some(v) if v.as_object().is_some() => Some(v.clone()),
                Some(_) => {
                    return Err(
                        "invalid non-object 'managed_group' in provenance manifest".to_string()
                    );
                }
            };
            entries.push(FileProvenanceEntry {
                rel_path,
                pre_existing,
                orig_mode,
                orig_sha256,
                deployed_sha256,
                managed_group,
            });
        }
        Ok(Self {
            created_dirs,
            entries,
        })
    }

    fn serialize(&self) -> String {
        let dirs: Vec<JsonValue> = self
            .created_dirs
            .iter()
            .map(|d| JsonValue::Str(d.clone()))
            .collect();
        let items: Vec<JsonValue> = self
            .entries
            .iter()
            .map(|e| {
                JsonValue::Object(vec![
                    ("rel_path".to_string(), JsonValue::Str(e.rel_path.clone())),
                    ("pre_existing".to_string(), JsonValue::Bool(e.pre_existing)),
                    (
                        "orig_mode".to_string(),
                        e.orig_mode
                            .map_or(JsonValue::Null, |m| JsonValue::Uint(u64::from(m))),
                    ),
                    (
                        "orig_sha256".to_string(),
                        e.orig_sha256
                            .as_ref()
                            .map_or(JsonValue::Null, |s| JsonValue::Str(s.clone())),
                    ),
                    (
                        "deployed_sha256".to_string(),
                        JsonValue::Str(e.deployed_sha256.clone()),
                    ),
                    (
                        "managed_group".to_string(),
                        e.managed_group.clone().unwrap_or(JsonValue::Null),
                    ),
                ])
            })
            .collect();
        let doc = JsonValue::Object(vec![
            (
                "format".to_string(),
                JsonValue::Str(BUNDLE_PROVENANCE_FORMAT.to_string()),
            ),
            ("created_dirs".to_string(), JsonValue::Array(dirs)),
            ("entries".to_string(), JsonValue::Array(items)),
        ]);
        let mut out = String::new();
        format_json_pretty_2space(&doc, 0, &mut out);
        out.push('\n');
        out
    }

    fn entry_for(&self, rel_path: &str) -> Option<&FileProvenanceEntry> {
        self.entries.iter().find(|e| e.rel_path == rel_path)
    }
}

fn workspace_managed_rel_paths() -> Vec<String> {
    let mut v = vec![
        "AGENTS.md".to_string(),
        ".ignore".to_string(),
        ".cursorignore".to_string(),
        ".codex/config.toml".to_string(),
        ".claude/settings.json".to_string(),
        ".cursor/hooks.json".to_string(),
    ];
    for af in AGENT_MD_FILES {
        for sub in [".claude/agents", ".cursor/agents", ".codex/agents"] {
            v.push(format!("{sub}/{af}"));
        }
    }
    v
}

fn gemini_managed_rel_paths() -> Vec<String> {
    let mut v = vec!["GEMINI.md".to_string(), "settings.json".to_string()];
    for af in AGENT_MD_FILES {
        v.push(format!("agents/{af}"));
    }
    v
}

#[allow(clippy::too_many_arguments)]
fn write_bundle_provenance_file(
    target: &Path,
    rel_path: &str,
    new_bytes: &[u8],
    managed_group: Option<JsonValue>,
    prior_entry: Option<&FileProvenanceEntry>,
    mode: u32,
    use_cp_semantics: bool,
    journal: &mut RollbackJournal,
    log: &mut Vec<String>,
) -> Result<FileProvenanceEntry, String> {
    let existing_meta = validate_optional_regular_file_lstat(target, "target file")?;
    let bak = backup_path_for(target);
    let existing_bak = validate_optional_regular_file_lstat(&bak, "backup file")?;

    #[cfg(unix)]
    let current_disk_mode = existing_meta.as_ref().map(|m| {
        use std::os::unix::fs::PermissionsExt;
        m.permissions().mode() & 0o777
    });
    #[cfg(not(unix))]
    let current_disk_mode: Option<u32> = None;

    let deployed_sha256 = crate::crypto::sha256_hex(new_bytes);
    let is_cursor_hooks = rel_path == ".cursor/hooks.json";

    if let Some(prior) = prior_entry {
        if prior.pre_existing && existing_bak.is_none() {
            return Err(format!(
                "missing required backup '{}' for pre-existing '{}' during re-activation",
                bak.display(),
                target.display()
            ));
        }
        if existing_meta.is_some() {
            let existing_bytes = fs::read(target)
                .map_err(|e| format!("failed reading '{}': {e}", target.display()))?;
            let actual_sha = crate::crypto::sha256_hex(&existing_bytes);
            if let Some(ref exp_tpl) = prior.managed_group {
                let _ = verify_managed_json_intact_and_extract_user_part(
                    &existing_bytes,
                    exp_tpl,
                    is_cursor_hooks,
                    target,
                )?;
            } else if actual_sha != prior.deployed_sha256 {
                return Err(format!(
                    "managed file '{}' was modified externally; deactivate or restore before re-activating",
                    target.display()
                ));
            }
            journal.overwritten_files.push((
                target.to_path_buf(),
                existing_bytes,
                current_disk_mode,
            ));
        } else if prior.pre_existing {
            return Err(format!(
                "pre-existing managed file '{}' was removed externally; preserving backup '{}'",
                target.display(),
                bak.display()
            ));
        } else {
            journal.created_files.push(target.to_path_buf());
        }

        write_target_bytes_with_mode(target, new_bytes, mode, use_cp_semantics)?;
        log.push(format!(
            "[deploy] installed '{}' (mode {:04o}, {} bytes)",
            target.display(),
            mode,
            new_bytes.len()
        ));
        return Ok(FileProvenanceEntry {
            rel_path: rel_path.to_string(),
            pre_existing: prior.pre_existing,
            orig_mode: prior.orig_mode,
            orig_sha256: prior.orig_sha256.clone(),
            deployed_sha256,
            managed_group,
        });
    }

    if existing_bak.is_some() {
        return Err(format!(
            "orphaned backup '{}' exists without provenance manifest; refusing to overwrite original backup",
            bak.display()
        ));
    }

    let (pre_existing, orig_mode, orig_sha256) = if existing_meta.is_some() {
        let existing_bytes =
            fs::read(target).map_err(|e| format!("failed reading '{}': {e}", target.display()))?;
        let orig_sha = crate::crypto::sha256_hex(&existing_bytes);
        fs::write(&bak, &existing_bytes).map_err(|e| {
            format!(
                "failed backing up '{}' to '{}': {e}",
                target.display(),
                bak.display()
            )
        })?;
        #[cfg(unix)]
        if let Some(m) = current_disk_mode
            && !use_cp_semantics
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&bak, fs::Permissions::from_mode(m)).map_err(|e| {
                format!(
                    "failed preserving mode {:04o} on backup '{}': {e}",
                    m,
                    bak.display()
                )
            })?;
        }
        #[cfg(unix)]
        if let Some(m) = current_disk_mode
            && use_cp_semantics
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&bak, fs::Permissions::from_mode(m));
        }
        journal.created_backups.push(bak.clone());
        log.push(format!(
            "[backup] saved pre-existing '{}' -> '{}'",
            target.display(),
            bak.display()
        ));
        journal
            .overwritten_files
            .push((target.to_path_buf(), existing_bytes, current_disk_mode));
        (true, current_disk_mode, Some(orig_sha))
    } else {
        journal.created_files.push(target.to_path_buf());
        (false, None, None)
    };

    write_target_bytes_with_mode(target, new_bytes, mode, use_cp_semantics)?;
    log.push(format!(
        "[deploy] installed '{}' (mode {:04o}, {} bytes)",
        target.display(),
        mode,
        new_bytes.len()
    ));
    Ok(FileProvenanceEntry {
        rel_path: rel_path.to_string(),
        pre_existing,
        orig_mode,
        orig_sha256,
        deployed_sha256,
        managed_group,
    })
}

fn write_target_bytes_with_mode(
    target: &Path,
    new_bytes: &[u8],
    mode: u32,
    use_cp_semantics: bool,
) -> Result<(), String> {
    if use_cp_semantics {
        if target.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(target, fs::Permissions::from_mode(0o600));
            }
        }
        fs::write(target, new_bytes)
            .map_err(|e| format!("failed writing '{}': {e}", target.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(target, fs::Permissions::from_mode(mode));
        }
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

fn write_bundle_manifest_file(
    manifest_path: &Path,
    manifest: &BundleProvenanceManifest,
    mode: u32,
    use_cp_semantics: bool,
    journal: &mut RollbackJournal,
) -> Result<(), String> {
    if let Some(mmeta) =
        validate_optional_regular_file_lstat(manifest_path, "bundle provenance manifest")?
    {
        let prev = fs::read(manifest_path)
            .map_err(|e| format!("failed reading '{}': {e}", manifest_path.display()))?;
        #[cfg(unix)]
        let prev_mode = {
            use std::os::unix::fs::PermissionsExt;
            Some(mmeta.permissions().mode() & 0o777)
        };
        #[cfg(not(unix))]
        let prev_mode: Option<u32> = {
            let _ = &mmeta;
            None
        };
        journal
            .overwritten_files
            .push((manifest_path.to_path_buf(), prev, prev_mode));
    } else {
        journal.created_files.push(manifest_path.to_path_buf());
    }
    let body = manifest.serialize();
    write_target_bytes_with_mode(manifest_path, body.as_bytes(), mode, use_cp_semantics)
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
        let rc_meta = validate_optional_regular_file_lstat(&rc_path, rc_name)?;
        if rc_name == ".bashrc" && rc_meta.is_none() {
            continue;
        }
        let existing = if rc_meta.is_some() {
            fs::read_to_string(&rc_path)
                .map_err(|e| format!("failed reading '{}': {e}", rc_path.display()))?
        } else {
            String::new()
        };
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

fn deploy_gemini_home_plane(
    dotagent_root: &Path,
    home: &Path,
    abs_guard_bin: Option<&Path>,
    dry_run: bool,
    log: &mut Vec<String>,
) -> Result<Option<RollbackJournal>, String> {
    validate_existing_regular_dir_lstat(home, "HOME directory")?;
    let gemini_dir = home.join(".gemini");
    let gemini_agents = gemini_dir.join("agents");
    let gemini_existed = validate_optional_dir_lstat(&gemini_dir, "Gemini directory")?;
    let agents_existed = if gemini_existed {
        validate_optional_dir_lstat(&gemini_agents, "Gemini agents directory")?
    } else {
        false
    };

    let allowed_rels = gemini_managed_rel_paths();
    let manifest_path = gemini_dir.join(BUNDLE_PROVENANCE_FILE);
    let prior_manifest = if gemini_existed
        && validate_optional_regular_file_lstat(&manifest_path, "Gemini provenance manifest")?
            .is_some()
    {
        let raw = fs::read_to_string(&manifest_path)
            .map_err(|e| format!("failed reading '{}': {e}", manifest_path.display()))?;
        Some(BundleProvenanceManifest::parse(&raw, &allowed_rels)?)
    } else {
        None
    };

    let mut staged: Vec<(String, Vec<u8>, Option<JsonValue>)> =
        Vec::with_capacity(allowed_rels.len());
    let gemini_md = fs::read(dotagent_root.join("dist/gemini/GEMINI.md"))
        .map_err(|e| format!("missing dist/gemini/GEMINI.md: {e}"))?;
    staged.push(("GEMINI.md".to_string(), gemini_md, None));

    let gemini_settings_tpl = fs::read_to_string(dotagent_root.join("dist/gemini/settings.json"))
        .map_err(|e| format!("missing dist/gemini/settings.json: {e}"))?;
    let gemini_settings_dst = gemini_dir.join("settings.json");
    let existing_gemini = if gemini_existed
        && validate_optional_regular_file_lstat(&gemini_settings_dst, "Gemini settings.json")?
            .is_some()
    {
        Some(fs::read_to_string(&gemini_settings_dst).map_err(|e| {
            format!(
                "failed reading existing '{}': {e}",
                gemini_settings_dst.display()
            )
        })?)
    } else {
        None
    };
    let (merged_gemini, pinned_gemini_tpl) = merge_settings_json_preserving_user_prefs(
        existing_gemini.as_deref(),
        &gemini_settings_tpl,
        abs_guard_bin,
        Some("gemini"),
    )?;
    staged.push((
        "settings.json".to_string(),
        merged_gemini.into_bytes(),
        Some(pinned_gemini_tpl),
    ));

    for af in AGENT_MD_FILES {
        let rel = format!("agents/{af}");
        let dst = gemini_dir.join(&rel);
        if agents_existed {
            let _ = validate_optional_regular_file_lstat(&dst, "Gemini agent")?;
        }
        let bytes = fs::read(dotagent_root.join("dist/gemini/agents").join(af))
            .map_err(|e| format!("missing dist/gemini/agents/{af}: {e}"))?;
        staged.push((rel, bytes, None));
    }

    if gemini_existed {
        let _ = validate_optional_regular_file_lstat(
            &gemini_dir.join("GEMINI.md"),
            "Gemini GEMINI.md",
        )?;
        for (rel, _, _) in &staged {
            let dst = gemini_dir.join(rel);
            let _ = validate_optional_regular_file_lstat(&backup_path_for(&dst), "Gemini backup")?;
        }
    }

    if dry_run {
        for (rel, bytes, _) in &staged {
            let dst = gemini_dir.join(rel);
            log.push(format!(
                "[dry-run] would deploy '{}' (mode 0644, {} bytes)",
                dst.display(),
                bytes.len()
            ));
        }
        return Ok(None);
    }

    let mut journal = RollbackJournal::default();
    let mut created_dirs = prior_manifest
        .as_ref()
        .map(|m| m.created_dirs.clone())
        .unwrap_or_default();

    let run_res = (|| -> Result<(), String> {
        if !gemini_existed {
            fs::create_dir(&gemini_dir)
                .map_err(|e| format!("failed creating '{}': {e}", gemini_dir.display()))?;
            journal.created_dirs.push(gemini_dir.clone());
            if !created_dirs.iter().any(|d| d.is_empty()) {
                created_dirs.push(String::new());
            }
        }
        if !agents_existed {
            fs::create_dir(&gemini_agents)
                .map_err(|e| format!("failed creating '{}': {e}", gemini_agents.display()))?;
            journal.created_dirs.push(gemini_agents.clone());
            if !created_dirs.iter().any(|d| d == "agents") {
                created_dirs.push("agents".to_string());
            }
        }

        let mut entries = Vec::with_capacity(staged.len());
        for (rel, bytes, mg) in staged {
            let dst = gemini_dir.join(&rel);
            let prior_e = prior_manifest.as_ref().and_then(|m| m.entry_for(&rel));
            let entry = write_bundle_provenance_file(
                &dst,
                &rel,
                &bytes,
                mg,
                prior_e,
                0o644,
                true,
                &mut journal,
                log,
            )?;
            entries.push(entry);
        }
        let new_manifest = BundleProvenanceManifest {
            created_dirs,
            entries,
        };
        write_bundle_manifest_file(&manifest_path, &new_manifest, 0o644, true, &mut journal)?;
        Ok(())
    })();

    if let Err(e) = run_res {
        journal.rollback();
        return Err(e);
    }
    Ok(Some(journal))
}

fn deploy_canonical_dotagent_mirrors(
    dotagent_root: &Path,
    dry_run: bool,
    log: &mut Vec<String>,
) -> Result<(), String> {
    let subdirs = [
        ".claude",
        ".claude/agents",
        ".cursor",
        ".cursor/agents",
        ".codex",
        ".codex/agents",
    ];
    for sub in subdirs {
        let _ = validate_optional_dir_lstat(&dotagent_root.join(sub), "harness directory")?;
    }
    if !dry_run {
        for sub in [".claude/agents", ".cursor/agents", ".codex/agents"] {
            fs::create_dir_all(dotagent_root.join(sub)).map_err(|e| {
                format!(
                    "failed creating '{}': {e}",
                    dotagent_root.join(sub).display()
                )
            })?;
        }
    }
    let pairs: &[(&str, &str)] = &[
        ("dist/AGENTS.md", "AGENTS.md"),
        ("dist/.ignore", ".ignore"),
        ("dist/cursor/.cursorignore", ".cursorignore"),
        ("dist/codex/config.toml", ".codex/config.toml"),
        ("dist/claude/settings.json", ".claude/settings.json"),
        ("dist/cursor/hooks.json", ".cursor/hooks.json"),
    ];
    for &(src_rel, dst_rel) in pairs {
        let dst = dotagent_root.join(dst_rel);
        let _ = validate_optional_regular_file_lstat(&dst, "harness mirror")?;
        let bytes = fs::read(dotagent_root.join(src_rel))
            .map_err(|e| format!("missing '{src_rel}': {e}"))?;
        if !dry_run && dst.is_file() && fs::read(&dst).ok().as_deref() == Some(bytes.as_slice()) {
            continue;
        }
        write_with_nondestructive_backup(&dst, &bytes, 0o644, false, dry_run, log)?;
    }
    for af in AGENT_MD_FILES {
        for (dist_sub, dst_sub) in [
            ("dist/claude/agents", ".claude/agents"),
            ("dist/cursor/agents", ".cursor/agents"),
            ("dist/codex/agents", ".codex/agents"),
        ] {
            let dst = dotagent_root.join(dst_sub).join(af);
            let _ = validate_optional_regular_file_lstat(&dst, "harness agent mirror")?;
            let bytes = fs::read(dotagent_root.join(dist_sub).join(af))
                .map_err(|e| format!("missing '{dist_sub}/{af}': {e}"))?;
            if !dry_run && dst.is_file() && fs::read(&dst).ok().as_deref() == Some(bytes.as_slice())
            {
                continue;
            }
            write_with_nondestructive_backup(&dst, &bytes, 0o644, false, dry_run, log)?;
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
    verify_all_dist_manifest_sources(dotagent_root)?;
    if !is_external {
        return deploy_canonical_dotagent_mirrors(dotagent_root, dry_run, log);
    }

    validate_existing_regular_dir_lstat(target_root, "target workspace")?;
    if !dry_run {
        let pre_failures = crate::antigravity_adapter::audit_workspace_scoped(target_root);
        if !pre_failures.is_empty() {
            return Err(format!(
                "target workspace '{}' failed security audit: {}",
                target_root.display(),
                pre_failures.join("; ")
            ));
        }
    }

    let dir_rels = [
        ".claude",
        ".claude/agents",
        ".cursor",
        ".cursor/agents",
        ".codex",
        ".codex/agents",
    ];
    let mut dir_existed = Vec::with_capacity(dir_rels.len());
    for rel_d in &dir_rels {
        let existed = validate_optional_dir_lstat(&target_root.join(rel_d), "harness directory")?;
        dir_existed.push((*rel_d, existed));
    }

    let allowed_rels = workspace_managed_rel_paths();
    let manifest_path = target_root.join(BUNDLE_PROVENANCE_FILE);
    let prior_manifest =
        if validate_optional_regular_file_lstat(&manifest_path, "workspace provenance manifest")?
            .is_some()
        {
            let raw = fs::read_to_string(&manifest_path)
                .map_err(|e| format!("failed reading '{}': {e}", manifest_path.display()))?;
            Some(BundleProvenanceManifest::parse(&raw, &allowed_rels)?)
        } else {
            None
        };

    let mut staged: Vec<(String, Vec<u8>, Option<JsonValue>)> =
        Vec::with_capacity(allowed_rels.len());
    for &(src_rel, dst_rel) in &[
        ("dist/AGENTS.md", "AGENTS.md"),
        ("dist/.ignore", ".ignore"),
        ("dist/cursor/.cursorignore", ".cursorignore"),
    ] {
        let bytes = fs::read(dotagent_root.join(src_rel))
            .map_err(|e| format!("missing '{src_rel}': {e}"))?;
        staged.push((dst_rel.to_string(), bytes, None));
    }

    let codex_tpl = fs::read_to_string(dotagent_root.join("dist/codex/config.toml"))
        .map_err(|e| format!("missing 'dist/codex/config.toml': {e}"))?;
    let codex_bytes = pin_codex_notify_toml(&codex_tpl, abs_guard_bin)?.into_bytes();
    staged.push((".codex/config.toml".to_string(), codex_bytes, None));

    let claude_tpl = fs::read_to_string(dotagent_root.join("dist/claude/settings.json"))
        .map_err(|e| format!("missing dist/claude/settings.json: {e}"))?;
    let claude_dst = target_root.join(".claude/settings.json");
    let existing_claude = if dir_existed[0].1
        && validate_optional_regular_file_lstat(&claude_dst, "Claude settings.json")?.is_some()
    {
        Some(
            fs::read_to_string(&claude_dst)
                .map_err(|e| format!("failed reading existing '{}': {e}", claude_dst.display()))?,
        )
    } else {
        None
    };
    let (merged_claude, pinned_claude_tpl) = merge_settings_json_preserving_user_prefs(
        existing_claude.as_deref(),
        &claude_tpl,
        abs_guard_bin,
        Some("claude"),
    )?;
    staged.push((
        ".claude/settings.json".to_string(),
        merged_claude.into_bytes(),
        Some(pinned_claude_tpl),
    ));

    let cursor_tpl = fs::read_to_string(dotagent_root.join("dist/cursor/hooks.json"))
        .map_err(|e| format!("missing dist/cursor/hooks.json: {e}"))?;
    let cursor_dst = target_root.join(".cursor/hooks.json");
    let existing_cursor = if dir_existed[2].1
        && validate_optional_regular_file_lstat(&cursor_dst, "Cursor hooks.json")?.is_some()
    {
        Some(
            fs::read_to_string(&cursor_dst)
                .map_err(|e| format!("failed reading existing '{}': {e}", cursor_dst.display()))?,
        )
    } else {
        None
    };
    let (merged_cursor, pinned_cursor_tpl) = merge_cursor_hooks_json_preserving_siblings(
        existing_cursor.as_deref(),
        &cursor_tpl,
        abs_guard_bin,
    )?;
    staged.push((
        ".cursor/hooks.json".to_string(),
        merged_cursor.into_bytes(),
        Some(pinned_cursor_tpl),
    ));

    for af in AGENT_MD_FILES {
        for (dist_sub, dst_sub) in [
            ("dist/claude/agents", ".claude/agents"),
            ("dist/cursor/agents", ".cursor/agents"),
            ("dist/codex/agents", ".codex/agents"),
        ] {
            let bytes = fs::read(dotagent_root.join(dist_sub).join(af))
                .map_err(|e| format!("missing '{dist_sub}/{af}': {e}"))?;
            staged.push((format!("{dst_sub}/{af}"), bytes, None));
        }
    }

    for (rel, _, _) in &staged {
        let dst = target_root.join(rel);
        let parent_exists = dst.parent().is_some_and(|p| p == target_root || p.is_dir());
        if parent_exists {
            let _ = validate_optional_regular_file_lstat(&dst, "harness target")?;
            let _ = validate_optional_regular_file_lstat(
                &backup_path_for(&dst),
                "harness target backup",
            )?;
        }
    }

    if dry_run {
        for (rel, bytes, _) in &staged {
            log.push(format!(
                "[dry-run] would deploy '{}' (mode {:04o}, {} bytes)",
                target_root.join(rel).display(),
                mode,
                bytes.len()
            ));
        }
        deploy_antigravity_workspace_plane(
            dotagent_root,
            target_root,
            abs_guard_bin,
            None,
            mode,
            true,
            log,
        )?;
        return Ok(());
    }

    let mut journal = RollbackJournal::default();
    let mut created_dirs = prior_manifest
        .as_ref()
        .map(|m| m.created_dirs.clone())
        .unwrap_or_default();

    let run_res = (|| -> Result<(), String> {
        for &(rel_d, existed) in &dir_existed {
            if !existed {
                let dp = target_root.join(rel_d);
                fs::create_dir(&dp)
                    .map_err(|e| format!("failed creating '{}': {e}", dp.display()))?;
                journal.created_dirs.push(dp);
                if !created_dirs.iter().any(|d| d == rel_d) {
                    created_dirs.push(rel_d.to_string());
                }
            }
        }

        let mut entries = Vec::with_capacity(staged.len());
        for (rel, bytes, mg) in staged {
            let dst = target_root.join(&rel);
            let prior_e = prior_manifest.as_ref().and_then(|m| m.entry_for(&rel));
            let entry = write_bundle_provenance_file(
                &dst,
                &rel,
                &bytes,
                mg,
                prior_e,
                mode,
                false,
                &mut journal,
                log,
            )?;
            entries.push(entry);
        }

        let new_manifest = BundleProvenanceManifest {
            created_dirs,
            entries,
        };
        write_bundle_manifest_file(&manifest_path, &new_manifest, mode, false, &mut journal)?;

        deploy_antigravity_workspace_plane(
            dotagent_root,
            target_root,
            abs_guard_bin,
            None,
            mode,
            false,
            log,
        )?;
        Ok(())
    })();

    if let Err(e) = run_res {
        journal.rollback();
        return Err(e);
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
    validate_existing_regular_dir_lstat(home, "HOME directory")?;
    validate_existing_regular_dir_lstat(target_ws, "target workspace")?;
    verify_all_dist_manifest_sources(dotagent_root)?;

    let canon_dotagent =
        fs::canonicalize(dotagent_root).unwrap_or_else(|_| dotagent_root.to_path_buf());
    let canon_target = fs::canonicalize(target_ws).unwrap_or_else(|_| target_ws.to_path_buf());
    let is_external_target = canon_target != canon_dotagent;

    let verified_guard_buf: Option<PathBuf> = if is_external_target {
        Some(resolve_verified_guard_binary(bin_dir)?)
    } else {
        let _ = validate_optional_dir_lstat(bin_dir, "guard binary directory")?;
        if fs::symlink_metadata(bin_dir.join("agent-guard")).is_ok()
            || fs::symlink_metadata(bin_dir.join("dotagent")).is_ok()
        {
            Some(resolve_verified_guard_binary(bin_dir)?)
        } else if let Ok(cur_exe) = std::env::current_exe()
            && cur_exe
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == "agent-guard" || n == "dotagent")
        {
            Some(verify_guard_binary_path(&cur_exe)?)
        } else {
            None
        }
    };
    let abs_guard_opt = verified_guard_buf.as_deref();

    if is_external_target && !dry_run {
        let pre_failures = crate::antigravity_adapter::audit_workspace_scoped(target_ws);
        if !pre_failures.is_empty() {
            return Err(format!(
                "target workspace '{}' failed security audit: {}",
                target_ws.display(),
                pre_failures.join("; ")
            ));
        }
    }

    // 1. State directory (0700) & shell PATH wiring (.bashrc + .zshenv)
    let local_dir = home.join(".local");
    let local_state = local_dir.join("state");
    let state_root = local_state.join("agent-guard");
    let state_sessions = state_root.join("sessions");
    for sd in [&local_dir, &local_state, &state_root, &state_sessions] {
        let _ = validate_optional_dir_lstat(sd, "agent-guard state directory")?;
    }
    if !dry_run {
        fs::create_dir_all(&state_sessions)
            .map_err(|e| format!("failed creating '{}': {e}", state_sessions.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700));
            let _ = fs::set_permissions(&state_sessions, fs::Permissions::from_mode(0o700));
        }
    }
    ensure_shell_rc_path(home, bin_dir, dry_run, &mut log)?;

    // 2. Enforce all 19 global Git hardening keys (preserving user.name & user.email)
    enforce_global_git_settings(dry_run, &mut log)?;

    if !dry_run && let Err(errs) = audit_repository(dotagent_root) {
        return Err(format!(
            "dotagent repository audit failed: {}",
            errs.join("; ")
        ));
    }

    // 3. Deploy ~/.gemini global constitution, merged settings.json, and 7 subagents
    let mut gemini_journal =
        deploy_gemini_home_plane(dotagent_root, home, abs_guard_opt, dry_run, &mut log)?;

    // 4. Deploy canonical mirrors in dotagent_root ONLY when activating dotagent_root itself
    //    (never write into read-only release bundles like ~/.local/share/dotagent).
    if !is_external_target {
        if let Err(e) = deploy_workspace_bundle(
            dotagent_root,
            dotagent_root,
            0o644,
            false,
            None,
            dry_run,
            &mut log,
        ) {
            if let Some(ref mut gj) = gemini_journal {
                gj.rollback();
            }
            return Err(e);
        }
        invalidate_or_purge_swarm_state(dotagent_root, false, dry_run, &mut log)?;
    } else {
        // 5. Deploy external target_ws (0444 read-only control plane, provenance backups + pinned binary path)
        if let Err(e) = deploy_workspace_bundle(
            dotagent_root,
            target_ws,
            0o444,
            true,
            abs_guard_opt,
            dry_run,
            &mut log,
        ) {
            if let Some(ref mut gj) = gemini_journal {
                gj.rollback();
            }
            return Err(e);
        }
        invalidate_or_purge_swarm_state(target_ws, false, dry_run, &mut log)?;
        if !dry_run
            && target_ws.join(".git").exists()
            && let Err(errs) = audit_repository(target_ws)
        {
            let _ = execute_workspace_only_deactivate(target_ws, false);
            if let Some(ref mut gj) = gemini_journal {
                gj.rollback();
            }
            return Err(format!(
                "target workspace '{}' failed security audit: {}",
                target_ws.display(),
                errs.join("; ")
            ));
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

    let verified_guard = resolve_verified_guard_binary(bin_dir)?;

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
    if !dry_run
        && target_ws.join(".git").exists()
        && let Err(errs) = audit_repository(target_ws)
    {
        let _ = execute_workspace_only_deactivate(target_ws, false);
        return Err(format!(
            "target workspace '{}' failed security audit: {}",
            target_ws.display(),
            errs.join("; ")
        ));
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

struct ValidatedBundleDeactivation {
    root: PathBuf,
    manifest_path: PathBuf,
    created_dirs: Vec<String>,
    actions: Vec<PlannedDeactivation>,
}

fn plan_bundle_deactivation(
    root: &Path,
    allowed_rels: &[String],
    plane_label: &str,
    root_must_exist: bool,
) -> Result<Option<ValidatedBundleDeactivation>, String> {
    if root_must_exist {
        validate_existing_regular_dir_lstat(root, plane_label)?;
    } else if !validate_optional_dir_lstat(root, plane_label)? {
        return Ok(None);
    }

    let manifest_path = root.join(BUNDLE_PROVENANCE_FILE);
    let manifest_meta =
        validate_optional_regular_file_lstat(&manifest_path, "bundle provenance manifest")?;

    if manifest_meta.is_none() {
        for rel in allowed_rels {
            let t = root.join(rel);
            let parent_ok = match t.parent() {
                Some(p) if p != root => validate_optional_dir_lstat(p, "harness directory")?,
                _ => true,
            };
            if parent_ok {
                let bak = backup_path_for(&t);
                if validate_optional_regular_file_lstat(&bak, "bundle backup")?.is_some() {
                    return Err(format!(
                        "{plane_label} backup '{}' exists without provenance manifest '{}'; preserving backup and refusing destructive cleanup",
                        bak.display(),
                        manifest_path.display()
                    ));
                }
            }
        }
        return Ok(None);
    }

    let raw_manifest = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("failed reading '{}': {e}", manifest_path.display()))?;
    let manifest = BundleProvenanceManifest::parse(&raw_manifest, allowed_rels)?;

    let mut actions = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        let target = root.join(&entry.rel_path);
        if let Some(parent) = target.parent()
            && parent != root
        {
            validate_existing_regular_dir_lstat(parent, "managed parent directory")?;
        }
        let Some(tmeta) = validate_optional_regular_file_lstat(&target, "managed bundle file")?
        else {
            return Err(format!(
                "managed {plane_label} file '{}' was removed outside deactivation; preserving backups and provenance manifest",
                target.display()
            ));
        };
        let current_bytes =
            fs::read(&target).map_err(|e| format!("failed reading '{}': {e}", target.display()))?;
        let current_sha = crate::crypto::sha256_hex(&current_bytes);
        #[cfg(unix)]
        let current_mode = {
            use std::os::unix::fs::PermissionsExt;
            Some(tmeta.permissions().mode() & 0o777)
        };
        #[cfg(not(unix))]
        let current_mode: Option<u32> = {
            let _ = &tmeta;
            None
        };

        let is_cursor_hooks = entry.rel_path == ".cursor/hooks.json";
        if let Some(ref exp_tpl) = entry.managed_group {
            let user_remaining = verify_managed_json_intact_and_extract_user_part(
                &current_bytes,
                exp_tpl,
                is_cursor_hooks,
                &target,
            )?;
            if entry.pre_existing {
                let bak = backup_path_for(&target);
                let Some(bmeta) =
                    validate_optional_regular_file_lstat(&bak, "managed JSON backup")?
                else {
                    return Err(format!(
                        "missing required backup '{}' for pre-existing '{}'",
                        bak.display(),
                        target.display()
                    ));
                };
                let bak_bytes = fs::read(&bak)
                    .map_err(|e| format!("failed reading '{}': {e}", bak.display()))?;
                if let Some(ref exp_orig) = entry.orig_sha256
                    && crate::crypto::sha256_hex(&bak_bytes) != *exp_orig
                {
                    return Err(format!(
                        "backup integrity mismatch on '{}'; refusing destructive restore",
                        bak.display()
                    ));
                }
                #[cfg(unix)]
                let bak_mode = {
                    use std::os::unix::fs::PermissionsExt;
                    Some(bmeta.permissions().mode() & 0o777)
                };
                #[cfg(not(unix))]
                let bak_mode: Option<u32> = {
                    let _ = &bmeta;
                    None
                };
                let restore_mode = entry.orig_mode.or(bak_mode);
                let orig_user = std::str::from_utf8(&bak_bytes)
                    .ok()
                    .and_then(|s| JsonValue::parse(s).ok())
                    .and_then(|v| {
                        extract_user_part_from_merged_json(&v, exp_tpl, is_cursor_hooks).ok()
                    });

                if current_sha == entry.deployed_sha256
                    && orig_user.as_ref() == Some(&user_remaining)
                {
                    actions.push(PlannedDeactivation::RestoreBackup {
                        target,
                        bak,
                        bytes: bak_bytes,
                        mode: restore_mode,
                    });
                } else {
                    let mut updated = String::new();
                    format_json_pretty_2space(
                        &JsonValue::Object(user_remaining.clone()),
                        0,
                        &mut updated,
                    );
                    updated.push('\n');
                    actions.push(PlannedDeactivation::RewriteHooks {
                        target,
                        bak_to_remove: Some(bak),
                        content: updated,
                        mode: restore_mode.or(current_mode),
                        remaining_count: user_remaining.len(),
                    });
                }
            } else if user_remaining.is_empty() {
                actions.push(PlannedDeactivation::RemoveCreated { target });
            } else {
                let mut updated = String::new();
                format_json_pretty_2space(
                    &JsonValue::Object(user_remaining.clone()),
                    0,
                    &mut updated,
                );
                updated.push('\n');
                let mode = match current_mode {
                    Some(0o444) | None => Some(0o644),
                    other => other,
                };
                actions.push(PlannedDeactivation::RewriteHooks {
                    target,
                    bak_to_remove: None,
                    content: updated,
                    mode,
                    remaining_count: user_remaining.len(),
                });
            }
        } else {
            if current_sha != entry.deployed_sha256 {
                return Err(format!(
                    "managed {plane_label} file '{}' was modified externally; preserving backups and provenance manifest",
                    target.display()
                ));
            }
            if entry.pre_existing {
                let bak = backup_path_for(&target);
                let Some(bmeta) = validate_optional_regular_file_lstat(&bak, "bundle backup")?
                else {
                    return Err(format!(
                        "missing required backup '{}' for pre-existing '{}'",
                        bak.display(),
                        target.display()
                    ));
                };
                let bak_bytes = fs::read(&bak)
                    .map_err(|e| format!("failed reading '{}': {e}", bak.display()))?;
                if let Some(ref exp_orig) = entry.orig_sha256
                    && crate::crypto::sha256_hex(&bak_bytes) != *exp_orig
                {
                    return Err(format!(
                        "backup integrity mismatch on '{}'; refusing destructive restore",
                        bak.display()
                    ));
                }
                #[cfg(unix)]
                let bak_mode = {
                    use std::os::unix::fs::PermissionsExt;
                    Some(bmeta.permissions().mode() & 0o777)
                };
                #[cfg(not(unix))]
                let bak_mode: Option<u32> = {
                    let _ = &bmeta;
                    None
                };
                actions.push(PlannedDeactivation::RestoreBackup {
                    target,
                    bak,
                    bytes: bak_bytes,
                    mode: entry.orig_mode.or(bak_mode),
                });
            } else {
                actions.push(PlannedDeactivation::RemoveCreated { target });
            }
        }
    }

    Ok(Some(ValidatedBundleDeactivation {
        root: root.to_path_buf(),
        manifest_path,
        created_dirs: manifest.created_dirs,
        actions,
    }))
}

fn execute_bundle_deactivation(
    plan: ValidatedBundleDeactivation,
    use_cp_semantics: bool,
    dry_run: bool,
) -> Result<Vec<String>, String> {
    let mut log = Vec::new();
    if dry_run {
        for action in &plan.actions {
            match action {
                PlannedDeactivation::RestoreBackup { target, bak, .. } => {
                    log.push(format!(
                        "[dry-run] would restore '{}' -> '{}'",
                        bak.display(),
                        target.display()
                    ));
                }
                PlannedDeactivation::RewriteHooks {
                    target,
                    remaining_count,
                    ..
                } => {
                    log.push(format!(
                        "[dry-run] would strip dotagent entries from '{}' while preserving {} user entry/group(s)",
                        target.display(),
                        remaining_count
                    ));
                }
                PlannedDeactivation::RemoveCreated { target } => {
                    log.push(format!(
                        "[dry-run] would remove deployed '{}'",
                        target.display()
                    ));
                }
            }
        }
        log.push(format!(
            "[dry-run] would remove provenance manifest '{}'",
            plan.manifest_path.display()
        ));
        return Ok(log);
    }

    for action in plan.actions {
        match action {
            PlannedDeactivation::RestoreBackup {
                target,
                bak,
                bytes,
                mode,
            } => {
                write_target_bytes_with_mode(
                    &target,
                    &bytes,
                    mode.unwrap_or(0o644),
                    use_cp_semantics,
                )?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&bak, fs::Permissions::from_mode(0o600));
                }
                fs::remove_file(&bak)
                    .map_err(|e| format!("failed removing backup '{}': {e}", bak.display()))?;
                log.push(format!(
                    "[restore] restored pre-existing '{}' from backup",
                    target.display()
                ));
            }
            PlannedDeactivation::RewriteHooks {
                target,
                bak_to_remove,
                content,
                mode,
                remaining_count,
            } => {
                write_target_bytes_with_mode(
                    &target,
                    content.as_bytes(),
                    mode.unwrap_or(0o644),
                    use_cp_semantics,
                )?;
                if let Some(bak) = bak_to_remove {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(&bak, fs::Permissions::from_mode(0o600));
                    }
                    fs::remove_file(&bak)
                        .map_err(|e| format!("failed removing backup '{}': {e}", bak.display()))?;
                }
                log.push(format!(
                    "[restore] removed dotagent managed settings from '{}' while preserving {} user entry/group(s)",
                    target.display(),
                    remaining_count
                ));
            }
            PlannedDeactivation::RemoveCreated { target } => {
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

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&plan.manifest_path, fs::Permissions::from_mode(0o600));
    }
    fs::remove_file(&plan.manifest_path).map_err(|e| {
        format!(
            "failed removing provenance manifest '{}': {e}",
            plan.manifest_path.display()
        )
    })?;
    for rel_d in plan.created_dirs.iter().rev() {
        let dp = if rel_d.is_empty() {
            plan.root.clone()
        } else {
            plan.root.join(rel_d)
        };
        let _ = fs::remove_dir(&dp);
    }
    Ok(log)
}

pub fn execute_deactivate(
    home: &Path,
    target_ws: &Path,
    dry_run: bool,
) -> Result<Vec<String>, String> {
    validate_existing_regular_dir_lstat(home, "HOME directory")?;
    let ws_plan =
        plan_bundle_deactivation(target_ws, &workspace_managed_rel_paths(), "workspace", true)?;
    let gemini_dir = home.join(".gemini");
    let gemini_plan = plan_bundle_deactivation(
        &gemini_dir,
        &gemini_managed_rel_paths(),
        "Gemini home",
        false,
    )?;
    // Pre-validate Antigravity plane before mutating any plane so cross-plane deactivation is atomic.
    let _ = execute_antigravity_deactivate(target_ws, true)?;

    let mut log = Vec::new();
    match ws_plan {
        Some(p) => log.extend(execute_bundle_deactivation(p, false, dry_run)?),
        None => log.push(format!(
            "[deactivate] No managed workspace bundle provenance in '{}'.",
            target_ws.display()
        )),
    }
    if let Some(gp) = gemini_plan {
        log.extend(execute_bundle_deactivation(gp, true, dry_run)?);
    }
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
    let ws_plan =
        plan_bundle_deactivation(target_ws, &workspace_managed_rel_paths(), "workspace", true)?;
    let _ = execute_antigravity_deactivate(target_ws, true)?;

    let mut log = Vec::new();
    match ws_plan {
        Some(p) => log.extend(execute_bundle_deactivation(p, false, dry_run)?),
        None => log.push(format!(
            "[deactivate] No managed workspace bundle provenance in '{}'.",
            target_ws.display()
        )),
    }
    let ag_lines = execute_antigravity_deactivate(target_ws, dry_run)?;
    log.extend(ag_lines);
    log.push(format!(
        "[deactivate] Completed workspace-only deactivation for '{}'.",
        target_ws.display()
    ));
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
    let mut header = Vec::with_capacity(4096);
    {
        use std::io::Read;
        let f = fs::File::open(&abs)
            .map_err(|e| format!("failed opening agent-guard binary '{}': {e}", abs.display()))?;
        f.take(4096)
            .read_to_end(&mut header)
            .map_err(|e| format!("failed reading agent-guard binary '{}': {e}", abs.display()))?;
    }
    if !crate::enforcement_state::is_valid_host_native_executable(&header) {
        return Err(format!(
            "agent-guard binary '{}' is not a valid native executable for this host OS/arch",
            abs.display()
        ));
    }
    let _ = quote_antigravity_path_arg(&abs, "agent-guard binary path")?;
    Ok(abs)
}

fn resolve_verified_guard_binary(bin_dir: &Path) -> Result<PathBuf, String> {
    validate_existing_regular_dir_lstat(bin_dir, "guard binary directory")?;
    let primary = bin_dir.join("agent-guard");
    if fs::symlink_metadata(&primary).is_ok() {
        return verify_guard_binary_path(&primary);
    }
    let secondary = bin_dir.join("dotagent");
    if fs::symlink_metadata(&secondary).is_ok() {
        return verify_guard_binary_path(&secondary);
    }
    Err(format!(
        "verified 'agent-guard' binary not found in '{}' (build and install binaries first or pass --bin-dir <dir>)",
        bin_dir.display()
    ))
}

fn is_safe_manifest_rel_path(rel: &str) -> bool {
    !rel.is_empty()
        && !rel.starts_with('/')
        && !rel.ends_with('/')
        && !rel.contains('\\')
        && rel
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

fn verify_all_dist_manifest_sources(dotagent_root: &Path) -> Result<(), String> {
    validate_existing_regular_dir_lstat(dotagent_root, "dotagent bundle root")?;
    validate_existing_regular_dir_lstat(&dotagent_root.join("dist"), "dist directory")?;
    let verify_dir = dotagent_root.join("dist-verify");
    validate_existing_regular_dir_lstat(&verify_dir, "dist-verify directory")?;

    let manifest_path = verify_dir.join("manifest.sha256");
    if validate_optional_regular_file_lstat(&manifest_path, "dist-verify/manifest.sha256")?
        .is_none()
    {
        return Err(
            "missing required bundle integrity manifest 'dist-verify/manifest.sha256'".to_string(),
        );
    }
    let raw_manifest = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("failed reading '{}': {e}", manifest_path.display()))?;
    let mut expected_hashes = std::collections::BTreeMap::new();
    for (line_idx, line) in raw_manifest.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let (Some(h), Some(rel), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(format!(
                "malformed entry at line {} in 'dist-verify/manifest.sha256'",
                line_idx + 1
            ));
        };
        if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "invalid SHA-256 digest for '{rel}' at line {} in 'dist-verify/manifest.sha256'",
                line_idx + 1
            ));
        }
        if !is_safe_manifest_rel_path(rel) {
            return Err(format!(
                "unsafe path '{rel}' at line {} in 'dist-verify/manifest.sha256'",
                line_idx + 1
            ));
        }
        if expected_hashes
            .insert(rel.to_string(), h.to_ascii_lowercase())
            .is_some()
        {
            return Err(format!(
                "duplicate SHA-256 entry for '{rel}' in 'dist-verify/manifest.sha256'"
            ));
        }
    }
    if expected_hashes.is_empty() {
        return Err("bundle integrity manifest 'dist-verify/manifest.sha256' is empty".to_string());
    }

    let mut required = vec![
        "dist/AGENTS.md".to_string(),
        "dist/.ignore".to_string(),
        "dist/cursor/.cursorignore".to_string(),
        "dist/codex/config.toml".to_string(),
        "dist/claude/settings.json".to_string(),
        "dist/cursor/hooks.json".to_string(),
        "dist/gemini/GEMINI.md".to_string(),
        "dist/gemini/settings.json".to_string(),
        "dist/antigravity/hooks.json".to_string(),
        "dist/gitconfig.hardened".to_string(),
    ];
    for af in AGENT_MD_FILES {
        for sub in [
            "dist/claude/agents",
            "dist/cursor/agents",
            "dist/codex/agents",
            "dist/gemini/agents",
            "dist/antigravity/agents",
        ] {
            required.push(format!("{sub}/{af}"));
        }
    }
    for req in &required {
        if !expected_hashes.contains_key(req) {
            return Err(format!(
                "bundle manifest missing required SHA-256 entry for '{req}'"
            ));
        }
    }

    for (rel, exp) in &expected_hashes {
        let mut cur = dotagent_root.to_path_buf();
        let parts: Vec<&str> = rel.split('/').collect();
        for dir_seg in &parts[..parts.len().saturating_sub(1)] {
            cur.push(dir_seg);
            validate_existing_regular_dir_lstat(&cur, "bundle parent directory")?;
        }
        let full = dotagent_root.join(rel);
        if validate_optional_regular_file_lstat(&full, rel)?.is_none() {
            return Err(format!("missing bundle artifact '{rel}'"));
        }
        let bytes = fs::read(&full).map_err(|e| format!("failed reading '{rel}': {e}"))?;
        let actual = crate::crypto::sha256_hex(&bytes);
        if &actual != exp {
            return Err(format!(
                "bundle integrity mismatch on '{rel}': expected {exp}, got {actual}"
            ));
        }
    }
    Ok(())
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
    let verify_dir = dotagent_root.join("dist-verify");
    validate_existing_regular_dir_lstat(&verify_dir, "dist-verify directory")?;

    let manifest_path = verify_dir.join("manifest.sha256");
    if validate_optional_regular_file_lstat(&manifest_path, "dist-verify/manifest.sha256")?
        .is_none()
    {
        return Err(
            "missing required bundle integrity manifest 'dist-verify/manifest.sha256'".to_string(),
        );
    }
    let raw_manifest = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("failed reading '{}': {e}", manifest_path.display()))?;
    let mut expected_hashes = std::collections::BTreeMap::new();
    for (line_idx, line) in raw_manifest.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let (Some(h), Some(rel), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(format!(
                "malformed entry at line {} in 'dist-verify/manifest.sha256'",
                line_idx + 1
            ));
        };
        if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "invalid SHA-256 digest for '{rel}' at line {} in 'dist-verify/manifest.sha256'",
                line_idx + 1
            ));
        }
        if expected_hashes
            .insert(rel.to_string(), h.to_ascii_lowercase())
            .is_some()
        {
            return Err(format!(
                "duplicate SHA-256 entry for '{rel}' in 'dist-verify/manifest.sha256'"
            ));
        }
    }
    if expected_hashes.is_empty() {
        return Err("bundle integrity manifest 'dist-verify/manifest.sha256' is empty".to_string());
    }

    let hooks_rel = "dist/antigravity/hooks.json";
    let hooks_path = dotagent_root.join(hooks_rel);
    if validate_optional_regular_file_lstat(&hooks_path, hooks_rel)?.is_none() {
        return Err(format!("missing bundle artifact '{hooks_rel}'"));
    }
    let Some(exp_hooks) = expected_hashes.get(hooks_rel) else {
        return Err(format!(
            "bundle manifest missing required SHA-256 entry for '{hooks_rel}'"
        ));
    };
    let hooks_bytes =
        fs::read(&hooks_path).map_err(|e| format!("failed reading '{hooks_rel}': {e}"))?;
    let actual_hooks = crate::crypto::sha256_hex(&hooks_bytes);
    if &actual_hooks != exp_hooks {
        return Err(format!(
            "bundle integrity mismatch on '{hooks_rel}': expected {exp_hooks}, got {actual_hooks}"
        ));
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
        let Some(exp) = expected_hashes.get(&rel) else {
            return Err(format!(
                "bundle manifest missing required SHA-256 entry for '{rel}'"
            ));
        };
        let bytes = fs::read(&p).map_err(|e| format!("failed reading '{rel}': {e}"))?;
        let actual = crate::crypto::sha256_hex(&bytes);
        if &actual != exp {
            return Err(format!(
                "bundle integrity mismatch on '{rel}': expected {exp}, got {actual}"
            ));
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

fn quote_antigravity_path_arg(path: &Path, label: &str) -> Result<String, String> {
    if !path.is_absolute() {
        return Err(format!(
            "{label} '{}' must be an absolute path",
            path.display()
        ));
    }
    let Some(s) = path.to_str() else {
        return Err(format!("{label} '{}' must be valid UTF-8", path.display()));
    };
    if s.is_empty() || s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(format!(
            "{label} '{}' contains disallowed control characters",
            path.display()
        ));
    }
    if is_safe_unquoted_path_str(s) {
        Ok(s.to_string())
    } else {
        Ok(crate::exec_sandbox::shell_quote_single(s))
    }
}

fn pin_antigravity_command_tree(
    val: &JsonValue,
    abs_guard_bin: Option<&Path>,
    abs_workspace: Option<&Path>,
    abs_trace_log: Option<&Path>,
) -> Result<JsonValue, String> {
    let Some(bin) = abs_guard_bin else {
        if abs_workspace.is_some() || abs_trace_log.is_some() {
            return Err(
                "cannot pin --workspace or --trace-log without a verified agent-guard binary"
                    .to_string(),
            );
        }
        return Ok(val.clone());
    };
    let bin_q = quote_antigravity_path_arg(bin, "agent-guard binary path")?;
    let ws_suffix = match abs_workspace {
        Some(w) => format!(
            " --workspace {}",
            quote_antigravity_path_arg(w, "workspace path")?
        ),
        None => String::new(),
    };
    let trace_suffix = match abs_trace_log {
        Some(t) => format!(
            " --trace-log {}",
            quote_antigravity_path_arg(t, "--trace-log path")?
        ),
        None => String::new(),
    };

    fn rewrite_node(
        node: &JsonValue,
        bin_q: &str,
        ws_suffix: &str,
        trace_suffix: &str,
    ) -> JsonValue {
        match node {
            JsonValue::Str(s) => {
                if let Some(rest) = s.strip_prefix("agent-guard antigravity-hook ") {
                    JsonValue::Str(format!(
                        "{bin_q} antigravity-hook {rest}{ws_suffix}{trace_suffix}"
                    ))
                } else if let Some(rest) = s.strip_prefix("agent-guard ") {
                    JsonValue::Str(format!("{bin_q} {rest}"))
                } else if s == "agent-guard" {
                    JsonValue::Str(bin_q.to_string())
                } else {
                    JsonValue::Str(s.clone())
                }
            }
            JsonValue::Array(items) => JsonValue::Array(
                items
                    .iter()
                    .map(|v| rewrite_node(v, bin_q, ws_suffix, trace_suffix))
                    .collect(),
            ),
            JsonValue::Object(entries) => JsonValue::Object(
                entries
                    .iter()
                    .map(|(k, v)| (k.clone(), rewrite_node(v, bin_q, ws_suffix, trace_suffix)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    Ok(rewrite_node(val, &bin_q, &ws_suffix, &trace_suffix))
}

/// Merges `dist/antigravity/hooks.json` into an optional pre-existing `.agents/hooks.json` without
/// discarding unrelated user hook groups, while pinning the verified `agent-guard` binary path.
pub fn merge_antigravity_hooks_json(
    existing_raw: Option<&str>,
    template_raw: &str,
    abs_guard_bin: Option<&Path>,
    abs_workspace: Option<&Path>,
) -> Result<String, String> {
    merge_antigravity_hooks_json_with_trace(
        existing_raw,
        template_raw,
        abs_guard_bin,
        abs_workspace,
        None,
    )
}

pub fn merge_antigravity_hooks_json_with_trace(
    existing_raw: Option<&str>,
    template_raw: &str,
    abs_guard_bin: Option<&Path>,
    abs_workspace: Option<&Path>,
    abs_trace_log: Option<&Path>,
) -> Result<String, String> {
    let template_parsed = JsonValue::parse(template_raw)
        .map_err(|e| format!("invalid dist/antigravity/hooks.json template: {e}"))?;
    let pinned_template = pin_antigravity_command_tree(
        &template_parsed,
        abs_guard_bin,
        abs_workspace,
        abs_trace_log,
    )?;
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

const ANTIGRAVITY_PROVENANCE_FILE: &str = ".dotagent-manifest.json";
const ANTIGRAVITY_PROVENANCE_FORMAT: &str = "dotagent.antigravity.provenance.v1";

#[derive(Debug, Clone, PartialEq)]
struct FileProvenanceEntry {
    rel_path: String,
    pre_existing: bool,
    orig_mode: Option<u32>,
    orig_sha256: Option<String>,
    deployed_sha256: String,
    managed_group: Option<JsonValue>,
}

#[derive(Debug, Clone, PartialEq)]
struct AntigravityProvenanceManifest {
    created_ag_dir: bool,
    created_agents_dir: bool,
    entries: Vec<FileProvenanceEntry>,
}

fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_valid_manifest_rel_path(rel: &str) -> bool {
    if rel == "hooks.json" {
        return true;
    }
    if let Some(rest) = rel.strip_prefix("agents/") {
        return !rest.is_empty()
            && !rest.contains('/')
            && !rest.contains('\\')
            && rest != "."
            && rest != "..";
    }
    false
}

impl AntigravityProvenanceManifest {
    fn parse(raw: &str) -> Result<Self, String> {
        let parsed = JsonValue::parse(raw)
            .map_err(|e| format!("invalid Antigravity provenance manifest JSON: {e}"))?;
        if parsed.get("format").and_then(JsonValue::as_str) != Some(ANTIGRAVITY_PROVENANCE_FORMAT) {
            return Err("unrecognized Antigravity provenance manifest format".to_string());
        }
        let created_ag_dir = parsed
            .get("created_ag_dir")
            .and_then(JsonValue::as_bool)
            .ok_or("missing boolean 'created_ag_dir' in provenance manifest")?;
        let created_agents_dir = parsed
            .get("created_agents_dir")
            .and_then(JsonValue::as_bool)
            .ok_or("missing boolean 'created_agents_dir' in provenance manifest")?;
        let arr = parsed
            .get("entries")
            .and_then(JsonValue::as_array)
            .ok_or("missing 'entries' array in provenance manifest")?;
        if arr.is_empty() {
            return Err("Antigravity provenance manifest 'entries' cannot be empty".to_string());
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut entries = Vec::with_capacity(arr.len());
        for item in arr {
            let rel_path = item
                .get("rel_path")
                .and_then(JsonValue::as_str)
                .filter(|s| is_valid_manifest_rel_path(s))
                .ok_or("invalid 'rel_path' in Antigravity provenance manifest")?
                .to_string();
            if !seen.insert(rel_path.clone()) {
                return Err(format!(
                    "duplicate provenance entry for '{rel_path}' in manifest"
                ));
            }
            let pre_existing = item
                .get("pre_existing")
                .and_then(JsonValue::as_bool)
                .ok_or("missing boolean 'pre_existing' in provenance manifest")?;
            let orig_mode = match item.get("orig_mode") {
                None | Some(JsonValue::Null) => None,
                Some(v) => {
                    let m = v
                        .as_u64()
                        .filter(|&m| m <= 0o777)
                        .ok_or("invalid 'orig_mode' in provenance manifest")?;
                    Some(m as u32)
                }
            };
            let orig_sha256 = match item.get("orig_sha256") {
                None | Some(JsonValue::Null) => None,
                Some(v) => {
                    let s = v
                        .as_str()
                        .filter(|s| is_valid_sha256_hex(s))
                        .ok_or("invalid 'orig_sha256' in provenance manifest")?;
                    Some(s.to_ascii_lowercase())
                }
            };
            if pre_existing && orig_sha256.is_none() {
                return Err(format!(
                    "pre-existing provenance entry '{rel_path}' is missing 'orig_sha256'"
                ));
            }
            let deployed_sha256 = item
                .get("deployed_sha256")
                .and_then(JsonValue::as_str)
                .filter(|s| is_valid_sha256_hex(s))
                .ok_or("invalid 'deployed_sha256' in provenance manifest")?
                .to_ascii_lowercase();
            let managed_group = match item.get("managed_group") {
                None | Some(JsonValue::Null) => None,
                Some(v) if v.as_object().is_some() => Some(v.clone()),
                Some(_) => {
                    return Err(
                        "invalid non-object 'managed_group' in provenance manifest".to_string()
                    );
                }
            };
            if rel_path == "hooks.json" && managed_group.is_none() {
                return Err(
                    "provenance entry for 'hooks.json' is missing 'managed_group'".to_string(),
                );
            }
            entries.push(FileProvenanceEntry {
                rel_path,
                pre_existing,
                orig_mode,
                orig_sha256,
                deployed_sha256,
                managed_group,
            });
        }
        Ok(Self {
            created_ag_dir,
            created_agents_dir,
            entries,
        })
    }

    fn serialize(&self) -> String {
        let items: Vec<JsonValue> = self
            .entries
            .iter()
            .map(|e| {
                JsonValue::Object(vec![
                    ("rel_path".to_string(), JsonValue::Str(e.rel_path.clone())),
                    ("pre_existing".to_string(), JsonValue::Bool(e.pre_existing)),
                    (
                        "orig_mode".to_string(),
                        e.orig_mode
                            .map_or(JsonValue::Null, |m| JsonValue::Uint(u64::from(m))),
                    ),
                    (
                        "orig_sha256".to_string(),
                        e.orig_sha256
                            .as_ref()
                            .map_or(JsonValue::Null, |s| JsonValue::Str(s.clone())),
                    ),
                    (
                        "deployed_sha256".to_string(),
                        JsonValue::Str(e.deployed_sha256.clone()),
                    ),
                    (
                        "managed_group".to_string(),
                        e.managed_group.clone().unwrap_or(JsonValue::Null),
                    ),
                ])
            })
            .collect();
        let doc = JsonValue::Object(vec![
            (
                "format".to_string(),
                JsonValue::Str(ANTIGRAVITY_PROVENANCE_FORMAT.to_string()),
            ),
            (
                "created_ag_dir".to_string(),
                JsonValue::Bool(self.created_ag_dir),
            ),
            (
                "created_agents_dir".to_string(),
                JsonValue::Bool(self.created_agents_dir),
            ),
            ("entries".to_string(), JsonValue::Array(items)),
        ]);
        let mut out = String::new();
        format_json_pretty_2space(&doc, 0, &mut out);
        out.push('\n');
        out
    }

    fn entry_for(&self, rel_path: &str) -> Option<&FileProvenanceEntry> {
        self.entries.iter().find(|e| e.rel_path == rel_path)
    }
}

#[allow(clippy::too_many_arguments)]
fn write_provenance_file_with_backup(
    target: &Path,
    rel_path: &str,
    new_bytes: &[u8],
    managed_group: Option<JsonValue>,
    prior_entry: Option<&FileProvenanceEntry>,
    default_new_mode: u32,
    preserve_existing_mode: bool,
    journal: &mut RollbackJournal,
    log: &mut Vec<String>,
) -> Result<FileProvenanceEntry, String> {
    let existing_meta = validate_optional_regular_file_lstat(target, "target file")?;
    let bak = backup_path_for(target);
    let existing_bak = validate_optional_regular_file_lstat(&bak, "backup file")?;

    #[cfg(unix)]
    let current_disk_mode = existing_meta.as_ref().map(|m| {
        use std::os::unix::fs::PermissionsExt;
        m.permissions().mode() & 0o777
    });
    #[cfg(not(unix))]
    let current_disk_mode: Option<u32> = None;

    let deployed_sha256 = crate::crypto::sha256_hex(new_bytes);

    if let Some(prior) = prior_entry {
        if prior.pre_existing && existing_bak.is_none() {
            return Err(format!(
                "missing required backup '{}' for pre-existing '{}' during re-activation",
                bak.display(),
                target.display()
            ));
        }
        let effective_mode = if prior.pre_existing && preserve_existing_mode {
            prior
                .orig_mode
                .or(current_disk_mode)
                .map(|m| m | 0o400)
                .unwrap_or(default_new_mode)
        } else {
            default_new_mode
        };

        if existing_meta.is_some() {
            let existing_bytes = fs::read(target)
                .map_err(|e| format!("failed reading '{}': {e}", target.display()))?;
            let actual_sha = crate::crypto::sha256_hex(&existing_bytes);
            if rel_path == "hooks.json" {
                let text = std::str::from_utf8(&existing_bytes)
                    .map_err(|_| format!("non-UTF-8 bytes in '{}'", target.display()))?;
                let parsed = JsonValue::parse(text)
                    .map_err(|e| format!("invalid JSON in '{}': {e}", target.display()))?;
                let entries = parsed
                    .as_object()
                    .ok_or_else(|| format!("non-object JSON in '{}'", target.display()))?;
                let cur_dg = entries
                    .iter()
                    .find(|(k, _)| k == "dotagent-guard")
                    .map(|(_, v)| v);
                let Some(cur_dg_val) = cur_dg else {
                    return Err(format!(
                        "managed 'dotagent-guard' hook group was removed externally from '{}'; preserving existing backup",
                        target.display()
                    ));
                };
                if let Some(ref exp_dg) = prior.managed_group
                    && cur_dg_val != exp_dg
                {
                    return Err(format!(
                        "managed 'dotagent-guard' hook group in '{}' was modified externally; preserving existing backup",
                        target.display()
                    ));
                }
            } else if actual_sha != prior.deployed_sha256 {
                return Err(format!(
                    "managed Antigravity file '{}' was modified externally; deactivate or restore before re-activating",
                    target.display()
                ));
            }
            journal.overwritten_files.push((
                target.to_path_buf(),
                existing_bytes,
                current_disk_mode,
            ));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(target, fs::Permissions::from_mode(0o600));
            }
        } else if prior.pre_existing {
            return Err(format!(
                "pre-existing managed file '{}' was removed externally; preserving backup '{}'",
                target.display(),
                bak.display()
            ));
        } else {
            journal.created_files.push(target.to_path_buf());
        }

        fs::write(target, new_bytes)
            .map_err(|e| format!("failed writing '{}': {e}", target.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(target, fs::Permissions::from_mode(effective_mode)).map_err(
                |e| {
                    format!(
                        "failed setting mode {:04o} on '{}': {e}",
                        effective_mode,
                        target.display()
                    )
                },
            )?;
        }
        log.push(format!(
            "[deploy] installed '{}' (mode {:04o}, {} bytes)",
            target.display(),
            effective_mode,
            new_bytes.len()
        ));
        return Ok(FileProvenanceEntry {
            rel_path: rel_path.to_string(),
            pre_existing: prior.pre_existing,
            orig_mode: prior.orig_mode,
            orig_sha256: prior.orig_sha256.clone(),
            deployed_sha256,
            managed_group,
        });
    }

    if existing_bak.is_some() {
        return Err(format!(
            "orphaned backup '{}' exists without provenance manifest; refusing to overwrite original backup",
            bak.display()
        ));
    }

    let effective_mode = if preserve_existing_mode {
        current_disk_mode
            .map(|m| m | 0o400)
            .unwrap_or(default_new_mode)
    } else {
        default_new_mode
    };

    let (pre_existing, orig_mode, orig_sha256) = if existing_meta.is_some() {
        let existing_bytes =
            fs::read(target).map_err(|e| format!("failed reading '{}': {e}", target.display()))?;
        let orig_sha = crate::crypto::sha256_hex(&existing_bytes);
        // Always preserve a durable backup and provenance record for pre-existing files,
        // even when `existing_bytes == new_bytes`, so `deactivate` restores user-owned files
        // rather than deleting them.
        fs::write(&bak, &existing_bytes).map_err(|e| {
            format!(
                "failed backing up '{}' to '{}': {e}",
                target.display(),
                bak.display()
            )
        })?;
        #[cfg(unix)]
        if let Some(m) = current_disk_mode {
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
        journal
            .overwritten_files
            .push((target.to_path_buf(), existing_bytes, current_disk_mode));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(target, fs::Permissions::from_mode(0o600));
        }
        (true, current_disk_mode, Some(orig_sha))
    } else {
        journal.created_files.push(target.to_path_buf());
        (false, None, None)
    };

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
    Ok(FileProvenanceEntry {
        rel_path: rel_path.to_string(),
        pre_existing,
        orig_mode,
        orig_sha256,
        deployed_sha256,
        managed_group,
    })
}

fn deploy_antigravity_workspace_plane(
    dotagent_root: &Path,
    target_ws: &Path,
    abs_guard_bin: Option<&Path>,
    trace_log: Option<&Path>,
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
    let validated_trace = match trace_log {
        Some(tp) => {
            let _ = quote_antigravity_path_arg(tp, "--trace-log path")?;
            if let Some(parent) = tp.parent() {
                validate_existing_regular_dir_lstat(parent, "--trace-log parent directory")?;
            }
            let _ = validate_optional_regular_file_lstat(tp, "--trace-log target file")?;
            Some(tp.to_path_buf())
        }
        None => None,
    };

    let ag_dir = detect_antigravity_workspace_dir(&abs_ws)?;
    let ag_agents_dir = ag_dir.join("agents");
    let ag_dir_exists = validate_optional_dir_lstat(&ag_dir, "Antigravity directory")?;
    let ag_agents_exists =
        validate_optional_dir_lstat(&ag_agents_dir, "Antigravity agents directory")?;

    let manifest_path = ag_dir.join(ANTIGRAVITY_PROVENANCE_FILE);
    let prior_manifest_meta =
        validate_optional_regular_file_lstat(&manifest_path, "Antigravity provenance manifest")?;
    let prior_manifest_raw_bytes = if prior_manifest_meta.is_some() {
        Some(
            fs::read(&manifest_path)
                .map_err(|e| format!("failed reading '{}': {e}", manifest_path.display()))?,
        )
    } else {
        None
    };
    let prior_manifest = match &prior_manifest_raw_bytes {
        Some(bytes) => {
            let s = std::str::from_utf8(bytes)
                .map_err(|_| format!("non-UTF-8 bytes in '{}'", manifest_path.display()))?;
            Some(AntigravityProvenanceManifest::parse(s)?)
        }
        None => None,
    };

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

    let merged_hooks = merge_antigravity_hooks_json_with_trace(
        existing_hooks_raw.as_deref(),
        &hooks_tpl,
        verified_bin.as_deref(),
        if verified_bin.is_some() {
            Some(abs_ws.as_path())
        } else {
            None
        },
        validated_trace.as_deref(),
    )?;
    let merged_parsed = JsonValue::parse(&merged_hooks)
        .map_err(|e| format!("merged hooks.json failed internal JSON check: {e}"))?;
    let managed_guard_group = merged_parsed
        .get("dotagent-guard")
        .cloned()
        .ok_or("merged hooks.json missing 'dotagent-guard' group")?;

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
        if existing_hooks_meta.is_some() && prior_manifest.is_none() && !hooks_bak.exists() {
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
        log.push(format!(
            "[dry-run] would record activation provenance '{}'",
            manifest_path.display()
        ));
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

        let mut prov_entries = Vec::with_capacity(1 + agent_blobs.len());
        let hooks_prov = write_provenance_file_with_backup(
            &hooks_dst,
            "hooks.json",
            merged_hooks.as_bytes(),
            Some(managed_guard_group),
            prior_manifest
                .as_ref()
                .and_then(|m| m.entry_for("hooks.json")),
            default_new_mode,
            true,
            &mut journal,
            log,
        )?;
        prov_entries.push(hooks_prov);

        for &(af, ref bytes) in &agent_blobs {
            let dst = ag_agents_dir.join(af);
            let rel = format!("agents/{af}");
            let agent_prov = write_provenance_file_with_backup(
                &dst,
                &rel,
                bytes,
                None,
                prior_manifest.as_ref().and_then(|m| m.entry_for(&rel)),
                default_new_mode,
                true,
                &mut journal,
                log,
            )?;
            prov_entries.push(agent_prov);
        }

        let new_manifest = AntigravityProvenanceManifest {
            created_ag_dir: prior_manifest
                .as_ref()
                .map_or(!ag_dir_exists, |m| m.created_ag_dir),
            created_agents_dir: prior_manifest
                .as_ref()
                .map_or(!ag_agents_exists, |m| m.created_agents_dir),
            entries: prov_entries,
        };
        let serialized_manifest = new_manifest.serialize();
        if let Some(prev_bytes) = prior_manifest_raw_bytes {
            #[cfg(unix)]
            let prev_mode = prior_manifest_meta.as_ref().map(|m| {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o777
            });
            #[cfg(not(unix))]
            let prev_mode: Option<u32> = None;
            journal
                .overwritten_files
                .push((manifest_path.clone(), prev_bytes, prev_mode));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600));
            }
        } else {
            journal.created_files.push(manifest_path.clone());
        }
        fs::write(&manifest_path, serialized_manifest.as_bytes())
            .map_err(|e| format!("failed writing '{}': {e}", manifest_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&manifest_path, fs::Permissions::from_mode(default_new_mode))
                .map_err(|e| {
                    format!(
                        "failed setting mode {:04o} on '{}': {e}",
                        default_new_mode,
                        manifest_path.display()
                    )
                })?;
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
///   records explicit ownership provenance in `.dotagent-manifest.json`, validates non-symlink object
///   types via `lstat`, and rolls back completely on partial failure.
pub fn execute_antigravity_activate(
    bin_dir: &Path,
    dotagent_root: &Path,
    target_ws: &Path,
    dry_run: bool,
) -> Result<Vec<String>, String> {
    execute_antigravity_activate_with_trace(bin_dir, dotagent_root, target_ws, None, dry_run)
}

pub fn execute_antigravity_activate_with_trace(
    bin_dir: &Path,
    dotagent_root: &Path,
    target_ws: &Path,
    trace_log: Option<&Path>,
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
        trace_log,
        0o444,
        dry_run,
        &mut log,
    )?;

    log.push(format!(
        "[activate] Installed workspace Antigravity hook configuration for '{}' (pinned binary='{}', global config untouched; host_enforced=unverified until observer-verified denial mediation is established; tested Antigravity Remote Agents VM configuration was not mediated).",
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
        "[activate] Installed workspace-scoped harness configuration for '{}' (global config untouched; host_enforced=unverified until observer-verified denial mediation is established).",
        target_ws.display()
    ));
    Ok(log)
}

enum PlannedDeactivation {
    RestoreBackup {
        target: PathBuf,
        bak: PathBuf,
        bytes: Vec<u8>,
        mode: Option<u32>,
    },
    RewriteHooks {
        target: PathBuf,
        bak_to_remove: Option<PathBuf>,
        content: String,
        mode: Option<u32>,
        remaining_count: usize,
    },
    RemoveCreated {
        target: PathBuf,
    },
}

/// Reversible workspace-scoped Antigravity deactivation:
/// - Verifies explicit ownership provenance in `.dotagent-manifest.json` before mutating or removing anything.
/// - Never deletes user-authored files based on `0444` mode or content markers.
/// - Preserves `.dotagent.bak` and `.dotagent-manifest.json` fail-closed whenever `hooks.json` or a
///   managed file was modified externally to remove or alter the managed `dotagent-guard` namespace.
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

    let manifest_path = ag_dir.join(ANTIGRAVITY_PROVENANCE_FILE);
    let manifest_meta =
        validate_optional_regular_file_lstat(&manifest_path, "Antigravity provenance manifest")?;

    if manifest_meta.is_none() {
        let hooks_bak = backup_path_for(&ag_dir.join("hooks.json"));
        if validate_optional_regular_file_lstat(&hooks_bak, "Antigravity hooks.json backup")?
            .is_some()
        {
            return Err(format!(
                "Antigravity backup '{}' exists without provenance manifest '{}'; preserving backup and refusing destructive cleanup",
                hooks_bak.display(),
                manifest_path.display()
            ));
        }
        let ag_agents_dir = ag_dir.join("agents");
        if validate_optional_dir_lstat(&ag_agents_dir, "Antigravity agents directory")? {
            for af in AGENT_MD_FILES {
                let bak = backup_path_for(&ag_agents_dir.join(af));
                if validate_optional_regular_file_lstat(&bak, "Antigravity agent backup")?.is_some()
                {
                    return Err(format!(
                        "Antigravity backup '{}' exists without provenance manifest '{}'; preserving backup and refusing destructive cleanup",
                        bak.display(),
                        manifest_path.display()
                    ));
                }
            }
        }
        return Ok(vec![format!(
            "[deactivate] No managed Antigravity deployment provenance in '{}'.",
            target_ws.display()
        )]);
    }

    let raw_manifest = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("failed reading '{}': {e}", manifest_path.display()))?;
    let manifest = AntigravityProvenanceManifest::parse(&raw_manifest)?;

    // Phase 1: Validate every provenance entry and backup BEFORE mutating or deleting anything.
    let mut plan = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        let target = ag_dir.join(&entry.rel_path);
        let Some(tmeta) =
            validate_optional_regular_file_lstat(&target, "managed Antigravity file")?
        else {
            return Err(format!(
                "managed Antigravity file '{}' was removed outside deactivation; preserving backups and provenance manifest",
                target.display()
            ));
        };
        let current_bytes =
            fs::read(&target).map_err(|e| format!("failed reading '{}': {e}", target.display()))?;
        let current_sha = crate::crypto::sha256_hex(&current_bytes);

        #[cfg(unix)]
        let current_mode = {
            use std::os::unix::fs::PermissionsExt;
            Some(tmeta.permissions().mode() & 0o777)
        };
        #[cfg(not(unix))]
        let current_mode: Option<u32> = {
            let _ = &tmeta;
            None
        };

        if entry.rel_path == "hooks.json" {
            let raw = std::str::from_utf8(&current_bytes).map_err(|_| {
                format!(
                    "cannot safely deactivate non-UTF-8 '{}'; preserving backup and provenance manifest",
                    target.display()
                )
            })?;
            let parsed = JsonValue::parse(raw).map_err(|e| {
                format!(
                    "cannot safely deactivate malformed '{}': {e}; preserving backup and provenance manifest",
                    target.display()
                )
            })?;
            let Some(entries) = parsed.as_object() else {
                return Err(format!(
                    "cannot safely deactivate non-object '{}'; preserving backup and provenance manifest",
                    target.display()
                ));
            };
            let Some((_, cur_dg)) = entries.iter().find(|(k, _)| k == "dotagent-guard") else {
                return Err(format!(
                    "managed 'dotagent-guard' hook group is missing from '{}' after external modification; preserving backup and provenance manifest",
                    target.display()
                ));
            };
            if let Some(ref exp_dg) = entry.managed_group
                && cur_dg != exp_dg
            {
                return Err(format!(
                    "managed 'dotagent-guard' hook group in '{}' was modified externally; preserving backup and provenance manifest",
                    target.display()
                ));
            }

            let remaining: Vec<(String, JsonValue)> = entries
                .iter()
                .filter(|(k, _)| k != "dotagent-guard")
                .cloned()
                .collect();

            if entry.pre_existing {
                let bak = backup_path_for(&target);
                let Some(bmeta) =
                    validate_optional_regular_file_lstat(&bak, "Antigravity hooks.json backup")?
                else {
                    return Err(format!(
                        "missing required backup '{}' for pre-existing '{}'",
                        bak.display(),
                        target.display()
                    ));
                };
                let bak_bytes = fs::read(&bak)
                    .map_err(|e| format!("failed reading '{}': {e}", bak.display()))?;
                if let Some(ref exp_orig) = entry.orig_sha256
                    && crate::crypto::sha256_hex(&bak_bytes) != *exp_orig
                {
                    return Err(format!(
                        "backup integrity mismatch on '{}'; refusing destructive restore",
                        bak.display()
                    ));
                }
                #[cfg(unix)]
                let bak_mode = {
                    use std::os::unix::fs::PermissionsExt;
                    Some(bmeta.permissions().mode() & 0o777)
                };
                #[cfg(not(unix))]
                let bak_mode: Option<u32> = {
                    let _ = &bmeta;
                    None
                };
                let restore_mode = entry.orig_mode.or(bak_mode);
                let orig_siblings_match = std::str::from_utf8(&bak_bytes)
                    .ok()
                    .and_then(|s| JsonValue::parse(s).ok())
                    .and_then(|v| {
                        v.as_object().map(|obj| {
                            let orig_rem: Vec<(String, JsonValue)> = obj
                                .iter()
                                .filter(|(k, _)| k != "dotagent-guard")
                                .cloned()
                                .collect();
                            orig_rem == remaining
                        })
                    })
                    .unwrap_or(false);

                if current_sha == entry.deployed_sha256 && orig_siblings_match {
                    plan.push(PlannedDeactivation::RestoreBackup {
                        target,
                        bak,
                        bytes: bak_bytes,
                        mode: restore_mode,
                    });
                } else {
                    let mut updated = String::new();
                    format_json_pretty_2space(
                        &JsonValue::Object(remaining.clone()),
                        0,
                        &mut updated,
                    );
                    updated.push('\n');
                    plan.push(PlannedDeactivation::RewriteHooks {
                        target,
                        bak_to_remove: Some(bak),
                        content: updated,
                        mode: restore_mode.or(current_mode),
                        remaining_count: remaining.len(),
                    });
                }
            } else if remaining.is_empty() {
                plan.push(PlannedDeactivation::RemoveCreated { target });
            } else {
                let mut updated = String::new();
                format_json_pretty_2space(&JsonValue::Object(remaining.clone()), 0, &mut updated);
                updated.push('\n');
                let mode = match current_mode {
                    Some(0o444) | None => Some(0o644),
                    other => other,
                };
                plan.push(PlannedDeactivation::RewriteHooks {
                    target,
                    bak_to_remove: None,
                    content: updated,
                    mode,
                    remaining_count: remaining.len(),
                });
            }
        } else {
            if current_sha != entry.deployed_sha256 {
                return Err(format!(
                    "managed Antigravity file '{}' was modified externally; preserving backups and provenance manifest",
                    target.display()
                ));
            }
            if entry.pre_existing {
                let bak = backup_path_for(&target);
                let Some(bmeta) =
                    validate_optional_regular_file_lstat(&bak, "Antigravity agent backup")?
                else {
                    return Err(format!(
                        "missing required backup '{}' for pre-existing '{}'",
                        bak.display(),
                        target.display()
                    ));
                };
                let bak_bytes = fs::read(&bak)
                    .map_err(|e| format!("failed reading '{}': {e}", bak.display()))?;
                if let Some(ref exp_orig) = entry.orig_sha256
                    && crate::crypto::sha256_hex(&bak_bytes) != *exp_orig
                {
                    return Err(format!(
                        "backup integrity mismatch on '{}'; refusing destructive restore",
                        bak.display()
                    ));
                }
                #[cfg(unix)]
                let bak_mode = {
                    use std::os::unix::fs::PermissionsExt;
                    Some(bmeta.permissions().mode() & 0o777)
                };
                #[cfg(not(unix))]
                let bak_mode: Option<u32> = {
                    let _ = &bmeta;
                    None
                };
                plan.push(PlannedDeactivation::RestoreBackup {
                    target,
                    bak,
                    bytes: bak_bytes,
                    mode: entry.orig_mode.or(bak_mode),
                });
            } else {
                plan.push(PlannedDeactivation::RemoveCreated { target });
            }
        }
    }

    // Phase 2: Execute validated plan (or report dry-run without touching disk).
    let mut log = Vec::new();
    if dry_run {
        for action in &plan {
            match action {
                PlannedDeactivation::RestoreBackup { target, bak, .. } => {
                    log.push(format!(
                        "[dry-run] would restore '{}' -> '{}'",
                        bak.display(),
                        target.display()
                    ));
                }
                PlannedDeactivation::RewriteHooks {
                    target,
                    remaining_count,
                    ..
                } => {
                    log.push(format!(
                        "[dry-run] would remove 'dotagent-guard' entry from '{}' while preserving {} user hook(s)",
                        target.display(),
                        remaining_count
                    ));
                }
                PlannedDeactivation::RemoveCreated { target } => {
                    log.push(format!(
                        "[dry-run] would remove deployed '{}'",
                        target.display()
                    ));
                }
            }
        }
        log.push(format!(
            "[dry-run] would remove provenance manifest '{}'",
            manifest_path.display()
        ));
        return Ok(log);
    }

    for action in plan {
        match action {
            PlannedDeactivation::RestoreBackup {
                target,
                bak,
                bytes,
                mode,
            } => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&target, fs::Permissions::from_mode(0o600));
                }
                fs::write(&target, bytes)
                    .map_err(|e| format!("failed restoring '{}': {e}", target.display()))?;
                #[cfg(unix)]
                if let Some(m) = mode {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&target, fs::Permissions::from_mode(m)).map_err(|e| {
                        format!(
                            "failed restoring permissions {:04o} on '{}': {e}",
                            m,
                            target.display()
                        )
                    })?;
                }
                #[cfg(not(unix))]
                let _ = mode;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&bak, fs::Permissions::from_mode(0o600));
                }
                fs::remove_file(&bak)
                    .map_err(|e| format!("failed removing backup '{}': {e}", bak.display()))?;
                log.push(format!(
                    "[restore] restored pre-existing '{}' from backup",
                    target.display()
                ));
            }
            PlannedDeactivation::RewriteHooks {
                target,
                bak_to_remove,
                content,
                mode,
                ..
            } => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&target, fs::Permissions::from_mode(0o600));
                }
                fs::write(&target, content)
                    .map_err(|e| format!("failed updating '{}': {e}", target.display()))?;
                #[cfg(unix)]
                if let Some(m) = mode {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&target, fs::Permissions::from_mode(m)).map_err(|e| {
                        format!(
                            "failed setting permissions {:04o} on '{}': {e}",
                            m,
                            target.display()
                        )
                    })?;
                }
                #[cfg(not(unix))]
                let _ = mode;
                if let Some(bak) = bak_to_remove {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(&bak, fs::Permissions::from_mode(0o600));
                    }
                    fs::remove_file(&bak)
                        .map_err(|e| format!("failed removing backup '{}': {e}", bak.display()))?;
                }
                log.push(format!(
                    "[update] removed 'dotagent-guard' from '{}' while preserving unrelated user hooks",
                    target.display()
                ));
            }
            PlannedDeactivation::RemoveCreated { target } => {
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

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600));
    }
    fs::remove_file(&manifest_path)
        .map_err(|e| format!("failed removing '{}': {e}", manifest_path.display()))?;

    let ag_agents_dir = ag_dir.join("agents");
    if validate_optional_dir_lstat(&ag_agents_dir, "Antigravity agents directory")?
        && fs::read_dir(&ag_agents_dir)
            .map(|mut it| it.next().is_none())
            .unwrap_or(false)
    {
        let _ = fs::remove_dir(&ag_agents_dir);
    }

    if fs::read_dir(&ag_dir)
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
