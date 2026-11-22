//! Shared CLI entrypoint for both `agent-guard` and unified `dotagent` binaries.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::budget_guard::{
    MAX_SLICED_FILE_BYTES, estimate_bpe_tokens, inspect_file_on_disk_hygiene,
};
use crate::cmd_policy::evaluate_shell_command;
use crate::injection_scan::scan_untrusted_content;
use crate::json::JsonValue;
use crate::path_policy::{PathAccess, validate_path};
use crate::sanitizer::{
    DEFAULT_COMPACT_STREAM_MAX_BYTES, DEFAULT_COMPACT_STREAM_MAX_LINES, sanitize_and_compact_bytes,
    wrap_spotlight_envelope,
};
use crate::traversal_ledger::SessionLedger;
use crate::unicode_guard::{ScanMode, scan_unicode};
use crate::{
    CANONICAL_DIST_GEMINI_SHA256, Decision, audit_repository, handle_post_edit,
    handle_post_edit_with_session, handle_post_tool_hook, handle_pre_compact_hook,
    handle_pre_tool_hook, handle_user_prompt_hook, pre_inspect_file_for_ingestion,
    resolve_repo_root, verify_global_git_hardening,
};

const MAX_HOOK_STDIN_BYTES: u64 = 262_144; // 256 KiB cap on hook JSON stdin

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HookPhase {
    PreTool,
    PostTool,
    UserPrompt,
    PreCompact,
}

impl HookPhase {
    fn event_name(self) -> &'static str {
        match self {
            Self::PreTool => "PreToolUse",
            Self::PostTool => "PostToolUse",
            Self::UserPrompt => "UserPromptSubmit",
            Self::PreCompact => "PreCompact",
        }
    }
}

pub fn run_cli_entrypoint() -> ExitCode {
    let mut raw_iter = std::env::args();
    let argv0 = raw_iter.next().unwrap_or_else(|| "agent-guard".to_string());
    let is_dotagent_cli = Path::new(&argv0)
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "dotagent");

    let mut args: Vec<String> = raw_iter.collect();
    if args.first().map(String::as_str) == Some("guard") {
        args.remove(0);
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    let sub = args.first().map(String::as_str).unwrap_or("--help");
    // Initialize only host processes that produce optional observations.
    // exec-sandbox applies kernel restrictions in-process and must start no such threads.
    let _telemetry = matches!(sub, "coordinator" | "hook-daemon" | "mcp-gateway")
        .then(crate::telemetry::runtime::start_host);
    match sub {
        #[cfg(unix)]
        "supervise-observations"
            if args.get(1).map(String::as_str) == Some("--owned") && args.len() == 2 =>
        {
            if crate::telemetry::transport::supervise().is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        #[cfg(unix)]
        "collect-observations" => {
            let owned = match &args[1..] {
                [] => false,
                [flag] if flag == "--owned" => true,
                _ => return ExitCode::from(2),
            };
            match crate::telemetry::transport::collect(owned) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("observation collector: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "swarm" => exec_sibling_tool("swarm-tool", &args[1..]),
        "compile" | "compiler" => exec_sibling_tool("dotagent-compiler", &args[1..]),
        "harness" => exec_sibling_tool("dotagent-harness", &args[1..]),
        "doctor" => crate::operator::run_doctor_cli(&args[1..], &cwd),
        "status" => crate::enforcement_state::run_status_cli(&args[1..], &cwd),
        "verify-enforcement" => {
            crate::enforcement_state::run_verify_enforcement_cli(&args[1..], &cwd)
        }
        "explain" => crate::diagnostics::run_explain_cli(&args[1..]),
        "session-reset" => crate::operator::run_session_reset_cli(&args[1..], &cwd),
        "elevate" => crate::operator::run_elevate_cli(&args[1..], &cwd),
        "approve" => crate::sudo_broker::run_approve_cli(&args[1..]),
        "sudo-request" => crate::sudo_broker::run_sudo_request_cli(&args[1..], &cwd),
        "sudo-result" => crate::sudo_broker::run_sudo_result_cli(&args[1..]),
        "activate" => crate::operator::run_activate_cli(&args[1..], &cwd),
        "deactivate" => crate::operator::run_deactivate_cli(&args[1..], &cwd),
        "fleet" => crate::fleet::run_fleet_cli(&args[1..], &cwd),
        "github-rulesets" => crate::github_rulesets::run_cli(&args[1..]),
        "feedback" => crate::feedback::run_feedback_cli(&args[1..], &cwd),
        "verify-ring0-ratchet" => {
            crate::ring0_ratchet::run_verify_ring0_ratchet_cli(&args[1..], &cwd)
        }
        "telemetry" => crate::telemetry::run_telemetry_cli(&args[1..]),
        "self-verify" => crate::fleet::run_self_verify_cli(&args[1..]),
        "verify-receipt" => crate::stop_receipt::run_verify_receipt_cli(&args[1..], &cwd),
        "receipt-pubkey" => crate::stop_receipt::run_receipt_pubkey_cli(&args[1..], &cwd),
        "mcp-gateway" => crate::mcp_gateway::run_mcp_gateway_cli(&args[1..], &cwd),
        "antigravity-hook" => {
            crate::antigravity_adapter::run_antigravity_hook_cli(&args[1..], &cwd)
        }
        "pre-tool" => {
            let (explicit_adapter, payload) = match read_hook_args_and_stdin(&args[1..]) {
                Ok(v) => v,
                Err(msg) => return emit_hook_denial("HOOK_INPUT_OVERFLOW", &msg, true),
            };
            let decision = eval_hook_preferring_hot_coord("pre-tool", &payload, &cwd, || {
                handle_pre_tool_hook(&payload, &cwd)
            });
            if let Decision::Deny { code, .. } = &decision
                && !matches!(*code, "CROSS_REPO_CWD_SPOOF" | "INVALID_HOOK_JSON")
                && let Some(adapter_id) =
                    resolve_pre_tool_witness_adapter(explicit_adapter, &payload)
            {
                let ws_root = resolve_repo_root(&cwd);
                crate::enforcement_state::record_denial_witness(
                    &ws_root,
                    adapter_id,
                    "PreToolUse",
                    payload.as_bytes(),
                    code,
                );
            }
            emit_hook_decision(decision, HookPhase::PreTool)
        }
        "post-tool" => {
            let (_, payload) = match read_hook_args_and_stdin(&args[1..]) {
                Ok(v) => v,
                Err(msg) => return emit_hook_denial("HOOK_INPUT_OVERFLOW", &msg, false),
            };
            let decision = eval_hook_preferring_hot_coord("post-tool", &payload, &cwd, || {
                handle_post_tool_hook(&payload, &cwd)
            });
            emit_hook_decision(decision, HookPhase::PostTool)
        }
        "user-prompt" => {
            let (_, payload) = match read_hook_args_and_stdin(&args[1..]) {
                Ok(v) => v,
                Err(msg) => return emit_hook_denial("HOOK_INPUT_OVERFLOW", &msg, false),
            };
            emit_hook_decision(
                handle_user_prompt_hook(&payload, &cwd),
                HookPhase::UserPrompt,
            )
        }
        "pre-compact" => {
            let (_, payload) = match read_hook_args_and_stdin(&args[1..]) {
                Ok(v) => v,
                Err(msg) => return emit_hook_denial("HOOK_INPUT_OVERFLOW", &msg, false),
            };
            emit_hook_decision(
                handle_pre_compact_hook(&payload, &cwd),
                HookPhase::PreCompact,
            )
        }
        "sanitize-stream" => run_sanitize_stream(),
        "read-safe" => {
            let Some(p) = args.get(1) else {
                eprintln!(
                    "[AGENT-GUARD] usage: agent-guard read-safe <path> [--offset N] [--limit M]"
                );
                return ExitCode::from(2);
            };
            run_read_safe(p, &args[2..], &cwd)
        }
        "post-edit" => {
            let has_hook_flag = args
                .get(1)
                .is_some_and(|a| matches!(a.as_str(), "--json" | "--adapter"));
            if let Some(file) = args.get(1).filter(|_| !has_hook_flag) {
                emit_cli_decision(handle_post_edit(file, &cwd))
            } else if has_hook_flag || !std::io::IsTerminal::is_terminal(&io::stdin()) {
                let (_, payload) = match read_hook_args_and_stdin(&args[1..]) {
                    Ok(v) => v,
                    Err(msg) => return emit_hook_denial("HOOK_INPUT_OVERFLOW", &msg, false),
                };
                if payload.trim().is_empty() {
                    eprintln!("[AGENT-GUARD] usage: agent-guard post-edit <file>");
                    return ExitCode::from(2);
                }
                let parsed = match JsonValue::parse(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        return emit_hook_denial(
                            "MALFORMED_HOOK_JSON",
                            &format!("Invalid JSON in post-edit hook stdin: {e}"),
                            false,
                        );
                    }
                };
                let target_file = parsed
                    .get("file_path")
                    .and_then(JsonValue::as_str)
                    .or_else(|| parsed.get("path").and_then(JsonValue::as_str))
                    .or_else(|| {
                        parsed
                            .get("tool_input")
                            .and_then(|ti| ti.get("file_path").or_else(|| ti.get("path")))
                            .and_then(JsonValue::as_str)
                    });
                let Some(file) = target_file.filter(|s| !s.trim().is_empty()) else {
                    return emit_hook_denial(
                        "MISSING_POST_EDIT_PATH",
                        "post-edit hook payload missing non-empty 'file_path' or 'path'.",
                        false,
                    );
                };
                let hook_sid = parsed
                    .get("session_id")
                    .or_else(|| parsed.get("conversation_id"))
                    .and_then(JsonValue::as_str)
                    .unwrap_or("");
                emit_cli_decision(handle_post_edit_with_session(file, &cwd, hook_sid))
            } else {
                eprintln!("[AGENT-GUARD] usage: agent-guard post-edit <file>");
                ExitCode::from(2)
            }
        }
        "on-stop" => run_on_stop(&args[1..], &cwd),
        "check-cmd" => {
            let Some(cmd) = args.get(1) else {
                eprintln!("[AGENT-GUARD] usage: agent-guard check-cmd \"<command>\"");
                return ExitCode::from(2);
            };
            let repo_root = resolve_repo_root(&cwd);
            match evaluate_shell_command(cmd, &repo_root, &cwd, false) {
                Ok(_) => {
                    println!("ALLOW: command passed shell AST & zero-trust policy");
                    ExitCode::SUCCESS
                }
                Err(cv) => emit_cli_decision(Decision::deny(cv.code, cv.detail, cv.halt_session)),
            }
        }
        "check-path" => {
            let Some(p) = args.get(1) else {
                eprintln!("[AGENT-GUARD] usage: agent-guard check-path <path> [--write]");
                return ExitCode::from(2);
            };
            let access = if args.get(2).is_some_and(|f| f == "--write") {
                PathAccess::Write
            } else {
                PathAccess::Read
            };
            let repo_root = resolve_repo_root(&cwd);
            match validate_path(&repo_root, &cwd, p, access) {
                Ok(valid) => {
                    println!(
                        "ALLOW: '{}' (repo_rel='{}', root_authority={})",
                        valid.canonical_or_norm.display(),
                        valid.repo_rel,
                        valid.is_root_authority
                    );
                    ExitCode::SUCCESS
                }
                Err(pv) => {
                    emit_cli_decision(Decision::deny(pv.code, pv.detail, pv.is_poisoned_zone))
                }
            }
        }
        "scan-file" => {
            let Some(p) = args.get(1) else {
                eprintln!("[AGENT-GUARD] usage: agent-guard scan-file <path>");
                return ExitCode::from(2);
            };
            run_scan_file(p, &cwd)
        }
        "audit-repo" => {
            let target = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| resolve_repo_root(&cwd));
            match audit_repository(&target) {
                Ok(passed) => {
                    for msg in passed {
                        println!("[OK] {msg}");
                    }
                    ExitCode::SUCCESS
                }
                Err(errs) => {
                    for e in errs {
                        eprintln!("[AGENT-GUARD AUDIT FAIL] {e}");
                    }
                    ExitCode::from(2)
                }
            }
        }
        "coordinator" => crate::coordinator::run_coordinator_cli(&args[1..], &cwd),
        "hook-daemon" => crate::coordinator::run_hook_daemon_cli(&args[1..]),
        "exec-sandbox" => crate::exec_sandbox::run_exec_sandbox_cli(&args[1..], &cwd),
        "sandbox-status" => crate::exec_sandbox::run_sandbox_status_cli(),
        "--probe-landlock-child" => crate::exec_sandbox::run_probe_landlock_child(),
        "--probe-seccomp-child" => crate::exec_sandbox::run_probe_seccomp_child(),
        "--version" | "-V" | "version" => {
            let bin_label = if is_dotagent_cli {
                "dotagent"
            } else {
                "agent-guard"
            };
            println!("{bin_label} {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "--help" | "-h" | "help" => {
            let bin_label = if is_dotagent_cli {
                "dotagent"
            } else {
                "agent-guard"
            };
            println!(
                "{bin_label} {} - Zero-Trust AI Agent Security Kernel & Unified Operator CLI\n\
                 Operator & Onboarding Commands:\n\
                 \x20 activate [--workspace <dir>] [--dry-run]  Non-destructive multi-harness activation & backups\n\
                 \x20 deactivate [--workspace <dir>]            Restore .dotagent.bak files & remove deployed plane\n\
                 \x20 fleet <audit|doctor|sync|build-image|configure-github>  Polyrepo sync, image builder, & GitHub Org rulesets\n\
                 \x20 github-rulesets <scope> [--dry-run|--verify|--apply]   Manage GitHub rulesets\n\
                 \x20 feedback <submit|status|sync-github|run-loop>  Agent friction ballots, AgentPI stream, & autonomous loop\n\
                 \x20 verify-ring0-ratchet [--base origin/main] Verify Ring-0 immutability & monotonic bypass corpus\n\
                 \x20 telemetry <summary|top-denies|baseline|trace|rotate|export-otlp>  Human-TTY-only security analytics\n\
                 \x20 verify-receipt [receipt.json] [--pubkey]  Verify asymmetric Ed25519 StopReceipt attestation\n\
                 \x20 self-verify --sums <SHA256SUMS>           Verify binary SHA-256 & SLSA v1.0 provenance\n\
                 \x20 doctor [--json] [path]                    Run 7-point live security & sandbox health report\n\
                 \x20 explain <CODE|--list> [--json]            Explain any guard code with rationale & remediation\n\
                 \x20 session-reset [--session <id>|--all]      Reset halted session state (interactive human TTY only)\n\
                 \x20 elevate [--ttl <min>|--status|--off]      Time-boxed local power-user lease (human TTY only)\n\
                 \x20 approve [req_id|--watch|--list|--reject]  Approve & run queued sudo ticket (human TTY only)\n\
                 \x20 swarm <run|role> ...                      Active multi-worktree DAG wave runner & Swarm CLI\n\
                 \x20 compile <build|verify> [root]             Deterministic Policy-IR & embedded Regorus compiler\n\
                 \x20 harness <run|bench> ...                   Adversarial, contract, & microbenchmark harness\n\
                 Kernel & Hook Commands:\n\
                 \x20 mcp-gateway           Local zero-trust mediating MCP JSON-RPC 2.0 sidecar (PKCE + DPoP)\n\
                 \x20 pre-tool              PreToolUse / BeforeTool JSON hook gate (stdin)\n\
                 \x20 post-tool             PostToolUse / AfterTool JSON output scanner (stdin)\n\
                 \x20 user-prompt           UserPromptSubmit turn-isolation reset hook (stdin)\n\
                 \x20 pre-compact           PreCompact / PreCompress step-budget reset & ASCII directive\n\
                 \x20 exec-sandbox          Execute shell command inside Landlock/Seatbelt/Seccomp VFS+Net sandbox\n\
                 \x20 sandbox-status        Report active host kernel VFS sandbox enforcement mode\n\
                 \x20 coordinator           Privilege-separated UNIX domain HMAC/epoch/hook daemon\n\
                 \x20 sanitize-stream       Pre-buffer 7-bit ASCII sanitizer & 120-line stream compactor\n\
                 \x20 read-safe <path>      Read & neuter file into 128-bit spotlighted 7-bit ASCII\n\
                 \x20 post-edit [file]      Incremental post-edit Unicode/secret/immutability check\n\
                 \x20 on-stop               Verification, git-hook lockdown, & Ed25519 StopReceipt gate\n\
                 \x20 check-cmd \"<cmd>\"     Validate a shell command against the AST policy\n\
                 \x20 check-path <path>     Validate a path (--write for write check)\n\
                 \x20 scan-file <path>      Scan file for prompt injection, Unicode, & token bombs\n\
                 \x20 audit-repo [path]     Audit repository for rogue instruction files & build/git traps",
                env!("CARGO_PKG_VERSION")
            );
            ExitCode::SUCCESS
        }
        other => emit_hook_denial(
            "UNKNOWN_SUBCOMMAND",
            &format!("Unrecognized subcommand '{other}' (run 'dotagent --help' for usage)."),
            false,
        ),
    }
}

fn exec_sibling_tool(bin_name: &str, forward_args: &[String]) -> ExitCode {
    let Some(resolved) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(bin_name)))
        .filter(|p| {
            std::fs::symlink_metadata(p)
                .is_ok_and(|m| !m.file_type().is_symlink() && m.file_type().is_file())
        })
    else {
        eprintln!(
            "[dotagent] HARD DENY: trusted sibling binary '{bin_name}' not found beside current executable"
        );
        return ExitCode::from(2);
    };

    match std::process::Command::new(&resolved)
        .args(forward_args)
        .status()
    {
        Ok(status) => match status.code() {
            Some(c) if (0..=255).contains(&c) => ExitCode::from(c as u8),
            _ => ExitCode::from(2),
        },
        Err(e) => {
            eprintln!(
                "[dotagent] HARD DENY: failed invoking '{}' ({}): {e}",
                bin_name,
                resolved.display()
            );
            ExitCode::from(2)
        }
    }
}

fn run_sanitize_stream() -> ExitCode {
    let mut raw = Vec::new();
    if io::stdin()
        .take(MAX_SLICED_FILE_BYTES)
        .read_to_end(&mut raw)
        .is_err()
    {
        println!("[AGENT-GUARD STREAM READ ERROR]");
        return ExitCode::SUCCESS;
    }
    let san = sanitize_and_compact_bytes(
        &raw,
        DEFAULT_COMPACT_STREAM_MAX_LINES,
        DEFAULT_COMPACT_STREAM_MAX_BYTES,
    );
    print!("{}", san.clean_ascii);
    if !san.clean_ascii.ends_with('\n') && !san.clean_ascii.is_empty() {
        println!();
    }
    ExitCode::SUCCESS
}

fn run_read_safe(raw_path: &str, extra: &[String], cwd: &Path) -> ExitCode {
    let mut offset_line: Option<usize> = None;
    let mut limit_lines: Option<usize> = None;
    let mut idx = 0usize;
    while idx < extra.len() {
        match extra[idx].as_str() {
            "--offset" => {
                offset_line = extra.get(idx + 1).and_then(|s| s.parse().ok());
                idx += 2;
            }
            "--limit" => {
                limit_lines = extra.get(idx + 1).and_then(|s| s.parse().ok());
                idx += 2;
            }
            _ => idx += 1,
        }
    }

    let repo_root = resolve_repo_root(cwd);
    let valid = match validate_path(&repo_root, cwd, raw_path, PathAccess::Read) {
        Ok(v) => v,
        Err(pv) => {
            return emit_cli_decision(Decision::deny(pv.code, pv.detail, pv.is_poisoned_zone));
        }
    };

    let sid = std::env::var("AGENT_GUARD_SESSION_ID").unwrap_or_else(|_| "default".to_string());
    let _session_lock = SessionLedger::acquire_lock(&repo_root, &sid);
    let mut ledger = SessionLedger::load_or_create(&repo_root, &sid);
    match pre_inspect_file_for_ingestion(
        &valid.canonical_or_norm,
        &valid.repo_rel,
        valid.is_root_authority,
        offset_line,
        limit_lines,
        &repo_root,
        &mut ledger,
        false,
    ) {
        Ok(clean_ascii) => {
            let _ = ledger.save(&repo_root);
            println!(
                "{}",
                wrap_spotlight_envelope(&clean_ascii, &ledger.turn_nonce, &valid.repo_rel)
            );
            ExitCode::SUCCESS
        }
        Err(dec) => {
            let can_auto_page = limit_lines.is_none()
                && matches!(
                    &dec,
                    Decision::Deny {
                        code: "FILE_BYTE_BUDGET_EXCEEDED"
                            | "FILE_BYTE_CAP_EXCEEDED"
                            | "LINE_COUNT_BUDGET_EXCEEDED"
                            | "TOKEN_ESTIMATE_EXCEEDED",
                        halt_session: false,
                        ..
                    }
                );
            if can_auto_page {
                let start = offset_line.unwrap_or(1).max(1);
                for page_len in [150usize, 75usize] {
                    if let Ok(clean_ascii) = pre_inspect_file_for_ingestion(
                        &valid.canonical_or_norm,
                        &valid.repo_rel,
                        valid.is_root_authority,
                        Some(start),
                        Some(page_len),
                        &repo_root,
                        &mut ledger,
                        false,
                    ) {
                        let _ = ledger.save(&repo_root);
                        let end = start + page_len - 1;
                        let next = end + 1;
                        eprintln!(
                            "[AGENT-GUARD AUTO-PAGINATED: showing lines {start}..={end}; pass `--offset {next} --limit {page_len}` for next page]"
                        );
                        println!(
                            "{}",
                            wrap_spotlight_envelope(
                                &clean_ascii,
                                &ledger.turn_nonce,
                                &valid.repo_rel
                            )
                        );
                        return ExitCode::SUCCESS;
                    }
                }
            }
            let _ = ledger.save(&repo_root);
            emit_cli_decision(dec)
        }
    }
}

fn infer_single_pre_tool_adapter(raw_payload: &str) -> Option<&'static str> {
    let parsed = crate::json::JsonValue::parse(raw_payload).ok()?;
    let has_cursor =
        parsed.get("cursor_version").is_some() || parsed.get("workspace_roots").is_some();
    let ev = parsed
        .get("hook_event_name")
        .and_then(crate::json::JsonValue::as_str);
    let is_gemini = ev == Some("BeforeTool");
    let is_claude = ev == Some("PreToolUse");
    let is_cursor_pre = has_cursor
        && matches!(
            ev,
            None | Some(
                "beforeShellExecution"
                    | "beforeMCPExecution"
                    | "beforeReadFile"
                    | "beforeSubmitPrompt"
            )
        );
    match (is_cursor_pre, is_gemini, is_claude, has_cursor) {
        (true, false, false, true) => Some("cursor"),
        (false, true, false, false) => Some("gemini"),
        (false, false, true, false) => Some("claude"),
        _ => None,
    }
}

fn resolve_pre_tool_witness_adapter(
    explicit_adapter: Option<&'static str>,
    raw_payload: &str,
) -> Option<&'static str> {
    let inferred = infer_single_pre_tool_adapter(raw_payload)?;
    match explicit_adapter {
        Some(exp) => (inferred == exp).then_some(exp),
        None => Some(inferred),
    }
}

fn read_hook_args_and_stdin(
    extra_args: &[String],
) -> Result<(Option<&'static str>, String), String> {
    let mut explicit_adapter: Option<&'static str> = None;
    let mut json_arg: Option<String> = None;
    let mut idx = 0usize;
    while idx < extra_args.len() {
        match extra_args[idx].as_str() {
            "--adapter" => {
                let Some(raw_ad) = extra_args.get(idx + 1) else {
                    return Err("missing argument after --adapter".to_string());
                };
                if explicit_adapter.is_some() {
                    return Err("duplicate --adapter argument".to_string());
                }
                explicit_adapter = Some(match raw_ad.as_str() {
                    "claude" => "claude",
                    "gemini" => "gemini",
                    "cursor" => "cursor",
                    other => return Err(format!("unsupported hook --adapter '{other}'")),
                });
                idx += 2;
            }
            "--json" => {
                let Some(raw_j) = extra_args.get(idx + 1) else {
                    return Err("missing argument after --json".to_string());
                };
                if json_arg.is_some() {
                    return Err("duplicate --json argument".to_string());
                };
                json_arg = Some(raw_j.clone());
                idx += 2;
            }
            other => return Err(format!("unsupported hook argument '{other}'")),
        }
    }
    if let Some(j) = json_arg {
        if j.len() as u64 > MAX_HOOK_STDIN_BYTES {
            return Err(format!(
                "Hook --json payload exceeded {MAX_HOOK_STDIN_BYTES} bytes (token/context bomb blocked)"
            ));
        }
        return Ok((explicit_adapter, j));
    }
    let mut buf = Vec::new();
    io::stdin()
        .take(MAX_HOOK_STDIN_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("stdin read error: {e}"))?;
    if buf.len() as u64 > MAX_HOOK_STDIN_BYTES {
        return Err(format!(
            "Hook stdin exceeded {MAX_HOOK_STDIN_BYTES} bytes (token/context bomb blocked)"
        ));
    }
    let payload =
        String::from_utf8(buf).map_err(|_| "Non-UTF-8 bytes in hook stdin".to_string())?;
    Ok((explicit_adapter, payload))
}

fn emit_hook_decision(decision: Decision, phase: HookPhase) -> ExitCode {
    match decision {
        Decision::Allow {
            advisory,
            updated_bash_cmd,
            updated_input_json,
        } => {
            if advisory.is_some() || updated_bash_cmd.is_some() || updated_input_json.is_some() {
                let mut fields = vec![(
                    "hookEventName".to_string(),
                    JsonValue::Str(phase.event_name().to_string()),
                )];
                if let Some(raw_obj) = updated_input_json {
                    let Ok(parsed_obj) = JsonValue::parse(&raw_obj) else {
                        return emit_hook_decision(
                            Decision::deny(
                                "INTERNAL_HOOK_JSON_ERROR",
                                "Failed serializing updatedInput JSON object".to_string(),
                                false,
                            ),
                            phase,
                        );
                    };
                    fields.push((
                        "permissionDecision".to_string(),
                        JsonValue::Str("allow".to_string()),
                    ));
                    fields.push(("updatedInput".to_string(), parsed_obj));
                } else if let Some(cmd) = updated_bash_cmd {
                    fields.push((
                        "permissionDecision".to_string(),
                        JsonValue::Str("allow".to_string()),
                    ));
                    fields.push((
                        "updatedInput".to_string(),
                        JsonValue::Object(vec![("command".to_string(), JsonValue::Str(cmd))]),
                    ));
                }
                if let Some(note) = advisory {
                    fields.push(("additionalContext".to_string(), JsonValue::Str(note)));
                }
                let out = JsonValue::Object(vec![(
                    "hookSpecificOutput".to_string(),
                    JsonValue::Object(fields),
                )]);
                println!("{}", out.to_json_string());
            }
            ExitCode::SUCCESS
        }
        Decision::Deny {
            code,
            reason,
            halt_session,
        } => {
            if phase == HookPhase::PostTool
                && matches!(
                    code,
                    "NON_ASCII_SANITIZED_PREBUFFER" | "TOOL_OUTPUT_FLOOD_BLOCKED"
                )
            {
                let note = if code == "TOOL_OUTPUT_FLOOD_BLOCKED" {
                    format!(
                        "[AGENT-GUARD AUTO-COMPACTED] Benign oversized tool output exceeded the 16 KiB step ceiling and was head/tail-compacted to clean 7-bit ASCII:\n{reason}"
                    )
                } else {
                    format!(
                        "[AGENT-GUARD PRE-BUFFER ASCII SANITIZER] Tool output contained non-ASCII or escape bytes and was sanitized to 7-bit ASCII:\n{reason}"
                    )
                };
                let out = JsonValue::Object(vec![(
                    "hookSpecificOutput".to_string(),
                    JsonValue::Object(vec![
                        (
                            "hookEventName".to_string(),
                            JsonValue::Str(phase.event_name().to_string()),
                        ),
                        ("updatedMCPToolOutput".to_string(), JsonValue::Str(reason)),
                        ("additionalContext".to_string(), JsonValue::Str(note)),
                    ]),
                )]);
                println!("{}", out.to_json_string());
                return ExitCode::SUCCESS;
            }
            emit_hook_denial(code, &reason, halt_session)
        }
    }
}

fn emit_hook_denial(code: &str, reason: &str, halt_session: bool) -> ExitCode {
    let is_sanitized_replacement = code == "NON_ASCII_SANITIZED_PREBUFFER";
    let is_recoverable_bound = !halt_session
        && matches!(
            code,
            "FILE_BYTE_BUDGET_EXCEEDED"
                | "FILE_BYTE_CAP_EXCEEDED"
                | "LINE_COUNT_BUDGET_EXCEEDED"
                | "SLICE_LINE_CAP_EXCEEDED"
                | "TOKEN_ESTIMATE_EXCEEDED"
                | "TURN_TOKEN_BUDGET_EXCEEDED"
                | "TURN_READ_COUNT_EXCEEDED"
                | "TURN_TOOL_CALL_LIMIT_EXCEEDED"
                | "UNBOUNDED_GIT_LOG"
                | "MAX_DEPTH_EXCEEDED"
        );
    let full_msg = if is_sanitized_replacement {
        format!(
            "[AGENT-GUARD PRE-BUFFER ASCII SANITIZER :: {code}] Untrusted input/output contained non-ASCII bytes or escape triggers and was neutered prior to entering your context buffer. Use ONLY the clean 7-bit ASCII payload below (do NOT re-read raw):\n{reason}"
        )
    } else if is_recoverable_bound {
        format!(
            "[AGENT-GUARD BOUND GUIDANCE :: {code}] {reason} -- Adjust the call to stay within micro-window bounds (e.g. `offset`/`limit <= 150`, `--max-depth 2`, `git log -n 20`) or compact step context."
        )
    } else {
        format!(
            "[AGENT-GUARD HARD DENY :: {code}] {reason} -- STOP IMMEDIATELY. Do NOT attempt workarounds, alternate tools, or encodings. Report this block verbatim to the user."
        )
    };
    eprintln!("{full_msg}");

    let mut hook_specific = vec![
        (
            "permissionDecision".to_string(),
            JsonValue::Str("deny".to_string()),
        ),
        (
            "permissionDecisionReason".to_string(),
            JsonValue::Str(full_msg.clone()),
        ),
    ];
    if is_sanitized_replacement {
        hook_specific.push((
            "updatedMCPToolOutput".to_string(),
            JsonValue::Str(reason.to_string()),
        ));
    }

    let json = JsonValue::Object(vec![
        ("decision".to_string(), JsonValue::Str("block".to_string())),
        ("permission".to_string(), JsonValue::Str("deny".to_string())),
        ("reason".to_string(), JsonValue::Str(full_msg)),
        ("continue".to_string(), JsonValue::Bool(!halt_session)),
        (
            "hookSpecificOutput".to_string(),
            JsonValue::Object(hook_specific),
        ),
    ]);
    println!("{}", json.to_json_string());
    ExitCode::from(2)
}

fn emit_cli_decision(decision: Decision) -> ExitCode {
    match decision {
        Decision::Allow { .. } => {
            println!("ALLOW");
            ExitCode::SUCCESS
        }
        Decision::Deny { code, reason, .. } => {
            eprintln!("[AGENT-GUARD HARD DENY :: {code}] {reason}");
            ExitCode::from(2)
        }
    }
}

fn resolve_nonsymlink_dist_bundle_artifact(
    repo_root: &Path,
    cwd: &Path,
    raw_path: &str,
) -> Option<(PathBuf, String, bool)> {
    let canon_repo = std::fs::canonicalize(repo_root).ok()?;
    let joined = if Path::new(raw_path).is_absolute() {
        PathBuf::from(raw_path)
    } else {
        let canon_cwd = std::fs::canonicalize(cwd).ok()?;
        if !canon_cwd.starts_with(&canon_repo) {
            return None;
        }
        canon_cwd.join(raw_path)
    };
    let rel_raw = joined.strip_prefix(&canon_repo).ok()?;

    let mut cur = canon_repo.clone();
    let mut rel_parts = Vec::new();
    for comp in rel_raw.components() {
        match comp {
            std::path::Component::CurDir => continue,
            std::path::Component::Normal(seg) => {
                let seg_str = seg.to_str()?;
                cur.push(seg);
                let meta = std::fs::symlink_metadata(&cur).ok()?;
                if meta.file_type().is_symlink() {
                    return None;
                }
                rel_parts.push(seg_str.to_string());
            }
            _ => return None,
        }
    }
    let final_meta = std::fs::symlink_metadata(&cur).ok()?;
    if final_meta.file_type().is_symlink() || !final_meta.file_type().is_file() {
        return None;
    }

    let rel = rel_parts.join("/");
    if !rel.starts_with("dist/") {
        return None;
    }

    let bytes = std::fs::read(&cur).ok()?;
    let actual_hex = crate::crypto::sha256_hex(&bytes);

    if rel == "dist/AGENTS.md" {
        let root_agents = canon_repo.join("AGENTS.md");
        let rmeta = std::fs::symlink_metadata(&root_agents).ok()?;
        if rmeta.file_type().is_symlink() || !rmeta.file_type().is_file() {
            return None;
        }
        let root_bytes = std::fs::read(&root_agents).ok()?;
        if crate::crypto::sha256_hex(&root_bytes) == actual_hex {
            return Some((cur, rel, true));
        }
        return None;
    }
    if rel == "dist/gemini/GEMINI.md" {
        if actual_hex == CANONICAL_DIST_GEMINI_SHA256 {
            return Some((cur, rel, true));
        }
        return None;
    }

    let manifest_path = canon_repo.join("dist-verify/manifest.sha256");
    let mmeta = std::fs::symlink_metadata(&manifest_path).ok()?;
    if mmeta.file_type().is_symlink() || !mmeta.file_type().is_file() {
        return None;
    }
    let manifest = std::fs::read_to_string(&manifest_path).ok()?;
    for line in manifest.lines() {
        let mut parts = line.split_whitespace();
        let Some(expected_hex) = parts.next() else {
            continue;
        };
        let Some(path_col) = parts.next() else {
            continue;
        };
        if path_col == rel && expected_hex == actual_hex {
            return Some((cur, rel, false));
        }
    }
    None
}

fn run_scan_file(raw_path: &str, cwd: &Path) -> ExitCode {
    let repo_root = resolve_repo_root(cwd);
    let (canon_path, repo_rel, is_trusted_authority) =
        match validate_path(&repo_root, cwd, raw_path, PathAccess::Read) {
            Ok(v) => (v.canonical_or_norm, v.repo_rel, v.is_root_authority),
            Err(pv) => {
                if pv.code == "UNAUTHORIZED_INSTRUCTION_FILE" {
                    if let Some((canon, rel, trusted)) =
                        resolve_nonsymlink_dist_bundle_artifact(&repo_root, cwd, raw_path)
                    {
                        (canon, rel, trusted)
                    } else {
                        return emit_cli_decision(Decision::deny(
                            pv.code,
                            pv.detail,
                            pv.is_poisoned_zone,
                        ));
                    }
                } else {
                    return emit_cli_decision(Decision::deny(
                        pv.code,
                        pv.detail,
                        pv.is_poisoned_zone,
                    ));
                }
            }
        };

    let content = match inspect_file_on_disk_hygiene(&canon_path) {
        Ok(c) => c,
        Err(bv) => return emit_cli_decision(Decision::deny(bv.code, bv.detail, false)),
    };

    let uni = scan_unicode(&content, ScanMode::UntrustedContent);
    if let Some(first) = uni.first() {
        return emit_cli_decision(Decision::deny(first.code, first.detail.clone(), true));
    }

    let parent = canon_path.parent().unwrap_or(&repo_root);
    let report = scan_untrusted_content(&content, &repo_root, parent, is_trusted_authority);
    if let Some(halt) = report.first_halt() {
        return emit_cli_decision(Decision::deny(halt.code, halt.detail.clone(), true));
    }

    let est_tokens = estimate_bpe_tokens(&content);
    println!(
        "CLEAN: '{}' ({} bytes, {} lines, ~{} tokens, {} in-repo pointers)",
        repo_rel,
        content.len(),
        content
            .lines()
            .count()
            .max(usize::from(!content.is_empty())),
        est_tokens,
        report.valid_repo_pointers.len()
    );
    ExitCode::SUCCESS
}

pub(crate) fn eval_hook_preferring_hot_coord<F>(
    phase: &str,
    payload: &str,
    cwd: &Path,
    local_fallback: F,
) -> Decision
where
    F: FnOnce() -> Decision,
{
    if std::env::var("AGENT_GUARD_HOT_COORD").as_deref() == Ok("1") {
        let repo_root = resolve_repo_root(cwd);
        if let Ok(dec) = crate::coordinator::rpc_eval_hook(&repo_root, phase, payload, cwd) {
            return dec;
        }
    }
    // A local fallback may submit to an existing collector; it never starts one.
    local_fallback()
}

fn run_on_stop(args: &[String], cwd: &Path) -> ExitCode {
    let mut receipt_out: Option<PathBuf> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--receipt-out" => {
                let Some(val) = args.get(i + 1) else {
                    eprintln!("[AGENT-GUARD ON-STOP FAIL] missing path after --receipt-out");
                    return ExitCode::from(2);
                };
                receipt_out = Some(PathBuf::from(val));
                i += 2;
            }
            "--adapter" => {
                let Some(ad) = args.get(i + 1) else {
                    eprintln!("[AGENT-GUARD ON-STOP FAIL] missing value after --adapter");
                    return ExitCode::from(2);
                };
                if !matches!(ad.as_str(), "claude" | "gemini" | "cursor" | "codex") {
                    eprintln!("[AGENT-GUARD ON-STOP FAIL] unsupported --adapter '{ad}'");
                    return ExitCode::from(2);
                }
                i += 2;
            }
            other => {
                eprintln!("[AGENT-GUARD ON-STOP FAIL] unsupported argument '{other}'");
                return ExitCode::from(2);
            }
        }
    }

    let repo_root = resolve_repo_root(cwd);

    let sid = std::env::var("AGENT_GUARD_SESSION_ID").unwrap_or_else(|_| "default".to_string());
    {
        let _ledger_lock = SessionLedger::acquire_lock(&repo_root, &sid);
        let ledger = SessionLedger::load_or_create(&repo_root, &sid);
        if ledger.halted {
            let reason = ledger
                .halt_reason
                .as_deref()
                .unwrap_or("circuit breaker tripped");
            eprintln!(
                "[AGENT-GUARD ON-STOP FAIL] SESSION_CIRCUIT_BREAKER_HALTED: session '{sid}' is halted ({reason})."
            );
            return ExitCode::from(2);
        }
    }

    if let Err(err) = verify_global_git_hardening() {
        eprintln!("[AGENT-GUARD ON-STOP FAIL] {err}");
        return ExitCode::from(2);
    }

    if let Err(errs) = audit_repository(&repo_root) {
        for e in errs {
            eprintln!("[AGENT-GUARD ON-STOP FAIL] {e}");
        }
        return ExitCode::from(2);
    }

    if let Err(swarm_err) = crate::work_ledger::verify_on_stop_swarm_gates(&repo_root) {
        eprintln!("[AGENT-GUARD ON-STOP FAIL] {swarm_err}");
        return ExitCode::from(2);
    }

    if let Err(smoke_err) = crate::smoke_gate::verify_repo_smoke_gate(&repo_root) {
        eprintln!("[AGENT-GUARD ON-STOP FAIL] {smoke_err}");
        return ExitCode::from(2);
    }

    if std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() != Ok("1")
        && std::env::var("AGENT_GUARD_WORKER_LOCK").as_deref() != Ok("1")
    {
        match crate::stop_receipt::issue_verified_stop_receipt(&repo_root, receipt_out.as_deref()) {
            Ok((receipt, path)) => {
                println!(
                    "[AGENT-GUARD ON-STOP OK] Repository '{}' passed security audit (StopReceipt='{}' ed25519={}).",
                    repo_root.display(),
                    path.display(),
                    &receipt.pubkey_ed25519_hex[..16]
                );
                return ExitCode::SUCCESS;
            }
            Err(err) => {
                eprintln!("[AGENT-GUARD ON-STOP FAIL] {err}");
                return ExitCode::from(2);
            }
        }
    } else if receipt_out.is_some() {
        eprintln!(
            "[AGENT-GUARD ON-STOP FAIL] STOP_RECEIPT_DENIED_IN_SANDBOX: StopReceipt signing requires host authority."
        );
        return ExitCode::from(2);
    }

    println!(
        "[AGENT-GUARD ON-STOP OK] Repository '{}' passed security audit.",
        repo_root.display()
    );
    ExitCode::SUCCESS
}
