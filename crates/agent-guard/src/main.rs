#![forbid(unsafe_code)]

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use agent_guard::budget_guard::inspect_file_budget;
use agent_guard::cmd_policy::evaluate_shell_command;
use agent_guard::injection_scan::scan_untrusted_content;
use agent_guard::json::JsonValue;
use agent_guard::path_policy::{PathAccess, validate_path};
use agent_guard::unicode_guard::{ScanMode, scan_unicode};
use agent_guard::{
    Decision, audit_repository, handle_post_edit, handle_post_tool_hook, handle_pre_tool_hook,
    handle_user_prompt_hook, resolve_repo_root,
};

const MAX_HOOK_STDIN_BYTES: u64 = 262_144; // 256 KiB cap on hook JSON stdin

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    let sub = args.first().map(String::as_str).unwrap_or("--help");
    match sub {
        "pre-tool" => {
            let payload = match read_bounded_stdin_or_arg(&args[1..]) {
                Ok(s) => s,
                Err(msg) => return emit_hook_denial("HOOK_INPUT_OVERFLOW", &msg, true),
            };
            emit_hook_decision(handle_pre_tool_hook(&payload, &cwd), true)
        }
        "post-tool" => {
            let payload = match read_bounded_stdin_or_arg(&args[1..]) {
                Ok(s) => s,
                Err(msg) => return emit_hook_denial("HOOK_INPUT_OVERFLOW", &msg, false),
            };
            emit_hook_decision(handle_post_tool_hook(&payload, &cwd), false)
        }
        "user-prompt" => {
            let payload = match read_bounded_stdin_or_arg(&args[1..]) {
                Ok(s) => s,
                Err(msg) => return emit_hook_denial("HOOK_INPUT_OVERFLOW", &msg, false),
            };
            emit_hook_decision(handle_user_prompt_hook(&payload, &cwd), false)
        }
        "post-edit" => {
            let Some(file) = args.get(1) else {
                eprintln!("[AGENT-GUARD] usage: agent-guard post-edit <file>");
                return ExitCode::from(2);
            };
            emit_cli_decision(handle_post_edit(file, &cwd))
        }
        "on-stop" => run_on_stop(&cwd),
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
        "--version" | "-V" | "version" => {
            println!("agent-guard {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => {
            println!(
                "agent-guard {} — Zero-Trust AI Agent Security Kernel\n\
                 Commands:\n\
                 \x20 pre-tool              PreToolUse / BeforeTool JSON hook gate (stdin)\n\
                 \x20 post-tool             PostToolUse / AfterTool JSON output scanner (stdin)\n\
                 \x20 user-prompt           UserPromptSubmit turn-isolation reset hook (stdin)\n\
                 \x20 post-edit <file>      Incremental post-edit Unicode/secret/immutability check\n\
                 \x20 on-stop               Verification & git-hook lockdown gate before completion\n\
                 \x20 check-cmd \"<cmd>\"     Validate a shell command against the AST policy\n\
                 \x20 check-path <path>     Validate a path (--write for write check)\n\
                 \x20 scan-file <path>      Scan file for prompt injection, Unicode, & token bombs\n\
                 \x20 audit-repo [path]     Audit repository for rogue instruction files & git traps",
                env!("CARGO_PKG_VERSION")
            );
            ExitCode::SUCCESS
        }
    }
}

fn read_bounded_stdin_or_arg(extra_args: &[String]) -> Result<String, String> {
    if extra_args.first().map(String::as_str) == Some("--json") {
        return extra_args
            .get(1)
            .cloned()
            .ok_or_else(|| "missing argument after --json".to_string());
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
    String::from_utf8(buf).map_err(|_| "Non-UTF-8 bytes in hook stdin".to_string())
}

fn emit_hook_decision(decision: Decision, is_pre_tool: bool) -> ExitCode {
    match decision {
        Decision::Allow { advisory } => {
            if let Some(note) = advisory {
                let out = JsonValue::Object(vec![(
                    "hookSpecificOutput".to_string(),
                    JsonValue::Object(vec![
                        (
                            "hookEventName".to_string(),
                            JsonValue::Str(if is_pre_tool {
                                "PreToolUse".to_string()
                            } else {
                                "PostToolUse".to_string()
                            }),
                        ),
                        ("additionalContext".to_string(), JsonValue::Str(note)),
                    ]),
                )]);
                println!("{}", out.to_json_string());
            }
            ExitCode::SUCCESS
        }
        Decision::Deny {
            code,
            reason,
            halt_session,
        } => emit_hook_denial(code, &reason, halt_session),
    }
}

fn emit_hook_denial(code: &str, reason: &str, halt_session: bool) -> ExitCode {
    let full_msg = format!(
        "[AGENT-GUARD HARD DENY :: {code}] {reason} — STOP IMMEDIATELY. Do NOT attempt workarounds, alternate tools, or encodings. Report this block verbatim to the user."
    );
    eprintln!("{full_msg}");

    let json = JsonValue::Object(vec![
        ("decision".to_string(), JsonValue::Str("block".to_string())),
        ("permission".to_string(), JsonValue::Str("deny".to_string())),
        ("reason".to_string(), JsonValue::Str(full_msg.clone())),
        ("continue".to_string(), JsonValue::Bool(!halt_session)),
        (
            "hookSpecificOutput".to_string(),
            JsonValue::Object(vec![
                (
                    "permissionDecision".to_string(),
                    JsonValue::Str("deny".to_string()),
                ),
                (
                    "permissionDecisionReason".to_string(),
                    JsonValue::Str(full_msg),
                ),
            ]),
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

fn run_scan_file(raw_path: &str, cwd: &Path) -> ExitCode {
    let repo_root = resolve_repo_root(cwd);
    let valid = match validate_path(&repo_root, cwd, raw_path, PathAccess::Read) {
        Ok(v) => v,
        Err(pv) => {
            return emit_cli_decision(Decision::deny(pv.code, pv.detail, pv.is_poisoned_zone));
        }
    };

    let (content, metrics) = match inspect_file_budget(&valid.canonical_or_norm, None, None) {
        Ok(r) => r,
        Err(bv) => return emit_cli_decision(Decision::deny(bv.code, bv.detail, false)),
    };

    let uni = scan_unicode(&content, ScanMode::UntrustedContent);
    if let Some(first) = uni.first() {
        return emit_cli_decision(Decision::deny(first.code, first.detail.clone(), true));
    }

    let parent = valid.canonical_or_norm.parent().unwrap_or(&repo_root);
    let report = scan_untrusted_content(&content, &repo_root, parent, valid.is_root_authority);
    if let Some(halt) = report.first_halt() {
        return emit_cli_decision(Decision::deny(halt.code, halt.detail.clone(), true));
    }

    println!(
        "CLEAN: '{}' ({} bytes, {} lines, ~{} tokens, {} in-repo pointers)",
        valid.repo_rel,
        metrics.byte_len,
        metrics.line_count,
        metrics.estimated_tokens,
        report.valid_repo_pointers.len()
    );
    ExitCode::SUCCESS
}

fn run_on_stop(cwd: &Path) -> ExitCode {
    let repo_root = resolve_repo_root(cwd);

    // 1. Verify global git hooks remain disabled (`core.hooksPath == /dev/null`)
    if let Ok(out) = Command::new("git")
        .args(["config", "--global", "--get", "core.hooksPath"])
        .output()
    {
        let val = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !val.is_empty() && val != "/dev/null" {
            eprintln!(
                "[AGENT-GUARD ON-STOP FAIL] Global git core.hooksPath is '{val}', expected '/dev/null'."
            );
            return ExitCode::from(2);
        }
    }

    // 2. Run repository security hygiene audit
    if let Err(errs) = audit_repository(&repo_root) {
        for e in errs {
            eprintln!("[AGENT-GUARD ON-STOP FAIL] {e}");
        }
        return ExitCode::from(2);
    }

    println!(
        "[AGENT-GUARD ON-STOP OK] Repository '{}' passed security audit.",
        repo_root.display()
    );
    ExitCode::SUCCESS
}
