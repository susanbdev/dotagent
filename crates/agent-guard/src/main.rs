#![forbid(unsafe_code)]

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use agent_guard::budget_guard::MAX_SLICED_FILE_BYTES;
use agent_guard::cmd_policy::evaluate_shell_command;
use agent_guard::injection_scan::scan_untrusted_content;
use agent_guard::json::JsonValue;
use agent_guard::path_policy::{PathAccess, validate_path};
use agent_guard::sanitizer::{
    DEFAULT_COMPACT_STREAM_MAX_BYTES, DEFAULT_COMPACT_STREAM_MAX_LINES, sanitize_and_compact_bytes,
    wrap_spotlight_envelope,
};
use agent_guard::traversal_ledger::SessionLedger;
use agent_guard::unicode_guard::{ScanMode, scan_unicode};
use agent_guard::{
    Decision, audit_repository, handle_post_edit, handle_post_tool_hook, handle_pre_compact_hook,
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
            emit_hook_decision(handle_pre_tool_hook(&payload, &cwd), HookPhase::PreTool)
        }
        "post-tool" => {
            let payload = match read_bounded_stdin_or_arg(&args[1..]) {
                Ok(s) => s,
                Err(msg) => return emit_hook_denial("HOOK_INPUT_OVERFLOW", &msg, false),
            };
            emit_hook_decision(handle_post_tool_hook(&payload, &cwd), HookPhase::PostTool)
        }
        "user-prompt" => {
            let payload = match read_bounded_stdin_or_arg(&args[1..]) {
                Ok(s) => s,
                Err(msg) => return emit_hook_denial("HOOK_INPUT_OVERFLOW", &msg, false),
            };
            emit_hook_decision(
                handle_user_prompt_hook(&payload, &cwd),
                HookPhase::UserPrompt,
            )
        }
        "pre-compact" => {
            let payload = match read_bounded_stdin_or_arg(&args[1..]) {
                Ok(s) => s,
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
                 \x20 pre-compact           PreCompact / PreCompress step-budget reset & ASCII directive\n\
                 \x20 sanitize-stream       Pre-buffer 7-bit ASCII sanitizer & 120-line stream compactor\n\
                 \x20 read-safe <path>      Read & neuter file into 128-bit spotlighted 7-bit ASCII\n\
                 \x20 post-edit <file>      Incremental post-edit Unicode/secret/immutability check\n\
                 \x20 on-stop               Verification & git-hook lockdown gate before completion\n\
                 \x20 check-cmd \"<cmd>\"     Validate a shell command against the AST policy\n\
                 \x20 check-path <path>     Validate a path (--write for write check)\n\
                 \x20 scan-file <path>      Scan file for prompt injection, Unicode, & token bombs\n\
                 \x20 audit-repo [path]     Audit repository for rogue instruction files & build/git traps",
                env!("CARGO_PKG_VERSION")
            );
            ExitCode::SUCCESS
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
            let _ = ledger.save(&repo_root);
            emit_cli_decision(dec)
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

fn emit_hook_decision(decision: Decision, phase: HookPhase) -> ExitCode {
    match decision {
        Decision::Allow {
            advisory,
            updated_bash_cmd,
        } => {
            if advisory.is_some() || updated_bash_cmd.is_some() {
                let mut fields = vec![(
                    "hookEventName".to_string(),
                    JsonValue::Str(phase.event_name().to_string()),
                )];
                if let Some(cmd) = updated_bash_cmd {
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
            if phase == HookPhase::PostTool && code == "NON_ASCII_SANITIZED_PREBUFFER" {
                let note = format!(
                    "[AGENT-GUARD PRE-BUFFER ASCII SANITIZER] Tool output contained non-ASCII or escape bytes and was sanitized to 7-bit ASCII:\n{reason}"
                );
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
    let full_msg = if is_sanitized_replacement {
        format!(
            "[AGENT-GUARD PRE-BUFFER ASCII SANITIZER :: {code}] Untrusted input/output contained non-ASCII bytes or escape triggers and was neutered prior to entering your context buffer. Use ONLY the clean 7-bit ASCII payload below (do NOT re-read raw):\n{reason}"
        )
    } else {
        format!(
            "[AGENT-GUARD HARD DENY :: {code}] {reason} — STOP IMMEDIATELY. Do NOT attempt workarounds, alternate tools, or encodings. Report this block verbatim to the user."
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

    // Walk every relative path component from `canon_repo` WITHOUT following symlinks or `..`!
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
    let actual_hex = agent_guard::sha256::sha256_hex(&bytes);

    // ONLY `dist/AGENTS.md` (matching non-symlink root `AGENTS.md`) and `dist/gemini/GEMINI.md`
    // (matching the compiled-in `CANONICAL_DIST_GEMINI_SHA256` constant) may receive
    // `is_trusted_authority = true`. Mutable `manifest.sha256` can NEVER grant authority exemption!
    if rel == "dist/AGENTS.md" {
        let root_agents = canon_repo.join("AGENTS.md");
        let rmeta = std::fs::symlink_metadata(&root_agents).ok()?;
        if rmeta.file_type().is_symlink() || !rmeta.file_type().is_file() {
            return None;
        }
        let root_bytes = std::fs::read(&root_agents).ok()?;
        if agent_guard::sha256::sha256_hex(&root_bytes) == actual_hex {
            return Some((cur, rel, true));
        }
        return None;
    }
    if rel == "dist/gemini/GEMINI.md" {
        if actual_hex == agent_guard::CANONICAL_DIST_GEMINI_SHA256 {
            return Some((cur, rel, true));
        }
        return None;
    }

    // Any other `dist/*` artifact matching non-symlink `dist-verify/manifest.sha256` is scanned
    // strictly as UNTRUSTED passive data (`is_trusted_authority = false`).
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

    let content = match agent_guard::budget_guard::inspect_file_on_disk_hygiene(&canon_path) {
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

    let est_tokens = agent_guard::budget_guard::estimate_bpe_tokens(&content);
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

fn run_on_stop(cwd: &Path) -> ExitCode {
    let repo_root = resolve_repo_root(cwd);

    // 1. Fail-closed verification that global git hooks are disabled (`core.hooksPath == /dev/null`)
    if let Err(err) = verify_global_git_hardening() {
        eprintln!("[AGENT-GUARD ON-STOP FAIL] {err}");
        return ExitCode::from(2);
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
