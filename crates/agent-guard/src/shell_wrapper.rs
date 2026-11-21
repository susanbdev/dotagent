#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! `agent-guard-sh`: Drop-in POSIX `$SHELL` wrapper enforcing `cmd_policy` AST inspection,
//! `SessionLedger` (`A -> B` ceiling, halted/tainted circuit breaker), and `exec-sandbox`
//! kernel VFS + network confinement for harnesses lacking native `PreToolUse` hooks.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::json::JsonValue;
use crate::{Decision, handle_pre_tool_hook};

/// Entrypoint for `agent-guard-sh` (`-c <cmd>`, `-lc <cmd>`, or `<script_file> [args...]`).
pub fn run_shell_wrapper_entrypoint() -> ExitCode {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    run_shell_wrapper_with_args(&raw_args, &cwd)
}

/// Evaluates shell wrapper invocation arguments deterministically (fail-closed on unrecognized flags).
pub fn run_shell_wrapper_with_args(args: &[String], cwd: &Path) -> ExitCode {
    if args.is_empty() {
        eprintln!(
            "[agent-guard-sh HARD DENY :: INTERACTIVE_SHELL_BLOCKED] Interactive shell sessions without `-c` or a script path are blocked."
        );
        return ExitCode::from(2);
    }

    match args[0].as_str() {
        "--version" | "-V" => {
            println!("agent-guard-sh {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        "--help" | "-h" => {
            println!(
                "agent-guard-sh {} - Zero-Trust Mediating Wrapper Shell\nUsage: agent-guard-sh -c \"<command>\" | agent-guard-sh -lc \"<command>\"",
                env!("CARGO_PKG_VERSION")
            );
            return ExitCode::SUCCESS;
        }
        _ => {}
    }

    let parsed_inv = match parse_shell_wrapper_invocation(args, cwd) {
        Ok(inv) => inv,
        Err((code, msg)) => {
            eprintln!("[agent-guard-sh HARD DENY :: {code}] {msg}");
            return ExitCode::from(2);
        }
    };

    // Route through full PreToolUse hook pipeline (`SessionLedger` + `cmd_policy` + role sandbox)
    let hook_payload = JsonValue::Object(vec![
        ("tool_name".to_string(), JsonValue::Str("Bash".to_string())),
        (
            "tool_input".to_string(),
            JsonValue::Object(vec![(
                "command".to_string(),
                JsonValue::Str(parsed_inv.inspect_cmd.clone()),
            )]),
        ),
    ])
    .to_json_string();

    match handle_pre_tool_hook(&hook_payload, cwd) {
        Decision::Allow { .. } => {
            let repo_root = crate::resolve_repo_root(cwd);
            let final_exec = if parsed_inv.is_inline_c {
                if let Ok(plan) = crate::cmd_policy::evaluate_shell_command(
                    &parsed_inv.inspect_cmd,
                    &repo_root,
                    cwd,
                    false,
                ) && let Some(rewritten) = plan.rewritten_command
                {
                    format!("{}{rewritten}", parsed_inv.opt_prefix)
                } else {
                    parsed_inv.exec_cmd
                }
            } else {
                parsed_inv.exec_cmd
            };
            execute_inside_sandbox(&final_exec, cwd)
        }
        Decision::Deny { code, reason, .. } => {
            eprintln!("[agent-guard-sh HARD DENY :: {code}] {reason}");
            ExitCode::from(2)
        }
    }
}

struct ParsedShellInvocation {
    inspect_cmd: String,
    exec_cmd: String,
    opt_prefix: String,
    is_inline_c: bool,
}

fn single_quote_posix(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn parse_shell_wrapper_invocation(
    args: &[String],
    cwd: &Path,
) -> Result<ParsedShellInvocation, (&'static str, String)> {
    let mut idx = 0usize;
    let mut saw_c = false;
    let mut opt_errexit = false;
    let mut opt_nounset = false;

    while idx < args.len() {
        let arg = args[idx].as_str();
        match arg {
            "-c" | "-lc" | "-cl" => {
                saw_c = true;
                idx += 1;
                break;
            }
            "-ec" | "-ce" => {
                saw_c = true;
                opt_errexit = true;
                idx += 1;
                break;
            }
            "-e" => {
                opt_errexit = true;
                idx += 1;
            }
            "-u" => {
                opt_nounset = true;
                idx += 1;
            }
            "-l" | "--login" | "--norc" | "--noprofile" => {
                idx += 1;
            }
            "-o" => {
                let Some(opt_name) = args.get(idx + 1) else {
                    return Err((
                        "SHELL_WRAPPER_INVALID_ARGS",
                        "Missing option name after `-o`.".to_string(),
                    ));
                };
                match opt_name.as_str() {
                    "pipefail" => {}
                    "errexit" => opt_errexit = true,
                    "nounset" => opt_nounset = true,
                    _ => {
                        return Err((
                            "SHELL_WRAPPER_UNSAFE_OPTION",
                            format!("Disallowed shell option `-o {opt_name}` in agent-guard-sh."),
                        ));
                    }
                }
                idx += 2;
            }
            f if f.starts_with('-') => {
                return Err((
                    "SHELL_WRAPPER_UNSUPPORTED_FLAG",
                    format!("Unsupported or unsafe shell flag '{f}' in agent-guard-sh."),
                ));
            }
            _ => break,
        }
    }

    let build_prefix = |errexit: bool, nounset: bool| -> String {
        let mut p = String::new();
        if errexit {
            p.push_str("set -e; ");
        }
        if nounset {
            p.push_str("set -u; ");
        }
        p
    };
    let opt_prefix = build_prefix(opt_errexit, opt_nounset);

    if saw_c {
        let Some(cmd_str) = args.get(idx) else {
            return Err((
                "SHELL_WRAPPER_MISSING_CMD",
                "Missing command string after `-c`.".to_string(),
            ));
        };
        if args.len() > idx + 1 {
            // Positional arguments `$0 $1 ...` after `-c cmd` can smuggle uninspected tokens into `$@`
            return Err((
                "SHELL_WRAPPER_EXTRA_POSITIONAL_ARGS",
                "Positional arguments after `-c <cmd>` are forbidden to prevent `$@` parameter smuggling."
                    .to_string(),
            ));
        }
        let exec_cmd = if opt_prefix.is_empty() {
            cmd_str.clone()
        } else {
            format!("{opt_prefix}{cmd_str}")
        };
        return Ok(ParsedShellInvocation {
            inspect_cmd: cmd_str.clone(),
            exec_cmd,
            opt_prefix,
            is_inline_c: true,
        });
    }

    // Script file execution: verify regular non-symlink file, check sh/bash shebang, validate its
    // AST body via `evaluate_shell_command`, and execute cleanly by quoted canonical path!
    let Some(script_arg) = args.get(idx) else {
        return Err((
            "SHELL_WRAPPER_MISSING_TARGET",
            "Missing command or script path.".to_string(),
        ));
    };
    if args.len() > idx + 1 {
        return Err((
            "SHELL_WRAPPER_SCRIPT_ARGS_BLOCKED",
            "Script arguments are blocked in agent-guard-sh; pass an explicit inline command via `-c`."
                .to_string(),
        ));
    }
    let repo_root = crate::resolve_repo_root(cwd);
    let valid = crate::path_policy::validate_path(
        &repo_root,
        cwd,
        script_arg,
        crate::path_policy::PathAccess::Read,
    )
    .map_err(|pv| (pv.code, pv.detail))?;
    let smeta = std::fs::symlink_metadata(&valid.canonical_or_norm).map_err(|e| {
        (
            "FILE_STAT_ERROR",
            format!("Failed stat on script '{}': {e}", valid.repo_rel),
        )
    })?;
    if smeta.file_type().is_symlink() || !smeta.file_type().is_file() {
        return Err((
            "SYMLINK_ESCAPE_BLOCKED",
            format!(
                "Script '{}' must be a regular non-symlink file.",
                valid.repo_rel
            ),
        ));
    }
    let script_body = crate::budget_guard::inspect_file_on_disk_hygiene(&valid.canonical_or_norm)
        .map_err(|bv| (bv.code, bv.detail))?;
    if let Some(first_line) = script_body.lines().next()
        && let Some(interp_raw) = first_line.strip_prefix("#!")
    {
        let interp = interp_raw.trim();
        let allowed_shebang = matches!(
            interp,
            "/bin/sh"
                | "/bin/bash"
                | "/usr/bin/sh"
                | "/usr/bin/bash"
                | "/usr/bin/env sh"
                | "/usr/bin/env bash"
        );
        if !allowed_shebang {
            return Err((
                "UNAPPROVED_INTERPRETER_BLOCKED",
                format!(
                    "Script '{}' uses unapproved shebang '#!{interp}'; only sh/bash scripts are permitted.",
                    valid.repo_rel
                ),
            ));
        }
    }
    crate::cmd_policy::evaluate_shell_command(&script_body, &repo_root, cwd, false)
        .map_err(|cv| (cv.code, cv.detail))?;

    let quoted_path = single_quote_posix(&valid.canonical_or_norm.to_string_lossy());
    let mut bash_flags = String::from("bash --norc --noprofile -o pipefail");
    if opt_errexit {
        bash_flags.push_str(" -e");
    }
    if opt_nounset {
        bash_flags.push_str(" -u");
    }
    Ok(ParsedShellInvocation {
        inspect_cmd: script_body,
        exec_cmd: format!("{bash_flags} {quoted_path}"),
        opt_prefix,
        is_inline_c: false,
    })
}

fn emit_post_tool_filtered_output(combined: &str, cwd: &Path) -> Result<(), ExitCode> {
    if combined.is_empty() {
        return Ok(());
    }
    let post_payload = JsonValue::Object(vec![
        ("tool_name".to_string(), JsonValue::Str("Bash".to_string())),
        (
            "tool_response".to_string(),
            JsonValue::Str(combined.to_string()),
        ),
    ])
    .to_json_string();
    match crate::handle_post_tool_hook(&post_payload, cwd) {
        Decision::Allow { .. } => {
            print!("{combined}");
            Ok(())
        }
        Decision::Deny {
            code: "NON_ASCII_SANITIZED_PREBUFFER" | "TOOL_OUTPUT_FLOOD_BLOCKED",
            reason,
            ..
        } => {
            println!("{reason}");
            Ok(())
        }
        Decision::Deny { code, reason, .. } => {
            eprintln!("[agent-guard-sh POST-TOOL HARD DENY :: {code}] {reason}");
            Err(ExitCode::from(2))
        }
    }
}

fn status_to_exit_code(status: std::process::ExitStatus) -> ExitCode {
    if let Some(c) = status.code() {
        if let Ok(b) = u8::try_from(c) {
            return ExitCode::from(b);
        }
        return ExitCode::from(1);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            let low = u8::try_from(sig & 0x7f).unwrap_or(1);
            return ExitCode::from(128u8.saturating_add(low));
        }
    }
    ExitCode::from(1)
}

fn execute_inside_sandbox(cmd_str: &str, cwd: &Path) -> ExitCode {
    if let Some(bin) = resolve_trusted_agent_guard_exe() {
        match Command::new(bin)
            .current_dir(cwd)
            .arg("exec-sandbox")
            .arg("--sanitize-stream")
            .arg("--cwd")
            .arg(cwd)
            .arg("--")
            .arg(cmd_str)
            .output()
        {
            Ok(out) => {
                let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
                let err_txt = String::from_utf8_lossy(&out.stderr);
                if !err_txt.is_empty() {
                    if !combined.is_empty() && !combined.ends_with('\n') {
                        combined.push('\n');
                    }
                    combined.push_str(&err_txt);
                }
                if let Err(deny_exit) = emit_post_tool_filtered_output(&combined, cwd) {
                    return deny_exit;
                }
                status_to_exit_code(out.status)
            }
            Err(e) => {
                eprintln!("[agent-guard-sh] failed spawning exec-sandbox: {e}");
                ExitCode::from(126)
            }
        }
    } else {
        let repo_root = crate::resolve_repo_root(cwd);
        let needs_strict_kernel = match crate::budget_guard::load_active_profile(&repo_root) {
            Ok(prof) => prof.network_access_none || !prof.enable_write_tools,
            Err(_) => true,
        };
        if std::env::var("AGENT_GUARD_REQUIRE_KERNEL").as_deref() == Ok("1") || needs_strict_kernel
        {
            eprintln!(
                "[agent-guard-sh HARD DENY :: SANDBOX_BINARY_UNAVAILABLE] Trusted agent-guard binary is required to enforce kernel VFS/network isolation for the active profile."
            );
            return ExitCode::from(2);
        }
        // Fallback captured execution still enforces env scrubbing, Git lockdown, stream sanitization, and PostToolUse scanning!
        let mut fb_cmd = Command::new("bash");
        fb_cmd.current_dir(cwd);
        for var in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "DYLD_FRAMEWORK_PATH",
            "BASH_ENV",
            "ENV",
            "PROMPT_COMMAND",
            "SHELLOPTS",
            "BASHOPTS",
            "CDPATH",
            "GLOBIGNORE",
            "IFS",
            "NODE_OPTIONS",
            "PYTHONPATH",
            "PYTHONSTARTUP",
            "RUBYOPT",
            "PERL5OPT",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_TARGET_DIR",
            "GIT_EXTERNAL_DIFF",
            "GIT_SSH_COMMAND",
            "GIT_SSH",
            "GIT_ASKPASS",
            "GIT_EXEC_PATH",
            "GIT_TEMPLATE_DIR",
            "GIT_CONFIG_PARAMETERS",
            "AGENT_GUARD_COORDINATOR_SOCK",
            "DOTAGENT_RECEIPT_SEED_HEX",
        ] {
            fb_cmd.env_remove(var);
        }
        for (env_k, _) in std::env::vars_os() {
            if let Some(ks) = env_k.to_str() {
                let up = ks.to_ascii_uppercase();
                if up.starts_with("CARGO_TARGET_")
                    || up.starts_with("CARGO_ALIAS_")
                    || up.starts_with("CARGO_REGISTRIES_")
                    || up.starts_with("CARGO_SOURCE_")
                    || up.starts_with("GIT_CONFIG_KEY_")
                    || up.starts_with("GIT_CONFIG_VALUE_")
                {
                    fb_cmd.env_remove(&env_k);
                }
            }
        }
        let git_pairs: &[(&str, &str)] = &[
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
        fb_cmd.env("GIT_CONFIG_COUNT", git_pairs.len().to_string());
        for (idx, (k, v)) in git_pairs.iter().enumerate() {
            fb_cmd.env(format!("GIT_CONFIG_KEY_{idx}"), k);
            fb_cmd.env(format!("GIT_CONFIG_VALUE_{idx}"), v);
        }
        match fb_cmd
            .env("AGENT_GUARD_IN_SANDBOX", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("PIP_NO_CACHE_DIR", "1")
            .env("NPM_CONFIG_IGNORE_SCRIPTS", "true")
            .args(["--norc", "--noprofile", "-o", "pipefail", "-c", cmd_str])
            .output()
        {
            Ok(out) => {
                let mut raw_bytes = out.stdout;
                if !out.stderr.is_empty() {
                    if !raw_bytes.is_empty() && !raw_bytes.ends_with(b"\n") {
                        raw_bytes.push(b'\n');
                    }
                    raw_bytes.extend_from_slice(&out.stderr);
                }
                let san = crate::sanitizer::sanitize_and_compact_bytes(
                    &raw_bytes,
                    crate::sanitizer::DEFAULT_COMPACT_STREAM_MAX_LINES,
                    crate::sanitizer::DEFAULT_COMPACT_STREAM_MAX_BYTES,
                );
                if let Err(deny_exit) = emit_post_tool_filtered_output(&san.clean_ascii, cwd) {
                    return deny_exit;
                }
                status_to_exit_code(out.status)
            }
            Err(e) => {
                eprintln!("[agent-guard-sh] failed spawning fallback bash: {e}");
                ExitCode::from(126)
            }
        }
    }
}

fn resolve_trusted_agent_guard_exe() -> Option<PathBuf> {
    if let Ok(cur) = std::env::current_exe()
        && let Some(dir) = cur.parent()
    {
        for name in ["agent-guard", "dotagent"] {
            let cand = dir.join(name);
            if crate::coordinator::is_trusted_executable_file(&cand) {
                return Some(cand);
            }
        }
        if let Some(parent_dir) = dir.parent() {
            for name in ["agent-guard", "dotagent"] {
                let cand = parent_dir.join(name);
                if crate::coordinator::is_trusted_executable_file(&cand) {
                    return Some(cand);
                }
            }
        }
    }
    None
}
