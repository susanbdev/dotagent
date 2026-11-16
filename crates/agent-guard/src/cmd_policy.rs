#![forbid(unsafe_code)]

//! Shell AST & command security policy engine.
//! Tokenizes POSIX/Bash command lines (resolving quote-splitting bypasses like
//! `c'a't /t"m"p/x` or `g\it push --force`), recursively extracts nested subshells,
//! command substitutions `$(...)` / `` `...` ``, process substitutions, redirections,
//! and indirect wrappers (`sh -c`, `bash -c`, `eval`, `env`, `xargs`), and enforces
//! zero-trust path, depth<=2, git-hook/config, package-script, and anti-confused-deputy rules.

use std::path::Path;

use crate::path_policy::{PathAccess, check_forbidden_zones_lexical, validate_path};
use crate::unicode_guard::{ScanMode, scan_unicode};

const MAX_SHELL_NESTING: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandViolation {
    pub code: &'static str,
    pub detail: String,
    pub halt_session: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CommandPlan {
    /// Repo-relative + canonical file paths read by this command (checked against budget + A->B->C ledger!)
    pub read_files: Vec<(String, std::path::PathBuf, bool)>,
    /// Repo-relative + canonical file paths mutated by this command
    pub write_files: Vec<(String, std::path::PathBuf)>,
}

#[derive(Debug, Clone)]
struct ParsedCommand {
    env_vars: Vec<(String, String)>,
    argv: Vec<String>,
    redirs: Vec<(RedirKind, String)>,
    piped_stdin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedirKind {
    Read,
    Write,
    Heredoc,
}

pub fn evaluate_shell_command(
    raw_cmd: &str,
    repo_root: &Path,
    cwd: &Path,
    session_tainted: bool,
) -> Result<CommandPlan, CommandViolation> {
    let trimmed = raw_cmd.trim();
    if trimmed.is_empty() {
        return Ok(CommandPlan::default());
    }

    // 1. Unicode, ANSI escape, $'...' quote, and homoglyph check
    let unicode_issues = scan_unicode(trimmed, ScanMode::StrictPathOrCommand);
    if let Some(first) = unicode_issues.first() {
        return Err(CommandViolation {
            code: first.code,
            detail: format!(
                "Shell command failed Unicode/escape guard: {}",
                first.detail
            ),
            halt_session: true,
        });
    }

    // 2. Block shell metacharacter smuggling patterns (${IFS}, parameter substring obfuscation)
    if trimmed.contains("$IFS") || trimmed.contains("${IFS") {
        return Err(CommandViolation {
            code: "SHELL_IFS_OBFUSCATION",
            detail: "$IFS word-splitting obfuscation is forbidden.".to_string(),
            halt_session: true,
        });
    }

    let mut plan = CommandPlan::default();
    analyze_recursive(trimmed, repo_root, cwd, session_tainted, 0, &mut plan)?;
    Ok(plan)
}

fn analyze_recursive(
    script: &str,
    repo_root: &Path,
    cwd: &Path,
    session_tainted: bool,
    depth: usize,
    plan: &mut CommandPlan,
) -> Result<(), CommandViolation> {
    if depth > MAX_SHELL_NESTING {
        return Err(CommandViolation {
            code: "SHELL_NESTING_EXCEEDED",
            detail: format!("Shell subshell/wrapper nesting exceeded limit ({MAX_SHELL_NESTING})."),
            halt_session: true,
        });
    }

    let mut subscripts = Vec::new();
    let commands = parse_shell_script(script, &mut subscripts)?;

    // Inspect nested `$(...)`, backticks, `<(...)`, subshells `(...)` first
    for sub in &subscripts {
        analyze_recursive(sub, repo_root, cwd, session_tainted, depth + 1, plan)?;
    }

    // Detect `base64 -d` / `xxd -r` / `openssl enc -d` anywhere in pipeline paired with shell/interpreter
    let has_decoder = commands.iter().any(is_payload_decoder);
    let has_interpreter = commands.iter().any(is_shell_or_interpreter);
    if has_decoder && has_interpreter {
        return Err(CommandViolation {
            code: "ENCODED_EXECUTION_PIPELINE",
            detail: "Decoding base64/hex directly into a shell or interpreter is hard-blocked."
                .to_string(),
            halt_session: true,
        });
    }

    for cmd in &commands {
        check_single_command(cmd, repo_root, cwd, session_tainted, depth, plan)?;
    }

    Ok(())
}

fn is_payload_decoder(cmd: &ParsedCommand) -> bool {
    let Some(bin) = cmd.argv.first().map(|s| basename(s)) else {
        return false;
    };
    match bin {
        "base64" => cmd
            .argv
            .iter()
            .any(|a| a == "-d" || a == "-D" || a == "--decode"),
        "xxd" => cmd.argv.iter().any(|a| a == "-r" || a == "-p"),
        "openssl" => cmd.argv.iter().any(|a| a == "enc" || a == "base64"),
        _ => false,
    }
}

fn is_shell_or_interpreter(cmd: &ParsedCommand) -> bool {
    let Some(bin) = cmd.argv.first().map(|s| basename(s)) else {
        return false;
    };
    matches!(
        bin,
        "sh" | "bash"
            | "dash"
            | "zsh"
            | "ksh"
            | "eval"
            | "source"
            | "."
            | "python"
            | "python3"
            | "node"
            | "perl"
            | "ruby"
            | "php"
            | "lua"
    )
}

fn check_single_command(
    cmd: &ParsedCommand,
    repo_root: &Path,
    cwd: &Path,
    session_tainted: bool,
    depth: usize,
    plan: &mut CommandPlan,
) -> Result<(), CommandViolation> {
    // 1. Validate environment variable assignments
    for (k, v) in &cmd.env_vars {
        check_env_assignment(k, v, repo_root, cwd)?;
    }

    // 2. Validate redirections (`> file`, `< file`)
    for (kind, target) in &cmd.redirs {
        if *kind == RedirKind::Heredoc || target.starts_with('&') {
            continue;
        }
        // Allow `/dev/null` redirection safely
        if target == "/dev/null" {
            continue;
        }
        reject_shell_glob_in_operand("redirection", target)?;
        let access = match kind {
            RedirKind::Read => PathAccess::Read,
            RedirKind::Write => PathAccess::Write,
            RedirKind::Heredoc => continue,
        };
        let valid =
            validate_path(repo_root, cwd, target, access).map_err(|pv| CommandViolation {
                code: pv.code,
                detail: format!("Redirection target '{target}' denied: {}", pv.detail),
                halt_session: pv.is_poisoned_zone,
            })?;
        match kind {
            RedirKind::Read => plan.read_files.push((
                valid.repo_rel,
                valid.canonical_or_norm,
                valid.is_root_authority,
            )),
            RedirKind::Write => plan
                .write_files
                .push((valid.repo_rel, valid.canonical_or_norm)),
            RedirKind::Heredoc => {}
        }
    }

    if cmd.argv.is_empty() {
        return Ok(());
    }

    let raw_bin = &cmd.argv[0];
    // Reject dynamic variable expansion in binary name (`$CMD`, `${CMD}`)
    if raw_bin.contains('$') {
        return Err(CommandViolation {
            code: "DYNAMIC_COMMAND_OBFUSCATION",
            detail: format!("Dynamic variable command invocation '{raw_bin}' is forbidden."),
            halt_session: true,
        });
    }
    // Check if binary path itself lives inside `/tmp`, `.cache`, `node_modules`, `.git/hooks`!
    if raw_bin.contains('/') {
        if raw_bin.contains(".git/hooks") {
            return Err(CommandViolation {
                code: "GIT_HOOK_EXECUTION_BLOCKED",
                detail: "Direct execution of .git/hooks scripts is strictly forbidden.".to_string(),
                halt_session: true,
            });
        }
        if let Err(pv) = check_forbidden_zones_lexical(raw_bin, raw_bin) {
            return Err(CommandViolation {
                code: pv.code,
                detail: format!(
                    "Executing binary from forbidden path '{raw_bin}': {}",
                    pv.detail
                ),
                halt_session: true,
            });
        }
    }

    let bin = basename(raw_bin);
    let args = &cmd.argv[1..];

    // 3. Unwrap prefix/nested command wrappers (`env`, `command`, `exec`, `nohup`, `timeout`, `nice`, `sh -c`, `eval`, `xargs`)
    match bin {
        "command" | "builtin" | "exec" | "nohup" => {
            let sub_argv = strip_leading_flags(args);
            if !sub_argv.is_empty() {
                let inner = ParsedCommand {
                    env_vars: Vec::new(),
                    argv: sub_argv.to_vec(),
                    redirs: cmd.redirs.clone(),
                    piped_stdin: cmd.piped_stdin,
                };
                return check_single_command(
                    &inner,
                    repo_root,
                    cwd,
                    session_tainted,
                    depth + 1,
                    plan,
                );
            }
            return Ok(());
        }
        "timeout" | "nice" => {
            // Skip flags and numeric duration/niceness, inspect wrapped command
            let mut idx = 0;
            while idx < args.len() && args[idx].starts_with('-') {
                if matches!(args[idx].as_str(), "-k" | "-s" | "-n") {
                    idx += 2;
                } else {
                    idx += 1;
                }
            }
            if bin == "timeout" && idx < args.len() {
                idx += 1; // duration argument
            }
            if idx < args.len() {
                let inner = ParsedCommand {
                    env_vars: Vec::new(),
                    argv: args[idx..].to_vec(),
                    redirs: cmd.redirs.clone(),
                    piped_stdin: cmd.piped_stdin,
                };
                return check_single_command(
                    &inner,
                    repo_root,
                    cwd,
                    session_tainted,
                    depth + 1,
                    plan,
                );
            }
            return Ok(());
        }
        "env" => {
            if args.is_empty() {
                return Err(CommandViolation {
                    code: "SECRET_ENV_DUMP_BLOCKED",
                    detail: "Dumping environment variables via bare `env` is forbidden."
                        .to_string(),
                    halt_session: false,
                });
            }
            let mut idx = 0;
            while idx < args.len() {
                let a = &args[idx];
                if a == "-i" || a == "--ignore-environment" {
                    idx += 1;
                } else if a == "-u" || a == "--unset" {
                    idx += 2;
                } else if let Some((k, v)) = a.split_once('=') {
                    check_env_assignment(k, v, repo_root, cwd)?;
                    idx += 1;
                } else if a.starts_with('-') {
                    return Err(CommandViolation {
                        code: "ENV_FLAG_BLOCKED",
                        detail: format!("Disallowed `env` flag '{a}'."),
                        halt_session: false,
                    });
                } else {
                    break;
                }
            }
            if idx >= args.len() {
                return Err(CommandViolation {
                    code: "SECRET_ENV_DUMP_BLOCKED",
                    detail:
                        "Dumping environment variables via `env` without a command is forbidden."
                            .to_string(),
                    halt_session: false,
                });
            }
            let inner = ParsedCommand {
                env_vars: Vec::new(),
                argv: args[idx..].to_vec(),
                redirs: cmd.redirs.clone(),
                piped_stdin: cmd.piped_stdin,
            };
            return check_single_command(&inner, repo_root, cwd, session_tainted, depth + 1, plan);
        }
        "sh" | "bash" | "dash" | "zsh" | "ksh" => {
            let mut idx = 0usize;
            while idx < args.len() {
                let a = args[idx].as_str();
                if a == "--rcfile"
                    || a == "--init-file"
                    || a.starts_with("--rcfile=")
                    || a.starts_with("--init-file=")
                {
                    return Err(CommandViolation {
                        code: "SHELL_RCFILE_OVERRIDE_BLOCKED",
                        detail: format!("`{bin} {a}` startup script override is forbidden."),
                        halt_session: true,
                    });
                }
                if a == "-o" || a == "+o" {
                    idx += 2;
                    continue;
                }
                if a.starts_with('-') && !a.starts_with("--") {
                    if let Some(c_pos) = a[1..].find('c') {
                        let after_c = &a[1 + c_pos + 1..];
                        let sub_script = if !after_c.is_empty() {
                            after_c
                        } else if let Some(next_arg) = args.get(idx + 1) {
                            next_arg.as_str()
                        } else {
                            return Err(CommandViolation {
                                code: "MALFORMED_SUBSHELL",
                                detail: format!("`{bin} -c` missing command string."),
                                halt_session: false,
                            });
                        };
                        return analyze_recursive(
                            sub_script,
                            repo_root,
                            cwd,
                            session_tainted,
                            depth + 1,
                            plan,
                        );
                    }
                }
                idx += 1;
            }

            let reads_stdin_commands = args.iter().any(|a| a == "-s" || a == "-");
            let has_stdin_stream = cmd.piped_stdin
                || cmd
                    .redirs
                    .iter()
                    .any(|(k, _)| matches!(k, RedirKind::Heredoc | RedirKind::Read));

            // Executing a script file `bash path/to/script.sh` — validate path & require read check
            let mut found_script_file = false;
            for a in args {
                if a == "-" {
                    return Err(CommandViolation {
                        code: "STDIN_SCRIPT_EXECUTION_BLOCKED",
                        detail: format!(
                            "Executing uninspected commands from stdin via `{bin} -` is forbidden."
                        ),
                        halt_session: true,
                    });
                }
                if !a.starts_with('-') {
                    reject_shell_glob_in_operand(bin, a)?;
                    let valid =
                        validate_path(repo_root, cwd, a, PathAccess::Read).map_err(|pv| {
                            CommandViolation {
                                code: pv.code,
                                detail: format!("Shell script '{a}' blocked: {}", pv.detail),
                                halt_session: pv.is_poisoned_zone,
                            }
                        })?;
                    plan.read_files.push((
                        valid.repo_rel,
                        valid.canonical_or_norm,
                        valid.is_root_authority,
                    ));
                    found_script_file = true;
                }
            }
            if reads_stdin_commands || (!found_script_file && has_stdin_stream) {
                return Err(CommandViolation {
                    code: "STDIN_SCRIPT_EXECUTION_BLOCKED",
                    detail: format!(
                        "Piping or redirecting uninspected shell commands into `{bin}` stdin is forbidden."
                    ),
                    halt_session: true,
                });
            }
            return Ok(());
        }
        "eval" => {
            let joined = args.join(" ");
            return analyze_recursive(&joined, repo_root, cwd, session_tainted, depth + 1, plan);
        }
        "source" | "." => {
            if let Some(script_path) = args.first() {
                reject_shell_glob_in_operand(bin, script_path)?;
                let valid =
                    validate_path(repo_root, cwd, script_path, PathAccess::Read).map_err(|pv| {
                        CommandViolation {
                            code: pv.code,
                            detail: format!("Sourcing '{script_path}' blocked: {}", pv.detail),
                            halt_session: pv.is_poisoned_zone,
                        }
                    })?;
                plan.read_files.push((
                    valid.repo_rel,
                    valid.canonical_or_norm,
                    valid.is_root_authority,
                ));
            }
            return Ok(());
        }
        "xargs" => {
            let mut idx = 0;
            while idx < args.len() && args[idx].starts_with('-') {
                if matches!(
                    args[idx].as_str(),
                    "-I" | "-L" | "-n" | "-P" | "-s" | "-d" | "-E" | "-a"
                ) {
                    if args[idx] == "-a" {
                        if let Some(f) = args.get(idx + 1) {
                            reject_shell_glob_in_operand("xargs -a", f)?;
                            let valid = validate_path(repo_root, cwd, f, PathAccess::Read)
                                .map_err(|pv| CommandViolation {
                                    code: pv.code,
                                    detail: pv.detail,
                                    halt_session: pv.is_poisoned_zone,
                                })?;
                            plan.read_files.push((
                                valid.repo_rel,
                                valid.canonical_or_norm,
                                valid.is_root_authority,
                            ));
                        }
                    }
                    idx += 2;
                } else {
                    idx += 1;
                }
            }
            if idx < args.len() {
                let target_bin = basename(&args[idx]);
                if !matches!(target_bin, "echo" | "printf" | "true") {
                    return Err(CommandViolation {
                        code: "XARGS_DYNAMIC_ARGS_BLOCKED",
                        detail: format!(
                            "`xargs {target_bin}` dynamically injects unvalidated stdin tokens into command arguments and is forbidden."
                        ),
                        halt_session: true,
                    });
                }
                let inner = ParsedCommand {
                    env_vars: Vec::new(),
                    argv: args[idx..].to_vec(),
                    redirs: Vec::new(),
                    piped_stdin: false,
                };
                return check_single_command(
                    &inner,
                    repo_root,
                    cwd,
                    session_tainted,
                    depth + 1,
                    plan,
                );
            }
            return Ok(());
        }
        _ => {}
    }

    // 4. Hard-blocked privilege escalation, system mutation, temp, & env-dump commands
    if matches!(
        bin,
        "sudo"
            | "su"
            | "doas"
            | "pkexec"
            | "chroot"
            | "nsenter"
            | "unshare"
            | "mount"
            | "umount"
            | "chown"
            | "chgrp"
            | "chattr"
            | "crontab"
            | "at"
            | "systemctl"
            | "service"
    ) {
        return Err(CommandViolation {
            code: "PRIVILEGE_ESCALATION_BLOCKED",
            detail: format!("System/privilege binary `{bin}` is strictly forbidden."),
            halt_session: false,
        });
    }

    if bin == "chmod" {
        return Err(CommandViolation {
            code: "PERMISSION_MUTATION_BLOCKED",
            detail: "`chmod` permission mutation by agents is blocked.".to_string(),
            halt_session: false,
        });
    }

    if bin == "mktemp" {
        return Err(CommandViolation {
            code: "FORBIDDEN_TMP_PATH",
            detail: "`mktemp` creates files in temporary directories, which is strictly forbidden."
                .to_string(),
            halt_session: true,
        });
    }

    if matches!(bin, "printenv" | "set") && (bin == "printenv" || args.is_empty()) {
        return Err(CommandViolation {
            code: "SECRET_ENV_DUMP_BLOCKED",
            detail: format!("Dumping environment secrets via `{bin}` is forbidden."),
            halt_session: false,
        });
    }
    if (bin == "export" && args.iter().any(|a| a == "-p"))
        || (bin == "declare" && args.iter().any(|a| a == "-x" || a == "-p"))
    {
        return Err(CommandViolation {
            code: "SECRET_ENV_DUMP_BLOCKED",
            detail: "Dumping exported shell environment variables is forbidden.".to_string(),
            halt_session: false,
        });
    }

    // Prevent agent from invoking `agent-guard` state-reset, user-prompt, or pre-compact hooks directly
    if bin == "agent-guard" {
        if let Some(sub) = args.first().map(String::as_str) {
            if matches!(
                sub,
                "user-prompt" | "reset" | "reset-session" | "pre-compact" | "compact-reset"
            ) {
                return Err(CommandViolation {
                    code: "SELF_TAMPERING_BLOCKED",
                    detail:
                        "Agents may not reset agent-guard session/compaction state or spoof lifecycle hooks."
                            .to_string(),
                    halt_session: true,
                });
            }
            if matches!(sub, "read-safe" | "scan-file") {
                if let Some(target_file) = args.get(1) {
                    validate_path(repo_root, cwd, target_file, PathAccess::Read).map_err(|pv| {
                        CommandViolation {
                            code: pv.code,
                            detail: pv.detail,
                            halt_session: pv.is_poisoned_zone,
                        }
                    })?;
                }
                return Ok(());
            }
            if sub == "sanitize-stream" {
                return Ok(());
            }
        }
    }

    // 5. Outbound network & exfiltration binaries (Zero Unvetted Network Execution + Anti-Exfil)
    if matches!(
        bin,
        "curl"
            | "wget"
            | "nc"
            | "ncat"
            | "netcat"
            | "socat"
            | "telnet"
            | "ftp"
            | "tftp"
            | "scp"
            | "sftp"
            | "ssh"
            | "dig"
            | "nslookup"
            | "host"
            | "whois"
    ) {
        return Err(CommandViolation {
            code: "NETWORK_EXFILTRATION_BLOCKED",
            detail: format!(
                "Outbound network/socket utility `{bin}` is hard-blocked to eliminate data exfiltration and SSRF/confused-deputy attacks."
            ),
            halt_session: false,
        });
    }

    // 6. Confused Deputy Gate on Ambient-Authority CLIs (`gh`, `gdocs`, `gdrive`, `gsheets`, `gslides`, `gcalendar`)
    if matches!(
        bin,
        "gh" | "gdocs" | "gdrive" | "gsheets" | "gslides" | "gcalendar"
    ) {
        check_ambient_authority_cli(bin, args, session_tainted)?;
        return Ok(());
    }

    // 7. Git Lockdown (hooks disabled, fsmonitor/filter/ext blocked, non-destructive, bounded log)
    if bin == "git" {
        check_git_command(args, repo_root, cwd, session_tainted)?;
        return Ok(());
    }

    // 8. Package Manager Lifecycle Script, Build-Config Trap, & Publish Lockdown
    if matches!(bin, "npm" | "pnpm" | "yarn" | "bun" | "npx" | "bunx") {
        check_node_pkg_manager(bin, args, repo_root, cwd)?;
        return Ok(());
    }
    if matches!(bin, "pip" | "pip3" | "uv") {
        check_python_pkg_manager(bin, args)?;
        return Ok(());
    }
    if bin == "cargo" {
        check_cargo_command(args, repo_root, cwd)?;
        return Ok(());
    }

    // 9. Inline Interpreter One-Liner & Stdin Script Inspection (`python -c`, `node -e`, `| python3`, `<<EOF`)
    if matches!(
        bin,
        "python" | "python3" | "node" | "perl" | "ruby" | "php" | "lua"
    ) {
        let has_code_stdin = cmd.piped_stdin
            || cmd
                .redirs
                .iter()
                .any(|(k, _)| matches!(k, RedirKind::Heredoc | RedirKind::Read));
        check_interpreter_command(bin, args, has_code_stdin, repo_root, cwd, plan)?;
        return Ok(());
    }

    // 10. Search & Directory Walk Depth Ceiling (`<= 2` levels)
    if matches!(
        bin,
        "find" | "rg" | "ripgrep" | "fd" | "fdfind" | "tree" | "ls" | "grep" | "egrep" | "fgrep"
    ) {
        check_search_or_walk_command(bin, args, repo_root, cwd, plan)?;
        return Ok(());
    }

    // 11. Standard File Reading / Writing Utilities -> validate every path operand!
    check_file_utility_paths(bin, args, repo_root, cwd, plan)?;

    Ok(())
}

fn check_env_assignment(
    key: &str,
    val: &str,
    repo_root: &Path,
    cwd: &Path,
) -> Result<(), CommandViolation> {
    let ku = key.to_ascii_uppercase();
    if ku.starts_with("AGENT_GUARD")
        || ku.starts_with("GIT_")
        || ku.starts_with("LD_")
        || ku.starts_with("DYLD_")
        || matches!(
            ku.as_str(),
            "BASH_ENV"
                | "ENV"
                | "PROMPT_COMMAND"
                | "IFS"
                | "CDPATH"
                | "TMPDIR"
                | "TMP"
                | "TEMP"
                | "NODE_OPTIONS"
                | "PYTHONPATH"
                | "PYTHONSTARTUP"
                | "RUBYOPT"
                | "PERL5OPT"
                | "RUSTC_WRAPPER"
                | "CARGO_BUILD_RUSTC_WRAPPER"
                | "HTTP_PROXY"
                | "HTTPS_PROXY"
                | "ALL_PROXY"
                | "NO_PROXY"
                | "SSL_CERT_FILE"
                | "SSL_CERT_DIR"
        )
    {
        return Err(CommandViolation {
            code: "DANGEROUS_ENV_OVERRIDE",
            detail: format!(
                "Overriding security-critical environment variable `{key}` is hard-blocked."
            ),
            halt_session: true,
        });
    }

    if val.contains('/') {
        if let Err(pv) = check_forbidden_zones_lexical(val, val) {
            let _ = (repo_root, cwd);
            return Err(CommandViolation {
                code: pv.code,
                detail: format!(
                    "Env variable `{key}` points to forbidden zone: {}",
                    pv.detail
                ),
                halt_session: pv.is_poisoned_zone,
            });
        }
    }
    Ok(())
}

fn check_ambient_authority_cli(
    bin: &str,
    args: &[String],
    session_tainted: bool,
) -> Result<(), CommandViolation> {
    let allow_deputy = std::env::var("AGENT_GUARD_ALLOW_DEPUTY")
        .map(|v| v == "1")
        .unwrap_or(false);

    if session_tainted {
        return Err(CommandViolation {
            code: "CONFUSED_DEPUTY_TAINTED_SESSION",
            detail: format!(
                "Privileged CLI `{bin}` is hard-blocked because the current session is tainted by untrusted content."
            ),
            halt_session: false,
        });
    }

    if bin != "gh" {
        // Google Workspace CLIs (`gdocs`, `gdrive`, etc.) carry user OAuth — block mutations or require explicit deputy capability
        if !allow_deputy {
            return Err(CommandViolation {
                code: "CONFUSED_DEPUTY_WORKSPACE_CLI",
                detail: format!(
                    "Ambient-authority Workspace CLI `{bin}` is blocked by zero-trust confused-deputy policy unless explicitly authorized by the human."
                ),
                halt_session: false,
            });
        }
        return Ok(());
    }

    // For `gh`: skip global/interleaved flags (`-R`, `--repo`, `-H`, `--hostname`, etc.) before extracting subcommands
    let mut positional: Vec<&str> = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            for rest in &args[i + 1..] {
                positional.push(rest.as_str());
            }
            break;
        }
        if matches!(
            a,
            "-R" | "--repo"
                | "-H"
                | "--hostname"
                | "-X"
                | "--method"
                | "-f"
                | "-F"
                | "--field"
                | "--raw-field"
                | "--input"
                | "-q"
                | "--jq"
                | "-t"
                | "--template"
        ) {
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        positional.push(a);
        i += 1;
    }

    let sub1 = positional.first().copied().unwrap_or("");
    let sub2 = positional.get(1).copied().unwrap_or("");

    if matches!(
        sub1,
        "auth" | "secret" | "variable" | "ssh-key" | "gpg-key" | "codespace"
    ) {
        return Err(CommandViolation {
            code: "GH_CREDENTIAL_ACCESS_BLOCKED",
            detail: format!(
                "`gh {sub1}` credential/secret operation is unconditionally forbidden."
            ),
            halt_session: true,
        });
    }

    if sub1 == "api" {
        let mutates = args.iter().any(|a| {
            let u = a.to_ascii_uppercase();
            u == "POST"
                || u == "PUT"
                || u == "PATCH"
                || u == "DELETE"
                || a == "-f"
                || a == "-F"
                || a.starts_with("--field")
                || a.starts_with("--raw-field")
                || a.starts_with("--input")
                || a == "--method"
                || a == "-X"
                || a.starts_with("-X")
                    && matches!(
                        a.strip_prefix("-X")
                            .unwrap_or("")
                            .to_ascii_uppercase()
                            .as_str(),
                        "POST" | "PUT" | "PATCH" | "DELETE"
                    )
        });
        if mutates && !allow_deputy {
            return Err(CommandViolation {
                code: "CONFUSED_DEPUTY_GH_MUTATION",
                detail: "Mutating `gh api` request blocked (confused-deputy protection). Ask the human to run or authorize."
                    .to_string(),
                halt_session: false,
            });
        }
        return Ok(());
    }

    let is_mutation = matches!(
        (sub1, sub2),
        (
            "pr",
            "create" | "merge" | "close" | "reopen" | "comment" | "review" | "edit" | "ready"
        ) | (
            "issue",
            "create" | "close" | "reopen" | "comment" | "edit" | "delete" | "transfer"
        ) | (
            "repo",
            "create" | "delete" | "archive" | "edit" | "fork" | "rename"
        ) | ("release", _)
            | ("workflow", "run" | "enable" | "disable")
            | ("gist", _)
    );

    if is_mutation && !allow_deputy {
        return Err(CommandViolation {
            code: "CONFUSED_DEPUTY_GH_MUTATION",
            detail: format!(
                "`gh {sub1} {sub2}` exercises ambient GitHub authority and is blocked by confused-deputy policy. Present the proposed command to the human."
            ),
            halt_session: false,
        });
    }

    Ok(())
}

fn check_git_command(
    args: &[String],
    repo_root: &Path,
    cwd: &Path,
    session_tainted: bool,
) -> Result<(), CommandViolation> {
    let mut idx = 0usize;
    let mut target_dir: Option<&str> = None;

    // Inspect global git flags before subcommand (`-c`, `-C`, `--git-dir`, `--upload-pack`, `--no-verify`)
    while idx < args.len() {
        let a = args[idx].as_str();
        if a == "-c" {
            let kv = args.get(idx + 1).map(String::as_str).unwrap_or("");
            check_git_inline_config(kv)?;
            idx += 2;
            continue;
        }
        if let Some(kv) = a.strip_prefix("-c") {
            if !kv.is_empty() {
                check_git_inline_config(kv)?;
                idx += 1;
                continue;
            }
        }
        if a == "-C" {
            if let Some(dir) = args.get(idx + 1) {
                validate_path(
                    repo_root,
                    cwd,
                    dir,
                    PathAccess::ListSearch {
                        requested_depth: Some(1),
                    },
                )
                .map_err(|pv| CommandViolation {
                    code: pv.code,
                    detail: format!("`git -C {dir}` denied: {}", pv.detail),
                    halt_session: pv.is_poisoned_zone,
                })?;
                target_dir = Some(dir.as_str());
            }
            idx += 2;
            continue;
        }
        if a.starts_with("--upload-pack")
            || a.starts_with("--receive-pack")
            || a.starts_with("--exec")
            || a.starts_with("--git-dir")
            || a.starts_with("--work-tree")
        {
            return Err(CommandViolation {
                code: "GIT_RCE_FLAG_BLOCKED",
                detail: format!("Dangerous git flag `{a}` is hard-blocked."),
                halt_session: true,
            });
        }
        if !a.starts_with('-') {
            break;
        }
        idx += 1;
    }

    inspect_repo_git_config_and_hooks(repo_root)?;
    if let Some(dir_str) = target_dir {
        let sub_dir = if Path::new(dir_str).is_absolute() {
            std::path::PathBuf::from(dir_str)
        } else {
            cwd.join(dir_str)
        };
        if sub_dir != repo_root {
            inspect_repo_git_config_and_hooks(&sub_dir)?;
        }
    }
    if repo_root.join(".git").join("config").exists()
        && let Err(msg) = crate::verify_global_git_hardening()
    {
        return Err(CommandViolation {
            code: "GIT_HARDENING_NOT_ACTIVE",
            detail: msg,
            halt_session: true,
        });
    }

    let Some(sub) = args.get(idx).map(String::as_str) else {
        return Ok(());
    };
    let sub_args = &args[idx + 1..];

    // Hard-block `--no-verify` anywhere
    if sub_args
        .iter()
        .any(|x| x == "--no-verify" || x == "-n" && sub == "commit")
    {
        return Err(CommandViolation {
            code: "GIT_NO_VERIFY_BLOCKED",
            detail: "Passing `--no-verify` (or `git commit -n`) is forbidden.".to_string(),
            halt_session: false,
        });
    }

    match sub {
        "hook" => {
            return Err(CommandViolation {
                code: "GIT_HOOK_DISABLED",
                detail: "Git hooks are globally disabled (`core.hooksPath=/dev/null`); `git hook` is forbidden."
                    .to_string(),
                halt_session: true,
            });
        }
        "config" => {
            // Allow read-only `--get` of non-secret keys? No — block `git config` mutations and global dumps
            let is_read_only = sub_args
                .iter()
                .all(|x| x == "--get" || x == "core.hooksPath" || x == "core.fsmonitor");
            if !is_read_only {
                return Err(CommandViolation {
                    code: "GIT_CONFIG_MUTATION_BLOCKED",
                    detail: "`git config` inspection/mutation is blocked to protect global git hardening and identity."
                        .to_string(),
                    halt_session: false,
                });
            }
        }
        "commit" => {
            if sub_args
                .iter()
                .any(|x| x == "--amend" || x.starts_with("--amend="))
            {
                return Err(CommandViolation {
                    code: "GIT_DESTRUCTIVE_AMEND",
                    detail: "`git commit --amend` is forbidden; create a new commit instead."
                        .to_string(),
                    halt_session: false,
                });
            }
        }
        "rebase" | "filter-branch" | "fast-import" => {
            return Err(CommandViolation {
                code: "GIT_HISTORY_REWRITE_BLOCKED",
                detail: format!("History-rewriting command `git {sub}` is forbidden."),
                halt_session: false,
            });
        }
        "reset" => {
            if sub_args.iter().any(|x| x == "--hard" || x == "--merge") {
                return Err(CommandViolation {
                    code: "GIT_DESTRUCTIVE_RESET",
                    detail: "`git reset --hard` is forbidden.".to_string(),
                    halt_session: false,
                });
            }
        }
        "clean" => {
            return Err(CommandViolation {
                code: "GIT_CLEAN_BLOCKED",
                detail: "`git clean` destructive working-tree deletion is forbidden.".to_string(),
                halt_session: false,
            });
        }
        "push" => {
            if sub_args.iter().any(|x| {
                x == "-f"
                    || x == "--force"
                    || x.starts_with("--force-with-lease")
                    || x.starts_with("--force-if-includes")
                    || x.starts_with('+')
                    || x == "--delete"
                    || x == "-d"
            }) {
                return Err(CommandViolation {
                    code: "GIT_FORCE_PUSH_BLOCKED",
                    detail: "Force-pushing or remote ref deletion via `git push` is unconditionally forbidden."
                        .to_string(),
                    halt_session: false,
                });
            }
            let allow_deputy = std::env::var("AGENT_GUARD_ALLOW_DEPUTY")
                .map(|v| v == "1")
                .unwrap_or(false);
            if session_tainted || !allow_deputy {
                return Err(CommandViolation {
                    code: "CONFUSED_DEPUTY_GIT_PUSH",
                    detail: "Autonomous `git push` is blocked by confused-deputy policy; leave commits ready locally for human push."
                        .to_string(),
                    halt_session: false,
                });
            }
        }
        "branch" => {
            if sub_args
                .iter()
                .any(|x| x == "-D" || x == "--delete" || x == "-d")
            {
                return Err(CommandViolation {
                    code: "GIT_BRANCH_DELETE_BLOCKED",
                    detail: "Deleting git branches is forbidden.".to_string(),
                    halt_session: false,
                });
            }
        }
        "remote" => {
            if let Some(op) = sub_args.first().map(String::as_str) {
                if op != "-v" && op != "--verbose" {
                    return Err(CommandViolation {
                        code: "GIT_REMOTE_MUTATION_BLOCKED",
                        detail: format!(
                            "`git remote {op}` mutation is forbidden (prevents push-redirect exfiltration)."
                        ),
                        halt_session: true,
                    });
                }
            }
        }
        "submodule" | "worktree" | "clone" | "fetch" | "pull" => {
            if matches!(sub, "submodule" | "clone") {
                return Err(CommandViolation {
                    code: "GIT_SUBMODULE_OR_CLONE_BLOCKED",
                    detail: format!(
                        "`git {sub}` is blocked to prevent submodule/remote RCE and unbounded traversal."
                    ),
                    halt_session: false,
                });
            }
        }
        "log" => {
            // Require bounded `-n <N<=50>` or `--max-count=<N<=50>` or `-<N<=50>` to prevent context saturation!
            let mut bound: Option<usize> = None;
            let mut i = 0;
            while i < sub_args.len() {
                let s = sub_args[i].as_str();
                if s == "-n" {
                    bound = sub_args.get(i + 1).and_then(|v| v.parse().ok());
                    break;
                } else if let Some(num) = s.strip_prefix("-n") {
                    bound = num.parse().ok();
                    break;
                } else if let Some(num) = s.strip_prefix("--max-count=") {
                    bound = num.parse().ok();
                    break;
                } else if let Some(num) = s.strip_prefix('-') {
                    if !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()) {
                        bound = num.parse().ok();
                        break;
                    }
                }
                i += 1;
            }
            match bound {
                Some(n) if n > 0 && n <= 50 => {}
                _ => {
                    return Err(CommandViolation {
                        code: "UNBOUNDED_GIT_LOG",
                        detail: "`git log` must include `-n <N>` (with N <= 50) to prevent context window saturation."
                            .to_string(),
                        halt_session: false,
                    });
                }
            }
        }
        _ => {}
    }

    Ok(())
}

fn check_git_inline_config(kv: &str) -> Result<(), CommandViolation> {
    let lower = kv.to_ascii_lowercase();
    let key = lower.split('=').next().unwrap_or("").trim();

    // Allow explicitly confirming `core.hookspath=/dev/null` or `core.fsmonitor=false`, block everything else dangerous!
    if lower == "core.hookspath=/dev/null" || lower == "core.fsmonitor=false" {
        return Ok(());
    }

    if key.starts_with("core.")
        || key.starts_with("filter.")
        || key.starts_with("diff.")
        || key.starts_with("merge.")
        || key.starts_with("protocol.")
        || key.starts_with("alias.")
        || key.starts_with("credential.")
        || key.starts_with("http.")
        || key.starts_with("remote.")
        || key.starts_with("user.")
        || key.starts_with("gpg.")
        || key.starts_with("ssh.")
    {
        return Err(CommandViolation {
            code: "GIT_CONFIG_OVERRIDE_BLOCKED",
            detail: format!("Inline `git -c {kv}` security override is forbidden."),
            halt_session: true,
        });
    }
    Ok(())
}

fn check_node_pkg_manager(
    bin: &str,
    args: &[String],
    repo_root: &Path,
    cwd: &Path,
) -> Result<(), CommandViolation> {
    if matches!(bin, "npx" | "bunx") {
        return Err(CommandViolation {
            code: "UNVETTED_NPX_BLOCKED",
            detail: format!(
                "`{bin}` downloads and executes arbitrary packages; strictly forbidden."
            ),
            halt_session: true,
        });
    }

    let check_dir_traps = |dir: &Path| -> Result<(), CommandViolation> {
        for rel in [".yarnrc.yml", ".yarnrc.yaml", ".yarnrc"] {
            if let Some(keys) = read_bounded_nonsymlink_config_keys(dir, rel)? {
                for bad in ["yarnpath", "plugins"] {
                    if keys.iter().any(|k| k.contains(bad)) {
                        return Err(CommandViolation {
                            code: "YARN_CONFIG_EXEC_TRAP",
                            detail: format!(
                                "Directory '{rel}' defines `{bad}` binary/plugin hijack — refusing `{bin}` execution."
                            ),
                            halt_session: true,
                        });
                    }
                }
            }
        }
        if let Some(keys) = read_bounded_nonsymlink_config_keys(dir, ".npmrc")? {
            for bad in ["script-shell", "onload-script"] {
                if keys.iter().any(|k| k.contains(bad)) {
                    return Err(CommandViolation {
                        code: "NPMRC_SCRIPT_TRAP",
                        detail: format!(
                            "Directory '.npmrc' defines `{bad}` shell hijack — refusing `{bin}` execution."
                        ),
                        halt_session: true,
                    });
                }
            }
        }
        Ok(())
    };

    check_dir_traps(repo_root)?;
    if cwd != repo_root {
        check_dir_traps(cwd)?;
    }

    let mut sub = "";
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-g"
            || a == "--global"
            || a.starts_with("--script-shell")
            || a.starts_with("--onload-script")
            || a.starts_with("--userconfig")
            || a.starts_with("--globalconfig")
        {
            return Err(CommandViolation {
                code: "PKG_CONFIG_OR_GLOBAL_BLOCKED",
                detail: format!("`{bin} {a}` global/config override is forbidden."),
                halt_session: true,
            });
        }
        if matches!(a, "--prefix" | "-C" | "--cwd" | "--dir") {
            let Some(dir_arg) = args.get(i + 1) else {
                return Err(CommandViolation {
                    code: "MALFORMED_PKG_COMMAND",
                    detail: format!("`{bin} {a}` missing directory argument."),
                    halt_session: false,
                });
            };
            let valid =
                validate_path(repo_root, cwd, dir_arg, PathAccess::Write).map_err(|pv| {
                    CommandViolation {
                        code: pv.code,
                        detail: pv.detail,
                        halt_session: pv.is_poisoned_zone,
                    }
                })?;
            check_dir_traps(&valid.canonical_or_norm)?;
            i += 2;
            continue;
        }
        if let Some(dir_arg) = a
            .strip_prefix("--prefix=")
            .or_else(|| a.strip_prefix("--cwd="))
            .or_else(|| a.strip_prefix("--dir="))
        {
            let valid =
                validate_path(repo_root, cwd, dir_arg, PathAccess::Write).map_err(|pv| {
                    CommandViolation {
                        code: pv.code,
                        detail: pv.detail,
                        halt_session: pv.is_poisoned_zone,
                    }
                })?;
            check_dir_traps(&valid.canonical_or_norm)?;
            i += 1;
            continue;
        }
        if matches!(
            a,
            "-w" | "--workspace" | "--filter" | "--loglevel" | "--registry"
        ) {
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        if sub.is_empty() {
            sub = a;
        }
        i += 1;
    }

    if matches!(
        sub,
        "dlx"
            | "exec"
            | "x"
            | "create"
            | "init"
            | "publish"
            | "login"
            | "adduser"
            | "token"
            | "run"
            | "run-script"
            | "rum"
            | "urn"
            | "start"
            | "restart"
            | "stop"
            | "rebuild"
            | "rb"
            | "link"
            | "ln"
            | "pack"
    ) {
        return Err(CommandViolation {
            code: "PKG_EXEC_OR_PUBLISH_BLOCKED",
            detail: format!(
                "`{bin} {sub}` executes arbitrary package scripts or publishes externally and is hard-blocked."
            ),
            halt_session: false,
        });
    }
    let has_ignore_scripts = args.iter().any(|a| a == "--ignore-scripts");
    if matches!(
        sub,
        "" | "install" | "i" | "add" | "ci" | "update" | "up" | "remove" | "rm" | "uninstall"
    ) {
        if !has_ignore_scripts {
            return Err(CommandViolation {
                code: "LIFECYCLE_SCRIPTS_NOT_DISABLED",
                detail: format!(
                    "`{bin} {}` must pass `--ignore-scripts` to block malicious preinstall/postinstall RCE.",
                    if sub.is_empty() { "install" } else { sub }
                ),
                halt_session: false,
            });
        }
        return Ok(());
    }
    if matches!(sub, "test" | "t" | "tst") {
        if bin == "bun" && sub == "test" {
            return Ok(());
        }
        return Err(CommandViolation {
            code: "PKG_EXEC_OR_PUBLISH_BLOCKED",
            detail: format!(
                "`{bin} {sub}` executes arbitrary `package.json` test scripts and is blocked (invoke the test runner directly)."
            ),
            halt_session: false,
        });
    }
    if matches!(sub, "list" | "ls" | "why" | "outdated" | "audit") {
        return Ok(());
    }
    Err(CommandViolation {
        code: "PKG_EXEC_OR_PUBLISH_BLOCKED",
        detail: format!(
            "Unapproved `{bin}` subcommand '{sub}' blocked (prevents shorthand package.json script execution)."
        ),
        halt_session: false,
    })
}

fn check_python_pkg_manager(bin: &str, args: &[String]) -> Result<(), CommandViolation> {
    let joined = args.join(" ").to_ascii_lowercase();
    if joined.contains("git+http") || joined.contains("git+ssh") || joined.contains("http://") {
        return Err(CommandViolation {
            code: "UNVETTED_URL_PACKAGE_BLOCKED",
            detail: format!("Installing URL/VCS packages via `{bin}` is forbidden."),
            halt_session: true,
        });
    }
    if joined.contains("install")
        && !args
            .iter()
            .any(|a| a == "--no-cache-dir" || a == "--no-cache")
    {
        return Err(CommandViolation {
            code: "PACKAGE_CACHE_BLEED_BLOCKED",
            detail: format!(
                "`{bin} install` must include `--no-cache-dir` / `--no-cache` to prevent cache bleed."
            ),
            halt_session: false,
        });
    }
    Ok(())
}

fn check_cargo_command(
    args: &[String],
    repo_root: &Path,
    cwd: &Path,
) -> Result<(), CommandViolation> {
    // Inspect `.cargo/config.toml` and `.cargo/config` (no-symlink, bounded, key-only) for RCE traps!
    for rel in [".cargo/config.toml", ".cargo/config"] {
        if let Some(keys) = read_bounded_nonsymlink_config_keys(repo_root, rel)? {
            for bad in [
                "rustc-wrapper",
                "rustc_wrapper",
                "workspace-wrapper",
                "linker",
                "runner",
                "[alias]",
                "rustc",
            ] {
                if keys
                    .iter()
                    .any(|k| k == bad || (bad != "rustc" && k.contains(bad)))
                {
                    return Err(CommandViolation {
                        code: "CARGO_CONFIG_EXEC_TRAP",
                        detail: format!(
                            "Repository '{rel}' contains dangerous execution directive matching `{bad}` — refusing `cargo` invocation."
                        ),
                        halt_session: true,
                    });
                }
            }
        }
    }

    let mut sub = "";
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--config" || a.starts_with("--config=") || a == "-Z" || a.starts_with("-Z") {
            return Err(CommandViolation {
                code: "CARGO_CONFIG_OVERRIDE_BLOCKED",
                detail: format!(
                    "`cargo {a}` CLI configuration/unstable override is forbidden (prevents `rustc-wrapper`/`linker`/`runner` injection)."
                ),
                halt_session: true,
            });
        }
        if a == "--manifest-path" || a == "-C" {
            let Some(p) = args.get(i + 1) else {
                return Err(CommandViolation {
                    code: "MALFORMED_CARGO_COMMAND",
                    detail: format!("`cargo {a}` missing path argument."),
                    halt_session: false,
                });
            };
            validate_path(repo_root, cwd, p, PathAccess::Read).map_err(|pv| CommandViolation {
                code: pv.code,
                detail: pv.detail,
                halt_session: pv.is_poisoned_zone,
            })?;
            i += 2;
            continue;
        }
        if let Some(p) = a.strip_prefix("--manifest-path=") {
            validate_path(repo_root, cwd, p, PathAccess::Read).map_err(|pv| CommandViolation {
                code: pv.code,
                detail: pv.detail,
                halt_session: pv.is_poisoned_zone,
            })?;
            i += 1;
            continue;
        }
        if a == "--target-dir" {
            let Some(p) = args.get(i + 1) else {
                return Err(CommandViolation {
                    code: "MALFORMED_CARGO_COMMAND",
                    detail: "`cargo --target-dir` missing path argument.".to_string(),
                    halt_session: false,
                });
            };
            validate_path(repo_root, cwd, p, PathAccess::Write).map_err(|pv| CommandViolation {
                code: pv.code,
                detail: pv.detail,
                halt_session: pv.is_poisoned_zone,
            })?;
            i += 2;
            continue;
        }
        if let Some(p) = a.strip_prefix("--target-dir=") {
            validate_path(repo_root, cwd, p, PathAccess::Write).map_err(|pv| CommandViolation {
                code: pv.code,
                detail: pv.detail,
                halt_session: pv.is_poisoned_zone,
            })?;
            i += 1;
            continue;
        }
        if a == "--color" {
            i += 2;
            continue;
        }
        if a.starts_with('+') || a.starts_with('-') {
            i += 1;
            continue;
        }
        if sub.is_empty() {
            sub = a;
        }
        i += 1;
    }

    if matches!(
        sub,
        "publish" | "login" | "owner" | "yank" | "install" | "uninstall"
    ) {
        return Err(CommandViolation {
            code: "CARGO_MUTATION_BLOCKED",
            detail: format!("`cargo {sub}` is forbidden by zero-trust agent policy."),
            halt_session: false,
        });
    }
    Ok(())
}

/// Reads a config file inside `base_dir` up to 16 KiB without following symlinks on any path
/// component, returning ONLY normalized lowercase section headers and key names (stripping all
/// RHS values so credentials/tokens inside `.npmrc`/`.yarnrc*` are never retained in memory).
fn read_bounded_nonsymlink_config_keys(
    base_dir: &Path,
    rel: &str,
) -> Result<Option<Vec<String>>, CommandViolation> {
    let raw_opt = read_bounded_nonsymlink_raw(base_dir, rel, 16_384)?;
    let Some(raw) = raw_opt else {
        return Ok(None);
    };
    let mut keys = Vec::new();
    for line in raw.lines() {
        let trimmed = line
            .split('#')
            .next()
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            keys.push(trimmed.to_ascii_lowercase());
            continue;
        }
        if let Some((lhs, _rhs)) = trimmed.split_once('=').or_else(|| trimmed.split_once(':')) {
            let k = lhs
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_ascii_lowercase();
            if !k.is_empty() {
                keys.push(k);
            }
        }
    }
    Ok(Some(keys))
}

fn read_bounded_nonsymlink_raw(
    base_dir: &Path,
    rel: &str,
    max_bytes: u64,
) -> Result<Option<String>, CommandViolation> {
    use std::io::Read;
    let mut cur = base_dir.to_path_buf();
    let parts: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
    for (idx, seg) in parts.iter().enumerate() {
        cur.push(seg);
        let is_last = idx + 1 == parts.len();
        match std::fs::symlink_metadata(&cur) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(CommandViolation {
                    code: "CONFIG_STAT_ERROR",
                    detail: format!("Cannot stat '{rel}': {e}"),
                    halt_session: true,
                });
            }
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(CommandViolation {
                        code: "SYMLINKED_BUILD_CONFIG_BLOCKED",
                        detail: format!(
                            "Configuration path '{rel}' contains a symlink component and is blocked."
                        ),
                        halt_session: true,
                    });
                }
                if is_last {
                    if !meta.file_type().is_file() {
                        return Ok(None);
                    }
                    if meta.len() > max_bytes {
                        return Err(CommandViolation {
                            code: "OVERSIZED_BUILD_CONFIG_BLOCKED",
                            detail: format!(
                                "Configuration file '{rel}' exceeds {max_bytes}-byte inspection ceiling."
                            ),
                            halt_session: true,
                        });
                    }
                }
            }
        }
    }

    let file = std::fs::File::open(&cur).map_err(|e| CommandViolation {
        code: "CONFIG_OPEN_ERROR",
        detail: format!("Cannot open '{rel}': {e}"),
        halt_session: true,
    })?;
    let mut buf = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut buf)
        .map_err(|e| CommandViolation {
            code: "CONFIG_READ_ERROR",
            detail: format!("Cannot read '{rel}': {e}"),
            halt_session: true,
        })?;
    if buf.len() as u64 > max_bytes {
        return Err(CommandViolation {
            code: "OVERSIZED_BUILD_CONFIG_BLOCKED",
            detail: format!("Configuration file '{rel}' exceeds {max_bytes} bytes."),
            halt_session: true,
        });
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| CommandViolation {
            code: "INVALID_BUILD_CONFIG_UTF8",
            detail: format!("Configuration file '{rel}' contains non-UTF-8 bytes."),
            halt_session: true,
        })
}

/// Fail-closed pre-tool and static-audit inspector for repo-local `.git/config` and `.git/hooks`.
pub fn inspect_repo_git_config_and_hooks(repo_root: &Path) -> Result<(), CommandViolation> {
    let git_dir = repo_root.join(".git");
    if let Ok(gmeta) = std::fs::symlink_metadata(&git_dir)
        && gmeta.file_type().is_symlink()
    {
        return Err(CommandViolation {
            code: "SYMLINKED_GIT_DIR_BLOCKED",
            detail: "Repository '.git' is a symlink, which is forbidden.".to_string(),
            halt_session: true,
        });
    }

    if let Some(cfg_text) = read_bounded_nonsymlink_raw(repo_root, ".git/config", 65_536)? {
        let mut section = String::new();
        for raw_line in cfg_text.lines() {
            let line = raw_line
                .split('#')
                .next()
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = line.to_ascii_lowercase();
                if section.starts_with("[filter ") && !section.contains("\"lfs\"") {
                    return Err(CommandViolation {
                        code: "REPO_GIT_CONFIG_TRAP",
                        detail: format!(
                            "Repository '.git/config' defines custom filter driver {section}."
                        ),
                        halt_session: true,
                    });
                }
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if let Some((raw_k, raw_v)) = lower.split_once('=') {
                let k = raw_k.trim();
                let v = raw_v.trim().trim_matches('"');
                let is_bad = match k {
                    "hookspath" => v != "/dev/null",
                    "attributesfile" => v != "/dev/null",
                    "fsmonitor" => v != "false" && !v.is_empty(),
                    "symlinks" => v == "true",
                    "sshcommand" | "gitproxy" | "askpass" | "editor" | "external" | "textconv"
                    | "uploadpack" | "receivepack" => !v.is_empty(),
                    "pager" => !v.is_empty() && v != "cat",
                    "smudge" | "clean" | "process" if section.starts_with("[filter ") => {
                        !v.is_empty()
                    }
                    _ if section == "[alias]" && v.starts_with('!') => true,
                    _ => false,
                };
                if is_bad {
                    return Err(CommandViolation {
                        code: "REPO_GIT_CONFIG_TRAP",
                        detail: format!(
                            "Repository '.git/config' overrides hardened setting `{k}` in {section}."
                        ),
                        halt_session: true,
                    });
                }
            }
        }
    }

    let hooks_dir = git_dir.join("hooks");
    if let Ok(hmeta) = std::fs::symlink_metadata(&hooks_dir)
        && hmeta.file_type().is_symlink()
    {
        return Err(CommandViolation {
            code: "SYMLINKED_GIT_HOOKS_BLOCKED",
            detail: "Repository '.git/hooks' is a symlink.".to_string(),
            halt_session: true,
        });
    }
    Ok(())
}

/// Static audit helper checking repository build-tool and `.gitattributes` execution traps.
pub fn inspect_repo_build_config_traps(repo_root: &Path) -> Vec<String> {
    let mut findings = Vec::new();
    for rel in [".cargo/config.toml", ".cargo/config"] {
        match read_bounded_nonsymlink_config_keys(repo_root, rel) {
            Err(cv) => findings.push(format!("{}: {}", cv.code, cv.detail)),
            Ok(Some(keys)) => {
                for bad in [
                    "rustc-wrapper",
                    "rustc_wrapper",
                    "workspace-wrapper",
                    "linker",
                    "runner",
                    "[alias]",
                    "rustc",
                ] {
                    if keys
                        .iter()
                        .any(|k| k == bad || (bad != "rustc" && k.contains(bad)))
                    {
                        findings.push(format!("CARGO_CONFIG_EXEC_TRAP: '{rel}' contains `{bad}`"));
                    }
                }
            }
            Ok(None) => {}
        }
    }
    for rel in [".yarnrc.yml", ".yarnrc.yaml", ".yarnrc"] {
        match read_bounded_nonsymlink_config_keys(repo_root, rel) {
            Err(cv) => findings.push(format!("{}: {}", cv.code, cv.detail)),
            Ok(Some(keys)) => {
                for bad in ["yarnpath", "plugins"] {
                    if keys.iter().any(|k| k.contains(bad)) {
                        findings.push(format!("YARN_CONFIG_EXEC_TRAP: '{rel}' contains `{bad}`"));
                    }
                }
            }
            Ok(None) => {}
        }
    }
    if let Err(cv) = read_bounded_nonsymlink_config_keys(repo_root, ".npmrc").and_then(|opt| {
        if let Some(keys) = opt {
            for bad in ["script-shell", "onload-script"] {
                if keys.iter().any(|k| k.contains(bad)) {
                    return Err(CommandViolation {
                        code: "NPMRC_SCRIPT_TRAP",
                        detail: format!("'.npmrc' contains `{bad}`"),
                        halt_session: true,
                    });
                }
            }
        }
        Ok(())
    }) {
        findings.push(format!("{}: {}", cv.code, cv.detail));
    }
    match read_bounded_nonsymlink_raw(repo_root, ".gitattributes", 16_384) {
        Err(cv) => findings.push(format!("{}: {}", cv.code, cv.detail)),
        Ok(Some(raw)) => {
            let lower = raw.to_ascii_lowercase();
            for bad in ["filter=", "diff=", "merge=", "textconv"] {
                if lower.contains(bad) {
                    findings.push(format!(
                        "GITATTRIBUTES_DRIVER_TRAP: '.gitattributes' contains `{bad}`"
                    ));
                }
            }
        }
        Ok(None) => {}
    }
    findings
}

fn check_interpreter_command(
    bin: &str,
    args: &[String],
    has_code_stdin: bool,
    repo_root: &Path,
    cwd: &Path,
    plan: &mut CommandPlan,
) -> Result<(), CommandViolation> {
    let inspect_inline_code = |flag_desc: &str, code: &str| -> Result<(), CommandViolation> {
        let lower = code.to_ascii_lowercase();
        const FORBIDDEN_SNIPPETS: &[&str] = &[
            "/tmp",
            "/var/tmp",
            "/dev/shm",
            ".cache",
            "__pycache__",
            "node_modules",
            "site-packages",
            ".venv",
            "vendor/",
            ".env",
            ".ssh",
            ".git",
            "agent-guard",
            "audit.jsonl",
            "plan.lock",
            "work_ledger",
            "os.environ",
            "process.env",
            "subprocess",
            "child_process",
            "os.system",
            "os.popen",
            "pty.spawn",
            "socket",
            "urllib",
            "http.client",
            "fetch(",
            "base64",
            "os.walk",
            "rglob(",
            "agents.md",
            "claude.md",
            "open(",
            "io.",
            "pathlib",
            "path(",
            "shutil",
            "glob.",
            "import os",
            "from os",
            "os.",
            "fs.",
            "require('fs",
            "require(\"fs",
            "node:fs",
            "readfile",
            "writefile",
            "appendfile",
            "unlink",
            "rename(",
            "chmod",
            "symlink",
            "mkdir",
            "rmdir",
            "file.",
            "file_get_contents",
            "file_put_contents",
            "fopen",
            "__import__",
            "importlib",
            "builtins",
            "getattr(",
            "eval(",
            "exec(",
            "compile(",
        ];
        for needle in FORBIDDEN_SNIPPETS {
            if lower.contains(needle) {
                return Err(CommandViolation {
                    code: "INTERPRETER_BYPASS_BLOCKED",
                    detail: format!(
                        "Inline `{bin} {flag_desc}` script references forbidden file/OS/exec API or path '{needle}'."
                    ),
                    halt_session: true,
                });
            }
        }
        // Also extract any quoted path-like string literals and validate against PathAccess::Write!
        for lit in extract_quoted_literals(code) {
            if lit.contains('/') || lit.contains("..") || lit.starts_with('.') {
                validate_path(repo_root, cwd, &lit, PathAccess::Write).map_err(|pv| {
                    CommandViolation {
                        code: pv.code,
                        detail: format!(
                            "Inline `{bin} {flag_desc}` path literal '{lit}' denied: {}",
                            pv.detail
                        ),
                        halt_session: pv.is_poisoned_zone,
                    }
                })?;
            }
        }
        Ok(())
    };

    for (i, a) in args.iter().enumerate() {
        let s = a.as_str();
        // Exact flag (`-c <code>`, `-e <code>`, `--eval <code>`, `-p <code>`, `--print <code>`, `-r <code>`)
        let is_exact_inline = matches!(
            (bin, s),
            ("python" | "python3", "-c")
                | ("node", "-e" | "--eval" | "-p" | "--print")
                | ("perl" | "ruby" | "lua", "-e")
                | ("php", "-r")
        );
        if is_exact_inline {
            let code = args.get(i + 1).map(String::as_str).unwrap_or("");
            return inspect_inline_code(s, code);
        }

        // Attached inline code (`python3 -c"..."`, `node -e"..."`, `node --eval="..."`, `php -r"..."`)
        let attached_code = match bin {
            "python" | "python3" => s.strip_prefix("-c").filter(|rest| !rest.is_empty()),
            "node" => s
                .strip_prefix("--eval=")
                .or_else(|| s.strip_prefix("--print="))
                .or_else(|| s.strip_prefix("-e").filter(|rest| !rest.is_empty()))
                .or_else(|| s.strip_prefix("-p").filter(|rest| !rest.is_empty())),
            "perl" | "ruby" | "lua" => s.strip_prefix("-e").filter(|rest| !rest.is_empty()),
            "php" => s.strip_prefix("-r").filter(|rest| !rest.is_empty()),
            _ => None,
        };
        if let Some(code) = attached_code {
            return inspect_inline_code(&s[..2.min(s.len())], code);
        }

        // Python `-m <module>` / `-m<module>`
        if matches!(bin, "python" | "python3") {
            let module_opt = if s == "-m" {
                args.get(i + 1).map(|m| (m.as_str(), i + 2))
            } else {
                s.strip_prefix("-m")
                    .filter(|rest| !rest.is_empty())
                    .map(|m| (m, i + 1))
            };
            if let Some((mod_name, rest_idx)) = module_opt {
                if mod_name == "pip" {
                    return check_python_pkg_manager("pip", &args[rest_idx..]);
                }
                if matches!(
                    mod_name,
                    "http.server" | "code" | "pdb" | "webbrowser" | "smtpd"
                ) {
                    return Err(CommandViolation {
                        code: "INTERPRETER_MODULE_BLOCKED",
                        detail: format!("`{bin} -m {mod_name}` is forbidden."),
                        halt_session: true,
                    });
                }
                if mod_name == "venv" {
                    for p in &args[rest_idx..] {
                        if !p.starts_with('-') {
                            reject_shell_glob_in_operand(bin, p)?;
                            validate_path(repo_root, cwd, p, PathAccess::Write).map_err(|pv| {
                                CommandViolation {
                                    code: pv.code,
                                    detail: pv.detail,
                                    halt_session: pv.is_poisoned_zone,
                                }
                            })?;
                        }
                    }
                }
                return Ok(());
            }
        }
    }

    // Script file execution: validate script path (or block `-` / stdin script execution!)
    let mut found_script_file = false;
    for a in args {
        if a == "-" {
            return Err(CommandViolation {
                code: "STDIN_SCRIPT_EXECUTION_BLOCKED",
                detail: format!(
                    "Executing uninspected script code from stdin via `{bin} -` is forbidden."
                ),
                halt_session: true,
            });
        }
        if !a.starts_with('-') {
            reject_shell_glob_in_operand(bin, a)?;
            let valid = validate_path(repo_root, cwd, a, PathAccess::Read).map_err(|pv| {
                CommandViolation {
                    code: pv.code,
                    detail: format!("`{bin}` target '{a}' denied: {}", pv.detail),
                    halt_session: pv.is_poisoned_zone,
                }
            })?;
            plan.read_files.push((
                valid.repo_rel,
                valid.canonical_or_norm,
                valid.is_root_authority,
            ));
            found_script_file = true;
            break;
        }
    }

    if !found_script_file && has_code_stdin {
        return Err(CommandViolation {
            code: "STDIN_SCRIPT_EXECUTION_BLOCKED",
            detail: format!(
                "Piping or redirecting executable script code into `{bin}` stdin is forbidden."
            ),
            halt_session: true,
        });
    }
    Ok(())
}

fn check_search_or_walk_command(
    bin: &str,
    args: &[String],
    repo_root: &Path,
    cwd: &Path,
    plan: &mut CommandPlan,
) -> Result<(), CommandViolation> {
    match bin {
        "ls" => {
            for a in args {
                if a == "--recursive"
                    || (a.starts_with('-') && !a.starts_with("--") && a.contains('R'))
                {
                    return Err(CommandViolation {
                        code: "UNBOUNDED_LS_RECURSIVE",
                        detail: "`ls -R` recursive directory snooping is forbidden (max depth is 2 levels)."
                            .to_string(),
                        halt_session: false,
                    });
                }
            }
            for a in args.iter().filter(|a| !a.starts_with('-')) {
                reject_shell_glob_in_operand(bin, a)?;
                validate_path(
                    repo_root,
                    cwd,
                    a,
                    PathAccess::ListSearch {
                        requested_depth: Some(1),
                    },
                )
                .map_err(|pv| CommandViolation {
                    code: pv.code,
                    detail: pv.detail,
                    halt_session: pv.is_poisoned_zone,
                })?;
            }
        }
        "grep" | "egrep" | "fgrep" => {
            for a in args {
                if a == "--recursive"
                    || a == "--dereference-recursive"
                    || (a.starts_with('-')
                        && !a.starts_with("--")
                        && (a.contains('r') || a.contains('R')))
                {
                    return Err(CommandViolation {
                        code: "UNBOUNDED_GREP_RECURSIVE",
                        detail: "Recursive `grep -r/-R` is forbidden (ignores `.ignore` and exceeds 2-level traversal depth). Use `rg --max-depth 2`."
                            .to_string(),
                        halt_session: false,
                    });
                }
            }
            // Non-flag operands after pattern are files
            let mut skipped_pattern = false;
            for a in args {
                if a.starts_with('-') {
                    continue;
                }
                if !skipped_pattern {
                    skipped_pattern = true;
                    continue;
                }
                reject_shell_glob_in_operand(bin, a)?;
                let valid = validate_path(repo_root, cwd, a, PathAccess::Read).map_err(|pv| {
                    CommandViolation {
                        code: pv.code,
                        detail: pv.detail,
                        halt_session: pv.is_poisoned_zone,
                    }
                })?;
                plan.read_files.push((
                    valid.repo_rel,
                    valid.canonical_or_norm,
                    valid.is_root_authority,
                ));
            }
        }
        "find" => {
            let mut max_depth: Option<usize> = None;
            let mut paths = Vec::new();
            let mut i = 0;
            while i < args.len() {
                let a = args[i].as_str();
                if matches!(
                    a,
                    "-exec" | "-execdir" | "-ok" | "-okdir" | "-delete" | "-fls" | "-fprint"
                ) {
                    return Err(CommandViolation {
                        code: "FIND_EXEC_OR_DELETE_BLOCKED",
                        detail: format!("`find {a}` is forbidden."),
                        halt_session: false,
                    });
                }
                if a == "-L" || a == "-follow" {
                    return Err(CommandViolation {
                        code: "FIND_SYMLINK_FOLLOW_BLOCKED",
                        detail: "`find -L` symlink following is forbidden.".to_string(),
                        halt_session: false,
                    });
                }
                if a == "-maxdepth" {
                    max_depth = args.get(i + 1).and_then(|v| v.parse().ok());
                    i += 2;
                    continue;
                }
                if !a.starts_with('-')
                    && a != "!"
                    && a != "("
                    && a != ")"
                    && max_depth.is_none()
                    && paths.is_empty()
                {
                    paths.push(a);
                }
                i += 1;
            }
            if paths.is_empty() {
                paths.push(".");
            }
            for p in paths {
                reject_shell_glob_in_operand(bin, p)?;
                validate_path(
                    repo_root,
                    cwd,
                    p,
                    PathAccess::ListSearch {
                        requested_depth: max_depth,
                    },
                )
                .map_err(|pv| CommandViolation {
                    code: pv.code,
                    detail: pv.detail,
                    halt_session: pv.is_poisoned_zone,
                })?;
            }
        }
        "rg" | "ripgrep" | "fd" | "fdfind" => {
            let mut max_depth: Option<usize> = None;
            let mut explicit_pattern_or_no_pattern = false;
            let mut extra_search_paths: Vec<String> = Vec::new();
            let mut i = 0;
            while i < args.len() {
                let a = args[i].as_str();
                if a == "--" {
                    break;
                }
                if a == "--unrestricted"
                    || a.starts_with("--no-ignore")
                    || a == "--follow"
                    || a == "-L"
                    || a.starts_with("--pre")
                    || (bin.starts_with("fd")
                        && (a == "-x" || a == "-X" || a.starts_with("--exec")))
                    || (a.starts_with('-')
                        && !a.starts_with("--")
                        && a.chars().skip(1).any(|c| c == 'u'))
                {
                    return Err(CommandViolation {
                        code: "SEARCH_IGNORE_BYPASS_BLOCKED",
                        detail: format!(
                            "`{bin} {a}` is forbidden (cannot bypass `.ignore` protections on cache/tmp/node_modules or follow symlinks)."
                        ),
                        halt_session: true,
                    });
                }
                if a == "--max-depth" || a == "-d" {
                    max_depth = args.get(i + 1).and_then(|v| v.parse().ok());
                    i += 2;
                    continue;
                }
                if let Some(v) = a.strip_prefix("--max-depth=") {
                    max_depth = v.parse().ok();
                    i += 1;
                    continue;
                }
                if a == "-e" || a == "--regexp" {
                    explicit_pattern_or_no_pattern = true;
                    i += 2;
                    continue;
                }
                if a.starts_with("--regexp=")
                    || (a.starts_with("-e") && a.len() > 2)
                    || a == "--files"
                    || a == "--type-list"
                {
                    explicit_pattern_or_no_pattern = true;
                    i += 1;
                    continue;
                }
                if a == "-f" || a == "--file" || a == "--ignore-file" {
                    if a == "-f" || a == "--file" {
                        explicit_pattern_or_no_pattern = true;
                    }
                    if let Some(fp) = args.get(i + 1) {
                        reject_shell_glob_in_operand(bin, fp)?;
                        let valid =
                            validate_path(repo_root, cwd, fp, PathAccess::Read).map_err(|pv| {
                                CommandViolation {
                                    code: pv.code,
                                    detail: pv.detail,
                                    halt_session: pv.is_poisoned_zone,
                                }
                            })?;
                        plan.read_files.push((
                            valid.repo_rel,
                            valid.canonical_or_norm,
                            valid.is_root_authority,
                        ));
                    }
                    i += 2;
                    continue;
                }
                if let Some(fp) = a
                    .strip_prefix("--file=")
                    .or_else(|| a.strip_prefix("--ignore-file="))
                    .or_else(|| {
                        if a.starts_with("-f") && a.len() > 2 {
                            Some(&a[2..])
                        } else {
                            None
                        }
                    })
                {
                    if !a.starts_with("--ignore-file=") {
                        explicit_pattern_or_no_pattern = true;
                    }
                    reject_shell_glob_in_operand(bin, fp)?;
                    let valid =
                        validate_path(repo_root, cwd, fp, PathAccess::Read).map_err(|pv| {
                            CommandViolation {
                                code: pv.code,
                                detail: pv.detail,
                                halt_session: pv.is_poisoned_zone,
                            }
                        })?;
                    plan.read_files.push((
                        valid.repo_rel,
                        valid.canonical_or_norm,
                        valid.is_root_authority,
                    ));
                    i += 1;
                    continue;
                }
                if a == "--search-path" {
                    if let Some(sp) = args.get(i + 1) {
                        extra_search_paths.push(sp.clone());
                    }
                    i += 2;
                    continue;
                }
                if let Some(sp) = a.strip_prefix("--search-path=") {
                    extra_search_paths.push(sp.to_string());
                    i += 1;
                    continue;
                }
                i += 1;
            }

            // Collect trailing path arguments (after pattern unless `-e`/`-f`/`--files` already supplied it)
            let non_flags: Vec<&String> = collect_non_flag_operands(bin, args);
            let mut target_paths: Vec<&str> = if explicit_pattern_or_no_pattern {
                non_flags.iter().map(|s| s.as_str()).collect()
            } else if non_flags.len() >= 2 {
                non_flags[1..].iter().map(|s| s.as_str()).collect()
            } else {
                Vec::new()
            };
            for sp in &extra_search_paths {
                target_paths.push(sp.as_str());
            }

            if target_paths.is_empty() {
                validate_path(
                    repo_root,
                    cwd,
                    ".",
                    PathAccess::ListSearch {
                        requested_depth: max_depth,
                    },
                )
                .map_err(|pv| CommandViolation {
                    code: pv.code,
                    detail: pv.detail,
                    halt_session: pv.is_poisoned_zone,
                })?;
            } else {
                for p in target_paths {
                    reject_shell_glob_in_operand(bin, p)?;
                    // Single explicit file target is allowed if `Read` passes; directory target requires `max_depth <= 2`
                    let candidate = if Path::new(p).is_absolute() {
                        std::path::PathBuf::from(p)
                    } else {
                        cwd.join(p)
                    };
                    if candidate.is_file() {
                        let valid =
                            validate_path(repo_root, cwd, p, PathAccess::Read).map_err(|pv| {
                                CommandViolation {
                                    code: pv.code,
                                    detail: pv.detail,
                                    halt_session: pv.is_poisoned_zone,
                                }
                            })?;
                        plan.read_files.push((
                            valid.repo_rel,
                            valid.canonical_or_norm,
                            valid.is_root_authority,
                        ));
                    } else {
                        validate_path(
                            repo_root,
                            cwd,
                            p,
                            PathAccess::ListSearch {
                                requested_depth: max_depth,
                            },
                        )
                        .map_err(|pv| CommandViolation {
                            code: pv.code,
                            detail: pv.detail,
                            halt_session: pv.is_poisoned_zone,
                        })?;
                    }
                }
            }
        }
        "tree" => {
            let mut max_depth: Option<usize> = None;
            let mut paths: Vec<&str> = Vec::new();
            let mut after_double_dash = false;
            let mut i = 0;
            while i < args.len() {
                let a = args[i].as_str();
                if !after_double_dash && a == "--" {
                    after_double_dash = true;
                    i += 1;
                    continue;
                }
                if !after_double_dash && a == "-L" {
                    max_depth = args.get(i + 1).and_then(|v| v.parse().ok());
                    i += 2;
                    continue;
                }
                if !after_double_dash && a.starts_with("-L") && a.len() > 2 {
                    max_depth = a[2..].parse().ok();
                    i += 1;
                    continue;
                }
                if !after_double_dash && a == "-o" {
                    if let Some(out_p) = args.get(i + 1) {
                        reject_shell_glob_in_operand(bin, out_p)?;
                        let valid = validate_path(repo_root, cwd, out_p, PathAccess::Write)
                            .map_err(|pv| CommandViolation {
                                code: pv.code,
                                detail: pv.detail,
                                halt_session: pv.is_poisoned_zone,
                            })?;
                        plan.write_files
                            .push((valid.repo_rel, valid.canonical_or_norm));
                    }
                    i += 2;
                    continue;
                }
                if !after_double_dash
                    && matches!(
                        a,
                        "-P" | "-I" | "-H" | "-T" | "--charset" | "--filelimit" | "--timefmt"
                    )
                {
                    i += 2;
                    continue;
                }
                if !after_double_dash && a.starts_with('-') {
                    if a == "-l" {
                        return Err(CommandViolation {
                            code: "SEARCH_IGNORE_BYPASS_BLOCKED",
                            detail: "`tree -l` symlink following is forbidden.".to_string(),
                            halt_session: true,
                        });
                    }
                    i += 1;
                    continue;
                }
                paths.push(a);
                i += 1;
            }
            if paths.is_empty() {
                paths.push(".");
            }
            for p in paths {
                reject_shell_glob_in_operand(bin, p)?;
                validate_path(
                    repo_root,
                    cwd,
                    p,
                    PathAccess::ListSearch {
                        requested_depth: max_depth,
                    },
                )
                .map_err(|pv| CommandViolation {
                    code: pv.code,
                    detail: pv.detail,
                    halt_session: pv.is_poisoned_zone,
                })?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_non_flag_operands<'a>(bin: &str, args: &'a [String]) -> Vec<&'a String> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut after_double_dash = false;
    while i < args.len() {
        let a = &args[i];
        if !after_double_dash && a == "--" {
            after_double_dash = true;
            i += 1;
            continue;
        }
        if !after_double_dash && a.starts_with('-') {
            let takes_val = matches!(
                a.as_str(),
                "-d" | "--max-depth"
                    | "-g"
                    | "--glob"
                    | "-t"
                    | "--type"
                    | "-T"
                    | "--type-not"
                    | "-A"
                    | "-B"
                    | "-C"
                    | "-m"
                    | "--max-count"
                    | "-e"
                    | "--regexp"
                    | "-f"
                    | "--file"
                    | "-E"
                    | "--exclude"
            );
            if takes_val {
                let _ = bin;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        out.push(a);
        i += 1;
    }
    out
}

fn check_file_utility_paths(
    bin: &str,
    args: &[String],
    repo_root: &Path,
    cwd: &Path,
    plan: &mut CommandPlan,
) -> Result<(), CommandViolation> {
    let is_reader = matches!(
        bin,
        "cat"
            | "head"
            | "tail"
            | "less"
            | "more"
            | "nl"
            | "wc"
            | "stat"
            | "file"
            | "sort"
            | "uniq"
            | "cut"
            | "jq"
            | "sha256sum"
            | "md5sum"
            | "diff"
            | "awk"
            | "sed"
    );
    let is_writer = matches!(bin, "rm" | "rmdir" | "mkdir" | "touch" | "truncate");
    let is_src_dst = matches!(bin, "cp" | "mv" | "ln");

    if bin == "awk" {
        if let Some(prog) = args.iter().find(|a| !a.starts_with('-')) {
            if prog.contains("system(") || prog.contains("| getline") {
                return Err(CommandViolation {
                    code: "AWK_SYSTEM_EXEC_BLOCKED",
                    detail: "`awk` `system(...)` command execution is forbidden.".to_string(),
                    halt_session: true,
                });
            }
        }
    }

    let sed_in_place = bin == "sed"
        && args
            .iter()
            .any(|a| a == "-i" || a.starts_with("-i") || a.starts_with("--in-place"));

    if is_reader {
        let mut skip_first_expr =
            matches!(bin, "jq" | "awk" | "sed") && !args.iter().any(|a| a == "-e" || a == "-f");
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if a.starts_with('-') {
                if matches!(
                    a.as_str(),
                    "-n" | "-c" | "-e" | "-f" | "-d" | "-F" | "--arg"
                ) {
                    if a == "-f" {
                        if let Some(script_f) = args.get(i + 1) {
                            reject_shell_glob_in_operand(bin, script_f)?;
                            let valid = validate_path(repo_root, cwd, script_f, PathAccess::Read)
                                .map_err(|pv| CommandViolation {
                                code: pv.code,
                                detail: pv.detail,
                                halt_session: pv.is_poisoned_zone,
                            })?;
                            plan.read_files.push((
                                valid.repo_rel,
                                valid.canonical_or_norm,
                                valid.is_root_authority,
                            ));
                        }
                    }
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if skip_first_expr {
                skip_first_expr = false;
                i += 1;
                continue;
            }
            reject_shell_glob_in_operand(bin, a)?;
            let access = if sed_in_place {
                PathAccess::Write
            } else {
                PathAccess::Read
            };
            let valid =
                validate_path(repo_root, cwd, a, access).map_err(|pv| CommandViolation {
                    code: pv.code,
                    detail: format!("`{bin}` operand '{a}' denied: {}", pv.detail),
                    halt_session: pv.is_poisoned_zone,
                })?;
            if sed_in_place {
                plan.write_files
                    .push((valid.repo_rel.clone(), valid.canonical_or_norm.clone()));
            }
            plan.read_files.push((
                valid.repo_rel,
                valid.canonical_or_norm,
                valid.is_root_authority,
            ));
            i += 1;
        }
        return Ok(());
    }

    if is_writer {
        for a in args.iter().filter(|a| !a.starts_with('-')) {
            reject_shell_glob_in_operand(bin, a)?;
            let valid = validate_path(repo_root, cwd, a, PathAccess::Write).map_err(|pv| {
                CommandViolation {
                    code: pv.code,
                    detail: format!("`{bin}` target '{a}' denied: {}", pv.detail),
                    halt_session: pv.is_poisoned_zone,
                }
            })?;
            plan.write_files
                .push((valid.repo_rel, valid.canonical_or_norm));
        }
        return Ok(());
    }

    if is_src_dst {
        let operands: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
        if operands.len() >= 2 {
            for src in &operands[..operands.len() - 1] {
                reject_shell_glob_in_operand(bin, src)?;
                let valid = validate_path(repo_root, cwd, src, PathAccess::Read).map_err(|pv| {
                    CommandViolation {
                        code: pv.code,
                        detail: format!("`{bin}` source '{src}' denied: {}", pv.detail),
                        halt_session: pv.is_poisoned_zone,
                    }
                })?;
                plan.read_files.push((
                    valid.repo_rel,
                    valid.canonical_or_norm,
                    valid.is_root_authority,
                ));
            }
            let dst = operands[operands.len() - 1];
            reject_shell_glob_in_operand(bin, dst)?;
            let valid_dst =
                validate_path(repo_root, cwd, dst, PathAccess::Write).map_err(|pv| {
                    CommandViolation {
                        code: pv.code,
                        detail: format!("`{bin}` destination '{dst}' denied: {}", pv.detail),
                        halt_session: pv.is_poisoned_zone,
                    }
                })?;
            plan.write_files
                .push((valid_dst.repo_rel, valid_dst.canonical_or_norm));
        }
        return Ok(());
    }

    // Fallback check for any other command: inspect path-looking arguments for globs and forbidden zones!
    for a in args {
        if a.starts_with(".*") || a.starts_with(".?") || a.starts_with(".[") {
            reject_shell_glob_in_operand(bin, a)?;
        }
        if a.contains('/') || a.starts_with('~') || a == ".env" || a.starts_with(".env.") {
            let cleaned = a.split('=').next_back().unwrap_or(a.as_str());
            if cleaned == "/dev/null" {
                continue;
            }
            reject_shell_glob_in_operand(bin, cleaned)?;
            if let Err(pv) = check_forbidden_zones_lexical(cleaned, a) {
                return Err(CommandViolation {
                    code: pv.code,
                    detail: format!("Argument '{a}' touches forbidden zone: {}", pv.detail),
                    halt_session: pv.is_poisoned_zone,
                });
            }
        }
    }

    Ok(())
}

fn reject_shell_glob_in_operand(ctx: &str, operand: &str) -> Result<(), CommandViolation> {
    if operand.contains('*') || operand.contains('?') || operand.contains('[') {
        return Err(CommandViolation {
            code: "SHELL_GLOB_OPERAND_BLOCKED",
            detail: format!(
                "`{ctx}` file/path operand '{operand}' contains shell glob metacharacters (`*`, `?`, `[`), which expand unpredictably across protected files at runtime."
            ),
            halt_session: false,
        });
    }
    Ok(())
}

fn extract_quoted_literals(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = code.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let q = bytes[i];
        if q == b'\'' || q == b'"' {
            i += 1;
            let mut cur = String::new();
            while i < bytes.len() && bytes[i] != q {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    cur.push(bytes[i + 1] as char);
                    i += 2;
                    continue;
                }
                let tail = &code[i..];
                let ch = tail.chars().next().unwrap_or('\0');
                cur.push(ch);
                i += ch.len_utf8();
            }
            if !cur.is_empty() {
                out.push(cur);
            }
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    out
}

fn basename(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

fn strip_leading_flags(args: &[String]) -> &[String] {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--" {
            return &args[i + 1..];
        }
        if !args[i].starts_with('-') {
            break;
        }
        i += 1;
    }
    &args[i..]
}

// ============================================================================
// Recursive-Descent Shell Tokenizer & Command / Subshell Extractor
// ============================================================================

fn parse_shell_script(
    script: &str,
    subscripts: &mut Vec<String>,
) -> Result<Vec<ParsedCommand>, CommandViolation> {
    let bytes = script.as_bytes();
    let mut i = 0usize;
    let mut commands = Vec::new();
    let mut cur_env = Vec::new();
    let mut cur_argv = Vec::new();
    let mut cur_redirs = Vec::new();
    let mut cur_piped_stdin = false;
    let mut pending_heredocs: Vec<(String, bool)> = Vec::new();

    let flush = |env: &mut Vec<(String, String)>,
                 argv: &mut Vec<String>,
                 redirs: &mut Vec<(RedirKind, String)>,
                 piped: &mut bool,
                 out: &mut Vec<ParsedCommand>| {
        if !env.is_empty() || !argv.is_empty() || !redirs.is_empty() {
            out.push(ParsedCommand {
                env_vars: std::mem::take(env),
                argv: std::mem::take(argv),
                redirs: std::mem::take(redirs),
                piped_stdin: *piped,
            });
            *piped = false;
        }
    };

    while i < bytes.len() {
        let b = bytes[i];
        // Skip horizontal whitespace
        if b == b' ' || b == b'\t' || b == b'\r' {
            i += 1;
            continue;
        }
        // Comments `# ...` until newline
        if b == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Command separators `;`, `\n`, `|`, `|&`, `&&`, `||`, `&`
        if matches!(b, b';' | b'\n' | b'|' | b'&') {
            let is_pipe = b == b'|' && bytes.get(i + 1) != Some(&b'|');
            flush(
                &mut cur_env,
                &mut cur_argv,
                &mut cur_redirs,
                &mut cur_piped_stdin,
                &mut commands,
            );
            cur_piped_stdin = is_pipe;
            if ((b == b'|' || b == b'&') && bytes.get(i + 1) == Some(&b))
                || (b == b'|' && bytes.get(i + 1) == Some(&b'&'))
            {
                i += 2;
            } else {
                i += 1;
            }
            if b == b'\n' && !pending_heredocs.is_empty() {
                for (delim, strip_tabs) in pending_heredocs.drain(..) {
                    while i < bytes.len() {
                        let line_start = i;
                        while i < bytes.len() && bytes[i] != b'\n' {
                            i += 1;
                        }
                        let raw_line = &script[line_start..i];
                        let clean_line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
                        let cmp_line = if strip_tabs {
                            clean_line.trim_start_matches('\t')
                        } else {
                            clean_line
                        };
                        if i < bytes.len() && bytes[i] == b'\n' {
                            i += 1;
                        }
                        if cmp_line == delim {
                            break;
                        }
                    }
                }
            }
            continue;
        }
        // Subshell `(...)`
        if b == b'(' {
            flush(
                &mut cur_env,
                &mut cur_argv,
                &mut cur_redirs,
                &mut cur_piped_stdin,
                &mut commands,
            );
            let (inner, next_i) = extract_balanced_parens(script, i)?;
            subscripts.push(inner);
            i = next_i;
            continue;
        }
        // Brace group `{ ...; }`
        if b == b'{' || b == b'}' {
            flush(
                &mut cur_env,
                &mut cur_argv,
                &mut cur_redirs,
                &mut cur_piped_stdin,
                &mut commands,
            );
            i += 1;
            continue;
        }
        // Process substitution `<(...)` or `>(...)`
        if (b == b'<' || b == b'>') && bytes.get(i + 1) == Some(&b'(') {
            let (inner, next_i) = extract_balanced_parens(script, i + 1)?;
            subscripts.push(inner);
            i = next_i;
            continue;
        }
        // Redirections `>>`, `>`, `<`, `<<`, `<<<`, `2>&1`, `1>/path`
        if b == b'<'
            || b == b'>'
            || (b.is_ascii_digit() && matches!(bytes.get(i + 1), Some(b'<' | b'>')))
        {
            if b.is_ascii_digit() {
                i += 1;
            }
            let rchar = bytes[i];
            let mut is_multiline_heredoc = false;
            let mut strip_heredoc_tabs = false;
            let kind = if rchar == b'<' {
                if bytes.get(i + 1) == Some(&b'<') {
                    if bytes.get(i + 2) == Some(&b'<') {
                        i += 3;
                    } else {
                        i += 2;
                        is_multiline_heredoc = true;
                        if bytes.get(i) == Some(&b'-') {
                            strip_heredoc_tabs = true;
                            i += 1;
                        }
                    }
                    RedirKind::Heredoc
                } else {
                    i += 1;
                    RedirKind::Read
                }
            } else {
                if bytes.get(i + 1) == Some(&b'>') || bytes.get(i + 1) == Some(&b'|') {
                    i += 2;
                } else {
                    i += 1;
                }
                RedirKind::Write
            };
            while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
                i += 1;
            }
            let (target_word, next_i) = read_shell_word(script, i, subscripts)?;
            if is_multiline_heredoc && !target_word.is_empty() {
                pending_heredocs.push((target_word.clone(), strip_heredoc_tabs));
            }
            cur_redirs.push((kind, target_word));
            i = next_i;
            continue;
        }

        // Normal word (resolving quotes & escapes, and extracting nested `$(...)` / `` `...` ``)
        let (word, next_i) = read_shell_word(script, i, subscripts)?;
        i = next_i;

        // Leading `KEY=VALUE` before command name
        if cur_argv.is_empty() {
            if let Some((k, v)) = split_valid_env_assignment(&word) {
                cur_env.push((k.to_string(), v.to_string()));
                continue;
            }
        }
        cur_argv.push(word);
    }

    flush(
        &mut cur_env,
        &mut cur_argv,
        &mut cur_redirs,
        &mut cur_piped_stdin,
        &mut commands,
    );
    Ok(commands)
}

fn split_valid_env_assignment(word: &str) -> Option<(&str, &str)> {
    let (k, v) = word.split_once('=')?;
    if k.is_empty() {
        return None;
    }
    let mut chars = k.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some((k, v))
}

fn read_shell_word(
    script: &str,
    start: usize,
    subscripts: &mut Vec<String>,
) -> Result<(String, usize), CommandViolation> {
    let bytes = script.as_bytes();
    let mut i = start;
    let mut out = String::new();

    while i < bytes.len() {
        let b = bytes[i];
        if matches!(
            b,
            b' ' | b'\t' | b'\r' | b'\n' | b';' | b'|' | b'&' | b'(' | b')' | b'<' | b'>'
        ) {
            break;
        }
        if b == b'\\' {
            if i + 1 >= bytes.len() {
                return Err(CommandViolation {
                    code: "UNTERMINATED_SHELL_ESCAPE",
                    detail: "Trailing backslash in shell command.".to_string(),
                    halt_session: false,
                });
            }
            let tail = &script[i + 1..];
            let ch = tail.chars().next().unwrap_or('\0');
            if ch != '\n' {
                out.push(ch);
            }
            i += 1 + ch.len_utf8();
            continue;
        }
        if b == b'\'' {
            i += 1;
            let start_sq = i;
            while i < bytes.len() && bytes[i] != b'\'' {
                i += 1;
            }
            if i >= bytes.len() {
                return Err(CommandViolation {
                    code: "UNTERMINATED_SINGLE_QUOTE",
                    detail: "Unterminated single quote in shell command.".to_string(),
                    halt_session: false,
                });
            }
            out.push_str(&script[start_sq..i]);
            i += 1;
            continue;
        }
        if b == b'"' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    let tail = &script[i + 1..];
                    let ch = tail.chars().next().unwrap_or('\0');
                    out.push(ch);
                    i += 1 + ch.len_utf8();
                } else if bytes[i] == b'$' && bytes.get(i + 1) == Some(&b'(') {
                    let (inner, next_i) = extract_balanced_parens(script, i + 1)?;
                    subscripts.push(inner);
                    out.push_str("$()");
                    i = next_i;
                } else if bytes[i] == b'`' {
                    let (inner, next_i) = extract_backticks(script, i)?;
                    subscripts.push(inner);
                    out.push_str("``");
                    i = next_i;
                } else {
                    let tail = &script[i..];
                    let ch = tail.chars().next().unwrap_or('\0');
                    out.push(ch);
                    i += ch.len_utf8();
                }
            }
            if i >= bytes.len() {
                return Err(CommandViolation {
                    code: "UNTERMINATED_DOUBLE_QUOTE",
                    detail: "Unterminated double quote in shell command.".to_string(),
                    halt_session: false,
                });
            }
            i += 1;
            continue;
        }
        if b == b'$' && bytes.get(i + 1) == Some(&b'(') {
            let (inner, next_i) = extract_balanced_parens(script, i + 1)?;
            subscripts.push(inner);
            out.push_str("$()");
            i = next_i;
            continue;
        }
        if b == b'`' {
            let (inner, next_i) = extract_backticks(script, i)?;
            subscripts.push(inner);
            out.push_str("``");
            i = next_i;
            continue;
        }

        let tail = &script[i..];
        let ch = tail.chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }

    Ok((out, i))
}

fn extract_balanced_parens(
    script: &str,
    open_idx: usize,
) -> Result<(String, usize), CommandViolation> {
    let bytes = script.as_bytes();
    let mut i = open_idx + 1;
    let mut depth = 1usize;
    let mut in_sq = false;
    let mut in_dq = false;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && !in_sq {
            i += 2;
            continue;
        }
        if b == b'\'' && !in_dq {
            in_sq = !in_sq;
        } else if b == b'"' && !in_sq {
            in_dq = !in_dq;
        } else if !in_sq && !in_dq {
            if b == b'(' {
                depth += 1;
            } else if b == b')' {
                depth -= 1;
                if depth == 0 {
                    return Ok((script[open_idx + 1..i].to_string(), i + 1));
                }
            }
        }
        i += 1;
    }

    Err(CommandViolation {
        code: "UNBALANCED_SUBSHELL",
        detail: "Unbalanced '(' in shell command.".to_string(),
        halt_session: false,
    })
}

fn extract_backticks(script: &str, open_idx: usize) -> Result<(String, usize), CommandViolation> {
    let bytes = script.as_bytes();
    let mut i = open_idx + 1;
    let mut inner = String::new();
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() && matches!(bytes[i + 1], b'`' | b'$' | b'\\') {
            inner.push(bytes[i + 1] as char);
            i += 2;
            continue;
        }
        if bytes[i] == b'`' {
            return Ok((inner, i + 1));
        }
        let tail = &script[i..];
        let ch = tail.chars().next().unwrap_or('\0');
        inner.push(ch);
        i += ch.len_utf8();
    }
    Err(CommandViolation {
        code: "UNTERMINATED_BACKTICK",
        detail: "Unterminated backtick command substitution.".to_string(),
        halt_session: false,
    })
}

#[cfg(test)]
mod tests {
    use super::evaluate_shell_command;

    #[test]
    fn defeats_quote_splitting_and_subshell_and_git_hook_bypasses() {
        let cwd = std::env::current_dir().expect("cwd");
        // Quote splitting `c'a't /t"m"p/secret`
        assert!(evaluate_shell_command("c'a't /t\"m\"p/secret", &cwd, &cwd, false).is_err());
        // Nested command substitution `echo $(cat .env)`
        assert!(evaluate_shell_command("echo $(cat .env)", &cwd, &cwd, false).is_err());
        // Unbounded `find .` without `-maxdepth <= 2`
        assert!(evaluate_shell_command("find . -name '*.rs'", &cwd, &cwd, false).is_err());
        // Bounded `find . -maxdepth 2` allowed!
        assert!(
            evaluate_shell_command("find . -maxdepth 2 -name '*.rs'", &cwd, &cwd, false).is_ok()
        );
        // `git -c core.hooksPath=.git/hooks status` blocked!
        assert!(
            evaluate_shell_command("git -c core.hooksPath=.git/hooks status", &cwd, &cwd, false)
                .is_err()
        );
        // `npm install` without `--ignore-scripts` blocked!
        assert!(evaluate_shell_command("npm install", &cwd, &cwd, false).is_err());
        assert!(evaluate_shell_command("npm install --ignore-scripts", &cwd, &cwd, false).is_ok());
    }
}
