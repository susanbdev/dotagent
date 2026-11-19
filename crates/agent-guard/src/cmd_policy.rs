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
    /// Repo-relative + canonical file paths searched by grep/rg (checked against existing >2 hop block without burning read budget!)
    pub search_files: Vec<(String, std::path::PathBuf)>,
    /// Repo-relative + canonical file paths mutated by this command
    pub write_files: Vec<(String, std::path::PathBuf)>,
    /// Optional safe command rewrite (e.g. injecting POSIX `-prune` exclusions on standalone `find`)
    pub rewritten_command: Option<String>,
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
    let (commands, has_compound_list_op) = parse_shell_script(script, &mut subscripts)?;

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

    // Compound `gh` lockdown: `gh` may ONLY run at top level (no subshells/command substitutions),
    // with zero compound list operators (`&&`, `||`, `;`, `&`, multi-line), either standalone or
    // as the first stage of a pipeline piped strictly to `jq`, `tr`, `head`, or `tail`.
    let has_gh = commands.iter().any(|c| command_invokes_bin(c, "gh"));
    if has_gh {
        if depth > 0 || !subscripts.is_empty() {
            return Err(CommandViolation {
                code: "GH_COMPOUND_CHAIN_BLOCKED",
                detail:
                    "Subshells and command substitutions inside or wrapping `gh` are forbidden; run a single atomic `gh` command."
                        .to_string(),
                halt_session: false,
            });
        }
        if has_compound_list_op || commands.iter().skip(1).any(|c| !c.piped_stdin) {
            return Err(CommandViolation {
                code: "GH_COMPOUND_CHAIN_BLOCKED",
                detail:
                    "Compound `gh` command chaining (`&&`, `||`, `;`, `&`, multi-line) is forbidden; run a single atomic `gh` command."
                        .to_string(),
                halt_session: false,
            });
        }
        let first_is_direct_gh = commands
            .first()
            .and_then(|c| c.argv.first())
            .is_some_and(|b| basename(b) == "gh")
            && commands[0].redirs.is_empty();
        if !first_is_direct_gh {
            return Err(CommandViolation {
                code: "GH_COMPOUND_CHAIN_BLOCKED",
                detail:
                    "`gh` must be invoked directly as the leading command without shell wrappers or redirections."
                        .to_string(),
                halt_session: false,
            });
        }
        for stage in &commands[1..] {
            let stage_bin = stage.argv.first().map(|b| basename(b)).unwrap_or("");
            if !stage.env_vars.is_empty()
                || !stage.redirs.is_empty()
                || !matches!(
                    stage_bin,
                    "jq" | "tr" | "head" | "tail" | "wc" | "sort" | "uniq" | "cut" | "grep" | "rg"
                )
            {
                return Err(CommandViolation {
                    code: "GH_COMPOUND_CHAIN_BLOCKED",
                    detail: format!(
                        "`gh` may only be piped strictly to pure stdin filters (`jq`, `tr`, `head`, `tail`, `wc`, `sort`, `uniq`, `cut`, `grep`, `rg`; got `{stage_bin}` or redirection)."
                    ),
                    halt_session: false,
                });
            }
        }
    }

    for (idx, cmd) in commands.iter().enumerate() {
        let reads_before = plan.read_files.len();
        let writes_before = plan.write_files.len();
        let searches_before = plan.search_files.len();
        check_single_command(cmd, repo_root, cwd, session_tainted, depth, plan)?;
        if has_gh
            && idx > 0
            && (plan.read_files.len() > reads_before
                || plan.write_files.len() > writes_before
                || plan.search_files.len() > searches_before)
        {
            return Err(CommandViolation {
                code: "GH_COMPOUND_CHAIN_BLOCKED",
                detail:
                    "Downstream filters in a `gh` pipeline may only filter stdin, not read/search/write files."
                        .to_string(),
                halt_session: false,
            });
        }
    }

    // If top-level script is a standalone `find` or `find ... | filter` pipeline, auto-inject
    // POSIX `-prune` exclusions on forbidden directories so `find . -maxdepth 2` never descends
    // into `node_modules/`, `target/`, `build/`, `.cache/`, or `tmp/`.
    if depth == 0 && !has_compound_list_op && subscripts.is_empty() {
        if let Some(rewritten) = maybe_rewrite_top_level_find(script, &commands) {
            plan.rewritten_command = Some(rewritten);
        }
    }

    Ok(())
}

fn command_invokes_bin(cmd: &ParsedCommand, target: &str) -> bool {
    let mut i = 0usize;
    while i < cmd.argv.len() {
        let tok = basename(&cmd.argv[i]);
        if tok == target {
            return true;
        }
        match tok {
            "command" | "builtin" | "exec" | "nohup" => {
                i += 1;
                while i < cmd.argv.len() && cmd.argv[i].starts_with('-') {
                    if cmd.argv[i] == "--" {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            "env" => {
                i += 1;
                while i < cmd.argv.len() {
                    let a = &cmd.argv[i];
                    if a == "-u" || a == "--unset" {
                        i += 2;
                    } else if a.starts_with('-') || a.contains('=') {
                        i += 1;
                    } else {
                        break;
                    }
                }
            }
            "timeout" | "nice" => {
                let is_timeout = tok == "timeout";
                i += 1;
                while i < cmd.argv.len() && cmd.argv[i].starts_with('-') {
                    let opt = cmd.argv[i].as_str();
                    if opt == "--" {
                        i += 1;
                        break;
                    }
                    if (is_timeout && matches!(opt, "-k" | "-s" | "--kill-after" | "--signal"))
                        || (!is_timeout && matches!(opt, "-n" | "--adjustment"))
                    {
                        i += 2;
                    } else if opt.starts_with("--")
                        && !matches!(opt, "--verbose" | "--foreground" | "--preserve-status")
                        && !opt.starts_with("--kill-after=")
                        && !opt.starts_with("--signal=")
                        && !opt.starts_with("--adjustment=")
                    {
                        return false;
                    } else {
                        i += 1;
                    }
                }
                if is_timeout && i < cmd.argv.len() {
                    i += 1;
                }
            }
            _ => return false,
        }
    }
    false
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
        "sh" | "bash" | "dash" | "zsh" | "ksh" | "eval" | "source" | "."
    ) || is_interpreter_binary(bin)
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
            let is_timeout = bin == "timeout";
            let mut idx = 0;
            while idx < args.len() && args[idx].starts_with('-') {
                let opt = args[idx].as_str();
                if opt == "--" {
                    idx += 1;
                    break;
                }
                if (is_timeout && matches!(opt, "-k" | "-s" | "--kill-after" | "--signal"))
                    || (!is_timeout && matches!(opt, "-n" | "--adjustment"))
                {
                    idx += 2;
                } else if opt.starts_with("--")
                    && !matches!(opt, "--verbose" | "--foreground" | "--preserve-status")
                    && !opt.starts_with("--kill-after=")
                    && !opt.starts_with("--signal=")
                    && !opt.starts_with("--adjustment=")
                {
                    return Err(CommandViolation {
                        code: "MALFORMED_SUBSHELL",
                        detail: format!("Unrecognized `{bin}` flag `{opt}`."),
                        halt_session: false,
                    });
                } else {
                    idx += 1;
                }
            }
            if is_timeout && idx < args.len() {
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
                    return Err(CommandViolation {
                        code: "DANGEROUS_ENV_OVERRIDE",
                        detail:
                            "`env -i` / `--ignore-environment` strips active security guard and proxy environment controls and is forbidden."
                                .to_string(),
                        halt_session: true,
                    });
                } else if a == "-u" || a == "--unset" {
                    let Some(var_name) = args.get(idx + 1) else {
                        return Err(CommandViolation {
                            code: "ENV_FLAG_BLOCKED",
                            detail: format!("`env {a}` missing variable name."),
                            halt_session: false,
                        });
                    };
                    check_env_assignment(var_name, "", repo_root, cwd)?;
                    idx += 2;
                } else if let Some(var_name) = a.strip_prefix("--unset=") {
                    check_env_assignment(var_name, "", repo_root, cwd)?;
                    idx += 1;
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
                let opt = args[idx].as_str();
                if opt == "--" {
                    idx += 1;
                    break;
                }
                if matches!(
                    opt,
                    "-I" | "-L"
                        | "-n"
                        | "-P"
                        | "-s"
                        | "-d"
                        | "-E"
                        | "-a"
                        | "--replace"
                        | "--max-lines"
                        | "--max-args"
                        | "--max-procs"
                        | "--max-chars"
                        | "--delimiter"
                        | "--eof"
                        | "--arg-file"
                ) {
                    if matches!(opt, "-a" | "--arg-file") {
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
                } else if let Some(f) = opt
                    .strip_prefix("--arg-file=")
                    .or_else(|| opt.strip_prefix("-a").filter(|rest| !rest.is_empty()))
                {
                    reject_shell_glob_in_operand("xargs --arg-file", f)?;
                    let valid =
                        validate_path(repo_root, cwd, f, PathAccess::Read).map_err(|pv| {
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
                    idx += 1;
                } else if matches!(
                    opt,
                    "-0" | "-r"
                        | "-t"
                        | "-x"
                        | "--null"
                        | "--no-run-if-empty"
                        | "--verbose"
                        | "--exit"
                ) || opt.starts_with("--replace=")
                    || opt.starts_with("--max-lines=")
                    || opt.starts_with("--max-args=")
                    || opt.starts_with("--max-procs=")
                    || opt.starts_with("--max-chars=")
                    || opt.starts_with("--delimiter=")
                    || opt.starts_with("--eof=")
                    || opt.starts_with("-I")
                    || opt.starts_with("-L")
                    || opt.starts_with("-n")
                    || opt.starts_with("-P")
                    || opt.starts_with("-s")
                    || opt.starts_with("-d")
                    || opt.starts_with("-E")
                {
                    idx += 1;
                } else {
                    return Err(CommandViolation {
                        code: "XARGS_DYNAMIC_ARGS_BLOCKED",
                        detail: format!(
                            "Unrecognized or unsafe `xargs` option `{opt}` is forbidden."
                        ),
                        halt_session: false,
                    });
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
    if matches!(bin, "export" | "declare" | "typeset" | "local" | "readonly") {
        let non_flags: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
        if (matches!(bin, "export" | "declare" | "typeset") && non_flags.is_empty())
            || args.iter().any(|a| a == "-p")
        {
            return Err(CommandViolation {
                code: "SECRET_ENV_DUMP_BLOCKED",
                detail: "Dumping exported shell environment variables is forbidden.".to_string(),
                halt_session: false,
            });
        }
        for entry in non_flags {
            let (k, v) = entry.split_once('=').unwrap_or((entry.as_str(), ""));
            check_env_assignment(k, v, repo_root, cwd)?;
        }
        return Ok(());
    }
    if bin == "unset" {
        for entry in args.iter().filter(|a| !a.starts_with('-')) {
            check_env_assignment(entry, "", repo_root, cwd)?;
        }
        return Ok(());
    }

    if bin == "swarm-tool"
        && args.iter().any(|a| {
            a == "--internal-exec-sandbox"
                || a.starts_with("--internal-exec-sandbox=")
                || a == "--probe-landlock-child"
        })
    {
        return Err(CommandViolation {
            code: "SELF_TAMPERING_BLOCKED",
            detail: "Agents may not invoke internal sandbox flags on `swarm-tool` directly."
                .to_string(),
            halt_session: true,
        });
    }

    // Prevent agent from invoking `agent-guard` / `dotagent` hooks, state resets, or unwrapped sandbox helpers
    if matches!(bin, "agent-guard" | "dotagent") {
        let sub_args: &[String] = if args.first().map(String::as_str) == Some("guard") {
            &args[1..]
        } else {
            args
        };
        if sub_args.iter().any(|a| a == "--probe-landlock-child") {
            return Err(CommandViolation {
                code: "SELF_TAMPERING_BLOCKED",
                detail: "Agents may not invoke internal Landlock probe flags directly.".to_string(),
                halt_session: true,
            });
        }
        if let Some(sub) = sub_args.first().map(String::as_str) {
            if matches!(
                sub,
                "user-prompt"
                    | "pre-tool"
                    | "post-tool"
                    | "post-edit"
                    | "on-stop"
                    | "reset"
                    | "reset-session"
                    | "session-reset"
                    | "pre-compact"
                    | "compact-reset"
                    | "coordinator"
                    | "activate"
                    | "deactivate"
            ) {
                return Err(CommandViolation {
                    code: "SELF_TAMPERING_BLOCKED",
                    detail:
                        "Agents may not reset agent-guard session/compaction state, spoof lifecycle hooks, mutate activation, or directly invoke the vault coordinator."
                            .to_string(),
                    halt_session: true,
                });
            }
            if sub == "swarm" {
                let mut forwarded = Vec::with_capacity(sub_args.len());
                forwarded.push("swarm-tool".to_string());
                forwarded.extend_from_slice(&sub_args[1..]);
                let inner = ParsedCommand {
                    env_vars: Vec::new(),
                    argv: forwarded,
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
            if matches!(sub, "read-safe" | "scan-file") {
                if let Some(target_file) = sub_args.get(1) {
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
            if matches!(sub, "sanitize-stream" | "sandbox-status") {
                return Ok(());
            }
            if sub == "exec-sandbox" {
                let mut idx = 1usize;
                let mut custom_cwd: Option<&str> = None;
                let mut after_sep = false;
                let mut inner_argv: Vec<String> = Vec::new();
                while idx < sub_args.len() {
                    if after_sep {
                        inner_argv.push(sub_args[idx].clone());
                        idx += 1;
                        continue;
                    }
                    match sub_args[idx].as_str() {
                        "--" => {
                            after_sep = true;
                            idx += 1;
                        }
                        "--sanitize-stream" | "--require-kernel" | "--deny-net" => {
                            idx += 1;
                        }
                        "--cwd" => {
                            let Some(dir) = sub_args.get(idx + 1) else {
                                return Err(CommandViolation {
                                    code: "MALFORMED_SUBSHELL",
                                    detail: "`agent-guard exec-sandbox --cwd` missing directory."
                                        .to_string(),
                                    halt_session: false,
                                });
                            };
                            validate_path(repo_root, cwd, dir, PathAccess::Read).map_err(|pv| {
                                CommandViolation {
                                    code: pv.code,
                                    detail: pv.detail,
                                    halt_session: pv.is_poisoned_zone,
                                }
                            })?;
                            custom_cwd = Some(dir.as_str());
                            idx += 2;
                        }
                        other if !other.starts_with('-') => {
                            inner_argv.push(other.to_string());
                            after_sep = true;
                            idx += 1;
                        }
                        other => {
                            return Err(CommandViolation {
                                code: "MALFORMED_SUBSHELL",
                                detail: format!(
                                    "Unrecognized `agent-guard exec-sandbox` flag `{other}`."
                                ),
                                halt_session: false,
                            });
                        }
                    }
                }
                if inner_argv.is_empty() {
                    return Err(CommandViolation {
                        code: "MALFORMED_SUBSHELL",
                        detail: "`agent-guard exec-sandbox` missing command.".to_string(),
                        halt_session: false,
                    });
                }
                let effective_cwd = custom_cwd
                    .map(|d| {
                        if Path::new(d).is_absolute() {
                            std::path::PathBuf::from(d)
                        } else {
                            cwd.join(d)
                        }
                    })
                    .unwrap_or_else(|| cwd.to_path_buf());
                if inner_argv.len() == 1 {
                    return analyze_recursive(
                        &inner_argv[0],
                        repo_root,
                        &effective_cwd,
                        session_tainted,
                        depth + 1,
                        plan,
                    );
                }
                let inner = ParsedCommand {
                    env_vars: Vec::new(),
                    argv: inner_argv,
                    redirs: cmd.redirs.clone(),
                    piped_stdin: cmd.piped_stdin,
                };
                return check_single_command(
                    &inner,
                    repo_root,
                    &effective_cwd,
                    session_tainted,
                    depth + 1,
                    plan,
                );
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

    // 8. Hard Interpreter & Runtime Lockdown (`python`, `python3`, `uvx`, `node`, `bun`, `deno`, `perl`, `ruby`, `php`, `lua`)
    if is_interpreter_binary(bin) {
        check_interpreter_command(bin, args, repo_root, cwd, session_tainted, plan)?;
        return Ok(());
    }
    if matches!(bin, "pytest" | "py.test") {
        check_pytest_command(bin, args, repo_root, cwd, plan)?;
        return Ok(());
    }

    // 9. Package Manager Lifecycle Script, Build-Config Trap, & Publish Lockdown
    if matches!(bin, "npm" | "pnpm" | "yarn" | "npx" | "bunx") {
        check_node_pkg_manager(bin, args, repo_root, cwd)?;
        return Ok(());
    }
    if matches!(bin, "pip" | "pip3" | "uv") {
        check_python_pkg_manager(bin, args, repo_root, cwd, session_tainted, plan)?;
        return Ok(());
    }
    if bin == "cargo" {
        check_cargo_command(args, repo_root, cwd)?;
        return Ok(());
    }

    // 10. Search & Directory Walk Depth Ceiling (`<= 2` levels)
    if matches!(
        bin,
        "find" | "rg" | "ripgrep" | "fd" | "fdfind" | "tree" | "ls" | "grep" | "egrep" | "fgrep"
    ) {
        check_search_or_walk_command(bin, args, repo_root, cwd, cmd.piped_stdin, plan)?;
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

    // Chained GitHub Actions workflow dispatch is unconditionally forbidden (even with deputy override)
    if sub1 == "workflow" && sub2 == "run" {
        return Err(CommandViolation {
            code: "GH_WORKFLOW_CHAIN_BLOCKED",
            detail: "`gh workflow run` chained workflow triggering is unconditionally forbidden."
                .to_string(),
            halt_session: true,
        });
    }

    if sub1 == "api" {
        let joined_lower = args.join(" ").to_ascii_lowercase();
        if joined_lower.contains("/dispatches")
            || joined_lower.contains("workflow_dispatch")
            || joined_lower.contains("repository_dispatch")
        {
            return Err(CommandViolation {
                code: "GH_WORKFLOW_CHAIN_BLOCKED",
                detail:
                    "Triggering GitHub workflow/repository dispatches via `gh api` is unconditionally forbidden."
                        .to_string(),
                halt_session: true,
            });
        }

        let mutates = if sub2.eq_ignore_ascii_case("graphql") {
            is_mutating_gh_graphql(args)
        } else {
            args.iter().any(|a| {
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
            })
        };
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
            | ("workflow", "enable" | "disable")
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

fn is_mutating_gh_graphql(args: &[String]) -> bool {
    let mut query_doc: Option<&str> = None;
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if a.starts_with("--input") {
            return true;
        }
        if a == "-X" || a == "--method" {
            let m = args.get(i + 1).map(String::as_str).unwrap_or("");
            if !m.eq_ignore_ascii_case("POST") {
                return true;
            }
            i += 2;
            continue;
        }
        if matches!(a, "-f" | "-F" | "--field" | "--raw-field") {
            let Some(kv) = args.get(i + 1) else {
                return true;
            };
            if let Some(q) = kv.strip_prefix("query=") {
                query_doc = Some(q);
            } else if kv.contains('@') {
                return true;
            }
            i += 2;
            continue;
        }
        if let Some(kv) = a
            .strip_prefix("--field=")
            .or_else(|| a.strip_prefix("--raw-field="))
            .or_else(|| a.strip_prefix("-f").filter(|s| !s.is_empty()))
            .or_else(|| a.strip_prefix("-F").filter(|s| !s.is_empty()))
        {
            if let Some(q) = kv.strip_prefix("query=") {
                query_doc = Some(q);
            } else if kv.contains('@') {
                return true;
            }
            i += 1;
            continue;
        }
        i += 1;
    }
    let Some(q) = query_doc else {
        return true;
    };
    let trimmed = q.trim_start();
    let lower = trimmed.to_ascii_lowercase();
    let starts_readonly = lower.starts_with('{')
        || lower.starts_with("query ")
        || lower.starts_with("query(")
        || lower.starts_with("query{")
        || lower.starts_with("query\n")
        || lower.starts_with("query\t");
    !starts_readonly || lower.contains("mutation") || lower.contains("subscription")
}

fn check_git_command(
    args: &[String],
    repo_root: &Path,
    cwd: &Path,
    session_tainted: bool,
) -> Result<(), CommandViolation> {
    if args.iter().any(|x| x == "--no-verify") {
        return Err(CommandViolation {
            code: "GIT_NO_VERIFY_BLOCKED",
            detail: "Passing `--no-verify` is unconditionally forbidden.".to_string(),
            halt_session: false,
        });
    }

    let mut idx = 0usize;
    let mut target_dir: Option<&str> = None;

    // Inspect global git flags before subcommand (`-c`, `--config-env`, `-C`, `--git-dir`, `--upload-pack`)
    while idx < args.len() {
        let a = args[idx].as_str();
        if a == "-c" || a.starts_with("--config-env") {
            let kv = args.get(idx + 1).map(String::as_str).unwrap_or(a);
            return check_git_inline_config(kv);
        }
        if let Some(kv) = a.strip_prefix("-c") {
            if !kv.is_empty() {
                return check_git_inline_config(kv);
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

    let Some(sub) = args.get(idx).map(String::as_str) else {
        return Ok(());
    };
    let sub_args = &args[idx + 1..];

    // Hard-block `--no-verify` (and `-n` shorthand on `git commit`)
    if sub == "commit"
        && sub_args.iter().any(|x| {
            x == "-n"
                || (x.starts_with('-')
                    && !x.starts_with("--")
                    && x.chars()
                        .skip(1)
                        .take_while(|&c| !matches!(c, 'm' | 'F' | 'C' | 'c'))
                        .any(|c| c == 'n'))
        })
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
            return Err(CommandViolation {
                code: "GIT_CONFIG_MUTATION_BLOCKED",
                detail: "`git config` is hard-blocked in PreToolUse to protect global git hardening and identity."
                    .to_string(),
                halt_session: false,
            });
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
            let is_mut = sub_args
                .first()
                .is_some_and(|op| op != "-v" && op != "--verbose");
            return Err(CommandViolation {
                code: "GIT_REMOTE_MUTATION_BLOCKED",
                detail: "`git remote` is hard-blocked in PreToolUse (prevents remote inspection/push-redirect exfiltration)."
                    .to_string(),
                halt_session: is_mut,
            });
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
    Err(CommandViolation {
        code: "GIT_CONFIG_OVERRIDE_BLOCKED",
        detail: format!(
            "Inline `git -c {kv}` configuration override is unconditionally forbidden."
        ),
        halt_session: true,
    })
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

fn check_python_pkg_manager(
    bin: &str,
    args: &[String],
    repo_root: &Path,
    cwd: &Path,
    session_tainted: bool,
    plan: &mut CommandPlan,
) -> Result<(), CommandViolation> {
    if bin == "uv" {
        let first_sub = args
            .iter()
            .find(|a| !a.starts_with('-'))
            .map(String::as_str)
            .unwrap_or("");
        if first_sub == "tool" || first_sub == "x" || args.iter().any(|a| a == "tool") {
            return check_interpreter_command("uvx", args, repo_root, cwd, session_tainted, plan);
        }
        if first_sub != "pip" || args.iter().any(|a| matches!(a.as_str(), "run" | "python")) {
            check_interpreter_command("uv run", args, repo_root, cwd, session_tainted, plan)?;
            return Ok(());
        }
    }
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

fn is_interpreter_binary(bin: &str) -> bool {
    let lower = bin.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "python"
            | "python2"
            | "python3"
            | "pypy"
            | "pypy3"
            | "uvx"
            | "pipx"
            | "node"
            | "nodejs"
            | "bun"
            | "deno"
            | "tsx"
            | "ts-node"
            | "perl"
            | "ruby"
            | "irb"
            | "php"
            | "lua"
            | "luajit"
    ) || lower.starts_with("python2.")
        || lower.starts_with("python3.")
        || lower.starts_with("perl5.")
        || lower.starts_with("ruby2.")
        || lower.starts_with("ruby3.")
        || lower.starts_with("php7")
        || lower.starts_with("php8")
        || lower.starts_with("lua5")
}

fn check_unittest_command(
    bin: &str,
    args: &[String],
    repo_root: &Path,
    cwd: &Path,
    plan: &mut CommandPlan,
) -> Result<(), CommandViolation> {
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        check_embedded_path_literals(bin, a)?;
        if a == "discover" {
            i += 1;
            continue;
        }
        if matches!(
            a,
            "-s" | "--start-directory" | "-t" | "--top-level-directory"
        ) {
            let Some(val) = args.get(i + 1) else {
                return Err(CommandViolation {
                    code: "MALFORMED_UNITTEST_COMMAND",
                    detail: format!("`{bin} -m unittest {a}` missing directory argument."),
                    halt_session: false,
                });
            };
            check_embedded_path_literals(bin, val)?;
            reject_shell_glob_in_operand(bin, val)?;
            let valid = validate_path(repo_root, cwd, val, PathAccess::Read).map_err(|pv| {
                CommandViolation {
                    code: pv.code,
                    detail: pv.detail,
                    halt_session: pv.is_poisoned_zone,
                }
            })?;
            plan.search_files
                .push((valid.repo_rel, valid.canonical_or_norm));
            i += 2;
            continue;
        }
        if matches!(a, "-p" | "--pattern" | "-k") {
            if let Some(val) = args.get(i + 1) {
                check_embedded_path_literals(bin, val)?;
            }
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        if a.contains('/')
            || a.starts_with('.')
            || a.starts_with('~')
            || a.to_ascii_lowercase().ends_with(".py")
        {
            reject_shell_glob_in_operand(bin, a)?;
            let valid = validate_path(repo_root, cwd, a, PathAccess::Read).map_err(|pv| {
                CommandViolation {
                    code: pv.code,
                    detail: pv.detail,
                    halt_session: pv.is_poisoned_zone,
                }
            })?;
            plan.search_files
                .push((valid.repo_rel, valid.canonical_or_norm));
        }
        i += 1;
    }
    Ok(())
}

fn check_interpreter_command(
    bin: &str,
    args: &[String],
    repo_root: &Path,
    cwd: &Path,
    session_tainted: bool,
    plan: &mut CommandPlan,
) -> Result<(), CommandViolation> {
    let lower_bin = bin.to_ascii_lowercase();
    if !session_tainted
        && matches!(lower_bin.as_str(), "python" | "python3")
        && args.first().map(String::as_str) == Some("-m")
    {
        match args.get(1).map(String::as_str) {
            Some("pytest") => {
                return check_pytest_command(bin, &args[2..], repo_root, cwd, plan);
            }
            Some("unittest") => {
                return check_unittest_command(bin, &args[2..], repo_root, cwd, plan);
            }
            _ => {}
        }
    }

    let allow_interpreter = std::env::var("AGENT_GUARD_ALLOW_INTERPRETER")
        .map(|v| v == "1")
        .unwrap_or(false);
    if session_tainted || !allow_interpreter {
        return Err(CommandViolation {
            code: "UNAPPROVED_INTERPRETER_BLOCKED",
            detail: format!(
                "Execution runtime `{bin}` is hard-blocked in PreToolUse (no Python/Node/Bun/Deno/Perl/Ruby/PHP/Lua/uv run without explicit host `AGENT_GUARD_ALLOW_INTERPRETER=1` approval; use raw coreutils `jq`, `tr`, `awk`, `sed`, `rg`)."
            ),
            halt_session: false,
        });
    }

    if matches!(lower_bin.as_str(), "uvx" | "pipx") {
        return Err(CommandViolation {
            code: "UNVETTED_URL_PACKAGE_BLOCKED",
            detail: format!(
                "`{bin}` ephemeral remote package execution remains blocked even when `AGENT_GUARD_ALLOW_INTERPRETER=1`."
            ),
            halt_session: true,
        });
    }

    // Even when `AGENT_GUARD_ALLOW_INTERPRETER=1` is opted in (alongside Layer-1 `exec-sandbox`),
    // inspect all inline scripts, URLs, network primitives, and file operands so interpreter opt-in
    // is never an all-or-nothing security cliff!
    const BLOCKED_INTERP_CAPABILITIES: &[&str] = &[
        "urllib",
        "http.client",
        "requests.",
        "httpx",
        "aiohttp",
        "socket.",
        "subprocess",
        "os.system",
        "pty.spawn",
        "child_process",
        "fetch(",
        "net.connect",
        "websocket",
        "io::socket",
        "net::http",
        "lwp::",
        "fsockopen",
        "curl_init",
    ];

    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        let lower_a = a.to_ascii_lowercase();
        if lower_a.starts_with("http://") || lower_a.starts_with("https://") {
            return Err(CommandViolation {
                code: "UNVETTED_URL_PACKAGE_BLOCKED",
                detail: format!("Remote URL execution (`{a}`) in `{bin}` is forbidden."),
                halt_session: true,
            });
        }
        check_embedded_path_literals(bin, a)?;
        for cap in BLOCKED_INTERP_CAPABILITIES {
            if lower_a.contains(cap) {
                return Err(CommandViolation {
                    code: "INTERPRETER_DANGEROUS_CAPABILITY_BLOCKED",
                    detail: format!(
                        "`{bin}` inline argument invokes restricted network/subprocess capability `{cap}`."
                    ),
                    halt_session: true,
                });
            }
        }

        if matches!(a, "-c" | "-e" | "-p" | "--eval" | "--print" | "-E") {
            if let Some(code_arg) = args.get(i + 1) {
                check_embedded_path_literals(bin, code_arg)?;
                let lc = code_arg.to_ascii_lowercase();
                for cap in BLOCKED_INTERP_CAPABILITIES {
                    if lc.contains(cap) {
                        return Err(CommandViolation {
                            code: "INTERPRETER_DANGEROUS_CAPABILITY_BLOCKED",
                            detail: format!(
                                "`{bin} {a}` inline code invokes restricted network/subprocess capability `{cap}`."
                            ),
                            halt_session: true,
                        });
                    }
                }
            }
            i += 2;
            continue;
        }
        if a == "-m" {
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }

        let looks_like_path = a.contains('/')
            || a.starts_with('.')
            || a.starts_with('~')
            || [
                ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".rb", ".pl", ".php", ".lua", ".json",
                ".toml", ".yaml", ".yml", ".md",
            ]
            .iter()
            .any(|ext| lower_a.ends_with(ext));

        if looks_like_path {
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
        i += 1;
    }

    Ok(())
}

fn check_pytest_command(
    bin: &str,
    args: &[String],
    repo_root: &Path,
    cwd: &Path,
    plan: &mut CommandPlan,
) -> Result<(), CommandViolation> {
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        check_embedded_path_literals(bin, a)?;
        if matches!(
            a,
            "-k" | "-m"
                | "-o"
                | "--override-ini"
                | "--maxfail"
                | "-n"
                | "--basetemp"
                | "-c"
                | "--rootdir"
                | "--confcutdir"
                | "--ignore"
                | "--deselect"
        ) {
            if let Some(val) = args.get(i + 1) {
                check_embedded_path_literals(bin, val)?;
                if matches!(a, "--basetemp" | "-c" | "--rootdir" | "--confcutdir") {
                    validate_path(repo_root, cwd, val, PathAccess::Read).map_err(|pv| {
                        CommandViolation {
                            code: pv.code,
                            detail: pv.detail,
                            halt_session: pv.is_poisoned_zone,
                        }
                    })?;
                }
            }
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        // Pytest node IDs may take the form `tests/test_foo.py::test_bar`
        let file_part = a.split("::").next().unwrap_or(a);
        reject_shell_glob_in_operand(bin, file_part)?;
        let valid = validate_path(repo_root, cwd, file_part, PathAccess::Read).map_err(|pv| {
            CommandViolation {
                code: pv.code,
                detail: pv.detail,
                halt_session: pv.is_poisoned_zone,
            }
        })?;
        plan.search_files
            .push((valid.repo_rel, valid.canonical_or_norm));
        i += 1;
    }
    Ok(())
}

fn check_search_or_walk_command(
    bin: &str,
    args: &[String],
    repo_root: &Path,
    cwd: &Path,
    piped_stdin: bool,
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
                if a == "--dereference"
                    || a == "--dereference-command-line"
                    || a == "--dereference-command-line-symlink-to-dir"
                    || (a.starts_with('-')
                        && !a.starts_with("--")
                        && (a.contains('L') || a.contains('H')))
                {
                    return Err(CommandViolation {
                        code: "LS_SYMLINK_FOLLOW_BLOCKED",
                        detail:
                            "`ls -L` / `--dereference` symlink following is forbidden in PreToolUse."
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
            // Non-flag operands after pattern are searched files (do not burn read hop depth!)
            let mut skipped_pattern = args.iter().any(|a| {
                a == "-e" || a.starts_with("--regexp=") || a == "-f" || a.starts_with("--file=")
            });
            let mut i = 0usize;
            while i < args.len() {
                let a = &args[i];
                if a.starts_with('-') {
                    if matches!(
                        a.as_str(),
                        "-e" | "--regexp" | "-A" | "-B" | "-C" | "-m" | "--max-count" | "--label"
                    ) {
                        i += 2;
                        continue;
                    }
                    if a == "-f" || a == "--file" {
                        if let Some(fp) = args.get(i + 1) {
                            reject_shell_glob_in_operand(bin, fp)?;
                            let valid = validate_path(repo_root, cwd, fp, PathAccess::Read)
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
                        i += 2;
                        continue;
                    }
                    i += 1;
                    continue;
                }
                if !skipped_pattern {
                    skipped_pattern = true;
                    i += 1;
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
                plan.search_files
                    .push((valid.repo_rel, valid.canonical_or_norm));
                i += 1;
            }
        }
        "find" => {
            let mut max_depth: Option<usize> = None;
            let mut paths: Vec<&str> = Vec::new();
            let mut in_predicates = false;
            let mut i = 0usize;
            while i < args.len() {
                let a = args[i].as_str();
                if !in_predicates {
                    if a == "-L" || a == "-H" || a == "-follow" {
                        return Err(CommandViolation {
                            code: "FIND_SYMLINK_FOLLOW_BLOCKED",
                            detail: format!("`find {a}` symlink following is forbidden."),
                            halt_session: false,
                        });
                    }
                    if a == "-P" || a.starts_with("-O") {
                        i += 1;
                        continue;
                    }
                    if a == "-D" {
                        i += 2;
                        continue;
                    }
                    if !a.starts_with('-') && !matches!(a, "!" | "(" | ")" | ",") {
                        paths.push(a);
                        i += 1;
                        continue;
                    }
                    in_predicates = true;
                }

                if matches!(
                    a,
                    "-exec"
                        | "-execdir"
                        | "-ok"
                        | "-okdir"
                        | "-delete"
                        | "-fls"
                        | "-fprint"
                        | "-fprint0"
                        | "-fprintf"
                ) {
                    return Err(CommandViolation {
                        code: "FIND_EXEC_OR_DELETE_BLOCKED",
                        detail: format!("`find {a}` is forbidden."),
                        halt_session: false,
                    });
                }
                if a == "-L" || a == "-follow" || a == "-H" {
                    return Err(CommandViolation {
                        code: "FIND_SYMLINK_FOLLOW_BLOCKED",
                        detail: format!("`find {a}` symlink following is forbidden."),
                        halt_session: false,
                    });
                }
                if a == "-depth" || a == "-d" {
                    return Err(CommandViolation {
                        code: "FIND_DEPTH_BYPASS_BLOCKED",
                        detail:
                            "`find -depth` disables `-prune` directory exclusion and is forbidden."
                                .to_string(),
                        halt_session: false,
                    });
                }
                if a == "-maxdepth" {
                    max_depth = args.get(i + 1).and_then(|v| v.parse().ok());
                    i += 2;
                    continue;
                }
                if matches!(
                    a,
                    "-mindepth"
                        | "-name"
                        | "-iname"
                        | "-path"
                        | "-ipath"
                        | "-wholename"
                        | "-iwholename"
                        | "-lname"
                        | "-ilname"
                        | "-regex"
                        | "-iregex"
                        | "-regextype"
                        | "-type"
                        | "-xtype"
                        | "-perm"
                        | "-user"
                        | "-group"
                        | "-uid"
                        | "-gid"
                        | "-size"
                        | "-mtime"
                        | "-mmin"
                        | "-ctime"
                        | "-cmin"
                        | "-atime"
                        | "-amin"
                        | "-newer"
                        | "-anewer"
                        | "-cnewer"
                        | "-links"
                        | "-inum"
                        | "-samefile"
                        | "-printf"
                        | "-fstype"
                ) {
                    if args.get(i + 1).is_none() {
                        return Err(CommandViolation {
                            code: "MALFORMED_FIND_COMMAND",
                            detail: format!("`find {a}` missing predicate argument."),
                            halt_session: false,
                        });
                    }
                    i += 2;
                    continue;
                }
                if a.starts_with('-') || matches!(a, "!" | "(" | ")" | ",") {
                    i += 1;
                    continue;
                }
                return Err(CommandViolation {
                    code: "MALFORMED_FIND_COMMAND",
                    detail: format!(
                        "Unexpected path or bare token '{a}' after `find` predicates; place all search paths before `-maxdepth`."
                    ),
                    halt_session: false,
                });
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

            let is_piped_rg_stdin = piped_stdin
                && matches!(bin, "rg" | "ripgrep")
                && !args.iter().any(|a| a == "--files");

            if target_paths.is_empty() {
                if !is_piped_rg_stdin {
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
                }
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
                        plan.search_files
                            .push((valid.repo_rel, valid.canonical_or_norm));
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
    // `tr` operates strictly on stdin -> stdout character sets and never accepts file path operands.
    if bin == "tr" {
        return Ok(());
    }

    let mut push_read = |target: &str, plan: &mut CommandPlan| -> Result<(), CommandViolation> {
        reject_shell_glob_in_operand(bin, target)?;
        let valid = validate_path(repo_root, cwd, target, PathAccess::Read).map_err(|pv| {
            CommandViolation {
                code: pv.code,
                detail: format!("`{bin}` operand '{target}' denied: {}", pv.detail),
                halt_session: pv.is_poisoned_zone,
            }
        })?;
        plan.read_files.push((
            valid.repo_rel,
            valid.canonical_or_norm,
            valid.is_root_authority,
        ));
        Ok(())
    };

    let push_write = |target: &str, plan: &mut CommandPlan| -> Result<(), CommandViolation> {
        reject_shell_glob_in_operand(bin, target)?;
        let valid = validate_path(repo_root, cwd, target, PathAccess::Write).map_err(|pv| {
            CommandViolation {
                code: pv.code,
                detail: format!("`{bin}` target '{target}' denied: {}", pv.detail),
                halt_session: pv.is_poisoned_zone,
            }
        })?;
        plan.write_files
            .push((valid.repo_rel, valid.canonical_or_norm));
        Ok(())
    };

    match bin {
        "jq" => {
            let mut has_filter_file = false;
            let mut seen_inline_filter = false;
            let mut after_double_dash = false;
            let mut i = 0usize;
            while i < args.len() {
                let a = args[i].as_str();
                if !after_double_dash && (a == "--args" || a == "--jsonargs") {
                    // All remaining tokens are scalar/JSON values, not files
                    return Ok(());
                }
                if !after_double_dash && a == "--" {
                    after_double_dash = true;
                    i += 1;
                    continue;
                }
                if !after_double_dash && a.starts_with('-') && a != "-" {
                    if a == "-f" || a == "--from-file" {
                        has_filter_file = true;
                        if let Some(fp) = args.get(i + 1) {
                            push_read(fp, plan)?;
                        }
                        i += 2;
                        continue;
                    }
                    if matches!(a, "--slurpfile" | "--rawfile") {
                        if let Some(fp) = args.get(i + 2) {
                            push_read(fp, plan)?;
                        }
                        i += 3;
                        continue;
                    }
                    if a == "-L" {
                        if let Some(dir) = args.get(i + 1) {
                            reject_shell_glob_in_operand(bin, dir)?;
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
                                detail: pv.detail,
                                halt_session: pv.is_poisoned_zone,
                            })?;
                        }
                        i += 2;
                        continue;
                    }
                    if matches!(a, "--arg" | "--argjson") {
                        i += 3;
                        continue;
                    }
                    if a == "--indent" {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    continue;
                }
                if !has_filter_file && !seen_inline_filter {
                    seen_inline_filter = true;
                    i += 1;
                    continue;
                }
                if a != "-" {
                    push_read(a, plan)?;
                }
                i += 1;
            }
            return Ok(());
        }
        "head" | "tail" => {
            let mut after_double_dash = false;
            let mut i = 0usize;
            while i < args.len() {
                let a = args[i].as_str();
                if !after_double_dash && a == "--" {
                    after_double_dash = true;
                    i += 1;
                    continue;
                }
                if !after_double_dash && a.starts_with('-') && a != "-" {
                    if matches!(
                        a,
                        "-n" | "--lines" | "-c" | "--bytes" | "-s" | "--sleep-interval" | "--pid"
                    ) {
                        i += 2;
                    } else {
                        i += 1;
                    }
                    continue;
                }
                if a != "-" {
                    push_read(a, plan)?;
                }
                i += 1;
            }
            return Ok(());
        }
        "cut" => {
            let mut after_double_dash = false;
            let mut i = 0usize;
            while i < args.len() {
                let a = args[i].as_str();
                if !after_double_dash && a == "--" {
                    after_double_dash = true;
                    i += 1;
                    continue;
                }
                if !after_double_dash && a.starts_with('-') && a != "-" {
                    if matches!(
                        a,
                        "-b" | "--bytes"
                            | "-c"
                            | "--characters"
                            | "-d"
                            | "--delimiter"
                            | "-f"
                            | "--fields"
                            | "--output-delimiter"
                    ) {
                        i += 2;
                    } else {
                        i += 1;
                    }
                    continue;
                }
                if a != "-" {
                    push_read(a, plan)?;
                }
                i += 1;
            }
            return Ok(());
        }
        "sort" => {
            let mut after_double_dash = false;
            let mut i = 0usize;
            while i < args.len() {
                let a = args[i].as_str();
                if !after_double_dash && a == "--" {
                    after_double_dash = true;
                    i += 1;
                    continue;
                }
                if !after_double_dash && a.starts_with('-') && a != "-" {
                    if a.starts_with("--compress-program") {
                        return Err(CommandViolation {
                            code: "SORT_COMPRESS_EXEC_BLOCKED",
                            detail: "`sort --compress-program` executes arbitrary external binaries and is forbidden."
                                .to_string(),
                            halt_session: true,
                        });
                    }
                    if a.starts_with("--files0-from") {
                        return Err(CommandViolation {
                            code: "DYNAMIC_FILES0_BLOCKED",
                            detail: "`sort --files0-from` dynamic path loading is forbidden."
                                .to_string(),
                            halt_session: true,
                        });
                    }
                    if a == "-o" || a == "--output" || a == "-T" || a == "--temporary-directory" {
                        if let Some(p) = args.get(i + 1) {
                            push_write(p, plan)?;
                        }
                        i += 2;
                        continue;
                    }
                    if let Some(p) = a
                        .strip_prefix("--output=")
                        .or_else(|| a.strip_prefix("--temporary-directory="))
                        .or_else(|| a.strip_prefix("-o").filter(|s| !s.is_empty()))
                        .or_else(|| a.strip_prefix("-T").filter(|s| !s.is_empty()))
                    {
                        push_write(p, plan)?;
                        i += 1;
                        continue;
                    }
                    if matches!(
                        a,
                        "-k" | "--key"
                            | "-t"
                            | "--field-separator"
                            | "-S"
                            | "--buffer-size"
                            | "--parallel"
                            | "--batch-size"
                    ) {
                        i += 2;
                    } else {
                        i += 1;
                    }
                    continue;
                }
                if a != "-" {
                    push_read(a, plan)?;
                }
                i += 1;
            }
            return Ok(());
        }
        "uniq" => {
            let mut after_double_dash = false;
            let mut pos_idx = 0usize;
            let mut i = 0usize;
            while i < args.len() {
                let a = args[i].as_str();
                if !after_double_dash && a == "--" {
                    after_double_dash = true;
                    i += 1;
                    continue;
                }
                if !after_double_dash && a.starts_with('-') && a != "-" {
                    if matches!(
                        a,
                        "-f" | "--skip-fields" | "-s" | "--skip-chars" | "-w" | "--check-chars"
                    ) {
                        i += 2;
                    } else {
                        i += 1;
                    }
                    continue;
                }
                if a != "-" {
                    if pos_idx == 0 {
                        push_read(a, plan)?;
                    } else {
                        push_write(a, plan)?;
                    }
                }
                pos_idx += 1;
                i += 1;
            }
            return Ok(());
        }
        "wc" => {
            let mut after_double_dash = false;
            for a in args {
                let s = a.as_str();
                if !after_double_dash && s == "--" {
                    after_double_dash = true;
                    continue;
                }
                if !after_double_dash && s.starts_with('-') && s != "-" {
                    if s.starts_with("--files0-from") {
                        return Err(CommandViolation {
                            code: "DYNAMIC_FILES0_BLOCKED",
                            detail: "`wc --files0-from` dynamic path loading is forbidden."
                                .to_string(),
                            halt_session: true,
                        });
                    }
                    continue;
                }
                if s != "-" {
                    push_read(s, plan)?;
                }
            }
            return Ok(());
        }
        _ => {}
    }

    if matches!(bin, "awk" | "gawk" | "mawk" | "nawk") {
        let mut has_explicit_prog = false;
        let mut after_double_dash = false;
        let mut i = 0usize;
        while i < args.len() {
            let a = args[i].as_str();
            if !after_double_dash && a == "--" {
                after_double_dash = true;
                i += 1;
                continue;
            }
            if !after_double_dash && a.starts_with('-') && a != "-" {
                if a == "-l" || a == "--load" || a.starts_with("-l") || a.starts_with("--load=") {
                    return Err(CommandViolation {
                        code: "AWK_SYSTEM_EXEC_BLOCKED",
                        detail: format!("`{bin} {a}` dynamic extension loading is forbidden."),
                        halt_session: true,
                    });
                }
                if a == "-o"
                    || a.starts_with("-o")
                    || a.starts_with("--pretty-print")
                    || a.starts_with("--dump-variables")
                    || a.starts_with("--profile")
                {
                    return Err(CommandViolation {
                        code: "AWK_FILE_REDIR_BLOCKED",
                        detail: format!("`{bin} {a}` file output flag is forbidden."),
                        halt_session: true,
                    });
                }
                if a == "-e" || a == "--source" {
                    let Some(prog) = args.get(i + 1) else {
                        return Err(CommandViolation {
                            code: "MALFORMED_AWK_COMMAND",
                            detail: format!("`{bin} {a}` missing program text."),
                            halt_session: false,
                        });
                    };
                    inspect_awk_program(prog)?;
                    has_explicit_prog = true;
                    i += 2;
                    continue;
                }
                if let Some(prog) = a
                    .strip_prefix("--source=")
                    .or_else(|| a.strip_prefix("-e").filter(|s| !s.is_empty()))
                {
                    inspect_awk_program(prog)?;
                    has_explicit_prog = true;
                    i += 1;
                    continue;
                }
                if a == "-f" || a == "--file" {
                    let Some(script_f) = args.get(i + 1) else {
                        return Err(CommandViolation {
                            code: "MALFORMED_AWK_COMMAND",
                            detail: format!("`{bin} {a}` missing script file operand."),
                            halt_session: false,
                        });
                    };
                    push_read(script_f, plan)?;
                    inspect_awk_or_sed_script_file(repo_root, cwd, script_f, true)?;
                    has_explicit_prog = true;
                    i += 2;
                    continue;
                }
                if let Some(script_f) = a
                    .strip_prefix("--file=")
                    .or_else(|| a.strip_prefix("-f").filter(|s| !s.is_empty()))
                {
                    push_read(script_f, plan)?;
                    inspect_awk_or_sed_script_file(repo_root, cwd, script_f, true)?;
                    has_explicit_prog = true;
                    i += 1;
                    continue;
                }
                if a == "-F" || a == "--field-separator" || a == "-W" {
                    i += 2;
                    continue;
                }
                if a == "-v" || a == "--assign" {
                    if let Some(assign) = args.get(i + 1) {
                        inspect_awk_assignment(assign, &mut push_read, plan)?;
                    }
                    i += 2;
                    continue;
                }
                if let Some(assign) = a
                    .strip_prefix("--assign=")
                    .or_else(|| a.strip_prefix("-v").filter(|s| !s.is_empty()))
                {
                    inspect_awk_assignment(assign, &mut push_read, plan)?;
                    i += 1;
                    continue;
                }
                i += 1;
                continue;
            }
            if !has_explicit_prog {
                inspect_awk_program(a)?;
                has_explicit_prog = true;
                i += 1;
                continue;
            }
            if a != "-" {
                if a.contains('=') && !Path::new(a).exists() {
                    inspect_awk_assignment(a, &mut push_read, plan)?;
                } else {
                    push_read(a, plan)?;
                }
            }
            i += 1;
        }
        return Ok(());
    }

    if matches!(bin, "sed" | "gsed") {
        let sed_in_place = args
            .iter()
            .any(|a| a == "-i" || a.starts_with("-i") || a.starts_with("--in-place"));
        let mut has_explicit_expr = false;
        let mut after_double_dash = false;
        let mut i = 0usize;
        while i < args.len() {
            let a = args[i].as_str();
            if !after_double_dash && a == "--" {
                after_double_dash = true;
                i += 1;
                continue;
            }
            if !after_double_dash && a.starts_with('-') && a != "-" {
                if a == "-e" || a == "--expression" {
                    let Some(expr) = args.get(i + 1) else {
                        return Err(CommandViolation {
                            code: "MALFORMED_SED_COMMAND",
                            detail: format!("`{bin} {a}` missing script expression."),
                            halt_session: false,
                        });
                    };
                    inspect_sed_script(expr)?;
                    has_explicit_expr = true;
                    i += 2;
                    continue;
                }
                if let Some(expr) = a
                    .strip_prefix("--expression=")
                    .or_else(|| a.strip_prefix("-e").filter(|s| !s.is_empty()))
                {
                    inspect_sed_script(expr)?;
                    has_explicit_expr = true;
                    i += 1;
                    continue;
                }
                if a == "-f" || a == "--file" {
                    let Some(script_f) = args.get(i + 1) else {
                        return Err(CommandViolation {
                            code: "MALFORMED_SED_COMMAND",
                            detail: format!("`{bin} {a}` missing script file."),
                            halt_session: false,
                        });
                    };
                    push_read(script_f, plan)?;
                    inspect_awk_or_sed_script_file(repo_root, cwd, script_f, false)?;
                    has_explicit_expr = true;
                    i += 2;
                    continue;
                }
                if let Some(script_f) = a
                    .strip_prefix("--file=")
                    .or_else(|| a.strip_prefix("-f").filter(|s| !s.is_empty()))
                {
                    push_read(script_f, plan)?;
                    inspect_awk_or_sed_script_file(repo_root, cwd, script_f, false)?;
                    has_explicit_expr = true;
                    i += 1;
                    continue;
                }
                if a == "-l" || a == "--line-length" {
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            if !has_explicit_expr {
                inspect_sed_script(a)?;
                has_explicit_expr = true;
                i += 1;
                continue;
            }
            if a != "-" {
                if sed_in_place {
                    push_write(a, plan)?;
                }
                push_read(a, plan)?;
            }
            i += 1;
        }
        return Ok(());
    }

    let is_reader = matches!(
        bin,
        "cat" | "less" | "more" | "nl" | "stat" | "file" | "sha256sum" | "md5sum" | "diff"
    );
    let is_writer = matches!(bin, "rm" | "rmdir" | "mkdir" | "touch" | "truncate");
    let is_src_dst = matches!(bin, "cp" | "mv" | "ln");

    if is_reader {
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if a.starts_with('-') && a != "-" {
                i += 1;
                continue;
            }
            if a != "-" {
                push_read(a, plan)?;
            }
            i += 1;
        }
        return Ok(());
    }

    if is_writer {
        for a in args.iter().filter(|a| !a.starts_with('-')) {
            push_write(a, plan)?;
        }
        return Ok(());
    }

    if is_src_dst {
        let operands: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
        if operands.len() >= 2 {
            for src in &operands[..operands.len() - 1] {
                push_read(src, plan)?;
            }
            let dst = operands[operands.len() - 1];
            push_write(dst, plan)?;
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

fn inspect_awk_or_sed_script_file(
    repo_root: &Path,
    cwd: &Path,
    script_f: &str,
    is_awk: bool,
) -> Result<(), CommandViolation> {
    let candidate = if Path::new(script_f).is_absolute() {
        std::path::PathBuf::from(script_f)
    } else {
        cwd.join(script_f)
    };
    let _ = repo_root;
    if let Ok(meta) = std::fs::symlink_metadata(&candidate) {
        if meta.file_type().is_file() && meta.len() <= 65_536 {
            if let Ok(text) = std::fs::read_to_string(&candidate) {
                if is_awk {
                    inspect_awk_program(&text)?;
                } else {
                    inspect_sed_script(&text)?;
                }
            }
        }
    }
    Ok(())
}

fn inspect_awk_assignment<F>(
    assign: &str,
    push_read: &mut F,
    plan: &mut CommandPlan,
) -> Result<(), CommandViolation>
where
    F: FnMut(&str, &mut CommandPlan) -> Result<(), CommandViolation>,
{
    let val = assign.split_once('=').map(|(_, v)| v).unwrap_or(assign);
    check_embedded_path_literals("awk -v", val)?;
    if (val.contains('/') || val.starts_with('.') || val.starts_with('~'))
        && val != "."
        && val != "/dev/null"
    {
        let candidate = Path::new(val);
        if candidate.exists() {
            push_read(val, plan)?;
        } else if let Err(pv) = check_forbidden_zones_lexical(val, assign) {
            return Err(CommandViolation {
                code: pv.code,
                detail: pv.detail,
                halt_session: pv.is_poisoned_zone,
            });
        }
    }
    Ok(())
}

fn check_embedded_path_literals(ctx: &str, text: &str) -> Result<(), CommandViolation> {
    let lower = text.to_ascii_lowercase();
    const PROTECTED_LITERALS: &[&str] = &[
        ".env",
        ".ssh",
        ".aws",
        ".gnupg",
        ".netrc",
        ".git/config",
        ".git/hooks",
        "agents.md",
        "claude.md",
        ".cursorrules",
        ".windsurfrules",
        ".clinerules",
        "copilot-instructions.md",
        ".claude/",
        ".codex/",
        ".cursor/",
        ".agent-guard",
        "audit.jsonl",
        "hmac.key",
        "coord.sock",
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/proc/",
        "node_modules",
    ];
    for needle in PROTECTED_LITERALS {
        if lower.contains(needle) {
            return Err(CommandViolation {
                code: "EMBEDDED_FORBIDDEN_PATH_BLOCKED",
                detail: format!(
                    "`{ctx}` embeds protected or forbidden path literal matching `{needle}`."
                ),
                halt_session: true,
            });
        }
    }
    Ok(())
}

fn inspect_awk_program(prog: &str) -> Result<(), CommandViolation> {
    check_embedded_path_literals("awk", prog)?;

    let bytes = prog.as_bytes();
    let mut i = 0usize;
    let mut in_str = false;
    let mut in_regex = false;
    let mut can_start_regex = true;
    let mut in_print_stmt = false;
    let mut in_getline_stmt = false;
    let mut paren_depth = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_str = false;
                can_start_regex = false;
            }
            i += 1;
            continue;
        }
        if in_regex {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'/' {
                in_regex = false;
                can_start_regex = false;
            }
            i += 1;
            continue;
        }
        if b == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b == b'"' {
            in_str = true;
            i += 1;
            continue;
        }
        if b == b'/' && can_start_regex {
            in_regex = true;
            i += 1;
            continue;
        }
        if b.is_ascii_whitespace() {
            if b == b'\n' && paren_depth == 0 {
                in_print_stmt = false;
                in_getline_stmt = false;
                can_start_regex = true;
            }
            i += 1;
            continue;
        }

        // Identifiers (`system`, `print`, `printf`, `getline`)
        if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let ident = &prog[start..i];
            if ident == "system" {
                let mut k = i;
                while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                    k += 1;
                }
                if k < bytes.len() && bytes[k] == b'(' {
                    return Err(CommandViolation {
                        code: "AWK_SYSTEM_EXEC_BLOCKED",
                        detail: "`awk` `system(...)` command execution is forbidden.".to_string(),
                        halt_session: true,
                    });
                }
            } else if ident == "print" || ident == "printf" {
                in_print_stmt = true;
                can_start_regex = true;
                continue;
            } else if ident == "getline" {
                in_getline_stmt = true;
                can_start_regex = false;
                continue;
            }
            can_start_regex = matches!(ident, "return" | "case" | "delete" | "in");
            continue;
        }

        match b {
            b'(' => {
                paren_depth += 1;
                can_start_regex = true;
            }
            b')' => {
                paren_depth = paren_depth.saturating_sub(1);
                can_start_regex = false;
            }
            b';' | b'{' | b'}' => {
                in_print_stmt = false;
                in_getline_stmt = false;
                can_start_regex = true;
            }
            b'|' => {
                // `||` is logical OR; single `|` or `|&` outside strings/regexes is a shell pipe!
                if bytes.get(i + 1) == Some(&b'|') {
                    can_start_regex = true;
                    i += 2;
                    continue;
                }
                return Err(CommandViolation {
                    code: "AWK_SYSTEM_EXEC_BLOCKED",
                    detail: "`awk` shell command pipe (`|` / `|&`) is forbidden.".to_string(),
                    halt_session: true,
                });
            }
            b'>' => {
                // `>>` in awk is exclusively file append redirection; unparenthesized `>` inside
                // `print`/`printf` is POSIX awk file output redirection.
                if bytes.get(i + 1) == Some(&b'>') || (in_print_stmt && paren_depth == 0) {
                    return Err(CommandViolation {
                        code: "AWK_FILE_REDIR_BLOCKED",
                        detail: "`awk` `>` / `>>` internal file redirection is forbidden."
                            .to_string(),
                        halt_session: true,
                    });
                }
                if bytes.get(i + 1) == Some(&b'=') {
                    i += 2;
                    can_start_regex = true;
                    continue;
                }
                can_start_regex = true;
            }
            b'<' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    i += 2;
                    can_start_regex = true;
                    continue;
                }
                if in_getline_stmt && paren_depth == 0 {
                    return Err(CommandViolation {
                        code: "AWK_FILE_REDIR_BLOCKED",
                        detail:
                            "`awk` `getline < file` unvalidated file input redirection is forbidden; pass files as CLI operands."
                                .to_string(),
                        halt_session: true,
                    });
                }
                can_start_regex = true;
            }
            b'~' | b'!' | b',' | b'=' | b'?' | b':' | b'&' | b'+' | b'-' | b'*' | b'%' | b'^'
            | b'[' => {
                can_start_regex = true;
            }
            _ => {
                can_start_regex = false;
            }
        }
        i += 1;
    }

    Ok(())
}

fn inspect_sed_script(script: &str) -> Result<(), CommandViolation> {
    let bytes = script.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        while i < bytes.len()
            && (bytes[i].is_ascii_whitespace() || matches!(bytes[i], b';' | b'{' | b'}'))
        {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        if bytes[i] == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        // Skip zero, one, or two sed addresses (`1`, `$`, `/re/`, `\crec`, `,`, `~`, `+`, `!`)
        loop {
            while i < bytes.len() && bytes[i].is_ascii_whitespace() && bytes[i] != b'\n' {
                i += 1;
            }
            if i >= bytes.len() {
                break;
            }
            let c = bytes[i];
            if c.is_ascii_digit() || matches!(c, b'$' | b',' | b'~' | b'+' | b'!') {
                i += 1;
                continue;
            }
            if c == b'/' {
                i += 1;
                while i < bytes.len() && bytes[i] != b'/' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1; // closing `/`
                // Optional GNU sed address modifiers `I` or `M`
                while i < bytes.len() && matches!(bytes[i], b'I' | b'M') {
                    i += 1;
                }
                continue;
            }
            if c == b'\\' && i + 1 < bytes.len() {
                let delim = bytes[i + 1];
                i += 2;
                while i < bytes.len() && bytes[i] != delim {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
                continue;
            }
            break;
        }

        while i < bytes.len() && bytes[i].is_ascii_whitespace() && bytes[i] != b'\n' {
            i += 1;
        }
        if i >= bytes.len() || matches!(bytes[i], b';' | b'\n' | b'{' | b'}') {
            continue;
        }

        let cmd = bytes[i];
        i += 1;
        match cmd {
            b'e' => {
                return Err(CommandViolation {
                    code: "SED_EXEC_OR_FILE_IO_BLOCKED",
                    detail: "`sed` `e` shell execution command is forbidden.".to_string(),
                    halt_session: true,
                });
            }
            b'r' | b'R' | b'w' | b'W' => {
                return Err(CommandViolation {
                    code: "SED_EXEC_OR_FILE_IO_BLOCKED",
                    detail: format!(
                        "`sed` `{}` external file read/write command is forbidden.",
                        cmd as char
                    ),
                    halt_session: true,
                });
            }
            b's' | b'y' => {
                if i < bytes.len() {
                    let delim = bytes[i];
                    i += 1;
                    // Skip pattern + replacement separated by `delim`
                    for _ in 0..2 {
                        while i < bytes.len() && bytes[i] != delim {
                            if bytes[i] == b'\\' {
                                i += 1;
                            }
                            i += 1;
                        }
                        if i < bytes.len() {
                            i += 1;
                        }
                    }
                    if cmd == b's' {
                        while i < bytes.len()
                            && !bytes[i].is_ascii_whitespace()
                            && !matches!(bytes[i], b';' | b'}')
                        {
                            let fl = bytes[i];
                            if fl == b'e' {
                                return Err(CommandViolation {
                                    code: "SED_EXEC_OR_FILE_IO_BLOCKED",
                                    detail: "`sed` `s///e` shell execution flag is forbidden."
                                        .to_string(),
                                    halt_session: true,
                                });
                            }
                            if fl == b'w' {
                                return Err(CommandViolation {
                                    code: "SED_EXEC_OR_FILE_IO_BLOCKED",
                                    detail:
                                        "`sed` `s///w` unvalidated file write flag is forbidden."
                                            .to_string(),
                                    halt_session: true,
                                });
                            }
                            i += 1;
                        }
                    }
                }
            }
            b'a' | b'i' | b'c' | b':' | b'b' | b't' | b'T' => {
                while i < bytes.len() && bytes[i] != b'\n' && bytes[i] != b';' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 2;
                        continue;
                    }
                    i += 1;
                }
            }
            _ => {
                while i < bytes.len() && bytes[i] != b'\n' && bytes[i] != b';' && bytes[i] != b'}' {
                    i += 1;
                }
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

fn shell_quote_single(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/'))
    {
        return arg.to_string();
    }
    format!("'{}'", arg.replace('\'', "'\\''"))
}

fn maybe_rewrite_top_level_find(_raw_script: &str, commands: &[ParsedCommand]) -> Option<String> {
    let first = commands.first()?;
    if !first.env_vars.is_empty() || !first.redirs.is_empty() {
        return None;
    }
    if first.argv.first().map(|s| basename(s)) != Some("find") {
        return None;
    }
    for stage in &commands[1..] {
        if !stage.piped_stdin || !stage.env_vars.is_empty() || !stage.redirs.is_empty() {
            return None;
        }
    }

    let args = &first.argv[1..];
    if args.iter().any(|a| a == "-prune") {
        return None;
    }

    let mut leading_opts: Vec<&str> = Vec::new();
    let mut start_paths: Vec<&str> = Vec::new();
    let mut idx = 0usize;
    while idx < args.len() {
        let a = args[idx].as_str();
        if a == "-P" || a.starts_with("-O") {
            leading_opts.push(a);
            idx += 1;
            continue;
        }
        if a == "-D" {
            leading_opts.push(a);
            if let Some(opt) = args.get(idx + 1) {
                leading_opts.push(opt.as_str());
            }
            idx += 2;
            continue;
        }
        if !a.starts_with('-') && !matches!(a, "!" | "(" | ")" | ",") {
            start_paths.push(a);
            idx += 1;
            continue;
        }
        break;
    }
    if start_paths.is_empty() {
        start_paths.push(".");
    }

    let mut global_opts: Vec<&str> = Vec::new();
    while idx < args.len() {
        let a = args[idx].as_str();
        if a == "-maxdepth" || a == "-mindepth" {
            global_opts.push(a);
            if let Some(val) = args.get(idx + 1) {
                global_opts.push(val.as_str());
            }
            idx += 2;
            continue;
        }
        if a == "-xdev" || a == "-mount" {
            global_opts.push(a);
            idx += 1;
            continue;
        }
        break;
    }

    let user_expr = &args[idx..];
    const ROOT_PRUNED_PATHS: &[&str] = &[
        "./target",
        "target",
        "./build",
        "build",
        "./dist-build",
        "dist-build",
    ];
    const PRUNED_NAMES: &[&str] = &[
        ".git",
        "node_modules",
        "vendor",
        ".venv",
        "venv",
        ".cache",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".next",
        ".turbo",
        "tmp",
        ".tmp",
        "temp",
        ".temp",
        ".agent-guard-state",
        ".env",
        ".env.*",
        "*.pem",
        "*.key",
        "audit.jsonl",
    ];

    let mut out = String::from("find");
    for opt in leading_opts {
        out.push(' ');
        out.push_str(&shell_quote_single(opt));
    }
    for p in start_paths {
        out.push(' ');
        out.push_str(&shell_quote_single(p));
    }
    for g in global_opts {
        out.push(' ');
        out.push_str(&shell_quote_single(g));
    }
    out.push_str(" '(' ");
    let mut first_pred = true;
    for rp in ROOT_PRUNED_PATHS {
        if !first_pred {
            out.push_str(" -o ");
        }
        first_pred = false;
        out.push_str("-path ");
        out.push_str(&shell_quote_single(rp));
    }
    for d in PRUNED_NAMES {
        if !first_pred {
            out.push_str(" -o ");
        }
        first_pred = false;
        out.push_str("-name ");
        out.push_str(&shell_quote_single(d));
    }
    out.push_str(" ')' -prune -o");

    if user_expr.is_empty() {
        out.push_str(" -print");
    } else {
        let has_explicit_action = user_expr
            .iter()
            .any(|t| matches!(t.as_str(), "-print" | "-print0" | "-ls" | "-printf"));
        out.push_str(" '('");
        for tok in user_expr {
            out.push(' ');
            out.push_str(&shell_quote_single(tok));
        }
        out.push_str(" ')'");
        if !has_explicit_action {
            out.push_str(" -print");
        }
    }

    for stage in &commands[1..] {
        out.push_str(" | ");
        for (ti, tok) in stage.argv.iter().enumerate() {
            if ti > 0 {
                out.push(' ');
            }
            out.push_str(&shell_quote_single(tok));
        }
    }

    Some(out)
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
) -> Result<(Vec<ParsedCommand>, bool), CommandViolation> {
    let bytes = script.as_bytes();
    let mut i = 0usize;
    let mut commands = Vec::new();
    let mut cur_env = Vec::new();
    let mut cur_argv = Vec::new();
    let mut cur_redirs = Vec::new();
    let mut cur_piped_stdin = false;
    let mut has_compound_list_op = false;
    let mut pending_heredocs: Vec<(String, bool, bool)> = Vec::new();

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
            let is_plain_pipe =
                b == b'|' && bytes.get(i + 1) != Some(&b'|') && bytes.get(i + 1) != Some(&b'&');
            if matches!(b, b';' | b'&')
                || (b == b'|' && matches!(bytes.get(i + 1), Some(b'|' | b'&')))
            {
                has_compound_list_op = true;
            }
            flush(
                &mut cur_env,
                &mut cur_argv,
                &mut cur_redirs,
                &mut cur_piped_stdin,
                &mut commands,
            );
            cur_piped_stdin = is_plain_pipe;
            if ((b == b'|' || b == b'&') && bytes.get(i + 1) == Some(&b))
                || (b == b'|' && bytes.get(i + 1) == Some(&b'&'))
            {
                i += 2;
            } else {
                i += 1;
            }
            if b == b'\n' && !pending_heredocs.is_empty() {
                for (delim, strip_tabs, is_quoted_delim) in pending_heredocs.drain(..) {
                    let body_start = i;
                    let mut body_end = bytes.len();
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
                            body_end = line_start;
                            break;
                        }
                    }
                    if !is_quoted_delim && body_end > body_start {
                        extract_unquoted_heredoc_expansions(
                            &script[body_start..body_end],
                            subscripts,
                        )?;
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
        if b == b')' {
            return Err(CommandViolation {
                code: "UNBALANCED_SUBSHELL",
                detail: "Unmatched ')' in shell command.".to_string(),
                halt_session: false,
            });
        }
        // Brace group `{ ...; }`
        if b == b'{' || b == b'}' {
            has_compound_list_op = true;
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
            let raw_delim_start = i;
            let (target_word, next_i) = read_shell_word(script, i, subscripts)?;
            if next_i <= i {
                return Err(CommandViolation {
                    code: "MALFORMED_REDIRECTION",
                    detail: "Shell redirection missing target operand.".to_string(),
                    halt_session: false,
                });
            }
            if is_multiline_heredoc && !target_word.is_empty() {
                let raw_delim = &script[raw_delim_start..next_i];
                let is_quoted_delim = raw_delim.contains(['\'', '"', '\\']);
                pending_heredocs.push((target_word.clone(), strip_heredoc_tabs, is_quoted_delim));
            }
            cur_redirs.push((kind, target_word));
            i = next_i;
            continue;
        }

        // Normal word (resolving quotes & escapes, and extracting nested `$(...)` / `` `...` ``)
        let (word, next_i) = read_shell_word(script, i, subscripts)?;
        if next_i <= i {
            return Err(CommandViolation {
                code: "UNEXPECTED_SHELL_TOKEN",
                detail: "Unexpected shell metacharacter in command.".to_string(),
                halt_session: false,
            });
        }
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
    Ok((commands, has_compound_list_op))
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

fn extract_unquoted_heredoc_expansions(
    body: &str,
    subscripts: &mut Vec<String>,
) -> Result<(), CommandViolation> {
    let bytes = body.as_bytes();
    let mut j = 0usize;
    while j < bytes.len() {
        if bytes[j] == b'\\' {
            if j + 1 < bytes.len() {
                let ch_len = body[j + 1..].chars().next().map_or(1, char::len_utf8);
                j += 1 + ch_len;
            } else {
                j += 1;
            }
            continue;
        }
        if bytes[j] == b'$' && bytes.get(j + 1) == Some(&b'(') {
            if bytes.get(j + 2) == Some(&b'(') {
                let (arith_inner, next_j) = extract_balanced_parens(body, j + 1)?;
                extract_unquoted_heredoc_expansions(&arith_inner, subscripts)?;
                j = next_j;
                continue;
            }
            let (inner, next_j) = extract_balanced_parens(body, j + 1)?;
            subscripts.push(inner);
            j = next_j;
            continue;
        }
        if bytes[j] == b'`' {
            let (inner, next_j) = extract_backticks(body, j)?;
            subscripts.push(inner);
            j = next_j;
            continue;
        }
        let ch_len = body[j..].chars().next().map_or(1, char::len_utf8);
        j += ch_len;
    }
    Ok(())
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
            if i + 1 >= bytes.len() {
                return Err(CommandViolation {
                    code: "UNTERMINATED_SHELL_ESCAPE",
                    detail: "Trailing backslash inside subshell.".to_string(),
                    halt_session: false,
                });
            }
            let ch_len = script[i + 1..].chars().next().map_or(1, char::len_utf8);
            i += 1 + ch_len;
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
        let ch_len = script[i..].chars().next().map_or(1, char::len_utf8);
        i += ch_len;
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
