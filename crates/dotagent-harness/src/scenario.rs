//! Declarative multi-harness TOML scenario loader, protocol payload builder,
//! and stateful execution engine for `dotagent-harness`.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use agent_guard::json::JsonValue;

use crate::CaseResult;
use crate::sandbox::TestSandbox;
use crate::toml_lite::{TomlTable, TomlValue, parse_toml_document};

#[derive(Debug, Clone)]
pub struct ScenarioSpec {
    pub id: String,
    pub source_file: String,
    pub harness: HarnessFlavor,
    pub description: String,
    pub session_id: String,
    pub profile: Option<String>,
    pub env: BTreeMap<String, String>,
    pub setup_files: Vec<SetupFile>,
    pub steps: Vec<ScenarioStep>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarnessFlavor {
    Claude,
    Gemini,
    Cursor,
    Codex,
    Cli,
}

impl HarnessFlavor {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "claude" => Ok(Self::Claude),
            "gemini" | "antigravity" => Ok(Self::Gemini),
            "cursor" => Ok(Self::Cursor),
            "codex" => Ok(Self::Codex),
            "cli" => Ok(Self::Cli),
            other => Err(format!(
                "unknown harness '{other}' (expected claude|gemini|cursor|codex|cli)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Gemini => "gemini",
            Self::Cursor => "cursor",
            Self::Codex => "codex",
            Self::Cli => "cli",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SetupFile {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct ScenarioStep {
    pub name: String,
    pub kind: String,
    pub tool_name: Option<String>,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub file_path: Option<String>,
    pub content: Option<String>,
    pub patch: Option<String>,
    pub offset: Option<u64>,
    pub limit: Option<u64>,
    pub start_line: Option<u64>,
    pub end_line: Option<u64>,
    pub cwd_override: Option<String>,
    pub tool_cwd: Option<String>,
    pub url: Option<String>,
    pub tool_response: Option<String>,
    pub stdin_text: Option<String>,
    pub raw_json: Option<String>,
    pub profile_override: Option<String>,
    pub expect_exit: i32,
    pub expect_decision: Option<String>,
    pub expect_code: Option<String>,
    pub expect_advisory_contains: Option<String>,
    pub expect_updated_input_contains: Option<String>,
    pub expect_updated_output_contains: Option<String>,
    pub expect_stdout_contains: Option<String>,
    pub expect_stderr_contains: Option<String>,
    pub expect_output_ascii_7bit: bool,
}

pub fn load_scenarios_from_path(path: &Path) -> Result<Vec<ScenarioSpec>, String> {
    if path.is_file() {
        return load_scenarios_from_file(path);
    }
    if !path.is_dir() {
        return Err(format!("scenario path '{}' does not exist", path.display()));
    }

    let mut files: Vec<PathBuf> = Vec::new();
    let entries = fs::read_dir(path)
        .map_err(|e| format!("failed reading scenario dir '{}': {e}", path.display()))?;
    for entry_res in entries {
        let entry = entry_res.map_err(|e| format!("dir entry error: {e}"))?;
        let file_type = entry
            .file_type()
            .map_err(|e| format!("file_type error: {e}"))?;
        if file_type.is_symlink() || !file_type.is_file() {
            continue;
        }
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) == Some("toml") {
            files.push(p);
        }
    }
    files.sort();

    let mut all = Vec::new();
    for file in files {
        let mut loaded = load_scenarios_from_file(&file)?;
        all.append(&mut loaded);
    }
    Ok(all)
}

pub fn load_scenarios_from_file(file: &Path) -> Result<Vec<ScenarioSpec>, String> {
    let raw = fs::read_to_string(file)
        .map_err(|e| format!("failed reading scenario file '{}': {e}", file.display()))?;
    let doc = parse_toml_document(&raw)
        .map_err(|e| format!("TOML error in '{}': {e}", file.display()))?;
    let source_name = file
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| file.display().to_string());

    let Some(items) = doc.get("scenario").and_then(TomlValue::as_array) else {
        return Err(format!(
            "scenario file '{}' contains no [[scenario]] entries",
            file.display()
        ));
    };

    let mut out = Vec::with_capacity(items.len());
    for (idx, item) in items.iter().enumerate() {
        let tbl = item
            .as_table()
            .ok_or_else(|| format!("scenario #{idx} in '{}' is not a table", file.display()))?;
        out.push(decode_scenario(tbl, &source_name, idx)?);
    }
    Ok(out)
}

fn decode_scenario(tbl: &TomlTable, source_file: &str, idx: usize) -> Result<ScenarioSpec, String> {
    let id = req_str(tbl, "id", source_file, idx)?;
    let harness_str = req_str(tbl, "harness", source_file, idx)?;
    let harness = HarnessFlavor::parse(&harness_str)?;
    let description = opt_str(tbl, "description").unwrap_or_default();
    let session_id = opt_str(tbl, "session_id").unwrap_or_else(|| format!("sess-{id}"));
    let profile = opt_str(tbl, "profile");

    let mut env = BTreeMap::new();
    if let Some(env_tbl) = tbl.get("env").and_then(TomlValue::as_table) {
        for (k, v) in env_tbl {
            let val = v.as_str().ok_or_else(|| {
                format!("scenario '{id}' in '{source_file}': env.{k} must be a string")
            })?;
            env.insert(k.clone(), val.to_string());
        }
    }

    let mut setup_files = Vec::new();
    if let Some(arr) = tbl.get("setup_files").and_then(TomlValue::as_array) {
        for f_val in arr {
            let f_tbl = f_val.as_table().ok_or_else(|| {
                format!("scenario '{id}': setup_files entry must be an inline table")
            })?;
            let path = req_str(f_tbl, "path", source_file, idx)?;
            let content = req_str(f_tbl, "content", source_file, idx)?;
            setup_files.push(SetupFile { path, content });
        }
    }

    let steps_arr = tbl
        .get("steps")
        .and_then(TomlValue::as_array)
        .ok_or_else(|| format!("scenario '{id}' in '{source_file}' has no [[scenario.steps]]"))?;
    if steps_arr.is_empty() {
        return Err(format!(
            "scenario '{id}' in '{source_file}' must define at least one step"
        ));
    }

    let mut steps = Vec::with_capacity(steps_arr.len());
    for (s_idx, s_val) in steps_arr.iter().enumerate() {
        let s_tbl = s_val
            .as_table()
            .ok_or_else(|| format!("scenario '{id}' step #{s_idx} is not a table"))?;
        steps.push(decode_step(s_tbl, &id, s_idx)?);
    }

    Ok(ScenarioSpec {
        id,
        source_file: source_file.to_string(),
        harness,
        description,
        session_id,
        profile,
        env,
        setup_files,
        steps,
    })
}

fn decode_step(tbl: &TomlTable, scen_id: &str, step_idx: usize) -> Result<ScenarioStep, String> {
    let kind = tbl
        .get("kind")
        .and_then(TomlValue::as_str)
        .ok_or_else(|| format!("scenario '{scen_id}' step #{step_idx} missing 'kind'"))?
        .to_string();
    let name = opt_str(tbl, "name").unwrap_or_else(|| format!("step_{}_{}", step_idx + 1, kind));
    let expect_exit = tbl
        .get("expect_exit")
        .and_then(TomlValue::as_i64)
        .ok_or_else(|| {
            format!("scenario '{scen_id}' step '{name}' missing integer 'expect_exit'")
        })? as i32;

    let mut args = Vec::new();
    if let Some(arr) = tbl.get("args").and_then(TomlValue::as_array) {
        for item in arr {
            let s = item.as_str().ok_or_else(|| {
                format!("scenario '{scen_id}' step '{name}': args must contain strings")
            })?;
            args.push(s.to_string());
        }
    }

    Ok(ScenarioStep {
        name,
        kind,
        tool_name: opt_str(tbl, "tool_name"),
        command: opt_str(tbl, "command"),
        args,
        file_path: opt_str(tbl, "file_path"),
        content: opt_str(tbl, "content"),
        patch: opt_str(tbl, "patch"),
        offset: opt_u64(tbl, "offset"),
        limit: opt_u64(tbl, "limit"),
        start_line: opt_u64(tbl, "start_line"),
        end_line: opt_u64(tbl, "end_line"),
        cwd_override: opt_str(tbl, "cwd_override"),
        tool_cwd: opt_str(tbl, "tool_cwd"),
        url: opt_str(tbl, "url"),
        tool_response: opt_str(tbl, "tool_response"),
        stdin_text: opt_str(tbl, "stdin_text"),
        raw_json: opt_str(tbl, "raw_json"),
        profile_override: opt_str(tbl, "profile"),
        expect_exit,
        expect_decision: opt_str(tbl, "expect_decision"),
        expect_code: opt_str(tbl, "expect_code"),
        expect_advisory_contains: opt_str(tbl, "expect_advisory_contains"),
        expect_updated_input_contains: opt_str(tbl, "expect_updated_input_contains"),
        expect_updated_output_contains: opt_str(tbl, "expect_updated_output_contains"),
        expect_stdout_contains: opt_str(tbl, "expect_stdout_contains"),
        expect_stderr_contains: opt_str(tbl, "expect_stderr_contains"),
        expect_output_ascii_7bit: tbl
            .get("expect_output_ascii_7bit")
            .and_then(TomlValue::as_bool)
            .unwrap_or(false),
    })
}

fn req_str(tbl: &TomlTable, key: &str, source_file: &str, idx: usize) -> Result<String, String> {
    tbl.get(key)
        .and_then(TomlValue::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| {
            format!("scenario #{idx} in '{source_file}' missing required string '{key}'")
        })
}

fn opt_str(tbl: &TomlTable, key: &str) -> Option<String> {
    tbl.get(key)
        .and_then(TomlValue::as_str)
        .map(ToString::to_string)
}

fn opt_u64(tbl: &TomlTable, key: &str) -> Option<u64> {
    tbl.get(key)
        .and_then(TomlValue::as_i64)
        .and_then(|n| u64::try_from(n).ok())
}

pub fn run_scenario(
    spec: &ScenarioSpec,
    workspace_root: &Path,
    agent_guard_bin: &Path,
) -> CaseResult {
    let started = Instant::now();
    let case_id = format!("scenario::{}/{}", spec.harness.as_str(), spec.id);

    let sandbox = match TestSandbox::create(workspace_root, &format!("scen_{}", spec.id)) {
        Ok(sb) => sb,
        Err(e) => {
            return CaseResult::fail(
                case_id,
                "scenarios",
                started.elapsed().as_millis() as u64,
                format!("sandbox init failed: {e}"),
            );
        }
    };

    // Copy runtime profiles into the sandbox repo so AGENT_GUARD_PROFILE resolution
    // exercises real profiles/*.toml tightening rules.
    let profiles_src = workspace_root.join("profiles");
    if profiles_src.is_dir()
        && let Err(e) = crate::sandbox::copy_dir_filtered_bounded(
            &profiles_src,
            &sandbox.repo_dir.join("profiles"),
            0,
            2,
        )
    {
        return CaseResult::fail(
            case_id,
            "scenarios",
            started.elapsed().as_millis() as u64,
            format!("failed seeding profiles: {e}"),
        );
    }

    for file in &spec.setup_files {
        let rendered = expand_placeholders(&file.content, &sandbox);
        if let Err(e) = sandbox.write_repo_file(&file.path, &rendered) {
            return CaseResult::fail(
                case_id,
                "scenarios",
                started.elapsed().as_millis() as u64,
                format!("failed seeding file '{}': {e}", file.path),
            );
        }
    }

    for (idx, step) in spec.steps.iter().enumerate() {
        if let Err(reason) = execute_step(spec, step, idx, &sandbox, agent_guard_bin) {
            return CaseResult::fail(
                case_id,
                "scenarios",
                started.elapsed().as_millis() as u64,
                format!("step #{} ('{}'): {reason}", idx + 1, step.name),
            );
        }
    }

    CaseResult::pass(
        case_id,
        "scenarios",
        started.elapsed().as_millis() as u64,
        format!(
            "{} ({} steps, {})",
            if spec.description.is_empty() {
                &spec.id
            } else {
                &spec.description
            },
            spec.steps.len(),
            spec.source_file
        ),
    )
}

struct InvocationPlan {
    cli_args: Vec<String>,
    stdin_payload: Option<String>,
    is_hook_json: bool,
}

fn execute_step(
    spec: &ScenarioSpec,
    step: &ScenarioStep,
    _idx: usize,
    sandbox: &TestSandbox,
    agent_guard_bin: &Path,
) -> Result<(), String> {
    let plan = build_invocation_plan(spec, step, sandbox)?;

    let mut cmd = Command::new(agent_guard_bin);
    sandbox.configure_isolated_command(&mut cmd);

    if let Some(ref prof) = step.profile_override.as_ref().or(spec.profile.as_ref()) {
        cmd.env("AGENT_GUARD_PROFILE", prof);
    }
    for (k, v) in &spec.env {
        cmd.env(k, expand_placeholders(v, sandbox));
    }

    cmd.args(&plan.cli_args);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    if plan.stdin_payload.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed spawning agent-guard: {e}"))?;
    if let Some(ref body) = plan.stdin_payload
        && let Some(mut stdin_pipe) = child.stdin.take()
    {
        stdin_pipe
            .write_all(body.as_bytes())
            .map_err(|e| format!("failed writing stdin payload: {e}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("failed waiting on agent-guard: {e}"))?;
    let actual_exit = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    if actual_exit != step.expect_exit {
        return Err(format!(
            "expected exit code {}, got {} (stdout={}, stderr={})",
            step.expect_exit,
            actual_exit,
            compact_diag(&stdout),
            compact_diag(&stderr)
        ));
    }

    if step.expect_output_ascii_7bit && !output.stdout.iter().all(|b| *b < 0x80) {
        return Err("stdout contained non-7-bit-ASCII bytes (>= 0x80)".to_string());
    }

    if let Some(ref needle) = step.expect_stdout_contains {
        let exp = expand_placeholders(needle, sandbox);
        if !stdout.contains(&exp) {
            return Err(format!(
                "stdout missing '{exp}' (got: {})",
                compact_diag(&stdout)
            ));
        }
    }

    if let Some(ref needle) = step.expect_stderr_contains {
        let exp = expand_placeholders(needle, sandbox);
        if !stderr.contains(&exp) {
            return Err(format!(
                "stderr missing '{exp}' (got: {})",
                compact_diag(&stderr)
            ));
        }
    }

    if let Some(ref code) = step.expect_code
        && !stdout.contains(code.as_str())
        && !stderr.contains(code.as_str())
    {
        return Err(format!(
            "expected violation/status code '{code}' in stdout or stderr (stdout={}, stderr={})",
            compact_diag(&stdout),
            compact_diag(&stderr)
        ));
    }

    if plan.is_hook_json {
        verify_hook_envelope(step, &stdout, sandbox)?;
    }

    Ok(())
}

fn verify_hook_envelope(
    step: &ScenarioStep,
    stdout: &str,
    sandbox: &TestSandbox,
) -> Result<(), String> {
    let trimmed = stdout.trim();
    let parsed = if trimmed.is_empty() {
        None
    } else {
        Some(JsonValue::parse(trimmed).map_err(|e| {
            format!(
                "hook emitted invalid JSON on stdout: {e} (raw={})",
                compact_diag(trimmed)
            )
        })?)
    };

    if let Some(ref want_dec) = step.expect_decision {
        match want_dec.as_str() {
            "block" | "deny" => {
                let Some(ref root) = parsed else {
                    return Err("expected block JSON envelope on stdout, got empty".to_string());
                };
                let top_dec = root.get("decision").and_then(JsonValue::as_str);
                let perm_dec = root
                    .get("hookSpecificOutput")
                    .and_then(|h| h.get("permissionDecision"))
                    .and_then(JsonValue::as_str);
                if top_dec != Some("block") || perm_dec != Some("deny") {
                    return Err(format!(
                        "expected decision=block & permissionDecision=deny, got {}",
                        compact_diag(trimmed)
                    ));
                }
            }
            "allow" => {
                if let Some(ref root) = parsed {
                    if root.get("decision").and_then(JsonValue::as_str) == Some("block") {
                        return Err(format!(
                            "expected allow decision, got block JSON: {}",
                            compact_diag(trimmed)
                        ));
                    }
                    if let Some(perm) = root
                        .get("hookSpecificOutput")
                        .and_then(|h| h.get("permissionDecision"))
                        .and_then(JsonValue::as_str)
                        && perm != "allow"
                    {
                        return Err(format!("expected permissionDecision=allow, got '{perm}'"));
                    }
                }
            }
            other => {
                return Err(format!(
                    "unsupported expect_decision '{other}' (expected allow|block)"
                ));
            }
        }
    }

    if let Some(ref needle) = step.expect_advisory_contains {
        let exp = expand_placeholders(needle, sandbox);
        let adv = parsed
            .as_ref()
            .and_then(|r| r.get("hookSpecificOutput"))
            .and_then(|h| h.get("additionalContext"))
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        if !adv.contains(&exp) {
            return Err(format!(
                "hookSpecificOutput.additionalContext missing '{exp}' (got '{}')",
                compact_diag(adv)
            ));
        }
    }

    if let Some(ref needle) = step.expect_updated_input_contains {
        let exp = expand_placeholders(needle, sandbox);
        let upd = parsed
            .as_ref()
            .and_then(|r| r.get("hookSpecificOutput"))
            .and_then(|h| h.get("updatedInput"))
            .map(JsonValue::to_json_string)
            .unwrap_or_default();
        if !upd.contains(&exp) {
            return Err(format!(
                "hookSpecificOutput.updatedInput missing '{exp}' (got '{}')",
                compact_diag(&upd)
            ));
        }
    }

    if let Some(ref needle) = step.expect_updated_output_contains {
        let exp = expand_placeholders(needle, sandbox);
        let upd = parsed
            .as_ref()
            .and_then(|r| r.get("hookSpecificOutput"))
            .and_then(|h| h.get("updatedMCPToolOutput"))
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        if !upd.contains(&exp) {
            return Err(format!(
                "hookSpecificOutput.updatedMCPToolOutput missing '{exp}' (got '{}')",
                compact_diag(upd)
            ));
        }
    }

    Ok(())
}

fn build_invocation_plan(
    spec: &ScenarioSpec,
    step: &ScenarioStep,
    sandbox: &TestSandbox,
) -> Result<InvocationPlan, String> {
    if let Some(ref raw) = step.raw_json {
        let sub = match step.kind.as_str() {
            "user_prompt" | "before_agent" | "before_submit_prompt" => "user-prompt",
            "pre_tool"
            | "before_tool"
            | "before_shell_execution"
            | "before_read_file"
            | "before_mcp_execution"
            | "apply_patch" => "pre-tool",
            "post_tool" | "after_tool" => "post-tool",
            "pre_compact" | "pre_compress" => "pre-compact",
            other => {
                return Err(format!("raw_json unsupported for step kind '{other}'"));
            }
        };
        return Ok(InvocationPlan {
            cli_args: vec![sub.to_string()],
            stdin_payload: Some(expand_placeholders(raw, sandbox)),
            is_hook_json: true,
        });
    }

    let claimed_cwd = step
        .cwd_override
        .as_deref()
        .map(|s| expand_placeholders(s, sandbox))
        .unwrap_or_else(|| sandbox.repo_dir.to_string_lossy().into_owned());

    match (spec.harness, step.kind.as_str()) {
        // --- User Prompt / Turn Reset Hooks ---
        (HarnessFlavor::Claude, "user_prompt")
        | (HarnessFlavor::Codex, "user_prompt")
        | (HarnessFlavor::Cli, "user_prompt") => {
            let payload = JsonValue::Object(vec![
                (
                    "session_id".to_string(),
                    JsonValue::Str(spec.session_id.clone()),
                ),
                ("cwd".to_string(), JsonValue::Str(claimed_cwd)),
                (
                    "hook_event_name".to_string(),
                    JsonValue::Str("UserPromptSubmit".to_string()),
                ),
                (
                    "prompt".to_string(),
                    JsonValue::Str(
                        step.content
                            .clone()
                            .unwrap_or_else(|| "Run task cleanly.".to_string()),
                    ),
                ),
            ]);
            Ok(InvocationPlan {
                cli_args: vec!["user-prompt".to_string()],
                stdin_payload: Some(payload.to_json_string()),
                is_hook_json: true,
            })
        }
        (HarnessFlavor::Gemini, "before_agent" | "user_prompt") => {
            let payload = JsonValue::Object(vec![
                (
                    "session_id".to_string(),
                    JsonValue::Str(spec.session_id.clone()),
                ),
                ("cwd".to_string(), JsonValue::Str(claimed_cwd)),
                (
                    "hook_event_name".to_string(),
                    JsonValue::Str("BeforeAgent".to_string()),
                ),
            ]);
            Ok(InvocationPlan {
                cli_args: vec!["user-prompt".to_string()],
                stdin_payload: Some(payload.to_json_string()),
                is_hook_json: true,
            })
        }
        (HarnessFlavor::Cursor, "before_submit_prompt" | "user_prompt") => {
            let payload = JsonValue::Object(vec![
                (
                    "conversation_id".to_string(),
                    JsonValue::Str(spec.session_id.clone()),
                ),
                (
                    "workspace_roots".to_string(),
                    JsonValue::Array(vec![JsonValue::Str(claimed_cwd)]),
                ),
                (
                    "hook_event_name".to_string(),
                    JsonValue::Str("beforeSubmitPrompt".to_string()),
                ),
            ]);
            Ok(InvocationPlan {
                cli_args: vec!["user-prompt".to_string()],
                stdin_payload: Some(payload.to_json_string()),
                is_hook_json: true,
            })
        }

        // --- PreToolUse / BeforeTool Hooks ---
        (HarnessFlavor::Claude, "pre_tool") => {
            let tool = step.tool_name.clone().unwrap_or_else(|| "Bash".to_string());
            let tool_input = build_tool_input_object(HarnessFlavor::Claude, step, sandbox);
            let payload = JsonValue::Object(vec![
                (
                    "session_id".to_string(),
                    JsonValue::Str(spec.session_id.clone()),
                ),
                ("cwd".to_string(), JsonValue::Str(claimed_cwd)),
                (
                    "hook_event_name".to_string(),
                    JsonValue::Str("PreToolUse".to_string()),
                ),
                ("tool_name".to_string(), JsonValue::Str(tool)),
                ("tool_input".to_string(), tool_input),
            ]);
            Ok(InvocationPlan {
                cli_args: vec!["pre-tool".to_string()],
                stdin_payload: Some(payload.to_json_string()),
                is_hook_json: true,
            })
        }
        (HarnessFlavor::Gemini, "before_tool" | "pre_tool") => {
            let tool = step
                .tool_name
                .clone()
                .unwrap_or_else(|| "view_file".to_string());
            let tool_input = build_tool_input_object(HarnessFlavor::Gemini, step, sandbox);
            let payload = JsonValue::Object(vec![
                (
                    "session_id".to_string(),
                    JsonValue::Str(spec.session_id.clone()),
                ),
                ("cwd".to_string(), JsonValue::Str(claimed_cwd)),
                (
                    "hook_event_name".to_string(),
                    JsonValue::Str("BeforeTool".to_string()),
                ),
                ("tool_name".to_string(), JsonValue::Str(tool)),
                ("tool_input".to_string(), tool_input),
            ]);
            Ok(InvocationPlan {
                cli_args: vec!["pre-tool".to_string()],
                stdin_payload: Some(payload.to_json_string()),
                is_hook_json: true,
            })
        }
        (HarnessFlavor::Cursor, "before_shell_execution") => {
            let cmd_str = expand_opt(&step.command, sandbox).unwrap_or_default();
            let payload = JsonValue::Object(vec![
                (
                    "conversation_id".to_string(),
                    JsonValue::Str(spec.session_id.clone()),
                ),
                (
                    "workspace_roots".to_string(),
                    JsonValue::Array(vec![JsonValue::Str(claimed_cwd)]),
                ),
                (
                    "hook_event_name".to_string(),
                    JsonValue::Str("beforeShellExecution".to_string()),
                ),
                ("command".to_string(), JsonValue::Str(cmd_str)),
            ]);
            Ok(InvocationPlan {
                cli_args: vec!["pre-tool".to_string()],
                stdin_payload: Some(payload.to_json_string()),
                is_hook_json: true,
            })
        }
        (HarnessFlavor::Cursor, "before_read_file") => {
            let file_str = expand_opt(&step.file_path, sandbox).unwrap_or_default();
            let payload = JsonValue::Object(vec![
                (
                    "conversation_id".to_string(),
                    JsonValue::Str(spec.session_id.clone()),
                ),
                (
                    "workspace_roots".to_string(),
                    JsonValue::Array(vec![JsonValue::Str(claimed_cwd)]),
                ),
                (
                    "hook_event_name".to_string(),
                    JsonValue::Str("beforeReadFile".to_string()),
                ),
                ("file_path".to_string(), JsonValue::Str(file_str)),
            ]);
            Ok(InvocationPlan {
                cli_args: vec!["pre-tool".to_string()],
                stdin_payload: Some(payload.to_json_string()),
                is_hook_json: true,
            })
        }
        (HarnessFlavor::Cursor, "before_mcp_execution") => {
            let tool = step
                .tool_name
                .clone()
                .unwrap_or_else(|| "mcp__susanbdev__ping".to_string());
            let payload = JsonValue::Object(vec![
                (
                    "conversation_id".to_string(),
                    JsonValue::Str(spec.session_id.clone()),
                ),
                (
                    "workspace_roots".to_string(),
                    JsonValue::Array(vec![JsonValue::Str(claimed_cwd)]),
                ),
                (
                    "hook_event_name".to_string(),
                    JsonValue::Str("beforeMCPExecution".to_string()),
                ),
                ("tool_name".to_string(), JsonValue::Str(tool)),
                (
                    "tool_input".to_string(),
                    build_tool_input_object(HarnessFlavor::Cursor, step, sandbox),
                ),
            ]);
            Ok(InvocationPlan {
                cli_args: vec!["pre-tool".to_string()],
                stdin_payload: Some(payload.to_json_string()),
                is_hook_json: true,
            })
        }
        (HarnessFlavor::Codex, "apply_patch" | "pre_tool") => {
            let tool = step
                .tool_name
                .clone()
                .unwrap_or_else(|| "apply_patch".to_string());
            let payload = JsonValue::Object(vec![
                (
                    "session_id".to_string(),
                    JsonValue::Str(spec.session_id.clone()),
                ),
                ("cwd".to_string(), JsonValue::Str(claimed_cwd)),
                ("tool_name".to_string(), JsonValue::Str(tool)),
                (
                    "tool_input".to_string(),
                    build_tool_input_object(HarnessFlavor::Codex, step, sandbox),
                ),
            ]);
            Ok(InvocationPlan {
                cli_args: vec!["pre-tool".to_string()],
                stdin_payload: Some(payload.to_json_string()),
                is_hook_json: true,
            })
        }

        // --- PostToolUse / AfterTool Hooks ---
        (HarnessFlavor::Claude, "post_tool") => {
            let tool = step.tool_name.clone().unwrap_or_else(|| "Bash".to_string());
            let resp = expand_opt(&step.tool_response, sandbox).unwrap_or_default();
            let payload = JsonValue::Object(vec![
                (
                    "session_id".to_string(),
                    JsonValue::Str(spec.session_id.clone()),
                ),
                ("cwd".to_string(), JsonValue::Str(claimed_cwd)),
                (
                    "hook_event_name".to_string(),
                    JsonValue::Str("PostToolUse".to_string()),
                ),
                ("tool_name".to_string(), JsonValue::Str(tool)),
                ("tool_response".to_string(), JsonValue::Str(resp)),
            ]);
            Ok(InvocationPlan {
                cli_args: vec!["post-tool".to_string()],
                stdin_payload: Some(payload.to_json_string()),
                is_hook_json: true,
            })
        }
        (HarnessFlavor::Gemini, "after_tool" | "post_tool") => {
            let tool = step
                .tool_name
                .clone()
                .unwrap_or_else(|| "run_command".to_string());
            let resp = expand_opt(&step.tool_response, sandbox).unwrap_or_default();
            let payload = JsonValue::Object(vec![
                (
                    "session_id".to_string(),
                    JsonValue::Str(spec.session_id.clone()),
                ),
                ("cwd".to_string(), JsonValue::Str(claimed_cwd)),
                (
                    "hook_event_name".to_string(),
                    JsonValue::Str("AfterTool".to_string()),
                ),
                ("tool_name".to_string(), JsonValue::Str(tool)),
                ("tool_output".to_string(), JsonValue::Str(resp)),
            ]);
            Ok(InvocationPlan {
                cli_args: vec!["post-tool".to_string()],
                stdin_payload: Some(payload.to_json_string()),
                is_hook_json: true,
            })
        }

        // --- PreCompact / PreCompress Hooks ---
        (_, "pre_compact" | "pre_compress") => {
            let event_name = if spec.harness == HarnessFlavor::Gemini {
                "PreCompress"
            } else {
                "PreCompact"
            };
            let payload = JsonValue::Object(vec![
                (
                    "session_id".to_string(),
                    JsonValue::Str(spec.session_id.clone()),
                ),
                ("cwd".to_string(), JsonValue::Str(claimed_cwd)),
                (
                    "hook_event_name".to_string(),
                    JsonValue::Str(event_name.to_string()),
                ),
            ]);
            Ok(InvocationPlan {
                cli_args: vec!["pre-compact".to_string()],
                stdin_payload: Some(payload.to_json_string()),
                is_hook_json: true,
            })
        }

        // --- Stop / Notify Hooks ---
        (_, "on_stop" | "after_agent" | "stop" | "notify_stop") => Ok(InvocationPlan {
            cli_args: vec!["on-stop".to_string()],
            stdin_payload: None,
            is_hook_json: false,
        }),

        // --- Direct CLI Subcommands & Codex Sandbox ---
        (_, "exec_sandbox") => {
            let mut cli_args = vec![
                "exec-sandbox".to_string(),
                "--sanitize-stream".to_string(),
                "--cwd".to_string(),
                claimed_cwd,
                "--".to_string(),
            ];
            if step.args.is_empty() {
                return Err("exec_sandbox step requires non-empty 'args = [...]'".to_string());
            }
            for a in &step.args {
                cli_args.push(expand_placeholders(a, sandbox));
            }
            Ok(InvocationPlan {
                cli_args,
                stdin_payload: None,
                is_hook_json: false,
            })
        }
        (_, "check_cmd") => {
            let c = expand_opt(&step.command, sandbox)
                .ok_or_else(|| "check_cmd step requires 'command'".to_string())?;
            Ok(InvocationPlan {
                cli_args: vec!["check-cmd".to_string(), c],
                stdin_payload: None,
                is_hook_json: false,
            })
        }
        (_, "check_path_read") => {
            let p = expand_opt(&step.file_path, sandbox)
                .ok_or_else(|| "check_path_read requires 'file_path'".to_string())?;
            Ok(InvocationPlan {
                cli_args: vec!["check-path".to_string(), p],
                stdin_payload: None,
                is_hook_json: false,
            })
        }
        (_, "check_path_write") => {
            let p = expand_opt(&step.file_path, sandbox)
                .ok_or_else(|| "check_path_write requires 'file_path'".to_string())?;
            Ok(InvocationPlan {
                cli_args: vec!["check-path".to_string(), p, "--write".to_string()],
                stdin_payload: None,
                is_hook_json: false,
            })
        }
        (_, "read_safe") => {
            let p = expand_opt(&step.file_path, sandbox)
                .ok_or_else(|| "read_safe requires 'file_path'".to_string())?;
            let mut cli_args = vec!["read-safe".to_string(), p];
            if let Some(off) = step.offset {
                cli_args.push("--offset".to_string());
                cli_args.push(off.to_string());
            }
            if let Some(lim) = step.limit {
                cli_args.push("--limit".to_string());
                cli_args.push(lim.to_string());
            }
            Ok(InvocationPlan {
                cli_args,
                stdin_payload: None,
                is_hook_json: false,
            })
        }
        (_, "post_edit") => {
            let p = expand_opt(&step.file_path, sandbox)
                .ok_or_else(|| "post_edit requires 'file_path'".to_string())?;
            Ok(InvocationPlan {
                cli_args: vec!["post-edit".to_string(), p],
                stdin_payload: None,
                is_hook_json: false,
            })
        }
        (_, "scan_file") => {
            let p = expand_opt(&step.file_path, sandbox)
                .ok_or_else(|| "scan_file requires 'file_path'".to_string())?;
            Ok(InvocationPlan {
                cli_args: vec!["scan-file".to_string(), p],
                stdin_payload: None,
                is_hook_json: false,
            })
        }
        (_, "sanitize_stream") => Ok(InvocationPlan {
            cli_args: vec!["sanitize-stream".to_string()],
            stdin_payload: Some(expand_opt(&step.stdin_text, sandbox).unwrap_or_default()),
            is_hook_json: false,
        }),
        (_, "audit_repo") => {
            let target = expand_opt(&step.file_path, sandbox).unwrap_or(claimed_cwd);
            Ok(InvocationPlan {
                cli_args: vec!["audit-repo".to_string(), target],
                stdin_payload: None,
                is_hook_json: false,
            })
        }
        (_, "sandbox_status") => Ok(InvocationPlan {
            cli_args: vec!["sandbox-status".to_string()],
            stdin_payload: None,
            is_hook_json: false,
        }),
        (flavor, other) => Err(format!(
            "unsupported step kind '{other}' for harness '{}'",
            flavor.as_str()
        )),
    }
}

fn build_tool_input_object(
    flavor: HarnessFlavor,
    step: &ScenarioStep,
    sandbox: &TestSandbox,
) -> JsonValue {
    let mut fields = Vec::new();
    let is_gemini = flavor == HarnessFlavor::Gemini;

    if let Some(cmd_str) = expand_opt(&step.command, sandbox) {
        let key = if is_gemini { "CommandLine" } else { "command" };
        fields.push((key.to_string(), JsonValue::Str(cmd_str)));
    }
    if let Some(tcwd) = expand_opt(&step.tool_cwd, sandbox) {
        let key = if is_gemini { "Cwd" } else { "cwd" };
        fields.push((key.to_string(), JsonValue::Str(tcwd)));
    }
    if let Some(fp) = expand_opt(&step.file_path, sandbox) {
        let tool_lower = step.tool_name.as_deref().unwrap_or("").to_ascii_lowercase();
        let key = if is_gemini
            && matches!(
                tool_lower.as_str(),
                "write_to_file" | "replace_file_content"
            ) {
            "TargetFile"
        } else if is_gemini {
            "AbsolutePath"
        } else {
            "file_path"
        };
        fields.push((key.to_string(), JsonValue::Str(fp)));
    }
    if let Some(body) = expand_opt(&step.content, sandbox) {
        let key = if is_gemini { "CodeContent" } else { "content" };
        fields.push((key.to_string(), JsonValue::Str(body)));
    }
    if let Some(patch) = expand_opt(&step.patch, sandbox) {
        fields.push(("patch".to_string(), JsonValue::Str(patch)));
    }
    if let Some(url) = expand_opt(&step.url, sandbox) {
        fields.push(("url".to_string(), JsonValue::Str(url)));
    }
    if let Some(off) = step.offset {
        fields.push(("offset".to_string(), JsonValue::Number(off as f64)));
    }
    if let Some(lim) = step.limit {
        fields.push(("limit".to_string(), JsonValue::Number(lim as f64)));
    }
    if let Some(sl) = step.start_line {
        fields.push(("StartLine".to_string(), JsonValue::Number(sl as f64)));
    }
    if let Some(el) = step.end_line {
        fields.push(("EndLine".to_string(), JsonValue::Number(el as f64)));
    }

    JsonValue::Object(fields)
}

fn expand_opt(opt: &Option<String>, sandbox: &TestSandbox) -> Option<String> {
    opt.as_deref().map(|s| expand_placeholders(s, sandbox))
}

pub fn expand_placeholders(raw: &str, sandbox: &TestSandbox) -> String {
    let rlo = char::from_u32(0x2000 + 0x2E)
        .expect("RLO scalar")
        .to_string();
    let esc = char::from_u32(27).expect("ESC scalar").to_string();
    raw.replace("{{REPO_ROOT}}", &sandbox.repo_dir.to_string_lossy())
        .replace(
            "{{SIBLING_REPO}}",
            &sandbox.sibling_repo_dir.to_string_lossy(),
        )
        .replace("{{STATE_DIR}}", &sandbox.state_dir.to_string_lossy())
        .replace("{{TEST_BIDI_RLO}}", &rlo)
        .replace("{{TEST_ESC}}", &esc)
}

fn compact_diag(s: &str) -> String {
    let single = s.replace('\n', "\\n").replace('\r', "\\r");
    if single.len() <= 220 {
        single
    } else {
        let mut end = 220;
        while end > 0 && !single.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...(truncated)", &single[..end])
    }
}
