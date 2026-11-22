//! Translation for Google's native Antigravity workspace hooks.
//!
//! Hook errors are ignored by the host. Enforcement events always emit a valid JSON
//! response and exit successfully, including when the request or guard state is invalid.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::cli::{read_bounded_hook_stdin, verify_stop_repository};
use crate::exec_sandbox::{
    is_canonical_exec_sandbox_wrapper, shell_quote_single, wrap_bash_with_exec_sandbox_session,
};
use crate::json::JsonValue;
use crate::path_policy::{MAX_DIRECTORY_WALK_DEPTH, PathAccess, validate_path};
use crate::traversal_ledger::{SessionLedger, append_audit_jsonl, audit_ascii};
use crate::{
    Decision, HookCallerContext, evaluate_pre_tool_payload, find_first_unicode_violation_in_json,
    resolve_repo_root,
};

#[derive(Clone, Copy)]
enum Event {
    SessionStart,
    PreToolUse,
    PostToolUse,
    PreInvocation,
    PostInvocation,
    Stop,
}

impl Event {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "SessionStart" => Self::SessionStart,
            "PreToolUse" => Self::PreToolUse,
            "PostToolUse" => Self::PostToolUse,
            "PreInvocation" => Self::PreInvocation,
            "PostInvocation" => Self::PostInvocation,
            "Stop" => Self::Stop,
            _ => return None,
        })
    }

    fn reject(self, reason: &str) -> JsonValue {
        match self {
            Self::PreToolUse => deny(reason),
            Self::PreInvocation | Self::PostInvocation => object([
                ("terminationBehavior", text("terminate")),
                (
                    "injectSteps",
                    JsonValue::Array(vec![object([(
                        "errorMessage",
                        object([("userMessage", text(reason))]),
                    )])]),
                ),
            ]),
            Self::Stop => object([("decision", text("stop"))]),
            Self::SessionStart | Self::PostToolUse => object([]),
        }
    }
}

struct ToolCall<'a> {
    name: &'a str,
    args: &'a JsonValue,
    step: u64,
}

enum Request<'a> {
    SessionStart,
    PreTool(ToolCall<'a>),
    PostTool { call: ToolCall<'a>, failed: bool },
    Invocation,
    Stop { fully_idle: bool },
}

fn text(value: impl Into<String>) -> JsonValue {
    JsonValue::Str(value.into())
}

fn object<const N: usize>(fields: [(&str, JsonValue); N]) -> JsonValue {
    JsonValue::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn deny(reason: &str) -> JsonValue {
    object([("decision", text("deny")), ("reason", text(reason))])
}

pub(crate) fn run_cli(args: &[String]) -> ExitCode {
    let event = args.first().and_then(|name| Event::parse(name));
    let result = match (event, args) {
        (Some(event), [_, flag, root]) if flag == "--workspace" => run(event, Path::new(root)),
        _ => Err("Expected a supported Antigravity event and --workspace PATH.".to_owned()),
    };
    let reply = match result {
        Ok(reply) => reply,
        Err(error) => {
            let reason = format!("[DOTAGENT ANTIGRAVITY] {}", audit_ascii(&error, 1024));
            eprintln!("{reason}");
            event.unwrap_or(Event::PreToolUse).reject(&reason)
        }
    };
    println!("{}", reply.to_json_string());
    ExitCode::SUCCESS
}

fn run(event: Event, pinned: &Path) -> Result<JsonValue, String> {
    let raw = read_bounded_hook_stdin()?;
    let payload =
        JsonValue::parse(&raw).map_err(|_| "Malformed Antigravity hook JSON.".to_owned())?;
    let workspace = validate_envelope(&payload, pinned)?;
    let sid = required_string(&payload, "conversationId")?;
    if !is_conversation_uuid(sid) {
        return Err("conversationId must be a UUID.".to_owned());
    }
    let sid = sid.to_ascii_lowercase();

    match parse_request(event, &payload)? {
        Request::SessionStart => {
            with_ledger(&workspace, &sid, |ledger| ledger.save_locked(&workspace))?;
            Ok(object([]))
        }
        Request::PreTool(call) => pre_tool(call, &workspace, &sid),
        Request::PostTool { call, failed } => {
            // The host provides only the proposed call and a status/error, never tool output.
            append_audit_jsonl(
                &workspace,
                &sid,
                "Antigravity.PostToolUse",
                "ANTIGRAVITY_TOOL_OBSERVED",
                &format!("tool={} step={} failed={failed}", call.name, call.step),
                false,
            );
            Ok(object([]))
        }
        Request::Invocation => {
            // An invocation can be an automatic re-entry. It cannot reset a halted turn.
            with_ledger(&workspace, &sid, check_halted)?;
            Ok(object([]))
        }
        Request::Stop { fully_idle } => {
            if fully_idle {
                let verified = with_ledger(&workspace, &sid, check_halted).and_then(|()| {
                    verify_stop_repository(&workspace).map_err(|errors| errors.join("; "))
                });
                let code = if verified.is_ok() {
                    "ANTIGRAVITY_STOP_VERIFIED"
                } else {
                    "ANTIGRAVITY_STOP_VERIFICATION_FAILED"
                };
                append_audit_jsonl(&workspace, &sid, "Antigravity.Stop", code, "", false);
                verified?;
            }
            Ok(object([("decision", text("stop"))]))
        }
    }
}

fn validate_envelope(payload: &JsonValue, pinned: &Path) -> Result<PathBuf, String> {
    if payload.as_object().is_none() {
        return Err("Antigravity hook envelope must be an object.".to_owned());
    }
    for key in [
        "transcriptPath",
        "artifactDirectoryPath",
        "modelName",
        "lastUserInput",
    ] {
        if payload
            .get(key)
            .is_some_and(|value| value.as_str().is_none())
        {
            return Err(format!("{key} must be a string when present."));
        }
    }
    let Some([reported]) = payload.get("workspacePaths").and_then(JsonValue::as_array) else {
        return Err("Exactly one workspacePaths entry is required.".to_owned());
    };
    let Some(reported) = reported.as_str().map(Path::new) else {
        return Err("workspacePaths must contain an absolute directory string.".to_owned());
    };
    // The literal argument is installed by the operator. The payload never chooses the root,
    // and the child process's initial working directory does not select a different repository.
    if !pinned.is_absolute() || pinned != reported {
        return Err("The hook workspace does not match the installed workspace pin.".to_owned());
    }
    let resolved = fs::canonicalize(pinned)
        .map_err(|_| "Cannot resolve the installed workspace.".to_owned())?;
    if resolved != pinned || !resolved.is_dir() || resolve_repo_root(&resolved) != resolved {
        return Err("The workspace pin must identify a real, canonical workspace root.".to_owned());
    }
    Ok(resolved)
}

fn parse_request(event: Event, payload: &JsonValue) -> Result<Request<'_>, String> {
    match event {
        Event::SessionStart => Ok(Request::SessionStart),
        Event::PreToolUse => Ok(Request::PreTool(parse_tool(payload)?)),
        Event::PostToolUse => Ok(Request::PostTool {
            call: parse_tool(payload)?,
            failed: !optional_error(payload)?.is_empty(),
        }),
        Event::PreInvocation | Event::PostInvocation => {
            required_integer(payload, "invocationNum")?;
            required_integer(payload, "initialNumSteps")?;
            Ok(Request::Invocation)
        }
        Event::Stop => {
            required_integer(payload, "executionNum")?;
            required_string(payload, "terminationReason")?;
            optional_error(payload)?;
            let fully_idle = payload
                .get("fullyIdle")
                .and_then(JsonValue::as_bool)
                .ok_or_else(|| "fullyIdle must be a boolean.".to_owned())?;
            Ok(Request::Stop { fully_idle })
        }
    }
}

fn parse_tool(payload: &JsonValue) -> Result<ToolCall<'_>, String> {
    let call = payload
        .get("toolCall")
        .ok_or_else(|| "Missing toolCall.".to_owned())?;
    let name = required_string(call, "name")?;
    if name.len() > 128 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err("Invalid native tool name.".to_owned());
    }
    let args = call
        .get("args")
        .filter(|args| args.as_object().is_some())
        .ok_or_else(|| "toolCall.args must be an object.".to_owned())?;
    Ok(ToolCall {
        name,
        args,
        step: required_integer(payload, "stepIdx")?,
    })
}

fn required_string<'a>(object: &'a JsonValue, field: &str) -> Result<&'a str, String> {
    object
        .get(field)
        .and_then(JsonValue::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{field} must be a nonempty string."))
}

fn required_integer(object: &JsonValue, field: &str) -> Result<u64, String> {
    match object.get(field) {
        Some(JsonValue::Uint(value)) => Ok(*value),
        Some(JsonValue::Int(value)) if *value >= 0 => Ok(*value as u64),
        _ => Err(format!("{field} must be a nonnegative integer.")),
    }
}

fn optional_error(object: &JsonValue) -> Result<&str, String> {
    match object.get("error") {
        None => Ok(""),
        Some(JsonValue::Str(error)) => Ok(error),
        Some(_) => Err("error must be a string when present.".to_owned()),
    }
}

fn is_conversation_uuid(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn with_ledger<T>(
    workspace: &Path,
    sid: &str,
    action: impl FnOnce(&SessionLedger) -> Result<T, String>,
) -> Result<T, String> {
    let _lock = SessionLedger::acquire_lock(workspace, sid)
        .ok_or_else(|| "Cannot lock the active session ledger.".to_owned())?;
    let ledger = SessionLedger::load_or_create(workspace, sid);
    action(&ledger)
}

fn check_halted(ledger: &SessionLedger) -> Result<(), String> {
    if ledger.halted {
        return Err(format!(
            "SESSION_CIRCUIT_BREAKER_HALTED: {}",
            ledger
                .halt_reason
                .as_deref()
                .unwrap_or("circuit breaker tripped")
        ));
    }
    Ok(())
}

fn native_args(call: &ToolCall<'_>, workspace: &Path) -> Result<JsonValue, String> {
    let args = call.args;
    if let Some(violation) = find_first_unicode_violation_in_json(args) {
        return Err(format!("{}: {}", violation.code, violation.detail));
    }
    match call.name {
        "run_command" => {
            require_arg_keys(args, &["CommandLine", "Cwd", "WaitMsBeforeAsync"])?;
            required_string(args, "CommandLine")?;
            if args.get("Cwd").is_some() {
                absolute_arg(args, "Cwd")?;
            }
            if args.get("WaitMsBeforeAsync").is_some() {
                required_integer(args, "WaitMsBeforeAsync")?;
            }
        }
        "view_file" => {
            require_arg_keys(args, &["AbsolutePath", "StartLine", "EndLine"])?;
            absolute_arg(args, "AbsolutePath")?;
            // Google's table does not specify how slice indices are interpreted. Only
            // authorize when the complete file satisfies the canonical pre-ingestion gate.
            for key in ["StartLine", "EndLine"] {
                if args.get(key).is_some() {
                    required_integer(args, key)?;
                }
            }
            let path = required_string(args, "AbsolutePath")?;
            return Ok(object([("AbsolutePath", text(path))]));
        }
        "write_to_file" | "replace_file_content" | "multi_replace_file_content" => {
            absolute_arg(args, "TargetFile")?;
            if args
                .get("IsArtifact")
                .is_some_and(|value| value.as_bool() != Some(false))
            {
                return Err(
                    "Artifact-directory writes are outside the pinned workspace contract."
                        .to_owned(),
                );
            }
        }
        "list_dir" => {
            require_arg_keys(args, &["DirectoryPath"])?;
            absolute_arg(args, "DirectoryPath")?;
        }
        "find_by_name" => {
            require_arg_keys(
                args,
                &[
                    "SearchDirectory",
                    "Pattern",
                    "MaxDepth",
                    "Type",
                    "Excludes",
                    "Extensions",
                    "FullPath",
                ],
            )?;
            absolute_arg(args, "SearchDirectory")?;
            required_string(args, "Pattern")?;
            let depth = required_integer(args, "MaxDepth")?;
            if depth == 0 || depth > MAX_DIRECTORY_WALK_DEPTH as u64 {
                return Err("find_by_name requires an explicit, bounded MaxDepth.".to_owned());
            }
            let Some(fields) = args.as_object() else {
                return Err("Expected tool arguments.".to_owned());
            };
            return Ok(JsonValue::Object(
                fields
                    .iter()
                    .map(|(name, value)| {
                        let key = if name == "SearchDirectory" {
                            "DirectoryPath".to_owned()
                        } else {
                            name.clone()
                        };
                        (key, value.clone())
                    })
                    .collect(),
            ));
        }
        "grep_search" => {
            require_arg_keys(
                args,
                &[
                    "SearchPath",
                    "Query",
                    "IsRegex",
                    "CaseInsensitive",
                    "Includes",
                    "MatchPerLine",
                ],
            )?;
            absolute_arg(args, "SearchPath")?;
            required_string(args, "Query")?;
            let path = required_string(args, "SearchPath")?;
            let valid = validate_path(workspace, workspace, path, PathAccess::Read)
                .map_err(|error| format!("{}: {}", error.code, error.detail))?;
            if !valid.canonical_or_norm.is_file() {
                return Err("grep_search requires a regular file because the host has no depth limit field.".to_owned());
            }
        }
        "read_url_content" | "web_search" => {}
        _ if call.name.starts_with("mcp__") => {}
        _ => {
            return Err(format!(
                "UNRECOGNIZED_TOOL_BLOCKED: Unsupported native tool '{}'.",
                call.name
            ));
        }
    }
    Ok(args.clone())
}

fn require_arg_keys(args: &JsonValue, expected: &[&str]) -> Result<(), String> {
    let fields = args
        .as_object()
        .ok_or_else(|| "Expected tool arguments.".to_owned())?;
    if fields
        .iter()
        .any(|(name, _)| !expected.contains(&name.as_str()))
    {
        return Err("Native tool supplied undocumented argument fields.".to_owned());
    }
    Ok(())
}

fn absolute_arg(args: &JsonValue, key: &str) -> Result<(), String> {
    if !Path::new(required_string(args, key)?).is_absolute() {
        return Err(format!("{key} must be an absolute path."));
    }
    Ok(())
}

fn pre_tool(call: ToolCall<'_>, workspace: &Path, sid: &str) -> Result<JsonValue, String> {
    let input = native_args(&call, workspace)?;
    let normalized = object([
        ("session_id", text(sid)),
        ("tool_name", text(call.name)),
        ("tool_input", input),
    ]);
    let mut caller = HookCallerContext::from_env();
    if caller
        .session_id
        .as_deref()
        .is_some_and(|id| !id.trim().is_empty() && id.trim() != sid)
    {
        return Err(
            "The native conversation conflicts with the configured host session identity."
                .to_owned(),
        );
    }
    // A provider conversation identifies its ledger. It does not authenticate a Swarm role.
    caller.session_id = None;
    match evaluate_pre_tool_payload(&normalized, workspace, &caller, None, true) {
        Decision::Deny { code, reason, .. } => {
            Ok(deny(&format!("{code}: {}", audit_ascii(&reason, 1024))))
        }
        Decision::Allow {
            updated_bash_cmd, ..
        } if call.name == "run_command" => {
            let command = updated_bash_cmd
                .as_deref()
                .unwrap_or(required_string(call.args, "CommandLine")?);
            let overwrite = shell_overwrite(command, call.args, workspace, sid)?;
            Ok(object([
                ("decision", text("allow")),
                ("overwrite", overwrite),
            ]))
        }
        Decision::Allow {
            updated_bash_cmd: Some(_),
            ..
        }
        | Decision::Allow {
            updated_input_json: Some(_),
            ..
        } => Err(
            "The guard requires a rewrite outside the verified native tool contract.".to_owned(),
        ),
        Decision::Allow { .. } => Ok(object([("decision", text("allow"))])),
    }
}

fn shell_overwrite(
    command: &str,
    args: &JsonValue,
    workspace: &Path,
    sid: &str,
) -> Result<JsonValue, String> {
    let native = std::env::current_exe()
        .map_err(|_| "Cannot locate the pinned guard executable.".to_owned())?;
    let executable = native
        .to_str()
        .ok_or_else(|| "Unsupported guard executable path.".to_owned())?;
    let cwd = args
        .get("Cwd")
        .and_then(JsonValue::as_str)
        .map(Path::new)
        .unwrap_or(workspace);
    let canonical_cwd = fs::canonicalize(cwd)
        .map_err(|_| "Cannot resolve the tool working directory.".to_owned())?;
    if canonical_cwd != cwd || !cwd.is_dir() || resolve_repo_root(cwd) != workspace {
        return Err(
            "The tool working directory must be a canonical directory in the pinned workspace."
                .to_owned(),
        );
    }
    let cwd = cwd
        .to_str()
        .ok_or_else(|| "Unsupported shell workspace path.".to_owned())?;
    let wrapped;
    let canonical = if is_canonical_exec_sandbox_wrapper(command) {
        command.trim()
    } else {
        wrapped = wrap_bash_with_exec_sandbox_session(command, true, Some(sid));
        &wrapped
    };
    let rest = canonical
        .strip_prefix("agent-guard exec-sandbox --sanitize-stream")
        .ok_or_else(|| {
            "Guard shell rewrite does not use the expected sandbox entry point.".to_owned()
        })?;
    let tail = if rest.starts_with(" --session-id ") {
        let (_, payload) = rest
            .split_once(" -- ")
            .ok_or_else(|| "Invalid guard shell rewrite.".to_owned())?;
        payload
    } else {
        rest.strip_prefix(" -- ")
            .ok_or_else(|| "Invalid guard shell rewrite.".to_owned())?
    };
    let command = format!(
        "{} exec-sandbox --sanitize-stream --require-kernel --cwd {} --session-id {} -- {tail}",
        shell_quote_single(executable),
        shell_quote_single(cwd),
        shell_quote_single(sid)
    );
    Ok(object([("CommandLine", text(command))]))
}
