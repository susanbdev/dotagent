#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! Typed native Google Antigravity hook protocol adapter (`crates/agent-guard/src/antigravity_adapter.rs`).
//!
//! Responsibilities strictly bounded to protocol translation:
//! `Antigravity stdin JSON -> typed normalized request -> authoritative agent-guard engine -> Antigravity stdout JSON`.
//!
//! Two-capability verification boundary:
//! - **Capability 1 -- Rust Security Kernel & Protocol Adapter (`verified`):** Direct CLI and wire-contract
//!   suites verify bounded input (`<= 256 KiB`), strict UTF-8, RFC 7493 duplicate-key-rejecting JSON,
//!   fail-closed `conversationId`/`workspacePaths`/`toolCall` validation, delegation to `handle_pre_tool_hook`,
//!   `handle_post_tool_hook`, `handle_post_edit_with_session`, and `handle_user_prompt_hook`, and exit-`0`
//!   Antigravity decision emission (`allow`, `overwrite`, `deny`, `terminate`, `block`) with diagnostics on `stderr`.
//! - **Capability 2 -- Host Runtime Mediation (`requires observed live tool-call traversal`):** Static
//!   deployment of `.agents/hooks.json` and `agent-guard` never proves runtime protection on its own.
//!   - **Antigravity Remote Agents:** **Not enforced in the tested configuration** (prohibited shell and native
//!     file canary operations executed with zero observed adapter trace records; this proves enforcement did not
//!     occur in the tested session without establishing whether the host failed configuration discovery, omitted
//!     hook dispatch, or intentionally excludes hooks in that execution mode).
//!   - **Local Antigravity IDE / CLI:** **Unverified** until dedicated live host mediation is tested and observed.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use crate::budget_guard::{STEP_SOFT_COMPACT_TOKENS, load_active_profile};
use crate::cmd_policy::{inspect_repo_build_config_traps, inspect_repo_git_config_and_hooks};
use crate::json::JsonValue;
use crate::path_policy::{PathAccess, lexical_normalize, validate_path};
use crate::repo_audit::audit_github_workflows;
use crate::traversal_ledger::{SessionLedger, append_audit_jsonl};
use crate::unicode_guard::{ScanMode, scan_unicode};
use crate::{
    Decision, discover_git_root_from_canon, handle_post_edit_with_session, handle_post_tool_hook,
    handle_pre_tool_hook, handle_user_prompt_hook, resolve_repo_root,
};

/// Maximum raw byte size accepted on stdin for an Antigravity hook payload (256 KiB).
pub const MAX_ANTIGRAVITY_STDIN_BYTES: usize = 262_144;

/// Maximum byte size of an opt-in bounded non-sensitive invocation trace log (256 KiB).
const MAX_TRACE_LOG_BYTES: u64 = 262_144;

/// Documented Antigravity lifecycle events (`https://antigravity.google/docs/hooks/`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntigravityEvent {
    SessionStart,
    PreInvocation,
    PreToolUse,
    PostToolUse,
    PostInvocation,
    Stop,
}

/// Accurate enforcement classification per Antigravity's documented host contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventEnforcementClass {
    /// Initializes session state and may inject system context; cannot block session creation itself.
    SessionBootstrap,
    /// Runs before model call; can terminate execution via `"terminationBehavior": "terminate"`.
    ModelGate,
    /// Primary pre-execution tool gate; enforces `"allow"`, `"deny"`, and top-level arg `"overwrite"`.
    ToolGate,
    /// Observational post-execution callback (`stdout` is `{}`); cannot undo executed side effects or
    /// rewrite tool results, but updates `SessionLedger` / trips circuit breaker for subsequent turns.
    ObservationalStateUpdate,
    /// Runs after model call; can force loop termination via `"terminationBehavior": "terminate"`.
    LoopControlGate,
    /// Runs when loop stops; records stop audit evidence and may request at most 1 bounded continuation.
    StopAuditGate,
}

impl AntigravityEvent {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "SessionStart" | "session-start" => Some(Self::SessionStart),
            "PreInvocation" | "pre-invocation" => Some(Self::PreInvocation),
            "PreToolUse" | "pre-tool" | "pre-tool-use" => Some(Self::PreToolUse),
            "PostToolUse" | "post-tool" | "post-tool-use" => Some(Self::PostToolUse),
            "PostInvocation" | "post-invocation" => Some(Self::PostInvocation),
            "Stop" | "stop" => Some(Self::Stop),
            _ => None,
        }
    }

    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::SessionStart => "SessionStart",
            Self::PreInvocation => "PreInvocation",
            Self::PreToolUse => "PreToolUse",
            Self::PostToolUse => "PostToolUse",
            Self::PostInvocation => "PostInvocation",
            Self::Stop => "Stop",
        }
    }

    pub fn enforcement_class(self) -> EventEnforcementClass {
        match self {
            Self::SessionStart => EventEnforcementClass::SessionBootstrap,
            Self::PreInvocation => EventEnforcementClass::ModelGate,
            Self::PreToolUse => EventEnforcementClass::ToolGate,
            Self::PostToolUse => EventEnforcementClass::ObservationalStateUpdate,
            Self::PostInvocation => EventEnforcementClass::LoopControlGate,
            Self::Stop => EventEnforcementClass::StopAuditGate,
        }
    }
}

/// Deterministic outcome produced by the Antigravity protocol adapter prior to I/O emission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntigravityOutcome {
    pub event: Option<AntigravityEvent>,
    pub enforcement: Option<EventEnforcementClass>,
    pub stdout_json: Option<String>,
    pub stderr_diagnostic: Option<String>,
    pub exit_code: u8,
}

#[derive(Debug, Clone)]
struct CommonEnvelope {
    conversation_id: String,
    selected_workspace: PathBuf,
    repo_root: PathBuf,
    last_user_input: Option<String>,
}

#[derive(Debug, Clone)]
struct NormalizedToolCall {
    name: String,
    args: JsonValue,
    step_idx: Option<u64>,
}

#[derive(Debug, Clone)]
struct AdapterRejection {
    code: &'static str,
    reason: String,
}

impl AdapterRejection {
    fn new(code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }

    fn formatted(&self) -> String {
        format!("[AGENT-GUARD HARD DENY :: {}] {}", self.code, self.reason)
    }
}

/// CLI entrypoint for `agent-guard antigravity-hook <Event> [--workspace <dir>] [--trace-log <path>] [--json <payload>]`.
pub fn run_antigravity_hook_cli(args: &[String], fallback_cwd: &Path) -> ExitCode {
    let Some(event_raw) = args.first().map(String::as_str) else {
        eprintln!(
            "[AGENT-GUARD HARD DENY :: MISSING_LIFECYCLE_EVENT] usage: agent-guard antigravity-hook <SessionStart|PreInvocation|PreToolUse|PostToolUse|PostInvocation|Stop> [--workspace <dir>] [--trace-log <path>] [--json <payload>]"
        );
        return ExitCode::from(2);
    };

    let mut explicit_ws: Option<PathBuf> = None;
    let mut trace_log: Option<PathBuf> = None;
    let mut inline_json: Option<Vec<u8>> = None;
    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--workspace" | "-w" => {
                let Some(w) = args.get(i + 1) else {
                    eprintln!(
                        "[AGENT-GUARD HARD DENY :: INVALID_CLI_ARGS] missing path after --workspace"
                    );
                    return ExitCode::from(2);
                };
                explicit_ws = Some(PathBuf::from(w));
                i += 2;
            }
            "--trace-log" => {
                let Some(tp) = args.get(i + 1) else {
                    eprintln!(
                        "[AGENT-GUARD HARD DENY :: INVALID_CLI_ARGS] missing path after --trace-log"
                    );
                    return ExitCode::from(2);
                };
                trace_log = Some(PathBuf::from(tp));
                i += 2;
            }
            "--json" => {
                let Some(j) = args.get(i + 1) else {
                    eprintln!(
                        "[AGENT-GUARD HARD DENY :: INVALID_CLI_ARGS] missing payload after --json"
                    );
                    return ExitCode::from(2);
                };
                inline_json = Some(j.as_bytes().to_vec());
                i += 2;
            }
            other => {
                eprintln!(
                    "[AGENT-GUARD HARD DENY :: INVALID_CLI_ARGS] unrecognized argument '{other}'"
                );
                return ExitCode::from(2);
            }
        }
    }

    let raw_bytes = match inline_json {
        Some(b) => b,
        None => match read_bounded_stdin_bytes() {
            Ok(b) => b,
            Err(io_err) => {
                let outcome = match AntigravityEvent::parse(event_raw) {
                    Some(ev) => reject_for_event(
                        ev,
                        &AdapterRejection::new("HOOK_STDIN_READ_ERROR", io_err),
                    ),
                    None => AntigravityOutcome {
                        event: None,
                        enforcement: None,
                        stdout_json: None,
                        stderr_diagnostic: Some(format!(
                            "[AGENT-GUARD HARD DENY :: UNSUPPORTED_LIFECYCLE_EVENT] unsupported Antigravity lifecycle event '{event_raw}'"
                        )),
                        exit_code: 2,
                    },
                };
                if let Some(ref tp) = trace_log {
                    record_bounded_invocation_trace(tp, event_raw, &[], &outcome);
                }
                return emit_outcome(outcome);
            }
        },
    };

    let outcome = evaluate_antigravity_hook_bytes(
        event_raw,
        &raw_bytes,
        fallback_cwd,
        explicit_ws.as_deref(),
    );
    if let Some(ref tp) = trace_log {
        record_bounded_invocation_trace(tp, event_raw, &raw_bytes, &outcome);
    }
    emit_outcome(outcome)
}

fn sanitize_trace_tool_name(raw_input: &[u8]) -> Option<String> {
    if raw_input.is_empty() || raw_input.len() > MAX_ANTIGRAVITY_STDIN_BYTES {
        return None;
    }
    let raw_str = std::str::from_utf8(raw_input).ok()?;
    let parsed = JsonValue::parse(raw_str).ok()?;
    let name = parsed
        .get("toolCall")
        .and_then(|tc| tc.get("name"))
        .and_then(JsonValue::as_str)?
        .trim();
    if name.is_empty() || name.len() > 64 {
        return None;
    }
    if name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':' | b'.'))
    {
        Some(name.to_string())
    } else {
        None
    }
}

fn classify_trace_decision(outcome: &AntigravityOutcome) -> (&'static str, bool) {
    if outcome.exit_code != 0 {
        return ("protocol_error", outcome.stdout_json.is_none());
    }
    let Some(ref raw_out) = outcome.stdout_json else {
        return ("protocol_error", false);
    };
    let Ok(parsed) = JsonValue::parse(raw_out) else {
        return ("protocol_error", false);
    };
    if let Some(dec) = parsed.get("decision").and_then(JsonValue::as_str) {
        return match dec {
            "deny" => ("deny", true),
            "block" => ("terminate_or_block", true),
            "allow" if parsed.get("overwrite").is_some() => ("allow_overwrite", true),
            "allow" => ("allow", true),
            _ => ("protocol_error", true),
        };
    }
    if parsed
        .get("terminationBehavior")
        .and_then(JsonValue::as_str)
        == Some("terminate")
    {
        return ("terminate_or_block", true);
    }
    ("allow", true)
}

/// Appends a single bounded, non-sensitive JSONL trace entry when `--trace-log <path>` is configured.
/// Never logs tool arguments, prompts, environment variables, file contents, paths, or secrets, and
/// ignores all I/O errors so authoritative guard decisions and exit codes are never altered.
pub fn record_bounded_invocation_trace(
    trace_path: &Path,
    event_raw: &str,
    raw_input: &[u8],
    outcome: &AntigravityOutcome,
) {
    if !trace_path.is_absolute() {
        return;
    }
    if trace_path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return;
    }
    let trace_str = trace_path.to_string_lossy();
    if is_forbidden_workspace_root(&trace_str) {
        return;
    }
    let Some(parent) = trace_path.parent() else {
        return;
    };
    for anc in parent.ancestors() {
        let Ok(meta) = fs::symlink_metadata(anc) else {
            return;
        };
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            return;
        }
    }
    if let Ok(canon_parent) = fs::canonicalize(parent)
        && is_forbidden_workspace_root(&canon_parent.to_string_lossy())
    {
        return;
    }
    match fs::symlink_metadata(trace_path) {
        Ok(meta) => {
            if meta.file_type().is_symlink()
                || !meta.file_type().is_file()
                || meta.len() >= MAX_TRACE_LOG_BYTES
            {
                return;
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return,
    }

    let now_dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let ts_unix = now_dur.as_secs();
    let ts_nanos = now_dur.as_nanos();
    let pid = std::process::id();
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(b"dotagent.ag.inv.v1\0");
    seed.extend_from_slice(&ts_nanos.to_le_bytes());
    seed.extend_from_slice(&pid.to_le_bytes());
    seed.extend_from_slice(&(raw_input.len() as u64).to_le_bytes());
    seed.extend_from_slice(event_raw.as_bytes());
    let inv_hex = crate::crypto::sha256_hex(&seed);
    let invocation_id = format!("inv_{}", &inv_hex[..16]);

    let event_label = outcome
        .event
        .map(AntigravityEvent::canonical_name)
        .unwrap_or("invalid");
    let tool_val = match sanitize_trace_tool_name(raw_input) {
        Some(t) => JsonValue::Str(t),
        None => JsonValue::Null,
    };
    let (guard_decision, response_serialized) = classify_trace_decision(outcome);

    let line_json = JsonValue::Object(vec![
        (
            "schema".to_string(),
            JsonValue::Str("dotagent.antigravity.invocation.v1".to_string()),
        ),
        ("ts_unix".to_string(), JsonValue::Uint(ts_unix)),
        ("invocation_id".to_string(), JsonValue::Str(invocation_id)),
        ("adapter_entry".to_string(), JsonValue::Bool(true)),
        ("event".to_string(), JsonValue::Str(event_label.to_string())),
        ("tool_name".to_string(), tool_val),
        (
            "guard_decision".to_string(),
            JsonValue::Str(guard_decision.to_string()),
        ),
        (
            "response_serialized".to_string(),
            JsonValue::Bool(response_serialized),
        ),
        (
            "exit_code".to_string(),
            JsonValue::Uint(u64::from(outcome.exit_code)),
        ),
    ])
    .to_json_string();

    let mut opts = fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    if let Ok(mut f) = opts.open(trace_path) {
        let _ = writeln!(f, "{line_json}");
    }
}

fn emit_outcome(outcome: AntigravityOutcome) -> ExitCode {
    if let Some(diag) = outcome.stderr_diagnostic {
        eprintln!("{diag}");
    }
    if let Some(json_line) = outcome.stdout_json {
        println!("{json_line}");
    }
    ExitCode::from(outcome.exit_code)
}

fn read_bounded_stdin_bytes() -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let cap = (MAX_ANTIGRAVITY_STDIN_BYTES as u64).saturating_add(1);
    io::stdin()
        .take(cap)
        .read_to_end(&mut buf)
        .map_err(|e| format!("stdin read error: {e}"))?;
    Ok(buf)
}

/// Evaluates a raw Antigravity hook invocation entirely in-memory (used directly by both CLI and tests).
pub fn evaluate_antigravity_hook_bytes(
    event_raw: &str,
    raw_input: &[u8],
    fallback_cwd: &Path,
    explicit_workspace: Option<&Path>,
) -> AntigravityOutcome {
    let Some(event) = AntigravityEvent::parse(event_raw) else {
        return AntigravityOutcome {
            event: None,
            enforcement: None,
            stdout_json: None,
            stderr_diagnostic: Some(format!(
                "[AGENT-GUARD HARD DENY :: UNSUPPORTED_LIFECYCLE_EVENT] Unsupported Antigravity lifecycle event '{event_raw}' (expected SessionStart|PreInvocation|PreToolUse|PostToolUse|PostInvocation|Stop)."
            )),
            exit_code: 2,
        };
    };

    if raw_input.len() > MAX_ANTIGRAVITY_STDIN_BYTES {
        return reject_for_event(
            event,
            &AdapterRejection::new(
                "HOOK_INPUT_OVERFLOW",
                format!(
                    "Antigravity {} stdin exceeded {MAX_ANTIGRAVITY_STDIN_BYTES} bytes (token/context bomb blocked).",
                    event.canonical_name()
                ),
            ),
        );
    }

    let Ok(raw_json) = std::str::from_utf8(raw_input) else {
        return reject_for_event(
            event,
            &AdapterRejection::new(
                "NON_UTF8_HOOK_INPUT",
                format!(
                    "Antigravity {} stdin contained invalid UTF-8 bytes.",
                    event.canonical_name()
                ),
            ),
        );
    };

    if raw_json.trim().is_empty() {
        return reject_for_event(
            event,
            &AdapterRejection::new(
                "INVALID_HOOK_JSON",
                format!(
                    "Antigravity {} stdin JSON payload is empty.",
                    event.canonical_name()
                ),
            ),
        );
    }

    let parsed = match JsonValue::parse(raw_json) {
        Ok(v) => v,
        Err(e) => {
            return reject_for_event(
                event,
                &AdapterRejection::new(
                    "INVALID_HOOK_JSON",
                    format!(
                        "Malformed Antigravity {} JSON payload: {e}",
                        event.canonical_name()
                    ),
                ),
            );
        }
    };

    if parsed.as_object().is_none() {
        return reject_for_event(
            event,
            &AdapterRejection::new(
                "INVALID_HOOK_JSON",
                format!(
                    "Antigravity {} root JSON payload must be an object.",
                    event.canonical_name()
                ),
            ),
        );
    }

    let common = match parse_and_verify_common_envelope(&parsed, fallback_cwd, explicit_workspace) {
        Ok(c) => c,
        Err(rej) => return reject_for_event(event, &rej),
    };

    match event {
        AntigravityEvent::SessionStart => handle_session_start(&common),
        AntigravityEvent::PreInvocation => handle_pre_invocation(&parsed, &common),
        AntigravityEvent::PreToolUse => handle_pre_tool_use(&parsed, &common),
        AntigravityEvent::PostToolUse => handle_post_tool_use(&parsed, &common),
        AntigravityEvent::PostInvocation => handle_post_invocation(&parsed, &common),
        AntigravityEvent::Stop => handle_stop(&parsed, &common),
    }
}

fn reject_for_event(event: AntigravityEvent, rej: &AdapterRejection) -> AntigravityOutcome {
    let formatted = rej.formatted();
    let stdout_json = match event {
        AntigravityEvent::PreToolUse => JsonValue::Object(vec![
            ("decision".to_string(), JsonValue::Str("deny".to_string())),
            ("reason".to_string(), JsonValue::Str(formatted.clone())),
        ])
        .to_json_string(),
        AntigravityEvent::PreInvocation | AntigravityEvent::PostInvocation => {
            JsonValue::Object(vec![
                (
                    "injectSteps".to_string(),
                    JsonValue::Array(vec![JsonValue::Object(vec![(
                        "errorMessage".to_string(),
                        JsonValue::Object(vec![(
                            "userMessage".to_string(),
                            JsonValue::Str(formatted.clone()),
                        )]),
                    )])]),
                ),
                (
                    "terminationBehavior".to_string(),
                    JsonValue::Str("terminate".to_string()),
                ),
            ])
            .to_json_string()
        }
        AntigravityEvent::SessionStart => JsonValue::Object(vec![(
            "injectSteps".to_string(),
            JsonValue::Array(vec![JsonValue::Object(vec![(
                "errorMessage".to_string(),
                JsonValue::Object(vec![(
                    "userMessage".to_string(),
                    JsonValue::Str(formatted.clone()),
                )]),
            )])]),
        )])
        .to_json_string(),
        AntigravityEvent::PostToolUse => "{}".to_string(),
        AntigravityEvent::Stop => JsonValue::Object(vec![(
            "decision".to_string(),
            JsonValue::Str("allow".to_string()),
        )])
        .to_json_string(),
    };

    AntigravityOutcome {
        event: Some(event),
        enforcement: Some(event.enforcement_class()),
        stdout_json: Some(stdout_json),
        stderr_diagnostic: Some(formatted),
        exit_code: 0,
    }
}

fn validate_clean_identifier(
    val: &str,
    field: &str,
    max_len: usize,
    missing_code: &'static str,
    invalid_code: &'static str,
) -> Result<(), AdapterRejection> {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return Err(AdapterRejection::new(
            missing_code,
            format!("Required Antigravity field '{field}' is empty."),
        ));
    }
    if val.len() > max_len {
        return Err(AdapterRejection::new(
            invalid_code,
            format!("Antigravity field '{field}' exceeds {max_len} bytes."),
        ));
    }
    if val.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(AdapterRejection::new(
            "PATH_CONTROL_INJECTION",
            format!("Antigravity field '{field}' contains forbidden control bytes."),
        ));
    }
    let uni = scan_unicode(val, ScanMode::StrictPathOrCommand);
    if let Some(first) = uni.first() {
        return Err(AdapterRejection::new(
            first.code,
            format!(
                "Antigravity field '{field}' failed Unicode inspection: {}",
                first.detail
            ),
        ));
    }
    Ok(())
}

fn is_forbidden_workspace_root(path_str: &str) -> bool {
    let lower = path_str.to_ascii_lowercase();
    if lower == "/tmp"
        || lower.starts_with("/tmp/")
        || lower == "/var/tmp"
        || lower.starts_with("/var/tmp/")
        || lower == "/dev/shm"
        || lower.starts_with("/dev/shm/")
        || lower.contains("/.local/state/agent-guard")
    {
        return true;
    }
    for seg in lower.split('/').filter(|s| !s.is_empty()) {
        if matches!(
            seg,
            "tmp"
                | ".tmp"
                | ".cache"
                | "__pycache__"
                | "node_modules"
                | "vendor"
                | ".venv"
                | "venv"
                | ".ssh"
                | ".aws"
                | ".gnupg"
        ) {
            return true;
        }
    }
    false
}

fn validate_workspace_path_candidate(
    raw_path: &Path,
    label: &str,
) -> Result<Option<PathBuf>, AdapterRejection> {
    if !raw_path.is_absolute() {
        return Err(AdapterRejection::new(
            "INVALID_WORKSPACE_IDENTITY",
            format!("{label} '{}' must be an absolute path.", raw_path.display()),
        ));
    }
    for comp in raw_path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(AdapterRejection::new(
                "INVALID_WORKSPACE_IDENTITY",
                format!(
                    "{label} '{}' must not contain '..' parent traversal.",
                    raw_path.display()
                ),
            ));
        }
    }
    let raw_s = raw_path.to_string_lossy();
    if is_forbidden_workspace_root(&raw_s) {
        return Err(AdapterRejection::new(
            "FORBIDDEN_ZONE_WORKSPACE",
            format!(
                "{label} '{}' resides inside a forbidden zone.",
                raw_path.display()
            ),
        ));
    }
    let meta = match fs::symlink_metadata(raw_path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = raw_path.parent() {
                if fs::symlink_metadata(parent).is_ok_and(|pm| pm.file_type().is_symlink()) {
                    return Err(AdapterRejection::new(
                        "INVALID_WORKSPACE_IDENTITY",
                        format!(
                            "{label} '{}' parent must not be a symlink.",
                            raw_path.display()
                        ),
                    ));
                }
                if fs::canonicalize(parent)
                    .is_ok_and(|cp| is_forbidden_workspace_root(&cp.to_string_lossy()))
                {
                    return Err(AdapterRejection::new(
                        "FORBIDDEN_ZONE_WORKSPACE",
                        format!(
                            "{label} '{}' resides inside a forbidden zone.",
                            raw_path.display()
                        ),
                    ));
                }
            }
            return Ok(None);
        }
        Err(e) => {
            return Err(AdapterRejection::new(
                "INVALID_WORKSPACE_IDENTITY",
                format!("{label} '{}' does not exist: {e}", raw_path.display()),
            ));
        }
    };
    if meta.file_type().is_symlink() {
        return Err(AdapterRejection::new(
            "INVALID_WORKSPACE_IDENTITY",
            format!("{label} '{}' must not be a symlink.", raw_path.display()),
        ));
    }
    if !meta.file_type().is_dir() {
        return Err(AdapterRejection::new(
            "INVALID_WORKSPACE_IDENTITY",
            format!("{label} '{}' is not a directory.", raw_path.display()),
        ));
    }
    let canon = fs::canonicalize(raw_path).map_err(|e| {
        AdapterRejection::new(
            "INVALID_WORKSPACE_IDENTITY",
            format!(
                "Failed canonicalizing {label} '{}': {e}",
                raw_path.display()
            ),
        )
    })?;
    let canon_s = canon.to_string_lossy();
    if is_forbidden_workspace_root(&canon_s) {
        return Err(AdapterRejection::new(
            "FORBIDDEN_ZONE_WORKSPACE",
            format!(
                "{label} '{}' resides inside a forbidden zone.",
                raw_path.display()
            ),
        ));
    }
    Ok(Some(canon))
}

fn validate_nonsymlink_existing_dir(
    raw_path: &Path,
    label: &str,
) -> Result<PathBuf, AdapterRejection> {
    match validate_workspace_path_candidate(raw_path, label)? {
        Some(canon) => Ok(canon),
        None => Err(AdapterRejection::new(
            "INVALID_WORKSPACE_IDENTITY",
            format!("{label} '{}' does not exist.", raw_path.display()),
        )),
    }
}

fn parse_and_verify_common_envelope(
    parsed: &JsonValue,
    fallback_cwd: &Path,
    explicit_workspace: Option<&Path>,
) -> Result<CommonEnvelope, AdapterRejection> {
    if parsed.get("session_id").is_some() || parsed.get("conversation_id").is_some() {
        return Err(AdapterRejection::new(
            "AMBIGUOUS_TOOL_PARAM_ALIAS",
            "Antigravity hook payload must use 'conversationId' without conflicting legacy session key aliases.",
        ));
    }
    if parsed.get("cwd").is_some()
        || parsed.get("working_directory").is_some()
        || parsed.get("workspace_roots").is_some()
    {
        return Err(AdapterRejection::new(
            "AMBIGUOUS_TOOL_PARAM_ALIAS",
            "Antigravity hook payload must use 'workspacePaths' without conflicting legacy cwd aliases.",
        ));
    }

    let Some(conv_id) = parsed.get("conversationId").and_then(JsonValue::as_str) else {
        return Err(AdapterRejection::new(
            "MISSING_CONVERSATION_ID",
            "Antigravity hook payload missing required string field 'conversationId'.",
        ));
    };
    validate_clean_identifier(
        conv_id,
        "conversationId",
        512,
        "MISSING_CONVERSATION_ID",
        "INVALID_CONVERSATION_ID",
    )?;

    for opt_str_field in ["transcriptPath", "artifactDirectoryPath", "modelName"] {
        if let Some(val) = parsed.get(opt_str_field)
            && !matches!(val, JsonValue::Null)
        {
            let Some(s) = val.as_str() else {
                return Err(AdapterRejection::new(
                    "INVALID_HOOK_FIELD",
                    format!("Antigravity optional field '{opt_str_field}' must be a string."),
                ));
            };
            if s.bytes().any(|b| b < 0x20 || b == 0x7F) {
                return Err(AdapterRejection::new(
                    "PATH_CONTROL_INJECTION",
                    format!("Antigravity field '{opt_str_field}' contains control characters."),
                ));
            }
            let uni = scan_unicode(s, ScanMode::StrictPathOrCommand);
            if let Some(first) = uni.first() {
                return Err(AdapterRejection::new(
                    first.code,
                    format!(
                        "Field '{opt_str_field}' failed Unicode check: {}",
                        first.detail
                    ),
                ));
            }
        }
    }

    let last_user_input = match parsed.get("lastUserInput") {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::Str(s)) => {
            let uni = scan_unicode(s, ScanMode::UntrustedContent);
            if let Some(first) = uni.first() {
                return Err(AdapterRejection::new(
                    first.code,
                    format!(
                        "Antigravity 'lastUserInput' contained forbidden Unicode/control sequence: {}",
                        first.detail
                    ),
                ));
            }
            Some(s.clone())
        }
        Some(_) => {
            return Err(AdapterRejection::new(
                "INVALID_HOOK_FIELD",
                "Antigravity optional field 'lastUserInput' must be a string.",
            ));
        }
    };

    let Some(ws_arr) = parsed.get("workspacePaths").and_then(JsonValue::as_array) else {
        return Err(AdapterRejection::new(
            "MISSING_WORKSPACE_IDENTITY",
            "Antigravity hook payload missing required array field 'workspacePaths'.",
        ));
    };
    if ws_arr.is_empty() {
        return Err(AdapterRejection::new(
            "MISSING_WORKSPACE_IDENTITY",
            "Antigravity 'workspacePaths' array must contain at least one workspace directory.",
        ));
    }
    if ws_arr.len() > 64 {
        return Err(AdapterRejection::new(
            "INVALID_WORKSPACE_IDENTITY",
            "Antigravity 'workspacePaths' exceeds maximum of 64 workspace roots.",
        ));
    }

    let mut canon_workspaces: Vec<PathBuf> = Vec::with_capacity(ws_arr.len());
    let mut had_unmounted_sibling = false;
    for entry in ws_arr {
        let Some(raw_ws) = entry.as_str() else {
            return Err(AdapterRejection::new(
                "INVALID_WORKSPACE_IDENTITY",
                "Every entry in 'workspacePaths' must be a string.",
            ));
        };
        validate_clean_identifier(
            raw_ws,
            "workspacePaths[]",
            4096,
            "MISSING_WORKSPACE_IDENTITY",
            "INVALID_WORKSPACE_IDENTITY",
        )?;
        match validate_workspace_path_candidate(Path::new(raw_ws), "workspacePaths entry")? {
            Some(canon) => {
                if !canon_workspaces.contains(&canon) {
                    canon_workspaces.push(canon);
                }
            }
            None => {
                had_unmounted_sibling = true;
            }
        }
    }
    if canon_workspaces.is_empty() {
        return Err(AdapterRejection::new(
            "INVALID_WORKSPACE_IDENTITY",
            "No existing workspace directory found in Antigravity 'workspacePaths'.",
        ));
    }

    let selected_workspace = resolve_authoritative_workspace(
        &canon_workspaces,
        had_unmounted_sibling,
        fallback_cwd,
        explicit_workspace,
    )?;
    let repo_root = resolve_repo_root(&selected_workspace);

    Ok(CommonEnvelope {
        conversation_id: conv_id.to_string(),
        selected_workspace,
        repo_root,
        last_user_input,
    })
}

fn resolve_authoritative_workspace(
    canon_workspaces: &[PathBuf],
    had_unmounted_sibling: bool,
    fallback_cwd: &Path,
    explicit_workspace: Option<&Path>,
) -> Result<PathBuf, AdapterRejection> {
    if let Some(exp) = explicit_workspace {
        let canon_exp = validate_nonsymlink_existing_dir(exp, "pinned --workspace")?;
        if !canon_workspaces.iter().any(|w| w == &canon_exp) {
            return Err(AdapterRejection::new(
                "WORKSPACE_IDENTITY_MISMATCH",
                format!(
                    "Pinned hook workspace '{}' is not among active Antigravity workspacePaths.",
                    canon_exp.display()
                ),
            ));
        }
        return Ok(canon_exp);
    }

    let fallback_canon =
        fs::canonicalize(fallback_cwd).unwrap_or_else(|_| lexical_normalize(fallback_cwd));

    if canon_workspaces.len() == 1 && !had_unmounted_sibling {
        let only = &canon_workspaces[0];
        let ws_repo = resolve_repo_root(only);
        let cwd_git = discover_git_root_from_canon(&fallback_canon);
        if cwd_git.join(".git").exists()
            && cwd_git != ws_repo
            && !only.starts_with(&fallback_canon)
            && !fallback_canon.starts_with(only)
        {
            return Err(AdapterRejection::new(
                "AMBIGUOUS_WORKSPACE_IDENTITY",
                format!(
                    "Process working directory '{}' belongs to repository '{}', conflicting with workspacePaths '{}'.",
                    fallback_canon.display(),
                    cwd_git.display(),
                    only.display()
                ),
            ));
        }
        return Ok(only.clone());
    }

    // Multiple workspaces: first check if trusted OS fallback_cwd uniquely selects a leaf workspace
    // without also being a parent container above other sibling workspaces in `canon_workspaces`.
    let containing_cwd: Vec<&PathBuf> = canon_workspaces
        .iter()
        .filter(|w| fallback_canon.starts_with(w.as_path()))
        .collect();
    if let Some(deepest) = containing_cwd
        .into_iter()
        .max_by_key(|p| p.components().count())
    {
        let has_other_descendant_of_cwd = canon_workspaces
            .iter()
            .any(|w| w != deepest && w.starts_with(&fallback_canon));
        if !has_other_descendant_of_cwd {
            return Ok(deepest.clone());
        }
    }

    // Special case for single-repo container layout: `["/workspace", "/workspace/owner/repo"]`
    // where all other workspace entries are strict non-git ancestors of a single leaf git repository.
    let git_workspaces: Vec<&PathBuf> = canon_workspaces
        .iter()
        .filter(|w| w.join(".git").exists())
        .collect();
    if !had_unmounted_sibling && git_workspaces.len() == 1 {
        let sole_git = git_workspaces[0];
        let all_others_are_non_git_ancestors = canon_workspaces
            .iter()
            .all(|w| w == sole_git || (!w.join(".git").exists() && sole_git.starts_with(w)));
        if all_others_are_non_git_ancestors {
            return Ok(sole_git.clone());
        }
    }

    Err(AdapterRejection::new(
        "AMBIGUOUS_WORKSPACE_IDENTITY",
        format!(
            "Antigravity payload supplied {} workspaces without an unambiguous repository binding (pin `--workspace <dir>` in `.agents/hooks.json` or open a single repository project).",
            canon_workspaces.len()
        ),
    ))
}

fn parse_tool_call_envelope(parsed: &JsonValue) -> Result<NormalizedToolCall, AdapterRejection> {
    if parsed.get("tool_name").is_some()
        || parsed.get("toolName").is_some()
        || parsed.get("tool_input").is_some()
        || parsed.get("command").is_some()
        || parsed.get("file_path").is_some()
    {
        return Err(AdapterRejection::new(
            "AMBIGUOUS_TOOL_PARAM_ALIAS",
            "Antigravity tool hook must supply 'toolCall.name' and 'toolCall.args' without top-level legacy tool aliases.",
        ));
    }

    let Some(tc_val) = parsed.get("toolCall") else {
        return Err(AdapterRejection::new(
            "MISSING_TOOL_CALL",
            "Antigravity tool hook payload missing required 'toolCall' object.",
        ));
    };
    let Some(_tc_obj) = tc_val.as_object() else {
        return Err(AdapterRejection::new(
            "MISSING_TOOL_CALL",
            "Antigravity 'toolCall' field must be a JSON object.",
        ));
    };

    let Some(name_raw) = tc_val.get("name").and_then(JsonValue::as_str) else {
        return Err(AdapterRejection::new(
            "MISSING_TOOL_NAME",
            "Antigravity 'toolCall.name' must be a non-empty string.",
        ));
    };
    validate_clean_identifier(
        name_raw,
        "toolCall.name",
        256,
        "MISSING_TOOL_NAME",
        "INVALID_TOOL_NAME",
    )?;

    let Some(args_val) = tc_val.get("args") else {
        return Err(AdapterRejection::new(
            "INVALID_TOOL_ARGS",
            "Antigravity 'toolCall.args' object is required.",
        ));
    };
    if args_val.as_object().is_none() {
        return Err(AdapterRejection::new(
            "INVALID_TOOL_ARGS",
            "Antigravity 'toolCall.args' must be a JSON object (stringified or array args rejected).",
        ));
    }

    let step_idx = match parsed.get("stepIdx") {
        None | Some(JsonValue::Null) => None,
        Some(v) => {
            let Some(idx) = v.as_u64() else {
                return Err(AdapterRejection::new(
                    "INVALID_STEP_INDEX",
                    "Antigravity 'stepIdx' must be a non-negative integer.",
                ));
            };
            Some(idx)
        }
    };

    Ok(NormalizedToolCall {
        name: name_raw.to_string(),
        args: args_val.clone(),
        step_idx,
    })
}

fn handle_session_start(common: &CommonEnvelope) -> AntigravityOutcome {
    let mut fields = vec![
        (
            "session_id".to_string(),
            JsonValue::Str(common.conversation_id.clone()),
        ),
        (
            "cwd".to_string(),
            JsonValue::Str(common.selected_workspace.to_string_lossy().into_owned()),
        ),
    ];
    if let Some(ref prompt) = common.last_user_input {
        fields.push(("prompt".to_string(), JsonValue::Str(prompt.clone())));
    }
    let norm_json = JsonValue::Object(fields).to_json_string();
    let dec = handle_user_prompt_hook(&norm_json, &common.selected_workspace);
    match dec {
        Decision::Allow { advisory, .. } => {
            let stdout_json = if let Some(msg) = advisory {
                JsonValue::Object(vec![(
                    "injectSteps".to_string(),
                    JsonValue::Array(vec![JsonValue::Object(vec![(
                        "systemMessage".to_string(),
                        JsonValue::Object(vec![("systemMessage".to_string(), JsonValue::Str(msg))]),
                    )])]),
                )])
                .to_json_string()
            } else {
                "{}".to_string()
            };
            AntigravityOutcome {
                event: Some(AntigravityEvent::SessionStart),
                enforcement: Some(EventEnforcementClass::SessionBootstrap),
                stdout_json: Some(stdout_json),
                stderr_diagnostic: None,
                exit_code: 0,
            }
        }
        Decision::Deny { code, reason, .. } => reject_for_event(
            AntigravityEvent::SessionStart,
            &AdapterRejection::new(code, reason),
        ),
    }
}

fn validate_invocation_counters(parsed: &JsonValue) -> Result<Option<u64>, AdapterRejection> {
    let mut inv_num = None;
    for field in ["invocationNum", "initialNumSteps"] {
        if let Some(val) = parsed.get(field)
            && !matches!(val, JsonValue::Null)
        {
            let Some(n) = val.as_u64() else {
                return Err(AdapterRejection::new(
                    "INVALID_HOOK_FIELD",
                    format!("Antigravity '{field}' must be a non-negative integer."),
                ));
            };
            if field == "invocationNum" {
                inv_num = Some(n);
            }
        }
    }
    Ok(inv_num)
}

fn handle_pre_invocation(parsed: &JsonValue, common: &CommonEnvelope) -> AntigravityOutcome {
    let inv_num = match validate_invocation_counters(parsed) {
        Ok(n) => n,
        Err(rej) => return reject_for_event(AntigravityEvent::PreInvocation, &rej),
    };

    let profile = match load_active_profile(&common.repo_root) {
        Ok(p) => p,
        Err(bv) => {
            return reject_for_event(
                AntigravityEvent::PreInvocation,
                &AdapterRejection::new(bv.code, bv.detail),
            );
        }
    };

    {
        let _lock = SessionLedger::acquire_lock(&common.repo_root, &common.conversation_id);
        let ledger = SessionLedger::load_or_create(&common.repo_root, &common.conversation_id);
        if ledger.halted {
            let detail = ledger
                .halt_reason
                .unwrap_or_else(|| "session circuit breaker is tripped".to_string());
            return reject_for_event(
                AntigravityEvent::PreInvocation,
                &AdapterRejection::new("SESSION_CIRCUIT_BREAKER_HALTED", detail),
            );
        }
    }

    if inv_num == Some(0) {
        let mut fields = vec![
            (
                "session_id".to_string(),
                JsonValue::Str(common.conversation_id.clone()),
            ),
            (
                "cwd".to_string(),
                JsonValue::Str(common.selected_workspace.to_string_lossy().into_owned()),
            ),
        ];
        if let Some(ref prompt) = common.last_user_input {
            fields.push(("prompt".to_string(), JsonValue::Str(prompt.clone())));
        }
        let norm_json = JsonValue::Object(fields).to_json_string();
        if let Decision::Deny { code, reason, .. } =
            handle_user_prompt_hook(&norm_json, &common.selected_workspace)
        {
            return reject_for_event(
                AntigravityEvent::PreInvocation,
                &AdapterRejection::new(code, reason),
            );
        }
    }

    let _lock = SessionLedger::acquire_lock(&common.repo_root, &common.conversation_id);
    let ledger = SessionLedger::load_or_create(&common.repo_root, &common.conversation_id);
    let stdout_json = if ledger.cumulative_tokens
        >= STEP_SOFT_COMPACT_TOKENS.min(profile.max_turn_tokens)
    {
        let note = format!(
            "[COMPACT_STEP_NOW] Step context reached {}/{} tokens ({} tool calls). Finish this discrete step and compact context immediately.",
            ledger.cumulative_tokens, profile.max_turn_tokens, ledger.tool_calls
        );
        JsonValue::Object(vec![(
            "injectSteps".to_string(),
            JsonValue::Array(vec![JsonValue::Object(vec![(
                "ephemeralMessage".to_string(),
                JsonValue::Str(note),
            )])]),
        )])
        .to_json_string()
    } else {
        "{}".to_string()
    };

    AntigravityOutcome {
        event: Some(AntigravityEvent::PreInvocation),
        enforcement: Some(EventEnforcementClass::ModelGate),
        stdout_json: Some(stdout_json),
        stderr_diagnostic: None,
        exit_code: 0,
    }
}

fn handle_pre_tool_use(parsed: &JsonValue, common: &CommonEnvelope) -> AntigravityOutcome {
    let tc = match parse_tool_call_envelope(parsed) {
        Ok(t) => t,
        Err(rej) => return reject_for_event(AntigravityEvent::PreToolUse, &rej),
    };
    let _ = tc.step_idx;

    let norm_payload = JsonValue::Object(vec![
        (
            "session_id".to_string(),
            JsonValue::Str(common.conversation_id.clone()),
        ),
        (
            "hook_event_name".to_string(),
            JsonValue::Str("PreToolUse".to_string()),
        ),
        (
            "cwd".to_string(),
            JsonValue::Str(common.selected_workspace.to_string_lossy().into_owned()),
        ),
        ("tool_name".to_string(), JsonValue::Str(tc.name.clone())),
        ("tool_input".to_string(), tc.args.clone()),
    ])
    .to_json_string();

    let decision = eval_pre_tool_authoritative(&norm_payload, &common.selected_workspace);
    if let Decision::Deny { code, .. } = &decision {
        crate::enforcement_state::record_denial_witness(
            &common.selected_workspace,
            "antigravity",
            "PreToolUse",
            norm_payload.as_bytes(),
            code,
        );
    }
    format_pre_tool_outcome(decision, &tc.args)
}

fn eval_pre_tool_authoritative(norm_payload: &str, workspace_cwd: &Path) -> Decision {
    if std::env::var("AGENT_GUARD_HOT_COORD").as_deref() == Ok("1") {
        let repo_root = resolve_repo_root(workspace_cwd);
        if let Ok(dec) =
            crate::coordinator::rpc_eval_hook(&repo_root, "pre-tool", norm_payload, workspace_cwd)
        {
            return dec;
        }
    }
    let _telemetry = crate::telemetry::runtime::start_host();
    handle_pre_tool_hook(norm_payload, workspace_cwd)
}

fn format_pre_tool_outcome(decision: Decision, original_args: &JsonValue) -> AntigravityOutcome {
    match decision {
        Decision::Allow {
            advisory,
            updated_bash_cmd,
            updated_input_json,
        } => {
            let overwrite_res =
                compute_antigravity_overwrite(original_args, updated_bash_cmd, updated_input_json);
            match overwrite_res {
                Ok(Some(overwrite_obj)) => {
                    let out = JsonValue::Object(vec![
                        ("decision".to_string(), JsonValue::Str("allow".to_string())),
                        ("overwrite".to_string(), overwrite_obj),
                    ])
                    .to_json_string();
                    AntigravityOutcome {
                        event: Some(AntigravityEvent::PreToolUse),
                        enforcement: Some(EventEnforcementClass::ToolGate),
                        stdout_json: Some(out),
                        stderr_diagnostic: advisory,
                        exit_code: 0,
                    }
                }
                Ok(None) => {
                    let out = JsonValue::Object(vec![(
                        "decision".to_string(),
                        JsonValue::Str("allow".to_string()),
                    )])
                    .to_json_string();
                    AntigravityOutcome {
                        event: Some(AntigravityEvent::PreToolUse),
                        enforcement: Some(EventEnforcementClass::ToolGate),
                        stdout_json: Some(out),
                        stderr_diagnostic: advisory,
                        exit_code: 0,
                    }
                }
                Err(rej) => reject_for_event(AntigravityEvent::PreToolUse, &rej),
            }
        }
        Decision::Deny {
            code,
            reason,
            halt_session,
        } => {
            let msg = format_denial_reason(code, &reason, halt_session);
            let out = JsonValue::Object(vec![
                ("decision".to_string(), JsonValue::Str("deny".to_string())),
                ("reason".to_string(), JsonValue::Str(msg.clone())),
            ])
            .to_json_string();
            AntigravityOutcome {
                event: Some(AntigravityEvent::PreToolUse),
                enforcement: Some(EventEnforcementClass::ToolGate),
                stdout_json: Some(out),
                stderr_diagnostic: Some(msg),
                exit_code: 0,
            }
        }
    }
}

fn format_denial_reason(code: &str, reason: &str, halt_session: bool) -> String {
    if code == "NON_ASCII_SANITIZED_PREBUFFER" {
        format!(
            "[AGENT-GUARD PRE-BUFFER ASCII SANITIZER :: {code}] Untrusted file contained non-ASCII bytes or escape triggers and was neutered prior to entering your context buffer. Use ONLY the clean 7-bit ASCII payload below (do NOT re-read raw):\n{reason}"
        )
    } else if !halt_session
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
        )
    {
        format!(
            "[AGENT-GUARD BOUND GUIDANCE :: {code}] {reason} -- Adjust the call to stay within micro-window bounds (e.g. StartLine/EndLine <= 150 lines, --max-depth 2, git log -n 20) or compact step context."
        )
    } else {
        format!(
            "[AGENT-GUARD HARD DENY :: {code}] {reason} -- STOP IMMEDIATELY. Do NOT attempt workarounds, alternate tools, or encodings. Report this block verbatim to the user."
        )
    }
}

/// Computes the minimal non-empty shallow-merge `overwrite` object per Antigravity's documented
/// `PreToolUse` contract (`overwrite` merges top-level keys into `toolCall.args`).
/// Never emits an empty `{}` overwrite object, and fails closed if a rewrite attempts to delete
/// an existing top-level key (which shallow top-level merge cannot express).
fn compute_antigravity_overwrite(
    original_args: &JsonValue,
    updated_bash_cmd: Option<String>,
    updated_input_json: Option<String>,
) -> Result<Option<JsonValue>, AdapterRejection> {
    let Some(orig_entries) = original_args.as_object() else {
        return Err(AdapterRejection::new(
            "INVALID_TOOL_ARGS",
            "Original toolCall.args is not a JSON object.",
        ));
    };

    if let Some(raw_updated) = updated_input_json {
        let parsed_updated = JsonValue::parse(&raw_updated).map_err(|e| {
            AdapterRejection::new(
                "INTERNAL_HOOK_JSON_ERROR",
                format!("Failed parsing authoritative updated_input_json: {e}"),
            )
        })?;
        let Some(updated_entries) = parsed_updated.as_object() else {
            return Err(AdapterRejection::new(
                "INTERNAL_HOOK_JSON_ERROR",
                "Authoritative updated_input_json must be a JSON object.",
            ));
        };

        for (orig_k, _) in orig_entries {
            if !updated_entries.iter().any(|(uk, _)| uk == orig_k) {
                return Err(AdapterRejection::new(
                    "AMBIGUOUS_TOOL_PARAM_ALIAS",
                    format!(
                        "Cannot represent removal of parameter '{orig_k}' via Antigravity shallow-merge 'overwrite'; pass canonical Antigravity parameter names only."
                    ),
                ));
            }
        }

        let mut diff_entries = Vec::new();
        for (uk, uv) in updated_entries {
            if original_args.get(uk) != Some(uv) {
                diff_entries.push((uk.clone(), uv.clone()));
            }
        }
        if diff_entries.is_empty() {
            return Ok(None);
        }
        return Ok(Some(JsonValue::Object(diff_entries)));
    }

    if let Some(rewritten_cmd) = updated_bash_cmd {
        let target_key = ["CommandLine", "command", "cmd", "script"]
            .into_iter()
            .find(|k| original_args.get(k).is_some())
            .unwrap_or("CommandLine");
        let new_val = JsonValue::Str(rewritten_cmd);
        if original_args.get(target_key) == Some(&new_val) {
            return Ok(None);
        }
        return Ok(Some(JsonValue::Object(vec![(
            target_key.to_string(),
            new_val,
        )])));
    }

    Ok(None)
}

fn handle_post_tool_use(parsed: &JsonValue, common: &CommonEnvelope) -> AntigravityOutcome {
    let tc = match parse_tool_call_envelope(parsed) {
        Ok(t) => t,
        Err(rej) => return reject_for_event(AntigravityEvent::PostToolUse, &rej),
    };

    let tool_error = match parsed.get("error") {
        None | Some(JsonValue::Null) => String::new(),
        Some(JsonValue::Str(s)) => s.clone(),
        Some(_) => {
            return reject_for_event(
                AntigravityEvent::PostToolUse,
                &AdapterRejection::new(
                    "INVALID_HOOK_FIELD",
                    "Antigravity PostToolUse 'error' field must be a string when present.",
                ),
            );
        }
    };

    let mut diagnostics = Vec::new();

    // Post-edit file hygiene check for completed file-mutation tools (trips session circuit breaker
    // if forbidden Unicode or accidental plaintext secrets were written).
    let norm_name = tc.name.to_ascii_lowercase();
    if tool_error.is_empty()
        && matches!(
            norm_name.as_str(),
            "write_to_file"
                | "replace_file_content"
                | "multi_replace_file_content"
                | "write"
                | "edit"
                | "multiedit"
        )
        && let Some(target_file) = ["TargetFile", "file_path", "path", "target_file"]
            .into_iter()
            .find_map(|k| tc.args.get(k).and_then(JsonValue::as_str))
    {
        let edit_dec = handle_post_edit_with_session(
            target_file,
            &common.selected_workspace,
            &common.conversation_id,
        );
        if let Decision::Deny {
            code,
            reason,
            halt_session,
        } = edit_dec
        {
            if halt_session {
                let _lock = SessionLedger::acquire_lock(&common.repo_root, &common.conversation_id);
                let mut ledger =
                    SessionLedger::load_or_create(&common.repo_root, &common.conversation_id);
                ledger.trip_circuit_breaker(format!("{code}: {reason}"));
                let _ = ledger.save_locked(&common.repo_root);
            }
            append_audit_jsonl(
                &common.repo_root,
                &common.conversation_id,
                &tc.name,
                code,
                &reason,
                halt_session,
            );
            diagnostics.push(format!("[AGENT-GUARD POST-TOOL ALERT :: {code}] {reason}"));
        }
    }

    // Observe any tool output or error payload supplied by the host via authoritative PostToolUse engine.
    let observed_output = ["toolResponse", "tool_response", "output", "result"]
        .into_iter()
        .find_map(|k| parsed.get(k).cloned())
        .or((!tool_error.is_empty()).then_some(JsonValue::Str(tool_error)));

    if let Some(out_val) = observed_output {
        let post_payload = JsonValue::Object(vec![
            (
                "session_id".to_string(),
                JsonValue::Str(common.conversation_id.clone()),
            ),
            (
                "hook_event_name".to_string(),
                JsonValue::Str("PostToolUse".to_string()),
            ),
            (
                "cwd".to_string(),
                JsonValue::Str(common.selected_workspace.to_string_lossy().into_owned()),
            ),
            ("tool_name".to_string(), JsonValue::Str(tc.name)),
            ("tool_response".to_string(), out_val),
        ])
        .to_json_string();

        if let Decision::Deny { code, reason, .. } =
            handle_post_tool_hook(&post_payload, &common.selected_workspace)
        {
            diagnostics.push(format!(
                "[AGENT-GUARD POST-TOOL OBSERVATION :: {code}] {reason}"
            ));
        }
    }

    AntigravityOutcome {
        event: Some(AntigravityEvent::PostToolUse),
        enforcement: Some(EventEnforcementClass::ObservationalStateUpdate),
        stdout_json: Some("{}".to_string()),
        stderr_diagnostic: if diagnostics.is_empty() {
            None
        } else {
            Some(diagnostics.join("\n"))
        },
        exit_code: 0,
    }
}

fn handle_post_invocation(parsed: &JsonValue, common: &CommonEnvelope) -> AntigravityOutcome {
    if let Err(rej) = validate_invocation_counters(parsed) {
        return reject_for_event(AntigravityEvent::PostInvocation, &rej);
    }

    let profile = match load_active_profile(&common.repo_root) {
        Ok(p) => p,
        Err(bv) => {
            return reject_for_event(
                AntigravityEvent::PostInvocation,
                &AdapterRejection::new(bv.code, bv.detail),
            );
        }
    };

    let _lock = SessionLedger::acquire_lock(&common.repo_root, &common.conversation_id);
    let ledger = SessionLedger::load_or_create(&common.repo_root, &common.conversation_id);
    if ledger.halted {
        let detail = ledger
            .halt_reason
            .unwrap_or_else(|| "session circuit breaker is tripped".to_string());
        return reject_for_event(
            AntigravityEvent::PostInvocation,
            &AdapterRejection::new("SESSION_CIRCUIT_BREAKER_HALTED", detail),
        );
    }

    let stdout_json = if ledger.cumulative_tokens > profile.max_turn_tokens {
        let msg = format!(
            "[AGENT-GUARD TURN_TOKEN_BUDGET_EXCEEDED] Step context ({} tokens) exceeded ceiling ({} tokens for profile '{}'). Compact immediately.",
            ledger.cumulative_tokens, profile.max_turn_tokens, profile.profile_id
        );
        JsonValue::Object(vec![(
            "injectSteps".to_string(),
            JsonValue::Array(vec![JsonValue::Object(vec![(
                "ephemeralMessage".to_string(),
                JsonValue::Str(msg),
            )])]),
        )])
        .to_json_string()
    } else {
        "{}".to_string()
    };

    AntigravityOutcome {
        event: Some(AntigravityEvent::PostInvocation),
        enforcement: Some(EventEnforcementClass::LoopControlGate),
        stdout_json: Some(stdout_json),
        stderr_diagnostic: None,
        exit_code: 0,
    }
}

fn handle_stop(parsed: &JsonValue, common: &CommonEnvelope) -> AntigravityOutcome {
    let Some(fully_idle) = parsed.get("fullyIdle").and_then(JsonValue::as_bool) else {
        return reject_for_event(
            AntigravityEvent::Stop,
            &AdapterRejection::new(
                "INVALID_HOOK_FIELD",
                "Antigravity Stop payload missing required boolean field 'fullyIdle'.",
            ),
        );
    };

    let execution_num = match parsed.get("executionNum") {
        None | Some(JsonValue::Null) => 1u64,
        Some(v) => {
            let Some(n) = v.as_u64() else {
                return reject_for_event(
                    AntigravityEvent::Stop,
                    &AdapterRejection::new(
                        "INVALID_HOOK_FIELD",
                        "Antigravity Stop 'executionNum' must be a non-negative integer.",
                    ),
                );
            };
            n
        }
    };

    let termination_reason = match parsed.get("terminationReason") {
        None | Some(JsonValue::Null) => "model_stop".to_string(),
        Some(JsonValue::Str(s)) => s.clone(),
        Some(_) => {
            return reject_for_event(
                AntigravityEvent::Stop,
                &AdapterRejection::new(
                    "INVALID_HOOK_FIELD",
                    "Antigravity Stop 'terminationReason' must be a string.",
                ),
            );
        }
    };

    if let Some(err_val) = parsed.get("error")
        && !matches!(err_val, JsonValue::Null | JsonValue::Str(_))
    {
        return reject_for_event(
            AntigravityEvent::Stop,
            &AdapterRejection::new(
                "INVALID_HOOK_FIELD",
                "Antigravity Stop 'error' must be a string when present.",
            ),
        );
    }

    let halted_reason = {
        let _lock = SessionLedger::acquire_lock(&common.repo_root, &common.conversation_id);
        let ledger = SessionLedger::load_or_create(&common.repo_root, &common.conversation_id);
        if ledger.halted {
            Some(
                ledger
                    .halt_reason
                    .unwrap_or_else(|| "circuit breaker tripped".to_string()),
            )
        } else {
            None
        }
    };

    if let Some(reason) = halted_reason {
        let diag = format!(
            "[AGENT-GUARD STOP AUDIT FAIL] SESSION_CIRCUIT_BREAKER_HALTED: session '{}' halted ({reason}). Allowing loop termination without retry.",
            common.conversation_id
        );
        append_audit_jsonl(
            &common.repo_root,
            &common.conversation_id,
            "Stop",
            "SESSION_CIRCUIT_BREAKER_HALTED",
            &reason,
            true,
        );
        return AntigravityOutcome {
            event: Some(AntigravityEvent::Stop),
            enforcement: Some(EventEnforcementClass::StopAuditGate),
            stdout_json: Some(
                JsonValue::Object(vec![(
                    "decision".to_string(),
                    JsonValue::Str("allow".to_string()),
                )])
                .to_json_string(),
            ),
            stderr_diagnostic: Some(diag),
            exit_code: 0,
        };
    }

    let mut gate_failures = audit_workspace_scoped(&common.repo_root);
    if let Err(swarm_err) = crate::work_ledger::verify_on_stop_swarm_gates(&common.repo_root) {
        gate_failures.push(swarm_err);
    }
    if let Err(smoke_err) = crate::smoke_gate::verify_repo_smoke_gate(&common.repo_root) {
        gate_failures.push(smoke_err);
    }

    if !gate_failures.is_empty() {
        let combined = gate_failures.join("; ");
        append_audit_jsonl(
            &common.repo_root,
            &common.conversation_id,
            "Stop",
            "STOP_GATE_CHECK_FAILED",
            &combined,
            false,
        );
        // Bounded retry: request continuation AT MOST ONCE (execution_num <= 1) on normal idle model_stop.
        if fully_idle && termination_reason == "model_stop" && execution_num <= 1 {
            let reason = format!(
                "[AGENT-GUARD ON-STOP GATE] Workspace verification reported issue(s): {combined}"
            );
            let out = JsonValue::Object(vec![
                (
                    "decision".to_string(),
                    JsonValue::Str("continue".to_string()),
                ),
                ("reason".to_string(), JsonValue::Str(reason.clone())),
            ])
            .to_json_string();
            return AntigravityOutcome {
                event: Some(AntigravityEvent::Stop),
                enforcement: Some(EventEnforcementClass::StopAuditGate),
                stdout_json: Some(out),
                stderr_diagnostic: Some(reason),
                exit_code: 0,
            };
        }
        return AntigravityOutcome {
            event: Some(AntigravityEvent::Stop),
            enforcement: Some(EventEnforcementClass::StopAuditGate),
            stdout_json: Some(
                JsonValue::Object(vec![(
                    "decision".to_string(),
                    JsonValue::Str("allow".to_string()),
                )])
                .to_json_string(),
            ),
            stderr_diagnostic: Some(format!(
                "[AGENT-GUARD STOP AUDIT WARN] {combined} (allowing stop after bounded check)"
            )),
            exit_code: 0,
        };
    }

    append_audit_jsonl(
        &common.repo_root,
        &common.conversation_id,
        "Stop",
        "STOP_AUDIT_OK",
        "workspace-scoped stop audit passed",
        false,
    );

    AntigravityOutcome {
        event: Some(AntigravityEvent::Stop),
        enforcement: Some(EventEnforcementClass::StopAuditGate),
        stdout_json: Some(
            JsonValue::Object(vec![(
                "decision".to_string(),
                JsonValue::Str("allow".to_string()),
            )])
            .to_json_string(),
        ),
        stderr_diagnostic: None,
        exit_code: 0,
    }
}

/// Workspace-scoped repository hygiene audit that does NOT require global `~/.gitconfig` 19-key
/// lockdown (so workspace-scoped Antigravity hooks work standalone without global Git mutation).
pub(crate) fn audit_workspace_scoped(repo_root: &Path) -> Vec<String> {
    let mut failures = Vec::new();
    if repo_root.join(".git").exists()
        && let Err(cv) = inspect_repo_git_config_and_hooks(repo_root)
    {
        failures.push(format!("{}: {}", cv.code, cv.detail));
    }
    failures.extend(inspect_repo_build_config_traps(repo_root));
    audit_github_workflows(repo_root, &mut failures);

    let root_agents = repo_root.join("AGENTS.md");
    if let Ok(meta) = fs::symlink_metadata(&root_agents) {
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            failures.push(format!(
                "SYMLINKED_ROOT_AGENTS_MD: '{}' must be a regular file, not a symlink",
                root_agents.display()
            ));
        } else if let Ok(body) = fs::read_to_string(&root_agents) {
            let uni = scan_unicode(&body, ScanMode::UntrustedContent);
            if let Some(first) = uni.first() {
                failures.push(format!(
                    "ROOT_AGENTS_UNICODE: '{}' failed Unicode check: {}",
                    root_agents.display(),
                    first.detail
                ));
            }
        }
    }

    // Bounded depth <= 2 check for symlink escapes or shadow instruction files inside workspace.
    scan_workspace_shadow_authority_bounded(repo_root, repo_root, 0, &mut failures);
    failures
}

fn scan_workspace_shadow_authority_bounded(
    repo_root: &Path,
    dir: &Path,
    depth: usize,
    failures: &mut Vec<String>,
) {
    if depth > 2 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let lower = name.to_string_lossy().to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            ".git"
                | "target"
                | "build"
                | "dist"
                | "dist-build"
                | "node_modules"
                | "vendor"
                | ".venv"
                | "venv"
                | ".cache"
                | "__pycache__"
                | "tmp"
                | ".tmp"
        ) {
            continue;
        }
        let full = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            if let Err(pv) = validate_path(
                repo_root,
                repo_root,
                &full.to_string_lossy(),
                PathAccess::ReferencePointer,
            ) {
                failures.push(format!(
                    "SUSPICIOUS_SYMLINK: '{}' -> {}",
                    full.display(),
                    pv.detail
                ));
            }
        } else if ft.is_file() {
            let rel = full
                .strip_prefix(repo_root)
                .unwrap_or(&full)
                .to_string_lossy()
                .replace('\\', "/");
            if let Err(pv) = validate_path(repo_root, repo_root, &rel, PathAccess::ReferencePointer)
                && pv.code == "UNAUTHORIZED_INSTRUCTION_FILE"
            {
                failures.push(format!("ROGUE_AUTHORITY_FILE: {}", pv.detail));
            }
        } else if ft.is_dir() && depth < 2 {
            scan_workspace_shadow_authority_bounded(repo_root, &full, depth + 1, failures);
        }
    }
}
