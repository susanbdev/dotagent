#![forbid(unsafe_code)]

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use agent_guard::json::JsonValue;

const AGENT_GUARD: &str = env!("CARGO_BIN_EXE_agent-guard");
const CONVERSATION: &str = "17a4bdad-32fd-4d10-9c86-2bb86596fbd8";
const OVERSIZED: usize = 512 * 1024;
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn object<'a>(fields: impl IntoIterator<Item = (&'a str, JsonValue)>) -> JsonValue {
    JsonValue::Object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_string(), value))
            .collect(),
    )
}

fn text(value: impl Into<String>) -> JsonValue {
    JsonValue::Str(value.into())
}

fn path_text(path: &Path) -> JsonValue {
    text(path.to_str().expect("fixture path is UTF-8"))
}

struct Fixture {
    base: PathBuf,
    workspace: PathBuf,
    home: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("Cargo workspace")
            .join("target/trv");
        fs::create_dir_all(&root).expect("create integration fixture parent");
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let base = root.join(format!("native-hook-{}-{sequence}", std::process::id()));
        fs::create_dir(&base).expect("create exclusive integration fixture");
        let base = base.canonicalize().expect("canonical fixture root");
        let workspace = base.join("workspace");
        // This empty marker keeps repo discovery inside the fixture. It needs no Git process.
        fs::create_dir_all(workspace.join(".git")).expect("create isolated workspace");
        fs::write(workspace.join("AGENTS.md"), "# Test workspace\n").expect("write test policy");
        let home = base.join("home");
        for directory in ["config", "state", "data", "runtime", "tools"] {
            fs::create_dir_all(home.join(directory)).expect("create isolated child directory");
        }
        Self {
            base,
            workspace,
            home,
        }
    }

    fn workspace_paths(&self) -> JsonValue {
        JsonValue::Array(vec![path_text(&self.workspace)])
    }

    fn request<'a>(&self, fields: impl IntoIterator<Item = (&'a str, JsonValue)>) -> JsonValue {
        object(
            [
                ("conversationId", text(CONVERSATION)),
                ("workspacePaths", self.workspace_paths()),
            ]
            .into_iter()
            .chain(fields),
        )
    }

    fn tool(&self, name: &str, args: JsonValue) -> JsonValue {
        self.request([
            ("toolCall", object([("name", text(name)), ("args", args)])),
            ("stepIdx", JsonValue::Uint(2)),
        ])
    }

    fn command(&self) -> Command {
        let mut command = Command::new(AGENT_GUARD);
        command
            .current_dir(&self.workspace)
            .env_clear()
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("PATH", self.home.join("tools"))
            .env("XDG_CONFIG_HOME", self.home.join("config"))
            .env("XDG_STATE_HOME", self.home.join("state"))
            .env("XDG_DATA_HOME", self.home.join("data"))
            .env("XDG_RUNTIME_DIR", self.home.join("runtime"))
            .env("AGENT_GUARD_STATE_DIR", self.home.join("state"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn native_bytes(&self, event: &str, bytes: &[u8]) -> JsonValue {
        self.native_bytes_with(event, bytes, |_| {})
    }

    fn native_bytes_with(
        &self,
        event: &str,
        bytes: &[u8],
        configure: impl FnOnce(&mut Command),
    ) -> JsonValue {
        let mut command = self.command();
        command
            .args(["antigravity-hook", event, "--workspace"])
            .arg(&self.workspace);
        configure(&mut command);
        let output = invoke(&mut command, bytes);
        assert_eq!(
            output.status.code(),
            Some(0),
            "native {event} should return a JSON decision with exit 0: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        one_object(&output.stdout)
    }

    fn native(&self, event: &str, body: JsonValue) -> JsonValue {
        self.native_bytes(event, body.to_json_string().as_bytes())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn invoke(command: &mut Command, bytes: &[u8]) -> Output {
    let mut child = command.spawn().expect("run agent-guard hook command");
    let mut input = child.stdin.take().expect("piped hook request");
    let provided = input.write_all(bytes);
    drop(input);
    if let Err(error) = provided {
        assert!(
            bytes.len() >= OVERSIZED && error.kind() == ErrorKind::BrokenPipe,
            "write hook request: {error}"
        );
    }
    child.wait_with_output().expect("collect hook output")
}

fn one_object(bytes: &[u8]) -> JsonValue {
    let stdout = std::str::from_utf8(bytes).expect("native hook output is UTF-8");
    assert_eq!(stdout.lines().count(), 1, "one JSON line, got {stdout:?}");
    let value = JsonValue::parse(stdout).unwrap_or_else(|error| panic!("{error}: {stdout:?}"));
    assert!(
        value.as_object().is_some(),
        "expected an object: {stdout:?}"
    );
    value
}

fn assert_decision(reply: &JsonValue, decision: &str) {
    assert_eq!(
        reply.get("decision").and_then(JsonValue::as_str),
        Some(decision),
        "reply: {reply:?}"
    );
}

fn assert_denied(reply: &JsonValue) {
    assert_decision(reply, "deny");
    assert!(
        reply
            .get("reason")
            .and_then(JsonValue::as_str)
            .is_some_and(|why| !why.is_empty()),
        "deny reason missing: {reply:?}"
    );
    assert!(
        reply.get("overwrite").is_none(),
        "denial supplied a tool rewrite"
    );
}

fn assert_denied_for(reply: &JsonValue, reason: &str) {
    assert_denied(reply);
    assert!(
        reply
            .get("reason")
            .and_then(JsonValue::as_str)
            .is_some_and(|message| message.contains(reason)),
        "expected {reason}: {reply:?}"
    );
}

fn assert_no_action(reply: &JsonValue) {
    assert_eq!(reply.as_object(), Some([].as_slice()), "reply: {reply:?}");
}

#[test]
fn native_shell_decisions_pin_allowed_commands_to_the_sandbox() {
    let fixture = Fixture::new();
    let allowed = fixture.native(
        "PreToolUse",
        fixture.tool(
            "run_command",
            object([
                ("CommandLine", text("pwd")),
                ("Cwd", path_text(&fixture.workspace)),
            ]),
        ),
    );
    assert_decision(&allowed, "allow");
    let overwrite = allowed
        .get("overwrite")
        .expect("allowed shell command must be rewritten");
    let wrapped = overwrite
        .get("CommandLine")
        .and_then(JsonValue::as_str)
        .expect("native command key");
    assert_eq!(overwrite.as_object().map(<[_]>::len), Some(1));
    let executable = Path::new(AGENT_GUARD)
        .canonicalize()
        .expect("trusted binary path");
    assert!(
        wrapped.contains(executable.to_str().expect("UTF-8 binary path")),
        "{wrapped}"
    );
    for required in [
        "exec-sandbox",
        "--sanitize-stream",
        "--require-kernel",
        "--cwd",
        "--session-id",
        CONVERSATION,
        fixture.workspace.to_str().expect("UTF-8 workspace path"),
        "pwd",
    ] {
        assert!(wrapped.contains(required), "missing {required}: {wrapped}");
    }

    let denied = fixture.native(
        "PreToolUse",
        fixture.tool(
            "run_command",
            object([("CommandLine", text("python3 --version"))]),
        ),
    );
    assert_denied_for(&denied, "UNAPPROVED_INTERPRETER_BLOCKED");

    let mismatched_cwd = fixture.tool(
        "run_command",
        object([
            ("CommandLine", text("pwd")),
            ("Cwd", path_text(&fixture.base)),
        ]),
    );
    assert_denied(&fixture.native("PreToolUse", mismatched_cwd));
}

#[test]
fn native_dispatch_uses_the_installed_pin_and_checks_host_role_identity() {
    let fixture = Fixture::new();
    let allowed_file = fixture.workspace.join("public.txt");
    fs::write(&allowed_file, b"fixture data\n").expect("write file in pinned workspace");
    let body = fixture
        .tool(
            "view_file",
            object([("AbsolutePath", path_text(&allowed_file))]),
        )
        .to_json_string();
    let reply = fixture.native_bytes_with("PreToolUse", body.as_bytes(), |command| {
        command.current_dir(&fixture.base);
    });
    assert_decision(&reply, "allow");

    let conflicting_session = fixture.native_bytes_with("PreToolUse", body.as_bytes(), |command| {
        command.env("AGENT_GUARD_SESSION_ID", "swm_different_session");
    });
    assert_denied_for(
        &conflicting_session,
        "conflicts with the configured host session",
    );

    let invalid_role = fixture.native_bytes_with("PreToolUse", body.as_bytes(), |command| {
        command.env("AGENT_GUARD_ROLE", "fixture-unknown-role");
    });
    assert_denied_for(&invalid_role, "INVALID_SWARM_ROLE");
}

#[test]
fn native_file_decisions_enforce_workspace_and_config_protection_without_writes() {
    let fixture = Fixture::new();
    let public = fixture.workspace.join("public.txt");
    let outside = fixture.base.join("outside.txt");
    let config = fixture.workspace.join(".agents/hooks.json");
    fs::write(&public, b"plain public text\n").expect("write readable fixture");
    fs::write(&outside, b"outside sentinel\n").expect("write outside fixture");
    fs::create_dir(config.parent().expect("hooks config parent")).expect("create hooks fixture");
    fs::write(&config, b"{}\n").expect("write original hooks fixture");

    let allowed = fixture.native(
        "PreToolUse",
        fixture.tool("view_file", object([("AbsolutePath", path_text(&public))])),
    );
    assert_decision(&allowed, "allow");
    assert!(allowed.get("overwrite").is_none());

    let denied_read = fixture.native(
        "PreToolUse",
        fixture.tool("view_file", object([("AbsolutePath", path_text(&outside))])),
    );
    assert_denied(&denied_read);
    assert!(!denied_read.to_json_string().contains("outside sentinel"));

    for (path, original, reason) in [
        (
            &outside,
            b"outside sentinel\n".as_slice(),
            "REPO_BOUNDARY_ESCAPE",
        ),
        (&config, b"{}\n".as_slice(), "IMMUTABLE_CONTROL_PLANE"),
    ] {
        let body = fixture.tool(
            "write_to_file",
            object([
                ("TargetFile", path_text(path)),
                ("CodeContent", text("replacement text\n")),
                ("Overwrite", JsonValue::Bool(true)),
            ]),
        );
        assert_denied_for(&fixture.native("PreToolUse", body), reason);
        assert_eq!(
            fs::read(path).expect("original file still exists"),
            original
        );
    }
}

#[test]
fn native_tool_requests_fail_closed_on_invalid_protocol() {
    let fixture = Fixture::new();
    assert_denied(&fixture.native_bytes("PreToolUse", b"{\"conversationId\":"));
    assert_denied_for(
        &fixture.native("PreToolUse", fixture.tool("unknown_tool", object([]))),
        "UNRECOGNIZED_TOOL_BLOCKED",
    );
    assert_denied(&fixture.native("UnknownEvent", fixture.request([])));

    let tool_call = object([
        ("name", text("run_command")),
        ("args", object([("CommandLine", text("pwd"))])),
    ]);
    let required = [
        ("conversationId", text(CONVERSATION)),
        ("toolCall", tool_call),
        ("stepIdx", JsonValue::Uint(1)),
    ];
    assert_denied(&fixture.native("PreToolUse", object(required.clone())));
    for roots in [
        vec![path_text(&fixture.base)],
        vec![path_text(&fixture.workspace), path_text(&fixture.base)],
    ] {
        let payload = object(
            required
                .clone()
                .into_iter()
                .chain([("workspacePaths", JsonValue::Array(roots))]),
        );
        assert_denied(&fixture.native("PreToolUse", payload));
    }

    let bad_step = fixture.request([
        (
            "toolCall",
            object([
                ("name", text("run_command")),
                ("args", object([("CommandLine", text("pwd"))])),
            ]),
        ),
        ("stepIdx", text("1")),
    ]);
    assert_denied(&fixture.native("PreToolUse", bad_step));

    let large = fixture.tool(
        "run_command",
        object([("CommandLine", text("x".repeat(OVERSIZED)))]),
    );
    assert_denied(&fixture.native("PreToolUse", large));

    let unicode_wire = fixture
        .tool(
            "run_command",
            object([("CommandLine", text("printf '@CONTROL@'"))]),
        )
        .to_json_string()
        .replace("@CONTROL@", "\\u202e");
    let unicode_reply = fixture.native_bytes("PreToolUse", unicode_wire.as_bytes());
    assert_denied_for(&unicode_reply, "UNICODE_TROJAN_BIDI");
    assert!(unicode_reply.to_json_string().is_ascii());
}

#[test]
fn native_lifecycle_uses_event_specific_responses() {
    let fixture = Fixture::new();
    assert_no_action(&fixture.native("SessionStart", fixture.request([])));
    let invocation = fixture.request([
        ("invocationNum", JsonValue::Uint(1)),
        ("initialNumSteps", JsonValue::Uint(0)),
    ]);
    for event in ["PreInvocation", "PostInvocation"] {
        assert_no_action(&fixture.native(event, invocation.clone()));
    }
    let missing_invocation_fields = fixture.native("PreInvocation", fixture.request([]));
    assert_eq!(
        missing_invocation_fields
            .get("terminationBehavior")
            .and_then(JsonValue::as_str),
        Some("terminate")
    );
    assert!(
        missing_invocation_fields
            .get("injectSteps")
            .and_then(JsonValue::as_array)
            .is_some_and(|steps| !steps.is_empty())
    );
    let file = fixture.workspace.join("file.txt");
    fs::write(&file, b"useful content\n").expect("create file fixture");
    let read = fixture.tool("view_file", object([("AbsolutePath", path_text(&file))]));
    assert_decision(&fixture.native("PreToolUse", read.clone()), "allow");
    assert_no_action(&fixture.native("PostToolUse", read));
    let stop = fixture.native(
        "Stop",
        fixture.request([
            ("executionNum", JsonValue::Uint(1)),
            ("terminationReason", text("completed")),
            ("fullyIdle", JsonValue::Bool(false)),
        ]),
    );
    assert_decision(&stop, "stop");
}

#[test]
fn native_pre_invocation_preserves_the_conversation_circuit_breaker() {
    let fixture = Fixture::new();
    assert_no_action(&fixture.native("SessionStart", fixture.request([])));
    let blocked = fixture.tool(
        "run_command",
        object([("CommandLine", text("agent-guard-sh --help"))]),
    );
    assert_denied_for(
        &fixture.native("PreToolUse", blocked),
        "SELF_TAMPERING_BLOCKED",
    );

    let invocation = fixture.request([
        ("invocationNum", JsonValue::Uint(2)),
        ("initialNumSteps", JsonValue::Uint(3)),
    ]);
    let reply = fixture.native("PreInvocation", invocation);
    assert_eq!(
        reply.get("terminationBehavior").and_then(JsonValue::as_str),
        Some("terminate"),
    );
    let message = reply
        .get("injectSteps")
        .and_then(JsonValue::as_array)
        .and_then(|steps| steps.first())
        .and_then(|step| step.get("errorMessage"))
        .and_then(|error| error.get("userMessage"))
        .and_then(JsonValue::as_str);
    assert!(message.is_some_and(|message| message.contains("SESSION_CIRCUIT_BREAKER_HALTED")));

    let after = fixture.tool("run_command", object([("CommandLine", text("pwd"))]));
    assert_denied_for(
        &fixture.native("PreToolUse", after),
        "SESSION_HALTED_OR_EXHAUSTED",
    );
}

#[test]
fn gemini_before_tool_keeps_the_existing_decision_envelope() {
    let fixture = Fixture::new();
    let body = object([
        ("hook_event_name", text("BeforeTool")),
        ("session_id", text("fixture-gemini-conversation")),
        ("cwd", path_text(&fixture.workspace)),
        ("tool_name", text("run_shell_command")),
        (
            "tool_input",
            object([("command", text("python3 --version"))]),
        ),
    ]);
    let output = invoke(
        fixture.command().arg("pre-tool"),
        body.to_json_string().as_bytes(),
    );
    assert_eq!(output.status.code(), Some(2));
    let reply = one_object(&output.stdout);
    assert_decision(&reply, "block");
    assert_eq!(
        reply
            .get("hookSpecificOutput")
            .and_then(|fields| fields.get("permissionDecision"))
            .and_then(JsonValue::as_str),
        Some("deny")
    );
}
