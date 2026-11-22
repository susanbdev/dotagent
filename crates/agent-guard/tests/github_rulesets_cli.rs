#![forbid(unsafe_code)]

use std::process::{Command, Output};

use agent_guard::cmd_policy::evaluate_shell_command;
use agent_guard::json::JsonValue;

fn rulesets(args: &[&str], marker: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dotagent"));
    command.env_clear().arg("github-rulesets").args(args);
    if let Some(marker) = marker {
        command.env(marker, "1");
    }
    command.output().expect("execute ruleset CLI fixture")
}

#[test]
fn apply_rejects_each_agent_harness_before_consulting_github() {
    for marker in [
        "AGENT_GUARD_IN_SANDBOX",
        "AGENT_GUARD_WORKER_LOCK",
        "AGENT_GUARD_ROLE",
        "CLAUDECODE",
        "CLAUDE_CODE_ENTRYPOINT",
        "CURSOR_TRACE_ID",
        "CURSOR_AGENT",
        "CODEX_SANDBOX",
        "CODEX_ENV_SANDBOX",
        "GEMINI_CLI",
        "ANTIGRAVITY_AGENT",
    ] {
        let output = rulesets(&["--repo", "fixture/dotagent", "--apply"], Some(marker));
        assert_eq!(output.status.code(), Some(2), "{marker}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(marker),
            "{marker}"
        );
        assert!(output.stdout.is_empty(), "{marker}");
    }
    let output = rulesets(&["--org", "fixture", "--apply"], None);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("interactive operator terminal"));
}

#[test]
fn agent_shell_allows_only_offline_ruleset_commands() {
    let root = std::env::current_dir().expect("checkout path");
    for command in [
        "dotagent github-rulesets --repo fixture/dotagent --apply",
        "agent-guard guard github-rulesets --org fixture --verify",
    ] {
        let violation = evaluate_shell_command(command, &root, &root, false)
            .expect_err("deny live rulesets in the agent shell");
        assert_eq!(violation.code, "SELF_TAMPERING_BLOCKED");
    }
    assert!(
        evaluate_shell_command(
            "dotagent github-rulesets --org fixture --dry-run",
            &root,
            &root,
            false,
        )
        .is_ok()
    );
}

#[test]
fn native_help_and_plan_work_in_a_clean_environment() {
    let output = rulesets(&["--help"], None);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("github-rulesets"));
    let output = rulesets(
        &["--repo", "fixture/dotagent", "--dry-run"],
        Some("CODEX_SANDBOX"),
    );
    assert!(output.status.success());
    let plan =
        JsonValue::parse(&String::from_utf8(output.stdout).expect("UTF-8")).expect("JSON plan");
    assert_eq!(
        plan.get("endpoint").and_then(JsonValue::as_str),
        Some("repos/fixture/dotagent/rulesets")
    );
}
