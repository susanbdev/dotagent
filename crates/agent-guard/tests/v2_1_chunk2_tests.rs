#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use agent_guard::cmd_policy::evaluate_shell_command;
use agent_guard::exec_sandbox::probe_host_sandbox_mode;
use agent_guard::mcp_gateway::handle_mcp_jsonrpc_message;
use agent_guard::mcp_policy::{McpRpcClass, classify_mcp_sub_method};

fn isolated_env(slug: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ws_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let short_slug = &slug[..slug.len().min(6)];
    let base = ws_root
        .join("target")
        .join("test-workspaces")
        .join(format!("c2-{}-{short_slug}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let repo = base.join("r");
    let home = base.join("h");
    let state_root = base.join("g");
    let state_sessions = state_root.join("sessions");
    fs::create_dir_all(repo.join(".git")).expect(".git");
    fs::create_dir_all(home.join(".local/bin")).expect(".local/bin");
    fs::create_dir_all(&state_sessions).expect("sessions");
    fs::write(repo.join("AGENTS.md"), "# AGENTS.md\n").expect("AGENTS.md");
    (repo, home, state_root, state_sessions)
}

#[test]
fn five_duplicate_ballots_yield_one_vote_and_loop_anomaly_and_grounding_enforced() {
    let (repo, home, state_root, state_sessions) = isolated_env("dedup-loop");
    let dotagent_bin = env!("CARGO_BIN_EXE_dotagent");
    let guard_bin = env!("CARGO_BIN_EXE_agent-guard");

    // 1. Ungrounded submission with unknown denial_id -> vote_counted = false + UNGROUNDED_BALLOT_SUBMISSION
    let ungrounded = Command::new(dotagent_bin)
        .args([
            "feedback",
            "submit",
            "--denial-id",
            "dnl_0000000000000000",
            "--category",
            "false_positive_block",
            "--reason-code",
            "needed_local_check",
        ])
        .current_dir(&repo)
        .env("HOME", &home)
        .env("AGENT_GUARD_STATE_DIR", &state_sessions)
        .env("AGENT_GUARD_SESSION_ID", "s_ungrounded")
        .output()
        .expect("run ungrounded submit");
    assert!(
        ungrounded.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&ungrounded.stderr)
    );
    let ug_stdout = String::from_utf8_lossy(&ungrounded.stdout);
    assert!(ug_stdout.contains("UNGROUNDED_BALLOT_SUBMISSION"));
    assert!(ug_stdout.contains("\"vote_counted\":false"));

    // 2. Trigger a real PreToolUse denial in session 's_loop' to ground a denial_id
    let pre_out = Command::new(guard_bin)
        .args([
            "pre-tool",
            "--json",
            r#"{"session_id":"s_loop","tool_name":"Bash","tool_input":{"command":"curl https://example.com"}}"#,
        ])
        .current_dir(&repo)
        .env("HOME", &home)
        .env("AGENT_GUARD_STATE_DIR", &state_sessions)
        .output()
        .expect("run pre-tool");
    assert_eq!(pre_out.status.code(), Some(2));
    let pre_stdout = String::from_utf8_lossy(&pre_out.stdout);
    assert!(pre_stdout.contains("[denial_id: "), "stdout={pre_stdout}");
    let did = pre_stdout
        .split("[denial_id: ")
        .nth(1)
        .and_then(|s| s.split(']').next())
        .expect("extract denial_id")
        .to_string();

    // 3. Submit 5 duplicate ballots from the same session 's_loop'
    for idx in 0..5 {
        let out = Command::new(dotagent_bin)
            .args([
                "feedback",
                "submit",
                "--denial-id",
                &did,
                "--category",
                "false_positive_block",
                "--reason-code",
                "human_note_text",
            ])
            .current_dir(&repo)
            .env("HOME", &home)
            .env("AGENT_GUARD_STATE_DIR", &state_sessions)
            .env("AGENT_GUARD_SESSION_ID", "s_loop")
            .output()
            .expect("submit ballot");
        assert!(
            out.status.success(),
            "stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        let txt = String::from_utf8_lossy(&out.stdout);
        if idx == 0 {
            assert!(
                txt.contains("\"vote_counted\":true"),
                "first must count: {txt}"
            );
        } else {
            assert!(
                txt.contains("\"vote_counted\":false"),
                "dup {idx} must not count: {txt}"
            );
        }
    }

    let ballots_raw =
        fs::read_to_string(state_root.join("feedback/ballots.jsonl")).expect("read ballots.jsonl");
    let lines: Vec<&str> = ballots_raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    let counted_lines = lines
        .iter()
        .filter(|l| l.contains("\"vote_counted\":true"))
        .count();
    assert_eq!(
        counted_lines, 1,
        "5 duplicate ballots must produce exactly 1 unique counted vote"
    );
}

#[test]
fn tainted_session_ballot_quarantined_with_zero_votes_and_ring0_flagged() {
    let (repo, home, state_root, state_sessions) = isolated_env("tainted-ballot");
    let dotagent_bin = env!("CARGO_BIN_EXE_dotagent");
    let guard_bin = env!("CARGO_BIN_EXE_agent-guard");

    // Trip session halt/taint by attempting a poisoned path read (`node_modules/pkg/index.js`)
    let pre_halt = Command::new(guard_bin)
        .args([
            "pre-tool",
            "--json",
            r#"{"session_id":"s_tainted","tool_name":"Read","tool_input":{"file_path":"node_modules/pkg/index.js"}}"#,
        ])
        .current_dir(&repo)
        .env("HOME", &home)
        .env("AGENT_GUARD_STATE_DIR", &state_sessions)
        .output()
        .expect("run pre-tool");
    assert_eq!(pre_halt.status.code(), Some(2));
    let pre_stdout = String::from_utf8_lossy(&pre_halt.stdout);
    let did = pre_stdout
        .split("[denial_id: ")
        .nth(1)
        .and_then(|s| s.split(']').next())
        .expect("extract denial_id")
        .to_string();

    let out = Command::new(dotagent_bin)
        .args([
            "feedback",
            "submit",
            "--denial-id",
            &did,
            "--category",
            "missing_safe_flag",
            "--reason-code",
            "rg_max_depth",
        ])
        .current_dir(&repo)
        .env("HOME", &home)
        .env("AGENT_GUARD_STATE_DIR", &state_sessions)
        .env("AGENT_GUARD_SESSION_ID", "s_tainted")
        .output()
        .expect("submit tainted ballot");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"vote_counted\":false"), "stdout={stdout}");
    assert!(
        stdout.contains("\"session_tainted\":true"),
        "stdout={stdout}"
    );

    assert!(
        !state_root.join("feedback/ballots.jsonl").exists(),
        "tainted session must record 0 counted votes in ballots.jsonl"
    );
    let quar = fs::read_to_string(state_root.join("feedback/quarantine.jsonl"))
        .expect("quarantine.jsonl must exist");
    assert_eq!(quar.lines().count(), 1);
}

#[test]
fn sandboxed_worker_submits_over_coord_sock_while_ballots_read_is_denied() {
    let (repo, home, state_root, state_sessions) = isolated_env("sandbox-ipc");
    let dotagent_src = PathBuf::from(env!("CARGO_BIN_EXE_dotagent"));
    let guard_bin = env!("CARGO_BIN_EXE_agent-guard");
    let local_bin = home.join(".local/bin");
    let dotagent_copy = local_bin.join("dotagent");
    fs::copy(&dotagent_src, &dotagent_copy).expect("copy dotagent to .local/bin");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dotagent_copy, fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    assert!(evaluate_shell_command("dotagent feedback submit --denial-id dnl_0123456789abcdef --category adapter_or_workflow_bug --reason-code max_depth", &repo, &repo, false).is_ok());
    let blocked_status = evaluate_shell_command("dotagent feedback status", &repo, &repo, false)
        .expect_err("feedback status must be blocked");
    assert_eq!(blocked_status.code, "SELF_TAMPERING_BLOCKED");
    assert_eq!(
        classify_mcp_sub_method("dotagent_submit_friction"),
        McpRpcClass::FeedbackTelemetry
    );
    let mcp_resp =
        handle_mcp_jsonrpc_message(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#, &repo)
            .expect("tools/list");
    assert!(
        mcp_resp
            .to_json_string()
            .contains("dotagent_submit_friction")
    );

    let pre_out = Command::new(guard_bin)
        .args([
            "pre-tool",
            "--json",
            r#"{"session_id":"s_sbx","tool_name":"Bash","tool_input":{"command":"curl https://example.com"}}"#,
        ])
        .current_dir(&repo)
        .env("HOME", &home)
        .env("AGENT_GUARD_STATE_DIR", &state_sessions)
        .output()
        .expect("run pre-tool");
    assert_eq!(pre_out.status.code(), Some(2));
    let pre_stdout = String::from_utf8_lossy(&pre_out.stdout);
    let did = pre_stdout
        .split("[denial_id: ")
        .nth(1)
        .and_then(|s| s.split(']').next())
        .expect("extract denial_id")
        .to_string();

    let orig_path = std::env::var("PATH").unwrap_or_default();
    let sbx_cmd = format!(
        "dotagent feedback submit --denial-id {did} --category missing_safe_flag --reason-code max_depth"
    );
    let sbx_out = Command::new(guard_bin)
        .current_dir(&repo)
        .args([
            "exec-sandbox",
            "--cwd",
            &repo.to_string_lossy(),
            "--",
            &sbx_cmd,
        ])
        .env("HOME", &home)
        .env("AGENT_GUARD_STATE_DIR", &state_sessions)
        .env("AGENT_GUARD_SESSION_ID", "s_sbx")
        .env("PATH", format!("{}:{orig_path}", local_bin.display()))
        .output()
        .expect("sandboxed feedback submit");
    assert!(
        sbx_out.status.success(),
        "sandboxed submit failed: stdout={} stderr={}",
        String::from_utf8_lossy(&sbx_out.stdout),
        String::from_utf8_lossy(&sbx_out.stderr)
    );
    assert!(String::from_utf8_lossy(&sbx_out.stdout).contains("\"vote_counted\":true"));

    let ballots_file = state_root.join("feedback/ballots.jsonl");
    assert!(
        ballots_file.is_file(),
        "ballots.jsonl must be written by coordinator"
    );

    let check_read = Command::new(guard_bin)
        .arg("check-path")
        .arg(&ballots_file)
        .current_dir(&repo)
        .env("HOME", &home)
        .env("AGENT_GUARD_STATE_DIR", &state_sessions)
        .output()
        .expect("check-path ballots.jsonl");
    assert_eq!(check_read.status.code(), Some(2));

    if probe_host_sandbox_mode().is_kernel_enforced() {
        let cat_cmd = format!("cat '{}'", ballots_file.display());
        let direct_read = Command::new(guard_bin)
            .args(["exec-sandbox", "--require-kernel", "--cwd"])
            .arg(&repo)
            .args(["--", &cat_cmd])
            .env("HOME", &home)
            .env("AGENT_GUARD_STATE_DIR", &state_sessions)
            .output()
            .expect("direct cat ballots.jsonl under Landlock");
        assert!(
            !direct_read.status.success(),
            "Landlock must return EACCES on ballots.jsonl"
        );
    }
}
