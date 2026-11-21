#![forbid(unsafe_code)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use agent_guard::crypto::sha256_hex;
use agent_guard::plugin_lattice::{
    VerdictLevel, combine_verdicts, glob_match_path, record_quorum_approval_breadcrumb,
};

fn isolated_env(slug: &str) -> (PathBuf, PathBuf, PathBuf) {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ws_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let base = ws_root
        .join("target")
        .join("test-workspaces")
        .join(format!("ag-c3-{}-{slug}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let repo = base.join("repo");
    let home = base.join("home");
    let state_sessions = base.join("guard-state").join("sessions");
    fs::create_dir_all(repo.join(".git")).expect(".git");
    fs::create_dir_all(repo.join("profiles/plugins")).expect("plugins");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&state_sessions).expect("sessions");
    fs::write(repo.join("AGENTS.md"), "# AGENTS.md\n").expect("AGENTS.md");
    (repo, home, state_sessions)
}

fn run_pre_tool(
    repo: &Path,
    home: &Path,
    state_sessions: &Path,
    payload: &str,
) -> (i32, String, String) {
    let guard_bin = env!("CARGO_BIN_EXE_agent-guard");
    let mut child = Command::new(guard_bin)
        .arg("pre-tool")
        .current_dir(repo)
        .env("HOME", home)
        .env("AGENT_GUARD_STATE_DIR", state_sessions)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pre-tool");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    let out = child.wait_with_output().expect("wait pre-tool");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn write_pinned_profile(repo: &Path, pins: &[(&str, &str)]) {
    let mut toml = String::from("profile_id = \"coding-agent\"\n[plugins]\n");
    for (name, hex) in pins {
        toml.push_str(&format!("\"{name}\" = \"{hex}\"\n"));
    }
    fs::write(repo.join("profiles/coding-agent.toml"), toml).expect("write profile");
}

#[test]
fn malicious_rego_allow_cannot_downgrade_ring0_deny() {
    assert_eq!(
        combine_verdicts(VerdictLevel::Deny, &[VerdictLevel::Allow]),
        VerdictLevel::Deny
    );
    assert_eq!(
        combine_verdicts(
            VerdictLevel::Deny,
            &[VerdictLevel::Allow, VerdictLevel::RequireVoteQuorum]
        ),
        VerdictLevel::Deny
    );

    let (repo, home, state_sessions) = isolated_env("monotone-ring0");
    let rego = "package dotagent.plugin\nverdict := \"allow\"\n";
    fs::write(repo.join("profiles/plugins/always_allow.rego"), rego).expect("write rego");
    write_pinned_profile(
        &repo,
        &[("always_allow.rego", &sha256_hex(rego.as_bytes()))],
    );

    // Ring-0 blocks writing into `profiles/plugins/` (`IMMUTABLE_CONTROL_PLANE`) and reading `.env`
    let write_ctl = format!(
        "{{\"session_id\":\"coder1\",\"cwd\":\"{}\",\"tool_name\":\"Write\",\"tool_input\":{{\"file_path\":\"profiles/plugins/evil.rego\",\"content\":\"x\"}}}}",
        repo.display()
    );
    let (code1, out1, err1) = run_pre_tool(&repo, &home, &state_sessions, &write_ctl);
    let combined1 = format!("{out1}{err1}");
    assert!(
        code1 != 0 || combined1.contains("IMMUTABLE_CONTROL_PLANE"),
        "expected IMMUTABLE_CONTROL_PLANE: code={code1} {combined1}"
    );
    assert!(combined1.contains("IMMUTABLE_CONTROL_PLANE"));

    let write_secret = format!(
        "{{\"session_id\":\"coder1\",\"cwd\":\"{}\",\"tool_name\":\"Write\",\"tool_input\":{{\"file_path\":\".env.production\",\"content\":\"x=1\"}}}}",
        repo.display()
    );
    let (_code2, out2, err2) = run_pre_tool(&repo, &home, &state_sessions, &write_secret);
    let combined2 = format!("{out2}{err2}");
    assert!(
        combined2.contains("FORBIDDEN_SECRET_PATH") || combined2.contains("deny"),
        "Ring-0 secret block must never be downgraded by Rego 'allow': {combined2}"
    );
}

#[test]
fn rego_plugin_quorum_blocks_at_one_approval_and_passes_at_two_distinct_hmac_approvals() {
    let (repo, home, state_sessions) = isolated_env("rego-quorum");
    let rego = r#"package dotagent.plugin

verdict := "require_vote_quorum" if {
    input.is_write
    some p in input.target_rel_paths
    startswith(p, "migrations/")
}

min_approvals := 2
reason := "SQL migrations require 2 distinct reviewer approvals"
"#;
    fs::write(repo.join("profiles/plugins/sql_quorum.rego"), rego).expect("write rego");
    write_pinned_profile(&repo, &[("sql_quorum.rego", &sha256_hex(rego.as_bytes()))]);

    let payload = format!(
        "{{\"session_id\":\"coder_main\",\"cwd\":\"{}\",\"tool_name\":\"Write\",\"tool_input\":{{\"file_path\":\"migrations/001.sql\",\"content\":\"CREATE TABLE t (id INT);\\n\"}}}}",
        repo.display()
    );

    // 0 approvals -> blocked with PLUGIN_QUORUM_REQUIRED
    let (_c0, out0, err0) = run_pre_tool(&repo, &home, &state_sessions, &payload);
    assert!(
        format!("{out0}{err0}").contains("PLUGIN_QUORUM_REQUIRED"),
        "expected PLUGIN_QUORUM_REQUIRED at 0 approvals: {out0}{err0}"
    );

    // Record 1st valid HMAC-signed reviewer breadcrumb approval inside isolated state dir
    spawn_record_approval(
        &repo,
        &home,
        &state_sessions,
        "reviewer_alpha",
        "migrations/001.sql",
    );
    // Duplicate approval by same reviewer_alpha AND self-approval by coder_main must NOT satisfy 2-quorum!
    spawn_record_approval(
        &repo,
        &home,
        &state_sessions,
        "reviewer_alpha",
        "migrations/001.sql",
    );
    spawn_record_approval(
        &repo,
        &home,
        &state_sessions,
        "coder_main",
        "migrations/001.sql",
    );

    let (_c1, out1, err1) = run_pre_tool(&repo, &home, &state_sessions, &payload);
    let combined1 = format!("{out1}{err1}");
    assert!(
        combined1.contains("PLUGIN_QUORUM_REQUIRED") && combined1.contains("1/2"),
        "expected 1/2 approvals blocked: {combined1}"
    );

    // Record 2nd distinct HMAC-verified reviewer approval -> passes!
    spawn_record_approval(
        &repo,
        &home,
        &state_sessions,
        "reviewer_beta",
        "migrations/001.sql",
    );

    let (c2, out2, err2) = run_pre_tool(&repo, &home, &state_sessions, &payload);
    let combined2 = format!("{out2}{err2}");
    assert_eq!(
        c2, 0,
        "expected exit 0 at 2 distinct approvals: {combined2}"
    );
    assert!(
        !combined2.contains("PLUGIN_QUORUM_REQUIRED"),
        "quorum must pass at 2 distinct approvals: {combined2}"
    );
}

#[test]
fn quorum_approval_child_worker() {
    let Ok(repo) = std::env::var("AG_C3_HELPER_REPO") else {
        return;
    };
    let reviewer = std::env::var("AG_C3_HELPER_REVIEWER").expect("reviewer");
    let rel_path = std::env::var("AG_C3_HELPER_PATH").expect("path");
    let repo_path = Path::new(&repo);
    let cap = agent_guard::swarm_contracts::SessionCapability {
        session_id: reviewer.clone(),
        role: agent_guard::swarm_contracts::SwarmRole::AdversarialReviewer,
        task_id: "mig-1".to_string(),
        attempt: 1,
        repo_sha256: "0".repeat(64),
        plan_sha256: "0".repeat(64),
        assigned_read_paths: vec![],
        allowed_write_paths: vec![],
        assigned_tests: vec![],
        last_green_tree_oid: None,
        consecutive_test_failures: 0,
        blocked_scope_attempts: 0,
        malicious_flags: 0,
    };
    agent_guard::role_sandbox::save_session_capability(repo_path, &cap)
        .expect("save reviewer capability");
    record_quorum_approval_breadcrumb(repo_path, &reviewer, "mig-1", &rel_path)
        .expect("record quorum approval breadcrumb");
}

fn spawn_record_approval(
    repo: &Path,
    home: &Path,
    state_sessions: &Path,
    reviewer: &str,
    rel_path: &str,
) {
    let exe = std::env::current_exe().expect("current_exe");
    let st = Command::new(exe)
        .args(["--exact", "quorum_approval_child_worker", "--nocapture"])
        .current_dir(repo)
        .env("HOME", home)
        .env("AGENT_GUARD_STATE_DIR", state_sessions)
        .env("AG_C3_HELPER_REPO", repo)
        .env("AG_C3_HELPER_REVIEWER", reviewer)
        .env("AG_C3_HELPER_PATH", rel_path)
        .status()
        .expect("run child helper");
    assert!(st.success(), "child helper must succeed");
}

#[test]
fn unpinned_or_tampered_plugin_fails_closed_and_toml_plugin_enforces_globs() {
    assert!(glob_match_path("migrations/*.sql", "migrations/001.sql"));
    assert!(!glob_match_path(
        "migrations/*.sql",
        "migrations/sub/001.sql"
    ));
    assert!(glob_match_path("migrations/**", "migrations/sub/001.sql"));

    let (repo, home, state_sessions) = isolated_env("unpinned-fail-closed");
    fs::write(
        repo.join("profiles/plugins/rogue.rego"),
        "package dotagent.plugin\nverdict := \"allow\"\n",
    )
    .expect("write unpinned rego");

    let payload = format!(
        "{{\"session_id\":\"coder1\",\"cwd\":\"{}\",\"tool_name\":\"Write\",\"tool_input\":{{\"file_path\":\"src/lib.rs\",\"content\":\"pub fn ok() {{}}\\n\"}}}}",
        repo.display()
    );
    let (_c, out, err) = run_pre_tool(&repo, &home, &state_sessions, &payload);
    assert!(
        format!("{out}{err}").contains("PLUGIN_INTEGRITY_VIOLATION"),
        "unpinned .rego must fail closed with PLUGIN_INTEGRITY_VIOLATION: {out}{err}"
    );

    // Replace with hash-pinned .toml plugin blocking `schema/*.sql`
    let _ = fs::remove_file(repo.join("profiles/plugins/rogue.rego"));
    let toml_plugin = "[rule]\nwrite_only = true\npath_globs = [\"schema/*.sql\"]\nverdict = \"deny\"\nreason = \"schema frozen\"\n";
    fs::write(repo.join("profiles/plugins/freeze.toml"), toml_plugin).expect("write toml plugin");
    write_pinned_profile(
        &repo,
        &[("freeze.toml", &sha256_hex(toml_plugin.as_bytes()))],
    );

    let (_c_ok, out_ok, err_ok) = run_pre_tool(&repo, &home, &state_sessions, &payload);
    assert!(
        !format!("{out_ok}{err_ok}").contains("PLUGIN_"),
        "clean src/lib.rs write must pass pinned freeze.toml: {out_ok}{err_ok}"
    );

    let blocked_payload = format!(
        "{{\"session_id\":\"coder1\",\"cwd\":\"{}\",\"tool_name\":\"Write\",\"tool_input\":{{\"file_path\":\"schema/v1.sql\",\"content\":\"DROP TABLE t;\\n\"}}}}",
        repo.display()
    );
    let (_c_blk, out_blk, err_blk) = run_pre_tool(&repo, &home, &state_sessions, &blocked_payload);
    assert!(
        format!("{out_blk}{err_blk}").contains("PLUGIN_POLICY_DENIED"),
        "schema/v1.sql write must be denied by freeze.toml: {out_blk}{err_blk}"
    );
}
