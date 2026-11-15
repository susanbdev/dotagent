#![forbid(unsafe_code)]

//! End-to-end process-level CLI delegation tests verifying `swarm-tool` across
//! all 6 roles (`master`, `investigator`, `qa`, `grunt`, `reviewer`, `coroner`)
//! and fail-closed `agent-guard on-stop` enforcement (`F32` / `F33`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use agent_guard::json::JsonValue;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn swarm_tool_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_swarm-tool"))
}

fn agent_guard_bin() -> PathBuf {
    let mut p = swarm_tool_bin();
    p.set_file_name("agent-guard");
    if !p.exists() {
        let status = Command::new("cargo")
            .args(["build", "-p", "agent-guard", "--quiet"])
            .current_dir(workspace_root())
            .status()
            .expect("build agent-guard");
        assert!(status.success());
    }
    p
}

#[test]
fn end_to_end_swarm_tool_role_delegation_and_fail_closed_on_stop_cli() {
    let dir = workspace_root()
        .join("target")
        .join("test-workspaces")
        .join("e2e_cli_delegation");
    let _ = fs::remove_dir_all(&dir);
    let repo = dir.join("repo");
    let state = dir.join("state");
    fs::create_dir_all(repo.join(".git").join("info")).unwrap();
    fs::create_dir_all(repo.join("src")).unwrap();
    fs::create_dir_all(repo.join("tests")).unwrap();
    fs::create_dir_all(&state).unwrap();

    fs::write(repo.join("AGENTS.md"), "# Canonical Root AGENTS.md\n").unwrap();
    fs::write(
        repo.join("Cargo.lock"),
        "version = 3\n\n[[package]]\nname = \"sha2\"\nversion = \"0.10.9\"\n",
    )
    .unwrap();
    fs::write(
        repo.join("src/calc.rs"),
        "pub fn clamp_pct(v: u8) -> u8 { v.min(100) }\n",
    )
    .unwrap();
    fs::write(
        repo.join("plan.dag.json"),
        r#"{
  "plan_id": "E2E-SWARM-DEMO",
  "tasks": [
    {
      "id": "TASK-1",
      "wave": "W1",
      "depends_on": [],
      "domain_risk": "security_critical",
      "assigned_read_paths": ["src/calc.rs"],
      "allowed_write_paths": ["src/calc.rs"],
      "assigned_tests": ["calc_bounds_test"]
    }
  ]
}"#,
    )
    .unwrap();
    fs::write(
        repo.join("tests/test_attribution.toml"),
        r#"[[tests]]
name = "calc_bounds_test"
primary_suspect = "TASK-1"
secondary_suspects = []
boundary_interfaces = []
"#,
    )
    .unwrap();

    // 1. MASTER: lock wave DAG & mint Investigator + Grunt sessions
    let lock_out = Command::new(swarm_tool_bin())
        .args(["master", "lock-plan", "plan.dag.json"])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .output()
        .unwrap();
    assert!(
        lock_out.status.success(),
        "lock-plan stderr: {}",
        String::from_utf8_lossy(&lock_out.stderr)
    );

    let inv_mint = Command::new(swarm_tool_bin())
        .args([
            "master",
            "mint-session",
            "--role",
            "investigator",
            "--task",
            "TASK-1",
        ])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .output()
        .unwrap();
    assert!(inv_mint.status.success());
    let inv_json = JsonValue::parse(&String::from_utf8_lossy(&inv_mint.stdout)).unwrap();
    let inv_sid = inv_json
        .get("session_id")
        .and_then(JsonValue::as_str)
        .unwrap()
        .to_string();

    // 2. INVESTIGATOR: deep scout + emit <=200-token ObservedFact packet -> MASTER ingests it
    let scout_out = Command::new(swarm_tool_bin())
        .args(["investigator", "scout", "--dir", "src", "--max-depth", "20"])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .output()
        .unwrap();
    assert!(scout_out.status.success());
    assert!(String::from_utf8_lossy(&scout_out.stdout).contains("src/calc.rs:1: pub fn clamp_pct"));

    let fact_out = Command::new(swarm_tool_bin())
        .args([
            "investigator",
            "emit-fact",
            "--session",
            &inv_sid,
            "--task",
            "TASK-1",
            "--claim",
            "clamp_pct is defined in src/calc.rs line 1.",
            "--slice",
            "src/calc.rs:1-1",
        ])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .output()
        .unwrap();
    assert!(fact_out.status.success());
    let fact_pkt = String::from_utf8_lossy(&fact_out.stdout).trim().to_string();

    let ingest_out = Command::new(swarm_tool_bin())
        .args(["master", "ingest-packet", &fact_pkt])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .output()
        .unwrap();
    assert!(ingest_out.status.success());

    // 3. QA ENGINEER: coverage-targets, verify-attribution, triangulate
    let cov_out = Command::new(swarm_tool_bin())
        .args(["qa", "coverage-targets"])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .output()
        .unwrap();
    assert!(cov_out.status.success());
    assert!(String::from_utf8_lossy(&cov_out.stdout).contains("92"));

    let attr_out = Command::new(swarm_tool_bin())
        .args(["qa", "verify-attribution", "tests/test_attribution.toml"])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .output()
        .unwrap();
    assert!(attr_out.status.success());

    // 4. GRUNT: mint session -> verify `agent-guard on-stop` FAILS CLOSED (exit 2) before ledger!
    let grunt_mint = Command::new(swarm_tool_bin())
        .args([
            "master",
            "mint-session",
            "--role",
            "grunt",
            "--task",
            "TASK-1",
        ])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .output()
        .unwrap();
    assert!(grunt_mint.status.success());
    let grunt_sid = JsonValue::parse(&String::from_utf8_lossy(&grunt_mint.stdout))
        .unwrap()
        .get("session_id")
        .and_then(JsonValue::as_str)
        .unwrap()
        .to_string();

    let premature_stop = Command::new(agent_guard_bin())
        .arg("on-stop")
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .env("AGENT_GUARD_ROLE", "grunt")
        .env("AGENT_GUARD_SESSION_ID", &grunt_sid)
        .output()
        .unwrap();
    assert_eq!(
        premature_stop.status.code(),
        Some(2),
        "Grunt stopping without WORK_LEDGER receipt MUST fail closed with exit 2"
    );

    // Grunt edits file, logs breadcrumb, runs checkpoint-green (`true`), and submits 2+2 ledger
    fs::write(
        repo.join("src/calc.rs"),
        "pub fn clamp_pct(v: u8) -> u8 { v.clamp(0, 95) }\n",
    )
    .unwrap();
    assert!(
        Command::new(swarm_tool_bin())
            .args([
                "grunt",
                "record-edit",
                "--session",
                &grunt_sid,
                "--file",
                "src/calc.rs",
                "--lines",
                "1-1",
            ])
            .current_dir(&repo)
            .env("AGENT_GUARD_STATE_DIR", &state)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(swarm_tool_bin())
            .args([
                "grunt",
                "checkpoint-green",
                "--session",
                &grunt_sid,
                "--",
                "true",
            ])
            .current_dir(&repo)
            .env("AGENT_GUARD_STATE_DIR", &state)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(swarm_tool_bin())
            .args([
                "grunt",
                "submit-ledger",
                "--session",
                &grunt_sid,
                "--what",
                "Updated clamp_pct upper bound to 95 in src/calc.rs. Recorded authenticated edit breadcrumb.",
                "--why",
                "Swarm QA domain coverage ceiling caps targets at 95 percent. Verified green test checkpoint on current tree.",
            ])
            .current_dir(&repo)
            .env("AGENT_GUARD_STATE_DIR", &state)
            .status()
            .unwrap()
            .success()
    );

    // Now `agent-guard on-stop` MUST PASS (exit 0)!
    let valid_stop = Command::new(agent_guard_bin())
        .arg("on-stop")
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .env("AGENT_GUARD_ROLE", "grunt")
        .env("AGENT_GUARD_SESSION_ID", &grunt_sid)
        .output()
        .unwrap();
    assert!(
        valid_stop.status.success(),
        "valid Grunt stop stderr: {}",
        String::from_utf8_lossy(&valid_stop.stderr)
    );

    // 5. REVIEWER & CORONER: verify lockfile lookup, verdict, and HMAC breadcrumb trail
    assert!(
        Command::new(swarm_tool_bin())
            .args([
                "reviewer",
                "lookup-doc",
                "--ecosystem",
                "cargo",
                "--package",
                "sha2",
                "--version",
                "0.10.9",
            ])
            .current_dir(&repo)
            .env("AGENT_GUARD_STATE_DIR", &state)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(swarm_tool_bin())
            .args(["coroner", "verify-trail", "src/.breadcrumbs.jsonl"])
            .current_dir(&repo)
            .env("AGENT_GUARD_STATE_DIR", &state)
            .status()
            .unwrap()
            .success()
    );

    // 6. PR #2 CLI regressions:
    // (a) Investigator session cannot invoke `swarm-tool grunt` (`ROLE_CAPABILITY_MISMATCH`)
    let cross_role = Command::new(swarm_tool_bin())
        .args(["grunt", "context", "--session", &inv_sid])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .output()
        .unwrap();
    assert!(!cross_role.status.success());
    assert!(
        String::from_utf8_lossy(&cross_role.stderr).contains("ROLE_CAPABILITY_MISMATCH"),
        "expected ROLE_CAPABILITY_MISMATCH, got: {}",
        String::from_utf8_lossy(&cross_role.stderr)
    );

    // (b) `AGENT_GUARD_ROLE=standard` cannot downgrade a minted Grunt session on `on-stop`
    let downgrade_stop = Command::new(agent_guard_bin())
        .arg("on-stop")
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .env("AGENT_GUARD_ROLE", "standard")
        .env("AGENT_GUARD_SESSION_ID", &grunt_sid)
        .output()
        .unwrap();
    assert_eq!(downgrade_stop.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&downgrade_stop.stderr).contains("ROLE_CAPABILITY_MISMATCH"),
        "expected ROLE_CAPABILITY_MISMATCH on env role downgrade, got: {}",
        String::from_utf8_lossy(&downgrade_stop.stderr)
    );

    // (c) `coroner recover-spool` flushes nested `src/calc.rs` events to `src/.breadcrumbs.jsonl`
    fs::remove_file(repo.join("src/.breadcrumbs.jsonl")).unwrap();
    let rec_out = Command::new(swarm_tool_bin())
        .args(["coroner", "recover-spool", &grunt_sid])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .output()
        .unwrap();
    assert!(
        rec_out.status.success(),
        "recover-spool stderr: {}",
        String::from_utf8_lossy(&rec_out.stderr)
    );
    assert!(
        repo.join("src/.breadcrumbs.jsonl").exists(),
        "recover-spool must recreate src/.breadcrumbs.jsonl for src/calc.rs edit events"
    );
    assert!(
        Command::new(swarm_tool_bin())
            .args(["coroner", "verify-trail", "src/.breadcrumbs.jsonl"])
            .current_dir(&repo)
            .env("AGENT_GUARD_STATE_DIR", &state)
            .status()
            .unwrap()
            .success()
    );
}
