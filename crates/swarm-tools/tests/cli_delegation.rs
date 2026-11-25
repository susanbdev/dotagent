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

/// Runs `cmd`, retrying only on `ETXTBSY` (os error 26). Exec of a freshly copied binary can
/// race a concurrent `fork` in another test thread that still holds the copy's write fd.
fn retry_output_on_etxtbsy(cmd: &mut Command) -> std::io::Result<std::process::Output> {
    const ATTEMPTS: u32 = 5;
    const BACKOFF: std::time::Duration = std::time::Duration::from_millis(15);
    let mut attempt = 1;
    loop {
        match cmd.output() {
            Err(e) if e.raw_os_error() == Some(26) && attempt < ATTEMPTS => {
                attempt += 1;
                std::thread::sleep(BACKOFF);
            }
            other => return other,
        }
    }
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
        repo.join("tests/test_calc.py"),
        concat!(
            "import pathlib, unittest\n",
            "class CalcBoundsTest(unittest.TestCase):\n",
            "    def test_clamp_95(self):\n",
            "        src = pathlib.Path('src/calc.rs').read_text(encoding='utf-8')\n",
            "        self.assertIn('clamp(0, 95)', src)\n",
            "if __name__ == '__main__':\n",
            "    unittest.main()\n",
        ),
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
      "assigned_read_paths": ["src/calc.rs", "tests/test_calc.py"],
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

    // 1. MASTER: lock wave DAG & mint Investigator session
    let lock_out = Command::new(swarm_tool_bin())
        .args(["master", "lock-plan", "plan.dag.json"])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .env("AGENT_GUARD_ROLE", "master")
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
        .env("AGENT_GUARD_ROLE", "master")
        .output()
        .unwrap();
    assert!(inv_mint.status.success());
    let inv_json = JsonValue::parse(&String::from_utf8_lossy(&inv_mint.stdout)).unwrap();
    let inv_sid = inv_json
        .get("session_id")
        .and_then(JsonValue::as_str)
        .unwrap()
        .to_string();

    // 2. INVESTIGATOR: deep scout + emit <=200-token ObservedFact packet -> MASTER ingests it & closes session
    let scout_out = Command::new(swarm_tool_bin())
        .args(["investigator", "scout", "--dir", "src", "--max-depth", "20"])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .output()
        .unwrap();
    assert!(
        scout_out.status.success(),
        "investigator scout stderr: {}",
        String::from_utf8_lossy(&scout_out.stderr)
    );
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
        .env("AGENT_GUARD_ROLE", "master")
        .output()
        .unwrap();
    assert!(
        ingest_out.status.success(),
        "ingest-packet stderr: {}",
        String::from_utf8_lossy(&ingest_out.stderr)
    );
    assert!(
        Command::new(swarm_tool_bin())
            .args(["master", "close-session", "--session", &inv_sid])
            .current_dir(&repo)
            .env("AGENT_GUARD_STATE_DIR", &state)
            .env("AGENT_GUARD_ROLE", "master")
            .status()
            .unwrap()
            .success()
    );

    // 3. QA ENGINEER: mint QA capability -> coverage-targets, verify-attribution -> close QA session
    let qa_mint = Command::new(swarm_tool_bin())
        .args(["master", "mint-session", "--role", "qa", "--task", "TASK-1"])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .env("AGENT_GUARD_ROLE", "master")
        .output()
        .unwrap();
    assert!(qa_mint.status.success());
    let qa_sid = JsonValue::parse(&String::from_utf8_lossy(&qa_mint.stdout))
        .unwrap()
        .get("session_id")
        .and_then(JsonValue::as_str)
        .unwrap()
        .to_string();

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

    assert!(
        Command::new(swarm_tool_bin())
            .args(["master", "close-session", "--session", &qa_sid])
            .current_dir(&repo)
            .env("AGENT_GUARD_STATE_DIR", &state)
            .env("AGENT_GUARD_ROLE", "master")
            .status()
            .unwrap()
            .success()
    );

    // 4. GRUNT: mint session -> verify `agent-guard on-stop` FAILS CLOSED (exit 2) before ledger,
    //    EVEN when neither AGENT_GUARD_ROLE nor AGENT_GUARD_SESSION_ID is passed in env!
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
        .env("AGENT_GUARD_ROLE", "master")
        .output()
        .unwrap();
    assert!(grunt_mint.status.success());
    let grunt_sid = JsonValue::parse(&String::from_utf8_lossy(&grunt_mint.stdout))
        .unwrap()
        .get("session_id")
        .and_then(JsonValue::as_str)
        .unwrap()
        .to_string();

    let hardened_gitconfig = workspace_root().join("dist/gitconfig.hardened");
    let premature_envless_stop = Command::new(agent_guard_bin())
        .arg("on-stop")
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .env("GIT_CONFIG_GLOBAL", &hardened_gitconfig)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("AGENT_GUARD_ROLE")
        .env_remove("AGENT_GUARD_SESSION_ID")
        .output()
        .unwrap();
    assert_eq!(
        premature_envless_stop.status.code(),
        Some(2),
        "Grunt stopping without env vars MUST still fail closed via active_sessions.json"
    );
    assert!(
        String::from_utf8_lossy(&premature_envless_stop.stderr)
            .contains("GRUNT_MISSING_WORK_LEDGER"),
        "expected GRUNT_MISSING_WORK_LEDGER, got: {}",
        String::from_utf8_lossy(&premature_envless_stop.stderr)
    );

    // While Grunt slot is open, unauthenticated `swarm-tool master` escalation MUST fail closed
    let grunt_master_escalate = Command::new(swarm_tool_bin())
        .args(["master", "status"])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .env_remove("AGENT_GUARD_ROLE")
        .env_remove("AGENT_GUARD_SESSION_ID")
        .output()
        .unwrap();
    assert!(!grunt_master_escalate.status.success());
    assert!(
        String::from_utf8_lossy(&grunt_master_escalate.stderr).contains("ROLE_CAPABILITY_MISMATCH"),
        "expected ROLE_CAPABILITY_MISMATCH on unauthenticated master call during Grunt slot, got: {}",
        String::from_utf8_lossy(&grunt_master_escalate.stderr)
    );

    // Grunt edits file, logs breadcrumb, verifies `-- true` is rejected, runs real unittest checkpoint, and submits 2+2 ledger
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

    let fake_true_checkpoint = Command::new(swarm_tool_bin())
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
        .output()
        .unwrap();
    assert!(!fake_true_checkpoint.status.success());
    assert!(
        String::from_utf8_lossy(&fake_true_checkpoint.stderr)
            .contains("INVALID_TEST_RUNNER_COMMAND"),
        "expected INVALID_TEST_RUNNER_COMMAND on `-- true`, got: {}",
        String::from_utf8_lossy(&fake_true_checkpoint.stderr)
    );

    let kernel_enforced = agent_guard::exec_sandbox::probe_host_sandbox_mode().is_kernel_enforced();
    let real_checkpoint = Command::new(swarm_tool_bin())
        .args([
            "grunt",
            "checkpoint-green",
            "--session",
            &grunt_sid,
            "--",
            "python3",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
        ])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .output()
        .unwrap();
    if kernel_enforced {
        assert!(
            real_checkpoint.status.success(),
            "real unittest checkpoint stderr: {}",
            String::from_utf8_lossy(&real_checkpoint.stderr)
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

        // Now `agent-guard on-stop` MUST PASS (exit 0) even without env vars, and close Grunt in `active_sessions.json`!
        let valid_stop = Command::new(agent_guard_bin())
            .arg("on-stop")
            .current_dir(&repo)
            .env("AGENT_GUARD_STATE_DIR", &state)
            .env("GIT_CONFIG_GLOBAL", &hardened_gitconfig)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("AGENT_GUARD_ROLE")
            .env_remove("AGENT_GUARD_SESSION_ID")
            .output()
            .unwrap();
        assert!(
            valid_stop.status.success(),
            "valid Grunt stop stderr: {}",
            String::from_utf8_lossy(&valid_stop.stderr)
        );
    } else {
        assert!(!real_checkpoint.status.success());
        assert!(
            String::from_utf8_lossy(&real_checkpoint.stderr).contains("KERNEL_SANDBOX_UNAVAILABLE"),
            "degraded kernel must fail closed on checkpoint-green: {}",
            String::from_utf8_lossy(&real_checkpoint.stderr)
        );
        assert!(
            Command::new(swarm_tool_bin())
                .args(["master", "close-session", "--session", &grunt_sid])
                .current_dir(&repo)
                .env("AGENT_GUARD_STATE_DIR", &state)
                .env("AGENT_GUARD_ROLE", "master")
                .status()
                .unwrap()
                .success()
        );
    }

    // 5. REVIEWER & CORONER: mint capabilities -> verify lockfile lookup and HMAC breadcrumb trail
    let rev_mint = Command::new(swarm_tool_bin())
        .args([
            "master",
            "mint-session",
            "--role",
            "reviewer",
            "--task",
            "TASK-1",
        ])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .env("AGENT_GUARD_ROLE", "master")
        .output()
        .unwrap();
    assert!(rev_mint.status.success());
    let rev_sid = JsonValue::parse(&String::from_utf8_lossy(&rev_mint.stdout))
        .unwrap()
        .get("session_id")
        .and_then(JsonValue::as_str)
        .unwrap()
        .to_string();

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
            .args(["master", "close-session", "--session", &rev_sid])
            .current_dir(&repo)
            .env("AGENT_GUARD_STATE_DIR", &state)
            .env("AGENT_GUARD_ROLE", "master")
            .status()
            .unwrap()
            .success()
    );

    let cor_mint = Command::new(swarm_tool_bin())
        .args([
            "master",
            "mint-session",
            "--role",
            "coroner",
            "--task",
            "TASK-1",
        ])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .env("AGENT_GUARD_ROLE", "master")
        .output()
        .unwrap();
    assert!(cor_mint.status.success());
    let cor_sid = JsonValue::parse(&String::from_utf8_lossy(&cor_mint.stdout))
        .unwrap()
        .get("session_id")
        .and_then(JsonValue::as_str)
        .unwrap()
        .to_string();

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
        .env("GIT_CONFIG_GLOBAL", &hardened_gitconfig)
        .env("GIT_CONFIG_NOSYSTEM", "1")
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
        .args([
            "coroner",
            "recover-spool",
            &grunt_sid,
            "--session",
            &cor_sid,
        ])
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
            .args([
                "coroner",
                "verify-trail",
                "src/.breadcrumbs.jsonl",
                "--session",
                &cor_sid
            ])
            .current_dir(&repo)
            .env("AGENT_GUARD_STATE_DIR", &state)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn pr6_cli_capabilities_packet_provenance_and_landlock_vault_coordinator_e2e() {
    let dir = workspace_root()
        .join("target")
        .join("test-workspaces")
        .join("e2e_pr6_vault_coordinator");
    let _ = fs::remove_dir_all(&dir);
    let repo = dir.join("repo");
    let state = dir.join("state");
    fs::create_dir_all(repo.join(".git").join("info")).unwrap();
    fs::create_dir_all(repo.join("src")).unwrap();
    fs::create_dir_all(repo.join("tests")).unwrap();
    fs::create_dir_all(&state).unwrap();

    fs::write(repo.join("AGENTS.md"), "# Canonical Root AGENTS.md\n").unwrap();
    fs::write(repo.join("src/mod_a.rs"), "pub fn alpha() -> u8 { 1 }\n").unwrap();
    fs::write(
        repo.join("plan.dag.json"),
        r#"{
  "plan_id": "PR6-VAULT-E2E",
  "tasks": [
    {
      "id": "TASK-V1",
      "wave": "W1",
      "depends_on": [],
      "domain_risk": "security_critical",
      "assigned_read_paths": ["src/mod_a.rs", "tests/test_vault_isolated.py"],
      "allowed_write_paths": ["src/mod_a.rs"],
      "assigned_tests": ["vault_isolation_test"]
    }
  ]
}"#,
    )
    .unwrap();

    // 1. Findings #8 & #11: Unauthenticated `master` and `investigator scout` calls fail closed
    let unauth_master = Command::new(swarm_tool_bin())
        .args(["master", "status"])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .env_remove("AGENT_GUARD_ROLE")
        .env_remove("AGENT_GUARD_SESSION_ID")
        .output()
        .unwrap();
    assert!(!unauth_master.status.success());
    assert!(
        String::from_utf8_lossy(&unauth_master.stderr).contains("MISSING_SWARM_CAPABILITY"),
        "expected MISSING_SWARM_CAPABILITY on unauthenticated master, got: {}",
        String::from_utf8_lossy(&unauth_master.stderr)
    );

    let unauth_scout = Command::new(swarm_tool_bin())
        .args(["investigator", "scout", "--dir", "src"])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .env_remove("AGENT_GUARD_ROLE")
        .env_remove("AGENT_GUARD_SESSION_ID")
        .output()
        .unwrap();
    assert!(!unauth_scout.status.success());
    assert!(
        String::from_utf8_lossy(&unauth_scout.stderr).contains("MISSING_SWARM_CAPABILITY"),
        "expected MISSING_SWARM_CAPABILITY on unauthenticated investigator scout, got: {}",
        String::from_utf8_lossy(&unauth_scout.stderr)
    );

    // Lock plan as authenticated Master
    assert!(
        Command::new(swarm_tool_bin())
            .args(["master", "lock-plan", "plan.dag.json"])
            .current_dir(&repo)
            .env("AGENT_GUARD_STATE_DIR", &state)
            .env("AGENT_GUARD_ROLE", "master")
            .status()
            .unwrap()
            .success()
    );

    // 2. Finding #9: Every non-Master worker role (not just Grunt) blocks unauthenticated `master` calls while open
    for worker_role in ["investigator", "qa", "reviewer", "coroner"] {
        let mint = Command::new(swarm_tool_bin())
            .args([
                "master",
                "mint-session",
                "--role",
                worker_role,
                "--task",
                "TASK-V1",
            ])
            .current_dir(&repo)
            .env("AGENT_GUARD_STATE_DIR", &state)
            .env("AGENT_GUARD_ROLE", "master")
            .output()
            .unwrap();
        assert!(mint.status.success());
        let sid = JsonValue::parse(&String::from_utf8_lossy(&mint.stdout))
            .unwrap()
            .get("session_id")
            .and_then(JsonValue::as_str)
            .unwrap()
            .to_string();

        let esc = Command::new(swarm_tool_bin())
            .args(["master", "status"])
            .current_dir(&repo)
            .env("AGENT_GUARD_STATE_DIR", &state)
            .env_remove("AGENT_GUARD_ROLE")
            .env_remove("AGENT_GUARD_SESSION_ID")
            .output()
            .unwrap();
        assert!(!esc.status.success());
        assert!(
            String::from_utf8_lossy(&esc.stderr).contains("ROLE_CAPABILITY_MISMATCH"),
            "worker role '{worker_role}' must block unauthenticated master call, got: {}",
            String::from_utf8_lossy(&esc.stderr)
        );

        // Finding #10: If this is `qa`, verify `master ingest-packet` rejects an `ObservedFact` claiming `qa`'s session_id!
        if worker_role == "qa" {
            let spoofed_fact = format!(
                r#"{{"packet_type":"ObservedFact","session_id":"{sid}","task_id":"TASK-V1","claim":"Spoofed claim.","evidence_slices":["src/mod_a.rs:1-1"]}}"#
            );
            let bad_ingest = Command::new(swarm_tool_bin())
                .args(["master", "ingest-packet", &spoofed_fact])
                .current_dir(&repo)
                .env("AGENT_GUARD_STATE_DIR", &state)
                .env("AGENT_GUARD_ROLE", "master")
                .output()
                .unwrap();
            assert!(!bad_ingest.status.success());
            assert!(
                String::from_utf8_lossy(&bad_ingest.stderr).contains("PACKET_ROLE_MISMATCH"),
                "expected PACKET_ROLE_MISMATCH when QA session spoofs ObservedFact, got: {}",
                String::from_utf8_lossy(&bad_ingest.stderr)
            );
        }

        assert!(
            Command::new(swarm_tool_bin())
                .args(["master", "close-session", "--session", &sid])
                .current_dir(&repo)
                .env("AGENT_GUARD_STATE_DIR", &state)
                .env("AGENT_GUARD_ROLE", "master")
                .status()
                .unwrap()
                .success()
        );
    }

    // Fabricated unminted session_id in `ingest-packet` MUST also be rejected
    let unminted_pkt = r#"{"packet_type":"ObservedFact","session_id":"swm_investigator_TASK_V1_a1_0000000000","task_id":"TASK-V1","claim":"Unminted claim.","evidence_slices":["src/mod_a.rs:1-1"]}"#;
    let unminted_ingest = Command::new(swarm_tool_bin())
        .args(["master", "ingest-packet", unminted_pkt])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .env("AGENT_GUARD_ROLE", "master")
        .output()
        .unwrap();
    assert!(!unminted_ingest.status.success());
    assert!(
        String::from_utf8_lossy(&unminted_ingest.stderr).contains("UNAUTHENTICATED_WORKER_PACKET"),
        "expected UNAUTHENTICATED_WORKER_PACKET, got: {}",
        String::from_utf8_lossy(&unminted_ingest.stderr)
    );

    // 3. Vault + Out-of-Sandbox Unix-Socket Coordinator E2E under Linux Landlock LSM
    let swarm_root = state.join("swarm");
    let repo_swarm_dir = fs::read_dir(&swarm_root)
        .expect("read state/swarm")
        .flatten()
        .map(|e| e.path())
        .find(|p| p.is_dir())
        .expect("repo swarm state dir");
    let vault_key = repo_swarm_dir.join("vault").join("hmac.key");
    assert!(
        vault_key.exists(),
        "HMAC secret must be isolated at <swarm_state_dir>/vault/hmac.key"
    );

    let status_out = Command::new(agent_guard_bin())
        .arg("sandbox-status")
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .output()
        .unwrap();
    let landlock_enforced =
        String::from_utf8_lossy(&status_out.stdout).contains("mode=linux-landlock-enforced");

    // Write a unit test that verifies:
    // (a) `AGENT_GUARD_ROLE` and `AGENT_GUARD_SESSION_ID` are scrubbed inside `checkpoint-green`, AND
    // (b) On Linux Landlock kernels, reading `<swarm_state_dir>/vault/hmac.key` raises `PermissionError` (EACCES)!
    let py_test = format!(
        concat!(
            "import os, pathlib, unittest\n",
            "class VaultIsolationTest(unittest.TestCase):\n",
            "    def test_vault_key_blocked_and_env_scrubbed(self):\n",
            "        self.assertIsNone(os.environ.get('AGENT_GUARD_SESSION_ID'))\n",
            "        vault_path = pathlib.Path(r'''{}''')\n",
            "        if {}:\n",
            "            with self.assertRaises(PermissionError):\n",
            "                vault_path.read_bytes()\n",
            "if __name__ == '__main__':\n",
            "    unittest.main()\n",
        ),
        vault_key.display(),
        if landlock_enforced { "True" } else { "False" }
    );
    fs::write(repo.join("tests/test_vault_isolated.py"), py_test).unwrap();

    // Mint Grunt, edit `src/mod_a.rs`, record edit + checkpoint-green + submit-ledger THROUGH `agent-guard exec-sandbox`!
    let grunt_mint = Command::new(swarm_tool_bin())
        .args([
            "master",
            "mint-session",
            "--role",
            "grunt",
            "--task",
            "TASK-V1",
        ])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .env("AGENT_GUARD_ROLE", "master")
        .output()
        .unwrap();
    assert!(grunt_mint.status.success());
    let grunt_sid = JsonValue::parse(&String::from_utf8_lossy(&grunt_mint.stdout))
        .unwrap()
        .get("session_id")
        .and_then(JsonValue::as_str)
        .unwrap()
        .to_string();

    fs::write(repo.join("src/mod_a.rs"), "pub fn alpha() -> u8 { 42 }\n").unwrap();

    let kernel_enforced = agent_guard::exec_sandbox::probe_host_sandbox_mode().is_kernel_enforced();
    let sandboxed_record_cmd = format!(
        "'{}' grunt record-edit --session '{}' --file src/mod_a.rs --lines 1-1",
        swarm_tool_bin().display(),
        grunt_sid
    );
    let sb_rec = Command::new(agent_guard_bin())
        .args(["exec-sandbox", "--", &sandboxed_record_cmd])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .output()
        .unwrap();
    if kernel_enforced {
        assert!(
            sb_rec.status.success(),
            "sandboxed `swarm-tool grunt record-edit` must sign via coordinator Unix socket without vault/hmac.key access! stderr: {}",
            String::from_utf8_lossy(&sb_rec.stderr)
        );

        if landlock_enforced {
            // Direct shell attempt to read vault/hmac.key inside exec-sandbox MUST be kernel-denied!
            let steal_cmd = format!("cat '{}'", vault_key.display());
            let steal_out = Command::new(agent_guard_bin())
                .args(["exec-sandbox", "--", &steal_cmd])
                .current_dir(&repo)
                .env("AGENT_GUARD_STATE_DIR", &state)
                .output()
                .unwrap();
            assert!(
                !steal_out.status.success(),
                "Linux Landlock MUST deny reading vault/hmac.key inside exec-sandbox!"
            );
        }

        // Run `grunt checkpoint-green` (which executes `tests/test_vault_isolated.py` inside `agent-guard exec-sandbox`!)
        let cp_out = Command::new(swarm_tool_bin())
            .args([
                "grunt",
                "checkpoint-green",
                "--session",
                &grunt_sid,
                "--",
                "python3",
                "-m",
                "unittest",
                "discover",
                "-s",
                "tests",
            ])
            .current_dir(&repo)
            .env("AGENT_GUARD_STATE_DIR", &state)
            .output()
            .unwrap();
        assert!(
            cp_out.status.success(),
            "sandboxed checkpoint-green failed: stdout={} stderr={}",
            String::from_utf8_lossy(&cp_out.stdout),
            String::from_utf8_lossy(&cp_out.stderr)
        );

        let sandboxed_ledger_cmd = format!(
            "'{}' grunt submit-ledger --session '{}' --what 'Updated alpha return value in src/mod_a.rs. Signed edit via coordinator socket.' --why 'Verified Landlock vault isolation for HMAC secret. Confirmed green unittest suite inside sandbox.'",
            swarm_tool_bin().display(),
            grunt_sid
        );
        let sb_ledger = Command::new(agent_guard_bin())
            .args(["exec-sandbox", "--", &sandboxed_ledger_cmd])
            .current_dir(&repo)
            .env("AGENT_GUARD_STATE_DIR", &state)
            .output()
            .unwrap();
        assert!(
            sb_ledger.status.success(),
            "sandboxed `swarm-tool grunt submit-ledger` failed: stderr={}",
            String::from_utf8_lossy(&sb_ledger.stderr)
        );
    } else {
        assert!(!sb_rec.status.success());
        assert!(
            String::from_utf8_lossy(&sb_rec.stderr).contains("KERNEL_SANDBOX_UNAVAILABLE"),
            "degraded kernel must fail closed on exec-sandbox: {}",
            String::from_utf8_lossy(&sb_rec.stderr)
        );
    }

    // Removed `--internal-exec-sandbox` CLI flag must fail closed (exit 2, UNKNOWN_SUBCOMMAND)
    // even if a caller attempts to supply the former internal token env var.
    let direct_internal = Command::new(swarm_tool_bin())
        .args(["--internal-exec-sandbox", "--", "echo", "pwn"])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .env("AGENT_GUARD_INTERNAL_SBX_TOKEN", "1")
        .output()
        .unwrap();
    assert_eq!(direct_internal.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&direct_internal.stderr).contains("UNKNOWN_SUBCOMMAND"),
        "direct --internal-exec-sandbox stderr: {}",
        String::from_utf8_lossy(&direct_internal.stderr)
    );

    // Worker-controlled `HOME` containing a 0755 fake `.local/bin/agent-guard` must NEVER be
    // trusted when `swarm-tool` has no sibling `agent-guard` next to `current_exe()`.
    let isolated_bin_dir = dir.join("isolated_bin");
    let fake_home_dir = dir.join("fake_home").join(".local").join("bin");
    fs::create_dir_all(&isolated_bin_dir).unwrap();
    fs::create_dir_all(&fake_home_dir).unwrap();
    let isolated_swarm_tool = isolated_bin_dir.join("swarm-tool");
    fs::copy(swarm_tool_bin(), &isolated_swarm_tool).unwrap();
    let fake_ag = fake_home_dir.join("agent-guard");
    fs::write(
        &fake_ag,
        "#!/bin/sh\necho FAKE_HOME_AGENT_GUARD_HIJACK >&2\nexit 0\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&isolated_swarm_tool, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&fake_ag, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&fake_home_dir, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut hijack_cmd = Command::new(&isolated_swarm_tool);
    hijack_cmd
        .args([
            "grunt",
            "checkpoint-green",
            "--session",
            &grunt_sid,
            "--",
            "python3",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
        ])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .env("HOME", dir.join("fake_home"));
    let home_hijack = retry_output_on_etxtbsy(&mut hijack_cmd).unwrap();
    assert_eq!(home_hijack.status.code(), Some(2));
    let hijack_stderr = String::from_utf8_lossy(&home_hijack.stderr);
    assert!(
        hijack_stderr.contains("SANDBOX_BINARY_UNAVAILABLE")
            && !hijack_stderr.contains("FAKE_HOME_AGENT_GUARD_HIJACK"),
        "HOME hijack attempt stderr: {hijack_stderr}"
    );

    // `checkpoint-green` with `--skip` exclusion flag must be rejected
    let skip_cp = Command::new(swarm_tool_bin())
        .args([
            "grunt",
            "checkpoint-green",
            "--session",
            &grunt_sid,
            "--",
            "cargo",
            "test",
            "--",
            "--skip",
            "test_vault_isolated",
        ])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .output()
        .unwrap();
    assert!(!skip_cp.status.success());
    assert!(
        String::from_utf8_lossy(&skip_cp.stderr).contains("INVALID_TEST_RUNNER_COMMAND"),
        "skip checkpoint stderr: {}",
        String::from_utf8_lossy(&skip_cp.stderr)
    );

    for bad_runner_args in [
        &[
            "grunt",
            "checkpoint-green",
            "--session",
            &grunt_sid,
            "--",
            "pytest",
            "--deselect=tests/test_vault_isolated.py::test_ok",
        ][..],
        &[
            "grunt",
            "checkpoint-green",
            "--session",
            &grunt_sid,
            "--",
            "go",
            "test",
            "-run",
            "vault_isolation_test",
            "-exec",
            "sh",
        ][..],
    ] {
        let bad_cp = Command::new(swarm_tool_bin())
            .args(bad_runner_args)
            .current_dir(&repo)
            .env("AGENT_GUARD_STATE_DIR", &state)
            .output()
            .unwrap();
        assert!(!bad_cp.status.success());
        assert!(
            String::from_utf8_lossy(&bad_cp.stderr).contains("INVALID_TEST_RUNNER_COMMAND"),
            "bad runner args {bad_runner_args:?} stderr: {}",
            String::from_utf8_lossy(&bad_cp.stderr)
        );
    }

    // Once closed by Master, replaying `--session <grunt_sid>` must fail closed (`SESSION_CLOSED_OR_INACTIVE`)
    assert!(
        Command::new(swarm_tool_bin())
            .args(["master", "close-session", "--session", &grunt_sid])
            .current_dir(&repo)
            .env("AGENT_GUARD_STATE_DIR", &state)
            .env("AGENT_GUARD_ROLE", "master")
            .status()
            .unwrap()
            .success()
    );
    let replay_closed = Command::new(swarm_tool_bin())
        .args(["grunt", "context", "--session", &grunt_sid])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .output()
        .unwrap();
    assert!(!replay_closed.status.success());
    assert!(
        String::from_utf8_lossy(&replay_closed.stderr).contains("SESSION_CLOSED_OR_INACTIVE"),
        "closed session replay stderr: {}",
        String::from_utf8_lossy(&replay_closed.stderr)
    );

    // Non-TTY `lock-plan --amend --human-approved` must be rejected
    let amend_non_tty = Command::new(swarm_tool_bin())
        .args([
            "master",
            "lock-plan",
            "plan.dag.json",
            "--amend",
            "--human-approved",
        ])
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .env("AGENT_GUARD_ROLE", "master")
        .output()
        .unwrap();
    assert!(!amend_non_tty.status.success());
    assert!(
        String::from_utf8_lossy(&amend_non_tty.stderr).contains("PLAN_AMEND_REQUIRES_HUMAN_TTY"),
        "non-tty amend stderr: {}",
        String::from_utf8_lossy(&amend_non_tty.stderr)
    );
}
