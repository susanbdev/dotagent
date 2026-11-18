//! Deterministic Swarm v2 6-role delegation and PR #6 (`DA-01a`..`DA-06`)
//! adversarial security regression suite for `dotagent-harness`.

use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::Instant;

use agent_guard::breadcrumbs::{
    SignedBreadcrumbRecord, append_spool_frame, constant_time_eq_bytes, recover_spool_frames,
    sha256_digest,
};
use agent_guard::json::JsonValue;
use agent_guard::qa_suspects::{
    parse_and_validate_dag_json, parse_attribution_toml, triangulate_faults,
};
use agent_guard::swarm_contracts::{AuthenticatedEvent, EventOp, SuspectVerdict, hex_encode};

use crate::sandbox::TestSandbox;
use crate::{CaseResult, WorkspaceBinaries};

const CASE_SIX_ROLE_E2E: &str = "swarm::six_role_end_to_end_delegation_and_provenance";
const CASE_DA01_MASTER_ESCALATION: &str =
    "swarm::da01_blocks_sandboxed_and_worker_master_role_escalation";
const CASE_DA02A_REVIEW_LEDGER_AND_ROUNDS: &str =
    "swarm::da02a_enforces_verified_work_ledger_and_monotonic_review_rounds";
const CASE_DA02B_TEST_RUNNER_INTEGRITY: &str =
    "swarm::da02b_blocks_fake_binaries_noop_flags_and_omitted_assigned_tests";
const CASE_DA04B_HASH_CHAINED_LEDGER: &str =
    "swarm::da04b_detects_work_ledger_truncation_deletion_and_smell_mutation";
const CASE_DA05_SPOOL_INTEGRITY: &str =
    "swarm::da05_rejects_corrupt_midstream_spool_frame_while_quarantining_eof_tail";
const CASE_DA06_DAG_AND_TRIANGULATION: &str =
    "swarm::da06_blocks_overlapping_parallel_wave_globs_and_triangulates_all_secondary_suspects";

pub fn swarm_case_ids() -> &'static [&'static str] {
    &[
        CASE_SIX_ROLE_E2E,
        CASE_DA01_MASTER_ESCALATION,
        CASE_DA02A_REVIEW_LEDGER_AND_ROUNDS,
        CASE_DA02B_TEST_RUNNER_INTEGRITY,
        CASE_DA04B_HASH_CHAINED_LEDGER,
        CASE_DA05_SPOOL_INTEGRITY,
        CASE_DA06_DAG_AND_TRIANGULATION,
    ]
}

type SwarmCaseRunner = fn(&Path, &WorkspaceBinaries) -> Result<String, String>;

pub fn run_swarm_suite(
    workspace_root: &Path,
    bins: &WorkspaceBinaries,
    filter: Option<&str>,
) -> Vec<CaseResult> {
    let mut out = Vec::new();
    let runners: [(&str, SwarmCaseRunner); 7] = [
        (CASE_SIX_ROLE_E2E, case_six_role_e2e),
        (CASE_DA01_MASTER_ESCALATION, case_da01_master_escalation),
        (
            CASE_DA02A_REVIEW_LEDGER_AND_ROUNDS,
            case_da02a_review_ledger_and_rounds,
        ),
        (
            CASE_DA02B_TEST_RUNNER_INTEGRITY,
            case_da02b_test_runner_integrity,
        ),
        (
            CASE_DA04B_HASH_CHAINED_LEDGER,
            case_da04b_hash_chained_ledger,
        ),
        (CASE_DA05_SPOOL_INTEGRITY, case_da05_spool_integrity),
        (
            CASE_DA06_DAG_AND_TRIANGULATION,
            case_da06_dag_and_triangulation,
        ),
    ];

    for (id, func) in runners {
        if let Some(f) = filter
            && !id.contains(f)
        {
            continue;
        }
        let started = Instant::now();
        match func(workspace_root, bins) {
            Ok(detail) => {
                out.push(CaseResult::pass(
                    id.to_string(),
                    "swarm",
                    started.elapsed().as_millis() as u64,
                    detail,
                ));
            }
            Err(err) => {
                out.push(CaseResult::fail(
                    id.to_string(),
                    "swarm",
                    started.elapsed().as_millis() as u64,
                    err,
                ));
            }
        }
    }
    out
}

fn run_swarm_cmd(
    bins: &WorkspaceBinaries,
    sb: &TestSandbox,
    args: &[&str],
    role: Option<&str>,
    session_id: Option<&str>,
) -> Result<Output, String> {
    let mut c = Command::new(&bins.swarm_tool);
    c.args(args).current_dir(&sb.repo_dir);
    sb.configure_isolated_command(&mut c);
    if let Some(r) = role {
        c.env("AGENT_GUARD_ROLE", r);
    }
    if let Some(sid) = session_id {
        c.env("AGENT_GUARD_SESSION_ID", sid);
    }
    c.output()
        .map_err(|e| format!("failed spawning swarm-tool {:?}: {e}", args))
}

fn mint_role_session(
    bins: &WorkspaceBinaries,
    sb: &TestSandbox,
    role: &str,
    task: &str,
    attempt: u32,
) -> Result<String, String> {
    let att = attempt.to_string();
    let out = run_swarm_cmd(
        bins,
        sb,
        &[
            "master",
            "mint-session",
            "--role",
            role,
            "--task",
            task,
            "--attempt",
            &att,
        ],
        Some("master"),
        None,
    )?;
    if !out.status.success() {
        return Err(format!(
            "mint-session --role {role} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let parsed = JsonValue::parse(&String::from_utf8_lossy(&out.stdout))
        .map_err(|e| format!("invalid mint-session JSON: {e}"))?;
    parsed
        .get("session_id")
        .and_then(JsonValue::as_str)
        .map(str::to_string)
        .ok_or_else(|| "mint-session output missing session_id".to_string())
}

fn close_role_session(bins: &WorkspaceBinaries, sb: &TestSandbox, sid: &str) -> Result<(), String> {
    let out = run_swarm_cmd(
        bins,
        sb,
        &["master", "close-session", "--session", sid],
        Some("master"),
        None,
    )?;
    if !out.status.success() {
        return Err(format!(
            "close-session {sid} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

fn write_standard_fixture(sb: &TestSandbox, dag_json: &str) -> Result<(), String> {
    fs::create_dir_all(sb.repo_dir.join("src")).map_err(|e| e.to_string())?;
    fs::create_dir_all(sb.repo_dir.join("tests")).map_err(|e| e.to_string())?;
    fs::create_dir_all(sb.repo_dir.join("docs")).map_err(|e| e.to_string())?;
    fs::write(sb.repo_dir.join("docs/dag.json"), dag_json).map_err(|e| e.to_string())?;
    fs::write(
        sb.repo_dir.join("src/calc.rs"),
        "pub fn clamp_pct(v: u32) -> u32 {\n    v.min(95)\n}\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        sb.repo_dir.join("tests/test_calc.py"),
        "import unittest\nclass CalcBoundsTest(unittest.TestCase):\n    def test_bounds(self):\n        self.assertEqual(min(99, 95), 95)\nif __name__ == '__main__':\n    unittest.main()\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        sb.repo_dir.join("test_attribution.toml"),
        "[[tests]]\nname = \"test_calc\"\nprimary_suspect = \"TASK-1\"\nsecondary_suspects = []\n",
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn single_task_dag_json() -> &'static str {
    r#"{
  "plan_id": "HARNESS-SWARM-E2E",
  "tasks": [
    {
      "id": "TASK-1",
      "wave": "W1",
      "depends_on": [],
      "domain_risk": "core_logic",
      "assigned_read_paths": ["src/calc.rs", "tests/test_calc.py"],
      "allowed_write_paths": ["src/calc.rs"],
      "assigned_tests": ["test_calc"]
    }
  ]
}"#
}

fn case_six_role_e2e(workspace_root: &Path, bins: &WorkspaceBinaries) -> Result<String, String> {
    let sb = TestSandbox::create(workspace_root, "swarm_six_role_e2e")?;
    write_standard_fixture(&sb, single_task_dag_json())?;

    // 1. Master locks DAG plan
    let lock_out = run_swarm_cmd(
        bins,
        &sb,
        &["master", "lock-plan", "docs/dag.json"],
        Some("master"),
        None,
    )?;
    if !lock_out.status.success() {
        return Err(format!(
            "master lock-plan failed: {}",
            String::from_utf8_lossy(&lock_out.stderr)
        ));
    }

    // 2. Investigator scouts signatures and emits authenticated ObservedFact
    let inv_sid = mint_role_session(bins, &sb, "investigator", "TASK-1", 1)?;
    let scout = run_swarm_cmd(
        bins,
        &sb,
        &["investigator", "scout", "src", "--session", &inv_sid],
        None,
        None,
    )?;
    if !scout.status.success() {
        return Err(format!(
            "investigator scout failed: {}",
            String::from_utf8_lossy(&scout.stderr)
        ));
    }
    let fact = run_swarm_cmd(
        bins,
        &sb,
        &[
            "investigator",
            "emit-fact",
            "--session",
            &inv_sid,
            "--task",
            "TASK-1",
            "--claim",
            "clamp_pct caps input at 95 in src/calc.rs.",
            "--slice",
            "src/calc.rs:1-3",
        ],
        None,
        None,
    )?;
    if !fact.status.success() {
        return Err(format!(
            "investigator emit-fact failed: {}",
            String::from_utf8_lossy(&fact.stderr)
        ));
    }
    let fact_json = String::from_utf8_lossy(&fact.stdout).trim().to_string();
    let ingest = run_swarm_cmd(
        bins,
        &sb,
        &["master", "ingest-packet", &fact_json],
        Some("master"),
        None,
    )?;
    if !ingest.status.success() {
        return Err(format!(
            "master ingest-packet failed: {}",
            String::from_utf8_lossy(&ingest.stderr)
        ));
    }
    close_role_session(bins, &sb, &inv_sid)?;

    // 3. QA Engineer verifies attribution against locked plan
    let qa_sid = mint_role_session(bins, &sb, "qa", "TASK-1", 1)?;
    let qa_attr = run_swarm_cmd(
        bins,
        &sb,
        &[
            "qa",
            "verify-attribution",
            "test_attribution.toml",
            "--session",
            &qa_sid,
        ],
        None,
        None,
    )?;
    if !qa_attr.status.success() {
        return Err(format!(
            "qa verify-attribution failed: {}",
            String::from_utf8_lossy(&qa_attr.stderr)
        ));
    }
    close_role_session(bins, &sb, &qa_sid)?;

    // 4. Grunt records edit, runs sandboxed checkpoint-green, submits HMAC work ledger, and passes on-stop
    let grunt_sid = mint_role_session(bins, &sb, "grunt", "TASK-1", 1)?;
    let rec = run_swarm_cmd(
        bins,
        &sb,
        &[
            "grunt",
            "record-edit",
            "--session",
            &grunt_sid,
            "--file",
            "src/calc.rs",
            "--lines",
            "1-3",
        ],
        None,
        None,
    )?;
    if !rec.status.success() {
        return Err(format!(
            "grunt record-edit failed: {}",
            String::from_utf8_lossy(&rec.stderr)
        ));
    }
    let cp = run_swarm_cmd(
        bins,
        &sb,
        &[
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
        ],
        None,
        None,
    )?;
    if !cp.status.success() {
        return Err(format!(
            "grunt checkpoint-green failed: {}",
            String::from_utf8_lossy(&cp.stderr)
        ));
    }
    let led = run_swarm_cmd(
        bins,
        &sb,
        &[
            "grunt",
            "submit-ledger",
            "--session",
            &grunt_sid,
            "--what",
            "Verified clamp_pct upper bound in src/calc.rs. Signed edit breadcrumb.",
            "--why",
            "Satisfies core_logic bounds contract. Confirmed green unittest suite.",
        ],
        None,
        None,
    )?;
    if !led.status.success() {
        return Err(format!(
            "grunt submit-ledger failed: {}",
            String::from_utf8_lossy(&led.stderr)
        ));
    }
    let mut stop_cmd = Command::new(&bins.agent_guard);
    stop_cmd.arg("on-stop").current_dir(&sb.repo_dir);
    sb.configure_isolated_command(&mut stop_cmd);
    let stop_out = stop_cmd.output().map_err(|e| e.to_string())?;
    if !stop_out.status.success() {
        return Err(format!(
            "agent-guard on-stop after valid ledger failed: {}",
            String::from_utf8_lossy(&stop_out.stderr)
        ));
    }

    // 5. Adversarial Reviewer inspects ledger and approves Round 1
    let rev_sid = mint_role_session(bins, &sb, "reviewer", "TASK-1", 1)?;
    let verd = run_swarm_cmd(
        bins,
        &sb,
        &[
            "reviewer",
            "verdict",
            "--session",
            &rev_sid,
            "--task",
            "TASK-1",
            "--round",
            "1",
            "--attempt",
            "1",
            "--decision",
            "approve",
        ],
        None,
        None,
    )?;
    if !verd.status.success() {
        return Err(format!(
            "reviewer verdict approve failed: {}",
            String::from_utf8_lossy(&verd.stderr)
        ));
    }
    if !String::from_utf8_lossy(&verd.stdout).contains("\"outcome\":\"Approved\"") {
        return Err(format!(
            "expected Approved outcome, got: {}",
            String::from_utf8_lossy(&verd.stdout)
        ));
    }
    close_role_session(bins, &sb, &rev_sid)?;

    // 6. Forensic Coroner verifies HMAC breadcrumb trail
    let cor_sid = mint_role_session(bins, &sb, "coroner", "TASK-1", 1)?;
    let trail = run_swarm_cmd(
        bins,
        &sb,
        &[
            "coroner",
            "verify-trail",
            "src/.breadcrumbs.jsonl",
            "--session",
            &cor_sid,
        ],
        None,
        None,
    )?;
    if !trail.status.success() {
        return Err(format!(
            "coroner verify-trail failed: {}",
            String::from_utf8_lossy(&trail.stderr)
        ));
    }
    close_role_session(bins, &sb, &cor_sid)?;

    Ok(
        "6-role delegation (master -> investigator -> qa -> grunt -> reviewer -> coroner) verified"
            .to_string(),
    )
}

fn case_da01_master_escalation(
    workspace_root: &Path,
    bins: &WorkspaceBinaries,
) -> Result<String, String> {
    let sb = TestSandbox::create(workspace_root, "swarm_da01_escalation")?;
    write_standard_fixture(&sb, single_task_dag_json())?;
    let lock = run_swarm_cmd(
        bins,
        &sb,
        &["master", "lock-plan", "docs/dag.json"],
        Some("master"),
        None,
    )?;
    if !lock.status.success() {
        return Err("lock-plan failed".to_string());
    }
    let grunt_sid = mint_role_session(bins, &sb, "grunt", "TASK-1", 1)?;

    // 1. CRITICAL-DA-01a: Inside `agent-guard exec-sandbox`, `AGENT_GUARD_ROLE=master swarm-tool master status` MUST fail closed!
    let esc_cmd = format!(
        "AGENT_GUARD_ROLE=master '{}' master status",
        bins.swarm_tool.display()
    );
    let mut sb_exec = Command::new(&bins.agent_guard);
    sb_exec
        .args(["exec-sandbox", "--", &esc_cmd])
        .current_dir(&sb.repo_dir);
    sb.configure_isolated_command(&mut sb_exec);
    let sb_out = sb_exec.output().map_err(|e| e.to_string())?;
    if sb_out.status.success() {
        return Err(
            "CRITICAL-DA-01a regression: sandboxed AGENT_GUARD_ROLE=master succeeded!".to_string(),
        );
    }
    if !String::from_utf8_lossy(&sb_out.stderr).contains("ROLE_CAPABILITY_MISMATCH") {
        return Err(format!(
            "expected ROLE_CAPABILITY_MISMATCH inside sandbox, got: {}",
            String::from_utf8_lossy(&sb_out.stderr)
        ));
    }

    // 2. CRITICAL-DA-01b: `agent-guard pre-tool` with `AGENT_GUARD_ROLE=master` while a worker session (`grunt_sid`)
    //    is open MUST fail closed (`ROLE_CAPABILITY_MISMATCH`), NOT silently grant Master!
    let hook_payload = JsonValue::Object(vec![
        (
            "session_id".to_string(),
            JsonValue::Str("claude-worker-hook".to_string()),
        ),
        (
            "cwd".to_string(),
            JsonValue::Str(sb.repo_dir.to_string_lossy().into_owned()),
        ),
        (
            "hook_event_name".to_string(),
            JsonValue::Str("PreToolUse".to_string()),
        ),
        ("tool_name".to_string(), JsonValue::Str("Read".to_string())),
        (
            "tool_input".to_string(),
            JsonValue::Object(vec![(
                "file_path".to_string(),
                JsonValue::Str("AGENTS.md".to_string()),
            )]),
        ),
    ])
    .to_json_string();
    let mut ag_cmd = Command::new(&bins.agent_guard);
    ag_cmd
        .arg("pre-tool")
        .current_dir(&sb.repo_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    sb.configure_isolated_command(&mut ag_cmd);
    ag_cmd.env("AGENT_GUARD_ROLE", "master");
    let mut child = ag_cmd.spawn().map_err(|e| e.to_string())?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin
            .write_all(hook_payload.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    let ag_out = child.wait_with_output().map_err(|e| e.to_string())?;
    if ag_out.status.code() != Some(2) {
        return Err(format!(
            "CRITICAL-DA-01b regression: expected exit 2 when claiming AGENT_GUARD_ROLE=master while worker open, got {:?}",
            ag_out.status.code()
        ));
    }
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&ag_out.stdout),
        String::from_utf8_lossy(&ag_out.stderr)
    );
    if !combined.contains("ROLE_CAPABILITY_MISMATCH") {
        return Err(format!(
            "expected ROLE_CAPABILITY_MISMATCH in hook output, got: {combined}"
        ));
    }

    // 3. When a signed Master capability IS minted, bare `AGENT_GUARD_ROLE=master` without `--master-session` MUST also be rejected!
    close_role_session(bins, &sb, &grunt_sid)?;
    let master_sid = mint_role_session(bins, &sb, "master", "TASK-1", 1)?;
    let bare_master = run_swarm_cmd(bins, &sb, &["master", "status"], Some("master"), None)?;
    if bare_master.status.success() {
        return Err(
            "bare AGENT_GUARD_ROLE=master must be rejected when a signed Master capability is open"
                .to_string(),
        );
    }
    let signed_master = run_swarm_cmd(
        bins,
        &sb,
        &["master", "status", "--master-session", &master_sid],
        None,
        None,
    )?;
    if !signed_master.status.success() {
        return Err(format!(
            "signed --master-session failed: {}",
            String::from_utf8_lossy(&signed_master.stderr)
        ));
    }

    Ok(
        "DA-01a/01b verified: sandboxed & open-worker Master role escalation hard-denied"
            .to_string(),
    )
}

fn case_da02a_review_ledger_and_rounds(
    workspace_root: &Path,
    bins: &WorkspaceBinaries,
) -> Result<String, String> {
    let sb = TestSandbox::create(workspace_root, "swarm_da02a_review")?;
    write_standard_fixture(&sb, single_task_dag_json())?;
    let _ = run_swarm_cmd(
        bins,
        &sb,
        &["master", "lock-plan", "docs/dag.json"],
        Some("master"),
        None,
    )?;

    let rev_sid = mint_role_session(bins, &sb, "reviewer", "TASK-1", 1)?;

    // 1. Approving BEFORE any green WORK_LEDGER.jsonl receipt MUST fail (`MISSING_VERIFIED_WORK_LEDGER`)
    let premature = run_swarm_cmd(
        bins,
        &sb,
        &[
            "reviewer",
            "verdict",
            "--session",
            &rev_sid,
            "--task",
            "TASK-1",
            "--round",
            "1",
            "--attempt",
            "1",
            "--decision",
            "approve",
        ],
        None,
        None,
    )?;
    if premature.status.success()
        || !String::from_utf8_lossy(&premature.stderr).contains("MISSING_VERIFIED_WORK_LEDGER")
    {
        return Err(format!(
            "expected MISSING_VERIFIED_WORK_LEDGER on premature approve, got: {}",
            String::from_utf8_lossy(&premature.stderr)
        ));
    }

    // 2. Rejecting Round 1 records round=1 (`RetryCleanSlate`, `next_attempt=2`)
    let r1_reject = run_swarm_cmd(
        bins,
        &sb,
        &[
            "reviewer",
            "verdict",
            "--session",
            &rev_sid,
            "--task",
            "TASK-1",
            "--round",
            "1",
            "--attempt",
            "1",
            "--decision",
            "reject",
        ],
        None,
        None,
    )?;
    if !r1_reject.status.success() {
        return Err(format!(
            "round 1 reject failed: {}",
            String::from_utf8_lossy(&r1_reject.stderr)
        ));
    }

    // 3. Replaying `--round 1` MUST fail closed (`REVIEW_ROUND_REPLAY_OR_SKIP`)
    let replay_r1 = run_swarm_cmd(
        bins,
        &sb,
        &[
            "reviewer",
            "verdict",
            "--session",
            &rev_sid,
            "--task",
            "TASK-1",
            "--round",
            "1",
            "--attempt",
            "2",
            "--decision",
            "reject",
        ],
        None,
        None,
    )?;
    if replay_r1.status.success()
        || !String::from_utf8_lossy(&replay_r1.stderr).contains("REVIEW_ROUND_REPLAY_OR_SKIP")
    {
        return Err(format!(
            "expected REVIEW_ROUND_REPLAY_OR_SKIP on --round 1 replay, got: {}",
            String::from_utf8_lossy(&replay_r1.stderr)
        ));
    }
    close_role_session(bins, &sb, &rev_sid)?;

    // 4. Grunt completes Attempt 2 green ledger, then mutates `src/calc.rs` post-ledger -> Reviewer approve catches `STALE_WORK_LEDGER_TREE_OID`!
    let grunt_sid = mint_role_session(bins, &sb, "grunt", "TASK-1", 2)?;
    let _ = run_swarm_cmd(
        bins,
        &sb,
        &[
            "grunt",
            "record-edit",
            "--session",
            &grunt_sid,
            "--file",
            "src/calc.rs",
            "--lines",
            "1-3",
        ],
        None,
        None,
    )?;
    let _ = run_swarm_cmd(
        bins,
        &sb,
        &[
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
        ],
        None,
        None,
    )?;
    let _ = run_swarm_cmd(
        bins,
        &sb,
        &[
            "grunt",
            "submit-ledger",
            "--session",
            &grunt_sid,
            "--what",
            "Attempt two fix in src/calc.rs. Recorded signed edit event.",
            "--why",
            "Addressed round one review feedback. Passed unittest suite.",
        ],
        None,
        None,
    )?;
    close_role_session(bins, &sb, &grunt_sid)?;

    fs::write(
        sb.repo_dir.join("src/calc.rs"),
        "pub fn clamp_pct(v: u32) -> u32 {\n    v // sneaky post-ledger drift!\n}\n",
    )
    .map_err(|e| e.to_string())?;

    let rev2_sid = mint_role_session(bins, &sb, "reviewer", "TASK-1", 2)?;
    let drifted = run_swarm_cmd(
        bins,
        &sb,
        &[
            "reviewer",
            "verdict",
            "--session",
            &rev2_sid,
            "--task",
            "TASK-1",
            "--round",
            "2",
            "--attempt",
            "2",
            "--decision",
            "approve",
        ],
        None,
        None,
    )?;
    if drifted.status.success()
        || !String::from_utf8_lossy(&drifted.stderr).contains("STALE_WORK_LEDGER_TREE_OID")
    {
        return Err(format!(
            "expected STALE_WORK_LEDGER_TREE_OID on post-ledger file drift, got: {}",
            String::from_utf8_lossy(&drifted.stderr)
        ));
    }

    Ok(
        "DA-02a verified: premature approve, round replay, and post-ledger tree drift rejected"
            .to_string(),
    )
}

fn case_da02b_test_runner_integrity(
    workspace_root: &Path,
    bins: &WorkspaceBinaries,
) -> Result<String, String> {
    let sb = TestSandbox::create(workspace_root, "swarm_da02b_runner")?;
    write_standard_fixture(&sb, single_task_dag_json())?;
    let _ = run_swarm_cmd(
        bins,
        &sb,
        &["master", "lock-plan", "docs/dag.json"],
        Some("master"),
        None,
    )?;
    let grunt_sid = mint_role_session(bins, &sb, "grunt", "TASK-1", 1)?;

    // 1. Relative fake binary `./pytest` MUST fail (`INVALID_TEST_RUNNER_COMMAND`)
    let rel_bin = run_swarm_cmd(
        bins,
        &sb,
        &[
            "grunt",
            "checkpoint-green",
            "--session",
            &grunt_sid,
            "--",
            "./pytest",
        ],
        None,
        None,
    )?;
    if rel_bin.status.success()
        || !String::from_utf8_lossy(&rel_bin.stderr).contains("INVALID_TEST_RUNNER_COMMAND")
    {
        return Err(format!(
            "expected INVALID_TEST_RUNNER_COMMAND on ./pytest, got: {}",
            String::from_utf8_lossy(&rel_bin.stderr)
        ));
    }

    // 2. Compile-only `cargo test --no-run` MUST fail (`INVALID_TEST_RUNNER_COMMAND`)
    let no_run = run_swarm_cmd(
        bins,
        &sb,
        &[
            "grunt",
            "checkpoint-green",
            "--session",
            &grunt_sid,
            "--",
            "cargo",
            "test",
            "--no-run",
        ],
        None,
        None,
    )?;
    if no_run.status.success()
        || !String::from_utf8_lossy(&no_run.stderr).contains("INVALID_TEST_RUNNER_COMMAND")
    {
        return Err(format!(
            "expected INVALID_TEST_RUNNER_COMMAND on cargo test --no-run, got: {}",
            String::from_utf8_lossy(&no_run.stderr)
        ));
    }

    // 3. Narrowed filter omitting `test_calc` (`assigned_tests`) MUST fail (`ASSIGNED_TESTS_OMITTED`)
    let omitted = run_swarm_cmd(
        bins,
        &sb,
        &[
            "grunt",
            "checkpoint-green",
            "--session",
            &grunt_sid,
            "--",
            "python3",
            "-m",
            "unittest",
            "tests/test_unrelated_smoke.py",
        ],
        None,
        None,
    )?;
    if omitted.status.success()
        || !String::from_utf8_lossy(&omitted.stderr).contains("ASSIGNED_TESTS_OMITTED")
    {
        return Err(format!(
            "expected ASSIGNED_TESTS_OMITTED when narrowing away from assigned_tests, got: {}",
            String::from_utf8_lossy(&omitted.stderr)
        ));
    }

    Ok(
        "DA-02b verified: ./pytest, --no-run, and narrowed filters omitting assigned_tests rejected"
            .to_string(),
    )
}

fn case_da04b_hash_chained_ledger(
    workspace_root: &Path,
    bins: &WorkspaceBinaries,
) -> Result<String, String> {
    let sb = TestSandbox::create(workspace_root, "swarm_da04b_ledger")?;
    let two_task_dag = r#"{
  "plan_id": "HARNESS-LEDGER-CHAIN",
  "tasks": [
    {
      "id": "T1",
      "wave": "W1",
      "depends_on": [],
      "domain_risk": "core_logic",
      "assigned_read_paths": ["src/calc.rs", "tests/test_calc.py"],
      "allowed_write_paths": ["src/calc.rs"],
      "assigned_tests": ["test_calc"]
    },
    {
      "id": "T2",
      "wave": "W2",
      "depends_on": ["T1"],
      "domain_risk": "core_logic",
      "assigned_read_paths": ["src/calc.rs", "tests/test_calc.py"],
      "allowed_write_paths": ["src/calc.rs"],
      "assigned_tests": ["test_calc"]
    }
  ]
}"#;
    write_standard_fixture(&sb, two_task_dag)?;
    let _ = run_swarm_cmd(
        bins,
        &sb,
        &["master", "lock-plan", "docs/dag.json"],
        Some("master"),
        None,
    )?;

    for task_id in ["T1", "T2"] {
        let sid = mint_role_session(bins, &sb, "grunt", task_id, 1)?;
        let _ = run_swarm_cmd(
            bins,
            &sb,
            &[
                "grunt",
                "record-edit",
                "--session",
                &sid,
                "--file",
                "src/calc.rs",
                "--lines",
                "1-3",
            ],
            None,
            None,
        )?;
        let _ = run_swarm_cmd(
            bins,
            &sb,
            &[
                "grunt",
                "checkpoint-green",
                "--session",
                &sid,
                "--",
                "python3",
                "-m",
                "unittest",
                "discover",
                "-s",
                "tests",
            ],
            None,
            None,
        )?;
        let led = run_swarm_cmd(
            bins,
            &sb,
            &[
                "grunt",
                "submit-ledger",
                "--session",
                &sid,
                "--what",
                "Updated calc implementation cleanly. Recorded signed edit.",
                "--why",
                "Maintains hash-chained provenance. Verified green unit tests.",
            ],
            None,
            None,
        )?;
        if !led.status.success() {
            return Err(format!(
                "submit-ledger for {task_id} failed: {}",
                String::from_utf8_lossy(&led.stderr)
            ));
        }
        close_role_session(bins, &sb, &sid)?;
    }

    // Verify constant_time_eq_bytes helper
    if !constant_time_eq_bytes(b"dotagent-mac-32", b"dotagent-mac-32")
        || constant_time_eq_bytes(b"dotagent-mac-32", b"dotagent-mac-33")
        || constant_time_eq_bytes(b"short", b"longer")
    {
        return Err("constant_time_eq_bytes invariant failure".to_string());
    }

    let canon_repo = fs::canonicalize(&sb.repo_dir).unwrap_or_else(|_| sb.repo_dir.clone());
    let repo_hash = hex_encode(&sha256_digest(canon_repo.to_string_lossy().as_bytes()));
    let ledger_path = sb
        .state_dir
        .join("swarm")
        .join(&repo_hash[..24])
        .join("ledger")
        .join("WORK_LEDGER.jsonl");
    let raw_lines: Vec<String> = fs::read_to_string(&ledger_path)
        .map_err(|e| format!("failed reading {}: {e}", ledger_path.display()))?
        .lines()
        .map(str::to_string)
        .collect();
    if raw_lines.len() != 2 {
        return Err(format!("expected 2 ledger lines, got {}", raw_lines.len()));
    }

    // Deleting line 1 while keeping line 2 MUST break the `prev_record_mac` hash chain!
    fs::write(&ledger_path, format!("{}\n", raw_lines[1])).map_err(|e| e.to_string())?;
    let rev_sid = mint_role_session(bins, &sb, "reviewer", "T2", 1)?;
    let del_check = run_swarm_cmd(
        bins,
        &sb,
        &["reviewer", "inspect", "--session", &rev_sid, "--task", "T2"],
        None,
        None,
    )?;
    let del_stderr = String::from_utf8_lossy(&del_check.stderr);
    if del_check.status.success()
        || !del_stderr.contains("FORGED_WORK_LEDGER_ENTRY")
        || !del_stderr.contains("broken hash chain")
    {
        return Err(format!(
            "expected FORGED_WORK_LEDGER_ENTRY broken hash chain after deleting genesis ledger entry, got: {del_stderr}"
        ));
    }

    // Mutating `smell_badges` on restored ledger MUST fail HMAC verification!
    let mutated_line1 = raw_lines[0].replace(
        "\"smell_badges\":[]",
        "\"smell_badges\":[\"CONFUSED:SCOPE_THRASHING\"]",
    );
    fs::write(&ledger_path, format!("{mutated_line1}\n{}\n", raw_lines[1]))
        .map_err(|e| e.to_string())?;
    let badge_check = run_swarm_cmd(
        bins,
        &sb,
        &["reviewer", "inspect", "--session", &rev_sid, "--task", "T2"],
        None,
        None,
    )?;
    let badge_stderr = String::from_utf8_lossy(&badge_check.stderr);
    if badge_check.status.success()
        || !badge_stderr.contains("FORGED_WORK_LEDGER_ENTRY")
        || !badge_stderr.contains("HMAC verification failed")
    {
        return Err(format!(
            "expected FORGED_WORK_LEDGER_ENTRY HMAC verification failed after mutating smell_badges, got: {badge_stderr}"
        ));
    }

    Ok(
        "DA-04b verified: length-prefixed hash-chained WORK_LEDGER detects line deletion and badge tampering"
            .to_string(),
    )
}

fn case_da05_spool_integrity(
    workspace_root: &Path,
    _bins: &WorkspaceBinaries,
) -> Result<String, String> {
    let sb = TestSandbox::create(workspace_root, "swarm_da05_spool")?;
    let custom_spool = sb.state_dir.join("test_session.spool");
    let sample_rec = SignedBreadcrumbRecord {
        event: AuthenticatedEvent {
            schema_version: 1,
            repo_sha256: [0xBB; 32],
            plan_sha256: [0xCC; 32],
            session_id: "swm_s1".to_string(),
            task_id: "T1".to_string(),
            seq_no: 1,
            prev_event_mac: [0x00; 32],
            op: EventOp::FileEdit,
            canonical_rel_path: "src/calc.rs".to_string(),
            line_range: Some((1, 2)),
            doc_sha256: [0xDD; 32],
        },
        record_mac: [0xAA; 32],
    };
    append_spool_frame(&custom_spool, &sample_rec)?;
    append_spool_frame(&custom_spool, &sample_rec)?;

    // 1. Truncated incomplete EOF tail (`frame_end > raw.len()`) is cleanly quarantined
    let clean_bytes = fs::read(&custom_spool).map_err(|e| e.to_string())?;
    let mut with_torn_eof = clean_bytes.clone();
    with_torn_eof.extend_from_slice(&[0, 0, 0, 80, 1, 2, 3]);
    fs::write(&custom_spool, &with_torn_eof).map_err(|e| e.to_string())?;
    let report = recover_spool_frames(&custom_spool)?;
    if report.valid_records.len() != 2 || report.quarantined_tail_bytes != 7 {
        return Err(format!(
            "expected 2 recovered frames and 7 quarantined EOF bytes, got ({}, {})",
            report.valid_records.len(),
            report.quarantined_tail_bytes
        ));
    }

    // 2. Corrupting a byte inside complete frame #1 MUST fail closed (`CORRUPT_SPOOL_FRAME`), NOT skip!
    let mut corrupted = clean_bytes;
    corrupted[12] ^= 0xFF;
    fs::write(&custom_spool, &corrupted).map_err(|e| e.to_string())?;
    match recover_spool_frames(&custom_spool) {
        Ok(_) => {
            return Err(
                "DA-05 regression: corrupt complete spool frame was silently skipped!".to_string(),
            );
        }
        Err(e) if e.contains("CORRUPT_SPOOL_FRAME") => {}
        Err(other) => {
            return Err(format!("expected CORRUPT_SPOOL_FRAME, got: {other}"));
        }
    }

    Ok(
        "DA-05 verified: complete-frame CRC corruption fails closed while incomplete EOF tail quarantines"
            .to_string(),
    )
}

fn case_da06_dag_and_triangulation(
    _workspace_root: &Path,
    _bins: &WorkspaceBinaries,
) -> Result<String, String> {
    // 1. Overlapping directory/glob parallel writes in same wave MUST be rejected (`PARALLEL_WRITE_CONFLICT`)
    let overlapping_dag = r#"{
  "plan_id": "OVERLAP-TEST",
  "tasks": [
    {
      "id": "A",
      "wave": "W1",
      "depends_on": [],
      "domain_risk": "core_logic",
      "assigned_read_paths": ["src/lib.rs"],
      "allowed_write_paths": ["src/*"],
      "assigned_tests": ["t_a"]
    },
    {
      "id": "B",
      "wave": "W1",
      "depends_on": [],
      "domain_risk": "core_logic",
      "assigned_read_paths": ["src/calc.rs"],
      "allowed_write_paths": ["src/calc.rs"],
      "assigned_tests": ["t_b"]
    }
  ]
}"#;
    match parse_and_validate_dag_json(overlapping_dag) {
        Ok(_) => {
            return Err(
                "DA-06 regression: overlapping parallel write scopes ('src/*' vs 'src/calc.rs') accepted!"
                    .to_string(),
            );
        }
        Err(e) if e.contains("PARALLEL_WRITE_CONFLICT") => {}
        Err(other) => {
            return Err(format!("expected PARALLEL_WRITE_CONFLICT, got: {other}"));
        }
    }

    // 2. Transitive dependency chain `A -> B -> C` in wave W1 sharing `src/calc.rs` MUST be allowed!
    let transitive_dag = r#"{
  "plan_id": "TRANSITIVE-OK",
  "tasks": [
    {
      "id": "A",
      "wave": "W1",
      "depends_on": [],
      "domain_risk": "core_logic",
      "assigned_read_paths": ["src/calc.rs"],
      "allowed_write_paths": ["src/calc.rs"],
      "assigned_tests": ["t_a"]
    },
    {
      "id": "B",
      "wave": "W1",
      "depends_on": ["A"],
      "domain_risk": "core_logic",
      "assigned_read_paths": ["src/calc.rs"],
      "allowed_write_paths": ["src/calc.rs"],
      "assigned_tests": ["t_b"]
    },
    {
      "id": "C",
      "wave": "W1",
      "depends_on": ["B"],
      "domain_risk": "core_logic",
      "assigned_read_paths": ["src/calc.rs"],
      "allowed_write_paths": ["src/calc.rs"],
      "assigned_tests": ["t_c"]
    }
  ]
}"#;
    let _plan = parse_and_validate_dag_json(transitive_dag)?;

    // 3. `triangulate_faults` MUST inspect ALL `secondary_suspects` (including index >= 1), not just `.first()`!
    let attr_toml = "\
[[tests]]\n\
name = \"t_ab_boundary\"\n\
primary_suspect = \"A\"\n\
secondary_suspects = [\"B\", \"C\"]\n\
\n\
[[tests]]\n\
name = \"t_a\"\n\
primary_suspect = \"A\"\n\
secondary_suspects = []\n\
\n\
[[tests]]\n\
name = \"t_b\"\n\
primary_suspect = \"B\"\n\
secondary_suspects = []\n\
\n\
[[tests]]\n\
name = \"t_c\"\n\
primary_suspect = \"C\"\n\
secondary_suspects = []\n";
    let entries = parse_attribution_toml(attr_toml)?;
    let verdict = triangulate_faults(
        &entries,
        &["t_ab_boundary".to_string(), "t_c".to_string()],
        &["t_a".to_string(), "t_b".to_string()],
    );
    if verdict
        != (SuspectVerdict::BlockedByNeighbor {
            victim: "A".to_string(),
            neighbor_suspect: "C".to_string(),
            boundary_test: "t_ab_boundary".to_string(),
        })
    {
        return Err(format!(
            "DA-06 regression: expected BlockedByNeighbor(victim=A, neighbor=C) from 2nd secondary_suspect, got {verdict:?}"
        ));
    }

    Ok(
        "DA-06 verified: parallel prefix/glob write overlaps blocked and multi-secondary triangulation accurate"
            .to_string(),
    )
}
