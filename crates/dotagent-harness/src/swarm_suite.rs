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
const CASE_V2_BOOTSTRAP_CONCURRENT_SCOPE: &str =
    "swarm::v2_phase1_discovery_bootstrap_concurrent_hook_attach_and_scoped_hops";
const CASE_V2_ANTI_STUB_AND_LIVE_CONTRACTS: &str =
    "swarm::v2_anti_stub_gate_reviewer_block_and_live_integration_contracts";

pub fn swarm_case_ids() -> &'static [&'static str] {
    &[
        CASE_SIX_ROLE_E2E,
        CASE_DA01_MASTER_ESCALATION,
        CASE_DA02A_REVIEW_LEDGER_AND_ROUNDS,
        CASE_DA02B_TEST_RUNNER_INTEGRITY,
        CASE_DA04B_HASH_CHAINED_LEDGER,
        CASE_DA05_SPOOL_INTEGRITY,
        CASE_DA06_DAG_AND_TRIANGULATION,
        CASE_V2_BOOTSTRAP_CONCURRENT_SCOPE,
        CASE_V2_ANTI_STUB_AND_LIVE_CONTRACTS,
    ]
}

type SwarmCaseRunner = fn(&Path, &WorkspaceBinaries) -> Result<String, String>;

pub fn run_swarm_suite(
    workspace_root: &Path,
    bins: &WorkspaceBinaries,
    filter: Option<&str>,
) -> Vec<CaseResult> {
    let mut out = Vec::new();
    let runners: [(&str, SwarmCaseRunner); 9] = [
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
        (
            CASE_V2_BOOTSTRAP_CONCURRENT_SCOPE,
            case_v2_bootstrap_concurrent_scope,
        ),
        (
            CASE_V2_ANTI_STUB_AND_LIVE_CONTRACTS,
            case_v2_anti_stub_and_live_contracts,
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

fn run_guard_json(
    bins: &WorkspaceBinaries,
    sb: &TestSandbox,
    subcmd: &str,
    payload: &str,
) -> Result<Output, String> {
    let mut c = Command::new(&bins.agent_guard);
    c.args([subcmd, "--json", payload]);
    sb.configure_isolated_command(&mut c);
    c.output()
        .map_err(|e| format!("failed spawning agent-guard {subcmd}: {e}"))
}

fn case_v2_bootstrap_concurrent_scope(
    workspace_root: &Path,
    bins: &WorkspaceBinaries,
) -> Result<String, String> {
    let sb = TestSandbox::create(workspace_root, "swarm_v2_bootstrap_concurrent_scope")?;
    fs::create_dir_all(sb.repo_dir.join("src")).map_err(|e| e.to_string())?;
    fs::create_dir_all(sb.repo_dir.join("assets")).map_err(|e| e.to_string())?;
    fs::create_dir_all(sb.repo_dir.join("tests")).map_err(|e| e.to_string())?;
    fs::create_dir_all(sb.repo_dir.join("docs")).map_err(|e| e.to_string())?;

    // Seed A -> B -> C -> unassigned chain via backticked repo pointers.
    fs::write(
        sb.repo_dir.join("src/a.rs"),
        "// Entry module referencing `src/b.rs`\npub fn step_a() -> u32 { 1 }\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        sb.repo_dir.join("src/b.rs"),
        "// Middle module referencing `src/c.rs`\npub fn step_b() -> u32 { 2 }\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        sb.repo_dir.join("src/c.rs"),
        "// Leaf module referencing `src/unassigned.rs`\npub fn step_c() -> u32 { 3 }\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        sb.repo_dir.join("src/unassigned.rs"),
        "pub fn secret_unassigned() -> u32 { 99 }\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        sb.repo_dir.join("src/other.rs"),
        "pub fn other_worker_fn() -> u32 { 42 }\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        sb.repo_dir.join("tests/test_wave.py"),
        "import unittest\nclass WaveTest(unittest.TestCase):\n    def test_ok(self):\n        self.assertEqual(1 + 1, 2)\nif __name__ == '__main__':\n    unittest.main()\n",
    )
    .map_err(|e| e.to_string())?;

    // 1. Phase-1 Discovery Bootstrap BEFORE PLAN.lock.json exists:
    //    - Non-investigator roles MUST be rejected (`DISCOVERY_ROLE_FORBIDDEN`).
    let bad_disc = run_swarm_cmd(
        bins,
        &sb,
        &[
            "master",
            "mint-session",
            "--role",
            "grunt",
            "--task",
            "DISC-1",
            "--phase",
            "discovery",
        ],
        Some("master"),
        None,
    )?;
    if bad_disc.status.success()
        || !String::from_utf8_lossy(&bad_disc.stderr).contains("DISCOVERY_ROLE_FORBIDDEN")
    {
        return Err(format!(
            "expected DISCOVERY_ROLE_FORBIDDEN on grunt --phase discovery, got stderr={}",
            String::from_utf8_lossy(&bad_disc.stderr)
        ));
    }

    let disc_out = run_swarm_cmd(
        bins,
        &sb,
        &[
            "master",
            "mint-session",
            "--role",
            "investigator",
            "--task",
            "DISC-1",
            "--phase",
            "discovery",
            "--scope",
            "src/a.rs,src/b.rs,src/c.rs",
        ],
        Some("master"),
        None,
    )?;
    if !disc_out.status.success() {
        return Err(format!(
            "Phase-1 discovery mint-session failed: {}",
            String::from_utf8_lossy(&disc_out.stderr)
        ));
    }
    let disc_json = JsonValue::parse(&String::from_utf8_lossy(&disc_out.stdout))
        .map_err(|e| format!("invalid discovery mint JSON: {e}"))?;
    if disc_json.get("phase").and_then(JsonValue::as_str) != Some("discovery") {
        return Err("expected phase == 'discovery' on Phase-1 investigator mint".to_string());
    }
    let disc_sid = disc_json
        .get("session_id")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| "missing session_id on discovery mint".to_string())?
        .to_string();

    let scout_out = run_swarm_cmd(
        bins,
        &sb,
        &["investigator", "scout", "src", "--session", &disc_sid],
        None,
        None,
    )?;
    if !scout_out.status.success() {
        return Err(format!(
            "Phase-1 discovery scout failed: {}",
            String::from_utf8_lossy(&scout_out.stderr)
        ));
    }
    let fact_out = run_swarm_cmd(
        bins,
        &sb,
        &[
            "investigator",
            "emit-fact",
            "--session",
            &disc_sid,
            "--task",
            "DISC-1",
            "--claim",
            "Mapped step_a -> step_b -> step_c chain across src/a.rs..src/c.rs.",
            "--slice",
            "src/a.rs:1-2",
        ],
        None,
        None,
    )?;
    if !fact_out.status.success() {
        return Err(format!(
            "Phase-1 discovery emit-fact failed: {}",
            String::from_utf8_lossy(&fact_out.stderr)
        ));
    }
    let fact_pkt = String::from_utf8_lossy(&fact_out.stdout).trim().to_string();
    close_role_session(bins, &sb, &disc_sid)?;

    // Lock the wave DAG and confirm Phase-1 discovery packet provenance STILL verifies (no epoch wipe!).
    let parallel_dag = r#"{
  "plan_id": "V2-PARALLEL-BOOTSTRAP",
  "tasks": [
    {
      "id": "TASK-A",
      "wave": "W1",
      "depends_on": [],
      "domain_risk": "core_logic",
      "assigned_read_paths": ["src/a.rs", "src/b.rs", "src/c.rs", "tests/test_wave.py"],
      "allowed_write_paths": ["src/a.rs", "newdir/created.rs", "assets/font.woff2"],
      "assigned_tests": ["test_wave"]
    },
    {
      "id": "TASK-B",
      "wave": "W1",
      "depends_on": [],
      "domain_risk": "core_logic",
      "assigned_read_paths": ["src/other.rs", "tests/test_wave.py"],
      "allowed_write_paths": ["src/other.rs"],
      "assigned_tests": ["test_wave"]
    }
  ]
}"#;
    fs::write(sb.repo_dir.join("docs/dag.json"), parallel_dag).map_err(|e| e.to_string())?;
    let lock_out = run_swarm_cmd(
        bins,
        &sb,
        &["master", "lock-plan", "docs/dag.json"],
        Some("master"),
        None,
    )?;
    if !lock_out.status.success() {
        return Err(format!(
            "lock-plan after Phase-1 discovery failed: {}",
            String::from_utf8_lossy(&lock_out.stderr)
        ));
    }
    let ingest_after_lock = run_swarm_cmd(
        bins,
        &sb,
        &["master", "ingest-packet", &fact_pkt],
        Some("master"),
        None,
    )?;
    if !ingest_after_lock.status.success() {
        return Err(format!(
            "Phase-1 ObservedFact failed provenance check after initial lock-plan: {}",
            String::from_utf8_lossy(&ingest_after_lock.stderr)
        ));
    }

    // 2. Concurrent Worker Session Binding (`PreToolUse` auto-bind + explicit `attach`):
    let sid_a = mint_role_session(bins, &sb, "grunt", "TASK-A", 1)?;
    let sid_b = mint_role_session(bins, &sb, "grunt", "TASK-B", 1)?;

    // Unbound hook UUID MUST fail closed (`AMBIGUOUS_CONCURRENT_SWARM_SESSIONS`) when 2 sessions are open.
    let unbound_pre = run_guard_json(
        bins,
        &sb,
        "pre-tool",
        r#"{"session_id":"uuid-unbound","tool_name":"Read","tool_input":{"file_path":"src/a.rs"}}"#,
    )?;
    let unbound_msg = format!(
        "{}{}",
        String::from_utf8_lossy(&unbound_pre.stdout),
        String::from_utf8_lossy(&unbound_pre.stderr)
    );
    if !unbound_msg.contains("AMBIGUOUS_CONCURRENT_SWARM_SESSIONS") {
        return Err(format!(
            "expected AMBIGUOUS_CONCURRENT_SWARM_SESSIONS for unbound hook UUID, got: {unbound_msg}"
        ));
    }

    // Auto-bind `uuid-worker-a` via PreToolUse on `swarm-tool grunt context --session <sid_a>`.
    let auto_bind_payload = format!(
        r#"{{"session_id":"uuid-worker-a","tool_name":"Bash","tool_input":{{"command":"swarm-tool grunt context --session {sid_a}"}}}}"#
    );
    let auto_bind_out = run_guard_json(bins, &sb, "pre-tool", &auto_bind_payload)?;
    if !auto_bind_out.status.success() {
        return Err(format!(
            "PreToolUse auto-bind failed: {}{}",
            String::from_utf8_lossy(&auto_bind_out.stdout),
            String::from_utf8_lossy(&auto_bind_out.stderr)
        ));
    }

    // Bind `uuid-worker-b` via explicit `swarm-tool grunt attach --session <sid_b> --hook-session uuid-worker-b`.
    let attach_b = run_swarm_cmd(
        bins,
        &sb,
        &[
            "grunt",
            "attach",
            "--session",
            &sid_b,
            "--hook-session",
            "uuid-worker-b",
        ],
        None,
        None,
    )?;
    if !attach_b.status.success() {
        return Err(format!(
            "swarm-tool grunt attach failed: {}",
            String::from_utf8_lossy(&attach_b.stderr)
        ));
    }

    // Verify `uuid-worker-b` can read `src/other.rs` concurrently, while `uuid-worker-a` is blocked from `src/other.rs`.
    let b_read = run_guard_json(
        bins,
        &sb,
        "pre-tool",
        r#"{"session_id":"uuid-worker-b","tool_name":"Read","tool_input":{"file_path":"src/other.rs"}}"#,
    )?;
    if !b_read.status.success()
        || String::from_utf8_lossy(&b_read.stdout).contains("\"permissionDecision\":\"deny\"")
    {
        return Err(format!(
            "bound uuid-worker-b failed reading in-scope src/other.rs: {}",
            String::from_utf8_lossy(&b_read.stdout)
        ));
    }
    let a_cross_read = run_guard_json(
        bins,
        &sb,
        "pre-tool",
        r#"{"session_id":"uuid-worker-a","tool_name":"Read","tool_input":{"file_path":"src/other.rs"}}"#,
    )?;
    let a_cross_msg = format!(
        "{}{}",
        String::from_utf8_lossy(&a_cross_read.stdout),
        String::from_utf8_lossy(&a_cross_read.stderr)
    );
    if !a_cross_msg.contains("GRUNT_READ_OUT_OF_SCOPE") {
        return Err(format!(
            "expected GRUNT_READ_OUT_OF_SCOPE when uuid-worker-a reads TASK-B file, got: {a_cross_msg}"
        ));
    }

    // 3. Capability-preapproved `A -> B -> C` hop exemption on `uuid-worker-a`:
    for rel in ["src/a.rs", "src/b.rs", "src/c.rs"] {
        let pre_p = format!(
            r#"{{"session_id":"uuid-worker-a","tool_name":"Read","tool_input":{{"file_path":"{rel}"}}}}"#
        );
        let pre_r = run_guard_json(bins, &sb, "pre-tool", &pre_p)?;
        let pre_txt = String::from_utf8_lossy(&pre_r.stdout);
        if !pre_r.status.success()
            || pre_txt.contains("TRANSITIVE_DEPTH_EXCEEDED")
            || pre_txt.contains("\"deny\"")
        {
            return Err(format!(
                "capability-preapproved file '{rel}' unexpectedly denied on hop chain: stdout={pre_txt} stderr={}",
                String::from_utf8_lossy(&pre_r.stderr)
            ));
        }
        let body = fs::read_to_string(sb.repo_dir.join(rel)).map_err(|e| e.to_string())?;
        let post_obj = JsonValue::Object(vec![
            (
                "session_id".to_string(),
                JsonValue::Str("uuid-worker-a".to_string()),
            ),
            ("tool_name".to_string(), JsonValue::Str("Read".to_string())),
            (
                "tool_input".to_string(),
                JsonValue::Object(vec![(
                    "file_path".to_string(),
                    JsonValue::Str(rel.to_string()),
                )]),
            ),
            ("tool_response".to_string(), JsonValue::Str(body)),
        ]);
        let post_r = run_guard_json(bins, &sb, "post-tool", &post_obj.to_json_string())?;
        if !post_r.status.success() {
            return Err(format!(
                "post-tool failed on '{rel}': {}",
                String::from_utf8_lossy(&post_r.stderr)
            ));
        }
    }

    // 3b. Landlock precreate of new root-nested directory `newdir/created.rs` in `allowed_write_paths`:
    let mut sbx_cmd = Command::new(&bins.agent_guard);
    sbx_cmd.args([
        "exec-sandbox",
        "--session-id",
        "uuid-worker-a",
        "--",
        "printf 'pub fn created() -> u32 { 7 }\\n' > newdir/created.rs",
    ]);
    sb.configure_isolated_command(&mut sbx_cmd);
    let sbx_out = sbx_cmd
        .output()
        .map_err(|e| format!("exec-sandbox precreate test failed: {e}"))?;
    if !sbx_out.status.success() || !sb.repo_dir.join("newdir/created.rs").is_file() {
        return Err(format!(
            "exec-sandbox failed writing capability-authorized newdir/created.rs: status={:?} stderr={}",
            sbx_out.status.code(),
            String::from_utf8_lossy(&sbx_out.stderr)
        ));
    }

    // 3c. Vetted `.woff2` magic-byte check + raw SHA-256 breadcrumb in `post-edit`:
    fs::write(
        sb.repo_dir.join("assets/font.woff2"),
        b"FAKEFONT_NOT_WOFF2_HEADER",
    )
    .map_err(|e| e.to_string())?;
    let bad_font = run_guard_json(
        bins,
        &sb,
        "post-edit",
        r#"{"session_id":"uuid-worker-a","file_path":"assets/font.woff2"}"#,
    )?;
    if bad_font.status.success()
        || !String::from_utf8_lossy(&bad_font.stderr).contains("INVALID_WEBFONT_MAGIC")
    {
        return Err(format!(
            "expected INVALID_WEBFONT_MAGIC on spoofed .woff2, got stderr={}",
            String::from_utf8_lossy(&bad_font.stderr)
        ));
    }

    let mut valid_woff2 = b"wOF2\x00\x01\x00\x00".to_vec();
    valid_woff2.resize(64, 0u8);
    fs::write(sb.repo_dir.join("assets/font.woff2"), &valid_woff2).map_err(|e| e.to_string())?;
    let ok_font = run_guard_json(
        bins,
        &sb,
        "post-edit",
        r#"{"session_id":"uuid-worker-a","file_path":"assets/font.woff2"}"#,
    )?;
    if !ok_font.status.success() {
        return Err(format!(
            "valid wOF2 subset asset rejected by post-edit: {}",
            String::from_utf8_lossy(&ok_font.stderr)
        ));
    }
    if !sb.repo_dir.join("assets/.breadcrumbs.jsonl").is_file() {
        return Err(
            "expected assets/.breadcrumbs.jsonl after post-edit on valid .woff2".to_string(),
        );
    }

    close_role_session(bins, &sb, &sid_a)?;
    close_role_session(bins, &sb, &sid_b)?;

    Ok(
        "Swarm v2 bootstrap, concurrent hook auto-bind/attach, scoped A->B->C hops, Landlock precreate, and wOFF2 gate verified"
            .to_string(),
    )
}

fn case_v2_anti_stub_and_live_contracts(
    workspace_root: &Path,
    bins: &WorkspaceBinaries,
) -> Result<String, String> {
    let sb = TestSandbox::create(workspace_root, "swarm_v2_anti_stub_and_live_contracts")?;
    fs::create_dir_all(sb.repo_dir.join("src")).map_err(|e| e.to_string())?;
    fs::create_dir_all(sb.repo_dir.join("tests")).map_err(|e| e.to_string())?;
    fs::create_dir_all(sb.repo_dir.join("docs")).map_err(|e| e.to_string())?;

    let sec_dag = r#"{
  "plan_id": "V2-ANTI-STUB-GATE",
  "tasks": [
    {
      "id": "TASK-SEC",
      "wave": "W1",
      "depends_on": [],
      "domain_risk": "security_critical",
      "assigned_read_paths": ["src/vault.rs", "tests/test_vault_e2e.py"],
      "allowed_write_paths": ["src/vault.rs"],
      "assigned_tests": ["test_vault_e2e"]
    }
  ]
}"#;
    fs::write(sb.repo_dir.join("docs/dag.json"), sec_dag).map_err(|e| e.to_string())?;
    fs::write(
        sb.repo_dir.join("src/vault.rs"),
        "pub fn seal_secret(input: &str) -> usize {\n    input.len()\n}\n",
    )
    .map_err(|e| e.to_string())?;

    let lock_out = run_swarm_cmd(
        bins,
        &sb,
        &["master", "lock-plan", "docs/dag.json"],
        Some("master"),
        None,
    )?;
    if !lock_out.status.success() {
        return Err(format!(
            "lock-plan failed: {}",
            String::from_utf8_lossy(&lock_out.stderr)
        ));
    }

    // 1. Live Integration Contract Gate (`qa verify-attribution --require-live-contracts`):
    fs::write(
        sb.repo_dir.join("test_attribution.toml"),
        "[[tests]]\nname = \"test_vault_e2e\"\nprimary_suspect = \"TASK-SEC\"\nsecondary_suspects = []\n",
    )
    .map_err(|e| e.to_string())?;

    let qa_sid = mint_role_session(bins, &sb, "qa", "TASK-SEC", 1)?;

    // 1a. Missing integration test file under `tests/` -> `MISSING_LIVE_INTEGRATION_CONTRACT`.
    let missing_live = run_swarm_cmd(
        bins,
        &sb,
        &[
            "qa",
            "verify-attribution",
            "test_attribution.toml",
            "--require-live-contracts",
            "--session",
            &qa_sid,
        ],
        None,
        None,
    )?;
    if missing_live.status.success()
        || !String::from_utf8_lossy(&missing_live.stderr)
            .contains("MISSING_LIVE_INTEGRATION_CONTRACT")
    {
        return Err(format!(
            "expected MISSING_LIVE_INTEGRATION_CONTRACT when tests/ has no integration test, got: {}",
            String::from_utf8_lossy(&missing_live.stderr)
        ));
    }

    // 1b. Skipped integration test (`@unittest.skip`) -> `SKIPPED_ATTRIBUTED_TEST_FORBIDDEN`.
    fs::write(
        sb.repo_dir.join("tests/test_vault_e2e.py"),
        "import unittest\nclass VaultE2ETest(unittest.TestCase):\n    @unittest.skip('later')\n    def test_vault_e2e(self):\n        self.assertEqual(1, 1)\n",
    )
    .map_err(|e| e.to_string())?;
    let skipped_live = run_swarm_cmd(
        bins,
        &sb,
        &[
            "qa",
            "verify-attribution",
            "test_attribution.toml",
            "--require-live-contracts",
            "--session",
            &qa_sid,
        ],
        None,
        None,
    )?;
    if skipped_live.status.success()
        || !String::from_utf8_lossy(&skipped_live.stderr)
            .contains("SKIPPED_ATTRIBUTED_TEST_FORBIDDEN")
    {
        return Err(format!(
            "expected SKIPPED_ATTRIBUTED_TEST_FORBIDDEN on skipped test_vault_e2e, got: {}",
            String::from_utf8_lossy(&skipped_live.stderr)
        ));
    }

    // 1c. Live integration test without skip annotations passes `--require-live-contracts`.
    fs::write(
        sb.repo_dir.join("tests/test_vault_e2e.py"),
        "import unittest\nclass VaultE2ETest(unittest.TestCase):\n    def test_vault_e2e(self):\n        self.assertEqual(2 + 2, 4)\nif __name__ == '__main__':\n    unittest.main()\n",
    )
    .map_err(|e| e.to_string())?;
    let ok_live = run_swarm_cmd(
        bins,
        &sb,
        &[
            "qa",
            "verify-attribution",
            "test_attribution.toml",
            "--require-live-contracts",
            "--session",
            &qa_sid,
        ],
        None,
        None,
    )?;
    if !ok_live.status.success() {
        return Err(format!(
            "expected live integration contract verification to pass, got: {}",
            String::from_utf8_lossy(&ok_live.stderr)
        ));
    }
    close_role_session(bins, &sb, &qa_sid)?;

    // 2. Anti-Stub Gate (`submit-ledger --reject-stubs` + Reviewer hard block):
    let grunt_a1 = mint_role_session(bins, &sb, "grunt", "TASK-SEC", 1)?;
    fs::write(
        sb.repo_dir.join("src/vault.rs"),
        concat!(
            "pub fn dispatch(cmd: &str) {\n",
            "    let _ = read_secret_stdin();\n",
            "    match cmd {\n",
            "        \"rotate\" => {}\n",
            "        _ => todo!(\"finish vault handler\"),\n",
            "    }\n",
            "}\n",
        ),
    )
    .map_err(|e| e.to_string())?;

    let rec_a1 = run_swarm_cmd(
        bins,
        &sb,
        &[
            "grunt",
            "record-edit",
            "--session",
            &grunt_a1,
            "--file",
            "src/vault.rs",
        ],
        None,
        None,
    )?;
    if !rec_a1.status.success() {
        return Err(format!(
            "grunt record-edit a1 failed: {}",
            String::from_utf8_lossy(&rec_a1.stderr)
        ));
    }
    let cp_a1 = run_swarm_cmd(
        bins,
        &sb,
        &[
            "grunt",
            "checkpoint-green",
            "--session",
            &grunt_a1,
            "--",
            "python3",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-k",
            "test_vault_e2e",
        ],
        None,
        None,
    )?;
    if !cp_a1.status.success() {
        return Err(format!(
            "grunt checkpoint-green a1 failed: {}",
            String::from_utf8_lossy(&cp_a1.stderr)
        ));
    }

    // 2a. `submit-ledger --reject-stubs` MUST reject hollow production stubs (`HOLLOW_STUB_IMPLEMENTATION_REJECTED`).
    let reject_sub = run_swarm_cmd(
        bins,
        &sb,
        &[
            "grunt",
            "submit-ledger",
            "--session",
            &grunt_a1,
            "--reject-stubs",
            "--what",
            "Added dispatch stub in src/vault.rs. Wired initial rotate match arm.",
            "--why",
            "Prepared command dispatch entry point. Verified unit harness executes.",
        ],
        None,
        None,
    )?;
    if reject_sub.status.success()
        || !String::from_utf8_lossy(&reject_sub.stderr)
            .contains("HOLLOW_STUB_IMPLEMENTATION_REJECTED")
    {
        return Err(format!(
            "expected HOLLOW_STUB_IMPLEMENTATION_REJECTED on --reject-stubs, got stderr={}",
            String::from_utf8_lossy(&reject_sub.stderr)
        ));
    }

    // 2b. Even if submitted without `--reject-stubs`, `hollow_stub:*` badges are recorded and
    //     `AdversarialReviewer` `--decision approve` MUST hard-block (`REVIEWER_APPROVAL_BLOCKED_BY_HOLLOW_STUB`)!
    let plain_sub = run_swarm_cmd(
        bins,
        &sb,
        &[
            "grunt",
            "submit-ledger",
            "--session",
            &grunt_a1,
            "--what",
            "Added dispatch stub in src/vault.rs. Wired initial rotate match arm.",
            "--why",
            "Prepared command dispatch entry point. Verified unit harness executes.",
        ],
        None,
        None,
    )?;
    if !plain_sub.status.success() {
        return Err(format!(
            "plain submit-ledger a1 failed: {}",
            String::from_utf8_lossy(&plain_sub.stderr)
        ));
    }
    if !String::from_utf8_lossy(&plain_sub.stdout).contains("hollow_stub:") {
        return Err(format!(
            "expected hollow_stub:* smell badge on receipt, got: {}",
            String::from_utf8_lossy(&plain_sub.stdout)
        ));
    }

    let rev_a1 = mint_role_session(bins, &sb, "reviewer", "TASK-SEC", 1)?;
    let blocked_approve = run_swarm_cmd(
        bins,
        &sb,
        &[
            "reviewer",
            "verdict",
            "--session",
            &rev_a1,
            "--task",
            "TASK-SEC",
            "--round",
            "1",
            "--attempt",
            "1",
            "--decision",
            "approve",
            "--notes",
            "Attempted rubber-stamp approval.",
        ],
        None,
        None,
    )?;
    if blocked_approve.status.success()
        || !String::from_utf8_lossy(&blocked_approve.stderr)
            .contains("REVIEWER_APPROVAL_BLOCKED_BY_HOLLOW_STUB")
    {
        return Err(format!(
            "expected REVIEWER_APPROVAL_BLOCKED_BY_HOLLOW_STUB, got stderr={}",
            String::from_utf8_lossy(&blocked_approve.stderr)
        ));
    }

    let reject_verdict = run_swarm_cmd(
        bins,
        &sb,
        &[
            "reviewer",
            "verdict",
            "--session",
            &rev_a1,
            "--task",
            "TASK-SEC",
            "--round",
            "1",
            "--attempt",
            "1",
            "--decision",
            "reject",
            "--notes",
            "Hollow stub in src/vault.rs: remove todo! and empty rotate arm.",
        ],
        None,
        None,
    )?;
    if !reject_verdict.status.success() {
        return Err(format!(
            "reviewer reject verdict failed: {}",
            String::from_utf8_lossy(&reject_verdict.stderr)
        ));
    }
    close_role_session(bins, &sb, &rev_a1)?;

    // 2c. Clean-slate `attempt 2` implements real logic, passes `submit-ledger --reject-stubs` AND Reviewer approval!
    let grunt_a2 = mint_role_session(bins, &sb, "grunt", "TASK-SEC", 2)?;
    fs::write(
        sb.repo_dir.join("src/vault.rs"),
        concat!(
            "pub fn dispatch(cmd: &str, secret: &[u8]) -> Result<usize, &'static str> {\n",
            "    if secret.is_empty() {\n",
            "        return Err(\"EMPTY_SECRET\");\n",
            "    }\n",
            "    match cmd {\n",
            "        \"rotate\" => Ok(secret.len()),\n",
            "        _ => Err(\"UNSUPPORTED_COMMAND\"),\n",
            "    }\n",
            "}\n",
        ),
    )
    .map_err(|e| e.to_string())?;
    let rec_a2 = run_swarm_cmd(
        bins,
        &sb,
        &[
            "grunt",
            "record-edit",
            "--session",
            &grunt_a2,
            "--file",
            "src/vault.rs",
        ],
        None,
        None,
    )?;
    if !rec_a2.status.success() {
        return Err(format!(
            "grunt record-edit a2 failed: {}",
            String::from_utf8_lossy(&rec_a2.stderr)
        ));
    }
    let cp_a2 = run_swarm_cmd(
        bins,
        &sb,
        &[
            "grunt",
            "checkpoint-green",
            "--session",
            &grunt_a2,
            "--",
            "python3",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-k",
            "test_vault_e2e",
        ],
        None,
        None,
    )?;
    if !cp_a2.status.success() {
        return Err(format!(
            "grunt checkpoint-green a2 failed: {}",
            String::from_utf8_lossy(&cp_a2.stderr)
        ));
    }
    let clean_sub = run_swarm_cmd(
        bins,
        &sb,
        &[
            "grunt",
            "submit-ledger",
            "--session",
            &grunt_a2,
            "--reject-stubs",
            "--what",
            "Implemented real secret validation and rotate handler in src/vault.rs. Removed all hollow placeholders.",
            "--why",
            "Enforced non-empty secret custody invariant on rotate commands. Verified live e2e contract suite.",
        ],
        None,
        None,
    )?;
    if !clean_sub.status.success() {
        return Err(format!(
            "clean submit-ledger --reject-stubs failed: {}",
            String::from_utf8_lossy(&clean_sub.stderr)
        ));
    }

    let rev_a2 = mint_role_session(bins, &sb, "reviewer", "TASK-SEC", 2)?;
    let ok_approve = run_swarm_cmd(
        bins,
        &sb,
        &[
            "reviewer",
            "verdict",
            "--session",
            &rev_a2,
            "--task",
            "TASK-SEC",
            "--round",
            "2",
            "--attempt",
            "2",
            "--decision",
            "approve",
            "--notes",
            "Verified clean non-stub implementation and passing live contract.",
        ],
        None,
        None,
    )?;
    if !ok_approve.status.success() {
        return Err(format!(
            "reviewer approve on clean attempt 2 failed: {}",
            String::from_utf8_lossy(&ok_approve.stderr)
        ));
    }
    close_role_session(bins, &sb, &rev_a2)?;

    Ok(
        "Anti-stub scanner, submit-ledger --reject-stubs, Reviewer hollow-stub block, and QA live integration contract gate verified"
            .to_string(),
    )
}
