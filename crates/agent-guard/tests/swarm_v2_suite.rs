#![forbid(unsafe_code)]

//! Comprehensive Zero-Trust Swarm v2 specification & hostile-audit test suite
//! covering `F02`, `F06`, `F08`, `F10`, `F14`, `F16`, `F17`, `F18`, `F20`,
//! `F21`, `F27`, `F32`, and `F33`.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use agent_guard::breadcrumbs::{
    SignedBreadcrumbRecord, append_breadcrumb_for_path, ensure_git_info_exclude,
    flush_records_idempotent, recover_spool_frames, sha256_digest, spool_file_path,
    swarm_state_dir, verify_breadcrumbs_file,
};
use agent_guard::json::JsonValue;
use agent_guard::qa_suspects::{
    compute_task_coverage_targets, parse_and_validate_dag_json, parse_attribution_toml,
    save_locked_plan, triangulate_faults, verify_attribution_against_plan,
};
use agent_guard::role_sandbox::{
    check_role_shell_write_scope, enforce_role_pre_tool, evaluate_reviewer_verdict,
    is_qa_writable_path, lookup_pinned_package_doc, mint_session_capability,
    parse_and_validate_worker_packet, scout_repo_signatures,
};
use agent_guard::swarm_contracts::{
    EventOp, ReviewVerdictOutcome, SmellBucket, SuspectVerdict, SwarmRole,
};
use agent_guard::work_ledger::{
    classify_session_smells, compute_scoped_tree_oid, record_test_checkpoint,
    submit_work_ledger_entry, validate_two_plus_two_sentences, work_ledger_state_path,
};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn isolated_sandbox(name: &str) -> (PathBuf, PathBuf) {
    let dir = workspace_root()
        .join("target")
        .join("test-workspaces")
        .join(name);
    let _ = fs::remove_dir_all(&dir);
    let repo = dir.join("repo");
    let state = dir.join("state");
    fs::create_dir_all(repo.join(".git").join("info")).expect("create .git/info");
    fs::create_dir_all(&state).expect("create isolated state");
    fs::write(repo.join("AGENTS.md"), "# Canonical Root AGENTS.md\n").expect("write AGENTS.md");
    if let Ok(sdir) = swarm_state_dir(&repo) {
        let _ = fs::remove_dir_all(sdir);
    }
    (repo, state)
}

#[test]
fn f02_rejects_identical_content_path_swap_in_breadcrumbs() {
    let (repo, state) = isolated_sandbox("f02_path_swap");
    // Use mutex-free per-process state check via explicit repo hash isolation
    // (`swarm_state_dir` hashes canonical `repo` path, so every test sandbox has its own HMAC key!)
    let _ = state;

    fs::create_dir_all(repo.join("src")).unwrap();
    fs::create_dir_all(repo.join("tests/fixtures")).unwrap();
    let identical_bytes = b"pub const MAX_TTL: u64 = 300;\n";
    fs::write(repo.join("src/token_policy.rs"), identical_bytes).unwrap();
    fs::write(repo.join("tests/fixtures/token_policy.rs"), identical_bytes).unwrap();

    let signed = append_breadcrumb_for_path(
        &repo,
        "swm_grunt_t1",
        "W1.C",
        [0x11; 32],
        EventOp::FileEdit,
        "tests/fixtures/token_policy.rs",
        Some((1, 1)),
        sha256_digest(identical_bytes),
    )
    .expect("record fixture edit breadcrumb");

    let legitimate_trail = repo.join("tests/fixtures/.breadcrumbs.jsonl");
    assert_eq!(
        verify_breadcrumbs_file(&repo, &legitimate_trail).expect("legitimate trail valid"),
        1
    );

    // Forge a path-swap record claiming `src/token_policy.rs` was edited with the fixture's valid MAC!
    let mut forged: SignedBreadcrumbRecord = signed;
    forged.event.canonical_rel_path = "src/token_policy.rs".to_string();
    let forged_trail = repo.join("src/.breadcrumbs.jsonl");
    fs::write(&forged_trail, format!("{}\n", forged.to_json_line())).unwrap();

    let err = verify_breadcrumbs_file(&repo, &forged_trail)
        .expect_err("path-swapped breadcrumb MUST fail HMAC verification");
    assert!(
        err.contains("HMAC-SHA256 authentication tag mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
fn f06_investigator_depth_20_allowed_while_node_modules_and_writes_blocked() {
    let (repo, _) = isolated_sandbox("f06_investigator_depth");

    // Build a 10-level deep safe Rust module AND a forbidden node_modules trap
    let deep_dir = repo.join("a/b/c/d/e/f/g/h/i/j");
    fs::create_dir_all(&deep_dir).unwrap();
    fs::write(
        deep_dir.join("deep_mod.rs"),
        "pub fn deep_hidden_symbol(x: u32) -> u32 { x + 1 }\n",
    )
    .unwrap();

    let forbidden_nm = repo.join("a/b/node_modules/evil");
    fs::create_dir_all(&forbidden_nm).unwrap();
    fs::write(
        forbidden_nm.join("trap.rs"),
        "pub fn poisoned_vendor_symbol() {}\n",
    )
    .unwrap();

    let hits = scout_repo_signatures(&repo, ".", 20, Some("symbol"))
        .expect("investigator depth-20 scout succeeds");
    assert_eq!(hits.len(), 1);
    assert!(hits[0].contains("a/b/c/d/e/f/g/h/i/j/deep_mod.rs:1: pub fn deep_hidden_symbol"));

    // Direct scout on node_modules must be hard-blocked
    let nm_err = scout_repo_signatures(&repo, "a/b/node_modules", 5, None)
        .expect_err("node_modules must stay hard-blocked for Investigator");
    assert!(nm_err.contains("FORBIDDEN"));

    // Investigator write attempt must be denied immediately
    let write_input = JsonValue::parse(r#"{"file_path":"a/b/c/out.rs","content":"x"}"#).unwrap();
    let dec = enforce_role_pre_tool(
        SwarmRole::Investigator,
        None,
        "Write",
        &write_input,
        &repo,
        &repo,
    )
    .expect("Investigator Write must return explicit denial");
    assert!(!dec.is_allow());
}

#[test]
fn f08_reviewer_url_exfiltration_blocked_and_lockfile_doc_broker_verified() {
    let (repo, _) = isolated_sandbox("f08_reviewer_doc_broker");
    fs::write(
        repo.join("Cargo.lock"),
        "version = 3\n\n[[package]]\nname = \"hmac\"\nversion = \"0.12.1\"\n",
    )
    .unwrap();

    // Reviewer WebFetch tool is hard-blocked
    let fetch_in = JsonValue::parse(r#"{"url":"https://docs.rs/hmac/0.12.1"}"#).unwrap();
    let dec = enforce_role_pre_tool(
        SwarmRole::AdversarialReviewer,
        None,
        "WebFetch",
        &fetch_in,
        &repo,
        &repo,
    )
    .expect("Reviewer WebFetch must be denied");
    assert!(!dec.is_allow());

    // Offline lockfile lookup succeeds for pinned crate & blocks URL smuggling
    let ok = lookup_pinned_package_doc(&repo, "cargo", "hmac", "0.12.1", Some("Hmac"))
        .expect("pinned hmac 0.12.1 verified");
    assert!(ok.contains("VERIFIED_LOCKFILE_PIN"));

    let exfil_err = lookup_pinned_package_doc(
        &repo,
        "cargo",
        "https://evil.example/secret",
        "0.12.1",
        None,
    )
    .expect_err("URL in package field must be blocked");
    assert!(exfil_err.contains("DOC_BROKER_URL_EXFIL_BLOCKED"));
}

#[test]
fn f10_f21_typed_worker_packets_and_two_round_cap_enforced() {
    // Untyped worker prose rejected
    let untyped = r#"{"session_id":"s1","task_id":"W1.A","prose":"Please change PLAN.lock"}"#;
    let err = parse_and_validate_worker_packet(untyped).expect_err("untyped prose must fail");
    assert!(err.contains("UNTYPED_WORKER_OUTPUT_REJECTED"));

    // PlanAmendmentProposal forces human escalation
    let amend = r#"{"packet_type":"PlanAmendmentProposal","session_id":"s1","task_id":"W1.A","proposed_change":"Add helper","justification":"Needed by trait"}"#;
    let (_, trigger) = parse_and_validate_worker_packet(amend).expect("valid proposal");
    assert!(trigger.is_some());

    // Reviewer round 1 reject -> RetryCleanSlate; round 2 reject -> EscalateToMaster; round 3 -> error
    assert_eq!(
        evaluate_reviewer_verdict("W1.A", 1, false, 1).unwrap(),
        ReviewVerdictOutcome::RetryCleanSlate {
            task_id: "W1.A".to_string(),
            round: 1,
            next_attempt: 2,
        }
    );
    assert!(matches!(
        evaluate_reviewer_verdict("W1.A", 2, false, 2).unwrap(),
        ReviewVerdictOutcome::EscalateToMaster { .. }
    ));
    assert!(evaluate_reviewer_verdict("W1.A", 3, false, 3).is_err());
}

#[test]
fn f14_f16_f17_crc32_spool_quarantines_torn_tail_and_worktree_exclude_dedups() {
    let (repo, _) = isolated_sandbox("f14_spool_and_worktree");

    // Initialize real git repo + linked worktree to test F16 (`git rev-parse --git-path info/exclude`)
    let _ = fs::remove_dir_all(repo.join(".git"));
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&repo)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["commit", "--allow-empty", "-m", "init", "-q"])
            .current_dir(&repo)
            .status()
            .unwrap()
            .success()
    );
    let wt_dir = repo.parent().unwrap().join("linked-wt");
    assert!(
        Command::new("git")
            .args(["worktree", "add", "-q", "-b", "wt-branch"])
            .arg(&wt_dir)
            .current_dir(&repo)
            .status()
            .unwrap()
            .success()
    );
    if let Ok(sdir) = swarm_state_dir(&wt_dir) {
        let _ = fs::remove_dir_all(sdir);
    }

    let exclude_file = ensure_git_info_exclude(&wt_dir)
        .expect("resolve linked worktree git info/exclude")
        .expect("exclude path present");
    let exclude_body = fs::read_to_string(&exclude_file).unwrap();
    assert!(
        exclude_body
            .lines()
            .any(|l| l.trim() == ".breadcrumbs.jsonl")
    );

    // Write 2 valid events, then corrupt/truncate a 3rd frame tail in the binary spool
    fs::write(wt_dir.join("mod.rs"), "pub fn a() {}\n").unwrap();
    let r1 = append_breadcrumb_for_path(
        &wt_dir,
        "swm_crash_test",
        "W1.C",
        [0x22; 32],
        EventOp::FileEdit,
        "mod.rs",
        Some((1, 1)),
        sha256_digest(b"pub fn a() {}\n"),
    )
    .unwrap();
    let r2 = append_breadcrumb_for_path(
        &wt_dir,
        "swm_crash_test",
        "W1.C",
        [0x22; 32],
        EventOp::TestGreen,
        "mod.rs",
        None,
        sha256_digest(b"pub fn a() {}\n"),
    )
    .unwrap();

    let spool = spool_file_path(&wt_dir, "swm_crash_test").unwrap();
    let mut f = OpenOptions::new().append(true).open(&spool).unwrap();
    // Write a torn 20-byte header+partial payload simulating SIGKILL mid-write
    f.write_all(&[0, 0, 0, 99, 0xDE, 0xAD, 0xBE, 0xEF, b'{', b'"', b'x'])
        .unwrap();
    drop(f);

    let report = recover_spool_frames(&spool).expect("recover intact prefix frames");
    assert_eq!(report.valid_records.len(), 2);
    assert_eq!(report.quarantined_tail_bytes, 11);
    assert!(report.quarantine_path.unwrap().exists());

    // Idempotent dedup check (F17): re-flushing r1 + r2 appends 0 duplicate lines
    let trail = wt_dir.join(".breadcrumbs.jsonl");
    let newly_added = flush_records_idempotent(&trail, &[r1, r2]).unwrap();
    assert_eq!(newly_added, 0);
}

#[test]
fn f20_f27_domain_floored_coverage_and_fault_triangulation_verdicts() {
    let dag_raw = fs::read_to_string(workspace_root().join("docs/swarm_v2.dag.json")).unwrap();
    let plan = parse_and_validate_dag_json(&dag_raw).expect("swarm_v2.dag.json valid");
    let targets = compute_task_coverage_targets(&plan);

    // Leaf node W3.A touches adversarial security tests -> domain floor keeps it >= 92% even with 0 downstream dependents!
    let leaf = targets.iter().find(|t| t.task_id == "W3.A").unwrap();
    assert_eq!(leaf.downstream_dependents, 0);
    assert!(leaf.required_coverage_pct >= 92);

    // Verify repo's own tests/swarm_v2_attribution.toml against docs/swarm_v2.dag.json
    let attr_raw =
        fs::read_to_string(workspace_root().join("tests/swarm_v2_attribution.toml")).unwrap();
    let rules = parse_attribution_toml(&attr_raw).expect("parse attribution toml");
    verify_attribution_against_plan(&rules, &plan).expect("attribution matches DAG tasks");

    // 1. SuspectIsolated
    let v1 = triangulate_faults(
        &rules,
        &["f02_rejects_identical_content_path_swap_in_breadcrumbs".to_string()],
        &[],
    );
    assert_eq!(
        v1,
        SuspectVerdict::SuspectIsolated {
            primary_suspect: "W1.C".to_string(),
            failing_tests: vec![
                "f02_rejects_identical_content_path_swap_in_breadcrumbs".to_string()
            ],
        }
    );

    // 2. BlockedByNeighbor (boundary test fails + secondary suspect W1.C isolated test fails)
    let v2 = triangulate_faults(
        &rules,
        &[
            "f18_f32_f33_work_ledger_two_plus_two_tree_oid_and_smell_badges".to_string(),
            "f02_rejects_identical_content_path_swap_in_breadcrumbs".to_string(),
        ],
        &[],
    );
    assert_eq!(
        v2,
        SuspectVerdict::BlockedByNeighbor {
            victim: "W1.D".to_string(),
            neighbor_suspect: "W1.C".to_string(),
            boundary_test: "f18_f32_f33_work_ledger_two_plus_two_tree_oid_and_smell_badges"
                .to_string(),
        }
    );

    // 3a. InconclusiveAskMaster when boundary test fails WITHOUT passing standalone unit tests for both suspects
    let v3_incomplete = triangulate_faults(
        &rules,
        &["f18_f32_f33_work_ledger_two_plus_two_tree_oid_and_smell_badges".to_string()],
        &[],
    );
    assert!(matches!(
        v3_incomplete,
        SuspectVerdict::InconclusiveAskMaster { .. }
    ));

    // 3b. SeamOrSpecConflict (ONLY boundary test fails while BOTH W1.D and W1.C standalone unit tests explicitly pass)
    let v3 = triangulate_faults(
        &rules,
        &["f18_f32_f33_work_ledger_two_plus_two_tree_oid_and_smell_badges".to_string()],
        &[
            "f02_rejects_identical_content_path_swap_in_breadcrumbs".to_string(),
            "pr2_review_regressions_role_sandbox_spool_and_ledger_pins".to_string(),
        ],
    );
    assert_eq!(
        v3,
        SuspectVerdict::SeamOrSpecConflict {
            task_a: "W1.D".to_string(),
            task_b: "W1.C".to_string(),
            boundary_test: "f18_f32_f33_work_ledger_two_plus_two_tree_oid_and_smell_badges"
                .to_string(),
        }
    );
}

#[test]
fn f18_f32_f33_work_ledger_two_plus_two_tree_oid_and_smell_badges() {
    let (repo, _) = isolated_sandbox("f18_work_ledger");
    let dag = r#"{
      "plan_id": "TEST-PLAN",
      "tasks": [
        {
          "id": "T1",
          "wave": "W1",
          "depends_on": [],
          "domain_risk": "security_critical",
          "assigned_read_paths": ["src/lib.rs"],
          "allowed_write_paths": ["src/lib.rs"],
          "assigned_tests": ["t1_unit"]
        }
      ]
    }"#;
    let plan = parse_and_validate_dag_json(dag).unwrap();
    save_locked_plan(&repo, &plan, false).unwrap();

    fs::create_dir_all(repo.join("src")).unwrap();
    fs::write(
        repo.join("src/lib.rs"),
        "pub fn add(a: i32, b: i32) -> i32 { a + b }\n",
    )
    .unwrap();

    let cap = mint_session_capability(&repo, SwarmRole::Grunt, "T1", 1).unwrap();

    // Sentence validator enforces exact 2+2 pure ASCII sentences
    assert!(validate_two_plus_two_sentences("One sentence only.", "First. Second.").is_err());
    validate_two_plus_two_sentences(
        "Implemented checked addition in src/lib.rs. Added overflow guard for negative bounds.",
        "Locked task T1 required deterministic arithmetic. Upfront QA suite verifies boundary cases.",
    )
    .expect("valid 2+2 ASCII sentences");

    // Submitting before green test checkpoint must fail closed
    assert!(
        submit_work_ledger_entry(
            &repo,
            &cap.session_id,
            "Implemented checked addition in src/lib.rs. Added overflow guard for negative bounds.",
            "Locked task T1 required deterministic arithmetic. Upfront QA suite verifies boundary cases.",
        )
        .is_err()
    );

    // Record green test checkpoint, then sneak in an unverified edit -> must catch edit_after_last_green_test (F18)!
    record_test_checkpoint(&repo, &cap.session_id, true).unwrap();
    fs::write(
        repo.join("src/lib.rs"),
        "pub fn add(a: i32, b: i32) -> i32 { a - b }\n",
    )
    .unwrap();

    let reloaded =
        agent_guard::role_sandbox::load_session_capability(&repo, &cap.session_id).unwrap();
    let smells = classify_session_smells(&repo, &reloaded).unwrap();
    assert!(
        smells
            .iter()
            .any(|b| b.bucket == SmellBucket::Risky && b.signal == "edit_after_last_green_test")
    );
    let post_edit_err = submit_work_ledger_entry(
        &repo,
        &cap.session_id,
        "Implemented checked addition in src/lib.rs. Added overflow guard for negative bounds.",
        "Locked task T1 required deterministic arithmetic. Upfront QA suite verifies boundary cases.",
    )
    .expect_err("unverified edit after green checkpoint must block ledger submit");
    assert!(post_edit_err.contains("EDIT_AFTER_LAST_GREEN_TEST"));

    // Re-checkpoint green WITHOUT recording an authenticated FileEdit breadcrumb -> must fail with LEDGER_MISSING_EDIT_PROVENANCE!
    record_test_checkpoint(&repo, &cap.session_id, true).unwrap();
    let missing_prov_err = submit_work_ledger_entry(
        &repo,
        &cap.session_id,
        "Implemented checked addition in src/lib.rs. Added overflow guard for negative bounds.",
        "Locked task T1 required deterministic arithmetic. Upfront QA suite verifies boundary cases.",
    )
    .expect_err("green checkpoint without FileEdit provenance must be rejected");
    assert!(
        missing_prov_err.contains("LEDGER_MISSING_EDIT_PROVENANCE"),
        "expected LEDGER_MISSING_EDIT_PROVENANCE, got: {missing_prov_err}"
    );

    // Record authenticated FileEdit breadcrumb matching on-disk bytes + re-checkpoint green -> submit succeeds!
    append_breadcrumb_for_path(
        &repo,
        &cap.session_id,
        "T1",
        [0x11; 32],
        EventOp::FileEdit,
        "src/lib.rs",
        Some((1, 1)),
        sha256_digest(b"pub fn add(a: i32, b: i32) -> i32 { a - b }\n"),
    )
    .unwrap();
    record_test_checkpoint(&repo, &cap.session_id, true).unwrap();
    let entry = submit_work_ledger_entry(
        &repo,
        &cap.session_id,
        "Implemented checked addition in src/lib.rs. Added overflow guard for negative bounds.",
        "Locked task T1 required deterministic arithmetic. Upfront QA suite verifies boundary cases.",
    )
    .expect("ledger submit succeeds after FileEdit provenance + green checkpoint");
    assert!(entry.smell_badges.is_empty());
}

#[test]
fn all_six_role_skills_guides_and_compiled_agents_verified() {
    let root = workspace_root();
    for role in SwarmRole::all_swarm_roles() {
        let skill_dir = role.skill_dir_name().expect("swarm role skill dir");
        let skill_md = root.join("skills").join(skill_dir).join("SKILL.md");
        let guide_md = root.join("skills").join(skill_dir).join("ROLE_GUIDE.md");
        let nested_readme = root.join("skills").join(skill_dir).join("README.md");
        let profile_toml = root.join("profiles").join(format!("{skill_dir}.toml"));

        assert!(skill_md.exists(), "missing {}", skill_md.display());
        assert!(guide_md.exists(), "missing {}", guide_md.display());
        assert!(
            !nested_readme.exists(),
            "nested README.md must not exist: {}",
            nested_readme.display()
        );
        assert!(profile_toml.exists(), "missing {}", profile_toml.display());

        for dot_dir in [".claude", ".cursor", ".codex"] {
            let repo_agent = root
                .join(dot_dir)
                .join("agents")
                .join(format!("{skill_dir}.md"));
            assert!(repo_agent.exists(), "missing {}", repo_agent.display());
        }
        for harness in ["claude", "cursor", "codex", "gemini"] {
            let dist_agent = root
                .join("dist")
                .join(harness)
                .join("agents")
                .join(format!("{skill_dir}.md"));
            assert!(dist_agent.exists(), "missing {}", dist_agent.display());
        }

        let guide_text = fs::read_to_string(&guide_md).unwrap();
        assert!(guide_text.contains("## 1. What Your Job Is"));
        assert!(guide_text.contains("## 2. Explicit Rules You Must Follow"));
        assert!(guide_text.contains("## 3. Your Dedicated Rust Tooling"));
        assert!(guide_text.contains("swarm-tool "));
    }
}

#[test]
fn pr2_review_regressions_role_sandbox_spool_and_ledger_pins() {
    let (repo, _) = isolated_sandbox("pr2_review_regressions");

    // 1. QA writable path policy blocks all `src/` writes (including `src/*_test.rs` & `src/tests/*`) while allowing `tests/` & `pkg/test_*.py`
    assert!(!is_qa_writable_path("src/test_backdoor.rs"));
    assert!(!is_qa_writable_path(
        "crates/agent-guard/src/test_helper.rs"
    ));
    assert!(!is_qa_writable_path("src/calc_test.rs"));
    assert!(!is_qa_writable_path("src/tests/evil.rs"));
    assert!(is_qa_writable_path("crates/foo/tests/calc_test.rs"));
    assert!(is_qa_writable_path("tests/integration.rs"));
    assert!(is_qa_writable_path("pkg/test_auth.py"));

    // 2. Grunt without minted capability fails closed on both pre-tool and shell write checks
    let read_in = JsonValue::parse(r#"{"file_path":"src/lib.rs"}"#).unwrap();
    let missing_cap_dec =
        enforce_role_pre_tool(SwarmRole::Grunt, None, "Read", &read_in, &repo, &repo)
            .expect("Grunt without capability must be denied");
    assert!(!missing_cap_dec.is_allow());
    assert!(
        check_role_shell_write_scope(SwarmRole::Grunt, None, &["src/lib.rs".to_string()], &repo)
            .is_err()
    );

    // 3. Grunt cannot read arbitrary `docs/` outside `assigned_read_paths`
    let dag = r#"{
      "plan_id": "PR2-REGRESSION-PLAN",
      "tasks": [
        {
          "id": "T1",
          "wave": "W1",
          "depends_on": [],
          "domain_risk": "security_critical",
          "assigned_read_paths": ["src/lib.rs"],
          "allowed_write_paths": ["src/**"],
          "assigned_tests": ["t1_unit"]
        }
      ]
    }"#;
    let plan = parse_and_validate_dag_json(dag).unwrap();
    save_locked_plan(&repo, &plan, false).unwrap();
    fs::create_dir_all(repo.join("src")).unwrap();
    fs::create_dir_all(repo.join("docs")).unwrap();
    fs::write(repo.join("src/lib.rs"), "pub fn v() -> u32 { 1 }\n").unwrap();
    fs::write(
        repo.join("docs/secret_design.md"),
        "Confidential architecture\n",
    )
    .unwrap();

    let cap = mint_session_capability(&repo, SwarmRole::Grunt, "T1", 1).unwrap();
    let docs_read_in = JsonValue::parse(r#"{"file_path":"docs/secret_design.md"}"#).unwrap();
    let docs_dec = enforce_role_pre_tool(
        SwarmRole::Grunt,
        Some(&cap),
        "Read",
        &docs_read_in,
        &repo,
        &repo,
    )
    .expect("unassigned docs/ read must be denied for Grunt");
    assert!(!docs_dec.is_allow());

    // 4. Scoped Git-blob tree OID walks >12 directory levels while skipping forbidden `.env*` & `.cache`
    let deep_dir = repo.join("src/d1/d2/d3/d4/d5/d6/d7/d8/d9/d10/d11/d12/d13/d14");
    fs::create_dir_all(&deep_dir).unwrap();
    fs::write(deep_dir.join("leaf.rs"), "pub const LEAF: u8 = 1;\n").unwrap();
    let oid_v1 = compute_scoped_tree_oid(&repo, &["src/**".to_string()]).unwrap();
    fs::write(deep_dir.join("leaf.rs"), "pub const LEAF: u8 = 2;\n").unwrap();
    let oid_v2 = compute_scoped_tree_oid(&repo, &["src/**".to_string()]).unwrap();
    assert_ne!(
        oid_v1, oid_v2,
        "tree OID must detect mutations deeper than 12 directory levels"
    );

    // Forbidden `.env.local` and `.cache/` inside `src/` must never affect `compute_scoped_tree_oid`
    fs::write(repo.join("src/.env.local"), "SECRET_KEY=hunter2\n").unwrap();
    fs::create_dir_all(repo.join("src/.cache")).unwrap();
    fs::write(repo.join("src/.cache/blob.rs"), "pub fn ignored() {}\n").unwrap();
    let oid_with_forbidden = compute_scoped_tree_oid(&repo, &["src/**".to_string()]).unwrap();
    assert_eq!(
        oid_v2, oid_with_forbidden,
        "forbidden .env* and .cache files must be ignored by compute_scoped_tree_oid"
    );
    fs::remove_file(repo.join("src/.env.local")).unwrap();
    fs::remove_dir_all(repo.join("src/.cache")).unwrap();

    // 5. Breadcrumb verifier rejects duplicate/replayed seq_no and standalone seq_no gaps
    let b1 = append_breadcrumb_for_path(
        &repo,
        &cap.session_id,
        "T1",
        [0x33; 32],
        EventOp::FileEdit,
        "src/lib.rs",
        Some((1, 1)),
        sha256_digest(b"pub fn v() -> u32 { 1 }\n"),
    )
    .unwrap();
    fs::write(repo.join("src/lib.rs"), "pub fn v() -> u32 { 2 }\n").unwrap();
    let b2 = append_breadcrumb_for_path(
        &repo,
        &cap.session_id,
        "T1",
        [0x33; 32],
        EventOp::FileEdit,
        "src/lib.rs",
        Some((1, 1)),
        sha256_digest(b"pub fn v() -> u32 { 2 }\n"),
    )
    .unwrap();
    let dup_trail = repo.join("src/dup.breadcrumbs.jsonl");
    fs::write(
        &dup_trail,
        format!("{}\n{}\n", b1.to_json_line(), b1.to_json_line()),
    )
    .unwrap();
    assert!(
        verify_breadcrumbs_file(&repo, &dup_trail).is_err(),
        "duplicate seq_no replay must fail verification"
    );
    let skipped_first_trail = repo.join("src/skipped.breadcrumbs.jsonl");
    fs::write(&skipped_first_trail, format!("{}\n", b2.to_json_line())).unwrap();
    assert!(
        verify_breadcrumbs_file(&repo, &skipped_first_trail).is_err(),
        "omitting seq_no=1 for same-directory trail must fail verification"
    );
    fs::remove_file(&dup_trail).unwrap();
    fs::remove_file(&skipped_first_trail).unwrap();

    // 6. WorkLedgerEntry pins non-empty authenticated `event_ids` and tampering invalidates HMAC
    record_test_checkpoint(&repo, &cap.session_id, true).unwrap();
    let entry = submit_work_ledger_entry(
        &repo,
        &cap.session_id,
        "Updated deep leaf constant and verified src/lib.rs. Recorded signed edit breadcrumbs.",
        "Task T1 required deterministic deep-tree hashing. Verified green checkpoint before submission.",
    )
    .unwrap();
    assert!(
        entry.event_ids.len() >= 3,
        "ledger entry must pin edit + green-checkpoint event_ids"
    );
    assert!(entry.event_ids.contains(&b1.event_id_hex()));

    // Verify ledger file stores `event_ids` JSON array
    let ledger_raw = fs::read_to_string(work_ledger_state_path(&repo).unwrap()).unwrap();
    assert!(ledger_raw.contains("\"event_ids\":["));
}

#[test]
fn pr2_deep_adversarial_capability_slot_hmac_shell_and_patch_regressions() {
    let (repo, _) = isolated_sandbox("pr2_deep_adversarial");
    fs::create_dir_all(repo.join("src")).unwrap();
    fs::create_dir_all(repo.join("docs")).unwrap();
    fs::write(repo.join("src/allowed.rs"), "pub fn ok() -> u8 { 1 }\n").unwrap();
    fs::write(repo.join("src/forbidden.rs"), "pub fn nope() -> u8 { 2 }\n").unwrap();
    fs::write(repo.join("docs/internal.md"), "Internal design doc\n").unwrap();

    let dag = r#"{
      "plan_id": "PR2-DEEP-ADVERSARIAL",
      "tasks": [
        {
          "id": "TASK-DEEP",
          "wave": "W1",
          "depends_on": [],
          "domain_risk": "security_critical",
          "assigned_read_paths": ["src/allowed.rs"],
          "allowed_write_paths": ["src/allowed.rs"],
          "assigned_tests": []
        }
      ]
    }"#;
    let plan = parse_and_validate_dag_json(dag).unwrap();
    save_locked_plan(&repo, &plan, false).unwrap();

    // 1. Minting Grunt capability binds the repo-scoped active slot (`active_session.json`).
    //    Even when a harness passes a random UUID `session_id` without env vars, `handle_pre_tool_hook`
    //    enforces Grunt's exact read/write/Bash/apply_patch jail!
    let cap = mint_session_capability(&repo, SwarmRole::Grunt, "TASK-DEEP", 1).unwrap();

    let allowed_read = agent_guard::handle_pre_tool_hook(
        r#"{"session_id":"d94e6f18-4b0c-4a12-9f88-112233445566","tool_name":"Read","tool_input":{"file_path":"src/allowed.rs"}}"#,
        &repo,
    );
    assert!(
        allowed_read.is_allow(),
        "in-scope Read under active slot must succeed: {allowed_read:?}"
    );

    let out_of_scope_bash_read = agent_guard::handle_pre_tool_hook(
        r#"{"session_id":"d94e6f18-4b0c-4a12-9f88-112233445566","tool_name":"Bash","tool_input":{"command":"cat src/forbidden.rs"}}"#,
        &repo,
    );
    assert!(
        !out_of_scope_bash_read.is_allow(),
        "Grunt Bash `cat src/forbidden.rs` must be blocked by check_role_shell_read_scope"
    );

    let out_of_scope_patch = agent_guard::handle_pre_tool_hook(
        r#"{"session_id":"d94e6f18-4b0c-4a12-9f88-112233445566","tool_name":"apply_patch","tool_input":{"patch":"*** Begin Patch\n*** Update File: src/forbidden.rs\n@@\n-pub fn nope() -> u8 { 2 }\n+pub fn nope() -> u8 { 9 }\n*** End Patch\n"}}"#,
        &repo,
    );
    assert!(
        !out_of_scope_patch.is_allow(),
        "Grunt apply_patch on unassigned file must be blocked"
    );

    // 2. Worker `swarm-tool master` namespace escalation (even via `env -u ...`) is hard-blocked at PreToolUse
    let worker_escalate = enforce_role_pre_tool(
        SwarmRole::Grunt,
        Some(&cap),
        "Bash",
        &JsonValue::parse(
            r#"{"command":"env -u AGENT_GUARD_ROLE -u AGENT_GUARD_SESSION_ID swarm-tool master lock-plan evil.json"}"#,
        )
        .unwrap(),
        &repo,
        &repo,
    );
    assert!(
        worker_escalate.is_some_and(|d| !d.is_allow()),
        "Grunt invoking `swarm-tool master` must be denied at PreToolUse"
    );

    // 3. Master shell rejects command chaining, pipes, and substitutions (`git status && ...`)
    for chained_master_cmd in [
        r#"{"command":"git status && cat src/forbidden.rs"}"#,
        r#"{"command":"git log -n 5; python3 -c 'print(1)'"}"#,
        r#"{"command":"swarm-tool master status | sh"}"#,
        r#"{"command":"swarm-tool master ingest-packet \"$(cat src/forbidden.rs)\""}"#,
    ] {
        let dec = enforce_role_pre_tool(
            SwarmRole::Master,
            None,
            "Bash",
            &JsonValue::parse(chained_master_cmd).unwrap(),
            &repo,
            &repo,
        );
        assert!(
            dec.is_some_and(|d| !d.is_allow()),
            "chained/substituted Master command must be denied: {chained_master_cmd}"
        );
    }
    let clean_master_cmd = enforce_role_pre_tool(
        SwarmRole::Master,
        None,
        "Bash",
        &JsonValue::parse(r#"{"command":"git status --short"}"#).unwrap(),
        &repo,
        &repo,
    );
    assert!(
        clean_master_cmd.is_none(),
        "clean unchained `git status --short` must be permitted by Master role gate"
    );

    // 4. Zero-write roles block `apply_patch` too
    let inv_patch = enforce_role_pre_tool(
        SwarmRole::Investigator,
        None,
        "apply_patch",
        &JsonValue::parse(r#"{"patch":"*** Update File: src/allowed.rs\n"}"#).unwrap(),
        &repo,
        &repo,
    );
    assert!(inv_patch.is_some_and(|d| !d.is_allow()));

    // 5. Tampering with capability JSON on disk invalidates HMAC and fails closed
    let cap_path =
        agent_guard::role_sandbox::session_capability_path(&repo, &cap.session_id).unwrap();
    let tampered = fs::read_to_string(&cap_path)
        .unwrap()
        .replace("src/allowed.rs", "src/forbidden.rs");
    fs::write(&cap_path, tampered).unwrap();
    let load_err = agent_guard::role_sandbox::load_session_capability(&repo, &cap.session_id)
        .expect_err("tampered capability JSON must fail HMAC verification");
    assert!(load_err.contains("FORGED_SESSION_CAPABILITY"));
}

#[test]
fn pr6_round2_all_twelve_security_and_concurrency_regressions() {
    let (repo, _) = isolated_sandbox("pr6_round2_regressions");
    fs::create_dir_all(repo.join("src")).unwrap();
    fs::create_dir_all(repo.join("docs")).unwrap();
    fs::create_dir_all(repo.join("skills/swarm-master")).unwrap();
    fs::create_dir_all(repo.join("profiles")).unwrap();

    fs::write(repo.join("AGENTS.md"), "# Canonical Root AGENTS.md\n").unwrap();
    fs::write(repo.join("README.md"), "# Untrusted repo README\n").unwrap();
    fs::write(repo.join("spec.md"), "# Untrusted spec\n").unwrap();
    fs::write(repo.join("profiles/default.toml"), "profile_id = \"x\"\n").unwrap();
    fs::write(repo.join("docs/arch.md"), "Trusted Swarm docs\n").unwrap();
    fs::write(
        repo.join("skills/swarm-master/SKILL.md"),
        "Master skill instructions\n",
    )
    .unwrap();
    fs::write(repo.join("src/a.rs"), "pub fn a() -> u32 { 1 }\n").unwrap();
    fs::write(repo.join("src/b.rs"), "pub fn b() -> u32 { 2 }\n").unwrap();

    // 1. Finding #5: Master Read allowlist denies README.md, spec.md, and profiles/* while allowing AGENTS.md, docs/*, skills/*
    for denied_rel in ["README.md", "spec.md", "profiles/default.toml"] {
        let dec = enforce_role_pre_tool(
            SwarmRole::Master,
            None,
            "Read",
            &JsonValue::parse(&format!(r#"{{"file_path":"{denied_rel}"}}"#)).unwrap(),
            &repo,
            &repo,
        )
        .expect("Master Read on non-doc/skill path must return Deny");
        assert!(
            !dec.is_allow(),
            "Master must be denied reading {denied_rel}"
        );
    }
    for allowed_rel in ["AGENTS.md", "docs/arch.md", "skills/swarm-master/SKILL.md"] {
        let dec = enforce_role_pre_tool(
            SwarmRole::Master,
            None,
            "Read",
            &JsonValue::parse(&format!(r#"{{"file_path":"{allowed_rel}"}}"#)).unwrap(),
            &repo,
            &repo,
        );
        assert!(
            dec.is_none(),
            "Master must be allowed reading {allowed_rel}"
        );
    }

    // 2. Finding #2: PLAN.lock.json HMAC & plan_sha256 integrity
    let dag = r#"{
      "plan_id": "PR6-WAVE-CONCURRENT",
      "tasks": [
        {
          "id": "TASK-A",
          "wave": "W1",
          "depends_on": [],
          "domain_risk": "security_critical",
          "assigned_read_paths": ["src/a.rs"],
          "allowed_write_paths": ["src/a.rs"],
          "assigned_tests": []
        },
        {
          "id": "TASK-B",
          "wave": "W1",
          "depends_on": [],
          "domain_risk": "core_logic",
          "assigned_read_paths": ["src/b.rs"],
          "allowed_write_paths": ["src/b.rs"],
          "assigned_tests": []
        }
      ]
    }"#;
    let plan = parse_and_validate_dag_json(dag).unwrap();
    let plan_lock_path = save_locked_plan(&repo, &plan, false).unwrap();
    assert!(
        plan_lock_path.starts_with(swarm_state_dir(&repo).unwrap()),
        "PLAN.lock.json must live inside protected swarm_state_dir/ledger"
    );
    let orig_lock_raw = fs::read_to_string(&plan_lock_path).unwrap();
    let tampered_lock = orig_lock_raw.replace("src/a.rs", "src/b.rs");
    fs::write(&plan_lock_path, tampered_lock).unwrap();
    let lock_err = agent_guard::qa_suspects::load_locked_plan(&repo)
        .expect_err("mutated PLAN.lock.json must fail HMAC + SHA-256 verification");
    assert!(
        lock_err.contains("PLAN_LOCK_TAMPERED"),
        "expected PLAN_LOCK_TAMPERED, got: {lock_err}"
    );
    fs::write(&plan_lock_path, &orig_lock_raw).unwrap();
    assert!(agent_guard::qa_suspects::load_locked_plan(&repo).is_ok());

    // 3. Finding #3: Concurrent parallel-wave capabilities (Grunt A + Grunt B) without clobbering
    let cap_a = mint_session_capability(&repo, SwarmRole::Grunt, "TASK-A", 1).unwrap();
    let cap_b = mint_session_capability(&repo, SwarmRole::Grunt, "TASK-B", 1).unwrap();
    let open_caps = agent_guard::role_sandbox::load_open_session_capabilities(&repo).unwrap();
    assert_eq!(open_caps.len(), 2);

    // Unbound hook UUID fails closed when >=2 sessions are open concurrently
    let ambig_err = agent_guard::role_sandbox::resolve_active_role(&repo, "unbound-hook-uuid")
        .expect_err("env-less hook call with 2 open sessions must fail closed");
    assert!(
        ambig_err.contains("AMBIGUOUS_CONCURRENT_SWARM_SESSIONS"),
        "expected AMBIGUOUS_CONCURRENT_SWARM_SESSIONS, got: {ambig_err}"
    );
    // Explicit swm_* session IDs resolve deterministically to each isolated Grunt jail
    let (role_a, resolved_a) =
        agent_guard::role_sandbox::resolve_active_role(&repo, &cap_a.session_id).unwrap();
    assert_eq!(role_a, SwarmRole::Grunt);
    assert_eq!(resolved_a.unwrap().task_id, "TASK-A");

    // Closing Grunt A leaves Grunt B open and actively enforced even without env vars!
    agent_guard::role_sandbox::close_open_session(&repo, Some(&cap_a.session_id)).unwrap();
    let (role_b, resolved_b) =
        agent_guard::role_sandbox::resolve_active_role(&repo, "unbound-hook-uuid").unwrap();
    assert_eq!(role_b, SwarmRole::Grunt);
    assert_eq!(resolved_b.unwrap().session_id, cap_b.session_id);

    // 4. Finding #1: Multi-threaded concurrent spool appends maintain strict monotonic seq_no + hash chain
    let mut handles = Vec::new();
    for t_idx in 0..8u8 {
        let repo_clone = repo.clone();
        let sid_clone = cap_b.session_id.clone();
        handles.push(std::thread::spawn(move || {
            for iter in 0..10u8 {
                append_breadcrumb_for_path(
                    &repo_clone,
                    &sid_clone,
                    "TASK-B",
                    [0x42; 32],
                    EventOp::FileEdit,
                    "src/b.rs",
                    Some((1, 1)),
                    [t_idx.wrapping_mul(16).wrapping_add(iter); 32],
                )
                .expect("concurrent append_breadcrumb_for_path");
            }
        }));
    }
    for h in handles {
        h.join().expect("join thread");
    }
    let spool_report = recover_spool_frames(&spool_file_path(&repo, &cap_b.session_id).unwrap())
        .expect("recover concurrent spool");
    assert_eq!(spool_report.quarantined_tail_bytes, 0);
    // 1 SessionMint + 80 concurrent FileEdit events = 81 contiguous frames
    assert_eq!(spool_report.valid_records.len(), 81);
    for (idx, rec) in spool_report.valid_records.iter().enumerate() {
        assert_eq!(rec.event.seq_no, (idx as u64) + 1);
    }

    // 5. Findings #6 & #7: Stale FileEdit provenance rejected, valid FileEdit accepted, forged ledger line rejected on read
    // Right now the last concurrent FileEdit had synthetic doc_sha256 != on-disk src/b.rs -> must fail LEDGER_STALE_EDIT_PROVENANCE!
    record_test_checkpoint(&repo, &cap_b.session_id, true).unwrap();
    let stale_err = submit_work_ledger_entry(
        &repo,
        &cap_b.session_id,
        "Updated b function in src/b.rs. Verified concurrent spool integrity.",
        "Task B required deterministic concurrency verification. Green checkpoint recorded on workspace.",
    )
    .expect_err("mismatched FileEdit doc_sha256 must fail LEDGER_STALE_EDIT_PROVENANCE");
    assert!(
        stale_err.contains("LEDGER_STALE_EDIT_PROVENANCE"),
        "expected LEDGER_STALE_EDIT_PROVENANCE, got: {stale_err}"
    );

    // Record accurate FileEdit matching on-disk src/b.rs + checkpoint -> submit succeeds & load_work_ledger_entries authenticates!
    append_breadcrumb_for_path(
        &repo,
        &cap_b.session_id,
        "TASK-B",
        [0x42; 32],
        EventOp::FileEdit,
        "src/b.rs",
        Some((1, 1)),
        sha256_digest(b"pub fn b() -> u32 { 2 }\n"),
    )
    .unwrap();
    record_test_checkpoint(&repo, &cap_b.session_id, true).unwrap();
    submit_work_ledger_entry(
        &repo,
        &cap_b.session_id,
        "Updated b function in src/b.rs. Verified concurrent spool integrity.",
        "Task B required deterministic concurrency verification. Green checkpoint recorded on workspace.",
    )
    .unwrap();
    assert_eq!(
        agent_guard::work_ledger::load_work_ledger_entries(&repo)
            .unwrap()
            .len(),
        1
    );

    // Appending an unauthenticated JSON line to WORK_LEDGER.jsonl must fail load_work_ledger_entries!
    let ledger_file = work_ledger_state_path(&repo).unwrap();
    {
        let mut f = OpenOptions::new().append(true).open(&ledger_file).unwrap();
        writeln!(
            f,
            r#"{{"session_id":"{}","task_id":"TASK-B","attempt":1,"git_tree_oid":"deadbeef","event_ids":["00"],"what_changed":"Fake one. Fake two.","why_changed":"Why one. Why two.","smell_badges":[],"record_mac":"0000000000000000000000000000000000000000000000000000000000000000"}}"#,
            cap_b.session_id
        )
        .unwrap();
    }
    let forged_ledger_err = agent_guard::work_ledger::load_work_ledger_entries(&repo)
        .expect_err("forged WORK_LEDGER.jsonl entry must fail load_work_ledger_entries");
    assert!(
        forged_ledger_err.contains("FORGED_WORK_LEDGER_ENTRY"),
        "expected FORGED_WORK_LEDGER_ENTRY, got: {forged_ledger_err}"
    );

    // 6. Finding #4: npm exact-pin verification in package.json & package-lock.json
    fs::write(
        repo.join("package.json"),
        r#"{
  "name": "demo-app",
  "version": "5.3.0",
  "dependencies": {
    "lodash": "^4.17.21",
    "zod": "3.23.8"
  }
}"#,
    )
    .unwrap();
    let caret_err = lookup_pinned_package_doc(&repo, "npm", "lodash", "4.17.21", None)
        .expect_err("loose caret range in package.json without lockfile must be rejected");
    assert!(caret_err.contains("UNPINNED_DEPENDENCY"));
    let cross_ver_err = lookup_pinned_package_doc(&repo, "npm", "zod", "5.3.0", None)
        .expect_err("root package version 5.3.0 must not satisfy zod version check");
    assert!(cross_ver_err.contains("LOCKFILE_VERSION_MISMATCH"));
    assert!(lookup_pinned_package_doc(&repo, "npm", "zod", "3.23.8", None).is_ok());

    fs::write(
        repo.join("package-lock.json"),
        r#"{
  "name": "demo-app",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": { "version": "4.17.21" }
  }
}"#,
    )
    .unwrap();
    assert!(lookup_pinned_package_doc(&repo, "npm", "lodash", "4.17.21", None).is_ok());
    assert!(
        lookup_pinned_package_doc(&repo, "npm", "lodash", "4.17.20", None)
            .unwrap_err()
            .contains("LOCKFILE_VERSION_MISMATCH")
    );

    // 7. Finding #12: walk_scout_dir safely bounds oversized source files (>256 KiB / >2,000 lines)
    let mut huge_rs = String::from("pub fn early_scout_sig() -> usize { 1 }\n");
    for _ in 0..3_200 {
        huge_rs.push_str("// filler comment padding line to exceed two thousand lines and 256 KiB safely0123456789\n");
    }
    huge_rs.push_str("pub fn beyond_scout_cap_sig() -> usize { 2 }\n");
    fs::write(repo.join("src/huge_gen.rs"), huge_rs).unwrap();
    let scout_hits = scout_repo_signatures(&repo, "src", 4, Some("scout")).unwrap();
    assert!(
        scout_hits.iter().any(|h| h.contains("early_scout_sig")),
        "scout must capture signatures within bounded prefix"
    );
    assert!(
        !scout_hits
            .iter()
            .any(|h| h.contains("beyond_scout_cap_sig")),
        "scout must stop reading beyond 256 KiB / 2,000 lines"
    );
}
