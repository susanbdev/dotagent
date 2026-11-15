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

    // Re-checkpoint green -> submit succeeds with 0 risky drift badges!
    record_test_checkpoint(&repo, &cap.session_id, true).unwrap();
    let entry = submit_work_ledger_entry(
        &repo,
        &cap.session_id,
        "Implemented checked addition in src/lib.rs. Added overflow guard for negative bounds.",
        "Locked task T1 required deterministic arithmetic. Upfront QA suite verifies boundary cases.",
    )
    .expect("ledger submit succeeds after re-checkpoint");
    assert!(entry.smell_badges.is_empty());
}

#[test]
fn all_six_role_skills_readmes_and_compiled_agents_verified() {
    let root = workspace_root();
    for role in SwarmRole::all_swarm_roles() {
        let skill_dir = role.skill_dir_name().expect("swarm role skill dir");
        let skill_md = root.join("skills").join(skill_dir).join("SKILL.md");
        let readme_md = root.join("skills").join(skill_dir).join("README.md");
        let profile_toml = root.join("profiles").join(format!("{skill_dir}.toml"));

        assert!(skill_md.exists(), "missing {}", skill_md.display());
        assert!(readme_md.exists(), "missing {}", readme_md.display());
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

        let readme_text = fs::read_to_string(&readme_md).unwrap();
        assert!(readme_text.contains("## 1. What Your Job Is"));
        assert!(readme_text.contains("## 2. Explicit Rules You Must Follow"));
        assert!(readme_text.contains("## 3. Your Dedicated Rust Tooling"));
        assert!(readme_text.contains("swarm-tool "));
    }
}

#[test]
fn pr2_review_regressions_role_sandbox_spool_and_ledger_pins() {
    let (repo, _) = isolated_sandbox("pr2_review_regressions");

    // 1. QA writable path policy blocks `src/test_*.rs` production writes while allowing pytest `test_*.py`
    assert!(!is_qa_writable_path("src/test_backdoor.rs"));
    assert!(!is_qa_writable_path(
        "crates/agent-guard/src/test_helper.rs"
    ));
    assert!(is_qa_writable_path("src/calc_test.rs"));
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
