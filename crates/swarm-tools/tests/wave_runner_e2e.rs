#![forbid(unsafe_code)]

//! Live End-to-End Integration Tests for Pillar 1 (`dotagent-orchestrator` / `swarm-tools` v2.0):
//! - Parallel multi-worktree wave execution (`git worktree add --detach` + private `CARGO_TARGET_DIR`)
//! - Concurrent `(plan_id, task_id, attempt)` capability slots
//! - `recommended_model_tier` worker command routing (`frontier` vs `local_7b_or_mid`)
//! - 2-round adversarial retry recovery (`attempt 1` rejected -> `attempt 2` clean-slate approved)
//! - Kernel or supervisor rejection of out-of-scope writes
//! - Auto-computed & verified `doc_sha256` on `investigator emit-fact`

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use swarm_tools::{
    WaveSupervisorConfig, compute_and_verify_fact_doc_digests, run_swarm_dag_supervisor,
    verify_ingested_packet_doc_digests,
};

fn create_isolated_git_repo(slug: &str) -> PathBuf {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("target")
        .join("test-workspaces")
        .join(format!("swarm_v3_{slug}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(base.join("src")).expect("mkdir src");
    fs::write(base.join("AGENTS.md"), "# AGENTS.md\n").expect("write AGENTS.md");
    fs::write(base.join("src/base.rs"), "pub const BASE: u32 = 1;\n").expect("write base.rs");

    let git = |args: &[&str]| {
        let st = Command::new("git")
            .current_dir(&base)
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@dotagent.local")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@dotagent.local")
            .args(args)
            .status()
            .expect("git command");
        assert!(st.success(), "git {args:?} failed");
    };
    git(&["init", "-q"]);
    git(&["add", "."]);
    git(&["commit", "-qm", "init"]);
    base
}

fn ensure_agent_guard_built(workspace_root: &Path) {
    static BUILT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    BUILT.get_or_init(|| {
        let mut ag = PathBuf::from(env!("CARGO_BIN_EXE_swarm-tool"));
        ag.set_file_name(if cfg!(windows) {
            "agent-guard.exe"
        } else {
            "agent-guard"
        });
        if !ag.is_file() {
            let st = Command::new("cargo")
                .current_dir(workspace_root)
                .args([
                    "build",
                    "--locked",
                    "-p",
                    "agent-guard",
                    "--bin",
                    "agent-guard",
                ])
                .status()
                .expect("build agent-guard for sandboxed swarm e2e");
            assert!(st.success(), "cargo build -p agent-guard failed");
        }
    });
}

fn kernel_denied_path(error: &str, path: &str) -> bool {
    error.lines().any(|line| {
        line.contains(path)
            && (line.contains("Permission denied") || line.contains("Operation not permitted"))
    })
}

#[test]
fn parallel_multi_worktree_wave_reconciles_disjoint_writes_and_retries_round_1_reject() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    ensure_agent_guard_built(workspace_root);

    let repo = create_isolated_git_repo("parallel_reconcile");
    // Seed an untracked secret file in base repo; it MUST NEVER leak into ephemeral worktrees!
    fs::write(repo.join("canary_secret.pem"), "PRIVATE KEY MATERIAL\n").expect("write canary pem");

    let dag_json = r#"{
  "schema": "dotagent.plan_dag.v2.0",
  "plan_id": "E2E-PARALLEL-WAVE",
  "isolation_policy": {
    "per_task_git_worktree": true,
    "private_cargo_target_dir": true,
    "enforce_observed_writes_subset": true
  },
  "waves": [
    { "wave_id": "W0", "parallel": false, "nodes": ["W0.SETUP"] },
    { "wave_id": "W1", "parallel": true, "nodes": ["W1.LEFT", "W1.RIGHT"] }
  ],
  "tasks": [
    {
      "id": "W0.SETUP",
      "wave": "W0",
      "depends_on": [],
      "allowed_write_paths": ["src/setup.rs"],
      "assigned_read_paths": ["src/base.rs"],
      "recommended_model_tier": "frontier"
    },
    {
      "id": "W1.LEFT",
      "wave": "W1",
      "depends_on": ["W0.SETUP"],
      "allowed_write_paths": ["src/left.rs"],
      "assigned_read_paths": ["src/base.rs"],
      "recommended_model_tier": "local_7b_or_mid"
    },
    {
      "id": "W1.RIGHT",
      "wave": "W1",
      "depends_on": ["W0.SETUP"],
      "allowed_write_paths": ["src/right.rs"],
      "assigned_read_paths": ["src/base.rs"],
      "recommended_model_tier": "frontier"
    }
  ]
}"#;

    // Frontier worker writes setup.rs or right.rs (asserting Wave 0 setup.rs propagated into Wave 1 worktree
    // AND untracked canary_secret.pem was NOT snapshotted into the worktree!);
    // Mid worker writes left.rs (asserting CARGO_TARGET_DIR was preserved inside exec-sandbox!);
    // QA runs `git status --porcelain` inside the linked worktree under Landlock/Seatbelt!
    // Reviewer rejects attempt 1 of W1.LEFT and approves attempt 2!
    let st_bin = env!("CARGO_BIN_EXE_swarm-tool");
    let cfg = WaveSupervisorConfig {
        worker_cmd: None,
        frontier_cmd: Some(
            r#"test ! -e canary_secret.pem && if [ "$DOTAGENT_TASK_ID" = "W0.SETUP" ]; then printf 'pub const S: u32 = 1;\n' > src/setup.rs; else test -f src/setup.rs && printf 'pub const R: &str = "%s";\n' "$DOTAGENT_MODEL_TIER" > src/right.rs; fi"#
                .to_string(),
        ),
        mid_cmd: Some(
            r#"test ! -e canary_secret.pem && test -f src/setup.rs && test -n "$CARGO_TARGET_DIR" && printf 'pub const L_ATTEMPT: u32 = %s;\n' "$DOTAGENT_ATTEMPT" > src/left.rs"#
                .to_string(),
        ),
        test_cmd: Some(format!(
            r#"test "$AGENT_GUARD_ROLE" = "qa_engineer" && test -f AGENTS.md && git status --porcelain >/dev/null && '{st_bin}' qa coverage-targets --session "$AGENT_GUARD_SESSION_ID" >/dev/null"#
        )),
        reviewer_cmd: Some(
            r#"test "$AGENT_GUARD_ROLE" = "adversarial_reviewer" || exit 2; if [ "$DOTAGENT_TASK_ID" = "W1.LEFT" ] && [ "$DOTAGENT_ATTEMPT" = "1" ]; then exit 1; fi; exit 0"#
                .to_string(),
        ),
        llvm_cov_json: None,
        task_timeout_ms: 15_000,
        max_task_tokens: 4_000,
        dry_run: false,
        rotate_epoch: true,
        allow_amend: true,
    };

    if !agent_guard::exec_sandbox::probe_host_sandbox_mode().is_kernel_enforced() {
        let err = run_swarm_dag_supervisor(&repo, dag_json, &cfg).expect_err(
            "non-Landlock host kernel must fail closed with KERNEL_SANDBOX_UNAVAILABLE",
        );
        assert!(err.contains("KERNEL_SANDBOX_UNAVAILABLE"), "got: {err}");
        let mut dry_cfg = cfg.clone();
        dry_cfg.dry_run = true;
        let dry_report = run_swarm_dag_supervisor(&repo, dag_json, &dry_cfg)
            .expect("dry-run DAG planning and epoch rotation must succeed");
        assert_eq!(dry_report.waves_completed, 2);
        assert_eq!(dry_report.tasks_completed.len(), 3);
        assert!(dry_report.epoch_id.is_none());
        return;
    }

    let report = run_swarm_dag_supervisor(&repo, dag_json, &cfg).expect("DAG run must succeed");
    assert_eq!(report.waves_completed, 2);
    assert_eq!(report.tasks_completed.len(), 3);
    assert!(report.epoch_id.is_some());

    // Verify all disjoint worker writes were reconciled onto the base repository!
    let setup_body = fs::read_to_string(repo.join("src/setup.rs")).expect("setup.rs reconciled");
    let left_body = fs::read_to_string(repo.join("src/left.rs")).expect("left.rs reconciled");
    let right_body = fs::read_to_string(repo.join("src/right.rs")).expect("right.rs reconciled");
    assert_eq!(setup_body, "pub const S: u32 = 1;\n");
    assert_eq!(left_body, "pub const L_ATTEMPT: u32 = 2;\n");
    assert_eq!(right_body, "pub const R: &str = \"frontier\";\n");

    // Verify out-of-scope write in worktree is immediately hard-blocked!
    let bad_cfg = WaveSupervisorConfig {
        worker_cmd: Some("printf 'rogue' > src/unauthorized.rs".to_string()),
        allow_amend: true,
        ..WaveSupervisorConfig::default()
    };
    let err = run_swarm_dag_supervisor(&repo, dag_json, &bad_cfg)
        .expect_err("out-of-scope write must fail");
    assert!(
        err.contains("OBSERVED_WRITE_OUTSIDE_SCOPE")
            || kernel_denied_path(&err, "src/unauthorized.rs"),
        "got: {err}"
    );
    assert!(!repo.join("src/unauthorized.rs").exists());

    // Verify symlink creation inside allowed_write_paths is immediately hard-blocked!
    #[cfg(unix)]
    {
        let sym_cfg = WaveSupervisorConfig {
            worker_cmd: Some("rm -f src/setup.rs && ln -s ../AGENTS.md src/setup.rs".to_string()),
            allow_amend: true,
            ..WaveSupervisorConfig::default()
        };
        let sym_err = run_swarm_dag_supervisor(&repo, dag_json, &sym_cfg)
            .expect_err("symlink write must fail");
        assert!(
            sym_err.contains("OBSERVED_SYMLINK_FORBIDDEN")
                || sym_err.contains("OBSERVED_WRITE_FORBIDDEN_PATH")
                || kernel_denied_path(&sym_err, "src/setup.rs"),
            "got: {sym_err}"
        );
        assert!(
            fs::symlink_metadata(repo.join("src/setup.rs"))
                .expect("setup file remains")
                .is_file()
        );
        assert_eq!(
            fs::read_to_string(repo.join("src/setup.rs")).expect("setup content remains"),
            setup_body
        );
    }

    let _ = fs::remove_dir_all(&repo);
}

#[test]
fn emit_fact_auto_hashes_doc_sha256_and_detects_tamper_on_ingest() {
    let repo = create_isolated_git_repo("fact_doc_sha");
    let slices = vec!["src/base.rs:1-1".to_string()];
    let (primary_sha, map) =
        compute_and_verify_fact_doc_digests(&repo, &slices, None, None).expect("hash slice");
    let sha = primary_sha.expect("computed primary sha");
    assert_eq!(map.get("src/base.rs"), Some(&sha));

    let packet = format!(
        r#"{{"packet_type":"ObservedFact","session_id":"s1","task_id":"T1","claim":"BASE is 1","evidence_slices":["src/base.rs:1-1"],"doc_sha256":"{sha}","doc_sha256_map":{{"src/base.rs":"{sha}"}}}}"#
    );
    assert!(verify_ingested_packet_doc_digests(&repo, &packet).is_ok());

    // Modify file on disk -> ingest verification must catch stale/forged digest!
    fs::write(repo.join("src/base.rs"), "pub const BASE: u32 = 99;\n").expect("mutate");
    let err = verify_ingested_packet_doc_digests(&repo, &packet)
        .expect_err("must reject mismatched on-disk sha256");
    assert!(err.contains("PACKET_DOC_SHA256_MISMATCH"));

    let _ = fs::remove_dir_all(&repo);
}
