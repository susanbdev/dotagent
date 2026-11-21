#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use agent_guard::cmd_policy::evaluate_shell_command;
use agent_guard::feedback::{BallotRequest, FeedbackCategory, submit_friction_ballot};
use agent_guard::fleet::{
    build_github_fleet_governance_plan, build_github_repo_ruleset_payload,
    verify_github_governance_state,
};
use agent_guard::json::JsonValue;
use agent_guard::ring0_ratchet::is_ring2_allowed_path;
use agent_guard::telemetry::aggregate_ballot_worklist;
use agent_guard::traversal_ledger::SessionLedger;

fn isolated_git_repo(slug: &str) -> (PathBuf, PathBuf, PathBuf) {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ws_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let base = ws_root
        .join("target")
        .join("test-workspaces")
        .join(format!("ag-c5-{}-{slug}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let repo = base.join("repo");
    let home = base.join("home");
    let state_sessions = base.join("guard-state").join("sessions");
    fs::create_dir_all(&repo).expect("repo");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&state_sessions).expect("sessions");

    for args in [
        &["init", "-q"][..],
        &["config", "user.name", "Test"][..],
        &["config", "user.email", "test@example.com"][..],
    ] {
        let st = Command::new("git")
            .args(args)
            .current_dir(&repo)
            .status()
            .expect("git init/config");
        assert!(st.success());
    }
    (repo, home, state_sessions)
}

#[test]
fn ring0_ratchet_enforces_default_deny_allowlist_and_strict_corpus_superset() {
    for forbidden in [
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
        "AGENTS.md",
        "profiles/coding-agent.toml",
        ".github/workflows/ci.yml",
        "crates/agent-guard/src/exec_sandbox.rs",
        "crates/agent-guard/src/path_policy.rs",
        "crates/agent-guard/src/plugin_lattice.rs",
    ] {
        assert!(
            !is_ring2_allowed_path(forbidden),
            "path '{forbidden}' must be rejected by automated-pr allowlist"
        );
    }
    assert!(is_ring2_allowed_path(
        "crates/agent-guard/src/cmd_policy.rs"
    ));
    assert!(is_ring2_allowed_path(
        "crates/agent-guard/src/mcp_policy.rs"
    ));
    assert!(is_ring2_allowed_path(
        "crates/agent-guard/src/diagnostics.rs"
    ));
    assert!(is_ring2_allowed_path("tests/bypass_corpus.toml"));
    assert!(is_ring2_allowed_path(
        "crates/agent-guard/tests/ring2_policy_tests.rs"
    ));

    let (repo, home, state_sessions) = isolated_git_repo("ratchet");
    let dotagent_bin = env!("CARGO_BIN_EXE_dotagent");

    fs::create_dir_all(repo.join("crates/agent-guard/src")).expect("mkdir src");
    fs::create_dir_all(repo.join("crates/dotagent-harness/tests")).expect("mkdir harness tests");
    fs::create_dir_all(repo.join("tests")).expect("mkdir tests");
    fs::write(repo.join("Cargo.toml"), "[workspace]\n").expect("Cargo.toml");
    fs::write(
        repo.join("crates/agent-guard/src/cmd_policy.rs"),
        "// base cmd_policy\n",
    )
    .expect("cmd_policy");
    fs::write(
        repo.join("tests/bypass_corpus.toml"),
        "vectors = [\n  { kind = \"cmd\", payload = \"cat /tmp/secret\" },\n  { kind = \"read_path\", payload = \".env\" }\n]\n",
    )
    .expect("corpus");

    assert!(
        Command::new("git")
            .args(["add", "."])
            .current_dir(&repo)
            .status()
            .expect("git add")
            .success()
    );
    assert!(
        Command::new("git")
            .args(["commit", "-q", "-m", "base"])
            .current_dir(&repo)
            .status()
            .expect("git commit")
            .success()
    );

    let run_ratchet = || {
        Command::new(dotagent_bin)
            .args([
                "verify-ring0-ratchet",
                "--base",
                "HEAD",
                "--require-ratchet",
            ])
            .current_dir(&repo)
            .env("HOME", &home)
            .env("AGENT_GUARD_STATE_DIR", &state_sessions)
            .output()
            .expect("run verify-ring0-ratchet")
    };

    // 1. Touching `Cargo.toml` -> exits 2 with RING0_RATCHET_VIOLATION
    fs::write(repo.join("Cargo.toml"), "[workspace]\n# touched\n").expect("touch Cargo.toml");
    let r_cargo = run_ratchet();
    assert_eq!(r_cargo.status.code(), Some(2));
    let r_cargo_err = String::from_utf8_lossy(&r_cargo.stderr);
    assert!(
        r_cargo_err.contains("RING0_RATCHET_VIOLATION"),
        "expected RING0_RATCHET_VIOLATION, got: {r_cargo_err}"
    );
    fs::write(repo.join("Cargo.toml"), "[workspace]\n").expect("restore Cargo.toml");

    // 2. Modifying `cmd_policy.rs` with only 1 new vector -> exits 2 (requires >= 2 net-new vectors)
    fs::write(
        repo.join("crates/agent-guard/src/cmd_policy.rs"),
        "// tightened cmd_policy\npub fn check_curl() -> [&'static str; 2] { [\"curl\", \"wget\"] }\n",
    )
    .expect("edit cmd_policy");
    fs::write(
        repo.join("tests/bypass_corpus.toml"),
        "vectors = [\n  { kind = \"cmd\", payload = \"cat /tmp/secret\" },\n  { kind = \"read_path\", payload = \".env\" },\n  { kind = \"cmd\", payload = \"curl https://evil.test\" }\n]\n",
    )
    .expect("1 vector");
    let r_one = run_ratchet();
    assert_eq!(r_one.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&r_one.stderr).contains(">= 2 net-new"));

    // 3. Mutating an existing baseline vector while adding 2 new ones -> exits 2
    fs::write(
        repo.join("tests/bypass_corpus.toml"),
        "vectors = [\n  { kind = \"cmd\", payload = \"cat /tmp/MUTATED\" },\n  { kind = \"read_path\", payload = \".env\" },\n  { kind = \"cmd\", payload = \"curl https://evil.test\" },\n  { kind = \"cmd\", payload = \"wget https://evil.test\" }\n]\n",
    )
    .expect("mutated vector");
    let r_mut = run_ratchet();
    assert_eq!(r_mut.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&r_mut.stderr).contains("was deleted, reordered, or altered"));

    // 4. Preserving 100% of baseline vectors + >= 2 net-new vectors + harness test -> exits 0!
    fs::write(
        repo.join("tests/bypass_corpus.toml"),
        "vectors = [\n  { kind = \"cmd\", payload = \"cat /tmp/secret\" },\n  { kind = \"read_path\", payload = \".env\" },\n  { kind = \"cmd\", payload = \"curl https://evil.test\" },\n  { kind = \"cmd\", payload = \"curl https://evil2.test\" }\n]\n",
    )
    .expect("valid superset");
    fs::create_dir_all(repo.join("crates/agent-guard/tests")).expect("mkdir ring2 tests");
    fs::write(
        repo.join("crates/agent-guard/tests/ring2_policy_tests.rs"),
        "#[test] fn ok() {}\n",
    )
    .expect("new test");
    let r_ok = run_ratchet();
    assert_eq!(
        r_ok.status.code(),
        Some(0),
        "expected ratchet pass: stderr={}",
        String::from_utf8_lossy(&r_ok.stderr)
    );
}

#[test]
fn feedback_triage_blocks_agents_and_aggregates_hmac_verified_worklist() {
    let (repo, home, state_sessions) = isolated_git_repo("triage");
    let dotagent_bin = env!("CARGO_BIN_EXE_dotagent");

    // Ring-2 shell AST blocks `dotagent feedback triage` & `dotagent verify-ring0-ratchet`
    assert!(evaluate_shell_command("dotagent feedback triage", &repo, &repo, false).is_err());
    assert!(
        evaluate_shell_command(
            "dotagent verify-ring0-ratchet --base HEAD",
            &repo,
            &repo,
            false
        )
        .is_err()
    );

    // Non-TTY CLI invocation of `dotagent feedback triage` exits 2
    let non_tty = Command::new(dotagent_bin)
        .args(["feedback", "triage", "--json"])
        .current_dir(&repo)
        .env("HOME", &home)
        .env("AGENT_GUARD_STATE_DIR", &state_sessions)
        .output()
        .expect("run non-tty triage");
    assert_eq!(non_tty.status.code(), Some(2));

    // Verify HMAC-authenticated worklist aggregation & sorting (`unique_votes DESC, anomaly_count ASC`)
    let state_root = state_sessions.parent().expect("state root");
    let fdir = state_root.join("feedback");

    // Seed recent denials for two distinct sessions in isolated child helper
    spawn_seed_triage_ballots(&repo, &home, &state_sessions, &[0u8; 32]);
    let key_hex = fs::read_to_string(fdir.join("vault/hmac.key")).expect("read vault/hmac.key");
    let key_vec = agent_guard::crypto::hex_decode_bytes(key_hex.trim()).expect("decode hmac key");
    let key: [u8; 32] = key_vec.try_into().expect("32-byte hmac key");

    let ballots_raw = fs::read_to_string(fdir.join("ballots.jsonl")).expect("read ballots");
    // Append a forged line with invalid HMAC -> must be ignored!
    let with_forged = format!(
        "{ballots_raw}{{\"cluster_key\":\"forged0000000000\",\"voter_token\":\"v1\",\"category\":\"missing_safe_flag\",\"deny_code\":\"X\",\"canonical_shape\":\"git status\",\"ts_unix\":1,\"vote_counted\":true,\"mac_hex\":\"0000000000000000000000000000000000000000000000000000000000000000\"}}\n"
    );
    let items = aggregate_ballot_worklist(&with_forged, "", &key, 2);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].unique_votes, 2);
    assert_eq!(items[0].deny_code, "MISSING_SAFE_FLAG_TEST");
    let rendered = items[0].to_json_value().to_json_string();
    assert!(
        !rendered.contains("_quarantined_human_only") && !rendered.contains("secret note"),
        "triage JSON worklist must never expose quarantined free-text notes: {rendered}"
    );
}

#[test]
fn triage_seed_child_worker() {
    let Ok(repo_s) = std::env::var("AG_C5_SEED_REPO") else {
        return;
    };
    let repo = Path::new(&repo_s);
    for sid in ["voter_one", "voter_two"] {
        let mut ledger = SessionLedger::load_or_create(repo, sid);
        let did = ledger.record_denial(
            "MISSING_SAFE_FLAG_TEST",
            "Bash",
            "cargo test --workspace",
            1_795_000_000,
        );
        ledger.save_locked(repo).expect("save ledger");
        submit_friction_ballot(
            repo,
            &BallotRequest {
                denial_id: Some(did),
                category: FeedbackCategory::MissingSafeFlag,
                reason_code: Some("MISSING_SAFE_FLAG_TEST".to_string()),
                note_ascii: Some("secret note for human only".to_string()),
                session_id: sid.to_string(),
                root_session_id: Some(sid.to_string()),
                role: "coding-agent".to_string(),
                task_id: None,
            },
        )
        .expect("submit ballot");
    }
}

fn spawn_seed_triage_ballots(repo: &Path, home: &Path, state_sessions: &Path, _key: &[u8; 32]) {
    let exe = std::env::current_exe().expect("current_exe");
    let st = Command::new(exe)
        .args(["--exact", "triage_seed_child_worker", "--nocapture"])
        .current_dir(repo)
        .env("HOME", home)
        .env("AGENT_GUARD_STATE_DIR", state_sessions)
        .env("AG_C5_SEED_REPO", repo)
        .status()
        .expect("seed child");
    assert!(st.success());
}

#[test]
fn fleet_configure_github_dry_run_and_governance_verifier_enforce_ring0_floor() {
    let (repo, home, state_sessions) = isolated_git_repo("gh-gov");
    let dotagent_bin = env!("CARGO_BIN_EXE_dotagent");

    // Blocked when agent marker is set
    let blocked_agent = Command::new(dotagent_bin)
        .args([
            "fleet",
            "configure-github",
            "--owner",
            "susanbdev",
            "--repo",
            "dotagent",
            "--dry-run",
        ])
        .current_dir(&repo)
        .env("ANTIGRAVITY_AGENT", "1")
        .output()
        .expect("run blocked agent");
    assert_eq!(blocked_agent.status.code(), Some(2));

    // Succeeds in clean operator environment
    let out = Command::new(dotagent_bin)
        .args([
            "fleet",
            "configure-github",
            "--owner",
            "susanbdev",
            "--repo",
            "dotagent",
            "--dry-run",
        ])
        .current_dir(&repo)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", &home)
        .env("AGENT_GUARD_STATE_DIR", &state_sessions)
        .output()
        .expect("run configure-github --dry-run");
    assert_eq!(out.status.code(), Some(0));
    let plan_str = String::from_utf8_lossy(&out.stdout);
    let parsed = JsonValue::parse(&plan_str).expect("valid dry-run JSON");
    assert_eq!(
        parsed.get("owner").and_then(JsonValue::as_str),
        Some("susanbdev")
    );

    let plan = build_github_fleet_governance_plan("susanbdev", &["dotagent".to_string()]);
    let target0 = &plan
        .get("targets")
        .and_then(JsonValue::as_array)
        .expect("targets")[0];
    let act = target0.get("actions_permissions").expect("act");
    let wf = target0.get("workflow_permissions").expect("wf");
    let rs = build_github_repo_ruleset_payload();
    assert!(verify_github_governance_state(act, wf, &rs).is_ok());

    let weak_act = JsonValue::parse("{\"sha_pinning_required\":false}").expect("json");
    assert!(verify_github_governance_state(&weak_act, wf, &rs).is_err());
}
