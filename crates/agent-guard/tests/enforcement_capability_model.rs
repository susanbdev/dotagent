#![forbid(unsafe_code)]

//! Deterministic production-path regression tests for the five-state runtime enforcement
//! capability model and Phase 4 observer-bound verification contract
//! (`crates/agent-guard/tests/enforcement_capability_model.rs`).
//!
//! Covers all 15 scenarios:
//!  1. Binary installed but integration unconfigured.
//!  2. Configuration valid but no invocations observed.
//!  3. Invocation recorded without host-enforcement proof.
//!  4. Caller-forged invocation and capability evidence.
//!  5. Stale evidence from another binary version / digest.
//!  6. Stale evidence from another workspace / config.
//!  7. Unsupported host execution mode (including Remote Agents VM).
//!  8. Missing kernel enforcement.
//!  9. Verified seccomp capability without Landlock.
//! 10. Malformed or incomplete capability records.
//! 11. Unsupported native tool categories.
//! 12. Existing Gemini and Antigravity contract compatibility.
//! 13. Activation and deactivation behavior.
//! 14. Observational telemetry failure isolation.
//! 15. Authoritative allow/deny correctness and full 5-step observer verification contract.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use agent_guard::enforcement_state::{
    ConfigState, ExecutionMode, HostEnforcement, InstallState, InvocationState, KernelEnforcement,
    ProbeSnapshot, evaluate_enforcement_report,
};
use agent_guard::exec_sandbox::KernelSandboxMode;
use agent_guard::json::JsonValue;
use agent_guard::operator::{execute_antigravity_activate, execute_antigravity_deactivate};

static MODEL_TEST_SEQ: AtomicU64 = AtomicU64::new(0);

struct CapabilitySandbox {
    base: PathBuf,
    repo_dir: PathBuf,
    bin_dir: PathBuf,
    state_dir: PathBuf,
}

impl CapabilitySandbox {
    fn create(slug: &str) -> Self {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = manifest_dir
            .parent()
            .and_then(Path::parent)
            .expect("workspace root");
        let seq = MODEL_TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let base = root
            .join("target")
            .join("test-workspaces")
            .join(format!("cap_model_{slug}_{pid}_{seq}"));
        let _ = fs::remove_dir_all(&base);
        let repo_dir = base.join("repo");
        let bin_dir = base.join("bin");
        let state_dir = base.join("state");
        fs::create_dir_all(repo_dir.join(".git")).expect("mkdir .git");
        fs::write(repo_dir.join(".git/config"), "[core]\n\tbare = false\n")
            .expect("write .git/config");
        fs::create_dir_all(&bin_dir).expect("mkdir bin");
        fs::create_dir_all(&state_dir).expect("mkdir state");
        fs::write(
            repo_dir.join("AGENTS.md"),
            "# AGENTS.md -- Root Authority\n",
        )
        .expect("write AGENTS.md");
        fs::create_dir_all(repo_dir.join("src")).expect("mkdir src");
        fs::write(
            repo_dir.join("src/lib.rs"),
            "pub fn check() -> bool {\n    true\n}\n",
        )
        .expect("write src/lib.rs");

        // Install a dedicated per-sandbox copy of the real compiled `agent-guard` binary
        let compiled_bin = PathBuf::from(env!("CARGO_BIN_EXE_agent-guard"));
        let dst_bin = bin_dir.join("agent-guard");
        fs::copy(&compiled_bin, &dst_bin).expect("copy agent-guard binary");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dst_bin, fs::Permissions::from_mode(0o555))
                .expect("chmod 0555 agent-guard");
        }

        Self {
            base,
            repo_dir,
            bin_dir,
            state_dir,
        }
    }

    fn ws_json(&self) -> String {
        JsonValue::Str(self.repo_dir.to_string_lossy().into_owned()).to_json_string()
    }

    fn dotagent_root(&self) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("dotagent root")
            .to_path_buf()
    }

    fn activate_antigravity(&self) -> Vec<String> {
        execute_antigravity_activate(&self.bin_dir, &self.dotagent_root(), &self.repo_dir, false)
            .expect("activate antigravity")
    }

    fn run_cli(
        &self,
        args: &[&str],
        stdin_bytes: &[u8],
        extra_env: &[(&str, &str)],
    ) -> (i32, String, String) {
        let mut cmd = Command::new(self.bin_dir.join("agent-guard"));
        cmd.current_dir(&self.repo_dir)
            .args(args)
            .env("AGENT_GUARD_STATE_DIR", &self.state_dir)
            .env_remove("AGENT_GUARD_IN_SANDBOX")
            .env_remove("AGENT_GUARD_WORKER_LOCK")
            .env_remove("AGENT_GUARD_HOT_COORD")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for &(k, v) in extra_env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("spawn agent-guard");
        if !stdin_bytes.is_empty()
            && let Some(mut sin) = child.stdin.take()
        {
            let _ = sin.write_all(stdin_bytes);
        }
        let out = child.wait_with_output().expect("wait agent-guard");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
}

impl Drop for CapabilitySandbox {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let _ = Command::new("chmod")
                .args(["-R", "u+w"])
                .arg(&self.base)
                .status();
        }
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn local_landlock_snapshot() -> ProbeSnapshot {
    ProbeSnapshot {
        execution_mode: ExecutionMode::LocalHost,
        kernel_fs_mode: KernelSandboxMode::LinuxLandlockEnforced,
        seccomp_net: Some(true),
        netns_unshare: true,
        binary_version_override: None,
    }
}

#[test]
fn test_01_binary_installed_but_integration_unconfigured() {
    let sb = CapabilitySandbox::create("t01_unconfigured");
    let snap = local_landlock_snapshot();
    let report =
        evaluate_enforcement_report(&sb.repo_dir, &sb.bin_dir, "antigravity", None, None, &snap);

    assert!(matches!(report.installed, InstallState::Verified { .. }));
    assert_eq!(
        report.configured,
        ConfigState::Unconfigured {
            adapter_id: "antigravity".to_string(),
            reason_code: "INTEGRATION_UNCONFIGURED",
        }
    );
    assert_eq!(
        report.invoked,
        InvocationState::NoneObserved {
            reason_code: "NO_INVOCATIONS_OBSERVED",
        }
    );
    assert!(matches!(
        report.host_enforced,
        HostEnforcement::Unverified {
            reason_code: "INTEGRATION_UNCONFIGURED",
            ..
        }
    ));
    assert!(!report.mandatory_protection_verified);
}

#[test]
fn test_02_configuration_valid_but_no_invocations_observed() {
    let sb = CapabilitySandbox::create("t02_configured_no_inv");
    sb.activate_antigravity();

    let (code, stdout, stderr) = sb.run_cli(
        &[
            "status",
            "--json",
            "--adapter",
            "antigravity",
            "--execution-mode",
            "local",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(code, 0, "status failed: {stderr}");
    let doc = JsonValue::parse(stdout.trim()).expect("status json");
    assert_eq!(
        doc.get("installed")
            .and_then(|v| v.get("state"))
            .and_then(JsonValue::as_str),
        Some("verified")
    );
    assert_eq!(
        doc.get("configured")
            .and_then(|v| v.get("state"))
            .and_then(JsonValue::as_str),
        Some("valid")
    );
    assert_eq!(
        doc.get("invoked")
            .and_then(|v| v.get("state"))
            .and_then(JsonValue::as_str),
        Some("none_observed")
    );
    assert_eq!(
        doc.get("host_enforced")
            .and_then(|v| v.get("state"))
            .and_then(JsonValue::as_str),
        Some("unverified")
    );
    assert_eq!(
        doc.get("host_enforced")
            .and_then(|v| v.get("reason_code"))
            .and_then(JsonValue::as_str),
        Some("HOST_ENFORCEMENT_UNVERIFIED")
    );
    assert_eq!(
        doc.get("mandatory_protection_verified")
            .and_then(JsonValue::as_bool),
        Some(false)
    );
}

#[test]
fn test_03_invocation_recorded_without_host_enforcement_proof() {
    let sb = CapabilitySandbox::create("t03_diag_only");
    sb.activate_antigravity();
    let trace_dir = sb.base.join("diag");
    fs::create_dir_all(&trace_dir).expect("mkdir diag");
    let trace_path = trace_dir.join("invocations.jsonl");

    // Direct production hook replay writes both SessionLedger and trace_log, and even triggers a
    // PendingChallenge denial witness -- NONE of these may certify `host_enforced = verified`!
    let obs_seed = [0x33u8; 32];
    let obs_pk = agent_guard::enforcement_state::derive_observer_pubkey_hex(&obs_seed);
    let (b_code, b_out, b_err) = sb.run_cli(
        &[
            "verify-enforcement",
            "begin",
            "--json",
            "--execution-mode",
            "local",
            "--observer-pubkey",
            &obs_pk,
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(b_code, 0, "begin failed: out={b_out} err={b_err}");
    let begin_json = JsonValue::parse(b_out.trim()).expect("begin json");
    let canary_rel = begin_json
        .get("canary_rel_path")
        .and_then(JsonValue::as_str)
        .expect("canary_rel_path");

    let payload = format!(
        r#"{{"conversationId":"conv_t03","workspacePaths":[{}],"toolCall":{{"name":"write_to_file","args":{{"TargetFile":"{}/{}","CodeContent":"CANARY\n","Overwrite":true}}}},"stepIdx":0}}"#,
        sb.ws_json(),
        sb.repo_dir.display(),
        canary_rel
    );
    let (h_code, h_out, _) = sb.run_cli(
        &[
            "antigravity-hook",
            "PreToolUse",
            "--workspace",
            &sb.repo_dir.to_string_lossy(),
            "--trace-log",
            &trace_path.to_string_lossy(),
        ],
        payload.as_bytes(),
        &[],
    );
    assert_eq!(h_code, 0);
    assert_eq!(
        JsonValue::parse(h_out.trim())
            .expect("hook json")
            .get("decision")
            .and_then(JsonValue::as_str),
        Some("deny")
    );

    // Status BEFORE observer completion MUST stay DiagnosticOnly + Unverified (`mandatory_protection_verified == false`)!
    let (s_code, s_out, _) = sb.run_cli(
        &[
            "status",
            "--json",
            "--require-host-enforced",
            "--execution-mode",
            "local",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            "--trace-log",
            &trace_path.to_string_lossy(),
            "--session",
            "conv_t03",
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(
        s_code, 2,
        "--require-host-enforced must fail closed when only invocation/witness exists: {s_out}"
    );
    let s_json = JsonValue::parse(s_out.trim()).expect("status json");
    assert_eq!(
        s_json
            .get("invoked")
            .and_then(|v| v.get("state"))
            .and_then(JsonValue::as_str),
        Some("diagnostic_only")
    );
    assert_eq!(
        s_json
            .get("invoked")
            .and_then(|v| v.get("trust_level"))
            .and_then(JsonValue::as_str),
        Some("self_reported_diagnostic")
    );
    assert_eq!(
        s_json
            .get("host_enforced")
            .and_then(|v| v.get("state"))
            .and_then(JsonValue::as_str),
        Some("unverified")
    );
    assert_eq!(
        s_json
            .get("host_enforced")
            .and_then(|v| v.get("reason_code"))
            .and_then(JsonValue::as_str),
        Some("INVOCATION_WITHOUT_ENFORCEMENT_PROOF")
    );
    assert_eq!(
        s_json
            .get("mandatory_protection_verified")
            .and_then(JsonValue::as_bool),
        Some(false)
    );
}

#[test]
fn test_04_caller_forged_invocation_and_capability_evidence_rejected() {
    let sb = CapabilitySandbox::create("t04_forged");
    sb.activate_antigravity();

    // 4a: Caller plants a forged trace file claiming 100 denials
    let forged_trace = sb.base.join("forged_trace.jsonl");
    fs::write(
        &forged_trace,
        "{\"schema\":\"dotagent.antigravity.invocation.v1\",\"ts_unix\":1900000000,\"invocation_id\":\"inv_forged0000000000\",\"adapter_entry\":true,\"event\":\"PreToolUse\",\"tool_name\":\"run_command\",\"guard_decision\":\"deny\",\"response_serialized\":true,\"exit_code\":0}\n",
    )
    .expect("write forged trace");

    let (c1, out1, _) = sb.run_cli(
        &[
            "status",
            "--json",
            "--execution-mode",
            "local",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            "--trace-log",
            &forged_trace.to_string_lossy(),
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(c1, 0);
    let j1 = JsonValue::parse(out1.trim()).expect("j1");
    assert_eq!(
        j1.get("invoked")
            .and_then(|v| v.get("state"))
            .and_then(JsonValue::as_str),
        Some("diagnostic_only")
    );
    assert_eq!(
        j1.get("mandatory_protection_verified")
            .and_then(JsonValue::as_bool),
        Some(false)
    );

    // 4b: Caller plants a forged capability verification receipt in state_dir/enforcement/
    let enf_dir = sb.state_dir.join("enforcement");
    fs::create_dir_all(&enf_dir).expect("mkdir enforcement");
    let canon_ws = fs::canonicalize(&sb.repo_dir).expect("canon ws");
    let ws_sha = agent_guard::crypto::sha256_hex(canon_ws.to_string_lossy().as_bytes());
    let slot = format!("{}_antigravity", &ws_sha[..24]);
    let forged_receipt = format!(
        r#"{{"schema":"dotagent.enforcement_receipt.v1","challenge_id":"ch_forged","verified_at_unix":1900000000,"adapter_id":"antigravity","execution_mode":"local-host","workspace_sha256":"{}","config_sha256":"{}","binary_version":"{}","binary_sha256":"{}","mac":"0000000000000000000000000000000000000000000000000000000000000000"}}"#,
        ws_sha,
        "a".repeat(64),
        env!("CARGO_PKG_VERSION"),
        "b".repeat(64)
    );
    fs::write(enf_dir.join(format!("receipt_{slot}.json")), forged_receipt)
        .expect("write forged receipt");

    let (c2, out2, _) = sb.run_cli(
        &[
            "status",
            "--json",
            "--require-host-enforced",
            "--execution-mode",
            "local",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(c2, 2, "forged receipt must be rejected");
    let j2 = JsonValue::parse(out2.trim()).expect("j2");
    assert_eq!(
        j2.get("host_enforced")
            .and_then(|v| v.get("reason_code"))
            .and_then(JsonValue::as_str),
        Some("FORGED_EVIDENCE_REJECTED")
    );
    assert_eq!(
        j2.get("mandatory_protection_verified")
            .and_then(JsonValue::as_bool),
        Some(false)
    );
}

fn establish_genuine_receipt_via_cli(sb: &CapabilitySandbox) {
    let obs_seed = [0x5Au8; 32];
    let obs_pk = agent_guard::enforcement_state::derive_observer_pubkey_hex(&obs_seed);
    let (b_code, b_out, b_err) = sb.run_cli(
        &[
            "verify-enforcement",
            "begin",
            "--json",
            "--execution-mode",
            "local",
            "--observer-pubkey",
            &obs_pk,
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(b_code, 0, "begin failed: {b_err}");
    let bj = JsonValue::parse(b_out.trim()).expect("begin json");
    let cid = bj
        .get("challenge_id")
        .and_then(JsonValue::as_str)
        .expect("cid");
    let canary_rel = bj
        .get("canary_rel_path")
        .and_then(JsonValue::as_str)
        .expect("canary");

    let payload = format!(
        r#"{{"conversationId":"conv_ver","workspacePaths":[{}],"toolCall":{{"name":"write_to_file","args":{{"TargetFile":"{}/{}","CodeContent":"BLOCKED\n","Overwrite":true}}}},"stepIdx":0}}"#,
        sb.ws_json(),
        sb.repo_dir.display(),
        canary_rel
    );
    let (h_code, _, _) = sb.run_cli(
        &[
            "antigravity-hook",
            "PreToolUse",
            "--workspace",
            &sb.repo_dir.to_string_lossy(),
        ],
        payload.as_bytes(),
        &[],
    );
    assert_eq!(h_code, 0);

    let obs_sig = agent_guard::enforcement_state::sign_observer_verdict(
        &obs_seed,
        cid,
        "antigravity",
        &sb.repo_dir,
        canary_rel,
        true,
    );
    let (c_code, _, c_err) = sb.run_cli(
        &[
            "verify-enforcement",
            "complete",
            "--json",
            "--execution-mode",
            "local",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            "--challenge",
            cid,
            "--host-prevented-execution",
            "true",
            "--observer-sig",
            &obs_sig,
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(c_code, 0, "complete failed: {c_err}");
}

#[test]
fn test_05_stale_evidence_from_another_binary_version_or_digest_rejected() {
    let sb = CapabilitySandbox::create("t05_stale_bin");
    sb.activate_antigravity();
    establish_genuine_receipt_via_cli(&sb);

    // 5a: Baseline verified
    let (ok_code, _, _) = sb.run_cli(
        &[
            "status",
            "--json",
            "--require-host-enforced",
            "--execution-mode",
            "local",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(ok_code, 0);

    // 5b: Simulated binary version upgrade invalidates receipt (`STALE_BINARY_EVIDENCE`)
    // Point `AGENT_GUARD_STATE_DIR` in-process via CLI by modifying binary digest in `sb.bin_dir/agent-guard`
    let bin_path = sb.bin_dir.join("agent-guard");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bin_path, fs::Permissions::from_mode(0o755)).expect("chmod 0755");
    }
    let mut bin_bytes = fs::read(&bin_path).expect("read bin");
    bin_bytes.push(0u8);
    fs::write(&bin_path, &bin_bytes).expect("append byte to simulate new binary digest");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bin_path, fs::Permissions::from_mode(0o555)).expect("chmod 0555");
    }

    // Run status using the untouched Cargo binary while pointing `--bin-dir` to the modified binary
    let cargo_bin = PathBuf::from(env!("CARGO_BIN_EXE_agent-guard"));
    let out = Command::new(cargo_bin)
        .current_dir(&sb.repo_dir)
        .args([
            "status",
            "--json",
            "--require-host-enforced",
            "--execution-mode",
            "local",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            &sb.repo_dir.to_string_lossy(),
        ])
        .env("AGENT_GUARD_STATE_DIR", &sb.state_dir)
        .output()
        .expect("run status after binary change");
    assert_eq!(out.status.code(), Some(2));
    let sj = JsonValue::parse(&String::from_utf8_lossy(&out.stdout)).expect("status json");
    assert_eq!(
        sj.get("host_enforced")
            .and_then(|v| v.get("reason_code"))
            .and_then(JsonValue::as_str),
        Some("STALE_BINARY_EVIDENCE")
    );
    assert_eq!(
        sj.get("mandatory_protection_verified")
            .and_then(JsonValue::as_bool),
        Some(false)
    );
}

#[test]
fn test_06_stale_evidence_from_another_workspace_or_config_rejected() {
    let sb = CapabilitySandbox::create("t06_stale_ws");
    sb.activate_antigravity();
    establish_genuine_receipt_via_cli(&sb);

    // Create a second workspace sharing the same state_dir and copy workspace 1's valid HMAC-signed receipt into workspace 2's slot
    let repo2 = sb.base.join("repo_other");
    fs::create_dir_all(repo2.join(".git")).expect("mkdir repo2 .git");
    fs::write(repo2.join("AGENTS.md"), "# AGENTS.md\n").expect("write repo2 AGENTS.md");
    execute_antigravity_activate(&sb.bin_dir, &sb.dotagent_root(), &repo2, false)
        .expect("activate repo2");

    let ws1_sha = agent_guard::crypto::sha256_hex(
        fs::canonicalize(&sb.repo_dir)
            .expect("canon1")
            .to_string_lossy()
            .as_bytes(),
    );
    let ws2_sha = agent_guard::crypto::sha256_hex(
        fs::canonicalize(&repo2)
            .expect("canon2")
            .to_string_lossy()
            .as_bytes(),
    );
    let enf_dir = sb.state_dir.join("enforcement");
    let rec1_bytes = fs::read(enf_dir.join(format!("receipt_{}_antigravity.json", &ws1_sha[..24])))
        .expect("read rec1");
    fs::write(
        enf_dir.join(format!("receipt_{}_antigravity.json", &ws2_sha[..24])),
        rec1_bytes,
    )
    .expect("copy rec1 into repo2 slot");

    let (c_ws, out_ws, _) = sb.run_cli(
        &[
            "status",
            "--json",
            "--require-host-enforced",
            "--execution-mode",
            "local",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            &repo2.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(c_ws, 2);
    let j_ws = JsonValue::parse(out_ws.trim()).expect("j_ws");
    assert_eq!(
        j_ws.get("host_enforced")
            .and_then(|v| v.get("reason_code"))
            .and_then(JsonValue::as_str),
        Some("STALE_WORKSPACE_EVIDENCE")
    );

    // Also modify hooks.json in repo1 (re-activating with a trace-log changes config_sha256) -> STALE_CONFIG_EVIDENCE!
    let trace_dir = sb.base.join("tr");
    fs::create_dir_all(&trace_dir).expect("mkdir tr");
    let (act_c, _, act_e) = sb.run_cli(
        &[
            "activate",
            "--antigravity",
            "--dotagent-root",
            &sb.dotagent_root().to_string_lossy(),
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            "--workspace",
            &sb.repo_dir.to_string_lossy(),
            "--trace-log",
            &trace_dir.join("t.jsonl").to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(act_c, 0, "re-activate failed: {act_e}");
    let (c_cfg, out_cfg, _) = sb.run_cli(
        &[
            "status",
            "--json",
            "--require-host-enforced",
            "--execution-mode",
            "local",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(c_cfg, 2);
    let j_cfg = JsonValue::parse(out_cfg.trim()).expect("j_cfg");
    assert_eq!(
        j_cfg
            .get("host_enforced")
            .and_then(|v| v.get("reason_code"))
            .and_then(JsonValue::as_str),
        Some("STALE_CONFIG_EVIDENCE")
    );
}

#[test]
fn test_07_unsupported_host_execution_mode_and_remote_agents_vm() {
    let sb = CapabilitySandbox::create("t07_remote_mode");
    sb.activate_antigravity();

    // 7a: Antigravity Remote Agents VM mode
    let (c_rem, out_rem, _) = sb.run_cli(
        &[
            "status",
            "--json",
            "--require-host-enforced",
            "--execution-mode",
            "remote-agents",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(c_rem, 2);
    let j_rem = JsonValue::parse(out_rem.trim()).expect("j_rem");
    assert_eq!(
        j_rem
            .get("configured")
            .and_then(|v| v.get("state"))
            .and_then(JsonValue::as_str),
        Some("valid")
    );
    assert_eq!(
        j_rem
            .get("host_enforced")
            .and_then(|v| v.get("state"))
            .and_then(JsonValue::as_str),
        Some("not_verified_for_execution_mode")
    );
    assert_eq!(
        j_rem
            .get("host_enforced")
            .and_then(|v| v.get("reason_code"))
            .and_then(JsonValue::as_str),
        Some("HOST_EXECUTION_MODE_UNVERIFIED")
    );
    assert_eq!(
        j_rem
            .get("mandatory_protection_verified")
            .and_then(JsonValue::as_bool),
        Some(false)
    );

    // 7b: `verify-enforcement begin` refuses unavailable host callback in Remote Agents mode without external observer
    let (vb_code, vb_out, _) = sb.run_cli(
        &[
            "verify-enforcement",
            "begin",
            "--json",
            "--execution-mode",
            "remote-agents",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(vb_code, 2);
    let vbj = JsonValue::parse(vb_out.trim()).expect("vbj");
    assert_eq!(
        vbj.get("code").and_then(JsonValue::as_str),
        Some("VERIFICATION_UNAVAILABLE")
    );

    // 7c: Explicit unsupported host mode
    let (c_unsup, out_unsup, _) = sb.run_cli(
        &[
            "status",
            "--json",
            "--execution-mode",
            "unsupported",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(c_unsup, 0);
    let j_unsup = JsonValue::parse(out_unsup.trim()).expect("j_unsup");
    assert_eq!(
        j_unsup
            .get("host_enforced")
            .and_then(|v| v.get("reason_code"))
            .and_then(JsonValue::as_str),
        Some("UNSUPPORTED_EXECUTION_MODE")
    );
}

#[test]
fn test_08_missing_kernel_enforcement() {
    let sb = CapabilitySandbox::create("t08_no_kernel");
    sb.activate_antigravity();
    let snap = ProbeSnapshot {
        execution_mode: ExecutionMode::LocalHost,
        kernel_fs_mode: KernelSandboxMode::FallbackEnvAndAstOnly,
        seccomp_net: Some(false),
        netns_unshare: false,
        binary_version_override: None,
    };
    let report =
        evaluate_enforcement_report(&sb.repo_dir, &sb.bin_dir, "antigravity", None, None, &snap);
    assert!(matches!(
        report.kernel_enforced,
        KernelEnforcement::Unavailable {
            reason_code: "KERNEL_SANDBOX_UNAVAILABLE",
            ..
        }
    ));
}

#[test]
fn test_09_verified_seccomp_capability_without_landlock() {
    let sb = CapabilitySandbox::create("t09_seccomp_no_landlock");
    sb.activate_antigravity();
    let snap = ProbeSnapshot {
        execution_mode: ExecutionMode::AntigravityRemoteAgentsVm,
        kernel_fs_mode: KernelSandboxMode::FallbackEnvAndAstOnly,
        seccomp_net: Some(true),
        netns_unshare: false,
        binary_version_override: None,
    };
    let report =
        evaluate_enforcement_report(&sb.repo_dir, &sb.bin_dir, "antigravity", None, None, &snap);
    #[cfg(target_os = "linux")]
    {
        use agent_guard::enforcement_state::{LandlockState, SeccompState};
        assert!(matches!(
            report.kernel_enforced,
            KernelEnforcement::Partial {
                landlock: LandlockState::Unavailable,
                seccomp: SeccompState::Verified,
                reason_code: "LANDLOCK_UNAVAILABLE_SECCOMP_VERIFIED",
                ..
            }
        ));
    }
    assert!(!report.mandatory_protection_verified);
}

#[test]
fn test_10_malformed_or_incomplete_capability_and_trace_records() {
    let sb = CapabilitySandbox::create("t10_malformed");
    sb.activate_antigravity();

    // 10a: Malformed trace log
    let bad_trace = sb.base.join("bad_trace.jsonl");
    fs::write(&bad_trace, "{truncated_json\n").expect("write bad_trace");
    let (c1, out1, _) = sb.run_cli(
        &[
            "status",
            "--json",
            "--execution-mode",
            "local",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            "--trace-log",
            &bad_trace.to_string_lossy(),
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(c1, 0);
    let j1 = JsonValue::parse(out1.trim()).expect("j1");
    assert_eq!(
        j1.get("invoked")
            .and_then(|v| v.get("reason_code"))
            .and_then(JsonValue::as_str),
        Some("MALFORMED_CAPABILITY_RECORD")
    );

    // 10b: Incomplete receipt missing `binary_sha256` with valid-looking key file present
    let enf_dir = sb.state_dir.join("enforcement");
    fs::create_dir_all(&enf_dir).expect("mkdir enf");
    let key_path = enf_dir.join("verify_host.key");
    fs::write(&key_path, [7u8; 32]).expect("write key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
    }
    let ws_sha = agent_guard::crypto::sha256_hex(
        fs::canonicalize(&sb.repo_dir)
            .expect("canon")
            .to_string_lossy()
            .as_bytes(),
    );
    fs::write(
        enf_dir.join(format!("receipt_{}_antigravity.json", &ws_sha[..24])),
        "{\"schema\":\"dotagent.enforcement_receipt.v1\",\"challenge_id\":\"ch_incomplete\"}",
    )
    .expect("write incomplete receipt");

    let (c2, out2, _) = sb.run_cli(
        &[
            "status",
            "--json",
            "--execution-mode",
            "local",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(c2, 0);
    let j2 = JsonValue::parse(out2.trim()).expect("j2");
    assert_eq!(
        j2.get("host_enforced")
            .and_then(|v| v.get("reason_code"))
            .and_then(JsonValue::as_str),
        Some("MALFORMED_CAPABILITY_RECORD")
    );
    assert_eq!(
        j2.get("mandatory_protection_verified")
            .and_then(JsonValue::as_bool),
        Some(false)
    );
}

#[test]
fn test_11_unsupported_native_tool_categories_denied_fail_closed() {
    let sb = CapabilitySandbox::create("t11_unsupported_tools");
    for tool in [
        "browser_subagent",
        "create_github_repository",
        "fork_github_repository",
        "detach_github_repository",
        "generate_image",
        "save_skill",
        "delete_skill",
    ] {
        let payload = format!(
            r#"{{"conversationId":"conv_t11","workspacePaths":[{}],"toolCall":{{"name":"{}","args":{{"name":"test"}}}},"stepIdx":0}}"#,
            sb.ws_json(),
            tool
        );
        let (code, stdout, _) = sb.run_cli(
            &[
                "antigravity-hook",
                "PreToolUse",
                "--workspace",
                &sb.repo_dir.to_string_lossy(),
            ],
            payload.as_bytes(),
            &[],
        );
        assert_eq!(code, 0, "Antigravity hook must exit 0 on deny for {tool}");
        let parsed = JsonValue::parse(stdout.trim()).expect("valid json");
        assert_eq!(
            parsed.get("decision").and_then(JsonValue::as_str),
            Some("deny"),
            "{tool} must be denied fail-closed"
        );
        assert!(
            parsed
                .get("reason")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .contains("UNRECOGNIZED_TOOL_BLOCKED"),
            "unexpected reason for {tool}: {stdout}"
        );
    }
}

#[test]
fn test_12_existing_gemini_and_antigravity_contract_compatibility() {
    let sb = CapabilitySandbox::create("t12_contracts");

    // Gemini wire contract preserved
    let gem_payload = format!(
        r#"{{"session_id":"gem_t12","hook_event_name":"BeforeTool","tool_name":"view_file","tool_input":{{"AbsolutePath":"{}/src/lib.rs","StartLine":1,"EndLine":5}}}}"#,
        sb.repo_dir.display()
    );
    let (g_code, g_out, _) = sb.run_cli(&["pre-tool"], gem_payload.as_bytes(), &[]);
    assert_eq!(g_code, 0);
    assert!(
        JsonValue::parse(g_out.trim())
            .expect("gem json")
            .get("hookSpecificOutput")
            .is_some()
    );

    // Antigravity wire contract preserved
    let ag_payload = format!(
        r#"{{"conversationId":"ag_t12","workspacePaths":[{}],"toolCall":{{"name":"view_file","args":{{"AbsolutePath":"{}/src/lib.rs","StartLine":1,"EndLine":5}}}},"stepIdx":0}}"#,
        sb.ws_json(),
        sb.repo_dir.display()
    );
    let (a_code, a_out, _) = sb.run_cli(
        &[
            "antigravity-hook",
            "PreToolUse",
            "--workspace",
            &sb.repo_dir.to_string_lossy(),
        ],
        ag_payload.as_bytes(),
        &[],
    );
    assert_eq!(a_code, 0);
    assert_eq!(a_out.trim(), "{\"decision\":\"allow\"}");

    // Placing Gemini schema inside `.agents/hooks.json` is flagged as CONFIG_PROTOCOL_INCOMPATIBLE
    fs::create_dir_all(sb.repo_dir.join(".agents")).expect("mkdir .agents");
    fs::write(
        sb.repo_dir.join(".agents/hooks.json"),
        "{\"hooks\":{\"BeforeTool\":[]}}\n",
    )
    .expect("write wrong schema");
    let snap = local_landlock_snapshot();
    let rep =
        evaluate_enforcement_report(&sb.repo_dir, &sb.bin_dir, "antigravity", None, None, &snap);
    assert!(matches!(
        rep.configured,
        ConfigState::Invalid {
            reason_code: "CONFIG_PROTOCOL_INCOMPATIBLE",
            ..
        }
    ));
}

#[test]
fn test_13_activation_and_deactivation_reversibility_and_honest_reporting() {
    let sb = CapabilitySandbox::create("t13_act_deact");
    let fake_home = sb.base.join("home");
    fs::create_dir_all(&fake_home).expect("mkdir home");
    fs::write(
        fake_home.join(".gitconfig"),
        "[user]\n\tname = PreserveMe\n",
    )
    .expect("write .gitconfig");

    let act_log = sb.activate_antigravity();
    let joined = act_log.join("\n");
    assert!(joined.contains("host_enforced=unverified"));
    assert!(!joined.contains("hooks active"));
    assert!(sb.repo_dir.join(".agents/hooks.json").is_file());

    execute_antigravity_deactivate(&sb.repo_dir, false).expect("deactivate");
    assert!(!sb.repo_dir.join(".agents").exists());
    assert_eq!(
        fs::read_to_string(fake_home.join(".gitconfig")).expect("read .gitconfig"),
        "[user]\n\tname = PreserveMe\n"
    );
}

#[test]
fn test_14_observational_telemetry_failure_never_alters_authoritative_decisions() {
    let sb = CapabilitySandbox::create("t14_telemetry_fail");
    // Obstruct `audit.jsonl` by planting a directory where the audit file would be written
    fs::create_dir_all(sb.state_dir.join("audit.jsonl")).expect("plant directory at audit.jsonl");
    let bad_trace = sb.base.join("missing_parent_dir/trace.jsonl");

    let allow_payload = format!(
        r#"{{"conversationId":"conv_t14","workspacePaths":[{}],"toolCall":{{"name":"view_file","args":{{"AbsolutePath":"{}/src/lib.rs","StartLine":1,"EndLine":5}}}},"stepIdx":0}}"#,
        sb.ws_json(),
        sb.repo_dir.display()
    );
    let (c_allow, out_allow, _) = sb.run_cli(
        &[
            "antigravity-hook",
            "PreToolUse",
            "--workspace",
            &sb.repo_dir.to_string_lossy(),
            "--trace-log",
            &bad_trace.to_string_lossy(),
        ],
        allow_payload.as_bytes(),
        &[("DOTAGENT_TELEMETRY", "0")],
    );
    assert_eq!(c_allow, 0);
    assert_eq!(out_allow.trim(), "{\"decision\":\"allow\"}");

    let deny_payload = format!(
        r#"{{"conversationId":"conv_t14","workspacePaths":[{}],"toolCall":{{"name":"view_file","args":{{"AbsolutePath":"{}/.env"}}}},"stepIdx":1}}"#,
        sb.ws_json(),
        sb.repo_dir.display()
    );
    let (c_deny, out_deny, _) = sb.run_cli(
        &[
            "antigravity-hook",
            "PreToolUse",
            "--workspace",
            &sb.repo_dir.to_string_lossy(),
            "--trace-log",
            &bad_trace.to_string_lossy(),
        ],
        deny_payload.as_bytes(),
        &[("DOTAGENT_TELEMETRY", "0")],
    );
    assert_eq!(c_deny, 0);
    assert_eq!(
        JsonValue::parse(out_deny.trim())
            .expect("deny json")
            .get("decision")
            .and_then(JsonValue::as_str),
        Some("deny")
    );
}

#[test]
fn test_15_authoritative_allow_deny_and_full_5_step_observer_verification_contract() {
    let sb = CapabilitySandbox::create("t15_full_contract");
    sb.activate_antigravity();

    let obs_seed = [0x77u8; 32];
    let obs_pk = agent_guard::enforcement_state::derive_observer_pubkey_hex(&obs_seed);

    // 15a: Begin challenge -> attempt `complete` before hook invocation -> fails `HOOK_NOT_INVOKED`
    let (_, b1_out, _) = sb.run_cli(
        &[
            "verify-enforcement",
            "begin",
            "--json",
            "--execution-mode",
            "local",
            "--observer-pubkey",
            &obs_pk,
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    let b1 = JsonValue::parse(b1_out.trim()).expect("b1");
    let cid1 = b1
        .get("challenge_id")
        .and_then(JsonValue::as_str)
        .expect("cid1");
    let canary1 = b1
        .get("canary_rel_path")
        .and_then(JsonValue::as_str)
        .expect("canary1");
    let sig1 = agent_guard::enforcement_state::sign_observer_verdict(
        &obs_seed,
        cid1,
        "antigravity",
        &sb.repo_dir,
        canary1,
        true,
    );

    let (no_hook_code, no_hook_out, _) = sb.run_cli(
        &[
            "verify-enforcement",
            "complete",
            "--json",
            "--execution-mode",
            "local",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            "--challenge",
            cid1,
            "--host-prevented-execution",
            "true",
            "--observer-sig",
            &sig1,
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(no_hook_code, 2);
    assert_eq!(
        JsonValue::parse(no_hook_out.trim())
            .expect("nh json")
            .get("code")
            .and_then(JsonValue::as_str),
        Some("HOOK_NOT_INVOKED")
    );

    // 15b: Hook runs and denies canary, BUT advisory/broken host writes the canary side-effect file anyway -> `PROHIBITED_SIDE_EFFECT_OBSERVED`!
    let p1 = format!(
        r#"{{"conversationId":"conv_t15","workspacePaths":[{}],"toolCall":{{"name":"write_to_file","args":{{"TargetFile":"{}/{}","CodeContent":"BYPASSED\n","Overwrite":true}}}},"stepIdx":0}}"#,
        sb.ws_json(),
        sb.repo_dir.display(),
        canary1
    );
    let (hc1, ho1, _) = sb.run_cli(
        &[
            "antigravity-hook",
            "PreToolUse",
            "--workspace",
            &sb.repo_dir.to_string_lossy(),
        ],
        p1.as_bytes(),
        &[],
    );
    assert_eq!(hc1, 0);
    assert_eq!(
        JsonValue::parse(ho1.trim())
            .expect("ho1")
            .get("decision")
            .and_then(JsonValue::as_str),
        Some("deny")
    );

    // Unauthenticated self-attestation without `--observer-sig` MUST be rejected (`OBSERVER_ATTESTATION_REQUIRED`)
    let (unauth_code, unauth_out, _) = sb.run_cli(
        &[
            "verify-enforcement",
            "complete",
            "--json",
            "--execution-mode",
            "local",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            "--challenge",
            cid1,
            "--host-prevented-execution",
            "true",
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(unauth_code, 2);
    assert_eq!(
        JsonValue::parse(unauth_out.trim())
            .expect("unauth json")
            .get("code")
            .and_then(JsonValue::as_str),
        Some("OBSERVER_ATTESTATION_REQUIRED")
    );

    // Wrong Ed25519 observer key MUST be rejected (`FORGED_EVIDENCE_REJECTED`)
    let wrong_sig = agent_guard::enforcement_state::sign_observer_verdict(
        &[0x99u8; 32],
        cid1,
        "antigravity",
        &sb.repo_dir,
        canary1,
        true,
    );
    let (bad_sig_code, bad_sig_out, _) = sb.run_cli(
        &[
            "verify-enforcement",
            "complete",
            "--json",
            "--execution-mode",
            "local",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            "--challenge",
            cid1,
            "--host-prevented-execution",
            "true",
            "--observer-sig",
            &wrong_sig,
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(bad_sig_code, 2);
    assert_eq!(
        JsonValue::parse(bad_sig_out.trim())
            .expect("bad sig json")
            .get("code")
            .and_then(JsonValue::as_str),
        Some("FORGED_EVIDENCE_REJECTED")
    );

    // Simulate broken host ignoring denial and writing the prohibited side effect
    fs::write(sb.repo_dir.join(canary1), "BYPASSED\n").expect("plant side effect");
    let (se_code, se_out, _) = sb.run_cli(
        &[
            "verify-enforcement",
            "complete",
            "--json",
            "--execution-mode",
            "local",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            "--challenge",
            cid1,
            "--host-prevented-execution",
            "true",
            "--observer-sig",
            &sig1,
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(se_code, 2);
    assert_eq!(
        JsonValue::parse(se_out.trim())
            .expect("se json")
            .get("code")
            .and_then(JsonValue::as_str),
        Some("PROHIBITED_SIDE_EFFECT_OBSERVED")
    );
    fs::remove_file(sb.repo_dir.join(canary1)).expect("cleanup planted side effect");

    // 15c: Clean 5-step completion succeeds -> `mandatory_protection_verified == true`!
    establish_genuine_receipt_via_cli(&sb);
    let (final_code, final_out, _) = sb.run_cli(
        &[
            "status",
            "--json",
            "--require-host-enforced",
            "--execution-mode",
            "local",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(final_code, 0, "verified status must exit 0: {final_out}");
    let fj = JsonValue::parse(final_out.trim()).expect("final json");
    assert_eq!(
        fj.get("mandatory_protection_verified")
            .and_then(JsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        fj.get("host_enforced")
            .and_then(|v| v.get("state"))
            .and_then(JsonValue::as_str),
        Some("verified")
    );
}

#[test]
fn test_16_strict_hook_token_parsing_post_tool_use_check_quoted_paths_and_witness_isolation() {
    let sb = CapabilitySandbox::create("t16_strict_config");
    sb.activate_antigravity();
    let hooks_path = sb.repo_dir.join(".agents/hooks.json");
    let valid_hooks = fs::read_to_string(&hooks_path).expect("read valid hooks");
    let snap = local_landlock_snapshot();

    // 16a: Substring suffix attack (`antigravity-hook PreToolUse-malicious`) MUST be rejected!
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hooks_path, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
    }
    let suffix_tampered = valid_hooks.replace(
        "antigravity-hook PreToolUse",
        "antigravity-hook PreToolUse-malicious",
    );
    fs::write(&hooks_path, suffix_tampered).expect("write suffix tampered hooks");
    let rep_suffix =
        evaluate_enforcement_report(&sb.repo_dir, &sb.bin_dir, "antigravity", None, None, &snap);
    assert!(matches!(
        rep_suffix.configured,
        ConfigState::Invalid {
            reason_code: "CONFIG_PROTOCOL_INCOMPATIBLE",
            ..
        }
    ));

    // 16b: Omitting `PostToolUse` from `dotagent-guard` MUST be rejected!
    let mut parsed_hooks = JsonValue::parse(&valid_hooks).expect("parse valid hooks");
    if let JsonValue::Object(ref mut root_entries) = parsed_hooks
        && let Some((_, JsonValue::Object(dg_entries))) =
            root_entries.iter_mut().find(|(k, _)| k == "dotagent-guard")
    {
        dg_entries.retain(|(k, _)| k != "PostToolUse");
    }
    fs::write(&hooks_path, format!("{}\n", parsed_hooks.to_json_string()))
        .expect("write missing PostToolUse hooks");
    let rep_no_post =
        evaluate_enforcement_report(&sb.repo_dir, &sb.bin_dir, "antigravity", None, None, &snap);
    assert!(matches!(
        rep_no_post.configured,
        ConfigState::Invalid {
            reason_code: "CONFIG_PROTOCOL_INCOMPATIBLE",
            ..
        }
    ));

    // 16c: Workspace & binary paths containing spaces quote safely during `activate` and validate cleanly!
    let spaced_ws = sb.base.join("workspace with spaces");
    let spaced_bin_dir = sb.base.join("bin with spaces");
    fs::create_dir_all(spaced_ws.join(".git")).expect("mkdir spaced .git");
    fs::create_dir_all(spaced_ws.join("src")).expect("mkdir spaced src");
    fs::write(spaced_ws.join("AGENTS.md"), "# AGENTS.md\n").expect("spaced AGENTS.md");
    fs::write(spaced_ws.join("src/lib.rs"), "pub fn ok() {}\n").expect("spaced lib.rs");
    fs::create_dir_all(&spaced_bin_dir).expect("mkdir spaced bin");
    fs::copy(
        sb.bin_dir.join("agent-guard"),
        spaced_bin_dir.join("agent-guard"),
    )
    .expect("copy guard to spaced bin");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            spaced_bin_dir.join("agent-guard"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("chmod 0755 spaced guard");
    }
    execute_antigravity_activate(&spaced_bin_dir, &sb.dotagent_root(), &spaced_ws, false)
        .expect("activate spaced workspace and binary");
    let rep_spaced = evaluate_enforcement_report(
        &spaced_ws,
        &spaced_bin_dir,
        "antigravity",
        None,
        None,
        &snap,
    );
    assert!(
        matches!(
            rep_spaced.configured,
            ConfigState::Valid {
                pinned_binary_matches: true,
                protocol_compatible: true,
                ..
            }
        ),
        "spaced paths must quote and validate cleanly: {:?}",
        rep_spaced.configured
    );

    // 16d: Legacy `pre-tool` Gemini denial (`BeforeTool`) must NOT cross-populate a pending `claude` challenge!
    fs::create_dir_all(spaced_ws.join(".claude")).expect("mkdir .claude");
    let gbin = sb.bin_dir.join("agent-guard");
    let gbin_d = gbin.display();
    let claude_cfg = format!(
        concat!(
            "{{\"hooks\":{{",
            "\"UserPromptSubmit\":[{{\"hooks\":[{{\"type\":\"command\",\"command\":\"{0} user-prompt\"}}]}}],",
            "\"PreToolUse\":[{{\"matcher\":\"*\",\"hooks\":[{{\"type\":\"command\",\"command\":\"{0} pre-tool\"}}]}}],",
            "\"PostToolUse\":[{{\"matcher\":\"*\",\"hooks\":[{{\"type\":\"command\",\"command\":\"{0} post-tool\"}}]}}],",
            "\"PreCompact\":[{{\"hooks\":[{{\"type\":\"command\",\"command\":\"{0} pre-compact\"}}]}}],",
            "\"Stop\":[{{\"hooks\":[{{\"type\":\"command\",\"command\":\"{0} on-stop\"}}]}}]",
            "}}}}\n"
        ),
        gbin_d
    );
    fs::write(spaced_ws.join(".claude/settings.json"), claude_cfg).expect("write claude settings");
    let obs_seed = [0x42u8; 32];
    let obs_pk = agent_guard::enforcement_state::derive_observer_pubkey_hex(&obs_seed);
    let (cb_code, cb_out, cb_err) = sb.run_cli(
        &[
            "verify-enforcement",
            "begin",
            "--json",
            "--adapter",
            "claude",
            "--execution-mode",
            "local",
            "--observer-pubkey",
            &obs_pk,
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            &spaced_ws.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(cb_code, 0, "claude begin failed: {cb_err}");
    let cb_json = JsonValue::parse(cb_out.trim()).expect("cb json");
    let claude_cid = cb_json
        .get("challenge_id")
        .and_then(JsonValue::as_str)
        .expect("claude cid");
    let claude_canary = cb_json
        .get("canary_rel_path")
        .and_then(JsonValue::as_str)
        .expect("claude canary");

    // Send a Gemini (`BeforeTool`) payload referencing `claude_canary` through `pre-tool`
    let gemini_spoof = format!(
        r#"{{"session_id":"gem_spoof","hook_event_name":"BeforeTool","tool_name":"Write","tool_input":{{"file_path":"{}/{}"}}}}"#,
        spaced_ws.display(),
        claude_canary
    );
    let _ = sb.run_cli(&["pre-tool"], gemini_spoof.as_bytes(), &[]);

    let claude_sig = agent_guard::enforcement_state::sign_observer_verdict(
        &obs_seed,
        claude_cid,
        "claude",
        &spaced_ws,
        claude_canary,
        true,
    );
    let (cc_code, cc_out, _) = sb.run_cli(
        &[
            "verify-enforcement",
            "complete",
            "--json",
            "--adapter",
            "claude",
            "--execution-mode",
            "local",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            "--challenge",
            claude_cid,
            "--host-prevented-execution",
            "true",
            "--observer-sig",
            &claude_sig,
            &spaced_ws.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(
        cc_code, 2,
        "Gemini pre-tool payload must NOT create a witness in claude's slot"
    );
    assert_eq!(
        JsonValue::parse(cc_out.trim())
            .expect("cc json")
            .get("code")
            .and_then(JsonValue::as_str),
        Some("HOOK_NOT_INVOKED")
    );
}

#[test]
fn test_17_phase2_multi_harness_sandbox_probe_and_witness_regressions() {
    let sb = CapabilitySandbox::create("t17_phase2_reg");
    let snap = ProbeSnapshot {
        execution_mode: ExecutionMode::LocalHost,
        kernel_fs_mode: KernelSandboxMode::LinuxLandlockEnforced,
        seccomp_net: Some(true),
        netns_unshare: true,
        binary_version_override: None,
    };

    // 17a: Paths containing BOTH spaces and apostrophes (`'`) activate and validate cleanly across all 5 adapters!
    let apos_ws = sb.base.join("alice's repo");
    let apos_bin = sb.base.join("alice's bin");
    let apos_home = sb.base.join("alice's home");
    fs::create_dir_all(apos_ws.join(".git")).expect("mkdir apos .git");
    fs::create_dir_all(&apos_bin).expect("mkdir apos bin");
    fs::create_dir_all(&apos_home).expect("mkdir apos home");
    fs::write(apos_ws.join("AGENTS.md"), "# AGENTS.md\n").expect("write apos AGENTS.md");
    for name in ["agent-guard", "dotagent"] {
        let src = if name == "agent-guard" {
            PathBuf::from(env!("CARGO_BIN_EXE_agent-guard"))
        } else {
            PathBuf::from(env!("CARGO_BIN_EXE_dotagent"))
        };
        let dst = apos_bin.join(name);
        fs::copy(src, &dst).expect("copy bin");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dst, fs::Permissions::from_mode(0o755)).expect("chmod 0755");
        }
    }

    let act_out = Command::new(apos_bin.join("dotagent"))
        .args(["activate", "--dotagent-root"])
        .arg(sb.dotagent_root())
        .arg("--workspace")
        .arg(&apos_ws)
        .arg("--bin-dir")
        .arg(&apos_bin)
        .env("HOME", &apos_home)
        .env("AGENT_GUARD_STATE_DIR", &sb.state_dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("activate all on apostrophe paths");
    assert!(
        act_out.status.success(),
        "activate failed: {}",
        String::from_utf8_lossy(&act_out.stderr)
    );

    for ad in ["antigravity", "claude", "cursor", "codex", "gemini"] {
        let st_out = Command::new(apos_bin.join("dotagent"))
            .args([
                "status",
                "--json",
                "--execution-mode",
                "local",
                "--adapter",
                ad,
                "--bin-dir",
            ])
            .arg(&apos_bin)
            .arg(&apos_ws)
            .env("HOME", &apos_home)
            .env("AGENT_GUARD_STATE_DIR", &sb.state_dir)
            .output()
            .expect("status adapter");
        assert!(
            st_out.status.success(),
            "status failed for {ad}: {}",
            String::from_utf8_lossy(&st_out.stderr)
        );
        let sj = JsonValue::parse(&String::from_utf8_lossy(&st_out.stdout)).expect("parse status");
        assert_eq!(
            sj.get("configured")
                .and_then(|v| v.get("state"))
                .and_then(JsonValue::as_str),
            Some("valid"),
            "adapter {ad} should be valid on apostrophe path: {}",
            String::from_utf8_lossy(&st_out.stdout)
        );
        if ad == "codex" {
            assert_eq!(
                sj.get("host_enforced")
                    .and_then(|v| v.get("reason_code"))
                    .and_then(JsonValue::as_str),
                Some("ADAPTER_LACKS_PRETOOL_HOOK")
            );
        }
    }

    // 17b: Missing/disabled hooks and invalid Codex TOML are rejected across claude, cursor, gemini, codex, and antigravity!
    let cached_inst = agent_guard::enforcement_state::evaluate_install_state(&apos_bin, "2.1.0");
    let other_ws = sb.base.join("other_ws");
    fs::create_dir_all(other_ws.join(".git")).expect("mkdir other .git");
    fs::create_dir_all(other_ws.join(".agents")).expect("mkdir other .agents");
    fs::write(other_ws.join("AGENTS.md"), "# AGENTS.md\n").expect("other AGENTS.md");
    // Copying apos_ws's `.agents/hooks.json` into `other_ws` must fail with `CONFIG_WORKSPACE_MISMATCH`
    fs::copy(
        apos_ws.join(".agents/hooks.json"),
        other_ws.join(".agents/hooks.json"),
    )
    .expect("copy hooks.json across workspaces");
    let cfg_ws_mismatch = agent_guard::enforcement_state::evaluate_config_state(
        &other_ws,
        "antigravity",
        &cached_inst,
    );
    assert!(matches!(
        cfg_ws_mismatch,
        ConfigState::Invalid {
            reason_code: "CONFIG_WORKSPACE_MISMATCH",
            ..
        }
    ));

    // Claude `disableAllHooks: true` and missing `PostToolUse` fail closed
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for rel in [
            ".claude/settings.json",
            ".cursor/hooks.json",
            ".codex/config.toml",
        ] {
            fs::set_permissions(apos_ws.join(rel), fs::Permissions::from_mode(0o644))
                .expect("chmod writable");
        }
    }
    fs::write(
        apos_ws.join(".claude/settings.json"),
        format!(
            "{{\"disableAllHooks\":true,\"_note\":\"{}\"}}\n",
            apos_bin.join("agent-guard").display()
        ),
    )
    .expect("write disabled claude");
    let cfg_claude_dis =
        agent_guard::enforcement_state::evaluate_config_state(&apos_ws, "claude", &cached_inst);
    assert!(matches!(
        cfg_claude_dis,
        ConfigState::Invalid {
            reason_code: "CONFIG_HOOKS_DISABLED",
            ..
        }
    ));

    // Cursor missing `afterShellExecution` fails closed
    fs::write(
        apos_ws.join(".cursor/hooks.json"),
        format!(
            "{{\"version\":1,\"hooks\":{{\"beforeShellExecution\":[{{\"command\":\"'{}' pre-tool\"}}]}}}}\n",
            apos_bin.join("agent-guard").display()
        ),
    )
    .expect("write incomplete cursor");
    let cfg_cursor_inc =
        agent_guard::enforcement_state::evaluate_config_state(&apos_ws, "cursor", &cached_inst);
    assert!(matches!(
        cfg_cursor_inc,
        ConfigState::Invalid {
            reason_code: "CONFIG_PROTOCOL_INCOMPATIBLE",
            ..
        }
    ));

    // Codex malformed TOML and `danger-full-access` fail closed
    fs::write(apos_ws.join(".codex/config.toml"), ":::not valid toml[[[\n")
        .expect("write bad toml");
    let cfg_codex_bad =
        agent_guard::enforcement_state::evaluate_config_state(&apos_ws, "codex", &cached_inst);
    assert!(matches!(
        cfg_codex_bad,
        ConfigState::Invalid {
            reason_code: "CONFIG_MALFORMED_TOML",
            ..
        }
    ));
    fs::write(
        apos_ws.join(".codex/config.toml"),
        "sandbox_mode = \"danger-full-access\"\nnotify = [\"agent-guard\", \"on-stop\"]\n",
    )
    .expect("write danger codex");
    let cfg_codex_danger =
        agent_guard::enforcement_state::evaluate_config_state(&apos_ws, "codex", &cached_inst);
    assert!(matches!(
        cfg_codex_danger,
        ConfigState::Invalid {
            reason_code: "CONFIG_HOOKS_DISABLED",
            ..
        }
    ));

    fs::write(
        apos_ws.join(".codex/config.toml"),
        format!(
            "sandbox_mode = \"workspace-write\"\nnotify = [\"{}\", \"on-stop\"]\nunrelated = [\n[sandbox_workspace_write]\nnetwork_access = false\n",
            apos_bin.join("agent-guard").display()
        ),
    )
    .expect("write unclosed unknown toml key");
    let cfg_codex_unknown_bad =
        agent_guard::enforcement_state::evaluate_config_state(&apos_ws, "codex", &cached_inst);
    assert!(matches!(
        cfg_codex_unknown_bad,
        ConfigState::Invalid {
            reason_code: "CONFIG_MALFORMED_TOML",
            ..
        }
    ));

    // Shell script, 4-byte ELF stub, and wrong-OS executable headers fail `InstallState` (`BINARY_INVALID_FORMAT`)
    let fake_bin_dir = sb.base.join("fake_bin");
    fs::create_dir_all(&fake_bin_dir).expect("mkdir fake_bin");
    let fake_guard = fake_bin_dir.join("agent-guard");
    let wrong_os_bytes: &[u8] = if cfg!(target_os = "linux") {
        &[0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01]
    } else {
        b"\x7fELF\x02\x01\x01\x00"
    };
    for bad_bytes in [
        b"#!/bin/sh\nexit 0\n".as_slice(),
        b"\x7fELF",
        wrong_os_bytes,
    ] {
        #[cfg(unix)]
        if fake_guard.exists() {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&fake_guard, fs::Permissions::from_mode(0o755))
                .expect("chmod writable");
        }
        fs::write(&fake_guard, bad_bytes).expect("write bad binary");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&fake_guard, fs::Permissions::from_mode(0o555))
                .expect("chmod 0555");
        }
        let rep_fake_bin = evaluate_enforcement_report(
            &sb.repo_dir,
            &fake_bin_dir,
            "antigravity",
            None,
            None,
            &snap,
        );
        assert!(matches!(
            rep_fake_bin.installed,
            InstallState::IntegrityFailed {
                reason_code: "BINARY_INVALID_FORMAT",
                ..
            }
        ));
    }

    // 17c: Ancestor rogue `agent-guard` executable above `current_exe` is NEVER executed by sandbox probes!
    let probe_tree = sb.base.join("probe_anc");
    let child_bin_dir = probe_tree.join("nested/bin");
    fs::create_dir_all(&child_bin_dir).expect("mkdir nested/bin");
    let marker_file = probe_tree.join("rogue_executed.marker");
    let rogue_anc = probe_tree.join("agent-guard");
    fs::write(
        &rogue_anc,
        format!(
            "#!/bin/sh\nprintf 'pwned' > '{}'\necho linux-landlock-enforced\n",
            marker_file.display()
        ),
    )
    .expect("write rogue ancestor");
    fs::copy(
        sb.bin_dir.join("agent-guard"),
        child_bin_dir.join("agent-guard"),
    )
    .expect("copy nested real guard");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&rogue_anc, fs::Permissions::from_mode(0o755)).expect("chmod rogue");
        fs::set_permissions(
            child_bin_dir.join("agent-guard"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("chmod nested guard");
    }
    let sbx_st = Command::new(child_bin_dir.join("agent-guard"))
        .arg("sandbox-status")
        .output()
        .expect("run nested sandbox-status");
    assert!(sbx_st.status.success());
    assert!(
        !marker_file.exists(),
        "rogue ancestor binary MUST NEVER be executed during sandbox probes"
    );

    // 17d: Relative `--bin-dir`, ambiguous multi-adapter payload rejection, session_id canary smuggling rejection,
    //      `UnsupportedHost` rejection even with `--external-observer`, and harness env marker block!
    sb.activate_antigravity();
    let obs_seed = [0x77u8; 32];
    let obs_pk = agent_guard::enforcement_state::derive_observer_pubkey_hex(&obs_seed);

    // Ambient harness marker (`CLAUDECODE=1`) blocks `verify-enforcement`
    let (env_blk, env_out, _) = sb.run_cli(
        &[
            "verify-enforcement",
            "begin",
            "--json",
            "--execution-mode",
            "local",
            "--observer-pubkey",
            &obs_pk,
            "--bin-dir",
            "../bin",
            ".",
        ],
        b"",
        &[("CLAUDECODE", "1")],
    );
    assert_eq!(env_blk, 2);
    assert_eq!(
        JsonValue::parse(env_out.trim())
            .expect("env json")
            .get("code")
            .and_then(JsonValue::as_str),
        Some("SANDBOX_FORBIDDEN")
    );

    // `UnsupportedHost` rejected even with `--external-observer`
    let (unsup_c, unsup_out, _) = sb.run_cli(
        &[
            "verify-enforcement",
            "begin",
            "--json",
            "--external-observer",
            "--execution-mode",
            "unsupported",
            "--observer-pubkey",
            &obs_pk,
            "--bin-dir",
            "../bin",
            ".",
        ],
        b"",
        &[],
    );
    assert_eq!(unsup_c, 2);
    assert_eq!(
        JsonValue::parse(unsup_out.trim())
            .expect("unsup json")
            .get("code")
            .and_then(JsonValue::as_str),
        Some("UNSUPPORTED_EXECUTION_MODE")
    );

    // Relative `--bin-dir ../bin` succeeds in `begin`
    let (rel_c, rel_out, rel_err) = sb.run_cli(
        &[
            "verify-enforcement",
            "begin",
            "--json",
            "--execution-mode",
            "local",
            "--observer-pubkey",
            &obs_pk,
            "--bin-dir",
            "../bin",
            ".",
        ],
        b"",
        &[],
    );
    assert_eq!(rel_c, 0, "relative --bin-dir begin failed: {rel_err}");
    let rel_j = JsonValue::parse(rel_out.trim()).expect("rel json");
    let rel_cid = rel_j
        .get("challenge_id")
        .and_then(JsonValue::as_str)
        .expect("rel cid");
    let rel_canary = rel_j
        .get("canary_rel_path")
        .and_then(JsonValue::as_str)
        .expect("rel canary");

    // Smuggling `rel_canary` in `conversationId` while denying an unrelated `.env` read must NOT mint a witness!
    let smuggled = format!(
        r#"{{"conversationId":"smuggle_{rel_canary}","workspacePaths":[{}],"toolName":"view_file","parameters":{{"AbsolutePath":"{}/.env"}}}}"#,
        sb.ws_json(),
        sb.repo_dir.display()
    );
    let _ = sb.run_cli(
        &["antigravity-hook", "PreToolUse"],
        smuggled.as_bytes(),
        &[],
    );
    let rel_sig = agent_guard::enforcement_state::sign_observer_verdict(
        &obs_seed,
        rel_cid,
        "antigravity",
        &sb.repo_dir,
        rel_canary,
        true,
    );
    let (sm_c, sm_out, _) = sb.run_cli(
        &[
            "verify-enforcement",
            "complete",
            "--json",
            "--execution-mode",
            "local",
            "--bin-dir",
            "../bin",
            "--challenge",
            rel_cid,
            "--host-prevented-execution",
            "true",
            "--observer-sig",
            &rel_sig,
            ".",
        ],
        b"",
        &[],
    );
    assert_eq!(sm_c, 2);
    assert_eq!(
        JsonValue::parse(sm_out.trim())
            .expect("sm json")
            .get("code")
            .and_then(JsonValue::as_str),
        Some("HOOK_NOT_INVOKED")
    );

    // 17e: Cross-workspace `cwd` payload spoofing AND missing/wrong event discriminator under `--adapter claude` must NOT mint a witness!
    fs::create_dir_all(sb.repo_dir.join(".claude")).expect("mkdir .claude");
    let gbin_d = sb.bin_dir.join("agent-guard").display().to_string();
    let claude_cfg = format!(
        concat!(
            "{{\"hooks\":{{",
            "\"UserPromptSubmit\":[{{\"hooks\":[{{\"type\":\"command\",\"command\":\"'{0}' user-prompt --adapter claude\"}}]}}],",
            "\"PreToolUse\":[{{\"matcher\":\"*\",\"hooks\":[{{\"type\":\"command\",\"command\":\"'{0}' pre-tool --adapter claude\"}}]}}],",
            "\"PostToolUse\":[{{\"matcher\":\"*\",\"hooks\":[{{\"type\":\"command\",\"command\":\"'{0}' post-tool --adapter claude\"}}]}}],",
            "\"PreCompact\":[{{\"hooks\":[{{\"type\":\"command\",\"command\":\"'{0}' pre-compact --adapter claude\"}}]}}],",
            "\"Stop\":[{{\"hooks\":[{{\"type\":\"command\",\"command\":\"'{0}' on-stop --adapter claude\"}}]}}]",
            "}}}}\n"
        ),
        gbin_d
    );
    fs::write(sb.repo_dir.join(".claude/settings.json"), claude_cfg)
        .expect("write claude settings");
    let (cl_b_c, cl_b_out, cl_b_err) = sb.run_cli(
        &[
            "verify-enforcement",
            "begin",
            "--json",
            "--adapter",
            "claude",
            "--execution-mode",
            "local",
            "--observer-pubkey",
            &obs_pk,
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(cl_b_c, 0, "claude begin failed: {cl_b_err}");
    let cl_b_j = JsonValue::parse(cl_b_out.trim()).expect("cl_b json");
    let cl_cid = cl_b_j
        .get("challenge_id")
        .and_then(JsonValue::as_str)
        .expect("cl cid");
    let cl_canary = cl_b_j
        .get("canary_rel_path")
        .and_then(JsonValue::as_str)
        .expect("cl canary");

    // Attempt 1: Invoke `pre-tool --adapter claude` from `other_ws` while claiming `cwd = sb.repo_dir`
    let cross_cwd_payload = format!(
        r#"{{"session_id":"cross_ws","hook_event_name":"PreToolUse","cwd":{},"tool_name":"Write","tool_input":{{"file_path":"{}/{}"}}}}"#,
        sb.ws_json(),
        sb.repo_dir.display(),
        cl_canary
    );
    let mut cross_child = Command::new(sb.bin_dir.join("agent-guard"))
        .current_dir(&other_ws)
        .args(["pre-tool", "--adapter", "claude"])
        .env("AGENT_GUARD_STATE_DIR", &sb.state_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cross-ws pre-tool");
    if let Some(mut sin) = cross_child.stdin.take() {
        let _ = sin.write_all(cross_cwd_payload.as_bytes());
    }
    let _ = cross_child.wait_with_output().expect("wait cross-ws");

    // Attempt 2: Invoke `pre-tool --adapter claude` inside `sb.repo_dir` with `PostToolUse` or missing `hook_event_name`
    for bad_ev_payload in [
        format!(
            r#"{{"session_id":"no_ev","tool_name":"Write","tool_input":{{"file_path":"{}/{}"}}}}"#,
            sb.repo_dir.display(),
            cl_canary
        ),
        format!(
            r#"{{"session_id":"post_ev","hook_event_name":"PostToolUse","tool_name":"Write","tool_input":{{"file_path":"{}/{}"}}}}"#,
            sb.repo_dir.display(),
            cl_canary
        ),
    ] {
        let _ = sb.run_cli(
            &["pre-tool", "--adapter", "claude"],
            bad_ev_payload.as_bytes(),
            &[],
        );
    }

    let cl_sig = agent_guard::enforcement_state::sign_observer_verdict(
        &obs_seed,
        cl_cid,
        "claude",
        &sb.repo_dir,
        cl_canary,
        true,
    );
    let (cl_bad_c, cl_bad_out, _) = sb.run_cli(
        &[
            "verify-enforcement",
            "complete",
            "--json",
            "--adapter",
            "claude",
            "--execution-mode",
            "local",
            "--bin-dir",
            &sb.bin_dir.to_string_lossy(),
            "--challenge",
            cl_cid,
            "--host-prevented-execution",
            "true",
            "--observer-sig",
            &cl_sig,
            &sb.repo_dir.to_string_lossy(),
        ],
        b"",
        &[],
    );
    assert_eq!(cl_bad_c, 2);
    assert_eq!(
        JsonValue::parse(cl_bad_out.trim())
            .expect("cl_bad json")
            .get("code")
            .and_then(JsonValue::as_str),
        Some("HOOK_NOT_INVOKED")
    );
}
