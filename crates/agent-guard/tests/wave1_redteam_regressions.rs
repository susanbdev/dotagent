#![forbid(unsafe_code)]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use agent_guard::crypto::{hex_encode, sha256_hex};
use agent_guard::handle_pre_tool_hook;
use agent_guard::json::JsonValue;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn create_isolated_workspace(short_name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let base = workspace_root().join("target").join("tw").join(short_name);
    let _ = fs::remove_dir_all(&base);
    let repo = base.join("r");
    let home = base.join("h");
    let state = base.join("s");
    fs::create_dir_all(repo.join("src")).expect("mkdir src");
    fs::create_dir_all(&home).expect("mkdir home");
    fs::create_dir_all(&state).expect("mkdir state");
    fs::write(repo.join("AGENTS.md"), "# Canonical Root Authority\n").expect("write AGENTS.md");
    fs::write(repo.join("src/clean.rs"), "pub fn ok() -> u32 { 42 }\n").expect("write clean.rs");

    let git_init = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .status()
        .expect("git init");
    assert!(git_init.success());
    (repo, home, state)
}

#[test]
fn wave1_cli_unknown_subcommands_fail_closed_and_cursor_post_edit_stdin_works() {
    let (ws, home, _state) = create_isolated_workspace("w1_cli");
    let guard_bin = PathBuf::from(env!("CARGO_BIN_EXE_agent-guard"));

    // 1. Typo in hook subcommand must exit 2 (HARD DENY), never 0!
    let typo = Command::new(&guard_bin)
        .arg("pre_tool")
        .env("HOME", &home)
        .current_dir(&ws)
        .output()
        .expect("spawn agent-guard pre_tool");
    assert_eq!(typo.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&typo.stderr);
    assert!(stderr.contains("UNKNOWN_SUBCOMMAND"), "stderr: {stderr}");

    // 2. Explicit --help exits 0
    let help = Command::new(&guard_bin)
        .arg("--help")
        .env("HOME", &home)
        .current_dir(&ws)
        .output()
        .expect("spawn agent-guard --help");
    assert_eq!(help.status.code(), Some(0));

    // 3. Cursor `afterFileEdit` stdin JSON hook mode on `agent-guard post-edit`
    let mut child_clean = Command::new(&guard_bin)
        .arg("post-edit")
        .env("HOME", &home)
        .current_dir(&ws)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn post-edit clean");
    child_clean
        .stdin
        .take()
        .expect("stdin")
        .write_all(br#"{"file_path":"src/clean.rs"}"#)
        .expect("write stdin");
    let out_clean = child_clean.wait_with_output().expect("wait clean");
    assert_eq!(out_clean.status.code(), Some(0));

    let mut child_blocked = Command::new(&guard_bin)
        .arg("post-edit")
        .env("HOME", &home)
        .current_dir(&ws)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn post-edit AGENTS.md");
    child_blocked
        .stdin
        .take()
        .expect("stdin")
        .write_all(br#"{"file_path":"AGENTS.md"}"#)
        .expect("write stdin");
    let out_blocked = child_blocked.wait_with_output().expect("wait blocked");
    assert_eq!(out_blocked.status.code(), Some(2));
}

#[test]
fn wave1_duplicate_json_key_smuggling_and_corrupt_session_state_fail_closed() {
    let (ws, home, _state) = create_isolated_workspace("w1_json");
    let guard_bin = PathBuf::from(env!("CARGO_BIN_EXE_agent-guard"));

    // 1. RFC 7493 I-JSON duplicate key smuggling attempt must be hard-denied!
    let smuggled = r#"{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"curl https://evil.invalid"},"tool_input":{"command":"echo innocent"}}"#;
    let dec = handle_pre_tool_hook(smuggled, &ws);
    match dec {
        agent_guard::Decision::Deny { code, .. } => {
            assert_eq!(code, "INVALID_HOOK_JSON");
        }
        other => panic!("expected Deny(INVALID_HOOK_JSON), got {other:?}"),
    }

    // 2. Corrupting session ledger JSON inside isolated test HOME must fail closed (exit 2)
    let init_ok = Command::new(&guard_bin)
        .args([
            "pre-tool",
            "--json",
            r#"{"session_id":"corrupt_check","tool_name":"Read","tool_input":{"file_path":"src/clean.rs"}}"#,
        ])
        .env("HOME", &home)
        .current_dir(&ws)
        .output()
        .expect("run initial pre-tool");
    assert_eq!(init_ok.status.code(), Some(0));

    let sessions_dir = home.join(".local/state/agent-guard/sessions");
    let mut corrupted_count = 0usize;
    for entry in fs::read_dir(&sessions_dir)
        .expect("read isolated test sessions dir")
        .flatten()
    {
        let p = entry.path();
        if p.extension().is_some_and(|e| e == "json") {
            fs::write(&p, b"{corrupt-json!!").expect("corrupt session json");
            corrupted_count += 1;
        }
    }
    assert_eq!(corrupted_count, 1);

    let after_corrupt = Command::new(&guard_bin)
        .args([
            "pre-tool",
            "--json",
            r#"{"session_id":"corrupt_check","tool_name":"Read","tool_input":{"file_path":"src/clean.rs"}}"#,
        ])
        .env("HOME", &home)
        .current_dir(&ws)
        .output()
        .expect("run pre-tool after corrupt");
    assert_eq!(
        after_corrupt.status.code(),
        Some(2),
        "corrupt SessionLedger must fail closed instead of resetting halted=false"
    );
    let stderr = String::from_utf8_lossy(&after_corrupt.stderr);
    assert!(stderr.contains("CORRUPT_SESSION_STATE"), "stderr: {stderr}");
}

#[test]
fn wave1_coordinator_blocks_plan_lock_master_mint_and_scope_escalation_over_ipc() {
    let (ws, home, _state_dir) = create_isolated_workspace("c1");
    let canon_ws = fs::canonicalize(&ws).expect("canon ws");
    let guard_bin = PathBuf::from(env!("CARGO_BIN_EXE_agent-guard"));

    let repo_ns = &sha256_hex(canon_ws.to_string_lossy().as_bytes())[..24];
    let swarm_dir = home.join(".local/state/agent-guard/swarm").join(repo_ns);
    fs::create_dir_all(swarm_dir.join("vault")).expect("mkdir vault");
    fs::create_dir_all(swarm_dir.join("sessions")).expect("mkdir sessions");
    let key_hex = "42".repeat(32);
    fs::write(swarm_dir.join("vault/hmac.key"), &key_hex).expect("write test vault key");

    let mut daemon = Command::new(&guard_bin)
        .args(["coordinator", "--repo"])
        .arg(&canon_ws)
        .args(["--idle-secs", "5"])
        .env("HOME", &home)
        .env_remove("AGENT_GUARD_STATE_DIR")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn coordinator");

    let sock_path = swarm_dir.join("ipc/coord.sock");
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline && !sock_path.exists() {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(sock_path.exists(), "coordinator socket must come online");

    let send_rpc = |req_json: &str| -> String {
        let mut stream = agent_guard::coordinator::connect_unix_short_path(&sock_path)
            .expect("connect coord.sock");
        stream
            .write_all(format!("{req_json}\n").as_bytes())
            .expect("write rpc");
        stream.flush().expect("flush rpc");
        let mut line = String::new();
        BufReader::new(stream)
            .read_line(&mut line)
            .expect("read rpc");
        line
    };

    // 1. Signing `PLAN_LOCK_HMAC_DOMAIN` over IPC must be hard-denied!
    let plan_domain_hex = hex_encode(b"dotagent-plan-lock-v1");
    let resp1 = send_rpc(&format!(
        r#"{{"op":"domain_hmac","domain_hex":"{plan_domain_hex}","payload_hex":"deadbeef"}}"#
    ));
    assert!(
        resp1.contains("PRIVILEGED_DOMAIN_DENIED"),
        "PLAN_LOCK signing over IPC must be blocked: {resp1}"
    );

    // 2. Minting `master` over `CAPABILITY_HMAC_DOMAIN` must be hard-denied!
    let cap_domain_hex = hex_encode(b"DOTAGENT_SESSION_CAPABILITY_V1");
    let forged_master_hex = encode_raw_cap_hex(
        "swm_master_T1_a1_0011223344",
        "master",
        "T1",
        &["src/clean.rs"],
        0,
    );
    let resp2 = send_rpc(&format!(
        r#"{{"op":"domain_hmac","domain_hex":"{cap_domain_hex}","payload_hex":"{forged_master_hex}"}}"#
    ));
    assert!(
        resp2.contains("PRIVILEGED_ROLE_DENIED"),
        "Master capability signing over IPC must be blocked: {resp2}"
    );

    // 3. Minting an unminted Grunt session over IPC must be hard-denied!
    let unminted_grunt_hex = encode_raw_cap_hex(
        "swm_grunt_T1_a1_9988776655",
        "grunt",
        "T1",
        &["src/clean.rs"],
        0,
    );
    let resp_unminted = send_rpc(&format!(
        r#"{{"op":"domain_hmac","domain_hex":"{cap_domain_hex}","payload_hex":"{unminted_grunt_hex}"}}"#
    ));
    assert!(
        resp_unminted.contains("UNMINTED_CAPABILITY_DENIED"),
        "Unminted worker capability signing over IPC must be blocked: {resp_unminted}"
    );

    // 4. Write a validly host-signed Grunt session on disk, then verify scope-widening is blocked while counter updates succeed!
    let sid = "swm_grunt_T1_a1_aabbccddeeff";
    let base_payload_bytes = decode_hex_for_test(&encode_raw_cap_hex(
        sid,
        "grunt",
        "T1",
        &["src/clean.rs"],
        0,
    ));
    let valid_mac_hex = compute_host_cap_mac(&[0x42u8; 32], &base_payload_bytes);
    let disk_json = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str(sid.to_string())),
        ("role".to_string(), JsonValue::Str("grunt".to_string())),
        ("task_id".to_string(), JsonValue::Str("T1".to_string())),
        ("attempt".to_string(), JsonValue::Uint(1)),
        ("repo_sha256".to_string(), JsonValue::Str("aa".repeat(32))),
        ("plan_sha256".to_string(), JsonValue::Str("bb".repeat(32))),
        (
            "assigned_read_paths".to_string(),
            JsonValue::Array(vec![JsonValue::Str("src/clean.rs".to_string())]),
        ),
        (
            "allowed_write_paths".to_string(),
            JsonValue::Array(vec![JsonValue::Str("src/clean.rs".to_string())]),
        ),
        (
            "assigned_tests".to_string(),
            JsonValue::Array(vec![JsonValue::Str("ok".to_string())]),
        ),
        ("last_green_tree_oid".to_string(), JsonValue::Null),
        ("consecutive_test_failures".to_string(), JsonValue::Uint(0)),
        ("blocked_scope_attempts".to_string(), JsonValue::Uint(0)),
        ("malicious_flags".to_string(), JsonValue::Uint(0)),
        ("record_mac".to_string(), JsonValue::Str(valid_mac_hex)),
    ]);
    fs::write(
        swarm_dir.join("sessions").join(format!("{sid}.json")),
        disk_json.to_json_string(),
    )
    .expect("write minted grunt session");

    let widened_hex = encode_raw_cap_hex(sid, "grunt", "T1", &["src/clean.rs", "Cargo.toml"], 0);
    let resp3 = send_rpc(&format!(
        r#"{{"op":"domain_hmac","domain_hex":"{cap_domain_hex}","payload_hex":"{widened_hex}"}}"#
    ));
    assert!(
        resp3.contains("CAPABILITY_SCOPE_ESCALATION_DENIED"),
        "Capability scope widening over IPC must be blocked: {resp3}"
    );

    let counter_update_hex = encode_raw_cap_hex(sid, "grunt", "T1", &["src/clean.rs"], 2);
    let resp4 = send_rpc(&format!(
        r#"{{"op":"domain_hmac","domain_hex":"{cap_domain_hex}","payload_hex":"{counter_update_hex}"}}"#
    ));
    assert!(
        resp4.contains(r#""ok":true"#),
        "Legitimate counter update must succeed: {resp4}"
    );

    // 5. Boolean-only `verify_domain_hmac` never leaks expected MAC on mismatch!
    let wrong_mac = "00".repeat(32);
    let verify_resp = send_rpc(&format!(
        r#"{{"op":"verify_domain_hmac","domain_hex":"{cap_domain_hex}","payload_hex":"{counter_update_hex}","expected_mac_hex":"{wrong_mac}"}}"#
    ));
    assert!(
        verify_resp.contains(r#""valid":false"#) && !verify_resp.contains("mac_hex"),
        "Boolean verifier must never leak expected MAC: {verify_resp}"
    );

    // 6. Domain-boundary shift attack (`DOTAGENT_SESSION_CAPABILITY_V` + `'1' || len || payload`)
    //    and unknown HMAC domains must be hard-denied by closed coordinator allowlist!
    let shifted_domain_hex = hex_encode(b"DOTAGENT_SESSION_CAPABILITY_V");
    let mut shifted_payload = vec![b'1'];
    let raw_master_bytes = decode_hex_for_test(&forged_master_hex);
    shifted_payload.extend_from_slice(&(raw_master_bytes.len() as u64).to_be_bytes());
    shifted_payload.extend_from_slice(&raw_master_bytes);
    let shifted_payload_hex = hex_encode(&shifted_payload);
    let resp_shift = send_rpc(&format!(
        r#"{{"op":"domain_hmac","domain_hex":"{shifted_domain_hex}","payload_hex":"{shifted_payload_hex}"}}"#
    ));
    assert!(
        resp_shift.contains("UNRECOGNIZED_HMAC_DOMAIN_DENIED"),
        "Shifted domain prefix must be rejected by closed allowlist: {resp_shift}"
    );

    // 7. `ACTIVE_SLOT_DOMAIN` over IPC must enforce REV2 monotonic CAS, lock serialization,
    //    and refuse initializing or re-opening sessions!
    let active_domain_hex = hex_encode(b"DOTAGENT_ACTIVE_SESSIONS_REGISTRY_V2");
    let encode_rev2_active = |rev: u64, open: &[&str]| -> String {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"REV2");
        buf.extend_from_slice(&rev.to_be_bytes());
        buf.extend_from_slice(&(open.len() as u32).to_be_bytes());
        for s in open {
            buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
            buf.extend_from_slice(s.as_bytes());
        }
        buf.extend_from_slice(&0u32.to_be_bytes());
        hex_encode(&buf)
    };
    let forged_active_hex = encode_rev2_active(2, &["swm_grunt_T1_a1_reopened99"]);
    let resp_uninit = send_rpc(&format!(
        r#"{{"op":"domain_hmac","domain_hex":"{active_domain_hex}","payload_hex":"{forged_active_hex}"}}"#
    ));
    assert!(
        resp_uninit.contains("UNINITIALIZED_ACTIVE_SESSIONS_DENIED"),
        "Initializing active_sessions over IPC must be blocked: {resp_uninit}"
    );

    let rev1_empty_hex = encode_rev2_active(1, &[]);
    let rev1_empty_bytes = decode_hex_for_test(&rev1_empty_hex);
    let rev1_empty_mac = compute_host_domain_mac(
        &[0x42u8; 32],
        b"DOTAGENT_ACTIVE_SESSIONS_REGISTRY_V2",
        &rev1_empty_bytes,
    );
    fs::write(
        swarm_dir.join("sessions").join("active_sessions.json"),
        format!(
            r#"{{"revision":1,"open_sessions":[],"hook_bindings":{{}},"record_mac":"{rev1_empty_mac}"}}"#
        ),
    )
    .expect("write rev1 empty active_sessions.json");
    let resp_reopen = send_rpc(&format!(
        r#"{{"op":"domain_hmac","domain_hex":"{active_domain_hex}","payload_hex":"{forged_active_hex}"}}"#
    ));
    assert!(
        resp_reopen.contains("ACTIVE_SESSION_ESCALATION_DENIED"),
        "Opening/re-opening session via IPC active_sessions must be blocked: {resp_reopen}"
    );

    // Stale CAS revision (rev=1 when disk is already rev=1 -> expected rev=2) must fail closed!
    let stale_rev_hex = encode_rev2_active(1, &[]);
    let resp_stale = send_rpc(&format!(
        r#"{{"op":"domain_hmac","domain_hex":"{active_domain_hex}","payload_hex":"{stale_rev_hex}"}}"#
    ));
    assert!(
        resp_stale.contains("STALE_ACTIVE_SESSIONS_CAS_CONFLICT"),
        "Stale active_sessions revision must be rejected by CAS check: {resp_stale}"
    );

    // Worker IPC attempting to delete/deactivate open sessions or overwrite/remove existing hook
    // bindings must fail closed with `ACTIVE_SESSION_DELETION_DENIED`!
    let encode_rev2_with_bindings =
        |rev: u64, open: &[&str], bindings: &[(&str, &str)]| -> String {
            let mut buf = Vec::new();
            buf.extend_from_slice(b"REV2");
            buf.extend_from_slice(&rev.to_be_bytes());
            buf.extend_from_slice(&(open.len() as u32).to_be_bytes());
            for s in open {
                buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
                buf.extend_from_slice(s.as_bytes());
            }
            buf.extend_from_slice(&(bindings.len() as u32).to_be_bytes());
            for (k, v) in bindings {
                buf.extend_from_slice(&(k.len() as u32).to_be_bytes());
                buf.extend_from_slice(k.as_bytes());
                buf.extend_from_slice(&(v.len() as u32).to_be_bytes());
                buf.extend_from_slice(v.as_bytes());
            }
            hex_encode(&buf)
        };
    let rev5_two_open_hex = encode_rev2_with_bindings(
        5,
        &["swm_grunt_T1_a1_open01", "swm_qa_T1_a1_open02"],
        &[("hook-uuid-1", "swm_grunt_T1_a1_open01")],
    );
    let rev5_two_open_bytes = decode_hex_for_test(&rev5_two_open_hex);
    let rev5_two_open_mac = compute_host_domain_mac(
        &[0x42u8; 32],
        b"DOTAGENT_ACTIVE_SESSIONS_REGISTRY_V2",
        &rev5_two_open_bytes,
    );
    fs::write(
        swarm_dir.join("sessions").join("active_sessions.json"),
        format!(
            r#"{{"revision":5,"open_sessions":["swm_grunt_T1_a1_open01","swm_qa_T1_a1_open02"],"hook_bindings":{{"hook-uuid-1":"swm_grunt_T1_a1_open01"}},"record_mac":"{rev5_two_open_mac}"}}"#
        ),
    )
    .expect("write rev5 active_sessions.json");

    let deactivate_payload_hex = encode_rev2_with_bindings(
        6,
        &["swm_grunt_T1_a1_open01"],
        &[("hook-uuid-1", "swm_grunt_T1_a1_open01")],
    );
    let resp_deactivate = send_rpc(&format!(
        r#"{{"op":"domain_hmac","domain_hex":"{active_domain_hex}","payload_hex":"{deactivate_payload_hex}"}}"#
    ));
    assert!(
        resp_deactivate.contains("ACTIVE_SESSION_DELETION_DENIED"),
        "Worker IPC deactivating open session must be rejected: {resp_deactivate}"
    );

    let overwrite_binding_hex = encode_rev2_with_bindings(
        6,
        &["swm_grunt_T1_a1_open01", "swm_qa_T1_a1_open02"],
        &[("hook-uuid-1", "swm_qa_T1_a1_open02")],
    );
    let resp_overwrite_bind = send_rpc(&format!(
        r#"{{"op":"domain_hmac","domain_hex":"{active_domain_hex}","payload_hex":"{overwrite_binding_hex}"}}"#
    ));
    assert!(
        resp_overwrite_bind.contains("ACTIVE_SESSION_DELETION_DENIED"),
        "Worker IPC overwriting existing hook binding must be rejected: {resp_overwrite_bind}"
    );

    // 8. Legacy pre-v2 unprefixed HMAC tag must fail closed with explicit LEGACY_HMAC_V1_STATE_INVALIDATED!
    let legacy_v1_mac = {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(&[0x42u8; 32]).expect("hmac");
        mac.update(b"DOTAGENT_SESSION_CAPABILITY_V1");
        mac.update(&(base_payload_bytes.len() as u64).to_be_bytes());
        mac.update(&base_payload_bytes);
        hex_encode(&mac.finalize().into_bytes())
    };
    let base_payload_hex = hex_encode(&base_payload_bytes);
    let resp_legacy = send_rpc(&format!(
        r#"{{"op":"verify_domain_hmac","domain_hex":"{cap_domain_hex}","payload_hex":"{base_payload_hex}","expected_mac_hex":"{legacy_v1_mac}"}}"#
    ));
    assert!(
        resp_legacy.contains("LEGACY_HMAC_V1_STATE_INVALIDATED"),
        "Legacy v1 unprefixed MAC must fail closed with LEGACY_HMAC_V1_STATE_INVALIDATED: {resp_legacy}"
    );

    let _ = daemon.kill();
    let _ = daemon.wait();
}

fn compute_host_domain_mac(key: &[u8; 32], domain: &[u8], payload: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    mac.update(&(domain.len() as u64).to_be_bytes());
    mac.update(domain);
    mac.update(&(payload.len() as u64).to_be_bytes());
    mac.update(payload);
    hex_encode(&mac.finalize().into_bytes())
}

fn compute_host_cap_mac(key: &[u8; 32], payload: &[u8]) -> String {
    compute_host_domain_mac(key, b"DOTAGENT_SESSION_CAPABILITY_V1", payload)
}

fn decode_hex_for_test(hex: &str) -> Vec<u8> {
    agent_guard::crypto::hex_decode_bytes(hex).expect("valid hex")
}

fn encode_raw_cap_hex(
    sid: &str,
    role: &str,
    task_id: &str,
    write_paths: &[&str],
    failures: u32,
) -> String {
    let mut payload = Vec::new();
    let push_str = |buf: &mut Vec<u8>, s: &str| {
        buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
        buf.extend_from_slice(s.as_bytes());
    };
    let push_vec = |buf: &mut Vec<u8>, items: &[&str]| {
        buf.extend_from_slice(&(items.len() as u32).to_be_bytes());
        for item in items {
            buf.extend_from_slice(&(item.len() as u32).to_be_bytes());
            buf.extend_from_slice(item.as_bytes());
        }
    };
    push_str(&mut payload, sid);
    push_str(&mut payload, role);
    push_str(&mut payload, task_id);
    payload.extend_from_slice(&1u32.to_be_bytes());
    push_str(&mut payload, &"aa".repeat(32));
    push_str(&mut payload, &"bb".repeat(32));
    push_vec(&mut payload, &["src/clean.rs"]);
    push_vec(&mut payload, write_paths);
    push_vec(&mut payload, &["ok"]);
    payload.push(0);
    payload.extend_from_slice(&failures.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes());
    hex_encode(&payload)
}

#[test]
fn wave1_exec_sandbox_drains_large_stdout_without_sigpipe_kill() {
    let (ws, home, _state) = create_isolated_workspace("w1_pipe");
    let guard_bin = PathBuf::from(env!("CARGO_BIN_EXE_agent-guard"));

    let out = Command::new(&guard_bin)
        .args(["exec-sandbox", "--sanitize-stream", "--", "seq 1 6000"])
        .env("HOME", &home)
        .current_dir(&ws)
        .output()
        .expect("spawn exec-sandbox seq 1 6000");
    assert!(
        out.status.success(),
        "noisy >24 KiB command in exec-sandbox must exit 0 cleanly: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("6000"),
        "tail must preserve final lines: {stdout}"
    );
}

#[test]
fn wave2_audit_shell_heredoc_alias_smuggling_and_sandbox_unwrap_regressions() {
    let (ws, home, state) = create_isolated_workspace("w2_audit");
    let guard_bin = PathBuf::from(env!("CARGO_BIN_EXE_agent-guard"));
    let hardened_gitcfg = workspace_root().join("dist").join("gitconfig.hardened");

    let run_pre_tool =
        |payload: &str, extra_env: &[(&str, &str)]| -> (i32, Option<JsonValue>, String) {
            let mut cmd = Command::new(&guard_bin);
            cmd.args(["pre-tool", "--json", payload])
                .env("HOME", &home)
                .env("AGENT_GUARD_STATE_DIR", &state)
                .env("GIT_CONFIG_GLOBAL", &hardened_gitcfg)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .current_dir(&ws);
            for (k, v) in extra_env {
                cmd.env(k, v);
            }
            let out = cmd.output().expect("spawn agent-guard pre-tool");
            let code = out.status.code().unwrap_or(-1);
            let stdout_str = String::from_utf8_lossy(&out.stdout);
            let parsed = if stdout_str.trim().is_empty() {
                None
            } else {
                Some(JsonValue::parse(&stdout_str).expect("parse hook JSON"))
            };
            let stderr_str = String::from_utf8_lossy(&out.stderr).into_owned();
            (code, parsed, stderr_str)
        };

    // 1. P0-2: `# agent-guard sanitize-stream` comment must NOT bypass exec-sandbox wrapping!
    let (code_cu, Some(comment_unwrap), _) = run_pre_tool(
        r#"{"session_id":"s_p02","tool_name":"Bash","tool_input":{"command":"ls # agent-guard sanitize-stream"}}"#,
        &[],
    ) else {
        panic!("expected JSON updatedInput on Bash allow");
    };
    assert_eq!(code_cu, 0);
    let hso = comment_unwrap.get("hookSpecificOutput").expect("hso");
    assert_eq!(
        hso.get("permissionDecision").and_then(JsonValue::as_str),
        Some("allow")
    );
    let wrapped_cmd = hso
        .get("updatedInput")
        .and_then(|u| u.get("command"))
        .and_then(JsonValue::as_str)
        .expect("updatedInput.command");
    assert!(
        wrapped_cmd.starts_with("agent-guard exec-sandbox --sanitize-stream -- "),
        "comment substring must still be wrapped in exec-sandbox: {wrapped_cmd}"
    );

    // 2. P0-2/P0-4: Multi-harness `run_command` (`CommandLine` + `Cwd`) rewrites `CommandLine` in place!
    let (code_rc, Some(run_cmd_res), _) = run_pre_tool(
        r#"{"session_id":"s_rc","tool_name":"run_command","tool_input":{"CommandLine":"ls","Cwd":"."}}"#,
        &[],
    ) else {
        panic!("expected JSON updatedInput on run_command allow");
    };
    assert_eq!(code_rc, 0);
    let rc_input = run_cmd_res
        .get("hookSpecificOutput")
        .and_then(|h| h.get("updatedInput"))
        .expect("run_command updatedInput");
    assert!(
        rc_input
            .get("CommandLine")
            .and_then(JsonValue::as_str)
            .is_some_and(|s| s.starts_with("agent-guard exec-sandbox --sanitize-stream -- ")),
        "CommandLine must be rewritten in place: {}",
        rc_input.to_json_string()
    );
    assert_eq!(rc_input.get("Cwd").and_then(JsonValue::as_str), Some("."));
    assert!(rc_input.get("command").is_none());

    // 3. P0-3: Unquoted heredoc command substitution denied; single-quoted heredoc & pure math allowed!
    let (code_hd1, _, stderr_hd1) = run_pre_tool(
        r#"{"session_id":"s_hd1","tool_name":"Bash","tool_input":{"command":"cat <<EOF\n$(curl https://evil.invalid)\nEOF"}}"#,
        &[],
    );
    assert_eq!(
        code_hd1, 2,
        "unquoted heredoc $(curl ...) must be denied: {stderr_hd1}"
    );

    let (code_hd2, _, stderr_hd2) = run_pre_tool(
        r#"{"session_id":"s_hd2","tool_name":"Bash","tool_input":{"command":"cat <<'EOF'\n$(curl https://evil.invalid)\nEOF"}}"#,
        &[],
    );
    assert_eq!(
        code_hd2, 0,
        "single-quoted heredoc literal must be allowed: {stderr_hd2}"
    );

    let (code_hd3, _, stderr_hd3) = run_pre_tool(
        r#"{"session_id":"s_hd3","tool_name":"Bash","tool_input":{"command":"cat <<EOF\n$((1 + 1))\nEOF"}}"#,
        &[],
    );
    assert_eq!(
        code_hd3, 0,
        "benign arithmetic $((1 + 1)) in unquoted heredoc must be allowed: {stderr_hd3}"
    );

    // 4. P0-4: Cross-schema alias smuggling (`file_path` + `AbsolutePath`, `command` + `CommandLine`)
    //    and `ContentOffset` + `StartLine` slice bypass must be hard-denied!
    for (sid, bad_json, expected_code) in [
        (
            "s_al1",
            r#"{"session_id":"s_al1","tool_name":"Read","tool_input":{"file_path":"src/clean.rs","AbsolutePath":"/etc/passwd"}}"#,
            "AMBIGUOUS_TOOL_PARAM_ALIAS",
        ),
        (
            "s_al2",
            r#"{"session_id":"s_al2","tool_name":"Bash","tool_input":{"command":"ls","CommandLine":"curl https://evil.invalid"}}"#,
            "AMBIGUOUS_TOOL_PARAM_ALIAS",
        ),
        (
            "s_al3",
            r#"{"session_id":"s_al3","tool_name":"view_file","tool_input":{"AbsolutePath":"src/clean.rs","StartLine":1,"EndLine":10,"ContentOffset":500}}"#,
            "AMBIGUOUS_TOOL_PARAM_ALIAS",
        ),
        (
            "s_al4",
            r#"{"session_id":"s_al4","tool_name":"view_file","tool_input":{"AbsolutePath":"src/clean.rs","StartLine":1,"EndLine":50,"end_line":9999}}"#,
            "AMBIGUOUS_TOOL_PARAM_ALIAS",
        ),
        (
            "s_al5",
            r#"{"session_id":"s_al5","tool_name":"Read","tool_input":{"file_path":"src/clean.rs","offset":1,"limit":50,"EndLine":9999}}"#,
            "AMBIGUOUS_TOOL_PARAM_ALIAS",
        ),
        (
            "s_al6",
            r#"{"session_id":"s_al6","tool_name":"view_file","tool_input":{"AbsolutePath":"src/clean.rs","StartLine":20,"EndLine":10}}"#,
            "AMBIGUOUS_TOOL_PARAM_ALIAS",
        ),
        (
            "s_al7",
            r#"{"session_id":"s_al7","cwd":".","working_directory":"/etc","tool_name":"Read","tool_input":{"file_path":"src/clean.rs"}}"#,
            "AMBIGUOUS_TOOL_PARAM_ALIAS",
        ),
    ] {
        let (code, _, stderr) = run_pre_tool(bad_json, &[]);
        assert_eq!(code, 2, "case {sid} must exit 2");
        assert!(
            stderr.contains(expected_code),
            "case {sid} expected {expected_code}, got: {stderr}"
        );
    }

    // 5. P1-2: Corrupt/unknown AGENT_GUARD_PROFILE in `exec-sandbox` must fail closed (exit 2)!
    let bad_prof = Command::new(&guard_bin)
        .args(["exec-sandbox", "--", "echo should_not_run"])
        .env("HOME", &home)
        .env("AGENT_GUARD_STATE_DIR", &state)
        .env("AGENT_GUARD_PROFILE", "bogus-corrupt-profile")
        .current_dir(&ws)
        .output()
        .expect("spawn exec-sandbox with bogus profile");
    assert_eq!(
        bad_prof.status.code(),
        Some(2),
        "exec-sandbox must fail closed on invalid profile: stderr={}",
        String::from_utf8_lossy(&bad_prof.stderr)
    );

    // 6. P2: Read-only profile (`research-readonly`) blocks mutating `mcp__susanbdev__*` tools while allowing `get_*`!
    let (code_ro_mut, _, stderr_ro_mut) = run_pre_tool(
        r#"{"session_id":"s_ro1","tool_name":"mcp__susanbdev__update_issue","tool_input":{"id":"1"}}"#,
        &[("AGENT_GUARD_PROFILE", "research-readonly")],
    );
    assert_eq!(code_ro_mut, 2);
    assert!(stderr_ro_mut.contains("PROFILE_WRITE_TOOLS_DISABLED"));

    let (code_ro_get, _, stderr_ro_get) = run_pre_tool(
        r#"{"session_id":"s_ro2","tool_name":"mcp__susanbdev__get_issue","tool_input":{"id":"1"}}"#,
        &[("AGENT_GUARD_PROFILE", "research-readonly")],
    );
    assert_eq!(
        code_ro_get, 0,
        "read-only get_issue must be allowed: {stderr_ro_get}"
    );

    // 7. Copilot review regressions:
    //    (a) >128 brace alternatives in Glob fails closed (`SHADOW_AUTHORITY_FILE_BLOCKED`) instead of truncating!
    let mut big_brace_items: Vec<String> = (0..130).map(|n| format!("safe{n}.txt")).collect();
    big_brace_items.push("AGENTS.md".to_string());
    let big_glob = format!("docs/{{{}}}", big_brace_items.join(","));
    let big_glob_json = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str("s_bg".to_string())),
        ("tool_name".to_string(), JsonValue::Str("Glob".to_string())),
        (
            "tool_input".to_string(),
            JsonValue::Object(vec![("pattern".to_string(), JsonValue::Str(big_glob))]),
        ),
    ])
    .to_json_string();
    let (code_bg, _, stderr_bg) = run_pre_tool(&big_glob_json, &[]);
    assert_eq!(code_bg, 2);
    assert!(
        stderr_bg.contains("SHADOW_AUTHORITY_FILE_BLOCKED"),
        "expected SHADOW_AUTHORITY_FILE_BLOCKED on >128 brace overflow, got: {stderr_bg}"
    );

    //    (b) Group/world-accessible `AGENT_GUARD_COORDINATOR_SOCK` parent directory fails closed!
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let open_sock_dir = state.join("open_ipc");
        fs::create_dir_all(&open_sock_dir).expect("mkdir open_ipc");
        fs::set_permissions(&open_sock_dir, fs::Permissions::from_mode(0o755))
            .expect("chmod 0755 open_ipc");
        let bad_coord = Command::new(&guard_bin)
            .args(["coordinator", "--repo"])
            .arg(&ws)
            .env("HOME", &home)
            .env("AGENT_GUARD_STATE_DIR", &state)
            .env(
                "AGENT_GUARD_COORDINATOR_SOCK",
                open_sock_dir.join("coord.sock"),
            )
            .output()
            .expect("spawn coordinator with 0755 socket parent");
        assert_eq!(bad_coord.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&bad_coord.stderr).contains("INVALID_COORDINATOR_SOCK"),
            "0755 socket parent must fail closed: {}",
            String::from_utf8_lossy(&bad_coord.stderr)
        );

        //    (c) `is_trusted_executable_file` rejects group-writable binaries and group-writable ancestor dirs!
        let _ = fs::set_permissions(
            workspace_root().join("target"),
            fs::Permissions::from_mode(0o755),
        );
        let _ = fs::set_permissions(
            workspace_root().join("target/tw"),
            fs::Permissions::from_mode(0o755),
        );
        let _ = fs::set_permissions(
            workspace_root().join("target/tw/w2_audit"),
            fs::Permissions::from_mode(0o755),
        );
        let _ = fs::set_permissions(&home, fs::Permissions::from_mode(0o700));
        let trusted_dir = home.join("bin_ok");
        fs::create_dir_all(&trusted_dir).expect("mkdir bin_ok");
        fs::set_permissions(&trusted_dir, fs::Permissions::from_mode(0o755))
            .expect("chmod 0755 bin_ok");
        let bin_file = trusted_dir.join("agent-guard");
        fs::write(&bin_file, b"#!/bin/sh\n").expect("write mock bin");
        fs::set_permissions(&bin_file, fs::Permissions::from_mode(0o555))
            .expect("chmod 0555 mock bin");
        assert!(
            agent_guard::coordinator::is_trusted_executable_file(&bin_file),
            "0555 binary in 0755/0700 ancestor chain must be trusted"
        );

        fs::set_permissions(&bin_file, fs::Permissions::from_mode(0o775))
            .expect("chmod 0775 mock bin");
        assert!(
            !agent_guard::coordinator::is_trusted_executable_file(&bin_file),
            "group-writable 0775 binary must be rejected"
        );
        fs::set_permissions(&bin_file, fs::Permissions::from_mode(0o555))
            .expect("restore 0555 mock bin");
        fs::set_permissions(&trusted_dir, fs::Permissions::from_mode(0o775))
            .expect("chmod 0775 parent dir");
        assert!(
            !agent_guard::coordinator::is_trusted_executable_file(&bin_file),
            "0555 binary inside group-writable 0775 ancestor directory must be rejected"
        );
    }
}
