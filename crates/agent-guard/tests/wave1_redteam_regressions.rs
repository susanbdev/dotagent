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

    let _ = daemon.kill();
    let _ = daemon.wait();
}

fn compute_host_cap_mac(key: &[u8; 32], payload: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let domain = b"DOTAGENT_SESSION_CAPABILITY_V1";
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    mac.update(domain);
    mac.update(&(payload.len() as u64).to_be_bytes());
    mac.update(payload);
    hex_encode(&mac.finalize().into_bytes())
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
