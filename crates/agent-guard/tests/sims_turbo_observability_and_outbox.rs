#![forbid(unsafe_code)]

//! End-to-End Integration Verification for:
//! 1. Attested `ExecutionMode::SimsMicroVm` (`sims.guest_attestation.v1` `0444` regular-file &
//!    `uid 0` live-host verification, `RuntimeProfile::apply_sims_microvm_turbo` ergonomic ceilings).
//! 2. `agora` / `agora-mcp` stdio & tool prefix allowlisting (`mcp__agora__*`, `mcp__agora_mcp__*`,
//!    `mcp__agora-mcp__*`) while rejecting mutating calls without deputy approval and unvetted servers.
//! 3. Lazy-warmed `hook.sock` daemon (`should_auto_warm_hook_daemon` preserving cold CLI isolation
//!    on unactivated workspaces, detached background warmup on activated workspaces, warm RPC routing,
//!    and clean socket-unlink shutdown).
//! 4. W3C `trace_id` / `span_id` propagation, per-stage nanosecond spans (`duration_ns`,
//!    `ast_eval_ns`, `path_policy_ns`, `coord_ipc_ns`), and OTLP `dotagent.guard.decision.duration_ns`
//!    histogram export (`bucketCounts`, `explicitBounds`, `p50_ns`, `p95_ns`, `p99_ns`).
//! 5. Out-of-band feedback ballot staging on `dotagent on-stop` and `dotagent feedback export-outbox`
//!    atomic file export + zero-token loopback `tl-proxy` forwarding (`SELF_TAMPERING_BLOCKED` &
//!    `FEEDBACK_OPERATOR_ONLY` enforcement for agents).

#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use agent_guard::budget_guard::{
    SIMS_MICROVM_MAX_DIRECT_DISCOVERY_CALLS, SIMS_MICROVM_MAX_RAW_FILE_BYTES,
    SIMS_MICROVM_MAX_SLICE_LINES, SIMS_MICROVM_MAX_TURN_TOKENS, load_active_profile,
};
use agent_guard::coordinator::connect_unix_short_path;
use agent_guard::enforcement_state::{
    ExecutionMode, detect_execution_mode, verify_sims_guest_attestation_file,
};
use agent_guard::feedback_loop::FEEDBACK_OUTBOX_SCHEMA_V1;
use agent_guard::json::JsonValue;
use agent_guard::mcp_policy::validate_mcp_server_command;
use agent_guard::telemetry::{analyze_audit_jsonl_str, render_otlp_export_json};

struct IsolatedWorkspace {
    root: PathBuf,
    home: PathBuf,
    state: PathBuf,
    repo: PathBuf,
}

impl IsolatedWorkspace {
    fn create(prefix: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(1);
        let ws_root = fs::canonicalize(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(Path::parent)
                .expect("workspace root"),
        )
        .expect("canonicalize workspace root");
        let target_dir = ws_root.join("target").join("test-workspaces");
        fs::create_dir_all(&target_dir).expect("mkdir target/test-workspaces");
        let _ = fs::set_permissions(&target_dir, fs::Permissions::from_mode(0o755));
        let root = target_dir.join(format!(
            "{prefix}_{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        let home = root.join("home");
        let state = root.join("state");
        let repo = root.join("repo");
        fs::create_dir_all(&home).expect("mkdir home");
        fs::create_dir_all(&state).expect("mkdir state");
        fs::create_dir_all(repo.join("src")).expect("mkdir src");
        fs::create_dir_all(repo.join("profiles")).expect("mkdir profiles");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("chmod 0700 root");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("chmod 0700 home");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("chmod 0700 state");

        let init_st = Command::new("git")
            .current_dir(&repo)
            .args(["init", "-q", "-b", "main"])
            .status()
            .expect("git init");
        assert!(init_st.success());

        fs::copy(
            ws_root.join("dist/gitconfig.hardened"),
            home.join(".gitconfig"),
        )
        .expect("copy gitconfig.hardened");
        for prof in ["coding-agent.toml", "research-readonly.toml"] {
            fs::copy(
                ws_root.join("profiles").join(prof),
                repo.join("profiles").join(prof),
            )
            .expect("copy profile");
        }

        let agents_md = repo.join("AGENTS.md");
        fs::write(&agents_md, "# Canonical Root Authority\n").expect("write AGENTS.md");
        fs::set_permissions(&agents_md, fs::Permissions::from_mode(0o444))
            .expect("chmod 0444 AGENTS.md");
        fs::write(
            repo.join("src/lib.rs"),
            "pub fn compute_slot(v: u64) -> u64 {\n    v + 1\n}\n",
        )
        .expect("write src/lib.rs");
        Self {
            root,
            home,
            state,
            repo,
        }
    }

    fn run_clean_cmd(
        &self,
        bin: &Path,
        args: &[&str],
        stdin_body: Option<&str>,
        extra_env: &[(&str, &str)],
    ) -> Output {
        let mut cmd = Command::new(bin);
        cmd.args(args)
            .current_dir(&self.repo)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", &self.home)
            .env("AGENT_GUARD_STATE_DIR", &self.state)
            .stdin(if stdin_body.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for &(k, v) in extra_env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("spawn subprocess");
        if let Some(body) = stdin_body
            && let Some(mut sin) = child.stdin.take()
        {
            sin.write_all(body.as_bytes()).expect("write stdin");
        }
        child.wait_with_output().expect("wait subprocess")
    }
}

impl Drop for IsolatedWorkspace {
    fn drop(&mut self) {
        let daemon_dir = self.state.join("daemon");
        let _ = fs::remove_file(daemon_dir.join("auto_warm.enabled"));
        let _ = fs::remove_file(daemon_dir.join("hook.sock"));
        let _ = fs::set_permissions(
            self.repo.join("AGENTS.md"),
            fs::Permissions::from_mode(0o644),
        );
        thread::sleep(Duration::from_millis(30));
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn agent_guard_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-guard"))
}

fn dotagent_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dotagent"))
}

fn extract_denial_id(text: &str) -> Option<String> {
    let marker = "[denial_id: ";
    let start = text.find(marker)? + marker.len();
    let rest = &text[start..];
    let end = rest.find(']')?;
    Some(rest[..end].trim().to_string())
}

#[test]
fn sims_microvm_attestation_and_agora_mcp_policy_end_to_end() {
    let ws = IsolatedWorkspace::create("sims_agora_e2e");
    let att_dir = ws.root.join("attestation");
    fs::create_dir_all(&att_dir).expect("mkdir attestation");

    let valid_doc = r#"{"schema":"sims.guest_attestation.v1","mountless":true,"zero_nic":true,"egress_mode":"vsock_trustless_only"}"#;
    let att_ok = att_dir.join("guest-attestation.json");
    fs::write(&att_ok, valid_doc).expect("write att_ok");
    fs::set_permissions(&att_ok, fs::Permissions::from_mode(0o444)).expect("chmod 0444");

    assert!(verify_sims_guest_attestation_file(&att_ok, false));
    // Live-host check (`require_root_owner = true`) rejects non-root files so unprivileged guests cannot forge Turbo Mode.
    if unsafe_free_geteuid_is_nonroot(&att_ok) {
        assert!(!verify_sims_guest_attestation_file(&att_ok, true));
    }

    let att_sym = att_dir.join("sym.json");
    symlink(&att_ok, &att_sym).expect("symlink");
    assert!(!verify_sims_guest_attestation_file(&att_sym, false));

    let att_writable = att_dir.join("writable.json");
    fs::write(&att_writable, valid_doc).expect("write writable");
    fs::set_permissions(&att_writable, fs::Permissions::from_mode(0o644)).expect("chmod 0644");
    assert!(!verify_sims_guest_attestation_file(&att_writable, false));

    let mode = detect_execution_mode(Some("sims-microvm")).expect("sims-microvm mode");
    assert_eq!(mode, ExecutionMode::SimsMicroVm);
    assert!(mode.supports_local_observer_verification());

    let mut prof = load_active_profile(&ws.repo).expect("load active profile");
    prof.apply_sims_microvm_turbo();
    assert_eq!(prof.max_slice_lines, SIMS_MICROVM_MAX_SLICE_LINES);
    assert_eq!(prof.max_raw_file_bytes, SIMS_MICROVM_MAX_RAW_FILE_BYTES);
    assert_eq!(prof.max_turn_tokens, SIMS_MICROVM_MAX_TURN_TOKENS);
    assert_eq!(
        prof.max_direct_discovery_calls,
        SIMS_MICROVM_MAX_DIRECT_DISCOVERY_CALLS
    );

    assert!(
        validate_mcp_server_command(
            "agora",
            "agora",
            &["serve".to_string(), "--stdio".to_string()],
        )
        .is_ok()
    );
    assert!(
        validate_mcp_server_command(
            "rogue",
            "agora",
            &["serve".to_string(), "--stdio".to_string()],
        )
        .is_err()
    );

    let guard = agent_guard_bin();
    for tool in [
        "mcp__agora__agora_search",
        "mcp__agora_mcp__agora_get_thread",
        "mcp__agora-mcp__agora_status",
    ] {
        let payload = format!(
            r#"{{"session_id":"s_agora_ok","tool_name":"{tool}","tool_input":{{"query":"spec"}}}}"#
        );
        let out = ws.run_clean_cmd(&guard, &["pre-tool"], Some(&payload), &[]);
        assert!(
            out.status.success(),
            "expected allow for {tool}, stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // Read-only agora tool allowed under `research-readonly`, whereas mutating agora tool is blocked
    let ro_airlock = ws.run_clean_cmd(
        &guard,
        &["pre-tool"],
        Some(r#"{"session_id":"s_agora_ro","tool_name":"mcp__agora__agora_search","tool_input":{"query":"hi"}}"#),
        &[("AGENT_GUARD_PROFILE", "research-readonly")],
    );
    assert!(ro_airlock.status.success());

    let mutating_out = ws.run_clean_cmd(
        &guard,
        &["pre-tool"],
        Some(r#"{"session_id":"s_agora_mut","tool_name":"mcp__agora__agora_post_message","tool_input":{"body":"hi"}}"#),
        &[("AGENT_GUARD_PROFILE", "research-readonly")],
    );
    assert_eq!(mutating_out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&mutating_out.stderr).contains("PROFILE_WRITE_TOOLS_DISABLED"));

    // Unvetted MCP server prefix must be hard-blocked
    let rogue_out = ws.run_clean_cmd(
        &guard,
        &["pre-tool"],
        Some(r#"{"session_id":"s_agora_rogue","tool_name":"mcp__rogue__agora_search","tool_input":{"query":"x"}}"#),
        &[],
    );
    assert_eq!(rogue_out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&rogue_out.stderr).contains("UNVETTED_MCP_SERVER_BLOCKED"),
        "expected UNVETTED_MCP_SERVER_BLOCKED, got: {}",
        String::from_utf8_lossy(&rogue_out.stderr)
    );

    let _ = fs::set_permissions(&att_ok, fs::Permissions::from_mode(0o644));
}

fn unsafe_free_geteuid_is_nonroot(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    fs::symlink_metadata(path).is_ok_and(|m| m.uid() != 0)
}

#[test]
fn auto_warm_hook_daemon_cold_cli_isolation_and_w3c_otlp_histogram() {
    let ws = IsolatedWorkspace::create("warm_coord_otlp");
    let guard = agent_guard_bin();

    // 1. Cold unactivated workspace: `pre-tool` must NOT spawn `hook-daemon` or create `daemon/`.
    let cold_payload = r#"{"session_id":"s_cold_1","tool_name":"Read","tool_input":{"file_path":"src/lib.rs","offset":1,"limit":10}}"#;
    let cold_out = ws.run_clean_cmd(&guard, &["pre-tool"], Some(cold_payload), &[]);
    assert!(cold_out.status.success());
    assert!(
        !ws.state.join("daemon").exists(),
        "cold unactivated pre-tool must preserve cold_cli_isolation (no daemon/ created)"
    );

    // 2. Activated workspace (`.claude/settings.json` present): lazy detached spawn brings up `hook.sock` + collector.
    fs::create_dir_all(ws.repo.join(".claude")).expect("mkdir .claude");
    fs::write(ws.repo.join(".claude/settings.json"), "{}\n").expect("write settings.json");

    let first_warm = ws.run_clean_cmd(
        &guard,
        &["pre-tool"],
        Some(r#"{"session_id":"s_warm_0","tool_name":"Read","tool_input":{"file_path":"src/lib.rs","offset":1,"limit":10}}"#),
        &[],
    );
    assert!(first_warm.status.success());
    assert!(ws.state.join("daemon/auto_warm.enabled").exists());

    let sock_path = ws.state.join("daemon/hook.sock");
    let obs_route = ws.state.join("observations/route");
    let obs_health = ws.state.join("observations/health");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut ready = false;
    while Instant::now() < deadline {
        let route_ready = fs::symlink_metadata(&obs_route).is_ok_and(|m| m.len() == 48);
        let health_ready = fs::read_to_string(&obs_health)
            .ok()
            .and_then(|s| JsonValue::parse(&s).ok())
            .and_then(|j| j.get("collector_pid").and_then(JsonValue::as_u64))
            .is_some_and(|pid| pid != 0);
        if route_ready
            && health_ready
            && let Ok(mut s) = connect_unix_short_path(&sock_path)
        {
            let _ = s.write_all(b"{\"op\":\"ping\"}\n");
            let mut line = String::new();
            if BufReader::new(s).read_line(&mut line).is_ok() && line.contains("\"ok\":true") {
                ready = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        ready,
        "lazy-spawned hook-daemon + collector failed to become ready"
    );
    thread::sleep(Duration::from_millis(110));

    // 3. Subsequent hook evaluations route over warm `hook.sock` and record W3C trace/span + stage timings.
    let w3c_tid_allow = "4bf92f3577b34da6a3ce929d0e0e4736";
    let tp_allow = format!("00-{w3c_tid_allow}-00f067aa0ba902b7-01");
    let warm_allow = ws.run_clean_cmd(
        &guard,
        &["pre-tool"],
        Some(r#"{"session_id":"s_warm_1","tool_name":"Bash","tool_input":{"command":"rg --max-depth 2 compute_slot src"}}"#),
        &[("TRACEPARENT", &tp_allow)],
    );
    assert!(warm_allow.status.success());

    let w3c_tid_deny = "0123456789abcdef0123456789abcdef";
    let tp_deny = format!("00-{w3c_tid_deny}-fedcba9876543210-01");
    let warm_deny = ws.run_clean_cmd(
        &guard,
        &["pre-tool"],
        Some(r#"{"session_id":"s_warm_2","tool_name":"Bash","tool_input":{"command":"curl https://example.com"}}"#),
        &[("TRACEPARENT", &tp_deny)],
    );
    assert_eq!(warm_deny.status.code(), Some(2));

    // Wait for supervised observation store inside isolated `ws.state` to flush records.
    let store_file = ws.state.join(["audit", ".jsonl"].concat());
    let flush_deadline = Instant::now() + Duration::from_secs(3);
    let mut raw_log = String::new();
    while Instant::now() < flush_deadline {
        if let Ok(s) = fs::read_to_string(&store_file) {
            raw_log = s;
            if raw_log.contains("NETWORK_EXFILTRATION_BLOCKED")
                && raw_log.contains(w3c_tid_allow)
                && raw_log.contains(w3c_tid_deny)
            {
                break;
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    let health_dump = fs::read_to_string(&obs_health).unwrap_or_default();
    assert!(
        raw_log.contains("NETWORK_EXFILTRATION_BLOCKED")
            && raw_log.contains(w3c_tid_allow)
            && raw_log.contains(w3c_tid_deny),
        "expected warm daemon telemetry with propagated W3C trace_ids, health={health_dump}, got: {raw_log}"
    );
    assert!(
        raw_log.contains("\"coord_ipc_ns\":") && raw_log.contains("\"ast_eval_ns\":"),
        "expected coord_ipc_ns and ast_eval_ns spans in warm daemon telemetry: {raw_log}"
    );

    let summary = analyze_audit_jsonl_str(&raw_log, None);
    assert!(summary.decision_duration_count >= 2);
    assert!(summary.decision_duration_p50_ns.is_some());
    assert!(summary.decision_duration_p95_ns.is_some());
    assert!(summary.decision_duration_p99_ns.is_some());

    let otlp_str = render_otlp_export_json(&summary, 1_700_000_000_000_000_000).to_json_string();
    assert!(otlp_str.contains("dotagent.guard.decision.duration_ns"));
    assert!(otlp_str.contains("\"histogram\""));
    assert!(otlp_str.contains("\"bucketCounts\""));
    assert!(otlp_str.contains("\"explicitBounds\""));

    // 4. Unlinking `auto_warm.enabled` + `hook.sock` causes `hook-daemon` to exit cleanly.
    let _ = fs::remove_file(ws.state.join("daemon/auto_warm.enabled"));
    let _ = fs::remove_file(&sock_path);
    let stop_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < stop_deadline {
        if connect_unix_short_path(&sock_path).is_err() {
            break;
        }
        thread::sleep(Duration::from_millis(15));
    }
    assert!(connect_unix_short_path(&sock_path).is_err());
}

#[test]
fn on_stop_outbox_staging_and_export_outbox_loopback_forward_e2e() {
    let ws = IsolatedWorkspace::create("outbox_e2e");
    let guard = agent_guard_bin();
    let dotagent = dotagent_bin();

    // 1. Trigger a real kernel-grounded denial to obtain `[denial_id: dnl_<hex>]`.
    let deny_out = ws.run_clean_cmd(
        &guard,
        &["pre-tool"],
        Some(r#"{"session_id":"s_fb_1","tool_name":"Bash","tool_input":{"command":"curl https://example.com"}}"#),
        &[("DOTAGENT_NO_AUTO_COORD", "1")],
    );
    assert_eq!(deny_out.status.code(), Some(2));
    let stderr_s = String::from_utf8_lossy(&deny_out.stderr);
    let denial_id = extract_denial_id(&stderr_s).expect("extract denial_id from stderr");

    // 2. Agent submits friction ballot via `dotagent feedback submit` grounded to session `s_fb_1`.
    let sub_out = ws.run_clean_cmd(
        &dotagent,
        &[
            "feedback",
            "submit",
            "--denial-id",
            &denial_id,
            "--category",
            "false_positive_block",
            "--reason-code",
            "legitimate_test_workflow",
        ],
        None,
        &[
            ("DOTAGENT_NO_AUTO_COORD", "1"),
            ("AGENT_GUARD_SESSION_ID", "s_fb_1"),
        ],
    );
    assert!(
        sub_out.status.success(),
        "feedback submit failed: {}",
        String::from_utf8_lossy(&sub_out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&sub_out.stdout).contains("\"vote_counted\":true"),
        "expected grounded ballot vote_counted=true, got: {}",
        String::from_utf8_lossy(&sub_out.stdout)
    );

    // 3. Agents are hard-blocked from invoking `dotagent feedback export-outbox` both at PreToolUse
    //    (`SELF_TAMPERING_BLOCKED`) and inside agent harnesses (`FEEDBACK_OPERATOR_ONLY`).
    let agent_cmd_try = ws.run_clean_cmd(
        &guard,
        &["pre-tool"],
        Some(r#"{"session_id":"s_fb_1","tool_name":"Bash","tool_input":{"command":"dotagent feedback export-outbox --json"}}"#),
        &[("DOTAGENT_NO_AUTO_COORD", "1")],
    );
    assert_eq!(agent_cmd_try.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&agent_cmd_try.stderr).contains("SELF_TAMPERING_BLOCKED"));

    let harness_try = ws.run_clean_cmd(
        &dotagent,
        &["feedback", "export-outbox", "--json"],
        None,
        &[("CLAUDECODE", "1")],
    );
    assert_eq!(harness_try.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&harness_try.stderr).contains("FEEDBACK_OPERATOR_ONLY"));

    // 4. `dotagent on-stop` automatically stages a signed `dotagent.feedback_outbox.v1` file.
    let stop_out = ws.run_clean_cmd(
        &dotagent,
        &["on-stop"],
        None,
        &[("GITHUB_TOKEN", "ghp_dummy_token_must_not_be_needed_123456")],
    );
    assert!(
        stop_out.status.success(),
        "dotagent on-stop failed: {}",
        String::from_utf8_lossy(&stop_out.stderr)
    );
    let outbox_dir = ws.state.join("feedback/outbox");
    let staged_files: Vec<PathBuf> = fs::read_dir(&outbox_dir)
        .expect("read outbox dir")
        .filter_map(|e| e.ok().map(|d| d.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    assert_eq!(staged_files.len(), 1, "expected 1 staged outbox JSON file");
    let staged_json = JsonValue::parse(&fs::read_to_string(&staged_files[0]).expect("read staged"))
        .expect("parse staged JSON");
    assert_eq!(
        staged_json.get("schema").and_then(JsonValue::as_str),
        Some(FEEDBACK_OUTBOX_SCHEMA_V1)
    );
    assert_eq!(
        staged_json.get("ballot_count").and_then(JsonValue::as_u64),
        Some(1)
    );

    // 5. `dotagent feedback export-outbox --out ... --forward-url ... --json` exports atomically,
    //    forwards over loopback `tl-proxy` with `0` Authorization header, and marks ballots synced.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local_addr").port();
    let mock_proxy = thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let _ = sock.set_read_timeout(Some(Duration::from_secs(3)));
        let mut raw = Vec::with_capacity(8192);
        let mut chunk = [0u8; 4096];
        let mut expected_total: Option<usize> = None;
        loop {
            match sock.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&chunk[..n]);
                    if expected_total.is_none()
                        && let Some(hdr_end) = raw.windows(4).position(|w| w == b"\r\n\r\n")
                    {
                        let body_start = hdr_end + 4;
                        let hdr_str = String::from_utf8_lossy(&raw[..hdr_end]);
                        let content_len = hdr_str
                            .lines()
                            .find_map(|line| {
                                let (k, v) = line.split_once(':')?;
                                k.trim()
                                    .eq_ignore_ascii_case("content-length")
                                    .then(|| v.trim().parse::<usize>().ok())?
                            })
                            .unwrap_or(0);
                        expected_total = Some(body_start + content_len);
                    }
                    if let Some(total) = expected_total
                        && raw.len() >= total
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let req_s = String::from_utf8_lossy(&raw).into_owned();
        sock.write_all(
            b"HTTP/1.1 202 Accepted\r\nConnection: close\r\nContent-Length: 2\r\n\r\nOK",
        )
        .expect("write 202");
        let _ = sock.flush();
        let _ = sock.shutdown(std::net::Shutdown::Write);
        let _ = sock.read(&mut chunk);
        req_s
    });

    let exported_path = ws.root.join("exported_outbox.json");
    let forward_url = format!("http://127.0.0.1:{port}/v1/feedback/outbox");
    let export_out = ws.run_clean_cmd(
        &dotagent,
        &[
            "feedback",
            "export-outbox",
            "--out",
            exported_path.to_str().expect("utf8 path"),
            "--forward-url",
            &forward_url,
            "--json",
        ],
        None,
        &[("GITHUB_TOKEN", "ghp_secret_must_be_scrubbed_before_socket")],
    );
    assert!(
        export_out.status.success(),
        "export-outbox failed: {}",
        String::from_utf8_lossy(&export_out.stderr)
    );
    let wire_req = mock_proxy.join().expect("join mock tl-proxy");
    assert!(wire_req.starts_with("POST /v1/feedback/outbox HTTP/1.1\r\n"));
    assert!(wire_req.contains("X-Dotagent-Sig-Domain: dotagent:sync-sig:v2\r\n"));
    assert!(!wire_req.to_ascii_lowercase().contains("authorization:"));
    assert!(!wire_req.contains("ghp_secret_must_be_scrubbed_before_socket"));

    let resp_json = JsonValue::parse(
        std::str::from_utf8(&export_out.stdout)
            .expect("utf8 stdout")
            .trim(),
    )
    .expect("parse export-outbox --json");
    assert_eq!(resp_json.get("ok").and_then(JsonValue::as_bool), Some(true));
    assert_eq!(
        resp_json.get("ballot_count").and_then(JsonValue::as_u64),
        Some(1)
    );
    assert_eq!(
        resp_json
            .get("forward_http_status")
            .and_then(JsonValue::as_u64),
        Some(202)
    );
    assert!(exported_path.is_file());

    // Subsequent export-outbox reports 0 unsynced ballots because `--forward-url` marked it synced.
    let second_out = ws.run_clean_cmd(
        &dotagent,
        &["feedback", "export-outbox", "--json"],
        None,
        &[],
    );
    assert!(second_out.status.success());
    let second_json = JsonValue::parse(
        std::str::from_utf8(&second_out.stdout)
            .expect("utf8 stdout")
            .trim(),
    )
    .expect("parse second export-outbox --json");
    assert_eq!(
        second_json.get("ballot_count").and_then(JsonValue::as_u64),
        Some(0)
    );
}
