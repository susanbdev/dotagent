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
