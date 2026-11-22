#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use agent_guard::json::JsonValue;
use agent_guard::operator::{execute_deactivate, execute_workspace_only_deactivate};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn fresh_sandbox_dir(name: &str) -> PathBuf {
    let base = workspace_root().join("target").join("p4").join(name);
    if base.exists() {
        #[cfg(unix)]
        {
            let _ = Command::new("chmod")
                .args(["-R", "u+rwX"])
                .arg(&base)
                .status();
        }
        let _ = fs::remove_dir_all(&base);
    }
    fs::create_dir_all(&base).expect("create sandbox dir");
    base
}

#[cfg(unix)]
fn file_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::symlink_metadata(path)
        .expect("stat path")
        .permissions()
        .mode()
        & 0o777
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set_permissions");
}

fn stage_guard_binaries(bin_dir: &Path) {
    fs::create_dir_all(bin_dir).expect("create bin_dir");
    for (name, src) in [
        ("agent-guard", env!("CARGO_BIN_EXE_agent-guard")),
        ("dotagent", env!("CARGO_BIN_EXE_dotagent")),
        ("agent-guard-sh", env!("CARGO_BIN_EXE_agent-guard-sh")),
    ] {
        let dst = bin_dir.join(name);
        fs::copy(src, &dst).expect("copy binary");
        #[cfg(unix)]
        set_mode(&dst, 0o555);
    }
}

fn init_git_repo(repo: &Path, home: &Path) {
    fs::create_dir_all(repo).expect("create repo");
    let st = Command::new("git")
        .args(["init", "-q"])
        .arg(repo)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .expect("git init");
    assert!(st.success(), "git init failed");
}

fn run_dotagent(home: &Path, state_dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_dotagent"))
        .args(args)
        .env("HOME", home)
        .env("AGENT_GUARD_STATE_DIR", state_dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("ANTIGRAVITY_AGENT")
        .env_remove("CLAUDECODE")
        .env_remove("GEMINI_CLI")
        .env_remove("CURSOR_TRACE_ID")
        .env_remove("CODEX_SANDBOX")
        .output()
        .expect("spawn dotagent")
}

#[test]
fn scenario_01_fresh_install_and_activation_preserves_unrelated_files() {
    let sb = fresh_sandbox_dir("s01_fresh");
    let home = sb.join("home");
    let state_dir = sb.join("state");
    let bin_dir = home.join(".local/bin");
    let repo = sb.join("repo");
    fs::create_dir_all(&home).expect("mkdir home");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    stage_guard_binaries(&bin_dir);
    init_git_repo(&repo, &home);

    fs::create_dir_all(repo.join("src")).expect("mkdir src");
    fs::create_dir_all(repo.join(".claude")).expect("mkdir .claude");
    fs::write(repo.join("src/lib.rs"), "pub fn answer() -> u32 { 42 }\n").expect("write lib.rs");
    fs::write(repo.join(".claude/unrelated.txt"), "keep-me\n").expect("write unrelated");
    fs::write(home.join(".bashrc"), "# user bashrc\n").expect("write .bashrc");

    let root = workspace_root();
    let out = run_dotagent(
        &home,
        &state_dir,
        &[
            "activate",
            "--dotagent-root",
            &root.to_string_lossy(),
            "--workspace",
            &repo.to_string_lossy(),
            "--bin-dir",
            &bin_dir.to_string_lossy(),
        ],
    );
    assert!(
        out.status.success(),
        "fresh activate failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert_eq!(
        fs::read_to_string(repo.join("src/lib.rs")).expect("lib.rs"),
        "pub fn answer() -> u32 { 42 }\n"
    );
    assert_eq!(
        fs::read_to_string(repo.join(".claude/unrelated.txt")).expect("unrelated.txt"),
        "keep-me\n"
    );
    assert!(repo.join(".dotagent-manifest.json").is_file());
    assert!(repo.join(".agents/.dotagent-manifest.json").is_file());
    assert!(home.join(".gemini/.dotagent-manifest.json").is_file());

    let doc = run_dotagent(
        &home,
        &state_dir,
        &[
            "doctor",
            "--json",
            "--allow-degraded",
            "--bin-dir",
            &bin_dir.to_string_lossy(),
            &repo.to_string_lossy(),
        ],
    );
    assert!(
        doc.status.success(),
        "doctor failed: stdout={} stderr={}",
        String::from_utf8_lossy(&doc.stdout),
        String::from_utf8_lossy(&doc.stderr)
    );
    let dj = JsonValue::parse(&String::from_utf8_lossy(&doc.stdout)).expect("doctor json");
    assert_eq!(dj.get("healthy").and_then(JsonValue::as_bool), Some(true));
}

#[test]
fn scenario_02_repeated_activation_is_deterministic_and_preserves_original_backups() {
    let sb = fresh_sandbox_dir("s02_repeat");
    let home = sb.join("home");
    let state_dir = sb.join("state");
    let bin_dir = home.join(".local/bin");
    let repo = sb.join("repo");
    fs::create_dir_all(home.join(".gemini")).expect("mkdir .gemini");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    stage_guard_binaries(&bin_dir);
    init_git_repo(&repo, &home);

    fs::create_dir_all(repo.join(".claude")).expect("mkdir .claude");
    let orig_agents = "# Original Project Guide\n";
    let orig_claude = "{\n  \"theme\": \"nord\"\n}\n";
    let orig_gemini = "{\n  \"customPref\": true\n}\n";
    fs::write(repo.join("AGENTS.md"), orig_agents).expect("seed AGENTS.md");
    fs::write(repo.join(".claude/settings.json"), orig_claude).expect("seed claude");
    fs::write(home.join(".gemini/settings.json"), orig_gemini).expect("seed gemini");
    #[cfg(unix)]
    {
        set_mode(&repo.join("AGENTS.md"), 0o640);
        set_mode(&repo.join(".claude/settings.json"), 0o600);
        set_mode(&home.join(".gemini/settings.json"), 0o600);
    }

    let root = workspace_root();
    let mut snapshots = Vec::new();
    for round in 0..3 {
        let out = run_dotagent(
            &home,
            &state_dir,
            &[
                "activate",
                "--dotagent-root",
                &root.to_string_lossy(),
                "--workspace",
                &repo.to_string_lossy(),
                "--bin-dir",
                &bin_dir.to_string_lossy(),
            ],
        );
        assert!(
            out.status.success(),
            "round {round} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        snapshots.push((
            fs::read(repo.join(".claude/settings.json")).expect("read claude"),
            fs::read(repo.join(".cursor/hooks.json")).expect("read cursor"),
            fs::read(repo.join(".agents/hooks.json")).expect("read ag"),
            fs::read(repo.join(".dotagent-manifest.json")).expect("read manifest"),
        ));
    }
    assert_eq!(snapshots[0], snapshots[1]);
    assert_eq!(snapshots[1], snapshots[2]);

    assert_eq!(
        fs::read_to_string(repo.join("AGENTS.md.dotagent.bak")).expect("AGENTS bak"),
        orig_agents
    );
    assert_eq!(
        fs::read_to_string(repo.join(".claude/settings.json.dotagent.bak")).expect("claude bak"),
        orig_claude
    );
    assert_eq!(
        fs::read_to_string(home.join(".gemini/settings.json.dotagent.bak")).expect("gemini bak"),
        orig_gemini
    );
    #[cfg(unix)]
    {
        assert_eq!(file_mode(&repo.join("AGENTS.md.dotagent.bak")), 0o640);
        assert_eq!(
            file_mode(&repo.join(".claude/settings.json.dotagent.bak")),
            0o600
        );
    }
}

#[test]
fn scenario_03_sibling_hooks_preserved_across_reactivation_and_deactivation() {
    let sb = fresh_sandbox_dir("s03_siblings");
    let home = sb.join("home");
    let state_dir = sb.join("state");
    let bin_dir = home.join(".local/bin");
    let repo = sb.join("repo");
    fs::create_dir_all(home.join(".gemini")).expect("mkdir .gemini");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    stage_guard_binaries(&bin_dir);
    init_git_repo(&repo, &home);

    fs::create_dir_all(repo.join(".agents")).expect("mkdir .agents");
    fs::create_dir_all(repo.join(".claude")).expect("mkdir .claude");
    fs::create_dir_all(repo.join(".cursor")).expect("mkdir .cursor");

    fs::write(
        repo.join(".agents/hooks.json"),
        "{\n  \"team-linter\": {\n    \"Stop\": []\n  }\n}\n",
    )
    .expect("seed ag hooks");
    fs::write(
        repo.join(".claude/settings.json"),
        r#"{
  "theme": "gruvbox",
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "/usr/bin/true claude-sibling-1"
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/usr/bin/true claude-session-banner"
          }
        ]
      }
    ]
  }
}
"#,
    )
    .expect("seed claude hooks");
    fs::write(
        repo.join(".cursor/hooks.json"),
        r#"{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      {
        "command": "/usr/bin/true cursor-sibling-1"
      }
    ]
  }
}
"#,
    )
    .expect("seed cursor hooks");
    fs::write(
        home.join(".gemini/settings.json"),
        r#"{
  "uiTheme": "dark",
  "hooks": {
    "BeforeTool": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "name": "user-gemini-hook",
            "type": "command",
            "command": "/usr/bin/true gemini-sibling-1"
          }
        ]
      }
    ]
  }
}
"#,
    )
    .expect("seed gemini hooks");

    let root = workspace_root();
    let act1 = run_dotagent(
        &home,
        &state_dir,
        &[
            "activate",
            "--dotagent-root",
            &root.to_string_lossy(),
            "--workspace",
            &repo.to_string_lossy(),
            "--bin-dir",
            &bin_dir.to_string_lossy(),
        ],
    );
    assert!(
        act1.status.success(),
        "activate 1 failed: {}",
        String::from_utf8_lossy(&act1.stderr)
    );

    // Every adapter must validate as `configured.state == "valid"` with user sibling hooks present!
    for ad in ["antigravity", "claude", "cursor", "codex", "gemini"] {
        let st = run_dotagent(
            &home,
            &state_dir,
            &[
                "status",
                "--json",
                "--execution-mode",
                "local",
                "--adapter",
                ad,
                "--bin-dir",
                &bin_dir.to_string_lossy(),
                &repo.to_string_lossy(),
            ],
        );
        assert!(
            st.status.success(),
            "status {ad}: {}",
            String::from_utf8_lossy(&st.stderr)
        );
        let sj = JsonValue::parse(&String::from_utf8_lossy(&st.stdout)).expect("status json");
        assert_eq!(
            sj.get("configured")
                .and_then(|c| c.get("state"))
                .and_then(JsonValue::as_str),
            Some("valid"),
            "adapter {ad} invalid with sibling hooks: {}",
            String::from_utf8_lossy(&st.stdout)
        );
    }

    // Add a second sibling hook to Antigravity, Claude, and Cursor while keeping dotagent hooks intact,
    // then re-run `activate` and finally `execute_deactivate` -> BOTH sibling hooks must survive!
    let ag_cur = fs::read_to_string(repo.join(".agents/hooks.json")).expect("read ag");
    let mut ag_obj = JsonValue::parse(&ag_cur)
        .expect("parse ag")
        .as_object()
        .expect("obj")
        .to_vec();
    ag_obj.push((
        "second-team-hook".to_string(),
        JsonValue::parse("{\"PreToolUse\":[]}").expect("json"),
    ));
    #[cfg(unix)]
    set_mode(&repo.join(".agents/hooks.json"), 0o644);
    fs::write(
        repo.join(".agents/hooks.json"),
        format!("{}\n", JsonValue::Object(ag_obj).to_json_string()),
    )
    .expect("write ag with 2nd sibling");

    let cur_cursor = fs::read_to_string(repo.join(".cursor/hooks.json")).expect("read cursor");
    let updated_cursor = cur_cursor.replace(
        "\"/usr/bin/true cursor-sibling-1\"",
        "\"/usr/bin/true cursor-sibling-1\"\n      },\n      {\n        \"command\": \"/usr/bin/true cursor-sibling-2\"",
    );
    #[cfg(unix)]
    set_mode(&repo.join(".cursor/hooks.json"), 0o644);
    fs::write(repo.join(".cursor/hooks.json"), updated_cursor)
        .expect("write cursor with 2nd sibling");

    let act2 = run_dotagent(
        &home,
        &state_dir,
        &[
            "activate",
            "--dotagent-root",
            &root.to_string_lossy(),
            "--workspace",
            &repo.to_string_lossy(),
            "--bin-dir",
            &bin_dir.to_string_lossy(),
        ],
    );
    assert!(
        act2.status.success(),
        "activate 2 failed: {}",
        String::from_utf8_lossy(&act2.stderr)
    );

    execute_deactivate(&home, &repo, false).expect("deactivate preserving all sibling hooks");

    let ag_after = fs::read_to_string(repo.join(".agents/hooks.json")).expect("ag after");
    assert!(ag_after.contains("team-linter") && ag_after.contains("second-team-hook"));
    assert!(!ag_after.contains("dotagent-guard"));

    let cursor_after = fs::read_to_string(repo.join(".cursor/hooks.json")).expect("cursor after");
    assert!(
        cursor_after.contains("cursor-sibling-1") && cursor_after.contains("cursor-sibling-2"),
        "cursor_after={cursor_after}"
    );
    assert!(!cursor_after.contains("agent-guard"));

    let claude_after =
        fs::read_to_string(repo.join(".claude/settings.json")).expect("claude after");
    assert!(
        claude_after.contains("claude-sibling-1")
            && claude_after.contains("claude-session-banner")
            && claude_after.contains("gruvbox")
    );
    assert!(!claude_after.contains("agent-guard"));
}

#[test]
fn scenario_04_invalid_or_tampered_distribution_manifests_fail_closed() {
    let sb = fresh_sandbox_dir("s04_bad_manifest");
    let home = sb.join("home");
    let state_dir = sb.join("state");
    let bin_dir = sb.join("bin");
    let repo = sb.join("repo");
    fs::create_dir_all(&home).expect("mkdir home");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    stage_guard_binaries(&bin_dir);
    init_git_repo(&repo, &home);

    let root = workspace_root();
    let bad_bundle = sb.join("bad_bundle");
    let cp_st = Command::new("cp")
        .args(["-R"])
        .arg(root.join("dist"))
        .arg(root.join("dist-verify"))
        .arg(root.join("profiles"))
        .arg(root.join("skills"))
        .arg(root.join("AGENTS.md"))
        .output();
    drop(cp_st);
    fs::create_dir_all(&bad_bundle).expect("mkdir bad_bundle");
    for sub in ["dist", "dist-verify", "profiles", "skills"] {
        let st = Command::new("cp")
            .args(["-R"])
            .arg(root.join(sub))
            .arg(bad_bundle.join(sub))
            .status()
            .expect("cp dir");
        assert!(st.success());
    }
    fs::copy(root.join("AGENTS.md"), bad_bundle.join("AGENTS.md")).expect("cp AGENTS.md");

    // 4a: Tamper `dist/claude/settings.json` without updating `manifest.sha256`
    fs::write(
        bad_bundle.join("dist/claude/settings.json"),
        "{\"disableAllHooks\":true}\n",
    )
    .expect("tamper claude settings");
    let out_tamper = run_dotagent(
        &home,
        &state_dir,
        &[
            "activate",
            "--dotagent-root",
            &bad_bundle.to_string_lossy(),
            "--workspace",
            &repo.to_string_lossy(),
            "--bin-dir",
            &bin_dir.to_string_lossy(),
        ],
    );
    assert_eq!(out_tamper.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out_tamper.stderr).contains("bundle integrity mismatch"),
        "stderr={}",
        String::from_utf8_lossy(&out_tamper.stderr)
    );
    assert!(!repo.join("AGENTS.md").exists());
    assert!(!home.join(".gemini").exists());

    // 4b: Malformed / traversal line in `manifest.sha256`
    fs::write(
        bad_bundle.join("dist-verify/manifest.sha256"),
        "0000000000000000000000000000000000000000000000000000000000000000  ../evil\n",
    )
    .expect("write traversal manifest");
    let out_trav = run_dotagent(
        &home,
        &state_dir,
        &[
            "activate",
            "--dotagent-root",
            &bad_bundle.to_string_lossy(),
            "--workspace",
            &repo.to_string_lossy(),
            "--bin-dir",
            &bin_dir.to_string_lossy(),
        ],
    );
    assert_eq!(out_trav.status.code(), Some(2));
    assert!(!repo.join("AGENTS.md").exists());
}

#[test]
#[cfg(unix)]
fn scenario_05_symlinks_fifos_and_unexpected_filesystem_objects_rejected() {
    use std::os::unix::fs::symlink;

    let sb = fresh_sandbox_dir("s05_special_fs");
    let home = sb.join("home");
    let state_dir = sb.join("state");
    let bin_dir = sb.join("bin");
    fs::create_dir_all(&home).expect("mkdir home");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    stage_guard_binaries(&bin_dir);
    let root = workspace_root();

    // 5a: FIFO at `.claude/settings.json`
    let repo_fifo = sb.join("repo_fifo");
    init_git_repo(&repo_fifo, &home);
    fs::create_dir_all(repo_fifo.join(".claude")).expect("mkdir .claude");
    let mkfifo_st = Command::new("mkfifo")
        .arg(repo_fifo.join(".claude/settings.json"))
        .status()
        .expect("mkfifo");
    assert!(mkfifo_st.success());
    let out_fifo = run_dotagent(
        &home,
        &state_dir,
        &[
            "activate",
            "--dotagent-root",
            &root.to_string_lossy(),
            "--workspace",
            &repo_fifo.to_string_lossy(),
            "--bin-dir",
            &bin_dir.to_string_lossy(),
        ],
    );
    assert_eq!(out_fifo.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out_fifo.stderr).contains("non-regular"),
        "stderr={}",
        String::from_utf8_lossy(&out_fifo.stderr)
    );
    assert!(!repo_fifo.join(".dotagent-manifest.json").exists());

    // 5b: Regular file at directory path `.codex`
    let repo_file_at_dir = sb.join("repo_file_at_dir");
    init_git_repo(&repo_file_at_dir, &home);
    fs::write(repo_file_at_dir.join(".codex"), "not-a-dir\n").expect("write file at .codex");
    let out_fad = run_dotagent(
        &home,
        &state_dir,
        &[
            "activate",
            "--dotagent-root",
            &root.to_string_lossy(),
            "--workspace",
            &repo_file_at_dir.to_string_lossy(),
            "--bin-dir",
            &bin_dir.to_string_lossy(),
        ],
    );
    assert_eq!(out_fad.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out_fad.stderr).contains("non-directory"));

    // 5c: Symlinked `$HOME/.local/state/agent-guard`
    let home_sym = sb.join("home_sym");
    let decoy = sb.join("decoy_state");
    fs::create_dir_all(home_sym.join(".local/state")).expect("mkdir .local/state");
    fs::create_dir_all(&decoy).expect("mkdir decoy");
    set_mode(&decoy, 0o755);
    symlink(&decoy, home_sym.join(".local/state/agent-guard")).expect("symlink state");
    let repo_clean = sb.join("repo_clean");
    init_git_repo(&repo_clean, &home);
    let out_sym = run_dotagent(
        &home_sym,
        &state_dir,
        &[
            "activate",
            "--dotagent-root",
            &root.to_string_lossy(),
            "--workspace",
            &repo_clean.to_string_lossy(),
            "--bin-dir",
            &bin_dir.to_string_lossy(),
        ],
    );
    assert_eq!(out_sym.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out_sym.stderr).contains("symlinked"));
    assert_eq!(
        file_mode(&decoy),
        0o755,
        "symlink target permissions must not be mutated"
    );
}

#[test]
fn scenario_06_paths_with_spaces_apostrophes_and_special_characters() {
    let sb = fresh_sandbox_dir("s06_weird_paths");
    let weird = sb.join("dir with 'spaces' & (parens) [v1]");
    let home = weird.join("home dir");
    let state_dir = weird.join("state dir");
    let bin_dir = weird.join("bin 'dir'");
    let repo = weird.join("project 'repo'");
    fs::create_dir_all(&home).expect("mkdir home");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    stage_guard_binaries(&bin_dir);
    init_git_repo(&repo, &home);

    let root = workspace_root();
    let act = run_dotagent(
        &home,
        &state_dir,
        &[
            "activate",
            "--dotagent-root",
            &root.to_string_lossy(),
            "--workspace",
            &repo.to_string_lossy(),
            "--bin-dir",
            &bin_dir.to_string_lossy(),
        ],
    );
    assert!(
        act.status.success(),
        "activate weird path failed: {}",
        String::from_utf8_lossy(&act.stderr)
    );

    for ad in ["antigravity", "claude", "cursor", "codex", "gemini"] {
        let st = run_dotagent(
            &home,
            &state_dir,
            &[
                "status",
                "--json",
                "--execution-mode",
                "local",
                "--adapter",
                ad,
                "--bin-dir",
                &bin_dir.to_string_lossy(),
                &repo.to_string_lossy(),
            ],
        );
        assert!(st.status.success(), "status {ad} failed");
        let sj = JsonValue::parse(&String::from_utf8_lossy(&st.stdout)).expect("json");
        assert_eq!(
            sj.get("configured")
                .and_then(|c| c.get("state"))
                .and_then(JsonValue::as_str),
            Some("valid")
        );
    }

    execute_deactivate(&home, &repo, false).expect("deactivate weird path");
    assert!(!repo.join(".dotagent-manifest.json").exists());
    assert!(!repo.join(".agents/.dotagent-manifest.json").exists());
}

#[test]
fn scenario_07_interrupted_mid_bundle_install_rolls_back_cleanly() {
    let sb = fresh_sandbox_dir("s07_rollback");
    let home = sb.join("home");
    let state_dir = sb.join("state");
    let bin_dir = sb.join("bin");
    let repo = sb.join("repo");
    fs::create_dir_all(&home).expect("mkdir home");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    stage_guard_binaries(&bin_dir);
    init_git_repo(&repo, &home);

    let orig_agents = "# Keep My Exact Original AGENTS.md\n";
    let orig_claude = "{\n  \"theme\": \"dracula\"\n}\n";
    fs::create_dir_all(repo.join(".claude")).expect("mkdir .claude");
    fs::write(repo.join("AGENTS.md"), orig_agents).expect("seed AGENTS.md");
    fs::write(repo.join(".claude/settings.json"), orig_claude).expect("seed claude");
    #[cfg(unix)]
    set_mode(&repo.join("AGENTS.md"), 0o640);

    // Create ambiguous `.agent` + `_agent` customization dirs so `deploy_antigravity_workspace_plane`
    // fails AFTER all `.claude`, `.cursor`, `.codex`, `AGENTS.md`, and `.dotagent-manifest.json` writes!
    fs::create_dir_all(repo.join(".agent")).expect("mkdir .agent");
    fs::create_dir_all(repo.join("_agent")).expect("mkdir _agent");

    let root = workspace_root();
    let act = run_dotagent(
        &home,
        &state_dir,
        &[
            "activate",
            "--dotagent-root",
            &root.to_string_lossy(),
            "--workspace",
            &repo.to_string_lossy(),
            "--bin-dir",
            &bin_dir.to_string_lossy(),
        ],
    );
    assert_eq!(act.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&act.stderr).contains("ambiguous Antigravity"),
        "stderr={}",
        String::from_utf8_lossy(&act.stderr)
    );

    // RollbackJournal MUST have restored BOTH `repo` and `$HOME/.gemini` cleanly!
    assert_eq!(
        fs::read_to_string(repo.join("AGENTS.md")).expect("rolled back AGENTS.md"),
        orig_agents
    );
    #[cfg(unix)]
    assert_eq!(file_mode(&repo.join("AGENTS.md")), 0o640);
    assert_eq!(
        fs::read_to_string(repo.join(".claude/settings.json")).expect("rolled back claude"),
        orig_claude
    );
    assert!(!repo.join("AGENTS.md.dotagent.bak").exists());
    assert!(!repo.join(".claude/settings.json.dotagent.bak").exists());
    assert!(!repo.join(".dotagent-manifest.json").exists());
    assert!(!repo.join(".cursor").exists());
    assert!(!repo.join(".codex").exists());
    assert!(!home.join(".gemini").exists());
}

#[test]
fn scenario_08_external_modifications_produce_explicit_conflict_and_preserve_backups() {
    let sb = fresh_sandbox_dir("s08_ext_mod");
    let home = sb.join("home");
    let state_dir = sb.join("state");
    let bin_dir = sb.join("bin");
    let repo = sb.join("repo");
    fs::create_dir_all(&home).expect("mkdir home");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    stage_guard_binaries(&bin_dir);
    init_git_repo(&repo, &home);

    let orig_agents = "# Original User Notes\n";
    fs::write(repo.join("AGENTS.md"), orig_agents).expect("seed AGENTS.md");

    let root = workspace_root();
    let act = run_dotagent(
        &home,
        &state_dir,
        &[
            "activate",
            "--dotagent-root",
            &root.to_string_lossy(),
            "--workspace",
            &repo.to_string_lossy(),
            "--bin-dir",
            &bin_dir.to_string_lossy(),
        ],
    );
    assert!(act.status.success());

    // 8a: External modification to `AGENTS.md`
    let ext_edit = "# User Edited After Activation\n";
    #[cfg(unix)]
    set_mode(&repo.join("AGENTS.md"), 0o644);
    fs::write(repo.join("AGENTS.md"), ext_edit).expect("external edit");

    let react = run_dotagent(
        &home,
        &state_dir,
        &[
            "activate",
            "--dotagent-root",
            &root.to_string_lossy(),
            "--workspace",
            &repo.to_string_lossy(),
            "--bin-dir",
            &bin_dir.to_string_lossy(),
        ],
    );
    assert_eq!(react.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&react.stderr).contains("modified externally"));
    assert_eq!(
        fs::read_to_string(repo.join("AGENTS.md")).expect("ext edit untouched"),
        ext_edit
    );

    let deact_err = execute_deactivate(&home, &repo, false)
        .expect_err("deactivate must fail closed on external edit");
    assert!(deact_err.contains("modified externally"));
    assert_eq!(
        fs::read_to_string(repo.join("AGENTS.md")).expect("ext edit still untouched"),
        ext_edit
    );
    assert_eq!(
        fs::read_to_string(repo.join("AGENTS.md.dotagent.bak")).expect("backup preserved"),
        orig_agents
    );
    assert!(repo.join(".dotagent-manifest.json").is_file());

    // Restore `AGENTS.md` to deployed bytes, then tamper with managed `disableAllHooks` in `.claude/settings.json`
    fs::copy(root.join("dist/AGENTS.md"), repo.join("AGENTS.md")).expect("restore deployed");
    let claude_raw = fs::read_to_string(repo.join(".claude/settings.json")).expect("read claude");
    let tampered_claude =
        claude_raw.replace("\"disableAllHooks\": false", "\"disableAllHooks\": true");
    #[cfg(unix)]
    set_mode(&repo.join(".claude/settings.json"), 0o644);
    fs::write(repo.join(".claude/settings.json"), tampered_claude).expect("tamper claude");

    let deact_tamper = execute_workspace_only_deactivate(&repo, false)
        .expect_err("tampered security key in claude settings must conflict");
    assert!(deact_tamper.contains("disableAllHooks"));
    assert!(repo.join(".dotagent-manifest.json").is_file());
}

#[test]
fn scenario_09_deactivation_restores_permissions_and_never_guesses_ownership() {
    let sb = fresh_sandbox_dir("s09_deact_ownership");
    let home = sb.join("home");
    let state_dir = sb.join("state");
    let bin_dir = sb.join("bin");
    let unactivated = sb.join("unactivated");
    fs::create_dir_all(&home).expect("mkdir home");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    stage_guard_binaries(&bin_dir);
    init_git_repo(&unactivated, &home);

    // 9a: Unactivated workspace with user-authored `0444` files at managed paths -> ZERO deletions!
    fs::create_dir_all(unactivated.join(".claude/agents")).expect("mkdir .claude/agents");
    let user_ro_agents = "# User-owned read-only AGENTS.md\n";
    let user_ro_sub = "# User-owned 0444 subagent\n";
    fs::write(unactivated.join("AGENTS.md"), user_ro_agents).expect("write user AGENTS.md");
    fs::write(
        unactivated.join(".claude/agents/research-airlock.md"),
        user_ro_sub,
    )
    .expect("write user subagent");
    #[cfg(unix)]
    {
        set_mode(&unactivated.join("AGENTS.md"), 0o444);
        set_mode(
            &unactivated.join(".claude/agents/research-airlock.md"),
            0o444,
        );
    }

    execute_deactivate(&home, &unactivated, false).expect("deactivate unactivated ws");
    assert_eq!(
        fs::read_to_string(unactivated.join("AGENTS.md")).expect("user 0444 AGENTS.md intact"),
        user_ro_agents
    );
    assert_eq!(
        fs::read_to_string(unactivated.join(".claude/agents/research-airlock.md"))
            .expect("user 0444 subagent intact"),
        user_ro_sub
    );

    // 9b: Orphaned `.dotagent.bak` without provenance manifest -> fail closed!
    #[cfg(unix)]
    set_mode(&unactivated.join("AGENTS.md"), 0o644);
    fs::write(unactivated.join("AGENTS.md.dotagent.bak"), "orphan\n").expect("write orphan bak");
    let orphan_err = execute_workspace_only_deactivate(&unactivated, false)
        .expect_err("orphaned backup without manifest must fail closed");
    assert!(orphan_err.contains("without provenance manifest"));
    fs::remove_file(unactivated.join("AGENTS.md.dotagent.bak")).expect("rm orphan bak");
    #[cfg(unix)]
    set_mode(&unactivated.join("AGENTS.md"), 0o640);

    // 9c: Activate on top, then `execute_deactivate` -> exact bytes & `0640` permissions restored,
    //     and newly created `$HOME/.gemini` files removed!
    let root = workspace_root();
    let act = run_dotagent(
        &home,
        &state_dir,
        &[
            "activate",
            "--dotagent-root",
            &root.to_string_lossy(),
            "--workspace",
            &unactivated.to_string_lossy(),
            "--bin-dir",
            &bin_dir.to_string_lossy(),
        ],
    );
    assert!(
        act.status.success(),
        "activate failed: {}",
        String::from_utf8_lossy(&act.stderr)
    );
    assert!(home.join(".gemini/GEMINI.md").is_file());

    execute_deactivate(&home, &unactivated, false).expect("full deactivate");
    assert_eq!(
        fs::read_to_string(unactivated.join("AGENTS.md")).expect("restored AGENTS.md"),
        user_ro_agents
    );
    #[cfg(unix)]
    {
        assert_eq!(file_mode(&unactivated.join("AGENTS.md")), 0o640);
        assert_eq!(
            file_mode(&unactivated.join(".claude/agents/research-airlock.md")),
            0o444
        );
    }
    assert!(!home.join(".gemini/GEMINI.md").exists());
    assert!(!home.join(".gemini/settings.json").exists());
    assert!(!home.join(".gemini").exists());
}

#[test]
#[cfg(unix)]
fn scenario_10_verified_prebuilt_and_sealed_release_bundle_activation() {
    let sb = fresh_sandbox_dir("s10_prebuilt");
    let home = sb.join("home");
    let state_dir = sb.join("state");
    let prebuilt = sb.join("prebuilt");
    let prebuilt_bin = prebuilt.join("bin");
    let repo = sb.join("repo");
    fs::create_dir_all(&home).expect("mkdir home");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    fs::create_dir_all(&prebuilt_bin).expect("mkdir prebuilt/bin");
    init_git_repo(&repo, &home);

    let root = workspace_root();
    // Stage all 6 binaries in `prebuilt/bin/` and generate `SHA256SUMS`
    let guard_src = PathBuf::from(env!("CARGO_BIN_EXE_agent-guard"));
    let dotagent_src = PathBuf::from(env!("CARGO_BIN_EXE_dotagent"));
    let sh_src = PathBuf::from(env!("CARGO_BIN_EXE_agent-guard-sh"));
    let bin_parent = guard_src.parent().expect("bin parent");
    let compiler_src = if bin_parent.join("dotagent-compiler").is_file() {
        bin_parent.join("dotagent-compiler")
    } else {
        let ctgt = sb.join("compiler_tgt");
        let st = Command::new("cargo")
            .args([
                "build",
                "--locked",
                "--manifest-path",
                &root.join("Cargo.toml").to_string_lossy(),
                "-p",
                "dotagent-compiler",
                "--bin",
                "dotagent-compiler",
                "--target-dir",
                &ctgt.to_string_lossy(),
            ])
            .status()
            .expect("build dotagent-compiler");
        assert!(st.success(), "failed building dotagent-compiler");
        ctgt.join("debug/dotagent-compiler")
    };
    for (name, src) in [
        ("dotagent", &dotagent_src),
        ("agent-guard", &guard_src),
        ("agent-guard-sh", &sh_src),
        ("dotagent-compiler", &compiler_src),
        ("swarm-tool", &dotagent_src),
        ("dotagent-harness", &dotagent_src),
    ] {
        fs::copy(src, prebuilt_bin.join(name)).expect("copy prebuilt bin");
        set_mode(&prebuilt_bin.join(name), 0o755);
    }
    let bad_sums = sb.join("BAD_SUMS");
    fs::write(
        &bad_sums,
        "0000000000000000000000000000000000000000000000000000000000000000  bin/agent-guard\n",
    )
    .expect("write bad sums");
    let bad_out = Command::new("bash")
        .arg(root.join("scripts/activate-local.sh"))
        .arg(&repo)
        .arg("--from-prebuilt")
        .arg(&prebuilt)
        .arg("--prebuilt-sums")
        .arg(&bad_sums)
        .env("HOME", &home)
        .env("AGENT_GUARD_STATE_DIR", &state_dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("run activate-local.sh bad sums");
    assert_eq!(bad_out.status.code(), Some(2));
    assert!(!home.join(".local/bin/agent-guard").exists());

    let sums_path = sb.join("SHA256SUMS");
    let mut sums_body = String::new();
    for name in [
        "dotagent",
        "agent-guard",
        "agent-guard-sh",
        "dotagent-compiler",
        "swarm-tool",
        "dotagent-harness",
    ] {
        let bytes = fs::read(prebuilt_bin.join(name)).expect("read bin");
        let digest = agent_guard::crypto::sha256_hex(&bytes);
        sums_body.push_str(&format!("{digest}  bin/{name}\n"));
    }
    fs::write(&sums_path, &sums_body).expect("write SHA256SUMS");
    let ok_out = Command::new("bash")
        .arg(root.join("scripts/activate-local.sh"))
        .arg(&repo)
        .arg("--from-prebuilt")
        .arg(&prebuilt)
        .arg("--prebuilt-sums")
        .arg(&sums_path)
        .env("HOME", &home)
        .env("AGENT_GUARD_STATE_DIR", &state_dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("run activate-local.sh --from-prebuilt");
    assert!(
        ok_out.status.success(),
        "activate-local.sh failed: stdout={} stderr={}",
        String::from_utf8_lossy(&ok_out.stdout),
        String::from_utf8_lossy(&ok_out.stderr)
    );
    for name in [
        "dotagent",
        "agent-guard",
        "agent-guard-sh",
        "dotagent-compiler",
        "swarm-tool",
        "dotagent-harness",
    ] {
        assert_eq!(file_mode(&home.join(".local/bin").join(name)), 0o555);
    }

    // Also verify activating a fresh repo from a `0555`-sealed release bundle layout (`install.sh` seal_tree)!
    let sealed_bundle = sb.join("sealed_share_dotagent");
    fs::create_dir_all(&sealed_bundle).expect("mkdir sealed_bundle");
    for sub in ["dist", "dist-verify", "profiles", "skills"] {
        let st = Command::new("cp")
            .args(["-R"])
            .arg(root.join(sub))
            .arg(sealed_bundle.join(sub))
            .status()
            .expect("cp bundle dir");
        assert!(st.success());
    }
    fs::copy(root.join("AGENTS.md"), sealed_bundle.join("AGENTS.md")).expect("cp AGENTS.md");
    assert!(
        Command::new("find")
            .arg(&sealed_bundle)
            .args(["-type", "f", "-exec", "chmod", "0444", "{}", "+"])
            .status()
            .expect("chmod 0444")
            .success()
    );
    assert!(
        Command::new("find")
            .arg(&sealed_bundle)
            .args(["-type", "d", "-exec", "chmod", "0555", "{}", "+"])
            .status()
            .expect("chmod 0555")
            .success()
    );

    let repo2 = sb.join("repo_from_sealed");
    init_git_repo(&repo2, &home);
    let sealed_act = run_dotagent(
        &home,
        &state_dir,
        &[
            "activate",
            "--dotagent-root",
            &sealed_bundle.to_string_lossy(),
            "--workspace",
            &repo2.to_string_lossy(),
            "--bin-dir",
            &home.join(".local/bin").to_string_lossy(),
        ],
    );
    assert!(
        sealed_act.status.success(),
        "activate from 0555 sealed release bundle failed: {}",
        String::from_utf8_lossy(&sealed_act.stderr)
    );
    assert!(repo2.join(".dotagent-manifest.json").is_file());
    assert!(!sealed_bundle.join(".claude").exists());
}

#[test]
fn scenario_11_binary_integrity_mismatch_and_missing_pin_fail_closed() {
    let sb = fresh_sandbox_dir("s11_bin_integrity");
    let home = sb.join("home");
    let state_dir = sb.join("state");
    let empty_bin = sb.join("empty_bin");
    let fake_bin = sb.join("fake_bin");
    let repo = sb.join("repo");
    fs::create_dir_all(&home).expect("mkdir home");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    fs::create_dir_all(&empty_bin).expect("mkdir empty_bin");
    fs::create_dir_all(&fake_bin).expect("mkdir fake_bin");
    init_git_repo(&repo, &home);
    let root = workspace_root();

    // 11a: Unpopulated `--bin-dir` MUST NOT silently fall back to `current_exe()`!
    let out_missing = run_dotagent(
        &home,
        &state_dir,
        &[
            "activate",
            "--dotagent-root",
            &root.to_string_lossy(),
            "--workspace",
            &repo.to_string_lossy(),
            "--bin-dir",
            &empty_bin.to_string_lossy(),
        ],
    );
    assert_eq!(out_missing.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out_missing.stderr)
            .contains("verified 'agent-guard' binary not found"),
        "stderr={}",
        String::from_utf8_lossy(&out_missing.stderr)
    );
    assert!(!repo.join("AGENTS.md").exists());

    // 11b: Shell script masquerading as `agent-guard` (`0555` executable, non-native binary format) -> rejected!
    let bogus = fake_bin.join("agent-guard");
    fs::write(&bogus, b"#!/bin/sh\nexit 0\n").expect("write bogus script");
    #[cfg(unix)]
    set_mode(&bogus, 0o555);

    let out_bogus = run_dotagent(
        &home,
        &state_dir,
        &[
            "activate",
            "--dotagent-root",
            &root.to_string_lossy(),
            "--workspace",
            &repo.to_string_lossy(),
            "--bin-dir",
            &fake_bin.to_string_lossy(),
        ],
    );
    assert_eq!(out_bogus.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out_bogus.stderr).contains("not a valid native executable"),
        "stderr={}",
        String::from_utf8_lossy(&out_bogus.stderr)
    );
    assert!(!repo.join("AGENTS.md").exists());
}
