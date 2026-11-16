#![forbid(unsafe_code)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use agent_guard::cmd_policy::evaluate_shell_command;
use agent_guard::injection_scan::scan_untrusted_content;
use agent_guard::json::JsonValue;
use agent_guard::path_policy::{PathAccess, validate_path};
use agent_guard::unicode_guard::{ScanMode, scan_unicode};
use agent_guard::{Decision, handle_post_tool_hook, handle_pre_tool_hook, handle_user_prompt_hook};

fn test_sandbox_root(name: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let dir = workspace_root
        .join("target")
        .join("test-workspaces")
        .join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join(".git")).expect("create sandbox .git");
    fs::create_dir_all(dir.join(".state")).expect("create isolated state dir");
    dir
}

#[derive(Debug)]
struct CorpusVector {
    kind: String,
    payload: String,
}

fn load_bypass_corpus() -> Vec<CorpusVector> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let corpus_path = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("tests")
        .join("bypass_corpus.toml");
    let raw = fs::read_to_string(&corpus_path).expect("read tests/bypass_corpus.toml");

    let mut out = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('{') {
            continue;
        }
        let kind = extract_toml_string_field(trimmed, "kind").expect("kind field");
        let payload = extract_toml_string_field(trimmed, "payload").expect("payload field");
        out.push(CorpusVector { kind, payload });
    }
    out
}

fn extract_toml_string_field(line: &str, key: &str) -> Option<String> {
    let marker = format!("{key} = \"");
    let start = line.find(&marker)? + marker.len();
    let bytes = line.as_bytes();
    let mut i = start;
    let mut out = String::new();
    while i < bytes.len() {
        if bytes[i] == b'"' {
            return Some(out);
        }
        if bytes[i] == b'\\' {
            i += 1;
            let esc = *bytes.get(i)?;
            i += 1;
            match esc {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'u' => {
                    let hex = std::str::from_utf8(bytes.get(i..i + 4)?).ok()?;
                    let cp = u32::from_str_radix(hex, 16).ok()?;
                    out.push(char::from_u32(cp)?);
                    i += 4;
                }
                b'U' => {
                    let hex = std::str::from_utf8(bytes.get(i..i + 8)?).ok()?;
                    let cp = u32::from_str_radix(hex, 16).ok()?;
                    out.push(char::from_u32(cp)?);
                    i += 8;
                }
                other => {
                    out.push('\\');
                    out.push(other as char);
                }
            }
        } else {
            let tail = std::str::from_utf8(&bytes[i..]).ok()?;
            let ch = tail.chars().next()?;
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    None
}

#[test]
fn blocks_entire_250_plus_bypass_corpus_at_100_percent() {
    let repo = test_sandbox_root("corpus_sandbox");
    let vectors = load_bypass_corpus();
    assert_eq!(
        vectors.len(),
        290,
        "Expected exact 290 adversarial bypass vectors, got {}",
        vectors.len()
    );

    for (idx, vec_item) in vectors.iter().enumerate() {
        let blocked = match vec_item.kind.as_str() {
            "cmd" => evaluate_shell_command(&vec_item.payload, &repo, &repo, false).is_err(),
            "read_path" => {
                validate_path(&repo, &repo, &vec_item.payload, PathAccess::Read).is_err()
            }
            "write_path" => {
                validate_path(&repo, &repo, &vec_item.payload, PathAccess::Write).is_err()
            }
            "glob" => {
                let hook = JsonValue::Object(vec![
                    (
                        "session_id".to_string(),
                        JsonValue::Str(format!("glob_{idx}")),
                    ),
                    (
                        "cwd".to_string(),
                        JsonValue::Str(repo.to_string_lossy().into_owned()),
                    ),
                    ("tool_name".to_string(), JsonValue::Str("Glob".to_string())),
                    (
                        "tool_input".to_string(),
                        JsonValue::Object(vec![(
                            "pattern".to_string(),
                            JsonValue::Str(vec_item.payload.clone()),
                        )]),
                    ),
                ]);
                !handle_pre_tool_hook(&hook.to_json_string(), &repo).is_allow()
            }
            "content" => {
                let uni_bad =
                    !scan_unicode(&vec_item.payload, ScanMode::UntrustedContent).is_empty();
                let inj_bad = scan_untrusted_content(&vec_item.payload, &repo, &repo, false)
                    .first_halt()
                    .is_some();
                uni_bad || inj_bad
            }
            other => panic!("unknown corpus kind '{other}'"),
        };

        assert!(
            blocked,
            "Adversarial corpus vector #{idx} (kind='{}', payload={:?}) WAS NOT BLOCKED!",
            vec_item.kind, vec_item.payload
        );
    }
}

#[test]
fn enforces_a_to_b_allowed_and_b_to_c_hard_stop_across_read_and_bash() {
    let repo = test_sandbox_root("transitive_abc");
    let docs = repo.join("docs");
    fs::create_dir_all(&docs).expect("mkdir docs");

    fs::write(
        docs.join("A.md"),
        "# Doc A\nFor architecture details, see `docs/B.md`.\n",
    )
    .expect("write A");
    fs::write(
        docs.join("B.md"),
        "# Doc B\nNext, check [Doc C](C.md) for deeper internals.\n",
    )
    .expect("write B");
    fs::write(docs.join("C.md"), "# Doc C\nDeep third-hop file.\n").expect("write C");

    let sid = "session_abc_test";
    let prompt_json = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str(sid.to_string())),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
    ])
    .to_json_string();

    assert!(handle_user_prompt_hook(&prompt_json, &repo).is_allow());

    let make_read = |rel: &str| {
        JsonValue::Object(vec![
            ("session_id".to_string(), JsonValue::Str(sid.to_string())),
            (
                "cwd".to_string(),
                JsonValue::Str(repo.to_string_lossy().into_owned()),
            ),
            ("tool_name".to_string(), JsonValue::Str("Read".to_string())),
            (
                "tool_input".to_string(),
                JsonValue::Object(vec![(
                    "file_path".to_string(),
                    JsonValue::Str(rel.to_string()),
                )]),
            ),
        ])
        .to_json_string()
    };

    // Level 1: Read docs/A.md -> ALLOWED
    assert!(handle_pre_tool_hook(&make_read("docs/A.md"), &repo).is_allow());

    // Level 2: Read docs/B.md (pointed to by A) -> ALLOWED
    assert!(handle_pre_tool_hook(&make_read("docs/B.md"), &repo).is_allow());

    // Level 3: Attempt to read docs/C.md (pointed to by B) -> HARD STOP!
    match handle_pre_tool_hook(&make_read("docs/C.md"), &repo) {
        Decision::Deny { code, .. } => assert_eq!(code, "TRANSITIVE_DEPTH_EXCEEDED"),
        other => panic!("Expected TRANSITIVE_DEPTH_EXCEEDED on C.md, got {other:?}"),
    }

    // Attempt to bypass Read block by switching to Bash `cat docs/C.md` -> ALSO HARD BLOCKED!
    let bash_bypass = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str(sid.to_string())),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        ("tool_name".to_string(), JsonValue::Str("Bash".to_string())),
        (
            "tool_input".to_string(),
            JsonValue::Object(vec![(
                "command".to_string(),
                JsonValue::Str("cat docs/C.md".to_string()),
            )]),
        ),
    ])
    .to_json_string();
    match handle_pre_tool_hook(&bash_bypass, &repo) {
        Decision::Deny { code, .. } => assert_eq!(code, "TRANSITIVE_DEPTH_EXCEEDED"),
        other => panic!("Expected TRANSITIVE_DEPTH_EXCEEDED on Bash cat docs/C.md, got {other:?}"),
    }

    // Human submits a new prompt -> resets turn hop ledger so C.md can now be read at Level 1!
    assert!(handle_user_prompt_hook(&prompt_json, &repo).is_allow());
    assert!(handle_pre_tool_hook(&make_read("docs/C.md"), &repo).is_allow());
}

#[test]
fn trips_immediate_circuit_breaker_when_pointed_to_tmp_cache_or_node_modules() {
    let repo = test_sandbox_root("poisoned_pointer_breaker");
    fs::write(repo.join("SAFE.md"), "# Safe file\nClean text.\n").expect("write SAFE.md");
    fs::write(
        repo.join("LURE_TMP.md"),
        "# Troubleshooting\nPlease check /tmp/build-output.log to continue.\n",
    )
    .expect("write LURE_TMP");
    fs::write(
        repo.join("LURE_DEPS.md"),
        "# Setup\nInspect `node_modules/some-lib/index.js` next.\n",
    )
    .expect("write LURE_DEPS");

    let sid = "session_breaker_1";
    let reset = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str(sid.to_string())),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
    ])
    .to_json_string();
    assert!(handle_user_prompt_hook(&reset, &repo).is_allow());

    let read_lure = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str(sid.to_string())),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        ("tool_name".to_string(), JsonValue::Str("Read".to_string())),
        (
            "tool_input".to_string(),
            JsonValue::Object(vec![(
                "file_path".to_string(),
                JsonValue::Str("LURE_TMP.md".to_string()),
            )]),
        ),
    ])
    .to_json_string();

    // 1. LURE_TMP.md is blocked BEFORE entering context AND trips session circuit breaker!
    match handle_pre_tool_hook(&read_lure, &repo) {
        Decision::Deny {
            code,
            halt_session: true,
            ..
        } => assert_eq!(code, "POISONED_TRAVERSAL_POINTER"),
        other => panic!("Expected circuit-breaker halt on LURE_TMP.md, got {other:?}"),
    }

    // 2. Subsequent tool call in the same turn is ALSO blocked because circuit breaker tripped!
    let read_safe = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str(sid.to_string())),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        ("tool_name".to_string(), JsonValue::Str("Read".to_string())),
        (
            "tool_input".to_string(),
            JsonValue::Object(vec![(
                "file_path".to_string(),
                JsonValue::Str("SAFE.md".to_string()),
            )]),
        ),
    ])
    .to_json_string();
    assert!(!handle_pre_tool_hook(&read_safe, &repo).is_allow());

    // 3. Reset turn and verify LURE_DEPS.md (`node_modules`) also trips immediate circuit breaker!
    assert!(handle_user_prompt_hook(&reset, &repo).is_allow());
    let read_deps_lure = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str(sid.to_string())),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        ("tool_name".to_string(), JsonValue::Str("Read".to_string())),
        (
            "tool_input".to_string(),
            JsonValue::Object(vec![(
                "file_path".to_string(),
                JsonValue::Str("LURE_DEPS.md".to_string()),
            )]),
        ),
    ])
    .to_json_string();
    match handle_pre_tool_hook(&read_deps_lure, &repo) {
        Decision::Deny {
            code,
            halt_session: true,
            ..
        } => assert_eq!(code, "POISONED_TRAVERSAL_POINTER"),
        other => panic!("Expected circuit-breaker halt on LURE_DEPS.md, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn blocks_symlink_escape_to_tmp_and_sibling_repositories() {
    use std::os::unix::fs::symlink;

    let repo_a = test_sandbox_root("symlink_repo_a");
    let repo_b = test_sandbox_root("symlink_repo_b");
    fs::write(repo_b.join("SECRET_SIBLING.md"), "Cross-repo secret").expect("write sibling");

    symlink("/tmp/nonexistent_payload", repo_a.join("link_to_tmp.md")).expect("symlink tmp");
    symlink(
        repo_b.join("SECRET_SIBLING.md"),
        repo_a.join("link_to_sibling.md"),
    )
    .expect("symlink sibling");

    assert!(validate_path(&repo_a, &repo_a, "link_to_tmp.md", PathAccess::Read).is_err());
    assert!(validate_path(&repo_a, &repo_a, "link_to_sibling.md", PathAccess::Read).is_err());
    assert!(
        validate_path(
            &repo_a,
            &repo_a,
            &repo_b.join("SECRET_SIBLING.md").to_string_lossy(),
            PathAccess::Read
        )
        .is_err()
    );
}

#[test]
fn blocks_token_exhaustion_files_output_floods_and_json_surrogate_tags() {
    let repo = test_sandbox_root("budget_and_surrogates");
    for sid in ["s_budget", "s_flood", "s_tag"] {
        let init = JsonValue::Object(vec![
            ("session_id".to_string(), JsonValue::Str(sid.to_string())),
            (
                "cwd".to_string(),
                JsonValue::Str(repo.to_string_lossy().into_owned()),
            ),
        ])
        .to_json_string();
        assert!(handle_user_prompt_hook(&init, &repo).is_allow());
    }

    // 1. 80 KiB multi-line file -> blocked un-sliced, allowed when sliced <= 200 lines!
    let mut big_lines = String::new();
    for i in 0..1600 {
        big_lines.push_str(&format!(
            "line {i:04}: standard safe log message for testing bounded slicing.\n"
        ));
    }
    fs::write(repo.join("large.txt"), &big_lines).expect("write large.txt");
    for sid in ["s_budget", "s_flood", "s_tag"] {
        let init = JsonValue::Object(vec![
            ("session_id".to_string(), JsonValue::Str(sid.to_string())),
            (
                "cwd".to_string(),
                JsonValue::Str(repo.to_string_lossy().into_owned()),
            ),
        ])
        .to_json_string();
        assert!(handle_user_prompt_hook(&init, &repo).is_allow());
    }

    let unsliced = JsonValue::Object(vec![
        (
            "session_id".to_string(),
            JsonValue::Str("s_budget".to_string()),
        ),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        ("tool_name".to_string(), JsonValue::Str("Read".to_string())),
        (
            "tool_input".to_string(),
            JsonValue::Object(vec![(
                "file_path".to_string(),
                JsonValue::Str("large.txt".to_string()),
            )]),
        ),
    ])
    .to_json_string();
    match handle_pre_tool_hook(&unsliced, &repo) {
        Decision::Deny { code, .. } => assert_eq!(code, "FILE_BYTE_BUDGET_EXCEEDED"),
        other => panic!("Expected FILE_BYTE_BUDGET_EXCEEDED, got {other:?}"),
    }

    let sliced = JsonValue::Object(vec![
        (
            "session_id".to_string(),
            JsonValue::Str("s_budget".to_string()),
        ),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        ("tool_name".to_string(), JsonValue::Str("Read".to_string())),
        (
            "tool_input".to_string(),
            JsonValue::Object(vec![
                (
                    "file_path".to_string(),
                    JsonValue::Str("large.txt".to_string()),
                ),
                ("offset".to_string(), JsonValue::Number(1.0)),
                ("limit".to_string(), JsonValue::Number(100.0)),
            ]),
        ),
    ])
    .to_json_string();
    assert!(handle_pre_tool_hook(&sliced, &repo).is_allow());

    // 2. PostToolUse dynamic stdout flood (> 48 KiB) -> blocked!
    let flood_json = JsonValue::Object(vec![
        (
            "session_id".to_string(),
            JsonValue::Str("s_flood".to_string()),
        ),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        (
            "tool_response".to_string(),
            JsonValue::Str("x\n".repeat(30_000)),
        ),
    ])
    .to_json_string();
    match handle_post_tool_hook(&flood_json, &repo) {
        Decision::Deny { code, .. } => assert_eq!(code, "TOOL_OUTPUT_FLOOD_BLOCKED"),
        other => panic!("Expected TOOL_OUTPUT_FLOOD_BLOCKED, got {other:?}"),
    }

    // 3. JSON UTF-16 surrogate pair smuggling Unicode Tag U+E0041 (surrogates db40 + dc41) -> blocked!
    let surrogate_tag = concat!("\\", "udb40", "\\", "udc41");
    let surrogate_hook = format!(
        r#"{{"session_id":"s_tag","cwd":"{}","tool_name":"Write","tool_input":{{"file_path":"src/main.rs","content":"fn main() {{ /* {} */ }}"}}}}"#,
        repo.display(),
        surrogate_tag
    );
    match handle_pre_tool_hook(&surrogate_hook, &repo) {
        Decision::Deny { code, .. } => assert_eq!(code, "UNICODE_TAG_SMUGGLING"),
        other => panic!("Expected UNICODE_TAG_SMUGGLING, got {other:?}"),
    }
}

#[test]
fn cli_binary_returns_exit_code_2_on_violation_and_0_on_root_agents_md() {
    let repo = test_sandbox_root("cli_e2e");
    fs::write(
        repo.join("AGENTS.md"),
        "# AGENTS.md\nRoot security authority.\n",
    )
    .expect("write root AGENTS.md");

    let bin = env!("CARGO_BIN_EXE_agent-guard");

    // 1. Reading root AGENTS.md -> Exit 0
    let mut child_ok = Command::new(bin)
        .arg("pre-tool")
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", repo.join(".state"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agent-guard");
    child_ok
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(
            format!(
                r#"{{"session_id":"cli1","cwd":"{}","tool_name":"Read","tool_input":{{"file_path":"AGENTS.md"}}}}"#,
                repo.display()
            )
            .as_bytes(),
        )
        .expect("write stdin");
    let out_ok = child_ok.wait_with_output().expect("wait ok");
    assert_eq!(out_ok.status.code(), Some(0));

    // 2. Attempting `ls node_modules` via Bash -> Exit 2 + structured JSON deny!
    let mut child_deny = Command::new(bin)
        .arg("pre-tool")
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", repo.join(".state"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agent-guard");
    child_deny
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(
            format!(
                r#"{{"session_id":"cli1","cwd":"{}","tool_name":"Bash","tool_input":{{"command":"ls node_modules"}}}}"#,
                repo.display()
            )
            .as_bytes(),
        )
        .expect("write stdin");
    let out_deny = child_deny.wait_with_output().expect("wait deny");
    assert_eq!(out_deny.status.code(), Some(2));
    let stdout_str = String::from_utf8_lossy(&out_deny.stdout);
    assert!(stdout_str.contains("\"permissionDecision\":\"deny\""));
    let audit_body = fs::read_to_string(repo.join(".state").join("audit.jsonl"))
        .expect("audit.jsonl recorded on deny");
    assert!(audit_body.contains("FORBIDDEN_DEPENDENCY_PATH"));
    assert!(
        audit_body
            .bytes()
            .all(|b| b == b'\n' || (0x20..=0x7E).contains(&b))
    );
}

#[test]
fn neuters_non_ascii_and_escapes_before_buffer_on_read_and_stream() {
    let repo = test_sandbox_root("prebuffer_ascii_sanitizer");
    let sid = "session_ascii_san";
    let init = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str(sid.to_string())),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
    ])
    .to_json_string();
    assert!(handle_user_prompt_hook(&init, &repo).is_allow());

    // Untrusted doc with non-ASCII UTF-8, CR line-overwrite, and literal escape triggers
    let dirty_doc = "Header: Caf\u{00E9} \u{1F680} \u{4E2D}\u{6587}\r\n\
                     SPOOFED_PREFIX\rClean visible line\n\
                     Escapes: \\u0041 \\x42 &#x43; %C3%A9\n";
    fs::write(repo.join("dirty.md"), dirty_doc).expect("write dirty.md");

    let read_req = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str(sid.to_string())),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        ("tool_name".to_string(), JsonValue::Str("Read".to_string())),
        (
            "tool_input".to_string(),
            JsonValue::Object(vec![(
                "file_path".to_string(),
                JsonValue::Str("dirty.md".to_string()),
            )]),
        ),
    ])
    .to_json_string();

    // Raw Read MUST be blocked before buffer and replaced with 100% 7-bit clean ASCII + 128-bit spotlight nonce!
    match handle_pre_tool_hook(&read_req, &repo) {
        Decision::Deny {
            code,
            reason,
            halt_session: false,
        } => {
            assert_eq!(code, "NON_ASCII_SANITIZED_PREBUFFER");
            assert!(
                reason
                    .bytes()
                    .all(|b| b == b'\n' || b == b'\t' || (0x20..=0x7E).contains(&b)),
                "Sanitized pre-buffer payload contained non-7-bit-ASCII byte!"
            );
            assert!(reason.contains("<<<UNTRUSTED_ASCII_DATA_"));
            assert!(reason.contains("<<<END_UNTRUSTED_ASCII_DATA_"));
            assert!(reason.contains("[NON_ASCII"));
            assert!(reason.contains("\\[u]0041"));
            assert!(reason.contains("\\[x]42"));
            assert!(reason.contains("&[#]x43;"));
            assert!(reason.contains("%[_]C3"));
            assert!(!reason.contains('\r'));
        }
        other => panic!("Expected NON_ASCII_SANITIZED_PREBUFFER, got {other:?}"),
    }

    // Verify `agent-guard sanitize-stream` binary neuters ANSI + non-ASCII + compacts >120 lines!
    let bin = env!("CARGO_BIN_EXE_agent-guard");
    let mut child = Command::new(bin)
        .arg("sanitize-stream")
        .current_dir(&repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn sanitize-stream");
    let mut noisy_stream = String::from("\x1b[31mCOLOR\x1b[0m \u{1F525} \\u0041\r\n");
    for i in 0..220 {
        noisy_stream.push_str(&format!("log line {i}\n"));
    }
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(noisy_stream.as_bytes())
        .expect("write noisy stream");
    let out = child.wait_with_output().expect("wait sanitize-stream");
    assert_eq!(out.status.code(), Some(0));
    let clean = String::from_utf8(out.stdout).expect("utf8 stdout");
    assert!(
        clean
            .bytes()
            .all(|b| b == b'\n' || b == b'\t' || (0x20..=0x7E).contains(&b))
    );
    assert!(clean.contains("[ANSI_STRIPPED]"));
    assert!(clean.contains("[NON_ASCII]"));
    assert!(clean.contains("\\[u]0041"));
    assert!(clean.contains("COMPACTED"));
}

#[test]
fn blocks_cargo_and_yarn_build_config_execution_traps_and_audits_repo() {
    let repo = test_sandbox_root("build_config_traps");

    // Plant `.cargo/config.toml` rustc-wrapper RCE trap
    fs::create_dir_all(repo.join(".cargo")).expect("mkdir .cargo");
    fs::write(
        repo.join(".cargo/config.toml"),
        "[build]\nrustc-wrapper = \"./pwn.sh\"\n",
    )
    .expect("write .cargo/config.toml");

    let cargo_err =
        evaluate_shell_command("cargo test", &repo, &repo, false).expect_err("cargo trap blocked");
    assert_eq!(cargo_err.code, "CARGO_CONFIG_EXEC_TRAP");

    // Plant `.yarnrc.yml` yarnPath RCE trap and `.gitattributes` filter trap
    fs::write(
        repo.join(".yarnrc.yml"),
        "yarnPath: .yarn/releases/evil.cjs\n",
    )
    .expect("write .yarnrc.yml");
    fs::write(repo.join(".gitattributes"), "*.rs filter=evil\n").expect("write .gitattributes");

    let yarn_err =
        evaluate_shell_command("yarn test", &repo, &repo, false).expect_err("yarn trap blocked");
    assert_eq!(yarn_err.code, "YARN_CONFIG_EXEC_TRAP");

    let audit_errs = agent_guard::audit_repository(&repo).expect_err("audit catches traps");
    assert!(
        audit_errs
            .iter()
            .any(|e| e.contains("CARGO_CONFIG_EXEC_TRAP"))
    );
    assert!(
        audit_errs
            .iter()
            .any(|e| e.contains("YARN_CONFIG_EXEC_TRAP"))
    );
    assert!(
        audit_errs
            .iter()
            .any(|e| e.contains("GITATTRIBUTES_DRIVER_TRAP"))
    );
}

#[test]
fn enforces_tiny_16k_step_window_soft_compaction_trigger_and_pre_compact_nonce_rotation() {
    let repo = test_sandbox_root("tiny_step_compaction");
    fs::create_dir_all(repo.join("docs")).expect("mkdir docs");
    fs::write(repo.join("docs/A.md"), "See `docs/B.md`.\n").expect("write A");
    fs::write(repo.join("docs/B.md"), "See `docs/C.md`.\n").expect("write B");
    fs::write(repo.join("docs/C.md"), "Third hop.\n").expect("write C");

    let sid = "session_compact_step";
    let init = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str(sid.to_string())),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
    ])
    .to_json_string();
    let initial_nonce = match handle_user_prompt_hook(&init, &repo) {
        Decision::Allow {
            advisory: Some(note),
            ..
        } => note,
        other => panic!("Expected advisory with nonce, got {other:?}"),
    };

    // Establish A -> B -> C chain before compaction
    let make_read = |rel: &str| {
        JsonValue::Object(vec![
            ("session_id".to_string(), JsonValue::Str(sid.to_string())),
            (
                "cwd".to_string(),
                JsonValue::Str(repo.to_string_lossy().into_owned()),
            ),
            ("tool_name".to_string(), JsonValue::Str("Read".to_string())),
            (
                "tool_input".to_string(),
                JsonValue::Object(vec![(
                    "file_path".to_string(),
                    JsonValue::Str(rel.to_string()),
                )]),
            ),
        ])
        .to_json_string()
    };
    assert!(handle_pre_tool_hook(&make_read("docs/A.md"), &repo).is_allow());
    assert!(handle_pre_tool_hook(&make_read("docs/B.md"), &repo).is_allow());

    // Push step tokens past 8k soft-compact threshold via PostToolUse outputs
    let chunk_out = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str(sid.to_string())),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        (
            "tool_response".to_string(),
            JsonValue::Str("alpha beta gamma delta epsilon zeta eta theta\n".repeat(320)),
        ),
    ])
    .to_json_string();
    let _ = handle_post_tool_hook(&chunk_out, &repo);
    let _ = handle_post_tool_hook(&chunk_out, &repo);
    match handle_post_tool_hook(&chunk_out, &repo) {
        Decision::Allow {
            advisory: Some(note),
            ..
        } => assert!(
            note.contains("COMPACT_STEP_NOW"),
            "Expected COMPACT_STEP_NOW trigger in {note}"
        ),
        other => panic!("Expected Allow with COMPACT_STEP_NOW, got {other:?}"),
    }

    // Push past 16k hard step ceiling -> next file read is blocked until step compacts!
    let _ = handle_post_tool_hook(&chunk_out, &repo);
    let _ = handle_post_tool_hook(&chunk_out, &repo);
    fs::write(
        repo.join("step_extra.txt"),
        "extra tokens after uncompacted multi-step work\n".repeat(40),
    )
    .expect("write step_extra.txt");
    match handle_pre_tool_hook(&make_read("step_extra.txt"), &repo) {
        Decision::Deny { code, .. } => assert_eq!(code, "TURN_TOKEN_BUDGET_EXCEEDED"),
        other => panic!("Expected TURN_TOKEN_BUDGET_EXCEEDED at 16k ceiling, got {other:?}"),
    }

    // Trigger PreCompact -> resets step token counter & rotates 128-bit nonce, while keeping C.md blocked!
    let compact_decision = agent_guard::handle_pre_compact_hook(&init, &repo);
    match compact_decision {
        Decision::Allow {
            advisory: Some(note),
            ..
        } => {
            assert!(note.contains("TINY-CONTEXT STEP COMPACTION"));
            assert_ne!(note, initial_nonce);
        }
        other => panic!("Expected PreCompact allow advisory, got {other:?}"),
    }

    // Now step_extra.txt is allowed in the fresh compacted step micro-window...
    assert!(handle_pre_tool_hook(&make_read("step_extra.txt"), &repo).is_allow());
    // ...while 3rd-hop `docs/C.md` STILL remains hard-blocked across compaction!
    match handle_pre_tool_hook(&make_read("docs/C.md"), &repo) {
        Decision::Deny { code, .. } => assert_eq!(code, "TRANSITIVE_DEPTH_EXCEEDED"),
        other => panic!("Expected C.md to remain blocked after step compaction, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn regression_pr1_review_findings() {
    use std::os::unix::fs::symlink;

    let repo = test_sandbox_root("pr1_regressions");

    // 1. Missing root AGENTS.md must fail audit_repository
    let missing_errs =
        agent_guard::audit_repository(&repo).expect_err("missing root AGENTS.md must fail audit");
    assert!(
        missing_errs
            .iter()
            .any(|e| e.contains("MISSING_ROOT_AGENTS_MD")),
        "Expected MISSING_ROOT_AGENTS_MD, got {missing_errs:?}"
    );

    // 2. Symlinked root AGENTS.md must fail both validate_path and audit_repository
    fs::write(repo.join("real_agents.md"), "# placeholder\n").expect("write real_agents.md");
    symlink(repo.join("real_agents.md"), repo.join("AGENTS.md")).expect("symlink root AGENTS.md");
    assert!(validate_path(&repo, &repo, "AGENTS.md", PathAccess::Read).is_err());
    let sym_errs =
        agent_guard::audit_repository(&repo).expect_err("symlinked root AGENTS.md must fail");
    assert!(
        sym_errs
            .iter()
            .any(|e| e.contains("SYMLINKED_ROOT_AGENTS_MD")),
        "Expected SYMLINKED_ROOT_AGENTS_MD, got {sym_errs:?}"
    );
    fs::remove_file(repo.join("AGENTS.md")).expect("remove symlink AGENTS.md");
    fs::write(repo.join("AGENTS.md"), "# Root AGENTS\n").expect("write regular AGENTS.md");
    assert!(validate_path(&repo, &repo, "AGENTS.md", PathAccess::Read).is_ok());

    // 3. Nested symlink sub/AGENTS.md -> ../AGENTS.md must be blocked BEFORE symlink resolution
    fs::create_dir_all(repo.join("sub")).expect("mkdir sub");
    symlink("../AGENTS.md", repo.join("sub/AGENTS.md")).expect("symlink sub/AGENTS.md");
    let nested_err = validate_path(&repo, &repo, "sub/AGENTS.md", PathAccess::Read)
        .expect_err("nested symlink sub/AGENTS.md must be denied");
    assert_eq!(nested_err.code, "UNAUTHORIZED_INSTRUCTION_FILE");

    // 4. Cross-repo cwd spoofing in hook payload must be hard-denied
    let sibling_repo = test_sandbox_root("pr1_sibling_repo");
    let spoof_req = JsonValue::Object(vec![
        (
            "session_id".to_string(),
            JsonValue::Str("pr1_spoof".to_string()),
        ),
        (
            "cwd".to_string(),
            JsonValue::Str(sibling_repo.to_string_lossy().into_owned()),
        ),
        ("tool_name".to_string(), JsonValue::Str("Read".to_string())),
        (
            "tool_input".to_string(),
            JsonValue::Object(vec![(
                "file_path".to_string(),
                JsonValue::Str("AGENTS.md".to_string()),
            )]),
        ),
    ])
    .to_json_string();
    match handle_pre_tool_hook(&spoof_req, &repo) {
        Decision::Deny { code, .. } => assert_eq!(code, "CROSS_REPO_CWD_SPOOF"),
        other => panic!("Expected CROSS_REPO_CWD_SPOOF, got {other:?}"),
    }

    // 5. PostToolUse must sanitize non-ASCII/escape tool outputs pre-buffer AND register dynamic pointers
    fs::create_dir_all(repo.join("docs")).expect("mkdir docs");
    fs::write(repo.join("docs/hop1.md"), "Hop 1.\n").expect("write hop1");
    fs::write(repo.join("docs/hop2.md"), "See `docs/hop3.md`.\n").expect("write hop2");
    fs::write(repo.join("docs/hop3.md"), "Hop 3.\n").expect("write hop3");
    for sid in ["pr1_post", "pr1_post_chain"] {
        let init = JsonValue::Object(vec![
            ("session_id".to_string(), JsonValue::Str(sid.to_string())),
            (
                "cwd".to_string(),
                JsonValue::Str(repo.to_string_lossy().into_owned()),
            ),
        ])
        .to_json_string();
        assert!(handle_user_prompt_hook(&init, &repo).is_allow());
    }

    let dirty_post = JsonValue::Object(vec![
        (
            "session_id".to_string(),
            JsonValue::Str("pr1_post".to_string()),
        ),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        ("tool_name".to_string(), JsonValue::Str("Grep".to_string())),
        (
            "tool_response".to_string(),
            JsonValue::Str("docs/hop1.md:1: cafe\u{00E9} see `docs/hop2.md`\n".to_string()),
        ),
    ])
    .to_json_string();
    match handle_post_tool_hook(&dirty_post, &repo) {
        Decision::Deny { code, reason, .. } => {
            assert_eq!(code, "NON_ASCII_SANITIZED_PREBUFFER");
            assert!(reason.contains("[NON_ASCII"));
        }
        other => panic!("Expected NON_ASCII_SANITIZED_PREBUFFER on PostToolUse, got {other:?}"),
    }

    // Clean PostToolUse output referencing docs/hop2.md registers hop2 at depth 2 -> hop2's pointer to hop3 is depth 3 (blocked!)
    let clean_post = JsonValue::Object(vec![
        (
            "session_id".to_string(),
            JsonValue::Str("pr1_post_chain".to_string()),
        ),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        (
            "tool_name".to_string(),
            JsonValue::Str("mcp_doc_search".to_string()),
        ),
        (
            "tool_response".to_string(),
            JsonValue::Str("match in `docs/hop2.md`\n".to_string()),
        ),
    ])
    .to_json_string();
    assert!(handle_post_tool_hook(&clean_post, &repo).is_allow());
    let read_hop2 = JsonValue::Object(vec![
        (
            "session_id".to_string(),
            JsonValue::Str("pr1_post_chain".to_string()),
        ),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        ("tool_name".to_string(), JsonValue::Str("Read".to_string())),
        (
            "tool_input".to_string(),
            JsonValue::Object(vec![(
                "file_path".to_string(),
                JsonValue::Str("docs/hop2.md".to_string()),
            )]),
        ),
    ])
    .to_json_string();
    assert!(handle_pre_tool_hook(&read_hop2, &repo).is_allow());
    let read_hop3 = JsonValue::Object(vec![
        (
            "session_id".to_string(),
            JsonValue::Str("pr1_post_chain".to_string()),
        ),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        ("tool_name".to_string(), JsonValue::Str("Read".to_string())),
        (
            "tool_input".to_string(),
            JsonValue::Object(vec![(
                "file_path".to_string(),
                JsonValue::Str("docs/hop3.md".to_string()),
            )]),
        ),
    ])
    .to_json_string();
    match handle_pre_tool_hook(&read_hop3, &repo) {
        Decision::Deny { code, .. } => assert_eq!(code, "TRANSITIVE_DEPTH_EXCEEDED"),
        other => {
            panic!("Expected TRANSITIVE_DEPTH_EXCEEDED via PostToolUse pointer, got {other:?}")
        }
    }

    // 6. sanitize_and_compact_bytes must never exceed max_bytes even after appending truncation marker
    let huge = "0123456789abcdef\n".repeat(400);
    let report = agent_guard::sanitizer::sanitize_and_compact_bytes(huge.as_bytes(), 500, 256);
    assert!(
        report.clean_ascii.len() <= 256,
        "Expected compacted output <= 256 bytes, got {}",
        report.clean_ascii.len()
    );
}

#[test]
fn regression_deep_adversarial_pr1_findings() {
    let repo = test_sandbox_root("pr1_deep_adversarial");
    let outside = test_sandbox_root("pr1_deep_outside");
    fs::write(repo.join("AGENTS.md"), "# Canonical Root\n").expect("write AGENTS.md");
    fs::create_dir_all(repo.join("src")).expect("mkdir src");
    fs::write(repo.join("src/lib.rs"), "pub fn ok() {}\n").expect("write src/lib.rs");

    // 1. Inner symlink + ENOENT trailing path (`escape_link/nonexistent_dir/new.txt`) must be caught!
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(&outside, repo.join("escape_link")).expect("symlink escape_link");
        let res = validate_path(
            &repo,
            &repo,
            "escape_link/nonexistent_subdir/created.txt",
            PathAccess::Write,
        );
        assert!(
            res.is_err(),
            "Write through inner symlink with ENOENT trailing segments must be blocked!"
        );
    }

    // 2. `apply_patch` / `patch` tool validates target paths and Unicode smuggling
    let sid = "deep_pr1_sess";
    let reset = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str(sid.to_string())),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
    ])
    .to_json_string();
    assert!(handle_user_prompt_hook(&reset, &repo).is_allow());

    let bad_patch = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str(sid.to_string())),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        (
            "tool_name".to_string(),
            JsonValue::Str("apply_patch".to_string()),
        ),
        (
            "tool_input".to_string(),
            JsonValue::Object(vec![(
                "patch".to_string(),
                JsonValue::Str("*** Update File: AGENTS.md\n@@\n-old\n+new\n".to_string()),
            )]),
        ),
    ])
    .to_json_string();
    assert!(!handle_pre_tool_hook(&bad_patch, &repo).is_allow());

    assert!(handle_user_prompt_hook(&reset, &repo).is_allow());
    let ok_patch = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str(sid.to_string())),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        (
            "tool_name".to_string(),
            JsonValue::Str("apply_patch".to_string()),
        ),
        (
            "tool_input".to_string(),
            JsonValue::Object(vec![(
                "patch".to_string(),
                JsonValue::Str(
                    "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n--- sql comment\n+pub fn ok2() {}\n"
                        .to_string(),
                ),
            )]),
        ),
    ])
    .to_json_string();
    assert!(handle_pre_tool_hook(&ok_patch, &repo).is_allow());

    // 3. `MultiEdit` nested `edits` array catches Trojan Source Bidi & secondary forbidden paths
    let rlo = char::from_u32(0x202E).unwrap();
    let multiedit_bidi = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str(sid.to_string())),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        (
            "tool_name".to_string(),
            JsonValue::Str("MultiEdit".to_string()),
        ),
        (
            "tool_input".to_string(),
            JsonValue::Object(vec![
                (
                    "file_path".to_string(),
                    JsonValue::Str("src/lib.rs".to_string()),
                ),
                (
                    "edits".to_string(),
                    JsonValue::Array(vec![JsonValue::Object(vec![(
                        "new_string".to_string(),
                        JsonValue::Str(format!("let x = \"{rlo}\";")),
                    )])]),
                ),
            ]),
        ),
    ])
    .to_json_string();
    assert!(!handle_pre_tool_hook(&multiedit_bidi, &repo).is_allow());
    assert!(handle_user_prompt_hook(&reset, &repo).is_allow());

    // 4. `Grep` regex pattern allows standard regex escapes (`\x7f`) while blocking Bidi
    let grep_ok = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str(sid.to_string())),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        ("tool_name".to_string(), JsonValue::Str("Grep".to_string())),
        (
            "tool_input".to_string(),
            JsonValue::Object(vec![
                (
                    "pattern".to_string(),
                    JsonValue::Str(concat!("foo\\", "x7fbar").to_string()),
                ),
                ("path".to_string(), JsonValue::Str("src".to_string())),
            ]),
        ),
    ])
    .to_json_string();
    assert!(handle_pre_tool_hook(&grep_ok, &repo).is_allow());

    // 5. Shell AST bypasses: piped/heredoc/herestring stdin code, attached -c/-e, gh -R, npm --prefix, cargo --config, rg -e, tree, xargs
    let must_block_cmds = [
        "echo id | sh",
        "echo 'import os' | python3",
        "sh <<'EOF'\ncat /etc/passwd\nEOF\n",
        "bash <<< 'cat /etc/passwd'",
        "python3 <<EOF\nprint(1)\nEOF\n",
        concat!("sh -c'cat /", "tmp/x'"),
        concat!("sh -xc'cat /", "tmp/x'"),
        "python3 -c'import subprocess'",
        "node --eval=\"require('child_process')\"",
        "gh -R owner/repo pr merge 1",
        "gh -R owner/repo auth status",
        concat!("npm --prefix /", "tmp install --ignore-scripts"),
        "npm --prefix src install",
        "cargo --config 'build.rustc-wrapper=\"evil\"' check",
        "cargo +nightly publish",
        concat!("rg --max-depth 2 -e needle /", "tmp"),
        concat!("tree -L 2 /", "tmp"),
        "printf 'AGENTS.md\\n' | xargs rm",
    ];
    for cmd in must_block_cmds {
        assert!(
            evaluate_shell_command(cmd, &repo, &repo, false).is_err(),
            "Expected shell command `{cmd}` to be blocked!"
        );
    }

    // Benign pipeline into `python3 -c` (code inspected via `-c`, stdin is data) remains allowed!
    assert!(
        evaluate_shell_command(
            "echo '{\"a\":1}' | python3 -c 'import json, sys'",
            &repo,
            &repo,
            false
        )
        .is_ok()
    );

    // 6. Discovery output (`Bash` / `ls`) after a Level-2 read must NOT poison unread files to Level 3
    fs::create_dir_all(repo.join("docs")).expect("mkdir docs");
    fs::write(repo.join("docs/a.md"), "See [b](b.md).\n").expect("write a.md");
    fs::write(repo.join("docs/b.md"), "Leaf doc.\n").expect("write b.md");
    fs::write(repo.join("docs/unvisited.md"), "Unvisited sibling.\n").expect("write unvisited.md");
    assert!(handle_user_prompt_hook(&reset, &repo).is_allow());
    for rel in ["docs/a.md", "docs/b.md"] {
        let req = JsonValue::Object(vec![
            ("session_id".to_string(), JsonValue::Str(sid.to_string())),
            (
                "cwd".to_string(),
                JsonValue::Str(repo.to_string_lossy().into_owned()),
            ),
            ("tool_name".to_string(), JsonValue::Str("Read".to_string())),
            (
                "tool_input".to_string(),
                JsonValue::Object(vec![(
                    "file_path".to_string(),
                    JsonValue::Str(rel.to_string()),
                )]),
            ),
        ])
        .to_json_string();
        assert!(handle_pre_tool_hook(&req, &repo).is_allow());
    }
    let bash_ls_post = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str(sid.to_string())),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        ("tool_name".to_string(), JsonValue::Str("Bash".to_string())),
        (
            "tool_response".to_string(),
            JsonValue::Str("docs/unvisited.md\n".to_string()),
        ),
    ])
    .to_json_string();
    assert!(handle_post_tool_hook(&bash_ls_post, &repo).is_allow());
    let read_unvisited = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str(sid.to_string())),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        ("tool_name".to_string(), JsonValue::Str("Read".to_string())),
        (
            "tool_input".to_string(),
            JsonValue::Object(vec![(
                "file_path".to_string(),
                JsonValue::Str("docs/unvisited.md".to_string()),
            )]),
        ),
    ])
    .to_json_string();
    assert!(
        handle_pre_tool_hook(&read_unvisited, &repo).is_allow(),
        "Bash/ls discovery output must not poison unread workspace files to Level 3!"
    );

    // 7. Large structured JSON object (> 2 KiB) on PostToolUse does NOT falsely trigger SINGLE_LINE_TOKEN_BOMB,
    //    and CLI `post-tool` with non-ASCII exits 0 (advisory replacement) instead of 2!
    let mut fields = Vec::new();
    for idx in 0..45 {
        fields.push((
            format!("field_{idx:02}"),
            JsonValue::Str("clean_ascii_value_0123456789abcdef0123456789".to_string()),
        ));
    }
    let structured_post = JsonValue::Object(vec![
        ("session_id".to_string(), JsonValue::Str(sid.to_string())),
        (
            "cwd".to_string(),
            JsonValue::Str(repo.to_string_lossy().into_owned()),
        ),
        (
            "tool_name".to_string(),
            JsonValue::Str("mcp_tool".to_string()),
        ),
        ("tool_response".to_string(), JsonValue::Object(fields)),
    ])
    .to_json_string();
    assert!(
        handle_post_tool_hook(&structured_post, &repo).is_allow(),
        "Structured >2 KiB JSON object in PostToolUse must not trip SINGLE_LINE_TOKEN_BOMB"
    );

    let bin = env!("CARGO_BIN_EXE_agent-guard");
    let e_acute = char::from_u32(0x00E9).unwrap();
    let mut child_post = Command::new(bin)
        .arg("post-tool")
        .current_dir(&repo)
        .env("AGENT_GUARD_STATE_DIR", repo.join(".state"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agent-guard post-tool");
    child_post
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(
            format!(
                r#"{{"session_id":"cli_post","cwd":"{}","tool_name":"Bash","tool_response":"caf{e_acute}"}}"#,
                repo.display()
            )
            .as_bytes(),
        )
        .expect("write post-tool stdin");
    let out_post = child_post.wait_with_output().expect("wait post-tool");
    assert_eq!(
        out_post.status.code(),
        Some(0),
        "PostToolUse pre-buffer ASCII sanitization must exit 0 with advisory context!"
    );
}
