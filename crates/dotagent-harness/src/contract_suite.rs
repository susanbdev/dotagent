#![forbid(unsafe_code)]

//! Versioned Upstream Harness & MCP Sidecar Wire-Contract Suite (`Pillar 6`).
//!
//! Replays pinned golden wire fixtures (`tests/harness_contracts/upstream_wire_contracts_v2.toml`)
//! against the compiled `agent-guard` binary and verifies:
//! 1. Claude Code (`1.0.x`), Cursor (`0.49+`), Gemini CLI (`0.4+`), and OpenAI Codex (`0.2+`)
//!    exact JSON output envelope paths and exit codes.
//! 2. `agent-guard mcp-gateway` JSON-RPC 2.0 (`2024-11-05`) stdio contract (`initialize`,
//!    `tools/list`, mediated `tools/call` `dotagent_read_file` spotlighting & forbidden-path block).
//! 3. Detached Ed25519 `StopReceipt` emission on `on-stop` and CI `verify-receipt` admission gate.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

use agent_guard::json::JsonValue;

use crate::CaseResult;
use crate::sandbox::TestSandbox;

#[derive(Debug, Clone)]
struct WireContractFixture {
    id: String,
    harness: String,
    harness_version: String,
    subcommand: String,
    stdin_json: String,
    profile_env: Option<String>,
    expected_exit: i32,
    required_stdout_json_paths: Vec<String>,
    expected_stdout_substring: String,
}

pub fn load_contract_case_ids(workspace_root: &Path) -> Result<Vec<String>, String> {
    let fixtures = load_wire_contract_fixtures(workspace_root)?;
    let mut ids: Vec<String> = fixtures
        .into_iter()
        .map(|f| format!("contract::{}/{}", f.harness, f.id))
        .collect();
    ids.push("contract::mcp-gateway/jsonrpc_initialize_read_and_deny".to_string());
    ids.push("contract::stop-receipt/ed25519_on_stop_and_verify_gate".to_string());
    Ok(ids)
}

pub fn run_contract_suite(
    workspace_root: &Path,
    agent_guard_bin: &Path,
    filter: Option<&str>,
) -> Result<Vec<CaseResult>, String> {
    let fixtures = load_wire_contract_fixtures(workspace_root)?;
    let mut results = Vec::new();

    for fx in &fixtures {
        let case_id = format!("contract::{}/{}", fx.harness, fx.id);
        if let Some(f) = filter
            && !case_id.contains(f)
        {
            continue;
        }
        let started = Instant::now();
        match run_single_wire_fixture(workspace_root, agent_guard_bin, fx) {
            Ok(detail) => results.push(CaseResult::pass(
                case_id,
                "contracts",
                started.elapsed().as_millis() as u64,
                detail,
            )),
            Err(err) => results.push(CaseResult::fail(
                case_id,
                "contracts",
                started.elapsed().as_millis() as u64,
                err,
            )),
        }
    }

    let mcp_id = "contract::mcp-gateway/jsonrpc_initialize_read_and_deny";
    if filter.is_none_or(|f| mcp_id.contains(f)) {
        let started = Instant::now();
        match run_mcp_gateway_contract(workspace_root, agent_guard_bin) {
            Ok(detail) => results.push(CaseResult::pass(
                mcp_id.to_string(),
                "contracts",
                started.elapsed().as_millis() as u64,
                detail,
            )),
            Err(err) => results.push(CaseResult::fail(
                mcp_id.to_string(),
                "contracts",
                started.elapsed().as_millis() as u64,
                err,
            )),
        }
    }

    let receipt_id = "contract::stop-receipt/ed25519_on_stop_and_verify_gate";
    if filter.is_none_or(|f| receipt_id.contains(f)) {
        let started = Instant::now();
        match run_stop_receipt_contract(workspace_root, agent_guard_bin) {
            Ok(detail) => results.push(CaseResult::pass(
                receipt_id.to_string(),
                "contracts",
                started.elapsed().as_millis() as u64,
                detail,
            )),
            Err(err) => results.push(CaseResult::fail(
                receipt_id.to_string(),
                "contracts",
                started.elapsed().as_millis() as u64,
                err,
            )),
        }
    }

    Ok(results)
}

fn run_single_wire_fixture(
    workspace_root: &Path,
    agent_guard_bin: &Path,
    fx: &WireContractFixture,
) -> Result<String, String> {
    let sb = TestSandbox::create(workspace_root, &format!("contract_{}", fx.id))?;
    let profiles_src = workspace_root.join("profiles");
    if profiles_src.is_dir() {
        crate::sandbox::copy_dir_filtered_bounded(
            &profiles_src,
            &sb.repo_dir.join("profiles"),
            0,
            2,
        )?;
    }
    let mut readme_lines = String::from("# Contract Fixture Readme\n");
    for n in 2..=320 {
        readme_lines.push_str(&format!("Line {n}: passive ascii fixture content\n"));
    }
    sb.write_repo_file("README.md", &readme_lines)?;

    let mut cmd = Command::new(agent_guard_bin);
    sb.configure_isolated_command(&mut cmd);
    cmd.current_dir(&sb.repo_dir)
        .args(fx.subcommand.split_whitespace())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(ref prof) = fx.profile_env {
        cmd.env("AGENT_GUARD_PROFILE", prof);
    }

    let rendered_stdin = fx
        .stdin_json
        .replace("{{REPO_ROOT}}", &sb.repo_dir.to_string_lossy());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed spawning agent-guard: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(rendered_stdin.as_bytes())
            .map_err(|e| format!("failed writing stdin: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("failed waiting on agent-guard: {e}"))?;
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    if code != fx.expected_exit {
        return Err(format!(
            "[{} {}] expected exit {}, got {} (stdout='{}', stderr='{}')",
            fx.harness,
            fx.harness_version,
            fx.expected_exit,
            code,
            stdout.trim(),
            stderr.trim()
        ));
    }

    if !fx.required_stdout_json_paths.is_empty() {
        let parsed = JsonValue::parse(stdout.trim()).map_err(|e| {
            format!(
                "[{} {}] stdout is not valid JSON ({e}): '{}'",
                fx.harness,
                fx.harness_version,
                stdout.trim()
            )
        })?;
        for dotted in &fx.required_stdout_json_paths {
            if resolve_dotted_json_path(&parsed, dotted).is_none() {
                return Err(format!(
                    "[{} {}] missing required wire field '{dotted}' in '{}'",
                    fx.harness,
                    fx.harness_version,
                    stdout.trim()
                ));
            }
        }
    }

    if !fx.expected_stdout_substring.is_empty() && !stdout.contains(&fx.expected_stdout_substring) {
        return Err(format!(
            "[{} {}] missing expected stdout substring '{}' in stdout='{}' (stderr='{}')",
            fx.harness,
            fx.harness_version,
            fx.expected_stdout_substring,
            stdout.trim(),
            stderr.trim()
        ));
    }

    Ok(format!(
        "Verified {} ({}) wire schema contract ({} paths)",
        fx.harness,
        fx.harness_version,
        fx.required_stdout_json_paths.len()
    ))
}

fn run_mcp_gateway_contract(
    workspace_root: &Path,
    agent_guard_bin: &Path,
) -> Result<String, String> {
    let sb = TestSandbox::create(workspace_root, "contract_mcp_gateway")?;
    sb.write_repo_file("src/hello.rs", "pub fn answer() -> u32 { 42 }\n")?;

    let requests = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"dotagent_read_file","arguments":{"path":"src/hello.rs"}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"dotagent_read_file","arguments":{"path":".env"}}}"#,
    ];
    let payload = format!("{}\n", requests.join("\n"));

    let mut cmd = Command::new(agent_guard_bin);
    sb.configure_isolated_command(&mut cmd);
    cmd.current_dir(&sb.repo_dir)
        .args(["mcp-gateway", "--cwd"])
        .arg(&sb.repo_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed spawning mcp-gateway: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(payload.as_bytes())
            .map_err(|e| format!("stdin write error: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("wait error: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "mcp-gateway exited non-zero: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let lines: Vec<&str> = std::str::from_utf8(&out.stdout)
        .map_err(|_| "non-UTF8 mcp-gateway stdout".to_string())?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    if lines.len() != 4 {
        return Err(format!(
            "expected 4 JSON-RPC responses (notification omitted), got {}",
            lines.len()
        ));
    }
    if !lines[2].contains("UNTRUSTED_ASCII_DATA_") || !lines[2].contains("pub fn answer") {
        return Err(format!(
            "mediated dotagent_read_file response missing 128-bit spotlighting: {}",
            lines[2]
        ));
    }
    if !lines[3].contains("\"isError\":true") {
        return Err(format!(
            "mediated .env read must return isError=true: {}",
            lines[3]
        ));
    }

    Ok("Verified JSON-RPC 2.0 mcp-gateway initialize, tools/list, spotlighted read, and .env block".to_string())
}

fn run_stop_receipt_contract(
    workspace_root: &Path,
    agent_guard_bin: &Path,
) -> Result<String, String> {
    let sb = TestSandbox::create(workspace_root, "contract_stop_receipt")?;
    let _ = fs::remove_dir_all(sb.repo_dir.join(".git"));
    let _ = Command::new("git")
        .current_dir(&sb.repo_dir)
        .args(["init", "-q"])
        .status();
    let agents_body = fs::read_to_string(workspace_root.join("AGENTS.md"))
        .map_err(|e| format!("read AGENTS.md: {e}"))?;
    sb.write_repo_file("AGENTS.md", &agents_body)?;
    sb.write_repo_file("src/lib.rs", "pub const V: u32 = 2;\n")?;
    if let Ok(manifest_body) =
        fs::read_to_string(workspace_root.join("dist-verify/manifest.sha256"))
    {
        sb.write_repo_file("dist-verify/manifest.sha256", &manifest_body)?;
    }

    let receipt_path = sb.root.join("stop.receipt.json");
    let mut stop_cmd = Command::new(agent_guard_bin);
    sb.configure_isolated_command(&mut stop_cmd);
    let stop_out = stop_cmd
        .current_dir(&sb.repo_dir)
        .arg("on-stop")
        .arg("--receipt-out")
        .arg(&receipt_path)
        .output()
        .map_err(|e| format!("failed running on-stop: {e}"))?;
    if !stop_out.status.success() {
        return Err(format!(
            "on-stop failed: stdout={} stderr={}",
            String::from_utf8_lossy(&stop_out.stdout),
            String::from_utf8_lossy(&stop_out.stderr)
        ));
    }

    let mut pk_cmd = Command::new(agent_guard_bin);
    sb.configure_isolated_command(&mut pk_cmd);
    let pk_out = pk_cmd
        .current_dir(&sb.repo_dir)
        .args(["receipt-pubkey", "--repo"])
        .arg(&sb.repo_dir)
        .output()
        .map_err(|e| format!("failed running receipt-pubkey: {e}"))?;
    if !pk_out.status.success() {
        return Err(format!(
            "receipt-pubkey failed: {}",
            String::from_utf8_lossy(&pk_out.stderr)
        ));
    }
    let pubkey_hex = String::from_utf8_lossy(&pk_out.stdout).trim().to_string();

    let mut ver_cmd = Command::new(agent_guard_bin);
    sb.configure_isolated_command(&mut ver_cmd);
    let ver_out = ver_cmd
        .current_dir(&sb.repo_dir)
        .arg("verify-receipt")
        .arg(&receipt_path)
        .arg("--repo")
        .arg(&sb.repo_dir)
        .arg("--pubkey")
        .arg(&pubkey_hex)
        .output()
        .map_err(|e| format!("failed running verify-receipt: {e}"))?;
    if !ver_out.status.success() {
        return Err(format!(
            "verify-receipt failed on clean tree: {}",
            String::from_utf8_lossy(&ver_out.stderr)
        ));
    }

    // Unpinned verification without --pubkey on a clean host state dir MUST fail closed (exit 2)!
    let empty_state = sb.root.join("unpinned_verifier_state");
    let _ = fs::create_dir_all(&empty_state);
    let mut unpinned_cmd = Command::new(agent_guard_bin);
    sb.configure_isolated_command(&mut unpinned_cmd);
    let unpinned_out = unpinned_cmd
        .current_dir(&sb.repo_dir)
        .env("AGENT_GUARD_STATE_DIR", &empty_state)
        .env_remove("DOTAGENT_RECEIPT_PUBKEY")
        .arg("verify-receipt")
        .arg(&receipt_path)
        .arg("--repo")
        .arg(&sb.repo_dir)
        .output()
        .map_err(|e| format!("failed running unpinned verify-receipt: {e}"))?;
    if unpinned_out.status.code() != Some(2) {
        return Err(
            "verify-receipt without pinned pubkey did not fail closed with exit 2".to_string(),
        );
    }

    // Mutate worktree after receipt -> verify-receipt MUST reject with exit 2 (`RECEIPT_WORKTREE_DRIFT`)!
    sb.write_repo_file("src/lib.rs", "pub const V: u32 = 999;\n")?;
    let mut drift_cmd = Command::new(agent_guard_bin);
    sb.configure_isolated_command(&mut drift_cmd);
    let drift_out = drift_cmd
        .current_dir(&sb.repo_dir)
        .arg("verify-receipt")
        .arg(&receipt_path)
        .arg("--repo")
        .arg(&sb.repo_dir)
        .arg("--pubkey")
        .arg(&pubkey_hex)
        .output()
        .map_err(|e| format!("failed running drift verify-receipt: {e}"))?;
    if drift_out.status.code() != Some(2) {
        return Err("post-receipt worktree mutation was not rejected with exit 2".to_string());
    }

    Ok("Verified Ed25519 StopReceipt emission on on-stop, pinned --pubkey verification, unpinned key rejection, and post-stop worktree drift rejection".to_string())
}

fn resolve_dotted_json_path<'a>(root: &'a JsonValue, dotted: &str) -> Option<&'a JsonValue> {
    let mut cur = root;
    for seg in dotted.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

fn strip_contract_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    for (idx, b) in line.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_double {
            if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_double = false;
            }
            continue;
        }
        if in_single {
            if b == b'\'' {
                in_single = false;
            }
            continue;
        }
        match b {
            b'\'' => in_single = true,
            b'"' => in_double = true,
            b'#' => return line[..idx].trim(),
            _ => {}
        }
    }
    line.trim()
}

fn load_wire_contract_fixtures(workspace_root: &Path) -> Result<Vec<WireContractFixture>, String> {
    let path = workspace_root
        .join("tests")
        .join("harness_contracts")
        .join("upstream_wire_contracts_v2.toml");
    let raw = fs::read_to_string(&path)
        .map_err(|e| format!("failed reading '{}': {e}", path.display()))?;

    let mut out = Vec::new();
    let mut cur_fields: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    let mut cur_arrays: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut in_block = false;

    let flush = |fields: &mut std::collections::BTreeMap<String, String>,
                 arrays: &mut std::collections::BTreeMap<String, Vec<String>>,
                 acc: &mut Vec<WireContractFixture>|
     -> Result<(), String> {
        let id = fields
            .remove("id")
            .ok_or_else(|| "contract block missing 'id'".to_string())?;
        let harness = fields
            .remove("harness")
            .unwrap_or_else(|| "unknown".to_string());
        let harness_version = fields
            .remove("harness_version")
            .unwrap_or_else(|| "v1".to_string());
        let subcommand = fields
            .remove("subcommand")
            .unwrap_or_else(|| "pre-tool".to_string());
        let stdin_json = fields.remove("stdin_json").unwrap_or_default();
        let profile_env = fields.remove("profile_env");
        let expected_exit_raw = fields
            .remove("expected_exit")
            .ok_or_else(|| format!("contract '{id}' missing mandatory 'expected_exit'"))?;
        let expected_exit = expected_exit_raw.parse::<i32>().map_err(|_| {
            format!("contract '{id}' has invalid integer expected_exit='{expected_exit_raw}'")
        })?;
        let required_stdout_json_paths = arrays
            .remove("required_stdout_json_paths")
            .unwrap_or_default();
        let expected_stdout_substring = fields
            .remove("expected_stdout_substring")
            .unwrap_or_default();
        fields.clear();
        arrays.clear();
        acc.push(WireContractFixture {
            id,
            harness,
            harness_version,
            subcommand,
            stdin_json,
            profile_env,
            expected_exit,
            required_stdout_json_paths,
            expected_stdout_substring,
        });
        Ok(())
    };

    for (line_idx, raw_line) in raw.lines().enumerate() {
        let line = strip_contract_comment(raw_line);
        if line.is_empty() {
            continue;
        }
        if line == "[[contract]]" {
            if in_block {
                flush(&mut cur_fields, &mut cur_arrays, &mut out)?;
            }
            in_block = true;
            continue;
        }
        let Some((k_raw, v_raw)) = line.split_once('=') else {
            return Err(format!(
                "malformed contract line {} in '{}': '{line}'",
                line_idx + 1,
                path.display()
            ));
        };
        let key = k_raw.trim().to_string();
        let val = v_raw.trim();
        if val.starts_with('[') && val.ends_with(']') {
            let parsed = JsonValue::parse(val)
                .map_err(|e| format!("invalid contract array for '{key}': {e}"))?;
            let vec_s: Vec<String> = parsed
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(JsonValue::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            cur_arrays.insert(key, vec_s);
        } else if val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2 {
            cur_fields.insert(key, val[1..val.len() - 1].to_string());
        } else if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
            match JsonValue::parse(val) {
                Ok(JsonValue::Str(s)) => {
                    cur_fields.insert(key, s);
                }
                Err(e) => {
                    return Err(format!(
                        "invalid quoted contract string for '{key}' at line {}: {e}",
                        line_idx + 1
                    ));
                }
                _ => {
                    return Err(format!(
                        "unexpected non-string JSON literal for '{key}' at line {}",
                        line_idx + 1
                    ));
                }
            }
        } else {
            cur_fields.insert(key, val.to_string());
        }
    }
    if in_block {
        flush(&mut cur_fields, &mut cur_arrays, &mut out)?;
    }
    Ok(out)
}
