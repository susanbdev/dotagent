//! Reproducible latency (`p50` / `p95` / `p99`) & throughput (`MiB/s`) microbenchmark suite.
//!
//! Measures real end-to-end performance across the four primary hot paths:
//! 1. `pre_tool_read_hook` (in-process JSON parse + path policy + session ledger + Unicode/budget inspection)
//! 2. `pre_tool_bash_ast` (in-process JSON parse + shell lexer/AST + git/network/depth policy)
//! 3. `post_tool_scan` (in-process untrusted output injection + Unicode + compaction gate)
//! 4. `ascii_stream_sanitizer_64k` (`sanitize_and_compact_bytes` throughput in `MiB/s` on 64 KiB mixed stream)
//! 5. `cli_pre_tool_cold_start` (full OS process spawn + stdin JSON hook + stdout decision exit)

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use agent_guard::json::JsonValue;
use agent_guard::sanitizer::{
    DEFAULT_COMPACT_STREAM_MAX_BYTES, DEFAULT_COMPACT_STREAM_MAX_LINES, sanitize_and_compact_bytes,
};
use agent_guard::{handle_post_tool_hook, handle_pre_tool_hook};

use crate::{HarnessConfig, ReportFormat, resolve_workspace_binaries};

#[derive(Debug, Clone)]
pub struct BenchMetric {
    pub name: &'static str,
    pub iterations: usize,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub throughput_mib_s: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct BenchReport {
    pub metrics: Vec<BenchMetric>,
}

struct TempBenchDir(PathBuf);

impl Drop for TempBenchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn run_benchmarks(cfg: &HarnessConfig, quick: bool) -> Result<BenchReport, String> {
    let bins = resolve_workspace_binaries(cfg)?;
    let sb = cfg
        .workspace_root
        .join("target")
        .join("test-workspaces")
        .join(format!("tbench-{}", std::process::id()));
    let _ = fs::remove_dir_all(&sb);
    let _cleanup = TempBenchDir(sb.clone());
    let home = sb.join("h");
    let state_dir = sb.join("state");
    let repo = sb.join("repo");
    fs::create_dir_all(&home).map_err(|e| format!("create bench home: {e}"))?;
    fs::create_dir_all(&state_dir).map_err(|e| format!("create bench state: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700));
    }
    fs::create_dir_all(repo.join("src")).map_err(|e| format!("create bench repo: {e}"))?;

    let init = Command::new("git")
        .arg("init")
        .arg(&repo)
        .env("HOME", &home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .map_err(|e| format!("git init bench repo: {e}"))?;
    if !init.status.success() {
        return Err("git init failed in bench repo".to_string());
    }

    fs::write(repo.join("AGENTS.md"), "# Canonical Root Authority\n")
        .map_err(|e| format!("write AGENTS.md: {e}"))?;
    let mut sample_rs = String::new();
    for idx in 0..80 {
        sample_rs.push_str(&format!(
            "pub fn compute_slot_{idx}(x: u64) -> u64 {{ x.wrapping_mul(6364136223846793005).wrapping_add({idx}) }}\n"
        ));
    }
    fs::write(repo.join("src/lib.rs"), &sample_rs).map_err(|e| format!("write src/lib.rs: {e}"))?;

    let in_proc_iters = if quick { 60 } else { 400 };
    let cli_iters = if quick { 12 } else { 50 };
    let run_nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_nanos() as u64) ^ u64::from(std::process::id()))
        .unwrap_or(0);

    let mut metrics = Vec::with_capacity(7);

    // 1. In-process PreToolUse (Read) — rotate session_id every 4 calls so turn-read caps aren't tripped
    let mut read_samples = Vec::with_capacity(in_proc_iters);
    for i in 0..in_proc_iters {
        let sid = format!("bench_r_{run_nonce:x}_{}", i / 4);
        let payload = format!(
            "{{\"session_id\":\"{sid}\",\"tool_name\":\"Read\",\"tool_input\":{{\"file_path\":\"src/lib.rs\",\"offset\":1,\"limit\":60}}}}"
        );
        let t0 = Instant::now();
        let dec = handle_pre_tool_hook(&payload, &repo);
        read_samples.push(t0.elapsed().as_micros() as u64);
        if matches!(dec, agent_guard::Decision::Deny { .. }) {
            return Err(format!(
                "unexpected deny in pre_tool_read_hook benchmark: {dec:?}"
            ));
        }
    }
    metrics.push(compute_percentiles(
        "pre_tool_read_hook_inproc",
        read_samples,
        None,
    ));

    // 2. In-process PreToolUse (Bash AST validation)
    let mut bash_samples = Vec::with_capacity(in_proc_iters);
    for i in 0..in_proc_iters {
        let sid = format!("bench_b_{run_nonce:x}_{}", i / 4);
        let payload = format!(
            "{{\"session_id\":\"{sid}\",\"tool_name\":\"Bash\",\"tool_input\":{{\"command\":\"rg --max-depth 2 compute_slot src\"}}}}"
        );
        let t0 = Instant::now();
        let dec = handle_pre_tool_hook(&payload, &repo);
        bash_samples.push(t0.elapsed().as_micros() as u64);
        if matches!(dec, agent_guard::Decision::Deny { .. }) {
            return Err(format!(
                "unexpected deny in pre_tool_bash_ast benchmark: {dec:?}"
            ));
        }
    }
    metrics.push(compute_percentiles(
        "pre_tool_bash_ast_inproc",
        bash_samples,
        None,
    ));

    // 3. In-process PostToolUse output scanner
    let mut post_samples = Vec::with_capacity(in_proc_iters);
    for i in 0..in_proc_iters {
        let post_payload = format!(
            "{{\"session_id\":\"bench_p_{run_nonce:x}_{}\",\"tool_name\":\"Bash\",\"tool_response\":\"src/lib.rs:1:pub fn compute_slot_0(x: u64) -> u64\\nsrc/lib.rs:2:pub fn compute_slot_1(x: u64) -> u64\\n\"}}",
            i / 12
        );
        let t0 = Instant::now();
        let dec = handle_post_tool_hook(&post_payload, &repo);
        post_samples.push(t0.elapsed().as_micros() as u64);
        if matches!(dec, agent_guard::Decision::Deny { .. }) {
            return Err(format!(
                "unexpected deny in post_tool_scan benchmark: {dec:?}"
            ));
        }
    }
    metrics.push(compute_percentiles(
        "post_tool_scan_inproc",
        post_samples,
        None,
    ));

    // 4. 64 KiB stream sanitizer & compactor throughput (MiB/s)
    let mut stream_64k = Vec::with_capacity(65_536);
    while stream_64k.len() < 65_536 {
        stream_64k.extend_from_slice(
            b"2026-11-18T16:00:00Z INFO crate::engine \x1b[32mok\x1b[0m latency_us=42 path=src/lib.rs\n",
        );
    }
    stream_64k.truncate(65_536);
    let mut san_samples = Vec::with_capacity(in_proc_iters);
    for _ in 0..in_proc_iters {
        let t0 = Instant::now();
        let out = sanitize_and_compact_bytes(
            &stream_64k,
            DEFAULT_COMPACT_STREAM_MAX_LINES,
            DEFAULT_COMPACT_STREAM_MAX_BYTES,
        );
        san_samples.push(t0.elapsed().as_micros() as u64);
        if out.clean_ascii.is_empty() {
            return Err("empty sanitizer output in benchmark".to_string());
        }
    }
    let mut sorted_san = san_samples.clone();
    sorted_san.sort_unstable();
    let p50_san_us = percentile_sorted(&sorted_san, 50).max(1);
    let mib_per_call = (stream_64k.len() as f64) / (1024.0 * 1024.0);
    let throughput_mib_s = mib_per_call / ((p50_san_us as f64) / 1_000_000.0);
    metrics.push(compute_percentiles(
        "sanitize_stream_64k",
        san_samples,
        Some(throughput_mib_s),
    ));

    // 5. Warm Unix socket RPC roundtrip (`coord_sock_warm_rpc` over host `hook-daemon`)
    #[cfg(unix)]
    {
        let sock_path = state_dir.join("daemon/hook.sock");
        let mut daemon = Command::new(&bins.agent_guard)
            .args(["hook-daemon", "--idle-secs", "15"])
            .current_dir(&repo)
            .env_remove("LD_LIBRARY_PATH")
            .env_remove("DYLD_LIBRARY_PATH")
            .env_remove("DYLD_FALLBACK_LIBRARY_PATH")
            .env("HOME", &home)
            .env("AGENT_GUARD_STATE_DIR", &state_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn hook-daemon for benchmark: {e}"))?;

        let wait_deadline = Instant::now() + Duration::from_secs(2);
        let mut ready = false;
        while Instant::now() < wait_deadline {
            if let Ok(mut s) = agent_guard::coordinator::connect_unix_short_path(&sock_path) {
                let _ = s.write_all(b"{\"op\":\"ping\"}\n");
                let mut r = BufReader::new(s);
                let mut line = String::new();
                if r.read_line(&mut line).is_ok() && line.contains("\"ok\":true") {
                    ready = true;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if !ready {
            let _ = daemon.kill();
            let _ = daemon.wait();
            return Err("hook-daemon socket failed to become ready in benchmark".to_string());
        }

        let repo_s = repo.to_string_lossy().into_owned();
        let mut warm_rpc_samples = Vec::with_capacity(in_proc_iters);
        for i in 0..in_proc_iters {
            let sid = format!("bench_w_{run_nonce:x}_{}", i / 4);
            let hook_payload = format!(
                "{{\"session_id\":\"{sid}\",\"tool_name\":\"Bash\",\"tool_input\":{{\"command\":\"rg --max-depth 2 compute_slot src\"}}}}"
            );
            let rpc_line = JsonValue::Object(vec![
                ("op".to_string(), JsonValue::Str("eval_hook".to_string())),
                ("phase".to_string(), JsonValue::Str("pre-tool".to_string())),
                ("payload".to_string(), JsonValue::Str(hook_payload)),
                ("repo_root".to_string(), JsonValue::Str(repo_s.clone())),
                ("cwd".to_string(), JsonValue::Str(repo_s.clone())),
            ])
            .to_json_string();

            let t0 = Instant::now();
            let mut stream = agent_guard::coordinator::connect_unix_short_path(&sock_path)
                .map_err(|e| format!("connect warm hook.sock: {e}"))?;
            stream
                .write_all(rpc_line.as_bytes())
                .and_then(|()| stream.write_all(b"\n"))
                .and_then(|()| stream.flush())
                .map_err(|e| format!("write warm hook.sock: {e}"))?;
            let mut resp_line = String::new();
            BufReader::new(stream)
                .read_line(&mut resp_line)
                .map_err(|e| format!("read warm hook.sock: {e}"))?;
            warm_rpc_samples.push(t0.elapsed().as_micros() as u64);
            if !resp_line.contains("\"allow\":true") {
                let _ = fs::remove_file(&sock_path);
                let _ = daemon.kill();
                let _ = daemon.wait();
                return Err(format!(
                    "unexpected response in coord_sock_warm_rpc benchmark: {resp_line}"
                ));
            }
        }
        let _ = fs::remove_file(&sock_path);
        let _ = daemon.wait();
        metrics.push(compute_percentiles(
            "coord_sock_warm_rpc",
            warm_rpc_samples,
            None,
        ));
    }

    // 6. Mediating MCP gateway JSON-RPC 2.0 stdio roundtrip (`mcp_gateway_stdio_roundtrip`)
    {
        let mut gw = Command::new(&bins.agent_guard)
            .arg("mcp-gateway")
            .arg("--cwd")
            .arg(&repo)
            .current_dir(&repo)
            .env_remove("LD_LIBRARY_PATH")
            .env_remove("DYLD_LIBRARY_PATH")
            .env_remove("DYLD_FALLBACK_LIBRARY_PATH")
            .env("HOME", &home)
            .env("AGENT_GUARD_STATE_DIR", &state_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn mcp-gateway for benchmark: {e}"))?;

        let mut gw_in = gw
            .stdin
            .take()
            .ok_or_else(|| "missing mcp-gateway stdin".to_string())?;
        let gw_out = gw
            .stdout
            .take()
            .ok_or_else(|| "missing mcp-gateway stdout".to_string())?;
        let mut gw_reader = BufReader::new(gw_out);

        gw_in
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"bench\",\"version\":\"1.0\"}}}\n",
            )
            .and_then(|()| gw_in.flush())
            .map_err(|e| format!("write mcp-gateway initialize: {e}"))?;
        let mut init_resp = String::new();
        gw_reader
            .read_line(&mut init_resp)
            .map_err(|e| format!("read mcp-gateway initialize: {e}"))?;
        if !init_resp.contains("dotagent-mcp-gateway") {
            drop(gw_in);
            let _ = gw.kill();
            let _ = gw.wait();
            return Err(format!("unexpected mcp-gateway init response: {init_resp}"));
        }

        let mut mcp_samples = Vec::with_capacity(in_proc_iters);
        for i in 0..in_proc_iters {
            let call_line = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{},\"method\":\"tools/call\",\"params\":{{\"name\":\"dotagent_status\",\"arguments\":{{}}}}}}\n",
                i + 1
            );
            let t0 = Instant::now();
            gw_in
                .write_all(call_line.as_bytes())
                .and_then(|()| gw_in.flush())
                .map_err(|e| format!("write mcp-gateway tools/call: {e}"))?;
            let mut call_resp = String::new();
            gw_reader
                .read_line(&mut call_resp)
                .map_err(|e| format!("read mcp-gateway tools/call: {e}"))?;
            mcp_samples.push(t0.elapsed().as_micros() as u64);
            if !call_resp.contains("\"result\"") {
                drop(gw_in);
                let _ = gw.kill();
                let _ = gw.wait();
                return Err(format!(
                    "unexpected mcp-gateway tools/call response: {call_resp}"
                ));
            }
        }
        drop(gw_in);
        let _ = gw.wait();
        metrics.push(compute_percentiles(
            "mcp_gateway_stdio_roundtrip",
            mcp_samples,
            None,
        ));
    }

    // 7. End-to-end `agent-guard pre-tool` OS process cold-start latency
    let mut cli_samples = Vec::with_capacity(cli_iters);
    for i in 0..cli_iters {
        let req = format!(
            "{{\"session_id\":\"bench_cli_{}\",\"tool_name\":\"Bash\",\"tool_input\":{{\"command\":\"git log -n 5\"}}}}",
            i / 10
        );
        let t0 = Instant::now();
        let mut child = Command::new(&bins.agent_guard)
            .arg("pre-tool")
            .current_dir(&repo)
            .env_remove("LD_LIBRARY_PATH")
            .env_remove("DYLD_LIBRARY_PATH")
            .env_remove("DYLD_FALLBACK_LIBRARY_PATH")
            .env("HOME", &home)
            .env("AGENT_GUARD_STATE_DIR", &state_dir)
            .env("DOTAGENT_NO_AUTO_COORD", "1")
            .env(
                "GIT_CONFIG_GLOBAL",
                cfg.workspace_root.join("dist/gitconfig.hardened"),
            )
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn agent-guard pre-tool: {e}"))?;
        if let Some(mut sin) = child.stdin.take() {
            sin.write_all(req.as_bytes())
                .map_err(|e| format!("write stdin: {e}"))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("wait agent-guard: {e}"))?;
        cli_samples.push(t0.elapsed().as_micros() as u64);
        if !out.status.success() {
            return Err(format!(
                "cli_pre_tool_cold_start failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }
    metrics.push(compute_percentiles(
        "cli_pre_tool_cold_start",
        cli_samples,
        None,
    ));

    Ok(BenchReport { metrics })
}

fn compute_percentiles(
    name: &'static str,
    mut samples_us: Vec<u64>,
    throughput_mib_s: Option<f64>,
) -> BenchMetric {
    samples_us.sort_unstable();
    let iterations = samples_us.len();
    BenchMetric {
        name,
        iterations,
        p50_us: percentile_sorted(&samples_us, 50),
        p95_us: percentile_sorted(&samples_us, 95),
        p99_us: percentile_sorted(&samples_us, 99),
        throughput_mib_s,
    }
}

fn percentile_sorted(sorted: &[u64], pct: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) * pct) / 100;
    sorted[idx]
}

pub fn render_bench_report(report: &BenchReport, format: ReportFormat) -> String {
    match format {
        ReportFormat::Text => {
            let mut out = String::from(
                "Benchmark                       Iters    p50 (us)   p95 (us)   p99 (us)   Throughput\n\
                 ------------------------------  ------  ---------  ---------  ---------  ------------\n",
            );
            for m in &report.metrics {
                let tp = m
                    .throughput_mib_s
                    .map(|v| format!("{v:>7.1} MiB/s"))
                    .unwrap_or_else(|| "      -".to_string());
                out.push_str(&format!(
                    "{:<30}  {:>6}  {:>9}  {:>9}  {:>9}  {}\n",
                    m.name, m.iterations, m.p50_us, m.p95_us, m.p99_us, tp
                ));
            }
            out
        }
        ReportFormat::Json => {
            let items: Vec<JsonValue> = report
                .metrics
                .iter()
                .map(|m| {
                    let mut fields = vec![
                        ("name".to_string(), JsonValue::Str(m.name.to_string())),
                        (
                            "iterations".to_string(),
                            JsonValue::Uint(m.iterations as u64),
                        ),
                        ("p50_us".to_string(), JsonValue::Uint(m.p50_us)),
                        ("p95_us".to_string(), JsonValue::Uint(m.p95_us)),
                        ("p99_us".to_string(), JsonValue::Uint(m.p99_us)),
                    ];
                    if let Some(tp) = m.throughput_mib_s {
                        fields.push((
                            "throughput_mib_s".to_string(),
                            JsonValue::Str(format!("{tp:.2}")),
                        ));
                    }
                    JsonValue::Object(fields)
                })
                .collect();
            JsonValue::Object(vec![("benchmarks".to_string(), JsonValue::Array(items))])
                .to_json_string()
        }
    }
}
