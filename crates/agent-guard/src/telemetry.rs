#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! Human-TTY-Gated Operator Security Telemetry & Audit Log Rotation (`Pillar 5`).
//!
//! Preserves 100% AI agent self-blindness (`GUARD_SELF_BLINDNESS`):
//! - Any invocation from a non-interactive pipe/socket (`!stdin.is_terminal() || !stdout.is_terminal()`),
//!   from inside `exec-sandbox` (`AGENT_GUARD_IN_SANDBOX=1`), or with any AI harness / CI environment
//!   variable active is **hard-denied with exit code 2** before touching `~/.local/state/agent-guard`.
//! - Human operators at an interactive terminal gain instant visibility into deny distributions,
//!   circuit-breaker trips, session token burn, bounded `audit.jsonl` rotation, and OpenTelemetry
//!   (`OTLP/JSON`) metrics export for `susanbdev/control-center`.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Cursor, IsTerminal, Read};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::json::JsonValue;
use crate::path_policy::{PathAccess, check_forbidden_zones_lexical, validate_path};

pub(crate) mod capture;
pub(crate) mod controls;
mod diagnostics;
pub(crate) mod observations;
pub(crate) mod protocol;
#[cfg(all(unix, feature = "collector-fixture"))]
#[doc(hidden)]
pub mod release_probe;
pub(crate) mod runtime;
mod runtime_health;
pub(crate) mod store;
#[cfg(unix)]
pub(crate) mod transport;

pub(crate) const AGENT_SANDBOX_AND_HARNESS_MARKERS: &[&str] = &[
    "AGENT_GUARD_IN_SANDBOX",
    "AGENT_GUARD_WORKER_LOCK",
    "AGENT_GUARD_ROLE",
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "CURSOR_TRACE_ID",
    "CURSOR_AGENT",
    "CODEX_SANDBOX",
    "CODEX_ENV_SANDBOX",
    "GEMINI_CLI",
    "ANTIGRAVITY_AGENT",
];

const AGENT_HARNESS_ENV_MARKERS: &[&str] = &[
    "AGENT_GUARD_IN_SANDBOX",
    "AGENT_GUARD_WORKER_LOCK",
    "AGENT_GUARD_ROLE",
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "CURSOR_TRACE_ID",
    "CURSOR_AGENT",
    "CODEX_SANDBOX",
    "CODEX_ENV_SANDBOX",
    "GEMINI_CLI",
    "ANTIGRAVITY_AGENT",
    "CI",
    "GITHUB_ACTIONS",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditSummary {
    pub total_events: usize,
    pub halted_events: usize,
    pub unique_sessions: usize,
    pub unique_repos: usize,
    pub min_ts: Option<u64>,
    pub max_ts: Option<u64>,
    pub counts_by_code: BTreeMap<String, usize>,
    pub counts_by_tool: BTreeMap<String, usize>,
}

impl AuditSummary {
    pub fn top_denies(&self, limit: usize) -> Vec<(String, usize)> {
        let mut pairs: Vec<(String, usize)> = self
            .counts_by_code
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        pairs.truncate(limit);
        pairs
    }

    pub fn to_json_value(&self) -> JsonValue {
        let code_entries: Vec<(String, JsonValue)> = self
            .counts_by_code
            .iter()
            .map(|(k, v)| (k.clone(), JsonValue::Uint(*v as u64)))
            .collect();
        let tool_entries: Vec<(String, JsonValue)> = self
            .counts_by_tool
            .iter()
            .map(|(k, v)| (k.clone(), JsonValue::Uint(*v as u64)))
            .collect();
        JsonValue::Object(vec![
            (
                "total_events".to_string(),
                JsonValue::Uint(self.total_events as u64),
            ),
            (
                "halted_events".to_string(),
                JsonValue::Uint(self.halted_events as u64),
            ),
            (
                "unique_sessions".to_string(),
                JsonValue::Uint(self.unique_sessions as u64),
            ),
            (
                "unique_repos".to_string(),
                JsonValue::Uint(self.unique_repos as u64),
            ),
            (
                "min_ts".to_string(),
                self.min_ts.map_or(JsonValue::Null, JsonValue::Uint),
            ),
            (
                "max_ts".to_string(),
                self.max_ts.map_or(JsonValue::Null, JsonValue::Uint),
            ),
            (
                "counts_by_code".to_string(),
                JsonValue::Object(code_entries),
            ),
            (
                "counts_by_tool".to_string(),
                JsonValue::Object(tool_entries),
            ),
        ])
    }
}

/// Enforces `GUARD_SELF_BLINDNESS`: only an interactive human terminal outside all agent/sandbox/CI
/// contexts may query or rotate operator telemetry.
pub fn verify_human_tty_telemetry_gate() -> Result<(), (&'static str, String)> {
    for marker in AGENT_HARNESS_ENV_MARKERS {
        if let Ok(val) = std::env::var(marker)
            && !val.trim().is_empty()
            && val.trim() != "0"
            && !val.trim().eq_ignore_ascii_case("false")
        {
            return Err((
                "TELEMETRY_AGENT_BLINDNESS_ENFORCED",
                format!(
                    "dotagent telemetry is strictly human-operator-only; blocked due to active agent/sandbox/CI marker '{marker}'."
                ),
            ));
        }
    }

    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err((
            "TELEMETRY_REQUIRES_HUMAN_TTY",
            "dotagent telemetry requires an interactive human TTY (stdin and stdout must be terminals) to preserve AI agent self-blindness."
                .to_string(),
        ));
    }

    Ok(())
}

/// Pure deterministic aggregation over `audit.jsonl` content with optional repository filter.
pub fn analyze_audit_jsonl_str(raw: &str, repo_filter: Option<&str>) -> AuditSummary {
    let mut cursor = Cursor::new(raw.as_bytes());
    analyze_audit_jsonl_reader(&mut cursor, repo_filter)
}

/// Streaming line-by-line aggregation over any `BufRead` without loading multi-MiB logs into RAM.
pub fn analyze_audit_jsonl_reader<R: BufRead>(
    reader: &mut R,
    repo_filter: Option<&str>,
) -> AuditSummary {
    let mut summary = AuditSummary::default();
    let mut sessions = std::collections::BTreeSet::new();
    let mut repos = std::collections::BTreeSet::new();
    let mut line = String::new();

    loop {
        line.clear();
        let Ok(n) = (&mut *reader).take(65_536).read_line(&mut line) else {
            break;
        };
        if n == 0 {
            break;
        }
        if n >= 65_536 && !line.ends_with('\n') {
            // Drain remainder of oversized corrupt line without unbounded allocation.
            let mut discard = [0u8; 4096];
            loop {
                match reader.read(&mut discard) {
                    Ok(0) | Err(_) => break,
                    Ok(k) => {
                        if discard[..k].contains(&b'\n') {
                            break;
                        }
                    }
                }
            }
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(val) = JsonValue::parse(trimmed) else {
            continue;
        };
        if val.get("schema_version").is_some() {
            continue;
        }
        let repo = val.get("repo").and_then(JsonValue::as_str).unwrap_or("");
        if let Some(filter) = repo_filter
            && !repo.contains(filter) && repo != crate::crypto::sha256_hex(filter.as_bytes())
        {
            continue;
        }
        summary.total_events += 1;
        if val.get("halted").and_then(JsonValue::as_bool) == Some(true) {
            summary.halted_events += 1;
        }
        if !repo.is_empty() {
            repos.insert(repo.to_string());
        }
        if let Some(sid) = val
            .get("session_hash")
            .or_else(|| val.get("session_id"))
            .and_then(JsonValue::as_str)
            && !sid.is_empty()
        {
            sessions.insert(sid.to_string());
        }
        if let Some(ts) = val.get("ts").and_then(JsonValue::as_u64) {
            summary.min_ts = Some(summary.min_ts.map_or(ts, |m| m.min(ts)));
            summary.max_ts = Some(summary.max_ts.map_or(ts, |m| m.max(ts)));
        }
        let code = val
            .get("code")
            .and_then(JsonValue::as_str)
            .unwrap_or("UNKNOWN");
        *summary.counts_by_code.entry(code.to_string()).or_insert(0) += 1;
        let tool = val
            .get("tool")
            .and_then(JsonValue::as_str)
            .unwrap_or("UNKNOWN");
        *summary.counts_by_tool.entry(tool.to_string()).or_insert(0) += 1;
    }

    summary.unique_sessions = sessions.len();
    summary.unique_repos = repos.len();
    summary
}

/// Renders an OpenTelemetry (`OTLP/JSON` v1) metrics export payload for `susanbdev/control-center`.
pub fn render_otlp_export_json(summary: &AuditSummary, exported_at_ns: u64) -> JsonValue {
    let code_points: Vec<JsonValue> = summary
        .counts_by_code
        .iter()
        .map(|(code, count)| {
            JsonValue::Object(vec![
                (
                    "attributes".to_string(),
                    JsonValue::Array(vec![JsonValue::Object(vec![
                        ("key".to_string(), JsonValue::Str("guard.code".to_string())),
                        (
                            "value".to_string(),
                            JsonValue::Object(vec![(
                                "stringValue".to_string(),
                                JsonValue::Str(code.clone()),
                            )]),
                        ),
                    ])]),
                ),
                (
                    "timeUnixNano".to_string(),
                    JsonValue::Str(exported_at_ns.to_string()),
                ),
                (
                    "asInt".to_string(),
                    JsonValue::Str((*count as u64).to_string()),
                ),
            ])
        })
        .collect();

    let metrics = vec![
        JsonValue::Object(vec![
            (
                "name".to_string(),
                JsonValue::Str("dotagent.guard.events.total".to_string()),
            ),
            (
                "sum".to_string(),
                JsonValue::Object(vec![
                    ("isMonotonic".to_string(), JsonValue::Bool(true)),
                    (
                        "aggregationTemporality".to_string(),
                        JsonValue::Uint(2), // AGGREGATION_TEMPORALITY_CUMULATIVE
                    ),
                    ("dataPoints".to_string(), JsonValue::Array(code_points)),
                ]),
            ),
        ]),
        JsonValue::Object(vec![
            (
                "name".to_string(),
                JsonValue::Str("dotagent.guard.circuit_breaker.halts".to_string()),
            ),
            (
                "gauge".to_string(),
                JsonValue::Object(vec![(
                    "dataPoints".to_string(),
                    JsonValue::Array(vec![JsonValue::Object(vec![
                        (
                            "timeUnixNano".to_string(),
                            JsonValue::Str(exported_at_ns.to_string()),
                        ),
                        (
                            "asInt".to_string(),
                            JsonValue::Str((summary.halted_events as u64).to_string()),
                        ),
                    ])]),
                )]),
            ),
        ]),
    ];

    JsonValue::Object(vec![(
        "resourceMetrics".to_string(),
        JsonValue::Array(vec![JsonValue::Object(vec![
            (
                "resource".to_string(),
                JsonValue::Object(vec![(
                    "attributes".to_string(),
                    JsonValue::Array(vec![
                        JsonValue::Object(vec![
                            (
                                "key".to_string(),
                                JsonValue::Str("service.name".to_string()),
                            ),
                            (
                                "value".to_string(),
                                JsonValue::Object(vec![(
                                    "stringValue".to_string(),
                                    JsonValue::Str("dotagent-guard".to_string()),
                                )]),
                            ),
                        ]),
                        JsonValue::Object(vec![
                            (
                                "key".to_string(),
                                JsonValue::Str("service.version".to_string()),
                            ),
                            (
                                "value".to_string(),
                                JsonValue::Object(vec![(
                                    "stringValue".to_string(),
                                    JsonValue::Str(env!("CARGO_PKG_VERSION").to_string()),
                                )]),
                            ),
                        ]),
                    ]),
                )]),
            ),
            (
                "scopeMetrics".to_string(),
                JsonValue::Array(vec![JsonValue::Object(vec![
                    (
                        "scope".to_string(),
                        JsonValue::Object(vec![(
                            "name".to_string(),
                            JsonValue::Str("dotagent.telemetry".to_string()),
                        )]),
                    ),
                    ("metrics".to_string(), JsonValue::Array(metrics)),
                ])]),
            ),
        ])]),
    )])
}

/// Rotates the protected audit log under the same lock as its writer.
pub fn rotate_audit_log_at_path(
    audit_path: &Path,
    max_bytes: u64,
    keep_archives: usize,
) -> Result<bool, String> {
    store::rotate_at(audit_path, max_bytes, keep_archives).map_err(|error| error.to_string())
}

fn validate_telemetry_export_target(target: &str) -> Result<(), String> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err("empty --out path".to_string());
    }
    check_forbidden_zones_lexical(trimmed, trimmed)
        .map_err(|v| format!("{}: {}", v.code, v.detail))?;
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let repo_root = crate::resolve_repo_root(&cwd);
    let p = Path::new(trimmed);
    let full = if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    };
    if !p.is_absolute() || full.starts_with(&repo_root) {
        validate_path(&repo_root, &cwd, trimmed, PathAccess::Write)
            .map_err(|v| format!("{}: {}", v.code, v.detail))?;
    }
    let mut cur = PathBuf::new();
    for comp in full.components() {
        match comp {
            Component::RootDir | Component::Prefix(_) => cur.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::Normal(seg) => {
                cur.push(seg);
                if let Ok(meta) = fs::symlink_metadata(&cur)
                    && meta.file_type().is_symlink()
                {
                    return Err(format!(
                        "symlink component '{}' is forbidden",
                        cur.display()
                    ));
                }
            }
            Component::ParentDir => {
                return Err("'..' traversal in --out path is forbidden".to_string());
            }
        }
    }
    if let Ok(meta) = fs::symlink_metadata(&full) {
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            return Err("destination exists and is not a regular file".to_string());
        }
        if meta.permissions().readonly() {
            return Err(
                "destination is read-only (refusing to overwrite 0444 control file)".to_string(),
            );
        }
    }
    Ok(())
}

fn run_trace_cli(path: &Path, args: &[String]) -> ExitCode {
    let trace_id = match args {
        [] => None,
        [flag, id] if flag == "--trace-id" && capture::valid_id(id) => Some(id.as_str()),
        _ => {
            eprintln!("usage: dotagent telemetry trace [--trace-id ID]");
            return ExitCode::from(2);
        }
    };
    let report = match store::open_audit_read(path) {
        Ok(Some(file)) => diagnostics::analyze(&mut BufReader::new(file), trace_id),
        Ok(None) => {
            eprintln!("[DOTAGENT CAPTURE] No active audit file. Capture coverage is unavailable.");
            return ExitCode::from(2);
        }
        Err(_) => Err(io::Error::other("audit log unavailable")),
    };
    match report {
        Ok(report) => {
            println!("{}", report.to_json_string());
            ExitCode::SUCCESS
        }
        Err(_) => {
            eprintln!("[DOTAGENT CAPTURE] Protected audit log is unavailable.");
            ExitCode::from(2)
        }
    }
}

/// CLI entrypoint: `dotagent telemetry <summary|top-denies|baseline|trace|rotate|export-otlp> ...`
pub fn run_telemetry_cli(args: &[String]) -> ExitCode {
    if let Err((code, msg)) = verify_human_tty_telemetry_gate() {
        eprintln!("[AGENT-GUARD HARD DENY :: {code}] {msg}");
        return ExitCode::from(2);
    }

    let mut sshsig_file: Option<PathBuf> = None;
    let mut filtered: Vec<String> = Vec::with_capacity(args.len());
    let mut idx = 0usize;
    while idx < args.len() {
        if args[idx] == "--sshsig" {
            let Some(v) = args.get(idx + 1) else {
                eprintln!("[AGENT-GUARD HARD DENY :: SSHSIG_REQUIRED] missing path after --sshsig");
                return ExitCode::from(2);
            };
            sshsig_file = Some(PathBuf::from(v));
            idx += 2;
        } else {
            filtered.push(args[idx].clone());
            idx += 1;
        }
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let repo_root = crate::resolve_repo_root(&cwd);
    if let Err(ge) = crate::operator::verify_operator_sshsig_gate(
        &repo_root,
        "telemetry",
        sshsig_file.as_deref(),
    ) {
        eprintln!("[AGENT-GUARD HARD DENY :: {}] {}", ge.code, ge.detail);
        return ExitCode::from(2);
    }

    let args = filtered.as_slice();
    let sub = args.first().map(String::as_str).unwrap_or("summary");
    let audit_path = crate::traversal_ledger::audit_log_path();

    match sub {
        "baseline" => observations::run_baseline_cli(&args[1..], &repo_root),
        "trace" => run_trace_cli(&audit_path, &args[1..]),
        #[cfg(unix)]
        "delivery" => match transport::delivery_status() {
            Ok(status) => { println!("{}", status.to_json_string()); ExitCode::SUCCESS }
            Err(e) => { eprintln!("collector delivery status unavailable: {e}"); ExitCode::FAILURE }
        },
        "rotate" => {
            let mut max_bytes: u64 = 10 * 1024 * 1024; // 10 MiB default
            let mut keep: usize = 5;
            let mut i = 1usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--max-bytes" if i + 1 < args.len() => {
                        if let Ok(v) = args[i + 1].parse::<u64>() {
                            max_bytes = v;
                        }
                        i += 2;
                    }
                    "--keep" if i + 1 < args.len() => {
                        if let Ok(v) = args[i + 1].parse::<usize>() {
                            keep = v;
                        }
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            match rotate_audit_log_at_path(&audit_path, max_bytes, keep) {
                Ok(true) => {
                    println!(
                        "[DOTAGENT TELEMETRY] Rotated '{}' (threshold={} bytes, keep={}).",
                        audit_path.display(),
                        max_bytes,
                        keep
                    );
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    println!(
                        "[DOTAGENT TELEMETRY] No rotation needed for '{}' (below {} bytes).",
                        audit_path.display(),
                        max_bytes
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("[DOTAGENT TELEMETRY ERROR] {e}");
                    ExitCode::from(2)
                }
            }
        }
        "summary" | "top-denies" | "export-otlp" => {
            let json_mode = args.iter().any(|a| a == "--json");
            let mut repo_filter: Option<&str> = None;
            let mut limit: usize = 10;
            let mut out_file: Option<&str> = None;
            let mut i = 1usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--repo" if i + 1 < args.len() => {
                        repo_filter = Some(args[i + 1].as_str());
                        i += 2;
                    }
                    "--limit" if i + 1 < args.len() => {
                        if let Ok(n) = args[i + 1].parse::<usize>() {
                            limit = n.clamp(1, 100);
                        }
                        i += 2;
                    }
                    "--out" if i + 1 < args.len() => {
                        out_file = Some(args[i + 1].as_str());
                        i += 2;
                    }
                    _ => i += 1,
                }
            }

            let summary = match fs::symlink_metadata(&audit_path) {
                Ok(m) if !m.file_type().is_symlink() && m.file_type().is_file() => {
                    match File::open(&audit_path) {
                        Ok(f) => {
                            let mut br = BufReader::new(f);
                            analyze_audit_jsonl_reader(&mut br, repo_filter)
                        }
                        Err(_) => AuditSummary::default(),
                    }
                }
                _ => AuditSummary::default(),
            };

            if sub == "export-otlp" {
                let ns = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
                    .unwrap_or(0);
                let payload = render_otlp_export_json(&summary, ns).to_json_string();
                if let Some(target) = out_file {
                    if let Err(e) = validate_telemetry_export_target(target) {
                        eprintln!("[DOTAGENT TELEMETRY ERROR] refused writing '{target}': {e}");
                        return ExitCode::from(2);
                    }
                    let target_path = Path::new(target);
                    if let Err(e) = crate::coordinator::write_atomic_private_0600(
                        target_path,
                        format!("{payload}\n").as_bytes(),
                    ) {
                        eprintln!("[DOTAGENT TELEMETRY ERROR] failed writing '{target}': {e}");
                        return ExitCode::from(2);
                    }
                    println!("[DOTAGENT TELEMETRY] Exported OTLP metrics to '{target}'.");
                } else {
                    println!("{payload}");
                }
                return ExitCode::SUCCESS;
            }

            if sub == "top-denies" {
                let top = summary.top_denies(limit);
                if json_mode {
                    let items: Vec<JsonValue> = top
                        .into_iter()
                        .map(|(code, count)| {
                            JsonValue::Object(vec![
                                ("code".to_string(), JsonValue::Str(code)),
                                ("count".to_string(), JsonValue::Uint(count as u64)),
                            ])
                        })
                        .collect();
                    println!("{}", JsonValue::Array(items).to_json_string());
                } else {
                    println!(
                        "Top {} Guard Codes (total_events={}, halted={}):",
                        limit, summary.total_events, summary.halted_events
                    );
                    for (code, count) in top {
                        println!("  {count:>6}  {code}");
                    }
                }
                return ExitCode::SUCCESS;
            }

            if json_mode {
                println!("{}", summary.to_json_value().to_json_string());
            } else {
                println!(
                    "[DOTAGENT TELEMETRY SUMMARY] events={} halted={} sessions={} repos={}",
                    summary.total_events,
                    summary.halted_events,
                    summary.unique_sessions,
                    summary.unique_repos
                );
                for (code, count) in summary.top_denies(10) {
                    println!("  code {code}: {count}");
                }
            }
            ExitCode::SUCCESS
        }
        other => {
            eprintln!(
                "[DOTAGENT TELEMETRY] unrecognized subcommand '{other}' (expected summary | top-denies | rotate | export-otlp)"
            );
            ExitCode::from(2)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriageClusterItem {
    pub cluster_key: String,
    pub category: String,
    pub deny_code: String,
    pub normalized_shape: String,
    pub unique_votes: usize,
    pub anomaly_count: usize,
    pub ring0_locked: bool,
}

impl TriageClusterItem {
    pub fn to_json_value(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "cluster_key".to_string(),
                JsonValue::Str(self.cluster_key.clone()),
            ),
            (
                "category".to_string(),
                JsonValue::Str(self.category.clone()),
            ),
            (
                "deny_code".to_string(),
                JsonValue::Str(self.deny_code.clone()),
            ),
            (
                "normalized_shape".to_string(),
                JsonValue::Str(self.normalized_shape.clone()),
            ),
            (
                "unique_votes".to_string(),
                JsonValue::Uint(self.unique_votes as u64),
            ),
            (
                "anomaly_count".to_string(),
                JsonValue::Uint(self.anomaly_count as u64),
            ),
            (
                "ring0_locked".to_string(),
                JsonValue::Bool(self.ring0_locked),
            ),
        ])
    }
}

pub fn aggregate_ballot_worklist(
    ballots_raw: &str,
    quarantine_raw: &str,
    vault_key: &[u8; 32],
    min_votes: usize,
) -> Vec<TriageClusterItem> {
    let mut anomalies: BTreeMap<String, usize> = BTreeMap::new();
    for line in quarantine_raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
    {
        if let Ok(v) = JsonValue::parse(line)
            && let Some(ck) = v.get("cluster_key").and_then(JsonValue::as_str)
        {
            *anomalies.entry(ck.to_string()).or_insert(0) += 1;
        }
    }

    struct Acc {
        category: String,
        deny_code: String,
        shape: String,
        ring0: bool,
        voters: std::collections::BTreeSet<String>,
    }
    let mut grouped: BTreeMap<String, Acc> = BTreeMap::new();
    for line in ballots_raw.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Ok(v) = JsonValue::parse(line) else {
            continue;
        };
        if v.get("vote_counted").and_then(JsonValue::as_bool) == Some(false) {
            continue;
        }
        let Ok(b) = crate::feedback::SignedBallotRecord::from_json_value(&v) else {
            continue;
        };
        let Ok(expected_mac) = crate::coordinator::compute_domain_tag_for_feedback(
            vault_key,
            crate::feedback::FEEDBACK_BALLOT_HMAC_DOMAIN,
            &b.canonical_mac_bytes(),
        ) else {
            continue;
        };
        let Ok(given_mac) = crate::crypto::hex_decode_bytes(&b.mac_hex) else {
            continue;
        };
        if !crate::crypto::constant_time_eq_bytes(&expected_mac, &given_mac) {
            continue;
        }
        let dc = b.deny_code.unwrap_or(b.reason_code);
        let ring0 = crate::feedback::is_ring0_constitutional_code(&dc);
        let entry = grouped.entry(b.cluster_key).or_insert_with(|| Acc {
            category: b.category,
            deny_code: dc,
            shape: b.canonical_shape,
            ring0,
            voters: std::collections::BTreeSet::new(),
        });
        entry.voters.insert(b.voter_token);
    }

    let mut out: Vec<TriageClusterItem> = grouped
        .into_iter()
        .filter_map(|(ck, acc)| {
            let votes = acc.voters.len();
            (votes >= min_votes).then(|| TriageClusterItem {
                anomaly_count: anomalies.get(&ck).copied().unwrap_or(0),
                cluster_key: ck,
                category: acc.category,
                deny_code: acc.deny_code,
                normalized_shape: acc.shape,
                unique_votes: votes,
                ring0_locked: acc.ring0,
            })
        })
        .collect();
    out.sort_by(|a, b| {
        b.unique_votes
            .cmp(&a.unique_votes)
            .then_with(|| a.anomaly_count.cmp(&b.anomaly_count))
            .then_with(|| a.cluster_key.cmp(&b.cluster_key))
    });
    out
}

pub fn run_operator_feedback_triage_cli(args: &[String], cwd: &Path) -> ExitCode {
    if let Err((code, detail)) = verify_human_tty_telemetry_gate() {
        eprintln!("[AGENT-GUARD HARD DENY :: {code}] {detail}");
        return ExitCode::from(2);
    }
    let mut min_votes = 2usize;
    let mut json_mode = false;
    let mut sshsig_file: Option<PathBuf> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--min-votes" if i + 1 < args.len() => {
                min_votes = args[i + 1].parse::<usize>().unwrap_or(2).max(1);
                i += 2;
            }
            "--sshsig" if i + 1 < args.len() => {
                sshsig_file = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--json" => {
                json_mode = true;
                i += 1;
            }
            other => {
                eprintln!("[dotagent feedback triage] unrecognized argument '{other}'");
                return ExitCode::from(2);
            }
        }
    }
    let repo_root = crate::resolve_repo_root(cwd);
    if let Err(ge) = crate::operator::verify_operator_sshsig_gate(
        &repo_root,
        "feedback-triage",
        sshsig_file.as_deref(),
    ) {
        eprintln!("[AGENT-GUARD HARD DENY :: {}] {}", ge.code, ge.detail);
        return ExitCode::from(2);
    }
    let key = match crate::feedback::load_or_init_global_feedback_key() {
        Ok(zk) => zk,
        Err(e) => {
            eprintln!("[dotagent feedback triage] failed loading feedback vault key: {e}");
            return ExitCode::from(2);
        }
    };
    let fdir = match crate::feedback::feedback_state_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[dotagent feedback triage] FEEDBACK_STATE_TAMPERED: {e}");
            return ExitCode::from(2);
        }
    };
    let read_state_file = |name: &str| -> Result<String, String> {
        let p = fdir.join(name);
        if let Ok(m) = fs::symlink_metadata(&p)
            && m.len() > 16_777_216
        {
            return Err(format!("'{name}' exceeds 16 MiB cap"));
        }
        Ok(crate::traversal_ledger::read_nonsymlink_state_file(&p)?.unwrap_or_default())
    };
    let (ballots_raw, quar_raw) = match (
        read_state_file("ballots.jsonl"),
        read_state_file("quarantine.jsonl"),
    ) {
        (Ok(b), Ok(q)) => (b, q),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("[dotagent feedback triage] FEEDBACK_STATE_TAMPERED: {e}");
            return ExitCode::from(2);
        }
    };
    let items = aggregate_ballot_worklist(&ballots_raw, &quar_raw, key.as_bytes(), min_votes);
    if json_mode {
        let arr: Vec<JsonValue> = items.iter().map(TriageClusterItem::to_json_value).collect();
        println!("{}", JsonValue::Array(arr).to_json_string());
    } else {
        let esc = |s: &str| s.replace('|', "\\|").replace('`', "'");
        println!("| Cluster | Votes | Anomalies | Ring0 | Category | Code | Shape |");
        println!("| --- | --- | --- | --- | --- | --- | --- |");
        for it in &items {
            println!(
                "| `{}` | {} | {} | {} | `{}` | `{}` | `{}` |",
                esc(&it.cluster_key),
                it.unique_votes,
                it.anomaly_count,
                it.ring0_locked,
                esc(&it.category),
                esc(&it.deny_code),
                esc(&it.normalized_shape)
            );
        }
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_aggregates_and_renders_otlp_without_touching_guard_state() {
        let sample = concat!(
            r#"{"ts":1700000001,"repo":"/w/dotagent","session_id":"s1","session_hash":"a1b2","tool":"Read","code":"FORBIDDEN_PATH_ZONE","halted":true,"detail":"blocked"}"#,
            "\n",
            r#"{"ts":1700000005,"repo":"/w/dotagent","session_id":"s1","session_hash":"a1b2","tool":"Bash","code":"FORBIDDEN_BINARY","halted":false,"detail":"curl"}"#,
            "\n",
            r#"{"ts":1700000009,"repo":"/w/api","session_id":"s2","session_hash":"c3d4","tool":"Read","code":"FORBIDDEN_PATH_ZONE","halted":true,"detail":"blocked"}"#,
            "\n"
        );
        let sum = analyze_audit_jsonl_str(sample, None);
        assert_eq!(sum.total_events, 3);
        assert_eq!(sum.halted_events, 2);
        assert_eq!(sum.unique_sessions, 2);
        assert_eq!(sum.unique_repos, 2);
        let top = sum.top_denies(2);
        assert_eq!(top[0], ("FORBIDDEN_PATH_ZONE".to_string(), 2));
        assert_eq!(top[1], ("FORBIDDEN_BINARY".to_string(), 1));

        let filtered = analyze_audit_jsonl_str(sample, Some("/w/api"));
        assert_eq!(filtered.total_events, 1);

        let otlp = render_otlp_export_json(&sum, 1_700_000_009_000_000_000).to_json_string();
        assert!(otlp.contains("dotagent.guard.events.total"));
        assert!(otlp.contains("FORBIDDEN_PATH_ZONE"));
    }

    #[test]
    fn non_tty_or_sandbox_invocation_is_hard_denied() {
        // Under `cargo test`, stdin/stdout pipes are non-TTY or CI/sandbox markers apply:
        assert!(verify_human_tty_telemetry_gate().is_err());
    }
}
