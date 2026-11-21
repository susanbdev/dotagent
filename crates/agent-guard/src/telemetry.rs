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

use crate::breadcrumbs::ExclusiveFileLockGuard;
use crate::json::JsonValue;
use crate::path_policy::{PathAccess, check_forbidden_zones_lexical, validate_path};

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
        let repo = val.get("repo").and_then(JsonValue::as_str).unwrap_or("");
        if let Some(filter) = repo_filter
            && !repo.contains(filter)
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

/// Rotates `audit_path` (`audit.jsonl -> audit.jsonl.1 .. .keep`) when its size is `>= max_bytes`,
/// holding `ExclusiveFileLockGuard` and verifying non-symlink regular file invariants at every slot.
pub fn rotate_audit_log_at_path(
    audit_path: &Path,
    max_bytes: u64,
    keep_archives: usize,
) -> Result<bool, String> {
    let keep = keep_archives.clamp(1, 20);
    let _audit_lock = ExclusiveFileLockGuard::acquire(audit_path)?;
    let meta = match fs::symlink_metadata(audit_path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("failed stat on '{}': {e}", audit_path.display())),
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(format!(
            "refusing to rotate non-regular/symlink audit file '{}'",
            audit_path.display()
        ));
    }
    if meta.len() < max_bytes {
        return Ok(false);
    }

    let slot_path =
        |idx: usize| -> PathBuf { PathBuf::from(format!("{}.{idx}", audit_path.display())) };

    for idx in (1..=keep).rev() {
        let dst = slot_path(idx);
        if let Ok(dm) = fs::symlink_metadata(&dst)
            && dm.file_type().is_symlink()
        {
            return Err(format!(
                "refusing rotation: archive slot '{}' is a symlink",
                dst.display()
            ));
        }
        if idx == keep && dst.exists() {
            let _ = fs::remove_file(&dst);
        }
        if idx > 1 {
            let prev = slot_path(idx - 1);
            if let Ok(pm) = fs::symlink_metadata(&prev) {
                if pm.file_type().is_symlink() {
                    return Err(format!(
                        "refusing rotation: archive slot '{}' is a symlink",
                        prev.display()
                    ));
                }
                if pm.file_type().is_file() {
                    fs::rename(&prev, &dst).map_err(|e| {
                        format!(
                            "failed rotating '{}' -> '{}': {e}",
                            prev.display(),
                            dst.display()
                        )
                    })?;
                }
            }
        }
    }

    let first_archive = slot_path(1);
    fs::rename(audit_path, &first_archive).map_err(|e| {
        format!(
            "failed rotating '{}' -> '{}': {e}",
            audit_path.display(),
            first_archive.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let _ = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(audit_path);
    }
    #[cfg(not(unix))]
    {
        let _ = fs::File::create(audit_path);
    }
    Ok(true)
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

/// CLI entrypoint: `dotagent telemetry <summary|top-denies|rotate|export-otlp> ...`
pub fn run_telemetry_cli(args: &[String]) -> ExitCode {
    if let Err((code, msg)) = verify_human_tty_telemetry_gate() {
        eprintln!("[AGENT-GUARD HARD DENY :: {code}] {msg}");
        return ExitCode::from(2);
    }

    let sub = args.first().map(String::as_str).unwrap_or("summary");
    let audit_path = crate::traversal_ledger::audit_log_path();

    match sub {
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
