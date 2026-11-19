#![forbid(unsafe_code)]

//! `dotagent-harness`: Full-stack deterministic test harness for `susanbdev/dotagent`.
//!
//! Covers five orthogonal security planes:
//! 1. `scenarios`: Declarative TOML multi-harness hook & CLI session replay across
//!    Claude Code, Gemini/Antigravity, Cursor, OpenAI Codex, and direct CLI gates.
//! 2. `swarm`: Deterministic 6-role Swarm v2 delegation (`master`, `investigator`,
//!    `qa`, `grunt`, `reviewer`, `coroner`) and PR #6 (`DA-01a`..`DA-06`) regressions.
//! 3. `compiler`: `dotagent-compiler` deterministic bundle build/verify, drift/tamper
//!    detection, skill/profile/workflow gates, symlink refusal, and Rego policy invariants.
//! 4. `bootstrap`: Isolated sandbox verification of `scripts/activate-local.sh`
//!    (environment scrubbing, `0555` binaries, 19 global Git hardening keys, `0444`
//!    control plane, symlink target refusal, and pre-build RCE trap rejection).
//! 5. `corpus`: Canonical 305-vector adversarial bypass corpus verification.

pub mod bench_suite;
pub mod bootstrap_suite;
pub mod compiler_suite;
pub mod corpus_suite;
pub mod sandbox;
pub mod scenario;
pub mod swarm_suite;
pub mod toml_lite;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Instant;

use agent_guard::json::JsonValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuiteSelection {
    All,
    Scenarios,
    Swarm,
    Compiler,
    Bootstrap,
    Corpus,
}

impl SuiteSelection {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "all" => Ok(Self::All),
            "scenarios" | "scenario" => Ok(Self::Scenarios),
            "swarm" | "swarm-v2" => Ok(Self::Swarm),
            "compiler" => Ok(Self::Compiler),
            "bootstrap" | "activate" => Ok(Self::Bootstrap),
            "corpus" => Ok(Self::Corpus),
            other => Err(format!(
                "unknown suite '{other}' (expected all|scenarios|swarm|compiler|bootstrap|corpus)"
            )),
        }
    }

    pub fn includes(self, target: Self) -> bool {
        self == Self::All || self == target
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Text,
    Json,
}

impl ReportFormat {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "text" | "pretty" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => Err(format!("unknown format '{other}' (expected text|json)")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HarnessConfig {
    pub workspace_root: PathBuf,
    pub scenario_path: PathBuf,
    pub suite: SuiteSelection,
    pub filter: Option<String>,
    pub agent_guard_bin: Option<PathBuf>,
    pub compiler_bin: Option<PathBuf>,
    pub swarm_tool_bin: Option<PathBuf>,
}

impl HarnessConfig {
    pub fn for_workspace(workspace_root: PathBuf) -> Self {
        let scenario_path = workspace_root.join("tests").join("scenarios");
        Self {
            workspace_root,
            scenario_path,
            suite: SuiteSelection::All,
            filter: None,
            agent_guard_bin: None,
            compiler_bin: None,
            swarm_tool_bin: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkspaceBinaries {
    pub agent_guard: PathBuf,
    pub dotagent_compiler: PathBuf,
    pub swarm_tool: PathBuf,
}

#[derive(Debug, Clone)]
pub struct CaseResult {
    pub id: String,
    pub suite: String,
    pub passed: bool,
    pub duration_ms: u64,
    pub detail: String,
}

impl CaseResult {
    pub fn pass(id: String, suite: &str, duration_ms: u64, detail: String) -> Self {
        Self {
            id,
            suite: suite.to_string(),
            passed: true,
            duration_ms,
            detail,
        }
    }

    pub fn fail(id: String, suite: &str, duration_ms: u64, detail: String) -> Self {
        Self {
            id,
            suite: suite.to_string(),
            passed: false,
            duration_ms,
            detail,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HarnessReport {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub duration_ms: u64,
    pub cases: Vec<CaseResult>,
}

impl HarnessReport {
    pub fn all_passed(&self) -> bool {
        self.failed == 0 && self.total > 0
    }
}

pub fn discover_workspace_root() -> PathBuf {
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let p = PathBuf::from(manifest_dir);
        if let Some(root) = p.parent().and_then(Path::parent)
            && root.join("Cargo.toml").is_file()
        {
            return root.to_path_buf();
        }
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut cur = cwd.as_path();
    loop {
        if cur.join("Cargo.toml").is_file() && cur.join("crates").join("agent-guard").is_dir() {
            return cur.to_path_buf();
        }
        let Some(parent) = cur.parent() else {
            return cwd;
        };
        cur = parent;
    }
}

pub fn resolve_workspace_binaries(cfg: &HarnessConfig) -> Result<WorkspaceBinaries, String> {
    let guard_override = cfg
        .agent_guard_bin
        .clone()
        .or_else(|| std::env::var("DOTAGENT_GUARD_BIN").ok().map(PathBuf::from));
    let compiler_override = cfg.compiler_bin.clone().or_else(|| {
        std::env::var("DOTAGENT_COMPILER_BIN")
            .ok()
            .map(PathBuf::from)
    });
    let swarm_override = cfg.swarm_tool_bin.clone().or_else(|| {
        std::env::var("DOTAGENT_SWARM_TOOL_BIN")
            .ok()
            .map(PathBuf::from)
    });

    if guard_override.is_none() || compiler_override.is_none() || swarm_override.is_none() {
        static BUILD_ONCE: OnceLock<Result<(), String>> = OnceLock::new();
        BUILD_ONCE
            .get_or_init(|| build_workspace_bins(&cfg.workspace_root))
            .clone()?;
    }

    let guard_path =
        guard_override.or_else(|| find_built_binary(&cfg.workspace_root, "agent-guard"));
    let compiler_path =
        compiler_override.or_else(|| find_built_binary(&cfg.workspace_root, "dotagent-compiler"));
    let swarm_path =
        swarm_override.or_else(|| find_built_binary(&cfg.workspace_root, "swarm-tool"));

    let agent_guard = guard_path.ok_or_else(|| {
        "unable to locate compiled 'agent-guard' binary under target/".to_string()
    })?;
    let dotagent_compiler = compiler_path.ok_or_else(|| {
        "unable to locate compiled 'dotagent-compiler' binary under target/".to_string()
    })?;
    let swarm_tool = swarm_path
        .ok_or_else(|| "unable to locate compiled 'swarm-tool' binary under target/".to_string())?;

    Ok(WorkspaceBinaries {
        agent_guard,
        dotagent_compiler,
        swarm_tool,
    })
}

fn find_built_binary(workspace_root: &Path, name: &str) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Some(exe_dir) = exe.parent()
    {
        // When invoked via `cargo run`, current_exe is `target/<profile>/dotagent-harness`.
        candidates.push(exe_dir.join(name));
        // When invoked via `cargo test`, current_exe is `target/<profile>/deps/<test_bin>`.
        if let Some(profile_dir) = exe_dir.parent() {
            candidates.push(profile_dir.join(name));
        }
    }
    candidates.push(workspace_root.join("target").join("debug").join(name));
    candidates.push(workspace_root.join("target").join("release").join(name));

    candidates.into_iter().find(|p| p.is_file())
}

fn build_workspace_bins(workspace_root: &Path) -> Result<(), String> {
    let status = Command::new("cargo")
        .arg("build")
        .arg("-q")
        .arg("-p")
        .arg("agent-guard")
        .arg("-p")
        .arg("dotagent-compiler")
        .arg("-p")
        .arg("swarm-tools")
        .arg("--manifest-path")
        .arg(workspace_root.join("Cargo.toml"))
        .status()
        .map_err(|e| format!("failed running cargo build for workspace binaries: {e}"))?;
    if !status.success() {
        return Err(
            "cargo build -p agent-guard -p dotagent-compiler -p swarm-tools failed".to_string(),
        );
    }
    Ok(())
}

pub fn list_cases(cfg: &HarnessConfig) -> Result<Vec<String>, String> {
    let mut ids = Vec::new();
    if cfg.suite.includes(SuiteSelection::Scenarios) {
        let scenarios = scenario::load_scenarios_from_path(&cfg.scenario_path)?;
        for s in scenarios {
            let id = format!("scenario::{}/{}", s.harness.as_str(), s.id);
            if matches_filter(&id, cfg.filter.as_deref()) {
                ids.push(id);
            }
        }
    }
    if cfg.suite.includes(SuiteSelection::Swarm) {
        for id in swarm_suite::swarm_case_ids() {
            if matches_filter(id, cfg.filter.as_deref()) {
                ids.push(id.to_string());
            }
        }
    }
    if cfg.suite.includes(SuiteSelection::Compiler) {
        for id in compiler_suite::compiler_case_ids() {
            if matches_filter(id, cfg.filter.as_deref()) {
                ids.push(id.to_string());
            }
        }
    }
    if cfg.suite.includes(SuiteSelection::Bootstrap) {
        for id in bootstrap_suite::bootstrap_case_ids() {
            if matches_filter(id, cfg.filter.as_deref()) {
                ids.push(id.to_string());
            }
        }
    }
    if cfg.suite.includes(SuiteSelection::Corpus) {
        for id in corpus_suite::corpus_case_ids() {
            if matches_filter(id, cfg.filter.as_deref()) {
                ids.push(id.to_string());
            }
        }
    }
    Ok(ids)
}

pub fn run_harness(cfg: &HarnessConfig) -> Result<HarnessReport, String> {
    let started = Instant::now();
    let needs_bins = cfg.suite.includes(SuiteSelection::Scenarios)
        || cfg.suite.includes(SuiteSelection::Swarm)
        || cfg.suite.includes(SuiteSelection::Compiler)
        || cfg.suite.includes(SuiteSelection::Bootstrap);
    let bins = if needs_bins {
        Some(resolve_workspace_binaries(cfg)?)
    } else {
        None
    };

    let mut cases = Vec::new();

    if cfg.suite.includes(SuiteSelection::Scenarios) {
        let b = bins.as_ref().expect("resolved binaries");
        let scenarios = scenario::load_scenarios_from_path(&cfg.scenario_path)?;
        for spec in &scenarios {
            let full_id = format!("scenario::{}/{}", spec.harness.as_str(), spec.id);
            if !matches_filter(&full_id, cfg.filter.as_deref()) {
                continue;
            }
            cases.push(scenario::run_scenario(
                spec,
                &cfg.workspace_root,
                &b.agent_guard,
            ));
        }
    }

    if cfg.suite.includes(SuiteSelection::Swarm) {
        let b = bins.as_ref().expect("resolved binaries");
        cases.extend(swarm_suite::run_swarm_suite(
            &cfg.workspace_root,
            b,
            cfg.filter.as_deref(),
        ));
    }

    if cfg.suite.includes(SuiteSelection::Compiler) {
        let b = bins.as_ref().expect("resolved binaries");
        cases.extend(compiler_suite::run_compiler_suite(
            &cfg.workspace_root,
            &b.dotagent_compiler,
            cfg.filter.as_deref(),
        ));
    }

    if cfg.suite.includes(SuiteSelection::Bootstrap) {
        let b = bins.as_ref().expect("resolved binaries");
        cases.extend(bootstrap_suite::run_bootstrap_suite(
            &cfg.workspace_root,
            b,
            cfg.filter.as_deref(),
        ));
    }

    if cfg.suite.includes(SuiteSelection::Corpus) {
        cases.extend(corpus_suite::run_corpus_suite(
            &cfg.workspace_root,
            cfg.filter.as_deref(),
        ));
    }

    let total = cases.len();
    let passed = cases.iter().filter(|c| c.passed).count();
    let failed = total.saturating_sub(passed);

    Ok(HarnessReport {
        total,
        passed,
        failed,
        duration_ms: started.elapsed().as_millis() as u64,
        cases,
    })
}

fn matches_filter(id: &str, filter: Option<&str>) -> bool {
    match filter {
        Some(f) => id.contains(f),
        None => true,
    }
}

pub fn render_text_report(report: &HarnessReport) -> String {
    let mut out = String::new();
    out.push_str("========================================================================\n");
    out.push_str(" dotagent-harness :: Zero-Trust Multi-Harness Verification Report\n");
    out.push_str("========================================================================\n");
    for c in &report.cases {
        let status = if c.passed { "PASS" } else { "FAIL" };
        out.push_str(&format!(
            "[{status}] {:<56} ({:>4} ms)\n       {}\n",
            c.id, c.duration_ms, c.detail
        ));
    }
    out.push_str("------------------------------------------------------------------------\n");
    out.push_str(&format!(
        "Summary: {}/{} passed, {} failed in {} ms\n",
        report.passed, report.total, report.failed, report.duration_ms
    ));
    out
}

pub fn render_json_report(report: &HarnessReport) -> String {
    let case_items: Vec<JsonValue> = report
        .cases
        .iter()
        .map(|c| {
            JsonValue::Object(vec![
                ("id".to_string(), JsonValue::Str(c.id.clone())),
                ("suite".to_string(), JsonValue::Str(c.suite.clone())),
                ("passed".to_string(), JsonValue::Bool(c.passed)),
                (
                    "duration_ms".to_string(),
                    JsonValue::Number(c.duration_ms as f64),
                ),
                ("detail".to_string(), JsonValue::Str(c.detail.clone())),
            ])
        })
        .collect();

    let root = JsonValue::Object(vec![
        (
            "status".to_string(),
            JsonValue::Str(if report.all_passed() { "pass" } else { "fail" }.to_string()),
        ),
        ("total".to_string(), JsonValue::Number(report.total as f64)),
        (
            "passed".to_string(),
            JsonValue::Number(report.passed as f64),
        ),
        (
            "failed".to_string(),
            JsonValue::Number(report.failed as f64),
        ),
        (
            "duration_ms".to_string(),
            JsonValue::Number(report.duration_ms as f64),
        ),
        ("cases".to_string(), JsonValue::Array(case_items)),
    ]);
    root.to_json_string()
}
