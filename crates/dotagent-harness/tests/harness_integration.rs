#![forbid(unsafe_code)]

use std::process::Command;

use agent_guard::json::JsonValue;
use dotagent_harness::{
    HarnessConfig, SuiteSelection, discover_workspace_root, list_cases, render_text_report,
    run_harness,
};

fn assert_suite_passes(suite: SuiteSelection) {
    let mut cfg = HarnessConfig::for_workspace(discover_workspace_root());
    cfg.suite = suite;
    let report = run_harness(&cfg).expect("run harness suite");
    if !report.all_passed() {
        panic!(
            "dotagent-harness suite {suite:?} failed:\n{}",
            render_text_report(&report)
        );
    }
}

#[test]
fn declarative_multi_harness_scenarios_pass() {
    assert_suite_passes(SuiteSelection::Scenarios);
}

#[test]
fn swarm_v2_delegation_and_adversarial_regression_suite_passes() {
    assert_suite_passes(SuiteSelection::Swarm);
}

#[test]
fn dotagent_compiler_build_verify_and_tamper_suite_passes() {
    assert_suite_passes(SuiteSelection::Compiler);
}

#[test]
fn activate_local_bootstrap_and_rce_trap_suite_passes() {
    assert_suite_passes(SuiteSelection::Bootstrap);
}

#[test]
fn canonical_bypass_corpus_suite_passes() {
    assert_suite_passes(SuiteSelection::Corpus);
}

#[test]
fn upstream_wire_and_sidecar_contracts_suite_passes() {
    assert_suite_passes(SuiteSelection::Contracts);
}

#[test]
fn cli_binary_supports_list_and_structured_json_reports() {
    let ws = discover_workspace_root();
    let cfg = HarnessConfig::for_workspace(ws.clone());
    let listed = list_cases(&cfg).expect("list cases");
    assert!(
        listed.len() >= 35,
        "expected >= 35 total harness cases across all 5 suites, got {}",
        listed.len()
    );

    let bin = env!("CARGO_BIN_EXE_dotagent-harness");
    let list_out = Command::new(bin)
        .arg("--list")
        .arg("--workspace")
        .arg(&ws)
        .output()
        .expect("run --list");
    assert!(list_out.status.success(), "--list failed");
    let list_stdout = String::from_utf8_lossy(&list_out.stdout);
    assert!(list_stdout.contains("scenario::claude/claude_full_hook_lifecycle"));
    assert!(list_stdout.contains("swarm::six_role_end_to_end_delegation_and_provenance"));
    assert!(list_stdout.contains("compiler::live_workspace_verify_and_rego_contract"));
    assert!(
        list_stdout.contains("bootstrap::end_to_end_activate_local_env_scrub_git19_and_0444_plane")
    );

    let json_out = Command::new(bin)
        .arg("run")
        .arg("--suite")
        .arg("scenarios")
        .arg("--filter")
        .arg("claude_full_hook_lifecycle")
        .arg("--format")
        .arg("json")
        .arg("--workspace")
        .arg(&ws)
        .output()
        .expect("run --format json");
    assert!(
        json_out.status.success(),
        "JSON CLI run failed: stderr={}",
        String::from_utf8_lossy(&json_out.stderr)
    );
    let parsed =
        JsonValue::parse(&String::from_utf8_lossy(&json_out.stdout)).expect("valid JSON report");
    assert_eq!(
        parsed.get("status").and_then(JsonValue::as_str),
        Some("pass")
    );
    assert_eq!(parsed.get("failed").and_then(JsonValue::as_u64), Some(0));

    let bench_out = Command::new(bin)
        .args(["bench", "--quick", "--json", "--workspace"])
        .arg(&ws)
        .output()
        .expect("run bench --quick --json");
    assert!(
        bench_out.status.success(),
        "bench CLI failed: {}",
        String::from_utf8_lossy(&bench_out.stderr)
    );
    let bench_json =
        JsonValue::parse(&String::from_utf8_lossy(&bench_out.stdout)).expect("valid bench JSON");
    assert_eq!(
        bench_json
            .get("benchmarks")
            .and_then(JsonValue::as_array)
            .map(<[JsonValue]>::len),
        Some(5)
    );
}

#[test]
fn airlock_pareto_eval_proves_token_savings_zero_hop_pollution_and_cap_knee() {
    let ws = discover_workspace_root();
    let cfg = HarnessConfig::for_workspace(ws.clone());
    let report = dotagent_harness::airlock_eval::run_airlock_evaluation(&cfg)
        .expect("run airlock evaluation");

    assert!(
        report.baseline.rust_files_sampled >= 40,
        "expected >= 40 real Rust modules sampled, got {}",
        report.baseline.rust_files_sampled
    );
    assert_eq!(
        report.recommended_cap, 4,
        "expected zero-surgical-friction Pareto knee at cap=4"
    );

    let cap0 = report
        .rows
        .iter()
        .find(|r| r.max_direct_discovery_calls == 0)
        .expect("cap 0 row");
    let cap4 = report
        .rows
        .iter()
        .find(|r| r.max_direct_discovery_calls == 4)
        .expect("cap 4 row");
    let cap28 = report
        .rows
        .iter()
        .find(|r| r.max_direct_discovery_calls == 28)
        .expect("cap 28 row");

    // Cap 0 forces subagent overhead on surgical 1..4-lookup edits (why Swarm Master != standalone coding-agent)
    assert!(cap0.surgical_forced_subagent_pct >= 75.0);

    // Cap 4 achieves 0% surgical false-positives AND 100% multi-module investigation containment!
    assert_eq!(cap4.surgical_forced_subagent_pct, 0.0);
    assert_eq!(cap4.investigation_caught_pct, 100.0);
    assert_eq!(cap4.parent_exploratory_files_exposed, 0);
    assert_eq!(cap4.downstream_hop_blocks, 0);
    assert_eq!(cap4.step_budget_failures, 0);
    assert!(
        cap4.investigation_token_savings_pct >= 60.0,
        "expected >= 60% parent investigation token savings at cap=4, got {:.1}%",
        cap4.investigation_token_savings_pct
    );

    // Unbounded parent exploration (cap=28) leaks untrusted files, pollutes A->B->C hops, and OOMs 16k window!
    assert!(cap28.parent_exploratory_files_exposed >= 20);
    assert!(cap28.downstream_hop_blocks >= 2);
    assert!(cap28.step_budget_failures >= 1);
    assert!(cap28.pareto_effective_cost > (cap4.pareto_effective_cost * 3) / 2);

    // CLI JSON output contract check
    let bin = env!("CARGO_BIN_EXE_dotagent-harness");
    let cli_out = Command::new(bin)
        .args(["airlock-eval", "--json", "--workspace"])
        .arg(&ws)
        .output()
        .expect("run airlock-eval --json");
    assert!(cli_out.status.success());
    let parsed =
        JsonValue::parse(&String::from_utf8_lossy(&cli_out.stdout)).expect("valid airlock JSON");
    assert_eq!(
        parsed.get("recommended_cap").and_then(JsonValue::as_u64),
        Some(4)
    );
}
