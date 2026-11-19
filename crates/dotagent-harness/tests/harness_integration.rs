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
