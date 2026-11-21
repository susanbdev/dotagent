#![forbid(unsafe_code)]

//! Canonical Ring-2 Policy Regression Suite (`crates/agent-guard/tests/ring2_policy_tests.rs`).
//!
//! Autonomous Ring-2 friction PRs may add regression tests to this file (one of the 5 allowed
//! paths in `ring0_ratchet.rs`) alongside `>= 2` target-matched deny vectors in
//! `tests/bypass_corpus.toml`.

use std::path::Path;

use agent_guard::cmd_policy::evaluate_shell_command;
use agent_guard::diagnostics::lookup_explanation;
use agent_guard::mcp_policy::{McpRpcClass, classify_mcp_sub_method};

#[test]
fn ring2_baseline_policy_and_diagnostics_invariants_hold() {
    let repo = Path::new("/workspace");
    assert!(
        evaluate_shell_command(
            "dotagent feedback submit --denial-id dnl_0123456789abcdef --category false_positive_block --reason-code safe_flag",
            repo,
            repo,
            false
        )
        .is_ok()
    );
    assert!(
        evaluate_shell_command(
            "dotagent feedback submit --denial-id dnl_0123456789abcdef --category false_positive_block --shape 'git status'",
            repo,
            repo,
            false
        )
        .is_err()
    );
    assert_eq!(
        classify_mcp_sub_method("dotagent_submit_friction"),
        McpRpcClass::ReadOnly
    );
    assert!(lookup_explanation("FEEDBACK_RATE_LIMIT_EXCEEDED").is_some());
}
