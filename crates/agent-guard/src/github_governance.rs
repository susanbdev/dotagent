#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! Idempotent GitHub Organization & User Zero-Trust Governance Provisioner
//! (`dotagent fleet configure-github`).
//!
//! Configures both GitHub Organizations (e.g., `susanbdev`) and Personal User Accounts
//! (e.g., `susanbeasles`):
//! 1. **Organization & User Actions Hardening**:
//!    - Organization (`orgs/<org>/actions/permissions*`): `allowed_actions: "selected"`,
//!      `sha_pinning_required: true`, `github_owned_allowed: true`, `verified_allowed: false`,
//!      `default_workflow_permissions: "read"`, `can_approve_pull_request_reviews: false`.
//!    - User (`repos/<user>/<repo>/actions/permissions*`): repo-level `sha_pinning_required: true`,
//!      `default_workflow_permissions: "read"`, `can_approve_pull_request_reviews: false`.
//! 2. **Repository Merge Settings**:
//!    - Squash-only linear merges (`allow_squash_merge: true`, `allow_merge_commit: false`,
//!      `allow_rebase_merge: false`, `delete_branch_on_merge: true`, `allow_auto_merge: true`).
//! 3. **Default-Branch Ruleset (`dotagent-zero-trust-main`)**:
//!    - Explicit `bypass_actors: []` (excluding `dotagent-loop[bot]` and repo admins from bypass),
//!      blocks deletion and force-pushes (`non_fast_forward`), requires linear history, requires PRs
//!      with `allowed_merge_methods: ["squash"]`, `required_review_thread_resolution: true`,
//!      `dismiss_stale_reviews_on_push: true`, and at least one eligible collaborator approval.
//!      On `dotagent`, it also requires the Guardrail CI jobs and the exact-head `Ring-0 & Copilot
//!      Gate`, and configures `copilot_code_review` with `review_on_push: true`.

use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use crate::feedback_loop::resolve_gh_bin;
use crate::json::JsonValue;

pub const RULESET_NAME: &str = "dotagent-zero-trust-main";

pub(crate) const RATCHET_CHECK_RUN: &str = "Ring-0 Constitutional Ratchet";
pub(crate) const COPILOT_GATE_CONTEXT: &str = "Ring-0 & Copilot Gate";

const DOTAGENT_REQUIRED_CHECKS: &str = include_str!("../../../config/github-required-checks.txt");

pub fn dotagent_required_checks() -> std::str::Lines<'static> {
    DOTAGENT_REQUIRED_CHECKS.lines()
}

pub const GOVERNANCE_LABELS: &[(&str, &str, &str)] = &[
    (
        "dotagent-friction",
        "1d76db",
        "Structured agent guardrail or workflow friction cluster",
    ),
    (
        "priority:ready",
        "0e8a16",
        "Friction cluster met unique untainted swarm quorum",
    ),
    (
        "dotagent-approved-triage",
        "2ea44f",
        "Explicit human operator override authorizing autonomous Ring-2 triage",
    ),
    (
        "friction-escalated-human",
        "e99695",
        "2-strike autonomous loop circuit breaker tripped; escalated for human review",
    ),
    (
        "automated-pr-open",
        "5319e7",
        "Autonomous Ring-2 PR is currently open for this friction cluster",
    ),
    (
        "signal:agent-loop-anomaly",
        "fbca04",
        "Single agent session submitted >= 3 duplicate ballots (AgentPI pipeline loop signal)",
    ),
    (
        "signal:tainted-quarantine",
        "d93f0b",
        "Tainted session attempted ballot submission (zero vote weight, AgentPI high-risk signal)",
    ),
    (
        "ring0:constitutional-review",
        "b60205",
        "Touches Ring-0 constitutional code; auto-coder restricted to diagnostic clarity only",
    ),
    (
        "wontfix-constitutional",
        "5319e7",
        "Blocked permanently by Ring-0 / AGENTS.md constitutional security review",
    ),
    (
        "automated-friction-fix",
        "0052cc",
        "Autonomous Ring-2 improvement PR gated by Ring-0 Ratchet, Adversarial, and Copilot",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceMode {
    DryRun,
    VerifyOnly,
    Apply,
}

#[derive(Debug, Clone)]
pub struct GovernanceRepoReport {
    pub full_repo: String,
    pub ok: bool,
    pub actions_taken: Vec<String>,
    pub drift_findings: Vec<String>,
}

impl GovernanceRepoReport {
    pub fn to_json_value(&self) -> JsonValue {
        let acts: Vec<JsonValue> = self
            .actions_taken
            .iter()
            .map(|s| JsonValue::Str(s.clone()))
            .collect();
        let drifts: Vec<JsonValue> = self
            .drift_findings
            .iter()
            .map(|s| JsonValue::Str(s.clone()))
            .collect();
        JsonValue::Object(vec![
            (
                "repository".to_string(),
                JsonValue::Str(self.full_repo.clone()),
            ),
            ("ok".to_string(), JsonValue::Bool(self.ok)),
            ("actions".to_string(), JsonValue::Array(acts)),
            ("drift_findings".to_string(), JsonValue::Array(drifts)),
        ])
    }
}

pub fn validate_github_ident(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 100 || s == "." || s == ".." {
        return Err(format!("invalid GitHub identifier '{s}'"));
    }
    let bytes = s.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return Err(format!(
            "GitHub identifier '{s}' must begin with an ASCII alphanumeric character"
        ));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        return Err(format!(
            "GitHub identifier '{s}' contains disallowed characters"
        ));
    }
    Ok(())
}

fn validate_url_safe_branch(b: &str) -> Result<(), String> {
    if b.is_empty()
        || b.len() > 200
        || b.starts_with('-')
        || b.starts_with('/')
        || b.ends_with('/')
        || b.contains("..")
    {
        return Err(format!("unsafe branch name '{b}'"));
    }
    if !b
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-' | b'/'))
    {
        return Err(format!("disallowed characters in branch '{b}'"));
    }
    Ok(())
}

pub fn build_org_actions_permissions_payload() -> JsonValue {
    JsonValue::Object(vec![
        ("enabled".to_string(), JsonValue::Bool(true)),
        (
            "allowed_actions".to_string(),
            JsonValue::Str("selected".to_string()),
        ),
        ("sha_pinning_required".to_string(), JsonValue::Bool(true)),
    ])
}

pub fn build_user_repo_actions_permissions_payload() -> JsonValue {
    JsonValue::Object(vec![
        ("enabled".to_string(), JsonValue::Bool(true)),
        (
            "allowed_actions".to_string(),
            JsonValue::Str("selected".to_string()),
        ),
        ("sha_pinning_required".to_string(), JsonValue::Bool(true)),
    ])
}

pub fn build_selected_actions_payload() -> JsonValue {
    JsonValue::Object(vec![
        ("github_owned_allowed".to_string(), JsonValue::Bool(true)),
        ("verified_allowed".to_string(), JsonValue::Bool(false)),
        ("patterns_allowed".to_string(), JsonValue::Array(Vec::new())),
    ])
}

pub fn build_workflow_permissions_payload() -> JsonValue {
    JsonValue::Object(vec![
        (
            "default_workflow_permissions".to_string(),
            JsonValue::Str("read".to_string()),
        ),
        (
            "can_approve_pull_request_reviews".to_string(),
            JsonValue::Bool(false),
        ),
    ])
}

pub fn build_repo_merge_settings_payload() -> JsonValue {
    JsonValue::Object(vec![
        ("allow_squash_merge".to_string(), JsonValue::Bool(true)),
        ("allow_merge_commit".to_string(), JsonValue::Bool(false)),
        ("allow_rebase_merge".to_string(), JsonValue::Bool(false)),
        ("delete_branch_on_merge".to_string(), JsonValue::Bool(true)),
        ("allow_auto_merge".to_string(), JsonValue::Bool(true)),
    ])
}

/// GitHub App id of GitHub Actions; required checks are pinned to it so that a token holding
/// `statuses: write` cannot forge a green context from outside Actions.
pub const GITHUB_ACTIONS_INTEGRATION_ID: u64 = 15368;

const MINIMUM_APPROVING_REVIEWS: u64 = 1;
const EXTRA_COPILOT_APPROVAL: &str = "require_extra_approval_for_unattributed_changes";

pub fn build_main_ruleset_payload(
    required_check_contexts: &[String],
    include_copilot_rule: bool,
) -> JsonValue {
    // GitHub pins status contexts to an App identity shared by Actions workflows.
    // Keep an eligible collaborator approval even when the automated gate is required.
    let mut rules: Vec<JsonValue> = vec![
        JsonValue::Object(vec![(
            "type".to_string(),
            JsonValue::Str("deletion".to_string()),
        )]),
        JsonValue::Object(vec![(
            "type".to_string(),
            JsonValue::Str("non_fast_forward".to_string()),
        )]),
        JsonValue::Object(vec![(
            "type".to_string(),
            JsonValue::Str("required_linear_history".to_string()),
        )]),
        JsonValue::Object(vec![
            (
                "type".to_string(),
                JsonValue::Str("pull_request".to_string()),
            ),
            (
                "parameters".to_string(),
                JsonValue::Object(vec![
                    (
                        "allowed_merge_methods".to_string(),
                        JsonValue::Array(vec![JsonValue::Str("squash".to_string())]),
                    ),
                    (
                        "dismiss_stale_reviews_on_push".to_string(),
                        JsonValue::Bool(true),
                    ),
                    (
                        "require_code_owner_review".to_string(),
                        JsonValue::Bool(false),
                    ),
                    (EXTRA_COPILOT_APPROVAL.to_string(), JsonValue::Bool(true)),
                    (
                        "require_last_push_approval".to_string(),
                        JsonValue::Bool(false),
                    ),
                    (
                        "required_approving_review_count".to_string(),
                        JsonValue::Uint(MINIMUM_APPROVING_REVIEWS),
                    ),
                    (
                        "required_review_thread_resolution".to_string(),
                        JsonValue::Bool(true),
                    ),
                ]),
            ),
        ]),
    ];

    if include_copilot_rule {
        rules.push(JsonValue::Object(vec![
            (
                "type".to_string(),
                JsonValue::Str("copilot_code_review".to_string()),
            ),
            (
                "parameters".to_string(),
                JsonValue::Object(vec![
                    (
                        "review_draft_pull_requests".to_string(),
                        JsonValue::Bool(false),
                    ),
                    ("review_on_push".to_string(), JsonValue::Bool(true)),
                ]),
            ),
        ]));
    }

    if !required_check_contexts.is_empty() {
        let checks_arr: Vec<JsonValue> = required_check_contexts
            .iter()
            .map(|ctx| {
                JsonValue::Object(vec![
                    ("context".to_string(), JsonValue::Str(ctx.clone())),
                    (
                        "integration_id".to_string(),
                        JsonValue::Uint(GITHUB_ACTIONS_INTEGRATION_ID),
                    ),
                ])
            })
            .collect();
        rules.push(JsonValue::Object(vec![
            (
                "type".to_string(),
                JsonValue::Str("required_status_checks".to_string()),
            ),
            (
                "parameters".to_string(),
                JsonValue::Object(vec![
                    (
                        "strict_required_status_checks_policy".to_string(),
                        JsonValue::Bool(true),
                    ),
                    (
                        "do_not_enforce_on_create".to_string(),
                        JsonValue::Bool(false),
                    ),
                    (
                        "required_status_checks".to_string(),
                        JsonValue::Array(checks_arr),
                    ),
                ]),
            ),
        ]));
    }

    JsonValue::Object(vec![
        ("name".to_string(), JsonValue::Str(RULESET_NAME.to_string())),
        ("target".to_string(), JsonValue::Str("branch".to_string())),
        (
            "enforcement".to_string(),
            JsonValue::Str("active".to_string()),
        ),
        ("bypass_actors".to_string(), JsonValue::Array(Vec::new())),
        (
            "conditions".to_string(),
            JsonValue::Object(vec![(
                "ref_name".to_string(),
                JsonValue::Object(vec![
                    (
                        "include".to_string(),
                        JsonValue::Array(vec![JsonValue::Str("~DEFAULT_BRANCH".to_string())]),
                    ),
                    ("exclude".to_string(), JsonValue::Array(Vec::new())),
                ]),
            )]),
        ),
        ("rules".to_string(), JsonValue::Array(rules)),
    ])
}

pub fn run_configure_github_cli(args: &[String]) -> ExitCode {
    if let Err(msg) =
        crate::fleet::verify_operator_not_in_agent_sandbox("dotagent fleet configure-github")
    {
        eprintln!("[AGENT-GUARD HARD DENY] {msg}");
        return ExitCode::from(2);
    }

    let mut owner = String::from("susanbdev");
    let mut repos: Vec<String> = Vec::new();
    let mut all_fleet = false;
    let mut mode = GovernanceMode::DryRun;
    let mut explicit_mode = false;
    let mut json_mode = false;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--owner" | "--org" if i + 1 < args.len() => {
                owner = args[i + 1].trim().to_string();
                i += 2;
            }
            "--repo" if i + 1 < args.len() => {
                repos.push(args[i + 1].trim().to_string());
                i += 2;
            }
            "--repos" if i + 1 < args.len() => {
                for part in args[i + 1].split(',') {
                    let t = part.trim();
                    if !t.is_empty() {
                        repos.push(t.to_string());
                    }
                }
                i += 2;
            }
            "--all-fleet" | "--all" => {
                all_fleet = true;
                i += 1;
            }
            "--dry-run" => {
                mode = GovernanceMode::DryRun;
                explicit_mode = true;
                i += 1;
            }
            "--verify" => {
                mode = GovernanceMode::VerifyOnly;
                explicit_mode = true;
                i += 1;
            }
            "--apply" => {
                mode = GovernanceMode::Apply;
                explicit_mode = true;
                i += 1;
            }
            "--json" => {
                json_mode = true;
                i += 1;
            }
            other => {
                eprintln!(
                    "[dotagent fleet configure-github] unrecognized argument '{other}'\n\
                     usage: dotagent fleet configure-github --owner <org_or_user> [--repo <name> | --repos <csv> | --all-fleet] [--dry-run | --verify | --apply] [--json]"
                );
                return ExitCode::from(2);
            }
        }
    }

    if !explicit_mode {
        mode = GovernanceMode::DryRun;
    }

    if let Err(e) = validate_github_ident(&owner) {
        eprintln!("[dotagent fleet configure-github] HARD DENY: {e}");
        return ExitCode::from(2);
    }

    let gh = resolve_gh_bin();
    let mut org_notes: Vec<String> = Vec::new();
    let is_org = match detect_owner_is_org(&gh, &owner) {
        Ok(b) => b,
        Err(e) if mode == GovernanceMode::DryRun => {
            org_notes.push(format!(
                "offline/unauthenticated dry-run owner probe note: {e}"
            ));
            false
        }
        Err(e) => {
            eprintln!(
                "[dotagent fleet configure-github] failed querying owner '{owner}' via GitHub API: {e}"
            );
            return ExitCode::from(2);
        }
    };

    if all_fleet {
        match list_owner_repos(&gh, &owner, is_org) {
            Ok(found) => {
                for r in found {
                    if !repos.contains(&r) {
                        repos.push(r);
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "[dotagent fleet configure-github] failed listing repos for '{owner}': {e}"
                );
                return ExitCode::from(2);
            }
        }
    }
    if repos.is_empty() {
        repos.push("dotagent".to_string());
    }

    let mut all_ok = true;
    if is_org {
        match configure_or_verify_org(&gh, &owner, mode) {
            Ok((ok_org, notes)) => {
                if !ok_org {
                    all_ok = false;
                }
                org_notes.extend(notes);
            }
            Err(e) => {
                all_ok = false;
                org_notes.push(format!("ORG_GOVERNANCE_ERROR: {e}"));
            }
        }
    } else {
        org_notes.push(format!(
            "Owner '{owner}' is a User account (applying repo-level SHA-pinned Actions, read-only workflow permissions, & ruleset policies)."
        ));
    }

    let mut reports = Vec::with_capacity(repos.len());
    for r in &repos {
        let short_name = if let Some((prefix, rest)) = r.split_once('/') {
            if !prefix.eq_ignore_ascii_case(&owner) {
                all_ok = false;
                reports.push(GovernanceRepoReport {
                    full_repo: r.clone(),
                    ok: false,
                    actions_taken: Vec::new(),
                    drift_findings: vec![format!(
                        "repo '{r}' owner prefix does not match --owner '{owner}'"
                    )],
                });
                continue;
            }
            rest
        } else {
            r.as_str()
        };
        if let Err(e) = validate_github_ident(short_name) {
            all_ok = false;
            reports.push(GovernanceRepoReport {
                full_repo: format!("{owner}/{short_name}"),
                ok: false,
                actions_taken: Vec::new(),
                drift_findings: vec![e],
            });
            continue;
        }
        let full_repo = format!("{owner}/{short_name}");
        match configure_or_verify_repo(&gh, &full_repo, short_name, is_org, mode) {
            Ok(rep) => {
                if !rep.ok {
                    all_ok = false;
                }
                reports.push(rep);
            }
            Err(e) => {
                all_ok = false;
                reports.push(GovernanceRepoReport {
                    full_repo,
                    ok: false,
                    actions_taken: Vec::new(),
                    drift_findings: vec![e],
                });
            }
        }
    }

    if json_mode {
        let org_arr: Vec<JsonValue> = org_notes.into_iter().map(JsonValue::Str).collect();
        let rep_arr: Vec<JsonValue> = reports
            .iter()
            .map(GovernanceRepoReport::to_json_value)
            .collect();
        let out = JsonValue::Object(vec![
            ("owner".to_string(), JsonValue::Str(owner)),
            ("is_organization".to_string(), JsonValue::Bool(is_org)),
            (
                "mode".to_string(),
                JsonValue::Str(
                    match mode {
                        GovernanceMode::DryRun => "dry_run",
                        GovernanceMode::VerifyOnly => "verify",
                        GovernanceMode::Apply => "apply",
                    }
                    .to_string(),
                ),
            ),
            ("ok".to_string(), JsonValue::Bool(all_ok)),
            ("org_notes".to_string(), JsonValue::Array(org_arr)),
            ("repositories".to_string(), JsonValue::Array(rep_arr)),
        ]);
        println!("{}", out.to_json_string());
    } else {
        println!(
            "[dotagent fleet configure-github] owner='{}' is_org={} mode={:?} ok={}",
            owner, is_org, mode, all_ok
        );
        for n in &org_notes {
            println!("  [ORG] {n}");
        }
        for rep in &reports {
            println!("  [REPO {}] ok={}", rep.full_repo, rep.ok);
            for act in &rep.actions_taken {
                println!("    + {act}");
            }
            for drift in &rep.drift_findings {
                println!("    ! {drift}");
            }
        }
    }

    if all_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

/// Drift findings for a repo-level `selected-actions` policy (GitHub-owned actions only).
pub fn selected_actions_drift(sel: &JsonValue) -> Vec<String> {
    let mut out = Vec::new();
    if sel.get("github_owned_allowed").and_then(JsonValue::as_bool) != Some(true) {
        out.push("selected-actions github_owned_allowed is not true".to_string());
    }
    if sel.get("verified_allowed").and_then(JsonValue::as_bool) != Some(false) {
        out.push("selected-actions verified_allowed is not false".to_string());
    }
    if sel
        .get("patterns_allowed")
        .and_then(JsonValue::as_array)
        .is_none_or(|a| !a.is_empty())
    {
        out.push("selected-actions patterns_allowed is not empty".to_string());
    }
    out
}

/// Deep verification of the `dotagent-zero-trust-main` ruleset body against the payload that
/// `--apply` writes: required checks + strict policy, pull_request parameters, and target refs.
pub fn ruleset_detail_drift(detail: &JsonValue, required_checks: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    if !detail
        .get("bypass_actors")
        .and_then(JsonValue::as_array)
        .is_some_and(<[JsonValue]>::is_empty)
    {
        out.push("ruleset bypass_actors must be an explicit empty array".to_string());
    }
    let empty: &[JsonValue] = &[];
    let rules = detail
        .get("rules")
        .and_then(JsonValue::as_array)
        .unwrap_or(empty);
    let find_rule = |t: &str| {
        rules
            .iter()
            .find(|r| r.get("type").and_then(JsonValue::as_str) == Some(t))
    };

    match find_rule("pull_request").and_then(|r| r.get("parameters")) {
        None => out.push("pull_request rule has no parameters".to_string()),
        Some(p) => {
            if p.get("dismiss_stale_reviews_on_push")
                .and_then(JsonValue::as_bool)
                != Some(true)
            {
                out.push("pull_request.dismiss_stale_reviews_on_push is not true".to_string());
            }
            if p.get("required_review_thread_resolution")
                .and_then(JsonValue::as_bool)
                != Some(true)
            {
                out.push("pull_request.required_review_thread_resolution is not true".to_string());
            }
            let methods: Vec<&str> = p
                .get("allowed_merge_methods")
                .and_then(JsonValue::as_array)
                .unwrap_or(empty)
                .iter()
                .filter_map(JsonValue::as_str)
                .collect();
            if methods != ["squash"] {
                out.push("pull_request.allowed_merge_methods is not exactly [squash]".to_string());
            }
            let approvals = p
                .get("required_approving_review_count")
                .and_then(JsonValue::as_u64)
                .unwrap_or(0);
            if approvals < MINIMUM_APPROVING_REVIEWS {
                out.push(format!(
                    "pull_request.required_approving_review_count must be at least {MINIMUM_APPROVING_REVIEWS}"
                ));
            }
            if p.get(EXTRA_COPILOT_APPROVAL).and_then(JsonValue::as_bool) != Some(true) {
                out.push(format!("pull_request.{EXTRA_COPILOT_APPROVAL} is not true"));
            }
        }
    }

    if !required_checks.is_empty() {
        match find_rule("required_status_checks").and_then(|r| r.get("parameters")) {
            None => out.push("missing required_status_checks rule".to_string()),
            Some(p) => {
                if p.get("strict_required_status_checks_policy")
                    .and_then(JsonValue::as_bool)
                    != Some(true)
                {
                    out.push("strict_required_status_checks_policy is not true".to_string());
                }
                let entries: &[JsonValue] = p
                    .get("required_status_checks")
                    .and_then(JsonValue::as_array)
                    .unwrap_or(empty);
                for req in required_checks {
                    let entry = entries.iter().find(|c| {
                        c.get("context").and_then(JsonValue::as_str) == Some(req.as_str())
                    });
                    match entry {
                        None => out.push(format!(
                            "required status check '{req}' missing from ruleset"
                        )),
                        Some(c) => {
                            if c.get("integration_id").and_then(JsonValue::as_u64)
                                != Some(GITHUB_ACTIONS_INTEGRATION_ID)
                            {
                                out.push(format!(
                                    "required status check '{req}' is not pinned to integration_id {GITHUB_ACTIONS_INTEGRATION_ID} (GitHub Actions)"
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    let includes_default = detail
        .get("conditions")
        .and_then(|c| c.get("ref_name"))
        .and_then(|r| r.get("include"))
        .and_then(JsonValue::as_array)
        .is_some_and(|a| {
            a.iter().any(|v| {
                matches!(
                    v.as_str(),
                    Some("~DEFAULT_BRANCH" | "refs/heads/main" | "~ALL")
                )
            })
        });
    if !includes_default {
        out.push("ruleset conditions.ref_name.include does not target ~DEFAULT_BRANCH".to_string());
    }
    if detail.get("target").and_then(JsonValue::as_str) != Some("branch") {
        out.push("ruleset target is not 'branch'".to_string());
    }
    out
}

fn gh_api_get_json(gh: &Path, endpoint: &str) -> Result<JsonValue, String> {
    let out = Command::new(gh)
        .args(["api", endpoint])
        .output()
        .map_err(|e| format!("gh api GET '{endpoint}' failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "gh api GET '{endpoint}' exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    JsonValue::parse(String::from_utf8_lossy(&out.stdout).trim())
        .map_err(|e| format!("invalid JSON from '{endpoint}': {e}"))
}

fn gh_api_write_json(
    gh: &Path,
    method: &str,
    endpoint: &str,
    body: &JsonValue,
) -> Result<JsonValue, String> {
    let mut child = Command::new(gh)
        .args(["api", "-X", method, endpoint, "--input", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("gh api {method} '{endpoint}' spawn failed: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(body.to_json_string().as_bytes())
            .map_err(|e| format!("gh api stdin write failed: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("gh api wait failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "gh api {method} '{endpoint}' failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let txt = String::from_utf8_lossy(&out.stdout);
    if txt.trim().is_empty() {
        Ok(JsonValue::Object(Vec::new()))
    } else {
        JsonValue::parse(txt.trim()).or_else(|_| Ok(JsonValue::Object(Vec::new())))
    }
}

fn detect_owner_is_org(gh: &Path, owner: &str) -> Result<bool, String> {
    validate_github_ident(owner)?;
    let v = gh_api_get_json(gh, &format!("users/{owner}"))?;
    Ok(v.get("type")
        .and_then(JsonValue::as_str)
        .is_some_and(|t| t.eq_ignore_ascii_case("Organization")))
}

fn list_owner_repos(gh: &Path, owner: &str, is_org: bool) -> Result<Vec<String>, String> {
    validate_github_ident(owner)?;
    let ep = if is_org {
        format!("orgs/{owner}/repos?per_page=100")
    } else {
        format!("users/{owner}/repos?per_page=100")
    };
    let out = Command::new(gh)
        .args(["api", "--paginate", "--slurp", &ep])
        .output()
        .map_err(|e| format!("gh api '{ep}' failed: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    let v = JsonValue::parse(String::from_utf8_lossy(&out.stdout).trim())
        .map_err(|e| format!("invalid JSON from '{ep}': {e}"))?;
    let mut names = Vec::new();
    if let Some(outer) = v.as_array() {
        for page in outer {
            if let Some(arr) = page.as_array() {
                for item in arr {
                    if item.get("archived").and_then(JsonValue::as_bool) == Some(true) {
                        continue;
                    }
                    if let Some(n) = item.get("name").and_then(JsonValue::as_str)
                        && validate_github_ident(n).is_ok()
                        && !names.contains(&n.to_string())
                    {
                        names.push(n.to_string());
                    }
                }
            }
        }
    }
    names.sort();
    Ok(names)
}

fn configure_or_verify_org(
    gh: &Path,
    org: &str,
    mode: GovernanceMode,
) -> Result<(bool, Vec<String>), String> {
    let mut notes = Vec::new();
    match mode {
        GovernanceMode::DryRun => {
            notes.push(format!(
                "[DRY-RUN] PUT orgs/{org}/actions/permissions -> {}",
                build_org_actions_permissions_payload().to_json_string()
            ));
            notes.push(format!(
                "[DRY-RUN] PUT orgs/{org}/actions/permissions/selected-actions -> {}",
                build_selected_actions_payload().to_json_string()
            ));
            notes.push(format!(
                "[DRY-RUN] PUT orgs/{org}/actions/permissions/workflow -> {}",
                build_workflow_permissions_payload().to_json_string()
            ));
            Ok((true, notes))
        }
        GovernanceMode::VerifyOnly => {
            let mut ok = true;
            let perms = gh_api_get_json(gh, &format!("orgs/{org}/actions/permissions"))?;
            if perms
                .get("sha_pinning_required")
                .and_then(JsonValue::as_bool)
                != Some(true)
            {
                ok = false;
                notes.push("DRIFT: org sha_pinning_required is not true".to_string());
            }
            if perms.get("allowed_actions").and_then(JsonValue::as_str) != Some("selected") {
                ok = false;
                notes.push("DRIFT: org allowed_actions is not 'selected'".to_string());
            }
            let wf = gh_api_get_json(gh, &format!("orgs/{org}/actions/permissions/workflow"))?;
            if wf
                .get("default_workflow_permissions")
                .and_then(JsonValue::as_str)
                != Some("read")
            {
                ok = false;
                notes.push("DRIFT: org default_workflow_permissions is not 'read'".to_string());
            }
            if wf
                .get("can_approve_pull_request_reviews")
                .and_then(JsonValue::as_bool)
                != Some(false)
            {
                ok = false;
                notes.push("DRIFT: org can_approve_pull_request_reviews is not false".to_string());
            }
            if ok {
                notes.push(
                    "verified org-wide Actions SHA-pinning, selected GitHub-owned actions, & read-only workflow token"
                        .to_string(),
                );
            }
            Ok((ok, notes))
        }
        GovernanceMode::Apply => {
            gh_api_write_json(
                gh,
                "PUT",
                &format!("orgs/{org}/actions/permissions"),
                &build_org_actions_permissions_payload(),
            )?;
            gh_api_write_json(
                gh,
                "PUT",
                &format!("orgs/{org}/actions/permissions/selected-actions"),
                &build_selected_actions_payload(),
            )?;
            gh_api_write_json(
                gh,
                "PUT",
                &format!("orgs/{org}/actions/permissions/workflow"),
                &build_workflow_permissions_payload(),
            )?;
            notes.push(format!(
                "Applied org-wide Actions SHA-pinning & read-only workflow defaults on '{org}'"
            ));
            Ok((true, notes))
        }
    }
}

fn discover_required_checks(
    gh: &Path,
    full_repo: &str,
    repo_short: &str,
    default_branch: &str,
) -> Vec<String> {
    if repo_short == "dotagent" {
        return dotagent_required_checks().map(str::to_owned).collect();
    }
    if validate_url_safe_branch(default_branch).is_err() {
        return Vec::new();
    }
    let encoded_branch = default_branch.replace('/', "%2F");
    let endpoint = format!("repos/{full_repo}/commits/{encoded_branch}/check-runs");
    let Ok(v) = gh_api_get_json(gh, &endpoint) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    if let Some(arr) = v.get("check_runs").and_then(JsonValue::as_array) {
        for cr in arr {
            let app_slug = cr
                .get("app")
                .and_then(|a| a.get("slug"))
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            if app_slug == "github-actions"
                && let Some(n) = cr.get("name").and_then(JsonValue::as_str)
                && !names.contains(&n.to_string())
            {
                names.push(n.to_string());
            }
        }
    }
    names.sort();
    names
}

fn configure_or_verify_repo(
    gh: &Path,
    full_repo: &str,
    repo_short: &str,
    is_org: bool,
    mode: GovernanceMode,
) -> Result<GovernanceRepoReport, String> {
    let mut actions_taken = Vec::new();
    let mut drift_findings = Vec::new();

    let repo_meta = gh_api_get_json(gh, &format!("repos/{full_repo}")).ok();
    let default_branch = repo_meta
        .as_ref()
        .and_then(|m| m.get("default_branch"))
        .and_then(JsonValue::as_str)
        .filter(|b| validate_url_safe_branch(b).is_ok())
        .unwrap_or("main")
        .to_string();

    let required_checks = discover_required_checks(gh, full_repo, repo_short, &default_branch);
    let ruleset_payload = build_main_ruleset_payload(&required_checks, true);

    match mode {
        GovernanceMode::DryRun => {
            actions_taken.push(format!(
                "[DRY-RUN] PATCH repos/{full_repo} -> {}",
                build_repo_merge_settings_payload().to_json_string()
            ));
            if !is_org {
                actions_taken.push(format!(
                    "[DRY-RUN] PUT repos/{full_repo}/actions/permissions -> {}",
                    build_user_repo_actions_permissions_payload().to_json_string()
                ));
            }
            actions_taken.push(format!(
                "[DRY-RUN] PUT repos/{full_repo}/actions/permissions/workflow -> {}",
                build_workflow_permissions_payload().to_json_string()
            ));
            actions_taken.push(format!(
                "[DRY-RUN] UPSERT ruleset '{RULESET_NAME}' on repos/{full_repo}/rulesets (bypass_actors=[], required_checks={})",
                required_checks.len()
            ));
            actions_taken.push(format!(
                "[DRY-RUN] ENSURE {} governance & AgentPI labels",
                GOVERNANCE_LABELS.len()
            ));
            Ok(GovernanceRepoReport {
                full_repo: full_repo.to_string(),
                ok: true,
                actions_taken,
                drift_findings,
            })
        }
        GovernanceMode::VerifyOnly => {
            let Some(meta) = repo_meta else {
                return Err(format!("unable to read repos/{full_repo}"));
            };
            if meta.get("allow_squash_merge").and_then(JsonValue::as_bool) != Some(true) {
                drift_findings.push("allow_squash_merge is not true".to_string());
            }
            if meta.get("allow_merge_commit").and_then(JsonValue::as_bool) != Some(false) {
                drift_findings.push(
                    "allow_merge_commit is true (expected false for linear squash-only history)"
                        .to_string(),
                );
            }
            if meta.get("allow_rebase_merge").and_then(JsonValue::as_bool) != Some(false) {
                drift_findings.push(
                    "allow_rebase_merge is true (expected false for squash-only history)"
                        .to_string(),
                );
            }
            if meta
                .get("delete_branch_on_merge")
                .and_then(JsonValue::as_bool)
                != Some(true)
            {
                drift_findings.push("delete_branch_on_merge is false (expected true)".to_string());
            }

            let act_perms = gh_api_get_json(gh, &format!("repos/{full_repo}/actions/permissions"))?;
            if act_perms
                .get("sha_pinning_required")
                .and_then(JsonValue::as_bool)
                != Some(true)
            {
                drift_findings.push("repo actions sha_pinning_required is not true".to_string());
            }
            if !is_org {
                if act_perms.get("allowed_actions").and_then(JsonValue::as_str) != Some("selected")
                {
                    drift_findings.push("repo allowed_actions is not 'selected'".to_string());
                } else {
                    let sel = gh_api_get_json(
                        gh,
                        &format!("repos/{full_repo}/actions/permissions/selected-actions"),
                    )?;
                    drift_findings.extend(selected_actions_drift(&sel));
                }
            }

            let wf = gh_api_get_json(
                gh,
                &format!("repos/{full_repo}/actions/permissions/workflow"),
            )?;
            if wf
                .get("default_workflow_permissions")
                .and_then(JsonValue::as_str)
                != Some("read")
            {
                drift_findings.push("default_workflow_permissions is not 'read'".to_string());
            }
            if wf
                .get("can_approve_pull_request_reviews")
                .and_then(JsonValue::as_bool)
                != Some(false)
            {
                drift_findings.push("can_approve_pull_request_reviews is not false".to_string());
            }

            let rulesets = gh_api_get_json(gh, &format!("repos/{full_repo}/rulesets"))?;
            let ruleset_id = rulesets.as_array().and_then(|arr| {
                arr.iter().find_map(|r| {
                    if r.get("name").and_then(JsonValue::as_str) == Some(RULESET_NAME)
                        && r.get("enforcement").and_then(JsonValue::as_str) == Some("active")
                    {
                        r.get("id").and_then(JsonValue::as_u64)
                    } else {
                        None
                    }
                })
            });

            match ruleset_id {
                None => {
                    drift_findings.push(format!(
                        "missing active ruleset '{RULESET_NAME}' on {full_repo}"
                    ));
                }
                Some(id) => {
                    let detail = gh_api_get_json(gh, &format!("repos/{full_repo}/rulesets/{id}"))?;
                    let rules_arr = detail
                        .get("rules")
                        .and_then(JsonValue::as_array)
                        .map(<[JsonValue]>::to_vec)
                        .unwrap_or_default();
                    for req_rule in [
                        "deletion",
                        "non_fast_forward",
                        "required_linear_history",
                        "pull_request",
                    ] {
                        if !rules_arr
                            .iter()
                            .any(|r| r.get("type").and_then(JsonValue::as_str) == Some(req_rule))
                        {
                            drift_findings.push(format!(
                                "ruleset '{RULESET_NAME}' missing mandatory '{req_rule}' rule"
                            ));
                        }
                    }
                    drift_findings.extend(ruleset_detail_drift(&detail, &required_checks));
                    actions_taken.push(format!(
                        "verified active ruleset '{RULESET_NAME}' (id={id}, bypass_actors=[])"
                    ));
                }
            }

            let ok = drift_findings.is_empty();
            Ok(GovernanceRepoReport {
                full_repo: full_repo.to_string(),
                ok,
                actions_taken,
                drift_findings,
            })
        }
        GovernanceMode::Apply => {
            gh_api_write_json(
                gh,
                "PATCH",
                &format!("repos/{full_repo}"),
                &build_repo_merge_settings_payload(),
            )?;
            actions_taken
                .push("applied squash-only linear merge & auto-delete-branch settings".to_string());

            if is_org {
                // Org-level selected-actions policy may lock repo-level allowed_actions (HTTP 409/422);
                // if the repo-level PUT is rejected, verify the effective repository policy still
                // enforces `sha_pinning_required: true` from the organization before proceeding.
                if let Err(put_err) = gh_api_write_json(
                    gh,
                    "PUT",
                    &format!("repos/{full_repo}/actions/permissions"),
                    &build_org_actions_permissions_payload(),
                ) {
                    let effective =
                        gh_api_get_json(gh, &format!("repos/{full_repo}/actions/permissions"))?;
                    let sha_pinned = effective
                        .get("sha_pinning_required")
                        .and_then(JsonValue::as_bool)
                        .unwrap_or(false);
                    if !sha_pinned {
                        return Err(format!(
                            "failed enforcing sha_pinning_required on '{full_repo}' ({put_err}) and effective repo policy has sha_pinning_required=false"
                        ));
                    }
                }
            } else {
                // Personal `User` account (`susanbeasles`): strictly enforce repo-level SHA pinning
                // and a GitHub-owned-only selected-actions allowlist.
                gh_api_write_json(
                    gh,
                    "PUT",
                    &format!("repos/{full_repo}/actions/permissions"),
                    &build_user_repo_actions_permissions_payload(),
                )?;
                gh_api_write_json(
                    gh,
                    "PUT",
                    &format!("repos/{full_repo}/actions/permissions/selected-actions"),
                    &build_selected_actions_payload(),
                )?;
            }
            gh_api_write_json(
                gh,
                "PUT",
                &format!("repos/{full_repo}/actions/permissions/workflow"),
                &build_workflow_permissions_payload(),
            )?;
            actions_taken.push(
                "enforced SHA-pinned Actions & read-only GITHUB_TOKEN workflow permissions"
                    .to_string(),
            );

            let existing_id = gh_api_get_json(gh, &format!("repos/{full_repo}/rulesets"))?
                .as_array()
                .and_then(|arr| {
                    arr.iter().find_map(|r| {
                        if r.get("name").and_then(JsonValue::as_str) == Some(RULESET_NAME) {
                            r.get("id").and_then(JsonValue::as_u64)
                        } else {
                            None
                        }
                    })
                });

            let (method, ep) = match existing_id {
                Some(id) => ("PUT", format!("repos/{full_repo}/rulesets/{id}")),
                None => ("POST", format!("repos/{full_repo}/rulesets")),
            };

            match gh_api_write_json(gh, method, &ep, &ruleset_payload) {
                Ok(_) => {
                    actions_taken.push(format!(
                        "upserted active ruleset '{RULESET_NAME}' (bypass_actors=[], copilot_code_review=true, required_checks={})",
                        required_checks.len()
                    ));
                }
                Err(first_err) => {
                    let lower_err = first_err.to_ascii_lowercase();
                    if !(first_err.contains("422") || lower_err.contains("copilot")) {
                        return Err(format!("ruleset upsert failed: {first_err}"));
                    }
                    let fallback_payload = build_main_ruleset_payload(&required_checks, false);
                    gh_api_write_json(gh, method, &ep, &fallback_payload).map_err(|e2| {
                        format!("ruleset upsert failed ({first_err}; fallback also failed: {e2})")
                    })?;
                    actions_taken.push(format!(
                        "upserted active ruleset '{RULESET_NAME}' (bypass_actors=[], without copilot_code_review rule due to account tier; required_checks={})",
                        required_checks.len()
                    ));
                }
            }

            for &(name, color, desc) in GOVERNANCE_LABELS {
                let st = Command::new(gh)
                    .args([
                        "label",
                        "create",
                        name,
                        "-R",
                        full_repo,
                        "--color",
                        color,
                        "--description",
                        desc,
                        "--force",
                    ])
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .output()
                    .map_err(|e| format!("gh label create '{name}' failed: {e}"))?;
                if !st.status.success() {
                    return Err(format!(
                        "gh label create '{name}' failed: {}",
                        String::from_utf8_lossy(&st.stderr).trim()
                    ));
                }
            }
            actions_taken.push(format!(
                "provisioned {} friction & AgentPI labels",
                GOVERNANCE_LABELS.len()
            ));

            Ok(GovernanceRepoReport {
                full_repo: full_repo.to_string(),
                ok: true,
                actions_taken,
                drift_findings,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_check_catalog_has_unique_names_and_both_review_gates() {
        assert!(DOTAGENT_REQUIRED_CHECKS.ends_with('\n'));
        assert!(!DOTAGENT_REQUIRED_CHECKS.contains('\r'));
        let mut names = std::collections::BTreeSet::new();
        for name in dotagent_required_checks() {
            assert!(!name.is_empty() && name == name.trim());
            assert!(!name.chars().any(char::is_control));
            assert!(names.insert(name), "duplicate check name: {name}");
        }
        assert!(names.contains(RATCHET_CHECK_RUN));
        assert!(names.contains(COPILOT_GATE_CONTEXT));
    }

    #[test]
    fn builds_required_check_non_bypass_ruleset_and_validates_identifiers() {
        let checks: Vec<String> = dotagent_required_checks().map(str::to_owned).collect();
        let checks_without_review: Vec<String> = dotagent_required_checks()
            .filter(|name| *name != COPILOT_GATE_CONTEXT)
            .map(str::to_owned)
            .collect();
        let payload = build_main_ruleset_payload(&checks, true);
        let s = payload.to_json_string();
        assert!(s.contains(RULESET_NAME));
        assert!(s.contains("\"bypass_actors\":[]"));
        assert!(s.contains("\"required_review_thread_resolution\":true"));
        assert!(s.contains("Ring-0 Constitutional Ratchet"));
        assert!(s.contains("Ring-0 & Copilot Gate"));

        // The approval floor applies regardless of the selected automated gates.
        let empty_fb = build_main_ruleset_payload(&[], false).to_json_string();
        assert!(empty_fb.contains("\"required_approving_review_count\":1"));
        let ci_only = build_main_ruleset_payload(&checks_without_review, false).to_json_string();
        assert!(ci_only.contains("\"required_approving_review_count\":1"));
        let copilot_only = build_main_ruleset_payload(&[], true).to_json_string();
        assert!(copilot_only.contains("\"required_approving_review_count\":1"));
        let weak = build_main_ruleset_payload(&checks_without_review, true);
        let copilot_ci = weak.to_json_string();
        assert!(copilot_ci.contains("\"required_approving_review_count\":1"));
        assert!(s.contains("\"required_approving_review_count\":1"));
        assert!(s.contains("\"require_extra_approval_for_unattributed_changes\":true"));
        assert!(s.contains("\"integration_id\":15368"));

        assert!(ruleset_detail_drift(&payload, &checks).is_empty());
        let drift = ruleset_detail_drift(&weak, &checks);
        assert!(drift.iter().any(|d| d.contains("Ring-0 & Copilot Gate")));
        let no_approval = JsonValue::parse(&s.replace(
            "\"required_approving_review_count\":1",
            "\"required_approving_review_count\":0",
        ))
        .unwrap();
        assert!(
            ruleset_detail_drift(&no_approval, &checks)
                .iter()
                .any(|d| { d.contains("required_approving_review_count") })
        );
        let no_extra_approval = JsonValue::parse(&s.replace(
            "\"require_extra_approval_for_unattributed_changes\":true,",
            "",
        ))
        .unwrap();
        assert!(
            ruleset_detail_drift(&no_extra_approval, &checks)
                .iter()
                .any(|d| { d.contains(EXTRA_COPILOT_APPROVAL) })
        );
        let no_bypass = JsonValue::parse(&s.replace("\"bypass_actors\":[],", "")).unwrap();
        assert!(
            ruleset_detail_drift(&no_bypass, &checks)
                .iter()
                .any(|d| { d.contains("bypass_actors") })
        );
        let unpinned =
            JsonValue::parse(&s.replace("\"integration_id\":15368", "\"integration_id\":1"))
                .unwrap_or(JsonValue::Null);
        let drift_unpinned = ruleset_detail_drift(&unpinned, &checks);
        assert!(drift_unpinned.iter().any(|d| d.contains("integration_id")));
        assert!(selected_actions_drift(&build_selected_actions_payload()).is_empty());

        assert!(validate_github_ident("susanbdev").is_ok());
        assert!(validate_github_ident("susanbeasles").is_ok());
        assert!(validate_github_ident("../evil").is_err());
        assert!(validate_github_ident("-flag").is_err());
    }
}
