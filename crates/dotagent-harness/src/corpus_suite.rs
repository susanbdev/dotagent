//! Canonical adversarial bypass corpus verifier (`tests/bypass_corpus.toml`)
//! integrated into `dotagent-harness` reporting.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Instant;

use agent_guard::cmd_policy::evaluate_shell_command;
use agent_guard::injection_scan::scan_untrusted_content;
use agent_guard::json::JsonValue;
use agent_guard::path_policy::{PathAccess, validate_path};
use agent_guard::unicode_guard::{ScanMode, scan_unicode};
use agent_guard::{Decision, handle_pre_tool_hook};

use crate::CaseResult;
use crate::sandbox::TestSandbox;

pub fn corpus_case_ids() -> Vec<&'static str> {
    vec!["corpus::bypass_corpus_100_percent_deny"]
}

pub fn run_corpus_suite(workspace_root: &Path, filter: Option<&str>) -> Vec<CaseResult> {
    let id = "corpus::bypass_corpus_100_percent_deny";
    if let Some(f) = filter
        && !id.contains(f)
    {
        return Vec::new();
    }
    let started = Instant::now();
    match verify_corpus(workspace_root) {
        Ok(detail) => vec![CaseResult::pass(
            id.to_string(),
            "corpus",
            started.elapsed().as_millis() as u64,
            detail,
        )],
        Err(err) => vec![CaseResult::fail(
            id.to_string(),
            "corpus",
            started.elapsed().as_millis() as u64,
            err,
        )],
    }
}

struct VectorEntry {
    kind: String,
    payload: String,
}

fn verify_corpus(workspace_root: &Path) -> Result<String, String> {
    let corpus_path = workspace_root.join("tests").join("bypass_corpus.toml");
    let raw = fs::read_to_string(&corpus_path)
        .map_err(|e| format!("failed reading '{}': {e}", corpus_path.display()))?;
    let vectors = parse_corpus_vectors(&raw)?;
    if vectors.is_empty() {
        return Err("bypass_corpus.toml contained 0 vectors".to_string());
    }

    let sb = TestSandbox::create(workspace_root, "corpus_verify")?;
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    let mut allowed_leaks = Vec::new();

    for (idx, vec_item) in vectors.iter().enumerate() {
        *by_kind.entry(vec_item.kind.clone()).or_insert(0) += 1;
        let blocked = match vec_item.kind.as_str() {
            "cmd" => evaluate_shell_command(&vec_item.payload, &sb.repo_dir, &sb.repo_dir, false)
                .is_err(),
            "read_path" => validate_path(
                &sb.repo_dir,
                &sb.repo_dir,
                &vec_item.payload,
                PathAccess::Read,
            )
            .is_err(),
            "write_path" => validate_path(
                &sb.repo_dir,
                &sb.repo_dir,
                &vec_item.payload,
                PathAccess::Write,
            )
            .is_err(),
            "glob" => {
                let hook = JsonValue::Object(vec![
                    (
                        "session_id".to_string(),
                        JsonValue::Str(format!("corpus-glob-{idx}")),
                    ),
                    (
                        "cwd".to_string(),
                        JsonValue::Str(sb.repo_dir.to_string_lossy().into_owned()),
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
                matches!(
                    handle_pre_tool_hook(&hook.to_json_string(), &sb.repo_dir),
                    Decision::Deny { .. }
                )
            }
            "content" => {
                let uni = scan_unicode(&vec_item.payload, ScanMode::UntrustedContent);
                let inj =
                    scan_untrusted_content(&vec_item.payload, &sb.repo_dir, &sb.repo_dir, false);
                !uni.is_empty() || inj.first_halt().is_some() || !inj.findings.is_empty()
            }
            "mcp" => agent_guard::ring0_ratchet::mcp_corpus_vector_blocked(&vec_item.payload),
            other => {
                return Err(format!(
                    "unknown vector kind '{other}' at vector #{}",
                    idx + 1
                ));
            }
        };

        if !blocked {
            allowed_leaks.push(format!("#{} ({})", idx + 1, vec_item.kind));
        }
    }

    if !allowed_leaks.is_empty() {
        return Err(format!(
            "{} bypass vectors unexpectedly allowed: {}",
            allowed_leaks.len(),
            allowed_leaks.join(", ")
        ));
    }

    let breakdown: Vec<String> = by_kind
        .into_iter()
        .map(|(k, n)| format!("{k}={n}"))
        .collect();
    Ok(format!(
        "Blocked {}/{} canonical bypass vectors ({})",
        vectors.len(),
        vectors.len(),
        breakdown.join(", ")
    ))
}

fn parse_corpus_vectors(raw: &str) -> Result<Vec<VectorEntry>, String> {
    let pairs = agent_guard::ring0_ratchet::parse_bypass_corpus_vectors_ordered(raw)?;
    Ok(pairs
        .into_iter()
        .map(|(kind, payload)| VectorEntry { kind, payload })
        .collect())
}
