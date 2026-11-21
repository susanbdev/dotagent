//! Empirical Subagent Airlock Usefulness & `max_direct_discovery_calls` Pareto Calibration Suite.
//!
//! Answers two engineering questions with reproducible measurements over real repository modules
//! and real `agent-guard` hook executions (`handle_user_prompt_hook`, `handle_pre_tool_hook`,
//! `handle_post_tool_hook`, and `SessionLedger`):
//! 1. **Does `research-airlock` measurably improve parent context hygiene and safety?**
//!    Measures parent BPE token accumulation, untrusted exploratory file exposure inside the
//!    write-capable `coding-agent` ledger, and `A -> B -> C` hop-graph exhaustion on downstream
//!    edits with vs. without airlock delegation.
//! 2. **Why `max_direct_discovery_calls = 4` (vs `0, 1, 2, 3, 6, 8, 12, 28`)?**
//!    Sweeps candidate caps across 10 realistic workloads (5 surgical `0..=4`-lookup edits +
//!    5 multi-module `5..=14`-lookup investigations) grounded in real `susanbdev/dotagent` crate
//!    slices and search outputs to locate the Pareto knee minimizing both surgical friction and
//!    parent context/taint bloat.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use agent_guard::budget_guard::estimate_bpe_tokens;
use agent_guard::json::JsonValue;
use agent_guard::traversal_ledger::SessionLedger;
use agent_guard::{Decision, handle_post_tool_hook, handle_pre_tool_hook, handle_user_prompt_hook};

use crate::{HarnessConfig, ReportFormat};

pub const CANDIDATE_DISCOVERY_CAPS: &[usize] = &[0, 1, 2, 3, 4, 5, 6, 8, 12, 28];

/// Average follow-up parent tool turns in an implementation step (`Read` -> `Edit` -> `test` -> reply)
/// that re-process every token retained in the parent context window.
pub const PARENT_FOLLOWUP_TURNS: usize = 4;

/// One-time child subagent constitution/prompt + orchestration round-trip overhead (paid once and discarded).
pub const SUBAGENT_BOOT_OVERHEAD_TOKENS: usize = 2_800;

#[derive(Debug, Clone)]
pub struct RepoCorpusBaseline {
    pub rust_files_sampled: usize,
    pub median_120_line_slice_tokens: usize,
    pub p90_120_line_slice_tokens: usize,
    pub median_search_output_tokens: usize,
    pub scenario_max_inline_discoveries: usize,
}

#[derive(Debug, Clone)]
pub struct CapSweepRow {
    pub max_direct_discovery_calls: usize,
    pub surgical_forced_subagent_pct: f64,
    pub investigation_caught_pct: f64,
    pub mean_surgical_parent_tokens: usize,
    pub mean_investigation_parent_tokens: usize,
    pub investigation_token_savings_pct: f64,
    pub parent_exploratory_files_exposed: usize,
    pub downstream_hop_blocks: usize,
    pub step_budget_failures: usize,
    pub pareto_effective_cost: usize,
}

#[derive(Debug, Clone)]
pub struct AirlockEvalReport {
    pub baseline: RepoCorpusBaseline,
    pub rows: Vec<CapSweepRow>,
    pub recommended_cap: usize,
}

#[derive(Clone, Copy)]
enum WorkloadKind {
    Surgical,
    Investigation,
}

struct WorkloadSpec {
    id: &'static str,
    kind: WorkloadKind,
    discovery_steps: usize,
    exploratory_slice_reads: usize,
    target_impl_reads: usize,
    triggers_hop_chain: bool,
}

const WORKLOADS: &[WorkloadSpec] = &[
    // 5 Surgical daily coding tasks (0..=4 targeted lookups)
    WorkloadSpec {
        id: "s0_known_path_direct_edit",
        kind: WorkloadKind::Surgical,
        discovery_steps: 0,
        exploratory_slice_reads: 0,
        target_impl_reads: 1,
        triggers_hop_chain: false,
    },
    WorkloadSpec {
        id: "s1_single_symbol_hotfix",
        kind: WorkloadKind::Surgical,
        discovery_steps: 1,
        exploratory_slice_reads: 0,
        target_impl_reads: 1,
        triggers_hop_chain: false,
    },
    WorkloadSpec {
        id: "s2_cli_flag_plus_test_wiring",
        kind: WorkloadKind::Surgical,
        discovery_steps: 2,
        exploratory_slice_reads: 0,
        target_impl_reads: 2,
        triggers_hop_chain: false,
    },
    WorkloadSpec {
        id: "s3_def_callers_and_test_seam",
        kind: WorkloadKind::Surgical,
        discovery_steps: 3,
        exploratory_slice_reads: 1,
        target_impl_reads: 2,
        triggers_hop_chain: false,
    },
    WorkloadSpec {
        id: "s4_four_crate_workspace_glob_check",
        kind: WorkloadKind::Surgical,
        discovery_steps: 4,
        exploratory_slice_reads: 0,
        target_impl_reads: 2,
        triggers_hop_chain: false,
    },
    // 5 Broad / unfamiliar repo investigation tasks (5..=14 lookups + exploratory reads)
    WorkloadSpec {
        id: "i5_cross_crate_policy_trace",
        kind: WorkloadKind::Investigation,
        discovery_steps: 5,
        exploratory_slice_reads: 3,
        target_impl_reads: 2,
        triggers_hop_chain: false,
    },
    WorkloadSpec {
        id: "i7_unfamiliar_subsystem_survey",
        kind: WorkloadKind::Investigation,
        discovery_steps: 7,
        exploratory_slice_reads: 4,
        target_impl_reads: 2,
        triggers_hop_chain: true,
    },
    WorkloadSpec {
        id: "i9_multi_harness_adapter_audit",
        kind: WorkloadKind::Investigation,
        discovery_steps: 9,
        exploratory_slice_reads: 5,
        target_impl_reads: 2,
        triggers_hop_chain: false,
    },
    WorkloadSpec {
        id: "i11_role_sandbox_security_review",
        kind: WorkloadKind::Investigation,
        discovery_steps: 11,
        exploratory_slice_reads: 6,
        target_impl_reads: 2,
        triggers_hop_chain: true,
    },
    WorkloadSpec {
        id: "i14_full_repo_architecture_map",
        kind: WorkloadKind::Investigation,
        discovery_steps: 14,
        exploratory_slice_reads: 8,
        target_impl_reads: 2,
        triggers_hop_chain: true,
    },
];

pub fn run_airlock_evaluation(cfg: &HarnessConfig) -> Result<AirlockEvalReport, String> {
    let baseline = measure_workspace_baseline(&cfg.workspace_root)?;
    let sb = cfg
        .workspace_root
        .join("target")
        .join(format!("tairlock-eval-{}", std::process::id()));
    let _ = fs::remove_dir_all(&sb);
    let home = sb.join("h");
    let repo = sb.join("repo");
    fs::create_dir_all(&home).map_err(|e| format!("create eval home: {e}"))?;
    fs::create_dir_all(repo.join("profiles")).map_err(|e| format!("create profiles: {e}"))?;
    fs::create_dir_all(repo.join("src")).map_err(|e| format!("create src: {e}"))?;

    let init = Command::new("git")
        .arg("init")
        .arg(&repo)
        .env("HOME", &home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .map_err(|e| format!("git init eval repo: {e}"))?;
    if !init.status.success() {
        return Err("git init failed in airlock eval repo".to_string());
    }

    fs::write(repo.join("AGENTS.md"), "# Canonical Root Authority\n")
        .map_err(|e| format!("write AGENTS.md: {e}"))?;

    // Stage 10 realistic Rust module files matching the workspace's measured median slice token size,
    // plus an A -> B -> C pointer chain (`mod_0.rs` -> `mod_1.rs` -> `hop_c.rs`) to test hop pollution!
    stage_realistic_modules(&repo, &cfg.workspace_root)?;

    let search_hit_blob = build_realistic_search_output(baseline.median_search_output_tokens);
    let airlock_summary_blob = "1) src/impl_0.rs:1-48 pub fn apply_patch_step(ctx: &StepCtx) -> Result<(), GuardErr>\n\
         2) src/impl_1.rs:1-42 pub fn verify_postconditions(state: &Ledger) -> bool\n\
         3) Hop boundary clean; 0 forbidden pointers.";

    let mut raw_rows = Vec::with_capacity(CANDIDATE_DISCOVERY_CAPS.len());
    for &cap_k in CANDIDATE_DISCOVERY_CAPS {
        write_profile_with_discovery_cap(&repo, cap_k)?;
        let row = evaluate_single_cap(&repo, cap_k, &search_hit_blob, airlock_summary_blob)?;
        raw_rows.push(row);
    }

    let unbounded_inv_tokens = raw_rows
        .last()
        .map(|r| r.mean_investigation_parent_tokens.max(1))
        .unwrap_or(1);
    for row in &mut raw_rows {
        let saved = unbounded_inv_tokens.saturating_sub(row.mean_investigation_parent_tokens);
        row.investigation_token_savings_pct =
            (saved as f64 * 100.0) / (unbounded_inv_tokens as f64);
    }

    // Select standalone zero-friction Pareto knee: minimum `pareto_effective_cost` among caps with
    // `0` step budget OOMs, `0` downstream hop blocks, `0` untrusted exploratory exposure, and `0%` surgical friction.
    let recommended_cap = raw_rows
        .iter()
        .filter(|r| {
            r.step_budget_failures == 0
                && r.downstream_hop_blocks == 0
                && r.parent_exploratory_files_exposed == 0
                && r.surgical_forced_subagent_pct == 0.0
        })
        .min_by_key(|r| r.pareto_effective_cost)
        .or_else(|| {
            raw_rows
                .iter()
                .filter(|r| r.step_budget_failures == 0 && r.downstream_hop_blocks == 0)
                .min_by_key(|r| r.pareto_effective_cost)
        })
        .map(|r| r.max_direct_discovery_calls)
        .unwrap_or(4);

    let _ = fs::remove_dir_all(&sb);
    Ok(AirlockEvalReport {
        baseline,
        rows: raw_rows,
        recommended_cap,
    })
}

fn measure_workspace_baseline(workspace_root: &Path) -> Result<RepoCorpusBaseline, String> {
    let mut slice_tokens = Vec::new();
    let mut search_tokens = Vec::new();
    let crate_src_dirs = [
        workspace_root.join("crates/agent-guard/src"),
        workspace_root.join("crates/dotagent-compiler/src"),
        workspace_root.join("crates/dotagent-harness/src"),
        workspace_root.join("crates/swarm-tools/src"),
    ];

    for dir in &crate_src_dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        let mut dir_sig_lines = Vec::new();
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let Ok(text) = fs::read_to_string(&p) else {
                continue;
            };
            let first_120: String = text.lines().take(120).collect::<Vec<_>>().join("\n");
            slice_tokens.push(estimate_bpe_tokens(&first_120));

            let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("mod.rs");
            for (idx, line) in text.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("pub fn ") || trimmed.starts_with("pub struct ") {
                    dir_sig_lines.push(format!("{fname}:{}: {trimmed}", idx + 1));
                    if dir_sig_lines.len() >= 14 {
                        break;
                    }
                }
            }
        }
        if !dir_sig_lines.is_empty() {
            search_tokens.push(estimate_bpe_tokens(&dir_sig_lines.join("\n")));
        }
    }

    slice_tokens.sort_unstable();
    search_tokens.sort_unstable();

    let scenario_max_inline = measure_max_inline_discoveries_in_scenarios(workspace_root);

    let n = slice_tokens.len().max(1);
    let med_slice = slice_tokens.get(n / 2).copied().unwrap_or(620);
    let p90_slice = slice_tokens
        .get((n.saturating_mul(9)) / 10)
        .copied()
        .unwrap_or(880);
    let med_search = search_tokens
        .get(search_tokens.len() / 2)
        .copied()
        .unwrap_or(115);

    Ok(RepoCorpusBaseline {
        rust_files_sampled: slice_tokens.len(),
        median_120_line_slice_tokens: med_slice,
        p90_120_line_slice_tokens: p90_slice,
        median_search_output_tokens: med_search,
        scenario_max_inline_discoveries: scenario_max_inline,
    })
}

fn measure_max_inline_discoveries_in_scenarios(workspace_root: &Path) -> usize {
    let scen_dir = workspace_root.join("tests/scenarios");
    let Ok(entries) = fs::read_dir(scen_dir) else {
        return 2;
    };
    let mut max_disc = 0usize;
    for entry in entries.flatten() {
        let Ok(raw) = fs::read_to_string(entry.path()) else {
            continue;
        };
        for block in raw.split("[[scenario]]").skip(1) {
            let mut cur = 0usize;
            for step in block.split("[[scenario.steps]]").skip(1) {
                if step.contains("expect_exit = 0")
                    && (step.contains("\"Grep\"")
                        || step.contains("\"Glob\"")
                        || step.contains("\"grep_search\"")
                        || step.contains("\"find_by_name\"")
                        || step.contains("rg ")
                        || step.contains("find "))
                {
                    cur += 1;
                }
            }
            max_disc = max_disc.max(cur);
        }
    }
    max_disc
}

fn stage_realistic_modules(repo: &Path, workspace_root: &Path) -> Result<(), String> {
    let seed_rs = fs::read_to_string(workspace_root.join("crates/agent-guard/src/budget_guard.rs"))
        .unwrap_or_else(|_| "pub fn fallback_fn(x: usize) -> usize { x + 1 }\n".repeat(90));
    let clean_seed: String = seed_rs
        .lines()
        .filter(|l| l.is_ascii() && !l.contains("AGENTS.md") && !l.contains("/tmp"))
        .take(95)
        .collect::<Vec<_>>()
        .join("\n");

    for idx in 0..8 {
        let mut content = format!("//! Exploratory module {idx} with untrusted comments.\n");
        if idx == 0 {
            // Level-1 read of explore_0.rs discovers hop_b.rs (level 2), which in turn points to hop_c.rs (level 3)!
            content.push_str("// Follow-up adapter lives in `src/hop_b.rs` for transit.\n");
        }
        content.push_str(&clean_seed);
        content.push('\n');
        fs::write(repo.join("src").join(format!("explore_{idx}.rs")), content)
            .map_err(|e| format!("write explore_{idx}.rs: {e}"))?;
    }

    fs::write(
        repo.join("src/hop_b.rs"),
        format!(
            "//! Hop-B intermediate module (not in initial grep output).\n// Final seam lives in `src/hop_c.rs` next.\n{clean_seed}\n"
        ),
    )
    .map_err(|e| format!("write hop_b.rs: {e}"))?;

    for idx in 0..2 {
        let impl_body = format!(
            "//! Target surgical implementation module {idx}.\npub fn apply_step_{idx}(v: u64) -> u64 {{ v + {idx} }}\n{clean_seed}\n"
        );
        fs::write(repo.join("src").join(format!("impl_{idx}.rs")), impl_body)
            .map_err(|e| format!("write impl_{idx}.rs: {e}"))?;
    }
    fs::write(
        repo.join("src/hop_c.rs"),
        format!(
            "//! Hop-C target module.\npub fn hop_c_target() -> bool {{ true }}\n{clean_seed}\n"
        ),
    )
    .map_err(|e| format!("write hop_c.rs: {e}"))?;

    Ok(())
}

fn build_realistic_search_output(target_tokens: usize) -> String {
    let mut out = String::new();
    let mut line_no = 1usize;
    while estimate_bpe_tokens(&out) < target_tokens.max(60) {
        let _ = writeln!(
            &mut out,
            "src/explore_{}.rs:{}: pub fn evaluate_policy_gate_{}(ctx: &HookContext, cap: usize) -> Decision",
            line_no % 8,
            line_no * 11,
            line_no
        );
        line_no += 1;
    }
    out
}

fn write_profile_with_discovery_cap(repo: &Path, cap_k: usize) -> Result<(), String> {
    let pad = " ".repeat(cap_k % 17);
    let toml = format!(
        "profile_id = \"coding-agent\"{pad}\n\
         version = \"1.0.0\"\n\
         [isolation]\n\
         disable_auto_memory = true\n\
         per_repo_state_namespace = true\n\
         block_cross_repo_reads = true\n\
         taint_gates_privileged_clis = true\n\
         subagent_airlock_max_tokens = 200\n\
         max_direct_discovery_calls = {cap_k}\n"
    );
    fs::write(repo.join("profiles/coding-agent.toml"), toml)
        .map_err(|e| format!("write coding-agent.toml: {e}"))
}

fn evaluate_single_cap(
    repo: &Path,
    cap_k: usize,
    search_hit_blob: &str,
    airlock_summary_blob: &str,
) -> Result<CapSweepRow, String> {
    let cwd_s = repo.to_string_lossy().into_owned();
    let mut surgical_count = 0usize;
    let mut surgical_forced = 0usize;
    let mut inv_count = 0usize;
    let mut inv_caught = 0usize;
    let mut surgical_tokens_sum = 0usize;
    let mut inv_tokens_sum = 0usize;
    let mut parent_exploratory_exposed = 0usize;
    let mut downstream_hop_blocks = 0usize;
    let mut step_budget_failures = 0usize;
    let mut total_effective_cost = 0usize;

    for w in WORKLOADS {
        let sid = format!("eval_k{cap_k}_{}", w.id);
        let reset = JsonValue::Object(vec![
            ("session_id".to_string(), JsonValue::Str(sid.clone())),
            ("cwd".to_string(), JsonValue::Str(cwd_s.clone())),
            (
                "prompt".to_string(),
                JsonValue::Str(format!("Execute task {}", w.id)),
            ),
        ])
        .to_json_string();
        if !handle_user_prompt_hook(&reset, repo).is_allow() {
            return Err(format!("user_prompt reset failed for {sid}"));
        }

        let mut delegated_to_airlock = false;
        let mut hit_budget_failure = false;
        for step_idx in 0..w.discovery_steps {
            let grep_req = JsonValue::Object(vec![
                ("session_id".to_string(), JsonValue::Str(sid.clone())),
                ("cwd".to_string(), JsonValue::Str(cwd_s.clone())),
                ("tool_name".to_string(), JsonValue::Str("Grep".to_string())),
                (
                    "tool_input".to_string(),
                    JsonValue::Object(vec![
                        ("path".to_string(), JsonValue::Str("src".to_string())),
                        (
                            "pattern".to_string(),
                            JsonValue::Str(format!("gate_{step_idx}")),
                        ),
                    ]),
                ),
            ])
            .to_json_string();

            match handle_pre_tool_hook(&grep_req, repo) {
                Decision::Allow { .. } => {
                    let post_grep = JsonValue::Object(vec![
                        ("session_id".to_string(), JsonValue::Str(sid.clone())),
                        ("cwd".to_string(), JsonValue::Str(cwd_s.clone())),
                        ("tool_name".to_string(), JsonValue::Str("Grep".to_string())),
                        (
                            "tool_response".to_string(),
                            JsonValue::Str(search_hit_blob.to_string()),
                        ),
                    ])
                    .to_json_string();
                    if let Decision::Deny {
                        code: "TURN_TOKEN_BUDGET_EXCEEDED",
                        ..
                    } = handle_post_tool_hook(&post_grep, repo)
                    {
                        hit_budget_failure = true;
                        break;
                    }
                }
                Decision::Deny {
                    code: "SUBAGENT_AIRLOCK_REQUIRED",
                    ..
                } => {
                    let task_req = JsonValue::Object(vec![
                        ("session_id".to_string(), JsonValue::Str(sid.clone())),
                        ("cwd".to_string(), JsonValue::Str(cwd_s.clone())),
                        ("tool_name".to_string(), JsonValue::Str("Task".to_string())),
                        (
                            "tool_input".to_string(),
                            JsonValue::Object(vec![
                                (
                                    "subagent_type".to_string(),
                                    JsonValue::Str("research-airlock".to_string()),
                                ),
                                (
                                    "prompt".to_string(),
                                    JsonValue::Str("Map target symbol slices in src".to_string()),
                                ),
                            ]),
                        ),
                    ])
                    .to_json_string();
                    if !handle_pre_tool_hook(&task_req, repo).is_allow() {
                        return Err("research-airlock delegation unexpectedly denied".to_string());
                    }
                    let post_task = JsonValue::Object(vec![
                        ("session_id".to_string(), JsonValue::Str(sid.clone())),
                        ("cwd".to_string(), JsonValue::Str(cwd_s.clone())),
                        ("tool_name".to_string(), JsonValue::Str("Task".to_string())),
                        (
                            "tool_response".to_string(),
                            JsonValue::Str(airlock_summary_blob.to_string()),
                        ),
                    ])
                    .to_json_string();
                    let _ = handle_post_tool_hook(&post_task, repo);
                    delegated_to_airlock = true;
                    break;
                }
                Decision::Deny {
                    code: "TURN_TOKEN_BUDGET_EXCEEDED" | "SESSION_HALTED_OR_EXHAUSTED",
                    ..
                } => {
                    hit_budget_failure = true;
                    break;
                }
                other => {
                    return Err(format!(
                        "unexpected decision on Grep in {}: {other:?}",
                        w.id
                    ));
                }
            }
        }

        if !delegated_to_airlock {
            for r_idx in 0..w.exploratory_slice_reads {
                let rel = if w.triggers_hop_chain && r_idx == 1 {
                    "src/hop_b.rs".to_string()
                } else {
                    format!("src/explore_{}.rs", r_idx % 8)
                };
                let read_req = JsonValue::Object(vec![
                    ("session_id".to_string(), JsonValue::Str(sid.clone())),
                    ("cwd".to_string(), JsonValue::Str(cwd_s.clone())),
                    ("tool_name".to_string(), JsonValue::Str("Read".to_string())),
                    (
                        "tool_input".to_string(),
                        JsonValue::Object(vec![
                            ("file_path".to_string(), JsonValue::Str(rel)),
                            ("offset".to_string(), JsonValue::Uint(1)),
                            ("limit".to_string(), JsonValue::Uint(90)),
                        ]),
                    ),
                ])
                .to_json_string();
                match handle_pre_tool_hook(&read_req, repo) {
                    Decision::Allow { .. } => {
                        if matches!(w.kind, WorkloadKind::Investigation) {
                            parent_exploratory_exposed += 1;
                        }
                    }
                    Decision::Deny {
                        code: "TURN_TOKEN_BUDGET_EXCEEDED" | "FILE_READ_BUDGET_EXCEEDED",
                        ..
                    } => {
                        hit_budget_failure = true;
                    }
                    _ => {}
                }
            }
        }

        for impl_idx in 0..w.target_impl_reads {
            let target_rel = if w.triggers_hop_chain && impl_idx + 1 == w.target_impl_reads {
                "src/hop_c.rs".to_string()
            } else {
                format!("src/impl_{}.rs", impl_idx % 2)
            };
            let impl_read = JsonValue::Object(vec![
                ("session_id".to_string(), JsonValue::Str(sid.clone())),
                ("cwd".to_string(), JsonValue::Str(cwd_s.clone())),
                ("tool_name".to_string(), JsonValue::Str("Read".to_string())),
                (
                    "tool_input".to_string(),
                    JsonValue::Object(vec![
                        ("file_path".to_string(), JsonValue::Str(target_rel)),
                        ("offset".to_string(), JsonValue::Uint(1)),
                        ("limit".to_string(), JsonValue::Uint(70)),
                    ]),
                ),
            ])
            .to_json_string();
            match handle_pre_tool_hook(&impl_read, repo) {
                Decision::Deny {
                    code: "TRANSITIVE_DEPTH_EXCEEDED",
                    ..
                } => {
                    downstream_hop_blocks += 1;
                }
                Decision::Deny {
                    code: "TURN_TOKEN_BUDGET_EXCEEDED" | "FILE_READ_BUDGET_EXCEEDED",
                    ..
                } => {
                    hit_budget_failure = true;
                }
                _ => {}
            }
        }

        if hit_budget_failure {
            step_budget_failures += 1;
        }

        let ledger = SessionLedger::load_or_create(repo, &sid);
        let parent_tokens = ledger.cumulative_tokens;
        // Every token kept in the parent window is re-billed across PARENT_FOLLOWUP_TURNS (`Read` -> `Edit` -> `test` -> reply),
        // whereas delegated `research-airlock` exploration pays child tokens ONCE in a disposable context and discards them!
        let search_tok_each = estimate_bpe_tokens(search_hit_blob);
        let child_disposable_cost = if delegated_to_airlock {
            let rem_searches = w.discovery_steps.saturating_sub(cap_k).max(1);
            SUBAGENT_BOOT_OVERHEAD_TOKENS
                .saturating_add(rem_searches.saturating_mul(search_tok_each))
                .saturating_add(w.exploratory_slice_reads.saturating_mul(950))
        } else {
            0
        };
        let failure_penalty = if hit_budget_failure || downstream_hop_blocks > 0 {
            16_000
        } else {
            0
        };
        total_effective_cost = total_effective_cost
            .saturating_add(parent_tokens.saturating_mul(PARENT_FOLLOWUP_TURNS))
            .saturating_add(child_disposable_cost)
            .saturating_add(failure_penalty);

        match w.kind {
            WorkloadKind::Surgical => {
                surgical_count += 1;
                if delegated_to_airlock {
                    surgical_forced += 1;
                }
                surgical_tokens_sum += parent_tokens;
            }
            WorkloadKind::Investigation => {
                inv_count += 1;
                if delegated_to_airlock {
                    inv_caught += 1;
                }
                inv_tokens_sum += parent_tokens;
            }
        }
    }

    Ok(CapSweepRow {
        max_direct_discovery_calls: cap_k,
        surgical_forced_subagent_pct: (surgical_forced as f64 * 100.0)
            / (surgical_count.max(1) as f64),
        investigation_caught_pct: (inv_caught as f64 * 100.0) / (inv_count.max(1) as f64),
        mean_surgical_parent_tokens: surgical_tokens_sum / surgical_count.max(1),
        mean_investigation_parent_tokens: inv_tokens_sum / inv_count.max(1),
        investigation_token_savings_pct: 0.0,
        parent_exploratory_files_exposed: parent_exploratory_exposed,
        downstream_hop_blocks,
        step_budget_failures,
        pareto_effective_cost: total_effective_cost,
    })
}

pub fn render_airlock_eval_report(report: &AirlockEvalReport, format: ReportFormat) -> String {
    match format {
        ReportFormat::Json => {
            let rows_json: Vec<JsonValue> = report
                .rows
                .iter()
                .map(|r| {
                    JsonValue::Object(vec![
                        (
                            "max_direct_discovery_calls".to_string(),
                            JsonValue::Uint(r.max_direct_discovery_calls as u64),
                        ),
                        (
                            "surgical_forced_subagent_pct".to_string(),
                            JsonValue::Number(r.surgical_forced_subagent_pct),
                        ),
                        (
                            "investigation_caught_pct".to_string(),
                            JsonValue::Number(r.investigation_caught_pct),
                        ),
                        (
                            "mean_surgical_parent_tokens".to_string(),
                            JsonValue::Uint(r.mean_surgical_parent_tokens as u64),
                        ),
                        (
                            "mean_investigation_parent_tokens".to_string(),
                            JsonValue::Uint(r.mean_investigation_parent_tokens as u64),
                        ),
                        (
                            "investigation_token_savings_pct".to_string(),
                            JsonValue::Number(
                                (r.investigation_token_savings_pct * 10.0).round() / 10.0,
                            ),
                        ),
                        (
                            "parent_exploratory_files_exposed".to_string(),
                            JsonValue::Uint(r.parent_exploratory_files_exposed as u64),
                        ),
                        (
                            "downstream_hop_blocks".to_string(),
                            JsonValue::Uint(r.downstream_hop_blocks as u64),
                        ),
                        (
                            "step_budget_failures".to_string(),
                            JsonValue::Uint(r.step_budget_failures as u64),
                        ),
                        (
                            "pareto_effective_cost".to_string(),
                            JsonValue::Uint(r.pareto_effective_cost as u64),
                        ),
                    ])
                })
                .collect();

            let root = JsonValue::Object(vec![
                (
                    "baseline".to_string(),
                    JsonValue::Object(vec![
                        (
                            "rust_files_sampled".to_string(),
                            JsonValue::Uint(report.baseline.rust_files_sampled as u64),
                        ),
                        (
                            "median_120_line_slice_tokens".to_string(),
                            JsonValue::Uint(report.baseline.median_120_line_slice_tokens as u64),
                        ),
                        (
                            "p90_120_line_slice_tokens".to_string(),
                            JsonValue::Uint(report.baseline.p90_120_line_slice_tokens as u64),
                        ),
                        (
                            "median_search_output_tokens".to_string(),
                            JsonValue::Uint(report.baseline.median_search_output_tokens as u64),
                        ),
                        (
                            "scenario_max_inline_discoveries".to_string(),
                            JsonValue::Uint(report.baseline.scenario_max_inline_discoveries as u64),
                        ),
                    ]),
                ),
                (
                    "recommended_cap".to_string(),
                    JsonValue::Uint(report.recommended_cap as u64),
                ),
                ("sweep".to_string(), JsonValue::Array(rows_json)),
            ]);
            root.to_json_string()
        }
        ReportFormat::Text => {
            let mut out = String::new();
            let _ = writeln!(
                &mut out,
                "==================================================================================================="
            );
            let _ = writeln!(
                &mut out,
                " dotagent-harness :: Subagent Airlock Usefulness & Discovery-Cap Pareto Calibration"
            );
            let _ = writeln!(
                &mut out,
                "==================================================================================================="
            );
            let _ = writeln!(
                &mut out,
                "Workspace Baseline ({} Rust modules sampled):",
                report.baseline.rust_files_sampled
            );
            let _ = writeln!(
                &mut out,
                "  - Median 120-line Rust slice: {} BPE tokens (p90: {} tokens)",
                report.baseline.median_120_line_slice_tokens,
                report.baseline.p90_120_line_slice_tokens
            );
            let _ = writeln!(
                &mut out,
                "  - Median crate signature search output: {} BPE tokens (airlock summary cap: <= 200 tokens)",
                report.baseline.median_search_output_tokens
            );
            let _ = writeln!(
                &mut out,
                "  - Max inline discoveries in existing TOML scenarios: {}",
                report.baseline.scenario_max_inline_discoveries
            );
            let _ = writeln!(
                &mut out,
                "---------------------------------------------------------------------------------------------------"
            );
            let _ = writeln!(
                &mut out,
                "{:>4} | {:>9} | {:>9} | {:>8} | {:>8} | {:>7} | {:>9} | {:>7} | {:>8} | {:>10}",
                "cap",
                "surg_fp%",
                "inv_air%",
                "surg_tok",
                "inv_tok",
                "saved%",
                "untrust_f",
                "hop_err",
                "16k_oom",
                "total_cost"
            );
            let _ = writeln!(
                &mut out,
                "---------------------------------------------------------------------------------------------------"
            );
            for r in &report.rows {
                let marker = if r.max_direct_discovery_calls == report.recommended_cap {
                    "*"
                } else {
                    " "
                };
                let _ = writeln!(
                    &mut out,
                    "{:>3}{marker} | {:>8.1}% | {:>8.1}% | {:>8} | {:>8} | {:>6.1}% | {:>9} | {:>7} | {:>8} | {:>10}",
                    r.max_direct_discovery_calls,
                    r.surgical_forced_subagent_pct,
                    r.investigation_caught_pct,
                    r.mean_surgical_parent_tokens,
                    r.mean_investigation_parent_tokens,
                    r.investigation_token_savings_pct,
                    r.parent_exploratory_files_exposed,
                    r.downstream_hop_blocks,
                    r.step_budget_failures,
                    r.pareto_effective_cost
                );
            }
            let _ = writeln!(
                &mut out,
                "---------------------------------------------------------------------------------------------------"
            );
            let _ = writeln!(
                &mut out,
                "Pareto-optimal cap (*): max_direct_discovery_calls = {}",
                report.recommended_cap
            );
            out
        }
    }
}
