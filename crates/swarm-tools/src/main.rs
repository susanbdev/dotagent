#![forbid(unsafe_code)]

//! `swarm-tool`: Dedicated deterministic Rust CLI tooling for each of the 6
//! Zero-Trust Swarm v2 roles (`master`, `investigator`, `qa`, `grunt`,
//! `reviewer`, `coroner`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use agent_guard::breadcrumbs::{
    append_breadcrumb_for_path, flush_records_idempotent, recover_spool_frames, sha256_digest,
    spool_file_path, verify_breadcrumbs_file,
};
use agent_guard::cmd_policy::evaluate_shell_command;
use agent_guard::json::JsonValue;
use agent_guard::path_policy::{PathAccess, validate_path};
use agent_guard::qa_suspects::{
    compute_task_coverage_targets, load_locked_plan, parse_and_validate_dag_json,
    parse_attribution_toml, save_locked_plan, triangulate_faults, verify_attribution_against_plan,
};
use agent_guard::resolve_repo_root;
use agent_guard::role_sandbox::{
    evaluate_reviewer_verdict, list_session_capabilities, load_session_capability,
    lookup_pinned_package_doc, mint_session_capability, parse_and_validate_worker_packet,
    path_matches_any_scope, scout_repo_signatures,
};
use agent_guard::swarm_contracts::{
    EventOp, ReviewVerdictOutcome, SuspectVerdict, SwarmRole, WorkerPacket, hex_decode_32,
};
use agent_guard::work_ledger::{
    classify_session_smells, load_work_ledger_entries, record_test_checkpoint,
    submit_work_ledger_entry,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let repo_root = resolve_repo_root(&cwd);

    let Some(role_ns) = args.first().map(String::as_str) else {
        print_usage();
        return ExitCode::SUCCESS;
    };
    let rest = &args[1..];

    let result = match role_ns {
        "master" => run_master(&repo_root, &cwd, rest),
        "investigator" => run_investigator(&repo_root, rest),
        "qa" => run_qa(&repo_root, &cwd, rest),
        "grunt" => run_grunt(&repo_root, &cwd, rest),
        "reviewer" => run_reviewer(&repo_root, rest),
        "coroner" => run_coroner(&repo_root, &cwd, rest),
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        other => Err(format!(
            "unknown role namespace '{other}' (expected master, investigator, qa, grunt, reviewer, or coroner)"
        )),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("[SWARM-TOOL ERROR] {err}");
            ExitCode::from(2)
        }
    }
}

fn run_master(repo_root: &Path, cwd: &Path, args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("--help");
    match sub {
        "lock-plan" => {
            let dag_arg = args.get(1).ok_or_else(|| {
                "usage: swarm-tool master lock-plan <dag.json> [--amend --human-approved]"
                    .to_string()
            })?;
            let valid = validate_path(repo_root, cwd, dag_arg, PathAccess::Read)
                .map_err(|pv| format!("{}: {}", pv.code, pv.detail))?;
            let raw = fs::read_to_string(&valid.canonical_or_norm)
                .map_err(|e| format!("cannot read '{}': {e}", valid.repo_rel))?;
            let plan = parse_and_validate_dag_json(&raw)?;
            let allow_amend =
                args.iter().any(|a| a == "--amend") && args.iter().any(|a| a == "--human-approved");
            let saved_path = save_locked_plan(repo_root, &plan, allow_amend)?;
            let out = JsonValue::Object(vec![
                (
                    "status".to_string(),
                    JsonValue::Str("PLAN_LOCKED".to_string()),
                ),
                ("plan_id".to_string(), JsonValue::Str(plan.plan_id)),
                ("plan_sha256".to_string(), JsonValue::Str(plan.plan_sha256)),
                (
                    "task_count".to_string(),
                    JsonValue::Number(plan.tasks.len() as f64),
                ),
                (
                    "lock_path".to_string(),
                    JsonValue::Str(saved_path.to_string_lossy().into_owned()),
                ),
            ]);
            println!("{}", out.to_json_string());
            Ok(())
        }
        "mint-session" => {
            let role_str = flag_val(args, "--role")
                .ok_or_else(|| "missing --role <master|investigator|qa-engineer|grunt|adversarial-reviewer|forensic-coroner>".to_string())?;
            let role = SwarmRole::from_str_id(&role_str)
                .ok_or_else(|| format!("invalid role '{role_str}'"))?;
            let task_id =
                flag_val(args, "--task").ok_or_else(|| "missing --task <task_id>".to_string())?;
            let attempt = flag_val(args, "--attempt")
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(1);

            let cap = mint_session_capability(repo_root, role, &task_id, attempt)?;
            let out = JsonValue::Object(vec![
                (
                    "status".to_string(),
                    JsonValue::Str("SESSION_MINTED".to_string()),
                ),
                (
                    "session_id".to_string(),
                    JsonValue::Str(cap.session_id.clone()),
                ),
                (
                    "role".to_string(),
                    JsonValue::Str(cap.role.as_str_id().to_string()),
                ),
                (
                    "skill".to_string(),
                    JsonValue::Str(
                        cap.role
                            .skill_dir_name()
                            .unwrap_or("zero-trust-guardrails")
                            .to_string(),
                    ),
                ),
                ("task_id".to_string(), JsonValue::Str(cap.task_id)),
                (
                    "attempt".to_string(),
                    JsonValue::Number(f64::from(cap.attempt)),
                ),
                ("plan_sha256".to_string(), JsonValue::Str(cap.plan_sha256)),
                (
                    "env".to_string(),
                    JsonValue::Object(vec![
                        (
                            "AGENT_GUARD_ROLE".to_string(),
                            JsonValue::Str(cap.role.as_str_id().to_string()),
                        ),
                        (
                            "AGENT_GUARD_SESSION_ID".to_string(),
                            JsonValue::Str(cap.session_id),
                        ),
                    ]),
                ),
            ]);
            println!("{}", out.to_json_string());
            Ok(())
        }
        "ingest-packet" => {
            let arg = args.get(1).ok_or_else(|| {
                "usage: swarm-tool master ingest-packet <json_or_file>".to_string()
            })?;
            let raw = if arg.trim_start().starts_with('{') {
                arg.clone()
            } else {
                let valid = validate_path(repo_root, cwd, arg, PathAccess::Read)
                    .map_err(|pv| format!("{}: {}", pv.code, pv.detail))?;
                fs::read_to_string(&valid.canonical_or_norm)
                    .map_err(|e| format!("cannot read '{}': {e}", valid.repo_rel))?
            };
            let (pkt, trigger) = parse_and_validate_worker_packet(&raw)?;
            let pkt_kind = match pkt {
                WorkerPacket::ObservedFact { .. } => "ObservedFact",
                WorkerPacket::WorkerHypothesis { .. } => "WorkerHypothesis",
                WorkerPacket::PlanAmendmentProposal { .. } => "PlanAmendmentProposal",
            };
            let esc = trigger
                .as_ref()
                .map(|t| JsonValue::Str(t.code().to_string()))
                .unwrap_or(JsonValue::Null);
            let out = JsonValue::Object(vec![
                (
                    "status".to_string(),
                    JsonValue::Str("PACKET_VALIDATED".to_string()),
                ),
                (
                    "packet_type".to_string(),
                    JsonValue::Str(pkt_kind.to_string()),
                ),
                (
                    "requires_human_escalation".to_string(),
                    JsonValue::Bool(trigger.is_some()),
                ),
                ("escalation_code".to_string(), esc),
            ]);
            println!("{}", out.to_json_string());
            Ok(())
        }
        "status" => {
            let plan_summary = match load_locked_plan(repo_root) {
                Ok(p) => JsonValue::Object(vec![
                    ("plan_id".to_string(), JsonValue::Str(p.plan_id)),
                    ("plan_sha256".to_string(), JsonValue::Str(p.plan_sha256)),
                    ("tasks".to_string(), JsonValue::Number(p.tasks.len() as f64)),
                ]),
                Err(_) => JsonValue::Null,
            };
            let sessions = list_session_capabilities(repo_root).unwrap_or_default();
            let ledger = load_work_ledger_entries(repo_root).unwrap_or_default();
            let out = JsonValue::Object(vec![
                ("locked_plan".to_string(), plan_summary),
                (
                    "minted_sessions".to_string(),
                    JsonValue::Number(sessions.len() as f64),
                ),
                (
                    "completed_ledger_receipts".to_string(),
                    JsonValue::Number(ledger.len() as f64),
                ),
            ]);
            println!("{}", out.to_json_string());
            Ok(())
        }
        _ => Err(
            "usage: swarm-tool master <lock-plan|mint-session|ingest-packet|status> ..."
                .to_string(),
        ),
    }
}

fn run_investigator(repo_root: &Path, args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("--help");
    match sub {
        "scout" => {
            let dir = flag_val(args, "--dir").unwrap_or_else(|| ".".to_string());
            let depth = flag_val(args, "--max-depth")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(20);
            let filter = flag_val(args, "--filter");
            let hits = scout_repo_signatures(repo_root, &dir, depth, filter.as_deref())?;
            for h in &hits {
                println!("{h}");
            }
            println!("[scout_hits={}]", hits.len());
            Ok(())
        }
        "emit-fact" => {
            let session_id = flag_val(args, "--session")
                .or_else(|| std::env::var("AGENT_GUARD_SESSION_ID").ok())
                .ok_or_else(|| "missing --session <sid>".to_string())?;
            let task_id =
                flag_val(args, "--task").ok_or_else(|| "missing --task <task_id>".to_string())?;
            let claim = flag_val(args, "--claim")
                .ok_or_else(|| "missing --claim \"<ascii>\"".to_string())?;
            let slices = flag_vals_multi(args, "--slice");
            for sl in &slices {
                let p = sl.split(':').next().unwrap_or(sl.as_str());
                validate_path(repo_root, repo_root, p, PathAccess::Read)
                    .map_err(|pv| format!("invalid evidence slice '{sl}': {}", pv.detail))?;
            }
            let obj = JsonValue::Object(vec![
                (
                    "packet_type".to_string(),
                    JsonValue::Str("ObservedFact".to_string()),
                ),
                ("session_id".to_string(), JsonValue::Str(session_id)),
                ("task_id".to_string(), JsonValue::Str(task_id)),
                ("claim".to_string(), JsonValue::Str(claim)),
                (
                    "evidence_slices".to_string(),
                    JsonValue::Array(slices.into_iter().map(JsonValue::Str).collect()),
                ),
            ]);
            let serialized = obj.to_json_string();
            let _ = parse_and_validate_worker_packet(&serialized)?;
            println!("{serialized}");
            Ok(())
        }
        _ => Err("usage: swarm-tool investigator <scout|emit-fact> ...".to_string()),
    }
}

fn run_qa(repo_root: &Path, cwd: &Path, args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("--help");
    match sub {
        "coverage-targets" => {
            let plan = if let Some(plan_arg) = flag_val(args, "--plan") {
                let valid = validate_path(repo_root, cwd, &plan_arg, PathAccess::Read)
                    .map_err(|pv| format!("{}: {}", pv.code, pv.detail))?;
                let raw =
                    fs::read_to_string(&valid.canonical_or_norm).map_err(|e| e.to_string())?;
                parse_and_validate_dag_json(&raw)?
            } else {
                load_locked_plan(repo_root)?
            };
            let targets = compute_task_coverage_targets(&plan);
            let rows: Vec<JsonValue> = targets
                .into_iter()
                .map(|t| {
                    JsonValue::Object(vec![
                        ("task_id".to_string(), JsonValue::Str(t.task_id)),
                        (
                            "domain_floor_pct".to_string(),
                            JsonValue::Number(f64::from(t.domain_floor_pct)),
                        ),
                        (
                            "downstream_dependents".to_string(),
                            JsonValue::Number(t.downstream_dependents as f64),
                        ),
                        (
                            "required_coverage_pct".to_string(),
                            JsonValue::Number(f64::from(t.required_coverage_pct)),
                        ),
                    ])
                })
                .collect();
            println!("{}", JsonValue::Array(rows).to_json_string());
            Ok(())
        }
        "verify-attribution" => {
            let attr_arg = args
                .get(1)
                .ok_or_else(|| "usage: swarm-tool qa verify-attribution <test_attribution.toml> [--plan <dag.json>]".to_string())?;
            let valid = validate_path(repo_root, cwd, attr_arg, PathAccess::Read)
                .map_err(|pv| format!("{}: {}", pv.code, pv.detail))?;
            let raw = fs::read_to_string(&valid.canonical_or_norm).map_err(|e| e.to_string())?;
            let rules = parse_attribution_toml(&raw)?;
            let plan = if let Some(plan_arg) = flag_val(args, "--plan") {
                let vp = validate_path(repo_root, cwd, &plan_arg, PathAccess::Read)
                    .map_err(|pv| format!("{}: {}", pv.code, pv.detail))?;
                let pr = fs::read_to_string(&vp.canonical_or_norm).map_err(|e| e.to_string())?;
                parse_and_validate_dag_json(&pr)?
            } else {
                load_locked_plan(repo_root)?
            };
            verify_attribution_against_plan(&rules, &plan)?;
            println!(
                "{}",
                JsonValue::Object(vec![
                    (
                        "status".to_string(),
                        JsonValue::Str("ATTRIBUTION_VALID".to_string())
                    ),
                    (
                        "rule_count".to_string(),
                        JsonValue::Number(rules.len() as f64)
                    ),
                ])
                .to_json_string()
            );
            Ok(())
        }
        "triangulate" => {
            let attr_arg = flag_val(args, "--attribution")
                .ok_or_else(|| "missing --attribution <test_attribution.toml>".to_string())?;
            let valid = validate_path(repo_root, cwd, &attr_arg, PathAccess::Read)
                .map_err(|pv| format!("{}: {}", pv.code, pv.detail))?;
            let raw = fs::read_to_string(&valid.canonical_or_norm).map_err(|e| e.to_string())?;
            let rules = parse_attribution_toml(&raw)?;
            let failing = split_csv(&flag_val(args, "--failing").unwrap_or_default());
            let passing = split_csv(&flag_val(args, "--passing").unwrap_or_default());
            let verdict = triangulate_faults(&rules, &failing, &passing);
            let out = match verdict {
                SuspectVerdict::SuspectIsolated {
                    primary_suspect,
                    failing_tests,
                } => JsonValue::Object(vec![
                    (
                        "verdict".to_string(),
                        JsonValue::Str("SuspectIsolated".to_string()),
                    ),
                    (
                        "primary_suspect".to_string(),
                        JsonValue::Str(primary_suspect),
                    ),
                    (
                        "failing_tests".to_string(),
                        JsonValue::Array(failing_tests.into_iter().map(JsonValue::Str).collect()),
                    ),
                ]),
                SuspectVerdict::BlockedByNeighbor {
                    victim,
                    neighbor_suspect,
                    boundary_test,
                } => JsonValue::Object(vec![
                    (
                        "verdict".to_string(),
                        JsonValue::Str("BlockedByNeighbor".to_string()),
                    ),
                    ("victim".to_string(), JsonValue::Str(victim)),
                    (
                        "neighbor_suspect".to_string(),
                        JsonValue::Str(neighbor_suspect),
                    ),
                    ("boundary_test".to_string(), JsonValue::Str(boundary_test)),
                ]),
                SuspectVerdict::SeamOrSpecConflict {
                    task_a,
                    task_b,
                    boundary_test,
                } => JsonValue::Object(vec![
                    (
                        "verdict".to_string(),
                        JsonValue::Str("SeamOrSpecConflict".to_string()),
                    ),
                    ("task_a".to_string(), JsonValue::Str(task_a)),
                    ("task_b".to_string(), JsonValue::Str(task_b)),
                    ("boundary_test".to_string(), JsonValue::Str(boundary_test)),
                ]),
                SuspectVerdict::InconclusiveAskMaster { reason } => JsonValue::Object(vec![
                    (
                        "verdict".to_string(),
                        JsonValue::Str("InconclusiveAskMaster".to_string()),
                    ),
                    ("reason".to_string(), JsonValue::Str(reason)),
                ]),
            };
            println!("{}", out.to_json_string());
            Ok(())
        }
        _ => Err(
            "usage: swarm-tool qa <coverage-targets|verify-attribution|triangulate> ..."
                .to_string(),
        ),
    }
}

fn run_grunt(repo_root: &Path, cwd: &Path, args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("--help");
    let resolve_sid = |args: &[String]| -> Result<String, String> {
        flag_val(args, "--session")
            .or_else(|| std::env::var("AGENT_GUARD_SESSION_ID").ok())
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| "missing --session <sid> or AGENT_GUARD_SESSION_ID".to_string())
    };

    match sub {
        "context" => {
            let sid = resolve_sid(args)?;
            let cap = load_session_capability(repo_root, &sid)?;
            let out = JsonValue::Object(vec![
                ("session_id".to_string(), JsonValue::Str(cap.session_id)),
                ("task_id".to_string(), JsonValue::Str(cap.task_id)),
                ("attempt".to_string(), JsonValue::Number(f64::from(cap.attempt))),
                (
                    "assigned_read_paths".to_string(),
                    JsonValue::Array(
                        cap.assigned_read_paths
                            .into_iter()
                            .map(JsonValue::Str)
                            .collect(),
                    ),
                ),
                (
                    "allowed_write_paths".to_string(),
                    JsonValue::Array(
                        cap.allowed_write_paths
                            .into_iter()
                            .map(JsonValue::Str)
                            .collect(),
                    ),
                ),
                (
                    "assigned_tests".to_string(),
                    JsonValue::Array(cap.assigned_tests.into_iter().map(JsonValue::Str).collect()),
                ),
            ]);
            println!("{}", out.to_json_string());
            Ok(())
        }
        "record-edit" => {
            let sid = resolve_sid(args)?;
            let cap = load_session_capability(repo_root, &sid)?;
            let raw_file = flag_val(args, "--file")
                .ok_or_else(|| "missing --file <rel_path>".to_string())?;
            let valid = validate_path(repo_root, cwd, &raw_file, PathAccess::Write)
                .map_err(|pv| format!("{}: {}", pv.code, pv.detail))?;
            if !path_matches_any_scope(&valid.repo_rel, &cap.allowed_write_paths) {
                return Err(format!(
                    "GRUNT_WRITE_OUT_OF_SCOPE: '{}' is outside allowed_write_paths",
                    valid.repo_rel
                ));
            }
            let bytes = fs::read(&valid.canonical_or_norm)
                .map_err(|e| format!("cannot read edited file '{}': {e}", valid.repo_rel))?;
            let line_range = flag_val(args, "--lines").and_then(|s| {
                let (a, b) = s.split_once('-')?;
                Some((a.parse::<u64>().ok()?, b.parse::<u64>().ok()?))
            });
            let plan_bytes = hex_decode_32(&cap.plan_sha256).unwrap_or([0u8; 32]);
            let signed = append_breadcrumb_for_path(
                repo_root,
                &cap.session_id,
                &cap.task_id,
                plan_bytes,
                EventOp::FileEdit,
                &valid.repo_rel,
                line_range,
                sha256_digest(&bytes),
            )?;
            println!(
                "{}",
                JsonValue::Object(vec![
                    ("status".to_string(), JsonValue::Str("BREADCRUMB_RECORDED".to_string())),
                    ("event_id".to_string(), JsonValue::Str(signed.event_id_hex())),
                    ("seq_no".to_string(), JsonValue::Number(signed.event.seq_no as f64)),
                    ("file".to_string(), JsonValue::Str(valid.repo_rel)),
                ])
                .to_json_string()
            );
            Ok(())
        }
        "checkpoint-green" => {
            let sid = resolve_sid(args)?;
            let sep_idx = args
                .iter()
                .position(|a| a == "--")
                .ok_or_else(|| "usage: swarm-tool grunt checkpoint-green --session <sid> -- <test_cmd...>".to_string())?;
            let cmd_tokens = &args[sep_idx + 1..];
            if cmd_tokens.is_empty() {
                return Err("missing test command after `--`".to_string());
            }
            let joined_cmd = cmd_tokens.join(" ");
            evaluate_shell_command(&joined_cmd, repo_root, cwd, false)
                .map_err(|cv| format!("{}: {}", cv.code, cv.detail))?;

            let status = Command::new(&cmd_tokens[0])
                .args(&cmd_tokens[1..])
                .current_dir(repo_root)
                .status()
                .map_err(|e| format!("failed spawning test command '{}': {e}", cmd_tokens[0]))?;

            let passed = status.success();
            let (_cap, tree_oid) = record_test_checkpoint(repo_root, &sid, passed)?;
            if !passed {
                return Err(format!(
                    "TEST_CHECKPOINT_FAILED: command '{}' exited non-zero",
                    joined_cmd
                ));
            }
            println!(
                "{}",
                JsonValue::Object(vec![
                    ("status".to_string(), JsonValue::Str("CHECKPOINT_GREEN".to_string())),
                    ("session_id".to_string(), JsonValue::Str(sid)),
                    ("green_tree_oid".to_string(), JsonValue::Str(tree_oid)),
                ])
                .to_json_string()
            );
            Ok(())
        }
        "submit-ledger" => {
            let sid = resolve_sid(args)?;
            let what = flag_val(args, "--what")
                .ok_or_else(|| "missing --what \"<2 ASCII sentences>\"".to_string())?;
            let why = flag_val(args, "--why")
                .ok_or_else(|| "missing --why \"<2 ASCII sentences>\"".to_string())?;
            let entry = submit_work_ledger_entry(repo_root, &sid, &what, &why)?;
            println!("{}", entry.to_json_value().to_json_string());
            Ok(())
        }
        "report-blocker" => {
            let sid = resolve_sid(args)?;
            let cap = load_session_capability(repo_root, &sid)?;
            let missing = flag_val(args, "--missing-path").unwrap_or_default();
            let hyp = flag_val(args, "--hypothesis")
                .ok_or_else(|| "missing --hypothesis \"<ascii>\"".to_string())?;
            let pkt = JsonValue::Object(vec![
                (
                    "packet_type".to_string(),
                    JsonValue::Str("WorkerHypothesis".to_string()),
                ),
                ("session_id".to_string(), JsonValue::Str(cap.session_id)),
                ("task_id".to_string(), JsonValue::Str(cap.task_id)),
                ("missing_path".to_string(), JsonValue::Str(missing)),
                ("hypothesis".to_string(), JsonValue::Str(hyp)),
            ])
            .to_json_string();
            let _ = parse_and_validate_worker_packet(&pkt)?;
            println!("{pkt}");
            Ok(())
        }
        _ => Err(
            "usage: swarm-tool grunt <context|record-edit|checkpoint-green|submit-ledger|report-blocker> ...".to_string(),
        ),
    }
}

fn run_reviewer(repo_root: &Path, args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("--help");
    match sub {
        "inspect" => {
            let task_id =
                flag_val(args, "--task").ok_or_else(|| "missing --task <task_id>".to_string())?;
            let entries: Vec<_> = load_work_ledger_entries(repo_root)?
                .into_iter()
                .filter(|e| e.task_id == task_id)
                .map(|e| e.to_json_value())
                .collect();
            let out = JsonValue::Object(vec![
                ("task_id".to_string(), JsonValue::Str(task_id)),
                ("ledger_entries".to_string(), JsonValue::Array(entries)),
            ]);
            println!("{}", out.to_json_string());
            Ok(())
        }
        "lookup-doc" => {
            let eco = flag_val(args, "--ecosystem")
                .ok_or_else(|| "missing --ecosystem <cargo|npm>".to_string())?;
            let pkg = flag_val(args, "--package")
                .ok_or_else(|| "missing --package <name>".to_string())?;
            let ver =
                flag_val(args, "--version").ok_or_else(|| "missing --version <ver>".to_string())?;
            let sym = flag_val(args, "--symbol");
            let msg = lookup_pinned_package_doc(repo_root, &eco, &pkg, &ver, sym.as_deref())?;
            println!(
                "{}",
                JsonValue::Object(vec![
                    (
                        "status".to_string(),
                        JsonValue::Str("PIN_VERIFIED".to_string())
                    ),
                    ("detail".to_string(), JsonValue::Str(msg)),
                ])
                .to_json_string()
            );
            Ok(())
        }
        "verdict" => {
            let task_id =
                flag_val(args, "--task").ok_or_else(|| "missing --task <task_id>".to_string())?;
            let round = flag_val(args, "--round")
                .and_then(|s| s.parse::<u8>().ok())
                .ok_or_else(|| "missing --round <1|2>".to_string())?;
            let decision = flag_val(args, "--decision")
                .ok_or_else(|| "missing --decision <approve|reject>".to_string())?;
            let approved = match decision.as_str() {
                "approve" | "approved" => true,
                "reject" | "rejected" => false,
                other => {
                    return Err(format!(
                        "invalid --decision '{other}' (expected approve or reject)"
                    ));
                }
            };
            let attempt = flag_val(args, "--attempt")
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(1);
            let notes = flag_val(args, "--notes").unwrap_or_default();
            let outcome = evaluate_reviewer_verdict(&task_id, round, approved, attempt)?;
            let out = match outcome {
                ReviewVerdictOutcome::Approved { task_id, round } => JsonValue::Object(vec![
                    (
                        "outcome".to_string(),
                        JsonValue::Str("Approved".to_string()),
                    ),
                    ("task_id".to_string(), JsonValue::Str(task_id)),
                    ("round".to_string(), JsonValue::Number(f64::from(round))),
                    ("notes".to_string(), JsonValue::Str(notes)),
                ]),
                ReviewVerdictOutcome::RetryCleanSlate {
                    task_id,
                    round,
                    next_attempt,
                } => JsonValue::Object(vec![
                    (
                        "outcome".to_string(),
                        JsonValue::Str("RetryCleanSlate".to_string()),
                    ),
                    ("task_id".to_string(), JsonValue::Str(task_id)),
                    ("round".to_string(), JsonValue::Number(f64::from(round))),
                    (
                        "next_attempt".to_string(),
                        JsonValue::Number(f64::from(next_attempt)),
                    ),
                    ("notes".to_string(), JsonValue::Str(notes)),
                ]),
                ReviewVerdictOutcome::EscalateToMaster { trigger } => JsonValue::Object(vec![
                    (
                        "outcome".to_string(),
                        JsonValue::Str("EscalateToMaster".to_string()),
                    ),
                    (
                        "escalation_code".to_string(),
                        JsonValue::Str(trigger.code().to_string()),
                    ),
                    ("notes".to_string(), JsonValue::Str(notes)),
                ]),
            };
            println!("{}", out.to_json_string());
            Ok(())
        }
        _ => Err("usage: swarm-tool reviewer <inspect|lookup-doc|verdict> ...".to_string()),
    }
}

fn run_coroner(repo_root: &Path, cwd: &Path, args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("--help");
    match sub {
        "verify-trail" => {
            let raw_p = args.get(1).ok_or_else(|| {
                "usage: swarm-tool coroner verify-trail <breadcrumbs.jsonl>".to_string()
            })?;
            let valid = validate_path(repo_root, cwd, raw_p, PathAccess::Read)
                .map_err(|pv| format!("{}: {}", pv.code, pv.detail))?;
            let count = verify_breadcrumbs_file(repo_root, &valid.canonical_or_norm)?;
            println!(
                "{}",
                JsonValue::Object(vec![
                    (
                        "status".to_string(),
                        JsonValue::Str("TRAIL_VERIFIED".to_string())
                    ),
                    (
                        "verified_events".to_string(),
                        JsonValue::Number(count as f64)
                    ),
                    ("file".to_string(), JsonValue::Str(valid.repo_rel)),
                ])
                .to_json_string()
            );
            Ok(())
        }
        "recover-spool" => {
            let sid = args.get(1).ok_or_else(|| {
                "usage: swarm-tool coroner recover-spool <session_id>".to_string()
            })?;
            let spool_path = spool_file_path(repo_root, sid)?;
            let report = recover_spool_frames(&spool_path)?;
            let trail_path = repo_root.join(".breadcrumbs.jsonl");
            let flushed = if !report.valid_records.is_empty() {
                flush_records_idempotent(&trail_path, &report.valid_records)?
            } else {
                0
            };
            println!(
                "{}",
                JsonValue::Object(vec![
                    (
                        "status".to_string(),
                        JsonValue::Str("SPOOL_RECOVERED".to_string())
                    ),
                    (
                        "valid_frames".to_string(),
                        JsonValue::Number(report.valid_records.len() as f64),
                    ),
                    (
                        "quarantined_tail_bytes".to_string(),
                        JsonValue::Number(report.quarantined_tail_bytes as f64),
                    ),
                    (
                        "newly_flushed".to_string(),
                        JsonValue::Number(flushed as f64)
                    ),
                ])
                .to_json_string()
            );
            Ok(())
        }
        "triage" => {
            let sid = flag_val(args, "--session")
                .ok_or_else(|| "missing --session <session_id>".to_string())?;
            let cap = load_session_capability(repo_root, &sid)?;
            let smells = classify_session_smells(repo_root, &cap)?;
            let badges: Vec<JsonValue> = smells
                .iter()
                .map(|b| JsonValue::Str(format!("{}:{}", b.bucket.as_str(), b.signal)))
                .collect();
            println!(
                "{}",
                JsonValue::Object(vec![
                    ("session_id".to_string(), JsonValue::Str(cap.session_id)),
                    ("task_id".to_string(), JsonValue::Str(cap.task_id)),
                    (
                        "role".to_string(),
                        JsonValue::Str(cap.role.as_str_id().to_string())
                    ),
                    (
                        "smell_count".to_string(),
                        JsonValue::Number(badges.len() as f64)
                    ),
                    ("smell_badges".to_string(), JsonValue::Array(badges)),
                ])
                .to_json_string()
            );
            Ok(())
        }
        _ => Err("usage: swarm-tool coroner <verify-trail|recover-spool|triage> ...".to_string()),
    }
}

fn flag_val(args: &[String], flag: &str) -> Option<String> {
    for (i, a) in args.iter().enumerate() {
        if a == flag {
            return args.get(i + 1).cloned();
        }
        if let Some(rest) = a.strip_prefix(&format!("{flag}=")) {
            return Some(rest.to_string());
        }
    }
    None
}

fn flag_vals_multi(args: &[String], flag: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if a == flag {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
            }
        } else if let Some(rest) = a.strip_prefix(&format!("{flag}=")) {
            out.push(rest.to_string());
        }
    }
    out
}

fn split_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn print_usage() {
    println!(
        "swarm-tool -- Role-specific deterministic Rust CLI tooling for dotagent Swarm v2\n\
         \n\
         Usage:\n\
         \x20 swarm-tool master <lock-plan|mint-session|ingest-packet|status>\n\
         \x20 swarm-tool investigator <scout|emit-fact>\n\
         \x20 swarm-tool qa <coverage-targets|verify-attribution|triangulate>\n\
         \x20 swarm-tool grunt <context|record-edit|checkpoint-green|submit-ledger|report-blocker>\n\
         \x20 swarm-tool reviewer <inspect|lookup-doc|verdict>\n\
         \x20 swarm-tool coroner <verify-trail|recover-spool|triage>"
    );
}
