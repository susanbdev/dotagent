#![forbid(unsafe_code)]

//! `swarm-tool`: Dedicated deterministic Rust CLI tooling for each of the 6
//! Zero-Trust Swarm v2 roles (`master`, `investigator`, `qa`, `grunt`,
//! `reviewer`, `coroner`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use agent_guard::Decision;
use agent_guard::breadcrumbs::{
    ExclusiveFileLockGuard, append_breadcrumb_for_path, compute_arbitrary_hmac_hex,
    flush_records_idempotent, load_or_init_vault_hmac_key, recover_spool_frames, sha256_digest,
    spool_file_path, swarm_state_dir, trail_path_for_rel_path, verify_arbitrary_hmac_hex,
    verify_breadcrumbs_file, verify_event_mac_for_repo,
};
use agent_guard::cmd_policy::evaluate_shell_command;
use agent_guard::json::JsonValue;
use agent_guard::path_policy::{PathAccess, validate_path};
use agent_guard::qa_suspects::{
    compute_task_coverage_targets, load_locked_plan, parse_and_validate_dag_json,
    parse_attribution_toml, plan_lock_state_path, save_locked_plan, triangulate_faults,
    verify_attribution_against_plan,
};
use agent_guard::resolve_repo_root;
use agent_guard::role_sandbox::{
    check_role_shell_read_scope, check_role_shell_write_scope, clear_active_session_slot,
    close_open_session, evaluate_reviewer_verdict, list_session_capabilities,
    load_active_session_slot, load_open_session_capabilities, load_session_capability,
    lookup_pinned_package_doc, mint_session_capability, parse_and_validate_worker_packet,
    path_matches_any_scope, scout_repo_signatures,
};
use agent_guard::swarm_contracts::{
    EventOp, ReviewVerdictOutcome, SessionCapability, SuspectVerdict, SwarmRole, WorkerPacket,
    hex_decode_32,
};
use agent_guard::work_ledger::{
    classify_session_smells, compute_scoped_tree_oid, load_work_ledger_entries,
    record_test_checkpoint, submit_work_ledger_entry,
};

const INTERNAL_SBX_TOKEN_ENV: &str = "AGENT_GUARD_INTERNAL_SBX_TOKEN";
const INTERNAL_SBX_TOKEN_VAL: &str = "swarm-checkpoint-green-v1";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let repo_root = resolve_repo_root(&cwd);

    let Some(role_ns) = args.first().map(String::as_str) else {
        print_usage();
        return ExitCode::SUCCESS;
    };
    let rest = &args[1..];

    match role_ns {
        "--probe-landlock-child" => return agent_guard::exec_sandbox::run_probe_landlock_child(),
        "--internal-exec-sandbox" => {
            if std::env::var(INTERNAL_SBX_TOKEN_ENV).ok().as_deref() != Some(INTERNAL_SBX_TOKEN_VAL)
            {
                eprintln!(
                    "[SWARM-TOOL HARD DENY :: SELF_TAMPERING_BLOCKED] `--internal-exec-sandbox` is reserved for `swarm-tool grunt checkpoint-green` and cannot be invoked directly."
                );
                return ExitCode::from(2);
            }
            return agent_guard::exec_sandbox::run_exec_sandbox_cli(rest, &cwd);
        }
        "--version" | "-V" | "version" => {
            println!("swarm-tool {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        "master" | "investigator" | "qa" | "grunt" | "reviewer" | "coroner"
            if rest
                .first()
                .is_some_and(|s| matches!(s.as_str(), "--help" | "-h" | "help")) =>
        {
            print_role_usage(role_ns);
            return ExitCode::SUCCESS;
        }
        _ => {}
    }

    let result = match role_ns {
        "master" => enforce_ambient_role_namespace(&repo_root, SwarmRole::Master, role_ns, rest)
            .and_then(|()| run_master(&repo_root, &cwd, rest)),
        "investigator" => {
            enforce_ambient_role_namespace(&repo_root, SwarmRole::Investigator, role_ns, rest)
                .and_then(|()| run_investigator(&repo_root, rest))
        }
        "qa" => enforce_ambient_role_namespace(&repo_root, SwarmRole::QaEngineer, role_ns, rest)
            .and_then(|()| run_qa(&repo_root, &cwd, rest)),
        "grunt" => enforce_ambient_role_namespace(&repo_root, SwarmRole::Grunt, role_ns, rest)
            .and_then(|()| run_grunt(&repo_root, &cwd, rest)),
        "reviewer" => enforce_ambient_role_namespace(
            &repo_root,
            SwarmRole::AdversarialReviewer,
            role_ns,
            rest,
        )
        .and_then(|()| run_reviewer(&repo_root, rest)),
        "coroner" => {
            enforce_ambient_role_namespace(&repo_root, SwarmRole::ForensicCoroner, role_ns, rest)
                .and_then(|()| run_coroner(&repo_root, &cwd, rest))
        }
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        other => Err(format!(
            "UNKNOWN_SUBCOMMAND: unknown role namespace '{other}' (expected master, investigator, qa, grunt, reviewer, or coroner)"
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

fn enforce_ambient_role_namespace(
    repo_root: &Path,
    expected_role: SwarmRole,
    role_ns: &str,
    sub_args: &[String],
) -> Result<(), String> {
    let mut explicit_env_role = None;
    if let Ok(env_role_raw) = std::env::var("AGENT_GUARD_ROLE") {
        let raw = env_role_raw.trim();
        if !raw.is_empty() {
            let env_role = SwarmRole::from_str_id(raw).ok_or_else(|| {
                format!("INVALID_SWARM_ROLE: unrecognized AGENT_GUARD_ROLE='{raw}'")
            })?;
            explicit_env_role = Some(env_role);
            if env_role != expected_role {
                return Err(format!(
                    "ROLE_CAPABILITY_MISMATCH: active AGENT_GUARD_ROLE='{}' cannot invoke 'swarm-tool {role_ns}'",
                    env_role.as_str_id()
                ));
            }
        }
    }

    let mut env_cap: Option<SessionCapability> = None;
    if let Ok(env_sid) = std::env::var("AGENT_GUARD_SESSION_ID") {
        let sid = env_sid.trim();
        if !sid.is_empty() {
            let cap = load_session_capability(repo_root, sid)?;
            if cap.role != expected_role {
                return Err(format!(
                    "ROLE_CAPABILITY_MISMATCH: active session '{}' has role '{}', cannot invoke 'swarm-tool {role_ns}'",
                    cap.session_id,
                    cap.role.as_str_id()
                ));
            }
            env_cap = Some(cap);
        }
    }

    if expected_role == SwarmRole::Master {
        if std::env::var("AGENT_GUARD_WORKER_LOCK").as_deref() == Ok("1") {
            return Err(
                "ROLE_CAPABILITY_MISMATCH: locked worker test subprocess cannot invoke 'swarm-tool master'"
                    .to_string(),
            );
        }
        let master_flag_cap = flag_val(sub_args, "--master-session")
            .map(|sid| load_capability_for_role(repo_root, &sid, SwarmRole::Master, "master"))
            .transpose()?;
        let has_signed_master_cap = env_cap.is_some() || master_flag_cap.is_some();

        if !has_signed_master_cap {
            if std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() == Ok("1") {
                return Err(
                    "ROLE_CAPABILITY_MISMATCH: sandboxed subprocess cannot authenticate to 'swarm-tool master' via bare AGENT_GUARD_ROLE=master; present a signed Master capability"
                        .to_string(),
                );
            }
            if explicit_env_role == Some(SwarmRole::Master) {
                // Verify direct host vault possession first so a Landlocked/Seatbelted worker that stripped
                // `AGENT_GUARD_IN_SANDBOX` via `env -u` fails closed (`EACCES` on `vault/hmac.key`)
                // before touching any session/lock state directory.
                let _ = load_or_init_vault_hmac_key(repo_root).map_err(|_| {
                    "ROLE_CAPABILITY_MISMATCH: sandboxed process lacks vault authority and cannot invoke 'swarm-tool master' without a signed Master capability"
                        .to_string()
                })?;
                if list_session_capabilities(repo_root)?
                    .iter()
                    .any(|c| c.role == SwarmRole::Master)
                {
                    return Err(
                        "ROLE_CAPABILITY_MISMATCH: a signed Master capability is active; 'swarm-tool master' requires --master-session or AGENT_GUARD_SESSION_ID"
                            .to_string(),
                    );
                }
                return Ok(());
            }
            if let Ok(open_sessions) = load_open_session_capabilities(repo_root)
                && let Some(worker_cap) = open_sessions.iter().find(|c| c.role != SwarmRole::Master)
            {
                return Err(format!(
                    "ROLE_CAPABILITY_MISMATCH: active '{}' session '{}' is open; cannot invoke 'swarm-tool master' before session closes",
                    worker_cap.role.as_str_id(),
                    worker_cap.session_id
                ));
            }
            return Err(
                "MISSING_SWARM_CAPABILITY: invoking 'swarm-tool master' requires host vault authority or a minted Master session capability"
                    .to_string(),
            );
        }
        return Ok(());
    }

    // For all 5 non-Master worker namespaces: if another worker session is open with a different role
    // and caller did not present an explicit `--session` or `AGENT_GUARD_SESSION_ID` for `expected_role`,
    // fail closed immediately (`ROLE_CAPABILITY_MISMATCH` or `AMBIGUOUS_CONCURRENT_SWARM_SESSIONS`).
    let _ = resolve_worker_capability(repo_root, sub_args, expected_role, role_ns)?;
    Ok(())
}

fn load_capability_for_role(
    repo_root: &Path,
    session_id: &str,
    expected_role: SwarmRole,
    role_ns: &str,
) -> Result<SessionCapability, String> {
    let cap = load_session_capability(repo_root, session_id)?;
    if cap.role != expected_role {
        return Err(format!(
            "ROLE_CAPABILITY_MISMATCH: session '{}' has role '{}', cannot invoke 'swarm-tool {role_ns}'",
            cap.session_id,
            cap.role.as_str_id()
        ));
    }
    if expected_role != SwarmRole::Master {
        let open_caps = load_open_session_capabilities(repo_root)?;
        if !open_caps.iter().any(|c| c.session_id == cap.session_id) {
            return Err(format!(
                "SESSION_CLOSED_OR_INACTIVE: session '{}' is closed or no longer registered in active_sessions.json",
                cap.session_id
            ));
        }
    }
    Ok(cap)
}

fn resolve_worker_capability(
    repo_root: &Path,
    args: &[String],
    expected_role: SwarmRole,
    role_ns: &str,
) -> Result<SessionCapability, String> {
    let is_coroner_triage =
        expected_role == SwarmRole::ForensicCoroner && args.first().is_some_and(|s| s == "triage");

    let candidate_sid = if is_coroner_triage {
        flag_val(args, "--coroner-session")
            .or_else(|| {
                if flag_val(args, "--target-session").is_some() {
                    flag_val(args, "--session")
                } else {
                    None
                }
            })
            .or_else(|| std::env::var("AGENT_GUARD_SESSION_ID").ok())
            .filter(|s| !s.trim().is_empty())
    } else {
        flag_val(args, "--session")
            .or_else(|| std::env::var("AGENT_GUARD_SESSION_ID").ok())
            .filter(|s| !s.trim().is_empty())
    };

    if let Some(sid) = candidate_sid {
        return load_capability_for_role(repo_root, sid.trim(), expected_role, role_ns);
    }

    match load_active_session_slot(repo_root)? {
        Some(slot_cap) => {
            if slot_cap.role != expected_role {
                return Err(format!(
                    "ROLE_CAPABILITY_MISMATCH: active session '{}' has role '{}', cannot invoke 'swarm-tool {role_ns}'",
                    slot_cap.session_id,
                    slot_cap.role.as_str_id()
                ));
            }
            Ok(slot_cap)
        }
        None => Err(format!(
            "MISSING_SWARM_CAPABILITY: 'swarm-tool {role_ns}' requires a minted '{}' session capability (--session <sid>, AGENT_GUARD_SESSION_ID, or open session slot)",
            expected_role.as_str_id()
        )),
    }
}

fn verify_worker_packet_provenance(repo_root: &Path, pkt: &WorkerPacket) -> Result<(), String> {
    let (session_id, task_id, allowed_roles): (&str, &str, &[SwarmRole]) = match pkt {
        WorkerPacket::ObservedFact {
            session_id,
            task_id,
            ..
        } => (
            session_id.as_str(),
            task_id.as_str(),
            &[SwarmRole::Investigator, SwarmRole::ForensicCoroner],
        ),
        WorkerPacket::WorkerHypothesis {
            session_id,
            task_id,
            ..
        } => (
            session_id.as_str(),
            task_id.as_str(),
            &[
                SwarmRole::Grunt,
                SwarmRole::QaEngineer,
                SwarmRole::Investigator,
            ],
        ),
        WorkerPacket::PlanAmendmentProposal {
            session_id,
            task_id,
            ..
        } => (
            session_id.as_str(),
            task_id.as_str(),
            &[
                SwarmRole::Investigator,
                SwarmRole::QaEngineer,
                SwarmRole::Grunt,
                SwarmRole::AdversarialReviewer,
                SwarmRole::ForensicCoroner,
            ],
        ),
    };

    let cap = load_session_capability(repo_root, session_id)
        .map_err(|e| format!("UNAUTHENTICATED_WORKER_PACKET: {e}"))?;
    if cap.task_id != task_id {
        return Err(format!(
            "PACKET_TASK_MISMATCH: packet claims task '{task_id}', but minted session '{}' is bound to task '{}'",
            cap.session_id, cap.task_id
        ));
    }
    if !allowed_roles.contains(&cap.role) {
        return Err(format!(
            "PACKET_ROLE_MISMATCH: session '{}' has role '{}', which is not authorized to emit this packet variant",
            cap.session_id,
            cap.role.as_str_id()
        ));
    }
    Ok(())
}

fn run_master(repo_root: &Path, cwd: &Path, args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("--help");
    match sub {
        "lock-plan" => {
            if std::env::var("AGENT_GUARD_IN_SANDBOX").is_ok_and(|v| v == "1")
                || std::env::var("AGENT_GUARD_WORKER_LOCK").is_ok_and(|v| v == "1")
            {
                return Err(
                    "PLAN_LOCK_DENIED_IN_SANDBOX: `swarm-tool master lock-plan` must be executed on the host outside `exec-sandbox`."
                        .to_string(),
                );
            }
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
            if allow_amend
                && (!std::io::IsTerminal::is_terminal(&std::io::stdin())
                    || !std::io::IsTerminal::is_terminal(&std::io::stdout()))
            {
                return Err(
                    "PLAN_AMEND_REQUIRES_HUMAN_TTY: `lock-plan --amend --human-approved` requires an interactive human terminal (stdin/stdout TTY) so AI agents cannot self-approve plan amendments."
                        .to_string(),
                );
            }
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
            verify_worker_packet_provenance(repo_root, &pkt)?;
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
        "close-session" => {
            let target_sid = flag_val(args, "--session").or_else(|| {
                args.get(1)
                    .filter(|s| !s.starts_with('-'))
                    .cloned()
            });
            match target_sid {
                Some(sid) => close_open_session(repo_root, Some(&sid))?,
                None => clear_active_session_slot(repo_root)?,
            }
            let out = JsonValue::Object(vec![(
                "status".to_string(),
                JsonValue::Str("ACTIVE_SESSION_CLOSED".to_string()),
            )]);
            println!("{}", out.to_json_string());
            Ok(())
        }
        "status" => {
            let lock_file = plan_lock_state_path(repo_root)?;
            let plan_summary = if lock_file.exists()
                && fs::metadata(&lock_file).is_ok_and(|m| m.len() > 0)
            {
                let p = load_locked_plan(repo_root)?;
                JsonValue::Object(vec![
                    ("plan_id".to_string(), JsonValue::Str(p.plan_id)),
                    ("plan_sha256".to_string(), JsonValue::Str(p.plan_sha256)),
                    ("tasks".to_string(), JsonValue::Number(p.tasks.len() as f64)),
                ])
            } else {
                JsonValue::Null
            };
            let open_caps = load_open_session_capabilities(repo_root)?;
            let active_slot = if open_caps.len() == 1 {
                JsonValue::Str(open_caps[0].session_id.clone())
            } else {
                JsonValue::Null
            };
            let open_ids: Vec<JsonValue> = open_caps
                .into_iter()
                .map(|c| JsonValue::Str(c.session_id))
                .collect();
            let sessions = list_session_capabilities(repo_root)?;
            let ledger = load_work_ledger_entries(repo_root)?;
            let out = JsonValue::Object(vec![
                ("locked_plan".to_string(), plan_summary),
                ("active_session_slot".to_string(), active_slot),
                ("open_sessions".to_string(), JsonValue::Array(open_ids)),
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
            "usage: swarm-tool master <lock-plan|mint-session|close-session|ingest-packet|status> ..."
                .to_string(),
        ),
    }
}

fn run_investigator(repo_root: &Path, args: &[String]) -> Result<(), String> {
    let cap = resolve_worker_capability(repo_root, args, SwarmRole::Investigator, "investigator")?;
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
            let task_id = flag_val(args, "--task").unwrap_or_else(|| cap.task_id.clone());
            if task_id != cap.task_id {
                return Err(format!(
                    "ROLE_CAPABILITY_MISMATCH: session '{}' is bound to task '{}', not '{task_id}'",
                    cap.session_id, cap.task_id
                ));
            }
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
                ("session_id".to_string(), JsonValue::Str(cap.session_id)),
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
    let _cap = resolve_worker_capability(repo_root, args, SwarmRole::QaEngineer, "qa")?;
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

fn validate_grunt_test_runner_command(
    cmd_tokens: &[String],
    assigned_tests: &[String],
) -> Result<(), String> {
    let Some(first) = cmd_tokens.first() else {
        return Err("missing test command after `--`".to_string());
    };
    if first.contains('/') || first.contains('\\') {
        return Err(format!(
            "INVALID_TEST_RUNNER_COMMAND: path-qualified binary '{}' is forbidden in `checkpoint-green`; invoke bare canonical test runner (`cargo`, `pytest`, `python3`, `npm`, `go`)",
            first
        ));
    }
    let base = first.as_str();
    let rest = &cmd_tokens[1..];

    for tok in rest {
        let lower = tok.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "--no-run"
                | "--collect-only"
                | "--co"
                | "--setup-only"
                | "--list"
                | "--version"
                | "-v"
                | "--help"
                | "-h"
                | "--fixtures"
        ) && !(tok == "-v"
            && matches!(
                base,
                "pytest" | "py.test" | "python" | "python3" | "uv" | "go"
            ))
        {
            return Err(format!(
                "INVALID_TEST_RUNNER_COMMAND: non-executing flag '{tok}' is forbidden in `checkpoint-green`"
            ));
        }
        if tok == "-V" || lower.starts_with("--no-run=") {
            return Err(format!(
                "INVALID_TEST_RUNNER_COMMAND: non-executing flag '{tok}' is forbidden in `checkpoint-green`"
            ));
        }
        if matches!(
            lower.as_str(),
            "--skip" | "-skip" | "--exclude" | "--exclude-regex" | "--ignore"
        ) || lower.starts_with("--skip=")
            || lower.starts_with("-skip=")
            || lower.starts_with("--exclude=")
            || lower.starts_with("--exclude-regex=")
            || lower.starts_with("--ignore=")
            || (base == "ctest" && tok == "-E")
        {
            return Err(format!(
                "INVALID_TEST_RUNNER_COMMAND: test-exclusion flag '{tok}' is forbidden in `checkpoint-green`"
            ));
        }
    }

    let mut narrowed_filters: Vec<String> = Vec::new();
    let is_valid_runner = match base {
        "cargo" => {
            let mut idx = 0usize;
            while idx < rest.len() && rest[idx].starts_with('+') {
                idx += 1;
            }
            match rest.get(idx).map(String::as_str) {
                Some("test") => {
                    collect_cargo_test_filters(&rest[idx + 1..], &mut narrowed_filters);
                    true
                }
                Some("nextest") if rest.get(idx + 1).map(String::as_str) == Some("run") => {
                    collect_cargo_test_filters(&rest[idx + 2..], &mut narrowed_filters);
                    true
                }
                _ => false,
            }
        }
        "pytest" | "py.test" => {
            collect_pytest_filters_checked(rest, &mut narrowed_filters)?;
            true
        }
        "ctest" => {
            collect_ctest_filters(rest, &mut narrowed_filters);
            true
        }
        "python" | "python3" => {
            if rest.len() >= 2 && rest[0] == "-m" {
                match rest[1].as_str() {
                    "pytest" => {
                        collect_pytest_filters_checked(&rest[2..], &mut narrowed_filters)?;
                        true
                    }
                    "unittest" => {
                        collect_unittest_filters(&rest[2..], &mut narrowed_filters);
                        true
                    }
                    _ => false,
                }
            } else {
                false
            }
        }
        "uv" => {
            if rest.len() >= 2 && rest[0] == "run" && rest[1] == "pytest" {
                collect_pytest_filters_checked(&rest[2..], &mut narrowed_filters)?;
                true
            } else {
                false
            }
        }
        "npm" | "pnpm" | "yarn" | "bun" => match rest.first().map(String::as_str) {
            Some("test" | "vitest" | "jest") => {
                collect_js_test_filters(&rest[1..], &mut narrowed_filters);
                true
            }
            Some("run")
                if rest
                    .get(1)
                    .is_some_and(|s| s == "test" || s.starts_with("test:")) =>
            {
                collect_js_test_filters(&rest[2..], &mut narrowed_filters);
                true
            }
            _ => false,
        },
        "go" if rest.first().is_some_and(|s| s == "test") => {
            collect_go_test_filters(&rest[1..], &mut narrowed_filters);
            true
        }
        _ => false,
    };

    if !is_valid_runner {
        return Err(format!(
            "INVALID_TEST_RUNNER_COMMAND: `checkpoint-green` requires an authentic test runner (`cargo test`, `pytest`, `python3 -m unittest`, `npm/pnpm/yarn/bun test`, or `go test`); refusing `{}`",
            cmd_tokens.join(" ")
        ));
    }

    if !narrowed_filters.is_empty() && !assigned_tests.is_empty() {
        for assigned in assigned_tests {
            let norm_assigned = normalize_test_identifier(assigned);
            if norm_assigned.is_empty() {
                continue;
            }
            let covered = narrowed_filters.iter().any(|flt| {
                let norm_flt = normalize_test_identifier(flt);
                norm_flt == norm_assigned || norm_flt.contains(&norm_assigned)
            });
            if !covered {
                return Err(format!(
                    "ASSIGNED_TESTS_OMITTED: narrowed test command `{}` omits required assigned test '{}' (run the full suite or include all `assigned_tests`)",
                    cmd_tokens.join(" "),
                    assigned
                ));
            }
        }
    }
    Ok(())
}

fn normalize_test_identifier(raw: &str) -> String {
    let trimmed = raw.trim().trim_start_matches("./").trim_end_matches('/');
    let no_prefix = trimmed.strip_prefix("tests/").unwrap_or(trimmed);
    for ext in [".rs", ".py", ".ts", ".tsx", ".js", ".go"] {
        if let Some(stem) = no_prefix.strip_suffix(ext) {
            return stem.to_string();
        }
    }
    no_prefix.to_string()
}

fn collect_cargo_test_filters(args: &[String], out: &mut Vec<String>) {
    let mut i = 0usize;
    let mut after_sep = false;
    while i < args.len() {
        let tok = args[i].as_str();
        if !after_sep && tok == "--" {
            after_sep = true;
            i += 1;
            continue;
        }
        if !after_sep {
            if tok == "--test" {
                if let Some(val) = args.get(i + 1) {
                    out.push(val.clone());
                }
                i += 2;
                continue;
            }
            if matches!(
                tok,
                "-p" | "--package"
                    | "--bin"
                    | "--example"
                    | "--bench"
                    | "--features"
                    | "--manifest-path"
                    | "--target"
                    | "--target-dir"
                    | "--profile"
                    | "-j"
                    | "--jobs"
            ) {
                i += 2;
                continue;
            }
        } else if tok == "--test-threads" {
            i += 2;
            continue;
        }
        if tok.starts_with('-') {
            i += 1;
            continue;
        }
        out.push(tok.to_string());
        i += 1;
    }
}

fn collect_ctest_filters(args: &[String], out: &mut Vec<String>) {
    let mut i = 0usize;
    while i < args.len() {
        let tok = args[i].as_str();
        if matches!(tok, "-R" | "--tests-regex") {
            if let Some(val) = args.get(i + 1) {
                out.push(val.clone());
            }
            i += 2;
            continue;
        }
        if let Some(val) = tok.strip_prefix("--tests-regex=") {
            out.push(val.to_string());
        }
        i += 1;
    }
}

fn collect_go_test_filters(args: &[String], out: &mut Vec<String>) {
    let mut i = 0usize;
    while i < args.len() {
        let tok = args[i].as_str();
        if matches!(tok, "-run" | "--run") {
            if let Some(val) = args.get(i + 1) {
                out.push(val.clone());
            }
            i += 2;
            continue;
        }
        if let Some(val) = tok
            .strip_prefix("-run=")
            .or_else(|| tok.strip_prefix("--run="))
        {
            out.push(val.to_string());
            i += 1;
            continue;
        }
        if matches!(tok, "-count" | "-timeout" | "-parallel" | "-p" | "-tags") {
            i += 2;
            continue;
        }
        if !tok.starts_with('-') && !matches!(tok, "./..." | "." | "./") {
            out.push(tok.to_string());
        }
        i += 1;
    }
}

fn collect_js_test_filters(args: &[String], out: &mut Vec<String>) {
    let mut i = 0usize;
    while i < args.len() {
        let tok = args[i].as_str();
        if tok == "--" {
            i += 1;
            continue;
        }
        if matches!(tok, "-t" | "--testNamePattern" | "--testPathPattern") {
            if let Some(val) = args.get(i + 1) {
                out.push(val.clone());
            }
            i += 2;
            continue;
        }
        if let Some(val) = tok
            .strip_prefix("--testNamePattern=")
            .or_else(|| tok.strip_prefix("--testPathPattern="))
        {
            out.push(val.to_string());
            i += 1;
            continue;
        }
        if !tok.starts_with('-') {
            out.push(tok.to_string());
        }
        i += 1;
    }
}

fn collect_pytest_filters_checked(args: &[String], out: &mut Vec<String>) -> Result<(), String> {
    let mut i = 0usize;
    while i < args.len() {
        let tok = args[i].as_str();
        if tok == "-k"
            && let Some(expr) = args.get(i + 1)
        {
            let norm = format!(" {} ", expr.to_ascii_lowercase());
            if norm.contains(" not ") || expr.trim_start().to_ascii_lowercase().starts_with("not(")
            {
                return Err(format!(
                    "INVALID_TEST_RUNNER_COMMAND: negative pytest `-k '{expr}'` exclusion is forbidden in `checkpoint-green`"
                ));
            }
        }
        i += 1;
    }
    collect_pytest_filters(args, out);
    Ok(())
}

fn collect_pytest_filters(args: &[String], out: &mut Vec<String>) {
    let mut i = 0usize;
    while i < args.len() {
        let tok = args[i].as_str();
        if tok == "-k" || tok == "-m" {
            if let Some(val) = args.get(i + 1) {
                out.push(val.clone());
            }
            i += 2;
            continue;
        }
        if matches!(
            tok,
            "-c" | "-o" | "--rootdir" | "--confcutdir" | "--maxfail"
        ) {
            i += 2;
            continue;
        }
        if tok.starts_with('-') {
            i += 1;
            continue;
        }
        let trimmed = tok.trim_end_matches('/');
        if !matches!(trimmed, "." | "tests") {
            out.push(tok.to_string());
        }
        i += 1;
    }
}

fn collect_unittest_filters(args: &[String], out: &mut Vec<String>) {
    let is_discover = args.first().map(String::as_str) == Some("discover");
    let mut i = if is_discover { 1usize } else { 0usize };
    while i < args.len() {
        let tok = args[i].as_str();
        if tok == "-k" {
            if let Some(val) = args.get(i + 1) {
                out.push(val.clone());
            }
            i += 2;
            continue;
        }
        if matches!(
            tok,
            "-s" | "--start-directory" | "-t" | "--top-level-directory"
        ) {
            i += 2;
            continue;
        }
        if tok == "-p" || tok == "--pattern" {
            if let Some(pat) = args.get(i + 1)
                && pat != "test*.py"
                && pat != "test_*.py"
            {
                out.push(pat.clone());
            }
            i += 2;
            continue;
        }
        if tok.starts_with('-') {
            i += 1;
            continue;
        }
        if !is_discover {
            out.push(tok.to_string());
        }
        i += 1;
    }
}

fn format_role_denial(dec: Decision) -> String {
    match dec {
        Decision::Deny { code, reason, .. } => format!("{code}: {reason}"),
        Decision::Allow { .. } => "denied".to_string(),
    }
}

fn resolve_sibling_agent_guard_bin() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        let mut sib = exe;
        sib.set_file_name("agent-guard");
        if sib.is_file() {
            return Some(sib);
        }
    }
    None
}

fn run_grunt(repo_root: &Path, cwd: &Path, args: &[String]) -> Result<(), String> {
    let cap = resolve_worker_capability(repo_root, args, SwarmRole::Grunt, "grunt")?;
    let sid = cap.session_id.clone();
    let sub = args.first().map(String::as_str).unwrap_or("--help");

    match sub {
        "context" => {
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
            let sep_idx = args
                .iter()
                .position(|a| a == "--")
                .ok_or_else(|| "usage: swarm-tool grunt checkpoint-green --session <sid> -- <test_cmd...>".to_string())?;
            let cmd_tokens = &args[sep_idx + 1..];
            validate_grunt_test_runner_command(cmd_tokens, &cap.assigned_tests)?;
            let joined_cmd = cmd_tokens
                .iter()
                .map(|t| quote_token_for_shell_ast(t))
                .collect::<Vec<_>>()
                .join(" ");
            let plan = evaluate_shell_command(&joined_cmd, repo_root, cwd, false)
                .map_err(|cv| format!("{}: {}", cv.code, cv.detail))?;
            let write_rels: Vec<String> = plan.write_files.iter().map(|(r, _)| r.clone()).collect();
            check_role_shell_write_scope(SwarmRole::Grunt, Some(&cap), &write_rels, repo_root)
                .map_err(format_role_denial)?;
            let read_rels: Vec<String> =
                plan.read_files.iter().map(|(r, _, _)| r.clone()).collect();
            check_role_shell_read_scope(SwarmRole::Grunt, Some(&cap), &read_rels, repo_root)
                .map_err(format_role_denial)?;

            // Execute the untrusted test runner strictly inside `exec-sandbox --deny-net`
            // (using sibling `agent-guard` or self `--internal-exec-sandbox` — NEVER unsandboxed!)
            // so `cargo test`/`pytest`/`unittest` has zero kernel access to `vault/hmac.key`,
            // `ipc/coord.sock`, `sessions/`, `spools/`, `ledger/`, or outbound TCP sockets.
            let (sandbox_bin, sandbox_subcmd) = if let Some(ag_bin) = resolve_sibling_agent_guard_bin() {
                (ag_bin, "exec-sandbox")
            } else {
                let self_exe = std::env::current_exe().map_err(|e| {
                    format!(
                        "SANDBOX_BINARY_UNAVAILABLE: refusing to execute untrusted test command outside OS sandbox ({e})"
                    )
                })?;
                (self_exe, "--internal-exec-sandbox")
            };

            let mut sbx_cmd = Command::new(sandbox_bin);
            sbx_cmd
                .arg(sandbox_subcmd)
                .arg("--deny-net")
                .arg("--cwd")
                .arg(repo_root)
                .arg("--")
                .args(cmd_tokens)
                .current_dir(repo_root)
                .env_remove("AGENT_GUARD_ROLE")
                .env_remove("AGENT_GUARD_SESSION_ID")
                .env_remove("AGENT_GUARD_COORDINATOR_SOCK")
                .env("AGENT_GUARD_WORKER_LOCK", "1")
                .env("PYTHONDONTWRITEBYTECODE", "1");
            if sandbox_subcmd == "--internal-exec-sandbox" {
                sbx_cmd.env(INTERNAL_SBX_TOKEN_ENV, INTERNAL_SBX_TOKEN_VAL);
            }
            let status = sbx_cmd.status().map_err(|e| {
                format!(
                    "SANDBOX_BINARY_UNAVAILABLE: failed spawning sandboxed test command '{}': {e}",
                    cmd_tokens[0]
                )
            })?;

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
            let what = flag_val(args, "--what")
                .ok_or_else(|| "missing --what \"<2 ASCII sentences>\"".to_string())?;
            let why = flag_val(args, "--why")
                .ok_or_else(|| "missing --why \"<2 ASCII sentences>\"".to_string())?;
            let entry = submit_work_ledger_entry(repo_root, &sid, &what, &why)?;
            println!("{}", entry.to_json_value().to_json_string());
            Ok(())
        }
        "report-blocker" => {
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

const REVIEW_STATE_HMAC_DOMAIN: &[u8] = b"DOTAGENT_SWARM_V2_REVIEW_STATE_V1";

fn encode_review_state_mac_payload(
    plan_sha256: &str,
    task_id: &str,
    last_round: u8,
    min_next_attempt: u32,
    finalized: bool,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    let push_str = |out: &mut Vec<u8>, s: &str| {
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(s.as_bytes());
    };
    push_str(&mut buf, plan_sha256);
    push_str(&mut buf, task_id);
    buf.push(last_round);
    buf.extend_from_slice(&min_next_attempt.to_be_bytes());
    buf.push(u8::from(finalized));
    buf
}

fn review_state_file_path(repo_root: &Path, task_id: &str) -> Result<PathBuf, String> {
    let dir = swarm_state_dir(repo_root)?.join("ledger");
    fs::create_dir_all(&dir)
        .map_err(|e| format!("failed creating review ledger dir '{}': {e}", dir.display()))?;
    let safe_task: String = task_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Ok(dir.join(format!("review_{safe_task}.json")))
}

fn record_and_evaluate_reviewer_verdict(
    repo_root: &Path,
    cap: &SessionCapability,
    task_id: &str,
    round: u8,
    approved: bool,
    attempt: u32,
) -> Result<ReviewVerdictOutcome, String> {
    if cap.task_id != task_id {
        return Err(format!(
            "ROLE_CAPABILITY_MISMATCH: reviewer session '{}' is scoped to task '{}', cannot issue verdict for task '{task_id}'",
            cap.session_id, cap.task_id
        ));
    }
    let plan = load_locked_plan(repo_root)?;
    let task_spec = plan
        .tasks
        .iter()
        .find(|t| t.task_id == task_id)
        .ok_or_else(|| {
            format!("UNKNOWN_TASK_ID: task '{task_id}' does not exist in locked PLAN.lock.json")
        })?;
    let plan_sha_hex = plan.plan_sha256.clone();

    if approved {
        let entries = load_work_ledger_entries(repo_root)?;
        let matching_entry = entries
            .iter()
            .rev()
            .find(|e| e.task_id == task_id && e.attempt == attempt)
            .ok_or_else(|| {
                format!(
                    "MISSING_VERIFIED_WORK_LEDGER: cannot approve task '{task_id}' attempt {attempt} without an HMAC-verified green WORK_LEDGER.jsonl receipt"
                )
            })?;
        let current_oid = compute_scoped_tree_oid(repo_root, &task_spec.allowed_write_paths)?;
        if current_oid != matching_entry.git_tree_oid {
            return Err(format!(
                "STALE_WORK_LEDGER_TREE_OID: workspace tree '{current_oid}' drifted from green WORK_LEDGER.jsonl tree '{}' for task '{task_id}'",
                matching_entry.git_tree_oid
            ));
        }
    }

    let state_path = review_state_file_path(repo_root, task_id)?;
    let _lock = ExclusiveFileLockGuard::acquire(&state_path)?;
    if let Ok(meta) = fs::symlink_metadata(&state_path)
        && meta.file_type().is_symlink()
    {
        return Err(format!(
            "SYMLINK_STATE_FORBIDDEN: review state '{}' cannot be a symlink",
            state_path.display()
        ));
    }

    let (mut last_round, mut min_next_attempt, mut finalized) = (0u8, 1u32, false);
    if state_path.exists() {
        let raw = fs::read_to_string(&state_path).map_err(|e| {
            format!(
                "failed reading review state '{}': {e}",
                state_path.display()
            )
        })?;
        let val = JsonValue::parse(&raw)
            .map_err(|e| format!("CORRUPT_REVIEW_STATE: invalid JSON: {e}"))?;
        let stored_plan = val
            .get("plan_sha256")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "CORRUPT_REVIEW_STATE: missing plan_sha256".to_string())?;
        let stored_task = val
            .get("task_id")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "CORRUPT_REVIEW_STATE: missing task_id".to_string())?;
        let stored_round = val
            .get("last_round")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| "CORRUPT_REVIEW_STATE: missing last_round".to_string())?
            as u8;
        let stored_min_attempt = val
            .get("min_next_attempt")
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| "CORRUPT_REVIEW_STATE: missing min_next_attempt".to_string())?
            as u32;
        let stored_final = val
            .get("finalized")
            .and_then(JsonValue::as_bool)
            .ok_or_else(|| "CORRUPT_REVIEW_STATE: missing finalized".to_string())?;
        let stored_mac = val
            .get("state_mac")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "CORRUPT_REVIEW_STATE: missing state_mac".to_string())?;
        let expected_payload = encode_review_state_mac_payload(
            stored_plan,
            stored_task,
            stored_round,
            stored_min_attempt,
            stored_final,
        );
        verify_arbitrary_hmac_hex(
            repo_root,
            REVIEW_STATE_HMAC_DOMAIN,
            &expected_payload,
            stored_mac,
        )?;
        if stored_task != task_id {
            return Err("CORRUPT_REVIEW_STATE: task_id mismatch in review state".to_string());
        }
        if stored_plan == plan_sha_hex {
            last_round = stored_round;
            min_next_attempt = stored_min_attempt;
            finalized = stored_final;
        }
    }

    if finalized {
        return Err(format!(
            "REVIEW_VERDICT_FINALIZED: review for task '{task_id}' is already finalized at round {last_round}"
        ));
    }
    let expected_round = last_round.saturating_add(1);
    if round != expected_round {
        return Err(format!(
            "REVIEW_ROUND_REPLAY_OR_SKIP: task '{task_id}' is at review round {last_round}; expected --round {expected_round}, got --round {round}"
        ));
    }
    if attempt < min_next_attempt {
        return Err(format!(
            "REVIEW_STALE_ATTEMPT: task '{task_id}' round {round} requires attempt >= {min_next_attempt}, got attempt {attempt}"
        ));
    }

    let outcome = evaluate_reviewer_verdict(task_id, round, approved, attempt)?;
    let (new_min_attempt, new_finalized) = match &outcome {
        ReviewVerdictOutcome::Approved { .. } => (attempt, true),
        ReviewVerdictOutcome::RetryCleanSlate { next_attempt, .. } => (*next_attempt, false),
        ReviewVerdictOutcome::EscalateToMaster { .. } => (attempt, true),
    };
    let mac_payload = encode_review_state_mac_payload(
        &plan_sha_hex,
        task_id,
        round,
        new_min_attempt,
        new_finalized,
    );
    let mac_hex = compute_arbitrary_hmac_hex(repo_root, REVIEW_STATE_HMAC_DOMAIN, &mac_payload)?;
    let state_json = JsonValue::Object(vec![
        ("plan_sha256".to_string(), JsonValue::Str(plan_sha_hex)),
        ("task_id".to_string(), JsonValue::Str(task_id.to_string())),
        (
            "last_round".to_string(),
            JsonValue::Number(f64::from(round)),
        ),
        (
            "min_next_attempt".to_string(),
            JsonValue::Number(f64::from(new_min_attempt)),
        ),
        ("finalized".to_string(), JsonValue::Bool(new_finalized)),
        ("state_mac".to_string(), JsonValue::Str(mac_hex)),
    ])
    .to_json_string();
    fs::write(&state_path, format!("{state_json}\n")).map_err(|e| {
        format!(
            "failed persisting review state '{}': {e}",
            state_path.display()
        )
    })?;
    Ok(outcome)
}

fn run_reviewer(repo_root: &Path, args: &[String]) -> Result<(), String> {
    let cap =
        resolve_worker_capability(repo_root, args, SwarmRole::AdversarialReviewer, "reviewer")?;
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
                .unwrap_or(cap.attempt);
            let notes = flag_val(args, "--notes").unwrap_or_default();
            let outcome = record_and_evaluate_reviewer_verdict(
                repo_root, &cap, &task_id, round, approved, attempt,
            )?;
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
    let _cap = resolve_worker_capability(repo_root, args, SwarmRole::ForensicCoroner, "coroner")?;
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
            let valid_count = report.valid_records.len();
            let mut by_trail: BTreeMap<PathBuf, Vec<_>> = BTreeMap::new();
            for rec in report.valid_records {
                verify_event_mac_for_repo(repo_root, &rec.event, &rec.record_mac)?;
                let trail_path = trail_path_for_rel_path(repo_root, &rec.event.canonical_rel_path)?;
                by_trail.entry(trail_path).or_default().push(rec);
            }
            let mut flushed = 0usize;
            for (trail_path, records) in &by_trail {
                flushed += flush_records_idempotent(trail_path, records)?;
            }
            println!(
                "{}",
                JsonValue::Object(vec![
                    (
                        "status".to_string(),
                        JsonValue::Str("SPOOL_RECOVERED".to_string())
                    ),
                    (
                        "valid_frames".to_string(),
                        JsonValue::Number(valid_count as f64),
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
            let sid = flag_val(args, "--target-session")
                .or_else(|| flag_val(args, "--session"))
                .ok_or_else(|| "missing --target-session <session_id>".to_string())?;
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

fn quote_token_for_shell_ast(tok: &str) -> String {
    if !tok.is_empty()
        && tok.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/' | b':' | b'=' | b'+')
        })
    {
        tok.to_string()
    } else {
        format!("'{}'", tok.replace('\'', "'\\''"))
    }
}

fn print_role_usage(role_ns: &str) {
    match role_ns {
        "master" => println!(
            "swarm-tool master <lock-plan|mint-session|close-session|ingest-packet|status> [options]"
        ),
        "investigator" => {
            println!("swarm-tool investigator <scout|emit-fact> [--session <sid>] [options]")
        }
        "qa" => println!(
            "swarm-tool qa <coverage-targets|verify-attribution|triangulate> [--session <sid>] [options]"
        ),
        "grunt" => println!(
            "swarm-tool grunt <context|record-edit|checkpoint-green|submit-ledger|report-blocker> [--session <sid>] [options]"
        ),
        "reviewer" => {
            println!("swarm-tool reviewer <inspect|lookup-doc|verdict> [--session <sid>] [options]")
        }
        "coroner" => println!(
            "swarm-tool coroner <verify-trail|recover-spool|triage> [--session <sid>] [options]"
        ),
        _ => print_usage(),
    }
}

fn print_usage() {
    println!(
        "swarm-tool -- Role-specific deterministic Rust CLI tooling for dotagent Swarm v2\n\
         \n\
         Usage:\n\
         \x20 swarm-tool master <lock-plan|mint-session|close-session|ingest-packet|status>\n\
         \x20 swarm-tool investigator <scout|emit-fact>\n\
         \x20 swarm-tool qa <coverage-targets|verify-attribution|triangulate>\n\
         \x20 swarm-tool grunt <context|record-edit|checkpoint-green|submit-ledger|report-blocker>\n\
         \x20 swarm-tool coroner <verify-trail|recover-spool|triage>\n\
         \x20 swarm-tool reviewer <inspect|lookup-doc|verdict>"
    );
}
