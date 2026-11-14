#![forbid(unsafe_code)]

//! Deterministic `0`-LLM 4-bucket smell classifier (`MALICIOUS`, `OFF_TASK`,
//! `CONFUSED`, `RISKY`), `2+2` pure-ASCII sentence `WORK_LEDGER.jsonl` receipt
//! engine, and fail-closed `Grunt` `on-stop` tree-OID verifier (`F18`, `F32`, `F33`).

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::breadcrumbs::{
    append_breadcrumb_for_path, compute_arbitrary_hmac_hex, recover_spool_frames, sha256_digest,
    spool_file_path, swarm_state_dir,
};
use crate::json::JsonValue;
use crate::role_sandbox::{
    load_session_capability, path_matches_any_scope, resolve_active_role, save_session_capability,
};
use crate::swarm_contracts::{
    EventOp, SessionCapability, SmellBadge, SmellBucket, SwarmRole, WorkLedgerEntry, hex_decode_32,
    hex_encode,
};
use crate::unicode_guard::{ScanMode, scan_unicode};

const LEDGER_HMAC_DOMAIN: &[u8] = b"DOTAGENT_SWARM_V2_WORK_LEDGER_V1";

pub fn work_ledger_state_path(repo_root: &Path) -> Result<PathBuf, String> {
    Ok(swarm_state_dir(repo_root)?.join("WORK_LEDGER.jsonl"))
}

/// Computes a deterministic SHA-256 tree OID over all files matching `allowed_write_paths`
/// (replacing coarse filesystem `mtime` checks per `F18` so even sub-millisecond edits
/// after `checkpoint-green` are caught reliably).
pub fn compute_scoped_tree_oid(
    repo_root: &Path,
    scope_patterns: &[String],
) -> Result<String, String> {
    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let mut file_digests: BTreeMap<String, String> = BTreeMap::new();
    collect_scoped_blobs(
        &canon_repo,
        &canon_repo,
        scope_patterns,
        0,
        &mut file_digests,
    );

    let mut buf = Vec::new();
    for (rel, digest) in &file_digests {
        buf.extend_from_slice(&(rel.len() as u32).to_be_bytes());
        buf.extend_from_slice(rel.as_bytes());
        buf.extend_from_slice(digest.as_bytes());
    }
    Ok(hex_encode(&sha256_digest(&buf)))
}

fn collect_scoped_blobs(
    canon_repo: &Path,
    dir: &Path,
    scope_patterns: &[String],
    depth: usize,
    out: &mut BTreeMap<String, String>,
) {
    if depth > 12 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == ".git"
            || name_str == "target"
            || name_str == "node_modules"
            || name_str == ".state"
            || name_str == ".breadcrumbs.jsonl"
        {
            continue;
        }
        let full = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            collect_scoped_blobs(canon_repo, &full, scope_patterns, depth + 1, out);
        } else if ft.is_file() {
            let rel = full
                .strip_prefix(canon_repo)
                .unwrap_or(&full)
                .to_string_lossy()
                .replace('\\', "/");
            if scope_patterns.is_empty() || path_matches_any_scope(&rel, scope_patterns) {
                if let Ok(bytes) = fs::read(&full) {
                    out.insert(rel, hex_encode(&sha256_digest(&bytes)));
                }
            }
        }
    }
}

/// Records the result of `swarm-tool grunt checkpoint-green` into the session capability
/// and breadcrumb flight recorder.
pub fn record_test_checkpoint(
    repo_root: &Path,
    session_id: &str,
    passed: bool,
) -> Result<(SessionCapability, String), String> {
    let mut cap = load_session_capability(repo_root, session_id)?;
    let tree_oid = compute_scoped_tree_oid(repo_root, &cap.allowed_write_paths)?;
    let tree_bytes = hex_decode_32(&tree_oid).unwrap_or([0u8; 32]);
    let plan_bytes = hex_decode_32(&cap.plan_sha256).unwrap_or([0u8; 32]);

    if passed {
        cap.last_green_tree_oid = Some(tree_oid.clone());
        cap.consecutive_test_failures = 0;
        save_session_capability(repo_root, &cap)?;
        let _ = append_breadcrumb_for_path(
            repo_root,
            session_id,
            &cap.task_id,
            plan_bytes,
            EventOp::TestGreen,
            "WORK_LEDGER.jsonl",
            None,
            tree_bytes,
        );
    } else {
        cap.consecutive_test_failures = cap.consecutive_test_failures.saturating_add(1);
        save_session_capability(repo_root, &cap)?;
        let _ = append_breadcrumb_for_path(
            repo_root,
            session_id,
            &cap.task_id,
            plan_bytes,
            EventOp::TestFail,
            "WORK_LEDGER.jsonl",
            None,
            tree_bytes,
        );
    }

    Ok((cap, tree_oid))
}

/// Enforces strict pure 7-bit ASCII and exact `2` sentences for `what_changed` +
/// exact `2` sentences for `why_changed`.
pub fn validate_two_plus_two_sentences(
    what_changed: &str,
    why_changed: &str,
) -> Result<(), String> {
    for (field, text) in [("what_changed", what_changed), ("why_changed", why_changed)] {
        let uni = scan_unicode(text, ScanMode::UntrustedContent);
        if let Some(first) = uni.first() {
            return Err(format!(
                "{field} failed 7-bit ASCII/Unicode check: {}",
                first.detail
            ));
        }
        if text.bytes().any(|b| !(0x20..=0x7E).contains(&b)) {
            return Err(format!(
                "{field} must be single-line printable 7-bit ASCII (0x20..=0x7E)"
            ));
        }
        let n = count_terminal_sentences(text);
        if n != 2 {
            return Err(format!(
                "LEDGER_SENTENCE_COUNT_INVALID: {field} must contain exactly 2 sentences, found {n}"
            ));
        }
    }
    Ok(())
}

fn count_terminal_sentences(text: &str) -> usize {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return 0;
    }
    let bytes = trimmed.as_bytes();
    let mut count = 0usize;
    let mut word_chars_in_current = 0usize;

    for (i, &b) in bytes.iter().enumerate() {
        if b.is_ascii_alphabetic() {
            word_chars_in_current += 1;
        }
        if matches!(b, b'.' | b'!' | b'?') {
            let next_is_boundary = i + 1 == bytes.len() || bytes[i + 1] == b' ';
            if next_is_boundary && word_chars_in_current >= 3 {
                count += 1;
                word_chars_in_current = 0;
            }
        }
    }
    count
}

/// Deterministic `0`-LLM 4-bucket smell detector (`MALICIOUS`, `OFF_TASK`, `CONFUSED`, `RISKY`).
pub fn classify_session_smells(
    repo_root: &Path,
    cap: &SessionCapability,
) -> Result<Vec<SmellBadge>, String> {
    let mut badges = Vec::new();
    let current_oid = compute_scoped_tree_oid(repo_root, &cap.allowed_write_paths)?;

    if cap.malicious_flags > 0 {
        badges.push(SmellBadge {
            bucket: SmellBucket::Malicious,
            signal: format!("policy_halt_triggers={}", cap.malicious_flags),
        });
    }
    if cap.blocked_scope_attempts >= 2 {
        badges.push(SmellBadge {
            bucket: SmellBucket::OffTask,
            signal: format!("out_of_scope_attempts={}", cap.blocked_scope_attempts),
        });
    }
    if cap.consecutive_test_failures >= 3 {
        badges.push(SmellBadge {
            bucket: SmellBucket::Confused,
            signal: format!("compile_or_test_loop={}", cap.consecutive_test_failures),
        });
    }

    // Check spool for compile/test thrashing or quarantined crash tails
    if let Ok(spool_path) = spool_file_path(repo_root, &cap.session_id) {
        if let Ok(rec) = recover_spool_frames(&spool_path) {
            if rec.quarantined_tail_bytes > 0 {
                badges.push(SmellBadge {
                    bucket: SmellBucket::Risky,
                    signal: format!("quarantined_spool_bytes={}", rec.quarantined_tail_bytes),
                });
            }
            let fail_events = rec
                .valid_records
                .iter()
                .filter(|r| r.event.op == EventOp::TestFail)
                .count();
            if fail_events >= 4 && !badges.iter().any(|b| b.bucket == SmellBucket::Confused) {
                badges.push(SmellBadge {
                    bucket: SmellBucket::Confused,
                    signal: format!("repeated_test_failures={fail_events}"),
                });
            }
        }
    }

    match &cap.last_green_tree_oid {
        None => {
            badges.push(SmellBadge {
                bucket: SmellBucket::Risky,
                signal: "no_verified_green_test_checkpoint".to_string(),
            });
        }
        Some(green_oid) if green_oid != &current_oid => {
            badges.push(SmellBadge {
                bucket: SmellBucket::Risky,
                signal: "edit_after_last_green_test".to_string(),
            });
        }
        _ => {}
    }

    if cap.attempt >= 3 {
        badges.push(SmellBadge {
            bucket: SmellBucket::Risky,
            signal: format!("high_retry_attempt={}", cap.attempt),
        });
    }

    Ok(badges)
}

/// Appends an authenticated `2+2`-sentence `WorkLedgerEntry` ONLY if the workspace
/// tree OID matches `last_green_tree_oid` (`F18`).
pub fn submit_work_ledger_entry(
    repo_root: &Path,
    session_id: &str,
    what_changed: &str,
    why_changed: &str,
) -> Result<WorkLedgerEntry, String> {
    validate_two_plus_two_sentences(what_changed, why_changed)?;
    let cap = load_session_capability(repo_root, session_id)?;
    let current_oid = compute_scoped_tree_oid(repo_root, &cap.allowed_write_paths)?;

    let Some(ref green_oid) = cap.last_green_tree_oid else {
        return Err(
            "UNVERIFIED_GREEN_STATE: run `swarm-tool grunt checkpoint-green -- <test_cmd>` before submitting ledger".to_string(),
        );
    };
    if green_oid != &current_oid {
        return Err(
            "EDIT_AFTER_LAST_GREEN_TEST: files in allowed_write_paths changed after last green test checkpoint; re-run `checkpoint-green`".to_string(),
        );
    }

    let smell_badges = classify_session_smells(repo_root, &cap)?;
    let mac_payload = format!(
        "{}|{}|{}|{}|{}|{}",
        cap.session_id,
        cap.task_id,
        cap.attempt,
        current_oid,
        what_changed.trim(),
        why_changed.trim()
    );
    let record_mac_hex =
        compute_arbitrary_hmac_hex(repo_root, LEDGER_HMAC_DOMAIN, mac_payload.as_bytes())?;

    let entry = WorkLedgerEntry {
        session_id: cap.session_id.clone(),
        task_id: cap.task_id.clone(),
        attempt: cap.attempt,
        git_tree_oid: current_oid.clone(),
        what_changed: what_changed.trim().to_string(),
        why_changed: why_changed.trim().to_string(),
        smell_badges,
        record_mac_hex,
    };

    let ledger_path = work_ledger_state_path(repo_root)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&ledger_path)
        .map_err(|e| format!("failed opening WORK_LEDGER.jsonl: {e}"))?;
    writeln!(file, "{}", entry.to_json_value().to_json_string())
        .map_err(|e| format!("failed writing WORK_LEDGER.jsonl: {e}"))?;
    file.sync_data()
        .map_err(|e| format!("failed fsyncing WORK_LEDGER.jsonl: {e}"))?;

    let plan_bytes = hex_decode_32(&cap.plan_sha256).unwrap_or([0u8; 32]);
    let tree_bytes = hex_decode_32(&current_oid).unwrap_or([0u8; 32]);
    let _ = append_breadcrumb_for_path(
        repo_root,
        session_id,
        &cap.task_id,
        plan_bytes,
        EventOp::LedgerSubmit,
        "WORK_LEDGER.jsonl",
        None,
        tree_bytes,
    );

    Ok(entry)
}

pub fn load_work_ledger_entries(repo_root: &Path) -> Result<Vec<WorkLedgerEntry>, String> {
    let path = work_ledger_state_path(repo_root)?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for line in raw.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let v = JsonValue::parse(t).map_err(|e| format!("corrupt ledger JSON: {e}"))?;
        let badges = v
            .get("smell_badges")
            .and_then(JsonValue::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(JsonValue::as_str)
                    .filter_map(|s| {
                        let (b, sig) = s.split_once(':')?;
                        let bucket = match b {
                            "MALICIOUS" => SmellBucket::Malicious,
                            "OFF_TASK" => SmellBucket::OffTask,
                            "CONFUSED" => SmellBucket::Confused,
                            "RISKY" => SmellBucket::Risky,
                            _ => return None,
                        };
                        Some(SmellBadge {
                            bucket,
                            signal: sig.to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        out.push(WorkLedgerEntry {
            session_id: v
                .get("session_id")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            task_id: v
                .get("task_id")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            attempt: v.get("attempt").and_then(JsonValue::as_u64).unwrap_or(1) as u32,
            git_tree_oid: v
                .get("git_tree_oid")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            what_changed: v
                .get("what_changed")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            why_changed: v
                .get("why_changed")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            smell_badges: badges,
            record_mac_hex: v
                .get("record_mac")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
        });
    }
    Ok(out)
}

/// Enforced by `agent-guard on-stop`:
/// 1. Rejects any git-staged `.breadcrumbs.jsonl` file.
/// 2. If running as `SwarmRole::Grunt`, fails closed (`Err`) unless `AGENT_GUARD_SESSION_ID`
///    has a valid, HMAC-verified `WorkLedgerEntry` matching the current workspace tree OID (`F32`/`F33`).
pub fn verify_on_stop_swarm_gates(repo_root: &Path) -> Result<(), String> {
    // 1. Check git index for staged `.breadcrumbs.jsonl`
    if let Ok(out) = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["diff", "--cached", "--name-only"])
        .output()
    {
        if out.status.success() {
            let staged = String::from_utf8_lossy(&out.stdout);
            for line in staged.lines() {
                if line.trim().ends_with(".breadcrumbs.jsonl") {
                    return Err(format!(
                        "STAGED_BREADCRUMBS_FORBIDDEN: local flight-recorder file '{}' is staged in git index",
                        line.trim()
                    ));
                }
            }
        }
    }

    // 2. Fail-closed Grunt completion receipt check
    let sid = std::env::var("AGENT_GUARD_SESSION_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "default".to_string());

    let (role, cap_opt) = resolve_active_role(repo_root, &sid)?;
    if role == SwarmRole::Grunt {
        let Some(cap) = cap_opt else {
            return Err(format!(
                "GRUNT_MISSING_WORK_LEDGER: active Grunt session '{sid}' has no minted capability or WORK_LEDGER.jsonl receipt"
            ));
        };
        let entries = load_work_ledger_entries(repo_root)?;
        let Some(latest) = entries
            .iter()
            .rev()
            .find(|e| e.session_id == cap.session_id && e.attempt == cap.attempt)
        else {
            return Err(format!(
                "GRUNT_MISSING_WORK_LEDGER: Grunt session '{}' (attempt {}) tried to stop without submitting a 2+2-sentence WORK_LEDGER.jsonl receipt",
                cap.session_id, cap.attempt
            ));
        };

        let current_oid = compute_scoped_tree_oid(repo_root, &cap.allowed_write_paths)?;
        if latest.git_tree_oid != current_oid {
            return Err(format!(
                "GRUNT_DRIFTED_AFTER_LEDGER: files in allowed_write_paths changed after WORK_LEDGER.jsonl receipt (expected tree {}, got {})",
                &latest.git_tree_oid[..12],
                &current_oid[..12]
            ));
        }

        let expected_payload = format!(
            "{}|{}|{}|{}|{}|{}",
            latest.session_id,
            latest.task_id,
            latest.attempt,
            latest.git_tree_oid,
            latest.what_changed,
            latest.why_changed
        );
        let expected_mac =
            compute_arbitrary_hmac_hex(repo_root, LEDGER_HMAC_DOMAIN, expected_payload.as_bytes())?;
        if expected_mac != latest.record_mac_hex {
            return Err(
                "GRUNT_FORGED_WORK_LEDGER: WORK_LEDGER.jsonl HMAC tag verification failed"
                    .to_string(),
            );
        }
    }

    Ok(())
}
