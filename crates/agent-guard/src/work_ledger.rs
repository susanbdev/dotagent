#![forbid(unsafe_code)]

//! Deterministic `0`-LLM 4-bucket smell classifier (`MALICIOUS`, `OFF_TASK`,
//! `CONFUSED`, `RISKY`), `2+2` pure-ASCII sentence `WORK_LEDGER.jsonl` receipt
//! engine, and fail-closed `Grunt` `on-stop` tree-OID verifier (`F18`, `F32`, `F33`).

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::breadcrumbs::{
    ExclusiveFileLockGuard, append_breadcrumb_for_path, compute_arbitrary_hmac_hex,
    ensure_regular_non_symlink_file, flush_records_idempotent, open_append_nofollow,
    recover_spool_frames, sha256_digest, spool_file_path, swarm_state_dir, trail_path_for_rel_path,
    verify_arbitrary_hmac_hex, verify_breadcrumbs_file, verify_event_mac_for_repo,
};
use crate::json::JsonValue;
use crate::path_policy::{PathAccess, validate_path_with_max_depth};
use crate::qa_suspects::{SourceToken, rust_source_tokens};
use crate::role_sandbox::{
    close_open_session, load_session_capability, path_matches_any_scope, resolve_active_role,
    save_session_capability,
};
use crate::swarm_contracts::{
    EventOp, SessionCapability, SmellBadge, SmellBucket, SwarmRole, WorkLedgerEntry, hex_decode_32,
    hex_encode,
};
use crate::unicode_guard::{ScanMode, scan_unicode};

const LEDGER_HMAC_DOMAIN: &[u8] = b"DOTAGENT_SWARM_V2_WORK_LEDGER_V2";
const GENESIS_LEDGER_PREV_MAC: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

fn push_len_prefixed_bytes(buf: &mut Vec<u8>, slice: &[u8]) {
    buf.extend_from_slice(&(slice.len() as u64).to_be_bytes());
    buf.extend_from_slice(slice);
}

#[allow(clippy::too_many_arguments)]
fn encode_work_ledger_mac_payload(
    prev_mac_hex: &str,
    session_id: &str,
    task_id: &str,
    attempt: u32,
    git_tree_oid: &str,
    event_ids: &[String],
    what_changed: &str,
    why_changed: &str,
    smell_badges: &[SmellBadge],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    push_len_prefixed_bytes(&mut buf, prev_mac_hex.as_bytes());
    push_len_prefixed_bytes(&mut buf, session_id.as_bytes());
    push_len_prefixed_bytes(&mut buf, task_id.as_bytes());
    buf.extend_from_slice(&attempt.to_be_bytes());
    push_len_prefixed_bytes(&mut buf, git_tree_oid.as_bytes());
    buf.extend_from_slice(&(event_ids.len() as u64).to_be_bytes());
    for eid in event_ids {
        push_len_prefixed_bytes(&mut buf, eid.as_bytes());
    }
    push_len_prefixed_bytes(&mut buf, what_changed.as_bytes());
    push_len_prefixed_bytes(&mut buf, why_changed.as_bytes());
    buf.extend_from_slice(&(smell_badges.len() as u64).to_be_bytes());
    for badge in smell_badges {
        let bucket_str = match badge.bucket {
            SmellBucket::Malicious => "MALICIOUS",
            SmellBucket::OffTask => "OFF_TASK",
            SmellBucket::Confused => "CONFUSED",
            SmellBucket::Risky => "RISKY",
        };
        push_len_prefixed_bytes(&mut buf, bucket_str.as_bytes());
        push_len_prefixed_bytes(&mut buf, badge.signal.as_bytes());
    }
    buf
}

pub fn work_ledger_state_path(repo_root: &Path) -> Result<PathBuf, String> {
    let dir = swarm_state_dir(repo_root)?.join("ledger");
    if !dir.is_dir() {
        fs::create_dir_all(&dir)
            .map_err(|e| format!("failed creating swarm ledger dir '{}': {e}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
    }
    Ok(dir.join("WORK_LEDGER.jsonl"))
}

/// Computes a deterministic scoped Git-blob `SHA-256` tree digest (`git_tree_oid`) over all
/// clean repository files matching `scope_patterns`:
/// - Each in-scope file is hashed with Git SHA-256 blob framing (`"blob <len>\0<body>"`).
/// - Forbidden directories/files (temp, cache, `node_modules`, `vendor`, `.venv`, `.env*`,
///   guard state, `audit.jsonl`, `.breadcrumbs.jsonl`, `.git`, `target`) and symlinks are
///   excluded via `path_policy` before reading or recursing, with zero artificial depth cap.
pub fn compute_scoped_tree_oid(
    repo_root: &Path,
    scope_patterns: &[String],
) -> Result<String, String> {
    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let mut file_digests: BTreeMap<String, String> = BTreeMap::new();
    collect_scoped_blobs(&canon_repo, &canon_repo, scope_patterns, &mut file_digests);

    let mut buf = Vec::new();
    buf.extend_from_slice(b"DOTAGENT_GIT_BLOB_TREE_V1\0");
    for (rel, blob_oid) in &file_digests {
        buf.extend_from_slice(b"100644 ");
        buf.extend_from_slice(&(rel.len() as u32).to_be_bytes());
        buf.extend_from_slice(rel.as_bytes());
        buf.push(0);
        buf.extend_from_slice(blob_oid.as_bytes());
    }
    Ok(hex_encode(&sha256_digest(&buf)))
}

fn git_sha256_blob_oid(bytes: &[u8]) -> String {
    let header = format!("blob {}\0", bytes.len());
    let mut framed = Vec::with_capacity(header.len() + bytes.len());
    framed.extend_from_slice(header.as_bytes());
    framed.extend_from_slice(bytes);
    hex_encode(&sha256_digest(&framed))
}

fn collect_scoped_blobs(
    canon_repo: &Path,
    dir: &Path,
    scope_patterns: &[String],
    out: &mut BTreeMap<String, String>,
) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == ".git"
            || name_str == "target"
            || name_str == ".state"
            || name_str == ".breadcrumbs.jsonl"
            || name_str.ends_with(".breadcrumbs.jsonl.lock")
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
        let rel = full
            .strip_prefix(canon_repo)
            .unwrap_or(&full)
            .to_string_lossy()
            .replace('\\', "/");

        if ft.is_dir() {
            if !scope_patterns.is_empty() && !dir_can_match_any_scope(&rel, scope_patterns) {
                continue;
            }
            // Skip any forbidden cache, temp, dependency, secret, or guard-state directory before recursing!
            if validate_path_with_max_depth(
                canon_repo,
                canon_repo,
                &rel,
                PathAccess::ListSearch {
                    requested_depth: Some(1),
                },
                usize::MAX,
            )
            .is_err()
            {
                continue;
            }
            collect_scoped_blobs(canon_repo, &full, scope_patterns, out);
        } else if ft.is_file()
            && (scope_patterns.is_empty() || path_matches_any_scope(&rel, scope_patterns))
        {
            // Enforce full path_policy Read validation so .env*, *.pem, audit.jsonl, etc. are never hashed!
            if validate_path_with_max_depth(
                canon_repo,
                canon_repo,
                &rel,
                PathAccess::Read,
                usize::MAX,
            )
            .is_err()
            {
                continue;
            }
            if let Ok(bytes) = fs::read(&full) {
                out.insert(rel, git_sha256_blob_oid(&bytes));
            }
        }
    }
}

/// Returns `true` iff at least one descendant file inside `dir_rel` could possibly match `patterns`.
fn dir_can_match_any_scope(dir_rel: &str, patterns: &[String]) -> bool {
    let clean_dir = dir_rel.trim_start_matches("./").trim_end_matches('/');
    for pat in patterns {
        let p = pat.trim().trim_start_matches("./");
        if matches!(p, "" | "." | "*" | "**") {
            return true;
        }
        if let Some(prefix) = p.strip_suffix("/**") {
            let base = prefix.trim_end_matches('/');
            if base.is_empty()
                || clean_dir == base
                || clean_dir.starts_with(&format!("{base}/"))
                || base.starts_with(&format!("{clean_dir}/"))
            {
                return true;
            }
        } else if let Some(prefix) = p.strip_suffix("/*") {
            let base = prefix.trim_end_matches('/');
            // `base/*` matches direct files inside `base`, so we must enter ancestors of `base` and `base` itself,
            // but never need to recurse into subdirectories deeper than `base`!
            if base.is_empty() || clean_dir == base || base.starts_with(&format!("{clean_dir}/")) {
                return true;
            }
        } else {
            let base = p.trim_end_matches('/');
            if clean_dir == base
                || clean_dir.starts_with(&format!("{base}/"))
                || base.starts_with(&format!("{clean_dir}/"))
            {
                return true;
            }
        }
    }
    false
}

/// Records the result of `swarm-tool grunt checkpoint-green` into the session capability
/// and breadcrumb flight recorder.
pub fn record_test_checkpoint(
    repo_root: &Path,
    session_id: &str,
    passed: bool,
) -> Result<(SessionCapability, String), String> {
    let mut cap = load_session_capability(repo_root, session_id)?;
    if cap.role != SwarmRole::Grunt {
        return Err(format!(
            "ROLE_CAPABILITY_MISMATCH: session '{}' has role '{}', only 'grunt' may record test checkpoints",
            cap.session_id,
            cap.role.as_str_id()
        ));
    }
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
    const ABBREVIATIONS: &[&str] = &[
        "e.g.", "i.e.", "vs.", "etc.", "cf.", "fig.", "sec.", "approx.", "min.", "max.", "no.",
        "inc.", "ltd.", "mr.", "ms.", "dr.", "st.", "ref.", "vol.", "est.",
    ];

    let trimmed = text.trim();
    if trimmed.is_empty() {
        return 0;
    }
    let bytes = trimmed.as_bytes();
    let lower = trimmed.to_ascii_lowercase();
    let mut count = 0usize;
    let mut word_chars_in_current = 0usize;

    for (i, &b) in bytes.iter().enumerate() {
        if b.is_ascii_alphabetic() {
            word_chars_in_current += 1;
        }
        if matches!(b, b'.' | b'!' | b'?') {
            if b == b'.' {
                // Skip numeric decimals / version numbers such as `1.0`, `v1.2`, `0.4.7`.
                let prev_is_digit = i > 0 && bytes[i - 1].is_ascii_digit();
                let next_is_digit = i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit();
                if prev_is_digit && next_is_digit {
                    continue;
                }
                // Skip periods internal to multi-dot abbreviations like the first dot in `e.g.` or `i.e.`.
                if i + 2 < bytes.len() && bytes[i + 1].is_ascii_alphabetic() && bytes[i + 2] == b'.'
                {
                    continue;
                }
                // Skip trailing period of common engineering abbreviations (`e.g.`, `i.e.`, `vs.`, `etc.`, ...).
                let prefix = &lower[..=i];
                let is_abbrev = ABBREVIATIONS.iter().any(|abbr| {
                    if !prefix.ends_with(abbr) {
                        return false;
                    }
                    let start = prefix.len() - abbr.len();
                    start == 0 || !prefix.as_bytes()[start - 1].is_ascii_alphanumeric()
                });
                if is_abbrev {
                    continue;
                }
            }

            let next_is_boundary = i + 1 == bytes.len()
                || bytes[i + 1].is_ascii_whitespace()
                || (matches!(bytes[i + 1], b')' | b']' | b'"' | b'\'')
                    && (i + 2 == bytes.len() || bytes[i + 2].is_ascii_whitespace()));
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

    if !cap.allowed_write_paths.is_empty() {
        badges.extend(scan_production_stub_smells(
            repo_root,
            &cap.allowed_write_paths,
        ));
    }

    Ok(badges)
}

/// Scans in-scope non-test production files for reward-hacking stubs:
/// - `todo!(...)` / `unimplemented!(...)` macros outside `#[cfg(test)]`
/// - Empty string-literal dispatch arms (`"fault-inject" => {}`)
/// - HTTP `501` unimplemented shims (`501` + `"not implemented"` / `"attach compiled"` / `"before live dispatch"`)
/// - Unbound secret-stream reads (`if let Err(...) = ...read_secret_stdin()` / `let _ = ...read_secret_from_fd()`)
/// - No-op stack-copy `.to_bytes()` + `.zeroize()` inside `Drop::drop`
pub fn scan_production_stub_smells(repo_root: &Path, write_patterns: &[String]) -> Vec<SmellBadge> {
    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let mut prod_files = BTreeMap::new();
    collect_scoped_source_files(&canon_repo, &canon_repo, write_patterns, &mut prod_files);

    let mut out = Vec::new();
    for (rel, body) in prod_files {
        if crate::role_sandbox::is_qa_writable_path(&rel) {
            continue;
        }
        let rust_tokens = if rel.ends_with(".rs") {
            rust_source_tokens(&body)
        } else {
            Vec::new()
        };
        let test_ranges = rust_cfg_test_item_ranges(&rust_tokens);
        let effective = mask_rust_test_items(&body, &test_ranges);
        let macro_lines = rust_stub_macro_lines(&rust_tokens, &test_ranges);

        let mut in_drop_fn = false;
        let mut drop_brace_depth: i32 = 0;
        let mut drop_copied_bytes_var: Option<String> = None;

        for (idx, raw_line) in effective.lines().enumerate() {
            let line_no = idx + 1;
            if macro_lines.contains(&line_no) {
                out.push(SmellBadge {
                    bucket: SmellBucket::Risky,
                    signal: format!("hollow_stub:todo_macro:{rel}:{line_no}"),
                });
            }
            let trimmed = raw_line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with("/*")
                || trimmed.starts_with('*')
            {
                continue;
            }
            let code_only = trimmed.split("//").next().unwrap_or(trimmed).trim();
            let lower = code_only.to_ascii_lowercase();

            if is_empty_string_literal_match_arm(code_only) {
                out.push(SmellBadge {
                    bucket: SmellBucket::Risky,
                    signal: format!("hollow_stub:empty_literal_arm:{rel}:{line_no}"),
                });
            }

            if code_only.contains("501")
                && (lower.contains("not implemented")
                    || lower.contains("attach compiled")
                    || lower.contains("before live dispatch"))
            {
                out.push(SmellBadge {
                    bucket: SmellBucket::Risky,
                    signal: format!("hollow_stub:http_501_placeholder:{rel}:{line_no}"),
                });
            }

            if (code_only.starts_with("let _ =")
                || code_only.starts_with("if let Err(")
                || code_only.starts_with("let Err("))
                && (code_only.contains("read_secret_stdin(")
                    || code_only.contains("read_secret_from_fd("))
            {
                out.push(SmellBadge {
                    bucket: SmellBucket::Malicious,
                    signal: format!("hollow_stub:discarded_secret_read:{rel}:{line_no}"),
                });
            }

            if rel.ends_with(".rs") {
                if !in_drop_fn && code_only.starts_with("fn drop(&mut self)") {
                    in_drop_fn = true;
                    drop_brace_depth = 0;
                    drop_copied_bytes_var = None;
                }
                if in_drop_fn {
                    for ch in code_only.chars() {
                        if ch == '{' {
                            drop_brace_depth += 1;
                        } else if ch == '}' {
                            drop_brace_depth -= 1;
                        }
                    }
                    if let Some(rest) = code_only.strip_prefix("let mut ")
                        && let Some((var_name, rhs)) = rest.split_once('=')
                        && rhs.contains(".to_bytes()")
                    {
                        drop_copied_bytes_var = Some(var_name.trim().to_string());
                    } else if let Some(ref vname) = drop_copied_bytes_var
                        && code_only.starts_with(&format!("{vname}.zeroize()"))
                    {
                        out.push(SmellBadge {
                            bucket: SmellBucket::Risky,
                            signal: format!("hollow_stub:noop_stack_copy_zeroize:{rel}:{line_no}"),
                        });
                        drop_copied_bytes_var = None;
                    }
                    if drop_brace_depth <= 0 {
                        in_drop_fn = false;
                        drop_copied_bytes_var = None;
                    }
                }
            }
        }
    }
    out
}

fn collect_scoped_source_files(
    canon_repo: &Path,
    dir: &Path,
    scope_patterns: &[String],
    out: &mut BTreeMap<String, String>,
) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if matches!(
            name_str.as_ref(),
            ".git" | "target" | ".state" | ".breadcrumbs.jsonl"
        ) || name_str.ends_with(".breadcrumbs.jsonl.lock")
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
        let rel = full
            .strip_prefix(canon_repo)
            .unwrap_or(&full)
            .to_string_lossy()
            .replace('\\', "/");
        if ft.is_dir() {
            if !scope_patterns.is_empty() && !dir_can_match_any_scope(&rel, scope_patterns) {
                continue;
            }
            if validate_path_with_max_depth(
                canon_repo,
                canon_repo,
                &rel,
                PathAccess::ListSearch {
                    requested_depth: Some(1),
                },
                usize::MAX,
            )
            .is_err()
            {
                continue;
            }
            collect_scoped_source_files(canon_repo, &full, scope_patterns, out);
        } else if ft.is_file()
            && (scope_patterns.is_empty() || path_matches_any_scope(&rel, scope_patterns))
            && validate_path_with_max_depth(
                canon_repo,
                canon_repo,
                &rel,
                PathAccess::Read,
                usize::MAX,
            )
            .is_ok()
            && let Ok(text) = fs::read_to_string(&full)
        {
            out.insert(rel, text);
        }
    }
}

fn rust_cfg_test_item_ranges(tokens: &[SourceToken<'_>]) -> Vec<Range<usize>> {
    const CFG_TEST: [&str; 7] = ["#", "[", "cfg", "(", "test", ")", "]"];
    let mut ranges = Vec::new();
    let mut index = 0;
    while let Some(attribute) = tokens.get(index..index + CFG_TEST.len()) {
        if attribute
            .iter()
            .zip(CFG_TEST)
            .all(|(token, expected)| token.is(expected))
            && let Some(end) = rust_attributed_item_end(tokens, index + CFG_TEST.len())
        {
            ranges.push(attribute[0].offset..tokens[end].offset + tokens[end].text.len());
            index = end + 1;
        } else {
            index += 1;
        }
    }
    ranges
}

fn rust_attributed_item_end(tokens: &[SourceToken<'_>], start: usize) -> Option<usize> {
    let mut groups = Vec::new();
    let mut item_kind_found = false;
    let mut braced_item = false;
    let mut type_parameters = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        if groups.is_empty() {
            if token.is("}") {
                return None;
            }
            if token.is(";") {
                return item_kind_found.then_some(index);
            }
            if !item_kind_found {
                braced_item = [
                    "fn",
                    "mod",
                    "struct",
                    "enum",
                    "union",
                    "trait",
                    "impl",
                    "extern",
                    "macro_rules",
                    "{",
                ]
                .iter()
                .any(|name| token.is(name))
                    || rust_macro_item_starts_at(tokens, index);
                let const_fn = token.is("const")
                    && tokens.get(index + 1).is_some_and(|next| {
                        ["fn", "async", "unsafe", "extern"]
                            .iter()
                            .any(|qualifier| next.is(qualifier))
                    });
                item_kind_found = braced_item
                    || !const_fn
                        && ["type", "const", "static", "use", "let"]
                            .iter()
                            .any(|name| token.is(name));
                if !item_kind_found
                    && !const_fn
                    && !["#", "[", "pub", "(", "async", "unsafe", "default", "auto"]
                        .iter()
                        .any(|qualifier| token.is(qualifier))
                {
                    return None;
                }
            }
            if braced_item {
                if token.is("<") {
                    type_parameters += 1;
                } else if token.is(">")
                    && !tokens
                        .get(index.wrapping_sub(1))
                        .is_some_and(|previous| previous.is("-"))
                {
                    type_parameters = type_parameters.saturating_sub(1);
                }
            }
        }
        if let Some(close) = [("(", ")"), ("[", "]"), ("{", "}")]
            .into_iter()
            .find_map(|(open, close)| token.is(open).then_some(close))
        {
            groups.push(close);
        } else if groups.last().is_some_and(|close| token.is(close)) {
            groups.pop();
            if groups.is_empty() && token.is("}") && braced_item && type_parameters == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn rust_macro_item_starts_at(tokens: &[SourceToken<'_>], mut index: usize) -> bool {
    while let Some(token) = tokens.get(index).filter(|token| {
        token.is(token.text)
            && token
                .text
                .starts_with(|first: char| first.is_alphabetic() || first == '_')
    }) {
        if token.is("_") {
            return false;
        }
        if tokens.get(index + 1).is_some_and(|next| next.is("!")) {
            return tokens
                .get(index + 2)
                .is_some_and(|opener| ["(", "[", "{"].iter().any(|text| opener.is(text)));
        }
        if !tokens
            .get(index + 1..index + 3)
            .is_some_and(|pair| pair.iter().all(|colon| colon.is(":")))
        {
            return false;
        }
        index += 3;
    }
    false
}

fn mask_rust_test_items<'a>(source: &'a str, test_ranges: &[Range<usize>]) -> Cow<'a, str> {
    if test_ranges.is_empty() {
        return Cow::Borrowed(source);
    }
    let mut code = String::with_capacity(source.len());
    let mut copied = 0;
    for range in test_ranges {
        code.push_str(&source[copied..range.start]);
        code.push(' ');
        code.extend(source[range.clone()].chars().filter(|&c| c == '\n'));
        copied = range.end;
    }
    code.push_str(&source[copied..]);
    Cow::Owned(code)
}

fn rust_stub_macro_lines(
    tokens: &[SourceToken<'_>],
    test_ranges: &[Range<usize>],
) -> BTreeSet<usize> {
    tokens
        .windows(3)
        .filter(|t| {
            (t[0].is("todo")
                || t[0].is("unimplemented")
                || t[0].is("r#todo")
                || t[0].is("r#unimplemented"))
                && t[1].is("!")
                && (t[2].is("(") || t[2].is("[") || t[2].is("{"))
                && !test_ranges
                    .get(test_ranges.partition_point(|range| range.end <= t[0].offset))
                    .is_some_and(|range| range.start <= t[2].offset)
        })
        .map(|t| t[0].line)
        .collect()
}

fn is_empty_string_literal_match_arm(code_only: &str) -> bool {
    if !code_only.starts_with('"') {
        return false;
    }
    let Some((_, rhs)) = code_only.split_once("=>") else {
        return false;
    };
    let rhs_clean = rhs.trim().trim_end_matches(',').trim();
    rhs_clean == "{}" || rhs_clean == "()"
}

type TrailRecordsMap = BTreeMap<PathBuf, Vec<crate::breadcrumbs::SignedBreadcrumbRecord>>;

struct VerifiedSessionEvents {
    ids: Vec<String>,
    by_trail: TrailRecordsMap,
    latest_edit_sha_by_rel: BTreeMap<String, [u8; 32]>,
}

fn collect_verified_session_event_ids(
    repo_root: &Path,
    session_id: &str,
    task_id: &str,
) -> Result<VerifiedSessionEvents, String> {
    let spool_path = spool_file_path(repo_root, session_id)?;
    if !spool_path.exists() {
        return Err(format!(
            "LEDGER_MISSING_PINNED_EVENTS: session '{session_id}' has no breadcrumb spool to pin"
        ));
    }
    let report = recover_spool_frames(&spool_path)?;
    let mut ids = Vec::new();
    let mut by_trail: TrailRecordsMap = BTreeMap::new();
    let mut latest_edit_sha_by_rel: BTreeMap<String, [u8; 32]> = BTreeMap::new();
    let mut has_green = false;
    let mut expected_prev_mac = [0u8; 32];

    for (idx, rec) in report.valid_records.into_iter().enumerate() {
        verify_event_mac_for_repo(repo_root, &rec.event, &rec.record_mac)?;
        let expected_seq = (idx as u64) + 1;
        if rec.event.seq_no != expected_seq {
            return Err(format!(
                "LEDGER_BROKEN_EVENT_CHAIN: session '{session_id}' expected seq_no {expected_seq}, got {}",
                rec.event.seq_no
            ));
        }
        if rec.event.prev_event_mac != expected_prev_mac {
            return Err(format!(
                "LEDGER_BROKEN_EVENT_CHAIN: session '{session_id}' prev_event_mac mismatch at seq_no {expected_seq}"
            ));
        }
        expected_prev_mac = rec.record_mac;

        if rec.event.session_id != session_id || rec.event.task_id != task_id {
            return Err(format!(
                "LEDGER_FOREIGN_EVENT: spool event belongs to ({}, {}), expected ({session_id}, {task_id})",
                rec.event.session_id, rec.event.task_id
            ));
        }
        match rec.event.op {
            EventOp::TestGreen => {
                has_green = true;
            }
            EventOp::FileEdit => {
                latest_edit_sha_by_rel
                    .insert(rec.event.canonical_rel_path.clone(), rec.event.doc_sha256);
            }
            _ => {}
        }
        ids.push(rec.event_id_hex());
        let trail = trail_path_for_rel_path(repo_root, &rec.event.canonical_rel_path)?;
        by_trail.entry(trail).or_default().push(rec);
    }

    if ids.is_empty() || !has_green {
        return Err(format!(
            "LEDGER_MISSING_PINNED_EVENTS: session '{session_id}' has no verified green-checkpoint breadcrumb events"
        ));
    }
    Ok(VerifiedSessionEvents {
        ids,
        by_trail,
        latest_edit_sha_by_rel,
    })
}

/// Appends an authenticated `2+2`-sentence `WorkLedgerEntry` ONLY if:
/// 1. Workspace tree OID matches `last_green_tree_oid` (`F18`),
/// 2. Session recorded >=1 authenticated `EventOp::FileEdit` breadcrumb in `allowed_write_paths`
///    whose `doc_sha256` matches the current on-disk file bytes (Finding #6), and
/// 3. All authenticated session `event_ids` are pinned into the HMAC-authenticated receipt.
pub fn submit_work_ledger_entry(
    repo_root: &Path,
    session_id: &str,
    what_changed: &str,
    why_changed: &str,
) -> Result<WorkLedgerEntry, String> {
    submit_work_ledger_entry_with_opts(repo_root, session_id, what_changed, why_changed, false)
}

pub fn submit_work_ledger_entry_with_opts(
    repo_root: &Path,
    session_id: &str,
    what_changed: &str,
    why_changed: &str,
    reject_hollow_stubs: bool,
) -> Result<WorkLedgerEntry, String> {
    validate_two_plus_two_sentences(what_changed, why_changed)?;
    let cap = load_session_capability(repo_root, session_id)?;
    if cap.role != SwarmRole::Grunt {
        return Err(format!(
            "ROLE_CAPABILITY_MISMATCH: session '{}' has role '{}', only 'grunt' may submit WORK_LEDGER.jsonl receipts",
            cap.session_id,
            cap.role.as_str_id()
        ));
    }
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

    let verified = collect_verified_session_event_ids(repo_root, &cap.session_id, &cap.task_id)?;
    if verified.latest_edit_sha_by_rel.is_empty() {
        return Err(format!(
            "LEDGER_MISSING_EDIT_PROVENANCE: session '{}' recorded zero authenticated FileEdit breadcrumbs; edit provenance is required before submitting WORK_LEDGER.jsonl",
            cap.session_id
        ));
    }

    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    for (rel_path, recorded_sha) in &verified.latest_edit_sha_by_rel {
        if !path_matches_any_scope(rel_path, &cap.allowed_write_paths) {
            return Err(format!(
                "LEDGER_OUT_OF_SCOPE_EDIT_PROVENANCE: FileEdit breadcrumb path '{rel_path}' is outside allowed_write_paths {:?}",
                cap.allowed_write_paths
            ));
        }
        let disk_path = canon_repo.join(rel_path);
        if disk_path.exists() {
            let bytes = fs::read(&disk_path).map_err(|e| {
                format!(
                    "LEDGER_STALE_EDIT_PROVENANCE: failed reading edited file '{rel_path}': {e}"
                )
            })?;
            let current_sha = sha256_digest(&bytes);
            if &current_sha != recorded_sha {
                return Err(format!(
                    "LEDGER_STALE_EDIT_PROVENANCE: on-disk SHA-256 of '{rel_path}' ({}) does not match latest authenticated FileEdit breadcrumb ({})",
                    &hex_encode(&current_sha)[..12],
                    &hex_encode(recorded_sha)[..12]
                ));
            }
        } else if *recorded_sha != [0u8; 32] {
            return Err(format!(
                "LEDGER_STALE_EDIT_PROVENANCE: edited file '{rel_path}' was removed on disk without matching deletion provenance"
            ));
        }
    }

    for (trail_path, records) in &verified.by_trail {
        if let Err(e) = flush_records_idempotent(trail_path, records) {
            if std::env::var("AGENT_GUARD_IN_SANDBOX").ok().as_deref() == Some("1") {
                let root_trail = repo_root.join(".breadcrumbs.jsonl");
                flush_records_idempotent(&root_trail, records)?;
            } else {
                return Err(e);
            }
        }
    }

    let smell_badges = classify_session_smells(repo_root, &cap)?;
    if reject_hollow_stubs
        && let Some(stub_badge) = smell_badges
            .iter()
            .find(|b| b.signal.starts_with("hollow_stub:"))
    {
        return Err(format!(
            "HOLLOW_STUB_IMPLEMENTATION_REJECTED: production stub detected ({}) in session '{}'; replace placeholders with real implementation before submitting WORK_LEDGER.jsonl",
            stub_badge.signal, cap.session_id
        ));
    }
    let what_trimmed = what_changed.trim().to_string();
    let why_trimmed = why_changed.trim().to_string();
    let event_ids = verified.ids;

    let ledger_path = work_ledger_state_path(repo_root)?;
    let entry = {
        let _ledger_lock = ExclusiveFileLockGuard::acquire(&ledger_path)?;
        let prev_mac_hex = if fs::symlink_metadata(&ledger_path).is_ok() {
            ensure_regular_non_symlink_file(&ledger_path)?;
            let existing_raw = fs::read_to_string(&ledger_path)
                .map_err(|e| format!("failed reading WORK_LEDGER.jsonl: {e}"))?;
            match existing_raw.lines().map(str::trim).rfind(|l| !l.is_empty()) {
                Some(last_line) => {
                    let parsed = JsonValue::parse(last_line).map_err(|e| {
                        format!("FORGED_WORK_LEDGER_ENTRY: corrupt tail in WORK_LEDGER.jsonl: {e}")
                    })?;
                    parsed
                        .get("record_mac")
                        .and_then(JsonValue::as_str)
                        .filter(|s| !s.is_empty())
                        .ok_or_else(|| {
                            "FORGED_WORK_LEDGER_ENTRY: missing record_mac in tail entry".to_string()
                        })?
                        .to_string()
                }
                None => GENESIS_LEDGER_PREV_MAC.to_string(),
            }
        } else {
            GENESIS_LEDGER_PREV_MAC.to_string()
        };

        let mac_payload = encode_work_ledger_mac_payload(
            &prev_mac_hex,
            &cap.session_id,
            &cap.task_id,
            cap.attempt,
            &current_oid,
            &event_ids,
            &what_trimmed,
            &why_trimmed,
            &smell_badges,
        );
        let record_mac_hex =
            compute_arbitrary_hmac_hex(repo_root, LEDGER_HMAC_DOMAIN, &mac_payload)?;

        let built = WorkLedgerEntry {
            session_id: cap.session_id.clone(),
            task_id: cap.task_id.clone(),
            attempt: cap.attempt,
            git_tree_oid: current_oid.clone(),
            event_ids,
            what_changed: what_trimmed,
            why_changed: why_trimmed,
            smell_badges,
            record_mac_hex,
        };

        let mut json_val = built.to_json_value();
        if let JsonValue::Object(ref mut fields) = json_val {
            fields.push(("prev_record_mac".to_string(), JsonValue::Str(prev_mac_hex)));
        }

        let mut file = open_append_nofollow(&ledger_path)?;
        writeln!(file, "{}", json_val.to_json_string())
            .map_err(|e| format!("failed writing WORK_LEDGER.jsonl: {e}"))?;
        file.sync_data()
            .map_err(|e| format!("failed fsyncing WORK_LEDGER.jsonl: {e}"))?;
        built
    };

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

/// Loads and authenticates every entry in `WORK_LEDGER.jsonl` (`2+2` sentence schema,
/// length-prefixed `LEDGER_HMAC_DOMAIN` signature covering `smell_badges` + `prev_record_mac`
/// hash chain, and pinned session `event_ids` provenance).
pub fn load_work_ledger_entries(repo_root: &Path) -> Result<Vec<WorkLedgerEntry>, String> {
    let path = work_ledger_state_path(repo_root)?;
    if fs::symlink_metadata(&path).is_err() {
        return Ok(Vec::new());
    }
    ensure_regular_non_symlink_file(&path)?;
    let raw = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let mut expected_prev_mac = GENESIS_LEDGER_PREV_MAC.to_string();

    for (line_idx, line) in raw.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let v = JsonValue::parse(t).map_err(|e| {
            format!(
                "FORGED_WORK_LEDGER_ENTRY: corrupt ledger JSON at line {}: {e}",
                line_idx + 1
            )
        })?;
        let mut badges = Vec::new();
        if let Some(arr) = v.get("smell_badges").and_then(JsonValue::as_array) {
            for item in arr {
                let raw_badge = item.as_str().ok_or_else(|| {
                    format!(
                        "FORGED_WORK_LEDGER_ENTRY: non-string smell_badge at line {}",
                        line_idx + 1
                    )
                })?;
                let (b, sig) = raw_badge.split_once(':').ok_or_else(|| {
                    format!(
                        "FORGED_WORK_LEDGER_ENTRY: malformed smell_badge '{raw_badge}' at line {}",
                        line_idx + 1
                    )
                })?;
                let bucket = match b {
                    "MALICIOUS" => SmellBucket::Malicious,
                    "OFF_TASK" => SmellBucket::OffTask,
                    "CONFUSED" => SmellBucket::Confused,
                    "RISKY" => SmellBucket::Risky,
                    _ => {
                        return Err(format!(
                            "FORGED_WORK_LEDGER_ENTRY: unknown smell bucket '{b}' at line {}",
                            line_idx + 1
                        ));
                    }
                };
                badges.push(SmellBadge {
                    bucket,
                    signal: sig.to_string(),
                });
            }
        }
        let event_ids: Vec<String> = v
            .get("event_ids")
            .and_then(JsonValue::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(JsonValue::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        if let Some(recorded_prev) = v.get("prev_record_mac").and_then(JsonValue::as_str)
            && !recorded_prev.eq_ignore_ascii_case(&expected_prev_mac)
        {
            return Err(format!(
                "FORGED_WORK_LEDGER_ENTRY: broken hash chain at line {} (expected prev_record_mac '{}', got '{recorded_prev}')",
                line_idx + 1,
                expected_prev_mac
            ));
        }

        let entry = WorkLedgerEntry {
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
            event_ids,
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
        };

        if entry.session_id.is_empty()
            || entry.task_id.is_empty()
            || entry.git_tree_oid.is_empty()
            || entry.event_ids.is_empty()
            || entry.record_mac_hex.is_empty()
        {
            return Err(format!(
                "FORGED_WORK_LEDGER_ENTRY: missing required fields or empty event_ids at line {}",
                line_idx + 1
            ));
        }
        validate_two_plus_two_sentences(&entry.what_changed, &entry.why_changed).map_err(|e| {
            format!(
                "FORGED_WORK_LEDGER_ENTRY: invalid 2+2 sentences at line {}: {e}",
                line_idx + 1
            )
        })?;

        let expected_payload = encode_work_ledger_mac_payload(
            &expected_prev_mac,
            &entry.session_id,
            &entry.task_id,
            entry.attempt,
            &entry.git_tree_oid,
            &entry.event_ids,
            &entry.what_changed,
            &entry.why_changed,
            &entry.smell_badges,
        );
        verify_arbitrary_hmac_hex(
            repo_root,
            LEDGER_HMAC_DOMAIN,
            &expected_payload,
            &entry.record_mac_hex,
        )
        .map_err(|e| {
            format!(
                "FORGED_WORK_LEDGER_ENTRY: HMAC verification failed for session '{}' at line {}: {e}",
                entry.session_id,
                line_idx + 1
            )
        })?;

        let verified = collect_verified_session_event_ids(
            repo_root,
            &entry.session_id,
            &entry.task_id,
        )
        .map_err(|e| {
            format!(
                "FORGED_WORK_LEDGER_ENTRY: unverified event provenance for session '{}': {e}",
                entry.session_id
            )
        })?;
        let verified_set: BTreeSet<&str> = verified.ids.iter().map(String::as_str).collect();
        for pinned in &entry.event_ids {
            if !verified_set.contains(pinned.as_str()) {
                return Err(format!(
                    "FORGED_WORK_LEDGER_ENTRY: pinned event_id '{pinned}' not found in authenticated session '{}' breadcrumbs",
                    entry.session_id
                ));
            }
        }

        expected_prev_mac = entry.record_mac_hex.clone();
        out.push(entry);
    }
    Ok(out)
}

/// Enforced by `agent-guard on-stop`:
/// 1. Rejects any git-staged `.breadcrumbs.jsonl` file.
/// 2. If running as `SwarmRole::Grunt`, fails closed (`Err`) unless `AGENT_GUARD_SESSION_ID`
///    has a valid, HMAC-verified `WorkLedgerEntry` matching the current workspace tree OID
///    AND pinning authenticated session `event_ids` present in `.breadcrumbs.jsonl` (`F32`/`F33`).
pub fn verify_on_stop_swarm_gates(repo_root: &Path) -> Result<(), String> {
    // 1. Check git index for staged `.breadcrumbs.jsonl`
    if let Ok(out) = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["diff", "--cached", "--name-only"])
        .output()
        && out.status.success()
    {
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

    // 2. Fail-closed Grunt completion receipt check
    let sid = std::env::var("AGENT_GUARD_SESSION_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "default".to_string());

    let (role, cap_opt) = resolve_active_role(repo_root, &sid)?;
    if role == SwarmRole::Grunt {
        let Some(ref cap) = cap_opt else {
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

        let verified =
            collect_verified_session_event_ids(repo_root, &cap.session_id, &cap.task_id)?;
        for trail_path in verified.by_trail.keys() {
            if trail_path.exists() {
                verify_breadcrumbs_file(repo_root, trail_path)?;
            }
        }
    }

    if let Some(ref finished_cap) = cap_opt {
        let _ = close_open_session(repo_root, Some(&finished_cap.session_id));
    }

    Ok(())
}

#[cfg(test)]
#[path = "../tests/fixtures/stub_macro_checks.rs"]
mod stub_macro_tests;
