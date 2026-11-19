//! Static zero-trust repository & workflow hygiene auditor (`audit-repo` & `verify_global_git_hardening`).
//!
//! Enforces:
//! - All 19 global Git hardening settings (`core.hooksPath=/dev/null`, `https`-only, `fsckObjects=true`)
//! - `.git/config` and `.git/hooks` RCE / local-override inspection
//! - Build-tool (`.cargo/config*`, `.yarnrc*`, `.npmrc`) and `.gitattributes` filter trap detection
//! - Non-symlink canonical root `AGENTS.md` + bounded (`<= 2` depth) rogue shadow authority scan
//! - `.github/workflows/*.{yml,yaml}` chained-trigger prohibition (`workflow_run`, `workflow_call`, `repository_dispatch`)

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::CANONICAL_DIST_GEMINI_SHA256;
use crate::cmd_policy::{inspect_repo_build_config_traps, inspect_repo_git_config_and_hooks};
use crate::crypto;
use crate::path_policy::{MAX_DIRECTORY_WALK_DEPTH, PathAccess, validate_path};
use crate::unicode_guard::{ScanMode, scan_unicode};

/// Verifies fail-closed that all 19 canonical global Git hardening keys are enforced (`dist/gitconfig.hardened`).
pub fn verify_global_git_hardening() -> Result<(), String> {
    const REQUIRED_GLOBAL_GIT_SETTINGS: &[(&str, &str)] = &[
        ("core.hookspath", "/dev/null"),
        ("core.attributesfile", "/dev/null"),
        ("core.fsmonitor", "false"),
        ("core.pager", "cat"),
        ("core.symlinks", "false"),
        ("core.autocrlf", "input"),
        ("core.protecthfs", "true"),
        ("core.protectntfs", "true"),
        ("gc.auto", "0"),
        ("protocol.allow", "never"),
        ("protocol.https.allow", "always"),
        ("protocol.file.allow", "never"),
        ("protocol.ext.allow", "never"),
        ("protocol.git.allow", "never"),
        ("submodule.recurse", "false"),
        ("submodule.fetchjobs", "0"),
        ("transfer.fsckobjects", "true"),
        ("fetch.fsckobjects", "true"),
        ("receive.fsckobjects", "true"),
    ];

    let out = Command::new("git")
        .args(["config", "--global", "--list"])
        .output()
        .map_err(|e| {
            format!("GIT_HOOKS_CHECK_ERROR: failed running `git config --global --list`: {e}")
        })?;
    if !out.status.success() {
        return Err(
            "GIT_HOOKS_NOT_DISABLED: `git config --global --list` failed or global ~/.gitconfig is missing"
                .to_string(),
        );
    }

    let raw = String::from_utf8_lossy(&out.stdout);
    let mut actual = BTreeMap::new();
    for line in raw.lines() {
        if let Some((k, v)) = line.split_once('=') {
            actual.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    for &(key, expected) in REQUIRED_GLOBAL_GIT_SETTINGS {
        let got = actual.get(key).map(String::as_str).unwrap_or("");
        if got != expected {
            let err_code = if key == "core.hookspath" {
                "GIT_HOOKS_NOT_DISABLED"
            } else {
                "GIT_HARDENING_MISSING"
            };
            return Err(format!(
                "{err_code}: global git '{key}' is '{}', expected '{expected}'",
                if got.is_empty() { "<unset>" } else { got }
            ));
        }
    }
    Ok(())
}

/// Audits a repository root (depth <= 2, zero snooping in cache/tmp/deps) for:
/// - Active `.git/hooks` scripts or missing global `core.hooksPath=/dev/null` (+ all 19 hardened keys)
/// - Dangerous `.git/config`, `.gitattributes`, `.cargo/config*`, `.yarnrc*`, or `.npmrc` RCE directives
/// - Mandatory non-symlink root `AGENTS.md` + zero shadow/nested agent instruction files
/// - Unicode smuggling inside root `AGENTS.md`
pub fn audit_repository(repo_root: &Path) -> Result<Vec<String>, Vec<String>> {
    let mut checks_ok = Vec::new();
    let mut failures = Vec::new();

    // 0. Fail-closed check that all 19 global git hardening settings are active
    match verify_global_git_hardening() {
        Ok(()) => checks_ok.push(
            "Verified all 19 global git hardening keys (core.hooksPath=/dev/null, protocol lockdown, fsckObjects)"
                .to_string(),
        ),
        Err(msg) => failures.push(msg),
    }

    // 1. Inspect `.git/config` and `.git/hooks` (no-symlink, bounded, catches local hooksPath/attributesFile/!alias)
    match inspect_repo_git_config_and_hooks(repo_root) {
        Ok(()) => checks_ok.push(
            "Inspected .git/config and .git/hooks for local hooksPath/attributesFile/alias/RCE directives"
                .to_string(),
        ),
        Err(cv) => failures.push(format!("{}: {}", cv.code, cv.detail)),
    }

    // 2. Inspect `.cargo/config*`, `.yarnrc*`, `.npmrc`, and `.gitattributes` for build/filter execution traps
    let build_traps = inspect_repo_build_config_traps(repo_root);
    if build_traps.is_empty() {
        checks_ok.push(
            "Verified zero build-tool (.cargo/config*, .yarnrc*, .npmrc) or .gitattributes execution traps"
                .to_string(),
        );
    } else {
        failures.extend(build_traps);
    }

    // 3. Require canonical root `AGENTS.md` as a regular non-symlink file inside the repository
    let root_agents = repo_root.join("AGENTS.md");
    let mut root_agents_sha256: Option<String> = None;
    match fs::symlink_metadata(&root_agents) {
        Err(_) => {
            failures.push(format!(
                "MISSING_ROOT_AGENTS_MD: mandatory canonical authority '{}' is missing",
                root_agents.display()
            ));
        }
        Ok(meta) if meta.file_type().is_symlink() || !meta.file_type().is_file() => {
            failures.push(format!(
                "SYMLINKED_ROOT_AGENTS_MD: '{}' must be a regular file inside the repository, not a symlink",
                root_agents.display()
            ));
        }
        Ok(_) => match fs::read_to_string(&root_agents) {
            Ok(body) => {
                let uni = scan_unicode(&body, ScanMode::UntrustedContent);
                if let Some(first) = uni.first() {
                    failures.push(format!(
                        "ROOT_AGENTS_UNICODE: '{}' failed Unicode check: {}",
                        root_agents.display(),
                        first.detail
                    ));
                } else if body.len() > 16_384 {
                    failures.push(format!(
                        "ROOT_AGENTS_OVERSIZED: '{}' is {} bytes (> 16 KiB authority ceiling)",
                        root_agents.display(),
                        body.len()
                    ));
                } else {
                    root_agents_sha256 = Some(crypto::sha256_hex(body.as_bytes()));
                    checks_ok.push("Verified root AGENTS.md integrity & clean Unicode".to_string());
                }
            }
            Err(e) => failures.push(format!("Cannot read root AGENTS.md: {e}")),
        },
    }

    // 4. Walk up to depth 2 (skipping .git, target, build, node_modules, caches, tmp) to detect rogue instruction files
    let pinned_dist = load_pinned_dist_hashes(repo_root);
    audit_dir_depth_bounded(
        repo_root,
        repo_root,
        0,
        &pinned_dist,
        root_agents_sha256.as_deref(),
        &mut failures,
    );
    checks_ok
        .push("Scanned depth <= 2 for unauthorized shadow/nested instruction files".to_string());

    // 5. Audit `.github/workflows/` against chained workflow triggers and dispatch loops
    let wf_failures_before = failures.len();
    audit_github_workflows(repo_root, &mut failures);
    if failures.len() == wf_failures_before {
        checks_ok.push(
            "Verified .github/workflows contains zero chained triggers (workflow_run/workflow_call/repository_dispatch/gh workflow run)"
                .to_string(),
        );
    }

    if failures.is_empty() {
        Ok(checks_ok)
    } else {
        Err(failures)
    }
}

/// Audits `.github/workflows/*.{yml,yaml}` to reject chained GitHub Actions triggers
/// (`workflow_run`, `workflow_call`, `repository_dispatch`), reusable workflow calls
/// (`uses: .../.github/workflows/...`), and CLI/API workflow dispatch loops (`gh workflow run`, `/dispatches`).
pub fn audit_github_workflows(repo_root: &Path, failures: &mut Vec<String>) {
    let dot_github = repo_root.join(".github");
    match fs::symlink_metadata(&dot_github) {
        Err(_) => return,
        Ok(meta) if meta.file_type().is_symlink() => {
            failures
                .push("WORKFLOW_SYMLINK_FORBIDDEN: '.github' must not be a symlink.".to_string());
            return;
        }
        Ok(meta) if !meta.file_type().is_dir() => return,
        Ok(_) => {}
    }

    let wf_dir = dot_github.join("workflows");
    match fs::symlink_metadata(&wf_dir) {
        Err(_) => return,
        Ok(meta) if meta.file_type().is_symlink() => {
            failures.push(
                "WORKFLOW_SYMLINK_FORBIDDEN: '.github/workflows' must not be a symlink."
                    .to_string(),
            );
            return;
        }
        Ok(meta) if !meta.file_type().is_dir() => return,
        Ok(_) => {}
    }

    let entries = match fs::read_dir(&wf_dir) {
        Ok(it) => it,
        Err(e) => {
            failures.push(format!(
                "WORKFLOW_READ_DIR_ERROR: failed reading '{}': {e}",
                wf_dir.display()
            ));
            return;
        }
    };

    let mut paths = Vec::new();
    for entry_res in entries {
        match entry_res {
            Ok(ent) => paths.push(ent.path()),
            Err(e) => failures.push(format!(
                "WORKFLOW_DIR_ENTRY_ERROR: failed reading entry in '{}': {e}",
                wf_dir.display()
            )),
        }
    }
    paths.sort();

    for path in paths {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let rel = format!(".github/workflows/{name}");
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                failures.push(format!(
                    "WORKFLOW_METADATA_ERROR: failed stat on '{rel}': {e}"
                ));
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            failures.push(format!(
                "WORKFLOW_SYMLINK_FORBIDDEN: workflow file '{rel}' must not be a symlink."
            ));
            continue;
        }
        if !meta.file_type().is_file() {
            continue;
        }
        let lower_name = name.to_ascii_lowercase();
        if !(lower_name.ends_with(".yml") || lower_name.ends_with(".yaml")) {
            continue;
        }
        let body = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                failures.push(format!("WORKFLOW_READ_ERROR: failed reading '{rel}': {e}"));
                continue;
            }
        };
        for (idx, raw_line) in body.lines().enumerate() {
            let ln = idx + 1;
            let stripped = strip_yaml_comment(raw_line);
            let trimmed = stripped.trim();
            if trimmed.is_empty() {
                continue;
            }
            let lower = trimmed.to_ascii_lowercase();
            for forbidden_trigger in ["workflow_run", "workflow_call", "repository_dispatch"] {
                if contains_yaml_identifier(&lower, forbidden_trigger) {
                    failures.push(format!(
                        "CHAINED_WORKFLOW_TRIGGER_FORBIDDEN: '{rel}' line {ln} uses forbidden chained GitHub Actions trigger '{forbidden_trigger}'."
                    ));
                }
            }
            let collapsed = lower.split_whitespace().collect::<Vec<_>>().join(" ");
            if collapsed.contains("gh workflow run") {
                failures.push(format!(
                    "CHAINED_WORKFLOW_DISPATCH_FORBIDDEN: '{rel}' line {ln} invokes forbidden 'gh workflow run'."
                ));
            }
            if lower.contains("/dispatches") {
                failures.push(format!(
                    "CHAINED_WORKFLOW_DISPATCH_FORBIDDEN: '{rel}' line {ln} invokes forbidden GitHub '/dispatches' endpoint."
                ));
            }
            if (lower.starts_with("uses:") || lower.starts_with("- uses:"))
                && lower.contains(".github/workflows/")
            {
                failures.push(format!(
                    "CHAINED_WORKFLOW_CALL_FORBIDDEN: '{rel}' line {ln} chains into another workflow via 'uses:'."
                ));
            }
        }
    }
}

fn strip_yaml_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut prev_backslash = false;
    for (idx, ch) in line.char_indices() {
        if in_double {
            if ch == '"' && !prev_backslash {
                in_double = false;
            }
            prev_backslash = ch == '\\' && !prev_backslash;
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            continue;
        }
        match ch {
            '\'' => in_single = true,
            '"' => in_double = true,
            '#' if idx == 0 || line[..idx].ends_with(char::is_whitespace) => {
                return &line[..idx];
            }
            _ => {}
        }
    }
    line
}

fn contains_yaml_identifier(haystack_lower: &str, ident: &str) -> bool {
    let bytes = haystack_lower.as_bytes();
    let needle = ident.as_bytes();
    if needle.is_empty() || bytes.len() < needle.len() {
        return false;
    }
    let is_ident_byte = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    let mut pos = 0;
    while pos + needle.len() <= bytes.len() {
        if &bytes[pos..pos + needle.len()] == needle {
            let left_ok = pos == 0 || !is_ident_byte(bytes[pos - 1]);
            let right_pos = pos + needle.len();
            let right_ok = right_pos == bytes.len() || !is_ident_byte(bytes[right_pos]);
            if left_ok && right_ok {
                return true;
            }
        }
        pos += 1;
    }
    false
}

fn load_pinned_dist_hashes(repo_root: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let manifest_path = repo_root.join("dist-verify").join("manifest.sha256");
    let Ok(meta) = fs::symlink_metadata(&manifest_path) else {
        return map;
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return map;
    }
    let Ok(raw) = fs::read_to_string(manifest_path) else {
        return map;
    };
    for line in raw.lines() {
        if let Some((hash, rel)) = line.split_once("  ") {
            let h = hash.trim();
            let r = rel.trim();
            if h.len() == 64 && matches!(r, "dist/AGENTS.md" | "dist/gemini/GEMINI.md") {
                map.insert(r.to_string(), h.to_string());
            }
        }
    }
    map
}

fn is_canonical_dist_authority_artifact(
    rel: &str,
    full_path: &Path,
    pinned_dist: &BTreeMap<String, String>,
    root_agents_sha256: Option<&str>,
) -> bool {
    let Some(manifest_hash) = pinned_dist.get(rel) else {
        return false;
    };
    let Ok(bytes) = fs::read(full_path) else {
        return false;
    };
    let actual_hash = crypto::sha256_hex(&bytes);
    if actual_hash != *manifest_hash {
        return false;
    }
    match rel {
        "dist/AGENTS.md" => root_agents_sha256.is_some_and(|root_h| actual_hash == root_h),
        "dist/gemini/GEMINI.md" => actual_hash == CANONICAL_DIST_GEMINI_SHA256,
        _ => false,
    }
}

fn audit_dir_depth_bounded(
    repo_root: &Path,
    dir: &Path,
    depth: usize,
    pinned_dist: &BTreeMap<String, String>,
    root_agents_sha256: Option<&str>,
    failures: &mut Vec<String>,
) {
    if depth > MAX_DIRECTORY_WALK_DEPTH {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(it) => it,
        Err(e) => {
            failures.push(format!(
                "AUDIT_READ_DIR_ERROR: failed to read directory '{}' during repository audit: {e}",
                dir.display()
            ));
            return;
        }
    };
    for entry_res in entries {
        let entry = match entry_res {
            Ok(ent) => ent,
            Err(e) => {
                failures.push(format!(
                    "AUDIT_DIR_ENTRY_ERROR: failed reading entry inside '{}': {e}",
                    dir.display()
                ));
                continue;
            }
        };
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let lower = name_str.to_ascii_lowercase();

        // Never descend into .git, build outputs, caches, tmp, or dependencies!
        if matches!(
            lower.as_str(),
            ".git"
                | "target"
                | "build"
                | "dist-build"
                | "node_modules"
                | "vendor"
                | ".venv"
                | "venv"
                | ".cache"
                | "__pycache__"
                | "tmp"
                | ".tmp"
        ) {
            continue;
        }

        let full = entry.path();
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(e) => {
                failures.push(format!(
                    "AUDIT_FILE_TYPE_ERROR: failed inspecting '{}' file type: {e}",
                    full.display()
                ));
                continue;
            }
        };
        if ft.is_symlink() {
            if let Err(pv) = validate_path(
                repo_root,
                repo_root,
                &full.to_string_lossy(),
                PathAccess::ReferencePointer,
            ) {
                failures.push(format!(
                    "SUSPICIOUS_SYMLINK: '{}' -> {}",
                    full.display(),
                    pv.detail
                ));
            }
            continue;
        }
        if ft.is_file() {
            let rel = full
                .strip_prefix(repo_root)
                .unwrap_or(&full)
                .to_string_lossy()
                .replace('\\', "/");
            if let Err(pv) = validate_path(repo_root, repo_root, &rel, PathAccess::ReferencePointer)
                && pv.code == "UNAUTHORIZED_INSTRUCTION_FILE"
                && !is_canonical_dist_authority_artifact(
                    &rel,
                    &full,
                    pinned_dist,
                    root_agents_sha256,
                )
            {
                failures.push(format!("ROGUE_AUTHORITY_FILE: {}", pv.detail));
            }
        } else if ft.is_dir() && depth < MAX_DIRECTORY_WALK_DEPTH {
            audit_dir_depth_bounded(
                repo_root,
                &full,
                depth + 1,
                pinned_dist,
                root_agents_sha256,
                failures,
            );
        }
    }
}
