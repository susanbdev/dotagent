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

    // 6. Enforce dotagent v2.2 anti-shim, fail-closed runtime, and polyglot golden-vector laws
    let v22_failures_before = failures.len();
    audit_anti_shim_and_polyglot_laws(repo_root, &mut failures);
    if failures.len() == v22_failures_before {
        checks_ok.push(
            "Verified v2.2 anti-shim (NO_UNLINKED_RUNTIME_SHIM), fail-closed (NO_FAIL_OPEN_FALLBACK), and polyglot vector (POLYGLOT_GOLDEN_VECTORS) laws"
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

const MAX_HOST_GLUE_LINES: usize = 150;
const WASM_MAGIC_V1: &[u8; 8] = b"\0asm\x01\x00\x00\x00";
const NEEDLE_CLEAN_TRUE_SP: &str = concat!("clean:", " true");
const NEEDLE_CLEAN_TRUE_NOSP: &str = concat!("clean:", "true");
const NEEDLE_RESTORED_TRUE_SP: &str = concat!("restored:", " true");
const NEEDLE_RESTORED_TRUE_NOSP: &str = concat!("restored:", "true");
const NEEDLE_BACKUP_ADAPTER: &str = concat!("class ", "BackupAdapter");
const NEEDLE_AIRGAP_ADAPTER: &str = concat!("class ", "AirgapAdapter");
const NEEDLE_RECOVERY_ADAPTER: &str = concat!("class ", "RecoveryAdapter");
const NEEDLE_SYNTHETIC_FAKE: &str = concat!("synthetic ", "fake");
const NEEDLE_NO_CONTAINER: &str = concat!("!ctx.", "container");
const NEEDLE_DASH_BIN: &str = concat!("\"/bin/", "dash\"");
const NEEDLE_DASH_CMD: &str = concat!("Command::new(\"", "dash\")");
const NEEDLE_RFC8032_TEST_KEY: &str = concat!("d75a9801", "82b10ab7");
const NEEDLE_SQLITE3_CLI: &str = concat!("Command::new(\"", "sqlite3\")");

pub fn verify_anti_shim_and_polyglot_laws(repo_root: &Path) -> Result<(), String> {
    let mut failures = Vec::new();
    audit_anti_shim_and_polyglot_laws(repo_root, &mut failures);
    if let Some(first) = failures.first() {
        return Err(first.clone());
    }
    Ok(())
}

pub fn audit_anti_shim_and_polyglot_laws(repo_root: &Path, failures: &mut Vec<String>) {
    let has_cargo_toml = is_regular_nonsymlink_file(&repo_root.join("Cargo.toml"));
    let wrangler_configs = collect_root_wrangler_configs(repo_root);
    let has_tf = repo_has_opentofu_files(repo_root);
    let has_containerfile = repo_has_containerfile(repo_root);
    let deploy_py = repo_root.join("scripts").join("deploy.py");
    let has_deploy_py = fs::symlink_metadata(&deploy_py).is_ok();

    // 1. Imperative scripts/deploy.py forbidden where OpenTofu (.tf) modules exist
    if has_tf && has_deploy_py {
        failures.push(
            "NO_UNLINKED_RUNTIME_SHIM: imperative 'scripts/deploy.py' REST provisioner is forbidden where OpenTofu (.tf) modules exist; execute 'tofu plan'/'tofu apply' instead.".to_string(),
        );
    }
    if has_tf {
        audit_tf_deploy_workflows(repo_root, failures);
    }

    // 2. Cargo + Wrangler repositories must link compiled wasm32-unknown-unknown artifacts with <= 150 SLOC glue
    if has_cargo_toml && !wrangler_configs.is_empty() {
        let has_wasm_crate = workspace_declares_wasm_cdylib(repo_root);
        if !has_wasm_crate {
            failures.push(
                "NO_UNLINKED_RUNTIME_SHIM: repository contains Cargo.toml alongside wrangler config, but no workspace crate declares `cdylib` for wasm32-unknown-unknown linkage.".to_string(),
            );
        }
        if has_deploy_py && let Ok(py_text) = fs::read_to_string(&deploy_py) {
            let py_lines = py_text.lines().count();
            if py_lines > MAX_HOST_GLUE_LINES || py_text.contains("-shim.mjs") {
                failures.push(format!(
                    "NO_UNLINKED_RUNTIME_SHIM: 'scripts/deploy.py' ({py_lines} lines) exceeds {MAX_HOST_GLUE_LINES}-line glue cap or bundles unlinked JS shims."
                ));
            }
        }
        for (cfg_name, cfg_path) in &wrangler_configs {
            audit_wrangler_wasm_linkage(repo_root, cfg_name, cfg_path, failures);
        }
    }

    // 3. Cargo + Containerfile repositories must not use dash substring stubs in primitives/dotagent or RFC 8032 test keys
    if has_cargo_toml && has_containerfile {
        audit_container_runtime_attestation(repo_root, failures);
    }

    // 4. Scan bounded non-test source files for > 150 SLOC .js/.mjs/.cjs shims and NO_FAIL_OPEN_FALLBACK violations
    let mut source_files = Vec::new();
    collect_bounded_source_files(repo_root, repo_root, 0, &mut source_files);
    let is_worker_cargo_repo = has_cargo_toml && !wrangler_configs.is_empty();
    for (rel, full) in &source_files {
        if is_test_rel_path(rel) {
            continue;
        }
        let Ok(raw) = fs::read_to_string(full) else {
            continue;
        };
        if rel.ends_with(".mjs") || rel.ends_with(".js") || rel.ends_with(".cjs") {
            let line_count = raw.lines().count();
            if line_count > MAX_HOST_GLUE_LINES {
                failures.push(format!(
                    "NO_UNLINKED_RUNTIME_SHIM: '{rel}' is {line_count} lines (> {MAX_HOST_GLUE_LINES} SLOC JS/MJS/CJS ceiling)."
                ));
            }
        }
        audit_fail_open_patterns(rel, &raw, is_worker_cargo_repo, failures);
    }

    // 5. Enforce POLYGLOT_GOLDEN_VECTORS when TargetEmitter or 4-language packages exist
    audit_polyglot_golden_vectors(repo_root, failures);
}

fn is_regular_nonsymlink_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| !m.file_type().is_symlink() && m.file_type().is_file())
}

fn is_regular_nonsymlink_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| !m.file_type().is_symlink() && m.file_type().is_dir())
}

fn collect_root_wrangler_configs(repo_root: &Path) -> Vec<(String, std::path::PathBuf)> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(repo_root) else {
        return out;
    };
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        if name.starts_with("wrangler")
            && (name.ends_with(".toml") || name.ends_with(".json") || name.ends_with(".jsonc"))
            && is_regular_nonsymlink_file(&ent.path())
        {
            out.push((name, ent.path()));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn repo_has_opentofu_files(repo_root: &Path) -> bool {
    has_extension_bounded(repo_root, "tf", 2)
}

fn repo_has_containerfile(repo_root: &Path) -> bool {
    if is_regular_nonsymlink_file(&repo_root.join("Containerfile"))
        || is_regular_nonsymlink_file(&repo_root.join("Dockerfile"))
    {
        return true;
    }
    for sub in ["profiles", "primitives", "images"] {
        let sub_dir = repo_root.join(sub);
        if is_regular_nonsymlink_dir(&sub_dir)
            && let Ok(rd) = fs::read_dir(&sub_dir)
        {
            for ent in rd.flatten() {
                let p = ent.path();
                if is_regular_nonsymlink_dir(&p)
                    && (is_regular_nonsymlink_file(&p.join("Containerfile"))
                        || is_regular_nonsymlink_file(&p.join("Dockerfile")))
                {
                    return true;
                }
            }
        }
    }
    false
}

fn has_extension_bounded(dir: &Path, ext: &str, max_depth: usize) -> bool {
    let Ok(rd) = fs::read_dir(dir) else {
        return false;
    };
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            ".git" | "target" | "node_modules" | "vendor" | ".venv" | ".cache" | "tmp" | ".tmp"
        ) {
            continue;
        }
        let p = ent.path();
        let Ok(ft) = ent.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_file() && p.extension().and_then(|e| e.to_str()) == Some(ext) {
            return true;
        }
        if ft.is_dir() && max_depth > 0 && has_extension_bounded(&p, ext, max_depth - 1) {
            return true;
        }
    }
    false
}

fn audit_tf_deploy_workflows(repo_root: &Path, failures: &mut Vec<String>) {
    let wf_dir = repo_root.join(".github").join("workflows");
    if !is_regular_nonsymlink_dir(&wf_dir) {
        return;
    }
    let Ok(rd) = fs::read_dir(&wf_dir) else {
        return;
    };
    for ent in rd.flatten() {
        let p = ent.path();
        if !is_regular_nonsymlink_file(&p) {
            continue;
        }
        let name = ent.file_name().to_string_lossy().into_owned();
        if !(name.ends_with(".yml") || name.ends_with(".yaml")) {
            continue;
        }
        let Ok(body) = fs::read_to_string(&p) else {
            continue;
        };
        if body.contains("deploy.py") {
            failures.push(format!(
                "NO_UNLINKED_RUNTIME_SHIM: '.github/workflows/{name}' invokes imperative 'deploy.py' instead of OpenTofu ('tofu plan'/'tofu apply')."
            ));
        }
    }
}

fn workspace_declares_wasm_cdylib(repo_root: &Path) -> bool {
    let mut manifests = vec![repo_root.join("Cargo.toml")];
    for container in ["crates", "worker", "workers"] {
        let dir = repo_root.join(container);
        if is_regular_nonsymlink_dir(&dir)
            && let Ok(rd) = fs::read_dir(&dir)
        {
            for ent in rd.flatten() {
                let p = ent.path();
                if is_regular_nonsymlink_file(&p)
                    && ent.file_name().to_string_lossy() == "Cargo.toml"
                {
                    manifests.push(p);
                } else if is_regular_nonsymlink_dir(&p) {
                    let sub_manifest = p.join("Cargo.toml");
                    if is_regular_nonsymlink_file(&sub_manifest) {
                        manifests.push(sub_manifest);
                    }
                }
            }
        }
    }
    for m in manifests {
        if let Ok(raw) = fs::read_to_string(&m)
            && (raw.contains("\"cdylib\"") || raw.contains("'cdylib'"))
        {
            return true;
        }
    }
    false
}

fn extract_wrangler_main_field(cfg_name: &str, text: &str) -> Option<String> {
    if cfg_name.ends_with(".toml") {
        for raw_line in text.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if let Some((k, v)) = line.split_once('=')
                && k.trim() == "main"
            {
                let clean = v.trim().trim_matches('"').trim_matches('\'').trim();
                if !clean.is_empty() {
                    return Some(clean.to_string());
                }
            }
        }
        return None;
    }
    let stripped = crate::stop_receipt::strip_code_comments_preserve_lines(text, false);
    let parsed = crate::json::JsonValue::parse(&stripped).ok()?;
    parsed
        .get("main")
        .and_then(crate::json::JsonValue::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

fn collect_wasm_module_refs(text: &str, base_dir: &str) -> Vec<String> {
    let mut refs = Vec::new();
    for delim in ['"', '\''] {
        for tok in text.split(delim).skip(1).step_by(2).map(str::trim) {
            if tok.ends_with(".wasm") && !tok.contains("://") && !tok.starts_with('/') {
                let Some(joined) = resolve_rel_import(base_dir, tok) else {
                    continue;
                };
                if !refs.contains(&joined) {
                    refs.push(joined);
                }
            }
        }
    }
    refs
}

fn resolve_rel_import(base_dir: &str, raw_rel: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for seg in base_dir.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    for seg in raw_rel.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("/"))
}

fn audit_wrangler_wasm_linkage(
    repo_root: &Path,
    cfg_name: &str,
    cfg_path: &Path,
    failures: &mut Vec<String>,
) {
    let Ok(cfg_text) = fs::read_to_string(cfg_path) else {
        failures.push(format!(
            "NO_UNLINKED_RUNTIME_SHIM: failed reading '{cfg_name}'."
        ));
        return;
    };
    let Some(main_rel) = extract_wrangler_main_field(cfg_name, &cfg_text) else {
        failures.push(format!(
            "NO_UNLINKED_RUNTIME_SHIM: '{cfg_name}' is missing a `main` entrypoint."
        ));
        return;
    };
    let Some(clean_main) = resolve_rel_import("", &main_rel) else {
        failures.push(format!(
            "NO_UNLINKED_RUNTIME_SHIM: '{cfg_name}' main '{main_rel}' escapes repository root."
        ));
        return;
    };
    let main_path = repo_root.join(&clean_main);
    if !is_regular_nonsymlink_file(&main_path) {
        failures.push(format!(
            "NO_UNLINKED_RUNTIME_SHIM: '{cfg_name}' main '{clean_main}' does not exist as a regular file."
        ));
        return;
    }
    let Ok(main_text) = fs::read_to_string(&main_path) else {
        failures.push(format!(
            "NO_UNLINKED_RUNTIME_SHIM: failed reading '{clean_main}'."
        ));
        return;
    };
    let main_lines = main_text.lines().count();
    if main_lines > MAX_HOST_GLUE_LINES {
        failures.push(format!(
            "NO_UNLINKED_RUNTIME_SHIM: '{clean_main}' referenced by '{cfg_name}' is {main_lines} lines (> {MAX_HOST_GLUE_LINES}-line host FFI cap)."
        ));
    }
    let base_dir = Path::new(&clean_main)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut wasm_refs = collect_wasm_module_refs(&cfg_text, "");
    for w in collect_wasm_module_refs(&main_text, &base_dir) {
        if !wasm_refs.contains(&w) {
            wasm_refs.push(w);
        }
    }
    if wasm_refs.is_empty() {
        failures.push(format!(
            "NO_UNLINKED_RUNTIME_SHIM: '{cfg_name}' ('{clean_main}') in Rust workspace does not import any compiled .wasm artifact."
        ));
        return;
    }
    for w_rel in &wasm_refs {
        let w_path = repo_root.join(w_rel);
        if let Ok(meta) = fs::symlink_metadata(&w_path) {
            if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                failures.push(format!(
                    "NO_UNLINKED_RUNTIME_SHIM: '{w_rel}' must be a regular non-symlink .wasm file."
                ));
            } else if let Ok(bytes) = fs::read(&w_path)
                && !bytes.starts_with(WASM_MAGIC_V1)
            {
                failures.push(format!(
                    "NO_UNLINKED_RUNTIME_SHIM: '{w_rel}' lacks valid Wasm v1 magic header."
                ));
            }
        }
    }
}

fn audit_container_runtime_attestation(repo_root: &Path, failures: &mut Vec<String>) {
    let prim_dotagent = repo_root.join("primitives").join("dotagent");
    if is_regular_nonsymlink_dir(&prim_dotagent)
        && let Ok(rd) = fs::read_dir(&prim_dotagent)
    {
        for ent in rd.flatten() {
            let p = ent.path();
            if is_regular_nonsymlink_file(&p)
                && p.extension().and_then(|e| e.to_str()) == Some("rs")
                && let Ok(body) = fs::read_to_string(&p)
            {
                let stripped =
                    crate::stop_receipt::strip_code_comments_preserve_lines(&body, false);
                if stripped.contains(NEEDLE_DASH_BIN) || stripped.contains(NEEDLE_DASH_CMD) {
                    let fname = ent.file_name().to_string_lossy().into_owned();
                    failures.push(format!(
                        "NO_UNLINKED_RUNTIME_SHIM: 'primitives/dotagent/{fname}' delegates to a dash shell stub instead of attested dotagent binaries."
                    ));
                }
            }
        }
    }
    let manifests_dir = repo_root.join("manifests");
    if is_regular_nonsymlink_dir(&manifests_dir)
        && let Ok(rd) = fs::read_dir(&manifests_dir)
    {
        for ent in rd.flatten() {
            let p = ent.path();
            if is_regular_nonsymlink_file(&p)
                && p.extension().and_then(|e| e.to_str()) == Some("json")
                && let Ok(body) = fs::read_to_string(&p)
                && body.to_ascii_lowercase().contains(NEEDLE_RFC8032_TEST_KEY)
            {
                let fname = ent.file_name().to_string_lossy().into_owned();
                failures.push(format!(
                    "NO_UNLINKED_RUNTIME_SHIM: 'manifests/{fname}' pins RFC 8032 test-vector Ed25519 key d75a9801... instead of production Root/Vault key."
                ));
            }
        }
    }
}

fn collect_bounded_source_files(
    repo_root: &Path,
    dir: &Path,
    depth: usize,
    out: &mut Vec<(String, std::path::PathBuf)>,
) {
    if depth > 4 || out.len() >= 1024 {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for ent in entries {
        if out.len() >= 1024 {
            return;
        }
        let name = ent.file_name().to_string_lossy().into_owned();
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            ".git"
                | "target"
                | "build"
                | "dist"
                | "dist-verify"
                | "dist-build"
                | "node_modules"
                | "vendor"
                | ".venv"
                | "venv"
                | ".cache"
                | "__pycache__"
                | "tmp"
                | ".tmp"
                | "shared"
        ) {
            continue;
        }
        let Ok(ft) = ent.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        let full = ent.path();
        if ft.is_file() {
            let Some(ext) = full.extension().and_then(|e| e.to_str()) else {
                continue;
            };
            if matches!(ext, "rs" | "mjs" | "js" | "cjs" | "ts" | "tsx")
                && full.metadata().is_ok_and(|m| m.len() <= 1_048_576)
            {
                let rel = full
                    .strip_prefix(repo_root)
                    .unwrap_or(&full)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, full));
            }
        } else if ft.is_dir() && depth < 4 {
            collect_bounded_source_files(repo_root, &full, depth + 1, out);
        }
    }
}

fn is_test_rel_path(rel: &str) -> bool {
    let fname = rel.rsplit('/').next().unwrap_or(rel);
    rel.starts_with("tests/")
        || rel.contains("/tests/")
        || rel.starts_with("test/")
        || rel.contains("/test/")
        || rel.starts_with("__tests__/")
        || rel.contains("/__tests__/")
        || rel.starts_with("bench/")
        || rel.contains("/bench/")
        || fname.ends_with("_test.rs")
        || fname.ends_with("_tests.rs")
        || fname.ends_with("_test.js")
        || fname.ends_with("_test.mjs")
        || fname.ends_with("_test.cjs")
        || fname.contains(".test.")
        || fname.contains(".spec.")
}

fn audit_fail_open_patterns(
    rel: &str,
    raw: &str,
    is_worker_cargo_repo: bool,
    failures: &mut Vec<String>,
) {
    let prod_slice = if rel.ends_with(".rs") {
        raw.split("\n#[cfg(test)]").next().unwrap_or(raw)
    } else {
        raw
    };
    let stripped = crate::stop_receipt::strip_code_comments_preserve_lines(prod_slice, false);

    if stripped.contains(NEEDLE_BACKUP_ADAPTER)
        || stripped.contains(NEEDLE_AIRGAP_ADAPTER)
        || stripped.contains(NEEDLE_RECOVERY_ADAPTER)
        || stripped.contains(NEEDLE_SYNTHETIC_FAKE)
        || stripped.contains(NEEDLE_NO_CONTAINER)
    {
        failures.push(format!(
            "NO_FAIL_OPEN_FALLBACK: '{rel}' contains synthetic container fallback adapter in production code."
        ));
    }

    // Detect catch (...) blocks returning clean: true or restored: true
    let lines: Vec<&str> = stripped.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        if line.contains("catch") {
            let window_end = (idx + 12).min(lines.len());
            let window = lines[idx..window_end].join(" ");
            if window.contains(NEEDLE_CLEAN_TRUE_SP)
                || window.contains(NEEDLE_CLEAN_TRUE_NOSP)
                || window.contains(NEEDLE_RESTORED_TRUE_SP)
                || window.contains(NEEDLE_RESTORED_TRUE_NOSP)
            {
                failures.push(format!(
                    "NO_FAIL_OPEN_FALLBACK: '{rel}:{}' contains fail-open catch block returning clean/restored=true.",
                    idx + 1
                ));
                break;
            }
        }
    }

    if is_worker_cargo_repo && rel.ends_with(".rs") && stripped.contains(NEEDLE_SQLITE3_CLI) {
        failures.push(format!(
            "NO_FAIL_OPEN_FALLBACK: '{rel}' spawns host `sqlite3` CLI inside a Cloudflare Worker repository instead of using Wasm/DO storage."
        ));
    }
}

fn audit_polyglot_golden_vectors(repo_root: &Path, failures: &mut Vec<String>) {
    let has_target_compiler = is_regular_nonsymlink_dir(&repo_root.join("compiler").join("target"));
    let has_four_packages = is_regular_nonsymlink_dir(&repo_root.join("packages").join("rust"))
        && is_regular_nonsymlink_dir(&repo_root.join("packages").join("ts"))
        && is_regular_nonsymlink_dir(&repo_root.join("packages").join("python"))
        && is_regular_nonsymlink_dir(&repo_root.join("packages").join("c"));
    if !has_target_compiler && !has_four_packages {
        return;
    }

    let vectors_dir = repo_root.join("vectors");
    if !is_regular_nonsymlink_dir(&vectors_dir) {
        failures.push(
            "POLYGLOT_GOLDEN_VECTORS: polyglot contract repository is missing shared 'vectors/' directory.".to_string(),
        );
        return;
    }

    let mut json_vector_count = 0usize;
    if let Ok(rd) = fs::read_dir(&vectors_dir) {
        for ent in rd.flatten() {
            let p = ent.path();
            if is_regular_nonsymlink_file(&p)
                && p.extension().and_then(|e| e.to_str()) == Some("json")
                && let Ok(body) = fs::read_to_string(&p)
                && crate::json::JsonValue::parse(&body).is_ok()
            {
                json_vector_count += 1;
            }
        }
    }
    if json_vector_count == 0 {
        failures.push(
            "POLYGLOT_GOLDEN_VECTORS: 'vectors/' contains zero valid '*.json' golden vector files."
                .to_string(),
        );
    }

    for (lang, sub_dir) in [
        ("Rust", "packages/rust"),
        ("TypeScript", "packages/ts"),
        ("Python", "packages/python"),
        ("C11", "packages/c"),
    ] {
        let dir = repo_root.join(sub_dir);
        if !dir_references_vectors(&dir, 0) {
            failures.push(format!(
                "POLYGLOT_GOLDEN_VECTORS: {lang} package ('{sub_dir}') lacks golden-vector round-trip tests referencing 'vectors/'."
            ));
        }
    }
}

fn dir_references_vectors(dir: &Path, depth: usize) -> bool {
    if depth > 3 || !is_regular_nonsymlink_dir(dir) {
        return false;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return false;
    };
    for ent in rd.flatten() {
        let p = ent.path();
        let Ok(ft) = ent.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_file() {
            if let Ok(body) = fs::read_to_string(&p)
                && body.contains("vectors/")
            {
                return true;
            }
        } else if ft.is_dir() && dir_references_vectors(&p, depth + 1) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_rel_import_rejects_traversal_past_repo_root() {
        assert_eq!(
            resolve_rel_import("worker", "./svc.wasm"),
            Some("worker/svc.wasm".to_string())
        );
        assert_eq!(
            resolve_rel_import("worker", "../pkg/svc.wasm"),
            Some("pkg/svc.wasm".to_string())
        );
        assert_eq!(resolve_rel_import("worker", "../../svc.wasm"), None);
        assert_eq!(resolve_rel_import("", "../svc.wasm"), None);
        assert_eq!(resolve_rel_import("a/b", "../../../evil.wasm"), None);
    }

    #[test]
    fn test_js_paths_are_recognized_before_sloc_shim_gate() {
        assert!(is_test_rel_path("tests/e2e_suite.mjs"));
        assert!(is_test_rel_path("packages/ui/src/widget.test.js"));
        assert!(is_test_rel_path("packages/ui/__tests__/shim.cjs"));
        assert!(!is_test_rel_path("worker/runtime_shim.cjs"));
    }
}
