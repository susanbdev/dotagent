#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! Polyrepo Fleet Operations, `/opt/dotagent` Image Builder, & SLSA `self-verify` (`Pillar 5`).
//!
//! Provides:
//! - `dotagent fleet <audit|doctor|sync> --root <org_dir>`: Parallel depth-1 repository discovery,
//!   non-destructive multi-repo bundle synchronization, SHA-256 root authority drift checks, and
//!   per-repo security audit reporting.
//! - `dotagent fleet build-image --out <dir>`: Stages an immutable `/opt/dotagent` (`prim-dotagent`)
//!   filesystem layer (`0555` binaries, `0444` manifests/policies, sorted `IMAGE_MANIFEST.sha256`).
//! - `dotagent self-verify`: Verifies binary/archive SHA-256 digests against `SHA256SUMS` and
//!   SLSA v1.0 in-toto DSSE provenance statements.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::budget_guard::load_active_profile;
use crate::crypto::{
    constant_time_eq_bytes, hex_decode_32, hex_decode_bytes, sha256_bytes, sha256_hex,
};
use crate::github_governance::{COPILOT_GATE_CONTEXT, RATCHET_CHECK_RUN, dotagent_required_checks};
use crate::json::JsonValue;
use crate::{audit_repository, resolve_repo_root};

const SKIPPED_FLEET_DIRS: &[&str] = &[
    "target",
    "node_modules",
    "vendor",
    "tmp",
    "temp",
    "dist",
    "dist-verify",
    "dist-release",
    "release-out",
];

#[derive(Debug, Clone)]
pub struct FleetRepoReport {
    pub repo_name: String,
    pub repo_path: PathBuf,
    pub ok: bool,
    pub authority_synced: bool,
    pub detail: String,
}

impl FleetRepoReport {
    pub fn to_json_value(&self) -> JsonValue {
        JsonValue::Object(vec![
            ("repo".to_string(), JsonValue::Str(self.repo_name.clone())),
            (
                "path".to_string(),
                JsonValue::Str(self.repo_path.display().to_string()),
            ),
            ("ok".to_string(), JsonValue::Bool(self.ok)),
            (
                "authority_synced".to_string(),
                JsonValue::Bool(self.authority_synced),
            ),
            ("detail".to_string(), JsonValue::Str(self.detail.clone())),
        ])
    }
}

/// Discovers direct child Git repositories (`maxdepth = 1`) under `org_root`, strictly skipping
/// symlinks, hidden folders, and forbidden cache/temp/dependency directories.
pub fn discover_fleet_repositories(org_root: &Path) -> Result<Vec<PathBuf>, String> {
    let meta = fs::symlink_metadata(org_root)
        .map_err(|e| format!("cannot stat fleet root '{}': {e}", org_root.display()))?;
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Err(format!(
            "fleet root '{}' must be a regular non-symlink directory",
            org_root.display()
        ));
    }

    let mut repos = Vec::new();
    let entries = fs::read_dir(org_root)
        .map_err(|e| format!("failed reading fleet root '{}': {e}", org_root.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with('.')
            || SKIPPED_FLEET_DIRS
                .iter()
                .any(|skip| name.eq_ignore_ascii_case(skip))
        {
            continue;
        }
        let Ok(emeta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if emeta.file_type().is_symlink() || !emeta.file_type().is_dir() {
            continue;
        }
        let git_marker = path.join(".git");
        if let Ok(gmeta) = fs::symlink_metadata(&git_marker)
            && !gmeta.file_type().is_symlink()
        {
            repos.push(path);
        }
    }
    repos.sort();
    Ok(repos)
}

/// Audits all discovered repositories in `org_root` in parallel using scoped OS threads.
pub fn audit_fleet_parallel(
    org_root: &Path,
    canonical_agents_sha256: Option<&str>,
    include_profile_check: bool,
) -> Result<Vec<FleetRepoReport>, String> {
    let repos = discover_fleet_repositories(org_root)?;
    let mut results = Vec::with_capacity(repos.len());

    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(repos.len());
        for repo in repos {
            handles.push(s.spawn(move || {
                let repo_name = repo
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("<repo>")
                    .to_string();
                let agents_path = repo.join("AGENTS.md");
                let agents_nonsymlink_bytes = fs::symlink_metadata(&agents_path)
                    .ok()
                    .filter(|m| !m.file_type().is_symlink() && m.file_type().is_file())
                    .and_then(|_| fs::read(&agents_path).ok());
                let authority_synced = match (canonical_agents_sha256, agents_nonsymlink_bytes) {
                    (Some(exp), Some(bytes)) => sha256_hex(&bytes) == exp,
                    (None, Some(_)) => true,
                    _ => false,
                };

                match audit_repository(&repo) {
                    Ok(passed) => {
                        if include_profile_check {
                            if let Err(bv) = load_active_profile(&repo) {
                                return FleetRepoReport {
                                    repo_name,
                                    repo_path: repo,
                                    ok: false,
                                    authority_synced,
                                    detail: format!("profile error {}: {}", bv.code, bv.detail),
                                };
                            }
                        }
                        let ok = authority_synced || canonical_agents_sha256.is_none();
                        let detail = if ok {
                            format!(
                                "clean ({} checks, authority_synced={authority_synced})",
                                passed.len()
                            )
                        } else {
                            "AGENTS.md SHA-256 drift relative to canonical dist/AGENTS.md"
                                .to_string()
                        };
                        FleetRepoReport {
                            repo_name,
                            repo_path: repo,
                            ok,
                            authority_synced,
                            detail,
                        }
                    }
                    Err(errs) => FleetRepoReport {
                        repo_name,
                        repo_path: repo,
                        ok: false,
                        authority_synced,
                        detail: errs.join("; "),
                    },
                }
            }));
        }
        for h in handles {
            if let Ok(rep) = h.join() {
                results.push(rep);
            }
        }
    });

    results.sort_by(|a, b| a.repo_name.cmp(&b.repo_name));
    Ok(results)
}

/// Builds an immutable `/opt/dotagent` (`prim-dotagent`) filesystem layer under `stage_dir`,
/// setting `0555` on binaries/directories and `0444` on manifests/policies, plus emitting
/// `IMAGE_MANIFEST.sha256`.
pub fn build_immutable_dotagent_image(
    dotagent_root: &Path,
    bin_source_dir: Option<&Path>,
    stage_dir: &Path,
) -> Result<PathBuf, String> {
    if let Ok(meta) = fs::symlink_metadata(stage_dir) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "stage output '{}' must not be a symlink",
                stage_dir.display()
            ));
        }
        if !meta.file_type().is_dir() {
            return Err(format!(
                "stage output '{}' exists and is not a directory",
                stage_dir.display()
            ));
        }
        let mut entries = fs::read_dir(stage_dir)
            .map_err(|e| format!("failed reading stage output '{}': {e}", stage_dir.display()))?;
        if entries.next().is_some() {
            return Err(format!(
                "STAGE_DIR_NOT_EMPTY: stage output '{}' must not exist or must be an empty directory so stale files cannot escape IMAGE_MANIFEST.sha256",
                stage_dir.display()
            ));
        }
        set_mode(stage_dir, 0o755);
    }
    let stage_bin = stage_dir.join("bin");
    if let Ok(meta) = fs::symlink_metadata(&stage_bin) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "stage bin '{}' must not be a symlink",
                stage_bin.display()
            ));
        }
        if meta.file_type().is_dir() {
            set_mode(&stage_bin, 0o755);
        }
    }
    fs::create_dir_all(&stage_bin)
        .map_err(|e| format!("failed creating '{}': {e}", stage_bin.display()))?;

    let inferred_bin_dir = bin_source_dir
        .map(Path::to_path_buf)
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(Path::to_path_buf))
        })
        .unwrap_or_else(|| dotagent_root.join("target/release"));

    let mut manifest_entries: BTreeMap<String, String> = BTreeMap::new();

    for bin_name in [
        "dotagent",
        "agent-guard",
        "agent-guard-sh",
        "dotagent-compiler",
        "swarm-tool",
        "dotagent-harness",
    ] {
        let src = inferred_bin_dir.join(bin_name);
        if let Ok(meta) = fs::symlink_metadata(&src)
            && meta.file_type().is_file()
            && !meta.file_type().is_symlink()
        {
            let dst = stage_bin.join(bin_name);
            unlock_writable_if_exists(&dst)?;
            fs::copy(&src, &dst)
                .map_err(|e| format!("failed copying binary '{}': {e}", src.display()))?;
            set_mode(&dst, 0o555);
            let bytes = fs::read(&dst)
                .map_err(|e| format!("failed hashing staged binary '{}': {e}", dst.display()))?;
            manifest_entries.insert(format!("bin/{bin_name}"), sha256_hex(&bytes));
        }
    }

    for tree_name in ["dist", "profiles", "skills"] {
        let src_dir = dotagent_root.join(tree_name);
        if let Ok(smeta) = fs::symlink_metadata(&src_dir)
            && !smeta.file_type().is_symlink()
            && smeta.file_type().is_dir()
        {
            let target_tree = stage_dir.join(tree_name);
            copy_dir_bounded_depth(
                &src_dir,
                &target_tree,
                tree_name,
                0,
                4,
                &mut manifest_entries,
            )?;
            set_mode(&target_tree, 0o555);
        }
    }

    for doc in [
        "AGENTS.md",
        "README.md",
        "THREAT_MODEL.md",
        "SECURITY.md",
        "spec.md",
    ] {
        let src = dotagent_root.join(doc);
        if let Ok(smeta) = fs::symlink_metadata(&src)
            && !smeta.file_type().is_symlink()
            && smeta.file_type().is_file()
        {
            let dst = stage_dir.join(doc);
            unlock_writable_if_exists(&dst)?;
            fs::copy(&src, &dst).map_err(|e| format!("failed copying '{}': {e}", src.display()))?;
            set_mode(&dst, 0o444);
            let bytes =
                fs::read(&dst).map_err(|e| format!("failed reading '{}': {e}", dst.display()))?;
            manifest_entries.insert(doc.to_string(), sha256_hex(&bytes));
        }
    }

    let mut manifest_text = String::new();
    for (rel, sha) in &manifest_entries {
        manifest_text.push_str(&format!("{sha}  {rel}\n"));
    }
    let manifest_path = stage_dir.join("IMAGE_MANIFEST.sha256");
    unlock_writable_if_exists(&manifest_path)?;
    fs::write(&manifest_path, manifest_text.as_bytes())
        .map_err(|e| format!("failed writing IMAGE_MANIFEST.sha256: {e}"))?;
    set_mode(&manifest_path, 0o444);
    set_mode(&stage_bin, 0o555);
    set_mode(stage_dir, 0o555);
    Ok(manifest_path)
}

fn copy_dir_bounded_depth(
    src: &Path,
    dst: &Path,
    rel_prefix: &str,
    depth: usize,
    max_depth: usize,
    manifest: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    if depth > max_depth {
        return Err(format!(
            "FLEET_IMAGE_DEPTH_EXCEEDED: '{}' exceeded staging depth cap {max_depth}",
            src.display()
        ));
    }
    if let Ok(dmeta) = fs::symlink_metadata(dst) {
        if dmeta.file_type().is_symlink() {
            return Err(format!(
                "refusing symlinked staging directory '{}'",
                dst.display()
            ));
        }
        if dmeta.file_type().is_dir() {
            set_mode(dst, 0o755);
        }
    }
    fs::create_dir_all(dst).map_err(|e| format!("failed mkdir '{}': {e}", dst.display()))?;
    let entries =
        fs::read_dir(src).map_err(|e| format!("failed reading '{}': {e}", src.display()))?;
    for entry in entries.flatten() {
        let p = entry.path();
        let Ok(meta) = fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        let Some(fname) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let child_rel = format!("{rel_prefix}/{fname}");
        let target = dst.join(fname);
        if meta.file_type().is_dir() {
            copy_dir_bounded_depth(&p, &target, &child_rel, depth + 1, max_depth, manifest)?;
            set_mode(&target, 0o555);
        } else if meta.file_type().is_file() {
            unlock_writable_if_exists(&target)?;
            fs::copy(&p, &target).map_err(|e| format!("failed copying '{}': {e}", p.display()))?;
            set_mode(&target, 0o444);
            let bytes = fs::read(&target)
                .map_err(|e| format!("failed hashing '{}': {e}", target.display()))?;
            manifest.insert(child_rel, sha256_hex(&bytes));
        }
    }
    Ok(())
}

fn unlock_writable_if_exists(path: &Path) -> Result<(), String> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "SYMLINK_TAMPER_DETECTED: staged path '{}' is a symlink",
                path.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
    }
    Ok(())
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    if let Ok(meta) = fs::symlink_metadata(path)
        && !meta.file_type().is_symlink()
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

pub(crate) fn verify_operator_not_in_agent_sandbox(cmd_label: &str) -> Result<(), String> {
    for marker in crate::telemetry::AGENT_SANDBOX_AND_HARNESS_MARKERS {
        if let Ok(val) = std::env::var(marker)
            && !val.trim().is_empty()
            && val.trim() != "0"
            && !val.trim().eq_ignore_ascii_case("false")
        {
            return Err(format!(
                "FLEET_OPERATOR_ONLY: `{cmd_label}` is blocked inside AI agent / sandbox environment ('{marker}' is active)."
            ));
        }
    }
    Ok(())
}

fn trusted_git_cmd(cwd: &Path) -> Result<std::process::Command, String> {
    let git_bin = [
        "/usr/bin/git",
        "/opt/homebrew/bin/git",
        "/usr/local/bin/git",
    ]
    .into_iter()
    .map(Path::new)
    .find(|p| crate::coordinator::is_trusted_executable_file(p))
    .ok_or_else(|| {
        "no trusted system git executable found in /usr/bin, /opt/homebrew/bin, or /usr/local/bin"
            .to_string()
    })?;
    let mut cmd = std::process::Command::new(git_bin);
    cmd.current_dir(cwd)
        .env_remove("GIT_EXTERNAL_DIFF")
        .env_remove("GIT_DIFF_OPTS")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_CONFIG_PARAMETERS")
        .env_remove("GIT_CONFIG_GLOBAL")
        .env_remove("GIT_CONFIG_SYSTEM")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_0", "/dev/null")
        .env("GIT_CONFIG_KEY_1", "core.fsmonitor")
        .env("GIT_CONFIG_VALUE_1", "false");
    Ok(cmd)
}

fn verify_bundle_rollout_provenance(bundle_root: &Path) -> Result<(), String> {
    use std::process::Command;
    if let Err(errs) = audit_repository(bundle_root) {
        return Err(format!(
            "bundle repository failed audit: {}",
            errs.join("; ")
        ));
    }
    let st = trusted_git_cmd(bundle_root)?
        .args(["status", "--porcelain=v1", "-z", "-uall"])
        .output()
        .map_err(|e| format!("git status on bundle failed: {e}"))?;
    if !st.status.success() || st.stdout.iter().any(|b| *b != 0) {
        return Err(
            "bundle repository has uncommitted or untracked changes (rollout requires clean HEAD)"
                .to_string(),
        );
    }
    let head_out = trusted_git_cmd(bundle_root)?
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .map_err(|e| format!("git rev-parse HEAD failed: {e}"))?;
    let head_oid = String::from_utf8_lossy(&head_out.stdout).trim().to_string();
    if head_oid.is_empty() {
        return Err("unable to resolve bundle HEAD commit".to_string());
    }

    // 1. Accept if HEAD has an annotated tag carrying an SSH signature that verifies against the
    //    bundle's committed `config/allowed_human_signers` keyring (GPG keyrings are ignored).
    let signers_path = bundle_root.join("config/allowed_human_signers");
    let signers_ok = fs::symlink_metadata(&signers_path)
        .is_ok_and(|m| m.file_type().is_file() && !m.file_type().is_symlink());
    if signers_ok
        && let Ok(mut tag_cmd) = trusted_git_cmd(bundle_root)
        && let Ok(tags_out) = tag_cmd.args(["tag", "--points-at", "HEAD"]).output()
        && tags_out.status.success()
    {
        for tag in String::from_utf8_lossy(&tags_out.stdout)
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.starts_with('-'))
        {
            let is_ssh_signed = trusted_git_cmd(bundle_root).is_ok_and(|mut c| {
                c.args(["cat-file", "tag", tag]).output().is_ok_and(|o| {
                    o.status.success()
                        && String::from_utf8_lossy(&o.stdout)
                            .contains("-----BEGIN SSH SIGNATURE-----")
                })
            });
            if !is_ssh_signed {
                continue;
            }
            if trusted_git_cmd(bundle_root).is_ok_and(|mut c| {
                c.env("GIT_CONFIG_COUNT", "3")
                    .env("GIT_CONFIG_KEY_2", "gpg.ssh.allowedSignersFile")
                    .env("GIT_CONFIG_VALUE_2", &signers_path)
                    .args(["verify-tag", "--end-of-options", tag])
                    .output()
                    .is_ok_and(|o| o.status.success())
            }) {
                return Ok(());
            }
        }
    }

    // 2. Otherwise HEAD must already be on `susanbdev/dotagent` main (so it passed the PR-time
    //    7-check ruleset, including the Ring-0 ratchet and the Copilot gate status, which only
    //    attach to PR head commits) AND every main-push CI check-run on HEAD must be green.
    let gh = crate::feedback_loop::resolve_gh_bin();
    let cmp_ep = format!("repos/susanbdev/dotagent/compare/main...{head_oid}");
    let cmp_out = Command::new(&gh)
        .args(["api", &cmp_ep])
        .output()
        .map_err(|e| format!("gh api compare failed: {e}"))?;
    if !cmp_out.status.success() {
        return Err(format!(
            "HEAD '{head_oid}' lacks a pinned-signer tag and main ancestry could not be verified"
        ));
    }
    let cmp = JsonValue::parse(String::from_utf8_lossy(&cmp_out.stdout).trim())
        .map_err(|e| format!("invalid compare JSON: {e}"))?;
    let cmp_status = cmp.get("status").and_then(JsonValue::as_str).unwrap_or("");
    if !matches!(cmp_status, "identical" | "behind") {
        return Err(format!(
            "HEAD '{head_oid}' is not contained in susanbdev/dotagent main (compare status '{cmp_status}')"
        ));
    }

    let ep = format!("repos/susanbdev/dotagent/commits/{head_oid}/check-runs?per_page=100");
    let cr_out = Command::new(&gh)
        .args(["api", "--paginate", "--slurp", &ep])
        .output()
        .map_err(|e| format!("gh api check-runs failed: {e}"))?;
    if !cr_out.status.success() {
        return Err(format!(
            "HEAD '{head_oid}' lacks verified signed tag and GitHub check-runs query failed"
        ));
    }
    let v = JsonValue::parse(String::from_utf8_lossy(&cr_out.stdout).trim())
        .map_err(|e| format!("invalid check-runs JSON: {e}"))?;
    let pages = v
        .as_array()
        .ok_or_else(|| "check-runs --slurp output is not an array".to_string())?;
    let mut latest: BTreeMap<String, (u64, String, String)> = BTreeMap::new();
    for page in pages {
        let runs = page
            .get("check_runs")
            .and_then(JsonValue::as_array)
            .ok_or_else(|| "missing check_runs array".to_string())?;
        for r in runs {
            let name = r.get("name").and_then(JsonValue::as_str).unwrap_or("");
            let id = r.get("id").and_then(JsonValue::as_u64).unwrap_or(0);
            let status = r.get("status").and_then(JsonValue::as_str).unwrap_or("");
            let concl = r
                .get("conclusion")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            match latest.get_mut(name) {
                Some((prev_id, prev_st, prev_concl)) if id >= *prev_id => {
                    *prev_id = id;
                    *prev_st = status.to_string();
                    *prev_concl = concl.to_string();
                }
                Some(_) => {}
                None => {
                    latest.insert(
                        name.to_string(),
                        (id, status.to_string(), concl.to_string()),
                    );
                }
            }
        }
    }
    for (name, (_, status, concl)) in &latest {
        // The Ring-0 ratchet job is intentionally skipped on main pushes (enforced at PR time).
        let skipped_ok = name == RATCHET_CHECK_RUN && concl == "skipped";
        if status != "completed" || (concl != "success" && !skipped_ok) {
            return Err(format!(
                "HEAD '{head_oid}' check-run '{name}' is {status}/{concl} (all must be green)"
            ));
        }
    }
    // Both review gates run on the PR head. Require all remaining checks on the main push.
    for req in dotagent_required_checks()
        .filter(|name| !matches!(*name, RATCHET_CHECK_RUN | COPILOT_GATE_CONTEXT))
    {
        match latest.get(req) {
            Some((_, st, c)) if st == "completed" && c == "success" => {}
            _ => {
                return Err(format!(
                    "HEAD '{head_oid}' is missing required green main-push check-run '{req}'"
                ));
            }
        }
    }
    Ok(())
}

/// CLI entrypoint: `dotagent fleet <audit|doctor|sync|build-image> ...`
pub fn run_fleet_cli(args: &[String], cwd: &Path) -> ExitCode {
    if let Err(msg) = verify_operator_not_in_agent_sandbox("dotagent fleet") {
        eprintln!("[AGENT-GUARD HARD DENY] {msg}");
        return ExitCode::from(2);
    }

    let sub = args.first().map(String::as_str).unwrap_or("audit");
    if sub == "configure-github" {
        if args.iter().any(|a| a == "--owner") {
            return run_fleet_configure_github_cli(&args[1..], cwd);
        }
        return crate::github_governance::run_configure_github_cli(&args[1..]);
    }
    let json_mode = args.iter().any(|a| a == "--json");
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let require_provenance = args.iter().any(|a| a == "--require-provenance")
        || std::env::var("DOTAGENT_FLEET_REQUIRE_PROVENANCE").as_deref() == Ok("1");
    let mut org_root: Option<PathBuf> = None;
    let mut dotagent_root: Option<PathBuf> = None;
    let mut bin_dir: Option<PathBuf> = None;
    let mut out_dir: Option<PathBuf> = None;

    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--root" if i + 1 < args.len() => {
                org_root = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--dotagent-root" if i + 1 < args.len() => {
                dotagent_root = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--bin-dir" if i + 1 < args.len() => {
                bin_dir = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--out" if i + 1 < args.len() => {
                out_dir = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--json" | "--dry-run" | "--require-provenance" | "--allow-unverified-local" => i += 1,
            other if !other.starts_with('-') && org_root.is_none() => {
                org_root = Some(PathBuf::from(other));
                i += 1;
            }
            other => {
                eprintln!("[dotagent fleet] unrecognized argument '{other}'");
                return ExitCode::from(2);
            }
        }
    }

    let resolved_bundle = dotagent_root.unwrap_or_else(|| resolve_repo_root(cwd));

    match sub {
        "build-image" => {
            let Some(stage) = out_dir.or(org_root) else {
                eprintln!(
                    "[dotagent fleet] usage: dotagent fleet build-image --out <stage_dir> [--dotagent-root <dir>] [--bin-dir <dir>]"
                );
                return ExitCode::from(2);
            };
            // Immutable images are rollout artifacts: provenance is mandatory unless the operator
            // explicitly opts into an unverified local developer build.
            let allow_unverified = args.iter().any(|a| a == "--allow-unverified-local");
            if !allow_unverified
                && let Err(prov_err) = verify_bundle_rollout_provenance(&resolved_bundle)
            {
                eprintln!(
                    "[dotagent fleet build-image] HARD DENY: PROVENANCE_REQUIRED: {prov_err} (pass --allow-unverified-local for developer-only images)"
                );
                return ExitCode::from(2);
            }
            match build_immutable_dotagent_image(&resolved_bundle, bin_dir.as_deref(), &stage) {
                Ok(manifest) => {
                    println!(
                        "[DOTAGENT FLEET IMAGE OK] Staged immutable layer at '{}' (manifest='{}')",
                        stage.display(),
                        manifest.display()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("[dotagent fleet build-image] HARD DENY: {e}");
                    ExitCode::from(2)
                }
            }
        }
        "audit" | "doctor" => {
            let target_org = org_root.unwrap_or_else(|| cwd.to_path_buf());
            let dist_agents = resolved_bundle.join("dist/AGENTS.md");
            let canon_agents_sha = fs::symlink_metadata(&dist_agents)
                .ok()
                .filter(|m| !m.file_type().is_symlink() && m.file_type().is_file())
                .and_then(|_| fs::read(&dist_agents).ok())
                .map(|b| sha256_hex(&b));
            match audit_fleet_parallel(&target_org, canon_agents_sha.as_deref(), sub == "doctor") {
                Ok(reports) => {
                    let all_ok = reports.iter().all(|r| r.ok);
                    if json_mode {
                        let arr: Vec<JsonValue> =
                            reports.iter().map(FleetRepoReport::to_json_value).collect();
                        let out = JsonValue::Object(vec![
                            ("ok".to_string(), JsonValue::Bool(all_ok)),
                            (
                                "repo_count".to_string(),
                                JsonValue::Uint(reports.len() as u64),
                            ),
                            ("repositories".to_string(), JsonValue::Array(arr)),
                        ]);
                        println!("{}", out.to_json_string());
                    } else {
                        println!(
                            "[DOTAGENT FLEET {}] scanned {} repositories under '{}':",
                            sub.to_ascii_uppercase(),
                            reports.len(),
                            target_org.display()
                        );
                        for r in &reports {
                            let tag = if r.ok { "PASS" } else { "FAIL" };
                            println!("  [{tag}] {}: {}", r.repo_name, r.detail);
                        }
                    }
                    if all_ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(2)
                    }
                }
                Err(e) => {
                    eprintln!("[dotagent fleet {sub}] HARD DENY: {e}");
                    ExitCode::from(2)
                }
            }
        }
        "sync" => {
            let Some(target_org) = org_root else {
                eprintln!(
                    "[dotagent fleet] usage: dotagent fleet sync --root <org_dir> [--dotagent-root <dir>] [--require-provenance] [--dry-run]"
                );
                return ExitCode::from(2);
            };
            if require_provenance
                && let Err(prov_err) = verify_bundle_rollout_provenance(&resolved_bundle)
            {
                eprintln!("[dotagent fleet sync] HARD DENY: {prov_err}");
                return ExitCode::from(2);
            }
            let Ok(home_raw) = std::env::var("HOME") else {
                eprintln!("[dotagent fleet sync] HOME environment variable is not set");
                return ExitCode::from(2);
            };
            let home = PathBuf::from(home_raw);
            let resolved_bin = bin_dir.unwrap_or_else(|| home.join(".local/bin"));
            let repos = match discover_fleet_repositories(&target_org) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[dotagent fleet sync] HARD DENY: {e}");
                    return ExitCode::from(2);
                }
            };
            // Step 1: One-time global $HOME + canonical dotagent_root setup (avoids concurrent $HOME races)
            if let Err(e) = crate::operator::execute_activate(
                &home,
                &resolved_bin,
                &resolved_bundle,
                &resolved_bundle,
                dry_run,
            ) {
                eprintln!("[dotagent fleet sync] global setup failed: {e}");
                return ExitCode::from(2);
            }
            // Step 2: Parallel per-repository bundle synchronization + audit
            let mut sync_outcomes: Vec<(PathBuf, Result<(), String>)> =
                Vec::with_capacity(repos.len());
            std::thread::scope(|s| {
                let mut handles = Vec::with_capacity(repos.len());
                for repo in &repos {
                    let repo_clone = repo.clone();
                    let bin_ref = &resolved_bin;
                    let bundle_ref = &resolved_bundle;
                    handles.push(s.spawn(move || {
                        let res = crate::operator::activate_external_workspace_only(
                            bin_ref,
                            bundle_ref,
                            &repo_clone,
                            dry_run,
                        )
                        .map(|_| ());
                        (repo_clone, res)
                    }));
                }
                for h in handles {
                    if let Ok(pair) = h.join() {
                        sync_outcomes.push(pair);
                    }
                }
            });
            sync_outcomes.sort_by(|a, b| a.0.cmp(&b.0));
            let mut failed = 0usize;
            for (repo, res) in sync_outcomes {
                match res {
                    Ok(()) => println!("[SYNC OK] {}", repo.display()),
                    Err(e) => {
                        eprintln!("[SYNC FAIL] {}: {e}", repo.display());
                        failed += 1;
                    }
                }
            }
            if failed == 0 {
                println!(
                    "[DOTAGENT FLEET SYNC COMPLETE] synchronized {} repositories.",
                    repos.len()
                );
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        other => {
            eprintln!(
                "[dotagent fleet] unrecognized subcommand '{other}' (expected audit | doctor | sync | build-image)"
            );
            ExitCode::from(2)
        }
    }
}

fn build_dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let header = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    );
    let mut pae = Vec::with_capacity(header.len() + payload.len());
    pae.extend_from_slice(header.as_bytes());
    pae.extend_from_slice(payload);
    pae
}

fn verify_ed25519_detached_hex(
    message: &[u8],
    sig_hex: &str,
    pubkey_hex: &str,
) -> Result<(), String> {
    let pub_bytes =
        hex_decode_32(pubkey_hex.trim()).map_err(|e| format!("invalid Ed25519 pubkey hex: {e}"))?;
    let vk = VerifyingKey::from_bytes(&pub_bytes)
        .map_err(|e| format!("invalid Ed25519 verifying key: {e}"))?;
    let sig_vec = hex_decode_bytes(sig_hex.trim())
        .map_err(|e| format!("invalid Ed25519 signature hex: {e}"))?;
    let sig_arr: [u8; 64] = sig_vec
        .try_into()
        .map_err(|_| "Ed25519 signature must be 64 bytes (128 hex chars)".to_string())?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(message, &sig)
        .map_err(|_| "ED25519_SIGNATURE_INVALID: signature verification failed".to_string())
}

/// Verifies a file's SHA-256 digest against `SHA256SUMS` and optional SLSA v1.0 in-toto
/// provenance JSON (`https://in-toto.io/Statement/v1`, raw statement or signed DSSE envelope).
pub fn verify_artifact_digest_and_slsa(
    subject_path: &Path,
    sha256sums_content: &str,
    slsa_statement_json: Option<&str>,
) -> Result<String, String> {
    verify_artifact_digest_slsa_and_signature(
        subject_path,
        sha256sums_content,
        slsa_statement_json,
        None,
        None,
        None,
    )
    .map(|(sha, _crypto)| sha)
}

pub fn verify_artifact_digest_slsa_and_signature(
    subject_path: &Path,
    sha256sums_content: &str,
    slsa_statement_json: Option<&str>,
    detached_sums_sig_hex: Option<&str>,
    pinned_pubkey_hex: Option<&str>,
    expected_builder_id: Option<&str>,
) -> Result<(String, bool), String> {
    let meta = fs::symlink_metadata(subject_path)
        .map_err(|e| format!("cannot stat subject '{}': {e}", subject_path.display()))?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(format!(
            "subject '{}' must be a regular non-symlink file",
            subject_path.display()
        ));
    }
    let bytes = fs::read(subject_path)
        .map_err(|e| format!("failed reading '{}': {e}", subject_path.display()))?;
    let actual_digest = sha256_bytes(&bytes);
    let actual_hex = sha256_hex(&bytes);
    let fname = subject_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "invalid subject filename".to_string())?;
    let norm_subject_rel = subject_path.to_string_lossy().replace('\\', "/");
    let norm_subject_rel = norm_subject_rel.trim_start_matches("./");

    let mut exact_sums_matches: Vec<&str> = Vec::new();
    let mut basename_sums_matches: Vec<&str> = Vec::new();
    for line in sha256sums_content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let Some(hex_col) = parts.next() else {
            continue;
        };
        let Some(name_col) = parts.next() else {
            continue;
        };
        let clean_rel = name_col.trim_start_matches('*').trim_start_matches("./");
        if clean_rel == norm_subject_rel {
            exact_sums_matches.push(hex_col);
        }
        let clean_base = clean_rel.rsplit('/').next().unwrap_or(clean_rel);
        if clean_base == fname {
            basename_sums_matches.push(hex_col);
        }
    }

    let chosen_hex = if exact_sums_matches.len() == 1 {
        exact_sums_matches[0]
    } else if exact_sums_matches.len() > 1 {
        return Err(format!(
            "AMBIGUOUS_SHA256SUMS_ENTRY: multiple entries match '{norm_subject_rel}'"
        ));
    } else if basename_sums_matches.len() == 1 {
        basename_sums_matches[0]
    } else if basename_sums_matches.len() > 1 {
        return Err(format!(
            "AMBIGUOUS_SHA256SUMS_BASENAME: multiple entries share basename '{fname}'; pass exact relative path"
        ));
    } else {
        return Err(format!(
            "SUBJECT_NOT_IN_SHA256SUMS: '{fname}' not listed in provided SHA256SUMS"
        ));
    };

    let exp_bytes = hex_decode_32(chosen_hex)
        .map_err(|e| format!("malformed SHA-256 in SHA256SUMS for '{fname}': {e}"))?;
    if !constant_time_eq_bytes(&actual_digest, &exp_bytes) {
        return Err(format!(
            "SHA256_MISMATCH: '{fname}' actual {actual_hex} != SHA256SUMS {chosen_hex}"
        ));
    }

    let mut cryptographically_verified = false;
    if detached_sums_sig_hex.is_some() && pinned_pubkey_hex.is_none() {
        return Err("SIGNATURE_PUBKEY_REQUIRED: --sig requires --pubkey <ed25519_pubkey>".into());
    }
    if let (Some(sig_h), Some(pub_h)) = (detached_sums_sig_hex, pinned_pubkey_hex) {
        verify_ed25519_detached_hex(sha256sums_content.as_bytes(), sig_h, pub_h)?;
        cryptographically_verified = true;
    }

    if let Some(raw_slsa) = slsa_statement_json {
        let outer =
            JsonValue::parse(raw_slsa).map_err(|e| format!("invalid SLSA provenance JSON: {e}"))?;

        // Unwrap optional DSSE envelope (`{"payloadType":"application/vnd.in-toto+json","payload":"<b64>","signatures":[{"sig":"..."}]}`)
        let stmt = if let Some(payload_b64) = outer.get("payload").and_then(JsonValue::as_str) {
            let payload_type = outer
                .get("payloadType")
                .and_then(JsonValue::as_str)
                .unwrap_or_default();
            if payload_type != "application/vnd.in-toto+json" {
                return Err(format!(
                    "DSSE_INVALID_PAYLOAD_TYPE: expected 'application/vnd.in-toto+json', got '{payload_type}'"
                ));
            }
            let decoded = decode_standard_or_url_base64(payload_b64)?;
            if let Some(pub_h) = pinned_pubkey_hex {
                let dsse_sig = outer
                    .get("signatures")
                    .and_then(JsonValue::as_array)
                    .and_then(|a| a.first())
                    .and_then(|s| s.get("sig"))
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| "DSSE envelope missing signatures[0].sig".to_string())?;
                let sig_bytes = decode_standard_or_url_base64(dsse_sig)?;
                let sig_hex = crate::crypto::hex_encode(&sig_bytes);
                let pae = build_dsse_pae(payload_type, &decoded);
                verify_ed25519_detached_hex(&pae, &sig_hex, pub_h)?;
                cryptographically_verified = true;
            }
            let inner_str = String::from_utf8(decoded)
                .map_err(|_| "non-UTF8 DSSE in-toto statement payload".to_string())?;
            JsonValue::parse(&inner_str)
                .map_err(|e| format!("invalid DSSE inner Statement JSON: {e}"))?
        } else {
            if pinned_pubkey_hex.is_some() {
                return Err(
                    "DSSE_SIGNATURE_REQUIRED: --pubkey requires SLSA provenance to be wrapped in a signed DSSE envelope"
                        .to_string(),
                );
            }
            outer
        };

        let stmt_type = stmt
            .get("_type")
            .and_then(JsonValue::as_str)
            .unwrap_or_default();
        if stmt_type != "https://in-toto.io/Statement/v1" {
            return Err(format!(
                "SLSA_INVALID_STATEMENT_TYPE: expected 'https://in-toto.io/Statement/v1', got '{stmt_type}'"
            ));
        }
        let pred_type = stmt
            .get("predicateType")
            .and_then(JsonValue::as_str)
            .unwrap_or_default();
        if pred_type != "https://slsa.dev/provenance/v1" {
            return Err(format!(
                "SLSA_INVALID_PREDICATE_TYPE: expected 'https://slsa.dev/provenance/v1', got '{pred_type}'"
            ));
        }

        let Some(pred) = stmt.get("predicate").filter(|p| p.as_object().is_some()) else {
            return Err("SLSA_MISSING_PREDICATE: statement.predicate must be a JSON object".into());
        };
        {
            let builder_id = pred
                .get("runDetails")
                .and_then(|rd| rd.get("builder"))
                .and_then(|b| b.get("id"))
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            if let Some(exp_builder) = expected_builder_id {
                if builder_id != exp_builder {
                    return Err(format!(
                        "SLSA_BUILDER_MISMATCH: expected builder.id '{exp_builder}', got '{builder_id}'"
                    ));
                }
            } else if pred.get("runDetails").is_some() && builder_id.trim().is_empty() {
                return Err(
                    "SLSA_MISSING_BUILDER_ID: predicate.runDetails.builder.id is empty".into(),
                );
            }
        }

        let subjects = stmt
            .get("subject")
            .and_then(JsonValue::as_array)
            .ok_or_else(|| "SLSA statement missing 'subject' array".to_string())?;
        let mut exact_slsa: Vec<&JsonValue> = Vec::new();
        let mut base_slsa: Vec<&JsonValue> = Vec::new();
        for subj in subjects {
            let sname = subj
                .get("name")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .trim_start_matches("./");
            if sname == norm_subject_rel {
                exact_slsa.push(subj);
            }
            let clean_sname = sname.rsplit('/').next().unwrap_or(sname);
            if clean_sname == fname {
                base_slsa.push(subj);
            }
        }
        let matched_subj = if exact_slsa.len() == 1 {
            exact_slsa[0]
        } else if exact_slsa.len() > 1 {
            return Err(format!(
                "SLSA_AMBIGUOUS_SUBJECT: multiple subjects match '{norm_subject_rel}'"
            ));
        } else if base_slsa.len() == 1 {
            base_slsa[0]
        } else if base_slsa.len() > 1 {
            return Err(format!(
                "SLSA_AMBIGUOUS_BASENAME: multiple SLSA subjects share basename '{fname}'"
            ));
        } else {
            return Err(format!(
                "SLSA_SUBJECT_MISSING: '{fname}' not attested in SLSA provenance subject list"
            ));
        };

        let sha_hex = matched_subj
            .get("digest")
            .and_then(|d| d.get("sha256"))
            .and_then(JsonValue::as_str)
            .ok_or_else(|| format!("SLSA subject '{fname}' missing digest.sha256"))?;
        let slsa_exp_bytes =
            hex_decode_32(sha_hex).map_err(|e| format!("invalid SLSA sha256 hex: {e}"))?;
        if !constant_time_eq_bytes(&actual_digest, &slsa_exp_bytes) {
            return Err(format!(
                "SLSA_DIGEST_MISMATCH: '{fname}' actual {actual_hex} != SLSA {sha_hex}"
            ));
        }
    }

    if pinned_pubkey_hex.is_some() && !cryptographically_verified {
        return Err(
            "SIGNATURE_MISSING_FOR_PUBKEY: --pubkey was supplied without --sig or a signed DSSE envelope"
                .to_string(),
        );
    }

    Ok((actual_hex, cryptographically_verified))
}

fn decode_standard_or_url_base64(raw: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    let unpadded = cleaned.trim_end_matches('=');
    crate::mcp_gateway::base64url_decode_nopad(unpadded)
}

fn read_hex_or_file_arg(raw: &str, label: &str) -> Result<String, String> {
    let p = Path::new(raw);
    if p.exists() {
        let meta = fs::symlink_metadata(p)
            .map_err(|e| format!("failed stat on {label} '{}': {e}", p.display()))?;
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            return Err(format!(
                "{label} '{}' must be a regular non-symlink file",
                p.display()
            ));
        }
        return fs::read_to_string(p)
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("failed reading {label} '{}': {e}", p.display()));
    }
    Ok(raw.trim().to_string())
}

/// CLI entrypoint: `dotagent self-verify [--subject <file>] --sums <SHA256SUMS> [--sig <sig>] [--pubkey <pub>] [--provenance <statement.json>] [--expected-builder <uri>]`
pub fn run_self_verify_cli(args: &[String]) -> ExitCode {
    let mut subject: Option<PathBuf> = None;
    let mut sums_path: Option<PathBuf> = None;
    let mut prov_path: Option<PathBuf> = None;
    let mut sig_arg: Option<String> = None;
    let mut pubkey_arg: Option<String> = None;
    let mut expected_builder: Option<String> = None;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--subject" if i + 1 < args.len() => {
                subject = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--sums" | "--manifest" if i + 1 < args.len() => {
                sums_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--provenance" if i + 1 < args.len() => {
                prov_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--sig" if i + 1 < args.len() => {
                sig_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--pubkey" if i + 1 < args.len() => {
                pubkey_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--expected-builder" if i + 1 < args.len() => {
                expected_builder = Some(args[i + 1].clone());
                i += 2;
            }
            other => {
                eprintln!("[dotagent self-verify] unrecognized argument '{other}'");
                return ExitCode::from(2);
            }
        }
    }

    let resolved_subject = match subject.or_else(|| std::env::current_exe().ok()) {
        Some(p) => p,
        None => {
            eprintln!("[dotagent self-verify] failed resolving subject binary path");
            return ExitCode::from(2);
        }
    };
    let Some(sums_file) = sums_path else {
        eprintln!(
            "[dotagent self-verify] usage: dotagent self-verify --sums <SHA256SUMS> [--subject <file>] [--sig <ed25519.sig>] [--pubkey <ed25519.pub>] [--provenance <slsa-statement.json>]"
        );
        return ExitCode::from(2);
    };
    if let Ok(m) = fs::symlink_metadata(&sums_file)
        && m.file_type().is_symlink()
    {
        eprintln!(
            "[DOTAGENT SELF-VERIFY FAIL] SYMLINK_TAMPER_DETECTED: '{}' is a symlink",
            sums_file.display()
        );
        return ExitCode::from(2);
    }
    let sums_raw = match fs::read_to_string(&sums_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[dotagent self-verify] failed reading '{}': {e}",
                sums_file.display()
            );
            return ExitCode::from(2);
        }
    };
    let prov_raw = match prov_path {
        Some(p) => {
            if let Ok(m) = fs::symlink_metadata(&p)
                && m.file_type().is_symlink()
            {
                eprintln!(
                    "[DOTAGENT SELF-VERIFY FAIL] SYMLINK_TAMPER_DETECTED: provenance '{}' is a symlink",
                    p.display()
                );
                return ExitCode::from(2);
            }
            match fs::read_to_string(&p) {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!(
                        "[dotagent self-verify] failed reading provenance '{}': {e}",
                        p.display()
                    );
                    return ExitCode::from(2);
                }
            }
        }
        None => None,
    };
    let sig_hex = match sig_arg {
        Some(ref raw) => match read_hex_or_file_arg(raw, "signature") {
            Ok(h) => Some(h),
            Err(e) => {
                eprintln!("[DOTAGENT SELF-VERIFY FAIL] {e}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    let pub_hex = match pubkey_arg {
        Some(ref raw) => match read_hex_or_file_arg(raw, "pubkey") {
            Ok(h) => Some(h),
            Err(e) => {
                eprintln!("[DOTAGENT SELF-VERIFY FAIL] {e}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };

    match verify_artifact_digest_slsa_and_signature(
        &resolved_subject,
        &sums_raw,
        prov_raw.as_deref(),
        sig_hex.as_deref(),
        pub_hex.as_deref(),
        expected_builder.as_deref(),
    ) {
        Ok((digest, crypto_ok)) => {
            println!(
                "[DOTAGENT SELF-VERIFY OK] subject='{}' sha256={} slsa_manifest_checked={} cryptographically_verified={}",
                resolved_subject.display(),
                digest,
                prov_raw.is_some(),
                crypto_ok
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("[DOTAGENT SELF-VERIFY FAIL] {e}");
            ExitCode::from(2)
        }
    }
}

pub fn build_github_repo_ruleset_payload() -> JsonValue {
    let kv = |k: &str, v: &str| (k.to_string(), JsonValue::Str(v.to_string()));
    let kb = |k: &str, v: bool| (k.to_string(), JsonValue::Bool(v));
    let ku = |k: &str, v: u64| (k.to_string(), JsonValue::Uint(v));
    let actor = |id: u64, ty: &str| {
        JsonValue::Object(vec![
            ku("actor_id", id),
            kv("actor_type", ty),
            kv("bypass_mode", "pull_request"),
        ])
    };
    JsonValue::Object(vec![
        kv("name", "dotagent-ring0-main-protection"),
        kv("target", "branch"),
        kv("enforcement", "active"),
        (
            "bypass_actors".to_string(),
            JsonValue::Array(vec![
                actor(5, "RepositoryRole"),
                actor(1, "OrganizationAdmin"),
            ]),
        ),
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
        (
            "rules".to_string(),
            JsonValue::Array(vec![
                JsonValue::Object(vec![kv("type", "deletion")]),
                JsonValue::Object(vec![kv("type", "non_fast_forward")]),
                JsonValue::Object(vec![kv("type", "required_linear_history")]),
                JsonValue::Object(vec![
                    kv("type", "pull_request"),
                    (
                        "parameters".to_string(),
                        JsonValue::Object(vec![
                            (
                                "allowed_merge_methods".to_string(),
                                JsonValue::Array(vec![JsonValue::Str("squash".to_string())]),
                            ),
                            ku("required_approving_review_count", 1),
                            kb("required_review_thread_resolution", true),
                            kb("dismiss_stale_reviews_on_push", true),
                            kb("require_code_owner_review", false),
                            kb("require_last_push_approval", false),
                        ]),
                    ),
                ]),
            ]),
        ),
    ])
}

pub fn build_github_fleet_governance_plan(owner: &str, repos: &[String]) -> JsonValue {
    let kv = |k: &str, v: &str| (k.to_string(), JsonValue::Str(v.to_string()));
    let kb = |k: &str, v: bool| (k.to_string(), JsonValue::Bool(v));
    let ruleset = build_github_repo_ruleset_payload();
    let targets: Vec<JsonValue> = repos
        .iter()
        .map(|repo| {
            JsonValue::Object(vec![
                kv("owner", owner),
                kv("repo", repo),
                (
                    "actions_permissions".to_string(),
                    JsonValue::Object(vec![
                        kv(
                            "endpoint",
                            &format!("/repos/{owner}/{repo}/actions/permissions"),
                        ),
                        kb("enabled", true),
                        kb("sha_pinning_required", true),
                    ]),
                ),
                (
                    "workflow_permissions".to_string(),
                    JsonValue::Object(vec![
                        kv(
                            "endpoint",
                            &format!("/repos/{owner}/{repo}/actions/permissions/workflow"),
                        ),
                        kv("default_workflow_permissions", "read"),
                        kb("can_approve_pull_request_reviews", false),
                    ]),
                ),
                (
                    "ruleset".to_string(),
                    JsonValue::Object(vec![
                        kv("endpoint", &format!("/repos/{owner}/{repo}/rulesets")),
                        ("payload".to_string(), ruleset.clone()),
                    ]),
                ),
            ])
        })
        .collect();
    JsonValue::Object(vec![
        kv("schema", "dotagent.fleet.github_governance.v1"),
        kv("owner", owner),
        ("targets".to_string(), JsonValue::Array(targets)),
    ])
}

fn is_safe_gh_slug(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty()
        && t.len() <= 100
        && t != "."
        && t != ".."
        && !t.starts_with('-')
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

pub fn verify_github_governance_state(
    actions_perms: &JsonValue,
    workflow_perms: &JsonValue,
    ruleset: &JsonValue,
) -> Result<(), Vec<String>> {
    let mut errs = Vec::new();
    if actions_perms.get("enabled").and_then(JsonValue::as_bool) != Some(true) {
        errs.push("actions enabled must be true".to_string());
    }
    if actions_perms
        .get("sha_pinning_required")
        .and_then(JsonValue::as_bool)
        != Some(true)
    {
        errs.push("sha_pinning_required must be true".to_string());
    }
    if workflow_perms
        .get("default_workflow_permissions")
        .and_then(JsonValue::as_str)
        != Some("read")
    {
        errs.push("default_workflow_permissions must equal 'read'".to_string());
    }
    if workflow_perms
        .get("can_approve_pull_request_reviews")
        .and_then(JsonValue::as_bool)
        != Some(false)
    {
        errs.push("can_approve_pull_request_reviews must be false".to_string());
    }
    if ruleset.get("target").and_then(JsonValue::as_str) != Some("branch")
        || ruleset.get("enforcement").and_then(JsonValue::as_str) != Some("active")
    {
        errs.push("ruleset must have target='branch' and enforcement='active'".to_string());
    }
    let cond_ok = ruleset
        .get("conditions")
        .and_then(|c| c.get("ref_name"))
        .is_some_and(|rn| {
            let inc_ok = rn
                .get("include")
                .and_then(JsonValue::as_array)
                .is_some_and(|inc| inc.iter().any(|x| x.as_str() == Some("~DEFAULT_BRANCH")));
            let exc_empty = rn
                .get("exclude")
                .and_then(JsonValue::as_array)
                .is_none_or(<[JsonValue]>::is_empty);
            inc_ok && exc_empty
        });
    if !cond_ok {
        errs.push("ruleset must include ~DEFAULT_BRANCH with empty exclude".to_string());
    }
    let bypass_ok = ruleset
        .get("bypass_actors")
        .and_then(JsonValue::as_array)
        .is_some_and(|arr| {
            !arr.is_empty()
                && arr.iter().all(|a| {
                    let mode_ok =
                        a.get("bypass_mode").and_then(JsonValue::as_str) == Some("pull_request");
                    let atype = a.get("actor_type").and_then(JsonValue::as_str);
                    let aid = a.get("actor_id").and_then(JsonValue::as_u64);
                    let admin_ok = matches!(
                        (atype, aid),
                        (Some("RepositoryRole"), Some(5)) | (Some("OrganizationAdmin"), Some(1))
                    );
                    mode_ok && admin_ok
                })
        });
    if !bypass_ok {
        errs.push("ruleset bypass_actors must strictly be admin pull_request only".to_string());
    }
    let rules = ruleset.get("rules").and_then(JsonValue::as_array);
    for req_rule in ["deletion", "non_fast_forward", "required_linear_history"] {
        let present = rules.is_some_and(|rs| {
            rs.iter()
                .any(|r| r.get("type").and_then(JsonValue::as_str) == Some(req_rule))
        });
        if !present {
            errs.push(format!("ruleset missing {req_rule}"));
        }
    }
    let pr_ok = rules.is_some_and(|rs| {
        rs.iter().any(|r| {
            if r.get("type").and_then(JsonValue::as_str) != Some("pull_request") {
                return false;
            }
            let Some(p) = r.get("parameters") else {
                return false;
            };
            let squash_only = p
                .get("allowed_merge_methods")
                .and_then(JsonValue::as_array)
                .is_some_and(|m| m.len() == 1 && m[0].as_str() == Some("squash"));
            let rev_cnt = p
                .get("required_approving_review_count")
                .and_then(JsonValue::as_u64)
                .unwrap_or(0)
                >= 1;
            let threads = p
                .get("required_review_thread_resolution")
                .and_then(JsonValue::as_bool)
                == Some(true);
            squash_only && rev_cnt && threads
        })
    });
    if !pr_ok {
        errs.push(
            "ruleset pull_request must enforce squash-only, >=1 review, and thread resolution"
                .into(),
        );
    }
    if errs.is_empty() { Ok(()) } else { Err(errs) }
}

fn run_fleet_configure_github_cli(args: &[String], cwd: &Path) -> ExitCode {
    let mut owner: Option<String> = None;
    let mut single_repo: Option<String> = None;
    let mut all_fleet = false;
    let mut org_root: Option<PathBuf> = None;
    let mut dry_run = false;
    let mut verify_only = false;
    let mut sshsig_file: Option<PathBuf> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--owner" if i + 1 < args.len() => {
                owner = Some(args[i + 1].clone());
                i += 2;
            }
            "--repo" if i + 1 < args.len() => {
                single_repo = Some(args[i + 1].clone());
                i += 2;
            }
            "--root" if i + 1 < args.len() => {
                org_root = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--sshsig" if i + 1 < args.len() => {
                sshsig_file = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--all-fleet" => {
                all_fleet = true;
                i += 1;
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            "--verify" => {
                verify_only = true;
                i += 1;
            }
            "--json" => i += 1,
            other => {
                eprintln!("[dotagent fleet configure-github] unrecognized arg '{other}'");
                return ExitCode::from(2);
            }
        }
    }
    let Some(owner_str) = owner.filter(|s| is_safe_gh_slug(s)) else {
        eprintln!(
            "[dotagent fleet] usage: dotagent fleet configure-github --owner <org_or_user> [--repo <name> | --all-fleet] [--sshsig <path>] [--dry-run] [--verify]"
        );
        return ExitCode::from(2);
    };
    let repos: Vec<String> = if let Some(r) = single_repo {
        vec![r]
    } else if all_fleet {
        let root = org_root.unwrap_or_else(|| cwd.to_path_buf());
        match discover_fleet_repositories(&root) {
            Ok(paths) => paths
                .iter()
                .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(String::from))
                .collect(),
            Err(e) => {
                eprintln!("[dotagent fleet configure-github] {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        eprintln!("[dotagent fleet configure-github] pass --repo <name> or --all-fleet");
        return ExitCode::from(2);
    };
    if repos.is_empty() || repos.iter().any(|r| !is_safe_gh_slug(r)) {
        eprintln!("[dotagent fleet configure-github] invalid or empty repository slug list");
        return ExitCode::from(2);
    }

    let plan = build_github_fleet_governance_plan(&owner_str, &repos);
    if dry_run {
        println!("{}", plan.to_json_string());
        return ExitCode::SUCCESS;
    }
    if let Err((code, detail)) = crate::telemetry::verify_human_tty_telemetry_gate() {
        eprintln!("[AGENT-GUARD HARD DENY :: {code}] {detail}");
        return ExitCode::from(2);
    }
    let repo_root = crate::resolve_repo_root(cwd);
    if let Err(ge) = crate::operator::verify_operator_sshsig_gate(
        &repo_root,
        "configure-github",
        sshsig_file.as_deref(),
    ) {
        eprintln!("[AGENT-GUARD HARD DENY :: {}] {}", ge.code, ge.detail);
        return ExitCode::from(2);
    }
    let canon_root = fs::canonicalize(&repo_root).unwrap_or_else(|_| repo_root.clone());
    let mut gh_candidates = vec![
        PathBuf::from("/opt/antigravity/bin/gh"),
        PathBuf::from("/usr/local/bin/gh"),
        PathBuf::from("/opt/homebrew/bin/gh"),
        PathBuf::from("/usr/bin/gh"),
    ];
    if let Some(path_os) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_os) {
            if dir.is_absolute() {
                gh_candidates.push(dir.join("gh"));
            }
        }
    }
    let Some(gh_bin) = gh_candidates.into_iter().find(|p| {
        p.is_absolute()
            && !p.starts_with(&repo_root)
            && fs::canonicalize(p).is_ok_and(|c| {
                !c.starts_with(&canon_root) && crate::coordinator::is_trusted_executable_file(&c)
            })
    }) else {
        eprintln!("[dotagent fleet configure-github] trusted absolute `gh` binary not found");
        return ExitCode::from(2);
    };
    let build_gh_cmd = || -> std::process::Command {
        let mut c = std::process::Command::new(&gh_bin);
        c.env_clear();
        c.env(
            "PATH",
            "/opt/antigravity/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin",
        );
        c.env("GH_PROMPT_DISABLED", "1");
        c.env("NO_COLOR", "1");
        for k in [
            "HOME",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "GH_CONFIG_DIR",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        ] {
            if let Ok(v) = std::env::var(k) {
                c.env(k, v);
            }
        }
        c
    };
    let gh_get = |ep: &str| -> Result<JsonValue, String> {
        let out = build_gh_cmd()
            .args(["api", ep])
            .output()
            .map_err(|e| format!("gh api '{ep}' failed: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "gh api '{ep}' exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        JsonValue::parse(&String::from_utf8_lossy(&out.stdout))
            .map_err(|e| format!("invalid JSON from '{ep}': {e}"))
    };
    for repo in &repos {
        if verify_only {
            let act = match gh_get(&format!("/repos/{owner_str}/{repo}/actions/permissions")) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[VERIFY FAIL] {owner_str}/{repo}: {e}");
                    return ExitCode::from(2);
                }
            };
            let wf = match gh_get(&format!(
                "/repos/{owner_str}/{repo}/actions/permissions/workflow"
            )) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[VERIFY FAIL] {owner_str}/{repo}: {e}");
                    return ExitCode::from(2);
                }
            };
            let rs_list = match gh_get(&format!("/repos/{owner_str}/{repo}/rulesets")) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[VERIFY FAIL] {owner_str}/{repo}: {e}");
                    return ExitCode::from(2);
                }
            };
            let rs_ok = rs_list.as_array().is_some_and(|arr| {
                arr.iter().any(|item| {
                    item.get("id")
                        .and_then(JsonValue::as_u64)
                        .and_then(|id| {
                            gh_get(&format!("/repos/{owner_str}/{repo}/rulesets/{id}")).ok()
                        })
                        .is_some_and(|full| {
                            verify_github_governance_state(&act, &wf, &full).is_ok()
                        })
                })
            });
            if !rs_ok {
                eprintln!(
                    "[VERIFY FAIL] {owner_str}/{repo}: active GitHub ruleset/Actions governance does not satisfy Ring-0 floor"
                );
                return ExitCode::from(2);
            }
            println!("[VERIFY OK] {owner_str}/{repo}");
        } else {
            let gh_put = |method: &str, ep: &str, body: &str| -> Result<(), String> {
                use std::io::Write;
                let mut child = build_gh_cmd()
                    .args(["api", "--method", method, ep, "--input", "-"])
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .map_err(|e| format!("failed spawning gh: {e}"))?;
                if let Some(mut sin) = child.stdin.take() {
                    let _ = sin.write_all(body.as_bytes());
                }
                let out = child.wait_with_output().map_err(|e| e.to_string())?;
                if out.status.success() {
                    Ok(())
                } else {
                    Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
                }
            };
            let rs_payload = build_github_repo_ruleset_payload();
            let rs_name = rs_payload
                .get("name")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            let existing_id = gh_get(&format!("/repos/{owner_str}/{repo}/rulesets"))
                .ok()
                .and_then(|v| {
                    v.as_array()?.iter().find_map(|it| {
                        (it.get("name").and_then(JsonValue::as_str) == Some(rs_name))
                            .then(|| it.get("id").and_then(JsonValue::as_u64))
                            .flatten()
                    })
                });
            let (rs_method, rs_ep) = match existing_id {
                Some(id) => ("PUT", format!("/repos/{owner_str}/{repo}/rulesets/{id}")),
                None => ("POST", format!("/repos/{owner_str}/{repo}/rulesets")),
            };
            let rs_json = rs_payload.to_json_string();
            for (m, ep, b) in [
                (
                    "PUT",
                    format!("/repos/{owner_str}/{repo}/actions/permissions"),
                    "{\"enabled\":true,\"sha_pinning_required\":true}".to_string(),
                ),
                (
                    "PUT",
                    format!("/repos/{owner_str}/{repo}/actions/permissions/workflow"),
                    "{\"default_workflow_permissions\":\"read\",\"can_approve_pull_request_reviews\":false}".to_string(),
                ),
                (rs_method, rs_ep, rs_json),
            ] {
                if let Err(e) = gh_put(m, &ep, &b) {
                    eprintln!("[CONFIGURE FAIL] {ep}: {e}");
                    return ExitCode::from(2);
                }
            }
            println!("[CONFIGURE OK] {owner_str}/{repo}");
        }
    }
    ExitCode::SUCCESS
}
