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
        if meta.file_type().is_dir() {
            set_mode(stage_dir, 0o755);
        }
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

fn verify_operator_not_in_agent_sandbox(cmd_label: &str) -> Result<(), String> {
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

/// CLI entrypoint: `dotagent fleet <audit|doctor|sync|build-image> ...`
pub fn run_fleet_cli(args: &[String], cwd: &Path) -> ExitCode {
    if let Err(msg) = verify_operator_not_in_agent_sandbox("dotagent fleet") {
        eprintln!("[AGENT-GUARD HARD DENY] {msg}");
        return ExitCode::from(2);
    }

    let sub = args.first().map(String::as_str).unwrap_or("audit");
    let json_mode = args.iter().any(|a| a == "--json");
    let dry_run = args.iter().any(|a| a == "--dry-run");
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
            "--json" | "--dry-run" => i += 1,
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
            let canon_agents_sha = fs::read(resolved_bundle.join("dist/AGENTS.md"))
                .ok()
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
                    "[dotagent fleet] usage: dotagent fleet sync --root <org_dir> [--dotagent-root <dir>] [--dry-run]"
                );
                return ExitCode::from(2);
            };
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

        if let Some(pred) = stmt.get("predicate") {
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
