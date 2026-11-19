#![forbid(unsafe_code)]

//! Canonical + lexical path policy engine.
//! Enforces:
//! - Zero access to temp (`/tmp`, `/var/tmp`, `/dev/shm`, `tmp/`, `.tmp/`)
//! - Zero access to caches (`.cache/`, `~/.cache`, `__pycache__/`, `.next/`, `.turbo/`, etc.)
//! - Zero access to dependency trees (`node_modules/`, `vendor/`, `.venv/`, `site-packages/`, etc.)
//! - Zero access to secrets/credentials (`.env*`, `*.pem`, `*.key`, `~/.ssh`, `~/.aws`, etc.)
//! - Component-by-component symlink escape detection (`lstat` + `read_link`)
//! - Strict per-repo boundary (blocks cross-repo cache/context bleed)
//! - Single Root Authority File (`<repo_root>/AGENTS.md` ONLY — all nested/shadow instruction files blocked)
//! - Control-plane immutability (`AGENTS.md`, `.git/`, `.claude/`, `.codex/`, `.cursor/`, `.guard/`)
//! - Max 2-level directory walk / relative `..` climb restriction

use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::unicode_guard::{ScanMode, scan_unicode};

pub const MAX_DIRECTORY_WALK_DEPTH: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathAccess {
    Read,
    Write,
    ListSearch {
        requested_depth: Option<usize>,
    },
    /// Used when inspecting a pointer/link mentioned inside a doc or source file.
    ReferencePointer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathViolation {
    pub code: &'static str,
    pub detail: String,
    pub is_poisoned_zone: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPath {
    pub canonical_or_norm: PathBuf,
    pub repo_rel: String,
    pub is_root_authority: bool,
}

pub fn effective_max_walk_depth_for_repo(repo_root: &Path) -> usize {
    if let Ok((crate::swarm_contracts::SwarmRole::Investigator, Some(_))) =
        crate::role_sandbox::resolve_active_role(repo_root, "")
    {
        return crate::swarm_contracts::INVESTIGATOR_MAX_WALK_DEPTH;
    }
    MAX_DIRECTORY_WALK_DEPTH
}

pub fn effective_max_walk_depth() -> usize {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let repo_root = crate::resolve_repo_root(&cwd);
    effective_max_walk_depth_for_repo(&repo_root)
}

pub fn validate_path(
    repo_root: &Path,
    cwd: &Path,
    raw_path: &str,
    access: PathAccess,
) -> Result<ValidatedPath, PathViolation> {
    validate_path_with_max_depth(
        repo_root,
        cwd,
        raw_path,
        access,
        effective_max_walk_depth_for_repo(repo_root),
    )
}

pub fn validate_path_with_max_depth(
    repo_root: &Path,
    cwd: &Path,
    raw_path: &str,
    access: PathAccess,
    max_walk_depth: usize,
) -> Result<ValidatedPath, PathViolation> {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        return Err(PathViolation {
            code: "EMPTY_PATH",
            detail: "Empty path rejected".to_string(),
            is_poisoned_zone: false,
        });
    }

    if trimmed.contains('\n') || trimmed.contains('\r') || trimmed.contains('\0') {
        return Err(PathViolation {
            code: "PATH_CONTROL_INJECTION",
            detail: "Control or newline character inside file path rejected".to_string(),
            is_poisoned_zone: false,
        });
    }

    let unicode_issues = scan_unicode(trimmed, ScanMode::StrictPathOrCommand);
    if let Some(first) = unicode_issues.first() {
        return Err(PathViolation {
            code: first.code,
            detail: format!("Path '{}' failed Unicode check: {}", trimmed, first.detail),
            is_poisoned_zone: false,
        });
    }

    // Expand leading `~` so home-directory caches/secrets (`~/.cache`, `~/.ssh`) are caught immediately
    let expanded = expand_tilde(trimmed);

    // 1. Check raw lexical prefixes and segments BEFORE resolving symlinks or `..`
    check_forbidden_zones_lexical(&expanded, trimmed)?;

    // Check relative `..` climb depth (max 2 levels)
    let parent_climbs = Path::new(&expanded)
        .components()
        .filter(|c| matches!(c, Component::ParentDir))
        .count();
    if parent_climbs > MAX_DIRECTORY_WALK_DEPTH {
        return Err(PathViolation {
            code: "MAX_TRAVERSAL_DEPTH_EXCEEDED",
            detail: format!(
                "Path '{trimmed}' climbs {parent_climbs} parent levels (> max {MAX_DIRECTORY_WALK_DEPTH} levels)"
            ),
            is_poisoned_zone: false,
        });
    }

    // Enforce directory search / walk depth ceiling (`<= 2` default, `<= 20` for Investigator)
    if let PathAccess::ListSearch { requested_depth } = access {
        match requested_depth {
            None => {
                return Err(PathViolation {
                    code: "UNBOUNDED_TRAVERSAL_BLOCKED",
                    detail: format!(
                        "Unbounded recursive traversal on '{trimmed}' is forbidden; restrict depth to <= {max_walk_depth} levels."
                    ),
                    is_poisoned_zone: false,
                });
            }
            Some(d) if d > max_walk_depth => {
                return Err(PathViolation {
                    code: "MAX_TRAVERSAL_DEPTH_EXCEEDED",
                    detail: format!(
                        "Requested traversal depth {d} on '{trimmed}' exceeds max {max_walk_depth} levels."
                    ),
                    is_poisoned_zone: false,
                });
            }
            _ => {}
        }
    }

    let (canon_repo, repo_is_canon) = match fs::canonicalize(repo_root) {
        Ok(c) => (c, true),
        Err(_) => (lexical_normalize(repo_root), false),
    };
    let lex_repo = if repo_is_canon {
        lexical_normalize(repo_root)
    } else {
        canon_repo.clone()
    };
    let base_dir = if Path::new(&expanded).is_absolute() {
        PathBuf::from(&expanded)
    } else {
        cwd.join(&expanded)
    };

    // Pre-symlink lexical authority gate so nested symlinked AGENTS.md is rejected!
    let lex_target = lexical_normalize(&base_dir);
    let lex_rel_opt = lex_target
        .strip_prefix(&canon_repo)
        .ok()
        .or_else(|| lex_target.strip_prefix(&lex_repo).ok())
        .map(path_to_slash_string);
    if let Some(ref lex_rel) = lex_rel_opt {
        check_repo_build_artifact_segments(&canon_repo, lex_rel, trimmed)?;
        let lex_is_root = check_authority_file_policy(lex_rel, access)?;
        if lex_is_root {
            if let Ok(meta) = fs::symlink_metadata(&base_dir) {
                if meta.file_type().is_symlink() {
                    return Err(PathViolation {
                        code: "UNAUTHORIZED_INSTRUCTION_FILE",
                        detail: "Root 'AGENTS.md' must be a regular file, not a symlink."
                            .to_string(),
                        is_poisoned_zone: true,
                    });
                }
            }
        }
    }

    // 2. Walk every existing component to detect symlinks pointing to forbidden zones or escaping repo_root
    let resolved = resolve_checking_symlinks(&base_dir, &canon_repo, repo_is_canon)?;

    // 3. Re-check forbidden zones on resolved canonical path
    check_forbidden_zones_lexical(&resolved.to_string_lossy(), trimmed)?;

    // 4. Enforce strict repository boundary (anti-cross-repo cache/context bleed)
    if !resolved.starts_with(&canon_repo) {
        return Err(PathViolation {
            code: "REPO_BOUNDARY_ESCAPE",
            detail: format!(
                "Path '{trimmed}' resolves to '{}' outside repository root '{}' (cross-boundary access / cache bleed blocked)",
                resolved.display(),
                canon_repo.display()
            ),
            is_poisoned_zone: false,
        });
    }

    let rel_path_buf = resolved
        .strip_prefix(&canon_repo)
        .unwrap_or(Path::new(""))
        .to_path_buf();
    let repo_rel = path_to_slash_string(&rel_path_buf);
    check_repo_build_artifact_segments(&canon_repo, &repo_rel, trimmed)?;

    // 5. Enforce Single Root Authority File (`<repo_root>/AGENTS.md` ONLY)
    let is_root_authority = check_authority_file_policy(&repo_rel, access)?;
    if is_root_authority && lex_rel_opt.as_deref() != Some("AGENTS.md") {
        return Err(PathViolation {
            code: "UNAUTHORIZED_INSTRUCTION_FILE",
            detail: format!(
                "Symlink alias '{trimmed}' pointing to root 'AGENTS.md' is forbidden; access root 'AGENTS.md' directly."
            ),
            is_poisoned_zone: true,
        });
    }

    // 6. Enforce Control-Plane Immutability on Writes
    if access == PathAccess::Write {
        check_immutable_control_plane(&repo_rel)?;
    }

    // 7. Block reading lockfiles & minified bundles that saturate context windows
    if access == PathAccess::Read {
        check_lockfile_or_bundle(&repo_rel)?;
    }

    Ok(ValidatedPath {
        canonical_or_norm: resolved,
        repo_rel,
        is_root_authority,
    })
}

/// Validates a `Glob` or search filter pattern (`**/*.rs`, `crates/**`, `a/b/c/*.rs`) so
/// ergonomic workspace searches work smoothly while outside-repo paths, symlink escapes,
/// brace-expanded forbidden zones (`node_modules`, `target`, `build`, `.cache`, `tmp`),
/// and shadow instruction files are rejected deterministically.
pub fn validate_workspace_glob_pattern(
    repo_root: &Path,
    cwd: &Path,
    base_raw_path: &str,
    pat: &str,
) -> Result<(), PathViolation> {
    let trimmed = pat.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    if trimmed.contains('\n') || trimmed.contains('\r') || trimmed.contains('\0') {
        return Err(PathViolation {
            code: "PATH_CONTROL_INJECTION",
            detail: "Control or newline character inside glob pattern rejected".to_string(),
            is_poisoned_zone: false,
        });
    }

    let unicode_issues = scan_unicode(trimmed, ScanMode::StrictPathOrCommand);
    if let Some(first) = unicode_issues.first() {
        return Err(PathViolation {
            code: first.code,
            detail: format!(
                "Glob pattern '{}' failed Unicode check: {}",
                trimmed, first.detail
            ),
            is_poisoned_zone: false,
        });
    }

    let expanded = expand_tilde(trimmed);
    check_forbidden_zones_lexical(&expanded, trimmed)?;

    let norm_slashes = expanded.replace('\\', "/");
    for seg in norm_slashes.split('/').filter(|s| !s.is_empty()) {
        if seg.contains('{') || seg.contains('}') {
            for alt in seg
                .split(['{', ',', '}'])
                .map(str::trim)
                .filter(|s| !s.is_empty() && *s != "*" && *s != "**")
            {
                check_forbidden_zones_lexical(alt, trimmed)?;
            }
        }
    }

    let base_dir = if Path::new(base_raw_path).is_absolute() {
        PathBuf::from(base_raw_path)
    } else {
        cwd.join(base_raw_path)
    };

    let meta_pos = norm_slashes.find(['*', '?', '[', '{']);
    let Some(pos) = meta_pos else {
        validate_path(
            repo_root,
            &base_dir,
            &expanded,
            PathAccess::ReferencePointer,
        )?;
        return Ok(());
    };

    let after_meta = &norm_slashes[pos..];
    if after_meta.split('/').any(|seg| seg == "..") {
        return Err(PathViolation {
            code: "MAX_TRAVERSAL_DEPTH_EXCEEDED",
            detail: format!(
                "Glob pattern '{trimmed}' contains parent-directory '..' traversal after wildcards"
            ),
            is_poisoned_zone: false,
        });
    }

    let before_meta = &norm_slashes[..pos];
    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| lexical_normalize(repo_root));
    let lex_repo = lexical_normalize(repo_root);

    if norm_slashes.starts_with('/') {
        let dir_prefix = match before_meta.rfind('/') {
            Some(0) | None => "/",
            Some(idx) => &before_meta[..idx],
        };
        validate_path(repo_root, cwd, dir_prefix, PathAccess::ReferencePointer)?;

        let abs_pat = Path::new(&norm_slashes);
        if let Some(rel_after_repo) = abs_pat
            .strip_prefix(&canon_repo)
            .ok()
            .or_else(|| abs_pat.strip_prefix(&lex_repo).ok())
            .map(path_to_slash_string)
        {
            check_repo_build_artifact_segments(&canon_repo, &rel_after_repo, trimmed)?;
            check_glob_shadow_authority(&rel_after_repo, true)?;
        }
    } else {
        let dir_prefix = match before_meta.rfind('/') {
            Some(idx) => &before_meta[..idx],
            None => "",
        };
        if !dir_prefix.is_empty() {
            let v = validate_path(
                repo_root,
                &base_dir,
                dir_prefix,
                PathAccess::ReferencePointer,
            )?;
            let eff_rel = if v.repo_rel.is_empty() {
                norm_slashes.clone()
            } else {
                format!("{}/{}", v.repo_rel, &norm_slashes[pos..])
            };
            check_repo_build_artifact_segments(&canon_repo, &eff_rel, trimmed)?;
            let has_subdir_or_slash = !v.repo_rel.is_empty() || norm_slashes.contains('/');
            check_glob_shadow_authority(&norm_slashes, has_subdir_or_slash)?;
        } else {
            let base_valid =
                validate_path(repo_root, cwd, base_raw_path, PathAccess::ReferencePointer)?;
            let eff_rel = if base_valid.repo_rel.is_empty() {
                norm_slashes.clone()
            } else {
                format!("{}/{}", base_valid.repo_rel, norm_slashes)
            };
            check_repo_build_artifact_segments(&canon_repo, &eff_rel, trimmed)?;
            let has_subdir_or_slash = !base_valid.repo_rel.is_empty() || norm_slashes.contains('/');
            check_glob_shadow_authority(&norm_slashes, has_subdir_or_slash)?;
        }
    }

    Ok(())
}

fn check_glob_shadow_authority(
    pat_slashes: &str,
    has_subdir_or_slash: bool,
) -> Result<(), PathViolation> {
    let lower = pat_slashes.to_ascii_lowercase();
    let debracketed = lower.replace(['[', ']'], "");
    let raw_tail = debracketed.rsplit('/').next().unwrap_or(&debracketed);

    // Expand brace alternatives in tail (e.g. `claude.{md,txt}` -> `claude.md`, `claude.txt`)
    let tail_candidates: Vec<String> = if let (Some(open), Some(close)) =
        (raw_tail.find('{'), raw_tail.rfind('}'))
        && open < close
    {
        let prefix = &raw_tail[..open];
        let suffix = &raw_tail[close + 1..];
        raw_tail[open + 1..close]
            .split(',')
            .map(|alt| format!("{prefix}{}{suffix}", alt.trim()))
            .collect()
    } else {
        vec![raw_tail.to_string()]
    };

    let path_targets_rules_dir = debracketed.starts_with(".cursor/rules/")
        || debracketed.contains("/.cursor/rules/")
        || debracketed.starts_with(".claude/rules/")
        || debracketed.contains("/.claude/rules/")
        || debracketed.starts_with(".github/instructions/")
        || debracketed.contains("/.github/instructions/");

    let is_shadow = path_targets_rules_dir
        || tail_candidates.iter().any(|cand| {
            let stripped = cand.trim_matches(['*', '?']);
            matches!(
                cand.as_str(),
                "agents.override.md"
                    | "claude.md"
                    | "claude.local.md"
                    | "gemini.md"
                    | ".cursorrules"
                    | ".windsurfrules"
                    | ".clinerules"
                    | ".roorules"
                    | "copilot-instructions.md"
                    | ".aider.conf.yml"
            ) || matches!(
                stripped,
                "agents.override.md"
                    | "agents.override"
                    | "claude.md"
                    | "claude.local.md"
                    | "claude.local"
                    | "gemini.md"
                    | ".cursorrules"
                    | ".windsurfrules"
                    | ".clinerules"
                    | ".roorules"
                    | "copilot-instructions.md"
                    | "copilot-instructions"
                    | ".aider.conf.yml"
                    | ".aider.conf"
            ) || cand.ends_with(".instructions.md")
                || (cand == "agents.md" && has_subdir_or_slash)
                || (stripped == "agents.md" && (has_subdir_or_slash || cand != "agents.md"))
        });

    if is_shadow {
        return Err(PathViolation {
            code: "UNAUTHORIZED_INSTRUCTION_FILE",
            detail: format!(
                "Glob pattern '{pat_slashes}' targets unauthorized shadow/nested instruction files."
            ),
            is_poisoned_zone: true,
        });
    }
    Ok(())
}

fn expand_tilde(raw: &str) -> String {
    if raw == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return home;
        }
    } else if let Some(rest) = raw.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}/{rest}", home.trim_end_matches('/'));
        }
    }
    raw.to_string()
}

pub fn check_forbidden_zones_lexical(
    path_str: &str,
    display_raw: &str,
) -> Result<(), PathViolation> {
    let normalized_slashes = path_str.replace('\\', "/");
    let lower = normalized_slashes.to_ascii_lowercase();

    // System temp & shared-memory prefixes
    const TMP_PREFIXES: &[&str] = &[
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/run/user",
        "/private/tmp",
        "/private/var/tmp",
    ];
    for prefix in TMP_PREFIXES {
        if lower == *prefix || lower.starts_with(&format!("{prefix}/")) {
            return Err(PathViolation {
                code: "FORBIDDEN_TMP_PATH",
                detail: format!(
                    "Access to temporary directory '{display_raw}' is strictly forbidden."
                ),
                is_poisoned_zone: true,
            });
        }
    }

    // System secret / proxy / procfs prefixes
    const SYSTEM_SECRET_PREFIXES: &[&str] = &[
        "/proc/self/environ",
        "/var/lib/agy-plugin-proxy",
        "/etc/shadow",
        "/etc/gshadow",
    ];
    for prefix in SYSTEM_SECRET_PREFIXES {
        if lower == *prefix || lower.starts_with(&format!("{prefix}/")) {
            return Err(PathViolation {
                code: "FORBIDDEN_SECRET_PATH",
                detail: format!("Access to sensitive system path '{display_raw}' is forbidden."),
                is_poisoned_zone: true,
            });
        }
    }
    if lower.starts_with("/proc/") && lower.ends_with("/environ") {
        return Err(PathViolation {
            code: "FORBIDDEN_SECRET_PATH",
            detail: format!("Reading process environment '{display_raw}' is forbidden."),
            is_poisoned_zone: true,
        });
    }

    let segments: Vec<&str> = normalized_slashes
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();

    for (idx, seg) in segments.iter().enumerate() {
        let seg_lower = seg.to_ascii_lowercase();

        // Temp directory segments anywhere in path
        if matches!(seg_lower.as_str(), "tmp" | ".tmp" | "temp" | ".temp") {
            return Err(PathViolation {
                code: "FORBIDDEN_TMP_PATH",
                detail: format!(
                    "Access to temp folder segment '{seg}' in '{display_raw}' is forbidden."
                ),
                is_poisoned_zone: true,
            });
        }

        // Cache directory segments anywhere in path
        if is_cache_segment(&seg_lower) {
            return Err(PathViolation {
                code: "FORBIDDEN_CACHE_PATH",
                detail: format!("Access to cache folder '{seg}' in '{display_raw}' is forbidden."),
                is_poisoned_zone: true,
            });
        }

        // `~/.cargo/registry` or `~/.cargo/git` or `Library/Caches`
        if seg_lower == ".cargo" {
            if let Some(next) = segments.get(idx + 1) {
                let nl = next.to_ascii_lowercase();
                if nl == "registry" || nl == "git" {
                    return Err(PathViolation {
                        code: "FORBIDDEN_CACHE_PATH",
                        detail: format!(
                            "Access to Cargo registry/git cache in '{display_raw}' is forbidden."
                        ),
                        is_poisoned_zone: true,
                    });
                }
            }
        }
        if seg_lower == "library"
            && segments
                .get(idx + 1)
                .is_some_and(|n| n.eq_ignore_ascii_case("caches"))
        {
            return Err(PathViolation {
                code: "FORBIDDEN_CACHE_PATH",
                detail: format!("Access to macOS Library/Caches in '{display_raw}' is forbidden."),
                is_poisoned_zone: true,
            });
        }

        // Dependency / vendor / package folders
        if is_dependency_segment(&seg_lower) {
            return Err(PathViolation {
                code: "FORBIDDEN_DEPENDENCY_PATH",
                detail: format!(
                    "Snooping inside dependency folder '{seg}' in '{display_raw}' is strictly forbidden."
                ),
                is_poisoned_zone: true,
            });
        }
        // Rust `target/{debug,release}/deps` or `target/{debug,release}/build`
        if seg_lower == "target" {
            if let (Some(profile), Some(sub)) = (segments.get(idx + 1), segments.get(idx + 2)) {
                let pl = profile.to_ascii_lowercase();
                let sl = sub.to_ascii_lowercase();
                if matches!(pl.as_str(), "debug" | "release")
                    && matches!(sl.as_str(), "deps" | "build" | ".fingerprint")
                {
                    return Err(PathViolation {
                        code: "FORBIDDEN_DEPENDENCY_PATH",
                        detail: format!(
                            "Access to compiled dependency/cache artifact '{display_raw}' is forbidden."
                        ),
                        is_poisoned_zone: true,
                    });
                }
            }
        }
        if !Path::new(&normalized_slashes).is_absolute()
            && is_build_artifact_segment(&seg_lower)
            && (idx == 0 || (idx == 1 && segments[0] == "**"))
        {
            return Err(PathViolation {
                code: "FORBIDDEN_BUILD_ARTIFACT_PATH",
                detail: format!(
                    "Direct tool access inside build output directory '{seg}' ('{display_raw}') is forbidden; let build/test tools manage build artifacts."
                ),
                is_poisoned_zone: false,
            });
        }

        // Secret / credential directories & files
        if is_secret_segment(&seg_lower) {
            return Err(PathViolation {
                code: "FORBIDDEN_SECRET_PATH",
                detail: format!("Access to secret/credential path '{display_raw}' is forbidden."),
                is_poisoned_zone: true,
            });
        }
        if seg_lower == ".config"
            && segments
                .get(idx + 1)
                .is_some_and(|n| matches!(n.to_ascii_lowercase().as_str(), "gh" | "gcloud" | "op"))
        {
            return Err(PathViolation {
                code: "FORBIDDEN_SECRET_PATH",
                detail: format!("Access to CLI credential store '{display_raw}' is forbidden."),
                is_poisoned_zone: true,
            });
        }
        if seg_lower == ".git"
            && segments
                .get(idx + 1)
                .is_some_and(|n| matches!(n.to_ascii_lowercase().as_str(), "hooks" | "config"))
        {
            return Err(PathViolation {
                code: "FORBIDDEN_GIT_CONTROL_PATH",
                detail: format!(
                    "Access to '.git/hooks' or '.git/config' ('{display_raw}') is strictly forbidden."
                ),
                is_poisoned_zone: true,
            });
        }
        // Self-blindness: block reading or modifying agent-guard's own state ledger, swarm vault, hmac.key, spools, or audit.jsonl
        let next_seg = segments.get(idx + 1).copied().unwrap_or("");
        if seg_lower == ".agent-guard-state"
            || (seg_lower == "state" && next_seg.eq_ignore_ascii_case("agent-guard"))
            || (seg_lower == "agent-guard"
                && (next_seg.eq_ignore_ascii_case("swarm")
                    || next_seg.eq_ignore_ascii_case("sessions")
                    || next_seg.eq_ignore_ascii_case("vault")))
            || (seg_lower == "swarm"
                && (next_seg.eq_ignore_ascii_case("vault")
                    || next_seg.eq_ignore_ascii_case("sessions")
                    || next_seg.eq_ignore_ascii_case("spools")
                    || next_seg.eq_ignore_ascii_case("ipc")
                    || next_seg.eq_ignore_ascii_case("locks")))
            || seg_lower == "hmac.key"
            || seg_lower == "coord.sock"
            || seg_lower.ends_with(".spool")
            || seg_lower.ends_with(".spool.quarantine")
            || seg_lower == "audit.jsonl"
        {
            return Err(PathViolation {
                code: "FORBIDDEN_GUARD_STATE_PATH",
                detail: format!(
                    "Access to agent-guard internal state/vault/audit path '{display_raw}' is strictly forbidden (self-blindness enforcement)."
                ),
                is_poisoned_zone: true,
            });
        }
    }

    // Dynamic self-blindness on active `state_base_dir()` AND any enclosing `agent-guard`/`swarm` parent root
    let active_state = crate::traversal_ledger::state_base_dir();
    if active_state.is_absolute() {
        let mut protected_roots = vec![active_state.clone()];
        let mut anc = active_state.parent();
        while let Some(p) = anc {
            if let Some(name) = p.file_name().and_then(|s| s.to_str())
                && (name.eq_ignore_ascii_case("agent-guard")
                    || name.eq_ignore_ascii_case("swarm")
                    || name.eq_ignore_ascii_case(".agent-guard-state"))
            {
                protected_roots.push(p.to_path_buf());
            }
            anc = p.parent();
        }
        for root_dir in protected_roots {
            let state_slash = root_dir.to_string_lossy().replace('\\', "/");
            let state_lower = state_slash.trim_end_matches('/').to_ascii_lowercase();
            if !state_lower.is_empty()
                && (lower == state_lower || lower.starts_with(&format!("{state_lower}/")))
            {
                return Err(PathViolation {
                    code: "FORBIDDEN_GUARD_STATE_PATH",
                    detail: format!(
                        "Access to active agent-guard state directory '{display_raw}' is strictly forbidden (self-blindness enforcement)."
                    ),
                    is_poisoned_zone: true,
                });
            }
        }
    }

    Ok(())
}

pub fn check_repo_build_artifact_segments(
    repo_root: &Path,
    repo_rel: &str,
    display_raw: &str,
) -> Result<(), PathViolation> {
    let segs: Vec<&str> = repo_rel.split('/').filter(|s| !s.is_empty()).collect();
    let mut cur = repo_root.to_path_buf();
    for (idx, seg) in segs.iter().enumerate() {
        let seg_lower = seg.to_ascii_lowercase();
        if !seg.contains(['*', '?', '[', '{']) {
            cur.push(seg);
        }
        if is_build_artifact_segment(&seg_lower) {
            let is_root_build_dir = idx == 0 || (idx == 1 && segs[0] == "**");
            let has_build_marker = !seg.contains(['*', '?', '[', '{'])
                && (cur.join("CACHEDIR.TAG").is_file() || cur.join(".rustc_info.json").is_file());
            if is_root_build_dir || has_build_marker {
                return Err(PathViolation {
                    code: "FORBIDDEN_BUILD_ARTIFACT_PATH",
                    detail: format!(
                        "Direct tool access inside build output directory '{seg}' ('{display_raw}') is forbidden; let build/test tools manage build artifacts."
                    ),
                    is_poisoned_zone: false,
                });
            }
        }
    }
    Ok(())
}

pub fn is_build_artifact_segment(seg_lower: &str) -> bool {
    matches!(seg_lower, "target" | "build" | "dist-build")
}

fn is_cache_segment(seg_lower: &str) -> bool {
    matches!(
        seg_lower,
        ".cache"
            | "__pycache__"
            | ".pytest_cache"
            | ".mypy_cache"
            | ".ruff_cache"
            | ".hypothesis"
            | ".tox"
            | ".nox"
            | ".next"
            | ".nuxt"
            | ".turbo"
            | ".parcel-cache"
            | ".vite"
            | ".eslintcache"
            | ".stylelintcache"
            | ".angular"
            | ".svelte-kit"
            | ".docusaurus"
            | ".ccache"
            | ".sass-cache"
            | ".gradle"
            | ".m2"
            | ".ivy2"
            | ".sbt"
            | ".npm"
            | ".pnpm-store"
            | ".rustup"
    )
}

fn is_dependency_segment(seg_lower: &str) -> bool {
    matches!(
        seg_lower,
        "node_modules"
            | "bower_components"
            | "jspm_packages"
            | "vendor"
            | ".venv"
            | "venv"
            | "virtualenv"
            | "site-packages"
            | "dist-packages"
            | "__pypackages__"
            | ".pnpm"
            | ".yarn"
            | "pods"
            | "carthage"
            | ".bundle"
            | "elm-stuff"
            | "deps"
    )
}

fn is_secret_segment(seg_lower: &str) -> bool {
    if seg_lower.starts_with(".env") {
        return true;
    }
    if matches!(
        seg_lower,
        ".ssh"
            | ".aws"
            | ".gnupg"
            | ".kube"
            | ".netrc"
            | ".git-credentials"
            | ".gitcookies"
            | ".npmrc"
            | ".pypirc"
            | "id_rsa"
            | "id_ed25519"
            | "id_ecdsa"
            | "id_dsa"
    ) {
        return true;
    }
    if seg_lower.starts_with("id_rsa.")
        || seg_lower.starts_with("id_ed25519.")
        || seg_lower.starts_with("id_ecdsa.")
    {
        return true;
    }
    for ext in [".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx"] {
        if seg_lower.ends_with(ext) {
            return true;
        }
    }
    false
}

fn resolve_checking_symlinks(
    abs_path: &Path,
    canon_repo: &Path,
    repo_is_canon: bool,
) -> Result<PathBuf, PathViolation> {
    resolve_checking_symlinks_depth(abs_path, canon_repo, repo_is_canon, 0)
}

fn resolve_checking_symlinks_depth(
    abs_path: &Path,
    canon_repo: &Path,
    repo_is_canon: bool,
    symlink_depth: usize,
) -> Result<PathBuf, PathViolation> {
    if symlink_depth > 16 {
        return Err(PathViolation {
            code: "SYMLINK_LOOP_DEPTH_EXCEEDED",
            detail: format!(
                "Symlink resolution exceeded max depth (16) while validating '{}'",
                abs_path.display()
            ),
            is_poisoned_zone: true,
        });
    }

    let (mut acc, iter_path) = if repo_is_canon && let Ok(rel) = abs_path.strip_prefix(canon_repo) {
        (canon_repo.to_path_buf(), rel)
    } else {
        (PathBuf::new(), abs_path)
    };

    for comp in iter_path.components() {
        match comp {
            Component::RootDir => acc.push("/"),
            Component::Prefix(p) => acc.push(p.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                acc.pop();
            }
            Component::Normal(seg) => {
                acc.push(seg);
                if let Ok(meta) = fs::symlink_metadata(&acc) {
                    if meta.file_type().is_symlink() {
                        let target = fs::read_link(&acc).map_err(|e| PathViolation {
                            code: "SYMLINK_READ_ERROR",
                            detail: format!("Failed reading symlink '{}': {e}", acc.display()),
                            is_poisoned_zone: false,
                        })?;
                        // Check raw link target lexically first (catches broken symlink to `/tmp/payload`!)
                        check_forbidden_zones_lexical(
                            &target.to_string_lossy(),
                            &acc.to_string_lossy(),
                        )?;

                        let resolved_target = if target.is_absolute() {
                            target
                        } else {
                            let mut base = acc.clone();
                            base.pop();
                            base.join(target)
                        };

                        // Recursively walk `resolved_target` component-by-component so inner symlinks
                        // are resolved even when a trailing child component does not exist yet (`ENOENT`).
                        let canon_target = resolve_checking_symlinks_depth(
                            &resolved_target,
                            canon_repo,
                            repo_is_canon,
                            symlink_depth + 1,
                        )?;

                        check_forbidden_zones_lexical(
                            &canon_target.to_string_lossy(),
                            &acc.to_string_lossy(),
                        )?;

                        // Only enforce repo containment once inside repo_root (allow OS symlinks above repo_root if any)
                        if acc.starts_with(canon_repo) && !canon_target.starts_with(canon_repo) {
                            return Err(PathViolation {
                                code: "SYMLINK_BOUNDARY_ESCAPE",
                                detail: format!(
                                    "Symlink '{}' points outside repository root to '{}' (confused-deputy symlink escape blocked)",
                                    acc.display(),
                                    canon_target.display()
                                ),
                                is_poisoned_zone: true,
                            });
                        }
                        acc = canon_target;
                    }
                }
            }
        }
    }
    Ok(acc)
}

fn check_authority_file_policy(repo_rel: &str, access: PathAccess) -> Result<bool, PathViolation> {
    if repo_rel.is_empty() {
        return Ok(false);
    }

    // Exact root `AGENTS.md` is the ONLY permitted authority file in the repository
    if repo_rel == "AGENTS.md" {
        if access == PathAccess::Write {
            return Err(PathViolation {
                code: "IMMUTABLE_ROOT_AUTHORITY",
                detail: "Root 'AGENTS.md' is immutable to agents; propose changes in prose for human review."
                    .to_string(),
                is_poisoned_zone: false,
            });
        }
        return Ok(true);
    }

    let lower = repo_rel.to_ascii_lowercase();
    let file_name = lower.rsplit('/').next().unwrap_or(&lower);

    let is_shadow_or_nested_authority = matches!(
        file_name,
        "agents.md"
            | "agents.override.md"
            | "claude.md"
            | "claude.local.md"
            | "gemini.md"
            | ".cursorrules"
            | ".windsurfrules"
            | ".clinerules"
            | ".roorules"
            | "copilot-instructions.md"
            | ".aider.conf.yml"
    ) || file_name.ends_with(".instructions.md")
        || lower.starts_with(".cursor/rules/")
        || lower.contains("/.cursor/rules/")
        || lower.starts_with(".claude/rules/")
        || lower.contains("/.claude/rules/")
        || lower.starts_with(".github/instructions/")
        || lower.contains("/.github/instructions/");

    if is_shadow_or_nested_authority {
        return Err(PathViolation {
            code: "UNAUTHORIZED_INSTRUCTION_FILE",
            detail: format!(
                "Instruction file '{repo_rel}' is blocked: ONLY root 'AGENTS.md' is an authorized instruction source. All nested/shadow instruction files are untrusted."
            ),
            is_poisoned_zone: true,
        });
    }

    Ok(false)
}

fn check_immutable_control_plane(repo_rel: &str) -> Result<(), PathViolation> {
    let lower = repo_rel.to_ascii_lowercase();
    let file_name = lower.rsplit('/').next().unwrap_or(&lower);
    let protected_prefixes = [
        ".git/",
        ".guard/",
        ".agent-guard/",
        ".claude/",
        ".codex/",
        ".cursor/",
        ".gemini/",
        ".github/",
        ".cargo/",
        ".yarn/",
    ];
    for p in protected_prefixes {
        if lower == p.trim_end_matches('/')
            || lower.starts_with(p)
            || lower.contains(&format!("/{p}"))
        {
            return Err(PathViolation {
                code: "IMMUTABLE_CONTROL_PLANE",
                detail: format!(
                    "Modifying control-plane or build-runner path '{repo_rel}' is hard-blocked (self-tampering / build-hook prohibition)."
                ),
                is_poisoned_zone: false,
            });
        }
    }
    if matches!(
        lower.as_str(),
        "agents.md"
            | "review.md"
            | ".agent-policy.json"
            | ".gitconfig"
            | ".gitattributes"
            | ".envrc"
            | ".ignore"
            | ".rgignore"
            | ".cursorignore"
    ) || matches!(
        file_name,
        ".gitattributes"
            | ".envrc"
            | ".npmrc"
            | ".yarnrc"
            | ".yarnrc.yml"
            | ".pnpmfile.cjs"
            | "rust-toolchain"
            | "rust-toolchain.toml"
            | ".mise.toml"
            | ".tool-versions"
            | ".breadcrumbs.jsonl"
            | "plan.lock.json"
            | "work_ledger.jsonl"
    ) {
        return Err(PathViolation {
            code: "IMMUTABLE_CONTROL_PLANE",
            detail: format!(
                "Modifying protected execution/filter or swarm provenance file '{repo_rel}' directly is hard-blocked; use `swarm-tool`."
            ),
            is_poisoned_zone: false,
        });
    }
    Ok(())
}

fn check_lockfile_or_bundle(repo_rel: &str) -> Result<(), PathViolation> {
    let lower = repo_rel.to_ascii_lowercase();
    let file_name = lower.rsplit('/').next().unwrap_or(&lower);
    if matches!(
        file_name,
        "cargo.lock"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "bun.lockb"
            | "composer.lock"
            | "gemfile.lock"
            | "poetry.lock"
            | "uv.lock"
            | "pipfile.lock"
            | "flake.lock"
            | "go.sum"
    ) || (file_name != "plan.lock.json" && file_name.ends_with(".lock.json"))
        || file_name.ends_with(".min.js")
        || file_name.ends_with(".min.css")
        || file_name.ends_with(".js.map")
        || file_name.ends_with(".css.map")
        || file_name.ends_with(".wasm")
    {
        return Err(PathViolation {
            code: "LOCKFILE_OR_BUNDLE_BLOCKED",
            detail: format!(
                "Reading lockfile or compiled bundle '{repo_rel}' is blocked to prevent token exhaustion and dependency-metadata injection."
            ),
            is_poisoned_zone: false,
        });
    }
    Ok(())
}

pub fn lexical_normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn path_to_slash_string(p: &Path) -> String {
    let mut parts = Vec::new();
    for c in p.components() {
        if let Component::Normal(s) = c {
            parts.push(s.to_string_lossy().into_owned());
        }
    }
    parts.join("/")
}

#[cfg(test)]
mod tests {
    use super::{PathAccess, check_forbidden_zones_lexical, validate_path};
    use std::path::Path;

    #[test]
    fn blocks_tmp_cache_and_node_modules() {
        assert!(check_forbidden_zones_lexical("/tmp/foo.txt", "/tmp/foo.txt").is_err());
        assert!(check_forbidden_zones_lexical("packages/a/node_modules/x/index.js", "nm").is_err());
        assert!(check_forbidden_zones_lexical(".cache/data.json", ".cache").is_err());
        assert!(check_forbidden_zones_lexical(".env.production", ".env").is_err());
    }

    #[test]
    fn enforces_root_only_agents_md() {
        let cwd = std::env::current_dir().expect("cwd");
        assert!(
            validate_path(&cwd, &cwd, "AGENTS.md", PathAccess::Read)
                .expect("root AGENTS.md read")
                .is_root_authority
        );
        assert!(validate_path(&cwd, &cwd, "AGENTS.md", PathAccess::Write).is_err());
        assert!(validate_path(&cwd, &cwd, "subdir/AGENTS.md", PathAccess::Read).is_err());
        assert!(validate_path(&cwd, &cwd, "CLAUDE.md", PathAccess::Read).is_err());
        assert!(validate_path(&cwd, &cwd, ".cursorrules", PathAccess::Read).is_err());
        assert!(
            validate_path(
                &cwd,
                Path::new(&cwd),
                ".github/copilot-instructions.md",
                PathAccess::Read
            )
            .is_err()
        );
    }
}
