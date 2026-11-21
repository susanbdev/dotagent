#![forbid(unsafe_code)]

//! Anti-token-exhaustion and anti-context-window-saturation guard.
//! Protects LLM context windows and KV caches from:
//! - Oversized files (> 64 KB un-sliced) and streaming /dev/zero style memory bombs
//! - Minified / base64 single-line bombs (> 2,048 bytes on one line)
//! - Unbounded multi-hundred-line dumps (> 500 lines without explicit limit <= 200)
//! - Adversarial BPE tokenizer splitter bombs (~1 byte = 1 token high-density symbols/UTF-8)
//! - Repetitive token stuffing & cumulative per-turn context exhaustion

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

pub const MAX_RAW_FILE_BYTES: u64 = 24_576; // 24 KiB max un-sliced read (tiny context micro-window)
pub const MAX_SLICED_FILE_BYTES: u64 = 1_048_576; // 1 MiB absolute ceiling even when sliced
pub const MAX_SLICE_LINES: usize = 150;
pub const MAX_UNSLICED_LINES: usize = 300;
pub const MAX_SINGLE_LINE_BYTES: usize = 2_048;
pub const MAX_TOOL_OUTPUT_BYTES: usize = 16_384; // 16 KiB dynamic tool stdout cap
pub const STEP_SOFT_COMPACT_TOKENS: usize = 8_000; // Soft step threshold -> trigger immediate compaction
pub const MAX_TURN_TOKENS: usize = 16_000; // Hard per-step untrusted token ceiling
pub const MAX_TURN_FILE_READS: usize = 18;
pub const MAX_TURN_TOOL_CALLS: usize = 28;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentMetrics {
    pub byte_len: usize,
    pub line_count: usize,
    pub max_line_bytes: usize,
    pub estimated_tokens: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetViolation {
    pub code: &'static str,
    pub detail: String,
}

/// Validates on-disk hygiene after `Write`/`Edit` (regular file, `<= 1 MiB`, no NUL bytes,
/// valid UTF-8, no single-line or repetition bombs) without applying the `24 KiB` LLM
/// context-read cap so legitimate multi-hundred-line source files remain editable.
pub fn inspect_file_on_disk_hygiene(path: &Path) -> Result<String, BudgetViolation> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| BudgetViolation {
        code: "FILE_STAT_ERROR",
        detail: format!("Cannot stat '{}': {e}", path.display()),
    })?;

    if !meta.file_type().is_file() {
        return Err(BudgetViolation {
            code: "NON_REGULAR_FILE",
            detail: format!(
                "Refusing non-regular file '{}' (FIFO/socket/device/symlink blocked)",
                path.display()
            ),
        });
    }

    let file_len = meta.len();
    if file_len > MAX_SLICED_FILE_BYTES {
        return Err(BudgetViolation {
            code: "FILE_ABSOLUTE_SIZE_EXCEEDED",
            detail: format!(
                "File '{}' is {file_len} bytes (> {MAX_SLICED_FILE_BYTES} byte safety ceiling).",
                path.display()
            ),
        });
    }

    let cap = (MAX_SLICED_FILE_BYTES as usize) + 1;
    let file = File::open(path).map_err(|e| BudgetViolation {
        code: "FILE_OPEN_ERROR",
        detail: format!("Cannot open '{}': {e}", path.display()),
    })?;
    let fd_meta = file.metadata().map_err(|e| BudgetViolation {
        code: "FILE_STAT_ERROR",
        detail: format!("Cannot fstat '{}': {e}", path.display()),
    })?;
    if !fd_meta.file_type().is_file() || fd_meta.len() > MAX_SLICED_FILE_BYTES {
        return Err(BudgetViolation {
            code: "FILE_TOCTOU_REJECTED",
            detail: format!(
                "Opened descriptor for '{}' failed regular-file or size check (TOCTOU swap blocked).",
                path.display()
            ),
        });
    }

    let mut raw = Vec::new();
    file.take(cap as u64)
        .read_to_end(&mut raw)
        .map_err(|e| BudgetViolation {
            code: "FILE_READ_ERROR",
            detail: format!("Cannot read '{}': {e}", path.display()),
        })?;

    if raw.contains(&0u8) {
        return Err(BudgetViolation {
            code: "BINARY_FILE_BLOCKED",
            detail: format!(
                "Binary file '{}' (contains NUL bytes) rejected.",
                path.display()
            ),
        });
    }

    let text = String::from_utf8(raw).map_err(|_| BudgetViolation {
        code: "INVALID_UTF8_BLOCKED",
        detail: format!("Non-UTF-8 file '{}' rejected.", path.display()),
    })?;

    for (idx, line) in text.split('\n').enumerate() {
        if line.len() > MAX_SINGLE_LINE_BYTES {
            return Err(BudgetViolation {
                code: "SINGLE_LINE_BOMB_BLOCKED",
                detail: format!(
                    "Line {} is {} bytes (> {MAX_SINGLE_LINE_BYTES} byte ceiling — minified/base64 bomb blocked).",
                    idx + 1,
                    line.len()
                ),
            });
        }
    }

    if has_pathological_run(&text) {
        return Err(BudgetViolation {
            code: "REPETITION_SATURATION_BOMB",
            detail: "Pathological repeated character/token run detected.".to_string(),
        });
    }

    Ok(text)
}

pub const MAX_VETTED_WEBFONT_BYTES: u64 = 65_536; // 64 KiB cap for subset `.woff2`/`.woff` glyph atlases

/// Validates bounded, magic-verified `.woff2` (`wOF2`) and `.woff` (`wOFF`) static webfont
/// assets during `post-edit` so UI libraries (such as `vespoli-ui`'s `< 2 KB` glyph font)
/// can persist valid font assets on disk while keeping binary context-ingestion hard-blocked.
/// Returns `None` when `path` does not carry a `.woff2`/`.woff` extension.
pub fn inspect_vetted_webfont_asset_on_disk(
    path: &Path,
) -> Option<Result<Vec<u8>, BudgetViolation>> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())?;
    let expected_magic: &[u8; 4] = match ext.as_str() {
        "woff2" => b"wOF2",
        "woff" => b"wOFF",
        _ => return None,
    };

    let check = || -> Result<Vec<u8>, BudgetViolation> {
        let meta = std::fs::symlink_metadata(path).map_err(|e| BudgetViolation {
            code: "FILE_STAT_ERROR",
            detail: format!("Cannot stat '{}': {e}", path.display()),
        })?;
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            return Err(BudgetViolation {
                code: "NON_REGULAR_FILE",
                detail: format!(
                    "Refusing non-regular webfont file '{}' (FIFO/socket/device/symlink blocked)",
                    path.display()
                ),
            });
        }
        if meta.len() > MAX_VETTED_WEBFONT_BYTES {
            return Err(BudgetViolation {
                code: "WEBFONT_SIZE_EXCEEDED",
                detail: format!(
                    "Webfont asset '{}' is {} bytes (> {MAX_VETTED_WEBFONT_BYTES} byte subset glyph ceiling).",
                    path.display(),
                    meta.len()
                ),
            });
        }

        let file = File::open(path).map_err(|e| BudgetViolation {
            code: "FILE_OPEN_ERROR",
            detail: format!("Cannot open '{}': {e}", path.display()),
        })?;
        let fd_meta = file.metadata().map_err(|e| BudgetViolation {
            code: "FILE_STAT_ERROR",
            detail: format!("Cannot fstat '{}': {e}", path.display()),
        })?;
        if !fd_meta.file_type().is_file() || fd_meta.len() > MAX_VETTED_WEBFONT_BYTES {
            return Err(BudgetViolation {
                code: "FILE_TOCTOU_REJECTED",
                detail: format!(
                    "Opened descriptor for '{}' failed regular-file or webfont size check.",
                    path.display()
                ),
            });
        }

        let mut raw = Vec::new();
        file.take(MAX_VETTED_WEBFONT_BYTES + 1)
            .read_to_end(&mut raw)
            .map_err(|e| BudgetViolation {
                code: "FILE_READ_ERROR",
                detail: format!("Cannot read '{}': {e}", path.display()),
            })?;
        if raw.len() < 44 || &raw[..4] != expected_magic {
            return Err(BudgetViolation {
                code: "INVALID_WEBFONT_MAGIC",
                detail: format!(
                    "File '{}' carries '.{ext}' extension without valid WOFF/WOFF2 header signature.",
                    path.display()
                ),
            });
        }
        Ok(raw)
    };

    Some(check())
}

/// Safely reads up to `MAX_RAW_FILE_BYTES + 1` (or bounded slice) using `Read::take`
/// so a multi-gigabyte file or special device can never OOM the guard itself.
pub fn inspect_file_budget(
    path: &Path,
    offset_line: Option<usize>,
    limit_lines: Option<usize>,
) -> Result<(String, ContentMetrics), BudgetViolation> {
    inspect_file_budget_with_limits(
        path,
        offset_line,
        limit_lines,
        MAX_SLICE_LINES,
        MAX_RAW_FILE_BYTES,
        MAX_UNSLICED_LINES,
    )
}

pub fn inspect_file_budget_with_limits(
    path: &Path,
    offset_line: Option<usize>,
    limit_lines: Option<usize>,
    max_slice_lines: usize,
    max_raw_bytes: u64,
    max_unsliced_lines: usize,
) -> Result<(String, ContentMetrics), BudgetViolation> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| BudgetViolation {
        code: "FILE_STAT_ERROR",
        detail: format!("Cannot stat '{}': {e}", path.display()),
    })?;

    if !meta.file_type().is_file() {
        return Err(BudgetViolation {
            code: "NON_REGULAR_FILE",
            detail: format!(
                "Refusing to read non-regular file '{}' (FIFO/socket/device/symlink blocked)",
                path.display()
            ),
        });
    }

    let file_len = meta.len();
    let has_bounded_slice = limit_lines.is_some_and(|l| l > 0 && l <= max_slice_lines);

    if !has_bounded_slice && file_len > max_raw_bytes {
        return Err(BudgetViolation {
            code: "FILE_BYTE_BUDGET_EXCEEDED",
            detail: format!(
                "File '{}' is {file_len} bytes (> {max_raw_bytes} byte limit). Request a bounded line range (<= {max_slice_lines} lines) to prevent context window saturation.",
                path.display()
            ),
        });
    }

    if file_len > MAX_SLICED_FILE_BYTES {
        return Err(BudgetViolation {
            code: "FILE_ABSOLUTE_SIZE_EXCEEDED",
            detail: format!(
                "File '{}' is {file_len} bytes (> {MAX_SLICED_FILE_BYTES} byte absolute safety ceiling); skipped to prevent token/memory exhaustion.",
                path.display()
            ),
        });
    }

    let cap = (MAX_SLICED_FILE_BYTES as usize) + 1;
    let file = File::open(path).map_err(|e| BudgetViolation {
        code: "FILE_OPEN_ERROR",
        detail: format!("Cannot open '{}': {e}", path.display()),
    })?;

    let mut raw = Vec::new();
    file.take(cap as u64)
        .read_to_end(&mut raw)
        .map_err(|e| BudgetViolation {
            code: "FILE_READ_ERROR",
            detail: format!("Cannot read '{}': {e}", path.display()),
        })?;

    if raw.contains(&0u8) {
        return Err(BudgetViolation {
            code: "BINARY_FILE_BLOCKED",
            detail: format!(
                "Binary file '{}' (contains NUL bytes) blocked from entering LLM context.",
                path.display()
            ),
        });
    }

    let full_text = String::from_utf8(raw).map_err(|_| BudgetViolation {
        code: "INVALID_UTF8_BLOCKED",
        detail: format!(
            "Non-UTF-8 file '{}' blocked from entering LLM context.",
            path.display()
        ),
    })?;

    let inspected_text = if has_bounded_slice {
        let start = offset_line.unwrap_or(1).saturating_sub(1);
        let count = limit_lines.unwrap_or(max_slice_lines);
        let mut sliced = String::new();
        for (idx, line) in full_text.lines().skip(start).take(count).enumerate() {
            if idx > 0 {
                sliced.push('\n');
            }
            sliced.push_str(line);
        }
        sliced
    } else {
        full_text
    };

    let metrics = analyze_text_budget_with_limits(
        &inspected_text,
        !has_bounded_slice,
        max_raw_bytes,
        max_unsliced_lines,
        max_slice_lines,
    )?;
    Ok((inspected_text, metrics))
}

pub fn analyze_text_budget(
    text: &str,
    enforce_unsliced_line_cap: bool,
) -> Result<ContentMetrics, BudgetViolation> {
    analyze_text_budget_with_limits(
        text,
        enforce_unsliced_line_cap,
        MAX_RAW_FILE_BYTES,
        MAX_UNSLICED_LINES,
        MAX_SLICE_LINES,
    )
}

pub fn analyze_text_budget_with_limits(
    text: &str,
    enforce_unsliced_line_cap: bool,
    max_raw_bytes: u64,
    max_unsliced_lines: usize,
    max_slice_lines: usize,
) -> Result<ContentMetrics, BudgetViolation> {
    if text.len() > max_raw_bytes as usize {
        return Err(BudgetViolation {
            code: "CONTENT_BYTE_BUDGET_EXCEEDED",
            detail: format!(
                "Content payload is {} bytes (> {max_raw_bytes} byte context-saturation ceiling).",
                text.len(),
            ),
        });
    }

    let mut line_count = 0usize;
    let mut max_line_bytes = 0usize;
    for line in text.split('\n') {
        line_count += 1;
        if line.len() > max_line_bytes {
            max_line_bytes = line.len();
        }
        if line.len() > MAX_SINGLE_LINE_BYTES {
            return Err(BudgetViolation {
                code: "SINGLE_LINE_BOMB_BLOCKED",
                detail: format!(
                    "Line {line_count} is {} bytes (> {MAX_SINGLE_LINE_BYTES} byte ceiling — minified/base64/token-stuffing bomb blocked).",
                    line.len()
                ),
            });
        }
    }

    if enforce_unsliced_line_cap && line_count > max_unsliced_lines {
        return Err(BudgetViolation {
            code: "LINE_COUNT_BUDGET_EXCEEDED",
            detail: format!(
                "Content has {line_count} lines (> {max_unsliced_lines} unsliced line limit). Read bounded slices (<= {max_slice_lines} lines).",
            ),
        });
    }

    let estimated_tokens = estimate_bpe_tokens(text);

    // Adversarial BPE tokenizer density bomb heuristic:
    // Normal code/prose averages ~0.22 - 0.38 tokens/byte.
    // Adversarial symbol/UTF-8 BPE splitter strings push > 0.72 tokens/byte.
    if text.len() >= 512 {
        let ratio = (estimated_tokens as f64) / (text.len() as f64);
        if ratio > 0.72 {
            return Err(BudgetViolation {
                code: "TOKENIZER_SPLITTER_BOMB",
                detail: format!(
                    "Abnormal BPE token density ({estimated_tokens} est. tokens in {} bytes, ratio {ratio:.2}) — adversarial token-exhaustion payload blocked.",
                    text.len()
                ),
            });
        }
    }

    // Repetitive character/symbol flood check (e.g., 512+ identical non-space punctuation chars)
    if has_pathological_run(text) {
        return Err(BudgetViolation {
            code: "REPETITION_SATURATION_BOMB",
            detail:
                "Pathological repeated character/token run detected (context saturation defense)."
                    .to_string(),
        });
    }

    Ok(ContentMetrics {
        byte_len: text.len(),
        line_count,
        max_line_bytes,
        estimated_tokens,
    })
}

/// Conservative BPE token estimator accounting for alphanumeric runs vs
/// punctuation/operator/non-ASCII UTF-8 token splits.
pub fn estimate_bpe_tokens(text: &str) -> usize {
    let mut tokens = 0usize;
    let mut alnum_run = 0usize;

    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            alnum_run += 1;
            if alnum_run == 4 {
                tokens += 1;
                alnum_run = 0;
            }
        } else {
            if alnum_run > 0 {
                tokens += 1;
                alnum_run = 0;
            }
            if ch.is_ascii_whitespace() {
                // Whitespace typically merges with adjacent BPE token unless repeated
                continue;
            } else if ch.is_ascii() {
                // Every ASCII punctuation/operator symbol often becomes its own token when ungrouped
                tokens += 1;
            } else {
                // Multi-byte UTF-8 characters frequently split into 1-3 BPE byte-fallback tokens
                tokens += ch.len_utf8().min(2);
            }
        }
    }
    if alnum_run > 0 {
        tokens += 1;
    }
    tokens.max(usize::from(!text.is_empty()))
}

fn has_pathological_run(text: &str) -> bool {
    let mut last: Option<char> = None;
    let mut run = 0usize;
    for ch in text.chars() {
        if ch == ' ' || ch == '\n' || ch == '\t' {
            last = None;
            run = 0;
            continue;
        }
        if Some(ch) == last {
            run += 1;
            if run >= 300 {
                return true;
            }
        } else {
            last = Some(ch);
            run = 1;
        }
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeProfile {
    pub profile_id: String,
    pub enable_write_tools: bool,
    pub write_scope_none: bool,
    pub network_access_none: bool,
    pub max_raw_file_bytes: u64,
    pub max_slice_lines: usize,
    pub max_single_line_bytes: usize,
    pub max_turn_tokens: usize,
    pub max_turn_file_reads: usize,
    pub max_turn_tool_calls: usize,
    pub max_direct_discovery_calls: usize,
    pub max_return_summary_ascii_tokens: Option<usize>,
}

pub const DEFAULT_MAX_DIRECT_DISCOVERY_CALLS: usize = 4;

impl RuntimeProfile {
    pub fn coding_agent_default() -> Self {
        Self {
            profile_id: "coding-agent".to_string(),
            enable_write_tools: true,
            write_scope_none: false,
            network_access_none: false,
            max_raw_file_bytes: MAX_RAW_FILE_BYTES,
            max_slice_lines: MAX_SLICE_LINES,
            max_single_line_bytes: MAX_SINGLE_LINE_BYTES,
            max_turn_tokens: MAX_TURN_TOKENS,
            max_turn_file_reads: MAX_TURN_FILE_READS,
            max_turn_tool_calls: MAX_TURN_TOOL_CALLS,
            max_direct_discovery_calls: DEFAULT_MAX_DIRECT_DISCOVERY_CALLS,
            max_return_summary_ascii_tokens: Some(200),
        }
    }

    pub fn research_readonly_default() -> Self {
        Self {
            profile_id: "research-readonly".to_string(),
            enable_write_tools: false,
            write_scope_none: true,
            network_access_none: true,
            max_raw_file_bytes: MAX_RAW_FILE_BYTES,
            max_slice_lines: MAX_SLICE_LINES,
            max_single_line_bytes: MAX_SINGLE_LINE_BYTES,
            max_turn_tokens: 12_000,
            max_turn_file_reads: MAX_TURN_FILE_READS,
            max_turn_tool_calls: MAX_TURN_TOOL_CALLS,
            max_direct_discovery_calls: MAX_TURN_TOOL_CALLS,
            max_return_summary_ascii_tokens: Some(200),
        }
    }

    pub fn apply_elevated_lease(&mut self) {
        self.max_slice_lines = 2_000;
        self.max_raw_file_bytes = 262_144;
        self.max_turn_tokens = 64_000;
        self.max_turn_file_reads = 120;
        self.max_turn_tool_calls = 120;
        self.max_direct_discovery_calls = 120;
        self.max_return_summary_ascii_tokens = Some(2_000);
    }
}

/// Loads and enforces the active runtime profile (`AGENT_GUARD_PROFILE`, defaulting to
/// `coding-agent`), reading `profiles/<id>.toml` when present inside `repo_root` without
/// following symlinks and clamping every parsed limit to the canonical hard ceiling so a
/// workspace file can tighten (or match) limits but never loosen kernel invariants.
pub fn load_active_profile(repo_root: &Path) -> Result<RuntimeProfile, BudgetViolation> {
    let raw_id = std::env::var("AGENT_GUARD_PROFILE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "coding-agent".to_string());

    load_profile_by_id(repo_root, &raw_id)
}

#[derive(Clone)]
struct CachedProfile {
    repo_root: PathBuf,
    profile_id: String,
    mtime_nanos: u128,
    file_len: u64,
    profile: RuntimeProfile,
}

static PROFILE_CACHE: Mutex<Option<CachedProfile>> = Mutex::new(None);

pub fn load_profile_by_id(
    repo_root: &Path,
    profile_id: &str,
) -> Result<RuntimeProfile, BudgetViolation> {
    let mut profile = match profile_id {
        "coding-agent" | "swarm-grunt" | "swarm-qa-engineer" => {
            let mut p = RuntimeProfile::coding_agent_default();
            p.profile_id = profile_id.to_string();
            p
        }
        "research-readonly"
        | "adversarial-reviewer"
        | "swarm-master"
        | "swarm-investigator"
        | "swarm-adversarial-reviewer"
        | "swarm-forensic-coroner" => {
            let mut p = RuntimeProfile::research_readonly_default();
            p.profile_id = profile_id.to_string();
            if profile_id == "adversarial-reviewer" {
                p.max_turn_tokens = MAX_TURN_TOKENS;
            }
            p
        }
        other => {
            return Err(BudgetViolation {
                code: "UNKNOWN_RUNTIME_PROFILE",
                detail: format!(
                    "Unrecognized AGENT_GUARD_PROFILE '{other}' (expected 'coding-agent', 'research-readonly', 'adversarial-reviewer', or 'swarm-*')."
                ),
            });
        }
    };

    let profiles_dir = repo_root.join("profiles");
    if let Ok(dir_meta) = std::fs::symlink_metadata(&profiles_dir) {
        if dir_meta.file_type().is_symlink() {
            return Err(BudgetViolation {
                code: "SYMLINKED_PROFILE_BLOCKED",
                detail: "profiles/ directory must not be a symlink.".to_string(),
            });
        }
        let toml_path = profiles_dir.join(format!("{profile_id}.toml"));
        if let Ok(meta) = std::fs::symlink_metadata(&toml_path) {
            if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                return Err(BudgetViolation {
                    code: "SYMLINKED_PROFILE_BLOCKED",
                    detail: format!(
                        "Profile '{}' must be a regular non-symlink file.",
                        toml_path.display()
                    ),
                });
            }
            if meta.len() > 16_384 {
                return Err(BudgetViolation {
                    code: "OVERSIZED_PROFILE_BLOCKED",
                    detail: format!("Profile '{}' exceeds 16 KiB ceiling.", toml_path.display()),
                });
            }
            let mtime_nanos = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            if mtime_nanos != 0
                && let Ok(guard) = PROFILE_CACHE.lock()
                && let Some(ref entry) = *guard
                && entry.repo_root == repo_root
                && entry.profile_id == profile_id
                && entry.mtime_nanos == mtime_nanos
                && entry.file_len == meta.len()
            {
                let mut cached = entry.profile.clone();
                if cached.profile_id == "coding-agent"
                    && crate::operator::has_active_elevated_lease(repo_root)
                {
                    cached.apply_elevated_lease();
                }
                return Ok(cached);
            }
            let file = File::open(&toml_path).map_err(|e| BudgetViolation {
                code: "UNREADABLE_PROFILE_BLOCKED",
                detail: format!("Failed opening profile '{}': {e}", toml_path.display()),
            })?;
            let fmeta = file.metadata().map_err(|e| BudgetViolation {
                code: "UNREADABLE_PROFILE_BLOCKED",
                detail: format!("Failed fstat on profile '{}': {e}", toml_path.display()),
            })?;
            if !fmeta.is_file() || fmeta.len() > 16_384 {
                return Err(BudgetViolation {
                    code: "OVERSIZED_PROFILE_BLOCKED",
                    detail: format!(
                        "Profile '{}' failed open descriptor validation.",
                        toml_path.display()
                    ),
                });
            }
            let mut buf = Vec::with_capacity(fmeta.len() as usize);
            file.take(16_385)
                .read_to_end(&mut buf)
                .map_err(|e| BudgetViolation {
                    code: "UNREADABLE_PROFILE_BLOCKED",
                    detail: format!("Failed reading profile '{}': {e}", toml_path.display()),
                })?;
            let text = String::from_utf8(buf).map_err(|_| BudgetViolation {
                code: "MALFORMED_PROFILE_TOML",
                detail: format!("Profile '{}' is not valid UTF-8.", toml_path.display()),
            })?;
            apply_profile_toml_tightening(&mut profile, &text)?;
            if mtime_nanos != 0
                && let Ok(mut guard) = PROFILE_CACHE.lock()
            {
                *guard = Some(CachedProfile {
                    repo_root: repo_root.to_path_buf(),
                    profile_id: profile_id.to_string(),
                    mtime_nanos,
                    file_len: meta.len(),
                    profile: profile.clone(),
                });
            }
        }
    }

    if profile.profile_id == "coding-agent" && crate::operator::has_active_elevated_lease(repo_root)
    {
        profile.apply_elevated_lease();
    }
    Ok(profile)
}

fn strip_toml_comment(line: &str) -> &str {
    let mut in_quotes = false;
    let mut escape = false;
    for (idx, ch) in line.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' && in_quotes {
            escape = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }
        if ch == '#' && !in_quotes {
            return &line[..idx];
        }
    }
    line
}

fn require_invariant(cond: bool, key: &str, detail: &str) -> Result<(), BudgetViolation> {
    if cond {
        Ok(())
    } else {
        Err(BudgetViolation {
            code: "PROFILE_INVARIANT_LOOSENED",
            detail: format!("Profile key '{key}' violates kernel security invariant: {detail}"),
        })
    }
}

fn parse_positive_usize(val: &str, key: &str) -> Result<usize, BudgetViolation> {
    val.parse::<usize>().map_err(|_| BudgetViolation {
        code: "MALFORMED_PROFILE_TOML",
        detail: format!("Profile key '{key}' expected non-negative integer, got '{val}'."),
    })
}

fn apply_profile_toml_tightening(
    profile: &mut RuntimeProfile,
    toml_text: &str,
) -> Result<(), BudgetViolation> {
    let mut section = String::new();
    let baseline_ro = !profile.enable_write_tools || profile.write_scope_none;
    let baseline_net_none = profile.network_access_none;

    for raw_line in toml_text.lines() {
        let line = strip_toml_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let sec = line[1..line.len() - 1].trim();
            match sec {
                "authority" | "git" | "traversal" | "sanitization" | "budgets" | "isolation"
                | "swarm" | "mcp" => {
                    section = sec.to_string();
                    continue;
                }
                other => {
                    return Err(BudgetViolation {
                        code: "UNKNOWN_PROFILE_KEY",
                        detail: format!(
                            "Unrecognized TOML section '[{other}]' in profile '{}' .",
                            profile.profile_id
                        ),
                    });
                }
            }
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(BudgetViolation {
                code: "MALFORMED_PROFILE_TOML",
                detail: format!(
                    "Malformed line '{line}' in profile '{}'.",
                    profile.profile_id
                ),
            });
        };
        let key = k.trim();
        let raw_val = v.trim();
        let val = raw_val.trim_matches('"');

        match (section.as_str(), key) {
            ("", "profile_id") => {
                require_invariant(
                    val == profile.profile_id,
                    "profile_id",
                    "must match requested profile identifier",
                )?;
            }
            ("", "version") | ("", "role") | ("", "skill") | ("", "rust_cli") => {
                require_invariant(!val.is_empty(), key, "metadata field must not be empty")?;
            }
            ("", "privilege_tier") => {
                require_invariant(val == "ring-1", key, "must remain 'ring-1'")?;
            }
            ("", "source_read_scope") => {
                require_invariant(val == "none", key, "only 'none' is valid when set")?;
            }
            ("", "approval_authority") => {
                require_invariant(
                    !matches!(val, "autonomous" | "unrestricted" | "all" | "*"),
                    key,
                    "cannot grant autonomous approval authority",
                )?;
            }
            ("", "enable_write_tools") => match val {
                "false" => profile.enable_write_tools = false,
                "true" => require_invariant(
                    !baseline_ro,
                    key,
                    "cannot enable write tools on a read-only profile",
                )?,
                _ => {
                    return Err(BudgetViolation {
                        code: "MALFORMED_PROFILE_TOML",
                        detail: format!("Invalid boolean '{val}' for enable_write_tools."),
                    });
                }
            },
            ("", "write_scope") => match val {
                "none" => {
                    profile.write_scope_none = true;
                    profile.enable_write_tools = false;
                }
                "repo-bounded-non-control-plane"
                | "session-allowed-write-paths-only"
                | "tests-and-attribution-only" => {
                    require_invariant(
                        !baseline_ro,
                        key,
                        "cannot widen write_scope on a read-only profile",
                    )?;
                }
                _ => {
                    return Err(BudgetViolation {
                        code: "PROFILE_INVARIANT_LOOSENED",
                        detail: format!("Unsupported or overly broad write_scope '{val}'."),
                    });
                }
            },
            ("", "network_access") | ("swarm", "network_access") => match val {
                "none" | "false" => profile.network_access_none = true,
                "allowlisted" | "proxy-only" | "true" => require_invariant(
                    !baseline_net_none,
                    key,
                    "cannot re-enable network access on an offline profile",
                )?,
                _ => {
                    return Err(BudgetViolation {
                        code: "PROFILE_INVARIANT_LOOSENED",
                        detail: format!("Unsupported network_access '{val}'."),
                    });
                }
            },
            ("authority", "root_file") => {
                require_invariant(val == "AGENTS.md", key, "must equal 'AGENTS.md'")?;
            }
            ("authority", "allow_nested_authority_files")
            | ("authority", "allow_shadow_authority_files") => {
                require_invariant(val == "false", key, "must equal false")?;
            }
            ("authority", "treat_all_other_files_as_untrusted") => {
                require_invariant(val == "true", key, "must equal true")?;
            }
            ("git", "disable_all_hooks") | ("git", "protect_hfs") | ("git", "protect_ntfs") => {
                require_invariant(val == "true", key, "must equal true")?;
            }
            ("git", "hooks_path") | ("git", "attributes_file") => {
                require_invariant(val == "/dev/null", key, "must equal '/dev/null'")?;
            }
            ("git", "fsmonitor")
            | ("git", "submodule_recurse")
            | ("git", "allow_force_push")
            | ("git", "allow_history_rewrite")
            | ("git", "allow_autonomous_push") => {
                require_invariant(val == "false", key, "must equal false")?;
            }
            ("git", "gc_auto") => {
                require_invariant(val == "0", key, "must equal 0")?;
            }
            ("git", "allowed_protocols") => {
                let compact: String = raw_val.chars().filter(|c| !c.is_whitespace()).collect();
                require_invariant(
                    compact == "[\"https\"]",
                    key,
                    "must restrict git protocols strictly to [\"https\"]",
                )?;
            }
            ("traversal", "max_directory_walk_depth") => {
                let depth = parse_positive_usize(val, key)?;
                let max_allowed = if profile.profile_id == "swarm-investigator" {
                    20
                } else {
                    2
                };
                require_invariant(
                    depth <= max_allowed,
                    key,
                    "exceeds profile traversal depth ceiling",
                )?;
            }
            ("traversal", "allow_repo_search") => {
                require_invariant(matches!(val, "true" | "false"), key, "must be boolean")?;
            }
            ("traversal", "max_reference_pointer_levels") => {
                let levels = parse_positive_usize(val, key)?;
                require_invariant(levels <= 2, key, "cannot exceed 2-hop A->B ceiling")?;
            }
            ("traversal", "halt_on_poisoned_pointer") => {
                require_invariant(val == "true", key, "must equal true")?;
            }
            ("traversal", "forbidden_zones") => {
                for mandatory in ["\"tmp\"", "\"cache\"", "\"dependencies\"", "\"secrets\""] {
                    require_invariant(
                        raw_val.contains(mandatory),
                        key,
                        "must retain mandatory forbidden zones (tmp, cache, dependencies, secrets)",
                    )?;
                }
            }
            ("sanitization", "pre_buffer_ascii_only")
            | ("sanitization", "defang_escape_sequences")
            | ("sanitization", "strip_ansi_and_cr") => {
                require_invariant(val == "true", key, "must equal true")?;
            }
            ("sanitization", "per_step_spotlight_nonce_bits") => {
                let bits = parse_positive_usize(val, key)?;
                require_invariant(bits >= 128, key, "nonce entropy must be >= 128 bits")?;
            }
            ("budgets", "max_raw_file_bytes") | ("", "max_raw_file_bytes") => {
                let n = val.parse::<u64>().map_err(|_| BudgetViolation {
                    code: "MALFORMED_PROFILE_TOML",
                    detail: format!("Invalid u64 '{val}' for max_raw_file_bytes."),
                })?;
                profile.max_raw_file_bytes = profile.max_raw_file_bytes.min(n.max(1024));
            }
            ("budgets", "max_slice_lines") | ("", "max_slice_lines") => {
                let n = parse_positive_usize(val, key)?;
                profile.max_slice_lines = profile.max_slice_lines.min(n.max(10));
            }
            ("budgets", "max_unsliced_lines") => {
                let n = parse_positive_usize(val, key)?;
                require_invariant(n <= 300, key, "cannot exceed 300 unsliced lines")?;
            }
            ("budgets", "max_single_line_bytes") | ("", "max_single_line_bytes") => {
                let n = parse_positive_usize(val, key)?;
                profile.max_single_line_bytes = profile.max_single_line_bytes.min(n.max(128));
            }
            ("budgets", "step_soft_compact_tokens") => {
                let n = parse_positive_usize(val, key)?;
                require_invariant(
                    n <= MAX_TURN_TOKENS,
                    key,
                    "cannot exceed turn token ceiling",
                )?;
            }
            ("budgets", "max_turn_tokens") | ("", "max_turn_tokens") => {
                let n = parse_positive_usize(val, key)?;
                profile.max_turn_tokens = profile.max_turn_tokens.min(n.max(512));
            }
            ("budgets", "max_turn_file_reads") | ("", "max_turn_file_reads") => {
                let n = parse_positive_usize(val, key)?;
                profile.max_turn_file_reads = profile.max_turn_file_reads.min(n.max(1));
            }
            ("budgets", "max_turn_tool_calls") | ("", "max_turn_tool_calls") => {
                let n = parse_positive_usize(val, key)?;
                profile.max_turn_tool_calls = profile.max_turn_tool_calls.min(n.max(1));
            }
            ("budgets", "auto_compact_pct_override") => {
                let n = parse_positive_usize(val, key)?;
                require_invariant((1..=100).contains(&n), key, "must be percentage 1..=100")?;
            }
            ("budgets", "compact_after_every_step") => {
                require_invariant(val == "true", key, "must equal true")?;
            }
            ("budgets", "max_return_summary_ascii_tokens")
            | ("isolation", "subagent_airlock_max_tokens")
            | ("swarm", "max_packet_ascii_tokens")
            | ("", "max_return_summary_ascii_tokens")
            | ("", "subagent_airlock_max_tokens") => {
                let n = parse_positive_usize(val, key)?;
                let cur = profile.max_return_summary_ascii_tokens.unwrap_or(200);
                profile.max_return_summary_ascii_tokens = Some(cur.min(n.max(16)));
            }
            ("isolation", "max_direct_discovery_calls")
            | ("budgets", "max_direct_discovery_calls")
            | ("", "max_direct_discovery_calls") => {
                let n = parse_positive_usize(val, key)?;
                require_invariant(
                    n <= MAX_TURN_TOOL_CALLS,
                    key,
                    "cannot exceed max_turn_tool_calls",
                )?;
                profile.max_direct_discovery_calls = n;
            }
            ("isolation", "disable_auto_memory")
            | ("isolation", "per_repo_state_namespace")
            | ("isolation", "block_cross_repo_reads")
            | ("isolation", "taint_gates_privileged_clis") => {
                require_invariant(val == "true", key, "must equal true")?;
            }
            ("swarm", "env_role") | ("swarm", "escalation_triggers") => {
                require_invariant(!val.is_empty(), key, "swarm config must not be empty")?;
            }
            ("swarm", "max_adversarial_rounds") => {
                let n = parse_positive_usize(val, key)?;
                require_invariant((1..=2).contains(&n), key, "must be 1..=2")?;
            }
            ("swarm", "arbitrary_url_fetch") => {
                require_invariant(val == "false", key, "must equal false")?;
            }
            ("swarm", "doc_broker") => {
                require_invariant(
                    val == "lockfile-pinned-offline",
                    key,
                    "must be offline lockfile-pinned",
                )?;
            }
            ("swarm", "lazy_spawn_on_smell_only")
            | ("swarm", "require_green_tree_oid_checkpoint")
            | ("swarm", "require_two_plus_two_work_ledger")
            | ("swarm", "fail_closed_on_stop")
            | ("swarm", "typed_worker_packets_only")
            | ("swarm", "clean_slate_retry") => {
                require_invariant(val == "true", key, "must equal true")?;
            }
            ("swarm", "security_domain_coverage_floor_pct") => {
                let n = parse_positive_usize(val, key)?;
                require_invariant(
                    (90..=100).contains(&n),
                    key,
                    "coverage floor must be 90..=100",
                )?;
            }
            ("swarm", "primary_suspect_cardinality") => {
                let n = parse_positive_usize(val, key)?;
                require_invariant(n == 1, key, "primary_suspect_cardinality must equal 1")?;
            }
            ("swarm", "max_secondary_suspects") => {
                let n = parse_positive_usize(val, key)?;
                require_invariant(n <= 2, key, "max_secondary_suspects must be <= 2")?;
            }
            ("mcp", "allowed_endpoint") => {
                require_invariant(
                    val.starts_with("https://"),
                    key,
                    "MCP endpoint must use https://",
                )?;
            }
            ("mcp", "ban_stdio_npx_servers") => {
                require_invariant(val == "true", key, "must equal true")?;
            }
            (sec, other) => {
                return Err(BudgetViolation {
                    code: "UNKNOWN_PROFILE_KEY",
                    detail: format!(
                        "Unrecognized profile key '{}{other}' in profile '{}'.",
                        if sec.is_empty() {
                            String::new()
                        } else {
                            format!("{sec}.")
                        },
                        profile.profile_id
                    ),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        RuntimeProfile, analyze_text_budget, apply_profile_toml_tightening, load_profile_by_id,
    };
    use std::path::Path;

    #[test]
    fn blocks_minified_single_line_and_splitter_bombs() {
        let minified = "a".repeat(2500);
        assert!(analyze_text_budget(&minified, true).is_err());

        // Dense alternating punctuation splitter bomb (> 0.72 tokens/byte)
        let mut splitter = String::new();
        for i in 0..700 {
            if i % 50 == 49 {
                splitter.push('\n');
            } else {
                splitter.push_str("!@#$%^&*()");
            }
        }
        let err = analyze_text_budget(&splitter, true).expect_err("must block splitter bomb");
        assert_eq!(err.code, "TOKENIZER_SPLITTER_BOMB");

        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for id in [
            "coding-agent",
            "research-readonly",
            "adversarial-reviewer",
            "swarm-master",
            "swarm-investigator",
            "swarm-qa-engineer",
            "swarm-grunt",
            "swarm-adversarial-reviewer",
            "swarm-forensic-coroner",
        ] {
            let p = load_profile_by_id(&repo_root, id)
                .unwrap_or_else(|e| panic!("profile {id} must validate cleanly: {}", e.detail));
            assert_eq!(p.profile_id, id);
        }
    }

    #[test]
    fn rejects_unknown_keys_and_invariant_loosening_in_profile_toml() {
        let mut p = RuntimeProfile::coding_agent_default();
        let err = apply_profile_toml_tightening(&mut p, "potemkin_magic_knob = true\n")
            .expect_err("must reject unknown profile keys");
        assert_eq!(err.code, "UNKNOWN_PROFILE_KEY");

        let mut p2 = RuntimeProfile::coding_agent_default();
        let err2 = apply_profile_toml_tightening(&mut p2, "[git]\ndisable_all_hooks = false\n")
            .expect_err("must reject invariant loosening");
        assert_eq!(err2.code, "PROFILE_INVARIANT_LOOSENED");

        let mut p3 = RuntimeProfile::coding_agent_default();
        apply_profile_toml_tightening(&mut p3, "network_access = \"none\"\n")
            .expect("tightening network_access to none must succeed");
        assert!(p3.network_access_none);
    }
}
