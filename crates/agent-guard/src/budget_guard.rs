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
use std::path::Path;

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

/// Safely reads up to `MAX_RAW_FILE_BYTES + 1` (or bounded slice) using `Read::take`
/// so a multi-gigabyte file or special device can never OOM the guard itself.
pub fn inspect_file_budget(
    path: &Path,
    offset_line: Option<usize>,
    limit_lines: Option<usize>,
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
    let has_bounded_slice = limit_lines.is_some_and(|l| l > 0 && l <= MAX_SLICE_LINES);

    if !has_bounded_slice && file_len > MAX_RAW_FILE_BYTES {
        return Err(BudgetViolation {
            code: "FILE_BYTE_BUDGET_EXCEEDED",
            detail: format!(
                "File '{}' is {file_len} bytes (> {MAX_RAW_FILE_BYTES} byte limit). Request a bounded line range (<= {MAX_SLICE_LINES} lines) to prevent context window saturation.",
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
        let count = limit_lines.unwrap_or(MAX_SLICE_LINES);
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

    let metrics = analyze_text_budget(&inspected_text, !has_bounded_slice)?;
    Ok((inspected_text, metrics))
}

pub fn analyze_text_budget(
    text: &str,
    enforce_unsliced_line_cap: bool,
) -> Result<ContentMetrics, BudgetViolation> {
    if text.len() > MAX_RAW_FILE_BYTES as usize {
        return Err(BudgetViolation {
            code: "CONTENT_BYTE_BUDGET_EXCEEDED",
            detail: format!(
                "Content payload is {} bytes (> {} byte context-saturation ceiling).",
                text.len(),
                MAX_RAW_FILE_BYTES
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

    if enforce_unsliced_line_cap && line_count > MAX_UNSLICED_LINES {
        return Err(BudgetViolation {
            code: "LINE_COUNT_BUDGET_EXCEEDED",
            detail: format!(
                "Content has {line_count} lines (> {MAX_UNSLICED_LINES} unsliced line limit). Read bounded slices (<= {MAX_SLICE_LINES} lines).",
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
    pub max_raw_file_bytes: u64,
    pub max_slice_lines: usize,
    pub max_single_line_bytes: usize,
    pub max_turn_tokens: usize,
    pub max_turn_file_reads: usize,
    pub max_turn_tool_calls: usize,
    pub max_return_summary_ascii_tokens: Option<usize>,
}

impl RuntimeProfile {
    pub fn coding_agent_default() -> Self {
        Self {
            profile_id: "coding-agent".to_string(),
            enable_write_tools: true,
            write_scope_none: false,
            max_raw_file_bytes: MAX_RAW_FILE_BYTES,
            max_slice_lines: MAX_SLICE_LINES,
            max_single_line_bytes: MAX_SINGLE_LINE_BYTES,
            max_turn_tokens: MAX_TURN_TOKENS,
            max_turn_file_reads: MAX_TURN_FILE_READS,
            max_turn_tool_calls: MAX_TURN_TOOL_CALLS,
            max_return_summary_ascii_tokens: Some(200),
        }
    }

    pub fn research_readonly_default() -> Self {
        Self {
            profile_id: "research-readonly".to_string(),
            enable_write_tools: false,
            write_scope_none: true,
            max_raw_file_bytes: MAX_RAW_FILE_BYTES,
            max_slice_lines: MAX_SLICE_LINES,
            max_single_line_bytes: MAX_SINGLE_LINE_BYTES,
            max_turn_tokens: 12_000,
            max_turn_file_reads: MAX_TURN_FILE_READS,
            max_turn_tool_calls: MAX_TURN_TOOL_CALLS,
            max_return_summary_ascii_tokens: Some(200),
        }
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
        | "swarm-master"
        | "swarm-investigator"
        | "swarm-adversarial-reviewer"
        | "swarm-forensic-coroner" => {
            let mut p = RuntimeProfile::research_readonly_default();
            p.profile_id = profile_id.to_string();
            p
        }
        other => {
            return Err(BudgetViolation {
                code: "UNKNOWN_RUNTIME_PROFILE",
                detail: format!(
                    "Unrecognized AGENT_GUARD_PROFILE '{other}' (expected 'coding-agent', 'research-readonly', or 'swarm-*')."
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
            if let Ok(file) = File::open(&toml_path) {
                let mut buf = Vec::new();
                if file.take(16_384).read_to_end(&mut buf).is_ok()
                    && let Ok(text) = String::from_utf8(buf)
                {
                    apply_profile_toml_tightening(&mut profile, &text);
                }
            }
        }
    }

    Ok(profile)
}

fn apply_profile_toml_tightening(profile: &mut RuntimeProfile, toml_text: &str) {
    for raw_line in toml_text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim().trim_matches('"');
        match key {
            "enable_write_tools" if val == "false" => {
                profile.enable_write_tools = false;
            }
            "write_scope" if val == "none" => {
                profile.write_scope_none = true;
                profile.enable_write_tools = false;
            }
            "max_raw_file_bytes" => {
                if let Ok(n) = val.parse::<u64>() {
                    profile.max_raw_file_bytes = profile.max_raw_file_bytes.min(n.max(1024));
                }
            }
            "max_slice_lines" => {
                if let Ok(n) = val.parse::<usize>() {
                    profile.max_slice_lines = profile.max_slice_lines.min(n.max(10));
                }
            }
            "max_single_line_bytes" => {
                if let Ok(n) = val.parse::<usize>() {
                    profile.max_single_line_bytes = profile.max_single_line_bytes.min(n.max(128));
                }
            }
            "max_turn_tokens" => {
                if let Ok(n) = val.parse::<usize>() {
                    profile.max_turn_tokens = profile.max_turn_tokens.min(n.max(512));
                }
            }
            "max_turn_file_reads" => {
                if let Ok(n) = val.parse::<usize>() {
                    profile.max_turn_file_reads = profile.max_turn_file_reads.min(n.max(1));
                }
            }
            "max_turn_tool_calls" => {
                if let Ok(n) = val.parse::<usize>() {
                    profile.max_turn_tool_calls = profile.max_turn_tool_calls.min(n.max(1));
                }
            }
            "max_return_summary_ascii_tokens" | "subagent_airlock_max_tokens" => {
                if let Ok(n) = val.parse::<usize>() {
                    let cur = profile.max_return_summary_ascii_tokens.unwrap_or(200);
                    profile.max_return_summary_ascii_tokens = Some(cur.min(n.max(16)));
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{analyze_text_budget, load_profile_by_id};
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

        let ro = load_profile_by_id(Path::new("."), "research-readonly").expect("ro profile");
        assert!(!ro.enable_write_tools);
        assert_eq!(ro.max_turn_tokens, 12_000);
    }
}
