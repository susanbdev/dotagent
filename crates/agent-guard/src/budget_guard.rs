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

#[cfg(test)]
mod tests {
    use super::analyze_text_budget;

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
    }
}
