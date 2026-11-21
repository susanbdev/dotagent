#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! Inverted Ring-0 Constitutional Allowlist Ratchet (`dotagent verify-ring0-ratchet`).
//!
//! Enforces four hard mechanical guarantees (`dotagent v2.1`):
//! 1. **Hardware-Signed Human Commit Gate**: Unless `--require-ratchet` is passed, checks whether
//!    the working tree is clean, `GITHUB_ACTOR` is not an automation bot, and **every** commit in
//!    `<merge_base>..HEAD` passes cryptographic FIDO2/SSH verification (`ssh-keygen -Y verify -n git`)
//!    against `<merge_base>:config/allowed_human_signers`. Otherwise, strict Ring-2 ratchet mode
//!    executes unconditionally regardless of branch name or PR label.
//! 2. **Complete Working-Tree + Untracked + Mode Diff**: Computes `merge_base` (failing closed on
//!    shallow clones), unions `git diff --raw -z <merge_base>` (committed + staged + unstaged edits
//!    and file modes) with `git ls-files --others --exclude-standard -z` (untracked files), and
//!    rejects symlink (`120000`) or executable (`100755`) mode mutations.
//! 3. **Strict 5-File Ring-2 Allowlist**: Rejects (`exit 2`) any path outside:
//!    - `crates/agent-guard/src/cmd_policy.rs`
//!    - `crates/agent-guard/src/mcp_policy.rs`
//!    - `crates/agent-guard/src/diagnostics.rs`
//!    - `tests/bypass_corpus.toml`
//!    - `crates/agent-guard/tests/ring2_policy_tests.rs`
//! 4. **Prefix-Identical Corpus, Duplicate Rejection, & Target-Matched `>= 2` Abuse Vectors**:
//!    Requires all pre-existing vectors in `tests/bypass_corpus.toml` to remain in exact order and
//!    byte-for-byte identical, rejects normalized duplicate payloads, verifies every new vector
//!    triggers a `Deny` verdict, and requires `>= 2` net-new vectors targeting the exact binary or
//!    MCP tool modified in `cmd_policy.rs` / `mcp_policy.rs`.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::cmd_policy::evaluate_shell_command;
use crate::injection_scan::scan_untrusted_content;
use crate::json::JsonValue;
use crate::path_policy::{PathAccess, validate_path};
use crate::resolve_repo_root;
use crate::traversal_ledger::{ensure_nonsymlink_state_dir, extract_target_bin_or_tool};
use crate::unicode_guard::{ScanMode, scan_unicode};

/// Exact 5-file Ring-2 allowlist permitted in non-hardware-signed / autonomous PRs.
pub const RING2_EXACT_ALLOWED_PATHS: &[&str] = &[
    "crates/agent-guard/src/cmd_policy.rs",
    "crates/agent-guard/src/mcp_policy.rs",
    "crates/agent-guard/src/diagnostics.rs",
    "tests/bypass_corpus.toml",
    "crates/agent-guard/tests/ring2_policy_tests.rs",
];

pub const POLICY_ALLOWLIST_PATHS: &[&str] = &[
    "crates/agent-guard/src/cmd_policy.rs",
    "crates/agent-guard/src/mcp_policy.rs",
];

pub const ALLOWED_CORPUS_KINDS: &[&str] =
    &["cmd", "read_path", "write_path", "glob", "content", "mcp"];

/// One-time self-extinguishing genesis commit SHA of `susanbdev/dotagent` `v2.0.0` prior to
/// `config/allowed_human_signers` existing on `main`. Once `config/allowed_human_signers` lands on
/// `main`, `origin/main` advances permanently off this SHA and this genesis clause never fires again.
const RING0_SIGNERS_GENESIS_BASE_SHA: &str = "0194af29450aa65d1699337ec731d1740efc00e4";

/// SHA-256 of the exact genesis `config/allowed_human_signers` bytes (two GitHub-published
/// `sk-ssh-ed25519@openssh.com` FIDO2 keys of `susanbeasles`). Genesis enrollment is accepted only
/// for this precise keyring; any other bytes on the genesis base fail closed.
const RING0_GENESIS_SIGNERS_SHA256: &str =
    "89ce5a026336a21d62959969b1552654c79709d03601d82f16fc3102d1dd7692";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatchetReport {
    pub base_ref: String,
    pub merge_base: String,
    pub human_hardware_signed: bool,
    pub enforce_ring0_paths: bool,
    pub changed_files: Vec<String>,
    pub base_corpus_count: usize,
    pub head_corpus_count: usize,
    pub added_corpus_vectors: usize,
    pub policy_allowlist_touched: bool,
}

impl RatchetReport {
    pub fn to_json_value(&self) -> JsonValue {
        let files: Vec<JsonValue> = self
            .changed_files
            .iter()
            .map(|f| JsonValue::Str(f.clone()))
            .collect();
        JsonValue::Object(vec![
            ("ok".to_string(), JsonValue::Bool(true)),
            (
                "base_ref".to_string(),
                JsonValue::Str(self.base_ref.clone()),
            ),
            (
                "merge_base".to_string(),
                JsonValue::Str(self.merge_base.clone()),
            ),
            (
                "human_hardware_signed".to_string(),
                JsonValue::Bool(self.human_hardware_signed),
            ),
            (
                "enforce_ring0_paths".to_string(),
                JsonValue::Bool(self.enforce_ring0_paths),
            ),
            ("changed_files".to_string(), JsonValue::Array(files)),
            (
                "base_corpus_count".to_string(),
                JsonValue::Uint(self.base_corpus_count as u64),
            ),
            (
                "head_corpus_count".to_string(),
                JsonValue::Uint(self.head_corpus_count as u64),
            ),
            (
                "added_corpus_vectors".to_string(),
                JsonValue::Uint(self.added_corpus_vectors as u64),
            ),
            (
                "policy_allowlist_touched".to_string(),
                JsonValue::Bool(self.policy_allowlist_touched),
            ),
        ])
    }
}

pub fn validate_git_ref_arg(git_ref: &str) -> Result<(), String> {
    if git_ref.is_empty() || git_ref.len() > 256 {
        return Err("git ref must be 1..=256 ASCII bytes".to_string());
    }
    if git_ref.starts_with('-') {
        return Err(format!(
            "git ref '{git_ref}' cannot start with '-' (flag injection blocked)"
        ));
    }
    if git_ref.contains("..") || git_ref.contains("@{") || git_ref.ends_with(".lock") {
        return Err(format!(
            "git ref '{git_ref}' contains forbidden range or reflog syntax"
        ));
    }
    if !git_ref
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'~' | b'^' | b'-'))
    {
        return Err(format!(
            "git ref '{git_ref}' contains disallowed characters"
        ));
    }
    Ok(())
}

pub fn normalize_repo_rel_path(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("empty repository path".to_string());
    }
    if raw.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err("control byte in repository path".to_string());
    }
    let replaced = raw.replace('\\', "/");
    if replaced.starts_with('/') {
        return Err(format!(
            "absolute path '{raw}' outside repository relative form"
        ));
    }
    let mut parts = Vec::new();
    for seg in replaced.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err(format!("parent traversal '..' in repository path '{raw}'"));
        }
        parts.push(seg);
    }
    if parts.is_empty() {
        return Err(format!("degenerate repository path '{raw}'"));
    }
    Ok(parts.join("/"))
}

pub fn is_ring2_allowed_path(repo_rel: &str) -> bool {
    let Ok(norm) = normalize_repo_rel_path(repo_rel) else {
        return false;
    };
    RING2_EXACT_ALLOWED_PATHS.contains(&norm.as_str())
}

pub fn is_ring0_protected_path(repo_rel: &str) -> bool {
    !is_ring2_allowed_path(repo_rel)
}

fn is_policy_allowlist_path(repo_rel: &str) -> bool {
    let Ok(norm) = normalize_repo_rel_path(repo_rel) else {
        return false;
    };
    let lower = norm.to_ascii_lowercase();
    POLICY_ALLOWLIST_PATHS.contains(&lower.as_str())
}

fn verify_no_symlink_along_repo_rel(repo_root: &Path, norm_rel: &str) -> Result<(), String> {
    let mut cur = repo_root.to_path_buf();
    for seg in norm_rel.split('/') {
        cur.push(seg);
        if let Ok(meta) = fs::symlink_metadata(&cur)
            && meta.file_type().is_symlink()
        {
            return Err(format!(
                "RING0_RATCHET_VIOLATION: symlink detected at '{norm_rel}' inside repository"
            ));
        }
    }
    Ok(())
}

/// Strict canonical TOML state-machine parser for `tests/bypass_corpus.toml`, shared by both
/// `ring0_ratchet` and `dotagent-harness` so zero parser differential can exist.
pub fn parse_bypass_corpus_vectors_ordered(
    raw_toml: &str,
) -> Result<Vec<(String, String)>, String> {
    if raw_toml.as_bytes().contains(&0) {
        return Err("bypass_corpus.toml contains NUL byte".to_string());
    }
    let mut parser = CorpusTomlParser::new(raw_toml);
    let vectors = parser.parse_corpus()?;
    if vectors.is_empty() {
        return Err("bypass_corpus.toml parsed 0 vectors (refusing empty corpus)".to_string());
    }
    Ok(vectors)
}

pub fn parse_bypass_corpus_vectors(raw_toml: &str) -> Result<BTreeSet<(String, String)>, String> {
    let ordered = parse_bypass_corpus_vectors_ordered(raw_toml)?;
    Ok(ordered.into_iter().collect())
}

struct CorpusTomlParser<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
    line: usize,
}

impl<'a> CorpusTomlParser<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src,
            bytes: src.as_bytes(),
            pos: 0,
            line: 1,
        }
    }

    fn parse_corpus(&mut self) -> Result<Vec<(String, String)>, String> {
        self.skip_ws_and_comments()?;
        let key = self.parse_bare_ident()?;
        if key != "vectors" {
            return Err(format!(
                "bypass_corpus.toml line {}: expected top-level 'vectors', found '{key}'",
                self.line
            ));
        }
        self.skip_inline_ws();
        self.expect_byte(b'=')?;
        self.skip_ws_and_comments()?;
        self.expect_byte(b'[')?;

        let mut out = Vec::new();
        loop {
            self.skip_ws_and_comments()?;
            if self.peek() == Some(b']') {
                self.advance(1);
                break;
            }
            let entry = self.parse_vector_inline_table()?;
            out.push(entry);
            self.skip_ws_and_comments()?;
            if self.peek() == Some(b',') {
                self.advance(1);
            } else if self.peek() != Some(b']') {
                return Err(format!(
                    "bypass_corpus.toml line {}: expected ',' or ']' after vector entry",
                    self.line
                ));
            }
        }

        self.skip_ws_and_comments()?;
        if self.pos != self.bytes.len() {
            return Err(format!(
                "bypass_corpus.toml line {}: unexpected trailing content after 'vectors' array",
                self.line
            ));
        }
        Ok(out)
    }

    fn parse_vector_inline_table(&mut self) -> Result<(String, String), String> {
        let entry_line = self.line;
        self.expect_byte(b'{')?;
        let mut kind: Option<String> = None;
        let mut payload: Option<String> = None;

        loop {
            self.skip_inline_ws();
            if self.peek() == Some(b'}') {
                self.advance(1);
                break;
            }
            let field = self.parse_bare_ident()?;
            self.skip_inline_ws();
            self.expect_byte(b'=')?;
            self.skip_inline_ws();
            let val = self.parse_single_line_string()?;
            match field.as_str() {
                "kind" => {
                    if kind.is_some() {
                        return Err(format!(
                            "bypass_corpus.toml line {}: duplicate 'kind' key",
                            self.line
                        ));
                    }
                    if !ALLOWED_CORPUS_KINDS.contains(&val.as_str()) {
                        return Err(format!(
                            "bypass_corpus.toml line {}: unsupported vector kind '{val}'",
                            self.line
                        ));
                    }
                    kind = Some(val);
                }
                "payload" => {
                    if payload.is_some() {
                        return Err(format!(
                            "bypass_corpus.toml line {}: duplicate 'payload' key",
                            self.line
                        ));
                    }
                    if val.is_empty() {
                        return Err(format!(
                            "bypass_corpus.toml line {}: empty 'payload' in bypass_corpus.toml",
                            self.line
                        ));
                    }
                    payload = Some(val);
                }
                other => {
                    return Err(format!(
                        "bypass_corpus.toml line {}: unknown inline-table key '{other}'",
                        self.line
                    ));
                }
            }
            self.skip_inline_ws();
            if self.peek() == Some(b',') {
                self.advance(1);
            } else if self.peek() != Some(b'}') {
                return Err(format!(
                    "bypass_corpus.toml line {}: expected ',' or '}}' inside inline table",
                    self.line
                ));
            }
        }

        let k = kind.ok_or_else(|| {
            format!("bypass_corpus.toml line {entry_line}: vector missing 'kind'")
        })?;
        let p = payload.ok_or_else(|| {
            format!("bypass_corpus.toml line {entry_line}: vector missing 'payload'")
        })?;
        Ok((k, p))
    }

    fn parse_single_line_string(&mut self) -> Result<String, String> {
        if self.starts_with(b"\"\"\"") || self.starts_with(b"'''") {
            return Err(format!(
                "bypass_corpus.toml line {}: multiline strings are forbidden in bypass_corpus.toml",
                self.line
            ));
        }
        match self.peek() {
            Some(b'"') => self.parse_basic_string(),
            Some(b'\'') => self.parse_literal_string(),
            _ => Err(format!(
                "bypass_corpus.toml line {}: expected quoted string value",
                self.line
            )),
        }
    }

    fn parse_basic_string(&mut self) -> Result<String, String> {
        self.advance(1);
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b == b'"' {
                self.advance(1);
                return Ok(out);
            }
            if b == b'\n' || b == b'\r' || (b < 0x20 && b != b'\t') || b == 0x7F {
                return Err(format!(
                    "bypass_corpus.toml line {}: unescaped newline or control byte in basic string",
                    self.line
                ));
            }
            if b == b'\\' {
                self.advance(1);
                let Some(esc) = self.peek() else {
                    return Err(format!(
                        "bypass_corpus.toml line {}: EOF after '\\'",
                        self.line
                    ));
                };
                self.advance(1);
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000C}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let ch = self.parse_hex_scalar(4)?;
                        out.push(ch);
                    }
                    b'U' => {
                        let ch = self.parse_hex_scalar(8)?;
                        out.push(ch);
                    }
                    other => {
                        return Err(format!(
                            "bypass_corpus.toml line {}: invalid TOML escape '\\{}'",
                            self.line, other as char
                        ));
                    }
                }
            } else {
                let ch = self.next_utf8_char()?;
                out.push(ch);
            }
        }
        Err(format!(
            "bypass_corpus.toml line {}: unterminated basic string",
            self.line
        ))
    }

    fn parse_literal_string(&mut self) -> Result<String, String> {
        self.advance(1);
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b == b'\'' {
                self.advance(1);
                return Ok(out);
            }
            if b == b'\n' || b == b'\r' || (b < 0x20 && b != b'\t') || b == 0x7F {
                return Err(format!(
                    "bypass_corpus.toml line {}: newline or control byte in literal string",
                    self.line
                ));
            }
            let ch = self.next_utf8_char()?;
            out.push(ch);
        }
        Err(format!(
            "bypass_corpus.toml line {}: unterminated literal string",
            self.line
        ))
    }

    fn parse_hex_scalar(&mut self, digits: usize) -> Result<char, String> {
        let Some(slice) = self.bytes.get(self.pos..self.pos + digits) else {
            return Err(format!(
                "bypass_corpus.toml line {}: truncated unicode escape",
                self.line
            ));
        };
        let hex = std::str::from_utf8(slice).map_err(|_| {
            format!(
                "bypass_corpus.toml line {}: non-ASCII unicode escape",
                self.line
            )
        })?;
        if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "bypass_corpus.toml line {}: invalid hex escape '{hex}'",
                self.line
            ));
        }
        let cp = u32::from_str_radix(hex, 16).map_err(|_| {
            format!(
                "bypass_corpus.toml line {}: invalid codepoint '{hex}'",
                self.line
            )
        })?;
        let ch = char::from_u32(cp).ok_or_else(|| {
            format!(
                "bypass_corpus.toml line {}: surrogate or out-of-range scalar U+{cp:04X}",
                self.line
            )
        })?;
        self.pos += digits;
        Ok(ch)
    }

    fn next_utf8_char(&mut self) -> Result<char, String> {
        let tail = &self.src[self.pos..];
        let ch = tail.chars().next().ok_or_else(|| {
            format!(
                "bypass_corpus.toml line {}: unexpected EOF reading UTF-8 char",
                self.line
            )
        })?;
        self.pos += ch.len_utf8();
        Ok(ch)
    }

    fn parse_bare_ident(&mut self) -> Result<String, String> {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
                self.advance(1);
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(format!(
                "bypass_corpus.toml line {}: expected identifier",
                self.line
            ));
        }
        Ok(self.src[start..self.pos].to_string())
    }

    fn skip_inline_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.advance(1);
        }
    }

    fn skip_ws_and_comments(&mut self) -> Result<(), String> {
        loop {
            while let Some(b) = self.peek() {
                match b {
                    b' ' | b'\t' | b'\r' => self.advance(1),
                    b'\n' => {
                        self.line += 1;
                        self.advance(1);
                    }
                    _ => break,
                }
            }
            if self.peek() == Some(b'#') {
                while let Some(b) = self.peek() {
                    if b == b'\n' {
                        break;
                    }
                    if b < 0x20 && b != b'\t' && b != b'\r' {
                        return Err(format!(
                            "bypass_corpus.toml line {}: control byte in comment",
                            self.line
                        ));
                    }
                    self.advance(1);
                }
            } else {
                break;
            }
        }
        Ok(())
    }

    fn expect_byte(&mut self, expected: u8) -> Result<(), String> {
        match self.peek() {
            Some(actual) if actual == expected => {
                self.advance(1);
                Ok(())
            }
            _ => Err(format!(
                "bypass_corpus.toml line {}: expected '{}'",
                self.line, expected as char
            )),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn starts_with(&self, prefix: &[u8]) -> bool {
        self.bytes
            .get(self.pos..self.pos + prefix.len())
            .is_some_and(|s| s == prefix)
    }

    fn advance(&mut self, count: usize) {
        self.pos += count;
    }
}

/// Builds a hardened `git` invocation: hooks, attributes, fsmonitor, external diff drivers and
/// textconv filters are neutralized through environment-scoped config (never `git -c`).
fn git_cmd(repo_root: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(repo_root)
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
        .env("GIT_CONFIG_COUNT", "3")
        .env("GIT_CONFIG_KEY_0", "core.fsmonitor")
        .env("GIT_CONFIG_VALUE_0", "false")
        .env("GIT_CONFIG_KEY_1", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_1", "/dev/null")
        .env("GIT_CONFIG_KEY_2", "core.attributesFile")
        .env("GIT_CONFIG_VALUE_2", "/dev/null");
    cmd
}

fn resolve_git_commit_oid(repo_root: &Path, rev: &str) -> Result<String, String> {
    validate_git_ref_arg(rev)?;
    let out = git_cmd(repo_root)
        .args([
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{rev}^{{commit}}"),
        ])
        .output()
        .map_err(|e| format!("git rev-parse '{rev}' failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "RING0_RATCHET_VIOLATION: cannot resolve git commit '{rev}': {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn resolve_merge_base(repo_root: &Path, base_ref: &str) -> Result<String, String> {
    validate_git_ref_arg(base_ref)?;
    let shallow_out = git_cmd(repo_root)
        .args(["rev-parse", "--is-shallow-repository"])
        .output()
        .map_err(|e| format!("git rev-parse --is-shallow-repository failed: {e}"))?;
    if shallow_out.status.success() && String::from_utf8_lossy(&shallow_out.stdout).trim() == "true"
    {
        return Err(
            "RING0_RATCHET_VIOLATION: shallow git clone rejected (checkout requires fetch-depth: 0)"
                .to_string(),
        );
    }

    let mb_out = git_cmd(repo_root)
        .args(["merge-base", "--end-of-options", base_ref, "HEAD"])
        .output()
        .map_err(|e| format!("git merge-base '{base_ref}' HEAD failed: {e}"))?;
    if !mb_out.status.success() {
        return Err(format!(
            "RING0_RATCHET_VIOLATION: failed computing merge-base between '{base_ref}' and HEAD: {}",
            String::from_utf8_lossy(&mb_out.stderr).trim()
        ));
    }
    let mb = String::from_utf8_lossy(&mb_out.stdout).trim().to_string();
    if mb.is_empty() {
        return Err("RING0_RATCHET_VIOLATION: empty merge-base OID".to_string());
    }
    Ok(mb)
}

#[derive(Debug)]
struct WorkingDiffSummary {
    changed_files: Vec<String>,
    has_uncommitted_or_untracked: bool,
    forbidden_mode_mutation: Option<String>,
}

fn collect_working_and_commit_diff(
    repo_root: &Path,
    merge_base: &str,
) -> Result<WorkingDiffSummary, String> {
    let mut all_paths = BTreeSet::new();
    let mut forbidden_mode: Option<String> = None;

    // 1. `git diff --raw -z <merge_base>` diffs `merge_base` against the LIVE working tree + index + HEAD!
    let raw_out = git_cmd(repo_root)
        .args([
            "diff",
            "--raw",
            "-z",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--end-of-options",
            merge_base,
        ])
        .output()
        .map_err(|e| format!("git diff --raw '{merge_base}' failed: {e}"))?;
    if !raw_out.status.success() {
        return Err(format!(
            "RING0_RATCHET_VIOLATION: git diff --raw '{merge_base}' failed: {}",
            String::from_utf8_lossy(&raw_out.stderr).trim()
        ));
    }
    let tokens: Vec<&[u8]> = raw_out.stdout.split(|b| *b == 0).collect();
    let mut i = 0usize;
    while i < tokens.len() {
        let meta = tokens[i];
        if meta.is_empty() {
            i += 1;
            continue;
        }
        let meta_str = std::str::from_utf8(meta)
            .map_err(|_| "non-UTF-8 header in git diff --raw".to_string())?;
        // Format: `:<old_mode> <new_mode> <old_oid> <new_oid> <status_score>`
        let parts: Vec<&str> = meta_str
            .trim_start_matches(':')
            .split_whitespace()
            .collect();
        if parts.len() < 5 {
            return Err(format!("malformed git diff --raw record '{meta_str}'"));
        }
        let old_mode = parts[0];
        let new_mode = parts[1];
        let status_tok = parts[4];
        let Some(p1_bytes) = tokens.get(i + 1).copied() else {
            return Err("truncated path in git diff --raw -z".to_string());
        };
        let p1_str = std::str::from_utf8(p1_bytes)
            .map_err(|_| "non-UTF-8 path in git diff --raw".to_string())?;
        let p1_norm = normalize_repo_rel_path(p1_str)?;
        all_paths.insert(p1_norm.clone());

        // Autonomous PRs may only produce regular non-executable files: deletions (`D` /
        // `000000`), symlinks (`120000`), gitlinks (`160000`) and exec-bit flips all fail closed.
        if status_tok.starts_with('D')
            || new_mode != "100644"
            || old_mode == "120000"
            || old_mode == "160000"
        {
            forbidden_mode = Some(format!(
                "RING0_RATCHET_VIOLATION: forbidden file mode/symlink change ({old_mode} -> {new_mode}) on '{p1_norm}'"
            ));
        }

        if status_tok.starts_with('R') || status_tok.starts_with('C') {
            let Some(p2_bytes) = tokens.get(i + 2).copied() else {
                return Err("truncated rename destination in git diff --raw -z".to_string());
            };
            let p2_str = std::str::from_utf8(p2_bytes)
                .map_err(|_| "non-UTF-8 rename path in git diff --raw".to_string())?;
            let p2_norm = normalize_repo_rel_path(p2_str)?;
            all_paths.insert(p2_norm);
            i += 3;
        } else {
            i += 2;
        }
    }

    // 2. Union untracked files via `git ls-files --others --exclude-standard -z`
    let untracked_out = git_cmd(repo_root)
        .args(["ls-files", "--others", "--exclude-standard", "-z"])
        .output()
        .map_err(|e| format!("git ls-files --others failed: {e}"))?;
    if !untracked_out.status.success() {
        return Err(format!(
            "RING0_RATCHET_VIOLATION: git ls-files failed: {}",
            String::from_utf8_lossy(&untracked_out.stderr).trim()
        ));
    }
    for raw_u in untracked_out.stdout.split(|b| *b == 0) {
        if raw_u.is_empty() {
            continue;
        }
        let s = std::str::from_utf8(raw_u).map_err(|_| "non-UTF-8 untracked path".to_string())?;
        let u_norm = normalize_repo_rel_path(s)?;
        if forbidden_mode.is_none() {
            let full_u = repo_root.join(&u_norm);
            match fs::symlink_metadata(&full_u) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                        forbidden_mode = Some(format!(
                            "RING0_RATCHET_VIOLATION: untracked path '{u_norm}' is a symlink or non-regular file"
                        ));
                    } else {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let mode = meta.permissions().mode();
                            if (mode & 0o111) != 0 {
                                forbidden_mode = Some(format!(
                                    "RING0_RATCHET_VIOLATION: untracked file '{u_norm}' has executable mode {:o} (autonomous Ring-2 edits only permit regular 100644 files)",
                                    mode & 0o777
                                ));
                            }
                        }
                    }
                }
                Err(e) => {
                    forbidden_mode = Some(format!(
                        "RING0_RATCHET_VIOLATION: cannot stat untracked path '{u_norm}': {e}"
                    ));
                }
            }
        }
        all_paths.insert(u_norm);
    }

    // 3. Check working-tree cleanliness (`git status --porcelain=v1 -z -uall`)
    let status_out = git_cmd(repo_root)
        .args(["status", "--porcelain=v1", "-z", "-uall"])
        .output()
        .map_err(|e| format!("git status failed: {e}"))?;
    if !status_out.status.success() {
        return Err("RING0_RATCHET_VIOLATION: git status failed".to_string());
    }
    let has_uncommitted_or_untracked = status_out.stdout.iter().any(|b| *b != 0);

    Ok(WorkingDiffSummary {
        changed_files: all_paths.into_iter().collect(),
        has_uncommitted_or_untracked,
        forbidden_mode_mutation: forbidden_mode,
    })
}

fn is_bot_github_actor() -> bool {
    if std::env::var("DOTAGENT_AUTONOMOUS_LOOP").as_deref() == Ok("1") {
        return true;
    }
    if let Ok(actor) = std::env::var("GITHUB_ACTOR") {
        let lower = actor.trim().to_ascii_lowercase();
        if lower.ends_with("[bot]") || lower == "dotagent-loop" || lower == "github-actions" {
            return true;
        }
    }
    false
}

/// Extracts `(unsigned_commit_payload_bytes, ssh_signature_pem)` from a raw Git commit object.
pub fn extract_commit_ssh_gpgsig(raw_commit: &[u8]) -> Option<(Vec<u8>, String)> {
    let text = std::str::from_utf8(raw_commit).ok()?;
    let (headers, body) = text.split_once("\n\n")?;
    let mut unsigned_headers = Vec::new();
    let mut sig_lines = Vec::new();
    let mut in_gpgsig = false;

    for line in headers.lines() {
        if let Some(first_sig) = line.strip_prefix("gpgsig ") {
            in_gpgsig = true;
            sig_lines.push(first_sig.to_string());
            continue;
        }
        if in_gpgsig {
            if let Some(cont) = line.strip_prefix(' ') {
                sig_lines.push(cont.to_string());
                continue;
            }
            in_gpgsig = false;
        }
        unsigned_headers.push(line);
    }

    if sig_lines.is_empty() {
        return None;
    }
    let mut sig_pem = sig_lines.join("\n");
    sig_pem.push('\n');
    if !sig_pem.contains("BEGIN SSH SIGNATURE") {
        return None;
    }
    let mut unsigned_payload = unsigned_headers.join("\n");
    unsigned_payload.push_str("\n\n");
    unsigned_payload.push_str(body);
    Some((unsigned_payload.into_bytes(), sig_pem))
}

fn verify_commit_ssh_signature_against_signers(
    repo_root: &Path,
    commit_oid: &str,
    allowed_signers_content: &str,
) -> Result<bool, String> {
    static VERIFY_SEQ: AtomicU64 = AtomicU64::new(0);
    let cat_out = git_cmd(repo_root)
        .args(["cat-file", "commit", commit_oid])
        .output()
        .map_err(|e| format!("git cat-file commit '{commit_oid}' failed: {e}"))?;
    if !cat_out.status.success() {
        return Ok(false);
    }
    let Some((unsigned_payload, sig_pem)) = extract_commit_ssh_gpgsig(&cat_out.stdout) else {
        return Ok(false);
    };

    let scratch = crate::traversal_ledger::state_root_dir().join("ratchet-verify");
    ensure_nonsymlink_state_dir(&scratch)?;
    let seq = VERIFY_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let signers_path = scratch.join(format!("signers.{pid}.{seq}"));
    let sig_path = scratch.join(format!("commit.{pid}.{seq}.sig"));
    let _ = fs::remove_file(&signers_path);
    let _ = fs::remove_file(&sig_path);

    let write_private = |p: &Path, data: &[u8]| -> Result<(), String> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(p)
            .map_err(|e| format!("failed creating '{}': {e}", p.display()))?;
        f.write_all(data)
            .map_err(|e| format!("failed writing '{}': {e}", p.display()))
    };

    let res = (|| -> Result<bool, String> {
        write_private(&signers_path, allowed_signers_content.as_bytes())?;
        write_private(&sig_path, sig_pem.as_bytes())?;

        let find_out = Command::new("ssh-keygen")
            .args(["-Y", "find-principals", "-f"])
            .arg(&signers_path)
            .arg("-s")
            .arg(&sig_path)
            .output()
            .map_err(|e| format!("ssh-keygen -Y find-principals failed: {e}"))?;
        if !find_out.status.success() {
            return Ok(false);
        }
        let principal = String::from_utf8_lossy(&find_out.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        if principal.is_empty() {
            return Ok(false);
        }

        let mut verify_child = Command::new("ssh-keygen")
            .args(["-Y", "verify", "-f"])
            .arg(&signers_path)
            .args(["-I", &principal, "-n", "git", "-s"])
            .arg(&sig_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("ssh-keygen -Y verify spawn failed: {e}"))?;
        if let Some(mut stdin) = verify_child.stdin.take() {
            let _ = stdin.write_all(&unsigned_payload);
        }
        let status = verify_child
            .wait()
            .map_err(|e| format!("ssh-keygen -Y verify wait failed: {e}"))?;
        Ok(status.success())
    })();

    let _ = fs::remove_file(&signers_path);
    let _ = fs::remove_file(&sig_path);
    res
}

fn check_all_commits_human_hardware_signed(
    repo_root: &Path,
    base_ref: &str,
    merge_base: &str,
    has_uncommitted_or_untracked: bool,
) -> Result<bool, String> {
    if has_uncommitted_or_untracked || is_bot_github_actor() {
        return Ok(false);
    }

    let signers_spec = format!("{merge_base}:config/allowed_human_signers");
    let signers_out = git_cmd(repo_root)
        .args(["show", "--end-of-options", &signers_spec])
        .output()
        .map_err(|e| format!("git show '{signers_spec}' failed: {e}"))?;

    if !signers_out.status.success() {
        // One-time self-extinguishing genesis enrollment: `merge_base` must descend from the
        // v2.0.0 genesis SHA, `base_ref` must still lack `config/allowed_human_signers`, and
        // `HEAD:config/allowed_human_signers` must match the pinned SHA-256 digest byte-for-byte.
        let base_oid = resolve_git_commit_oid(repo_root, base_ref)?;
        let mb_oid = resolve_git_commit_oid(repo_root, merge_base)?;
        let descends_from_v2_genesis = git_cmd(repo_root)
            .args([
                "merge-base",
                "--is-ancestor",
                "--end-of-options",
                RING0_SIGNERS_GENESIS_BASE_SHA,
                &mb_oid,
            ])
            .status()
            .is_ok_and(|s| s.success());
        let base_lacks_signers = !git_cmd(repo_root)
            .args([
                "cat-file",
                "-e",
                &format!("{base_oid}:config/allowed_human_signers"),
            ])
            .status()
            .is_ok_and(|s| s.success());
        if descends_from_v2_genesis && base_lacks_signers {
            let head_signers = git_cmd(repo_root)
                .args([
                    "show",
                    "--end-of-options",
                    "HEAD:config/allowed_human_signers",
                ])
                .output()
                .map_err(|e| format!("git show HEAD:config/allowed_human_signers failed: {e}"))?;
            if head_signers.status.success()
                && crate::crypto::sha256_hex(&head_signers.stdout) == RING0_GENESIS_SIGNERS_SHA256
            {
                eprintln!(
                    "[ring0-ratchet] GENESIS_SIGNER_ENROLLMENT: base {base_oid} has no signer keyring; accepting pinned-digest enrollment once (self-extinguishes when main has config/allowed_human_signers)."
                );
                return Ok(true);
            }
        }
        return Ok(false);
    }

    let signers_text = String::from_utf8_lossy(&signers_out.stdout).into_owned();
    let has_enrolled_signer = signers_text
        .lines()
        .any(|l| !l.trim().is_empty() && !l.trim().starts_with('#'));
    if !has_enrolled_signer {
        return Ok(false);
    }

    let rev_list_out = git_cmd(repo_root)
        .args([
            "rev-list",
            "--end-of-options",
            &format!("{merge_base}..HEAD"),
        ])
        .output()
        .map_err(|e| format!("git rev-list failed: {e}"))?;
    if !rev_list_out.status.success() {
        return Ok(false);
    }
    let commits: Vec<String> = String::from_utf8_lossy(&rev_list_out.stdout)
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    if commits.is_empty() {
        return Ok(false);
    }

    for oid in &commits {
        if !verify_commit_ssh_signature_against_signers(repo_root, oid, &signers_text)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn normalize_payload_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn verify_corpus_prefix_and_no_duplicates(
    base_ordered: &[(String, String)],
    candidate_ordered: &[(String, String)],
    label: &str,
) -> Result<Vec<(String, String)>, String> {
    if candidate_ordered.len() < base_ordered.len() {
        return Err(format!(
            "RING0_RATCHET_VIOLATION: bypass_corpus.toml in {label} shrank from {} to {} vectors",
            base_ordered.len(),
            candidate_ordered.len()
        ));
    }
    for (idx, base_item) in base_ordered.iter().enumerate() {
        if &candidate_ordered[idx] != base_item {
            return Err(format!(
                "RING0_RATCHET_VIOLATION: pre-existing bypass_corpus.toml entry #{} (kind='{}', payload='{}') was deleted, reordered, or altered in {label}",
                idx + 1,
                base_item.0,
                base_item.1
            ));
        }
    }

    let mut existing_norm = BTreeSet::new();
    for (k, p) in base_ordered {
        existing_norm.insert((k.clone(), normalize_payload_ws(p)));
    }
    let added = candidate_ordered[base_ordered.len()..].to_vec();
    for (offset, (k, p)) in added.iter().enumerate() {
        let norm_pair = (k.clone(), normalize_payload_ws(p));
        if !existing_norm.insert(norm_pair) {
            return Err(format!(
                "RING0_RATCHET_VIOLATION: duplicate normalized bypass_corpus vector at entry #{} (kind='{k}', payload='{p}')",
                base_ordered.len() + offset + 1
            ));
        }
    }
    Ok(added)
}

fn strip_rust_line_and_block_comments(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0usize;
    let mut in_str = false;
    let mut esc = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            out.push(b as char);
            if esc {
                esc = false;
            } else if b == b'\\' {
                esc = true;
            } else if b == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            in_str = true;
            out.push('"');
            i += 1;
            continue;
        }
        if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            break;
        }
        if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        out.push(b as char);
        i += 1;
    }
    out
}

fn extract_fn_check_target(line: &str) -> Option<String> {
    let fn_pos = line.find("fn check_")?;
    let after = &line[fn_pos + "fn check_".len()..];
    let bin_tok = after.split(['_', '(']).next()?;
    if !bin_tok.is_empty() && !matches!(bin_tok, "single" | "env" | "path" | "shell") {
        Some(bin_tok.to_ascii_lowercase())
    } else {
        None
    }
}

fn extract_modified_policy_targets(repo_root: &Path, merge_base: &str) -> BTreeSet<String> {
    let mut targets = BTreeSet::new();
    let Ok(out) = git_cmd(repo_root)
        .args([
            "diff",
            "-U0",
            "--no-ext-diff",
            "--no-textconv",
            "--end-of-options",
            merge_base,
            "--",
            "crates/agent-guard/src/cmd_policy.rs",
            "crates/agent-guard/src/mcp_policy.rs",
        ])
        .output()
    else {
        return targets;
    };
    if !out.status.success() {
        return targets;
    }
    let diff_text = String::from_utf8_lossy(&out.stdout);
    let mut current_hunk_fn_target: Option<String> = None;
    for raw_line in diff_text.lines() {
        if raw_line.starts_with("+++") || raw_line.starts_with("---") {
            continue;
        }
        if raw_line.starts_with("@@") {
            current_hunk_fn_target = extract_fn_check_target(raw_line);
            if let Some(ref t) = current_hunk_fn_target {
                targets.insert(t.clone());
            }
            continue;
        }
        if !(raw_line.starts_with('+') || raw_line.starts_with('-')) {
            continue;
        }
        let code = strip_rust_line_and_block_comments(&raw_line[1..]);
        if let Some(fn_target) = extract_fn_check_target(&code) {
            current_hunk_fn_target = Some(fn_target.clone());
            targets.insert(fn_target);
            continue;
        }
        // Inside a dedicated `fn check_<bin>_*` hunk, the target is scoped strictly to `<bin>` so
        // string literals inside that function body cannot broaden `modified_targets`.
        if current_hunk_fn_target.is_some() {
            continue;
        }
        // In top-level dispatchers (`evaluate_single_command`, `evaluate_mcp_tool`, etc.), extract
        // targets from both removed (`-`) and added (`+`) structural declarations (excluding
        // comments and dead `let _ = "..."` bindings).
        if code.trim_start().starts_with("let _ =") {
            continue;
        }
        let is_structural = code.contains("=>")
            || code.contains("==")
            || code.contains("matches!(")
            || code.contains("eq_ignore_ascii_case(")
            || code.contains("starts_with(")
            || code.contains('|');
        if !is_structural {
            continue;
        }
        let mut rest = code.as_str();
        while let Some(q1) = rest.find('"') {
            rest = &rest[q1 + 1..];
            let Some(q2) = rest.find('"') else {
                break;
            };
            let lit = &rest[..q2];
            rest = &rest[q2 + 1..];
            for part in lit.split('|') {
                let trimmed = part.trim().trim_end_matches('*');
                if !trimmed.is_empty()
                    && trimmed.len() <= 48
                    && !trimmed.starts_with('-')
                    && trimmed
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    && trimmed.bytes().any(|b| b.is_ascii_lowercase())
                {
                    targets.insert(trimmed.to_ascii_lowercase());
                }
            }
        }
    }
    targets
}

/// Stateless MCP corpus evaluation: a vector is "blocked" iff the MCP tool is denied under the
/// strictest posture (`enable_write_tools = false`, tainted session). This proves the tool is NOT
/// classified `ReadOnly`, which is exactly the invariant an autonomous `mcp_policy.rs` edit could
/// erode (reclassifying a mutating verb as read-only).
pub fn mcp_corpus_vector_blocked(payload: &str) -> bool {
    let full_tool = payload.split_whitespace().next().unwrap_or("");
    if full_tool.is_empty() {
        return true;
    }
    let sub_method = full_tool.rsplit("__").next().unwrap_or(full_tool);
    crate::mcp_policy::authorize_mcp_rpc_invocation(
        full_tool,
        sub_method,
        true,
        true,
        "research-readonly",
    )
    .is_err()
}

/// Stateless glob corpus evaluation mirroring the PreToolUse `Glob` gate without touching any
/// session ledger, audit log, or hook daemon.
fn glob_corpus_vector_blocked(repo_root: &Path, payload: &str) -> bool {
    !scan_unicode(payload, ScanMode::StrictPathOrCommand).is_empty()
        || crate::path_policy::validate_workspace_glob_pattern(repo_root, repo_root, ".", payload)
            .is_err()
}

fn verify_vector_triggers_deny_and_matches_target(
    repo_root: &Path,
    kind: &str,
    payload: &str,
    modified_targets: &BTreeSet<String>,
    require_target_match: bool,
) -> Result<bool, String> {
    let blocked = match kind {
        "cmd" => evaluate_shell_command(payload, repo_root, repo_root, false).is_err(),
        "read_path" => validate_path(repo_root, repo_root, payload, PathAccess::Read).is_err(),
        "write_path" => validate_path(repo_root, repo_root, payload, PathAccess::Write).is_err(),
        "glob" => glob_corpus_vector_blocked(repo_root, payload),
        "mcp" => mcp_corpus_vector_blocked(payload),
        "content" => {
            let uni = scan_unicode(payload, ScanMode::UntrustedContent);
            let inj = scan_untrusted_content(payload, repo_root, repo_root, false);
            !uni.is_empty() || inj.first_halt().is_some() || !inj.findings.is_empty()
        }
        other => {
            return Err(format!("unknown vector kind '{other}'"));
        }
    };
    if !blocked {
        return Err(format!(
            "RING0_RATCHET_VIOLATION: net-new bypass_corpus vector (kind='{kind}', payload='{payload}') did NOT trigger a Deny verdict"
        ));
    }

    if !require_target_match {
        return Ok(true);
    }
    if modified_targets.is_empty() {
        return Err(
            "RING0_RATCHET_VIOLATION: cmd_policy.rs/mcp_policy.rs changed but no modified binary/MCP tool target could be attributed from the diff; refusing to accept unattributable policy edits"
                .to_string(),
        );
    }
    let matched = match kind {
        "cmd" => {
            let lead = extract_target_bin_or_tool("Bash", payload).to_ascii_lowercase();
            modified_targets.contains(&lead)
        }
        "mcp" => {
            let full_tool = payload
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            let sub = full_tool.rsplit("__").next().unwrap_or("").to_string();
            modified_targets.iter().any(|t| {
                full_tool == *t
                    || sub == *t
                    || sub.starts_with(t.as_str())
                    || sub.split('_').any(|seg| seg == t)
            })
        }
        _ => false,
    };
    Ok(matched)
}

/// Ring-2 policy files whose references to Ring-0 constitutional deny codes may never shrink.
const CONSTITUTIONAL_CODE_GUARDED_FILES: &[&str] = &[
    "crates/agent-guard/src/cmd_policy.rs",
    "crates/agent-guard/src/mcp_policy.rs",
    "crates/agent-guard/src/diagnostics.rs",
];

fn count_constitutional_codes(raw: &str) -> Vec<usize> {
    crate::feedback::RING0_CONSTITUTIONAL_CODES
        .iter()
        .map(|code| raw.matches(code).count())
        .collect()
}

fn verify_constitutional_code_counts_not_reduced(
    repo_root: &Path,
    merge_base: &str,
    changed_files: &[String],
) -> Result<(), String> {
    for rel in CONSTITUTIONAL_CODE_GUARDED_FILES {
        if !changed_files.iter().any(|p| p == rel) {
            continue;
        }
        let spec = format!("{merge_base}:{rel}");
        let base_out = git_cmd(repo_root)
            .args(["show", "--end-of-options", &spec])
            .output()
            .map_err(|e| format!("failed reading '{spec}': {e}"))?;
        if !base_out.status.success() {
            // File absent at merge-base: nothing to ratchet against.
            continue;
        }
        let base_raw = String::from_utf8_lossy(&base_out.stdout);
        verify_no_symlink_along_repo_rel(repo_root, rel)?;
        let head_raw = fs::read_to_string(repo_root.join(rel)).unwrap_or_default();
        let base_counts = count_constitutional_codes(&base_raw);
        let head_counts = count_constitutional_codes(&head_raw);
        for (idx, code) in crate::feedback::RING0_CONSTITUTIONAL_CODES
            .iter()
            .enumerate()
        {
            let before = base_counts.get(idx).copied().unwrap_or(0);
            let after = head_counts.get(idx).copied().unwrap_or(0);
            if after < before {
                return Err(format!(
                    "RING0_RATCHET_VIOLATION: '{rel}' reduces references to Ring-0 constitutional code '{code}' ({before} -> {after}); autonomous edits may never weaken constitutional denials"
                ));
            }
        }
    }
    Ok(())
}

pub fn verify_ring0_ratchet(
    repo_root: &Path,
    base_ref: &str,
    force_ratchet: bool,
) -> Result<RatchetReport, String> {
    validate_git_ref_arg(base_ref)?;
    let merge_base = resolve_merge_base(repo_root, base_ref)?;
    let diff_summary = collect_working_and_commit_diff(repo_root, &merge_base)?;

    let human_hardware_signed = if force_ratchet {
        false
    } else {
        check_all_commits_human_hardware_signed(
            repo_root,
            base_ref,
            &merge_base,
            diff_summary.has_uncommitted_or_untracked,
        )?
    };
    let enforce_ring0_paths = force_ratchet || !human_hardware_signed;

    if enforce_ring0_paths && let Some(mode_err) = diff_summary.forbidden_mode_mutation {
        return Err(mode_err);
    }

    for path in &diff_summary.changed_files {
        verify_no_symlink_along_repo_rel(repo_root, path)?;
        if enforce_ring0_paths && !is_ring2_allowed_path(path) {
            return Err(format!(
                "RING0_RATCHET_VIOLATION: path '{path}' is outside the strict 5-file Ring-2 allowlist (commits lack verified hardware signature in config/allowed_human_signers)"
            ));
        }
    }

    if enforce_ring0_paths {
        verify_constitutional_code_counts_not_reduced(
            repo_root,
            &merge_base,
            &diff_summary.changed_files,
        )?;
    }

    let show_spec = format!("{merge_base}:tests/bypass_corpus.toml");
    let base_corpus_out = git_cmd(repo_root)
        .args(["show", "--end-of-options", &show_spec])
        .output()
        .map_err(|e| format!("failed reading '{show_spec}': {e}"))?;
    if !base_corpus_out.status.success() {
        let stderr = String::from_utf8_lossy(&base_corpus_out.stderr);
        return Err(format!(
            "RING0_RATCHET_VIOLATION: failed loading base corpus '{show_spec}': {}",
            stderr.trim()
        ));
    }
    let base_raw = std::str::from_utf8(&base_corpus_out.stdout)
        .map_err(|_| "RING0_RATCHET_VIOLATION: non-UTF-8 base bypass_corpus.toml".to_string())?;
    let base_ordered = parse_bypass_corpus_vectors_ordered(base_raw)?;

    let committed_head_out = git_cmd(repo_root)
        .args(["show", "--end-of-options", "HEAD:tests/bypass_corpus.toml"])
        .output()
        .map_err(|e| format!("failed reading 'HEAD:tests/bypass_corpus.toml': {e}"))?;
    if !committed_head_out.status.success() {
        return Err(format!(
            "RING0_RATCHET_VIOLATION: failed loading HEAD corpus: {}",
            String::from_utf8_lossy(&committed_head_out.stderr).trim()
        ));
    }
    let committed_head_raw = std::str::from_utf8(&committed_head_out.stdout)
        .map_err(|_| "RING0_RATCHET_VIOLATION: non-UTF-8 HEAD bypass_corpus.toml".to_string())?;
    let committed_head_ordered = parse_bypass_corpus_vectors_ordered(committed_head_raw)?;
    let _ = verify_corpus_prefix_and_no_duplicates(&base_ordered, &committed_head_ordered, "HEAD")?;

    verify_no_symlink_along_repo_rel(repo_root, "tests/bypass_corpus.toml")?;
    let head_corpus_path = repo_root.join("tests/bypass_corpus.toml");
    let corpus_meta = fs::symlink_metadata(&head_corpus_path).map_err(|e| {
        format!(
            "RING0_RATCHET_VIOLATION: cannot stat '{}': {e}",
            head_corpus_path.display()
        )
    })?;
    if corpus_meta.file_type().is_symlink() || !corpus_meta.file_type().is_file() {
        return Err(
            "RING0_RATCHET_VIOLATION: tests/bypass_corpus.toml must be a regular non-symlink file"
                .to_string(),
        );
    }
    let head_raw = fs::read_to_string(&head_corpus_path).map_err(|e| {
        format!(
            "RING0_RATCHET_VIOLATION: failed reading '{}': {e}",
            head_corpus_path.display()
        )
    })?;
    let head_ordered = parse_bypass_corpus_vectors_ordered(&head_raw)?;
    let _ = verify_corpus_prefix_and_no_duplicates(
        &committed_head_ordered,
        &head_ordered,
        "working tree vs HEAD",
    )?;
    let added_vectors =
        verify_corpus_prefix_and_no_duplicates(&base_ordered, &head_ordered, "working tree")?;

    let policy_allowlist_touched = diff_summary
        .changed_files
        .iter()
        .any(|p| is_policy_allowlist_path(p));

    if enforce_ring0_paths && policy_allowlist_touched {
        if added_vectors.len() < 2 {
            return Err(format!(
                "RING0_RATCHET_VIOLATION: modifying cmd_policy.rs or mcp_policy.rs requires appending >= 2 net-new adversarial abuse vectors to tests/bypass_corpus.toml (found {})",
                added_vectors.len()
            ));
        }
        let modified_targets = extract_modified_policy_targets(repo_root, &merge_base);
        let mut target_matched_count = 0usize;
        for (k, p) in &added_vectors {
            if verify_vector_triggers_deny_and_matches_target(
                repo_root,
                k,
                p,
                &modified_targets,
                true,
            )? {
                target_matched_count += 1;
            }
        }
        if target_matched_count < 2 {
            return Err(format!(
                "RING0_RATCHET_VIOLATION: modifying cmd_policy.rs or mcp_policy.rs requires >= 2 net-new Deny vectors in tests/bypass_corpus.toml targeting the modified binary/MCP tool {:?} (matched only {target_matched_count})",
                modified_targets
            ));
        }
    } else {
        let empty_targets = BTreeSet::new();
        for (k, p) in &added_vectors {
            let _ = verify_vector_triggers_deny_and_matches_target(
                repo_root,
                k,
                p,
                &empty_targets,
                false,
            )?;
        }
    }

    Ok(RatchetReport {
        base_ref: base_ref.to_string(),
        merge_base,
        human_hardware_signed,
        enforce_ring0_paths,
        changed_files: diff_summary.changed_files,
        base_corpus_count: base_ordered.len(),
        head_corpus_count: head_ordered.len(),
        added_corpus_vectors: added_vectors.len(),
        policy_allowlist_touched,
    })
}

pub fn verify_corpus_monotonic_only(
    repo_root: &Path,
    base_ref: &str,
) -> Result<RatchetReport, String> {
    validate_git_ref_arg(base_ref)?;
    let merge_base = resolve_merge_base(repo_root, base_ref)?;
    let diff_summary = collect_working_and_commit_diff(repo_root, &merge_base)?;
    let show_spec = format!("{merge_base}:tests/bypass_corpus.toml");
    let base_out = git_cmd(repo_root)
        .args(["show", "--end-of-options", &show_spec])
        .output()
        .map_err(|e| format!("failed reading '{show_spec}': {e}"))?;
    if !base_out.status.success() {
        return Err(format!(
            "RING0_RATCHET_VIOLATION: failed loading base corpus '{show_spec}'"
        ));
    }
    let base_ordered =
        parse_bypass_corpus_vectors_ordered(&String::from_utf8_lossy(&base_out.stdout))?;
    let head_raw = fs::read_to_string(repo_root.join("tests/bypass_corpus.toml"))
        .map_err(|e| format!("failed reading working-tree bypass_corpus.toml: {e}"))?;
    let head_ordered = parse_bypass_corpus_vectors_ordered(&head_raw)?;
    let added =
        verify_corpus_prefix_and_no_duplicates(&base_ordered, &head_ordered, "working tree")?;
    let empty_targets = BTreeSet::new();
    for (k, p) in &added {
        let _ =
            verify_vector_triggers_deny_and_matches_target(repo_root, k, p, &empty_targets, false)?;
    }
    Ok(RatchetReport {
        base_ref: base_ref.to_string(),
        merge_base,
        human_hardware_signed: false,
        enforce_ring0_paths: false,
        changed_files: diff_summary.changed_files,
        base_corpus_count: base_ordered.len(),
        head_corpus_count: head_ordered.len(),
        added_corpus_vectors: added.len(),
        policy_allowlist_touched: false,
    })
}

pub fn run_verify_ring0_ratchet_cli(args: &[String], cwd: &Path) -> ExitCode {
    let mut base_ref = String::from("origin/main");
    let mut force_ratchet = false;
    let mut corpus_only = false;
    let mut json_mode = false;
    let mut repo_override: Option<String> = None;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--base" if i + 1 < args.len() => {
                base_ref = args[i + 1].clone();
                i += 2;
            }
            "--repo" if i + 1 < args.len() => {
                repo_override = Some(args[i + 1].clone());
                i += 2;
            }
            "--require-ratchet" | "--enforce-ring0" => {
                force_ratchet = true;
                i += 1;
            }
            "--corpus-only" => {
                corpus_only = true;
                i += 1;
            }
            "--json" => {
                json_mode = true;
                i += 1;
            }
            other => {
                eprintln!(
                    "[dotagent verify-ring0-ratchet] unrecognized argument '{other}' (expected --base <ref> [--require-ratchet] [--repo <dir>] [--json])"
                );
                return ExitCode::from(2);
            }
        }
    }

    let target_dir = repo_override
        .as_deref()
        .map(Path::new)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| resolve_repo_root(cwd));

    let res = if corpus_only {
        verify_corpus_monotonic_only(&target_dir, &base_ref)
    } else {
        verify_ring0_ratchet(&target_dir, &base_ref, force_ratchet)
    };

    match res {
        Ok(report) => {
            if json_mode {
                println!("{}", report.to_json_value().to_json_string());
            } else {
                println!(
                    "[RING0 RATCHET OK] base='{}' merge_base='{}' hw_signed={} enforce_ring0={} changed={} corpus={} (+{} new vectors)",
                    report.base_ref,
                    &report.merge_base[..report.merge_base.len().min(12)],
                    report.human_hardware_signed,
                    report.enforce_ring0_paths,
                    report.changed_files.len(),
                    report.head_corpus_count,
                    report.added_corpus_vectors
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("[RING0 RATCHET FAIL] {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_strict_five_file_ring2_allowlist_and_corpus_prefix_identity() {
        let base_sample = r#"
vectors = [
  { kind = "cmd", payload = "c\"a\"t /tmp/secret.txt" },
  { kind = "cmd", payload = "\\cat /tmp/secret.txt" },
]
"#;
        let base_ord = parse_bypass_corpus_vectors_ordered(base_sample).expect("base");
        assert_eq!(base_ord.len(), 2);

        // Reordering existing vectors fails prefix identity check!
        let reordered = vec![base_ord[1].clone(), base_ord[0].clone()];
        assert!(verify_corpus_prefix_and_no_duplicates(&base_ord, &reordered, "test").is_err());

        // Normalized whitespace duplicate fails!
        let mut dup = base_ord.clone();
        dup.push(("cmd".to_string(), "c\"a\"t   /tmp/secret.txt".to_string()));
        assert!(verify_corpus_prefix_and_no_duplicates(&base_ord, &dup, "test").is_err());

        // Strict 5-file Ring-2 allowlist
        assert!(is_ring2_allowed_path(
            "crates/agent-guard/src/cmd_policy.rs"
        ));
        assert!(is_ring2_allowed_path(
            "crates/agent-guard/src/mcp_policy.rs"
        ));
        assert!(is_ring2_allowed_path(
            "crates/agent-guard/src/diagnostics.rs"
        ));
        assert!(is_ring2_allowed_path("tests/bypass_corpus.toml"));
        assert!(is_ring2_allowed_path(
            "crates/agent-guard/tests/ring2_policy_tests.rs"
        ));
        assert!(!is_ring2_allowed_path("Cargo.toml"));
        assert!(!is_ring2_allowed_path("build.rs"));
        assert!(!is_ring2_allowed_path("crates/dotagent-harness/src/lib.rs"));
        assert!(!is_ring2_allowed_path(
            "crates/agent-guard/src/feedback_loop.rs"
        ));
        assert!(!is_ring2_allowed_path(".claude/settings.json"));
        assert!(!is_ring2_allowed_path(
            "crates/agent-guard/tests/other_arbitrary_test.rs"
        ));
    }
}
