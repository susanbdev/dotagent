#![forbid(unsafe_code)]

//! Stateful per-turn traversal graph, repo-isolated namespace (anti-cache-bleed),
//! poisoned-pointer circuit breaker, cumulative context budget ledger, and
//! CaMeL-style provenance taint tracker.
//!
//! Enforces:
//! 1. Reference traversal ceiling of max 2 levels:
//!    - Level 1: File A (opened directly from human prompt / root target) -> ALLOWED
//!    - Level 2: File B (referenced inside File A: A -> B) -> ALLOWED
//!    - Level 3: File C (referenced inside File B: A -> B -> C) -> HARD STOP (Exit 2)
//! 2. Immediate Circuit Breaker:
//!    - If ANY file or output points the agent toward a cache, tmp, or dependency
//!      directory (`node_modules`, `.venv`, `/tmp`, `.cache`, etc.), the session
//!      immediately trips `halted = true` and blocks all further tool calls in the turn.
//! 3. Repo-Isolated State (Zero Cross-Repo Cache Bleed):
//!    - Keyed by `SHA-256(canonical_repo_root || ":" || session_id)`.
//!    - Stored under `~/.local/state/agent-guard/sessions` (`0700`), never `/tmp` or `~/.cache`.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::budget_guard::{MAX_TURN_FILE_READS, MAX_TURN_TOKENS, MAX_TURN_TOOL_CALLS};
use crate::json::JsonValue;
use crate::sha256::sha256_hex;

pub const MAX_REFERENCE_LEVEL: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraversalNode {
    /// 1 = direct read (A), 2 = first hop (A -> B), 3+ = forbidden hop (A -> B -> C)
    pub level: u8,
    /// Provenance chain description, e.g. "docs/A.md -> docs/B.md"
    pub chain: String,
    /// Whether this file itself has already been read in this step
    pub was_read: bool,
}

#[derive(Debug, Clone)]
pub struct SessionLedger {
    pub repo_root: String,
    pub session_id: String,
    pub turn_nonce: String,
    pub compaction_epoch: usize,
    pub halted: bool,
    pub halt_reason: Option<String>,
    pub tainted: bool,
    pub taint_reason: Option<String>,
    pub cumulative_tokens: usize,
    pub file_reads: usize,
    pub tool_calls: usize,
    pub nodes: BTreeMap<String, TraversalNode>,
}

impl SessionLedger {
    pub fn new(repo_root: &Path, session_id: &str) -> Self {
        let clean_sid = sanitize_session_id(session_id);
        let turn_nonce = generate_turn_nonce(repo_root, &clean_sid, 0);
        Self {
            repo_root: repo_root.to_string_lossy().into_owned(),
            session_id: clean_sid,
            turn_nonce,
            compaction_epoch: 0,
            halted: false,
            halt_reason: None,
            tainted: false,
            taint_reason: None,
            cumulative_tokens: 0,
            file_reads: 0,
            tool_calls: 0,
            nodes: BTreeMap::new(),
        }
    }

    pub fn load_or_create(repo_root: &Path, session_id: &str) -> Self {
        let path = ledger_file_path(repo_root, session_id);
        let Ok(raw) = fs::read_to_string(&path) else {
            return Self::new(repo_root, session_id);
        };
        Self::from_json(&raw).unwrap_or_else(|| Self::new(repo_root, session_id))
    }

    pub fn save(&self, repo_root: &Path) -> Result<(), String> {
        let path = ledger_file_path(repo_root, &self.session_id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed creating state dir '{}': {e}", parent.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        let serialized = self.to_json();
        fs::write(&path, serialized.as_bytes())
            .map_err(|e| format!("failed writing ledger '{}': {e}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn reset_for_new_user_prompt(repo_root: &Path, session_id: &str) -> Result<Self, String> {
        let fresh = Self::new(repo_root, session_id);
        fresh.save(repo_root)?;
        Ok(fresh)
    }

    /// Resets per-step context window counters (`cumulative_tokens`, `file_reads`, `tool_calls`)
    /// and rotates the 128-bit spotlighting `turn_nonce` upon step compaction while preserving
    /// circuit-breaker halts, provenance taint, and the `A -> B -> C` hop graph!
    pub fn compact_step(&mut self, repo_root: &Path) {
        self.compaction_epoch = self.compaction_epoch.saturating_add(1);
        self.cumulative_tokens = 0;
        self.file_reads = 0;
        self.tool_calls = 0;
        self.turn_nonce = generate_turn_nonce(repo_root, &self.session_id, self.compaction_epoch);
        for node in self.nodes.values_mut() {
            node.was_read = false;
        }
    }

    pub fn trip_circuit_breaker(&mut self, reason: String) {
        self.halted = true;
        self.halt_reason = Some(reason);
        self.tainted = true;
    }

    pub fn mark_tainted(&mut self, reason: String) {
        self.tainted = true;
        if self.taint_reason.is_none() {
            self.taint_reason = Some(reason);
        }
    }

    pub fn check_not_halted(&self) -> Result<(), String> {
        if self.halted {
            let reason = self
                .halt_reason
                .as_deref()
                .unwrap_or("circuit breaker tripped due to malicious pointer or injection");
            return Err(format!(
                "Session is HALTED by agent-guard circuit breaker ({reason}). Stop all actions immediately and report to the user."
            ));
        }
        Ok(())
    }

    pub fn record_tool_call(&mut self) -> Result<(), String> {
        self.check_not_halted()?;
        if self.tool_calls >= MAX_TURN_TOOL_CALLS {
            return Err(format!(
                "Step tool-call ceiling exceeded ({MAX_TURN_TOOL_CALLS} calls). Compact step context immediately before continuing."
            ));
        }
        self.tool_calls += 1;
        Ok(())
    }

    /// Validates whether reading `rel_path` violates the max-2-level pointer hop chain
    /// (`A -> B` allowed, `A -> B -> C` hard-denied!) and records the read + token budget.
    /// Returns the assigned level (`1` or `2`) of `rel_path`.
    pub fn authorize_and_record_read(
        &mut self,
        rel_path: &str,
        estimated_tokens: usize,
    ) -> Result<u8, (&'static str, String)> {
        if let Err(msg) = self.check_not_halted() {
            return Err(("SESSION_CIRCUIT_BREAKER_HALTED", msg));
        }

        if let Some(existing) = self.nodes.get(rel_path) {
            if existing.level > MAX_REFERENCE_LEVEL {
                return Err((
                    "TRANSITIVE_DEPTH_EXCEEDED",
                    format!(
                        "Transitive reference chain '{} -> {rel_path}' reaches level {} (> max {MAX_REFERENCE_LEVEL} levels: A -> B allowed, B -> C forbidden). Stop immediately and ask the user.",
                        existing.chain, existing.level
                    ),
                ));
            }
        }

        let already_read = self.nodes.get(rel_path).is_some_and(|n| n.was_read);
        if !already_read && self.file_reads >= MAX_TURN_FILE_READS {
            return Err((
                "FILE_READ_BUDGET_EXCEEDED",
                format!(
                    "Step file-read limit ({MAX_TURN_FILE_READS} files) reached; compact step context before reading '{rel_path}'."
                ),
            ));
        }

        let next_tokens = self.cumulative_tokens.saturating_add(estimated_tokens);
        if next_tokens > MAX_TURN_TOKENS {
            return Err((
                "TURN_TOKEN_BUDGET_EXCEEDED",
                format!(
                    "Reading '{rel_path}' (+{estimated_tokens} est. tokens) would exceed tight step context ceiling ({next_tokens} > {MAX_TURN_TOKENS}). Compact this step immediately rather than carrying multi-step history."
                ),
            ));
        }

        self.cumulative_tokens = next_tokens;
        if !already_read {
            self.file_reads += 1;
        }

        let assigned_level = if let Some(node) = self.nodes.get_mut(rel_path) {
            node.was_read = true;
            node.level
        } else {
            self.nodes.insert(
                rel_path.to_string(),
                TraversalNode {
                    level: 1,
                    chain: rel_path.to_string(),
                    was_read: true,
                },
            );
            1
        };

        Ok(assigned_level)
    }

    /// Registers outgoing file pointers discovered inside `source_rel` (at `source_level`).
    /// - If `source_level == 1` (`A`), discovered `B` gets `level = 2` (`A -> B`, allowed).
    /// - If `source_level >= 2` (`B`), discovered `C` gets `level = 3` (`A -> B -> C`, BLOCKED!).
    ///
    /// Never downgrades an already-read file (`was_read == true`), and never overwrites an allowed
    /// `level <= 2` discovery with a deeper path if `B` was already directly reachable from `A`.
    pub fn register_outgoing_pointers(&mut self, source_rel: &str, targets: &[String]) {
        let (source_level, source_chain) = match self.nodes.get(source_rel) {
            Some(n) => (n.level, n.chain.clone()),
            None => (1, source_rel.to_string()),
        };
        let target_level = source_level.saturating_add(1);

        for target in targets {
            if target == source_rel {
                continue;
            }
            match self.nodes.get(target) {
                Some(existing) if existing.was_read || existing.level <= MAX_REFERENCE_LEVEL => {
                    // Already read or already directly referenced from a Level-1 file
                    continue;
                }
                _ => {
                    self.nodes.insert(
                        target.clone(),
                        TraversalNode {
                            level: target_level,
                            chain: source_chain.clone(),
                            was_read: false,
                        },
                    );
                }
            }
        }
    }

    /// Registers repository pointers discovered inside dynamic `PostToolUse` outputs
    /// (MCP responses, custom tools, etc.) so subsequent `Read` calls cannot bypass
    /// the `A -> B -> C` transitive hop ceiling.
    pub fn register_dynamic_tool_pointers(&mut self, tool_label: &str, targets: &[String]) {
        if targets.is_empty() {
            return;
        }
        let norm = tool_label.to_ascii_lowercase();
        let is_local_discovery = matches!(
            norm.as_str(),
            "bash"
                | "sh"
                | "shell"
                | "run_command"
                | "run_shell_command"
                | "execute_command"
                | "grep"
                | "glob"
                | "ls"
                | "grep_search"
                | "find_by_name"
                | "list_dir"
                | "list_directory"
        );
        if is_local_discovery {
            for target in targets {
                self.nodes.entry(target.clone()).or_insert(TraversalNode {
                    level: 1,
                    chain: target.clone(),
                    was_read: false,
                });
            }
            return;
        }

        let max_read_level = self
            .nodes
            .values()
            .filter(|n| n.was_read)
            .map(|n| n.level)
            .max()
            .unwrap_or(1);
        let source_key = format!("<tool_output:{tool_label}:{max_read_level}>");
        self.nodes
            .entry(source_key.clone())
            .or_insert(TraversalNode {
                level: max_read_level,
                chain: source_key.clone(),
                was_read: true,
            });
        self.register_outgoing_pointers(&source_key, targets);
    }

    fn to_json(&self) -> String {
        let mut nodes_entries = Vec::with_capacity(self.nodes.len());
        for (k, v) in &self.nodes {
            nodes_entries.push((
                k.clone(),
                JsonValue::Object(vec![
                    ("level".to_string(), JsonValue::Number(v.level as f64)),
                    ("chain".to_string(), JsonValue::Str(v.chain.clone())),
                    ("was_read".to_string(), JsonValue::Bool(v.was_read)),
                ]),
            ));
        }

        let obj = JsonValue::Object(vec![
            (
                "repo_root".to_string(),
                JsonValue::Str(self.repo_root.clone()),
            ),
            (
                "session_id".to_string(),
                JsonValue::Str(self.session_id.clone()),
            ),
            (
                "turn_nonce".to_string(),
                JsonValue::Str(self.turn_nonce.clone()),
            ),
            (
                "compaction_epoch".to_string(),
                JsonValue::Number(self.compaction_epoch as f64),
            ),
            ("halted".to_string(), JsonValue::Bool(self.halted)),
            (
                "halt_reason".to_string(),
                match &self.halt_reason {
                    Some(r) => JsonValue::Str(r.clone()),
                    None => JsonValue::Null,
                },
            ),
            ("tainted".to_string(), JsonValue::Bool(self.tainted)),
            (
                "taint_reason".to_string(),
                match &self.taint_reason {
                    Some(r) => JsonValue::Str(r.clone()),
                    None => JsonValue::Null,
                },
            ),
            (
                "cumulative_tokens".to_string(),
                JsonValue::Number(self.cumulative_tokens as f64),
            ),
            (
                "file_reads".to_string(),
                JsonValue::Number(self.file_reads as f64),
            ),
            (
                "tool_calls".to_string(),
                JsonValue::Number(self.tool_calls as f64),
            ),
            ("nodes".to_string(), JsonValue::Object(nodes_entries)),
        ]);

        obj.to_json_string()
    }

    fn from_json(raw: &str) -> Option<Self> {
        let v = JsonValue::parse(raw).ok()?;
        let repo_root = v.get("repo_root")?.as_str()?.to_string();
        let session_id = v.get("session_id")?.as_str()?.to_string();
        let compaction_epoch = v
            .get("compaction_epoch")
            .and_then(JsonValue::as_u64)
            .unwrap_or(0) as usize;
        let turn_nonce = v
            .get("turn_nonce")
            .and_then(JsonValue::as_str)
            .filter(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .map(String::from)
            .unwrap_or_else(|| {
                generate_turn_nonce(Path::new(&repo_root), &session_id, compaction_epoch)
            });
        let halted = v.get("halted")?.as_bool()?;
        let halt_reason = v
            .get("halt_reason")
            .and_then(JsonValue::as_str)
            .map(String::from);
        let tainted = v.get("tainted")?.as_bool()?;
        let taint_reason = v
            .get("taint_reason")
            .and_then(JsonValue::as_str)
            .map(String::from);
        let cumulative_tokens = v.get("cumulative_tokens")?.as_u64()? as usize;
        let file_reads = v.get("file_reads")?.as_u64()? as usize;
        let tool_calls = v.get("tool_calls")?.as_u64()? as usize;

        let mut nodes = BTreeMap::new();
        if let Some(entries) = v.get("nodes").and_then(JsonValue::as_object) {
            for (k, node_val) in entries {
                let level = node_val.get("level")?.as_u64()? as u8;
                let chain = node_val.get("chain")?.as_str()?.to_string();
                let was_read = node_val.get("was_read")?.as_bool()?;
                nodes.insert(
                    k.clone(),
                    TraversalNode {
                        level,
                        chain,
                        was_read,
                    },
                );
            }
        }

        Some(Self {
            repo_root,
            session_id,
            turn_nonce,
            compaction_epoch,
            halted,
            halt_reason,
            tainted,
            taint_reason,
            cumulative_tokens,
            file_reads,
            tool_calls,
            nodes,
        })
    }
}

fn generate_turn_nonce(repo_root: &Path, session_id: &str, epoch: usize) -> String {
    let mut seed = Vec::with_capacity(128);
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        let mut entropy = [0u8; 16];
        if f.read_exact(&mut entropy).is_ok() {
            seed.extend_from_slice(&entropy);
        }
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    seed.extend_from_slice(&nanos.to_le_bytes());
    seed.extend_from_slice(&std::process::id().to_le_bytes());
    seed.extend_from_slice(&epoch.to_le_bytes());
    seed.extend_from_slice(repo_root.to_string_lossy().as_bytes());
    seed.push(b':');
    seed.extend_from_slice(session_id.as_bytes());
    let hex = sha256_hex(&seed);
    hex[..32].to_string()
}

fn sanitize_session_id(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "default".to_string()
    } else {
        cleaned
    }
}

pub fn validate_state_dir_override(raw: &str) -> Option<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || !crate::unicode_guard::scan_unicode(
            trimmed,
            crate::unicode_guard::ScanMode::StrictPathOrCommand,
        )
        .is_empty()
    {
        return None;
    }
    let candidate = Path::new(trimmed);
    if !candidate.is_absolute() {
        return None;
    }
    let slash = trimmed.replace('\\', "/");
    let lower = slash.to_ascii_lowercase();
    for bad_prefix in [
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/run/user",
        "/private/tmp",
        "/private/var/tmp",
        "/proc/",
    ] {
        if lower == bad_prefix || lower.starts_with(&format!("{bad_prefix}/")) {
            return None;
        }
    }

    let mut acc = PathBuf::new();
    let mut inside_git_repo = false;
    for comp in candidate.components() {
        match comp {
            std::path::Component::RootDir => acc.push("/"),
            std::path::Component::Prefix(p) => acc.push(p.as_os_str()),
            std::path::Component::CurDir | std::path::Component::ParentDir => return None,
            std::path::Component::Normal(seg) => {
                let s = seg.to_string_lossy().to_ascii_lowercase();
                if s == ".git"
                    || s.starts_with(".env")
                    || matches!(
                        s.as_str(),
                        "tmp"
                            | ".tmp"
                            | "temp"
                            | ".temp"
                            | ".cache"
                            | "__pycache__"
                            | ".pytest_cache"
                            | ".mypy_cache"
                            | ".ruff_cache"
                            | ".next"
                            | ".turbo"
                            | "node_modules"
                            | "vendor"
                            | ".venv"
                            | "venv"
                            | "site-packages"
                            | ".ssh"
                            | ".aws"
                            | ".gnupg"
                    )
                {
                    return None;
                }
                acc.push(seg);
                if let Ok(meta) = fs::symlink_metadata(&acc) {
                    if meta.file_type().is_symlink() {
                        return None;
                    }
                    if acc.join(".git").exists() {
                        inside_git_repo = true;
                    }
                }
            }
        }
    }

    // Prevent redirecting guard state/audit logs into a repository working tree
    // (allowing only dedicated `target/test-workspaces/` sandboxes used by cargo tests).
    let is_test_workspace = lower.contains("/target/test-workspaces/");
    if inside_git_repo && !is_test_workspace {
        return None;
    }

    Some(acc)
}

pub fn state_base_dir() -> PathBuf {
    if let Ok(override_dir) = std::env::var("AGENT_GUARD_STATE_DIR") {
        if let Some(valid) = validate_state_dir_override(&override_dir) {
            return valid;
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("agent-guard")
            .join("sessions");
    }
    PathBuf::from(".agent-guard-state")
}

pub fn audit_log_path() -> PathBuf {
    let base = state_base_dir();
    if base.file_name().is_some_and(|n| n == "sessions") {
        if let Some(parent) = base.parent() {
            return parent.join("audit.jsonl");
        }
    }
    base.join("audit.jsonl")
}

/// Appends a single pure-ASCII JSONL record (`0600`) to `audit.jsonl` for forensic review
/// of blocked prompt injections, poisoned pointers, or budget violations.
pub fn append_audit_jsonl(
    repo_root: &Path,
    session_id: &str,
    tool: &str,
    code: &str,
    detail: &str,
    halted: bool,
) {
    let path = audit_log_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    let ts_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ascii_detail: String = detail
        .chars()
        .map(|c| {
            if c.is_ascii() && !c.is_ascii_control() {
                c
            } else {
                '?'
            }
        })
        .take(240)
        .collect();
    let record = JsonValue::Object(vec![
        ("ts".to_string(), JsonValue::Number(ts_secs as f64)),
        (
            "repo".to_string(),
            JsonValue::Str(repo_root.to_string_lossy().into_owned()),
        ),
        (
            "session_id".to_string(),
            JsonValue::Str(sanitize_session_id(session_id)),
        ),
        ("tool".to_string(), JsonValue::Str(tool.to_string())),
        ("code".to_string(), JsonValue::Str(code.to_string())),
        ("halted".to_string(), JsonValue::Bool(halted)),
        ("detail".to_string(), JsonValue::Str(ascii_detail)),
    ]);
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{}", record.to_json_string());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
    }
}

fn ledger_file_path(repo_root: &Path, session_id: &str) -> PathBuf {
    let sid = sanitize_session_id(session_id);
    let key = format!("{}:{sid}", repo_root.display());
    let digest = sha256_hex(key.as_bytes());
    state_base_dir().join(format!("{}.json", &digest[..32]))
}

#[cfg(test)]
mod tests {
    use super::SessionLedger;
    use std::path::Path;

    #[test]
    fn enforces_a_to_b_allowed_and_b_to_c_blocked() {
        let mut ledger = SessionLedger::new(Path::new("/repo"), "s1");

        // 1. Read docs/A.md directly -> Level 1
        let lvl_a = ledger
            .authorize_and_record_read("docs/A.md", 100)
            .expect("A allowed");
        assert_eq!(lvl_a, 1);

        // A points to docs/B.md
        ledger.register_outgoing_pointers("docs/A.md", &["docs/B.md".to_string()]);

        // 2. Read docs/B.md -> Level 2 (allowed!)
        let lvl_b = ledger
            .authorize_and_record_read("docs/B.md", 100)
            .expect("B allowed");
        assert_eq!(lvl_b, 2);

        // B points to docs/C.md
        ledger.register_outgoing_pointers("docs/B.md", &["docs/C.md".to_string()]);

        // 3. Attempt to read docs/C.md -> Level 3 -> HARD STOP!
        let err = ledger
            .authorize_and_record_read("docs/C.md", 100)
            .expect_err("C must be blocked");
        assert_eq!(err.0, "TRANSITIVE_DEPTH_EXCEEDED");
    }
}
