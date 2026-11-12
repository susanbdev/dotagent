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
use std::fs;
use std::path::{Path, PathBuf};

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
    /// Whether this file itself has already been read in this turn
    pub was_read: bool,
}

#[derive(Debug, Clone)]
pub struct SessionLedger {
    pub repo_root: String,
    pub session_id: String,
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
        Self {
            repo_root: repo_root.to_string_lossy().into_owned(),
            session_id: sanitize_session_id(session_id),
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
                "Turn tool-call ceiling exceeded ({MAX_TURN_TOOL_CALLS} calls). Halting to prevent runaway loop / token exhaustion."
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
                    "Turn file-read limit ({MAX_TURN_FILE_READS} files) reached; refusing '{rel_path}' to prevent context window saturation."
                ),
            ));
        }

        let next_tokens = self.cumulative_tokens.saturating_add(estimated_tokens);
        if next_tokens > MAX_TURN_TOKENS {
            return Err((
                "TURN_TOKEN_BUDGET_EXCEEDED",
                format!(
                    "Reading '{rel_path}' (+{estimated_tokens} est. tokens) would exceed turn untrusted token ceiling ({next_tokens} > {MAX_TURN_TOKENS}). Stop and summarize before saturating context."
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

pub fn state_base_dir() -> PathBuf {
    if let Ok(override_dir) = std::env::var("AGENT_GUARD_STATE_DIR") {
        let trimmed = override_dir.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
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
