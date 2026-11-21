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

use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::breadcrumbs::ExclusiveFileLockGuard;
use crate::budget_guard::{MAX_TURN_FILE_READS, MAX_TURN_TOKENS, MAX_TURN_TOOL_CALLS};
use crate::crypto::sha256_hex;
use crate::json::JsonValue;

pub const MAX_REFERENCE_LEVEL: u8 = 2;
pub const MAX_RECENT_DENIALS: usize = 32;
pub const MAX_RECENT_TRACES: usize = 16;

pub type HotLedgerCache = Mutex<BTreeMap<String, (u128, u64, u64, SessionLedger)>>;

fn meta_inode(meta: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraversalNode {
    /// 1 = direct read (A), 2 = first hop (A -> B), 3+ = forbidden hop (A -> B -> C)
    pub level: u8,
    /// Provenance chain description, e.g. "docs/A.md -> docs/B.md"
    pub chain: String,
    /// Whether this file itself has already been read in this step
    pub was_read: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentDenialRecord {
    pub denial_id: String,
    pub code: String,
    pub target_bin_or_tool: String,
    pub canonical_shape: String,
    pub ts_unix: u64,
}

#[derive(Debug, Clone)]
pub struct SessionLedger {
    pub repo_root: String,
    pub session_id: String,
    pub root_session_id: String,
    pub session_key_hash: String,
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
    pub last_tool_trace_id: Option<String>,
    pub recent_traces: VecDeque<(String, String)>,
    pub recent_denials: VecDeque<RecentDenialRecord>,
    pub ballot_submissions: u32,
    pub ballot_counts_by_cluster: BTreeMap<String, u32>,
    pub mcp_readonly_feedback_calls: u32,
}

pub(crate) fn resolve_default_root_session_id(clean_sid: &str) -> String {
    for var in [
        "AGENT_GUARD_ROOT_SESSION_ID",
        "AGENT_GUARD_PARENT_SESSION_ID",
    ] {
        if let Ok(raw) = std::env::var(var) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                let s = sanitize_session_id(trimmed);
                if !s.is_empty() && s != "default" {
                    return s;
                }
            }
        }
    }
    clean_sid.to_string()
}

impl SessionLedger {
    pub fn apply_root_session_override(&mut self, caller_root_sid: Option<&str>) {
        if self.root_session_id != self.session_id {
            return;
        }
        if let Some(raw) = caller_root_sid {
            let s = sanitize_session_id(raw.trim());
            if !s.is_empty() && s != "default" {
                self.root_session_id = s;
                return;
            }
        }
        let env_resolved = resolve_default_root_session_id(&self.session_id);
        if env_resolved != self.session_id {
            self.root_session_id = env_resolved;
        }
    }

    /// Acquires an exclusive per-session file lock so concurrent parallel tool hooks
    /// (`pre-tool`, `post-tool`, `pre-compact`, `user-prompt`) serialize state transitions
    /// without lost updates or clobbered circuit-breaker flags.
    pub fn acquire_lock(repo_root: &Path, session_id: &str) -> Option<ExclusiveFileLockGuard> {
        let key_hash = compute_session_key_hash(repo_root, session_id);
        let path = ledger_file_path_for_hash(&key_hash);
        ExclusiveFileLockGuard::acquire(&path).ok()
    }

    pub fn new(repo_root: &Path, session_id: &str) -> Self {
        let clean_sid = sanitize_session_id(session_id);
        let root_session_id = resolve_default_root_session_id(&clean_sid);
        let session_key_hash = compute_session_key_hash(repo_root, session_id);
        let turn_nonce = generate_turn_nonce(repo_root, session_id, 0);
        Self {
            repo_root: repo_root.to_string_lossy().into_owned(),
            session_id: clean_sid,
            root_session_id,
            session_key_hash,
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
            last_tool_trace_id: None,
            recent_traces: VecDeque::new(),
            recent_denials: VecDeque::new(),
            ballot_submissions: 0,
            ballot_counts_by_cluster: BTreeMap::new(),
            mcp_readonly_feedback_calls: 0,
        }
    }

    pub fn load_or_create(repo_root: &Path, session_id: &str) -> Self {
        let key_hash = compute_session_key_hash(repo_root, session_id);
        let path = ledger_file_path_for_hash(&key_hash);
        match read_nonsymlink_state_file(&path) {
            Ok(Some(raw)) => {
                if raw.trim().is_empty() {
                    let mut halted = Self::new(repo_root, session_id);
                    halted.trip_circuit_breaker(
                        "CORRUPT_SESSION_STATE: empty session ledger file rejected (fail-closed)"
                            .to_string(),
                    );
                    return halted;
                }
                if let Some(mut loaded) = Self::from_json(&raw) {
                    if loaded.session_key_hash.is_empty() || loaded.session_key_hash == key_hash {
                        loaded.session_key_hash = key_hash;
                        return loaded;
                    }
                }
                let mut halted = Self::new(repo_root, session_id);
                halted.trip_circuit_breaker(
                    "CORRUPT_SESSION_STATE: unreadable or mismatched session ledger JSON (fail-closed)"
                        .to_string(),
                );
                halted
            }
            Ok(None) => Self::new(repo_root, session_id),
            Err(symlink_err) => {
                let mut halted = Self::new(repo_root, session_id);
                halted.trip_circuit_breaker(format!("STATE_SYMLINK_REJECTED: {symlink_err}"));
                halted
            }
        }
    }

    pub fn save(&self, repo_root: &Path) -> Result<(), String> {
        let key_hash = if self.session_key_hash.is_empty() {
            compute_session_key_hash(repo_root, &self.session_id)
        } else {
            self.session_key_hash.clone()
        };
        let path = ledger_file_path_for_hash(&key_hash);
        // Defense-in-depth monotonic sticky merge: never clear an already-persisted
        // `halted` or `tainted` bit during an unlocked `save` call.
        let mut merged = self.clone();
        if let Ok(Some(existing_raw)) = read_nonsymlink_state_file(&path)
            && let Some(existing) = Self::from_json(&existing_raw)
            && (existing.session_key_hash.is_empty() || existing.session_key_hash == key_hash)
        {
            if existing.halted && !merged.halted {
                merged.halted = true;
                merged.halt_reason = existing.halt_reason;
            }
            if existing.tainted && !merged.tainted {
                merged.tainted = true;
                merged.taint_reason = existing.taint_reason;
            }
        }
        let serialized = merged.to_json();
        atomic_write_nonsymlink_state_file_opts(
            &path,
            serialized.as_bytes(),
            merged.halted || merged.tainted,
        )
    }

    /// Persists ledger while the caller already holds `SessionLedger::acquire_lock`,
    /// avoiding a redundant disk re-read + JSON re-parse on the hook hot path while still
    /// forcing durable storage sync whenever `halted` or `tainted` is set.
    pub fn save_locked(&self, repo_root: &Path) -> Result<(), String> {
        self.save_locked_with_cache(repo_root, None)
    }

    pub fn load_or_create_with_cache(
        repo_root: &Path,
        session_id: &str,
        cache: Option<&HotLedgerCache>,
    ) -> Self {
        let key_hash = compute_session_key_hash(repo_root, session_id);
        let path = ledger_file_path_for_hash(&key_hash);
        if let Some(hot) = cache
            && let Ok(meta) = fs::symlink_metadata(&path)
            && !meta.file_type().is_symlink()
            && meta.file_type().is_file()
            && let Some(mtime_nanos) = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
            && mtime_nanos != 0
            && let Ok(guard) = hot.lock()
            && let Some((cached_mtime, cached_len, cached_ino, cached_ledger)) =
                guard.get(&key_hash)
            && *cached_mtime == mtime_nanos
            && *cached_len == meta.len()
            && *cached_ino == meta_inode(&meta)
        {
            return cached_ledger.clone();
        }
        let loaded = Self::load_or_create(repo_root, session_id);
        if let Some(hot) = cache
            && let Ok(meta) = fs::symlink_metadata(&path)
            && !meta.file_type().is_symlink()
            && meta.file_type().is_file()
            && let Some(mtime_nanos) = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
            && mtime_nanos != 0
            && let Ok(mut guard) = hot.lock()
        {
            if guard.len() >= 256 && !guard.contains_key(&key_hash) {
                guard.clear();
            }
            guard.insert(
                key_hash,
                (mtime_nanos, meta.len(), meta_inode(&meta), loaded.clone()),
            );
        }
        loaded
    }

    pub fn save_locked_with_cache(
        &self,
        repo_root: &Path,
        cache: Option<&HotLedgerCache>,
    ) -> Result<(), String> {
        let key_hash = if self.session_key_hash.is_empty() {
            compute_session_key_hash(repo_root, &self.session_id)
        } else {
            self.session_key_hash.clone()
        };
        let path = ledger_file_path_for_hash(&key_hash);
        let serialized = self.to_json();
        atomic_write_nonsymlink_state_file_opts(
            &path,
            serialized.as_bytes(),
            self.halted || self.tainted,
        )?;
        if let Some(hot) = cache
            && let Ok(meta) = fs::symlink_metadata(&path)
            && !meta.file_type().is_symlink()
            && meta.file_type().is_file()
            && let Some(mtime_nanos) = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
            && mtime_nanos != 0
            && let Ok(mut guard) = hot.lock()
        {
            if guard.len() >= 256 && !guard.contains_key(&key_hash) {
                guard.clear();
            }
            guard.insert(
                key_hash,
                (mtime_nanos, meta.len(), meta_inode(&meta), self.clone()),
            );
        }
        Ok(())
    }

    pub fn reset_for_new_user_prompt(repo_root: &Path, session_id: &str) -> Result<Self, String> {
        let _lock = Self::acquire_lock(repo_root, session_id);
        let mut fresh = Self::new(repo_root, session_id);
        let path = ledger_file_path_for_hash(&fresh.session_key_hash);
        if let Ok(Some(raw)) = read_nonsymlink_state_file(&path)
            && let Some(prev) = Self::from_json(&raw)
            && (prev.session_key_hash.is_empty() || prev.session_key_hash == fresh.session_key_hash)
        {
            if !prev.root_session_id.is_empty() {
                fresh.root_session_id = prev.root_session_id;
            }
            fresh.last_tool_trace_id = prev.last_tool_trace_id;
            fresh.recent_denials = prev.recent_denials;
            fresh.ballot_submissions = prev.ballot_submissions;
            fresh.ballot_counts_by_cluster = prev.ballot_counts_by_cluster;
            fresh.mcp_readonly_feedback_calls = prev.mcp_readonly_feedback_calls;
        }
        let serialized = fresh.to_json();
        atomic_write_nonsymlink_state_file(&path, serialized.as_bytes())?;
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
        self.turn_nonce =
            generate_turn_nonce(repo_root, &self.session_key_hash, self.compaction_epoch);
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
        self.record_tool_call_with_limit(MAX_TURN_TOOL_CALLS)
    }

    pub fn record_tool_call_with_limit(&mut self, max_calls: usize) -> Result<(), String> {
        self.check_not_halted()?;
        if self.tool_calls >= max_calls {
            return Err(format!(
                "Step tool-call ceiling exceeded ({max_calls} calls). Compact step context immediately before continuing."
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
        self.authorize_and_record_read_with_limits(
            rel_path,
            estimated_tokens,
            MAX_TURN_FILE_READS,
            MAX_TURN_TOKENS,
        )
    }

    pub fn authorize_and_record_read_with_limits(
        &mut self,
        rel_path: &str,
        estimated_tokens: usize,
        max_file_reads: usize,
        max_turn_tokens: usize,
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
        if !already_read && self.file_reads >= max_file_reads {
            return Err((
                "FILE_READ_BUDGET_EXCEEDED",
                format!(
                    "Step file-read limit ({max_file_reads} files) reached; compact step context before reading '{rel_path}'."
                ),
            ));
        }

        let next_tokens = self.cumulative_tokens.saturating_add(estimated_tokens);
        if next_tokens > max_turn_tokens {
            return Err((
                "TURN_TOKEN_BUDGET_EXCEEDED",
                format!(
                    "Reading '{rel_path}' (+{estimated_tokens} est. tokens) would exceed tight step context ceiling ({next_tokens} > {max_turn_tokens}). Compact this step immediately rather than carrying multi-step history."
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

    /// Checks that a search target (`Grep`, `rg`, `grep`) has not already been placed
    /// beyond `MAX_REFERENCE_LEVEL` by an `A -> B -> C` file-read chain, without burning
    /// `file_reads` budget or advancing instruction-traversal hop depth.
    pub fn check_search_target(&self, rel_path: &str) -> Result<(), (&'static str, String)> {
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
        Ok(())
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
                | "grep_search"
                | "rg"
                | "ripgrep"
                | "fd"
                | "fdfind"
                | "glob"
                | "find"
                | "find_by_name"
                | "ls"
                | "list_dir"
                | "list_directory"
                | "tree"
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

    pub fn record_denial(
        &mut self,
        code: &str,
        tool_name: &str,
        shape: &str,
        ts_unix: u64,
    ) -> String {
        static DENIAL_SEQ: AtomicU64 = AtomicU64::new(0);
        let norm_code = code.trim().to_ascii_uppercase();
        if norm_code.is_empty() {
            return String::new();
        }
        let target_bin_or_tool = extract_target_bin_or_tool(tool_name, shape);
        let (canonical_shape, _) = crate::feedback::scrub_high_entropy_and_secrets(shape, 120);
        let seq = DENIAL_SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let id_seed = format!(
            "dotagent:denial:v2:{}:{}:{}:{}:{}:{}:{}",
            self.session_key_hash,
            self.tool_calls,
            self.recent_denials.len(),
            seq,
            nanos,
            norm_code,
            canonical_shape
        );
        let denial_id = format!("dnl_{}", &sha256_hex(id_seed.as_bytes())[..16]);

        while self.recent_denials.len() >= MAX_RECENT_DENIALS {
            self.recent_denials.pop_front();
        }
        self.recent_denials.push_back(RecentDenialRecord {
            denial_id: denial_id.clone(),
            code: norm_code,
            target_bin_or_tool,
            canonical_shape,
            ts_unix,
        });
        denial_id
    }

    pub fn record_allowed_tool_trace(&mut self, tool_name: &str) -> String {
        static TRACE_SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = TRACE_SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let norm_tool = if tool_name.trim().is_empty() {
            "tool"
        } else {
            tool_name.trim()
        };
        let seed = format!(
            "dotagent:trace:v2:{}:{}:{}:{}:{}",
            self.session_key_hash, self.tool_calls, seq, nanos, norm_tool
        );
        let trace_id = format!("trc_{}", &sha256_hex(seed.as_bytes())[..16]);
        self.last_tool_trace_id = Some(trace_id.clone());
        while self.recent_traces.len() >= MAX_RECENT_TRACES {
            self.recent_traces.pop_front();
        }
        self.recent_traces
            .push_back((trace_id.clone(), norm_tool.to_string()));
        trace_id
    }

    pub fn lookup_trace_by_id(&self, trace_id: &str) -> Option<&str> {
        let trimmed = trace_id.trim();
        if trimmed.is_empty() {
            return None;
        }
        if let Some((_, tname)) = self
            .recent_traces
            .iter()
            .rev()
            .find(|(tid, _)| tid == trimmed)
        {
            return Some(tname.as_str());
        }
        if self.last_tool_trace_id.as_deref() == Some(trimmed) {
            return Some("tool");
        }
        None
    }

    pub fn lookup_denial_by_id(&self, denial_id: &str) -> Option<&RecentDenialRecord> {
        let trimmed = denial_id.trim();
        if trimmed.is_empty() {
            return None;
        }
        self.recent_denials
            .iter()
            .rev()
            .find(|d| d.denial_id == trimmed)
    }

    pub fn has_recent_denial(&self, code: &str) -> bool {
        let norm = code.trim().to_ascii_uppercase();
        !norm.is_empty() && self.recent_denials.iter().any(|d| d.code == norm)
    }

    pub fn record_ballot_submission(&mut self, cluster_key: &str) -> (u32, u32) {
        self.ballot_submissions = self.ballot_submissions.saturating_add(1);
        let entry = self
            .ballot_counts_by_cluster
            .entry(cluster_key.to_string())
            .or_insert(0);
        *entry = entry.saturating_add(1);
        (*entry, self.ballot_submissions)
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

        let denials_arr: Vec<JsonValue> = self
            .recent_denials
            .iter()
            .map(|d| {
                JsonValue::Object(vec![
                    ("denial_id".to_string(), JsonValue::Str(d.denial_id.clone())),
                    ("code".to_string(), JsonValue::Str(d.code.clone())),
                    (
                        "target_bin_or_tool".to_string(),
                        JsonValue::Str(d.target_bin_or_tool.clone()),
                    ),
                    (
                        "canonical_shape".to_string(),
                        JsonValue::Str(d.canonical_shape.clone()),
                    ),
                    ("ts_unix".to_string(), JsonValue::Uint(d.ts_unix)),
                ])
            })
            .collect();

        let traces_arr: Vec<JsonValue> = self
            .recent_traces
            .iter()
            .map(|(tid, tname)| {
                JsonValue::Object(vec![
                    ("trace_id".to_string(), JsonValue::Str(tid.clone())),
                    ("tool_name".to_string(), JsonValue::Str(tname.clone())),
                ])
            })
            .collect();

        let cluster_entries: Vec<(String, JsonValue)> = self
            .ballot_counts_by_cluster
            .iter()
            .map(|(k, v)| (k.clone(), JsonValue::Uint(u64::from(*v))))
            .collect();

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
                "root_session_id".to_string(),
                JsonValue::Str(self.root_session_id.clone()),
            ),
            (
                "session_key_hash".to_string(),
                JsonValue::Str(self.session_key_hash.clone()),
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
            (
                "last_tool_trace_id".to_string(),
                match &self.last_tool_trace_id {
                    Some(t) => JsonValue::Str(t.clone()),
                    None => JsonValue::Null,
                },
            ),
            ("recent_traces".to_string(), JsonValue::Array(traces_arr)),
            ("recent_denials".to_string(), JsonValue::Array(denials_arr)),
            (
                "ballot_submissions".to_string(),
                JsonValue::Uint(u64::from(self.ballot_submissions)),
            ),
            (
                "ballot_counts_by_cluster".to_string(),
                JsonValue::Object(cluster_entries),
            ),
            (
                "mcp_readonly_feedback_calls".to_string(),
                JsonValue::Uint(u64::from(self.mcp_readonly_feedback_calls)),
            ),
        ]);

        obj.to_json_string()
    }

    fn from_json(raw: &str) -> Option<Self> {
        let v = JsonValue::parse(raw).ok()?;
        let repo_root = v.get("repo_root")?.as_str()?.to_string();
        let session_id = v.get("session_id")?.as_str()?.to_string();
        let root_session_id = v
            .get("root_session_id")
            .and_then(JsonValue::as_str)
            .map(sanitize_session_id)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| resolve_default_root_session_id(&session_id));
        let session_key_hash = v
            .get("session_key_hash")
            .and_then(JsonValue::as_str)
            .map(String::from)
            .unwrap_or_default();
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

        let last_tool_trace_id = v
            .get("last_tool_trace_id")
            .and_then(JsonValue::as_str)
            .map(String::from);

        let mut recent_traces = VecDeque::new();
        if let Some(arr) = v.get("recent_traces").and_then(JsonValue::as_array) {
            for item in arr.iter().take(MAX_RECENT_TRACES) {
                if let (Some(tid), Some(tname)) = (
                    item.get("trace_id").and_then(JsonValue::as_str),
                    item.get("tool_name").and_then(JsonValue::as_str),
                ) {
                    recent_traces.push_back((tid.to_string(), tname.to_string()));
                }
            }
        }

        let mut recent_denials = VecDeque::new();
        if let Some(arr) = v.get("recent_denials").and_then(JsonValue::as_array) {
            for item in arr.iter().take(MAX_RECENT_DENIALS) {
                let code_opt = item.get("code").and_then(JsonValue::as_str);
                let did_opt = item.get("denial_id").and_then(JsonValue::as_str);
                let tgt_opt = item
                    .get("target_bin_or_tool")
                    .or_else(|| item.get("tool_name"))
                    .and_then(JsonValue::as_str);
                let shape_opt = item
                    .get("canonical_shape")
                    .or_else(|| item.get("normalized_shape"))
                    .and_then(JsonValue::as_str);
                if let (Some(c), Some(tgt), Some(sh)) = (code_opt, tgt_opt, shape_opt) {
                    let ts = item.get("ts_unix").and_then(JsonValue::as_u64).unwrap_or(0);
                    let did = did_opt.map(String::from).unwrap_or_else(|| {
                        format!(
                            "dnl_{}",
                            &sha256_hex(format!("{session_id}:{c}:{sh}:{ts}").as_bytes())[..16]
                        )
                    });
                    recent_denials.push_back(RecentDenialRecord {
                        denial_id: did,
                        code: c.to_string(),
                        target_bin_or_tool: tgt.to_string(),
                        canonical_shape: sh.to_string(),
                        ts_unix: ts,
                    });
                }
            }
        }
        let ballot_submissions = v
            .get("ballot_submissions")
            .and_then(JsonValue::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0);
        let mut ballot_counts_by_cluster = BTreeMap::new();
        if let Some(entries) = v
            .get("ballot_counts_by_cluster")
            .and_then(JsonValue::as_object)
        {
            for (k, cnt_val) in entries {
                if let Some(cnt) = cnt_val.as_u64().and_then(|n| u32::try_from(n).ok()) {
                    ballot_counts_by_cluster.insert(k.clone(), cnt);
                }
            }
        }
        let mcp_readonly_feedback_calls = v
            .get("mcp_readonly_feedback_calls")
            .and_then(JsonValue::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0);

        Some(Self {
            repo_root,
            session_id,
            root_session_id,
            session_key_hash,
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
            last_tool_trace_id,
            recent_traces,
            recent_denials,
            ballot_submissions,
            ballot_counts_by_cluster,
            mcp_readonly_feedback_calls,
        })
    }
}

pub(crate) fn extract_target_bin_or_tool(tool_name: &str, shape: &str) -> String {
    let lower_tool = tool_name.trim().to_ascii_lowercase();
    if matches!(
        lower_tool.as_str(),
        "" | "bash" | "sh" | "run_command" | "run_terminal_cmd" | "shell" | "execute_command"
    ) {
        for raw_tok in shape.split_whitespace() {
            let trimmed = raw_tok.trim_matches(|c: char| {
                matches!(c, '"' | '\'' | '(' | ')' | '{' | '}' | ';' | '|')
            });
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.contains('=') && !trimmed.starts_with('-') {
                continue;
            }
            if matches!(trimmed, "env" | "command" | "nohup" | "time") {
                continue;
            }
            let base = trimmed.rsplit('/').next().unwrap_or(trimmed);
            let clean: String = base
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .take(48)
                .collect();
            if !clean.is_empty() {
                return clean.to_ascii_lowercase();
            }
        }
    }
    let clean: String = lower_tool
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(48)
        .collect();
    if clean.is_empty() {
        "guard".to_string()
    } else {
        clean
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

    let is_test_workspace = lower.contains("/target/test-workspaces/");
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
                    if !is_test_workspace && !inside_git_repo && acc.join(".git").exists() {
                        inside_git_repo = true;
                    }
                }
            }
        }
    }

    // Prevent redirecting guard state/audit logs into a repository working tree
    // (allowing only dedicated `target/test-workspaces/` sandboxes used by cargo tests).
    if inside_git_repo && !is_test_workspace {
        return None;
    }

    Some(acc)
}

static STATE_OVERRIDE_CACHE: Mutex<Option<(String, PathBuf)>> = Mutex::new(None);

pub fn state_base_dir() -> PathBuf {
    if let Ok(override_dir) = std::env::var("AGENT_GUARD_STATE_DIR") {
        if let Ok(guard) = STATE_OVERRIDE_CACHE.lock()
            && let Some((ref cached_raw, ref cached_path)) = *guard
            && *cached_raw == override_dir
            && fs::symlink_metadata(cached_path)
                .is_ok_and(|m| !m.file_type().is_symlink() && m.file_type().is_dir())
        {
            return cached_path.clone();
        }
        if let Some(valid) = validate_state_dir_override(&override_dir) {
            if let Ok(mut guard) = STATE_OVERRIDE_CACHE.lock() {
                *guard = Some((override_dir, valid.clone()));
            }
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

/// Guard state root: the parent of `.../sessions` for the default layout, or the
/// `AGENT_GUARD_STATE_DIR` override itself. Every auxiliary state tree (feedback spools, vaults,
/// ratchet scratch) MUST live under this root so it inherits sandbox self-blindness.
pub(crate) fn state_root_dir() -> PathBuf {
    let base = state_base_dir();
    if base.file_name().is_some_and(|n| n == "sessions")
        && let Some(parent) = base.parent()
    {
        return parent.to_path_buf();
    }
    base
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

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) const O_NOFOLLOW_FLAG: i32 = 0o400000;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(crate) const O_NOFOLLOW_FLAG: i32 = 0o100000;
#[cfg(target_os = "macos")]
pub(crate) const O_NOFOLLOW_FLAG: i32 = 0x0100;
#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
)))]
pub(crate) const O_NOFOLLOW_FLAG: i32 = 0;

pub(crate) fn ensure_nonsymlink_state_dir(dir: &Path) -> Result<(), String> {
    if let Ok(meta) = fs::symlink_metadata(dir) {
        if meta.file_type().is_symlink() {
            return Err(format!("state directory '{}' is a symlink", dir.display()));
        }
        if !meta.file_type().is_dir() {
            return Err(format!(
                "state directory '{}' is not a regular directory",
                dir.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if (meta.permissions().mode() & 0o777) != 0o700 {
                let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
            }
        }
        return Ok(());
    }
    fs::create_dir_all(dir)
        .map_err(|e| format!("failed creating state dir '{}': {e}", dir.display()))?;
    let meta = fs::symlink_metadata(dir)
        .map_err(|e| format!("failed stat on state dir '{}': {e}", dir.display()))?;
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Err(format!(
            "state directory '{}' is not a regular directory",
            dir.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

pub fn read_nonsymlink_state_file(path: &Path) -> Result<Option<String>, String> {
    if let Some(parent) = path.parent()
        && let Ok(pm) = fs::symlink_metadata(parent)
        && pm.file_type().is_symlink()
    {
        return Err(format!("state parent '{}' is a symlink", parent.display()));
    }
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot stat '{}': {e}", path.display())),
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(format!(
            "state file '{}' is a symlink or non-regular file",
            path.display()
        ));
    }

    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos"
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(O_NOFOLLOW_FLAG);
    }

    let file = opts
        .open(path)
        .map_err(|e| format!("cannot open state file '{}': {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let fmeta = file
            .metadata()
            .map_err(|e| format!("fstat failed on '{}': {e}", path.display()))?;
        if fmeta.dev() != meta.dev() || fmeta.ino() != meta.ino() {
            return Err(format!(
                "TOCTOU inode mismatch opening state file '{}'",
                path.display()
            ));
        }
    }

    let mut buf = Vec::new();
    file.take(262_144)
        .read_to_end(&mut buf)
        .map_err(|e| format!("failed reading state file '{}': {e}", path.display()))?;
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| format!("non-UTF-8 bytes in state file '{}'", path.display()))
}

static STAGE_SEQ: AtomicU64 = AtomicU64::new(0);

pub fn atomic_write_nonsymlink_state_file(path: &Path, data: &[u8]) -> Result<(), String> {
    atomic_write_nonsymlink_state_file_opts(path, data, true)
}

pub fn atomic_write_nonsymlink_state_file_opts(
    path: &Path,
    data: &[u8],
    durable_sync: bool,
) -> Result<(), String> {
    let Some(parent) = path.parent() else {
        return Err("state file missing parent directory".to_string());
    };
    ensure_nonsymlink_state_dir(parent)?;
    if let Ok(existing) = fs::symlink_metadata(path)
        && existing.file_type().is_symlink()
    {
        return Err(format!(
            "refusing to overwrite symlinked state file '{}'",
            path.display()
        ));
    }

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = STAGE_SEQ.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("state.json");
    let stage = parent.join(format!(
        ".{file_name}.stage.{}.{seq}.{nanos}",
        std::process::id()
    ));
    let _ = fs::remove_file(&stage);

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&stage)
        .map_err(|e| format!("failed creating staging file '{}': {e}", stage.display()))?;
    let write_res = if durable_sync {
        f.write_all(data).and_then(|()| f.sync_data())
    } else {
        f.write_all(data)
    };
    if let Err(e) = write_res {
        let _ = fs::remove_file(&stage);
        return Err(format!(
            "failed writing staging file '{}': {e}",
            stage.display()
        ));
    }
    drop(f);

    if let Ok(dest_meta) = fs::symlink_metadata(path)
        && dest_meta.file_type().is_symlink()
    {
        let _ = fs::remove_file(&stage);
        return Err(format!(
            "refusing to rename over symlinked state file '{}'",
            path.display()
        ));
    }
    fs::rename(&stage, path).map_err(|e| {
        let _ = fs::remove_file(&stage);
        format!("failed renaming state file '{}': {e}", path.display())
    })
}

/// Appends a single pure-ASCII JSONL record (`0600`) to `audit.jsonl` without following symlinks.
pub fn append_audit_jsonl(
    repo_root: &Path,
    session_id: &str,
    tool: &str,
    code: &str,
    detail: &str,
    halted: bool,
) {
    let path = audit_log_path();
    let Some(parent) = path.parent() else {
        return;
    };
    if ensure_nonsymlink_state_dir(parent).is_err() {
        return;
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
    let session_hash = compute_session_key_hash(repo_root, session_id);
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
        (
            "session_hash".to_string(),
            JsonValue::Str(session_hash[..16].to_string()),
        ),
        ("tool".to_string(), JsonValue::Str(tool.to_string())),
        ("code".to_string(), JsonValue::Str(code.to_string())),
        ("halted".to_string(), JsonValue::Bool(halted)),
        ("detail".to_string(), JsonValue::Str(ascii_detail.clone())),
    ]);

    let _audit_lock = ExclusiveFileLockGuard::acquire(&path);
    let file_opt = match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            opts.open(&path).ok()
        }
        Ok(meta) if !meta.file_type().is_symlink() && meta.file_type().is_file() => {
            let mut opts = OpenOptions::new();
            opts.write(true).append(true);
            #[cfg(any(
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                ),
                target_os = "macos"
            ))]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.custom_flags(O_NOFOLLOW_FLAG);
            }
            opts.open(&path).ok().filter(|f| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    f.metadata()
                        .map(|fm| fm.dev() == meta.dev() && fm.ino() == meta.ino())
                        .unwrap_or(false)
                }
                #[cfg(not(unix))]
                {
                    let _ = f;
                    true
                }
            })
        }
        _ => None,
    };

    if let Some(mut file) = file_opt {
        let _ = writeln!(file, "{}", record.to_json_string());
    }

    crate::feedback::record_guard_denial_agentpi_signal(
        repo_root,
        &session_hash[..16],
        tool,
        code,
        &ascii_detail,
        halted,
        ts_secs,
    );
}

/// Host/coordinator-only check verifying whether `(repo_root, session_id)` actually experienced
/// `expected_code` in `audit.jsonl` (never exposed to agents; preserves `GUARD_SELF_BLINDNESS`).
pub fn audit_log_has_session_denial(
    repo_root: &Path,
    session_id: &str,
    expected_code: &str,
) -> bool {
    use std::io::{Seek, SeekFrom};
    let norm_code = expected_code.trim().to_ascii_uppercase();
    if norm_code.is_empty() {
        return false;
    }
    let path = audit_log_path();
    let Ok(meta) = fs::symlink_metadata(&path) else {
        return false;
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return false;
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos"
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(O_NOFOLLOW_FLAG);
    }
    let Ok(mut file) = opts.open(&path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(fm) = file.metadata() else {
            return false;
        };
        if fm.dev() != meta.dev() || fm.ino() != meta.ino() {
            return false;
        }
    }
    if meta.len() > 262_144 {
        let _ = file.seek(SeekFrom::End(-262_144));
    }
    let mut buf = Vec::new();
    if file.take(262_144).read_to_end(&mut buf).is_err() {
        return false;
    }
    let raw = String::from_utf8_lossy(&buf);
    let expected_hash = compute_session_key_hash(repo_root, session_id);
    let prefix = &expected_hash[..16];
    for line in raw.lines().rev().take(512) {
        if let Ok(v) = JsonValue::parse(line) {
            let sh = v
                .get("session_hash")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            let c = v.get("code").and_then(JsonValue::as_str).unwrap_or("");
            if sh == prefix && c.eq_ignore_ascii_case(&norm_code) {
                return true;
            }
        }
    }
    false
}

pub fn compute_session_key_hash(repo_root: &Path, raw_session_id: &str) -> String {
    let effective_repo = if repo_root.join(".git").is_file() {
        crate::resolve_common_repo_root(repo_root)
    } else {
        repo_root.to_path_buf()
    };
    let repo_bytes = effective_repo.to_string_lossy();
    let framed = format!(
        "v2:{}:{}:{}:{}",
        repo_bytes.len(),
        repo_bytes,
        raw_session_id.len(),
        raw_session_id
    );
    sha256_hex(framed.as_bytes())
}

pub fn session_ledger_path(repo_root: &Path, session_id: &str) -> PathBuf {
    let key_hash = compute_session_key_hash(repo_root, session_id);
    ledger_file_path_for_hash(&key_hash)
}

fn ledger_file_path_for_hash(session_key_hash: &str) -> PathBuf {
    let prefix = if session_key_hash.len() >= 32 {
        &session_key_hash[..32]
    } else {
        session_key_hash
    };
    state_base_dir().join(format!("{prefix}.json"))
}

#[cfg(test)]
mod tests {
    use super::{SessionLedger, compute_session_key_hash};
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

        // 4. Lossless session hash separates punctuation/Unicode collisions
        assert_ne!(
            compute_session_key_hash(Path::new("/repo"), "abc/def"),
            compute_session_key_hash(Path::new("/repo"), "abcdef")
        );
        assert_ne!(
            compute_session_key_hash(Path::new("/repo"), "\u{03B1}"),
            compute_session_key_hash(Path::new("/repo"), "\u{03B2}")
        );
    }
}
