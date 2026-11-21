//! Typed zero-trust denial catalog and `explain <CODE>` operator reference.
//!
//! Every `GuardCode` variant maps bijectively (`as_str` / `from_code`) to a structured
//! `CodeExplanation` so denial codes across hooks, CLI subcommands, tests, and documentation
//! have compile-time exhaustiveness and instant one-line operator remediation.

use std::process::ExitCode;

use crate::json::JsonValue;

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuardCode {
    UnknownSubcommand,
    InvalidHookJson,
    HookInputOverflow,
    CorruptSessionState,
    SessionCircuitBreakerTripped,
    PoisonedPointerDetected,
    UnauthorizedInstructionFile,
    TransitiveHopLimitExceeded,
    ForbiddenDirectoryAccess,
    CrossRepositoryEscape,
    SymlinkEscapeBlocked,
    MaxDepthExceeded,
    UnboundedGitLog,
    FileByteBudgetExceeded,
    SliceLineCapExceeded,
    SingleLineBombBlocked,
    TokenizerSplitterBomb,
    TurnTokenBudgetExceeded,
    TurnReadCountExceeded,
    TurnToolCallLimitExceeded,
    NonAsciiSanitizedPrebuffer,
    BidiControlCharacter,
    UnicodeTagSmuggling,
    PromptInjectionDetected,
    HardcodedSecretLiteral,
    ImmutableControlPlane,
    GitHooksNotDisabled,
    ConfusedDeputyBlocked,
    DestructiveGitBlocked,
    UnknownRuntimeProfile,
    UnknownProfileKey,
    ProfileInvariantLoosened,
    RoleCapabilityMismatch,
    GruntWriteOutOfScope,
    PrivilegedDomainDenied,
    PrivilegedRoleDenied,
    UnmintedCapabilityDenied,
    CapabilityScopeEscalationDenied,
    LedgerSentenceCountInvalid,
    SandboxBinaryUnavailable,
    SessionResetRequiresHumanTty,
    SessionResetDeniedInSandbox,
    AmbiguousToolParamAlias,
    UnrecognizedHmacDomainDenied,
    Ring0RatchetViolation,
    FeedbackOperatorOnly,
    InvalidFeedbackBallot,
    FeedbackRateLimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeExplanation {
    pub variant: GuardCode,
    pub code: &'static str,
    pub severity: &'static str,
    pub category: &'static str,
    pub summary: &'static str,
    pub rationale: &'static str,
    pub remediation: &'static str,
}

const CATALOG: &[CodeExplanation] = &[
    CodeExplanation {
        variant: GuardCode::UnknownSubcommand,
        code: "UNKNOWN_SUBCOMMAND",
        severity: "HARD_DENY",
        category: "cli",
        summary: "Unrecognized CLI subcommand rejected fail-closed (exit 2).",
        rationale: "Exiting 0 on misspelled hook subcommands (e.g. `pre_tool`) would cause Claude, Gemini, or Cursor to allow uninspected tool execution.",
        remediation: "Run `dotagent --help` or `agent-guard --help` and fix the subcommand spelling in your hook config.",
    },
    CodeExplanation {
        variant: GuardCode::InvalidHookJson,
        code: "INVALID_HOOK_JSON",
        severity: "HARD_DENY",
        category: "json",
        summary: "Hook payload violated strict RFC 8259 / RFC 7493 I-JSON grammar.",
        rationale: "Duplicate object keys or malformed numbers enable first-wins vs last-wins parser-differential smuggling between harnesses and `agent-guard`.",
        remediation: "Ensure hook stdin contains a single valid UTF-8 JSON object with unique keys.",
    },
    CodeExplanation {
        variant: GuardCode::HookInputOverflow,
        code: "HOOK_INPUT_OVERFLOW",
        severity: "HARD_DENY",
        category: "budget",
        summary: "Hook stdin exceeded the 256 KiB payload ceiling.",
        rationale: "Caps memory and CPU latency on adversarial tool-input/output context bombs.",
        remediation: "Read or write files in bounded slices (`<= 150` lines, `<= 24 KiB`) instead of streaming multi-hundred-KiB blobs through hook JSON.",
    },
    CodeExplanation {
        variant: GuardCode::CorruptSessionState,
        code: "CORRUPT_SESSION_STATE",
        severity: "CIRCUIT_BREAKER",
        category: "ledger",
        summary: "On-disk `SessionLedger` JSON was empty, truncated, or mismatched.",
        rationale: "Resetting corrupt session state to `halted = false` would allow state-file tampering to clear an active circuit breaker.",
        remediation: "From an interactive human terminal, run `dotagent session-reset` to initialize a clean session ledger.",
    },
    CodeExplanation {
        variant: GuardCode::SessionCircuitBreakerTripped,
        code: "SESSION_CIRCUIT_BREAKER_TRIPPED",
        severity: "CIRCUIT_BREAKER",
        category: "ledger",
        summary: "Session is halted after an earlier high-severity security trigger.",
        rationale: "Once untrusted data attempts prompt injection, Bidi/Tag smuggling, or poisoned-pointer redirection, subsequent tool calls in that session cannot be trusted.",
        remediation: "Inspect the triggering file reported by the agent, then run `dotagent session-reset` from your human TTY.",
    },
    CodeExplanation {
        variant: GuardCode::PoisonedPointerDetected,
        code: "POISONED_POINTER_DETECTED",
        severity: "CIRCUIT_BREAKER",
        category: "injection",
        summary: "Untrusted text attempted to direct the agent into `/tmp`, cache, or `node_modules`.",
        rationale: "Indirect prompt-injection payloads frequently stage second-stage instructions inside temp, cache, or dependency directories.",
        remediation: "Quarantine or sanitize the file containing the poisoned path reference, then run `dotagent session-reset` from a human TTY.",
    },
    CodeExplanation {
        variant: GuardCode::UnauthorizedInstructionFile,
        code: "UNAUTHORIZED_INSTRUCTION_FILE",
        severity: "CIRCUIT_BREAKER",
        category: "authority",
        summary: "Access to a nested or shadow instruction file (`CLAUDE.md`, `.cursorrules`, nested `AGENTS.md`) was blocked.",
        rationale: "Only `<repo_root>/AGENTS.md` at depth 0 holds Ring-1 authority; shadow instruction files in subdirectories are treated as hostile takeover vectors.",
        remediation: "Consolidate legitimate repository rules into root `AGENTS.md` and remove nested shadow rule files.",
    },
    CodeExplanation {
        variant: GuardCode::TransitiveHopLimitExceeded,
        code: "TRANSITIVE_HOP_LIMIT_EXCEEDED",
        severity: "HARD_DENY",
        category: "traversal",
        summary: "Pointer chain exceeded the 2-level (`File A -> File B`) reference ceiling.",
        rationale: "Unbounded `A -> B -> C` pointer chasing enables multi-hop context poisoning across untrusted files.",
        remediation: "Stop at `File B` and ask the human user before opening `File C`.",
    },
    CodeExplanation {
        variant: GuardCode::ForbiddenDirectoryAccess,
        code: "FORBIDDEN_DIRECTORY_ACCESS",
        severity: "HARD_DENY",
        category: "path",
        summary: "Attempted read/write/search inside temp, cache, vendor, `node_modules`, `.env*`, or guard state.",
        rationale: "Enforces zero snooping across ephemeral `/tmp`, package caches, dependency trees, credentials, and `agent-guard` state.",
        remediation: "Target source files inside the active repository root only.",
    },
    CodeExplanation {
        variant: GuardCode::CrossRepositoryEscape,
        code: "CROSS_REPOSITORY_ESCAPE",
        severity: "HARD_DENY",
        category: "path",
        summary: "Path resolved outside the active repository root.",
        rationale: "Prevents lateral movement or confused-deputy reads/writes into sibling repositories or `$HOME`.",
        remediation: "Stay within the current repository root unless the user switches workspaces.",
    },
    CodeExplanation {
        variant: GuardCode::SymlinkEscapeBlocked,
        code: "SYMLINK_ESCAPE_BLOCKED",
        severity: "CIRCUIT_BREAKER",
        category: "path",
        summary: "Path traversed a symbolic link escaping the repository or pointing to a forbidden zone.",
        rationale: "Defeats lexical path-check bypasses via crafted symlinks.",
        remediation: "Replace repository symlinks targeting external/temp paths with regular in-repo files.",
    },
    CodeExplanation {
        variant: GuardCode::MaxDepthExceeded,
        code: "MAX_DEPTH_EXCEEDED",
        severity: "RECOVERABLE_BOUND",
        category: "traversal",
        summary: "Directory walk or search omitted `--max-depth 2` / `-maxdepth 2` (or used `**` / `-R`).",
        rationale: "Prevents context flooding and accidental traversal into deep dependency/cache trees.",
        remediation: "Re-run with `rg --max-depth 2 <pattern> <subdir>` or `find <subdir> -maxdepth 2`.",
    },
    CodeExplanation {
        variant: GuardCode::UnboundedGitLog,
        code: "UNBOUNDED_GIT_LOG",
        severity: "RECOVERABLE_BOUND",
        category: "budget",
        summary: "`git log` was invoked without `-n <= 20` / `--max-count <= 20`.",
        rationale: "Unbounded commit logs bloat the context window and expose historical untrusted commit messages.",
        remediation: "Pass `-n 20` (e.g., `git log -n 20 --oneline`).",
    },
    CodeExplanation {
        variant: GuardCode::FileByteBudgetExceeded,
        code: "FILE_BYTE_BUDGET_EXCEEDED",
        severity: "RECOVERABLE_BOUND",
        category: "budget",
        summary: "Full-file read exceeded the 24 KiB micro-window budget.",
        rationale: "Keeps per-step context tiny and bounded.",
        remediation: "Read a bounded line slice (`offset` + `limit <= 150`) or use `agent-guard read-safe <path> --offset 1 --limit 150`.",
    },
    CodeExplanation {
        variant: GuardCode::SliceLineCapExceeded,
        code: "SLICE_LINE_CAP_EXCEEDED",
        severity: "RECOVERABLE_BOUND",
        category: "budget",
        summary: "Requested read slice exceeded 150 lines.",
        rationale: "Enforces `<= 150`-line micro-windows per read step.",
        remediation: "Reduce `limit` (or `EndLine - StartLine + 1`) to `<= 150` lines.",
    },
    CodeExplanation {
        variant: GuardCode::SingleLineBombBlocked,
        code: "SINGLE_LINE_BOMB_BLOCKED",
        severity: "HARD_DENY",
        category: "budget",
        summary: "File contains a minified/single-line payload exceeding `2,048` bytes on one line.",
        rationale: "Blocks minified JS/WASM bundles and single-line token bombs disguised as source code.",
        remediation: "Format the file across normal line lengths (`<= 2,048` bytes/line) and skip minified bundles.",
    },
    CodeExplanation {
        variant: GuardCode::TokenizerSplitterBomb,
        code: "TOKENIZER_SPLITTER_BOMB",
        severity: "HARD_DENY",
        category: "budget",
        summary: "High token-per-byte density (`> 0.72` tokens/byte) detected.",
        rationale: "Alternating punctuation/symbol payloads exhaust BPE token budgets far faster than byte caps.",
        remediation: "Inspect and remove dense synthetic symbol runs before reading.",
    },
    CodeExplanation {
        variant: GuardCode::TurnTokenBudgetExceeded,
        code: "TURN_TOKEN_BUDGET_EXCEEDED",
        severity: "RECOVERABLE_BOUND",
        category: "budget",
        summary: "Cumulative step token budget (`16,000` tokens on `coding-agent`) reached.",
        rationale: "Prevents multi-feature context accumulation and attention dilution.",
        remediation: "Compact step context now (`pre-compact`) or start a fresh prompt turn.",
    },
    CodeExplanation {
        variant: GuardCode::TurnReadCountExceeded,
        code: "TURN_READ_COUNT_EXCEEDED",
        severity: "RECOVERABLE_BOUND",
        category: "budget",
        summary: "Step file-read count ceiling (`18` reads) reached.",
        rationale: "Encourages targeted searches and subagent airlock delegation for broad exploration.",
        remediation: "Delegate multi-file surveys to `research-airlock` or compact the current step.",
    },
    CodeExplanation {
        variant: GuardCode::TurnToolCallLimitExceeded,
        code: "TURN_TOOL_CALL_LIMIT_EXCEEDED",
        severity: "RECOVERABLE_BOUND",
        category: "budget",
        summary: "Step tool-call ceiling (`28` calls) reached.",
        rationale: "Bounds autonomous loops within a single step window.",
        remediation: "Compact context or summarize progress to the user.",
    },
    CodeExplanation {
        variant: GuardCode::NonAsciiSanitizedPrebuffer,
        code: "NON_ASCII_SANITIZED_PREBUFFER",
        severity: "SANITIZED_REPLACEMENT",
        category: "unicode",
        summary: "Non-ASCII bytes or escape sequences were neutered into clean 7-bit ASCII.",
        rationale: "Pre-buffer 7-bit ASCII sanitization neutralizes homoglyphs, ANSI terminal escapes, and encoded smuggling without halting benign Unicode docs.",
        remediation: "Consume the provided clean 7-bit ASCII payload directly; do not re-read raw bytes.",
    },
    CodeExplanation {
        variant: GuardCode::BidiControlCharacter,
        code: "BIDI_CONTROL_CHARACTER",
        severity: "CIRCUIT_BREAKER",
        category: "unicode",
        summary: "Trojan Source bidirectional override/isolate character (`U+202A..U+202E`, `U+2066..U+2069`) detected.",
        rationale: "Bidi controls visually reorder source code and comments to hide malicious logic.",
        remediation: "Strip all Bidi control codepoints from the file and run `dotagent session-reset`.",
    },
    CodeExplanation {
        variant: GuardCode::UnicodeTagSmuggling,
        code: "UNICODE_TAG_SMUGGLING",
        severity: "CIRCUIT_BREAKER",
        category: "unicode",
        summary: "Invisible Plane-14 Unicode Tag (`U+E0000..U+E007F`) or Glassworm Variation Selector detected.",
        rationale: "Invisible Unicode tag planes encode hidden ASCII prompt injections that render zero-width to human reviewers.",
        remediation: "Strip invisible Unicode Tag / Variation Selector codepoints and run `dotagent session-reset`.",
    },
    CodeExplanation {
        variant: GuardCode::PromptInjectionDetected,
        code: "PROMPT_INJECTION_DETECTED",
        severity: "CIRCUIT_BREAKER",
        category: "injection",
        summary: "Hostile role-override, rule-cancellation, or spotlight-delimiter spoofing phrase detected.",
        rationale: "Quarantines untrusted data attempting to hijack agent instructions or close `<<<UNTRUSTED_ASCII_DATA_<nonce>>>>`.",
        remediation: "Quote the flagged snippet to the user and run `dotagent session-reset` once resolved.",
    },
    CodeExplanation {
        variant: GuardCode::HardcodedSecretLiteral,
        code: "HARDCODED_SECRET_LITERAL",
        severity: "CIRCUIT_BREAKER",
        category: "secrets",
        summary: "Edited file contained a high-confidence API key, private key block, or bearer token literal.",
        rationale: "Prevents accidental credential commits into version control.",
        remediation: "Remove the secret literal, load credentials via sanctioned secret references, and run `dotagent session-reset`.",
    },
    CodeExplanation {
        variant: GuardCode::ImmutableControlPlane,
        code: "IMMUTABLE_CONTROL_PLANE",
        severity: "HARD_DENY",
        category: "authority",
        summary: "Write attempt targeted an immutable control-plane file (`AGENTS.md`, `.cargo/config*`, `.gitattributes`, `.claude/*`).",
        rationale: "Agents must never modify their own security policy, git filter drivers, or compiler wrapper configs.",
        remediation: "Ask the human operator to review and apply control-plane changes manually.",
    },
    CodeExplanation {
        variant: GuardCode::GitHooksNotDisabled,
        code: "GIT_HOOKS_NOT_DISABLED",
        severity: "HARD_DENY",
        category: "git",
        summary: "Global Git configuration is missing one or more of the 19 required hardening keys (`core.hooksPath=/dev/null`, etc.).",
        rationale: "Repository `.git/hooks`, `core.fsmonitor`, or `ext::` protocols execute arbitrary shell commands during benign `git status`/`git diff` calls.",
        remediation: "Run `dotagent activate` (or `scripts/activate-local.sh`) to apply all 19 global Git lockdown keys.",
    },
    CodeExplanation {
        variant: GuardCode::ConfusedDeputyBlocked,
        code: "CONFUSED_DEPUTY_BLOCKED",
        severity: "HARD_DENY",
        category: "shell",
        summary: "Blocked network client, script-running installer, or autonomous external mutation (`curl`, `wget`, `npx`, `git push`, `gh pr merge`).",
        rationale: "Prevents data exfiltration, postinstall script RCE, and unapproved external mutations.",
        remediation: "Use `npm install --ignore-scripts` for packages, and let the human user run or explicitly authorize `git push` / `gh` mutations.",
    },
    CodeExplanation {
        variant: GuardCode::DestructiveGitBlocked,
        code: "DESTRUCTIVE_GIT_BLOCKED",
        severity: "HARD_DENY",
        category: "git",
        summary: "Blocked history-rewriting or worktree-destroying Git command (`reset --hard`, `clean`, `rebase`, `commit --amend`, `push --force`).",
        rationale: "Preserves commit provenance and prevents irreversible loss of uncommitted work.",
        remediation: "Create a forward commit instead of amending or rewriting history.",
    },
    CodeExplanation {
        variant: GuardCode::UnknownRuntimeProfile,
        code: "UNKNOWN_RUNTIME_PROFILE",
        severity: "HARD_DENY",
        category: "profile",
        summary: "`AGENT_GUARD_PROFILE` referenced an unrecognized profile identifier.",
        rationale: "Unknown profiles fail closed rather than silently falling back to permissive defaults.",
        remediation: "Set `AGENT_GUARD_PROFILE` to `coding-agent`, `research-readonly`, `adversarial-reviewer`, or a valid `swarm-*` profile.",
    },
    CodeExplanation {
        variant: GuardCode::UnknownProfileKey,
        code: "UNKNOWN_PROFILE_KEY",
        severity: "HARD_DENY",
        category: "profile",
        summary: "`profiles/<id>.toml` contained an unrecognized section or configuration key.",
        rationale: "Eliminates 'Potemkin' security knobs that look enforced in TOML but are silently ignored at runtime.",
        remediation: "Remove the unknown key or update `budget_guard.rs` to enforce it explicitly.",
    },
    CodeExplanation {
        variant: GuardCode::ProfileInvariantLoosened,
        code: "PROFILE_INVARIANT_LOOSENED",
        severity: "HARD_DENY",
        category: "profile",
        summary: "`profiles/<id>.toml` attempted to loosen a mandatory kernel invariant (e.g. enabling git hooks or nested authority files).",
        rationale: "Workspace profiles may tighten budgets or disable network/writes, never weaken Ring-1 invariants.",
        remediation: "Restore mandatory invariants (`disable_all_hooks = true`, `allow_nested_authority_files = false`, `hooks_path = \"/dev/null\"`).",
    },
    CodeExplanation {
        variant: GuardCode::RoleCapabilityMismatch,
        code: "ROLE_CAPABILITY_MISMATCH",
        severity: "HARD_DENY",
        category: "swarm",
        summary: "Swarm worker attempted to invoke a CLI namespace or session belonging to a different `SwarmRole`.",
        rationale: "Enforces strict least-privilege separation across `master`, `investigator`, `qa`, `grunt`, `reviewer`, and `coroner`.",
        remediation: "Invoke only the `swarm-tool <role>` subcommands matching your minted `SessionCapability`.",
    },
    CodeExplanation {
        variant: GuardCode::GruntWriteOutOfScope,
        code: "GRUNT_WRITE_OUT_OF_SCOPE",
        severity: "HARD_DENY",
        category: "swarm",
        summary: "Swarm `grunt` worker attempted to modify a path outside `allowed_write_paths`.",
        rationale: "Confines parallel DAG workers to disjoint file scopes verified by HMAC-signed capabilities.",
        remediation: "Edit only paths listed in `swarm-tool grunt context`, or emit `swarm-tool grunt report-blocker --missing-path <path>`.",
    },
    CodeExplanation {
        variant: GuardCode::PrivilegedDomainDenied,
        code: "PRIVILEGED_DOMAIN_DENIED",
        severity: "HARD_DENY",
        category: "coordinator",
        summary: "Sandboxed worker attempted to sign a host-only HMAC domain (`PLAN_LOCK`) over `coord.sock`.",
        rationale: "`PLAN.lock.json` authority belongs exclusively to host-side `Master` with direct `vault/hmac.key` possession.",
        remediation: "Lock DAG plans on the host via `swarm-tool master lock-plan` outside `exec-sandbox`.",
    },
    CodeExplanation {
        variant: GuardCode::PrivilegedRoleDenied,
        code: "PRIVILEGED_ROLE_DENIED",
        severity: "HARD_DENY",
        category: "coordinator",
        summary: "Coordinator IPC rejected an attempt to sign a `master` capability.",
        rationale: "Prevents a sandboxed worker with access to `coord.sock` from self-minting `master` supervisor privileges.",
        remediation: "Mint sessions strictly from host-side `Master`.",
    },
    CodeExplanation {
        variant: GuardCode::UnmintedCapabilityDenied,
        code: "UNMINTED_CAPABILITY_DENIED",
        severity: "HARD_DENY",
        category: "coordinator",
        summary: "Coordinator IPC rejected a capability update for a session ID not previously minted on disk.",
        rationale: "Workers may update counters on existing host-minted capabilities, never mint new sessions over IPC.",
        remediation: "Mint the worker session first via `swarm-tool master mint-session`.",
    },
    CodeExplanation {
        variant: GuardCode::CapabilityScopeEscalationDenied,
        code: "CAPABILITY_SCOPE_ESCALATION_DENIED",
        severity: "HARD_DENY",
        category: "coordinator",
        summary: "Coordinator IPC rejected an attempt to alter immutable capability fields (`role`, `task_id`, `plan_sha256`, path scopes).",
        rationale: "Guarantees worker IPC re-signing can only advance runtime counters (`consecutive_test_failures`, `last_green_tree_oid`).",
        remediation: "If broader file scope is required, emit `report-blocker` so `Master` can re-plan.",
    },
    CodeExplanation {
        variant: GuardCode::LedgerSentenceCountInvalid,
        code: "LEDGER_SENTENCE_COUNT_INVALID",
        severity: "RECOVERABLE_BOUND",
        category: "swarm",
        summary: "Work-ledger `--what` or `--why` summary did not contain exactly 2 printable ASCII sentences.",
        rationale: "Enforces concise, fixed-bound `2+2` provenance receipts for zero-bloat `Master`/`Reviewer` handoffs.",
        remediation: "Provide exactly 2 complete ASCII sentences ending in `.`, `!`, or `?` for both `--what` and `--why` (abbreviations like `e.g.`, `i.e.`, `vs.`, and `v1.0` are supported).",
    },
    CodeExplanation {
        variant: GuardCode::SandboxBinaryUnavailable,
        code: "SANDBOX_BINARY_UNAVAILABLE",
        severity: "HARD_DENY",
        category: "sandbox",
        summary: "`swarm-tool grunt checkpoint-green` refused to run a test command without `exec-sandbox`.",
        rationale: "Never falls back to unsandboxed host execution where untrusted tests could read `vault/hmac.key` or open outbound sockets.",
        remediation: "Ensure `agent-guard` / `swarm-tool` is installed cleanly via `dotagent activate`.",
    },
    CodeExplanation {
        variant: GuardCode::SessionResetRequiresHumanTty,
        code: "SESSION_RESET_REQUIRES_HUMAN_TTY",
        severity: "HARD_DENY",
        category: "operator",
        summary: "`session-reset` was invoked from a non-interactive pipe or background subshell.",
        rationale: "Prevents an AI agent from clearing its own `halted` / `tainted` circuit breaker via a tool call.",
        remediation: "Run `dotagent session-reset` directly inside your interactive terminal.",
    },
    CodeExplanation {
        variant: GuardCode::SessionResetDeniedInSandbox,
        code: "SESSION_RESET_DENIED_IN_SANDBOX",
        severity: "HARD_DENY",
        category: "operator",
        summary: "`session-reset` was invoked inside `exec-sandbox` or a locked Swarm worker.",
        rationale: "Sandboxed agent subprocesses are strictly prohibited from resetting guard state.",
        remediation: "Run `dotagent session-reset` from an unsandboxed human shell.",
    },
    CodeExplanation {
        variant: GuardCode::AmbiguousToolParamAlias,
        code: "AMBIGUOUS_TOOL_PARAM_ALIAS",
        severity: "CIRCUIT_BREAKER",
        category: "json",
        summary: "Tool input supplied multiple cross-harness synonym keys simultaneously.",
        rationale: "Supplying both `file_path` and `AbsolutePath` (or `command` and `CommandLine`) enables cross-schema parameter smuggling where one key passes validation while the harness executes the other.",
        remediation: "Pass only the single canonical parameter name expected by the active tool schema.",
    },
    CodeExplanation {
        variant: GuardCode::UnrecognizedHmacDomainDenied,
        code: "UNRECOGNIZED_HMAC_DOMAIN_DENIED",
        severity: "HARD_DENY",
        category: "swarm",
        summary: "`coord.sock` rejected an unknown or unpermitted HMAC domain over IPC.",
        rationale: "Restricts vault HMAC signing and verification strictly to length-prefixed, explicitly allowlisted Swarm v2 record domains.",
        remediation: "Use the official `swarm-tool` role subcommands rather than raw `coord.sock` RPC frames.",
    },
    CodeExplanation {
        variant: GuardCode::Ring0RatchetViolation,
        code: "RING0_RATCHET_VIOLATION",
        severity: "HARD_DENY",
        category: "feedback",
        summary: "Automated friction PR attempted to modify a Ring-0 constitutional file or weaken the bypass corpus.",
        rationale: "Autonomous self-improvement loops may only evolve Ring-2 ergonomics/flags/diagnostics and must strictly preserve all Ring-0 files (`AGENTS.md`, `THREAT_MODEL.md`, workflows, Rego, sandbox/Kani primitives) plus monotonically expand `tests/bypass_corpus.toml`.",
        remediation: "Revert any Ring-0 file edits, keep all pre-existing bypass corpus vectors intact, and append at least 2 adversarial abuse vectors when changing `cmd_policy.rs` or `mcp_policy.rs`.",
    },
    CodeExplanation {
        variant: GuardCode::FeedbackOperatorOnly,
        code: "FEEDBACK_OPERATOR_ONLY",
        severity: "HARD_DENY",
        category: "feedback",
        summary: "Privileged `dotagent feedback` queue/loop subcommand was invoked from an AI agent or sandbox.",
        rationale: "Agents may submit friction ballots (`dotagent feedback submit`), but queue inspection, GitHub issue syncing, triage, and autonomous merge loops are restricted to operator/CI contexts.",
        remediation: "Use `dotagent feedback submit` as an agent, or run `sync-github` / `run-loop` from an operator terminal or authorized CI workflow.",
    },
    CodeExplanation {
        variant: GuardCode::InvalidFeedbackBallot,
        code: "INVALID_FEEDBACK_BALLOT",
        severity: "HARD_DENY",
        category: "feedback",
        summary: "Friction ballot failed schema, category, denial_id format, or ASCII validation.",
        rationale: "Prevents prompt-injection payloads, shell metacharacters, or malformed fields from entering the feedback spool.",
        remediation: "Pass `--denial-id <dnl_hex>` from the guard denial message, a valid `--category`, and optional `--reason-code <token>`.",
    },
    CodeExplanation {
        variant: GuardCode::FeedbackRateLimitExceeded,
        code: "FEEDBACK_RATE_LIMIT_EXCEEDED",
        severity: "HARD_DENY",
        category: "feedback",
        summary: "Session exceeded the per-session friction ballot submission ceiling (> 8 submissions; disk writes halted).",
        rationale: "Prevents runaway retry loops or compromised subagents from exhausting disk space under ~/.local/state/agent-guard/feedback.",
        remediation: "Stop submitting duplicate friction ballots in a loop and proceed with a compliant alternative or report the block to the user.",
    },
];

impl GuardCode {
    pub fn explanation(self) -> &'static CodeExplanation {
        for entry in CATALOG {
            if entry.variant == self {
                return entry;
            }
        }
        &CATALOG[0]
    }

    pub fn as_str(self) -> &'static str {
        self.explanation().code
    }

    pub fn from_code_str(raw: &str) -> Option<Self> {
        CATALOG.iter().find(|e| e.code == raw).map(|e| e.variant)
    }
}

pub fn all_explanations() -> &'static [CodeExplanation] {
    CATALOG
}

pub fn lookup_explanation(raw_code: &str) -> Option<&'static CodeExplanation> {
    let norm = raw_code.trim().to_ascii_uppercase().replace('-', "_");
    if let Some(exact) = CATALOG.iter().find(|e| e.code == norm) {
        return Some(exact);
    }
    CATALOG
        .iter()
        .find(|e| e.code.contains(&norm) || norm.contains(e.code))
}

pub fn run_explain_cli(args: &[String]) -> ExitCode {
    let json_mode = args.iter().any(|a| a == "--json");
    let list_mode = args.iter().any(|a| a == "--list" || a == "-l");

    if list_mode {
        if json_mode {
            let arr: Vec<JsonValue> = CATALOG
                .iter()
                .map(|e| {
                    JsonValue::Object(vec![
                        ("code".to_string(), JsonValue::Str(e.code.to_string())),
                        (
                            "severity".to_string(),
                            JsonValue::Str(e.severity.to_string()),
                        ),
                        (
                            "category".to_string(),
                            JsonValue::Str(e.category.to_string()),
                        ),
                        ("summary".to_string(), JsonValue::Str(e.summary.to_string())),
                    ])
                })
                .collect();
            println!("{}", JsonValue::Array(arr).to_json_string());
        } else {
            for e in CATALOG {
                println!("{:<36} [{}] {}", e.code, e.severity, e.summary);
            }
        }
        return ExitCode::SUCCESS;
    }

    let query = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str);
    let Some(code_arg) = query else {
        eprintln!(
            "[AGENT-GUARD] usage: dotagent explain <CODE> [--json] | dotagent explain --list"
        );
        return ExitCode::from(2);
    };

    let Some(exp) = lookup_explanation(code_arg) else {
        eprintln!(
            "[AGENT-GUARD] unknown guard code '{code_arg}' (run `dotagent explain --list` to view all {} catalog codes)",
            CATALOG.len()
        );
        return ExitCode::from(2);
    };

    if json_mode {
        let obj = JsonValue::Object(vec![
            ("code".to_string(), JsonValue::Str(exp.code.to_string())),
            (
                "severity".to_string(),
                JsonValue::Str(exp.severity.to_string()),
            ),
            (
                "category".to_string(),
                JsonValue::Str(exp.category.to_string()),
            ),
            (
                "summary".to_string(),
                JsonValue::Str(exp.summary.to_string()),
            ),
            (
                "rationale".to_string(),
                JsonValue::Str(exp.rationale.to_string()),
            ),
            (
                "remediation".to_string(),
                JsonValue::Str(exp.remediation.to_string()),
            ),
        ]);
        println!("{}", obj.to_json_string());
    } else {
        println!("Code:        {}", exp.code);
        println!("Severity:    {}", exp.severity);
        println!("Category:    {}", exp.category);
        println!("Summary:     {}", exp.summary);
        println!("Rationale:   {}", exp.rationale);
        println!("Remediation: {}", exp.remediation);
    }
    ExitCode::SUCCESS
}
