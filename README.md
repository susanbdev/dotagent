# dotagent

Secure by design Agent and LLM skills, settings, configurations, and tools for various environments.

## Components

- **`crates/agent-guard`**: `#![forbid(unsafe_code)]` Rust 2024 deterministic security kernel (`hmac`, `sha2`, `crc32fast`) intercepting `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `PreCompact`, `PostEdit`, and `Stop` lifecycle events across Antigravity / Gemini, Claude Code, and Cursor, plus sandbox/MCP lockdown and `notify = ["agent-guard", "on-stop"]` stop-gate verification on OpenAI Codex, Swarm v2 role sandboxes, full-record HMAC breadcrumbs, upfront QA fault triangulation, and fail-closed `2+2` Work Ledger gates.
- **`crates/swarm-tools`**: Dedicated Rust role CLI binary (`swarm-tool`) equipping each of the 6 Swarm v2 roles (`master`, `investigator`, `qa`, `grunt`, `reviewer`, `coroner`) with deterministic local execution commands.
- **`crates/dotagent-compiler`**: Reproducible bundle compiler and `SHA-256` / `policy-hub` / pure-7-bit-ASCII verifier emitting `dist/` harness configurations, `research-airlock` + 6 `swarm-*` subagent manifests across Claude Code, Cursor, OpenAI Codex, and Gemini, `skills/manifest.lock.json`, and `dist-verify/manifest.sha256`.
- **`profiles/` & `skills/`**: Token-minimal (`<= 3 KiB`) pure-ASCII `SKILL.md` manifests plus explicit per-role `ROLE_GUIDE.md` manuals (`skills/swarm-{master,investigator,qa-engineer,grunt,adversarial-reviewer,forensic-coroner}/`) defining each role's job, hard rules, and Rust tooling.
- **`tests/bypass_corpus.toml` & Swarm v2 Suites**: `290` adversarial bypass vectors (`100%` block rate) plus `swarm_v2_suite.rs` and `cli_delegation.rs` verifying full-record HMAC path binding, CRC32 crash spool recovery, linked `git worktree` excludes, depth-20 Investigator scoping, Reviewer URL-exfiltration blocking, `1 / 0..2 / 0..N` fault triangulation, and fail-closed `on-stop` gates.

## Enforced Security Guarantees

1. **Untrusted Data Quarantine, 128-Bit Spotlighting, & Single Root Authority (`<repo_root>/AGENTS.md` ONLY)**: All repository files, docs, comments, logs, and tool outputs are untrusted passive data spotlighted inside per-step randomized 128-bit nonces (`<<<UNTRUSTED_ASCII_DATA_<nonce>>>>`). Nested/shadow instruction files are hard-blocked, and deployed control-plane files are VFS read-only (`0444` configs, `0555` binaries).
2. **Pre-Buffer 7-Bit ASCII Sanitization & Escape Neutering**: Prior to reaching the agent's context buffer, all untrusted reads and wrapped `Bash` streams (`agent-guard sanitize-stream`) strip CR/ANSI/control bytes, neuter every non-ASCII character (`>= 0x80`), and defang literal `\uXXXX`, `\UXXXXXXXX`, `\xXX`, `\033`, `&#...;`, and `%XX` escape triggers, while Trojan Source Bidi, Unicode Tags (`U+E0000..U+E007F`), Variation Selectors, and homoglyphs trip an immediate session halt.
3. **Zero Cache, Temp, Dependency, Secret, or Guard-State Snooping**: Lexical + component-by-component symlink checks block `/tmp`, `/var/tmp`, `/dev/shm`, `tmp/`, `.cache/`, `__pycache__/`, `.next/`, `.turbo/`, `node_modules/`, `vendor/`, `.venv/`, `site-packages/`, `.env*`, credential stores, and `~/.local/state/agent-guard` (`audit.jsonl` self-blindness).
4. **Max 2-Level Traversal & `A -> B` Reference Hop Ledger**: Directory walks require depth `<= 2`, and stateful provenance tracking permits `File A -> File B` while hard-stopping `File B -> File C` (preserved across step compactions) and immediately tripping a session circuit breaker on any `cache`/`tmp`/`dependency` pointer.
5. **Tiny Step Context Micro-Windows & Immediate Compaction**: Enforces `24 KiB` raw file cap (`<= 150`-line slices), `120`-line stream head/tail compaction, `8k` soft-compaction advisory (`COMPACT_STEP_NOW`), `16k` hard per-step token ceiling, harness auto-compaction (`15%` / `20k` tokens + `PreCompact` step reset), and a `<= 200`-token read-only `research-airlock` subagent so sessions never drag multi-feature history to 200k windows.
6. **Git, Build-Tool, & Confused-Deputy Lockdown**: Globally disables Git hooks and attribute drivers (`core.hooksPath = /dev/null`, `core.attributesFile = /dev/null`, `core.fsmonitor = false`, `core.protectHFS = true`, `core.protectNTFS = true`, `gc.auto = 0`, `protocol.allow = never` + `https` only), blocks `.cargo/config*` (`rustc-wrapper`/`linker`/`runner`) and `.yarnrc*` (`yarnPath`) traps, and taint-gates ambient-authority CLIs.

## Quick Verification & Local Activation

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./scripts/activate-local.sh
```
