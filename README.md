# dotagent

Secure by design Agent and LLM skills, settings, configurations, and tools for various environments.

## Components

- **`crates/agent-guard`**: Zero-dependency, `#![forbid(unsafe_code)]` Rust 2024 deterministic security kernel intercepting `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `PostEdit`, and `Stop` lifecycle events across Antigravity / Gemini, Claude Code, Cursor, and OpenAI Codex.
- **`crates/dotagent-compiler`**: Reproducible bundle compiler and `SHA-256` / `policy-hub` verifier emitting `dist/` harness configurations, `skills/manifest.lock.json`, and `dist-verify/manifest.sha256`.
- **`profiles/` & `skills/`**: Token-minimal (`<= 3 KiB`), zero-network role manifests and domain skills.
- **`tests/bypass_corpus.toml`**: `260+` adversarial shell AST, symlink, Unicode smuggling, token-bomb, cache-bleed, and confused-deputy bypass vectors verified at `100%` block rate.

## Enforced Security Guarantees

1. **Untrusted Data Quarantine & Single Root Authority (`<repo_root>/AGENTS.md` ONLY)**: All repository files, docs, comments, logs, and tool outputs are untrusted passive data. Nested or shadow instruction files (`*/AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.github/copilot-instructions.md`) are hard-blocked.
2. **Zero Cache, Temp, Dependency, or Secret Snooping**: Lexical + component-by-component symlink checks block `/tmp`, `/var/tmp`, `/dev/shm`, `tmp/`, `.cache/`, `__pycache__/`, `.next/`, `.turbo/`, `node_modules/`, `vendor/`, `.venv/`, `site-packages/`, `.env*`, and credential stores.
3. **Max 2-Level Traversal & `A -> B` Reference Hop Ledger**: Directory walks require depth `<= 2`, and stateful per-turn provenance tracking permits `File A -> File B` while hard-stopping `File B -> File C` (and immediately tripping a session circuit breaker if any file points toward `cache`, `tmp`, or `dependency` directories).
4. **Unicode, Token-Exhaustion, Cache-Bleed, Git-Hook, & Confused-Deputy Elimination**:
   - Blocks Trojan Source Bidi controls, Unicode Tags (`U+E0000..U+E007F`), Variation Selectors, zero-width joiners, ANSI `$'...'` escapes, UTF-16 surrogate escapes, and homoglyphs.
   - Enforces file byte (`64 KiB`), line (`500` unsliced / `200` sliced), single-line (`2 KiB`), BPE token-density splitter, and cumulative turn (`48k` tokens) ceilings.
   - Isolates state per canonical repository `SHA-256` and disables harness `autoMemory` to prevent cache bleed.
   - Globally disables Git hooks (`core.hooksPath = /dev/null`, `core.fsmonitor = false`, `protocol.allow = https`, `submodule.recurse = false`) and taint-gates ambient-authority CLIs (`git push`, `gh`, `gdocs`, `gdrive`, `curl`/`wget`, `npm install --ignore-scripts`).

## Quick Verification & Local Activation

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./scripts/activate-local.sh
```
