# `susanbdev/dotagent` — Agent Guardrails, Skills & Multi-Harness Bundle Specification

`susanbdev/dotagent` compiles the static `agent-guard` hook binary (`< 2 ms` cold start), token-bounded `SKILL.md` modules, and reproducible harness configuration trees for `.claude/`, `.codex/`, `.cursor/`, Gemini, and `prim-dotagent` (`/opt/dotagent`).

---

## 1. Repository Layout

```text
dotagent/
├── Cargo.toml                      # Depends on susanbdev-shared (safety, git, policy, crypto)
├── crates/
│   ├── guard/                      # `agent-guard` CLI binary
│   │   └── src/
│   │       ├── main.rs             # Subcommands: pre-tool, post-edit, git-hook, on-stop
│   │       ├── command.rs          # Shell AST check via Command::validate()
│   │       ├── path.rs             # Symlink-resolved path gate via SafePath::resolve()
│   │       ├── hygiene.rs          # Incremental AST lint (Noun/Verb rules, 0-SVG, reuse check)
│   │       └── receipt.rs          # StopReceipt::issue() & StopReceipt::verify()
│   └── bundle/                     # HarnessBundle::compile(profile) -> deterministic target trees
├── skills/                         # <= 3 KB (~800 token) domain skills + SHA-256 script lockfile
│   ├── manifest.lock.json
│   ├── primitives/SKILL.md
│   ├── contracts/SKILL.md
│   ├── vespoli-ui/SKILL.md
│   ├── workers/SKILL.md
│   ├── zero-trust/SKILL.md
│   └── review/SKILL.md
├── profiles/
│   ├── author.toml                 # Coding agent (scoped workspace writes, 0 approval power)
│   ├── reviewer.toml               # Independent reviewer (`enable_write_tools = false`)
│   └── explorer.toml               # Read-only research profile
└── tests/
    └── bypasses.toml               # 250+ shell, symlink, encoding & AST violation vectors
```

---

## 2. `agent-guard` Hook Lifecycle

1. **`agent-guard pre-tool`**:
   * Parses candidate shell strings with `Command::validate()` (`tree-sitter-bash` across `|`, `&&`, `$(...)`, `<(...)`, `xargs`, `find -exec`, `sh -c`) and resolves file arguments via `SafePath::resolve()`.
   * Blocks reads of credential paths (`.env*`, `*.pem`, `*.key`, `~/.ssh`, `~/.aws`, `~/.netrc`), writes to control paths (`.guard/`, `.agent-guard/`, `.claude/`, `.codex/`, `.cursor/`, `.github/`, `AGENTS.md`, `CLAUDE.md`, `REVIEW.md`), destructive `git` flags (`--amend`, `rebase`, `reset --hard`, `--force*`, `--no-verify`), and lifecycle-script package installs.
   * Exits with code **`2`** and a structured denial message instructing the harness to halt and surface the denial verbatim without retrying via alternate encodings or tools.
2. **`agent-guard post-edit <file>`**:
   * Runs `< 200 ms` incremental AST checks (`Hygiene::inspectFile()`) on the modified file—rejecting `policy-hub` Noun/Verb naming violations, duplicated `susanbdev/shared` primitives, `<svg>` / inline `style` in UI code, `unsafe` in Rust, and `SecretFinding::scan()` hits before the agent touches another file.
3. **`agent-guard on-stop`**:
   * Executes `.guard/checks/on-stop` (the target repo's full test, typecheck, and Rego suite) and emits a signed `StopReceipt` bound to the working tree `Digest` so completion cannot be claimed without passing checks.

---

## 3. `HarnessBundle` Compiler & Skill Rules

* **`HarnessBundle::compile(profile)`**: Consumes `policy-hub/constitution/{AGENTS,REVIEW}.md`, `profiles/*.toml`, and `skills/*` to emit deterministic harness trees wiring MCP exclusively to `https://mcp.zt.susanb.dev/mcp`.
* **Skill Constraints**: Every `SKILL.md` is `<= 3,072` bytes, fetches zero remote content at runtime, and pins any helper script's `SHA-256` in `skills/manifest.lock.json` (verified by `agent-guard` prior to execution).
* **Corpus Gate**: `cargo test` runs all `250+` entries in `tests/bypasses.toml` (base64 subshells, `python -c` file reads, symlinked `.env` targets, `+HEAD:main` refspecs) requiring a `100%` block rate.
