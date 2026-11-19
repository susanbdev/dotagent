# dotagent Threat Model & Security Architecture

Status: Normative (`v1.0.0`)
Scope: `agent-guard` (`dotagent`), `swarm-tool`, `dotagent-compiler`, `dotagent-harness`, and compiled harness bundles (`dist/`).

## 1. Adversary Model

`dotagent` assumes an **actively hostile workspace and untrusted LLM context** operating on an uncompromised developer workstation or CI runner:

- **Untrusted Inputs (`Ring-2`)**: Every repository file, README, code comment, test fixture, dependency manifest, compiler diagnostic, Git commit/branch name, PR comment, and tool output is treated as adversary-controlled passive data capable of carrying indirect prompt injections, Unicode smuggling payloads, symlink traps, or build-tool RCE configurations.
- **Compromised or Confused Agent Context (`Ring-2`)**: An LLM session (or delegated Swarm worker) may be subverted mid-turn into attempting unauthorized file reads, lateral scope escalation, credential theft, shell command smuggling, history rewriting, or audit-log tampering.
- **Trusted Computing Base (`Ring-1` & `Ring-0`)**: The host OS kernel (`Ring-0`), immutable `0555` `dotagent`/`agent-guard` binaries installed outside workspace write scope, root-depth `<repo_root>/AGENTS.md` (`0444`), and the privilege-separated `coord.sock` vault process (`Ring-1`) constitute the TCB.

## 2. Trust Rings & Isolation Boundaries

| Ring | Principal / Component | Privileges | Boundary Enforcement |
| :--- | :--- | :--- | :--- |
| `Ring-2` | LLM Harnesses, Swarm Workers, Repository Data, Build Outputs | Scoped workspace reads/edits via mediated tools only | Spotlighted inside 128-bit nonces; stripped to 7-bit ASCII prior to context buffer; blocked from direct secret/cache/state access |
| `Ring-1` | `agent-guard` Hook Kernel & `coord.sock` Coordinator | Reads `0600` `vault/hmac.key` (Coordinator only), mutates `SessionLedger` under `flock`, enforces policy | `#![forbid(unsafe_code)]`; `deny(clippy::unwrap_used, expect_used, panic)`; boolean-only MAC verification over Unix domain socket |
| `Ring-0` | Host OS Kernel (Linux Landlock / macOS Seatbelt) | Syscall-level VFS and TCP socket mediation | Irrevocable `prctl(PR_SET_NO_NEW_PRIVS)` + Landlock ABI `V1..V5` / `AccessNet` (`V4+`) or `sandbox-exec` SBPL prior to `exec` |

## 3. Threat-to-Control Enforcement Matrix

| Threat Class | Concrete Attack Vector | Deterministic Control (`agent-guard`) | Verification Suite |
| :--- | :--- | :--- | :--- |
| Indirect Prompt Injection & Shadow Authority | Malicious instructions in `README.md`, comments, PRs, or nested `CLAUDE.md` / `.cursorrules` | Single Root Authority (`<repo_root>/AGENTS.md` depth `0` only); 128-bit per-step spotlighting (`<<<UNTRUSTED_ASCII_DATA_<nonce>>>>`); static `ROGUE_AUTHORITY_FILE` repo audit | `bypass_corpus.toml`, `dotagent-compiler verify` |
| Invisible Unicode & Parser Differential Smuggling | Trojan Source Bidi overrides, Unicode Tags (`U+E0000..U+E007F`), Variation Selectors, Cyrillic/Greek homoglyphs, duplicate JSON keys (`{"file_path":"bad","file_path":"ok"}`) | Pre-buffer 7-bit ASCII sanitizer (`sanitize-stream`), escape defanging (`\u`, `\x`, `\033`, `&#`, `%XX`), `UNICODE_BIDI_THREAT` halt, RFC 7493 duplicate-key JSON rejection (`Int(i64)`/`Uint(u64)`) | `wave1_redteam_regressions.rs`, `property_fuzz_suite.rs` (`5,300+` cases) |
| Symlink Escape, Cache/Temp Snooping, & Self-Audit Recon | Symlink chain `src/link -> ~/.ssh/id_rsa`, reading `/tmp`, `node_modules/`, `.env*`, or `audit.jsonl` | Component-wise `lstat` resolution (`validate_path`), hard-coded forbidden zones, and `GUARD_SELF_BLINDNESS` on `~/.local/state/agent-guard` | `bypass_corpus.toml`, `property_fuzz_suite.rs` |
| Multi-Hop Context Poisoning & Compaction Amnesia | `File A -> File B -> File C` breadcrumb chains or `File A -> .venv/...`; forcing compaction to clear taint | `flock`-serialized `SessionLedger` enforcing max walk depth `<= 2`, `A -> B` hop ceiling, sticky `halted`/`tainted` flags across `PreCompact`, and `CORRUPT_SESSION_STATE` fail-closed lock recovery | `wave1_redteam_regressions.rs`, `scenarios/*.toml` |
| Shell, Git Hook, & Build-Tool Confused Deputy | Unmatched shell tokens, `$(...)` smuggling, `.git/hooks/post-checkout`, `.cargo/config.toml` `rustc-wrapper`, `.yarnrc.yml` `yarnPath`, chained GitHub `workflow_run` | Total shell lexer/AST validator (`UNBALANCED_SUBSHELL` / forward-progress invariant), 19-key `gitconfig.hardened`, `fstat` TOCTOU profile loader, build-trap & CI workflow static audit | `property_fuzz_suite.rs`, `harness_integration.rs` |
| Swarm Forgery, Replay, & Lateral Escalation | Worker minting `master` capability, forging `PLAN.lock.json`, widening task scope over `coord.sock`, or fabricating test checkpoints | Privilege-separated `coord.sock` blocking `PLAN_LOCK` & `master` RPCs, verifying open capability scope against `PLAN.lock.json`, and binding `WORK_LEDGER` entries to scoped Git tree OIDs | `wave1_redteam_regressions.rs`, `swarm_v2_suite.rs`, `cli_delegation.rs` |

## 4. Cryptographic Key Hierarchy & Privilege Separation

Swarm state integrity relies on `sha2::Sha256` and `hmac::Hmac<Sha256>` (`RFC 2104` / `FIPS 180-4`) with constant-time tag comparison (`subtle::ConstantTimeEq`) and `ZeroizingKey` volatile memory wiping on `Drop`:

1. **Root Secret (`vault/hmac.key`)**: `32` CSPRNG bytes stored at `~/.local/state/agent-guard/swarm/<repo_hash>/vault/hmac.key` (`0600` inside `0700` `vault/`).
2. **Worker Key Blindness**: When `agent-guard exec-sandbox` launches a Landlock-confined worker, `vault/` is excluded from the worker's VFS ruleset. Workers hold zero read access to `hmac.key`.
3. **Domain-Separated HMAC Contexts**: Every MAC computation prefixes an explicit domain label so tags cannot be replayed across record types:
   - `dotagent:swarm-v2:plan-lock:v1` (`PLAN.lock.json` -- direct Trusted Host / Master only; **never** signable over `coord.sock`)
   - `dotagent:swarm-v2:capability:v1` (`sessions/<sid>.cap.json` -- `master` role minting hard-blocked over `coord.sock`)
   - `dotagent:swarm-v2:breadcrumb-event:v1` (`spool/*.spool` & `.breadcrumbs.jsonl` -- validated against open session capability and `PLAN.lock.json` read/write scope)
   - `dotagent:swarm-v2:work-ledger:v1` (`ledger/WORK_LEDGER.jsonl` -- bound to scoped Git tree OID, authenticated edit provenance, and green test checkpoint)
4. **Zero-Oracle Verification RPCs**: `coord.sock` sits inside a `0700` `run/` directory created prior to `bind(2)`, serves bounded requests across a 16-worker thread pool, and exposes boolean-only MAC verification (`verify_mac` returns `valid: bool`, never raw expected tag bytes).

## 5. OS Kernel Enforcement Matrix

`agent-guard exec-sandbox` applies defense-in-depth OS confinement on top of `PreToolUse` AST policy:

| Host Platform | VFS Read/Write Mediation | Outbound / Inbound TCP (`--deny-net`) | `--require-kernel` Behavior |
| :--- | :--- | :--- | :--- |
| Linux `>= 6.7` (Landlock ABI `V4..V5`) | Kernel-enforced `AccessFs` allowlist (`.git` objects/index writable, `.git/hooks` & `.git/config` unwritable) | Kernel-enforced `AccessNet::BindTcp \| ConnectTcp` empty port ruleset (hard `EACCES`) | Allowed (Full VFS + TCP kernel isolation) |
| Linux `5.13 .. 6.6` (Landlock ABI `V1..V3`) | Kernel-enforced `AccessFs` allowlist | Landlock `V1..V3` lacks `AccessNet`; user-space AST blocks network binaries | **Fails closed (`exit 2`)** when `--deny-net` + `--require-kernel` are both requested |
| Containerized Linux (Landlock disabled / unprivileged seccomp) | User-space `PreToolUse` path & shell AST enforcement + sanitized environment (`--norc --noprofile`, `process_group(0)`) | User-space AST network binary block | **Fails closed (`exit 2`)** (`KERNEL_SANDBOX_UNAVAILABLE`) |
| macOS (`sandbox-exec` SBPL) | `(deny file-write*)` with escaped literal/subpath allowlist (`escape_sbpl_literal`) and hard deny on `.git/hooks` & `.git/config` | `(deny network*)` when `--deny-net` is enabled | Allowed when `/usr/bin/sandbox-exec` is present; fails closed otherwise |

## 6. Explicit Non-Goals & Residual Assumptions

1. **Host Root / Kernel / `ptrace` Compromise**: `dotagent` confines unprivileged AI coding agents and subprocesses. It does not defend against a local attacker who already possesses `uid 0`, `CAP_SYS_ADMIN`, or `CAP_SYS_PTRACE` outside the sandbox.
2. **Hardware & Microarchitectural Side Channels**: Constant-time MAC verification prevents timing oracles over IPC, but speculative-execution attacks (`Spectre`/`MDS`) remain the responsibility of the host kernel and hypervisor.
3. **Interactive Human Operator Trust (`dotagent session-reset`)**: `session-reset` requires an interactive human TTY (`isatty` on stdin and stderr) and refuses execution when `AGENT_GUARD_*` sandbox markers are set. A human operator deliberately resetting a halted session at their terminal assumes responsibility for resuming that session.
4. **Kernel TCP Mediation Below Linux `6.7` Without `--require-kernel`**: On Linux kernels `5.13..6.6` where Landlock `V4` `AccessNet` is absent and `--require-kernel` is not passed, VFS isolation remains kernel-enforced while network restriction falls back to user-space command policy. High-assurance CI or production deployments requiring mandatory kernel TCP isolation must pass `--require-kernel` on Linux `>= 6.7` or macOS.
