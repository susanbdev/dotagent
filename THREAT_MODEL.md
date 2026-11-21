# dotagent Threat Model & Security Architecture

Status: Normative (`v2.0.0`)
Scope: `agent-guard` (`dotagent`, `agent-guard-sh`), `swarm-tool`, `dotagent-compiler`, `dotagent-harness`, and compiled Policy-IR harness bundles (`dist/`).

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
4. **Zero-Oracle Verification & Host-Only Hook Daemon Separation**: `coord.sock` sits inside a `0700` `ipc/` directory, serves bounded requests across a 16-worker thread pool, exposes boolean-only MAC verification (`verify_mac` returns `valid: bool`), and strictly rejects `eval_hook` (`EVAL_HOOK_FORBIDDEN_ON_WORKER_SOCKET`). Warm `pre-tool`/`post-tool` evaluation runs over a separate host-only `~/.local/state/agent-guard/daemon/hook.sock` inaccessible to sandboxed workers.

5. **Asymmetric Ed25519 `StopReceipt` Attestation (`vault/stop_receipt_ed25519.key`)**: `0600` Ed25519 signing seed isolated inside `vault/` (inaccessible to `exec-sandbox` workers). `agent-guard on-stop` signs `(repo_id, head_commit_oid, work_tree_oid, bundle_manifest_sha256, ledger_clean_summary, epoch_id)` under `DOTAGENT_STOP_RECEIPT_ED25519_V2`, verified in CI against a pinned public key via `dotagent verify-receipt --pubkey <hex|path>` alongside live repo/HEAD/worktree/manifest digest checks.

## 5. OS Kernel Enforcement Matrix

`agent-guard exec-sandbox` applies defense-in-depth OS confinement on top of `PreToolUse` AST policy:

| Host Platform | VFS Read/Write Mediation | Outbound / Inbound Network (`--deny-net`) | `--require-kernel` Behavior |
| :--- | :--- | :--- | :--- |
| Linux `>= 6.7` (Landlock ABI `V4..V5`) | Kernel-enforced `AccessFs` allowlist (`.git` objects/index writable, `.git/hooks` & `.git/config` unwritable) | Landlock `AccessNet::BindTcp \| ConnectTcp` + strict `seccomp-bpf` allowlist (`domain != AF_UNIX && domain != AF_NETLINK` -> `EPERM`) | Allowed (Full VFS + Socket kernel isolation) |
| Linux `5.13 .. 6.6` (Landlock ABI `V1..V3`) | Kernel-enforced `AccessFs` allowlist | Strict `seccomp-bpf` socket-domain allowlist (`AF_UNIX`/`AF_NETLINK` only; all IP/packet/vsock/RDS/TIPC domains -> `EPERM`) | Allowed when Landlock VFS + seccomp filter succeed |
| Containerized Linux (Landlock disabled / unprivileged seccomp) | User-space `PreToolUse` path & shell AST enforcement + sanitized environment (`--norc --noprofile`, `process_group(0)`) | Strict `seccomp-bpf` `SYS_socket` / `SYS_socketpair` allowlist (`EPERM`) + probed `unshare --user --net` when Landlock is absent | **Fails closed (`exit 2`)** (`KERNEL_SANDBOX_UNAVAILABLE` / `KERNEL_NET_SANDBOX_FAILED`) |
| macOS (`sandbox-exec` SBPL) | `(deny file-write*)` with escaped literal/subpath allowlist (`escape_sbpl_literal`) and hard deny on `.git/hooks` & `.git/config` | `(deny network*)` (with scoped `AF_UNIX` allowance for `ipc/coord.sock`) when `--deny-net` is enabled | Allowed when `/usr/bin/sandbox-exec` is present; fails closed otherwise |

## 6. Explicit Non-Goals & Residual Assumptions

1. **Host Root / Kernel / `ptrace` Compromise**: `dotagent` confines unprivileged AI coding agents and subprocesses. It does not defend against a local attacker who already possesses `uid 0`, `CAP_SYS_ADMIN`, or `CAP_SYS_PTRACE` outside the sandbox.
2. **Hardware & Microarchitectural Side Channels**: Constant-time MAC verification prevents timing oracles over IPC, but speculative-execution attacks (`Spectre`/`MDS`) remain the responsibility of the host kernel and hypervisor.
3. **Interactive Human Operator Trust (`dotagent session-reset` & `dotagent telemetry`)**: Both commands require an interactive human TTY (`isatty` on stdin and stdout) and refuse execution when any `AGENT_GUARD_*` or AI harness environment markers are active.

