# dotagent Threat Model & Security Architecture

Status: Normative (`v2.1.0`)
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
| `Ring-0` | Host OS Kernel (Linux Landlock / macOS Seatbelt) & FIDO2 `SSHSIG` | Syscall-level VFS and TCP socket mediation; physical hardware `UP == 1` operator authorization | Irrevocable `prctl(PR_SET_NO_NEW_PRIVS)` + Landlock ABI `V1..V5` / `AccessNet` (`V4+`), macOS `sandbox-exec` SBPL, and `sk-ssh-ed25519@openssh.com` |

## 3. Threat-to-Control Enforcement Matrix

| Threat Class | Concrete Attack Vector | Deterministic Control (`agent-guard`) | Verification Suite |
| :--- | :--- | :--- | :--- |
| Indirect Prompt Injection & Shadow Authority | Malicious instructions in `README.md`, comments, PRs, or nested `CLAUDE.md` / `.cursorrules` | Single Root Authority (`<repo_root>/AGENTS.md` depth `0` only); 128-bit per-step spotlighting (`<<<UNTRUSTED_ASCII_DATA_<nonce>>>>`); static `ROGUE_AUTHORITY_FILE` repo audit | `bypass_corpus.toml`, `dotagent-compiler verify` |
| Invisible Unicode & Parser Differential Smuggling | Trojan Source Bidi overrides, Unicode Tags (`U+E0000..U+E007F`), Variation Selectors, Cyrillic/Greek homoglyphs, duplicate JSON keys (`{"file_path":"bad","file_path":"ok"}`) | Pre-buffer 7-bit ASCII sanitizer (`sanitize-stream`), escape defanging (`\u`, `\x`, `\033`, `&#`, `%XX`), `UNICODE_BIDI_THREAT` halt, RFC 7493 duplicate-key JSON rejection (`Int(i64)`/`Uint(u64)`) | `wave1_redteam_regressions.rs`, `property_fuzz_suite.rs` (`5,300+` cases) |
| Symlink Escape, Nested Secret Snooping, & Self-Audit Recon | Symlink chain `src/link -> ~/.ssh/id_rsa`, nested `apps/web/.env`, reading `/tmp`, `node_modules/`, or `audit.jsonl`/`ballots.jsonl` | Component-wise `lstat` resolution (`validate_path`), depth-3 Landlock recursive secret exclusion (`add_filtered_repo_tree`), and `GUARD_SELF_BLINDNESS` on `~/.local/state/agent-guard` | `v2_1_chunk1_tests.rs`, `v2_1_chunk2_tests.rs`, `bypass_corpus.toml` |
| Multi-Hop Context Poisoning & Ballot Poisoning | `File A -> File B -> File C` chains; tainted agent spamming false-positive ballots to weaken policy | `flock`-serialized `SessionLedger` (`A -> B` ceiling), `1`-vote-per-`(voter_token, cluster_key)` HMAC ballots (`feedback.rs`), tainted ballot quarantine, `[AGENTPI_EVENT]` tap, and `verify-ring0-ratchet` | `v2_1_chunk2_tests.rs`, `v2_1_chunk5_tests.rs` |
| Plugin Downgrade & Unbuilt Facade Attestation | Rogue `.rego` plugin returning `"allow"` over Ring-0 `Deny`; `wrangler` pointing to missing/invalid `.wasm` or stub markers | SHA-256-pinned `plugin_lattice.rs` (`combine_verdicts` join-semilattice `Ord::max` + Kani proof) with 2-reviewer HMAC quorums; `smoke_gate.rs` bound into Ed25519 `StopReceipt` | `v2_1_chunk3_tests.rs`, `v2_1_chunk4_tests.rs`, `kani_proofs.rs` |
| Shell, `.git/config` Unlink, & PTY Operator Spoofing | `.git/config` `unlink+creat` inside sandbox; `pty.openpty()` spoofing `session-reset` / `telemetry` | Atomic `pre_git_cfg_bytes` snapshot & restore (`GIT_CONFIG_TAMPERED`), 19-key `gitconfig.hardened`, and FIDO2 `sk-ssh-ed25519@openssh.com` (`UP == 1`) `SSHSIG` challenge (`sshsig_touch.rs`) | `v2_1_chunk1_tests.rs`, `differential_shell_oracle.rs` |
| Swarm Forgery, Replay, & Lateral Escalation | Worker minting `master` capability, forging `PLAN.lock.json`, widening task scope over `coord.sock`, or fabricating test checkpoints | Privilege-separated `coord.sock` blocking `PLAN_LOCK` & `master` RPCs, verifying open capability scope against `PLAN.lock.json`, and binding `WORK_LEDGER` entries to scoped Git tree OIDs | `wave1_redteam_regressions.rs`, `swarm_v2_suite.rs` |

## 4. Cryptographic Key Hierarchy & Privilege Separation

Swarm state integrity relies on `sha2::Sha256` and `hmac::Hmac<Sha256>` (`RFC 2104` / `FIPS 180-4`) with constant-time tag comparison (`subtle::ConstantTimeEq`) and `ZeroizingKey` volatile memory wiping on `Drop`:

1. **Root Secret (`vault/hmac.key`)**: `32` CSPRNG bytes stored at `~/.local/state/agent-guard/swarm/<repo_hash>/vault/hmac.key` (`0600` inside `0700` `vault/`).
2. **Worker Key Blindness**: When `agent-guard exec-sandbox` launches a Landlock-confined worker, `vault/` is excluded from the worker's VFS ruleset. Workers hold zero read access to `hmac.key`.
3. **Domain-Separated HMAC Contexts**: Every MAC computation prefixes an explicit domain label so tags cannot be replayed across record types:
   - `dotagent:swarm-v2:plan-lock:v1` (`PLAN.lock.json` -- direct Trusted Host / Master only; **never** signable over `coord.sock`)
   - `dotagent:swarm-v2:capability:v1` (`sessions/<sid>.cap.json` -- `master` role minting hard-blocked over `coord.sock`)
   - `dotagent:swarm-v2:breadcrumb-event:v1` (`spool/*.spool` & `.breadcrumbs.jsonl` -- validated against open session capability, `PLAN.lock.json` scope, and quorum `review_approve` trails)
   - `dotagent:swarm-v2:work-ledger:v1` (`ledger/WORK_LEDGER.jsonl` -- bound to scoped Git tree OID, authenticated edit provenance, and green test checkpoint)
   - `dotagent:feedback-v1:ballot` (`feedback/ballots.jsonl` -- write-only over `coord.sock`, `0` read RPCs)
4. **Zero-Oracle Verification & Host-Only Hook Daemon Separation**: `coord.sock` sits inside a `0700` `ipc/` directory, serves bounded requests across a 16-worker thread pool, exposes boolean-only MAC verification (`verify_mac` returns `valid: bool`), and strictly rejects `eval_hook` (`EVAL_HOOK_FORBIDDEN_ON_WORKER_SOCKET`). Warm `pre-tool`/`post-tool` evaluation runs over a separate host-only `~/.local/state/agent-guard/daemon/hook.sock` inaccessible to sandboxed workers.
5. **Asymmetric Ed25519 `StopReceipt` Attestation (`vault/stop_receipt_ed25519.key`)**: `0600` Ed25519 signing seed isolated inside `vault/`. `agent-guard on-stop` signs `(repo_id, head_commit_oid, work_tree_oid, bundle_manifest_sha256, smoke_gate_digest, ledger_clean_summary, epoch_id)` under `DOTAGENT_STOP_RECEIPT_ED25519_V2`, verified in CI against a pinned public key via `dotagent verify-receipt --pubkey <hex|path>`.

## 5. OS Kernel Enforcement Matrix

`agent-guard exec-sandbox` applies defense-in-depth OS confinement on top of `PreToolUse` AST policy:

| Host Platform | VFS Read/Write Mediation | Outbound / Inbound Network (`--deny-net`) | `--require-kernel` / `doctor` |
| :--- | :--- | :--- | :--- |
| Linux `>= 6.7` (Landlock ABI `V4..V5`) | Depth-3 secret-excluding `AccessFs` allowlist + atomic `.git/config` snapshot/restore | Landlock `AccessNet::BindTcp \| ConnectTcp` + strict `seccomp-bpf` (`AF_UNIX`/`AF_NETLINK` only -> `EPERM`) | `doctor` green; full VFS + TCP/socket isolation |
| Linux `5.13 .. 6.6` (Landlock ABI `V1..V3`) | Depth-3 secret-excluding `AccessFs` allowlist + atomic `.git/config` snapshot/restore | Strict `seccomp-bpf` (`AF_UNIX`/`AF_NETLINK` only -> `EPERM`) | `doctor` green when Landlock + seccomp active |
| Containerized Linux (Landlock disabled) | User-space `PreToolUse` AST + sanitized env + atomic `.git/config` snapshot/restore | Strict `seccomp-bpf` (`EPERM`) + probed `unshare --user --net` | Fails `doctor` loudly unless `--allow-degraded`; `--require-kernel` exits `2` |
| macOS (`sandbox-exec` SBPL) | `(deny file-write*)` with subpath allowlist and hard deny on `.git/hooks`, `.git/config`, `profiles/`, & `.env*` | `(deny network*)` (with scoped `AF_UNIX` allowance for `ipc/coord.sock`) | `doctor` green when `/usr/bin/sandbox-exec` present |

## 6. Explicit Non-Goals & Residual Assumptions

1. **Host Root / Kernel / `ptrace` Compromise**: `dotagent` confines unprivileged AI coding agents and subprocesses. It does not defend against a local attacker who already possesses `uid 0`, `CAP_SYS_ADMIN`, or `CAP_SYS_PTRACE` outside the sandbox.
2. **Hardware & Microarchitectural Side Channels**: Constant-time MAC verification prevents timing oracles over IPC, but speculative-execution attacks (`Spectre`/`MDS`) remain the responsibility of the host kernel and hypervisor.
3. **Interactive Human Operator Trust & FIDO2 `SSHSIG` (`sshsig_touch.rs`)**: `session-reset`, `deactivate`, `telemetry`, and `feedback triage` require an interactive human TTY outside all agent/sandbox markers AND, when `~/.config/dotagent/operator_sk_keys` is present, an OpenSSH `SSHSIG` (`sk-ssh-ed25519@openssh.com`) physical touch (`UP == 1`) over `(repo_id, epoch_id, floor_ts_60s)`.
