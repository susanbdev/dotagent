# Changelog

All notable changes to `dotagent` are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Universal distribution (`packaging/`)**: deterministic stdlib `repackage.py` turning the four attested release archives into a hardened `install.sh` (baked SHA-256 digests + pinned YubiKey SSHSIG signer, EOF function gate, `AGENT_GUARD_*` refusal, pre-extraction tar audit, atomic binary swap), four PyPI wheels, four npm platform packages + root package (zero lifecycle scripts), a Homebrew formula, and `.deb`/`.rpm`/`.apk` via `nfpm`, plus a `FROM scratch` OCI image definition.
- **Release workflow**: `repackage-ecosystem`, `publish-ghcr`, `publish-pypi`, `publish-npm`, and `publish-homebrew` jobs (OIDC trusted publishing, SHA-pinned actions); every release asset including `install.sh` is covered by SLSA build provenance.
- **`scripts/sign-release-yk.sh`**: local YubiKey ceremony (attestation-gated, macOS universal `.pkg` notarization, SSHSIG over `SHA256SUMS`).
- **`scripts/activate-local.sh --from-prebuilt <dir>`** installs verified release binaries without invoking Cargo; `cargo binstall` metadata added to every binary crate.
- `tests/packaging/`: installer, repackager, ceremony and workflow-hygiene tests (truncated stream, tampered archive, forged/namespace-confused SSHSIG, tar traversal/link/device rejection, running-binary atomic replace, byte-identical repackaging).

## [2.0.0] - 2026-11-20

### Added
- **Active Multi-Worktree Swarm Orchestrator (`dotagent swarm run <dag.json>`)**: Extracted `swarm-tools` library + topological DAG wave supervisor (`crates/swarm-tools/src/lib.rs`) supporting concurrent `(plan_id, task_id, attempt)` capability slots, ephemeral `git worktree add --detach` + isolated per-worker `CARGO_TARGET_DIR`, `recommended_model_tier` worker routing, hard wall-clock/token/`MAX_ADVERSARIAL_ROUNDS = 2` caps, `allowed_write_paths` diff-subset reconciliation, automatic `doc_sha256` fact hashing, and `cargo llvm-cov --json` / JSON test report QA fault triangulation.
- **Universal Harness Parity (`agent-guard mcp-gateway`, `agent-guard-sh`, & Per-RPC MCP Manifest)**: Added JSON-RPC 2.0 local mediating MCP sidecar (`mcp_gateway.rs`) with RFC 7636 PKCE (`S256`) and RFC 9449 Ed25519 `DPoP` (`dpop+jwt`) proof binding, declarative fail-closed Per-RPC MCP capability gating (`mcp_policy.rs`), drop-in POSIX `$SHELL` wrapper `agent-guard-sh` (`shell_wrapper.rs`), and Cursor `afterShellExecution` / `afterMCPExecution` / `preCompact` + `mcp.json` parity.
- **Policy-IR Bundle Compiler, Embedded `regorus` OPA Gate, & Executable `spec.md` Sync**: Lowered `profiles/*.toml` and `skills/*` into target-native artifacts (`dist/claude`, `dist/cursor`, `dist/codex`, `dist/gemini`, `dist/antigravity/harness.json`, `dist/profiles/policy_ir.json`), evaluated `dotagent_harness.rego` in-process via `regorus` over JSON and normalized TOML ASTs, and added automated `Cargo.toml` / `crates/agent-guard/src/*.rs` / `spec.md` drift verification.
- **Hot `coord.sock` Hook RPC, Linux `seccomp-bpf` + NetNS Isolation, & Ed25519 `StopReceipt`**: Added warm `eval_hook` RPC and per-plan HMAC epoch rotation on `coord.sock`, kernel `seccomp-bpf` `AF_INET`/`AF_INET6`/`AF_PACKET`/`AF_VSOCK` socket filtering + probed `CLONE_NEWUSER | CLONE_NEWNET` `--deny-net` isolation on Linux `< 6.7` / containers, and vault-isolated Ed25519 `StopReceipt` attestation (`on-stop` + `dotagent verify-receipt`).
- **Polyrepo Fleet CLI, Human-TTY Telemetry, & Reproducible Supply Chain**: Added `dotagent fleet <audit|doctor|sync|build-image>` (`/opt/dotagent` `0555`/`0444` layer builder), TTY-gated `dotagent telemetry <summary|top-denies|rotate|export-otlp>` preserving `GUARD_SELF_BLINDNESS`, `dotagent self-verify` SLSA v1.0 attestation check, `deny.toml` + `cargo-deny` CI gate, and bit-for-bit reproducible release tarballs.
- **Differential `/bin/bash` Fuzz Oracle, Kani Proofs, & Harness Wire Contracts**: Added `1,200+` differential `/bin/bash` vs `cmd_policy` oracle vectors (`differential_shell_oracle.rs`), `#[cfg(kani)]` formal bounded proofs (`kani_proofs.rs`), and pinned upstream harness contract fixtures (`contract_suite.rs`).

### Performance
- **Sub-Millisecond Lifecycle Hooks (`9x-13x` Lower Latency)**: Eliminated hardware `fsync` stalls on benign per-step `SessionLedger` counter updates while preserving durable `sync_data` flushes whenever `halted` or `tainted` is set, added lock-held `SessionLedger::save_locked`, deduplicated `resolve_validated_cwd` / `resolve_checking_symlinks` VFS `lstat` walks, cached symlink-verified `RuntimeProfile` TOML configs, and bypassed Swarm directory creation/scanning when no Swarm state is active (`pre_tool_read_hook_inproc` `p50`: `3,435 us -> 364 us`; `pre_tool_bash_ast_inproc` `p50`: `3,340 us -> 274 us`; `post_tool_scan_inproc` `p50`: `2,789 us -> 218 us`; `cli_pre_tool_cold_start` `p50`: `4,154 us -> 1,439 us`).
- **`744 MiB/s` 7-Bit ASCII Stream Sanitizer (`3.4x` Higher Throughput)**: Replaced character-by-character sanitization and `Vec<&str>` line compaction with a 256-byte L1 `ASCII_LUT` span scanner, Stage-2 escape-trigger pass-through elision, byte-indexed CSI/OSC stripping, and zero-allocation head/tail byte slicing (`sanitize_stream_64k` `p50`: `286 us -> 84 us`, `p99`: `861 us -> 104 us`, `218.5 MiB/s -> 744.0 MiB/s`), plus SIMD `is_ascii()` and token-stem prefilters in `unicode_guard` and `injection_scan`.
- **`2x` Faster Release Builds & Cached CI Matrix**: Removed redundant 5-binary cross-target LTO passes in `Cargo.toml` (`46.2s -> 20.4s` cold `--release` workspace build) and added SHA-pinned `actions/cache` workspace artifact caching with single-pass release binary execution in `.github/workflows/ci.yml`.


## [1.0.0] - 2026-11-18

### Security
- **Fail-Closed CLI, JSON, & Session Ledger**: Unrecognized CLI subcommands across `agent-guard`, `dotagent`, `swarm-tool`, `dotagent-compiler`, and `dotagent-harness` exit `2` (`UNKNOWN_SUBCOMMAND`). Duplicate JSON object keys (`RFC 7493` I-JSON smuggling) and corrupt/truncated `SessionLedger` files (`CORRUPT_SESSION_STATE`) fail closed under exclusive `flock` locking while preserving sticky `halted`/`tainted` flags across concurrent writers.
- **Audited Cryptography & Privilege-Separated Coordinator**: Replaced custom SHA-256 code with `sha2::Sha256`, `hmac::Hmac<Sha256>`, `subtle::ConstantTimeEq`, and volatile `ZeroizingKey`. Hardened `coord.sock` (`0700` parent pre-bind, 16-worker pool, boolean-only MAC verification RPCs, `PLAN_LOCK` and `master` capability minting blocked over IPC, and strict capability/plan path-scope validation).
- **OS Sandbox Hardening (`exec-sandbox`)**: Added Linux `6.7+` Landlock `V4` `AccessNet::BindTcp | ConnectTcp` enforcement under `--deny-net` (failing closed under `--require-kernel` when `AccessNet` is unavailable), bounded background pipe draining to prevent `SIGPIPE` truncation, `process_group(0)` timeout termination, `--norc --noprofile` shell hygiene, `.git` index lockfile support, and escaped macOS `sandbox-exec` SBPL profiles.
- **Shell Lexer Forward-Progress Guarantee**: Fixed unmatched `)` and empty redirection edge cases in `cmd_policy` (`UNBALANCED_SUBSHELL` / `MALFORMED_REDIRECTION`) uncovered by property-based fuzzing.

### Added
- **Unified `dotagent` Multicall Operator CLI**: Added `dotagent doctor [--json]`, `dotagent explain <CODE|--list> [--json]` (33-code remediation catalog), interactive human-TTY `dotagent session-reset`, non-destructive `dotagent activate` / `dotagent deactivate` (with `.dotagent.bak` backups, JSON user-preference preservation, `~/.bashrc` + `~/.zshenv` `PATH` setup, and pinned absolute GUI hook paths), and `swarm` / `compile` / `harness` subcommand delegation.
- **Swarm v2 Architecture (`swarm-tool`)**: Six least-privilege roles (`master`, `investigator`, `qa-engineer`, `grunt`, `adversarial-reviewer`, `forensic-coroner`), full-record HMAC breadcrumbs with `CRC32` crash spool recovery, upfront `1 / 0..2 / 0..N` QA fault triangulation, and abbreviation-aware `2+2` Work Ledger stop gates.
- **Multi-Harness Replay, Property Fuzzing, & Microbenchmarks**: Added `dotagent-harness` (`305+` adversarial corpus vectors, declarative multi-harness scenarios, and `dotagent-harness bench [--quick] [--json]`) plus `5,300+` deterministic property/mutation fuzz iterations (`property_fuzz_suite.rs`).
- **Flagship Documentation & Verifiable Releases**: Added formal [THREAT_MODEL.md](THREAT_MODEL.md), [SECURITY.md](SECURITY.md), multi-OS (`ubuntu-latest` + `macos-latest`) + MSRV `1.88.0` CI matrix, and tag-triggered SLSA provenance release workflow (`.github/workflows/release.yml`).

### Changed
- **Zero-Panic Production Kernel & Modularity**: Enforced `#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]` across `agent-guard`, extracted `repo_audit` into its own module, pruned `compute_scoped_tree_oid` directory walks to `O(|scope|)` for monorepos, and added a zero-subprocess fast path to `ensure_git_info_exclude`.
