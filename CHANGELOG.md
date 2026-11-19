# Changelog

All notable changes to `dotagent` are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **Flagship Documentation & Verifiable Releases**: Added formal [THREAT_MODEL.md](THREAT_MODEL.md), [SECURITY.md](SECURITY.md), multi-OS (`ubuntu-latest` + `macos-latest`) + MSRV `1.85.0` CI matrix, and tag-triggered SLSA provenance release workflow (`.github/workflows/release.yml`).

### Changed
- **Zero-Panic Production Kernel & Modularity**: Enforced `#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]` across `agent-guard`, extracted `repo_audit` into its own module, pruned `compute_scoped_tree_oid` directory walks to `O(|scope|)` for monorepos, and added a zero-subprocess fast path to `ensure_git_info_exclude`.
