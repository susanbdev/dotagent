# Security Policy

## Supported Versions

| Version | Supported | Notes |
| :--- | :--- | :--- |
| `1.0.x` | Yes | Active mainline security kernel, Swarm v2 runtime, and multi-harness bundle compiler |
| `< 1.0.0` | No | Pre-`1.0` development snapshots |

## Reporting a Vulnerability

Please **do not** open public GitHub issues or pull requests for suspected security bypasses, sandbox escapes, cryptographic flaws, or confused-deputy vectors.

1. **Private GitHub Security Advisory (Preferred)**: Report vulnerabilities privately via [GitHub Security Advisories](https://github.com/susanbdev/dotagent/security/advisories/new).
2. **Required Triage Details**:
   - Affected binary/crate (`agent-guard`/`dotagent`, `swarm-tool`, `dotagent-compiler`, or `dotagent-harness`) and OS/kernel version (`uname -srm`).
   - Minimal deterministic reproducer (JSON hook payload, shell string, or `dotagent-harness` TOML scenario).
   - Expected `[agent-guard HARD DENY :: <CODE>]` vs observed behavior.
3. **Response Targets**:
   - Initial acknowledgment within **48 hours**.
   - Triage classification and remediation timeline within **5 business days**.
   - Every confirmed bypass is added as a permanent regression case in `tests/bypass_corpus.toml` or `crates/agent-guard/tests/`.

## Enforced Engineering & Security Invariants

Every change merged to `main` must preserve the following mechanical invariants:

- **Memory & Panic Safety**: `#![forbid(unsafe_code)]` across all workspace crates; `#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]` on the `agent-guard` production library.
- **Standardized Audited Cryptography**: `sha2::Sha256`, `hmac::Hmac<Sha256>`, `subtle::ConstantTimeEq`, and volatile `ZeroizingKey` wipe on `Drop` (no hand-rolled digest primitives).
- **Strict Control-Plane Hygiene**: All compiled `dist/` configs, `skills/`, and `profiles/` are verified pure 7-bit ASCII and SHA-256 locked in `dist-verify/manifest.sha256` and `skills/manifest.lock.json`.
- **Zero Chained CI Triggers**: GitHub Actions workflows use isolated, minimal permissions and never chain triggers across untrusted events.

## Local Security Self-Audit

Operators and auditors can verify all workspace and host invariants offline at any time:

```bash
dotagent doctor
dotagent audit-repo .
dotagent-compiler verify .
cargo test --workspace --offline
```
