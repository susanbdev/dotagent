# ADR-0001: Skill-Driven 6-Role Coding Swarm, Upfront QA Attribution, & Pure-Rust Local Provenance

- **ADR ID**: `ADR-0001`
- **Status**: Accepted
- **Date**: `2026-11-13`
- **Repository**: `susanbdev/dotagent`
- **Related Specification**: [`SWARM_TECHNICAL_SPEC.md`](file:///home/antigravity/susanbdev/dotagent/docs/SWARM_TECHNICAL_SPEC.md), [`SWARM_IMPLEMENTATION_PLAN.md`](file:///home/antigravity/susanbdev/dotagent/docs/SWARM_IMPLEMENTATION_PLAN.md), [`AGENTS.md`](file:///home/antigravity/susanbdev/dotagent/AGENTS.md)

---

## 1. Context & Problem Statement

`susanbdev/dotagent` is our flagship baseline showing how production coding agents should be structured, constrained, and hardened out of the box across Claude Code, Cursor, Codex, and Gemini.

Standard single-agent setups fail predictably on real engineering work:
1. **Context Window Bloat & Compaction Decay**: Carrying search noise, compiler logs, and multi-task history in one `200k` window degrades reasoning, while repeated LLM compaction drops subtle constraints.
2. **Prompt-Injection Coupling**: Letting the orchestrating agent read raw repository files directly exposes orchestration authority to untrusted comments, fixtures, and READMEs.
3. **Wandering Workers & Untested Edits**: Unconstrained subagents roam unrelated directories, delete assertions to make tests green, edit files after their last test run, or clobber sibling files in parallel waves.
4. **Scope Creep Risk**: Hypervisor management, multi-VM snapshot cloning, and external cloud ML pipelines belong in dedicated outer simulation products--not inside a baseline coding-agent skills and guardrails repository.

---

## 2. Decision Drivers

1. Deliver the swarm orchestration model primarily as **drop-in `SKILL.md` skills and compiled subagent harnesses** backed by fast, minimal-dependency [`agent-guard`](file:///home/antigravity/susanbdev/dotagent/crates/agent-guard/src/lib.rs) CLI hooks.
2. Protect `Master`'s context window across `15+` concurrent projects via total delegation, post-approval **hard context wipe**, and a terse `2+2`-sentence Work Ledger.
3. Make implementation nodes simple and constrained enough that fast **`7B` local models** succeed reliably with zero exploratory roaming.
4. Capture tamper-evident local provenance (`.breadcrumbs.jsonl`, `HMAC-SHA256` event chains, `0`-LLM heuristic badges) in clean local JSONL files with zero external server requirements.

---

## 3. Considered Alternatives & Why They Were Rejected

- **Alternative A: Monolithic Frontier Agent + Aggressive Compaction** -- Rejected; lossy compaction still exposes the decision-maker to raw untrusted files pre-compaction and degrades over multi-wave projects.
- **Alternative B: Coupling `dotagent` to Custom MicroVM Supervisors & External Encrypted Telemetry Servers** -- Rejected; turns a clean, portable baseline skills/hooks repository into heavy infrastructure. Outer VM platforms can read `dotagent`'s local JSONL files without polluting `dotagent`.
- **Alternative C: Blanket Repo-Wide Coverage Numbers + Unattributed Test Suites** -- Rejected; wastes tokens over-testing `1/10` leaf nodes while under-testing `10/10` spine/security nodes, and fails to isolate which parallel worker broke a shared boundary.
- **Alternative D: Unrestricted URL Fetching for Code Reviewers** -- Rejected; even `GET`-only requests to documentation domains allow exfiltrating repository secrets inside URL paths (`https://docs.rs/<encoded_data>`).

---

## 4. Decision Outcome

1. **Skill-First 6-Role Swarm + Hard Context Wipe**:
   - **`Master` (`skills/swarm-master/SKILL.md`)**: Sole human interface; ruthless pre-plan interrogation; locks `PLAN.lock.md` + `PLAN.dag.json` (`SHA-256` verified); executes a **hard context wipe**; never reads or edits source code; arbitrates `Approach X vs. Y` clashes and Round-2 review deadlocks; interrupts the human **only** on 4 hard triggers (unbreakable loop, unforeseen physical blocker, critical access block, verified hostile injection).
   - **`Investigator` (`skills/swarm-investigator/SKILL.md`)**: Read-only (`0` writes); permitted `20`-level directory depth search outside `realpath`-canonicalized forbidden zones; requires `canonical_path:Lstart-Lend` + `doc_sha256` receipts.
   - **`QA Engineer` (`skills/swarm-qa-engineer/SKILL.md`)**: Runs **upfront before Grunts**; writes frozen tests + `test_attribution.toml` (`Primary: 1`, `Secondary: 0..2`, `Tertiary: 0..N`) scaled by `max(domain_risk_floor, dag_fanout)`.
   - **`Grunt` (`skills/swarm-grunt/SKILL.md`)**: `7B`-ready explicit micro-specs; **`0` search/roaming**; writes only `allowed_write_paths` in isolated git worktrees.
   - **`Adversarial Reviewer` (`skills/swarm-adversarial-reviewer/SKILL.md`)**: Offline by default (or lockfile-verified package ID doc lookup only); line-cited evidence; **hard immutable `2`-round cap** before `Master` escalation.
   - **`Forensic Coroner` (`skills/swarm-forensic-coroner/SKILL.md`)**: Lazy post-mortem auditor (`0` source writes); runs `0`-LLM heuristic triage, verifies `.breadcrumbs.jsonl` HMAC continuity, salvages CRC32 crash spools into per-directory trails, and produces bounded root-cause reports on flagged failures.
2. **Evidence-Based Suspect Isolation (`SBFL`)**: `agent-guard qa-suspects` evaluates test pass/fail results against a clean baseline to distinguish `SuspectIsolated`, `BlockedByNeighbor`, `SeamOrSpecConflict` (routed to `Master`), and `InconclusiveAskMaster`.
3. **Complete-Record `HMAC-SHA256` Provenance & Lazy `0`-LLM Triage**: Uses standard audited `hmac` + `sha2` crates over length-delimited event records covering all path/line/task/hash fields, stamping a 1-line Rust heuristic badge (`MALICIOUS`, `OFF_TASK`, `CONFUSED`, `RISKY`) onto the Work Ledger so `Master` pays `0` extra tokens on clean runs.
4. **Crash-Safe Worktree Breadcrumbs & Fail-Closed `2+2` Work Ledger**: `[len][crc32]` framed spools flush idempotently (`event_id` dedup + `fsync` + `git rev-parse --git-path info/exclude`) to `.breadcrumbs.jsonl`, and `on-stop` blocks worker completion (`exit 2`) until `2+2` ASCII sentences + verified receipt pins matching `git write-tree` blob hashes are recorded.

---

## 5. Consequences

- **Positive**: Portable, crisp, zero-infrastructure-bloat baseline repo; any developer or outer runner gets battle-hardened role skills, harness configs, and Rust guardrails immediately.
- **Tradeoffs**: Requires crisp `Master` micro-specs (enforced by the `swarm-master` skill checklist) and isolated git worktrees for concurrent waves.
