# ADR-0001: Privilege-Separated 5-Role Swarm, Merkle Runtime Provenance, & `N`-Parallel MicroVM Counterfactual Optimization

- **ADR ID**: `ADR-0001`
- **Status**: Accepted
- **Date**: `2026-11-12`
- **Repository**: `susanbdev/dotagent`
- **Related Specification**: [`SWARM_TECHNICAL_SPEC.md`](file:///home/antigravity/susanbdev/dotagent/docs/SWARM_TECHNICAL_SPEC.md), [`spec.md`](file:///home/antigravity/susanbdev/dotagent/spec.md), [`AGENTS.md`](file:///home/antigravity/susanbdev/dotagent/AGENTS.md)

---

## 1. Context & Problem Statement

Extensive real-world iteration with autonomous coding agents across multi-repository software systems (`15+` concurrent projects) exposed five compounding failure modes in standard industry agent architectures:

1. **Context Window Saturation & Compaction Rot**: Long-lived agents carrying exploration outputs, compiler errors, raw diffs, and multi-feature state toward `100k-200k` token windows suffer rapid reasoning degradation. Aggressive LLM-based compaction is lossy: it drops critical edge-case constraints while laundering hallucinated or prompt-injected state forward into subsequent turns.
2. **Untrusted Data / Decision-Maker Coupling**: In single-context agents, the model reading untrusted source code and dependency outputs is the same model making architectural and tool-execution decisions--creating an unavoidable confused-deputy and indirect prompt-injection attack surface.
3. **Unverifiable Self-Reporting & Parallel Worker Chaos**: Subagents routinely rationalize broken workarounds, edit code after running their last test, or stomp shared files in parallel runs. Without cryptographic OS-level provenance, a supervisor cannot verify *who* touched *what* or *which* parallel worker broke an integration seam without re-reading raw code itself.
4. **Credit-Assignment Collapse in Naively Logged Telemetry**: Dumping raw chat histories into vector databases ("RAG memory") fails to improve future runs because monolithic transcripts provide no clean causal mapping between specific orchestration choices (task size, model tier, coverage requirement, retry cutoff) and downstream success or regression.
5. **Fragile Static Heuristics**: Any initial human guess at orchestration magic numbers (coverage percentages, retry limits, local-vs-frontier routing cutoffs, churn thresholds) will be suboptimal on Day 1. Sequential `A/B` testing across different tasks is drowned out by task-difficulty variance.

We need an architecture that simultaneously guarantees **zero-trust security invariants**, **scales a single human's oversight across `15+` concurrent projects**, **executes the majority of implementation work on cheap/fast `7B`-class local models**, and **turns every execution into cryptographically attested counterfactual training data** for continuous self-improvement via our `Agora` (`mcp__susanbdev`) MCP hub.

---

## 2. Decision Drivers

1. **Zero Untrusted Token Exposure in Orchestrator Context**: The accountable decision-maker (`Master`) must never ingest raw repository files, raw diffs, or raw `stdout`.
2. **Zero Reliance on LLM Honesty**: Every file touch, line range, byte state, and completion claim must be verified mechanically in pure `#![forbid(unsafe_code)]` Rust ([`agent-guard`](file:///home/antigravity/susanbdev/dotagent/crates/agent-guard/src/lib.rs)) with zero LLM tokens on the happy path.
3. **Mathematical Fault Isolation**: Test failures across parallel tasks must isolate the guilty worker by set elimination rather than burning tokens across innocent workers.
4. **7B-Model Execution Viability**: Implementation tasks must be constrained tightly enough that small local models succeed reliably without exploratory wandering.
5. **Time-Travel Clone Safety (`Turn T -> x 100`)**: Provenance chains and telemetry IDs must remain collision-free and cryptographically linked when a running microVM is rewound to an arbitrary turn (e.g., `Turn 230`) and instantaneously forked `x 100` across intertwined Local and Frontier models.
6. **Hard Separation of Immutable Security vs. Tunable Weights**: Adaptive ML optimization must never be capable of weakening security boundaries.

---

## 3. Considered Alternatives & Why They Were Rejected

### Alternative A: Single Frontier Agent + Aggressive Multi-Step Compaction
- **Rejected**: Even frequent compaction (`15%` window ceiling) still exposes the orchestrating model directly to raw untrusted repo text *before* compaction runs, and repeated lossy summarization degrades architectural coherence across `30+` task nodes or `15` concurrent repositories.

### Alternative B: Vector-DB / RAG "Agent Memory" Over Historical Transcripts
- **Rejected**: Retrieving noisy historical transcripts injects stale assumptions and cross-project contamination without solving causal credit assignment. Knowing *what* happened in a past chat does not tell the orchestrator *which* threshold nudge or model assignment maximizes pass rate per dollar.

### Alternative C: Uniform Codebase-Wide Test Coverage Target (e.g., Flat `80%`)
- **Rejected**: Over-invests tokens testing isolated leaf tasks that nothing downstream depends on (`1/10` criticality) while under-protecting foundational spine modules (`10/10` criticality) where tiny precision errors cascade debilitatively across every downstream task.

### Alternative D: Flat Random UUID Event Logs + Per-Directory `flock` Contention
- **Rejected**: Random UUIDs can be hallucinated unless cross-checked against mutable tables, do not attest to on-disk file hashes (`doc_sha256`), and collide or lose lineage when a microVM snapshot is cloned `x 100` mid-run at `Turn 230`. Scattering blocking `flock` calls across parallel workers risks lock contention and partial JSONL writes.

### Alternative E: End-to-End Neural Policy Controlling All Guardrail Thresholds
- **Rejected**: Allowing ML models to adjust security rules (path policies, ASCII sanitization, command allowlists) creates an adversarial poisoning / reward-hacking vector ("boiling the frog"). Neural policies also overfit severely during the `1-1,000` run cold-start regime compared to constrained tabular/bandit models.

---

## 4. Decision Outcome

We adopt a **7-Pillar Zero-Trust Swarm & Counterfactual Learning Architecture**:

### Decision 1: Hard Context Wipe After Plan Lock + Ephemeral Non-Compacting Subagents
- **What**: Phase 1 produces an explicit self-prompt summary + topological task DAG (`PLAN.lock.md` + `PLAN.dag.json`), locked `0444` (`SHA-256` pinned) upon human approval. `Master` **wipes its entire context window** and operates strictly from the locked plan and a terse Work Ledger. Subagents **never compact**; they run one micro-task in a fresh context and terminate.
- **Why**: Eliminates compaction drift completely while bounding `Master`'s context growth to $O(|V_{\text{DAG}}|)$ (`~80-120` tokens per task), enabling oversight of `15+` projects simultaneously.

### Decision 2: Five Strictly Partitioned Roles Enforced at the Kernel Boundary
- **What**: [`agent-guard`](file:///home/antigravity/susanbdev/dotagent/crates/agent-guard/src/lib.rs) enforces distinct capability sandboxes per role:
  1. **`Master`**: Sole human contact; ruthless upfront requirement extraction; autonomous post-approval execution with a strict **4-trigger human escalation gate** (unbreakable loop, unforeseen physical architectural blocker, critical access block, verified hostile injection); sole arbiter of cross-worker `Approach X vs. Y` disputes and Round-2 review deadlocks; **hard-blocked from reading/writing repo source**.
  2. **`Zero-Trust Investigator`**: Strictly read-only (`0` writes); **exempted from `max-depth <= 2`** (`20+` levels permitted for deep discovery) while still hard-blocked from all forbidden cache/tmp/dependency/secret dirs; every claim requires exact `file:Lstart-Lend` + `SHA-256` receipts.
  3. **`QA Engineer`**: Runs upfront before `Grunt` implementation; writes tests + `test_attribution.toml` only (`0` prod code writes); scales coverage targets (`50%` to `90%+`) dynamically from DAG downstream fan-out + error-cascade severity; tags every test with **`Primary (1)`, `Secondary (0..2)`, and `Tertiary (0..N)`** task attribution.
  4. **`Standard Grunt`**: Scoped `allowed_write_paths` only; **`0` codebase exploration (`rg`/`find` blocked)**; fed constraints explicit enough for a **`7B` local model** to execute with zero ambiguity.
  5. **`Adversarial Reviewer`**: Read-only repo access + **HTTPS `GET`-only documentation allowlist** for external sources of truth; line-referenced evidence required; capped at **`2` failed remediation rounds** before mandatory `Master` intervention.

### Decision 3: Pure-Rust Combinatorial Fault Triangulation
- **What**: Before dispatching repair agents on test failures, Rust evaluates the `Primary / Secondary / Tertiary` pass/fail matrix: isolating single-owner bugs, shielding clean tasks from broken `Secondary` neighbors, and routing genuine `Approach X vs. Approach Y` seam clashes directly to `Master`.
- **Why**: Prevents token burnout and cascading code thrash when one worker breaks a shared interface.

### Decision 4: Keyed `HMAC-SHA256` Fork-Safe Merkle Event Chains + Lazy Heuristic Triage
- **What**: Subagent `stdin`/`stdout`/`stderr` lines are captured by a pure-Rust tap, assigned keyed `HMAC-SHA256` Merkle IDs binding `(prev_event_id, fork_epoch, clone_id, session_id, seq_no, ts_ns, op, doc_sha256)`, and tagged deterministically (`MALICIOUS`, `OFF_TASK`, `CONFUSED`, `RISKY`). Raw flight logs remain `0600` self-blind inside guard state and are ignored unless `Master` spots a Tier-0 alert badge during triage (escalating lazily to structured Rust spans or a disposable `Forensic Coroner` subagent).
- **Why**: Zero LLM cost on the `95%` clean path, zero hallucinated receipts, and complete immunity to snapshot-clone ID collisions when rewinding to `Turn 230` and forking `x 100`.

### Decision 5: Single-Writer Per-Directory `.breadcrumbs.jsonl` Queue + `2+2` Work Ledger Stop Gate
- **What**: Lock-free per-session spools feed a single-writer Rust queue that populates `<dir>/.breadcrumbs.jsonl` (`ts_ns`, `session_id`, `op`, `file`, `lines`, `doc_sha256`, `event_id`) in every touched directory--git-excluded for clean commits, guard-locked against tampering, and harvested into telemetry. `on-stop` hard-blocks completion until the subagent writes `<= 2` action sentences + `<= 2` issue/mitigation sentences pinned to verified session `HMAC` `event_id`s.
- **Why**: Gives instant spatial blame (`which session touched this folder/file/line at what hash`) and forces crisp causal summaries backed by unforgeable OS receipts.

### Decision 6: Externalized Bounded `PolicyVector` + `N`-Parallel Pooled Cross-Examination
- **What**: Security laws remain immutable Rust code; all tunable heuristics live in a signed `PolicyVector` (`policy.v1.json`) clamped within hard Rust min/max bounds. Parallel `N`-arm microVM forks evaluate candidate `PolicyVector`s and `Local + Frontier` model mixes on the exact same base commit and cross-test final trees against the **pooled union of cohort QA suites** before computing group-relative advantage (`GRPO`).
- **Why**: Eliminates task-variance noise, prevents an arm from cheating via weaker tests, and turns bad initial threshold guesses into self-correcting empirical parameters.

### Decision 7: Two-Lane Attested & Asymmetric-Encrypted `Agora` (`mcp__susanbdev`) Export
- **What**: Clones fire an immediate `< 2 KiB` signed scorecard to `Agora` (consistent-hashed by `cohort_id` for `< 10ms` lock-free in-memory scoring), followed by a staggered (`clone_id * 20ms`) upload of the **Merkle delta archive** (`Turn_fork+1 .. End`) attested via `manifest.sha256` and encrypted on-VM using **only `Agora`'s public key**.
- **Why**: Sustains `100+` concurrent microVM bursts without thundering-herd stalls while guaranteeing compromised worker VMs cannot decrypt historical telemetry or proprietary ML data.

---

## 5. Consequences

### Positive
- **Predictable Orchestrator Precision**: `Master` stays tiny, untainted, and razor-sharp across `15+` concurrent projects without compaction decay.
- **Radical Compute Cost Reduction**: Tight upfront specs + upfront QA boundaries push the bulk of implementation onto zero-marginal-cost `7B` local models, reserving frontier tokens for `Master` arbitration and `Adversarial Review`.
- **Compounding Empirical Moats**: Every `Turn T -> x 100` fork banks compiler-verified `Contextual Bandit` policy data and `Step-DPO` trajectories into `Agora`.
- **Cryptographic Non-Repudiation**: Every line of code, directory touch, and ledger claim traces back through an unbroken `HMAC-SHA256` Merkle chain.

### Tradeoffs & Mitigations
1. **Higher Upfront Planning & Spec Authoring Rigor**: `Grunt` workers with `0` exploration will fail immediately if `Master` writes lazy specs.
   - *Mitigation*: Enforced upfront `Investigator` receipt gathering, mandatory pre-approval user interrogation, and `PolicyVector` spec-density pre-flight checks before spawning a `Grunt`.
2. **Disk I/O Overhead from Per-Line Stream Capture & Directory Breadcrumbs**: High-volume `rg` searches by `Investigator` workers could generate noisy breadcrumb entries.
   - *Mitigation*: Single-writer async spooling + collapsing contiguous match ranges per `(session_id, file, doc_sha256)` within a single `GREP` invocation, plus Merkle delta deduplication on export.
3. **Reviewer Network Exfiltration Risk**: Giving `Adversarial Reviewer` outbound web access could leak code via crafted URLs.
   - *Mitigation*: Enforced HTTPS `GET`-only documentation domain allowlist in proxy/`cmd_policy` with strict URL query-length caps and zero auth/POST payloads.

---

## 6. Verification & Implementation Gates

Implementation of this ADR inside `susanbdev/dotagent` is gated on:
1. `100%` `#![forbid(unsafe_code)]` Rust unit and adversarial bypass tests covering role boundary denials, `HMAC` receipt forgery rejection, `Primary/Secondary/Tertiary` fault triangulation, and post-fork `Turn T -> x 100` Merkle uniqueness.
2. Pure 7-bit ASCII compliance across all compiled profiles (`master`, `investigator`, `qa-engineer`, `grunt`, `adversarial-reviewer`, `forensic-coroner`) verified by `dotagent-compiler verify .`.
3. Zero regressions across existing [`bypass_corpus.toml`](file:///home/antigravity/susanbdev/dotagent/tests/bypass_corpus.toml) security vectors.
