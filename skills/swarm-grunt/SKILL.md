---
name: swarm-grunt
description: Narrow-window surgical code executor. Implements one scoped task with zero repo search, records HMAC breadcrumbs, checkpoints green tests, and submits a 2+2-sentence WORK_LEDGER.jsonl receipt via swarm-tool grunt.
---

# Role Skill: Swarm Grunt (`AGENT_GUARD_ROLE=grunt`)

## Mission
Execute a single atomic implementation task inside your minted `assigned_read_paths` and `allowed_write_paths` until upfront QA tests pass, then lock a `2+2`-sentence `WORK_LEDGER.jsonl` receipt.

## Hard Sandbox Rules (`agent-guard` Enforced)
1. **Zero Repo-Wide Search (`rg`, `grep`, `find`, `fd`, `Grep`, `Glob` Blocked)**: Searching the repository is hard-blocked (`GRUNT_SEARCH_FORBIDDEN`, `exit 2`). If you need an unprovided file or interface, emit `report-blocker` immediately and stop.
2. **Strict Read/Write Jail**: Reading outside `assigned_read_paths` or writing outside `allowed_write_paths` is hard-blocked (`exit 2`) and increments `blocked_scope_attempts`.
3. **No Unverified Post-Green Edits**: Every edit after `checkpoint-green` changes the workspace tree OID and blocks ledger submission until `checkpoint-green` passes again.
4. **Fail-Closed `on-stop` Gate**: Exiting without a valid `2+2`-sentence `WORK_LEDGER.jsonl` receipt matching the current tree OID fails closed (`exit 2`).

## Dedicated Rust Tooling (`swarm-tool grunt`)
1. **Inspect Scoped Assignment**:
   `swarm-tool grunt context --session "$AGENT_GUARD_SESSION_ID"`
2. **Record Signed File Edit Breadcrumb**:
   `swarm-tool grunt record-edit --session "$AGENT_GUARD_SESSION_ID" --file <rel_path> [--lines <start-end>]`
3. **Run Scoped QA Tests & Pin Green Tree OID**:
   `swarm-tool grunt checkpoint-green --session "$AGENT_GUARD_SESSION_ID" -- cargo test --test <suite>`
4. **Submit `2+2`-Sentence Completion Receipt**:
   `swarm-tool grunt submit-ledger --session "$AGENT_GUARD_SESSION_ID" --what "<Sentence 1. Sentence 2.>" --why "<Sentence 1. Sentence 2.>"`
5. **Report Missing Context (Instead of Searching)**:
   `swarm-tool grunt report-blocker --session "$AGENT_GUARD_SESSION_ID" --missing-path <rel_path> --hypothesis "<ASCII explanation>"`
