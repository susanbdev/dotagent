# Dotagent local telemetry

## Baseline and ownership

The integration base is `e30d3ab9b4ce5b9b959ab86fe21c50e2c590a551`, the Phase 0 reconciliation merged through PR #21. Its parent, `83195f47bdaf31471a33526df0014730b3dde8cc`, is the merged swarm work from PR #19. The original starting revision `2ae1b1e4045fa53041711474619b9c0688e463a8` includes PR #17. The initial local Thread B work used the provisional swarm commit `3eb6ce4282fa0437f3cbb3c0ae2263db2eb35964`. Compatibility work used separate worktrees.

| Historical baseline observation | Source | Result |
| --- | --- | --- |
| Original `HEAD`, `main`, and `origin/main` | Clean clone, local Git refs | Resolved individually to `2ae1b1e4045fa53041711474619b9c0688e463a8` |
| Advertised `main` | Remote ref listing | `2ae1b1e4045fa53041711474619b9c0688e463a8` |
| Advertised and cached swarm integration tip | Remote listing and local remote-tracking ref | `3eb6ce4282fa0437f3cbb3c0ae2263db2eb35964` |
| `origin/v2-1-review-fixes` | Local resolution | Exit `128`, unresolved |
| Review fixes commit | Local ancestry of the swarm integration tip | `05dbf08ef3d48096a058b6b81fbc4dbf1db0c3f2` present |
| Thread B branch base | Local `HEAD` after selecting the base | `3eb6ce4282fa0437f3cbb3c0ae2263db2eb35964` |

The Phase 0 range changes `crates/agent-guard/src/lib.rs`, `crates/agent-guard/src/budget_guard.rs`, and `crates/agent-guard/src/traversal_ledger.rs`. Thread B works on top of that range. The integration writer handles boundary calls and module registration. Thread A retains `coordinator.rs`, `role_sandbox.rs`, `work_ledger.rs`, `breadcrumbs.rs`, `exec_sandbox.rs`, `shell_wrapper.rs`, and supervisor gates in `crates/swarm-tools/src/lib.rs`. Those paths are inputs for route review and future integration.

## Schema version 1

| Field | Units and meaning |
| --- | --- |
| `schema_version`, `event_id`, `event_type` | Envelope revision, local process-assigned identifier, and event family. |
| `producer.component`, `producer.instance_id`, `producer.sequence` | Stable component label, process instance label, and process-local sequence. Auxiliary identifier allocation can consume sequence numbers. Ordering across instances is unknown. |
| `timing.observed_at_unix_ms`, `timing.occurred_at_unix_ms` | Wall-clock milliseconds since the Unix epoch. The occurrence time comes from the call site when available. |
| `timing.duration_ns`, `timing.clock` | Observed monotonic elapsed nanoseconds within a single process, with the clock/source label. |
| `timing.writer_wait_us` | Store-observed wait to acquire the writer lock, in monotonic microseconds. |
| `correlation.trace_id`, `parent_event_id`, `execution_id`, `intervention_id` | Trace, immediate parent, invocation, and intervention identities. Each has its own lifetime. |
| `correlation.causal_links[]` | Up to eight references with `event_id`, `relation` and `method`. `heuristic` also requires `algorithm_version`. `explicit` and `exact` describe the source of the link. |
| `correlation.source_event_id` | Stable original identity for projections and replay deduplication. Preserve it across retries. |
| `work.repo_id`, `session_id`, `root_session_id`, `plan_id`, `task_id`, `allocating_parent_id`, `role`, `attempt`, `epoch` | Applicable repository, session and work context. Repository IDs derive from the local repository path. Task epoch and attempt are integers when known. |
| `configuration.policy_id`, `bundle_id`, `profile_id` | Applicable configuration identities. Decision thresholds, units and precedence belong to the domain payload. |
| `trust.origin`, `authentication`, `evidence`, `verification` | Emitter identity class, provenance of submission, evidence type and verification state. `local_host_callsite` denotes in-process provenance. Use the owning gate or journal to validate authoritative evidence. |
| `result.action`, `reason_code`, `disposition`, `completeness` | Bounded outcome labels. Completeness is `complete`, `partial`, or `unavailable` for the stated observation. |
| `payload` | Domain fields selected by producer component and event family within the envelope version. Example fixture payloads also declare `namespace`. |

Absent optional fields mean unknown or inapplicable. The encoder accepts ASCII identifiers up to 128 bytes, up to 48 fields or items per payload collection, a nesting depth of four from the payload root, and 192 payload nodes. The serialized frame includes its newline within a 16 KiB ceiling. Controlled token syntax is a size and format check. Call sites must select safe typed values before constructing an event.

### Producers and evidence

| Producer | Allowed event families | Evidence |
| --- | --- | --- |
| `dotagent.baseline` | `EXECUTION_STARTED`, `EXECUTION_FINISHED`, `PREREQUISITE_CHECKED` | Fixed host-mediated prerequisite commands and observed results. |
| `agent-guard.shell-wrapper` | `EXECUTION_STARTED`, `EXECUTION_FINISHED` | Host launch and OS wait result for the trusted sandbox mediator. |
| `agent-guard.hook` | `CONTROL_DECISION`, `USAGE_AND_DISPOSITION`, `DETECTION_ASSESSMENT`, `RECOVERY_OR_ESCALATION` | Guard actions, observed boundary measurements and unreviewed derived assessments. |
| `agent-guard.audit` | `CAPTURE_HEALTH` | Local storage activity. |

The emitter assigns provenance from a closed producer allowlist. Worker input has no generic event submission entry point. Hook-origin activity can still contain adapter-reported quantities. Coverage and domain fields must describe that boundary. Treat a detector category as a suspected finding. A completed guard denial is an observed action. A subsequent reviewed assessment references the original event and retains the original disposition. Each execution result applies to its observed process. An unmatched launch remains incomplete.

| Event family | Domain fields and interpretation |
| --- | --- |
| `EXECUTION_STARTED`, `EXECUTION_FINISHED` | `executable`, `subject`, `route`, and status fields describe the mediator invocation. The baseline producer may include `argument_summary` and `deadline_ms` for its fixed prerequisite commands. `nested_process_coverage` applies to child commands. Process exit, signal and timeout are separate observations. |
| `PREREQUISITE_CHECKED` | `requested_check`, `source_freshness`, `check_expectation` and `observed_status`. Optional fields include `resolved_commit` or `worktree_dirty` with `status_scope`. A failed check and a successful status observation remain separate. |
| `CONTROL_DECISION` | `boundary`, `control`, `threshold`, `unit` and `threshold_source` where applicable. Decisions, effective limits and routing are evaluated together. |
| `USAGE_AND_DISPOSITION` | Requested, granted, selected, scanned and emitted counts when observed. Line offsets are one-based. Byte counts use bytes, `continuation_available` is a Boolean, and estimated tokens use `dotagent.bpe-heuristic.v1`. Output records identify sanitizer transformations and dropped bytes attributable to each cap. |
| `DETECTION_ASSESSMENT` | Category, detector version, observed scan span and optional safe coordinates. Detector alerts begin as suspected. |
| `RECOVERY_OR_ESCALATION` | Intervention identity and explicit or exact causal references. A recovery's parent and supporting antecedents can differ. |
| `CAPTURE_HEALTH` | `failed_appends`, `torn_bytes` and `expired_archives` record storage activity known to the writer. |

The default file slice setting is 150 lines in `coding-agent` and `research-readonly`. A control record identifies when the effective profile selects that limit. Raw file, single-line and tool-output caps have separate byte units. The recorded boundary identifies whether the guard performed a check or observed a measurement.

## Storage and data handling

The existing protected audit file holds legacy JSONL and versioned records. Legacy denial lookup considers complete legacy records under a 512-record and 256 KiB legacy budget, with an outer 2 MiB scan of the active file. Typed frames are excluded as denial evidence. Typed diagnostics use the schema marker. Authority belongs to the transition journal or gate that produced the original evidence. Project an authoritative event using its stable source identity if the projection is retried.

The writer uses the existing cross-process audit lock. The Unix state directory is protected with mode `0700` and audit files with `0600`. The writer checks for regular files, single links and a consistent open descriptor. Runtime worker blindness continues to depend on existing sandbox and path enforcement. Human CLI diagnostics pass the existing interactive TTY and harness-marker gate.

The append path limits active files to a 10 MiB target with up to five numbered archives by default. Rotation reserves room for a bounded health record. Manual rotation shares the writer lock and allows up to 20 archives. Retention is size-based, so the earliest retained wall-clock time depends on event volume and rotation. Use the oldest retained observation and any gap indications when evaluating coverage. The newest recoverable incomplete suffix, at most one frame, is quarantined separately. A missing frame boundary beyond that limit produces a writer error. A pending quarantine allows restart to report the gap before finalizing recovery. Quarantine bytes are outside the diagnostic stream and carry unknown origin.

The append API distinguishes `Persisted`, `DroppedNoncritical` and `FailedRequiredEvidence`. Buffered success acknowledges a complete write to the operating system. Required success includes a data sync and a directory sync on Unix. Failure is returned to the caller with a bounded operator diagnostic. A later successful write can persist a health record for available counters. Failed-write counters are process-local and can be lost when a writer terminates. Logging is synchronous and uses the bounded existing lock wait.

Payload construction uses allowlisted command shapes, names and metrics before serialization. Treat raw prompts, source, shell strings, arbitrary arguments, environment and output as sensitive input. Secret-derived hashes can be reversible for low-entropy values. Use a bounded reference to a retained authorized artifact when available. Character sanitization serves output hygiene. It cannot establish that emitted data is free of secrets.

## Reader and extraction boundary

Keep envelope decoding independent of the writer. Read complete JSON objects within a fixed byte and record budget. Treat older records without a schema marker as legacy. Skip unsupported versions and event families with a coverage count. For recognized versions, ignore additive fields outside the consumer's schema and preserve unknown states. Interpret chronology within a producer or a direct causal chain. Treat timing buckets as inclusive measurements when intervals overlap.

To extract the contract into a shared Rust component, move the envelope types, producer capability checks and wire-format fixtures together. Keep Dotagent payload constructors and access control at the application boundary. Keep transport and retention behind the emitter implementation. Register each future producer explicitly, assign a new instance per process and preserve source IDs for projections. MCP, sims and envctl examples under `crates/agent-guard/tests/fixtures/telemetry/` are schema fixtures. A future assessment producer uses its own identity and references immutable captured records.

### Operator diagnostics

From the repository directory, an authorized operator can run `dotagent telemetry baseline` to record individual observations for `HEAD`, local `main`, cached `origin/main` and working-tree status. Add `--include-review-fixes` to check cached `origin/v2-1-review-fixes` before status. The fixed checks run through the existing sandbox mediator with kernel enforcement required, network denied and read-only access. Status includes changes to recorded submodule commits while ignoring nested submodule dirtiness. The baseline exits unsuccessfully if a prerequisite cannot be established or its record cannot be persisted. Each check has one 10-second monotonic deadline for output collection and the mediator wait. On a timeout, the host attempts to stop the outer mediator process group and records whether it reaped the direct child. Nested execution remains unavailable on this route. Remote freshness is outside this route. Operator signature requirements apply when configured.

Use `dotagent telemetry trace` for aggregated observations from the beginning of the active file, up to 8 MiB or 4,096 records. Archives are outside this query window. `dotagent telemetry trace --trace-id ID` adds up to 256 rows from a trace and its connected observations. The report includes control settings, interventions, outcomes where linked, truncation and continuation, detector dispositions, storage health and explicit coverage counters. It limits each grouping to 128 keys with overflow counts. A missing or unreadable active file produces an unavailable result. A launch without its observed finish is incomplete in the queried window. Missing predecessor events can reflect earlier rotation. The writer-wait aggregate reports the observed sample count and total microseconds, with a null total when no sample is present. Event durations are reported separately and can overlap.

## Execution ledger

All task inputs start from `3eb6ce4282fa0437f3cbb3c0ae2263db2eb35964` plus completed prerequisite changes in this branch. The table uses paths relative to `crates/agent-guard/` unless a full repository path is shown. Each row's write set is assigned to its owner for that integration step.

| Task and requirements | Owner and prerequisite | Assigned reads | Allowed writes and expected output |
| --- | --- | --- | --- |
| C00, reconcile Git observations and route ownership | Integration. No task prerequisite. | Git refs, `AGENTS.md`, `docs/swarm_v2.dag.json`, `.github/workflows/ci.yml`, telemetry and boundary files below. | `docs/thread-b-telemetry.md` baseline manifest and path map. |
| C01, freeze envelope and trust checks (E07, E13) | B with A review. C00 identifies host and worker surfaces. | `src/json.rs`, `src/lib.rs`, `src/telemetry.rs`, `src/traversal_ledger.rs`. | `src/telemetry/capture.rs` and telemetry fixtures. Typed encoder, emitter and wire-schema fixtures. |
| C02, start protected capture (E01, E10, E11) | B with integration registration. C01 supplies the envelope and outcomes. | `src/traversal_ledger.rs`, `src/breadcrumbs.rs`, `src/telemetry.rs`, `src/cli.rs`. | `src/telemetry/store.rs`, `src/traversal_ledger.rs`, `src/telemetry.rs`, `src/cli.rs` at owned boundaries. Shared writer and baseline entry point. |
| B01, bound storage and recover tails (E10, E11, E17) | B. C02 establishes a single writer and frame format. | `src/breadcrumbs.rs`, `src/traversal_ledger.rs`, `src/telemetry.rs`. | `src/telemetry/store.rs`, `src/traversal_ledger.rs`, `src/telemetry.rs`. Serialized append and rotation, framed recovery, explicit failure handling. |
| B02, record execution and prerequisite results (E01–E03, E12, E14) | B. C01 defines payloads. C02 provides the baseline sink. A04 supplies broader trusted launch and termination callbacks. | `src/cli.rs`, `src/shell_wrapper.rs`, `src/exec_sandbox.rs`, `crates/dotagent-harness/src/bootstrap_suite.rs`. | `src/telemetry/observations.rs`, `src/cli.rs` for baseline wiring. Fixed check routes, truthful result states and route coverage. |
| B03, measure decisions and effective limits (E05, E12, E14) | B and integration. C01/C02 provide capture. Phase 0 integration base contains the prior boundary changes. | `src/lib.rs`, `src/budget_guard.rs`, `src/sanitizer.rs`. | `src/telemetry/controls.rs`, `src/budget_guard.rs`, `src/sanitizer.rs`, `src/lib.rs` at registered boundaries. Typed limits, counts and continuation data. |
| B04, distinguish detection and assessment (E06, E12) | B and integration. B03 provides observed sanitizer and enforcement boundaries. | `src/injection_scan.rs`, `src/lib.rs`, `src/sanitizer.rs`. | `src/telemetry/controls.rs`, `src/lib.rs` at registered boundaries. Detector provenance and linked assessment representation. |
| B05, follow intervention and outcome chains (E04, E14, E15, E18) | B. B02–B04 furnish observations. A04 owns authoritative task outcomes and live lineage handoff. | `src/telemetry/capture.rs`, domain payload modules, `crates/swarm-tools/src/lib.rs`. | `src/telemetry/diagnostics.rs` and typed payload tests. Explicit links, bounded summaries and source-ID deduplication. |
| B06, expose capture health and diagnostics (E10, E11, E14, E17–E19) | B and integration. B01 supplies retention and health signals. B05 supplies trace semantics. | `src/telemetry/store.rs`, `src/telemetry.rs`, `src/traversal_ledger.rs`. | `src/telemetry/diagnostics.rs`, `src/telemetry.rs` for authorized diagnostic wiring. Bounded descriptive query output. |
| B07, prove schema reuse (E13, E17) | B. C01 stabilizes the envelope. B06 establishes reader behavior. | `src/telemetry/capture.rs`, `src/telemetry/diagnostics.rs`. | `tests/fixtures/telemetry/mcp.json`, `tests/fixtures/telemetry/sims.json`, `tests/fixtures/telemetry/envctl.json`, `docs/thread-b-telemetry.md`. Reusable envelope examples and extraction steps. |

| Task | Shared resource and integration gate | Escalation or unresolved condition |
| --- | --- | --- |
| C00 | Pin each Git observation before assigning shared paths. | Keep unresolved revisions visible. The selected branch resolves independently. |
| C01 | Domain constructors and schema fixtures must agree on fields, emitter permissions and compatibility. | A review and any new producers require the integration owner. |
| C02 | The same audit writer and lock serve old and new records. E01 retains a failed prerequisite alongside a successful status observation. | Protected state incompatibility or required persistence errors go to the operator. |
| B01 | Concurrent append, tail recovery, rotation and restart preserve complete frames or return explicit errors. | Filesystem, permission, lock and retention failures create coverage gaps. |
| B02 | Isolation between per-ref resolutions. Verify distinct exits, signals, missing completion and route coverage. | A04 controls authoritative general commands, nested-shell visibility and lifecycle completion. |
| B03 | Recorded limits match the policy path exercised, including the profile-selected line slice limit and separate byte limits. | Adapter-visible fragment boundaries or compaction callbacks can be unavailable. |
| B04 | Detector version and category persist with observed action and an independently linked confirmation or dismissal. | Live review callback coverage requires an authorized producer. |
| B05 | Retried projections count once. Chains require explicit or exact supported correlation, and inferred links remain labeled. | Live authoritative outcomes and cross-session lineage require A04. |
| B06 | Queries enforce existing human access, bounded reads and cardinality. Disabled or failed storage stays visible. | Counts describe the retained, queried interval. Sustained-load acceptance belongs to I02. |
| B07 | Named fixture domains load under shared envelope rules and tolerate an unknown payload. | Production cross-project producer registration belongs to a later integration. |

## Supported routes and pending integration

| Route | Observation boundary | Coverage limitation |
| --- | --- | --- |
| Baseline prerequisite checks | Host launch and termination of fixed Git checks, then separate prerequisite result | The checkout observation can change after the command completes. Cached remote-tracking refs and fresh remote observations are distinct. |
| Guard read decision and budget inspection | Observed selected source slice, limits and guard decision | Adapter emission after the hook is outside this boundary. |
| Guard tool output processing | Observed input and sanitized or compacted output metrics where exposed to the hook | An absent hook callback leaves coverage unknown. |
| Guard detector alert and enforcement | Suspected category and observed denial or other action | Human confirmation and false-negative ground truth require reviewed evidence. |
| Protected audit storage | Active append, bounded recovery, rotation and read windows | Termination during a write can leave an incomplete suffix or an unrecorded failure interval. |
| General shell and checkpoint execution | A04 trusted launch and completion | Live Thread A instrumentation pending. Individual nested-shell commands require separate supported observations. |
| Coordinator allocation, lease, stage and supervisor terminal outcomes | Existing authoritative transaction or journal | Live Thread A instrumentation and integrated acceptance pending. |
| Standalone harness outcomes and compaction | Harness lifecycle callbacks where available | Coverage remains unknown until exercised and measured per adapter. |
| Antigravity end-to-end | Combined A and B lifecycle | Integrated acceptance pending. |

The Thread A closure roadmap keeps S01–S04 and P07 with their assigned owner. Later S05–S12, L01–L12, W01–W08, A01–A08, P01–P06/P08, O01–O04, F01–F03 and V01–V03 depend on the existing security roadmap. Thread B observations supply inputs for those checks. Limit policy changes require I02 and I03 with comparable runs.

## Acceptance tracking

| Checks | Thread B evidence surfaces | Integrated coverage still required |
| --- | --- | --- |
| E01 | `telemetry::observations` exercises independent ref and status results. | Authorized live `baseline --include-review-fixes` run with unresolved cached review fixes followed by a successful status. |
| E02–E03 | `telemetry::observations` distinguishes direct process states and declares nested process coverage. `telemetry::diagnostics` reports unmatched starts in a bounded window. | A04 termination callbacks and route verification. |
| E04, E14, E18 | `telemetry::diagnostics` exercises retries, linked alternatives, incomplete coverage and stable projection deduplication. | A04 durable lineage handoff and authentic terminal outcomes. |
| E05, E12 | `telemetry::controls`, `budget_guard`, `sanitizer`, and `telemetry::capture` exercise measured boundaries and safe payload fields. A fixture calls the production PostToolUse handler in isolated state and verifies persisted measurements and omission of raw output. | Per-adapter emitted output and a comparable read workload. |
| E06 | `telemetry::diagnostics` exercises a linked reviewed dismissal while preserving an observed guard decision. | Authorized assessment callback. |
| E07, E13 | `telemetry::capture` tests emitter eligibility and field bounds. `telemetry::diagnostics` exercises reader compatibility and invalid frames. | Combined worker boundary review and ready-to-admit producer verification. |
| E08–E09, E15–E16 | Ownership remains with A and the integration owner. Thread B provides observation and reader contracts. | Authoritative completion and integrated Antigravity verification. |
| E10–E11, E17 | `telemetry::store` exercises four processes writing 80 complete records, torn-tail recovery, pending quarantine across restart, retention and explicit writer failure. `telemetry::diagnostics` exposes storage and reader coverage. | Platform and filesystem coverage, including a live capacity failure, where available. |
| E19–E20 | Event rate and retained size can be measured at the writer. Fixtures exercise bounded work. | I02 sustained-load evidence against predeclared limits, then I03 replay if policy changes are proposed. |

The focused local fixture suite is `cargo test --locked -p agent-guard --lib telemetry::`. Repository format, clippy and compiler gates are listed in `.github/workflows/ci.yml`.

| Verification | Observed status |
| --- | --- |
| `cargo fetch --locked` | Passed with Cargo 1.88.0. |
| `cargo metadata --offline --locked --format-version=1` | Passed. The 81 resolved packages declare no Rust version above 1.88. |
| `cargo fmt --all -- --check` and `git diff --check` | Passed. |
| `cargo check --workspace --all-targets --offline --locked` | Passed with Rust 1.88.0 using isolated build and test-state directories. |
| `cargo test -p agent-guard --lib --offline --locked telemetry::` | Passed 30 tests, with 36 filtered out. The one ignored latency fixture was run separately. |
| `cargo clippy --workspace --all-targets --offline --locked -- -D warnings` | Failed with 11 diagnostics in untouched source files. A clean checkout of the pinned base reproduced all 11 at the same lines and with the same lint IDs. |
| `cargo run -p dotagent-compiler --offline --locked -- verify .` | Passed for all 58 compiled artifacts. |
| `cargo test -p agent-guard --lib --offline --locked telemetry::store::tests::measures_isolated_append_latency -- --ignored --nocapture` | Passed with the measurements below. |

The latency fixture used one writer on Linux x86-64 and a Rust 1.88.0 debug build. Each mode wrote 192 representative events. The fixture measures per-append time and file growth under these local conditions. I02 still requires comparable live workloads and predeclared resource and latency budgets.

| Append mode | Sample count | Median | p95 | File growth |
| --- | ---: | ---: | ---: | ---: |
| Buffered | 192 | 138,368 ns | 253,871 ns | 156,486 bytes |
| Required sync | 192 | 451,538 ns | 604,418 ns | 156,486 bytes |

## Integration on the reconciled Phase 0 base

The integration applies the telemetry and host-wrapper commits on top of `e30d3ab`. The protected audit writer and the authorized read path remain inside the guard. Checkpoint validation, coordinator state, supervisor acceptance and the release workflows keep their existing authority. The existing webfont fixture and the new measured-read fixture both run on this tree.

| Outcome level | Evidence |
| --- | --- |
| Attempted | An adapter request or dispatch record identifies the intended action. The shell wrapper emits `EXECUTION_STARTED` after it successfully launches the trusted sandbox mediator. |
| Observed | The wrapper records the mediator's OS wait result before output filtering. The execution ID connects launch and finish. Nested execution remains unavailable on this route. |
| Authoritative | The existing checkpoint ledger and supervisor reconciliation own accepted task outcomes. Telemetry currently provides no live projection from those gates. |

The wrapper omits command text and streams from telemetry. The fixed Git baseline reports the actual static policy denial when linked worktree metadata is unsupported. Its command-policy fixture uses standalone repository metadata.

### Combined verification

| Check | Result |
| --- | --- |
| Formatting and diff validation | Passed. |
| Strict workspace Clippy | Passed on Rust 1.100.0, the CI stable channel. The audit counters retain saturating behavior on the Rust 1.88.0 MSRV. |
| Workspace check and build, offline and locked | Passed on Rust 1.88.0. |
| Workspace test compilation, offline and locked | All 26 Cargo test executables compiled. Full behavioral execution was outside this run. |
| Focused telemetry tests | 35 passed. The separately measured writer fixture was ignored in this run. |
| Focused security tests | Checkpoint session identity, isolated scratch preparation and webfont file handling passed. |
| Compiler verification | All 58 artifacts matched. |
| Gemini/Antigravity adapter replay | One scenario and all 10 steps passed against the combined binaries. |
| Native Antigravity | Unverified. The workspace has no connected authenticated runtime. |

Release promotion and hardware signer rotation remain blocked pending independent verification of the existing [release signing requirements](RELEASE_SIGNING.md).
