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

Trusted hosts start two independent worker lanes before local evaluation. Each lane preallocates 128 queue slots and permits one job in flight. Producers and consumers try the queue lock once per attempt. Consumers retry on their own polling schedule. Full, closed, contended and unavailable lanes reject submissions before building a descriptor or cloning legacy and export inputs. Source sequences are assigned under the admission guard so concurrently admitted typed events from each producer persist in order. The worker validates and builds the wire envelope, serializes records, redacts legacy and export inputs, and performs sink I/O after releasing the queue lock. Set `DOTAGENT_TELEMETRY=0` before startup to disable both lanes.

Call sites still construct bounded domain payloads, and successful admission copies bounded context and takes an observation timestamp. Some legacy and export descriptors allocate bounded owned input. Rejection can release an already constructed payload. Allocator and scheduler costs, as well as host thread creation at startup, affect wall-clock measurements. Submission has no wait for queue capacity, worker progress, I/O, or acknowledgement. No memory, file descriptor, or other handle into protected telemetry state is given to sandboxed workers.

The audit worker writes typed and legacy observations through the protected local store. The independent export worker writes optional AgentPI projections, including guard, plugin and feedback-loop signals, to the existing protected mirror. Explicit feedback command results and MCP replies retain their result channels. `DOTAGENT_AGENTPI_STDERR` no longer enables optional stderr output. The human-authorized `telemetry export-otlp` command continues to read and render a local snapshot in a separate invocation.

The session ledger, authenticated breadcrumbs, signed feedback ballots, coordinator transactions, work-ledger checkpoints and StopReceipts retain their own durability and decision rules. Use session-ledger evidence to ground feedback, checkpoint and permission decisions. The legacy audit lookup provides a best-effort view of the active observation file.

### Delivery and shutdown

| Status | Evidence |
| --- | --- |
| `admitted` | An owned descriptor or job was accepted into that process's queue. `queued` remains a compatibility alias. A source event ID can correlate an admitted event whose record never appears. |
| `persisted` | The worker reported a successful sink operation. Buffered writes carry the sink's existing durability and provide no durable handoff acknowledgement. |
| `failed` | A worker reported an encoding rejection or sink error for an admitted job. A sink error can follow a partial write. |
| `dropped` | Admission rejected the submission as full, contended, unavailable, closed, or invalid. The cause counters remain visible. |
| `pending` | The sampled difference between admissions and reported terminal outcomes. Jobs may be queued, executing, or abandoned after a worker stopped. |
| `unconfirmed_at_exit` | Admitted work without retained outcome evidence when a process ends. Live samples report this value as unknown. An absent or zero-pending sample cannot establish complete delivery. |

Closing stops admission and lets the workers drain as their sinks permit. The host can exit immediately. Process-scoped `CAPTURE_HEALTH` snapshots are partial and may sample either active or closing workers. They can omit recent completions, disappear on sink failure, or never be produced. Shutdown and restart neither replay pending jobs nor reconcile counters across process instances. Missing observations can reflect disabled capture, unavailable collectors, admission drops, worker failure, process exit, rotation, or reader limits.

In an unwinding build a telemetry worker panic stops its lane, records the panic and worker exit in memory, and leaves accepted work without a reported outcome pending. Future admissions report unavailable. The other lane remains independent. Worker panics are process-fatal in the existing `panic = "abort"` release build. Thread isolation covers sink errors and stalls. Containing a release abort requires moving telemetry processing to a separate process.

Telemetry sink locks and in-process lock registries are separate from the authoritative journals. Authoritative storage retains its existing failure behavior for a shared-volume outage. Capture results have no role in security state transitions.

### Producer lifetimes

| Producer | Lifetime and coverage |
| --- | --- |
| CLI pre- and post-tool hooks | Opt-in hot routing evaluates the hook and captures its observations inside the existing host hook daemon. The CLI starts local workers only for local evaluation. Local fallback is one-shot. |
| CLI pre-compact and safe reads | One process per invocation. Queued work may remain unconfirmed at exit. |
| Shell wrapper and operator baseline | One process per invocation. The last mediator or prerequisite observations can still be pending when it returns. |
| MCP gateway | Client-owned stdio session. The gateway can exit at EOF with queued or in-flight records. |
| Hook daemon and coordinator | Existing idle-bounded host processes. Their own observations can outlive individual requests. |
| Feedback and plugin projections | Follow the host that observed the action. Coordinator-mediated ballots use the coordinator's export lane after the signed journal write. |
| Sandbox and locked worker processes | Telemetry lanes are unavailable. |

The existing host hook socket carries authoritative request-and-reply evaluations. A useful independently owned collector for one-shot routes needs a pre-provisioned bounded one-way transport, authenticated host provenance, validated descriptor frames, and restart coverage. The worker-capable coordinator socket remains scoped to its authority operations. Independent collector transport and release panic isolation belong in a separate follow-up because the present host routes cannot supply those properties. Until that work lands, short-lived routes remain best effort and delivery at exit is unconfirmed.

Payload construction uses allowlisted command shapes, names and metrics before serialization. Treat raw prompts, source, shell strings, arbitrary arguments, environment and output as sensitive input. Secret-derived hashes can be reversible for low-entropy values. Use a bounded reference to a retained authorized artifact when available. Character sanitization serves output hygiene. It cannot establish that emitted data is free of secrets.

## Reader and extraction boundary

Keep envelope decoding independent of the writer. Read complete JSON objects within a fixed byte and record budget. Treat older records without a schema marker as legacy. Skip unsupported versions and event families with a coverage count. For recognized versions, ignore additive fields outside the consumer's schema and preserve unknown states. Interpret chronology within a producer or a direct causal chain. Treat timing buckets as inclusive measurements when intervals overlap.

To extract the contract into a shared Rust component, move the envelope types, producer capability checks and wire-format fixtures together. Keep Dotagent payload constructors and access control at the application boundary. Keep transport and retention behind the emitter implementation. Register each future producer explicitly, assign a new instance per process and preserve source IDs for projections. MCP, sims and envctl examples under `crates/agent-guard/tests/fixtures/telemetry/` are schema fixtures. A future assessment producer uses its own identity and references immutable captured records.

### Operator diagnostics

From the repository directory, an authorized operator can run `dotagent telemetry baseline` to record individual observations for `HEAD`, local `main`, cached `origin/main` and working-tree status. Add `--include-review-fixes` to check cached `origin/v2-1-review-fixes` before status. The fixed checks run through the existing sandbox mediator with kernel enforcement required, network denied and read-only access. Status includes changes to recorded submodule commits while ignoring nested submodule dirtiness. The baseline exit status reflects the prerequisite checks. Each check also reports `capture_queued` or `capture_dropped`. Queue admission supplies correlation IDs while persistence is pending. Each check has one 10-second monotonic deadline for output collection and the mediator wait. On a timeout, the host attempts to stop the outer mediator process group and records whether it reaped the direct child. Nested execution remains unavailable on this route. Remote freshness is outside this route. Operator signature requirements apply when configured.

Use `dotagent telemetry trace` for aggregated observations from the beginning of the active file, up to 8 MiB or 4,096 records. Archives are outside this query window. `dotagent telemetry trace --trace-id ID` adds up to 256 rows from a trace and its connected observations. The report includes control settings, interventions, outcomes where linked, truncation and continuation, detector dispositions, storage health and explicit coverage counters. It includes up to 128 latest process-scoped runtime snapshots from the retained window, with explicit omitted or invalid snapshot counts. It limits each grouping to 128 keys with overflow counts. A missing or unreadable active file produces an unavailable result. A launch without its observed finish is incomplete in the queried window. Missing predecessor events can reflect earlier rotation. The writer-wait aggregate reports the observed sample count and total microseconds, with a null total when no sample is present. Event durations are reported separately and can overlap.

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

### Historical standalone Thread B verification

These checks used the provisional base `3eb6ce4`. The current verification commands and results are in the integration section below. Repository format, Clippy and compiler gates are listed in `.github/workflows/ci.yml`.

| Verification | Observed status |
| --- | --- |
| `cargo fetch --locked` | Passed with Cargo 1.88.0. |
| `cargo metadata --offline --locked --format-version=1` | Passed. The 81 resolved packages declare no Rust version above 1.88. |
| `cargo fmt --all -- --check` and `git diff --check` | Passed. |
| `cargo check --workspace --all-targets --offline --locked` | Passed with Rust 1.88.0 using isolated build and test-state directories. |
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

### Phase 0 integration verification

| Check | Result |
| --- | --- |
| Formatting and diff validation | Passed. |
| Strict workspace Clippy | Passed on Rust 1.100.0, the CI stable channel. The audit counters retain saturating behavior on the Rust 1.88.0 MSRV. |
| Workspace check and build, offline and locked | Passed on Rust 1.88.0. |
| Workspace test compilation, offline and locked | All 26 Cargo test executables compiled. Full behavioral execution was outside this run. |
| `cargo test -p agent-guard --lib --offline --locked telemetry::` | 35 passed. One append-latency fixture is ignored by default. Its separate run is recorded in the historical verification above. |
| `cargo test -p agent-guard --lib --offline --locked sanitizer::tests::byte_compaction_counts_only_removed_source_bytes` | One regression passed. It checks byte accounting for cuts before, within, and after the line-compaction marker. |
| Focused security tests | Checkpoint session identity, isolated scratch preparation and webfont file handling passed. |
| Compiler verification | All 58 artifacts matched. |
| Gemini/Antigravity adapter replay | One scenario and all 10 steps passed against the combined binaries. |
| Native Antigravity | Unverified. The workspace has no connected authenticated runtime. |

Release promotion and hardware signer rotation remain blocked pending independent verification of the existing [release signing requirements](RELEASE_SIGNING.md).

## Nonblocking verification

### Initial implementation at `650205b`

The runtime tests hold a telemetry writer behind a barrier while queue admission, a production PostToolUse decision and shutdown return. Other fixtures hold the real audit-file lock, hold the queue admission mutex, fill the queue, provide an invalid audit destination, and start the hook without a collector. The independent export lane can stall while audit jobs complete. The audit worker counts both injected `EIO` and a Linux `ENOSPC` write to `/dev/full`, then completes another job. A live MCP fixture verifies a successful JSON-RPC ballot result and delivery to the AgentPI mirror. The disk fixture isolates the telemetry write. A failure on a volume that also hosts authoritative state remains subject to the security journals' existing rules.

The telemetry suite passed 45 tests, with three opt-in benchmarks. The FIFO isolation test, MCP fixtures, checkpoint identity and scratch fixtures, webfont fixture, workspace compilation, strict workspace Clippy, and all 58 compiler artifact checks passed. Workspace test compilation covered all 26 test executables. The behavioral run covered the focused suites listed here.

Run the release benchmark on Linux.

```sh
cargo test -p agent-guard --release --lib --offline --locked \
  telemetry::runtime::tests::measures_ -- --test-threads=1 --ignored --nocapture
```

The policy benchmark runs with a no-op sink and drains the enabled lane between batches outside the timed region. The PostToolUse benchmark runs the production hook in separate processes, alternates the order of enabled and disabled modes, discards warmup observations and excludes process startup. The full-queue measurements hold the worker until sampling ends. Admission includes the job wrapper and single try-lock attempt. Wall-clock measurements depend on the host and scheduler.

Linux x86-64 release measurements used Rust 1.100.0 and 2,048 samples per row. Both enabled hook runs persisted every queued observation, including warmup.

| Measurement | p50 | p95 | p99 | Maximum observed |
| --- | ---: | ---: | ---: | ---: |
| Guard policy, telemetry disabled | 451 ns | 541 ns | 1,422 ns | 84,868 ns |
| Guard policy, telemetry enabled | 581 ns | 671 ns | 1,882 ns | 50,255 ns |
| Guard policy, queue full | 471 ns | 641 ns | 1,883 ns | 43,826 ns |
| Successful admission alone | 30 ns | 40 ns | 80 ns | 311 ns |
| Full-queue drop alone | 30 ns | 31 ns | 60 ns | 311 ns |
| PostToolUse, telemetry disabled | 166.940 µs | 265.799 µs | 318.568 µs | 1,065.199 µs |
| PostToolUse, telemetry enabled | 183.035 µs | 278.298 µs | 362.354 µs | 1,350.057 µs |
| Difference between PostToolUse quantiles | +16.095 µs | +12.499 µs | +43.786 µs | — |

### PR #23 remediation

Three causes drove the remediation. Process-owned queues share the lifetime of their producer, so local hooks could exit after admission and before persistence. The emitter previously built and serialized the complete envelope before the queue had a slot, and assigned event sequence before concurrent admission order was known. A worker that unwound could leave its lane marked running, and health snapshots did not express the unknown outcomes at process exit.

| File under `crates/agent-guard/src` | Changed behavior |
| --- | --- |
| `telemetry/capture.rs` | `guard_context`, `record_guard`, `emit`, `EventDescriptor::new`, `EventDescriptor::encode`, and the shared `encode` path separate bounded capture from wire encoding and preserve source identity. |
| `telemetry/runtime.rs` | `Lane::try_admit`, `Lane::submit_with`, `submit_event`, `submit_audit_task` and `submit_export` defer owned snapshot creation until admission. `worker_entry` and `run_worker` expose lane termination and keep queue operations off sink locks. |
| `telemetry/runtime_health.rs` | `publish` and `read` add partial delivery accounting with legacy snapshot compatibility. |
| `cli.rs`, `telemetry/observations.rs` | `run_cli_entrypoint` and `eval_hook_preferring_hot_coord` start local workers only for local pre/post evaluation. `ShellMediatorObservation::new` checks available capture before constructing wrapper context. |
| `traversal_ledger.rs`, `feedback.rs` | `append_audit_jsonl`, `record_guard_denial_agentpi_signal`, and the mirror portion of `commit_ballot_on_host_redacted` defer optional copies until admission. |
| `feedback_loop.rs`, `plugin_lattice.rs` | `run_worktree_adversarial_copilot_and_merge` and `apply_pre_tool_plugin_lattice` defer constructing their optional export jobs until admission. |
| `telemetry/runtime_tests.rs` | Adds process exit and restart, concurrent correlation, independent lane panic, full-queue factory, shutdown accounting, and authority isolation fixtures. The production hook test compares both allow and deny outcomes across failure conditions. |

On Linux, 53 focused telemetry tests passed with three benchmarks ignored by default. The tests exercised a real held audit lock, rejection of a file with unsafe permissions, injected `EIO`, and a Linux `/dev/full` write returning `ENOSPC`. A subprocess exited with a pending record and the next process started fresh and wrote its own event. Two stalled telemetry lanes left a halted session journal persisted and an authoritative write failure still returned `STATE_WRITE_ERROR`. Signed ballot append and error propagation precede the optional mirror admission. Checkpoint, receipt and supervisor implementations remain separate from capture.

The optimized benchmark used Rust 1.100.0 on Linux x86-64 with an AMD EPYC 9V74 and five visible CPUs. Each row has 2,048 measured PostToolUse invocations, with two processes per mode and 64 warmup invocations per process. The second round reverses the mode order. The timed interval includes the production hook and excludes process startup. Disabled and unavailable both run without lanes, reached through explicit disablement and absence of runtime startup, respectively. The saturated case holds the worker and fills all slots before measurement. Both enabled processes persisted all their admitted observations after warmup and measurement.

| PostToolUse mode | p50 (us) | p95 (us) | p99 (us) | Maximum (us) |
| --- | ---: | ---: | ---: | ---: |
| Disabled | 168.613 | 254.712 | 362.303 | 1,985.549 |
| Enabled | 199.519 | 328.312 | 438.057 | 1,384.156 |
| Saturated | 177.417 | 277.707 | 368.733 | 725.439 |
| Unavailable | 172.228 | 298.548 | 693.400 | 2,078.779 |

The initial enabled run measured 183.035, 278.298 and 362.354 us at p50, p95 and p99. The remediation's enabled quantiles were higher in this run. Its disabled p99 also increased. These runs differ in mode ordering and reflect scheduler and filesystem variation. They establish the observed distribution under each fixture and leave performance improvement unverified. The fixture tests supply the evidence for sink independence.
