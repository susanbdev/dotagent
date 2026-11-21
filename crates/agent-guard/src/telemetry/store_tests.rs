use super::*;
use std::collections::BTreeSet;
use std::process::{Command, Stdio};

fn record(value: u64) -> JsonValue {
    JsonValue::Object(vec![("fixture".into(), JsonValue::Uint(value))])
}

#[test]
fn rejects_oversized_and_duplicate_key_frames() {
    let huge = JsonValue::Object(vec![(
        "text".into(),
        JsonValue::Str("s".repeat(MAX_RECORD_BYTES)),
    )]);
    assert_eq!(encode(&huge), Err(CaptureError::InvalidRecord));
    let duplicate = JsonValue::Object(vec![
        ("fixture".into(), JsonValue::Uint(1)),
        ("fixture".into(), JsonValue::Uint(2)),
    ]);
    assert_eq!(encode(&duplicate), Err(CaptureError::InvalidRecord));
    assert_eq!(encode(&record(47)).expect("encode"), b"{\"fixture\":47}\n");
}

#[test]
fn writer_wait_is_stored_only_on_versioned_records_with_timing() {
    let typed = JsonValue::Object(vec![
        ("schema_version".into(), JsonValue::Uint(1)),
        ("timing".into(), JsonValue::Object(Vec::new())),
    ]);
    let frame = encode_with_writer_wait(&typed, 47).expect("encode writer measurement");
    let read =
        JsonValue::parse(std::str::from_utf8(&frame).expect("ASCII frame")).expect("read frame");
    assert_eq!(
        read.get("timing")
            .and_then(|timing| timing.get("writer_wait_us"))
            .and_then(JsonValue::as_u64),
        Some(47),
    );
    assert_eq!(
        encode_with_writer_wait(&record(47), 49).expect("encode legacy fixture"),
        encode(&record(47)).expect("unmodified legacy frame"),
    );
}

struct TestState(PathBuf);

impl TestState {
    fn new(label: &str) -> Self {
        let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace = crate_root.ancestors().nth(2).expect("workspace directory");
        let state = workspace
            .join("target/test-workspaces")
            .join(format!("telemetry-{label}-{}", std::process::id()));
        fs::create_dir_all(&state).expect("test state directory");
        Self(state)
    }

    fn worker(&self, mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .args(["--exact", "telemetry::store::tests::process_worker"])
            .env("AGENT_GUARD_STATE_DIR", &self.0)
            .env("DOTAGENT_STORE_TEST_CASE", mode)
            .stdout(Stdio::null());
        command
    }

    fn active(&self) -> PathBuf {
        self.0.join("audit.jsonl")
    }
}

impl Drop for TestState {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn read_records(path: &Path) -> Vec<JsonValue> {
    let raw = fs::read_to_string(path).expect("read fixture frames");
    assert!(raw.is_empty() || raw.ends_with('\n'));
    raw.lines()
        .map(|line| JsonValue::parse(line).expect("complete JSON object"))
        .collect()
}

#[test]
fn processes_serialize_complete_appends() {
    let state = TestState::new("concurrent");
    let mut children: Vec<_> = (0..4)
        .map(|worker| {
            state
                .worker(&worker.to_string())
                .spawn()
                .expect("spawn audit writer")
        })
        .collect();
    for child in &mut children {
        assert!(child.wait().expect("wait for audit writer").success());
    }
    let records = read_records(&state.active());
    assert_eq!(records.len(), 80);
    let seen: BTreeSet<_> = records
        .iter()
        .filter_map(|entry| entry.get("fixture").and_then(JsonValue::as_u64))
        .collect();
    assert_eq!(seen, (0..80).collect());
}

#[test]
fn restart_quarantines_torn_tail_before_append() {
    let state = TestState::new("torn");
    let path = state.active();
    let mut file = create(&path).expect("open fixture");
    file.write_all(&encode(&record(97)).expect("encode"))
        .expect("write complete frame");
    let unfinished = b"{\"fixture\":99}";
    file.write_all(unfinished).expect("simulate torn frame");
    drop(file);

    assert!(
        state
            .worker("repair")
            .status()
            .expect("restart writer")
            .success()
    );
    assert_eq!(
        fs::read(suffix_path(&path, ".torn")).expect("quarantine"),
        unfinished
    );
    let records = read_records(&path);
    assert_eq!(records.len(), 3);
    assert_eq!(records[0], record(97));
    assert!(records[1].get("event_type").is_some());
    assert_eq!(records[2], record(98));
}

#[test]
fn restart_finishes_pending_quarantine_after_active_tail_was_removed() {
    let state = TestState::new("pending");
    let path = state.active();
    let unfinished = b"{\"fixture\":";
    let mut pending =
        create(&suffix_path(&path, ".torn.pending")).expect("open quarantine fixture");
    pending.write_all(unfinished).expect("write pending tail");
    drop(pending);

    assert!(
        state
            .worker("repair")
            .status()
            .expect("restart writer")
            .success()
    );
    let records = read_records(&path);
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[0]
            .get("payload")
            .and_then(|value| value.get("torn_bytes"))
            .and_then(JsonValue::as_u64),
        Some(unfinished.len() as u64),
    );
    assert_eq!(records[1], record(98));
    assert_eq!(
        fs::read(suffix_path(&path, ".torn")).expect("quarantine"),
        unfinished
    );
    assert!(!suffix_path(&path, ".torn.pending").exists());
}

#[test]
fn rotation_enforces_retention_and_records_eviction() {
    let state = TestState::new("retention");
    assert!(
        state
            .worker("rotate")
            .status()
            .expect("rotate fixture")
            .success()
    );
    let path = state.active();
    let active = read_records(&path);
    assert_eq!(active.len(), 1);
    assert!(active[0].get("event_type").is_some());
    assert_eq!(read_records(&archive_path(&path, 1)), vec![record(2)]);
    assert!(!archive_path(&path, 2).exists());
}

#[test]
fn writer_failure_is_returned_and_next_append_records_gap() {
    let state = TestState::new("failure");
    fs::create_dir(state.active()).expect("block audit destination");
    assert!(
        state
            .worker("failure")
            .status()
            .expect("run writer")
            .success()
    );
    let active = read_records(&state.active());
    assert_eq!(active.len(), 2);
    assert!(active[0].get("event_type").is_some());
    assert_eq!(active[1], record(98));
}

#[test]
fn legacy_denial_lookup_excludes_rotated_and_typed_observations() {
    let state = TestState::new("legacy");
    assert!(
        state
            .worker("legacy")
            .status()
            .expect("exercise legacy reader")
            .success()
    );
    let archived = read_records(&archive_path(&state.active(), 1));
    assert_eq!(archived.len(), 1);
    assert_eq!(
        archived[0].get("detail").and_then(JsonValue::as_str),
        Some("[redacted]")
    );
}

#[test]
fn post_tool_hook_records_counts_without_retaining_output() {
    let state = TestState::new("post-tool");
    let repo = TestState::new("post-tool-repo");
    fs::create_dir(repo.0.join(".git")).expect("fixture repository marker");
    assert!(
        state
            .worker("post-tool")
            .env("DOTAGENT_STORE_TEST_REPO", &repo.0)
            .status()
            .expect("invoke fixture host hook")
            .success()
    );
    let active = state.active();
    let records = read_records(&active);
    let usage = records
        .iter()
        .find(|entry| {
            entry.get("event_type").and_then(JsonValue::as_str) == Some("USAGE_AND_DISPOSITION")
        })
        .expect("hook usage record");
    let payload = usage.get("payload").expect("typed payload");
    assert_eq!(
        payload.get("requested_bytes").and_then(JsonValue::as_u64),
        Some("ordinary fixture output".len() as u64)
    );
    assert!(payload.get("emitted_bytes").is_none());
    assert!(
        !fs::read_to_string(active)
            .expect("fixture audit")
            .contains("ordinary fixture output")
    );
}

#[test]
#[ignore = "reports local append latency without portable timing assertions"]
fn measures_isolated_append_latency() {
    let state = TestState::new("latency");
    assert!(
        state
            .worker("benchmark")
            .arg("--nocapture")
            .stdout(Stdio::inherit())
            .status()
            .expect("run isolated latency fixture")
            .success()
    );
}

fn report_append_latency(path: &Path) {
    const ITERATIONS: usize = 192;
    let fixture = r#"{
        "schema_version": 1,
        "event_id": "fixture-event-000",
        "event_type": "CONTROL_DECISION",
        "producer": {"component": "agent-guard.hook", "instance_id": "fixture-host", "sequence": 1},
        "timing": {"clock": "system_wall_and_process_monotonic", "duration_ns": 10000},
        "correlation": {"trace_id": "fixture-trace-000", "intervention_id": "fixture-intervention-000"},
        "work": {"repo_id": "fixture-repo", "session_id": "fixture-session-000"},
        "configuration": {"profile_id": "balanced"},
        "trust": {"origin": "trusted_guard", "authentication": "local_host_callsite", "evidence": "observed_action", "verification": "observed"},
        "result": {"action": "truncate", "reason_code": "FIXTURE_LIMIT", "disposition": "applied", "completeness": "complete"},
        "payload": {"requested_lines": 400, "granted_lines": 150, "emitted_lines": 150, "continuation_available": true}
    }"#;
    let template = JsonValue::parse(fixture).expect("parse representative record");
    println!(
        "isolated writer fixture on {}/{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    for (mode, durability) in [
        ("buffered", Durability::Buffered),
        ("required", Durability::Required),
    ] {
        let before = fs::metadata(path).map_or(0, |meta| meta.len());
        let mut latencies = Vec::with_capacity(ITERATIONS);
        let mut encoded_bytes = 0;
        for sequence in 0..ITERATIONS {
            let mut record = template.clone();
            let JsonValue::Object(fields) = &mut record else {
                unreachable!("fixture is an object")
            };
            fields[1].1 = JsonValue::Str(format!("fixture-{mode}-{sequence:03}"));
            let start = Instant::now();
            let receipt = append(&record, durability).expect("persist latency fixture frame");
            latencies.push(start.elapsed().as_nanos());
            encoded_bytes += receipt.bytes as u64;
        }
        let growth = fs::metadata(path).expect("fixture log metadata").len() - before;
        assert_eq!(growth, encoded_bytes);
        latencies.sort_unstable();
        let median = latencies[ITERATIONS.div_ceil(2) - 1];
        let p95 = latencies[(95 * ITERATIONS).div_ceil(100) - 1];
        println!("{mode}: n={ITERATIONS}, median={median} ns, p95={p95} ns, growth={growth} bytes");
    }
}

#[test]
fn process_worker() {
    let Ok(mode) = std::env::var("DOTAGENT_STORE_TEST_CASE") else {
        return;
    };
    let fixture_state = std::env::var_os("AGENT_GUARD_STATE_DIR").expect("fixture state override");
    let path = audit_log_path();
    assert_eq!(path, PathBuf::from(fixture_state).join("audit.jsonl"));
    match mode.as_str() {
        "benchmark" => report_append_latency(&path),
        "post-tool" => {
            let repo = std::env::var_os("DOTAGENT_STORE_TEST_REPO").expect("synthetic repo");
            let decision = crate::handle_post_tool_hook(
                r#"{"tool_name":"Read","tool_response":"ordinary fixture output"}"#,
                Path::new(&repo),
            );
            assert!(decision.is_allow(), "{decision:?}");
        }

        "repair" => {
            let receipt = append(&record(98), Durability::Required).expect("repair and append");
            assert!(receipt.durable);
        }
        "rotate" => {
            append(&record(1), Durability::Buffered).expect("append 1");
            assert!(rotate_at(&path, 1, 1).expect("first rotation"));
            append(&record(2), Durability::Buffered).expect("append 2");
            assert!(rotate_at(&path, 1, 1).expect("rotate with eviction"));
        }
        "failure" => {
            assert_eq!(
                append(&record(97), Durability::Required),
                Err(CaptureError::InvalidState)
            );
            fs::remove_dir(path).expect("unblock fixture destination");
            append(&record(98), Durability::Required).expect("recover audit writer");
        }
        "legacy" => {
            use crate::traversal_ledger::{
                append_audit_jsonl, audit_log_has_session_denial, compute_session_key_hash,
            };

            let repo = Path::new("/repository-fixture");
            let session = "session-fixture";
            let code = "FIXTURE_DENY";
            append_audit_jsonl(
                repo,
                session,
                "Bash",
                code,
                "unstructured fixture detail",
                false,
            );
            assert!(audit_log_has_session_denial(repo, session, code));
            assert!(rotate_at(&path, 1, 1).expect("archive legacy record"));
            assert!(!audit_log_has_session_denial(repo, session, code));

            let hash = compute_session_key_hash(repo, session);
            let typed = JsonValue::Object(vec![
                ("schema_version".into(), JsonValue::Uint(1)),
                (
                    "event_type".into(),
                    JsonValue::Str("CONTROL_DECISION".into()),
                ),
                (
                    "session_hash".into(),
                    JsonValue::Str(hash[..16].to_string()),
                ),
                ("code".into(), JsonValue::Str("OBSERVATION_FIXTURE".into())),
            ]);
            append(&typed, Durability::Buffered).expect("store typed observation fixture");
            assert!(!audit_log_has_session_denial(
                repo,
                session,
                "OBSERVATION_FIXTURE"
            ));
        }
        worker => {
            let start = worker.parse::<u64>().expect("fixture worker index") * 20;
            for value in start..start + 20 {
                append(&record(value), Durability::Buffered).expect("serialize frame");
            }
        }
    }
}
