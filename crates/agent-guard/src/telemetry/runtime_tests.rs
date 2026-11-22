use std::fs;
use std::hint::black_box;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
#[cfg(panic = "unwind")]
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::{AUDIT_OFFLINE, DropReason, GLOBAL, Lane, Runtime, Submission, start_global};
use crate::breadcrumbs::ExclusiveFileLockGuard;
use crate::json::JsonValue;
use crate::telemetry::store::{self, Durability};
use crate::traversal_ledger::audit_log_path;

const WATCHDOG: Duration = Duration::from_secs(5);

fn deadline() -> Instant {
    Instant::now() + WATCHDOG
}

// The tests arrange the desired lane state before asserting a single-shot drop.
// Setup jobs may race an idle worker's mutex, so retry only setup on contention.
fn enqueue(lane: &Lane, job: impl FnOnce() -> bool + Send + 'static) {
    let job = Arc::new(Mutex::new(Some(job)));
    let deadline = deadline();
    loop {
        let pending = Arc::clone(&job);
        match lane.submit(move || pending.lock().unwrap().take().unwrap()()) {
            Submission::Queued => return,
            Submission::Dropped(DropReason::Contended) if Instant::now() < deadline => {
                thread::yield_now();
            }
            _ => panic!("could not enqueue fixture job"),
        }
    }
}

fn stall(lane: &Lane) -> Sender<()> {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    enqueue(lane, move || {
        started_tx.send(()).is_ok() && release_rx.recv_timeout(WATCHDOG * 2).is_ok()
    });
    started_rx
        .recv_timeout(WATCHDOG)
        .expect("fixture writer reached the gate");
    release_tx
}

#[test]
fn saturated_audit_lane_drops_without_waiting_for_its_writer() {
    let runtime = Runtime::new(1);
    let release = stall(&runtime.audit);
    enqueue(&runtime.audit, || true);

    thread::scope(|scope| {
        let (sent, received) = mpsc::channel();
        let audit = &runtime.audit;
        scope.spawn(move || sent.send(audit.submit(|| true)).unwrap());
        let disposition = received.recv_timeout(WATCHDOG);
        let while_stalled = audit.snapshot();
        release.send(()).expect("release audit writer");

        assert!(matches!(
            disposition,
            Ok(Submission::Dropped(DropReason::Full))
        ));
        assert_eq!(while_stalled.queued, 2);
        assert_eq!(while_stalled.persisted, 0);
        assert_eq!(while_stalled.full, 1);
    });
    assert!(runtime.wait_idle(deadline()));
    assert_eq!(runtime.audit.snapshot().persisted, 2);
}

#[test]
fn admission_mutex_contention_is_counted_without_waiting() {
    let runtime = Runtime::new(1);
    let audit = &runtime.audit;
    let held = audit.state.jobs.lock().unwrap();

    thread::scope(|scope| {
        let (sent, received) = mpsc::channel();
        scope.spawn(move || sent.send(audit.submit(|| true)).unwrap());
        let disposition = received.recv_timeout(WATCHDOG);
        drop(held);
        assert!(matches!(
            disposition,
            Ok(Submission::Dropped(DropReason::Contended))
        ));
    });
    let counts = audit.snapshot();
    assert_eq!(counts.queued, 0);
    assert_eq!(counts.contended, 1);
}

#[test]
fn collector_absence_is_reported_without_running_a_job() {
    let lane = Lane::new(1);
    let (ran, observed) = mpsc::channel();
    assert!(matches!(
        lane.submit(move || ran.send(()).is_ok()),
        Submission::Dropped(DropReason::Unavailable)
    ));
    assert!(observed.try_recv().is_err());
    let counts = lane.snapshot();
    assert_eq!(counts.queued, 0);
    assert_eq!(counts.unavailable, 1);
}

#[test]
fn stalled_export_lane_does_not_prevent_audit_progress() {
    let runtime = Runtime::new(1);
    let release = stall(&runtime.export);
    enqueue(&runtime.export, || true);
    let (written, observed) = mpsc::channel();
    enqueue(&runtime.audit, move || written.send(()).is_ok());
    let audit_progress = observed.recv_timeout(WATCHDOG);
    let export_progress = runtime.export.snapshot().persisted;
    release.send(()).expect("release export worker");

    assert!(audit_progress.is_ok());
    assert_eq!(export_progress, 0);
    assert!(runtime.wait_idle(deadline()));
    assert_eq!(runtime.audit.snapshot().persisted, 1);
    assert_eq!(runtime.export.snapshot().persisted, 2);
}

#[test]
fn a_full_lane_drops_without_creating_an_owned_snapshot() {
    let runtime = Runtime::new(1);
    let release = stall(&runtime.audit);
    enqueue(&runtime.audit, || true);
    let mut prepared = false;
    let receipt = runtime.audit.submit_with(|| {
        prepared = true;
        || true
    });
    release.send(()).unwrap();
    assert_eq!(receipt, Submission::Dropped(DropReason::Full));
    assert!(!prepared);
    assert_eq!(runtime.audit.snapshot().full, 1);
    assert!(runtime.wait_idle(deadline()));
}

#[test]
fn closing_is_nonblocking_and_drains_accepted_work() {
    let runtime = Runtime::new(1);
    let release = stall(&runtime.audit);
    enqueue(&runtime.audit, || true);

    thread::scope(|scope| {
        let (sent, received) = mpsc::channel();
        let runtime = &runtime;
        scope.spawn(move || {
            runtime.close();
            let late = runtime.audit.submit(|| true);
            sent.send((late, runtime.wait_stopped(Instant::now())))
                .unwrap();
        });
        let closed = received.recv_timeout(WATCHDOG);
        release
            .send(())
            .expect("release writer after shutdown request");
        assert!(matches!(
            closed,
            Ok((Submission::Dropped(DropReason::Closed), false))
        ));
    });
    assert!(runtime.wait_stopped(deadline()));
    let counts = runtime.audit.snapshot();
    assert_eq!(counts.queued, 2);
    assert_eq!(counts.persisted, 2);
    assert_eq!(counts.closed, 1);
}

#[cfg(panic = "unwind")]
#[test]
fn worker_panic_closes_only_its_lane_and_preserves_pending_accounting() {
    for fail_audit in [true, false] {
        let runtime = Runtime::new(2);
        let (failed, healthy) = if fail_audit {
            (&runtime.audit, &runtime.export)
        } else {
            (&runtime.export, &runtime.audit)
        };
        let (started, ready) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        enqueue(failed, move || {
            started.send(()).unwrap();
            gate.recv_timeout(WATCHDOG).unwrap();
            panic!("intentional writer fixture panic");
        });
        ready.recv_timeout(WATCHDOG).unwrap();
        enqueue(failed, || true);
        release.send(()).unwrap();

        assert!(super::wait_until(deadline(), || {
            !failed.state.running.load(Ordering::Acquire)
        }));
        let counts = failed.snapshot();
        assert_eq!(counts.queued, 2);
        assert_eq!(counts.persisted, 0);
        assert_eq!(counts.worker_panics, 1);
        assert_eq!(counts.worker_exits, 1);
        assert!(counts.pending() >= 1);
        assert!(matches!(
            failed.submit(|| true),
            Submission::Dropped(DropReason::Unavailable)
        ));
        assert_eq!(failed.snapshot().unavailable, 1);

        let (finished, result) = mpsc::channel();
        enqueue(healthy, move || finished.send(()).is_ok());
        result
            .recv_timeout(WATCHDOG)
            .expect("other lane stays live");
        runtime.close();
        assert!(runtime.wait_stopped(deadline()));
        assert_eq!(healthy.snapshot().persisted, 1);
    }
}

#[cfg(unix)]
#[test]
fn injected_io_failure_and_disk_exhaustion_do_not_end_the_collector() {
    use std::io;

    let runtime = Runtime::new(3);
    enqueue(&runtime.audit, || {
        Err::<(), _>(io::Error::from_raw_os_error(5)).is_ok()
    });
    let (observed, result) = mpsc::channel();
    enqueue(&runtime.audit, move || {
        let write = disk_exhaustion_fixture();
        observed
            .send(write.as_ref().err().and_then(io::Error::raw_os_error))
            .unwrap();
        write.is_ok()
    });
    enqueue(&runtime.audit, || true);

    assert!(runtime.wait_idle(deadline()));
    assert_eq!(result.recv_timeout(WATCHDOG).unwrap(), Some(28));
    let counts = runtime.audit.snapshot();
    assert_eq!(counts.queued, 3);
    assert_eq!(counts.failed, 2);
    assert_eq!(counts.persisted, 1);
}

#[cfg(target_os = "linux")]
fn disk_exhaustion_fixture() -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};

    // Linux's zero-capacity character device returns ENOSPC without using disk.
    let mut full = fs::OpenOptions::new()
        .write(true)
        .custom_flags(crate::traversal_ledger::O_NOFOLLOW_FLAG)
        .open("/dev/full")?;
    let metadata = full.metadata()?;
    if !metadata.file_type().is_char_device() || metadata.rdev() != 0x107 {
        return Err(std::io::Error::other(
            "expected the Linux /dev/full character device",
        ));
    }
    full.write_all(b"x")
}

#[cfg(all(unix, not(target_os = "linux")))]
fn disk_exhaustion_fixture() -> std::io::Result<()> {
    Err(std::io::Error::from_raw_os_error(28))
}

struct IsolatedState(PathBuf);

impl IsolatedState {
    fn new(label: &str) -> Self {
        let path = workspace_root()
            .join("target/test-workspaces")
            .join(format!("telemetry-runtime-{label}-{}", std::process::id()));
        fs::create_dir_all(&path).expect("create isolated telemetry fixture state");
        Self(path)
    }

    fn worker(&self, mode: &str) -> Command {
        let state = self.0.join("state");
        let repo = self.0.join("repo");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(repo.join(".git")).unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "telemetry::runtime::tests::isolated_audit_worker",
            ])
            .env("AGENT_GUARD_STATE_DIR", state)
            .env("DOTAGENT_RUNTIME_TEST_MODE", mode)
            .env("DOTAGENT_RUNTIME_TEST_REPO", repo)
            .env_remove("AGENT_GUARD_SESSION_ID")
            .env_remove("DOTAGENT_TELEMETRY")
            .stdin(Stdio::null());
        command
    }
}

impl Drop for IsolatedState {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
}

fn fixture_record() -> JsonValue {
    JsonValue::Object(vec![("runtime_fixture".into(), JsonValue::Bool(true))])
}

#[test]
fn actual_audit_lock_contention_is_confined_to_the_writer() {
    let state = IsolatedState::new("lock");
    let result = state
        .worker("store-lock")
        .status()
        .expect("run isolated audit fixture");
    assert!(result.success());
}

#[test]
fn short_lived_producer_can_exit_with_pending_work_and_restart_without_replay() {
    let state = IsolatedState::new("short-exit");
    assert!(state.worker("exit-pending").status().unwrap().success());
    let active = state.0.join("state/audit.jsonl");
    assert!(store::open_audit_read(&active).unwrap().is_none());

    assert!(state.worker("restart").status().unwrap().success());
    let records = fixture_records(&active);
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0]
            .get("result")
            .and_then(|result| result.get("reason_code"))
            .and_then(JsonValue::as_str),
        Some("AFTER_RESTART")
    );
}

#[test]
fn concurrent_producers_preserve_sequence_and_parent_links() {
    let state = IsolatedState::new("ordering");
    assert!(state.worker("ordering").status().unwrap().success());
}

#[test]
fn stalled_observation_lanes_preserve_authoritative_writes_and_failure() {
    let state = IsolatedState::new("authority");
    assert!(state.worker("authority").status().unwrap().success());
}

#[test]
fn post_tool_hook_preserves_allow_and_deny_across_audit_conditions() {
    for mode in [
        "hook-enabled",
        "hook-disabled",
        "hook-full",
        "hook-lock",
        "hook-failure",
        "hook-absent",
    ] {
        let state = IsolatedState::new(mode);
        let mut worker = state.worker(mode);
        if mode == "hook-disabled" {
            worker.env("DOTAGENT_TELEMETRY", "0");
        }
        assert!(
            worker.status().expect("run isolated hook").success(),
            "hook fixture failed in mode {mode}"
        );
    }
}

#[test]
fn isolated_audit_worker() {
    let Ok(mode) = std::env::var("DOTAGENT_RUNTIME_TEST_MODE") else {
        return;
    };
    let expected = PathBuf::from(std::env::var_os("AGENT_GUARD_STATE_DIR").unwrap())
        .canonicalize()
        .unwrap()
        .join("audit.jsonl");
    let path = audit_log_path();
    assert_eq!(path, expected);
    let repo = PathBuf::from(std::env::var_os("DOTAGENT_RUNTIME_TEST_REPO").unwrap());
    match mode.as_str() {
        "store-lock" => exercise_audit_lock(&path),
        "exit-pending" => exit_with_unconfirmed_admission(),
        "restart" => exercise_restart(),
        "ordering" => exercise_ordering(&path),
        "authority" => exercise_authority_independence(&repo),
        "hook-enabled" => {
            assert!(start_global());
            let runtime = GLOBAL.get().unwrap();
            let release = stall(&runtime.audit);
            let decisions = observe_hook_decisions(&repo);
            release.send(()).unwrap();
            assert_hook_decisions(decisions);
            assert!(runtime.wait_idle(deadline()));
            assert!(runtime.audit.snapshot().persisted > 1);
        }
        "hook-disabled" => {
            assert!(!start_global());
            assert_hook_decisions(observe_hook_decisions(&repo));
            assert!(store::open_audit_read(&path).unwrap().is_none());
        }
        "hook-full" => exercise_hook_while_audit_is_full(&repo),
        "hook-lock" => exercise_hook_while_audit_is_locked(&repo, &path),
        "hook-failure" => exercise_hook_with_failed_audit(&repo, &path),
        "hook-absent" => {
            assert!(GLOBAL.get().is_none());
            assert_hook_decisions(observe_hook_decisions(&repo));
            assert!(AUDIT_OFFLINE.snapshot().unavailable > 0);
            assert!(store::open_audit_read(&path).unwrap().is_none());
        }
        "bench-disabled" | "bench-enabled" | "bench-saturated" | "bench-unavailable" => {
            report_hook_benchmark(&repo, &mode);
        }
        _ => panic!("unrecognized telemetry fixture mode"),
    }
}

fn fixture_event(context: &crate::telemetry::capture::Context, reason: &'static str) -> String {
    use crate::telemetry::capture::{Producer, emit, hook_decision};

    let deadline = deadline();
    loop {
        let payload = hook_decision("post_tool_hook", "allow", reason, "observed", None);
        if let Some(event_id) = emit(Producer::Guard, context, payload) {
            return event_id;
        }
        assert!(Instant::now() < deadline, "fixture event was not admitted");
        thread::yield_now();
    }
}

fn exit_with_unconfirmed_admission() -> ! {
    let host = super::start_host();
    let runtime = GLOBAL.get().unwrap();
    let _hold_until_exit = stall(&runtime.audit);
    let _ = fixture_event(
        &crate::telemetry::capture::Context::default(),
        "EXIT_PENDING",
    );
    drop(host);
    let counts = runtime.audit.snapshot();
    assert_eq!(counts.queued, 2);
    assert_eq!(counts.pending(), 2);
    assert_eq!((counts.persisted, counts.failed), (0, 0));
    std::process::exit(0);
}

fn exercise_restart() {
    assert!(start_global());
    let runtime = GLOBAL.get().unwrap();
    assert_eq!(runtime.audit.snapshot().queued, 0);
    let _ = fixture_event(
        &crate::telemetry::capture::Context::default(),
        "AFTER_RESTART",
    );
    assert!(runtime.wait_idle(deadline()));
    let counts = runtime.audit.snapshot();
    assert_eq!((counts.queued, counts.persisted, counts.failed), (1, 1, 0));
    assert_eq!(counts.pending(), 0);
}

fn exercise_authority_independence(repo: &Path) {
    use crate::traversal_ledger::{SessionLedger, session_ledger_path};

    assert!(start_global());
    let runtime = GLOBAL.get().unwrap();
    let release_audit = stall(&runtime.audit);
    let release_export = stall(&runtime.export);
    thread::scope(|scope| {
        let (finished, observed) = mpsc::channel();
        scope.spawn(move || {
            let mut ledger = SessionLedger::new(repo, "telemetry-authority-commit");
            ledger.trip_circuit_breaker("fixture halt".to_owned());
            ledger.save(repo).expect("persist halted security journal");
            let halted = SessionLedger::load_or_create(repo, &ledger.session_id).halted;

            let blocked_path = session_ledger_path(repo, "telemetry-authority-write-failure");
            fs::create_dir_all(&blocked_path).expect("fixture blocks the authoritative file write");
            let denied = matches!(
                crate::handle_user_prompt_hook(
                    r#"{"session_id":"telemetry-authority-write-failure"}"#,
                    repo,
                ),
                crate::Decision::Deny {
                    code: "STATE_WRITE_ERROR",
                    ..
                }
            );
            finished.send((halted, denied)).unwrap();
        });
        let verdicts = observed.recv_timeout(WATCHDOG);
        release_audit.send(()).unwrap();
        release_export.send(()).unwrap();
        assert_eq!(verdicts.unwrap(), (true, true));
    });
}

fn fixture_records(path: &Path) -> Vec<JsonValue> {
    let mut audit = String::new();
    store::open_audit_read(path)
        .unwrap()
        .unwrap()
        .read_to_string(&mut audit)
        .unwrap();
    audit
        .lines()
        .map(|line| JsonValue::parse(line).unwrap())
        .collect()
}

fn exercise_ordering(path: &Path) {
    use crate::telemetry::capture::Context;

    assert!(start_global());
    let runtime = GLOBAL.get().unwrap();
    let release = stall(&runtime.audit);
    const PRODUCERS: usize = 4;
    const EVENTS_PER_PRODUCER: usize = 6;
    let added = thread::scope(|scope| {
        let barrier = Arc::new(Barrier::new(PRODUCERS));
        (0..PRODUCERS)
            .map(|producer| {
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    let trace_id = format!("fixture-producer-{producer}");
                    let mut context = Context {
                        trace_id: Some(trace_id.clone()),
                        ..Context::default()
                    };
                    barrier.wait();
                    let mut ids = Vec::with_capacity(EVENTS_PER_PRODUCER);
                    for _ in 0..EVENTS_PER_PRODUCER {
                        let event_id = fixture_event(&context, "CONCURRENT_ORDERING");
                        context.parent_event_id = Some(event_id.clone());
                        ids.push(event_id);
                    }
                    (trace_id, ids)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|producer| producer.join().unwrap())
            .collect::<Vec<_>>()
    });
    release.send(()).unwrap();
    assert!(runtime.wait_idle(deadline()));
    let records = fixture_records(path);
    assert_eq!(records.len(), PRODUCERS * EVENTS_PER_PRODUCER);
    let sequence = |entry: &JsonValue| {
        entry
            .get("producer")
            .and_then(|producer| producer.get("sequence"))
            .and_then(JsonValue::as_u64)
            .unwrap()
    };
    assert!(
        records
            .windows(2)
            .all(|pair| sequence(&pair[0]) < sequence(&pair[1]))
    );
    for (trace_id, ids) in added {
        let persisted: Vec<_> = records
            .iter()
            .filter(|record| {
                record
                    .get("correlation")
                    .and_then(|correlation| correlation.get("trace_id"))
                    .and_then(JsonValue::as_str)
                    == Some(trace_id.as_str())
            })
            .collect();
        assert_eq!(persisted.len(), ids.len());
        for (index, record) in persisted.into_iter().enumerate() {
            assert_eq!(
                record.get("event_id").and_then(JsonValue::as_str),
                Some(ids[index].as_str())
            );
            assert_eq!(
                record
                    .get("correlation")
                    .and_then(|correlation| correlation.get("parent_event_id"))
                    .and_then(JsonValue::as_str),
                index.checked_sub(1).map(|prior| ids[prior].as_str()),
            );
        }
    }
}

fn exercise_audit_lock(path: &Path) {
    let hold = ExclusiveFileLockGuard::acquire(path).expect("hold the isolated audit lock");
    let runtime = Runtime::new(2);
    let (started, entering_store) = mpsc::channel();
    enqueue(&runtime.audit, move || {
        started.send(()).unwrap();
        store::append(&fixture_record(), Durability::Buffered).is_ok()
    });
    entering_store.recv_timeout(WATCHDOG).unwrap();

    // A second audit decision is admitted while the real file lock is held.
    thread::scope(|scope| {
        let (sent, received) = mpsc::channel();
        let audit = &runtime.audit;
        scope.spawn(move || sent.send(audit.submit(|| true)).unwrap());
        let admitted = received.recv_timeout(WATCHDOG);
        let during = audit.snapshot();
        drop(hold);
        assert!(matches!(admitted, Ok(Submission::Queued)));
        assert_eq!(during.persisted, 0);
        assert_eq!(during.failed, 0);
    });
    assert!(runtime.wait_idle(deadline()));
    assert_eq!(runtime.audit.snapshot().persisted, 2);
    assert!(store::open_audit_read(path).unwrap().is_some());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // Protected audit files must remain private even when the caller can write them.
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
        enqueue(&runtime.audit, || {
            store::append(&fixture_record(), Durability::Buffered).is_ok()
        });
        assert!(runtime.wait_idle(deadline()));
        assert_eq!(runtime.audit.snapshot().failed, 1);
    }

    // An invalid destination exercises the real store's error reporting.
    fs::remove_file(path).unwrap();
    fs::create_dir(path).unwrap();
    enqueue(&runtime.audit, || {
        store::append(&fixture_record(), Durability::Buffered).is_ok()
    });
    assert!(runtime.wait_idle(deadline()));
    assert_eq!(runtime.audit.snapshot().failed, 1 + u64::from(cfg!(unix)));
}

const HOOK_OUTPUT: &str = "ordinary fixture output";

fn observe_hook(repo: &Path) -> crate::Decision {
    crate::handle_post_tool_hook(
        r#"{"tool_name":"Read","tool_response":"ordinary fixture output"}"#,
        repo,
    )
}

fn observe_hook_decisions(repo: &Path) -> (crate::Decision, crate::Decision) {
    let ordinary_but_over_budget = JsonValue::Object(vec![
        ("tool_name".into(), JsonValue::Str("Task".into())),
        (
            "tool_response".into(),
            JsonValue::Str("ordinary detail ".repeat(100)),
        ),
    ]);
    (
        observe_hook(repo),
        crate::handle_post_tool_hook(&ordinary_but_over_budget.to_json_string(), repo),
    )
}

fn assert_hook_decisions((allow, deny): (crate::Decision, crate::Decision)) {
    assert!(allow.is_allow());
    assert!(matches!(
        deny,
        crate::Decision::Deny {
            code: "SUBAGENT_RETURN_BUDGET_EXCEEDED",
            halt_session: false,
            ..
        }
    ));
}

fn exercise_hook_while_audit_is_full(repo: &Path) {
    start_global();
    let runtime = GLOBAL.get().unwrap();
    let release = stall(&runtime.audit);
    for _ in 0..super::QUEUE_CAPACITY {
        enqueue(&runtime.audit, || true);
    }
    thread::scope(|scope| {
        let (returned, decision) = mpsc::channel();
        scope.spawn(move || returned.send(observe_hook_decisions(repo)).unwrap());
        let actual = decision.recv_timeout(WATCHDOG);
        let counts = runtime.audit.snapshot();
        release.send(()).expect("release the stalled writer");
        assert_hook_decisions(actual.expect("hook returned with a full queue"));
        assert!(counts.full > 0);
        assert_eq!(counts.persisted, 0);
    });
    assert!(runtime.wait_idle(deadline()));
}

fn exercise_hook_while_audit_is_locked(repo: &Path, path: &Path) {
    let hold = ExclusiveFileLockGuard::acquire(path).unwrap();
    start_global();
    let runtime = GLOBAL.get().unwrap();
    let (started, entering_store) = mpsc::channel();
    enqueue(&runtime.audit, move || {
        started.send(()).unwrap();
        store::append(&fixture_record(), Durability::Buffered).is_ok()
    });
    entering_store.recv_timeout(WATCHDOG).unwrap();

    thread::scope(|scope| {
        let (returned, decision) = mpsc::channel();
        scope.spawn(move || returned.send(observe_hook_decisions(repo)).unwrap());
        let actual = decision.recv_timeout(WATCHDOG);
        let queued = runtime.audit.snapshot();
        drop(hold);
        assert_hook_decisions(actual.expect("hook returned while audit was locked"));
        assert!(queued.queued > 1);
        assert_eq!((queued.persisted, queued.failed), (0, 0));
    });
    assert!(runtime.wait_idle(deadline()));
    let mut audit = String::new();
    store::open_audit_read(path)
        .unwrap()
        .unwrap()
        .read_to_string(&mut audit)
        .unwrap();
    assert!(!audit.contains(HOOK_OUTPUT));
    assert!(audit.lines().any(|line| {
        JsonValue::parse(line).is_ok_and(|record| {
            record.get("event_type").and_then(JsonValue::as_str) == Some("USAGE_AND_DISPOSITION")
                && record
                    .get("payload")
                    .and_then(|body| body.get("requested_bytes"))
                    .and_then(JsonValue::as_u64)
                    == Some(HOOK_OUTPUT.len() as u64)
        })
    }));
}

fn exercise_hook_with_failed_audit(repo: &Path, path: &Path) {
    fs::create_dir(path).unwrap();
    start_global();
    let runtime = GLOBAL.get().unwrap();
    let release = stall(&runtime.audit);
    let decisions = observe_hook_decisions(repo);
    release.send(()).unwrap();

    assert_hook_decisions(decisions);
    assert!(runtime.wait_idle(deadline()));
    assert!(runtime.audit.snapshot().failed > 0);
}

fn percentile(sorted: &[i128], rank: usize) -> i128 {
    sorted[(rank * sorted.len()).div_ceil(100) - 1]
}

fn summarize(label: &str, samples: &mut [i128]) {
    samples.sort_unstable();
    println!(
        "{label}: n={}, p50={}ns, p95={}ns, p99={}ns, max={}ns",
        samples.len(),
        percentile(samples, 50),
        percentile(samples, 95),
        percentile(samples, 99),
        samples.last().unwrap(),
    );
}

const HOOK_BENCH_WARMUP: usize = 64;
const HOOK_BENCH_SAMPLES: usize = 1024;
const HOOK_BENCH_DATA_PREFIX: &str = "hook_samples_ns=";

#[test]
#[ignore = "reports process-isolated post-tool hook latency without portable timing assertions"]
fn measures_post_tool_hook_overhead() {
    let configurations = [
        ("bench-disabled", "0"),
        ("bench-enabled", "1"),
        ("bench-saturated", "1"),
        ("bench-unavailable", "1"),
    ];
    let mut elapsed = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    println!(
        "{} {}, debug_assertions={}, {} warmup calls per process",
        std::env::consts::OS,
        std::env::consts::ARCH,
        cfg!(debug_assertions),
        HOOK_BENCH_WARMUP,
    );
    for round in 0..2 {
        for step in 0..configurations.len() {
            let mode = if round == 0 {
                step
            } else {
                configurations.len() - step - 1
            };
            let (label, setting) = configurations[mode];
            let fixture = IsolatedState::new(&format!("{label}-{round}"));
            let child = fixture
                .worker(label)
                .env("DOTAGENT_TELEMETRY", setting)
                .arg("--nocapture")
                .output()
                .expect("run isolated hook benchmark");
            assert!(child.status.success(), "{label} benchmark child failed");
            let report = String::from_utf8(child.stdout).expect("ASCII fixture report");
            let samples = report
                .lines()
                .find_map(|line| line.strip_prefix(HOOK_BENCH_DATA_PREFIX))
                .expect("fixture sample line");
            let batch: Vec<i128> = samples
                .split(',')
                .map(|latency| latency.parse().expect("numeric fixture latency"))
                .collect();
            assert_eq!(batch.len(), HOOK_BENCH_SAMPLES);
            elapsed[mode].extend(batch);
            for row in report
                .lines()
                .filter(|line| line.starts_with("hook_writer="))
            {
                println!("{label} round={round} {row}");
            }
        }
    }

    for ((label, _), samples) in configurations.into_iter().zip(&mut elapsed) {
        summarize(label, samples);
    }
    let [disabled, enabled, ..] = &elapsed;
    println!(
        "enabled minus disabled quantiles: p50={}ns, p95={}ns, p99={}ns",
        percentile(enabled, 50) - percentile(disabled, 50),
        percentile(enabled, 95) - percentile(disabled, 95),
        percentile(enabled, 99) - percentile(disabled, 99),
    );
}

fn report_hook_benchmark(repo: &Path, mode: &str) {
    if mode != "bench-unavailable" {
        start_global();
    }
    let runtime = GLOBAL.get();
    assert_eq!(
        runtime.is_some(),
        matches!(mode, "bench-enabled" | "bench-saturated")
    );
    let release = runtime
        .filter(|_| mode == "bench-saturated")
        .map(|runtime| {
            let release = stall(&runtime.audit);
            for _ in 0..super::QUEUE_CAPACITY {
                enqueue(&runtime.audit, || true);
            }
            release
        });
    let mut times = Vec::with_capacity(HOOK_BENCH_SAMPLES);
    for iteration in 0..(HOOK_BENCH_WARMUP + HOOK_BENCH_SAMPLES) {
        let start = Instant::now();
        let decision = observe_hook(repo);
        let elapsed = start.elapsed().as_nanos();
        assert!(decision.is_allow(), "ordinary fixture output is allowed");
        if iteration >= HOOK_BENCH_WARMUP {
            times.push(elapsed.to_string());
        }
    }
    if let Some(runtime) = runtime {
        if let Some(release) = release {
            let counts = runtime.audit.snapshot();
            release.send(()).unwrap();
            assert_eq!((counts.persisted, counts.failed), (0, 0));
            assert!(counts.full >= (HOOK_BENCH_WARMUP + HOOK_BENCH_SAMPLES) as u64);
        }
        assert!(runtime.wait_idle(deadline()));
        let counts = runtime.audit.snapshot();
        assert!(counts.persisted > 0);
        println!(
            "hook_writer={mode} queued={} persisted={} failed={} full={} contended={}",
            counts.queued, counts.persisted, counts.failed, counts.full, counts.contended,
        );
    } else {
        let unavailable = AUDIT_OFFLINE.snapshot().unavailable;
        if mode == "bench-unavailable" {
            assert!(unavailable > 0);
        }
        println!("hook_writer={mode} unavailable={unavailable}");
    }
    println!("{HOOK_BENCH_DATA_PREFIX}{}", times.join(","));
}

#[test]
#[ignore = "reports local guard-policy and lane-admission latency without portable timing assertions"]
fn measures_guard_decision_and_admission_overhead() {
    const WARMUP: usize = 128;
    const SAMPLES: usize = 2048;
    let fixture = IsolatedState::new("decision-benchmark");
    let repo = fixture.0.join("repo");
    fs::create_dir_all(repo.join(".git")).unwrap();
    let enabled = Runtime::new(super::QUEUE_CAPACITY);
    let saturated = Runtime::new(1);
    let release = stall(&saturated.audit);
    enqueue(&saturated.audit, || true);
    let configurations = [None, Some(&enabled.audit), Some(&saturated.audit)];
    let mut durations = [Vec::new(), Vec::new(), Vec::new()];

    println!(
        "{} {}, benign guard policy evaluation with optional lane admission and a no-op sink",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    for iteration in 0..(WARMUP + SAMPLES) {
        if iteration % 32 == 0 {
            assert!(enabled.wait_idle(deadline()));
        }
        for step in 0..configurations.len() {
            let mode = (iteration + step) % configurations.len();
            let start = Instant::now();
            let allowed = crate::cmd_policy::evaluate_shell_command(
                black_box("printf %s ordinary"),
                &repo,
                &repo,
                false,
            )
            .is_ok();
            if let Some(lane) = configurations[mode] {
                black_box(lane.submit(move || allowed));
            }
            let elapsed = start.elapsed().as_nanos() as i128;
            assert!(allowed);
            if iteration >= WARMUP {
                durations[mode].push(elapsed);
            }
        }
    }
    let saturated_full = saturated.audit.snapshot().full;
    assert!(enabled.wait_idle(deadline()));
    assert_eq!(saturated_full as usize, WARMUP + SAMPLES);

    let [disabled, enabled_samples, saturated_samples] = &mut durations;
    let mut enabled_overhead: Vec<_> = enabled_samples
        .iter()
        .zip(disabled.iter())
        .map(|(on, off)| on - off)
        .collect();
    let mut saturated_overhead: Vec<_> = saturated_samples
        .iter()
        .zip(disabled.iter())
        .map(|(on, off)| on - off)
        .collect();
    summarize("optional capture disabled", disabled);
    summarize("optional capture enabled", enabled_samples);
    summarize("optional capture saturated", saturated_samples);
    summarize("enabled overhead, paired", &mut enabled_overhead);
    summarize("saturated overhead, paired", &mut saturated_overhead);
    let counts = enabled.audit.snapshot();
    assert_eq!(counts.full, 0);
    println!(
        "enabled admission: queued={}, completed={}, full={}, contended={}; saturated full={saturated_full}",
        counts.queued, counts.persisted, counts.full, counts.contended,
    );

    let mut admitted = Vec::with_capacity(SAMPLES);
    let mut full = Vec::with_capacity(SAMPLES);
    for iteration in 0..SAMPLES {
        if iteration % 32 == 0 {
            assert!(enabled.wait_idle(deadline()));
        }
        let start = Instant::now();
        let result = enabled.audit.submit(|| true);
        let elapsed = start.elapsed().as_nanos() as i128;
        if matches!(result, Submission::Queued) {
            admitted.push(elapsed);
        }

        let start = Instant::now();
        let result = saturated.audit.submit(|| true);
        let elapsed = start.elapsed().as_nanos() as i128;
        assert_eq!(result, Submission::Dropped(DropReason::Full));
        full.push(elapsed);
    }
    release.send(()).unwrap();
    assert!(enabled.wait_idle(deadline()));
    assert!(saturated.wait_idle(deadline()));
    assert_eq!(enabled.audit.snapshot().full, 0);
    summarize("admission only, queued", &mut admitted);
    summarize("admission only, full", &mut full);
}
