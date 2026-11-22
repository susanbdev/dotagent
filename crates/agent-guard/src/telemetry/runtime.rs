//! Process-owned background lanes for optional observations.
//!
//! Only lifecycle entry points start workers. Submission performs one try-lock,
//! bounds queue occupancy, and never waits for a worker, sink, or acknowledgement.

use std::collections::VecDeque;
#[cfg(test)]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

use super::capture::{Context, EventDescriptor, EventIdentity, Payload, Producer};
use super::protocol::{Kind, Record};
use super::{runtime_health, store};
use crate::json::JsonValue;

pub(super) const QUEUE_CAPACITY: usize = 128;
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(1);

#[cfg(test)]
static GLOBAL: OnceLock<Runtime> = OnceLock::new();
#[cfg(test)]
static STARTED: AtomicBool = AtomicBool::new(false);
static AUDIT_OFFLINE: AtomicCounters = AtomicCounters::new();
static EXPORT_OFFLINE: AtomicCounters = AtomicCounters::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DropReason {
    Full,
    Contended,
    Unavailable,
    Closed,
    Invalid,
    Transport,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Submission {
    Queued,
    Dropped(DropReason),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counters {
    pub queued: u64,
    pub persisted: u64,
    pub failed: u64,
    pub full: u64,
    pub contended: u64,
    pub unavailable: u64,
    pub closed: u64,
    pub invalid: u64,
    pub transport: u64,
    pub worker_exits: u64,
    pub worker_panics: u64,
}

struct AtomicCounters {
    queued: AtomicU64,
    persisted: AtomicU64,
    failed: AtomicU64,
    full: AtomicU64,
    contended: AtomicU64,
    unavailable: AtomicU64,
    closed: AtomicU64,
    invalid: AtomicU64,
    transport: AtomicU64,
    worker_exits: AtomicU64,
    worker_panics: AtomicU64,
}

impl AtomicCounters {
    const fn new() -> Self {
        Self {
            queued: AtomicU64::new(0),
            persisted: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            full: AtomicU64::new(0),
            contended: AtomicU64::new(0),
            unavailable: AtomicU64::new(0),
            closed: AtomicU64::new(0),
            invalid: AtomicU64::new(0),
            transport: AtomicU64::new(0),
            worker_exits: AtomicU64::new(0),
            worker_panics: AtomicU64::new(0),
        }
    }

    fn note_drop(&self, reason: DropReason) {
        let count = match reason {
            DropReason::Full => &self.full,
            DropReason::Contended => &self.contended,
            DropReason::Unavailable => &self.unavailable,
            DropReason::Closed => &self.closed,
            DropReason::Invalid => &self.invalid,
            DropReason::Transport => &self.transport,
        };
        count.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Counters {
        let persisted = self.persisted.load(Ordering::Acquire);
        let failed = self.failed.load(Ordering::Acquire);
        Counters {
            queued: self.queued.load(Ordering::Acquire),
            persisted,
            failed,
            full: self.full.load(Ordering::Relaxed),
            contended: self.contended.load(Ordering::Relaxed),
            unavailable: self.unavailable.load(Ordering::Relaxed),
            closed: self.closed.load(Ordering::Relaxed),
            invalid: self.invalid.load(Ordering::Relaxed),
            transport: self.transport.load(Ordering::Relaxed),
            worker_exits: self.worker_exits.load(Ordering::Relaxed),
            worker_panics: self.worker_panics.load(Ordering::Relaxed),
        }
    }
}

impl Counters {
    pub(super) fn pending(self) -> u64 {
        self.queued
            .saturating_sub(self.persisted.saturating_add(self.failed))
    }

    pub(super) fn dropped(self) -> u64 {
        self.full
            .saturating_add(self.contended)
            .saturating_add(self.unavailable)
            .saturating_add(self.closed)
            .saturating_add(self.invalid)
            .saturating_add(self.transport)
    }

    fn including_offline(mut self, offline: &AtomicCounters) -> Self {
        self.unavailable = self
            .unavailable
            .saturating_add(offline.unavailable.load(Ordering::Relaxed));
        self.invalid = self
            .invalid
            .saturating_add(offline.invalid.load(Ordering::Relaxed));
        self
    }
}

// Keep one owned descriptor in each preallocated slot without a producer-side box.
#[allow(clippy::large_enum_variant)]
enum Job {
    Record(Record),
    #[cfg(test)]
    Audit(EventDescriptor),
    #[cfg(test)]
    Task(Box<dyn FnOnce() -> bool + Send + 'static>),
}

impl Job {
    fn run(self) -> bool {
        match self {
            Self::Record(record) if record.kind.mirror() => {
                crate::feedback::write_agentpi_mirror(&record.body)
            }
            Self::Record(record) => {
                store::append(&record.body, store::Durability::Required).is_ok()
            }
            #[cfg(test)]
            Self::Audit(event) => event
                .encode()
                .is_ok_and(|record| store::append(&record, store::Durability::Buffered).is_ok()),
            #[cfg(test)]
            Self::Task(task) => task(),
        }
    }
}

struct LaneState {
    jobs: Mutex<VecDeque<Job>>,
    capacity: usize,
    accepting: AtomicBool,
    running: AtomicBool,
    counters: AtomicCounters,
}

struct Lane {
    state: Arc<LaneState>,
}

impl Lane {
    fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            state: Arc::new(LaneState {
                jobs: Mutex::new(VecDeque::with_capacity(capacity)),
                capacity,
                accepting: AtomicBool::new(true),
                running: AtomicBool::new(false),
                counters: AtomicCounters::new(),
            }),
        }
    }

    fn start(&self, name: &'static str, report_export: Option<Arc<LaneState>>) {
        let state = Arc::clone(&self.state);
        self.state.running.store(true, Ordering::Release);
        if thread::Builder::new()
            .name(name.into())
            .spawn(move || worker_entry(&state, report_export.as_deref()))
            .is_err()
        {
            self.state.running.store(false, Ordering::Release);
        }
    }

    #[cfg(test)]
    fn submit(&self, task: impl FnOnce() -> bool + Send + 'static) -> Submission {
        self.submit_with(|| task)
    }

    // `build` runs on the producer under the admission guard. It may only copy bounded
    // inputs into the job. Encoding, redaction, and sink operations belong in the job.
    #[cfg(test)]
    fn submit_with<Task>(&self, build: impl FnOnce() -> Task) -> Submission
    where
        Task: FnOnce() -> bool + Send + 'static,
    {
        match self.admit(|| Some((Job::Task(Box::new(build())), ()))) {
            Ok(()) => Submission::Queued,
            Err(reason) => Submission::Dropped(reason),
        }
    }

    #[cfg(test)]
    fn admit<T>(&self, build: impl FnOnce() -> Option<(Job, T)>) -> Result<T, DropReason> {
        self.try_admit(build).inspect_err(|reason| {
            self.state.counters.note_drop(*reason);
        })
    }

    #[cfg(test)]
    fn try_admit<T>(&self, build: impl FnOnce() -> Option<(Job, T)>) -> Result<T, DropReason> {
        let state = &self.state;
        if !state.accepting.load(Ordering::Acquire) {
            return Err(DropReason::Closed);
        }
        if !state.running.load(Ordering::Acquire) {
            return Err(DropReason::Unavailable);
        }
        let mut jobs = match state.jobs.try_lock() {
            Ok(jobs) => jobs,
            Err(TryLockError::WouldBlock) => return Err(DropReason::Contended),
            Err(TryLockError::Poisoned(_)) => return Err(DropReason::Unavailable),
        };
        if !state.accepting.load(Ordering::Acquire) {
            return Err(DropReason::Closed);
        }
        if !state.running.load(Ordering::Acquire) {
            return Err(DropReason::Unavailable);
        }
        if jobs.len() == state.capacity {
            return Err(DropReason::Full);
        }
        let (job, output) = build().ok_or(DropReason::Invalid)?;
        jobs.push_back(job);
        state.counters.queued.fetch_add(1, Ordering::Release);
        Ok(output)
    }

    #[cfg(test)]
    fn snapshot(&self) -> Counters {
        self.state.counters.snapshot()
    }

    fn close(&self) {
        self.state.accepting.store(false, Ordering::Release);
    }
}

fn worker_entry(state: &LaneState, export: Option<&LaneState>) {
    // This isolates an unwind. In an aborting build a panic terminates the process.
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_worker(state, export)));
    if result.is_err() {
        // The in-flight job may have reached its sink. Leave its outcome unconfirmed.
        state.counters.worker_panics.fetch_add(1, Ordering::Relaxed);
    }
    state.counters.worker_exits.fetch_add(1, Ordering::Relaxed);
    state.running.store(false, Ordering::Release);
}

fn run_worker(state: &LaneState, export: Option<&LaneState>) {
    let mut last_report = None;
    let mut next_snapshot = Instant::now() + SNAPSHOT_INTERVAL;
    let mut completed = 0u64;
    loop {
        let (job, closing) = if state.accepting.load(Ordering::Acquire)
            && state.counters.queued.load(Ordering::Acquire) == completed
        {
            // Idle workers leave the admission lock alone.
            (None, false)
        } else {
            let mut jobs = match state.jobs.try_lock() {
                Ok(jobs) => jobs,
                Err(TryLockError::WouldBlock) => {
                    thread::sleep(POLL_INTERVAL);
                    continue;
                }
                Err(TryLockError::Poisoned(_)) => break,
            };
            (jobs.pop_front(), !state.accepting.load(Ordering::Acquire))
        };
        let idle = job.is_none();
        if let Some(job) = job {
            let success = job.run();
            let counter = if success {
                &state.counters.persisted
            } else {
                &state.counters.failed
            };
            counter.fetch_add(1, Ordering::Release);
            completed = completed.wrapping_add(1);
        }
        if let Some(export) = export
            && ((closing && idle) || Instant::now() >= next_snapshot)
        {
            let snapshots = (
                state.counters.snapshot().including_offline(&AUDIT_OFFLINE),
                export
                    .counters
                    .snapshot()
                    .including_offline(&EXPORT_OFFLINE),
                closing,
            );
            if (snapshots.0 != Counters::default() || snapshots.1 != Counters::default())
                && Some(snapshots) != last_report
                && runtime_health::publish(snapshots.0, snapshots.1, snapshots.2)
            {
                last_report = Some(snapshots);
            }
            next_snapshot = Instant::now() + SNAPSHOT_INTERVAL;
        }
        if idle {
            if closing {
                break;
            }
            // Polling avoids a wakeup or a kernel wait on the submission path.
            thread::sleep(POLL_INTERVAL);
        }
    }
}

pub(super) struct Runtime {
    audit: Lane,
    export: Lane,
}

impl Runtime {
    pub(super) fn start(capacity: usize, report: bool) -> Self {
        let audit = Lane::new(capacity);
        let export = Lane::new(capacity);
        export.start("dotagent-export", None);
        let report_export = report.then(|| Arc::clone(&export.state));
        audit.start("dotagent-audit", report_export);
        Self { audit, export }
    }

    pub(super) fn receive(&self, record: Record) {
        let lane = if record.kind.mirror() {
            &self.export
        } else {
            &self.audit
        };
        // Both sides of this mutex live in the collector. The worker releases it before I/O.
        let state = &lane.state;
        let Ok(mut jobs) = state.jobs.lock() else {
            state.counters.note_drop(DropReason::Unavailable);
            return;
        };
        if !state.running.load(Ordering::Acquire) {
            state.counters.note_drop(DropReason::Unavailable);
        } else if jobs.len() >= state.capacity {
            state.counters.note_drop(DropReason::Full);
        } else {
            jobs.push_back(Job::Record(record));
            state.counters.queued.fetch_add(1, Ordering::Release);
        }
    }

    pub(super) fn rejected(&self, reason: DropReason) {
        self.audit.state.counters.note_drop(reason);
    }

    pub(super) fn counts(&self) -> (Counters, Counters) {
        (
            self.audit.state.counters.snapshot(),
            self.export.state.counters.snapshot(),
        )
    }

    pub(super) fn finish(&self) {
        self.close();
        while self.audit.state.running.load(Ordering::Acquire)
            || self.export.state.running.load(Ordering::Acquire)
        {
            thread::park_timeout(POLL_INTERVAL);
        }
    }

    fn close(&self) {
        self.audit.close();
        self.export.close();
    }

    #[cfg(test)]
    fn new(capacity: usize) -> Self {
        Self::start(capacity, false)
    }

    #[cfg(test)]
    fn wait_idle(&self, deadline: Instant) -> bool {
        wait_until(deadline, || {
            [&self.audit, &self.export].into_iter().all(|lane| {
                let stats = lane.snapshot();
                stats.queued == stats.persisted.saturating_add(stats.failed)
            })
        })
    }

    #[cfg(test)]
    fn wait_stopped(&self, deadline: Instant) -> bool {
        wait_until(deadline, || {
            [&self.audit, &self.export]
                .into_iter()
                .all(|lane| !lane.state.running.load(Ordering::Acquire))
        })
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.close();
    }
}

/// Initialize workers during trusted process setup, before serving any work.
/// A process that applies its own kernel sandbox must never call this.
#[cfg(test)]
pub(crate) fn start_global() -> bool {
    if !super::capture::host_capture_allowed()
        || std::env::var_os("DOTAGENT_TELEMETRY").as_deref() == Some(std::ffi::OsStr::new("0"))
        || STARTED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
    {
        return false;
    }
    let _ = GLOBAL.set(Runtime::start(QUEUE_CAPACITY, !cfg!(test)));
    true
}

/// Stop accepting work. This operation deliberately does not join either worker.
#[cfg(test)]
pub(crate) fn close_global() {
    if let Some(runtime) = GLOBAL.get() {
        runtime.close();
    }
}

pub(crate) struct HostTelemetry {
    #[cfg(unix)]
    child: Option<std::process::Child>,
    #[cfg(test)]
    local: bool,
}

impl Drop for HostTelemetry {
    fn drop(&mut self) {
        #[cfg(test)]
        if self.local {
            close_global();
        }
        #[cfg(unix)]
        if let Some(child) = &mut self.child {
            drop(child.stdin.take());
            let _ = child.try_wait();
        }
    }
}

pub(crate) fn start_host() -> HostTelemetry {
    HostTelemetry {
        #[cfg(all(unix, not(test)))]
        child: super::transport::launch(),
        #[cfg(all(unix, test))]
        child: None,
        #[cfg(test)]
        local: start_global(),
    }
}

pub(crate) fn audit_active() -> bool {
    #[cfg(test)]
    if let Some(runtime) = GLOBAL.get() {
        return runtime.audit.state.accepting.load(Ordering::Acquire)
            && runtime.audit.state.running.load(Ordering::Acquire);
    }
    #[cfg(unix)]
    {
        super::transport::active()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn handoff<T>(mirror: bool, build: impl FnOnce() -> Option<(Record, T)>) -> Result<T, DropReason> {
    let counters = if mirror {
        &EXPORT_OFFLINE
    } else {
        &AUDIT_OFFLINE
    };
    #[cfg(test)]
    if let Some(runtime) = GLOBAL.get() {
        let lane = if mirror {
            &runtime.export
        } else {
            &runtime.audit
        };
        return lane.admit(|| build().map(|(record, receipt)| (Job::Record(record), receipt)));
    }
    #[cfg(unix)]
    let result = super::transport::send(build);
    #[cfg(not(unix))]
    let result = {
        let _ = build;
        Err(DropReason::Unavailable)
    };
    result
        .inspect_err(|reason| counters.note_drop(*reason))
        .inspect(|_| {
            counters.queued.fetch_add(1, Ordering::Relaxed);
        })
}

pub(crate) fn submit_event(
    producer: Producer,
    context: &Context,
    payload: Payload,
) -> Option<EventIdentity> {
    try_event(producer, context, payload).ok()
}

pub(super) fn try_event(
    producer: Producer,
    context: &Context,
    payload: Payload,
) -> Result<EventIdentity, DropReason> {
    #[cfg(test)]
    if let Some(runtime) = GLOBAL.get() {
        return runtime.audit.admit(|| {
            let (identity, event) = EventDescriptor::new(producer, context, payload).ok()?;
            Some((Job::Audit(event), identity))
        });
    }
    handoff(false, || {
        let (id, event) = EventDescriptor::new(producer, context, payload).ok()?;
        Some((
            Record {
                kind: Kind::Event,
                body: event.encode().ok()?,
            },
            id,
        ))
    })
}

pub(crate) fn submit_record(kind: Kind, build: impl FnOnce() -> JsonValue) -> Submission {
    match handoff(kind.mirror(), || {
        Some((
            Record {
                kind,
                body: build(),
            },
            (),
        ))
    }) {
        Ok(()) => Submission::Queued,
        Err(reason) => Submission::Dropped(reason),
    }
}

pub(super) fn handoff_counts() -> [u64; 7] {
    let a = AUDIT_OFFLINE.snapshot();
    let b = EXPORT_OFFLINE.snapshot();
    [a.queued.saturating_add(b.queued), a.full.saturating_add(b.full),
        a.contended.saturating_add(b.contended), a.unavailable.saturating_add(b.unavailable),
        a.invalid.saturating_add(b.invalid), a.transport.saturating_add(b.transport),
        a.closed.saturating_add(b.closed)]
}

pub(crate) fn note_invalid_audit() {
    AUDIT_OFFLINE.note_drop(DropReason::Invalid);
}
pub(crate) fn note_invalid_export() {
    EXPORT_OFFLINE.note_drop(DropReason::Invalid);
}

#[cfg(test)]
pub(crate) fn wait_idle(deadline: Instant) -> bool {
    GLOBAL
        .get()
        .is_some_and(|runtime| runtime.wait_idle(deadline))
}

#[cfg(test)]
fn wait_until(deadline: Instant, mut check: impl FnMut() -> bool) -> bool {
    loop {
        if check() {
            return true;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        thread::sleep(left.min(POLL_INTERVAL));
    }
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
