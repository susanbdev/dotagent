//! Process-owned background lanes for optional observations.
//!
//! Only lifecycle entry points start workers. Submission performs one try-lock,
//! bounds queue occupancy, and never waits for a worker, sink, or acknowledgement.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

use super::capture::{Context, EventDescriptor, EventIdentity, Payload, Producer};
use super::{runtime_health, store};

const QUEUE_CAPACITY: usize = 128;
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(1);

static GLOBAL: OnceLock<Runtime> = OnceLock::new();
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
    Audit(EventDescriptor),
    Task(Box<dyn FnOnce() -> bool + Send + 'static>),
}

impl Job {
    fn run(self) -> bool {
        match self {
            Self::Audit(event) => event
                .encode()
                .is_ok_and(|record| store::append(&record, store::Durability::Buffered).is_ok()),
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
    fn submit_with<Task>(&self, build: impl FnOnce() -> Task) -> Submission
    where
        Task: FnOnce() -> bool + Send + 'static,
    {
        match self.admit(|| Some((Job::Task(Box::new(build())), ()))) {
            Ok(()) => Submission::Queued,
            Err(reason) => Submission::Dropped(reason),
        }
    }

    fn admit<T>(&self, build: impl FnOnce() -> Option<(Job, T)>) -> Result<T, DropReason> {
        self.try_admit(build).inspect_err(|reason| {
            self.state.counters.note_drop(*reason);
        })
    }

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

struct Runtime {
    audit: Lane,
    export: Lane,
}

impl Runtime {
    fn start(capacity: usize, report: bool) -> Self {
        let audit = Lane::new(capacity);
        let export = Lane::new(capacity);
        export.start("dotagent-export", None);
        let report_export = report.then(|| Arc::clone(&export.state));
        audit.start("dotagent-audit", report_export);
        Self { audit, export }
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
pub(crate) fn close_global() {
    if let Some(runtime) = GLOBAL.get() {
        runtime.close();
    }
}

pub(crate) struct HostTelemetry(bool);

impl Drop for HostTelemetry {
    fn drop(&mut self) {
        if self.0 {
            close_global();
        }
    }
}

pub(crate) fn start_host() -> HostTelemetry {
    HostTelemetry(start_global())
}

/// Allow call sites to elide observation-only context when the lane is unavailable.
pub(crate) fn audit_active() -> bool {
    GLOBAL.get().is_some_and(|runtime| {
        runtime.audit.state.accepting.load(Ordering::Acquire)
            && runtime.audit.state.running.load(Ordering::Acquire)
    })
}

pub(crate) fn submit_event(
    producer: Producer,
    context: &Context,
    payload: Payload,
) -> Option<EventIdentity> {
    let Some(runtime) = GLOBAL.get() else {
        AUDIT_OFFLINE.note_drop(DropReason::Unavailable);
        return None;
    };
    runtime
        .audit
        .admit(|| {
            let (identity, event) = EventDescriptor::new(producer, context, payload).ok()?;
            Some((Job::Audit(event), identity))
        })
        .ok()
}

pub(crate) fn submit_audit_task<Task>(build: impl FnOnce() -> Task) -> Submission
where
    Task: FnOnce() -> bool + Send + 'static,
{
    match GLOBAL.get() {
        Some(runtime) => runtime.audit.submit_with(build),
        None => {
            AUDIT_OFFLINE.note_drop(DropReason::Unavailable);
            Submission::Dropped(DropReason::Unavailable)
        }
    }
}

pub(crate) fn submit_export<Task>(build: impl FnOnce() -> Task) -> Submission
where
    Task: FnOnce() -> bool + Send + 'static,
{
    match GLOBAL.get() {
        Some(runtime) => runtime.export.submit_with(build),
        None => {
            EXPORT_OFFLINE.note_drop(DropReason::Unavailable);
            Submission::Dropped(DropReason::Unavailable)
        }
    }
}

pub(crate) fn note_invalid_audit() {
    GLOBAL
        .get()
        .map_or(&AUDIT_OFFLINE, |runtime| &runtime.audit.state.counters)
        .invalid
        .fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn note_invalid_export() {
    GLOBAL
        .get()
        .map_or(&EXPORT_OFFLINE, |runtime| &runtime.export.state.counters)
        .invalid
        .fetch_add(1, Ordering::Relaxed);
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
