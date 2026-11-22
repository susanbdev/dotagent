//! Typed local prerequisite checks and process observations.

#[cfg(unix)]
use std::io::{self, Read};
#[cfg(unix)]
use std::net::Shutdown;
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::os::unix::{net::UnixStream, process::CommandExt};
use std::path::Path;
#[cfg(unix)]
use std::process::{Child, Command, Stdio};
use std::process::{ExitCode, ExitStatus};
#[cfg(unix)]
use std::time::Duration;
use std::time::Instant;

use crate::json::JsonValue;

use super::capture::{
    Completeness, Context, EmitResult, EventType, Payload, Producer, emit, emit_required,
    host_capture_allowed, next_local_id, report_failure, unix_time_ms,
};

const BASELINE_ROUTE: &str = "repo_baseline_mediator";
const SHELL_WRAPPER_ROUTE: &str = "shell_wrapper_mediator";
const BASELINE_DEADLINE_MS: u64 = 10_000;
#[cfg(unix)]
const POLL_INTERVAL: Duration = Duration::from_millis(5);
#[cfg(unix)]
const REAP_GRACE: Duration = Duration::from_secs(1);
#[cfg(unix)]
const GROUP_SIGNAL_GRACE: Duration = Duration::from_millis(100);
#[cfg(unix)]
const MAX_CHECK_OUTPUT: usize = 128;
const BASE_REFS: [Check; 3] = [Check::Head, Check::LocalMain, Check::CachedOriginMain];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Check {
    Head,
    LocalMain,
    CachedOriginMain,
    CachedReviewFixes,
    WorktreeStatus,
}

impl Check {
    fn identity(self) -> &'static str {
        match self {
            Self::Head => "HEAD",
            Self::LocalMain => "refs/heads/main",
            Self::CachedOriginMain => "refs/remotes/origin/main",
            Self::CachedReviewFixes => "refs/remotes/origin/v2-1-review-fixes",
            Self::WorktreeStatus => "git_status",
        }
    }

    fn script(self) -> &'static str {
        match self {
            Self::Head => "git rev-parse --quiet --verify --end-of-options 'HEAD^{commit}'",
            Self::LocalMain => {
                "git rev-parse --quiet --verify --end-of-options 'refs/heads/main^{commit}'"
            }
            Self::CachedOriginMain => {
                "git rev-parse --quiet --verify --end-of-options 'refs/remotes/origin/main^{commit}'"
            }
            Self::CachedReviewFixes => {
                "git rev-parse --quiet --verify --end-of-options 'refs/remotes/origin/v2-1-review-fixes^{commit}'"
            }
            // The mediator runs Bash with pipefail. Only a byte count crosses its output boundary.
            Self::WorktreeStatus => {
                "git --no-optional-locks status --porcelain=v1 -z --untracked-files=normal --ignore-submodules=dirty | wc -c"
            }
        }
    }

    fn freshness(self) -> &'static str {
        match self {
            Self::CachedOriginMain | Self::CachedReviewFixes => "cached_remote_tracking_ref",
            _ => "local_at_execution",
        }
    }

    fn observation(self, status: ExitStatus, bounded_stdout: Option<&[u8]>) -> CheckObservation {
        if !status.success() {
            return CheckObservation::Unsuccessful;
        }
        let Some(output) = bounded_stdout.and_then(|bytes| std::str::from_utf8(bytes).ok()) else {
            return CheckObservation::Unavailable("INVALID_MEDIATOR_OUTPUT");
        };
        let value = output.trim();
        if self == Self::WorktreeStatus {
            return value
                .parse::<u64>()
                .map(|bytes| CheckObservation::Worktree { dirty: bytes != 0 })
                .unwrap_or(CheckObservation::Unavailable("INVALID_MEDIATOR_OUTPUT"));
        }
        if matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            CheckObservation::Commit(value.to_ascii_lowercase())
        } else {
            CheckObservation::Unavailable("INVALID_MEDIATOR_OUTPUT")
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CheckObservation {
    Commit(String),
    Worktree { dirty: bool },
    Unsuccessful,
    Unavailable(&'static str),
}

impl CheckObservation {
    fn status(&self) -> &'static str {
        match self {
            Self::Commit(_) => "resolved",
            Self::Worktree { .. } => "observed",
            Self::Unsuccessful => "unsuccessful",
            Self::Unavailable(_) => "unavailable",
        }
    }

    fn satisfied(&self) -> bool {
        matches!(self, Self::Commit(_) | Self::Worktree { .. })
    }

    fn payload(&self, check: Check) -> Payload {
        let mut fields = vec![
            string_field("route", BASELINE_ROUTE),
            string_field("requested_check", check.identity()),
            string_field("source_freshness", check.freshness()),
            string_field("observed_status", self.status()),
            string_field("check_expectation", "required_observation"),
        ];
        if check == Check::WorktreeStatus {
            fields.push(string_field(
                "status_scope",
                "worktree_with_submodule_commits",
            ));
        }
        match self {
            Self::Commit(commit) => fields.push(string_field("resolved_commit", commit)),
            Self::Worktree { dirty } => {
                fields.push(("worktree_dirty".to_string(), JsonValue::Bool(*dirty)));
            }
            Self::Unsuccessful | Self::Unavailable(_) => {}
        }
        let (completeness, reason) = match self {
            Self::Commit(_) | Self::Worktree { .. } => (Completeness::Complete, "CHECK_OBSERVED"),
            Self::Unsuccessful => (Completeness::Partial, "MEDIATOR_UNSUCCESSFUL"),
            Self::Unavailable(reason) => (Completeness::Unavailable, *reason),
        };
        Payload::new(
            EventType::PrerequisiteChecked,
            completeness,
            JsonValue::Object(fields),
        )
        .with_result("check", reason, self.status())
    }
}

fn string_field(name: &str, value: &str) -> (String, JsonValue) {
    (name.to_string(), JsonValue::Str(value.to_string()))
}

fn baseline_execution_fields(check: Check) -> Vec<(String, JsonValue)> {
    let mut fields = mediator_execution_fields(BASELINE_ROUTE);
    fields.push(string_field("argument_summary", check.identity()));
    fields.push((
        "deadline_ms".to_string(),
        JsonValue::Uint(BASELINE_DEADLINE_MS),
    ));
    fields
}

fn mediator_execution_fields(route: &'static str) -> Vec<(String, JsonValue)> {
    vec![
        string_field("route", route),
        string_field("executable", "dotagent_guard"),
        string_field("subject", "mediator_process"),
        string_field("nested_process_coverage", "unavailable"),
        string_field("duration_scope", "mediator_observation"),
    ]
}

fn execution_started(fields: Vec<(String, JsonValue)>) -> Payload {
    Payload::new(
        EventType::ExecutionStarted,
        Completeness::Partial,
        JsonValue::Object(fields),
    )
    .with_result("launch", "MEDIATOR_STARTED", "started")
}

/// Converts a direct process wait to separate exit and signal fields. Only a caller that
/// observed a deadline can set `deadline_observed`. No numeric shell code implies a signal.
pub(crate) fn process_result_fields(
    status: Option<ExitStatus>,
    deadline_observed: bool,
    expected_exit_code: Option<i32>,
) -> Vec<(String, JsonValue)> {
    let code = status.and_then(|status| status.code());
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt;
        status.and_then(|status| status.signal())
    };
    #[cfg(not(unix))]
    let signal: Option<i32> = None;

    let disposition = match (deadline_observed, code, signal) {
        (true, _, _) => "timed_out",
        (false, Some(_), _) => "exited",
        (false, None, Some(_)) => "signaled",
        (false, None, None) => "termination_unobserved",
    };
    let mut fields = vec![string_field("termination", disposition)];
    if let Some(code) = code {
        fields.push(("exit_code".to_string(), JsonValue::Int(i64::from(code))));
    }
    if let Some(signal) = signal {
        fields.push(("signal".to_string(), JsonValue::Int(i64::from(signal))));
    }
    if let Some(expected) = expected_exit_code {
        fields.push((
            "expected_exit_code".to_string(),
            JsonValue::Int(i64::from(expected)),
        ));
        if status.is_some() || deadline_observed {
            fields.push((
                "expectation_met".to_string(),
                JsonValue::Bool(!deadline_observed && code == Some(expected)),
            ));
        }
    }
    fields
}

#[derive(Clone, Copy, Debug)]
enum MediatorResult {
    Waited(ExitStatus),
    LaunchFailed,
    WaitFailed,
    #[cfg(unix)]
    TimedOut(Option<ExitStatus>),
    #[cfg(not(unix))]
    Unavailable,
}

impl MediatorResult {
    fn reason(self) -> &'static str {
        match self {
            Self::Waited(status) if status.success() => "MEDIATOR_COMPLETED",
            Self::Waited(_) => "MEDIATOR_UNSUCCESSFUL",
            Self::LaunchFailed => "MEDIATOR_LAUNCH_FAILED",
            Self::WaitFailed => "MEDIATOR_WAIT_FAILED",
            #[cfg(unix)]
            Self::TimedOut(_) => "MEDIATOR_TIMEOUT",
            #[cfg(not(unix))]
            Self::Unavailable => "BASELINE_PLATFORM_UNAVAILABLE",
        }
    }
}

fn execution_finished(mut fields: Vec<(String, JsonValue)>, result: MediatorResult) -> Payload {
    let (completeness, disposition) = match result {
        MediatorResult::Waited(status) => {
            fields.extend(process_result_fields(Some(status), false, None));
            let disposition = if status.success() {
                "finished"
            } else {
                "failed"
            };
            (Completeness::Partial, disposition)
        }
        MediatorResult::LaunchFailed => {
            fields.push(string_field("termination", "launch_failed"));
            (Completeness::Unavailable, "failed")
        }
        MediatorResult::WaitFailed => {
            fields.extend(process_result_fields(None, false, None));
            (Completeness::Unavailable, "unknown")
        }
        #[cfg(unix)]
        MediatorResult::TimedOut(status) => {
            fields.extend(process_result_fields(status, true, None));
            fields.push(string_field(
                "cleanup_scope",
                "outer_mediator_process_group",
            ));
            fields.push((
                "mediator_reaped".to_string(),
                JsonValue::Bool(status.is_some()),
            ));
            (Completeness::Partial, "timed_out")
        }
        #[cfg(not(unix))]
        MediatorResult::Unavailable => {
            fields.push(string_field("termination", "unavailable"));
            (Completeness::Unavailable, "unavailable")
        }
    };
    Payload::new(
        EventType::ExecutionFinished,
        completeness,
        JsonValue::Object(fields),
    )
    .with_result("finish", result.reason(), disposition)
}

/// An observation owned by the host shell wrapper. The child is the trusted sandbox
/// executable, and any processes inside that executable are outside this boundary.
pub(crate) struct ShellMediatorObservation {
    context: Context,
    started_at: Option<Instant>,
}

impl ShellMediatorObservation {
    pub(crate) fn new(repo_root: &Path) -> Option<Self> {
        if !host_capture_allowed() {
            return None;
        }
        let mut context = Context::for_repo(repo_root);
        context.trace_id = Some(next_local_id());
        context.execution_id = Some(next_local_id());
        Some(Self {
            context,
            started_at: None,
        })
    }

    pub(crate) fn started(&mut self) {
        self.started_at = Some(Instant::now());
        self.context.occurred_at_unix_ms = unix_time_ms();
        self.context.parent_event_id = self.emit(execution_started(mediator_execution_fields(
            SHELL_WRAPPER_ROUTE,
        )));
    }

    pub(crate) fn finished(mut self, status: Option<ExitStatus>) {
        self.context.occurred_at_unix_ms = unix_time_ms();
        self.context.duration_ns = self
            .started_at
            .and_then(|start| u64::try_from(start.elapsed().as_nanos()).ok());
        let result = match status {
            Some(status) => MediatorResult::Waited(status),
            None if self.started_at.is_some() => MediatorResult::WaitFailed,
            None => MediatorResult::LaunchFailed,
        };
        let _ = self.emit(execution_finished(
            mediator_execution_fields(SHELL_WRAPPER_ROUTE),
            result,
        ));
    }

    fn emit(&self, payload: Payload) -> Option<String> {
        match emit(Producer::ExecutionMediator, &self.context, payload) {
            EmitResult::Persisted(receipt) => Some(receipt.event_id),
            EmitResult::DroppedNoncritical(reason) | EmitResult::FailedRequiredEvidence(reason) => {
                report_failure(reason);
                None
            }
        }
    }
}

fn record(context: &Context, payload: Payload, persisted: &mut bool) -> Option<String> {
    match emit_required(Producer::Baseline, context, payload) {
        EmitResult::Persisted(receipt) if receipt.storage.durable => return Some(receipt.event_id),
        EmitResult::Persisted(_) => report_failure("AUDIT_DURABILITY_UNCONFIRMED"),
        EmitResult::FailedRequiredEvidence(reason) | EmitResult::DroppedNoncritical(reason) => {
            report_failure(reason);
        }
    }
    *persisted = false;
    None
}

#[cfg(unix)]
fn launch_baseline_check(repo_root: &Path, check: Check) -> io::Result<BaselineMediator> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .current_dir(repo_root)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null");
    if let Some(home) = std::env::var_os("HOME") {
        command.env("HOME", home);
    }
    command
        .args([
            "exec-sandbox",
            "--require-kernel",
            "--deny-net",
            "--read-only",
            "--sanitize-stream",
            "--",
            check.script(),
        ])
        .stderr(Stdio::null());
    BaselineMediator::spawn(command)
}

#[cfg(unix)]
struct BaselineMediator {
    child: Child,
    output: UnixStream,
}

#[cfg(unix)]
impl BaselineMediator {
    fn spawn(command: Command) -> io::Result<Self> {
        let (reader, writer) = UnixStream::pair()?;
        Self::spawn_with_output(command, reader, writer)
    }

    fn spawn_with_output(
        mut command: Command,
        reader: UnixStream,
        writer: UnixStream,
    ) -> io::Result<Self> {
        reader.set_nonblocking(true)?;
        reader.shutdown(Shutdown::Write)?;
        writer.shutdown(Shutdown::Read)?;
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::from(OwnedFd::from(writer)))
            .process_group(0)
            .spawn()?;
        drop(command);
        Ok(Self {
            child,
            output: reader,
        })
    }

    fn collect(self, deadline: Instant) -> (MediatorResult, Option<Vec<u8>>) {
        let Self {
            mut child,
            mut output,
        } = self;
        let captured = read_mediator_output(&mut output, deadline);
        drop(output);
        // Until the pipe reaches EOF, leave the group leader unreaped so its PGID cannot be
        // reused before timeout cleanup. An inherited writer can outlive that leader.
        if let OutputCapture::Finished(bytes) = captured {
            match wait_until(&mut child, deadline) {
                Ok(Some(status)) => return (MediatorResult::Waited(status), bytes),
                // A failed wait may mean the OS no longer recognizes the child as ours.
                Err(_) => return (MediatorResult::WaitFailed, None),
                Ok(None) => {}
            }
        }
        (MediatorResult::TimedOut(terminate_mediator(child)), None)
    }
}

#[cfg(unix)]
enum OutputCapture {
    Finished(Option<Vec<u8>>),
    TimedOut,
}

#[cfg(unix)]
fn read_mediator_output(output: &mut UnixStream, deadline: Instant) -> OutputCapture {
    let mut retained = Vec::with_capacity(MAX_CHECK_OUTPUT);
    let mut chunk = [0; 1_024];
    let mut oversized = false;
    while Instant::now() < deadline {
        match output.read(&mut chunk) {
            Ok(0) => return OutputCapture::Finished((!oversized).then_some(retained)),
            Ok(count) => {
                let keep = count.min(MAX_CHECK_OUTPUT - retained.len());
                retained.extend_from_slice(&chunk[..keep]);
                oversized |= keep < count;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => pause_until(deadline),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return OutputCapture::Finished(None),
        }
    }
    OutputCapture::TimedOut
}

#[cfg(unix)]
fn wait_until(child: &mut Child, deadline: Instant) -> io::Result<Option<ExitStatus>> {
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(None) => pause_until(deadline),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
    Ok(None)
}

#[cfg(unix)]
fn pause_until(deadline: Instant) {
    std::thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
}

#[cfg(unix)]
fn terminate_mediator(mut child: Child) -> Option<ExitStatus> {
    let pid = child.id();
    if pid > 1
        && let Some(kill) = ["/bin/kill", "/usr/bin/kill"]
            .into_iter()
            .find(|path| Path::new(path).is_file())
        && let Ok(mut signal) = Command::new(kill)
            .args(["-s", "KILL", "--", &format!("-{pid}")])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    {
        if matches!(
            wait_until(&mut signal, Instant::now() + GROUP_SIGNAL_GRACE),
            Ok(None)
        ) {
            let _ = signal.kill();
            let _ = wait_until(&mut signal, Instant::now() + GROUP_SIGNAL_GRACE);
        }
    }
    // Cover an unavailable group utility or a failed group signal. The direct child is our only
    // waitable process, and the sandbox's own descendant process groups are outside this scope.
    let _ = child.kill();
    wait_until(&mut child, Instant::now() + REAP_GRACE)
        .ok()
        .flatten()
}

fn capture_check(repo_root: &Path, check: Check, mut context: Context) -> bool {
    context.execution_id = Some(next_local_id());
    let mut persisted = true;

    // Keep the existing command policy in the path. A refusal supplies neither a launch
    // observation nor evidence that the requested ref was absent.
    let refusal = match crate::cmd_policy::evaluate_shell_command(
        check.script(),
        repo_root,
        repo_root,
        false,
    ) {
        Ok(plan) if plan.rewritten_command.is_none() && plan.write_files.is_empty() => None,
        Ok(_) => Some("BASELINE_POLICY_PLAN_UNEXPECTED"),
        Err(denial) => Some(denial.code),
    };
    if let Some(reason) = refusal {
        let observation = CheckObservation::Unavailable(reason);
        context.occurred_at_unix_ms = unix_time_ms();
        record(&context, observation.payload(check), &mut persisted);
        print_observation(check, &observation, persisted);
        return false;
    }

    let started_at = Instant::now();
    #[cfg(unix)]
    let (termination, output) = match launch_baseline_check(repo_root, check) {
        Ok(mediator) => {
            context.occurred_at_unix_ms = unix_time_ms();
            context.parent_event_id = record(
                &context,
                execution_started(baseline_execution_fields(check)),
                &mut persisted,
            );
            mediator.collect(started_at + Duration::from_millis(BASELINE_DEADLINE_MS))
        }
        Err(_) => (MediatorResult::LaunchFailed, None),
    };
    #[cfg(not(unix))]
    let (termination, output): (MediatorResult, Option<Vec<u8>>) =
        (MediatorResult::Unavailable, None);
    let observation = match termination {
        MediatorResult::Waited(status) => check.observation(status, output.as_deref()),
        _ => CheckObservation::Unavailable(termination.reason()),
    };
    context.occurred_at_unix_ms = unix_time_ms();
    context.duration_ns = u64::try_from(started_at.elapsed().as_nanos()).ok();
    context.parent_event_id = record(
        &context,
        execution_finished(baseline_execution_fields(check), termination),
        &mut persisted,
    );
    context.duration_ns = None;
    context.occurred_at_unix_ms = unix_time_ms();
    record(&context, observation.payload(check), &mut persisted);
    print_observation(check, &observation, persisted);
    persisted && observation.satisfied()
}

fn print_observation(check: Check, observation: &CheckObservation, persisted: bool) {
    let persistence = if persisted { "recorded" } else { "capture_gap" };
    let value = match observation {
        CheckObservation::Commit(commit) => commit.as_str(),
        CheckObservation::Worktree { dirty: true } => "dirty",
        CheckObservation::Worktree { dirty: false } => "clean",
        _ => observation.status(),
    };
    println!("{} {} {}", check.identity(), value, persistence);
}

/// Entry point called after the existing human TTY and operator signature gates.
pub(super) fn run_baseline_cli(args: &[String], repo_root: &Path) -> ExitCode {
    let include_review_fixes = match args {
        [] => false,
        [flag] if flag == "--include-review-fixes" => true,
        _ => {
            eprintln!(
                "[DOTAGENT TELEMETRY] usage: dotagent telemetry baseline [--include-review-fixes] [--sshsig <path>]"
            );
            return ExitCode::from(2);
        }
    };
    let mut context = Context::for_repo(repo_root);
    context.trace_id = Some(next_local_id());
    let mut complete = true;
    for check in baseline_checks(include_review_fixes) {
        complete &= capture_check(repo_root, check, context.clone());
    }
    println!("remote_freshness unavailable (local checks only)");
    if complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn baseline_checks(include_review_fixes: bool) -> impl Iterator<Item = Check> {
    BASE_REFS
        .into_iter()
        .chain(include_review_fixes.then_some(Check::CachedReviewFixes))
        .chain([Check::WorktreeStatus])
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn exit(code: i32) -> ExitStatus {
        ExitStatus::from_raw(code << 8)
    }

    #[test]
    fn fixed_baseline_commands_pass_the_existing_readonly_policy() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/dotagent-telemetry-fixtures")
            .join(next_local_id());
        std::fs::create_dir_all(fixture.join(".git")).expect("isolated Git directory fixture");
        let repo = fixture.canonicalize().expect("canonical fixture directory");
        for check in baseline_checks(true) {
            let plan =
                crate::cmd_policy::evaluate_shell_command(check.script(), &repo, &repo, false)
                    .expect("fixed read-only Git command should pass guard evaluation");
            assert!(plan.rewritten_command.is_none());
            assert!(plan.write_files.is_empty());
        }
        std::fs::remove_dir_all(fixture).expect("clean isolated policy fixture");
    }

    #[test]
    fn host_shell_mediator_records_wait_status_without_command_data() {
        use super::super::capture::encode;

        let mut context = Context::default();
        let (event_id, _) = encode(
            Producer::ExecutionMediator,
            &context,
            execution_started(mediator_execution_fields(SHELL_WRAPPER_ROUTE)),
        )
        .expect("mediator start record");
        context.parent_event_id = Some(event_id.clone());
        let (_, finished) = encode(
            Producer::ExecutionMediator,
            &context,
            execution_finished(
                mediator_execution_fields(SHELL_WRAPPER_ROUTE),
                MediatorResult::Waited(exit(137)),
            ),
        )
        .expect("mediator finish record");
        let payload = finished.get("payload").expect("typed payload");
        assert_eq!(
            payload.get("route").and_then(JsonValue::as_str),
            Some(SHELL_WRAPPER_ROUTE)
        );
        assert_eq!(
            payload.get("exit_code").and_then(JsonValue::as_i64),
            Some(137)
        );
        assert!(payload.get("signal").is_none());
        assert!(payload.get("argument_summary").is_none());
        assert_eq!(
            payload
                .get("nested_process_coverage")
                .and_then(JsonValue::as_str),
            Some("unavailable")
        );
        assert_eq!(
            finished
                .get("correlation")
                .and_then(|value| value.get("parent_event_id"))
                .and_then(JsonValue::as_str),
            Some(event_id.as_str())
        );

        let (_, wait_failure) = encode(
            Producer::ExecutionMediator,
            &context,
            execution_finished(
                mediator_execution_fields(SHELL_WRAPPER_ROUTE),
                MediatorResult::WaitFailed,
            ),
        )
        .expect("mediator wait failure record");
        assert_eq!(
            wait_failure
                .get("payload")
                .and_then(|value| value.get("termination"))
                .and_then(JsonValue::as_str),
            Some("termination_unobserved")
        );
    }

    #[test]
    fn failed_ref_is_not_overwritten_by_later_worktree_status() {
        let observations: Vec<_> = baseline_checks(true)
            .map(|check| match check {
                Check::CachedReviewFixes => check.observation(exit(1), None),
                Check::WorktreeStatus => check.observation(exit(0), Some(b"0\n")),
                _ => {
                    check.observation(exit(0), Some(b"0123456789012345678901234567890123456789\n"))
                }
            })
            .collect();
        assert_eq!(observations[3], CheckObservation::Unsuccessful);
        assert_eq!(observations[4], CheckObservation::Worktree { dirty: false });
        assert!(!observations.iter().all(CheckObservation::satisfied));
        assert!(!baseline_checks(false).any(|check| check == Check::CachedReviewFixes));
        assert_eq!(
            Check::CachedReviewFixes.freshness(),
            "cached_remote_tracking_ref"
        );
    }

    #[test]
    fn launch_capture_separates_exit_signal_timeout_and_unknown() {
        let encoded_exit = JsonValue::Object(process_result_fields(Some(exit(137)), false, None));
        assert_eq!(
            encoded_exit.get("exit_code").and_then(JsonValue::as_i64),
            Some(137)
        );
        assert!(encoded_exit.get("signal").is_none());
        let signaled = JsonValue::Object(process_result_fields(
            Some(ExitStatus::from_raw(9)),
            false,
            None,
        ));
        assert_eq!(signaled.get("signal").and_then(JsonValue::as_i64), Some(9));
        assert!(signaled.get("exit_code").is_none());
        let timeout = JsonValue::Object(process_result_fields(None, true, None));
        assert_eq!(
            timeout.get("termination").and_then(JsonValue::as_str),
            Some("timed_out")
        );
        let unknown = JsonValue::Object(process_result_fields(None, false, None));
        assert_eq!(
            unknown.get("termination").and_then(JsonValue::as_str),
            Some("termination_unobserved")
        );
    }

    #[test]
    fn expected_negative_keeps_the_real_status_and_requires_evidence() {
        let expected = JsonValue::Object(process_result_fields(Some(exit(1)), false, Some(1)));
        assert_eq!(
            expected.get("exit_code").and_then(JsonValue::as_i64),
            Some(1)
        );
        assert_eq!(
            expected.get("expectation_met").and_then(JsonValue::as_bool),
            Some(true)
        );
        let unexpected = JsonValue::Object(process_result_fields(Some(exit(2)), false, Some(1)));
        assert_eq!(
            unexpected
                .get("expectation_met")
                .and_then(JsonValue::as_bool),
            Some(false)
        );
        let missing = JsonValue::Object(process_result_fields(None, false, Some(1)));
        assert!(missing.get("expectation_met").is_none());
    }

    #[test]
    fn output_requires_the_expected_scalar_shape() {
        assert_eq!(
            Check::Head.observation(exit(0), Some(b"unrelated text\n")),
            CheckObservation::Unavailable("INVALID_MEDIATOR_OUTPUT")
        );
        assert_eq!(
            Check::WorktreeStatus.observation(exit(0), Some(b"5\n")),
            CheckObservation::Worktree { dirty: true }
        );
        assert_eq!(
            Check::WorktreeStatus.observation(exit(0), Some(b"5\nwarning\n")),
            CheckObservation::Unavailable("INVALID_MEDIATOR_OUTPUT")
        );
    }

    #[test]
    fn oversized_mediator_output_is_drained_without_becoming_evidence() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf '%0512d' 0"]);
        let mediator = BaselineMediator::spawn(command).expect("spawn benign output fixture");
        let (result, output) = mediator.collect(Instant::now() + Duration::from_secs(3));
        assert!(matches!(result, MediatorResult::Waited(status) if status.success()));
        assert_eq!(output, None);
    }

    #[test]
    fn baseline_deadline_covers_stdout_retained_outside_the_mediator_group() {
        use super::super::capture::encode;

        let (reader, writer) = UnixStream::pair().expect("stdout fixture");
        let outside_group_holder = writer.try_clone().expect("keep stdout open");
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf '0\\n'"]);
        let mediator = BaselineMediator::spawn_with_output(command, reader, writer)
            .expect("spawn benign mediator fixture");
        let start = Instant::now();
        let (result, output) = mediator.collect(start + Duration::from_millis(150));
        drop(outside_group_holder);
        assert!(start.elapsed() < Duration::from_secs(3));
        assert!(matches!(result, MediatorResult::TimedOut(Some(_))));
        assert_eq!(output, None);

        let (_, record) = encode(
            Producer::Baseline,
            &Context::default(),
            execution_finished(baseline_execution_fields(Check::WorktreeStatus), result),
        )
        .expect("timeout event stays distinct from wait status");
        let payload = record.get("payload").expect("typed payload");
        assert_eq!(
            payload.get("termination").and_then(JsonValue::as_str),
            Some("timed_out")
        );
        assert_eq!(
            payload.get("mediator_reaped").and_then(JsonValue::as_bool),
            Some(true)
        );
        assert_eq!(
            payload.get("cleanup_scope").and_then(JsonValue::as_str),
            Some("outer_mediator_process_group")
        );
    }

    #[test]
    fn baseline_deadline_covers_wait_after_stdout_closes() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exec 1>&-; exec /bin/sleep 10"]);
        let mediator = BaselineMediator::spawn(command).expect("spawn benign waiting fixture");
        let start = Instant::now();
        let (result, output) = mediator.collect(start + Duration::from_millis(150));
        assert!(start.elapsed() < Duration::from_secs(3));
        assert!(
            matches!(result, MediatorResult::TimedOut(Some(status)) if status.signal().is_some())
        );
        assert_eq!(output, None);
    }
}
