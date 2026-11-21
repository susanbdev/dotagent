//! Typed local prerequisite checks and process observations.

use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, ExitCode, ExitStatus, Stdio};
use std::time::Instant;

use crate::json::JsonValue;

use super::capture::{
    Completeness, Context, EmitResult, EventType, Payload, Producer, emit_required, next_local_id,
    report_failure, unix_time_ms,
};

const BASELINE_ROUTE: &str = "repo_baseline_mediator";
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
    vec![
        string_field("route", BASELINE_ROUTE),
        string_field("executable", "dotagent_guard"),
        string_field("subject", "mediator_process"),
        string_field("argument_summary", check.identity()),
        string_field("nested_process_coverage", "unavailable"),
        string_field("duration_scope", "mediator_observation"),
    ]
}

fn execution_started(check: Check) -> Payload {
    Payload::new(
        EventType::ExecutionStarted,
        Completeness::Partial,
        JsonValue::Object(baseline_execution_fields(check)),
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

fn execution_finished(check: Check, status: Option<ExitStatus>, launched: bool) -> Payload {
    let mut fields = baseline_execution_fields(check);
    if launched {
        fields.extend(process_result_fields(status, false, None));
    } else {
        fields.push(string_field("termination", "launch_failed"));
    }
    let (completeness, reason, disposition) = match (status, launched) {
        (Some(status), _) if status.success() => {
            (Completeness::Partial, "MEDIATOR_COMPLETED", "finished")
        }
        (Some(_), _) => (Completeness::Partial, "MEDIATOR_UNSUCCESSFUL", "failed"),
        (None, true) => (Completeness::Unavailable, "MEDIATOR_WAIT_FAILED", "unknown"),
        (None, false) => (
            Completeness::Unavailable,
            "MEDIATOR_LAUNCH_FAILED",
            "failed",
        ),
    };
    Payload::new(
        EventType::ExecutionFinished,
        completeness,
        JsonValue::Object(fields),
    )
    .with_result("finish", reason, disposition)
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

fn launch_baseline_check(repo_root: &Path, check: Check) -> std::io::Result<std::process::Child> {
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
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
}

fn bounded_check_output(mut stdout: impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut output = Vec::with_capacity(MAX_CHECK_OUTPUT + 1);
    stdout
        .by_ref()
        .take((MAX_CHECK_OUTPUT + 1) as u64)
        .read_to_end(&mut output)?;
    if output.len() <= MAX_CHECK_OUTPUT {
        return Ok(Some(output));
    }
    // Continue draining the existing mediator's output so it can finish, with no further retention.
    io::copy(&mut stdout, &mut io::sink())?;
    Ok(None)
}

fn capture_check(repo_root: &Path, check: Check, mut context: Context) -> bool {
    context.execution_id = Some(next_local_id());
    let mut persisted = true;

    // Keep the existing command policy in the path. A refusal supplies neither a launch
    // observation nor evidence that the requested ref was absent.
    if !crate::cmd_policy::evaluate_shell_command(check.script(), repo_root, repo_root, false)
        .is_ok_and(|plan| plan.rewritten_command.is_none() && plan.write_files.is_empty())
    {
        let observation = CheckObservation::Unavailable("BASELINE_POLICY_DENIED");
        context.occurred_at_unix_ms = unix_time_ms();
        record(&context, observation.payload(check), &mut persisted);
        print_observation(check, &observation, persisted);
        return false;
    }

    let started_at = Instant::now();
    let (status, observation, launched) = match launch_baseline_check(repo_root, check) {
        Ok(mut child) => {
            context.occurred_at_unix_ms = unix_time_ms();
            context.parent_event_id = record(&context, execution_started(check), &mut persisted);
            let output = child
                .stdout
                .take()
                .and_then(|stdout| bounded_check_output(stdout).ok().flatten());
            match child.wait() {
                Ok(status) => (
                    Some(status),
                    check.observation(status, output.as_deref()),
                    true,
                ),
                Err(_) => (
                    None,
                    CheckObservation::Unavailable("MEDIATOR_WAIT_FAILED"),
                    true,
                ),
            }
        }
        Err(_) => (
            None,
            CheckObservation::Unavailable("MEDIATOR_LAUNCH_FAILED"),
            false,
        ),
    };
    context.occurred_at_unix_ms = unix_time_ms();
    context.duration_ns = u64::try_from(started_at.elapsed().as_nanos()).ok();
    context.parent_event_id = record(
        &context,
        execution_finished(check, status, launched),
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
        let repo = crate::resolve_repo_root(Path::new(env!("CARGO_MANIFEST_DIR")));
        for check in baseline_checks(true) {
            let plan =
                crate::cmd_policy::evaluate_shell_command(check.script(), &repo, &repo, false)
                    .expect("fixed read-only Git command should pass guard evaluation");
            assert!(plan.rewritten_command.is_none());
            assert!(plan.write_files.is_empty());
        }
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
        let mut stdout = io::Cursor::new(vec![b'x'; MAX_CHECK_OUTPUT * 4]);
        assert_eq!(bounded_check_output(&mut stdout).unwrap(), None);
        assert_eq!(stdout.position(), (MAX_CHECK_OUTPUT * 4) as u64);
    }
}
