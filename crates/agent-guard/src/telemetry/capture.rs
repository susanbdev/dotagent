//! Versioned observations submitted by host call sites. The wire format carries
//! provenance for interpretation and cannot authorize a state transition.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::sha256_hex;
use crate::json::JsonValue;

use super::runtime::{Submission, note_invalid_audit, submit_audit};
use super::store::Durability;

pub(crate) const SCHEMA_VERSION: u64 = 1;
pub(crate) const MAX_RECORD_BYTES: usize = 16 * 1024;
const MAX_ID_BYTES: usize = 128;
const MAX_CAUSAL_LINKS: usize = 8;
const MAX_PAYLOAD_FIELDS: usize = 48;
const MAX_PAYLOAD_DEPTH: usize = 4;
const MAX_PAYLOAD_NODES: usize = 192;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
static INSTANCE_NANOS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum EventType {
    ExecutionStarted,
    ExecutionFinished,
    PrerequisiteChecked,
    ControlDecision,
    UsageAndDisposition,
    DetectionAssessment,
    RecoveryOrEscalation,
    CaptureHealth,
}

impl EventType {
    fn as_str(self) -> &'static str {
        match self {
            Self::ExecutionStarted => "EXECUTION_STARTED",
            Self::ExecutionFinished => "EXECUTION_FINISHED",
            Self::PrerequisiteChecked => "PREREQUISITE_CHECKED",
            Self::ControlDecision => "CONTROL_DECISION",
            Self::UsageAndDisposition => "USAGE_AND_DISPOSITION",
            Self::DetectionAssessment => "DETECTION_ASSESSMENT",
            Self::RecoveryOrEscalation => "RECOVERY_OR_ESCALATION",
            Self::CaptureHealth => "CAPTURE_HEALTH",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Completeness {
    Complete,
    Partial,
    Unavailable,
}

impl Completeness {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Producer {
    Baseline,
    ExecutionMediator,
    Guard,
    Capture,
}

impl Producer {
    fn metadata(self, kind: EventType) -> (&'static str, &'static str, &'static str, &'static str) {
        match self {
            Self::Baseline => (
                "dotagent.baseline",
                "trusted_execution_mediator",
                "observed_execution",
                "local_observation",
            ),
            Self::ExecutionMediator => (
                "agent-guard.shell-wrapper",
                "trusted_execution_mediator",
                "observed_execution",
                "local_observation",
            ),
            Self::Guard => match kind {
                EventType::DetectionAssessment => (
                    "agent-guard.hook",
                    "trusted_guard",
                    "derived_assessment",
                    "unreviewed",
                ),
                EventType::UsageAndDisposition => (
                    "agent-guard.hook",
                    "trusted_guard",
                    "observed_boundary",
                    "local_observation",
                ),
                _ => (
                    "agent-guard.hook",
                    "trusted_guard",
                    "observed_action",
                    "local_observation",
                ),
            },
            Self::Capture => (
                "agent-guard.audit",
                "trusted_capture",
                "observed_storage",
                "local_observation",
            ),
        }
    }

    fn can_emit(self, kind: EventType) -> bool {
        match self {
            Self::Baseline => matches!(
                kind,
                EventType::ExecutionStarted
                    | EventType::ExecutionFinished
                    | EventType::PrerequisiteChecked
            ),
            Self::ExecutionMediator => matches!(
                kind,
                EventType::ExecutionStarted | EventType::ExecutionFinished
            ),
            Self::Guard => matches!(
                kind,
                EventType::ControlDecision
                    | EventType::UsageAndDisposition
                    | EventType::DetectionAssessment
                    | EventType::RecoveryOrEscalation
            ),
            Self::Capture => kind == EventType::CaptureHealth,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CausalLink {
    pub event_id: String,
    pub relation: &'static str,
    pub method: &'static str,
    pub algorithm_version: Option<&'static str>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Context {
    pub trace_id: Option<String>,
    pub parent_event_id: Option<String>,
    pub execution_id: Option<String>,
    pub intervention_id: Option<String>,
    pub source_event_id: Option<String>,
    pub causal_links: Vec<CausalLink>,
    pub repo_id: Option<String>,
    pub session_id: Option<String>,
    pub root_session_id: Option<String>,
    pub plan_id: Option<String>,
    pub task_id: Option<String>,
    pub allocating_parent_id: Option<String>,
    pub role: Option<String>,
    pub attempt: Option<u64>,
    pub epoch: Option<u64>,
    pub policy_id: Option<String>,
    pub bundle_id: Option<String>,
    pub profile_id: Option<String>,
    pub duration_ns: Option<u64>,
    pub occurred_at_unix_ms: Option<u64>,
}

impl Context {
    pub(crate) fn for_repo(repo: &Path) -> Self {
        Self {
            repo_id: Some(sha256_hex(repo.as_os_str().as_encoded_bytes())),
            ..Self::default()
        }
    }
}

#[derive(Debug)]
pub(crate) struct Payload {
    kind: EventType,
    completeness: Completeness,
    body: JsonValue,
    action: &'static str,
    reason_code: &'static str,
    disposition: &'static str,
}

impl Payload {
    // Kept within the telemetry module. Callers outside it use domain constructors.
    pub(super) fn new(kind: EventType, completeness: Completeness, body: JsonValue) -> Self {
        Self {
            kind,
            completeness,
            body,
            action: "observe",
            reason_code: "OBSERVATION",
            disposition: "observed",
        }
    }

    pub(super) fn with_result(
        mut self,
        action: &'static str,
        reason_code: &'static str,
        disposition: &'static str,
    ) -> Self {
        self.action = action;
        self.reason_code = reason_code;
        self.disposition = disposition;
        self
    }
}

pub(crate) fn guard_context(
    repo: &Path,
    ledger: &crate::traversal_ledger::SessionLedger,
    profile_id: Option<&str>,
) -> Context {
    Context {
        trace_id: Some(next_local_id()),
        repo_id: Context::for_repo(repo).repo_id,
        session_id: Some(ledger.session_key_hash.clone()),
        profile_id: profile_id.filter(|id| valid_id(id)).map(str::to_owned),
        epoch: u64::try_from(ledger.compaction_epoch).ok(),
        occurred_at_unix_ms: unix_time_ms(),
        ..Context::default()
    }
}

pub(crate) fn record_guard(context: &Context, payload: Payload) {
    let _ = emit(Producer::Guard, context, payload);
}

pub(crate) fn host_capture_allowed() -> bool {
    // A sandboxed process cannot opt in to host recording with hook input.
    std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() != Ok("1")
        && std::env::var("AGENT_GUARD_WORKER_LOCK").as_deref() != Ok("1")
}

pub(crate) fn intervention(context: &Context) -> Context {
    let mut context = context.clone();
    context.intervention_id = context.trace_id.clone();
    context
}

pub(crate) fn record_alert(context: &Context, alert: Payload, action: Payload) {
    let mut action_context = intervention(context);
    action_context.parent_event_id = emit(Producer::Guard, context, alert);
    record_guard(&action_context, action);
}

pub(crate) fn pagination_recovery(attempt: u64, resolved: bool) -> Payload {
    let (action, disposition) = if resolved {
        ("safe_alternative", "observed")
    } else {
        ("retry", "observed")
    };
    Payload::new(
        EventType::RecoveryOrEscalation,
        Completeness::Complete,
        object([
            ("route", text("pre_tool_hook")),
            ("operation", text("file_read")),
            ("attempt", JsonValue::Uint(attempt)),
            ("scope", text("guard_inspection_only")),
        ]),
    )
    .with_result(action, "AUTO_PAGINATION", disposition)
}

pub(crate) fn hook_decision(
    route: &'static str,
    action: &'static str,
    reason_code: &'static str,
    disposition: &'static str,
    limit: Option<(u64, &'static str)>,
) -> Payload {
    let mut body = vec![("route", text(route)), ("control", text(route))];
    if let Some((threshold, unit)) = limit {
        body.extend([
            ("threshold", JsonValue::Uint(threshold)),
            ("unit", text(unit)),
        ]);
    }
    Payload::new(
        EventType::ControlDecision,
        Completeness::Complete,
        object(body),
    )
    .with_result(action, reason_code, disposition)
}

/// Returns an event ID only after queue admission. The ID supports correlation while storage is
/// pending, and a later record can refer to an event that never reaches the audit log.
pub(crate) fn emit(producer: Producer, context: &Context, payload: Payload) -> Option<String> {
    if !host_capture_allowed() {
        return None;
    }
    if !super::runtime::prepare_audit() {
        return None;
    }
    let Ok((event_id, record)) = encode(producer, context, payload) else {
        note_invalid_audit();
        return None;
    };
    match submit_audit(record, Durability::Buffered) {
        Submission::Queued => Some(event_id),
        Submission::Dropped(_) => None,
    }
}

pub(crate) fn unix_time_ms() -> Option<u64> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(elapsed.as_millis()).ok()
}

fn next_identity() -> (String, u64, String) {
    let mut created = INSTANCE_NANOS.load(Ordering::Relaxed);
    if created == 0 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_nanos()).ok())
            .unwrap_or(1)
            .max(1);
        created =
            match INSTANCE_NANOS.compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => now,
                Err(existing) => existing,
            };
    }
    // IDs are local labels. They are neither credentials nor authentication.
    let instance = format!("{:x}-{created:x}", std::process::id());
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    let event_id = format!("{instance}-{sequence:x}");
    (instance, sequence, event_id)
}

pub(crate) fn next_local_id() -> String {
    next_identity().2
}

pub(super) fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn bounded_value(value: &JsonValue, depth: usize, nodes: &mut usize) -> bool {
    if depth > MAX_PAYLOAD_DEPTH || *nodes == MAX_PAYLOAD_NODES {
        return false;
    }
    *nodes += 1;
    match value {
        JsonValue::Str(value) => valid_id(value),
        JsonValue::Array(items) => {
            items.len() <= MAX_PAYLOAD_FIELDS
                && items
                    .iter()
                    .all(|item| bounded_value(item, depth + 1, nodes))
        }
        JsonValue::Object(fields) => {
            fields.len() <= MAX_PAYLOAD_FIELDS
                && fields.iter().enumerate().all(|(index, (key, value))| {
                    valid_id(key)
                        && !fields[..index].iter().any(|(other, _)| key == other)
                        && bounded_value(value, depth + 1, nodes)
                })
        }
        JsonValue::Number(number) => number.is_finite(),
        _ => true,
    }
}

fn text(value: &str) -> JsonValue {
    JsonValue::Str(value.to_owned())
}

fn object(fields: impl IntoIterator<Item = (&'static str, JsonValue)>) -> JsonValue {
    JsonValue::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}

fn fields(
    strings: &[(&'static str, Option<&str>)],
    integers: &[(&'static str, Option<u64>)],
) -> JsonValue {
    object(
        strings
            .iter()
            .filter_map(|(key, value)| Some((*key, text((*value)?))))
            .chain(
                integers
                    .iter()
                    .filter_map(|(key, value)| Some((*key, JsonValue::Uint((*value)?)))),
            ),
    )
}

pub(super) fn encode(
    producer: Producer,
    context: &Context,
    payload: Payload,
) -> Result<(String, JsonValue), &'static str> {
    if !producer.can_emit(payload.kind) {
        return Err("DISALLOWED_EMITTER");
    }
    if !matches!(payload.body, JsonValue::Object(_))
        || !bounded_value(&payload.body, 0, &mut 0)
        || ![payload.action, payload.reason_code, payload.disposition]
            .into_iter()
            .all(valid_id)
    {
        return Err("INVALID_EVENT_PAYLOAD");
    }
    let correlation_ids = [
        ("trace_id", context.trace_id.as_deref()),
        ("parent_event_id", context.parent_event_id.as_deref()),
        ("execution_id", context.execution_id.as_deref()),
        ("intervention_id", context.intervention_id.as_deref()),
        ("source_event_id", context.source_event_id.as_deref()),
    ];
    let work_ids = [
        ("repo_id", context.repo_id.as_deref()),
        ("session_id", context.session_id.as_deref()),
        ("root_session_id", context.root_session_id.as_deref()),
        ("plan_id", context.plan_id.as_deref()),
        ("task_id", context.task_id.as_deref()),
        (
            "allocating_parent_id",
            context.allocating_parent_id.as_deref(),
        ),
        ("role", context.role.as_deref()),
    ];
    let config_ids = [
        ("policy_id", context.policy_id.as_deref()),
        ("bundle_id", context.bundle_id.as_deref()),
        ("profile_id", context.profile_id.as_deref()),
    ];
    if correlation_ids
        .iter()
        .chain(&work_ids)
        .chain(&config_ids)
        .filter_map(|(_, id)| *id)
        .any(|id| !valid_id(id))
        || context.causal_links.len() > MAX_CAUSAL_LINKS
    {
        return Err("INVALID_CONTEXT");
    }
    let mut links = Vec::with_capacity(context.causal_links.len());
    for link in &context.causal_links {
        let valid_method = match link.method {
            "explicit" | "exact" => link.algorithm_version.is_none(),
            "heuristic" => link.algorithm_version.is_some_and(valid_id),
            _ => false,
        };
        if !valid_method || !valid_id(&link.event_id) || !valid_id(link.relation) {
            return Err("INVALID_CAUSAL_LINK");
        }
        links.push(fields(
            &[
                ("event_id", Some(&link.event_id)),
                ("relation", Some(link.relation)),
                ("method", Some(link.method)),
                ("algorithm_version", link.algorithm_version),
            ],
            &[],
        ));
    }
    let mut correlation = fields(&correlation_ids, &[]);
    if let JsonValue::Object(fields) = &mut correlation
        && !links.is_empty()
    {
        fields.push(("causal_links".into(), JsonValue::Array(links)));
    }

    let (instance_id, sequence, event_id) = next_identity();
    let (component, origin, evidence, verification) = producer.metadata(payload.kind);
    let observed = unix_time_ms();
    let record = object([
        ("schema_version", JsonValue::Uint(SCHEMA_VERSION)),
        ("event_id", text(&event_id)),
        ("event_type", text(payload.kind.as_str())),
        (
            "producer",
            object([
                ("component", text(component)),
                ("instance_id", text(&instance_id)),
                ("sequence", JsonValue::Uint(sequence)),
            ]),
        ),
        (
            "timing",
            fields(
                &[("clock", Some("system_wall_and_process_monotonic"))],
                &[
                    ("occurred_at_unix_ms", context.occurred_at_unix_ms),
                    ("observed_at_unix_ms", observed),
                    ("duration_ns", context.duration_ns),
                ],
            ),
        ),
        ("correlation", correlation),
        (
            "work",
            fields(
                &work_ids,
                &[("attempt", context.attempt), ("epoch", context.epoch)],
            ),
        ),
        ("configuration", fields(&config_ids, &[])),
        (
            "trust",
            object([
                ("origin", text(origin)),
                ("authentication", text("local_host_callsite")),
                ("evidence", text(evidence)),
                ("verification", text(verification)),
                (
                    "correlation_scope",
                    text(if producer == Producer::Guard {
                        "local_trace_and_reported_session"
                    } else {
                        "local_trace"
                    }),
                ),
            ]),
        ),
        (
            "result",
            object([
                ("action", text(payload.action)),
                ("reason_code", text(payload.reason_code)),
                ("disposition", text(payload.disposition)),
                ("completeness", text(payload.completeness.as_str())),
            ]),
        ),
        ("payload", payload.body),
    ]);
    if record.to_json_string().len() >= MAX_RECORD_BYTES {
        return Err("EVENT_TOO_LARGE");
    }
    Ok((event_id, record))
}

pub(super) fn capture_health_record(
    failed_appends: u64,
    torn_bytes: u64,
    expired_archives: u64,
) -> JsonValue {
    let context = Context {
        occurred_at_unix_ms: unix_time_ms(),
        ..Context::default()
    };
    let payload = Payload::new(
        EventType::CaptureHealth,
        if failed_appends > 0 || torn_bytes > 0 {
            Completeness::Partial
        } else {
            Completeness::Complete
        },
        object([
            ("failed_appends", JsonValue::Uint(failed_appends)),
            ("torn_bytes", JsonValue::Uint(torn_bytes)),
            ("expired_archives", JsonValue::Uint(expired_archives)),
        ]),
    )
    .with_result("record_gap", "AUDIT_STORAGE_ACTIVITY", "observed");
    encode(Producer::Capture, &context, payload).map_or(JsonValue::Null, |(_, record)| record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_provenance_and_unknown_fields_round_trip() {
        let context = Context {
            trace_id: Some("trace-1".into()),
            ..Context::default()
        };
        let record = encode(
            Producer::Guard,
            &context,
            Payload::new(
                EventType::ControlDecision,
                Completeness::Complete,
                object([]),
            ),
        )
        .unwrap()
        .1;
        assert_eq!(JsonValue::parse(&record.to_json_string()).unwrap(), record);
        assert_eq!(record.get("schema_version"), Some(&JsonValue::Uint(1)));
        let timing = record.get("timing").unwrap();
        assert!(timing.get("occurred_at_unix_ms").is_none());
        assert!(timing.get("duration_ns").is_none());
        assert_eq!(
            record
                .get("trust")
                .unwrap()
                .get("origin")
                .and_then(JsonValue::as_str),
            Some("trusted_guard")
        );
    }

    #[test]
    fn each_event_family_is_restricted_to_its_host_producer() {
        let context = Context::default();
        for (kind, allowed) in [
            (EventType::ExecutionStarted, Producer::Baseline),
            (EventType::ExecutionFinished, Producer::Baseline),
            (EventType::PrerequisiteChecked, Producer::Baseline),
            (EventType::ControlDecision, Producer::Guard),
            (EventType::UsageAndDisposition, Producer::Guard),
            (EventType::DetectionAssessment, Producer::Guard),
            (EventType::RecoveryOrEscalation, Producer::Guard),
            (EventType::CaptureHealth, Producer::Capture),
        ] {
            for producer in [
                Producer::Baseline,
                Producer::ExecutionMediator,
                Producer::Guard,
                Producer::Capture,
            ] {
                let payload = Payload::new(kind, Completeness::Complete, object([]));
                let allowed = producer == allowed
                    || (producer == Producer::ExecutionMediator
                        && matches!(
                            kind,
                            EventType::ExecutionStarted | EventType::ExecutionFinished
                        ));
                assert_eq!(encode(producer, &context, payload).is_ok(), allowed);
            }
        }
    }

    #[test]
    fn wrong_emitter_and_unbounded_or_invalid_values_are_rejected() {
        let context = Context::default();
        let payload = Payload::new(
            EventType::ExecutionStarted,
            Completeness::Complete,
            object([]),
        );
        assert_eq!(
            encode(Producer::Guard, &context, payload),
            Err("DISALLOWED_EMITTER")
        );
        let payload = Payload::new(
            EventType::ControlDecision,
            Completeness::Complete,
            object([("detail", text(&"x".repeat(MAX_RECORD_BYTES)))]),
        );
        assert_eq!(
            encode(Producer::Guard, &context, payload),
            Err("INVALID_EVENT_PAYLOAD")
        );
        let payload = Payload::new(
            EventType::ControlDecision,
            Completeness::Complete,
            object([("detail", text("raw content with spaces"))]),
        );
        assert_eq!(
            encode(Producer::Guard, &context, payload),
            Err("INVALID_EVENT_PAYLOAD")
        );
    }

    #[test]
    fn portably_named_fixture_domains_share_the_envelope_shape() {
        for fixture in [
            include_str!("../../tests/fixtures/telemetry/mcp.json"),
            include_str!("../../tests/fixtures/telemetry/sims.json"),
            include_str!("../../tests/fixtures/telemetry/envctl.json"),
        ] {
            let value = JsonValue::parse(fixture).unwrap();
            assert_eq!(
                value.get("schema_version"),
                Some(&JsonValue::Uint(SCHEMA_VERSION))
            );
            assert!(value.get("producer").is_some());
            assert!(value.get("payload").is_some());
            assert!(value.get("work").unwrap().get("task_id").is_none());
        }
    }
}
