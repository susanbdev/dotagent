//! Metadata-only observations from guard decisions, bounded reads, and sanitization.

use crate::budget_guard::{
    MAX_RAW_FILE_BYTES, MAX_SINGLE_LINE_BYTES, MAX_SLICED_FILE_BYTES, MAX_UNSLICED_LINES,
    ReadObservation, RuntimeProfile,
};
use crate::injection_scan::{InjectionFinding, ScanSeverity};
use crate::json::JsonValue;
use crate::sanitizer::{CompactionObservation, SanitizedOutput};
use crate::unicode_guard::UnicodeViolation;

use super::capture::{Completeness, EventType, Payload};

const TOKEN_ESTIMATOR: &str = "dotagent.bpe-heuristic.v1";

#[derive(Clone, Copy)]
pub(crate) enum Boundary {
    FileRead,
    ToolOutput,
    SubagentReturn,
    Compaction,
}

impl Boundary {
    const fn name(self) -> &'static str {
        match self {
            Self::FileRead => "file_read",
            Self::ToolOutput => "tool_output",
            Self::SubagentReturn => "subagent_return",
            Self::Compaction => "compaction_callback",
        }
    }
}

pub(crate) enum Control {
    FileRawBytes,
    FileAbsoluteBytes,
    FileSliceLines,
    FileSingleLineBytes,
    FileUnslicedLines,
    TurnTokens,
    TurnFileReads,
    ToolOutputBytes,
    SubagentReturnTokens,
}

impl Control {
    const fn fields(self) -> (&'static str, &'static str) {
        match self {
            Self::FileRawBytes => ("file_raw_bytes", "bytes"),
            Self::FileAbsoluteBytes => ("file_absolute_bytes", "bytes"),
            Self::FileSliceLines => ("file_slice_lines", "lines"),
            Self::FileSingleLineBytes => ("single_line_bytes", "bytes"),
            Self::FileUnslicedLines => ("file_unsliced_lines", "lines"),
            Self::TurnTokens => ("turn_tokens", "estimated_tokens"),
            Self::TurnFileReads => ("turn_file_reads", "calls"),
            Self::ToolOutputBytes => ("tool_output_bytes", "bytes"),
            Self::SubagentReturnTokens => ("subagent_return_tokens", "estimated_tokens"),
        }
    }
}

pub(crate) enum LimitSource {
    GuardConstant,
    EffectiveProfile,
    ProfileAndGuardConstant,
}

impl LimitSource {
    const fn name(self) -> &'static str {
        match self {
            Self::GuardConstant => "guard_constant",
            Self::EffectiveProfile => "effective_profile",
            Self::ProfileAndGuardConstant => "profile_and_guard_constant",
        }
    }
}

pub(crate) enum ControlAction {
    Deny,
    Truncate,
    Quarantine,
}

impl ControlAction {
    const fn fields(self) -> (&'static str, &'static str) {
        match self {
            Self::Deny => ("deny", "denied"),
            Self::Truncate => ("truncate", "truncated"),
            Self::Quarantine => ("quarantine", "quarantined"),
        }
    }
}

pub(crate) fn control_decision(
    boundary: Boundary,
    control: Control,
    threshold: u64,
    source: LimitSource,
    action: ControlAction,
    reason: &'static str,
) -> Payload {
    let (control, unit) = control.fields();
    let (action, disposition) = action.fields();
    let mut fields = vec![
        label("boundary", boundary.name()),
        label("control", control),
        number("threshold", threshold),
        label("unit", unit),
        label("threshold_source", source.name()),
    ];
    if unit == "estimated_tokens" {
        fields.push(label("token_estimation_method", TOKEN_ESTIMATOR));
    }
    Payload::new(
        EventType::ControlDecision,
        Completeness::Complete,
        JsonValue::Object(fields),
    )
    .with_result(action, reason, disposition)
}

pub(crate) fn read_budget_decision(
    reason: &'static str,
    profile: &RuntimeProfile,
) -> Option<Payload> {
    use Control as C;
    use LimitSource as S;
    let (control, threshold, source) = match reason {
        "FILE_BYTE_BUDGET_EXCEEDED" | "CONTENT_BYTE_BUDGET_EXCEEDED" | "FILE_BYTE_CAP_EXCEEDED" => {
            (
                C::FileRawBytes,
                profile.max_raw_file_bytes,
                S::EffectiveProfile,
            )
        }
        "FILE_ABSOLUTE_SIZE_EXCEEDED" => (
            C::FileAbsoluteBytes,
            MAX_SLICED_FILE_BYTES,
            S::GuardConstant,
        ),
        "SINGLE_LINE_BOMB_BLOCKED" => (
            C::FileSingleLineBytes,
            MAX_SINGLE_LINE_BYTES as u64,
            S::GuardConstant,
        ),
        "SLICE_LINE_CAP_EXCEEDED" => (
            C::FileSliceLines,
            profile.max_slice_lines as u64,
            S::EffectiveProfile,
        ),
        "LINE_COUNT_BUDGET_EXCEEDED" => (
            C::FileUnslicedLines,
            MAX_UNSLICED_LINES.max(profile.max_slice_lines) as u64,
            S::ProfileAndGuardConstant,
        ),
        "FILE_READ_BUDGET_EXCEEDED" => (
            C::TurnFileReads,
            profile.max_turn_file_reads as u64,
            S::EffectiveProfile,
        ),
        "TURN_TOKEN_BUDGET_EXCEEDED" => (
            C::TurnTokens,
            profile.max_turn_tokens as u64,
            S::EffectiveProfile,
        ),
        _ => return None,
    };
    Some(control_decision(
        Boundary::FileRead,
        control,
        threshold,
        source,
        ControlAction::Deny,
        reason,
    ))
}

pub(crate) fn output_budget_decision(reason: &'static str) -> Option<Payload> {
    let (control, threshold) = match reason {
        "CONTENT_BYTE_BUDGET_EXCEEDED" => (Control::ToolOutputBytes, MAX_RAW_FILE_BYTES),
        "SINGLE_LINE_BOMB_BLOCKED" => (Control::FileSingleLineBytes, MAX_SINGLE_LINE_BYTES as u64),
        _ => return None,
    };
    Some(control_decision(
        Boundary::ToolOutput,
        control,
        threshold,
        LimitSource::GuardConstant,
        ControlAction::Deny,
        reason,
    ))
}

pub(crate) fn enforcement_decision(boundary: Boundary, reason: &'static str) -> Payload {
    let (action, disposition) = ControlAction::Quarantine.fields();
    Payload::new(
        EventType::ControlDecision,
        Completeness::Complete,
        JsonValue::Object(vec![
            label("boundary", boundary.name()),
            label("control", "detector_enforcement"),
        ]),
    )
    .with_result(action, reason, disposition)
}

pub(crate) struct ReadMeasurement<'a> {
    pub observation: &'a ReadObservation,
    pub requested_offset_line: Option<usize>,
    pub requested_lines: Option<usize>,
    pub granted_lines: Option<usize>,
    /// Content bytes and lines actually emitted at this boundary, if observed.
    pub emitted: Option<(usize, usize)>,
    pub estimated_tokens: Option<usize>,
    pub sanitized: Option<&'a SanitizedOutput>,
}

impl ReadMeasurement<'_> {
    pub(crate) fn payload(&self) -> Payload {
        let read = self.observation;
        let mut fields = vec![label("boundary", Boundary::FileRead.name())];
        optional_number(
            &mut fields,
            "requested_offset_line",
            self.requested_offset_line,
        );
        optional_number(&mut fields, "requested_lines", self.requested_lines);
        optional_number(&mut fields, "granted_lines", self.granted_lines);
        optional_number(
            &mut fields,
            "selected_offset_line",
            read.selected_offset_line,
        );
        optional_number(&mut fields, "selected_lines", read.selected_lines);
        optional_number(&mut fields, "selected_bytes", read.selected_bytes);
        optional_number(
            &mut fields,
            "selected_max_line_bytes",
            read.selected_max_line_bytes,
        );
        optional_number(&mut fields, "source_lines", read.source_lines);
        optional_number(&mut fields, "read_bytes", read.read_bytes);
        if let Some(bytes) = read.source_bytes_at_stat {
            fields.push(number("source_bytes_at_stat", bytes));
        }
        if let Some(duration) = read.duration_ns {
            fields.push(number("duration_ns", duration));
        }
        if let (Some(requested), Some(granted), Some(source), Some(offset)) = (
            self.requested_lines,
            self.granted_lines.filter(|&granted| granted > 0),
            read.source_lines,
            read.selected_offset_line,
        ) {
            let requested_available =
                requested.min(source.saturating_sub(offset.saturating_sub(1)));
            fields.push(number(
                "dropped_lines",
                requested_available.saturating_sub(granted) as u64,
            ));
        }
        if let Some(available) = read.continuation_available {
            fields.push((
                "continuation_available".to_string(),
                JsonValue::Bool(available),
            ));
        }
        if let Some(sanitized) = self.sanitized {
            fields.push(number(
                "sanitized_bytes",
                sanitized.clean_ascii.len() as u64,
            ));
            transformations(&mut fields, sanitized);
        }
        emitted(&mut fields, self.emitted);
        estimated(&mut fields, self.estimated_tokens);
        let complete = self.emitted.is_some() && read.source_lines.is_some();
        usage_payload(complete, "READ_INSPECTION", fields)
    }
}

pub(crate) struct OutputMeasurement<'a> {
    pub boundary: Boundary,
    pub requested_bytes: usize,
    pub scanned_bytes: usize,
    pub sanitized: &'a SanitizedOutput,
    pub compaction: Option<&'a CompactionObservation>,
    pub estimated_tokens: Option<usize>,
    /// Content bytes and lines actually emitted at this boundary, if observed.
    pub emitted: Option<(usize, usize)>,
    pub continuation_available: Option<bool>,
}

impl OutputMeasurement<'_> {
    pub(crate) fn payload(&self) -> Payload {
        let sanitized = self.sanitized;
        let mut fields = vec![
            label("boundary", self.boundary.name()),
            number("requested_bytes", self.requested_bytes as u64),
            number("scanned_bytes", self.scanned_bytes as u64),
            number(
                "unscanned_bytes",
                self.requested_bytes.saturating_sub(self.scanned_bytes) as u64,
            ),
        ];
        transformations(&mut fields, sanitized);
        if let Some(compaction) = self.compaction {
            optional_number(&mut fields, "scanned_lines", compaction.input_lines);
            if self.scanned_bytes == self.requested_bytes {
                optional_number(&mut fields, "requested_lines", compaction.input_lines);
            }
            fields.extend([
                number("compaction_line_limit", compaction.line_limit as u64),
                number("compaction_byte_limit", compaction.byte_limit as u64),
                number("sanitized_bytes", compaction.sanitized_bytes as u64),
                number("compacted_bytes", sanitized.clean_ascii.len() as u64),
                number(
                    "line_cap_dropped_bytes",
                    compaction.line_cap_dropped_bytes as u64,
                ),
                number(
                    "byte_cap_dropped_bytes",
                    compaction.byte_cap_dropped_bytes as u64,
                ),
                number(
                    "dropped_bytes",
                    (compaction.line_cap_dropped_bytes + compaction.byte_cap_dropped_bytes) as u64,
                ),
                number("dropped_lines", sanitized.truncated_lines as u64),
                (
                    "byte_cap_applied".to_string(),
                    JsonValue::Bool(compaction.byte_cap_applied),
                ),
                (
                    "invalid_utf8_replaced".to_string(),
                    JsonValue::Bool(compaction.replaced_invalid_utf8),
                ),
            ]);
            if let Some(duration) = compaction.duration_ns {
                fields.push(number("duration_ns", duration));
            }
        } else {
            fields.push(number(
                "sanitized_bytes",
                sanitized.clean_ascii.len() as u64,
            ));
        }
        if let Some(available) = self.continuation_available {
            fields.push((
                "continuation_available".to_string(),
                JsonValue::Bool(available),
            ));
        }
        emitted(&mut fields, self.emitted);
        estimated(&mut fields, self.estimated_tokens);
        let complete = self.emitted.is_some() && self.scanned_bytes == self.requested_bytes;
        usage_payload(complete, "OUTPUT_SANITIZATION", fields)
    }
}

pub(crate) fn compaction_callback(epoch: usize) -> Payload {
    usage_payload(
        false,
        "COMPACTION_CALLBACK_OBSERVED",
        vec![
            label("boundary", Boundary::Compaction.name()),
            number("guard_compaction_epoch", epoch as u64),
            label("harness_compaction_result", "unavailable"),
        ],
    )
}

pub(crate) type DetectionSource = Boundary;

pub(crate) fn injection_alert(
    source: DetectionSource,
    finding: &InjectionFinding,
    scanned_bytes: usize,
    complete: bool,
) -> Payload {
    let signal = match finding.severity {
        ScanSeverity::TaintAndWarn => "taint_and_warn",
        ScanSeverity::ImmediateHalt => "halt",
    };
    assessment_payload(
        source,
        finding.code,
        "dotagent.injection-scan.v1",
        scanned_bytes,
        complete,
        label("detector_signal", signal),
    )
}

pub(crate) fn unicode_alert(
    source: DetectionSource,
    finding: &UnicodeViolation,
    scanned_bytes: usize,
    complete: bool,
) -> Payload {
    assessment_payload(
        source,
        finding.code,
        "dotagent.unicode-guard.v1",
        scanned_bytes,
        complete,
        number("finding_byte_offset", finding.offset as u64),
    )
}

fn assessment_payload(
    source: DetectionSource,
    category: &'static str,
    detector: &'static str,
    scanned_bytes: usize,
    complete: bool,
    feature: (String, JsonValue),
) -> Payload {
    Payload::new(
        EventType::DetectionAssessment,
        completeness(complete),
        JsonValue::Object(vec![
            label("boundary", source.name()),
            label("detector", detector),
            label("rule", category),
            label("category", category),
            label("assessment", "suspected"),
            number("scanned_bytes", scanned_bytes as u64),
            feature,
        ]),
    )
    .with_result("observe", "DETECTOR_ALERT", "suspected")
}

fn usage_payload(
    complete: bool,
    reason: &'static str,
    fields: Vec<(String, JsonValue)>,
) -> Payload {
    Payload::new(
        EventType::UsageAndDisposition,
        completeness(complete),
        JsonValue::Object(fields),
    )
    .with_result("measure", reason, "observed")
}

fn completeness(complete: bool) -> Completeness {
    if complete {
        Completeness::Complete
    } else {
        Completeness::Partial
    }
}

fn emitted(fields: &mut Vec<(String, JsonValue)>, emitted: Option<(usize, usize)>) {
    if let Some((bytes, lines)) = emitted {
        fields.push(number("emitted_bytes", bytes as u64));
        fields.push(number("emitted_lines", lines as u64));
    }
}

fn transformations(fields: &mut Vec<(String, JsonValue)>, sanitized: &SanitizedOutput) {
    fields.extend([
        number(
            "non_ascii_characters_replaced",
            sanitized.neutered_non_ascii_count as u64,
        ),
        number(
            "escape_sequences_defanged",
            sanitized.defanged_escape_count as u64,
        ),
        number(
            "control_sequences_stripped",
            sanitized.stripped_control_count as u64,
        ),
    ]);
}

fn estimated(fields: &mut Vec<(String, JsonValue)>, tokens: Option<usize>) {
    if let Some(tokens) = tokens {
        fields.push(number("estimated_tokens", tokens as u64));
        fields.push(label("token_estimation_method", TOKEN_ESTIMATOR));
    }
}

fn optional_number(fields: &mut Vec<(String, JsonValue)>, name: &str, value: Option<usize>) {
    if let Some(value) = value {
        fields.push(number(name, value as u64));
    }
}

fn label(name: &str, value: &str) -> (String, JsonValue) {
    (name.to_string(), JsonValue::Str(value.to_string()))
}

fn number(name: &str, value: u64) -> (String, JsonValue) {
    (name.to_string(), JsonValue::Uint(value))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::budget_guard::inspect_file_budget_with_observation;
    use crate::sanitizer::{neuter_to_clean_ascii, sanitize_and_compact_bytes_observed};
    use crate::telemetry::capture::{Context, Producer, encode};

    fn encode_guard(payload: Payload) -> JsonValue {
        encode(Producer::Guard, &Context::default(), payload)
            .unwrap()
            .1
    }

    #[test]
    fn bounded_read_reports_range_and_effective_limit_units() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let source = include_str!("../../Cargo.toml");
        let mut observation = ReadObservation::default();
        let (selected, metrics) = inspect_file_budget_with_observation(
            &path,
            Some(2),
            Some(2),
            2,
            MAX_RAW_FILE_BYTES,
            MAX_UNSLICED_LINES,
            &mut observation,
        )
        .unwrap();
        let sanitized = neuter_to_clean_ascii(&selected);
        let usage = encode_guard(
            ReadMeasurement {
                observation: &observation,
                requested_offset_line: Some(2),
                requested_lines: Some(8),
                granted_lines: Some(2),
                emitted: None,
                estimated_tokens: Some(metrics.estimated_tokens),
                sanitized: Some(&sanitized),
            }
            .payload(),
        );
        let body = usage.get("payload").unwrap();
        assert_eq!(
            body.get("read_bytes").and_then(JsonValue::as_u64),
            Some(source.len() as u64)
        );
        assert_eq!(
            body.get("selected_offset_line").and_then(JsonValue::as_u64),
            Some(2)
        );
        assert_eq!(
            body.get("selected_lines").and_then(JsonValue::as_u64),
            Some(2)
        );
        assert_eq!(
            body.get("dropped_lines").and_then(JsonValue::as_u64),
            Some(6)
        );
        assert_eq!(
            body.get("continuation_available")
                .and_then(JsonValue::as_bool),
            Some(true)
        );
        assert_eq!(
            body.get("sanitized_bytes").and_then(JsonValue::as_u64),
            Some(sanitized.clean_ascii.len() as u64)
        );
        assert!(body.get("emitted_bytes").is_none());
        assert!(!usage.to_json_string().contains("Cargo.toml"));

        let limit = encode_guard(control_decision(
            Boundary::FileRead,
            Control::FileSliceLines,
            150,
            LimitSource::EffectiveProfile,
            ControlAction::Truncate,
            "READ_SLICE_CLAMPED",
        ));
        let body = limit.get("payload").unwrap();
        assert_eq!(body.get("threshold").and_then(JsonValue::as_u64), Some(150));
        assert_eq!(body.get("unit").and_then(JsonValue::as_str), Some("lines"));
    }

    #[test]
    fn denied_read_distinguishes_stat_size_from_unread_content() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let mut observation = ReadObservation::default();
        let denied = inspect_file_budget_with_observation(
            &path,
            None,
            None,
            150,
            1,
            MAX_UNSLICED_LINES,
            &mut observation,
        )
        .unwrap_err();
        assert_eq!(denied.code, "FILE_BYTE_BUDGET_EXCEEDED");
        assert!(
            observation
                .source_bytes_at_stat
                .is_some_and(|size| size > 1)
        );
        assert!(observation.read_bytes.is_none());
        assert!(observation.selected_bytes.is_none());
    }

    #[test]
    fn output_usage_counts_original_sanitized_bytes_removed_by_compaction_once() {
        let raw = "some text\n".repeat(27);
        let (sanitized, compaction) = sanitize_and_compact_bytes_observed(raw.as_bytes(), 10, 4);
        assert_eq!(sanitized.clean_ascii.len(), 4);
        assert_eq!(compaction.sanitized_bytes, raw.len());
        assert!(compaction.byte_cap_applied);
        assert!(compaction.line_cap_dropped_bytes > 0);
        assert_eq!(
            compaction.line_cap_dropped_bytes + compaction.byte_cap_dropped_bytes,
            raw.len()
        );

        let usage = encode_guard(
            OutputMeasurement {
                boundary: Boundary::ToolOutput,
                requested_bytes: raw.len() + 200,
                scanned_bytes: raw.len(),
                sanitized: &sanitized,
                compaction: Some(&compaction),
                estimated_tokens: None,
                emitted: Some((
                    sanitized.clean_ascii.len(),
                    sanitized.clean_ascii.lines().count(),
                )),
                continuation_available: None,
            }
            .payload(),
        );
        let body = usage.get("payload").unwrap();
        assert_eq!(
            body.get("unscanned_bytes").and_then(JsonValue::as_u64),
            Some(200)
        );
        assert_eq!(
            body.get("dropped_bytes").and_then(JsonValue::as_u64),
            Some(raw.len() as u64)
        );
        assert_eq!(
            body.get("scanned_lines").and_then(JsonValue::as_u64),
            Some(27)
        );
        assert!(body.get("requested_lines").is_none());
        assert!(body.get("continuation_available").is_none());
        assert!(!usage.to_json_string().contains("some text"));
    }

    #[test]
    fn suspected_detection_omits_details_and_separates_enforcement() {
        let finding = InjectionFinding {
            code: "FIXTURE_CATEGORY",
            severity: ScanSeverity::ImmediateHalt,
            detail: "canary detail intentionally omitted".to_string(),
        };
        let alert = encode_guard(injection_alert(
            DetectionSource::FileRead,
            &finding,
            17,
            true,
        ));
        let enforcement = encode_guard(enforcement_decision(Boundary::FileRead, finding.code));
        let body = alert.get("payload").unwrap();
        assert_eq!(
            body.get("assessment").and_then(JsonValue::as_str),
            Some("suspected")
        );
        assert!(body.get("finding_byte_offset").is_none());
        assert!(!alert.to_json_string().contains(&finding.detail));
        assert_ne!(alert.get("event_type"), enforcement.get("event_type"));
        assert_eq!(
            enforcement
                .get("result")
                .unwrap()
                .get("action")
                .and_then(JsonValue::as_str),
            Some("quarantine")
        );
    }
}
