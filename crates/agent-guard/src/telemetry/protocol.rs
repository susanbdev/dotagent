//! Local observation datagrams. No record contains a command, destination, or callback.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::json::JsonValue;

pub(super) const MAX_FRAME: usize = 16 * 1024;
const HEADER: usize = 84;
const TAG: usize = 32;
const DOMAIN: &[u8] = b"dotagent/observation/v1\0";

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Kind {
    Event = 1,
    Legacy = 2,
    Denial = 3,
    Ballot = 4,
    Signal = 5,
    Merge = 6,
}

impl Kind {
    pub(super) fn mirror(self) -> bool {
        matches!(
            self,
            Self::Denial | Self::Ballot | Self::Signal | Self::Merge
        )
    }

    fn decode(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Event),
            2 => Some(Self::Legacy),
            3 => Some(Self::Denial),
            4 => Some(Self::Ballot),
            5 => Some(Self::Signal),
            6 => Some(Self::Merge),
            _ => None,
        }
    }
}

pub(super) struct Record {
    pub kind: Kind,
    pub body: JsonValue,
}

fn only(value: &JsonValue, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|fields| {
        fields.len() == keys.len() && fields.iter().all(|(k, _)| keys.contains(&k.as_str()))
    })
}

/// Transport only fixed tool classes; harness-supplied tool names can contain arbitrary text.
pub(crate) fn tool_class(raw: &str) -> &str {
    match raw {
        "Read" | "Write" | "Edit" | "Bash" | "Task" | "Grep" | "Glob" | "Agent" | "git" | "rg"
        | "ls" | "cat" | "sed" | "cargo" | "sh" | "bash" | "read-safe" => raw,
        _ => "other",
    }
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-:/".contains(&c))
}

fn scalar_tree(value: &JsonValue, depth: usize, budget: &mut usize) -> bool {
    if depth > 7 || *budget == 0 {
        return false;
    }
    *budget -= 1;
    match value {
        JsonValue::Object(fields) => {
            fields.len() <= 48
                && fields
                    .iter()
                    .all(|(k, v)| token(k) && scalar_tree(v, depth + 1, budget))
        }
        JsonValue::Array(values) => {
            values.len() <= 16 && values.iter().all(|v| scalar_tree(v, depth + 1, budget))
        }
        JsonValue::Str(s) => token(s) || s.is_empty() || s == "[redacted]",
        JsonValue::Number(n) => n.is_finite(),
        _ => true,
    }
}

fn fields(value: Option<&JsonValue>, keys: &[&str]) -> bool {
    value
        .and_then(JsonValue::as_object)
        .is_some_and(|entries| entries.iter().all(|(k, _)| keys.contains(&k.as_str())))
}

fn event_fields(body: &JsonValue) -> bool {
    const MEASUREMENTS: &[&str] = &[
        "argument_summary",
        "assessment",
        "attempt",
        "boundary",
        "byte_cap_applied",
        "byte_cap_dropped_bytes",
        "category",
        "check_expectation",
        "cleanup_scope",
        "compacted_bytes",
        "compaction_byte_limit",
        "compaction_line_limit",
        "continuation_available",
        "control",
        "control_sequences_stripped",
        "deadline_ms",
        "detector",
        "detector_signal",
        "dropped_bytes",
        "dropped_lines",
        "duration_ns",
        "duration_scope",
        "emitted_bytes",
        "emitted_lines",
        "escape_sequences_defanged",
        "estimated_tokens",
        "executable",
        "exit_code",
        "expectation_met",
        "expected_exit_code",
        "finding_byte_offset",
        "granted_lines",
        "guard_compaction_epoch",
        "harness_compaction_result",
        "invalid_utf8_replaced",
        "line_cap_dropped_bytes",
        "mediator_reaped",
        "nested_process_coverage",
        "non_ascii_characters_replaced",
        "observed_status",
        "operation",
        "read_bytes",
        "requested_bytes",
        "requested_check",
        "requested_lines",
        "requested_offset_line",
        "resolved_commit",
        "route",
        "rule",
        "sanitized_bytes",
        "scanned_bytes",
        "scanned_lines",
        "scope",
        "selected_bytes",
        "selected_lines",
        "selected_max_line_bytes",
        "selected_offset_line",
        "signal",
        "source_bytes_at_stat",
        "source_freshness",
        "source_lines",
        "status_scope",
        "subject",
        "termination",
        "threshold",
        "threshold_source",
        "token_estimation_method",
        "unit",
        "unscanned_bytes",
        "worktree_dirty",
    ];
    let correlation = body.get("correlation");
    let links = correlation.and_then(|c| c.get("causal_links"));
    super::capture::valid_wire_provenance(body)
        && fields(
            body.get("producer"),
            &["component", "instance_id", "sequence"],
        )
        && fields(
            body.get("timing"),
            &[
                "clock",
                "occurred_at_unix_ms",
                "observed_at_unix_ms",
                "duration_ns",
            ],
        )
        && fields(
            body.get("work"),
            &[
                "repo_id",
                "session_id",
                "root_session_id",
                "plan_id",
                "task_id",
                "allocating_parent_id",
                "role",
                "attempt",
                "epoch",
            ],
        )
        && fields(
            body.get("configuration"),
            &["policy_id", "bundle_id", "profile_id"],
        )
        && fields(
            body.get("result"),
            &["action", "reason_code", "disposition", "completeness"],
        )
        && fields(
            correlation,
            &[
                "trace_id",
                "parent_event_id",
                "execution_id",
                "intervention_id",
                "source_event_id",
                "causal_links",
            ],
        )
        && links.is_none_or(|v| {
            v.as_array().is_some_and(|a| {
                a.len() <= 8
                    && a.iter().all(|link| {
                        fields(
                            Some(link),
                            &["event_id", "relation", "method", "algorithm_version"],
                        )
                    })
            })
        })
        && fields(body.get("payload"), MEASUREMENTS)
        && body
            .get("payload")
            .and_then(JsonValue::as_object)
            .is_some_and(|f| {
                f.iter()
                    .all(|(_, v)| !matches!(v, JsonValue::Array(_) | JsonValue::Object(_)))
            })
}

pub(super) struct Received {
    pub record: Record,
    pub tag: [u8; 32],
    pub pid: u32,
    pub sequence: u64,
    pub counts: [u64; 7],
}

impl Received {
    pub(super) fn diagnostic(&self) -> JsonValue {
        let names = [
            "accepted",
            "capacity",
            "contended",
            "unavailable",
            "invalid",
            "transport",
            "closed",
        ];
        let mut fields: Vec<_> = names
            .into_iter()
            .zip(self.counts)
            .map(|(name, count)| (name.to_owned(), JsonValue::Uint(count)))
            .collect();
        fields.push(("pid".into(), JsonValue::Uint(self.pid.into())));
        fields.push(("frame_sequence".into(), JsonValue::Uint(self.sequence)));
        fields.push(("producer_confirmed_persisted".into(), JsonValue::Null));
        JsonValue::Object(fields)
    }
}

impl Record {
    fn valid(&self) -> bool {
        let body = &self.body;
        let field = |key| body.get(key).and_then(JsonValue::as_str);
        if !scalar_tree(body, 0, &mut 320) {
            return false;
        }
        match self.kind {
            Kind::Signal => {
                only(body, &["schema", "event_type", "risk_level", "tool_name"])
                    && field("event_type") == Some("PLUGIN_LATTICE_SIGNAL")
            }
            Kind::Merge => {
                only(
                    body,
                    &[
                        "schema",
                        "event_type",
                        "severity",
                        "cluster_key",
                        "issue_number",
                        "pr_number",
                        "head_sha",
                    ],
                ) && field("event_type") == Some("loop_merge")
            }
            Kind::Event => {
                only(
                    body,
                    &[
                        "schema_version",
                        "event_id",
                        "event_type",
                        "producer",
                        "timing",
                        "correlation",
                        "work",
                        "configuration",
                        "trust",
                        "result",
                        "payload",
                    ],
                ) && body.get("schema_version").and_then(JsonValue::as_u64) == Some(1)
                    && matches!(
                        field("event_type"),
                        Some(
                            "EXECUTION_STARTED"
                                | "EXECUTION_FINISHED"
                                | "PREREQUISITE_CHECKED"
                                | "CONTROL_DECISION"
                                | "USAGE_AND_DISPOSITION"
                                | "DETECTION_ASSESSMENT"
                                | "RECOVERY_OR_ESCALATION"
                        )
                    )
                    && event_fields(body)
                    && field("event_id").is_some_and(token)
                    && [
                        "producer",
                        "timing",
                        "correlation",
                        "work",
                        "configuration",
                        "trust",
                        "result",
                        "payload",
                    ]
                    .iter()
                    .all(|k| body.get(k).and_then(JsonValue::as_object).is_some())
            }
            Kind::Legacy => {
                only(
                    body,
                    &[
                        "ts",
                        "repo",
                        "session_hash",
                        "tool",
                        "code",
                        "halted",
                        "detail",
                    ],
                ) && field("session_hash")
                    .is_some_and(|s| s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                    && matches!(field("detail"), Some("" | "[redacted]"))
            }
            Kind::Denial => {
                only(
                    body,
                    &[
                        "schema",
                        "event_type",
                        "severity",
                        "repo_id",
                        "session_hash",
                        "tool",
                        "code",
                        "halted",
                        "detail",
                        "ts_unix",
                    ],
                ) && field("event_type") == Some("guard_denial")
                    && matches!(field("detail"), Some("" | "[redacted]"))
            }
            Kind::Ballot => {
                only(
                    body,
                    &[
                        "schema",
                        "event_type",
                        "severity",
                        "ballot_id",
                        "cluster_key",
                        "category",
                        "deny_code",
                        "target_bin_or_tool",
                        "canonical_shape",
                        "session_hash",
                        "role",
                        "session_tainted",
                        "grounded",
                        "vote_counted",
                        "deduplicated_retry",
                        "quarantined",
                        "session_cluster_submissions",
                        "session_total_submissions",
                        "risk_flags",
                        "ts_unix",
                    ],
                ) && field("event_type") == Some("friction_ballot")
            }
        }
    }

    pub(super) fn frame(&self, key: &[u8; 32], seq: u64, now: u64) -> Option<Vec<u8>> {
        if !self.valid() {
            return None;
        }
        let body = self.body.to_json_string();
        if body.len() > MAX_FRAME - HEADER - TAG {
            return None;
        }
        let mut out = Vec::with_capacity(HEADER + body.len() + TAG);
        out.extend_from_slice(b"DOBS\x01");
        out.push(self.kind as u8);
        out.extend_from_slice(&u16::try_from(body.len()).ok()?.to_be_bytes());
        out.extend_from_slice(&std::process::id().to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&now.to_be_bytes());
        for count in super::runtime::handoff_counts() {
            out.extend_from_slice(&count.to_be_bytes());
        }
        out.extend_from_slice(body.as_bytes());
        let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
        mac.update(DOMAIN);
        mac.update(&out);
        out.extend_from_slice(&mac.finalize().into_bytes());
        Some(out)
    }

    pub(super) fn parse(frame: &[u8], key: &[u8; 32], now: u64) -> Option<Received> {
        if !(HEADER + TAG..=MAX_FRAME).contains(&frame.len()) || frame.get(..5)? != b"DOBS\x01" {
            return None;
        }
        let kind = Kind::decode(*frame.get(5)?)?;
        let len = usize::from(u16::from_be_bytes(frame.get(6..8)?.try_into().ok()?));
        if frame.len() != HEADER + len + TAG {
            return None;
        }
        let timestamp = u64::from_be_bytes(frame.get(20..28)?.try_into().ok()?);
        if timestamp.abs_diff(now) > 30_000 {
            return None;
        }
        let (signed, tag) = frame.split_at(HEADER + len);
        let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
        mac.update(DOMAIN);
        mac.update(signed);
        mac.verify_slice(tag).ok()?;
        let body = JsonValue::parse(std::str::from_utf8(signed.get(HEADER..)?).ok()?).ok()?;
        let record = Self { kind, body };
        if !record.valid() {
            return None;
        }
        let mut counts = [0; 7];
        for (idx, value) in counts.iter_mut().enumerate() {
            let start = 28 + idx * 8;
            *value = u64::from_be_bytes(frame.get(start..start + 8)?.try_into().ok()?);
        }
        Some(Received {
            record,
            tag: tag.try_into().ok()?,
            counts,
            pid: u32::from_be_bytes(frame.get(8..12)?.try_into().ok()?),
            sequence: u64::from_be_bytes(frame.get(12..20)?.try_into().ok()?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::capture::{self, Context, Producer, hook_decision};

    fn record() -> Record {
        let (_, body) = capture::encode(
            Producer::Guard,
            &Context::default(),
            hook_decision("post_tool_hook", "allow", "PROBE", "observed", None),
        )
        .unwrap();
        Record {
            kind: Kind::Event,
            body,
        }
    }

    #[test]
    fn rejects_foreign_generation_malformed_truncated_and_expired_datagrams() {
        let key = [17; 32];
        let now = 80_000;
        let frame = record().frame(&key, 1, now).unwrap();
        assert!(Record::parse(&frame, &key, now).is_some());
        assert!(Record::parse(&frame, &[18; 32], now).is_none());
        assert!(Record::parse(&frame, &key, now + 30_001).is_none());
        for length in [0, HEADER - 1, HEADER, frame.len() - 1] {
            assert!(Record::parse(&frame[..length], &key, now).is_none());
        }
        for index in [0, 4, 5, 6, HEADER, frame.len() - 1] {
            let mut corrupt = frame.clone();
            corrupt[index] ^= 127;
            assert!(Record::parse(&corrupt, &key, now).is_none());
        }
        assert!(Record::parse(&vec![0; MAX_FRAME + 1], &key, now).is_none());
    }

    #[test]
    fn rejects_unrecognized_fields_sink_substitution_and_forged_provenance() {
        let mut event = record();
        event.kind = Kind::Ballot;
        assert!(!event.valid());
        event.kind = Kind::Event;
        let JsonValue::Object(fields) = &mut event.body else {
            unreachable!()
        };
        let (_, JsonValue::Object(payload)) =
            fields.iter_mut().find(|(k, _)| k == "payload").unwrap()
        else {
            unreachable!()
        };
        payload.push(("prompt".into(), JsonValue::Str("fixture".into())));
        assert!(event.frame(&[1; 32], 1, 1).is_none());
        let mut event = record();
        let JsonValue::Object(fields) = &mut event.body else {
            unreachable!()
        };
        let (_, trust) = fields.iter_mut().find(|(k, _)| k == "trust").unwrap();
        *trust = JsonValue::Null;
        assert!(!event.valid());
    }
}
