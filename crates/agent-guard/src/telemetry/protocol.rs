//! Local observation datagrams. No record contains a command, destination, or callback.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::json::JsonValue;

pub(super) const MAX_FRAME: usize = 16 * 1024;
const HEADER: usize = 28;
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
        out.extend_from_slice(body.as_bytes());
        let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
        mac.update(DOMAIN);
        mac.update(&out);
        out.extend_from_slice(&mac.finalize().into_bytes());
        Some(out)
    }

    pub(super) fn parse(frame: &[u8], key: &[u8; 32], now: u64) -> Option<(Self, [u8; 32])> {
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
        Some((record, tag.try_into().ok()?))
    }
}
