//! Opportunistic, process-scoped snapshots of background telemetry queues.

use crate::json::JsonValue;

use super::capture::{self, Completeness, Context, EventType, Payload, Producer};
use super::runtime::Counters;
use super::store::{self, Durability};

pub(super) const REASON: &str = "ASYNC_RUNTIME_SNAPSHOT";

const COUNTERS: [&str; 8] = [
    "queued",
    "persisted",
    "failed",
    "full",
    "contended",
    "unavailable",
    "closed",
    "invalid",
];

fn encode_counters(counters: Counters) -> JsonValue {
    let values = [
        counters.queued,
        counters.persisted,
        counters.failed,
        counters.full,
        counters.contended,
        counters.unavailable,
        counters.closed,
        counters.invalid,
    ];
    JsonValue::Object(
        COUNTERS
            .into_iter()
            .zip(values)
            .map(|(name, value)| (name.to_string(), JsonValue::Uint(value)))
            .collect(),
    )
}

fn bounded_counters(value: &JsonValue) -> Option<JsonValue> {
    let fields = COUNTERS
        .into_iter()
        .map(|name| {
            Some((
                name.to_string(),
                JsonValue::Uint(value.get(name)?.as_u64()?),
            ))
        })
        .collect::<Option<Vec<_>>>()?;
    Some(JsonValue::Object(fields))
}

fn snapshot_payload(audit: JsonValue, export: JsonValue) -> JsonValue {
    JsonValue::Object(vec![
        ("scope".to_string(), JsonValue::Str("process".to_string())),
        ("audit_queue".to_string(), audit),
        ("export_queue".to_string(), export),
    ])
}

pub(super) fn read(payload: &JsonValue) -> Option<JsonValue> {
    if payload.get("scope")?.as_str()? != "process" {
        return None;
    }
    Some(snapshot_payload(
        bounded_counters(payload.get("audit_queue")?)?,
        bounded_counters(payload.get("export_queue")?)?,
    ))
}

/// Called by the persistence worker. This observation does not enqueue another
/// audit item or count itself as queue work.
pub(super) fn publish(audit: Counters, export: Counters) -> bool {
    let context = Context {
        occurred_at_unix_ms: capture::unix_time_ms(),
        ..Context::default()
    };
    let payload = Payload::new(
        EventType::CaptureHealth,
        Completeness::Complete,
        snapshot_payload(encode_counters(audit), encode_counters(export)),
    )
    .with_result("observe", REASON, "observed");
    capture::encode(Producer::Capture, &context, payload)
        .is_ok_and(|(_, record)| store::append(&record, Durability::Required).is_ok())
}
