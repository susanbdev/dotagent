//! Opportunistic, process-scoped snapshots of background telemetry queues.

use crate::json::JsonValue;

use super::capture::{self, Completeness, Context, EventType, Payload, Producer};
use super::runtime::Counters;
use super::store::{self, Durability};

pub(super) const REASON: &str = "ASYNC_RUNTIME_SNAPSHOT";

fn encode_counters(counters: Counters, lifecycle_reported: bool) -> JsonValue {
    let fields = [
        ("queued", counters.queued),
        ("admitted", counters.queued),
        ("persisted", counters.persisted),
        ("failed", counters.failed),
        ("dropped", counters.dropped()),
        ("full", counters.full),
        ("contended", counters.contended),
        ("unavailable", counters.unavailable),
        ("closed", counters.closed),
        ("invalid", counters.invalid),
        ("transport", counters.transport),
        ("pending", counters.pending()),
    ];
    let lifecycle_counter = |count| {
        if lifecycle_reported {
            JsonValue::Uint(count)
        } else {
            JsonValue::Null
        }
    };
    JsonValue::Object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), JsonValue::Uint(value)))
            .chain([
                (
                    "worker_exits".to_owned(),
                    lifecycle_counter(counters.worker_exits),
                ),
                (
                    "worker_panics".to_owned(),
                    lifecycle_counter(counters.worker_panics),
                ),
                ("unconfirmed_at_exit".to_owned(), JsonValue::Null),
            ])
            .collect(),
    )
}

fn bounded_counters(value: &JsonValue) -> Option<JsonValue> {
    let count = |key| value.get(key)?.as_u64();
    let (worker_exits, worker_panics, lifecycle_reported) =
        match (value.get("worker_exits"), value.get("worker_panics")) {
            (None, None) | (Some(JsonValue::Null), Some(JsonValue::Null)) => (0, 0, false),
            (Some(exits), Some(panics)) => (exits.as_u64()?, panics.as_u64()?, true),
            _ => return None,
        };
    let counters = Counters {
        queued: count("queued")?,
        persisted: count("persisted")?,
        failed: count("failed")?,
        full: count("full")?,
        contended: count("contended")?,
        unavailable: count("unavailable")?,
        closed: count("closed")?,
        invalid: count("invalid")?,
        transport: count("transport").unwrap_or(0),
        worker_exits,
        worker_panics,
    };
    Some(encode_counters(counters, lifecycle_reported))
}

fn snapshot_payload(audit: JsonValue, export: JsonValue, phase: JsonValue) -> JsonValue {
    JsonValue::Object(vec![
        ("scope".to_string(), JsonValue::Str("process".to_string())),
        ("phase".to_string(), phase),
        ("audit_queue".to_string(), audit),
        ("export_queue".to_string(), export),
    ])
}

pub(super) fn status(audit: Counters, export: Counters, closing: bool) -> JsonValue {
    let mut value = snapshot_payload(
        encode_counters(audit, true),
        encode_counters(export, true),
        JsonValue::Str(if closing { "closing" } else { "active" }.to_owned()),
    );
    if let JsonValue::Object(fields) = &mut value {
        let (permission, full) = store::storage_failures();
        fields.push((
            "storage_permission_denied".into(),
            JsonValue::Uint(permission),
        ));
        fields.push(("storage_full".into(), JsonValue::Uint(full)));
    }
    value
}

pub(super) fn read(payload: &JsonValue) -> Option<JsonValue> {
    if payload.get("scope")?.as_str()? != "process" {
        return None;
    }
    let phase = match payload.get("phase") {
        None | Some(JsonValue::Null) => JsonValue::Null,
        Some(JsonValue::Str(phase)) if matches!(phase.as_str(), "active" | "closing") => {
            JsonValue::Str(phase.clone())
        }
        _ => return None,
    };
    Some(snapshot_payload(
        bounded_counters(payload.get("audit_queue")?)?,
        bounded_counters(payload.get("export_queue")?)?,
        phase,
    ))
}

/// Called by the persistence worker. This observation does not enqueue another
/// audit item or count itself as queue work.
pub(super) fn publish(audit: Counters, export: Counters, closing: bool) -> bool {
    let context = Context {
        occurred_at_unix_ms: capture::unix_time_ms(),
        ..Context::default()
    };
    let payload = Payload::new(
        EventType::CaptureHealth,
        Completeness::Partial,
        status(audit, export, closing),
    )
    .with_result("observe", REASON, "observed");
    capture::encode(Producer::Capture, &context, payload)
        .is_ok_and(|(_, record)| store::append(&record, Durability::Required).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closing_snapshot_distinguishes_pending_from_unknown_exit_outcomes() {
        let lane = encode_counters(
            Counters {
                queued: 5,
                persisted: 2,
                failed: 1,
                full: 2,
                unavailable: 1,
                ..Counters::default()
            },
            true,
        );
        let payload = snapshot_payload(lane.clone(), lane, JsonValue::Str("closing".to_owned()));
        let report = read(&payload).unwrap();
        let audit = report.get("audit_queue").unwrap();
        for (key, expected) in [("admitted", 5), ("pending", 2), ("dropped", 3)] {
            assert_eq!(audit.get(key).and_then(JsonValue::as_u64), Some(expected));
        }
        assert!(matches!(
            audit.get("unconfirmed_at_exit"),
            Some(JsonValue::Null)
        ));
    }
}
