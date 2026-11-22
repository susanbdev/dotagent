//! Bounded descriptive diagnostics over records from the protected local audit reader.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, BufRead};

use crate::json::JsonValue;

const MAX_BYTES_READ: u64 = 8 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = super::capture::MAX_RECORD_BYTES;
const MAX_RECORDS: usize = 4_096;
const MAX_IDENT_BYTES: usize = 128;
const MAX_LINKS: usize = 8;
const MAX_ANCESTORS: usize = 64;
const MAX_GROUPS: usize = 128;
const MAX_TRACE_ROWS: usize = 256;

type JsonFields = Vec<(String, JsonValue)>;

const EVENT_TYPES: &[&str] = &[
    "SESSION_ALLOCATED",
    "EXECUTION_STARTED",
    "EXECUTION_FINISHED",
    "PREREQUISITE_CHECKED",
    "CONTROL_DECISION",
    "USAGE_AND_DISPOSITION",
    "DETECTION_ASSESSMENT",
    "RECOVERY_OR_ESCALATION",
    "BUDGET_OVERRIDE_OR_LEASE_EVENT",
    "STAGE_DISPOSITION",
    "TASK_TERMINAL_OUTCOME",
    "STANDALONE_TURN_OUTCOME",
    "CAPTURE_HEALTH",
];

#[derive(Default)]
struct Coverage {
    legacy: u64,
    invalid: u64,
    unsupported: u64,
    duplicates: u64,
    partial: u64,
    unavailable: u64,
    untrusted: u64,
    missing_links: u64,
    heuristic_links: u64,
    ancestor_limit: u64,
    byte_limit: bool,
    record_limit: bool,
}

#[derive(Default)]
struct Counts {
    values: BTreeMap<String, u64>,
    overflow: u64,
}

impl Counts {
    fn add(&mut self, key: String, count: u64) {
        if let Some(previous) = self.values.get_mut(&key) {
            *previous = previous.saturating_add(count);
        } else if self.values.len() < MAX_GROUPS {
            self.values.insert(key, count);
        } else {
            self.overflow = self.overflow.saturating_add(count);
        }
    }

    fn json(self) -> JsonValue {
        let values = self
            .values
            .into_iter()
            .map(|(key, count)| (key, JsonValue::Uint(count)))
            .collect();
        object([
            ("groups", JsonValue::Object(values)),
            ("overflow", JsonValue::Uint(self.overflow)),
        ])
    }
}

#[derive(Debug)]
struct Row {
    id: String,
    kind: &'static str,
    component: Option<String>,
    instance: Option<String>,
    sequence: Option<u64>,
    duration_ns: Option<u64>,
    writer_wait_us: Option<u64>,
    elapsed_to_recovery_ns: Option<u64>,
    repo: Option<String>,
    trace: Option<String>,
    execution: Option<String>,
    intervention: Option<String>,
    source: Option<String>,
    parent: Option<String>,
    links: Vec<String>,
    heuristic_links: u64,
    authenticated: bool,
    origin: Option<String>,
    action: Option<String>,
    decision: Option<String>,
    completeness: Option<String>,
    control: Option<String>,
    threshold: Option<u64>,
    unit: Option<String>,
    threshold_source: Option<String>,
    route: Option<String>,
    dropped_bytes: Option<u64>,
    dropped_lines: Option<u64>,
    continuation: Option<bool>,
    assessment: Option<String>,
    verification: Option<String>,
    reason: Option<String>,
    failed_appends: Option<u64>,
    torn_bytes: Option<u64>,
    expired_archives: Option<u64>,
}

fn text(fields: &JsonValue, key: &str) -> Option<String> {
    let raw = fields.get(key)?.as_str()?;
    safe_identifier(raw).then(|| raw.to_string())
}

fn identifier(fields: &JsonValue, key: &str) -> Option<String> {
    let raw = fields.get(key)?.as_str()?;
    super::capture::valid_id(raw).then(|| raw.to_string())
}

fn safe_identifier(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= MAX_IDENT_BYTES
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

fn number(fields: &JsonValue, key: &str) -> Option<u64> {
    fields.get(key)?.as_u64()
}

impl Row {
    fn parse(record: &JsonValue, coverage: &mut Coverage) -> Option<Self> {
        // Typed records share the legacy audit stream and carry their own schema marker.
        if record.get("schema_version").is_none() {
            coverage.legacy += 1;
            return None;
        }
        let kind = record.get("event_type").and_then(JsonValue::as_str);
        let kind = EVENT_TYPES
            .iter()
            .copied()
            .find(|value| Some(*value) == kind);
        let Some(kind) = kind.filter(|_| number(record, "schema_version") == Some(1)) else {
            coverage.unsupported += 1;
            return None;
        };
        let Some(id) = identifier(record, "event_id") else {
            coverage.invalid += 1;
            return None;
        };
        let producer = record.get("producer").unwrap_or(&JsonValue::Null);
        let timing = record.get("timing").unwrap_or(&JsonValue::Null);
        let correlation = record.get("correlation").unwrap_or(&JsonValue::Null);
        let work = record.get("work").unwrap_or(&JsonValue::Null);
        let trust = record.get("trust").unwrap_or(&JsonValue::Null);
        let result = record.get("result").unwrap_or(&JsonValue::Null);
        let payload = record.get("payload").unwrap_or(&JsonValue::Null);

        let origin = text(trust, "origin");
        let authenticated = matches!(
            origin.as_deref(),
            Some(
                "trusted_execution_mediator"
                    | "trusted_coordinator"
                    | "trusted_guard"
                    | "trusted_capture"
                    | "human_assessment"
            )
        ) && matches!(
            trust.get("authentication").and_then(JsonValue::as_str),
            Some("local_host_callsite" | "authenticated")
        );
        let mut links = Vec::new();
        let mut heuristic_links = 0;
        if authenticated {
            if let Some(values) = correlation
                .get("causal_links")
                .and_then(JsonValue::as_array)
            {
                for link in values.iter().take(MAX_LINKS) {
                    if matches!(
                        link.get("method").and_then(JsonValue::as_str),
                        Some("explicit" | "exact")
                    ) {
                        links.extend(identifier(link, "event_id"));
                    } else {
                        heuristic_links += 1;
                    }
                }
                heuristic_links += values.len().saturating_sub(MAX_LINKS) as u64;
            }
        }

        Some(Self {
            id,
            kind,
            component: text(producer, "component"),
            instance: text(producer, "instance_id"),
            sequence: number(producer, "sequence"),
            duration_ns: number(timing, "duration_ns").or_else(|| number(payload, "duration_ns")),
            writer_wait_us: number(timing, "writer_wait_us"),
            elapsed_to_recovery_ns: number(payload, "elapsed_to_recovery_ns"),
            repo: text(work, "repo_id"),
            trace: authenticated
                .then(|| identifier(correlation, "trace_id"))
                .flatten(),
            execution: authenticated
                .then(|| identifier(correlation, "execution_id"))
                .flatten(),
            intervention: authenticated
                .then(|| identifier(correlation, "intervention_id"))
                .flatten(),
            source: authenticated
                .then(|| identifier(correlation, "source_event_id"))
                .flatten(),
            parent: authenticated
                .then(|| identifier(correlation, "parent_event_id"))
                .flatten(),
            links,
            heuristic_links,
            authenticated,
            origin,
            action: text(result, "action"),
            decision: text(result, "disposition"),
            completeness: text(result, "completeness"),
            control: text(payload, "control"),
            threshold: number(payload, "threshold"),
            unit: text(payload, "unit"),
            threshold_source: text(payload, "threshold_source"),
            route: text(payload, "route").or_else(|| text(payload, "boundary")),
            dropped_bytes: number(payload, "dropped_bytes"),
            dropped_lines: number(payload, "dropped_lines"),
            continuation: payload
                .get("continuation_available")
                .and_then(JsonValue::as_bool),
            assessment: text(payload, "assessment"),
            verification: text(trust, "verification"),
            reason: text(result, "reason_code"),
            failed_appends: number(payload, "failed_appends"),
            torn_bytes: number(payload, "torn_bytes"),
            expired_archives: number(payload, "expired_archives"),
        })
    }

    fn trace_json(&self) -> JsonValue {
        let mut fields = vec![
            ("event_id".to_string(), JsonValue::Str(self.id.clone())),
            (
                "event_type".to_string(),
                JsonValue::Str(self.kind.to_string()),
            ),
        ];
        for (key, value) in [
            ("trace_id", &self.trace),
            ("producer", &self.component),
            ("producer_instance_id", &self.instance),
            ("execution_id", &self.execution),
            ("intervention_id", &self.intervention),
            ("parent_event_id", &self.parent),
            ("origin", &self.origin),
            ("action", &self.action),
            ("disposition", &self.decision),
            ("completeness", &self.completeness),
            ("control", &self.control),
            ("unit", &self.unit),
            ("threshold_source", &self.threshold_source),
            ("route", &self.route),
        ] {
            if let Some(value) = value {
                fields.push((key.to_string(), JsonValue::Str(value.clone())));
            }
        }
        for (key, value) in [
            ("producer_sequence", self.sequence),
            ("duration_ns", self.duration_ns),
            ("writer_wait_us", self.writer_wait_us),
            ("threshold", self.threshold),
            ("dropped_bytes", self.dropped_bytes),
            ("dropped_lines", self.dropped_lines),
        ] {
            if let Some(value) = value {
                fields.push((key.to_string(), JsonValue::Uint(value)));
            }
        }
        if let Some(value) = self.continuation {
            fields.push(("continuation_available".to_string(), JsonValue::Bool(value)));
        }
        fields.push((
            "causal_event_ids".to_string(),
            JsonValue::Array(self.links.iter().cloned().map(JsonValue::Str).collect()),
        ));
        JsonValue::Object(fields)
    }
}

enum Line {
    End,
    Record,
    Invalid,
}

fn read_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> io::Result<Line> {
    line.clear();
    let mut oversized = false;
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            return Ok(if oversized || !line.is_empty() {
                Line::Invalid
            } else {
                Line::End
            });
        }
        let newline = buf.iter().position(|b| *b == b'\n');
        let take = newline.map_or(buf.len(), |index| index + 1);
        if !oversized && line.len() + take <= MAX_RECORD_BYTES {
            line.extend_from_slice(&buf[..take]);
        } else {
            oversized = true;
        }
        reader.consume(take);
        if newline.is_some() {
            return Ok(if oversized {
                Line::Invalid
            } else {
                Line::Record
            });
        }
    }
}

struct Window {
    rows: Vec<Row>,
    aliases: BTreeMap<String, String>,
    coverage: Coverage,
}

fn read_rows(reader: &mut impl BufRead) -> io::Result<Window> {
    let mut reader = std::io::Read::take(reader, MAX_BYTES_READ);
    let mut coverage = Coverage::default();
    let mut row_ids = BTreeSet::new();
    let mut projected = BTreeMap::<_, String>::new();
    let mut aliases = BTreeMap::new();
    let mut line = Vec::new();
    let mut rows = Vec::new();
    let mut exhausted_records = true;
    for _ in 0..MAX_RECORDS {
        match read_line(&mut reader, &mut line)? {
            Line::End => {
                exhausted_records = false;
                break;
            }
            Line::Invalid => {
                coverage.invalid += 1;
                continue;
            }
            Line::Record => {}
        }
        let Ok(value) = std::str::from_utf8(&line)
            .map_err(|_| ())
            .and_then(|line| JsonValue::parse(line).map_err(|_| ()))
        else {
            coverage.invalid += 1;
            continue;
        };
        let Some(row) = Row::parse(&value, &mut coverage) else {
            continue;
        };
        let scope = |id: &str| (row.authenticated, id.to_string());
        if !row_ids.insert(scope(&row.id)) {
            coverage.duplicates += 1;
            continue;
        }
        if let Some(source) = row.source.as_ref() {
            let key = (row.repo.clone(), row.kind, source.clone());
            if let Some(original) = projected.get(&key) {
                aliases.insert(row.id, original.clone());
                coverage.duplicates += 1;
                continue;
            }
            projected.insert(key, row.id.clone());
        }
        rows.push(row);
    }
    if reader.limit() == 0 {
        // Take reports an empty buffer at its artificial EOF. Check the underlying
        // buffer without consuming an extra byte from outside the scan window.
        coverage.byte_limit = !reader.get_mut().fill_buf()?.is_empty();
    } else if exhausted_records {
        coverage.record_limit = !reader.fill_buf()?.is_empty();
    }
    Ok(Window {
        rows,
        aliases,
        coverage,
    })
}

fn links(
    rows: &[Row],
    aliases: &BTreeMap<String, String>,
    coverage: &mut Coverage,
) -> Vec<Vec<usize>> {
    let index: BTreeMap<_, _> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row.authenticated)
        .map(|(index, row)| (row.id.as_str(), index))
        .collect();
    rows.iter()
        .map(|row| {
            coverage.heuristic_links += row.heuristic_links;
            row.parent
                .iter()
                .chain(&row.links)
                .filter_map(|id| {
                    let canonical = aliases.get(id).unwrap_or(id);
                    let target = index.get(canonical.as_str()).copied();
                    coverage.missing_links += u64::from(target.is_none());
                    target
                })
                .collect()
        })
        .collect()
}

fn scope(rows: &[Row], parents: &[Vec<usize>], trace: Option<&str>) -> BTreeSet<usize> {
    let Some(trace) = trace else {
        return (0..rows.len()).collect();
    };
    let mut neighbors = vec![Vec::new(); rows.len()];
    let mut intervention_anchor = BTreeMap::new();
    let mut execution_anchor = BTreeMap::new();
    let mut queue = VecDeque::new();
    for (index, row) in rows.iter().enumerate() {
        if row.trace.as_deref() == Some(trace) {
            queue.push_back(index);
        }
        for target in &parents[index] {
            neighbors[index].push(*target);
            neighbors[*target].push(index);
        }
        for (id, anchors) in [
            (row.intervention.as_ref(), &mut intervention_anchor),
            (row.execution.as_ref(), &mut execution_anchor),
        ] {
            if let Some(id) = id {
                let anchor = *anchors
                    .entry((row.repo.as_deref(), id.as_str()))
                    .or_insert(index);
                if anchor != index {
                    neighbors[index].push(anchor);
                    neighbors[anchor].push(index);
                }
            }
        }
    }
    let mut selected = BTreeSet::new();
    while let Some(index) = queue.pop_front() {
        if selected.insert(index) {
            queue.extend(neighbors[index].iter().copied());
        }
    }
    selected
}

fn ancestry(index: usize, parents: &[Vec<usize>], coverage: &mut Coverage) -> BTreeSet<usize> {
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([index]);
    while let Some(index) = queue.pop_front() {
        if seen.contains(&index) {
            continue;
        }
        if seen.len() == MAX_ANCESTORS {
            coverage.ancestor_limit += 1;
            break;
        }
        seen.insert(index);
        queue.extend(parents[index].iter().copied());
    }
    seen
}

#[derive(Default)]
struct Chain {
    interventions: u64,
    retries: u64,
    safe_alternatives: u64,
    escalations: u64,
    recovered: bool,
    abandoned: bool,
    recovery_durations: BTreeSet<u64>,
    outcomes: BTreeSet<String>,
}

impl Chain {
    fn observe(&mut self, row: &Row, is_anchor: bool) {
        if is_anchor && row.kind == "CONTROL_DECISION" {
            self.interventions += 1;
        }
        if row.authenticated && row.kind == "RECOVERY_OR_ESCALATION" {
            match row.action.as_deref() {
                Some("retry") => self.retries += 1,
                Some("safe_alternative") => self.safe_alternatives += 1,
                Some("escalate") => self.escalations += 1,
                Some("abandon") => self.abandoned = true,
                _ => {}
            }
            if matches!(row.decision.as_deref(), Some("succeeded" | "recovered"))
                && matches!(
                    row.action.as_deref(),
                    Some("retry" | "safe_alternative" | "recover")
                )
            {
                self.recovered = true;
                self.recovery_durations.extend(row.elapsed_to_recovery_ns);
            }
        }
        if row.authenticated
            && matches!(
                (row.kind, row.origin.as_deref()),
                ("TASK_TERMINAL_OUTCOME", Some("trusted_coordinator"))
                    | ("STANDALONE_TURN_OUTCOME", Some("trusted_guard"))
            )
            && row.completeness.as_deref() == Some("complete")
        {
            self.outcomes.extend(row.decision.clone());
        }
    }

    fn status(&self) -> &'static str {
        if self.interventions == 0 || (self.recovered && self.abandoned) {
            "unknown"
        } else if self.recovered && self.retries > 0 {
            "recovered_after_retry"
        } else if self.recovered {
            "recovered_directly"
        } else if self.abandoned {
            "abandonment_observed"
        } else if self.escalations > 0 {
            "escalated"
        } else {
            "unknown"
        }
    }

    fn json(self, id: String) -> JsonValue {
        let status = self.status();
        let recovery_duration = if self.recovery_durations.len() == 1 {
            self.recovery_durations.first().copied()
        } else {
            None
        };
        let terminal_outcome = if self.outcomes.len() == 1 {
            self.outcomes.into_iter().next()
        } else {
            None
        };
        object([
            ("intervention_id", JsonValue::Str(id)),
            ("status", JsonValue::Str(status.to_string())),
            ("decisions", JsonValue::Uint(self.interventions)),
            ("retries", JsonValue::Uint(self.retries)),
            ("safe_alternatives", JsonValue::Uint(self.safe_alternatives)),
            ("escalations", JsonValue::Uint(self.escalations)),
            (
                "recovery_duration_ns",
                recovery_duration.map_or(JsonValue::Null, JsonValue::Uint),
            ),
            (
                "terminal_outcome",
                terminal_outcome.map_or(JsonValue::Null, JsonValue::Str),
            ),
        ])
    }
}

fn correlation(
    rows: &[Row],
    parents: &[Vec<usize>],
    selected: &BTreeSet<usize>,
    coverage: &mut Coverage,
) -> (JsonValue, JsonValue) {
    let mut chains = BTreeMap::new();
    let mut findings = BTreeMap::<usize, BTreeMap<usize, &str>>::new();
    let mut superseded = BTreeSet::new();
    let mut unlinked_corrections = 0;
    let mut omitted_chains = 0;
    for index in selected {
        let row = &rows[*index];
        let ancestors = ancestry(*index, parents, coverage);
        let intervention_ids: BTreeSet<_> = ancestors
            .iter()
            .filter_map(|ancestor| {
                let anchor = &rows[*ancestor];
                anchor
                    .intervention
                    .as_ref()
                    .map(|id| (anchor.repo.as_deref(), id.as_str()))
            })
            .collect();
        for key in intervention_ids {
            if chains.len() == MAX_GROUPS && !chains.contains_key(&key) {
                omitted_chains += 1;
                continue;
            }
            let chain: &mut Chain = chains.entry(key).or_default();
            chain.observe(row, row.intervention.as_deref() == Some(key.1));
        }
        if row.kind != "DETECTION_ASSESSMENT" || !row.authenticated {
            continue;
        }
        match row.assessment.as_deref() {
            Some("suspected") => {
                findings.entry(*index).or_default();
            }
            Some(assessment @ ("confirmed" | "dismissed"))
                if row.origin.as_deref() == Some("human_assessment")
                    && matches!(row.verification.as_deref(), Some("verified" | "reviewed")) =>
            {
                let mut has_root = false;
                for ancestor in ancestors.iter().filter(|ancestor| *ancestor != index) {
                    let candidate = &rows[*ancestor];
                    if candidate.kind != "DETECTION_ASSESSMENT" {
                        continue;
                    }
                    match candidate.assessment.as_deref() {
                        Some("suspected") => {
                            findings
                                .entry(*ancestor)
                                .or_default()
                                .insert(*index, assessment);
                            has_root = true;
                        }
                        Some("confirmed" | "dismissed") => {
                            superseded.insert(*ancestor);
                        }
                        _ => {}
                    }
                }
                unlinked_corrections += u64::from(!has_root);
            }
            _ => {}
        }
    }
    let mut statuses = Counts::default();
    let chain_details = chains
        .into_iter()
        .map(|((_, id), chain)| {
            statuses.add(chain.status().to_string(), 1);
            chain.json(id.to_string())
        })
        .collect();
    let mut finding_counts = Counts::default();
    for assessments in findings.into_values() {
        let active: BTreeSet<_> = assessments
            .into_iter()
            .filter(|(event, _)| !superseded.contains(event))
            .map(|(_, assessment)| assessment)
            .collect();
        let status = match active.len() {
            0 => "unreviewed",
            1 => active.first().copied().unwrap_or("unknown"),
            _ => "conflicting_assessments",
        };
        finding_counts.add(status.to_string(), 1);
    }
    (
        object([
            ("statuses", statuses.json()),
            ("chains", JsonValue::Array(chain_details)),
            (
                "omitted_chain_associations",
                JsonValue::Uint(omitted_chains),
            ),
        ]),
        object([
            ("findings", finding_counts.json()),
            (
                "unlinked_corrections",
                JsonValue::Uint(unlinked_corrections),
            ),
            ("detection_accuracy", JsonValue::Null),
        ]),
    )
}

fn object<const N: usize>(pairs: [(&str, JsonValue); N]) -> JsonValue {
    let fields: JsonFields = pairs
        .into_iter()
        .map(|(name, value)| (name.to_string(), value))
        .collect();
    JsonValue::Object(fields)
}

/// Read only complete records from a bounded input window. The caller supplies the existing
/// human-authorized reader or an in-memory fixture. Output contains no domain payload bodies.
pub(crate) fn analyze(reader: &mut impl BufRead, trace: Option<&str>) -> io::Result<JsonValue> {
    if trace.is_some_and(|trace| !super::capture::valid_id(trace)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid trace ID",
        ));
    }
    let Window {
        rows,
        aliases,
        mut coverage,
    } = read_rows(reader)?;
    let parents = links(&rows, &aliases, &mut coverage);
    let selected = scope(&rows, &parents, trace);
    let (interventions, assessments) = correlation(&rows, &parents, &selected, &mut coverage);
    let mut decisions = Counts::default();
    let mut durations = Counts::default();
    let mut health = Counts::default();
    let mut starts = BTreeSet::new();
    let mut finishes = BTreeSet::new();
    let mut truncations = 0;
    let mut dropped_bytes = 0u64;
    let mut dropped_lines = 0u64;
    let mut missing_drop_measurements = 0u64;
    let mut missing_execution_ids = 0u64;
    let mut failed_appends = 0u64;
    let mut torn_bytes = 0u64;
    let mut expired_archives = 0u64;
    let mut writer_wait_samples = 0u64;
    let mut writer_wait_sum_us = 0u64;
    let mut continuation_available = 0;
    let mut continuation_unknown = 0;
    let mut trace_rows = Vec::new();
    for index in &selected {
        let row = &rows[*index];
        match row.completeness.as_deref() {
            Some("complete") => {}
            Some("partial") => coverage.partial += 1,
            _ => coverage.unavailable += 1,
        }
        if !row.authenticated {
            coverage.untrusted += 1;
            continue;
        }
        match row.kind {
            "CONTROL_DECISION" => {
                let control = row.control.as_deref().unwrap_or("unknown_control");
                let route = row.route.as_deref().unwrap_or("unknown_route");
                let decision = row.decision.as_deref().unwrap_or("unknown_decision");
                let unit = row.unit.as_deref().unwrap_or("unknown_unit");
                let source = row.threshold_source.as_deref().unwrap_or("unknown_source");
                let threshold = row
                    .threshold
                    .map_or_else(|| "unknown".to_string(), |n| n.to_string());
                decisions.add(
                    format!("{control}/{route}/{decision}/{threshold}/{unit}/{source}"),
                    1,
                );
            }
            "EXECUTION_STARTED" => {
                starts.extend(row.execution.as_ref().map(|id| (row.repo.as_ref(), id)));
                missing_execution_ids += u64::from(row.execution.is_none());
            }
            "EXECUTION_FINISHED" => {
                finishes.extend(row.execution.as_ref().map(|id| (row.repo.as_ref(), id)));
                missing_execution_ids += u64::from(row.execution.is_none());
            }
            "USAGE_AND_DISPOSITION"
                if row.decision.as_deref() == Some("truncated")
                    || row.dropped_bytes.is_some_and(|bytes| bytes > 0)
                    || row.dropped_lines.is_some_and(|lines| lines > 0) =>
            {
                truncations += 1;
                dropped_bytes = dropped_bytes.saturating_add(row.dropped_bytes.unwrap_or(0));
                dropped_lines = dropped_lines.saturating_add(row.dropped_lines.unwrap_or(0));
                missing_drop_measurements +=
                    u64::from(row.dropped_bytes.is_none() && row.dropped_lines.is_none());
                continuation_available += u64::from(row.continuation == Some(true));
                continuation_unknown += u64::from(row.continuation.is_none());
            }
            "CAPTURE_HEALTH" => {
                health.add(row.reason.as_deref().unwrap_or("unknown").to_string(), 1);
                failed_appends = failed_appends.saturating_add(row.failed_appends.unwrap_or(0));
                torn_bytes = torn_bytes.saturating_add(row.torn_bytes.unwrap_or(0));
                expired_archives =
                    expired_archives.saturating_add(row.expired_archives.unwrap_or(0));
            }
            _ => {}
        }
        if let Some(duration) = row.duration_ns {
            durations.add(row.kind.to_string(), duration);
        }
        if let Some(wait) = row.writer_wait_us {
            writer_wait_samples += 1;
            writer_wait_sum_us = writer_wait_sum_us.saturating_add(wait);
        }
        if trace.is_some() && trace_rows.len() < MAX_TRACE_ROWS {
            trace_rows.push(row.trace_json());
        }
    }
    let omitted_trace_rows = if trace.is_some() {
        selected.len().saturating_sub(trace_rows.len()) as u64
    } else {
        0
    };
    Ok(object([
        ("records_in_scope", JsonValue::Uint(selected.len() as u64)),
        (
            "decisions_by_control_route_disposition_threshold_unit_source",
            decisions.json(),
        ),
        ("overlapping_duration_ns_by_event_type", durations.json()),
        (
            "observed_writer_wait",
            object([
                ("samples", JsonValue::Uint(writer_wait_samples)),
                (
                    "sum_us",
                    if writer_wait_samples == 0 {
                        JsonValue::Null
                    } else {
                        JsonValue::Uint(writer_wait_sum_us)
                    },
                ),
            ]),
        ),
        ("interventions", interventions),
        ("assessments", assessments),
        (
            "unfinished_executions_in_window",
            JsonValue::Uint(starts.difference(&finishes).count() as u64),
        ),
        (
            "truncation",
            object([
                ("events", JsonValue::Uint(truncations)),
                ("measured_dropped_bytes", JsonValue::Uint(dropped_bytes)),
                ("measured_dropped_lines", JsonValue::Uint(dropped_lines)),
                (
                    "unknown_drop_measurements",
                    JsonValue::Uint(missing_drop_measurements),
                ),
                (
                    "continuation_available",
                    JsonValue::Uint(continuation_available),
                ),
                (
                    "continuation_unknown",
                    JsonValue::Uint(continuation_unknown),
                ),
            ]),
        ),
        (
            "capture_health",
            object([
                ("record_counts_by_reason", health.json()),
                ("recorded_failed_appends", JsonValue::Uint(failed_appends)),
                ("recorded_torn_bytes", JsonValue::Uint(torn_bytes)),
                (
                    "recorded_expired_archives",
                    JsonValue::Uint(expired_archives),
                ),
            ]),
        ),
        (
            "coverage",
            object([
                ("legacy_records_in_input", JsonValue::Uint(coverage.legacy)),
                (
                    "invalid_or_incomplete_records_in_input",
                    JsonValue::Uint(coverage.invalid),
                ),
                (
                    "unsupported_schema_or_payload_in_input",
                    JsonValue::Uint(coverage.unsupported),
                ),
                (
                    "duplicate_records_in_input",
                    JsonValue::Uint(coverage.duplicates),
                ),
                (
                    "partial_records_in_scope",
                    JsonValue::Uint(coverage.partial),
                ),
                (
                    "unavailable_records_in_scope",
                    JsonValue::Uint(coverage.unavailable),
                ),
                (
                    "untrusted_records_excluded_from_metrics",
                    JsonValue::Uint(coverage.untrusted),
                ),
                (
                    "execution_records_missing_ids",
                    JsonValue::Uint(missing_execution_ids),
                ),
                (
                    "missing_links_in_input",
                    JsonValue::Uint(coverage.missing_links),
                ),
                (
                    "heuristic_links_in_input",
                    JsonValue::Uint(coverage.heuristic_links),
                ),
                (
                    "ancestor_search_limit_hits",
                    JsonValue::Uint(coverage.ancestor_limit),
                ),
                (
                    "input_byte_limit_reached",
                    JsonValue::Bool(coverage.byte_limit),
                ),
                (
                    "input_record_limit_reached",
                    JsonValue::Bool(coverage.record_limit),
                ),
                ("omitted_trace_rows", JsonValue::Uint(omitted_trace_rows)),
            ]),
        ),
        ("trace", JsonValue::Array(trace_rows)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    fn string(value: &str) -> JsonValue {
        JsonValue::Str(value.to_string())
    }

    fn fixture(
        id: &str,
        kind: &str,
        origin: &str,
        correlation: JsonValue,
        action: &str,
        disposition: &str,
        payload: JsonValue,
    ) -> JsonValue {
        object([
            ("schema_version", JsonValue::Uint(1)),
            ("event_id", string(id)),
            ("event_type", string(kind)),
            ("work", object([("repo_id", string("repo-id"))])),
            ("correlation", correlation),
            (
                "trust",
                object([
                    ("origin", string(origin)),
                    ("authentication", string("local_host_callsite")),
                    ("verification", string("reviewed")),
                ]),
            ),
            (
                "result",
                object([
                    ("action", string(action)),
                    ("disposition", string(disposition)),
                    ("completeness", string("complete")),
                ]),
            ),
            ("payload", payload),
        ])
    }

    fn jsonl(rows: &[JsonValue]) -> String {
        rows.iter()
            .map(|row| format!("{}\n", row.to_json_string()))
            .collect()
    }

    fn link(id: &str, method: &str) -> JsonValue {
        object([
            ("event_id", string(id)),
            ("relation", string("responds_to")),
            ("method", string(method)),
        ])
    }

    fn find<'a>(mut node: &'a JsonValue, path: &[&str]) -> &'a JsonValue {
        for key in path {
            node = node.get(key).unwrap_or_else(|| panic!("missing {key}"));
        }
        node
    }

    #[test]
    fn record_limit_reports_omitted_input_only_when_more_bytes_follow() {
        let frame = b"{}\n";
        let mut raw = frame.repeat(MAX_RECORDS);
        let exact = read_rows(&mut Cursor::new(&raw)).unwrap();
        assert_eq!(exact.coverage.legacy, MAX_RECORDS as u64);
        assert!(!exact.coverage.record_limit);
        assert!(!exact.coverage.byte_limit);

        let consumed = raw.len() as u64;
        raw.extend_from_slice(frame);
        let mut reader = Cursor::new(&raw);
        let over = read_rows(&mut reader).unwrap();
        assert_eq!(over.coverage.legacy, MAX_RECORDS as u64);
        assert!(over.coverage.record_limit);
        assert!(!over.coverage.byte_limit);
        assert_eq!(reader.position(), consumed);
    }

    #[test]
    fn byte_limit_checks_actual_eof_at_the_shared_byte_and_record_boundary() {
        let mut frame = vec![b' '; MAX_BYTES_READ as usize / MAX_RECORDS];
        frame[..2].copy_from_slice(b"{}");
        *frame.last_mut().unwrap() = b'\n';
        let mut raw = frame.repeat(MAX_RECORDS);
        assert_eq!(raw.len() as u64, MAX_BYTES_READ);
        let exact = read_rows(&mut Cursor::new(&raw)).unwrap();
        assert_eq!(exact.coverage.legacy, MAX_RECORDS as u64);
        assert!(!exact.coverage.record_limit);
        assert!(!exact.coverage.byte_limit);

        raw.extend_from_slice(b"{}\n");
        let mut reader = Cursor::new(&raw);
        let over = read_rows(&mut reader).unwrap();
        assert_eq!(over.coverage.legacy, MAX_RECORDS as u64);
        assert!(!over.coverage.record_limit);
        assert!(over.coverage.byte_limit);
        assert_eq!(reader.position(), MAX_BYTES_READ);
    }

    #[test]
    fn retries_and_alternative_stay_linked_across_trace_changes_and_duplicate_projections() {
        let control = |id, trace, intervention, source| {
            fixture(
                id,
                "CONTROL_DECISION",
                "trusted_guard",
                object([
                    ("intervention_id", string(intervention)),
                    ("trace_id", string(trace)),
                    ("source_event_id", string(source)),
                ]),
                "deny",
                "denied",
                object([
                    ("control", string("read_limit")),
                    ("route", string("read_hook")),
                    ("threshold", JsonValue::Uint(150)),
                    ("unit", string("lines")),
                ]),
            )
        };
        let mut records = vec![
            control("d1", "trace-a", "i1", "persisted-1"),
            control("d1-replay", "trace-a", "i1", "persisted-1"),
            control("d2", "trace-b", "i2", "persisted-2"),
            control("d3", "trace-c", "i3", "persisted-3"),
        ];
        for id in ["retry-1", "retry-2", "retry-3"] {
            records.push(fixture(
                id,
                "RECOVERY_OR_ESCALATION",
                "trusted_guard",
                object([("parent_event_id", string("d1-replay"))]),
                "retry",
                "observed",
                object([]),
            ));
        }
        records.push(fixture(
            "safe",
            "RECOVERY_OR_ESCALATION",
            "trusted_guard",
            object([
                ("trace_id", string("trace-new")),
                (
                    "causal_links",
                    JsonValue::Array(vec![
                        link("retry-3", "explicit"),
                        link("d2", "exact"),
                        link("d3", "heuristic"),
                    ]),
                ),
            ]),
            "safe_alternative",
            "succeeded",
            object([("elapsed_to_recovery_ns", JsonValue::Uint(4_200))]),
        ));
        records.push(fixture(
            "terminal",
            "TASK_TERMINAL_OUTCOME",
            "trusted_coordinator",
            object([("parent_event_id", string("safe"))]),
            "finish",
            "accepted",
            object([]),
        ));
        let raw = jsonl(&records);
        let report = analyze(&mut Cursor::new(&raw), Some("trace-a")).unwrap();
        let chains = find(&report, &["interventions", "chains"])
            .as_array()
            .unwrap();
        assert_eq!(chains.len(), 2);
        assert_eq!(
            find(&chains[0], &["status"]).as_str(),
            Some("recovered_after_retry")
        );
        assert_eq!(find(&chains[0], &["retries"]).as_u64(), Some(3));
        assert_eq!(find(&chains[0], &["safe_alternatives"]).as_u64(), Some(1));
        assert_eq!(
            find(&chains[0], &["terminal_outcome"]).as_str(),
            Some("accepted")
        );
        assert_eq!(
            find(&chains[0], &["recovery_duration_ns"]).as_u64(),
            Some(4_200)
        );
        assert_eq!(
            find(&chains[1], &["status"]).as_str(),
            Some("recovered_directly")
        );
        assert_eq!(
            find(&report, &["coverage", "duplicate_records_in_input"]).as_u64(),
            Some(1)
        );
        assert_eq!(
            find(&report, &["coverage", "heuristic_links_in_input"]).as_u64(),
            Some(1)
        );
        assert_eq!(
            find(&report, &["coverage", "missing_links_in_input"]).as_u64(),
            Some(0)
        );
    }

    #[test]
    fn unsupported_and_torn_records_are_visible_and_valid_later_frames_survive() {
        let start = fixture(
            "start",
            "EXECUTION_STARTED",
            "trusted_execution_mediator",
            object([("execution_id", string("execution-1"))]),
            "start",
            "observed",
            object([]),
        );
        let unknown = object([
            ("event_type", string("EXECUTION_FINISHED")),
            ("schema_version", JsonValue::Uint(99)),
        ]);
        let untrusted = fixture(
            "claim",
            "EXECUTION_FINISHED",
            "worker_claim",
            object([("execution_id", string("execution-1"))]),
            "finish",
            "succeeded",
            object([]),
        );
        let mut bytes = vec![b'x'; MAX_RECORD_BYTES + 10];
        bytes.push(b'\n');
        bytes.extend(jsonl(&[unknown, start, untrusted]).bytes());
        bytes.extend(b"{\"event_id\":\"torn\"}");
        let reader = Cursor::new(bytes);
        let report = analyze(&mut BufReader::with_capacity(13, reader), None).unwrap();
        assert_eq!(
            find(&report, &["unfinished_executions_in_window"]).as_u64(),
            Some(1)
        );
        let coverage = find(&report, &["coverage"]);
        assert_eq!(
            find(coverage, &["invalid_or_incomplete_records_in_input"]).as_u64(),
            Some(2)
        );
        assert_eq!(
            find(coverage, &["unsupported_schema_or_payload_in_input"]).as_u64(),
            Some(1)
        );
        assert_eq!(
            find(coverage, &["untrusted_records_excluded_from_metrics"]).as_u64(),
            Some(1)
        );
    }

    #[test]
    fn linked_review_can_dismiss_a_finding_without_reclassifying_the_guard_action() {
        let detect = |id, origin, parent, classification| {
            fixture(
                id,
                "DETECTION_ASSESSMENT",
                origin,
                object([("parent_event_id", string(parent))]),
                "assess",
                "observed",
                object([("assessment", string(classification))]),
            )
        };
        let rows = [
            fixture(
                "decision",
                "CONTROL_DECISION",
                "trusted_guard",
                object([]),
                "deny",
                "denied",
                object([("control", string("input_scan"))]),
            ),
            detect("suspect", "trusted_guard", "decision", "suspected"),
            detect("review1", "human_assessment", "suspect", "confirmed"),
            detect("review2", "human_assessment", "review1", "dismissed"),
            detect("unlinked", "human_assessment", "missing", "confirmed"),
        ];
        let report = analyze(&mut Cursor::new(jsonl(&rows)), None).unwrap();
        let counts = find(&report, &["assessments", "findings", "groups"]);
        assert_eq!(find(counts, &["dismissed"]).as_u64(), Some(1));
        assert!(counts.get("confirmed").is_none());
        assert_eq!(
            find(&report, &["assessments", "unlinked_corrections"]).as_u64(),
            Some(1)
        );
        assert_eq!(
            find(&report, &["assessments", "detection_accuracy"]),
            &JsonValue::Null
        );
        let decisions = find(
            &report,
            &[
                "decisions_by_control_route_disposition_threshold_unit_source",
                "groups",
            ],
        );
        assert_eq!(
            find(
                decisions,
                &["input_scan/unknown_route/denied/unknown/unknown_unit/unknown_source"]
            )
            .as_u64(),
            Some(1)
        );
    }

    #[test]
    fn scoped_trace_omits_payload_text_and_reports_unknown_truncation_measurements() {
        let mut event = fixture(
            "truncation",
            "USAGE_AND_DISPOSITION",
            "trusted_guard",
            object([("trace_id", string("trace-a"))]),
            "measure",
            "observed",
            object([
                ("dropped_lines", JsonValue::Uint(30)),
                ("unknown_payload_field", string("fixture-value")),
            ]),
        );
        let JsonValue::Object(fields) = &mut event else {
            panic!("expected fixture object");
        };
        fields.push((
            "timing".to_string(),
            object([("writer_wait_us", JsonValue::Uint(17))]),
        ));
        let report = analyze(&mut Cursor::new(jsonl(&[event])), Some("trace-a")).unwrap();
        let truncation = find(&report, &["truncation"]);
        assert_eq!(
            find(truncation, &["measured_dropped_lines"]).as_u64(),
            Some(30)
        );
        assert_eq!(
            find(truncation, &["continuation_unknown"]).as_u64(),
            Some(1)
        );
        assert_eq!(
            find(&report, &["observed_writer_wait", "samples"]).as_u64(),
            Some(1)
        );
        assert_eq!(
            find(&report, &["observed_writer_wait", "sum_us"]).as_u64(),
            Some(17)
        );
        let trace = find(&report, &["trace"]).as_array().unwrap();
        assert_eq!(find(&trace[0], &["writer_wait_us"]).as_u64(), Some(17));
        assert!(!report.to_json_string().contains("fixture-value"));
    }
}
