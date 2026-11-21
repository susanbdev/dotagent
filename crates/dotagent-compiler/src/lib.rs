#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! `dotagent-compiler` Library: Declarative Policy-IR Lowering, Embedded `regorus` OPA Gate,
//! & Executable Specification Synchronization (`Pillar 3`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use agent_guard::json::JsonValue;
use agent_guard::mcp_policy::MCP_CAPABILITY_MANIFEST;
use regorus::{Engine, Value as RegoValue};

pub const ALLOWED_MCP_URL: &str = "https://mcp.zt.susanb.dev/mcp";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileIr {
    pub file_name: String,
    pub profile_id: String,
    pub version: String,
    pub privilege_tier: String,
    pub role: Option<String>,
    pub enable_write_tools: bool,
    pub network_access: String,
    pub root_file: String,
    pub hooks_path: String,
    pub max_directory_walk_depth: u64,
    pub max_reference_pointer_levels: u64,
    pub pre_buffer_ascii_only: bool,
    pub max_raw_file_bytes: u64,
    pub max_slice_lines: u64,
    pub max_turn_tokens: u64,
    pub max_turn_file_reads: u64,
    pub max_turn_tool_calls: u64,
    pub auto_compact_pct_override: u64,
    pub disable_auto_memory: bool,
    pub subagent_airlock_max_tokens: u64,
    pub max_direct_discovery_calls: u64,
    pub mcp_allowed_endpoint: String,
    pub ban_stdio_npx_servers: bool,
}

impl ProfileIr {
    pub fn to_json_value(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "file_name".to_string(),
                JsonValue::Str(self.file_name.clone()),
            ),
            (
                "profile_id".to_string(),
                JsonValue::Str(self.profile_id.clone()),
            ),
            ("version".to_string(), JsonValue::Str(self.version.clone())),
            (
                "privilege_tier".to_string(),
                JsonValue::Str(self.privilege_tier.clone()),
            ),
            (
                "role".to_string(),
                self.role
                    .as_ref()
                    .map_or(JsonValue::Null, |r| JsonValue::Str(r.clone())),
            ),
            (
                "enable_write_tools".to_string(),
                JsonValue::Bool(self.enable_write_tools),
            ),
            (
                "network_access".to_string(),
                JsonValue::Str(self.network_access.clone()),
            ),
            (
                "authority".to_string(),
                JsonValue::Object(vec![(
                    "root_file".to_string(),
                    JsonValue::Str(self.root_file.clone()),
                )]),
            ),
            (
                "git".to_string(),
                JsonValue::Object(vec![(
                    "hooks_path".to_string(),
                    JsonValue::Str(self.hooks_path.clone()),
                )]),
            ),
            (
                "traversal".to_string(),
                JsonValue::Object(vec![
                    (
                        "max_directory_walk_depth".to_string(),
                        JsonValue::Uint(self.max_directory_walk_depth),
                    ),
                    (
                        "max_reference_pointer_levels".to_string(),
                        JsonValue::Uint(self.max_reference_pointer_levels),
                    ),
                ]),
            ),
            (
                "sanitization".to_string(),
                JsonValue::Object(vec![(
                    "pre_buffer_ascii_only".to_string(),
                    JsonValue::Bool(self.pre_buffer_ascii_only),
                )]),
            ),
            (
                "budgets".to_string(),
                JsonValue::Object(vec![
                    (
                        "max_raw_file_bytes".to_string(),
                        JsonValue::Uint(self.max_raw_file_bytes),
                    ),
                    (
                        "max_slice_lines".to_string(),
                        JsonValue::Uint(self.max_slice_lines),
                    ),
                    (
                        "max_turn_tokens".to_string(),
                        JsonValue::Uint(self.max_turn_tokens),
                    ),
                    (
                        "max_turn_file_reads".to_string(),
                        JsonValue::Uint(self.max_turn_file_reads),
                    ),
                    (
                        "max_turn_tool_calls".to_string(),
                        JsonValue::Uint(self.max_turn_tool_calls),
                    ),
                    (
                        "auto_compact_pct_override".to_string(),
                        JsonValue::Uint(self.auto_compact_pct_override),
                    ),
                ]),
            ),
            (
                "isolation".to_string(),
                JsonValue::Object(vec![
                    (
                        "disable_auto_memory".to_string(),
                        JsonValue::Bool(self.disable_auto_memory),
                    ),
                    (
                        "subagent_airlock_max_tokens".to_string(),
                        JsonValue::Uint(self.subagent_airlock_max_tokens),
                    ),
                    (
                        "max_direct_discovery_calls".to_string(),
                        JsonValue::Uint(self.max_direct_discovery_calls),
                    ),
                ]),
            ),
            (
                "mcp".to_string(),
                JsonValue::Object(vec![
                    (
                        "allowed_endpoint".to_string(),
                        JsonValue::Str(self.mcp_allowed_endpoint.clone()),
                    ),
                    (
                        "ban_stdio_npx_servers".to_string(),
                        JsonValue::Bool(self.ban_stdio_npx_servers),
                    ),
                ]),
            ),
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillIr {
    pub name: String,
    pub description: String,
    pub sha256: String,
    pub bytes: usize,
}

impl SkillIr {
    pub fn to_json_value(&self) -> JsonValue {
        JsonValue::Object(vec![
            ("name".to_string(), JsonValue::Str(self.name.clone())),
            (
                "description".to_string(),
                JsonValue::Str(self.description.clone()),
            ),
            ("sha256".to_string(), JsonValue::Str(self.sha256.clone())),
            ("bytes".to_string(), JsonValue::Uint(self.bytes as u64)),
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBundleIr {
    pub schema: String,
    pub compiler_version: String,
    pub profiles: Vec<ProfileIr>,
    pub skills: Vec<SkillIr>,
}

impl PolicyBundleIr {
    pub fn new(profiles: Vec<ProfileIr>, skills: Vec<SkillIr>) -> Self {
        Self {
            schema: "dotagent.policy_ir.v2".to_string(),
            compiler_version: env!("CARGO_PKG_VERSION").to_string(),
            profiles,
            skills,
        }
    }

    pub fn to_json_value(&self) -> JsonValue {
        let prof_arr: Vec<JsonValue> = self.profiles.iter().map(ProfileIr::to_json_value).collect();
        let skill_arr: Vec<JsonValue> = self.skills.iter().map(SkillIr::to_json_value).collect();
        let mcp_rules: Vec<JsonValue> = MCP_CAPABILITY_MANIFEST
            .iter()
            .map(|r| {
                JsonValue::Object(vec![
                    ("pattern".to_string(), JsonValue::Str(r.pattern.to_string())),
                    (
                        "class".to_string(),
                        JsonValue::Str(r.class.as_str().to_string()),
                    ),
                    (
                        "description".to_string(),
                        JsonValue::Str(r.description.to_string()),
                    ),
                ])
            })
            .collect();

        JsonValue::Object(vec![
            ("schema".to_string(), JsonValue::Str(self.schema.clone())),
            (
                "compiler_version".to_string(),
                JsonValue::Str(self.compiler_version.clone()),
            ),
            ("profiles".to_string(), JsonValue::Array(prof_arr)),
            ("skills".to_string(), JsonValue::Array(skill_arr)),
            (
                "mcp_capability_manifest".to_string(),
                JsonValue::Array(mcp_rules),
            ),
        ])
    }
}

/// Deterministic 2-space pretty-printer for `JsonValue` that delegates all string escaping to
/// `JsonValue::to_json_string()` so rendered JSON artifacts are immune to string interpolation bugs.
pub fn format_json_pretty(val: &JsonValue) -> String {
    let mut out = String::new();
    write_json_pretty_inner(val, 0, &mut out);
    out.push('\n');
    out
}

fn write_json_pretty_inner(val: &JsonValue, indent: usize, out: &mut String) {
    match val {
        JsonValue::Null
        | JsonValue::Bool(_)
        | JsonValue::Number(_)
        | JsonValue::Int(_)
        | JsonValue::Uint(_)
        | JsonValue::Str(_) => {
            out.push_str(&val.to_json_string());
        }
        JsonValue::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            let child_pad = " ".repeat(indent + 2);
            for (idx, item) in items.iter().enumerate() {
                out.push_str(&child_pad);
                write_json_pretty_inner(item, indent + 2, out);
                if idx + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&" ".repeat(indent));
            out.push(']');
        }
        JsonValue::Object(entries) => {
            if entries.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{\n");
            let child_pad = " ".repeat(indent + 2);
            for (idx, (k, v)) in entries.iter().enumerate() {
                out.push_str(&child_pad);
                out.push_str(&JsonValue::Str(k.clone()).to_json_string());
                out.push_str(": ");
                write_json_pretty_inner(v, indent + 2, out);
                if idx + 1 < entries.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&" ".repeat(indent));
            out.push('}');
        }
    }
}

/// Normalizes a clean subset of TOML (sections `[a]`, quote-aware dotted `[a."b.c"]`, dotted LHS
/// assignments `a.b = v`, strings `"..."`/`'...'`, bools, integers, arrays) into a deterministic
/// `JsonValue` AST so `regorus` evaluates Rego rules directly over `codex/config.toml` and
/// `profiles/*.toml`. Fails closed on `[[...]]` array-of-tables and `{...}` inline tables.
pub fn normalize_toml_to_json_value(raw_toml: &str) -> Result<JsonValue, String> {
    let mut root: BTreeMap<String, TomlNode> = BTreeMap::new();
    let mut current_section: Vec<String> = Vec::new();

    for (line_idx, raw_line) in raw_toml.lines().enumerate() {
        let line_no = line_idx + 1;
        let clean = strip_toml_comment(raw_line);
        if clean.is_empty() {
            continue;
        }
        if clean.starts_with("[[") {
            return Err(format!(
                "TOML array-of-tables '[[...]]' is forbidden in policy configs at line {line_no}"
            ));
        }
        if clean.starts_with('[') && clean.ends_with(']') {
            let inner = clean[1..clean.len() - 1].trim();
            if inner.is_empty() {
                return Err(format!("empty TOML table header at line {line_no}"));
            }
            current_section = split_toml_dotted_path(inner, line_no)?;
            ensure_toml_table_path(&mut root, &current_section)?;
            continue;
        }
        let Some((k_raw, v_raw)) = split_toml_key_value_outside_quotes(clean) else {
            return Err(format!(
                "invalid TOML key=value syntax at line {line_no}: '{clean}'"
            ));
        };
        let key_segments = split_toml_dotted_path(k_raw.trim(), line_no)?;
        let (leaf_key, sub_path) = key_segments
            .split_last()
            .ok_or_else(|| format!("empty TOML key at line {line_no}"))?;
        let mut full_table_path = Vec::with_capacity(current_section.len() + sub_path.len());
        full_table_path.extend_from_slice(&current_section);
        full_table_path.extend_from_slice(sub_path);

        let val = parse_toml_scalar_or_array(v_raw.trim(), line_no)?;
        insert_toml_value_at_path(&mut root, &full_table_path, leaf_key.clone(), val)?;
    }

    Ok(toml_map_to_json(root))
}

fn split_toml_key_value_outside_quotes(line: &str) -> Option<(&str, &str)> {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for (idx, b) in line.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_double {
            if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_double = false;
            }
            continue;
        }
        if in_single {
            if b == b'\'' {
                in_single = false;
            }
            continue;
        }
        match b {
            b'"' => in_double = true,
            b'\'' => in_single = true,
            b'=' => return Some((&line[..idx], &line[idx + 1..])),
            _ => {}
        }
    }
    None
}

fn split_toml_dotted_path(raw: &str, line_no: usize) -> Result<Vec<String>, String> {
    let mut raw_parts: Vec<&str> = Vec::new();
    let mut start = 0usize;
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;

    for (idx, b) in raw.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_double {
            if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_double = false;
            }
            continue;
        }
        if in_single {
            if b == b'\'' {
                in_single = false;
            }
            continue;
        }
        match b {
            b'"' => in_double = true,
            b'\'' => in_single = true,
            b'.' => {
                raw_parts.push(&raw[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    if in_double || in_single || escaped {
        return Err(format!("unclosed quote in TOML key path at line {line_no}"));
    }
    raw_parts.push(&raw[start..]);

    let mut out = Vec::with_capacity(raw_parts.len());
    for part in raw_parts {
        let seg = part.trim();
        if seg.is_empty() {
            return Err(format!("empty segment in TOML key path at line {line_no}"));
        }
        if seg.starts_with('"') && seg.ends_with('"') && seg.len() >= 2 {
            match JsonValue::parse(seg) {
                Ok(JsonValue::Str(s)) => out.push(s),
                _ => {
                    return Err(format!(
                        "invalid quoted TOML key segment '{seg}' at line {line_no}"
                    ));
                }
            }
        } else if seg.starts_with('\'') && seg.ends_with('\'') && seg.len() >= 2 {
            out.push(seg[1..seg.len() - 1].to_string());
        } else if seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            out.push(seg.to_string());
        } else {
            return Err(format!(
                "invalid bare TOML key segment '{seg}' at line {line_no}"
            ));
        }
    }
    Ok(out)
}

#[derive(Debug, Clone)]
enum TomlNode {
    Table(BTreeMap<String, TomlNode>),
    Leaf(JsonValue),
}

fn ensure_toml_table_path(
    root: &mut BTreeMap<String, TomlNode>,
    path: &[String],
) -> Result<(), String> {
    let mut cur = root;
    for seg in path {
        let entry = cur
            .entry(seg.clone())
            .or_insert_with(|| TomlNode::Table(BTreeMap::new()));
        match entry {
            TomlNode::Table(sub) => cur = sub,
            TomlNode::Leaf(_) => {
                return Err(format!("TOML section '{seg}' collides with scalar key"));
            }
        }
    }
    Ok(())
}

fn insert_toml_value_at_path(
    root: &mut BTreeMap<String, TomlNode>,
    path: &[String],
    key: String,
    val: JsonValue,
) -> Result<(), String> {
    let mut cur = root;
    for seg in path {
        let entry = cur
            .entry(seg.clone())
            .or_insert_with(|| TomlNode::Table(BTreeMap::new()));
        match entry {
            TomlNode::Table(sub) => cur = sub,
            TomlNode::Leaf(_) => {
                return Err(format!("TOML section '{seg}' collides with scalar key"));
            }
        }
    }
    if cur.insert(key.clone(), TomlNode::Leaf(val)).is_some() {
        return Err(format!("duplicate TOML key '{key}'"));
    }
    Ok(())
}

fn toml_map_to_json(map: BTreeMap<String, TomlNode>) -> JsonValue {
    let entries = map
        .into_iter()
        .map(|(k, v)| match v {
            TomlNode::Table(sub) => (k, toml_map_to_json(sub)),
            TomlNode::Leaf(j) => (k, j),
        })
        .collect();
    JsonValue::Object(entries)
}

pub fn strip_toml_comment(line: &str) -> &str {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for (idx, b) in line.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_double {
            if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_double = false;
            }
            continue;
        }
        if in_single {
            if b == b'\'' {
                in_single = false;
            }
            continue;
        }
        match b {
            b'"' => in_double = true,
            b'\'' => in_single = true,
            b'#' => return line[..idx].trim(),
            _ => {}
        }
    }
    line.trim()
}

fn parse_toml_scalar_or_array(raw: &str, line_no: usize) -> Result<JsonValue, String> {
    if raw.starts_with('{') {
        return Err(format!(
            "TOML inline tables '{{...}}' are forbidden in policy configs at line {line_no}"
        ));
    }
    if raw == "true" {
        return Ok(JsonValue::Bool(true));
    }
    if raw == "false" {
        return Ok(JsonValue::Bool(false));
    }
    if raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2 {
        if raw.starts_with("\"\"\"") {
            return Err(format!(
                "multiline TOML strings are forbidden in policy configs at line {line_no}"
            ));
        }
        return JsonValue::parse(raw)
            .map_err(|e| format!("invalid TOML string literal at line {line_no}: {e}"));
    }
    if raw.starts_with('\'') && raw.ends_with('\'') && raw.len() >= 2 {
        if raw.starts_with("'''") {
            return Err(format!(
                "multiline TOML literal strings are forbidden in policy configs at line {line_no}"
            ));
        }
        let inner = &raw[1..raw.len() - 1];
        if inner.contains('\'') {
            return Err(format!(
                "invalid unescaped quote in TOML literal string at line {line_no}"
            ));
        }
        return Ok(JsonValue::Str(inner.to_string()));
    }
    if raw.starts_with('[') && raw.ends_with(']') {
        return parse_toml_array(raw, line_no);
    }
    if let Ok(u) = raw.parse::<u64>() {
        return Ok(JsonValue::Uint(u));
    }
    if let Ok(i) = raw.parse::<i64>() {
        return Ok(JsonValue::Int(i));
    }
    Err(format!("unsupported TOML value '{raw}' at line {line_no}"))
}

fn parse_toml_array(raw: &str, line_no: usize) -> Result<JsonValue, String> {
    let inner = raw[1..raw.len() - 1].trim();
    if inner.is_empty() {
        return Ok(JsonValue::Array(Vec::new()));
    }
    let mut items = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;

    for (idx, b) in inner.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_double {
            if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_double = false;
            }
            continue;
        }
        if in_single {
            if b == b'\'' {
                in_single = false;
            }
            continue;
        }
        match b {
            b'"' => in_double = true,
            b'\'' => in_single = true,
            b'[' => depth += 1,
            b']' => {
                if depth == 0 {
                    return Err(format!("unbalanced ']' in TOML array at line {line_no}"));
                }
                depth -= 1;
            }
            b',' if depth == 0 => {
                let elem = inner[start..idx].trim();
                if !elem.is_empty() {
                    items.push(parse_toml_scalar_or_array(elem, line_no)?);
                }
                start = idx + 1;
            }
            _ => {}
        }
    }
    if in_double || in_single || escaped || depth != 0 {
        return Err(format!("unclosed TOML array literal at line {line_no}"));
    }
    let tail = inner[start..].trim();
    if !tail.is_empty() {
        items.push(parse_toml_scalar_or_array(tail, line_no)?);
    }
    Ok(JsonValue::Array(items))
}

/// Parses a `profiles/<name>.toml` file into a strongly typed `ProfileIr`.
pub fn parse_profile_toml_to_ir(file_name: &str, raw_toml: &str) -> Result<ProfileIr, String> {
    let ast = normalize_toml_to_json_value(raw_toml)?;
    let profile_id = ast
        .get("profile_id")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| format!("profile '{file_name}' missing string 'profile_id'"))?
        .to_string();
    let version = ast
        .get("version")
        .and_then(JsonValue::as_str)
        .unwrap_or("2.0.0")
        .to_string();
    let privilege_tier = ast
        .get("privilege_tier")
        .and_then(JsonValue::as_str)
        .unwrap_or("ring-1")
        .to_string();
    let role = ast
        .get("role")
        .and_then(JsonValue::as_str)
        .map(String::from);
    let write_scope = ast
        .get("write_scope")
        .and_then(JsonValue::as_str)
        .unwrap_or("");
    let enable_write_tools = ast
        .get("enable_write_tools")
        .and_then(JsonValue::as_bool)
        .unwrap_or(!matches!(write_scope, "none" | "read-only" | "readonly"));
    let network_access = ast
        .get("network_access")
        .and_then(JsonValue::as_str)
        .unwrap_or("restricted")
        .to_string();

    let root_file = ast
        .get("authority")
        .and_then(|a| a.get("root_file"))
        .and_then(JsonValue::as_str)
        .ok_or_else(|| format!("profile '{file_name}' missing authority.root_file"))?
        .to_string();
    let hooks_path = ast
        .get("git")
        .and_then(|g| g.get("hooks_path"))
        .and_then(JsonValue::as_str)
        .ok_or_else(|| format!("profile '{file_name}' missing git.hooks_path"))?
        .to_string();

    let max_directory_walk_depth = ast
        .get("traversal")
        .and_then(|t| t.get("max_directory_walk_depth"))
        .and_then(JsonValue::as_u64)
        .unwrap_or(2);
    let max_reference_pointer_levels = ast
        .get("traversal")
        .and_then(|t| t.get("max_reference_pointer_levels"))
        .and_then(JsonValue::as_u64)
        .unwrap_or(2);
    let pre_buffer_ascii_only = ast
        .get("sanitization")
        .and_then(|s| s.get("pre_buffer_ascii_only"))
        .and_then(JsonValue::as_bool)
        .unwrap_or(true);

    let budgets = ast.get("budgets");
    let max_raw_file_bytes = budgets
        .and_then(|b| b.get("max_raw_file_bytes"))
        .and_then(JsonValue::as_u64)
        .unwrap_or(24_576);
    let max_slice_lines = budgets
        .and_then(|b| b.get("max_slice_lines"))
        .and_then(JsonValue::as_u64)
        .unwrap_or(150);
    let max_turn_tokens = budgets
        .and_then(|b| b.get("max_turn_tokens"))
        .and_then(JsonValue::as_u64)
        .unwrap_or(16_000);
    let max_turn_file_reads = budgets
        .and_then(|b| b.get("max_turn_file_reads"))
        .and_then(JsonValue::as_u64)
        .unwrap_or(18);
    let max_turn_tool_calls = budgets
        .and_then(|b| b.get("max_turn_tool_calls"))
        .and_then(JsonValue::as_u64)
        .unwrap_or(28);
    let auto_compact_pct_override = budgets
        .and_then(|b| b.get("auto_compact_pct_override"))
        .and_then(JsonValue::as_u64)
        .unwrap_or(15);

    let isolation = ast.get("isolation");
    let disable_auto_memory = isolation
        .and_then(|i| i.get("disable_auto_memory"))
        .and_then(JsonValue::as_bool)
        .unwrap_or(true);
    let subagent_airlock_max_tokens = isolation
        .and_then(|i| i.get("subagent_airlock_max_tokens"))
        .and_then(JsonValue::as_u64)
        .unwrap_or(200);
    let default_direct_discovery = if enable_write_tools {
        4
    } else {
        max_turn_tool_calls
    };
    let max_direct_discovery_calls = isolation
        .and_then(|i| i.get("max_direct_discovery_calls"))
        .or_else(|| budgets.and_then(|b| b.get("max_direct_discovery_calls")))
        .and_then(JsonValue::as_u64)
        .unwrap_or(default_direct_discovery);

    let mcp = ast.get("mcp");
    let mcp_allowed_endpoint = mcp
        .and_then(|m| m.get("allowed_endpoint"))
        .and_then(JsonValue::as_str)
        .unwrap_or(ALLOWED_MCP_URL)
        .to_string();
    let ban_stdio_npx_servers = mcp
        .and_then(|m| m.get("ban_stdio_npx_servers"))
        .and_then(JsonValue::as_bool)
        .unwrap_or(true);

    Ok(ProfileIr {
        file_name: file_name.to_string(),
        profile_id,
        version,
        privilege_tier,
        role,
        enable_write_tools,
        network_access,
        root_file,
        hooks_path,
        max_directory_walk_depth,
        max_reference_pointer_levels,
        pre_buffer_ascii_only,
        max_raw_file_bytes,
        max_slice_lines,
        max_turn_tokens,
        max_turn_file_reads,
        max_turn_tool_calls,
        auto_compact_pct_override,
        disable_auto_memory,
        subagent_airlock_max_tokens,
        max_direct_discovery_calls,
        mcp_allowed_endpoint,
        ban_stdio_npx_servers,
    })
}

/// Compiles all parsed `ProfileIr`s, `SkillIr`s, and the declarative `MCP_CAPABILITY_MANIFEST`
/// into `dist/profiles/policy_ir.json`.
pub fn compile_policy_bundle_ir_json(profiles: &[ProfileIr], skills: &[SkillIr]) -> String {
    let bundle = PolicyBundleIr::new(profiles.to_vec(), skills.to_vec());
    format!("{}\n", bundle.to_json_value().to_json_string())
}

/// Lowers `coding-agent` `ProfileIr` into Claude Code `settings.json` (`dist/claude/settings.json`).
pub fn render_claude_settings_from_ir(coding: &ProfileIr) -> String {
    let deny_rules: &[&str] = &[
        "Read(/tmp/**)",
        "Read(/var/tmp/**)",
        "Read(/dev/shm/**)",
        "Read(**/tmp/**)",
        "Read(**/.tmp/**)",
        "Read(**/.cache/**)",
        "Read(~/.cache/**)",
        "Read(**/__pycache__/**)",
        "Read(**/.pytest_cache/**)",
        "Read(**/.mypy_cache/**)",
        "Read(**/.ruff_cache/**)",
        "Read(**/.next/**)",
        "Read(**/.turbo/**)",
        "Read(**/node_modules/**)",
        "Read(**/vendor/**)",
        "Read(**/.venv/**)",
        "Read(**/venv/**)",
        "Read(**/site-packages/**)",
        "Read(target/**)",
        "Read(build/**)",
        "Read(dist-build/**)",
        "Read(.env)",
        "Read(.env.*)",
        "Read(.env*)",
        "Read(**/.env)",
        "Read(**/.env.*)",
        "Read(**/.env*)",
        "Read(**/*.pem)",
        "Read(**/*.key)",
        "Read(~/.ssh/**)",
        "Read(~/.aws/**)",
        "Read(~/.gnupg/**)",
        "Read(~/.config/gh/**)",
        "Read(~/.local/state/agent-guard/**)",
        "Read(**/audit.jsonl)",
        "Read(CLAUDE.md)",
        "Read(**/CLAUDE.md)",
        "Read(CLAUDE.local.md)",
        "Read(**/CLAUDE.local.md)",
        "Read(*/AGENTS.md)",
        "Read(**/*/AGENTS.md)",
        "Read(.cursorrules)",
        "Read(**/.cursorrules)",
        "Read(.github/copilot-instructions.md)",
        "Edit(AGENTS.md)",
        "Write(AGENTS.md)",
        "Edit(.claude/**)",
        "Write(.claude/**)",
        "Edit(.guard/**)",
        "Write(.guard/**)",
        "Edit(.git/**)",
        "Write(.git/**)",
        "Edit(.cargo/**)",
        "Write(.cargo/**)",
        "Edit(.yarn/**)",
        "Write(.yarn/**)",
        "Edit(.gitattributes)",
        "Write(.gitattributes)",
        "Edit(**/.npmrc)",
        "Write(**/.npmrc)",
        "Edit(**/.yarnrc.yml)",
        "Write(**/.yarnrc.yml)",
        "Edit(rust-toolchain.toml)",
        "Write(rust-toolchain.toml)",
        "Bash(curl *)",
        "Bash(wget *)",
        "Bash(nc *)",
        "Bash(ssh *)",
        "Bash(sudo *)",
        "Bash(mktemp*)",
        "Bash(npx *)",
        "Bash(uvx *)",
        "Bash(gh workflow run*)",
        "Bash(git push*)",
        "Bash(git remote*)",
        "Bash(git config*)",
        "Bash(git -c *)",
        "Bash(git rebase*)",
        "Bash(git reset --hard*)",
        "Bash(git commit --amend*)",
        "Bash(git hook*)",
    ];

    let hook_cmd = |cmd: &str, timeout: u64| -> JsonValue {
        JsonValue::Object(vec![
            ("type".to_string(), JsonValue::Str("command".to_string())),
            ("command".to_string(), JsonValue::Str(cmd.to_string())),
            ("timeout".to_string(), JsonValue::Uint(timeout)),
        ])
    };
    let unmached_hook = |cmd: &str, timeout: u64| -> JsonValue {
        JsonValue::Array(vec![JsonValue::Object(vec![(
            "hooks".to_string(),
            JsonValue::Array(vec![hook_cmd(cmd, timeout)]),
        )])])
    };
    let wildcard_hook = |cmd: &str, timeout: u64| -> JsonValue {
        JsonValue::Array(vec![JsonValue::Object(vec![
            ("matcher".to_string(), JsonValue::Str("*".to_string())),
            (
                "hooks".to_string(),
                JsonValue::Array(vec![hook_cmd(cmd, timeout)]),
            ),
        ])])
    };

    let doc = JsonValue::Object(vec![
        (
            "autoMemoryEnabled".to_string(),
            JsonValue::Bool(!coding.disable_auto_memory),
        ),
        ("disableAllHooks".to_string(), JsonValue::Bool(false)),
        (
            "env".to_string(),
            JsonValue::Object(vec![
                (
                    "AGENT_GUARD_WRAP_BASH_ASCII".to_string(),
                    JsonValue::Str("1".to_string()),
                ),
                (
                    "CLAUDE_AUTOCOMPACT_PCT_OVERRIDE".to_string(),
                    JsonValue::Str(coding.auto_compact_pct_override.to_string()),
                ),
                (
                    "BASH_MAX_OUTPUT_LENGTH".to_string(),
                    JsonValue::Str("12000".to_string()),
                ),
                (
                    "MAX_MCP_OUTPUT_TOKENS".to_string(),
                    JsonValue::Str("3000".to_string()),
                ),
                (
                    "GIT_CONFIG_NOSYSTEM".to_string(),
                    JsonValue::Str("1".to_string()),
                ),
                (
                    "PYTHONDONTWRITEBYTECODE".to_string(),
                    JsonValue::Str("1".to_string()),
                ),
                (
                    "PIP_NO_CACHE_DIR".to_string(),
                    JsonValue::Str("1".to_string()),
                ),
                (
                    "NPM_CONFIG_IGNORE_SCRIPTS".to_string(),
                    JsonValue::Str("true".to_string()),
                ),
                (
                    "HISTFILE".to_string(),
                    JsonValue::Str("/dev/null".to_string()),
                ),
            ]),
        ),
        (
            "permissions".to_string(),
            JsonValue::Object(vec![
                ("allow".to_string(), JsonValue::Array(Vec::new())),
                (
                    "deny".to_string(),
                    JsonValue::Array(
                        deny_rules
                            .iter()
                            .map(|s| JsonValue::Str((*s).to_string()))
                            .collect(),
                    ),
                ),
            ]),
        ),
        (
            "hooks".to_string(),
            JsonValue::Object(vec![
                (
                    "UserPromptSubmit".to_string(),
                    unmached_hook("agent-guard user-prompt", 5),
                ),
                (
                    "PreToolUse".to_string(),
                    wildcard_hook("agent-guard pre-tool", 5),
                ),
                (
                    "PostToolUse".to_string(),
                    wildcard_hook("agent-guard post-tool", 5),
                ),
                (
                    "PreCompact".to_string(),
                    unmached_hook("agent-guard pre-compact", 5),
                ),
                ("Stop".to_string(), unmached_hook("agent-guard on-stop", 15)),
            ]),
        ),
        (
            "mcpServers".to_string(),
            JsonValue::Object(vec![(
                "susanbdev".to_string(),
                JsonValue::Object(vec![
                    ("type".to_string(), JsonValue::Str("http".to_string())),
                    (
                        "url".to_string(),
                        JsonValue::Str(coding.mcp_allowed_endpoint.clone()),
                    ),
                ]),
            )]),
        ),
    ]);
    format_json_pretty(&doc)
}

/// Lowers `coding-agent` `ProfileIr` into Gemini CLI `settings.json` (`dist/gemini/settings.json`).
pub fn render_gemini_settings_from_ir(coding: &ProfileIr) -> String {
    let gem_hook = |name: &str, cmd: &str, timeout_ms: u64, matcher: Option<&str>| -> JsonValue {
        let inner = JsonValue::Object(vec![
            ("name".to_string(), JsonValue::Str(name.to_string())),
            ("type".to_string(), JsonValue::Str("command".to_string())),
            ("command".to_string(), JsonValue::Str(cmd.to_string())),
            ("timeout".to_string(), JsonValue::Uint(timeout_ms)),
        ]);
        let mut outer = Vec::new();
        if let Some(m) = matcher {
            outer.push(("matcher".to_string(), JsonValue::Str(m.to_string())));
        }
        outer.push(("hooks".to_string(), JsonValue::Array(vec![inner])));
        JsonValue::Array(vec![JsonValue::Object(outer)])
    };

    let compression_ratio = (coding.auto_compact_pct_override as f64) / 100.0;
    let doc = JsonValue::Object(vec![
        (
            "contextFileName".to_string(),
            JsonValue::Str(coding.root_file.clone()),
        ),
        (
            "checkpointing".to_string(),
            JsonValue::Object(vec![("enabled".to_string(), JsonValue::Bool(false))]),
        ),
        (
            "model".to_string(),
            JsonValue::Object(vec![
                (
                    "compressionThreshold".to_string(),
                    JsonValue::Number(compression_ratio),
                ),
                ("maxSessionTurns".to_string(), JsonValue::Uint(25)),
            ]),
        ),
        (
            "tools".to_string(),
            JsonValue::Object(vec![
                (
                    "truncateToolOutputThreshold".to_string(),
                    JsonValue::Uint(12000),
                ),
                (
                    "truncateToolOutputLines".to_string(),
                    JsonValue::Uint(coding.max_slice_lines.min(120)),
                ),
            ]),
        ),
        (
            "hooks".to_string(),
            JsonValue::Object(vec![
                (
                    "BeforeAgent".to_string(),
                    gem_hook(
                        "agent-guard-turn-reset",
                        "agent-guard user-prompt",
                        5000,
                        None,
                    ),
                ),
                (
                    "BeforeTool".to_string(),
                    gem_hook(
                        "agent-guard-pre-tool",
                        "agent-guard pre-tool",
                        5000,
                        Some(".*"),
                    ),
                ),
                (
                    "AfterTool".to_string(),
                    gem_hook(
                        "agent-guard-post-tool",
                        "agent-guard post-tool",
                        5000,
                        Some(".*"),
                    ),
                ),
                (
                    "PreCompress".to_string(),
                    gem_hook(
                        "agent-guard-pre-compact",
                        "agent-guard pre-compact",
                        5000,
                        None,
                    ),
                ),
                (
                    "AfterAgent".to_string(),
                    gem_hook("agent-guard-on-stop", "agent-guard on-stop", 15000, None),
                ),
            ]),
        ),
        (
            "mcpServers".to_string(),
            JsonValue::Object(vec![(
                "susanbdev".to_string(),
                JsonValue::Object(vec![(
                    "httpUrl".to_string(),
                    JsonValue::Str(coding.mcp_allowed_endpoint.clone()),
                )]),
            )]),
        ),
    ]);
    format_json_pretty(&doc)
}

/// Lowers `coding-agent` `ProfileIr` into Cursor's full lifecycle hooks (`dist/cursor/hooks.json`),
/// closing the `PostToolUse` (`afterShellExecution` + `afterMCPExecution`) and `preCompact` parity gaps!
pub fn render_cursor_hooks_from_ir(_coding: &ProfileIr) -> String {
    let hook_entry = |cmd: &str| -> JsonValue {
        JsonValue::Array(vec![JsonValue::Object(vec![(
            "command".to_string(),
            JsonValue::Str(cmd.to_string()),
        )])])
    };
    let doc = JsonValue::Object(vec![
        ("version".to_string(), JsonValue::Uint(1)),
        (
            "hooks".to_string(),
            JsonValue::Object(vec![
                (
                    "beforeSubmitPrompt".to_string(),
                    hook_entry("agent-guard user-prompt"),
                ),
                (
                    "beforeShellExecution".to_string(),
                    hook_entry("agent-guard pre-tool"),
                ),
                (
                    "afterShellExecution".to_string(),
                    hook_entry("agent-guard post-tool"),
                ),
                (
                    "beforeReadFile".to_string(),
                    hook_entry("agent-guard pre-tool"),
                ),
                (
                    "beforeMCPExecution".to_string(),
                    hook_entry("agent-guard pre-tool"),
                ),
                (
                    "afterMCPExecution".to_string(),
                    hook_entry("agent-guard post-tool"),
                ),
                (
                    "preCompact".to_string(),
                    hook_entry("agent-guard pre-compact"),
                ),
                (
                    "afterFileEdit".to_string(),
                    hook_entry("agent-guard post-edit"),
                ),
                ("stop".to_string(), hook_entry("agent-guard on-stop")),
            ]),
        ),
    ]);
    format_json_pretty(&doc)
}

/// Lowers `coding-agent` `ProfileIr` into Cursor's locked MCP client binding (`dist/cursor/mcp.json`).
pub fn render_cursor_mcp_json_from_ir(coding: &ProfileIr) -> String {
    let doc = JsonValue::Object(vec![(
        "mcpServers".to_string(),
        JsonValue::Object(vec![(
            "susanbdev".to_string(),
            JsonValue::Object(vec![(
                "url".to_string(),
                JsonValue::Str(coding.mcp_allowed_endpoint.clone()),
            )]),
        )]),
    )]);
    format_json_pretty(&doc)
}

/// Lowers `coding-agent` `ProfileIr` into OpenAI Codex `config.toml` (`dist/codex/config.toml`).
pub fn render_codex_config_from_ir(coding: &ProfileIr) -> String {
    let escaped_url = JsonValue::Str(coding.mcp_allowed_endpoint.clone()).to_json_string();
    format!(
        r#"# Managed by susanbdev/dotagent -- OpenAI Codex Zero-Trust Configuration (Policy-IR v2)
approval_policy = "on-request"
sandbox_mode = "workspace-write"
project_doc_max_bytes = 16384
project_doc_fallback_filenames = []
model_auto_compact_token_limit = {}
tool_output_token_limit = 2500
notify = ["agent-guard", "on-stop"]

[sandbox_workspace_write]
network_access = false
exclude_tmpdir_env_var = true
exclude_slash_tmp = true

[shell_environment_policy]
inherit = "all"
ignore_default_excludes = false
exclude = ["AWS_*", "GITHUB_*", "GH_*", "ANTHROPIC_*", "OPENAI_*", "GEMINI_*", "*_TOKEN", "*_SECRET", "*_KEY", "AGENT_GUARD_ALLOW_*"]
include_only = ["PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LC_*", "TERM", "CARGO_HOME", "RUSTUP_HOME", "XDG_RUNTIME_DIR", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "AGENT_GUARD_PROFILE", "AGENT_GUARD_ROLE", "AGENT_GUARD_SESSION_ID", "AGENT_GUARD_ROOT_SESSION_ID", "AGENT_GUARD_STATE_DIR", "AGENT_GUARD_COORDINATOR_SOCK", "AGENT_GUARD_HOT_COORD"]

[mcp_servers.susanbdev]
url = {escaped_url}
"#,
        coding.max_turn_tokens.max(16_000),
    )
}

/// Lowers `coding-agent` `ProfileIr` into the Cloud / Remote Antigravity VM runtime manifest (`dist/antigravity/harness.json`).
pub fn render_antigravity_harness_json_from_ir(coding: &ProfileIr) -> String {
    let doc = JsonValue::Object(vec![
        (
            "schema".to_string(),
            JsonValue::Str("dotagent.antigravity.v2".to_string()),
        ),
        (
            "profile_id".to_string(),
            JsonValue::Str(coding.profile_id.clone()),
        ),
        (
            "autoMemoryEnabled".to_string(),
            JsonValue::Bool(!coding.disable_auto_memory),
        ),
        (
            "shellWrapper".to_string(),
            JsonValue::Str("agent-guard-sh".to_string()),
        ),
        (
            "mediatingSidecar".to_string(),
            JsonValue::Array(vec![
                JsonValue::Str("agent-guard".to_string()),
                JsonValue::Str("mcp-gateway".to_string()),
            ]),
        ),
        (
            "stopReceiptVerify".to_string(),
            JsonValue::Array(vec![
                JsonValue::Str("dotagent".to_string()),
                JsonValue::Str("verify-receipt".to_string()),
            ]),
        ),
        (
            "feedbackSubmit".to_string(),
            JsonValue::Array(vec![
                JsonValue::Str("dotagent".to_string()),
                JsonValue::Str("feedback".to_string()),
                JsonValue::Str("submit".to_string()),
            ]),
        ),
        (
            "budgets".to_string(),
            JsonValue::Object(vec![
                (
                    "maxSliceLines".to_string(),
                    JsonValue::Uint(coding.max_slice_lines),
                ),
                (
                    "maxRawFileBytes".to_string(),
                    JsonValue::Uint(coding.max_raw_file_bytes),
                ),
                (
                    "maxTurnTokens".to_string(),
                    JsonValue::Uint(coding.max_turn_tokens),
                ),
                (
                    "subagentAirlockMaxTokens".to_string(),
                    JsonValue::Uint(coding.subagent_airlock_max_tokens),
                ),
                (
                    "maxDirectDiscoveryCalls".to_string(),
                    JsonValue::Uint(coding.max_direct_discovery_calls),
                ),
            ]),
        ),
        (
            "subagents".to_string(),
            JsonValue::Object(vec![(
                "research-airlock".to_string(),
                JsonValue::Object(vec![
                    (
                        "baseType".to_string(),
                        JsonValue::Str("research".to_string()),
                    ),
                    ("enableWriteTools".to_string(), JsonValue::Bool(false)),
                    ("enableSubagentTools".to_string(), JsonValue::Bool(false)),
                    ("enableMcpTools".to_string(), JsonValue::Bool(false)),
                    (
                        "workspace".to_string(),
                        JsonValue::Str("inherit".to_string()),
                    ),
                    (
                        "maxWalkDepth".to_string(),
                        JsonValue::Uint(coding.max_directory_walk_depth),
                    ),
                    (
                        "maxReturnTokens".to_string(),
                        JsonValue::Uint(coding.subagent_airlock_max_tokens),
                    ),
                ]),
            )]),
        ),
        (
            "mcpServers".to_string(),
            JsonValue::Object(vec![(
                "susanbdev".to_string(),
                JsonValue::Object(vec![(
                    "url".to_string(),
                    JsonValue::Str(coding.mcp_allowed_endpoint.clone()),
                )]),
            )]),
        ),
    ]);
    format_json_pretty(&doc)
}

/// Lowers an agent markdown specification from Claude frontmatter + body into target-native
/// harness frontmatter (`antigravity`, `claude`, `cursor`, `codex`, `gemini`) driven by the matching `ProfileIr`.
pub fn lower_agent_markdown_for_harness(
    harness: &str,
    agent_file_name: &str,
    claude_markdown: &str,
    profile: Option<&ProfileIr>,
) -> String {
    if harness == "claude" {
        return claude_markdown.to_string();
    }

    let (frontmatter, body) = split_yaml_frontmatter(claude_markdown);
    let name = extract_yaml_scalar(frontmatter, "name")
        .unwrap_or_else(|| agent_file_name.trim_end_matches(".md"));
    let description =
        extract_yaml_scalar(frontmatter, "description").unwrap_or("Zero-trust subagent");
    let enable_writes = profile.is_some_and(|p| p.enable_write_tools);
    let max_tokens = profile.map_or(8_000, |p| p.max_turn_tokens);
    let max_depth = profile.map_or(2, |p| p.max_directory_walk_depth);

    match harness {
        "antigravity" => format!(
            "---\nname: {name}\ndescription: {description}\nenable_write_tools: {enable_writes}\nenable_subagent_tools: false\nenable_mcp_tools: false\nworkspace: inherit\nmax_turn_tokens: {max_tokens}\nmax_walk_depth: {max_depth}\n---\n{body}"
        ),
        "cursor" => format!(
            "---\nname: {name}\ndescription: {description}\nreadonly: {}\nmax_turn_tokens: {max_tokens}\nmax_walk_depth: {max_depth}\n---\n{body}",
            !enable_writes
        ),
        "codex" => format!(
            "---\nname: {name}\ndescription: {description}\nsandbox_mode: {}\nnetwork_access: none\nshell_wrapper: agent-guard-sh\nmax_turn_tokens: {max_tokens}\n---\n{body}",
            if enable_writes {
                "workspace-write"
            } else {
                "read-only"
            }
        ),
        "gemini" => format!(
            "---\nname: {name}\ndescription: {description}\nkind: local\nenable_write_tools: {enable_writes}\nmax_turn_tokens: {max_tokens}\n---\n{body}"
        ),
        _ => claude_markdown.to_string(),
    }
}

fn split_yaml_frontmatter(md: &str) -> (&str, &str) {
    if let Some(rest) = md.strip_prefix("---\n")
        && let Some(end_idx) = rest.find("\n---\n")
    {
        let fm = &rest[..end_idx];
        let body = &rest[end_idx + 5..];
        return (fm, body);
    }
    ("", md)
}

fn extract_yaml_scalar<'a>(fm: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}:");
    for line in fm.lines() {
        if let Some(val) = line.trim().strip_prefix(&prefix) {
            return Some(val.trim().trim_matches('"'));
        }
    }
    None
}

/// Canonical Rego v1 policy bundle evaluated in-process by `regorus` across JSON AND normalized TOML ASTs.
pub fn render_rego_policy_v2() -> String {
    r#"package susanbdev.dotagent.harness

import rego.v1

allowed_mcp_url := "https://mcp.zt.susanb.dev/mcp"
allowed_mcp_keys := {"url", "httpUrl", "type"}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcpServers", {})
    not is_object(cfg)
    msg := sprintf("MCP server '%s' entry must be a JSON object", [server_name])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcpServers", {})
    is_object(cfg)
    some k, _ in cfg
    not k in allowed_mcp_keys
    msg := sprintf("MCP server '%s' contains forbidden field '%s' (stdio/command/args/headers/upstream forbidden)", [server_name, k])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcpServers", {})
    is_object(cfg)
    t := object.get(cfg, "type", "http")
    t != "http"
    msg := sprintf("MCP server '%s' type '%v' is forbidden; only 'http' allowed", [server_name, t])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcpServers", {})
    is_object(cfg)
    u := object.get(cfg, "url", null)
    u != null
    u != allowed_mcp_url
    msg := sprintf("unapproved MCP server '%s' url '%v'", [server_name, u])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcpServers", {})
    is_object(cfg)
    hu := object.get(cfg, "httpUrl", null)
    hu != null
    hu != allowed_mcp_url
    msg := sprintf("unapproved MCP server '%s' httpUrl '%v'", [server_name, hu])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcpServers", {})
    is_object(cfg)
    object.get(cfg, "url", null) == null
    object.get(cfg, "httpUrl", null) == null
    msg := sprintf("MCP server '%s' missing mandatory pinned url/httpUrl", [server_name])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcp_servers", {})
    not is_object(cfg)
    msg := sprintf("Codex TOML mcp_servers.%s entry must be a table", [server_name])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcp_servers", {})
    is_object(cfg)
    some k, _ in cfg
    not k in allowed_mcp_keys
    msg := sprintf("Codex TOML mcp_servers.%s contains forbidden field '%s'", [server_name, k])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcp_servers", {})
    is_object(cfg)
    u := object.get(cfg, "url", null)
    u != null
    u != allowed_mcp_url
    msg := sprintf("unapproved Codex TOML mcp_servers.%s URL '%v'", [server_name, u])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcp_servers", {})
    is_object(cfg)
    hu := object.get(cfg, "httpUrl", null)
    hu != null
    hu != allowed_mcp_url
    msg := sprintf("unapproved Codex TOML mcp_servers.%s httpUrl '%v'", [server_name, hu])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcp_servers", {})
    is_object(cfg)
    object.get(cfg, "url", null) == null
    object.get(cfg, "httpUrl", null) == null
    msg := sprintf("Codex TOML mcp_servers.%s missing mandatory pinned url", [server_name])
}

is_codex_config if object.get(input, "mcp_servers", null) != null
is_codex_config if object.get(input, "sandbox_mode", null) != null
is_codex_config if object.get(input, "approval_policy", null) != null
is_codex_config if object.get(input, "sandbox_workspace_write", null) != null
is_codex_config if object.get(input, "notify", null) != null
is_codex_config if object.get(input, "shell_environment_policy", null) != null
is_codex_config if object.get(input, "project_doc_max_bytes", null) != null
is_codex_config if object.get(input, "model_auto_compact_token_limit", null) != null

deny contains msg if {
    is_codex_config
    object.get(input, "sandbox_mode", "") != "workspace-write"
    msg := "Codex sandbox_mode must equal 'workspace-write'"
}

deny contains msg if {
    is_codex_config
    object.get(input, "approval_policy", "on-request") == "never"
    msg := "Codex approval_policy 'never' is forbidden"
}

deny contains msg if {
    is_codex_config
    object.get(input, "notify", []) != ["agent-guard", "on-stop"]
    msg := "Codex notify hook must equal ['agent-guard', 'on-stop']"
}

deny contains msg if {
    is_codex_config
    object.get(input, "sandbox_workspace_write", null) == null
    msg := "Codex configuration missing mandatory [sandbox_workspace_write] section"
}

deny contains msg if {
    sbx := object.get(input, "sandbox_workspace_write", null)
    sbx != null
    object.get(sbx, "network_access", true) != false
    msg := "Codex sandbox_workspace_write.network_access must be false"
}

deny contains msg if {
    sbx := object.get(input, "sandbox_workspace_write", null)
    sbx != null
    object.get(sbx, "exclude_slash_tmp", false) != true
    msg := "Codex sandbox_workspace_write.exclude_slash_tmp must be true"
}

deny contains msg if {
    some rule in object.get(object.get(input, "permissions", {}), "allow", [])
    contains(rule, "*")
    msg := sprintf("wildcard permission allowlist entry '%s' is forbidden", [rule])
}

deny contains msg if {
    object.get(input, "autoMemoryEnabled", false) == true
    msg := "autoMemoryEnabled must be false to prevent cross-session cache bleed"
}

deny contains msg if {
    object.get(input, "disableAllHooks", false) == true
    msg := "disableAllHooks must be false so agent-guard hooks cannot be disabled"
}

deny contains msg if {
    auth := object.get(input, "authority", null)
    auth != null
    object.get(auth, "root_file", "") != "AGENTS.md"
    msg := "profile authority.root_file must equal AGENTS.md"
}

deny contains msg if {
    git_cfg := object.get(input, "git", null)
    git_cfg != null
    object.get(git_cfg, "hooks_path", "") != "/dev/null"
    msg := "profile git.hooks_path must equal /dev/null"
}

deny contains msg if {
    trav := object.get(input, "traversal", null)
    trav != null
    object.get(input, "role", "") != "investigator"
    object.get(trav, "max_directory_walk_depth", 2) > 2
    msg := "non-investigator profile traversal.max_directory_walk_depth must be <= 2"
}

deny contains msg if {
    trav := object.get(input, "traversal", null)
    trav != null
    object.get(input, "role", "") == "investigator"
    object.get(trav, "max_directory_walk_depth", 20) > 20
    msg := "investigator profile traversal.max_directory_walk_depth must be <= 20"
}

deny contains msg if {
    trav := object.get(input, "traversal", null)
    trav != null
    object.get(trav, "max_reference_pointer_levels", 2) > 2
    msg := "profile traversal.max_reference_pointer_levels must be <= 2"
}

deny contains msg if {
    some prof in object.get(input, "profiles", [])
    object.get(object.get(prof, "git", {}), "hooks_path", "") != "/dev/null"
    msg := sprintf("compiled profile '%s' violates git.hooks_path=/dev/null", [object.get(prof, "profile_id", "<unknown>")])
}

forbidden_workflow_triggers := {"workflow_run", "workflow_call", "repository_dispatch"}

deny contains msg if {
    some trigger in forbidden_workflow_triggers
    on_cfg := object.get(object.get(input, "workflow", {}), "on", {})
    object.get(on_cfg, trigger, null) != null
    msg := sprintf("chained GitHub Actions trigger '%s' is strictly forbidden", [trigger])
}
"#
    .to_string()
}

/// Evaluates `rego_source` (`package susanbdev.dotagent.harness`) in-process using `regorus::Engine`
/// against `input_json_str`. Fails closed if Rego syntax fails or `deny` yields any violation.
pub fn evaluate_rego_policy_gate(
    policy_label: &str,
    rego_source: &str,
    artifact_label: &str,
    input_json_str: &str,
) -> Result<(), String> {
    let mut engine = Engine::new();
    engine
        .add_policy(policy_label.to_string(), rego_source.to_string())
        .map_err(|e| format!("Regorus policy compile error in '{policy_label}': {e}"))?;
    engine
        .set_input_json(input_json_str)
        .map_err(|e| format!("Regorus input JSON error for '{artifact_label}': {e}"))?;
    let val = engine
        .eval_rule("data.susanbdev.dotagent.harness.deny".to_string())
        .map_err(|e| format!("Regorus eval error on '{artifact_label}': {e}"))?;

    let mut violations = Vec::new();
    match val {
        RegoValue::Set(items) => {
            for item in items.iter() {
                violations.push(rego_value_to_plain_string(item));
            }
        }
        RegoValue::Array(items) => {
            for item in items.iter() {
                violations.push(rego_value_to_plain_string(item));
            }
        }
        RegoValue::Undefined => {}
        other => {
            violations.push(format!("unexpected non-empty Rego deny result: {other:?}"));
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        violations.sort();
        Err(format!(
            "Rego policy gate denied '{artifact_label}': {}",
            violations.join("; ")
        ))
    }
}

fn rego_value_to_plain_string(v: &RegoValue) -> String {
    match v {
        RegoValue::String(s) => s.as_ref().to_string(),
        other => format!("{other:?}"),
    }
}

/// Executable Spec Sync (`Pillar 3`): verifies `spec.md` (and `THREAT_MODEL.md`) stay synchronized
/// with the workspace `Cargo.toml` crates, `crates/agent-guard/src/*.rs`, and `crates/agent-guard/src/bin/*.rs`.
pub fn verify_executable_spec_sync(repo_root: &Path) -> Result<(), String> {
    let spec_path = repo_root.join("spec.md");
    let cargo_path = repo_root.join("Cargo.toml");
    let Ok(spec_meta) = fs::symlink_metadata(&spec_path) else {
        return Ok(());
    };
    let Ok(cargo_meta) = fs::symlink_metadata(&cargo_path) else {
        return Ok(());
    };
    if spec_meta.file_type().is_symlink() || cargo_meta.file_type().is_symlink() {
        return Err("SPEC_DRIFT_DETECTED: spec.md and Cargo.toml must not be symlinks".to_string());
    }
    if !spec_meta.file_type().is_file() || !cargo_meta.file_type().is_file() {
        return Ok(());
    }

    let spec_text = fs::read_to_string(&spec_path)
        .map_err(|e| format!("failed reading '{}': {e}", spec_path.display()))?;
    let cargo_text = fs::read_to_string(&cargo_path)
        .map_err(|e| format!("failed reading '{}': {e}", cargo_path.display()))?;

    // 1. Reject stale removed module references (`sha256.rs`)
    if spec_text.contains("sha256.rs") {
        return Err(
            "SPEC_DRIFT_DETECTED: spec.md references removed module 'sha256.rs' (replaced by 'crypto.rs')"
                .to_string(),
        );
    }

    // 2. Verify every workspace member crate in Cargo.toml is documented in spec.md
    for line in cargo_text.lines() {
        let trimmed = line.trim().trim_matches(',').trim_matches('"');
        if let Some(crate_name) = trimmed.strip_prefix("crates/") {
            let tree_tok = format!("+-- {crate_name}/");
            let path_tok = format!("crates/{crate_name}");
            if !spec_text.contains(&tree_tok) && !spec_text.contains(&path_tok) {
                return Err(format!(
                    "SPEC_DRIFT_DETECTED: workspace crate '{crate_name}' in Cargo.toml is missing from spec.md"
                ));
            }
        }
    }

    // 3. Verify every `.rs` module in `crates/agent-guard/src/` and `crates/agent-guard/src/bin/` is documented in `spec.md`
    let guard_src = repo_root.join("crates/agent-guard/src");
    if fs::symlink_metadata(&guard_src).is_ok_and(|m| !m.file_type().is_symlink() && m.is_dir()) {
        let entries = fs::read_dir(&guard_src)
            .map_err(|e| format!("failed reading '{}': {e}", guard_src.display()))?;
        for entry in entries.flatten() {
            let p = entry.path();
            let ft = entry
                .file_type()
                .map_err(|e| format!("cannot stat '{}': {e}", p.display()))?;
            if ft.is_symlink() {
                return Err(format!(
                    "SPEC_DRIFT_DETECTED: symlink '{}' forbidden in crates/agent-guard/src",
                    p.display()
                ));
            }
            if ft.is_file()
                && p.extension().is_some_and(|e| e == "rs")
                && let Some(fname) = p.file_name().and_then(|n| n.to_str())
            {
                let tree_tok = format!("+-- {fname} ");
                let tree_eol = format!("+-- {fname}\n");
                let path_tok = format!("src/{fname}");
                if !spec_text.contains(&tree_tok)
                    && !spec_text.contains(&tree_eol)
                    && !spec_text.contains(&path_tok)
                {
                    return Err(format!(
                        "SPEC_DRIFT_DETECTED: kernel module 'crates/agent-guard/src/{fname}' is undocumented in spec.md"
                    ));
                }
            }
        }
    }
    let guard_bin = guard_src.join("bin");
    if fs::symlink_metadata(&guard_bin).is_ok_and(|m| !m.file_type().is_symlink() && m.is_dir()) {
        let entries = fs::read_dir(&guard_bin)
            .map_err(|e| format!("failed reading '{}': {e}", guard_bin.display()))?;
        for entry in entries.flatten() {
            let p = entry.path();
            let ft = entry
                .file_type()
                .map_err(|e| format!("cannot stat '{}': {e}", p.display()))?;
            if ft.is_symlink() {
                return Err(format!(
                    "SPEC_DRIFT_DETECTED: symlink '{}' forbidden in crates/agent-guard/src/bin",
                    p.display()
                ));
            }
            if ft.is_file()
                && p.extension().is_some_and(|e| e == "rs")
                && let Some(fname) = p.file_name().and_then(|n| n.to_str())
                && !spec_text.contains(&format!("bin/{fname}"))
            {
                return Err(format!(
                    "SPEC_DRIFT_DETECTED: binary target 'crates/agent-guard/src/bin/{fname}' is undocumented in spec.md"
                ));
            }
        }
    }

    // 4. Verify any explicit `crates/<crate>/src/<mod>.rs` path mentioned in `spec.md` or `THREAT_MODEL.md` exists on disk as a non-symlink regular file!
    let mut docs_to_check = vec![("spec.md", spec_text)];
    let tm_path = repo_root.join("THREAT_MODEL.md");
    if let Ok(tm_meta) = fs::symlink_metadata(&tm_path) {
        if tm_meta.file_type().is_symlink() {
            return Err("SPEC_DRIFT_DETECTED: THREAT_MODEL.md must not be a symlink".to_string());
        }
        if tm_meta.file_type().is_file()
            && let Ok(tm_text) = fs::read_to_string(&tm_path)
        {
            docs_to_check.push(("THREAT_MODEL.md", tm_text));
        }
    }

    for (doc_label, body) in &docs_to_check {
        let mut seen = BTreeSet::new();
        for tok in body.split(|c: char| {
            c.is_ascii_whitespace() || matches!(c, '`' | '(' | ')' | '[' | ']' | '"' | '\'' | ',')
        }) {
            let clean = tok.split('#').next().unwrap_or(tok);
            if clean.starts_with("crates/")
                && clean.ends_with(".rs")
                && !clean.contains('*')
                && !clean.contains('<')
                && seen.insert(clean)
            {
                let candidate = repo_root.join(clean);
                let ok_regular = fs::symlink_metadata(&candidate)
                    .is_ok_and(|m| !m.file_type().is_symlink() && m.file_type().is_file());
                if !ok_regular {
                    return Err(format!(
                        "SPEC_DRIFT_DETECTED: {doc_label} references missing or symlinked Rust file '{clean}'"
                    ));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regorus_evaluates_json_and_normalized_codex_toml_policies_and_blocks_bypasses() {
        let rego = render_rego_policy_v2();

        // 1. Valid Codex TOML -> passes Rego!
        let good_codex = r#"
approval_policy = "on-request"
sandbox_mode = "workspace-write"
notify = ["agent-guard", "on-stop"]
[sandbox_workspace_write]
network_access = false
exclude_slash_tmp = true
[mcp_servers.susanbdev]
url = "https://mcp.zt.susanb.dev/mcp"
"#;
        let good_json = normalize_toml_to_json_value(good_codex)
            .expect("valid TOML")
            .to_json_string();
        assert!(evaluate_rego_policy_gate("harness.rego", &rego, "codex.toml", &good_json).is_ok());

        // 1b. Codex TOML omitting notify stop hook -> blocked!
        let missing_notify_json = normalize_toml_to_json_value(
            r#"
approval_policy = "on-request"
sandbox_mode = "workspace-write"
[sandbox_workspace_write]
network_access = false
exclude_slash_tmp = true
"#,
        )
        .expect("valid TOML")
        .to_json_string();
        assert!(
            evaluate_rego_policy_gate("harness.rego", &rego, "codex.toml", &missing_notify_json)
                .is_err()
        );

        // 2. Dotted LHS TOML key bypass (`mcp_servers.evil.url = ...`) -> normalized into nested object & blocked!
        let dotted_bypass = r#"
approval_policy = "on-request"
sandbox_mode = "workspace-write"
sandbox_workspace_write.network_access = false
sandbox_workspace_write.exclude_slash_tmp = true
mcp_servers.evil.url = "https://attacker.example/mcp"
"#;
        let dotted_json = normalize_toml_to_json_value(dotted_bypass)
            .expect("valid dotted TOML")
            .to_json_string();
        let err = evaluate_rego_policy_gate("harness.rego", &rego, "codex.toml", &dotted_json)
            .expect_err("Regorus must block dotted LHS Codex MCP URL");
        assert!(err.contains("attacker.example"), "got: {err}");

        // 3. Quoted table header with dot (`[mcp_servers."evil.dot"]`) -> parsed quote-aware & blocked!
        let quoted_header = r#"
sandbox_mode = "workspace-write"
[sandbox_workspace_write]
network_access = false
exclude_slash_tmp = true
[mcp_servers."evil.dot"]
url = 'https://attacker.example/mcp#frag' # comment after literal string
"#;
        let q_json = normalize_toml_to_json_value(quoted_header)
            .expect("valid quoted TOML")
            .to_json_string();
        assert!(evaluate_rego_policy_gate("harness.rego", &rego, "codex.toml", &q_json).is_err());

        // 4. Dual url + evil httpUrl masking attempt -> blocked!
        let dual_url_json = r#"{"mcpServers":{"susanbdev":{"url":"https://mcp.zt.susanb.dev/mcp","httpUrl":"https://evil.example/mcp"}}}"#;
        let dual_err =
            evaluate_rego_policy_gate("harness.rego", &rego, "settings.json", dual_url_json)
                .expect_err("must block evil httpUrl even when url is valid");
        assert!(dual_err.contains("evil.example"), "got: {dual_err}");

        // 5. disableAllHooks == true -> blocked!
        let hooks_disabled = r#"{"disableAllHooks":true}"#;
        assert!(
            evaluate_rego_policy_gate("harness.rego", &rego, "settings.json", hooks_disabled)
                .is_err()
        );

        // 6. Codex config omitting [sandbox_workspace_write] -> blocked!
        let missing_sbx = r#"
sandbox_mode = "workspace-write"
[mcp_servers.susanbdev]
url = "https://mcp.zt.susanb.dev/mcp"
"#;
        let missing_sbx_json = normalize_toml_to_json_value(missing_sbx)
            .expect("valid TOML")
            .to_json_string();
        assert!(
            evaluate_rego_policy_gate("harness.rego", &rego, "codex.toml", &missing_sbx_json)
                .is_err()
        );

        // 7. Array-of-tables and inline tables rejected fail-closed!
        assert!(normalize_toml_to_json_value("[[mcp_servers]]\nurl = \"x\"").is_err());
        assert!(normalize_toml_to_json_value("mcp_servers = { url = \"x\" }").is_err());
    }
}
