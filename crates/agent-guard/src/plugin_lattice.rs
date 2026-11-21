#![forbid(unsafe_code)]

//! Zero-exposure monotonic `PreToolUse` plugin lattice (`Rego` + declarative `.toml` quorums).

use std::path::Path;

use regorus::{Engine, Value as RegoValue};

use crate::Decision;
pub use crate::breadcrumbs::{count_verified_quorum_approvals, record_quorum_approval_breadcrumb};
pub use crate::budget_guard::MAX_PLUGIN_FILE_BYTES;
use crate::budget_guard::{RuntimeProfile, load_verified_profile_plugins};
use crate::json::JsonValue;
pub use crate::path_policy::glob_match_path;
use crate::sshsig_touch::verify_env_plugin_touch;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerdictLevel {
    Allow = 0,
    EmitSignal = 1,
    RequireVoteQuorum = 2,
    RequireHumanTouch = 3,
    Deny = 4,
    HaltSession = 5,
}

impl VerdictLevel {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Allow),
            1 => Some(Self::EmitSignal),
            2 => Some(Self::RequireVoteQuorum),
            3 => Some(Self::RequireHumanTouch),
            4 => Some(Self::Deny),
            5 => Some(Self::HaltSession),
            _ => None,
        }
    }

    pub fn parse_tag(raw: &str) -> Option<(Self, Option<usize>)> {
        let s = raw.trim().to_ascii_lowercase().replace('-', "_");
        if let Some(rest) = s.strip_prefix("require_vote_quorum(") {
            let n = rest.strip_suffix(')')?.trim().parse::<usize>().ok()?;
            return Some((Self::RequireVoteQuorum, Some(n.clamp(1, 16))));
        }
        match s.as_str() {
            "allow" => Some((Self::Allow, None)),
            "emit_signal" | "signal" => Some((Self::EmitSignal, None)),
            "require_vote_quorum" | "vote_quorum" | "quorum" => {
                Some((Self::RequireVoteQuorum, None))
            }
            "require_human_touch" | "human_touch" => Some((Self::RequireHumanTouch, None)),
            "deny" => Some((Self::Deny, None)),
            "halt_session" | "halt" => Some((Self::HaltSession, None)),
            _ => None,
        }
    }
}

pub fn combine_verdicts(ring0_core: VerdictLevel, plugin_levels: &[VerdictLevel]) -> VerdictLevel {
    plugin_levels.iter().copied().fold(ring0_core, Ord::max)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookSnapshot {
    pub phase: String,
    pub repo_id: String,
    pub role: String,
    pub tool_name: String,
    pub is_write: bool,
    pub cmd_program: String,
    pub cmd_args_sanitized: Vec<String>,
    pub target_rel_paths: Vec<String>,
    pub tainted: bool,
    pub step_count: u32,
    pub recent_denial_count_60s: u32,
    pub ballot_anomaly_count: u32,
    pub active_quorum_approvals: usize,
}

impl HookSnapshot {
    pub fn to_json_value(&self) -> JsonValue {
        let kv = |k: &str, v: &str| (k.to_string(), JsonValue::Str(v.to_string()));
        let kb = |k: &str, v: bool| (k.to_string(), JsonValue::Bool(v));
        let ku = |k: &str, v: u64| (k.to_string(), JsonValue::Uint(v));
        let arr = |k: &str, xs: &[String]| {
            let items = xs.iter().cloned().map(JsonValue::Str).collect();
            (k.to_string(), JsonValue::Array(items))
        };
        let d60 = u64::from(self.recent_denial_count_60s);
        let banom = u64::from(self.ballot_anomaly_count);
        let qapp = self.active_quorum_approvals as u64;
        JsonValue::Object(vec![
            kv("phase", &self.phase),
            kv("repo_id", &self.repo_id),
            kv("role", &self.role),
            kv("tool_name", &self.tool_name),
            kb("is_write", self.is_write),
            kv("cmd_program", &self.cmd_program),
            arr("cmd_args_sanitized", &self.cmd_args_sanitized),
            arr("target_rel_paths", &self.target_rel_paths),
            kb("tainted", self.tainted),
            ku("step_count", u64::from(self.step_count)),
            ku("recent_denial_count_60s", d60),
            ku("ballot_anomaly_count", banom),
            ku("active_quorum_approvals", qapp),
        ])
    }
}

type Outcome = (VerdictLevel, usize, Vec<String>, &'static str, String);

fn parse_list(raw: &str) -> Result<Vec<String>, String> {
    let t = raw.trim();
    let inner = t.strip_prefix('[').and_then(|x| x.strip_suffix(']'));
    let inner = inner.ok_or_else(|| "bad array".to_string())?.trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for item in inner.split(',') {
        let s = item
            .trim()
            .strip_prefix('"')
            .and_then(|x| x.strip_suffix('"'));
        out.push(s.ok_or_else(|| "bad str".to_string())?.to_string());
    }
    Ok(out)
}

fn try_eval_toml(name: &str, src: &str, snap: &HookSnapshot) -> Result<Outcome, String> {
    let (mut tools, mut globs, mut cmds, mut roles) = (vec![], vec![], vec![], vec![]);
    let (mut write_only, mut when_tainted) = (false, false);
    let (mut min_denials, mut min_anomalies, mut min_steps) = (0u32, 0u32, 0u32);
    let (mut verdict, mut min_app, mut reason) = (VerdictLevel::Allow, 2usize, name.to_string());
    for raw in src.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || matches!(line, "[rule]" | "[[rule]]") {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| format!("Malformed line in '{name}'"))?;
        let (key, val) = (k.trim(), v.trim());
        match key {
            "id" => {}
            "reason" => reason = val.trim_matches('"').to_string(),
            "write_only" => write_only = val == "true",
            "when_tainted" => when_tainted = val == "true",
            "min_recent_denials_60s" => min_denials = val.parse().unwrap_or(u32::MAX),
            "min_ballot_anomalies" => min_anomalies = val.parse().unwrap_or(u32::MAX),
            "min_steps" => min_steps = val.parse().unwrap_or(u32::MAX),
            "min_approvals" => min_app = val.parse::<usize>().unwrap_or(2).clamp(1, 16),
            "tools" => tools = parse_list(val)?,
            "path_globs" => globs = parse_list(val)?,
            "cmd_programs" => cmds = parse_list(val)?,
            "roles" => roles = parse_list(val)?,
            "verdict" => {
                let (lvl, opt_n) = VerdictLevel::parse_tag(val.trim_matches('"'))
                    .ok_or_else(|| format!("Unknown verdict in '{name}'"))?;
                (verdict, min_app) = (lvl, opt_n.unwrap_or(min_app));
            }
            _ => return Err(format!("Unknown key '{key}' in '{name}'")),
        }
    }
    let tool_ok = tools.is_empty()
        || tools
            .iter()
            .any(|t| t == "*" || t.eq_ignore_ascii_case(&snap.tool_name));
    let glob_ok = globs.is_empty()
        || snap
            .target_rel_paths
            .iter()
            .any(|p| globs.iter().any(|g| glob_match_path(g, p)));
    let matched = (!write_only || snap.is_write)
        && (!when_tainted || snap.tainted)
        && snap.recent_denial_count_60s >= min_denials
        && snap.ballot_anomaly_count >= min_anomalies
        && snap.step_count >= min_steps
        && tool_ok
        && (cmds.is_empty() || cmds.contains(&snap.cmd_program))
        && glob_ok;
    let lvl = if matched {
        verdict
    } else {
        VerdictLevel::Allow
    };
    Ok((lvl, min_app, roles, "PLUGIN_POLICY_DENIED", reason))
}

fn try_eval_rego(name: &str, src: &str, snap_json: &str) -> Result<Outcome, String> {
    for banned in ["http.send", "opa.runtime", "net.lookup_ip_addr"] {
        if src.contains(banned) {
            return Err(format!("Forbidden builtin '{banned}' in '{name}'."));
        }
    }
    let pkg = src
        .lines()
        .find_map(|l| l.trim().strip_prefix("package ").map(str::trim))
        .unwrap_or("dotagent.plugin");
    let mut engine = Engine::new();
    engine
        .add_policy(name.to_string(), src.to_string())
        .map_err(|e| format!("Rego compile error in '{name}': {e}"))?;
    engine
        .set_input_json(snap_json)
        .map_err(|e| format!("Rego input error: {e}"))?;
    let mut level = VerdictLevel::Allow;
    let mut min_app = match engine.eval_rule(format!("data.{pkg}.min_approvals")) {
        Ok(RegoValue::Number(n)) => n.as_u64().unwrap_or(2) as usize,
        _ => 2usize,
    }
    .clamp(1, 16);
    let reason = match engine.eval_rule(format!("data.{pkg}.reason")) {
        Ok(RegoValue::String(s)) => s.as_ref().to_string(),
        _ => format!("Rego plugin '{name}' escalated verdict."),
    };
    match engine
        .eval_rule(format!("data.{pkg}.verdict"))
        .map_err(|e| format!("Rego eval error in '{name}': {e}"))?
    {
        RegoValue::String(s) => {
            let (lvl, opt_n) = VerdictLevel::parse_tag(s.as_ref())
                .ok_or_else(|| format!("Invalid Rego verdict '{s}' in '{name}'."))?;
            (level, min_app) = (level.max(lvl), opt_n.unwrap_or(min_app));
        }
        RegoValue::Undefined => {}
        _ => return Err(format!("Non-string Rego verdict in '{name}'.")),
    }
    if matches!(
        engine.eval_rule(format!("data.{pkg}.deny")),
        Ok(RegoValue::Bool(true))
    ) {
        level = level.max(VerdictLevel::Deny);
    }
    if let Ok(RegoValue::Number(n)) = engine.eval_rule(format!("data.{pkg}.require_quorum"))
        && let Some(q) = n.as_u64()
        && q > 0
    {
        (level, min_app) = (
            level.max(VerdictLevel::RequireVoteQuorum),
            (q as usize).clamp(1, 16),
        );
    }
    Ok((level, min_app, Vec::new(), "PLUGIN_POLICY_DENIED", reason))
}

pub fn apply_pre_tool_plugin_lattice(
    repo_root: &Path,
    session_id: &str,
    profile: &RuntimeProfile,
    mut snap: HookSnapshot,
    ring0_decision: Decision,
) -> Decision {
    let ring0_core = match &ring0_decision {
        Decision::Allow { .. } => VerdictLevel::Allow,
        Decision::Deny { halt_session, .. } if *halt_session => VerdictLevel::HaltSession,
        Decision::Deny { .. } => VerdictLevel::Deny,
    };
    let plugins = match load_verified_profile_plugins(repo_root, profile) {
        Ok(list) if list.is_empty() => return ring0_decision,
        Ok(list) => list,
        Err((c, r)) if ring0_core < VerdictLevel::Deny => return Decision::deny(c, r, false),
        Err(_) => return ring0_decision,
    };
    let paths = &snap.target_rel_paths;
    snap.active_quorum_approvals =
        count_verified_quorum_approvals(repo_root, session_id, paths, &[]);
    let snap_json = snap.to_json_value().to_json_string();
    let (mut levels, mut max_q, mut q_roles) = (Vec::new(), 1usize, Vec::new());
    let (mut top_code, mut top_reason) = ("PLUGIN_POLICY_DENIED", String::new());
    for (fname, src) in &plugins {
        let res = if fname.ends_with(".rego") {
            try_eval_rego(fname, src, &snap_json)
        } else {
            try_eval_toml(fname, src, &snap)
        };
        let (lvl, min_app, roles, code, reason) =
            res.unwrap_or_else(|e| (VerdictLevel::Deny, 0, vec![], "PLUGIN_EVALUATION_ERROR", e));
        if lvl == VerdictLevel::RequireVoteQuorum && min_app >= max_q {
            max_q = min_app;
            if !roles.is_empty() {
                q_roles = roles;
            }
        }
        if (lvl >= VerdictLevel::RequireVoteQuorum && top_reason.is_empty())
            || code != "PLUGIN_POLICY_DENIED"
        {
            (top_code, top_reason) = (code, reason);
        }
        levels.push(lvl);
    }
    let final_level = combine_verdicts(ring0_core, &levels);
    if ring0_core >= VerdictLevel::Deny {
        if let (Decision::Deny { code, reason, .. }, VerdictLevel::HaltSession) =
            (&ring0_decision, final_level)
        {
            return Decision::deny(code, reason.clone(), true);
        }
        return ring0_decision;
    }
    match final_level {
        VerdictLevel::Allow => ring0_decision,
        VerdictLevel::EmitSignal => {
            eprintln!(
                "[AGENTPI_EVENT] {{\"schema\":\"dotagent.agentpi.event.v1\",\"event_type\":\"PLUGIN_LATTICE_SIGNAL\",\"risk_level\":\"low\",\"tool_name\":\"{}\"}}",
                snap.tool_name
            );
            ring0_decision
        }
        VerdictLevel::RequireVoteQuorum => {
            let paths = &snap.target_rel_paths;
            let v = if q_roles.is_empty() {
                snap.active_quorum_approvals
            } else {
                count_verified_quorum_approvals(repo_root, session_id, paths, &q_roles)
            };
            if v >= max_q {
                ring0_decision
            } else {
                let msg = format!("{top_reason} (verified_approvals={v}/{max_q})");
                Decision::deny("PLUGIN_QUORUM_REQUIRED", msg, false)
            }
        }
        VerdictLevel::RequireHumanTouch
            if verify_env_plugin_touch(
                repo_root,
                format!(
                    "dotagent:plugin-touch:v1:{}:{session_id}:{}:{}",
                    snap.repo_id,
                    snap.tool_name,
                    snap.target_rel_paths.join(","),
                )
                .as_bytes(),
            ) =>
        {
            ring0_decision
        }
        VerdictLevel::RequireHumanTouch => {
            Decision::deny("PLUGIN_HUMAN_TOUCH_REQUIRED", top_reason, false)
        }
        VerdictLevel::Deny => Decision::deny(top_code, top_reason, false),
        VerdictLevel::HaltSession => Decision::deny("PLUGIN_POLICY_HALT", top_reason, true),
    }
}
