#![forbid(unsafe_code)]

//! Anti-facade `on-stop` smoke gate & artifact attestation (`wrangler`, `.wasm`, stub markers).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::crypto::{hex_encode, sha256_hex};
use crate::json::JsonValue;
use crate::path_policy::glob_match_path;
use crate::stop_receipt::{
    clean_smoke_rel_nonsymlink, recent_or_dirty_repo_paths, strip_code_comments_preserve_lines,
    verify_smoke_artifact,
};

const NEEDLE_TODO: &str = concat!("to", "do!(");
const NEEDLE_UNIMPL: &str = concat!("unimple", "mented!(");
const NEEDLE_FACADE: &str = concat!("FIXME", "_FACADE");
const NEEDLE_STUB_ESC: &str = concat!("{\\\"st", "ub\\\"");
const NEEDLE_STUB_RAW: &str = concat!("{\"st", "ub\"");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmokeGateReport {
    pub smoke_gate_digest: String,
    pub verified_artifacts: BTreeMap<String, String>,
}

fn parse_str_array(raw: &str) -> Result<Vec<String>, String> {
    let t = raw.trim();
    let s = t.strip_prefix('[').and_then(|x| x.strip_suffix(']'));
    let inner = s.ok_or("SMOKE_CONFIG_INVALID: expected array")?.trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    inner
        .split(',')
        .map(|x| {
            let u = x.trim().strip_prefix('"').and_then(|y| y.strip_suffix('"'));
            u.map(String::from)
                .ok_or_else(|| "SMOKE_CONFIG_INVALID: bad str".into())
        })
        .collect()
}

fn parse_smoke_bool(key: &str, value: &str) -> Result<bool, String> {
    value
        .parse::<bool>()
        .map_err(|_| format!("SMOKE_CONFIG_INVALID: '{key}' must be a TOML boolean"))
}

fn extract_wrangler_main(cfg_name: &str, text: &str) -> Result<String, String> {
    if cfg_name.ends_with(".toml") {
        let stripped = strip_code_comments_preserve_lines(text, true);
        for raw in stripped.lines() {
            if let Some((k, v)) = raw.trim().split_once('=')
                && k.trim() == "main"
            {
                let u = v.trim().trim_matches('"').trim_matches('\'').trim();
                if !u.is_empty() {
                    return Ok(u.to_string());
                }
            }
        }
        return Err(format!(
            "SMOKE_CONFIG_INVALID: '{cfg_name}' missing valid main"
        ));
    }
    let stripped = strip_code_comments_preserve_lines(text, false);
    let parsed = JsonValue::parse(&stripped)
        .map_err(|e| format!("SMOKE_CONFIG_INVALID: malformed '{cfg_name}': {e}"))?;
    let main = parsed
        .get("main")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("SMOKE_CONFIG_INVALID: '{cfg_name}' missing valid main"))?;
    Ok(main.to_string())
}

fn collect_wasm_refs(text: &str, base_dir: &str) -> Vec<String> {
    let mut refs = Vec::new();
    for delim in ['"', '\''] {
        for t in text.split(delim).skip(1).step_by(2).map(str::trim) {
            if t.ends_with(".wasm") && !t.contains("://") && !t.starts_with('/') {
                let c = t.trim_start_matches("./");
                let j = if base_dir.is_empty() {
                    c.to_string()
                } else {
                    format!("{base_dir}/{c}")
                };
                if !refs.contains(&j) {
                    refs.push(j);
                }
            }
        }
    }
    refs
}

fn is_non_test_source(rel: &str, exempt: &[String]) -> bool {
    if ![".rs", ".swift", ".ts", ".tsx", ".js", ".mjs", ".jsx", ".kt"]
        .iter()
        .any(|e| rel.ends_with(e))
    {
        return false;
    }
    let f = rel.rsplit('/').next().unwrap_or(rel);
    !(rel.starts_with("tests/")
        || rel.contains("/tests/")
        || rel.contains("/__tests__/")
        || f.ends_with("_test.rs")
        || f.ends_with("_tests.rs")
        || f.contains(".test.")
        || f.contains(".spec.")
        || exempt.iter().any(|g| glob_match_path(g, rel)))
}

pub fn verify_repo_smoke_gate(repo_root: &Path) -> Result<SmokeGateReport, String> {
    let canon = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let cfg_path = canon.join(".dotagent-smoke.toml");
    let (mut req_artifacts, mut exempt) = (Vec::new(), Vec::new());
    let (mut scan_facade, mut detect_wrangler, mut cfg_sha) = (true, true, "NONE".to_string());

    match fs::symlink_metadata(&cfg_path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.file_type().is_file() || meta.len() > 32_768 {
                return Err(
                    "SMOKE_CONFIG_INVALID: .dotagent-smoke.toml invalid or oversized".into(),
                );
            }
            let raw = fs::read(&cfg_path).map_err(|e| format!("SMOKE_CONFIG_INVALID: {e}"))?;
            if raw.iter().any(|&b| b >= 0x80 || b == 0) {
                return Err("SMOKE_CONFIG_INVALID: .dotagent-smoke.toml non-ASCII".into());
            }
            cfg_sha = sha256_hex(&raw);
            for raw_line in String::from_utf8_lossy(&raw).lines() {
                let line = raw_line.split('#').next().unwrap_or("").trim();
                if line.is_empty() || line.starts_with('[') {
                    continue;
                }
                let (k, v) = line
                    .split_once('=')
                    .ok_or("SMOKE_CONFIG_INVALID: bad line")?;
                match (k.trim(), v.trim()) {
                    ("required_artifacts", val) => req_artifacts = parse_str_array(val)?,
                    ("allowed_facade_globs", val) => exempt = parse_str_array(val)?,
                    (key @ "scan_facade_tokens", val) => {
                        scan_facade = parse_smoke_bool(key, val)?;
                    }
                    (key @ "wrangler_auto_detect", val) => {
                        detect_wrangler = parse_smoke_bool(key, val)?;
                    }
                    (other, _) => {
                        return Err(format!("SMOKE_CONFIG_INVALID: unknown key '{other}'"));
                    }
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!(
                "SMOKE_CONFIG_INVALID: cannot stat .dotagent-smoke.toml: {e}"
            ));
        }
    }

    let mut verified = BTreeMap::new();
    for rel in &req_artifacts {
        verify_smoke_artifact(
            &canon,
            rel,
            ".dotagent-smoke.toml",
            &mut verified,
            std::io::sink(),
        )?;
    }

    if detect_wrangler {
        let rd = fs::read_dir(&canon)
            .map_err(|e| format!("SMOKE_CONFIG_INVALID: cannot read repo root: {e}"))?;
        let mut cfgs: Vec<(String, PathBuf)> = Vec::new();
        for entry_res in rd {
            let e = entry_res.map_err(|er| format!("SMOKE_CONFIG_INVALID: dir entry: {er}"))?;
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with("wrangler")
                && (n.ends_with(".toml") || n.ends_with(".jsonc") || n.ends_with(".json"))
            {
                cfgs.push((n, e.path()));
            }
        }
        cfgs.sort_by(|a, b| a.0.cmp(&b.0));
        for (cfg_name, p) in cfgs {
            let m = fs::symlink_metadata(&p)
                .map_err(|e| format!("SMOKE_CONFIG_INVALID: cannot stat '{cfg_name}': {e}"))?;
            if m.file_type().is_symlink() || !m.file_type().is_file() || m.len() > 131_072 {
                return Err(format!(
                    "SMOKE_CONFIG_INVALID: '{cfg_name}' symlink or oversized"
                ));
            }
            let text = fs::read_to_string(&p)
                .map_err(|e| format!("SMOKE_CONFIG_INVALID: cannot read '{cfg_name}': {e}"))?;
            let main_rel = extract_wrangler_main(&cfg_name, &text)?;
            let mut shim_bytes = Vec::new();
            verify_smoke_artifact(&canon, &main_rel, &cfg_name, &mut verified, &mut shim_bytes)?;
            let pdir = Path::new(main_rel.trim_start_matches("./"))
                .parent()
                .map(|d| d.to_string_lossy().into_owned())
                .unwrap_or_default();
            for w in collect_wasm_refs(&text, "") {
                verify_smoke_artifact(&canon, &w, &cfg_name, &mut verified, std::io::sink())?;
            }
            let shim = String::from_utf8(shim_bytes)
                .map_err(|e| format!("SMOKE_ARTIFACT_MISSING: cannot read '{main_rel}': {e}"))?;
            for w in collect_wasm_refs(&shim, &pdir) {
                verify_smoke_artifact(&canon, &w, &main_rel, &mut verified, std::io::sink())?;
            }
        }
    }

    if scan_facade {
        for rel in recent_or_dirty_repo_paths(&canon)? {
            if !is_non_test_source(&rel, &exempt) {
                continue;
            }
            if matches!(
                fs::symlink_metadata(canon.join(rel.trim_start_matches("./"))),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound
            ) {
                continue;
            }
            let (full, norm) = clean_smoke_rel_nonsymlink(&canon, &rel)?;
            let text = fs::read_to_string(&full)
                .map_err(|e| format!("SMOKE_CONFIG_INVALID: cannot read '{norm}': {e}"))?;
            let stripped = strip_code_comments_preserve_lines(&text, false);
            for (idx, (raw_l, code_l)) in text.lines().zip(stripped.lines()).enumerate() {
                let nw: String = code_l
                    .chars()
                    .filter(|c| !c.is_ascii_whitespace())
                    .collect();
                if raw_l.contains(NEEDLE_FACADE)
                    || nw.contains(NEEDLE_TODO)
                    || nw.contains(NEEDLE_UNIMPL)
                    || nw.contains(NEEDLE_STUB_ESC)
                    || nw.contains(NEEDLE_STUB_RAW)
                {
                    return Err(format!(
                        "SMOKE_FACADE_TOKEN_DETECTED: stub marker in '{norm}:{}'",
                        idx + 1
                    ));
                }
            }
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(b"DOTAGENT_SMOKE_GATE_V1\0");
    hasher.update(cfg_sha.as_bytes());
    hasher.update([0u8]);
    for (k, v) in &verified {
        hasher.update((k.len() as u32).to_be_bytes());
        hasher.update(k.as_bytes());
        hasher.update(v.as_bytes());
    }
    Ok(SmokeGateReport {
        smoke_gate_digest: hex_encode(&hasher.finalize()),
        verified_artifacts: verified,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_smoke_bool;

    #[test]
    fn smoke_config_booleans_require_toml_literals() {
        for key in ["scan_facade_tokens", "wrangler_auto_detect"] {
            assert_eq!(parse_smoke_bool(key, "true"), Ok(true));
            assert_eq!(parse_smoke_bool(key, "false"), Ok(false));
            for value in ["yes", "1", "\"false\"", "False", ""] {
                assert!(parse_smoke_bool(key, value).is_err());
            }
        }
    }
}
