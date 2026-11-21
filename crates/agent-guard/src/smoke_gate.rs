#![forbid(unsafe_code)]

//! Anti-facade `on-stop` smoke gate & artifact attestation (`wrangler`, `.wasm`, stub markers).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::crypto::{hex_encode, sha256_hex};
use crate::path_policy::glob_match_path;
use crate::stop_receipt::dirty_porcelain_paths;

const WASM_V1_MAGIC: &[u8; 8] = b"\0asm\x01\0\0\0";
const NEEDLE_TODO: &str = concat!("to", "do!(");
const NEEDLE_UNIMPL: &str = concat!("unimple", "mented!(");
const NEEDLE_FACADE: &str = concat!("FIXME", "_FACADE");
const NEEDLE_STUB_JSON: &str = concat!("{\\\"st", "ub\\\"");

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

fn clean_rel_nonsymlink(canon_repo: &Path, rel: &str) -> Result<(PathBuf, String), String> {
    let trimmed = rel.trim().trim_start_matches("./");
    if trimmed.is_empty() || Path::new(trimmed).is_absolute() {
        return Err(format!("SMOKE_ARTIFACT_MISSING: invalid path '{rel}'"));
    }
    let (mut cur, mut norm) = (canon_repo.to_path_buf(), Vec::new());
    for comp in Path::new(trimmed).components() {
        match comp {
            Component::CurDir => {}
            Component::Normal(seg) => {
                let s = seg.to_string_lossy().into_owned();
                cur.push(&s);
                if fs::symlink_metadata(&cur).is_ok_and(|m| m.file_type().is_symlink()) {
                    return Err(format!("SMOKE_ARTIFACT_MISSING: symlink '{rel}'"));
                }
                norm.push(s);
            }
            _ => return Err(format!("SMOKE_ARTIFACT_MISSING: traversal '{rel}'")),
        }
    }
    Ok((cur, norm.join("/")))
}

fn verify_artifact(
    canon: &Path,
    rel: &str,
    hint: &str,
    out: &mut BTreeMap<String, String>,
) -> Result<PathBuf, String> {
    let (full, norm) = clean_rel_nonsymlink(canon, rel)?;
    let meta = fs::symlink_metadata(&full)
        .map_err(|_| format!("SMOKE_ARTIFACT_MISSING: '{norm}' ({hint}) missing"))?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() || meta.len() == 0 {
        return Err(format!(
            "SMOKE_ARTIFACT_MISSING: '{norm}' ({hint}) empty or non-regular"
        ));
    }
    let bytes = fs::read(&full).map_err(|e| format!("SMOKE_ARTIFACT_MISSING: '{norm}': {e}"))?;
    if norm.ends_with(".wasm") && !bytes.starts_with(WASM_V1_MAGIC) {
        return Err(format!(
            "SMOKE_WASM_MAGIC_INVALID: '{norm}' lacks valid Wasm v1 magic"
        ));
    }
    out.insert(norm, sha256_hex(&bytes));
    Ok(full)
}

fn strip_jsonc_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_str = false;
    let mut esc = false;
    while let Some(c) = chars.next() {
        if in_str {
            out.push(c);
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
        } else if c == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for n in chars.by_ref() {
                if n == '\n' {
                    out.push('\n');
                    break;
                }
            }
        } else if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            while let Some(n) = chars.next() {
                if n == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn extract_wrangler_main(cfg_name: &str, text: &str) -> Option<String> {
    if cfg_name.ends_with(".toml") {
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if let Some((k, v)) = line.split_once('=')
                && k.trim() == "main"
            {
                let u = v.trim().trim_matches('"').trim_matches('\'');
                if !u.is_empty() {
                    return Some(u.to_string());
                }
            }
        }
        return None;
    }
    let cleaned = if cfg_name.ends_with(".jsonc") {
        strip_jsonc_comments(text)
    } else {
        text.to_string()
    };
    let val = crate::JsonValue::parse(&cleaned).ok()?;
    let main_s = val.get("main").and_then(crate::JsonValue::as_str)?.trim();
    if main_s.is_empty() {
        None
    } else {
        Some(main_s.to_string())
    }
}

fn collect_wasm_refs(text: &str, base_dir: &str) -> Vec<String> {
    let mut refs = Vec::new();
    for t in text.split('"').skip(1).step_by(2).map(str::trim) {
        if t.ends_with(".wasm") && !t.contains("://") && !t.starts_with('/') {
            let c = t.trim_start_matches("./");
            let j = if base_dir.is_empty() || !t.starts_with("./") {
                c.to_string()
            } else {
                format!("{base_dir}/{c}")
            };
            if !refs.contains(&j) {
                refs.push(j);
            }
        }
    }
    refs
}

fn is_non_test_source(rel: &str, exempt: &[String]) -> bool {
    if ![".rs", ".swift", ".ts", ".tsx", ".kt"]
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

    if let Ok(meta) = fs::symlink_metadata(&cfg_path) {
        if meta.file_type().is_symlink() || !meta.file_type().is_file() || meta.len() > 32_768 {
            return Err("SMOKE_CONFIG_INVALID: .dotagent-smoke.toml invalid or oversized".into());
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
                ("scan_facade_tokens", val) => scan_facade = val == "true",
                ("wrangler_auto_detect", val) => detect_wrangler = val == "true",
                (other, _) => return Err(format!("SMOKE_CONFIG_INVALID: unknown key '{other}'")),
            }
        }
    }

    let mut verified = BTreeMap::new();
    for rel in &req_artifacts {
        verify_artifact(&canon, rel, ".dotagent-smoke.toml", &mut verified)?;
    }

    if detect_wrangler && let Ok(rd) = fs::read_dir(&canon) {
        let mut cfgs: Vec<(String, PathBuf)> = rd
            .flatten()
            .filter_map(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                let w = n.starts_with("wrangler")
                    && (n.ends_with(".toml") || n.ends_with(".jsonc") || n.ends_with(".json"));
                w.then(|| (n, e.path()))
            })
            .collect();
        cfgs.sort_by(|a, b| a.0.cmp(&b.0));
        for (cfg_name, p) in cfgs {
            let m = fs::symlink_metadata(&p)
                .map_err(|e| format!("SMOKE_CONFIG_INVALID: cannot stat '{cfg_name}': {e}"))?;
            if m.file_type().is_symlink() || !m.file_type().is_file() || m.len() > 131_072 {
                return Err(format!(
                    "SMOKE_CONFIG_INVALID: '{cfg_name}' is symlink, non-regular file, or exceeds 128 KiB"
                ));
            }
            let text = fs::read_to_string(&p)
                .map_err(|e| format!("SMOKE_CONFIG_INVALID: cannot read '{cfg_name}': {e}"))?;
            let main_rel = extract_wrangler_main(&cfg_name, &text).ok_or_else(|| {
                format!("SMOKE_CONFIG_INVALID: '{cfg_name}' is missing a valid 'main' entrypoint")
            })?;
            let main_full = verify_artifact(&canon, &main_rel, &cfg_name, &mut verified)?;
            let pdir = Path::new(main_rel.trim_start_matches("./"))
                .parent()
                .map(|d| d.to_string_lossy().into_owned())
                .unwrap_or_default();
            for w in collect_wasm_refs(&text, "") {
                verify_artifact(&canon, &w, &cfg_name, &mut verified)?;
            }
            if let Ok(shim) = fs::read_to_string(&main_full) {
                for w in collect_wasm_refs(&shim, &pdir) {
                    verify_artifact(&canon, &w, &main_rel, &mut verified)?;
                }
            }
        }
    }

    if scan_facade {
        for rel in dirty_porcelain_paths(&canon) {
            if !is_non_test_source(&rel, &exempt) {
                continue;
            }
            let Ok((full, norm)) = clean_rel_nonsymlink(&canon, &rel) else {
                continue;
            };
            let Ok(text) = fs::read_to_string(&full) else {
                continue;
            };
            for (idx, line) in text.lines().enumerate() {
                let code_part = line.split("//").next().unwrap_or("");
                if line.contains(NEEDLE_FACADE)
                    || code_part.contains(NEEDLE_TODO)
                    || code_part.contains(NEEDLE_UNIMPL)
                    || code_part.contains(NEEDLE_STUB_JSON)
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
