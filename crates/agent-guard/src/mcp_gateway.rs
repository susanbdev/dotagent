#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! `agent-guard mcp-gateway`: Local Zero-Trust Mediating MCP Proxy (`Pillar 2`).
//!
//! Gives every AI harness (OpenAI Codex, Cursor, Claude Code, Gemini CLI, and remote cloud VMs)
//! identical `Ring-1` runtime enforcement over a single local Model Context Protocol (`JSON-RPC 2.0`)
//! stdio proxy:
//! - Mediates `dotagent_read_file`, `dotagent_edit_file`, `dotagent_search`, `dotagent_exec`, and
//!   `dotagent_status` through `handle_pre_tool_hook` (`SessionLedger` `A -> B` ceiling, forbidden
//!   zones, `cmd_policy`, taint/halt circuit breaker) and `handle_post_tool_hook` (7-bit ASCII
//!   pre-buffer spotlighting + poisoned-pointer halt).
//! - Pins upstream MCP routing exclusively to `https://mcp.zt.susanb.dev/mcp` and implements
//!   RFC 7636 OAuth 2.1 PKCE (`S256`) + RFC 9449 Ed25519 `DPoP` (`dpop+jwt`) proof binding.

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::budget_guard::{inspect_file_budget, load_active_profile};
use crate::crypto::{ZeroizingKey, hex_encode, sha256_bytes};
use crate::json::JsonValue;
use crate::mcp_policy::authorize_mcp_rpc_invocation;
use crate::path_policy::{PathAccess, validate_path};
use crate::sanitizer::wrap_spotlight_envelope;
use crate::traversal_ledger::SessionLedger;
use crate::{
    Decision, handle_post_edit, handle_post_tool_hook, handle_pre_tool_hook, resolve_repo_root,
};

pub const CANONICAL_UPSTREAM_MCP_URL: &str = "https://mcp.zt.susanb.dev/mcp";
const MAX_MCP_FRAME_BYTES: usize = 262_144; // 256 KiB per JSON-RPC frame

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpWireFraming {
    NewlineDelimited,
    ContentLength,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkceS256Challenge {
    pub code_challenge: String,
    pub code_challenge_method: &'static str,
}

/// Validates that an upstream MCP endpoint matches the sole pinned zero-trust URL.
pub fn validate_upstream_mcp_endpoint(url: &str) -> Result<&'static str, (&'static str, String)> {
    if url.trim() == CANONICAL_UPSTREAM_MCP_URL {
        Ok(CANONICAL_UPSTREAM_MCP_URL)
    } else {
        Err((
            "MCP_ENDPOINT_PIN_VIOLATION",
            format!(
                "Upstream MCP endpoint '{url}' is forbidden; only '{CANONICAL_UPSTREAM_MCP_URL}' is permitted."
            ),
        ))
    }
}

/// Computes an RFC 7636 OAuth 2.1 PKCE `S256` challenge (`BASE64URL_NOPAD(SHA256(verifier))`).
pub fn compute_pkce_s256_challenge(code_verifier: &str) -> Result<PkceS256Challenge, String> {
    let bytes = code_verifier.as_bytes();
    if bytes.len() < 43 || bytes.len() > 128 {
        return Err("PKCE code_verifier length must be 43..=128 ASCII characters".to_string());
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    {
        return Err("PKCE code_verifier contains invalid non-RFC7636 characters".to_string());
    }
    let digest = sha256_bytes(bytes);
    Ok(PkceS256Challenge {
        code_challenge: base64url_encode_nopad(&digest),
        code_challenge_method: "S256",
    })
}

/// Mints an RFC 9449 `dpop+jwt` (`EdDSA` / Ed25519) proof token bound to `(htm, htu, ath, jti, iat)`,
/// enforcing that `htu` matches `https://mcp.zt.susanb.dev/mcp`.
pub fn mint_dpop_proof_jwt(
    signing_key: &SigningKey,
    htm: &str,
    htu: &str,
    access_token: Option<&str>,
    jti: &str,
    iat: u64,
) -> Result<String, String> {
    validate_upstream_mcp_endpoint(htu).map_err(|(c, m)| format!("{c}: {m}"))?;
    if !matches!(htm, "POST" | "GET") {
        return Err(format!("unsupported DPoP HTTP method '{htm}'"));
    }
    if jti.trim().is_empty() {
        return Err("DPoP jti must be non-empty".to_string());
    }

    let pub_b64 = base64url_encode_nopad(signing_key.verifying_key().as_bytes());
    let header = JsonValue::Object(vec![
        ("typ".to_string(), JsonValue::Str("dpop+jwt".to_string())),
        ("alg".to_string(), JsonValue::Str("EdDSA".to_string())),
        (
            "jwk".to_string(),
            JsonValue::Object(vec![
                ("kty".to_string(), JsonValue::Str("OKP".to_string())),
                ("crv".to_string(), JsonValue::Str("Ed25519".to_string())),
                ("x".to_string(), JsonValue::Str(pub_b64)),
            ]),
        ),
    ]);

    let mut claims = vec![
        ("jti".to_string(), JsonValue::Str(jti.to_string())),
        ("htm".to_string(), JsonValue::Str(htm.to_string())),
        ("htu".to_string(), JsonValue::Str(htu.to_string())),
        ("iat".to_string(), JsonValue::Uint(iat)),
    ];
    if let Some(tok) = access_token.filter(|t| !t.is_empty()) {
        let ath = base64url_encode_nopad(&sha256_bytes(tok.as_bytes()));
        claims.push(("ath".to_string(), JsonValue::Str(ath)));
    }
    let payload = JsonValue::Object(claims);

    let header_b64 = base64url_encode_nopad(header.to_json_string().as_bytes());
    let payload_b64 = base64url_encode_nopad(payload.to_json_string().as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = base64url_encode_nopad(&sig.to_bytes());
    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Verifies an RFC 9449 `dpop+jwt` (`EdDSA` / Ed25519) proof token against `(expected_htm, expected_htu, access_token)`.
pub fn verify_dpop_proof_jwt(
    jwt: &str,
    expected_htm: &str,
    expected_htu: &str,
    expected_access_token: Option<&str>,
) -> Result<VerifyingKey, String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("malformed DPoP JWT: expected 3 dot-separated segments".to_string());
    }
    let header_bytes = base64url_decode_nopad(parts[0])?;
    let payload_bytes = base64url_decode_nopad(parts[1])?;
    let sig_bytes = base64url_decode_nopad(parts[2])?;

    let header_str =
        String::from_utf8(header_bytes).map_err(|_| "non-UTF8 DPoP header".to_string())?;
    let payload_str =
        String::from_utf8(payload_bytes).map_err(|_| "non-UTF8 DPoP payload".to_string())?;
    let header = JsonValue::parse(&header_str).map_err(|e| format!("invalid DPoP header: {e}"))?;
    let payload =
        JsonValue::parse(&payload_str).map_err(|e| format!("invalid DPoP payload: {e}"))?;

    if header.get("typ").and_then(JsonValue::as_str) != Some("dpop+jwt") {
        return Err("DPoP header typ must be 'dpop+jwt'".to_string());
    }
    if header.get("alg").and_then(JsonValue::as_str) != Some("EdDSA") {
        return Err("DPoP header alg must be 'EdDSA'".to_string());
    }
    let jwk = header
        .get("jwk")
        .ok_or_else(|| "missing jwk object in DPoP header".to_string())?;
    if jwk.get("kty").and_then(JsonValue::as_str) != Some("OKP") {
        return Err("DPoP jwk.kty must be 'OKP'".to_string());
    }
    if jwk.get("crv").and_then(JsonValue::as_str) != Some("Ed25519") {
        return Err("DPoP jwk.crv must be 'Ed25519'".to_string());
    }
    if jwk.get("d").is_some() {
        return Err("DPoP jwk must not embed private key parameter 'd'".to_string());
    }
    let x_b64 = jwk
        .get("x")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| "missing jwk.x in DPoP header".to_string())?;
    let pub_vec = base64url_decode_nopad(x_b64)?;
    let pub_arr: [u8; 32] = pub_vec
        .try_into()
        .map_err(|_| "DPoP jwk.x must be 32 bytes".to_string())?;
    let vk = VerifyingKey::from_bytes(&pub_arr).map_err(|e| format!("invalid Ed25519 key: {e}"))?;

    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "DPoP signature must be 64 bytes".to_string())?;
    let sig = Signature::from_bytes(&sig_arr);
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| "DPoP Ed25519 signature verification failed".to_string())?;

    if !payload
        .get("jti")
        .and_then(JsonValue::as_str)
        .is_some_and(|s| !s.trim().is_empty())
    {
        return Err("DPoP payload missing non-empty jti claim".to_string());
    }
    if payload.get("iat").and_then(JsonValue::as_u64).is_none() {
        return Err("DPoP payload missing integer iat claim".to_string());
    }
    if payload.get("htm").and_then(JsonValue::as_str) != Some(expected_htm) {
        return Err("DPoP htm claim mismatch".to_string());
    }
    if payload.get("htu").and_then(JsonValue::as_str) != Some(expected_htu) {
        return Err("DPoP htu claim mismatch".to_string());
    }
    validate_upstream_mcp_endpoint(expected_htu).map_err(|(c, m)| format!("{c}: {m}"))?;

    match expected_access_token {
        Some(tok) => {
            let exp_ath = base64url_encode_nopad(&sha256_bytes(tok.as_bytes()));
            if payload.get("ath").and_then(JsonValue::as_str) != Some(exp_ath.as_str()) {
                return Err("DPoP ath access-token hash binding mismatch".to_string());
            }
        }
        None => {
            if payload.get("ath").is_some() {
                return Err("unexpected DPoP ath claim when no access token was bound".to_string());
            }
        }
    }
    Ok(vk)
}

pub fn base64url_encode_nopad(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((input.len() * 4).div_ceil(3));
    let mut i = 0usize;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(n & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
    }
    out
}

pub fn base64url_decode_nopad(input: &str) -> Result<Vec<u8>, String> {
    if input.contains('=') {
        return Err("unpadded base64url must not contain '=' padding".to_string());
    }
    let val_of = |b: u8| -> Result<u32, String> {
        match b {
            b'A'..=b'Z' => Ok((b - b'A') as u32),
            b'a'..=b'z' => Ok((b - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((b - b'0' + 52) as u32),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err(format!("invalid base64url byte 0x{b:02x}")),
        }
    };
    let bytes = input.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err("invalid base64url length".to_string());
    }
    let mut out = Vec::with_capacity((bytes.len() * 3) / 4);
    let mut i = 0usize;
    while i + 4 <= bytes.len() {
        let n = (val_of(bytes[i])? << 18)
            | (val_of(bytes[i + 1])? << 12)
            | (val_of(bytes[i + 2])? << 6)
            | val_of(bytes[i + 3])?;
        out.push(((n >> 16) & 0xff) as u8);
        out.push(((n >> 8) & 0xff) as u8);
        out.push((n & 0xff) as u8);
        i += 4;
    }
    let rem = bytes.len() - i;
    if rem == 2 {
        let b0 = val_of(bytes[i])?;
        let b1 = val_of(bytes[i + 1])?;
        if (b1 & 0x0f) != 0 {
            return Err("non-canonical base64url trailing pad bits".to_string());
        }
        let n = (b0 << 18) | (b1 << 12);
        out.push(((n >> 16) & 0xff) as u8);
    } else if rem == 3 {
        let b0 = val_of(bytes[i])?;
        let b1 = val_of(bytes[i + 1])?;
        let b2 = val_of(bytes[i + 2])?;
        if (b2 & 0x03) != 0 {
            return Err("non-canonical base64url trailing pad bits".to_string());
        }
        let n = (b0 << 18) | (b1 << 12) | (b2 << 6);
        out.push(((n >> 16) & 0xff) as u8);
        out.push(((n >> 8) & 0xff) as u8);
    }
    Ok(out)
}

/// CLI entrypoint: `agent-guard mcp-gateway [--cwd <dir>] [--upstream <url>]`
pub fn run_mcp_gateway_cli(args: &[String], default_cwd: &Path) -> ExitCode {
    let mut cwd = default_cwd.to_path_buf();
    let mut upstream_url = CANONICAL_UPSTREAM_MCP_URL.to_string();

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--cwd" if i + 1 < args.len() => {
                cwd = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--upstream" if i + 1 < args.len() => {
                upstream_url = args[i + 1].clone();
                i += 2;
            }
            "--help" | "-h" => {
                println!(
                    "agent-guard mcp-gateway {} - Zero-Trust Mediating MCP JSON-RPC 2.0 Sidecar\nUsage: agent-guard mcp-gateway [--cwd <dir>] [--upstream https://mcp.zt.susanb.dev/mcp]",
                    env!("CARGO_PKG_VERSION")
                );
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("[agent-guard mcp-gateway] unrecognized argument '{other}'");
                return ExitCode::from(2);
            }
        }
    }

    if let Err((code, msg)) = validate_upstream_mcp_endpoint(&upstream_url) {
        eprintln!("[agent-guard mcp-gateway HARD DENY :: {code}] {msg}");
        return ExitCode::from(2);
    }

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();
    if let Err(e) = serve_mcp_stream(&mut reader, &mut writer, &cwd) {
        eprintln!("[agent-guard mcp-gateway] stream error: {e}");
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

/// Serves an MCP JSON-RPC 2.0 session over arbitrary `BufRead`/`Write` streams (supporting both
/// newline-delimited JSON-RPC 2.0 and `Content-Length` framed messages).
pub fn serve_mcp_stream<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    cwd: &Path,
) -> Result<(), String> {
    while let Some((frame_str, framing)) = read_next_mcp_frame(reader)? {
        if let Some(resp_json) = handle_mcp_jsonrpc_message(&frame_str, cwd) {
            write_mcp_frame(writer, &resp_json.to_json_string(), framing)?;
        }
    }
    Ok(())
}

fn read_next_mcp_frame<R: BufRead>(
    reader: &mut R,
) -> Result<Option<(String, McpWireFraming)>, String> {
    loop {
        let mut line = String::new();
        let n = (&mut *reader)
            .take((MAX_MCP_FRAME_BYTES + 1) as u64)
            .read_line(&mut line)
            .map_err(|e| format!("MCP read error: {e}"))?;
        if n == 0 {
            return Ok(None);
        }
        if line.len() > MAX_MCP_FRAME_BYTES {
            return Err("MCP frame exceeded 256 KiB ceiling".to_string());
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed
            .strip_prefix("Content-Length:")
            .or_else(|| trimmed.strip_prefix("content-length:"))
        {
            let content_len: usize = rest
                .trim()
                .parse()
                .map_err(|_| "invalid Content-Length header in MCP stream".to_string())?;
            if content_len > MAX_MCP_FRAME_BYTES {
                return Err(format!(
                    "MCP Content-Length {content_len} exceeds {MAX_MCP_FRAME_BYTES} byte cap"
                ));
            }
            // Consume remaining headers up to blank line (hard-capped to <= 32 headers)
            let mut hdr_count = 0usize;
            loop {
                hdr_count += 1;
                if hdr_count > 32 {
                    return Err("MCP frame exceeded 32 header line limit".to_string());
                }
                let mut hdr = String::new();
                let hn = (&mut *reader)
                    .take(4097)
                    .read_line(&mut hdr)
                    .map_err(|e| format!("MCP header read error: {e}"))?;
                if hdr.len() > 4096 {
                    return Err("MCP header line exceeded 4 KiB ceiling".to_string());
                }
                if hn == 0 || hdr.trim().is_empty() {
                    break;
                }
            }
            let mut body = vec![0u8; content_len];
            reader
                .read_exact(&mut body)
                .map_err(|e| format!("truncated MCP Content-Length body: {e}"))?;
            let text = String::from_utf8(body)
                .map_err(|_| "non-UTF8 bytes in MCP Content-Length body".to_string())?;
            return Ok(Some((text, McpWireFraming::ContentLength)));
        }
        return Ok(Some((
            trimmed.to_string(),
            McpWireFraming::NewlineDelimited,
        )));
    }
}

fn write_mcp_frame<W: Write>(
    writer: &mut W,
    body_json: &str,
    framing: McpWireFraming,
) -> Result<(), String> {
    match framing {
        McpWireFraming::NewlineDelimited => writer
            .write_all(body_json.as_bytes())
            .and_then(|()| writer.write_all(b"\n"))
            .and_then(|()| writer.flush())
            .map_err(|e| format!("MCP write error: {e}")),
        McpWireFraming::ContentLength => {
            let header = format!("Content-Length: {}\r\n\r\n", body_json.len());
            writer
                .write_all(header.as_bytes())
                .and_then(|()| writer.write_all(body_json.as_bytes()))
                .and_then(|()| writer.flush())
                .map_err(|e| format!("MCP write error: {e}"))
        }
    }
}

/// Evaluates a single JSON-RPC 2.0 request/notification message, returning `None` for notifications.
pub fn handle_mcp_jsonrpc_message(raw_json: &str, cwd: &Path) -> Option<JsonValue> {
    let req = match JsonValue::parse(raw_json) {
        Ok(v) => v,
        Err(e) => {
            return Some(jsonrpc_error(
                JsonValue::Null,
                -32700,
                &format!("Parse error (RFC 7493 strict JSON): {e}"),
            ));
        }
    };

    let id_opt = req.get("id").cloned();
    if req.get("jsonrpc").and_then(JsonValue::as_str) != Some("2.0") {
        return Some(jsonrpc_error(
            id_opt.unwrap_or(JsonValue::Null),
            -32600,
            "Invalid Request: jsonrpc version must equal '2.0'",
        ));
    }
    let Some(method) = req.get("method").and_then(JsonValue::as_str) else {
        return id_opt.map(|id| jsonrpc_error(id, -32600, "Invalid Request: missing method"));
    };

    // JSON-RPC notifications have no `id` field and expect no response frame
    let id = id_opt?;

    match method {
        "initialize" => {
            let client_proto = req
                .get("params")
                .and_then(|p| p.get("protocolVersion"))
                .and_then(JsonValue::as_str)
                .unwrap_or("2024-11-05");
            Some(jsonrpc_ok(
                id,
                JsonValue::Object(vec![
                    (
                        "protocolVersion".to_string(),
                        JsonValue::Str(client_proto.to_string()),
                    ),
                    (
                        "capabilities".to_string(),
                        JsonValue::Object(vec![(
                            "tools".to_string(),
                            JsonValue::Object(vec![(
                                "listChanged".to_string(),
                                JsonValue::Bool(false),
                            )]),
                        )]),
                    ),
                    (
                        "serverInfo".to_string(),
                        JsonValue::Object(vec![
                            (
                                "name".to_string(),
                                JsonValue::Str("dotagent-mcp-gateway".to_string()),
                            ),
                            (
                                "version".to_string(),
                                JsonValue::Str(env!("CARGO_PKG_VERSION").to_string()),
                            ),
                        ]),
                    ),
                ]),
            ))
        }
        "ping" => Some(jsonrpc_ok(id, JsonValue::Object(Vec::new()))),
        "tools/list" => Some(jsonrpc_ok(
            id,
            JsonValue::Object(vec![(
                "tools".to_string(),
                JsonValue::Array(gateway_tools_manifest()),
            )]),
        )),
        "tools/call" => {
            let Some(params) = req.get("params") else {
                return Some(jsonrpc_error(id, -32602, "Missing params in tools/call"));
            };
            let Some(tool_name) = params.get("name").and_then(JsonValue::as_str) else {
                return Some(jsonrpc_error(id, -32602, "Missing tool name in tools/call"));
            };
            let empty_obj = JsonValue::Object(Vec::new());
            let args_val = params.get("arguments").unwrap_or(&empty_obj);
            let tool_result = dispatch_mediated_tool_call(tool_name, args_val, cwd);
            Some(jsonrpc_ok(id, tool_result))
        }
        other => Some(jsonrpc_error(
            id,
            -32601,
            &format!("Method not found in dotagent-mcp-gateway: '{other}'"),
        )),
    }
}

fn generate_csprng_32_and_jti() -> Result<(ZeroizingKey, String), String> {
    let mut raw = [0u8; 48];
    #[cfg(unix)]
    {
        let mut f = fs::File::open("/dev/urandom")
            .map_err(|e| format!("failed opening /dev/urandom for DPoP: {e}"))?;
        f.read_exact(&mut raw)
            .map_err(|e| format!("failed reading /dev/urandom for DPoP: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let d1 = sha256_bytes(&nanos.to_le_bytes());
        let d2 = sha256_bytes(&std::process::id().to_le_bytes());
        raw[..32].copy_from_slice(&d1);
        raw[32..48].copy_from_slice(&d2[..16]);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&raw[..32]);
    let jti = format!("jti-{}", hex_encode(&raw[32..48]));
    let zk = ZeroizingKey::new(seed);
    crate::crypto::zeroize_slice(&mut seed);
    crate::crypto::zeroize_slice(&mut raw);
    Ok((zk, jti))
}

fn dispatch_mediated_tool_call(tool_name: &str, args: &JsonValue, cwd: &Path) -> JsonValue {
    let call_started = std::time::Instant::now();
    let repo_root = resolve_repo_root(cwd);
    let profile = match load_active_profile(&repo_root) {
        Ok(p) => p,
        Err(bv) => return mcp_tool_error(bv.code, &bv.detail),
    };
    let sid = std::env::var("AGENT_GUARD_SESSION_ID").unwrap_or_else(|_| "default".to_string());
    let ledger_snapshot = {
        let _lock = SessionLedger::acquire_lock(&repo_root, &sid);
        SessionLedger::load_or_create(&repo_root, &sid)
    };
    let mut observation = crate::telemetry::capture::guard_context(
        &repo_root,
        &ledger_snapshot,
        Some(&profile.profile_id),
    );
    if ledger_snapshot.halted {
        return mcp_tool_error(
            "SESSION_CIRCUIT_BREAKER_HALTED",
            ledger_snapshot
                .halt_reason
                .as_deref()
                .unwrap_or("Session halted"),
        );
    }

    // 1. Per-RPC capability classification & taint/profile gate
    let sub_method = crate::strip_approved_mcp_server_prefix(tool_name)
        .or_else(|| tool_name.strip_prefix("mcp__dotagent__"))
        .or_else(|| tool_name.strip_prefix("mcp__dotagent_mcp_gateway__"))
        .unwrap_or(tool_name);
    if let Err((code, detail, halt)) = authorize_mcp_rpc_invocation(
        tool_name,
        sub_method,
        !profile.enable_write_tools,
        ledger_snapshot.tainted,
        &profile.profile_id,
    ) {
        let denial_id = {
            let _lock = SessionLedger::acquire_lock(&repo_root, &sid);
            let mut l = SessionLedger::load_or_create(&repo_root, &sid);
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let did = l.record_denial(code, tool_name, sub_method, ts);
            if halt {
                l.trip_circuit_breaker(format!("{code}: {detail}"));
            }
            let _ = l.save_locked(&repo_root);
            did
        };
        let full_detail = if denial_id.is_empty() {
            detail
        } else {
            format!("{detail} [denial_id: {denial_id}]")
        };
        let dur_ns = u64::try_from(call_started.elapsed().as_nanos()).ok();
        let stages = crate::telemetry::capture::DecisionStageTimings {
            duration_ns: dur_ns,
            ..Default::default()
        };
        observation.duration_ns = dur_ns;
        observation
            .intervention_id
            .clone_from(&observation.trace_id);
        crate::traversal_ledger::append_audit_jsonl_with_timings(
            &repo_root,
            &sid,
            tool_name,
            code,
            &full_detail,
            halt,
            observation.trace_id.as_deref(),
            observation.span_id.as_deref(),
            stages,
        );
        crate::telemetry::capture::record_guard(
            &observation,
            crate::telemetry::capture::hook_decision_with_stages(
                "mcp_gateway",
                "deny",
                code,
                "denied",
                None,
                stages,
            ),
        );
        return mcp_tool_error(code, &full_detail);
    }

    // 2. Dispatch mediated zero-trust workspace & upstream tools
    match sub_method {
        "dotagent_status" | "ping" => {
            let status_txt = format!(
                "repo_root={} profile={} halted={} tainted={} reads={} calls={} upstream_pin={}",
                repo_root.display(),
                profile.profile_id,
                ledger_snapshot.halted,
                ledger_snapshot.tainted,
                ledger_snapshot.file_reads,
                ledger_snapshot.tool_calls,
                CANONICAL_UPSTREAM_MCP_URL
            );
            let dur_ns = u64::try_from(call_started.elapsed().as_nanos()).ok();
            let stages = crate::telemetry::capture::DecisionStageTimings {
                duration_ns: dur_ns,
                ..Default::default()
            };
            observation.duration_ns = dur_ns;
            crate::telemetry::capture::record_guard(
                &observation,
                crate::telemetry::capture::hook_decision_with_stages(
                    "mcp_gateway",
                    "allow",
                    "GUARD_ALLOW",
                    "allowed",
                    None,
                    stages,
                ),
            );
            mcp_tool_success(&status_txt)
        }
        "dotagent_read_file" => {
            if args.get("path").is_some() && args.get("file_path").is_some() {
                return mcp_tool_error(
                    "AMBIGUOUS_TOOL_PARAM_ALIAS",
                    "dotagent_read_file cannot specify both 'path' and 'file_path'",
                );
            }
            let Some(path_str) = args
                .get("path")
                .or_else(|| args.get("file_path"))
                .and_then(JsonValue::as_str)
            else {
                return mcp_tool_error("MISSING_PATH", "dotagent_read_file requires 'path'");
            };
            let active_prof = match crate::budget_guard::load_active_profile(&repo_root) {
                Ok(p) => p,
                Err(bv) => return mcp_tool_error(bv.code, &bv.detail),
            };
            let max_lines = active_prof.max_slice_lines;
            let offset = match args.get("offset").and_then(JsonValue::as_u64) {
                Some(v) => match usize::try_from(v) {
                    Ok(u) => Some(u),
                    Err(_) => {
                        return mcp_tool_error("SLICE_LINE_CAP_EXCEEDED", "offset overflow");
                    }
                },
                None => None,
            };
            let limit = match args.get("limit").and_then(JsonValue::as_u64) {
                Some(v) => match usize::try_from(v) {
                    Ok(u) => Some(u.min(max_lines)),
                    Err(_) => Some(max_lines),
                },
                None => Some(max_lines),
            };

            let mut input_fields = vec![(
                "file_path".to_string(),
                JsonValue::Str(path_str.to_string()),
            )];
            if let Some(off) = offset {
                input_fields.push(("offset".to_string(), JsonValue::Uint(off as u64)));
            }
            if let Some(lim) = limit {
                input_fields.push(("limit".to_string(), JsonValue::Uint(lim as u64)));
            }
            let hook_req = JsonValue::Object(vec![
                ("tool_name".to_string(), JsonValue::Str("Read".to_string())),
                ("tool_input".to_string(), JsonValue::Object(input_fields)),
            ])
            .to_json_string();

            // `handle_pre_tool_hook` enforces Swarm `assigned_read_paths`, `SessionLedger` lock,
            // `A -> B` ceiling, `pre_inspect_file_for_ingestion`, circuit-breaker halt persistence,
            // and `audit.jsonl` logging!
            match handle_pre_tool_hook(&hook_req, cwd) {
                Decision::Deny {
                    code: "NON_ASCII_SANITIZED_PREBUFFER",
                    reason,
                    ..
                } => mcp_tool_success(&reason),
                Decision::Deny { code, reason, .. } => mcp_tool_error(code, &reason),
                Decision::Allow {
                    updated_input_json, ..
                } => {
                    let mut eff_offset = offset;
                    let mut eff_limit = limit;
                    if let Some(ref upd_raw) = updated_input_json
                        && let Ok(upd_val) = JsonValue::parse(upd_raw)
                    {
                        if let Some(o) = upd_val
                            .get("offset")
                            .and_then(JsonValue::as_u64)
                            .and_then(|v| usize::try_from(v).ok())
                        {
                            eff_offset = Some(o);
                        }
                        if let Some(l) = upd_val
                            .get("limit")
                            .and_then(JsonValue::as_u64)
                            .and_then(|v| usize::try_from(v).ok())
                        {
                            eff_limit = Some(l.min(max_lines));
                        }
                    }

                    let valid = match validate_path(&repo_root, cwd, path_str, PathAccess::Read) {
                        Ok(v) => v,
                        Err(pv) => return mcp_tool_error(pv.code, &pv.detail),
                    };
                    let (raw_slice, _metrics) = match inspect_file_budget(
                        &valid.canonical_or_norm,
                        eff_offset,
                        eff_limit,
                    ) {
                        Ok(pair) => pair,
                        Err(bv) => return mcp_tool_error(bv.code, &bv.detail),
                    };
                    let uni = crate::unicode_guard::scan_unicode(
                        &raw_slice,
                        crate::unicode_guard::ScanMode::UntrustedContent,
                    );
                    if let Some(first) = uni.first() {
                        return mcp_tool_error(first.code, &first.detail);
                    }
                    let clean_slice =
                        crate::sanitizer::neuter_to_clean_ascii(&raw_slice).clean_ascii;
                    let read_post_req = JsonValue::Object(vec![
                        ("tool_name".to_string(), JsonValue::Str("Read".to_string())),
                        (
                            "tool_response".to_string(),
                            JsonValue::Str(clean_slice.clone()),
                        ),
                    ])
                    .to_json_string();
                    let effective_body = match handle_post_tool_hook(&read_post_req, cwd) {
                        Decision::Allow { .. } => clean_slice,
                        Decision::Deny {
                            code: "NON_ASCII_SANITIZED_PREBUFFER" | "TOOL_OUTPUT_FLOOD_BLOCKED",
                            reason,
                            ..
                        } => reason,
                        Decision::Deny { code, reason, .. } => {
                            return mcp_tool_error(code, &reason);
                        }
                    };
                    let turn_nonce = {
                        let _lock = SessionLedger::acquire_lock(&repo_root, &sid);
                        SessionLedger::load_or_create(&repo_root, &sid).turn_nonce
                    };
                    let spotlighted =
                        wrap_spotlight_envelope(&effective_body, &turn_nonce, &valid.repo_rel);
                    mcp_tool_success(&spotlighted)
                }
            }
        }
        "dotagent_edit_file" => {
            if args.get("path").is_some() && args.get("file_path").is_some() {
                return mcp_tool_error(
                    "AMBIGUOUS_TOOL_PARAM_ALIAS",
                    "dotagent_edit_file cannot specify both 'path' and 'file_path'",
                );
            }
            let Some(path_str) = args
                .get("path")
                .or_else(|| args.get("file_path"))
                .and_then(JsonValue::as_str)
            else {
                return mcp_tool_error("MISSING_PATH", "dotagent_edit_file requires 'path'");
            };
            let Some(new_content) = args.get("content").and_then(JsonValue::as_str) else {
                return mcp_tool_error(
                    "MISSING_CONTENT",
                    "dotagent_edit_file requires string 'content'",
                );
            };

            let hook_req = JsonValue::Object(vec![
                ("tool_name".to_string(), JsonValue::Str("Write".to_string())),
                (
                    "tool_input".to_string(),
                    JsonValue::Object(vec![
                        (
                            "file_path".to_string(),
                            JsonValue::Str(path_str.to_string()),
                        ),
                        (
                            "content".to_string(),
                            JsonValue::Str(new_content.to_string()),
                        ),
                    ]),
                ),
            ])
            .to_json_string();
            if let Decision::Deny { code, reason, .. } = handle_pre_tool_hook(&hook_req, cwd) {
                return mcp_tool_error(code, &reason);
            }

            let valid = match validate_path(&repo_root, cwd, path_str, PathAccess::Write) {
                Ok(v) => v,
                Err(pv) => return mcp_tool_error(pv.code, &pv.detail),
            };
            if let Err(err_msg) = write_workspace_file_nonsymlink_atomic(
                &repo_root,
                &valid.canonical_or_norm,
                new_content.as_bytes(),
            ) {
                return mcp_tool_error("WRITE_IO_ERROR", &err_msg);
            }
            if let Decision::Deny { code, reason, .. } = handle_post_edit(path_str, cwd) {
                return mcp_tool_error(code, &reason);
            }
            mcp_tool_success(&format!("OK: wrote '{}'", valid.repo_rel))
        }
        "dotagent_search" => {
            let pattern = args
                .get("pattern")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            if pattern.is_empty() {
                return mcp_tool_error("MISSING_PATTERN", "dotagent_search requires 'pattern'");
            }
            let rel_dir = args.get("path").and_then(JsonValue::as_str).unwrap_or(".");
            let hook_req = JsonValue::Object(vec![
                ("tool_name".to_string(), JsonValue::Str("Grep".to_string())),
                (
                    "tool_input".to_string(),
                    JsonValue::Object(vec![
                        ("path".to_string(), JsonValue::Str(rel_dir.to_string())),
                        ("pattern".to_string(), JsonValue::Str(pattern.to_string())),
                        ("max_depth".to_string(), JsonValue::Uint(2)),
                    ]),
                ),
            ])
            .to_json_string();
            if let Decision::Deny { code, reason, .. } = handle_pre_tool_hook(&hook_req, cwd) {
                return mcp_tool_error(code, &reason);
            }
            let target = if Path::new(rel_dir).is_absolute() {
                PathBuf::from(rel_dir)
            } else {
                cwd.join(rel_dir)
            };
            let mut hits = Vec::new();
            search_bounded_depth2(&repo_root, &target, pattern, 0, &mut hits);
            let raw_out = if hits.is_empty() {
                "No matches found (maxdepth <= 2).".to_string()
            } else {
                hits.join("\n")
            };
            post_sanitize_tool_output("Grep", &raw_out, cwd, true)
        }
        "dotagent_exec" => {
            let Some(cmd_str) = args.get("command").and_then(JsonValue::as_str) else {
                return mcp_tool_error("MISSING_COMMAND", "dotagent_exec requires 'command'");
            };
            let hook_req = JsonValue::Object(vec![
                ("tool_name".to_string(), JsonValue::Str("Bash".to_string())),
                (
                    "tool_input".to_string(),
                    JsonValue::Object(vec![(
                        "command".to_string(),
                        JsonValue::Str(cmd_str.to_string()),
                    )]),
                ),
            ])
            .to_json_string();
            if let Decision::Deny { code, reason, .. } = handle_pre_tool_hook(&hook_req, cwd) {
                return mcp_tool_error(code, &reason);
            }
            let tainted = SessionLedger::load_or_create(&repo_root, &sid).tainted;
            let effective_cmd = match crate::cmd_policy::evaluate_shell_command(
                cmd_str, &repo_root, cwd, tainted,
            ) {
                Ok(plan) => plan
                    .rewritten_command
                    .unwrap_or_else(|| cmd_str.to_string()),
                Err(cv) => return mcp_tool_error(cv.code, &cv.detail),
            };
            let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("agent-guard"));
            match Command::new(exe)
                .current_dir(cwd)
                .args(["exec-sandbox", "--sanitize-stream", "--", &effective_cmd])
                .output()
            {
                Ok(out) => {
                    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
                    let err_s = String::from_utf8_lossy(&out.stderr);
                    if !err_s.is_empty() {
                        if !text.is_empty() && !text.ends_with('\n') {
                            text.push('\n');
                        }
                        text.push_str(&err_s);
                    }
                    // Unconditionally scan BOTH zero and non-zero command output through PostToolUse
                    // so non-zero exit commands cannot smuggle poisoned pointers or prompt injections!
                    post_sanitize_tool_output("Bash", &text, cwd, out.status.success())
                }
                Err(e) => mcp_tool_error("EXEC_SPAWN_FAILED", &format!("{e}")),
            }
        }
        "dotagent_submit_friction" => {
            let hook_req = JsonValue::Object(vec![
                (
                    "tool_name".to_string(),
                    JsonValue::Str("dotagent_submit_friction".to_string()),
                ),
                ("tool_input".to_string(), args.clone()),
            ])
            .to_json_string();
            if let Decision::Deny { code, reason, .. } = handle_pre_tool_hook(&hook_req, cwd) {
                return mcp_tool_error(code, &reason);
            }
            if !profile.enable_write_tools {
                let Some(_lock) = SessionLedger::acquire_lock(&repo_root, &sid) else {
                    return mcp_tool_error(
                        "FEEDBACK_QUOTA_STATE_UNAVAILABLE",
                        "could not lock the session feedback quota",
                    );
                };
                let mut l = SessionLedger::load_or_create(&repo_root, &sid);
                if l.mcp_readonly_feedback_calls >= 5 {
                    return mcp_tool_error(
                        "FEEDBACK_RATE_LIMIT_EXCEEDED",
                        "research-readonly profile caps dotagent_submit_friction at 5 calls per session",
                    );
                }
                l.mcp_readonly_feedback_calls = l.mcp_readonly_feedback_calls.saturating_add(1);
                if l.save_locked(&repo_root).is_err() {
                    return mcp_tool_error(
                        "FEEDBACK_QUOTA_STATE_UNAVAILABLE",
                        "could not persist the session feedback quota",
                    );
                }
            }
            let Some(cat_str) = args.get("category").and_then(JsonValue::as_str) else {
                return mcp_tool_error(
                    "INVALID_FEEDBACK_BALLOT",
                    "dotagent_submit_friction requires 'category'",
                );
            };
            let Some(category) = crate::feedback::FeedbackCategory::parse(cat_str) else {
                return mcp_tool_error(
                    "INVALID_FEEDBACK_BALLOT",
                    &format!(
                        "unrecognized category '{cat_str}' (expected false_positive_block | missing_safe_flag | pagination_or_budget_friction | unclear_remediation | adapter_or_workflow_bug)"
                    ),
                );
            };
            let Some(denial_id) = args
                .get("denial_id")
                .and_then(JsonValue::as_str)
                .map(str::trim)
                .filter(|id| !id.is_empty())
            else {
                return mcp_tool_error(
                    "INVALID_FEEDBACK_BALLOT",
                    "dotagent_submit_friction requires a non-empty 'denial_id' string",
                );
            };
            let reason_code = args
                .get("reason_code")
                .and_then(JsonValue::as_str)
                .map(String::from);
            if args.get("note_ascii").is_some() && args.get("summary").is_some() {
                return mcp_tool_error(
                    "AMBIGUOUS_TOOL_PARAM_ALIAS",
                    "dotagent_submit_friction cannot specify both 'note_ascii' and 'summary'",
                );
            }
            let note_ascii = args
                .get("note_ascii")
                .or_else(|| args.get("summary"))
                .and_then(JsonValue::as_str)
                .map(String::from);
            let root_session_id = std::env::var("AGENT_GUARD_ROOT_SESSION_ID")
                .ok()
                .or_else(|| std::env::var("AGENT_GUARD_PARENT_SESSION_ID").ok());
            let role =
                std::env::var("AGENT_GUARD_ROLE").unwrap_or_else(|_| "coding-agent".to_string());
            let task_id = std::env::var("DOTAGENT_TASK_ID").ok();
            let req = crate::feedback::BallotRequest {
                denial_id: Some(denial_id.to_string()),
                category,
                reason_code,
                note_ascii,
                session_id: sid,
                root_session_id,
                role,
                task_id,
            };
            match crate::feedback::submit_friction_ballot_with_sink(
                &repo_root,
                &req,
                crate::feedback::EmitSink::HookOrMcpStderr,
            ) {
                Ok(agentpi_ev) => mcp_tool_success(&agentpi_ev.to_json_string()),
                Err(err) => mcp_tool_error(err.guard_code().as_str(), err.message()),
            }
        }
        _ => {
            // Upstream `mcp__susanbdev__*` call: run full PreToolUse validation + mint CSPRNG DPoP proof
            let prefixed = if tool_name.starts_with("mcp__susanbdev__") {
                tool_name.to_string()
            } else {
                format!("mcp__susanbdev__{sub_method}")
            };
            let hook_req = JsonValue::Object(vec![
                ("tool_name".to_string(), JsonValue::Str(prefixed.clone())),
                ("tool_input".to_string(), args.clone()),
            ])
            .to_json_string();
            if let Decision::Deny { code, reason, .. } = handle_pre_tool_hook(&hook_req, cwd) {
                return mcp_tool_error(code, &reason);
            }

            let iat = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let (dpop_seed, jti) = match generate_csprng_32_and_jti() {
                Ok(pair) => pair,
                Err(e) => return mcp_tool_error("DPOP_KEYGEN_FAILED", &e),
            };
            let sk = SigningKey::from_bytes(dpop_seed.as_bytes());
            if let Err(e) =
                mint_dpop_proof_jwt(&sk, "POST", CANONICAL_UPSTREAM_MCP_URL, None, &jti, iat)
            {
                return mcp_tool_error("DPOP_MINT_FAILED", &e);
            }
            mcp_tool_error(
                "MCP_UPSTREAM_TRANSPORT_UNCONFIGURED",
                &format!(
                    "Policy and RFC 9449 DPoP proof succeeded for '{prefixed}', but no live HTTPS session to '{CANONICAL_UPSTREAM_MCP_URL}' is active in offline stdio mode."
                ),
            )
        }
    }
}

fn post_sanitize_tool_output(
    tool_name: &str,
    raw_out: &str,
    cwd: &Path,
    exit_zero: bool,
) -> JsonValue {
    let post_req = JsonValue::Object(vec![
        (
            "tool_name".to_string(),
            JsonValue::Str(tool_name.to_string()),
        ),
        (
            "tool_response".to_string(),
            JsonValue::Str(raw_out.to_string()),
        ),
    ])
    .to_json_string();
    match handle_post_tool_hook(&post_req, cwd) {
        Decision::Allow { .. } => {
            if exit_zero {
                mcp_tool_success(raw_out)
            } else {
                mcp_tool_error("EXEC_NON_ZERO", raw_out)
            }
        }
        Decision::Deny {
            code: "NON_ASCII_SANITIZED_PREBUFFER" | "TOOL_OUTPUT_FLOOD_BLOCKED",
            reason,
            ..
        } => {
            if exit_zero {
                mcp_tool_success(&reason)
            } else {
                mcp_tool_error("EXEC_NON_ZERO", &reason)
            }
        }
        Decision::Deny { code, reason, .. } => mcp_tool_error(code, &reason),
    }
}

fn search_bounded_depth2(
    repo_root: &Path,
    dir: &Path,
    pattern: &str,
    depth: usize,
    hits: &mut Vec<String>,
) {
    if depth > 2 || hits.len() >= 80 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if hits.len() >= 80 {
            break;
        }
        let p = entry.path();
        let Ok(meta) = fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        let Some(s) = p.to_str() else {
            continue;
        };
        if meta.file_type().is_dir() {
            if depth < 2
                && validate_path(repo_root, repo_root, s, PathAccess::ReferencePointer).is_ok()
            {
                search_bounded_depth2(repo_root, &p, pattern, depth + 1, hits);
            }
        } else if meta.file_type().is_file()
            && meta.len() <= 256 * 1024
            && let Ok(valid) = validate_path(repo_root, repo_root, s, PathAccess::Read)
            && let Ok(text) = fs::read_to_string(&valid.canonical_or_norm)
        {
            for (idx, line) in text.lines().enumerate() {
                if line.contains(pattern) {
                    hits.push(format!("{}:{}: {}", valid.repo_rel, idx + 1, line));
                    if hits.len() >= 80 {
                        break;
                    }
                }
            }
        }
    }
}

fn gateway_tools_manifest() -> Vec<JsonValue> {
    let mk_tool = |name: &str, desc: &str, req_fields: &[&str]| -> JsonValue {
        let props: Vec<(String, JsonValue)> = req_fields
            .iter()
            .map(|f| {
                (
                    (*f).to_string(),
                    JsonValue::Object(vec![(
                        "type".to_string(),
                        JsonValue::Str("string".to_string()),
                    )]),
                )
            })
            .collect();
        let req_arr: Vec<JsonValue> = req_fields
            .iter()
            .map(|f| JsonValue::Str((*f).to_string()))
            .collect();
        JsonValue::Object(vec![
            ("name".to_string(), JsonValue::Str(name.to_string())),
            ("description".to_string(), JsonValue::Str(desc.to_string())),
            (
                "inputSchema".to_string(),
                JsonValue::Object(vec![
                    ("type".to_string(), JsonValue::Str("object".to_string())),
                    ("properties".to_string(), JsonValue::Object(props)),
                    ("required".to_string(), JsonValue::Array(req_arr)),
                ]),
            ),
        ])
    };
    vec![
        mk_tool(
            "dotagent_read_file",
            "Bounded <=150-line zero-trust file reader with A->B ledger and 7-bit ASCII spotlighting",
            &["path"],
        ),
        mk_tool(
            "dotagent_edit_file",
            "Policy-gated workspace file writer with post-edit Unicode/secret/authority verification",
            &["path", "content"],
        ),
        mk_tool(
            "dotagent_search",
            "Max-depth-2 workspace search excluding forbidden cache/temp/dependency zones",
            &["pattern"],
        ),
        mk_tool(
            "dotagent_exec",
            "Execute AST-vetted command inside Landlock/Seatbelt/Seccomp exec-sandbox",
            &["command"],
        ),
        mk_tool(
            "dotagent_status",
            "Read-only status of active zero-trust profile, session ledger, and pinned MCP endpoint",
            &[],
        ),
        JsonValue::Object(vec![
            (
                "name".to_string(),
                JsonValue::Str("dotagent_submit_friction".to_string()),
            ),
            (
                "description".to_string(),
                JsonValue::Str(
                    "Submit a kernel-grounded guardrail false-positive or workflow friction ballot"
                        .to_string(),
                ),
            ),
            (
                "inputSchema".to_string(),
                JsonValue::Object(vec![
                    ("type".to_string(), JsonValue::Str("object".to_string())),
                    (
                        "properties".to_string(),
                        JsonValue::Object(vec![
                            (
                                "denial_id".to_string(),
                                JsonValue::Object(vec![(
                                    "type".to_string(),
                                    JsonValue::Str("string".to_string()),
                                )]),
                            ),
                            (
                                "category".to_string(),
                                JsonValue::Object(vec![(
                                    "type".to_string(),
                                    JsonValue::Str("string".to_string()),
                                )]),
                            ),
                            (
                                "reason_code".to_string(),
                                JsonValue::Object(vec![(
                                    "type".to_string(),
                                    JsonValue::Str("string".to_string()),
                                )]),
                            ),
                            (
                                "note_ascii".to_string(),
                                JsonValue::Object(vec![(
                                    "type".to_string(),
                                    JsonValue::Str("string".to_string()),
                                )]),
                            ),
                        ]),
                    ),
                    (
                        "required".to_string(),
                        JsonValue::Array(vec![
                            JsonValue::Str("denial_id".to_string()),
                            JsonValue::Str("category".to_string()),
                        ]),
                    ),
                ]),
            ),
        ]),
    ]
}

fn mcp_tool_success(text: &str) -> JsonValue {
    JsonValue::Object(vec![
        (
            "content".to_string(),
            JsonValue::Array(vec![JsonValue::Object(vec![
                ("type".to_string(), JsonValue::Str("text".to_string())),
                ("text".to_string(), JsonValue::Str(text.to_string())),
            ])]),
        ),
        ("isError".to_string(), JsonValue::Bool(false)),
    ])
}

fn mcp_tool_error(code: &str, detail: &str) -> JsonValue {
    JsonValue::Object(vec![
        (
            "content".to_string(),
            JsonValue::Array(vec![JsonValue::Object(vec![
                ("type".to_string(), JsonValue::Str("text".to_string())),
                (
                    "text".to_string(),
                    JsonValue::Str(format!("[AGENT-GUARD HARD DENY :: {code}] {detail}")),
                ),
            ])]),
        ),
        ("isError".to_string(), JsonValue::Bool(true)),
    ])
}

fn write_workspace_file_nonsymlink_atomic(
    repo_root: &Path,
    dst: &Path,
    bytes: &[u8],
) -> Result<(), String> {
    static EDIT_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let canon_repo = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let rel = dst
        .strip_prefix(&canon_repo)
        .map_err(|_| "destination path escapes canonical repository root".to_string())?;

    let mut cur = canon_repo;
    if let Some(rel_parent) = rel.parent() {
        for comp in rel_parent.components() {
            let std::path::Component::Normal(seg) = comp else {
                return Err("disallowed path component in destination".to_string());
            };
            cur.push(seg);
            match fs::symlink_metadata(&cur) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err(format!(
                            "SYMLINK_ESCAPE_BLOCKED: ancestor directory '{}' is a symlink",
                            cur.display()
                        ));
                    }
                    if !meta.file_type().is_dir() {
                        return Err(format!("ancestor '{}' is not a directory", cur.display()));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&cur).map_err(|ce| {
                        format!("failed creating directory '{}': {ce}", cur.display())
                    })?;
                }
                Err(e) => {
                    return Err(format!("failed statting '{}': {e}", cur.display()));
                }
            }
        }
    }

    if let Ok(meta) = fs::symlink_metadata(dst)
        && meta.file_type().is_symlink()
    {
        return Err(format!(
            "SYMLINK_ESCAPE_BLOCKED: destination '{}' is a symlink",
            dst.display()
        ));
    }

    let seq = EDIT_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let fname = dst
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("edit.tmp");
    let tmp_path = cur.join(format!(".{fname}.mcp_tmp.{}.{seq}", std::process::id()));
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp_path)
        .map_err(|e| format!("failed creating atomic temp file: {e}"))?;
    if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("failed writing temp file: {e}"));
    }
    drop(f);

    if let Ok(meta) = fs::symlink_metadata(dst)
        && meta.file_type().is_symlink()
    {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!(
            "SYMLINK_ESCAPE_BLOCKED: destination '{}' became a symlink during write",
            dst.display()
        ));
    }
    if let Err(e) = fs::rename(&tmp_path, dst) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("failed renaming atomic temp file: {e}"));
    }
    Ok(())
}

fn jsonrpc_ok(id: JsonValue, result: JsonValue) -> JsonValue {
    JsonValue::Object(vec![
        ("jsonrpc".to_string(), JsonValue::Str("2.0".to_string())),
        ("id".to_string(), id),
        ("result".to_string(), result),
    ])
}

fn jsonrpc_error(id: JsonValue, code: i64, message: &str) -> JsonValue {
    JsonValue::Object(vec![
        ("jsonrpc".to_string(), JsonValue::Str("2.0".to_string())),
        ("id".to_string(), id),
        (
            "error".to_string(),
            JsonValue::Object(vec![
                ("code".to_string(), JsonValue::Int(code)),
                ("message".to_string(), JsonValue::Str(message.to_string())),
            ]),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn pkce_s256_matches_rfc7636_appendix_b_vector() {
        // RFC 7636 Appendix B official test vector!
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let pkce = compute_pkce_s256_challenge(verifier).expect("valid verifier");
        assert_eq!(pkce.code_challenge_method, "S256");
        assert_eq!(
            pkce.code_challenge,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn dpop_jwt_roundtrip_and_endpoint_pinning() {
        let sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let jwt = mint_dpop_proof_jwt(
            &sk,
            "POST",
            CANONICAL_UPSTREAM_MCP_URL,
            Some("tok_abc_123"),
            "jti-001",
            1_795_000_000,
        )
        .expect("mint DPoP");
        let vk = verify_dpop_proof_jwt(
            &jwt,
            "POST",
            CANONICAL_UPSTREAM_MCP_URL,
            Some("tok_abc_123"),
        )
        .expect("verify DPoP");
        assert_eq!(vk, sk.verifying_key());

        // Evil unpinned endpoint must be rejected
        assert!(
            mint_dpop_proof_jwt(&sk, "POST", "https://evil.example/mcp", None, "j1", 1).is_err()
        );
        // Token substitution must fail `ath` verification
        assert!(
            verify_dpop_proof_jwt(&jwt, "POST", CANONICAL_UPSTREAM_MCP_URL, Some("wrong_tok"))
                .is_err()
        );
    }

    #[test]
    fn mcp_stdio_handles_initialize_and_tools_list_in_both_framings() {
        let req_line = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#;
        let mut input = Cursor::new(format!("{req_line}\n"));
        let mut output = Vec::new();
        serve_mcp_stream(&mut input, &mut output, Path::new(".")).expect("serve newline MCP");
        let out_str = String::from_utf8(output).expect("utf8");
        assert!(out_str.contains("dotagent-mcp-gateway"));

        let list_body = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        let framed = format!("Content-Length: {}\r\n\r\n{}", list_body.len(), list_body);
        let mut cl_in = Cursor::new(framed.into_bytes());
        let mut cl_out = Vec::new();
        serve_mcp_stream(&mut cl_in, &mut cl_out, Path::new("."))
            .expect("serve Content-Length MCP");
        let cl_str = String::from_utf8(cl_out).expect("utf8");
        assert!(cl_str.starts_with("Content-Length: "));
        assert!(cl_str.contains("dotagent_read_file"));
    }
}
