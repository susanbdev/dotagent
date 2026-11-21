#![forbid(unsafe_code)]

//! Pure-Rust OpenSSH `SSHSIG` FIDO2 hardware user-presence (`sk-ssh-ed25519@openssh.com`) gate.

use std::fs;
use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};

use crate::crypto::{base64_decode_clean, constant_time_eq_bytes, hex_decode_32, sha256_bytes};

pub const OPERATOR_SSHSIG_NAMESPACE: &str = "dotagent-operator@susanb.dev";
pub const SK_ED25519_ALG: &str = "sk-ssh-ed25519@openssh.com";
const SSHSIG_MAGIC: &[u8; 6] = b"SSHSIG";
const SSH_SK_USER_PRESENCE_REQD: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardError {
    pub code: &'static str,
    pub detail: String,
}

impl GuardError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for GuardError {}

fn gerr(code: &'static str, msg: &str) -> GuardError {
    GuardError::new(code, msg)
}

struct SshCursor<'a>(&'a [u8], usize);

impl<'a> SshCursor<'a> {
    fn read_fixed(&mut self, len: usize) -> Result<&'a [u8], GuardError> {
        let end = self
            .1
            .checked_add(len)
            .filter(|&e| e <= self.0.len())
            .ok_or_else(|| gerr("SSHSIG_MALFORMED", "truncated SSHSIG field"))?;
        let out = &self.0[self.1..end];
        self.1 = end;
        Ok(out)
    }

    fn read_u8(&mut self) -> Result<u8, GuardError> {
        Ok(self.read_fixed(1)?[0])
    }

    fn read_u32(&mut self) -> Result<u32, GuardError> {
        let b = self.read_fixed(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_bytes(&mut self) -> Result<&'a [u8], GuardError> {
        let n = usize::try_from(self.read_u32()?)
            .map_err(|_| gerr("SSHSIG_MALFORMED", "length overflow"))?;
        self.read_fixed(n)
    }

    fn read_str(&mut self) -> Result<&'a str, GuardError> {
        std::str::from_utf8(self.read_bytes()?)
            .map_err(|_| gerr("SSHSIG_MALFORMED", "non-UTF8 SSH string"))
    }

    fn ensure_empty(&self) -> Result<(), GuardError> {
        if self.1 == self.0.len() {
            Ok(())
        } else {
            Err(gerr("SSHSIG_MALFORMED", "trailing SSHSIG bytes"))
        }
    }
}

fn push_ssh_str(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&u32::try_from(data.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(data);
}

/// Verifies an OpenSSH `SSHSIG` PEM signature made by `sk-ssh-ed25519@openssh.com`,
/// requiring `flags & 0x01 != 0` (`User Presence` touch) and returning `counter`.
pub fn verify_fido2_sshsig_ed25519(
    namespace: &str,
    challenge: &[u8],
    sig_pem: &str,
    allowed_pubkeys: &[[u8; 32]],
) -> Result<u32, GuardError> {
    if namespace.is_empty() || allowed_pubkeys.is_empty() {
        return Err(gerr("SSHSIG_CONFIG_INVALID", "empty namespace/keys"));
    }
    let (_, rest) = sig_pem
        .split_once("-----BEGIN SSH SIGNATURE-----")
        .ok_or_else(|| gerr("SSHSIG_MALFORMED", "missing BEGIN SSH SIGNATURE"))?;
    let (body_b64, _) = rest
        .split_once("-----END SSH SIGNATURE-----")
        .ok_or_else(|| gerr("SSHSIG_MALFORMED", "missing END SSH SIGNATURE"))?;
    let raw = base64_decode_clean(body_b64, 16_384).map_err(|m| gerr("SSHSIG_MALFORMED", m))?;

    let mut outer = SshCursor(&raw, 0);
    if outer.read_fixed(6)? != SSHSIG_MAGIC || outer.read_u32()? != 1 {
        return Err(gerr("SSHSIG_MALFORMED", "bad SSHSIG preamble"));
    }
    let mut pk_cur = SshCursor(outer.read_bytes()?, 0);
    if pk_cur.read_str()? != SK_ED25519_ALG {
        return Err(gerr("SSHSIG_WRONG_KEY_TYPE", "not sk-ssh-ed25519"));
    }
    let pk_bytes: [u8; 32] = pk_cur
        .read_bytes()?
        .try_into()
        .map_err(|_| gerr("SSHSIG_MALFORMED", "pubkey must be 32 bytes"))?;
    let application = pk_cur.read_bytes()?;
    if !matches!(application, b"ssh:" | b"ssh:dotagent") {
        return Err(gerr("SSHSIG_WRONG_APPLICATION", "untrusted sk application"));
    }
    pk_cur.ensure_empty()?;

    let sig_ns = outer.read_str()?;
    if sig_ns != namespace {
        return Err(gerr("SSHSIG_NAMESPACE_MISMATCH", "namespace mismatch"));
    }
    let reserved = outer.read_bytes()?;
    let hash_alg = outer.read_str()?;
    let mut sg_cur = SshCursor(outer.read_bytes()?, 0);
    outer.ensure_empty()?;

    if sg_cur.read_str()? != SK_ED25519_ALG {
        return Err(gerr("SSHSIG_WRONG_SIG_TYPE", "not sk-ssh-ed25519"));
    }
    let sig_bytes: [u8; 64] = sg_cur
        .read_bytes()?
        .try_into()
        .map_err(|_| gerr("SSHSIG_MALFORMED", "Ed25519 sig must be 64 bytes"))?;
    let (flags, counter) = (sg_cur.read_u8()?, sg_cur.read_u32()?);
    sg_cur.ensure_empty()?;

    if flags & SSH_SK_USER_PRESENCE_REQD == 0 {
        return Err(gerr("SSHSIG_USER_PRESENCE_REQUIRED", "UP touch bit is 0"));
    }
    if !allowed_pubkeys
        .iter()
        .any(|k| constant_time_eq_bytes(k, &pk_bytes))
    {
        return Err(gerr("SSHSIG_UNTRUSTED_PUBKEY", "untrusted sk pubkey"));
    }
    let msg_hash: Vec<u8> = match hash_alg {
        "sha512" => Sha512::digest(challenge).to_vec(),
        "sha256" => Sha256::digest(challenge).to_vec(),
        _ => return Err(gerr("SSHSIG_UNSUPPORTED_HASH", "expected sha512/sha256")),
    };
    let mut preimage = Vec::with_capacity(128);
    preimage.extend_from_slice(SSHSIG_MAGIC);
    push_ssh_str(&mut preimage, sig_ns.as_bytes());
    push_ssh_str(&mut preimage, reserved);
    push_ssh_str(&mut preimage, hash_alg.as_bytes());
    push_ssh_str(&mut preimage, &msg_hash);

    let mut sk_signed = Vec::with_capacity(69);
    sk_signed.extend_from_slice(&sha256_bytes(application));
    sk_signed.push(flags);
    sk_signed.extend_from_slice(&counter.to_be_bytes());
    sk_signed.extend_from_slice(&sha256_bytes(&preimage));

    let vk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| gerr("SSHSIG_INVALID_PUBKEY", "invalid Ed25519 key"))?;
    if vk.is_weak() {
        return Err(gerr("SSHSIG_WEAK_PUBKEY", "weak Ed25519 key"));
    }
    vk.verify_strict(&sk_signed, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| gerr("SSHSIG_VERIFY_FAILED", "signature verification failed"))?;
    Ok(counter)
}

pub fn format_operator_challenge(
    action: &str,
    repo_id: &str,
    epoch_id: u64,
    floor_ts_60s: u64,
) -> String {
    format!("dotagent:operator:v1:{action}:{repo_id}:{epoch_id}:{floor_ts_60s}")
}

pub fn load_operator_sk_keys_from_home(home: &Path) -> Result<Option<Vec<[u8; 32]>>, GuardError> {
    if home.as_os_str().is_empty() || !home.is_absolute() {
        return Err(gerr("SSHSIG_CONFIG_INVALID", "HOME must be absolute"));
    }
    let dot_cfg = home.join(".config");
    let cfg_dir = dot_cfg.join("dotagent");
    let key_file = cfg_dir.join("operator_sk_keys");
    if fs::symlink_metadata(&dot_cfg).is_ok_and(|m| m.file_type().is_symlink())
        || fs::symlink_metadata(&cfg_dir).is_ok_and(|m| m.file_type().is_symlink())
    {
        return Err(gerr("SSHSIG_SYMLINK_TAMPER", ".config path is symlink"));
    }
    let Ok(meta) = fs::symlink_metadata(&key_file) else {
        return Ok(None);
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() || meta.len() > 65_536 {
        return Err(gerr("SSHSIG_SYMLINK_TAMPER", "invalid operator_sk_keys"));
    }
    let raw = fs::read_to_string(&key_file)
        .map_err(|e| GuardError::new("SSHSIG_KEYRING_IO", e.to_string()))?;
    let mut keys = Vec::new();
    for line in raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        if line.len() == 64
            && let Ok(k) = hex_decode_32(line)
        {
            keys.push(k);
            continue;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        if let Some(i) = toks.iter().position(|&t| t == SK_ED25519_ALG)
            && let Some(b64) = toks.get(i + 1)
        {
            let blob =
                base64_decode_clean(b64, 4_096).map_err(|m| gerr("SSHSIG_KEYRING_INVALID", m))?;
            let mut cur = SshCursor(&blob, 0);
            if cur.read_str()? == SK_ED25519_ALG
                && let Ok(k) = <[u8; 32]>::try_from(cur.read_bytes()?)
                && matches!(cur.read_bytes()?, b"ssh:" | b"ssh:dotagent")
                && cur.ensure_empty().is_ok()
            {
                keys.push(k);
                continue;
            }
        }
        return Err(gerr("SSHSIG_KEYRING_INVALID", "unrecognized sk key"));
    }
    if keys.is_empty() {
        return Err(gerr("SSHSIG_KEYRING_EMPTY", "empty operator_sk_keys"));
    }
    Ok(Some(keys))
}
