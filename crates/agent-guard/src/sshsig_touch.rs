#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! Pure-Rust OpenSSH `SSHSIG` gate: strict FIDO2 `sk-*` (`UP=1`) for `v*` release tags, and
//! standard `ssh-ed25519` / `sk-ssh-ed25519@openssh.com` verification for operator/plugin/CLI gates.

use std::fs;
use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};

use crate::crypto::{base64_decode_clean, constant_time_eq_bytes, hex_decode_32, sha256_bytes};

pub const OPERATOR_SSHSIG_NAMESPACE: &str = "dotagent-operator@susanb.dev";
pub const SK_ED25519_ALG: &str = "sk-ssh-ed25519@openssh.com";
pub const SSH_ED25519_ALG: &str = "ssh-ed25519";
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

/// Checks the signed FIDO2 attributes of an OpenSSH Git release-tag signature. OpenSSH
/// independently verifies the signature bytes against the enrolled public key.
pub fn release_signature_has_fido2_touch(sig_pem: &str) -> Result<bool, GuardError> {
    let body = sig_pem
        .trim()
        .strip_prefix("-----BEGIN SSH SIGNATURE-----")
        .and_then(|body| body.strip_suffix("-----END SSH SIGNATURE-----"))
        .filter(|body| body.len() <= 32_768)
        .ok_or_else(|| gerr("SSHSIG_MALFORMED", "invalid SSHSIG envelope"))?;
    let raw = base64_decode_clean(body, 16_384).map_err(|m| gerr("SSHSIG_MALFORMED", m))?;
    release_signature_bytes_have_fido2_touch(&raw)
}

fn release_signature_bytes_have_fido2_touch(raw: &[u8]) -> Result<bool, GuardError> {
    let mut outer = SshCursor(raw, 0);
    if outer.read_fixed(6)? != SSHSIG_MAGIC || outer.read_u32()? != 1 {
        return Err(gerr("SSHSIG_MALFORMED", "bad SSHSIG preamble"));
    }
    let mut key = SshCursor(outer.read_bytes()?, 0);
    let algorithm = key.read_str()?;
    if !matches!(
        algorithm,
        SK_ED25519_ALG | "sk-ecdsa-sha2-nistp256@openssh.com"
    ) {
        return Ok(false);
    }
    if outer.read_str()? != "git" {
        return Err(gerr("SSHSIG_NAMESPACE_MISMATCH", "expected git namespace"));
    }
    outer.read_bytes()?;
    outer.read_bytes()?;
    let mut signed = SshCursor(outer.read_bytes()?, 0);
    outer.ensure_empty()?;
    if signed.read_str()? != algorithm {
        return Err(gerr("SSHSIG_WRONG_SIG_TYPE", "FIDO2 algorithms must agree"));
    }
    signed.read_bytes()?;
    let flags = signed.read_u8()?;
    signed.read_u32()?;
    signed.ensure_empty()?;
    if flags & SSH_SK_USER_PRESENCE_REQD == 0 {
        return Err(gerr("SSHSIG_USER_PRESENCE_REQUIRED", "UP touch bit is 0"));
    }
    Ok(true)
}

/// Verifies an OpenSSH `SSHSIG` PEM signature made by either standard `ssh-ed25519`
/// (returning counter `0`) or `sk-ssh-ed25519@openssh.com` (without requiring `UP=1`,
/// returning the signed `counter`).
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
    let pk_alg = pk_cur.read_str()?;
    let (pk_bytes, sk_application): ([u8; 32], Option<&[u8]>) = match pk_alg {
        SSH_ED25519_ALG => {
            let pk: [u8; 32] = pk_cur
                .read_bytes()?
                .try_into()
                .map_err(|_| gerr("SSHSIG_MALFORMED", "pubkey must be 32 bytes"))?;
            pk_cur.ensure_empty()?;
            (pk, None)
        }
        SK_ED25519_ALG => {
            let pk: [u8; 32] = pk_cur
                .read_bytes()?
                .try_into()
                .map_err(|_| gerr("SSHSIG_MALFORMED", "pubkey must be 32 bytes"))?;
            let application = pk_cur.read_bytes()?;
            if !matches!(application, b"ssh:" | b"ssh:dotagent") {
                return Err(gerr("SSHSIG_WRONG_APPLICATION", "untrusted sk application"));
            }
            pk_cur.ensure_empty()?;
            (pk, Some(application))
        }
        _ => {
            return Err(gerr(
                "SSHSIG_WRONG_KEY_TYPE",
                "expected ssh-ed25519 or sk-ssh-ed25519@openssh.com",
            ));
        }
    };

    let sig_ns = outer.read_str()?;
    if sig_ns != namespace {
        return Err(gerr("SSHSIG_NAMESPACE_MISMATCH", "namespace mismatch"));
    }
    let reserved = outer.read_bytes()?;
    let hash_alg = outer.read_str()?;
    let mut sg_cur = SshCursor(outer.read_bytes()?, 0);
    outer.ensure_empty()?;

    if sg_cur.read_str()? != pk_alg {
        return Err(gerr(
            "SSHSIG_WRONG_SIG_TYPE",
            "signature algorithm mismatch",
        ));
    }
    let sig_bytes: [u8; 64] = sg_cur
        .read_bytes()?
        .try_into()
        .map_err(|_| gerr("SSHSIG_MALFORMED", "Ed25519 sig must be 64 bytes"))?;
    let sk_meta = if sk_application.is_some() {
        let flags = sg_cur.read_u8()?;
        let counter = sg_cur.read_u32()?;
        sg_cur.ensure_empty()?;
        Some((flags, counter))
    } else {
        sg_cur.ensure_empty()?;
        None
    };

    if !allowed_pubkeys
        .iter()
        .any(|k| constant_time_eq_bytes(k, &pk_bytes))
    {
        return Err(gerr("SSHSIG_UNTRUSTED_PUBKEY", "untrusted ssh pubkey"));
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

    let vk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| gerr("SSHSIG_INVALID_PUBKEY", "invalid Ed25519 key"))?;
    if vk.is_weak() {
        return Err(gerr("SSHSIG_WEAK_PUBKEY", "weak Ed25519 key"));
    }

    if let (Some(application), Some((flags, counter))) = (sk_application, sk_meta) {
        let mut sk_signed = Vec::with_capacity(69);
        sk_signed.extend_from_slice(&sha256_bytes(application));
        sk_signed.push(flags);
        sk_signed.extend_from_slice(&counter.to_be_bytes());
        sk_signed.extend_from_slice(&sha256_bytes(&preimage));
        vk.verify_strict(&sk_signed, &Signature::from_bytes(&sig_bytes))
            .map_err(|_| gerr("SSHSIG_VERIFY_FAILED", "signature verification failed"))?;
        Ok(counter)
    } else {
        vk.verify_strict(&preimage, &Signature::from_bytes(&sig_bytes))
            .map_err(|_| gerr("SSHSIG_VERIFY_FAILED", "signature verification failed"))?;
        Ok(0)
    }
}

pub fn format_operator_challenge(
    action: &str,
    repo_id: &str,
    epoch_id: u64,
    floor_ts_60s: u64,
) -> String {
    format!("dotagent:operator:v1:{action}:{repo_id}:{epoch_id}:{floor_ts_60s}")
}

fn parse_ed25519_pubkey_line(line: &str) -> Result<[u8; 32], GuardError> {
    if line.len() == 64
        && let Ok(k) = hex_decode_32(line)
    {
        return Ok(k);
    }
    let toks: Vec<&str> = line.split_whitespace().collect();
    if let Some(i) = toks.iter().position(|&t| t == SSH_ED25519_ALG)
        && let Some(b64) = toks.get(i + 1)
    {
        let blob =
            base64_decode_clean(b64, 4_096).map_err(|m| gerr("SSHSIG_KEYRING_INVALID", m))?;
        let mut cur = SshCursor(&blob, 0);
        if cur.read_str()? == SSH_ED25519_ALG
            && let Ok(k) = <[u8; 32]>::try_from(cur.read_bytes()?)
            && cur.ensure_empty().is_ok()
        {
            return Ok(k);
        }
    }
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
            return Ok(k);
        }
    }
    Err(gerr("SSHSIG_KEYRING_INVALID", "unrecognized ssh key"))
}

fn read_nonsymlink_keyring_file(
    key_file: &Path,
    strict_lines: bool,
) -> Result<Option<Vec<[u8; 32]>>, GuardError> {
    let Ok(meta) = fs::symlink_metadata(key_file) else {
        return Ok(None);
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() || meta.len() > 65_536 {
        return Err(gerr("SSHSIG_SYMLINK_TAMPER", "invalid operator key file"));
    }
    let raw = fs::read_to_string(key_file)
        .map_err(|e| GuardError::new("SSHSIG_KEYRING_IO", e.to_string()))?;
    let mut keys = Vec::new();
    for line in raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        match parse_ed25519_pubkey_line(line) {
            Ok(k) => keys.push(k),
            Err(e) if strict_lines => return Err(e),
            Err(_) => {}
        }
    }
    if strict_lines && keys.is_empty() {
        return Err(gerr("SSHSIG_KEYRING_EMPTY", "empty operator keyring"));
    }
    Ok(Some(keys))
}

pub fn load_operator_sk_keys_from_home(home: &Path) -> Result<Option<Vec<[u8; 32]>>, GuardError> {
    if home.as_os_str().is_empty() || !home.is_absolute() {
        return Err(gerr("SSHSIG_CONFIG_INVALID", "HOME must be absolute"));
    }
    let dot_cfg = home.join(".config");
    let cfg_dir = dot_cfg.join("dotagent");
    if fs::symlink_metadata(&dot_cfg).is_ok_and(|m| m.file_type().is_symlink())
        || fs::symlink_metadata(&cfg_dir).is_ok_and(|m| m.file_type().is_symlink())
    {
        return Err(gerr("SSHSIG_SYMLINK_TAMPER", ".config path is symlink"));
    }
    let mut combined = Vec::new();
    let mut found_file = false;
    for filename in ["operator_keys", "operator_sk_keys", "allowed_signers"] {
        if let Some(keys) = read_nonsymlink_keyring_file(&cfg_dir.join(filename), true)? {
            found_file = true;
            combined.extend(keys);
        }
    }
    if !found_file {
        return Ok(None);
    }
    if combined.is_empty() {
        return Err(gerr("SSHSIG_KEYRING_EMPTY", "empty operator keyring"));
    }
    Ok(Some(combined))
}

/// Loads configured operator keys from `~/.config/dotagent/{operator_keys,operator_sk_keys,allowed_signers}`,
/// falling back to `~/.ssh/allowed_signers` and `~/.ssh/id_ed25519.pub` when present.
pub fn load_operator_or_ssh_keys_from_home(
    home: &Path,
) -> Result<Option<Vec<[u8; 32]>>, GuardError> {
    if let Some(keys) = load_operator_sk_keys_from_home(home)? {
        return Ok(Some(keys));
    }
    let dot_ssh = home.join(".ssh");
    if fs::symlink_metadata(&dot_ssh).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(gerr("SSHSIG_SYMLINK_TAMPER", ".ssh path is symlink"));
    }
    let mut fallback = Vec::new();
    for filename in ["allowed_signers", "id_ed25519.pub"] {
        if let Some(keys) = read_nonsymlink_keyring_file(&dot_ssh.join(filename), false)? {
            fallback.extend(keys);
        }
    }
    if fallback.is_empty() {
        Ok(None)
    } else {
        Ok(Some(fallback))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git_signature_attributes(algorithm: &str, flags: u8) -> Vec<u8> {
        let mut public_key = Vec::new();
        push_ssh_str(&mut public_key, algorithm.as_bytes());
        let mut signature = Vec::new();
        push_ssh_str(&mut signature, algorithm.as_bytes());
        push_ssh_str(&mut signature, &[0; 64]);
        signature.push(flags);
        signature.extend_from_slice(&1u32.to_be_bytes());
        let mut raw = SSHSIG_MAGIC.to_vec();
        raw.extend_from_slice(&1u32.to_be_bytes());
        push_ssh_str(&mut raw, &public_key);
        push_ssh_str(&mut raw, b"git");
        push_ssh_str(&mut raw, b"");
        push_ssh_str(&mut raw, b"sha512");
        push_ssh_str(&mut raw, &signature);
        raw
    }

    #[test]
    fn release_signature_requires_fido2_user_presence() {
        let raw = git_signature_attributes(SK_ED25519_ALG, SSH_SK_USER_PRESENCE_REQD);
        assert_eq!(release_signature_bytes_have_fido2_touch(&raw), Ok(true));
        let raw = git_signature_attributes(SK_ED25519_ALG, 0);
        assert_eq!(
            release_signature_bytes_have_fido2_touch(&raw)
                .expect_err("a release signature requires hardware touch")
                .code,
            "SSHSIG_USER_PRESENCE_REQUIRED"
        );
        let raw = git_signature_attributes("ssh-ed25519", 0);
        assert_eq!(release_signature_bytes_have_fido2_touch(&raw), Ok(false));
    }

    #[test]
    fn standard_ssh_ed25519_keygen_sign_and_home_fallback_verify() {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = manifest
            .parent()
            .and_then(Path::parent)
            .expect("ws")
            .join("target")
            .join(format!("sshsig-ed25519-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let ssh_dir = root.join(".ssh");
        fs::create_dir_all(&ssh_dir).expect("mkdir .ssh");
        let key_path = ssh_dir.join("id_ed25519");
        assert!(
            Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-N", "", "-C", "op@local", "-f"])
                .arg(&key_path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("ssh-keygen")
                .success()
        );
        let keys = load_operator_or_ssh_keys_from_home(&root)
            .expect("load ssh keys")
            .expect("id_ed25519.pub loaded");
        assert_eq!(keys.len(), 1);

        let challenge = b"dotagent:operator:v1:repo123:0:1795275600";
        let mut child = Command::new("ssh-keygen")
            .args(["-Y", "sign", "-f"])
            .arg(&key_path)
            .args(["-n", OPERATOR_SSHSIG_NAMESPACE])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("ssh-keygen -Y sign");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(challenge)
            .expect("write");
        let out = child.wait_with_output().expect("wait");
        assert!(out.status.success());
        let sig_pem = String::from_utf8(out.stdout).expect("utf8");
        assert_eq!(
            verify_fido2_sshsig_ed25519(OPERATOR_SSHSIG_NAMESPACE, challenge, &sig_pem, &keys),
            Ok(0)
        );
        let _ = fs::remove_dir_all(&root);
    }
}
