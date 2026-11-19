#![forbid(unsafe_code)]

//! Audited cryptographic primitives & zeroizing key wrappers (`sha2` + `hmac`).
//!
//! Centralizes all SHA-256 hashing, hex encoding/decoding, constant-time MAC
//! comparison, and automatic memory zeroization on `Drop` using safe Rust 2024
//! (`#![forbid(unsafe_code)]`) without custom hash compression code or heap-copy
//! padding buffers.

use std::fmt::Write as _;
use std::ops::Deref;
use std::sync::atomic::{Ordering, compiler_fence};

use sha2::{Digest, Sha256};

/// 256-bit secret key buffer that overwrites its bytes with zeros on `Drop`
/// through `black_box` + `SeqCst` compiler fences so key material does not
/// linger in stack or heap allocations.
#[derive(Clone)]
pub struct ZeroizingKey([u8; 32]);

impl ZeroizingKey {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Deref for ZeroizingKey {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for ZeroizingKey {
    fn drop(&mut self) {
        zeroize_slice(&mut self.0);
    }
}

impl std::fmt::Debug for ZeroizingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ZeroizingKey([REDACTED; 32])")
    }
}

/// Overwrites `buf` in-place with zeros without dead-store elimination.
#[inline(never)]
pub fn zeroize_slice(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
        std::hint::black_box(b);
    }
    compiler_fence(Ordering::SeqCst);
}

/// Computes the FIPS 180-4 SHA-256 digest of `data` via RustCrypto `sha2` (streaming, zero heap copy).
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Computes the lowercase 64-character hex SHA-256 digest of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&sha256_bytes(data))
}

/// Encodes arbitrary bytes as lowercase hexadecimal.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Decodes an even-length hexadecimal string into raw bytes.
pub fn hex_decode_bytes(raw: &str) -> Result<Vec<u8>, String> {
    let trimmed = raw.trim();
    if trimmed.len() % 2 != 0 {
        return Err("hex string must have even byte length".to_string());
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let bytes = trimmed.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        let hi = decode_nibble(bytes[idx])?;
        let lo = decode_nibble(bytes[idx + 1])?;
        out.push((hi << 4) | lo);
        idx += 2;
    }
    Ok(out)
}

/// Decodes a 64-character hexadecimal string into a fixed 32-byte array.
pub fn hex_decode_32(raw: &str) -> Result<[u8; 32], String> {
    let trimmed = raw.trim();
    if trimmed.len() != 64 {
        return Err(format!(
            "expected 64-char hex digest, got {} chars",
            trimmed.len()
        ));
    }
    let decoded = hex_decode_bytes(trimmed)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&decoded);
    Ok(arr)
}

fn decode_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex character 0x{b:02x}")),
    }
}

/// Constant-time byte slice equality check resistant to compiler short-circuiting.
#[inline(never)]
pub fn constant_time_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= std::hint::black_box(x ^ y);
    }
    std::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::{ZeroizingKey, constant_time_eq_bytes, hex_decode_32, sha256_hex, zeroize_slice};

    #[test]
    fn fips_180_4_test_vectors_and_zeroize() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );

        let digest =
            hex_decode_32("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .expect("decode 32");
        assert!(constant_time_eq_bytes(&digest, &digest));
        let mut buf = [0xAAu8; 32];
        zeroize_slice(&mut buf);
        assert_eq!(buf, [0u8; 32]);
        let key = ZeroizingKey::new([0x42u8; 32]);
        assert_eq!(format!("{key:?}"), "ZeroizingKey([REDACTED; 32])");
    }
}
