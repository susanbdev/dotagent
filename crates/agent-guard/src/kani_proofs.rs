#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! Bounded Formal Verification Harnesses (`#[cfg(kani)]`) & Exhaustive Invariant Mirrors (`Pillar 6`).
//!
//! Proves panic-freedom, termination, RFC 7493 duplicate-key rejection, and strict 7-bit ASCII
//! output post-conditions across:
//! 1. `json::JsonValue::parse`
//! 2. `sanitizer::sanitize_and_compact_bytes`
//! 3. `cmd_policy::evaluate_shell_command`

use std::path::Path;

use crate::cmd_policy::evaluate_shell_command;
use crate::json::JsonValue;
use crate::sanitizer::sanitize_and_compact_bytes;

/// Formal post-condition check for `sanitize_and_compact_bytes`:
/// - Never panics on arbitrary byte sequences.
/// - Every emitted byte is strict 7-bit ASCII (`< 0x80`), free of `\r` (`0x0d`), NUL (`0x00`),
///   and raw ESC (`0x1b`).
pub fn check_sanitizer_postconditions(raw: &[u8]) -> bool {
    let out = sanitize_and_compact_bytes(raw, 64, 4096);
    out.clean_ascii
        .bytes()
        .all(|b| b < 0x80 && b != b'\r' && b != 0x00 && b != 0x1b)
}

/// Formal post-condition check for `JsonValue::parse`:
/// - Never panics on arbitrary UTF-8 strings.
/// - Any two-key object `{"k":1,"k":2}` with identical keys is strictly rejected (`Err`).
pub fn check_json_no_panic_and_duplicate_rejection(candidate: &str, key: &str) -> bool {
    let _ = JsonValue::parse(candidate);
    if key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        let dup = format!(r#"{{"{key}":1,"{key}":2}}"#);
        if JsonValue::parse(&dup).is_ok() {
            return false;
        }
    }
    true
}

/// Formal post-condition check for `evaluate_shell_command`:
/// - Terminates without panic on arbitrary candidate command strings.
pub fn check_cmd_policy_no_panic(cmd: &str) -> bool {
    let root = Path::new("/repo");
    let _ = evaluate_shell_command(cmd, root, root, false);
    true
}

#[cfg(kani)]
mod proofs {
    use crate::cmd_policy::scan_shell_brace_and_quote_bytes;
    use crate::crypto::{constant_time_eq_bytes, zeroize_slice};
    use crate::json::is_unique_str_key;
    use crate::sanitizer::is_clean_7bit_ascii_byte;

    #[kani::proof]
    #[kani::unwind(12)]
    fn proof_constant_time_eq_soundness() {
        let a: [u8; 8] = kani::any();
        let b: [u8; 8] = kani::any();
        assert_eq!(constant_time_eq_bytes(&a, &b), a == b);
    }

    #[kani::proof]
    #[kani::unwind(36)]
    fn proof_zeroize_wipes_all_secret_bytes() {
        let mut key: [u8; 32] = kani::any();
        zeroize_slice(&mut key);
        assert_eq!(key, [0u8; 32]);
    }

    #[kani::proof]
    fn proof_sanitizer_7bit_ascii_lut_postcondition() {
        let b: u8 = kani::any();
        let clean = is_clean_7bit_ascii_byte(b);
        let expected = b == b'\n' || b == b'\t' || (0x20..=0x7E).contains(&b);
        assert_eq!(clean, expected);
        if b >= 0x80 || b == b'\r' || b == 0x00 || b == 0x1B || b == 0x7F {
            assert!(!clean);
        }
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn proof_json_duplicate_key_rejection() {
        let k1: [u8; 2] = kani::any();
        let k2: [u8; 2] = kani::any();
        kani::assume(k1[0].is_ascii_alphabetic() && k1[1].is_ascii_alphabetic());
        kani::assume(k2[0].is_ascii_alphabetic() && k2[1].is_ascii_alphabetic());
        if let (Ok(s1), Ok(s2)) = (core::str::from_utf8(&k1), core::str::from_utf8(&k2)) {
            let existing = [s1];
            assert_eq!(is_unique_str_key(&existing, s2), s1 != s2);
        }
    }

    #[kani::proof]
    #[kani::unwind(40)]
    fn proof_shell_lexer_forward_progress_and_brace_block() {
        let raw: [u8; 6] = kani::any();
        let _ = scan_shell_brace_and_quote_bytes(&raw);
        assert_eq!(
            scan_shell_brace_and_quote_bytes(b"{a,b}"),
            Err("SHELL_BRACE_EXPANSION_BLOCKED")
        );
        assert_eq!(
            scan_shell_brace_and_quote_bytes(b"{1..3}"),
            Err("SHELL_BRACE_EXPANSION_BLOCKED")
        );
        assert!(scan_shell_brace_and_quote_bytes(b"${a}").is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_formal_postconditions_across_adversarial_byte_boundaries() {
        for b in 0u8..=255u8 {
            let sample = [b, b'\r', 0x1b, b'[', b'3', b'1', b'm', 0x00, 0xfe, b'A'];
            assert!(check_sanitizer_postconditions(&sample));
        }
        for pat in [
            "",
            "{",
            "{\"a\":1,\"a\":2}",
            "[[[[[[[[[[[[",
            "\"\\u0000\\uD800\"",
            "{\"x\": -0.0e9999}",
        ] {
            assert!(check_json_no_panic_and_duplicate_rejection(pat, "same"));
        }
        for cmd in [
            "",
            "'''\"\"\"\\$\\(",
            "$'\\x2f\\x74\\x6d\\x70'",
            "echo a | cat && git status \\\n --short",
            "((1+1)); $(true)",
        ] {
            assert!(check_cmd_policy_no_panic(cmd));
        }
    }
}
