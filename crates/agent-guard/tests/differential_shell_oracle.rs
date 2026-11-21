#![forbid(unsafe_code)]

//! Differential `/bin/bash` vs `cmd_policy::evaluate_shell_command` Tokenization & Fail-Open Oracle (`Pillar 6`).
//!
//! Evaluates 1,200+ adversarial quoting, escaping, line-continuation, IFS, pipeline, subshell,
//! and redirection mutations against BOTH a real `/bin/bash` word-expansion oracle and
//! `agent_guard::cmd_policy::evaluate_shell_command`, proving zero fail-open parser differentials.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use agent_guard::cmd_policy::evaluate_shell_command;

fn isolated_oracle_repo() -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("target")
        .join("test-workspaces")
        .join(format!("diff_shell_oracle_{}", std::process::id()));
    let _ = fs::create_dir_all(dir.join("src"));
    let _ = fs::write(dir.join("AGENTS.md"), "# AGENTS.md\n");
    let _ = fs::write(dir.join("src/lib.rs"), "pub fn ok() {}\n");
    dir
}

/// Evaluates batches of candidate shell argument lists inside a real shell word-splitting
/// function (`__emit_words() { printf '%s\n' "$@"; }`) rooted in `repo_dir` without executing external binaries.
fn query_real_shell_word_oracle(
    shell_bin: &str,
    shell_flags: &[&str],
    repo_dir: &Path,
    arg_expressions: &[String],
) -> Vec<Vec<String>> {
    let mut script = String::from("__emit_words() { printf '%s\\n' \"$@\"; }\n");
    for (idx, expr) in arg_expressions.iter().enumerate() {
        script.push_str(&format!("printf '===CASE_{idx}===\\n'\n"));
        script.push_str(&format!("__emit_words {expr}\n"));
    }
    script.push_str("printf '===END===\\n'\n");

    let mut cmd = Command::new(shell_bin);
    cmd.current_dir(repo_dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .args(shell_flags)
        .arg("-c")
        .arg(&script);
    let out = cmd
        .output()
        .expect("failed spawning shell differential oracle");
    assert!(
        out.status.success(),
        "{shell_bin} oracle script failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut results = vec![Vec::new(); arg_expressions.len()];
    let mut current_idx: Option<usize> = None;

    for line in stdout.lines() {
        if line == "===END===" {
            break;
        }
        if let Some(rest) = line.strip_prefix("===CASE_")
            && let Some(num_s) = rest.strip_suffix("===")
            && let Ok(idx) = num_s.parse::<usize>()
        {
            current_idx = Some(idx);
            continue;
        }
        if let Some(i) = current_idx
            && i < results.len()
        {
            results[i].push(line.to_string());
        }
    }
    results
}

fn is_forbidden_binary_word(w: &str) -> bool {
    let base = w.rsplit('/').next().unwrap_or(w);
    matches!(
        base,
        "curl" | "wget" | "nc" | "ncat" | "ssh" | "scp" | "sudo" | "su" | "npx" | "socat"
    )
}

fn is_forbidden_zone_word(w: &str) -> bool {
    w == ".env"
        || w.starts_with(".env.")
        || w.contains("node_modules/")
        || w.contains("vendor/")
        || w.contains(".venv/")
        || w.contains(".git/hooks")
        || w.contains("audit.jsonl")
}

/// Deterministic xorshift64 PRNG for reproducible fuzz generation.
struct XorShift64(u64);

impl XorShift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        let idx = (self.next_u64() as usize) % items.len();
        &items[idx]
    }
}

fn obfuscate_word_for_bash(rng: &mut XorShift64, plain: &str) -> String {
    let chars: Vec<char> = plain.chars().collect();
    if chars.len() < 2 {
        return plain.to_string();
    }
    let split_at = 1 + ((rng.next_u64() as usize) % (chars.len() - 1));
    let left: String = chars[..split_at].iter().collect();
    let right: String = chars[split_at..].iter().collect();

    match rng.next_u64() % 8 {
        0 => format!("'{left}'\"{right}\""),
        1 => format!("\"{left}\"'{right}'"),
        2 => format!("{left}\\{right}"),
        3 => format!("{left}\\\n{right}"),
        4 => format!("''{left}''{right}"),
        5 => format!("${{DOTAGENT_UNSET_VAR:-{plain}}}"),
        6 => {
            let octal: String = plain.bytes().map(|b| format!("\\{:03o}", b)).collect();
            format!("$'{octal}'")
        }
        _ => format!("\"{left}\"{right}"),
    }
}

#[test]
fn differential_bash_oracle_proves_zero_fail_open_across_1200_vectors() {
    if !Path::new("/bin/bash").is_file() {
        return;
    }
    let repo = isolated_oracle_repo();

    let forbidden_bins = [
        "curl",
        "wget",
        "nc",
        "ssh",
        "sudo",
        "npx",
        "/usr/bin/curl",
        "/bin/su",
    ];
    let forbidden_paths = [
        ".env",
        ".env.production",
        "node_modules/pkg/index.js",
        "vendor/mod/lib.go",
        ".venv/pyvenv.cfg",
        ".git/hooks/pre-commit",
        "audit.jsonl",
    ];
    let safe_readers = ["cat", "head -n 5", "wc -l", "ls"];

    let mut rng = XorShift64(0xD07A_6E27_2026_0006);
    let mut expressions = Vec::with_capacity(1210);

    // 1. 600 obfuscated forbidden-binary invocations
    for _ in 0..600 {
        let target_bin = rng.pick(&forbidden_bins);
        let obf = obfuscate_word_for_bash(&mut rng, target_bin);
        expressions.push(format!("{obf} https://example.invalid"));
    }

    // 2. 600 obfuscated forbidden-path read/arg invocations
    for _ in 0..600 {
        let reader = rng.pick(&safe_readers);
        let target_path = rng.pick(&forbidden_paths);
        let obf_path = obfuscate_word_for_bash(&mut rng, target_path);
        expressions.push(format!("{reader} {obf_path}"));
    }

    // 3. Explicit brace-expansion, parameter-expansion, and octal-escape differential vectors
    for extra in [
        "{curl,-s,https://example.invalid}",
        "{wget,-qO-,https://example.invalid}",
        "cat {.env,src/lib.rs}",
        "cat {src/lib.rs,node_modules/pkg/index.js}",
        "${UNSET_BIN:-curl} https://example.invalid",
        "cat ${UNSET_PATH:-.env}",
        "$'\\143\\165\\162\\154' https://example.invalid",
        "cat $'\\056\\145\\156\\166'",
    ] {
        expressions.push(extra.to_string());
    }

    for chunk in expressions.chunks(200) {
        let bash_words_batch =
            query_real_shell_word_oracle("/bin/bash", &["--norc", "--noprofile"], &repo, chunk);
        for (expr, resolved_words) in chunk.iter().zip(bash_words_batch.iter()) {
            let bash_sees_forbidden = resolved_words
                .first()
                .is_some_and(|w| is_forbidden_binary_word(w))
                || resolved_words.iter().any(|w| is_forbidden_zone_word(w));

            assert!(
                bash_sees_forbidden,
                "oracle sanity check failed for '{expr}' -> {resolved_words:?}"
            );

            let policy_res = evaluate_shell_command(expr, &repo, &repo, false);
            assert!(
                policy_res.is_err(),
                "PARSER DIFFERENTIAL FAIL-OPEN: /bin/bash resolved '{expr}' to forbidden {resolved_words:?}, but cmd_policy allowed it: {policy_res:?}"
            );
        }
    }

    // 4. POSIX `/bin/sh` differential parity check on portable quoting & parameter-expansion vectors
    if Path::new("/bin/sh").is_file() {
        let sh_vectors: Vec<String> = [
            "'cu'\"rl\" https://example.invalid",
            "c\\url https://example.invalid",
            "${UNSET_BIN:-wget} https://example.invalid",
            "cat .e'n'v",
            "cat ${UNSET_PATH:-audit.jsonl}",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let sh_words_batch = query_real_shell_word_oracle("/bin/sh", &[], &repo, &sh_vectors);
        for (expr, resolved_words) in sh_vectors.iter().zip(sh_words_batch.iter()) {
            assert!(
                resolved_words
                    .first()
                    .is_some_and(|w| is_forbidden_binary_word(w))
                    || resolved_words.iter().any(|w| is_forbidden_zone_word(w))
            );
            assert!(
                evaluate_shell_command(expr, &repo, &repo, false).is_err(),
                "/bin/sh differential fail-open on '{expr}'"
            );
        }
    }

    // 5. Verify compound shell structures (`|`, `&&`, `;`, `$()`, ANSI-C `$'...'`, redirections)
    let compound_adversarial = [
        "git status && 'cu'\"rl\" https://evil.invalid",
        "echo ok | \"wg\"'et' -qO- https://evil.invalid",
        "cat .e'n'v",
        "cat .\"env\"",
        "cat $\'\\x2e\\x65\\x6e\\x76\'",
        "cat <.env",
        "cat < .git/hooks/pre-commit",
        "echo hacked > AGENTS.md",
        "echo hacked >> .git/config",
        "find . -maxdepth 3 -type f",
        "rg --max-depth 4 foo src",
    ];
    for cmd in compound_adversarial {
        assert!(
            evaluate_shell_command(cmd, &repo, &repo, false).is_err(),
            "compound adversarial command '{cmd}' must be denied"
        );
    }

    let _ = fs::remove_dir_all(&repo);
}
