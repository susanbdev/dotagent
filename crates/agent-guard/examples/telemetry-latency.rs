//! Pure-Rust independent spawn-through-exit cold CLI latency report (replaces Python script).

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    match unix_latency::run_all() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("[telemetry-latency FAIL] {err}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
mod unix_latency {
    use std::collections::BTreeSet;
    use std::env;
    use std::fs;
    use std::io::{self, BufRead, BufReader, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixDatagram;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use agent_guard::crypto::sha256_hex;
    use agent_guard::json::JsonValue;

    const SAMPLES: usize = 128;
    const WARMUP: usize = 8;
    static NEXT_WS: AtomicU64 = AtomicU64::new(0);

    struct BenchWorkspace {
        base: PathBuf,
        repo: PathBuf,
        state: PathBuf,
    }

    impl BenchWorkspace {
        fn create() -> Result<Self, String> {
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let root = fs::canonicalize(manifest_dir.join("../.."))
                .map_err(|e| format!("canonicalize workspace root: {e}"))?;
            let parent = root.join("target/test-workspaces");
            fs::create_dir_all(&parent)
                .map_err(|e| format!("mkdir '{}': {e}", parent.display()))?;
            let seq = NEXT_WS.fetch_add(1, Ordering::Relaxed);
            let base = parent.join(format!("l-{seq}"));
            if base.exists() {
                let _ = fs::remove_dir_all(&base);
            }
            let repo = base.join("r");
            let state = base.join("s");
            fs::create_dir_all(repo.join(".git")).map_err(|e| format!("mkdir .git: {e}"))?;
            fs::write(repo.join("plain.txt"), b"ordinary fixture text\n")
                .map_err(|e| format!("write plain.txt: {e}"))?;
            fs::create_dir_all(&state).map_err(|e| format!("mkdir state: {e}"))?;
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("chmod 0700 state: {e}"))?;
            Ok(Self { base, repo, state })
        }

        fn clean_env(&self) -> Vec<(String, String)> {
            let mut vars: Vec<(String, String)> = env::vars()
                .filter(|(k, _)| !k.starts_with("AGENT_GUARD_") && !k.starts_with("DOTAGENT_"))
                .collect();
            vars.push((
                "AGENT_GUARD_STATE_DIR".to_string(),
                self.state.to_string_lossy().into_owned(),
            ));
            vars
        }
    }

    impl Drop for BenchWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    struct CollectorChild(Child);

    impl CollectorChild {
        fn spawn(dotagent_bin: &Path, ws: &BenchWorkspace) -> Result<Self, String> {
            let mut child = Command::new(dotagent_bin)
                .args(["collect-observations", "--owned"])
                .current_dir(&ws.repo)
                .env_clear()
                .envs(ws.clean_env())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| format!("spawn collector: {e}"))?;
            let stdout = child.stdout.take().ok_or("missing collector stdout")?;
            let mut line = String::new();
            BufReader::new(stdout)
                .read_line(&mut line)
                .map_err(|e| format!("read READY: {e}"))?;
            if line.trim() != "READY" {
                return Err(format!("expected READY, got '{}'", line.trim()));
            }
            Ok(Self(child))
        }
    }

    impl Drop for CollectorChild {
        fn drop(&mut self) {
            self.0.stdin = None;
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn invocation(
        operation: &str,
        dir: &Path,
        repo: &Path,
        session: &str,
    ) -> (PathBuf, Vec<String>, Option<String>) {
        let dotagent = dir.join("dotagent");
        let plain = repo.join("plain.txt").to_string_lossy().into_owned();
        match operation {
            "pre-tool" => {
                let body = JsonValue::Object(vec![
                    ("session_id".into(), JsonValue::Str(session.into())),
                    ("tool_name".into(), JsonValue::Str("Read".into())),
                    (
                        "tool_input".into(),
                        JsonValue::Object(vec![("file_path".into(), JsonValue::Str(plain))]),
                    ),
                ]);
                (
                    dotagent,
                    vec!["pre-tool".into()],
                    Some(body.to_json_string()),
                )
            }
            "post-tool" => {
                let body = JsonValue::Object(vec![
                    ("session_id".into(), JsonValue::Str(session.into())),
                    ("tool_name".into(), JsonValue::Str("Read".into())),
                    ("tool_response".into(), JsonValue::Str("fixture".into())),
                ]);
                (
                    dotagent,
                    vec!["post-tool".into()],
                    Some(body.to_json_string()),
                )
            }
            "shell" => (
                dir.join("agent-guard-sh"),
                vec!["-c".into(), "printf %s fixture".into()],
                None,
            ),
            "read-safe" => (dotagent, vec!["read-safe".into(), "plain.txt".into()], None),
            _ => {
                let body =
                    JsonValue::Object(vec![("session_id".into(), JsonValue::Str(session.into()))]);
                (
                    dotagent,
                    vec!["pre-compact".into()],
                    Some(body.to_json_string()),
                )
            }
        }
    }

    fn extract_upper_codes(text: &str) -> Vec<String> {
        let mut codes = BTreeSet::new();
        for token in text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
            if token.len() >= 5
                && token.as_bytes()[0].is_ascii_uppercase()
                && token
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            {
                codes.insert(token.to_string());
            }
        }
        codes.into_iter().take(8).collect()
    }

    fn percentile(sorted: &[u64], pct: usize) -> u64 {
        let idx = (sorted.len() * pct).div_ceil(100).saturating_sub(1);
        sorted[idx]
    }

    fn run_condition(mode: &str, main_dir: &Path, pr_dir: &Path) -> Result<(), String> {
        let ws = BenchWorkspace::create()?;
        let env_vars = ws.clean_env();
        let mut collector = if mode != "absent" {
            Some(CollectorChild::spawn(&pr_dir.join("dotagent"), &ws)?)
        } else {
            None
        };

        if let Some(ref mut col) = collector {
            if mode == "crashed" {
                let _ = col.0.kill();
                let _ = col.0.wait();
            } else if mode == "saturated" {
                let status = Command::new("/bin/kill")
                    .arg("-STOP")
                    .arg(col.0.id().to_string())
                    .status()
                    .map_err(|e| format!("kill -STOP: {e}"))?;
                if !status.success() {
                    return Err("failed to SIGSTOP collector for saturated benchmark".to_string());
                }
                let sender = UnixDatagram::unbound().map_err(|e| format!("unbound: {e}"))?;
                sender
                    .set_nonblocking(true)
                    .map_err(|e| format!("nonblocking: {e}"))?;
                sender
                    .connect(ws.state.join("observations/in"))
                    .map_err(|e| format!("connect saturated socket: {e}"))?;
                let mut hit_backpressure = false;
                for _ in 0..16384 {
                    match sender.send(b"benchmark-capacity") {
                        Ok(_) => {}
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            hit_backpressure = true;
                            break;
                        }
                        Err(e) => return Err(format!("saturated send error: {e}")),
                    }
                }
                if !hit_backpressure {
                    return Err("failed to establish kernel backpressure".to_string());
                }
            }
        }

        let repo_str = ws.repo.to_str().ok_or("non-utf8 repo")?;
        let default_framed = format!("v2:{}:{repo_str}:7:default", repo_str.len());
        let default_ledger = format!("{}.json", &sha256_hex(default_framed.as_bytes())[..32]);

        let builds = [("main", main_dir), ("pr", pr_dir)];
        for operation in ["pre-tool", "post-tool", "shell", "read-safe", "pre-compact"] {
            let mut main_samples = Vec::with_capacity(SAMPLES);
            let mut pr_samples = Vec::with_capacity(SAMPLES);
            let mut main_exits = BTreeSet::new();
            let mut pr_exits = BTreeSet::new();

            for cycle in 0..(SAMPLES + WARMUP) {
                let order = if cycle % 2 == 0 {
                    [0usize, 1usize]
                } else {
                    [1usize, 0usize]
                };
                for idx in order {
                    let (label, dir) = builds[idx];
                    let session = format!("bench-{mode}-{operation}-{cycle}-{label}");
                    let (bin, args, payload) = invocation(operation, dir, &ws.repo, &session);
                    if payload.is_none() || operation == "read-safe" {
                        let _ = fs::remove_file(ws.state.join(&default_ledger));
                    }
                    let start = Instant::now();
                    let mut child = Command::new(&bin)
                        .args(&args)
                        .current_dir(&ws.repo)
                        .env_clear()
                        .envs(env_vars.iter().cloned())
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                        .map_err(|e| format!("spawn bench '{}': {e}", bin.display()))?;
                    if let Some(ref data) = payload
                        && let Some(mut sin) = child.stdin.take()
                    {
                        let _ = sin.write_all(data.as_bytes());
                    } else {
                        child.stdin = None;
                    }
                    let out = child
                        .wait_with_output()
                        .map_err(|e| format!("wait bench: {e}"))?;
                    let elapsed = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
                    let code = out.status.code().unwrap_or(-1);

                    if cycle == 0 && label == "pr" {
                        let mut diag = out.stderr.clone();
                        diag.extend_from_slice(&out.stdout);
                        let text = String::from_utf8_lossy(&diag);
                        let codes = extract_upper_codes(&text);
                        println!("FIXTURE {mode} {operation} {code} {codes:?}");
                    }
                    if cycle >= WARMUP {
                        if label == "main" {
                            main_samples.push(elapsed);
                            main_exits.insert(code);
                        } else {
                            pr_samples.push(elapsed);
                            pr_exits.insert(code);
                        }
                    }
                }
            }

            for (label, mut samples, exits) in [
                ("main", main_samples, main_exits),
                ("pr", pr_samples, pr_exits),
            ] {
                samples.sort_unstable();
                let exit_arr: Vec<JsonValue> = exits
                    .into_iter()
                    .map(|c| JsonValue::Int(i64::from(c)))
                    .collect();
                let report = JsonValue::Object(vec![
                    ("collector".into(), JsonValue::Str(mode.into())),
                    ("exit".into(), JsonValue::Array(exit_arr)),
                    ("max".into(), JsonValue::Uint(percentile(&samples, 100))),
                    ("n".into(), JsonValue::Uint(SAMPLES as u64)),
                    ("operation".into(), JsonValue::Str(operation.into())),
                    ("p50".into(), JsonValue::Uint(percentile(&samples, 50))),
                    ("p95".into(), JsonValue::Uint(percentile(&samples, 95))),
                    ("p99".into(), JsonValue::Uint(percentile(&samples, 99))),
                    ("revision".into(), JsonValue::Str(label.into())),
                ]);
                println!("COLD_NS {}", report.to_json_string());
            }
        }

        if let Some(mut col) = collector {
            col.0.stdin = None;
            let _ = col.0.kill();
            let _ = col.0.wait();
        }
        let close_deadline = Instant::now() + Duration::from_secs(3);
        while ws.state.join("observations/in").exists() && Instant::now() < close_deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }

    pub fn run_all() -> Result<(), String> {
        let mut args = env::args().skip(1);
        let main_arg = args.next().ok_or(
            "usage: telemetry-latency <baseline/target/release> <candidate/target/release>",
        )?;
        let pr_arg = args.next().ok_or(
            "usage: telemetry-latency <baseline/target/release> <candidate/target/release>",
        )?;
        let main_dir =
            fs::canonicalize(main_arg).map_err(|e| format!("canonicalize baseline dir: {e}"))?;
        let pr_dir =
            fs::canonicalize(pr_arg).map_err(|e| format!("canonicalize candidate dir: {e}"))?;
        println!("PLATFORM {} {}", env::consts::OS, env::consts::ARCH);
        for condition in ["absent", "available", "crashed", "saturated"] {
            run_condition(condition, &main_dir, &pr_dir)?;
        }
        Ok(())
    }
}
