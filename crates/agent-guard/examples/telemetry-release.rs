//! Pure-Rust release collector isolation and boundary harness (replaces Python scripts).

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    match unix_harness::run_all() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("[telemetry-release FAIL] {err}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
mod unix_harness {
    use std::collections::{BTreeMap, BTreeSet};
    use std::env;
    use std::fs;
    use std::io::{self, BufRead, BufReader, Write};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::net::{UnixDatagram, UnixStream};
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::{self, Receiver};
    use std::thread;
    use std::time::{Duration, Instant};

    use agent_guard::crypto::sha256_hex;
    use agent_guard::json::JsonValue;

    const WATCHDOG: Duration = Duration::from_secs(10);
    static NEXT_WS: AtomicU64 = AtomicU64::new(0);

    struct TempWorkspace {
        base: PathBuf,
        repo: PathBuf,
        state: PathBuf,
    }

    impl TempWorkspace {
        fn create() -> Result<Self, String> {
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let root = fs::canonicalize(manifest_dir.join("../.."))
                .map_err(|e| format!("canonicalize workspace root: {e}"))?;
            let parent = root.join("target/test-workspaces");
            fs::create_dir_all(&parent)
                .map_err(|e| format!("mkdir '{}': {e}", parent.display()))?;
            let seq = NEXT_WS.fetch_add(1, Ordering::Relaxed);
            let base = parent.join(format!("o-{seq}"));
            if base.exists() {
                let _ = fs::remove_dir_all(&base);
            }
            let repo = base.join("r");
            let state = base.join("s");
            fs::create_dir_all(repo.join(".git")).map_err(|e| format!("mkdir repo/.git: {e}"))?;
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

    impl Drop for TempWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    struct ManagedProcess {
        label: String,
        child: Child,
        stdin: Option<ChildStdin>,
        lines: Receiver<io::Result<String>>,
    }

    impl ManagedProcess {
        fn spawn(
            args: &[&Path],
            extra_str_args: &[&str],
            ws: &TempWorkspace,
            ready: bool,
            fd_limit_32: bool,
        ) -> Result<Self, String> {
            let bin = args.first().ok_or("missing binary path")?;
            let mut cmd = if fd_limit_32 {
                let mut sh = Command::new("/bin/sh");
                sh.arg("-c")
                    .arg("ulimit -c 0 && ulimit -n 32 && exec \"$@\"")
                    .arg("sh")
                    .arg(bin);
                for s in extra_str_args {
                    sh.arg(s);
                }
                sh
            } else if extra_str_args.first() == Some(&"panic") {
                let mut sh = Command::new("/bin/sh");
                sh.arg("-c")
                    .arg("ulimit -c 0 && exec \"$@\"")
                    .arg("sh")
                    .arg(bin);
                for s in extra_str_args {
                    sh.arg(s);
                }
                sh
            } else {
                let mut c = Command::new(bin);
                for s in extra_str_args {
                    c.arg(s);
                }
                c
            };

            cmd.current_dir(&ws.repo)
                .env_clear()
                .envs(ws.clean_env())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());

            let label = format!("{} {}", bin.display(), extra_str_args.join(" "));
            let mut child = cmd.spawn().map_err(|e| format!("spawn '{label}': {e}"))?;
            let stdin = child.stdin.take();
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| format!("missing stdout on '{label}'"))?;
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });

            let proc_guard = Self {
                label,
                child,
                stdin,
                lines: rx,
            };
            if ready {
                let banner = proc_guard.read_line()?;
                if banner != "READY" {
                    return Err(format!(
                        "expected READY from '{}', got '{banner}'",
                        proc_guard.label
                    ));
                }
            }
            Ok(proc_guard)
        }

        fn read_line(&self) -> Result<String, String> {
            match self.lines.recv_timeout(WATCHDOG) {
                Ok(Ok(s)) => Ok(s.trim().to_string()),
                Ok(Err(e)) => Err(format!("stdout read error on '{}': {e}", self.label)),
                Err(_) => Err(format!(
                    "subprocess response exceeded watchdog or unexpected EOF from '{}'",
                    self.label
                )),
            }
        }

        fn ask(&mut self, request: &str) -> Result<String, String> {
            let stdin = self
                .stdin
                .as_mut()
                .ok_or_else(|| format!("stdin closed on '{}'", self.label))?;
            stdin
                .write_all(format!("{request}\n").as_bytes())
                .and_then(|()| stdin.flush())
                .map_err(|e| format!("stdin write on '{}': {e}", self.label))?;
            self.read_line()
        }

        fn write_bytes(&mut self, data: &[u8]) -> Result<(), String> {
            let stdin = self
                .stdin
                .as_mut()
                .ok_or_else(|| format!("stdin closed on '{}'", self.label))?;
            stdin
                .write_all(data)
                .and_then(|()| stdin.flush())
                .map_err(|e| format!("stdin write bytes on '{}': {e}", self.label))
        }

        fn close_stdin(&mut self) {
            self.stdin = None;
        }

        fn poll(&mut self) -> Result<Option<ExitStatus>, String> {
            self.child
                .try_wait()
                .map_err(|e| format!("try_wait on '{}': {e}", self.label))
        }

        fn kill_and_wait(&mut self) -> Result<ExitStatus, String> {
            let _ = self.child.kill();
            self.wait_watchdog()
        }

        fn wait_watchdog(&mut self) -> Result<ExitStatus, String> {
            let deadline = Instant::now() + WATCHDOG;
            loop {
                if let Some(status) = self.poll()? {
                    return Ok(status);
                }
                if Instant::now() >= deadline {
                    let _ = self.child.kill();
                    return Err(format!("wait watchdog expired for '{}'", self.label));
                }
                thread::sleep(Duration::from_millis(5));
            }
        }

        fn pid(&self) -> u32 {
            self.child.id()
        }
    }

    impl Drop for ManagedProcess {
        fn drop(&mut self) {
            self.stdin = None;
            if let Ok(None) = self.child.try_wait() {
                let _ = self.child.kill();
            }
            let _ = self.child.wait();
        }
    }

    fn until<T>(label: &str, mut check: impl FnMut() -> Option<T>) -> Result<T, String> {
        let deadline = Instant::now() + WATCHDOG;
        while Instant::now() < deadline {
            if let Some(val) = check() {
                return Ok(val);
            }
            thread::yield_now();
            thread::sleep(Duration::from_millis(2));
        }
        Err(format!("watchdog expired while awaiting {label}"))
    }

    fn signal_pid(pid: u64, sig_arg: &str) -> Result<bool, String> {
        let status = Command::new("/bin/kill")
            .arg(sig_arg)
            .arg(pid.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("/bin/kill {sig_arg} {pid}: {e}"))?;
        Ok(status.success())
    }

    fn pid_alive(pid: u64) -> bool {
        signal_pid(pid, "-0").unwrap_or(false)
    }

    fn stop_reading(pid: u32) -> Result<(), String> {
        if !signal_pid(u64::from(pid), "-STOP")? {
            return Err(format!("failed to SIGSTOP pid {pid}"));
        }
        Ok(())
    }

    fn health(state: &Path) -> JsonValue {
        let path = state.join("observations/health");
        fs::read_to_string(path)
            .ok()
            .and_then(|s| JsonValue::parse(&s).ok())
            .unwrap_or(JsonValue::Null)
    }

    fn observed(state: &Path) -> Vec<JsonValue> {
        let path = state.join("audit.jsonl");
        let Ok(data) = fs::read_to_string(path) else {
            return Vec::new();
        };
        let mut parts: Vec<&str> = data.split('\n').collect();
        if !parts.is_empty() {
            parts.pop();
        }
        parts
            .into_iter()
            .filter(|row| !row.is_empty())
            .filter_map(|row| JsonValue::parse(row).ok())
            .collect()
    }

    fn submitted(producer: &mut ManagedProcess) -> Result<Option<String>, String> {
        let result = producer.ask("observe")?;
        Ok(result.strip_prefix("ACCEPTED ").map(str::to_string))
    }

    fn assert_authority(producer: &mut ManagedProcess) -> Result<(), String> {
        let reply = producer.ask("guard")?;
        if reply != "GUARD true true true true" {
            return Err(format!("unexpected guard authority reply: '{reply}'"));
        }
        if producer.poll()?.is_some() {
            return Err("producer exited unexpectedly".to_string());
        }
        Ok(())
    }

    fn exercise(mode: &str, bins: &Path) -> Result<(), String> {
        let cli = bins.join("dotagent");
        let probe = bins.join("examples/observation-probe");
        let ws = TempWorkspace::create()?;
        let mut producer = ManagedProcess::spawn(&[&probe], &["producer"], &ws, true, false)?;

        if mode == "absent" {
            let reply = producer.ask("observe")?;
            if reply != "Unavailable" {
                return Err(format!("absent expected Unavailable, got '{reply}'"));
            }
            assert_authority(&mut producer)?;
            if ws.state.join("observations").exists() {
                return Err("observations dir should not exist in absent mode".to_string());
            }
            return Ok(());
        }

        if mode == "permission" {
            let file = ws.state.join("write-denied");
            fs::write(&file, b"").map_err(|e| format!("write-denied: {e}"))?;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o400))
                .map_err(|e| format!("chmod 0400 write-denied: {e}"))?;
        }

        let injected = matches!(
            mode,
            "panic" | "exit-handoff" | "enospc" | "permission" | "blocked-store" | "fd-exhausted"
        );
        let mut receiver = if injected {
            ManagedProcess::spawn(&[&probe], &[mode], &ws, true, mode == "fd-exhausted")?
        } else {
            ManagedProcess::spawn(
                &[&cli],
                &["collect-observations", "--owned"],
                &ws,
                true,
                false,
            )?
        };

        let mut replacement_receiver: Option<ManagedProcess> = None;

        match mode {
            "panic" | "exit-handoff" => {
                let accepted = submitted(&mut producer)?
                    .ok_or_else(|| format!("{mode}: expected ACCEPTED event id"))?;
                let status = receiver.wait_watchdog()?;
                if mode == "panic" {
                    if status.signal() != Some(6) {
                        return Err(format!(
                            "panic expected SIGABRT (signal 6), got code={:?} signal={:?}",
                            status.code(),
                            status.signal()
                        ));
                    }
                } else if status.code() != Some(73) {
                    return Err(format!(
                        "exit-handoff expected exit 73, got {:?}",
                        status.code()
                    ));
                }
                let obs = producer.ask("observe")?;
                if obs != "Unavailable" {
                    return Err(format!("after {mode} expected Unavailable, got '{obs}'"));
                }
                if observed(&ws.state).iter().any(|r| {
                    r.get("event_id").and_then(JsonValue::as_str) == Some(accepted.as_str())
                }) {
                    return Err(format!("{mode}: aborted event persisted unexpectedly"));
                }
            }
            "kill" | "stale" | "restart" => {
                let previous = submitted(&mut producer)?
                    .ok_or_else(|| format!("{mode}: expected first ACCEPTED event"))?;
                until("first event persisted", || {
                    observed(&ws.state)
                        .iter()
                        .any(|r| {
                            r.get("event_id").and_then(JsonValue::as_str) == Some(previous.as_str())
                        })
                        .then_some(())
                })?;
                let _ = receiver.kill_and_wait()?;
                let sock_meta = fs::symlink_metadata(ws.state.join("observations/in"))
                    .map_err(|e| format!("stat observations/in: {e}"))?;
                let _ = sock_meta;
                if mode == "stale" {
                    producer = ManagedProcess::spawn(&[&probe], &["producer"], &ws, true, false)?;
                }
                let unavail = producer.ask("observe")?;
                if unavail != "Unavailable" {
                    return Err(format!("{mode}: expected Unavailable, got '{unavail}'"));
                }
                if mode == "restart" {
                    replacement_receiver = Some(ManagedProcess::spawn(
                        &[&cli],
                        &["collect-observations", "--owned"],
                        &ws,
                        true,
                        false,
                    )?);
                    let second = until("second event submitted", || {
                        submitted(&mut producer).ok().flatten()
                    })?;
                    if second == previous {
                        return Err("restart: second event id matched previous".to_string());
                    }
                    until("second event persisted", || {
                        observed(&ws.state)
                            .iter()
                            .any(|r| {
                                r.get("event_id").and_then(JsonValue::as_str)
                                    == Some(second.as_str())
                            })
                            .then_some(())
                    })?;
                    let rows = observed(&ws.state);
                    let prev_cnt = rows
                        .iter()
                        .filter(|r| {
                            r.get("event_id").and_then(JsonValue::as_str) == Some(previous.as_str())
                        })
                        .count();
                    let sec_cnt = rows
                        .iter()
                        .filter(|r| {
                            r.get("event_id").and_then(JsonValue::as_str) == Some(second.as_str())
                        })
                        .count();
                    if prev_cnt != 1 || sec_cnt != 1 {
                        return Err(format!(
                            "restart counts expected 1/1, got {prev_cnt}/{sec_cnt}"
                        ));
                    }
                }
            }
            "permission" | "enospc" => {
                let accepted = submitted(&mut producer)?
                    .ok_or_else(|| format!("{mode}: expected ACCEPTED"))?;
                until("audit_queue.failed > 0", || {
                    health(&ws.state)
                        .get("audit_queue")
                        .and_then(|q| q.get("failed"))
                        .and_then(JsonValue::as_u64)
                        .filter(|&n| n > 0)
                })?;
                let h = health(&ws.state);
                let persisted = h
                    .get("audit_queue")
                    .and_then(|q| q.get("persisted"))
                    .and_then(JsonValue::as_u64);
                if persisted != Some(0) {
                    return Err(format!("{mode}: expected persisted=0, got {persisted:?}"));
                }
                let counter = if mode == "enospc" {
                    "storage_full"
                } else {
                    "storage_permission_denied"
                };
                if h.get(counter).and_then(JsonValue::as_u64).unwrap_or(0) < 1 {
                    return Err(format!("{mode}: expected {counter} >= 1"));
                }
                if observed(&ws.state).iter().any(|r| {
                    r.get("event_id").and_then(JsonValue::as_str) == Some(accepted.as_str())
                }) {
                    return Err(format!("{mode}: failed event persisted unexpectedly"));
                }
            }
            "fd-exhausted" => {
                let exh = receiver.read_line()?;
                if exh != "EXHAUSTED" {
                    return Err(format!("expected EXHAUSTED, got '{exh}'"));
                }
                if submitted(&mut producer)?.is_none() {
                    return Err("fd-exhausted: expected ACCEPTED".to_string());
                }
                let store_err = receiver.read_line()?;
                if !store_err.starts_with("STORE_ERROR ") {
                    return Err(format!("expected STORE_ERROR, got '{store_err}'"));
                }
            }
            "stopped" => {
                stop_reading(receiver.pid())?;
                until("Full backpressure", || {
                    (producer.ask("observe").ok().as_deref() == Some("Full")).then_some(())
                })?;
            }
            "blocked-store" => {
                if submitted(&mut producer)?.is_none() {
                    return Err("blocked-store: expected ACCEPTED".to_string());
                }
                let stalled = receiver.read_line()?;
                if stalled != "STALLED" {
                    return Err(format!("expected STALLED, got '{stalled}'"));
                }
                until("audit_queue.full > 0", || {
                    for _ in 0..16 {
                        let _ = producer.ask("observe");
                    }
                    health(&ws.state)
                        .get("audit_queue")
                        .and_then(|q| q.get("full"))
                        .and_then(JsonValue::as_u64)
                        .filter(|&n| n > 0)
                })?;
                if health(&ws.state)
                    .get("audit_queue")
                    .and_then(|q| q.get("persisted"))
                    .and_then(JsonValue::as_u64)
                    != Some(0)
                {
                    return Err("blocked-store: expected persisted=0 while stalled".to_string());
                }
            }
            "healthy" => {
                let event = submitted(&mut producer)?.ok_or("healthy: expected ACCEPTED")?;
                until("healthy event persisted", || {
                    observed(&ws.state)
                        .iter()
                        .any(|r| {
                            r.get("event_id").and_then(JsonValue::as_str) == Some(event.as_str())
                        })
                        .then_some(())
                })?;
            }
            other => return Err(format!("unknown mode '{other}'")),
        }

        assert_authority(&mut producer)?;
        let rows = observed(&ws.state);
        let ids: Vec<&str> = rows
            .iter()
            .filter_map(|r| r.get("event_id").and_then(JsonValue::as_str))
            .collect();
        let unique: BTreeSet<&str> = ids.iter().copied().collect();
        if ids.len() != unique.len() {
            return Err("duplicate event_ids persisted".to_string());
        }

        if mode == "blocked-store" {
            receiver.write_bytes(b"x")?;
            until("blocked-store persisted > 0", || {
                health(&ws.state)
                    .get("audit_queue")
                    .and_then(|q| q.get("persisted"))
                    .and_then(JsonValue::as_u64)
                    .filter(|&n| n > 0)
            })?;
        }
        if mode == "healthy" {
            receiver.close_stdin();
            let status = receiver.wait_watchdog()?;
            if !status.success() {
                return Err(format!("healthy receiver exit: {status:?}"));
            }
            if health(&ws.state).get("phase").and_then(JsonValue::as_str) != Some("closing") {
                return Err("healthy receiver did not record closing phase".to_string());
            }
            if ws.state.join("observations/in").exists() {
                return Err("healthy receiver left observations/in behind".to_string());
            }
        }

        drop(replacement_receiver);
        drop(receiver);
        drop(producer);
        Ok(())
    }

    fn daemon_rpc(address: &Path, repo: &Path, payload: &str) -> Result<JsonValue, String> {
        let req = JsonValue::Object(vec![
            ("op".to_string(), JsonValue::Str("eval_hook".to_string())),
            ("phase".to_string(), JsonValue::Str("post-tool".to_string())),
            (
                "repo_root".to_string(),
                JsonValue::Str(repo.to_string_lossy().into_owned()),
            ),
            (
                "cwd".to_string(),
                JsonValue::Str(repo.to_string_lossy().into_owned()),
            ),
            ("payload".to_string(), JsonValue::Str(payload.to_string())),
        ]);
        let mut stream = UnixStream::connect(address)
            .map_err(|e| format!("connect '{}': {e}", address.display()))?;
        stream
            .set_read_timeout(Some(WATCHDOG))
            .map_err(|e| format!("set_read_timeout: {e}"))?;
        stream
            .set_write_timeout(Some(WATCHDOG))
            .map_err(|e| format!("set_write_timeout: {e}"))?;
        stream
            .write_all(format!("{}\n", req.to_json_string()).as_bytes())
            .map_err(|e| format!("write daemon rpc: {e}"))?;
        let mut line = String::new();
        BufReader::new(stream)
            .read_line(&mut line)
            .map_err(|e| format!("read daemon rpc: {e}"))?;
        JsonValue::parse(&line).map_err(|e| format!("parse daemon rpc reply: {e}"))
    }

    fn shipped_host(bins: &Path) -> Result<(), String> {
        let cli = bins.join("dotagent");
        let ws = TempWorkspace::create()?;
        let replacement_pid = {
            let mut host = ManagedProcess::spawn(
                &[&cli],
                &["hook-daemon", "--idle-secs", "30"],
                &ws,
                false,
                false,
            )?;
            let address = ws.state.join("daemon/hook.sock");
            until("daemon/hook.sock", || {
                fs::symlink_metadata(&address).ok().map(|_| ())
            })?;
            until("observations/route", || {
                ws.state.join("observations/route").is_file().then_some(())
            })?;

            let allow = r#"{"tool_name":"Read","tool_response":"unique_private_fixture_output"}"#;
            let deny = format!(
                r#"{{"tool_name":"Task","tool_response":"{}"}}"#,
                "ordinary detail ".repeat(100)
            );
            if daemon_rpc(&address, &ws.repo, allow)?
                .get("allow")
                .and_then(JsonValue::as_bool)
                != Some(true)
            {
                return Err("expected allow=true from hook-daemon".to_string());
            }
            if daemon_rpc(&address, &ws.repo, &deny)?
                .get("code")
                .and_then(JsonValue::as_str)
                != Some("SUBAGENT_RETURN_BUDGET_EXCEEDED")
            {
                return Err("expected SUBAGENT_RETURN_BUDGET_EXCEEDED from hook-daemon".to_string());
            }
            until("USAGE_AND_DISPOSITION observed", || {
                observed(&ws.state)
                    .iter()
                    .any(|r| {
                        r.get("event_type").and_then(JsonValue::as_str)
                            == Some("USAGE_AND_DISPOSITION")
                    })
                    .then_some(())
            })?;
            let raw_audit = fs::read_to_string(ws.state.join("audit.jsonl"))
                .map_err(|e| format!("read audit.jsonl: {e}"))?;
            if raw_audit.contains("unique_private_fixture_output") {
                return Err("private tool_response leaked into audit.jsonl".to_string());
            }
            if host.poll()?.is_some() {
                return Err("hook-daemon exited prematurely".to_string());
            }

            let first_pid = until("collector_pid", || {
                health(&ws.state)
                    .get("collector_pid")
                    .and_then(JsonValue::as_u64)
            })?;
            if !signal_pid(first_pid, "-KILL")? {
                return Err(format!("failed to SIGKILL collector {first_pid}"));
            }
            let repl_pid = until("replacement collector_pid", || {
                health(&ws.state)
                    .get("collector_pid")
                    .and_then(JsonValue::as_u64)
                    .filter(|&pid| pid != 0 && pid != first_pid)
            })?;
            if daemon_rpc(&address, &ws.repo, allow)?
                .get("allow")
                .and_then(JsonValue::as_bool)
                != Some(true)
            {
                return Err("expected allow=true after collector replacement".to_string());
            }
            if daemon_rpc(&address, &ws.repo, &deny)?
                .get("code")
                .and_then(JsonValue::as_str)
                != Some("SUBAGENT_RETURN_BUDGET_EXCEEDED")
            {
                return Err("expected deny code after collector replacement".to_string());
            }
            if host.poll()?.is_some() {
                return Err("hook-daemon exited after collector replacement".to_string());
            }
            let _ = host.kill_and_wait()?;
            repl_pid
        };

        until("supervised replacement collector closed cleanly", || {
            (!pid_alive(replacement_pid)
                && health(&ws.state).get("phase").and_then(JsonValue::as_str) == Some("closing")
                && !ws.state.join("observations/in").exists()
                && !ws.state.join("observations/route").exists())
            .then_some(())
        })?;
        Ok(())
    }

    fn boundaries(bins: &Path) -> Result<(), String> {
        let cli = bins.join("dotagent");
        let probe = bins.join("examples/observation-probe");
        let ws = TempWorkspace::create()?;
        let mut collector = ManagedProcess::spawn(
            &[&cli],
            &["collect-observations", "--owned"],
            &ws,
            true,
            false,
        )?;
        let endpoint = ws.state.join("observations/in");
        let directory = ws.state.join("observations");

        let dir_mode = fs::metadata(&directory)
            .map_err(|e| format!("stat observations dir: {e}"))?
            .permissions()
            .mode()
            & 0o777;
        let in_mode = fs::symlink_metadata(&endpoint)
            .map_err(|e| format!("stat observations/in: {e}"))?
            .permissions()
            .mode()
            & 0o777;
        let route_mode = fs::symlink_metadata(directory.join("route"))
            .map_err(|e| format!("stat observations/route: {e}"))?
            .permissions()
            .mode()
            & 0o777;
        if dir_mode != 0o700 || in_mode != 0o600 || route_mode != 0o600 {
            return Err(format!(
                "unexpected permissions dir={dir_mode:o} in={in_mode:o} route={route_mode:o}"
            ));
        }

        {
            let client = UnixDatagram::unbound().map_err(|e| format!("unbound dgram: {e}"))?;
            client
                .connect(&endpoint)
                .map_err(|e| format!("connect dgram: {e}"))?;
            let mut bad3 = vec![b'D', b'O', b'B', b'S', 0x02];
            bad3.extend_from_slice(&[0u8; 100]);
            let bad4 = vec![0u8; 256];
            for frame in [&[][..], &b"DOBS"[..], &bad3[..], &bad4[..]] {
                client
                    .send(frame)
                    .map_err(|e| format!("send malformed frame: {e}"))?;
            }
        }
        until("audit_queue.invalid >= 4", || {
            health(&ws.state)
                .get("audit_queue")
                .and_then(|q| q.get("invalid"))
                .and_then(JsonValue::as_u64)
                .filter(|&n| n >= 4)
        })?;
        if observed(&ws.state)
            .iter()
            .any(|r| r.get("event_type").and_then(JsonValue::as_str) != Some("CAPTURE_HEALTH"))
        {
            return Err("malformed frames produced unexpected audit record".to_string());
        }

        let original = directory.join("original");
        fs::rename(&endpoint, &original).map_err(|e| format!("rename in->original: {e}"))?;
        {
            let substitute =
                UnixDatagram::bind(&endpoint).map_err(|e| format!("bind substitute: {e}"))?;
            substitute
                .set_nonblocking(true)
                .map_err(|e| format!("set_nonblocking substitute: {e}"))?;
            fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("chmod substitute: {e}"))?;
            {
                let mut producer =
                    ManagedProcess::spawn(&[&probe], &["producer"], &ws, true, false)?;
                let obs = producer.ask("observe")?;
                if obs != "Transport" {
                    return Err(format!("substitute expected Transport, got '{obs}'"));
                }
                assert_authority(&mut producer)?;
            }
            let mut scratch = [0u8; 64];
            if !matches!(
                substitute.recv(&mut scratch),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock
            ) {
                return Err("substitute socket unexpectedly received traffic".to_string());
            }
        }
        fs::remove_file(&endpoint).map_err(|e| format!("unlink substitute: {e}"))?;
        symlink("original", &endpoint).map_err(|e| format!("symlink original: {e}"))?;
        {
            let mut producer = ManagedProcess::spawn(&[&probe], &["producer"], &ws, true, false)?;
            let obs = producer.ask("observe")?;
            if obs != "Transport" {
                return Err(format!("symlink expected Transport, got '{obs}'"));
            }
        }
        fs::remove_file(&endpoint).map_err(|e| format!("unlink symlink: {e}"))?;
        fs::rename(&original, &endpoint).map_err(|e| format!("restore original->in: {e}"))?;

        fs::set_permissions(directory.join("route"), fs::Permissions::from_mode(0o644))
            .map_err(|e| format!("chmod 0644 route: {e}"))?;
        {
            let mut producer = ManagedProcess::spawn(&[&probe], &["producer"], &ws, true, false)?;
            let obs = producer.ask("observe")?;
            if obs != "Transport" {
                return Err(format!("0644 route expected Transport, got '{obs}'"));
            }
        }
        fs::set_permissions(directory.join("route"), fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("restore 0600 route: {e}"))?;

        let repo_str = ws.repo.to_str().ok_or("non-utf8 repo path")?;
        let mut expected = BTreeMap::new();
        for (sid, size) in [("session-first", 41u64), ("session-second", 53u64)] {
            let payload = format!(
                r#"{{"session_id":"{sid}","tool_name":"Read","tool_response":"{}"}}"#,
                "x".repeat(size as usize)
            );
            let mut child = Command::new(&cli)
                .arg("post-tool")
                .current_dir(&ws.repo)
                .env_clear()
                .envs(ws.clean_env())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| format!("spawn post-tool: {e}"))?;
            if let Some(mut sin) = child.stdin.take() {
                sin.write_all(payload.as_bytes())
                    .map_err(|e| format!("write post-tool stdin: {e}"))?;
            }
            let out = child
                .wait_with_output()
                .map_err(|e| format!("wait post-tool: {e}"))?;
            if !out.status.success() {
                return Err(format!("post-tool failed: {:?}", out.status));
            }
            let framed = format!("v2:{}:{repo_str}:{}:{sid}", repo_str.len(), sid.len());
            expected.insert(sha256_hex(framed.as_bytes()), size);
        }

        until("session correlation observed", || {
            let mut actual = BTreeMap::new();
            for row in observed(&ws.state) {
                if row.get("event_type").and_then(JsonValue::as_str)
                    == Some("USAGE_AND_DISPOSITION")
                    && let Some(sid) = row
                        .get("work")
                        .and_then(|w| w.get("session_id"))
                        .and_then(JsonValue::as_str)
                    && expected.contains_key(sid)
                    && let Some(req_bytes) = row
                        .get("payload")
                        .and_then(|p| p.get("requested_bytes"))
                        .and_then(JsonValue::as_u64)
                {
                    actual.insert(sid.to_string(), req_bytes);
                }
            }
            (actual == expected).then_some(())
        })?;

        if collector.poll()?.is_some() {
            return Err("collector exited unexpectedly during boundaries".to_string());
        }
        collector.close_stdin();
        let status = collector.wait_watchdog()?;
        if !status.success() {
            return Err(format!("boundaries collector exit: {status:?}"));
        }
        Ok(())
    }

    fn supervised_deadlock_and_restart_cap(bins: &Path) -> Result<(), String> {
        let cli = bins.join("dotagent");
        let probe = bins.join("examples/observation-probe");

        // 1. Supervised deadlocked (`SIGSTOP`ped) collector MUST be killed & reaped on graceful HostTelemetry::drop!
        {
            let ws = TempWorkspace::create()?;
            let mut host = ManagedProcess::spawn(
                &[&cli],
                &["hook-daemon", "--idle-secs", "1"],
                &ws,
                false,
                false,
            )?;
            let address = ws.state.join("daemon/hook.sock");
            until("daemon/hook.sock (deadlock reap)", || {
                fs::symlink_metadata(&address).ok().map(|_| ())
            })?;
            let deadlocked_pid = until("collector_pid (deadlock reap)", || {
                health(&ws.state)
                    .get("collector_pid")
                    .and_then(JsonValue::as_u64)
                    .filter(|&pid| pid != 0)
            })?;
            if !signal_pid(deadlocked_pid, "-STOP")? {
                return Err(format!("failed to SIGSTOP collector {deadlocked_pid}"));
            }
            let exit_status = host.wait_watchdog()?;
            if !exit_status.success() {
                return Err(format!(
                    "hook-daemon idle exit failed while collector SIGSTOPped: {exit_status:?}"
                ));
            }
            until("SIGSTOPped collector killed and reaped", || {
                (!pid_alive(deadlocked_pid)).then_some(())
            })?;
        }

        // 1b. If BOTH `supervise-observations` AND `collect-observations` are `SIGSTOP`ped,
        //     `HostTelemetry::drop` kills the entire supervisor process group so neither is orphaned!
        {
            let ws = TempWorkspace::create()?;
            let mut host = ManagedProcess::spawn(
                &[&cli],
                &["hook-daemon", "--idle-secs", "1"],
                &ws,
                false,
                false,
            )?;
            let address = ws.state.join("daemon/hook.sock");
            until("daemon/hook.sock (both stopped)", || {
                fs::symlink_metadata(&address).ok().map(|_| ())
            })?;
            let col_pid = until("collector_pid (both stopped)", || {
                health(&ws.state)
                    .get("collector_pid")
                    .and_then(JsonValue::as_u64)
                    .filter(|&pid| pid != 0)
            })?;
            let ps_out = Command::new("/bin/ps")
                .args(["-o", "ppid=", "-p", &col_pid.to_string()])
                .output()
                .map_err(|e| format!("ps ppid: {e}"))?;
            let sup_pid: u64 = String::from_utf8_lossy(&ps_out.stdout)
                .trim()
                .parse()
                .map_err(|e| format!("parse supervisor ppid: {e}"))?;
            if sup_pid > 1 && sup_pid != u64::from(host.pid()) {
                let _ = signal_pid(sup_pid, "-STOP")?;
            }
            let _ = signal_pid(col_pid, "-STOP")?;
            let exit_status = host.wait_watchdog()?;
            if !exit_status.success() {
                return Err(format!(
                    "hook-daemon idle exit failed while supervisor+collector SIGSTOPped: {exit_status:?}"
                ));
            }
            until(
                "SIGSTOPped supervisor and collector both terminated",
                || (!pid_alive(col_pid) && (sup_pid <= 1 || !pid_alive(sup_pid))).then_some(()),
            )?;
        }

        // 2. Deadlocked store worker (`deadlocked-owned`) exits within bounded finish window and cleans up socket/route!
        {
            let ws = TempWorkspace::create()?;
            let mut producer = ManagedProcess::spawn(&[&probe], &["producer"], &ws, true, false)?;
            let mut receiver =
                ManagedProcess::spawn(&[&probe], &["deadlocked-owned"], &ws, true, false)?;
            if submitted(&mut producer)?.is_none() {
                return Err("deadlocked-owned: expected ACCEPTED".to_string());
            }
            let line = receiver.read_line()?;
            if line != "DEADLOCKED" {
                return Err(format!("expected DEADLOCKED, got '{line}'"));
            }
            assert_authority(&mut producer)?;
            let close_start = Instant::now();
            receiver.close_stdin();
            let status = receiver.wait_watchdog()?;
            if !status.success() {
                return Err(format!("deadlocked-owned exit failed: {status:?}"));
            }
            if close_start.elapsed() > Duration::from_secs(3) {
                return Err(format!(
                    "deadlocked-owned took {:?} (> 3s budget)",
                    close_start.elapsed()
                ));
            }
            if ws.state.join("observations/in").exists()
                || ws.state.join("observations/route").exists()
            {
                return Err("deadlocked-owned left socket or route behind".to_string());
            }
        }

        // 3. Supervisor enforces 3-starts-per-60s restart cap without losing authoritative allow/deny!
        {
            let ws = TempWorkspace::create()?;
            let mut host = ManagedProcess::spawn(
                &[&cli],
                &["hook-daemon", "--idle-secs", "30"],
                &ws,
                false,
                false,
            )?;
            let address = ws.state.join("daemon/hook.sock");
            until("daemon/hook.sock (restart cap)", || {
                fs::symlink_metadata(&address).ok().map(|_| ())
            })?;
            let mut seen_pids = Vec::new();
            for round in 0..3 {
                let pid = until("collector_pid (restart round)", || {
                    health(&ws.state)
                        .get("collector_pid")
                        .and_then(JsonValue::as_u64)
                        .filter(|&p| p != 0 && !seen_pids.contains(&p))
                })?;
                seen_pids.push(pid);
                if !signal_pid(pid, "-KILL")? {
                    return Err(format!("failed to SIGKILL collector round {round}: {pid}"));
                }
                until("killed collector reaped", || {
                    (!pid_alive(pid)).then_some(())
                })?;
            }
            // After 3 starts within 60s, no 4th collector may be spawned immediately
            thread::sleep(Duration::from_millis(250));
            let latest_pid = health(&ws.state)
                .get("collector_pid")
                .and_then(JsonValue::as_u64)
                .unwrap_or(0);
            if latest_pid != 0 && !seen_pids.contains(&latest_pid) {
                return Err(format!(
                    "supervisor exceeded 3-starts-per-60s cap (unexpected 4th pid {latest_pid})"
                ));
            }
            let allow = r#"{"tool_name":"Read","tool_response":"ordinary fixture"}"#;
            let deny = format!(
                r#"{{"tool_name":"Task","tool_response":"{}"}}"#,
                "ordinary detail ".repeat(100)
            );
            if daemon_rpc(&address, &ws.repo, allow)?
                .get("allow")
                .and_then(JsonValue::as_bool)
                != Some(true)
            {
                return Err("expected allow=true when restart cap exhausted".to_string());
            }
            if daemon_rpc(&address, &ws.repo, &deny)?
                .get("code")
                .and_then(JsonValue::as_str)
                != Some("SUBAGENT_RETURN_BUDGET_EXCEEDED")
            {
                return Err("expected deny code when restart cap exhausted".to_string());
            }
            let _ = host.kill_and_wait()?;
        }

        // 4. Runtime `observations` directory-to-symlink swap NEVER writes or unlinks through symlink!
        {
            let ws = TempWorkspace::create()?;
            let mut collector = ManagedProcess::spawn(
                &[&cli],
                &["collect-observations", "--owned"],
                &ws,
                true,
                false,
            )?;
            let obs_dir = ws.state.join("observations");
            let moved_dir = ws.state.join("observations_moved");
            let victim_dir = ws.base.join("victim");
            fs::create_dir_all(&victim_dir).map_err(|e| format!("mkdir victim: {e}"))?;
            fs::write(victim_dir.join("route"), b"sentinel-route")
                .map_err(|e| format!("write victim/route: {e}"))?;
            fs::write(victim_dir.join("in"), b"sentinel-in")
                .map_err(|e| format!("write victim/in: {e}"))?;
            fs::rename(&obs_dir, &moved_dir).map_err(|e| format!("rename obs->moved: {e}"))?;
            symlink(&victim_dir, &obs_dir).map_err(|e| format!("symlink obs->victim: {e}"))?;
            collector.close_stdin();
            let status = collector.wait_watchdog()?;
            if !status.success() {
                return Err(format!("collector exit after dir swap failed: {status:?}"));
            }
            if fs::read(victim_dir.join("route")).ok().as_deref() != Some(b"sentinel-route")
                || fs::read(victim_dir.join("in")).ok().as_deref() != Some(b"sentinel-in")
                || victim_dir.join("health").exists()
            {
                return Err(
                    "Endpoint wrote or unlinked files through swapped observations symlink!"
                        .to_string(),
                );
            }
        }

        Ok(())
    }

    fn cold_cli_isolation(bins: &Path) -> Result<(), String> {
        let guard = bins.join("agent-guard");
        for cond in ["absent", "crashed", "saturated"] {
            let ws = TempWorkspace::create()?;
            fs::write(ws.repo.join("AGENTS.md"), "# AGENTS.md\n")
                .map_err(|e| format!("write AGENTS.md: {e}"))?;
            let mut col_opt = if cond != "absent" {
                Some(ManagedProcess::spawn(
                    &[&guard],
                    &["collect-observations", "--owned"],
                    &ws,
                    true,
                    false,
                )?)
            } else {
                None
            };
            if let Some(ref mut col) = col_opt {
                if cond == "crashed" {
                    let _ = col.kill_and_wait()?;
                } else if cond == "saturated" {
                    stop_reading(col.pid())?;
                    let sender =
                        UnixDatagram::unbound().map_err(|e| format!("unbound dgram: {e}"))?;
                    sender
                        .set_nonblocking(true)
                        .map_err(|e| format!("nonblock dgram: {e}"))?;
                    sender
                        .connect(ws.state.join("observations/in"))
                        .map_err(|e| format!("connect dgram: {e}"))?;
                    for _ in 0..16384 {
                        if matches!(sender.send(b"sat"), Err(ref e) if e.kind() == io::ErrorKind::WouldBlock)
                        {
                            break;
                        }
                    }
                }
            }

            let ws_json = JsonValue::Str(ws.repo.to_string_lossy().into_owned()).to_json_string();
            for i in 0..12 {
                // Cold `antigravity-hook PreToolUse` allow + deny
                let ag_allow = format!(
                    r#"{{"conversationId":"cold_ag_{cond}_{i}","workspacePaths":[{ws_json}],"toolCall":{{"name":"view_file","args":{{"AbsolutePath":"{}/plain.txt","StartLine":1,"EndLine":5}}}},"stepIdx":0}}"#,
                    ws.repo.display()
                );
                let start = Instant::now();
                let mut child = Command::new(&guard)
                    .args(["antigravity-hook", "PreToolUse"])
                    .current_dir(&ws.repo)
                    .env_clear()
                    .envs(ws.clean_env())
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|e| format!("spawn cold antigravity allow: {e}"))?;
                if let Some(mut sin) = child.stdin.take() {
                    sin.write_all(ag_allow.as_bytes())
                        .map_err(|e| format!("write ag allow: {e}"))?;
                }
                let out = child
                    .wait_with_output()
                    .map_err(|e| format!("wait ag allow: {e}"))?;
                if !out.status.success() {
                    return Err(format!("cold antigravity allow exit {:?}", out.status));
                }
                if start.elapsed() > Duration::from_millis(500) {
                    return Err(format!(
                        "cold antigravity-hook PreToolUse ({cond}) exceeded 500ms: {:?}",
                        start.elapsed()
                    ));
                }
                let stdout_s = String::from_utf8(out.stdout)
                    .map_err(|_| "non-utf8 stdout on antigravity allow".to_string())?;
                let parsed = JsonValue::parse(stdout_s.trim()).map_err(|e| {
                    format!("contaminated stdout on antigravity allow ('{stdout_s}'): {e}")
                })?;
                if parsed.get("decision").and_then(JsonValue::as_str) != Some("allow")
                    || stdout_s.lines().count() != 1
                {
                    return Err(format!("unexpected antigravity allow stdout: '{stdout_s}'"));
                }

                let ag_deny = format!(
                    r#"{{"conversationId":"cold_ag_d_{cond}_{i}","workspacePaths":[{ws_json}],"toolCall":{{"name":"view_file","args":{{"AbsolutePath":"{}/.env"}}}},"stepIdx":0}}"#,
                    ws.repo.display()
                );
                let mut d_child = Command::new(&guard)
                    .args(["antigravity-hook", "PreToolUse"])
                    .current_dir(&ws.repo)
                    .env_clear()
                    .envs(ws.clean_env())
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|e| format!("spawn cold antigravity deny: {e}"))?;
                if let Some(mut sin) = d_child.stdin.take() {
                    sin.write_all(ag_deny.as_bytes())
                        .map_err(|e| format!("write ag deny: {e}"))?;
                }
                let d_out = d_child
                    .wait_with_output()
                    .map_err(|e| format!("wait ag deny: {e}"))?;
                if !d_out.status.success() {
                    return Err(format!("cold antigravity deny exit {:?}", d_out.status));
                }
                let d_stdout = String::from_utf8(d_out.stdout)
                    .map_err(|_| "non-utf8 stdout on antigravity deny".to_string())?;
                let d_parsed = JsonValue::parse(d_stdout.trim()).map_err(|e| {
                    format!("contaminated stdout on antigravity deny ('{d_stdout}'): {e}")
                })?;
                if d_parsed.get("decision").and_then(JsonValue::as_str) != Some("deny")
                    || d_stdout.lines().count() != 1
                {
                    return Err(format!("unexpected antigravity deny stdout: '{d_stdout}'"));
                }

                if cond == "absent" && ws.state.join("observations").exists() {
                    return Err(
                        "cold antigravity-hook PreToolUse unexpectedly spawned observations collector!"
                            .to_string(),
                    );
                }
            }

            if let Some(mut col) = col_opt
                && cond == "saturated"
            {
                let _ = signal_pid(u64::from(col.pid()), "-CONT");
                let _ = col.kill_and_wait();
            }
        }
        Ok(())
    }

    pub fn run_all() -> Result<(), String> {
        let arg1 = env::args()
            .nth(1)
            .ok_or("usage: telemetry-release <target/release>")?;
        let binaries =
            fs::canonicalize(arg1).map_err(|e| format!("canonicalize binaries dir: {e}"))?;
        for scenario in [
            "healthy",
            "absent",
            "panic",
            "kill",
            "exit-handoff",
            "stale",
            "stopped",
            "blocked-store",
            "permission",
            "enospc",
            "fd-exhausted",
            "restart",
        ] {
            exercise(scenario, &binaries)?;
            println!("PASS {scenario}");
        }
        shipped_host(&binaries)?;
        println!("PASS production hook daemon and automatic collector");
        supervised_deadlock_and_restart_cap(&binaries)?;
        println!(
            "PASS supervised deadlock reap, restart cap, bounded worker finish, and symlink-swap defense"
        );
        cold_cli_isolation(&binaries)?;
        println!("PASS repeated cold CLI startup isolation and stdout purity");
        boundaries(&binaries)?;
        println!("PASS local endpoint authentication, protocol rejection and session correlation");
        Ok(())
    }
}
