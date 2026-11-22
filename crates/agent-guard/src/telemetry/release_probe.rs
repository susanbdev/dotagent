//! Entry point for the separately built abort-profile integration fixture.

use std::io::{self, BufRead, Write};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU8, Ordering};

use super::capture::{Context, Producer, hook_decision};
use super::runtime;

static FAULT: AtomicU8 = AtomicU8::new(0);

#[allow(clippy::panic)]
pub(super) fn before_store(frame: &[u8]) -> io::Result<()> {
    match FAULT.load(Ordering::Relaxed) {
        1 => panic!("injected release collector panic"),
        2 => std::fs::OpenOptions::new()
            .write(true)
            .open(crate::traversal_ledger::observation_state_root_dir().join("write-denied"))?
            .write_all(frame),
        3 => {
            #[cfg(target_os = "linux")]
            {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open("/dev/full")?
                    .write_all(frame)
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(io::Error::from_raw_os_error(28))
            }
        }
        5 if FAULT.swap(0, Ordering::Relaxed) == 5 => {
            writeln!(io::stdout().lock(), "STALLED")?;
            let mut byte = [0];
            std::io::Read::read_exact(&mut io::stdin(), &mut byte)
        }
        7 => {
            writeln!(io::stdout().lock(), "DEADLOCKED")?;
            std::thread::sleep(std::time::Duration::from_secs(60));
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(super) fn exhaust_fds() -> Vec<std::fs::File> {
    let mut held = Vec::new();
    if FAULT.load(Ordering::Relaxed) == 6 {
        for _ in 0..64 {
            match std::fs::File::open("/dev/null") {
                Ok(file) => held.push(file),
                Err(e) if e.raw_os_error() == Some(24) => {
                    let _ = writeln!(io::stdout().lock(), "EXHAUSTED");
                    break;
                }
                Err(_) => break,
            }
        }
    }
    held
}

pub(super) fn store_error(error: &super::store::CaptureError) {
    if FAULT.load(Ordering::Relaxed) == 6 {
        let _ = writeln!(io::stdout().lock(), "STORE_ERROR {error:?}");
    }
}

pub(super) fn after_receive() {
    if FAULT.load(Ordering::Relaxed) == 4 {
        std::process::exit(73);
    }
}

fn producer() -> io::Result<()> {
    use crate::traversal_ledger::{SessionLedger, session_ledger_path};
    let repo = std::env::current_dir()?;
    writeln!(io::stdout().lock(), "READY")?;
    for line in io::stdin().lock().lines() {
        let answer = match line?.as_str() {
            "observe" => {
                let payload = hook_decision("post_tool_hook", "allow", "PROBE", "observed", None);
                match runtime::try_event(Producer::Guard, &Context::default(), payload) {
                    Ok(id) => format!("ACCEPTED {}", id.event_id()),
                    Err(reason) => format!("{reason:?}"),
                }
            }
            "guard" => {
                let allow = crate::handle_post_tool_hook(
                    r#"{"tool_name":"Read","tool_response":"ordinary fixture output"}"#,
                    &repo,
                );
                let payload = format!(
                    r#"{{"tool_name":"Task","tool_response":"{}"}}"#,
                    "ordinary detail ".repeat(100)
                );
                let deny = crate::handle_post_tool_hook(&payload, &repo);
                let mut ledger = SessionLedger::new(&repo, "probe-halt");
                ledger.trip_circuit_breaker("fixture".to_owned());
                ledger.save(&repo).map_err(io::Error::other)?;
                let persisted = SessionLedger::load_or_create(&repo, "probe-halt").halted;
                std::fs::create_dir_all(session_ledger_path(&repo, "probe-failed-write"))?;
                let failed =
                    crate::handle_user_prompt_hook(r#"{"session_id":"probe-failed-write"}"#, &repo);
                let decision = matches!(
                    deny,
                    crate::Decision::Deny {
                        code: "SUBAGENT_RETURN_BUDGET_EXCEEDED",
                        ..
                    }
                );
                let failure = matches!(
                    failed,
                    crate::Decision::Deny {
                        code: "STATE_WRITE_ERROR",
                        ..
                    }
                );
                format!(
                    "GUARD {} {decision} {persisted} {failure}",
                    allow.is_allow()
                )
            }
            "quit" => break,
            _ => return Err(io::Error::from(io::ErrorKind::InvalidInput)),
        };
        writeln!(io::stdout().lock(), "{answer}")?;
    }
    Ok(())
}

pub fn run() -> ExitCode {
    if !cfg!(panic = "abort") {
        return ExitCode::FAILURE;
    }
    let mode = std::env::args().nth(1).unwrap_or_default();
    let result = if mode == "producer" {
        producer()
    } else {
        let (fault, owned) = match mode.as_str() {
            "panic" => (1, false),
            "permission" => (2, false),
            "enospc" => (3, false),
            "exit-handoff" => (4, false),
            "blocked-store" => (5, false),
            "fd-exhausted" => (6, false),
            "deadlocked-owned" => (7, true),
            _ => return ExitCode::FAILURE,
        };
        FAULT.store(fault, Ordering::Relaxed);
        super::transport::collect(owned)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("release probe: {e}");
            ExitCode::FAILURE
        }
    }
}
