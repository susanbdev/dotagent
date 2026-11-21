#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    agent_guard::shell_wrapper::run_shell_wrapper_entrypoint()
}
