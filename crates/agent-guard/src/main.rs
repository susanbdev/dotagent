#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    agent_guard::cli::run_cli_entrypoint()
}
