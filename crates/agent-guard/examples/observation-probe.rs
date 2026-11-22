fn main() -> std::process::ExitCode {
    #[cfg(unix)]
    {
        agent_guard::telemetry::release_probe::run()
    }
    #[cfg(not(unix))]
    {
        std::process::ExitCode::FAILURE
    }
}
