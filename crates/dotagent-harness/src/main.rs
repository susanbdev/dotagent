#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use dotagent_harness::{
    HarnessConfig, ReportFormat, SuiteSelection, discover_workspace_root, list_cases,
    render_json_report, render_text_report, run_harness,
};

const USAGE: &str = "\
Usage: dotagent-harness [run|list] [options]\n\
\n\
Options:\n\
  --suite <all|scenarios|swarm|compiler|bootstrap|corpus>  Select suite (default: all)\n\
  --filter <substring>                                     Only run case IDs matching substring\n\
  --scenario-dir <path>                                    Custom TOML scenario file or directory\n\
  --workspace <path>                                       Dotagent repository root\n\
  --agent-guard-bin <path>                                 Explicit path to agent-guard binary\n\
  --compiler-bin <path>                                    Explicit path to dotagent-compiler binary\n\
  --swarm-tool-bin <path>                                  Explicit path to swarm-tool binary\n\
  --format <text|json>                                     Output format (default: text)\n\
  --list                                                   List discovered case IDs without running\n\
  -h, --help                                               Print this usage guide\n";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut cfg = HarnessConfig::for_workspace(discover_workspace_root());
    let mut format = ReportFormat::Text;
    let mut list_only = false;
    let mut custom_scenario_path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "run" => i += 1,
            "list" | "--list" => {
                list_only = true;
                i += 1;
            }
            "-h" | "--help" | "help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--suite" => {
                let Some(val) = args.get(i + 1) else {
                    eprintln!("[dotagent-harness] missing value for --suite");
                    return ExitCode::from(1);
                };
                match SuiteSelection::parse(val) {
                    Ok(s) => cfg.suite = s,
                    Err(e) => {
                        eprintln!("[dotagent-harness] {e}");
                        return ExitCode::from(1);
                    }
                }
                i += 2;
            }
            "--filter" => {
                let Some(val) = args.get(i + 1) else {
                    eprintln!("[dotagent-harness] missing value for --filter");
                    return ExitCode::from(1);
                };
                cfg.filter = Some(val.clone());
                i += 2;
            }
            "--scenario-dir" => {
                let Some(val) = args.get(i + 1) else {
                    eprintln!("[dotagent-harness] missing value for --scenario-dir");
                    return ExitCode::from(1);
                };
                custom_scenario_path = Some(PathBuf::from(val));
                i += 2;
            }
            "--workspace" => {
                let Some(val) = args.get(i + 1) else {
                    eprintln!("[dotagent-harness] missing value for --workspace");
                    return ExitCode::from(1);
                };
                let root = PathBuf::from(val);
                cfg.scenario_path = root.join("tests").join("scenarios");
                cfg.workspace_root = root;
                i += 2;
            }
            "--agent-guard-bin" => {
                let Some(val) = args.get(i + 1) else {
                    eprintln!("[dotagent-harness] missing value for --agent-guard-bin");
                    return ExitCode::from(1);
                };
                cfg.agent_guard_bin = Some(PathBuf::from(val));
                i += 2;
            }
            "--compiler-bin" => {
                let Some(val) = args.get(i + 1) else {
                    eprintln!("[dotagent-harness] missing value for --compiler-bin");
                    return ExitCode::from(1);
                };
                cfg.compiler_bin = Some(PathBuf::from(val));
                i += 2;
            }
            "--swarm-tool-bin" => {
                let Some(val) = args.get(i + 1) else {
                    eprintln!("[dotagent-harness] missing value for --swarm-tool-bin");
                    return ExitCode::from(1);
                };
                cfg.swarm_tool_bin = Some(PathBuf::from(val));
                i += 2;
            }
            "--format" => {
                let Some(val) = args.get(i + 1) else {
                    eprintln!("[dotagent-harness] missing value for --format");
                    return ExitCode::from(1);
                };
                match ReportFormat::parse(val) {
                    Ok(f) => format = f,
                    Err(e) => {
                        eprintln!("[dotagent-harness] {e}");
                        return ExitCode::from(1);
                    }
                }
                i += 2;
            }
            unknown => {
                eprintln!("[dotagent-harness] unrecognized argument '{unknown}'\n{USAGE}");
                return ExitCode::from(1);
            }
        }
    }

    if let Some(custom) = custom_scenario_path {
        cfg.scenario_path = custom;
    }

    if list_only {
        match list_cases(&cfg) {
            Ok(ids) => {
                for id in ids {
                    println!("{id}");
                }
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("[dotagent-harness ERROR] {e}");
                return ExitCode::from(2);
            }
        }
    }

    match run_harness(&cfg) {
        Ok(report) => {
            match format {
                ReportFormat::Text => print!("{}", render_text_report(&report)),
                ReportFormat::Json => println!("{}", render_json_report(&report)),
            }
            if report.all_passed() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Err(e) => {
            eprintln!("[dotagent-harness ERROR] {e}");
            ExitCode::from(2)
        }
    }
}
