//! Isolated sandbox test suite for `scripts/activate-local.sh`.
//!
//! Verifies:
//! 1. Full end-to-end bootstrap: environment scrubbing, 0555 binary installation,
//!    `dotagent-compiler verify`, all 19 global Git hardening keys (while preserving
//!    pre-existing `user.name` / `user.email`), `~/.gemini` wiring, `0444` read-only
//!    target workspace control-plane deployment, and `agent-guard audit-repo`.
//! 2. Pre-build RCE trap hard-denials (`exit 2` before Cargo executes):
//!    - `.cargo/config.toml` `rustc-wrapper`
//!    - symlinked root `AGENTS.md`
//!    - `.gitattributes` `filter=` driver
//!    - `.yarnrc.yml` `yarnPath` override

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::CaseResult;
use crate::WorkspaceBinaries;
use crate::sandbox::{copy_dir_filtered_bounded, reset_and_remove_dir};

pub fn bootstrap_case_ids() -> Vec<&'static str> {
    vec![
        "bootstrap::end_to_end_activate_local_env_scrub_git19_and_0444_plane",
        "bootstrap::rejects_cargo_config_rustc_wrapper_before_build",
        "bootstrap::rejects_symlinked_root_agents_md_before_build",
        "bootstrap::rejects_gitattributes_filter_driver_before_build",
        "bootstrap::rejects_yarnrc_yarnpath_override_before_build",
        "bootstrap::rejects_symlinked_target_workspace_harness_path",
    ]
}

pub fn run_bootstrap_suite(
    workspace_root: &Path,
    bins: &WorkspaceBinaries,
    filter: Option<&str>,
) -> Vec<CaseResult> {
    type BootFn = fn(&Path, &WorkspaceBinaries) -> Result<String, String>;
    let cases: [(&str, BootFn); 6] = [
        (
            "bootstrap::end_to_end_activate_local_env_scrub_git19_and_0444_plane",
            case_happy_path_bootstrap,
        ),
        (
            "bootstrap::rejects_cargo_config_rustc_wrapper_before_build",
            case_trap_cargo_wrapper,
        ),
        (
            "bootstrap::rejects_symlinked_root_agents_md_before_build",
            case_trap_symlink_agents,
        ),
        (
            "bootstrap::rejects_gitattributes_filter_driver_before_build",
            case_trap_gitattributes_filter,
        ),
        (
            "bootstrap::rejects_yarnrc_yarnpath_override_before_build",
            case_trap_yarnpath,
        ),
        (
            "bootstrap::rejects_symlinked_target_workspace_harness_path",
            case_trap_symlink_target_workspace,
        ),
    ];

    let mut results = Vec::new();
    for (id, func) in cases {
        if let Some(f) = filter
            && !id.contains(f)
        {
            continue;
        }
        let started = Instant::now();
        match func(workspace_root, bins) {
            Ok(detail) => results.push(CaseResult::pass(
                id.to_string(),
                "bootstrap",
                started.elapsed().as_millis() as u64,
                detail,
            )),
            Err(err) => results.push(CaseResult::fail(
                id.to_string(),
                "bootstrap",
                started.elapsed().as_millis() as u64,
                err,
            )),
        }
    }
    results
}

struct BootstrapSandbox {
    home_dir: PathBuf,
    dotagent_dir: PathBuf,
    target_ws: PathBuf,
    shim_dir: PathBuf,
    cargo_invoked_marker: PathBuf,
}

fn stage_bootstrap_sandbox(
    workspace_root: &Path,
    slug: &str,
    bins: &WorkspaceBinaries,
) -> Result<BootstrapSandbox, String> {
    let base = workspace_root
        .join("target")
        .join("test-workspaces")
        .join("dotagent-harness")
        .join(slug);
    reset_and_remove_dir(&base);

    // Nest dotagent_dir inside home_dir so activate-local.sh's upward .cargo scan
    // halts at $HOME and stays 100% isolated from parent directories.
    let home_dir = base.join("home");
    let dotagent_dir = home_dir.join("dotagent");
    let target_ws = home_dir.join("target-project");
    let shim_dir = base.join("shim-bin");
    let cargo_invoked_marker = base.join("cargo_ran.flag");

    for d in [
        &home_dir,
        &dotagent_dir.join(".git").join("hooks"),
        &dotagent_dir.join("crates").join("dotagent-compiler"),
        &target_ws.join(".git"),
        &shim_dir,
    ] {
        fs::create_dir_all(d).map_err(|e| format!("failed creating '{}': {e}", d.display()))?;
    }

    // Copy required dotagent trees and root mirrors.
    for rel_dir in [
        "scripts",
        "dist",
        "dist-verify",
        "skills",
        "profiles",
        ".github",
        ".claude",
        ".cursor",
        ".codex",
    ] {
        let src = workspace_root.join(rel_dir);
        if src.is_dir() {
            copy_dir_filtered_bounded(&src, &dotagent_dir.join(rel_dir), 0, 4)?;
        }
    }

    for rel_file in ["AGENTS.md", ".ignore", ".cursorignore", "Cargo.toml"] {
        let src = workspace_root.join(rel_file);
        if src.is_file() {
            fs::copy(&src, dotagent_dir.join(rel_file))
                .map_err(|e| format!("failed copying '{rel_file}': {e}"))?;
        }
    }

    // Seed pre-existing git identity in isolated HOME to verify preservation.
    fs::write(
        home_dir.join(".gitconfig"),
        "[user]\n\tname = Dotagent Harness\n\temail = harness@dotagent.local\n",
    )
    .map_err(|e| format!("failed writing initial .gitconfig: {e}"))?;
    fs::write(home_dir.join(".bashrc"), "# isolated bashrc\n")
        .map_err(|e| format!("failed writing .bashrc: {e}"))?;

    // Install fast offline cargo shim that asserts poisoned env vars were scrubbed
    // and stages pre-built workspace binaries into target/release/.
    let cargo_shim = shim_dir.join("cargo");
    let shim_body = format!(
        "#!/usr/bin/env bash\n\
         set -euo pipefail\n\
         echo ran > \"{}\"\n\
         if [[ -n \"${{RUSTC_WRAPPER:-}}\" || -n \"${{LD_PRELOAD:-}}\" || -n \"${{CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER:-}}\" || -n \"${{GIT_CONFIG_PARAMETERS:-}}\" ]]; then\n\
             echo \"poisoned env var leaked into cargo build\" >&2\n\
             exit 99\n\
         fi\n\
         mkdir -p \"{}/target/release\"\n\
         cp -f \"{}\" \"{}/target/release/agent-guard\"\n\
         cp -f \"{}\" \"{}/target/release/dotagent-compiler\"\n\
         cp -f \"{}\" \"{}/target/release/swarm-tool\"\n\
         chmod 0755 \"{}/target/release/agent-guard\" \"{}/target/release/dotagent-compiler\" \"{}/target/release/swarm-tool\"\n",
        cargo_invoked_marker.display(),
        dotagent_dir.display(),
        bins.agent_guard.display(),
        dotagent_dir.display(),
        bins.dotagent_compiler.display(),
        dotagent_dir.display(),
        bins.swarm_tool.display(),
        dotagent_dir.display(),
        dotagent_dir.display(),
        dotagent_dir.display(),
        dotagent_dir.display(),
    );
    fs::write(&cargo_shim, shim_body).map_err(|e| format!("write cargo shim: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&cargo_shim, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod cargo shim: {e}"))?;
        fs::set_permissions(
            dotagent_dir.join("scripts").join("activate-local.sh"),
            fs::Permissions::from_mode(0o755),
        )
        .map_err(|e| format!("chmod activate-local.sh: {e}"))?;
    }

    Ok(BootstrapSandbox {
        home_dir,
        dotagent_dir,
        target_ws,
        shim_dir,
        cargo_invoked_marker,
    })
}

fn run_activate_script(sb: &BootstrapSandbox) -> Result<(i32, String, String), String> {
    let orig_path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());
    let combined_path = format!("{}:{orig_path}", sb.shim_dir.display());

    let out = Command::new("bash")
        .arg(sb.dotagent_dir.join("scripts").join("activate-local.sh"))
        .arg(&sb.target_ws)
        .current_dir(&sb.dotagent_dir)
        .env("HOME", &sb.home_dir)
        .env("PATH", combined_path)
        // Inject hostile env vars to prove activate-local.sh scrubs every one of them!
        .env("RUSTC_WRAPPER", "/evil/wrapper")
        .env("LD_PRELOAD", "/evil/preload.so")
        .env("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER", "/evil/ld")
        .env("GIT_CONFIG_PARAMETERS", "'core.hooksPath=/evil'")
        .output()
        .map_err(|e| format!("failed executing activate-local.sh: {e}"))?;

    Ok((
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

fn case_happy_path_bootstrap(
    workspace_root: &Path,
    bins: &WorkspaceBinaries,
) -> Result<String, String> {
    let sb = stage_bootstrap_sandbox(workspace_root, "boot_happy", bins)?;
    let (code, stdout, stderr) = run_activate_script(&sb)?;
    if code != 0 {
        return Err(format!(
            "activate-local.sh exited {code}: stdout={stdout} stderr={stderr}"
        ));
    }
    if !sb.cargo_invoked_marker.is_file() {
        return Err("expected cargo build step to execute".to_string());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for bin_name in ["agent-guard", "dotagent-compiler", "swarm-tool"] {
            let bin_p = sb.home_dir.join(".local").join("bin").join(bin_name);
            let mode = fs::metadata(&bin_p)
                .map_err(|e| format!("missing installed '{bin_name}': {e}"))?
                .permissions()
                .mode()
                & 0o777;
            if mode != 0o555 {
                return Err(format!(
                    "expected installed '{bin_name}' mode 0555, got {mode:04o}"
                ));
            }
        }

        for deployed in [
            "AGENTS.md",
            ".ignore",
            ".cursorignore",
            ".claude/settings.json",
            ".claude/agents/research-airlock.md",
            ".claude/agents/swarm-master.md",
            ".cursor/hooks.json",
            ".cursor/agents/swarm-grunt.md",
            ".codex/config.toml",
            ".codex/agents/swarm-qa-engineer.md",
        ] {
            let p = sb.target_ws.join(deployed);
            let mode = fs::metadata(&p)
                .map_err(|e| format!("missing deployed target file '{deployed}': {e}"))?
                .permissions()
                .mode()
                & 0o777;
            if mode != 0o444 {
                return Err(format!(
                    "expected target workspace '{deployed}' mode 0444, got {mode:04o}"
                ));
            }
        }
    }

    let gitcfg = fs::read_to_string(sb.home_dir.join(".gitconfig"))
        .map_err(|e| format!("failed reading resulting .gitconfig: {e}"))?;
    for expected in [
        "Dotagent Harness",
        "harness@dotagent.local",
        "hooksPath = /dev/null",
        "attributesFile = /dev/null",
        "fsckObjects = true",
    ] {
        if !gitcfg.contains(expected) {
            return Err(format!(
                "resulting .gitconfig missing expected entry '{expected}'"
            ));
        }
    }

    if !sb.home_dir.join(".gemini").join("GEMINI.md").is_file()
        || !sb.home_dir.join(".gemini").join("settings.json").is_file()
    {
        return Err("~/.gemini/GEMINI.md or settings.json was not installed".to_string());
    }

    Ok(
        "Verified env scrub, 0555 binaries, 19 git keys + preserved identity, ~/.gemini, 0444 plane, and live audit-repo"
            .to_string(),
    )
}

fn case_trap_cargo_wrapper(
    workspace_root: &Path,
    bins: &WorkspaceBinaries,
) -> Result<String, String> {
    let sb = stage_bootstrap_sandbox(workspace_root, "boot_trap_cargo", bins)?;
    fs::create_dir_all(sb.dotagent_dir.join(".cargo")).map_err(|e| e.to_string())?;
    fs::write(
        sb.dotagent_dir.join(".cargo").join("config.toml"),
        "[build]\nrustc-wrapper = \"/bin/sh\"\n",
    )
    .map_err(|e| e.to_string())?;

    let (code, _, stderr) = run_activate_script(&sb)?;
    if code != 2 || sb.cargo_invoked_marker.exists() || !stderr.contains("HARD DENY") {
        return Err(format!(
            "expected pre-build exit 2 before cargo ran, got code={code} stderr={stderr}"
        ));
    }
    Ok(
        "Rejected .cargo/config.toml rustc-wrapper with exit 2 prior to Cargo invocation"
            .to_string(),
    )
}

fn case_trap_symlink_agents(
    workspace_root: &Path,
    bins: &WorkspaceBinaries,
) -> Result<String, String> {
    let sb = stage_bootstrap_sandbox(workspace_root, "boot_trap_symlink_agents", bins)?;
    #[cfg(unix)]
    {
        let agents_p = sb.dotagent_dir.join("AGENTS.md");
        let _ = fs::remove_file(&agents_p);
        std::os::unix::fs::symlink(sb.dotagent_dir.join("dist").join("AGENTS.md"), &agents_p)
            .map_err(|e| e.to_string())?;
        let (code, _, stderr) = run_activate_script(&sb)?;
        if code != 2 || sb.cargo_invoked_marker.exists() || !stderr.contains("AGENTS.md") {
            return Err(format!(
                "expected pre-build exit 2 on symlinked AGENTS.md, got code={code} stderr={stderr}"
            ));
        }
    }
    Ok("Rejected symlinked root AGENTS.md with exit 2 prior to Cargo invocation".to_string())
}

fn case_trap_gitattributes_filter(
    workspace_root: &Path,
    bins: &WorkspaceBinaries,
) -> Result<String, String> {
    let sb = stage_bootstrap_sandbox(workspace_root, "boot_trap_gitattr", bins)?;
    fs::write(
        sb.dotagent_dir.join(".gitattributes"),
        "*.rs filter=malicious-smudge\n",
    )
    .map_err(|e| e.to_string())?;

    let (code, _, stderr) = run_activate_script(&sb)?;
    if code != 2 || sb.cargo_invoked_marker.exists() || !stderr.contains(".gitattributes") {
        return Err(format!(
            "expected pre-build exit 2 on .gitattributes filter=, got code={code} stderr={stderr}"
        ));
    }
    Ok("Rejected .gitattributes filter driver with exit 2 prior to Cargo invocation".to_string())
}

fn case_trap_yarnpath(workspace_root: &Path, bins: &WorkspaceBinaries) -> Result<String, String> {
    let sb = stage_bootstrap_sandbox(workspace_root, "boot_trap_yarnpath", bins)?;
    fs::write(
        sb.dotagent_dir.join(".yarnrc.yml"),
        "yarnPath: ./.yarn/releases/evil.cjs\n",
    )
    .map_err(|e| e.to_string())?;

    let (code, _, stderr) = run_activate_script(&sb)?;
    if code != 2 || sb.cargo_invoked_marker.exists() || !stderr.contains("yarnPath") {
        return Err(format!(
            "expected pre-build exit 2 on .yarnrc.yml yarnPath, got code={code} stderr={stderr}"
        ));
    }
    Ok("Rejected .yarnrc.yml yarnPath trap with exit 2 prior to Cargo invocation".to_string())
}

fn case_trap_symlink_target_workspace(
    workspace_root: &Path,
    bins: &WorkspaceBinaries,
) -> Result<String, String> {
    let sb = stage_bootstrap_sandbox(workspace_root, "boot_trap_target_symlink", bins)?;
    #[cfg(unix)]
    {
        let victim = sb.home_dir.join("victim.txt");
        fs::write(&victim, "DO_NOT_CLOBBER\n").map_err(|e| e.to_string())?;
        fs::create_dir_all(sb.target_ws.join(".claude")).map_err(|e| e.to_string())?;
        std::os::unix::fs::symlink(&victim, sb.target_ws.join(".claude").join("settings.json"))
            .map_err(|e| e.to_string())?;

        let (code, _, stderr) = run_activate_script(&sb)?;
        let victim_after = fs::read_to_string(&victim).map_err(|e| e.to_string())?;
        if code != 2 || !stderr.contains("HARD DENY") || victim_after != "DO_NOT_CLOBBER\n" {
            return Err(format!(
                "expected exit 2 without clobbering symlink victim, got code={code} stderr={stderr}"
            ));
        }
    }
    Ok(
        "Rejected symlinked target workspace .claude/settings.json with exit 2 without clobbering victim"
            .to_string(),
    )
}
