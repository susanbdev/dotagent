#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use agent_guard::stop_receipt::StopReceipt;

fn isolated_git_repo(slug: &str) -> (PathBuf, PathBuf, PathBuf) {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ws_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let base = ws_root
        .join("target")
        .join("test-workspaces")
        .join(format!("ag-c4-{}-{slug}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let repo = base.join("repo");
    let home = base.join("home");
    let state_sessions = base.join("guard-state").join("sessions");
    fs::create_dir_all(&repo).expect("repo");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&state_sessions).expect("sessions");

    let git_init = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .status()
        .expect("git init");
    assert!(git_init.success());
    fs::write(repo.join("AGENTS.md"), "# AGENTS.md\n").expect("AGENTS.md");
    (repo, home, state_sessions)
}

fn configure_hermetic_global_git(home: &Path) {
    let ws_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf();
    let hardened = fs::read_to_string(ws_root.join("dist/gitconfig.hardened"))
        .expect("read dist/gitconfig.hardened");
    fs::write(
        home.join(".gitconfig"),
        format!("{hardened}\n[user]\n\tname = Test\n\temail = test@example.com\n"),
    )
    .expect("write .gitconfig");
}

#[test]
fn wrangler_missing_shim_and_bad_wasm_fail_on_stop_until_valid_artifacts_bound_in_receipt() {
    let (repo, home, state_sessions) = isolated_git_repo("wrangler-smoke");
    configure_hermetic_global_git(&home);
    let guard_bin = env!("CARGO_BIN_EXE_agent-guard");
    let dotagent_bin = env!("CARGO_BIN_EXE_dotagent");

    fs::write(
        repo.join("wrangler.public.toml"),
        "name = \"edge-api\"\nmain = \"build/worker/shim.mjs\"\ncompatibility_date = \"2026-01-01\"\n",
    )
    .expect("write wrangler.public.toml");

    // 1. Missing `build/worker/shim.mjs` -> fails `on-stop` with SMOKE_ARTIFACT_MISSING
    let receipt_path = repo.parent().expect("parent").join("out.receipt.json");
    let out_missing = Command::new(guard_bin)
        .args(["on-stop", "--receipt-out"])
        .arg(&receipt_path)
        .current_dir(&repo)
        .env("HOME", &home)
        .env("AGENT_GUARD_STATE_DIR", &state_sessions)
        .output()
        .expect("run on-stop missing");
    assert_eq!(out_missing.status.code(), Some(2));
    let err_missing = String::from_utf8_lossy(&out_missing.stderr);
    assert!(
        err_missing.contains("SMOKE_ARTIFACT_MISSING"),
        "expected SMOKE_ARTIFACT_MISSING: {err_missing}"
    );

    // 2. Write `shim.mjs` referencing `./index_bg.wasm` with invalid Wasm magic -> fails SMOKE_WASM_MAGIC_INVALID
    fs::create_dir_all(repo.join("build/worker")).expect("mkdir build/worker");
    fs::write(
        repo.join("build/worker/shim.mjs"),
        "import wasm from \"./index_bg.wasm\";\nexport default { fetch() { return new Response(\"ok\"); } };\n",
    )
    .expect("write shim.mjs");
    fs::write(repo.join("build/worker/index_bg.wasm"), b"NOT_WASM").expect("write bad wasm");

    let out_bad_wasm = Command::new(guard_bin)
        .args(["on-stop", "--receipt-out"])
        .arg(&receipt_path)
        .current_dir(&repo)
        .env("HOME", &home)
        .env("AGENT_GUARD_STATE_DIR", &state_sessions)
        .output()
        .expect("run on-stop bad wasm");
    assert_eq!(out_bad_wasm.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out_bad_wasm.stderr).contains("SMOKE_WASM_MAGIC_INVALID"),
        "expected SMOKE_WASM_MAGIC_INVALID"
    );

    // 3. Write valid Wasm v1 header (`\0asm\x01\0\0\0`) + dirty facade stub in `src/lib.rs` -> fails SMOKE_FACADE_TOKEN_DETECTED
    fs::write(repo.join("build/worker/index_bg.wasm"), b"\0asm\x01\0\0\0").expect("valid wasm");
    fs::create_dir_all(repo.join("src")).expect("mkdir src");
    let stub_src = format!(
        "pub fn run() {{ {} \"not ready\"); }}\n",
        concat!("to", "do!(")
    );
    fs::write(repo.join("src/lib.rs"), stub_src).expect("write stub src");

    let out_facade = Command::new(guard_bin)
        .args(["on-stop", "--receipt-out"])
        .arg(&receipt_path)
        .current_dir(&repo)
        .env("HOME", &home)
        .env("AGENT_GUARD_STATE_DIR", &state_sessions)
        .output()
        .expect("run on-stop facade");
    assert_eq!(out_facade.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out_facade.stderr).contains("SMOKE_FACADE_TOKEN_DETECTED"),
        "expected SMOKE_FACADE_TOKEN_DETECTED"
    );

    // 4. Replace stub with real implementation -> `on-stop` succeeds and binds `smoke_gate_digest` in Ed25519 StopReceipt!
    fs::write(repo.join("src/lib.rs"), "pub fn run() -> u32 { 42 }\n").expect("write real src");
    let out_ok = Command::new(guard_bin)
        .args(["on-stop", "--receipt-out"])
        .arg(&receipt_path)
        .current_dir(&repo)
        .env("HOME", &home)
        .env("AGENT_GUARD_STATE_DIR", &state_sessions)
        .output()
        .expect("run on-stop ok");
    assert_eq!(
        out_ok.status.code(),
        Some(0),
        "expected on-stop exit 0: stderr={}",
        String::from_utf8_lossy(&out_ok.stderr)
    );

    let raw_receipt = fs::read_to_string(&receipt_path).expect("read receipt");
    let parsed = StopReceipt::from_json_str(&raw_receipt).expect("parse StopReceipt");
    assert_eq!(parsed.smoke_gate_digest.len(), 64);

    let verify_ok = Command::new(dotagent_bin)
        .arg("verify-receipt")
        .arg(&receipt_path)
        .args(["--repo", &repo.to_string_lossy()])
        .current_dir(&repo)
        .env("HOME", &home)
        .env("AGENT_GUARD_STATE_DIR", &state_sessions)
        .output()
        .expect("verify-receipt");
    assert_eq!(
        verify_ok.status.code(),
        Some(0),
        "verify-receipt must succeed: stderr={}",
        String::from_utf8_lossy(&verify_ok.stderr)
    );
}
