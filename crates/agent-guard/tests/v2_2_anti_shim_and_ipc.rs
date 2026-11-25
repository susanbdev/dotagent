#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use agent_guard::coordinator::intern_known_guard_code;
use agent_guard::feedback_loop::write_atomic_outbox_file;
use agent_guard::path_policy::{ScopedRequestSession, resolve_max_walk_depth};
use agent_guard::qa_suspects::{parse_and_validate_dag_json, save_locked_plan};
use agent_guard::role_sandbox::mint_session_capability;
use agent_guard::smoke_gate::verify_repo_smoke_gate;
use agent_guard::swarm_contracts::{INVESTIGATOR_MAX_WALK_DEPTH, SwarmRole};
use agent_guard::{
    Decision, HookCallerContext, audit_repository, handle_pre_tool_hook_with_context,
};

struct TempWorkspace(PathBuf);

impl TempWorkspace {
    fn new(label: &str) -> Self {
        let base = std::env::current_dir()
            .expect("cwd")
            .join("target")
            .join("test-workspaces")
            .join(format!("v22-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("mkdir test workspace");
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&base)
            .status()
            .expect("git init");
        Command::new("git")
            .args(["config", "user.email", "test@dotagent.local"])
            .current_dir(&base)
            .status()
            .expect("git email");
        Command::new("git")
            .args(["config", "user.name", "dotagent-test"])
            .current_dir(&base)
            .status()
            .expect("git name");
        fs::write(base.join("AGENTS.md"), "# AGENTS.md\n").expect("write AGENTS.md");
        Self(base)
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn dynamic_guard_codes_never_collapse_to_coordinator_hook_deny() {
    assert_eq!(
        intern_known_guard_code("NO_UNLINKED_RUNTIME_SHIM"),
        "NO_UNLINKED_RUNTIME_SHIM"
    );
    assert_eq!(
        intern_known_guard_code("FUTURE_CUSTOM_DENIAL_V99"),
        "FUTURE_CUSTOM_DENIAL_V99"
    );
    assert_eq!(
        intern_known_guard_code("bad lowercase"),
        "COORDINATOR_HOOK_DENY"
    );
    assert_eq!(intern_known_guard_code(""), "COORDINATOR_HOOK_DENY");
}

#[test]
fn investigator_session_preserves_walk_depth_over_ipc_without_process_env() {
    let ws = TempWorkspace::new("investigator-ipc");
    let dag = r#"{
        "plan_id": "V22-PLAN",
        "waves": [{
            "wave_id": "W0",
            "tasks": [{
                "task_id": "T-INV",
                "assigned_read_paths": ["crates"],
                "allowed_write_paths": ["crates/mod.rs"],
                "assigned_tests": ["t1"]
            }]
        }]
    }"#;
    let plan = parse_and_validate_dag_json(dag).expect("parse dag");
    save_locked_plan(&ws.0, &plan, true).expect("save locked plan");
    let cap = mint_session_capability(&ws.0, SwarmRole::Investigator, "T-INV", 1)
        .expect("mint investigator capability");

    // Process env has no AGENT_GUARD_SESSION_ID (simulating scrubbed hook-daemon),
    // while IPC request threads caller_ctx.session_id explicitly.
    assert_eq!(
        resolve_max_walk_depth(&ws.0, Some(&cap.session_id)),
        INVESTIGATOR_MAX_WALK_DEPTH
    );
    {
        let _scope = ScopedRequestSession::enter(Some(&cap.session_id));
        assert_eq!(
            agent_guard::path_policy::effective_max_walk_depth_for_repo(&ws.0),
            INVESTIGATOR_MAX_WALK_DEPTH
        );
    }

    let deep_dir = ws.0.join("crates/a/b/c/d");
    fs::create_dir_all(&deep_dir).expect("mkdir deep");
    fs::write(deep_dir.join("leaf.rs"), "pub fn check() {}\n").expect("write leaf");

    let caller_ctx = HookCallerContext {
        session_id: Some(cap.session_id.clone()),
        root_session_id: None,
        profile_id: None,
        role_id: Some("investigator".to_string()),
        direct_explore: None,
    };
    let payload = r#"{"tool_name":"Read","tool_input":{"file_path":"crates/a/b/c/d/leaf.rs","offset":1,"limit":10}}"#;
    let dec = handle_pre_tool_hook_with_context(payload, &ws.0, &caller_ctx, None);
    assert!(
        matches!(dec, Decision::Allow { .. }),
        "Investigator deep read over IPC must succeed without daemon env: {dec:?}"
    );
}

#[cfg(unix)]
#[test]
fn write_atomic_outbox_blocks_intermediate_ancestor_symlink() {
    use std::os::unix::fs::symlink;

    let ws = TempWorkspace::new("outbox-symlink");
    let real_dir = ws.0.join("real_outside");
    fs::create_dir_all(&real_dir).expect("mkdir real_outside");
    let sym_ancestor = ws.0.join("linked_ancestor");
    symlink(&real_dir, &sym_ancestor).expect("create ancestor symlink");

    // Intermediate component `linked_ancestor` is a symlink, while `nested` is a normal subpath.
    let target = sym_ancestor.join("nested").join("outbox.json");
    let err = write_atomic_outbox_file(&target, b"{}\n")
        .expect_err("intermediate symlink ancestor must be blocked");
    assert!(err.contains("SYMLINK_OUTBOX_BLOCKED"), "{err}");

    let clean_target = ws.0.join("outbox_dir").join("sub").join("outbox.json");
    write_atomic_outbox_file(&clean_target, b"{\"ok\":true}\n")
        .expect("regular non-symlink ancestor chain must succeed");
}

#[test]
fn v22_anti_shim_fail_open_and_polyglot_vector_laws_enforce_strictly() {
    // 1. Cargo + Wrangler without Wasm linkage or > 150-line shim must fail NO_UNLINKED_RUNTIME_SHIM
    let worker_ws = TempWorkspace::new("worker-shim");
    fs::write(
        worker_ws.0.join("Cargo.toml"),
        "[package]\nname = \"svc\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("Cargo.toml");
    fs::write(
        worker_ws.0.join("wrangler.toml"),
        "name = \"svc\"\nmain = \"worker/shim.mjs\"\n",
    )
    .expect("wrangler.toml");
    fs::create_dir_all(worker_ws.0.join("worker")).expect("mkdir worker");
    fs::write(
        worker_ws.0.join("worker/shim.mjs"),
        "export default { async fetch() { try { throw 1; } catch (_) { return { clean: true }; } } };\n",
    )
    .expect("shim.mjs");

    let errs =
        audit_repository(&worker_ws.0).expect_err("unlinked shim + fail-open catch must fail");
    assert!(
        errs.iter().any(|e| e.contains("NO_UNLINKED_RUNTIME_SHIM")),
        "expected NO_UNLINKED_RUNTIME_SHIM in {errs:?}"
    );
    assert!(
        errs.iter().any(|e| e.contains("NO_FAIL_OPEN_FALLBACK")),
        "expected NO_FAIL_OPEN_FALLBACK in {errs:?}"
    );

    // Fix Worker workspace: cdylib + <= 150-line host FFI importing valid .wasm
    fs::write(
        worker_ws.0.join("Cargo.toml"),
        "[package]\nname = \"svc\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[lib]\ncrate-type = [\"cdylib\", \"rlib\"]\n",
    )
    .expect("Cargo.toml cdylib");
    fs::write(
        worker_ws.0.join("worker/svc.wasm"),
        b"\0asm\x01\x00\x00\x00",
    )
    .expect("svc.wasm");
    fs::write(
        worker_ws.0.join("worker/shim.mjs"),
        "import wasmMod from \"./svc.wasm\";\nexport default { async fetch() { return new Response(String(Boolean(wasmMod))); } };\n",
    )
    .expect("clean host glue");
    Command::new("git")
        .args(["add", "."])
        .current_dir(&worker_ws.0)
        .status()
        .expect("git add");
    Command::new("git")
        .args(["commit", "-q", "-m", "clean wasm worker"])
        .current_dir(&worker_ws.0)
        .status()
        .expect("git commit");

    audit_repository(&worker_ws.0).expect("linked wasm worker <= 150 lines must pass");
    verify_repo_smoke_gate(&worker_ws.0).expect("smoke gate must pass linked wasm worker");

    // 2. OpenTofu repo with imperative scripts/deploy.py must fail NO_UNLINKED_RUNTIME_SHIM
    let tf_ws = TempWorkspace::new("tf-deploy-py");
    fs::write(tf_ws.0.join("main.tf"), "terraform {}\n").expect("main.tf");
    fs::create_dir_all(tf_ws.0.join("scripts")).expect("mkdir scripts");
    fs::write(tf_ws.0.join("scripts/deploy.py"), "print('bypass')\n").expect("deploy.py");
    let tf_errs = audit_repository(&tf_ws.0).expect_err("deploy.py over .tf must fail");
    assert!(
        tf_errs
            .iter()
            .any(|e| e.contains("NO_UNLINKED_RUNTIME_SHIM")),
        "{tf_errs:?}"
    );

    // 3. Polyglot repository must provide shared vectors/*.json referenced across all 4 bindings
    let poly_ws = TempWorkspace::new("polyglot");
    for lang_dir in [
        "packages/rust",
        "packages/ts",
        "packages/python",
        "packages/c",
    ] {
        fs::create_dir_all(poly_ws.0.join(lang_dir)).expect("mkdir pkg");
    }
    let poly_errs = audit_repository(&poly_ws.0).expect_err("missing vectors must fail");
    assert!(
        poly_errs
            .iter()
            .any(|e| e.contains("POLYGLOT_GOLDEN_VECTORS")),
        "{poly_errs:?}"
    );
    fs::create_dir_all(poly_ws.0.join("vectors")).expect("mkdir vectors");
    fs::write(
        poly_ws.0.join("vectors/golden.json"),
        "{\"cases\":[{\"in\":\"a\",\"out\":\"a\"}]}\n",
    )
    .expect("write golden.json");
    for (file, content) in [
        ("packages/rust/test.rs", "// uses vectors/golden.json\n"),
        ("packages/ts/test.ts", "// uses vectors/golden.json\n"),
        (
            "packages/python/test_vec.py",
            "# uses vectors/golden.json\n",
        ),
        ("packages/c/test_vec.c", "/* uses vectors/golden.json */\n"),
    ] {
        fs::write(poly_ws.0.join(file), content).expect("write lang test");
    }
    audit_repository(&poly_ws.0).expect("polyglot repo with 4-language vectors must pass");
}
