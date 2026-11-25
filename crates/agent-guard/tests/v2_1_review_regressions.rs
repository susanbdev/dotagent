#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use agent_guard::breadcrumbs::{
    count_verified_quorum_approvals, record_quorum_approval_breadcrumb, sha256_digest,
};
use agent_guard::cmd_policy::evaluate_shell_command;
use agent_guard::crypto::{hex_encode, sha256_hex};
use agent_guard::fleet::{
    build_github_fleet_governance_plan, build_github_repo_ruleset_payload,
    verify_github_governance_state,
};
use agent_guard::json::JsonValue;
use agent_guard::role_sandbox::save_session_capability;
use agent_guard::smoke_gate::verify_repo_smoke_gate;
use agent_guard::sshsig_touch::{load_operator_sk_keys_from_home, verify_fido2_sshsig_ed25519};
use agent_guard::swarm_contracts::{SessionCapability, SwarmRole};

fn sandbox(slug: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ws_root = manifest_dir.parent().and_then(Path::parent).expect("ws");
    let dir = ws_root
        .join("target")
        .join("trv")
        .join(format!("{}-{slug}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn push_ssh_str(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn build_sk_sshsig_pem(
    sk: &SigningKey,
    app: &[u8],
    namespace: &str,
    msg: &[u8],
    flags: u8,
) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let b64 = |input: &[u8]| -> String {
        let mut out = String::new();
        for c in input.chunks(3) {
            let b0 = c[0] as u32;
            let b1 = if c.len() > 1 { c[1] as u32 } else { 0 };
            let b2 = if c.len() > 2 { c[2] as u32 } else { 0 };
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(B64[((n >> 18) & 0x3f) as usize] as char);
            out.push(B64[((n >> 12) & 0x3f) as usize] as char);
            out.push(if c.len() > 1 {
                B64[((n >> 6) & 0x3f) as usize] as char
            } else {
                '='
            });
            out.push(if c.len() > 2 {
                B64[(n & 0x3f) as usize] as char
            } else {
                '='
            });
        }
        out
    };
    let pub_bytes = sk.verifying_key().to_bytes();
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"SSHSIG");
    push_ssh_str(&mut preimage, namespace.as_bytes());
    push_ssh_str(&mut preimage, b"");
    push_ssh_str(&mut preimage, b"sha512");
    let mh = sha2::Sha512::digest(msg);
    push_ssh_str(&mut preimage, &mh);
    let mut sk_signed = Vec::new();
    sk_signed.extend_from_slice(&Sha256::digest(app));
    sk_signed.push(flags);
    sk_signed.extend_from_slice(&7u32.to_be_bytes());
    sk_signed.extend_from_slice(&Sha256::digest(&preimage));
    let sig = sk.sign(&sk_signed);
    let mut pub_blob = Vec::new();
    push_ssh_str(&mut pub_blob, b"sk-ssh-ed25519@openssh.com");
    push_ssh_str(&mut pub_blob, &pub_bytes);
    push_ssh_str(&mut pub_blob, app);
    let mut sig_blob = Vec::new();
    push_ssh_str(&mut sig_blob, b"sk-ssh-ed25519@openssh.com");
    push_ssh_str(&mut sig_blob, &sig.to_bytes());
    sig_blob.push(flags);
    sig_blob.extend_from_slice(&7u32.to_be_bytes());
    let mut wire = Vec::new();
    wire.extend_from_slice(b"SSHSIG");
    wire.extend_from_slice(&1u32.to_be_bytes());
    push_ssh_str(&mut wire, &pub_blob);
    push_ssh_str(&mut wire, namespace.as_bytes());
    push_ssh_str(&mut wire, b"");
    push_ssh_str(&mut wire, b"sha512");
    push_ssh_str(&mut wire, &sig_blob);
    format!(
        "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
        b64(&wire)
    )
}

#[test]
fn review_regressions_sshsig_app_quorum_binding_and_repo_local_bin_blocks() {
    let sk = SigningKey::from_bytes(&[0x55u8; 32]);
    let pk = sk.verifying_key().to_bytes();
    let foreign_pem = build_sk_sshsig_pem(&sk, b"ssh:evil-rp", "dotagent-operator", b"chal", 0x01);
    assert!(
        verify_fido2_sshsig_ed25519("dotagent-operator", b"chal", &foreign_pem, &[pk]).is_err(),
        "foreign FIDO2 RP application must be rejected"
    );
    let valid_pem = build_sk_sshsig_pem(&sk, b"ssh:", "dotagent-operator", b"chal", 0x00);
    assert_eq!(
        verify_fido2_sshsig_ed25519("dotagent-operator", b"chal", &valid_pem, &[pk]).expect("ok"),
        7
    );
    assert!(load_operator_sk_keys_from_home(Path::new("relative/home")).is_err());

    let base = sandbox("quorum-cap");
    let repo = base.join("r");
    fs::create_dir_all(repo.join(".git")).expect("git");
    fs::create_dir_all(repo.join("migrations")).expect("migrations");
    fs::write(repo.join("AGENTS.md"), "# AGENTS.md\n").expect("agents");
    fs::write(repo.join("migrations/001.sql"), "CREATE TABLE t(id INT);\n").expect("sql");
    let canon = fs::canonicalize(&repo).expect("canon");
    let repo_sha = hex_encode(&sha256_digest(canon.to_string_lossy().as_bytes()));

    assert!(
        record_quorum_approval_breadcrumb(&canon, "swm_unminted", "t1", "migrations/001.sql")
            .is_err()
    );
    let grunt = SessionCapability {
        session_id: "swm_grunt1".to_string(),
        role: SwarmRole::Grunt,
        task_id: "t1".to_string(),
        attempt: 1,
        repo_sha256: repo_sha.clone(),
        plan_sha256: "0".repeat(64),
        assigned_read_paths: vec!["migrations/001.sql".into()],
        allowed_write_paths: vec!["migrations/001.sql".into()],
        assigned_tests: vec![],
        last_green_tree_oid: None,
        consecutive_test_failures: 0,
        blocked_scope_attempts: 0,
        malicious_flags: 0,
    };
    save_session_capability(&canon, &grunt).expect("save grunt");
    assert!(
        record_quorum_approval_breadcrumb(&canon, "swm_grunt1", "t1", "migrations/001.sql")
            .is_err()
    );

    let rev = SessionCapability {
        session_id: "swm_rev1".to_string(),
        role: SwarmRole::AdversarialReviewer,
        task_id: "t1".to_string(),
        attempt: 1,
        repo_sha256: repo_sha,
        plan_sha256: "0".repeat(64),
        assigned_read_paths: vec!["migrations/001.sql".into()],
        allowed_write_paths: vec![],
        assigned_tests: vec![],
        last_green_tree_oid: None,
        consecutive_test_failures: 0,
        blocked_scope_attempts: 0,
        malicious_flags: 0,
    };
    save_session_capability(&canon, &rev).expect("save rev");
    record_quorum_approval_breadcrumb(&canon, "swm_rev1", "t1", "migrations/001.sql")
        .expect("approve");
    assert!(record_quorum_approval_breadcrumb(&canon, "swm_rev1", "t1", "../outside.sql").is_err());
    assert!(record_quorum_approval_breadcrumb(&canon, "swm_rev1", "t1", "AGENTS.md").is_err());
    assert_eq!(
        count_verified_quorum_approvals(&canon, "swm_grunt1", &["migrations/001.sql".into()], &[]),
        1
    );
    // Mutating file content after approval invalidates quorum count (`doc_sha256` drift)!
    fs::write(repo.join("migrations/001.sql"), "DROP TABLE t;\n").expect("tamper sql");
    assert_eq!(
        count_verified_quorum_approvals(&canon, "swm_grunt1", &["migrations/001.sql".into()], &[]),
        0
    );

    assert!(evaluate_shell_command("./bin/dotagent doctor", &canon, &canon, false).is_err());
    assert!(evaluate_shell_command("./bin/swarm-tool status", &canon, &canon, false).is_err());
    assert!(evaluate_shell_command("./bin/git status", &canon, &canon, false).is_err());
    for protected in [
        "profiles/plugins/rogue.rego",
        "profiles/coding-agent.toml",
        ".dotagent-smoke.toml",
    ] {
        assert!(
            agent_guard::path_policy::validate_path(
                &canon,
                &canon,
                protected,
                agent_guard::path_policy::PathAccess::Write,
            )
            .is_err(),
            "write to {protected} must be denied"
        );
    }
}

#[test]
fn review_regressions_smoke_jsonc_committed_stub_fleet_and_plugin_evade() {
    let base = sandbox("multi-reg");
    let repo = base.join("r");
    fs::create_dir_all(&repo).expect("mkdir");
    Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .status()
        .expect("init");
    Command::new("git")
        .args(["config", "user.email", "t@dotagent.local"])
        .current_dir(&repo)
        .status()
        .expect("cfg");
    Command::new("git")
        .args(["config", "user.name", "t"])
        .current_dir(&repo)
        .status()
        .expect("cfg");

    fs::write(repo.join("AGENTS.md"), "# AGENTS.md\n").expect("agents");
    fs::write(
        repo.join("wrangler.jsonc"),
        "/* header */ {\"name\":\"w\",\"main\":\"dist/worker.mjs\"}",
    )
    .expect("wrangler.jsonc");
    assert!(
        verify_repo_smoke_gate(&repo).is_err(),
        "single-line wrangler.jsonc pointing to missing dist/worker.mjs must fail closed"
    );
    fs::create_dir_all(repo.join("dist")).expect("mkdir dist");
    let stub_macro = format!("{}{}", "to", "do!()");
    fs::write(
        repo.join("dist/worker.mjs"),
        format!("const u = \"https://ok.test\"; {stub_macro}\n"),
    )
    .expect("write worker with stub after URL");
    Command::new("git")
        .args(["add", "."])
        .current_dir(&repo)
        .status()
        .expect("add");
    Command::new("git")
        .args(["commit", "-q", "-m", "commit stub"])
        .current_dir(&repo)
        .status()
        .expect("commit");
    let stub_err =
        verify_repo_smoke_gate(&repo).expect_err("committed stub after // in URL must fail");
    assert!(
        stub_err.contains("SMOKE_FACADE_TOKEN_DETECTED"),
        "{stub_err}"
    );

    let plan = build_github_fleet_governance_plan("susanbdev", &["dotagent".into()]);
    let t0 = &plan
        .get("targets")
        .and_then(JsonValue::as_array)
        .expect("t")[0];
    let wf = t0.get("workflow_permissions").expect("wf");
    let rs = build_github_repo_ruleset_payload();
    let disabled_act =
        JsonValue::parse("{\"enabled\":false,\"sha_pinning_required\":true}").expect("json");
    assert!(verify_github_governance_state(&disabled_act, wf, &rs).is_err());

    fs::create_dir_all(repo.join("profiles/plugins")).expect("plugins dir");
    let rego_evade = "package dotagent.plugin\nverdict := \"allow\" { http . send({}) }\n";
    let rego_sha = sha256_hex(rego_evade.as_bytes());
    fs::write(repo.join("profiles/plugins/evade.rego"), rego_evade).expect("rego");
    fs::write(
        repo.join("profiles/coding-agent.toml"),
        format!("profile_id = \"coding-agent\"\n[plugins]\n\"evade.rego\" = \"{rego_sha}\"\n"),
    )
    .expect("profile");
    let dec = agent_guard::handle_pre_tool_hook(
        &format!(
            "{{\"session_id\":\"s_reg_plugin\",\"cwd\":\"{}\",\"tool_name\":\"Read\",\"tool_input\":{{\"file_path\":\"AGENTS.md\",\"offset\":1,\"limit\":5}}}}",
            repo.display()
        ),
        &repo,
    );
    assert!(
        matches!(
            dec,
            agent_guard::Decision::Deny {
                code: "PLUGIN_EVALUATION_ERROR",
                ..
            }
        ),
        "got {dec:?}"
    );

    assert!(agent_guard::crypto::base64_decode_clean("YW=h", 64).is_err());
    assert!(agent_guard::crypto::base64_decode_clean("Y===h", 64).is_err());
    assert_eq!(
        agent_guard::crypto::base64_decode_clean("YWI=", 64).expect("valid pad 1"),
        b"ab"
    );
    assert!(evaluate_shell_command("'.\\sub\\dotagent' doctor", &repo, &repo, false).is_err());
    assert!(
        evaluate_shell_command(
            "'.\\sub\\dotagent.exe' feedback submit",
            &repo,
            &repo,
            false
        )
        .is_err()
    );
    assert!(evaluate_shell_command("PATH=. dotagent doctor", &repo, &repo, false).is_err());

    let rego_conflict = "package dotagent.plugin\ndeny := true\ndeny := false\n";
    let c_sha = sha256_hex(rego_conflict.as_bytes());
    fs::write(repo.join("profiles/plugins/evade.rego"), rego_conflict).expect("rego conflict");
    fs::write(
        repo.join("profiles/coding-agent.toml"),
        format!("profile_id = \"coding-agent\"\n[plugins]\n\"evade.rego\" = \"{c_sha}\"\n"),
    )
    .expect("profile conflict");
    let c_dec = agent_guard::handle_pre_tool_hook(
        &format!(
            "{{\"session_id\":\"s_reg_plugin2\",\"cwd\":\"{}\",\"tool_name\":\"Read\",\"tool_input\":{{\"file_path\":\"AGENTS.md\",\"offset\":1,\"limit\":5}}}}",
            repo.display()
        ),
        &repo,
    );
    assert!(matches!(
        c_dec,
        agent_guard::Decision::Deny {
            code: "PLUGIN_EVALUATION_ERROR",
            ..
        }
    ));
}
