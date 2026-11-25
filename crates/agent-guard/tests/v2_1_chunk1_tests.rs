#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use agent_guard::exec_sandbox::probe_host_sandbox_mode;
use agent_guard::sshsig_touch::{
    OPERATOR_SSHSIG_NAMESPACE, SK_ED25519_ALG, SSH_ED25519_ALG,
    load_operator_or_ssh_keys_from_home, load_operator_sk_keys_from_home,
    release_signature_has_fido2_touch, verify_fido2_sshsig_ed25519,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256, Sha512};

fn push_ssh_str(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&u32::try_from(data.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(data);
}

fn encode_base64(input: &[u8]) -> String {
    const LUT: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let t = (b0 << 16) | (b1 << 8) | b2;
        out.push(LUT[((t >> 18) & 0x3f) as usize] as char);
        out.push(LUT[((t >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            LUT[((t >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            LUT[(t & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn mint_sk_sshsig_pem(
    sk: &SigningKey,
    application: &[u8],
    namespace: &str,
    challenge: &[u8],
    flags: u8,
    counter: u32,
) -> String {
    let msg_hash = Sha512::digest(challenge);
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"SSHSIG");
    push_ssh_str(&mut preimage, namespace.as_bytes());
    push_ssh_str(&mut preimage, b"");
    push_ssh_str(&mut preimage, b"sha512");
    push_ssh_str(&mut preimage, &msg_hash);

    let mut sk_signed = Vec::with_capacity(69);
    sk_signed.extend_from_slice(&Sha256::digest(application));
    sk_signed.push(flags);
    sk_signed.extend_from_slice(&counter.to_be_bytes());
    sk_signed.extend_from_slice(&Sha256::digest(&preimage));
    let sig = sk.sign(&sk_signed);

    let mut pk_blob = Vec::new();
    push_ssh_str(&mut pk_blob, SK_ED25519_ALG.as_bytes());
    push_ssh_str(&mut pk_blob, sk.verifying_key().as_bytes());
    push_ssh_str(&mut pk_blob, application);

    let mut sig_blob = Vec::new();
    push_ssh_str(&mut sig_blob, SK_ED25519_ALG.as_bytes());
    push_ssh_str(&mut sig_blob, &sig.to_bytes());
    sig_blob.push(flags);
    sig_blob.extend_from_slice(&counter.to_be_bytes());

    let mut outer = Vec::new();
    outer.extend_from_slice(b"SSHSIG");
    outer.extend_from_slice(&1u32.to_be_bytes());
    push_ssh_str(&mut outer, &pk_blob);
    push_ssh_str(&mut outer, namespace.as_bytes());
    push_ssh_str(&mut outer, b"");
    push_ssh_str(&mut outer, b"sha512");
    push_ssh_str(&mut outer, &sig_blob);

    format!(
        "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
        encode_base64(&outer)
    )
}

fn mint_ssh_ed25519_sshsig_pem(sk: &SigningKey, namespace: &str, challenge: &[u8]) -> String {
    let msg_hash = Sha512::digest(challenge);
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"SSHSIG");
    push_ssh_str(&mut preimage, namespace.as_bytes());
    push_ssh_str(&mut preimage, b"");
    push_ssh_str(&mut preimage, b"sha512");
    push_ssh_str(&mut preimage, &msg_hash);
    let sig = sk.sign(&preimage);

    let mut pk_blob = Vec::new();
    push_ssh_str(&mut pk_blob, SSH_ED25519_ALG.as_bytes());
    push_ssh_str(&mut pk_blob, sk.verifying_key().as_bytes());

    let mut sig_blob = Vec::new();
    push_ssh_str(&mut sig_blob, SSH_ED25519_ALG.as_bytes());
    push_ssh_str(&mut sig_blob, &sig.to_bytes());

    let mut outer = Vec::new();
    outer.extend_from_slice(b"SSHSIG");
    outer.extend_from_slice(&1u32.to_be_bytes());
    push_ssh_str(&mut outer, &pk_blob);
    push_ssh_str(&mut outer, namespace.as_bytes());
    push_ssh_str(&mut outer, b"");
    push_ssh_str(&mut outer, b"sha512");
    push_ssh_str(&mut outer, &sig_blob);

    format!(
        "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
        encode_base64(&outer)
    )
}

fn isolated_test_dir(slug: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ws_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let dir = ws_root
        .join("target")
        .join("test-workspaces")
        .join(format!("ag-c1-{}-{slug}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create test dir");
    dir
}

#[test]
fn operator_sshsig_accepts_standard_ed25519_and_up_zero_while_release_tags_require_fido2_up_one() {
    let sk = SigningKey::from_bytes(&[0x5au8; 32]);
    let pubkey = *sk.verifying_key().as_bytes();
    let challenge = b"dotagent:operator:v1:repo123:0:1795275600";

    // Release tags (`namespace = "git"`) strictly require `sk-*` FIDO2 with `UP=1`!
    let rel_up1 = mint_sk_sshsig_pem(&sk, b"ssh:dotagent", "git", b"tag v2.2.0", 0x01, 10);
    assert_eq!(release_signature_has_fido2_touch(&rel_up1), Ok(true));
    let rel_up0 = mint_sk_sshsig_pem(&sk, b"ssh:dotagent", "git", b"tag v2.2.0", 0x00, 11);
    assert_eq!(
        release_signature_has_fido2_touch(&rel_up0)
            .expect_err("v* release tag signature must reject UP=0")
            .code,
        "SSHSIG_USER_PRESENCE_REQUIRED"
    );
    let rel_std = mint_ssh_ed25519_sshsig_pem(&sk, "git", b"tag v2.2.0");
    assert_eq!(release_signature_has_fido2_touch(&rel_std), Ok(false));

    // Operator / plugin / CLI gates accept `sk-*` (`UP=1` and `UP=0`) AND standard `ssh-ed25519`!
    let pem_up1 = mint_sk_sshsig_pem(
        &sk,
        b"ssh:dotagent",
        OPERATOR_SSHSIG_NAMESPACE,
        challenge,
        0x01,
        77,
    );
    let cnt =
        verify_fido2_sshsig_ed25519(OPERATOR_SSHSIG_NAMESPACE, challenge, &pem_up1, &[pubkey])
            .expect("UP=1 sk-ssh-ed25519 must verify");
    assert_eq!(cnt, 77);

    let pem_up0 = mint_sk_sshsig_pem(
        &sk,
        b"ssh:dotagent",
        OPERATOR_SSHSIG_NAMESPACE,
        challenge,
        0x00,
        78,
    );
    let cnt_up0 =
        verify_fido2_sshsig_ed25519(OPERATOR_SSHSIG_NAMESPACE, challenge, &pem_up0, &[pubkey])
            .expect("UP=0 sk-ssh-ed25519 without touch must verify for operator gate");
    assert_eq!(cnt_up0, 78);

    let pem_std = mint_ssh_ed25519_sshsig_pem(&sk, OPERATOR_SSHSIG_NAMESPACE, challenge);
    let cnt_std =
        verify_fido2_sshsig_ed25519(OPERATOR_SSHSIG_NAMESPACE, challenge, &pem_std, &[pubkey])
            .expect("standard ssh-ed25519 must verify for operator gate");
    assert_eq!(cnt_std, 0);

    let base = isolated_test_dir("keyring");
    let cfg = base.join(".config/dotagent");
    fs::create_dir_all(&cfg).expect("cfg dir");
    let mut std_blob = Vec::new();
    push_ssh_str(&mut std_blob, SSH_ED25519_ALG.as_bytes());
    push_ssh_str(&mut std_blob, &pubkey);
    fs::write(
        cfg.join("operator_sk_keys"),
        format!(
            "operator@host namespaces=\"git\" {SSH_ED25519_ALG} {}\n",
            encode_base64(&std_blob)
        ),
    )
    .expect("write operator_sk_keys");
    let loaded = load_operator_sk_keys_from_home(&base)
        .expect("parse keyring")
        .expect("present");
    assert_eq!(loaded, vec![pubkey]);
    assert_eq!(
        load_operator_or_ssh_keys_from_home(&base)
            .expect("fallback loader")
            .expect("present"),
        vec![pubkey]
    );
}

#[test]
fn nested_apps_web_dotenv_returns_eacces_under_landlock() {
    let base = isolated_test_dir("nested-dotenv");
    let repo = base.join("repo");
    let home = base.join("home");
    fs::create_dir_all(repo.join(".git")).expect(".git");
    fs::create_dir_all(repo.join("apps/web/src")).expect("apps/web/src");
    fs::create_dir_all(&home).expect("home");
    fs::write(repo.join("AGENTS.md"), "# AGENTS.md\n").expect("AGENTS.md");
    fs::write(repo.join("apps/web/src/app.ts"), "export const v = 1;\n").expect("app.ts");
    let env_name = format!("{}{}", ".", "env");
    fs::write(repo.join("apps/web").join(&env_name), "PORT_CFG=9090\n").expect("nested env");

    let bin = env!("CARGO_BIN_EXE_agent-guard");
    let ok_out = Command::new(bin)
        .args(["exec-sandbox", "--cwd"])
        .arg(&repo)
        .args(["--", "cat apps/web/src/app.ts"])
        .env("HOME", &home)
        .output()
        .expect("run clean sibling read");
    assert!(ok_out.status.success(), "clean sibling read must succeed");

    if probe_host_sandbox_mode().is_kernel_enforced() {
        let cmd_str = format!("cat apps/web/{env_name}");
        let blocked = Command::new(bin)
            .args(["exec-sandbox", "--require-kernel", "--cwd"])
            .arg(&repo)
            .args(["--", &cmd_str])
            .env("HOME", &home)
            .output()
            .expect("run nested dotenv read");
        assert!(
            !blocked.status.success(),
            "nested dotenv read must fail under Landlock"
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&blocked.stdout),
            String::from_utf8_lossy(&blocked.stderr)
        );
        assert!(!combined.contains("PORT_CFG=9090"));
        let lc = combined.to_ascii_lowercase();
        assert!(
            lc.contains("permission denied") || lc.contains("operation not permitted"),
            "combined={combined}"
        );
    }
}

#[test]
fn git_config_unlink_creat_inside_sandbox_is_atomically_restored_and_exits_2() {
    let base = isolated_test_dir("git-cfg-restore");
    let repo = base.join("repo");
    let home = base.join("home");
    let local_bin = home.join(".local/bin");
    fs::create_dir_all(repo.join(".git/objects")).expect(".git/objects");
    fs::create_dir_all(&local_bin).expect(".local/bin");
    fs::write(repo.join("AGENTS.md"), "# AGENTS.md\n").expect("AGENTS.md");

    let orig_cfg = b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n";
    let cfg_path = repo.join(".git/config");
    fs::write(&cfg_path, orig_cfg).expect("write .git/config");

    let fake_git = local_bin.join("git");
    fs::write(
        &fake_git,
        "#!/bin/sh\nrm -f .git/config\nprintf '[core]\\n\\thooksPath = /evil\\n' > .git/objects/forged\nmv -f .git/objects/forged .git/config 2>/dev/null || touch .git/config\nexit 0\n",
    )
    .expect("write fake git");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&fake_git, fs::Permissions::from_mode(0o755)).expect("chmod 0755");
    }

    let orig_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{orig_path}", local_bin.display());
    let bin = env!("CARGO_BIN_EXE_agent-guard");
    let out = Command::new(bin)
        .args(["exec-sandbox", "--cwd"])
        .arg(&repo)
        .args(["--", "git status"])
        .env("HOME", &home)
        .env("PATH", new_path)
        .output()
        .expect("run sandboxed git tamper");

    #[cfg(not(target_os = "macos"))]
    {
        assert_eq!(
            out.status.code(),
            Some(2),
            "must exit 2 on .git/config tamper"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("GIT_CONFIG_TAMPERED"), "stderr={stderr}");
    }
    #[cfg(target_os = "macos")]
    {
        let _ = out;
    }
    let restored = fs::read(&cfg_path).expect("read restored .git/config");
    assert_eq!(
        restored, orig_cfg,
        ".git/config must remain byte-for-byte intact"
    );
}
