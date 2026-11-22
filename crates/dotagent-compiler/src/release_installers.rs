use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, FileTimes};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::release_archive::ReleaseTree;

const EPOCH: u64 = 1_700_000_000;
const MAX_SYSTEM_PACKAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const REPO_URL: &str = "https://github.com/susanbdev/dotagent";
const INSTALLER_EOF: &str = "dotagent_bootstrap \"$@\" --eof-v1\n";
const BINARIES: &[&str] = &[
    "dotagent",
    "agent-guard",
    "agent-guard-sh",
    "dotagent-compiler",
    "swarm-tool",
    "dotagent-harness",
];
const INSTALLER_DIGESTS: &[(&str, &str)] = &[
    (
        "x86_64-unknown-linux-musl",
        "SHA256_X86_64_UNKNOWN_LINUX_MUSL",
    ),
    (
        "aarch64-unknown-linux-musl",
        "SHA256_AARCH64_UNKNOWN_LINUX_MUSL",
    ),
    ("x86_64-apple-darwin", "SHA256_X86_64_APPLE_DARWIN"),
    ("aarch64-apple-darwin", "SHA256_AARCH64_APPLE_DARWIN"),
];
const SYSTEM_TARGETS: &[(&str, &str)] = &[
    ("aarch64-unknown-linux-musl", "arm64"),
    ("x86_64-unknown-linux-musl", "amd64"),
];
const P256_SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_installers(
    out: &Path,
    repo_root: &Path,
    tag: &str,
    version: &str,
    license: &str,
    signer: &Path,
    digests: &BTreeMap<String, String>,
    trees: &BTreeMap<String, ReleaseTree>,
    nfpm: Option<&Path>,
) -> Result<Vec<PathBuf>, String> {
    if tag.strip_prefix('v') != Some(version)
        || version.split('.').count() != 3
        || !version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("release tag must look like v1.2.3 and match the version".into());
    }
    if license.is_empty()
        || !license
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" ._+-()".contains(&b))
    {
        return Err("invalid release license identifier".into());
    }
    let out_meta =
        fs::symlink_metadata(out).map_err(|e| format!("output '{}': {e}", out.display()))?;
    if !out_meta.is_dir() {
        return Err(format!(
            "output '{}' must be a regular directory",
            out.display()
        ));
    }
    let repo = fs::canonicalize(repo_root).map_err(|e| format!("release repository: {e}"))?;
    let out = fs::canonicalize(out).map_err(|e| format!("release output: {e}"))?;
    let packaging = repo.join("packaging");
    let signer_spki = parse_signer_pem(&read_ascii(signer, 16_384)?)?;
    let template = read_ascii(&packaging.join("install.sh.in"), 262_144)?;
    let installer = render_installer(&template, tag, digests, &signer_spki)?;
    check_bash_syntax(&installer)?;
    let formula = render_formula(version, tag, license, digests)?;

    for dir in ["web", "brew", "sys"] {
        fs::create_dir(out.join(dir))
            .map_err(|e| format!("create release directory '{dir}': {e}"))?;
    }
    let installer_path = out.join("web/install.sh");
    let formula_path = out.join("brew/dotagent.rb");
    write_file(&installer_path, installer.as_bytes(), 0o644)?;
    write_file(&formula_path, formula.as_bytes(), 0o644)?;
    let mut outputs = vec![installer_path, formula_path];
    let Some(nfpm) = select_nfpm(nfpm, &repo, &out)? else {
        eprintln!("[repackage] nfpm not found: skipping .deb/.rpm/.apk");
        return Ok(outputs);
    };
    let config = read_ascii(&packaging.join("nfpm.yaml"), 65_536)?;
    outputs.extend(build_system(
        &out.join("sys"),
        version,
        trees,
        &nfpm,
        &config,
    )?);
    Ok(outputs)
}

fn read_ascii(path: &Path, max_bytes: u64) -> Result<String, String> {
    let io_error = |e| format!("{}: {e}", path.display());
    let meta = fs::symlink_metadata(path).map_err(io_error)?;
    if !meta.is_file() || meta.len() > max_bytes {
        return Err(format!(
            "'{}' must be a bounded regular file",
            path.display()
        ));
    }
    let mut options = File::options();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Refuse a replaced link and avoid blocking if the path becomes a FIFO.
        let flags = if cfg!(target_os = "macos") {
            0x0100 | 0x4
        } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
            0o100000 | 0o4000
        } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            0o400000 | 0o4000
        } else {
            0
        };
        options.custom_flags(flags);
    }
    let file = options.open(path).map_err(io_error)?;
    let opened = file.metadata().map_err(io_error)?;
    if !opened.is_file() || opened.len() > max_bytes {
        return Err(format!("'{}' changed while opening", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != meta.dev() || opened.ino() != meta.ino() {
            return Err(format!("'{}' changed while opening", path.display()));
        }
    }
    let mut data = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut data)
        .map_err(io_error)?;
    if data.len() as u64 > max_bytes
        || !data.is_ascii()
        || data.iter().any(|b| matches!(b, 0 | b'\r' | 0x1b))
    {
        return Err(format!(
            "'{}' must be bounded 7-bit ASCII without NUL, CR, or ESC",
            path.display()
        ));
    }
    String::from_utf8(data).map_err(|_| format!("'{}' must be ASCII", path.display()))
}

fn parse_signer_pem(text: &str) -> Result<String, String> {
    let mut lines = text
        .lines()
        .map(str::trim)
        .skip_while(|line| line.is_empty() || line.starts_with('#'));
    if lines.next() != Some("-----BEGIN PUBLIC KEY-----") {
        return Err("release signer must be a PEM PUBLIC KEY block".into());
    }
    let mut body = String::new();
    for line in lines.by_ref() {
        if line == "-----END PUBLIC KEY-----" {
            let der = STANDARD
                .decode(&body)
                .map_err(|_| "malformed PEM base64 in signers file")?;
            if der.len() != 91 || !der.starts_with(P256_SPKI_PREFIX) {
                return Err("release signer must be an ECDSA P-256 SPKI public key".into());
            }
            if lines.any(|line| !line.is_empty() && !line.starts_with('#')) {
                return Err("release signer must contain exactly one PEM PUBLIC KEY block".into());
            }
            return Ok(STANDARD.encode(der));
        }
        if line.is_empty()
            || !line
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
        {
            return Err("malformed PEM body in signers file".into());
        }
        body.push_str(line);
    }
    Err("no complete PEM PUBLIC KEY block found in signers file".into())
}

fn digest_for<'a>(digests: &'a BTreeMap<String, String>, target: &str) -> Result<&'a str, String> {
    let value = digests
        .get(target)
        .ok_or_else(|| format!("missing archive digest for '{target}'"))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!("invalid archive digest for '{target}'"));
    }
    Ok(value)
}

fn render_installer(
    template: &str,
    tag: &str,
    digests: &BTreeMap<String, String>,
    signer: &str,
) -> Result<String, String> {
    let mut text = template
        .replace("@RELEASE_TAG@", tag)
        .replace("@SIGNER_SPKI@", signer);
    for (target, name) in INSTALLER_DIGESTS {
        text = text.replace(&format!("@{name}@"), digest_for(digests, target)?);
    }
    let mut parts = text.split('@').skip(1).peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_some()
            && part.len() >= 3
            && part
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(format!("unrendered installer placeholder: {part}"));
        }
    }
    if !text.ends_with(INSTALLER_EOF) || text.matches(INSTALLER_EOF).count() != 1 {
        return Err("install.sh must end with a single EOF function gate".into());
    }
    Ok(text)
}

fn check_bash_syntax(text: &str) -> Result<(), String> {
    let bash = Path::new("/bin/bash");
    if !bash.is_file() {
        return Ok(());
    }
    let mut child = Command::new(bash)
        .arg("-n")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("run bash -n: {e}"))?;
    let written = child
        .stdin
        .take()
        .ok_or("bash -n stdin is unavailable")?
        .write_all(text.as_bytes());
    let status = child.wait().map_err(|e| format!("wait for bash -n: {e}"))?;
    if !status.success() {
        return Err("rendered install.sh fails bash -n".into());
    }
    written.map_err(|e| format!("write rendered install.sh to bash -n: {e}"))
}

fn render_formula(
    version: &str,
    tag: &str,
    license: &str,
    digests: &BTreeMap<String, String>,
) -> Result<String, String> {
    let license = if license.starts_with("LicenseRef") {
        ":cannot_represent".to_string()
    } else {
        format!("\"{license}\"")
    };
    let mut text = format!(
        "class Dotagent < Formula\n  desc \"Zero-trust guard, compiler and harness for AI coding agents\"\n  homepage \"https://susanb.dev/dotagent\"\n  version \"{version}\"\n  license {license}\n"
    );
    for (os, arm, intel) in [
        ("macos", "aarch64-apple-darwin", "x86_64-apple-darwin"),
        (
            "linux",
            "aarch64-unknown-linux-musl",
            "x86_64-unknown-linux-musl",
        ),
    ] {
        text.push_str(&format!("\n  on_{os} do\n"));
        for (arch, target) in [("arm", arm), ("intel", intel)] {
            let digest = digest_for(digests, target)?;
            text.push_str(&format!("    on_{arch} do\n      url \"{REPO_URL}/releases/download/{tag}/dotagent-{tag}-{target}.tar.gz\"\n      sha256 \"{digest}\"\n    end\n"));
        }
        text.push_str("  end\n");
    }
    text.push_str("\n  def install\n    root = Dir[\"dotagent-*\"].find { |p| File.directory?(p) } || \".\"\n    libexec.install Dir[\"#{root}/*\"]\n");
    for bin in BINARIES {
        text.push_str(&format!("    bin.install_symlink libexec/\"bin/{bin}\"\n"));
    }
    text.push_str(
        "  end\n\n  test do\n    assert_predicate bin/\"dotagent\", :executable?\n  end\nend\n",
    );
    Ok(text)
}

fn select_nfpm(
    explicit: Option<&Path>,
    repo: &Path,
    out: &Path,
) -> Result<Option<PathBuf>, String> {
    let resolve = |path: &Path| {
        let program = fs::canonicalize(path).ok()?;
        let meta = program.metadata().ok()?;
        if !meta.is_file() || program.starts_with(repo) || program.starts_with(out) {
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o111 == 0 {
                return None;
            }
        }
        Some(program)
    };
    if let Some(path) = explicit {
        return resolve(path).map(Some).ok_or_else(|| {
            format!(
                "nfpm '{}' must be an executable outside the release checkout and output",
                path.display()
            )
        });
    }
    Ok(std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .filter(|dir| dir.is_absolute())
            .find_map(|dir| resolve(&dir.join("nfpm")))
    }))
}

fn build_system(
    sys_dir: &Path,
    version: &str,
    trees: &BTreeMap<String, ReleaseTree>,
    nfpm: &Path,
    config: &str,
) -> Result<Vec<PathBuf>, String> {
    let mut outputs = Vec::new();
    for (target, arch) in SYSTEM_TARGETS {
        let files = trees
            .get(*target)
            .ok_or_else(|| format!("missing release tree for '{target}'"))?;
        let scratch = sys_dir.join(format!(".nfpm-{arch}"));
        fs::create_dir(&scratch).map_err(|e| format!("create nfpm staging directory: {e}"))?;
        let stage = scratch.join("opt/dotagent");
        let mut directories = BTreeSet::new();
        let result = (|| {
            File::open(&scratch)
                .and_then(|file| set_mode(&file, 0o700))
                .map_err(|e| format!("secure nfpm staging directory: {e}"))?;
            stage_system_tree(&stage, files, &mut directories)?;
            let config_path = scratch.join("nfpm.yaml");
            // nfpm does not interpolate the source path in contents entries.
            let stage_path = stage
                .to_str()
                .filter(|path| !path.chars().any(char::is_control))
                .ok_or("nfpm stage path must be UTF-8 without control characters")?;
            let stage_yaml = format!("'{}'", stage_path.replace('\'', "''"));
            let rendered = config
                .replace("${NFPM_VERSION}", version)
                .replace("${NFPM_ARCH}", arch)
                .replace("${NFPM_STAGE}", &stage_yaml);
            write_file(&config_path, rendered.as_bytes(), 0o444)?;
            for format in ["deb", "rpm", "apk"] {
                outputs.push(run_nfpm(
                    nfpm,
                    sys_dir,
                    &scratch,
                    &stage,
                    &config_path,
                    version,
                    arch,
                    format,
                )?);
            }
            Ok::<(), String>(())
        })();
        // Thaw only the directories created and sealed by this invocation.
        let mut cleanup = Ok(());
        for dir in directories {
            if fs::canonicalize(&dir).ok().as_deref() == Some(dir.as_path())
                && let Err(e) = File::open(&dir).and_then(|file| set_mode(&file, 0o755))
            {
                cleanup = Err(format!(
                    "thaw nfpm staging directory '{}': {e}",
                    dir.display()
                ));
                break;
            }
        }
        let removed =
            fs::remove_dir_all(&scratch).map_err(|e| format!("remove nfpm staging directory: {e}"));
        result?;
        cleanup?;
        removed?;
    }
    Ok(outputs)
}

fn stage_system_tree(
    stage: &Path,
    files: &ReleaseTree,
    directories: &mut BTreeSet<PathBuf>,
) -> Result<(), String> {
    fs::create_dir_all(stage).map_err(|e| format!("create system staging tree: {e}"))?;
    directories.insert(stage.to_path_buf());
    for (relative, (data, _)) in files {
        let path = Path::new(relative);
        let Some(first) = path.iter().next() else {
            return Err("empty system staging path".into());
        };
        if !path.components().all(|c| matches!(c, Component::Normal(_))) {
            return Err(format!("invalid system staging path '{relative}'"));
        }
        if relative.contains('/')
            && !matches!(first.to_str(), Some("bin" | "dist" | "profiles" | "skills"))
        {
            continue;
        }
        let output = stage.join(path);
        let parent = output.parent().ok_or("system staging path has no parent")?;
        fs::create_dir_all(parent).map_err(|e| format!("create system staging parent: {e}"))?;
        directories.extend(
            parent
                .ancestors()
                .take_while(|dir| dir.starts_with(stage))
                .map(Path::to_path_buf),
        );
        write_file(
            &output,
            data,
            if relative.starts_with("bin/") {
                0o555
            } else {
                0o444
            },
        )?;
    }
    for dir in directories.iter().rev() {
        let opened = File::open(dir)
            .map_err(|e| format!("open system staging directory '{}': {e}", dir.display()))?;
        set_epoch(&opened)
            .and_then(|()| set_mode(&opened, 0o555))
            .map_err(|e| format!("seal system staging directory '{}': {e}", dir.display()))?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_nfpm(
    nfpm: &Path,
    sys_dir: &Path,
    scratch: &Path,
    stage: &Path,
    config: &Path,
    version: &str,
    arch: &str,
    format: &str,
) -> Result<PathBuf, String> {
    let target = scratch.join(format);
    fs::create_dir(&target).map_err(|e| format!("create nfpm output directory: {e}"))?;
    let status = Command::new(nfpm)
        .args(["package", "--packager", format, "--config"])
        .arg(config)
        .arg("--target")
        .arg(&target)
        .current_dir(scratch)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", scratch)
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("NFPM_VERSION", version)
        .env("NFPM_ARCH", arch)
        .env("NFPM_STAGE", stage)
        .env("SOURCE_DATE_EPOCH", EPOCH.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .map_err(|e| format!("start nfpm {format} for {arch}: {e}"))?;
    if !status.success() {
        return Err(format!("nfpm {format} for {arch} failed: {status}"));
    }
    if !fs::symlink_metadata(&target).is_ok_and(|meta| meta.is_dir())
        || fs::canonicalize(&target).ok().as_deref() != Some(target.as_path())
    {
        return Err(format!(
            "nfpm output directory changed for {arch} .{format}"
        ));
    }
    let mut packages = fs::read_dir(&target).map_err(|e| format!("read nfpm output: {e}"))?;
    let artifact = packages
        .next()
        .transpose()
        .map_err(|e| format!("inspect nfpm output: {e}"))?
        .ok_or_else(|| format!("nfpm did not produce a {format} for {arch}"))?;
    let artifact_meta =
        fs::symlink_metadata(artifact.path()).map_err(|e| format!("stat nfpm output: {e}"))?;
    let name = artifact.file_name();
    if packages.next().is_some()
        || !artifact_meta.is_file()
        || artifact_meta.len() == 0
        || artifact_meta.len() > MAX_SYSTEM_PACKAGE_BYTES
        || !name.to_str().is_some_and(|name| {
            name.starts_with("dotagent")
                && name.len() <= 180
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        })
        || artifact.path().extension().and_then(|ext| ext.to_str()) != Some(format)
    {
        return Err(format!(
            "expected one regular dotagent .{format} package for {arch}"
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if artifact_meta.nlink() != 1 {
            return Err(format!(
                "unexpected hard link in nfpm output for {arch} .{format}"
            ));
        }
    }
    let output = sys_dir.join(name);
    fs::hard_link(artifact.path(), &output)
        .map_err(|e| format!("publish local system package '{}': {e}", output.display()))?;
    Ok(output)
}

fn write_file(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("create '{}': {e}", path.display()))?;
    file.write_all(data)
        .and_then(|()| set_epoch(&file))
        .and_then(|()| set_mode(&file, mode))
        .map_err(|e| format!("write '{}': {e}", path.display()))
}

fn set_epoch(file: &File) -> std::io::Result<()> {
    let epoch = UNIX_EPOCH + Duration::from_secs(EPOCH);
    file.set_times(FileTimes::new().set_accessed(epoch).set_modified(epoch))
}

fn set_mode(file: &File, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    let permissions = {
        use std::os::unix::fs::PermissionsExt;
        fs::Permissions::from_mode(mode)
    };
    #[cfg(not(unix))]
    let permissions = {
        let mut permissions = file.metadata()?.permissions();
        permissions.set_readonly(mode & 0o200 == 0);
        permissions
    };
    file.set_permissions(permissions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_is_p256_spki_and_has_a_single_authority() {
        let signer = include_str!("../../../packaging/release-signer.pub");
        let canonical = parse_signer_pem(signer).expect("P-256 release signer");
        assert!(!canonical.contains('\n'));
        assert_eq!(STANDARD.decode(canonical).unwrap().len(), 91);
        assert!(parse_signer_pem(&format!("{signer}\n{signer}")).is_err());
        let not_p256 = STANDARD.encode([0; 91]);
        assert!(
            parse_signer_pem(&format!(
                "-----BEGIN PUBLIC KEY-----\n{not_p256}\n-----END PUBLIC KEY-----\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn installer_and_formula_preserve_release_layout() {
        let digests = INSTALLER_DIGESTS
            .iter()
            .enumerate()
            .map(|(n, (target, _))| (target.to_string(), format!("{n:064x}")))
            .collect();
        let template = include_str!("../../../packaging/install.sh.in");
        let signer =
            parse_signer_pem(include_str!("../../../packaging/release-signer.pub")).unwrap();
        let installer = render_installer(template, "v9.9.9", &digests, &signer).unwrap();
        assert!(installer.ends_with(INSTALLER_EOF));
        assert!(installer.contains(&format!("DOTAGENT_SIGNER_SPKI='{signer}'")));
        assert!(
            render_installer(
                &format!("@LEFTOVER@\n{template}"),
                "v9.9.9",
                &digests,
                &signer
            )
            .is_err()
        );
        check_bash_syntax(&installer).unwrap();

        let formula =
            render_formula("9.9.9", "v9.9.9", "LicenseRef-Proprietary", &digests).unwrap();
        assert!(formula.contains("license :cannot_represent"));
        assert_eq!(
            formula.matches("bin.install_symlink").count(),
            BINARIES.len()
        );
        for (target, digest) in digests {
            assert!(formula.contains(&format!(
                "dotagent-v9.9.9-{target}.tar.gz\"\n      sha256 \"{digest}\""
            )));
        }
    }
}
