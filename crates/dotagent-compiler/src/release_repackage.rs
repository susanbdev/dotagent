//! Assemble the verified release once for downstream publication adapters.

use crate::release_archive::{ReleaseTree, read_release};
use crate::release_ecosystem::{build_wheels_and_npm, npm_metadata};
use crate::release_installers::build_installers;
use crate::release_verify::{hash_file, read_regular};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const TARGETS: [&str; 4] = [
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-musl",
];
const MAX_ASSET_SIZE: u64 = 256 * 1024 * 1024;
const USAGE: &str = "repackage-release --archives DIR --tag TAG --signers PEM --out NEW_DIR [--repo-root DIR] [--license SPDX] [--nfpm PATH]";

pub(crate) fn run_cli(args: &[String]) -> ExitCode {
    if args == ["--help"] {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    report(repackage(args))
}

pub(crate) fn npm_cli(args: &[String]) -> ExitCode {
    let [path] = args else {
        return report(Err("release-npm-metadata ARCHIVE".to_owned()));
    };
    report(npm_metadata(Path::new(path)).map(|(name, version)| {
        println!("{name}\n{version}");
    }))
}

fn report(result: Result<(), String>) -> ExitCode {
    if let Err(error) = result {
        eprintln!("[dotagent-compiler RELEASE DENIED] {error}");
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

fn repackage(args: &[String]) -> Result<(), String> {
    let mut options = BTreeMap::new();
    let (pairs, leftovers) = args.as_chunks::<2>();
    for [flag, value] in pairs {
        let flag = flag.as_str();
        if !matches!(
            flag,
            "--archives" | "--tag" | "--signers" | "--out" | "--repo-root" | "--license" | "--nfpm"
        ) || value.is_empty()
            || options.insert(flag, value.as_str()).is_some()
        {
            return Err(format!("invalid release option {flag:?}; {USAGE}"));
        }
    }
    if !leftovers.is_empty() {
        return Err(USAGE.to_owned());
    }
    let required = |flag| {
        options
            .get(flag)
            .copied()
            .ok_or_else(|| format!("missing {flag}; {USAGE}"))
    };
    let tag = required("--tag")?;
    let version = stable_version(tag)?;
    let license = options
        .get("--license")
        .copied()
        .unwrap_or("LicenseRef-Proprietary");
    if license.is_empty()
        || license.len() > 256
        || !license
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-.+() ".contains(&b))
    {
        return Err("invalid release license expression".to_owned());
    }
    let archives = existing_dir(Path::new(required("--archives")?))?;
    let repo = existing_dir(Path::new(
        options.get("--repo-root").copied().unwrap_or("."),
    ))?;
    let signers = Path::new(required("--signers")?);
    let nfpm = options.get("--nfpm").map(Path::new);
    let out = Path::new(required("--out")?);
    let name = out
        .file_name()
        .ok_or_else(|| "release output must name a new directory".to_owned())?;
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let out = existing_dir(parent)?.join(name);
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(&out)
        .map_err(|e| format!("create new release output {}: {e}", out.display()))?;
    let bundle = out.join("bundle");
    fs::create_dir(&bundle).map_err(|e| format!("create release bundle: {e}"))?;

    let mut trees = BTreeMap::new();
    let mut digests = BTreeMap::new();
    let mut assets = BTreeMap::new();
    for target in TARGETS {
        let name = format!("dotagent-{tag}-{target}.tar.gz");
        let snapshot = bundle.join(&name);
        copy_asset(&archives.join(&name), &snapshot)?;
        trees.insert(target.to_owned(), read_release(&snapshot, tag, target)?);
        let digest = hash_file(&snapshot)?;
        digests.insert(target.to_owned(), digest.clone());
        assets.insert(name, digest);
    }
    check_parity(&trees)?;
    let mut outputs = build_wheels_and_npm(&out, version, license, &trees)?;
    outputs.extend(build_installers(
        &out, &repo, tag, version, license, signers, &digests, &trees, nfpm,
    )?);
    for asset in outputs {
        let name = asset
            .file_name()
            .and_then(|s| s.to_str())
            .filter(|s| {
                s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
                    && *s != "SHA256SUMS"
            })
            .ok_or_else(|| format!("invalid release output name {}", asset.display()))?;
        let parent = existing_dir(
            asset
                .parent()
                .ok_or_else(|| "release asset has no parent".to_owned())?,
        )?;
        if !parent.starts_with(&out) || parent == bundle {
            return Err(format!(
                "release asset is outside channel output: {}",
                asset.display()
            ));
        }
        let snapshot = bundle.join(name);
        copy_asset(&asset, &snapshot)?;
        assets.insert(name.to_owned(), hash_file(&snapshot)?);
    }

    let mut sums = Vec::new();
    for (name, digest) in &assets {
        writeln!(sums, "{digest}  {name}").map_err(|e| e.to_string())?;
    }
    for dir in [&out, &bundle] {
        let path = dir.join("SHA256SUMS");
        new_file(&path)?
            .write_all(&sums)
            .map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    println!(
        "Assembled {} verified release assets in {}",
        assets.len(),
        bundle.display()
    );
    Ok(())
}

fn stable_version(tag: &str) -> Result<&str, String> {
    tag.strip_prefix('v')
        .filter(|version| {
            version.len() <= 63
                && version.split('.').count() == 3
                && version.split('.').all(|part| {
                    !part.is_empty()
                        && (part == "0" || !part.starts_with('0'))
                        && part.bytes().all(|b| b.is_ascii_digit())
                })
        })
        .ok_or_else(|| "ecosystem release tag must look like v1.2.3".to_owned())
}

fn check_parity(trees: &BTreeMap<String, ReleaseTree>) -> Result<(), String> {
    fn shared(tree: &ReleaseTree) -> impl Iterator<Item = (&String, &(Vec<u8>, bool))> {
        tree.iter().filter(|(path, _)| {
            ["dist/", "profiles/", "skills/"]
                .iter()
                .any(|prefix| path.starts_with(prefix))
        })
    }
    let (first_target, first) = trees
        .first_key_value()
        .ok_or_else(|| "no platform release archives".to_owned())?;
    if !first.keys().any(|entry| entry.starts_with("dist/")) {
        return Err("release archives contain no dist tree".to_owned());
    }
    for (target, tree) in trees.iter().skip(1) {
        if !shared(first).eq(shared(tree)) {
            return Err(format!(
                "shared trees differ between {first_target} and {target}"
            ));
        }
    }
    Ok(())
}

fn existing_dir(path: &Path) -> Result<PathBuf, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|e| format!("inspect {}: {e}", path.display()))?;
    if !metadata.is_dir() {
        return Err(format!("expected a real directory: {}", path.display()));
    }
    path.canonicalize()
        .map_err(|e| format!("resolve {}: {e}", path.display()))
}

fn new_file(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))
}

fn copy_asset(source: &Path, destination: &Path) -> Result<(), String> {
    read_regular(source, |input| {
        let expected = input.metadata()?.len();
        if expected == 0 || expected > MAX_ASSET_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected a bounded nonempty release asset",
            ));
        }
        let mut output = new_file(destination).map_err(io::Error::other)?;
        if io::copy(&mut input.take(expected + 1), &mut output)? != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "asset changed during snapshot",
            ));
        }
        Ok(())
    })
}
