use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, Write};
use std::path::{Path, PathBuf};

use agent_guard::crypto::sha256_bytes;
use agent_guard::json::JsonValue;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use flate2::{Compression, GzBuilder};
use tar::{Builder, EntryType, Header};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipWriter};

use crate::release_archive::{ReleaseTree, read_rooted_archive};

const NPM_SCOPE: &str = "@susanbdev/dotagent";
const SUMMARY: &str = "Zero-trust guard, compiler and harness for AI coding agents";
const HOMEPAGE: &str = "https://susanb.dev/dotagent";
const REPO_URL: &str = "https://github.com/susanbdev/dotagent";
const TARBALL_EPOCH: u64 = 1_700_000_000;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const BINARIES: [&str; 6] = [
    "dotagent",
    "agent-guard",
    "agent-guard-sh",
    "dotagent-compiler",
    "swarm-tool",
    "dotagent-harness",
];

struct Platform {
    target: &'static str,
    wheel: &'static str,
    os: &'static str,
    cpu: &'static str,
}

impl Platform {
    fn npm_suffix(&self) -> String {
        format!("{}-{}", self.os, self.cpu)
    }

    fn package_name(&self) -> String {
        format!("{NPM_SCOPE}-{}", self.npm_suffix())
    }
}

const PLATFORMS: [Platform; 4] = [
    Platform {
        target: "aarch64-apple-darwin",
        wheel: "macosx_11_0_arm64",
        os: "darwin",
        cpu: "arm64",
    },
    Platform {
        target: "aarch64-unknown-linux-musl",
        wheel: "musllinux_1_2_aarch64.manylinux_2_17_aarch64",
        os: "linux",
        cpu: "arm64",
    },
    Platform {
        target: "x86_64-apple-darwin",
        wheel: "macosx_10_12_x86_64",
        os: "darwin",
        cpu: "x64",
    },
    Platform {
        target: "x86_64-unknown-linux-musl",
        wheel: "musllinux_1_2_x86_64.manylinux_2_17_x86_64",
        os: "linux",
        cpu: "x64",
    },
];

struct Entry<'a> {
    name: String,
    data: Cow<'a, [u8]>,
    mode: u32,
}

impl<'a> Entry<'a> {
    fn bytes(name: String, data: &'a [u8], mode: u32) -> Self {
        Self {
            name,
            data: Cow::Borrowed(data),
            mode,
        }
    }

    fn text(name: String, data: String, mode: u32) -> Self {
        Self {
            name,
            data: Cow::Owned(data.into_bytes()),
            mode,
        }
    }
}

fn valid_version(version: &str) -> bool {
    version.len() <= 63
        && version.split('.').count() == 3
        && version.split('.').all(|part| {
            !part.is_empty()
                && (part == "0" || !part.starts_with('0'))
                && part.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn shared_file(path: &str) -> bool {
    path.split_once('/')
        .is_some_and(|(root, _)| matches!(root, "dist" | "profiles" | "skills"))
}

fn package_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains(['\\', ':'])
        && path.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

fn npm_filename(platform: Option<&Platform>, version: &str) -> String {
    match platform {
        Some(platform) => format!("susanbdev-dotagent-{}-{version}.tgz", platform.npm_suffix()),
        None => format!("susanbdev-dotagent-{version}.tgz"),
    }
}

pub(crate) fn build_wheels_and_npm(
    out: &Path,
    version: &str,
    license: &str,
    trees: &BTreeMap<String, ReleaseTree>,
) -> Result<Vec<PathBuf>, String> {
    if !valid_version(version) {
        return Err("ecosystem package version must have three numeric components".into());
    }
    if license.is_empty()
        || license.len() > 1024
        || !license.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err("ecosystem package license must be a printable ASCII line".into());
    }
    if trees.len() != PLATFORMS.len()
        || PLATFORMS
            .iter()
            .any(|platform| !trees.contains_key(platform.target))
    {
        return Err("ecosystem packaging needs the four supported release targets".into());
    }
    for files in trees.values() {
        if files.keys().any(|path| !package_relative_path(path)) {
            return Err("invalid relative ecosystem package path".into());
        }
        if BINARIES.iter().any(|binary| {
            files
                .get(&format!("bin/{binary}"))
                .is_none_or(|(data, _)| data.is_empty())
        }) {
            return Err("ecosystem package is missing a required binary".into());
        }
    }
    let output_error =
        |path: &Path, err: &dyn std::fmt::Display| format!("{}: {err}", path.display());
    if !out
        .symlink_metadata()
        .map_err(|err| output_error(out, &err))?
        .file_type()
        .is_dir()
    {
        return Err(format!(
            "{}: expected an existing output directory",
            out.display()
        ));
    }
    let pypi = out.join("pypi");
    let npm = out.join("npm");
    fs::create_dir(&pypi).map_err(|err| output_error(&pypi, &err))?;
    if let Err(err) = fs::create_dir(&npm) {
        let _ = fs::remove_dir(&pypi);
        return Err(output_error(&npm, &err));
    }

    let mut outputs = Vec::with_capacity(PLATFORMS.len() * 2 + 1);
    for platform in &PLATFORMS {
        let wheel = pypi.join(format!(
            "dotagent-{version}-py3-none-{}.whl",
            platform.wheel
        ));
        let file = new_file(&wheel).map_err(|err| output_error(&wheel, &err))?;
        write_wheel(file, version, license, platform, &trees[platform.target])
            .map_err(|err| output_error(&wheel, &err))?;
        outputs.push(wheel);
    }
    let npm_license = if license.starts_with("LicenseRef-") {
        "UNLICENSED"
    } else {
        license
    };
    for platform in &PLATFORMS {
        let path = npm.join(npm_filename(Some(platform), version));
        let entries = platform_npm(version, npm_license, platform, &trees[platform.target]);
        write_tgz(
            new_file(&path).map_err(|err| output_error(&path, &err))?,
            entries,
        )
        .map_err(|err| output_error(&path, &err))?;
        outputs.push(path);
    }
    let path = npm.join(npm_filename(None, version));
    write_tgz(
        new_file(&path).map_err(|err| output_error(&path, &err))?,
        root_npm(version, npm_license),
    )
    .map_err(|err| output_error(&path, &err))?;
    outputs.push(path);
    Ok(outputs)
}

fn new_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    options.open(path)
}

fn record_digest(data: &[u8]) -> String {
    format!("sha256={}", URL_SAFE_NO_PAD.encode(sha256_bytes(data)))
}

fn record_row(record: &mut String, name: &str, digest: &str, size: &str) {
    if name.contains([',', '"']) {
        let _ = writeln!(record, "\"{}\",{digest},{size}", name.replace('"', "\"\""));
    } else {
        let _ = writeln!(record, "{name},{digest},{size}");
    }
}

fn write_wheel<W: Write + Seek>(
    sink: W,
    version: &str,
    license: &str,
    platform: &Platform,
    files: &ReleaseTree,
) -> zip::result::ZipResult<W> {
    let data_dir = format!("dotagent-{version}.data");
    let info = format!("dotagent-{version}.dist-info");
    let metadata = format!(
        "Metadata-Version: 2.1\nName: dotagent\nVersion: {version}\nSummary: {SUMMARY}\n\
        Home-page: {HOMEPAGE}\nLicense: {license}\nProject-URL: Source, {REPO_URL}\n\
        Requires-Python: >=3.8\n\nPrebuilt dotagent binaries. Verify provenance with: \
        gh attestation verify <file> --owner susanbdev\n"
    );
    let mut wheel =
        String::from("Wheel-Version: 1.0\nGenerator: dotagent-repackage\nRoot-Is-Purelib: false\n");
    for tag in platform.wheel.split('.') {
        let _ = writeln!(wheel, "Tag: py3-none-{tag}");
    }

    let mut entries = Vec::new();
    for (relative, (data, _)) in files {
        if let Some(command) = relative.strip_prefix("bin/") {
            entries.push(Entry::bytes(
                format!("{data_dir}/scripts/{command}"),
                data,
                0o555,
            ));
        } else if shared_file(relative) {
            entries.push(Entry::bytes(
                format!("{data_dir}/data/share/dotagent/{relative}"),
                data,
                0o444,
            ));
        }
    }
    entries.push(Entry::text(format!("{info}/METADATA"), metadata, 0o444));
    entries.push(Entry::text(format!("{info}/WHEEL"), wheel, 0o444));
    let mut record = String::new();
    for entry in &entries {
        record_row(
            &mut record,
            &entry.name,
            &record_digest(&entry.data),
            &entry.data.len().to_string(),
        );
    }
    let record_name = format!("{info}/RECORD");
    record_row(&mut record, &record_name, "", "");
    entries.push(Entry::text(record_name, record, 0o444));

    let mut archive = ZipWriter::new(sink);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .compression_level(Some(9))
        .last_modified_time(
            DateTime::from_date_and_time(2023, 11, 14, 22, 13, 20)
                .expect("fixed valid ZIP timestamp"),
        );
    for entry in entries {
        archive.start_file(entry.name, options.unix_permissions(entry.mode))?;
        archive.write_all(&entry.data)?;
    }
    archive.finish()
}

fn string(value: impl Into<String>) -> JsonValue {
    JsonValue::Str(value.into())
}

fn object<'a>(entries: impl IntoIterator<Item = (&'a str, JsonValue)>) -> JsonValue {
    let values: BTreeMap<_, _> = entries.into_iter().collect();
    JsonValue::Object(
        values
            .into_iter()
            .map(|(name, value)| (name.to_string(), value))
            .collect(),
    )
}

fn package_map() -> JsonValue {
    let names: BTreeMap<_, _> = PLATFORMS
        .iter()
        .map(|platform| (platform.npm_suffix(), string(platform.package_name())))
        .collect();
    JsonValue::Object(names.into_iter().collect())
}

fn npm_manifest(version: &str, license: &str, platform: Option<&Platform>) -> String {
    let (name, description) = match platform {
        Some(platform) => (
            platform.package_name(),
            format!("{SUMMARY} ({} binaries)", platform.npm_suffix()),
        ),
        None => (NPM_SCOPE.into(), SUMMARY.into()),
    };
    let mut fields = vec![
        ("name", string(name)),
        ("version", string(version)),
        ("description", string(description)),
        ("license", string(license)),
        ("homepage", string(HOMEPAGE)),
        (
            "repository",
            object([
                ("type", string("git")),
                ("url", string(format!("git+{REPO_URL}.git"))),
            ]),
        ),
        ("publishConfig", object([("access", string("public"))])),
    ];
    if let Some(platform) = platform {
        fields.extend([
            ("os", JsonValue::Array(vec![string(platform.os)])),
            ("cpu", JsonValue::Array(vec![string(platform.cpu)])),
            (
                "files",
                JsonValue::Array(vec![string("bin/"), string("share/")]),
            ),
        ]);
    } else {
        let dependencies: BTreeMap<_, _> = PLATFORMS
            .iter()
            .map(|platform| (platform.package_name(), string(version)))
            .collect();
        fields.extend([
            (
                "bin",
                object(
                    BINARIES
                        .iter()
                        .map(|&binary| (binary, string(format!("bin/{binary}.js")))),
                ),
            ),
            ("files", JsonValue::Array(vec![string("bin/")])),
            ("engines", object([("node", string(">=18"))])),
            (
                "optionalDependencies",
                JsonValue::Object(dependencies.into_iter().collect()),
            ),
        ]);
    }
    format!("{}\n", object(fields).to_json_string())
}

fn platform_npm<'a>(
    version: &str,
    license: &str,
    platform: &Platform,
    files: &'a ReleaseTree,
) -> Vec<Entry<'a>> {
    let mut entries = vec![Entry::text(
        "package/package.json".into(),
        npm_manifest(version, license, Some(platform)),
        0o644,
    )];
    for (relative, (data, _)) in files {
        if relative.starts_with("bin/") {
            entries.push(Entry::bytes(format!("package/{relative}"), data, 0o755));
        } else if shared_file(relative) {
            entries.push(Entry::bytes(
                format!("package/share/dotagent/{relative}"),
                data,
                0o644,
            ));
        }
    }
    entries
}

fn root_npm(version: &str, license: &str) -> Vec<Entry<'static>> {
    let mut entries = vec![Entry::text(
        "package/package.json".into(),
        npm_manifest(version, license, None),
        0o644,
    )];
    let packages = package_map().to_json_string();
    for binary in BINARIES {
        entries.push(Entry::text(
            format!("package/bin/{binary}.js"),
            render_shim(binary, &packages),
            0o755,
        ));
    }
    entries
}

fn render_shim(binary: &str, packages: &str) -> String {
    format!(
        r#"#!/usr/bin/env node
"use strict";
const {{ spawnSync }} = require("node:child_process");
const path = require("node:path");
const PACKAGES = {packages};
const key = process.platform + "-" + process.arch;
const name = PACKAGES[key];
if (!name) {{
  process.stderr.write("dotagent: unsupported platform " + key + "\n");
  process.exit(2);
}}
let root;
try {{
  root = path.dirname(require.resolve(name + "/package.json"));
}} catch (err) {{
  process.stderr.write("dotagent: platform package " + name + " is not installed (optionalDependencies skipped?)\n");
  process.exit(2);
}}
const result = spawnSync(path.join(root, "bin", "{binary}"), process.argv.slice(2), {{ stdio: "inherit" }});
if (result.error) {{
  process.stderr.write(String(result.error) + "\n");
  process.exit(2);
}}
if (result.signal) {{
  process.kill(process.pid, result.signal);
}}
process.exit(result.status === null ? 1 : result.status);
"#
    )
}

fn write_tgz<W: Write>(sink: W, mut entries: Vec<Entry<'_>>) -> io::Result<W> {
    entries.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    let gzip = GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(sink, Compression::best());
    let mut archive = Builder::new(gzip);
    for entry in entries {
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        header.set_mode(entry.mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(TARBALL_EPOCH);
        header.set_size(entry.data.len() as u64);
        archive.append_data(&mut header, entry.name, entry.data.as_ref())?;
    }
    archive.into_inner()?.finish()
}

fn validate_npm_package_routing(
    manifest: &JsonValue,
    platform: Option<&Platform>,
    version: &str,
) -> Result<(), String> {
    if let Some(platform) = platform {
        for (property, expected) in [("os", platform.os), ("cpu", platform.cpu)] {
            let matches = manifest
                .get(property)
                .and_then(JsonValue::as_array)
                .is_some_and(|items| matches!(items, [item] if item.as_str() == Some(expected)));
            if !matches {
                return Err(format!(
                    "npm platform package has incorrect {property} metadata"
                ));
            }
        }
    } else {
        let binaries = manifest.get("bin");
        if binaries.and_then(JsonValue::as_object).map(<[_]>::len) != Some(BINARIES.len())
            || BINARIES.iter().any(|&binary| {
                binaries
                    .and_then(|entries| entries.get(binary))
                    .and_then(JsonValue::as_str)
                    != Some(format!("bin/{binary}.js").as_str())
            })
        {
            return Err("npm root package has incorrect executable aliases".into());
        }
        let dependencies = manifest.get("optionalDependencies");
        if dependencies.and_then(JsonValue::as_object).map(<[_]>::len) != Some(PLATFORMS.len())
            || PLATFORMS.iter().any(|platform| {
                dependencies
                    .and_then(|entries| entries.get(&platform.package_name()))
                    .and_then(JsonValue::as_str)
                    != Some(version)
            })
        {
            return Err("npm root package has incorrect platform dependencies".into());
        }
    }
    Ok(())
}

pub(crate) fn npm_metadata(path: &Path) -> Result<(String, String), String> {
    let files = read_rooted_archive(path, "package")?;
    let (manifest, _) = files
        .get("package.json")
        .ok_or_else(|| "missing npm package.json".to_string())?;
    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err("npm package.json exceeds the manifest size limit".into());
    }
    let text = std::str::from_utf8(manifest).map_err(|_| "npm package.json is not UTF-8")?;
    let values =
        JsonValue::parse(text).map_err(|err| format!("invalid npm package.json: {err}"))?;
    if values.as_object().is_none() {
        return Err("npm package.json must be an object".into());
    }
    if values.get("scripts").is_some() {
        return Err("npm release package must not supply lifecycle scripts".into());
    }
    let property = |name: &str| {
        values
            .get(name)
            .and_then(JsonValue::as_str)
            .ok_or_else(|| format!("npm package.json must have a string {name}"))
    };
    let name = property("name")?;
    let version = property("version")?;
    if !valid_version(version) {
        return Err("npm release package has an invalid version".into());
    }
    let platform = PLATFORMS
        .iter()
        .find(|platform| platform.package_name() == name);
    if name != NPM_SCOPE && platform.is_none() {
        return Err("unexpected npm release package name".into());
    }
    if path.file_name().and_then(|name| name.to_str())
        != Some(npm_filename(platform, version).as_str())
    {
        return Err("npm release filename does not match its package name and version".into());
    }
    let allowed = |name: &str| {
        name == "package.json"
            || match platform {
                Some(_) => {
                    name.starts_with("bin/")
                        || name
                            .strip_prefix("share/dotagent/")
                            .is_some_and(shared_file)
                }
                None => BINARIES
                    .iter()
                    .any(|binary| name == format!("bin/{binary}.js")),
            }
    };
    if files
        .keys()
        .any(|name| !package_relative_path(name) || !allowed(name))
    {
        return Err("unexpected file outside the npm release package layout".into());
    }
    for binary in BINARIES {
        let command = if platform.is_some() {
            format!("bin/{binary}")
        } else {
            format!("bin/{binary}.js")
        };
        if !files
            .get(&command)
            .is_some_and(|(data, executable)| !data.is_empty() && *executable)
        {
            return Err(format!(
                "npm release package is missing executable {command}"
            ));
        }
    }
    validate_npm_package_routing(&values, platform, version)?;
    Ok((name.to_string(), version.to_string()))
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    const VERSION: &str = "9.9.9";
    const LICENSE: &str = "LicenseRef-Proprietary";
    static SCRATCH_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let sequence = SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::current_dir().unwrap().join(format!(
                ".dotagent-release-ecosystem-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn folder(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::create_dir(&path).unwrap();
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn files() -> ReleaseTree {
        let mut files: ReleaseTree = BINARIES
            .iter()
            .map(|bin| (format!("bin/{bin}"), (b"abc".to_vec(), true)))
            .collect();
        files.insert("dist/manifest.txt".into(), (b"bundle\n".to_vec(), false));
        files
    }

    fn zip_text<R: Read + Seek>(archive: &mut zip::ZipArchive<R>, name: &str) -> String {
        let mut text = String::new();
        archive
            .by_name(name)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        text
    }

    #[test]
    fn ecosystem_outputs_are_reproducible_and_preserve_channel_formats() {
        let scratch = Scratch::new();
        let trees = PLATFORMS
            .iter()
            .map(|platform| (platform.target.to_string(), files()))
            .collect();
        let first = scratch.folder("first");
        let second = scratch.folder("second");
        let first_outputs = build_wheels_and_npm(&first, VERSION, LICENSE, &trees).unwrap();
        let second_outputs = build_wheels_and_npm(&second, VERSION, LICENSE, &trees).unwrap();
        assert_eq!(first_outputs.len(), 9);
        for (first_file, second_file) in first_outputs.iter().zip(second_outputs) {
            assert_eq!(first_file.file_name(), second_file.file_name());
            assert_eq!(
                fs::read(first_file).unwrap(),
                fs::read(second_file).unwrap()
            );
        }
        assert!(build_wheels_and_npm(&first, VERSION, LICENSE, &trees).is_err());
        assert_eq!(fs::read_dir(first.join("pypi")).unwrap().count(), 4);

        let mut wheel = zip::ZipArchive::new(
            File::open(first.join(
                "pypi/dotagent-9.9.9-py3-none-musllinux_1_2_x86_64.manylinux_2_17_x86_64.whl",
            ))
            .unwrap(),
        )
        .unwrap();
        let executable = "dotagent-9.9.9.data/scripts/dotagent";
        let archived = wheel.by_name(executable).unwrap();
        assert_eq!(archived.unix_mode(), Some(0o100555));
        assert_eq!(
            archived.last_modified().unwrap(),
            DateTime::from_date_and_time(2023, 11, 14, 22, 13, 20).unwrap()
        );
        drop(archived);
        let record = zip_text(&mut wheel, "dotagent-9.9.9.dist-info/RECORD");
        assert!(record.contains(&format!(
            "{executable},sha256=ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0,3\n"
        )));
        assert!(record.ends_with("dotagent-9.9.9.dist-info/RECORD,,\n"));
        let metadata = zip_text(&mut wheel, "dotagent-9.9.9.dist-info/WHEEL");
        assert!(metadata.ends_with(
            "Tag: py3-none-musllinux_1_2_x86_64\nTag: py3-none-manylinux_2_17_x86_64\n"
        ));

        let platform = first.join("npm/susanbdev-dotagent-darwin-arm64-9.9.9.tgz");
        assert_eq!(
            npm_metadata(&platform).unwrap(),
            ("@susanbdev/dotagent-darwin-arm64".into(), VERSION.into())
        );
        let platform_files = read_rooted_archive(&platform, "package").unwrap();
        let platform_manifest =
            JsonValue::parse(std::str::from_utf8(&platform_files["package.json"].0).unwrap())
                .unwrap();
        assert_eq!(
            platform_manifest.get("os"),
            Some(&JsonValue::Array(vec![string("darwin")]))
        );
        assert_eq!(
            platform_manifest.get("cpu"),
            Some(&JsonValue::Array(vec![string("arm64")]))
        );
        assert_eq!(
            platform_manifest.get("license"),
            Some(&string("UNLICENSED"))
        );
        assert_eq!(platform_files["bin/dotagent"], (b"abc".to_vec(), true));

        let root = first.join("npm/susanbdev-dotagent-9.9.9.tgz");
        assert_eq!(
            npm_metadata(&root).unwrap(),
            (NPM_SCOPE.into(), VERSION.into())
        );
        let root_files = read_rooted_archive(&root, "package").unwrap();
        let root_manifest =
            JsonValue::parse(std::str::from_utf8(&root_files["package.json"].0).unwrap()).unwrap();
        assert_eq!(
            root_manifest
                .get("optionalDependencies")
                .unwrap()
                .as_object()
                .unwrap()
                .len(),
            4
        );
        let shim = std::str::from_utf8(&root_files["bin/agent-guard.js"].0).unwrap();
        assert!(shim.contains(
            "spawnSync(path.join(root, \"bin\", \"agent-guard\"), process.argv.slice(2)"
        ));
        assert!(root_files["bin/agent-guard.js"].1);

        let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(File::open(root).unwrap()));
        for file in tar.entries().unwrap() {
            let file = file.unwrap();
            assert_eq!(file.header().uid().unwrap(), 0);
            assert_eq!(file.header().gid().unwrap(), 0);
            assert_eq!(file.header().mtime().unwrap(), TARBALL_EPOCH);
        }
    }

    #[test]
    fn wheel_record_supports_comma_and_quote_paths() {
        let mut files = files();
        files.insert("dist/hello,\"world\".txt".into(), (b"abc".to_vec(), false));
        let bytes = write_wheel(
            Cursor::new(Vec::new()),
            VERSION,
            LICENSE,
            &PLATFORMS[0],
            &files,
        )
        .unwrap();
        let mut wheel = zip::ZipArchive::new(bytes).unwrap();
        let record = zip_text(&mut wheel, "dotagent-9.9.9.dist-info/RECORD");
        assert!(record.contains(
            "\"dotagent-9.9.9.data/data/share/dotagent/dist/hello,\"\"world\"\".txt\",sha256="
        ));
    }

    #[test]
    fn npm_metadata_rejects_conflicting_or_unsafe_manifest_identity() {
        let scratch = Scratch::new();
        let path = scratch.folder("wrong-name").join("renamed.tgz");
        write_tgz(new_file(&path).unwrap(), root_npm(VERSION, "UNLICENSED")).unwrap();
        assert!(npm_metadata(&path).unwrap_err().contains("filename"));

        let fixtures = [
            (
                "duplicate-name",
                "duplicate JSON object key",
                r#"{"name":"@susanbdev/dotagent","name":"@susanbdev/dotagent","version":"9.9.9"}"#,
            ),
            (
                "with-scripts",
                "lifecycle scripts",
                r#"{"name":"@susanbdev/dotagent","version":"9.9.9","scripts":{"install":"example"}}"#,
            ),
            (
                "incomplete-package",
                "missing executable",
                r#"{"name":"@susanbdev/dotagent","version":"9.9.9"}"#,
            ),
        ];
        for (directory, expected, manifest) in fixtures {
            let path = scratch.folder(directory).join(npm_filename(None, VERSION));
            let entries = vec![Entry::text(
                "package/package.json".into(),
                manifest.into(),
                0o644,
            )];
            write_tgz(new_file(&path).unwrap(), entries).unwrap();
            let error = npm_metadata(&path).unwrap_err();
            assert!(error.contains(expected), "{directory}: {error}");
        }

        let path = scratch
            .folder("misrouted")
            .join(npm_filename(None, VERSION));
        let mut entries = root_npm(VERSION, "UNLICENSED");
        entries[0].data = Cow::Owned(
            npm_manifest(VERSION, "UNLICENSED", None)
                .replace(
                    "dotagent-linux-x64\":\"9.9.9",
                    "dotagent-linux-x64\":\"9.9.8",
                )
                .into_bytes(),
        );
        write_tgz(new_file(&path).unwrap(), entries).unwrap();
        assert!(
            npm_metadata(&path)
                .unwrap_err()
                .contains("platform dependencies")
        );
    }
}
