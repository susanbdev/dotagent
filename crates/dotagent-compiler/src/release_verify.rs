//! Offline release metadata and SHA-256 verification for the release workflow.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;

use agent_guard::crypto::hex_encode;
use agent_guard::json::JsonValue;
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

const TEXT_LIMIT: usize = 1024 * 1024;
const ATTESTATION_LIMIT: usize = 16 * 1024 * 1024;
const SUMS_NAME: &str = "SHA256SUMS";

fn same_entry(before: &Metadata, after: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (
            before.dev(),
            before.ino(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (after.dev(), after.ino(), after.ctime(), after.ctime_nsec())
        {
            return false;
        }
    }
    before.file_type() == after.file_type()
        && before.len() == after.len()
        && before
            .modified()
            .is_ok_and(|time| after.modified().is_ok_and(|later| later == time))
}

pub(crate) fn read_regular<T>(
    path: &Path,
    read: impl FnOnce(&mut File) -> io::Result<T>,
) -> Result<T, String> {
    let path_error = |error: io::Error| format!("{}: {error}", path.display());
    let changed = || format!("{}: file changed while reading", path.display());
    let before = fs::symlink_metadata(path).map_err(path_error)?;
    if !before.file_type().is_file() {
        return Err(format!(
            "{}: expected a regular non-symlink file",
            path.display()
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        #[cfg(all(target_os = "linux", not(target_arch = "aarch64")))]
        options.custom_flags(0o400000 | 0o4000); // O_NOFOLLOW | O_NONBLOCK
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        options.custom_flags(0o100000 | 0o4000);
        #[cfg(target_os = "macos")]
        options.custom_flags(0x0100 | 0x0004); // O_NOFOLLOW | O_NONBLOCK
    }
    let mut file = options.open(path).map_err(path_error)?;
    if !same_entry(&before, &file.metadata().map_err(path_error)?) {
        return Err(changed());
    }
    let result = read(&mut file).map_err(path_error)?;
    if !same_entry(&before, &file.metadata().map_err(path_error)?)
        || !same_entry(&before, &fs::symlink_metadata(path).map_err(path_error)?)
    {
        return Err(changed());
    }
    Ok(result)
}

fn read_utf8(reader: impl Read, limit: usize) -> io::Result<String> {
    let mut bytes = Vec::new();
    reader.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("input exceeds {limit} bytes"),
        ));
    }
    String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn read_text(path: &Path, limit: usize) -> Result<String, String> {
    read_regular(path, |file| read_utf8(file, limit))
}

fn version_from_manifest(text: &str) -> Result<String, String> {
    let manifest = text
        .parse::<toml::Table>()
        .map_err(|error| format!("invalid Cargo.toml: {error}"))?;
    let version = manifest
        .get("workspace")
        .and_then(|value| value.get("package"))
        .and_then(|value| value.get("version"))
        .and_then(toml::Value::as_str)
        .ok_or("manifest lacks string workspace.package.version")?;
    let (core, suffix) = version
        .split_once('-')
        .map_or((version, None), |(core, suffix)| (core, Some(suffix)));
    let mut components = core.split('.');
    let valid_core = (0..3).all(|_| {
        components
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    }) && components.next().is_none();
    if !valid_core
        || suffix.is_some_and(|suffix| {
            suffix.is_empty()
                || !suffix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        })
    {
        return Err("invalid workspace.package.version for a release tag".to_owned());
    }
    Ok(version.to_owned())
}

pub(crate) fn hash_file(path: &Path) -> Result<String, String> {
    read_regular(path, |file| {
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 8192];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                return Ok(hex_encode(&digest.finalize()));
            }
            digest.update(&buffer[..count]);
        }
    })
}

fn is_sha256(hex: &str) -> bool {
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn verify_hash(path: &Path, expected: &str) -> Result<(), String> {
    if !is_sha256(expected) {
        return Err("expected a lowercase SHA-256 digest".to_owned());
    }
    let actual = hash_file(path)?;
    if actual != expected {
        return Err(format!(
            "{}: SHA-256 mismatch (expected {expected}, got {actual})",
            path.display()
        ));
    }
    Ok(())
}

fn safe_asset_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 255
        && bytes.next().is_some_and(|b| b.is_ascii_alphanumeric())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
        && !name.eq_ignore_ascii_case(SUMS_NAME)
}

fn parse_sums(text: &str) -> Result<BTreeMap<&str, &str>, String> {
    let mut entries = BTreeMap::new();
    let mut names = BTreeSet::new();
    for (index, line) in text.split_terminator('\n').enumerate() {
        let (digest, name) = line
            .split_once("  ")
            .filter(|(digest, name)| is_sha256(digest) && safe_asset_name(name))
            .ok_or_else(|| format!("invalid SHA256SUMS entry on line {}", index + 1))?;
        if !names.insert(name.to_ascii_lowercase()) {
            return Err(format!("duplicate SHA256SUMS asset {name:?}"));
        }
        entries.insert(name, digest);
    }
    if entries.is_empty() {
        return Err("SHA256SUMS has no entries".to_owned());
    }
    Ok(entries)
}

fn directory_assets(path: &Path) -> Result<BTreeSet<String>, String> {
    let path_error = |error: io::Error| format!("{}: {error}", path.display());
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(path).map_err(path_error)? {
        let entry = entry.map_err(path_error)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("{}: non-UTF-8 release asset name", path.display()))?;
        if !entry.file_type().map_err(path_error)?.is_file()
            || !(name == SUMS_NAME || safe_asset_name(&name))
        {
            return Err(format!(
                "{}: unexpected release directory entry {name:?}",
                path.display()
            ));
        }
        if name != SUMS_NAME {
            names.insert(name);
        }
    }
    Ok(names)
}

fn verify_assets(assets: &Path, sums: &Path, only: &[&str]) -> Result<(), String> {
    let path_error = |error: io::Error| format!("{}: {error}", assets.display());
    let dir = fs::symlink_metadata(assets).map_err(path_error)?;
    if !dir.file_type().is_dir() {
        return Err(format!(
            "{}: expected a non-symlink asset directory",
            assets.display()
        ));
    }
    let text = read_text(sums, TEXT_LIMIT)?;
    let entries = parse_sums(&text)?;
    if only.is_empty() {
        let actual = directory_assets(assets)?;
        let expected: BTreeSet<_> = entries.keys().copied().collect();
        let actual_names: BTreeSet<_> = actual.iter().map(String::as_str).collect();
        if actual_names != expected {
            let missing: Vec<_> = expected.difference(&actual_names).copied().collect();
            let extra: Vec<_> = actual_names.difference(&expected).copied().collect();
            return Err(format!(
                "release asset set differs from SHA256SUMS (missing {missing:?}, extra {extra:?})"
            ));
        }
    }
    let selected: Vec<_> = if only.is_empty() {
        entries.keys().copied().collect()
    } else {
        only.to_vec()
    };
    let mut seen = BTreeSet::new();
    for name in selected {
        if !safe_asset_name(name) || !seen.insert(name) {
            return Err(format!(
                "invalid or duplicate selected release asset {name:?}"
            ));
        }
        let expected = entries
            .get(name)
            .ok_or_else(|| format!("release asset {name:?} is absent from SHA256SUMS"))?;
        verify_hash(&assets.join(name), expected)?;
    }
    if !same_entry(&dir, &fs::symlink_metadata(assets).map_err(path_error)?) {
        return Err(format!(
            "{}: asset directory changed during verification",
            assets.display()
        ));
    }
    Ok(())
}

fn statement_from_bundle(input: &str) -> Result<JsonValue, String> {
    let bundles = JsonValue::parse(input)?;
    let first = bundles
        .as_array()
        .and_then(|array| array.first())
        .filter(|bundle| bundle.as_object().is_some())
        .ok_or("invalid verified attestation bundle")?;
    let statement = if let Some(statement) = first
        .get("verificationResult")
        .and_then(|result| result.get("statement"))
        .filter(|value| value.as_object().is_some())
    {
        statement.clone()
    } else {
        let envelope = first
            .get("bundle")
            .and_then(|bundle| bundle.get("dsseEnvelope"))
            .or_else(|| first.get("dsseEnvelope"))
            .ok_or("verified bundle has no DSSE envelope")?;
        if envelope
            .get("payloadType")
            .is_some_and(|kind| kind.as_str() != Some("application/vnd.in-toto+json"))
        {
            return Err("DSSE envelope has an unexpected payload type".to_owned());
        }
        let payload = envelope
            .get("payload")
            .and_then(JsonValue::as_str)
            .ok_or("DSSE envelope has no payload")?;
        let decoded = STANDARD
            .decode(payload)
            .map_err(|error| format!("invalid DSSE payload encoding: {error}"))?;
        let decoded = std::str::from_utf8(&decoded)
            .map_err(|error| format!("DSSE payload is not UTF-8: {error}"))?;
        JsonValue::parse(decoded)?
    };
    if !statement
        .get("subject")
        .and_then(JsonValue::as_array)
        .is_some_and(|subjects| {
            !subjects.is_empty()
                && subjects.iter().all(|subject| {
                    subject
                        .get("name")
                        .and_then(JsonValue::as_str)
                        .is_some_and(|name| !name.is_empty() && !name.chars().any(char::is_control))
                        && subject
                            .get("digest")
                            .and_then(|digest| digest.get("sha256"))
                            .and_then(JsonValue::as_str)
                            .is_some_and(is_sha256)
                })
        })
    {
        return Err("verified attestation lacks valid SHA-256 subjects".to_owned());
    }
    Ok(statement)
}

fn write_statement(path: &Path, statement: &JsonValue) -> Result<(), String> {
    let name = path
        .file_name()
        .ok_or("statement output lacks a filename")?;
    let mut staged_name = name.to_os_string();
    staged_name.push(format!(".tmp-{}", std::process::id()));
    let staged = path.with_file_name(staged_name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&staged)
        .map_err(|error| format!("{}: {error}", staged.display()))?;
    let result = writeln!(file, "{}", statement.to_json_string());
    drop(file);
    let result = result.and_then(|()| fs::hard_link(&staged, path));
    let cleanup = fs::remove_file(&staged);
    result
        .and(cleanup)
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn oci_digest(input: &str) -> Result<String, String> {
    let metadata = JsonValue::parse(input)?;
    metadata
        .get("containerimage.digest")
        .and_then(JsonValue::as_str)
        .filter(|digest| digest.strip_prefix("sha256:").is_some_and(is_sha256))
        .map(str::to_owned)
        .ok_or_else(|| "invalid or missing containerimage.digest in build metadata".to_owned())
}

fn asset_options(args: &[String]) -> Result<(&Path, &Path, Vec<&str>), String> {
    let mut assets = None;
    let mut sums = None;
    let mut only = Vec::new();
    let (pairs, remainder) = args.as_chunks::<2>();
    for pair in pairs {
        let flag = pair[0].as_str();
        let value = pair[1].as_str();
        if value.is_empty() || value.starts_with("--") {
            return Err(format!("{flag} requires a value"));
        }
        let slot = match flag {
            "--assets" => &mut assets,
            "--sums" => &mut sums,
            "--only" => {
                only.push(value);
                continue;
            }
            _ => return Err(format!("unknown release asset option {flag:?}")),
        };
        if slot.replace(Path::new(value)).is_some() {
            return Err(format!("duplicate {flag}"));
        }
    }
    match (assets, sums, remainder) {
        (Some(assets), Some(sums), []) => Ok((assets, sums, only)),
        _ => Err(
            "usage: verify-release-assets --assets DIR --sums PATH [--only NAME ...]".to_owned(),
        ),
    }
}

fn run(sub: &str, args: &[String]) -> Result<(), String> {
    match (sub, args) {
        ("release-check-loopback", []) => std::net::TcpListener::bind(("127.0.0.1", 0))
            .map(drop)
            .map_err(|error| error.to_string())?,
        ("release-version", [flag, input]) if flag == "--manifest" => {
            let text = if input == "-" {
                read_utf8(io::stdin().lock(), TEXT_LIMIT)
                    .map_err(|error| format!("stdin: {error}"))?
            } else {
                read_text(Path::new(input), TEXT_LIMIT)?
            };
            println!("{}", version_from_manifest(&text)?);
        }
        ("hash-release-file", [file]) => println!("{}", hash_file(Path::new(file))?),
        ("verify-file-sha256", [file, digest]) => verify_hash(Path::new(file), digest)?,
        ("verify-release-assets", _) => {
            let (assets, sums, only) = asset_options(args)?;
            verify_assets(assets, sums, &only)?;
        }
        ("release-attestation-statement", [first, first_path, second, second_path])
            if matches!(
                (first.as_str(), second.as_str()),
                ("--bundle", "--out") | ("--out", "--bundle")
            ) =>
        {
            let (bundle, output) = if first == "--bundle" {
                (first_path, second_path)
            } else {
                (second_path, first_path)
            };
            let input = read_text(Path::new(bundle), ATTESTATION_LIMIT)?;
            write_statement(Path::new(output), &statement_from_bundle(&input)?)?;
        }
        ("release-oci-digest", [metadata_flag, path]) if metadata_flag == "--metadata" => {
            println!("{}", oci_digest(&read_text(Path::new(path), TEXT_LIMIT)?)?);
        }
        _ => return Err(format!("invalid arguments for {sub}")),
    }
    Ok(())
}

pub(crate) fn run_cli(sub: &str, args: &[String]) -> ExitCode {
    match run(sub, args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("[dotagent-compiler] {sub}: {error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    static FIXTURES: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
            fs::create_dir_all(&root).unwrap();
            let path = root.join(format!(
                "release-verify-test-{}-{}",
                std::process::id(),
                FIXTURES.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn versions_are_read_from_strict_workspace_toml() {
        for value in ["2.1.0", "2.1.0-rc.1", "001.2.3--feature"] {
            let input = format!("[workspace.package]\nversion = '{value}'\n");
            assert_eq!(version_from_manifest(&input).unwrap(), value);
        }
        for input in [
            "[package]\nversion = '2.1.0'",
            "[workspace.package]\nversion = 210",
            "[workspace.package]\nversion = '2.1.0'\nversion = '2.1.1'",
            "[workspace.package]\nversion = '2.1.0+local'",
            "[workspace.package]\nversion = '2.1.0-'",
            "[workspace.package]\nversion = '2.1'",
        ] {
            assert!(version_from_manifest(input).is_err(), "{input}");
        }
        assert!(read_utf8(b"abc".as_slice(), 2).is_err());
    }

    #[test]
    fn complete_checksums_check_asset_set_and_subset_hashes_only_selected_files() {
        let fixture = Fixture::new();
        let sums = fixture.0.join(SUMS_NAME);
        let a = fixture.0.join("a.tar.gz");
        let b = fixture.0.join("b.tar.gz");
        fs::write(&a, b"abc").unwrap();
        fs::write(&b, b"abc").unwrap();
        fs::write(&sums, format!("{ABC}  a.tar.gz\n{ABC}  b.tar.gz\n")).unwrap();
        assert_eq!(hash_file(&a).unwrap(), ABC);
        assert!(verify_assets(&fixture.0, &sums, &[]).is_ok());
        fs::write(fixture.0.join("unexpected"), b"extra").unwrap();
        assert!(
            verify_assets(&fixture.0, &sums, &[])
                .unwrap_err()
                .contains("extra")
        );
        fs::remove_file(&b).unwrap();
        assert!(verify_assets(&fixture.0, &sums, &["a.tar.gz"]).is_ok());
        assert!(verify_assets(&fixture.0, &sums, &["a.tar.gz", "a.tar.gz"]).is_err());
        assert!(verify_assets(&fixture.0, &sums, &["missing.tar.gz"]).is_err());
        fs::write(&a, b"different").unwrap();
        assert!(
            verify_assets(&fixture.0, &sums, &["a.tar.gz"])
                .unwrap_err()
                .contains("SHA-256 mismatch")
        );
    }

    #[test]
    fn checksum_paths_and_duplicate_lines_are_rejected() {
        for name in ["../a", "/asset", "a\\b", "a file", "SHA256SUMS"] {
            assert!(parse_sums(&format!("{ABC}  {name}\n")).is_err(), "{name}");
        }
        assert!(parse_sums(&format!("{}  asset\n", ABC.to_ascii_uppercase())).is_err());
        assert!(parse_sums(&format!("{ABC}  asset\n{ABC}  Asset\n")).is_err());
        assert!(parse_sums(&format!("{ABC}  asset\n\n")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_inputs_fail_closed() {
        let fixture = Fixture::new();
        let sums = fixture.0.join(SUMS_NAME);
        let linked = fixture.0.join("linked.tar.gz");
        let real = fixture.0.join("data.tar.gz");
        fs::write(&real, b"abc").unwrap();
        fs::write(&sums, format!("{ABC}  linked.tar.gz\n")).unwrap();
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        assert!(hash_file(&linked).is_err());
        assert!(verify_assets(&fixture.0, &sums, &["linked.tar.gz"]).is_err());
    }

    #[test]
    fn attestation_translation_checks_subjects_and_does_not_replace_outputs() {
        let body =
            format!(r#"{{"subject":[{{"name":"asset.tar.gz","digest":{{"sha256":"{ABC}"}}}}]}}"#);
        let direct = format!(r#"[{{"verificationResult":{{"statement":{body}}}}}]"#);
        let envelope = format!(
            r#"[{{"bundle":{{"dsseEnvelope":{{"payload":"{}"}}}}}}]"#,
            STANDARD.encode(&body)
        );
        let statement = statement_from_bundle(&direct).unwrap();
        assert_eq!(statement_from_bundle(&envelope).unwrap(), statement);
        assert!(
            statement_from_bundle(r#"[{"verificationResult":{"statement":{"subject":[]}}}]"#)
                .is_err()
        );
        let fixture = Fixture::new();
        let output = fixture.0.join("statement.json");
        write_statement(&output, &statement).unwrap();
        assert!(write_statement(&output, &JsonValue::Null).is_err());
        assert_eq!(
            JsonValue::parse(&fs::read_to_string(&output).unwrap()).unwrap(),
            statement
        );
    }

    #[test]
    fn buildx_digest_requires_exact_sha256_prefix_and_lowercase_hex() {
        assert_eq!(
            oci_digest(&format!(r#"{{"containerimage.digest":"sha256:{ABC}"}}"#)).unwrap(),
            format!("sha256:{ABC}")
        );
        for value in [
            ABC.to_owned(),
            format!("sha256:{}", ABC.to_ascii_uppercase()),
            "sha512:abc".to_owned(),
        ] {
            assert!(oci_digest(&format!(r#"{{"containerimage.digest":"{value}"}}"#)).is_err());
        }
    }
}
