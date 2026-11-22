use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use agent_guard::crypto::sha256_hex;
use flate2::{Compression, GzBuilder};
use tar::{Builder, EntryType, Header};

const TAG: &str = "v9.9.9";
const BINARIES: [&str; 6] = [
    "dotagent",
    "agent-guard",
    "agent-guard-sh",
    "dotagent-compiler",
    "swarm-tool",
    "dotagent-harness",
];

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn elf(cpu: u16) -> Vec<u8> {
    let mut bytes = vec![0; 121];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (offset, value) in [(16, 3u16), (18, cpu), (52, 64), (54, 56), (56, 1)] {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [(20, 1u32), (64, 1), (68, 5)] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [
        (24, 0x1040u64),
        (32, 64),
        (80, 0x1000),
        (96, 121),
        (104, 121),
    ] {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn macho(cpu: u32, subtype: u32) -> Vec<u8> {
    let mut bytes = vec![0; 176];
    for (offset, value) in [
        (0, 0xfeed_facf),
        (4, cpu),
        (8, subtype),
        (12, 2),
        (16, 3),
        (20, 112),
        (32, 0x8000_0028),
        (36, 24),
        (40, 144),
        (56, 0x1d),
        (60, 16),
        (64, 160),
        (68, 12),
        (72, 0x19),
        (76, 72),
        (120, 160),
        (132, 5),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[160..164].copy_from_slice(&0xfade_0cc0u32.to_be_bytes());
    bytes[164..168].copy_from_slice(&12u32.to_be_bytes());
    bytes
}

fn append<W: Write>(tar: &mut Builder<W>, name: &str, mode: u32, kind: EntryType, data: &[u8]) {
    let mut header = Header::new_ustar();
    header.set_entry_type(kind);
    header.set_size(data.len() as u64);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    tar.append_data(&mut header, name, data).unwrap();
}

fn archive(directory: &Path, target: &str, binary: &[u8]) -> PathBuf {
    let root = format!("dotagent-{TAG}-{target}");
    let path = directory.join(format!("{root}.tar.gz"));
    let gzip = GzBuilder::new()
        .mtime(0)
        .write(File::create(&path).unwrap(), Compression::fast());
    let mut tar = Builder::new(gzip);
    append(
        &mut tar,
        &format!("{root}/"),
        0o755,
        EntryType::Directory,
        b"",
    );
    for command in BINARIES {
        append(
            &mut tar,
            &format!("{root}/bin/{command}"),
            0o555,
            EntryType::Regular,
            binary,
        );
    }
    for (name, data) in [
        ("dist/manifest.txt", b"dist tree\n".as_slice()),
        ("profiles/default.toml", b"enabled = true\n".as_slice()),
        ("skills/fixture.md", b"skill\n".as_slice()),
    ] {
        append(
            &mut tar,
            &format!("{root}/{name}"),
            0o444,
            EntryType::Regular,
            data,
        );
    }
    tar.into_inner().unwrap().finish().unwrap();
    path
}

fn produced_files(root: &Path) -> BTreeMap<PathBuf, String> {
    fn visit(root: &Path, directory: &Path, known: &mut BTreeMap<PathBuf, String>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                visit(root, &path, known);
            } else {
                assert!(
                    kind.is_file(),
                    "unexpected special file: {}",
                    path.display()
                );
                known.insert(
                    path.strip_prefix(root).unwrap().into(),
                    sha256_hex(&fs::read(&path).unwrap()),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}

fn compiler(path: &Path, subcommand: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dotagent-compiler"));
    command.env("PATH", path).arg(subcommand);
    command
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn four_target_release_pipeline_is_reproducible_and_verified() {
    let scratch = std::env::current_dir().unwrap().join(format!(
        ".dotagent-release-integration-{}",
        std::process::id()
    ));
    fs::create_dir(&scratch).unwrap();
    let _cleanup = Scratch(scratch.clone());
    let archives = scratch.join("archives");
    let no_tools = scratch.join("no-tools");
    fs::create_dir(&archives).unwrap();
    fs::create_dir(&no_tools).unwrap();
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let inputs = [
        ("aarch64-apple-darwin", macho(0x0100_000c, 0)),
        ("aarch64-unknown-linux-musl", elf(183)),
        ("x86_64-apple-darwin", macho(0x0100_0007, 3)),
        ("x86_64-unknown-linux-musl", elf(62)),
    ];
    let inputs: Vec<_> = inputs
        .iter()
        .map(|(target, binary)| archive(&archives, target, binary))
        .collect();
    let signer = repo.join("packaging/release-signer.pub");
    let repackage = |out: &Path| {
        compiler(&no_tools, "repackage-release")
            .args(["--tag", TAG, "--archives"])
            .arg(&archives)
            .arg("--signers")
            .arg(&signer)
            .arg("--repo-root")
            .arg(&repo)
            .arg("--out")
            .arg(out)
            .output()
            .unwrap()
    };

    let first = scratch.join("first");
    let second = scratch.join("second");
    success(repackage(&first));
    success(repackage(&second));
    let snapshot = produced_files(&first);
    assert_eq!(snapshot, produced_files(&second));
    let refused = repackage(&first);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("create new release output"));
    assert_eq!(snapshot, produced_files(&first));
    assert!(fs::read_dir(first.join("sys")).unwrap().next().is_none());

    let bundle = first.join("bundle");
    let sums = bundle.join("SHA256SUMS");
    let verify = || {
        compiler(&no_tools, "verify-release-assets")
            .arg("--assets")
            .arg(&bundle)
            .arg("--sums")
            .arg(&sums)
            .output()
            .unwrap()
    };
    success(verify());
    let checksums = fs::read_to_string(&sums).unwrap();
    assert_eq!(
        checksums,
        fs::read_to_string(first.join("SHA256SUMS")).unwrap()
    );
    let entries: BTreeMap<_, _> = checksums
        .lines()
        .map(|line| {
            let (digest, name) = line.split_once("  ").unwrap();
            assert_eq!(sha256_hex(&fs::read(bundle.join(name)).unwrap()), digest);
            (name, digest)
        })
        .collect();
    assert_eq!(entries.len(), 15);
    assert_eq!(
        entries.keys().filter(|name| name.ends_with(".whl")).count(),
        4
    );
    assert_eq!(
        entries.keys().filter(|name| name.ends_with(".tgz")).count(),
        5
    );

    let installer = fs::read_to_string(first.join("web/install.sh")).unwrap();
    let formula = fs::read_to_string(first.join("brew/dotagent.rb")).unwrap();
    assert!(installer.ends_with("dotagent_bootstrap \"$@\" --eof-v1\n"));
    assert!(formula.contains("version \"9.9.9\""));
    for archive in inputs {
        let name = archive.file_name().unwrap().to_str().unwrap();
        let checksum = sha256_hex(&fs::read(&archive).unwrap());
        assert_eq!(entries[name], checksum);
        assert!(installer.contains(&checksum));
        assert!(formula.contains(&checksum));
    }

    let wheel = "dotagent-9.9.9-py3-none-macosx_11_0_arm64.whl";
    let mut wheel_zip =
        zip::ZipArchive::new(File::open(first.join("pypi").join(wheel)).unwrap()).unwrap();
    let mut raw = Vec::new();
    wheel_zip
        .by_name("dotagent-9.9.9.data/scripts/dotagent")
        .unwrap()
        .read_to_end(&mut raw)
        .unwrap();
    assert_eq!(raw, macho(0x0100_000c, 0));
    let root_package = first.join("npm/susanbdev-dotagent-9.9.9.tgz");
    let identity = success(
        compiler(&no_tools, "release-npm-metadata")
            .arg(root_package)
            .output()
            .unwrap(),
    );
    assert_eq!(identity, "@susanbdev/dotagent\n9.9.9\n");

    fs::write(bundle.join(wheel), b"changed wheel").unwrap();
    let denied = verify();
    assert_eq!(denied.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&denied.stderr).contains(wheel));
}
