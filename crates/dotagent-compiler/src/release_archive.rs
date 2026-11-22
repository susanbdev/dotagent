//! Deterministic release archive construction and bounded, non-following extraction.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use flate2::bufread::GzDecoder;
use tar::{Archive, EntryType};

use crate::macos_preview::macho::{self, Arch};
use crate::preview_archive::{append_entry, finish_tar, publish_archive, tar_builder};

pub(crate) type ReleaseTree = BTreeMap<String, (Vec<u8>, bool)>;

const BINARIES: [&str; 6] = [
    "dotagent",
    "agent-guard",
    "agent-guard-sh",
    "dotagent-compiler",
    "swarm-tool",
    "dotagent-harness",
];
const SHARED_DIRS: [&str; 4] = ["dist", "dist-verify", "profiles", "skills"];
const DOCUMENTS: [&str; 6] = [
    "AGENTS.md",
    "README.md",
    "THREAT_MODEL.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "spec.md",
];
const MAX_ENTRIES: usize = 4096;
const MAX_DEPTH: usize = 24;
const MAX_PATH_BYTES: usize = 4096;
const MAX_MEMBER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TREE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_COMPRESSED_BYTES: u64 = MAX_TREE_BYTES + 32 * 1024 * 1024;
const MAX_DECODED_BYTES: u64 = MAX_TREE_BYTES + 32 * 1024 * 1024;
const MAX_PADDING: usize = 10_240;

const PACKAGE_USAGE: &str = "Usage: dotagent-compiler package-release-archive \
    --repo-root PATH --target TRIPLE --tag TAG --out ARCHIVE";
const UNPACK_USAGE: &str = "Usage: dotagent-compiler unpack-release-archive \
    --archive ARCHIVE --target TRIPLE --tag TAG --out-dir DIR";

pub(crate) fn package_cli(args: &[String]) -> ExitCode {
    cli(args, PACKAGE_USAGE, || {
        let [repo, target, tag, out] =
            options(args, ["--repo-root", "--target", "--tag", "--out"])?;
        package(Path::new(repo), tag, target, Path::new(out))
    })
}

pub(crate) fn unpack_cli(args: &[String]) -> ExitCode {
    cli(args, UNPACK_USAGE, || {
        let [archive, target, tag, out] =
            options(args, ["--archive", "--target", "--tag", "--out-dir"])?;
        unpack(Path::new(archive), tag, target, Path::new(out))
    })
}

fn cli(args: &[String], usage: &str, run: impl FnOnce() -> Result<(), String>) -> ExitCode {
    if matches!(args, [argument] if matches!(argument.as_str(), "--help" | "-h")) {
        println!("{usage}");
        return ExitCode::SUCCESS;
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("[dotagent-compiler release archive] {error}");
            ExitCode::from(2)
        }
    }
}

fn options<'a>(args: &'a [String], flags: [&str; 4]) -> Result<[&'a str; 4], String> {
    if args.len() != 8 {
        return Err(format!("expected {}", flags.join(", ")));
    }
    let mut values = [""; 4];
    for pair in args.as_chunks::<2>().0 {
        let flag = pair[0].as_str();
        let index = flags
            .iter()
            .position(|candidate| *candidate == flag)
            .ok_or_else(|| format!("unknown release archive option {flag:?}"))?;
        let value = pair[1].as_str();
        if !values[index].is_empty()
            || value.is_empty()
            || value.starts_with('-')
            || value.chars().any(char::is_control)
        {
            return Err(format!("{flag} requires one nonempty value"));
        }
        values[index] = value;
    }
    Ok(values)
}

#[derive(Clone, Copy)]
enum Target {
    Elf { cpu: u16, static_link: bool },
    Mach(Arch),
}

fn release_spec(tag: &str, triple: &str) -> Result<(String, Target), String> {
    let valid_tag = tag.len() <= 64
        && tag.strip_prefix('v').is_some_and(|tag| {
            let (version, suffix) = tag
                .split_once('-')
                .map_or((tag, None), |(v, s)| (v, Some(s)));
            let parts: Vec<_> = version.split('.').collect();
            parts.len() == 3
                && parts
                    .iter()
                    .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
                && suffix.is_none_or(|suffix| {
                    !suffix.is_empty()
                        && suffix
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
                })
        });
    if !valid_tag {
        return Err(
            "invalid release tag; expected vMAJOR.MINOR.PATCH with an optional suffix".into(),
        );
    }
    let target = match triple {
        "x86_64-unknown-linux-musl" => Target::Elf {
            cpu: 62,
            static_link: true,
        },
        "aarch64-unknown-linux-musl" => Target::Elf {
            cpu: 183,
            static_link: true,
        },
        "x86_64-unknown-linux-gnu" if tag == "v0.0.0-ci" => Target::Elf {
            cpu: 62,
            static_link: false,
        },
        "aarch64-unknown-linux-gnu" if tag == "v0.0.0-ci" => Target::Elf {
            cpu: 183,
            static_link: false,
        },
        "x86_64-apple-darwin" => Target::Mach(Arch::X86_64),
        "aarch64-apple-darwin" => Target::Mach(Arch::Arm64),
        _ => return Err(format!("unsupported release target {triple:?}")),
    };
    Ok((format!("dotagent-{tag}-{triple}"), target))
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], String> {
    bytes
        .get(offset..offset.saturating_add(N))
        .and_then(|field| field.try_into().ok())
        .ok_or_else(|| "truncated ELF structure".into())
}

fn elf64(bytes: &[u8], cpu: u16, static_link: bool) -> Result<(), String> {
    let u16_at = |index| field(bytes, index).map(u16::from_le_bytes);
    let u32_at = |index| field(bytes, index).map(u32::from_le_bytes);
    let u64_at = |index| field(bytes, index).map(u64::from_le_bytes);
    if bytes.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || !matches!(u16_at(16)?, 2 | 3)
        || u16_at(18)? != cpu
        || u32_at(20)? != 1
        || u16_at(52)? != 64
        || u16_at(54)? != 56
    {
        return Err("expected a native 64-bit little-endian ELF executable".into());
    }
    let entry = u64_at(24)?;
    let first = usize::try_from(u64_at(32)?).map_err(|_| "invalid ELF program header offset")?;
    let count = usize::from(u16_at(56)?);
    if entry == 0
        || first < 64
        || !(1..=1024).contains(&count)
        || first
            .checked_add(count * 56)
            .is_none_or(|end| end > bytes.len())
    {
        return Err("invalid ELF entry point or header table".into());
    }
    let mut entry_mapped = false;
    let mut interpreter = false;
    for index in 0..count {
        let header = first + index * 56;
        let kind = u32_at(header)?;
        let flags = u32_at(header + 4)?;
        let offset = u64_at(header + 8)?;
        let address = u64_at(header + 16)?;
        let file_size = u64_at(header + 32)?;
        let mem_size = u64_at(header + 40)?;
        let end = offset
            .checked_add(file_size)
            .filter(|end| *end <= bytes.len() as u64)
            .ok_or("ELF program segment exceeds file bounds")?;
        match kind {
            1 => {
                if file_size > mem_size || address.checked_add(mem_size).is_none() {
                    return Err("invalid ELF load segment range".into());
                }
                entry_mapped |= flags & 1 != 0 && entry >= address && entry - address < file_size;
            }
            2 if static_link => {
                let dynamic = &bytes[offset as usize..end as usize];
                let (records, trailing) = dynamic.as_chunks::<16>();
                if !trailing.is_empty() || records.len() > 4096 {
                    return Err("invalid ELF dynamic segment size".into());
                }
                let mut terminated = false;
                for record in records {
                    match u64::from_le_bytes(field(record, 0)?) {
                        0 => {
                            terminated = true;
                            break;
                        }
                        1 => return Err("musl release executable requires a shared library".into()),
                        _ => {}
                    }
                }
                if !terminated {
                    return Err("ELF dynamic segment has no terminator".into());
                }
            }
            3 => {
                if static_link || interpreter {
                    return Err("unexpected ELF program interpreter".into());
                }
                let wanted = if cpu == 62 {
                    b"/lib64/ld-linux-x86-64.so.2\0".as_slice()
                } else {
                    b"/lib/ld-linux-aarch64.so.1\0".as_slice()
                };
                if &bytes[offset as usize..end as usize] != wanted {
                    return Err("unexpected GNU ELF interpreter".into());
                }
                interpreter = true;
            }
            _ => {}
        }
    }
    if !entry_mapped || !static_link && !interpreter {
        return Err(
            "ELF entry point is not in an executable load segment, or interpreter is missing"
                .into(),
        );
    }
    Ok(())
}

fn validate_binaries(files: &ReleaseTree, target: Target) -> Result<(), String> {
    for bin in BINARIES {
        let rel = format!("bin/{bin}");
        let (bytes, executable) = files
            .get(&rel)
            .ok_or_else(|| format!("missing binary {bin}"))?;
        if !executable {
            return Err(format!("{rel} is not executable"));
        }
        match target {
            Target::Elf { cpu, static_link } => elf64(bytes, cpu, static_link),
            Target::Mach(arch) => macho::thin(bytes, arch, false),
        }
        .map_err(|error| format!("{rel}: {error}"))?;
    }
    Ok(())
}

fn path_error(path: &Path, error: impl std::fmt::Display) -> String {
    format!("'{}': {error}", path.display())
}

fn absolute(path: &Path) -> Result<PathBuf, String> {
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(path_error(
            path,
            "parent directory components are not allowed",
        ));
    }
    let full = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| path_error(path, error))?
            .join(path)
    };
    Ok(full.components().collect())
}

fn canonical(path: &Path) -> Result<PathBuf, String> {
    let full = absolute(path)?;
    let resolved = fs::canonicalize(&full).map_err(|error| path_error(&full, error))?;
    if full != resolved {
        return Err(path_error(
            path,
            "path must be canonical and contain no symlinks",
        ));
    }
    Ok(full)
}

fn directory(path: &Path, create: bool) -> Result<PathBuf, String> {
    let path = absolute(path)?;
    if create {
        let ancestors: Vec<_> = path.ancestors().collect();
        for ancestor in ancestors.into_iter().rev() {
            match fs::symlink_metadata(ancestor) {
                Ok(metadata) if metadata.is_dir() => {}
                Ok(_) => return Err(path_error(ancestor, "expected a non-symlink directory")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(ancestor).map_err(|error| path_error(ancestor, error))?;
                }
                Err(error) => return Err(path_error(ancestor, error)),
            }
        }
    }
    let path = canonical(&path)?;
    if !path.is_dir() {
        return Err(path_error(&path, "expected a directory"));
    }
    Ok(path)
}

fn same_file(a: &Metadata, b: &Metadata) -> bool {
    if !a.is_file() || !b.is_file() || a.len() != b.len() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (
            a.dev(),
            a.ino(),
            a.mtime(),
            a.mtime_nsec(),
            a.ctime(),
            a.ctime_nsec(),
        ) == (
            b.dev(),
            b.ino(),
            b.mtime(),
            b.mtime_nsec(),
            b.ctime(),
            b.ctime_nsec(),
        )
    }
    #[cfg(not(unix))]
    {
        a.modified().ok() == b.modified().ok()
    }
}

fn unchanged(path: &Path, file: &File, before: &Metadata) -> Result<(), String> {
    let opened = file.metadata().map_err(|err| path_error(path, err))?;
    canonical(path)?;
    let named = fs::symlink_metadata(path).map_err(|err| path_error(path, err))?;
    if !same_file(before, &opened) || !same_file(before, &named) {
        return Err(path_error(path, "file changed during archive processing"));
    }
    Ok(())
}

fn regular(path: &Path, bound: u64) -> Result<(PathBuf, File, Metadata), String> {
    let path = canonical(path)?;
    let before = fs::symlink_metadata(&path).map_err(|err| path_error(&path, err))?;
    if !before.is_file() || before.len() > bound {
        return Err(path_error(
            &path,
            format!("expected a regular file of at most {bound} bytes"),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let flags = if cfg!(target_os = "macos") {
            0x0100 | 0x0004
        } else if cfg!(target_arch = "aarch64") {
            0o100000 | 0o4000
        } else {
            0o400000 | 0o4000
        };
        options.custom_flags(flags);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    let file = options.open(&path).map_err(|err| path_error(&path, err))?;
    unchanged(&path, &file, &before)?;
    Ok((path, file, before))
}

fn read_limited(reader: impl Read, length: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(length as usize);
    reader
        .take(length + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| err.to_string())?;
    if bytes.len() as u64 != length {
        return Err("file length changed during read, or archive member is truncated".into());
    }
    Ok(bytes)
}

fn valid_name(path: &str) -> bool {
    path.len() <= MAX_PATH_BYTES
        && path
            .bytes()
            .all(|byte| matches!(byte, 0x20..=0x7e) && !matches!(byte, b'\\' | b':'))
        && path.split('/').count() <= MAX_DEPTH
        && path
            .split('/')
            .all(|part| !matches!(part, "" | "." | "..") && part.len() <= 255)
}

#[derive(Default)]
struct Contents {
    root_present: bool,
    files: ReleaseTree,
    dirs: BTreeSet<String>,
    bytes: u64,
}

impl Contents {
    fn validate_names(&self) -> Result<(), String> {
        let mut spellings = BTreeMap::<String, &str>::new();
        for name in self.files.keys().chain(&self.dirs) {
            if !valid_name(name) {
                return Err(format!("unsafe archive member {name:?}"));
            }
            let mut parent = name.as_str();
            loop {
                if spellings
                    .insert(parent.to_ascii_lowercase(), parent)
                    .is_some_and(|previous| previous != parent)
                {
                    return Err(format!("case-colliding archive path {parent:?}"));
                }
                let Some((outer, _)) = parent.rsplit_once('/') else {
                    break;
                };
                if self.files.contains_key(outer) {
                    return Err(format!("archive file conflicts with directory {outer:?}"));
                }
                parent = outer;
            }
        }
        Ok(())
    }

    fn budget(&self) -> u64 {
        MAX_TREE_BYTES - self.bytes
    }

    fn has_name(&self, name: &str) -> bool {
        self.files.contains_key(name) || self.dirs.contains(name)
    }
}

fn extension_path(kind: EntryType, bytes: &[u8]) -> Result<String, String> {
    let path = if kind == EntryType::GNULongName {
        let raw = bytes
            .strip_suffix(b"\0")
            .ok_or("unterminated GNU archive path")?;
        std::str::from_utf8(raw).map_err(|_| "non-UTF-8 GNU archive path")?
    } else {
        let text = std::str::from_utf8(bytes).map_err(|_| "non-UTF-8 PAX archive path")?;
        let (length, record) = text.split_once(' ').ok_or("invalid PAX path record")?;
        if length.parse::<usize>().ok() != Some(bytes.len()) {
            return Err("incorrect PAX path record length".into());
        }
        record
            .strip_prefix("path=")
            .and_then(|path| path.strip_suffix('\n'))
            .ok_or("unexpected archive extension; only PAX path records are supported")?
    };
    Ok(path.to_owned())
}

fn read_content(path: &Path, root: &str, release_modes: bool) -> Result<Contents, String> {
    if !valid_name(root) || root.contains('/') {
        return Err("expected a single canonical archive root".into());
    }
    let (path, file, before) = regular(path, MAX_COMPRESSED_BYTES)?;
    let decoder = GzDecoder::new(BufReader::new((&file).take(MAX_COMPRESSED_BYTES + 1)));
    let mut decoded = decoder.take(MAX_DECODED_BYTES + 1);
    let mut contents = Contents::default();
    let mut extension = None;
    {
        let mut tar = Archive::new(&mut decoded);
        let entries = tar
            .entries()
            .map_err(|err| path_error(&path, err))?
            .raw(true);
        for (index, entry) in entries.enumerate() {
            if index == MAX_ENTRIES {
                return Err(path_error(&path, "too many archive members"));
            }
            let mut entry = entry.map_err(|err| path_error(&path, err))?;
            let kind = entry.header().entry_type();
            if matches!(kind, EntryType::GNULongName | EntryType::XHeader) {
                if extension.is_some() || entry.size() > (MAX_PATH_BYTES + 64) as u64 {
                    return Err(path_error(
                        &path,
                        "invalid or oversized archive path extension",
                    ));
                }
                let size = entry.size();
                extension = Some(extension_path(kind, &read_limited(&mut entry, size)?)?);
                continue;
            }
            if !matches!(kind, EntryType::Directory | EntryType::Regular) {
                return Err(path_error(
                    &path,
                    "archive contains a symlink, hard link, or other special member",
                ));
            }
            let name = match extension.take() {
                Some(name) => name,
                None => String::from_utf8(entry.path_bytes().into_owned())
                    .map_err(|_| path_error(&path, "non-UTF-8 archive path"))?,
            };
            let is_dir = kind == EntryType::Directory;
            let name = if is_dir {
                name.strip_suffix('/').unwrap_or(&name)
            } else {
                &name
            };
            if !valid_name(name) {
                return Err(path_error(&path, format!("unsafe archive member {name:?}")));
            }
            let (first, relative) = name.split_once('/').unwrap_or((name, ""));
            if first != root || relative.is_empty() && !is_dir {
                return Err(path_error(
                    &path,
                    format!("member outside archive root: {name:?}"),
                ));
            }
            let mode = entry
                .header()
                .mode()
                .map_err(|err| path_error(&path, err))?;
            if mode & !0o777 != 0 || contents.has_name(relative) {
                return Err(path_error(
                    &path,
                    format!("duplicate archive member or unsafe mode: {name:?}"),
                ));
            }
            let canonical_mode = if is_dir {
                mode == 0o755
            } else {
                matches!(mode, 0o444 | 0o555)
            };
            if release_modes && !canonical_mode {
                return Err(path_error(
                    &path,
                    format!("noncanonical release mode {mode:o} for {name:?}"),
                ));
            }
            if is_dir {
                if entry.size() != 0 {
                    return Err(path_error(&path, "archive directory contains data"));
                }
                if relative.is_empty() {
                    if contents.root_present {
                        return Err(path_error(&path, "duplicate archive root"));
                    }
                    contents.root_present = true;
                } else {
                    contents.dirs.insert(relative.to_owned());
                }
                continue;
            }
            let length = entry.size();
            if length > contents.budget().min(MAX_MEMBER_BYTES) {
                return Err(path_error(
                    &path,
                    format!("archive size limit exceeded at {name:?}"),
                ));
            }
            let bytes = read_limited(&mut entry, length).map_err(|err| path_error(&path, err))?;
            contents.bytes += length;
            contents
                .files
                .insert(relative.to_owned(), (bytes, mode & 0o111 != 0));
        }
    }
    if extension.is_some() {
        return Err(path_error(&path, "archive ended after a path extension"));
    }
    let mut tail = [0; 4096];
    let mut padding = 0;
    loop {
        let count = decoded
            .read(&mut tail)
            .map_err(|err| path_error(&path, err))?;
        if count == 0 {
            break;
        }
        padding += count;
        if padding > MAX_PADDING || tail[..count].iter().any(|&value| value != 0) {
            return Err(path_error(
                &path,
                "unexpected data after the tar terminator",
            ));
        }
    }
    if padding < 512 || !padding.is_multiple_of(512) || decoded.limit() == 0 {
        return Err(path_error(
            &path,
            "invalid tar terminator or decoded archive size",
        ));
    }
    let mut compressed = decoded.into_inner().into_inner();
    if !compressed
        .fill_buf()
        .map_err(|err| path_error(&path, err))?
        .is_empty()
    {
        return Err(path_error(&path, "unexpected bytes after the gzip trailer"));
    }
    unchanged(&path, &file, &before)?;
    contents.validate_names()?;
    Ok(contents)
}

pub(crate) fn read_rooted_archive(archive: &Path, root: &str) -> Result<ReleaseTree, String> {
    Ok(read_content(archive, root, false)?.files)
}

fn release_contents(archive: &Path, root: &str, target: Target) -> Result<Contents, String> {
    let contents = read_content(archive, root, true)?;
    if !contents.root_present {
        return Err(path_error(
            archive,
            "missing canonical release root directory",
        ));
    }
    validate_binaries(&contents.files, target)?;
    Ok(contents)
}

pub(crate) fn read_release(archive: &Path, tag: &str, target: &str) -> Result<ReleaseTree, String> {
    let (root, target) = release_spec(tag, target)?;
    Ok(release_contents(archive, &root, target)?.files)
}

fn collect_file(
    repo: &Path,
    source: &str,
    name: &str,
    contents: &mut Contents,
) -> Result<(), String> {
    let requested = repo.join(source);
    let bound = contents.budget().min(MAX_MEMBER_BYTES);
    let (path, file, before) = regular(&requested, bound)?;
    let bytes = read_limited(&file, before.len()).map_err(|err| path_error(&path, err))?;
    unchanged(&path, &file, &before)?;
    contents.bytes += bytes.len() as u64;
    let executable = name.starts_with("bin/") || {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            before.permissions().mode() & 0o111 != 0
        }
        #[cfg(not(unix))]
        {
            false
        }
    };
    contents.files.insert(name.to_owned(), (bytes, executable));
    Ok(())
}

fn collect_directory(repo: &Path, relative: &str, contents: &mut Contents) -> Result<(), String> {
    if !valid_name(relative) {
        return Err(format!("unsafe release directory name {relative:?}"));
    }
    let dir = directory(&repo.join(relative), false)?;
    contents.dirs.insert(relative.to_owned());
    for entry in fs::read_dir(&dir).map_err(|err| path_error(&dir, err))? {
        if contents.dirs.len() + contents.files.len() >= MAX_ENTRIES - 1 {
            return Err("too many release archive members".into());
        }
        let entry = entry.map_err(|err| path_error(&dir, err))?;
        let kind = entry
            .file_type()
            .map_err(|err| path_error(&entry.path(), err))?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("non-UTF-8 release member path")?;
        let child = format!("{relative}/{name}");
        if !valid_name(&child) {
            return Err(format!("unsafe release member name {child:?}"));
        }
        if kind.is_dir() {
            collect_directory(repo, &child, contents)?;
        } else if kind.is_file() {
            collect_file(repo, &child, &child, contents)?;
        } else {
            return Err(format!(
                "release path {child:?} is a symlink or special file"
            ));
        }
    }
    Ok(())
}

fn package(repo: &Path, tag: &str, target: &str, out: &Path) -> Result<(), String> {
    let (root, format) = release_spec(tag, target)?;
    let repo = directory(repo, false)?;
    let mut contents = Contents::default();
    contents.dirs.insert("bin".into());
    for bin in BINARIES {
        collect_file(
            &repo,
            &format!("target/{target}/release/{bin}"),
            &format!("bin/{bin}"),
            &mut contents,
        )?;
    }
    validate_binaries(&contents.files, format)?;
    for doc in DOCUMENTS {
        collect_file(&repo, doc, doc, &mut contents)?;
    }
    for shared in SHARED_DIRS {
        collect_directory(&repo, shared, &mut contents)?;
    }
    contents.validate_names()?;

    let out = absolute(out)?;
    directory(
        out.parent().ok_or("archive output must have a parent")?,
        true,
    )?;
    let files = &contents.files;
    let names: BTreeSet<_> = contents.dirs.iter().chain(files.keys()).collect();
    publish_archive(&out, |file| {
        let mut tar = tar_builder(file);
        append_entry(
            &mut tar,
            &format!("{root}/"),
            EntryType::Directory,
            0o755,
            b"",
        )?;
        for name in names {
            if let Some((bytes, executable)) = files.get(name) {
                let mode = if *executable { 0o555 } else { 0o444 };
                append_entry(
                    &mut tar,
                    &format!("{root}/{name}"),
                    EntryType::Regular,
                    mode,
                    bytes,
                )?;
            } else {
                append_entry(
                    &mut tar,
                    &format!("{root}/{name}/"),
                    EntryType::Directory,
                    0o755,
                    b"",
                )?;
            }
        }
        finish_tar(tar)
    })
    .map_err(|err| path_error(&out, err))?;
    println!("Packaged '{}' ({root})", out.display());
    Ok(())
}

struct UnpackGuard(PathBuf);

impl Drop for UnpackGuard {
    fn drop(&mut self) {
        if !self.0.as_os_str().is_empty() {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

fn unpack(archive: &Path, tag: &str, target: &str, out: &Path) -> Result<(), String> {
    let (root, target) = release_spec(tag, target)?;
    let contents = release_contents(archive, &root, target)?;
    let path = directory(out, true)?.join(root);
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(&path)
        .map_err(|err| path_error(&path, err))?;
    let mut cleanup = UnpackGuard(path.clone());
    for name in contents.dirs {
        fs::create_dir_all(path.join(&name)).map_err(|err| path_error(&path.join(name), err))?;
    }
    for (name, (bytes, executable)) in contents.files {
        let destination = path.join(name);
        let parent = destination.parent().ok_or("invalid destination file")?;
        fs::create_dir_all(parent).map_err(|err| path_error(parent, err))?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
            .map_err(|err| path_error(&destination, err))?;
        output
            .write_all(&bytes)
            .map_err(|err| path_error(&destination, err))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if executable { 0o555 } else { 0o444 };
            output
                .set_permissions(fs::Permissions::from_mode(mode))
                .map_err(|err| path_error(&destination, err))?;
        }
        #[cfg(not(unix))]
        let _ = executable;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .map_err(|err| path_error(&path, err))?;
    }
    cleanup.0.clear();
    println!("{}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG: &str = "v1.2.3";
    const TARGET: &str = "x86_64-unknown-linux-musl";

    fn executable(cpu: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; 121];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&cpu.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x1040u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
        bytes[80..88].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&121u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&121u64.to_le_bytes());
        bytes
    }

    #[test]
    fn elf_requires_native_architecture_and_a_backed_executable_entry() {
        let mut binary = executable(62);
        assert!(elf64(&binary, 62, true).is_ok());
        assert!(elf64(&binary, 183, true).is_err());
        assert!(elf64(&binary, 62, false).is_err());
        binary[68..72].copy_from_slice(&4u32.to_le_bytes());
        assert!(elf64(&binary, 62, true).is_err());
    }

    #[test]
    fn release_validates_members_and_exhausts_gzip_stream() {
        let scratch = std::env::current_dir()
            .unwrap()
            .canonicalize()
            .unwrap()
            .join(format!(".native-release-test-{}", std::process::id()));
        fs::create_dir(&scratch).unwrap();
        let _cleanup = UnpackGuard(scratch.clone());
        let path = scratch.join("archive.tar.gz");
        let (root, _) = release_spec(TAG, TARGET).unwrap();
        let native = executable(62);
        let long_path = format!("skills/{}/{}", "a".repeat(200), "b".repeat(200));

        let mut tar = tar_builder(Vec::new());
        append_entry(
            &mut tar,
            &format!("{root}/"),
            EntryType::Directory,
            0o755,
            b"",
        )
        .unwrap();
        for bin in BINARIES {
            append_entry(
                &mut tar,
                &format!("{root}/bin/{bin}"),
                EntryType::Regular,
                0o555,
                &native,
            )
            .unwrap();
        }
        append_entry(
            &mut tar,
            &format!("{root}/{long_path}"),
            EntryType::Regular,
            0o444,
            b"skill",
        )
        .unwrap();
        let mut bytes = finish_tar(tar).unwrap();
        fs::write(&path, &bytes).unwrap();
        let members = read_release(&path, TAG, TARGET).unwrap();
        assert_eq!(members["bin/dotagent"], (native, true));
        assert_eq!(members[&long_path], (b"skill".to_vec(), false));

        bytes.push(0);
        fs::write(&path, bytes).unwrap();
        assert!(
            read_release(&path, TAG, TARGET)
                .unwrap_err()
                .contains("gzip trailer")
        );

        let mut tar = tar_builder(Vec::new());
        append_entry(
            &mut tar,
            &format!("{root}/bin/dotagent"),
            EntryType::Regular,
            0o777,
            b"not normalized",
        )
        .unwrap();
        fs::write(&path, finish_tar(tar).unwrap()).unwrap();
        assert!(
            read_release(&path, TAG, TARGET)
                .unwrap_err()
                .contains("noncanonical release mode")
        );

        let mut tar = tar_builder(Vec::new());
        append_entry(&mut tar, "package/link", EntryType::Symlink, 0o777, b"").unwrap();
        fs::write(&path, finish_tar(tar).unwrap()).unwrap();
        assert!(
            read_rooted_archive(&path, "package")
                .unwrap_err()
                .contains("special member")
        );
    }
}
