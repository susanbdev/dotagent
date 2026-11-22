//! Package the two guarded Dotagent build slices as a verified macOS preview.

use std::process::ExitCode;

const USAGE: &str = "Usage: dotagent-compiler package-macos-preview \
    --native PATH --other PATH --commit SHA --out-dir DIR";

pub(crate) fn run_cli(args: &[String]) -> ExitCode {
    if matches!(args, [arg] if matches!(arg.as_str(), "-h" | "--help")) {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("[dotagent-compiler macOS preview] {error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn run(_args: &[String]) -> Result<(), String> {
    Err("package-macos-preview must run on macOS".into())
}

#[cfg(target_os = "macos")]
fn run(args: &[String]) -> Result<(), String> {
    platform::package(args)
}

pub(crate) mod macho {
    #[cfg(any(target_os = "macos", test))]
    use std::ops::Range;

    pub(super) const MAX_BYTES: usize = 256 * 1024 * 1024;

    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const MH_EXECUTE: u32 = 2;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_MAIN: u32 = 0x8000_0028;
    const LC_CODE_SIGNATURE: u32 = 0x1d;
    const EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
    #[cfg(any(target_os = "macos", test))]
    const FAT_MAGIC: u32 = 0xcafe_babe;
    #[cfg(any(target_os = "macos", test))]
    const FAT_MAGIC_64: u32 = 0xcafe_babf;
    const HEADER_BYTES: usize = 32;
    const MAX_COMMANDS: usize = 4096;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Arch {
        Arm64,
        X86_64,
    }

    impl Arch {
        fn from_cpu(cpu: u32) -> Result<Self, String> {
            match cpu {
                0x0100_000c => Ok(Self::Arm64),
                0x0100_0007 => Ok(Self::X86_64),
                _ => Err(format!("unsupported Mach-O CPU type {cpu:#x}")),
            }
        }

        fn generic_subtype(self) -> u32 {
            match self {
                Self::Arm64 => 0,
                Self::X86_64 => 3,
            }
        }

        #[cfg(any(target_os = "macos", test))]
        pub(super) fn other(self) -> Self {
            match self {
                Self::Arm64 => Self::X86_64,
                Self::X86_64 => Self::Arm64,
            }
        }

        #[cfg(target_os = "macos")]
        pub(super) fn host() -> Result<Self, String> {
            match std::env::consts::ARCH {
                "aarch64" => Ok(Self::Arm64),
                "x86_64" => Ok(Self::X86_64),
                arch => Err(format!("unsupported macOS host architecture {arch}")),
            }
        }

        #[cfg(target_os = "macos")]
        pub(super) fn triple(self) -> &'static str {
            match self {
                Self::Arm64 => "aarch64-apple-darwin",
                Self::X86_64 => "x86_64-apple-darwin",
            }
        }
    }

    fn read<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], String> {
        bytes
            .get(offset..offset.saturating_add(N))
            .and_then(|field| field.try_into().ok())
            .ok_or_else(|| "truncated Mach-O structure".into())
    }

    fn le32(bytes: &[u8], offset: usize) -> Result<u32, String> {
        Ok(u32::from_le_bytes(read(bytes, offset)?))
    }

    fn be32(bytes: &[u8], offset: usize) -> Result<u32, String> {
        Ok(u32::from_be_bytes(read(bytes, offset)?))
    }

    #[cfg(any(target_os = "macos", test))]
    fn be64(bytes: &[u8], offset: usize) -> Result<u64, String> {
        Ok(u64::from_be_bytes(read(bytes, offset)?))
    }

    fn check_bound(bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(format!("Mach-O executable must be 1 to {MAX_BYTES} bytes"));
        }
        Ok(())
    }

    fn thin_identity(bytes: &[u8]) -> Result<(Arch, u32), String> {
        if le32(bytes, 0)? != MH_MAGIC_64 || le32(bytes, 12)? != MH_EXECUTE {
            return Err("expected a thin 64-bit Mach-O executable".into());
        }
        let arch = Arch::from_cpu(le32(bytes, 4)?)?;
        let subtype = le32(bytes, 8)?;
        if subtype & 0x00ff_ffff != arch.generic_subtype() {
            return Err(format!("incompatible {arch:?} Mach-O CPU subtype"));
        }
        Ok((arch, subtype))
    }

    pub(crate) fn thin(bytes: &[u8], wanted: Arch, signed: bool) -> Result<(), String> {
        check_bound(bytes)?;
        let (actual, _) = thin_identity(bytes)?;
        if actual != wanted {
            return Err(format!("expected {wanted:?} Mach-O, got {actual:?}"));
        }
        let count = le32(bytes, 16)? as usize;
        let command_bytes = le32(bytes, 20)? as usize;
        let command_end = HEADER_BYTES
            .checked_add(command_bytes)
            .filter(|end| *end <= bytes.len())
            .ok_or("invalid Mach-O load command extent")?;
        if count == 0 || count > MAX_COMMANDS || count > command_bytes / 8 {
            return Err("invalid Mach-O load command count".into());
        }

        let mut cursor = HEADER_BYTES;
        let mut entry_offset = None;
        let mut executable_sections = Vec::new();
        let mut signature_found = false;
        for _ in 0..count {
            let command = le32(bytes, cursor)?;
            let size = le32(bytes, cursor + 4)? as usize;
            let end = cursor
                .checked_add(size)
                .filter(|end| size >= 8 && size.is_multiple_of(8) && *end <= command_end)
                .ok_or("invalid Mach-O load command size")?;
            match command {
                LC_SEGMENT_64 => {
                    if size < 72
                        || !(size - 72).is_multiple_of(80)
                        || (size - 72) / 80 != le32(bytes, cursor + 64)? as usize
                    {
                        return Err("invalid Mach-O segment command size".into());
                    }
                    let file_offset = u64::from_le_bytes(read(bytes, cursor + 40)?);
                    let file_size = u64::from_le_bytes(read(bytes, cursor + 48)?);
                    let file_end = file_offset
                        .checked_add(file_size)
                        .filter(|end| *end <= bytes.len() as u64)
                        .ok_or("invalid Mach-O file segment extent")?;
                    if le32(bytes, cursor + 60)? & 4 != 0 && file_size > 0 {
                        executable_sections.push(file_offset..file_end);
                    }
                }
                LC_MAIN => {
                    if entry_offset.is_some() || size != 24 {
                        return Err("invalid Mach-O entry point command".into());
                    }
                    let offset = u64::from_le_bytes(read(bytes, cursor + 8)?);
                    if offset < command_end as u64 || offset >= bytes.len() as u64 {
                        return Err("Mach-O entry point is outside executable code".into());
                    }
                    entry_offset = Some(offset);
                }
                LC_CODE_SIGNATURE => {
                    if signature_found || size != 16 {
                        return Err("invalid Mach-O signature command".into());
                    }
                    let offset = le32(bytes, cursor + 8)? as usize;
                    let length = le32(bytes, cursor + 12)? as usize;
                    if offset < command_end
                        || length < 12
                        || offset
                            .checked_add(length)
                            .is_none_or(|end| end > bytes.len())
                        || be32(bytes, offset)? != EMBEDDED_SIGNATURE
                        || !(12..=length).contains(&(be32(bytes, offset + 4)? as usize))
                    {
                        return Err("invalid embedded Mach-O signature extent".into());
                    }
                    signature_found = true;
                }
                _ => {}
            }
            cursor = end;
        }
        if cursor != command_end
            || !entry_offset.is_some_and(|offset| {
                executable_sections
                    .iter()
                    .any(|segment| segment.contains(&offset))
            })
            || signed && !signature_found
        {
            return Err("Mach-O commands do not contain the required executable metadata".into());
        }
        Ok(())
    }

    #[cfg(any(target_os = "macos", test))]
    fn fat_slice(
        bytes: &[u8],
        index: usize,
        wide: bool,
    ) -> Result<(Arch, u32, Range<usize>), String> {
        let record_size = if wide { 32 } else { 20 };
        let record = 8 + index * record_size;
        let arch = Arch::from_cpu(be32(bytes, record)?)?;
        let subtype = be32(bytes, record + 4)?;
        let (offset, length, align) = if wide {
            if be32(bytes, record + 28)? != 0 {
                return Err("invalid reserved Mach-O architecture field".into());
            }
            (
                be64(bytes, record + 8)?,
                be64(bytes, record + 16)?,
                be32(bytes, record + 24)?,
            )
        } else {
            (
                u64::from(be32(bytes, record + 8)?),
                u64::from(be32(bytes, record + 12)?),
                be32(bytes, record + 16)?,
            )
        };
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= bytes.len() as u64)
            .ok_or("universal Mach-O slice exceeds file bounds")?;
        if offset < (8 + 2 * record_size) as u64
            || length < HEADER_BYTES as u64
            || align > 31
            || offset & ((1u64 << align) - 1) != 0
        {
            return Err("invalid universal Mach-O slice size or alignment".into());
        }
        Ok((arch, subtype, offset as usize..end as usize))
    }

    #[cfg(any(target_os = "macos", test))]
    pub(super) fn universal(bytes: &[u8]) -> Result<(), String> {
        check_bound(bytes)?;
        let wide = match be32(bytes, 0)? {
            FAT_MAGIC => false,
            FAT_MAGIC_64 => true,
            _ => return Err("expected a universal Mach-O executable".into()),
        };
        if be32(bytes, 4)? != 2 {
            return Err("universal Mach-O must contain exactly two slices".into());
        }
        let left = fat_slice(bytes, 0, wide)?;
        let right = fat_slice(bytes, 1, wide)?;
        if left.0.other() != right.0 || left.2.start < right.2.end && right.2.start < left.2.end {
            return Err("universal Mach-O must contain one arm64 and one x86_64 slice".into());
        }
        for (arch, subtype, range) in [left, right] {
            let slice = &bytes[range];
            if thin_identity(slice)? != (arch, subtype) {
                return Err("universal Mach-O and contained slice CPU fields disagree".into());
            }
            thin(slice, arch, true)?;
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::fs::{self, DirBuilder, Metadata, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    use std::path::{Component, Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use agent_guard::json::JsonValue;

    use super::USAGE;
    use super::macho::{self, Arch, MAX_BYTES};

    const ARCHIVE_NAME: &str = "dotagent-macos-universal.tar.gz";
    const OUTPUT_LIMIT: u64 = 64 * 1024;
    const TOOL_TIMEOUT: Duration = Duration::from_secs(60);
    const O_NOFOLLOW: i32 = 0x0100;
    const O_NONBLOCK: i32 = 0x0004;
    const SMOKE_PROFILE: &str =
        "(version 1) (allow default) (deny network*) (deny file-write*) (deny process-fork)";

    struct Args<'a> {
        native: &'a Path,
        other: &'a Path,
        commit: &'a str,
        out: &'a Path,
    }

    impl<'a> Args<'a> {
        fn parse(argv: &'a [String]) -> Result<Self, String> {
            let mut native = None;
            let mut other = None;
            let mut commit = None;
            let mut out = None;
            let mut args = argv.iter().map(String::as_str);
            while let Some(flag) = args.next() {
                let slot = match flag {
                    "--native" => &mut native,
                    "--other" => &mut other,
                    "--commit" => &mut commit,
                    "--out-dir" => &mut out,
                    _ => return Err(format!("unknown preview option {flag:?}\n{USAGE}")),
                };
                if slot.is_some() {
                    return Err(format!("duplicate {flag}"));
                }
                *slot = Some(
                    args.next()
                        .filter(|value| {
                            !value.is_empty()
                                && !value.starts_with('-')
                                && !value.chars().any(char::is_control)
                        })
                        .ok_or_else(|| format!("{flag} requires a value"))?,
                );
            }
            let commit = commit.ok_or("missing --commit")?;
            if commit.len() != 40
                || !commit
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err("--commit requires a full lowercase Git commit SHA".into());
            }
            Ok(Self {
                native: Path::new(native.ok_or("missing --native")?),
                other: Path::new(other.ok_or("missing --other")?),
                commit,
                out: Path::new(out.ok_or("missing --out-dir")?),
            })
        }
    }

    fn absolute(path: &Path) -> Result<PathBuf, String> {
        if path
            .components()
            .any(|component| component == Component::ParentDir)
        {
            return Err(format!(
                "parent directory components are not allowed in '{}'",
                path.display()
            ));
        }
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|err| err.to_string())?
                .join(path)
        };
        Ok(path.components().collect())
    }

    fn canonical(path: &Path) -> Result<PathBuf, String> {
        let absolute = absolute(path)?;
        let resolved = fs::canonicalize(&absolute).map_err(|err| path_error(&absolute, err))?;
        if resolved != absolute {
            return Err(path_error(
                path,
                "expected a canonical path without symlinks",
            ));
        }
        Ok(absolute)
    }

    fn path_error(path: &Path, error: impl std::fmt::Display) -> String {
        format!("'{}': {error}", path.display())
    }

    fn same_file(left: &Metadata, right: &Metadata) -> bool {
        left.is_file()
            && right.is_file()
            && (left.dev(), left.ino(), left.len()) == (right.dev(), right.ino(), right.len())
            && (
                left.mtime(),
                left.mtime_nsec(),
                left.ctime(),
                left.ctime_nsec(),
            ) == (
                right.mtime(),
                right.mtime_nsec(),
                right.ctime(),
                right.ctime_nsec(),
            )
    }

    fn read_executable(path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
        let path = canonical(path)?;
        let file_error = |err| path_error(&path, err);
        let before = fs::symlink_metadata(&path).map_err(file_error)?;
        let limit = max_bytes as u64;
        if !before.is_file() || before.len() == 0 || before.len() > limit {
            return Err(path_error(
                &path,
                format!("expected a regular file of 1 to {max_bytes} bytes"),
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW | O_NONBLOCK)
            .open(&path)
            .map_err(file_error)?;
        let opened = file.metadata().map_err(file_error)?;
        if !same_file(&before, &opened) {
            return Err(path_error(&path, "executable changed while opening"));
        }
        let mut bytes = Vec::with_capacity(opened.len() as usize);
        (&file)
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(file_error)?;
        let after = file.metadata().map_err(file_error)?;
        let named = fs::symlink_metadata(&path).map_err(file_error)?;
        if bytes.len() as u64 != opened.len()
            || !same_file(&after, &opened)
            || !same_file(&named, &opened)
            || canonical(&path)? != path
        {
            return Err(path_error(&path, "executable changed while reading"));
        }
        Ok(bytes)
    }

    fn create_directory(path: &Path) -> Result<(), String> {
        DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|err| path_error(path, err))
    }

    struct Stage(PathBuf);

    impl Drop for Stage {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn stage_input(path: &Path, bytes: &[u8]) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(path)
            .map_err(|err| path_error(path, err))?;
        file.write_all(bytes).map_err(|err| path_error(path, err))
    }

    fn system(path: &str) -> Command {
        let mut command = Command::new(path);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C");
        command
    }

    fn collect(pipe: impl Read + Send + 'static) -> thread::JoinHandle<io::Result<Vec<u8>>> {
        thread::spawn(move || {
            let mut content = Vec::new();
            pipe.take(OUTPUT_LIMIT + 1).read_to_end(&mut content)?;
            Ok(content)
        })
    }

    fn bounded(command: &mut Command, label: &str) -> Result<String, String> {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| format!("{label}: {err}"))?;
        let output = collect(child.stdout.take().ok_or("missing preview tool stdout")?);
        let errors = collect(child.stderr.take().ok_or("missing preview tool stderr")?);
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() < TOOL_TIMEOUT => {
                    thread::sleep(Duration::from_millis(20));
                }
                result => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return match result {
                        Err(err) => Err(format!("{label}: {err}")),
                        _ => Err(format!("{label} timed out")),
                    };
                }
            }
        };
        if !status.success() {
            return Err(format!("{label} failed ({status})"));
        }
        let join = |reader: thread::JoinHandle<io::Result<Vec<u8>>>| {
            reader
                .join()
                .map_err(|_| format!("{label}: output reader failed"))?
                .map_err(|err| format!("{label}: {err}"))
        };
        let stdout = join(output)?;
        let stderr = join(errors)?;
        if stdout.len() as u64 > OUTPUT_LIMIT || stderr.len() as u64 > OUTPUT_LIMIT {
            return Err(format!("{label} exceeded its output limit"));
        }
        String::from_utf8(stdout).map_err(|err| format!("{label}: {err}"))
    }

    fn smoke(executable: &Path, stage: &Path, args: &[&str]) -> Result<String, String> {
        bounded(
            system("/usr/bin/sandbox-exec")
                .args(["-p", SMOKE_PROFILE])
                .arg(executable)
                .args(args)
                .current_dir(stage),
            "offline Dotagent smoke test",
        )
    }

    fn check_plan(output: &str) -> Result<(), String> {
        let plan = JsonValue::parse(output)
            .map_err(|err| format!("invalid offline ruleset JSON: {err}"))?;
        let Some([rule]) = plan.get("rulesets").and_then(JsonValue::as_array) else {
            return Err("unexpected offline ruleset list".into());
        };
        if plan.get("endpoint").and_then(JsonValue::as_str)
            != Some("repos/susanbdev/dotagent/rulesets")
            || rule.get("name").and_then(JsonValue::as_str) != Some("dotagent-zero-trust-main")
            || rule.get("target").and_then(JsonValue::as_str) != Some("branch")
            || rule.get("enforcement").and_then(JsonValue::as_str) != Some("active")
            || !rule
                .get("bypass_actors")
                .and_then(JsonValue::as_array)
                .is_some_and(<[_]>::is_empty)
        {
            return Err("unexpected offline ruleset plan".into());
        }
        Ok(())
    }

    pub(super) fn package(argv: &[String]) -> Result<(), String> {
        let args = Args::parse(argv)?;
        let host = Arch::host()?;
        let head = bounded(
            system("/usr/bin/git")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_TERMINAL_PROMPT", "0")
                .args(["rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"]),
            "verify checkout Git commit",
        )?;
        if head.trim_end() != args.commit {
            return Err("--commit does not match the current checkout".into());
        }

        let native = read_executable(args.native, MAX_BYTES)?;
        macho::thin(&native, host, false)?;
        let other = read_executable(args.other, MAX_BYTES - native.len())?;
        macho::thin(&other, host.other(), false)?;

        let out = absolute(args.out)?;
        let parent = out.parent().ok_or("output directory must have a parent")?;
        let name = out.file_name().ok_or("output directory must have a name")?;
        let out = canonical(parent)?.join(name);
        create_directory(&out)?;
        let stage_path = out.join("stage");
        create_directory(&stage_path)?;
        let stage = Stage(stage_path);
        let native_path = stage.0.join("native");
        let other_path = stage.0.join("other");
        stage_input(&native_path, &native)?;
        stage_input(&other_path, &other)?;
        drop(native);
        drop(other);

        let executable = stage.0.join("dotagent");
        bounded(
            system("/usr/bin/lipo")
                .arg("-create")
                .arg(&native_path)
                .arg(&other_path)
                .arg("-output")
                .arg(&executable),
            "assemble universal Mach-O",
        )?;
        bounded(
            system("/usr/bin/codesign")
                .args(["--force", "--sign", "-"])
                .arg(&executable),
            "ad-hoc sign universal Mach-O",
        )?;
        bounded(
            system("/usr/bin/codesign")
                .args(["--verify", "--strict", "--all-architectures"])
                .arg(&executable),
            "verify Mac code signatures",
        )?;
        let bytes = read_executable(&executable, MAX_BYTES)?;
        macho::universal(&bytes)?;
        let help = smoke(&executable, &stage.0, &["github-rulesets", "--help"])?;
        if !help.contains("Usage: dotagent github-rulesets") || !help.contains("--dry-run") {
            return Err("unexpected Dotagent ruleset help".into());
        }
        let plan = smoke(
            &executable,
            &stage.0,
            &[
                "github-rulesets",
                "--repo",
                "susanbdev/dotagent",
                "--dry-run",
            ],
        )?;
        check_plan(&plan)?;

        let archive = out.join(ARCHIVE_NAME);
        let build = format!(
            "Commit: {}\nSmoke-test host: {}\nSignature: ad hoc\n",
            args.commit,
            host.triple(),
        );
        crate::preview_archive::write_preview(&archive, &bytes, &build)?;
        println!("Created macOS preview '{}'", archive.display());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::macho::{Arch, thin, universal};

    const EXECUTABLE_BYTES: usize = 176;

    fn le32(bytes: &mut [u8], index: usize, value: u32) {
        bytes[index..index + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn be32(bytes: &mut [u8], index: usize, value: u32) {
        bytes[index..index + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn cpu(arch: Arch) -> (u32, u32) {
        match arch {
            Arch::Arm64 => (0x0100_000c, 0),
            Arch::X86_64 => (0x0100_0007, 3),
        }
    }

    fn executable(arch: Arch) -> [u8; EXECUTABLE_BYTES] {
        let mut bytes = [0; EXECUTABLE_BYTES];
        let (kind, subtype) = cpu(arch);
        for (index, value) in [
            (0, 0xfeed_facf),
            (4, kind),
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
            le32(&mut bytes, index, value);
        }
        be32(&mut bytes, 160, 0xfade_0cc0);
        be32(&mut bytes, 164, 12);
        bytes
    }

    #[test]
    fn thin_validation_checks_cpu_file_type_and_extent() {
        let mut bytes = executable(Arch::Arm64);
        assert!(thin(&bytes, Arch::Arm64, true).is_ok());
        assert!(thin(&bytes, Arch::X86_64, true).is_err());
        assert!(thin(&bytes[..168], Arch::Arm64, true).is_err());
        le32(&mut bytes, 40, 160);
        assert!(thin(&bytes, Arch::Arm64, true).is_err());
        le32(&mut bytes, 40, 144);
        le32(&mut bytes, 12, 1);
        assert!(thin(&bytes, Arch::Arm64, true).is_err());
    }

    #[test]
    fn universal_validation_checks_both_signed_executable_slices() {
        let offsets = [64, 240];
        let mut bytes = [0; 416];
        be32(&mut bytes, 0, 0xcafe_babe);
        be32(&mut bytes, 4, 2);
        for (index, arch) in [Arch::Arm64, Arch::X86_64].into_iter().enumerate() {
            let record = 8 + index * 20;
            let offset = offsets[index];
            let (kind, subtype) = cpu(arch);
            be32(&mut bytes, record, kind);
            be32(&mut bytes, record + 4, subtype);
            be32(&mut bytes, record + 8, offset as u32);
            be32(&mut bytes, record + 12, EXECUTABLE_BYTES as u32);
            be32(&mut bytes, record + 16, 4);
            bytes[offset..offset + EXECUTABLE_BYTES].copy_from_slice(&executable(arch));
        }
        assert!(universal(&bytes).is_ok());
        assert!(universal(&bytes[..415]).is_err());
        be32(&mut bytes, 28 + 8, 64);
        assert!(universal(&bytes).is_err());
        be32(&mut bytes, 28 + 8, 240);
        be32(&mut bytes, 240 + 160, 0);
        assert!(universal(&bytes).is_err());
    }
}
