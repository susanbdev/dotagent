use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(any(target_os = "macos", test))]
use agent_guard::crypto::sha256_hex;
use flate2::{Compression, GzBuilder, write::GzEncoder};
use tar::{Builder, EntryType, Header};

#[cfg(any(target_os = "macos", test))]
const MAX_EXECUTABLE_BYTES: usize = 256 * 1024 * 1024;
#[cfg(any(target_os = "macos", test))]
const MAX_BUILD_BYTES: usize = 16 * 1024;
static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(any(target_os = "macos", test))]
pub(crate) fn write_preview(
    archive_path: &Path,
    executable: &[u8],
    build: &str,
) -> Result<(), String> {
    if executable.is_empty() || executable.len() > MAX_EXECUTABLE_BYTES {
        return Err(format!(
            "preview executable must contain 1 to {MAX_EXECUTABLE_BYTES} bytes"
        ));
    }
    if build.is_empty() || build.len() > MAX_BUILD_BYTES {
        return Err(format!(
            "preview build information must contain 1 to {MAX_BUILD_BYTES} bytes"
        ));
    }
    publish_archive(archive_path, |file| write_archive(file, executable, build)).map_err(|error| {
        format!(
            "cannot publish preview '{}': {error}",
            archive_path.display()
        )
    })
}

pub(crate) fn publish_archive(
    archive_path: &Path,
    write: impl FnOnce(File) -> io::Result<File>,
) -> io::Result<()> {
    let name = archive_path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "expected an archive filename")
    })?;
    let parent = archive_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = parent.canonicalize()?;
    let destination = parent.join(name);
    match destination.symlink_metadata() {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "archive destination already exists",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let staged = StagedArchive::new(&parent)?;
    let file = staged.open()?;
    let file = write(file)?;
    file.sync_all()?;
    drop(file);

    // The staging file and destination share a filesystem. An existing target,
    // including a symlink, makes this atomic publication fail without clobbering it.
    fs::hard_link(staged.file(), destination)
}

struct StagedArchive(PathBuf);

impl StagedArchive {
    fn new(parent: &Path) -> io::Result<Self> {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        for _ in 0..64 {
            let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                ".dotagent-preview-{}-{sequence}",
                std::process::id()
            ));
            match builder.create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "failed to reserve a preview staging directory",
        ))
    }

    fn file(&self) -> PathBuf {
        self.0.join("archive.tar.gz")
    }

    fn open(&self) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o644);
        }
        options.open(self.file())
    }
}

impl Drop for StagedArchive {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.file());
        let _ = fs::remove_dir(&self.0);
    }
}

#[cfg(any(target_os = "macos", test))]
fn write_archive<W: Write>(sink: W, executable: &[u8], build: &str) -> io::Result<W> {
    let checksum = format!("{}  dotagent\n", sha256_hex(executable));
    let mut archive = tar_builder(sink);
    append_entry(
        &mut archive,
        "dotagent",
        EntryType::Regular,
        0o755,
        executable,
    )?;
    append_entry(
        &mut archive,
        "SHA256SUMS",
        EntryType::Regular,
        0o644,
        checksum.as_bytes(),
    )?;
    append_entry(
        &mut archive,
        "BUILD.txt",
        EntryType::Regular,
        0o644,
        build.as_bytes(),
    )?;
    finish_tar(archive)
}

pub(crate) fn tar_builder<W: Write>(sink: W) -> Builder<GzEncoder<W>> {
    let encoder = GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(sink, Compression::default());
    Builder::new(encoder)
}

pub(crate) fn finish_tar<W: Write>(mut archive: Builder<GzEncoder<W>>) -> io::Result<W> {
    archive.finish()?;
    archive.into_inner()?.finish()
}

pub(crate) fn append_entry<W: Write>(
    archive: &mut Builder<W>,
    name: &str,
    kind: EntryType,
    mode: u32,
    data: &[u8],
) -> io::Result<()> {
    let mut header = Header::new_ustar();
    header.set_entry_type(kind);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(data.len() as u64);
    archive.append_data(&mut header, name, data)
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use flate2::read::GzDecoder;

    use super::*;

    #[test]
    fn preview_archive_is_deterministic_and_roundtrips() {
        let binary = b"abc";
        let build = "Commit: abc123\nSignature: ad hoc\n";
        let first = write_archive(Vec::new(), binary, build).unwrap();
        assert_eq!(first, write_archive(Vec::new(), binary, build).unwrap());
        let gzip = GzDecoder::new(first.as_slice());
        let gzip_header = gzip.header().unwrap();
        assert_eq!(gzip_header.mtime(), 0);
        assert_eq!(gzip_header.operating_system(), 255);
        assert!(gzip_header.filename().is_none());

        let checksum =
            b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  dotagent\n";
        let expected = [
            ("dotagent", 0o755, binary.as_slice()),
            ("SHA256SUMS", 0o644, checksum.as_slice()),
            ("BUILD.txt", 0o644, build.as_bytes()),
        ];
        let mut tar = tar::Archive::new(gzip);
        let mut entries = tar.entries().unwrap();
        for (name, mode, data) in expected {
            let mut entry = entries.next().unwrap().unwrap();
            assert_eq!(entry.path().unwrap().as_ref(), Path::new(name));
            let header = entry.header();
            assert!(header.entry_type().is_file());
            assert_eq!(header.mode().unwrap(), mode);
            assert_eq!(header.uid().unwrap(), 0);
            assert_eq!(header.gid().unwrap(), 0);
            assert_eq!(header.mtime().unwrap(), 0);
            let mut actual = Vec::new();
            entry.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, data);
        }
        assert!(entries.next().is_none());
    }

    #[test]
    fn publication_preserves_existing_archive_and_cleans_staging() {
        let scratch = StagedArchive::new(&std::env::current_dir().unwrap()).unwrap();
        let output = scratch.file();
        write_preview(&output, b"original", "Build 1\n").unwrap();
        let original = fs::read(&output).unwrap();
        let error = write_preview(&output, b"replacement", "Build 2\n").unwrap_err();
        assert!(error.contains("archive destination already exists"));
        assert_eq!(fs::read(&output).unwrap(), original);
        assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 1);
    }
}
