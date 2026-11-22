//! Serialized local audit append, complete-frame recovery, and bounded retention.

use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::breadcrumbs::ExclusiveFileLockGuard;
use crate::json::JsonValue;
use crate::traversal_ledger::{O_NOFOLLOW_FLAG, audit_log_path, ensure_nonsymlink_state_dir};

pub(crate) use super::capture::MAX_RECORD_BYTES;
pub(crate) const DEFAULT_MAX_BYTES: u64 = 10 * 1024 * 1024;
pub(crate) const DEFAULT_KEEP: usize = 5;
pub(crate) const MAX_ARCHIVES: usize = 20;

static PERMISSION_FAILURES: AtomicU64 = AtomicU64::new(0);
static SPACE_FAILURES: AtomicU64 = AtomicU64::new(0);

pub(super) fn storage_failures() -> (u64, u64) {
    (PERMISSION_FAILURES.load(Ordering::Relaxed), SPACE_FAILURES.load(Ordering::Relaxed))
}

static FAILED_APPENDS: AtomicU64 = AtomicU64::new(0);
static EXPIRED_ARCHIVES: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub(crate) enum Durability {
    /// A complete frame was handed to the operating system.
    #[cfg(test)]
    Buffered,
    /// The frame was synced and new directory entries were synced if applicable.
    Required,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Receipt {
    pub(crate) bytes: usize,
    pub(crate) writer_wait_us: u64,
    pub(crate) durable: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CaptureError {
    InvalidRecord,
    InvalidState,
    LockUnavailable,
    UnboundedTail,
    Io(io::ErrorKind),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRecord => f.write_str("invalid audit frame"),
            Self::InvalidState => f.write_str("invalid protected audit path"),
            Self::LockUnavailable => f.write_str("audit writer lock unavailable"),
            Self::UnboundedTail => f.write_str("audit tail exceeds recovery bound"),
            Self::Io(kind) => write!(f, "audit I/O failure ({kind:?})"),
        }
    }
}

impl From<io::Error> for CaptureError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

pub(crate) fn append(record: &JsonValue, durability: Durability) -> Result<Receipt, CaptureError> {
    let result = append_at(
        &audit_log_path(),
        record,
        durability,
        DEFAULT_MAX_BYTES,
        DEFAULT_KEEP,
    );
    if let Err(error) = &result {
        count(&FAILED_APPENDS, 1);
        match error {
            CaptureError::Io(io::ErrorKind::PermissionDenied) => count(&PERMISSION_FAILURES, 1),
            CaptureError::Io(io::ErrorKind::StorageFull) => count(&SPACE_FAILURES, 1),
            _ => (),
        }
        #[cfg(all(unix, feature = "collector-fixture"))]
        super::release_probe::store_error(error);
    }
    result
}

fn count(counter: &AtomicU64, amount: u64) {
    let mut current = counter.load(Ordering::Relaxed);
    while let Err(observed) = counter.compare_exchange_weak(
        current,
        current.saturating_add(amount),
        Ordering::Relaxed,
        Ordering::Relaxed,
    ) {
        current = observed;
    }
}

fn charge(value: &JsonValue, remaining: &mut usize, depth: usize) -> Option<()> {
    if depth > 24 {
        return None;
    }
    *remaining = remaining.checked_sub(1)?;
    match value {
        JsonValue::Str(text) => *remaining = remaining.checked_sub(text.len())?,
        JsonValue::Array(items) => {
            for item in items {
                charge(item, remaining, depth + 1)?;
            }
        }
        JsonValue::Object(fields) => {
            for (name, entry) in fields {
                *remaining = remaining.checked_sub(name.len() + 1)?;
                charge(entry, remaining, depth + 1)?;
            }
        }
        _ => {}
    }
    Some(())
}

fn encode(record: &JsonValue) -> Result<Vec<u8>, CaptureError> {
    let mut remaining = MAX_RECORD_BYTES;
    if record.as_object().is_none() || charge(record, &mut remaining, 0).is_none() {
        return Err(CaptureError::InvalidRecord);
    }
    let mut frame = record.to_json_string().into_bytes();
    if frame.len() >= MAX_RECORD_BYTES || !frame.is_ascii() {
        return Err(CaptureError::InvalidRecord);
    }
    if std::str::from_utf8(&frame)
        .ok()
        .and_then(|text| JsonValue::parse(text).ok())
        .is_none()
    {
        return Err(CaptureError::InvalidRecord);
    }
    frame.push(b'\n');
    Ok(frame)
}

fn encode_with_writer_wait(
    record: &JsonValue,
    writer_wait_us: u64,
) -> Result<Vec<u8>, CaptureError> {
    if record.get("schema_version").is_none() || record.get("timing").is_none() {
        return encode(record);
    }
    let mut remaining = MAX_RECORD_BYTES;
    charge(record, &mut remaining, 0).ok_or(CaptureError::InvalidRecord)?;
    let mut measured = record.clone();
    let JsonValue::Object(fields) = &mut measured else {
        return Err(CaptureError::InvalidRecord);
    };
    let Some((_, JsonValue::Object(timing))) = fields.iter_mut().find(|(key, _)| key == "timing")
    else {
        return Err(CaptureError::InvalidRecord);
    };
    if timing.iter().any(|(key, _)| key == "writer_wait_us") {
        return Err(CaptureError::InvalidRecord);
    }
    timing.push(("writer_wait_us".into(), JsonValue::Uint(writer_wait_us)));
    encode(&measured)
}

fn prepare_parent(path: &Path) -> Result<&Path, CaptureError> {
    let parent = path.parent().ok_or(CaptureError::InvalidState)?;
    ensure_nonsymlink_state_dir(parent).map_err(|_| CaptureError::InvalidState)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::symlink_metadata(parent)?.permissions().mode() & 0o777 != 0o700 {
            return Err(CaptureError::InvalidState);
        }
    }
    Ok(parent)
}

fn regular_metadata(path: &Path) -> Result<Option<Metadata>, CaptureError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !meta.is_file() {
        return Err(CaptureError::InvalidState);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 || meta.mode() & 0o777 != 0o600 {
            return Err(CaptureError::InvalidState);
        }
    }
    Ok(Some(meta))
}

fn open_existing(path: &Path, meta: &Metadata, writable: bool) -> Result<File, CaptureError> {
    let mut options = OpenOptions::new();
    options.read(true).append(writable);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(O_NOFOLLOW_FLAG);
    }
    let file = options.open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() {
        return Err(CaptureError::InvalidState);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != meta.dev()
            || opened.ino() != meta.ino()
            || opened.nlink() != 1
            || opened.mode() & 0o777 != 0o600
        {
            return Err(CaptureError::InvalidState);
        }
    }
    #[cfg(not(unix))]
    let _ = meta;
    Ok(file)
}

fn create(path: &Path) -> Result<File, CaptureError> {
    let mut options = OpenOptions::new();
    options.read(true).append(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file.metadata()?.permissions().mode() & 0o777 != 0o600 {
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(file)
}

fn suffix_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

pub(crate) fn archive_path(path: &Path, index: usize) -> PathBuf {
    suffix_path(path, &format!(".{index}"))
}

pub(crate) fn open_audit_read(path: &Path) -> Result<Option<File>, CaptureError> {
    regular_metadata(path)?
        .map(|meta| open_existing(path, &meta, false))
        .transpose()
}

fn recover_tail(path: &Path, file: &mut File) -> Result<u64, CaptureError> {
    let quarantine = suffix_path(path, ".torn.pending");
    let pending = regular_metadata(&quarantine)?;
    let pending_len = pending.as_ref().map_or(0, Metadata::len);
    if pending_len > MAX_RECORD_BYTES as u64 {
        return Err(CaptureError::UnboundedTail);
    }
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(pending_len);
    }
    file.seek(SeekFrom::End(-1))?;
    let mut final_byte = [0];
    file.read_exact(&mut final_byte)?;
    if final_byte[0] == b'\n' {
        return Ok(pending_len);
    }
    let span = len.min(MAX_RECORD_BYTES as u64);
    file.seek(SeekFrom::Start(len - span))?;
    let mut tail = vec![0; span as usize];
    file.read_exact(&mut tail)?;
    let start = match tail.iter().rposition(|byte| *byte == b'\n') {
        Some(index) => index + 1,
        None if len == span => 0,
        None => return Err(CaptureError::UnboundedTail),
    };
    let torn = &tail[start..];
    let mut quarantined = match pending {
        Some(meta) => open_existing(&quarantine, &meta, true)?,
        None => create(&quarantine)?,
    };
    quarantined.set_len(0)?;
    quarantined.write_all(torn)?;
    quarantined.sync_data()?;
    sync_parent(path)?;
    let recovered_len = len - torn.len() as u64;
    file.set_len(recovered_len)?;
    file.seek(SeekFrom::Start(recovered_len))?;
    file.sync_data()?;
    Ok(torn.len() as u64)
}

fn finish_tail_recovery(path: &Path) -> Result<(), CaptureError> {
    let quarantine = suffix_path(path, ".torn");
    regular_metadata(&quarantine)?;
    fs::rename(suffix_path(path, ".torn.pending"), quarantine)?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> Result<(), CaptureError> {
    #[cfg(unix)]
    File::open(path.parent().ok_or(CaptureError::InvalidState)?)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn rotate_locked(path: &Path, keep: usize) -> Result<(), CaptureError> {
    let mut archives = Vec::with_capacity(MAX_ARCHIVES);
    for index in 1..=MAX_ARCHIVES {
        let archive = archive_path(path, index);
        archives.push((regular_metadata(&archive)?.is_some(), archive));
    }
    for (index, (exists, archive)) in archives.iter().enumerate().rev() {
        if !exists {
            continue;
        }
        if index + 1 >= keep {
            fs::remove_file(archive)?;
            count(&EXPIRED_ARCHIVES, 1);
        } else {
            fs::rename(archive, &archives[index + 1].1)?;
        }
    }
    fs::rename(path, &archives[0].1)?;
    sync_parent(path)
}

fn append_at(
    path: &Path,
    record: &JsonValue,
    durability: Durability,
    max_bytes: u64,
    keep: usize,
) -> Result<Receipt, CaptureError> {
    prepare_parent(path)?;
    let start = Instant::now();
    let _lock = ExclusiveFileLockGuard::acquire_observation(path)
        .map_err(|_| CaptureError::LockUnavailable)?;
    let writer_wait_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
    let frame = encode_with_writer_wait(record, writer_wait_us)?;
    let mut file = match regular_metadata(path)? {
        Some(meta) => open_existing(path, &meta, true)?,
        None => create(path)?,
    };
    let torn = recover_tail(path, &mut file)?;
    let len = file.metadata()?.len();
    // Reserve space for the bounded recovery frame before deciding whether to rotate.
    if len > 0 && len.saturating_add((frame.len() + MAX_RECORD_BYTES) as u64) > max_bytes {
        drop(file);
        rotate_locked(path, keep)?;
        file = create(path)?;
    }
    let durable = matches!(durability, Durability::Required);
    let recovered = write_health(path, &mut file, torn)?;
    #[cfg(all(unix, feature = "collector-fixture"))]
    if record.get("event_type").and_then(JsonValue::as_str) != Some("CAPTURE_HEALTH") {
        super::release_probe::before_store(&frame)?;
    }
    file.write_all(&frame)?;
    if durable {
        file.sync_data()?;
    }
    if durable || recovered {
        sync_parent(path)?;
    }
    Ok(Receipt {
        bytes: frame.len(),
        writer_wait_us,
        durable,
    })
}

fn write_health(path: &Path, file: &mut File, torn: u64) -> Result<bool, CaptureError> {
    let failed = FAILED_APPENDS.swap(0, Ordering::Relaxed);
    let expired = EXPIRED_ARCHIVES.swap(0, Ordering::Relaxed);
    if failed == 0 && torn == 0 && expired == 0 {
        return Ok(false);
    }
    let result = encode(&super::capture::capture_health_record(
        failed, torn, expired,
    ))
    .and_then(|health| {
        file.write_all(&health)?;
        file.sync_data()?;
        if torn != 0 {
            finish_tail_recovery(path)?;
        }
        Ok(true)
    });
    if result.is_err() {
        count(&FAILED_APPENDS, failed);
        count(&EXPIRED_ARCHIVES, expired);
    }
    result
}

pub(crate) fn rotate_at(path: &Path, max_bytes: u64, keep: usize) -> Result<bool, CaptureError> {
    prepare_parent(path)?;
    let _lock = ExclusiveFileLockGuard::acquire_observation(path)
        .map_err(|_| CaptureError::LockUnavailable)?;
    let Some(meta) = regular_metadata(path)? else {
        return Ok(false);
    };
    if meta.len() < max_bytes {
        return Ok(false);
    }
    let mut file = open_existing(path, &meta, true)?;
    let torn = recover_tail(path, &mut file)?;
    drop(file);
    rotate_locked(path, keep.clamp(1, MAX_ARCHIVES))?;
    let mut active = create(path)?;
    write_health(path, &mut active, torn)?;
    sync_parent(path)?;
    Ok(true)
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
