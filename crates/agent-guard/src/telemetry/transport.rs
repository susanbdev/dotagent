//! Private, generation-bound local transport. Only the collector creates filesystem entries.

use std::collections::{BTreeSet, VecDeque};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::capture;
use super::protocol::{MAX_FRAME, Record};
use super::runtime::{DropReason, Runtime};
use crate::breadcrumbs::ExclusiveFileLockGuard;
use crate::traversal_ledger::{O_NOFOLLOW_FLAG, observation_state_root_dir};

const ROUTE: &str = "route";
const SOCKET: &str = "in";
const RETRY_INTERVAL: Duration = Duration::from_millis(100);
const ROUTE_BYTES: usize = 48;
const REPLAY_LIMIT: usize = 16384;
static CLIENT: Mutex<Client> = Mutex::new(Client {
    peer: None,
    retry: None,
    sequence: 0,
});

fn invalid() -> io::Error {
    io::Error::from(io::ErrorKind::PermissionDenied)
}

fn uid(socket: &UnixDatagram) -> io::Result<u32> {
    let fd: OwnedFd = socket.try_clone()?.into();
    Ok(File::from(fd).metadata()?.uid())
}

fn private_dir(owner: u32, create: bool) -> io::Result<PathBuf> {
    let root = observation_state_root_dir();
    if !root.is_absolute() {
        return Err(invalid());
    }
    let dir = root.join("observations");
    for path in dir.ancestors().collect::<Vec<_>>().into_iter().rev() {
        let meta = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(e) if create && e.kind() == io::ErrorKind::NotFound => {
                match DirBuilder::new().mode(0o700).create(path) {
                    Ok(()) => (),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
                    Err(e) => return Err(e),
                }
                fs::symlink_metadata(path)?
            }
            Err(e) => return Err(e),
        };
        if !meta.is_dir() || (meta.uid() != owner && meta.uid() != 0) || meta.mode() & 0o022 != 0 {
            return Err(invalid());
        }
        if path == dir && (meta.uid() != owner || meta.mode() & 0o777 != 0o700) {
            return Err(invalid());
        }
    }
    Ok(dir)
}

fn socket_at<T>(dir: &Path, f: impl FnOnce(&Path) -> io::Result<T>) -> io::Result<T> {
    if O_NOFOLLOW_FLAG == 0 {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    }
    #[cfg(target_os = "linux")]
    {
        let fd = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW_FLAG)
            .open(dir)?;
        f(&PathBuf::from(format!(
            "/proc/self/fd/{}/{SOCKET}",
            fd.as_raw_fd()
        )))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let meta = fs::symlink_metadata(dir)?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(invalid());
        }
        let path = dir.join(SOCKET);
        if path.as_os_str().len() <= 95 {
            f(&path)
        } else {
            f(&crate::coordinator::shorten_unix_socket_via_cwd(&path))
        }
    }
}

fn identity(dir: &Path, owner: u32) -> io::Result<[u8; 16]> {
    let meta = fs::symlink_metadata(dir.join(SOCKET))?;
    if !meta.file_type().is_socket() || meta.uid() != owner || meta.mode() & 0o777 != 0o600 {
        return Err(invalid());
    }
    let mut id = [0; 16];
    id[..8].copy_from_slice(&meta.dev().to_be_bytes());
    id[8..].copy_from_slice(&meta.ino().to_be_bytes());
    Ok(id)
}

fn route(dir: &Path, owner: u32) -> io::Result<[u8; ROUTE_BYTES]> {
    let path = dir.join(ROUTE);
    let before = fs::symlink_metadata(&path)?;
    let valid = |m: &fs::Metadata| {
        m.is_file()
            && m.uid() == owner
            && m.nlink() == 1
            && m.mode() & 0o777 == 0o600
            && m.len() == ROUTE_BYTES as u64
    };
    if !valid(&before) {
        return Err(invalid());
    }
    #[cfg(target_os = "linux")]
    const NONBLOCK: i32 = 0o4000;
    #[cfg(not(target_os = "linux"))]
    const NONBLOCK: i32 = 4;
    if O_NOFOLLOW_FLAG == 0 {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW_FLAG | NONBLOCK)
        .open(path)?;
    let after = file.metadata()?;
    if !valid(&after) || (before.dev(), before.ino()) != (after.dev(), after.ino()) {
        return Err(invalid());
    }
    let mut bytes = [0; ROUTE_BYTES];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

struct Peer {
    socket: UnixDatagram,
    key: [u8; 32],
}

impl Peer {
    fn open() -> io::Result<Self> {
        let socket = UnixDatagram::unbound()?;
        socket.set_nonblocking(true)?;
        let owner = uid(&socket)?;
        let dir = private_dir(owner, false)?;
        let route = route(&dir, owner)?;
        if identity(&dir, owner)? != route[..16] {
            return Err(invalid());
        }
        socket_at(&dir, |path| socket.connect(path))?;
        if identity(&dir, owner)? != route[..16] {
            return Err(invalid());
        }
        Ok(Self {
            socket,
            key: route[16..].try_into().map_err(|_| invalid())?,
        })
    }
}

fn failure(error: &io::Error) -> DropReason {
    #[cfg(target_os = "linux")]
    let (no_buffers, oversized) = (105, 90);
    #[cfg(not(target_os = "linux"))]
    let (no_buffers, oversized) = (55, 40);
    if error.raw_os_error() == Some(no_buffers) {
        return DropReason::Full;
    }
    if error.raw_os_error() == Some(oversized) {
        return DropReason::Invalid;
    }
    match error.kind() {
        io::ErrorKind::WouldBlock => DropReason::Full,
        io::ErrorKind::NotFound
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::NotConnected
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset => DropReason::Unavailable,
        _ => DropReason::Transport,
    }
}

struct Client {
    peer: Option<Peer>,
    retry: Option<Instant>,
    sequence: u64,
}

impl Client {
    fn ready(&mut self) -> Result<(), DropReason> {
        if self.peer.is_some() {
            return Ok(());
        }
        let now = Instant::now();
        if self.retry.is_some_and(|after| now < after) {
            return Err(DropReason::Unavailable);
        }
        self.retry = Some(now + RETRY_INTERVAL);
        self.peer = Some(Peer::open().map_err(|e| failure(&e))?);
        Ok(())
    }
}

fn probe_peer_ready() -> bool {
    enabled()
        && CLIENT
            .try_lock()
            .is_ok_and(|mut client| client.ready().is_ok())
}

/// The explicit operator baseline may wait for its new collector before running its checks.
pub(super) fn prepare_baseline() {
    if !enabled() {
        return;
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while !probe_peer_ready() && Instant::now() < deadline {
        std::thread::park_timeout(Duration::from_millis(20));
    }
}

pub(super) fn enabled() -> bool {
    O_NOFOLLOW_FLAG != 0
        && capture::host_capture_allowed()
        && std::env::var_os("DOTAGENT_TELEMETRY").as_deref() != Some(std::ffi::OsStr::new("0"))
}

pub(super) fn send<T>(build: impl FnOnce() -> Option<(Record, T)>) -> Result<T, DropReason> {
    if !enabled() {
        return Err(DropReason::Unavailable);
    }
    let mut client = CLIENT.try_lock().map_err(|_| DropReason::Contended)?;
    client.ready()?;
    let (record, receipt) = build().ok_or(DropReason::Invalid)?;
    client.sequence = client.sequence.checked_add(1).ok_or(DropReason::Closed)?;
    let peer = client.peer.as_ref().ok_or(DropReason::Unavailable)?;
    let frame = record
        .frame(
            &peer.key,
            client.sequence,
            capture::unix_time_ms().ok_or(DropReason::Invalid)?,
        )
        .ok_or(DropReason::Invalid)?;
    match peer.socket.send(&frame) {
        Ok(n) if n == frame.len() => Ok(receipt),
        Ok(_) => Err(DropReason::Transport),
        Err(error) => {
            let reason = failure(&error);
            if reason != DropReason::Full {
                client.peer = None;
            }
            Err(reason)
        }
    }
}

fn child_command(role: &str) -> io::Result<Command> {
    use std::os::unix::process::CommandExt;
    let current = std::env::current_exe()?;
    #[cfg(target_os = "linux")]
    let mut command = {
        let mut c = Command::new("/proc/self/exe");
        c.arg0(&current);
        c
    };
    #[cfg(not(target_os = "linux"))]
    let mut command = Command::new(current);
    command.process_group(0);
    command.arg(role).arg("--owned").env_clear();
    for name in ["HOME", "AGENT_GUARD_STATE_DIR"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Ok(command)
}

#[cfg(not(test))]
pub(super) fn launch() -> Option<Child> {
    if !enabled() {
        return None;
    }
    child_command("supervise-observations").ok()?.spawn().ok()
}

/// Owns the child and its restart budget outside the guard's panic and scheduling domain.
pub(crate) fn supervise() -> io::Result<()> {
    if !enabled() {
        return Err(invalid());
    }
    let (closed, owner) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("observation-owner".into())
        .spawn(move || {
            let _ = io::stdin().read(&mut [0]);
            let _ = closed.send(());
        })?;
    let mut child: Option<Child> = None;
    let mut starts = VecDeque::with_capacity(3);
    loop {
        if let Some(process) = &mut child
            && process.try_wait()?.is_some()
        {
            child = None;
        }
        let now = Instant::now();
        while starts.front().is_some_and(|tick| *tick <= now) {
            starts.pop_front();
        }
        if child.is_none() && starts.len() < 3 && Peer::open().is_err() {
            starts.push_back(now + Duration::from_secs(60));
            child = child_command("collect-observations")?.spawn().ok();
        }
        if !matches!(
            owner.recv_timeout(Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) {
            break;
        }
    }
    if let Some(mut child) = child {
        drop(child.stdin.take());
        let deadline = Instant::now() + Duration::from_millis(350);
        while child.try_wait()?.is_none() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    Ok(())
}

struct Endpoint {
    socket: UnixDatagram,
    dir: PathBuf,
    dir_id: (u64, u64),
    owner: u32,
    id: [u8; 16],
    key: [u8; 32],
}

impl Endpoint {
    fn bind() -> io::Result<Option<Self>> {
        let probe = UnixDatagram::unbound()?;
        probe.set_nonblocking(true)?;
        let owner = uid(&probe)?;
        let dir = private_dir(owner, true)?;
        let dir_meta = fs::symlink_metadata(&dir)?;
        if dir_meta.file_type().is_symlink() || !dir_meta.is_dir() {
            return Err(invalid());
        }
        let dir_id = (dir_meta.dev(), dir_meta.ino());
        let path = dir.join(SOCKET);
        let _lock = ExclusiveFileLockGuard::acquire_observation(&path).map_err(io::Error::other)?;
        match identity(&dir, owner) {
            Ok(_) => match socket_at(&dir, |p| probe.connect(p)) {
                Ok(()) => return Ok(None),
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => fs::remove_file(&path)?,
                Err(e) => return Err(e),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        let mut key = [0; 32];
        File::open("/dev/urandom")?.read_exact(&mut key)?;
        let socket = socket_at(&dir, |p| UnixDatagram::bind(p))?;
        let sock_meta = fs::symlink_metadata(&path)?;
        if sock_meta.file_type().is_symlink()
            || !sock_meta.file_type().is_socket()
            || sock_meta.uid() != owner
        {
            return Err(invalid());
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let id = identity(&dir, owner)?;
        let endpoint = Self {
            socket,
            dir,
            dir_id,
            owner,
            id,
            key,
        };
        endpoint.verified_dir()?;
        let staging = endpoint.dir.join(format!("route-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(O_NOFOLLOW_FLAG)
            .mode(0o600)
            .open(&staging)?;
        let route_dst = endpoint.dir.join(ROUTE);
        if fs::symlink_metadata(&route_dst).is_ok_and(|m| m.file_type().is_symlink()) {
            let _ = fs::remove_file(&staging);
            return Err(invalid());
        }
        let publish = file
            .write_all(&id)
            .and_then(|()| file.write_all(&key))
            .and_then(|()| endpoint.verified_dir().map(|_| ()))
            .and_then(|()| fs::rename(&staging, &route_dst));
        if let Err(error) = publish {
            let _ = fs::remove_file(staging);
            return Err(error);
        }
        endpoint
            .socket
            .set_read_timeout(Some(Duration::from_millis(100)))?;
        Ok(Some(endpoint))
    }

    fn verified_dir(&self) -> io::Result<&Path> {
        let checked = private_dir(self.owner, false)?;
        if checked != self.dir {
            return Err(invalid());
        }
        let dm = fs::symlink_metadata(&self.dir)?;
        if dm.file_type().is_symlink() || !dm.is_dir() || (dm.dev(), dm.ino()) != self.dir_id {
            return Err(invalid());
        }
        Ok(&self.dir)
    }
}

impl Endpoint {
    fn report(
        &self,
        counts: (super::runtime::Counters, super::runtime::Counters),
        closing: bool,
        last_producer: &crate::json::JsonValue,
    ) -> io::Result<()> {
        let dir = self.verified_dir()?;
        let stage = dir.join(format!("health-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(O_NOFOLLOW_FLAG)
            .mode(0o600)
            .open(&stage)?;
        let mut status = super::runtime_health::status(counts.0, counts.1, closing);
        if let crate::json::JsonValue::Object(fields) = &mut status {
            fields.push(("last_producer_before_handoff".into(), last_producer.clone()));
            fields.push((
                "collector_pid".into(),
                crate::json::JsonValue::Uint(u64::from(std::process::id())),
            ));
            fields.push((
                "generation".into(),
                crate::json::JsonValue::Str(crate::crypto::hex_encode(&self.id)),
            ));
        }
        let status = status.to_json_string();
        let health_dst = dir.join("health");
        if fs::symlink_metadata(&health_dst).is_ok_and(|m| m.file_type().is_symlink()) {
            let _ = fs::remove_file(&stage);
            return Err(invalid());
        }
        let result = file
            .write_all(status.as_bytes())
            .and_then(|()| self.verified_dir().map(|_| ()))
            .and_then(|()| fs::rename(&stage, health_dst));
        if result.is_err() {
            let _ = fs::remove_file(stage);
        }
        result
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        if self.verified_dir().is_ok() && identity(&self.dir, self.owner).ok() == Some(self.id) {
            if fs::symlink_metadata(self.dir.join(ROUTE)).is_ok_and(|m| !m.file_type().is_symlink())
            {
                let _ = fs::remove_file(self.dir.join(ROUTE));
            }
            let _ = fs::remove_file(self.dir.join(SOCKET));
        }
    }
}

pub(super) fn delivery_status() -> io::Result<crate::json::JsonValue> {
    use crate::json::JsonValue;
    let socket = UnixDatagram::unbound()?;
    let dir = private_dir(uid(&socket)?, false)?;
    let mut data = String::new();
    super::store::open_audit_read(&dir.join("health"))
        .map_err(|e| io::Error::other(e.to_string()))?
        .ok_or(io::ErrorKind::NotFound)?
        .take(8193)
        .read_to_string(&mut data)?;
    if data.len() > 8192 {
        return Err(invalid());
    }
    let snapshot = JsonValue::parse(&data).map_err(io::Error::other)?;
    let mut clean = super::runtime_health::read(&snapshot).ok_or_else(invalid)?;
    if let JsonValue::Object(fields) = &mut clean {
        for name in ["collector_pid", "storage_permission_denied", "storage_full"] {
            if let Some(n) = snapshot.get(name).and_then(JsonValue::as_u64) {
                fields.push((name.into(), JsonValue::Uint(n)));
            }
        }
        if let Some(last) = snapshot.get("last_producer_before_handoff") {
            let mut counts = Vec::new();
            for name in [
                "pid",
                "frame_sequence",
                "accepted",
                "capacity",
                "contended",
                "unavailable",
                "invalid",
                "transport",
                "closed",
            ] {
                if let Some(n) = last.get(name).and_then(JsonValue::as_u64) {
                    counts.push((name.into(), JsonValue::Uint(n)));
                }
            }
            fields.push((
                "last_producer_before_handoff".into(),
                JsonValue::Object(counts),
            ));
        }
    }
    Ok(JsonValue::Object(vec![
        (
            "collector_available".into(),
            JsonValue::Bool(Peer::open().is_ok()),
        ),
        ("last_collector_snapshot".into(), clean),
    ]))
}

pub(crate) fn collect(owned: bool) -> io::Result<()> {
    if !enabled() {
        return Err(invalid());
    }
    let Some(endpoint) = Endpoint::bind()? else {
        return Ok(());
    };
    static CLOSING: AtomicBool = AtomicBool::new(false);
    if owned {
        std::thread::Builder::new()
            .name("collector-owner".into())
            .spawn(|| {
                let _ = io::stdin().read(&mut [0]);
                CLOSING.store(true, Ordering::Release);
            })?;
    }
    let runtime = Runtime::start(super::runtime::QUEUE_CAPACITY, true);
    writeln!(io::stdout().lock(), "READY")?;
    #[cfg(feature = "collector-fixture")]
    let _held = super::release_probe::exhaust_fds();
    let mut buf = [0; MAX_FRAME + 1];
    let mut seen = BTreeSet::new();
    let mut expiry = VecDeque::new();
    let mut last_report = None;
    let mut last_producer = crate::json::JsonValue::Null;
    let mut next_report = Instant::now();
    let mut drain_left = super::runtime::QUEUE_CAPACITY;
    loop {
        if Instant::now() >= next_report {
            let counts = runtime.counts();
            if Some(counts) != last_report && endpoint.report(counts, false, &last_producer).is_ok()
            {
                last_report = Some(counts);
            }
            next_report = Instant::now() + Duration::from_millis(100);
        }
        if CLOSING.load(Ordering::Acquire) {
            if drain_left == 0 {
                break;
            }
            drain_left -= 1;
            endpoint.socket.set_nonblocking(true)?;
        }
        match endpoint.socket.recv(&mut buf) {
            Ok(n) => {
                let Some(now) = capture::unix_time_ms() else {
                    continue;
                };
                let Some(received) = Record::parse(&buf[..n], &endpoint.key, now) else {
                    runtime.rejected(DropReason::Invalid);
                    continue;
                };
                let tick = Instant::now();
                while expiry.front().is_some_and(|(t, _)| *t <= tick) {
                    if let Some((_, old)) = expiry.pop_front() {
                        seen.remove(&old);
                    }
                }
                let tag = received.tag;
                if seen.len() == REPLAY_LIMIT {
                    runtime.rejected(DropReason::Full);
                    continue;
                }
                if !seen.insert(tag) {
                    runtime.rejected(DropReason::Invalid);
                    continue;
                }
                expiry.push_back((tick + Duration::from_secs(61), tag));
                #[cfg(feature = "collector-fixture")]
                super::release_probe::after_receive();
                last_producer = received.diagnostic();
                runtime.receive(received.record);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if CLOSING.load(Ordering::Acquire) {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
            Err(e) => return Err(e),
        }
    }
    runtime.finish(Duration::from_millis(200));
    let _ = endpoint.report(runtime.counts(), true, &last_producer);
    Ok(())
}
