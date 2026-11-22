//! Private, generation-bound local transport. Only the collector creates filesystem entries.

use std::collections::{BTreeSet, VecDeque};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
#[cfg(not(test))]
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
static CLIENT: Mutex<Client> = Mutex::new(Client { peer: None, retry: None, sequence: 0 });

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
    let path = dir.join(SOCKET);
    if path.as_os_str().len() <= 95 {
        return f(&path);
    }
    #[cfg(target_os = "linux")]
    {
        let fd = OpenOptions::new().read(true).custom_flags(O_NOFOLLOW_FLAG).open(dir)?;
        f(&PathBuf::from(format!("/proc/self/fd/{}/{SOCKET}", fd.as_raw_fd())))
    }
    #[cfg(not(target_os = "linux"))]
    f(&crate::coordinator::shorten_unix_socket_via_cwd(&path))
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
        m.is_file() && m.uid() == owner && m.nlink() == 1
            && m.mode() & 0o777 == 0o600 && m.len() == ROUTE_BYTES as u64
    };
    if !valid(&before) {
        return Err(invalid());
    }
    #[cfg(target_os = "linux")]
    const NONBLOCK: i32 = 0o4000;
    #[cfg(not(target_os = "linux"))]
    const NONBLOCK: i32 = 4;
    let mut file = OpenOptions::new().read(true).custom_flags(O_NOFOLLOW_FLAG | NONBLOCK).open(path)?;
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
        Ok(Self { socket, key: route[16..].try_into().map_err(|_| invalid())? })
    }
}

fn failure(error: &io::Error) -> DropReason {
    match error.kind() {
        io::ErrorKind::WouldBlock => DropReason::Full,
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused | io::ErrorKind::NotConnected
        | io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => DropReason::Unavailable,
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

pub(super) fn active() -> bool {
    enabled() && CLIENT.try_lock().is_ok_and(|mut client| client.ready().is_ok())
}

fn enabled() -> bool {
    capture::host_capture_allowed()
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
    let frame = record.frame(&peer.key, client.sequence, capture::unix_time_ms().ok_or(DropReason::Invalid)?)
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

#[cfg(not(test))]
pub(super) fn launch() -> Option<Child> {
    if !enabled() || active() {
        return None;
    }
    let mut command = Command::new(std::env::current_exe().ok()?);
    command.arg("collect-observations").arg("--owned").env_clear();
    for name in ["HOME", "AGENT_GUARD_STATE_DIR"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().ok()
}

struct Endpoint {
    socket: UnixDatagram,
    dir: PathBuf,
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
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let id = identity(&dir, owner)?;
        let endpoint = Self { socket, dir, owner, id, key };
        let staging = endpoint.dir.join(format!("route-{}", crate::crypto::hex_encode(&key[..8])));
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&staging)?;
        let publish = file.write_all(&id).and_then(|()| file.write_all(&key))
            .and_then(|()| fs::rename(&staging, endpoint.dir.join(ROUTE)));
        if let Err(error) = publish {
            let _ = fs::remove_file(staging);
            return Err(error);
        }
        endpoint.socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        Ok(Some(endpoint))
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        if identity(&self.dir, self.owner).ok() == Some(self.id) {
            let _ = fs::remove_file(self.dir.join(ROUTE));
            let _ = fs::remove_file(self.dir.join(SOCKET));
        }
    }
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
        std::thread::Builder::new().name("collector-owner".into()).spawn(|| {
            let _ = io::stdin().read(&mut [0]);
            CLOSING.store(true, Ordering::Release);
        })?;
    } else {
        writeln!(io::stdout().lock(), "READY")?;
    }
    let runtime = Runtime::start(super::runtime::QUEUE_CAPACITY, true);
    let mut buf = [0; MAX_FRAME + 1];
    let mut seen = BTreeSet::new();
    let mut expiry = VecDeque::new();
    loop {
        if CLOSING.load(Ordering::Acquire) {
            endpoint.socket.set_nonblocking(true)?;
        }
        match endpoint.socket.recv(&mut buf) {
            Ok(n) => {
                let Some(now) = capture::unix_time_ms() else { continue };
                let Some((record, tag)) = Record::parse(&buf[..n], &endpoint.key, now) else {
                    runtime.rejected();
                    continue;
                };
                let tick = Instant::now();
                while expiry.front().is_some_and(|(t, _)| *t <= tick) {
                    if let Some((_, old)) = expiry.pop_front() {
                        seen.remove(&old);
                    }
                }
                if seen.len() == REPLAY_LIMIT || !seen.insert(tag) {
                    runtime.rejected();
                    continue;
                }
                expiry.push_back((tick + Duration::from_secs(61), tag));
                runtime.receive(record);
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                if CLOSING.load(Ordering::Acquire) { break; }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
            Err(e) => return Err(e),
        }
    }
    runtime.finish();
    Ok(())
}
