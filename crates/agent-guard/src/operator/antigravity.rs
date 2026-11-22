//! Workspace-only installation of the bundle's native Antigravity hooks.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::crypto::sha256_hex;
use crate::exec_sandbox::shell_quote_single;
use crate::json::JsonValue;

const TEMPLATE: &str = "dist/antigravity/hooks.json";
const MAX_CONFIG: u64 = 262_144;
const MAX_BACKUP: u64 = MAX_CONFIG * 7;
const BACKUP_FORMAT: &str = "dotagent.antigravity.activation.v1";
const HOOK_EVENTS: &[&str] = &[
    "SessionStart",
    "PreToolUse",
    "PostToolUse",
    "PreInvocation",
    "PostInvocation",
    "Stop",
];

#[derive(Clone, Eq, PartialEq)]
struct Snapshot {
    text: String,
    mode: u32,
}

struct Backup {
    previous: Option<Snapshot>,
    managed: JsonValue,
    installed_digest: String,
    created_agents_dir: bool,
}

impl Backup {
    fn parse(text: &str) -> Result<Self, String> {
        let data =
            JsonValue::parse(text).map_err(|e| format!("invalid Antigravity backup: {e}"))?;
        let invalid = || "unrecognized Antigravity activation backup".to_string();
        if data.get("format").and_then(JsonValue::as_str) != Some(BACKUP_FORMAT) {
            return Err(invalid());
        }
        let previous = match data.get("previous") {
            Some(JsonValue::Null) => None,
            Some(value) => {
                let text = value
                    .get("config")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(invalid)?;
                if text.len() as u64 > MAX_CONFIG {
                    return Err(invalid());
                }
                let mode = value
                    .get("mode")
                    .and_then(JsonValue::as_u64)
                    .filter(|mode| *mode <= 0o777)
                    .ok_or_else(invalid)? as u32;
                config_entries(Some(text))?;
                Some(Snapshot {
                    text: text.to_string(),
                    mode,
                })
            }
            None => return Err(invalid()),
        };
        let managed = data
            .get("managed")
            .filter(|value| value.as_object().is_some())
            .ok_or_else(invalid)?
            .clone();
        let installed_digest = data
            .get("installed_sha256")
            .and_then(JsonValue::as_str)
            .filter(|digest| digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(invalid)?
            .to_string();
        let created_agents_dir = data
            .get("created_agents_dir")
            .and_then(JsonValue::as_bool)
            .ok_or_else(invalid)?;
        Ok(Self {
            previous,
            managed,
            installed_digest,
            created_agents_dir,
        })
    }

    fn serialize(&self) -> String {
        let previous = self.previous.as_ref().map_or(JsonValue::Null, |value| {
            JsonValue::Object(vec![
                ("config".into(), JsonValue::Str(value.text.clone())),
                ("mode".into(), JsonValue::Uint(u64::from(value.mode))),
            ])
        });
        serialize_object(vec![
            ("format".into(), JsonValue::Str(BACKUP_FORMAT.into())),
            ("previous".into(), previous),
            ("managed".into(), self.managed.clone()),
            (
                "installed_sha256".into(),
                JsonValue::Str(self.installed_digest.clone()),
            ),
            (
                "created_agents_dir".into(),
                JsonValue::Bool(self.created_agents_dir),
            ),
        ])
    }
}

struct Paths {
    agents: PathBuf,
    hooks: PathBuf,
    backup: PathBuf,
}

impl Paths {
    fn new(workspace: &Path) -> Self {
        let agents = workspace.join(".agents");
        let hooks = agents.join("hooks.json");
        let backup = super::backup_path_for(&hooks);
        Self {
            agents,
            hooks,
            backup,
        }
    }
}

struct WorkspaceLock {
    path: PathBuf,
    created_agents_dir: bool,
}

impl WorkspaceLock {
    fn acquire(agents: &Path, create: bool) -> Result<Self, String> {
        let created_agents_dir = if create && !directory_exists(agents)? {
            match fs::create_dir(agents) {
                Ok(()) => true,
                Err(e) if e.kind() == ErrorKind::AlreadyExists => false,
                Err(e) => {
                    return Err(format!(
                        "create Antigravity directory '{}': {e}",
                        agents.display()
                    ));
                }
            }
        } else {
            false
        };
        if !directory_exists(agents)? {
            return Err("Antigravity workspace directory is missing".into());
        }
        let path = agents.join(".hooks.json.dotagent.lock");
        match create_new(&path) {
            Ok(_) => Ok(Self {
                path,
                created_agents_dir,
            }),
            Err(e) => {
                if created_agents_dir {
                    let _ = fs::remove_dir(agents);
                }
                Err(format!(
                    "cannot lock Antigravity workspace '{}': {e}",
                    agents.display()
                ))
            }
        }
    }
}

impl Drop for WorkspaceLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        if self.created_agents_dir
            && let Some(dir) = self.path.parent()
        {
            let _ = fs::remove_dir(dir);
        }
    }
}

pub(super) fn workspace_root(cwd: &Path, path: &Path) -> Result<PathBuf, String> {
    let supplied = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    if !supplied.is_absolute()
        || supplied
            .components()
            .any(|part| part == Component::ParentDir)
    {
        return Err(format!(
            "workspace or bundle path must be absolute or normalized: '{}'",
            supplied.display()
        ));
    }
    let normalized: PathBuf = supplied.components().collect();
    let ancestors: Vec<_> = normalized.ancestors().collect();
    for dir in ancestors.into_iter().rev() {
        if !directory_exists(dir)? {
            return Err(format!("directory '{}' does not exist", dir.display()));
        }
    }
    if fs::canonicalize(&normalized).ok().as_deref() != Some(normalized.as_path()) {
        return Err(format!(
            "directory '{}' is not a canonical nonsymlink path",
            normalized.display()
        ));
    }
    Ok(normalized)
}

pub(super) fn activate(
    cwd: &Path,
    workspace: &Path,
    bundle: &Path,
    bin_dir: Option<&Path>,
    dry_run: bool,
) -> Result<Vec<String>, String> {
    let workspace = workspace_root(cwd, workspace)?;
    let bundle = workspace_root(cwd, bundle)?;
    let binary = guard_binary(cwd, bin_dir)?;
    let managed = compile_managed_hooks(&bundle, &workspace, &binary)?;
    let paths = Paths::new(&workspace);
    directory_exists(&paths.agents)?;
    let lock = if dry_run {
        None
    } else {
        Some(WorkspaceLock::acquire(&paths.agents, true)?)
    };
    let current = read_snapshot(&paths.hooks, MAX_CONFIG)?;
    let mut entries = config_entries(current.as_ref().map(|state| state.text.as_str()))?;
    let namespace = entries
        .iter()
        .find(|(key, _)| key == "dotagent")
        .map(|(_, value)| value);
    let saved = read_snapshot(&paths.backup, MAX_BACKUP)?
        .map(|backup| Backup::parse(&backup.text))
        .transpose()?;
    if let Some(saved) = &saved {
        if saved.managed != managed {
            return Err("existing Antigravity deployment differs; deactivate it before changing the hook binary or template".into());
        }
        if namespace == Some(&managed) {
            return Ok(vec![format!(
                "[activate] Antigravity hooks already active in '{}'",
                workspace.display()
            )]);
        }
        if current != saved.previous {
            return Err("workspace hooks changed after an incomplete activation; existing configuration was preserved".into());
        }
    }
    if namespace.is_some() {
        return Err(
            "workspace already defines a dotagent hook namespace; its configuration was preserved"
                .into(),
        );
    }
    entries.push(("dotagent".into(), managed.clone()));
    let installed = serialize_object(entries);
    if installed.len() as u64 > MAX_CONFIG {
        return Err("merged Antigravity hooks exceed the configuration size limit".into());
    }
    if dry_run {
        return Ok(vec![format!(
            "[dry-run] would save '{}' and install workspace Antigravity hooks in '{}'",
            paths.backup.display(),
            paths.hooks.display()
        )]);
    }

    let new_backup = saved.is_none();
    if new_backup {
        let backup = Backup {
            previous: current.clone(),
            managed,
            installed_digest: sha256_hex(installed.as_bytes()),
            created_agents_dir: lock.as_ref().is_some_and(|lock| lock.created_agents_dir),
        };
        publish(&paths.backup, &backup.serialize(), 0o600, false)?;
    }
    let mode = current.as_ref().map_or(0o644, |state| state.mode);
    if let Err(error) = replace_matching(&paths.hooks, current.as_ref(), Some((&installed, mode))) {
        if new_backup {
            let _ = fs::remove_file(&paths.backup);
        }
        return Err(error);
    }
    Ok(vec![format!(
        "[activate] Installed workspace Antigravity hooks in '{}'",
        paths.hooks.display()
    )])
}

pub(super) fn deactivate(workspace: &Path, dry_run: bool) -> Result<Vec<String>, String> {
    let paths = Paths::new(workspace);
    let noop = || {
        vec![format!(
            "[deactivate] No managed Antigravity hooks in '{}'",
            workspace.display()
        )]
    };
    if !directory_exists(&paths.agents)? {
        return Ok(noop());
    }
    let lock = if dry_run {
        None
    } else {
        Some(WorkspaceLock::acquire(&paths.agents, false)?)
    };
    let current = read_snapshot(&paths.hooks, MAX_CONFIG)?;
    let Some(backup_file) = read_snapshot(&paths.backup, MAX_BACKUP)? else {
        return Ok(noop());
    };
    let backup = Backup::parse(&backup_file.text)?;
    if current.is_none() && backup.previous.is_some() {
        return Err("Antigravity hooks were removed outside deactivation; the original configuration remains in the backup".into());
    }
    let mut entries = config_entries(current.as_ref().map(|state| state.text.as_str()))?;
    let mut update = None;
    if let Some(index) = entries.iter().position(|(key, _)| key == "dotagent") {
        if entries[index].1 != backup.managed {
            return Err(
                "managed Antigravity hooks changed; their configuration was preserved".into(),
            );
        }
        let current = current
            .as_ref()
            .ok_or("missing Antigravity configuration")?;
        if sha256_hex(current.text.as_bytes()) == backup.installed_digest {
            update = Some(
                backup
                    .previous
                    .as_ref()
                    .map(|state| (state.text.clone(), state.mode)),
            );
        } else {
            entries.remove(index);
            update = Some(Some((serialize_object(entries), current.mode)));
        }
    }
    if dry_run {
        return Ok(vec![format!(
            "[dry-run] would deactivate workspace Antigravity hooks in '{}' and preserve unrelated settings",
            paths.hooks.display()
        )]);
    }
    if let Some(update) = &update {
        replace_matching(
            &paths.hooks,
            current.as_ref(),
            update.as_ref().map(|(text, mode)| (text.as_str(), *mode)),
        )?;
    }
    fs::remove_file(&paths.backup)
        .map_err(|e| format!("remove Antigravity activation backup: {e}"))?;
    drop(lock);
    if backup.created_agents_dir {
        let _ = fs::remove_dir(&paths.agents);
    }
    Ok(vec![format!(
        "[deactivate] Removed managed workspace Antigravity hooks from '{}'",
        paths.hooks.display()
    )])
}

fn directory_exists(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => Ok(true),
        Ok(_) => Err(format!(
            "'{}' must be a regular nonsymlink directory",
            path.display()
        )),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("inspect directory '{}': {e}", path.display())),
    }
}

fn guard_binary(cwd: &Path, bin_dir: Option<&Path>) -> Result<PathBuf, String> {
    let inferred;
    let dir = if let Some(dir) = bin_dir {
        dir
    } else {
        inferred =
            std::env::current_exe().map_err(|e| format!("resolve current executable: {e}"))?;
        inferred
            .parent()
            .ok_or("cannot resolve installed binary directory")?
    };
    let path = workspace_root(cwd, dir)?.join("agent-guard");
    let meta =
        fs::symlink_metadata(&path).map_err(|e| format!("inspect '{}': {e}", path.display()))?;
    if !meta.is_file() || file_mode(&meta) & 0o111 == 0 || file_mode(&meta) & 0o022 != 0 {
        return Err(format!(
            "'{}' must be a regular executable without group or other write permissions",
            path.display()
        ));
    }
    Ok(path)
}

fn compile_managed_hooks(
    bundle: &Path,
    workspace: &Path,
    binary: &Path,
) -> Result<JsonValue, String> {
    let manifest_dir = bundle.join("dist-verify");
    let template_dir = bundle.join("dist/antigravity");
    for dir in [bundle.join("dist"), manifest_dir.clone(), template_dir] {
        if !directory_exists(&dir)? {
            return Err(format!("missing bundle directory '{}'", dir.display()));
        }
    }
    let manifest = read_snapshot(&manifest_dir.join("manifest.sha256"), MAX_CONFIG)?
        .ok_or("bundle integrity manifest is missing")?;
    let template = read_snapshot(&bundle.join(TEMPLATE), MAX_CONFIG)?
        .ok_or("native Antigravity hook bundle is missing")?;
    let mut hashes = manifest
        .text
        .lines()
        .filter_map(|line| line.split_once("  "))
        .filter(|(_, path)| *path == TEMPLATE)
        .map(|(digest, _)| digest);
    if hashes.next() != Some(sha256_hex(template.text.as_bytes()).as_str())
        || hashes.next().is_some()
    {
        return Err("native Antigravity hook bundle failed SHA-256 manifest verification".into());
    }
    let mut body = config_entries(Some(&template.text))?;
    if body.len() != 1 || body[0].0 != "dotagent" {
        return Err("native Antigravity bundle must contain only its dotagent namespace".into());
    }
    let (_, mut managed) = body.remove(0);
    let JsonValue::Object(fields) = &mut managed else {
        return Err("invalid managed Antigravity hook namespace".into());
    };
    if fields.len() != HOOK_EVENTS.len() + 1
        || !fields
            .iter()
            .any(|(key, value)| key == "enabled" && value.as_bool() == Some(true))
    {
        return Err("invalid managed Antigravity event set".into());
    }
    let command_path = |path: &Path| {
        path.to_str()
            .filter(|value| !value.chars().any(char::is_control))
            .map(shell_quote_single)
            .ok_or_else(|| {
                format!(
                    "path '{}' cannot be quoted in an Antigravity command",
                    path.display()
                )
            })
    };
    let bin = command_path(binary)?;
    let workspace = command_path(workspace)?;
    for event in HOOK_EVENTS {
        let (_, value) = fields
            .iter_mut()
            .find(|(key, _)| key == event)
            .ok_or_else(|| format!("missing native Antigravity event '{event}'"))?;
        let old = format!("agent-guard antigravity-hook {event}");
        let new = format!("{bin} antigravity-hook {event} --workspace {workspace}");
        if pin_commands(value, &old, &new)? != 1 {
            return Err(format!(
                "expected one verified command for Antigravity event '{event}'"
            ));
        }
    }
    Ok(managed)
}

fn pin_commands(value: &mut JsonValue, expected: &str, pinned: &str) -> Result<usize, String> {
    match value {
        JsonValue::Array(values) => values.iter_mut().try_fold(0, |count, value| {
            Ok(count + pin_commands(value, expected, pinned)?)
        }),
        JsonValue::Object(fields) => fields.iter_mut().try_fold(0, |count, (key, value)| {
            if key == "command" {
                if value.as_str() != Some(expected) {
                    return Err(
                        "unexpected executable or arguments in the native Antigravity bundle"
                            .into(),
                    );
                }
                *value = JsonValue::Str(pinned.to_owned());
                Ok(count + 1)
            } else {
                Ok(count + pin_commands(value, expected, pinned)?)
            }
        }),
        _ => Ok(0),
    }
}

fn config_entries(text: Option<&str>) -> Result<Vec<(String, JsonValue)>, String> {
    let Some(text) = text else {
        return Ok(Vec::new());
    };
    match JsonValue::parse(text).map_err(|e| format!("invalid Antigravity hooks JSON: {e}"))? {
        JsonValue::Object(entries) => Ok(entries),
        _ => Err("Antigravity hooks JSON must be an object".into()),
    }
}

fn serialize_object(entries: Vec<(String, JsonValue)>) -> String {
    format!("{}\n", JsonValue::Object(entries).to_json_string())
}

fn file_mode(meta: &Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        if meta.permissions().readonly() {
            0o555
        } else {
            0o755
        }
    }
}

fn read_snapshot(path: &Path, maximum: u64) -> Result<Option<Snapshot>, String> {
    let err = |e| format!("read '{}': {e}", path.display());
    let before = match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() && meta.len() <= maximum => meta,
        Ok(_) => {
            return Err(format!(
                "'{}' must be a bounded regular nonsymlink file",
                path.display()
            ));
        }
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(err(e)),
    };
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let nonblock = if cfg!(target_os = "macos") {
            0x4
        } else {
            0o4000
        };
        options.custom_flags(crate::traversal_ledger::O_NOFOLLOW_FLAG | nonblock);
    }
    let file = options.open(path).map_err(err)?;
    let opened = file.metadata().map_err(err)?;
    if !opened.is_file() || opened.len() != before.len() || !same_file(&before, &opened) {
        return Err(format!("'{}' changed while opening", path.display()));
    }
    let mut text = String::new();
    file.take(maximum + 1)
        .read_to_string(&mut text)
        .map_err(err)?;
    if text.len() as u64 != opened.len() {
        return Err(format!("'{}' changed while reading", path.display()));
    }
    Ok(Some(Snapshot {
        text,
        mode: file_mode(&opened),
    }))
}

#[cfg(unix)]
fn same_file(before: &Metadata, opened: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == opened.dev() && before.ino() == opened.ino()
}

#[cfg(not(unix))]
fn same_file(_before: &Metadata, _opened: &Metadata) -> bool {
    true
}

fn create_new(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn replace_matching(
    path: &Path,
    expected: Option<&Snapshot>,
    updated: Option<(&str, u32)>,
) -> Result<(), String> {
    if read_snapshot(path, MAX_CONFIG)?.as_ref() != expected {
        return Err(format!(
            "configuration '{}' changed during deployment",
            path.display()
        ));
    }
    match updated {
        Some((text, mode)) => publish(path, text, mode, expected.is_some()),
        None => fs::remove_file(path)
            .map_err(|e| format!("remove Antigravity hooks '{}': {e}", path.display())),
    }
}

fn publish(path: &Path, text: &str, mode: u32, replace: bool) -> Result<(), String> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = path.parent().ok_or("Antigravity file has no directory")?;
    if !directory_exists(dir)? {
        return Err("Antigravity directory disappeared during deployment".into());
    }
    let stage = dir.join(format!(
        ".hooks.json.dotagent.{}.{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file =
        create_new(&stage).map_err(|e| format!("stage Antigravity configuration: {e}"))?;
    let result = (|| -> std::io::Result<()> {
        file.write_all(text.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        let _ = mode;
        file.sync_all()?;
        if replace {
            fs::rename(&stage, path)
        } else {
            fs::hard_link(&stage, path)
        }
    })();
    drop(file);
    let _ = fs::remove_file(&stage);
    result.map_err(|e| {
        format!(
            "publish Antigravity configuration '{}': {e}",
            path.display()
        )
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Fixture {
        base: PathBuf,
        workspace: PathBuf,
        bundle: PathBuf,
        bin: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let base = fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "dotagent-native-activation-{name}-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed),
                ));
            fs::create_dir(&base).unwrap();
            let workspace = base.join("workspace's tools");
            let bin = base.join("installed binaries");
            fs::create_dir(&workspace).unwrap();
            fs::create_dir(&bin).unwrap();
            let guard = bin.join("agent-guard");
            fs::write(&guard, b"fixture executable").unwrap();
            fs::set_permissions(&guard, fs::Permissions::from_mode(0o755)).unwrap();
            let bundle =
                fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
            Self {
                base,
                workspace,
                bundle,
                bin,
            }
        }

        fn activate(&self, dry_run: bool) -> Result<Vec<String>, String> {
            activate(
                &self.base,
                &self.workspace,
                &self.bundle,
                Some(&self.bin),
                dry_run,
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    #[test]
    fn native_hooks_preserve_original_bytes_and_modes() {
        let fixture = Fixture::new("restore");
        let paths = Paths::new(&fixture.workspace);
        fs::create_dir(&paths.agents).unwrap();
        let original = "{\n  \"user-hooks\": {\"enabled\": false}\n}\n";
        fs::write(&paths.hooks, original).unwrap();
        fs::set_permissions(&paths.hooks, fs::Permissions::from_mode(0o640)).unwrap();
        let before = fs::read(&paths.hooks).unwrap();
        assert_eq!(
            fixture.activate(true).unwrap(),
            fixture.activate(true).unwrap()
        );
        assert!(!paths.backup.exists());
        assert_eq!(fs::read(&paths.hooks).unwrap(), before);

        fixture.activate(false).unwrap();
        let first = fs::read_to_string(&paths.hooks).unwrap();
        fixture.activate(false).unwrap();
        assert_eq!(fs::read_to_string(&paths.hooks).unwrap(), first);
        assert_eq!(file_mode(&fs::metadata(&paths.hooks).unwrap()), 0o640);
        assert_eq!(file_mode(&fs::metadata(&paths.backup).unwrap()), 0o600);
        let deployed = JsonValue::parse(&first).unwrap();
        assert_eq!(
            deployed
                .get("user-hooks")
                .unwrap()
                .get("enabled")
                .and_then(JsonValue::as_bool),
            Some(false)
        );
        let guard = shell_quote_single(fixture.bin.join("agent-guard").to_str().unwrap());
        let workspace = shell_quote_single(fixture.workspace.to_str().unwrap());
        let hook = supplied_session_start_command(&deployed);
        assert_eq!(
            hook,
            format!("{guard} antigravity-hook SessionStart --workspace {workspace}")
        );

        deactivate(&fixture.workspace, true).unwrap();
        assert!(paths.backup.exists());
        assert_eq!(fs::read_to_string(&paths.hooks).unwrap(), first);
        deactivate(&fixture.workspace, false).unwrap();
        assert!(!paths.backup.exists());
        assert_eq!(fs::read_to_string(&paths.hooks).unwrap(), original);
        assert_eq!(file_mode(&fs::metadata(&paths.hooks).unwrap()), 0o640);
    }

    fn supplied_session_start_command(value: &JsonValue) -> &str {
        value
            .get("dotagent")
            .unwrap()
            .get("SessionStart")
            .unwrap()
            .as_array()
            .unwrap()[0]
            .get("command")
            .unwrap()
            .as_str()
            .unwrap()
    }

    #[test]
    fn deactivation_preserves_settings_added_after_installation() {
        let fixture = Fixture::new("later-edits");
        let paths = Paths::new(&fixture.workspace);
        fixture.activate(true).unwrap();
        assert!(!paths.agents.exists());
        fixture.activate(false).unwrap();
        let deployed = fs::read_to_string(&paths.hooks).unwrap();
        let mut entries = config_entries(Some(&deployed)).unwrap();
        entries.push(("later-user-hooks".into(), JsonValue::Object(vec![])));
        fs::write(&paths.hooks, serialize_object(entries)).unwrap();
        deactivate(&fixture.workspace, false).unwrap();
        assert_eq!(
            fs::read_to_string(&paths.hooks).unwrap(),
            "{\"later-user-hooks\":{}}\n"
        );
        assert!(!paths.backup.exists());
    }

    #[test]
    fn interrupted_activation_can_be_retried_without_replacing_original_backup() {
        let fixture = Fixture::new("retry");
        let paths = Paths::new(&fixture.workspace);
        fixture.activate(false).unwrap();
        let saved = fs::read_to_string(&paths.backup).unwrap();
        fs::remove_file(&paths.hooks).unwrap();
        fixture.activate(false).unwrap();
        assert_eq!(fs::read_to_string(&paths.backup).unwrap(), saved);
        deactivate(&fixture.workspace, false).unwrap();
        assert!(!paths.agents.exists());
    }

    #[test]
    fn activation_refuses_unmanaged_namespace_and_linked_paths() {
        let fixture = Fixture::new("unsafe-config");
        let paths = Paths::new(&fixture.workspace);
        fs::create_dir(&paths.agents).unwrap();
        fs::write(&paths.hooks, "{\"dotagent\":{\"enabled\":false}}\n").unwrap();
        assert!(
            fixture
                .activate(false)
                .unwrap_err()
                .contains("already defines")
        );
        assert!(!paths.backup.exists());
        assert_eq!(
            fs::read_to_string(&paths.hooks).unwrap(),
            "{\"dotagent\":{\"enabled\":false}}\n"
        );

        fs::remove_file(&paths.hooks).unwrap();
        let other = fixture.base.join("other-config.json");
        fs::write(&other, "{}\n").unwrap();
        symlink(&other, &paths.hooks).unwrap();
        assert!(fixture.activate(false).is_err());
        assert!(deactivate(&fixture.workspace, false).is_err());
        assert_eq!(fs::read_to_string(other).unwrap(), "{}\n");
        assert!(!paths.backup.exists());
    }

    #[test]
    fn activation_checks_bundle_integrity_before_workspace_writes() {
        let mut fixture = Fixture::new("manifest");
        let bundle = fixture.base.join("alternate bundle");
        fs::create_dir_all(bundle.join("dist/antigravity")).unwrap();
        fs::create_dir(bundle.join("dist-verify")).unwrap();
        fs::copy(
            fixture.bundle.join("dist-verify/manifest.sha256"),
            bundle.join("dist-verify/manifest.sha256"),
        )
        .unwrap();
        fs::write(bundle.join(TEMPLATE), "{}\n").unwrap();
        fixture.bundle = bundle;

        assert!(
            fixture
                .activate(false)
                .unwrap_err()
                .contains("SHA-256 manifest verification")
        );
        assert!(!Paths::new(&fixture.workspace).agents.exists());
    }
}
