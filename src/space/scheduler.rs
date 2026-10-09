//! Exact user scheduler for automatic Local release reconciliation.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::output;

use super::command::{self, Tool};
use super::host::HostProfile;
use super::paths::Paths;

const MARKER: &str = "shimpz-local-update-v2";
const MAX_SCHEDULER_BYTES: u64 = 16 * 1024;
const SYSTEMD_TIMER: &str = "shimpz-update.timer";
const SYSTEMD_SERVICE: &str = "shimpz-update.service";
const LAUNCHD_LABEL: &str = "com.shimpz.update";
/// `launchctl print` exit status when the domain has no service with the requested label.
const LAUNCHD_SERVICE_NOT_FOUND: i32 = 113;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryState {
    Absent,
    Current,
    OwnedCorrupt,
    Foreign,
}

#[derive(Debug)]
struct Entry {
    path: PathBuf,
    state: EntryState,
    removable: bool,
}

#[derive(Clone, Copy, Debug)]
struct EntryFacts {
    regular: bool,
    symlink: bool,
    uid: u32,
    mode: u32,
    len: u64,
}

/// Exit status and captured standard output of one scheduler host command.
#[derive(Debug)]
struct Probe {
    code: Option<i32>,
    stdout: String,
}

impl Probe {
    fn succeeded(&self) -> bool {
        self.code == Some(0)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum InstallOutcome {
    Enabled,
    Preserved(Vec<String>),
}

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct RemovalOutcome {
    pub(crate) preserved: Vec<String>,
    pub(crate) execution_unverified: bool,
}

pub(crate) fn install(
    profile: HostProfile,
    paths: &Paths,
    scheduled: bool,
) -> Result<InstallOutcome, String> {
    install_with_authorizer(profile, paths, scheduled, confirm_replace)
}

fn install_with_authorizer<F>(
    profile: HostProfile,
    paths: &Paths,
    scheduled: bool,
    mut authorize: F,
) -> Result<InstallOutcome, String>
where
    F: FnMut(&[PathBuf]) -> Result<bool, String>,
{
    let entries = inspect_entries(profile, paths)?;
    // A Foreign entry proves this parent already exists, so preserving it creates nothing.
    prepare_parent(match profile {
        HostProfile::Linux | HostProfile::Wsl => &paths.systemd_service,
        HostProfile::MacOs => &paths.launch_agent,
    })?;
    if let Some(preserved) = resolve_foreign_entries(&entries, scheduled, &mut authorize, || {
        unload(profile, paths);
    })? {
        return Ok(InstallOutcome::Preserved(preserved));
    }
    let entries = inspect_entries(profile, paths)?;
    if entries
        .iter()
        .any(|entry| entry.state == EntryState::Foreign)
    {
        return Err("a scheduler entry changed while it was being reconciled".into());
    }
    let current = entries
        .iter()
        .all(|entry| entry.state == EntryState::Current);
    match profile {
        // Unchanged unit files that systemd already runs need no reload and no re-enable.
        HostProfile::Linux | HostProfile::Wsl
            if current && systemd_schedule_is_running(run_probe) =>
        {
            Ok(())
        }
        HostProfile::Linux | HostProfile::Wsl => install_systemd(paths),
        HostProfile::MacOs => install_launch_agent(paths),
    }?;
    Ok(InstallOutcome::Enabled)
}

/// Whether systemd holds exactly the unit files on disk and runs the enabled timer. Any probe failure or unexpected
/// answer is `false`, so the caller reloads and enables as before.
fn systemd_schedule_is_running<R>(mut run: R) -> bool
where
    R: FnMut(Tool, &[&str]) -> Result<Probe, String>,
{
    let Ok(show) = run(
        Tool::Systemctl,
        &[
            "--user",
            "show",
            SYSTEMD_TIMER,
            SYSTEMD_SERVICE,
            "--property=Id,LoadState,ActiveState,UnitFileState,NeedDaemonReload",
        ],
    ) else {
        return false;
    };
    show.succeeded() && systemd_schedule_is_loaded(&show.stdout)
}

fn systemd_schedule_is_loaded(show: &str) -> bool {
    let mut units = BTreeMap::new();
    for block in show.split("\n\n").filter(|block| !block.trim().is_empty()) {
        let mut properties = BTreeMap::new();
        for line in block.lines() {
            let Some((key, value)) = line.split_once('=') else {
                return false;
            };
            if properties.insert(key, value).is_some() {
                return false;
            }
        }
        let Some(id) = properties.get("Id").copied() else {
            return false;
        };
        if units.insert(id, properties).is_some() {
            return false;
        }
    }
    let (Some(timer), Some(service)) = (units.get(SYSTEMD_TIMER), units.get(SYSTEMD_SERVICE))
    else {
        return false;
    };
    units.len() == 2
        && timer.get("LoadState") == Some(&"loaded")
        && timer.get("ActiveState") == Some(&"active")
        && timer.get("UnitFileState") == Some(&"enabled")
        && timer.get("NeedDaemonReload") == Some(&"no")
        && service.get("LoadState") == Some(&"loaded")
        && service.get("NeedDaemonReload") == Some(&"no")
}

fn resolve_foreign_entries<F>(
    entries: &[Entry],
    scheduled: bool,
    authorize: &mut F,
    before_remove: impl FnOnce(),
) -> Result<Option<Vec<String>>, String>
where
    F: FnMut(&[PathBuf]) -> Result<bool, String>,
{
    let foreign: Vec<_> = entries
        .iter()
        .filter(|entry| entry.state == EntryState::Foreign)
        .map(|entry| entry.path.clone())
        .collect();
    if !foreign.is_empty() {
        if scheduled || !authorize(&foreign)? {
            return Ok(Some(display_paths(&foreign)));
        }
        if let Some(entry) = entries
            .iter()
            .find(|entry| entry.state == EntryState::Foreign && !entry.removable)
        {
            return Err(format!(
                "the scheduler entry cannot be replaced safely: {}",
                display_path(&entry.path)
            ));
        }
        before_remove();
        for entry in entries
            .iter()
            .filter(|entry| entry.state == EntryState::Foreign)
        {
            remove_exact_entry(&entry.path)?;
        }
    }
    Ok(None)
}

pub(crate) fn preflight_remove(profile: HostProfile, paths: &Paths) -> Result<(), String> {
    inspect_entries(profile, paths).map(|_| ())
}

pub(crate) fn remove(profile: HostProfile, paths: &Paths) -> Result<RemovalOutcome, String> {
    let booted = systemd_booted();
    remove_with(
        profile,
        paths,
        || require_unloaded(profile, paths, booted, run_probe),
        || reload_systemd(booted),
    )
}

/// Deletes owned scheduler entries only after `unload` proves the job is no longer loaded.
fn remove_with(
    profile: HostProfile,
    paths: &Paths,
    unload: impl FnOnce() -> Result<(), String>,
    reload: impl FnOnce() -> Result<(), String>,
) -> Result<RemovalOutcome, String> {
    let entries = inspect_entries(profile, paths)?;
    let removable: Vec<_> = entries
        .iter()
        .filter(|entry| matches!(entry.state, EntryState::Current | EntryState::OwnedCorrupt))
        .collect();
    if !removable.is_empty() {
        unload()?;
    }
    for entry in &removable {
        remove_exact_entry(&entry.path)?;
    }
    let mut outcome = RemovalOutcome::default();
    for entry in entries
        .iter()
        .filter(|entry| entry.state == EntryState::Foreign)
    {
        outcome.preserved.push(display_path(&entry.path));
        outcome.execution_unverified = true;
    }
    for entry in &entries {
        if let Some(path) = remove_safe_temporary(&entry.path)? {
            outcome.preserved.push(display_path(&path));
        }
    }
    if !removable.is_empty() && matches!(profile, HostProfile::Linux | HostProfile::Wsl) {
        reload()?;
    }
    Ok(outcome)
}

fn reload_systemd(booted: bool) -> Result<(), String> {
    if booted && Tool::Systemctl.resolve().is_ok() {
        require_tool(
            Tool::Systemctl,
            ["--user", "daemon-reload"],
            "systemd did not reload after scheduler removal",
        )
    } else {
        Ok(())
    }
}

/// Unloads the owned job, or proves it is not loaded, before its scheduler files may be deleted.
fn require_unloaded<R>(
    profile: HostProfile,
    paths: &Paths,
    systemd_booted: bool,
    mut run: R,
) -> Result<(), String>
where
    R: FnMut(Tool, &[&str]) -> Result<Probe, String>,
{
    match profile {
        // Without a systemd-booted host no systemd user manager exists, so no timer can be loaded.
        HostProfile::Linux | HostProfile::Wsl if !systemd_booted => Ok(()),
        HostProfile::Linux | HostProfile::Wsl => {
            let next = format!(
                "run systemctl --user disable --now {SYSTEMD_TIMER}, then rerun the same shimpz command"
            );
            let mut systemctl = |arguments: &[&str]| {
                run(Tool::Systemctl, arguments).map_err(|error| unload_failure(&error, &next))
            };
            if systemctl(&["--user", "disable", "--now", SYSTEMD_TIMER])?.succeeded() {
                return Ok(());
            }
            let state = systemctl(&[
                "--user",
                "show",
                SYSTEMD_TIMER,
                "--property=ActiveState,UnitFileState",
            ])?;
            if state.succeeded() && systemd_timer_is_unloaded(&state.stdout) {
                Ok(())
            } else {
                Err(unload_failure(
                    "the automatic Local update timer could not be proven stopped and disabled",
                    &next,
                ))
            }
        }
        HostProfile::MacOs => {
            let domain = format!("gui/{}", rustix::process::getuid().as_raw());
            let service = format!("{domain}/{LAUNCHD_LABEL}");
            let next =
                format!("run launchctl bootout {service}, then rerun the same shimpz command");
            let mut launchctl = |arguments: &[&str]| {
                run(Tool::Launchctl, arguments).map_err(|error| unload_failure(&error, &next))
            };
            let plist = paths.launch_agent.to_string_lossy();
            if launchctl(&["bootout", &domain, &plist])?.succeeded() {
                return Ok(());
            }
            if launchctl(&["print", &service])?.code == Some(LAUNCHD_SERVICE_NOT_FOUND) {
                Ok(())
            } else {
                Err(unload_failure(
                    "the automatic Local update LaunchAgent could not be proven unloaded",
                    &next,
                ))
            }
        }
    }
}

fn systemd_timer_is_unloaded(show: &str) -> bool {
    let (mut active, mut unit_file) = (None, None);
    for line in show.lines() {
        if let Some(value) = line.strip_prefix("ActiveState=") {
            active = Some(value);
        } else if let Some(value) = line.strip_prefix("UnitFileState=") {
            unit_file = Some(value);
        }
    }
    matches!(active, Some("inactive" | "failed")) && matches!(unit_file, Some("" | "disabled"))
}

fn unload_failure(detail: &str, next: &str) -> String {
    format!("{detail}; the scheduler files were kept. Next: {next}")
}

fn run_probe(tool: Tool, arguments: &[&str]) -> Result<Probe, String> {
    let output = command::captured(tool, arguments)?;
    Ok(Probe {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
    })
}

/// Mirrors `sd_booted()`: only a systemd-booted host can run a systemd user manager.
fn systemd_booted() -> bool {
    match fs::symlink_metadata("/run/systemd/system") {
        Ok(metadata) => metadata.is_dir(),
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    }
}

fn install_systemd(paths: &Paths) -> Result<(), String> {
    write_atomic(&paths.systemd_service, &systemd_service(paths)?)?;
    write_atomic(&paths.systemd_timer, systemd_timer())?;
    require_tool(
        Tool::Systemctl,
        ["--user", "daemon-reload"],
        "systemd did not reload",
    )?;
    require_tool(
        Tool::Systemctl,
        ["--user", "enable", "--now", SYSTEMD_TIMER],
        "the automatic Local update timer could not be enabled",
    )
}

fn install_launch_agent(paths: &Paths) -> Result<(), String> {
    write_atomic(&paths.launch_agent, &launch_agent(paths)?)?;
    let domain = format!("gui/{}", rustix::process::getuid().as_raw());
    let _ = command::status(
        Tool::Launchctl,
        ["bootout", &domain, &paths.launch_agent.to_string_lossy()],
    );
    require_tool(
        Tool::Launchctl,
        ["bootstrap", &domain, &paths.launch_agent.to_string_lossy()],
        "the automatic Local update LaunchAgent could not be loaded",
    )
}

/// Best-effort unload before replacing an authorized foreign entry during installation.
fn unload(profile: HostProfile, paths: &Paths) {
    match profile {
        HostProfile::Linux | HostProfile::Wsl => {
            let _ = command::status(
                Tool::Systemctl,
                ["--user", "disable", "--now", SYSTEMD_TIMER],
            );
        }
        HostProfile::MacOs => {
            let _ = command::status(
                Tool::Launchctl,
                [
                    "bootout",
                    &format!("gui/{}", rustix::process::getuid().as_raw()),
                    &paths.launch_agent.to_string_lossy(),
                ],
            );
        }
    }
}

/// systemd applies no start timeout to a `Type=oneshot` unit by default (systemd.service(5), `TimeoutStartSec=`), so a
/// run that never ends would hold the lifecycle lock and stop every later update. Each host command already has its
/// own deadline; this one backs any other hang. Three hours is far above the longest legitimate apply, whose longest
/// measured run took under eleven minutes and whose slowest part, the image downloads, may take up to twenty minutes
/// each before their own deadline stops them, so the CLI's own deadline and rollback always end a single hung call
/// first. Past it systemd terminates the run's whole control group.
const SYSTEMD_START_TIMEOUT: &str = "3h";

fn systemd_service(paths: &Paths) -> Result<String, String> {
    Ok(format!(
        "# {MARKER}\n[Unit]\nDescription=Reconcile Shimpz Local Space\nAfter=docker.service\n\n[Service]\nType=oneshot\nTimeoutStartSec={SYSTEMD_START_TIMEOUT}\nExecStart={} start --scheduled\n",
        systemd_quote(&paths.managed_cli)?
    ))
}

fn systemd_timer() -> &'static str {
    "# shimpz-local-update-v2\n[Unit]\nDescription=Periodically reconcile Shimpz Local Space\n\n[Timer]\nOnActiveSec=30s\nOnUnitActiveSec=30s\nRandomizedDelaySec=5s\nAccuracySec=1s\n\n[Install]\nWantedBy=timers.target\n"
}

fn launch_agent(paths: &Paths) -> Result<String, String> {
    let cli = xml_escape(
        paths
            .managed_cli
            .to_str()
            .ok_or_else(|| "the managed CLI path is not UTF-8".to_owned())?,
    );
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- {MARKER} -->\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{LAUNCHD_LABEL}</string>\n<key>ProgramArguments</key><array><string>{cli}</string><string>start</string><string>--scheduled</string></array>\n<key>RunAtLoad</key><true/>\n<key>StartInterval</key><integer>30</integer>\n<key>ProcessType</key><string>Background</string>\n</dict></plist>\n"
    ))
}

fn inspect_entries(profile: HostProfile, paths: &Paths) -> Result<Vec<Entry>, String> {
    match profile {
        HostProfile::Linux | HostProfile::Wsl => Ok(vec![
            inspect_entry(
                &paths.systemd_service,
                &systemd_service(paths)?,
                &format!("# {MARKER}"),
            )?,
            inspect_entry(
                &paths.systemd_timer,
                systemd_timer(),
                &format!("# {MARKER}"),
            )?,
        ]),
        HostProfile::MacOs => Ok(vec![inspect_entry(
            &paths.launch_agent,
            &launch_agent(paths)?,
            &format!("<!-- {MARKER} -->"),
        )?]),
    }
}

fn inspect_entry(path: &Path, expected: &str, marker_line: &str) -> Result<Entry, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Entry {
                path: path.into(),
                state: EntryState::Absent,
                removable: false,
            });
        }
        Err(error) => return Err(io_error(error)),
    };
    let entry_facts = facts(&metadata);
    if entry_facts.symlink || !entry_facts.regular {
        return Ok(Entry {
            path: path.into(),
            state: EntryState::Foreign,
            removable: entry_facts.symlink,
        });
    }
    let contents = read_bounded_regular(path)?;
    Ok(Entry {
        path: path.into(),
        state: classify_entry(
            entry_facts,
            &contents,
            expected.as_bytes(),
            marker_line.as_bytes(),
        ),
        removable: true,
    })
}

fn facts(metadata: &fs::Metadata) -> EntryFacts {
    EntryFacts {
        regular: metadata.is_file(),
        symlink: metadata.file_type().is_symlink(),
        uid: metadata.uid(),
        mode: metadata.permissions().mode(),
        len: metadata.len(),
    }
}

fn classify_entry(
    entry: EntryFacts,
    contents: &[u8],
    expected: &[u8],
    marker_line: &[u8],
) -> EntryState {
    if entry.symlink
        || !entry.regular
        || entry.uid != rustix::process::getuid().as_raw()
        || entry.mode & 0o022 != 0
        || entry.len > MAX_SCHEDULER_BYTES
        || entry.len != contents.len() as u64
    {
        return EntryState::Foreign;
    }
    if contents == expected {
        EntryState::Current
    } else if contents
        .split(|byte| *byte == b'\n')
        .any(|line| line == marker_line)
    {
        EntryState::OwnedCorrupt
    } else {
        EntryState::Foreign
    }
}

fn read_bounded_regular(path: &Path) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(io_error)?;
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file() || metadata.len() > MAX_SCHEDULER_BYTES {
        return Ok(Vec::new());
    }
    let mut contents = Vec::new();
    file.take(MAX_SCHEDULER_BYTES + 1)
        .read_to_end(&mut contents)
        .map_err(io_error)?;
    Ok(contents)
}

fn confirm_replace(paths: &[PathBuf]) -> Result<bool, String> {
    let Ok(mut tty) = OpenOptions::new().read(true).write(true).open("/dev/tty") else {
        return Ok(false);
    };
    writeln!(
        tty,
        "Shimpz found scheduler entries it does not own: {}",
        display_paths(paths).join(", ")
    )
    .map_err(io_error)?;
    loop {
        write!(
            tty,
            "Replace only these exact entries to enable automatic Local updates? [Yes/No] "
        )
        .map_err(io_error)?;
        tty.flush().map_err(io_error)?;
        let Some(answer) = read_answer(&mut tty)? else {
            return Ok(false);
        };
        match answer.as_str() {
            "Yes" => return Ok(true),
            "No" | "" => return Ok(false),
            _ => writeln!(tty, "Please answer exactly Yes or No.").map_err(io_error)?,
        }
    }
}

fn read_answer(file: &mut File) -> Result<Option<String>, String> {
    let mut answer = String::new();
    let mut byte = [0_u8; 1];
    while file.read(&mut byte).map_err(io_error)? == 1 {
        if byte[0] == b'\n' {
            return Ok(Some(answer));
        }
        if answer.len() >= 8 || byte[0].is_ascii_control() {
            return Ok(None);
        }
        answer.push(char::from(byte[0]));
    }
    Ok(Some(answer))
}

fn write_atomic(path: &Path, value: &str) -> Result<(), String> {
    let temporary = temporary_path(path)?;
    if remove_safe_temporary(path)?.is_some() {
        return Err(format!(
            "refusing to replace an unsafe scheduler temporary file: {}",
            display_path(&temporary)
        ));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(io_error)?;
    if let Err(error) = file
        .write_all(value.as_bytes())
        .and_then(|()| file.sync_all())
    {
        let _ = fs::remove_file(&temporary);
        return Err(io_error(error));
    }
    fs::rename(&temporary, path).map_err(io_error)?;
    sync_parent(path)
}

fn remove_safe_temporary(path: &Path) -> Result<Option<PathBuf>, String> {
    let temporary = temporary_path(path)?;
    let metadata = match fs::symlink_metadata(&temporary) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(error)),
    };
    if metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == rustix::process::getuid().as_raw()
        && metadata.permissions().mode() & 0o022 == 0
        && metadata.len() <= MAX_SCHEDULER_BYTES
    {
        fs::remove_file(&temporary).map_err(io_error)?;
        Ok(None)
    } else {
        Ok(Some(temporary))
    }
}

fn temporary_path(path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .ok_or_else(|| "the scheduler entry name is invalid".to_owned())?;
    let mut temporary = OsString::from(name);
    temporary.push(".tmp");
    Ok(path.with_file_name(temporary))
}

fn prepare_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "the scheduler directory is invalid".to_owned())?;
    if !parent.exists() {
        let ancestor = parent
            .parent()
            .ok_or_else(|| "the scheduler directory is invalid".to_owned())?;
        fs::create_dir_all(ancestor).map_err(io_error)?;
        match DirBuilder::new().mode(0o700).create(parent) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(io_error(error)),
        }
    }
    let metadata = parent.symlink_metadata().map_err(io_error)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(format!(
            "the scheduler directory ownership or permissions are invalid: {}",
            display_path(parent)
        ));
    }
    Ok(())
}

fn remove_exact_entry(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

fn sync_parent(path: &Path) -> Result<(), String> {
    File::open(
        path.parent()
            .ok_or_else(|| "the scheduler directory is invalid".to_owned())?,
    )
    .and_then(|directory| directory.sync_all())
    .map_err(io_error)
}

fn display_paths(paths: &[PathBuf]) -> Vec<String> {
    paths.iter().map(|path| display_path(path)).collect()
}

fn display_path(path: &Path) -> String {
    output::sanitize_inline(&path.to_string_lossy())
}

fn systemd_quote(path: &Path) -> Result<String, String> {
    let value = path
        .to_str()
        .ok_or_else(|| "the managed CLI path is not UTF-8".to_owned())?;
    if value.chars().any(char::is_control) {
        return Err("the managed CLI path contains control characters".into());
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn require_tool<const N: usize>(
    tool: Tool,
    arguments: [&str; N],
    message: &str,
) -> Result<(), String> {
    if command::status(tool, arguments)?.success() {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn io_error(error: std::io::Error) -> String {
    let message = format!("scheduler operation failed: {error}");
    drop(error);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn create_private_directory(path: &Path) {
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn write_private_file(path: &Path, value: &str) {
        fs::write(path, value).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    const RUNNING_SCHEDULE: &str = "Id=shimpz-update.timer\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\nNeedDaemonReload=no\n\nId=shimpz-update.service\nLoadState=loaded\nActiveState=inactive\nUnitFileState=static\nNeedDaemonReload=no\n";

    #[test]
    fn only_a_loaded_enabled_active_schedule_skips_the_systemd_reload() {
        assert!(systemd_schedule_is_loaded(RUNNING_SCHEDULE));
        for (from, to) in [
            ("ActiveState=active", "ActiveState=inactive"),
            ("UnitFileState=enabled", "UnitFileState=disabled"),
            (
                "LoadState=loaded\nActiveState=active",
                "LoadState=not-found\nActiveState=active",
            ),
            (
                "static\nNeedDaemonReload=no",
                "static\nNeedDaemonReload=yes",
            ),
            (
                "enabled\nNeedDaemonReload=no",
                "enabled\nNeedDaemonReload=yes",
            ),
            (
                "ActiveState=inactive\n",
                "ActiveState=inactive\nActiveState=active\n",
            ),
            ("Id=shimpz-update.service", "Id=other.service"),
            ("\n\nId=shimpz-update.service", "\n\nId=shimpz-update.timer"),
            (
                "NeedDaemonReload=no\n\n",
                "NeedDaemonReload=no\nunparsed\n\n",
            ),
        ] {
            let changed = RUNNING_SCHEDULE.replacen(from, to, 1);
            assert_ne!(changed, RUNNING_SCHEDULE, "{from}");
            assert!(!systemd_schedule_is_loaded(&changed), "{to}");
        }
        assert!(!systemd_schedule_is_loaded(""));
    }

    #[test]
    fn the_running_schedule_probe_fails_toward_a_reload() {
        let answer = |code, stdout: &str| {
            let stdout = stdout.to_owned();
            move |tool: Tool, arguments: &[&str]| {
                assert_eq!(tool, Tool::Systemctl);
                assert_eq!(
                    arguments,
                    [
                        "--user",
                        "show",
                        SYSTEMD_TIMER,
                        SYSTEMD_SERVICE,
                        "--property=Id,LoadState,ActiveState,UnitFileState,NeedDaemonReload",
                    ]
                );
                Ok(Probe {
                    code,
                    stdout: stdout.clone(),
                })
            }
        };
        assert!(systemd_schedule_is_running(answer(
            Some(0),
            RUNNING_SCHEDULE
        )));
        assert!(!systemd_schedule_is_running(answer(
            Some(1),
            RUNNING_SCHEDULE
        )));
        assert!(!systemd_schedule_is_running(answer(None, RUNNING_SCHEDULE)));
        assert!(!systemd_schedule_is_running(|_, _| Err(
            "no systemctl".into()
        )));
    }

    #[test]
    fn emits_exact_non_shell_schedulers() {
        let paths = Paths::under(Path::new("/home/Ada Space")).unwrap();
        let service = systemd_service(&paths).unwrap();
        assert!(
            service.contains("ExecStart=\"/home/Ada Space/.shimpz/bin/shimpz\" start --scheduled")
        );
        assert!(!service.contains("sh -c"));
        // A oneshot unit has no start timeout unless it declares one, so a hung run could hold the update lock forever.
        assert!(service.contains("\nType=oneshot\nTimeoutStartSec=3h\n"));
        let timer = systemd_timer();
        assert!(timer.contains("OnActiveSec=30s"));
        assert!(timer.contains("OnUnitActiveSec=30s"));
        assert!(timer.contains("RandomizedDelaySec=5s"));
        assert!(timer.contains("AccuracySec=1s"));
        assert!(timer.contains("WantedBy=timers.target"));
        assert!(!timer.contains("OnBootSec="));
        assert!(!timer.contains("Persistent="));
        let plist = launch_agent(&paths).unwrap();
        assert!(plist.contains("<string>/home/Ada Space/.shimpz/bin/shimpz</string>"));
        assert!(plist.contains("<string>--scheduled</string>"));
        assert!(plist.contains("<key>StartInterval</key><integer>30</integer>"));
    }

    #[test]
    fn a_marked_timer_with_another_cadence_is_owned_and_replaced_by_the_current_one() {
        let current = systemd_timer();
        let other = current.replace("OnUnitActiveSec=30s", "OnUnitActiveSec=5m");
        assert_ne!(other, current);
        let facts = EntryFacts {
            regular: true,
            symlink: false,
            uid: rustix::process::getuid().as_raw(),
            mode: 0o100_600,
            len: other.len() as u64,
        };
        let marker = format!("# {MARKER}");
        assert_eq!(
            classify_entry(
                facts,
                other.as_bytes(),
                current.as_bytes(),
                marker.as_bytes()
            ),
            EntryState::OwnedCorrupt
        );
    }

    #[test]
    fn classifies_only_exact_or_marked_safe_files_as_owned() {
        let expected = b"# shimpz-local-update-v2\ncurrent\n";
        let corrupt = b"# shimpz-local-update-v2\ncorrupt\n";
        let foreign = b"current\n";
        let base = EntryFacts {
            regular: true,
            symlink: false,
            uid: rustix::process::getuid().as_raw(),
            mode: 0o100_600,
            len: expected.len() as u64,
        };
        assert_eq!(
            classify_entry(base, expected, expected, b"# shimpz-local-update-v2"),
            EntryState::Current
        );
        assert_eq!(
            classify_entry(
                EntryFacts {
                    len: corrupt.len() as u64,
                    ..base
                },
                corrupt,
                expected,
                b"# shimpz-local-update-v2"
            ),
            EntryState::OwnedCorrupt
        );
        assert_eq!(
            classify_entry(
                EntryFacts {
                    len: foreign.len() as u64,
                    ..base
                },
                foreign,
                expected,
                b"# shimpz-local-update-v2"
            ),
            EntryState::Foreign
        );
        for changed in [
            EntryFacts {
                uid: base.uid ^ 1,
                ..base
            },
            EntryFacts {
                len: MAX_SCHEDULER_BYTES + 1,
                ..base
            },
            EntryFacts {
                len: base.len + 1,
                ..base
            },
        ] {
            assert_eq!(
                classify_entry(changed, expected, expected, b"# shimpz-local-update-v2"),
                EntryState::Foreign
            );
        }
        assert_eq!(
            classify_entry(
                EntryFacts {
                    mode: 0o100_622,
                    ..base
                },
                expected,
                expected,
                b"# shimpz-local-update-v2"
            ),
            EntryState::Foreign
        );
    }

    #[test]
    fn preserves_the_exact_foreign_entry_without_confirmation() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        create_private_directory(paths.launch_agent.parent().unwrap());
        write_private_file(&paths.launch_agent, "foreign\n");
        let preserved =
            install_with_authorizer(HostProfile::MacOs, &paths, false, |_| Ok(false)).unwrap();
        assert_eq!(
            preserved,
            InstallOutcome::Preserved(vec![display_path(&paths.launch_agent)])
        );
        assert_eq!(
            fs::read_to_string(&paths.launch_agent).unwrap(),
            "foreign\n"
        );
    }

    #[test]
    fn affirmative_confirmation_removes_only_the_exact_foreign_entry() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        create_private_directory(paths.launch_agent.parent().unwrap());
        write_private_file(&paths.launch_agent, "foreign\n");
        let entries = inspect_entries(HostProfile::MacOs, &paths).unwrap();
        let mut authorize = |listed: &[PathBuf]| {
            assert_eq!(listed, std::slice::from_ref(&paths.launch_agent));
            Ok(true)
        };
        assert_eq!(
            resolve_foreign_entries(&entries, false, &mut authorize, || {}).unwrap(),
            None
        );
        assert!(fs::symlink_metadata(&paths.launch_agent).is_err());
    }

    #[test]
    fn scheduled_reconciliation_never_prompts_for_a_foreign_entry() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        create_private_directory(paths.launch_agent.parent().unwrap());
        write_private_file(&paths.launch_agent, "foreign\n");
        let outcome = install_with_authorizer(HostProfile::MacOs, &paths, true, |_| {
            panic!("scheduled reconciliation prompted")
        })
        .unwrap();
        assert_eq!(
            outcome,
            InstallOutcome::Preserved(vec![display_path(&paths.launch_agent)])
        );
    }

    #[test]
    fn removal_deletes_owned_entries_and_preserves_foreign_entries() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        create_private_directory(paths.launch_agent.parent().unwrap());
        write_private_file(&paths.launch_agent, &launch_agent(&paths).unwrap());
        assert_eq!(
            remove_with(HostProfile::MacOs, &paths, || Ok(()), || Ok(())).unwrap(),
            RemovalOutcome::default()
        );
        assert!(fs::symlink_metadata(&paths.launch_agent).is_err());

        write_private_file(
            &paths.launch_agent,
            &format!("<!-- {MARKER} -->\ncorrupt\n"),
        );
        assert_eq!(
            remove_with(HostProfile::MacOs, &paths, || Ok(()), || Ok(())).unwrap(),
            RemovalOutcome::default()
        );
        assert!(fs::symlink_metadata(&paths.launch_agent).is_err());

        write_private_file(&paths.launch_agent, "foreign\n");
        let outcome = remove_with(
            HostProfile::MacOs,
            &paths,
            || panic!("a foreign entry was unloaded"),
            || Ok(()),
        )
        .unwrap();
        assert_eq!(outcome.preserved, [display_path(&paths.launch_agent)]);
        assert!(outcome.execution_unverified);
        assert_eq!(
            fs::read_to_string(&paths.launch_agent).unwrap(),
            "foreign\n"
        );
    }

    fn probe(code: i32, stdout: &str) -> Probe {
        Probe {
            code: Some(code),
            stdout: stdout.into(),
        }
    }

    /// Runs `require_unloaded` against an exact scripted host and returns its result and commands.
    fn scripted_unload(
        profile: HostProfile,
        paths: &Paths,
        systemd_booted: bool,
        script: Vec<Result<Probe, String>>,
    ) -> (Result<(), String>, Vec<String>) {
        let mut script = script.into_iter();
        let mut calls = Vec::new();
        let result = require_unloaded(profile, paths, systemd_booted, |tool, arguments| {
            calls.push(format!("{tool:?} {}", arguments.join(" ")));
            script.next().expect("an unscripted scheduler command ran")
        });
        assert!(script.next().is_none(), "a scripted command did not run");
        (result, calls)
    }

    #[test]
    fn a_failed_unload_keeps_every_owned_entry_and_skips_the_reload() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        create_private_directory(paths.launch_agent.parent().unwrap());
        write_private_file(&paths.launch_agent, &launch_agent(&paths).unwrap());
        let error = remove_with(
            HostProfile::MacOs,
            &paths,
            || {
                scripted_unload(
                    HostProfile::MacOs,
                    &paths,
                    false,
                    vec![Ok(probe(5, "")), Ok(probe(0, "state = running\n"))],
                )
                .0
            },
            || panic!("reloaded after a failed unload"),
        )
        .unwrap_err();
        assert!(error.contains("could not be proven unloaded"), "{error}");
        assert!(error.contains("scheduler files were kept"), "{error}");
        assert!(error.contains("launchctl bootout gui/"), "{error}");
        assert_eq!(
            fs::read_to_string(&paths.launch_agent).unwrap(),
            launch_agent(&paths).unwrap()
        );

        create_private_directory(paths.systemd_service.parent().unwrap());
        write_private_file(&paths.systemd_service, &systemd_service(&paths).unwrap());
        write_private_file(&paths.systemd_timer, systemd_timer());
        let temporary = temporary_path(&paths.systemd_timer).unwrap();
        write_private_file(&temporary, "partial\n");
        let error = remove_with(
            HostProfile::Linux,
            &paths,
            || Err("injected unload failure".into()),
            || panic!("reloaded after a failed unload"),
        )
        .unwrap_err();
        assert_eq!(error, "injected unload failure");
        assert!(paths.systemd_service.is_file());
        assert!(paths.systemd_timer.is_file());
        assert!(temporary.is_file());
    }

    #[test]
    fn an_unloaded_or_absent_job_allows_owned_entry_removal() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        create_private_directory(paths.launch_agent.parent().unwrap());
        for script in [
            vec![Ok(probe(0, ""))],
            vec![Ok(probe(5, "")), Ok(probe(LAUNCHD_SERVICE_NOT_FOUND, ""))],
        ] {
            write_private_file(&paths.launch_agent, &launch_agent(&paths).unwrap());
            let outcome = remove_with(
                HostProfile::MacOs,
                &paths,
                || scripted_unload(HostProfile::MacOs, &paths, false, script).0,
                || panic!("launchd removal reloaded systemd"),
            )
            .unwrap();
            assert_eq!(outcome, RemovalOutcome::default());
            assert!(fs::symlink_metadata(&paths.launch_agent).is_err());
        }
    }

    #[test]
    fn launchd_unload_requires_bootout_or_proof_that_the_service_is_absent() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        let domain = format!("gui/{}", rustix::process::getuid().as_raw());
        let (result, calls) =
            scripted_unload(HostProfile::MacOs, &paths, true, vec![Ok(probe(0, ""))]);
        result.unwrap();
        assert_eq!(
            calls,
            [format!(
                "Launchctl bootout {domain} {}",
                paths.launch_agent.display()
            )]
        );

        let (result, calls) = scripted_unload(
            HostProfile::MacOs,
            &paths,
            true,
            vec![Ok(probe(3, "")), Ok(probe(LAUNCHD_SERVICE_NOT_FOUND, ""))],
        );
        result.unwrap();
        assert_eq!(
            calls[1],
            format!("Launchctl print {domain}/{LAUNCHD_LABEL}")
        );

        for print in [Ok(probe(0, "state = running\n")), Ok(probe(1, ""))] {
            let (result, _) = scripted_unload(
                HostProfile::MacOs,
                &paths,
                true,
                vec![Ok(probe(5, "")), print],
            );
            assert!(result.unwrap_err().contains("could not be proven unloaded"));
        }
        let (result, _) = scripted_unload(
            HostProfile::MacOs,
            &paths,
            true,
            vec![Err("required host tool is unavailable: Launchctl".into())],
        );
        let error = result.unwrap_err();
        assert!(
            error.starts_with("required host tool is unavailable"),
            "{error}"
        );
        assert!(error.contains("scheduler files were kept"), "{error}");
    }

    #[test]
    fn systemd_unload_requires_disable_or_proof_that_the_timer_is_unloaded() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        let (result, calls) = scripted_unload(HostProfile::Linux, &paths, false, Vec::new());
        result.unwrap();
        assert!(calls.is_empty());

        let (result, calls) =
            scripted_unload(HostProfile::Wsl, &paths, true, vec![Ok(probe(0, ""))]);
        result.unwrap();
        assert_eq!(
            calls,
            ["Systemctl --user disable --now shimpz-update.timer"]
        );

        for absent in [
            "LoadState=not-found\nActiveState=inactive\nUnitFileState=\n",
            "ActiveState=inactive\nUnitFileState=disabled\n",
            "ActiveState=failed\nUnitFileState=disabled\n",
        ] {
            let (result, calls) = scripted_unload(
                HostProfile::Linux,
                &paths,
                true,
                vec![Ok(probe(1, "")), Ok(probe(0, absent))],
            );
            result.unwrap();
            assert_eq!(
                calls[1],
                "Systemctl --user show shimpz-update.timer --property=ActiveState,UnitFileState"
            );
        }
        for loaded in [
            Ok(probe(0, "ActiveState=active\nUnitFileState=enabled\n")),
            Ok(probe(0, "ActiveState=inactive\nUnitFileState=enabled\n")),
            Ok(probe(0, "ActiveState=activating\nUnitFileState=disabled\n")),
            Ok(probe(0, "UnitFileState=disabled\n")),
            Ok(probe(1, "ActiveState=inactive\nUnitFileState=disabled\n")),
        ] {
            let (result, _) = scripted_unload(
                HostProfile::Linux,
                &paths,
                true,
                vec![Ok(probe(1, "")), loaded],
            );
            let error = result.unwrap_err();
            assert!(error.contains("could not be proven stopped"), "{error}");
            assert!(
                error.contains("systemctl --user disable --now shimpz-update.timer"),
                "{error}"
            );
        }
    }

    #[test]
    fn removal_deletes_only_safe_scheduler_temporaries() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        create_private_directory(paths.launch_agent.parent().unwrap());
        let temporary = temporary_path(&paths.launch_agent).unwrap();
        write_private_file(&temporary, "partial\n");
        assert_eq!(
            remove(HostProfile::MacOs, &paths).unwrap(),
            RemovalOutcome::default()
        );
        assert!(fs::symlink_metadata(&temporary).is_err());

        let target = home.path().join("temporary-target");
        fs::write(&target, "keep\n").unwrap();
        symlink(&target, &temporary).unwrap();
        let outcome = remove(HostProfile::MacOs, &paths).unwrap();
        assert_eq!(outcome.preserved, [display_path(&temporary)]);
        assert!(!outcome.execution_unverified);
        assert_eq!(fs::read_to_string(target).unwrap(), "keep\n");
    }

    #[test]
    fn does_not_follow_a_foreign_scheduler_symlink() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir_all(paths.launch_agent.parent().unwrap()).unwrap();
        let target = home.path().join("target");
        fs::write(&target, "keep\n").unwrap();
        symlink(&target, &paths.launch_agent).unwrap();
        let entries = inspect_entries(HostProfile::MacOs, &paths).unwrap();
        assert_eq!(entries[0].state, EntryState::Foreign);
        remove_exact_entry(&paths.launch_agent).unwrap();
        assert_eq!(fs::read_to_string(target).unwrap(), "keep\n");
    }

    #[test]
    fn uses_a_unique_temporary_sibling_for_each_entry() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        assert_eq!(
            temporary_path(&paths.systemd_service).unwrap(),
            paths
                .systemd_service
                .with_file_name("shimpz-update.service.tmp")
        );
        assert_eq!(
            temporary_path(&paths.systemd_timer).unwrap(),
            paths
                .systemd_timer
                .with_file_name("shimpz-update.timer.tmp")
        );
    }

    #[test]
    fn validates_every_foreign_entry_before_removing_any() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir_all(paths.systemd_service.parent().unwrap()).unwrap();
        fs::write(&paths.systemd_service, "foreign\n").unwrap();
        fs::create_dir(&paths.systemd_timer).unwrap();
        let entries = inspect_entries(HostProfile::Linux, &paths).unwrap();
        let mut authorize = |_: &[PathBuf]| -> Result<bool, String> { Ok(true) };
        let error = resolve_foreign_entries(&entries, false, &mut authorize, || {}).unwrap_err();
        assert!(error.contains("cannot be replaced safely"));
        assert_eq!(
            fs::read_to_string(&paths.systemd_service).unwrap(),
            "foreign\n"
        );
        assert!(paths.systemd_timer.is_dir());
    }

    #[test]
    fn creates_the_final_scheduler_directory_privately() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        prepare_parent(&paths.systemd_service).unwrap();
        let metadata = paths
            .systemd_service
            .parent()
            .unwrap()
            .symlink_metadata()
            .unwrap();
        assert_eq!(metadata.permissions().mode() & 0o077, 0);
        fs::set_permissions(
            paths.systemd_service.parent().unwrap(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        prepare_parent(&paths.systemd_service).unwrap();
        let retained = paths
            .systemd_service
            .parent()
            .unwrap()
            .symlink_metadata()
            .unwrap();
        assert_eq!(retained.permissions().mode() & 0o777, 0o755);
    }
}
