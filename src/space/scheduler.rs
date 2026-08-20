//! Exact user scheduler for automatic Local release reconciliation.

use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::command::{self, Tool};
use super::host::HostProfile;
use super::paths::Paths;

const MARKER: &str = "shimpz-local-update-v2";
const MAX_SCHEDULER_BYTES: u64 = 16 * 1024;

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
    if inspect_entries(profile, paths)?
        .iter()
        .any(|entry| entry.state == EntryState::Foreign)
    {
        return Err("a scheduler entry changed while it was being reconciled".into());
    }
    match profile {
        HostProfile::Linux | HostProfile::Wsl => install_systemd(paths),
        HostProfile::MacOs => install_launch_agent(paths),
    }?;
    Ok(InstallOutcome::Enabled)
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
    let entries = inspect_entries(profile, paths)?;
    let removable: Vec<_> = entries
        .iter()
        .filter(|entry| matches!(entry.state, EntryState::Current | EntryState::OwnedCorrupt))
        .collect();
    if !removable.is_empty() {
        unload(profile, paths);
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
    if !removable.is_empty()
        && matches!(profile, HostProfile::Linux | HostProfile::Wsl)
        && Tool::Systemctl.resolve().is_ok()
    {
        require_tool(
            Tool::Systemctl,
            ["--user", "daemon-reload"],
            "systemd did not reload after scheduler removal",
        )?;
    }
    Ok(outcome)
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
        ["--user", "enable", "--now", "shimpz-update.timer"],
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

fn unload(profile: HostProfile, paths: &Paths) {
    match profile {
        HostProfile::Linux | HostProfile::Wsl => {
            let _ = command::status(
                Tool::Systemctl,
                ["--user", "disable", "--now", "shimpz-update.timer"],
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

fn systemd_service(paths: &Paths) -> Result<String, String> {
    Ok(format!(
        "# {MARKER}\n[Unit]\nDescription=Reconcile Shimpz Local Space\nAfter=docker.service\n\n[Service]\nType=oneshot\nExecStart={} start --scheduled\n",
        systemd_quote(&paths.managed_cli)?
    ))
}

fn systemd_timer() -> &'static str {
    "# shimpz-local-update-v2\n[Unit]\nDescription=Periodically reconcile Shimpz Local Space\n\n[Timer]\nOnBootSec=5m\nOnUnitActiveSec=30m\nRandomizedDelaySec=10m\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
}

fn launch_agent(paths: &Paths) -> Result<String, String> {
    let cli = xml_escape(
        paths
            .managed_cli
            .to_str()
            .ok_or_else(|| "the managed CLI path is not UTF-8".to_owned())?,
    );
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- {MARKER} -->\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>com.shimpz.update</string>\n<key>ProgramArguments</key><array><string>{cli}</string><string>start</string><string>--scheduled</string></array>\n<key>RunAtLoad</key><true/>\n<key>StartInterval</key><integer>1800</integer>\n<key>ProcessType</key><string>Background</string>\n</dict></plist>\n"
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
    path.to_string_lossy()
        .chars()
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
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

    #[test]
    fn emits_exact_non_shell_schedulers() {
        let paths = Paths::under(Path::new("/home/Ada Space")).unwrap();
        let service = systemd_service(&paths).unwrap();
        assert!(
            service.contains("ExecStart=\"/home/Ada Space/.shimpz/bin/shimpz\" start --scheduled")
        );
        assert!(!service.contains("sh -c"));
        let plist = launch_agent(&paths).unwrap();
        assert!(plist.contains("<string>/home/Ada Space/.shimpz/bin/shimpz</string>"));
        assert!(plist.contains("<string>--scheduled</string>"));
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
            remove(HostProfile::MacOs, &paths).unwrap(),
            RemovalOutcome::default()
        );
        assert!(fs::symlink_metadata(&paths.launch_agent).is_err());

        write_private_file(
            &paths.launch_agent,
            &format!("<!-- {MARKER} -->\ncorrupt\n"),
        );
        assert_eq!(
            remove(HostProfile::MacOs, &paths).unwrap(),
            RemovalOutcome::default()
        );
        assert!(fs::symlink_metadata(&paths.launch_agent).is_err());

        write_private_file(&paths.launch_agent, "foreign\n");
        let outcome = remove(HostProfile::MacOs, &paths).unwrap();
        assert_eq!(outcome.preserved, [display_path(&paths.launch_agent)]);
        assert!(outcome.execution_unverified);
        assert_eq!(
            fs::read_to_string(&paths.launch_agent).unwrap(),
            "foreign\n"
        );
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
