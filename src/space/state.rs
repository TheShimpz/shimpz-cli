//! Bounded on-disk Local lifecycle state.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use super::docker::ResolvedRelease;
use super::host::HostProfile;
use super::id;
use super::paths::{MARKER, Paths};
use super::release;
use crate::private_file;

const STOPPED: &str = "shimpz-space-stopped-v1\n";
const MAX_ENVIRONMENT_BYTES: u64 = 8_192;

#[derive(Debug)]
pub(crate) struct Installed {
    pub(crate) space_id: String,
    pub(crate) release_ref: String,
    pub(crate) admin_image: String,
    pub(crate) ordinal: u64,
    pub(crate) port: u16,
    /// The exact published release a developer release was assembled from; `None` for a published release.
    pub(crate) baseline: Option<String>,
}

impl Installed {
    /// The published release this Space follows: itself, or the baseline of an installed developer release.
    pub(crate) fn published_ref(&self) -> &str {
        self.baseline.as_deref().unwrap_or(&self.release_ref)
    }
}

pub(crate) struct Lock {
    file: File,
}

impl Lock {
    pub(crate) fn acquire(paths: &Paths) -> Result<Self, String> {
        Self::try_acquire(paths)?
            .ok_or_else(|| "another Shimpz lifecycle operation is already running".to_owned())
    }

    pub(crate) fn try_acquire(paths: &Paths) -> Result<Option<Self>, String> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&paths.lock)
            .map_err(|error| format!("could not open the Local lifecycle lock: {error}"))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("could not inspect the Local lifecycle lock: {error}"))?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err("the Local lifecycle lock is invalid".into());
        }
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Some(Self { file })),
            Err(error)
                if error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::WOULDBLOCK =>
            {
                Ok(None)
            }
            Err(_) => Err("could not acquire the Local lifecycle lock".into()),
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
    }
}

pub(crate) fn read_installed(paths: &Paths, profile: HostProfile) -> Result<Installed, String> {
    let document = fs::read_to_string(&paths.environment)
        .map_err(|error| format!("could not read the installed Local environment: {error}"))?;
    parse_installed(&document, paths, profile)
}

/// Read the installed environment only as an admitted private record; `Ok(None)` when it is absent.
pub(crate) fn read_private_installed(
    paths: &Paths,
    profile: HostProfile,
) -> Result<Option<Installed>, String> {
    read_private_record(
        &paths.environment,
        MAX_ENVIRONMENT_BYTES,
        "the installed Local environment",
    )?
    .map(|document| parse_installed(&document, paths, profile))
    .transpose()
}

/// Read a record only when it is an owned, private, single-link regular file of at most `limit` bytes, or return
/// `Ok(None)` when it is absent. It is opened without following a symlink or blocking on a special file, and admitted
/// through the open handle, so the checked file is the one read.
pub(crate) fn read_private_record(
    path: &Path,
    limit: u64,
    name: &str,
) -> Result<Option<String>, String> {
    let refused = || format!("{name} is not a private record");
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => return Err(refused()),
        Err(error) => return Err(format!("{name} could not be opened: {error}")),
    };
    let metadata = file
        .metadata()
        .map_err(|error| format!("{name} could not be inspected: {error}"))?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() > limit
    {
        return Err(refused());
    }
    let mut document = String::new();
    file.take(limit + 1)
        .read_to_string(&mut document)
        .map_err(|error| format!("{name} could not be read: {error}"))?;
    if document.len() as u64 > limit {
        return Err(refused());
    }
    Ok(Some(document))
}

fn parse_installed(
    document: &str,
    paths: &Paths,
    profile: HostProfile,
) -> Result<Installed, String> {
    let values = parse_environment(document)?;
    validate_environment(&values, paths, profile)?;
    let space_id = values["SHIMPZ_SPACE_ID"];
    let release_ref = values["SHIMPZ_LOCAL_RELEASE_IMAGE"];
    let ordinal = positive_u64(values["SHIMPZ_LOCAL_RELEASE_ORDINAL"], "release ordinal")?;
    let port = values["SHIMPZ_PORT"]
        .parse::<u16>()
        .ok()
        .filter(|value| *value >= 1024)
        .ok_or_else(|| "the installed Admin port is invalid".to_owned())?;
    Ok(Installed {
        space_id: space_id.into(),
        release_ref: release_ref.into(),
        admin_image: values["SHIMPZ_ADMIN_IMAGE"].into(),
        ordinal,
        port,
        baseline: values
            .get("SHIMPZ_LOCAL_RELEASE_BASELINE")
            .map(|value| (*value).to_owned()),
    })
}

fn parse_environment(document: &str) -> Result<BTreeMap<&str, &str>, String> {
    if document.len() as u64 > MAX_ENVIRONMENT_BYTES || document.contains('\r') {
        return Err("the installed Local environment is malformed".into());
    }
    let mut values = BTreeMap::new();
    for line in document.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| "the installed Local environment is malformed".to_owned())?;
        if key.is_empty()
            || value.is_empty()
            || value.contains('=')
            || values.insert(key, value).is_some()
        {
            return Err("the installed Local environment is malformed".into());
        }
    }
    Ok(values)
}

fn validate_environment(
    values: &BTreeMap<&str, &str>,
    paths: &Paths,
    profile: HostProfile,
) -> Result<(), String> {
    let required = [
        "SHIMPZ_ADMIN_IMAGE",
        "SHIMPZ_TEAM_IMAGE",
        "SHIMPZ_BRAIN_IMAGE",
        "SHIMPZ_EGRESS_IMAGE",
        "SHIMPZ_LOCAL_RELEASE_IMAGE",
        "SHIMPZ_LOCAL_RELEASE_ORDINAL",
        "SHIMPZ_SPACE_PLATFORM",
        "SHIMPZ_PORT",
        "SHIMPZ_DOCKER_GID",
        "SHIMPZ_DOCKER_SOCKET",
        "SHIMPZ_SPACE_ID",
        "SHIMPZ_CPUSET",
        "SHIMPZ_PROJECT_NAME",
        "SHIMPZ_ADMIN_ALLOWED_ORIGINS",
        "SHIMPZ_STORAGE_PROFILE",
    ];
    let expected_storage = profile.storage().name();
    let linux = profile == HostProfile::Linux;
    let developer = values
        .get("SHIMPZ_LOCAL_RELEASE_IMAGE")
        .is_some_and(|value| release::valid_developer_release_ref(value));
    let expected = required.len() + usize::from(linux) + usize::from(developer);
    if values.len() != expected
        || required.iter().any(|key| !values.contains_key(key))
        || (linux && !values.contains_key("SHIMPZ_SECURE_VOLUME_ROOT"))
        || (developer && !values.contains_key("SHIMPZ_LOCAL_RELEASE_BASELINE"))
    {
        return Err("the installed Local environment has unknown or missing fields".into());
    }
    let space_id = values["SHIMPZ_SPACE_ID"];
    if !id::valid(space_id) {
        return Err("the installed Local Space identity is invalid".into());
    }
    let release_ref = values["SHIMPZ_LOCAL_RELEASE_IMAGE"];
    if !release::valid_release_ref(release_ref) {
        return Err("the installed Local release reference is invalid".into());
    }
    if developer
        && (profile == HostProfile::MacOs
            || !release::valid_published_release_ref(values["SHIMPZ_LOCAL_RELEASE_BASELINE"]))
    {
        return Err("the installed developer release baseline is invalid".into());
    }
    let port = values["SHIMPZ_PORT"]
        .parse::<u16>()
        .ok()
        .filter(|value| *value >= 1024)
        .ok_or_else(|| "the installed Admin port is invalid".to_owned())?;
    if values["SHIMPZ_PROJECT_NAME"] != "shimpz-space" {
        return Err("the installed Compose project is invalid".into());
    }
    let expected_platform = match profile {
        HostProfile::Linux | HostProfile::Wsl => "linux/amd64",
        HostProfile::MacOs => "linux/arm64",
    };
    if values["SHIMPZ_SPACE_PLATFORM"] != expected_platform
        || values["SHIMPZ_STORAGE_PROFILE"] != expected_storage
    {
        return Err("the installed Local host profile is invalid".into());
    }
    for (key, package) in [
        ("SHIMPZ_ADMIN_IMAGE", release::ADMIN),
        ("SHIMPZ_TEAM_IMAGE", release::TEAM),
        ("SHIMPZ_BRAIN_IMAGE", release::BRAIN),
        ("SHIMPZ_EGRESS_IMAGE", release::EGRESS),
    ] {
        // Only a developer release may run a member from this host's image store.
        let admitted = if developer {
            package.admits(values[key])
        } else {
            package.published(values[key])
        };
        if !admitted {
            return Err("an installed Local component image is invalid".into());
        }
    }
    if values["SHIMPZ_ADMIN_ALLOWED_ORIGINS"]
        != format!("http://localhost:{port},http://127.0.0.1:{port}")
    {
        return Err("the installed Local Admin origins are invalid".into());
    }
    if !valid_cpuset(values["SHIMPZ_CPUSET"]) || values["SHIMPZ_DOCKER_GID"].parse::<u32>().is_err()
    {
        return Err("the installed Local resource or Docker identity is invalid".into());
    }
    let socket = values["SHIMPZ_DOCKER_SOCKET"];
    let valid_socket = match profile {
        HostProfile::Linux | HostProfile::Wsl => socket == "/var/run/docker.sock",
        HostProfile::MacOs => socket == "/var/run/docker.sock.raw",
    };
    if !valid_socket {
        return Err("the installed Local Docker socket is invalid".into());
    }
    if linux
        && values.get("SHIMPZ_SECURE_VOLUME_ROOT")
            != Some(&paths.pool_mount.to_string_lossy().as_ref())
    {
        return Err("the installed encrypted volume root is invalid".into());
    }
    Ok(())
}

pub(crate) struct Environment<'a> {
    pub(crate) release: &'a ResolvedRelease,
    pub(crate) profile: HostProfile,
    pub(crate) space_id: &'a str,
    pub(crate) port: u16,
    pub(crate) docker_gid: u32,
    pub(crate) docker_socket: &'a Path,
    pub(crate) cpuset: &'a str,
    pub(crate) secure_root: &'a Path,
}

pub(crate) fn write_environment(
    paths: &Paths,
    environment: &Environment<'_>,
) -> Result<(), String> {
    let platform = match environment.profile {
        HostProfile::Linux | HostProfile::Wsl => "linux/amd64",
        HostProfile::MacOs => "linux/arm64",
    };
    let profile = environment.profile.storage().name();
    let release = &environment.release;
    let mut document = format!(
        "SHIMPZ_ADMIN_IMAGE={}\nSHIMPZ_TEAM_IMAGE={}\nSHIMPZ_BRAIN_IMAGE={}\nSHIMPZ_EGRESS_IMAGE={}\nSHIMPZ_LOCAL_RELEASE_IMAGE={}\nSHIMPZ_LOCAL_RELEASE_ORDINAL={}\nSHIMPZ_SPACE_PLATFORM={platform}\nSHIMPZ_PORT={}\nSHIMPZ_DOCKER_GID={}\nSHIMPZ_DOCKER_SOCKET={}\nSHIMPZ_SPACE_ID={}\nSHIMPZ_CPUSET={}\nSHIMPZ_PROJECT_NAME=shimpz-space\nSHIMPZ_ADMIN_ALLOWED_ORIGINS=http://localhost:{},http://127.0.0.1:{}\nSHIMPZ_STORAGE_PROFILE={profile}\n",
        release.metadata.admin,
        release.metadata.team,
        release.metadata.brain,
        release.metadata.egress,
        release.reference,
        release.metadata.ordinal,
        environment.port,
        environment.docker_gid,
        environment.docker_socket.display(),
        environment.space_id,
        environment.cpuset,
        environment.port,
        environment.port,
    );
    if environment.profile == HostProfile::Linux {
        writeln!(
            document,
            "SHIMPZ_SECURE_VOLUME_ROOT={}",
            environment.secure_root.display()
        )
        .expect("String writes are infallible");
    }
    if let Some(baseline) = &release.metadata.baseline {
        writeln!(document, "SHIMPZ_LOCAL_RELEASE_BASELINE={baseline}")
            .expect("String writes are infallible");
    }
    write_private(&paths.environment, &document)
}

pub(crate) fn write_marker(paths: &Paths) -> Result<(), String> {
    write_private(&paths.marker, &format!("{MARKER}\n"))
}

pub(crate) fn write_status(
    paths: &Paths,
    release: &ResolvedRelease,
    outcome: &str,
) -> Result<String, String> {
    let document = status_document(release, outcome)?;
    write_private(&paths.status, &document)?;
    Ok(document)
}

pub(crate) fn status_document(release: &ResolvedRelease, outcome: &str) -> Result<String, String> {
    if !matches!(outcome, "current" | "updated" | "rollback-needed") {
        return Err("the Local release status outcome is invalid".into());
    }
    let document = serde_json::to_string(&serde_json::json!({
        "release": release.reference,
        "ordinal": release.metadata.ordinal,
        "checked_at": unix_timestamp()?,
        "outcome": outcome,
    }))
    .map_err(|_| "could not serialize Local release status".to_owned())?;
    if document.len() > 1_024 {
        return Err("the Local release status is too large".into());
    }
    Ok(document)
}

pub(crate) fn remember_failed_release(
    paths: &Paths,
    release: &ResolvedRelease,
) -> Result<(), String> {
    write_private(
        &paths.failed_release,
        &format!("release={}\n", release.reference),
    )
}

pub(crate) fn failed_release_matches(paths: &Paths, release_ref: &str) -> Result<bool, String> {
    if !paths.failed_release.exists() {
        return Ok(false);
    }
    let metadata = paths.failed_release.symlink_metadata().map_err(io_error)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() > 256
    {
        return Err("the failed Local release record is invalid".into());
    }
    let document = fs::read_to_string(&paths.failed_release)
        .map_err(|_| "the failed Local release record is unreadable".to_owned())?;
    let recorded = document
        .strip_prefix("release=")
        .and_then(|value| value.strip_suffix('\n'))
        .filter(|value| !value.contains('\n'))
        .filter(|value| release::valid_release_ref(value))
        .ok_or_else(|| "the failed Local release record is malformed".to_owned())?;
    Ok(recorded == release_ref)
}

pub(crate) fn stopped(paths: &Paths) -> Result<bool, String> {
    let metadata = match paths.stopped.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(io_error(error)),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() != STOPPED.len() as u64
    {
        return Err("the Local stopped-state record is invalid".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&paths.stopped)
        .map_err(io_error)?;
    let mut document = String::with_capacity(STOPPED.len());
    file.read_to_string(&mut document).map_err(io_error)?;
    if document != STOPPED {
        return Err("the Local stopped-state record is malformed".into());
    }
    Ok(true)
}

pub(crate) fn write_stopped(paths: &Paths) -> Result<(), String> {
    if stopped(paths)? {
        return Ok(());
    }
    write_private(&paths.stopped, STOPPED)
}

pub(crate) fn clear_stopped(paths: &Paths) -> Result<(), String> {
    if !stopped(paths)? {
        return Ok(());
    }
    fs::remove_file(&paths.stopped).map_err(io_error)
}

pub(crate) fn random_space_id() -> Result<String, String> {
    let mut source =
        File::open("/dev/urandom").map_err(|_| "the system random source is unavailable")?;
    let mut bytes = [0_u8; 12];
    source
        .read_exact(&mut bytes)
        .map_err(|_| "could not generate the Local Space identity")?;
    let mut encoded = String::with_capacity(24);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("String writes are infallible");
    }
    Ok(format!("space-{encoded}"))
}

pub(crate) fn selected_port(installed: Option<&Installed>) -> Result<u16, String> {
    if let Some(installed) = installed {
        return Ok(installed.port);
    }
    match std::env::var("SHIMPZ_PORT") {
        Ok(value) => value
            .parse::<u16>()
            .ok()
            .filter(|port| *port >= 1024)
            .ok_or_else(|| "SHIMPZ_PORT must be between 1024 and 65535".into()),
        Err(std::env::VarError::NotPresent) => Ok(7777),
        Err(std::env::VarError::NotUnicode(_)) => Err("SHIMPZ_PORT is invalid".into()),
    }
}

pub(crate) fn write_private(path: &Path, value: &str) -> Result<(), String> {
    private_file::replace(path, value.as_bytes()).map_err(io_error)
}

fn unix_timestamp() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "the system clock is invalid".into())
}

fn positive_u64(value: &str, label: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("the installed {label} is invalid"))
}

fn valid_cpuset(value: &str) -> bool {
    if value == "0" {
        return true;
    }
    value.strip_prefix("0-").is_some_and(|upper| {
        !upper.starts_with('0') && upper.parse::<usize>().is_ok_and(|number| number > 0)
    })
}

fn io_error(error: std::io::Error) -> String {
    let message = format!("could not write Local lifecycle state: {error}");
    drop(error);
    message
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::space::release::Release;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn release() -> ResolvedRelease {
        ResolvedRelease {
            reference: format!("{}@sha256:{HEX}", crate::space::release::RELEASE_REPOSITORY),
            metadata: Release {
                ordinal: 1,
                umbrella_revision: "a".repeat(40),
                cli_revision: "b".repeat(40),
                cli_linux_amd64_sha256: HEX.into(),
                cli_macos_arm64_sha256: HEX.into(),
                admin: format!("ghcr.io/theshimpz/shimpz-admin@sha256:{HEX}"),
                team: format!("ghcr.io/theshimpz/shimpz-team-local@sha256:{HEX}"),
                brain: format!("ghcr.io/theshimpz/shimpz-brain@sha256:{HEX}"),
                egress: format!("ghcr.io/theshimpz/shimpz-egress@sha256:{HEX}"),
                baseline: None,
            },
        }
    }

    /// A developer release over `release()` that rebuilt Team.
    fn developer_release() -> ResolvedRelease {
        let published = release();
        let mut metadata = published.metadata;
        metadata.team = format!("localhost/shimpz-team-local@sha256:{}", "c".repeat(64));
        metadata.baseline = Some(published.reference);
        ResolvedRelease {
            reference: format!(
                "{}@sha256:{}",
                crate::space::release::DEVELOPER_RELEASE_REPOSITORY,
                "d".repeat(64)
            ),
            metadata,
        }
    }

    /// A temporary Local CLI home whose root directory exists; the guard owns its removal.
    fn fresh_paths() -> (tempfile::TempDir, Paths) {
        let home = tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        (home, paths)
    }

    /// The Linux environment every round-trip case starts from; cases override single fields.
    fn linux_environment<'a>(paths: &'a Paths, release: &'a ResolvedRelease) -> Environment<'a> {
        Environment {
            release,
            profile: HostProfile::Linux,
            space_id: "space-0123456789abcdef01234567",
            port: 7777,
            docker_gid: 998,
            docker_socket: Path::new("/var/run/docker.sock"),
            cpuset: "0-3",
            secure_root: &paths.pool_mount,
        }
    }

    fn write_linux(paths: &Paths, release: &ResolvedRelease) {
        write_environment(paths, &linux_environment(paths, release)).unwrap();
    }

    #[test]
    fn records_a_developer_release_only_with_its_exact_published_baseline() {
        let (_home, paths) = fresh_paths();
        let developer = developer_release();
        write_linux(&paths, &developer);
        let installed = read_installed(&paths, HostProfile::Linux).unwrap();
        assert_eq!(installed.release_ref, developer.reference);
        assert_eq!(installed.baseline, developer.metadata.baseline);
        assert_eq!(installed.published_ref(), release().reference);
        assert!(read_installed(&paths, HostProfile::MacOs).is_err());
        let valid = fs::read_to_string(&paths.environment).unwrap();
        let baseline_line = format!("SHIMPZ_LOCAL_RELEASE_BASELINE={}\n", release().reference);
        for invalid in [
            valid.replace(&baseline_line, ""),
            valid.replace(
                &baseline_line,
                &format!("SHIMPZ_LOCAL_RELEASE_BASELINE={}\n", developer.reference),
            ),
            format!("{valid}{baseline_line}"),
        ] {
            fs::write(&paths.environment, invalid).unwrap();
            assert!(read_installed(&paths, HostProfile::Linux).is_err());
        }

        // A published release carries neither the baseline field nor a member from this host's image store.
        write_linux(&paths, &release());
        let published = fs::read_to_string(&paths.environment).unwrap();
        assert!(!published.contains("SHIMPZ_LOCAL_RELEASE_BASELINE"));
        assert_eq!(
            read_installed(&paths, HostProfile::Linux).unwrap().baseline,
            None
        );
        for invalid in [
            format!("{published}{baseline_line}"),
            published.replace(
                "ghcr.io/theshimpz/shimpz-team-local@",
                "localhost/shimpz-team-local@",
            ),
        ] {
            fs::write(&paths.environment, invalid).unwrap();
            assert!(read_installed(&paths, HostProfile::Linux).is_err());
        }
    }

    #[test]
    fn validates_exact_ports() {
        assert_eq!(
            selected_port(Some(&Installed {
                space_id: "space-0123456789abcdef01234567".into(),
                release_ref: format!(
                    "{}@sha256:{}",
                    super::super::release::RELEASE_REPOSITORY,
                    "0".repeat(64)
                ),
                admin_image: format!("ghcr.io/theshimpz/shimpz-admin@sha256:{HEX}"),
                ordinal: 1,
                port: 7777,
                baseline: None,
            })),
            Ok(7777)
        );
    }

    #[test]
    fn retains_one_private_lifecycle_lock_inode() {
        let home = tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        {
            let _lock = Lock::acquire(&paths).unwrap();
            assert!(Lock::try_acquire(&paths).unwrap().is_none());
            let metadata = paths.lock.metadata().unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
        assert!(paths.lock.is_file());
        let _lock = Lock::acquire(&paths).unwrap();
    }

    #[test]
    fn round_trips_only_the_exact_linux_environment() {
        let (_home, paths) = fresh_paths();
        let release = release();
        write_linux(&paths, &release);
        let installed = read_installed(&paths, HostProfile::Linux).unwrap();
        assert_eq!(installed.space_id, "space-0123456789abcdef01234567");
        assert_eq!(installed.release_ref, release.reference);
        assert_eq!(installed.ordinal, 1);
        assert_eq!(installed.port, 7777);
    }

    #[test]
    fn round_trips_only_the_desktop_vm_socket_on_macos() {
        let (_home, paths) = fresh_paths();
        let release = release();
        write_environment(
            &paths,
            &Environment {
                profile: HostProfile::MacOs,
                docker_gid: 0,
                docker_socket: Path::new("/var/run/docker.sock.raw"),
                ..linux_environment(&paths, &release)
            },
        )
        .unwrap();
        assert!(read_installed(&paths, HostProfile::MacOs).is_ok());

        let invalid = fs::read_to_string(&paths.environment)
            .unwrap()
            .replace("/var/run/docker.sock.raw", "/var/run/docker.sock");
        fs::write(&paths.environment, invalid).unwrap();
        assert!(read_installed(&paths, HostProfile::MacOs).is_err());
    }

    #[test]
    fn rejects_unknown_mismatched_and_unbounded_environment_state() {
        let (_home, paths) = fresh_paths();
        let release = release();
        write_environment(
            &paths,
            &Environment {
                cpuset: "0",
                ..linux_environment(&paths, &release)
            },
        )
        .unwrap();
        let valid = fs::read_to_string(&paths.environment).unwrap();
        for invalid in [
            format!("{valid}UNKNOWN=value\n"),
            valid.replace(
                "SHIMPZ_STORAGE_PROFILE=linux-luks",
                "SHIMPZ_STORAGE_PROFILE=managed-disk",
            ),
            valid.replace(
                "SHIMPZ_STORAGE_PROFILE=linux-luks",
                "SHIMPZ_STORAGE_PROFILE=macos-filevault",
            ),
            valid.replace(
                "SHIMPZ_STORAGE_PROFILE=linux-luks",
                "SHIMPZ_STORAGE_PROFILE=windows-wsl",
            ),
            valid.replace("SHIMPZ_CPUSET=0", "SHIMPZ_CPUSET=0,1"),
            valid.replace(
                "SHIMPZ_DOCKER_SOCKET=/var/run/docker.sock",
                "SHIMPZ_DOCKER_SOCKET=/tmp/docker.sock",
            ),
            valid.replace(
                "ghcr.io/theshimpz/shimpz-admin@sha256:",
                "example.invalid/admin@sha256:",
            ),
        ] {
            fs::write(&paths.environment, invalid).unwrap();
            assert!(read_installed(&paths, HostProfile::Linux).is_err());
        }
    }

    #[test]
    fn remembers_only_one_private_failed_release_digest() {
        let (_home, paths) = fresh_paths();
        let release = release();
        assert!(!failed_release_matches(&paths, &release.reference).unwrap());
        remember_failed_release(&paths, &release).unwrap();
        assert!(failed_release_matches(&paths, &release.reference).unwrap());
        assert!(
            !failed_release_matches(
                &paths,
                &format!(
                    "{}@sha256:{}",
                    super::super::release::RELEASE_REPOSITORY,
                    "1".repeat(64)
                )
            )
            .unwrap()
        );
        fs::write(&paths.failed_release, "release=invalid\n").unwrap();
        assert!(failed_release_matches(&paths, &release.reference).is_err());
    }

    #[test]
    fn round_trips_only_the_exact_private_stopped_state() {
        let (_home, paths) = fresh_paths();

        assert!(!stopped(&paths).unwrap());
        write_stopped(&paths).unwrap();
        write_stopped(&paths).unwrap();
        assert!(stopped(&paths).unwrap());
        assert_eq!(
            paths.stopped.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
        clear_stopped(&paths).unwrap();
        clear_stopped(&paths).unwrap();
        assert!(!paths.stopped.exists());
    }

    #[test]
    fn refuses_unsafe_or_malformed_stopped_state() {
        use std::os::unix::fs::symlink;

        let (_home, paths) = fresh_paths();

        fs::write(&paths.stopped, "wrong stopped record\n").unwrap();
        assert!(stopped(&paths).is_err());
        fs::remove_file(&paths.stopped).unwrap();

        fs::write(&paths.stopped, STOPPED).unwrap();
        fs::set_permissions(&paths.stopped, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(stopped(&paths).is_err());
        fs::remove_file(&paths.stopped).unwrap();

        let target = paths.home.join("target");
        fs::write(&target, STOPPED).unwrap();
        symlink(&target, &paths.stopped).unwrap();
        assert!(stopped(&paths).is_err());
    }
}
