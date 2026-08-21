//! Bounded on-disk Local lifecycle state.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use super::docker::ResolvedRelease;
use super::host::HostProfile;
use super::paths::{MARKER, Paths};

const STOPPED: &str = "shimpz-space-stopped-v1\n";

#[derive(Debug)]
pub(crate) struct Installed {
    pub(crate) space_id: String,
    pub(crate) release_ref: String,
    pub(crate) admin_image: String,
    pub(crate) ordinal: u64,
    pub(crate) port: u16,
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
    let values = parse_environment(&document)?;
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
    })
}

fn parse_environment(document: &str) -> Result<BTreeMap<&str, &str>, String> {
    if document.len() > 8_192 || document.contains('\r') {
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
    let expected = required.len() + usize::from(linux);
    if values.len() != expected
        || required.iter().any(|key| !values.contains_key(key))
        || (linux && !values.contains_key("SHIMPZ_SECURE_VOLUME_ROOT"))
    {
        return Err("the installed Local environment has unknown or missing fields".into());
    }
    let space_id = values["SHIMPZ_SPACE_ID"];
    if !valid_space_id(space_id) {
        return Err("the installed Local Space identity is invalid".into());
    }
    let release_ref = values["SHIMPZ_LOCAL_RELEASE_IMAGE"];
    if !super::release::valid_release_ref(release_ref) {
        return Err("the installed Local release reference is invalid".into());
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
    for (key, repository) in [
        ("SHIMPZ_ADMIN_IMAGE", "ghcr.io/theshimpz/shimpz-admin"),
        ("SHIMPZ_TEAM_IMAGE", "ghcr.io/theshimpz/shimpz-team-local"),
        ("SHIMPZ_BRAIN_IMAGE", "ghcr.io/theshimpz/shimpz-brain"),
        ("SHIMPZ_EGRESS_IMAGE", "ghcr.io/theshimpz/shimpz-egress"),
    ] {
        if !valid_digest_ref(values[key], repository) {
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
    write_private(&paths.status, &document)?;
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
        .filter(|value| super::release::valid_release_ref(value))
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
    let temporary = path.with_extension("tmp");
    if temporary.exists() {
        fs::remove_file(&temporary).map_err(io_error)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(io_error)?;
    file.write_all(value.as_bytes()).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    fs::rename(temporary, path).map_err(io_error)
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

fn valid_space_id(value: &str) -> bool {
    value.strip_prefix("space-").is_some_and(|suffix| {
        suffix.len() == 24
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_digest_ref(value: &str, repository: &str) -> bool {
    value
        .strip_prefix(repository)
        .and_then(|suffix| suffix.strip_prefix("@sha256:"))
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
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
            },
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
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        let release = release();
        write_environment(
            &paths,
            &Environment {
                release: &release,
                profile: HostProfile::Linux,
                space_id: "space-0123456789abcdef01234567",
                port: 7777,
                docker_gid: 998,
                docker_socket: Path::new("/var/run/docker.sock"),
                cpuset: "0-3",
                secure_root: &paths.pool_mount,
            },
        )
        .unwrap();
        let installed = read_installed(&paths, HostProfile::Linux).unwrap();
        assert_eq!(installed.space_id, "space-0123456789abcdef01234567");
        assert_eq!(installed.release_ref, release.reference);
        assert_eq!(installed.ordinal, 1);
        assert_eq!(installed.port, 7777);
    }

    #[test]
    fn round_trips_only_the_desktop_vm_socket_on_macos() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        let release = release();
        write_environment(
            &paths,
            &Environment {
                release: &release,
                profile: HostProfile::MacOs,
                space_id: "space-0123456789abcdef01234567",
                port: 7777,
                docker_gid: 0,
                docker_socket: Path::new("/var/run/docker.sock.raw"),
                cpuset: "0-3",
                secure_root: &paths.pool_mount,
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
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        let release = release();
        write_environment(
            &paths,
            &Environment {
                release: &release,
                profile: HostProfile::Linux,
                space_id: "space-0123456789abcdef01234567",
                port: 7777,
                docker_gid: 998,
                docker_socket: Path::new("/var/run/docker.sock"),
                cpuset: "0",
                secure_root: &paths.pool_mount,
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
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
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
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();

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

        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();

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
