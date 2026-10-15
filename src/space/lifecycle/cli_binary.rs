//! The managed CLI binary: its private directory, the release-bound handoff and activation, and the evidence of a
//! handed-off release's commit.

use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use crate::space::docker::ResolvedRelease;
use crate::space::host::HostProfile;
use crate::space::paths::Paths;
use crate::space::{poll, state};

use super::{PathReport, io_error, remove_regular_if_present};

/// Reads the managed CLI directory when it exists: records every entry other than the managed artifacts in `others`
/// and returns the managed artifacts present, sorted. The directory must be a real directory, and owned by this user
/// when `require_owner`.
pub(super) fn scan_managed_bin(
    paths: &Paths,
    require_owner: bool,
    others: &mut PathReport,
) -> Result<Vec<PathBuf>, String> {
    let bin = paths.managed_bin();
    let metadata = match bin.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io_error(error)),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || require_owner && metadata.uid() != rustix::process::getuid().as_raw()
    {
        return Err(format!(
            "the managed CLI directory is invalid: {}",
            bin.display()
        ));
    }
    let artifacts = paths.managed_artifacts();
    let mut managed = Vec::with_capacity(artifacts.len());
    for entry in fs::read_dir(bin).map_err(io_error)? {
        let path = entry.map_err(io_error)?.path();
        if artifacts.contains(&path) {
            managed.push(path);
        } else {
            others.record(path);
        }
    }
    managed.sort();
    Ok(managed)
}

pub(super) fn validate_managed_bin(paths: &Paths) -> Result<(), String> {
    let mut unowned = PathReport::default();
    let managed = scan_managed_bin(paths, true, &mut unowned)?;
    if !unowned.is_empty() {
        return Err(format!(
            "refusing to use unowned managed CLI entries: {}; move or remove every unowned entry, then run shimpz install",
            unowned.render()
        ));
    }
    for path in managed {
        let metadata = path.symlink_metadata().map_err(io_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "the managed CLI artifact is invalid: {}",
                path.display()
            ));
        }
        if metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(format!(
                "the managed CLI artifact ownership or permissions are invalid: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_private_cli(path: &Path) -> Result<(), String> {
    let metadata = path.symlink_metadata().map_err(io_error)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(format!(
            "the managed CLI artifact ownership or permissions are invalid: {}",
            path.display()
        ));
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum CommitEvidence {
    Committed,
    NotCommitted,
    Unknown(String),
}

/// What the durable Local state proves about whether `release` committed. It committed only when its environment is
/// live and the status records its successful reconciliation: the environment is written before health is proved,
/// and the success status is the commit's last write, which a rollback replaces or removes. A missing environment,
/// an environment of another release, or a missing or other valid status proves it did not; anything unreadable or
/// malformed proves nothing.
pub(super) fn commit_evidence(
    paths: &Paths,
    profile: HostProfile,
    release: &ResolvedRelease,
) -> CommitEvidence {
    let installed = match state::read_installed_if_present(paths, profile) {
        Ok(Some(installed)) => installed,
        Ok(None) => return CommitEvidence::NotCommitted,
        Err(cause) => return CommitEvidence::Unknown(cause),
    };
    if installed.release_ref != release.reference {
        return CommitEvidence::NotCommitted;
    }
    if installed.ordinal != release.metadata.ordinal {
        return CommitEvidence::Unknown("the installed Local release ordinal is ambiguous".into());
    }
    match poll::status_record(paths, &release.reference, release.metadata.ordinal) {
        poll::StatusRecord::Reconciled => CommitEvidence::Committed,
        poll::StatusRecord::Other => CommitEvidence::NotCommitted,
        poll::StatusRecord::Unknown(cause) => CommitEvidence::Unknown(cause),
    }
}

/// Make the verified release-bound CLI the managed executable. The caller holds the lifecycle lock and has admitted
/// the exact release; nothing restores the previous executable, because apply retains the release-bound CLI.
pub(super) fn activate_cli(paths: &Paths, running: &Path, expected: &str) -> Result<(), String> {
    let bin = paths.managed_bin();
    match bin.symlink_metadata() {
        Ok(_) => validate_managed_bin(paths)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(bin).map_err(io_error)?;
        }
        Err(error) => return Err(io_error(error)),
    }
    fs::set_permissions(bin, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    let candidate = paths.managed_cli.with_extension("candidate");
    if same_file(running, &paths.managed_cli)? {
        // Replacing the running managed executable would unlink the image that apply verifies; keep its inode.
        if hash_file(&paths.managed_cli)? != expected {
            return Err("the running CLI is not bound to the selected Local release".into());
        }
        fs::set_permissions(&paths.managed_cli, fs::Permissions::from_mode(0o700))
            .map_err(io_error)?;
        remove_regular_if_present(&candidate)?;
    } else {
        remove_regular_if_present(&candidate)?;
        let staged = stage_cli(running, &candidate, expected)
            .and_then(|()| fs::rename(&candidate, &paths.managed_cli).map_err(io_error));
        if let Err(error) = staged {
            return Err(match remove_regular_if_present(&candidate) {
                Ok(()) => error,
                Err(cleanup) => format!("{error}; the staged CLI could not be removed: {cleanup}"),
            });
        }
    }
    remove_regular_if_present(&paths.managed_cli.with_extension("previous")).map_err(|error| {
        format!(
            "the release-bound CLI was installed, but a stale previous CLI could not be removed: {error}; run the installer again"
        )
    })
}

/// Copy the release-bound CLI to its private staging path and verify the copied bytes, not only their source.
fn stage_cli(source: &Path, candidate: &Path, expected: &str) -> Result<(), String> {
    fs::copy(source, candidate).map_err(io_error)?;
    fs::set_permissions(candidate, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    if hash_file(candidate)? != expected {
        return Err("the running CLI is not bound to the selected Local release".into());
    }
    Ok(())
}

fn same_file(left: &Path, right: &Path) -> Result<bool, String> {
    let right = match right.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(io_error(error)),
    };
    let left = fs::metadata(left).map_err(io_error)?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

pub(super) fn restore_previous_cli(managed: &Path, previous: &Path) -> Result<(), String> {
    remove_regular_if_present(managed)?;
    if previous.exists() {
        fs::rename(previous, managed).map_err(io_error)?;
    }
    Ok(())
}

pub(super) fn reconcile_previous_cli(managed: &Path, running: &Path) -> Result<(), String> {
    let previous = managed.with_extension("previous");
    if !previous.exists() {
        return Ok(());
    }
    validate_private_cli(&previous)?;
    if !managed.exists() {
        fs::rename(previous, managed).map_err(io_error)?;
        return Ok(());
    }
    validate_private_cli(managed)?;
    if hash_file(managed)? != hash_file(running)? {
        return Err(
            "an interrupted CLI handoff remains; run the managed ~/.shimpz/bin/shimpz command directly"
                .into(),
        );
    }
    remove_regular_if_present(&previous)
}

pub(super) fn ensure_public_cli(paths: &Paths) -> Result<(), String> {
    if paths.public_cli.exists() {
        let metadata = paths.public_cli.symlink_metadata().map_err(io_error)?;
        if metadata.file_type().is_symlink()
            && fs::read_link(&paths.public_cli).map_err(io_error)? == paths.managed_cli
        {
            return Ok(());
        }
        return Err("refusing to replace an unowned public shimpz command".into());
    }
    let parent = paths
        .public_cli
        .parent()
        .ok_or_else(|| "the public CLI directory is invalid".to_owned())?;
    if parent.exists() {
        let metadata = parent.symlink_metadata().map_err(io_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("the public CLI directory is invalid".into());
        }
    } else {
        fs::create_dir_all(parent).map_err(io_error)?;
    }
    symlink(&paths.managed_cli, &paths.public_cli).map_err(io_error)
}

pub(super) fn expected_cli_hash(
    release: &ResolvedRelease,
    profile: HostProfile,
) -> Result<&str, String> {
    match profile {
        HostProfile::Linux | HostProfile::Wsl => Ok(&release.metadata.cli_linux_amd64_sha256),
        HostProfile::MacOs => release
            .metadata
            .cli_macos_arm64_sha256
            .as_deref()
            .ok_or_else(|| "the Local release carries no macOS CLI".to_owned()),
    }
}

pub(super) fn verify_running_cli(
    release: &ResolvedRelease,
    profile: HostProfile,
) -> Result<(), String> {
    let current = std::env::current_exe().map_err(|_| "the running CLI path is unavailable")?;
    if hash_file(&current)? == expected_cli_hash(release, profile)? {
        Ok(())
    } else {
        Err("the running CLI is not bound to the selected Local release".into())
    }
}

pub(super) fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(io_error)?;
    let mut hasher = crate::digest::Sha256Hasher::new();
    let mut buffer = vec![0_u8; 16 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(io_error)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finish_hex())
}

/// Name why a release-bound CLI run did not succeed; its own diagnostic, if any, precedes this in the log.
pub(super) fn handoff_failure(status: std::io::Result<std::process::ExitStatus>) -> Option<String> {
    match status {
        Ok(status) if status.success() => None,
        Ok(status) => Some(match status.code() {
            Some(code) => format!("it exited with status {code}"),
            None => "it was stopped by a signal".into(),
        }),
        Err(error) => Some(format!("it could not start: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    use super::*;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn public_command_is_only_the_exact_managed_symlink() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir_all(paths.managed_cli.parent().unwrap()).unwrap();
        fs::write(&paths.managed_cli, "managed").unwrap();
        ensure_public_cli(&paths).unwrap();
        assert_eq!(fs::read_link(&paths.public_cli).unwrap(), paths.managed_cli);
        assert!(ensure_public_cli(&paths).is_ok());
        fs::remove_file(&paths.public_cli).unwrap();
        fs::write(&paths.public_cli, "foreign").unwrap();
        assert!(ensure_public_cli(&paths).is_err());
    }

    #[test]
    fn candidate_activation_restores_the_previous_private_cli() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir_all(paths.managed_cli.parent().unwrap()).unwrap();
        let previous = paths.managed_cli.with_extension("previous");
        fs::write(&paths.managed_cli, "candidate").unwrap();
        fs::write(&previous, "previous").unwrap();
        restore_previous_cli(&paths.managed_cli, &previous).unwrap();
        assert_eq!(fs::read_to_string(&paths.managed_cli).unwrap(), "previous");
        assert!(!previous.exists());
    }

    #[test]
    fn reconciles_only_a_previous_artifact_for_the_running_managed_cli() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir_all(paths.managed_cli.parent().unwrap()).unwrap();
        let previous = paths.managed_cli.with_extension("previous");
        fs::write(&paths.managed_cli, "current").unwrap();
        fs::write(&previous, "previous").unwrap();
        fs::set_permissions(&paths.managed_cli, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&previous, fs::Permissions::from_mode(0o700)).unwrap();
        reconcile_previous_cli(&paths.managed_cli, &paths.managed_cli).unwrap();
        assert!(!previous.exists());

        fs::remove_file(&paths.managed_cli).unwrap();
        fs::write(&previous, "restored").unwrap();
        fs::set_permissions(&previous, fs::Permissions::from_mode(0o700)).unwrap();
        reconcile_previous_cli(&paths.managed_cli, &paths.managed_cli).unwrap();
        assert_eq!(fs::read_to_string(&paths.managed_cli).unwrap(), "restored");

        fs::write(&previous, "previous").unwrap();
        fs::set_permissions(&previous, fs::Permissions::from_mode(0o700)).unwrap();
        let other = paths.managed_cli.parent().unwrap().join("other");
        fs::write(&other, "other").unwrap();
        assert!(reconcile_previous_cli(&paths.managed_cli, &other).is_err());
        assert!(previous.exists());
    }

    /// A private Space home with a managed CLI directory, plus a verified release-bound CLI outside it.
    fn activation_fixture(home: &Path) -> (Paths, PathBuf, String) {
        let paths = Paths::under(home).unwrap();
        fs::create_dir(&paths.home).unwrap();
        fs::set_permissions(&paths.home, fs::Permissions::from_mode(0o700)).unwrap();
        let source = home.join("bootstrap-shimpz");
        fs::write(&source, "release-bound CLI").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        let expected = hash_file(&source).unwrap();
        (paths, source, expected)
    }

    fn private_file(path: &Path, content: &str, mode: u32) {
        fs::write(path, content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn activation_installs_the_verified_cli_and_clears_stale_handoff_artifacts() {
        let home = tempfile::tempdir().unwrap();
        let (paths, source, expected) = activation_fixture(home.path());
        let bin = paths.managed_cli.parent().unwrap();
        fs::create_dir(bin).unwrap();
        private_file(&paths.managed_cli, "old CLI", 0o700);
        private_file(
            &paths.managed_cli.with_extension("previous"),
            "stale",
            0o700,
        );
        private_file(
            &paths.managed_cli.with_extension("candidate"),
            "stale",
            0o700,
        );

        activate_cli(&paths, &source, &expected).unwrap();

        assert_eq!(
            fs::read_to_string(&paths.managed_cli).unwrap(),
            "release-bound CLI"
        );
        assert_eq!(mode(&paths.managed_cli), 0o700);
        assert_eq!(mode(bin), 0o700);
        assert!(!paths.managed_cli.with_extension("previous").exists());
        assert!(!paths.managed_cli.with_extension("candidate").exists());
    }

    #[test]
    fn activation_creates_the_private_managed_directory_for_a_fresh_space() {
        let home = tempfile::tempdir().unwrap();
        let (paths, source, expected) = activation_fixture(home.path());

        activate_cli(&paths, &source, &expected).unwrap();

        assert_eq!(mode(paths.managed_cli.parent().unwrap()), 0o700);
        assert_eq!(mode(&paths.managed_cli), 0o700);
        assert_eq!(hash_file(&paths.managed_cli).unwrap(), expected);
    }

    #[test]
    fn activation_of_an_unbound_cli_leaves_the_managed_cli_untouched() {
        let home = tempfile::tempdir().unwrap();
        let (paths, source, _) = activation_fixture(home.path());
        fs::create_dir(paths.managed_cli.parent().unwrap()).unwrap();
        private_file(&paths.managed_cli, "old CLI", 0o700);

        let error = activate_cli(&paths, &source, HEX).unwrap_err();

        assert_eq!(
            error,
            "the running CLI is not bound to the selected Local release"
        );
        assert_eq!(fs::read_to_string(&paths.managed_cli).unwrap(), "old CLI");
        assert!(!paths.managed_cli.with_extension("candidate").exists());
    }

    #[test]
    fn activation_refuses_a_redirected_managed_directory() {
        let home = tempfile::tempdir().unwrap();
        let (paths, source, expected) = activation_fixture(home.path());
        let outside = home.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let bin = paths.managed_cli.parent().unwrap();
        symlink(&outside, bin).unwrap();
        assert!(activate_cli(&paths, &source, &expected).is_err());
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);

        fs::remove_file(bin).unwrap();
        symlink(home.path().join("missing"), bin).unwrap();
        assert!(activate_cli(&paths, &source, &expected).is_err());
        assert!(!home.path().join("missing").exists());
    }

    #[test]
    fn activation_refuses_foreign_entries_before_changing_the_managed_directory() {
        let home = tempfile::tempdir().unwrap();
        let (paths, source, expected) = activation_fixture(home.path());
        let bin = paths.managed_cli.parent().unwrap();
        fs::create_dir(bin).unwrap();
        fs::set_permissions(bin, fs::Permissions::from_mode(0o755)).unwrap();
        private_file(&paths.managed_cli, "old CLI", 0o700);
        private_file(&bin.join("foreign"), "foreign", 0o600);

        assert!(
            activate_cli(&paths, &source, &expected)
                .unwrap_err()
                .starts_with("refusing to use unowned managed CLI entries")
        );
        assert_eq!(mode(bin), 0o755);
        assert_eq!(fs::read_to_string(&paths.managed_cli).unwrap(), "old CLI");
    }

    #[test]
    fn activation_by_the_running_managed_cli_keeps_its_executable_image() {
        let home = tempfile::tempdir().unwrap();
        let (paths, _, expected) = activation_fixture(home.path());
        fs::create_dir(paths.managed_cli.parent().unwrap()).unwrap();
        private_file(&paths.managed_cli, "release-bound CLI", 0o600);
        private_file(&paths.managed_cli.with_extension("previous"), "old", 0o700);
        private_file(
            &paths.managed_cli.with_extension("candidate"),
            "stale",
            0o700,
        );
        let inode = fs::metadata(&paths.managed_cli).unwrap().ino();

        activate_cli(&paths, &paths.managed_cli, &expected).unwrap();

        assert_eq!(fs::metadata(&paths.managed_cli).unwrap().ino(), inode);
        assert_eq!(mode(&paths.managed_cli), 0o700);
        assert!(!paths.managed_cli.with_extension("previous").exists());
        assert!(!paths.managed_cli.with_extension("candidate").exists());
        assert!(activate_cli(&paths, &paths.managed_cli, HEX).is_err());
        assert_eq!(fs::metadata(&paths.managed_cli).unwrap().ino(), inode);
    }
}
