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
    let installed = match state::read_private_installed(paths, profile) {
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
