//! Native macOS and Windows/WSL protected Docker data-disk admission.

use std::path::Path;

use super::evidence::{HostProfile, bitlocker_record_valid, classify};
use crate::space::command::{self, Tool};
use crate::space::paths::Paths;

const BITLOCKER_QUERY: &str = "$ErrorActionPreference=\"Stop\"; $disk=Join-Path $env:LOCALAPPDATA \"Docker\\wsl\\data\\docker_data.vhdx\"; if (-not (Test-Path -LiteralPath $disk -PathType Leaf)) { throw \"missing Docker data disk\" }; $root=[System.IO.Path]::GetPathRoot($disk); $volume=Get-BitLockerVolume -MountPoint $root; if ($null -eq $volume) { throw \"missing BitLocker volume\" }; \"shimpz-bitlocker-v1|$($volume.VolumeStatus)|$($volume.ProtectionStatus)|$($volume.EncryptionPercentage)\"";

pub(crate) fn detect() -> Result<HostProfile, String> {
    let microsoft_kernel = std::fs::read_to_string("/proc/version")
        .is_ok_and(|value| value.to_ascii_lowercase().contains("microsoft"));
    let wsl_interop = Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists();
    let pid_one = std::fs::read_to_string("/proc/1/comm").unwrap_or_default();
    classify(
        std::env::consts::OS,
        std::env::consts::ARCH,
        microsoft_kernel,
        wsl_interop,
        &pid_one,
    )
}

pub(crate) fn verify(profile: HostProfile, paths: &Paths) -> Result<(), String> {
    match profile {
        HostProfile::Linux => Err("native Linux requires the dedicated LUKS admission".into()),
        HostProfile::MacOs => verify_macos(paths),
        HostProfile::Wsl => verify_wsl(),
    }
}

fn verify_macos(paths: &Paths) -> Result<(), String> {
    let active = command::status(Tool::FileVault, ["isactive"])?;
    if !active.success() {
        return Err("FileVault is not active".into());
    }
    let disk = paths
        .home
        .parent()
        .ok_or_else(|| "the user home is invalid".to_owned())?
        .join("Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw");
    let disk_link = disk
        .symlink_metadata()
        .map_err(|_| "Docker Desktop's default Docker.raw data disk is missing")?;
    if disk_link.file_type().is_symlink() || !disk_link.is_file() {
        return Err("Docker Desktop's data disk must be the supported default regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let startup = std::fs::metadata("/System/Volumes/Data")
            .map_err(|_| "the FileVault startup data filesystem is unavailable")?;
        let docker = disk
            .metadata()
            .map_err(|_| "Docker Desktop's data disk is unavailable")?;
        if startup.dev() != docker.dev() {
            return Err("Docker Desktop's data disk is outside the FileVault filesystem".into());
        }
    }
    Ok(())
}

fn verify_wsl() -> Result<(), String> {
    let record = command::output(
        Tool::PowerShell,
        ["-NoProfile", "-NonInteractive", "-Command", BITLOCKER_QUERY],
    )?;
    if bitlocker_record_valid(&record) {
        Ok(())
    } else {
        Err(
            "BitLocker does not fully encrypt and protect Docker Desktop's default WSL data disk"
                .into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_query_is_fixed_and_bounded_to_the_default_disk() {
        assert!(BITLOCKER_QUERY.contains("Docker\\wsl\\data\\docker_data.vhdx"));
        assert!(BITLOCKER_QUERY.contains("Get-BitLockerVolume -MountPoint $root"));
        assert!(!BITLOCKER_QUERY.contains("Invoke-Expression"));
        assert!(!BITLOCKER_QUERY.contains("SHIMPZ"));
    }
}
