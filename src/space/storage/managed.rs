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
    verify_macos_disk(paths)
}

fn verify_macos_disk(paths: &Paths) -> Result<(), String> {
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

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires the native macOS filesystem layout"]
    fn native_macos_proves_the_exact_docker_disk_filesystem() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        let disk = home
            .path()
            .join("Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw");
        std::fs::create_dir_all(disk.parent().unwrap()).unwrap();
        std::fs::write(&disk, []).unwrap();
        verify_macos_disk(&paths).unwrap();
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "requires native Windows PowerShell and the BitLocker provider"]
    fn native_windows_executes_the_exact_bitlocker_query_and_parser() {
        let local = std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA is required");
        let disk = Path::new(&local).join("Docker/wsl/data/docker_data.vhdx");
        std::fs::create_dir_all(disk.parent().unwrap()).unwrap();
        if !disk.exists() {
            std::fs::write(&disk, []).unwrap();
        }
        let result = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", BITLOCKER_QUERY])
            .output()
            .unwrap();
        assert!(result.status.success());
        let record = String::from_utf8(result.stdout).unwrap();
        let fields: Vec<_> = record.trim().split('|').collect();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0], "shimpz-bitlocker-v1");
        let expected = fields[1] == "FullyEncrypted" && fields[2] == "On" && fields[3] == "100";
        assert_eq!(bitlocker_record_valid(&record), expected);
    }
}
