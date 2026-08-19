//! Supported Local host classification and detection.

use std::path::Path;

use super::graph::StorageProfile;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostProfile {
    Linux,
    MacOs,
    Wsl,
}

pub(crate) fn classify(
    os: &str,
    arch: &str,
    microsoft_kernel: bool,
    wsl_interop: bool,
    pid_one: &str,
) -> Result<HostProfile, String> {
    match (os, arch, microsoft_kernel, wsl_interop) {
        ("linux", "x86_64", false, false) => Ok(HostProfile::Linux),
        ("linux", "x86_64", true, true) if pid_one.trim() == "systemd" => Ok(HostProfile::Wsl),
        ("macos", "aarch64", false, false) => Ok(HostProfile::MacOs),
        ("linux", "x86_64", true, true) => Err("WSL2 must run systemd as PID 1".into()),
        _ => Err("the host profile is unsupported or ambiguous".into()),
    }
}

pub(crate) fn detect() -> Result<HostProfile, String> {
    detect_from(
        Path::new("/proc"),
        std::env::consts::OS,
        std::env::consts::ARCH,
    )
}

fn detect_from(proc_root: &Path, os: &str, arch: &str) -> Result<HostProfile, String> {
    if os != "linux" {
        return classify(os, arch, false, false, "");
    }
    let microsoft_kernel = std::fs::read_to_string(proc_root.join("version"))
        .map_err(|_| "the Linux kernel identity is unavailable")?
        .to_ascii_lowercase()
        .contains("microsoft");
    let wsl_interop = proc_root
        .join("sys/fs/binfmt_misc/WSLInterop")
        .try_exists()
        .map_err(|_| "the WSL interop evidence is unavailable")?;
    let pid_one = std::fs::read_to_string(proc_root.join("1/comm")).unwrap_or_default();
    classify(os, arch, microsoft_kernel, wsl_interop, &pid_one)
}

impl HostProfile {
    pub(crate) const fn storage(self) -> StorageProfile {
        match self {
            Self::Linux => StorageProfile::LinuxLuks,
            Self::MacOs | Self::Wsl => StorageProfile::ManagedDisk,
        }
    }

    pub(crate) const fn disk_encryption_recommendation(self, fresh: bool) -> Option<&'static str> {
        if !fresh {
            return None;
        }
        match self {
            Self::Linux => None,
            Self::MacOs => Some(
                "Enable FileVault to protect Docker data at rest; Shimpz does not verify this macOS setting. https://docs.shimpz.com/install/macos/",
            ),
            Self::Wsl => Some(
                "Enable BitLocker on the Windows volume that stores Docker Desktop data; Shimpz does not verify this Windows setting. https://docs.shimpz.com/install/windows/",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn classifies_only_supported_unambiguous_hosts() {
        assert_eq!(
            classify("linux", "x86_64", false, false, "systemd"),
            Ok(HostProfile::Linux)
        );
        assert_eq!(
            classify("linux", "x86_64", true, true, "systemd\n"),
            Ok(HostProfile::Wsl)
        );
        assert_eq!(
            classify("macos", "aarch64", false, false, "launchd"),
            Ok(HostProfile::MacOs)
        );
        assert_eq!(HostProfile::Linux.storage(), StorageProfile::LinuxLuks);
        assert_eq!(HostProfile::Wsl.storage(), StorageProfile::ManagedDisk);
        assert_eq!(HostProfile::MacOs.storage(), StorageProfile::ManagedDisk);
        assert_eq!(
            HostProfile::Linux.disk_encryption_recommendation(true),
            None
        );
        assert_eq!(
            HostProfile::MacOs.disk_encryption_recommendation(true),
            Some(
                "Enable FileVault to protect Docker data at rest; Shimpz does not verify this macOS setting. https://docs.shimpz.com/install/macos/"
            )
        );
        assert_eq!(
            HostProfile::Wsl.disk_encryption_recommendation(true),
            Some(
                "Enable BitLocker on the Windows volume that stores Docker Desktop data; Shimpz does not verify this Windows setting. https://docs.shimpz.com/install/windows/"
            )
        );
        for profile in [HostProfile::Linux, HostProfile::MacOs, HostProfile::Wsl] {
            assert_eq!(profile.disk_encryption_recommendation(false), None);
        }
        for evidence in [
            ("linux", "aarch64", false, false, "systemd"),
            ("macos", "x86_64", false, false, "launchd"),
            ("linux", "x86_64", true, false, "systemd"),
            ("linux", "x86_64", false, true, "systemd"),
            ("windows", "x86_64", false, false, ""),
        ] {
            assert!(classify(evidence.0, evidence.1, evidence.2, evidence.3, evidence.4).is_err());
        }
        assert!(classify("linux", "x86_64", true, true, "init").is_err());
    }

    #[test]
    fn detects_only_complete_linux_evidence() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("version"), "Linux version 6.8").unwrap();
        assert_eq!(
            detect_from(root.path(), "linux", "x86_64"),
            Ok(HostProfile::Linux)
        );

        fs::remove_file(root.path().join("version")).unwrap();
        fs::create_dir(root.path().join("version")).unwrap();
        assert!(detect_from(root.path(), "linux", "x86_64").is_err());

        #[cfg(unix)]
        {
            fs::remove_dir(root.path().join("version")).unwrap();
            fs::write(root.path().join("version"), "Linux version 6.8").unwrap();
            fs::write(root.path().join("sys"), "not a directory").unwrap();
            assert!(detect_from(root.path(), "linux", "x86_64").is_err());
        }

        assert_eq!(
            detect_from(root.path(), "macos", "aarch64"),
            Ok(HostProfile::MacOs)
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn detects_a_supported_linux_kernel_host() {
        assert!(matches!(
            detect(),
            Ok(HostProfile::Linux | HostProfile::Wsl)
        ));
    }
}
