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

impl HostProfile {
    pub(crate) const fn storage(self) -> StorageProfile {
        match self {
            Self::Linux => StorageProfile::LinuxLuks,
            Self::MacOs | Self::Wsl => StorageProfile::ManagedDisk,
        }
    }
}

#[cfg(test)]
mod tests {
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

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn detects_the_current_native_linux_host() {
        assert_eq!(detect(), Ok(HostProfile::Linux));
    }
}
