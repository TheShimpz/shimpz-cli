//! Fail-closed supported-host classification and managed-disk evidence parsing.

use super::super::graph::StorageProfile;

#[derive(Debug, Eq, PartialEq)]
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

impl HostProfile {
    pub(crate) const fn storage(self) -> StorageProfile {
        match self {
            Self::Linux => StorageProfile::LinuxLuks,
            Self::MacOs | Self::Wsl => StorageProfile::ManagedDisk,
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Linux => "linux-luks",
            Self::MacOs => "macos-filevault",
            Self::Wsl => "windows-wsl",
        }
    }
}

pub(crate) fn bitlocker_record_valid(value: &str) -> bool {
    value.trim_end_matches(['\r', '\n']) == "shimpz-bitlocker-v1|FullyEncrypted|On|100"
}

pub(crate) fn luks_dump_valid(value: &str) -> bool {
    exactly_one(value, "Version:")
        && exactly_one_trimmed(value, "cipher:")
        && exactly_one_trimmed(value, "Key:")
        && exactly_one_trimmed(value, "PBKDF:")
        && has_exact(value, "Version:", "2")
        && has_exact_trimmed(value, "cipher:", "aes-xts-plain64")
        && has_exact_trimmed(value, "Key:", "512 bits")
        && has_exact_trimmed(value, "PBKDF:", "argon2id")
}

fn exactly_one(value: &str, prefix: &str) -> bool {
    value
        .lines()
        .filter(|line| line.starts_with(prefix))
        .count()
        == 1
}

fn exactly_one_trimmed(value: &str, prefix: &str) -> bool {
    value
        .lines()
        .filter(|line| line.trim_start().starts_with(prefix))
        .count()
        == 1
}

fn has_exact(value: &str, prefix: &str, expected: &str) -> bool {
    value.lines().any(|line| {
        line.strip_prefix(prefix)
            .is_some_and(|rest| rest.trim() == expected)
    })
}

fn has_exact_trimmed(value: &str, prefix: &str, expected: &str) -> bool {
    value.lines().any(|line| {
        line.trim_start()
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.trim() == expected)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LUKS: &str = "Version:       2\n  cipher:     aes-xts-plain64\n  Key:        512 bits\n  PBKDF:      argon2id\n";

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
        assert_eq!(HostProfile::MacOs.name(), "macos-filevault");
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
    fn parses_only_exact_bitlocker_evidence() {
        assert!(bitlocker_record_valid(
            "shimpz-bitlocker-v1|FullyEncrypted|On|100\r\n"
        ));
        for invalid in [
            "shimpz-bitlocker-v1|EncryptionInProgress|On|99",
            "shimpz-bitlocker-v1|FullyEncrypted|Off|100",
            "FullyEncrypted|On|100",
            "shimpz-bitlocker-v1|FullyEncrypted|On|100|extra",
        ] {
            assert!(!bitlocker_record_valid(invalid));
        }
    }

    #[test]
    fn parses_only_exact_luks2_parameters() {
        assert!(luks_dump_valid(LUKS));
        for invalid in [
            LUKS.replace("Version:       2", "Version:       1"),
            LUKS.replace("aes-xts-plain64", "aes-cbc"),
            LUKS.replace("512 bits", "256 bits"),
            LUKS.replace("argon2id", "pbkdf2"),
            format!("{LUKS}Version:       2\n"),
        ] {
            assert!(!luks_dump_valid(&invalid));
        }
    }
}
