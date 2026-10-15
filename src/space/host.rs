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

    /// The Docker platform every Local image runs as on this host.
    pub(crate) const fn platform(self) -> &'static str {
        match self {
            Self::Linux | Self::Wsl => "linux/amd64",
            Self::MacOs => "linux/arm64",
        }
    }

    /// The Docker engine socket the Local controller mounts on this host.
    pub(crate) const fn docker_socket(self) -> &'static str {
        match self {
            Self::Linux | Self::Wsl => "/var/run/docker.sock",
            Self::MacOs => "/var/run/docker.sock.raw",
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

const GIB: u64 = 1 << 30;
/// Docker memory below this draws a warning and never blocks an install.
const MEMORY_RECOMMENDED: u64 = 4 * GIB;

/// The free bytes an unprivileged writer may still use on one filesystem, which its device identifies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FreeSpace {
    pub(crate) device: u64,
    pub(crate) available: u64,
}

/// What the install preflight requires free disk space for.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Storage {
    DockerImages,
    SpaceData,
}

impl Storage {
    /// Fixed minimum-free-space policy: 10 GiB for Docker images and 2 GiB for the Linux pool's backing storage. It
    /// promises no fit; the values were chosen as several times the unpacked release set measured on 2026-10-11
    /// (about 1.4 GiB) and as a floor for the sparse pool's first writes.
    const fn minimum(self) -> u64 {
        match self {
            Self::DockerImages => 10 * GIB,
            Self::SpaceData => 2 * GIB,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::DockerImages => "Docker images",
            Self::SpaceData => "Shimpz Space data",
        }
    }
}

/// The install preflight's fixed policy. It refuses only when a measured filesystem has less free space than the
/// minimums of everything it holds, summed; otherwise it returns the warnings to show: Docker memory below the
/// recommendation, and each storage this host cannot measure. `None` is unmeasured, never ample.
pub(crate) fn preflight(
    memory: Option<u64>,
    storage: &[(Storage, Option<FreeSpace>)],
) -> Result<Vec<String>, String> {
    for free in storage.iter().filter_map(|(_, free)| *free) {
        let mut held: Vec<Storage> = storage
            .iter()
            .filter(|(_, other)| other.is_some_and(|other| other.device == free.device))
            .map(|(kind, _)| *kind)
            .collect();
        held.sort_unstable();
        held.dedup();
        let required = held.iter().map(|kind| kind.minimum()).sum();
        if free.available < required {
            let names: Vec<_> = held.iter().map(|kind| kind.name()).collect();
            return Err(format!(
                "the disk that holds {} has {} free; installing a Shimpz Space requires at least {} free there; free disk space, then run shimpz install again",
                names.join(" and "),
                gib(free.available),
                gib(required)
            ));
        }
    }
    let mut warnings = Vec::new();
    match memory {
        Some(bytes) if bytes >= MEMORY_RECOMMENDED => {}
        Some(bytes) => warnings.push(format!(
            "Docker has {} of memory; Shimpz recommends at least {} for a Space, which may respond slowly or stop services with less.",
            gib(bytes),
            gib(MEMORY_RECOMMENDED)
        )),
        None => warnings.push(format!(
            "Docker did not report its memory; Shimpz recommends at least {} for a Space.",
            gib(MEMORY_RECOMMENDED)
        )),
    }
    for (kind, _) in storage.iter().filter(|(_, free)| free.is_none()) {
        let warning = format!(
            "Shimpz cannot measure the free disk space for {} on this host; keep at least {} free there.",
            kind.name(),
            gib(kind.minimum())
        );
        if !warnings.contains(&warning) {
            warnings.push(warning);
        }
    }
    Ok(warnings)
}

/// The nearest existing ancestor of `path`, itself included, which holds what is later created there; `None` when an
/// ancestor cannot be inspected, so a higher one on another filesystem is never measured in its place.
pub(crate) fn nearest_existing(path: &Path) -> Option<&Path> {
    path.ancestors()
        .find_map(|ancestor| match ancestor.try_exists() {
            Ok(false) => None,
            Ok(true) => Some(Some(ancestor)),
            Err(_) => Some(None),
        })
        .flatten()
}

/// Bytes as GiB with at most one decimal, rounded down so free space is never overstated.
fn gib(bytes: u64) -> String {
    let tenths = u128::from(bytes) * 10 / u128::from(GIB);
    if tenths % 10 == 0 {
        format!("{} GiB", tenths / 10)
    } else {
        format!("{}.{} GiB", tenths / 10, tenths % 10)
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
        for (profile, platform, socket) in [
            (HostProfile::Linux, "linux/amd64", "/var/run/docker.sock"),
            (HostProfile::Wsl, "linux/amd64", "/var/run/docker.sock"),
            (
                HostProfile::MacOs,
                "linux/arm64",
                "/var/run/docker.sock.raw",
            ),
        ] {
            assert_eq!(profile.platform(), platform);
            assert_eq!(profile.docker_socket(), socket);
        }
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

    #[test]
    fn preflight_refuses_only_a_measured_shortfall_of_the_summed_minimums() {
        let free = |device, tenths: u64| {
            Some(FreeSpace {
                device,
                available: (tenths * GIB).div_ceil(10),
            })
        };
        let images = |space| (Storage::DockerImages, space);
        let data = |space| (Storage::SpaceData, space);
        assert_eq!(
            preflight(
                Some(8 * GIB),
                &[
                    images(free(1, 100)),
                    images(free(1, 100)),
                    data(free(2, 20))
                ]
            ),
            Ok(Vec::new())
        );
        assert_eq!(
            preflight(Some(8 * GIB), &[images(free(1, 115)), data(free(1, 115))]),
            Err("the disk that holds Docker images and Shimpz Space data has 11.5 GiB free; installing a Shimpz Space requires at least 12 GiB free there; free disk space, then run shimpz install again".into())
        );
        assert_eq!(
            preflight(None, &[images(free(1, 99)), data(free(2, 500))]),
            Err("the disk that holds Docker images has 9.9 GiB free; installing a Shimpz Space requires at least 10 GiB free there; free disk space, then run shimpz install again".into())
        );
        assert!(
            preflight(
                Some(8 * GIB),
                &[images(None), images(free(1, 500)), data(free(2, 19))]
            )
            .is_err_and(|error| error
                .starts_with("the disk that holds Shimpz Space data has 1.9 GiB free;"))
        );
    }

    #[test]
    fn preflight_warns_about_low_or_unreported_memory_and_unmeasured_storage() {
        assert_eq!(
            preflight(Some(4 * GIB - 1), &[(Storage::DockerImages, None), (Storage::DockerImages, None)]),
            Ok(vec![
                "Docker has 3.9 GiB of memory; Shimpz recommends at least 4 GiB for a Space, which may respond slowly or stop services with less.".to_owned(),
                "Shimpz cannot measure the free disk space for Docker images on this host; keep at least 10 GiB free there.".to_owned(),
            ])
        );
        assert_eq!(
            preflight(None, &[(Storage::SpaceData, None)]),
            Ok(vec![
                "Docker did not report its memory; Shimpz recommends at least 4 GiB for a Space.".to_owned(),
                "Shimpz cannot measure the free disk space for Shimpz Space data on this host; keep at least 2 GiB free there.".to_owned(),
            ])
        );
    }

    #[test]
    fn nearest_existing_stops_at_an_ancestor_it_cannot_inspect() {
        let root = tempfile::tempdir().unwrap();
        let pool = root.path().join("home/.shimpz/security/local-data.luks");
        fs::create_dir(root.path().join("home")).unwrap();
        assert_eq!(
            nearest_existing(&pool),
            Some(root.path().join("home").as_path())
        );
        fs::write(root.path().join("home/.shimpz"), "not a directory").unwrap();
        assert_eq!(nearest_existing(&pool), None);
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
