//! Supported Local host detection.

use std::path::Path;

use super::evidence::{HostProfile, classify};

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
