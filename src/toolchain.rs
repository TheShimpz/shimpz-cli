//! Private, pinned `uv` bootstrap without shell profile changes.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::output;

const UV_VERSION: &str = "0.11.32";

pub(crate) fn uv() -> Result<Command, String> {
    let executable = match std::env::var_os("SHIMPZ_UV") {
        Some(path) => validated(PathBuf::from(path))?,
        None => managed_uv()?,
    };
    let mut command = Command::new(executable);
    strip_untrusted_env(&mut command);
    Ok(command)
}

fn strip_untrusted_env(command: &mut Command) {
    command
        .env_remove("UV_DEFAULT_INDEX")
        .env_remove("UV_INDEX")
        .env_remove("UV_INDEX_URL")
        .env_remove("UV_EXTRA_INDEX_URL")
        .env_remove("UV_FIND_LINKS")
        .env_remove("UV_PYTHON_INSTALL_MIRROR")
        .env_remove("UV_INSECURE_HOST")
        .env_remove("UV_NATIVE_TLS");
}

fn managed_uv() -> Result<PathBuf, String> {
    let directory = cache_directory()?.join("toolchains").join(UV_VERSION);
    let executable = directory.join(executable_name());
    if executable.is_file() {
        verify_version(&executable)?;
        return Ok(executable);
    }
    std::fs::create_dir_all(&directory).map_err(|_| "uv cache cannot be created")?;
    output::progress(&format!("Installing managed uv {UV_VERSION}..."));
    install(&directory)?;
    if !executable.is_file() {
        return Err("managed uv installation failed".into());
    }
    verify_version(&executable)?;
    Ok(executable)
}

fn verify_version(executable: &Path) -> Result<(), String> {
    let output = Command::new(executable)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "managed uv cannot report its version")?;
    if !output.status.success() {
        return Err("managed uv cannot report its version".into());
    }
    if String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .nth(1)
        != Some(UV_VERSION)
    {
        return Err("managed uv version does not match the pinned release".into());
    }
    Ok(())
}

fn cache_directory() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("SHIMPZ_CACHE_DIR") {
        return Ok(PathBuf::from(path));
    }
    #[cfg(target_os = "windows")]
    let base = std::env::var_os("LOCALAPPDATA");
    #[cfg(not(target_os = "windows"))]
    let base = std::env::var_os("XDG_CACHE_HOME")
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache").into()));
    base.map(PathBuf::from)
        .map(|path| path.join("shimpz"))
        .ok_or_else(|| "user cache directory is unavailable".into())
}

fn validated(path: PathBuf) -> Result<PathBuf, String> {
    if path.is_file() {
        Ok(path)
    } else {
        Err("managed uv installation failed".into())
    }
}

const fn executable_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "uv.exe"
    } else {
        "uv"
    }
}

#[cfg(unix)]
fn install(directory: &Path) -> Result<(), String> {
    let url = format!(
        "https://releases.astral.sh/github/uv/releases/download/{UV_VERSION}/uv-installer.sh"
    );
    let script = format!("curl --proto '=https' --tlsv1.2 -LsSf '{url}' | sh");
    let output = Command::new("sh")
        .args(["-c", &script])
        .env("UV_UNMANAGED_INSTALL", directory)
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "managed uv installer is unavailable")?;
    if output.status.success() {
        Ok(())
    } else {
        Err(installer_failure(&output.stderr))
    }
}

#[cfg(windows)]
fn install(directory: &Path) -> Result<(), String> {
    let url = format!(
        "https://releases.astral.sh/github/uv/releases/download/{UV_VERSION}/uv-installer.ps1"
    );
    let script = format!(
        "$env:UV_UNMANAGED_INSTALL='{}'; irm '{url}' | iex",
        directory.display()
    );
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "managed uv installer is unavailable")?;
    if output.status.success() {
        Ok(())
    } else {
        Err(installer_failure(&output.stderr))
    }
}

fn installer_failure(stderr: &[u8]) -> String {
    let trimmed = String::from_utf8_lossy(stderr).trim().to_owned();
    if trimmed.is_empty() {
        "managed uv installation failed".into()
    } else {
        format!("managed uv installation failed: {trimmed}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::ffi::{OsStr, OsString};

    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    fn uv_shim(version: &str, name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("shimpz-uv-{name}-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let shim = directory.join("uv");
        fs::write(&shim, format!("#!/bin/sh\necho 'uv {version}'\n")).unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
        shim
    }

    #[cfg(unix)]
    #[test]
    fn rejects_uv_with_mismatched_version() {
        assert!(verify_version(&uv_shim("0.0.1", "mismatch")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn accepts_uv_matching_the_pinned_version() {
        assert!(verify_version(&uv_shim(UV_VERSION, "matching")).is_ok());
    }

    #[test]
    fn strips_untrusted_uv_environment() {
        let mut command = Command::new("uv");
        strip_untrusted_env(&mut command);
        let removed: BTreeSet<OsString> = command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(key, _)| key.to_owned())
            .collect();
        for key in [
            "UV_DEFAULT_INDEX",
            "UV_INDEX",
            "UV_INDEX_URL",
            "UV_EXTRA_INDEX_URL",
            "UV_FIND_LINKS",
            "UV_PYTHON_INSTALL_MIRROR",
            "UV_INSECURE_HOST",
            "UV_NATIVE_TLS",
        ] {
            assert!(removed.contains(OsStr::new(key)));
        }
    }

    #[test]
    fn surfaces_installer_stderr() {
        assert!(
            installer_failure(b"curl: (60) SSL certificate problem")
                .contains("curl: (60) SSL certificate problem")
        );
        assert_eq!(installer_failure(b"   "), "managed uv installation failed");
    }
}
