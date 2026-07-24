//! Private, pinned `uv` bootstrap without shell profile changes.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const UV_VERSION: &str = "0.11.32";

pub(crate) fn uv() -> Result<Command, String> {
    let executable = match std::env::var_os("SHIMPZ_UV") {
        Some(path) => validated(PathBuf::from(path))?,
        None => managed_uv()?,
    };
    let mut command = Command::new(executable);
    command
        .env_remove("UV_DEFAULT_INDEX")
        .env_remove("UV_INDEX")
        .env_remove("UV_INDEX_URL")
        .env_remove("UV_EXTRA_INDEX_URL")
        .env_remove("UV_FIND_LINKS");
    Ok(command)
}

fn managed_uv() -> Result<PathBuf, String> {
    let directory = cache_directory()?.join("toolchains").join(UV_VERSION);
    let executable = directory.join(executable_name());
    if executable.is_file() {
        return Ok(executable);
    }
    std::fs::create_dir_all(&directory).map_err(|_| "uv cache cannot be created")?;
    eprintln!("shimpz: installing managed uv {UV_VERSION}");
    install(&directory)?;
    validated(executable)
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
    let status = Command::new("sh")
        .args(["-c", &script])
        .env("UV_UNMANAGED_INSTALL", directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "managed uv installer is unavailable")?;
    if status.success() {
        Ok(())
    } else {
        Err("managed uv installation failed".into())
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
    let status = Command::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "managed uv installer is unavailable")?;
    if status.success() {
        Ok(())
    } else {
        Err("managed uv installation failed".into())
    }
}
