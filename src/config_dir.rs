//! The per-user `shimpz` configuration directory.

use std::env;
use std::path::PathBuf;

/// `shimpz` under the OS configuration root: `$XDG_CONFIG_HOME` or `~/.config` on Unix, `%APPDATA%` on Windows.
pub(crate) fn path() -> Option<PathBuf> {
    root().map(|root| root.join("shimpz"))
}

#[cfg(windows)]
fn root() -> Option<PathBuf> {
    env::var_os("APPDATA").map(PathBuf::from)
}

#[cfg(not(windows))]
fn root() -> Option<PathBuf> {
    env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
}
