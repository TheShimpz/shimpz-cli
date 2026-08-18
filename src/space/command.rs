//! Fixed host command boundary for privileged Space operations.

use std::ffi::OsStr;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Tool {
    Chown,
    Docker,
    FileVault,
    Findmnt,
    Install,
    Launchctl,
    Losetup,
    Luks,
    MkfsExt4,
    Mount,
    Mountpoint,
    PowerShell,
    Sudo,
    Systemctl,
    Umount,
}

impl Tool {
    fn candidates(self) -> &'static [&'static str] {
        match self {
            Self::Chown => &["/usr/bin/chown", "/bin/chown"],
            Self::Docker => &[
                "/usr/bin/docker",
                "/usr/local/bin/docker",
                "/opt/homebrew/bin/docker",
            ],
            Self::FileVault => &["/usr/bin/fdesetup"],
            Self::Findmnt => &["/usr/bin/findmnt", "/bin/findmnt"],
            Self::Install => &["/usr/bin/install"],
            Self::Launchctl => &["/bin/launchctl"],
            Self::Losetup => &["/usr/sbin/losetup", "/sbin/losetup"],
            Self::Luks => &["/usr/sbin/cryptsetup", "/sbin/cryptsetup"],
            Self::MkfsExt4 => &["/usr/sbin/mkfs.ext4", "/sbin/mkfs.ext4"],
            Self::Mount => &["/usr/bin/mount", "/bin/mount"],
            Self::Mountpoint => &["/usr/bin/mountpoint", "/bin/mountpoint"],
            Self::PowerShell => &["/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"],
            Self::Sudo => &["/usr/bin/sudo"],
            Self::Systemctl => &["/usr/bin/systemctl", "/bin/systemctl"],
            Self::Umount => &["/usr/bin/umount", "/bin/umount"],
        }
    }

    pub(crate) fn resolve(self) -> Result<PathBuf, String> {
        self.candidates()
            .iter()
            .map(Path::new)
            .find_map(trusted_executable)
            .ok_or_else(|| format!("required host tool is unavailable: {self:?}"))
    }
}

fn trusted_executable(path: &Path) -> Option<PathBuf> {
    let canonical = path.canonicalize().ok()?;
    let metadata = canonical.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            return None;
        }
    }
    Some(canonical)
}

pub(crate) fn output<I, S>(tool: Tool, arguments: I) -> Result<String, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let program = tool.resolve()?;
    let result = Command::new(&program)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("could not execute {}: {error}", program.display()))?;
    if !result.status.success() {
        return Err(format!("host command failed: {}", program.display()));
    }
    String::from_utf8(result.stdout).map_err(|_| "host command output was not UTF-8".into())
}

pub(crate) fn status<I, S>(tool: Tool, arguments: I) -> Result<ExitStatus, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let program = tool.resolve()?;
    Command::new(&program)
        .args(arguments)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| format!("could not execute {}: {error}", program.display()))
}

pub(crate) fn authorize() -> Result<(), String> {
    if effective_root() {
        return Ok(());
    }
    let tty =
        File::open("/dev/tty").map_err(|_| "administrator authorization requires a terminal")?;
    let sudo = Tool::Sudo.resolve()?;
    let result = Command::new(&sudo)
        .arg("--validate")
        .stdin(tty)
        .status()
        .map_err(|error| format!("could not execute {}: {error}", sudo.display()))?;
    if result.success() {
        Ok(())
    } else {
        Err("administrator authorization was not granted".into())
    }
}

pub(crate) fn privileged_status<I, S>(
    tool: Tool,
    arguments: I,
    passphrase_tty: bool,
) -> Result<ExitStatus, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let program = tool.resolve()?;
    let mut command = if effective_root() {
        Command::new(&program)
    } else {
        let sudo = Tool::Sudo.resolve()?;
        let mut command = Command::new(sudo);
        command.arg("--non-interactive").arg(&program);
        command
    };
    command.args(arguments);
    if passphrase_tty {
        let tty = File::open("/dev/tty").map_err(|_| "encrypted storage requires a terminal")?;
        command.stdin(tty);
    } else {
        command.stdin(Stdio::null());
    }
    command
        .status()
        .map_err(|error| format!("could not execute {}: {error}", program.display()))
}

fn effective_root() -> bool {
    #[cfg(unix)]
    {
        rustix::process::getuid().is_root()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_tools_have_only_absolute_fixed_candidates() {
        for tool in [
            Tool::Chown,
            Tool::Docker,
            Tool::FileVault,
            Tool::Findmnt,
            Tool::Install,
            Tool::Launchctl,
            Tool::Losetup,
            Tool::Luks,
            Tool::MkfsExt4,
            Tool::Mount,
            Tool::Mountpoint,
            Tool::PowerShell,
            Tool::Sudo,
            Tool::Systemctl,
            Tool::Umount,
        ] {
            assert!(!tool.candidates().is_empty());
            assert!(tool.candidates().iter().all(|path| path.starts_with('/')));
            assert!(tool.candidates().iter().all(|path| !path.contains("..")));
        }
    }
}
