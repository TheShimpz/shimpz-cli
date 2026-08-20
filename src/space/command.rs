//! Fixed host command boundary for Local Space operations.

use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Tool {
    Chown,
    Docker,
    Findmnt,
    Install,
    Launchctl,
    Losetup,
    Luks,
    MkfsExt4,
    Mount,
    Mountpoint,
    Sudo,
    Systemctl,
    Umount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostOs {
    MacOs,
    Other,
}

#[derive(Debug, Eq, PartialEq)]
enum Candidate {
    Absent,
    Refused { path: PathBuf, reason: &'static str },
    Trusted(PathBuf),
}

impl Tool {
    fn candidates(self) -> &'static [&'static str] {
        match self {
            Self::Chown => &["/usr/bin/chown", "/bin/chown"],
            Self::Docker => &[
                "/usr/bin/docker",
                "/Applications/Docker.app/Contents/Resources/bin/docker",
                "/usr/local/bin/docker",
                "/opt/homebrew/bin/docker",
            ],
            Self::Findmnt => &["/usr/bin/findmnt", "/bin/findmnt"],
            Self::Install => &["/usr/bin/install"],
            Self::Launchctl => &["/bin/launchctl"],
            Self::Losetup => &["/usr/sbin/losetup", "/sbin/losetup"],
            Self::Luks => &["/usr/sbin/cryptsetup", "/sbin/cryptsetup"],
            Self::MkfsExt4 => &["/usr/sbin/mkfs.ext4", "/sbin/mkfs.ext4"],
            Self::Mount => &["/usr/bin/mount", "/bin/mount"],
            Self::Mountpoint => &["/usr/bin/mountpoint", "/bin/mountpoint"],
            Self::Sudo => &["/usr/bin/sudo"],
            Self::Systemctl => &["/usr/bin/systemctl", "/bin/systemctl"],
            Self::Umount => &["/usr/bin/umount", "/bin/umount"],
        }
    }

    pub(crate) fn resolve(self) -> Result<PathBuf, String> {
        let candidates: Vec<_> = self.candidates().iter().map(PathBuf::from).collect();
        resolve_candidates(self, &candidates)
    }
}

fn resolve_candidates(tool: Tool, candidates: &[PathBuf]) -> Result<PathBuf, String> {
    let mut refused = None;
    for path in candidates {
        match inspect_executable(path, tool) {
            Candidate::Absent => {}
            Candidate::Refused { path, reason } => {
                refused.get_or_insert((path, reason));
            }
            Candidate::Trusted(path) => return Ok(path),
        }
    }
    if let Some((path, reason)) = refused {
        Err(format!(
            "required host tool was refused: {tool:?} executable {} {reason}",
            path.display()
        ))
    } else {
        let expected = candidates
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        Err(format!(
            "required host tool is unavailable: {tool:?}; expected an executable at {expected}"
        ))
    }
}

fn inspect_executable(path: &Path, tool: Tool) -> Candidate {
    match path.symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Candidate::Absent,
        Err(_) => {
            return Candidate::Refused {
                path: path.to_owned(),
                reason: "metadata could not be read safely",
            };
        }
        Ok(_) => {}
    }
    let Ok(canonical) = path.canonicalize() else {
        return Candidate::Refused {
            path: path.to_owned(),
            reason: "could not be resolved safely",
        };
    };
    let Ok(metadata) = canonical.metadata() else {
        return Candidate::Refused {
            path: canonical,
            reason: "metadata could not be read safely",
        };
    };
    if !metadata.is_file() {
        return Candidate::Refused {
            path: canonical,
            reason: "is not a regular file",
        };
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let host = if cfg!(target_os = "macos") {
            HostOs::MacOs
        } else {
            HostOs::Other
        };
        if let Some(reason) = metadata_refusal(
            tool,
            host,
            metadata.uid(),
            rustix::process::getuid().as_raw(),
            metadata.permissions().mode(),
        ) {
            return Candidate::Refused {
                path: canonical,
                reason,
            };
        }
    }
    #[cfg(not(unix))]
    let _ = tool;
    Candidate::Trusted(canonical)
}

#[cfg(test)]
fn trusted_executable(path: &Path, tool: Tool) -> Option<PathBuf> {
    match inspect_executable(path, tool) {
        Candidate::Trusted(path) => Some(path),
        Candidate::Absent | Candidate::Refused { .. } => None,
    }
}

#[cfg(test)]
fn trusted_metadata(tool: Tool, host: HostOs, file_uid: u32, process_uid: u32, mode: u32) -> bool {
    metadata_refusal(tool, host, file_uid, process_uid, mode).is_none()
}

fn metadata_refusal(
    tool: Tool,
    host: HostOs,
    file_uid: u32,
    process_uid: u32,
    mode: u32,
) -> Option<&'static str> {
    let owner_is_trusted =
        file_uid == 0 || (tool == Tool::Docker && host == HostOs::MacOs && file_uid == process_uid);
    if !owner_is_trusted {
        Some(if tool == Tool::Docker && host == HostOs::MacOs {
            "is not owned by root or the current macOS user"
        } else {
            "is not owned by root"
        })
    } else if mode & 0o022 != 0 {
        Some("is writable by group or others")
    } else {
        None
    }
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

pub(crate) fn privileged_status<I, S>(tool: Tool, arguments: I) -> Result<ExitStatus, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let (program, mut command) = privileged_command(tool)?;
    command
        .args(arguments)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| format!("could not execute {}: {error}", program.display()))
}

pub(crate) fn privileged_status_with_input<I, S>(
    tool: Tool,
    arguments: I,
    input: &[u8],
) -> Result<ExitStatus, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let (program, mut command) = privileged_command(tool)?;
    let mut child = command
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("could not execute {}: {error}", program.display()))?;
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| "privileged command input is unavailable".to_owned())?
        .write_all(input)
        .map_err(|_| "privileged command input failed".to_owned());
    let status = child
        .wait()
        .map_err(|error| format!("could not execute {}: {error}", program.display()))?;
    write_result?;
    Ok(status)
}

pub(crate) fn privileged_output<I, S>(tool: Tool, arguments: I) -> Result<String, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let (program, mut command) = privileged_command(tool)?;
    let result = command
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("could not execute {}: {error}", program.display()))?;
    if !result.status.success() {
        return Err(format!(
            "privileged host command failed: {}",
            program.display()
        ));
    }
    String::from_utf8(result.stdout).map_err(|_| "host command output was not UTF-8".into())
}

fn privileged_command(tool: Tool) -> Result<(PathBuf, Command), String> {
    let program = tool.resolve()?;
    let command = if effective_root() {
        Command::new(&program)
    } else {
        let sudo = Tool::Sudo.resolve()?;
        let mut command = Command::new(sudo);
        command.arg("--non-interactive").arg(&program);
        command
    };
    Ok((program, command))
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
            Tool::Findmnt,
            Tool::Install,
            Tool::Launchctl,
            Tool::Losetup,
            Tool::Luks,
            Tool::MkfsExt4,
            Tool::Mount,
            Tool::Mountpoint,
            Tool::Sudo,
            Tool::Systemctl,
            Tool::Umount,
        ] {
            assert!(!tool.candidates().is_empty());
            assert!(tool.candidates().iter().all(|path| path.starts_with('/')));
            assert!(tool.candidates().iter().all(|path| !path.contains("..")));
        }
        assert_eq!(
            Tool::Docker.candidates(),
            [
                "/usr/bin/docker",
                "/Applications/Docker.app/Contents/Resources/bin/docker",
                "/usr/local/bin/docker",
                "/opt/homebrew/bin/docker",
            ]
        );
    }

    #[test]
    fn macos_docker_admits_only_root_or_the_current_user() {
        assert!(trusted_metadata(
            Tool::Docker,
            HostOs::MacOs,
            501,
            501,
            0o100_755,
        ));
        assert!(!trusted_metadata(
            Tool::Docker,
            HostOs::MacOs,
            502,
            501,
            0o100_755,
        ));
        assert!(!trusted_metadata(
            Tool::Docker,
            HostOs::MacOs,
            501,
            0,
            0o100_755,
        ));
        assert!(trusted_metadata(
            Tool::Docker,
            HostOs::MacOs,
            0,
            501,
            0o100_755,
        ));
    }

    #[test]
    fn user_owned_executable_is_rejected_outside_macos_docker() {
        for tool in [
            Tool::Chown,
            Tool::Findmnt,
            Tool::Install,
            Tool::Launchctl,
            Tool::Losetup,
            Tool::Luks,
            Tool::MkfsExt4,
            Tool::Mount,
            Tool::Mountpoint,
            Tool::Sudo,
            Tool::Systemctl,
            Tool::Umount,
        ] {
            assert!(!trusted_metadata(tool, HostOs::MacOs, 501, 501, 0o100_755,));
        }
        assert!(!trusted_metadata(
            Tool::Docker,
            HostOs::Other,
            501,
            501,
            0o100_755,
        ));
    }

    #[test]
    fn writable_executable_is_never_trusted() {
        assert!(!trusted_metadata(
            Tool::Docker,
            HostOs::MacOs,
            501,
            501,
            0o100_775,
        ));
    }

    #[test]
    fn metadata_refusal_names_the_exact_owner_and_mode_rules() {
        assert_eq!(
            metadata_refusal(Tool::Docker, HostOs::Other, 501, 501, 0o100_755),
            Some("is not owned by root")
        );
        assert_eq!(
            metadata_refusal(Tool::Docker, HostOs::MacOs, 502, 501, 0o100_755),
            Some("is not owned by root or the current macOS user")
        );
        assert_eq!(
            metadata_refusal(Tool::Docker, HostOs::MacOs, 501, 501, 0o100_775),
            Some("is writable by group or others")
        );
    }

    #[test]
    fn absent_tool_lists_the_fixed_expected_paths() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("docker");

        assert_eq!(
            resolve_candidates(Tool::Docker, std::slice::from_ref(&executable)),
            Err(format!(
                "required host tool is unavailable: Docker; expected an executable at {}",
                executable.display()
            ))
        );
    }

    #[test]
    fn existing_directory_is_refused_instead_of_reported_absent() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("docker");
        std::fs::create_dir(&executable).unwrap();

        assert_eq!(
            resolve_candidates(Tool::Docker, std::slice::from_ref(&executable)),
            Err(format!(
                "required host tool was refused: Docker executable {} is not a regular file",
                executable.display()
            ))
        );
    }

    #[cfg(unix)]
    #[test]
    fn refused_docker_reports_the_failed_trust_property() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("docker");
        fs::write(&executable, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o775)).unwrap();

        let reason = if cfg!(target_os = "macos") || rustix::process::getuid().is_root() {
            "is writable by group or others"
        } else {
            "is not owned by root"
        };
        assert_eq!(
            resolve_candidates(Tool::Docker, std::slice::from_ref(&executable)),
            Err(format!(
                "required host tool was refused: Docker executable {} {reason}",
                executable.display()
            ))
        );
    }

    #[cfg(unix)]
    #[test]
    fn dangling_tool_symlink_is_refused_instead_of_reported_absent() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("docker");
        symlink(directory.path().join("missing"), &executable).unwrap();

        assert_eq!(
            resolve_candidates(Tool::Docker, std::slice::from_ref(&executable)),
            Err(format!(
                "required host tool was refused: Docker executable {} could not be resolved safely",
                executable.display()
            ))
        );
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_metadata_uses_the_platform_owner_policy() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("docker");
        fs::write(&executable, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();

        let uid = rustix::process::getuid().as_raw();
        assert_eq!(
            trusted_executable(&executable, Tool::Docker).is_some(),
            uid == 0 || cfg!(target_os = "macos")
        );

        fs::set_permissions(&executable, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(trusted_executable(&executable, Tool::Docker).is_none());
    }
}
