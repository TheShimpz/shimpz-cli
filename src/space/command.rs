//! Fixed host command boundary for Local Space operations.

use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use crate::capture;

/// The most output a fixed host tool may return on either stream before it is stopped.
const MAX_HOST_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

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
    Timeout,
    Umount,
}

/// How long one call of a quick host tool may run: a mount, unit, or metadata query answers in well under a second, so
/// two minutes leaves a loaded or waking host ample room while a wedged tool can no longer hold the lifecycle lock.
const QUICK_TOOL_BUDGET: Duration = Duration::from_mins(2);
/// How long one LUKS or filesystem operation may run: Argon2 key derivation and formatting take seconds.
const STORAGE_TOOL_BUDGET: Duration = Duration::from_mins(5);
/// How long `timeout` waits after its terminate signal before it kills a privileged tool.
const PRIVILEGED_KILL_AFTER: Duration = Duration::from_secs(5);
/// How long past a privileged tool's own deadline this process waits for `sudo` before reporting it may remain.
const PRIVILEGED_REAP_MARGIN: Duration = Duration::from_mins(1);
/// The exit statuses `timeout` reports when it terminated (124) or killed (128 + 9) the tool it ran.
const PRIVILEGED_TIMED_OUT: [i32; 2] = [124, 137];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostOs {
    MacOs,
    Other,
}

#[derive(Debug, Eq, PartialEq)]
enum Candidate {
    Absent,
    Refused(&'static str),
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
            Self::Timeout => &["/usr/bin/timeout", "/bin/timeout"],
            Self::Umount => &["/usr/bin/umount", "/bin/umount"],
        }
    }

    /// The longest one call of this tool may run before it is stopped.
    pub(crate) fn budget(self) -> Duration {
        match self {
            Self::Luks | Self::MkfsExt4 => STORAGE_TOOL_BUDGET,
            _ => QUICK_TOOL_BUDGET,
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
            Candidate::Refused(reason) => {
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
            return Candidate::Refused("metadata could not be read safely");
        }
        Ok(_) => {}
    }
    let Ok(canonical) = path.canonicalize() else {
        return Candidate::Refused("could not be resolved safely");
    };
    let Ok(metadata) = canonical.metadata() else {
        return Candidate::Refused("metadata could not be read safely");
    };
    if !metadata.is_file() {
        return Candidate::Refused("is not a regular file");
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
            return Candidate::Refused(reason);
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
        Candidate::Absent | Candidate::Refused(_) => None,
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
    let result = bounded(
        &program,
        Command::new(&program).args(arguments),
        tool.budget(),
    )?;
    if !result.status.success() {
        return Err(format!("host command failed: {}", program.display()));
    }
    String::from_utf8(result.stdout).map_err(|_| "host command output was not UTF-8".into())
}

/// Runs one fixed tool with stdin closed and stdout and stderr captured, whatever its exit status.
pub(crate) fn captured<I, S>(tool: Tool, arguments: I) -> Result<Output, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let program = tool.resolve()?;
    bounded(
        &program,
        Command::new(&program).args(arguments),
        tool.budget(),
    )
}

/// Capture at most `MAX_HOST_OUTPUT_BYTES` of each stream from one host tool, stopping it once it outlives `budget`.
fn bounded(program: &Path, command: &mut Command, budget: Duration) -> Result<Output, String> {
    capture::bounded_within(
        command,
        MAX_HOST_OUTPUT_BYTES,
        MAX_HOST_OUTPUT_BYTES,
        budget,
    )
    .map_err(|failure| wait_failure(program, budget, failure))
}

/// The diagnostic of a host command that outlived its deadline.
fn timed_out(program: &Path, budget: Duration, stopped: bool) -> String {
    let outcome = if stopped {
        "it was stopped"
    } else {
        "it could not be stopped and may still be running"
    };
    format!(
        "host command did not finish within {} s; {outcome}: {}",
        budget.as_secs(),
        program.display()
    )
}

pub(crate) fn status<I, S>(tool: Tool, arguments: I) -> Result<ExitStatus, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let program = tool.resolve()?;
    let budget = tool.budget();
    let mut child = capture::spawn(Command::new(&program).args(arguments).stdin(Stdio::null()))
        .map_err(|error| format!("could not execute {}: {error}", program.display()))?;
    capture::wait(&mut child, Instant::now() + budget)
        .map_err(|failure| wait_failure(&program, budget, failure))
}

/// The diagnostic of a host command whose wait failed: it outlived its deadline or could not be reaped.
fn wait_failure(program: &Path, budget: Duration, failure: capture::Failure) -> String {
    match failure {
        capture::Failure::TimedOut { stopped } => timed_out(program, budget, stopped),
        capture::Failure::Unavailable(error) => {
            format!("could not execute {}: {error}", program.display())
        }
        capture::Failure::Excessive => format!(
            "host command output exceeded its bound: {}",
            program.display()
        ),
    }
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
    let mut child = capture::spawn(command.args(arguments).stdin(Stdio::null()))
        .map_err(|error| format!("could not execute {}: {error}", program.display()))?;
    let status = capture::wait(&mut child, privileged_reap_deadline(tool))
        .map_err(|failure| wait_failure(&program, tool.budget(), failure))?;
    privileged_outcome(&program, tool, status)
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
    let mut child = capture::spawn(
        command
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )
    .map_err(|error| format!("could not execute {}: {error}", program.display()))?;
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| "privileged command input is unavailable".to_owned())
        .and_then(|mut stdin| {
            stdin
                .write_all(input)
                .map_err(|_| "privileged command input failed".to_owned())
        });
    let status = capture::wait(&mut child, privileged_reap_deadline(tool))
        .map_err(|failure| wait_failure(&program, tool.budget(), failure))?;
    write_result?;
    privileged_outcome(&program, tool, status)
}

pub(crate) fn privileged_output<I, S>(tool: Tool, arguments: I) -> Result<String, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let (program, mut command) = privileged_command(tool)?;
    let budget = privileged_reap_deadline(tool).saturating_duration_since(Instant::now());
    let result = bounded(&program, command.args(arguments), budget)?;
    let status = privileged_outcome(&program, tool, result.status)?;
    if !status.success() {
        return Err(format!(
            "privileged host command failed: {}",
            program.display()
        ));
    }
    String::from_utf8(result.stdout).map_err(|_| "host command output was not UTF-8".into())
}

/// A privileged tool runs under `timeout` as root, which alone may signal it: past its budget `timeout` terminates
/// it, kills it after a grace, and exits only once it ended, so a deadline never leaves it running behind `sudo`.
fn privileged_command(tool: Tool) -> Result<(PathBuf, Command), String> {
    let program = tool.resolve()?;
    let deadline = Tool::Timeout.resolve()?;
    let mut command = if effective_root() {
        Command::new(&deadline)
    } else {
        let sudo = Tool::Sudo.resolve()?;
        let mut command = Command::new(sudo);
        command.arg("--non-interactive").arg(&deadline);
        command
    };
    command
        .arg(format!("--kill-after={}s", PRIVILEGED_KILL_AFTER.as_secs()))
        .arg(format!("{}s", tool.budget().as_secs()))
        .arg(&program);
    Ok((program, command))
}

/// The moment past which this process stops waiting for a privileged tool that `timeout` should already have ended.
fn privileged_reap_deadline(tool: Tool) -> Instant {
    Instant::now() + tool.budget() + PRIVILEGED_KILL_AFTER + PRIVILEGED_REAP_MARGIN
}

/// The privileged tool's own status, or the refusal of one `timeout` stopped at its deadline.
fn privileged_outcome(
    program: &Path,
    tool: Tool,
    status: ExitStatus,
) -> Result<ExitStatus, String> {
    if status
        .code()
        .is_some_and(|code| PRIVILEGED_TIMED_OUT.contains(&code))
    {
        Err(timed_out(program, tool.budget(), true))
    } else {
        Ok(status)
    }
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

    /// Host tool output was once read without any bound; each stream now stops the tool one byte past its bound.
    #[cfg(unix)]
    #[test]
    fn host_tool_output_is_bounded_on_each_stream() {
        let shell = Path::new("/bin/sh");
        let run = |script: String| {
            bounded(
                shell,
                Command::new(shell).args(["-c", &script]),
                Duration::from_mins(1),
            )
        };
        let exact = run(format!("head -c {MAX_HOST_OUTPUT_BYTES} /dev/zero")).unwrap();
        assert_eq!(exact.stdout.len(), MAX_HOST_OUTPUT_BYTES);
        for redirect in ["", " >&2"] {
            let error = run(format!(
                "head -c {} /dev/zero{redirect}",
                MAX_HOST_OUTPUT_BYTES + 1
            ))
            .unwrap_err();
            assert_eq!(error, "host command output exceeded its bound: /bin/sh");
        }
    }

    /// Every production host tool.
    const TOOLS: [Tool; 14] = [
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
        Tool::Timeout,
        Tool::Umount,
    ];

    /// `timeout` ends a privileged tool past its deadline with 124, or 137 once it had to kill it; either is a
    /// refusal naming the deadline, never an ordinary failure the caller could misread.
    #[cfg(unix)]
    #[test]
    fn a_privileged_tool_stopped_at_its_deadline_is_reported_as_timed_out() {
        use std::os::unix::process::ExitStatusExt;

        let program = Path::new("/usr/sbin/cryptsetup");
        for code in [124, 137] {
            assert_eq!(
                privileged_outcome(program, Tool::Luks, ExitStatus::from_raw(code << 8)),
                Err("host command did not finish within 300 s; it was stopped: /usr/sbin/cryptsetup".into())
            );
        }
        for code in [0, 1, 5] {
            let status = ExitStatus::from_raw(code << 8);
            assert_eq!(privileged_outcome(program, Tool::Luks, status), Ok(status));
        }
        assert_eq!(Tool::Mount.budget(), Duration::from_mins(2));
        assert_eq!(Tool::MkfsExt4.budget(), Duration::from_mins(5));
    }

    #[test]
    fn production_tools_have_only_absolute_fixed_candidates() {
        for tool in TOOLS {
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
        for tool in TOOLS.into_iter().filter(|tool| *tool != Tool::Docker) {
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
    fn refused_tool_diagnostic_names_the_fixed_candidate_path() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real");
        let alias = directory.path().join("alias");
        std::fs::create_dir(&real).unwrap();
        symlink(&real, &alias).unwrap();
        let executable = alias.join("docker");
        std::fs::create_dir(&executable).unwrap();

        let error =
            resolve_candidates(Tool::Docker, std::slice::from_ref(&executable)).unwrap_err();
        assert!(error.contains("is not a regular file"));
        assert!(error.contains(&executable.display().to_string()));
        assert!(!error.contains(&real.join("docker").display().to_string()));
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
