//! Local Docker Engine and atomic release boundary.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use super::command::Tool;
use super::host::HostProfile;
use super::paths::Paths;
use super::release::{self, RELEASE_REPOSITORY, Release};

const RELEASE_CHANNEL: &str = "stable";
const MAX_DOCKER_DIAGNOSTIC_BYTES: usize = 32 * 1024;
const TRUNCATED_DIAGNOSTIC: &str = "\n[Docker diagnostic truncated]";

pub(crate) struct Engine {
    docker: PathBuf,
    pub(crate) platform: &'static str,
    pub(crate) cpuset: String,
}

pub(crate) struct ResolvedRelease {
    pub(crate) reference: String,
    pub(crate) metadata: Release,
}

impl Engine {
    pub(crate) fn connect(profile: HostProfile, paths: &Paths) -> Result<Self, String> {
        let docker = Tool::Docker.resolve()?;
        validate_endpoint(&docker, profile, paths)?;
        require_success(
            &docker,
            ["compose", "version"],
            "Docker Compose v2 check failed; run docker compose version as the current user",
        )?;
        require_success(
            &docker,
            ["info"],
            "Docker daemon check failed; start Docker and run docker info as the current user",
        )?;
        let server = output(&docker, ["version", "--format", "{{.Server.Version}}"])?;
        let api = output(&docker, ["version", "--format", "{{.Server.APIVersion}}"])?;
        let compose = output(&docker, ["compose", "version", "--short"])?;
        if !version_at_least(server.trim(), (25, 0, 0)) || !version_at_least(api.trim(), (1, 44, 0))
        {
            return Err(format!(
                "Docker Engine 25.0 or newer with API 1.44 is required (Engine {}, API {})",
                server.trim(),
                api.trim()
            ));
        }
        if !version_at_least(compose.trim(), (2, 20, 2)) {
            return Err(format!(
                "Docker Compose 2.20.2 or newer is required (found {})",
                compose.trim()
            ));
        }
        let processors = output(&docker, ["info", "--format", "{{.NCPU}}"])?
            .trim()
            .parse::<usize>()
            .ok();
        let processors = processors
            .filter(|value| *value > 0)
            .ok_or_else(|| "Docker returned an invalid CPU count".to_owned())?;
        let selected = (processors / 2).max(1);
        let cpuset = if selected == 1 {
            "0".into()
        } else {
            format!("0-{}", selected - 1)
        };
        let platform = match profile {
            HostProfile::Linux | HostProfile::Wsl => "linux/amd64",
            HostProfile::MacOs => "linux/arm64",
        };
        Ok(Self {
            docker,
            platform,
            cpuset,
        })
    }

    pub(crate) fn resolve_release(
        &self,
        exact: Option<&str>,
        temporary: &Path,
    ) -> Result<ResolvedRelease, String> {
        let selector = match exact {
            Some(reference) if release::valid_release_ref(reference) => reference.to_owned(),
            Some(_) => return Err("the internal Local release reference is invalid".into()),
            None => format!("{RELEASE_REPOSITORY}:{RELEASE_CHANNEL}"),
        };
        self.pull(&selector)?;
        let reference = if exact.is_some() {
            selector
        } else {
            self.unique_repo_digest(&selector, RELEASE_REPOSITORY)?
        };
        if !release::valid_release_ref(&reference) {
            return Err("Docker resolved an invalid Local release digest".into());
        }
        let metadata_path = temporary.join("release.env.tmp");
        let container = self.create(&reference, ["/release.env"])?;
        let copied = self.run_quiet_status(
            "Docker release metadata copy",
            [
                OsString::from("cp"),
                OsString::from(format!("{container}:/release.env")),
                metadata_path.as_os_str().to_owned(),
            ],
        );
        let removed = self.run_quiet_status(
            "Docker temporary container cleanup",
            [OsString::from("rm"), OsString::from(&container)],
        );
        if !copied?.success() || !removed?.success() {
            return Err("the Local release metadata could not be extracted cleanly".into());
        }
        let document = fs::read_to_string(&metadata_path)
            .map_err(|error| format!("could not read Local release metadata: {error}"))?;
        fs::remove_file(metadata_path)
            .map_err(|error| format!("could not remove temporary release metadata: {error}"))?;
        Ok(ResolvedRelease {
            reference,
            metadata: release::parse(&document)?,
        })
    }

    pub(crate) fn extract_cli(
        &self,
        release_ref: &str,
        profile: HostProfile,
        target: &Path,
    ) -> Result<(), String> {
        if !release::valid_release_ref(release_ref) {
            return Err("the Local release reference is invalid".into());
        }
        let member = match profile {
            HostProfile::Linux | HostProfile::Wsl => "/cli/x86_64-unknown-linux-musl/shimpz",
            HostProfile::MacOs => "/cli/aarch64-apple-darwin/shimpz",
        };
        let container = self.create(release_ref, [member])?;
        let copied = self.run_quiet_status(
            "Docker CLI copy",
            [
                OsString::from("cp"),
                OsString::from(format!("{container}:{member}")),
                target.as_os_str().to_owned(),
            ],
        );
        let removed = self.run_quiet_status(
            "Docker temporary container cleanup",
            [OsString::from("rm"), OsString::from(&container)],
        );
        if !copied?.success() || !removed?.success() {
            return Err("the release-bound CLI could not be extracted cleanly".into());
        }
        Ok(())
    }

    pub(crate) fn pull_exact(&self, reference: &str, repository: &str) -> Result<(), String> {
        if !valid_image_ref(reference, repository) {
            return Err("a release component image reference is invalid".into());
        }
        self.pull(reference)?;
        let actual = self.unique_repo_digest(reference, repository)?;
        if actual == reference {
            Ok(())
        } else {
            Err("Docker did not preserve the pinned component digest".into())
        }
    }

    #[cfg(unix)]
    pub(crate) fn controller_socket(
        &self,
        profile: HostProfile,
        team_image: &str,
    ) -> Result<(PathBuf, u32), String> {
        let path = controller_socket_path(profile);
        let mount = format!("type=bind,src={},dst=/var/run/docker.sock", path.display());
        let gid = match profile {
            HostProfile::MacOs => {
                let value = self
                    .run_output(socket_probe_arguments(
                    self.platform,
                    &self.cpuset,
                    &mount,
                    team_image,
                    None,
                    "import os,stat; metadata=os.stat('/var/run/docker.sock'); assert stat.S_ISSOCK(metadata.st_mode); print(metadata.st_gid)",
                ))
                    .map_err(|error| {
                        format!("the Team controller Docker socket identity probe failed: {error}")
                    })?;
                one_line(&value, "Docker socket group")?
                    .parse::<u32>()
                    .map_err(|_| "Docker returned an invalid Docker socket group".to_owned())?
            }
            HostProfile::Linux | HostProfile::Wsl => path
                .symlink_metadata()
                .ok()
                .filter(|metadata| metadata.file_type().is_socket())
                .map(|metadata| metadata.gid())
                .ok_or_else(|| {
                    "the Team controller cannot access the local Docker socket".to_owned()
                })?,
        };
        let script = "import socket; c=socket.socket(socket.AF_UNIX); c.settimeout(5); c.connect('/var/run/docker.sock'); c.sendall(b'GET /_ping HTTP/1.0\\r\\nHost: docker\\r\\n\\r\\n'); s=c.recv(128).split(b'\\r\\n',1)[0]; c.close(); raise SystemExit(0 if s in {b'HTTP/1.0 200 OK',b'HTTP/1.1 200 OK'} else 1)";
        let status = self.run_quiet_status(
            "Team controller Docker socket access probe",
            socket_probe_arguments(
                self.platform,
                &self.cpuset,
                &mount,
                team_image,
                Some(gid),
                script,
            ),
        )?;
        if status.success() {
            return Ok((path.into(), gid));
        }
        Err("the Team controller cannot access the local Docker socket".into())
    }

    pub(crate) fn compose<I, S>(&self, paths: &Paths, arguments: I) -> Result<ExitStatus, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new(&self.docker);
        command
            .arg("compose")
            .arg("--project-directory")
            .arg(&paths.home)
            .arg("--env-file")
            .arg(&paths.environment)
            .arg("--file")
            .arg(&paths.compose)
            .args(arguments)
            .stdin(Stdio::null());
        quiet_status(&mut command, "Docker Compose")
    }

    pub(crate) fn project_release_status(
        &self,
        admin_image: &str,
        document: &[u8],
    ) -> Result<(), String> {
        if !valid_image_ref(admin_image, "ghcr.io/theshimpz/shimpz-admin") || document.len() > 1_024
        {
            return Err("the Local release status projection is invalid".into());
        }
        let volume = "shimpz-space_release_status";
        let identity = self.run_output([
            "volume",
            "inspect",
            "--format",
            "{{.Name}}|{{index .Labels \"com.docker.compose.project\"}}|{{index .Labels \"com.docker.compose.volume\"}}",
            volume,
        ])?;
        if identity.trim() != "shimpz-space_release_status|shimpz-space|release_status" {
            return Err("the Local release status volume is not owned by this Space".into());
        }
        let mount = format!("type=volume,src={volume},dst=/run/shimpz-local-release,volume-nocopy");
        let arguments =
            status_projection_arguments(self.platform, &self.cpuset, &mount, admin_image);
        let mut child = Command::new(&self.docker)
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .map_err(|error| format!("could not execute Docker: {error}"))?;
        child
            .stdin
            .take()
            .ok_or_else(|| "Docker status input is unavailable".to_owned())?
            .write_all(document)
            .map_err(|_| "the Local release status could not be sent to Docker".to_owned())?;
        if child
            .wait()
            .map_err(|error| format!("could not execute Docker: {error}"))?
            .success()
        {
            Ok(())
        } else {
            Err("the Local release status could not be projected to Admin".into())
        }
    }

    pub(crate) fn run_output<I, S>(&self, arguments: I) -> Result<String, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        output(&self.docker, arguments)
    }

    pub(crate) fn run_quiet_status<I, S>(
        &self,
        operation: &str,
        arguments: I,
    ) -> Result<ExitStatus, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new(&self.docker);
        command.args(arguments).stdin(Stdio::null());
        quiet_status(&mut command, operation)
    }

    pub(crate) fn stop_containers(&self, containers: &[String]) -> Result<(), String> {
        if containers.is_empty() {
            return Ok(());
        }
        let mut arguments = vec![
            OsString::from("stop"),
            OsString::from("--time"),
            OsString::from("30"),
        ];
        arguments.extend(containers.iter().map(OsString::from));
        if self
            .run_quiet_status("Docker managed container stop", arguments)?
            .success()
        {
            Ok(())
        } else {
            Err("could not stop every managed Local container".into())
        }
    }

    fn pull(&self, reference: &str) -> Result<(), String> {
        let result = self.run_quiet_status(
            "Docker image download",
            ["pull", "--quiet", "--platform", self.platform, reference],
        )?;
        if result.success() {
            Ok(())
        } else {
            Err(format!(
                "Docker could not pull the pinned image: {reference}"
            ))
        }
    }

    fn create<I, S>(&self, reference: &str, command: I) -> Result<String, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut arguments = vec![
            OsString::from("create"),
            OsString::from("--platform"),
            OsString::from(self.platform),
            OsString::from(reference),
        ];
        arguments.extend(command.into_iter().map(|value| value.as_ref().to_owned()));
        one_line(&self.run_output(arguments)?, "temporary Docker container")
    }

    fn unique_repo_digest(&self, image: &str, repository: &str) -> Result<String, String> {
        let document = self.run_output([
            "image",
            "inspect",
            "--format",
            "{{json .RepoDigests}}",
            image,
        ])?;
        let digests: Vec<String> = serde_json::from_str(document.trim())
            .map_err(|_| "Docker returned malformed image digests".to_owned())?;
        let mut matching = digests
            .into_iter()
            .filter(|value| valid_image_ref(value, repository));
        let first = matching
            .next()
            .ok_or_else(|| "Docker returned no repository digest".to_owned())?;
        if matching.next().is_some() {
            return Err("Docker returned ambiguous repository digests".into());
        }
        Ok(first)
    }
}

#[cfg(unix)]
fn controller_socket_path(profile: HostProfile) -> &'static Path {
    match profile {
        HostProfile::MacOs => Path::new("/var/run/docker.sock.raw"),
        HostProfile::Linux | HostProfile::Wsl => Path::new("/var/run/docker.sock"),
    }
}

#[cfg(unix)]
fn socket_probe_arguments(
    platform: &str,
    cpuset: &str,
    mount: &str,
    team_image: &str,
    gid: Option<u32>,
    script: &str,
) -> Vec<OsString> {
    let mut arguments = [
        "run",
        "--rm",
        "--platform",
        platform,
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    if let Some(gid) = gid {
        arguments.extend([
            OsString::from("--group-add"),
            OsString::from(gid.to_string()),
        ]);
    }
    arguments.extend(
        [
            "--cpuset-cpus",
            cpuset,
            "--cpus",
            "0.25",
            "--memory",
            "64m",
            "--memory-swap",
            "64m",
            "--pids-limit",
            "32",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=8m",
            "--mount",
            mount,
            "--entrypoint",
            "/opt/venv/bin/python",
            team_image,
            "-c",
            script,
        ]
        .into_iter()
        .map(OsString::from),
    );
    arguments
}

fn status_projection_arguments(
    platform: &str,
    cpuset: &str,
    mount: &str,
    admin_image: &str,
) -> Vec<OsString> {
    let script = "import json,os,sys; raw=sys.stdin.buffer.read(1025); document=json.loads(raw); assert len(raw)<=1024 and set(document)=={'release','ordinal','checked_at','outcome'}; target='/run/shimpz-local-release/status.json'; temporary=target+'.tmp'; descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600); assert os.write(descriptor,raw)==len(raw); os.fchmod(descriptor,0o600); os.close(descriptor); os.replace(temporary,target)";
    [
        "run",
        "--rm",
        "--interactive",
        "--platform",
        platform,
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--user",
        "1000:1000",
        "--cpuset-cpus",
        cpuset,
        "--cpus",
        "0.25",
        "--memory",
        "64m",
        "--memory-swap",
        "64m",
        "--pids-limit",
        "32",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=8m",
        "--mount",
        mount,
        "--entrypoint",
        "/opt/venv/bin/python",
        admin_image,
        "-c",
        script,
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn validate_endpoint(docker: &Path, profile: HostProfile, paths: &Paths) -> Result<(), String> {
    let configured = std::env::var_os("DOCKER_HOST");
    if profile != HostProfile::Linux && configured.is_some() {
        return Err("DOCKER_HOST cannot select the managed Local Docker engine".into());
    }
    let (context, endpoint) = if let Some(configured) = configured {
        (
            None,
            configured
                .into_string()
                .map_err(|_| "DOCKER_HOST is invalid".to_owned())?,
        )
    } else {
        let context = one_line(&output(docker, ["context", "show"])?, "Docker context")?;
        let endpoint = one_line(
            &output(
                docker,
                [
                    "context",
                    "inspect",
                    "--format",
                    "{{.Endpoints.docker.Host}}",
                    &context,
                ],
            )?,
            "Docker endpoint",
        )?;
        (Some(context), endpoint)
    };
    let socket = endpoint
        .strip_prefix("unix://")
        .filter(|path| Path::new(path).is_absolute())
        .ok_or_else(|| "a local Docker Unix socket is required".to_owned())?;
    if Path::new(socket)
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err("the Docker socket path is invalid".into());
    }
    if profile != HostProfile::Linux {
        let user_home = paths
            .home
            .parent()
            .ok_or_else(|| "the user home is invalid".to_owned())?;
        validate_managed_endpoint(profile, user_home, context.as_deref(), &endpoint)?;
    }
    Ok(())
}

fn validate_managed_endpoint(
    profile: HostProfile,
    user_home: &Path,
    context: Option<&str>,
    endpoint: &str,
) -> Result<(), String> {
    let expected = match profile {
        HostProfile::MacOs => (
            "desktop-linux",
            format!("unix://{}/.docker/run/docker.sock", user_home.display()),
        ),
        HostProfile::Wsl => ("default", "unix:///var/run/docker.sock".to_owned()),
        HostProfile::Linux => return Err("the managed Docker profile is invalid".into()),
    };
    if context == Some(expected.0) && endpoint == expected.1 {
        Ok(())
    } else {
        Err("the managed Local profile requires Docker Desktop's default engine".into())
    }
}

fn require_success<I, S>(program: &Path, arguments: I, message: &str) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let result = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("could not execute Docker: {error}"))?;
    if result.success() {
        Ok(())
    } else {
        Err(format!("{message}; Docker returned {result}"))
    }
}

fn quiet_status(command: &mut Command, operation: &str) -> Result<ExitStatus, String> {
    let (status, diagnostic) = execute_quiet(command)?;
    if !status.success() {
        let detail = if diagnostic.is_empty() {
            String::new()
        } else {
            format!(": {diagnostic}")
        };
        crate::output::warning(&format!(
            "{operation} failed; Docker returned {status}{detail}"
        ));
    }
    Ok(status)
}

fn execute_quiet(command: &mut Command) -> Result<(ExitStatus, String), String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not execute Docker: {error}"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "Docker diagnostic output is unavailable".to_owned())?;
    let captured = drain_diagnostic(stderr);
    let status = child
        .wait()
        .map_err(|error| format!("could not execute Docker: {error}"))?;
    let captured = captured?;
    let diagnostic = render_diagnostic(&captured);
    Ok((status, diagnostic))
}

struct CapturedDiagnostic {
    bytes: Vec<u8>,
    truncated: bool,
}

fn drain_diagnostic(mut reader: impl Read) -> Result<CapturedDiagnostic, String> {
    let mut bytes = Vec::with_capacity(MAX_DOCKER_DIAGNOSTIC_BYTES);
    let mut truncated = false;
    let mut buffer = [0_u8; 4096];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| "Docker diagnostic output could not be read".to_owned())?;
        if count == 0 {
            break;
        }
        let retained = count.min(MAX_DOCKER_DIAGNOSTIC_BYTES.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&buffer[..retained]);
        truncated |= retained < count;
    }
    Ok(CapturedDiagnostic { bytes, truncated })
}

fn render_diagnostic(captured: &CapturedDiagnostic) -> String {
    let decoded = String::from_utf8_lossy(&captured.bytes);
    let sanitized = crate::output::sanitize(decoded.trim());
    let content_limit = MAX_DOCKER_DIAGNOSTIC_BYTES - TRUNCATED_DIAGNOSTIC.len();
    let mut rendered = String::with_capacity(sanitized.len().min(content_limit));
    let mut truncated = captured.truncated;
    for character in sanitized.chars() {
        if rendered.len() + character.len_utf8() > content_limit {
            truncated = true;
            break;
        }
        rendered.push(character);
    }
    if truncated {
        rendered.push_str(TRUNCATED_DIAGNOSTIC);
    }
    rendered
}

fn output<I, S>(program: &Path, arguments: I) -> Result<String, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let result = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("could not execute Docker: {error}"))?;
    if !result.status.success() {
        return Err(format!(
            "Docker operation failed; Docker returned {}",
            result.status
        ));
    }
    String::from_utf8(result.stdout).map_err(|_| "Docker returned non-UTF-8 output".into())
}

fn one_line(value: &str, label: &str) -> Result<String, String> {
    let mut lines = value.lines();
    let line = lines.next().filter(|line| !line.is_empty());
    if line.is_none() || lines.next().is_some() {
        return Err(format!("{label} is malformed"));
    }
    Ok(line.expect("checked").to_owned())
}

fn valid_image_ref(value: &str, repository: &str) -> bool {
    value
        .strip_prefix(repository)
        .and_then(|suffix| suffix.strip_prefix("@sha256:"))
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn version_at_least(value: &str, minimum: (u64, u64, u64)) -> bool {
    let core = value
        .trim_start_matches('v')
        .split(['-', '+'])
        .next()
        .unwrap_or_default();
    let mut components = core.split('.');
    let major = components.next().and_then(|value| value.parse().ok());
    let minor = components.next().and_then(|value| value.parse().ok());
    let patch = components
        .next()
        .map_or(Some(0), |value| value.parse().ok());
    if components.next().is_some() {
        return false;
    }
    major
        .zip(minor)
        .zip(patch)
        .is_some_and(|((major, minor), patch)| (major, minor, patch) >= minimum)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn validates_versions_without_accepting_junk() {
        assert!(version_at_least("25.0.0", (25, 0, 0)));
        assert!(version_at_least("v25.1.0-desktop.1", (25, 0, 0)));
        assert!(!version_at_least("24.9.9", (25, 0, 0)));
        assert!(!version_at_least("25", (25, 0, 0)));
        assert!(!version_at_least("25.0.0.1", (25, 0, 0)));
        assert!(!version_at_least("not-a-version", (25, 0, 0)));
    }

    #[test]
    fn managed_profiles_accept_only_their_default_docker_desktop_socket() {
        let home = Path::new("/Users/ada");
        assert!(
            validate_managed_endpoint(
                HostProfile::MacOs,
                home,
                Some("desktop-linux"),
                "unix:///Users/ada/.docker/run/docker.sock"
            )
            .is_ok()
        );
        assert!(
            validate_managed_endpoint(
                HostProfile::Wsl,
                Path::new("/home/ada"),
                Some("default"),
                "unix:///var/run/docker.sock"
            )
            .is_ok()
        );
        for (profile, context, endpoint) in [
            (
                HostProfile::MacOs,
                Some("default"),
                "unix:///Users/ada/.docker/run/docker.sock",
            ),
            (
                HostProfile::MacOs,
                Some("desktop-linux"),
                "unix:///tmp/docker.sock",
            ),
            (
                HostProfile::Wsl,
                Some("custom"),
                "unix:///var/run/docker.sock",
            ),
        ] {
            assert!(validate_managed_endpoint(profile, home, context, endpoint).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn macos_controller_uses_the_desktop_vm_socket_identity() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let command = temporary.path().join("docker");
        let calls = temporary.path().join("calls");
        fs::write(
            &command,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$*\" in *'print(metadata.st_gid)'*) printf '0\\n' ;; esac\n",
                calls.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&command, fs::Permissions::from_mode(0o700)).unwrap();
        let engine = Engine {
            docker: command,
            platform: "linux/arm64",
            cpuset: "0".into(),
        };
        let image = format!("ghcr.io/theshimpz/shimpz-team-local@sha256:{DIGEST}");

        let (socket, gid) = engine
            .controller_socket(HostProfile::MacOs, &image)
            .unwrap();

        assert_eq!(socket, Path::new("/var/run/docker.sock.raw"));
        assert_eq!(gid, 0);
        let arguments = fs::read_to_string(calls).unwrap();
        let mut invocations = arguments.lines();
        let identity = invocations.next().unwrap();
        assert!(identity.contains("src=/var/run/docker.sock.raw"));
        assert!(!identity.contains("--group-add"));
        let access = invocations.next().unwrap();
        assert!(access.contains("src=/var/run/docker.sock.raw"));
        assert!(access.contains("--group-add 0"));
        assert!(invocations.next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn macos_controller_names_a_failed_socket_identity_probe() {
        let engine = Engine {
            docker: PathBuf::from("/bin/false"),
            platform: "linux/arm64",
            cpuset: "0".into(),
        };
        let image = format!("ghcr.io/theshimpz/shimpz-team-local@sha256:{DIGEST}");

        let error = engine
            .controller_socket(HostProfile::MacOs, &image)
            .unwrap_err();

        assert_eq!(
            error,
            "the Team controller Docker socket identity probe failed: Docker operation failed; Docker returned exit status: 1"
        );
    }

    #[cfg(unix)]
    #[test]
    fn macos_controller_rejects_a_malformed_socket_group() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let command = temporary.path().join("docker");
        fs::write(&command, "#!/bin/sh\nprintf 'not-a-group\\n'\n").unwrap();
        fs::set_permissions(&command, fs::Permissions::from_mode(0o700)).unwrap();
        let engine = Engine {
            docker: command,
            platform: "linux/arm64",
            cpuset: "0".into(),
        };
        let image = format!("ghcr.io/theshimpz/shimpz-team-local@sha256:{DIGEST}");

        let error = engine
            .controller_socket(HostProfile::MacOs, &image)
            .unwrap_err();

        assert_eq!(error, "Docker returned an invalid Docker socket group");
    }

    #[cfg(unix)]
    #[test]
    fn socket_probe_arguments_preserve_the_security_boundary() {
        let arguments = socket_probe_arguments(
            "linux/arm64",
            "0-1",
            "type=bind,src=/var/run/docker.sock.raw,dst=/var/run/docker.sock",
            &format!("ghcr.io/theshimpz/shimpz-team-local@sha256:{DIGEST}"),
            Some(0),
            "pass",
        );
        let pairs = [
            ("--platform", "linux/arm64"),
            ("--pull", "never"),
            ("--network", "none"),
            ("--cap-drop", "ALL"),
            ("--security-opt", "no-new-privileges:true"),
            ("--group-add", "0"),
            ("--cpus", "0.25"),
            ("--memory", "64m"),
            ("--memory-swap", "64m"),
            ("--pids-limit", "32"),
            ("--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=8m"),
        ];

        assert_eq!(arguments.first(), Some(&OsString::from("run")));
        assert!(arguments.iter().any(|argument| argument == "--rm"));
        assert!(arguments.iter().any(|argument| argument == "--read-only"));
        for (option, value) in pairs {
            assert!(
                arguments
                    .windows(2)
                    .any(|pair| pair[0] == option && pair[1] == value)
            );
        }
        assert!(arguments.windows(2).any(|pair| {
            pair[0] == "--mount"
                && pair[1] == "type=bind,src=/var/run/docker.sock.raw,dst=/var/run/docker.sock"
        }));
        assert!(
            arguments
                .windows(2)
                .any(|pair| { pair[0] == "--entrypoint" && pair[1] == "/opt/venv/bin/python" })
        );
    }

    #[cfg(unix)]
    #[test]
    fn failed_docker_check_names_the_command_evidence_without_classifying_it() {
        let program = Path::new("/bin/sh");
        let error = require_success(
            program,
            ["-c", "exit 7"],
            "Docker daemon check failed; run docker info as the current user",
        )
        .unwrap_err();

        assert_eq!(
            error,
            "Docker daemon check failed; run docker info as the current user; Docker returned exit status: 7"
        );
    }

    #[cfg(unix)]
    #[test]
    fn quiet_success_captures_without_emitting_child_output() {
        let stdout = tempfile::NamedTempFile::new().unwrap();
        let stderr = tempfile::NamedTempFile::new().unwrap();
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "printf 'unexpected stdout'; printf 'unexpected stderr' >&2",
            ])
            .stdout(Stdio::from(stdout.reopen().unwrap()))
            .stderr(Stdio::from(stderr.reopen().unwrap()));

        let (status, diagnostic) = execute_quiet(&mut command).unwrap();

        assert!(status.success());
        assert_eq!(diagnostic, "unexpected stderr");
        assert_eq!(stdout.as_file().metadata().unwrap().len(), 0);
        assert_eq!(stderr.as_file().metadata().unwrap().len(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn quiet_failure_retains_a_sanitized_diagnostic() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf 'failed\\033[2J' >&2; exit 7"]);

        let (status, diagnostic) = execute_quiet(&mut command).unwrap();

        assert_eq!(status.code(), Some(7));
        assert!(diagnostic.contains("failed�[2J"));
        assert!(!diagnostic.contains('\u{1b}'));
    }

    #[test]
    fn diagnostic_capture_drains_and_bounds_excess_output() {
        let mut payload = vec![b'x'; MAX_DOCKER_DIAGNOSTIC_BYTES + 4096];
        payload[0] = b'\x1b';
        let mut source = std::io::Cursor::new(payload);

        let captured = drain_diagnostic(&mut source).unwrap();
        let rendered = render_diagnostic(&captured);

        assert_eq!(source.position(), MAX_DOCKER_DIAGNOSTIC_BYTES as u64 + 4096);
        assert_eq!(captured.bytes.len(), MAX_DOCKER_DIAGNOSTIC_BYTES);
        assert!(captured.truncated);
        assert!(rendered.len() <= MAX_DOCKER_DIAGNOSTIC_BYTES);
        assert!(rendered.ends_with(TRUNCATED_DIAGNOSTIC));
        assert!(!rendered.contains('\u{1b}'));
    }

    #[test]
    fn accepts_only_exact_repository_digest_references() {
        assert!(valid_image_ref(
            &format!("ghcr.io/theshimpz/shimpz-admin@sha256:{DIGEST}"),
            "ghcr.io/theshimpz/shimpz-admin"
        ));
        assert!(!valid_image_ref(
            &format!("example.invalid/admin@sha256:{DIGEST}"),
            "ghcr.io/theshimpz/shimpz-admin"
        ));
        assert!(!valid_image_ref(
            "ghcr.io/theshimpz/shimpz-admin:stable",
            "ghcr.io/theshimpz/shimpz-admin"
        ));
    }

    #[test]
    fn static_status_projection_preserves_owned_volume_and_requests_stdin_without_a_tty() {
        let arguments = status_projection_arguments(
            "linux/amd64",
            "0-3",
            "type=volume,src=release,dst=/run/release,volume-nocopy",
            &format!("ghcr.io/theshimpz/shimpz-admin@sha256:{DIGEST}"),
        );

        assert_eq!(arguments[0], "run");
        assert_eq!(arguments[2], "--interactive");
        assert!(
            arguments.iter().any(
                |argument| argument == "type=volume,src=release,dst=/run/release,volume-nocopy"
            )
        );
        assert!(arguments.iter().all(|argument| argument != "--tty"));
    }
}
