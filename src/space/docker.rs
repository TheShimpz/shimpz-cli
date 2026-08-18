//! Local Docker Engine and atomic release boundary.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use super::command::Tool;
use super::paths::Paths;
use super::release::{self, RELEASE_REPOSITORY, Release};
use super::storage::evidence::HostProfile;

const RELEASE_CHANNEL: &str = "stable";

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
    pub(crate) fn connect(profile: HostProfile) -> Result<Self, String> {
        let docker = Tool::Docker.resolve()?;
        validate_endpoint(&docker)?;
        require_success(
            &docker,
            ["compose", "version"],
            "Docker Compose v2 is required",
        )?;
        require_success(
            &docker,
            ["info"],
            "the Docker daemon is not available to this user",
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
        let copied = self.run_status([
            OsString::from("cp"),
            OsString::from(format!("{container}:/release.env")),
            metadata_path.as_os_str().to_owned(),
        ]);
        let removed = self.run_status([OsString::from("rm"), OsString::from(&container)]);
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
        let copied = self.run_status([
            OsString::from("cp"),
            OsString::from(format!("{container}:{member}")),
            target.as_os_str().to_owned(),
        ]);
        let removed = self.run_status([OsString::from("rm"), OsString::from(&container)]);
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
        let candidates: &[&str] = match profile {
            HostProfile::MacOs => &["/var/run/docker.sock.raw", "/var/run/docker.sock"],
            HostProfile::Linux | HostProfile::Wsl => &["/var/run/docker.sock"],
        };
        for candidate in candidates {
            let path = Path::new(candidate);
            let Ok(metadata) = path.symlink_metadata() else {
                continue;
            };
            if !metadata.file_type().is_socket() {
                continue;
            }
            let gid = metadata.gid();
            let mount = format!("type=bind,src={candidate},dst=/var/run/docker.sock");
            let script = "import socket; c=socket.socket(socket.AF_UNIX); c.settimeout(5); c.connect('/var/run/docker.sock'); c.sendall(b'GET /_ping HTTP/1.0\\r\\nHost: docker\\r\\n\\r\\n'); s=c.recv(128).split(b'\\r\\n',1)[0]; c.close(); raise SystemExit(0 if s in {b'HTTP/1.0 200 OK',b'HTTP/1.1 200 OK'} else 1)";
            let status = self.run_status([
                "run",
                "--rm",
                "--platform",
                self.platform,
                "--pull",
                "never",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--group-add",
                &gid.to_string(),
                "--cpuset-cpus",
                &self.cpuset,
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
                &mount,
                "--entrypoint",
                "/opt/venv/bin/python",
                team_image,
                "-c",
                script,
            ])?;
            if status.success() {
                return Ok((path.into(), gid));
            }
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
            .stdin(Stdio::null())
            .status()
            .map_err(|error| format!("could not execute Docker Compose: {error}"))
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
        let mount = format!("type=volume,src={volume},dst=/run/shimpz-local-release");
        let script = "import json,os,sys; raw=sys.stdin.buffer.read(1025); document=json.loads(raw); assert len(raw)<=1024 and set(document)=={'release','ordinal','checked_at','outcome'}; target='/run/shimpz-local-release/status.json'; temporary=target+'.tmp'; descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600); assert os.write(descriptor,raw)==len(raw); os.fchmod(descriptor,0o600); os.close(descriptor); os.replace(temporary,target)";
        let arguments = [
            "run",
            "--rm",
            "--platform",
            self.platform,
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
            &self.cpuset,
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
            &mount,
            "--entrypoint",
            "/opt/venv/bin/python",
            admin_image,
            "-c",
            script,
        ];
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

    pub(crate) fn run_status<I, S>(&self, arguments: I) -> Result<ExitStatus, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        Command::new(&self.docker)
            .args(arguments)
            .stdin(Stdio::null())
            .status()
            .map_err(|error| format!("could not execute Docker: {error}"))
    }

    fn pull(&self, reference: &str) -> Result<(), String> {
        let result =
            self.run_status(["pull", "--quiet", "--platform", self.platform, reference])?;
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

fn validate_endpoint(docker: &Path) -> Result<(), String> {
    let endpoint = if let Some(configured) = std::env::var_os("DOCKER_HOST") {
        configured
            .into_string()
            .map_err(|_| "DOCKER_HOST is invalid".to_owned())?
    } else {
        let context = one_line(&output(docker, ["context", "show"])?, "Docker context")?;
        output(
            docker,
            [
                "context",
                "inspect",
                "--format",
                "{{.Endpoints.docker.Host}}",
                &context,
            ],
        )?
        .trim()
        .to_owned()
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
    Ok(())
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
        Err(message.into())
    }
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
        return Err("Docker operation failed".into());
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
}
