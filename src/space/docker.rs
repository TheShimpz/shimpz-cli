//! Local Docker Engine and atomic release boundary.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{BufRead, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{ChildStdout, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::command::Tool;
use super::graph;
use super::host::HostProfile;
use super::paths::Paths;
#[cfg(unix)]
use super::poll::{self, TeamActivity};
use super::release::{
    self, ADMIN, DEVELOPER_RELEASE_REPOSITORY, EGRESS, Package, RELEASE_REPOSITORY, Release,
};
use crate::capture::{self, Drained};
use crate::digest;

const RELEASE_CHANNEL: &str = "stable";
const MAX_DOCKER_DIAGNOSTIC_BYTES: usize = 32 * 1024;
/// The most output one captured Docker command may return on either stream before it is stopped.
const MAX_DOCKER_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const TRUNCATED_DIAGNOSTIC: &str = "\n[Docker diagnostic truncated]";
const ADMIN_AUTHENTICATION_VOLUME: &str = "shimpz-space_data";
const ADMIN_AUTHENTICATION_OUTPUT_BYTES: usize = 64;
const ADMIN_AUTHENTICATION_ATTEMPTS: usize = 3;
const ADMIN_AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(10);
const RESET_CAPABILITY_VOLUME: &str = "shimpz-space_reset_capability";
/// The CPU quota of every one-shot helper container, inside the Space cpuset. One CPU bounds a helper as firmly as
/// a fraction would, while a quarter-CPU quota stretched each helper's Python start several-fold (the Admin
/// authentication probe from about 2 s to 7 s).
const HELPER_CPUS: &str = "1";
const ACCOUNT_EGRESS: &str = "shimpz-account-egress";
const ACCOUNT_CAPABILITY_TIMEOUT: Duration = Duration::from_secs(10);
/// State, exit code, Compose project, service and configuration hash, image, and the capability mount's source.
const INIT_RECORD_FORMAT: &str = "{{.State.Status}}|{{.State.ExitCode}}|{{index .Config.Labels \"com.docker.compose.project\"}}|{{index .Config.Labels \"com.docker.compose.service\"}}|{{index .Config.Labels \"com.docker.compose.config-hash\"}}|{{.Config.Image}}|{{range .Mounts}}{{if eq .Destination \"/run/shimpz-account-egress\"}}{{.Type}}:{{.Name}}{{end}}{{end}}";
const SPACE_PROJECT: &str = "shimpz-space";
const COMPOSE_UP: [&str; 9] = [
    "up",
    "-d",
    "--wait",
    "--wait-timeout",
    "120",
    "--no-build",
    "--pull",
    "never",
    "--remove-orphans",
];
const RUNTIME_STATE_RESET_CONTAINER: &str = "shimpz-runtime-state-reset";
const RUNTIME_STATE_RESET_KIND: &str = "runtime-state-reset";

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
        // The three engine observations are independent, so they run at once and are judged in this order.
        let (compose, daemon, processors) = thread::scope(|scope| {
            let compose = scope.spawn(|| output(&docker, ["compose", "version", "--short"]));
            // `docker version` fails unless the daemon answers, so one call proves it reachable and reports its
            // versions.
            let daemon = scope.spawn(|| {
                output(
                    &docker,
                    [
                        "version",
                        "--format",
                        "{{.Server.Version}}|{{.Server.APIVersion}}",
                    ],
                )
            });
            let processors = scope.spawn(|| output(&docker, ["info", "--format", "{{.NCPU}}"]));
            let joined = |handle: thread::ScopedJoinHandle<'_, Result<String, String>>| {
                handle
                    .join()
                    .unwrap_or_else(|_| Err("the Docker engine check failed".into()))
            };
            (joined(compose), joined(daemon), joined(processors))
        });
        let compose = compose.map_err(|error| {
            format!(
                "Docker Compose v2 check failed; run docker compose version as the current user; {error}"
            )
        })?;
        let daemon = daemon.map_err(|error| {
            format!(
                "Docker daemon check failed; start Docker and run docker info as the current user; {error}"
            )
        })?;
        require_engine_versions(&daemon, &compose)?;
        let processors = processors?.trim().parse::<usize>().ok();
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
        // A developer release set exists only in this host's image store and is never pulled; an exact published
        // set already present by that digest is content-addressed and needs no download.
        if release::valid_developer_release_ref(&selector) {
            self.require_present(&selector, DEVELOPER_RELEASE_REPOSITORY)?;
        } else if exact.is_none() || !self.present(&selector, RELEASE_REPOSITORY) {
            self.pull(&selector)?;
        }
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
        // The temporary metadata is read, if it was copied, and removed whatever else failed, so no exit leaves it.
        let copied = copied.map(|status| status.success());
        let document = match copied {
            Ok(true) => Some(
                fs::read_to_string(&metadata_path)
                    .map_err(|error| format!("could not read Local release metadata: {error}")),
            ),
            _ => None,
        };
        let cleaned = match fs::remove_file(&metadata_path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(format!(
                "could not remove temporary release metadata: {error}"
            )),
            _ => Ok(()),
        };
        let failure = match (copied, removed) {
            (Ok(true), Ok(removed)) if removed.success() => None,
            (Err(error), _) | (_, Err(error)) => Some(error),
            _ => Some("the Local release metadata could not be extracted cleanly".to_owned()),
        };
        if let Some(failure) = failure {
            return Err(match cleaned {
                Ok(()) => failure,
                Err(cleanup) => format!("{failure}; {cleanup}"),
            });
        }
        let document = match (
            document.unwrap_or_else(|| Err("Local release metadata was not copied".into())),
            cleaned,
        ) {
            (Ok(document), Ok(())) => document,
            (Err(error), Ok(())) | (Ok(_), Err(error)) => return Err(error),
            (Err(error), Err(cleanup)) => return Err(format!("{error}; {cleanup}")),
        };
        let state_epoch = self.run_output([
            "image",
            "inspect",
            "--format",
            &format!(
                "{{{{index .Config.Labels \"{}\"}}}}",
                release::STATE_EPOCH_LABEL
            ),
            &reference,
        ])?;
        let metadata = release::parse(&reference, &document, state_epoch.trim_end_matches('\n'))?;
        Ok(ResolvedRelease {
            reference,
            metadata,
        })
    }

    pub(crate) fn extract_cli(
        &self,
        release_ref: &str,
        profile: HostProfile,
        target: &Path,
    ) -> Result<(), String> {
        // A developer release carries only the amd64 Linux CLI and applies only to an amd64 Linux Space.
        let developer = release::valid_developer_release_ref(release_ref);
        if !(release::valid_published_release_ref(release_ref)
            || developer && profile != HostProfile::MacOs)
        {
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

    /// Make one release member available by its exact digest: a developer member must already be in this host's
    /// image store and is never pulled; a published member is pulled unless the store already holds exactly that
    /// digest for this Space's platform, since the digest names the content.
    pub(crate) fn pull_exact(&self, reference: &str, package: Package) -> Result<(), String> {
        let repository = reference.split_once('@').map_or("", |(name, _)| name);
        if package.developer(reference) {
            return self.require_present(reference, repository);
        }
        if !package.published(reference) {
            return Err("a release component image reference is invalid".into());
        }
        if self.present(reference, repository) {
            return Ok(());
        }
        self.pull(reference)?;
        let actual = self.unique_repo_digest(reference, repository)?;
        if actual == reference {
            Ok(())
        } else {
            Err("Docker did not preserve the pinned component digest".into())
        }
    }

    /// Admit a `localhost/` image only when this daemon's store already holds exactly that manifest digest for
    /// this Space's platform. Absence fails closed; nothing is pulled.
    fn require_present(&self, reference: &str, repository: &str) -> Result<(), String> {
        if self.present(reference, repository) {
            Ok(())
        } else {
            Err(format!(
                "the developer release image {reference} is not in the local Docker image store; deploy the change again with .scripts/local-release/deploy, or return to the published release with shimpz update"
            ))
        }
    }

    /// The state epoch an admitted release set declares in its image label.
    pub(crate) fn release_state_epoch(&self, release_ref: &str) -> Result<u32, String> {
        if !release::valid_release_ref(release_ref) {
            return Err("the Local release reference is invalid".into());
        }
        let label = self.run_output([
            "image",
            "inspect",
            "--format",
            &format!(
                "{{{{index .Config.Labels \"{}\"}}}}",
                release::STATE_EPOCH_LABEL
            ),
            release_ref,
        ])?;
        release::parse_state_epoch(label.trim_end_matches('\n'))
    }

    /// Empty exactly the named volumes of this Space, keeping each volume root with its ownership and mode, through
    /// one network-less, read-only container of an image the Space already admitted. Only the container's root may
    /// bypass file permissions, and it can do nothing but delete below the mounted roots.
    pub(crate) fn clear_volumes(&self, image: &str, volumes: &[&str]) -> Result<(), String> {
        if !release::TEAM.admits(image) {
            return Err("the selected Team image reference is invalid".into());
        }
        for volume in volumes {
            let name = format!("{SPACE_PROJECT}_{volume}");
            let identity = self.run_output([
                "volume",
                "inspect",
                "--format",
                "{{.Name}}|{{index .Labels \"com.docker.compose.project\"}}|{{index .Labels \"com.docker.compose.volume\"}}",
                &name,
            ])?;
            if identity.trim_end() != format!("{name}|{SPACE_PROJECT}|{volume}") {
                return Err(format!(
                    "the Local volume {volume} is not owned by this Space"
                ));
            }
        }
        // One fixed name: a helper an interrupted run left behind is removed before another starts, so no earlier
        // deletion can still run while the Space starts again.
        // Only this CLI's own helper is removed; any other occupant of the name is kept and refuses the reset.
        if let Ok(kind) = self.run_output([
            "container",
            "inspect",
            "--format",
            "{{index .Config.Labels \"com.shimpz.local.kind\"}}",
            RUNTIME_STATE_RESET_CONTAINER,
        ]) {
            if kind.trim_end() != RUNTIME_STATE_RESET_KIND {
                return Err(format!(
                    "another container is named {RUNTIME_STATE_RESET_CONTAINER}; it was kept"
                ));
            }
            let removed = self.run_quiet_status(
                "Docker runtime state reset cleanup",
                ["rm", "--force", RUNTIME_STATE_RESET_CONTAINER],
            )?;
            if !removed.success() {
                return Err("an earlier runtime state reset could not be removed".into());
            }
        }
        let arguments = clear_volumes_arguments(
            self.platform,
            &self.cpuset,
            image,
            RUNTIME_STATE_RESET_CONTAINER,
            volumes,
        );
        let status = self.run_quiet_status("Docker runtime state reset", arguments)?;
        if status.success() {
            Ok(())
        } else {
            Err("the Local runtime state could not be recreated".into())
        }
    }

    /// Whether this daemon's store holds exactly `reference` as a repository digest for this Space's platform.
    fn present(&self, reference: &str, repository: &str) -> bool {
        self.run_output([
            "image",
            "inspect",
            "--format",
            "{{json .RepoDigests}}|{{.Os}}/{{.Architecture}}",
            reference,
        ])
        .is_ok_and(|document| image_present(&document, reference, repository, self.platform))
    }

    #[cfg(unix)]
    /// Ask the running Team, through its own authenticated loopback client, whether work is active. Any Docker,
    /// timeout, or protocol failure is `Unknown`.
    pub(crate) fn team_activity(&self, container: &str, timeout: Duration) -> TeamActivity {
        match execute_bounded_stdout(
            Command::new(&self.docker)
                .args([
                    "exec",
                    container,
                    "/opt/venv/bin/python",
                    "-m",
                    "local.activity",
                ])
                .stdin(Stdio::null())
                .stderr(Stdio::null()),
            timeout,
        ) {
            Ok(BoundedOutput::Completed {
                status,
                bytes,
                truncated: false,
            }) if status.success() => poll::parse_team_activity(&bytes),
            _ => TeamActivity::Unknown,
        }
    }

    pub(crate) fn admin_authentication_state(&self, admin_image: &str) -> Result<String, String> {
        if !ADMIN.admits(admin_image) {
            return Err("the selected Admin image reference is invalid".into());
        }
        self.validate_admin_authentication_volume()?;
        let mount = format!(
            "type=volume,src={ADMIN_AUTHENTICATION_VOLUME},dst=/data,volume-nocopy,readonly"
        );
        for attempt in 0..ADMIN_AUTHENTICATION_ATTEMPTS {
            let container = format!(
                "shimpz-admin-authentication-probe-{}-{}",
                std::process::id(),
                attempt + 1
            );
            let arguments = admin_authentication_probe_arguments(
                self.platform,
                &self.cpuset,
                &mount,
                admin_image,
                &container,
            );
            match execute_bounded_stdout(
                Command::new(&self.docker)
                    .args(arguments)
                    .stdin(Stdio::null())
                    .stderr(Stdio::null()),
                ADMIN_AUTHENTICATION_TIMEOUT,
            )? {
                BoundedOutput::Completed {
                    status,
                    bytes,
                    truncated,
                } if status.success() => {
                    if truncated || bytes.len() > ADMIN_AUTHENTICATION_OUTPUT_BYTES {
                        return Err(
                            "the selected Admin returned an invalid authentication-state contract"
                                .into(),
                        );
                    }
                    return String::from_utf8(bytes).map_err(|_| {
                        "the selected Admin returned an invalid authentication-state contract"
                            .into()
                    });
                }
                BoundedOutput::Completed { .. } if attempt + 1 < ADMIN_AUTHENTICATION_ATTEMPTS => {
                    thread::sleep(Duration::from_millis(100));
                }
                BoundedOutput::Completed { .. } => {
                    return Err(
                        "the selected Admin could not inspect the existing Supervisor authentication record"
                            .into(),
                    );
                }
                BoundedOutput::TimedOut => {
                    if !self.remove_authentication_probe(&container)? {
                        return Err(format!(
                            "the selected Admin authentication check timed out and its temporary container could not be removed; run docker rm --force {container}"
                        ));
                    }
                    return Err("the selected Admin authentication check timed out".into());
                }
            }
        }
        unreachable!("the bounded authentication attempts always return")
    }

    fn validate_admin_authentication_volume(&self) -> Result<(), String> {
        let identity = self.run_output([
            "volume",
            "inspect",
            "--format",
            "{{.Name}}|{{index .Labels \"com.docker.compose.project\"}}|{{index .Labels \"com.docker.compose.volume\"}}",
            ADMIN_AUTHENTICATION_VOLUME,
        ])?;
        if identity.trim() == "shimpz-space_data|shimpz-space|data" {
            Ok(())
        } else {
            Err("the Admin data volume is not owned by this Space".into())
        }
    }

    fn remove_authentication_probe(&self, container: &str) -> Result<bool, String> {
        let inspect = Command::new(&self.docker)
            .args(["container", "inspect", container])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| format!("could not execute Docker: {error}"))?;
        if !inspect.success() {
            return Ok(true);
        }
        let removed = Command::new(&self.docker)
            .args(["rm", "--force", container])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| format!("could not execute Docker: {error}"))?;
        Ok(removed.success())
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

    /// Bring the Space up and wait for its health checks, recording when each container reached each state, so an
    /// apply reports how long every recreated container took to start and become healthy. Compose's output is read
    /// in bounded lines: only parsed container states and a bounded diagnostic prefix are kept.
    ///
    /// A full `up` starts an exited one-shot service again and holds every dependent until it exits. When the Account
    /// egress initializer already completed under exactly the candidate configuration, it is left alone: only the
    /// long-running services are brought up, still in their dependency order among themselves.
    pub(crate) fn compose_up(&self, paths: &Paths) -> Result<(ExitStatus, Vec<String>), String> {
        let selection: &[&str] = if self.completed_init_is_current(paths) {
            &graph::LONG_RUNNING_SERVICES
        } else {
            &[]
        };
        let started = Instant::now();
        let mut child = Command::new(&self.docker)
            .arg("compose")
            .arg("--progress")
            .arg("plain")
            .arg("--project-directory")
            .arg(&paths.home)
            .arg("--env-file")
            .arg(&paths.environment)
            .arg("--file")
            .arg(&paths.compose)
            .args(COMPOSE_UP)
            .args(if selection.is_empty() {
                &[][..]
            } else {
                &["--no-deps"][..]
            })
            .args(selection)
            // Progress must reach the stream read below, whatever the caller's environment selects.
            .env("COMPOSE_STATUS_STDOUT", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("could not execute Docker: {error}"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "Docker diagnostic output is unavailable".to_owned())?;
        let read = read_compose_progress(stderr, started);
        let status = child
            .wait()
            .map_err(|error| format!("could not execute Docker: {error}"))?;
        let (timings, diagnostic) = read?;
        if !status.success() {
            crate::output::warning(&format!(
                "Docker Compose failed; Docker returned {status}: {}",
                render_diagnostic(&diagnostic)
            ));
        }
        Ok((status, timings.summary()))
    }

    /// The initializer container exited 0 as this project's initializer, under the configuration hash Compose
    /// derives for it from the candidate files, and the capability it produced still passes its producer's own reader
    /// now, inside the running Account egress of the same image and capability volume. Any other state or any failed
    /// observation runs the initializer again.
    fn completed_init_is_current(&self, paths: &Paths) -> bool {
        let Ok(records) = self.run_output([
            "inspect",
            "--type=container",
            "--format",
            INIT_RECORD_FORMAT,
            graph::ACCOUNT_EGRESS_INIT,
            ACCOUNT_EGRESS,
        ]) else {
            return false;
        };
        let Ok(configuration) = self.run_output([
            OsStr::new("compose"),
            OsStr::new("--project-directory"),
            paths.home.as_os_str(),
            OsStr::new("--env-file"),
            paths.environment.as_os_str(),
            OsStr::new("--file"),
            paths.compose.as_os_str(),
            OsStr::new("config"),
            OsStr::new("--hash"),
            OsStr::new(graph::ACCOUNT_EGRESS_INIT),
        ]) else {
            return false;
        };
        completed_init_matches(&records, &configuration) && self.account_capability_reads()
    }

    /// The Account egress capability reader accepts the current capability. It prints nothing, so the capability
    /// never leaves the container.
    fn account_capability_reads(&self) -> bool {
        matches!(
            execute_bounded_stdout(
                Command::new(&self.docker)
                    .args([
                        "exec",
                        ACCOUNT_EGRESS,
                        "python3",
                        "-c",
                        "import sys; sys.path.insert(0, '/app/account'); import capability; capability.read_capability()",
                    ])
                    .stdin(Stdio::null())
                    .stderr(Stdio::null()),
                ACCOUNT_CAPABILITY_TIMEOUT,
            ),
            Ok(BoundedOutput::Completed {
                status,
                bytes,
                truncated: false,
            }) if status.success() && bytes.is_empty()
        )
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
        if !ADMIN.admits(admin_image) || document.len() > 1_024 {
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

    pub(crate) fn project_reset_capability(
        &self,
        admin_image: &str,
        document: &[u8],
    ) -> Result<(), String> {
        if !ADMIN.admits(admin_image) || document.is_empty() || document.len() > 1_024 {
            return Err("the Local reset capability projection is invalid".into());
        }
        self.validate_reset_capability_volume()?;
        let mount = format!(
            "type=volume,src={RESET_CAPABILITY_VOLUME},dst=/run/shimpz-local-reset,volume-nocopy"
        );
        let arguments = reset_capability_arguments(
            self.platform,
            &self.cpuset,
            &mount,
            admin_image,
            true,
            reset_capability_write_script(),
        );
        let mut child = Command::new(&self.docker)
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .map_err(|error| format!("could not execute Docker: {error}"))?;
        child
            .stdin
            .take()
            .ok_or_else(|| "Docker reset capability input is unavailable".to_owned())?
            .write_all(document)
            .map_err(|_| "the Local reset capability could not be sent to Docker".to_owned())?;
        if child
            .wait()
            .map_err(|error| format!("could not execute Docker: {error}"))?
            .success()
        {
            Ok(())
        } else {
            Err("the Local reset capability could not be projected to Admin".into())
        }
    }

    pub(crate) fn clear_reset_capability(&self, admin_image: &str) -> Result<(), String> {
        if !ADMIN.admits(admin_image) {
            return Err("the Local reset capability cleanup is invalid".into());
        }
        self.validate_reset_capability_volume()?;
        let mount = format!(
            "type=volume,src={RESET_CAPABILITY_VOLUME},dst=/run/shimpz-local-reset,volume-nocopy"
        );
        let arguments = reset_capability_arguments(
            self.platform,
            &self.cpuset,
            &mount,
            admin_image,
            false,
            reset_capability_clear_script(),
        );
        if self
            .run_quiet_status("Docker reset capability cleanup", arguments)?
            .success()
        {
            Ok(())
        } else {
            Err("the Local reset capability could not be removed".into())
        }
    }

    fn validate_reset_capability_volume(&self) -> Result<(), String> {
        let identity = self.run_output([
            "volume",
            "inspect",
            "--format",
            "{{.Name}}|{{index .Labels \"com.docker.compose.project\"}}|{{index .Labels \"com.docker.compose.volume\"}}",
            RESET_CAPABILITY_VOLUME,
        ])?;
        if identity.trim() == "shimpz-space_reset_capability|shimpz-space|reset_capability" {
            Ok(())
        } else {
            Err("the Local reset capability volume is not owned by this Space".into())
        }
    }

    #[cfg(test)]
    pub(crate) fn with_docker(docker: PathBuf) -> Self {
        Self {
            docker,
            platform: "linux/amd64",
            cpuset: "0".into(),
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
        let arguments = stop_arguments(containers);
        if self
            .run_quiet_status("Docker managed container stop", arguments)?
            .success()
        {
            Ok(())
        } else {
            Err("could not stop every managed Local container".into())
        }
    }

    /// Remove stopped containers by id, keeping every volume they mount.
    pub(crate) fn remove_containers(&self, containers: &[String]) -> Result<(), String> {
        if containers.is_empty() {
            return Ok(());
        }
        let mut arguments = vec![OsString::from("rm")];
        arguments.extend(containers.iter().map(OsString::from));
        if self
            .run_quiet_status("Docker replaced container removal", arguments)?
            .success()
        {
            Ok(())
        } else {
            Err("could not remove every replaced Local container".into())
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
        // The image was resolved or admitted just before; a create must never fetch it.
        let mut arguments = vec![
            OsString::from("create"),
            OsString::from("--pull"),
            OsString::from("never"),
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
            .filter(|value| digest::is_pinned(value, repository));
        let first = matching
            .next()
            .ok_or_else(|| "Docker returned no repository digest".to_owned())?;
        if matching.next().is_some() {
            return Err("Docker returned ambiguous repository digests".into());
        }
        Ok(first)
    }
}

fn stop_arguments(containers: &[String]) -> Vec<OsString> {
    // Omitting a timeout lets Docker honor each container's configured StopTimeout.
    let mut arguments = vec![OsString::from("stop")];
    arguments.extend(containers.iter().map(OsString::from));
    arguments
}

#[cfg(unix)]
fn controller_socket_path(profile: HostProfile) -> &'static Path {
    match profile {
        HostProfile::MacOs => Path::new("/var/run/docker.sock.raw"),
        HostProfile::Linux | HostProfile::Wsl => Path::new("/var/run/docker.sock"),
    }
}

/// `records` holds the inspected initializer, then the Account egress, in `INIT_RECORD_FORMAT`; `configuration` is
/// `docker compose config --hash` for the initializer.
fn completed_init_matches(records: &str, configuration: &str) -> bool {
    let Some(hash) = configuration
        .strip_suffix('\n')
        .and_then(|line| line.strip_prefix(graph::ACCOUNT_EGRESS_INIT))
        .and_then(|line| line.strip_prefix(' '))
        .filter(|hash| digest::is_sha256_hex(hash))
    else {
        return false;
    };
    let mut lines = records.split_terminator('\n');
    let (Some(init), Some(egress), None) = (lines.next(), lines.next(), lines.next()) else {
        return false;
    };
    let capability = format!("volume:{SPACE_PROJECT}_account_egress_capability");
    let Some(image) = init
        .strip_prefix(&format!(
            "exited|0|{SPACE_PROJECT}|{}|{hash}|",
            graph::ACCOUNT_EGRESS_INIT
        ))
        .and_then(|rest| rest.strip_suffix(&format!("|{capability}")))
        .filter(|image| EGRESS.admits(image))
    else {
        return false;
    };
    egress
        .strip_prefix(&format!("running|0|{SPACE_PROJECT}|{ACCOUNT_EGRESS}|"))
        .and_then(|rest| rest.split_once('|'))
        .is_some_and(|(egress_hash, rest)| {
            digest::is_sha256_hex(egress_hash) && rest == format!("{image}|{capability}")
        })
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
    let gid = gid.map(|gid| gid.to_string());
    let options = gid
        .as_deref()
        .map_or_else(Vec::new, |gid| vec!["--group-add", gid]);
    python_helper_arguments(
        platform,
        cpuset,
        "64m",
        &options,
        mount,
        team_image,
        &["-c", script],
    )
}

/// One-shot Python helper container: removed on exit, never pulled, offline, with a read-only root, no capabilities,
/// and no privilege gain, inside the Space cpuset with one CPU, `memory` without swap, 32 processes, a
/// non-executable `/tmp`, and exactly one `mount`. `options` holds only the helper's own name, labels, stdin, and
/// identity.
fn python_helper_arguments(
    platform: &str,
    cpuset: &str,
    memory: &str,
    options: &[&str],
    mount: &str,
    image: &str,
    command: &[&str],
) -> Vec<OsString> {
    ["run", "--rm"]
        .into_iter()
        .chain(options.iter().copied())
        .chain([
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
            "--cpuset-cpus",
            cpuset,
            "--cpus",
            HELPER_CPUS,
            "--memory",
            memory,
            "--memory-swap",
            memory,
            "--pids-limit",
            "32",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=8m",
            "--mount",
            mount,
            "--entrypoint",
            "/opt/venv/bin/python",
            image,
        ])
        .chain(command.iter().copied())
        .map(OsString::from)
        .collect()
}

/// The longest Compose progress line kept; anything beyond it on the same line is dropped.
const MAX_COMPOSE_LINE_BYTES: usize = 512;
/// The most containers whose progress is tracked.
const MAX_COMPOSE_CONTAINERS: usize = 64;

/// When each container Compose reported was first started and first healthy, from its plain progress events, which
/// read ` Container <name> <state>`.
#[derive(Default)]
struct ContainerTimings {
    containers: Vec<(String, Option<Duration>, Option<Duration>)>,
}

impl ContainerTimings {
    fn observe(&mut self, elapsed: Duration, line: &str) {
        let mut words = line.split_whitespace();
        let (Some("Container"), Some(name), Some(state), None) =
            (words.next(), words.next(), words.next(), words.next())
        else {
            return;
        };
        let index = match self
            .containers
            .iter()
            .position(|(known, _, _)| known == name)
        {
            Some(index) => index,
            None if self.containers.len() < MAX_COMPOSE_CONTAINERS => {
                self.containers.push((name.to_owned(), None, None));
                self.containers.len() - 1
            }
            None => return,
        };
        let entry = &mut self.containers[index];
        match state {
            "Started" if entry.1.is_none() => entry.1 = Some(elapsed),
            "Healthy" if entry.2.is_none() => entry.2 = Some(elapsed),
            _ => {}
        }
    }

    /// One line per started container: when it started and when it was first healthy, in seconds since `up` began.
    fn summary(&self) -> Vec<String> {
        self.containers
            .iter()
            .filter_map(|(name, started, healthy)| {
                let started = (*started)?;
                Some(match healthy {
                    Some(healthy) => format!(
                        "{name} started at {:.1}s and was healthy at {:.1}s",
                        started.as_secs_f64(),
                        healthy.as_secs_f64()
                    ),
                    None => format!("{name} started at {:.1}s", started.as_secs_f64()),
                })
            })
            .collect()
    }
}

/// Read Compose's progress stream to its end in bounded lines, timing every container event and keeping a bounded
/// diagnostic prefix, marked truncated when anything was dropped.
fn read_compose_progress(
    reader: impl Read,
    started: Instant,
) -> Result<(ContainerTimings, capture::Drained), String> {
    let mut reader = std::io::BufReader::new(reader);
    let mut timings = ContainerTimings::default();
    let mut diagnostic = capture::Drained {
        bytes: Vec::new(),
        truncated: false,
    };
    let mut line = Vec::with_capacity(MAX_COMPOSE_LINE_BYTES);
    loop {
        let available = reader
            .fill_buf()
            .map_err(|_| "Docker Compose progress could not be read".to_owned())?;
        if available.is_empty() {
            break;
        }
        let consumed = available.len();
        for &byte in available {
            let room = MAX_DOCKER_DIAGNOSTIC_BYTES - TRUNCATED_DIAGNOSTIC.len();
            if diagnostic.bytes.len() < room {
                diagnostic.bytes.push(byte);
            } else {
                diagnostic.truncated = true;
            }
            if byte == b'\n' {
                timings.observe(started.elapsed(), &String::from_utf8_lossy(&line));
                line.clear();
            } else if line.len() < MAX_COMPOSE_LINE_BYTES {
                line.push(byte);
            }
        }
        reader.consume(consumed);
    }
    if !line.is_empty() {
        timings.observe(started.elapsed(), &String::from_utf8_lossy(&line));
    }
    Ok((timings, diagnostic))
}

fn clear_volumes_arguments(
    platform: &str,
    cpuset: &str,
    image: &str,
    container: &str,
    volumes: &[&str],
) -> Vec<OsString> {
    let mut arguments: Vec<OsString> = [
        "run",
        "--rm",
        "--name",
        container,
        "--label",
        "com.shimpz.local.managed=1",
        "--label",
        "com.shimpz.local.kind=runtime-state-reset",
        "--platform",
        platform,
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "DAC_OVERRIDE",
        "--security-opt",
        "no-new-privileges:true",
        "--user",
        "0:0",
        "--cpuset-cpus",
        cpuset,
        "--memory",
        "256m",
        "--memory-swap",
        "256m",
        "--pids-limit",
        "32",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    for volume in volumes {
        arguments.push("--mount".into());
        arguments.push(
            format!("type=volume,src={SPACE_PROJECT}_{volume},dst=/state/{volume},volume-nocopy")
                .into(),
        );
    }
    // Depth 1 holds the volume roots themselves, which stay; everything below them is removed, and the deletions
    // reach the disk where they ran, inside Docker's own machine, before the new epoch is recorded.
    for value in [
        "--entrypoint",
        "/bin/sh",
        image,
        "-c",
        "find /state -mindepth 2 -delete && sync",
    ] {
        arguments.push(value.into());
    }
    arguments
}

fn admin_authentication_probe_arguments(
    platform: &str,
    cpuset: &str,
    mount: &str,
    admin_image: &str,
    container: &str,
) -> Vec<OsString> {
    python_helper_arguments(
        platform,
        cpuset,
        "256m",
        &[
            "--name",
            container,
            "--label",
            "com.shimpz.local.managed=1",
            "--label",
            "com.shimpz.local.kind=admin-authentication-probe",
            "--user",
            "1000:1000",
        ],
        mount,
        admin_image,
        &["-m", "authentication_state"],
    )
}

fn status_projection_arguments(
    platform: &str,
    cpuset: &str,
    mount: &str,
    admin_image: &str,
) -> Vec<OsString> {
    let script = "import json,os,sys; raw=sys.stdin.buffer.read(1025); document=json.loads(raw); assert len(raw)<=1024 and set(document)=={'release','ordinal','checked_at','outcome'}; target='/run/shimpz-local-release/status.json'; temporary=target+'.tmp'; descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600); assert os.write(descriptor,raw)==len(raw); os.fchmod(descriptor,0o600); os.close(descriptor); os.replace(temporary,target)";
    python_helper_arguments(
        platform,
        cpuset,
        "64m",
        &["--interactive", "--user", "1000:1000"],
        mount,
        admin_image,
        &["-c", script],
    )
}

fn reset_capability_write_script() -> &'static str {
    "import json,os,stat,sys; raw=sys.stdin.buffer.read(1025); document=json.loads(raw); assert 0<len(raw)<=1024 and set(document)=={'version','purpose','space_id','created_at','expires_at','capability_sha256'}; target='/run/shimpz-local-reset/capability.json'; temporary=target+'.tmp'; flags=os.O_WRONLY|os.O_CREAT|os.O_TRUNC|getattr(os,'O_NOFOLLOW',0); descriptor=os.open(temporary,flags,0o600); record=os.fstat(descriptor); assert stat.S_ISREG(record.st_mode) and record.st_nlink==1 and record.st_uid==1000 and record.st_gid==1000; assert os.write(descriptor,raw)==len(raw); os.fchmod(descriptor,0o600); os.fsync(descriptor); os.close(descriptor); os.replace(temporary,target)"
}

fn reset_capability_clear_script() -> &'static str {
    "import os; root='/run/shimpz-local-reset'; [(os.unlink(path) if os.path.lexists(path) else None) for path in (root+'/capability.json',root+'/capability.json.tmp')]"
}

fn reset_capability_arguments(
    platform: &str,
    cpuset: &str,
    mount: &str,
    admin_image: &str,
    interactive: bool,
    script: &str,
) -> Vec<OsString> {
    let options: &[&str] = if interactive {
        &["--interactive", "--user", "1000:1000"]
    } else {
        &["--user", "1000:1000"]
    };
    python_helper_arguments(
        platform,
        cpuset,
        "64m",
        options,
        mount,
        admin_image,
        &["-c", script],
    )
}

pub(crate) fn validate_endpoint(
    docker: &Path,
    profile: HostProfile,
    paths: &Paths,
) -> Result<(), String> {
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

/// The daemon answered `<engine>|<api>` and Compose its short version; each must meet the supported floor.
fn require_engine_versions(daemon: &str, compose: &str) -> Result<(), String> {
    let (server, api) = daemon.trim().split_once('|').unwrap_or((daemon.trim(), ""));
    if !version_at_least(server, (25, 0, 0)) || !version_at_least(api, (1, 44, 0)) {
        return Err(format!(
            "Docker Engine 25.0 or newer with API 1.44 is required (Engine {server}, API {api})"
        ));
    }
    if !version_at_least(compose.trim(), (2, 20, 2)) {
        return Err(format!(
            "Docker Compose 2.20.2 or newer is required (found {})",
            compose.trim()
        ));
    }
    Ok(())
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

enum BoundedOutput {
    Completed {
        status: ExitStatus,
        bytes: Vec<u8>,
        truncated: bool,
    },
    TimedOut,
}

fn execute_bounded_stdout(
    command: &mut Command,
    timeout: Duration,
) -> Result<BoundedOutput, String> {
    let mut child = command
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not execute Docker: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Docker authentication-state output is unavailable".to_owned())?;
    let captured = thread::spawn(move || drain_bounded_stdout(stdout));
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("could not execute Docker: {error}"))?
        {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            child
                .wait()
                .map_err(|error| format!("could not execute Docker: {error}"))?;
            break None;
        }
        thread::sleep(Duration::from_millis(25));
    };
    let captured = captured
        .join()
        .map_err(|_| "Docker authentication-state output could not be read".to_owned())??;
    match status {
        Some(status) => Ok(BoundedOutput::Completed {
            status,
            bytes: captured.bytes,
            truncated: captured.truncated,
        }),
        None => Ok(BoundedOutput::TimedOut),
    }
}

fn drain_bounded_stdout(stdout: ChildStdout) -> Result<Drained, String> {
    capture::drain(stdout, ADMIN_AUTHENTICATION_OUTPUT_BYTES + 1)
        .map_err(|_| "Docker authentication-state output could not be read".to_owned())
}

fn drain_diagnostic(reader: impl Read) -> Result<Drained, String> {
    capture::drain(reader, MAX_DOCKER_DIAGNOSTIC_BYTES)
        .map_err(|_| "Docker diagnostic output could not be read".to_owned())
}

fn render_diagnostic(captured: &Drained) -> String {
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
    let result = capture::bounded(
        Command::new(program).args(arguments),
        MAX_DOCKER_OUTPUT_BYTES,
        MAX_DOCKER_OUTPUT_BYTES,
    )
    .map_err(|failure| match failure {
        capture::Failure::Unavailable(error) => format!("could not execute Docker: {error}"),
        capture::Failure::Excessive => "Docker returned excessive output".to_owned(),
    })?;
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

/// The inspected image holds exactly `reference` among its repository digests and runs on `platform`.
fn image_present(document: &str, reference: &str, repository: &str, platform: &str) -> bool {
    let Some((digests, image_platform)) = document.trim_end().rsplit_once('|') else {
        return false;
    };
    let Ok(digests) = serde_json::from_str::<Vec<String>>(digests) else {
        return false;
    };
    digest::is_pinned(reference, repository)
        && image_platform == platform
        && digests.iter().any(|value| value == reference)
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

    /// Captured Docker output was once read without any bound; it now stops Docker one byte past its bound.
    #[cfg(unix)]
    #[test]
    fn captured_docker_output_is_bounded() {
        let shell = Path::new("/bin/sh");
        let exact = format!("head -c {MAX_DOCKER_OUTPUT_BYTES} /dev/zero");
        assert_eq!(
            output(shell, ["-c", &exact]).unwrap().len(),
            MAX_DOCKER_OUTPUT_BYTES
        );
        let excessive = format!("head -c {} /dev/zero", MAX_DOCKER_OUTPUT_BYTES + 1);
        assert_eq!(
            output(shell, ["-c", &excessive]),
            Err("Docker returned excessive output".into())
        );
    }

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
    fn managed_stop_omits_a_timeout_override_and_keeps_bounded_failures() {
        assert_eq!(
            stop_arguments(&["first".to_owned(), "second".to_owned()]),
            ["stop", "first", "second"].map(OsString::from)
        );

        let refused = Engine {
            docker: PathBuf::from("/usr/bin/false"),
            platform: "linux/amd64",
            cpuset: "0".into(),
        };
        assert_eq!(refused.stop_containers(&[]), Ok(()));
        assert_eq!(
            refused.stop_containers(&["first".to_owned()]),
            Err("could not stop every managed Local container".into())
        );
    }

    #[cfg(unix)]
    #[test]
    fn team_activity_runs_the_team_client_and_maps_every_failure_to_unknown() {
        let temporary = tempfile::tempdir().unwrap();
        let command = temporary.path().join("docker");
        let calls = temporary.path().join("calls");
        let answer = temporary.path().join("answer");
        let status = temporary.path().join("status");
        crate::fake_tool::write(
            &command,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncat '{}'\nexit $(cat '{}')\n",
                calls.display(),
                answer.display(),
                status.display()
            ),
        );
        let _ = fs::remove_file(&calls);
        let engine = Engine {
            docker: command,
            platform: "linux/amd64",
            cpuset: "0".into(),
        };
        for (output, code, expected) in [
            ("busy\n", "0", TeamActivity::Busy),
            ("idle\n", "0", TeamActivity::Idle),
            ("idle\n", "1", TeamActivity::Unknown),
            ("maybe\n", "0", TeamActivity::Unknown),
        ] {
            fs::write(&answer, output).unwrap();
            fs::write(&status, code).unwrap();
            assert_eq!(
                engine.team_activity("team-id", Duration::from_secs(5)),
                expected,
                "{output:?} {code}"
            );
        }
        let arguments = fs::read_to_string(calls).unwrap();
        assert_eq!(
            arguments.lines().collect::<Vec<_>>(),
            ["exec team-id /opt/venv/bin/python -m local.activity"; 4]
        );
    }

    #[cfg(unix)]
    #[test]
    fn macos_controller_uses_the_desktop_vm_socket_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let command = temporary.path().join("docker");
        let calls = temporary.path().join("calls");
        crate::fake_tool::write(
            &command,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$*\" in *'print(metadata.st_gid)'*) printf '0\\n' ;; esac\n",
                calls.display()
            ),
        );
        let _ = fs::remove_file(&calls);
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
            docker: PathBuf::from("/usr/bin/false"),
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
        let temporary = tempfile::tempdir().unwrap();
        let command = temporary.path().join("docker");
        crate::fake_tool::write(&command, "#!/bin/sh\nprintf 'not-a-group\\n'\n");
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

    fn init_records(hash: &str) -> String {
        let image = format!("localhost/shimpz-egress@sha256:{DIGEST}");
        let capability = "volume:shimpz-space_account_egress_capability";
        format!(
            "exited|0|shimpz-space|shimpz-account-egress-init|{hash}|{image}|{capability}\nrunning|0|shimpz-space|shimpz-account-egress|{}|{image}|{capability}\n",
            "9".repeat(64)
        )
    }

    #[test]
    fn only_an_initializer_completed_under_the_candidate_configuration_is_left_alone() {
        let hash = "c".repeat(64);
        let configuration = format!("shimpz-account-egress-init {hash}\n");
        let records = init_records(&hash);
        assert!(completed_init_matches(&records, &configuration));
        let other_image = format!("localhost/shimpz-egress@sha256:{}", "f".repeat(64));
        let (init, egress) = records.split_once('\n').unwrap();
        for changed in [
            records.replacen("exited|", "running|", 1),
            records.replacen("exited|", "created|", 1),
            records.replacen("exited|0|", "exited|1|", 1),
            records.replacen("shimpz-space|", "other|", 1),
            records.replacen("|shimpz-account-egress-init|", "|shimpz-account-egress|", 1),
            records.replacen(&hash, &"d".repeat(64), 1),
            records.replacen(
                "volume:shimpz-space_account_egress_capability",
                "volume:other",
                1,
            ),
            records.replacen("volume:shimpz-space_account_egress_capability", "bind:", 1),
            format!("{init}\n{}", egress.replacen("running|", "restarting|", 1)),
            format!(
                "{init}\n{}",
                egress.replacen("|shimpz-account-egress|", "|team|", 1)
            ),
            format!(
                "{init}\n{}",
                egress.replacen(
                    &format!("localhost/shimpz-egress@sha256:{DIGEST}"),
                    &other_image,
                    1
                )
            ),
            format!(
                "{init}\n{}",
                egress.replacen("volume:shimpz-space_account_egress_capability", "", 1)
            ),
            format!("{init}\n{}", egress.replacen(&"9".repeat(64), "", 1)),
            records.replace(
                &format!("localhost/shimpz-egress@sha256:{DIGEST}"),
                "localhost/shimpz-admin:latest",
            ),
            format!("{init}\n"),
            format!("{records}{egress}\n"),
        ] {
            assert!(
                !completed_init_matches(&changed, &configuration),
                "{changed}"
            );
        }
        for changed in [
            configuration.replace(&hash, &"C".repeat(64)),
            configuration.replace(&hash, &"c".repeat(63)),
            configuration.replace("shimpz-account-egress-init ", "shimpz-account-egress "),
            configuration.trim_end().to_owned(),
            format!("{configuration}{configuration}"),
            String::new(),
        ] {
            assert!(!completed_init_matches(&records, &changed), "{changed}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn compose_up_leaves_alone_only_a_current_initializer_whose_capability_still_reads() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = Paths::under(temporary.path()).unwrap();
        let calls = temporary.path().join("calls");
        let hash = "e".repeat(64);
        let services = " --no-deps team shimpz-assistant-egress shimpz-assistant-release shimpz-account-egress shimpz-brain-egress brain admin";
        for (records, capability, selected) in [
            (init_records(&hash), "exit 0", true),
            (init_records(&hash), "exit 1", false),
            (init_records(&hash), "printf leaked", false),
            (
                init_records(&hash).replacen("exited|0|", "exited|2|", 1),
                "exit 0",
                false,
            ),
        ] {
            let command = temporary.path().join("docker");
            let records = records.replace('\n', "\\n");
            crate::fake_tool::write(
                &command,
                format!(
                    "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$*\" in\n  inspect*) printf '{records}' ;;\n  *' config --hash '*) printf 'shimpz-account-egress-init {hash}\\n' ;;\n  exec*) {capability} ;;\nesac\n",
                    calls.display()
                ),
            );
            let _ = fs::remove_file(&calls);
            let engine = Engine {
                docker: command,
                platform: "linux/amd64",
                cpuset: "0".into(),
            };

            let (status, _) = engine.compose_up(&paths).unwrap();

            assert!(status.success());
            let invocations = fs::read_to_string(&calls).unwrap();
            let up = invocations
                .lines()
                .find(|line| line.contains(" up -d "))
                .unwrap();
            assert_eq!(up.ends_with(services), selected, "{capability}: {up}");
            assert_eq!(up.ends_with("--remove-orphans"), !selected, "{up}");
        }
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
            ("--cpus", HELPER_CPUS),
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

    #[test]
    fn compose_progress_reports_when_each_started_container_became_healthy() {
        let mut timings = ContainerTimings::default();
        let at = |seconds: f64| Duration::from_secs_f64(seconds);
        for (seconds, line) in [
            (0.1, " Container shimpz-brain Recreate "),
            (1.2, " Container shimpz-brain Recreated "),
            (1.3, " Container shimpz-team Running "),
            (1.4, " Container shimpz-brain Starting "),
            (1.9, " Container shimpz-brain Started "),
            (2.0, " Container shimpz-brain Waiting "),
            (4.5, " Container shimpz-brain Healthy "),
            (4.6, " Container shimpz-admin Started "),
            (5.0, " Container shimpz-brain Healthy "),
            (5.1, "container shimpz-admin is unhealthy"),
            (5.2, " Container a b c d"),
        ] {
            timings.observe(at(seconds), line);
        }
        assert_eq!(
            timings.summary(),
            [
                "shimpz-brain started at 1.9s and was healthy at 4.5s",
                "shimpz-admin started at 4.6s",
            ]
        );
    }

    #[test]
    fn compose_progress_is_read_in_bounded_lines_and_a_bounded_diagnostic() {
        let started = Instant::now();
        // One newline-free line far beyond every bound, then an ordinary event.
        let mut output = vec![b'x'; 3 * MAX_DOCKER_DIAGNOSTIC_BYTES];
        output.extend_from_slice(b"\n Container shimpz-brain Started \n");
        let (timings, diagnostic) = read_compose_progress(output.as_slice(), started).unwrap();
        assert_eq!(timings.summary().len(), 1);
        assert!(diagnostic.truncated);
        assert_eq!(
            diagnostic.bytes.len(),
            MAX_DOCKER_DIAGNOSTIC_BYTES - TRUNCATED_DIAGNOSTIC.len()
        );
        assert!(render_diagnostic(&diagnostic).ends_with(TRUNCATED_DIAGNOSTIC));
        // A short failure keeps its whole explanation, and a final line without a newline still counts.
        let (timings, diagnostic) = read_compose_progress(
            b"Error: service brain failed\n Container shimpz-brain Started".as_slice(),
            started,
        )
        .unwrap();
        assert_eq!(timings.summary().len(), 1);
        assert!(!diagnostic.truncated);
        assert!(render_diagnostic(&diagnostic).starts_with("Error: service brain failed"));
        // Container tracking is bounded too.
        let mut many = Vec::new();
        for index in 0..(MAX_COMPOSE_CONTAINERS + 10) {
            many.extend_from_slice(format!(" Container c{index} Started\n").as_bytes());
        }
        let (timings, _) = read_compose_progress(many.as_slice(), started).unwrap();
        assert_eq!(timings.summary().len(), MAX_COMPOSE_CONTAINERS);
    }

    #[test]
    fn runtime_state_reset_only_deletes_below_the_named_volume_roots_offline() {
        let image = format!("ghcr.io/theshimpz/shimpz-team-local@sha256:{DIGEST}");
        let arguments = clear_volumes_arguments(
            "linux/amd64",
            "0-3",
            &image,
            "shimpz-runtime-state-reset-1",
            &["controller_routine_state", "brain_runtime_state"],
        );
        let arguments: Vec<_> = arguments
            .iter()
            .map(|argument| argument.to_str().unwrap())
            .collect();
        let tail = [
            image.as_str(),
            "-c",
            "find /state -mindepth 2 -delete && sync",
        ];
        assert_eq!(&arguments[arguments.len() - tail.len()..], tail);
        for pair in [
            ["--network", "none"],
            ["--pull", "never"],
            ["--cap-drop", "ALL"],
            ["--cap-add", "DAC_OVERRIDE"],
            ["--entrypoint", "/bin/sh"],
            [
                "--mount",
                "type=volume,src=shimpz-space_controller_routine_state,dst=/state/controller_routine_state,volume-nocopy",
            ],
            [
                "--mount",
                "type=volume,src=shimpz-space_brain_runtime_state,dst=/state/brain_runtime_state,volume-nocopy",
            ],
        ] {
            assert!(
                arguments.windows(2).any(|window| window == pair),
                "{pair:?}"
            );
        }
        assert!(arguments.contains(&"--read-only") && arguments.contains(&"--rm"));
        assert_eq!(
            arguments
                .iter()
                .filter(|argument| **argument == "--cap-add")
                .count(),
            1
        );
        assert_eq!(
            arguments
                .iter()
                .filter(|argument| **argument == "--mount")
                .count(),
            2
        );
    }

    #[test]
    fn admin_authentication_probe_is_read_only_offline_and_resource_bounded() {
        let image = format!("ghcr.io/theshimpz/shimpz-admin@sha256:{DIGEST}");
        let mount = "type=volume,src=shimpz-space_data,dst=/data,volume-nocopy,readonly";
        let arguments = admin_authentication_probe_arguments(
            "linux/amd64",
            "0-3",
            mount,
            &image,
            "shimpz-admin-authentication-probe-1-1",
        );

        for required in [
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "no-new-privileges:true",
            "--user",
            "1000:1000",
            "--pull",
            "never",
            "--memory",
            "256m",
            "--memory-swap",
            "--pids-limit",
            "32",
            mount,
            "/opt/venv/bin/python",
            image.as_str(),
            "authentication_state",
        ] {
            assert!(arguments.iter().any(|argument| argument == required));
        }
        assert!(arguments.iter().all(|argument| argument != "--interactive"));
        assert!(arguments.iter().all(|argument| argument != "--tty"));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_probe_terminates_a_silent_process_at_its_deadline() {
        let started = Instant::now();
        let result = execute_bounded_stdout(
            Command::new("/bin/sh")
                .args(["-c", "exec sleep 5"])
                .stdin(Stdio::null())
                .stderr(Stdio::null()),
            Duration::from_millis(50),
        )
        .unwrap();

        assert!(matches!(result, BoundedOutput::TimedOut));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn engine_versions_meet_the_supported_floors() {
        assert_eq!(require_engine_versions("29.8.2|1.52\n", "5.6.0\n"), Ok(()));
        assert_eq!(
            require_engine_versions("24.0.9|1.43\n", "5.6.0\n"),
            Err(
                "Docker Engine 25.0 or newer with API 1.44 is required (Engine 24.0.9, API 1.43)"
                    .into()
            )
        );
        assert_eq!(
            require_engine_versions("29.8.2|1.43\n", "5.6.0\n"),
            Err(
                "Docker Engine 25.0 or newer with API 1.44 is required (Engine 29.8.2, API 1.43)"
                    .into()
            )
        );
        assert_eq!(
            require_engine_versions("29.8.2\n", "5.6.0\n"),
            Err(
                "Docker Engine 25.0 or newer with API 1.44 is required (Engine 29.8.2, API )"
                    .into()
            )
        );
        assert_eq!(
            require_engine_versions("29.8.2|1.52\n", "2.20.1\n"),
            Err("Docker Compose 2.20.2 or newer is required (found 2.20.1)".into())
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
    fn a_developer_image_is_admitted_only_by_its_exact_local_digest_and_platform() {
        let reference = format!("localhost/shimpz-admin@sha256:{DIGEST}");
        let present = format!(
            "[\"{reference}\",\"localhost/shimpz-admin@sha256:{}\"]|linux/amd64\n",
            "c".repeat(64)
        );
        assert!(image_present(
            &present,
            &reference,
            "localhost/shimpz-admin",
            "linux/amd64"
        ));
        for (document, platform) in [
            (present.as_str(), "linux/arm64"),
            ("[]|linux/amd64", "linux/amd64"),
            ("null|linux/amd64", "linux/amd64"),
            ("not json|linux/amd64", "linux/amd64"),
            (
                &format!("[\"{reference}x\"]|linux/amd64") as &str,
                "linux/amd64",
            ),
            (&format!("[\"{reference}\"]") as &str, "linux/amd64"),
        ] {
            assert!(!image_present(
                document,
                &reference,
                "localhost/shimpz-admin",
                platform
            ));
        }
        assert!(!image_present(
            &format!("[\"{reference}\"]|linux/amd64"),
            &reference,
            "localhost/shimpz-brain",
            "linux/amd64"
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

    #[test]
    fn reset_capability_projection_is_offline_unprivileged_and_stdin_only() {
        let image = format!("ghcr.io/theshimpz/shimpz-admin@sha256:{DIGEST}");
        let mount = "type=volume,src=reset,dst=/run/reset,volume-nocopy";
        let arguments = reset_capability_arguments(
            "linux/amd64",
            "0-3",
            mount,
            &image,
            true,
            reset_capability_write_script(),
        );

        for required in [
            "--interactive",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "no-new-privileges:true",
            "--user",
            "1000:1000",
            "--pull",
            "never",
            mount,
            image.as_str(),
        ] {
            assert!(arguments.iter().any(|argument| argument == required));
        }
        assert!(arguments.iter().all(|argument| argument != "--tty"));
        assert!(reset_capability_write_script().contains("O_NOFOLLOW"));
        assert!(reset_capability_write_script().contains("os.fsync"));
    }

    #[test]
    fn reset_capability_cleanup_cannot_receive_secret_input() {
        let arguments = reset_capability_arguments(
            "linux/amd64",
            "0-3",
            "type=volume,src=reset,dst=/run/reset,volume-nocopy",
            &format!("ghcr.io/theshimpz/shimpz-admin@sha256:{DIGEST}"),
            false,
            reset_capability_clear_script(),
        );

        assert!(arguments.iter().all(|argument| argument != "--interactive"));
        assert!(arguments.iter().all(|argument| argument != "--tty"));
        assert!(reset_capability_clear_script().contains("capability.json"));
        assert!(!reset_capability_clear_script().contains("sys.stdin"));
    }

    /// The exact argument list every Python helper must produce: its own identity, the complete hardening set once,
    /// and its own command after the image.
    fn hardened_helper(
        options: &[&str],
        memory: &str,
        image: &str,
        command: &[&str],
    ) -> Vec<String> {
        ["run", "--rm"]
            .into_iter()
            .chain(options.iter().copied())
            .chain([
                "--platform",
                "linux/amd64",
                "--pull",
                "never",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--cpuset-cpus",
                "0-3",
                "--cpus",
                "1",
                "--memory",
                memory,
                "--memory-swap",
                memory,
                "--pids-limit",
                "32",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=8m",
                "--mount",
                "m",
                "--entrypoint",
                "/opt/venv/bin/python",
                image,
            ])
            .chain(command.iter().copied())
            .map(str::to_owned)
            .collect()
    }

    fn text(arguments: Vec<OsString>) -> Vec<String> {
        arguments
            .into_iter()
            .map(|argument| argument.into_string().unwrap())
            .collect()
    }

    #[test]
    fn admin_helpers_share_one_exact_hardened_argument_list() {
        let image = format!("ghcr.io/theshimpz/shimpz-admin@sha256:{DIGEST}");
        let (platform, cpuset) = ("linux/amd64", "0-3");
        let user = ["--user", "1000:1000"];
        let stdin_user = ["--interactive", "--user", "1000:1000"];
        let admin = [
            "--name",
            "c",
            "--label",
            "com.shimpz.local.managed=1",
            "--label",
            "com.shimpz.local.kind=admin-authentication-probe",
            "--user",
            "1000:1000",
        ];
        assert_eq!(
            text(admin_authentication_probe_arguments(
                platform, cpuset, "m", &image, "c"
            )),
            hardened_helper(&admin, "256m", &image, &["-m", "authentication_state"])
        );
        assert_eq!(
            text(reset_capability_arguments(
                platform, cpuset, "m", &image, true, "s"
            )),
            hardened_helper(&stdin_user, "64m", &image, &["-c", "s"])
        );
        assert_eq!(
            text(reset_capability_arguments(
                platform, cpuset, "m", &image, false, "s"
            )),
            hardened_helper(&user, "64m", &image, &["-c", "s"])
        );
        let status = text(status_projection_arguments(platform, cpuset, "m", &image));
        let script = status.last().unwrap().clone();
        assert_eq!(
            status,
            hardened_helper(&stdin_user, "64m", &image, &["-c", &script])
        );
    }

    #[cfg(unix)]
    #[test]
    fn socket_probes_share_one_exact_hardened_argument_list() {
        let image = format!("ghcr.io/theshimpz/shimpz-team-local@sha256:{DIGEST}");
        assert_eq!(
            text(socket_probe_arguments(
                "linux/amd64",
                "0-3",
                "m",
                &image,
                None,
                "s"
            )),
            hardened_helper(&[], "64m", &image, &["-c", "s"])
        );
        assert_eq!(
            text(socket_probe_arguments(
                "linux/amd64",
                "0-3",
                "m",
                &image,
                Some(7),
                "s"
            )),
            hardened_helper(&["--group-add", "7"], "64m", &image, &["-c", "s"])
        );
    }
}
