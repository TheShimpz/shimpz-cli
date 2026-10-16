//! One-shot helper containers this process names: their sweep and proved removal, and the release-status and
//! reset-capability projections they write.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use super::exec::{
    docker_timed_out, output, quiet_status, silent_status, spawn_docker, wait_failure,
};
use super::{ADMIN_IDENTITY, DOCKER_QUICK, Engine, HELPER_CPUS, isolated_container};
use crate::capture;
use crate::space::graph::{self, KIND_LABEL, MANAGED_LABEL};
use crate::space::release::ADMIN;

/// Distinguishes the one-shot helper containers this process names.
static HELPER_SEQUENCE: AtomicU64 = AtomicU64::new(0);
/// The kind label, and name stem, of the helper that projects the Local release status.
pub(super) const RELEASE_STATUS_HELPER: &str = "release-status";
/// The kind label, and name stem, of the helpers that project or clear the reset capability.
const RESET_CAPABILITY_HELPER: &str = "reset-capability";

/// Remove every Space-managed helper container of `kind` an earlier run left, and prove none remains: a helper whose
/// removal could not be proved may still write what a new one would, so no new one starts until it is gone.
pub(super) fn sweep_helpers(docker: &Path, kind: &str) -> Result<(), String> {
    let list = || {
        output(
            docker,
            [
                "ps",
                "--all",
                "--quiet",
                "--filter",
                &format!("label={MANAGED_LABEL}=1"),
                "--filter",
                &format!("label={KIND_LABEL}={kind}"),
            ],
        )
    };
    let left = list()?;
    if left.trim().is_empty() {
        return Ok(());
    }
    let mut arguments = vec!["rm", "--force"];
    arguments.extend(left.split_whitespace());
    let _ = quiet_status(
        Command::new(docker).args(&arguments),
        "Docker helper container removal",
        DOCKER_QUICK,
    );
    if list()?.trim().is_empty() {
        Ok(())
    } else {
        Err(format!(
            "an earlier {kind} helper container could not be removed; run docker rm --force on the containers labelled {KIND_LABEL}={kind}"
        ))
    }
}

/// The Docker label options of one Space-managed one-shot container of `kind`, by which `sweep_helpers` finds it.
pub(super) fn helper_labels(kind: &str) -> [String; 4] {
    [
        "--label".to_owned(),
        format!("{MANAGED_LABEL}=1"),
        "--label".to_owned(),
        format!("{KIND_LABEL}={kind}"),
    ]
}

/// A container name owned by this process for one helper of `kind`, so a helper whose Docker client was stopped can
/// still be removed: stopping the client never stops its container.
pub(super) fn helper_name(kind: &str) -> String {
    format!(
        "shimpz-{kind}-{}-{}",
        std::process::id(),
        HELPER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

/// Remove a helper container by its exact name and prove it absent: Docker answers successfully that no container,
/// running or stopped, has that name.
pub(super) fn remove_helper(docker: &Path, name: &str) -> Result<(), String> {
    let _ = silent_status(docker, ["rm", "--force", name]);
    match output(
        docker,
        [
            "ps",
            "--all",
            "--quiet",
            "--filter",
            &format!("name=^/{name}$"),
        ],
    ) {
        Ok(listed) if listed.trim().is_empty() => Ok(()),
        _ => Err(format!(
            "the helper container {name} could not be proved removed and may still be running; run docker rm --force {name}"
        )),
    }
}

/// The failure of a helper whose Docker client stopped or failed, which does not prove its container ended: the
/// container is removed and proved gone, and a failed removal joins `cause`.
pub(super) fn helper_failure(docker: &Path, name: &str, cause: String) -> String {
    match remove_helper(docker, name) {
        Ok(()) => cause,
        Err(cleanup) => format!("{cause}; {cleanup}"),
    }
}
/// The graph keys of the volumes the reset capability and release status helpers mount.
pub(super) const RESET_CAPABILITY_VOLUME: &str = "reset_capability";
pub(super) const RELEASE_STATUS_VOLUME: &str = "release_status";

/// A started release status helper waiting for its document. It writes nothing unless committed: an abandoned
/// helper reads an empty input, which its script refuses before opening any file.
pub(crate) struct PendingStatus {
    child: Option<Child>,
    docker: PathBuf,
    name: String,
}

/// Why a status projection did not complete: the helper refused or failed the write and was reaped, or it could not
/// be reaped and may remain.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ProjectionFailure {
    NotProjected(String),
    Unreaped(String),
}

impl PendingStatus {
    /// Send the status document and wait for the helper to write it. A helper that could not be reaped is reported
    /// apart from one that refused or failed the write, so its cause is never lost.
    pub(crate) fn commit(mut self, document: &[u8]) -> Result<(), ProjectionFailure> {
        let mut child = self.child.take().ok_or_else(|| {
            ProjectionFailure::NotProjected("the Local release status helper is unavailable".into())
        })?;
        let sent = if document.len() > 1_024 {
            Err("the Local release status projection is invalid".to_owned())
        } else {
            child
                .stdin
                .take()
                .ok_or_else(|| "Docker status input is unavailable".to_owned())
                .and_then(|mut input| {
                    input.write_all(document).map_err(|_| {
                        "the Local release status could not be sent to Docker".to_owned()
                    })
                })
        };
        // The input is closed by now, so the helper ends and is reaped, even when nothing was sent; one that outlives
        // its deadline is stopped.
        drop(child.stdin.take());
        let outcome = match (
            capture::wait(&mut child, Instant::now() + DOCKER_QUICK),
            sent,
        ) {
            (Ok(status), Ok(())) if status.success() => return Ok(()),
            (Err(capture::Failure::TimedOut { stopped: true }), _) => {
                ProjectionFailure::NotProjected(docker_timed_out(DOCKER_QUICK, true))
            }
            (Err(failure), sent) => {
                let unreaped = format!(
                    "the Local release status helper could not be reaped: {}",
                    wait_failure(DOCKER_QUICK, failure)
                );
                ProjectionFailure::Unreaped(match sent {
                    Ok(()) => unreaped,
                    Err(cause) => format!("{cause}; {unreaped}"),
                })
            }
            (Ok(_), Err(cause)) => ProjectionFailure::NotProjected(cause),
            (Ok(_), Ok(())) => ProjectionFailure::NotProjected(
                "the Local release status could not be projected to Admin".into(),
            ),
        };
        // An unsuccessful client does not prove its container ended, and that container could still write the
        // document later: it is removed and proved gone, or the failure says it may remain.
        Err(match (outcome, remove_helper(&self.docker, &self.name)) {
            (outcome, Ok(())) => outcome,
            (
                ProjectionFailure::NotProjected(cause) | ProjectionFailure::Unreaped(cause),
                Err(cleanup),
            ) => ProjectionFailure::Unreaped(format!("{cause}; {cleanup}")),
        })
    }

    /// End the helper without a document and reap it; an unreaped helper is reported, never ignored.
    pub(crate) fn abandon(mut self) -> Result<(), String> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        drop(child.stdin.take());
        match capture::wait(&mut child, Instant::now() + DOCKER_QUICK) {
            Ok(_) => Ok(()),
            Err(capture::Failure::TimedOut { stopped: true }) => {
                remove_helper(&self.docker, &self.name)
            }
            Err(failure) => Err(format!(
                "the unused Local release status helper could not be reaped: {}",
                wait_failure(DOCKER_QUICK, failure)
            )),
        }
    }
}

impl Drop for PendingStatus {
    /// The fallback for an exit that neither committed nor abandoned: end the helper without a document.
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            drop(child.stdin.take());
            if capture::wait(&mut child, Instant::now() + DOCKER_QUICK).is_err() {
                let _ = remove_helper(&self.docker, &self.name);
            }
        }
    }
}

/// One-shot Python helper container: removed on exit, never pulled, offline, with a read-only root, no capabilities,
/// and no privilege gain, inside the Space cpuset with one CPU, `memory` without swap, 32 processes, a
/// non-executable `/tmp`, and exactly one `mount`. `options` holds only the helper's own name, labels, stdin, and
/// identity.
pub(super) fn python_helper_arguments(
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
        .chain(isolated_container(platform))
        .chain([
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

pub(super) fn status_projection_arguments(
    platform: &str,
    cpuset: &str,
    mount: &str,
    admin_image: &str,
    name: &str,
) -> Vec<OsString> {
    let script = "import json,os,sys; raw=sys.stdin.buffer.read(1025); document=json.loads(raw); assert len(raw)<=1024 and set(document)=={'release','ordinal','checked_at','outcome'}; target='/run/shimpz-local-release/status.json'; temporary=target+'.tmp'; descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600); assert os.write(descriptor,raw)==len(raw); os.fchmod(descriptor,0o600); os.close(descriptor); os.replace(temporary,target)";
    admin_helper_arguments(
        platform,
        cpuset,
        mount,
        admin_image,
        &admin_helper_options(RELEASE_STATUS_HELPER, true, name),
        script,
    )
}

pub(super) fn reset_capability_write_script() -> &'static str {
    "import json,os,stat,sys; raw=sys.stdin.buffer.read(1025); document=json.loads(raw); assert 0<len(raw)<=1024 and set(document)=={'version','purpose','space_id','created_at','expires_at','capability_sha256'}; target='/run/shimpz-local-reset/capability.json'; temporary=target+'.tmp'; flags=os.O_WRONLY|os.O_CREAT|os.O_TRUNC|getattr(os,'O_NOFOLLOW',0); descriptor=os.open(temporary,flags,0o600); record=os.fstat(descriptor); assert stat.S_ISREG(record.st_mode) and record.st_nlink==1 and record.st_uid==1000 and record.st_gid==1000; assert os.write(descriptor,raw)==len(raw); os.fchmod(descriptor,0o600); os.fsync(descriptor); os.close(descriptor); os.replace(temporary,target)"
}

pub(super) fn reset_capability_clear_script() -> &'static str {
    "import os; root='/run/shimpz-local-reset'; [(os.unlink(path) if os.path.lexists(path) else None) for path in (root+'/capability.json',root+'/capability.json.tmp')]"
}

pub(super) fn reset_capability_arguments(
    platform: &str,
    cpuset: &str,
    mount: &str,
    admin_image: &str,
    interactive: bool,
    script: &str,
    name: &str,
) -> Vec<OsString> {
    admin_helper_arguments(
        platform,
        cpuset,
        mount,
        admin_image,
        &admin_helper_options(RESET_CAPABILITY_HELPER, interactive, name),
        script,
    )
}

/// The options of one helper of `kind` named `name` that runs as Admin, reading its standard input when `interactive`.
pub(super) fn admin_helper_options(kind: &str, interactive: bool, name: &str) -> Vec<String> {
    interactive
        .then_some("--interactive")
        .into_iter()
        .chain(["--user", ADMIN_IDENTITY, "--name", name])
        .map(str::to_owned)
        .chain(helper_labels(kind))
        .collect()
}

/// A bounded helper with `options` that runs `script` with the Admin image.
fn admin_helper_arguments(
    platform: &str,
    cpuset: &str,
    mount: &str,
    admin_image: &str,
    options: &[String],
    script: &str,
) -> Vec<OsString> {
    let options: Vec<&str> = options.iter().map(String::as_str).collect();
    python_helper_arguments(
        platform,
        cpuset,
        "64m",
        &options,
        mount,
        admin_image,
        &["-c", script],
    )
}

impl Engine {
    pub(crate) fn project_release_status(
        &self,
        admin_image: &str,
        document: &[u8],
    ) -> Result<(), ProjectionFailure> {
        self.begin_release_status(admin_image)
            .map_err(ProjectionFailure::NotProjected)?
            .ok_or_else(|| {
                ProjectionFailure::NotProjected(
                    "the Local release status volume does not exist".into(),
                )
            })?
            .commit(document)
    }

    /// Start the hardened helper that projects the Local release status into this Space's owned volume, before the
    /// status is known: it waits on its input, so an apply can commit the status as soon as the candidate is healthy.
    /// `None` when the volume provably does not exist yet; Compose creates it, and the status is projected after.
    pub(crate) fn begin_release_status(
        &self,
        admin_image: &str,
    ) -> Result<Option<PendingStatus>, String> {
        if !ADMIN.admits(admin_image) {
            return Err("the Local release status projection is invalid".into());
        }
        let volume = graph::resource_name(RELEASE_STATUS_VOLUME);
        match self.owns_volume(RELEASE_STATUS_VOLUME) {
            Ok(true) => {}
            Ok(false) => {
                return Err("the Local release status volume is not owned by this Space".into());
            }
            // A failed inspection is absence only when the daemon lists no volume of exactly that name.
            Err(error) => {
                let listed = self.run_output([
                    "volume",
                    "ls",
                    "--quiet",
                    "--filter",
                    &format!("name=^{volume}$"),
                ])?;
                return if listed.lines().any(|name| name == volume) {
                    Err(error)
                } else {
                    Ok(None)
                };
            }
        }
        // A status helper an earlier projection could not prove removed may still write; no other may start first.
        sweep_helpers(&self.docker, RELEASE_STATUS_HELPER)?;
        let mount = format!("type=volume,src={volume},dst=/run/shimpz-local-release,volume-nocopy");
        let name = helper_name(RELEASE_STATUS_HELPER);
        let arguments =
            status_projection_arguments(self.platform, &self.cpuset, &mount, admin_image, &name);
        let child = spawn_docker(
            Command::new(&self.docker)
                .args(arguments)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
        )?;
        Ok(Some(PendingStatus {
            child: Some(child),
            docker: self.docker.clone(),
            name,
        }))
    }

    pub(crate) fn project_reset_capability(
        &self,
        admin_image: &str,
        document: &[u8],
    ) -> Result<(), String> {
        if !ADMIN.admits(admin_image) || document.is_empty() || document.len() > 1_024 {
            return Err("the Local reset capability projection is invalid".into());
        }
        let (name, arguments) = self.reset_capability_helper(admin_image, true)?;
        let mut child = spawn_docker(
            Command::new(&self.docker)
                .args(arguments)
                .stdin(Stdio::piped())
                .stdout(Stdio::null()),
        )?;
        let sent = child
            .stdin
            .take()
            .ok_or_else(|| "Docker reset capability input is unavailable".to_owned())
            .and_then(|mut input| {
                input.write_all(document).map_err(|_| {
                    "the Local reset capability could not be sent to Docker".to_owned()
                })
            });
        // The input is closed by now, so the helper ends; one that outlives its deadline is stopped.
        let cause = match (
            capture::wait(&mut child, Instant::now() + DOCKER_QUICK),
            sent,
        ) {
            (Ok(status), Ok(())) if status.success() => return Ok(()),
            (Err(failure), _) => wait_failure(DOCKER_QUICK, failure),
            (Ok(_), Err(cause)) => cause,
            (Ok(_), Ok(())) => "the Local reset capability could not be projected to Admin".into(),
        };
        Err(helper_failure(&self.docker, &name, cause))
    }

    pub(crate) fn clear_reset_capability(&self, admin_image: &str) -> Result<(), String> {
        if !ADMIN.admits(admin_image) {
            return Err("the Local reset capability cleanup is invalid".into());
        }
        let (name, arguments) = self.reset_capability_helper(admin_image, false)?;
        let cause = match self.run_quiet_status("Docker reset capability cleanup", arguments) {
            Ok(status) if status.success() => return Ok(()),
            Ok(_) => "the Local reset capability could not be removed".to_owned(),
            Err(cause) => cause,
        };
        Err(helper_failure(&self.docker, &name, cause))
    }

    /// The name and complete Docker arguments of one reset-capability helper, once the capability volume is proved
    /// and stale helpers are swept. A `write` helper reads the capability on its input and writes it; any other
    /// clears it.
    fn reset_capability_helper(
        &self,
        admin_image: &str,
        write: bool,
    ) -> Result<(String, Vec<OsString>), String> {
        self.require_owned_volume(RESET_CAPABILITY_VOLUME, "the Local reset capability volume")?;
        sweep_helpers(&self.docker, RESET_CAPABILITY_HELPER)?;
        let mount = format!(
            "type=volume,src={},dst=/run/shimpz-local-reset,volume-nocopy",
            graph::resource_name(RESET_CAPABILITY_VOLUME)
        );
        let name = helper_name(RESET_CAPABILITY_HELPER);
        let script = if write {
            reset_capability_write_script()
        } else {
            reset_capability_clear_script()
        };
        let arguments = reset_capability_arguments(
            self.platform,
            &self.cpuset,
            &mount,
            admin_image,
            write,
            script,
            &name,
        );
        Ok((name, arguments))
    }
}
