//! Native install, reconcile, stop, status, and reset orchestration.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use sha2::{Digest, Sha256};
use ureq::Agent;
use zeroize::Zeroizing;

use crate::args::{GraphProfile, SpaceInstall, SpaceStart};
use crate::output;

use super::docker::{Engine, ResolvedRelease};
use super::graph::{self, StorageProfile};
use super::host::{self, HostProfile};
use super::paths::Paths;
use super::resources::Inventory;
use super::scheduler;
use super::state::{self, Environment, Installed, Lock};
use super::status as status_report;
use super::storage::linux;

const ADMIN_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-admin";
const TEAM_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-team-local";
const BRAIN_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-brain";
const EGRESS_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-egress";
// Admin bounds its authoritative Team reset call at 180 seconds; the client must outlast it.
const ADMIN_RESET_TIMEOUT: Duration = Duration::from_secs(210);
const ADMIN_SESSION_TIMEOUT: Duration = Duration::from_secs(5);
const RESET_INCOMPLETE: &str = "the Space reset did not complete; re-run shimpz reset";
const STOP_PROGRESS: [&str; 3] = [
    "Checking the Shimpz Space...",
    "Stopping the Shimpz Space...",
    "Verifying that the Shimpz Space is fully stopped...",
];

pub(crate) fn install(options: &SpaceInstall) -> Result<String, String> {
    if let Some(profile) = options.print_graph {
        return Ok(graph::render(match profile {
            GraphProfile::LinuxLuks => StorageProfile::LinuxLuks,
            GraphProfile::ManagedDisk => StorageProfile::ManagedDisk,
        }));
    }
    let context = Context::open(false)?;
    let _lock = (!options.candidate)
        .then(|| Lock::acquire(&context.paths))
        .transpose()?;
    context.install(options.release.as_deref())
}

pub(crate) fn start(options: &SpaceStart) -> Result<String, String> {
    let context = Context::open(options.scheduled)?;
    let _lock = (!options.candidate)
        .then(|| Lock::acquire(&context.paths))
        .transpose()?;
    context.start(options)
}

pub(crate) fn status() -> Result<String, String> {
    let paths = Paths::discover()?;
    if !paths.marker_is_current()? {
        return Ok(status_report::not_installed().into());
    }
    validate_install_home(&paths)?;
    let Some(_lock) = Lock::try_acquire(&paths)? else {
        return Ok(status_report::operation_in_progress().into());
    };
    let profile = host::detect()?;
    let engine = Engine::connect(profile, &paths)?;
    let installed = state::read_installed(&paths, profile)?;
    let stopped = state::stopped(&paths)?;
    let graph_current = installed_graph_is_current(&paths, profile)?;
    let inventory = Inventory::inspect(&engine, &paths, profile.storage())?;
    let snapshot = runtime_snapshot(&engine, &inventory)?;
    status_report::render(
        &installed,
        graph_current,
        stopped,
        &snapshot.components,
        &snapshot.assistants,
    )
}

fn installed_graph_is_current(paths: &Paths, profile: HostProfile) -> Result<bool, String> {
    let expected = graph::render(profile.storage());
    match fs::read_to_string(&paths.compose) {
        Ok(actual) => Ok(actual == expected),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("could not read the installed Local graph: {error}")),
    }
}

fn runtime_snapshot(engine: &Engine, inventory: &Inventory) -> Result<RuntimeSnapshot, String> {
    let components = status_report::COMPONENTS
        .iter()
        .copied()
        .map(|component| {
            let record = engine.run_output([
                "inspect",
                "--type=container",
                "--format",
                "{{index .Config.Labels \"com.docker.compose.service\"}}|{{.State.Status}}|{{with .State.Health}}{{.Status}}{{end}}|{{.State.ExitCode}}",
                component.docker_name(),
            ]);
            status_report::observe(component, record.as_deref().ok())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let present = components
        .iter()
        .filter(|observation| observation.is_present())
        .count();
    if present != inventory.project_containers.len() {
        return Err("Docker returned an inconsistent Local runtime snapshot".into());
    }
    let assistants = inventory
        .assistant_containers()
        .into_iter()
        .map(|identifier| {
            let record = engine.run_output([
                "inspect",
                "--type=container",
                "--format",
                "{{.State.Status}}|{{.State.ExitCode}}",
                identifier,
            ])?;
            status_report::observe_assistant(&record)
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(RuntimeSnapshot {
        components,
        assistants,
    })
}

fn stop_absent(paths: &Paths) -> Result<String, String> {
    let profile = host::detect()?;
    let engine = Engine::connect(profile, paths)?;
    let inventory = Inventory::inspect(&engine, paths, profile.storage())?;
    let residue = unmarked_runtime_entries(paths)?;
    validate_unmarked_bin(paths)?;
    if inventory.empty() && residue.is_empty() {
        Ok("Shimpz Space is not installed. No change was needed.\nNext: shimpz install".into())
    } else {
        Err("Shimpz Space is not installed, but Local residue remains; run shimpz install for bounded recovery".into())
    }
}

pub(crate) fn stop() -> Result<String, String> {
    let paths = Paths::discover()?;
    validate_existing_install_home(&paths)?;
    let _lock = Lock::acquire(&paths)?;
    output::progress(STOP_PROGRESS[0]);
    if !paths.marker_is_current()? {
        return stop_absent(&paths);
    }
    Context::open(false)?.stop()
}

pub(crate) fn reset() -> Result<String, String> {
    let context = Context::open(false)?;
    let _lock = Lock::acquire(&context.paths)?;
    context.reset()
}

struct Context {
    paths: Paths,
    profile: HostProfile,
    engine: Engine,
    scheduled: bool,
}

struct RuntimeSnapshot {
    components: Vec<status_report::Observation>,
    assistants: Vec<status_report::AssistantObservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdminAttestation {
    Running { port: u16 },
    Stopped,
    Absent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApplyOutcome {
    Ready { port: u16 },
    Locked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdminPasswordState {
    Uninitialized,
    Configured,
    RecoveryRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailedReleaseDecision {
    UseSelected,
    ResumeInstalled,
    KeepRunning,
}

impl Context {
    fn open(scheduled: bool) -> Result<Self, String> {
        let paths = Paths::discover()?;
        validate_install_home(&paths)?;
        let profile = host::detect()?;
        let engine = Engine::connect(profile, &paths)?;
        Ok(Self {
            paths,
            profile,
            engine,
            scheduled,
        })
    }

    fn install(&self, exact_release: Option<&str>) -> Result<String, String> {
        let marker = self.paths.marker_is_current()?;
        if !marker {
            adopt_unmarked_home(&self.paths)?;
        }
        let inventory = Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?;
        let installed = if marker {
            match self
                .installed_state()
                .and_then(|installed| self.validate_installation_storage(installed))
            {
                Ok(installed) => Some(installed),
                Err(reason) => {
                    self.recover_corrupt(&inventory, &reason)?;
                    None
                }
            }
        } else {
            if !inventory.empty() {
                return Err(
                    "refusing to install over Docker resources without the exact Local marker"
                        .into(),
                );
            }
            None
        };
        let release = self
            .engine
            .resolve_release(exact_release, &self.paths.home)?;
        if exact_release.is_none() && self.handoff_if_needed(&release, false)? {
            return Ok("The release-bound CLI completed the installation.".into());
        }
        if let Some(recommendation) = self
            .profile
            .disk_encryption_recommendation(installed.is_none())
        {
            output::warning(recommendation);
        }
        self.apply(&release, installed.as_ref(), false, false)
    }

    fn validate_installation_storage(&self, installed: Installed) -> Result<Installed, String> {
        if self.profile == HostProfile::Linux
            && (!self.paths.security.exists() || linux::incomplete(&self.paths)?)
        {
            return Err("the encrypted Local storage transaction was interrupted".into());
        }
        Ok(installed)
    }

    fn start(&self, options: &SpaceStart) -> Result<String, String> {
        if !self.paths.marker_is_current()? {
            return Err("Shimpz Space is not installed; run shimpz install".into());
        }
        let installed = self.installed_state()?;
        Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?;
        let stopped = state::stopped(&self.paths)?;
        if options.scheduled && stopped {
            return Ok("Shimpz Space is stopped.\nNext: shimpz start".into());
        }
        let mut release = self
            .engine
            .resolve_release(options.release.as_deref(), &self.paths.home)?;
        let selected_failed = options.release.is_none()
            && state::failed_release_matches(&self.paths, &release.reference)?;
        let preserve_failed_release = match failed_release_decision(stopped, selected_failed) {
            FailedReleaseDecision::UseSelected => false,
            FailedReleaseDecision::ResumeInstalled => {
                release = self
                    .engine
                    .resolve_release(Some(&installed.release_ref), &self.paths.home)?;
                true
            }
            FailedReleaseDecision::KeepRunning => {
                return Ok("The selected Local release previously failed health; the current Space remains unchanged.".into());
            }
        };
        if options.release.is_none()
            && !preserve_failed_release
            && self.handoff_if_needed(&release, options.scheduled)?
        {
            return Ok("The release-bound CLI completed reconciliation.".into());
        }
        if options.candidate && options.release.is_none() {
            return Err("a candidate start requires an exact release".into());
        }
        self.apply(
            &release,
            Some(&installed),
            options.scheduled,
            preserve_failed_release,
        )
    }

    fn stop(&self) -> Result<String, String> {
        if !self.paths.marker_is_current()? {
            return Err("Shimpz Space is not installed; run shimpz install".into());
        }
        let installed = state::read_installed(&self.paths, self.profile)?;
        state::stopped(&self.paths)?;
        let inventory = Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?;
        state::write_stopped(&self.paths)?;
        output::progress(STOP_PROGRESS[1]);
        self.stop_owned_containers(&inventory)?;
        output::progress(STOP_PROGRESS[2]);
        let stopped_inventory =
            Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?;
        let snapshot = runtime_snapshot(&self.engine, &stopped_inventory)?;
        if !status_report::fully_stopped(&snapshot.components, &snapshot.assistants)? {
            return Err(status_report::incomplete_stop_error(
                &snapshot.components,
                &snapshot.assistants,
            )?);
        }
        status_report::render(
            &installed,
            installed_graph_is_current(&self.paths, self.profile)?,
            true,
            &snapshot.components,
            &snapshot.assistants,
        )
    }

    fn apply(
        &self,
        release: &ResolvedRelease,
        installed: Option<&Installed>,
        scheduled: bool,
        preserve_failed_release: bool,
    ) -> Result<String, String> {
        validate_forward_release(release, installed)?;
        verify_running_cli(release, self.profile)?;
        output::progress("Downloading Shimpz Space (1/4): Admin...");
        self.engine
            .pull_exact(&release.metadata.admin, ADMIN_REPOSITORY)?;
        output::progress("Downloading Shimpz Space (2/4): Team...");
        self.engine
            .pull_exact(&release.metadata.team, TEAM_REPOSITORY)?;
        output::progress("Downloading Shimpz Space (3/4): Brain...");
        self.engine
            .pull_exact(&release.metadata.brain, BRAIN_REPOSITORY)?;
        output::progress("Downloading Shimpz Space (4/4): network boundaries...");
        self.engine
            .pull_exact(&release.metadata.egress, EGRESS_REPOSITORY)?;
        let space_id = match installed {
            Some(installed) => installed.space_id.clone(),
            None => state::random_space_id()?,
        };
        let fresh = installed.is_none();
        if fresh {
            state::write_marker(&self.paths)?;
        }
        let outcome = match self.apply_owned(
            release,
            installed,
            scheduled,
            &space_id,
            preserve_failed_release,
        ) {
            Ok(outcome) => outcome,
            Err(error) if fresh => match self.compensate_fresh_failure(&space_id) {
                Ok(()) => return Err(error),
                Err(cleanup) => {
                    return Err(format!(
                        "{error}; fresh-install compensation also failed: {cleanup}"
                    ));
                }
            },
            Err(error) => return Err(error),
        };
        let ApplyOutcome::Ready { port } = outcome else {
            return Ok("Encrypted Local storage is locked. No workloads were started.".into());
        };
        let ready = ready_outcome(release, port);
        scheduler_outcome(
            ready,
            scheduler::install(self.profile, &self.paths, scheduled),
        )
    }

    fn apply_owned(
        &self,
        release: &ResolvedRelease,
        installed: Option<&Installed>,
        scheduled: bool,
        space_id: &str,
        preserve_failed_release: bool,
    ) -> Result<ApplyOutcome, String> {
        match self.ensure_storage(space_id, installed.is_none(), scheduled)? {
            linux::Admission::Locked => {
                return Ok(ApplyOutcome::Locked);
            }
            linux::Admission::Verified => {}
        }
        let port = state::selected_port(installed)?;
        let (docker_socket, docker_gid) = self
            .engine
            .controller_socket(self.profile, &release.metadata.team)?;
        let previous = installed
            .map(|_| backup_current(&self.paths, self.profile))
            .transpose()?;
        state::write_environment(
            &self.paths,
            &Environment {
                release,
                profile: self.profile,
                space_id,
                port,
                docker_gid,
                docker_socket: &docker_socket,
                cpuset: &self.engine.cpuset,
                secure_root: &self.paths.pool_mount,
            },
        )?;
        state::write_private(&self.paths.compose, &graph::render(self.profile.storage()))?;
        state::clear_stopped(&self.paths)?;
        output::progress("Starting the Shimpz Space...");
        let started = self.engine.compose(
            &self.paths,
            [
                "up",
                "-d",
                "--wait",
                "--wait-timeout",
                "120",
                "--no-build",
                "--pull",
                "never",
                "--remove-orphans",
            ],
        )?;
        if !started.success() {
            return match self.rollback(release, space_id, previous) {
                Ok(outcome) | Err(outcome) => Err(outcome),
            };
        }
        if let Err(storage_error) = self.validate_started_storage(space_id) {
            let rollback = self.rollback(release, space_id, previous);
            return match rollback {
                Ok(outcome) | Err(outcome) => Err(format!("{storage_error}; {outcome}")),
            };
        }
        output::progress("Verifying Supervisor password compatibility...");
        let was_upgrade = previous.is_some();
        let password_error = match admin_password_state(port) {
            Ok(AdminPasswordState::RecoveryRequired) if was_upgrade => Some(
                "the selected release cannot use the existing Supervisor password record; run shimpz reset, then shimpz install"
                    .to_owned(),
            ),
            Ok(AdminPasswordState::RecoveryRequired) => Some(
                "the fresh release returned an invalid Supervisor password state; retry shimpz install"
                    .to_owned(),
            ),
            Ok(AdminPasswordState::Uninitialized | AdminPasswordState::Configured) => None,
            Err(error) => Some(error),
        };
        if let Some(password_error) = password_error {
            let rollback = self.rollback(release, space_id, previous);
            return match rollback {
                Ok(outcome) | Err(outcome) => Err(format!("{password_error}; {outcome}")),
            };
        }
        let status =
            state::write_status(&self.paths, release, release_outcome(release, installed))?;
        if self
            .engine
            .project_release_status(&release.metadata.admin, status.as_bytes())
            .is_err()
        {
            return match self.rollback(release, space_id, previous) {
                Ok(outcome) | Err(outcome) => Err(outcome),
            };
        }
        remove_backup(previous)?;
        finish_failed_release_memory(&self.paths, preserve_failed_release)?;
        Ok(ApplyOutcome::Ready { port })
    }

    fn reset(&self) -> Result<String, String> {
        let marker = self.paths.marker_is_current()?;
        let inventory = Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?;
        let stopped = state::stopped(&self.paths)?;
        if !marker && inventory.empty() && !self.paths.security.exists() {
            let scheduler = scheduler::remove(self.profile, &self.paths)?;
            let mut preserved = self.remove_files()?;
            preserved.extend(scheduler.preserved);
            return Ok(reset_outcome(
                true,
                &preserved,
                scheduler.execution_unverified,
            ));
        }
        let installed = if marker {
            self.current_installation().ok()
        } else {
            None
        };
        if !inventory.empty() && installed.is_none() {
            return Err(
                "the current Local Space cannot be authenticated safely; run shimpz install for bounded recovery"
                    .into(),
            );
        }
        scheduler::preflight_remove(self.profile, &self.paths)?;
        if !inventory.empty()
            && let Some(current) = &installed
        {
            self.start_admin_for_reset()
                .map_err(|error| self.reset_failure(error, stopped))?;
            admin_reset(current.port).map_err(|error| self.reset_failure(error, stopped))?;
        }
        let remaining = Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?;
        remaining.remove(&self.engine)?;
        if self.profile == HostProfile::Linux && self.paths.security.exists() {
            let space_id = installed
                .map(|current| current.space_id)
                .or(inventory.space_id);
            linux::reset(&self.paths, space_id.as_deref())?;
        }
        let scheduler = scheduler::remove(self.profile, &self.paths)?;
        let mut preserved = self.remove_files()?;
        preserved.extend(scheduler.preserved);
        Ok(reset_outcome(
            false,
            &preserved,
            scheduler.execution_unverified,
        ))
    }

    fn current_installation(&self) -> Result<Installed, String> {
        let installed = self.installed_state()?;
        if !installed_graph_is_current(&self.paths, self.profile)? {
            return Err("the installed Local graph is not current".into());
        }
        Ok(installed)
    }

    fn installed_state(&self) -> Result<Installed, String> {
        state::stopped(&self.paths)?;
        state::read_installed(&self.paths, self.profile)
    }

    fn stop_owned_containers(&self, inventory: &Inventory) -> Result<(), String> {
        let mut identifiers = inventory.container_ids();
        if let Some(team_id) = inventory.team_container_id(&self.engine)?
            && let Ok(index) = identifiers.binary_search(&team_id)
        {
            let team = vec![identifiers.remove(index)];
            self.engine.stop_containers(&team)?;
        }
        self.engine.stop_containers(&identifiers)
    }

    fn reset_failure(&self, error: String, was_stopped: bool) -> String {
        if !was_stopped {
            return error;
        }
        match self.restore_stopped_after_reset_failure() {
            Ok(()) => error,
            Err(stop_error) => {
                format!("{error}; the stopped Space could not be restored: {stop_error}")
            }
        }
    }

    fn restore_stopped_after_reset_failure(&self) -> Result<(), String> {
        let inventory = Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?;
        self.stop_owned_containers(&inventory)?;
        let stopped = Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?;
        let snapshot = runtime_snapshot(&self.engine, &stopped)?;
        if status_report::fully_stopped(&snapshot.components, &snapshot.assistants)? {
            Ok(())
        } else {
            Err("the Space stop is incomplete; re-run shimpz stop".into())
        }
    }

    fn validate_started_storage(&self, space_id: &str) -> Result<(), String> {
        if self.profile == HostProfile::Linux {
            linux::Pool::new(&self.paths, space_id)?.validate_mounted()
        } else {
            Ok(())
        }
    }

    fn recover_corrupt(&self, inventory: &Inventory, reason: &str) -> Result<(), String> {
        if self.scheduled {
            return Err(reason.into());
        }
        let admin = self.prepare_admin_for_recovery()?;
        let names = inventory.container_names(&self.engine)?;
        let confirmed = recovery_prompt(reason, inventory, &names)?;
        if !confirmed {
            return Err("the corrupt Local Space was preserved; nothing changed".into());
        }
        let admin_port = match admin {
            AdminAttestation::Running { port } if admin_available(port) => Some(port),
            _ => None,
        };
        if let Some(port) = admin_port {
            admin_reset(port)?;
        }
        let space_id = inventory.space_id.clone();
        let remaining = if admin_port.is_some() {
            Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?
        } else {
            inventory.clone()
        };
        remaining.remove(&self.engine)?;
        if self.profile == HostProfile::Linux && self.paths.security.exists() {
            linux::reset(&self.paths, space_id.as_deref())?;
        }
        remove_runtime_files(&self.paths)?;
        match scheduler::remove(self.profile, &self.paths) {
            Ok(outcome) if outcome.execution_unverified => output::warning(&format!(
                "Preserved unrecognized scheduler entries; their execution state is unverified: {}",
                outcome.preserved.join(", ")
            )),
            Ok(_) => {}
            Err(error) => output::warning(&format!(
                "The corrupt Space was removed, but its scheduler cleanup could not be completed: {error}"
            )),
        }
        output::info("Corrupt Local Space removed; continuing with a fresh installation.");
        Ok(())
    }

    fn ensure_storage(
        &self,
        space_id: &str,
        fresh: bool,
        scheduled: bool,
    ) -> Result<linux::Admission, String> {
        match self.profile {
            HostProfile::Linux => linux::Pool::new(&self.paths, space_id)?.ensure(fresh, scheduled),
            HostProfile::MacOs | HostProfile::Wsl => Ok(linux::Admission::Verified),
        }
    }

    fn handoff_if_needed(
        &self,
        release: &ResolvedRelease,
        scheduled: bool,
    ) -> Result<bool, String> {
        let running = std::env::current_exe().map_err(|_| "the running CLI path is unavailable")?;
        reconcile_previous_cli(&self.paths.managed_cli, &running)?;
        let expected = expected_cli_hash(release, self.profile);
        if hash_file(&running)? == expected {
            return Ok(false);
        }
        let bin = self
            .paths
            .managed_cli
            .parent()
            .ok_or_else(|| "the managed CLI directory is invalid".to_owned())?;
        fs::create_dir_all(bin).map_err(io_error)?;
        fs::set_permissions(bin, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
        let candidate = self.paths.managed_cli.with_extension("candidate");
        if candidate.exists() {
            fs::remove_file(&candidate).map_err(io_error)?;
        }
        self.engine
            .extract_cli(&release.reference, self.profile, &candidate)?;
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
        if hash_file(&candidate)? != expected {
            fs::remove_file(&candidate).map_err(io_error)?;
            return Err("the extracted CLI hash does not match the atomic release".into());
        }
        let previous = self.paths.managed_cli.with_extension("previous");
        if self.paths.managed_cli.exists() {
            validate_private_cli(&self.paths.managed_cli)?;
            fs::rename(&self.paths.managed_cli, &previous).map_err(io_error)?;
        }
        if let Err(error) = fs::rename(&candidate, &self.paths.managed_cli) {
            restore_previous_cli(&self.paths.managed_cli, &previous)?;
            return Err(io_error(error));
        }
        let mut command = Command::new(&self.paths.managed_cli);
        if self.paths.marker.exists() {
            command.arg("start");
            if scheduled {
                command.arg("--scheduled");
            }
            command
                .arg("--release")
                .arg(&release.reference)
                .arg("--candidate");
        } else {
            command
                .arg("install")
                .arg("--release")
                .arg(&release.reference)
                .arg("--candidate");
        }
        let status = command
            .stdin(Stdio::null())
            .status()
            .map_err(|error| format!("could not start the release-bound CLI: {error}"));
        let completed = status.is_ok_and(|status| status.success());
        if !completed {
            restore_previous_cli(&self.paths.managed_cli, &previous)?;
            return Err(
                "the release-bound CLI did not complete; the previous CLI was restored".into(),
            );
        }
        remove_regular_if_present(&previous)?;
        ensure_public_cli(&self.paths)?;
        Ok(true)
    }

    fn rollback(
        &self,
        release: &ResolvedRelease,
        space_id: &str,
        backup: Option<Backup>,
    ) -> Result<String, String> {
        let _ = self
            .engine
            .compose(&self.paths, ["down", "--remove-orphans"]);
        let Some(backup) = backup else {
            return match self.compensate_fresh_failure(space_id) {
                Ok(()) => Err(
                    "the fresh Local release did not become healthy; its partial state was removed, so installation can be retried"
                        .into(),
                ),
                Err(cleanup) => Err(format!(
                    "the fresh Local release did not become healthy; compensation also failed: {cleanup}"
                )),
            };
        };
        let memory_error = state::remember_failed_release(&self.paths, release).err();
        fs::rename(&backup.compose, &self.paths.compose).map_err(io_error)?;
        fs::rename(&backup.environment, &self.paths.environment).map_err(io_error)?;
        let installed = state::read_installed(&self.paths, self.profile)?;
        match self.ensure_storage(&installed.space_id, false, self.scheduled)? {
            linux::Admission::Verified => {}
            linux::Admission::Locked => {
                state::write_status(&self.paths, release, "rollback-needed")?;
                if memory_error.is_some() {
                    return Err(format!(
                        "the previous release remained stopped because storage was locked, and {}",
                        self.disable_automatic_updates()
                    ));
                }
                return Err(
                    "the update failed; the previous release remained stopped because encrypted storage was locked"
                        .into(),
                );
            }
        }
        let restored = self.engine.compose(
            &self.paths,
            [
                "up",
                "-d",
                "--wait",
                "--wait-timeout",
                "120",
                "--no-build",
                "--pull",
                "never",
                "--remove-orphans",
            ],
        )?;
        let status = state::write_status(&self.paths, release, "rollback-needed")?;
        if restored.success()
            && self
                .engine
                .project_release_status(&release.metadata.admin, status.as_bytes())
                .is_err()
        {
            output::warning(
                "the previous release was restored, but Admin could not receive the rollback status",
            );
        }
        if memory_error.is_some() {
            return Err(format!(
                "the previous release was restored, but {}",
                self.disable_automatic_updates()
            ));
        }
        if restored.success() {
            Err("the update failed; the previous healthy release was restored".into())
        } else {
            Err("the update and its rollback both failed".into())
        }
    }

    fn disable_automatic_updates(&self) -> String {
        match scheduler::remove(self.profile, &self.paths) {
            Ok(outcome) if outcome.execution_unverified => format!(
                "automatic retry could not be proven disabled because unrecognized scheduler entries were preserved: {}",
                outcome.preserved.join(", ")
            ),
            Ok(_) => {
                "automatic updates were disabled because the failed release could not be remembered"
                    .into()
            }
            Err(error) => format!(
                "automatic retry could not be disabled because scheduler cleanup failed: {error}"
            ),
        }
    }

    fn compensate_fresh_failure(&self, space_id: &str) -> Result<(), String> {
        let inventory = Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?;
        inventory.remove(&self.engine)?;
        let remaining = Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?;
        if !remaining.empty() {
            return Err("managed Docker residue remains after fresh-install compensation".into());
        }
        if self.profile == HostProfile::Linux && self.paths.security.exists() {
            linux::reset(&self.paths, Some(space_id))?;
        }
        remove_runtime_files(&self.paths)
    }

    fn start_admin_for_reset(&self) -> Result<(), String> {
        if state::stopped(&self.paths)? {
            output::progress("Starting the Shimpz Space for reset authorization...");
            let started = self.engine.compose(
                &self.paths,
                [
                    "up",
                    "-d",
                    "--wait",
                    "--wait-timeout",
                    "120",
                    "--no-build",
                    "--pull",
                    "never",
                    "--remove-orphans",
                ],
            )?;
            if !started.success() {
                return Err("the stopped Space could not start for reset authorization".into());
            }
        }
        self.start_container_if_present("shimpz-team")?;
        let mut attestation = self.admin_attestation()?;
        if attestation == AdminAttestation::Stopped {
            let status = self
                .engine
                .run_quiet_status("Docker Admin container start", ["start", "shimpz-admin"])?;
            if !status.success() {
                return Err("the owned Admin container could not be started".into());
            }
            attestation = self.admin_attestation()?;
        }
        let expected = state::read_installed(&self.paths, self.profile)?.port;
        if attestation == (AdminAttestation::Running { port: expected })
            && admin_available(expected)
        {
            return Ok(());
        }
        Err("the Local Supervisor is unavailable; run shimpz install for bounded recovery".into())
    }

    fn prepare_admin_for_recovery(&self) -> Result<AdminAttestation, String> {
        let mut attestation = self.admin_attestation()?;
        if attestation == AdminAttestation::Absent {
            return Ok(attestation);
        }
        if self.start_container_if_present("shimpz-team").is_err() {
            output::info(
                "Admin could not be started; confirmed recovery will use owned-resource cleanup.",
            );
            return Ok(AdminAttestation::Stopped);
        }
        if attestation == AdminAttestation::Stopped {
            let started = self
                .engine
                .run_quiet_status(
                    "Docker Admin container recovery start",
                    ["start", "shimpz-admin"],
                )
                .is_ok_and(|status| status.success());
            if !started {
                output::info(
                    "Admin could not be started; confirmed recovery will use owned-resource cleanup.",
                );
                return Ok(AdminAttestation::Stopped);
            }
            attestation = self.admin_attestation()?;
        }
        Ok(attestation)
    }

    fn start_container_if_present(&self, name: &str) -> Result<(), String> {
        let state = self.engine.run_output([
            "inspect",
            "--type=container",
            "--format",
            "{{.State.Running}}",
            name,
        ]);
        match state.as_deref().map(str::trim) {
            Err(_) | Ok("true") => Ok(()),
            Ok("false") => {
                let status = self
                    .engine
                    .run_quiet_status("Docker owned container start", ["start", name])?;
                if status.success() {
                    Ok(())
                } else {
                    Err(format!("the owned container could not be started: {name}"))
                }
            }
            Ok(_) => Err(format!("the owned container state is malformed: {name}")),
        }
    }

    fn admin_attestation(&self) -> Result<AdminAttestation, String> {
        let record = self.engine.run_output([
            "inspect",
            "--type=container",
            "--format",
            "{{.State.Running}}|{{index .Config.Labels \"com.docker.compose.project\"}}|{{index .Config.Labels \"com.docker.compose.service\"}}|{{json .HostConfig.PortBindings}}",
            "shimpz-admin",
        ]);
        match record {
            Ok(record) => parse_admin_attestation(&record),
            Err(_) => Ok(AdminAttestation::Absent),
        }
    }

    fn remove_files(&self) -> Result<Vec<String>, String> {
        remove_runtime_files(&self.paths)?;
        remove_regular_if_present(&self.paths.managed_cli.with_extension("candidate"))?;
        remove_regular_if_present(&self.paths.managed_cli.with_extension("previous"))?;
        let mut preserved = PathReport::default();
        if self.paths.home.exists() {
            for entry in fs::read_dir(&self.paths.home).map_err(io_error)? {
                let path = entry.map_err(io_error)?.path();
                if path
                    == self
                        .paths
                        .managed_cli
                        .parent()
                        .expect("managed CLI has a parent")
                {
                    validate_unmarked_bin(&self.paths)?;
                } else {
                    preserved.record(path);
                }
            }
        }
        Ok(preserved.into_strings())
    }
}

fn remove_runtime_files(paths: &Paths) -> Result<(), String> {
    for path in [
        paths.compose.clone(),
        paths.environment.clone(),
        paths.status.clone(),
        paths.failed_release.clone(),
        paths.stopped.clone(),
        paths.compose.with_extension("previous"),
        paths.environment.with_extension("previous"),
        paths.compose.with_extension("tmp"),
        paths.environment.with_extension("tmp"),
        paths.status.with_extension("tmp"),
        paths.failed_release.with_extension("tmp"),
        paths.stopped.with_extension("tmp"),
        paths.home.join("release.env.tmp"),
        paths.marker.with_extension("tmp"),
        paths.marker.clone(),
    ] {
        remove_regular_if_present(&path)?;
    }
    Ok(())
}

fn release_outcome(release: &ResolvedRelease, installed: Option<&Installed>) -> &'static str {
    if installed.is_some_and(|current| current.release_ref == release.reference) {
        "current"
    } else {
        "updated"
    }
}

fn ready_outcome(release: &ResolvedRelease, port: u16) -> String {
    format!(
        "Shimpz Space is ready.\nAdmin: http://127.0.0.1:{port}\nRelease: ordinal {}\nNext: open the Admin address above.",
        release.metadata.ordinal
    )
}

fn scheduler_outcome(
    ready: String,
    outcome: Result<scheduler::InstallOutcome, String>,
) -> Result<String, String> {
    match outcome {
        Ok(scheduler::InstallOutcome::Enabled) => Ok(ready),
        Ok(scheduler::InstallOutcome::Preserved(paths)) => Ok(format!(
            "{ready}\nAutomatic Local updates were not enabled because these scheduler entries are not managed by Shimpz: {}. Their execution state is unverified. Remove or rename only those entries, then run shimpz start.",
            paths.join(", ")
        )),
        Err(error) => Err(format!(
            "{ready}\nThe Space is healthy, but automatic Local updates were not enabled: {error}. Resolve the exact scheduler entry or directory, then run shimpz start."
        )),
    }
}

fn reset_outcome(
    already_reset: bool,
    preserved: &[String],
    scheduler_execution_unverified: bool,
) -> String {
    let action = if already_reset {
        "Shimpz Space was reset successfully. No change was needed."
    } else {
        "Shimpz Space was reset successfully."
    };
    let suffix = if preserved.is_empty() {
        "No managed Space data remains; the shimpz command and lifecycle lock are retained."
            .to_owned()
    } else {
        format!("Preserved unrecognized content: {}", preserved.join(", "))
    };
    let scheduler = if scheduler_execution_unverified {
        " Scheduler execution state is unverified; run shimpz install from an interactive terminal to review the preserved entry."
    } else {
        ""
    };
    format!("{action} {suffix}{scheduler}")
}

#[derive(Debug)]
struct Backup {
    compose: PathBuf,
    environment: PathBuf,
}

fn backup_current(paths: &Paths, profile: HostProfile) -> Result<Backup, String> {
    let compose = paths.compose.with_extension("previous");
    let environment = paths.environment.with_extension("previous");
    state::write_private(&compose, &graph::render(profile.storage()))?;
    fs::copy(&paths.environment, &environment).map_err(io_error)?;
    Ok(Backup {
        compose,
        environment,
    })
}

const REPORTED_ENTRIES: usize = 8;

#[derive(Default)]
struct PathReport {
    named: Vec<PathBuf>,
    total: usize,
}

impl PathReport {
    fn record(&mut self, path: PathBuf) {
        self.total += 1;
        let index = self
            .named
            .binary_search(&path)
            .unwrap_or_else(|index| index);
        self.named.insert(index, path);
        self.named.truncate(REPORTED_ENTRIES);
    }

    fn is_empty(&self) -> bool {
        self.total == 0
    }

    fn render(&self) -> String {
        let mut rendered = self
            .named
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        if self.total > self.named.len() {
            use std::fmt::Write as _;
            write!(
                &mut rendered,
                ", and {} more",
                self.total - self.named.len()
            )
            .expect("String writes are infallible");
        }
        rendered
    }

    fn into_strings(self) -> Vec<String> {
        let hidden = self.total.saturating_sub(self.named.len());
        let mut rendered = self
            .named
            .into_iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        if hidden > 0 {
            rendered.push(format!("and {hidden} more unrecognized entries"));
        }
        rendered
    }
}

fn validate_install_home(paths: &Paths) -> Result<(), String> {
    if paths.home.exists() {
        validate_existing_install_home(paths)?;
    } else {
        fs::create_dir(&paths.home).map_err(io_error)?;
        fs::set_permissions(&paths.home, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    Ok(())
}

fn validate_existing_install_home(paths: &Paths) -> Result<(), String> {
    if !paths.home.exists() {
        return Ok(());
    }
    let metadata = paths.home.symlink_metadata().map_err(io_error)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("refusing to use an invalid Local Space directory".into());
    }
    Ok(())
}

fn adopt_unmarked_home(paths: &Paths) -> Result<(), String> {
    state::clear_stopped(paths)?;
    for temporary in [
        paths.home.join("release.env.tmp"),
        paths.marker.with_extension("tmp"),
    ] {
        remove_regular_if_present(&temporary)?;
    }
    let unowned = unmarked_runtime_entries(paths)?;
    if !unowned.is_empty() {
        return Err(format!(
            "refusing to use unowned Local Space entries under {}: {}; move or remove every unowned entry, then run shimpz install",
            paths.home.display(),
            unowned.render()
        ));
    }
    validate_unmarked_bin(paths)
}

fn unmarked_runtime_entries(paths: &Paths) -> Result<PathReport, String> {
    let mut entries = PathReport::default();
    if !paths.home.exists() {
        return Ok(entries);
    }
    let bin = paths
        .managed_cli
        .parent()
        .expect("managed CLI has a parent");
    for entry in fs::read_dir(&paths.home).map_err(io_error)? {
        let path = entry.map_err(io_error)?.path();
        if path != bin {
            entries.record(path);
        }
    }
    Ok(entries)
}

fn validate_unmarked_bin(paths: &Paths) -> Result<(), String> {
    let bin = paths
        .managed_cli
        .parent()
        .expect("managed CLI has a parent");
    if !bin.exists() {
        return Ok(());
    }
    let metadata = bin.symlink_metadata().map_err(io_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "the managed CLI directory is invalid: {}",
            bin.display()
        ));
    }
    let mut managed = Vec::with_capacity(3);
    let mut unowned = PathReport::default();
    for entry in fs::read_dir(bin).map_err(io_error)? {
        let path = entry.map_err(io_error)?.path();
        if path != paths.managed_cli
            && path != paths.managed_cli.with_extension("candidate")
            && path != paths.managed_cli.with_extension("previous")
        {
            unowned.record(path);
        } else {
            managed.push(path);
        }
    }
    if !unowned.is_empty() {
        return Err(format!(
            "refusing to use unowned managed CLI entries: {}; move or remove every unowned entry, then run shimpz install",
            unowned.render()
        ));
    }
    managed.sort();
    for path in managed {
        let metadata = path.symlink_metadata().map_err(io_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "the managed CLI artifact is invalid: {}",
                path.display()
            ));
        }
        if metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(format!(
                "the managed CLI artifact ownership or permissions are invalid: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn validate_private_cli(path: &Path) -> Result<(), String> {
    let metadata = path.symlink_metadata().map_err(io_error)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(format!(
            "the managed CLI artifact ownership or permissions are invalid: {}",
            path.display()
        ));
    }
    Ok(())
}

fn restore_previous_cli(managed: &Path, previous: &Path) -> Result<(), String> {
    remove_regular_if_present(managed)?;
    if previous.exists() {
        fs::rename(previous, managed).map_err(io_error)?;
    }
    Ok(())
}

fn reconcile_previous_cli(managed: &Path, running: &Path) -> Result<(), String> {
    let previous = managed.with_extension("previous");
    if !previous.exists() {
        return Ok(());
    }
    validate_private_cli(&previous)?;
    if !managed.exists() {
        fs::rename(previous, managed).map_err(io_error)?;
        return Ok(());
    }
    validate_private_cli(managed)?;
    if hash_file(managed)? != hash_file(running)? {
        return Err(
            "an interrupted CLI handoff remains; run the managed ~/.shimpz/bin/shimpz command directly"
                .into(),
        );
    }
    remove_regular_if_present(&previous)
}

fn ensure_public_cli(paths: &Paths) -> Result<(), String> {
    if paths.public_cli.exists() {
        let metadata = paths.public_cli.symlink_metadata().map_err(io_error)?;
        if metadata.file_type().is_symlink()
            && fs::read_link(&paths.public_cli).map_err(io_error)? == paths.managed_cli
        {
            return Ok(());
        }
        return Err("refusing to replace an unowned public shimpz command".into());
    }
    let parent = paths
        .public_cli
        .parent()
        .ok_or_else(|| "the public CLI directory is invalid".to_owned())?;
    if parent.exists() {
        let metadata = parent.symlink_metadata().map_err(io_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("the public CLI directory is invalid".into());
        }
    } else {
        fs::create_dir_all(parent).map_err(io_error)?;
    }
    symlink(&paths.managed_cli, &paths.public_cli).map_err(io_error)
}

fn parse_admin_attestation(record: &str) -> Result<AdminAttestation, String> {
    if record.len() > 4_096 || record.contains('\r') {
        return Err("the owned Admin listener attestation is malformed".into());
    }
    let mut lines = record.lines();
    let line = lines
        .next()
        .filter(|line| !line.is_empty() && lines.next().is_none())
        .ok_or_else(|| "the owned Admin listener attestation is malformed".to_owned())?;
    let fields: Vec<_> = line.splitn(4, '|').collect();
    if fields.len() != 4 || fields[1] != "shimpz-space" || fields[2] != "admin" {
        return Err("the owned Admin listener identity is invalid".into());
    }
    let binding_map = serde_json::from_str::<serde_json::Value>(fields[3])
        .map_err(|_| "the owned Admin listener binding is malformed".to_owned())?;
    let binding_map = binding_map
        .as_object()
        .filter(|bindings| bindings.len() == 1 && bindings.contains_key("4600/tcp"))
        .ok_or_else(|| "the owned Admin listener binding is invalid".to_owned())?;
    let bindings = binding_map["4600/tcp"]
        .as_array()
        .filter(|bindings| !bindings.is_empty() && bindings.len() <= 2)
        .ok_or_else(|| "the owned Admin listener binding is invalid".to_owned())?;
    let mut port = None;
    let mut ipv4 = false;
    for binding in bindings {
        let binding = binding
            .as_object()
            .filter(|binding| {
                binding.len() == 2
                    && binding.contains_key("HostIp")
                    && binding.contains_key("HostPort")
            })
            .ok_or_else(|| "the owned Admin listener binding is malformed".to_owned())?;
        let host = binding["HostIp"]
            .as_str()
            .filter(|host| matches!(*host, "127.0.0.1" | "::1"))
            .ok_or_else(|| "the owned Admin listener is not loopback-only".to_owned())?;
        let current = binding["HostPort"]
            .as_str()
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|value| *value >= 1024)
            .ok_or_else(|| "the owned Admin listener port is invalid".to_owned())?;
        if port.is_some_and(|expected| expected != current) || (host == "127.0.0.1" && ipv4) {
            return Err("the owned Admin listener binding is ambiguous".into());
        }
        port = Some(current);
        ipv4 |= host == "127.0.0.1";
    }
    if !ipv4 {
        return Err("the owned Admin listener has no IPv4 loopback binding".into());
    }
    match fields[0] {
        "true" => Ok(AdminAttestation::Running {
            port: port.expect("a valid binding has a port"),
        }),
        "false" => Ok(AdminAttestation::Stopped),
        _ => Err("the owned Admin container state is malformed".into()),
    }
}

fn validate_forward_release(
    release: &ResolvedRelease,
    installed: Option<&Installed>,
) -> Result<(), String> {
    let Some(installed) = installed else {
        return Ok(());
    };
    if release.metadata.ordinal < installed.ordinal
        || (release.metadata.ordinal == installed.ordinal
            && release.reference != installed.release_ref)
    {
        return Err("the Local release channel moved backward or became ambiguous".into());
    }
    Ok(())
}

fn expected_cli_hash(release: &ResolvedRelease, profile: HostProfile) -> &str {
    match profile {
        HostProfile::Linux | HostProfile::Wsl => &release.metadata.cli_linux_amd64_sha256,
        HostProfile::MacOs => &release.metadata.cli_macos_arm64_sha256,
    }
}

fn verify_running_cli(release: &ResolvedRelease, profile: HostProfile) -> Result<(), String> {
    let current = std::env::current_exe().map_err(|_| "the running CLI path is unavailable")?;
    if hash_file(&current)? == expected_cli_hash(release, profile) {
        Ok(())
    } else {
        Err("the running CLI is not bound to the selected Local release".into())
    }
}

fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(io_error)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 16 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(io_error)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn recovery_prompt(reason: &str, inventory: &Inventory, names: &[String]) -> Result<bool, String> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| "recovery requires an interactive terminal; nothing changed".to_owned())?;
    writeln!(tty, "The existing Local Space is corrupt: {reason}").map_err(io_error)?;
    writeln!(
        tty,
        "Owned scope: {} containers, {} volumes, {} networks",
        inventory.project_containers.len() + inventory.dynamic_containers.len(),
        inventory.project_volumes.len(),
        inventory.project_networks.len() + inventory.dynamic_networks.len()
    )
    .map_err(io_error)?;
    if !names.is_empty() {
        writeln!(tty, "Containers: {}", names.join(", ")).map_err(io_error)?;
    }
    loop {
        write!(
            tty,
            "Permanently remove this exact owned state and install a fresh Space? [Yes/No] "
        )
        .map_err(io_error)?;
        tty.flush().map_err(io_error)?;
        let mut answer = String::new();
        let mut byte = [0_u8; 1];
        while tty.read(&mut byte).map_err(io_error)? == 1 {
            if byte[0] == b'\n' {
                break;
            }
            if answer.len() >= 8 || byte[0].is_ascii_control() {
                return Err("the recovery answer is invalid; nothing changed".into());
            }
            answer.push(char::from(byte[0]));
        }
        match answer.as_str() {
            "Yes" => return Ok(true),
            "No" | "" => return Ok(false),
            _ => writeln!(tty, "Please answer exactly Yes or No.").map_err(io_error)?,
        }
    }
}

fn admin_password_state_response(
    status: u16,
    body: &serde_json::Value,
) -> Result<AdminPasswordState, String> {
    let invalid = || "Admin returned an invalid Local password-state contract".to_owned();
    if status != 200 {
        return Err(invalid());
    }
    let object = body.as_object().ok_or_else(invalid)?;
    if object.len() != 5
        || object.get("profile").and_then(serde_json::Value::as_str) != Some("local")
        || object
            .get("authenticated")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        || object
            .get("initialized")
            .and_then(serde_json::Value::as_bool)
            .is_none()
    {
        return Err(invalid());
    }
    let features = object
        .get("features")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid)?;
    if features.len() != 1
        || features
            .get("teamCredentials")
            .and_then(serde_json::Value::as_bool)
            .is_none()
    {
        return Err(invalid());
    }
    match (
        object
            .get("password_state")
            .and_then(serde_json::Value::as_str),
        object["initialized"].as_bool(),
    ) {
        (Some("uninitialized"), Some(false)) => Ok(AdminPasswordState::Uninitialized),
        (Some("configured"), Some(true)) => Ok(AdminPasswordState::Configured),
        (Some("recovery-required"), Some(true)) => Ok(AdminPasswordState::RecoveryRequired),
        _ => Err(invalid()),
    }
}

fn admin_password_state(port: u16) -> Result<AdminPasswordState, String> {
    let config = Agent::config_builder()
        .timeout_global(Some(ADMIN_SESSION_TIMEOUT))
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    let agent = Agent::new_with_config(config);
    let mut response = agent
        .post(format!("http://127.0.0.1:{port}/api/session"))
        .send_empty()
        .map_err(|_| "Admin did not provide the Local password-state contract".to_owned())?;
    let status = response.status().as_u16();
    let body: serde_json::Value = response
        .body_mut()
        .with_config()
        .limit(1_024)
        .read_json()
        .map_err(|_| "Admin returned an invalid Local password-state contract".to_owned())?;
    admin_password_state_response(status, &body)
}

fn admin_available(port: u16) -> bool {
    let config = Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(2)))
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    let agent = Agent::new_with_config(config);
    for _ in 0..30 {
        if agent
            .post(format!("http://127.0.0.1:{port}/api/session"))
            .send_empty()
            .is_ok_and(|response| response.status().as_u16() == 200)
        {
            return true;
        }
        thread::sleep(Duration::from_millis(500));
    }
    false
}

#[derive(Debug, Eq, PartialEq)]
enum AdminResetDecision {
    Complete,
    PasswordRequired,
}

fn admin_reset_decision(
    status: u16,
    body: &serde_json::Value,
) -> Result<AdminResetDecision, String> {
    if status == 200
        && body.as_object().is_some_and(|object| {
            object.len() == 1 && object.get("reset") == Some(&serde_json::Value::Bool(true))
        })
    {
        return Ok(AdminResetDecision::Complete);
    }
    if status == 409
        && body.get("code")
            == Some(&serde_json::Value::String(
                "supervisor-password-required".into(),
            ))
    {
        return Ok(AdminResetDecision::PasswordRequired);
    }
    if status == 409
        && body.get("code") == Some(&serde_json::Value::String("bootstrap-reset-refused".into()))
    {
        return Err(
            "Admin found inconsistent Supervisor state; nothing was deleted. Run shimpz install for bounded recovery"
                .into(),
        );
    }
    Err(RESET_INCOMPLETE.into())
}

fn bootstrap_admin_reset(port: u16) -> Result<AdminResetDecision, String> {
    let config = Agent::config_builder()
        .timeout_global(Some(ADMIN_RESET_TIMEOUT))
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    let agent = Agent::new_with_config(config);
    let request =
        ureq::http::Request::delete(format!("http://127.0.0.1:{port}/api/space/bootstrap"))
            .header("Content-Type", "application/json")
            .body("{}")
            .map_err(|_| "could not build the bootstrap Space reset".to_owned())?;
    let mut response = agent
        .run(request)
        .map_err(|_| RESET_INCOMPLETE.to_owned())?;
    let status = response.status().as_u16();
    let body: serde_json::Value = response
        .body_mut()
        .with_config()
        .limit(1_024)
        .read_json()
        .map_err(|_| RESET_INCOMPLETE.to_owned())?;
    admin_reset_decision(status, &body)
}

fn authenticated_reset_response(
    status: u16,
    body: Option<&serde_json::Value>,
) -> Result<(), String> {
    if status == 200
        && body.is_some_and(|body| {
            body.as_object().is_some_and(|object| {
                object.len() == 1 && object.get("reset") == Some(&serde_json::Value::Bool(true))
            })
        })
    {
        return Ok(());
    }
    Err(RESET_INCOMPLETE.into())
}

fn authenticated_login_response(status: u16) -> Result<(), String> {
    match status {
        200 => Ok(()),
        429 => Err(
            "too many Supervisor password attempts; wait one minute, then re-run shimpz reset"
                .into(),
        ),
        _ => Err("the Supervisor password was rejected".into()),
    }
}

fn admin_reset(port: u16) -> Result<(), String> {
    match bootstrap_admin_reset(port)? {
        AdminResetDecision::Complete => Ok(()),
        AdminResetDecision::PasswordRequired => authenticated_admin_reset(port),
    }
}

fn authenticated_admin_reset(port: u16) -> Result<(), String> {
    let password = Zeroizing::new(
        rpassword::prompt_password("Supervisor password: ")
            .map_err(|_| "could not read the Supervisor password".to_owned())?,
    );
    if password.is_empty() {
        return Err("the Supervisor password is required".into());
    }
    let config = Agent::config_builder()
        .timeout_global(Some(ADMIN_RESET_TIMEOUT))
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    let agent = Agent::new_with_config(config);
    let url = format!("http://127.0.0.1:{port}");
    let login = agent
        .post(format!("{url}/api/login"))
        .send_json(serde_json::json!({"password": password.as_str()}))
        .map_err(|_| "the Local Supervisor login is unavailable".to_owned())?;
    authenticated_login_response(login.status().as_u16())?;
    let cookie = login
        .headers()
        .get("set-cookie")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .filter(|value| value.starts_with("shimpz_admin="))
        .ok_or_else(|| "Admin returned an invalid Supervisor session".to_owned())?;
    let reset_body = serde_json::to_string(&serde_json::json!({"password": password.as_str()}))
        .map_err(|_| "could not encode the authenticated reset".to_owned())?;
    let request = ureq::http::Request::delete(format!("{url}/api/space"))
        .header("Cookie", cookie)
        .header("Content-Type", "application/json")
        .body(reset_body)
        .map_err(|_| "could not build the authenticated reset".to_owned())?;
    let mut response = agent
        .run(request)
        .map_err(|_| RESET_INCOMPLETE.to_owned())?;
    let status = response.status().as_u16();
    if status != 200 {
        return authenticated_reset_response(status, None);
    }
    let body: serde_json::Value = response
        .body_mut()
        .with_config()
        .limit(1_024)
        .read_json()
        .map_err(|_| RESET_INCOMPLETE.to_owned())?;
    authenticated_reset_response(status, Some(&body))
}

fn remove_backup(backup: Option<Backup>) -> Result<(), String> {
    if let Some(backup) = backup {
        fs::remove_file(backup.compose).map_err(io_error)?;
        fs::remove_file(backup.environment).map_err(io_error)?;
    }
    Ok(())
}

fn finish_failed_release_memory(paths: &Paths, preserve: bool) -> Result<(), String> {
    if preserve {
        Ok(())
    } else {
        remove_regular_if_present(&paths.failed_release)
    }
}

fn failed_release_decision(stopped: bool, selected_failed: bool) -> FailedReleaseDecision {
    match (stopped, selected_failed) {
        (_, false) => FailedReleaseDecision::UseSelected,
        (true, true) => FailedReleaseDecision::ResumeInstalled,
        (false, true) => FailedReleaseDecision::KeepRunning,
    }
}

fn remove_regular_if_present(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = path.symlink_metadata().map_err(io_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "refusing to remove invalid managed file: {}",
            path.display()
        ));
    }
    fs::remove_file(path).map_err(io_error)
}

fn io_error(error: std::io::Error) -> String {
    let message = format!("Local lifecycle operation failed: {error}");
    drop(error);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::release::Release;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn release(ordinal: u64, digest: char) -> ResolvedRelease {
        ResolvedRelease {
            reference: format!(
                "ghcr.io/theshimpz/shimpz-local-release@sha256:{}",
                digest.to_string().repeat(64)
            ),
            metadata: Release {
                ordinal,
                umbrella_revision: "a".repeat(40),
                cli_revision: "b".repeat(40),
                cli_linux_amd64_sha256: HEX.into(),
                cli_macos_arm64_sha256: HEX.into(),
                admin: format!("ghcr.io/theshimpz/shimpz-admin@sha256:{HEX}"),
                team: format!("ghcr.io/theshimpz/shimpz-team-local@sha256:{HEX}"),
                brain: format!("ghcr.io/theshimpz/shimpz-brain@sha256:{HEX}"),
                egress: format!("ghcr.io/theshimpz/shimpz-egress@sha256:{HEX}"),
            },
        }
    }

    #[test]
    fn rollback_backup_replaces_a_stale_graph_with_the_current_contract() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        fs::write(&paths.compose, "untrusted stale graph").unwrap();
        fs::write(&paths.environment, "current environment").unwrap();

        assert!(!installed_graph_is_current(&paths, HostProfile::MacOs).unwrap());
        let backup = backup_current(&paths, HostProfile::MacOs).unwrap();

        assert_eq!(
            fs::read_to_string(backup.compose).unwrap(),
            graph::render(StorageProfile::ManagedDisk)
        );
        assert_eq!(
            fs::read_to_string(backup.environment).unwrap(),
            "current environment"
        );
    }

    #[test]
    fn admits_only_monotonic_unambiguous_releases() {
        let installed = Installed {
            space_id: "space-0123456789abcdef01234567".into(),
            release_ref: release(2, 'b').reference,
            ordinal: 2,
            port: 7777,
        };
        assert!(validate_forward_release(&release(3, 'c'), Some(&installed)).is_ok());
        assert!(validate_forward_release(&release(2, 'b'), Some(&installed)).is_ok());
        assert!(validate_forward_release(&release(1, 'a'), Some(&installed)).is_err());
        assert!(validate_forward_release(&release(2, 'c'), Some(&installed)).is_err());
        assert!(validate_forward_release(&release(1, 'a'), None).is_ok());
    }

    #[test]
    fn reports_fresh_and_changed_releases_as_updated() {
        let current = release(2, 'b');
        let installed = Installed {
            space_id: "space-0123456789abcdef01234567".into(),
            release_ref: current.reference.clone(),
            ordinal: 2,
            port: 7777,
        };
        assert_eq!(release_outcome(&current, Some(&installed)), "current");
        assert_eq!(
            release_outcome(&release(3, 'c'), Some(&installed)),
            "updated"
        );
        assert_eq!(release_outcome(&release(1, 'a'), None), "updated");
    }

    #[test]
    fn stop_progress_is_bounded_redacted_and_ordered_by_stage() {
        let [checking, stopping, verifying] = STOP_PROGRESS;
        assert!(checking.starts_with("Checking"));
        assert!(stopping.starts_with("Stopping"));
        assert!(verifying.starts_with("Verifying"));
        for stage in STOP_PROGRESS {
            assert!(stage.ends_with("..."));
            assert_eq!(output::sanitize(stage), stage);
            assert!(!stage.contains("sha256:"));
            assert!(!stage.contains("space-"));
            assert!(!stage.bytes().any(|byte| byte.is_ascii_digit()));
            for name in crate::space::resources::RESERVED {
                assert!(!stage.contains(name), "{stage}");
            }
        }
    }

    #[test]
    fn a_stopped_resume_preserves_failed_release_memory_until_the_channel_moves() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        let failed = release(3, 'c');
        state::remember_failed_release(&paths, &failed).unwrap();

        finish_failed_release_memory(&paths, true).unwrap();
        assert!(state::failed_release_matches(&paths, &failed.reference).unwrap());

        finish_failed_release_memory(&paths, false).unwrap();
        assert!(!paths.failed_release.exists());
    }

    #[test]
    fn a_failed_channel_release_resumes_only_an_intentionally_stopped_space() {
        assert_eq!(
            failed_release_decision(true, true),
            FailedReleaseDecision::ResumeInstalled
        );
        assert_eq!(
            failed_release_decision(false, true),
            FailedReleaseDecision::KeepRunning
        );
        assert_eq!(
            failed_release_decision(true, false),
            FailedReleaseDecision::UseSelected
        );
    }

    #[test]
    fn ready_outcome_leads_to_admin_without_printing_the_digest() {
        let release = release(3, 'c');
        let outcome = ready_outcome(&release, 7777);

        assert_eq!(
            outcome,
            "Shimpz Space is ready.\nAdmin: http://127.0.0.1:7777\nRelease: ordinal 3\nNext: open the Admin address above."
        );
        assert!(!outcome.contains("sha256:"));
    }

    #[test]
    fn reset_outcomes_are_positive_and_report_preserved_content() {
        let already_clean = reset_outcome(true, &[], false);
        let changed = reset_outcome(false, &["/home/ada/.shimpz/notes".to_owned()], false);
        let scheduler = reset_outcome(
            true,
            &["/home/ada/Library/LaunchAgents/com.shimpz.update.plist".to_owned()],
            true,
        );
        assert_eq!(
            already_clean,
            "Shimpz Space was reset successfully. No change was needed. No managed Space data remains; the shimpz command and lifecycle lock are retained."
        );
        assert_eq!(
            changed,
            "Shimpz Space was reset successfully. Preserved unrecognized content: /home/ada/.shimpz/notes"
        );
        assert!(scheduler.contains("Scheduler execution state is unverified"));
        assert!(scheduler.contains("run shimpz install from an interactive terminal"));
        for outcome in [already_clean, changed, scheduler] {
            assert!(outcome.contains("Shimpz Space was reset successfully"));
        }
    }

    #[test]
    fn bootstrap_reset_prompts_only_for_the_exact_password_required_decision() {
        assert_eq!(
            admin_reset_decision(200, &serde_json::json!({"reset": true})),
            Ok(AdminResetDecision::Complete)
        );
        assert_eq!(
            admin_reset_decision(
                409,
                &serde_json::json!({
                    "code": "supervisor-password-required",
                    "detail": "ignored for control flow",
                    "future": true
                })
            ),
            Ok(AdminResetDecision::PasswordRequired)
        );
        for (status, body) in [
            (200, serde_json::json!({"reset": true, "extra": true})),
            (409, serde_json::json!({"detail": "password required"})),
            (
                503,
                serde_json::json!({"code": "supervisor-password-required"}),
            ),
        ] {
            assert!(
                admin_reset_decision(status, &body)
                    .unwrap_err()
                    .contains("re-run shimpz reset")
            );
        }
    }

    #[test]
    fn bootstrap_reset_names_inconsistent_supervisor_state_without_deleting() {
        let error = admin_reset_decision(
            409,
            &serde_json::json!({"code": "bootstrap-reset-refused", "detail": "untrusted"}),
        )
        .unwrap_err();

        assert!(error.contains("inconsistent Supervisor state"));
        assert!(error.contains("nothing was deleted"));
        assert!(!error.contains("untrusted"));
    }

    fn local_session(password_state: &str, initialized: bool) -> serde_json::Value {
        serde_json::json!({
            "profile": "local",
            "authenticated": false,
            "initialized": initialized,
            "password_state": password_state,
            "features": {"teamCredentials": true}
        })
    }

    #[test]
    fn release_gate_accepts_only_exact_consistent_local_password_states() {
        for (name, initialized, expected) in [
            ("uninitialized", false, AdminPasswordState::Uninitialized),
            ("configured", true, AdminPasswordState::Configured),
            (
                "recovery-required",
                true,
                AdminPasswordState::RecoveryRequired,
            ),
        ] {
            assert_eq!(
                admin_password_state_response(200, &local_session(name, initialized)),
                Ok(expected)
            );
        }

        for (status, body) in [
            (503, local_session("configured", true)),
            (200, local_session("configured", false)),
            (200, local_session("unknown", true)),
            (
                200,
                serde_json::json!({
                    "profile": "hosted",
                    "authenticated": false,
                    "initialized": true,
                    "password_state": "configured",
                    "features": {"teamCredentials": true}
                }),
            ),
            (
                200,
                serde_json::json!({
                    "profile": "local",
                    "authenticated": false,
                    "initialized": true,
                    "password_state": "configured",
                    "features": {"teamCredentials": true},
                    "extra": true
                }),
            ),
        ] {
            assert!(admin_password_state_response(status, &body).is_err());
        }
    }

    #[test]
    fn authenticated_reset_requires_exact_success_and_names_the_retry() {
        assert_eq!(
            authenticated_reset_response(200, Some(&serde_json::json!({"reset": true}))),
            Ok(())
        );
        assert_eq!(
            authenticated_reset_response(503, None),
            Err(RESET_INCOMPLETE.into())
        );
        for body in [
            serde_json::json!({"reset": false}),
            serde_json::json!({"reset": true, "extra": true}),
        ] {
            assert_eq!(
                authenticated_reset_response(200, Some(&body)),
                Err(RESET_INCOMPLETE.into())
            );
        }
    }

    #[test]
    fn authenticated_reset_distinguishes_throttling_from_password_rejection() {
        assert_eq!(authenticated_login_response(200), Ok(()));
        assert!(
            authenticated_login_response(429)
                .unwrap_err()
                .contains("wait one minute")
        );
        assert!(
            authenticated_login_response(401)
                .unwrap_err()
                .contains("password was rejected")
        );
    }

    #[test]
    fn scheduler_conflicts_do_not_erase_a_healthy_space_outcome() {
        let ready = "Shimpz Space is ready.".to_owned();
        let preserved = scheduler_outcome(
            ready.clone(),
            Ok(scheduler::InstallOutcome::Preserved(vec![
                "/home/ada/scheduler".into(),
            ])),
        )
        .unwrap();
        assert!(preserved.starts_with(&ready));
        assert!(preserved.contains("execution state is unverified"));
        let error = scheduler_outcome(ready.clone(), Err("write failed".into())).unwrap_err();
        assert!(error.starts_with(&ready));
        assert!(error.contains("Space is healthy"));
    }

    #[test]
    fn accepts_only_an_attested_loopback_admin_listener() {
        assert_eq!(
            parse_admin_attestation(
                "true|shimpz-space|admin|{\"4600/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"7777\"}]}\n"
            ),
            Ok(AdminAttestation::Running { port: 7777 })
        );
        assert_eq!(
            parse_admin_attestation(
                "true|shimpz-space|admin|{\"4600/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"7777\"},{\"HostIp\":\"::1\",\"HostPort\":\"7777\"}]}\n"
            ),
            Ok(AdminAttestation::Running { port: 7777 })
        );
        assert_eq!(
            parse_admin_attestation(
                "false|shimpz-space|admin|{\"4600/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"7777\"}]}\n"
            ),
            Ok(AdminAttestation::Stopped)
        );
        for invalid in [
            "true|foreign|admin|{\"4600/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"7777\"}]}",
            "true|shimpz-space|team|{\"4600/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"7777\"}]}",
            "true|shimpz-space|admin|{\"4600/tcp\":[{\"HostIp\":\"0.0.0.0\",\"HostPort\":\"7777\"}]}",
            "true|shimpz-space|admin|{\"4600/tcp\":[{\"HostIp\":\"::1\",\"HostPort\":\"7777\"}]}",
            "true|shimpz-space|admin|{\"4600/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"80\"}]}",
            "true|shimpz-space|admin|{\"4600/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"7777\"},{\"HostIp\":\"::1\",\"HostPort\":\"8888\"}]}",
            "true|shimpz-space|admin|{\"4600/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"7777\"}],\"80/tcp\":[]}",
            "true|shimpz-space|admin|null",
            "true|shimpz-space|admin|{}",
            "maybe|shimpz-space|admin|{\"4600/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"7777\"}]}",
        ] {
            assert!(parse_admin_attestation(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn unmarked_home_accepts_only_private_managed_cli_artifacts() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        fs::set_permissions(&paths.home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(paths.managed_cli.parent().unwrap()).unwrap();
        fs::write(paths.managed_cli.with_extension("candidate"), "candidate").unwrap();
        fs::set_permissions(
            paths.managed_cli.with_extension("candidate"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        validate_install_home(&paths).unwrap();
        assert!(adopt_unmarked_home(&paths).is_ok());
        let foreign = paths.managed_cli.parent().unwrap().join("foreign");
        fs::write(&foreign, "foreign").unwrap();
        let error = adopt_unmarked_home(&paths).unwrap_err();
        assert!(error.contains(&foreign.display().to_string()));
    }

    #[test]
    fn unmarked_home_reconciles_only_pre_marker_temporaries() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        fs::set_permissions(&paths.home, fs::Permissions::from_mode(0o700)).unwrap();
        let release_temporary = paths.home.join("release.env.tmp");
        let marker_temporary = paths.marker.with_extension("tmp");
        fs::write(&release_temporary, "metadata").unwrap();
        fs::write(&marker_temporary, "marker").unwrap();
        state::write_stopped(&paths).unwrap();
        validate_install_home(&paths).unwrap();
        assert_eq!(unmarked_runtime_entries(&paths).unwrap().total, 3);
        adopt_unmarked_home(&paths).unwrap();
        assert!(!release_temporary.exists());
        assert!(!marker_temporary.exists());
        assert!(!paths.stopped.exists());
        assert!(unmarked_runtime_entries(&paths).unwrap().is_empty());
    }

    #[test]
    fn absent_unmarked_home_has_no_runtime_residue() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();

        assert!(unmarked_runtime_entries(&paths).unwrap().is_empty());
    }

    #[test]
    fn unmarked_home_names_the_exact_unowned_entry() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        fs::set_permissions(&paths.home, fs::Permissions::from_mode(0o700)).unwrap();
        let unowned = paths.home.join("unexpected");
        fs::write(&unowned, "not owned by the Local contract").unwrap();

        validate_install_home(&paths).unwrap();
        let error = adopt_unmarked_home(&paths).unwrap_err();

        assert!(error.contains(&unowned.display().to_string()));
        assert!(error.contains("move or remove every unowned entry"));
    }

    #[test]
    fn private_home_validation_allows_reset_to_preserve_unowned_entries() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        fs::set_permissions(&paths.home, fs::Permissions::from_mode(0o700)).unwrap();
        let unowned = paths.home.join("preserved");
        fs::write(&unowned, "not owned by the Local contract").unwrap();

        validate_install_home(&paths).unwrap();

        assert!(unowned.exists());
        assert!(adopt_unmarked_home(&paths).is_err());
    }

    #[test]
    fn unowned_entry_reporting_is_bounded_and_deterministic() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        fs::set_permissions(&paths.home, fs::Permissions::from_mode(0o700)).unwrap();
        for index in (0..10).rev() {
            fs::write(paths.home.join(format!("unexpected-{index:02}")), "foreign").unwrap();
        }

        let error = adopt_unmarked_home(&paths).unwrap_err();

        for index in 0..8 {
            assert!(error.contains(&format!("unexpected-{index:02}")));
        }
        assert!(!error.contains("unexpected-08"));
        assert!(!error.contains("unexpected-09"));
        assert!(error.contains("and 2 more"));
    }

    #[test]
    fn managed_cli_validation_names_invalid_artifacts() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir_all(paths.managed_cli.parent().unwrap()).unwrap();
        fs::write(&paths.managed_cli, "managed").unwrap();
        fs::set_permissions(&paths.managed_cli, fs::Permissions::from_mode(0o755)).unwrap();

        let admission_error = adopt_unmarked_home(&paths).unwrap_err();
        let private_error = validate_private_cli(&paths.managed_cli).unwrap_err();

        for error in [admission_error, private_error] {
            assert!(error.contains(&paths.managed_cli.display().to_string()));
        }
    }

    #[test]
    fn reset_cleanup_removes_the_pre_marker_release_temporary() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        let temporary = paths.home.join("release.env.tmp");
        fs::write(&temporary, "metadata").unwrap();
        state::write_stopped(&paths).unwrap();

        remove_runtime_files(&paths).unwrap();

        assert!(!temporary.exists());
        assert!(!paths.stopped.exists());
    }

    #[test]
    fn public_command_is_only_the_exact_managed_symlink() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir_all(paths.managed_cli.parent().unwrap()).unwrap();
        fs::write(&paths.managed_cli, "managed").unwrap();
        ensure_public_cli(&paths).unwrap();
        assert_eq!(fs::read_link(&paths.public_cli).unwrap(), paths.managed_cli);
        assert!(ensure_public_cli(&paths).is_ok());
        fs::remove_file(&paths.public_cli).unwrap();
        fs::write(&paths.public_cli, "foreign").unwrap();
        assert!(ensure_public_cli(&paths).is_err());
    }

    #[test]
    fn candidate_activation_restores_the_previous_private_cli() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir_all(paths.managed_cli.parent().unwrap()).unwrap();
        let previous = paths.managed_cli.with_extension("previous");
        fs::write(&paths.managed_cli, "candidate").unwrap();
        fs::write(&previous, "previous").unwrap();
        restore_previous_cli(&paths.managed_cli, &previous).unwrap();
        assert_eq!(fs::read_to_string(&paths.managed_cli).unwrap(), "previous");
        assert!(!previous.exists());
    }

    #[test]
    fn reconciles_only_a_previous_artifact_for_the_running_managed_cli() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir_all(paths.managed_cli.parent().unwrap()).unwrap();
        let previous = paths.managed_cli.with_extension("previous");
        fs::write(&paths.managed_cli, "current").unwrap();
        fs::write(&previous, "previous").unwrap();
        fs::set_permissions(&paths.managed_cli, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&previous, fs::Permissions::from_mode(0o700)).unwrap();
        reconcile_previous_cli(&paths.managed_cli, &paths.managed_cli).unwrap();
        assert!(!previous.exists());

        fs::remove_file(&paths.managed_cli).unwrap();
        fs::write(&previous, "restored").unwrap();
        fs::set_permissions(&previous, fs::Permissions::from_mode(0o700)).unwrap();
        reconcile_previous_cli(&paths.managed_cli, &paths.managed_cli).unwrap();
        assert_eq!(fs::read_to_string(&paths.managed_cli).unwrap(), "restored");

        fs::write(&previous, "previous").unwrap();
        fs::set_permissions(&previous, fs::Permissions::from_mode(0o700)).unwrap();
        let other = paths.managed_cli.parent().unwrap().join("other");
        fs::write(&other, "other").unwrap();
        assert!(reconcile_previous_cli(&paths.managed_cli, &other).is_err());
        assert!(previous.exists());
    }
}
