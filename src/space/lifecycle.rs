//! Native install, reconcile, update, stop, status, and reset orchestration.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use ureq::Agent;
use zeroize::Zeroizing;

use crate::args::{GraphProfile, SpaceInstall, SpaceReset, SpaceStart};
use crate::output::{self, Withheld};

use super::deploy;
use super::docker::{Engine, PendingStatus, ProjectionFailure, ResolvedRelease};
use super::graph::{self, StorageProfile};
use super::host::{self, HostProfile};
use super::paths::Paths;
use super::poll;
use super::release;
use super::resources::{self, Inventory};
use super::scheduler;
use super::state::{self, Environment, Installed, Lock};
use super::status as status_report;
use super::storage::linux;

// Admin bounds its authoritative Team reset call at 180 seconds; the client must outlast it.
const ADMIN_RESET_TIMEOUT: Duration = Duration::from_secs(210);
const ADMIN_SESSION_TIMEOUT: Duration = Duration::from_secs(5);
const HOST_RESET_CAPABILITY_SECONDS: u64 = 120;
const RESET_INCOMPLETE: &str = "the Space reset did not complete; re-run shimpz reset";
const UPDATE_PROGRESS: &str = "Checking for Shimpz Space updates...";
const SCHEDULED_STOPPED: &str = "Shimpz Space is stopped.\nNext: shimpz start";
const UPDATE_DEFERRED: &str =
    "A Local update is waiting for active Shimpz work to finish; it will retry automatically.";
const STORAGE_LOCKED: &str = "Encrypted Local storage is locked. No workloads were started.";
const TEAM_ACTIVITY_TIMEOUT: Duration = Duration::from_secs(5);
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
    context.install(options.release.as_deref(), options.candidate)
}

pub(crate) fn start(options: &SpaceStart) -> Result<String, String> {
    // An unattended run under systemd starts every host command in its own process group, so a deadline stops the
    // command's descendants too; macOS keeps launchd's job group, and an interactive run keeps the terminal's.
    if options.scheduled && host::detect().is_ok_and(|profile| profile != HostProfile::MacOs) {
        crate::capture::isolate_process_groups();
    }
    let paths = Paths::discover()?;
    validate_install_home(&paths)?;
    let _lock = (!options.candidate)
        .then(|| Lock::acquire(&paths))
        .transpose()?;
    if options.scheduled && options.release.is_none() {
        if let Some(request) = deploy::claim(&paths)? {
            return apply_deploy_request(&paths, &request);
        }
        if let Some(message) = scheduled_gate(&paths)? {
            return Ok(message);
        }
    }
    Context::connect(paths, options.scheduled)?.start(options)
}

/// Apply the developer release a deploy request names, exactly as a scheduled start of that release, and record
/// whether this attempt committed it.
fn apply_deploy_request(paths: &Paths, request: &deploy::Request) -> Result<String, String> {
    let options = SpaceStart {
        scheduled: true,
        release: Some(request.release.clone()),
        candidate: false,
    };
    finish_deploy_request(paths, host::detect()?, request, || {
        Context::connect(Paths::discover()?, true)?.start(&options)
    })
}

/// A stopped Space keeps its stop intent: the request fails without running. Otherwise only an attempt that ends
/// with the requested release installed and its reconciliation recorded applied it; a deferral keeps the request.
fn finish_deploy_request(
    paths: &Paths,
    profile: HostProfile,
    request: &deploy::Request,
    start: impl FnOnce() -> Result<String, String>,
) -> Result<String, String> {
    let result = if state::stopped(paths)? {
        Err("the Local Space is stopped; start it with shimpz start, then deploy again".into())
    } else {
        start()
    };
    let outcome = match &result {
        Ok(message) if message == UPDATE_DEFERRED => deploy::Outcome::Deferred,
        Ok(message)
            if message != STORAGE_LOCKED && deploy_committed(paths, profile, &request.release) =>
        {
            deploy::Outcome::Applied
        }
        Ok(_) | Err(_) => deploy::Outcome::Failed,
    };
    let (Ok(message) | Err(message)) = &result;
    deploy::finish(paths, request, outcome, message)?;
    result
}

/// The installed release is exactly `release_ref` and its successful reconciliation is the recorded status.
fn deploy_committed(paths: &Paths, profile: HostProfile, release_ref: &str) -> bool {
    state::read_installed(paths, profile).is_ok_and(|installed| {
        installed.release_ref == release_ref
            && poll::status_record(paths, release_ref, installed.ordinal)
                == poll::StatusRecord::Reconciled
    })
}

/// The cheap scheduled check before any Docker work: a stopped Space or an unchanged release ends the run.
fn scheduled_gate(paths: &Paths) -> Result<Option<String>, String> {
    if !paths.marker_is_current()? {
        return Ok(None);
    }
    if state::stopped(paths)? {
        return Ok(Some(SCHEDULED_STOPPED.into()));
    }
    let installed = state::read_installed(paths, host::detect()?)?;
    Ok(poll::scheduled_gate(paths, &installed, poll::now(), poll::probe_stable)?.map(Into::into))
}

pub(crate) fn update() -> Result<String, String> {
    let context = Context::open(false)?;
    let _lock = Lock::acquire(&context.paths)?;
    context.update()
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

/// Observes the inventory-proven containers in bounded `docker inspect` batches. A static component the inventory
/// does not hold is absent; any record that is not exactly one distinct known component refuses the snapshot.
fn runtime_snapshot(engine: &Engine, inventory: &Inventory) -> Result<RuntimeSnapshot, String> {
    let inconsistent = || "Docker returned an inconsistent Local runtime snapshot".to_owned();
    let records = resources::inspect_containers(
        engine,
        &inventory.project_containers,
        // A batched inspect formats raw JSON maps, where a container without a healthcheck has no Health key and
        // `.State.Health` fails the whole call; `index` yields an empty value instead.
        "{{.Name}}|{{index .Config.Labels \"com.docker.compose.service\"}}|{{.State.Status}}|{{if index .State \"Health\"}}{{.State.Health.Status}}{{end}}|{{.State.ExitCode}}",
        "Local runtime state",
    )?;
    let mut present = BTreeMap::new();
    for record in &records {
        let (name, state) = record.split_once('|').ok_or_else(inconsistent)?;
        let name = name.strip_prefix('/').ok_or_else(inconsistent)?;
        if present.insert(name, state).is_some() {
            return Err(inconsistent());
        }
    }
    let components = status_report::COMPONENTS
        .iter()
        .copied()
        .map(|component| status_report::observe(component, present.remove(component.docker_name())))
        .collect::<Result<Vec<_>, _>>()?;
    if !present.is_empty() {
        return Err(inconsistent());
    }
    let assistant_ids: Vec<String> = inventory
        .assistant_containers()
        .into_iter()
        .map(str::to_owned)
        .collect();
    let assistants = resources::inspect_containers(
        engine,
        &assistant_ids,
        "{{.State.Status}}|{{.State.ExitCode}}",
        "Assistant runtime state",
    )?
    .iter()
    .map(|record| status_report::observe_assistant(record))
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
    validate_managed_bin(paths)?;
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

pub(crate) fn reset(options: &SpaceReset) -> Result<String, String> {
    let context = Context::open(false)?;
    let _lock = Lock::acquire(&context.paths)?;
    if options.hard {
        context.hard_reset()
    } else {
        context.reset()
    }
}

struct Context {
    paths: Paths,
    profile: HostProfile,
    engine: Engine,
    scheduled: bool,
    /// Whether this run emptied the runtime state, directly or through the release-bound CLI it handed off to.
    recreated: Cell<bool>,
}

/// The Team controller's Docker socket and its group, or why the controller cannot use it.
type ControllerSocket = Result<(PathBuf, u32), String>;

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
    Deferred,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdminAuthenticationState {
    Uninitialized,
    EnrollmentRequired,
    Configured,
    RecoveryRequired,
}

struct HostResetCapability {
    secret: Zeroizing<String>,
    document: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailedReleaseDecision {
    UseSelected,
    ResumeInstalled,
    KeepRunning,
}

/// What a start applies; `None` in its place keeps the running Space because the selection previously failed health.
struct StartSelection {
    release: ResolvedRelease,
    preserve_failed_release: bool,
    may_hand_off: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpdateDecision {
    Current,
    Failed,
    Available,
    Apply,
}

impl Context {
    fn open(scheduled: bool) -> Result<Self, String> {
        let paths = Paths::discover()?;
        validate_install_home(&paths)?;
        Self::connect(paths, scheduled)
    }

    fn connect(paths: Paths, scheduled: bool) -> Result<Self, String> {
        let profile = host::detect()?;
        let engine = Engine::connect(profile, &paths)?;
        Ok(Self {
            paths,
            profile,
            engine,
            scheduled,
            recreated: Cell::new(false),
        })
    }

    fn install(&self, exact_release: Option<&str>, candidate: bool) -> Result<String, String> {
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
        let release = self.resolve(exact_release)?;
        validate_forward_release(&release, installed.as_ref())?;
        if exact_release.is_some() && !candidate {
            // A developer release set is built on this host, so the CLI that names it hands off to the set's own
            // CLI unless it is that CLI.
            if release::valid_developer_release_ref(&release.reference)
                && self.handoff_if_needed(&release, installed.as_ref(), false)?
            {
                return Ok("The release-bound CLI completed the installation.".into());
            }
            // The acquisition bootstrap runs its verified CLI from outside the Space; that CLI becomes the managed
            // executable only here, under the lifecycle lock and after admission. Apply then retains it.
            let running =
                std::env::current_exe().map_err(|_| "the running CLI path is unavailable")?;
            activate_cli(
                &self.paths,
                &running,
                expected_cli_hash(&release, self.profile)?,
            )?;
        } else if exact_release.is_none()
            && self.handoff_if_needed(&release, installed.as_ref(), false)?
        {
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

    /// Resolve the `stable` channel or one exact release. A developer release is admitted only from this host's
    /// image store and only on the amd64 Linux profiles.
    fn resolve(&self, exact: Option<&str>) -> Result<ResolvedRelease, String> {
        let release = self.engine.resolve_release(exact, &self.paths.home)?;
        if release::valid_developer_release_ref(&release.reference)
            && self.profile == HostProfile::MacOs
        {
            return Err("a developer release applies only to an amd64 Linux Space".into());
        }
        Ok(release)
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
        // The inventory proof and the release resolution are independent, so the resolution runs beside it, its
        // warnings withheld; both are judged in the former order. A scheduled run of an intentionally stopped Space
        // still resolves nothing.
        let stopped = state::stopped(&self.paths);
        let resolve = match stopped {
            Ok(stopped) => !(options.scheduled && stopped),
            Err(_) => false,
        };
        let (engine, paths, storage) = (&self.engine, &self.paths, self.profile.storage());
        let (inventory, selection) = thread::scope(|scope| {
            let inventory = scope.spawn(|| Inventory::inspect(engine, paths, storage));
            let selection = resolve.then(|| {
                output::withhold(|| self.select_start(options, &installed, stopped == Ok(true)))
            });
            let inventory = inventory
                .join()
                .unwrap_or_else(|_| Err("the Local inventory could not be observed".into()));
            (inventory, selection)
        });
        if let Err(error) = inventory {
            // The refused inventory leads; a resolution that also failed, for example in its cleanup, follows it.
            return Err(match selection.map(Withheld::release) {
                Some(Err(resolution)) => {
                    format!("{error}; the Local release resolution also failed: {resolution}")
                }
                Some(Ok(_)) | None => error,
            });
        }
        let stopped = stopped?;
        if options.scheduled && stopped {
            return Ok(SCHEDULED_STOPPED.into());
        }
        let Some(StartSelection {
            release,
            preserve_failed_release,
            may_hand_off,
        }) = selection
            .ok_or_else(|| "the Local release was not resolved".to_owned())?
            .release()?
        else {
            return Ok("The selected Local release previously failed health; the current Space remains unchanged.".into());
        };
        if may_hand_off && self.handoff_if_needed(&release, Some(&installed), options.scheduled)? {
            return self.handoff_outcome(&release);
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

    /// Select what a start applies: the exact release it names, else the installed developer release, which never
    /// follows `stable`, else the `stable` channel. A selection without an exact release meets failed-release memory.
    fn select_start(
        &self,
        options: &SpaceStart,
        installed: &Installed,
        stopped: bool,
    ) -> Result<Option<StartSelection>, String> {
        let channel = options.release.is_none();
        let selected = match options.release.as_deref() {
            Some(exact) => Some(exact),
            None if installed.developer() => Some(installed.release_ref.as_str()),
            None => None,
        };
        let release = self.resolve(selected)?;
        validate_forward_release(&release, Some(installed))?;
        let selected_failed =
            channel && state::failed_release_matches(&self.paths, &release.reference)?;
        Ok(match failed_release_decision(stopped, selected_failed) {
            FailedReleaseDecision::UseSelected => Some(StartSelection {
                release,
                preserve_failed_release: false,
                may_hand_off: !options.candidate,
            }),
            FailedReleaseDecision::ResumeInstalled => Some(StartSelection {
                release: self.resolve(Some(&installed.release_ref))?,
                preserve_failed_release: true,
                may_hand_off: false,
            }),
            FailedReleaseDecision::KeepRunning => None,
        })
    }

    fn update(&self) -> Result<String, String> {
        if !self.paths.marker_is_current()? {
            return Err("Shimpz Space is not installed; run shimpz install".into());
        }
        let installed = self.validate_installation_storage(self.installed_state()?)?;
        Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?;
        let stopped = state::stopped(&self.paths)?;
        output::progress(UPDATE_PROGRESS);
        let release = self.resolve(None)?;
        validate_forward_release(&release, Some(&installed))?;
        let selected_failed = state::failed_release_matches(&self.paths, &release.reference)?;
        let decision = update_decision(&installed, &release, stopped, selected_failed);
        if let Some(outcome) = run_update_effect(decision, || {
            if self.handoff_if_needed(&release, Some(&installed), false)? {
                return Ok("The release-bound CLI completed the update.".into());
            }
            self.apply(&release, Some(&installed), false, false)
        })? {
            return Ok(outcome);
        }
        match decision {
            UpdateDecision::Current => Ok(current_release_outcome(&installed, stopped)),
            UpdateDecision::Failed => Ok(failed_update_outcome(stopped)),
            UpdateDecision::Available => Ok(available_release_outcome(&installed, &release)),
            UpdateDecision::Apply => Err("the Local update effect returned no outcome".into()),
        }
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
            // An apply that emptied the runtime state says so on every failure: rollback never restores it.
            Err(error) if self.recreated.get() => return Err(self.with_recreation(error)),
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
        let port = match outcome {
            ApplyOutcome::Ready { port } => port,
            ApplyOutcome::Locked => return Ok(STORAGE_LOCKED.into()),
            ApplyOutcome::Deferred => return Ok(UPDATE_DEFERRED.into()),
        };
        let mut ready = ready_outcome(release, port);
        if self.recreated.get() {
            ready = format!("{ready}\n{}", recreation_notice(release));
        }
        output::progress("Confirming the automatic update schedule...");
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
        let controller_socket = self.download_and_admit_candidate(release, installed)?;
        if scheduled && self.defer_for_activity(release, installed)? {
            return Ok(ApplyOutcome::Deferred);
        }
        let port = state::selected_port(installed)?;
        let (docker_socket, docker_gid) = controller_socket.release()?;
        let previous = installed
            .map(|_| backup_current(&self.paths, self.profile))
            .transpose()?;
        let candidate = Candidate {
            release,
            installed,
            space_id,
            port,
            docker_gid,
            docker_socket: &docker_socket,
        };
        let previous = self.start_or_roll_back(&candidate, previous)?;
        remove_backup(previous)?;
        finish_failed_release_memory(&self.paths, preserve_failed_release)?;
        Ok(ApplyOutcome::Ready { port })
    }

    /// Start the candidate; once its files replace the live ones, every failure before its status is committed
    /// rolls back, so no failure leaves the candidate configuration in place with the previous backup orphaned.
    /// On success the backup is returned for removal.
    fn start_or_roll_back(
        &self,
        candidate: &Candidate<'_>,
        previous: Option<Backup>,
    ) -> Result<Option<Backup>, String> {
        let Err(cause) = self.replace_and_start(candidate) else {
            return Ok(previous);
        };
        let outcome = match self.rollback(candidate.release, candidate.space_id, previous) {
            Ok(outcome) | Err(outcome) => outcome,
        };
        Err(match cause {
            Some(cause) => format!("{cause}; {outcome}"),
            None => outcome,
        })
    }

    /// Replace the live configuration with the candidate, start it, and commit its status. An `Err` carries the
    /// cause to report before the rollback outcome, or `None` when the rollback outcome alone describes it.
    fn replace_and_start(&self, candidate: &Candidate<'_>) -> Result<(), Option<String>> {
        let release = candidate.release;
        self.reconcile_runtime_state(
            Some(release.metadata.state_epoch),
            &release.metadata.team,
            candidate.installed.is_none(),
        )
        .map_err(Some)?;
        // Removing replaced containers at once pays only when Compose would otherwise recreate two or more in turn;
        // a single one is left to Compose, which creates its replacement before stopping it.
        let remove_first = match candidate.installed {
            Some(_) => {
                replaced_container_count(
                    &state::read_installed_images(&self.paths, self.profile).map_err(Some)?,
                    release,
                ) >= 2
            }
            None => false,
        };
        state::write_environment(
            &self.paths,
            &Environment {
                release,
                profile: self.profile,
                space_id: candidate.space_id,
                port: candidate.port,
                docker_gid: candidate.docker_gid,
                docker_socket: candidate.docker_socket,
                cpuset: &self.engine.cpuset,
                secure_root: &self.paths.pool_mount,
            },
        )
        .map_err(Some)?;
        state::write_private(&self.paths.compose, &graph::render(self.profile.storage()))
            .map_err(Some)?;
        state::clear_stopped(&self.paths).map_err(Some)?;
        output::progress("Starting the Shimpz Space...");
        let init_current = if remove_first {
            // The candidate files are written, so the initializer check reads them beside the removal; a replaced
            // egress image already changes the initializer's configuration, and any failed observation reruns it.
            let (engine, paths) = (&self.engine, &self.paths);
            let (init_current, removed) = thread::scope(|scope| {
                let init_current = scope.spawn(|| engine.completed_init_is_current(paths));
                let removed = self.remove_replaced_containers(release);
                (init_current.join().unwrap_or(false), removed)
            });
            removed.map_err(Some)?;
            init_current
        } else {
            self.engine.completed_init_is_current(&self.paths)
        };
        // An installed Space already holds the owned release status volume, so its helper starts now and waits only
        // for the document; a fresh Space's volume exists only once Compose created it, so it projects afterwards.
        let mut pending = match candidate.installed {
            Some(_) => self
                .engine
                .begin_release_status(&release.metadata.admin)
                .map_err(Some)?,
            None => None,
        };
        let started = self.start_candidate(candidate, init_current, &mut pending);
        // A helper the start did not commit is ended without a document, and reaped, before any rollback projects.
        let abandoned = pending.map_or(Ok(()), PendingStatus::abandon);
        let status = match (started, abandoned) {
            (Ok(status), Ok(())) => status,
            (Err(cause), Ok(())) => return Err(cause),
            (Err(Some(cause)), Err(cleanup)) => return Err(Some(format!("{cause}; {cleanup}"))),
            (Ok(_) | Err(None), Err(cleanup)) => return Err(Some(cleanup)),
        };
        // The local success record is the commit's last write: it and the live environment prove the commit.
        state::write_private(&self.paths.status, &status).map_err(Some)
    }

    /// Bring the candidate up, prove it, and project its status to Admin, through `pending` when one is waiting.
    /// Returns the status document for the local commit record.
    fn start_candidate(
        &self,
        candidate: &Candidate<'_>,
        init_current: bool,
        pending: &mut Option<PendingStatus>,
    ) -> Result<String, Option<String>> {
        let release = candidate.release;
        let (started, timings) = self
            .engine
            .compose_up(&self.paths, init_current)
            .map_err(Some)?;
        for timing in &timings {
            output::progress(timing);
        }
        if !started.success() {
            return Err(None);
        }
        self.validate_started_storage(candidate.space_id)
            .map_err(Some)?;
        output::progress("Verifying Supervisor authentication compatibility...");
        let authentication_error = match admin_authentication_state(candidate.port) {
            Ok(AdminAuthenticationState::RecoveryRequired) if candidate.installed.is_some() => Some(
                "the selected release cannot use the existing Supervisor authentication record; run shimpz reset --hard, then shimpz install"
                    .to_owned(),
            ),
            Ok(AdminAuthenticationState::RecoveryRequired) => Some(
                "the fresh release returned an invalid Supervisor authentication state".to_owned(),
            ),
            Ok(
                AdminAuthenticationState::Uninitialized
                | AdminAuthenticationState::EnrollmentRequired
                | AdminAuthenticationState::Configured,
            ) => None,
            Err(error) => Some(error),
        };
        if authentication_error.is_some() {
            return Err(authentication_error);
        }
        output::progress("Recording the Local release status...");
        let status = state::status_document(release, release_outcome(release, candidate.installed))
            .map_err(Some)?;
        match pending.take() {
            Some(pending) => pending.commit(status.as_bytes()),
            None => self
                .engine
                .project_release_status(&release.metadata.admin, status.as_bytes()),
        }
        // A helper that could not be reaped is reported before the rollback outcome; any other failure to project
        // leaves the rollback outcome to describe it.
        .map_err(|failure| match failure {
            ProjectionFailure::Unreaped(cause) => Some(cause),
            ProjectionFailure::NotProjected(_) => None,
        })?;
        Ok(status)
    }

    /// Stop, then remove, at once every Space container whose image the candidate replaces. Compose would otherwise
    /// recreate them one after another in dependency order (create, stop, remove, rename each) before it starts any;
    /// now it creates them fresh. Only containers the inventory proves are this project's are touched, each stop
    /// honors the container's own stop timeout, no volume is removed, and Compose still reconciles every service.
    /// This runs after the candidate replaced the live configuration, so any failure rolls back.
    fn remove_replaced_containers(&self, release: &ResolvedRelease) -> Result<(), String> {
        let inventory = Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?;
        let records = resources::inspect_containers(
            &self.engine,
            &inventory.project_containers,
            "{{.Name}}|{{.Config.Image}}",
            "Local container image",
        )?;
        let replaced = replaced_containers(&inventory.project_containers, &records, release)?;
        self.engine.stop_containers(&replaced)?;
        self.engine.remove_containers(&replaced)
    }

    /// Make every release image available, check the existing Supervisor authentication against a changed Admin,
    /// and probe the Team controller's Docker socket access. The Admin check and the socket probe are independent
    /// one-shot helpers, so they run beside the downloads, the probe once the exact Team image is admitted. Each
    /// check's warnings are withheld with its result and every answer is judged, and reported, in the former
    /// sequential order; the socket probe's is returned for the caller to judge where it did before: after the
    /// activity deferral and the port selection.
    fn download_and_admit_candidate(
        &self,
        release: &ResolvedRelease,
        installed: Option<&Installed>,
    ) -> Result<Withheld<ControllerSocket>, String> {
        output::progress("Downloading Shimpz Space (1/4): Admin...");
        self.engine
            .pull_exact(&release.metadata.admin, release::ADMIN)?;
        // Admin's own authentication record is read only by Admin, so an unchanged Admin image needs no new probe.
        let changed_admin =
            installed.is_some_and(|installed| installed.admin_image != release.metadata.admin);
        // The helpers borrow only the engine: the context's recreation flag stays on this thread.
        let (engine, profile) = (&self.engine, self.profile);
        let (authentication, downloads, controller_socket) = thread::scope(|scope| {
            let authentication = changed_admin.then(|| {
                output::progress("Checking existing Supervisor authentication...");
                scope.spawn(|| {
                    output::withhold(|| engine.admin_authentication_state(&release.metadata.admin))
                })
            });
            output::progress("Downloading Shimpz Space (2/4): Team...");
            let team =
                output::withhold(|| engine.pull_exact(&release.metadata.team, release::TEAM));
            let controller_socket = team.value().is_ok().then(|| {
                scope.spawn(|| {
                    output::withhold(|| engine.controller_socket(profile, &release.metadata.team))
                })
            });
            let mut downloads = vec![team];
            for (progress, image, package) in [
                (
                    "Downloading Shimpz Space (3/4): Brain...",
                    &release.metadata.brain,
                    release::BRAIN,
                ),
                (
                    "Downloading Shimpz Space (4/4): network boundaries...",
                    &release.metadata.egress,
                    release::EGRESS,
                ),
            ] {
                if downloads.iter().any(|download| download.value().is_err()) {
                    break;
                }
                output::progress(progress);
                downloads.push(output::withhold(|| engine.pull_exact(image, package)));
            }
            (
                authentication.map(joined),
                downloads,
                controller_socket.map(joined),
            )
        });
        if let Some(authentication) = authentication {
            let authentication_state = admin_authentication_state_probe_response(
                &authentication
                    .release()
                    .map_err(|error: String| candidate_admission_error(&error))?,
            )
            .map_err(|error| candidate_admission_error(&error))?;
            if authentication_state == AdminAuthenticationState::RecoveryRequired {
                return Err(candidate_admission_error(
                    "the selected release cannot use the existing Supervisor authentication record; run shimpz reset --hard, then shimpz install",
                ));
            }
        }
        for download in downloads {
            download.release()?;
        }
        controller_socket.ok_or_else(|| "the Team controller socket probe did not run".into())
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
                "the current Local Space cannot be authenticated safely; run shimpz reset --hard for explicit host recovery"
                    .into(),
            );
        }
        scheduler::preflight_remove(self.profile, &self.paths)?;
        if !inventory.empty()
            && let Some(current) = &installed
        {
            self.start_admin_for_reset()
                .map_err(|error| self.reset_failure(error, stopped))?;
            admin_reset(&self.engine, current)
                .map_err(|error| self.reset_failure(error, stopped))?;
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

    fn hard_reset(&self) -> Result<String, String> {
        output::progress("Checking the Shimpz Space hard reset scope...");
        self.paths
            .marker_is_owned()
            .map_err(|error| hard_reset_preflight(&error))?;
        let inventory = Inventory::inspect(&self.engine, &self.paths, self.profile.storage())
            .map_err(|error| hard_reset_preflight(&error))?;
        scheduler::preflight_remove(self.profile, &self.paths)
            .map_err(|error| hard_reset_preflight(&error))?;
        let preserved_files =
            preflight_remove_files(&self.paths, self.profile == HostProfile::Linux)
                .map_err(|error| hard_reset_preflight(&error))?;
        if self.profile == HostProfile::Linux {
            linux::preflight_reset(&self.paths, inventory.space_id.as_deref())
                .map_err(|error| hard_reset_preflight(&error))?;
        }
        let names = inventory
            .container_names(&self.engine)
            .map_err(|error| hard_reset_preflight(&error))?;
        if !hard_reset_prompt(&inventory, &names, &preserved_files)? {
            return Err("the Shimpz Space was preserved; nothing changed".into());
        }

        output::progress("Stopping the Shimpz Space for hard reset...");
        self.stop_owned_containers(&inventory)
            .map_err(|error| hard_reset_incomplete(&error))?;
        let stopped = Inventory::inspect(&self.engine, &self.paths, self.profile.storage())
            .map_err(|error| hard_reset_incomplete(&error))?;
        if !inventory.same_targets(&stopped) {
            return Err(hard_reset_incomplete(
                "the owned reset scope changed after confirmation",
            ));
        }

        output::progress("Removing the Shimpz Space owned state...");
        let space_id = inventory.space_id.clone();
        stopped
            .remove(&self.engine)
            .map_err(|error| hard_reset_incomplete(&error))?;
        let remaining = Inventory::inspect(&self.engine, &self.paths, self.profile.storage())
            .map_err(|error| hard_reset_incomplete(&error))?;
        if !remaining.empty() {
            return Err(hard_reset_incomplete(
                "owned Docker resources remain after hard reset",
            ));
        }
        if self.profile == HostProfile::Linux && self.paths.security.exists() {
            linux::reset(&self.paths, space_id.as_deref())
                .map_err(|error| hard_reset_incomplete(&error))?;
        }
        let scheduler = scheduler::remove(self.profile, &self.paths)
            .map_err(|error| hard_reset_incomplete(&error))?;
        let mut preserved = self
            .remove_files()
            .map_err(|error| hard_reset_incomplete(&error))?;
        preserved.extend(scheduler.preserved);
        Ok(hard_reset_outcome(
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

    /// Recreate the disposable runtime state empty unless the epoch recorded for it on disk is `epoch`, the stored
    /// format the starting release reads. An unknown epoch on either side always recreates it. The record is
    /// forgotten first and written only after the volumes were emptied, so an interrupted recreation is redone.
    /// Nothing is migrated: this repository is pre-production.
    fn reconcile_runtime_state(
        &self,
        epoch: Option<u32>,
        team_image: &str,
        fresh: bool,
    ) -> Result<bool, String> {
        let recreate =
            runtime_state_reset_needed(fresh, epoch, state::read_state_epoch(&self.paths));
        if recreate {
            output::progress("Recreating Team runtime state for a new stored format...");
            state::forget_state_epoch(&self.paths)?;
            let inventory = Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?;
            self.stop_owned_containers(&inventory)?;
            // Containers Team created before it stopped are found, stopped, and the whole Space proved stopped.
            self.restore_stopped_after_reset_failure()?;
            self.engine
                .clear_volumes(team_image, &graph::RUNTIME_STATE_VOLUMES)?;
            self.recreated.set(true);
        }
        // An unchanged record keeps its identity, so only a recreation or a fresh start replaces it.
        if let Some(epoch) = epoch
            && (recreate || fresh)
        {
            state::write_state_epoch(&self.paths, epoch)?;
        }
        Ok(recreate)
    }

    fn validate_started_storage(&self, space_id: &str) -> Result<(), String> {
        if self.profile == HostProfile::Linux {
            linux::Pool::new(&self.paths, space_id)?.validate_mounted()
        } else {
            Ok(())
        }
    }

    fn recover_corrupt(&self, inventory: &Inventory, reason: &str) -> Result<(), String> {
        self.recover_corrupt_after(inventory, reason, |names| {
            recovery_prompt(reason, inventory, names)
        })
    }

    /// Recover only after an affirmative answer: Team and Admin start for a bounded reset only once confirmed.
    fn recover_corrupt_after(
        &self,
        inventory: &Inventory,
        reason: &str,
        confirm: impl FnOnce(&[String]) -> Result<bool, String>,
    ) -> Result<(), String> {
        if self.scheduled {
            return Err(reason.into());
        }
        let names = inventory.container_names(&self.engine)?;
        if !confirm(&names)? {
            return Err("the corrupt Local Space was preserved; nothing changed".into());
        }
        let admin = self.prepare_admin_for_recovery()?;
        let admin_port = match admin {
            AdminAttestation::Running { port } if admin_available(port) => Some(port),
            _ => None,
        };
        if admin_port.is_some()
            && let Ok(installed) = state::read_installed(&self.paths, self.profile)
            && installed_graph_is_current(&self.paths, self.profile)?
        {
            admin_reset(&self.engine, &installed)?;
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
        corrupt_recovery_scheduler(scheduler::remove(self.profile, &self.paths))?;
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

    /// Report a release-bound CLI run truthfully: it may have deferred the update or left it unapplied.
    fn handoff_outcome(&self, release: &ResolvedRelease) -> Result<String, String> {
        if state::read_installed(&self.paths, self.profile)?.release_ref == release.reference {
            let completed = "The release-bound CLI completed reconciliation.";
            return Ok(if self.recreated.get() {
                format!("{completed}\n{}", recreation_notice(release))
            } else {
                completed.into()
            });
        }
        let deferred = poll::release_digest(&release.reference)
            .is_some_and(|digest| poll::deferred(&self.paths, digest, poll::now()));
        Ok(if deferred {
            UPDATE_DEFERRED.into()
        } else {
            "The release-bound CLI finished without applying the selected Local release.".into()
        })
    }

    /// Immediately before a scheduled update replaces a different running release, give active Team work a
    /// bounded chance to finish. A repair of the installed release never waits.
    fn defer_for_activity(
        &self,
        release: &ResolvedRelease,
        installed: Option<&Installed>,
    ) -> Result<bool, String> {
        if installed.is_none_or(|installed| installed.release_ref == release.reference) {
            return Ok(false);
        }
        let Some(digest) = poll::release_digest(&release.reference) else {
            return Ok(false);
        };
        // Ownership is re-proved here and its failure aborts the apply; only the Team client itself may be unknown.
        let team = Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?
            .team_container_id(&self.engine)?;
        poll::defer_for_activity(&self.paths, digest, poll::now(), || match &team {
            Some(team) => self.engine.team_activity(team, TEAM_ACTIVITY_TIMEOUT),
            None => poll::TeamActivity::Idle,
        })
    }

    fn handoff_if_needed(
        &self,
        release: &ResolvedRelease,
        installed: Option<&Installed>,
        scheduled: bool,
    ) -> Result<bool, String> {
        admit_before_handoff(release, installed, || {
            self.handoff_admitted_release(release, scheduled)
        })
    }

    fn handoff_admitted_release(
        &self,
        release: &ResolvedRelease,
        scheduled: bool,
    ) -> Result<bool, String> {
        let running = std::env::current_exe().map_err(|_| "the running CLI path is unavailable")?;
        reconcile_previous_cli(&self.paths.managed_cli, &running)?;
        let expected = expected_cli_hash(release, self.profile)?;
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
                .arg(&release.reference)
                .arg("--candidate");
        }
        let record_before = state::read_state_record(&self.paths);
        let failure = handoff_failure(command.stdin(Stdio::null()).status());
        // Only a completed recreation writes a new record; a record the child forgot but never rewrote proves none.
        if state::read_state_record(&self.paths)
            .is_some_and(|record| Some(&record) != record_before.as_ref())
        {
            self.recreated.set(true);
        }
        self.handoff_result(release, scheduled, &previous, failure)
            .map_err(|error| self.with_recreation(error))
    }

    /// Append the recreation of the runtime state to a failure that followed it: no rollback restores that state.
    fn with_recreation(&self, error: String) -> String {
        if self.recreated.get() {
            format!("{error}; the Team runtime state was recreated empty")
        } else {
            error
        }
    }

    fn handoff_result(
        &self,
        release: &ResolvedRelease,
        scheduled: bool,
        previous: &Path,
        failure: Option<String>,
    ) -> Result<bool, String> {
        // A successful exit proves nothing on its own: a scheduled child also succeeds when it defers the update or
        // finds storage locked, so the durable commit evidence decides which CLI matches the Space.
        match (commit_evidence(&self.paths, self.profile, release), failure) {
            (CommitEvidence::Committed, None) => {
                remove_regular_if_present(previous)?;
                ensure_public_cli(&self.paths)?;
                Ok(true)
            }
            (CommitEvidence::Committed, Some(reason)) => {
                // The child committed this release before failing, for example while enabling its scheduler, so
                // the Space now runs the release this CLI is bound to; the previous CLI must not be paired with it.
                let failure = format!(
                    "the release-bound CLI committed the release but did not complete ({reason}); the release-bound CLI was kept"
                );
                Err(
                    match remove_regular_if_present(previous)
                        .and_then(|()| ensure_public_cli(&self.paths))
                    {
                        Ok(()) => failure,
                        Err(error) => format!("{failure}; {error}"),
                    },
                )
            }
            (CommitEvidence::Unknown(cause), None) => {
                Err(self.uncertain_handoff("exited successfully, but", &cause, previous))
            }
            (CommitEvidence::Unknown(cause), Some(reason)) => Err(self.uncertain_handoff(
                &format!("did not complete ({reason}), and"),
                &cause,
                previous,
            )),
            (CommitEvidence::NotCommitted, None) => {
                restore_previous_cli(&self.paths.managed_cli, previous)?;
                if scheduled {
                    // Only a scheduled run may legitimately skip the commit; the caller reports the deferred or
                    // unapplied outcome from the unchanged Local state.
                    Ok(true)
                } else {
                    Err("the release-bound CLI exited without committing the selected Local release; the previous CLI was restored".into())
                }
            }
            (CommitEvidence::NotCommitted, Some(reason)) => {
                restore_previous_cli(&self.paths.managed_cli, previous)?;
                Err(format!(
                    "the release-bound CLI did not complete ({reason}); the previous CLI was restored"
                ))
            }
        }
    }

    /// Neither CLI can be proved to match the Space, so neither is discarded.
    fn uncertain_handoff(&self, outcome: &str, cause: &str, previous: &Path) -> String {
        format!(
            "the release-bound CLI {outcome} whether it committed the release could not be determined: {cause}; both CLIs were kept: {} (release-bound) and {} (previous). Next: run {} install; it reconciles the Space, offers recovery when its state is corrupt, and removes the previous CLI",
            self.paths.managed_cli.display(),
            previous.display(),
            self.paths.managed_cli.display()
        )
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
                    "the partial fresh Local release was removed, so installation can be retried"
                        .into(),
                ),
                Err(cleanup) => Err(format!(
                    "the partial fresh Local release could not be removed; compensation failed: {cleanup}"
                )),
            };
        };
        let memory_error = state::remember_failed_release(&self.paths, release).err();
        fs::rename(&backup.compose, &self.paths.compose).map_err(io_error)?;
        fs::rename(&backup.environment, &self.paths.environment).map_err(io_error)?;
        let installed = state::read_installed(&self.paths, self.profile)?;
        let previous_epoch = self.engine.release_state_epoch(&installed.release_ref).ok();
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
        // The previous release must never start on runtime state in a stored format it does not read.
        let restored = match self.reconcile_runtime_state(
            previous_epoch,
            &release.metadata.team,
            false,
        ) {
            // A restoration that could not run, or outlived its deadline, is a failed restoration: the rollback
            // status is still recorded.
            Ok(_) => match self.engine.compose(
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
            ) {
                Ok(status) => status.success(),
                Err(error) => {
                    output::warning(&format!(
                        "the previous release could not be started: {error}"
                    ));
                    false
                }
            },
            Err(error) => {
                output::warning(&format!(
                    "the previous release was not started because its runtime state could not be recreated: {error}"
                ));
                false
            }
        };
        // Persist and project independently: a failed local write must not leave Admin reporting the abandoned release.
        let status = state::status_document(release, "rollback-needed")?;
        let persisted = state::write_private(&self.paths.status, &status);
        let unreaped = if restored {
            self.project_rollback_status(release, &status)
        } else {
            None
        };
        // The restoration's own outcome leads; failed-release memory and scheduler diagnostics only follow it.
        let primary = if restored {
            "the update failed; the previous healthy release was restored"
        } else {
            "the update and its rollback both failed"
        };
        let primary = match persisted {
            Ok(()) => primary.to_owned(),
            Err(error) => format!("{primary}; the rollback status could not be recorded: {error}"),
        };
        // A status helper that could not be reaped may remain, so its cause follows the outcome.
        let primary = match unreaped {
            Some(cause) => format!("{primary}; {cause}"),
            None => primary,
        };
        if memory_error.is_some() {
            return Err(format!("{primary}; {}", self.disable_automatic_updates()));
        }
        Err(primary)
    }

    /// Project the rollback status to the restored Admin, warning when it cannot receive it, and return the cause of
    /// a status helper that could not be reaped, which may remain.
    fn project_rollback_status(&self, release: &ResolvedRelease, status: &str) -> Option<String> {
        let failure = self
            .engine
            .project_release_status(&release.metadata.admin, status.as_bytes())
            .err()?;
        output::warning(
            "the previous release was restored, but Admin could not receive the rollback status",
        );
        match failure {
            ProjectionFailure::Unreaped(cause) => Some(cause),
            ProjectionFailure::NotProjected(_) => None,
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
                    record_retained_bin_entries(&self.paths, &mut preserved)?;
                } else {
                    preserved.record(path);
                }
            }
        }
        Ok(preserved.into_strings())
    }
}

/// A fresh installation may follow corrupt recovery only once owned scheduler entries are gone: later failures would
/// otherwise skip scheduler reconciliation and leave owned residue. Unrecognized entries stay preserved with a warning.
fn corrupt_recovery_scheduler(
    removal: Result<scheduler::RemovalOutcome, String>,
) -> Result<(), String> {
    match removal {
        Ok(outcome) if outcome.execution_unverified => {
            output::warning(&format!(
                "Preserved unrecognized scheduler entries; their execution state is unverified: {}",
                outcome.preserved.join(", ")
            ));
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(error) => Err(format!(
            "the corrupt Local Space was removed, but its owned scheduler cleanup did not complete, so no fresh installation was started: {error}. After resolving that, run shimpz reset to finish the cleanup, then run shimpz install"
        )),
    }
}

fn remove_runtime_files(paths: &Paths) -> Result<(), String> {
    for path in managed_runtime_files(paths) {
        remove_regular_if_present(&path)?;
    }
    Ok(())
}

fn managed_runtime_files(paths: &Paths) -> [PathBuf; 23] {
    [
        paths.deploy_request.clone(),
        paths.deploy_result.clone(),
        paths.state_epoch.clone(),
        paths.deploy_request.with_extension("tmp"),
        paths.deploy_result.with_extension("tmp"),
        paths.state_epoch.with_extension("tmp"),
        paths.compose.clone(),
        paths.environment.clone(),
        paths.status.clone(),
        paths.release_poll.clone(),
        paths.failed_release.clone(),
        paths.stopped.clone(),
        paths.compose.with_extension("previous"),
        paths.environment.with_extension("previous"),
        paths.compose.with_extension("tmp"),
        paths.environment.with_extension("tmp"),
        paths.status.with_extension("tmp"),
        paths.release_poll.with_extension("tmp"),
        paths.failed_release.with_extension("tmp"),
        paths.stopped.with_extension("tmp"),
        paths.home.join("release.env.tmp"),
        paths.marker.with_extension("tmp"),
        paths.marker.clone(),
    ]
}

fn preflight_remove_files(paths: &Paths, protected_storage: bool) -> Result<Vec<String>, String> {
    let managed = managed_runtime_files(paths);
    for path in &managed {
        validate_regular_if_present(path)?;
    }
    let mut preserved = PathReport::default();
    if paths.home.exists() {
        let bin = paths
            .managed_cli
            .parent()
            .expect("managed CLI has a parent");
        for entry in fs::read_dir(&paths.home).map_err(io_error)? {
            let path = entry.map_err(io_error)?.path();
            if path == bin {
                record_retained_bin_entries(paths, &mut preserved)?;
            } else if !(managed.contains(&path) || protected_storage && path == paths.security) {
                preserved.record(path);
            }
        }
    }
    Ok(preserved.into_strings())
}

fn record_retained_bin_entries(paths: &Paths, preserved: &mut PathReport) -> Result<(), String> {
    let bin = paths
        .managed_cli
        .parent()
        .expect("managed CLI has a parent");
    let metadata = match bin.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "the managed CLI directory is invalid: {}",
            bin.display()
        ));
    }
    for entry in fs::read_dir(bin).map_err(io_error)? {
        let path = entry.map_err(io_error)?.path();
        if path == paths.managed_cli
            || path == paths.managed_cli.with_extension("candidate")
            || path == paths.managed_cli.with_extension("previous")
        {
            validate_private_cli(&path)?;
        } else {
            preserved.record(path);
        }
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

fn recreation_notice(release: &ResolvedRelease) -> String {
    format!(
        "Recreated the Team runtime state for state epoch {}; its earlier records were removed.",
        release.metadata.state_epoch
    )
}

fn ready_outcome(release: &ResolvedRelease, port: u16) -> String {
    format!(
        "Shimpz Space is ready.\nAdmin: http://127.0.0.1:{port}\nRelease: ordinal {}\nNext: open the Admin address above.",
        release.metadata.ordinal
    )
}

fn current_release_outcome(installed: &Installed, stopped: bool) -> String {
    let next = if stopped {
        "Stopped intent was preserved.\nNext: shimpz start"
    } else {
        "Next: shimpz status"
    };
    format!(
        "The installed Shimpz Space release is current.\nRelease: ordinal {}\n{next}",
        installed.ordinal
    )
}

fn available_release_outcome(installed: &Installed, release: &ResolvedRelease) -> String {
    format!(
        "A newer Shimpz Space release is available.\nInstalled release: ordinal {}\nAvailable release: ordinal {}\nStopped intent was preserved.\nNext: shimpz start",
        installed.ordinal, release.metadata.ordinal
    )
}

fn failed_update_outcome(stopped: bool) -> String {
    if stopped {
        "The selected Local release previously failed health.\nStopped intent was preserved.\nNext: shimpz start to resume the installed release."
            .into()
    } else {
        "The selected Local release previously failed health; the current Space remains unchanged.\nNext: wait for a different Local release selection."
            .into()
    }
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

fn hard_reset_outcome(preserved: &[String], scheduler_execution_unverified: bool) -> String {
    let cleanup = if preserved.is_empty() {
        "No managed Space data remains.".to_owned()
    } else {
        format!("Preserved unrecognized content: {}.", preserved.join(", "))
    };
    let scheduler = if scheduler_execution_unverified {
        " Scheduler execution state is unverified; review the preserved entry before reinstalling."
    } else {
        ""
    };
    format!(
        "Shimpz Space hard reset completed. {cleanup} Retained: the shimpz command, lifecycle lock, Creator credentials, and pulled images.{scheduler}\nNext: shimpz install"
    )
}

fn hard_reset_incomplete(error: &str) -> String {
    format!(
        "{error}; hard reset did not complete and the Space may be stopped; re-run shimpz reset --hard"
    )
}

fn hard_reset_preflight(error: &str) -> String {
    format!(
        "{error}; nothing changed; resolve the reported Local ownership or host prerequisite, then re-run shimpz reset --hard"
    )
}

/// The release a lifecycle run is replacing the live configuration with.
struct Candidate<'a> {
    release: &'a ResolvedRelease,
    installed: Option<&'a Installed>,
    space_id: &'a str,
    port: u16,
    docker_gid: u32,
    docker_socket: &'a Path,
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
            .map(|path| output::sanitize_inline(&path.to_string_lossy()))
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
            .map(|path| output::sanitize_inline(&path.to_string_lossy()))
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
    validate_managed_bin(paths)
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

fn validate_managed_bin(paths: &Paths) -> Result<(), String> {
    let bin = paths
        .managed_cli
        .parent()
        .expect("managed CLI has a parent");
    let metadata = match bin.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error(error)),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
    {
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

#[derive(Debug, Eq, PartialEq)]
enum CommitEvidence {
    Committed,
    NotCommitted,
    Unknown(String),
}

/// What the durable Local state proves about whether `release` committed. It committed only when its environment is
/// live and the status records its successful reconciliation: the environment is written before health is proved,
/// and the success status is the commit's last write, which a rollback replaces or removes. A missing environment,
/// an environment of another release, or a missing or other valid status proves it did not; anything unreadable or
/// malformed proves nothing.
fn commit_evidence(
    paths: &Paths,
    profile: HostProfile,
    release: &ResolvedRelease,
) -> CommitEvidence {
    let installed = match state::read_private_installed(paths, profile) {
        Ok(Some(installed)) => installed,
        Ok(None) => return CommitEvidence::NotCommitted,
        Err(cause) => return CommitEvidence::Unknown(cause),
    };
    if installed.release_ref != release.reference {
        return CommitEvidence::NotCommitted;
    }
    if installed.ordinal != release.metadata.ordinal {
        return CommitEvidence::Unknown("the installed Local release ordinal is ambiguous".into());
    }
    match poll::status_record(paths, &release.reference, release.metadata.ordinal) {
        poll::StatusRecord::Reconciled => CommitEvidence::Committed,
        poll::StatusRecord::Other => CommitEvidence::NotCommitted,
        poll::StatusRecord::Unknown(cause) => CommitEvidence::Unknown(cause),
    }
}

/// Make the verified release-bound CLI the managed executable. The caller holds the lifecycle lock and has admitted
/// the exact release; nothing restores the previous executable, because apply retains the release-bound CLI.
fn activate_cli(paths: &Paths, running: &Path, expected: &str) -> Result<(), String> {
    let bin = paths
        .managed_cli
        .parent()
        .expect("managed CLI has a parent");
    match bin.symlink_metadata() {
        Ok(_) => validate_managed_bin(paths)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(bin).map_err(io_error)?;
        }
        Err(error) => return Err(io_error(error)),
    }
    fs::set_permissions(bin, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    let candidate = paths.managed_cli.with_extension("candidate");
    if same_file(running, &paths.managed_cli)? {
        // Replacing the running managed executable would unlink the image that apply verifies; keep its inode.
        if hash_file(&paths.managed_cli)? != expected {
            return Err("the running CLI is not bound to the selected Local release".into());
        }
        fs::set_permissions(&paths.managed_cli, fs::Permissions::from_mode(0o700))
            .map_err(io_error)?;
        remove_regular_if_present(&candidate)?;
    } else {
        remove_regular_if_present(&candidate)?;
        let staged = stage_cli(running, &candidate, expected)
            .and_then(|()| fs::rename(&candidate, &paths.managed_cli).map_err(io_error));
        if let Err(error) = staged {
            return Err(match remove_regular_if_present(&candidate) {
                Ok(()) => error,
                Err(cleanup) => format!("{error}; the staged CLI could not be removed: {cleanup}"),
            });
        }
    }
    remove_regular_if_present(&paths.managed_cli.with_extension("previous")).map_err(|error| {
        format!(
            "the release-bound CLI was installed, but a stale previous CLI could not be removed: {error}; run the installer again"
        )
    })
}

/// Copy the release-bound CLI to its private staging path and verify the copied bytes, not only their source.
fn stage_cli(source: &Path, candidate: &Path, expected: &str) -> Result<(), String> {
    fs::copy(source, candidate).map_err(io_error)?;
    fs::set_permissions(candidate, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    if hash_file(candidate)? != expected {
        return Err("the running CLI is not bound to the selected Local release".into());
    }
    Ok(())
}

fn same_file(left: &Path, right: &Path) -> Result<bool, String> {
    let right = match right.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(io_error(error)),
    };
    let left = fs::metadata(left).map_err(io_error)?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
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

/// Admit only forward moves among published releases (ADR-0041). A developer release is an explicit selection on
/// this host and installs freshly or applies over any installed release; the explicit return to the published
/// channel replaces an installed developer release with any published release.
fn validate_forward_release(
    release: &ResolvedRelease,
    installed: Option<&Installed>,
) -> Result<(), String> {
    let Some(installed) = installed else {
        return Ok(());
    };
    if release::valid_developer_release_ref(&release.reference) || installed.developer() {
        return Ok(());
    }
    let same_reference = release.reference == installed.release_ref;
    let same_ordinal = release.metadata.ordinal == installed.ordinal;
    if release.metadata.ordinal < installed.ordinal || same_reference != same_ordinal {
        return Err("the Local release channel moved backward or became ambiguous".into());
    }
    Ok(())
}

/// Existing runtime state is recreated unless both the epoch recorded for it and the starting release's are known
/// and equal; a fresh Space has none.
fn runtime_state_reset_needed(fresh: bool, epoch: Option<u32>, recorded: Option<u32>) -> bool {
    !fresh && (epoch.is_none() || recorded != epoch)
}

fn admit_before_handoff<T>(
    release: &ResolvedRelease,
    installed: Option<&Installed>,
    handoff: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    validate_forward_release(release, installed)?;
    handoff()
}

fn expected_cli_hash(release: &ResolvedRelease, profile: HostProfile) -> Result<&str, String> {
    match profile {
        HostProfile::Linux | HostProfile::Wsl => Ok(&release.metadata.cli_linux_amd64_sha256),
        HostProfile::MacOs => release
            .metadata
            .cli_macos_arm64_sha256
            .as_deref()
            .ok_or_else(|| "the Local release carries no macOS CLI".to_owned()),
    }
}

fn verify_running_cli(release: &ResolvedRelease, profile: HostProfile) -> Result<(), String> {
    let current = std::env::current_exe().map_err(|_| "the running CLI path is unavailable")?;
    if hash_file(&current)? == expected_cli_hash(release, profile)? {
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

fn hard_reset_prompt(
    inventory: &Inventory,
    names: &[String],
    preserved: &[String],
) -> Result<bool, String> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| "hard reset requires an interactive terminal; nothing changed".to_owned())?;
    writeln!(
        tty,
        "Hard reset bypasses Shimpz Supervisor authorization and permanently removes the current owned Local Space."
    )
    .map_err(io_error)?;
    writeln!(
        tty,
        "Owned Docker scope: {} containers, {} volumes, {} networks",
        inventory.project_containers.len() + inventory.dynamic_containers.len(),
        inventory.project_volumes.len(),
        inventory.project_networks.len() + inventory.dynamic_networks.len()
    )
    .map_err(io_error)?;
    if !names.is_empty() {
        writeln!(tty, "Containers: {}", names.join(", ")).map_err(io_error)?;
    }
    if !preserved.is_empty() {
        writeln!(
            tty,
            "Preserved unrecognized content: {}",
            preserved.join(", ")
        )
        .map_err(io_error)?;
    }
    writeln!(
        tty,
        "Owned runtime files, scheduler state, and protected Linux storage are also removed when present."
    )
    .map_err(io_error)?;
    writeln!(
        tty,
        "Docker and host authorization remain required. Creator credentials, pulled images, the shimpz command, and lifecycle lock are retained."
    )
    .map_err(io_error)?;
    hard_reset_confirmation(&mut tty)
}

fn hard_reset_confirmation(terminal: &mut (impl Read + Write)) -> Result<bool, String> {
    write!(
        terminal,
        "Permanently hard reset this exact owned Local Space? [Yes/No] "
    )
    .map_err(io_error)?;
    terminal.flush().map_err(io_error)?;
    let mut answer = String::new();
    let mut byte = [0_u8; 1];
    while terminal.read(&mut byte).map_err(io_error)? == 1 {
        if byte[0] == b'\n' {
            break;
        }
        if answer.len() >= 8 || byte[0].is_ascii_control() {
            return Err("the hard reset answer is invalid; nothing changed".into());
        }
        answer.push(char::from(byte[0]));
    }
    match answer.as_str() {
        "Yes" => Ok(true),
        "No" | "" => Ok(false),
        _ => Err("the hard reset answer is invalid; nothing changed".into()),
    }
}

/// How many long-running Space containers `release` replaces, from the `previous` Admin, Team, Brain, and egress
/// images: one each for the first three and four for the shared egress image.
fn replaced_container_count(previous: &[String; 4], release: &ResolvedRelease) -> usize {
    let metadata = &release.metadata;
    [
        (&metadata.admin, 1),
        (&metadata.team, 1),
        (&metadata.brain, 1),
        (&metadata.egress, 4),
    ]
    .into_iter()
    .zip(previous)
    .filter(|((candidate, _), installed)| *candidate != *installed)
    .map(|((_, containers), _)| containers)
    .sum()
}

/// The long-running Space containers, among `identifiers` and their `name|image` records, whose image `release`
/// replaces. The one-shot initializer is left to Compose, and any record that is not exactly a name and an image
/// refuses the selection.
fn replaced_containers(
    identifiers: &[String],
    records: &[String],
    release: &ResolvedRelease,
) -> Result<Vec<String>, String> {
    let malformed = || "a Local container image record is malformed".to_owned();
    if identifiers.len() != records.len() {
        return Err(malformed());
    }
    let mut replaced = Vec::new();
    for (identifier, record) in identifiers.iter().zip(records) {
        let (name, image) = record.split_once('|').ok_or_else(malformed)?;
        let candidate = match name {
            "/shimpz-admin" => &release.metadata.admin,
            "/shimpz-team" => &release.metadata.team,
            "/shimpz-brain" => &release.metadata.brain,
            "/shimpz-brain-egress"
            | "/shimpz-assistant-egress"
            | "/shimpz-assistant-release"
            | "/shimpz-account-egress" => &release.metadata.egress,
            "/shimpz-account-egress-init" => continue,
            _ => return Err(malformed()),
        };
        if image.is_empty() {
            return Err(malformed());
        }
        if image != candidate {
            replaced.push(identifier.clone());
        }
    }
    Ok(replaced)
}

/// The answer of one concurrent helper; a worker that panicked answered nothing, which refuses the release.
fn joined<T>(
    handle: thread::ScopedJoinHandle<'_, Withheld<Result<T, String>>>,
) -> Withheld<Result<T, String>> {
    handle
        .join()
        .unwrap_or_else(|_| output::withhold(|| Err("a Local release check failed".into())))
}

fn candidate_admission_error(error: &str) -> String {
    format!("{error}; the installed release is unchanged")
}

fn admin_authentication_state_response(
    status: u16,
    body: &serde_json::Value,
) -> Result<AdminAuthenticationState, String> {
    let invalid = || "Admin returned an invalid Local authentication-state contract".to_owned();
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
            .get("authentication_state")
            .and_then(serde_json::Value::as_str),
        object["initialized"].as_bool(),
    ) {
        (Some("uninitialized"), Some(false)) => Ok(AdminAuthenticationState::Uninitialized),
        (Some("enrollment-required"), Some(true)) => {
            Ok(AdminAuthenticationState::EnrollmentRequired)
        }
        (Some("configured"), Some(true)) => Ok(AdminAuthenticationState::Configured),
        (Some("recovery-required"), Some(true)) => Ok(AdminAuthenticationState::RecoveryRequired),
        _ => Err(invalid()),
    }
}

fn admin_authentication_state_probe_response(
    response: &str,
) -> Result<AdminAuthenticationState, String> {
    match response {
        "uninitialized" => Ok(AdminAuthenticationState::Uninitialized),
        "enrollment-required" => Ok(AdminAuthenticationState::EnrollmentRequired),
        "configured" => Ok(AdminAuthenticationState::Configured),
        "recovery-required" => Ok(AdminAuthenticationState::RecoveryRequired),
        _ => Err("the selected Admin returned an invalid authentication-state contract".into()),
    }
}

fn admin_authentication_state(port: u16) -> Result<AdminAuthenticationState, String> {
    let config = Agent::config_builder()
        .timeout_global(Some(ADMIN_SESSION_TIMEOUT))
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    let agent = Agent::new_with_config(config);
    let mut response = agent
        .post(format!("http://127.0.0.1:{port}/api/session"))
        .send_empty()
        .map_err(|_| "Admin did not provide the Local authentication-state contract".to_owned())?;
    let status = response.status().as_u16();
    let body: serde_json::Value = response
        .body_mut()
        .with_config()
        .limit(1_024)
        .read_json()
        .map_err(|_| "Admin returned an invalid Local authentication-state contract".to_owned())?;
    admin_authentication_state_response(status, &body)
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
    retry_after: Option<&str>,
    password_presented: bool,
) -> Result<AdminResetDecision, String> {
    if status == 200
        && body.as_object().is_some_and(|object| {
            object.len() == 1 && object.get("reset") == Some(&serde_json::Value::Bool(true))
        })
    {
        return Ok(AdminResetDecision::Complete);
    }
    if !password_presented
        && status == 409
        && body.as_object().is_some_and(|object| {
            object.len() == 2
                && object.get("code").and_then(serde_json::Value::as_str)
                    == Some("supervisor-password-required")
                && object
                    .get("detail")
                    .and_then(serde_json::Value::as_str)
                    .is_some()
        })
    {
        return Ok(AdminResetDecision::PasswordRequired);
    }
    if password_presented {
        match status {
            401 => return Err("the Supervisor password was rejected".into()),
            429 => {
                let wait = match retry_after_seconds(retry_after) {
                    Some(1) => "wait 1 second".to_owned(),
                    Some(seconds) => format!("wait {seconds} seconds"),
                    None => "wait one minute".to_owned(),
                };
                return Err(format!(
                    "too many Supervisor password attempts; {wait}, then re-run shimpz reset"
                ));
            }
            _ => {}
        }
    }
    Err(RESET_INCOMPLETE.into())
}

fn request_admin_reset(
    port: u16,
    capability: &str,
    password: Option<&str>,
) -> Result<AdminResetDecision, String> {
    let config = Agent::config_builder()
        .timeout_global(Some(ADMIN_RESET_TIMEOUT))
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    let agent = Agent::new_with_config(config);
    let payload = match password {
        Some(password) => serde_json::json!({"capability": capability, "password": password}),
        None => serde_json::json!({"capability": capability}),
    };
    let body = serde_json::to_string(&payload)
        .map_err(|_| "could not encode the authorized Space reset".to_owned())?;
    let request = ureq::http::Request::delete(format!("http://127.0.0.1:{port}/api/space/host"))
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(|_| "could not build the authorized Space reset".to_owned())?;
    let mut response = agent
        .run(request)
        .map_err(|_| RESET_INCOMPLETE.to_owned())?;
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let response_body: serde_json::Value = response
        .body_mut()
        .with_config()
        .limit(1_024)
        .read_json()
        .map_err(|_| RESET_INCOMPLETE.to_owned())?;
    admin_reset_decision(
        status,
        &response_body,
        retry_after.as_deref(),
        password.is_some(),
    )
}

fn retry_after_seconds(value: Option<&str>) -> Option<u16> {
    let value = value?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value
        .parse::<u16>()
        .ok()
        .filter(|seconds| (1..=3_600).contains(seconds))
}

fn generate_host_reset_capability(space_id: &str) -> Result<HostResetCapability, String> {
    let mut source = fs::File::open("/dev/urandom")
        .map_err(|_| "the system random source is unavailable".to_owned())?;
    let mut secret_bytes = [0_u8; 32];
    source
        .read_exact(&mut secret_bytes)
        .map_err(|_| "could not generate the Local reset capability".to_owned())?;
    let mut secret = String::with_capacity(64);
    for byte in secret_bytes {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        secret.push(char::from(HEX[usize::from(byte >> 4)]));
        secret.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "the system clock cannot authorize a Local reset".to_owned())?
        .as_secs();
    let expires_at = created_at
        .checked_add(HOST_RESET_CAPABILITY_SECONDS)
        .ok_or_else(|| "the system clock cannot authorize a Local reset".to_owned())?;
    let capability_sha256 = format!("{:x}", Sha256::digest(secret_bytes));
    let document = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "purpose": "space-reset",
        "space_id": space_id,
        "created_at": created_at,
        "expires_at": expires_at,
        "capability_sha256": capability_sha256,
    }))
    .map_err(|_| "could not encode the Local reset capability".to_owned())?;
    Ok(HostResetCapability {
        secret: Zeroizing::new(secret),
        document,
    })
}

fn projected_admin_reset(
    engine: &Engine,
    installed: &Installed,
    password: Option<&str>,
) -> Result<AdminResetDecision, String> {
    let capability = generate_host_reset_capability(&installed.space_id)?;
    engine.project_reset_capability(&installed.admin_image, &capability.document)?;
    let result = request_admin_reset(installed.port, capability.secret.as_str(), password);
    let cleanup = engine.clear_reset_capability(&installed.admin_image);
    match (result, cleanup) {
        (Ok(decision), Ok(())) => Ok(decision),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(format!("{error}; {cleanup_error}")),
    }
}

fn admin_reset(engine: &Engine, installed: &Installed) -> Result<(), String> {
    output::progress("Authorizing the Shimpz Space reset...");
    if projected_admin_reset(engine, installed, None)? == AdminResetDecision::Complete {
        return Ok(());
    }
    let password = Zeroizing::new(
        rpassword::prompt_password("Supervisor password: ")
            .map_err(|_| "could not read the Supervisor password".to_owned())?,
    );
    if password.is_empty() {
        return Err("the Supervisor password is required".into());
    }
    output::progress("Verifying the Supervisor password...");
    if projected_admin_reset(engine, installed, Some(password.as_str()))?
        == AdminResetDecision::Complete
    {
        Ok(())
    } else {
        Err(RESET_INCOMPLETE.into())
    }
}

fn remove_backup(backup: Option<Backup>) -> Result<(), String> {
    if let Some(backup) = backup {
        fs::remove_file(backup.compose).map_err(io_error)?;
        fs::remove_file(backup.environment).map_err(io_error)?;
    }
    Ok(())
}

/// Name why a release-bound CLI run did not succeed; its own diagnostic, if any, precedes this in the log.
fn handoff_failure(status: std::io::Result<std::process::ExitStatus>) -> Option<String> {
    match status {
        Ok(status) if status.success() => None,
        Ok(status) => Some(match status.code() {
            Some(code) => format!("it exited with status {code}"),
            None => "it was stopped by a signal".into(),
        }),
        Err(error) => Some(format!("it could not start: {error}")),
    }
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

fn update_decision(
    installed: &Installed,
    release: &ResolvedRelease,
    stopped: bool,
    selected_failed: bool,
) -> UpdateDecision {
    if selected_failed {
        UpdateDecision::Failed
    } else if installed.release_ref == release.reference
        && installed.ordinal == release.metadata.ordinal
    {
        UpdateDecision::Current
    } else if stopped {
        UpdateDecision::Available
    } else {
        UpdateDecision::Apply
    }
}

fn run_update_effect(
    decision: UpdateDecision,
    apply: impl FnOnce() -> Result<String, String>,
) -> Result<Option<String>, String> {
    match decision {
        UpdateDecision::Apply => apply().map(Some),
        UpdateDecision::Current | UpdateDecision::Failed | UpdateDecision::Available => Ok(None),
    }
}

fn remove_regular_if_present(path: &Path) -> Result<(), String> {
    if !validate_regular_if_present(path)? {
        return Ok(());
    }
    fs::remove_file(path).map_err(io_error)
}

fn validate_regular_if_present(path: &Path) -> Result<bool, String> {
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(io_error(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "refusing to remove invalid managed file: {}",
            path.display()
        ));
    }
    Ok(true)
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

    use std::io::Cursor;

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
                cli_macos_arm64_sha256: Some(HEX.into()),
                admin: format!("ghcr.io/theshimpz/shimpz-admin@sha256:{HEX}"),
                team: format!("ghcr.io/theshimpz/shimpz-team-local@sha256:{HEX}"),
                brain: format!("ghcr.io/theshimpz/shimpz-brain@sha256:{HEX}"),
                egress: format!("ghcr.io/theshimpz/shimpz-egress@sha256:{HEX}"),
                state_epoch: 1,
            },
        }
    }

    /// A developer release with a rebuilt Admin, identified by `digest`.
    fn developer(ordinal: u64, digest: char) -> ResolvedRelease {
        let mut metadata = release(ordinal, 'b').metadata;
        metadata.admin = format!("localhost/shimpz-admin@sha256:{}", "e".repeat(64));
        metadata.cli_macos_arm64_sha256 = None;
        ResolvedRelease {
            reference: format!(
                "localhost/shimpz-local-release@sha256:{}",
                digest.to_string().repeat(64)
            ),
            metadata,
        }
    }

    fn installed_from(release: &ResolvedRelease) -> Installed {
        Installed {
            space_id: "space-0123456789abcdef01234567".into(),
            release_ref: release.reference.clone(),
            admin_image: release.metadata.admin.clone(),
            ordinal: release.metadata.ordinal,
            port: 7777,
        }
    }

    #[test]
    fn a_developer_release_installs_or_applies_over_any_installation_and_yields_to_an_explicit_return()
     {
        let published = installed_from(&release(2, 'b'));
        let installed = installed_from(&developer(9, '1'));
        // As a fresh install, or over a published release or another developer release, in either direction.
        assert!(validate_forward_release(&developer(9, '1'), None).is_ok());
        assert!(validate_forward_release(&developer(9, '1'), Some(&published)).is_ok());
        assert!(validate_forward_release(&developer(1, '2'), Some(&installed)).is_ok());
        assert!(validate_forward_release(&developer(9, '1'), Some(&installed)).is_ok());
        // The explicit return to the published channel replaces it with any published release.
        assert!(validate_forward_release(&release(1, 'a'), Some(&installed)).is_ok());
        assert!(validate_forward_release(&release(3, 'c'), Some(&installed)).is_ok());
        // Published releases still move only forward.
        assert!(validate_forward_release(&release(1, 'a'), Some(&published)).is_err());
        assert!(validate_forward_release(&release(2, 'c'), Some(&published)).is_err());
        assert!(validate_forward_release(&release(3, 'c'), Some(&published)).is_ok());
        // While running, an explicit update returns to `stable`; a stopped Space only reports it.
        assert_eq!(
            update_decision(&installed, &release(2, 'b'), false, false),
            UpdateDecision::Apply
        );
        assert_eq!(
            update_decision(&installed, &release(2, 'b'), true, false),
            UpdateDecision::Available
        );
    }

    /// The release.env document of a resolved release, as a release set image carries it.
    fn release_document(release: &ResolvedRelease) -> String {
        let metadata = &release.metadata;
        let (schema, macos) = match &metadata.cli_macos_arm64_sha256 {
            Some(hash) => ("local-v2", format!("cli_macos_arm64_sha256={hash}\n")),
            None => ("local-dev-v2", String::new()),
        };
        format!(
            "schema={schema}\nordinal={}\numbrella_revision={}\ncli_revision={}\ncli_linux_amd64_sha256={}\n{macos}admin={}\nteam={}\nbrain={}\negress={}\n",
            metadata.ordinal,
            metadata.umbrella_revision,
            metadata.cli_revision,
            metadata.cli_linux_amd64_sha256,
            metadata.admin,
            metadata.team,
            metadata.brain,
            metadata.egress,
        )
    }

    /// A Docker stand-in holding one developer release and the published images it reuses. It logs every call,
    /// declares state epoch 1 for every set, serves `localhost/` images only from its "store", and refuses to pull
    /// them.
    #[cfg(unix)]
    fn developer_docker(directory: &Path, developer: &ResolvedRelease) -> PathBuf {
        let developer_document = directory.join("developer.env");
        fs::write(&developer_document, release_document(developer)).unwrap();
        let log = directory.join("docker.log");
        let docker = directory.join("docker");
        crate::fake_tool::write(
            &docker,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\ncase \"$1\" in\n  pull) case \"$5\" in localhost/*) exit 1 ;; esac; exit 0 ;;\n  image) case \"$4\" in *Labels*) echo '1|<no value>' ;; *) printf '[\"%s\"]|linux/amd64\\n' \"$5\" ;; esac ;;\n  create) echo developer ;;\n  cp) cat '{developer}' > \"$3\" ;;\n  rm) exit 0 ;;\n  *) exit 1 ;;\nesac\n",
                log = log.display(),
                developer = developer_document.display(),
            ),
        );
        docker
    }

    #[cfg(unix)]
    #[test]
    fn a_developer_release_resolves_from_the_local_store_and_present_digests_are_never_pulled() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        let developer_release = developer(9, '1');
        let docker = developer_docker(home.path(), &developer_release);
        let context = Context {
            paths,
            profile: HostProfile::Linux,
            engine: Engine::with_docker(docker),
            scheduled: false,
            recreated: Cell::new(false),
        };
        let resolved = context.resolve(Some(&developer_release.reference)).unwrap();
        assert_eq!(resolved.reference, developer_release.reference);
        assert_eq!(resolved.metadata, developer_release.metadata);
        for (member, package) in [
            (&resolved.metadata.admin, release::ADMIN),
            (&resolved.metadata.team, release::TEAM),
        ] {
            context.engine.pull_exact(member, package).unwrap();
        }
        let log = fs::read_to_string(home.path().join("docker.log")).unwrap();
        assert!(log.contains(&format!(
            "create --pull never --platform linux/amd64 {}",
            developer_release.reference
        )));
        assert!(
            !log.lines().any(|line| line.starts_with("pull")),
            "pulled an image the store holds: {log}"
        );

        // The same set on macOS is refused.
        let macos = Context {
            profile: HostProfile::MacOs,
            ..context
        };
        assert!(macos.resolve(Some(&developer_release.reference)).is_err());
    }

    /// Run `shimpz install <developer release>` on a fresh Linux home whose Docker stand-in logs every call,
    /// refuses every pull, and holds the developer release set only when `stored`. The set's CLI is a fake child that
    /// records its arguments and commits the release as its apply would.
    #[cfg(unix)]
    fn fresh_developer_install(
        home: &Path,
        stored: bool,
    ) -> (Context, ResolvedRelease, Result<String, String>) {
        let root = home.join("fixture");
        fs::create_dir(&root).unwrap();
        let paths = Paths::under(home).unwrap();
        fs::create_dir(&paths.home).unwrap();
        let mut target = developer(9, '1');
        // The committed environment and status the child writes when its apply commits.
        state::write_environment(
            &paths,
            &Environment {
                release: &target,
                profile: HostProfile::Linux,
                space_id: "space-0123456789abcdef01234567",
                port: 7777,
                docker_gid: 0,
                docker_socket: Path::new("/var/run/docker.sock"),
                cpuset: "0",
                secure_root: &paths.pool_mount,
            },
        )
        .unwrap();
        fs::rename(&paths.environment, root.join("committed.env")).unwrap();
        let child = root.join("release-cli");
        fs::write(
            &child,
            format!(
                "#!/bin/sh\numask 077\nprintf '%s\\n' \"$*\" > '{arguments}'\ncp '{committed}' '{environment}'\nprintf '%s' '{status}' > '{status_path}'\n",
                arguments = root.join("child-arguments").display(),
                committed = root.join("committed.env").display(),
                environment = paths.environment.display(),
                status = serde_json::json!({
                    "release": target.reference,
                    "ordinal": 9,
                    "checked_at": 1,
                    "outcome": "updated",
                }),
                status_path = paths.home.join("release-status.json").display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
        target.metadata.cli_linux_amd64_sha256 = hash_file(&child).unwrap();
        fs::write(root.join("release.env"), release_document(&target)).unwrap();
        let docker = root.join("docker");
        crate::fake_tool::write(
            &docker,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\ncase \"$1\" in\n  image) [ {stored} = 1 ] || exit 1; case \"$4\" in *Labels*) echo '1|<no value>' ;; *) printf '[\"%s\"]|linux/amd64\\n' \"$5\" ;; esac ;;\n  create) case \"$7\" in /release.env) echo metadata ;; *) echo cli ;; esac ;;\n  cp) case \"$2\" in metadata:*) cat '{root}/release.env' > \"$3\" ;; *) cp '{child}' \"$3\" ;; esac ;;\n  ps|volume|network|rm) exit 0 ;;\n  *) exit 1 ;;\nesac\n",
                log = root.join("docker.log").display(),
                stored = u8::from(stored),
                root = root.display(),
                child = child.display(),
            ),
        );
        let context = Context {
            paths,
            profile: HostProfile::Linux,
            engine: Engine::with_docker(docker),
            scheduled: false,
            recreated: Cell::new(false),
        };
        let outcome = context.install(Some(&target.reference), false);
        let log = fs::read_to_string(root.join("docker.log")).unwrap();
        assert!(
            !log.lines().any(|line| line.starts_with("pull")),
            "pulled a developer release: {log}"
        );
        (context, target, outcome)
    }

    #[cfg(unix)]
    #[test]
    fn a_fresh_developer_install_hands_off_to_the_cli_of_its_set_from_the_local_store() {
        let home = tempfile::tempdir().unwrap();
        let (context, target, outcome) = fresh_developer_install(home.path(), true);
        assert_eq!(
            outcome,
            Ok("The release-bound CLI completed the installation.".into())
        );
        assert_eq!(
            fs::read_to_string(home.path().join("fixture/child-arguments")).unwrap(),
            format!("install {} --candidate\n", target.reference)
        );
        assert_eq!(
            hash_file(&context.paths.managed_cli).unwrap(),
            target.metadata.cli_linux_amd64_sha256
        );
        assert_eq!(
            fs::read_link(&context.paths.public_cli).unwrap(),
            context.paths.managed_cli
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_developer_install_missing_from_the_local_store_is_refused_without_a_pull() {
        let home = tempfile::tempdir().unwrap();
        let (context, target, outcome) = fresh_developer_install(home.path(), false);
        assert_eq!(
            outcome,
            Err(format!(
                "the developer release image {} is not in the local Docker image store; assemble it again with .scripts/local-release/deploy, or install the published release with shimpz install",
                target.reference
            ))
        );
        assert!(!home.path().join("fixture/child-arguments").exists());
        assert!(!context.paths.managed_cli.exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_resolution_whose_container_cleanup_fails_leaves_no_temporary_metadata() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        let developer_release = developer(9, '1');
        let docker = developer_docker(home.path(), &developer_release);
        let script = fs::read_to_string(&docker)
            .unwrap()
            .replace("rm) exit 0", "rm) exit 1");
        crate::fake_tool::write(&docker, script);
        let context = Context {
            paths,
            profile: HostProfile::Linux,
            engine: Engine::with_docker(docker),
            scheduled: false,
            recreated: Cell::new(false),
        };
        let Err(error) = context.resolve(Some(&developer_release.reference)) else {
            panic!("a resolution whose container cleanup failed was admitted");
        };
        assert_eq!(
            error,
            "the Local release metadata could not be extracted cleanly"
        );
        assert!(!context.paths.home.join("release.env.tmp").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_resolution_reports_an_unreadable_copy_together_with_its_failed_cleanup() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        let developer_release = developer(9, '1');
        let docker = developer_docker(home.path(), &developer_release);
        // The copy leaves a directory where the metadata belongs: it can be neither read nor unlinked.
        let copy = format!(
            "cat '{}' > \"$3\"",
            home.path().join("developer.env").display()
        );
        let script = fs::read_to_string(&docker).unwrap();
        assert!(script.contains(&copy));
        crate::fake_tool::write(&docker, script.replace(&copy, "mkdir \"$3\""));
        let context = Context {
            paths,
            profile: HostProfile::Linux,
            engine: Engine::with_docker(docker),
            scheduled: false,
            recreated: Cell::new(false),
        };
        let Err(error) = context.resolve(Some(&developer_release.reference)) else {
            panic!("an unreadable release metadata copy was admitted");
        };
        assert!(
            error.starts_with("the Local release metadata is not a regular file; ")
                && error.contains("could not remove temporary release metadata: "),
            "{error}"
        );
    }

    /// The copies a set image controls are trusted only as bounded regular files: a link is never followed, a FIFO
    /// never opened, and an oversized document never read whole.
    #[cfg(unix)]
    #[test]
    fn a_resolution_reads_only_a_bounded_regular_metadata_copy() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        let developer_release = developer(9, '1');
        let docker = developer_docker(home.path(), &developer_release);
        let document = home.path().join("developer.env");
        let copy = format!("cat '{}' > \"$3\"", document.display());
        let script = fs::read_to_string(&docker).unwrap();
        let context = Context {
            paths,
            profile: HostProfile::Linux,
            engine: Engine::with_docker(docker.clone()),
            scheduled: false,
            recreated: Cell::new(false),
        };
        for (replacement, refusal) in [
            (
                format!("ln -s '{}' \"$3\"", document.display()),
                "the Local release metadata is not a regular file",
            ),
            (
                "mkfifo \"$3\"".to_owned(),
                "the Local release metadata is not a regular file",
            ),
            (
                "head -c 2049 /dev/zero > \"$3\"".to_owned(),
                "the Local release metadata is malformed",
            ),
        ] {
            crate::fake_tool::write(&docker, script.replace(&copy, &replacement));
            let Err(error) = context.resolve(Some(&developer_release.reference)) else {
                panic!("admitted the copy made by {replacement}");
            };
            assert_eq!(error, refusal, "{replacement}");
            assert!(!context.paths.home.join("release.env.tmp").exists());
        }
        assert_eq!(
            fs::read_to_string(&document).unwrap(),
            release_document(&developer_release)
        );
    }

    /// A release-bound CLI copy that is a link is removed without following it, so no host file changes mode.
    #[cfg(unix)]
    #[test]
    fn an_extracted_cli_link_is_removed_without_touching_its_target() {
        let home = tempfile::tempdir().unwrap();
        let target = home.path().join("host-file");
        fs::write(&target, "host\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        let docker = home.path().join("docker");
        crate::fake_tool::write(
            &docker,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n  create) echo c ;;\n  cp) ln -s '{}' \"$3\" ;;\n  rm) exit 0 ;;\n  *) exit 1 ;;\nesac\n",
                target.display()
            ),
        );
        let candidate = home.path().join("shimpz.candidate");
        let Err(error) = Engine::with_docker(docker).extract_cli(
            &release(3, 'c').reference,
            HostProfile::Linux,
            &candidate,
        ) else {
            panic!("a linked CLI copy was admitted");
        };
        assert_eq!(error, "the release-bound CLI is not a regular file");
        assert!(fs::symlink_metadata(&candidate).is_err());
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    /// A Docker stand-in whose `stable` channel names `stable` and whose store holds every given release set at
    /// state epoch 1, each published set correctly signed.
    #[cfg(unix)]
    fn channel_docker(
        directory: &Path,
        stable: &ResolvedRelease,
        sets: &[&ResolvedRelease],
    ) -> PathBuf {
        for set in sets {
            let digest = set.reference.rsplit_once(':').unwrap().1;
            let document = release_document(set);
            let signature = if release::valid_published_release_ref(&set.reference) {
                release::test_signing::sign(&document, "1")
            } else {
                "<no value>".into()
            };
            fs::write(directory.join(format!("{digest}.env")), document).unwrap();
            fs::write(
                directory.join(format!("{digest}.labels")),
                format!("1|{signature}\n"),
            )
            .unwrap();
        }
        let docker = directory.join("channel-docker");
        crate::fake_tool::write(
            &docker,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n  pull) case \"$5\" in localhost/*) exit 1 ;; esac; exit 0 ;;\n  image) case \"$5\" in *:stable) printf '[\"%s\"]\\n' '{stable}' ;; *) case \"$4\" in *Labels*'|'*) cat '{directory}/'\"${{5##*:}}\".labels ;; *Labels*) echo 1 ;; *'|'*) printf '[\"%s\"]|linux/amd64\\n' \"$5\" ;; *) printf '[\"%s\"]\\n' \"$5\" ;; esac ;; esac ;;\n  create) printf 'c%s\\n' \"${{6##*:}}\" ;;\n  cp) container=\"${{2%%:*}}\"; cat '{directory}/'\"${{container#c}}\".env > \"$3\" ;;\n  rm) exit 0 ;;\n  *) exit 1 ;;\nesac\n",
                stable = stable.reference,
                directory = directory.display(),
            ),
        );
        docker
    }

    /// The release a start selects, whether it preserves failed-release memory, and whether it may hand off.
    #[cfg(unix)]
    fn selection(
        home: &Path,
        stable: &ResolvedRelease,
        sets: &[&ResolvedRelease],
        failed: Option<&str>,
        exact: Option<&str>,
        stopped: bool,
    ) -> Result<Option<(String, bool, bool)>, String> {
        let paths = Paths::under(home).unwrap();
        if !paths.home.exists() {
            fs::create_dir(&paths.home).unwrap();
        }
        if paths.failed_release.exists() {
            fs::remove_file(&paths.failed_release).unwrap();
        }
        if let Some(record) = failed {
            state::write_private(&paths.failed_release, record).unwrap();
        }
        let context = Context {
            paths,
            profile: HostProfile::Linux,
            engine: Engine::with_docker(channel_docker(home, stable, sets)),
            scheduled: true,
            recreated: Cell::new(false),
        };
        let options = SpaceStart {
            scheduled: true,
            release: exact.map(str::to_owned),
            candidate: false,
        };
        let installed = installed_from(&developer(9, '1'));
        Ok(context
            .select_start(&options, &installed, stopped)?
            .map(|selected| {
                (
                    selected.release.reference,
                    selected.preserve_failed_release,
                    selected.may_hand_off,
                )
            }))
    }

    #[cfg(unix)]
    #[test]
    fn a_published_release_is_admitted_only_with_a_valid_signature_before_any_handoff() {
        let home = tempfile::tempdir().unwrap();
        let stable = release(3, 'c');
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        let context = Context {
            paths,
            profile: HostProfile::Linux,
            engine: Engine::with_docker(channel_docker(home.path(), &stable, &[&stable])),
            scheduled: true,
            recreated: Cell::new(false),
        };
        let resolved = context.resolve(None).unwrap();
        assert_eq!(resolved.reference, stable.reference);
        assert_eq!(resolved.metadata, stable.metadata);
        // Without a ResolvedRelease nothing is handed off, pulled, or applied: every refusal ends the resolution.
        let labels = home.path().join(format!("{}.labels", "c".repeat(64)));
        let (other_key, _) = release::test_signing::generate();
        let swapped = release_document(&stable).replace(HEX, &"f".repeat(64));
        for refused in [
            "1|<no value>\n".to_owned(),
            format!("1|{}\n", release::test_signing::sign(&swapped, "1")),
            format!(
                "2|{}\n",
                release::test_signing::sign(&release_document(&stable), "1")
            ),
            format!(
                "1|{}\n",
                release::test_signing::sign_with(&other_key, &release_document(&stable), "1")
            ),
        ] {
            fs::write(&labels, &refused).unwrap();
            let Err(error) = context.resolve(None) else {
                panic!("admitted {refused}");
            };
            assert_eq!(error, "the Local release signature is invalid");
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_installed_developer_release_never_follows_stable_and_a_request_hands_off() {
        let home = tempfile::tempdir().unwrap();
        let newer = release(3, 'c');
        let installed = developer(9, '1');
        let requested = developer(10, '2');
        let sets = [&newer, &installed, &requested];
        let record = |release: &ResolvedRelease| format!("release={}\n", release.reference);
        let select = |failed: Option<&str>, exact, stopped| {
            selection(home.path(), &newer, &sets, failed, exact, stopped)
        };
        // A newer publication is not news: the scheduler repairs the installed developer release.
        assert_eq!(
            select(None, None, false),
            Ok(Some((installed.reference.clone(), false, true)))
        );
        // A developer release that failed its repair is not applied again by the scheduler.
        assert_eq!(select(Some(&record(&installed)), None, false), Ok(None));
        // A stopped Space resumes the installed developer release, preserving the memory.
        assert_eq!(
            select(Some(&record(&installed)), None, true),
            Ok(Some((installed.reference.clone(), true, false)))
        );
        assert!(select(Some("malformed"), None, false).is_err());
        // A deploy request applies its exact release whatever the memory says, handing off to its CLI.
        assert_eq!(
            select(Some(&record(&requested)), Some(&requested.reference), false),
            Ok(Some((requested.reference.clone(), false, true)))
        );
    }

    /// Opt-in: admit a developer release built by .scripts/local-release/deploy from this host's Docker store. Only reads images
    /// and creates temporary containers.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs SHIMPZ_DEVELOPER_RELEASE and this host's Docker store"]
    fn live_developer_release_resolves_from_this_hosts_store() {
        let reference =
            std::env::var("SHIMPZ_DEVELOPER_RELEASE").expect("SHIMPZ_DEVELOPER_RELEASE");
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        let context = Context {
            paths,
            profile: HostProfile::Linux,
            engine: Engine::with_docker(PathBuf::from("docker")),
            scheduled: false,
            recreated: Cell::new(false),
        };
        let release = context.resolve(Some(&reference)).unwrap();
        assert_eq!(release.metadata.cli_macos_arm64_sha256, None);
        let metadata = &release.metadata;
        for (member, package) in [
            (&metadata.admin, release::ADMIN),
            (&metadata.team, release::TEAM),
            (&metadata.brain, release::BRAIN),
            (&metadata.egress, release::EGRESS),
        ] {
            context.engine.pull_exact(member, package).unwrap();
        }
        let missing = format!("localhost/shimpz-local-release@sha256:{}", "0".repeat(64));
        assert!(context.resolve(Some(&missing)).is_err());
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

    /// A macOS Space whose live release is `ordinal` 1, backed up for an update, run by the given `docker`.
    #[cfg(unix)]
    fn installed_space(home: &Path, docker: PathBuf) -> (Context, Backup) {
        let paths = Paths::under(home).unwrap();
        fs::create_dir(&paths.home).unwrap();
        let space_id = state::random_space_id().unwrap();
        state::write_environment(
            &paths,
            &Environment {
                release: &release(1, 'a'),
                profile: HostProfile::MacOs,
                space_id: &space_id,
                port: 7777,
                docker_gid: 0,
                docker_socket: Path::new("/var/run/docker.sock.raw"),
                cpuset: "0",
                secure_root: &paths.pool_mount,
            },
        )
        .unwrap();
        let backup = backup_current(&paths, HostProfile::MacOs).unwrap();
        state::write_state_epoch(&paths, 1).unwrap();
        let context = Context {
            paths,
            profile: HostProfile::MacOs,
            engine: Engine::with_docker(docker),
            scheduled: false,
            recreated: Cell::new(false),
        };
        (context, backup)
    }

    /// A Docker stand-in that logs every call, holds no image until it is pulled, owns the Admin data volume, and
    /// fails every container run.
    #[cfg(unix)]
    fn logging_docker(home: &Path) -> (PathBuf, PathBuf) {
        let log = home.join("docker.log");
        let docker = home.join("logging-docker");
        crate::fake_tool::write(
            &docker,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\ncase \"$1\" in\n  volume) printf '%s\\n' 'shimpz-space_data|shimpz-space|data' ;;\n  image) case \"$4\" in *'|'*) exit 1 ;; *) printf '[\"%s\"]\\n' \"$5\" ;; esac ;;\n  pull) exit 0 ;;\n  *) exit 1 ;;\nesac\n",
                log = log.display()
            ),
        );
        (docker, log)
    }

    /// A Local home holding one pending deploy request for `requested`.
    #[cfg(unix)]
    fn deploy_home(requested: &ResolvedRelease) -> (tempfile::TempDir, Paths, deploy::Request) {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        state::write_private(
            &paths.deploy_request,
            &format!(
                "id=0123456789abcdef0123456789abcdef\nrelease={}\n",
                requested.reference
            ),
        )
        .unwrap();
        let request = deploy::claim(&paths).unwrap().unwrap();
        (home, paths, request)
    }

    #[cfg(unix)]
    fn deploy_outcome(paths: &Paths) -> String {
        let result: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&paths.deploy_result).unwrap()).unwrap();
        result["outcome"].as_str().unwrap().to_owned()
    }

    #[cfg(unix)]
    #[test]
    fn a_deploy_request_is_applied_only_by_an_attempt_that_commits_it() {
        let requested = developer(9, '1');
        // A developer release applies only to an amd64 Linux Space, whatever host runs this test.
        let profile = HostProfile::Linux;
        // The release is installed and its reconciliation recorded: applied, and the request is consumed.
        let (_home, paths, request) = deploy_home(&requested);
        state::write_environment(
            &paths,
            &Environment {
                release: &requested,
                profile,
                space_id: "space-0123456789abcdef01234567",
                port: 7777,
                docker_gid: 998,
                docker_socket: Path::new("/var/run/docker.sock"),
                cpuset: "0-3",
                secure_root: &paths.pool_mount,
            },
        )
        .unwrap();
        state::write_private(
            &paths.status,
            &state::status_document(&requested, "updated").unwrap(),
        )
        .unwrap();
        assert!(finish_deploy_request(&paths, profile, &request, || Ok("ready".into())).is_ok());
        assert_eq!(deploy_outcome(&paths), "applied");
        assert!(!paths.deploy_request.exists());
        // The same evidence never acknowledges a developer release on a macOS Space.
        state::write_private(
            &paths.deploy_request,
            &format!(
                "id=0123456789abcdef0123456789abcdef\nrelease={}\n",
                requested.reference
            ),
        )
        .unwrap();
        let request = deploy::claim(&paths).unwrap().unwrap();
        assert!(
            finish_deploy_request(&paths, HostProfile::MacOs, &request, || Ok("ready".into()))
                .is_ok()
        );
        assert_eq!(deploy_outcome(&paths), "failed");
        // The same evidence does not count when this attempt found storage locked.
        state::write_private(
            &paths.deploy_request,
            &format!(
                "id=0123456789abcdef0123456789abcdef\nrelease={}\n",
                requested.reference
            ),
        )
        .unwrap();
        let request = deploy::claim(&paths).unwrap().unwrap();
        assert!(
            finish_deploy_request(&paths, profile, &request, || Ok(STORAGE_LOCKED.into())).is_ok()
        );
        assert_eq!(deploy_outcome(&paths), "failed");
        // Nothing installed, or a refusal, fails it; a deferral keeps the request for the next run.
        let (_home, paths, request) = deploy_home(&requested);
        assert!(finish_deploy_request(&paths, profile, &request, || Ok("ready".into())).is_ok());
        assert_eq!(deploy_outcome(&paths), "failed");
        let (_home, paths, request) = deploy_home(&requested);
        assert!(
            finish_deploy_request(&paths, profile, &request, || Err("refused".into())).is_err()
        );
        assert_eq!(deploy_outcome(&paths), "failed");
        assert!(!paths.deploy_request.exists());
        let (_home, paths, request) = deploy_home(&requested);
        assert!(
            finish_deploy_request(&paths, profile, &request, || Ok(UPDATE_DEFERRED.into())).is_ok()
        );
        assert_eq!(deploy_outcome(&paths), "deferred");
        assert!(paths.deploy_request.exists());
        // A stopped Space keeps its stop intent: nothing runs.
        let (_home, paths, request) = deploy_home(&requested);
        state::write_stopped(&paths).unwrap();
        assert!(
            finish_deploy_request(&paths, profile, &request, || panic!(
                "a stopped Space was started"
            ))
            .is_err()
        );
        assert_eq!(deploy_outcome(&paths), "failed");
    }

    #[test]
    fn runtime_state_is_recreated_exactly_when_its_stored_format_epoch_differs_or_is_unknown() {
        // A fresh Space has no runtime state yet.
        assert!(!runtime_state_reset_needed(true, Some(2), None));
        assert!(!runtime_state_reset_needed(true, None, None));
        // The same known epoch keeps it; another epoch in either direction, or an unknown one, recreates it.
        assert!(!runtime_state_reset_needed(false, Some(2), Some(2)));
        assert!(runtime_state_reset_needed(false, Some(3), Some(2)));
        assert!(runtime_state_reset_needed(false, Some(1), Some(2)));
        assert!(runtime_state_reset_needed(false, Some(2), None));
        assert!(runtime_state_reset_needed(false, None, Some(2)));
        assert!(runtime_state_reset_needed(false, None, None));
    }

    #[test]
    fn the_runtime_state_group_holds_no_identity_records_or_bindings() {
        for volume in graph::RUNTIME_STATE_VOLUMES {
            assert!(graph::VOLUME_NAMES.contains(&volume), "{volume}");
        }
        for kept in [
            "data",
            "config",
            "supervisor_key",
            "controller_storage",
            "controller_publications",
            "controller_assistant_integration_state",
            "controller_assistant_integration_key",
            "controller_token",
            "brain_runtime_token",
            "account_egress_capability",
            "reset_capability",
            "assistant_egress_policy",
        ] {
            assert!(!graph::RUNTIME_STATE_VOLUMES.contains(&kept), "{kept}");
        }
    }

    #[test]
    fn the_state_epoch_record_is_private_and_forgotten_before_a_recreation() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        assert_eq!(state::read_state_epoch(&paths), None);
        state::write_state_epoch(&paths, 7).unwrap();
        assert_eq!(state::read_state_epoch(&paths), Some(7));
        assert_eq!(
            fs::metadata(&paths.state_epoch)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        // Each write is a distinct record, even for the same epoch.
        let first = state::read_state_record(&paths).unwrap();
        state::write_state_epoch(&paths, 7).unwrap();
        assert_ne!(state::read_state_record(&paths).unwrap(), first);
        state::forget_state_epoch(&paths).unwrap();
        state::forget_state_epoch(&paths).unwrap();
        assert_eq!(state::read_state_epoch(&paths), None);
        for invalid in [
            "7\n",
            "0 0123456789abcdef0123456789abcdef\n",
            "07 0123456789abcdef0123456789abcdef\n",
            "7 0123\n",
            "seven 0123456789abcdef0123456789abcdef\n",
        ] {
            state::write_private(&paths.state_epoch, invalid).unwrap();
            assert_eq!(state::read_state_epoch(&paths), None, "{invalid}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_unchanged_admin_image_needs_no_new_authentication_probe() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        let (docker, log) = logging_docker(home.path());
        let context = Context {
            paths,
            profile: HostProfile::Linux,
            engine: Engine::with_docker(docker),
            scheduled: true,
            recreated: Cell::new(false),
        };
        let candidate = release(2, 'b');
        let unchanged = installed_from(&release(1, 'a'));
        // The stand-in's empty inspection proves nothing present, so members are pulled; no probe runs. The Team
        // socket probe's refusal, whether the host has no socket or the stand-in refuses the probe, is returned for
        // the caller to judge.
        let controller_socket = context
            .download_and_admit_candidate(&candidate, Some(&unchanged))
            .unwrap();
        assert_eq!(
            controller_socket.release(),
            Err("the Team controller cannot access the local Docker socket".into())
        );
        assert!(
            !fs::read_to_string(&log)
                .unwrap()
                .contains("authentication_state")
        );
        let changed = Installed {
            admin_image: format!("ghcr.io/theshimpz/shimpz-admin@sha256:{}", "f".repeat(64)),
            ..unchanged
        };
        assert!(
            context
                .download_and_admit_candidate(&candidate, Some(&changed))
                .is_err()
        );
        assert!(
            fs::read_to_string(&log)
                .unwrap()
                .contains("authentication_state")
        );
    }

    #[test]
    fn only_long_running_containers_whose_image_the_release_replaces_are_removed_first() {
        let candidate = release(2, 'b');
        let old = format!("ghcr.io/theshimpz/shimpz-admin@sha256:{}", "f".repeat(64));
        let identifiers: Vec<String> = ["a", "t", "b", "e", "i"].map(String::from).to_vec();
        let records = vec![
            format!("/shimpz-admin|{old}"),
            format!("/shimpz-team|{}", candidate.metadata.team),
            format!("/shimpz-brain|{old}"),
            format!("/shimpz-account-egress|{}", candidate.metadata.egress),
            format!("/shimpz-account-egress-init|{old}"),
        ];
        assert_eq!(
            replaced_containers(&identifiers, &records, &candidate).unwrap(),
            ["a", "b"]
        );
        for refused in [
            vec!["/shimpz-admin".to_owned()],
            vec!["/shimpz-unknown|image".to_owned()],
            vec!["/shimpz-admin|".to_owned()],
        ] {
            assert!(replaced_containers(&identifiers[..1], &refused, &candidate).is_err());
        }
        assert!(replaced_containers(&identifiers, &records[..4], &candidate).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_admission_reports_the_admin_refusal_before_a_failed_later_download() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        // Admin downloads; the Team download fails at once while the Admin check is still running and then fails.
        let docker = home.path().join("docker");
        crate::fake_tool::write(
            &docker,
            "#!/bin/sh\ncase \"$1\" in\n  volume) printf '%s\\n' 'shimpz-space_data|shimpz-space|data' ;;\n  image) case \"$4\" in *'|'*) exit 1 ;; *) printf '[\"%s\"]\\n' \"$5\" ;; esac ;;\n  pull) case \"$*\" in *shimpz-admin*) exit 0 ;; *) exit 1 ;; esac ;;\n  run) sleep 0.2; exit 1 ;;\n  *) exit 1 ;;\nesac\n",
        );
        let context = Context {
            paths,
            profile: HostProfile::Linux,
            engine: Engine::with_docker(docker),
            scheduled: true,
            recreated: Cell::new(false),
        };
        let changed = Installed {
            admin_image: format!("ghcr.io/theshimpz/shimpz-admin@sha256:{}", "f".repeat(64)),
            ..installed_from(&release(1, 'a'))
        };
        let Err(error) = context.download_and_admit_candidate(&release(2, 'b'), Some(&changed))
        else {
            panic!("a refused Admin check admitted the release");
        };
        assert_eq!(
            error,
            candidate_admission_error(
                "the selected Admin could not inspect the existing Supervisor authentication record"
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_restoration_is_never_reported_as_restored() {
        let home = tempfile::tempdir().unwrap();
        // Every Compose call, including the restoration, exits unsuccessfully.
        let (context, backup) = installed_space(home.path(), PathBuf::from("/usr/bin/false"));
        let installed = state::read_installed(&context.paths, HostProfile::MacOs).unwrap();
        // The failed-release memory cannot be written, so the scheduler diagnostic follows the outcome.
        fs::create_dir(&context.paths.failed_release).unwrap();

        let outcome = context
            .rollback(&release(2, 'b'), &installed.space_id, Some(backup))
            .unwrap_err();

        assert!(
            outcome.starts_with("the update and its rollback both failed; "),
            "{outcome}"
        );
        assert!(!outcome.contains("restored"), "{outcome}");
    }

    /// A restoration Docker cannot run, as when it outlives its deadline and is stopped, still records the rollback.
    #[cfg(unix)]
    #[test]
    fn a_restoration_that_cannot_run_still_records_the_rollback() {
        let home = tempfile::tempdir().unwrap();
        let (context, backup) = installed_space(home.path(), home.path().join("absent-docker"));
        let installed = state::read_installed(&context.paths, HostProfile::MacOs).unwrap();

        let outcome = context
            .rollback(&release(2, 'b'), &installed.space_id, Some(backup))
            .unwrap_err();

        assert_eq!(outcome, "the update and its rollback both failed");
        let status: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&context.paths.status).unwrap()).unwrap();
        assert_eq!(status["outcome"], "rollback-needed");
    }

    const ADMIN_ID: &str = "a0000000000000000000000000000000000000000000000000000000000000ad";
    const TEAM_ID: &str = "b0000000000000000000000000000000000000000000000000000000000000be";
    const BRAIN_ID: &str = "c0000000000000000000000000000000000000000000000000000000000000cf";

    /// A Docker stand-in for an installed Space whose project holds the installed Admin, Team, and Brain: every name
    /// lookup misses, each listing holds only those three containers, the release image labels state epoch 1, a
    /// status helper appends whatever document it receives to `status.log`, and `stop`, `rm`, and `compose` exit
    /// with the given statuses. Every call is logged.
    #[cfg(unix)]
    fn replacing_docker(home: &Path, stop: u8, remove: u8, compose: u8) -> (PathBuf, PathBuf) {
        replacing_docker_with(home, stop, remove, compose, true)
    }

    /// `replacing_docker`, whose release status volume exists only when `status_volume` is set.
    #[cfg(unix)]
    fn replacing_docker_with(
        home: &Path,
        stop: u8,
        remove: u8,
        compose: u8,
        status_volume: bool,
    ) -> (PathBuf, PathBuf) {
        let log = home.join("docker.log");
        let docker = home.join("replacing-docker");
        let installed = release(1, 'a').metadata;
        crate::fake_tool::write(
            &docker,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\ncase \"$1\" in\n  ps) case \"$*\" in *com.docker.compose.project=shimpz-space*) printf '%s\\n' {admin_id} {team_id} {brain_id} ;; esac ;;\n  volume) case \"$2 $5\" in 'inspect shimpz-space_release_status') {status_volume} ;; inspect*) printf '%s|shimpz-space|%s\\n' \"$5\" \"${{5#shimpz-space_}}\" ;; esac ;;\n  network) ;;\n  inspect) case \"$*\" in\n    *com.docker.compose.service*) printf '%s\\n' '{admin_id}|/shimpz-admin|admin|{admin}' '{team_id}|/shimpz-team|team|{team}' '{brain_id}|/shimpz-brain|brain|{brain}' ;;\n    *'{{{{.Name}}}}|{{{{.Config.Image}}}}'*) printf '%s\\n' '{admin_id}|/shimpz-admin|{admin}' '{team_id}|/shimpz-team|{team}' '{brain_id}|/shimpz-brain|{brain}' ;;\n    *) exit 1 ;;\n  esac ;;\n  image) echo 1 ;;\n  stop) exit {stop} ;;\n  rm) exit {remove} ;;\n  compose) exit {compose} ;;\n  run) cat >> '{status}' ;;\n  *) exit 1 ;;\nesac\n",
                log = log.display(),
                status = home.join("status.log").display(),
                status_volume = if status_volume {
                    "printf '%s|shimpz-space|release_status\\n' \"$5\""
                } else {
                    "exit 1"
                },
                admin_id = ADMIN_ID,
                team_id = TEAM_ID,
                brain_id = BRAIN_ID,
                admin = installed.admin,
                team = installed.team,
                brain = installed.brain,
            ),
        );
        (docker, log)
    }

    /// A candidate that replaces the installed Admin image and, when `team` is set, the Team image too.
    fn replacing_release(team: bool) -> ResolvedRelease {
        let mut candidate = release(2, 'b');
        candidate.metadata.admin =
            format!("ghcr.io/theshimpz/shimpz-admin@sha256:{}", "c".repeat(64));
        if team {
            candidate.metadata.team = format!(
                "ghcr.io/theshimpz/shimpz-team-local@sha256:{}",
                "d".repeat(64)
            );
        }
        candidate
    }

    /// Run the start of `candidate_release` over a Space installed under `home` and return its error and the log.
    #[cfg(unix)]
    fn failed_start(
        home: &Path,
        docker: PathBuf,
        candidate_release: &ResolvedRelease,
    ) -> (String, Context) {
        let (context, backup) = installed_space(home, docker);
        let installed = state::read_installed(&context.paths, HostProfile::MacOs).unwrap();
        let candidate = Candidate {
            release: candidate_release,
            installed: Some(&installed),
            space_id: &installed.space_id,
            port: installed.port,
            docker_gid: 0,
            docker_socket: Path::new("/var/run/docker.sock.raw"),
        };
        let error = context
            .start_or_roll_back(&candidate, Some(backup))
            .unwrap_err();
        (error, context)
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_stop_or_removal_of_replaced_containers_rolls_back_and_keeps_volumes() {
        for (stop, remove, compose, cause, outcome) in [
            (
                1,
                0,
                0,
                "could not stop every managed Local container",
                "the previous healthy release was restored",
            ),
            (
                0,
                1,
                0,
                "could not remove every replaced Local container",
                "the previous healthy release was restored",
            ),
            (
                1,
                0,
                1,
                "could not stop every managed Local container",
                "the update and its rollback both failed",
            ),
        ] {
            let home = tempfile::tempdir().unwrap();
            let (docker, log) = replacing_docker(home.path(), stop, remove, compose);
            let (error, context) = failed_start(home.path(), docker, &replacing_release(true));

            assert!(error.contains(cause) && error.contains(outcome), "{error}");
            let calls = fs::read_to_string(&log).unwrap();
            // Both replaced containers are stopped at once and removed without their volumes; Brain is kept.
            assert!(
                calls
                    .lines()
                    .any(|line| line == format!("stop {ADMIN_ID} {TEAM_ID}"))
            );
            assert!(!calls.lines().any(|line| {
                (line.starts_with("stop ") || line.starts_with("rm ")) && line.contains(BRAIN_ID)
            }));
            if stop == 0 {
                assert!(
                    calls
                        .lines()
                        .any(|line| line == format!("rm {ADMIN_ID} {TEAM_ID}"))
                );
            } else {
                assert!(!calls.lines().any(|line| line.starts_with("rm ")));
            }
            // The rollback brought the previous configuration back up through Compose.
            assert!(
                calls
                    .lines()
                    .any(|line| line.starts_with("compose ") && line.contains(" up -d "))
            );
            let restored = state::read_installed(&context.paths, HostProfile::MacOs).unwrap();
            assert_eq!(restored.release_ref, release(1, 'a').reference);
        }
    }

    #[cfg(unix)]
    #[test]
    fn one_replaced_container_is_left_to_compose_and_an_uncommitted_status_helper_writes_nothing() {
        let home = tempfile::tempdir().unwrap();
        let (docker, log) = replacing_docker(home.path(), 0, 0, 1);
        let (error, _context) = failed_start(home.path(), docker, &replacing_release(false));

        assert!(
            error.contains("the update and its rollback both failed"),
            "{error}"
        );
        let calls = fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = calls.lines().collect();
        assert!(
            !lines
                .iter()
                .any(|line| line.starts_with("stop ") || line.starts_with("rm "))
        );
        // The status helper ran beside the candidate's Compose up and, never committed, received no document; it was
        // reaped before the rollback took the Space down.
        let helper = lines
            .iter()
            .position(|line| line.starts_with("run --rm --interactive "));
        let rollback_down = lines.iter().position(|line| {
            line.starts_with("compose ") && line.ends_with(" down --remove-orphans")
        });
        assert!(
            matches!((helper, rollback_down), (Some(helper), Some(down)) if helper < down),
            "{calls}"
        );
        assert_eq!(
            fs::read_to_string(home.path().join("status.log")).unwrap(),
            ""
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_installed_space_without_its_status_volume_projects_after_compose_instead() {
        let home = tempfile::tempdir().unwrap();
        let (docker, log) = replacing_docker_with(home.path(), 0, 0, 1, false);
        let (error, _context) = failed_start(home.path(), docker, &replacing_release(false));

        // An interrupted installation whose status volume Compose has not created yet still reaches Compose.
        assert!(
            error.contains("the update and its rollback both failed"),
            "{error}"
        );
        let calls = fs::read_to_string(&log).unwrap();
        assert!(calls.lines().any(|line| {
            line.starts_with("volume ls --quiet --filter name=^shimpz-space_release_status$")
        }));
        assert!(!calls.lines().any(|line| line.starts_with("run ")));
        assert!(calls.lines().any(|line| {
            line.starts_with("compose --progress plain ") && line.contains(" up -d ")
        }));
    }

    /// An installed, marked Space under `home` whose Docker is `docker`.
    #[cfg(unix)]
    fn started_space(home: &Path, docker: PathBuf) -> Context {
        let (context, backup) = installed_space(home, docker);
        remove_backup(Some(backup)).unwrap();
        state::write_marker(&context.paths).unwrap();
        context
    }

    #[cfg(unix)]
    #[test]
    fn a_start_judges_the_inventory_before_the_release_it_resolved_beside_it() {
        let options = SpaceStart {
            scheduled: true,
            release: None,
            candidate: false,
        };
        // A scheduled start of a stopped Space, or of an unreadable stopped record, resolves no release.
        let home = tempfile::tempdir().unwrap();
        let (docker, log) = replacing_docker(home.path(), 0, 0, 0);
        let context = started_space(home.path(), docker);
        state::write_stopped(&context.paths).unwrap();
        assert_eq!(context.start(&options).unwrap(), SCHEDULED_STOPPED);
        fs::remove_file(&context.paths.stopped).unwrap();
        fs::create_dir(&context.paths.stopped).unwrap();
        assert!(context.start(&options).is_err());
        let calls = fs::read_to_string(&log).unwrap();
        assert!(
            !calls
                .lines()
                .any(|line| line.starts_with("create ") || line.starts_with("pull "))
        );

        // A refused inventory leads, and a resolution that failed beside it follows.
        let home = tempfile::tempdir().unwrap();
        let docker = home.path().join("refusing-docker");
        crate::fake_tool::write(
            &docker,
            "#!/bin/sh\ncase \"$1\" in\n  ps) exit 1 ;;\n  *) exit 1 ;;\nesac\n",
        );
        let context = started_space(home.path(), docker);
        let error = context.start(&options).unwrap_err();
        assert!(
            error.contains("; the Local release resolution also failed: "),
            "{error}"
        );
        assert!(!error.starts_with("Docker could not pull"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn a_compose_invocation_failure_after_replacement_restores_the_previous_release() {
        let home = tempfile::tempdir().unwrap();
        let (docker, log) = replacing_docker(home.path(), 0, 0, 1);
        let (context, backup) = installed_space(home.path(), docker);
        let installed = state::read_installed(&context.paths, HostProfile::MacOs).unwrap();
        let candidate_release = release(2, 'b');
        let candidate = Candidate {
            release: &candidate_release,
            installed: Some(&installed),
            space_id: &installed.space_id,
            port: installed.port,
            docker_gid: 0,
            docker_socket: Path::new("/var/run/docker.sock.raw"),
        };

        assert!(
            context
                .start_or_roll_back(&candidate, Some(backup))
                .is_err()
        );
        // The candidate's own Compose up ran first; the rollback then took the Space down and brought the previous
        // release up. Nothing was replaced, so nothing was stopped or removed first.
        let calls = fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = calls.lines().collect();
        let candidate_up = lines.iter().position(|line| {
            line.starts_with("compose --progress plain ") && line.contains(" up -d ")
        });
        let rollback_down = lines.iter().position(|line| {
            line.starts_with("compose ") && line.ends_with(" down --remove-orphans")
        });
        let restoration_up = lines.iter().rposition(|line| {
            line.starts_with("compose --project-directory ") && line.contains(" up -d ")
        });
        assert!(
            matches!(
                (candidate_up, rollback_down, restoration_up),
                (Some(up), Some(down), Some(restored)) if up < down && down < restored
            ),
            "{calls}"
        );
        assert!(
            !lines
                .iter()
                .any(|line| line.starts_with("stop ") || line.starts_with("rm "))
        );

        let restored = state::read_installed(&context.paths, HostProfile::MacOs).unwrap();
        assert_eq!(restored.ordinal, 1);
        assert_eq!(restored.release_ref, release(1, 'a').reference);
        assert!(!context.paths.compose.with_extension("previous").exists());
        assert!(
            !context
                .paths
                .environment
                .with_extension("previous")
                .exists()
        );
    }

    #[test]
    fn admits_only_monotonic_unambiguous_releases() {
        let installed = Installed {
            space_id: "space-0123456789abcdef01234567".into(),
            release_ref: release(2, 'b').reference,
            admin_image: format!("ghcr.io/theshimpz/shimpz-admin@sha256:{HEX}"),
            ordinal: 2,
            port: 7777,
        };
        assert!(validate_forward_release(&release(3, 'c'), Some(&installed)).is_ok());
        assert!(validate_forward_release(&release(2, 'b'), Some(&installed)).is_ok());
        assert!(validate_forward_release(&release(1, 'a'), Some(&installed)).is_err());
        assert!(validate_forward_release(&release(2, 'c'), Some(&installed)).is_err());
        assert!(validate_forward_release(&release(3, 'b'), Some(&installed)).is_err());
        assert!(validate_forward_release(&release(1, 'a'), None).is_ok());
    }

    #[test]
    fn rejects_an_invalid_release_before_cli_handoff() {
        let installed = Installed {
            space_id: "space-0123456789abcdef01234567".into(),
            release_ref: release(2, 'b').reference,
            admin_image: format!("ghcr.io/theshimpz/shimpz-admin@sha256:{HEX}"),
            ordinal: 2,
            port: 7777,
        };
        for invalid in [release(1, 'a'), release(2, 'c'), release(3, 'b')] {
            let mut called = false;
            let outcome = admit_before_handoff(&invalid, Some(&installed), || {
                called = true;
                Ok(())
            });

            assert!(outcome.is_err());
            assert!(!called);
        }
    }

    #[test]
    fn reports_fresh_and_changed_releases_as_updated() {
        let current = release(2, 'b');
        let installed = Installed {
            space_id: "space-0123456789abcdef01234567".into(),
            release_ref: current.reference.clone(),
            admin_image: format!("ghcr.io/theshimpz/shimpz-admin@sha256:{HEX}"),
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
    fn explicit_update_decision_covers_current_failed_stopped_and_running_releases() {
        let current = release(2, 'b');
        let forward = release(3, 'c');
        let installed = Installed {
            space_id: "space-0123456789abcdef01234567".into(),
            release_ref: current.reference.clone(),
            admin_image: format!("ghcr.io/theshimpz/shimpz-admin@sha256:{HEX}"),
            ordinal: 2,
            port: 7777,
        };

        for stopped in [false, true] {
            assert_eq!(
                update_decision(&installed, &current, stopped, false),
                UpdateDecision::Current
            );
            assert_eq!(
                update_decision(&installed, &forward, stopped, true),
                UpdateDecision::Failed
            );
        }
        assert_eq!(
            update_decision(&installed, &forward, true, false),
            UpdateDecision::Available
        );
        assert_eq!(
            update_decision(&installed, &forward, false, false),
            UpdateDecision::Apply
        );
    }

    #[test]
    fn explicit_update_invokes_effects_only_for_a_running_forward_release() {
        let current = release(2, 'b');
        let forward = release(3, 'c');
        let installed = Installed {
            space_id: "space-0123456789abcdef01234567".into(),
            release_ref: current.reference.clone(),
            admin_image: format!("ghcr.io/theshimpz/shimpz-admin@sha256:{HEX}"),
            ordinal: 2,
            port: 7777,
        };
        let passive = [
            update_decision(&installed, &current, false, false),
            update_decision(&installed, &forward, true, false),
            update_decision(&installed, &forward, false, true),
            update_decision(&installed, &forward, true, true),
        ];
        for decision in passive {
            let mut calls = 0;
            let outcome = run_update_effect(decision, || {
                calls += 1;
                Ok("applied".into())
            })
            .unwrap();

            assert_eq!(outcome, None);
            assert_eq!(calls, 0);
        }

        let mut calls = 0;
        let decision = update_decision(&installed, &forward, false, false);
        let outcome = run_update_effect(decision, || {
            calls += 1;
            Ok("applied".into())
        })
        .unwrap();

        assert_eq!(outcome.as_deref(), Some("applied"));
        assert_eq!(calls, 1);
    }

    #[test]
    fn explicit_update_outcomes_are_bounded_and_do_not_claim_space_health() {
        let current = release(2, 'b');
        let forward = release(3, 'c');
        let installed = Installed {
            space_id: "space-0123456789abcdef01234567".into(),
            release_ref: current.reference.clone(),
            admin_image: format!("ghcr.io/theshimpz/shimpz-admin@sha256:{HEX}"),
            ordinal: 2,
            port: 7777,
        };
        let outcomes = [
            current_release_outcome(&installed, false),
            current_release_outcome(&installed, true),
            available_release_outcome(&installed, &forward),
            failed_update_outcome(false),
            failed_update_outcome(true),
        ];

        assert!(outcomes[0].contains("release is current"));
        assert!(outcomes[0].contains("Next: shimpz status"));
        assert!(outcomes[1].contains("Stopped intent was preserved"));
        assert!(outcomes[1].contains("Next: shimpz start"));
        assert!(outcomes[2].contains("Available release: ordinal 3"));
        assert!(outcomes[3].contains("wait for a different Local release selection"));
        assert!(outcomes[4].contains("resume the installed release"));
        for outcome in outcomes {
            assert!(outcome.len() < 320);
            assert!(!outcome.contains("healthy"));
            assert!(!outcome.contains("sha256:"));
            assert!(!outcome.contains("space-0123456789abcdef01234567"));
            assert_eq!(output::sanitize(&outcome), outcome);
        }
    }

    #[test]
    fn update_progress_is_bounded_and_redacted() {
        assert_eq!(UPDATE_PROGRESS, "Checking for Shimpz Space updates...");
        assert!(UPDATE_PROGRESS.len() < 64);
        assert!(!UPDATE_PROGRESS.contains("sha256:"));
        assert_eq!(output::sanitize(UPDATE_PROGRESS), UPDATE_PROGRESS);
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
    fn a_failed_handoff_names_its_exit_status_or_start_error() {
        use std::os::unix::process::ExitStatusExt;

        assert_eq!(
            handoff_failure(Ok(std::process::ExitStatus::from_raw(0))),
            None
        );
        assert_eq!(
            handoff_failure(Ok(std::process::ExitStatus::from_raw(1 << 8))).as_deref(),
            Some("it exited with status 1")
        );
        assert_eq!(
            handoff_failure(Ok(std::process::ExitStatus::from_raw(9))).as_deref(),
            Some("it was stopped by a signal")
        );
        let busy = std::io::Error::from_raw_os_error(26);
        assert!(
            handoff_failure(Err(busy))
                .is_some_and(|reason| reason.starts_with("it could not start: "))
        );
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
    fn corrupt_recovery_refuses_a_fresh_install_while_owned_scheduler_entries_remain() {
        assert_eq!(
            corrupt_recovery_scheduler(Ok(scheduler::RemovalOutcome::default())),
            Ok(())
        );
        let foreign = scheduler::RemovalOutcome {
            preserved: vec!["/home/ada/.config/systemd/user/shimpz-update.timer".to_owned()],
            execution_unverified: true,
        };
        assert_eq!(corrupt_recovery_scheduler(Ok(foreign)), Ok(()));

        let error = corrupt_recovery_scheduler(Err(
            "the automatic Local update timer could not be proven stopped and disabled; the scheduler files were kept"
                .to_owned(),
        ))
        .unwrap_err();
        assert!(
            error.starts_with("the corrupt Local Space was removed, but its owned scheduler cleanup did not complete, so no fresh installation was started: the automatic Local update timer could not be proven stopped and disabled"),
            "{error}"
        );
        assert!(
            error.ends_with("run shimpz reset to finish the cleanup, then run shimpz install"),
            "{error}"
        );
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
    fn hard_reset_outcome_names_retained_and_preserved_state() {
        let clean = hard_reset_outcome(&[], false);
        assert!(clean.contains("hard reset completed"));
        assert!(clean.contains("No managed Space data remains"));
        assert!(clean.contains("Creator credentials"));
        assert!(clean.contains("pulled images"));
        assert!(clean.ends_with("Next: shimpz install"));

        let preserved = hard_reset_outcome(&["/home/ada/.shimpz/notes".into()], true);
        assert!(preserved.contains("/home/ada/.shimpz/notes"));
        assert!(preserved.contains("Scheduler execution state is unverified"));
        let preflight = hard_reset_preflight("the Local Space identity is invalid");
        assert!(preflight.contains("nothing changed"));
        assert!(preflight.contains("re-run shimpz reset --hard"));
    }

    struct MemoryTerminal {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl MemoryTerminal {
        fn new(input: &[u8]) -> Self {
            Self {
                input: Cursor::new(input.to_vec()),
                output: Vec::new(),
            }
        }
    }

    impl Read for MemoryTerminal {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buffer)
        }
    }

    impl Write for MemoryTerminal {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.output.write(buffer)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn hard_reset_confirmation_accepts_only_exact_yes() {
        for (input, expected) in [
            (b"Yes\n".as_slice(), true),
            (b"No\n", false),
            (b"\n", false),
        ] {
            let mut terminal = MemoryTerminal::new(input);
            assert_eq!(hard_reset_confirmation(&mut terminal), Ok(expected));
            assert!(
                String::from_utf8(terminal.output)
                    .unwrap()
                    .contains("[Yes/No]")
            );
        }
        for input in [b"yes\n".as_slice(), b"Yes\r\n", b"123456789\n"] {
            let mut terminal = MemoryTerminal::new(input);
            assert!(
                hard_reset_confirmation(&mut terminal)
                    .unwrap_err()
                    .contains("nothing changed")
            );
        }
    }

    #[test]
    fn host_reset_prompts_only_for_the_exact_password_required_decision() {
        assert_eq!(
            admin_reset_decision(200, &serde_json::json!({"reset": true}), None, false),
            Ok(AdminResetDecision::Complete)
        );
        assert_eq!(
            admin_reset_decision(
                409,
                &serde_json::json!({
                    "code": "supervisor-password-required",
                    "detail": "Supervisor password is required"
                }),
                None,
                false,
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
                admin_reset_decision(status, &body, None, false)
                    .unwrap_err()
                    .contains("re-run shimpz reset")
            );
        }
    }

    #[test]
    fn generated_host_reset_capability_is_space_bound_bounded_and_secret_free() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let capability = generate_host_reset_capability("space-0123456789abcdef01234567").unwrap();
        let document: serde_json::Value = serde_json::from_slice(&capability.document).unwrap();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert_eq!(capability.secret.len(), 64);
        assert!(
            capability
                .secret
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        assert_eq!(document["version"], 1);
        assert_eq!(document["purpose"], "space-reset");
        assert_eq!(document["space_id"], "space-0123456789abcdef01234567");
        assert!(document["created_at"].as_u64().unwrap() >= before);
        assert!(document["created_at"].as_u64().unwrap() <= after);
        assert_eq!(
            document["expires_at"].as_u64().unwrap() - document["created_at"].as_u64().unwrap(),
            HOST_RESET_CAPABILITY_SECONDS
        );
        let secret = hex_bytes(capability.secret.as_str());
        assert_eq!(
            document["capability_sha256"],
            format!("{:x}", Sha256::digest(secret))
        );
        assert!(
            !String::from_utf8(capability.document)
                .unwrap()
                .contains(capability.secret.as_str())
        );
    }

    fn hex_bytes(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn local_session(authentication_state: &str, initialized: bool) -> serde_json::Value {
        serde_json::json!({
            "profile": "local",
            "authenticated": false,
            "initialized": initialized,
            "authentication_state": authentication_state,
            "features": {"teamCredentials": true}
        })
    }

    #[test]
    fn release_gate_accepts_only_exact_consistent_local_authentication_states() {
        for (name, initialized, expected) in [
            (
                "uninitialized",
                false,
                AdminAuthenticationState::Uninitialized,
            ),
            (
                "enrollment-required",
                true,
                AdminAuthenticationState::EnrollmentRequired,
            ),
            ("configured", true, AdminAuthenticationState::Configured),
            (
                "recovery-required",
                true,
                AdminAuthenticationState::RecoveryRequired,
            ),
        ] {
            assert_eq!(
                admin_authentication_state_response(200, &local_session(name, initialized)),
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
                    "profile": "unknown",
                    "authenticated": false,
                    "initialized": true,
                    "authentication_state": "configured",
                    "features": {"teamCredentials": true}
                }),
            ),
            (
                200,
                serde_json::json!({
                    "profile": "local",
                    "authenticated": false,
                    "initialized": true,
                    "authentication_state": "configured",
                    "features": {"teamCredentials": true},
                    "extra": true
                }),
            ),
        ] {
            assert!(admin_authentication_state_response(status, &body).is_err());
        }
    }

    #[test]
    fn candidate_authentication_probe_accepts_only_exact_bounded_states() {
        for (value, expected) in [
            ("uninitialized", AdminAuthenticationState::Uninitialized),
            (
                "enrollment-required",
                AdminAuthenticationState::EnrollmentRequired,
            ),
            ("configured", AdminAuthenticationState::Configured),
            (
                "recovery-required",
                AdminAuthenticationState::RecoveryRequired,
            ),
        ] {
            assert_eq!(
                admin_authentication_state_probe_response(value),
                Ok(expected)
            );
        }
        for invalid in ["", "configured\n", "recovery_required", "future-state"] {
            assert!(admin_authentication_state_probe_response(invalid).is_err());
        }
        assert_eq!(
            candidate_admission_error("the candidate check failed"),
            "the candidate check failed; the installed release is unchanged"
        );
    }

    #[test]
    fn host_reset_distinguishes_throttling_from_password_rejection() {
        assert!(
            admin_reset_decision(
                429,
                &serde_json::json!({"detail": "hidden"}),
                Some("1"),
                true
            )
            .unwrap_err()
            .contains("wait 1 second")
        );
        assert!(
            admin_reset_decision(
                429,
                &serde_json::json!({"detail": "hidden"}),
                Some("60"),
                true
            )
            .unwrap_err()
            .contains("wait 60 seconds")
        );
        for invalid in [None, Some("0"), Some("3601"), Some("untrusted\nvalue")] {
            let error =
                admin_reset_decision(429, &serde_json::json!({"detail": "hidden"}), invalid, true)
                    .unwrap_err();
            assert!(error.contains("wait one minute"));
            assert!(!error.contains("untrusted"));
        }
        assert!(
            admin_reset_decision(401, &serde_json::json!({"detail": "hidden"}), None, true)
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
    fn reset_preserves_unrecognized_entries_beside_the_managed_cli() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        let bin = paths.managed_cli.parent().unwrap();
        fs::create_dir_all(bin).unwrap();
        fs::set_permissions(bin, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&paths.managed_cli, "managed").unwrap();
        fs::set_permissions(&paths.managed_cli, fs::Permissions::from_mode(0o700)).unwrap();
        let unrecognized = bin.join("notes");
        fs::write(&unrecognized, "preserve").unwrap();

        let mut preserved = PathReport::default();
        record_retained_bin_entries(&paths, &mut preserved).unwrap();
        let preflight = preflight_remove_files(&paths, false).unwrap();

        assert!(unrecognized.exists());
        assert_eq!(
            preserved.into_strings(),
            [unrecognized.display().to_string()]
        );
        assert_eq!(preflight, [unrecognized.display().to_string()]);
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

    /// A private Space home with a managed CLI directory, plus a verified release-bound CLI outside it.
    fn activation_fixture(home: &Path) -> (Paths, PathBuf, String) {
        let paths = Paths::under(home).unwrap();
        fs::create_dir(&paths.home).unwrap();
        fs::set_permissions(&paths.home, fs::Permissions::from_mode(0o700)).unwrap();
        let source = home.join("bootstrap-shimpz");
        fs::write(&source, "release-bound CLI").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        let expected = hash_file(&source).unwrap();
        (paths, source, expected)
    }

    fn private_file(path: &Path, content: &str, mode: u32) {
        fs::write(path, content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn activation_installs_the_verified_cli_and_clears_stale_handoff_artifacts() {
        let home = tempfile::tempdir().unwrap();
        let (paths, source, expected) = activation_fixture(home.path());
        let bin = paths.managed_cli.parent().unwrap();
        fs::create_dir(bin).unwrap();
        private_file(&paths.managed_cli, "old CLI", 0o700);
        private_file(
            &paths.managed_cli.with_extension("previous"),
            "stale",
            0o700,
        );
        private_file(
            &paths.managed_cli.with_extension("candidate"),
            "stale",
            0o700,
        );

        activate_cli(&paths, &source, &expected).unwrap();

        assert_eq!(
            fs::read_to_string(&paths.managed_cli).unwrap(),
            "release-bound CLI"
        );
        assert_eq!(mode(&paths.managed_cli), 0o700);
        assert_eq!(mode(bin), 0o700);
        assert!(!paths.managed_cli.with_extension("previous").exists());
        assert!(!paths.managed_cli.with_extension("candidate").exists());
    }

    #[test]
    fn activation_creates_the_private_managed_directory_for_a_fresh_space() {
        let home = tempfile::tempdir().unwrap();
        let (paths, source, expected) = activation_fixture(home.path());

        activate_cli(&paths, &source, &expected).unwrap();

        assert_eq!(mode(paths.managed_cli.parent().unwrap()), 0o700);
        assert_eq!(mode(&paths.managed_cli), 0o700);
        assert_eq!(hash_file(&paths.managed_cli).unwrap(), expected);
    }

    #[test]
    fn activation_of_an_unbound_cli_leaves_the_managed_cli_untouched() {
        let home = tempfile::tempdir().unwrap();
        let (paths, source, _) = activation_fixture(home.path());
        fs::create_dir(paths.managed_cli.parent().unwrap()).unwrap();
        private_file(&paths.managed_cli, "old CLI", 0o700);

        let error = activate_cli(&paths, &source, HEX).unwrap_err();

        assert_eq!(
            error,
            "the running CLI is not bound to the selected Local release"
        );
        assert_eq!(fs::read_to_string(&paths.managed_cli).unwrap(), "old CLI");
        assert!(!paths.managed_cli.with_extension("candidate").exists());
    }

    #[test]
    fn activation_refuses_a_redirected_managed_directory() {
        let home = tempfile::tempdir().unwrap();
        let (paths, source, expected) = activation_fixture(home.path());
        let outside = home.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let bin = paths.managed_cli.parent().unwrap();
        symlink(&outside, bin).unwrap();
        assert!(activate_cli(&paths, &source, &expected).is_err());
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);

        fs::remove_file(bin).unwrap();
        symlink(home.path().join("missing"), bin).unwrap();
        assert!(activate_cli(&paths, &source, &expected).is_err());
        assert!(!home.path().join("missing").exists());
    }

    #[test]
    fn activation_refuses_foreign_entries_before_changing_the_managed_directory() {
        let home = tempfile::tempdir().unwrap();
        let (paths, source, expected) = activation_fixture(home.path());
        let bin = paths.managed_cli.parent().unwrap();
        fs::create_dir(bin).unwrap();
        fs::set_permissions(bin, fs::Permissions::from_mode(0o755)).unwrap();
        private_file(&paths.managed_cli, "old CLI", 0o700);
        private_file(&bin.join("foreign"), "foreign", 0o600);

        assert!(
            activate_cli(&paths, &source, &expected)
                .unwrap_err()
                .starts_with("refusing to use unowned managed CLI entries")
        );
        assert_eq!(mode(bin), 0o755);
        assert_eq!(fs::read_to_string(&paths.managed_cli).unwrap(), "old CLI");
    }

    #[test]
    fn activation_by_the_running_managed_cli_keeps_its_executable_image() {
        let home = tempfile::tempdir().unwrap();
        let (paths, _, expected) = activation_fixture(home.path());
        fs::create_dir(paths.managed_cli.parent().unwrap()).unwrap();
        private_file(&paths.managed_cli, "release-bound CLI", 0o600);
        private_file(&paths.managed_cli.with_extension("previous"), "old", 0o700);
        private_file(
            &paths.managed_cli.with_extension("candidate"),
            "stale",
            0o700,
        );
        let inode = fs::metadata(&paths.managed_cli).unwrap().ino();

        activate_cli(&paths, &paths.managed_cli, &expected).unwrap();

        assert_eq!(fs::metadata(&paths.managed_cli).unwrap().ino(), inode);
        assert_eq!(mode(&paths.managed_cli), 0o700);
        assert!(!paths.managed_cli.with_extension("previous").exists());
        assert!(!paths.managed_cli.with_extension("candidate").exists());
        assert!(activate_cli(&paths, &paths.managed_cli, HEX).is_err());
        assert_eq!(fs::metadata(&paths.managed_cli).unwrap().ino(), inode);
    }

    /// A committed release-1 Space whose handoff to release 2 runs a fake release-bound child CLI. The child runs
    /// `child_body` after recording its arguments; the fake Docker extracts that child as the release CLI.
    #[cfg(unix)]
    fn handoff_space(home: &Path, child_body: &str) -> (Context, ResolvedRelease, PathBuf) {
        let root = home.join("fixture");
        fs::create_dir(&root).unwrap();
        let docker = root.join("docker");
        let (context, backup) = installed_space(home, docker.clone());
        remove_backup(Some(backup)).unwrap();
        let installed = state::read_installed(&context.paths, HostProfile::MacOs).unwrap();
        state::write_status(&context.paths, &release(1, 'a'), "current").unwrap();
        let mut target = release(2, 'b');
        // The committed release-2 environment the child installs when its apply reaches the commit.
        fs::copy(&context.paths.environment, root.join("release-1.env")).unwrap();
        state::write_environment(
            &context.paths,
            &Environment {
                release: &target,
                profile: HostProfile::MacOs,
                space_id: &installed.space_id,
                port: installed.port,
                docker_gid: 0,
                docker_socket: Path::new("/var/run/docker.sock.raw"),
                cpuset: "0",
                secure_root: &context.paths.pool_mount,
            },
        )
        .unwrap();
        fs::copy(&context.paths.environment, root.join("release-2.env")).unwrap();
        fs::copy(root.join("release-1.env"), &context.paths.environment).unwrap();
        let child = root.join("release-cli");
        fs::write(
            &child,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\n{child_body}",
                root.join("child-arguments").display()
            ),
        )
        .unwrap();
        target.metadata.cli_macos_arm64_sha256 = Some(hash_file(&child).unwrap());
        crate::fake_tool::write(
            &docker,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n  create) printf '%s\\n' {} ;;\n  cp) cp '{}' \"$3\" ;;\n  *) exit 0 ;;\nesac\n",
                "c".repeat(64),
                child.display()
            ),
        );
        fs::create_dir_all(context.paths.managed_cli.parent().unwrap()).unwrap();
        private_file(&context.paths.managed_cli, "previous CLI", 0o700);
        (context, target, root)
    }

    #[cfg(unix)]
    #[test]
    fn a_handoff_failing_after_its_release_commit_keeps_the_release_bound_cli() {
        let home = tempfile::tempdir().unwrap();
        let child_status = format!(
            "cp '{}' '{}'\nprintf '%s' '{}' > '{}'\necho 'automatic Local updates were not enabled' >&2\nexit 1\n",
            home.path().join("fixture/release-2.env").display(),
            home.path().join(".shimpz/.env").display(),
            serde_json::json!({
                "release": release(2, 'b').reference,
                "ordinal": 2,
                "checked_at": 1,
                "outcome": "updated",
            }),
            home.path().join(".shimpz/release-status.json").display(),
        );
        let (context, target, root) = handoff_space(home.path(), &child_status);

        let error = context
            .handoff_admitted_release(&target, false)
            .unwrap_err();

        assert!(
            error.starts_with("the release-bound CLI committed the release but did not complete (it exited with status 1)"),
            "{error}"
        );
        assert_eq!(
            fs::read_to_string(root.join("child-arguments")).unwrap(),
            format!("install {} --candidate\n", target.reference)
        );
        assert_eq!(
            Some(hash_file(&context.paths.managed_cli).unwrap()),
            target.metadata.cli_macos_arm64_sha256
        );
        assert!(
            !context
                .paths
                .managed_cli
                .with_extension("previous")
                .exists()
        );
        assert!(
            !context
                .paths
                .managed_cli
                .with_extension("candidate")
                .exists()
        );
        assert_eq!(
            fs::read_link(&context.paths.public_cli).unwrap(),
            context.paths.managed_cli
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_handoff_that_rolled_back_restores_the_previous_cli() {
        let home = tempfile::tempdir().unwrap();
        let child_status = format!(
            "printf '%s' '{}' > '{}'\necho 'the previous healthy release was restored' >&2\nexit 1\n",
            serde_json::json!({
                "release": release(2, 'b').reference,
                "ordinal": 2,
                "checked_at": 1,
                "outcome": "rollback-needed",
            }),
            home.path().join(".shimpz/release-status.json").display(),
        );
        let (context, target, _) = handoff_space(home.path(), &child_status);

        let error = context
            .handoff_admitted_release(&target, false)
            .unwrap_err();

        assert!(error.ends_with("the previous CLI was restored"), "{error}");
        assert_eq!(
            fs::read_to_string(&context.paths.managed_cli).unwrap(),
            "previous CLI"
        );
        assert!(
            !context
                .paths
                .managed_cli
                .with_extension("previous")
                .exists()
        );
        assert!(!context.paths.public_cli.exists());
    }

    #[cfg(unix)]
    #[test]
    fn commit_evidence_separates_proved_commits_rollbacks_and_unknown_state() {
        let home = tempfile::tempdir().unwrap();
        let (context, _backup) = installed_space(home.path(), PathBuf::from("/usr/bin/false"));
        let paths = &context.paths;
        let installed = release(1, 'a');
        let evidence =
            |release: &ResolvedRelease| commit_evidence(paths, HostProfile::MacOs, release);
        let record = |value: serde_json::Value| {
            state::write_private(&paths.status, &value.to_string()).unwrap();
        };
        let unknown = |evidence: CommitEvidence| matches!(evidence, CommitEvidence::Unknown(_));

        // Positive non-commit: no success record, a rollback record, another release, or no environment.
        assert_eq!(evidence(&installed), CommitEvidence::NotCommitted);
        state::write_status(paths, &installed, "rollback-needed").unwrap();
        assert_eq!(evidence(&installed), CommitEvidence::NotCommitted);
        state::write_status(paths, &release(2, 'b'), "updated").unwrap();
        assert_eq!(evidence(&installed), CommitEvidence::NotCommitted);
        assert_eq!(evidence(&release(2, 'b')), CommitEvidence::NotCommitted);

        // A success record of the live release proves the commit, even after a backward clock change.
        state::write_status(paths, &installed, "current").unwrap();
        assert_eq!(evidence(&installed), CommitEvidence::Committed);
        record(serde_json::json!({
            "release": installed.reference, "ordinal": 1, "checked_at": u64::MAX, "outcome": "updated",
        }));
        assert_eq!(evidence(&installed), CommitEvidence::Committed);

        // Unreadable, refused, or malformed records prove nothing.
        fs::set_permissions(&paths.status, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(unknown(evidence(&installed)));
        fs::remove_file(&paths.status).unwrap();
        state::write_private(&paths.status, "{not json").unwrap();
        assert!(unknown(evidence(&installed)));
        record(serde_json::json!({
            "release": installed.reference, "ordinal": 1, "checked_at": 1, "outcome": "updated", "extra": true,
        }));
        assert!(unknown(evidence(&installed)));
        record(serde_json::json!({
            "release": installed.reference, "ordinal": 1, "checked_at": 1, "outcome": "committed",
        }));
        assert!(unknown(evidence(&installed)));
        record(serde_json::json!({
            "release": "invalid", "ordinal": 1, "checked_at": 1, "outcome": "updated",
        }));
        assert!(unknown(evidence(&installed)));
        record(serde_json::json!({
            "release": release(2, 'b').reference, "ordinal": 0, "checked_at": 1, "outcome": "updated",
        }));
        assert!(unknown(evidence(&installed)));
        record(serde_json::json!({
            "release": installed.reference, "ordinal": 2, "checked_at": 1, "outcome": "updated",
        }));
        assert!(unknown(evidence(&installed)));
        fs::remove_file(&paths.status).unwrap();
        let elsewhere = home.path().join("status-elsewhere");
        fs::write(&elsewhere, "{}").unwrap();
        symlink(&elsewhere, &paths.status).unwrap();
        assert!(unknown(evidence(&installed)));
        fs::remove_file(&paths.status).unwrap();

        state::write_status(paths, &installed, "current").unwrap();
        assert_eq!(evidence(&installed), CommitEvidence::Committed);
        let environment = fs::read_to_string(&paths.environment).unwrap();
        let refused = |evidence: CommitEvidence| {
            evidence
                == CommitEvidence::Unknown(
                    "the installed Local environment is not a private record".into(),
                )
        };
        // A redirected, shared, hard-linked, oversized, or special environment is refused, never followed.
        let elsewhere = home.path().join("environment-elsewhere");
        fs::rename(&paths.environment, &elsewhere).unwrap();
        symlink(&elsewhere, &paths.environment).unwrap();
        assert!(refused(evidence(&installed)));
        fs::remove_file(&paths.environment).unwrap();
        fs::rename(&elsewhere, &paths.environment).unwrap();
        fs::set_permissions(&paths.environment, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(refused(evidence(&installed)));
        fs::set_permissions(&paths.environment, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&paths.environment, home.path().join("environment-link")).unwrap();
        assert!(refused(evidence(&installed)));
        fs::remove_file(home.path().join("environment-link")).unwrap();
        assert_eq!(evidence(&installed), CommitEvidence::Committed);
        state::write_private(
            &paths.environment,
            &format!("{environment}{}", "#".repeat(8_192)),
        )
        .unwrap();
        assert!(refused(evidence(&installed)));
        fs::remove_file(&paths.environment).unwrap();
        fs::create_dir(&paths.environment).unwrap();
        assert!(refused(evidence(&installed)));
        fs::remove_dir(&paths.environment).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .args(["-m", "600"])
                .arg(&paths.environment)
                .status()
                .unwrap()
                .success()
        );
        assert!(refused(evidence(&installed)));
        fs::remove_file(&paths.environment).unwrap();

        state::write_private(&paths.environment, "SHIMPZ_LOCAL_RELEASE_IMAGE\n").unwrap();
        assert!(unknown(evidence(&installed)));
        fs::remove_file(&paths.environment).unwrap();
        assert_eq!(evidence(&installed), CommitEvidence::NotCommitted);
    }

    #[cfg(unix)]
    #[test]
    fn a_handoff_with_a_redirected_environment_keeps_both_clis() {
        let home = tempfile::tempdir().unwrap();
        let environment = home.path().join(".shimpz/.env");
        let child_status = format!(
            "rm '{environment}'\nln -s '{}' '{environment}'\nprintf '%s' '{}' > '{}'\nexit 1\n",
            home.path().join("fixture/release-2.env").display(),
            serde_json::json!({
                "release": release(2, 'b').reference,
                "ordinal": 2,
                "checked_at": 1,
                "outcome": "updated",
            }),
            home.path().join(".shimpz/release-status.json").display(),
            environment = environment.display(),
        );
        let (context, target, _) = handoff_space(home.path(), &child_status);

        let error = context
            .handoff_admitted_release(&target, false)
            .unwrap_err();

        assert!(
            error.contains("could not be determined: the installed Local environment is not a private record; both CLIs were kept"),
            "{error}"
        );
        assert_eq!(
            Some(hash_file(&context.paths.managed_cli).unwrap()),
            target.metadata.cli_macos_arm64_sha256
        );
        assert_eq!(
            fs::read_to_string(context.paths.managed_cli.with_extension("previous")).unwrap(),
            "previous CLI"
        );
        assert!(fs::symlink_metadata(&context.paths.public_cli).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_handoff_with_unknown_commit_evidence_keeps_both_clis() {
        let home = tempfile::tempdir().unwrap();
        let status = home.path().join(".shimpz/release-status.json");
        let child_status = format!(
            "cp '{}' '{}'\nprintf '%s' '{}' > '{}'\nchmod 400 '{}'\necho 'automatic Local updates were not enabled' >&2\nexit 1\n",
            home.path().join("fixture/release-2.env").display(),
            home.path().join(".shimpz/.env").display(),
            serde_json::json!({
                "release": release(2, 'b').reference,
                "ordinal": 2,
                "checked_at": 1,
                "outcome": "updated",
            }),
            status.display(),
            status.display(),
        );
        let (context, target, _) = handoff_space(home.path(), &child_status);

        let error = context
            .handoff_admitted_release(&target, false)
            .unwrap_err();

        assert!(
            error.contains("whether it committed the release could not be determined: the Local release status is not a private record; both CLIs were kept"),
            "{error}"
        );
        assert!(
            error.contains(" install; it reconciles the Space, offers recovery"),
            "{error}"
        );
        assert_eq!(
            Some(hash_file(&context.paths.managed_cli).unwrap()),
            target.metadata.cli_macos_arm64_sha256
        );
        assert_eq!(
            fs::read_to_string(context.paths.managed_cli.with_extension("previous")).unwrap(),
            "previous CLI"
        );
        assert!(!context.paths.public_cli.exists());
    }

    /// A scheduled handoff of a release-1 Space whose child exits successfully after running `child_body`.
    #[cfg(unix)]
    fn scheduled_handoff(
        home: &Path,
        child_body: &str,
    ) -> (Context, ResolvedRelease, PathBuf, Result<bool, String>) {
        let (context, target, root) = handoff_space(home, &format!("{child_body}exit 0\n"));
        state::write_marker(&context.paths).unwrap();
        let outcome = context.handoff_admitted_release(&target, true);
        assert_eq!(
            fs::read_to_string(root.join("child-arguments")).unwrap(),
            format!(
                "start --scheduled --release {} --candidate\n",
                target.reference
            )
        );
        (context, target, root, outcome)
    }

    #[cfg(unix)]
    fn assert_previous_cli_restored(context: &Context) {
        assert_eq!(
            fs::read_to_string(&context.paths.managed_cli).unwrap(),
            "previous CLI"
        );
        assert!(
            !context
                .paths
                .managed_cli
                .with_extension("previous")
                .exists()
        );
        assert!(!context.paths.public_cli.exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_handoff_that_recreated_and_rolled_back_reports_the_recreation() {
        let home = tempfile::tempdir().unwrap();
        // The child empties the runtime state for its release, fails health, and its rollback recreates the state
        // again for the previous epoch: the epoch ends where it began, but the record does not.
        let record = Paths::under(home.path()).unwrap().state_epoch;
        let child_body = format!(
            "umask 077\nprintf '1 %s\\n' {} > '{}'\nexit 1\n",
            "f".repeat(32),
            record.display()
        );
        let (_, _, _, outcome) = scheduled_handoff(home.path(), &child_body);

        let error = outcome.unwrap_err();
        assert!(
            error.ends_with("; the Team runtime state was recreated empty"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_handoff_that_failed_before_emptying_the_state_reports_no_recreation() {
        let home = tempfile::tempdir().unwrap();
        // The child forgot the record before its recreation failed: nothing was emptied.
        let record = Paths::under(home.path()).unwrap().state_epoch;
        let child_body = format!("rm -f '{}'\nexit 1\n", record.display());
        let (_, _, _, outcome) = scheduled_handoff(home.path(), &child_body);

        let error = outcome.unwrap_err();
        assert!(!error.contains("recreated"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn a_deferred_handoff_restores_the_previous_cli_and_reports_the_deferral() {
        let home = tempfile::tempdir().unwrap();
        // The child records an activity deferral of the target release and exits successfully without applying it.
        let (context, target, _, outcome) = scheduled_handoff(home.path(), "");
        let digest = poll::release_digest(&target.reference).unwrap();
        assert!(
            poll::defer_for_activity(&context.paths, digest, poll::now(), || {
                poll::TeamActivity::Busy
            })
            .unwrap()
        );

        assert_eq!(outcome, Ok(true));
        assert_previous_cli_restored(&context);
        assert_eq!(context.handoff_outcome(&target).unwrap(), UPDATE_DEFERRED);
    }

    #[cfg(unix)]
    #[test]
    fn a_handoff_that_found_storage_locked_restores_the_previous_cli() {
        let home = tempfile::tempdir().unwrap();
        let (context, target, _, outcome) = scheduled_handoff(home.path(), "");

        assert_eq!(outcome, Ok(true));
        assert_previous_cli_restored(&context);
        assert_eq!(
            context.handoff_outcome(&target).unwrap(),
            "The release-bound CLI finished without applying the selected Local release."
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_unscheduled_handoff_that_exits_without_a_commit_restores_the_previous_cli_and_fails() {
        let home = tempfile::tempdir().unwrap();
        let (context, target, _) = handoff_space(home.path(), "exit 0\n");

        let error = context
            .handoff_admitted_release(&target, false)
            .unwrap_err();

        assert_eq!(
            error,
            "the release-bound CLI exited without committing the selected Local release; the previous CLI was restored"
        );
        assert_previous_cli_restored(&context);
    }

    #[cfg(unix)]
    #[test]
    fn a_committed_handoff_removes_the_previous_cli() {
        let home = tempfile::tempdir().unwrap();
        let child_body = format!(
            "cp '{}' '{}'\nprintf '%s' '{}' > '{}'\n",
            home.path().join("fixture/release-2.env").display(),
            home.path().join(".shimpz/.env").display(),
            serde_json::json!({
                "release": release(2, 'b').reference,
                "ordinal": 2,
                "checked_at": 1,
                "outcome": "updated",
            }),
            home.path().join(".shimpz/release-status.json").display(),
        );
        let (context, target, _, outcome) = scheduled_handoff(home.path(), &child_body);

        assert_eq!(outcome, Ok(true));
        assert_eq!(
            Some(hash_file(&context.paths.managed_cli).unwrap()),
            target.metadata.cli_macos_arm64_sha256
        );
        assert!(
            !context
                .paths
                .managed_cli
                .with_extension("previous")
                .exists()
        );
        assert_eq!(
            fs::read_link(&context.paths.public_cli).unwrap(),
            context.paths.managed_cli
        );
        assert_eq!(
            context.handoff_outcome(&target).unwrap(),
            "The release-bound CLI completed reconciliation."
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_successful_handoff_with_unknown_commit_evidence_keeps_both_clis() {
        let home = tempfile::tempdir().unwrap();
        let status = home.path().join(".shimpz/release-status.json");
        let child_body = format!(
            "cp '{}' '{}'\nprintf '%s' '{}' > '{}'\nchmod 400 '{}'\n",
            home.path().join("fixture/release-2.env").display(),
            home.path().join(".shimpz/.env").display(),
            serde_json::json!({
                "release": release(2, 'b').reference,
                "ordinal": 2,
                "checked_at": 1,
                "outcome": "updated",
            }),
            status.display(),
            status.display(),
        );
        let (context, target, _, outcome) = scheduled_handoff(home.path(), &child_body);

        let error = outcome.unwrap_err();
        assert!(
            error.starts_with("the release-bound CLI exited successfully, but whether it committed the release could not be determined: the Local release status is not a private record; both CLIs were kept"),
            "{error}"
        );
        assert_eq!(
            Some(hash_file(&context.paths.managed_cli).unwrap()),
            target.metadata.cli_macos_arm64_sha256
        );
        assert_eq!(
            fs::read_to_string(context.paths.managed_cli.with_extension("previous")).unwrap(),
            "previous CLI"
        );
        assert!(!context.paths.public_cli.exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_rollback_projects_its_status_even_when_it_cannot_record_it_locally() {
        let home = tempfile::tempdir().unwrap();
        let docker = home.path().join("docker");
        let projected = home.path().join("projected");
        crate::fake_tool::write(
            &docker,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n  volume) printf '%s\\n' 'shimpz-space_release_status|shimpz-space|release_status' ;;\n  image) echo 1 ;;\n  run) cat > '{}' ;;\n  *) exit 0 ;;\nesac\n",
                projected.display()
            ),
        );
        let (context, backup) = installed_space(home.path(), docker);
        let installed = state::read_installed(&context.paths, HostProfile::MacOs).unwrap();
        // The local status staging path cannot be replaced, so recording the rollback status fails.
        fs::create_dir(context.paths.status.with_extension("tmp")).unwrap();

        let outcome = context
            .rollback(&release(2, 'b'), &installed.space_id, Some(backup))
            .unwrap_err();

        assert!(
            outcome.starts_with("the update failed; the previous healthy release was restored; the rollback status could not be recorded: "),
            "{outcome}"
        );
        let document: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&projected).unwrap()).unwrap();
        assert_eq!(document["release"], release(2, 'b').reference);
        assert_eq!(document["outcome"], "rollback-needed");
        assert!(!context.paths.status.exists());
    }

    /// A Docker double that records every invocation and reports stopped owned Team and Admin containers.
    #[cfg(unix)]
    fn stopped_space_docker(root: &Path) -> PathBuf {
        let command = root.join("docker");
        crate::fake_tool::write(
            &command,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{calls}'\n\
                 case \"$*\" in\n  \
                 *'{{{{.Name}}}}'*) printf '{team}|/shimpz-team\\n{admin}|/shimpz-admin\\n' ;;\n  \
                 *'shimpz-admin') printf 'false|shimpz-space|admin|{{\"4600/tcp\":[{{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"7777\"}}]}}\\n' ;;\n  \
                 *'shimpz-team') printf 'false\\n' ;;\n\
                 esac\n",
                calls = root.join("calls").display(),
                team = format_args!("{:0<64}", "c001"),
                admin = format_args!("{:0<64}", "c002"),
            ),
        );
        command
    }

    #[cfg(unix)]
    #[test]
    fn corrupt_recovery_starts_nothing_without_an_affirmative_answer() {
        let declined = || Ok(false);
        let noninteractive =
            || Err("recovery requires an interactive terminal; nothing changed".to_owned());
        for (answer, expected) in [
            (
                &declined as &dyn Fn() -> Result<bool, String>,
                "the corrupt Local Space was preserved; nothing changed",
            ),
            (
                &noninteractive,
                "recovery requires an interactive terminal; nothing changed",
            ),
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let docker = stopped_space_docker(temporary.path());
            let context = Context {
                paths: Paths::under(&temporary.path().join("home")).unwrap(),
                profile: HostProfile::MacOs,
                engine: Engine::with_docker(docker),
                scheduled: false,
                recreated: Cell::new(false),
            };
            let inventory = Inventory {
                project_containers: vec![format!("{:0<64}", "c001"), format!("{:0<64}", "c002")],
                ..Inventory::default()
            };
            let mut shown = Vec::new();
            let outcome = context.recover_corrupt_after(&inventory, "corrupt marker", |names| {
                shown = names.to_vec();
                answer()
            });

            assert_eq!(outcome, Err(expected.to_owned()));
            assert_eq!(shown, ["shimpz-admin", "shimpz-team"]);
            let calls = fs::read_to_string(temporary.path().join("calls")).unwrap();
            assert!(
                calls.lines().all(|call| !call.starts_with("start")),
                "{calls}"
            );
        }
        // The double does start a stopped Space once recovery is affirmed, so the refusal above is meaningful.
        let temporary = tempfile::tempdir().unwrap();
        let context = Context {
            paths: Paths::under(&temporary.path().join("home")).unwrap(),
            profile: HostProfile::MacOs,
            engine: Engine::with_docker(stopped_space_docker(temporary.path())),
            scheduled: false,
            recreated: Cell::new(false),
        };
        assert!(context.prepare_admin_for_recovery().is_ok());
        let calls = fs::read_to_string(temporary.path().join("calls")).unwrap();
        assert!(
            calls.lines().any(|call| call == "start shimpz-team"),
            "{calls}"
        );
        assert!(
            calls.lines().any(|call| call == "start shimpz-admin"),
            "{calls}"
        );
    }

    /// A fake `docker` that logs each call and answers every identifier after `--format` from `map`, whose lines
    /// start with each identifier's full 64-character id.
    #[cfg(unix)]
    fn inspecting_docker(map: &str) -> (tempfile::TempDir, Engine) {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        fs::write(root.join("map"), map).unwrap();
        let command = root.join("docker");
        crate::fake_tool::write(
            &command,
            format!(
                "#!/bin/sh\nprintf 'call\\n' >> '{calls}'\nseen=0\nfor argument in \"$@\"; do\n  \
                 if [ \"$seen\" = 2 ]; then grep -m1 \"^$argument\" '{map}' || true; fi\n  \
                 if [ \"$seen\" = 1 ]; then seen=2; fi\n  \
                 if [ \"$argument\" = --format ]; then seen=1; fi\ndone\n",
                calls = root.join("calls").display(),
                map = root.join("map").display(),
            ),
        );
        (temporary, Engine::with_docker(command))
    }

    #[cfg(unix)]
    fn inspect_calls(temporary: &tempfile::TempDir) -> usize {
        fs::read_to_string(temporary.path().join("calls"))
            .unwrap_or_default()
            .lines()
            .count()
    }

    #[cfg(unix)]
    #[test]
    fn a_runtime_snapshot_inspects_only_inventory_proven_containers_in_batches() {
        let components = status_report::COMPONENTS;
        let map = format!(
            "{:0<64}|/shimpz-admin|admin|running|healthy|0\n\
             {:0<64}|/shimpz-team|team|exited||7\n\
             {:0<64}|/shimpz-account-egress-init|shimpz-account-egress-init|exited||0\n\
             {:0<64}|running|0\n{:0<64}|exited|137\n",
            "c001", "c002", "c003", "a001", "a002"
        );
        let inventory = Inventory {
            project_containers: vec!["c001".into(), "c002".into(), "c003".into()],
            dynamic_containers: vec!["c002".into(), "a001".into(), "a002".into()],
            ..Inventory::default()
        };
        let (temporary, engine) = inspecting_docker(&map);
        let snapshot = runtime_snapshot(&engine, &inventory).unwrap();
        // Eight components and two Assistants used to cost ten Docker processes; two batches answer them all.
        assert_eq!(inspect_calls(&temporary), 2);
        let expected = components
            .iter()
            .map(|component| {
                let record = match component.docker_name() {
                    "shimpz-admin" => Some("admin|running|healthy|0"),
                    "shimpz-team" => Some("team|exited||7"),
                    "shimpz-account-egress-init" => Some("shimpz-account-egress-init|exited||0"),
                    _ => None,
                };
                status_report::observe(*component, record).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(snapshot.components, expected);
        assert_eq!(
            snapshot.assistants,
            [
                status_report::observe_assistant("running|0").unwrap(),
                status_report::observe_assistant("exited|137").unwrap(),
            ]
        );

        let (temporary, engine) = inspecting_docker("");
        let snapshot = runtime_snapshot(&engine, &Inventory::default()).unwrap();
        assert_eq!(inspect_calls(&temporary), 0);
        assert_eq!(
            snapshot.components,
            components.map(|component| status_report::observe(component, None).unwrap())
        );
        assert!(snapshot.assistants.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_runtime_snapshot_refuses_records_that_are_not_distinct_known_components() {
        let inventory = Inventory {
            project_containers: vec!["c001".into(), "c002".into()],
            ..Inventory::default()
        };
        let admin = format!("{:0<64}|/shimpz-admin|admin|running|healthy|0\n", "c001");
        for second in [
            "/foreign|admin|running|healthy|0",
            "/shimpz-admin|admin|running|healthy|0",
            "shimpz-team|team|running|healthy|0",
            "/shimpz-team|admin|running|healthy|0",
        ] {
            let (_temporary, engine) =
                inspecting_docker(&format!("{admin}{:0<64}|{second}\n", "c002"));
            assert!(runtime_snapshot(&engine, &inventory).is_err(), "{second}");
        }
        // A container that vanished after the inventory leaves its batch unanswered.
        let (_temporary, engine) = inspecting_docker(&admin);
        assert!(runtime_snapshot(&engine, &inventory).is_err());
        let assistant = Inventory {
            dynamic_containers: vec!["a001".into()],
            ..Inventory::default()
        };
        let (_temporary, engine) = inspecting_docker(&format!("{:0<64}|running|-1\n", "a001"));
        assert!(runtime_snapshot(&engine, &assistant).is_err());
    }
}
