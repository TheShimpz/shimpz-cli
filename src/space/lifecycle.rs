//! Native install, reconcile, status, and reset orchestration.

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
use super::paths::Paths;
use super::resources::Inventory;
use super::scheduler;
use super::state::{self, Environment, Installed, Lock};
use super::storage::evidence::HostProfile;
use super::storage::{linux, managed};

const ADMIN_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-admin";
const TEAM_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-team-local";
const BRAIN_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-brain";
const EGRESS_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-egress";

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
        return Ok("Shimpz Space is not installed. Nothing needs attention.".into());
    }
    let profile = managed::detect()?;
    let engine = Engine::connect(profile, &paths)?;
    let installed = state::read_installed(&paths, profile)?;
    Inventory::inspect(&engine, &paths, profile.storage())?;
    let runtime = engine.run_output([
        "compose",
        "--project-directory",
        &paths.home.to_string_lossy(),
        "--env-file",
        &paths.environment.to_string_lossy(),
        "--file",
        &paths.compose.to_string_lossy(),
        "ps",
        "--format",
        "json",
    ])?;
    if runtime.len() > 32 * 1024 {
        return Err("Docker returned an oversized Local status".into());
    }
    Ok(format!(
        "Shimpz Space {}\nRelease {} (ordinal {})\nAdmin http://127.0.0.1:{}\n{}",
        installed.space_id,
        installed.release_ref,
        installed.ordinal,
        installed.port,
        runtime.trim()
    ))
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

impl Context {
    fn open(scheduled: bool) -> Result<Self, String> {
        let paths = Paths::discover()?;
        ensure_install_home(&paths)?;
        let profile = managed::detect()?;
        let engine = Engine::connect(profile, &paths)?;
        scheduler::validate(profile, &paths)?;
        Ok(Self {
            paths,
            profile,
            engine,
            scheduled,
        })
    }

    fn install(&self, exact_release: Option<&str>) -> Result<String, String> {
        let marker = self.paths.marker_is_current()?;
        let inventory = Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?;
        let installed = if marker {
            match self.current_installation() {
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
        self.apply(&release, installed.as_ref(), false)
    }

    fn start(&self, options: &SpaceStart) -> Result<String, String> {
        if !self.paths.marker_is_current()? {
            return Err("Shimpz Space is not installed; run shimpz install".into());
        }
        let installed = self.current_installation()?;
        Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?;
        let release = self
            .engine
            .resolve_release(options.release.as_deref(), &self.paths.home)?;
        if options.release.is_none()
            && state::failed_release_matches(&self.paths, &release.reference)?
        {
            return Ok("The selected Local release previously failed health; the current Space remains unchanged.".into());
        }
        if options.release.is_none() && self.handoff_if_needed(&release, options.scheduled)? {
            return Ok("The release-bound CLI completed reconciliation.".into());
        }
        if options.candidate && options.release.is_none() {
            return Err("a candidate start requires an exact release".into());
        }
        self.apply(&release, Some(&installed), options.scheduled)
    }

    fn apply(
        &self,
        release: &ResolvedRelease,
        installed: Option<&Installed>,
        scheduled: bool,
    ) -> Result<String, String> {
        validate_forward_release(release, installed)?;
        verify_running_cli(release, self.profile)?;
        output::progress("Pulling the release-pinned Space images...");
        self.engine
            .pull_exact(&release.metadata.admin, ADMIN_REPOSITORY)?;
        self.engine
            .pull_exact(&release.metadata.team, TEAM_REPOSITORY)?;
        self.engine
            .pull_exact(&release.metadata.brain, BRAIN_REPOSITORY)?;
        self.engine
            .pull_exact(&release.metadata.egress, EGRESS_REPOSITORY)?;
        let space_id = match installed {
            Some(installed) => installed.space_id.clone(),
            None => state::random_space_id()?,
        };
        match self.ensure_storage(&space_id, installed.is_none(), scheduled)? {
            linux::Admission::Locked => {
                return Ok("Encrypted Local storage is locked. No workloads were started.".into());
            }
            linux::Admission::Verified => {}
        }
        let port = state::selected_port(installed)?;
        let (docker_socket, docker_gid) = self
            .engine
            .controller_socket(self.profile, &release.metadata.team)?;
        let previous = installed.map(|_| self.backup_current()).transpose()?;
        state::write_environment(
            &self.paths,
            &Environment {
                release,
                profile: self.profile,
                space_id: &space_id,
                port,
                docker_gid,
                docker_socket: &docker_socket,
                cpuset: &self.engine.cpuset,
                secure_root: &self.paths.pool_mount,
            },
        )?;
        state::write_private(&self.paths.compose, &graph::render(self.profile.storage()))?;
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
            return self.rollback(release, previous);
        }
        if let Err(storage_error) = self.validate_started_storage(&space_id) {
            let rollback = self.rollback(release, previous);
            return match rollback {
                Ok(outcome) | Err(outcome) => Err(format!("{storage_error}; {outcome}")),
            };
        }
        let status =
            state::write_status(&self.paths, release, release_outcome(release, installed))?;
        if self
            .engine
            .project_release_status(&release.metadata.admin, status.as_bytes())
            .is_err()
        {
            return self.rollback(release, previous);
        }
        remove_backup(previous)?;
        state::write_marker(&self.paths)?;
        scheduler::install(self.profile, &self.paths)?;
        remove_regular_if_present(&self.paths.failed_release)?;
        Ok(format!(
            "Shimpz Space is ready.\nAdmin http://127.0.0.1:{port}\nRelease {} (ordinal {})",
            release.reference, release.metadata.ordinal
        ))
    }

    fn reset(&self) -> Result<String, String> {
        let marker = self.paths.marker_is_current()?;
        let inventory = Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?;
        if self.profile != HostProfile::Linux && self.paths.security.exists() {
            return Err(
                "unexpected Local security content is outside the managed host profile".into(),
            );
        }
        if !marker && inventory.empty() && !self.paths.security.exists() {
            self.remove_files()?;
            return Ok("Shimpz Space was already reset. No managed data remains.".into());
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
        if !inventory.empty()
            && let Some(current) = &installed
        {
            self.start_admin_for_reset()?;
            authenticated_admin_reset(current.port)?;
        }
        let remaining = Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?;
        remaining.remove(&self.engine)?;
        if self.profile == HostProfile::Linux && self.paths.security.exists() {
            let space_id = installed
                .map(|current| current.space_id)
                .or(inventory.space_id);
            linux::reset(&self.paths, space_id.as_deref())?;
        }
        scheduler::remove(self.profile, &self.paths)?;
        let preserved = self.remove_files()?;
        let suffix = if preserved.is_empty() {
            "No managed Space data remains; the shimpz command is retained.".to_owned()
        } else {
            format!("Preserved unrecognized content: {}", preserved.join(", "))
        };
        Ok(format!("Shimpz Space was reset successfully. {suffix}"))
    }

    fn current_installation(&self) -> Result<Installed, String> {
        let installed = state::read_installed(&self.paths, self.profile)?;
        let expected = graph::render(self.profile.storage());
        let actual = fs::read_to_string(&self.paths.compose)
            .map_err(|error| format!("could not read the installed Local graph: {error}"))?;
        if actual != expected {
            return Err("the installed Local graph is not current".into());
        }
        Ok(installed)
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
        self.start_admin_if_present();
        let names = inventory.container_names(&self.engine)?;
        let confirmed = recovery_prompt(reason, inventory, &names)?;
        if !confirmed {
            return Err("the corrupt Local Space was preserved; nothing changed".into());
        }
        let admin_port = recovery_admin_port(&self.paths);
        let admin_is_live = admin_port.is_some_and(admin_available);
        if admin_is_live {
            authenticated_admin_reset(admin_port.expect("checked"))?;
        }
        scheduler::remove(self.profile, &self.paths)?;
        let space_id = inventory.space_id.clone();
        let remaining = if admin_is_live {
            Inventory::inspect(&self.engine, &self.paths, self.profile.storage())?
        } else {
            inventory.clone()
        };
        remaining.remove(&self.engine)?;
        if self.profile == HostProfile::Linux && self.paths.security.exists() {
            linux::reset(&self.paths, space_id.as_deref())?;
        }
        self.remove_runtime_files()?;
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
            HostProfile::MacOs | HostProfile::Wsl => {
                managed::verify(self.profile, &self.paths)?;
                Ok(linux::Admission::Verified)
            }
        }
    }

    fn handoff_if_needed(
        &self,
        release: &ResolvedRelease,
        scheduled: bool,
    ) -> Result<bool, String> {
        let expected = expected_cli_hash(release, self.profile);
        if hash_file(&std::env::current_exe().map_err(|_| "the running CLI path is unavailable")?)?
            == expected
        {
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
        if previous.exists() {
            return Err("a previous managed CLI compensation artifact remains".into());
        }
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

    fn backup_current(&self) -> Result<Backup, String> {
        let compose = self.paths.compose.with_extension("previous");
        let environment = self.paths.environment.with_extension("previous");
        fs::copy(&self.paths.compose, &compose).map_err(io_error)?;
        fs::copy(&self.paths.environment, &environment).map_err(io_error)?;
        Ok(Backup {
            compose,
            environment,
        })
    }

    fn rollback(
        &self,
        release: &ResolvedRelease,
        backup: Option<Backup>,
    ) -> Result<String, String> {
        let memory_error = state::remember_failed_release(&self.paths, release).err();
        let _ = self
            .engine
            .compose(&self.paths, ["down", "--remove-orphans"]);
        let Some(backup) = backup else {
            state::write_status(&self.paths, release, "rollback-needed")?;
            if memory_error.is_some() {
                return Err("the fresh Local release failed and could not be remembered".into());
            }
            return Err("the fresh Local release did not become healthy".into());
        };
        fs::rename(&backup.compose, &self.paths.compose).map_err(io_error)?;
        fs::rename(&backup.environment, &self.paths.environment).map_err(io_error)?;
        let installed = state::read_installed(&self.paths, self.profile)?;
        match self.ensure_storage(&installed.space_id, false, self.scheduled)? {
            linux::Admission::Verified => {}
            linux::Admission::Locked => {
                state::write_status(&self.paths, release, "rollback-needed")?;
                if memory_error.is_some() {
                    scheduler::remove(self.profile, &self.paths)?;
                    return Err(
                        "the previous release remained stopped because storage was locked, and automatic updates were disabled because the failed release could not be remembered"
                            .into(),
                    );
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
        state::write_status(&self.paths, release, "rollback-needed")?;
        if memory_error.is_some() {
            scheduler::remove(self.profile, &self.paths)?;
            return Err(
                "the previous release was restored, but automatic updates were disabled because the failed release could not be remembered"
                    .into(),
            );
        }
        if restored.success() {
            Err("the update failed; the previous healthy release was restored".into())
        } else {
            Err("the update and its rollback both failed".into())
        }
    }

    fn start_admin_for_reset(&self) -> Result<(), String> {
        self.start_admin_if_present();
        if admin_available(state::read_installed(&self.paths, self.profile)?.port) {
            Ok(())
        } else {
            Err(
                "the Local Supervisor is unavailable; run shimpz install for bounded recovery"
                    .into(),
            )
        }
    }

    fn start_admin_if_present(&self) {
        for name in ["shimpz-team", "shimpz-admin"] {
            if self
                .engine
                .run_output([
                    "inspect",
                    "--type=container",
                    "--format",
                    "{{.State.Running}}",
                    name,
                ])
                .is_ok_and(|value| value.trim() == "false")
            {
                let _ = self.engine.run_status(["start", name]);
            }
        }
    }

    fn remove_runtime_files(&self) -> Result<(), String> {
        for path in [
            &self.paths.compose,
            &self.paths.environment,
            &self.paths.marker,
            &self.paths.status,
            &self.paths.failed_release,
            &self.paths.compose.with_extension("previous"),
            &self.paths.environment.with_extension("previous"),
        ] {
            remove_regular_if_present(path)?;
        }
        Ok(())
    }

    fn remove_files(&self) -> Result<Vec<String>, String> {
        self.remove_runtime_files()?;
        remove_regular_if_present(&self.paths.managed_cli.with_extension("candidate"))?;
        remove_regular_if_present(&self.paths.managed_cli.with_extension("previous"))?;
        remove_regular_if_present(&self.paths.lock)?;
        let mut preserved = Vec::new();
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
                    preserved.push(path.display().to_string());
                }
            }
        }
        Ok(preserved)
    }
}

fn release_outcome(release: &ResolvedRelease, installed: Option<&Installed>) -> &'static str {
    if installed.is_some_and(|current| current.release_ref == release.reference) {
        "current"
    } else {
        "updated"
    }
}

#[derive(Debug)]
struct Backup {
    compose: PathBuf,
    environment: PathBuf,
}

fn ensure_install_home(paths: &Paths) -> Result<(), String> {
    if paths.home.exists() {
        let metadata = paths.home.symlink_metadata().map_err(io_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("refusing to use an invalid Local Space directory".into());
        }
        if !paths.marker.exists() {
            for entry in fs::read_dir(&paths.home).map_err(io_error)? {
                let path = entry.map_err(io_error)?.path();
                if path
                    != paths
                        .managed_cli
                        .parent()
                        .expect("managed CLI has a parent")
                {
                    return Err(format!(
                        "refusing to use existing unowned directory: {}",
                        paths.home.display()
                    ));
                }
            }
            validate_unmarked_bin(paths)?;
        }
    } else {
        fs::create_dir(&paths.home).map_err(io_error)?;
        fs::set_permissions(&paths.home, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    Ok(())
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
        return Err("the managed CLI directory is invalid".into());
    }
    for entry in fs::read_dir(bin).map_err(io_error)? {
        let path = entry.map_err(io_error)?.path();
        if path != paths.managed_cli
            && path != paths.managed_cli.with_extension("candidate")
            && path != paths.managed_cli.with_extension("previous")
        {
            return Err("the unmarked managed CLI directory contains unrecognized content".into());
        }
        let metadata = path.symlink_metadata().map_err(io_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("the managed CLI artifact is invalid".into());
        }
        if metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("the managed CLI artifact ownership or permissions are invalid".into());
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
        return Err("the managed CLI artifact ownership or permissions are invalid".into());
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

fn recovery_admin_port(paths: &Paths) -> Option<u16> {
    let Ok(document) = fs::read_to_string(&paths.environment) else {
        return None;
    };
    if document.len() > 8_192 || document.contains('\r') {
        return None;
    }
    let values: Vec<_> = document
        .lines()
        .filter_map(|line| line.strip_prefix("SHIMPZ_PORT="))
        .collect();
    if values.len() != 1 {
        return None;
    }
    values[0].parse::<u16>().ok().filter(|port| *port >= 1024)
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

fn authenticated_admin_reset(port: u16) -> Result<(), String> {
    let password = Zeroizing::new(
        rpassword::prompt_password("Supervisor password: ")
            .map_err(|_| "could not read the Supervisor password".to_owned())?,
    );
    if password.is_empty() {
        return Err("the Supervisor password is required".into());
    }
    let config = Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    let agent = Agent::new_with_config(config);
    let url = format!("http://127.0.0.1:{port}");
    let login = agent
        .post(format!("{url}/api/login"))
        .send_json(serde_json::json!({"password": password.as_str()}))
        .map_err(|_| "the Local Supervisor login is unavailable".to_owned())?;
    if login.status().as_u16() != 200 {
        return Err("the Supervisor password was rejected".into());
    }
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
        .map_err(|_| "the authenticated Space reset is unavailable".to_owned())?;
    if response.status().as_u16() != 200 {
        return Err("the authenticated Space reset did not complete".into());
    }
    let body: serde_json::Value = response
        .body_mut()
        .with_config()
        .limit(1_024)
        .read_json()
        .map_err(|_| "Admin returned an invalid Space reset response".to_owned())?;
    if body.as_object().is_some_and(|object| {
        object.len() == 1 && object.get("reset") == Some(&serde_json::Value::Bool(true))
    }) {
        Ok(())
    } else {
        Err("Admin returned an invalid Space reset response".into())
    }
}

fn remove_backup(backup: Option<Backup>) -> Result<(), String> {
    if let Some(backup) = backup {
        fs::remove_file(backup.compose).map_err(io_error)?;
        fs::remove_file(backup.environment).map_err(io_error)?;
    }
    Ok(())
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
    fn extracts_only_one_bounded_recovery_port() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        fs::write(&paths.environment, "SHIMPZ_PORT=7777\n").unwrap();
        assert_eq!(recovery_admin_port(&paths), Some(7777));
        fs::write(&paths.environment, "SHIMPZ_PORT=80\n").unwrap();
        assert_eq!(recovery_admin_port(&paths), None);
        fs::write(&paths.environment, "SHIMPZ_PORT=7777\nSHIMPZ_PORT=8888\n").unwrap();
        assert_eq!(recovery_admin_port(&paths), None);
    }

    #[test]
    fn unmarked_home_accepts_only_private_managed_cli_artifacts() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        fs::create_dir(paths.managed_cli.parent().unwrap()).unwrap();
        fs::write(paths.managed_cli.with_extension("candidate"), "candidate").unwrap();
        fs::set_permissions(
            paths.managed_cli.with_extension("candidate"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(ensure_install_home(&paths).is_ok());
        fs::write(
            paths.managed_cli.parent().unwrap().join("foreign"),
            "foreign",
        )
        .unwrap();
        assert!(ensure_install_home(&paths).is_err());
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
}
