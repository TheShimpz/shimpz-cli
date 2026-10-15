//! Space reset, hard reset, and corrupt-Space recovery, with the owned runtime files they remove.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use crate::output;
use crate::space::docker::COMPOSE_UP;
use crate::space::host::HostProfile;
use crate::space::paths::Paths;
use crate::space::resources::Inventory;
use crate::space::status as status_report;
use crate::space::storage::linux;
use crate::space::{graph, members, scheduler, state};

use super::admin::{AdminAttestation, admin_available, admin_reset};
use super::cli_binary::validate_private_cli;
use super::outcome::{
    hard_reset_incomplete, hard_reset_outcome, hard_reset_preflight, reset_outcome,
};
use super::{
    Context, PathReport, installed_graph_is_current, io_error, remove_regular_if_present,
    runtime_snapshot, validate_regular_if_present,
};

impl Context {
    pub(super) fn reset(&self) -> Result<String, String> {
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

    pub(super) fn hard_reset(&self) -> Result<String, String> {
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
            linux::reset(&self.paths, inventory.space_id.as_deref())
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

    pub(super) fn restore_stopped_after_reset_failure(&self) -> Result<(), String> {
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

    pub(super) fn recover_corrupt(
        &self,
        inventory: &Inventory,
        reason: &str,
    ) -> Result<(), String> {
        self.recover_corrupt_after(inventory, reason, |names| {
            recovery_prompt(reason, inventory, names)
        })
    }

    /// Recover only after an affirmative answer: Team and Admin start for a bounded reset only once confirmed.
    pub(super) fn recover_corrupt_after(
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
        let admin = self.prepare_admin_for_recovery(inventory)?;
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

    pub(super) fn start_admin_for_reset(&self) -> Result<(), String> {
        if state::stopped(&self.paths)? {
            output::progress("Starting the Shimpz Space for reset authorization...");
            let started = self.engine.compose(&self.paths, COMPOSE_UP)?;
            if !started.success() {
                return Err("the stopped Space could not start for reset authorization".into());
            }
        }
        self.start_container_if_present(graph::TEAM.container)?;
        if self.admin_attestation()? == AdminAttestation::Stopped {
            let status = self.engine.run_quiet_status(
                "Docker Admin container start",
                ["start", graph::ADMIN.container],
            )?;
            if !status.success() {
                return Err("the owned Admin container could not be started".into());
            }
        }
        let expected = state::read_installed(&self.paths, self.profile)?.port;
        // The graph is current here, so a member Docker started detached is recreated before Admin is attested.
        members::converge(&self.engine, &self.paths, expected)?;
        let attestation = self.admin_attestation()?;
        if attestation == (AdminAttestation::Running { port: expected })
            && admin_available(expected)
        {
            return Ok(());
        }
        Err("the Local Supervisor is unavailable; run shimpz install for bounded recovery".into())
    }

    pub(super) fn prepare_admin_for_recovery(
        &self,
        inventory: &Inventory,
    ) -> Result<AdminAttestation, String> {
        let mut attestation = self.admin_attestation()?;
        if attestation == AdminAttestation::Absent {
            return Ok(attestation);
        }
        if self
            .start_container_if_present(graph::TEAM.container)
            .is_err()
        {
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
                    ["start", graph::ADMIN.container],
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
        // The graph of a corrupt Space is untrusted, so a member Docker started detached is only reported: recovery
        // then uses owned-resource cleanup instead of an Admin it cannot reach as declared.
        if let AdminAttestation::Running { port } = attestation
            && !members::detached_services(&self.engine, &inventory.project_containers, port)?
                .is_empty()
        {
            output::info(
                "Admin could not be started; confirmed recovery will use owned-resource cleanup.",
            );
            return Ok(AdminAttestation::Stopped);
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

pub(super) fn remove_runtime_files(paths: &Paths) -> Result<(), String> {
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

pub(super) fn preflight_remove_files(
    paths: &Paths,
    protected_storage: bool,
) -> Result<Vec<String>, String> {
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

pub(super) fn record_retained_bin_entries(
    paths: &Paths,
    preserved: &mut PathReport,
) -> Result<(), String> {
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

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use crate::space::scheduler;

    use super::{corrupt_recovery_scheduler, hard_reset_confirmation};

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
}
