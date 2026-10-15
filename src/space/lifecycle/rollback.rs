//! Restoring the previous release after a failed apply, and compensating a failed fresh install.

use std::fs;
use std::path::PathBuf;

use crate::output;
use crate::space::docker::{COMPOSE_UP, ProjectionFailure, ResolvedRelease};
use crate::space::host::HostProfile;
use crate::space::paths::Paths;
use crate::space::resources::Inventory;
use crate::space::storage::linux;
use crate::space::{graph, members, scheduler, state};

use super::{Context, io_error, remove_runtime_files};

impl Context {
    pub(super) fn rollback(
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
            Ok(_) => match self.start_previous(installed.port) {
                Ok(started) => started,
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

    /// Bring the restored previous release up and prove its running members attached as declared, with Admin
    /// published on `port`. `Ok(false)` is a start Compose already reported as failed.
    fn start_previous(&self, port: u16) -> Result<bool, String> {
        if !self.engine.compose(&self.paths, COMPOSE_UP)?.success() {
            return Ok(false);
        }
        members::converge(&self.engine, &self.paths, port)?;
        Ok(true)
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

    pub(super) fn compensate_fresh_failure(&self, space_id: &str) -> Result<(), String> {
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
}

#[derive(Debug)]
pub(super) struct Backup {
    pub(super) compose: PathBuf,
    pub(super) environment: PathBuf,
}

pub(super) fn backup_current(paths: &Paths, profile: HostProfile) -> Result<Backup, String> {
    let compose = paths.compose.with_extension("previous");
    let environment = paths.environment.with_extension("previous");
    state::write_private(&compose, &graph::render(profile.storage()))?;
    fs::copy(&paths.environment, &environment).map_err(io_error)?;
    Ok(Backup {
        compose,
        environment,
    })
}

pub(super) fn remove_backup(backup: Option<Backup>) -> Result<(), String> {
    if let Some(backup) = backup {
        fs::remove_file(backup.compose).map_err(io_error)?;
        fs::remove_file(backup.environment).map_err(io_error)?;
    }
    Ok(())
}
