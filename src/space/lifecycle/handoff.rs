//! The handoff to the CLI bound to a selected release, and how its commit evidence decides which CLI is kept.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::space::docker::ResolvedRelease;
use crate::space::poll;
use crate::space::state::{self, Installed};

use super::cli_binary::{
    CommitEvidence, commit_evidence, ensure_public_cli, expected_cli_hash, handoff_failure,
    hash_file, reconcile_previous_cli, restore_previous_cli, validate_private_cli,
};
use super::outcome::{UPDATE_DEFERRED, recreation_notice};
use super::{Context, io_error, remove_regular_if_present, validate_forward_release};

impl Context {
    /// Report a release-bound CLI run truthfully: it may have deferred the update or left it unapplied.
    pub(super) fn handoff_outcome(&self, release: &ResolvedRelease) -> Result<String, String> {
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

    pub(super) fn handoff_if_needed(
        &self,
        release: &ResolvedRelease,
        installed: Option<&Installed>,
        scheduled: bool,
    ) -> Result<bool, String> {
        admit_before_handoff(release, installed, || {
            self.handoff_admitted_release(release, scheduled)
        })
    }

    pub(super) fn handoff_admitted_release(
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
    pub(super) fn with_recreation(&self, error: String) -> String {
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
}

pub(super) fn admit_before_handoff<T>(
    release: &ResolvedRelease,
    installed: Option<&Installed>,
    handoff: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    validate_forward_release(release, installed)?;
    handoff()
}
