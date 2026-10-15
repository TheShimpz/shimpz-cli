//! The bounded outcome messages lifecycle commands print.

use crate::space::docker::ResolvedRelease;
use crate::space::scheduler;
use crate::space::state::Installed;

pub(super) const SCHEDULED_STOPPED: &str = "Shimpz Space is stopped.\nNext: shimpz start";

pub(super) const UPDATE_DEFERRED: &str =
    "A Local update is waiting for active Shimpz work to finish; it will retry automatically.";

pub(super) const STORAGE_LOCKED: &str =
    "Encrypted Local storage is locked. No workloads were started.";

pub(super) fn release_outcome(
    release: &ResolvedRelease,
    installed: Option<&Installed>,
) -> &'static str {
    if installed.is_some_and(|current| current.release_ref == release.reference) {
        "current"
    } else {
        "updated"
    }
}

pub(super) fn recreation_notice(release: &ResolvedRelease) -> String {
    format!(
        "Recreated the Team runtime state for state epoch {}; its earlier records were removed.",
        release.metadata.state_epoch
    )
}

pub(super) fn ready_outcome(release: &ResolvedRelease, port: u16) -> String {
    format!(
        "Shimpz Space is ready.\nAdmin: http://127.0.0.1:{port}\nRelease: ordinal {}\nNext: open the Admin address above.",
        release.metadata.ordinal
    )
}

pub(super) fn current_release_outcome(installed: &Installed, stopped: bool) -> String {
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

pub(super) fn available_release_outcome(
    installed: &Installed,
    release: &ResolvedRelease,
) -> String {
    format!(
        "A newer Shimpz Space release is available.\nInstalled release: ordinal {}\nAvailable release: ordinal {}\nStopped intent was preserved.\nNext: shimpz start",
        installed.ordinal, release.metadata.ordinal
    )
}

pub(super) fn failed_update_outcome(stopped: bool) -> String {
    if stopped {
        "The selected Local release previously failed health.\nStopped intent was preserved.\nNext: shimpz start to resume the installed release."
            .into()
    } else {
        "The selected Local release previously failed health; the current Space remains unchanged.\nNext: wait for a different Local release selection."
            .into()
    }
}

pub(super) fn scheduler_outcome(
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

pub(super) fn reset_outcome(
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

pub(super) fn hard_reset_outcome(
    preserved: &[String],
    scheduler_execution_unverified: bool,
) -> String {
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

pub(super) fn hard_reset_incomplete(error: &str) -> String {
    format!(
        "{error}; hard reset did not complete and the Space may be stopped; re-run shimpz reset --hard"
    )
}

pub(super) fn hard_reset_preflight(error: &str) -> String {
    format!(
        "{error}; nothing changed; resolve the reported Local ownership or host prerequisite, then re-run shimpz reset --hard"
    )
}

pub(super) fn candidate_admission_error(error: &str) -> String {
    format!("{error}; the installed release is unchanged")
}
