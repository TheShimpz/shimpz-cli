//! Cheap scheduled release polling and activity deferral around the full reconciliation path.
//!
//! A scheduled run first asks the registry for the `stable` release index digest with one anonymous manifest
//! request, before any Docker work. An unchanged digest ends the run until the periodic full repair is due; a
//! changed digest, or a due repair, enters the unchanged full resolution, validation, apply, health, and rollback
//! path. The digest is only a hint: nothing is applied from it. Just before a scheduled update replaces the running
//! release, a bounded Team activity observation may defer it for a few minutes.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use ureq::Agent;

use super::paths::Paths;
use super::release::RELEASE_REPOSITORY;
use super::state::{self, Installed};

/// Full resolution and health repair still runs this often even when the release is unchanged.
const FULL_REPAIR_SECONDS: u64 = 30 * 60;
const BACKOFF_BASE_SECONDS: u64 = 2 * 60;
const BACKOFF_CAP_SECONDS: u64 = 30 * 60;
const RETRY_AFTER_CAP_SECONDS: u64 = 60 * 60;
/// Longest continuous wait for active Team work before a scheduled update applies anyway.
const BUSY_DEFER_SECONDS: u64 = 5 * 60;
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_POLL_STATE_BYTES: u64 = 1_024;
const MAX_STATUS_BYTES: u64 = 1_024;
const REGISTRY: &str = "https://ghcr.io";
const INDEX_MEDIA_TYPES: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json";
const CURRENT: &str = "No new Local release is available.";
const RETRY: &str = "The Local release check will retry later.";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct PollState {
    probe_failures: u32,
    probe_retry_at: u64,
    attempted_digest: String,
    attempted_at: u64,
    attempts: u32,
    retry_at: u64,
    deferred_digest: String,
    deferred_since: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Probe {
    Digest(String),
    Throttled { retry_after: Option<u64> },
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TeamActivity {
    Idle,
    Busy,
    Unknown,
}

/// The Team activity client prints exactly one closed word.
pub(crate) fn parse_team_activity(output: &[u8]) -> TeamActivity {
    match output {
        b"idle\n" => TeamActivity::Idle,
        b"busy\n" => TeamActivity::Busy,
        _ => TeamActivity::Unknown,
    }
}

/// Exponential backoff, honoring a bounded registry `Retry-After`.
fn backoff_seconds(failures: u32, retry_after: Option<u64>) -> u64 {
    let exponential = BACKOFF_BASE_SECONDS
        .saturating_mul(1 << failures.min(10))
        .min(BACKOFF_CAP_SECONDS);
    retry_after.map_or(exponential, |seconds| {
        exponential.max(seconds.min(RETRY_AFTER_CAP_SECONDS))
    })
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

pub(crate) fn release_digest(release_ref: &str) -> Option<&str> {
    release_ref
        .strip_prefix(RELEASE_REPOSITORY)
        .and_then(|rest| rest.strip_prefix('@'))
        .filter(|digest| valid_digest(digest))
}

/// Read one bounded private record owned by this user; anything else is treated as absent evidence.
fn read_private_record(path: &std::path::Path, limit: u64) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    let owned = metadata.is_file()
        && metadata.nlink() == 1
        && metadata.uid() == rustix::process::getuid().as_raw()
        && metadata.permissions().mode() & 0o777 == 0o600
        && metadata.len() <= limit;
    owned.then(|| fs::read_to_string(path).ok()).flatten()
}

/// Invalid, foreign, or impossible state resets to the default, which lets the probe and repair proceed.
fn read_state(paths: &Paths, now: u64) -> PollState {
    read_private_record(&paths.release_poll, MAX_POLL_STATE_BYTES)
        .and_then(|document| parse_state(&document, now))
        .unwrap_or_default()
}

fn parse_state(document: &str, now: u64) -> Option<PollState> {
    let value: Value = serde_json::from_str(document).ok()?;
    let object = value.as_object()?;
    if object.len() != 8 {
        return None;
    }
    let number = |key: &str| object.get(key).and_then(Value::as_u64);
    let digest = |key: &str| {
        object
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| value.is_empty() || valid_digest(value))
            .map(str::to_owned)
    };
    let parsed = PollState {
        probe_failures: u32::try_from(number("probe_failures")?).ok()?,
        probe_retry_at: number("probe_retry_at")?,
        attempted_digest: digest("attempted_digest")?,
        attempted_at: number("attempted_at")?,
        attempts: u32::try_from(number("attempts")?).ok()?,
        retry_at: number("retry_at")?,
        deferred_digest: digest("deferred_digest")?,
        deferred_since: number("deferred_since")?,
    };
    let plausible = parsed.attempted_at <= now
        && parsed.deferred_since <= now
        && parsed.probe_retry_at <= now.saturating_add(RETRY_AFTER_CAP_SECONDS)
        && parsed.retry_at <= now.saturating_add(BACKOFF_CAP_SECONDS);
    plausible.then_some(parsed)
}

fn write_state(paths: &Paths, value: &PollState) -> Result<(), String> {
    let document = serde_json::json!({
        "probe_failures": value.probe_failures,
        "probe_retry_at": value.probe_retry_at,
        "attempted_digest": value.attempted_digest,
        "attempted_at": value.attempted_at,
        "attempts": value.attempts,
        "retry_at": value.retry_at,
        "deferred_digest": value.deferred_digest,
        "deferred_since": value.deferred_since,
    })
    .to_string();
    state::write_private(&paths.release_poll, &document)
}

/// The time of the last successful full reconciliation of exactly the installed release, or `None` when the
/// evidence is missing, foreign, malformed, a rollback, or from the future.
fn last_repair(paths: &Paths, installed: &Installed, now: u64) -> Option<u64> {
    let document = read_private_record(&paths.status, MAX_STATUS_BYTES)?;
    let status = parse_status(&document)?;
    (status.reconciles(&installed.release_ref, installed.ordinal) && status.checked_at <= now)
        .then_some(status.checked_at)
}

struct Status {
    release: String,
    ordinal: u64,
    checked_at: u64,
    outcome: String,
}

impl Status {
    fn reconciles(&self, release_ref: &str, ordinal: u64) -> bool {
        self.release == release_ref
            && self.ordinal == ordinal
            && matches!(self.outcome.as_str(), "current" | "updated")
    }
}

fn parse_status(document: &str) -> Option<Status> {
    let value: Value = serde_json::from_str(document).ok()?;
    let object = value.as_object()?;
    let outcome = object.get("outcome")?.as_str()?;
    if object.len() != 4 || !matches!(outcome, "current" | "updated" | "rollback-needed") {
        return None;
    }
    let release = object.get("release")?.as_str()?;
    let ordinal = object.get("ordinal")?.as_u64()?;
    if !super::release::valid_release_ref(release) || ordinal == 0 {
        return None;
    }
    Some(Status {
        release: release.to_owned(),
        ordinal,
        checked_at: object.get("checked_at")?.as_u64()?,
        outcome: outcome.to_owned(),
    })
}

/// What the Local release status proves about one exact release.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum StatusRecord {
    /// A successful full reconciliation of exactly that release; a committed apply writes this record last.
    Reconciled,
    /// No record, or a valid record of another release or of a rollback: that release never committed after it.
    Other,
    /// The record exists but cannot be trusted, so it proves nothing either way.
    Unknown(&'static str),
}

/// Classify the status record for exactly `release_ref` at `ordinal`, independent of the clock.
pub(crate) fn status_record(paths: &Paths, release_ref: &str, ordinal: u64) -> StatusRecord {
    let metadata = match fs::symlink_metadata(&paths.status) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return StatusRecord::Other,
        Err(_) => {
            return StatusRecord::Unknown("the Local release status could not be inspected");
        }
    };
    let private = metadata.is_file()
        && metadata.nlink() == 1
        && metadata.uid() == rustix::process::getuid().as_raw()
        && metadata.permissions().mode() & 0o777 == 0o600
        && metadata.len() <= MAX_STATUS_BYTES;
    if !private {
        return StatusRecord::Unknown("the Local release status is not a private record");
    }
    let Ok(document) = fs::read_to_string(&paths.status) else {
        return StatusRecord::Unknown("the Local release status could not be read");
    };
    match parse_status(&document) {
        Some(status) if status.reconciles(release_ref, ordinal) => StatusRecord::Reconciled,
        Some(status) if status.release == release_ref && status.ordinal != ordinal => {
            StatusRecord::Unknown("the Local release status contradicts the release ordinal")
        }
        Some(_) => StatusRecord::Other,
        None => StatusRecord::Unknown("the Local release status is malformed"),
    }
}

/// Scheduled gate before any Docker work. Returns a message when the run may end here, or `None` when the full
/// reconciliation path must run. Registry backoff postpones the full path too, because that path resolves the
/// release through the same registry.
pub(crate) fn scheduled_gate(
    paths: &Paths,
    installed: &Installed,
    now: u64,
    probe: impl FnOnce() -> Probe,
) -> Result<Option<&'static str>, String> {
    let Some(installed_digest) = release_digest(&installed.release_ref) else {
        return Ok(None);
    };
    let mut state = read_state(paths, now);
    if now < state.probe_retry_at {
        return Ok(Some(RETRY));
    }
    let digest = match probe() {
        Probe::Digest(digest) => digest,
        Probe::Throttled { retry_after } => {
            state.probe_retry_at =
                now.saturating_add(backoff_seconds(state.probe_failures, retry_after));
            state.probe_failures = state.probe_failures.saturating_add(1);
            write_state(paths, &state)?;
            return Ok(Some(RETRY));
        }
        Probe::Unavailable => {
            state.probe_retry_at = now.saturating_add(backoff_seconds(state.probe_failures, None));
            state.probe_failures = state.probe_failures.saturating_add(1);
            write_state(paths, &state)?;
            return Ok(Some(RETRY));
        }
    };
    state.probe_failures = 0;
    state.probe_retry_at = 0;
    let repaired = last_repair(paths, installed, now);
    if repaired.is_some_and(|at| at >= state.attempted_at) {
        state.attempts = 0;
        state.retry_at = 0;
    }
    let repair_due = repaired.is_none_or(|at| now - at >= FULL_REPAIR_SECONDS);
    let message = if digest == installed_digest && !repair_due {
        Some(CURRENT)
    } else if digest == state.attempted_digest && now < state.retry_at {
        Some(RETRY)
    } else {
        if digest != state.attempted_digest {
            state.attempts = 0;
        }
        state.retry_at = now.saturating_add(backoff_seconds(state.attempts, None));
        state.attempts = state.attempts.saturating_add(1);
        state.attempted_digest = digest;
        state.attempted_at = now;
        None
    };
    write_state(paths, &state)?;
    Ok(message)
}

/// Decide, before a scheduled update replaces the running graph, whether active Team work defers it. Busy work
/// waits at most `BUSY_DEFER_SECONDS` per continuous deferral of one digest; a deferral retries at the next poll
/// instead of backing off. Unobservable activity applies at once: an unavailable or older Team, which cannot report
/// activity, must never hold back the update that repairs it.
pub(crate) fn defer_for_activity(
    paths: &Paths,
    digest: &str,
    now: u64,
    observe: impl FnOnce() -> TeamActivity,
) -> Result<bool, String> {
    let mut state = read_state(paths, now);
    let since = if state.deferred_digest == digest {
        state.deferred_since
    } else {
        now
    };
    let limit = match observe() {
        TeamActivity::Busy => BUSY_DEFER_SECONDS,
        TeamActivity::Idle | TeamActivity::Unknown => 0,
    };
    let defer = now - since < limit;
    if defer {
        state.deferred_digest = digest.into();
        state.deferred_since = since;
        if state.attempted_digest == digest {
            state.attempts = 0;
            state.retry_at = 0;
        }
    } else {
        state.deferred_digest.clear();
        state.deferred_since = 0;
    }
    write_state(paths, &state)?;
    Ok(defer)
}

/// Whether the last scheduled attempt for `digest` ended in an activity deferral.
pub(crate) fn deferred(paths: &Paths, digest: &str, now: u64) -> bool {
    read_state(paths, now).deferred_digest == digest
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// One anonymous token request plus one manifest HEAD for the public `stable` release index.
pub(crate) fn probe_stable() -> Probe {
    let agent = Agent::new_with_config(
        Agent::config_builder()
            .timeout_global(Some(PROBE_TIMEOUT))
            .max_redirects(0)
            .http_status_as_error(false)
            .build(),
    );
    let repository = RELEASE_REPOSITORY.trim_start_matches("ghcr.io/");
    let Ok(mut token_response) = agent
        .get(format!(
            "{REGISTRY}/token?scope=repository:{repository}:pull&service=ghcr.io"
        ))
        .call()
    else {
        return Probe::Unavailable;
    };
    if let Some(throttled) = throttled(token_response.status().as_u16(), token_response.headers()) {
        return throttled;
    }
    let Some(token) = token_response
        .body_mut()
        .with_config()
        .limit(8_192)
        .read_json::<Value>()
        .ok()
        .and_then(|body| body.get("token").and_then(Value::as_str).map(str::to_owned))
    else {
        return Probe::Unavailable;
    };
    let Ok(response) = agent
        .head(format!("{REGISTRY}/v2/{repository}/manifests/stable"))
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", INDEX_MEDIA_TYPES)
        .call()
    else {
        return Probe::Unavailable;
    };
    if let Some(throttled) = throttled(response.status().as_u16(), response.headers()) {
        return throttled;
    }
    match response
        .headers()
        .get("docker-content-digest")
        .and_then(|value| value.to_str().ok())
    {
        Some(digest) if response.status().as_u16() == 200 && valid_digest(digest) => {
            Probe::Digest(digest.into())
        }
        _ => Probe::Unavailable,
    }
}

fn throttled(status: u16, headers: &ureq::http::HeaderMap) -> Option<Probe> {
    if status == 429 || status == 503 {
        let retry_after = headers
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| retry_after_seconds(value, now()));
        return Some(Probe::Throttled { retry_after });
    }
    None
}

/// `Retry-After` as delay-seconds or an IMF-fixdate (RFC 9110 section 10.2.3).
fn retry_after_seconds(value: &str, now: u64) -> Option<u64> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(seconds);
    }
    imf_fixdate(value).map(|at| at.saturating_sub(now))
}

fn imf_fixdate(value: &str) -> Option<u64> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let fields: Vec<&str> = value.split(' ').collect();
    let [weekday, day, month, year, time, "GMT"] = fields.as_slice() else {
        return None;
    };
    let (hour, minute, second) = match time.split(':').collect::<Vec<_>>().as_slice() {
        [hour, minute, second] if [hour, minute, second].iter().all(|part| part.len() == 2) => (
            hour.parse::<u64>().ok()?,
            minute.parse::<u64>().ok()?,
            second.parse::<u64>().ok()?,
        ),
        _ => return None,
    };
    let day = day.parse::<u64>().ok().filter(|_| day.len() == 2)?;
    let month = MONTHS.iter().position(|name| name == month)? as u64 + 1;
    let year = year.parse::<u64>().ok().filter(|_| year.len() == 4)?;
    if weekday.len() != 4
        || !weekday.ends_with(',')
        || !(1..=31).contains(&day)
        || year < 1970
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm), valid for every year from 1970.
    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = shifted_year / 400;
    let year_of_era = shifted_year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = (era * 146_097 + day_of_era).checked_sub(719_468)?;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSTALLED: &str =
        "sha256:9ef8a1563853dc6e403552a32ad7a82506acb233c11bc439ba678c6bb94171fe";
    const NEWER: &str = "sha256:018032c574c269e4baef8b2f3f7c441e621f3ec14485977c1fa25d4f1a93c44b";

    fn digest(value: &str) -> Probe {
        Probe::Digest(value.into())
    }

    fn gate_paths() -> (tempfile::TempDir, Paths) {
        let directory = tempfile::tempdir().expect("temporary home");
        fs::create_dir_all(directory.path().join(".shimpz")).expect("space home");
        let paths = Paths::under(directory.path()).expect("paths");
        (directory, paths)
    }

    fn installed() -> Installed {
        Installed {
            space_id: "space".into(),
            release_ref: format!("{RELEASE_REPOSITORY}@{INSTALLED}"),
            admin_image: "admin".into(),
            ordinal: 7,
            port: 7777,
        }
    }

    fn status(release: &str, ordinal: u64, checked_at: u64, outcome: &str) -> String {
        serde_json::json!({
            "release": release, "ordinal": ordinal, "checked_at": checked_at, "outcome": outcome
        })
        .to_string()
    }

    fn record_repair(paths: &Paths, checked_at: u64) {
        let installed = installed();
        state::write_private(
            &paths.status,
            &status(
                &installed.release_ref,
                installed.ordinal,
                checked_at,
                "current",
            ),
        )
        .expect("status");
    }

    fn gate(paths: &Paths, now: u64, probe: Probe) -> Option<&'static str> {
        scheduled_gate(paths, &installed(), now, || probe).expect("gate")
    }

    #[test]
    fn an_unchanged_release_ends_the_run_until_the_repair_is_due() {
        let (_home, paths) = gate_paths();
        record_repair(&paths, 1_000);
        assert_eq!(gate(&paths, 1_060, digest(INSTALLED)), Some(CURRENT));
        assert_eq!(
            gate(&paths, 1_000 + FULL_REPAIR_SECONDS, digest(INSTALLED)),
            None
        );
    }

    #[test]
    fn a_new_release_reconciles_and_a_failed_attempt_backs_off_without_claiming_currency() {
        let (_home, paths) = gate_paths();
        record_repair(&paths, 1_000);
        assert_eq!(gate(&paths, 1_060, digest(NEWER)), None);
        assert_eq!(gate(&paths, 1_120, digest(NEWER)), Some(RETRY));
        assert_eq!(
            gate(&paths, 1_060 + BACKOFF_BASE_SECONDS, digest(NEWER)),
            None
        );
        let state = read_state(&paths, 1_300);
        assert_eq!(
            (state.attempted_digest.as_str(), state.attempts),
            (NEWER, 2)
        );
        assert_eq!(state.retry_at, 1_180 + 2 * BACKOFF_BASE_SECONDS);
    }

    #[test]
    fn a_successful_reconciliation_clears_the_attempt_backoff() {
        let (_home, paths) = gate_paths();
        record_repair(&paths, 1_000);
        assert_eq!(gate(&paths, 1_060, digest(INSTALLED)), Some(CURRENT));
        let due = 1_000 + FULL_REPAIR_SECONDS;
        assert_eq!(gate(&paths, due, digest(INSTALLED)), None);
        record_repair(&paths, due + 30);
        let later = due + 30 + FULL_REPAIR_SECONDS;
        assert_eq!(gate(&paths, later, digest(INSTALLED)), None);
        assert_eq!(read_state(&paths, later).attempts, 1);
    }

    #[test]
    fn a_failed_repair_retries_with_backoff_instead_of_every_poll() {
        let (_home, paths) = gate_paths();
        assert_eq!(gate(&paths, 5_000, digest(INSTALLED)), None);
        assert_eq!(gate(&paths, 5_100, digest(INSTALLED)), Some(RETRY));
        assert_eq!(
            gate(&paths, 5_000 + BACKOFF_BASE_SECONDS, digest(INSTALLED)),
            None
        );
    }

    #[test]
    fn only_complete_successful_evidence_for_the_installed_release_counts_as_a_repair() {
        let (_home, paths) = gate_paths();
        let installed = installed();
        for (document, mode) in [
            (
                serde_json::json!({ "checked_at": 1_000 }).to_string(),
                0o600,
            ),
            (
                status(&installed.release_ref, 7, 1_000, "rollback-needed"),
                0o600,
            ),
            (
                status(
                    &format!("{RELEASE_REPOSITORY}@{NEWER}"),
                    7,
                    1_000,
                    "current",
                ),
                0o600,
            ),
            (status(&installed.release_ref, 8, 1_000, "current"), 0o600),
            (status(&installed.release_ref, 7, 9_999, "current"), 0o600),
            (status(&installed.release_ref, 7, 1_000, "current"), 0o644),
        ] {
            state::write_private(&paths.status, &document).expect("status");
            fs::set_permissions(&paths.status, fs::Permissions::from_mode(mode)).expect("mode");
            assert_eq!(
                last_repair(&paths, &installed, 1_060),
                None,
                "{document} {mode:o}"
            );
        }
        record_repair(&paths, 1_000);
        assert_eq!(last_repair(&paths, &installed, 1_060), Some(1_000));
    }

    #[test]
    fn registry_backoff_postpones_the_probe_and_the_repair() {
        let (_home, paths) = gate_paths();
        let throttled = Probe::Throttled {
            retry_after: Some(600),
        };
        assert_eq!(gate(&paths, 5_000, throttled), Some(RETRY));
        let quiet = scheduled_gate(&paths, &installed(), 5_300, || {
            panic!("no probe during backoff")
        });
        assert_eq!(quiet.expect("gate"), Some(RETRY));
        assert_eq!(gate(&paths, 5_600, Probe::Unavailable), Some(RETRY));
        assert_eq!(read_state(&paths, 5_600).probe_failures, 2);
        assert_eq!(
            gate(&paths, 5_600 + 2 * BACKOFF_BASE_SECONDS, digest(INSTALLED)),
            None
        );
        assert_eq!(read_state(&paths, 6_000).probe_failures, 0);
    }

    #[test]
    fn backoff_grows_to_a_cap_and_honors_a_bounded_retry_after() {
        assert_eq!(backoff_seconds(0, None), BACKOFF_BASE_SECONDS);
        assert_eq!(backoff_seconds(1, None), 2 * BACKOFF_BASE_SECONDS);
        assert_eq!(backoff_seconds(30, None), BACKOFF_CAP_SECONDS);
        assert_eq!(backoff_seconds(0, Some(900)), 900);
        assert_eq!(backoff_seconds(0, Some(10)), BACKOFF_BASE_SECONDS);
        assert_eq!(backoff_seconds(0, Some(u64::MAX)), RETRY_AFTER_CAP_SECONDS);
    }

    #[test]
    fn retry_after_accepts_seconds_and_http_dates() {
        let at = 784_111_777;
        assert_eq!(retry_after_seconds("120", at), Some(120));
        assert_eq!(imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT"), Some(at));
        assert_eq!(
            retry_after_seconds("Sun, 06 Nov 1994 08:51:37 GMT", at),
            Some(120)
        );
        assert_eq!(
            retry_after_seconds("Sun, 06 Nov 1994 08:49:37 GMT", at + 5),
            Some(0)
        );
        for invalid in [
            "",
            "-1",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "Sun, 32 Nov 1994 08:49:37 GMT",
        ] {
            assert_eq!(retry_after_seconds(invalid, at), None, "{invalid}");
        }
    }

    #[test]
    fn only_exact_release_digests_are_accepted() {
        assert!(valid_digest(INSTALLED));
        for invalid in [
            "",
            "sha256:",
            "sha512:abc",
            &INSTALLED.to_uppercase(),
            &format!("{INSTALLED}0"),
        ] {
            assert!(!valid_digest(invalid), "{invalid}");
        }
        assert_eq!(
            release_digest(&format!("{RELEASE_REPOSITORY}@{INSTALLED}")),
            Some(INSTALLED)
        );
        assert_eq!(
            release_digest(&format!("ghcr.io/other/release@{INSTALLED}")),
            None
        );
        let (_home, paths) = gate_paths();
        let mut foreign = installed();
        foreign.release_ref = "not-a-release".into();
        assert_eq!(
            scheduled_gate(&paths, &foreign, 5_000, || panic!("no probe")).expect("gate"),
            None
        );
    }

    #[test]
    fn busy_work_defers_an_update_for_a_bounded_time_per_digest() {
        let (_home, paths) = gate_paths();
        assert_eq!(gate(&paths, 5_000, digest(NEWER)), None);
        assert!(defer_for_activity(&paths, NEWER, 5_010, || TeamActivity::Busy).expect("defer"));
        assert!(deferred(&paths, NEWER, 5_010));
        assert_eq!(read_state(&paths, 5_010).retry_at, 0);
        assert_eq!(gate(&paths, 5_130, digest(NEWER)), None);
        assert!(defer_for_activity(&paths, NEWER, 5_140, || TeamActivity::Busy).expect("defer"));
        assert!(
            !defer_for_activity(&paths, NEWER, 5_010 + BUSY_DEFER_SECONDS, || {
                TeamActivity::Busy
            })
            .expect("apply")
        );
        assert!(!deferred(&paths, NEWER, 5_400));
    }

    #[test]
    fn idle_or_unobservable_activity_applies_immediately_and_clears_a_deferral() {
        let (_home, paths) = gate_paths();
        assert!(!defer_for_activity(&paths, NEWER, 5_000, || TeamActivity::Idle).expect("apply"));
        assert!(defer_for_activity(&paths, NEWER, 5_000, || TeamActivity::Busy).expect("defer"));
        assert!(
            !defer_for_activity(&paths, NEWER, 5_060, || TeamActivity::Unknown).expect("apply")
        );
        assert!(!deferred(&paths, NEWER, 5_060));
        assert!(
            defer_for_activity(&paths, INSTALLED, 5_200, || TeamActivity::Busy).expect("defer")
        );
        assert!(
            defer_for_activity(&paths, NEWER, 5_260, || TeamActivity::Busy).expect("new digest")
        );
    }

    #[test]
    fn team_activity_output_is_a_closed_word() {
        assert_eq!(parse_team_activity(b"idle\n"), TeamActivity::Idle);
        assert_eq!(parse_team_activity(b"busy\n"), TeamActivity::Busy);
        for other in [&b""[..], b"idle", b"busy\nidle\n", b"IDLE\n", b"error\n"] {
            assert_eq!(parse_team_activity(other), TeamActivity::Unknown);
        }
    }

    #[test]
    #[ignore = "reads the public GHCR release channel"]
    fn live_probe_reads_the_public_stable_release_digest() {
        match probe_stable() {
            Probe::Digest(value) => assert!(valid_digest(&value)),
            other => panic!("unexpected live probe outcome: {other:?}"),
        }
    }

    #[test]
    fn poll_state_round_trips_and_rejects_malformed_or_future_documents() {
        let (_home, paths) = gate_paths();
        let state = PollState {
            probe_failures: 1,
            probe_retry_at: 900,
            attempted_digest: NEWER.into(),
            attempted_at: 5,
            attempts: 2,
            retry_at: 700,
            deferred_digest: String::new(),
            deferred_since: 0,
        };
        write_state(&paths, &state).expect("write");
        assert_eq!(read_state(&paths, 600), state);
        assert_eq!(read_state(&paths, 4), PollState::default());
        let document = fs::read_to_string(&paths.release_poll).expect("state");
        for invalid in [
            "{}".to_owned(),
            document.replace(NEWER, "sha256:x"),
            document.replace("\"attempts\":2", "\"attempts\":2,\"extra\":1"),
            document.replace(
                "\"retry_at\":700",
                &format!("\"retry_at\":{}", 600 + BACKOFF_CAP_SECONDS + 1),
            ),
            "not json".to_owned(),
        ] {
            assert_eq!(parse_state(&invalid, 600), None, "{invalid}");
        }
    }
}
