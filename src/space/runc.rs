//! The runc floor a Local Space host must meet before it runs third-party Assistant containers.
//!
//! runc 1.2.8, 1.3.3, and 1.4.0-rc.3 fix the November 2025 container escapes (CVE-2025-31133, CVE-2025-52565,
//! CVE-2025-52881; GHSA-cgrx-mc8f-2prm). The floor is per branch: one global minimum would admit the vulnerable
//! 1.3.0 through 1.3.2.

/// A final release ranks above every release candidate of the same version.
const FINAL: u64 = u64::MAX;

const REQUIREMENT: &str = "Docker's default runtime must be runc 1.2.8 or newer in the 1.2 line, 1.3.3 or newer in \
    the 1.3 line, or 1.4.0 or newer";

/// Admit the runc version Docker reports for its default runtime only when it carries the escape fixes. An absent
/// or unrecognized version is refused: Docker Engine and Docker Desktop both report the bundled runc version.
pub(super) fn require_patched(reported: &str) -> Result<(), String> {
    let reported = reported.trim();
    match patched(reported) {
        Some(true) => Ok(()),
        Some(false) => Err(format!(
            "runc {reported} is vulnerable to container escape (CVE-2025-31133, CVE-2025-52565, CVE-2025-52881); \
             {REQUIREMENT}; update Docker Engine or Docker Desktop, confirm the runc line of docker version, and \
             retry"
        )),
        None => Err(format!(
            "Docker did not report a recognizable runc version for its default runtime (found '{reported}'); \
             {REQUIREMENT}; set runc as the default runtime, confirm the runc line of docker version, and retry"
        )),
    }
}

fn patched(version: &str) -> Option<bool> {
    let rank = rank(version)?;
    let minimum = match (rank.0, rank.1) {
        (0, _) | (1, 0..=1) => return Some(false),
        (1, 2) => (1, 2, 8, FINAL),
        (1, 3) => (1, 3, 3, FINAL),
        (1, 4) => (1, 4, 0, 3),
        _ => return Some(true),
    };
    Some(rank >= minimum)
}

/// `major.minor.patch` with its release-candidate number, or `FINAL`. A `-rc` suffix (`-rc.3`, `-rc93`) marks a
/// candidate; `+` build metadata, `~` and `-<digit>` distribution packaging revisions describe the final release.
fn rank(version: &str) -> Option<(u64, u64, u64, u64)> {
    let split = version.find(['-', '+', '~']).unwrap_or(version.len());
    let (core, suffix) = version.split_at(split);
    let mut numbers = core.split('.').map(|value| {
        (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| value.parse::<u64>().ok())
            .flatten()
    });
    let (major, minor, patch) = (numbers.next()??, numbers.next()??, numbers.next()??);
    if numbers.next().is_some() {
        return None;
    }
    Some((major, minor, patch, candidate(suffix)?))
}

fn candidate(suffix: &str) -> Option<u64> {
    let Some(rest) = suffix.strip_prefix('-') else {
        return Some(FINAL);
    };
    if rest.starts_with(|character: char| character.is_ascii_digit()) {
        return Some(FINAL);
    }
    let number = rest.strip_prefix("rc")?;
    let number = number.strip_prefix('.').unwrap_or(number);
    let digits = number
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(number.len());
    number[..digits].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_only_the_patched_release_of_each_branch() {
        for version in [
            "1.2.8",
            "1.2.9",
            "1.3.3",
            "1.3.6",
            "1.4.0-rc.3",
            "1.4.0-rc.3+dev",
            "1.4.0",
            "1.4.1",
            "1.5.2",
            "2.0.0",
            "1.3.3-0ubuntu1~24.04.3",
            "1.2.8+ds1",
        ] {
            assert_eq!(require_patched(version), Ok(()), "{version}");
        }
    }

    #[test]
    fn refuses_every_vulnerable_release() {
        for version in [
            "1.3.0",
            "1.3.1",
            "1.3.2",
            "1.3.3-rc.1",
            "1.2.7",
            "1.2.0",
            "1.4.0-rc.1",
            "1.4.0-rc.2",
            "1.1.15+ds1",
            "1.1.12-0ubuntu3",
            "1.0.0-rc93",
            "0.9.9",
        ] {
            let refusal = require_patched(version).unwrap_err();
            assert!(refusal.contains("CVE-2025-31133"), "{version}");
            assert!(refusal.contains(version), "{version}");
        }
    }

    #[test]
    fn refuses_an_absent_or_unrecognized_version() {
        for version in [
            "",
            "\n",
            "1.3",
            "v1.3.3",
            "1.3.3.1",
            "1.3.x",
            "1.3.3-dev",
            "1.4.0-rc",
            "1.4.0-rc.",
        ] {
            let refusal = require_patched(version).unwrap_err();
            assert!(refusal.contains("recognizable runc version"), "{version:?}");
        }
    }
}
