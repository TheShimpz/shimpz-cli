//! In-place CLI upgrades from stable GitHub releases.

use std::path::Path;

use self_update::backends::github::Update;
use self_update::errors::Error;
use self_update::update::{Release, ReleaseUpdate};

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const ARCHIVE_BINARY_PATH: &str = "shimpz-{{ version }}-{{ target }}/{{ bin }}";

pub(crate) fn run() -> Result<String, String> {
    refuse_managed_space_cli()?;
    let latest = latest_release()?;
    if !newer_than_current(&latest.version)? {
        return Ok(format!("shimpz {CURRENT_VERSION} is already up to date."));
    }
    install(&latest)
}

fn refuse_managed_space_cli() -> Result<(), String> {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let current = std::env::current_exe().ok();
    if managed_space_verdict(cfg!(unix), home.as_deref(), current.as_deref())? {
        return Err(
            "this CLI is managed by Shimpz Space; run shimpz install to reconcile its atomic release"
                .into(),
        );
    }
    Ok(())
}

fn managed_space_verdict(
    unix: bool,
    home: Option<&Path>,
    current: Option<&Path>,
) -> Result<bool, String> {
    let Some(home) = home else {
        return if unix {
            Err("HOME is required to determine whether this CLI is managed".into())
        } else {
            Ok(false)
        };
    };
    if unix && !home.is_absolute() {
        return Err("HOME must be absolute to determine whether this CLI is managed".into());
    }
    let Some(current) = current else {
        return Ok(false);
    };
    Ok(is_managed_space_cli(home, current))
}

fn is_managed_space_cli(home: &Path, current: &Path) -> bool {
    let managed = home.join(".shimpz/bin/shimpz");
    let (Ok(current), Ok(managed)) = (current.canonicalize(), managed.canonicalize()) else {
        return false;
    };
    current == managed
}

fn latest_release() -> Result<Release, String> {
    updater(None)?
        .get_latest_release()
        .map_err(|error| github_error("CLI update check", &error))
}

fn github_error(context: &str, error: &Error) -> String {
    if matches!(error, Error::Ureq(ureq::Error::StatusCode(403))) {
        return "GitHub refused the CLI update request (HTTP 403). Retry later or download the standalone CLI from https://github.com/TheShimpz/shimpz-cli/releases/latest".into();
    }
    format!("{context} failed: {error}")
}

fn install(release: &Release) -> Result<String, String> {
    let tag = format!("v{}", release.version);
    let status = updater(Some(&tag))?
        .update()
        .map_err(|error| github_error("CLI update", &error))?;
    Ok(format!(
        "shimpz upgraded from {CURRENT_VERSION} to {}.",
        status.version()
    ))
}

fn newer_than_current(version: &str) -> Result<bool, String> {
    self_update::version::bump_is_greater(CURRENT_VERSION, version)
        .map_err(|_| "latest CLI release has an invalid version".into())
}

fn updater(target_version: Option<&str>) -> Result<Box<dyn ReleaseUpdate>, String> {
    let mut builder = Update::configure();
    builder
        .repo_owner("TheShimpz")
        .repo_name("shimpz-cli")
        .bin_name("shimpz")
        .bin_path_in_archive(ARCHIVE_BINARY_PATH)
        .current_version(CURRENT_VERSION)
        .show_download_progress(true)
        .show_output(false)
        .no_confirm(true);
    if let Some(version) = target_version {
        builder.target_version_tag(version);
    }
    builder
        .build()
        .map_err(|error| format!("CLI updater is unavailable: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_the_managed_cli_without_a_space_marker() {
        let home = tempfile::tempdir().unwrap();
        let managed = home.path().join(".shimpz/bin/shimpz");
        std::fs::create_dir_all(managed.parent().unwrap()).unwrap();
        std::fs::write(&managed, "managed").unwrap();
        let standalone = home.path().join("standalone-shimpz");
        std::fs::write(&standalone, "standalone").unwrap();

        assert!(managed_space_verdict(true, Some(home.path()), Some(&managed)).unwrap());
        assert!(!managed_space_verdict(true, Some(home.path()), Some(&standalone)).unwrap());
        assert!(!managed_space_verdict(true, Some(home.path()), None).unwrap());
        assert!(managed_space_verdict(true, None, Some(&managed)).is_err());
        assert!(!managed_space_verdict(false, None, Some(&managed)).unwrap());
    }

    #[test]
    fn explains_a_refused_anonymous_github_check() {
        let error = self_update::errors::Error::Ureq(ureq::Error::StatusCode(403));
        assert_eq!(
            github_error("CLI update check", &error),
            "GitHub refused the CLI update request (HTTP 403). Retry later or download the standalone CLI from https://github.com/TheShimpz/shimpz-cli/releases/latest"
        );
        assert_eq!(
            github_error("CLI update", &Error::Network("offline".into())),
            "CLI update failed: NetworkError: offline"
        );
    }

    #[cfg(unix)]
    #[test]
    fn recognizes_the_managed_cli_through_its_public_symlink() {
        let home = tempfile::tempdir().unwrap();
        let managed = home.path().join(".shimpz/bin/shimpz");
        let public = home.path().join(".local/bin/shimpz");
        std::fs::create_dir_all(managed.parent().unwrap()).unwrap();
        std::fs::create_dir_all(public.parent().unwrap()).unwrap();
        std::fs::write(&managed, "managed").unwrap();
        std::os::unix::fs::symlink(&managed, &public).unwrap();

        assert!(managed_space_verdict(true, Some(home.path()), Some(&public)).unwrap());
    }

    #[test]
    fn configures_the_published_archive_layout() {
        let configured = updater(Some("v9.8.7")).unwrap();
        assert_eq!(
            configured.bin_path_in_archive(),
            "shimpz-{{ version }}-{{ target }}/{{ bin }}"
        );
        assert_eq!(
            configured.bin_name(),
            format!("shimpz{}", std::env::consts::EXE_SUFFIX)
        );
        assert_eq!(configured.target_version().as_deref(), Some("v9.8.7"));
        assert!(configured.no_confirm());
    }

    #[test]
    fn upgrades_only_to_a_newer_semantic_version() {
        assert!(!newer_than_current(CURRENT_VERSION).unwrap());
        assert!(newer_than_current("999.0.0").unwrap());
        assert!(newer_than_current("not-a-version").is_err());
    }
}
