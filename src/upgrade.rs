//! In-place CLI upgrades from stable GitHub releases.

use self_update::backends::github::Update;
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
    let Some(home) = std::env::var_os("HOME").map(std::path::PathBuf::from) else {
        return Ok(());
    };
    let managed = home.join(".shimpz/bin/shimpz");
    let marker = home.join(".shimpz/.shimpz-space");
    if marker.exists()
        && managed.exists()
        && std::env::current_exe()
            .ok()
            .and_then(|path| path.canonicalize().ok())
            == managed.canonicalize().ok()
    {
        return Err(
            "this CLI is managed by Shimpz Space; run shimpz install to reconcile its atomic release"
                .into(),
        );
    }
    Ok(())
}

fn latest_release() -> Result<Release, String> {
    updater(None)?
        .get_latest_release()
        .map_err(|error| format!("CLI update check failed: {error}"))
}

fn install(release: &Release) -> Result<String, String> {
    let tag = format!("v{}", release.version);
    let status = updater(Some(&tag))?
        .update()
        .map_err(|error| format!("CLI update failed: {error}"))?;
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
