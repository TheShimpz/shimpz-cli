//! Upgrade guidance for the CLI.
//!
//! The CLI never replaces its own executable from the standalone channel: a GitHub Release checksum proves only
//! integrity, not authenticity. A Space-managed CLI is replaced only by the signed atomic Local release, and a
//! standalone CLI is reinstalled through Cargo.

use std::path::{Path, PathBuf};

const MANAGED_SPACE_GUIDANCE: &str =
    "this CLI is managed by Shimpz Space; run shimpz update to check its atomic release";
const STANDALONE_GUIDANCE: &str = "the Standalone CLI does not replace itself; the CLI was not changed; reinstall it with: cargo install --locked shimpz-cli";

pub(crate) fn run() -> Result<String, String> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let current = std::env::current_exe().ok();
    if managed_space_verdict(cfg!(unix), home.as_deref(), current.as_deref())? {
        return Err(MANAGED_SPACE_GUIDANCE.into());
    }
    Err(STANDALONE_GUIDANCE.into())
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
        assert!(MANAGED_SPACE_GUIDANCE.contains("shimpz update"));
        assert!(!MANAGED_SPACE_GUIDANCE.contains("shimpz install"));
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
}
