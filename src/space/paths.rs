//! Exact host paths owned by one Local Space installation.

use std::path::{Path, PathBuf};

pub(crate) const MARKER: &str = "shimpz-space-managed-v1";
pub(crate) const STORAGE_MARKER: &str = "shimpz-local-storage-v1";

#[derive(Debug)]
pub(crate) struct Paths {
    pub(crate) home: PathBuf,
    pub(crate) compose: PathBuf,
    pub(crate) environment: PathBuf,
    pub(crate) marker: PathBuf,
    pub(crate) lock: PathBuf,
    pub(crate) status: PathBuf,
    pub(crate) failed_release: PathBuf,
    pub(crate) stopped: PathBuf,
    pub(crate) managed_cli: PathBuf,
    pub(crate) security: PathBuf,
    pub(crate) storage_marker: PathBuf,
    pub(crate) pool_image: PathBuf,
    pub(crate) pool_uuid: PathBuf,
    pub(crate) pool_mount: PathBuf,
    pub(crate) systemd_service: PathBuf,
    pub(crate) systemd_timer: PathBuf,
    pub(crate) launch_agent: PathBuf,
    pub(crate) public_cli: PathBuf,
}

impl Paths {
    pub(crate) fn discover() -> Result<Self, String> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| "HOME must be an absolute path".to_owned())?;
        Self::under(&home)
    }

    pub(crate) fn under(user_home: &Path) -> Result<Self, String> {
        if !user_home.is_absolute() {
            return Err("the user home must be absolute".into());
        }
        let home = user_home.join(".shimpz");
        let security = home.join("security");
        let systemd = user_home.join(".config/systemd/user");
        Ok(Self {
            compose: home.join("compose.yaml"),
            environment: home.join(".env"),
            marker: home.join(".shimpz-space"),
            lock: user_home.join(".shimpz-update.lock"),
            status: home.join("release-status.json"),
            failed_release: home.join("failed-release.env"),
            stopped: home.join("stopped"),
            managed_cli: home.join("bin/shimpz"),
            storage_marker: security.join(".shimpz-storage"),
            pool_image: security.join("local-data.luks"),
            pool_uuid: security.join("local-data.uuid"),
            pool_mount: security.join("volumes"),
            systemd_service: systemd.join("shimpz-update.service"),
            systemd_timer: systemd.join("shimpz-update.timer"),
            launch_agent: user_home.join("Library/LaunchAgents/com.shimpz.update.plist"),
            public_cli: user_home.join(".local/bin/shimpz"),
            security,
            home,
        })
    }

    pub(crate) fn marker_is_current(&self) -> Result<bool, String> {
        if !self.marker.exists() {
            return Ok(false);
        }
        let metadata = self
            .marker
            .symlink_metadata()
            .map_err(|error| format!("could not inspect the Local Space marker: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("the Local Space marker is a symbolic link".into());
        }
        let value = std::fs::read_to_string(&self.marker)
            .map_err(|error| format!("could not read the Local Space marker: {error}"))?;
        if value != format!("{MARKER}\n") {
            return Err("the Local Space marker is not current".into());
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_every_owned_path_below_exact_roots() {
        let user_home = if cfg!(windows) {
            Path::new(r"C:\Users\ada")
        } else {
            Path::new("/home/ada")
        };
        let paths = Paths::under(user_home).unwrap();
        assert_eq!(paths.home, user_home.join(".shimpz"));
        assert_eq!(paths.managed_cli, user_home.join(".shimpz/bin/shimpz"));
        assert_eq!(paths.public_cli, user_home.join(".local/bin/shimpz"));
        assert_eq!(paths.stopped, user_home.join(".shimpz/stopped"));
        assert_eq!(
            paths.systemd_timer,
            user_home.join(".config/systemd/user/shimpz-update.timer")
        );
    }

    #[test]
    fn rejects_relative_home() {
        assert!(Paths::under(Path::new("relative")).is_err());
    }
}
