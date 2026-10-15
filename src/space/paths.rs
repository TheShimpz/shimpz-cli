//! Exact host paths owned by one Local Space installation.

use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

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
    pub(crate) release_poll: PathBuf,
    pub(crate) failed_release: PathBuf,
    pub(crate) stopped: PathBuf,
    pub(crate) deploy_request: PathBuf,
    pub(crate) deploy_result: PathBuf,
    pub(crate) state_epoch: PathBuf,
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

    /// The private directory of the managed CLI.
    #[cfg(unix)]
    pub(crate) fn managed_bin(&self) -> &Path {
        self.managed_cli.parent().expect("managed CLI has a parent")
    }

    /// The managed CLI artifacts: the executable, its staged candidate, and the previous executable it replaced.
    #[cfg(unix)]
    pub(crate) fn managed_artifacts(&self) -> [PathBuf; 3] {
        [
            self.managed_cli.clone(),
            self.managed_cli.with_extension("candidate"),
            self.managed_cli.with_extension("previous"),
        ]
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
            release_poll: home.join("release-poll.json"),
            failed_release: home.join("failed-release.env"),
            stopped: home.join("stopped"),
            deploy_request: home.join("deploy-request"),
            deploy_result: home.join("deploy-result"),
            state_epoch: home.join("state-epoch"),
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

    #[cfg(unix)]
    pub(crate) fn marker_is_owned(&self) -> Result<bool, String> {
        let metadata = match self.marker.symlink_metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(format!("could not inspect the Local Space marker: {error}"));
            }
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("the Local Space marker ownership or permissions are invalid".into());
        }
        Ok(true)
    }
}

/// Whether an exact regular file is at `path`: `Ok(false)` when nothing is there. A symlink, dangling or not, and
/// any other file type are refused as `refusal` followed by the path; `io_error` renders a failed read.
#[cfg(unix)]
pub(crate) fn regular_file_present(
    path: &Path,
    refusal: &str,
    io_error: fn(std::io::Error) -> String,
) -> Result<bool, String> {
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(io_error(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{refusal}: {}", path.display()));
    }
    Ok(true)
}

/// Removes the exact regular file at `path` when one is there, refusing anything else as [`regular_file_present`]
/// does.
#[cfg(unix)]
pub(crate) fn remove_regular_if_present(
    path: &Path,
    refusal: &str,
    io_error: fn(std::io::Error) -> String,
) -> Result<(), String> {
    if regular_file_present(path, refusal, io_error)? {
        std::fs::remove_file(path).map_err(io_error)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::fs;

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

    #[cfg(unix)]
    #[test]
    fn hard_reset_marker_proof_ignores_content_but_not_ownership_shape() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        fs::write(&paths.marker, "incompatible-release-marker\n").unwrap();
        fs::set_permissions(&paths.marker, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(paths.marker_is_owned().unwrap());
        assert!(paths.marker_is_current().is_err());

        fs::set_permissions(&paths.marker, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(paths.marker_is_owned().is_err());
    }

    #[test]
    fn rejects_relative_home() {
        assert!(Paths::under(Path::new("relative")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn removes_only_an_exact_regular_file_and_refuses_a_dangling_symlink() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("file");
        fs::write(&file, b"x").unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(root.path().join("missing"), &link).unwrap();
        let directory = root.path().join("directory");
        fs::create_dir(&directory).unwrap();
        let io_error = |error: std::io::Error| error.to_string();

        assert_eq!(
            remove_regular_if_present(&file, "refused", io_error),
            Ok(())
        );
        assert!(fs::symlink_metadata(&file).is_err());
        assert_eq!(
            remove_regular_if_present(&file, "refused", io_error),
            Ok(())
        );
        for path in [&link, &directory] {
            assert_eq!(
                remove_regular_if_present(path, "refused", io_error),
                Err(format!("refused: {}", path.display()))
            );
            assert!(fs::symlink_metadata(path).is_ok());
        }
    }
}
