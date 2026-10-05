//! The per-user `shimpz` configuration directory and the one admission rule for the private files it holds.

use std::env;
use std::fs::{Metadata, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

/// `shimpz` under the OS configuration root: `$XDG_CONFIG_HOME` or `~/.config` on Unix, `%APPDATA%` on Windows.
pub(crate) fn path() -> Option<PathBuf> {
    root().map(|root| root.join("shimpz"))
}

#[cfg(windows)]
fn root() -> Option<PathBuf> {
    env::var_os("APPDATA").map(PathBuf::from)
}

#[cfg(not(windows))]
fn root() -> Option<PathBuf> {
    env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
}

/// Never follow a final symbolic link or leak the descriptor to a child, and create the file readable only by this
/// user.
pub(crate) fn private_open(options: &mut OpenOptions) {
    #[cfg(unix)]
    options
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .mode(0o600);
    #[cfg(not(unix))]
    let _ = options;
}

/// Why an opened file is not this user's private file.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Refusal {
    /// The path names a directory, device, FIFO, or other non-regular file.
    NotRegularFile,
    /// The file is reachable by another user, owned by another user, or has another name.
    NotPrivate,
}

/// Admit an opened file only as a regular file owned by the effective user, with no group or other permission bits
/// and a single link.
pub(crate) fn admit(metadata: &Metadata) -> Result<(), Refusal> {
    if !metadata.file_type().is_file() {
        return Err(Refusal::NotRegularFile);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
    {
        return Err(Refusal::NotPrivate);
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::PermissionsExt;

    use super::{Refusal, admit, private_open};

    #[test]
    fn admits_only_a_single_link_owner_private_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("private");
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).write(true);
        private_open(&mut options);
        let file = options.open(&path).unwrap();
        assert_eq!(admit(&file.metadata().unwrap()), Ok(()));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            admit(&fs::metadata(&path).unwrap()),
            Err(Refusal::NotPrivate)
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&path, directory.path().join("second")).unwrap();
        assert_eq!(
            admit(&fs::metadata(&path).unwrap()),
            Err(Refusal::NotPrivate)
        );
        assert_eq!(
            admit(&fs::metadata(directory.path()).unwrap()),
            Err(Refusal::NotRegularFile)
        );
    }

    #[test]
    fn never_follows_a_planted_link() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        fs::write(&target, "").unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let mut options = OpenOptions::new();
        options.read(true);
        private_open(&mut options);
        assert!(options.open(&link).is_err());
    }
}
