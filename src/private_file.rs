//! Owner-private files: the one admission rule, the safe open flags, and atomic replacement.

use std::fs::{Metadata, OpenOptions};
#[cfg(unix)]
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::{fs, path::Path};

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

/// Replace `path` with `contents` through `<path>.tmp`, created exclusively with mode 0600 and synced before the rename.
/// A leftover regular temporary is discarded; any other leftover, such as a planted link, refuses the write.
#[cfg(unix)]
pub(crate) fn replace(path: &Path, contents: &[u8]) -> io::Result<()> {
    let temporary = path.with_extension("tmp");
    if temporary.exists() {
        let metadata = temporary.symlink_metadata()?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a regular file", temporary.display()),
            ));
        }
        fs::remove_file(&temporary)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(contents)?;
    file.sync_all()?;
    fs::rename(temporary, path)
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::PermissionsExt;

    use super::{Refusal, admit, private_open, replace};

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

    /// Space lifecycle state once deleted whatever sat at its temporary path, following storage only in refusing a
    /// planted link; both now refuse any non-regular leftover and discard only a stale regular one.
    #[test]
    fn replaces_atomically_and_refuses_a_planted_temporary() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("record");
        let temporary = directory.path().join("record.tmp");
        fs::write(&temporary, "stale").unwrap();
        replace(&path, b"first\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "first\n");
        assert!(!temporary.exists());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let target = directory.path().join("target");
        fs::write(&target, "kept").unwrap();
        std::os::unix::fs::symlink(&target, &temporary).unwrap();
        assert!(replace(&path, b"second\n").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "first\n");
        assert_eq!(fs::read_to_string(&target).unwrap(), "kept");
        assert!(
            temporary
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );

        fs::remove_file(&temporary).unwrap();
        fs::create_dir(&temporary).unwrap();
        assert!(replace(&path, b"third\n").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "first\n");
    }
}
