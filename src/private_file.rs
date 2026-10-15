//! Owner-private files: the safe open flags, the two admission rules, bounded record reads, and atomic replacement.

#[cfg(unix)]
use std::fs;
use std::fs::{File, Metadata, OpenOptions};
#[cfg(unix)]
use std::io::Write;
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

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

/// Open, creating it through [`private_open`] when absent, the lock file at `path` for reading and writing without
/// truncating it. The caller admits the file through the returned handle before locking it.
pub(crate) fn open_lock(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    private_open(&mut options);
    options.open(path)
}

/// Windows `FILE_FLAG_OPEN_REPARSE_POINT`: open a reparse point, such as a symbolic link, itself instead of its target.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// Open `path` only to read it, never following a final symbolic link (or, on Windows, a final reparse point),
/// blocking on a FIFO before its type is checked, or leaking the descriptor to a child. The caller admits the file
/// through the returned handle.
pub(crate) fn open_read(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::custom_flags(&mut options, FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

/// Why an opened file is not this user's private file.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Refusal {
    /// The path names a directory, device, FIFO, or other non-regular file.
    NotRegularFile,
    /// The file is reachable by another user, owned by another user, or has another name.
    #[cfg(unix)]
    NotPrivate,
}

/// Admit an opened file only as a regular file owned by the effective user, with no group or other permission bits
/// and a single link. This admits the Creator's own configuration files and locks, which a person may tighten below
/// 0600 by hand.
pub(crate) fn admit(metadata: &Metadata) -> Result<(), Refusal> {
    regular(metadata)?;
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0
        || !single_link_of(metadata, rustix::process::geteuid().as_raw())
    {
        return Err(Refusal::NotPrivate);
    }
    Ok(())
}

/// Admit an opened Local lifecycle record or lock: a regular file with a single link, like [`admit`], but owned by
/// the real user and with exactly mode 0600. This CLI creates every such file itself with exactly that mode (through
/// [`replace`] or [`open_lock`]) for the user who runs the lifecycle, so any other mode or owner is state it did
/// not leave and is refused rather than trusted.
pub(crate) fn admit_record(metadata: &Metadata) -> Result<(), Refusal> {
    regular(metadata)?;
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o777 != 0o600
        || !single_link_of(metadata, rustix::process::getuid().as_raw())
    {
        return Err(Refusal::NotPrivate);
    }
    Ok(())
}

fn regular(metadata: &Metadata) -> Result<(), Refusal> {
    if metadata.file_type().is_file() {
        Ok(())
    } else {
        Err(Refusal::NotRegularFile)
    }
}

#[cfg(unix)]
fn single_link_of(metadata: &Metadata, owner: u32) -> bool {
    metadata.uid() == owner && metadata.nlink() == 1
}

/// Why [`read_admitted`] read no document.
pub(crate) enum ReadFailure {
    /// The final path component is a symbolic link.
    Link,
    /// The opened file is not one the caller admits.
    NotAdmitted,
    /// The file holds more than the limit.
    Oversized,
    /// The file could not be opened, absence included.
    Open(io::Error),
    /// The opened file could not be inspected.
    Inspect(io::Error),
    /// The opened file could not be read.
    Read(io::Error),
}

/// Read the file at `path` only when `admits` admits it and it holds at most `limit` bytes. It is opened through
/// [`open_read`] and admitted through the open handle, so the checked file is the one read and no link is ever
/// followed.
pub(crate) fn read_admitted(
    path: &Path,
    limit: u64,
    admits: fn(&Metadata) -> bool,
) -> Result<String, ReadFailure> {
    let file = match open_read(path) {
        Ok(file) => file,
        #[cfg(unix)]
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => return Err(ReadFailure::Link),
        Err(error) => return Err(ReadFailure::Open(error)),
    };
    let metadata = file.metadata().map_err(ReadFailure::Inspect)?;
    if !admits(&metadata) {
        return Err(ReadFailure::NotAdmitted);
    }
    if metadata.len() > limit {
        return Err(ReadFailure::Oversized);
    }
    let mut document = String::new();
    file.take(limit + 1)
        .read_to_string(&mut document)
        .map_err(ReadFailure::Read)?;
    if document.len() as u64 > limit {
        return Err(ReadFailure::Oversized);
    }
    Ok(document)
}

/// Read a lifecycle record only when [`admit_record`] admits it and it holds at most `limit` bytes, through
/// [`read_admitted`], or return `Ok(None)` when it is absent.
pub(crate) fn read_record(path: &Path, limit: u64, name: &str) -> Result<Option<String>, String> {
    match read_admitted(path, limit, |metadata| admit_record(metadata).is_ok()) {
        Ok(document) => Ok(Some(document)),
        Err(ReadFailure::Open(error)) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(ReadFailure::Link | ReadFailure::NotAdmitted | ReadFailure::Oversized) => {
            Err(format!("{name} is not a private record"))
        }
        Err(ReadFailure::Open(error)) => Err(format!("{name} could not be opened: {error}")),
        Err(ReadFailure::Inspect(error)) => Err(format!("{name} could not be inspected: {error}")),
        Err(ReadFailure::Read(error)) => Err(format!("{name} could not be read: {error}")),
    }
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
    fs::rename(temporary, path)?;
    sync_parent(path)
}

/// Make a rename or removal in `path`'s directory durable.
#[cfg(unix)]
pub(crate) fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)?.sync_all()
}

/// Directory entries need no explicit sync on this platform.
#[cfg(not(unix))]
pub(crate) fn sync_parent(_: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::PermissionsExt;

    use super::{Refusal, admit, admit_record, private_open, read_record, replace};

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

    /// A lifecycle record keeps the stricter rule: a hand-tightened mode a Creator file may have is not this CLI's.
    #[test]
    fn admits_a_lifecycle_record_only_with_exactly_mode_0600() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("record");
        replace(&path, b"record\n").unwrap();
        assert_eq!(admit_record(&fs::metadata(&path).unwrap()), Ok(()));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(admit(&fs::metadata(&path).unwrap()), Ok(()));
        assert_eq!(
            admit_record(&fs::metadata(&path).unwrap()),
            Err(Refusal::NotPrivate)
        );
    }

    #[test]
    fn reads_a_record_only_through_its_admitted_handle() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("record");
        let refused = Err("the record is not a private record".to_owned());
        assert_eq!(read_record(&path, 64, "the record"), Ok(None));
        replace(&path, b"record\n").unwrap();
        assert_eq!(
            read_record(&path, 64, "the record"),
            Ok(Some("record\n".to_owned()))
        );
        assert_eq!(read_record(&path, 6, "the record"), refused);

        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(read_record(&link, 64, "the record"), refused);

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_record(&path, 64, "the record"), refused);
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

    /// A write refuses any non-regular leftover at its temporary path and discards only a stale regular one.
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
