//! Serialize staging and unstaging of one Assistant's Local snapshots on this workstation.

use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::config_dir;
use crate::private_file::{self, Refusal};

/// Holds one Assistant's snapshot lock until dropped.
pub(crate) struct SnapshotLock {
    _file: File,
}

/// Wait for exclusive use of `assistant_id`'s Local snapshots; the id is already a validated manifest identity.
pub(crate) fn acquire(assistant_id: &str) -> Result<SnapshotLock, String> {
    let configuration =
        config_dir::path().ok_or_else(|| "OS configuration directory is unavailable".to_owned())?;
    acquire_in(&configuration, assistant_id)
}

fn acquire_in(configuration: &Path, assistant_id: &str) -> Result<SnapshotLock, String> {
    let directory = configuration.join("snapshots");
    fs::create_dir_all(&directory)
        .map_err(|_| "Local snapshot lock directory cannot be created".to_owned())?;
    #[cfg(unix)]
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|_| "Local snapshot lock directory cannot be secured".to_owned())?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    private_file::private_open(&mut options);
    let file = options
        .open(directory.join(format!("{assistant_id}.lock")))
        .map_err(|_| "Local snapshot lock cannot be opened".to_owned())?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| "Local snapshot lock cannot be secured".to_owned())?;
    require_private_file(&file)?;
    file.lock()
        .map_err(|_| "Local snapshot lock cannot be acquired".to_owned())?;
    Ok(SnapshotLock { _file: file })
}

fn require_private_file(file: &File) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|_| "Local snapshot lock metadata is unavailable".to_owned())?;
    private_file::admit(&metadata).map_err(|refusal| match refusal {
        Refusal::NotRegularFile => "Local snapshot lock path is not a regular file".into(),
        Refusal::NotPrivate => "Local snapshot lock ownership or permissions are unsafe".into(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use super::acquire_in;

    #[test]
    fn one_assistant_is_staged_or_unstaged_by_one_command_at_a_time() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().to_owned();
        let held = acquire_in(&root, "proof-assistant").expect("first lock");
        let other = acquire_in(&root, "other-assistant").expect("independent Assistant lock");
        drop(other);

        let (sender, receiver) = mpsc::channel();
        let waiter_root = root.clone();
        let waiter = thread::spawn(move || {
            let _second = acquire_in(&waiter_root, "proof-assistant").expect("second lock");
            sender.send(()).expect("signal");
        });
        assert!(receiver.recv_timeout(Duration::from_millis(200)).is_err());
        drop(held);
        receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("the waiter proceeds once the first command releases the lock");
        waiter.join().expect("waiter");
        assert!(
            directory
                .path()
                .join("snapshots/proof-assistant.lock")
                .is_file()
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_planted_link_or_a_shared_lock_file() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary directory");
        let locks = directory.path().join("snapshots");
        fs::create_dir_all(&locks).expect("lock directory");
        let target = directory.path().join("elsewhere");
        fs::write(&target, "").expect("link target");
        std::os::unix::fs::symlink(&target, locks.join("linked.lock")).expect("planted link");
        assert!(acquire_in(directory.path(), "linked").is_err());

        let shared = locks.join("shared.lock");
        fs::write(&shared, "").expect("shared lock");
        fs::hard_link(&shared, directory.path().join("second-name")).expect("second link");
        assert!(acquire_in(directory.path(), "shared").is_err());

        let _held = acquire_in(directory.path(), "private").expect("private lock");
        let mode = fs::metadata(locks.join("private.lock"))
            .expect("lock metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(
            fs::metadata(&locks)
                .expect("directory")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}
