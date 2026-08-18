//! Native Linux LUKS2 pool lifecycle.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::evidence::luks_dump_valid;
use crate::space::command::{self, Tool};
use crate::space::paths::{Paths, STORAGE_MARKER};

const POOL_SIZE: u64 = 64 * 1024 * 1024 * 1024;
const VOLUME_SPECS: [(&str, u32, u32, u32); 23] = [
    ("config", 1000, 1000, 0o700),
    ("data", 1000, 1000, 0o700),
    ("controller_token", 10001, 10010, 0o750),
    ("controller_audit", 10001, 10001, 0o700),
    ("controller_storage", 10001, 10001, 0o700),
    ("controller_inference", 10001, 10001, 0o700),
    ("controller_action_journal", 10001, 10001, 0o700),
    ("controller_publications", 10001, 10001, 0o700),
    ("controller_cosign_trust", 10001, 10001, 0o700),
    (
        "controller_assistant_integration_state",
        10001,
        10001,
        0o700,
    ),
    ("controller_assistant_integration_key", 10001, 10001, 0o700),
    ("controller_chat_continuation_state", 10001, 10001, 0o700),
    ("controller_chat_continuation_key", 10001, 10001, 0o700),
    ("supervisor_key", 1000, 10021, 0o750),
    ("release_status", 1000, 1000, 0o700),
    ("assistant_egress_policy", 10001, 10017, 0o750),
    ("assistant_egress_audit", 10005, 10005, 0o700),
    ("assistant_release_audit", 10004, 10004, 0o700),
    ("account_egress_capability", 10006, 10022, 0o750),
    ("account_egress_audit", 10006, 10006, 0o700),
    ("brain_egress_audit", 10001, 10001, 0o700),
    ("brain_runtime_token", 10001, 10016, 0o750),
    ("brain_runtime_state", 10001, 10001, 0o700),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Admission {
    Verified,
    Locked,
}

pub(crate) struct Pool<'a> {
    paths: &'a Paths,
    space_id: &'a str,
}

impl<'a> Pool<'a> {
    pub(crate) fn new(paths: &'a Paths, space_id: &'a str) -> Result<Self, String> {
        if !valid_space_id(space_id) {
            return Err("the Local Space identity is invalid".into());
        }
        Ok(Self { paths, space_id })
    }

    pub(crate) fn ensure(&self, fresh: bool, scheduled: bool) -> Result<Admission, String> {
        if !self.paths.security.exists() {
            if !fresh {
                return Err("the existing Local Space has no encrypted storage".into());
            }
            self.provision()?;
            return Ok(Admission::Verified);
        }
        self.validate_metadata()?;
        if self.mounted_valid().is_ok() {
            return Ok(Admission::Verified);
        }
        if scheduled {
            return Ok(Admission::Locked);
        }
        command::authorize()?;
        if self.mapping_path().exists() {
            self.validate_mapping()?;
        } else {
            Self::cryptsetup(
                [
                    OsString::from("open"),
                    OsString::from("--type"),
                    OsString::from("luks2"),
                    self.paths.pool_image.as_os_str().to_owned(),
                    OsString::from(self.mapping_name()),
                ],
                true,
            )?;
            self.validate_mapping()?;
        }
        if !self.is_mounted()? {
            Self::root(
                Tool::Mount,
                [
                    OsString::from("-o"),
                    OsString::from("nodev,nosuid"),
                    self.mapping_path().as_os_str().to_owned(),
                    self.paths.pool_mount.as_os_str().to_owned(),
                ],
                false,
            )?;
            self.own_mount_root()?;
        }
        self.mounted_valid()?;
        Ok(Admission::Verified)
    }

    pub(crate) fn reset(&self) -> Result<(), String> {
        if !self.paths.security.exists() {
            return Ok(());
        }
        validate_security_entries(self.paths)?;
        self.validate_metadata()?;
        let mapping = self.mapping_path();
        if mapping.exists() {
            self.validate_mapping()?;
            command::authorize()?;
            if self.is_mounted()? {
                self.validate_mount()?;
                Self::root(
                    Tool::Umount,
                    [self.paths.pool_mount.as_os_str().to_owned()],
                    false,
                )?;
            }
            Self::cryptsetup(
                [OsString::from("close"), OsString::from(self.mapping_name())],
                false,
            )?;
            if mapping.exists() {
                return Err("the encrypted Local storage mapping remained open".into());
            }
        } else if self.is_mounted()? {
            return Err("refusing to unmount Local storage without its owned mapping".into());
        }
        fs::remove_file(&self.paths.pool_uuid).map_err(cleanup_error)?;
        fs::remove_file(&self.paths.pool_image).map_err(cleanup_error)?;
        fs::remove_file(&self.paths.storage_marker).map_err(cleanup_error)?;
        fs::remove_dir(&self.paths.pool_mount).map_err(cleanup_error)?;
        fs::remove_dir(&self.paths.security).map_err(cleanup_error)?;
        Ok(())
    }

    fn provision(&self) -> Result<(), String> {
        command::authorize()?;
        if self.mapping_path().exists() {
            return Err("a foreign device-mapper mapping uses the Local Space identity".into());
        }
        fs::create_dir(&self.paths.security)
            .map_err(|error| format!("could not create Local security directory: {error}"))?;
        fs::set_permissions(&self.paths.security, fs::Permissions::from_mode(0o700))
            .map_err(io_error)?;
        let result = self.provision_owned();
        if let Err(error) = result {
            return match self.discard_new() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(format!("{error}; cleanup also failed: {cleanup}")),
            };
        }
        Ok(())
    }

    fn provision_owned(&self) -> Result<(), String> {
        write_private(&self.paths.storage_marker, &format!("{STORAGE_MARKER}\n"))?;
        let image = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.paths.pool_image)
            .map_err(io_error)?;
        image.set_len(POOL_SIZE).map_err(io_error)?;
        Self::root(
            Tool::Install,
            [
                OsString::from("-d"),
                OsString::from("-o"),
                OsString::from("0"),
                OsString::from("-g"),
                OsString::from("0"),
                OsString::from("-m"),
                OsString::from("000"),
                self.paths.pool_mount.as_os_str().to_owned(),
            ],
            false,
        )?;
        Self::cryptsetup(
            [
                OsString::from("luksFormat"),
                OsString::from("--batch-mode"),
                OsString::from("--type"),
                OsString::from("luks2"),
                OsString::from("--cipher"),
                OsString::from("aes-xts-plain64"),
                OsString::from("--key-size"),
                OsString::from("512"),
                OsString::from("--pbkdf"),
                OsString::from("argon2id"),
                self.paths.pool_image.as_os_str().to_owned(),
            ],
            true,
        )?;
        let uuid = Self::luks_output([
            OsString::from("luksUUID"),
            self.paths.pool_image.as_os_str().to_owned(),
        ])?;
        let uuid = one_line(&uuid, "encrypted Local storage UUID")?;
        write_private(&self.paths.pool_uuid, &format!("{uuid}\n"))?;
        Self::cryptsetup(
            [
                OsString::from("open"),
                OsString::from("--type"),
                OsString::from("luks2"),
                self.paths.pool_image.as_os_str().to_owned(),
                OsString::from(self.mapping_name()),
            ],
            true,
        )?;
        self.validate_mapping()?;
        Self::root(
            Tool::MkfsExt4,
            [
                OsString::from("-q"),
                OsString::from("-m"),
                OsString::from("0"),
                self.mapping_path().as_os_str().to_owned(),
            ],
            false,
        )?;
        Self::root(
            Tool::Mount,
            [
                OsString::from("-o"),
                OsString::from("nodev,nosuid"),
                self.mapping_path().as_os_str().to_owned(),
                self.paths.pool_mount.as_os_str().to_owned(),
            ],
            false,
        )?;
        self.own_mount_root()?;
        self.create_volume_layout()?;
        self.mounted_valid()
    }

    fn validate_metadata(&self) -> Result<(), String> {
        exact_regular_file(&self.paths.storage_marker)?;
        exact_regular_file(&self.paths.pool_image)?;
        exact_regular_file(&self.paths.pool_uuid)?;
        if fs::read_to_string(&self.paths.storage_marker).map_err(io_error)?
            != format!("{STORAGE_MARKER}\n")
        {
            return Err("encrypted Local storage marker is invalid".into());
        }
        let expected_document = fs::read_to_string(&self.paths.pool_uuid).map_err(io_error)?;
        let expected = one_line(&expected_document, "pool UUID")?;
        let actual_document = Self::luks_output([
            OsString::from("luksUUID"),
            self.paths.pool_image.as_os_str().to_owned(),
        ])?;
        let actual = one_line(&actual_document, "pool UUID")?;
        if expected != actual {
            return Err("encrypted Local storage UUID does not match".into());
        }
        let dump = Self::luks_output([
            OsString::from("luksDump"),
            self.paths.pool_image.as_os_str().to_owned(),
        ])?;
        if !luks_dump_valid(&dump) {
            return Err("encrypted Local storage parameters are invalid".into());
        }
        Ok(())
    }

    fn validate_mapping(&self) -> Result<(), String> {
        self.validate_metadata()?;
        let status = Self::luks_output([
            OsString::from("status"),
            OsString::from(self.mapping_name()),
        ])?;
        let device = status
            .lines()
            .find_map(|line| line.trim().strip_prefix("device:"))
            .map(str::trim)
            .filter(|value| {
                value.starts_with("/dev/loop")
                    && value[9..].bytes().all(|byte| byte.is_ascii_digit())
            })
            .ok_or_else(|| {
                "encrypted Local storage mapping has invalid loop identity".to_owned()
            })?;
        let backing = command::privileged_output(
            Tool::Losetup,
            ["--noheadings", "--output", "BACK-FILE", device],
        )?;
        let backing = PathBuf::from(one_line(&backing, "loop backing file")?);
        if backing.canonicalize().map_err(io_error)?
            != self.paths.pool_image.canonicalize().map_err(io_error)?
        {
            return Err("encrypted Local storage mapping has foreign backing".into());
        }
        Ok(())
    }

    fn mounted_valid(&self) -> Result<(), String> {
        self.validate_mount()?;
        let metadata = self.paths.pool_mount.metadata().map_err(io_error)?;
        if metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.gid() != rustix::process::getgid().as_raw()
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err("encrypted Local storage root ownership is invalid".into());
        }
        for (name, uid, gid, mode) in VOLUME_SPECS {
            let metadata = self
                .paths
                .pool_mount
                .join(name)
                .symlink_metadata()
                .map_err(io_error)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != uid
                || metadata.gid() != gid
                || metadata.permissions().mode() & 0o777 != mode
            {
                return Err(format!("encrypted Local volume layout is invalid: {name}"));
            }
        }
        Ok(())
    }

    fn validate_mount(&self) -> Result<(), String> {
        self.validate_mapping()?;
        let mount = self.paths.pool_mount.to_string_lossy();
        let source_document =
            command::output(Tool::Findmnt, ["-rn", "-M", &mount, "-o", "SOURCE"])?;
        let filesystem_document =
            command::output(Tool::Findmnt, ["-rn", "-M", &mount, "-o", "FSTYPE"])?;
        let target_document =
            command::output(Tool::Findmnt, ["-rn", "-M", &mount, "-o", "TARGET"])?;
        let source = one_line(&source_document, "mount source")?;
        let filesystem = one_line(&filesystem_document, "mount filesystem")?;
        let target = one_line(&target_document, "mount target")?;
        if source != self.mapping_path().to_string_lossy()
            || filesystem != "ext4"
            || target != mount
        {
            return Err("encrypted Local storage mount identity is invalid".into());
        }
        Ok(())
    }

    fn create_volume_layout(&self) -> Result<(), String> {
        self.validate_mount()?;
        for (name, uid, gid, mode) in VOLUME_SPECS {
            Self::root(
                Tool::Install,
                [
                    OsString::from("-d"),
                    OsString::from("-o"),
                    OsString::from(uid.to_string()),
                    OsString::from("-g"),
                    OsString::from(gid.to_string()),
                    OsString::from("-m"),
                    OsString::from(format!("{mode:o}")),
                    self.paths.pool_mount.join(name).as_os_str().to_owned(),
                ],
                false,
            )?;
        }
        Ok(())
    }

    fn own_mount_root(&self) -> Result<(), String> {
        Self::root(
            Tool::Chown,
            [
                OsString::from(format!(
                    "{}:{}",
                    rustix::process::getuid().as_raw(),
                    rustix::process::getgid().as_raw()
                )),
                self.paths.pool_mount.as_os_str().to_owned(),
            ],
            false,
        )?;
        fs::set_permissions(&self.paths.pool_mount, fs::Permissions::from_mode(0o700))
            .map_err(io_error)
    }

    fn discard_new(&self) -> Result<(), String> {
        if self.is_mounted().unwrap_or(false) && self.validate_mount().is_ok() {
            Self::root(
                Tool::Umount,
                [self.paths.pool_mount.as_os_str().to_owned()],
                false,
            )?;
        }
        if self.mapping_path().exists() && self.validate_mapping().is_ok() {
            Self::cryptsetup(
                [OsString::from("close"), OsString::from(self.mapping_name())],
                false,
            )?;
        }
        if self.mapping_path().exists() {
            return Err("owned encrypted storage mapping remained after compensation".into());
        }
        remove_if_regular(&self.paths.pool_uuid)?;
        remove_if_regular(&self.paths.pool_image)?;
        remove_if_regular(&self.paths.storage_marker)?;
        remove_if_empty(&self.paths.pool_mount)?;
        remove_if_empty(&self.paths.security)
    }

    fn cryptsetup<I>(arguments: I, tty: bool) -> Result<(), String>
    where
        I: IntoIterator<Item = OsString>,
    {
        let result = command::privileged_status(Tool::Luks, arguments, tty)?;
        if result.success() {
            Ok(())
        } else {
            Err("encrypted Local storage operation failed".into())
        }
    }

    fn root<I>(tool: Tool, arguments: I, tty: bool) -> Result<(), String>
    where
        I: IntoIterator<Item = OsString>,
    {
        let result = command::privileged_status(tool, arguments, tty)?;
        if result.success() {
            Ok(())
        } else {
            Err(format!("privileged host operation failed: {tool:?}"))
        }
    }

    fn luks_output<I>(arguments: I) -> Result<String, String>
    where
        I: IntoIterator<Item = OsString>,
    {
        command::privileged_output(Tool::Luks, arguments)
    }

    fn is_mounted(&self) -> Result<bool, String> {
        Ok(command::status(
            Tool::Mountpoint,
            ["--quiet", &self.paths.pool_mount.to_string_lossy()],
        )?
        .success())
    }

    fn mapping_name(&self) -> String {
        format!(
            "shimpz-{}",
            self.space_id
                .strip_prefix("space-")
                .expect("validated Space id")
        )
    }

    fn mapping_path(&self) -> PathBuf {
        Path::new("/dev/mapper").join(self.mapping_name())
    }
}

fn valid_space_id(value: &str) -> bool {
    value.strip_prefix("space-").is_some_and(|suffix| {
        suffix.len() == 24
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn validate_security_entries(paths: &Paths) -> Result<(), String> {
    let admitted = [
        paths.storage_marker.as_path(),
        paths.pool_image.as_path(),
        paths.pool_uuid.as_path(),
        paths.pool_mount.as_path(),
    ];
    for entry in fs::read_dir(&paths.security).map_err(io_error)? {
        let path = entry.map_err(io_error)?.path();
        if !admitted.contains(&path.as_path()) {
            return Err(format!(
                "refusing to delete unrecognized Local security content: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn exact_regular_file(path: &Path) -> Result<(), String> {
    let metadata = path.symlink_metadata().map_err(io_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        Err(format!("invalid Local storage file: {}", path.display()))
    } else {
        Ok(())
    }
}

fn write_private(path: &Path, value: &str) -> Result<(), String> {
    let temporary = path.with_extension("tmp");
    if temporary.exists() {
        exact_regular_file(&temporary)?;
        fs::remove_file(&temporary).map_err(io_error)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(io_error)?;
    file.write_all(value.as_bytes()).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    fs::rename(temporary, path).map_err(io_error)
}

fn one_line<'a>(value: &'a str, label: &str) -> Result<&'a str, String> {
    let mut lines = value.lines();
    let line = lines.next().filter(|line| !line.is_empty());
    if line.is_none() || lines.next().is_some() {
        return Err(format!("{label} is malformed"));
    }
    Ok(line.expect("checked"))
}

fn remove_if_regular(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    exact_regular_file(path)?;
    fs::remove_file(path).map_err(cleanup_error)
}

fn remove_if_empty(path: &Path) -> Result<(), String> {
    if path.exists() {
        fs::remove_dir(path).map_err(cleanup_error)?;
    }
    Ok(())
}

fn io_error(error: std::io::Error) -> String {
    let message = format!("Local storage operation failed: {error}");
    drop(error);
    message
}

fn cleanup_error(error: std::io::Error) -> String {
    let message = format!("Local storage cleanup failed: {error}");
    drop(error);
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_only_exact_space_ids() {
        assert!(valid_space_id("space-0123456789abcdef01234567"));
        for invalid in [
            "0123456789abcdef01234567",
            "space-0123456789abcdef0123456",
            "space-0123456789abcdef012345678",
            "space-0123456789ABCDEF01234567",
            "space-0123456789abcdef0123456g",
        ] {
            assert!(!valid_space_id(invalid));
        }
    }

    #[test]
    fn volume_specs_match_the_canonical_graph() {
        assert_eq!(VOLUME_SPECS.len(), crate::space::graph::VOLUME_NAMES.len());
        for (index, spec) in VOLUME_SPECS.iter().enumerate() {
            assert_eq!(spec.0, crate::space::graph::VOLUME_NAMES[index]);
        }
    }
}
