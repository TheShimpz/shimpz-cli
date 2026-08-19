//! Native Linux LUKS2 pool lifecycle.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use memsafe::Secret;
use nix::sys::signal::{SigSet, SigmaskHow, Signal};
use rustix::termios::{LocalModes, OptionalActions, QueueSelector, Termios};

use super::evidence::{
    MIN_CRYPTSETUP_VERSION, cryptsetup_version, cryptsetup_version_supported, luks_dump_valid,
    luks_unlock_credentials_valid,
};
use crate::space::command::{self, Tool};
use crate::space::paths::{Paths, STORAGE_MARKER};

const POOL_SIZE: u64 = 64 * 1024 * 1024 * 1024;
const MAX_PASSPHRASE_BYTES: usize = 1_024;
const PASSPHRASE_BUFFER_BYTES: usize = MAX_PASSPHRASE_BYTES + 1;

macro_rules! live_trace {
    ($stage:literal) => {
        #[cfg(test)]
        eprintln!("Linux storage live: {}", $stage);
    };
}

const VOLUME_SPECS: [(&str, u32, u32, u32); 23] = [
    ("config", 1000, 1000, 0o700),
    ("data", 1000, 1000, 0o700),
    ("controller_token", 10001, 10010, 0o2750),
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
    ("supervisor_key", 0, 10021, 0o2770),
    ("release_status", 1000, 1000, 0o700),
    ("assistant_egress_policy", 10001, 10017, 0o750),
    ("assistant_egress_audit", 10005, 10005, 0o700),
    ("assistant_release_audit", 10004, 10004, 0o700),
    ("account_egress_capability", 0, 10022, 0o750),
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

struct LockedPassphrase {
    secret: Secret<PASSPHRASE_BUFFER_BYTES>,
    length: usize,
}

struct EchoRestoration<'a> {
    tty: &'a fs::File,
    original: Option<Termios>,
}

struct SignalMaskRestoration {
    original: Option<SigSet>,
}

impl EchoRestoration<'_> {
    fn restore(mut self) -> Result<(), String> {
        let original = self.original.as_ref().expect("terminal state is present");
        rustix::termios::tcsetattr(self.tty, OptionalActions::Now, original)
            .map_err(|_| "encrypted storage terminal state could not be restored".to_owned())?;
        self.original.take();
        Ok(())
    }
}

impl Drop for EchoRestoration<'_> {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            let _ = rustix::termios::tcsetattr(self.tty, OptionalActions::Now, &original);
        }
    }
}

impl SignalMaskRestoration {
    fn block() -> Result<Self, String> {
        let blocked = termination_signals();
        let original = blocked
            .thread_swap_mask(SigmaskHow::SIG_BLOCK)
            .map_err(|_| "encrypted storage terminal signals could not be blocked".to_owned())?;
        Ok(Self {
            original: Some(original),
        })
    }

    fn restore(mut self) -> Result<(), String> {
        self.original
            .as_ref()
            .expect("signal mask is present")
            .thread_set_mask()
            .map_err(|_| "encrypted storage terminal signals could not be restored".to_owned())?;
        self.original.take();
        Ok(())
    }
}

impl Drop for SignalMaskRestoration {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            let _ = original.thread_set_mask();
        }
    }
}

fn termination_signals() -> SigSet {
    [
        Signal::SIGHUP,
        Signal::SIGINT,
        Signal::SIGQUIT,
        Signal::SIGTERM,
        Signal::SIGTSTP,
    ]
    .into_iter()
    .collect()
}

impl LockedPassphrase {
    fn prompt(label: &str) -> Result<Self, String> {
        let tty = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|_| "encrypted storage requires a terminal".to_owned())?;
        let signals = SignalMaskRestoration::block()?;
        let original = rustix::termios::tcgetattr(&tty)
            .map_err(|_| "encrypted storage terminal state is unavailable".to_owned())?;
        let mut hidden = original.clone();
        hidden
            .local_modes
            .remove(LocalModes::ECHO | LocalModes::ECHONL);
        rustix::termios::tcsetattr(&tty, OptionalActions::Flush, &hidden)
            .map_err(|_| "encrypted storage terminal could not disable echo".to_owned())?;
        let restoration = EchoRestoration {
            tty: &tty,
            original: Some(original),
        };
        let mut output = &tty;
        output
            .write_all(label.as_bytes())
            .and_then(|()| output.flush())
            .map_err(|_| "encrypted storage terminal prompt failed".to_owned())?;
        let result = Self::read_from(&tty);
        restoration.restore()?;
        output
            .write_all(b"\n")
            .and_then(|()| output.flush())
            .map_err(|_| "encrypted storage terminal prompt failed".to_owned())?;
        signals.restore()?;
        result
    }

    fn read_from(tty: &fs::File) -> Result<Self, String> {
        let mut secret = Secret::new_with(|_| {})
            .map_err(|_| "encrypted storage passphrase memory could not be protected".to_owned())?;
        let length = {
            let mut buffer = secret
                .write()
                .map_err(|_| "encrypted storage passphrase memory is unavailable".to_owned())?;
            let mut reader = tty;
            let count = reader
                .read(&mut buffer[..])
                .map_err(|_| "could not read the encrypted storage passphrase".to_owned())?;
            match terminated_passphrase_length(&buffer[..count]) {
                Ok(length) => {
                    buffer[length..count].fill(0);
                    length
                }
                Err(error) => {
                    let _ = rustix::termios::tcflush(tty, QueueSelector::IFlush);
                    return Err(error);
                }
            }
        };
        Ok(Self { secret, length })
    }

    #[cfg(test)]
    fn from_test_input(value: &[u8]) -> Result<Self, String> {
        validate_passphrase(value)?;
        let length = value.len();
        let secret = Secret::new_with(|buffer| buffer[..length].copy_from_slice(value))
            .map_err(|_| "encrypted storage passphrase memory could not be protected".to_owned())?;
        Ok(Self { secret, length })
    }

    fn matches(&mut self, other: &mut Self) -> Result<bool, String> {
        if self.length != other.length {
            return Ok(false);
        }
        let left = self
            .secret
            .read()
            .map_err(|_| "encrypted storage passphrase memory is unavailable".to_owned())?;
        let right = other
            .secret
            .read()
            .map_err(|_| "encrypted storage passphrase memory is unavailable".to_owned())?;
        Ok(left[..self.length] == right[..other.length])
    }

    fn run_cryptsetup<I>(&mut self, operation: &str, arguments: I) -> Result<(), String>
    where
        I: IntoIterator<Item = OsString>,
    {
        let arguments = cryptsetup_secret_arguments(operation, self.length, arguments);
        let secret = self
            .secret
            .read()
            .map_err(|_| "encrypted storage passphrase memory is unavailable".to_owned())?;
        let result =
            command::privileged_status_with_input(Tool::Luks, arguments, &secret[..self.length])?;
        if result.success() {
            Ok(())
        } else {
            Err("encrypted Local storage operation failed".into())
        }
    }
}

fn terminated_passphrase_length(value: &[u8]) -> Result<usize, String> {
    let without_newline = value
        .strip_suffix(b"\n")
        .or_else(|| value.strip_suffix(b"\r"))
        .ok_or_else(|| "encrypted storage passphrase is too long".to_owned())?;
    let passphrase = without_newline
        .strip_suffix(b"\r")
        .unwrap_or(without_newline);
    validate_passphrase(passphrase)?;
    Ok(passphrase.len())
}

fn validate_passphrase(value: &[u8]) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_PASSPHRASE_BYTES
        || value.contains(&b'\n')
        || value.contains(&b'\r')
    {
        return Err("encrypted storage passphrase is invalid".into());
    }
    Ok(())
}

fn cryptsetup_secret_arguments<I>(operation: &str, length: usize, arguments: I) -> Vec<OsString>
where
    I: IntoIterator<Item = OsString>,
{
    let mut result = vec![
        OsString::from(operation),
        OsString::from("--key-file"),
        OsString::from("-"),
        OsString::from("--keyfile-size"),
        OsString::from(length.to_string()),
    ];
    result.extend(arguments);
    result
}

fn new_passphrase() -> Result<LockedPassphrase, String> {
    let mut passphrase = LockedPassphrase::prompt("New encrypted storage passphrase: ")?;
    let mut confirmation = LockedPassphrase::prompt("Confirm encrypted storage passphrase: ")?;
    if !passphrase.matches(&mut confirmation)? {
        return Err("encrypted storage passphrases do not match".into());
    }
    Ok(passphrase)
}

impl<'a> Pool<'a> {
    pub(crate) fn new(paths: &'a Paths, space_id: &'a str) -> Result<Self, String> {
        if !valid_space_id(space_id) {
            return Err("the Local Space identity is invalid".into());
        }
        Ok(Self { paths, space_id })
    }

    pub(crate) fn ensure(&self, fresh: bool, scheduled: bool) -> Result<Admission, String> {
        admit_cryptsetup()?;
        if !self.paths.security.exists() {
            if !fresh {
                return Err("the existing Local Space has no encrypted storage".into());
            }
            self.provision()?;
            return Ok(Admission::Verified);
        }
        validate_metadata(self.paths)?;
        if scheduled {
            if !self.is_mounted()? {
                return Ok(Admission::Locked);
            }
            self.mounted_valid_unprivileged()?;
            return Ok(Admission::Verified);
        }
        if self.mounted_valid().is_ok() {
            return Ok(Admission::Verified);
        }
        command::authorize()?;
        if self.mapping_path().exists() {
            self.validate_mapping()?;
        } else {
            let mut passphrase = LockedPassphrase::prompt("Encrypted storage passphrase: ")?;
            passphrase.run_cryptsetup(
                "open",
                [
                    OsString::from("--type"),
                    OsString::from("luks2"),
                    self.paths.pool_image.as_os_str().to_owned(),
                    OsString::from(self.mapping_name()),
                ],
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
            )?;
            self.own_mount_root()?;
        }
        self.mounted_valid()?;
        Ok(Admission::Verified)
    }

    pub(crate) fn validate_mounted(&self) -> Result<(), String> {
        self.mounted_valid_unprivileged()
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
        )?;
        let mut passphrase = new_passphrase()?;
        passphrase.run_cryptsetup(
            "luksFormat",
            [
                OsString::from("--batch-mode"),
                OsString::from("--type"),
                OsString::from("luks2"),
                OsString::from("--cipher"),
                OsString::from("aes-xts-plain64"),
                OsString::from("--key-size"),
                OsString::from("512"),
                OsString::from("--pbkdf"),
                OsString::from("argon2id"),
                OsString::from("--pbkdf-force-iterations"),
                OsString::from("8"),
                OsString::from("--pbkdf-memory"),
                OsString::from("262144"),
                OsString::from("--pbkdf-parallel"),
                OsString::from("4"),
                self.paths.pool_image.as_os_str().to_owned(),
            ],
        )?;
        live_trace!("formatted LUKS2 container");
        let uuid = Self::luks_output([
            OsString::from("luksUUID"),
            self.paths.pool_image.as_os_str().to_owned(),
        ])?;
        let uuid = one_line(&uuid, "encrypted Local storage UUID")?;
        write_private(&self.paths.pool_uuid, &format!("{uuid}\n"))?;
        live_trace!("recorded LUKS2 identity");
        passphrase.run_cryptsetup(
            "open",
            [
                OsString::from("--type"),
                OsString::from("luks2"),
                self.paths.pool_image.as_os_str().to_owned(),
                OsString::from(self.mapping_name()),
            ],
        )?;
        live_trace!("opened device-mapper mapping");
        self.validate_mapping()?;
        live_trace!("validated device-mapper mapping");
        Self::root(
            Tool::MkfsExt4,
            [
                OsString::from("-q"),
                OsString::from("-t"),
                OsString::from("ext4"),
                OsString::from("-E"),
                OsString::from("nodiscard"),
                OsString::from("-m"),
                OsString::from("0"),
                self.mapping_path().as_os_str().to_owned(),
            ],
        )?;
        live_trace!("formatted ext4 filesystem");
        Self::root(
            Tool::Mount,
            [
                OsString::from("-o"),
                OsString::from("nodev,nosuid"),
                self.mapping_path().as_os_str().to_owned(),
                self.paths.pool_mount.as_os_str().to_owned(),
            ],
        )?;
        live_trace!("mounted ext4 filesystem");
        self.own_mount_root()?;
        self.create_volume_layout()?;
        live_trace!("created encrypted volume layout");
        self.mounted_valid()
    }

    fn validate_mapping(&self) -> Result<(), String> {
        validate_metadata(self.paths)?;
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
        self.validate_volume_layout()
    }

    fn mounted_valid_unprivileged(&self) -> Result<(), String> {
        self.validate_mapping_unprivileged()?;
        self.validate_mount_identity()?;
        self.validate_volume_layout()
    }

    fn validate_volume_layout(&self) -> Result<(), String> {
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
                || metadata.permissions().mode() & 0o7777 != mode
            {
                return Err(format!("encrypted Local volume layout is invalid: {name}"));
            }
        }
        Ok(())
    }

    fn validate_mount(&self) -> Result<(), String> {
        self.validate_mapping()?;
        self.validate_mount_identity()
    }

    #[cfg(target_os = "linux")]
    fn validate_mapping_unprivileged(&self) -> Result<(), String> {
        validate_metadata(self.paths)?;
        let mapping = self.mapping_path().metadata().map_err(io_error)?;
        if !mapping.file_type().is_block_device() {
            return Err("encrypted Local storage mapping is not a block device".into());
        }
        let major = rustix::fs::major(mapping.rdev());
        let minor = rustix::fs::minor(mapping.rdev());
        let sys_device = PathBuf::from(format!("/sys/dev/block/{major}:{minor}"));
        let name_document = fs::read_to_string(sys_device.join("dm/name")).map_err(io_error)?;
        if one_line(&name_document, "device-mapper name")? != self.mapping_name() {
            return Err("encrypted Local storage mapping identity is invalid".into());
        }
        let mut slaves = fs::read_dir(sys_device.join("slaves")).map_err(io_error)?;
        let slave = slaves
            .next()
            .transpose()
            .map_err(io_error)?
            .ok_or_else(|| "encrypted Local storage mapping has no loop device".to_owned())?;
        if slaves.next().transpose().map_err(io_error)?.is_some() {
            return Err("encrypted Local storage mapping has ambiguous backing".into());
        }
        let slave = slave
            .file_name()
            .into_string()
            .ok()
            .filter(|value| {
                value.strip_prefix("loop").is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
                })
            })
            .ok_or_else(|| {
                "encrypted Local storage mapping has invalid loop identity".to_owned()
            })?;
        let backing_document =
            fs::read_to_string(format!("/sys/class/block/{slave}/loop/backing_file"))
                .map_err(io_error)?;
        let backing = PathBuf::from(one_line(&backing_document, "loop backing file")?);
        if backing.canonicalize().map_err(io_error)?
            != self.paths.pool_image.canonicalize().map_err(io_error)?
        {
            return Err("encrypted Local storage mapping has foreign backing".into());
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn validate_mapping_unprivileged(&self) -> Result<(), String> {
        Err("unprivileged encrypted mapping validation requires Linux".into())
    }

    fn validate_mount_identity(&self) -> Result<(), String> {
        let mount = self.paths.pool_mount.to_string_lossy();
        let device_document =
            command::output(Tool::Findmnt, ["-rn", "-M", &mount, "-o", "MAJ:MIN"])?;
        let filesystem_document =
            command::output(Tool::Findmnt, ["-rn", "-M", &mount, "-o", "FSTYPE"])?;
        let target_document =
            command::output(Tool::Findmnt, ["-rn", "-M", &mount, "-o", "TARGET"])?;
        let device = one_line(&device_document, "mount device")?;
        let filesystem = one_line(&filesystem_document, "mount filesystem")?;
        let target = one_line(&target_document, "mount target")?;
        let mapping = self.mapping_path().metadata().map_err(io_error)?;
        let expected_device = mapping_device_identity(&mapping);
        if device != expected_device || filesystem != "ext4" || target != mount {
            return Err(format!(
                "encrypted Local storage mount identity is invalid (device {device}, expected {expected_device}; filesystem {filesystem}; target {target}, expected {mount})"
            ));
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
        )?;
        fs::set_permissions(&self.paths.pool_mount, fs::Permissions::from_mode(0o700))
            .map_err(io_error)
    }

    fn discard_new(&self) -> Result<(), String> {
        if self.is_mounted().unwrap_or(false) && self.validate_mount().is_ok() {
            Self::root(Tool::Umount, [self.paths.pool_mount.as_os_str().to_owned()])?;
        }
        if self.mapping_path().exists() && self.validate_mapping().is_ok() {
            Self::cryptsetup([OsString::from("close"), OsString::from(self.mapping_name())])?;
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

    fn cryptsetup<I>(arguments: I) -> Result<(), String>
    where
        I: IntoIterator<Item = OsString>,
    {
        let result = command::privileged_status(Tool::Luks, arguments)?;
        if result.success() {
            Ok(())
        } else {
            Err("encrypted Local storage operation failed".into())
        }
    }

    fn root<I>(tool: Tool, arguments: I) -> Result<(), String>
    where
        I: IntoIterator<Item = OsString>,
    {
        let result = command::privileged_status(tool, arguments)?;
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

pub(crate) fn reset(paths: &Paths, expected_space_id: Option<&str>) -> Result<(), String> {
    if !paths.security.exists() {
        return Ok(());
    }
    if expected_space_id.is_some_and(|value| !valid_space_id(value)) {
        return Err("the Local Space identity is invalid".into());
    }
    validate_security_entries(paths)?;
    if incomplete(paths)? {
        return reset_incomplete(paths);
    }
    admit_cryptsetup()?;
    validate_metadata(paths)?;
    let mappings = discover_pool_mappings(paths)?;
    let identity = reset_mapping_identity(expected_space_id, &mappings)?;
    if let Some(identity) = identity {
        let pool = Pool::new(paths, &identity)?;
        command::authorize()?;
        pool.validate_mapping()?;
        if pool.is_mounted()? {
            pool.validate_mount()?;
            Pool::root(Tool::Umount, [paths.pool_mount.as_os_str().to_owned()])?;
        }
        Pool::cryptsetup([OsString::from("close"), OsString::from(pool.mapping_name())])?;
        if pool.mapping_path().exists() {
            return Err("the encrypted Local storage mapping remained open".into());
        }
    } else if command::status(
        Tool::Mountpoint,
        ["--quiet", &paths.pool_mount.to_string_lossy()],
    )?
    .success()
    {
        return Err("refusing to unmount Local storage without its owned mapping".into());
    }
    remove_pool_files(paths)
}

pub(crate) fn incomplete(paths: &Paths) -> Result<bool, String> {
    if !paths.security.exists() {
        return Ok(false);
    }
    validate_security_entries(paths)?;
    reconcile_storage_marker(paths)?;
    let marker = paths.storage_marker.exists();
    let image = paths.pool_image.exists();
    let uuid = paths.pool_uuid.exists();
    let mount = paths.pool_mount.exists();
    match (marker, image, mount, uuid) {
        (true, true, true, true) => Ok(false),
        (_, false, false, false) | (true, true, _, false) => Ok(true),
        _ => Err("the encrypted Local storage has an impossible partial layout".into()),
    }
}

fn reset_incomplete(paths: &Paths) -> Result<(), String> {
    if !paths.storage_marker.exists() {
        return remove_if_empty(&paths.security);
    }
    exact_regular_file(&paths.storage_marker)?;
    if fs::read_to_string(&paths.storage_marker).map_err(io_error)? != format!("{STORAGE_MARKER}\n")
    {
        return Err("encrypted Local storage marker is invalid".into());
    }
    if paths.pool_image.exists() {
        exact_regular_file(&paths.pool_image)?;
        refuse_open_partial_pool(paths)?;
    }
    if paths.pool_mount.exists() {
        let metadata = paths.pool_mount.symlink_metadata().map_err(io_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("encrypted Local storage mountpoint is invalid".into());
        }
    }
    remove_if_regular(&paths.pool_uuid.with_extension("tmp"))?;
    remove_if_empty(&paths.pool_mount)?;
    remove_if_regular(&paths.pool_image)?;
    remove_if_regular(&paths.storage_marker)?;
    remove_if_empty(&paths.security)
}

fn refuse_open_partial_pool(paths: &Paths) -> Result<(), String> {
    let pool = paths.pool_image.canonicalize().map_err(io_error)?;
    let blocks = fs::read_dir("/sys/class/block")
        .map_err(|_| "the host block-device inventory is unavailable".to_owned())?;
    for entry in blocks {
        let entry = entry.map_err(io_error)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.strip_prefix("loop").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        }) {
            continue;
        }
        let Some(backing) = read_loop_backing(&entry.path().join("loop/backing_file"))? else {
            continue;
        };
        if deleted_backing_is_pool(&backing, &pool) {
            return Err("the partial encrypted storage has a deleted open backing file".into());
        }
        if PathBuf::from(&backing)
            .canonicalize()
            .is_ok_and(|backing| backing == pool)
        {
            return Err("the partial encrypted storage still has an open loop device".into());
        }
    }
    Ok(())
}

fn reconcile_storage_marker(paths: &Paths) -> Result<(), String> {
    let temporary = paths.storage_marker.with_extension("tmp");
    if !temporary.exists() {
        return Ok(());
    }
    if paths.storage_marker.exists() {
        return Err("the encrypted Local storage has an unexpected marker temporary".into());
    }
    exact_regular_file(&temporary)?;
    if fs::read_to_string(&temporary).map_err(io_error)? != format!("{STORAGE_MARKER}\n") {
        return Err("encrypted Local storage marker temporary is invalid".into());
    }
    fs::rename(temporary, &paths.storage_marker).map_err(io_error)
}

fn discover_pool_mappings(paths: &Paths) -> Result<Vec<String>, String> {
    let pool = paths.pool_image.canonicalize().map_err(io_error)?;
    let recorded_uuid = fs::read_to_string(&paths.pool_uuid).map_err(io_error)?;
    let recorded_uuid = one_line(&recorded_uuid, "pool UUID")?.replace('-', "");
    let mut identities = Vec::new();
    let blocks = fs::read_dir("/sys/class/block")
        .map_err(|_| "the host block-device inventory is unavailable".to_owned())?;
    for entry in blocks {
        let entry = entry.map_err(io_error)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.strip_prefix("loop").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        }) {
            continue;
        }
        let backing = entry.path().join("loop/backing_file");
        let Some(backing) = read_loop_backing(&backing)? else {
            continue;
        };
        if deleted_backing_is_pool(&backing, &pool) {
            return Err("the encrypted Local storage has a deleted open backing file".into());
        }
        let Ok(backing) = PathBuf::from(&backing).canonicalize() else {
            continue;
        };
        if backing != pool {
            continue;
        }
        let mut holders = fs::read_dir(entry.path().join("holders")).map_err(|_| {
            "the encrypted Local storage holder inventory is unavailable".to_owned()
        })?;
        let mut found_holder = false;
        for holder in &mut holders {
            found_holder = true;
            let holder = holder.map_err(io_error)?;
            identities.push(validate_discovered_mapping(
                paths,
                &recorded_uuid,
                &holder.path(),
            )?);
        }
        if !found_holder {
            return Err("the encrypted Local storage has a foreign open loop device".into());
        }
    }
    identities.sort();
    identities.dedup();
    Ok(identities)
}

fn read_loop_backing(path: &Path) -> Result<Option<String>, String> {
    match fs::read_to_string(path) {
        Ok(document) => Ok(Some(document.trim_end().to_owned())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("the host loop-device backing evidence is unavailable".into()),
    }
}

fn deleted_backing_is_pool(value: &str, pool_image: &Path) -> bool {
    value
        .strip_suffix(" (deleted)")
        .is_some_and(|path| Path::new(path) == pool_image)
}

fn validate_discovered_mapping(
    paths: &Paths,
    recorded_uuid: &str,
    holder: &Path,
) -> Result<String, String> {
    let name_document = fs::read_to_string(holder.join("dm/name"))
        .map_err(|_| "the encrypted Local storage mapping name is unavailable".to_owned())?;
    let name = one_line(&name_document, "device-mapper name")?;
    let suffix = name
        .strip_prefix("shimpz-")
        .filter(|value| {
            value.len() == 24
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| "the encrypted Local storage has a foreign mapping name".to_owned())?;
    let dm_uuid_document = fs::read_to_string(holder.join("dm/uuid"))
        .map_err(|_| "the encrypted Local storage mapping UUID is unavailable".to_owned())?;
    let dm_uuid = one_line(&dm_uuid_document, "device-mapper UUID")?;
    if dm_uuid != format!("CRYPT-LUKS2-{recorded_uuid}-{name}") {
        return Err("the encrypted Local storage mapping UUID is invalid".into());
    }
    let identity = format!("space-{suffix}");
    Pool::new(paths, &identity)?.validate_mapping_unprivileged()?;
    Ok(identity)
}

fn reset_mapping_identity(
    expected: Option<&str>,
    discovered: &[String],
) -> Result<Option<String>, String> {
    let identity = match discovered {
        [] => None,
        [identity] => Some(identity.clone()),
        _ => return Err("the encrypted Local storage mapping identity is ambiguous".into()),
    };
    if expected.is_some() && expected != identity.as_deref() && identity.is_some() {
        return Err("the encrypted Local storage mapping identity does not match the Space".into());
    }
    Ok(identity)
}

fn remove_pool_files(paths: &Paths) -> Result<(), String> {
    fs::remove_file(&paths.pool_uuid).map_err(cleanup_error)?;
    fs::remove_dir(&paths.pool_mount).map_err(cleanup_error)?;
    fs::remove_file(&paths.pool_image).map_err(cleanup_error)?;
    fs::remove_file(&paths.storage_marker).map_err(cleanup_error)?;
    fs::remove_dir(&paths.security).map_err(cleanup_error)
}

fn validate_metadata(paths: &Paths) -> Result<(), String> {
    exact_regular_file(&paths.storage_marker)?;
    exact_regular_file(&paths.pool_image)?;
    exact_regular_file(&paths.pool_uuid)?;
    if fs::read_to_string(&paths.storage_marker).map_err(io_error)? != format!("{STORAGE_MARKER}\n")
    {
        return Err("encrypted Local storage marker is invalid".into());
    }
    let expected_document = fs::read_to_string(&paths.pool_uuid).map_err(io_error)?;
    let expected = one_line(&expected_document, "pool UUID")?;
    let actual_document = command::output(
        Tool::Luks,
        [
            OsString::from("luksUUID"),
            paths.pool_image.as_os_str().to_owned(),
        ],
    )?;
    let actual = one_line(&actual_document, "pool UUID")?;
    if expected != actual {
        return Err("encrypted Local storage UUID does not match".into());
    }
    let dump = command::output(
        Tool::Luks,
        [
            OsString::from("luksDump"),
            paths.pool_image.as_os_str().to_owned(),
        ],
    )?;
    if !luks_dump_valid(&dump) {
        return Err("encrypted Local storage parameters are invalid".into());
    }
    let unlock_credentials = command::output(
        Tool::Luks,
        [
            OsString::from("luksDump"),
            OsString::from("--dump-json-metadata"),
            paths.pool_image.as_os_str().to_owned(),
        ],
    )
    .map_err(|_| "encrypted Local storage unlock credential evidence is unavailable")?;
    if !luks_unlock_credentials_valid(&unlock_credentials) {
        return Err("encrypted Local storage unlock credentials are invalid".into());
    }
    Ok(())
}

fn admit_cryptsetup() -> Result<(), String> {
    let document = command::output(Tool::Luks, ["--version"])?;
    let version = cryptsetup_version(&document).ok_or_else(|| {
        "encrypted Local storage cryptsetup version evidence is malformed".to_owned()
    })?;
    if !cryptsetup_version_supported(version) {
        return Err(format!(
            "encrypted Local storage requires cryptsetup {}.{} or newer; found {}.{}.{}",
            MIN_CRYPTSETUP_VERSION.0, MIN_CRYPTSETUP_VERSION.1, version.0, version.1, version.2,
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn mapping_device_identity(mapping: &fs::Metadata) -> String {
    format!(
        "{}:{}",
        rustix::fs::major(mapping.rdev()),
        rustix::fs::minor(mapping.rdev())
    )
}

#[cfg(not(target_os = "linux"))]
fn mapping_device_identity(_mapping: &fs::Metadata) -> String {
    "unsupported".into()
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
    let metadata = paths.security.symlink_metadata().map_err(io_error)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("the encrypted Local storage directory is invalid".into());
    }
    let marker_temporary = paths.storage_marker.with_extension("tmp");
    let uuid_temporary = paths.pool_uuid.with_extension("tmp");
    let admitted = [
        paths.storage_marker.as_path(),
        marker_temporary.as_path(),
        paths.pool_image.as_path(),
        paths.pool_uuid.as_path(),
        uuid_temporary.as_path(),
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
    fn validates_locks_and_compares_passphrases_without_exposing_them() {
        for invalid in [
            Vec::new(),
            b"line\nfeed".to_vec(),
            b"carriage\rreturn".to_vec(),
            vec![b'a'; MAX_PASSPHRASE_BYTES + 1],
        ] {
            assert!(validate_passphrase(&invalid).is_err());
        }
        assert!(validate_passphrase(&vec![b'a'; MAX_PASSPHRASE_BYTES]).is_ok());
        assert_eq!(terminated_passphrase_length(b"correct horse\n"), Ok(13));
        assert_eq!(terminated_passphrase_length(b"correct horse\r\n"), Ok(13));
        assert!(terminated_passphrase_length(b"unterminated").is_err());

        let mut first = LockedPassphrase::from_test_input(b"correct horse")
            .expect("passphrase should be locked");
        let mut matching = LockedPassphrase::from_test_input(b"correct horse")
            .expect("passphrase should be locked");
        let mut different = LockedPassphrase::from_test_input(b"wrong battery")
            .expect("passphrase should be locked");
        let mut shorter =
            LockedPassphrase::from_test_input(b"short").expect("passphrase should be locked");
        assert!(first.matches(&mut matching).unwrap());
        assert!(!first.matches(&mut different).unwrap());
        assert!(!first.matches(&mut shorter).unwrap());
    }

    #[test]
    fn blocks_terminal_termination_until_echo_is_restored() {
        let signals = termination_signals();
        for signal in [
            Signal::SIGHUP,
            Signal::SIGINT,
            Signal::SIGQUIT,
            Signal::SIGTERM,
            Signal::SIGTSTP,
        ] {
            assert!(signals.contains(signal));
        }
        assert!(!signals.contains(Signal::SIGKILL));
        assert!(!signals.contains(Signal::SIGSTOP));
    }

    #[test]
    fn cryptsetup_secret_arguments_bind_exact_stdin_bytes() {
        let arguments = cryptsetup_secret_arguments(
            "open",
            13,
            [OsString::from("--type"), OsString::from("luks2")],
        );
        assert_eq!(
            arguments,
            [
                "open",
                "--key-file",
                "-",
                "--keyfile-size",
                "13",
                "--type",
                "luks2"
            ]
            .map(OsString::from)
        );
    }

    #[test]
    fn volume_specs_match_the_canonical_graph() {
        assert_eq!(VOLUME_SPECS.len(), crate::space::graph::VOLUME_NAMES.len());
        for (index, spec) in VOLUME_SPECS.iter().enumerate() {
            assert_eq!(spec.0, crate::space::graph::VOLUME_NAMES[index]);
            assert_eq!(spec.3 & 0o007, 0);
            assert_eq!(spec.3 & !0o7777, 0);
        }
        assert!(VOLUME_SPECS.contains(&("controller_token", 10001, 10010, 0o2750)));
        assert!(VOLUME_SPECS.contains(&("supervisor_key", 0, 10021, 0o2770)));
        assert!(VOLUME_SPECS.contains(&("assistant_egress_policy", 10001, 10017, 0o750)));
        assert!(VOLUME_SPECS.contains(&("account_egress_capability", 0, 10022, 0o750)));
    }

    #[test]
    fn reset_identity_accepts_only_zero_or_one_matching_mapping() {
        let expected = "space-0123456789abcdef01234567";
        assert_eq!(reset_mapping_identity(Some(expected), &[]).unwrap(), None);
        assert_eq!(
            reset_mapping_identity(None, &[expected.to_owned()]).unwrap(),
            Some(expected.to_owned())
        );
        assert_eq!(
            reset_mapping_identity(Some(expected), &[expected.to_owned()]).unwrap(),
            Some(expected.to_owned())
        );
        assert!(
            reset_mapping_identity(
                Some("space-aaaaaaaaaaaaaaaaaaaaaaaa"),
                &[expected.to_owned()]
            )
            .is_err()
        );
        assert!(
            reset_mapping_identity(
                None,
                &[
                    expected.to_owned(),
                    "space-aaaaaaaaaaaaaaaaaaaaaaaa".to_owned()
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_the_owned_pool_when_sysfs_reports_a_deleted_backing() {
        let pool = Path::new("/home/ada/.shimpz/security/local-data.luks");
        assert!(deleted_backing_is_pool(
            "/home/ada/.shimpz/security/local-data.luks (deleted)",
            pool
        ));
        assert!(!deleted_backing_is_pool(
            "/home/other/local-data.luks (deleted)",
            pool
        ));
        assert!(!deleted_backing_is_pool(
            "/home/ada/.shimpz/security/local-data.luks",
            pool
        ));
    }

    #[test]
    fn skips_only_absent_loop_backing_evidence() {
        let root = tempfile::tempdir().unwrap();
        let backing = root.path().join("backing_file");
        assert_eq!(read_loop_backing(&backing).unwrap(), None);

        fs::write(&backing, "/owned/pool.img").unwrap();
        assert_eq!(
            read_loop_backing(&backing).unwrap().as_deref(),
            Some("/owned/pool.img")
        );
        fs::write(&backing, "/owned/pool.img (deleted)\n").unwrap();
        assert_eq!(
            read_loop_backing(&backing).unwrap().as_deref(),
            Some("/owned/pool.img (deleted)")
        );

        fs::remove_file(&backing).unwrap();
        fs::create_dir(&backing).unwrap();
        assert!(read_loop_backing(&backing).is_err());
    }

    #[test]
    fn admits_only_current_interrupted_provision_layouts() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir_all(&paths.security).unwrap();
        fs::set_permissions(&paths.security, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(incomplete(&paths).unwrap());

        fs::write(
            paths.storage_marker.with_extension("tmp"),
            format!("{STORAGE_MARKER}\n"),
        )
        .unwrap();
        assert!(incomplete(&paths).unwrap());
        assert!(paths.storage_marker.exists());

        fs::write(&paths.pool_image, "partial").unwrap();
        assert!(incomplete(&paths).unwrap());
        fs::create_dir(&paths.pool_mount).unwrap();
        fs::write(paths.pool_uuid.with_extension("tmp"), "partial").unwrap();
        assert!(incomplete(&paths).unwrap());
        fs::remove_file(paths.pool_uuid.with_extension("tmp")).unwrap();
        fs::write(&paths.pool_uuid, "uuid\n").unwrap();
        assert!(!incomplete(&paths).unwrap());

        fs::remove_file(&paths.storage_marker).unwrap();
        assert!(incomplete(&paths).is_err());
    }

    #[test]
    fn incomplete_reset_finishes_exact_marker_and_empty_residue() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir_all(&paths.security).unwrap();
        fs::set_permissions(&paths.security, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&paths.storage_marker, format!("{STORAGE_MARKER}\n")).unwrap();
        reset_incomplete(&paths).unwrap();
        assert!(!paths.security.exists());

        fs::create_dir(&paths.security).unwrap();
        fs::set_permissions(&paths.security, fs::Permissions::from_mode(0o700)).unwrap();
        reset_incomplete(&paths).unwrap();
        assert!(!paths.security.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires real LUKS, loop, mount, sudo, and a controlling terminal"]
    fn live_pool_provisions_locks_reopens_and_resets_idempotently() {
        let home = std::env::var_os("SHIMPZ_LINUX_STORAGE_TEST_HOME")
            .map(PathBuf::from)
            .expect("SHIMPZ_LINUX_STORAGE_TEST_HOME is required");
        fs::create_dir_all(&home).unwrap();
        let paths = Paths::under(&home).unwrap();
        fs::create_dir(&paths.home).unwrap();
        let pool = Pool::new(&paths, "space-0123456789abcdef01234567").unwrap();
        assert_eq!(pool.ensure(true, false).unwrap(), Admission::Verified);
        pool.validate_mount().unwrap();
        Pool::root(Tool::Umount, [paths.pool_mount.as_os_str().to_owned()]).unwrap();
        Pool::cryptsetup([OsString::from("close"), OsString::from(pool.mapping_name())]).unwrap();
        assert_eq!(pool.ensure(false, true).unwrap(), Admission::Locked);
        assert_eq!(pool.ensure(false, false).unwrap(), Admission::Verified);
        reset(&paths, Some("space-0123456789abcdef01234567")).unwrap();
        reset(&paths, None).unwrap();
        assert!(!paths.security.exists());
    }
}
