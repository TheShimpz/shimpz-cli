//! Restricted local persistence for rotating CLI credentials.

use std::{
    env,
    fmt::{self, Debug, Formatter},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use atomic_write_file::OpenOptions as AtomicOpenOptions;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const CREDENTIALS_FILE: &str = "credentials.json";
const CREDENTIALS_LOCK_FILE: &str = "credentials.lock";
const MAX_CREDENTIALS_BYTES: u64 = 16 * 1024;
const FORMAT_VERSION: u8 = 1;
const VALID_SCOPES: [&str; 4] = [
    "identity:read",
    "teams:read",
    "assistant:publish",
    "assistant:install",
];

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Credentials {
    version: u8,
    access_token: String,
    refresh_token: String,
    access_expires_at: u64,
    refresh_expires_at: u64,
    scopes: Vec<String>,
}

impl Credentials {
    pub(crate) fn new(
        access_token: String,
        refresh_token: String,
        access_expires_at: u64,
        refresh_expires_at: u64,
        scopes: Vec<String>,
    ) -> Result<Self, String> {
        let credentials = Self {
            version: FORMAT_VERSION,
            access_token,
            refresh_token,
            access_expires_at,
            refresh_expires_at,
            scopes,
        };
        credentials.validate()?;
        Ok(credentials)
    }

    pub(crate) fn access_token(&self) -> &str {
        &self.access_token
    }

    pub(crate) fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    pub(crate) fn scopes(&self) -> &[String] {
        &self.scopes
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != FORMAT_VERSION
            || !valid_token(&self.access_token)
            || !valid_token(&self.refresh_token)
            || self.access_expires_at == 0
            || self.refresh_expires_at == 0
            || !valid_scopes(&self.scopes)
        {
            return Err("stored CLI credentials are invalid; run `shimpz auth` again".into());
        }
        Ok(())
    }
}

impl Debug for Credentials {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Credentials")
            .field("version", &self.version)
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("access_expires_at", &self.access_expires_at)
            .field("refresh_expires_at", &self.refresh_expires_at)
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

pub(crate) struct CredentialLock {
    _file: File,
}

pub(crate) fn lock() -> Result<CredentialLock, String> {
    let directory = config_root()
        .map(|root| root.join("shimpz"))
        .ok_or_else(|| "OS configuration directory is unavailable".to_owned())?;
    fs::create_dir_all(&directory)
        .map_err(|_| "CLI configuration directory cannot be created".to_owned())?;
    secure_directory(&directory)?;
    let path = directory.join(CREDENTIALS_LOCK_FILE);
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    configure_secure_open(&mut options);
    let file = options
        .open(path)
        .map_err(|_| "CLI credential lock cannot be opened".to_owned())?;
    secure_open_file(&file)?;
    file.lock()
        .map_err(|_| "CLI credentials are busy".to_owned())?;
    Ok(CredentialLock { _file: file })
}

pub(crate) fn load(_lock: &CredentialLock) -> Result<Option<Credentials>, String> {
    load_from(&credentials_path()?)
}

pub(crate) fn store(_lock: &CredentialLock, credentials: &Credentials) -> Result<(), String> {
    store_at(&credentials_path()?, credentials)
}

pub(crate) fn clear(_lock: &CredentialLock) -> Result<(), String> {
    clear_at(&credentials_path()?)
}

fn credentials_path() -> Result<PathBuf, String> {
    config_root()
        .map(|root| root.join("shimpz").join(CREDENTIALS_FILE))
        .ok_or_else(|| "OS configuration directory is unavailable".into())
}

#[cfg(windows)]
fn config_root() -> Option<PathBuf> {
    env::var_os("APPDATA").map(PathBuf::from)
}

#[cfg(not(windows))]
fn config_root() -> Option<PathBuf> {
    env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".config"))
        })
}

fn load_from(path: &Path) -> Result<Option<Credentials>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    configure_no_follow(&mut options);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("CLI credentials cannot be opened".into()),
    };
    let metadata = file
        .metadata()
        .map_err(|_| "CLI credential metadata is unavailable".to_owned())?;
    require_secure_file(&metadata)?;
    if metadata.len() > MAX_CREDENTIALS_BYTES {
        return Err("stored CLI credentials are invalid; run `shimpz auth` again".into());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(MAX_CREDENTIALS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "CLI credentials cannot be read".to_owned())?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CREDENTIALS_BYTES {
        return Err("stored CLI credentials are invalid; run `shimpz auth` again".into());
    }
    let credentials: Credentials = serde_json::from_slice(&bytes)
        .map_err(|_| "stored CLI credentials are invalid; run `shimpz auth` again".to_owned())?;
    credentials.validate()?;
    Ok(Some(credentials))
}

fn store_at(path: &Path, credentials: &Credentials) -> Result<(), String> {
    credentials.validate()?;
    let parent = path
        .parent()
        .ok_or_else(|| "CLI credential path is invalid".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|_| "CLI configuration directory cannot be created".to_owned())?;
    secure_directory(parent)?;
    let mut options = AtomicOpenOptions::new();
    configure_atomic_secure_open(&mut options);
    let mut file = options
        .open(path)
        .map_err(|_| "CLI credentials cannot be stored".to_owned())?;
    secure_open_file(file.as_file())?;
    serde_json::to_writer(&mut file, credentials)
        .map_err(|_| "CLI credentials cannot be encoded".to_owned())?;
    file.write_all(b"\n")
        .and_then(|()| file.sync_all())
        .map_err(|_| "CLI credentials cannot be stored".to_owned())?;
    file.commit()
        .map_err(|_| "CLI credentials cannot be replaced".to_owned())?;
    sync_directory(parent)
}

fn clear_at(path: &Path) -> Result<(), String> {
    if load_from(path)?.is_none() {
        return Ok(());
    }
    fs::remove_file(path).map_err(|_| "local CLI credentials cannot be removed".to_owned())?;
    path.parent().map_or(Ok(()), sync_directory)
}

fn require_secure_file(metadata: &fs::Metadata) -> Result<(), String> {
    if !metadata.file_type().is_file() {
        return Err("CLI credential path is not a regular file".into());
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
    {
        return Err("CLI credential file ownership or permissions are unsafe".into());
    }
    Ok(())
}

fn secure_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| "CLI configuration directory cannot be secured".to_owned())?;
    Ok(())
}

fn secure_open_file(file: &File) -> Result<(), String> {
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| "CLI credential file cannot be secured".to_owned())?;
    let metadata = file
        .metadata()
        .map_err(|_| "CLI credential metadata is unavailable".to_owned())?;
    require_secure_file(&metadata)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "CLI credential directory cannot be synchronized".to_owned())
}

#[cfg(not(unix))]
const fn sync_directory(_: &Path) -> Result<(), String> {
    Ok(())
}

fn configure_no_follow(options: &mut OpenOptions) {
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
}

fn configure_secure_open(options: &mut OpenOptions) {
    configure_no_follow(options);
    #[cfg(unix)]
    options.mode(0o600);
}

fn configure_atomic_secure_open(options: &mut AtomicOpenOptions) {
    #[cfg(unix)]
    options.mode(0o600);
}

fn valid_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_scopes(scopes: &[String]) -> bool {
    !scopes.is_empty()
        && scopes.len() <= VALID_SCOPES.len()
        && scopes
            .iter()
            .try_fold(None, |previous, scope| {
                let index = VALID_SCOPES.iter().position(|valid| valid == scope)?;
                previous
                    .is_none_or(|previous| previous < index)
                    .then_some(Some(index))
            })
            .is_some()
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use tempfile::TempDir;

    use super::{Credentials, clear_at, load_from, store_at};

    fn credentials() -> Credentials {
        Credentials::new(
            "a".repeat(43),
            "b".repeat(43),
            1_000,
            2_000,
            vec!["identity:read".into(), "assistant:publish".into()],
        )
        .unwrap()
    }

    #[test]
    fn stores_loads_and_clears_restricted_credentials() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("shimpz").join("credentials.json");

        store_at(&path, &credentials()).unwrap();
        let loaded = load_from(&path).unwrap().unwrap();

        assert_eq!(loaded.access_token(), "a".repeat(43));
        assert_eq!(loaded.refresh_token(), "b".repeat(43));
        assert_eq!(
            loaded.scopes.as_slice(),
            ["identity:read", "assistant:publish"]
        );
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        clear_at(&path).unwrap();
        assert!(load_from(&path).unwrap().is_none());
    }

    #[test]
    fn rejects_unsafe_or_malformed_credential_files() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("credentials.json");
        fs::write(&path, b"{}").unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let error = load_from(&path).unwrap_err();

        #[cfg(unix)]
        assert_eq!(
            error,
            "CLI credential file ownership or permissions are unsafe"
        );
        #[cfg(not(unix))]
        assert!(error.contains("stored CLI credentials are invalid"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_and_hardlinked_credential_files() {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().unwrap();
        let target = directory.path().join("target.json");
        let symlink_path = directory.path().join("symlink.json");
        let hardlink_path = directory.path().join("hardlink.json");
        store_at(&target, &credentials()).unwrap();

        symlink(&target, &symlink_path).unwrap();
        assert!(load_from(&symlink_path).is_err());

        fs::hard_link(&target, &hardlink_path).unwrap();
        assert_eq!(
            load_from(&target).unwrap_err(),
            "CLI credential file ownership or permissions are unsafe"
        );
    }

    #[test]
    fn atomically_replaces_complete_credentials() {
        use std::io::Read as _;

        let directory = TempDir::new().unwrap();
        let path = directory.path().join("credentials.json");
        let first = credentials();
        let second = Credentials::new(
            "c".repeat(43),
            "d".repeat(43),
            3_000,
            4_000,
            vec!["identity:read".into(), "assistant:install".into()],
        )
        .unwrap();
        store_at(&path, &first).unwrap();
        let mut old_file = File::open(&path).unwrap();

        store_at(&path, &second).unwrap();

        let loaded = load_from(&path).unwrap().unwrap();
        assert_eq!(loaded.access_token(), "c".repeat(43));
        let mut old_contents = String::new();
        old_file.read_to_string(&mut old_contents).unwrap();
        let old: Credentials = serde_json::from_str(&old_contents).unwrap();
        assert_eq!(old.access_token(), "a".repeat(43));
        assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    #[test]
    fn redacts_tokens_from_debug_output() {
        let debug = format!("{:?}", credentials());

        assert!(!debug.contains(&"a".repeat(43)));
        assert!(!debug.contains(&"b".repeat(43)));
        assert!(debug.contains("<redacted>"));
    }
}
