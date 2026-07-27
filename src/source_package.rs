//! Collect authored Assistant files without following links.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::ustar;

const MAX_COLLECTED_FILES: usize = 10_000;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum EntryKind {
    RegularFile,
    Special,
}

pub(crate) enum EntryContent {
    File {
        path: PathBuf,
        size: u64,
    },
    #[cfg(test)]
    Bytes(Vec<u8>),
    Empty,
}

impl EntryContent {
    pub(crate) fn size(&self) -> u64 {
        match self {
            Self::File { size, .. } => *size,
            #[cfg(test)]
            Self::Bytes(bytes) => bytes.len() as u64,
            Self::Empty => 0,
        }
    }

    pub(crate) fn read(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::File { path, size } => read_unchanged_file(path, *size),
            #[cfg(test)]
            Self::Bytes(bytes) => Ok(bytes.clone()),
            Self::Empty => Ok(Vec::new()),
        }
    }
}

pub(crate) struct InputEntry {
    pub(crate) path: String,
    pub(crate) kind: EntryKind,
    pub(crate) content: EntryContent,
}

pub(crate) struct SourcePackage {
    pub(crate) bytes: Vec<u8>,
    pub(crate) digest: String,
    pub(crate) excluded_roots: Vec<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Error {
    code: &'static str,
}

impl Error {
    pub(crate) const fn new(code: &'static str) -> Self {
        Self { code }
    }

    #[cfg(test)]
    pub(crate) const fn code(&self) -> &'static str {
        self.code
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "source package is invalid: {}", self.code)
    }
}

pub(crate) fn build(root: &Path) -> Result<SourcePackage, String> {
    let (entries, excluded_roots) = collect(root).map_err(|error| error.to_string())?;
    let bytes = ustar::build(&entries).map_err(|error| error.to_string())?;
    let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
    Ok(SourcePackage {
        bytes,
        digest,
        excluded_roots,
    })
}

pub(crate) fn check_summary(package: &SourcePackage) -> String {
    format!(
        "Assistant is valid.\nSource package: {} ({} bytes)",
        package.digest,
        package.bytes.len()
    )
}

pub(crate) fn exclusion_warning(package: &SourcePackage) -> Option<String> {
    (!package.excluded_roots.is_empty()).then(|| {
        let names = package
            .excluded_roots
            .iter()
            .map(|name| format!("{name:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("Excluded from publish: {names}")
    })
}

pub(crate) fn reject<T>(code: &'static str) -> Result<T, Error> {
    Err(Error::new(code))
}

fn collect(root: &Path) -> Result<(Vec<InputEntry>, Vec<String>), Error> {
    if !root.is_dir() {
        return reject("invalid_entry");
    }
    let mut entries = Vec::new();
    let mut excluded = Vec::new();
    let children = fs::read_dir(root).map_err(|_| Error::new("invalid_entry"))?;
    for child in children {
        let child = child.map_err(|_| Error::new("invalid_entry"))?;
        let name = child.file_name();
        match name.to_str() {
            Some("shimpz.toml" | "pyproject.toml") => {
                collect_entry(root, &child.path(), &mut entries)?;
            }
            Some("powers" | "lib" | "tests") => {
                collect_allowed_root(root, &child.path(), &mut entries)?;
            }
            _ => excluded.push(name.to_string_lossy().into_owned()),
        }
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    excluded.sort();
    Ok((entries, excluded))
}

fn collect_allowed_root(
    root: &Path,
    path: &Path,
    entries: &mut Vec<InputEntry>,
) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Error::new("invalid_entry"))?;
    if !metadata.is_dir() {
        return collect_entry(root, path, entries);
    }
    collect_directory(root, path, entries)
}

fn collect_directory(
    root: &Path,
    directory: &Path,
    entries: &mut Vec<InputEntry>,
) -> Result<(), Error> {
    let mut pending = vec![directory.to_owned()];
    while let Some(current) = pending.pop() {
        let children = fs::read_dir(current).map_err(|_| Error::new("invalid_entry"))?;
        for child in children {
            let child = child.map_err(|_| Error::new("invalid_entry"))?;
            let metadata =
                fs::symlink_metadata(child.path()).map_err(|_| Error::new("invalid_entry"))?;
            if metadata.is_dir() {
                pending.push(child.path());
            } else {
                collect_entry_with_metadata(root, &child.path(), &metadata, entries)?;
            }
        }
    }
    Ok(())
}

fn collect_entry(root: &Path, path: &Path, entries: &mut Vec<InputEntry>) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Error::new("invalid_entry"))?;
    collect_entry_with_metadata(root, path, &metadata, entries)
}

fn collect_entry_with_metadata(
    root: &Path,
    path: &Path,
    metadata: &Metadata,
    entries: &mut Vec<InputEntry>,
) -> Result<(), Error> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| Error::new("invalid_entry"))?;
    let package_path = relative
        .components()
        .map(|component| component.as_os_str().to_str())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| Error::new("non_ascii_path"))?
        .join("/");
    let kind = if metadata.is_file() && !metadata_has_multiple_links(metadata) {
        EntryKind::RegularFile
    } else {
        EntryKind::Special
    };
    let content = if kind == EntryKind::RegularFile {
        EntryContent::File {
            path: path.to_owned(),
            size: metadata.len(),
        }
    } else {
        EntryContent::Empty
    };
    entries.push(InputEntry {
        path: package_path,
        kind,
        content,
    });
    if entries.len() > MAX_COLLECTED_FILES {
        return reject("file_count_exceeded");
    }
    Ok(())
}

fn read_unchanged_file(path: &Path, expected_size: u64) -> Result<Vec<u8>, Error> {
    let mut file = open_without_following(path).map_err(|_| Error::new("invalid_entry"))?;
    let metadata = file.metadata().map_err(|_| Error::new("invalid_entry"))?;
    if !metadata.is_file() || metadata.len() != expected_size {
        return reject("invalid_entry");
    }
    reject_multiple_links(&file, &metadata)?;
    let limit = expected_size.saturating_add(1);
    let mut bytes = Vec::with_capacity(usize::try_from(expected_size).unwrap_or(0));
    file.by_ref()
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::new("invalid_entry"))?;
    if bytes.len() as u64 != expected_size {
        return reject("invalid_entry");
    }
    Ok(bytes)
}

fn open_without_following(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    configure_no_follow(&mut options);
    options.open(path)
}

#[cfg(unix)]
fn configure_no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(windows)]
fn configure_no_follow(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;
    options.custom_flags(0x0020_0000);
}

#[cfg(unix)]
fn metadata_has_multiple_links(metadata: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink() > 1
}

#[cfg(windows)]
const fn metadata_has_multiple_links(_: &Metadata) -> bool {
    false
}

#[cfg(unix)]
fn reject_multiple_links(_: &File, metadata: &Metadata) -> Result<(), Error> {
    if metadata_has_multiple_links(metadata) {
        return reject("invalid_entry");
    }
    Ok(())
}

#[cfg(windows)]
fn reject_multiple_links(file: &File, _: &Metadata) -> Result<(), Error> {
    let information =
        winapi_util::file::information(file).map_err(|_| Error::new("invalid_entry"))?;
    if information.number_of_links() > 1 {
        return reject("invalid_entry");
    }
    Ok(())
}
