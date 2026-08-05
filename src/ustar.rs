//! Emit the canonical POSIX ustar source-package representation.

use std::collections::{BTreeMap, BTreeSet};

use crate::source_package::{EntryKind, Error, InputEntry, reject, validate_icon};

const BLOCK: usize = 512;
const MAX_FILES: usize = 10_000;
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ICON_BYTES: u64 = 1024 * 1024;
const MAX_PACKAGE_BYTES: u64 = 32 * 1024 * 1024;

struct Record<'a> {
    path: String,
    content: Option<&'a InputEntry>,
}

pub(crate) fn build(entries: &[InputEntry]) -> Result<Vec<u8>, Error> {
    validate(entries)?;
    let records = records(entries)?;
    let package_size = archive_size(&records);
    if package_size > MAX_PACKAGE_BYTES {
        return reject("package_too_large");
    }
    let mut archive = Vec::with_capacity(usize::try_from(package_size).unwrap_or(0));
    for record in records {
        let content = record
            .content
            .map_or_else(|| Ok(Vec::new()), |entry| entry.content.read())?;
        archive.extend_from_slice(&header(
            &record.path,
            record.content.is_none(),
            content.len(),
        )?);
        archive.extend_from_slice(&content);
        archive.resize(archive.len() + padding(content.len()), 0);
    }
    archive.resize(archive.len() + 2 * BLOCK, 0);
    Ok(archive)
}

fn validate(entries: &[InputEntry]) -> Result<(), Error> {
    let mut exact = BTreeSet::new();
    let mut collisions = BTreeMap::new();
    for entry in entries {
        if entry.kind != EntryKind::RegularFile {
            return reject("special_file");
        }
        let components = validate_path(&entry.path)?;
        if !exact.insert(entry.path.as_str()) {
            return reject("duplicate_path");
        }
        let key = entry.path.to_ascii_lowercase();
        if collisions.insert(key, entry.path.as_str()).is_some() {
            return reject("case_collision");
        }
        validate_allowlist(&entry.path, &components)?;
    }
    validate_required(entries)?;
    if entries.len() > MAX_FILES {
        return reject("file_count_exceeded");
    }
    if entries
        .iter()
        .any(|entry| entry.content.size() > MAX_FILE_BYTES)
    {
        return reject("single_file_too_large");
    }
    let icon = entries
        .iter()
        .find(|entry| entry.path == "icon.png")
        .ok_or_else(|| Error::new("missing_required_file"))?;
    if icon.content.size() > MAX_ICON_BYTES {
        return reject("icon_too_large");
    }
    validate_icon(&icon.content.read()?)?;
    Ok(())
}

fn validate_path(path: &str) -> Result<Vec<&str>, Error> {
    if !path.is_ascii() {
        return reject("non_ascii_path");
    }
    if path.starts_with('/') {
        return reject("absolute_path");
    }
    let components = path.split('/').collect::<Vec<_>>();
    if components.iter().any(|part| matches!(*part, "." | "..")) {
        return reject("traversal");
    }
    if components
        .iter()
        .any(|part| part.is_empty() || !portable_segment(part))
    {
        return reject("invalid_path_segment");
    }
    if components.len() > 16 {
        return reject("path_too_deep");
    }
    split_path(path)?;
    Ok(components)
}

fn validate_allowlist(path: &str, components: &[&str]) -> Result<(), Error> {
    match components {
        ["powers", filename] if power_filename(filename) => Ok(()),
        ["powers", _] => reject("invalid_entry"),
        ["powers", ..] => reject("nested_power"),
        ["icon.png" | "shimpz.toml" | "pyproject.toml"] | ["lib" | "tests", _, ..] => Ok(()),
        _ if matches!(path, "icon.png" | "shimpz.toml" | "pyproject.toml") => Ok(()),
        _ => reject("unknown_root"),
    }
}

fn validate_required(entries: &[InputEntry]) -> Result<(), Error> {
    let paths = entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    if !paths.contains("icon.png")
        || !paths.contains("shimpz.toml")
        || !paths.contains("pyproject.toml")
    {
        return reject("missing_required_file");
    }
    if !paths.iter().any(|path| path.starts_with("powers/")) {
        return reject("missing_power");
    }
    Ok(())
}

fn records(entries: &[InputEntry]) -> Result<Vec<Record<'_>>, Error> {
    let mut directories = BTreeSet::new();
    for entry in entries {
        let components = entry.path.split('/').collect::<Vec<_>>();
        for end in 1..components.len() {
            directories.insert(components[..end].join("/"));
        }
    }
    let mut records = directories
        .into_iter()
        .map(|path| Record {
            path,
            content: None,
        })
        .chain(entries.iter().map(|entry| Record {
            path: entry.path.clone(),
            content: Some(entry),
        }))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.path.cmp(&right.path));
    for record in &records {
        split_path(&record.path)?;
    }
    Ok(records)
}

fn archive_size(records: &[Record<'_>]) -> u64 {
    records.iter().fold((2 * BLOCK) as u64, |total, record| {
        let size = record.content.map_or(0, |entry| entry.content.size());
        total + BLOCK as u64 + size.div_ceil(BLOCK as u64) * BLOCK as u64
    })
}

fn header(path: &str, directory: bool, size: usize) -> Result<[u8; BLOCK], Error> {
    let (prefix, name) = split_path(path)?;
    let mut header = [0_u8; BLOCK];
    put(&mut header, 0, 100, name.as_bytes())?;
    put_octal(&mut header, 100, 8, if directory { 0o755 } else { 0o644 })?;
    put_octal(&mut header, 108, 8, 0)?;
    put_octal(&mut header, 116, 8, 0)?;
    put_octal(&mut header, 124, 12, size as u64)?;
    put_octal(&mut header, 136, 12, 0)?;
    put(&mut header, 148, 8, b"        ")?;
    put(&mut header, 156, 1, if directory { b"5" } else { b"0" })?;
    put(&mut header, 257, 6, b"ustar\0")?;
    put(&mut header, 263, 2, b"00")?;
    put_octal(&mut header, 329, 8, 0)?;
    put_octal(&mut header, 337, 8, 0)?;
    put(&mut header, 345, 155, prefix.as_bytes())?;
    let checksum = format!(
        "{:06o}\0 ",
        header.iter().map(|byte| u64::from(*byte)).sum::<u64>()
    );
    put(&mut header, 148, 8, checksum.as_bytes())?;
    Ok(header)
}

fn split_path(path: &str) -> Result<(&str, &str), Error> {
    if path.len() > 256 {
        return reject("path_too_long");
    }
    if path.len() <= 100 {
        return Ok(("", path));
    }
    let Some((prefix, name)) = path.rsplit_once('/') else {
        return reject("ustar_name_too_long");
    };
    if prefix.len() > 155 {
        return reject("ustar_prefix_too_long");
    }
    if name.len() > 100 {
        return reject("ustar_name_too_long");
    }
    Ok((prefix, name))
}

fn put(header: &mut [u8; BLOCK], offset: usize, width: usize, value: &[u8]) -> Result<(), Error> {
    if value.len() > width {
        return reject("invalid_entry");
    }
    header[offset..offset + value.len()].copy_from_slice(value);
    Ok(())
}

fn put_octal(
    header: &mut [u8; BLOCK],
    offset: usize,
    width: usize,
    value: u64,
) -> Result<(), Error> {
    let field = format!("{value:0width$o}\0", width = width - 1);
    if field.len() != width {
        return reject("invalid_entry");
    }
    put(header, offset, width, field.as_bytes())
}

fn padding(size: usize) -> usize {
    (BLOCK - size % BLOCK) % BLOCK
}

fn portable_segment(segment: &str) -> bool {
    segment
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn power_filename(filename: &str) -> bool {
    let Some(stem) = filename.strip_suffix(".py") else {
        return false;
    };
    !stem.is_empty()
        && stem.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-')
                || (index > 0 && byte == b'.')
        })
}
