//! Read one exported file from the single-entry tar stream that `docker cp CONTAINER:PATH -` writes.
//!
//! The reader admits exactly one plain ustar regular-file entry followed only by zero blocks, so a link, a
//! directory, an extension header, or any second entry fails closed instead of being interpreted.

const BLOCK: usize = 512;

/// One regular file with the ownership and permissions recorded in its archive header.
#[derive(Debug)]
pub(crate) struct ArchivedFile {
    pub(crate) mode: u32,
    pub(crate) uid: u64,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) fn single_file(
    archive: &[u8],
    name: &str,
    limit: usize,
) -> Result<ArchivedFile, &'static str> {
    let header = archive.get(..BLOCK).ok_or("archive_shape")?;
    if !valid_checksum(header) || !header[257..].starts_with(b"ustar") {
        return Err("archive_header");
    }
    if text(&header[..100]) != Some(name) || text(&header[345..500]) != Some("") {
        return Err("archive_name");
    }
    if !matches!(header[156], b'0' | 0) {
        return Err("archive_type");
    }
    let size = usize::try_from(octal(&header[124..136]).ok_or("archive_header")?)
        .map_err(|_| "archive_bounds")?;
    if size > limit {
        return Err("archive_bounds");
    }
    let end = BLOCK + size;
    let bytes = archive.get(BLOCK..end).ok_or("archive_shape")?.to_vec();
    if archive[end..].iter().any(|byte| *byte != 0) {
        return Err("archive_shape");
    }
    let mode = u32::try_from(octal(&header[100..108]).ok_or("archive_header")?)
        .map_err(|_| "archive_header")?;
    let uid = octal(&header[108..116]).ok_or("archive_header")?;
    Ok(ArchivedFile { mode, uid, bytes })
}

fn valid_checksum(header: &[u8]) -> bool {
    let recorded = octal(&header[148..156]);
    let computed = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum::<u64>();
    recorded == Some(computed)
}

fn text(field: &[u8]) -> Option<&str> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0) {
        return None;
    }
    std::str::from_utf8(&field[..end]).ok()
}

fn octal(field: &[u8]) -> Option<u64> {
    let digits = field
        .iter()
        .copied()
        .take_while(|byte| *byte != 0 && *byte != b' ')
        .collect::<Vec<_>>();
    if digits.is_empty()
        || field[digits.len()..]
            .iter()
            .any(|byte| !matches!(byte, 0 | b' '))
    {
        return None;
    }
    digits.iter().try_fold(0_u64, |value, digit| {
        (b'0'..=b'7')
            .contains(digit)
            .then(|| value.checked_mul(8)?.checked_add(u64::from(digit - b'0')))
            .flatten()
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// One single-entry archive like `docker cp` writes.
    pub(crate) fn archive(name: &str, mode: u32, entry: tar::EntryType, bytes: &[u8]) -> Vec<u8> {
        let mut header = tar::Header::new_ustar();
        header.set_path(name).unwrap();
        header.set_mode(mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_size(bytes.len() as u64);
        header.set_entry_type(entry);
        header.set_cksum();
        let mut builder = tar::Builder::new(Vec::new());
        builder.append(&header, bytes).unwrap();
        builder.into_inner().unwrap()
    }

    #[test]
    fn reads_exactly_one_regular_file() {
        let file = single_file(
            &archive("shimpz.pack.json", 0o444, tar::EntryType::Regular, b"{}"),
            "shimpz.pack.json",
            16,
        )
        .expect("regular file");
        assert_eq!(
            (file.mode, file.uid, file.bytes.as_slice()),
            (0o444, 0, &b"{}"[..])
        );
    }

    #[test]
    fn refuses_every_other_archive_shape() {
        let regular = archive("shimpz.pack.json", 0o444, tar::EntryType::Regular, b"{}");
        assert_eq!(
            single_file(&regular, "shimpz.contract.json", 16).unwrap_err(),
            "archive_name"
        );
        assert_eq!(
            single_file(&regular, "shimpz.pack.json", 1).unwrap_err(),
            "archive_bounds"
        );
        let link = archive("shimpz.pack.json", 0o777, tar::EntryType::Symlink, b"");
        assert_eq!(
            single_file(&link, "shimpz.pack.json", 16).unwrap_err(),
            "archive_type"
        );
        let mut two = regular.clone();
        two.truncate(1024);
        two.extend(archive("other", 0o444, tar::EntryType::Regular, b"x"));
        assert_eq!(
            single_file(&two, "shimpz.pack.json", 16).unwrap_err(),
            "archive_shape"
        );
        let mut corrupted = regular;
        corrupted[100] = b'1';
        assert_eq!(
            single_file(&corrupted, "shimpz.pack.json", 16).unwrap_err(),
            "archive_header"
        );
        assert!(single_file(&[], "shimpz.pack.json", 16).is_err());
    }
}
