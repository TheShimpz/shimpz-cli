//! The `OpenAI` API key a Creator keeps in one private file of the CLI configuration directory.
//!
//! Only an absent file means "no key". Every other problem fails, so an unsafe, unreadable, or malformed key is never
//! silently replaced by untranslated text. The key is never printed, put in the environment, or passed to Docker.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::config_dir;
use crate::private_file::{self, ReadFailure, Refusal};

/// The key file's name inside the CLI's `shimpz` configuration directory.
pub(crate) const FILE_NAME: &str = "openai-api-key";
const MAX_KEY_BYTES: u64 = 4096;

/// The fixed key path: `~/.config/shimpz/openai-api-key` (or `$XDG_CONFIG_HOME`), `%APPDATA%\shimpz\...` on Windows.
/// Without an OS configuration directory no key file can exist.
pub(crate) fn path() -> Option<PathBuf> {
    config_dir::path().map(|directory| directory.join(FILE_NAME))
}

/// Read the key at `path`, or `None` only when no file exists there.
pub(crate) fn load(path: &Path) -> Result<Option<Zeroizing<String>>, String> {
    let unusable = |reason: &str| {
        format!(
            "the OpenAI API key file {} {reason}; fix it, or remove it to stage with English text",
            path.display()
        )
    };
    let bytes = match private_file::read_admitted(path, MAX_KEY_BYTES, private_file::admit) {
        Ok(bytes) => bytes,
        Err(ReadFailure::Open(error)) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(ReadFailure::Link | ReadFailure::Open(_)) => {
            return Err(unusable("cannot be opened as a regular file"));
        }
        Err(ReadFailure::Inspect(_)) => return Err(unusable("cannot be inspected")),
        Err(ReadFailure::NotAdmitted(Refusal::NotRegularFile)) => {
            return Err(unusable("is not a regular file"));
        }
        #[cfg(unix)]
        Err(ReadFailure::NotAdmitted(Refusal::NotPrivate)) => {
            return Err(unusable(
                "must be owned by you, readable only by you (mode 0600), and have a single link",
            ));
        }
        Err(ReadFailure::Oversized) => return Err(unusable("must hold exactly one API key")),
        Err(ReadFailure::Read(_)) => return Err(unusable("cannot be read")),
    };
    parse(&bytes)
        .map(Some)
        .ok_or_else(|| unusable("must hold exactly one API key"))
}

/// Admit one key of printable ASCII without whitespace, followed by at most one LF or CRLF.
fn parse(bytes: &[u8]) -> Option<Zeroizing<String>> {
    let key = bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .unwrap_or(bytes);
    (!key.is_empty() && key.iter().all(u8::is_ascii_graphic))
        .then(|| Zeroizing::new(key.iter().map(|byte| char::from(*byte)).collect()))
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn write(directory: &Path, bytes: &[u8]) -> PathBuf {
        let path = directory.join(FILE_NAME);
        fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    #[test]
    fn only_an_absent_file_means_no_key() {
        let directory = tempfile::tempdir().unwrap();
        assert!(load(&directory.path().join(FILE_NAME)).unwrap().is_none());
    }

    #[test]
    fn admits_one_key_with_an_optional_line_ending() {
        let directory = tempfile::tempdir().unwrap();
        for bytes in [&b"sk-test-123"[..], b"sk-test-123\n", b"sk-test-123\r\n"] {
            let key = load(&write(directory.path(), bytes)).unwrap().unwrap();
            assert_eq!(key.as_str(), "sk-test-123");
        }
    }

    #[test]
    fn refuses_malformed_contents_without_echoing_them() {
        let directory = tempfile::tempdir().unwrap();
        for bytes in [
            &b""[..],
            b"\n",
            b"sk-test 123",
            b"sk-test-123\n\n",
            b"sk-\ttest",
            "sk-tést".as_bytes(),
            &vec![b'k'; usize::try_from(MAX_KEY_BYTES).unwrap() + 1],
        ] {
            let error = load(&write(directory.path(), bytes)).unwrap_err();
            assert!(error.contains("must hold exactly one API key"), "{error}");
            assert!(!error.contains("sk-"), "{error}");
            assert!(
                error.contains("remove it to stage with English text"),
                "{error}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn refuses_shared_linked_or_special_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = write(directory.path(), b"sk-test-123");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load(&path).unwrap_err().contains("mode 0600"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let hard = directory.path().join("hard");
        fs::hard_link(&path, &hard).unwrap();
        assert!(load(&path).unwrap_err().contains("single link"));
        fs::remove_file(&hard).unwrap();

        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(load(&link).unwrap_err().contains("regular file"));

        let fifo = directory.path().join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        // A FIFO is refused at once instead of blocking for a writer.
        assert!(load(&fifo).unwrap_err().contains("not a regular file"));

        assert!(load(directory.path()).unwrap_err().contains("regular file"));
    }
}
