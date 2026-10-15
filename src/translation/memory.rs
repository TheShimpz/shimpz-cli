//! The workstation's per-message translation memory: one file per message id under one policy (ADR-0091).
//!
//! An entry is reused only after the caller admits it again for the current message declaration, so a corrupt,
//! interrupted, or now too-long entry is simply translated again and replaced.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use crate::language_pack::LOCALES;
use crate::private_file;

/// One entry holds seven bounded texts; anything larger is not an entry this CLI wrote.
const MAX_ENTRY_BYTES: u64 = 64 * 1024;

pub(crate) struct Memory {
    directory: PathBuf,
}

impl Memory {
    pub(crate) const fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    /// The remembered texts of one message, or `None` when absent, unreadable, or not a regular file.
    pub(crate) fn get(&self, id: &str) -> Option<BTreeMap<String, String>> {
        let bytes = private_file::read_admitted(
            &self.directory.join(format!("{id}.json")),
            MAX_ENTRY_BYTES,
            private_file::regular,
        )
        .ok()?;
        let texts: BTreeMap<String, String> = serde_json::from_slice(&bytes).ok()?;
        texts
            .keys()
            .map(String::as_str)
            .eq(LOCALES)
            .then_some(texts)
    }

    /// Atomically remember the admitted texts of one message.
    pub(crate) fn put(&self, id: &str, texts: &BTreeMap<String, String>) -> Result<(), String> {
        let failure = || "the translation memory cannot be stored".to_owned();
        fs::create_dir_all(&self.directory).map_err(|_| failure())?;
        let bytes = serde_json::to_vec(texts).map_err(|_| failure())?;
        let mut file =
            atomic_write_file::AtomicWriteFile::open(self.directory.join(format!("{id}.json")))
                .map_err(|_| failure())?;
        file.write_all(&bytes)
            .and_then(|()| file.commit())
            .map_err(|_| failure())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(text: &str) -> BTreeMap<String, String> {
        LOCALES
            .iter()
            .map(|locale| ((*locale).to_owned(), text.to_owned()))
            .collect()
    }

    #[test]
    fn remembers_complete_entries_and_ignores_anything_else() {
        let directory = tempfile::tempdir().unwrap();
        let memory = Memory::new(directory.path().join("policy"));
        let id = "a".repeat(64);
        assert!(memory.get(&id).is_none());
        memory.put(&id, &texts("Olá")).unwrap();
        assert_eq!(memory.get(&id), Some(texts("Olá")));

        let path = directory.path().join("policy").join(format!("{id}.json"));
        for corrupt in [
            b"{".to_vec(),
            br#"{"pt":"x"}"#.to_vec(),
            serde_json::to_vec(&{
                let mut extra = texts("x");
                extra.insert("en".into(), "x".into());
                extra
            })
            .unwrap(),
            vec![b' '; usize::try_from(MAX_ENTRY_BYTES).unwrap() + 1],
        ] {
            fs::write(&path, corrupt).unwrap();
            assert!(memory.get(&id).is_none());
        }
    }

    #[test]
    fn reports_a_memory_that_cannot_be_written() {
        let directory = tempfile::tempdir().unwrap();
        let blocked = directory.path().join("file");
        fs::write(&blocked, b"").unwrap();
        let memory = Memory::new(blocked.join("policy"));
        assert_eq!(
            memory.put("a", &texts("x")).unwrap_err(),
            "the translation memory cannot be stored"
        );
    }

    #[cfg(unix)]
    #[test]
    fn treats_special_or_linked_entries_as_absent_without_blocking() {
        let directory = tempfile::tempdir().unwrap();
        let memory = Memory::new(directory.path().to_owned());
        let fifo = directory.path().join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let fifo_entry = directory.path().join(format!("{}.json", "f".repeat(64)));
        fs::rename(&fifo, &fifo_entry).unwrap();
        assert!(memory.get(&"f".repeat(64)).is_none());

        let real = directory.path().join("real");
        fs::write(&real, serde_json::to_vec(&texts("x")).unwrap()).unwrap();
        std::os::unix::fs::symlink(
            &real,
            directory.path().join(format!("{}.json", "a".repeat(64))),
        )
        .unwrap();
        assert!(memory.get(&"a".repeat(64)).is_none());
        std::os::unix::fs::symlink(
            &fifo_entry,
            directory.path().join(format!("{}.json", "b".repeat(64))),
        )
        .unwrap();
        assert!(memory.get(&"b".repeat(64)).is_none());

        fs::create_dir(directory.path().join(format!("{}.json", "c".repeat(64)))).unwrap();
        assert!(memory.get(&"c".repeat(64)).is_none());
    }
}
