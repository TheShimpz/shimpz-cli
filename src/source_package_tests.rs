use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::source_package::{self, EntryContent, EntryKind, InputEntry};
use crate::ustar;

const VECTORS: &str = include_str!("../contracts/source-package/v1/vectors.json");
static NONCE: AtomicU64 = AtomicU64::new(0);

#[derive(Deserialize)]
struct Vectors {
    version: u8,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    valid: bool,
    error: Option<String>,
    entries: Vec<VectorEntry>,
    #[serde(default)]
    generate: Vec<Generate>,
    sha256: Option<String>,
}

#[derive(Deserialize)]
struct VectorEntry {
    path: String,
    #[serde(rename = "type")]
    kind: String,
    text: Option<String>,
    repeat: Option<Repeat>,
}

#[derive(Deserialize)]
struct Repeat {
    byte: String,
    count: usize,
}

#[derive(Deserialize)]
struct Generate {
    root: String,
    prefix: String,
    suffix: String,
    start: usize,
    count: usize,
    width: usize,
    text: String,
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new() -> Self {
        let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "shimpz-source-package-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("temporary directory");
        Self { path }
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).expect("remove temporary directory");
    }
}

#[test]
fn matches_every_source_package_golden_vector() {
    let vectors: Vectors = serde_json::from_str(VECTORS).expect("valid vectors");
    assert_eq!(vectors.version, 1);
    for case in vectors.cases {
        let entries = vector_entries(&case);
        let result = ustar::build(&entries);
        if case.valid {
            let bytes = result.unwrap_or_else(|error| panic!("{}: {error}", case.name));
            assert_eq!(
                format!("{:x}", Sha256::digest(bytes)),
                case.sha256.expect("valid digest"),
                "{}",
                case.name
            );
        } else {
            assert_eq!(
                result.expect_err(&case.name).code(),
                case.error.as_deref().expect("negative error"),
                "{}",
                case.name
            );
        }
    }
}

#[test]
fn collects_only_publishable_roots_from_disk() {
    let temporary = TemporaryDirectory::new();
    write_minimum(&temporary.path);
    fs::write(temporary.path.join("README.md"), "Local notes.\n").expect("README");

    let package = source_package::build(&temporary.path).expect("source package");

    assert_eq!(
        package.digest,
        "sha256:5afa5d913c54efb877eaa6b12e129e1938d16d3c6eb3a9750587e082604917e0"
    );
    assert_eq!(package.excluded_roots, ["README.md"]);
    assert_eq!(package.bytes.len() % 512, 0);
}

#[test]
fn rejects_hardlinks_inside_publishable_roots() {
    let temporary = TemporaryDirectory::new();
    write_minimum(&temporary.path);
    fs::create_dir(temporary.path.join("lib")).expect("lib");
    let original = temporary.path.join("lib/original.py");
    fs::write(&original, "VALUE = 1\n").expect("original");
    fs::hard_link(&original, temporary.path.join("lib/alias.py")).expect("hardlink");

    let error = source_package::build(&temporary.path)
        .err()
        .expect("hardlink must fail");

    #[cfg(unix)]
    assert_eq!(error, "source package is invalid: special_file");
    #[cfg(windows)]
    assert_eq!(error, "source package is invalid: invalid_entry");
}

#[cfg(unix)]
#[test]
fn rejects_symlinks_inside_publishable_roots() {
    use std::os::unix::fs::symlink;

    let temporary = TemporaryDirectory::new();
    write_minimum(&temporary.path);
    fs::create_dir(temporary.path.join("lib")).expect("lib");
    symlink(
        temporary.path.join("outside.py"),
        temporary.path.join("lib/link.py"),
    )
    .expect("symlink");

    let error = source_package::build(&temporary.path)
        .err()
        .expect("symlink must fail");

    assert_eq!(error, "source package is invalid: special_file");
}

fn write_minimum(root: &Path) {
    fs::create_dir(root.join("powers")).expect("powers");
    fs::write(root.join("shimpz.toml"), "spec = 1\n").expect("manifest");
    fs::write(root.join("pyproject.toml"), "[project]\nname = \"hello\"\n").expect("project");
    fs::write(
        root.join("powers/hello.py"),
        "async def run():\n    return \"hello\"\n",
    )
    .expect("Power");
}

fn vector_entries(case: &Case) -> Vec<InputEntry> {
    let mut entries = case.entries.iter().map(vector_entry).collect::<Vec<_>>();
    for generate in &case.generate {
        for index in generate.start..generate.start + generate.count {
            entries.push(InputEntry {
                path: format!(
                    "{}/{}{:0width$}{}",
                    generate.root,
                    generate.prefix,
                    index,
                    generate.suffix,
                    width = generate.width
                ),
                kind: EntryKind::RegularFile,
                content: EntryContent::Bytes(generate.text.as_bytes().to_vec()),
            });
        }
    }
    entries
}

fn vector_entry(entry: &VectorEntry) -> InputEntry {
    let kind = if entry.kind == "regular_file" {
        EntryKind::RegularFile
    } else {
        EntryKind::Special
    };
    let bytes = entry.repeat.as_ref().map_or_else(
        || {
            entry
                .text
                .as_deref()
                .unwrap_or_default()
                .as_bytes()
                .to_vec()
        },
        |repeat| repeat.byte.as_bytes().repeat(repeat.count),
    );
    InputEntry {
        path: entry.path.clone(),
        kind,
        content: EntryContent::Bytes(bytes),
    }
}
