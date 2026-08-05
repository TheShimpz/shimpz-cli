//! Integrity checks for the pinned source-package v1 authority.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use sha2::{Digest, Sha256};

const FILES: [(&str, &str); 4] = [
    (
        "README.md",
        "03f39efbcd2b047cc9b68f764dbaf080704dc033ee7dea18639c6dd00cfdca9b",
    ),
    (
        "contract.json",
        "27cc783eedef5488b357b16e4e05af24ec46498f86450c44af1d760cae26f0bb",
    ),
    (
        "vectors.json",
        "24f42e4f479ec04272790b4f1ddb21ea8821585feba6c5f337ae0bf02aa8442d",
    ),
    (
        "verify.py",
        "1f31a4ac2715531584493cc2d3dd3314db6318d9a4046214060a990f4cc81fb9",
    ),
];

fn contract_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("contracts/source-package")
}

#[test]
fn vendored_source_package_contract_matches_the_pinned_docs_tree() {
    let root = contract_root();
    let mirror = root.join("v1");
    let mut names = fs::read_dir(&mirror)
        .expect("contract directory")
        .map(|entry| entry.expect("contract entry").file_name())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        [
            "README.md",
            "contract-files.sha256",
            "contract.json",
            "vectors.json",
            "verify.py"
        ]
    );

    for (filename, expected) in FILES {
        let bytes = fs::read(mirror.join(filename)).expect("contract file");
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            expected,
            "{filename}"
        );
    }

    let checksums = fs::read(mirror.join("contract-files.sha256")).expect("checksum manifest");
    assert_eq!(
        format!("{:x}", Sha256::digest(&checksums)),
        "5ee3ad0c7d53f56304528861585b702c87e0c83a2bd11c6c9b4feb3ab2ffb3cf"
    );
    let upstream: Value =
        serde_json::from_slice(&fs::read(root.join("upstream.json")).expect("upstream identity"))
            .expect("valid upstream identity");
    assert_eq!(
        upstream["commit"],
        "38966a38c41712ecf68383541bc007a801a514cc"
    );
    assert_eq!(upstream["tree"], "6f1937d5c1785f0c79892f1efa873761acb45d1a");
}
