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
        "e458d431a14b17f3cedd938dad786c5b05f5ccdb23a03e4a8c31371ed81b7e4a",
    ),
    (
        "verify.py",
        "013113acace828c37e929f85624a22d7584076e306af60615f98d5cfd9a8c290",
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
        "c1f83364fc9b1b07e7bc014d48637dffd0c1d61eb7cdfe46063e1497aa869a43"
    );
    let upstream: Value =
        serde_json::from_slice(&fs::read(root.join("upstream.json")).expect("upstream identity"))
            .expect("valid upstream identity");
    assert_eq!(
        upstream["commit"],
        "62baa183c053143bea47ce128cfcab8884b9555d"
    );
    assert_eq!(upstream["tree"], "a9840a62a671be7fd7cff9cb24d89529e4404bd1");
}
