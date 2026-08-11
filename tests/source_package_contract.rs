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
        "b060ab4e9e0e0debde5413201a409bacfe52bcc1e982a0787448e32f027346ba",
    ),
    (
        "vectors.json",
        "da7116229fbcf070b8d0afa9eca481f6caa60135f97a09c153c614967a4ef7d5",
    ),
    (
        "verify.py",
        "9de01565ffea1348f840a54d484d000543efd16c344e90339cdccb0e86505140",
    ),
];

fn contract_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("contracts/source-package")
}

#[test]
fn vendored_source_package_contract_matches_the_pinned_developers_tree() {
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
        "c1f8e3cff8057b550d5e3ba7059e7bb0432b6c464a559395f51408f025704669"
    );
    let upstream: Value =
        serde_json::from_slice(&fs::read(root.join("upstream.json")).expect("upstream identity"))
            .expect("valid upstream identity");
    assert_eq!(
        upstream["commit"],
        "f0d651b74715cbfe7e252ffc0e9bd28f5864bf88"
    );
    assert_eq!(upstream["tree"], "4dc72d553c424b364766e59f915787e21d084b49");
}
