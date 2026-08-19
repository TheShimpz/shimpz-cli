//! Integrity checks for the pinned source-package v1 authority.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use sha2::{Digest, Sha256};

const FILES: [(&str, &str); 4] = [
    (
        "README.md",
        "b442b89c35440c939c1ede0818c235a1d8fbcb76fa6dbd652efce487e95a7626",
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
        "8ec6520349afd75423131df2d9a78f262d2be6a88892c96c73ce700572903f96"
    );
    let upstream: Value =
        serde_json::from_slice(&fs::read(root.join("upstream.json")).expect("upstream identity"))
            .expect("valid upstream identity");
    assert_eq!(
        upstream["commit"],
        "f602133860482241f8030e25a11e3a0f0dfe259d"
    );
    assert_eq!(upstream["tree"], "614d308e27d248ce5961327beb9789ae4b969ec6");
}
