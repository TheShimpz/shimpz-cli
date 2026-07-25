//! Integrity checks for the pinned source-package v1 authority.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use sha2::{Digest, Sha256};

const FILES: [(&str, &str); 4] = [
    (
        "README.md",
        "891ea6ad588fc462c94dcaca90ffc12e846f24d82ec27cfc04affa966dda1799",
    ),
    (
        "contract.json",
        "a22ecc75e1710e77478bdae066dab1dda656c52140ba815962ee4b8dc4a3ad44",
    ),
    (
        "vectors.json",
        "23136ed5c5b852fe52c88d462dcb1beed925e1862eeb6ec13875fc6de84c1e0b",
    ),
    (
        "verify.py",
        "1225639526745d53ceb0d7d488abb0b84f0ebdfe5c4ee983cee2f187b687eced",
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
        "02bea0d3664b273b1bbbc8a5352a08e8c9289b98315f26a9bc87555481acf706"
    );
    let upstream: Value =
        serde_json::from_slice(&fs::read(root.join("upstream.json")).expect("upstream identity"))
            .expect("valid upstream identity");
    assert_eq!(
        upstream["commit"],
        "e6b4906383e1487ef7221bc7c3f7fdcd194bd74d"
    );
    assert_eq!(upstream["tree"], "c6d8875d0e36513f4b1c4645c8df63dfb66ee00c");
}
