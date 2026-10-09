//! The one lowercase hexadecimal and SHA-256 digest grammar every verified reference admits.

use std::fmt::Write as _;

use ring::digest::{Context, SHA256};

const SHA256_PREFIX: &str = "sha256:";

/// The lowercase hexadecimal encoding of `bytes`.
pub(crate) fn lower_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// The bare lowercase hexadecimal SHA-256 of `bytes`.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    lower_hex(ring::digest::digest(&SHA256, bytes).as_ref())
}

/// An incremental SHA-256 whose result is its bare lowercase hexadecimal value.
pub(crate) struct Sha256Hasher(Context);

impl Sha256Hasher {
    pub(crate) fn new() -> Self {
        Self(Context::new(&SHA256))
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    pub(crate) fn finish_hex(self) -> String {
        lower_hex(self.0.finish().as_ref())
    }
}

/// Exactly `length` lowercase hexadecimal characters, the canonical encoding of digests and random identifiers.
pub(crate) fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A bare SHA-256 value: 64 lowercase hexadecimal characters.
pub(crate) fn is_sha256_hex(value: &str) -> bool {
    is_lower_hex(value, 64)
}

/// A `sha256:` digest with a bare SHA-256 value.
pub(crate) fn is_sha256(value: &str) -> bool {
    value.strip_prefix(SHA256_PREFIX).is_some_and(is_sha256_hex)
}

/// An immutable `<repository>@sha256:<hex>` reference to exactly this repository.
pub(crate) fn is_pinned(value: &str, repository: &str) -> bool {
    value
        .strip_prefix(repository)
        .and_then(|suffix| suffix.strip_prefix('@'))
        .is_some_and(is_sha256)
}

#[cfg(test)]
mod tests {
    use super::{Sha256Hasher, is_lower_hex, is_pinned, is_sha256, is_sha256_hex, sha256_hex};

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn admits_only_exact_lowercase_hexadecimal() {
        assert!(is_lower_hex("0123456789abcdef", 16));
        assert!(is_sha256_hex(HEX));
        for invalid in [
            "",
            &HEX[1..],
            &format!("{HEX}0"),
            &HEX.replace('a', "A"),
            &HEX.replace('a', "g"),
        ] {
            assert!(!is_sha256_hex(invalid), "{invalid:?}");
        }
    }

    #[test]
    fn admits_only_the_prefixed_sha256_digest() {
        assert!(is_sha256(&format!("sha256:{HEX}")));
        for invalid in [
            HEX.to_owned(),
            format!("SHA256:{HEX}"),
            format!("sha512:{HEX}"),
            format!("sha256:{}", &HEX[1..]),
            format!("sha256:{}", HEX.replace('a', "A")),
            format!(" sha256:{HEX}"),
        ] {
            assert!(!is_sha256(&invalid), "{invalid}");
        }
    }

    #[test]
    fn admits_only_a_digest_pinned_reference_to_the_exact_repository() {
        let repository = "ghcr.io/theshimpz/shimpz-admin";
        assert!(is_pinned(&format!("{repository}@sha256:{HEX}"), repository));
        for invalid in [
            format!("{repository}:latest"),
            format!("{repository}:tag@sha256:{HEX}"),
            format!("{repository}-evil@sha256:{HEX}"),
            format!("{repository}@sha256:{}", HEX.replace('a', "A")),
            format!("other/{repository}@sha256:{HEX}"),
            format!("{repository}@sha256:{HEX}x"),
        ] {
            assert!(!is_pinned(&invalid, repository), "{invalid}");
        }
    }

    #[test]
    fn hashes_the_fips_180_sha256_vectors() {
        const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(sha256_hex(b"abc"), ABC);
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"a");
        hasher.update(b"bc");
        assert_eq!(hasher.finish_hex(), ABC);
    }
}
