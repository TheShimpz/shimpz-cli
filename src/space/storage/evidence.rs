//! Native Linux LUKS2 evidence parsing.

use serde_json::Value;

pub(crate) const MIN_CRYPTSETUP_VERSION: (u32, u32) = (2, 4);

pub(crate) fn cryptsetup_version(value: &str) -> Option<(u32, u32, u32)> {
    let mut lines = value.lines();
    let line = lines.next().filter(|line| !line.is_empty())?;
    if lines.next().is_some() {
        return None;
    }
    let mut fields = line.split_ascii_whitespace();
    if fields.next() != Some("cryptsetup") {
        return None;
    }
    let mut numbers = fields.next()?.split('.');
    let version = (
        decimal_component(numbers.next()?)?,
        decimal_component(numbers.next()?)?,
        decimal_component(numbers.next()?)?,
    );
    if numbers.next().is_some() {
        return None;
    }
    Some(version)
}

pub(crate) fn cryptsetup_version_supported(version: (u32, u32, u32)) -> bool {
    (version.0, version.1) >= MIN_CRYPTSETUP_VERSION
}

fn decimal_component(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

pub(crate) fn luks_dump_valid(value: &str) -> bool {
    exactly_one(value, "Version:")
        && exactly_one_trimmed(value, "cipher:")
        && exactly_one_trimmed(value, "Key:")
        && exactly_one_trimmed(value, "PBKDF:")
        && exactly_one_trimmed(value, "Time cost:")
        && exactly_one_trimmed(value, "Memory:")
        && exactly_one_trimmed(value, "Threads:")
        && has_exact(value, "Version:", "2")
        && has_exact_trimmed(value, "cipher:", "aes-xts-plain64")
        && has_exact_trimmed(value, "Key:", "512 bits")
        && has_exact_trimmed(value, "PBKDF:", "argon2id")
        && has_exact_trimmed(value, "Time cost:", "8")
        && has_exact_trimmed(value, "Memory:", "262144")
        && has_exact_trimmed(value, "Threads:", "4")
}

pub(crate) fn luks_unlock_credentials_valid(value: &str) -> bool {
    let Ok(metadata) = serde_json::from_str::<Value>(value) else {
        return false;
    };
    let Some(metadata) = metadata.as_object() else {
        return false;
    };
    let Some(keyslots) = metadata.get("keyslots").and_then(Value::as_object) else {
        return false;
    };
    let Some(tokens) = metadata.get("tokens").and_then(Value::as_object) else {
        return false;
    };
    keyslots.len() == 1
        && keyslots
            .get("0")
            .and_then(Value::as_object)
            .is_some_and(|slot| slot.get("type").and_then(Value::as_str) == Some("luks2"))
        && tokens.is_empty()
}

fn exactly_one(value: &str, prefix: &str) -> bool {
    value
        .lines()
        .filter(|line| line.starts_with(prefix))
        .count()
        == 1
}

fn exactly_one_trimmed(value: &str, prefix: &str) -> bool {
    value
        .lines()
        .filter(|line| line.trim_start().starts_with(prefix))
        .count()
        == 1
}

fn has_exact(value: &str, prefix: &str, expected: &str) -> bool {
    value.lines().any(|line| {
        line.strip_prefix(prefix)
            .is_some_and(|rest| rest.trim() == expected)
    })
}

fn has_exact_trimmed(value: &str, prefix: &str, expected: &str) -> bool {
    value.lines().any(|line| {
        line.trim_start()
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.trim() == expected)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LUKS: &str = "Version:       2\n  cipher:     aes-xts-plain64\n  Key:        512 bits\n  PBKDF:      argon2id\n  Time cost:  8\n  Memory:     262144\n  Threads:    4\n";

    #[test]
    fn parses_only_strict_cryptsetup_versions() {
        for (document, expected) in [
            ("cryptsetup 2.4.0\n", (2, 4, 0)),
            (
                "cryptsetup 2.7.5 flags: UDEV BLKID KEYRING KERNEL_CAPI",
                (2, 7, 5),
            ),
            ("cryptsetup 2.10.0", (2, 10, 0)),
            ("cryptsetup 10.0.0", (10, 0, 0)),
            (" cryptsetup 2.4.0 ", (2, 4, 0)),
        ] {
            assert_eq!(cryptsetup_version(document), Some(expected));
        }
        for document in [
            "",
            "\n",
            "cryptsetup",
            "cryptsetup 2.4",
            "cryptsetup 2.4.0.1",
            "cryptsetup 2.4.0-rc1",
            "cryptsetup +2.4.0",
            "cryptsetup 2.+4.0",
            "cryptsetup 2.4.+0",
            "cryptsetup 2..0",
            "Cryptsetup 2.4.0",
            "cryptsetup 2.4.0\nextra",
            "cryptsetup 4294967296.4.0",
        ] {
            assert_eq!(cryptsetup_version(document), None);
        }
    }

    #[test]
    fn admits_only_supported_cryptsetup_versions() {
        for version in [(2, 4, 0), (2, 10, 0), (3, 0, 0), (10, 0, 0)] {
            assert!(cryptsetup_version_supported(version));
        }
        for version in [(2, 3, 7), (1, 7, 5)] {
            assert!(!cryptsetup_version_supported(version));
        }
    }

    #[test]
    fn parses_only_exact_luks2_parameters() {
        assert!(luks_dump_valid(LUKS));
        for invalid in [
            LUKS.replace("Version:       2", "Version:       1"),
            LUKS.replace("aes-xts-plain64", "aes-cbc"),
            LUKS.replace("512 bits", "256 bits"),
            LUKS.replace("argon2id", "pbkdf2"),
            LUKS.replace("Time cost:  8", "Time cost:  7"),
            LUKS.replace("Memory:     262144", "Memory:     131072"),
            LUKS.replace("Threads:    4", "Threads:    2"),
            format!("{LUKS}Version:       2\n"),
            format!("{LUKS}  Memory:     262144\n"),
        ] {
            assert!(!luks_dump_valid(&invalid));
        }
    }

    #[test]
    fn admits_only_one_human_unlock_credential() {
        let valid = r#"{"keyslots":{"0":{"type":"luks2"}},"tokens":{}}"#;
        assert!(luks_unlock_credentials_valid(valid));
        for invalid in [
            "not-json",
            "[]",
            r#"{"tokens":{}}"#,
            r#"{"keyslots":[],"tokens":{}}"#,
            r#"{"keyslots":{},"tokens":{}}"#,
            r#"{"keyslots":{"0":{"type":"luks2"},"1":{"type":"luks2"}},"tokens":{}}"#,
            r#"{"keyslots":{"1":{"type":"luks2"}},"tokens":{}}"#,
            r#"{"keyslots":{"0":[]},"tokens":{}}"#,
            r#"{"keyslots":{"0":{}},"tokens":{}}"#,
            r#"{"keyslots":{"0":{"type":"reencrypt"}},"tokens":{}}"#,
            r#"{"keyslots":{"0":{"type":"luks2"}}}"#,
            r#"{"keyslots":{"0":{"type":"luks2"}},"tokens":[]}"#,
            r#"{"keyslots":{"0":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2"}}}"#,
        ] {
            assert!(!luks_unlock_credentials_valid(invalid));
        }
    }
}
