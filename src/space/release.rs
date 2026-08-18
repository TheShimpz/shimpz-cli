//! Closed atomic Local release metadata.

use std::collections::BTreeMap;

pub(crate) const RELEASE_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-local-release";
const ADMIN_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-admin";
const TEAM_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-team-local";
const BRAIN_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-brain";
const EGRESS_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-egress";
const KEYS: [&str; 10] = [
    "schema",
    "ordinal",
    "umbrella_revision",
    "cli_revision",
    "cli_linux_amd64_sha256",
    "cli_macos_arm64_sha256",
    "admin",
    "team",
    "brain",
    "egress",
];

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Release {
    pub(crate) ordinal: u64,
    pub(crate) umbrella_revision: String,
    pub(crate) cli_revision: String,
    pub(crate) cli_linux_amd64_sha256: String,
    pub(crate) cli_macos_arm64_sha256: String,
    pub(crate) admin: String,
    pub(crate) team: String,
    pub(crate) brain: String,
    pub(crate) egress: String,
}

pub(crate) fn parse(document: &str) -> Result<Release, String> {
    if document.len() > 2_048 || document.contains('\r') {
        return Err("the Local release metadata is malformed".into());
    }
    let mut values = BTreeMap::new();
    for line in document.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| "the Local release metadata is malformed".to_owned())?;
        if key.is_empty()
            || value.is_empty()
            || value.contains('=')
            || values.insert(key, value).is_some()
        {
            return Err("the Local release metadata is malformed".into());
        }
    }
    if values.len() != KEYS.len() || KEYS.iter().any(|key| !values.contains_key(key)) {
        return Err("the Local release metadata contains an unknown or missing field".into());
    }
    if values["schema"] != "local-v2" {
        return Err("the Local release schema is unsupported".into());
    }
    let ordinal = values["ordinal"]
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| "the Local release ordinal is invalid".to_owned())?;
    for key in ["umbrella_revision", "cli_revision"] {
        if !valid_hex(values[key], 40) {
            return Err(format!("the Local release {key} is invalid"));
        }
    }
    for key in ["cli_linux_amd64_sha256", "cli_macos_arm64_sha256"] {
        if !valid_hex(values[key], 64) {
            return Err(format!("the Local release {key} is invalid"));
        }
    }
    for (key, repository) in [
        ("admin", ADMIN_REPOSITORY),
        ("team", TEAM_REPOSITORY),
        ("brain", BRAIN_REPOSITORY),
        ("egress", EGRESS_REPOSITORY),
    ] {
        if !valid_digest_ref(values[key], repository) {
            return Err(format!("the Local release {key} image is invalid"));
        }
    }
    Ok(Release {
        ordinal,
        umbrella_revision: values["umbrella_revision"].into(),
        cli_revision: values["cli_revision"].into(),
        cli_linux_amd64_sha256: values["cli_linux_amd64_sha256"].into(),
        cli_macos_arm64_sha256: values["cli_macos_arm64_sha256"].into(),
        admin: values["admin"].into(),
        team: values["team"].into(),
        brain: values["brain"].into(),
        egress: values["egress"].into(),
    })
}

pub(crate) fn valid_release_ref(value: &str) -> bool {
    valid_digest_ref(value, RELEASE_REPOSITORY)
}

fn valid_digest_ref(value: &str, repository: &str) -> bool {
    value
        .strip_prefix(repository)
        .and_then(|suffix| suffix.strip_prefix("@sha256:"))
        .is_some_and(|digest| valid_hex(digest, 64))
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX_40: &str = "0123456789abcdef0123456789abcdef01234567";
    const HEX_64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn valid() -> String {
        format!(
            "schema=local-v2\nordinal=42\numbrella_revision={HEX_40}\ncli_revision={HEX_40}\ncli_linux_amd64_sha256={HEX_64}\ncli_macos_arm64_sha256={HEX_64}\nadmin={ADMIN_REPOSITORY}@sha256:{HEX_64}\nteam={TEAM_REPOSITORY}@sha256:{HEX_64}\nbrain={BRAIN_REPOSITORY}@sha256:{HEX_64}\negress={EGRESS_REPOSITORY}@sha256:{HEX_64}\n"
        )
    }

    #[test]
    fn parses_only_the_closed_current_release() {
        let release = parse(&valid()).unwrap();
        assert_eq!(release.ordinal, 42);
        assert_eq!(release.cli_revision, HEX_40);
        assert_eq!(release.admin, format!("{ADMIN_REPOSITORY}@sha256:{HEX_64}"));
        assert!(valid_release_ref(&format!(
            "{RELEASE_REPOSITORY}@sha256:{HEX_64}"
        )));
        assert!(!valid_release_ref(&format!("{RELEASE_REPOSITORY}:stable")));
    }

    #[test]
    fn rejects_unknown_missing_duplicate_and_retired_fields() {
        for invalid in [
            "malformed".into(),
            valid().replace("schema=local-v2\n", "schema=local-v1\n"),
            valid().replace("ordinal=42\n", ""),
            format!("{}unknown=value\n", valid()),
            format!("{}ordinal=43\n", valid()),
            valid().replace("cli_revision=", "reconciler_sha256="),
        ] {
            assert!(parse(&invalid).is_err(), "accepted: {invalid}");
        }
    }

    #[test]
    fn rejects_malformed_values_and_untrusted_repositories() {
        for invalid in [
            valid().replace("ordinal=42", "ordinal=0"),
            valid().replace(HEX_40, "ABC"),
            valid().replacen(HEX_64, "ABC", 1),
            valid().replace(ADMIN_REPOSITORY, "example.invalid/admin"),
            valid().replace("schema=local-v2", "schema=local-v2=extra"),
            valid().replace('\n', "\r\n"),
            "x".repeat(2_049),
        ] {
            assert!(parse(&invalid).is_err());
        }
    }
}
