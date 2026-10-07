//! Closed atomic Local release metadata.
//!
//! A published release set lives under `ghcr.io/theshimpz/` and uses the closed `local-v2` schema with GHCR members
//! only. A developer release is built on the owner's host by the deploy pipeline, exists only in that host's Docker
//! image store under `localhost/`, and uses the closed `local-dev-v2` schema: the published fields without the macOS
//! CLI, because a developer release applies only to an amd64 Linux Space; each member is its package's GHCR or
//! `localhost/` digest reference. The reference namespace selects the schema, so neither can pass as the other.
//!
//! Every release set also declares its runtime state epoch in the image label [`STATE_EPOCH_LABEL`]. A different
//! epoch means the release reads a different stored format of the disposable Team and Brain runtime state, which is
//! recreated instead of migrated.

use std::collections::BTreeMap;

use crate::digest;

pub(crate) const RELEASE_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-local-release";
pub(crate) const DEVELOPER_RELEASE_REPOSITORY: &str = "localhost/shimpz-local-release";
pub(crate) const STATE_EPOCH_LABEL: &str = "org.shimpz.local.state-epoch";
const PUBLISHED_NAMESPACE: &str = "ghcr.io/theshimpz/";
const DEVELOPER_NAMESPACE: &str = "localhost/";
const PUBLISHED_SCHEMA: &str = "local-v2";
const DEVELOPER_SCHEMA: &str = "local-dev-v2";
const MACOS_CLI_KEY: &str = "cli_macos_arm64_sha256";
const KEYS: [&str; 10] = [
    "schema",
    "ordinal",
    "umbrella_revision",
    "cli_revision",
    "cli_linux_amd64_sha256",
    MACOS_CLI_KEY,
    "admin",
    "team",
    "brain",
    "egress",
];

/// One platform component's OCI package, admitted under the published or the developer namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Package(&'static str);

pub(crate) const ADMIN: Package = Package("shimpz-admin");
pub(crate) const TEAM: Package = Package("shimpz-team-local");
pub(crate) const BRAIN: Package = Package("shimpz-brain");
pub(crate) const EGRESS: Package = Package("shimpz-egress");

impl Package {
    /// Exactly `ghcr.io/theshimpz/<package>@sha256:<hex>`.
    pub(crate) fn published(self, value: &str) -> bool {
        in_namespace(value, PUBLISHED_NAMESPACE, self.0)
    }

    /// Exactly `localhost/<package>@sha256:<hex>`: an image present only in this host's Docker store.
    pub(crate) fn developer(self, value: &str) -> bool {
        in_namespace(value, DEVELOPER_NAMESPACE, self.0)
    }

    /// Either exact form of this package.
    pub(crate) fn admits(self, value: &str) -> bool {
        self.published(value) || self.developer(value)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Release {
    pub(crate) ordinal: u64,
    pub(crate) umbrella_revision: String,
    pub(crate) cli_revision: String,
    pub(crate) cli_linux_amd64_sha256: String,
    /// The macOS CLI of a published release; a developer release carries none.
    pub(crate) cli_macos_arm64_sha256: Option<String>,
    pub(crate) admin: String,
    pub(crate) team: String,
    pub(crate) brain: String,
    pub(crate) egress: String,
    /// The stored-format epoch of the disposable runtime state this release reads.
    pub(crate) state_epoch: u32,
}

impl Release {
    fn members(&self) -> [(&'static str, Package, &str); 4] {
        [
            ("admin", ADMIN, &self.admin),
            ("team", TEAM, &self.team),
            ("brain", BRAIN, &self.brain),
            ("egress", EGRESS, &self.egress),
        ]
    }
}

/// Parse a state epoch: a positive decimal without leading zeros.
pub(crate) fn parse_state_epoch(value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .ok()
        .filter(|epoch| *epoch > 0 && epoch.to_string() == value)
        .ok_or_else(|| "the Local release state epoch is invalid".to_owned())
}

/// Parse the metadata of the release set at `reference` with its state epoch label; the reference namespace
/// selects the only admissible schema.
pub(crate) fn parse(reference: &str, document: &str, state_epoch: &str) -> Result<Release, String> {
    let developer = if valid_published_release_ref(reference) {
        false
    } else if valid_developer_release_ref(reference) {
        true
    } else {
        return Err("the Local release reference is invalid".into());
    };
    let values = key_values(document, 2_048, "the Local release metadata is malformed")?;
    let keys = KEYS
        .iter()
        .filter(|key| !developer || **key != MACOS_CLI_KEY);
    if values.len() != keys.clone().count() || keys.into_iter().any(|key| !values.contains_key(key))
    {
        return Err("the Local release metadata contains an unknown or missing field".into());
    }
    let schema = if developer {
        DEVELOPER_SCHEMA
    } else {
        PUBLISHED_SCHEMA
    };
    if values["schema"] != schema {
        return Err("the Local release schema is unsupported".into());
    }
    let ordinal = values["ordinal"]
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| "the Local release ordinal is invalid".to_owned())?;
    for key in ["umbrella_revision", "cli_revision"] {
        if !digest::is_lower_hex(values[key], 40) {
            return Err(format!("the Local release {key} is invalid"));
        }
    }
    let macos = values.get(MACOS_CLI_KEY).map(|value| (*value).to_owned());
    for value in std::iter::once(values["cli_linux_amd64_sha256"]).chain(macos.as_deref()) {
        if !digest::is_sha256_hex(value) {
            return Err("the Local release CLI hash is invalid".into());
        }
    }
    let release = Release {
        ordinal,
        umbrella_revision: values["umbrella_revision"].into(),
        cli_revision: values["cli_revision"].into(),
        cli_linux_amd64_sha256: values["cli_linux_amd64_sha256"].into(),
        cli_macos_arm64_sha256: macos,
        admin: values["admin"].into(),
        team: values["team"].into(),
        brain: values["brain"].into(),
        egress: values["egress"].into(),
        state_epoch: parse_state_epoch(state_epoch)?,
    };
    for (key, package, value) in release.members() {
        let admitted = if developer {
            package.admits(value)
        } else {
            package.published(value)
        };
        if !admitted {
            return Err(format!("the Local release {key} image is invalid"));
        }
    }
    Ok(release)
}

/// A published or developer release set reference.
pub(crate) fn valid_release_ref(value: &str) -> bool {
    valid_published_release_ref(value) || valid_developer_release_ref(value)
}

pub(crate) fn valid_published_release_ref(value: &str) -> bool {
    digest::is_pinned(value, RELEASE_REPOSITORY)
}

pub(crate) fn valid_developer_release_ref(value: &str) -> bool {
    digest::is_pinned(value, DEVELOPER_RELEASE_REPOSITORY)
}

fn in_namespace(value: &str, namespace: &str, package: &str) -> bool {
    value
        .strip_prefix(namespace)
        .is_some_and(|rest| digest::is_pinned(rest, package))
}

/// Parse a bounded document of unique, non-empty `KEY=VALUE` lines without carriage returns; any other shape is
/// `malformed`.
pub(crate) fn key_values<'a>(
    document: &'a str,
    limit: u64,
    malformed: &str,
) -> Result<BTreeMap<&'a str, &'a str>, String> {
    if document.len() as u64 > limit || document.contains('\r') {
        return Err(malformed.into());
    }
    let mut values = BTreeMap::new();
    for line in document.lines() {
        let (key, value) = line.split_once('=').ok_or_else(|| malformed.to_owned())?;
        if key.is_empty()
            || value.is_empty()
            || value.contains('=')
            || values.insert(key, value).is_some()
        {
            return Err(malformed.into());
        }
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX_40: &str = "0123456789abcdef0123456789abcdef01234567";
    const HEX_64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OTHER_64: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const ADMIN_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-admin";
    const TEAM_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-team-local";
    const BRAIN_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-brain";
    const EGRESS_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-egress";

    fn published_ref() -> String {
        format!("{RELEASE_REPOSITORY}@sha256:{HEX_64}")
    }

    fn developer_ref() -> String {
        format!("{DEVELOPER_RELEASE_REPOSITORY}@sha256:{OTHER_64}")
    }

    fn valid() -> String {
        format!(
            "schema=local-v2\nordinal=42\numbrella_revision={HEX_40}\ncli_revision={HEX_40}\ncli_linux_amd64_sha256={HEX_64}\ncli_macos_arm64_sha256={HEX_64}\nadmin={ADMIN_REPOSITORY}@sha256:{HEX_64}\nteam={TEAM_REPOSITORY}@sha256:{HEX_64}\nbrain={BRAIN_REPOSITORY}@sha256:{HEX_64}\negress={EGRESS_REPOSITORY}@sha256:{HEX_64}\n"
        )
    }

    fn developer() -> String {
        valid()
            .replace("schema=local-v2", "schema=local-dev-v2")
            .replace(&format!("cli_macos_arm64_sha256={HEX_64}\n"), "")
            .replace(
                &format!("admin={ADMIN_REPOSITORY}@sha256:{HEX_64}"),
                &format!("admin=localhost/shimpz-admin@sha256:{OTHER_64}"),
            )
    }

    #[test]
    fn parses_only_the_closed_current_release() {
        let release = parse(&published_ref(), &valid(), "3").unwrap();
        assert_eq!(release.ordinal, 42);
        assert_eq!(release.cli_revision, HEX_40);
        assert_eq!(release.cli_macos_arm64_sha256.as_deref(), Some(HEX_64));
        assert_eq!(release.admin, format!("{ADMIN_REPOSITORY}@sha256:{HEX_64}"));
        assert_eq!(release.state_epoch, 3);
        assert!(valid_release_ref(&published_ref()));
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
            format!("{}baseline={}\n", valid(), published_ref()),
        ] {
            assert!(
                parse(&published_ref(), &invalid, "1").is_err(),
                "accepted: {invalid}"
            );
        }
    }

    #[test]
    fn rejects_malformed_values_untrusted_repositories_and_epochs() {
        for invalid in [
            valid().replace("ordinal=42", "ordinal=0"),
            valid().replace(HEX_40, "ABC"),
            valid().replacen(HEX_64, "ABC", 1),
            valid().replace(ADMIN_REPOSITORY, "example.invalid/admin"),
            valid().replace(ADMIN_REPOSITORY, "localhost/shimpz-admin"),
            valid().replace("schema=local-v2", "schema=local-v2=extra"),
            valid().replace('\n', "\r\n"),
            "x".repeat(2_049),
        ] {
            assert!(parse(&published_ref(), &invalid, "1").is_err());
        }
        for epoch in ["", "0", "01", "-1", "+1", "1.0", "4294967296", "<no value>"] {
            assert!(
                parse(&published_ref(), &valid(), epoch).is_err(),
                "accepted: {epoch}"
            );
        }
        assert_eq!(parse_state_epoch("4294967295"), Ok(u32::MAX));
    }

    #[test]
    fn the_reference_namespace_selects_the_only_admissible_schema() {
        let release = parse(&developer_ref(), &developer(), "1").unwrap();
        assert_eq!(release.cli_macos_arm64_sha256, None);
        assert_eq!(
            release.admin,
            format!("localhost/shimpz-admin@sha256:{OTHER_64}")
        );
        assert_eq!(release.team, format!("{TEAM_REPOSITORY}@sha256:{HEX_64}"));
        // A developer release may reuse every published member, for example for a CLI-only change.
        let unchanged = developer().replace(
            &format!("localhost/shimpz-admin@sha256:{OTHER_64}"),
            &format!("{ADMIN_REPOSITORY}@sha256:{HEX_64}"),
        );
        assert!(parse(&developer_ref(), &unchanged, "1").is_ok());
        // A published set never parses as a developer release, and a developer set never as a published one.
        assert!(parse(&published_ref(), &developer(), "1").is_err());
        assert!(parse(&developer_ref(), &valid(), "1").is_err());
        for invalid in [
            developer().replace("schema=local-dev-v2", "schema=local-v2"),
            developer().replace("schema=local-dev-v2", "schema=local-dev-v1"),
            format!("{}cli_macos_arm64_sha256={HEX_64}\n", developer()),
            format!("{}baseline={}\n", developer(), published_ref()),
            developer().replace("localhost/shimpz-admin", "localhost/shimpz-brain"),
            developer().replace("localhost/shimpz-admin", "127.0.0.1:5000/shimpz-admin"),
        ] {
            assert!(
                parse(&developer_ref(), &invalid, "1").is_err(),
                "accepted: {invalid}"
            );
        }
        for invalid in [
            format!("{DEVELOPER_RELEASE_REPOSITORY}:latest"),
            format!("localhost:5000/shimpz-local-release@sha256:{HEX_64}"),
            format!("ghcr.io/other/shimpz-local-release@sha256:{HEX_64}"),
        ] {
            assert!(!valid_release_ref(&invalid), "accepted: {invalid}");
            assert!(parse(&invalid, &valid(), "1").is_err());
        }
    }

    #[test]
    fn packages_admit_exactly_their_two_namespaces() {
        let published = format!("{ADMIN_REPOSITORY}@sha256:{HEX_64}");
        let developer = format!("localhost/shimpz-admin@sha256:{HEX_64}");
        assert!(ADMIN.published(&published) && !ADMIN.developer(&published));
        assert!(ADMIN.developer(&developer) && !ADMIN.published(&developer));
        assert!(ADMIN.admits(&published) && ADMIN.admits(&developer));
        for invalid in [
            format!("{ADMIN_REPOSITORY}:stable"),
            format!("localhost/shimpz-admin:sha256-{HEX_64}"),
            format!("localhost/shimpz-admin-extra@sha256:{HEX_64}"),
            format!("docker.io/localhost/shimpz-admin@sha256:{HEX_64}"),
            format!("localhost/shimpz-brain@sha256:{HEX_64}"),
        ] {
            assert!(!ADMIN.admits(&invalid), "accepted: {invalid}");
        }
    }
}
