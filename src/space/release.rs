//! Closed atomic Local release metadata.
//!
//! A published release set lives under `ghcr.io/theshimpz/` and uses the closed `local-v2` schema with GHCR members
//! only. A developer release (ADR-0099) is built on the owner's host, exists only in that host's Docker image store
//! under `localhost/`, and uses the closed `local-dev-v1` schema: the published fields plus the exact published
//! `baseline` it was assembled from. The reference namespace selects the schema, so neither can pass as the other.

use std::collections::BTreeMap;

use crate::digest;

pub(crate) const RELEASE_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-local-release";
pub(crate) const DEVELOPER_RELEASE_REPOSITORY: &str = "localhost/shimpz-local-release";
const PUBLISHED_NAMESPACE: &str = "ghcr.io/theshimpz/";
const DEVELOPER_NAMESPACE: &str = "localhost/";
const PUBLISHED_SCHEMA: &str = "local-v2";
const DEVELOPER_SCHEMA: &str = "local-dev-v1";
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
    pub(crate) cli_macos_arm64_sha256: String,
    pub(crate) admin: String,
    pub(crate) team: String,
    pub(crate) brain: String,
    pub(crate) egress: String,
    /// The exact published release a developer release was assembled from; `None` for a published release.
    pub(crate) baseline: Option<String>,
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

/// Parse the metadata of the release set at `reference`; its namespace selects the only admissible schema.
pub(crate) fn parse(reference: &str, document: &str) -> Result<Release, String> {
    let developer = if valid_published_release_ref(reference) {
        false
    } else if valid_developer_release_ref(reference) {
        true
    } else {
        return Err("the Local release reference is invalid".into());
    };
    let values = key_values(document, 2_048, "the Local release metadata is malformed")?;
    let expected = KEYS.len() + usize::from(developer);
    if values.len() != expected
        || KEYS.iter().any(|key| !values.contains_key(key))
        || (developer && !values.contains_key("baseline"))
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
    for key in ["cli_linux_amd64_sha256", "cli_macos_arm64_sha256"] {
        if !digest::is_sha256_hex(values[key]) {
            return Err(format!("the Local release {key} is invalid"));
        }
    }
    let baseline = developer
        .then(|| values["baseline"])
        .map(|value| {
            valid_published_release_ref(value)
                .then(|| value.to_owned())
                .ok_or_else(|| "the developer release baseline is invalid".to_owned())
        })
        .transpose()?;
    let release = Release {
        ordinal,
        umbrella_revision: values["umbrella_revision"].into(),
        cli_revision: values["cli_revision"].into(),
        cli_linux_amd64_sha256: values["cli_linux_amd64_sha256"].into(),
        cli_macos_arm64_sha256: values["cli_macos_arm64_sha256"].into(),
        admin: values["admin"].into(),
        team: values["team"].into(),
        brain: values["brain"].into(),
        egress: values["egress"].into(),
        baseline,
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
    if developer
        && !release
            .members()
            .iter()
            .any(|(_, package, value)| package.developer(value))
    {
        return Err("a developer release rebuilds no component".into());
    }
    Ok(release)
}

/// Bind a developer release to the exact published baseline it names: the same ordinal, CLI revision, and CLI
/// bytes, and every member it did not rebuild byte-for-byte the baseline's own.
pub(crate) fn bind_developer(developer: &Release, baseline: &Release) -> Result<(), String> {
    if developer.baseline.is_none() || baseline.baseline.is_some() {
        return Err("the developer release baseline is not a published release".into());
    }
    if developer.ordinal != baseline.ordinal
        || developer.cli_revision != baseline.cli_revision
        || developer.cli_linux_amd64_sha256 != baseline.cli_linux_amd64_sha256
        || developer.cli_macos_arm64_sha256 != baseline.cli_macos_arm64_sha256
    {
        return Err("the developer release does not match its published baseline".into());
    }
    for ((key, package, value), (_, _, published)) in
        developer.members().into_iter().zip(baseline.members())
    {
        if package.published(value) && value != published {
            return Err(format!(
                "the developer release {key} image is not its published baseline's"
            ));
        }
    }
    Ok(())
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

    /// A developer release over `valid()` that rebuilt Admin.
    fn developer() -> String {
        valid()
            .replace("schema=local-v2", "schema=local-dev-v1")
            .replace(
                &format!("admin={ADMIN_REPOSITORY}@sha256:{HEX_64}"),
                &format!("admin=localhost/shimpz-admin@sha256:{OTHER_64}"),
            )
            + &format!("baseline={}\n", published_ref())
    }

    #[test]
    fn parses_only_the_closed_current_release() {
        let release = parse(&published_ref(), &valid()).unwrap();
        assert_eq!(release.ordinal, 42);
        assert_eq!(release.cli_revision, HEX_40);
        assert_eq!(release.admin, format!("{ADMIN_REPOSITORY}@sha256:{HEX_64}"));
        assert_eq!(release.baseline, None);
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
                parse(&published_ref(), &invalid).is_err(),
                "accepted: {invalid}"
            );
        }
    }

    #[test]
    fn rejects_malformed_values_and_untrusted_repositories() {
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
            assert!(parse(&published_ref(), &invalid).is_err());
        }
    }

    #[test]
    fn the_reference_namespace_selects_the_only_admissible_schema() {
        let release = parse(&developer_ref(), &developer()).unwrap();
        assert_eq!(release.baseline, Some(published_ref()));
        assert_eq!(
            release.admin,
            format!("localhost/shimpz-admin@sha256:{OTHER_64}")
        );
        assert_eq!(release.team, format!("{TEAM_REPOSITORY}@sha256:{HEX_64}"));
        // A published set never parses as a developer release, and a developer set never as a published one.
        assert!(parse(&published_ref(), &developer()).is_err());
        assert!(parse(&developer_ref(), &valid()).is_err());
        for invalid in [
            developer().replace("schema=local-dev-v1", "schema=local-v2"),
            developer().replace(&format!("baseline={}\n", published_ref()), ""),
            developer().replace(&published_ref(), &developer_ref()),
            developer().replace(&published_ref(), &format!("{RELEASE_REPOSITORY}:stable")),
            developer().replace("localhost/shimpz-admin", "localhost/shimpz-brain"),
            developer().replace("localhost/shimpz-admin", "127.0.0.1:5000/shimpz-admin"),
            // A developer release rebuilds at least one component.
            developer().replace(
                &format!("localhost/shimpz-admin@sha256:{OTHER_64}"),
                &format!("{ADMIN_REPOSITORY}@sha256:{HEX_64}"),
            ),
        ] {
            assert!(
                parse(&developer_ref(), &invalid).is_err(),
                "accepted: {invalid}"
            );
        }
        for invalid in [
            format!("{DEVELOPER_RELEASE_REPOSITORY}:latest"),
            format!("localhost:5000/shimpz-local-release@sha256:{HEX_64}"),
            format!("ghcr.io/other/shimpz-local-release@sha256:{HEX_64}"),
        ] {
            assert!(!valid_release_ref(&invalid), "accepted: {invalid}");
            assert!(parse(&invalid, &valid()).is_err());
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

    #[test]
    fn a_developer_release_binds_to_its_exact_published_baseline() {
        let baseline = parse(&published_ref(), &valid()).unwrap();
        let developer_release = parse(&developer_ref(), &developer()).unwrap();
        assert_eq!(bind_developer(&developer_release, &baseline), Ok(()));
        assert!(bind_developer(&baseline, &baseline).is_err());
        assert!(bind_developer(&developer_release, &developer_release).is_err());
        for (from, to) in [
            ("ordinal=42", "ordinal=43"),
            (
                &format!("cli_revision={HEX_40}") as &str,
                "cli_revision=1123456789abcdef0123456789abcdef01234567",
            ),
            (
                &format!("cli_linux_amd64_sha256={HEX_64}"),
                &format!("cli_linux_amd64_sha256={OTHER_64}"),
            ),
            (
                &format!("cli_macos_arm64_sha256={HEX_64}"),
                &format!("cli_macos_arm64_sha256={OTHER_64}"),
            ),
            (
                &format!("team={TEAM_REPOSITORY}@sha256:{HEX_64}"),
                &format!("team={TEAM_REPOSITORY}@sha256:{OTHER_64}"),
            ),
        ] {
            let changed = parse(&developer_ref(), &developer().replace(from, to)).unwrap();
            assert!(bind_developer(&changed, &baseline).is_err(), "bound: {to}");
        }
    }
}
