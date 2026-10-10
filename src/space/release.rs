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
//!
//! A published release set carries in the image label [`SIGNATURE_LABEL`] the base64 DER ECDSA P-256 SHA-256
//! signature `publish.yml` made over its exact metadata followed by `state_epoch=<epoch>\n` (ADR-0103). It is verified
//! against the one pinned key before any field is read, so no registry or package credential alone can select what a
//! Space applies or which CLI it runs. A developer release is admitted only from this host's own image store and
//! carries none.
//!
//! The metadata of a published set also carries its signed validity window, `issued_at` and `expires` in Unix
//! seconds, at most [`VALIDITY_SECONDS`] apart. [`require_current`] admits a set for a change only inside that window,
//! tolerating [`CLOCK_SKEW_SECONDS`] of host clock error at either end; the lifecycle never judges the installed
//! release by it, so an expired window never stops, restarts, or rolls back a Space (ADR-0103, amended 2026-10-09).

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};

use crate::digest;

pub(crate) const RELEASE_REPOSITORY: &str = "ghcr.io/theshimpz/shimpz-local-release";
pub(crate) const DEVELOPER_RELEASE_REPOSITORY: &str = "localhost/shimpz-local-release";
pub(crate) const STATE_EPOCH_LABEL: &str = "org.shimpz.local.state-epoch";
pub(crate) const SIGNATURE_LABEL: &str = "org.shimpz.local.release-signature";
/// The DER prefix of every P-256 `SubjectPublicKeyInfo`; the 65-byte uncompressed point follows it.
const P256_PUBLIC_KEY_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
const PUBLISHED_NAMESPACE: &str = "ghcr.io/theshimpz/";
const DEVELOPER_NAMESPACE: &str = "localhost/";
const PUBLISHED_SCHEMA: &str = "local-v2";
const DEVELOPER_SCHEMA: &str = "local-dev-v2";
const MACOS_CLI_KEY: &str = "cli_macos_arm64_sha256";
const ISSUED_AT_KEY: &str = "issued_at";
const EXPIRES_KEY: &str = "expires";
/// The fields only a published set carries.
const PUBLISHED_ONLY_KEYS: [&str; 3] = [MACOS_CLI_KEY, ISSUED_AT_KEY, EXPIRES_KEY];
/// The longest signed validity window of a published release set: 30 days.
pub(crate) const VALIDITY_SECONDS: u64 = 30 * 86_400;
/// The host clock error tolerated at either end of a validity window: five minutes.
pub(crate) const CLOCK_SKEW_SECONDS: u64 = 5 * 60;
const KEYS: [&str; 12] = [
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
    ISSUED_AT_KEY,
    EXPIRES_KEY,
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
    /// The signed validity window of a published release; a developer release carries none.
    pub(crate) validity: Option<Validity>,
}

/// A published release set's signed validity window, in Unix seconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Validity {
    pub(crate) issued_at: u64,
    pub(crate) expires: u64,
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

/// The base64 P-256 `SubjectPublicKeyInfo` whose private half, held only by `publish.yml`, signs every published
/// release set; `docs/static/install.sh` and `.scripts/local-release/signing-key.pem` pin the same key.
pub(crate) const PUBLISHED_SIGNING_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsiSmhIGW2Txt7M3SuXQEEJZWqPQjlNkkH59ClG3czSQKkziiKEvnRwYqaVYk5Yosa6AUalFtdQz5XknSlGHPLw==";

/// The uncompressed P-256 point of a base64 `SubjectPublicKeyInfo`.
fn public_point(key: &str) -> Option<Vec<u8>> {
    let key = BASE64.decode(key).ok()?;
    key.strip_prefix(&P256_PUBLIC_KEY_PREFIX)
        .filter(|point| point.len() == 65 && point[0] == 4)
        .map(<[u8]>::to_vec)
}

/// Verify a published release set's signature over its exact metadata and state epoch label under `key`.
fn verify_signature(
    key: &str,
    document: &str,
    state_epoch: &str,
    signature: &str,
) -> Result<(), String> {
    let key =
        public_point(key).ok_or_else(|| "the Local release signing key is invalid".to_owned())?;
    let signature = BASE64
        .decode(signature)
        .map_err(|_| "the Local release signature is invalid".to_owned())?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key)
        .verify(
            format!("{document}state_epoch={state_epoch}\n").as_bytes(),
            &signature,
        )
        .map_err(|_| "the Local release signature is invalid".into())
}

/// Parse the metadata of the release set at `reference` with its state epoch and signature labels; the reference
/// namespace selects the only admissible schema, and a published set must carry a valid signature under `key`.
pub(crate) fn parse(
    reference: &str,
    document: &str,
    state_epoch: &str,
    signature: &str,
    key: &str,
) -> Result<Release, String> {
    let developer = if valid_published_release_ref(reference) {
        verify_signature(key, document, state_epoch, signature)?;
        false
    } else if valid_developer_release_ref(reference) {
        true
    } else {
        return Err("the Local release reference is invalid".into());
    };
    let values = key_values(document, 2_048, "the Local release metadata is malformed")?;
    let keys = KEYS
        .iter()
        .filter(|key| !developer || !PUBLISHED_ONLY_KEYS.contains(key));
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
        validity: if developer {
            None
        } else {
            Some(parse_validity(values[ISSUED_AT_KEY], values[EXPIRES_KEY])?)
        },
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

/// Parse a signed validity window: two positive decimal Unix times without leading zeros, `expires` later than
/// `issued_at` by at most [`VALIDITY_SECONDS`].
fn parse_validity(issued_at: &str, expires: &str) -> Result<Validity, String> {
    let time = |value: &str| {
        value
            .parse::<u64>()
            .ok()
            .filter(|time| *time > 0 && time.to_string() == value)
    };
    match (time(issued_at), time(expires)) {
        (Some(issued_at), Some(expires))
            if expires > issued_at && expires - issued_at <= VALIDITY_SECONDS =>
        {
            Ok(Validity { issued_at, expires })
        }
        _ => Err("the Local release validity window is invalid".into()),
    }
}

/// Admit a published release for a change at host time `now`, in Unix seconds, only inside its signed validity
/// window widened by [`CLOCK_SKEW_SECONDS`] at either end. A release without a window is refused: only a developer
/// release has none, and the lifecycle never passes one here.
pub(crate) fn require_current(release: &Release, now: u64) -> Result<(), String> {
    let validity = release
        .validity
        .ok_or_else(|| "the Local release carries no validity window".to_owned())?;
    if validity.issued_at > now.saturating_add(CLOCK_SKEW_SECONDS) {
        return Err(format!(
            "the Local release ordinal {} was issued at {}, later than this host's clock; nothing was applied. Correct the host clock and retry",
            release.ordinal,
            utc(validity.issued_at)
        ));
    }
    if now >= validity.expires.saturating_add(CLOCK_SKEW_SECONDS) {
        return Err(format!(
            "the Local release ordinal {} expired at {}; nothing was applied. Correct this host's clock if it is wrong, or retry after the release channel is renewed",
            release.ordinal,
            utc(validity.expires)
        ));
    }
    Ok(())
}

/// A Unix time as a UTC minute, such as `2026-10-09 14:05 UTC`.
fn utc(seconds: u64) -> String {
    // The civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let shifted = seconds / 86_400 + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    let minute = seconds % 86_400 / 60;
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        minute / 60,
        minute % 60
    )
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

/// The test build pins a key pair generated once per test process instead of the published key, so no private key
/// is ever committed.
#[cfg(test)]
pub(crate) mod test_signing {
    use std::sync::OnceLock;

    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

    struct Signing {
        pair: EcdsaKeyPair,
        public_key: String,
    }

    fn signing() -> &'static Signing {
        static SIGNING: OnceLock<Signing> = OnceLock::new();
        SIGNING.get_or_init(|| {
            let (pair, public_key) = generate();
            Signing { pair, public_key }
        })
    }

    /// A fresh P-256 key pair and its base64 `SubjectPublicKeyInfo`.
    pub(crate) fn generate() -> (EcdsaKeyPair, String) {
        let random = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &random)
                .unwrap();
        let public_key = BASE64.encode(
            [
                &super::P256_PUBLIC_KEY_PREFIX[..],
                pair.public_key().as_ref(),
            ]
            .concat(),
        );
        (pair, public_key)
    }

    /// The base64 `SubjectPublicKeyInfo` the test build pins.
    pub(crate) fn public_key() -> &'static str {
        &signing().public_key
    }

    /// The signature label `publish.yml` would set for this metadata and epoch, made with `pair`.
    pub(crate) fn sign_with(pair: &EcdsaKeyPair, document: &str, state_epoch: &str) -> String {
        let message = format!("{document}state_epoch={state_epoch}\n");
        BASE64.encode(pair.sign(&SystemRandom::new(), message.as_bytes()).unwrap())
    }

    /// The signature label of a correctly signed release set.
    pub(crate) fn sign(document: &str, state_epoch: &str) -> String {
        sign_with(&signing().pair, document, state_epoch)
    }
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
    /// 2026-10-09 00:00 UTC and exactly the longest window after it.
    const ISSUED_AT: u64 = 1_791_504_000;
    const EXPIRES: u64 = ISSUED_AT + VALIDITY_SECONDS;

    /// Parse a published set carrying a correct signature over exactly `document` and `epoch`.
    fn signed(document: &str, epoch: &str) -> Result<Release, String> {
        parse(
            &published_ref(),
            document,
            epoch,
            &test_signing::sign(document, epoch),
            test_signing::public_key(),
        )
    }

    /// Parse a set without a signature label, as Docker reports one.
    fn unsigned(reference: &str, document: &str, epoch: &str) -> Result<Release, String> {
        parse(
            reference,
            document,
            epoch,
            "<no value>",
            test_signing::public_key(),
        )
    }

    fn published_ref() -> String {
        format!("{RELEASE_REPOSITORY}@sha256:{HEX_64}")
    }

    fn developer_ref() -> String {
        format!("{DEVELOPER_RELEASE_REPOSITORY}@sha256:{OTHER_64}")
    }

    fn valid() -> String {
        format!(
            "schema=local-v2\nordinal=42\numbrella_revision={HEX_40}\ncli_revision={HEX_40}\ncli_linux_amd64_sha256={HEX_64}\ncli_macos_arm64_sha256={HEX_64}\nadmin={ADMIN_REPOSITORY}@sha256:{HEX_64}\nteam={TEAM_REPOSITORY}@sha256:{HEX_64}\nbrain={BRAIN_REPOSITORY}@sha256:{HEX_64}\negress={EGRESS_REPOSITORY}@sha256:{HEX_64}\nissued_at={ISSUED_AT}\nexpires={EXPIRES}\n"
        )
    }

    fn developer() -> String {
        valid()
            .replace("schema=local-v2", "schema=local-dev-v2")
            .replace(&format!("cli_macos_arm64_sha256={HEX_64}\n"), "")
            .replace(&format!("issued_at={ISSUED_AT}\nexpires={EXPIRES}\n"), "")
            .replace(
                &format!("admin={ADMIN_REPOSITORY}@sha256:{HEX_64}"),
                &format!("admin=localhost/shimpz-admin@sha256:{OTHER_64}"),
            )
    }

    #[test]
    fn parses_only_the_closed_current_release() {
        let release = signed(&valid(), "3").unwrap();
        assert_eq!(release.ordinal, 42);
        assert_eq!(release.cli_revision, HEX_40);
        assert_eq!(release.cli_macos_arm64_sha256.as_deref(), Some(HEX_64));
        assert_eq!(release.admin, format!("{ADMIN_REPOSITORY}@sha256:{HEX_64}"));
        assert_eq!(release.state_epoch, 3);
        assert_eq!(
            release.validity,
            Some(Validity {
                issued_at: ISSUED_AT,
                expires: EXPIRES
            })
        );
        assert!(valid_release_ref(&published_ref()));
        assert!(!valid_release_ref(&format!("{RELEASE_REPOSITORY}:stable")));
    }

    #[test]
    fn a_published_set_is_admitted_only_with_a_signature_over_its_exact_metadata_and_epoch() {
        let document = valid();
        let signature = test_signing::sign(&document, "3");
        let key = test_signing::public_key();
        assert!(parse(&published_ref(), &document, "3", &signature, key).is_ok());
        let (other_key, _) = test_signing::generate();
        for (document, epoch, signature) in [
            // No signature label, one that is not base64, and one that is not a DER signature.
            (document.clone(), "3", "<no value>".to_owned()),
            (document.clone(), "3", String::new()),
            (document.clone(), "3", "AAAA".to_owned()),
            // The signature of this set over another CLI, another ordinal, or another state epoch.
            (
                document.replacen(HEX_64, OTHER_64, 1),
                "3",
                signature.clone(),
            ),
            (
                document.replace("ordinal=42", "ordinal=43"),
                "3",
                signature.clone(),
            ),
            // The signature of this set over a later expiry.
            (
                document.replace(
                    &format!("expires={EXPIRES}"),
                    &format!("expires={}", EXPIRES + 1),
                ),
                "3",
                signature.clone(),
            ),
            (document.clone(), "4", signature.clone()),
            // A well-formed signature over this exact set by any other key.
            (
                document.clone(),
                "3",
                test_signing::sign_with(&other_key, &document, "3"),
            ),
        ] {
            assert_eq!(
                parse(&published_ref(), &document, epoch, &signature, key),
                Err("the Local release signature is invalid".into()),
                "accepted: {document} {epoch} {signature}"
            );
        }
        // A developer set is admitted only from this host's store and needs no signature.
        assert!(parse(&developer_ref(), &developer(), "1", &signature, key).is_ok());
        // The test build never verifies under the published pin, and nothing is admitted under a key that is not a
        // P-256 public key, such as an unset pin.
        assert_ne!(PUBLISHED_SIGNING_KEY, key);
        assert_eq!(
            parse(&published_ref(), &document, "3", &signature, "unset"),
            Err("the Local release signing key is invalid".into())
        );
    }

    /// A signature `openssl dgst -sha256 -sign` made, exactly as `publish.yml` makes it, verifies under ring. The
    /// private half of this vector's key was discarded after signing.
    #[test]
    fn an_openssl_release_signature_verifies() {
        const KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETbfbLmGJxyq2bWGtRSdlOquPktrfPHYvEixu+RaWAUYEb/eDOZMR5wBbROnXsVWCs357ZEL519jNLmdSIM1Z9A==";
        const SIGNATURE: &str = "MEYCIQCrnWKb6bzq/kFZePhAymGLY5I2q+ZGpnsplyE2a0kUbQIhAO/QhDlNsL7nX1njWX0VdpZ8pxH5lh0LuLpR3WVCvNa4";
        assert_eq!(verify_signature(KEY, &valid(), "3", SIGNATURE), Ok(()));
        assert!(verify_signature(KEY, &valid(), "4", SIGNATURE).is_err());
        assert!(verify_signature(test_signing::public_key(), &valid(), "3", SIGNATURE).is_err());
    }

    #[test]
    fn only_a_p256_subject_public_key_pins_the_signing_key() {
        let key = test_signing::public_key();
        assert_eq!(public_point(key).unwrap().len(), 65);
        let der = BASE64.decode(key).unwrap();
        for invalid in [
            String::new(),
            "not base64".to_owned(),
            BASE64.encode(&der[..90]),
            BASE64.encode([der.as_slice(), &[0]].concat()),
            BASE64.encode(&der[26..]),
            BASE64.encode([&der[..26], &[2], &der[27..]].concat()),
        ] {
            assert_eq!(public_point(&invalid), None, "accepted: {invalid}");
        }
    }

    #[test]
    fn rejects_unknown_missing_and_duplicate_fields() {
        for invalid in [
            "malformed".into(),
            valid().replace("schema=local-v2\n", "schema=unknown\n"),
            valid().replace("ordinal=42\n", ""),
            format!("{}unknown=value\n", valid()),
            format!("{}ordinal=43\n", valid()),
        ] {
            assert!(signed(&invalid, "1").is_err(), "accepted: {invalid}");
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
            assert!(signed(&invalid, "1").is_err());
        }
        for epoch in ["", "0", "01", "-1", "+1", "1.0", "4294967296", "<no value>"] {
            assert!(signed(&valid(), epoch).is_err(), "accepted: {epoch}");
        }
        assert_eq!(parse_state_epoch("4294967295"), Ok(u32::MAX));
    }

    #[test]
    fn the_reference_namespace_selects_the_only_admissible_schema() {
        let release = unsigned(&developer_ref(), &developer(), "1").unwrap();
        assert_eq!(release.cli_macos_arm64_sha256, None);
        assert_eq!(release.validity, None);
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
        assert!(unsigned(&developer_ref(), &unchanged, "1").is_ok());
        // A published set never parses as a developer release, and a developer set never as a published one.
        assert!(signed(&developer(), "1").is_err());
        assert!(unsigned(&developer_ref(), &valid(), "1").is_err());
        for invalid in [
            developer().replace("schema=local-dev-v2", "schema=local-v2"),
            format!("{}cli_macos_arm64_sha256={HEX_64}\n", developer()),
            format!("{}issued_at={ISSUED_AT}\nexpires={EXPIRES}\n", developer()),
            developer().replace("localhost/shimpz-admin", "localhost/shimpz-brain"),
            developer().replace("localhost/shimpz-admin", "127.0.0.1:5000/shimpz-admin"),
        ] {
            assert!(
                unsigned(&developer_ref(), &invalid, "1").is_err(),
                "accepted: {invalid}"
            );
        }
        for invalid in [
            format!("{DEVELOPER_RELEASE_REPOSITORY}:latest"),
            format!("localhost:5000/shimpz-local-release@sha256:{HEX_64}"),
            format!("ghcr.io/other/shimpz-local-release@sha256:{HEX_64}"),
        ] {
            assert!(!valid_release_ref(&invalid), "accepted: {invalid}");
            assert!(unsigned(&invalid, &valid(), "1").is_err());
        }
    }

    #[test]
    fn a_published_set_carries_only_a_positive_window_of_at_most_thirty_days() {
        let window = |issued_at: &str, expires: &str| {
            signed(
                &valid()
                    .replace(
                        &format!("issued_at={ISSUED_AT}"),
                        &format!("issued_at={issued_at}"),
                    )
                    .replace(&format!("expires={EXPIRES}"), &format!("expires={expires}")),
                "1",
            )
        };
        assert!(window("1", &(1 + VALIDITY_SECONDS).to_string()).is_ok());
        let issued_at = ISSUED_AT.to_string();
        for (issued_at, expires) in [
            // Inverted, empty, and one second longer than the longest window.
            (issued_at.clone(), (ISSUED_AT - 1).to_string()),
            (issued_at.clone(), issued_at.clone()),
            (issued_at.clone(), (EXPIRES + 1).to_string()),
            // Not a positive decimal without leading zeros, or beyond u64.
            ("0".to_owned(), "1".to_owned()),
            (format!("0{ISSUED_AT}"), EXPIRES.to_string()),
            (format!("+{ISSUED_AT}"), EXPIRES.to_string()),
            (issued_at.clone(), "18446744073709551616".to_owned()),
            (issued_at.clone(), "soon".to_owned()),
        ] {
            assert_eq!(
                window(&issued_at, &expires),
                Err("the Local release validity window is invalid".into()),
                "accepted: {issued_at} {expires}"
            );
        }
        for missing in ["issued_at", "expires"] {
            let document = valid()
                .split_inclusive('\n')
                .filter(|line| !line.starts_with(missing))
                .collect::<String>();
            assert!(
                signed(&document, "1").is_err(),
                "accepted without {missing}"
            );
        }
    }

    #[test]
    fn a_release_is_current_only_inside_its_window_widened_by_the_clock_tolerance() {
        let release = signed(&valid(), "1").unwrap();
        for now in [
            ISSUED_AT - CLOCK_SKEW_SECONDS,
            ISSUED_AT,
            EXPIRES - 1,
            EXPIRES + CLOCK_SKEW_SECONDS - 1,
        ] {
            assert_eq!(require_current(&release, now), Ok(()), "refused at {now}");
        }
        assert_eq!(
            require_current(&release, ISSUED_AT - CLOCK_SKEW_SECONDS - 1),
            Err("the Local release ordinal 42 was issued at 2026-10-09 00:00 UTC, later than this host's clock; nothing was applied. Correct the host clock and retry".into())
        );
        for now in [EXPIRES + CLOCK_SKEW_SECONDS, u64::MAX] {
            assert_eq!(
                require_current(&release, now),
                Err("the Local release ordinal 42 expired at 2026-11-08 00:00 UTC; nothing was applied. Correct this host's clock if it is wrong, or retry after the release channel is renewed".into())
            );
        }
        // A host clock before 1970 reads as zero, which is earlier than every window.
        assert!(require_current(&release, 0).is_err());
        let developer = unsigned(&developer_ref(), &developer(), "1").unwrap();
        assert_eq!(
            require_current(&developer, ISSUED_AT),
            Err("the Local release carries no validity window".into())
        );
    }

    #[test]
    fn utc_names_the_civil_minute() {
        assert_eq!(utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc(951_825_599), "2000-02-29 11:59 UTC");
        assert_eq!(utc(4_107_542_399), "2100-02-28 23:59 UTC");
        assert_eq!(utc(4_107_542_400), "2100-03-01 00:00 UTC");
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
