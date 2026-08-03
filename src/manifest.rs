//! Exact publication identity parsed from the manifest bytes in the source package.

use std::collections::BTreeSet;

use serde::Deserialize;

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct PublicationIdentity {
    pub(crate) id: String,
    pub(crate) version: String,
    pub(crate) creators: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PublicationManifest {
    shimpz: PublicationIdentity,
}

impl PublicationIdentity {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, String> {
        let source = std::str::from_utf8(bytes)
            .map_err(|_| "Assistant manifest identity is invalid".to_owned())?;
        let manifest: PublicationManifest = toml::from_str(source)
            .map_err(|_| "Assistant manifest identity is invalid".to_owned())?;
        let identity = manifest.shimpz;
        if !valid_id(&identity.id)
            || !valid_version(&identity.version)
            || !valid_creators(&identity.creators)
        {
            return Err("Assistant manifest identity is invalid".into());
        }
        Ok(identity)
    }
}

pub(crate) fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 40
        && value.starts_with(|character: char| character.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.ends_with('-')
        && !value.contains("--")
        && !matches!(value, "postgres" | "assistant-egress")
}

pub(crate) fn valid_version(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part == &"0" || !part.starts_with('0'))
        })
}

pub(crate) fn valid_creator(value: &str) -> bool {
    let Some(username) = value.strip_prefix('@') else {
        return false;
    };
    (3..=32).contains(&username.len())
        && username.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || byte == b'-' && index > 0 && index + 1 < username.len()
        })
}

fn valid_creators(creators: &[String]) -> bool {
    (1..=16).contains(&creators.len())
        && creators.iter().all(|creator| valid_creator(creator))
        && creators.iter().collect::<BTreeSet<_>>().len() == creators.len()
}

#[cfg(test)]
mod tests {
    use super::PublicationIdentity;

    const VALID: &str = r#"
[shimpz]
spec = 1
id = "hello-world"
version = "1.2.3"
creators = ["@creator-one", "@creator-two"]
name = "Hello"
"#;

    #[test]
    fn reads_publication_identity_without_normalizing_manifest_bytes() {
        assert_eq!(
            PublicationIdentity::parse(VALID.as_bytes()),
            Ok(PublicationIdentity {
                id: "hello-world".into(),
                version: "1.2.3".into(),
                creators: vec!["@creator-one".into(), "@creator-two".into()],
            })
        );
    }

    #[test]
    fn rejects_noncanonical_publication_identity() {
        for source in [
            VALID.replace("hello-world", "postgres"),
            VALID.replace("1.2.3", "1..3"),
            VALID.replace("@creator-two", "@creator-one"),
            VALID.replace("@creator-two", "@Creator"),
        ] {
            assert!(PublicationIdentity::parse(source.as_bytes()).is_err());
        }
    }

    #[test]
    fn rejects_the_retired_root_level_identity() {
        let retired = VALID.replace("[shimpz]\n", "");

        assert!(PublicationIdentity::parse(retired.as_bytes()).is_err());
    }
}
