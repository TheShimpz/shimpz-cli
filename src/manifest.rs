//! Exact publication identity parsed from the manifest bytes in the source package.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct PublicationIdentity {
    pub(crate) id: String,
    pub(crate) version: String,
    pub(crate) creators: Vec<String>,
    pub(crate) name: String,
    pub(crate) summary: String,
}

#[derive(Debug, Deserialize)]
struct PublicationManifest {
    shimpz: PublicationIdentity,
    #[serde(default)]
    integrations: BTreeMap<String, IntegrationDeclaration>,
}

#[derive(Debug, Deserialize)]
struct IntegrationDeclaration {
    scopes: Vec<String>,
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
            || !valid_display_text(&identity.name, 80)
            || !valid_display_text(&identity.summary, 160)
        {
            return Err("Assistant manifest identity is invalid".into());
        }
        Ok(identity)
    }
}

pub(crate) fn integration_ids(bytes: &[u8]) -> Result<Vec<String>, String> {
    let source = std::str::from_utf8(bytes)
        .map_err(|_| "Assistant manifest Integrations are invalid".to_owned())?;
    let manifest: PublicationManifest = toml::from_str(source)
        .map_err(|_| "Assistant manifest Integrations are invalid".to_owned())?;
    if manifest.integrations.len() > 16
        || manifest.integrations.iter().any(|(id, declaration)| {
            !valid_bounded_id(id, 80)
                || declaration.scopes.len() > 32
                || declaration.scopes.iter().any(|scope| {
                    scope.is_empty()
                        || scope.len() > 128
                        || scope.trim() != scope
                        || scope.chars().any(char::is_control)
                })
        })
    {
        return Err("Assistant manifest Integrations are invalid".into());
    }
    Ok(manifest.integrations.into_keys().collect())
}

fn valid_display_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.chars().count() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

pub(crate) fn valid_id(value: &str) -> bool {
    valid_bounded_id(value, 40)
        && !matches!(
            value,
            "postgres" | "assistant-egress" | "shimpz-assistant-egress"
        )
}

pub(crate) fn valid_action_id(value: &str) -> bool {
    valid_bounded_id(value, 80)
}

fn valid_bounded_id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.starts_with(|character: char| character.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.ends_with('-')
        && !value.contains("--")
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
    use super::{PublicationIdentity, integration_ids, valid_action_id};

    const VALID: &str = r#"
[shimpz]
spec = 1
id = "hello-world"
version = "1.2.3"
creators = ["@creator-one", "@creator-two"]
name = "Hello"
summary = "A bounded Assistant summary."
"#;

    #[test]
    fn reads_publication_identity_without_normalizing_manifest_bytes() {
        assert_eq!(
            PublicationIdentity::parse(VALID.as_bytes()),
            Ok(PublicationIdentity {
                id: "hello-world".into(),
                version: "1.2.3".into(),
                creators: vec!["@creator-one".into(), "@creator-two".into()],
                name: "Hello".into(),
                summary: "A bounded Assistant summary.".into(),
            })
        );
    }

    #[test]
    fn rejects_noncanonical_publication_identity() {
        for source in [
            VALID.replace("hello-world", "postgres"),
            VALID.replace("hello-world", "assistant-egress"),
            VALID.replace("hello-world", "shimpz-assistant-egress"),
            VALID.replace("1.2.3", "1..3"),
            VALID.replace("@creator-two", "@creator-one"),
            VALID.replace("@creator-two", "@Creator"),
            VALID.replace("Hello", ""),
        ] {
            assert!(PublicationIdentity::parse(source.as_bytes()).is_err());
        }
    }

    #[test]
    fn rejects_the_retired_root_level_identity() {
        let retired = VALID.replace("[shimpz]\n", "");

        assert!(PublicationIdentity::parse(retired.as_bytes()).is_err());
    }

    #[test]
    fn projects_only_bounded_canonical_integration_ids() {
        let source = format!("{VALID}\n[integrations.whatsapp]\nscopes = [\"messages.write\"]\n");
        assert_eq!(
            integration_ids(source.as_bytes()),
            Ok(vec!["whatsapp".into()])
        );
        assert!(
            integration_ids(format!("{VALID}\n[integrations.Bad]\nscopes = []\n").as_bytes())
                .is_err()
        );
        assert!(valid_action_id("send-message"));
        assert!(!valid_action_id("send_message"));
    }
}
