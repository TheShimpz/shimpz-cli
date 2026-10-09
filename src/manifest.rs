//! Exact publication identity parsed from the manifest bytes in the source package, plus the Assistant page copy
//! (`description` and Creator `links`) that the Developers manifest schema requires before publication.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::identifier;

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
    shimpz: PublicationTable,
    #[serde(default)]
    integrations: BTreeMap<String, IntegrationDeclaration>,
}

/// The `[shimpz]` table: the identity plus the page copy, which is validated here but not projected further.
#[derive(Debug, Deserialize)]
struct PublicationTable {
    #[serde(flatten)]
    identity: PublicationIdentity,
    description: Option<toml::Value>,
    links: Option<toml::Value>,
}

/// The closed Creator link kinds in canonical display order, each with the URL prefixes its host rule admits; an
/// empty list admits any public host.
const LINK_KINDS: [(&str, &[&str]); 6] = [
    ("site", &[]),
    ("github", &["https://github.com/"]),
    ("x", &["https://x.com/"]),
    (
        "youtube",
        &["https://youtube.com/", "https://www.youtube.com/"],
    ),
    (
        "linkedin",
        &["https://linkedin.com/", "https://www.linkedin.com/"],
    ),
    (
        "instagram",
        &["https://instagram.com/", "https://www.instagram.com/"],
    ),
];
const DESCRIPTION_CHARS: usize = 400;
const LINK_CHARS: usize = 256;
/// Top-level labels that never name a public host, as the manifest schema's `helpUrl` grammar refuses them.
const PRIVATE_TOP_LEVEL_LABELS: [&str; 11] = [
    "arpa",
    "example",
    "home",
    "internal",
    "invalid",
    "lan",
    "local",
    "localdomain",
    "localhost",
    "onion",
    "test",
];

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
        let PublicationTable {
            identity,
            description,
            links,
        } = manifest.shimpz;
        if !identifier::assistant_id(&identity.id)
            || !valid_version(&identity.version)
            || !valid_creators(&identity.creators)
            || !valid_display_text(&identity.name, 80)
            || !valid_display_text(&identity.summary, 80)
        {
            return Err("Assistant manifest identity is invalid".into());
        }
        validate_description(description.as_ref())?;
        validate_links(links.as_ref())?;
        Ok(identity)
    }
}

fn validate_description(description: Option<&toml::Value>) -> Result<(), String> {
    match description {
        None => Err(format!(
            "Assistant manifest is missing [shimpz].description: add one paragraph of 1 to {DESCRIPTION_CHARS} \
             characters that tells people what the Assistant does"
        )),
        Some(toml::Value::String(text)) if valid_display_text(text, DESCRIPTION_CHARS) => Ok(()),
        Some(_) => Err(format!(
            "Assistant manifest [shimpz].description is invalid: write one paragraph of 1 to {DESCRIPTION_CHARS} \
             characters on a single line, without surrounding spaces or control characters"
        )),
    }
}

fn validate_links(links: Option<&toml::Value>) -> Result<(), String> {
    let Some(links) = links else {
        return Ok(());
    };
    let Some(links) = links.as_table() else {
        return Err("Assistant manifest [shimpz.links] must be a table of link URLs".into());
    };
    if links.is_empty() {
        return Err(
            "Assistant manifest [shimpz.links] is empty: declare at least one link or remove the table".into(),
        );
    }
    for (kind, url) in links {
        let Some((kind, prefixes)) = LINK_KINDS.iter().find(|(known, _)| known == kind) else {
            return Err("Assistant manifest [shimpz.links] declares an unsupported link kind: use site, github, \
                 x, youtube, linkedin, or instagram"
                .into());
        };
        let admitted = url.as_str().is_some_and(|url| {
            url.len() <= LINK_CHARS
                && public_https_url(url)
                && (prefixes.is_empty() || prefixes.iter().any(|prefix| url.starts_with(prefix)))
        });
        if !admitted {
            let target = if prefixes.is_empty() {
                "a public https:// URL".to_owned()
            } else {
                prefixes.join(" or ")
            };
            return Err(format!(
                "Assistant manifest [shimpz.links].{kind} is invalid: use {target} with a path, at most \
                 {LINK_CHARS} characters, and no port, credentials, or fragment"
            ));
        }
    }
    Ok(())
}

/// The manifest schema's `helpUrl` grammar: an `https://` URL on a lowercase public DNS name with at least two
/// labels, no port or credentials, a path without dot segments, an optional non-empty query, and no fragment.
fn public_https_url(value: &str) -> bool {
    let Some((host, target)) = value
        .strip_prefix("https://")
        .and_then(|rest| rest.split_once('/'))
    else {
        return false;
    };
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    public_host(host) && path.split('/').all(valid_path_segment) && query.is_none_or(valid_query)
}

fn public_host(host: &str) -> bool {
    let labels = host.split('.').collect::<Vec<_>>();
    let Some((top, rest)) = labels.split_last() else {
        return false;
    };
    (1..=253).contains(&host.len())
        && !rest.is_empty()
        && rest.iter().all(|label| valid_label(label))
        && valid_label(top)
        && top.starts_with(|first: char| first.is_ascii_lowercase())
        && !PRIVATE_TOP_LEVEL_LABELS.contains(top)
}

fn valid_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && !label.starts_with("xn--")
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_path_segment(segment: &str) -> bool {
    segment != "." && segment != ".." && valid_escaped(segment, b"", false)
}

fn valid_query(query: &str) -> bool {
    !query.is_empty() && valid_escaped(query, b"/?", true)
}

/// Unreserved and sub-delimiter characters, `:` and `@`, any `extra` byte, and uppercase percent escapes; an escaped
/// dot is admitted only where `escaped_dot` allows it, so a path cannot spell a dot segment.
fn valid_escaped(value: &str, extra: &[u8], escaped_dot: bool) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let escape = &bytes[index + 1..bytes.len().min(index + 3)];
            if escape.len() != 2
                || !escape
                    .iter()
                    .all(|digit| digit.is_ascii_digit() || (b'A'..=b'F').contains(digit))
                || (!escaped_dot && escape == b"2E")
            {
                return false;
            }
            index += 3;
        } else if byte.is_ascii_alphanumeric()
            || b"-._~!$&()*+,;=:@".contains(&byte)
            || extra.contains(&byte)
        {
            index += 1;
        } else {
            return false;
        }
    }
    true
}

pub(crate) fn integration_ids(bytes: &[u8]) -> Result<Vec<String>, String> {
    let source = std::str::from_utf8(bytes)
        .map_err(|_| "Assistant manifest Integrations are invalid".to_owned())?;
    let manifest: PublicationManifest = toml::from_str(source)
        .map_err(|_| "Assistant manifest Integrations are invalid".to_owned())?;
    if manifest.integrations.len() > 16
        || manifest.integrations.iter().any(|(id, declaration)| {
            !identifier::declared(id)
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

/// The manifest schema's display-text rule: trimmed, bounded in code points, and free of control characters and of
/// invisible bidirectional, zero-width, and format characters.
fn valid_display_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.chars().count() <= maximum
        && value.trim() == value
        && !value.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}'
                )
        })
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
    use super::{PublicationIdentity, integration_ids};

    const VALID: &str = r#"
[shimpz]
spec = 1
id = "hello-world"
version = "1.2.3"
creators = ["@creator-one", "@creator-two"]
name = "Hello"
summary = "A bounded Assistant summary."
description = "Greets people by name in one short, friendly sentence."
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
    fn bounds_the_summary_to_a_short_eighty_character_description() {
        for summary in ["s".repeat(80), format!("{}\u{1F44B}", "s".repeat(79))] {
            let source = VALID.replace("A bounded Assistant summary.", &summary);
            assert_eq!(
                PublicationIdentity::parse(source.as_bytes()).map(|identity| identity.summary),
                Ok(summary)
            );
        }
        let source = VALID.replace("A bounded Assistant summary.", &"s".repeat(81));
        assert!(PublicationIdentity::parse(source.as_bytes()).is_err());
    }

    #[test]
    fn rejects_noncanonical_publication_identity() {
        for source in [
            VALID.replace("hello-world", "postgres"),
            VALID.replace("hello-world", "assistant-egress"),
            VALID.replace("hello-world", "shimpz-assistant-egress"),
            VALID.replace("hello-world", "hello--world"),
            VALID.replace("hello-world", &"a".repeat(41)),
            VALID.replace("1.2.3", "1..3"),
            VALID.replace("@creator-two", "@creator-one"),
            VALID.replace("@creator-two", "@Creator"),
            VALID.replace("Hello", ""),
        ] {
            assert!(PublicationIdentity::parse(source.as_bytes()).is_err());
        }
    }

    fn with_description(description: &str) -> String {
        VALID.replace(
            "Greets people by name in one short, friendly sentence.",
            description,
        )
    }

    fn with_links(links: &str) -> String {
        format!("{VALID}\n[shimpz.links]\n{links}\n")
    }

    #[test]
    fn bounds_the_description_to_four_hundred_code_points() {
        for description in [
            "d".to_owned(),
            "d".repeat(400),
            format!("{}\u{1F600}", "d".repeat(399)),
        ] {
            assert!(
                PublicationIdentity::parse(with_description(&description).as_bytes()).is_ok(),
                "{description}"
            );
        }
        let error =
            PublicationIdentity::parse(with_description(&"d".repeat(401)).as_bytes()).unwrap_err();
        assert!(error.contains("[shimpz].description is invalid"), "{error}");
    }

    #[test]
    fn refuses_a_missing_or_noncanonical_description() {
        let missing = VALID.replace(
            "description = \"Greets people by name in one short, friendly sentence.\"\n",
            "",
        );
        let error = PublicationIdentity::parse(missing.as_bytes()).unwrap_err();
        assert!(error.contains("missing [shimpz].description"), "{error}");
        for refused in [
            with_description(""),
            with_description(" Greets people."),
            with_description("Greets people. "),
            with_description("Greets people.\\nBriefly."),
            with_description("Greets\\u0085people."),
            with_description("Greets\\u200bpeople."),
            with_description("Greets\\u202epeople."),
            with_description("Greets\\ufeffpeople."),
            VALID.replace(
                "\"Greets people by name in one short, friendly sentence.\"",
                "42",
            ),
        ] {
            let error = PublicationIdentity::parse(refused.as_bytes()).unwrap_err();
            assert!(
                error.contains("[shimpz].description is invalid"),
                "{refused}: {error}"
            );
        }
    }

    #[test]
    fn admits_every_creator_link_kind_on_its_host() {
        for links in [
            "site = \"https://hello.example.org/\"",
            "site = \"https://docs.hello.dev/a/b-c_d~e?ref=shimpz&x=%2E\"",
            "github = \"https://github.com/hello\"",
            "x = \"https://x.com/hello\"",
            "youtube = \"https://youtube.com/@hello\"",
            "youtube = \"https://www.youtube.com/@hello\"",
            "linkedin = \"https://linkedin.com/in/hello\"",
            "linkedin = \"https://www.linkedin.com/company/hello\"",
            "instagram = \"https://instagram.com/hello\"",
            "instagram = \"https://www.instagram.com/hello\"",
            "site = \"https://hello.example.org/\"\ngithub = \"https://github.com/hello\"\nx = \"https://x.com/hello\"\n\
             youtube = \"https://www.youtube.com/@hello\"\nlinkedin = \"https://linkedin.com/in/hello\"\n\
             instagram = \"https://instagram.com/hello\"",
        ] {
            assert!(
                PublicationIdentity::parse(with_links(links).as_bytes()).is_ok(),
                "{links}"
            );
        }
        let at_bound = format!("https://hello.example.org/{}", "a".repeat(230));
        assert_eq!(at_bound.len(), 256);
        assert!(
            PublicationIdentity::parse(with_links(&format!("site = \"{at_bound}\"")).as_bytes())
                .is_ok()
        );
    }

    #[test]
    fn refuses_an_empty_or_unknown_link_table() {
        let empty = PublicationIdentity::parse(with_links("").as_bytes()).unwrap_err();
        assert!(empty.contains("[shimpz.links] is empty"), "{empty}");
        let unknown = PublicationIdentity::parse(
            with_links("facebook = \"https://facebook.com/hello\"").as_bytes(),
        )
        .unwrap_err();
        assert!(unknown.contains("unsupported link kind"), "{unknown}");
        let scalar = VALID.replace(
            "description = ",
            "links = \"https://hello.example.org/\"\ndescription = ",
        );
        let scalar = PublicationIdentity::parse(scalar.as_bytes()).unwrap_err();
        assert!(scalar.contains("must be a table"), "{scalar}");
    }

    #[test]
    fn refuses_each_noncanonical_creator_link() {
        let over_bound = format!("https://hello.example.org/{}", "a".repeat(231));
        for (kind, url) in [
            ("github", "https://gitlab.com/hello"),
            ("github", "https://www.github.com/hello"),
            ("x", "https://twitter.com/hello"),
            ("youtube", "https://youtube.com.hello.org/watch"),
            ("youtube", "https://m.youtube.com/@hello"),
            ("linkedin", "https://linkedin.com.evil.org/in/hello"),
            ("instagram", "https://instagram.co/hello"),
            ("site", "http://hello.example.org/"),
            ("site", "https://hello.example.org"),
            ("site", "https://hello.internal/"),
            ("site", "https://hello.localhost/"),
            ("site", "https://localhost/"),
            ("site", "https://192.168.0.10/"),
            ("site", "https://user@hello.example.org/"),
            ("site", "https://hello.example.org:8443/"),
            ("site", "https://hello.example.org/#about"),
            ("site", "https://hello.example.org/a/../b"),
            ("site", "https://hello.example.org/./b"),
            ("site", "https://hello.example.org/%2E%2E/b"),
            ("site", "https://hello.example.org/%2e"),
            ("site", "https://hello.example.org/a b"),
            ("site", "https://hello.example.org/?"),
            ("site", "https://Hello.example.org/"),
            ("site", "https://xn--hll-epa.example.org/"),
            ("site", "https://-hello.example.org/"),
            ("site", "https://hello.example.1org/"),
            ("site", "https://h\u{e9}llo.example.org/"),
            ("site", over_bound.as_str()),
        ] {
            let error =
                PublicationIdentity::parse(with_links(&format!("{kind} = \"{url}\"")).as_bytes())
                    .unwrap_err();
            assert!(
                error.contains(&format!("[shimpz.links].{kind} is invalid")),
                "{url}: {error}"
            );
        }
        let error = PublicationIdentity::parse(with_links("site = 42").as_bytes()).unwrap_err();
        assert!(error.contains("[shimpz.links].site is invalid"), "{error}");
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
        let integration = |id: &str| {
            integration_ids(format!("{VALID}\n[integrations.{id}]\nscopes = []\n").as_bytes())
        };
        for admitted in ["a-b".to_owned(), "a".repeat(64)] {
            assert_eq!(integration(&admitted), Ok(vec![admitted.clone()]));
        }
        for refused in ["a--b".to_owned(), "a-".to_owned(), "a".repeat(65)] {
            assert!(integration(&refused).is_err(), "{refused}");
        }
    }
}
