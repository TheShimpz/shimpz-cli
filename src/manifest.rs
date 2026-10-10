//! Exact publication identity parsed from the manifest bytes in the source package, plus the Assistant page copy
//! (`description` and Creator `links`) and each Stored Input's help text and help link that the Developers manifest
//! schema requires before publication.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::{identifier, route};

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
    #[serde(default)]
    stored_inputs: BTreeMap<String, toml::Value>,
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
const HELP_URL_CHARS: usize = 2048;
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
        let PublicationManifest {
            shimpz:
                PublicationTable {
                    identity,
                    description,
                    links,
                },
            stored_inputs,
            ..
        } = manifest;
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
        validate_stored_input_help(&stored_inputs)?;
        for (id, declaration) in &stored_inputs {
            let routes = declaration
                .get("routes")
                .map(|routes| serde_json::to_value(routes).unwrap_or_default());
            validate_stored_input_routes(id, routes.as_ref())?;
        }
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

/// Every secret a person is asked for says what it is, how to get it, and where: each Stored Input declares a help-text
/// `description` and the `help_url` of the official page or documentation where the value is made.
fn validate_stored_input_help(stored_inputs: &BTreeMap<String, toml::Value>) -> Result<(), String> {
    for (id, declaration) in stored_inputs {
        // A Creator's own table key is named only once it is a valid identifier, so a diagnostic never echoes noise.
        let name = if identifier::declared(id) {
            format!("[stored_inputs.{id}]")
        } else {
            "[stored_inputs]".to_owned()
        };
        let field = |key: &str| declaration.get(key).and_then(toml::Value::as_str);
        if !field("description").is_some_and(|text| valid_display_text(text, DESCRIPTION_CHARS)) {
            return Err(format!(
                "Assistant manifest {name}.description is invalid: write the help text a person reads before \
                 entering this secret, what it is and how to get it, as one line of 1 to {DESCRIPTION_CHARS} \
                 characters"
            ));
        }
        match field("help_url") {
            None if declaration.get("help_url").is_none() => {
                return Err(format!(
                    "Assistant manifest is missing {name}.help_url: add the official https:// page where a person \
                     creates this secret, or the provider documentation that explains how"
                ));
            }
            Some(url) if url.len() <= HELP_URL_CHARS && public_https_url(url) => {}
            _ => {
                return Err(format!(
                    "Assistant manifest {name}.help_url is invalid: use a public https:// URL with a path, at most \
                     {HELP_URL_CHARS} characters, and no port, credentials, or fragment"
                ));
            }
        }
    }
    Ok(())
}

/// Every Stored Input names the only provider endpoints on its host that ever receive its value, as the Developers
/// route grammar admits them (ADR-0106 amendment of 2026-10-09).
fn validate_stored_input_routes(
    id: &str,
    routes: Option<&serde_json::Value>,
) -> Result<(), String> {
    let name = if identifier::declared(id) {
        format!("[stored_inputs.{id}]")
    } else {
        "[stored_inputs]".to_owned()
    };
    let Some(routes) = routes else {
        return Err(format!(
            "Assistant manifest is missing {name}.routes: declare each provider endpoint that receives this secret as \
             {{ method = \"GET\", path = \"/v1/items\" }}, with `*` for exactly one path segment"
        ));
    };
    let Some(reason) = route::routes_error(routes) else {
        return Ok(());
    };
    let detail = match reason {
        "routes_invalid" => "declare a list of 1 to 32 routes",
        "route_duplicate" => "declare each method and path only once",
        "route_path_invalid" => {
            "write each path as `/`-prefixed segments of 1 to 64 unreserved characters, or `*` for exactly one \
             segment, at most 512 characters, without empty, `.`, or `..` segments or a trailing slash"
        }
        "route_credential" => {
            "a route never names an endpoint that issues, lists, or exchanges credentials (a segment containing \
             apikey, authoriz, credential, oauth, password, secret, or token)"
        }
        "route_query_invalid" => {
            "declare 1 to 8 query selectors, each a distinct unreserved `name` with 1 to 16 distinct `values` of \
             unreserved characters or uppercase percent escapes"
        }
        _ => {
            "give each route only a `method` of GET, HEAD, POST, PUT, PATCH, or DELETE, a `path`, and an optional \
              `query`"
        }
    };
    Err(format!(
        "Assistant manifest {name}.routes is invalid: {detail}"
    ))
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

/// Where Team places one Stored Input in the Action's provider calls to its host (ADR-0106).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct Placement {
    pub(crate) host: String,
    #[serde(default)]
    pub(crate) header: Option<String>,
    #[serde(default)]
    pub(crate) query: Option<String>,
    #[serde(default)]
    pub(crate) scheme: Option<String>,
    #[serde(default)]
    pub(crate) hmac: Option<String>,
    /// The only provider endpoints on its host that ever receive this value (ADR-0106 amendment of 2026-10-09).
    #[serde(default)]
    pub(crate) routes: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct CallManifest {
    network: NetworkDeclaration,
    #[serde(default)]
    stored_inputs: BTreeMap<String, Placement>,
}

#[derive(Debug, Deserialize)]
struct NetworkDeclaration {
    allowed_hosts: BTreeSet<String>,
}

/// The allowed hosts and every Stored Input placement of a manifest the SDK has already validated; a placement's
/// routes are checked again here, so a local run refuses the same manifests publication does.
pub(crate) fn call_policy(
    bytes: &[u8],
) -> Result<(BTreeSet<String>, BTreeMap<String, Placement>), String> {
    let manifest: CallManifest = std::str::from_utf8(bytes)
        .ok()
        .and_then(|source| toml::from_str(source).ok())
        .ok_or_else(|| "Assistant manifest network declarations are invalid".to_owned())?;
    for (id, placement) in &manifest.stored_inputs {
        validate_stored_input_routes(id, placement.routes.as_ref())?;
    }
    Ok((manifest.network.allowed_hosts, manifest.stored_inputs))
}

/// What a person reads before entering one Stored Input: its help text and the page where the value is made.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct StoredInputHelp {
    pub(crate) description: String,
    pub(crate) help_url: String,
}

#[derive(Debug, Deserialize)]
struct HelpManifest {
    #[serde(default)]
    stored_inputs: BTreeMap<String, StoredInputHelp>,
}

/// Every Stored Input's help of a manifest the SDK has already validated, by id.
pub(crate) fn stored_input_help(bytes: &[u8]) -> Result<BTreeMap<String, StoredInputHelp>, String> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|source| toml::from_str::<HelpManifest>(source).ok())
        .map(|manifest| manifest.stored_inputs)
        .ok_or_else(|| "Assistant manifest Stored Inputs are invalid".to_owned())
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
    use super::{
        PublicationIdentity, StoredInputHelp, call_policy, integration_ids, stored_input_help,
    };

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

    const HELP: &str = "Create an API key in the Exa dashboard and copy it.";
    const HELP_URL: &str = "https://dashboard.exa.ai/api-keys";

    const ROUTES: &str = "routes = [{ method = \"POST\", path = \"/search\" }]";

    fn with_stored_input(fields: &str) -> String {
        format!(
            "{VALID}\n[stored_inputs.exa-api-key]\nkind = \"password\"\nlabel = \"Exa API key\"\n{ROUTES}\n{fields}\n"
        )
    }

    fn with_routes(routes: &str) -> String {
        format!(
            "{VALID}\n[stored_inputs.exa-api-key]\nkind = \"password\"\nlabel = \"Exa API key\"\n\
             description = \"{HELP}\"\nhelp_url = \"{HELP_URL}\"\n{routes}\n"
        )
    }

    #[test]
    fn admits_a_stored_input_with_its_reviewed_routes_and_selectors() {
        for routes in [
            "routes = [{ method = \"POST\", path = \"/search\" }, { method = \"POST\", path = \"/contents\" }]",
            "[[stored_inputs.exa-api-key.routes]]\nmethod = \"GET\"\npath = \"/v26.0/*/insights\"\n\
             query = [{ name = \"fields\", values = [\"id%2Cname\"] }]",
        ] {
            assert!(
                PublicationIdentity::parse(with_routes(routes).as_bytes()).is_ok(),
                "{routes}"
            );
        }
    }

    #[test]
    fn a_local_run_carries_each_placements_routes_and_refuses_a_placement_without_them() {
        let placed = "[network]\nallowed_hosts = [\"api.exa.ai\"]\n\n[stored_inputs.exa-api-key]\n\
                      host = \"api.exa.ai\"\nheader = \"x-api-key\"\n";
        let (hosts, placements) =
            call_policy(format!("{placed}{ROUTES}\n").as_bytes()).expect("call policy");
        assert!(hosts.contains("api.exa.ai"));
        assert_eq!(
            placements["exa-api-key"].routes,
            Some(serde_json::json!([{"method": "POST", "path": "/search"}]))
        );
        let error = call_policy(placed.as_bytes()).unwrap_err();
        assert!(
            error.contains("missing [stored_inputs.exa-api-key].routes"),
            "{error}"
        );
        let error = call_policy(format!("{placed}routes = []\n").as_bytes()).unwrap_err();
        assert!(
            error.contains("[stored_inputs.exa-api-key].routes is invalid"),
            "{error}"
        );
    }

    #[test]
    fn refuses_a_stored_input_without_valid_reviewed_routes() {
        for (routes, expected) in [
            ("", "missing [stored_inputs.exa-api-key].routes"),
            ("routes = []", "declare a list of 1 to 32 routes"),
            ("routes = \"/search\"", "declare a list of 1 to 32 routes"),
            (
                "routes = [{ method = \"get\", path = \"/search\" }]",
                "only a `method` of GET",
            ),
            (
                "routes = [{ method = \"GET\", path = \"/search/\" }]",
                "`/`-prefixed segments",
            ),
            (
                "routes = [{ method = \"POST\", path = \"/v1/api_keys\" }]",
                "never names an endpoint that issues",
            ),
            (
                "routes = [{ method = \"GET\", path = \"/a\", query = [{ name = \"f\", values = [\"a,b\"] }] }]",
                "1 to 8 query selectors",
            ),
            (
                "routes = [{ method = \"GET\", path = \"/a\" }, { method = \"GET\", path = \"/a\" }]",
                "each method and path only once",
            ),
            (
                "routes = [{ method = \"GET\", path = 1979-05-27 }]",
                "`/`-prefixed segments",
            ),
        ] {
            let error = PublicationIdentity::parse(with_routes(routes).as_bytes()).unwrap_err();
            assert!(error.contains(expected), "{routes}: {error}");
            assert!(
                error.contains("[stored_inputs.exa-api-key].routes"),
                "{error}"
            );
        }
        let unnamed = super::validate_stored_input_routes("Bad Key", None).unwrap_err();
        assert!(
            unnamed.contains("missing [stored_inputs].routes"),
            "{unnamed}"
        );
    }

    #[test]
    fn projects_each_stored_input_help_by_id_for_the_local_prompt() {
        let source = with_stored_input(&format!(
            "description = \"{HELP}\"\nhelp_url = \"{HELP_URL}\"\nhost = \"api.exa.ai\"\nheader = \"x-api-key\""
        ));
        let help = stored_input_help(source.as_bytes()).expect("help");
        assert_eq!(
            help.get("exa-api-key"),
            Some(&StoredInputHelp {
                description: HELP.into(),
                help_url: HELP_URL.into()
            })
        );
        assert!(
            stored_input_help(VALID.as_bytes())
                .expect("no Stored Inputs")
                .is_empty()
        );
        assert!(stored_input_help(b"[stored_inputs.key]\nkind = 1\n").is_err());
    }

    #[test]
    fn admits_a_stored_input_with_its_help_text_and_help_link() {
        for fields in [
            format!("description = \"{HELP}\"\nhelp_url = \"{HELP_URL}\""),
            format!(
                "description = \"{}\"\nhelp_url = \"{HELP_URL}\"",
                "h".repeat(400)
            ),
            format!(
                "description = \"{HELP}\"\nhelp_url = \"https://exa.ai/{}\"",
                "a".repeat(2048 - "https://exa.ai/".len())
            ),
        ] {
            let source = with_stored_input(&fields);
            assert!(
                PublicationIdentity::parse(source.as_bytes()).is_ok(),
                "{fields}"
            );
        }
    }

    #[test]
    fn refuses_a_stored_input_without_its_help_text_or_help_link() {
        for (fields, expected) in [
            (
                format!("help_url = \"{HELP_URL}\""),
                "[stored_inputs.exa-api-key].description is invalid",
            ),
            (
                format!(
                    "description = \"{}\"\nhelp_url = \"{HELP_URL}\"",
                    "h".repeat(401)
                ),
                "[stored_inputs.exa-api-key].description is invalid",
            ),
            (
                format!("description = \"Line one.\\nLine two.\"\nhelp_url = \"{HELP_URL}\""),
                "[stored_inputs.exa-api-key].description is invalid",
            ),
            (
                format!("description = \"{HELP}\""),
                "missing [stored_inputs.exa-api-key].help_url",
            ),
            (
                format!(
                    "description = \"{HELP}\"\nhelp_url = \"http://dashboard.exa.ai/api-keys\""
                ),
                "[stored_inputs.exa-api-key].help_url is invalid",
            ),
            (
                format!(
                    "description = \"{HELP}\"\nhelp_url = \"https://dashboard.exa.ai/api-keys#new\""
                ),
                "[stored_inputs.exa-api-key].help_url is invalid",
            ),
            (
                format!("description = \"{HELP}\"\nhelp_url = 42"),
                "[stored_inputs.exa-api-key].help_url is invalid",
            ),
            (
                format!(
                    "description = \"{HELP}\"\nhelp_url = \"https://exa.ai/{}\"",
                    "a".repeat(2049 - "https://exa.ai/".len())
                ),
                "[stored_inputs.exa-api-key].help_url is invalid",
            ),
        ] {
            let error =
                PublicationIdentity::parse(with_stored_input(&fields).as_bytes()).unwrap_err();
            assert!(error.contains(expected), "{fields}: {error}");
        }
        let unnamed = format!(
            "{VALID}\n[stored_inputs.\"Bad Key\"]\nkind = \"password\"\nlabel = \"Key\"\nhelp_url = \"{HELP_URL}\"\n"
        );
        let error = PublicationIdentity::parse(unnamed.as_bytes()).unwrap_err();
        assert!(
            error.contains("Assistant manifest [stored_inputs].description is invalid"),
            "{error}"
        );
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
