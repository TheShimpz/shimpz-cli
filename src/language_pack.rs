//! Static Assistant message catalogs and the language packs prepared for them (ADR-0091).
//!
//! The CLI checks exactly what staging relies on: the canonical bytes, the catalog digest, and one admissible
//! translation of every message in every interface language. Team remains the admission authority and repeats the
//! complete Unicode text rules when it installs a Local snapshot.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::toolchain;

/// Every interface language other than English, which is the catalog itself.
pub(crate) const LOCALES: [&str; 7] = ["ar", "de", "es", "fr", "ja", "pt", "zh"];
const PACK_FORMAT: &str = "assistant-language-pack-v1";
const PACK_KEYS: [&str; 4] = ["catalog", "format", "locales", "policy"];
pub(crate) const MAX_PACK_BYTES: usize = 2_097_152;
const MAX_CATALOG_BYTES: usize = 131_072;
const MAX_CATALOG_DOCUMENT_BYTES: usize = 1_048_576;
const MAX_MESSAGES: usize = 256;
const MAX_PARAMS: usize = 8;
const MAX_TEMPLATE_CHARACTERS: usize = 500;
const FIELD_BOUNDS: [usize; 4] = [80, 120, 160, 500];

/// One extracted English catalog and its canonical digest.
pub(crate) struct Catalog {
    messages: Value,
    entries: Vec<Message>,
    digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    id: String,
    msgid: String,
    max_length: usize,
    params: Vec<Param>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Param {
    name: String,
    kind: String,
    max_length: usize,
}

/// Exact canonical pack bytes verified for one catalog.
#[derive(Debug)]
pub(crate) struct Pack {
    bytes: Vec<u8>,
    digest: String,
    policy: String,
}

impl Catalog {
    /// Admit the SDK's import-free `{"messages", "summary"}` catalog document.
    pub(crate) fn from_document(document: &str) -> Result<Self, String> {
        let invalid = || "Python SDK returned an invalid message catalog".to_owned();
        if document.len() > MAX_CATALOG_DOCUMENT_BYTES {
            return Err(invalid());
        }
        let value: Value = serde_json::from_str(document).map_err(|_| invalid())?;
        let mut object = match value {
            Value::Object(object) if object.len() == 2 && object.contains_key("summary") => object,
            _ => return Err(invalid()),
        };
        let messages = object.remove("messages").ok_or_else(invalid)?;
        let canonical = serde_json::to_vec(&messages).map_err(|_| invalid())?;
        let entries: Vec<Message> =
            serde_json::from_value(messages.clone()).map_err(|_| invalid())?;
        if canonical.len() > MAX_CATALOG_BYTES
            || !(1..=MAX_MESSAGES).contains(&entries.len())
            || !entries.iter().all(Message::valid)
            || entries.windows(2).any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(invalid());
        }
        Ok(Self {
            messages,
            entries,
            digest: digest(&canonical),
        })
    }

    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }

    pub(crate) fn messages(&self) -> &Value {
        &self.messages
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

impl Message {
    fn valid(&self) -> bool {
        let names = self
            .params
            .iter()
            .map(|param| param.name.as_str())
            .collect::<Vec<_>>();
        self.id == hex_sha256(self.msgid.as_bytes())
            && FIELD_BOUNDS.contains(&self.max_length)
            && self.params.len() <= MAX_PARAMS
            && names.windows(2).all(|pair| pair[0] < pair[1])
            && self.params.iter().all(Param::valid)
            && self.template_error(&self.msgid).is_none()
    }

    /// The first reason a template for this message is inadmissible, mirroring the protocol validator's codes.
    fn template_error(&self, template: &str) -> Option<&'static str> {
        if !public_text(template, MAX_TEMPLATE_CHARACTERS) {
            return Some("public_text");
        }
        let Some(names) = placeholders(template) else {
            return Some("translation_placeholders");
        };
        let unique = names.iter().copied().collect::<BTreeSet<_>>();
        let declared = self
            .params
            .iter()
            .map(|param| param.name.as_str())
            .collect::<BTreeSet<_>>();
        if unique.len() != names.len() || unique != declared {
            return Some("translation_placeholders");
        }
        let fields = names.iter().map(|name| name.len() + 2).sum::<usize>();
        let parameters = self
            .params
            .iter()
            .map(|param| param.max_length)
            .sum::<usize>();
        (template.chars().count() - fields + parameters > self.max_length)
            .then_some("translation_budget")
    }
}

impl Param {
    fn valid(&self) -> bool {
        let maximum = match self.kind.as_str() {
            "integer" => 15,
            "domain" | "dns_name" => 253,
            "identifier" => 128,
            _ => return false,
        };
        valid_param_name(&self.name) && (1..=maximum).contains(&self.max_length)
    }
}

impl Pack {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }

    pub(crate) fn policy(&self) -> &str {
        &self.policy
    }
}

/// Verify exact pack bytes for `catalog`, returning the protocol error code of the first violation.
pub(crate) fn verify(bytes: Vec<u8>, catalog: &Catalog) -> Result<Pack, &'static str> {
    if bytes.len() > MAX_PACK_BYTES {
        return Err("pack_bytes");
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "pack_encoding")?;
    if serde_json::to_vec(&value).ok().as_deref() != Some(bytes.as_slice()) {
        return Err("pack_encoding");
    }
    let Some(pack) = value
        .as_object()
        .filter(|pack| pack.keys().map(String::as_str).eq(PACK_KEYS))
    else {
        return Err("pack_shape");
    };
    let locales = pack["locales"]
        .as_object()
        .filter(|locales| locales.keys().map(String::as_str).eq(LOCALES))
        .ok_or("pack_shape")?;
    let policy = pack["policy"]
        .as_str()
        .filter(|policy| valid_digest(policy));
    let (Some(policy), Some(PACK_FORMAT), Some(pack_catalog)) = (
        policy,
        pack["format"].as_str(),
        pack["catalog"].as_str().filter(|value| valid_digest(value)),
    ) else {
        return Err("pack_shape");
    };
    if pack_catalog != catalog.digest {
        return Err("pack_catalog");
    }
    for translations in locales.values() {
        let translations = translations.as_object().ok_or("pack_shape")?;
        if translations.len() != catalog.entries.len()
            || !catalog
                .entries
                .iter()
                .all(|message| translations.contains_key(&message.id))
        {
            return Err("pack_incomplete");
        }
        for message in &catalog.entries {
            let text = translations[&message.id].as_str().ok_or("public_text")?;
            if let Some(error) = message.template_error(text) {
                return Err(error);
            }
        }
    }
    let policy = policy.to_owned();
    Ok(Pack {
        digest: digest(&bytes),
        bytes,
        policy,
    })
}

/// The CLI cache directory that holds prepared packs outside every authored project.
pub(crate) fn cache_directory() -> Result<PathBuf, String> {
    toolchain::cache_directory().map(|directory| directory.join("language-packs"))
}

/// Load and re-verify the pack prepared for exactly this catalog, if one exists.
pub(crate) fn load(directory: &Path, catalog: &Catalog) -> Result<Option<Pack>, String> {
    let file = match File::open(cache_file(directory, catalog)) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("the prepared language pack cannot be read".into()),
    };
    let mut bytes = Vec::new();
    file.take(u64::try_from(MAX_PACK_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "the prepared language pack cannot be read".to_owned())?;
    verify(bytes, catalog).map(Some).map_err(|code| {
        format!(
            "the prepared language pack is invalid ({code}); run 'shimpz assistant prepare' again"
        )
    })
}

/// Atomically keep a verified pack under its catalog digest.
pub(crate) fn store(directory: &Path, catalog: &Catalog, pack: &Pack) -> Result<(), String> {
    fs::create_dir_all(directory)
        .map_err(|_| "the language pack cache cannot be created".to_owned())?;
    let mut file = atomic_write_file::AtomicWriteFile::open(cache_file(directory, catalog))
        .map_err(|_| "the language pack cannot be stored".to_owned())?;
    file.write_all(&pack.bytes)
        .and_then(|()| file.commit())
        .map_err(|_| "the language pack cannot be stored".into())
}

/// The pack staging needs; staging never contacts Developers, so a missing pack names the command that makes it.
pub(crate) fn prepared(catalog: &Catalog) -> Result<Pack, String> {
    load(&cache_directory()?, catalog)?.ok_or_else(|| {
        "no language pack is prepared for this Assistant's current messages; run 'shimpz assistant prepare', then stage again".into()
    })
}

fn cache_file(directory: &Path, catalog: &Catalog) -> PathBuf {
    let name = catalog
        .digest
        .strip_prefix("sha256:")
        .unwrap_or(&catalog.digest);
    directory.join(format!("{name}.json"))
}

/// Return the named fields in order, or `None` for any other brace syntax.
fn placeholders(template: &str) -> Option<Vec<&str>> {
    let mut names = Vec::new();
    let mut rest = template;
    while rest.contains(['{', '}']) {
        let start = rest.find('{')?;
        let end = rest.find('}').filter(|end| *end > start)?;
        let name = &rest[start + 1..end];
        if !valid_param_name(name) {
            return None;
        }
        names.push(name);
        rest = &rest[end + 1..];
    }
    Some(names)
}

fn valid_param_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=32).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

/// Trimmed, bounded text without control characters or any whitespace other than a space.
fn public_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.chars().count() <= maximum
        && value.chars().all(|character| {
            !character.is_control() && (character == ' ' || !character.is_whitespace())
        })
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex_sha256(bytes))
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::json;

    use super::*;

    const SUMMARY: &str = "Greets people.";
    const TITLE: &str = "Send a greeting";
    const DESCRIPTION: &str = "Greet {name} with a Hello World message: {count}.";

    fn message(msgid: &str, max_length: usize, params: &Value) -> Value {
        json!({"id": hex_sha256(msgid.as_bytes()), "msgid": msgid, "max_length": max_length, "params": params})
    }

    /// One valid catalog document with a parameterized, a plain, and the summary message.
    pub(crate) fn catalog_document() -> String {
        let mut messages = vec![
            message(SUMMARY, 160, &json!([])),
            message(TITLE, 80, &json!([])),
            message(
                DESCRIPTION,
                500,
                &json!([
                    {"name": "count", "kind": "integer", "max_length": 4},
                    {"name": "name", "kind": "identifier", "max_length": 80}
                ]),
            ),
        ];
        messages.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
        json!({"messages": messages, "summary": SUMMARY}).to_string()
    }

    pub(crate) fn catalog() -> Catalog {
        Catalog::from_document(&catalog_document()).expect("valid catalog")
    }

    pub(crate) fn pack_value(catalog: &Catalog) -> Value {
        let translations = catalog
            .entries
            .iter()
            .map(|message| {
                let text = match message.msgid.as_str() {
                    DESCRIPTION => "Cumprimente {name}: {count}.",
                    TITLE => "Enviar uma saudação",
                    _ => "Cumprimenta pessoas.",
                };
                (message.id.clone(), Value::from(text))
            })
            .collect::<serde_json::Map<_, _>>();
        let locales = LOCALES
            .iter()
            .map(|locale| ((*locale).to_owned(), Value::Object(translations.clone())))
            .collect::<serde_json::Map<_, _>>();
        json!({
            "catalog": catalog.digest(),
            "format": PACK_FORMAT,
            "locales": locales,
            "policy": format!("sha256:{}", "c".repeat(64)),
        })
    }

    pub(crate) fn pack_bytes(catalog: &Catalog) -> Vec<u8> {
        serde_json::to_vec(&pack_value(catalog)).expect("canonical pack")
    }

    #[test]
    fn digests_the_catalog_exactly_like_the_protocol_reference() {
        // Python: canonical_json(messages) with ensure_ascii=False, sort_keys=True, compact separators.
        let document = json!({
            "messages": [message("Olá {zone}.", 80, &json!([{"name": "zone", "kind": "domain", "max_length": 40}]))],
            "summary": "x",
        });
        let catalog = Catalog::from_document(&document.to_string()).expect("catalog");
        assert_eq!(
            catalog.digest(),
            "sha256:3cdd6e027a8432499de8a3806ef847ec48c7332e187a75049f2759c78b6a0399"
        );
    }

    #[test]
    fn admits_only_the_sdk_catalog_document() {
        assert_eq!(catalog().len(), 3);
        let document: Value = serde_json::from_str(&catalog_document()).unwrap();
        for invalid in [
            json!({"messages": document["messages"]}),
            json!({"messages": [], "summary": SUMMARY}),
            json!({"messages": document["messages"], "summary": SUMMARY, "extra": true}),
            json!({"messages": [{"id": "0".repeat(64), "msgid": TITLE, "max_length": 80, "params": []}], "summary": SUMMARY}),
            json!({"messages": [message(TITLE, 90, &json!([]))], "summary": SUMMARY}),
            json!({"messages": [message("Use {x.y}", 80, &json!([]))], "summary": SUMMARY}),
        ] {
            assert!(
                Catalog::from_document(&invalid.to_string()).is_err(),
                "{invalid}"
            );
        }
        let mut reversed = document["messages"].as_array().unwrap().clone();
        reversed.reverse();
        assert!(
            Catalog::from_document(&json!({"messages": reversed, "summary": SUMMARY}).to_string())
                .is_err()
        );
    }

    #[test]
    fn admits_each_closed_param_kind_only_within_its_bound() {
        let document = |kind: &str, max_length: usize| {
            let mut messages = vec![
                message(SUMMARY, 160, &json!([])),
                message(
                    "Authorize {value}.",
                    500,
                    &json!([{"name": "value", "kind": kind, "max_length": max_length}]),
                ),
            ];
            messages.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
            json!({"messages": messages, "summary": SUMMARY}).to_string()
        };
        for (kind, maximum) in [
            ("integer", 15),
            ("domain", 253),
            ("dns_name", 253),
            ("identifier", 128),
        ] {
            assert!(
                Catalog::from_document(&document(kind, maximum)).is_ok(),
                "{kind}"
            );
            assert!(
                Catalog::from_document(&document(kind, maximum + 1)).is_err(),
                "{kind}"
            );
        }
        assert!(Catalog::from_document(&document("text", 10)).is_err());
    }

    type Mutation = fn(&mut Value, &str);

    #[test]
    fn verifies_exact_canonical_complete_packs() {
        let catalog = catalog();
        let pack = verify(pack_bytes(&catalog), &catalog).expect("valid pack");
        assert_eq!(pack.digest(), digest(&pack_bytes(&catalog)));
        assert_eq!(pack.policy(), format!("sha256:{}", "c".repeat(64)));

        let spaced = serde_json::to_string_pretty(&pack_value(&catalog)).unwrap();
        assert_eq!(
            verify(spaced.into_bytes(), &catalog).unwrap_err(),
            "pack_encoding"
        );
        assert_eq!(
            verify(b"{".to_vec(), &catalog).unwrap_err(),
            "pack_encoding"
        );

        let cases: [(&str, Mutation); 8] = [
            ("pack_shape", |pack, _| {
                pack["format"] = json!("assistant-language-pack-v2");
            }),
            ("pack_shape", |pack, _| {
                pack["locales"].as_object_mut().unwrap().remove("ja");
            }),
            ("pack_shape", |pack, _| {
                pack["locales"]["en"] = json!({});
            }),
            ("pack_catalog", |pack, _| {
                pack["catalog"] = json!(format!("sha256:{}", "d".repeat(64)));
            }),
            ("pack_incomplete", |pack, id| {
                pack["locales"]["pt"].as_object_mut().unwrap().remove(id);
            }),
            ("pack_incomplete", |pack, _| {
                pack["locales"]["zh"]["0".repeat(64)] = json!("extra");
            }),
            ("translation_placeholders", |pack, id| {
                pack["locales"]["de"][id] = json!("Grüße {name}.");
            }),
            ("translation_budget", |pack, id| {
                pack["locales"]["fr"][id] =
                    json!(format!("{} {{name}} {{count}}", "x".repeat(417)));
            }),
        ];
        let description = hex_sha256(DESCRIPTION.as_bytes());
        for (expected, mutate) in cases {
            let mut pack = pack_value(&catalog);
            mutate(&mut pack, &description);
            let bytes = serde_json::to_vec(&pack).unwrap();
            assert_eq!(verify(bytes, &catalog).unwrap_err(), expected);
        }
        let mut control = pack_value(&catalog);
        control["locales"]["es"][&description] = json!("Saluda a {name}:\n{count}.");
        assert_eq!(
            verify(serde_json::to_vec(&control).unwrap(), &catalog).unwrap_err(),
            "public_text"
        );
    }

    #[test]
    fn keeps_prepared_packs_by_catalog_and_reverifies_them() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = catalog();
        assert!(load(directory.path(), &catalog).unwrap().is_none());
        let pack = verify(pack_bytes(&catalog), &catalog).unwrap();
        store(directory.path(), &catalog, &pack).unwrap();
        let loaded = load(directory.path(), &catalog)
            .unwrap()
            .expect("stored pack");
        assert_eq!(loaded.digest(), pack.digest());

        // A changed catalog has another digest, so the earlier pack is never selected for it.
        let mut changed: Value = serde_json::from_str(&catalog_document()).unwrap();
        let summary = message("Greets people again.", 160, &json!([]));
        changed["messages"] = json!([summary]);
        changed["summary"] = json!("Greets people again.");
        let changed = Catalog::from_document(&changed.to_string()).unwrap();
        assert!(load(directory.path(), &changed).unwrap().is_none());

        fs::write(cache_file(directory.path(), &catalog), b"{}").unwrap();
        let error = load(directory.path(), &catalog).unwrap_err();
        assert!(error.contains("shimpz assistant prepare"), "{error}");
    }
}
