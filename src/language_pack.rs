//! Static Assistant message catalogs and the language packs staged with them (ADR-0091).
//!
//! The CLI applies the protocol reference rules a Local snapshot relies on: the canonical bytes, the catalog digest,
//! and one admissible text of every message in every interface language, including the Unicode text and placeholder
//! rules. The pinned SDK's reference validator and Team admission repeat them.

use std::collections::{BTreeMap, BTreeSet};

use icu_normalizer::ComposingNormalizerBorrowed;
use icu_properties::CodePointMapData;
use icu_properties::props::GeneralCategory;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

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
    canonical: Vec<u8>,
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
            entries,
            digest: digest(&canonical),
            canonical,
        })
    }

    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }

    /// The canonical catalog bytes the digest covers.
    pub(crate) fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    /// Every message as its id and English template, in catalog order.
    pub(crate) fn templates(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|message| (message.id.as_str(), message.msgid.as_str()))
    }

    /// The first reason `text` is not an admissible translation of message `id`, mirroring the protocol codes.
    pub(crate) fn translation_error(&self, id: &str, text: &str) -> Option<&'static str> {
        self.entries
            .iter()
            .find(|message| message.id == id)
            .map_or(Some("pack_incomplete"), |message| {
                message.template_error(text)
            })
    }

    /// The canonical pack of this catalog under `policy`, with exactly one admissible text per message and locale.
    pub(crate) fn pack(
        &self,
        policy: &str,
        locales: &BTreeMap<&str, BTreeMap<&str, &str>>,
    ) -> Result<Pack, &'static str> {
        let bytes = serde_json::to_vec(&json!({
            "catalog": self.digest,
            "format": PACK_FORMAT,
            "locales": locales,
            "policy": policy,
        }))
        .map_err(|_| "pack_encoding")?;
        verify(bytes, self)
    }

    /// The pack that shows each English template unchanged in every interface language.
    pub(crate) fn source_text_pack(&self, policy: &str) -> Result<Pack, &'static str> {
        let english = self.templates().collect::<BTreeMap<_, _>>();
        let locales = LOCALES
            .iter()
            .map(|locale| (*locale, english.clone()))
            .collect();
        self.pack(policy, &locales)
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
        if unique.len() != names.len() || unique != declared || mark_follows_field(template) {
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
        .filter(|policy| crate::digest::is_sha256(policy));
    let (Some(_), Some(PACK_FORMAT), Some(pack_catalog)) = (
        policy,
        pack["format"].as_str(),
        pack["catalog"]
            .as_str()
            .filter(|value| crate::digest::is_sha256(value)),
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
    Ok(Pack { bytes })
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

/// Trimmed, bounded, printable NFC text: the protocol's `public_text`, where printable excludes every Other (`C*`)
/// and Separator (`Z*`) character except the ASCII space, exactly like Python's `str.isprintable`.
fn public_text(value: &str, maximum: usize) -> bool {
    let categories = CodePointMapData::<GeneralCategory>::new();
    !value.is_empty()
        && value.trim() == value
        && value.chars().count() <= maximum
        && value.chars().all(|character| {
            character == ' '
                || !matches!(
                    categories.get(character),
                    GeneralCategory::Control
                        | GeneralCategory::Format
                        | GeneralCategory::Surrogate
                        | GeneralCategory::PrivateUse
                        | GeneralCategory::Unassigned
                        | GeneralCategory::SpaceSeparator
                        | GeneralCategory::LineSeparator
                        | GeneralCategory::ParagraphSeparator
                )
        })
        && ComposingNormalizerBorrowed::new_nfc().is_normalized(value)
}

/// Whether a combining mark directly follows a placeholder, which could denormalize an NFC rendering.
fn mark_follows_field(template: &str) -> bool {
    let categories = CodePointMapData::<GeneralCategory>::new();
    template.split('}').skip(1).any(|rest| {
        rest.chars().next().is_some_and(|character| {
            matches!(
                categories.get(character),
                GeneralCategory::NonspacingMark
                    | GeneralCategory::SpacingMark
                    | GeneralCategory::EnclosingMark
            )
        })
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
            message(SUMMARY, 80, &json!([])),
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

    /// A catalog of parameterless messages with their field bounds; the first one is the summary.
    pub(crate) fn catalog_of(messages: &[(&str, usize)]) -> Catalog {
        let mut entries = messages
            .iter()
            .map(|(msgid, max_length)| message(msgid, *max_length, &json!([])))
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
        Catalog::from_document(&json!({"messages": entries, "summary": messages[0].0}).to_string())
            .expect("valid catalog")
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
        assert_eq!(catalog().templates().count(), 3);
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
                message(SUMMARY, 80, &json!([])),
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
        assert_eq!(pack.bytes(), pack_bytes(&catalog).as_slice());

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
    fn applies_the_reference_unicode_text_rules_to_every_translation() {
        let catalog = catalog();
        let description = hex_sha256(DESCRIPTION.as_bytes());
        for (expected, text) in [
            // Decomposed "é" is not NFC.
            ("public_text", "Cumprimente {name}: {count}. Olá e\u{301}."),
            // Zero-width space (Cf), no-break space (Zs), private use (Co), and an unassigned code point (Cn).
            ("public_text", "Cumprimente\u{200b} {name}: {count}."),
            ("public_text", "Cumprimente\u{a0}{name}: {count}."),
            ("public_text", "Cumprimente {name}: {count}.\u{e000}"),
            ("public_text", "Cumprimente {name}: {count}.\u{378}"),
            ("public_text", " Cumprimente {name}: {count}."),
            // A combining mark directly after a placeholder.
            (
                "translation_placeholders",
                "Cumprimente {name}\u{301}: {count}.",
            ),
        ] {
            assert_eq!(
                catalog.translation_error(&description, text),
                Some(expected),
                "{text}"
            );
        }
        assert_eq!(
            catalog.translation_error(&description, "Begrüße {name}: {count}. 你好"),
            None
        );
        assert_eq!(
            catalog.translation_error(&"0".repeat(64), "x"),
            Some("pack_incomplete")
        );
    }

    #[test]
    fn builds_canonical_source_text_and_assembled_packs() {
        let catalog = catalog();
        let policy = format!("sha256:{}", "a".repeat(64));
        let source = catalog.source_text_pack(&policy).expect("source-text pack");
        let value: Value = serde_json::from_slice(source.bytes()).unwrap();
        assert_eq!(value["policy"], policy);
        for locale in LOCALES {
            for (id, msgid) in catalog.templates() {
                assert_eq!(value["locales"][locale][id], msgid);
            }
        }
        // The assembled pack is byte-identical to the canonical pack a reference producer writes.
        let expected = pack_bytes(&catalog);
        let translated: Value = serde_json::from_slice(&expected).unwrap();
        let locales = LOCALES
            .iter()
            .map(|locale| {
                let texts = translated["locales"][locale]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(id, text)| (id.as_str(), text.as_str().unwrap()))
                    .collect();
                (*locale, texts)
            })
            .collect();
        let assembled = catalog
            .pack(&format!("sha256:{}", "c".repeat(64)), &locales)
            .expect("assembled pack");
        assert_eq!(assembled.bytes(), expected.as_slice());
        let mut missing = locales.clone();
        missing.remove("ja");
        assert_eq!(catalog.pack(&policy, &missing).unwrap_err(), "pack_shape");
    }
}
