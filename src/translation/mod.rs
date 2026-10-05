//! The language pack of a Local snapshot, made on the Creator's workstation without any Shimpz service (ADR-0091).
//!
//! With an `OpenAI` API key in the private key file, every new or changed English message is translated through `OpenAI`
//! into every interface language and remembered per message, so unchanged messages are never translated again.
//! Without that file, every interface language shows the English text. Each kind of pack names its own policy, and
//! neither policy is the Developers translation policy, so a Local pack never claims a Developers translation.

mod key;
mod memory;
mod provider;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;

use serde_json::json;

use crate::language_pack::{self, Catalog, LOCALES, Pack};
use crate::{output, toolchain};
use memory::Memory;
use provider::{OpenAi, ProviderError, Translator};

const POLICY_FORMAT: &str = "shimpz-local-translation-policy-v1";
/// Parallel provider requests while translating one catalog.
const WORKERS: usize = 4;
/// Provider answers one message may receive before staging fails.
const ATTEMPTS: usize = 3;

/// How the staged pack renders the messages in every interface language other than English.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Language {
    Translated,
    SourceText,
}

impl Language {
    pub(crate) const fn describe(self) -> &'static str {
        match self {
            Self::Translated => "translated through OpenAI (gpt-6-luna) from this workstation",
            Self::SourceText => "English source text in every interface language",
        }
    }
}

/// The policy of packs translated from this workstation: the pinned model, instructions, and schema.
fn translated_policy() -> String {
    policy(&json!({
        "format": POLICY_FORMAT,
        "instructions": provider::INSTRUCTIONS,
        "model": provider::MODEL,
        "schema": provider::output_schema(),
        "source": "creator-workstation",
    }))
}

/// The policy of packs that show each English template unchanged.
fn source_text_policy() -> String {
    policy(&json!({"format": POLICY_FORMAT, "source": "english-source-text"}))
}

fn policy(document: &serde_json::Value) -> String {
    language_pack::digest(&serde_json::to_vec(document).unwrap_or_default())
}

/// The pack to stage for `catalog`, and how it renders the other interface languages.
pub(crate) fn pack(catalog: &Catalog) -> Result<(Pack, Language), String> {
    let key_path = key::path();
    let key = match &key_path {
        Some(path) => key::load(path)?,
        None => None,
    };
    let (Some(key), Some(key_path)) = (key, key_path) else {
        let pack = catalog
            .source_text_pack(&source_text_policy())
            .map_err(|code| format!("the English language pack is invalid ({code})"))?;
        return Ok((pack, Language::SourceText));
    };
    let policy = translated_policy();
    let memory = Memory::new(
        toolchain::cache_directory()?
            .join("translations")
            .join(policy.trim_start_matches("sha256:")),
    );
    translate(catalog, &policy, &memory, &OpenAi::new(&key), WORKERS)
        .map(|pack| (pack, Language::Translated))
        .map_err(|failure| failure.message(&key_path))
}

/// The line that tells a Creator how to translate a pack that shows English text.
pub(crate) fn key_hint() -> String {
    let location = key::path().map_or_else(
        || {
            format!(
                "the file {} in the CLI configuration directory",
                key::FILE_NAME
            )
        },
        |path| path.display().to_string(),
    );
    format!(
        "Assistant messages stay in English in every interface language. To translate them, save an OpenAI API key in {location} (readable only by you), then stage again."
    )
}

/// Why a translated pack could not be made.
#[derive(Debug, Eq, PartialEq)]
enum Failure {
    Provider(ProviderError),
    Refused(usize),
    Memory(String),
    Invalid(&'static str),
}

impl Failure {
    fn message(&self, key: &Path) -> String {
        let remedy = format!("or remove {} to stage with English text", key.display());
        match self {
            Self::Provider(ProviderError::Key) => format!(
                "OpenAI refused the API key in {}; replace it, {remedy}",
                key.display()
            ),
            Self::Provider(ProviderError::Limited) => format!(
                "OpenAI limited the translation requests (rate or quota); stage again later, {remedy}"
            ),
            Self::Provider(ProviderError::Unavailable | ProviderError::Refused) => {
                format!("OpenAI translation is unavailable; stage again later, {remedy}")
            }
            Self::Refused(count) => format!(
                "OpenAI could not translate {count} message(s) into every interface language in {ATTEMPTS} attempts; simplify or shorten that shimpz.text copy and stage again, {remedy}"
            ),
            Self::Memory(message) => message.clone(),
            Self::Invalid(code) => format!("the translated language pack is invalid ({code})"),
        }
    }
}

/// Whether remembered or provider texts are admissible for the current declaration of message `id`.
fn admissible(catalog: &Catalog, id: &str, texts: &BTreeMap<String, String>) -> bool {
    texts.keys().map(String::as_str).eq(LOCALES)
        && texts
            .values()
            .all(|text| catalog.translation_error(id, text).is_none())
}

/// Translate every message the memory cannot supply, stopping new work at the first terminal failure.
fn translate(
    catalog: &Catalog,
    policy: &str,
    memory: &Memory,
    translator: &dyn Translator,
    workers: usize,
) -> Result<Pack, Failure> {
    let mut texts = BTreeMap::new();
    let mut pending = Vec::new();
    for (id, template) in catalog.templates() {
        match memory
            .get(id)
            .filter(|remembered| admissible(catalog, id, remembered))
        {
            Some(remembered) => {
                texts.insert(id, remembered);
            }
            None => pending.push((id, template)),
        }
    }
    if !pending.is_empty() {
        output::progress(&format!(
            "Translating {} new or changed message(s) through OpenAI...",
            pending.len()
        ));
    }
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let refused = AtomicUsize::new(0);
    let failure = Mutex::new(None);
    let translated = Mutex::new(Vec::new());
    thread::scope(|scope| {
        for _ in 0..workers.min(pending.len()) {
            scope.spawn(|| {
                let fail = |error: Failure| {
                    stop.store(true, Ordering::SeqCst);
                    let mut first = failure
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    first.get_or_insert(error);
                };
                while !stop.load(Ordering::SeqCst) {
                    let Some(&(id, template)) = pending.get(next.fetch_add(1, Ordering::SeqCst))
                    else {
                        break;
                    };
                    match translate_message(catalog, id, template, translator) {
                        Ok(message) => match memory.put(id, &message) {
                            Ok(()) => translated
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .push((id, message)),
                            Err(error) => fail(Failure::Memory(error)),
                        },
                        Err(None) => {
                            refused.fetch_add(1, Ordering::SeqCst);
                            stop.store(true, Ordering::SeqCst);
                        }
                        Err(Some(error)) => fail(Failure::Provider(error)),
                    }
                }
            });
        }
    });
    if let Some(error) = failure
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    {
        return Err(error);
    }
    match refused.into_inner() {
        0 => {}
        count => return Err(Failure::Refused(count)),
    }
    texts.extend(
        translated
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    let locales = LOCALES
        .iter()
        .map(|locale| {
            let entries = texts
                .iter()
                .map(|(id, message)| (*id, message[*locale].as_str()))
                .collect();
            (*locale, entries)
        })
        .collect();
    catalog.pack(policy, &locales).map_err(Failure::Invalid)
}

/// One message's admitted texts; `Err(None)` after every attempt was refused, `Err(Some)` when the provider failed.
fn translate_message(
    catalog: &Catalog,
    id: &str,
    template: &str,
    translator: &dyn Translator,
) -> Result<BTreeMap<String, String>, Option<ProviderError>> {
    for _ in 0..ATTEMPTS {
        match translator.translate(template) {
            Ok(texts) if admissible(catalog, id, &texts) => return Ok(texts),
            Ok(_) | Err(ProviderError::Refused) => {}
            Err(error) => return Err(Some(error)),
        }
    }
    Err(None)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    use serde_json::Value;

    use super::*;
    use crate::language_pack::tests::{catalog, catalog_of};

    /// A fake provider whose answer is chosen per template and call.
    struct Fake<F: Fn(&str, usize) -> Result<BTreeMap<String, String>, ProviderError> + Sync> {
        answer: F,
        calls: AtomicUsize,
        active: AtomicUsize,
        peak: AtomicUsize,
    }

    impl<F: Fn(&str, usize) -> Result<BTreeMap<String, String>, ProviderError> + Sync> Fake<F> {
        fn new(answer: F) -> Self {
            Self {
                answer,
                calls: AtomicUsize::new(0),
                active: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
            }
        }
    }

    impl<F: Fn(&str, usize) -> Result<BTreeMap<String, String>, ProviderError> + Sync> Translator
        for Fake<F>
    {
        fn translate(&self, template: &str) -> Result<BTreeMap<String, String>, ProviderError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(5));
            self.active.fetch_sub(1, Ordering::SeqCst);
            (self.answer)(template, call)
        }
    }

    /// Every locale shows `[locale] template`, which keeps the template's placeholders and fits its budget.
    fn tagged(template: &str) -> BTreeMap<String, String> {
        LOCALES
            .iter()
            .map(|locale| ((*locale).to_owned(), format!("{locale} {template}")))
            .collect()
    }

    fn memory(directory: &Path) -> Memory {
        Memory::new(directory.join("memory"))
    }

    const POLICY: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn policies_are_pinned_and_never_the_developers_policy() {
        assert_eq!(
            translated_policy(),
            "sha256:a155c476af22c11e8ca76522ce00a8c15fc0cb04d664cb7c0de661e4d3403747"
        );
        assert_eq!(
            source_text_policy(),
            "sha256:52855d44158b34c730d32bdc597e690db42f0af37c26839d507f1f87210145ff"
        );
        for policy in [translated_policy(), source_text_policy()] {
            // developers-domain translation_policy::policy_identity() and the promotion proof fixture.
            assert_ne!(
                policy,
                "sha256:ba19aa6cfaf7e7917d5c006367541631a0786c89d5d8a20f151564b1add2cb41"
            );
        }
    }

    #[test]
    fn translates_every_message_once_and_reuses_the_memory() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = catalog();
        let fake = Fake::new(|template, _| Ok(tagged(template)));
        let pack = translate(&catalog, POLICY, &memory(directory.path()), &fake, WORKERS).unwrap();
        assert_eq!(
            fake.calls.load(Ordering::SeqCst),
            catalog.templates().count()
        );
        let value: Value = serde_json::from_slice(pack.bytes()).unwrap();
        for (id, template) in catalog.templates() {
            assert_eq!(value["locales"]["pt"][id], format!("pt {template}"));
        }
        assert_eq!(value["policy"], POLICY);

        // The same messages are never sent again.
        let again = Fake::new(|_, _| Err(ProviderError::Unavailable));
        let reused =
            translate(&catalog, POLICY, &memory(directory.path()), &again, WORKERS).unwrap();
        assert_eq!(again.calls.load(Ordering::SeqCst), 0);
        assert_eq!(reused.bytes(), pack.bytes());
    }

    #[test]
    fn retranslates_a_remembered_text_the_current_declaration_refuses() {
        let directory = tempfile::tempdir().unwrap();
        let memory = memory(directory.path());
        let catalog = catalog_of(&[("Greets people.", 160)]);
        let (id, template) = catalog.templates().next().unwrap();
        // A text admitted under a wider field no longer fits the 160-character summary bound.
        memory.put(id, &tagged(&"x".repeat(200))).unwrap();
        let fake = Fake::new(|template, _| Ok(tagged(template)));
        let pack = translate(&catalog, POLICY, &memory, &fake, WORKERS).unwrap();
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        let value: Value = serde_json::from_slice(pack.bytes()).unwrap();
        assert_eq!(value["locales"]["de"][id], format!("de {template}"));
        assert_eq!(memory.get(id), Some(tagged(template)));
    }

    #[test]
    fn fails_after_three_refused_answers_and_keeps_the_admitted_ones() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = catalog();
        let refused = catalog
            .templates()
            .find(|(_, template)| template.contains('{'))
            .unwrap()
            .1
            .to_owned();
        let fake = Fake::new(|template, _| {
            if template == refused {
                // A candidate that drops the placeholders, then a malformed answer, are both refused.
                Ok(tagged("no placeholders"))
            } else {
                Ok(tagged(template))
            }
        });
        let memory = memory(directory.path());
        assert_eq!(
            translate(&catalog, POLICY, &memory, &fake, 1).unwrap_err(),
            Failure::Refused(1)
        );
        let attempted = catalog
            .templates()
            .take_while(|(_, template)| *template != refused)
            .count();
        assert_eq!(fake.calls.load(Ordering::SeqCst), attempted + ATTEMPTS);
        for (id, template) in catalog.templates().take(attempted) {
            assert_eq!(memory.get(id), Some(tagged(template)));
        }
        let message = Failure::Refused(1).message(Path::new("/k"));
        assert!(
            message.contains("1 message(s)") && message.contains("remove /k"),
            "{message}"
        );
    }

    #[test]
    fn a_provider_failure_stops_every_further_request() {
        for (error, expected) in [
            (ProviderError::Key, "OpenAI refused the API key in /k"),
            (ProviderError::Limited, "rate or quota"),
            (
                ProviderError::Unavailable,
                "OpenAI translation is unavailable",
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let catalog = catalog();
            let fake = Fake::new(move |_, _| Err(error));
            let failure =
                translate(&catalog, POLICY, &memory(directory.path()), &fake, 1).unwrap_err();
            assert_eq!(failure, Failure::Provider(error));
            assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
            let message = failure.message(Path::new("/k"));
            assert!(message.contains(expected), "{message}");
            assert!(
                message.contains("remove /k to stage with English text"),
                "{message}"
            );
        }
    }

    #[test]
    fn a_refused_exchange_is_retried_like_an_inadmissible_answer() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = catalog_of(&[("Greets people.", 160)]);
        let fake = Fake::new(|template, call| {
            if call < 2 {
                Err(ProviderError::Refused)
            } else {
                Ok(tagged(template))
            }
        });
        assert!(translate(&catalog, POLICY, &memory(directory.path()), &fake, 1).is_ok());
        assert_eq!(fake.calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn at_most_four_requests_run_at_once() {
        let directory = tempfile::tempdir().unwrap();
        let messages = (0..12)
            .map(|index| format!("Message number {index}."))
            .collect::<Vec<_>>();
        let catalog = catalog_of(
            &messages
                .iter()
                .map(|message| (message.as_str(), 160))
                .collect::<Vec<_>>(),
        );
        let fake = Fake::new(|template, _| Ok(tagged(template)));
        translate(&catalog, POLICY, &memory(directory.path()), &fake, WORKERS).unwrap();
        assert_eq!(fake.calls.load(Ordering::SeqCst), 12);
        assert!(fake.peak.load(Ordering::SeqCst) <= WORKERS);
    }

    #[test]
    fn a_memory_that_cannot_be_written_fails_the_pack() {
        let directory = tempfile::tempdir().unwrap();
        let blocked = directory.path().join("file");
        std::fs::write(&blocked, b"").unwrap();
        let fake = Fake::new(|template, _| Ok(tagged(template)));
        assert_eq!(
            translate(
                &catalog(),
                POLICY,
                &Memory::new(blocked.join("m")),
                &fake,
                1
            )
            .unwrap_err(),
            Failure::Memory("the translation memory cannot be stored".into())
        );
    }

    #[test]
    fn hints_at_the_key_file_without_requiring_it() {
        assert!(key_hint().contains(key::FILE_NAME));
        assert_eq!(
            Language::SourceText.describe(),
            "English source text in every interface language"
        );
    }
}
