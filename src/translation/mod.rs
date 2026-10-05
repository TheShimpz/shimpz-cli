//! The language pack of a Local snapshot, made on the Creator's workstation without any Shimpz service (ADR-0091).
//!
//! With an `OpenAI` API key in the private key file, every English message without a valid remembered translation is
//! translated through `OpenAI` into every interface language. Translations are remembered per message only after the
//! complete pack passes the pinned SDK's reference validator, so an unchanged message is not translated again while
//! its remembered translation stays valid. Without that file, every interface language shows the English text. Each
//! kind of pack names its own policy, and neither is the Developers translation policy, so a Local pack never claims
//! a Developers translation.

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

/// One message's text in every interface language other than English, by locale.
type Texts = BTreeMap<String, String>;

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

/// The SDK reference validator applied to the exact pack bytes before staging or remembering anything.
pub(crate) type Verify<'a> = &'a dyn Fn(&[u8]) -> Result<(), String>;

/// The verified pack to stage for `catalog`, and how it renders the other interface languages.
pub(crate) fn pack(catalog: &Catalog, verify: Verify) -> Result<(Pack, Language), String> {
    let key_path = key::path();
    let key = match &key_path {
        Some(path) => key::load(path)?,
        None => None,
    };
    let (Some(key), Some(key_path)) = (key, key_path) else {
        let pack = catalog
            .source_text_pack(&source_text_policy())
            .map_err(|code| format!("the English language pack is invalid ({code})"))?;
        verify(pack.bytes())?;
        return Ok((pack, Language::SourceText));
    };
    let policy = translated_policy();
    let memory = Memory::new(
        toolchain::cache_directory()?
            .join("translations")
            .join(policy.trim_start_matches("sha256:")),
    );
    translate(
        catalog,
        &policy,
        &memory,
        &OpenAi::new(&key),
        WORKERS,
        verify,
    )
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
    Verify(String),
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
            Self::Memory(message) | Self::Verify(message) => message.clone(),
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

/// One message's outcome: its admitted texts, every attempt refused, cancelled by another failure, or a provider
/// failure.
enum Outcome {
    Translated(Texts),
    Refused,
    Cancelled,
    Failed(ProviderError),
}

/// Translate every message the memory cannot supply, stopping new requests, retries included, at the first terminal
/// failure. New translations are remembered only after `verify` admits the complete pack.
fn translate(
    catalog: &Catalog,
    policy: &str,
    memory: &Memory,
    translator: &dyn Translator,
    workers: usize,
    verify: Verify,
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
            "Translating {} message(s) through OpenAI...",
            pending.len()
        ));
    }
    let learned = translate_pending(catalog, &pending, translator, workers)?;
    for (id, message) in &learned {
        texts.insert(id, message.clone());
    }
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
    let pack = catalog.pack(policy, &locales).map_err(Failure::Invalid)?;
    verify(pack.bytes()).map_err(Failure::Verify)?;
    for (id, message) in &learned {
        memory.put(id, message).map_err(Failure::Memory)?;
    }
    Ok(pack)
}

/// Translate `pending` with at most `workers` concurrent requests; any terminal failure cancels all further requests.
fn translate_pending<'a>(
    catalog: &Catalog,
    pending: &[(&'a str, &str)],
    translator: &dyn Translator,
    workers: usize,
) -> Result<Vec<(&'a str, Texts)>, Failure> {
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let refused = AtomicUsize::new(0);
    let failure = Mutex::new(None);
    let translated = Mutex::new(Vec::new());
    thread::scope(|scope| {
        for _ in 0..workers.min(pending.len()) {
            scope.spawn(|| {
                while !stop.load(Ordering::SeqCst) {
                    let Some(&(id, template)) = pending.get(next.fetch_add(1, Ordering::SeqCst))
                    else {
                        break;
                    };
                    match translate_message(catalog, id, template, translator, &stop) {
                        Outcome::Translated(message) => translated
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push((id, message)),
                        Outcome::Refused => {
                            refused.fetch_add(1, Ordering::SeqCst);
                            stop.store(true, Ordering::SeqCst);
                        }
                        Outcome::Cancelled => break,
                        Outcome::Failed(error) => {
                            stop.store(true, Ordering::SeqCst);
                            failure
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .get_or_insert(Failure::Provider(error));
                        }
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
        0 => Ok(translated
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner)),
        count => Err(Failure::Refused(count)),
    }
}

/// Up to `ATTEMPTS` provider answers for one message, never starting an attempt once `stop` is set.
fn translate_message(
    catalog: &Catalog,
    id: &str,
    template: &str,
    translator: &dyn Translator,
    stop: &AtomicBool,
) -> Outcome {
    for _ in 0..ATTEMPTS {
        if stop.load(Ordering::SeqCst) {
            return Outcome::Cancelled;
        }
        match translator.translate(template) {
            Ok(texts) if admissible(catalog, id, &texts) => return Outcome::Translated(texts),
            Ok(_) | Err(ProviderError::Refused) => {}
            Err(error) => return Outcome::Failed(error),
        }
    }
    Outcome::Refused
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

    #[allow(clippy::unnecessary_wraps)]
    fn accept(_: &[u8]) -> Result<(), String> {
        Ok(())
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
        let pack = translate(
            &catalog,
            POLICY,
            &memory(directory.path()),
            &fake,
            WORKERS,
            &accept,
        )
        .unwrap();
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
        let reused = translate(
            &catalog,
            POLICY,
            &memory(directory.path()),
            &again,
            WORKERS,
            &accept,
        )
        .unwrap();
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
        let pack = translate(&catalog, POLICY, &memory, &fake, WORKERS, &accept).unwrap();
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        let value: Value = serde_json::from_slice(pack.bytes()).unwrap();
        assert_eq!(value["locales"]["de"][id], format!("de {template}"));
        assert_eq!(memory.get(id), Some(tagged(template)));
    }

    #[test]
    fn fails_after_three_refused_answers_and_remembers_nothing() {
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
            translate(&catalog, POLICY, &memory, &fake, 1, &accept).unwrap_err(),
            Failure::Refused(1)
        );
        let attempted = catalog
            .templates()
            .take_while(|(_, template)| *template != refused)
            .count();
        assert_eq!(fake.calls.load(Ordering::SeqCst), attempted + ATTEMPTS);
        for (id, _) in catalog.templates() {
            assert!(memory.get(id).is_none());
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
            let failure = translate(
                &catalog,
                POLICY,
                &memory(directory.path()),
                &fake,
                1,
                &accept,
            )
            .unwrap_err();
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
        assert!(
            translate(
                &catalog,
                POLICY,
                &memory(directory.path()),
                &fake,
                1,
                &accept
            )
            .is_ok()
        );
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
        translate(
            &catalog,
            POLICY,
            &memory(directory.path()),
            &fake,
            WORKERS,
            &accept,
        )
        .unwrap();
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
                1,
                &accept
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

    #[test]
    fn remembers_nothing_until_the_reference_validator_admits_the_pack() {
        let directory = tempfile::tempdir().unwrap();
        let memory = memory(directory.path());
        let catalog = catalog_of(&[("Greets people.", 160)]);
        let (id, template) = catalog.templates().next().unwrap();
        // U+1FAEA is assigned in the CLI's Unicode data but unassigned in the pinned reference's Unicode 16.
        let newer = Fake::new(|template, _| Ok(tagged(&format!("{template} \u{1faea}"))));
        let reference = |bytes: &[u8]| {
            if String::from_utf8_lossy(bytes).contains('\u{1faea}') {
                Err("the Python SDK refuses the language pack (public_text)".to_owned())
            } else {
                Ok(())
            }
        };
        assert_eq!(
            translate(&catalog, POLICY, &memory, &newer, 1, &reference).unwrap_err(),
            Failure::Verify("the Python SDK refuses the language pack (public_text)".into())
        );
        assert!(memory.get(id).is_none());

        // Staging again asks the provider again instead of reusing the refused answer.
        let fake = Fake::new(|template, _| Ok(tagged(template)));
        translate(&catalog, POLICY, &memory, &fake, 1, &reference).unwrap();
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        assert_eq!(memory.get(id), Some(tagged(template)));
    }

    #[test]
    fn a_terminal_failure_cancels_the_retries_of_other_workers() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = catalog_of(&[("Greets people.", 160), ("Fails at once.", 160)]);
        let failed = AtomicBool::new(false);
        let fake = Fake::new(|template, _| {
            if template == "Fails at once." {
                failed.store(true, Ordering::SeqCst);
                return Err(ProviderError::Key);
            }
            // Answer inadmissibly only after the other worker failed, which would otherwise earn two retries.
            while !failed.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(1));
            }
            thread::sleep(Duration::from_millis(50));
            Ok(tagged("no placeholders {x}"))
        });
        assert_eq!(
            translate(
                &catalog,
                POLICY,
                &memory(directory.path()),
                &fake,
                2,
                &accept
            )
            .unwrap_err(),
            Failure::Provider(ProviderError::Key)
        );
        assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
    }
}
