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

use icu_normalizer::ComposingNormalizerBorrowed;
use icu_properties::CodePointSetData;
use icu_properties::props::BidiControl;
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
/// Provider answers one message may receive before staging fails; a model often overshoots a short budget, so each
/// retry asks a tighter one and keeps every locale an earlier answer already fit.
const ATTEMPTS: usize = 5;

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

/// One message every attempt failed to translate, with why its last provider answer was refused.
#[derive(Debug, Eq, PartialEq)]
struct Refusal {
    id: String,
    template: String,
    reason: String,
}

/// Why an exchange whose answer lacked exactly the requested string fields was refused.
const MALFORMED: &str = "OpenAI returned no complete structured answer";
/// Characters of a refused English template quoted in a failure message.
const QUOTED_CHARACTERS: usize = 60;

impl Refusal {
    fn describe(&self) -> String {
        let mut quoted = self
            .template
            .chars()
            .take(QUOTED_CHARACTERS)
            .collect::<String>();
        if self.template.chars().count() > QUOTED_CHARACTERS {
            quoted.push_str("...");
        }
        format!(
            "message {} ({quoted:?}): {}",
            &self.id[..self.id.len().min(12)],
            self.reason
        )
    }
}

/// Why a translated pack could not be made.
#[derive(Debug, Eq, PartialEq)]
enum Failure {
    Provider(ProviderError),
    Refused(Vec<Refusal>),
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
            Self::Refused(refusals) => format!(
                "OpenAI could not translate {} message(s) into every interface language in {ATTEMPTS} attempts: {}; simplify or shorten that shimpz.text copy and stage again, {remedy}",
                refusals.len(),
                refusals
                    .iter()
                    .map(Refusal::describe)
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            Self::Memory(message) | Self::Verify(message) => message.clone(),
            Self::Invalid(code) => format!("the translated language pack is invalid ({code})"),
        }
    }
}

/// Whether remembered or provider texts are admissible for the current declaration of message `id`.
fn admissible(catalog: &Catalog, id: &str, texts: &BTreeMap<String, String>) -> bool {
    refusal_reason(catalog, id, texts).is_none()
}

/// Why `texts` are inadmissible for message `id`: each refused locale with its protocol code, never the text.
fn refusal_reason(catalog: &Catalog, id: &str, texts: &BTreeMap<String, String>) -> Option<String> {
    if !texts.keys().map(String::as_str).eq(LOCALES) {
        return Some("the answer does not have exactly one text per interface language".to_owned());
    }
    let refused = texts
        .iter()
        .filter_map(|(locale, text)| {
            catalog
                .translation_error(id, text)
                .map(|code| format!("{locale} {}", explain(code)))
        })
        .collect::<Vec<_>>();
    (!refused.is_empty()).then(|| refused.join(", "))
}

/// A protocol refusal code with what it means for the Creator's copy.
fn explain(code: &str) -> String {
    let meaning = match code {
        "public_text" => "is not trimmed, printable NFC text",
        "translation_placeholders" => "does not keep exactly the message's placeholders",
        "translation_budget" => "exceeds the field's length budget",
        _ => "is refused",
    };
    format!("{meaning} ({code})")
}

/// One message's outcome: its admitted texts, every attempt refused, cancelled by another failure, or a provider
/// failure.
enum Outcome {
    Translated(Texts),
    Refused(String),
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
    let refused = Mutex::new(Vec::new());
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
                        Outcome::Refused(reason) => {
                            stop.store(true, Ordering::SeqCst);
                            refused
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .push(Refusal {
                                    id: id.to_owned(),
                                    template: template.to_owned(),
                                    reason,
                                });
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
    let mut refused = refused
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if refused.is_empty() {
        return Ok(translated
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner));
    }
    refused.sort_by(|left, right| left.id.cmp(&right.id));
    Err(Failure::Refused(refused))
}

/// Every candidate without directional formatting marks and in Unicode NFC, before the unchanged admission rules.
///
/// The model often writes an Arabic right-to-left mark before a placeholder, which the instructions already forbid,
/// and canonically equivalent combining marks in another order, such as a shadda before its vowel sign; the
/// `public_text` rule refuses both. Removing only `Bidi_Control` characters, which are invisible, and composing
/// keep every visible character, so the producer repairs them here instead of discarding the answer.
fn composed(texts: Texts) -> Texts {
    let bidi_controls = CodePointSetData::new::<BidiControl>();
    let nfc = ComposingNormalizerBorrowed::new_nfc();
    texts
        .into_iter()
        .map(|(locale, text)| {
            let visible = text
                .chars()
                .filter(|character| !bidi_controls.contains(*character))
                .collect::<String>();
            let text = nfc.normalize(&visible).into_owned();
            (locale, text)
        })
        .collect()
}

/// Up to `ATTEMPTS` provider answers for one message, never starting an attempt once `stop` is set.
fn translate_message(
    catalog: &Catalog,
    id: &str,
    template: &str,
    translator: &dyn Translator,
    stop: &AtomicBool,
) -> Outcome {
    let mut reason = None;
    // The most characters the template's translation may have as written, which the provider is asked to fit.
    let budget = catalog
        .template_budget(id)
        .unwrap_or_else(|| template.chars().count());
    let floor = catalog.placeholder_characters(id);
    // A text admitted for a locale is kept, so a retry only has to bring the locales still refused within bounds.
    let mut admitted = Texts::new();
    for attempt in 0..ATTEMPTS {
        if stop.load(Ordering::SeqCst) {
            return Outcome::Cancelled;
        }
        reason = match translator
            .translate(template, requested(budget, floor, attempt))
            .map(composed)
        {
            // Every complete answer adds the locales it fits; one already admitted keeps its earlier text.
            Ok(texts) if texts.keys().map(String::as_str).eq(LOCALES) => {
                let refused = refusal_reason(catalog, id, &texts);
                for (locale, text) in texts {
                    if catalog.translation_error(id, &text).is_none() {
                        admitted.entry(locale).or_insert(text);
                    }
                }
                if admitted.keys().map(String::as_str).eq(LOCALES) {
                    return Outcome::Translated(admitted);
                }
                refused
            }
            Ok(texts) => refusal_reason(catalog, id, &texts),
            Err(ProviderError::Refused) => Some(MALFORMED.to_owned()),
            Err(error) => return Outcome::Failed(error),
        };
    }
    Outcome::Refused(reason.unwrap_or_default())
}

/// The budget asked of attempt `attempt`: the full budget first, then a tenth tighter per retry, because a model
/// that overshot once tends to overshoot by a little again, never below the written placeholders every translation
/// keeps; admission still checks the full budget.
fn requested(budget: usize, floor: usize, attempt: usize) -> usize {
    (budget * (10 - attempt.min(5)) / 10).max(floor).max(1)
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
        fn translate(
            &self,
            template: &str,
            _max_characters: usize,
        ) -> Result<BTreeMap<String, String>, ProviderError> {
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

    /// Translate `catalog` against the memory under `directory` with `workers` exchanges, admitting every pack.
    fn translate_in(
        catalog: &Catalog,
        directory: &Path,
        translator: &dyn Translator,
        workers: usize,
    ) -> Result<Pack, Failure> {
        translate(
            catalog,
            POLICY,
            &memory(directory),
            translator,
            workers,
            &accept,
        )
    }

    const POLICY: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn policies_are_pinned_and_never_the_developers_policy() {
        assert_eq!(
            translated_policy(),
            "sha256:777f9b28b25a5837f257ef702bca76e5a2971a42d720a00bda11097ac5003948"
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
        let pack = translate_in(&catalog, directory.path(), &fake, WORKERS).unwrap();
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
        let reused = translate_in(&catalog, directory.path(), &again, WORKERS).unwrap();
        assert_eq!(again.calls.load(Ordering::SeqCst), 0);
        assert_eq!(reused.bytes(), pack.bytes());
    }

    #[test]
    fn retranslates_a_remembered_text_the_current_declaration_refuses() {
        let directory = tempfile::tempdir().unwrap();
        let memory = memory(directory.path());
        let catalog = catalog_of(&[("Greets people.", 80)]);
        let (id, template) = catalog.templates().next().unwrap();
        // A text admitted under a wider field no longer fits the 80-character summary bound.
        memory.put(id, &tagged(&"x".repeat(120))).unwrap();
        let fake = Fake::new(|template, _| Ok(tagged(template)));
        let pack = translate(&catalog, POLICY, &memory, &fake, WORKERS, &accept).unwrap();
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        let value: Value = serde_json::from_slice(pack.bytes()).unwrap();
        assert_eq!(value["locales"]["de"][id], format!("de {template}"));
        assert_eq!(memory.get(id), Some(tagged(template)));
    }

    #[test]
    fn keeps_each_admitted_locale_and_retries_only_until_every_locale_fits() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = catalog_of(&[("Greets people.", 80)]);
        let (id, template) = catalog.templates().next().unwrap();
        let fake = Fake::new(|template, call| {
            let mut texts = tagged(template);
            // The first answer overshoots French, the second German; together they fit every locale.
            let long = if call == 0 { "fr" } else { "de" };
            texts.insert(long.to_owned(), "x".repeat(81));
            Ok(texts)
        });
        let pack = translate_in(&catalog, directory.path(), &fake, 1).unwrap();
        assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
        let value: Value = serde_json::from_slice(pack.bytes()).unwrap();
        assert_eq!(value["locales"]["fr"][id], format!("fr {template}"));
        assert_eq!(value["locales"]["de"][id], format!("de {template}"));
    }

    #[test]
    fn asks_a_tighter_budget_on_each_retry_but_never_none() {
        assert_eq!(
            (0..ATTEMPTS)
                .map(|attempt| requested(80, 0, attempt))
                .collect::<Vec<_>>(),
            [80, 72, 64, 56, 48]
        );
        assert_eq!(requested(1, 0, 2), 1);
        // A retry never asks for fewer characters than the placeholders every translation keeps.
        assert_eq!(
            (0..ATTEMPTS)
                .map(|attempt| requested(34, 34, attempt))
                .collect::<Vec<_>>(),
            [34, 34, 34, 34, 34]
        );
    }

    #[test]
    fn a_later_fully_valid_answer_never_replaces_a_locale_already_admitted() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = catalog_of(&[("Greets people.", 80)]);
        let (id, template) = catalog.templates().next().unwrap();
        let fake = Fake::new(|template, call| {
            if call == 0 {
                let mut texts = tagged(template);
                texts.insert("fr".to_owned(), "x".repeat(81));
                Ok(texts)
            } else {
                Ok(tagged("Greets everyone."))
            }
        });
        let pack = translate_in(&catalog, directory.path(), &fake, 1).unwrap();
        let value: Value = serde_json::from_slice(pack.bytes()).unwrap();
        assert_eq!(value["locales"]["de"][id], format!("de {template}"));
        assert_eq!(value["locales"]["fr"][id], "fr Greets everyone.");
    }

    #[test]
    fn fails_after_three_refused_answers_and_remembers_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = catalog();
        let (refused_id, refused) = catalog
            .templates()
            .find(|(_, template)| template.contains('{'))
            .map(|(id, template)| (id.to_owned(), template.to_owned()))
            .unwrap();
        let fake = Fake::new(|template, call| {
            if template != refused {
                Ok(tagged(template))
            } else if call % 2 == 0 {
                // A candidate that drops the placeholders and a malformed answer are both refused.
                Ok(tagged("no placeholders"))
            } else {
                Err(ProviderError::Refused)
            }
        });
        let memory = memory(directory.path());
        let failure = translate(&catalog, POLICY, &memory, &fake, 1, &accept).unwrap_err();
        let attempted = catalog
            .templates()
            .take_while(|(_, template)| *template != refused)
            .count();
        assert_eq!(fake.calls.load(Ordering::SeqCst), attempted + ATTEMPTS);
        for (id, _) in catalog.templates() {
            assert!(memory.get(id).is_none());
        }
        // The diagnostic names the message and why its last answer was refused in each locale, never the answer.
        let last_answer_was_malformed = (attempted + ATTEMPTS - 1) % 2 == 1;
        let reason = if last_answer_was_malformed {
            MALFORMED.to_owned()
        } else {
            LOCALES
                .iter()
                .map(|locale| format!("{locale} {}", explain("translation_placeholders")))
                .collect::<Vec<_>>()
                .join(", ")
        };
        assert_eq!(
            failure,
            Failure::Refused(vec![Refusal {
                id: refused_id.clone(),
                template: refused.clone(),
                reason: reason.clone(),
            }])
        );
        let message = failure.message(Path::new("/k"));
        assert!(
            message.contains("1 message(s)")
                && message.contains(&format!(
                    "message {} ({refused:?}): {reason};",
                    &refused_id[..12]
                ))
                && message.contains("remove /k")
                && !message.contains("no placeholders"),
            "{message}"
        );
    }

    #[test]
    fn names_every_refused_locale_and_quotes_at_most_sixty_characters() {
        let catalog = catalog_of(&[("Greets people.", 80)]);
        let (id, _) = catalog.templates().next().unwrap();
        let mut texts = tagged("Greets people.");
        texts.insert("ar".into(), "\u{200b}x".into());
        texts.insert("ja".into(), "y".repeat(81));
        assert_eq!(
            refusal_reason(&catalog, id, &texts).unwrap(),
            "ar is not trimmed, printable NFC text (public_text), ja exceeds the field's length budget \
             (translation_budget)"
        );
        texts.remove("zh");
        assert_eq!(
            refusal_reason(&catalog, id, &texts).unwrap(),
            "the answer does not have exactly one text per interface language"
        );
        let long = Refusal {
            id: "a".repeat(64),
            template: "\u{e9}".repeat(61),
            reason: "r".into(),
        };
        assert_eq!(
            long.describe(),
            format!(
                "message {} ({:?}): r",
                "a".repeat(12),
                format!("{}...", "\u{e9}".repeat(60))
            )
        );
    }

    #[test]
    fn removes_directional_marks_and_composes_before_the_unchanged_admission() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = catalog();
        let (id, template) = catalog
            .templates()
            .find(|(_, template)| template.contains('{'))
            .unwrap();
        // A right-to-left mark before each placeholder, and a shadda written before its fatha (not NFC).
        let answered = "\u{64a}\u{651}\u{64e} \u{200f}{name}: \u{2067}{count}\u{2069}.";
        let repaired = "\u{64a}\u{64e}\u{651} {name}: {count}.";
        for text in [
            answered,
            "\u{64a}\u{651}\u{64e} {name}: {count}.",
            "\u{200f}{name}: {count}.",
        ] {
            assert_eq!(catalog.translation_error(id, text), Some("public_text"));
        }
        let fake = Fake::new(|template, _| {
            let mut texts = tagged(template);
            if template.contains('{') {
                texts.insert("ar".into(), answered.into());
            }
            Ok(texts)
        });
        let memory = memory(directory.path());
        let pack = translate(&catalog, POLICY, &memory, &fake, 1, &accept).unwrap();
        let value: Value = serde_json::from_slice(pack.bytes()).unwrap();
        assert_eq!(value["locales"]["ar"][id], repaired);
        assert_eq!(memory.get(id).unwrap()["ar"], repaired);

        // Every other invisible or unprintable character is still refused, never removed.
        for invisible in ["\u{200b}", "\u{200d}", "\u{feff}", "\u{a0}"] {
            let mut texts = tagged(template);
            texts.insert("ar".into(), format!("{invisible}{{name}}: {{count}}."));
            assert_eq!(
                refusal_reason(&catalog, id, &composed(texts)).unwrap(),
                format!("ar {}", explain("public_text"))
            );
        }
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
            let failure = translate_in(&catalog, directory.path(), &fake, 1).unwrap_err();
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
        let catalog = catalog_of(&[("Greets people.", 80)]);
        let fake = Fake::new(|template, call| {
            if call < 2 {
                Err(ProviderError::Refused)
            } else {
                Ok(tagged(template))
            }
        });
        assert!(translate_in(&catalog, directory.path(), &fake, 1).is_ok());
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
        translate_in(&catalog, directory.path(), &fake, WORKERS).unwrap();
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
        let catalog = catalog_of(&[("Greets people.", 80)]);
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
    fn a_terminal_failure_elsewhere_cancels_every_further_attempt() {
        let catalog = catalog_of(&[("Greets people.", 80)]);
        let (id, template) = catalog.templates().next().unwrap();
        let stop = AtomicBool::new(false);
        // Another worker fails while this inadmissible answer is in flight, which would otherwise earn two retries.
        let fake = Fake::new(|_, _| {
            stop.store(true, Ordering::SeqCst);
            Ok(tagged("no placeholders {x}"))
        });
        assert!(matches!(
            translate_message(&catalog, id, template, &fake, &stop),
            Outcome::Cancelled
        ));
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        // Nothing starts once cancelled.
        assert!(matches!(
            translate_message(&catalog, id, template, &fake, &stop),
            Outcome::Cancelled
        ));
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    }
}
