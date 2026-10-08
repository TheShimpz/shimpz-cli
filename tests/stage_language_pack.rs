//! Proves that Local staging makes its language pack without any Shimpz sign-in or service (ADR-0091).

#![cfg(unix)]

#[path = "../src/fake_tool.rs"]
mod fake_tool;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const SUMMARY: &str = "Verify local file-backed Action execution.";
const LOCALES: [&str; 7] = ["ar", "de", "es", "fr", "ja", "pt", "zh"];

fn hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn messages() -> Value {
    json!([{"id": hex(SUMMARY.as_bytes()), "msgid": SUMMARY, "max_length": 80, "params": []}])
}

fn catalog_digest() -> String {
    hex(&serde_json::to_vec(&messages()).unwrap())
}

/// The pinned policy of packs translated from the workstation and of packs that show the English text.
const TRANSLATED_POLICY: &str = "2bf53fe5c497a38d08cafdf045079d7af5949f4c27329bd09b19b1dbba999c66";
const SOURCE_TEXT_POLICY: &str = "52855d44158b34c730d32bdc597e690db42f0af37c26839d507f1f87210145ff";

/// The canonical pack showing `text` for the summary in every interface language under `policy`.
fn pack(text: &str, policy: &str) -> Vec<u8> {
    let translations = Map::from_iter([(hex(SUMMARY.as_bytes()), json!(text))]);
    let locales = LOCALES
        .iter()
        .map(|locale| ((*locale).to_owned(), Value::Object(translations.clone())))
        .collect::<Map<_, _>>();
    serde_json::to_vec(&json!({
        "catalog": format!("sha256:{}", catalog_digest()),
        "format": "assistant-language-pack-v1",
        "locales": locales,
        "policy": format!("sha256:{policy}"),
    }))
    .unwrap()
}

struct Workspace {
    root: PathBuf,
    uv: PathBuf,
    log: PathBuf,
    verified: PathBuf,
}

impl Workspace {
    fn new(name: &str) -> Self {
        Self::with_validator(name, None)
    }

    /// A fake toolchain whose SDK reference validator admits every pack, or refuses with `refusal`.
    fn with_validator(name: &str, refusal: Option<&str>) -> Self {
        let root =
            std::env::temp_dir().join(format!("shimpz-stage-pack-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("cache")).unwrap();
        fs::create_dir_all(root.join("config")).unwrap();
        let log = root.join("uv.log");
        let verified = root.join("verified.json");
        let catalog = json!({"messages": messages(), "summary": SUMMARY}).to_string();
        let script = format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> '{log}'\n\
             if [ \"$1\" = --version ]; then echo 'uv 0.11.32'; exit 0; fi\n\
             if [ \"$1\" = run ]; then for argument in \"$@\"; do\n\
               if [ \"$argument\" = catalog ]; then printf '%s\\n' '{catalog}'; exit 0; fi\n\
               if [ \"$argument\" = verify-pack ]; then {verify}; fi\n\
             done; fi\n\
             exit 1\n",
            log = log.display(),
            verify = refusal.map_or_else(
                || format!(
                    "cat > '{}'; pack=$(sha256sum < '{}' | cut -d' ' -f1); printf '{{\"catalog\":\"sha256:{}\",\"pack\":\"sha256:%s\"}}\\n' \"$pack\"; exit 0",
                    verified.display(),
                    verified.display(),
                    catalog_digest()
                ),
                |code| format!("cat >/dev/null; printf 'shimpz: {code}\\n' >&2; exit 1"),
            ),
        );
        let uv = root.join("uv");
        fake_tool::write(&uv, script);
        Self {
            root,
            uv,
            log,
            verified,
        }
    }

    fn stage(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_shimpz"))
            .args(["assistant", "stage", "--project"])
            .arg(Path::new(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/assistant"
            )))
            .env("SHIMPZ_UV", &self.uv)
            .env("SHIMPZ_CACHE_DIR", self.root.join("cache"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("NO_COLOR", "1")
            .output()
            .unwrap()
    }

    fn calls(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Run `stage` and require that it reached dependency resolution, which this fake toolchain refuses before any Docker
/// work; return its standard error and the exact pack the SDK reference validator received.
fn staged_pack(workspace: &Workspace) -> (String, Vec<u8>) {
    let output = workspace.stage();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(!output.status.success());
    assert!(stderr.contains("Local snapshot dependencies"), "{stderr}");
    let calls = workspace.calls();
    assert!(calls.contains("shimpz._bridge verify-pack"), "{calls}");
    assert!(calls.contains("pip compile"), "{calls}");
    (stderr, fs::read(&workspace.verified).unwrap())
}

fn key_file(workspace: &Workspace, mode: u32) -> PathBuf {
    let directory = workspace.root.join("config/shimpz");
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("openai-api-key");
    fs::write(&path, "sk-test-not-a-real-key\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

#[test]
fn stages_english_source_text_without_a_key_or_any_sign_in() {
    let workspace = Workspace::new("source-text");
    let (stderr, staged) = staged_pack(&workspace);
    assert_eq!(staged, pack(SUMMARY, SOURCE_TEXT_POLICY));
    assert!(
        stderr.contains("Assistant messages stay in English in every interface language"),
        "{stderr}"
    );
    assert!(stderr.contains("openai-api-key"), "{stderr}");
    assert!(!stderr.contains("shimpz auth"), "{stderr}");
    assert!(!workspace.root.join("cache/translations").exists());
}

#[test]
fn stages_remembered_translations_with_a_key_without_contacting_the_provider() {
    let workspace = Workspace::new("remembered");
    key_file(&workspace, 0o600);
    let memory = workspace
        .root
        .join("cache/translations")
        .join(TRANSLATED_POLICY);
    fs::create_dir_all(&memory).unwrap();
    let texts = LOCALES
        .iter()
        .map(|locale| ((*locale).to_owned(), json!("Verifica a execução local.")))
        .collect::<Map<_, _>>();
    fs::write(
        memory.join(format!("{}.json", hex(SUMMARY.as_bytes()))),
        serde_json::to_vec(&texts).unwrap(),
    )
    .unwrap();
    let (stderr, staged) = staged_pack(&workspace);
    assert_eq!(
        staged,
        pack("Verifica a execução local.", TRANSLATED_POLICY)
    );
    assert!(!stderr.contains("Translating"), "{stderr}");
    assert!(!stderr.contains("stay in English"), "{stderr}");
    assert!(!stderr.contains("sk-test"), "{stderr}");
}

#[test]
fn refuses_an_unsafe_key_file_instead_of_staging_english_text() {
    let workspace = Workspace::new("unsafe-key");
    let path = key_file(&workspace, 0o644);
    let output = workspace.stage();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains(&path.display().to_string()), "{stderr}");
    assert!(stderr.contains("mode 0600"), "{stderr}");
    assert!(!stderr.contains("sk-test"), "{stderr}");
    assert!(!workspace.calls().contains("pip compile"));
}

#[test]
fn refuses_a_pack_the_sdk_reference_validator_refuses() {
    let workspace = Workspace::with_validator("sdk-refused", Some("translation_placeholders"));
    let output = workspace.stage();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("the Python SDK refuses the language pack (translation_placeholders)"),
        "{stderr}"
    );
    let calls = workspace.calls();
    assert!(calls.contains("shimpz._bridge verify-pack"), "{calls}");
    assert!(!calls.contains("pip compile"), "{calls}");
}
