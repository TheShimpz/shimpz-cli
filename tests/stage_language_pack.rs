//! Proves that Local staging uses only an already prepared language pack and never contacts Developers.

#![cfg(unix)]

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
    json!([{"id": hex(SUMMARY.as_bytes()), "msgid": SUMMARY, "max_length": 160, "params": []}])
}

fn catalog_digest() -> String {
    hex(&serde_json::to_vec(&messages()).unwrap())
}

fn pack() -> Vec<u8> {
    let translations =
        Map::from_iter([(hex(SUMMARY.as_bytes()), json!("Verifica a execução local."))]);
    let locales = LOCALES
        .iter()
        .map(|locale| ((*locale).to_owned(), Value::Object(translations.clone())))
        .collect::<Map<_, _>>();
    serde_json::to_vec(&json!({
        "catalog": format!("sha256:{}", catalog_digest()),
        "format": "assistant-language-pack-v1",
        "locales": locales,
        "policy": format!("sha256:{}", "c".repeat(64)),
    }))
    .unwrap()
}

struct Workspace {
    root: PathBuf,
    uv: PathBuf,
    log: PathBuf,
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
                    "pack=$(sha256sum | cut -d' ' -f1); printf '{{\"catalog\":\"sha256:{}\",\"pack\":\"sha256:%s\"}}\\n' \"$pack\"; exit 0",
                    catalog_digest()
                ),
                |code| format!("cat >/dev/null; printf 'shimpz: {code}\\n' >&2; exit 1"),
            ),
        );
        let uv = root.join("uv");
        fs::write(&uv, script).unwrap();
        fs::set_permissions(&uv, fs::Permissions::from_mode(0o755)).unwrap();
        Self { root, uv, log }
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

#[test]
fn refuses_to_stage_without_a_prepared_pack() {
    let workspace = Workspace::new("missing");
    let output = workspace.stage();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("run 'shimpz assistant prepare', then stage again"),
        "{stderr}"
    );
    let calls = workspace.calls();
    assert!(calls.contains("shimpz._bridge catalog"), "{calls}");
    assert!(!calls.contains("pip compile"), "{calls}");
}

#[test]
fn refuses_a_tampered_prepared_pack() {
    let workspace = Workspace::new("tampered");
    let directory = workspace.root.join("cache/language-packs");
    fs::create_dir_all(&directory).unwrap();
    let mut tampered = pack();
    tampered.push(b'\n');
    fs::write(
        directory.join(format!("{}.json", catalog_digest())),
        tampered,
    )
    .unwrap();
    let output = workspace.stage();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("prepared language pack is invalid (pack_encoding)"),
        "{stderr}"
    );
    assert!(!workspace.calls().contains("pip compile"));
}

#[test]
fn stages_offline_with_the_pack_prepared_for_the_current_catalog() {
    let workspace = Workspace::new("prepared");
    let directory = workspace.root.join("cache/language-packs");
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(format!("{}.json", catalog_digest())), pack()).unwrap();
    let output = workspace.stage();
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The pack is admitted from the cache alone; staging continues to dependency resolution, which this fake
    // toolchain refuses, before any Docker work. No Creator credential or Developers request exists on this path.
    assert!(!output.status.success());
    assert!(!stderr.contains("shimpz assistant prepare"), "{stderr}");
    assert!(stderr.contains("Local snapshot dependencies"), "{stderr}");
    assert!(workspace.calls().contains("pip compile"));
}

#[test]
fn refuses_a_cached_pack_the_sdk_reference_validator_refuses() {
    let workspace = Workspace::with_validator("sdk-refused", Some("translation_placeholders"));
    let directory = workspace.root.join("cache/language-packs");
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(format!("{}.json", catalog_digest())), pack()).unwrap();
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
