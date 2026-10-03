//! Exercises `shimpz assistant run` with catalog-reference human requests through the CLI process boundary.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

/// A canonical frame produced by the Python reference fingerprint (`sort_keys`, compact, no ASCII escaping).
const FRAME: &str = r#"{"type":"request","request":{"kind":"input:choice","ordinal":0,"title":{"message":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","params":{}},"description":{"message":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","params":{"zone":"example.com"}},"label":{"message":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","params":{}},"required":true,"options":[{"value":"proxied","label":{"message":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","params":{}},"description":null},{"value":"dns-only","label":{"message":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","params":{}},"description":null}],"fingerprint":"20e90c08af91d7f9a7c1a34ee04e0126c7b98df955678ca850c98c07de8de493"}}"#;
const RENDERED: &str = r#"{"kind":"input:choice","ordinal":0,"title":"Choose the DNS mode","description":"Choose how example.com is served.","label":"Mode","required":true,"options":[{"value":"proxied","label":"Proxied","description":null},{"value":"dns-only","label":"DNS only","description":null}],"fingerprint":"20e90c08af91d7f9a7c1a34ee04e0126c7b98df955678ca850c98c07de8de493"}"#;
const FINGERPRINT: &str = "20e90c08af91d7f9a7c1a34ee04e0126c7b98df955678ca850c98c07de8de493";

struct Workspace {
    root: PathBuf,
}

impl Workspace {
    fn new(name: &str, rendered: &str, render_exit: u8) -> Self {
        let root =
            std::env::temp_dir().join(format!("shimpz-run-render-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let script = format!(
            r#"#!/bin/sh
ROOT='{root}'
if [ "$1" = "--version" ]; then echo "uv 0.11.32"; exit 0; fi
if [ "$1" = "pip" ] && [ "$2" = "compile" ]; then exit 0; fi
if [ "$1" = "run" ]; then
  for argument in "$@"; do
    case "$argument" in
      contract) echo '{{"version":1,"actions":[{{"id":"greet","integrations":[]}}]}}'; exit 0;;
      render) cat > "$ROOT/render-stdin.json"; echo '{rendered}'; exit {render_exit};;
      invoke)
        count=$(ls "$ROOT" | grep -c '^invoke-')
        cat > "$ROOT/invoke-$count.json"
        if [ "$count" = 0 ]; then echo '{frame}'; else echo '{{"type":"result","result":{{"mode":"chosen"}}}}'; fi
        exit 0;;
    esac
  done
fi
exit 1
"#,
            root = root.display(),
            frame = FRAME,
        );
        fs::write(root.join("uv"), script).unwrap();
        fs::set_permissions(root.join("uv"), fs::Permissions::from_mode(0o755)).unwrap();
        Self { root }
    }

    fn run(&self, answer: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_shimpz"))
            .args(["assistant", "run", "greet", "--project"])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/assistant"
            ))
            .args(["--input", "{}"])
            .env("SHIMPZ_UV", self.root.join("uv"))
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(answer.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn json(&self, name: &str) -> Value {
        serde_json::from_slice(&fs::read(self.root.join(name)).unwrap()).unwrap()
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn shows_the_english_rendering_and_replays_the_canonical_answer() {
    let workspace = Workspace::new("choice", RENDERED, 0);
    let output = workspace.run("2\n");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let shown = format!("{stdout}{stderr}");
    assert!(output.status.success(), "{shown}");
    assert!(stdout.contains(r#""mode":"chosen""#), "{stdout}");
    for text in [
        "Choose the DNS mode",
        "Choose how example.com is served.",
        "Mode",
        "1. Proxied",
        "2. DNS only",
    ] {
        assert!(shown.contains(text), "{text}: {shown}");
    }
    assert!(!shown.contains("aaaaaaaa"), "{shown}");

    let frame: Value = serde_json::from_str(FRAME).unwrap();
    assert_eq!(
        workspace.json("render-stdin.json"),
        json!({"request": frame["request"]})
    );
    assert_eq!(
        workspace.json("invoke-1.json")["responses"],
        json!([{"kind": "input:choice", "ordinal": 0, "fingerprint": FINGERPRINT, "value": "dns-only"}])
    );
}

#[test]
fn refuses_a_rendering_that_changes_a_canonical_option_value() {
    let workspace = Workspace::new("changed", &RENDERED.replace("dns-only", "delete-all"), 0);
    let output = workspace.run("2\n");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("rendered an invalid human request"),
        "{stderr}"
    );
    assert!(!workspace.root.join("invoke-1.json").exists());
}

#[test]
fn reports_a_render_failure_without_bridge_diagnostics() {
    let workspace = Workspace::new("failed", "{}", 1);
    let output = workspace.run("2\n");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("cannot be rendered"), "{stderr}");
    assert!(!workspace.root.join("invoke-1.json").exists());
}
