//! Exercises `shimpz assistant run` with handled failure frames and transport faults through the CLI process boundary.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

const TOKEN: &str = "integration-secret-token";
const FAILURE: &str = r#"{"type":"failure","failure":{"error_type":"httpx.HTTPStatusError","message":"Client error 404 Not Found with integration-secret-token","provider":"api.example.com","http_status":404,"response_excerpt":"{\"error\":\"zone not found\"}","redacted":false,"truncated":false}}"#;
const REQUEST: &str = r#"{"type":"request","request":{"kind":"approval","ordinal":0,"title":{"message":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","params":{}},"description":{"message":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","params":{}},"fingerprint":"a86d7cdfaf3de9ed43148b22ef4680682b65179bcd1667ed3986a873603df7ad"}}"#;

struct Workspace {
    root: PathBuf,
}

impl Workspace {
    /// A fake `uv` whose `invoke` runs `script` once per call with the call count in `$count`.
    fn new(name: &str, invoke: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("shimpz-run-failure-{name}-{}", std::process::id()));
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
      contract) echo '{{"version":1,"actions":[{{"id":"greet","integrations":["example"]}}]}}'; exit 0;;
      render) cat > /dev/null; echo '{{"kind":"approval","ordinal":0,"title":"Approve","description":"Approve the greeting.","fingerprint":"a86d7cdfaf3de9ed43148b22ef4680682b65179bcd1667ed3986a873603df7ad"}}'; exit 0;;
      invoke)
        count=$(ls "$ROOT" | grep -c '^invoke-')
        cat > "$ROOT/invoke-$count.json"
        {invoke}
    esac
  done
fi
exit 1
"#,
            root = root.display(),
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
            .env("SHIMPZ_INTEGRATION_EXAMPLE", TOKEN)
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(&mut child.stdin.take().unwrap(), answer.as_bytes()).unwrap();
        child.wait_with_output().unwrap()
    }

    fn invocation(&self, index: usize) -> Value {
        serde_json::from_slice(&fs::read(self.root.join(format!("invoke-{index}.json"))).unwrap())
            .unwrap()
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn shown(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn shows_the_sanitized_failure_and_keeps_one_operation_id_across_replay() {
    let workspace = Workspace::new(
        "handled",
        &format!(
            r#"if [ "$count" = 0 ]; then echo '{REQUEST}'; else echo '{FAILURE}'; fi; exit 0;;"#
        ),
    );

    let output = workspace.run("y\n");
    let shown = shown(&output);

    assert!(!output.status.success(), "{shown}");
    for text in [
        "Action failed: httpx.HTTPStatusError: Client error 404 Not Found with [REDACTED]",
        "Provider: api.example.com (HTTP 404)",
        "Response: {\"error\":\"zone not found\"}",
        "Some diagnostic content was redacted or withheld.",
    ] {
        assert!(shown.contains(text), "{text}: {shown}");
    }
    assert!(!shown.contains(TOKEN), "{shown}");
    let first = workspace.invocation(0)["operation_id"].clone();
    let operation_id = first.as_str().expect("operation id");
    assert_eq!(operation_id.len(), 36);
    assert_eq!(&operation_id[14..15], "4");
    assert_eq!(workspace.invocation(1)["operation_id"], first);
}

#[test]
fn refuses_a_failure_frame_outside_the_closed_contract() {
    let frame = FAILURE.replace(
        r#""truncated":false}"#,
        r#""truncated":false,"stack":"Traceback"}"#,
    );
    let workspace = Workspace::new("open", &format!("echo '{frame}'; exit 0;;"));

    let shown = shown(&workspace.run(""));

    assert!(
        shown.contains("Python SDK failure frame is invalid"),
        "{shown}"
    );
    assert!(!shown.contains("Traceback"), "{shown}");
}

#[test]
fn reports_only_the_exit_status_of_a_failed_action_process() {
    let workspace = Workspace::new(
        "nonzero",
        &format!("echo 'raw {TOKEN} output' >&2; exit 3;;"),
    );

    let output = workspace.run("");
    let shown = shown(&output);

    assert!(!output.status.success());
    assert!(
        shown.contains("without a response frame (exit status 3)"),
        "{shown}"
    );
    assert!(!shown.contains(TOKEN), "{shown}");
}

#[test]
fn refuses_an_oversized_response_frame() {
    let workspace = Workspace::new(
        "oversized",
        "head -c 600000 /dev/zero | tr '\\0' 'a'; exit 0;;",
    );

    let shown = shown(&workspace.run(""));

    assert!(shown.contains("larger than 512 KiB"), "{shown}");
}

#[test]
fn refuses_a_successful_frame_with_stderr_output_without_showing_it() {
    let workspace = Workspace::new(
        "stderr",
        &format!("echo 'warning {TOKEN}' >&2; echo '{FAILURE}'; exit 0;;"),
    );

    let output = workspace.run("");
    let shown = shown(&output);

    assert!(!output.status.success());
    assert!(shown.contains("bytes to stderr"), "{shown}");
    assert!(!shown.contains(TOKEN), "{shown}");
    assert!(!shown.contains("warning"), "{shown}");
}
