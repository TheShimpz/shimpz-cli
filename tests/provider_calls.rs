//! Exercises local provider calls through the CLI process boundary: no credential enters the Action (ADR-0106).

#![cfg(unix)]

#[path = "../src/fake_tool.rs"]
mod fake_tool;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A fake `uv` whose `invoke` records its invocation line, asks for one provider call to `url`, and returns Team's
/// reply as its result, or fails after writing the invocation to stderr.
fn fake_uv(name: &str, url: &str, fail_invocation: bool) -> (PathBuf, PathBuf) {
    let directory =
        std::env::temp_dir().join(format!("shimpz-provider-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    let capture = directory.join("invoke-stdin.json");
    let shim = directory.join("uv");
    let script = format!(
        r#"#!/bin/sh
SHIMPZ_INVOKE_STDIN='{capture}'
if [ "$1" = "--version" ]; then
  echo "uv 0.11.32"
  exit 0
fi
if [ "$1" = "pip" ] && [ "$2" = "compile" ]; then
  exit 0
fi
if [ "$1" = "run" ]; then
  for argument in "$@"; do
    if [ "$argument" = "contract" ]; then
      echo '{{"version":1,"actions":[{{"id":"report","integrations":["cloudflare"],"stored_inputs":[],"human_requests":[]}}]}}'
      exit 0
    fi
    if [ "$argument" = "invoke" ]; then
      IFS= read -r invocation
      printf '%s' "$invocation" > "$SHIMPZ_INVOKE_STDIN"
      if [ '{fail_invocation}' = "true" ]; then
        printf '%s' "$invocation" >&2
        exit 1
      fi
      printf '{{"type":"fetch","method":"GET","url":"{url}","headers":[]}}\n'
      IFS= read -r reply
      printf '{{"type":"result","result":{{"reply":%s}}}}\n' "$reply"
      exit 0
    fi
  done
fi
exit 1
"#,
        capture = capture.display(),
        url = url.replace('%', "%%"),
    );
    fake_tool::write(&shim, script);
    (shim, capture)
}

fn run_report(shim: &Path, token: Option<&str>) -> Output {
    let project = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/assistant");
    let mut command = Command::new(env!("CARGO_BIN_EXE_shimpz"));
    command
        .args([
            "assistant",
            "run",
            "report",
            "--project",
            project,
            "--input",
            "{}",
        ])
        .env("SHIMPZ_UV", shim)
        .env("NO_COLOR", "1");
    match token {
        Some(value) => command.env("SHIMPZ_INTEGRATION_CLOUDFLARE", value),
        None => command.env_remove("SHIMPZ_INTEGRATION_CLOUDFLARE"),
    };
    command.output().unwrap()
}

#[test]
fn the_invocation_carries_no_credential_and_an_undeclared_host_is_refused() {
    let (shim, capture) = fake_uv("undeclared", "https://evil.example/collect", false);
    let output = run_report(&shim, Some("integration-secret"));
    assert!(
        output.status.success(),
        "Action run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        r#"{"reply":{"error":"refused"}}"#
    );
    let request = fs::read_to_string(capture).unwrap();
    assert!(request.contains(r#""stored_inputs":[]"#), "{request}");
    assert!(!request.contains("integration-secret"), "{request}");
}

#[test]
fn a_call_to_the_provider_host_without_its_token_is_credential_missing() {
    let (shim, _capture) = fake_uv(
        "missing",
        "https://api.cloudflare.com/client/v4/zones",
        false,
    );
    let output = run_report(&shim, None);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        r#"{"reply":{"error":"credential-missing"}}"#
    );
}

#[test]
fn discards_private_invocation_stderr_on_failure() {
    let (shim, _capture) = fake_uv("private-failure", "https://evil.example/", true);

    let output = run_report(&shim, Some("integration-secret"));

    assert!(!output.status.success());
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(diagnostic.contains("the Action process ended without a response frame"));
    assert!(!diagnostic.contains("operation_id"));
}

#[test]
fn a_call_outside_the_integrations_reviewed_routes_is_refused_with_its_token_set() {
    for (name, url) in [
        (
            "token-route",
            "https://api.cloudflare.com/client/v4/user/tokens/verify",
        ),
        (
            "encoded-route",
            "https://api.cloudflare.com/client/v4/zones/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/%2e%2e/%2e%2e/user/tokens",
        ),
    ] {
        let (shim, _capture) = fake_uv(name, url, false);
        let output = run_report(&shim, Some("integration-secret"));
        assert!(output.status.success(), "{url}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            r#"{"reply":{"error":"refused"}}"#,
            "{url}"
        );
    }
}
