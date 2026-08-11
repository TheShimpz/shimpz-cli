//! Exercises real Integration injection through the CLI process boundary.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fake_uv(name: &str) -> (PathBuf, PathBuf) {
    let directory =
        std::env::temp_dir().join(format!("shimpz-integration-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    let capture = directory.join("invoke-stdin.json");
    let shim = directory.join("uv");
    let script = format!(
        r#"#!/bin/sh
SHIMPZ_INVOKE_STDIN='{}'
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
      echo '{{"version":1,"actions":[{{"id":"report","integrations":["cloudflare"]}}]}}'
      exit 0
    fi
    if [ "$argument" = "invoke" ]; then
      cat > "$SHIMPZ_INVOKE_STDIN"
      echo '{{"type":"result","result":{{"token_length":16}}}}'
      exit 0
    fi
  done
fi
exit 1
"#,
        capture.display()
    );
    fs::write(&shim, script).unwrap();
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
    (shim, capture)
}

fn run_report(shim: &Path, token: Option<&str>) -> Output {
    let project = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/assistant");
    let mut command = Command::new(env!("CARGO_BIN_EXE_shimpz"));
    command
        .args(["test", "report", "--project", project, "--input", "{}"])
        .env("SHIMPZ_UV", shim)
        .env_remove("NO_COLOR")
        .env("CLICOLOR_FORCE", "1");
    match token {
        Some(value) => command.env("SHIMPZ_INTEGRATION_CLOUDFLARE", value),
        None => command.env_remove("SHIMPZ_INTEGRATION_CLOUDFLARE"),
    };
    command.output().unwrap()
}

#[test]
fn injects_declared_integration_token() {
    let (shim, capture) = fake_uv("success");
    let output = run_report(&shim, Some("integration-secret"));
    assert!(
        output.status.success(),
        "Action test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        r#"{"token_length":16}"#
    );
    let request = fs::read_to_string(capture).unwrap();
    assert!(request.contains(r#""integrations":{"cloudflare":"integration-secret"}"#));
}

#[test]
fn fails_closed_when_integration_variable_is_missing() {
    let (shim, capture) = fake_uv("missing");
    let output = run_report(&shim, None);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("SHIMPZ_INTEGRATION_CLOUDFLARE is required for this Action")
    );
    assert!(
        !capture.exists(),
        "invoke must not run without its Integration"
    );
}
