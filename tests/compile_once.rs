//! Verifies one dependency compilation per local Action run.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn compiles_requirements_once_per_action_run() {
    let directory =
        std::env::temp_dir().join(format!("shimpz-compile-once-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    let log = directory.join("uv.log");
    let shim = directory.join("uv");
    let script = r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "uv 0.11.32"
  exit 0
fi
if [ "$1" = "pip" ] && [ "$2" = "compile" ]; then
  echo "pip-compile" >> "$SHIMPZ_UV_LOG"
  exit 0
fi
if [ "$1" = "run" ]; then
  for argument in "$@"; do
    if [ "$argument" = "contract" ]; then
      echo '{"version":1,"actions":[{"id":"greet","integrations":[]}]}'
      exit 0
    fi
    if [ "$argument" = "invoke" ]; then
      cat >/dev/null
      echo '{"type":"result","result":{"message":"Hello, Ada"}}'
      exit 0
    fi
  done
fi
exit 1
"#;
    fs::write(&shim, script).unwrap();
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
    let project = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/assistant");

    let output = Command::new(env!("CARGO_BIN_EXE_shimpz"))
        .args([
            "assistant",
            "run",
            "greet",
            "--project",
            project,
            "--input",
            r#"{"name":"Ada"}"#,
        ])
        .env("SHIMPZ_UV", &shim)
        .env("SHIMPZ_UV_LOG", &log)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Action run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let compiles = fs::read_to_string(log)
        .unwrap()
        .lines()
        .filter(|line| *line == "pip-compile")
        .count();
    assert_eq!(
        compiles, 1,
        "exactly one `uv pip compile` per `shimpz assistant run`"
    );
}
