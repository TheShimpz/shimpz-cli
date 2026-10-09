//! A temporary project root with a fake `uv` for `shimpz assistant run` process-boundary suites.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

use crate::fake_tool;

/// Records each `invoke` call's first input line as `invoke-<n>.json` and leaves the call count in `$count`; the
/// input stays open for provider-call replies (ADR-0106).
pub const RECORD_INVOCATION: &str = r#"count=$(ls "$ROOT" | grep -c '^invoke-')
        IFS= read -r line; printf '%s' "$line" > "$ROOT/invoke-$count.json""#;

pub struct Workspace {
    pub root: PathBuf,
}

impl Workspace {
    /// A fake `uv` that answers `--version` and `pip compile`, and dispatches `run` to the suite's `cases` arms
    /// (`contract`, `render`, `invoke`), each of which must end with `;;`.
    pub fn new(suite: &str, name: &str, cases: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("shimpz-{suite}-{name}-{}", std::process::id()));
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
{cases}
    esac
  done
fi
exit 1
"#,
            root = root.display(),
        );
        fake_tool::write(&root.join("uv"), script);
        Self { root }
    }

    /// Runs the fixture Action `greet` with `answer` on stdin and the suite's extra environment.
    pub fn run(&self, answer: &str, env: &[(&str, &str)]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_shimpz"))
            .args(["assistant", "run", "greet", "--project"])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/assistant"
            ))
            .args(["--input", "{}"])
            .env("SHIMPZ_UV", self.root.join("uv"))
            .envs(env.iter().copied())
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

    pub fn json(&self, name: &str) -> Value {
        serde_json::from_slice(&fs::read(self.root.join(name)).unwrap()).unwrap()
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
