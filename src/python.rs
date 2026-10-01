//! Lock-free Python environment management through `uv`.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};

use serde_json::Value;
use zeroize::Zeroizing;

use crate::{language_pack, toolchain};

const PYTHON_VERSION: &str = "3.14";
const SDK_REQUIREMENT: &str = "shimpz==0.5.0";
const PRIVATE_BRIDGE_FAILURE: &str = "the Action process ended without a response frame";
/// The largest response frame Team admits from one Action process.
const MAX_RESPONSE_BYTES: u64 = 512 * 1_024;
const RENDER_FAILURE: &str =
    "Action human request cannot be rendered; review its shimpz.text copy and the Action tests";

pub(crate) struct Assistant {
    root: PathBuf,
    requirements: Requirements,
}

impl Assistant {
    pub(crate) fn open(project: &Path) -> Result<Self, String> {
        let root = project_root(project)?;
        let requirements = Requirements::compile(&root)?;
        Ok(Self { root, requirements })
    }

    pub(crate) fn contract(&self) -> Result<String, String> {
        bridge(
            Some(&self.requirements),
            ["contract".as_ref(), self.root.as_os_str()],
            None,
        )
    }

    pub(crate) fn invoke(&self, action_id: &str, input: &[u8]) -> Result<String, String> {
        bridge(
            Some(&self.requirements),
            ["invoke".as_ref(), self.root.as_os_str(), action_id.as_ref()],
            Some(BridgeInput {
                bytes: input,
                withheld: Some(PRIVATE_BRIDGE_FAILURE),
            }),
        )
    }

    /// Render a canonical request frame's catalog references in English for terminal display only.
    pub(crate) fn render(&self, frame: &Value) -> Result<String, String> {
        // Request parameters stay private like the invocation that produced them.
        let input = Zeroizing::new(
            serde_json::to_vec(&serde_json::json!({ "request": frame }))
                .map_err(|_| "Action human request is invalid".to_owned())?,
        );
        bridge(
            None,
            ["render".as_ref(), self.root.as_os_str()],
            Some(BridgeInput {
                bytes: &input,
                withheld: Some(RENDER_FAILURE),
            }),
        )
    }
}

/// Extract the project's static English message catalog without importing Creator code or its dependencies.
pub(crate) fn catalog(project: &Path) -> Result<String, String> {
    let root = project_root(project)?;
    bridge(None, ["catalog".as_ref(), root.as_os_str()], None)
}

/// Admit exact pack bytes with the pinned SDK's packaged reference validator, the rules Team applies at install,
/// against the project's statically extracted catalog.
pub(crate) fn verify_pack(project: &Path, catalog_digest: &str, pack: &[u8]) -> Result<(), String> {
    let root = project_root(project)?;
    let acknowledgement = bridge(
        None,
        ["verify-pack".as_ref(), root.as_os_str()],
        Some(BridgeInput {
            bytes: pack,
            withheld: None,
        }),
    )
    .map_err(|reason| {
        format!(
            "the Python SDK refuses the language pack ({reason}); run 'shimpz assistant prepare' again"
        )
    })?;
    let expected = serde_json::json!({
        "catalog": catalog_digest,
        "pack": language_pack::digest(pack),
    });
    if serde_json::from_str::<Value>(&acknowledgement).ok() == Some(expected) {
        Ok(())
    } else {
        Err("Python SDK returned an invalid language pack acknowledgement".into())
    }
}

fn project_root(project: &Path) -> Result<PathBuf, String> {
    project
        .canonicalize()
        .map_err(|_| "Assistant project is unavailable".into())
}

/// Bytes sent to the bridge on stdin. Secret-bearing input withholds every bridge diagnostic behind a fixed failure.
struct BridgeInput<'a> {
    bytes: &'a [u8],
    withheld: Option<&'static str>,
}

fn bridge<const SIZE: usize>(
    requirements: Option<&Requirements>,
    arguments: [&OsStr; SIZE],
    input: Option<BridgeInput>,
) -> Result<String, String> {
    let secret_bearing = input.as_ref().is_some_and(|input| input.withheld.is_some());
    let mut command = toolchain::uv()?;
    command.env_clear();
    for key in [
        "PATH",
        "HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "XDG_CONFIG_HOME",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "PATHEXT",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command.args([
        "run",
        "--default-index",
        "https://pypi.org/simple",
        "--isolated",
        "--no-project",
    ]);
    if let Some(requirements) = requirements {
        command.arg("--with-requirements").arg(&requirements.path);
    }
    command
        .args(["--with", SDK_REQUIREMENT])
        .args([
            "--managed-python",
            "--python",
            PYTHON_VERSION,
            "--no-env-file",
            "--no-config",
            "--quiet",
            "--no-progress",
            "python",
            // Isolated mode keeps the working directory, user site, and PYTHON* variables off the import path,
            // so an excluded project root such as `shimpz/` can never shadow the pinned SDK bridge.
            "-I",
            "-m",
            "shimpz._bridge",
        ])
        .args(arguments)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdout(Stdio::piped())
        // The SDK currently redirects Action-authored stdout to stderr. Never capture
        // that mixed stream while the bridge receives credentials or hidden input.
        .stderr(if secret_bearing {
            Stdio::null()
        } else {
            Stdio::piped()
        });
    if input.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command.spawn().map_err(|_| "managed uv cannot run")?;
    if let (Some(source), Some(mut destination)) = (&input, child.stdin.take()) {
        destination
            .write_all(source.bytes)
            .map_err(|_| "Action input cannot be sent")?;
    }
    finish(child, input.and_then(|input| input.withheld))
}

/// Read one bounded response frame and the child's exit status; stderr is drained only when it was captured.
fn finish(mut child: Child, withheld: Option<&'static str>) -> Result<String, String> {
    let stderr = child.stderr.take().map(|stream| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stream.take(MAX_RESPONSE_BYTES).read_to_end(&mut bytes);
            bytes
        })
    });
    let mut stdout = Vec::new();
    let read = child
        .stdout
        .take()
        .map(|stream| stream.take(MAX_RESPONSE_BYTES + 1).read_to_end(&mut stdout));
    if stdout.len() as u64 > MAX_RESPONSE_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err("Python SDK response frame is larger than 512 KiB".into());
    }
    let status = child.wait().map_err(|_| "Python SDK execution failed")?;
    let stderr = stderr
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default();
    if !matches!(read, Some(Ok(_))) {
        return Err("Python SDK execution failed".into());
    }
    if status.success() {
        decode(stdout)
    } else {
        Err(bridge_failure(&stderr, status.code(), withheld))
    }
}

/// A secret-bearing bridge reports only its exit status: raw child output may hold a private value.
fn bridge_failure(
    stderr: &[u8],
    code: Option<i32>,
    private_failure: Option<&'static str>,
) -> String {
    match (private_failure, code) {
        (None, _) => diagnostic(stderr, "Assistant validation failed"),
        (Some(failure), Some(code)) => {
            format!("{failure} (exit status {code}); review the Action source and tests")
        }
        (Some(failure), None) => {
            format!("{failure} (terminated by a signal); review the Action source and tests")
        }
    }
}

fn decode(stdout: Vec<u8>) -> Result<String, String> {
    let text =
        String::from_utf8(stdout).map_err(|_| "Python SDK returned invalid output".to_owned())?;
    let trimmed = text.trim_end();
    serde_json::from_str::<Value>(trimmed)
        .map_err(|_| "Python SDK returned invalid output".to_owned())?;
    Ok(trimmed.to_owned())
}

fn diagnostic(stderr: &[u8], fallback: &str) -> String {
    let message = String::from_utf8_lossy(stderr);
    let trimmed = message.trim();
    if trimmed.is_empty() {
        fallback.into()
    } else {
        trimmed.strip_prefix("shimpz: ").unwrap_or(trimmed).into()
    }
}

struct Requirements {
    path: PathBuf,
}

impl Requirements {
    fn compile(project: &Path) -> Result<Self, String> {
        let metadata = project.join("pyproject.toml");
        if !metadata.is_file() {
            return Err("pyproject.toml is required".into());
        }
        let requirements = Self::temporary()?;
        let output = toolchain::uv()?
            .args([
                "pip",
                "compile",
                "--default-index",
                "https://pypi.org/simple",
            ])
            .arg(metadata)
            .args(["--output-file"])
            .arg(&requirements.path)
            .args(["--python-version", PYTHON_VERSION, "--quiet", "--no-config"])
            .output()
            .map_err(|_| "managed uv cannot run")?;
        if output.status.success() {
            Ok(requirements)
        } else {
            Err(diagnostic(
                &output.stderr,
                "Python dependencies cannot be resolved",
            ))
        }
    }

    fn temporary() -> Result<Self, String> {
        for nonce in 0..16 {
            let path = std::env::temp_dir().join(format!(
                "shimpz-{}-{nonce}-requirements.txt",
                std::process::id()
            ));
            let created = OpenOptions::new().write(true).create_new(true).open(&path);
            match created {
                Ok(_) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err("temporary dependency file cannot be created".into()),
            }
        }
        Err("temporary dependency file cannot be created".into())
    }
}

impl Drop for Requirements {
    fn drop(&mut self) {
        let _result = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::{PRIVATE_BRIDGE_FAILURE, bridge_failure, decode};

    #[test]
    fn rejects_stdout_with_leading_noise() {
        let private_output = "private-output-sentinel";
        assert_eq!(
            decode(format!("{private_output}\n{{\"ok\":1}}\n").into_bytes()),
            Err("Python SDK returned invalid output".to_owned())
        );
    }

    #[test]
    fn rejects_stdout_with_trailing_object() {
        assert!(decode(b"{\"ok\":1}{\"ok\":2}".to_vec()).is_err());
    }

    #[test]
    fn accepts_a_single_json_object() {
        assert_eq!(
            decode(b"{\"ok\":1}\n".to_vec()),
            Ok("{\"ok\":1}".to_owned())
        );
    }

    #[test]
    fn reports_only_the_exit_status_of_a_secret_bearing_bridge() {
        let private_output = b"private-output-sentinel";

        let diagnostic = bridge_failure(private_output, Some(1), Some(PRIVATE_BRIDGE_FAILURE));

        assert_eq!(
            diagnostic,
            "the Action process ended without a response frame (exit status 1); review the Action source and tests"
        );
        assert!(!diagnostic.contains("private-output-sentinel"));
        assert!(
            bridge_failure(private_output, None, Some(PRIVATE_BRIDGE_FAILURE))
                .contains("terminated by a signal")
        );
    }

    #[test]
    fn preserves_non_secret_bridge_diagnostics() {
        assert_eq!(
            bridge_failure(b"shimpz: contract failure", Some(1), None),
            "contract failure"
        );
    }
}
