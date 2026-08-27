//! Lock-free Python environment management through `uv`.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde_json::Value;

use crate::toolchain;

const PYTHON_VERSION: &str = "3.14";
const SDK_REQUIREMENT: &str = "shimpz==0.4.1";
const PRIVATE_BRIDGE_FAILURE: &str = "Action execution failed; review the Action source and tests";

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
            &self.requirements,
            ["contract".as_ref(), self.root.as_os_str()],
            None,
        )
    }

    pub(crate) fn invoke(&self, action_id: &str, input: &[u8]) -> Result<String, String> {
        bridge(
            &self.requirements,
            ["invoke".as_ref(), self.root.as_os_str(), action_id.as_ref()],
            Some(input),
        )
    }
}

fn project_root(project: &Path) -> Result<PathBuf, String> {
    project
        .canonicalize()
        .map_err(|_| "Assistant project is unavailable".into())
}

fn bridge<const SIZE: usize>(
    requirements: &Requirements,
    arguments: [&OsStr; SIZE],
    input: Option<&[u8]>,
) -> Result<String, String> {
    let secret_bearing = input.is_some();
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
    command
        .args([
            "run",
            "--default-index",
            "https://pypi.org/simple",
            "--isolated",
            "--no-project",
            "--with-requirements",
        ])
        .arg(&requirements.path)
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
    if secret_bearing {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command.spawn().map_err(|_| "managed uv cannot run")?;
    if let (Some(source), Some(mut destination)) = (input, child.stdin.take()) {
        destination
            .write_all(source)
            .map_err(|_| "Action input cannot be sent")?;
    }
    let output = child
        .wait_with_output()
        .map_err(|_| "Python SDK execution failed")?;
    if output.status.success() {
        decode(output.stdout)
    } else {
        Err(bridge_failure(&output.stderr, secret_bearing))
    }
}

fn bridge_failure(stderr: &[u8], secret_bearing: bool) -> String {
    if secret_bearing {
        PRIVATE_BRIDGE_FAILURE.into()
    } else {
        diagnostic(stderr, "Assistant validation failed")
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
    fn discards_secret_bearing_bridge_diagnostics() {
        let private_output = b"private-output-sentinel";

        let diagnostic = bridge_failure(private_output, true);

        assert_eq!(diagnostic, PRIVATE_BRIDGE_FAILURE);
        assert!(!diagnostic.contains("private-output-sentinel"));
    }

    #[test]
    fn preserves_non_secret_bridge_diagnostics() {
        assert_eq!(
            bridge_failure(b"shimpz: contract failure", false),
            "contract failure"
        );
    }
}
