//! Lock-free Python environment management through `uv`.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::toolchain;

const PYTHON_VERSION: &str = "3.14";
const SDK_REQUIREMENT: &str = "shimpz==0.1.0";

pub(crate) fn contract(project: &Path) -> Result<String, String> {
    let root = project_root(project)?;
    let requirements = Requirements::compile(&root)?;
    bridge(&requirements, ["contract".as_ref(), root.as_os_str()], None)
}

pub(crate) fn invoke(project: &Path, power_id: &str, input: &[u8]) -> Result<String, String> {
    let root = project_root(project)?;
    let requirements = Requirements::compile(&root)?;
    bridge(
        &requirements,
        ["invoke".as_ref(), root.as_os_str(), power_id.as_ref()],
        Some(input),
    )
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
    let mut command = toolchain::uv()?;
    command
        .args([
            "run",
            "--default-index",
            "https://pypi.org/simple",
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
        .stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command.spawn().map_err(|_| "managed uv cannot run")?;
    if let (Some(source), Some(mut destination)) = (input, child.stdin.take()) {
        destination
            .write_all(source)
            .map_err(|_| "Power input cannot be sent")?;
    }
    let output = child
        .wait_with_output()
        .map_err(|_| "Python SDK execution failed")?;
    if output.status.success() {
        String::from_utf8(output.stdout)
            .map(|value| value.trim_end().to_owned())
            .map_err(|_| "Python SDK returned invalid output".into())
    } else {
        Err(diagnostic(&output.stderr, "Assistant validation failed"))
    }
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
