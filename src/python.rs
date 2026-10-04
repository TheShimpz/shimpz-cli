//! Lock-free Python environment management through `uv`.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};

use serde_json::Value;
use zeroize::Zeroizing;

use crate::{language_pack, toolchain};

const PYTHON_VERSION: &str = "3.14";
const SDK_REQUIREMENT: &str = "shimpz==0.5.2";
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
        // A secret-bearing bridge's stderr is drained and counted, never kept: any byte is a transport fault.
        .stderr(Stdio::piped());
    exchange(command, input)
}

/// Run one bridge process. Input is written on its own thread while stdout and stderr drain, so a child that fills
/// either output before it consumes a large invocation can never block both processes; the child is always reaped.
fn exchange(mut command: Command, input: Option<BridgeInput>) -> Result<String, String> {
    if input.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command.spawn().map_err(|_| "managed uv cannot run")?;
    let destination = child.stdin.take();
    let withheld = input.as_ref().and_then(|input| input.withheld);
    std::thread::scope(|scope| {
        // The writer owns the pipe, so its end closes stdin; a child that exits early ends the write with an error.
        let writer = input.zip(destination).map(|(source, mut destination)| {
            scope.spawn(move || destination.write_all(source.bytes))
        });
        let response = finish(child, withheld)?;
        match writer.map(std::thread::ScopedJoinHandle::join) {
            None | Some(Ok(Ok(()))) => Ok(response),
            Some(_) => Err("Action input cannot be sent".into()),
        }
    })
}

/// Read one bounded response frame and the child's exit status; stderr is drained only when it was captured.
fn finish(mut child: Child, withheld: Option<&'static str>) -> Result<String, String> {
    let private = withheld.is_some();
    let stderr = child
        .stderr
        .take()
        .map(|stream| std::thread::spawn(move || drain(stream, private)));
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
    let (stderr, stderr_bytes) = stderr
        .and_then(|reader| reader.join().ok())
        .unwrap_or((Vec::new(), 1));
    if !matches!(read, Some(Ok(_))) {
        return Err("Python SDK execution failed".into());
    }
    match (status.success(), private && stderr_bytes > 0) {
        (true, false) => decode(stdout),
        (true, true) => Err(format!(
            "the Action process wrote {stderr_bytes} bytes to stderr, which Team refuses as a transport fault; \
             the content is withheld"
        )),
        (false, _) => Err(bridge_failure(&stderr, status.code(), withheld)),
    }
}

/// Drain one stderr stream to its end. Private output is only counted; other output keeps a bounded prefix for
/// diagnostics. A read failure counts as output, so it can never pass as an empty stream.
fn drain(mut stream: ChildStderr, private: bool) -> (Vec<u8>, u64) {
    let mut kept = Vec::new();
    if !private {
        let _ = (&mut stream)
            .take(MAX_RESPONSE_BYTES)
            .read_to_end(&mut kept);
    }
    let rest = std::io::copy(&mut stream, &mut std::io::sink()).unwrap_or(1);
    let count = kept.len() as u64 + rest;
    (kept, count)
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

    /// Run `script` as the bridge with `input`, failing instead of hanging if the exchange deadlocks.
    #[cfg(unix)]
    fn exchange_within_deadline(script: &'static str, input: Vec<u8>) -> Result<String, String> {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut command = std::process::Command::new("sh");
            command
                .args(["-c", script])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let result = super::exchange(
                command,
                Some(super::BridgeInput {
                    bytes: &input,
                    withheld: None,
                }),
            );
            let _ = sender.send(result);
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("the bridge exchange deadlocked")
    }

    #[cfg(unix)]
    #[test]
    fn drains_stderr_written_before_a_large_input_is_read() {
        let result = exchange_within_deadline(
            r#"head -c 131072 /dev/zero >&2; bytes=$(wc -c); printf '{"bytes":%s}' $bytes"#,
            vec![b'x'; 256 * 1_024],
        );

        assert_eq!(result, Ok("{\"bytes\":262144}".to_owned()));
    }

    #[cfg(unix)]
    #[test]
    fn drains_stdout_written_before_a_large_input_is_read() {
        let result = exchange_within_deadline(
            r#"printf '{"pad":"'; head -c 131072 /dev/zero | tr '\0' a; printf '"}'; cat >/dev/null"#,
            vec![b'x'; 256 * 1_024],
        );

        assert!(result.is_ok_and(|response| response.len() == 131_072 + 10));
    }

    #[cfg(unix)]
    #[test]
    fn reports_the_failure_of_a_child_that_ended_before_reading_its_input() {
        let result = exchange_within_deadline(
            r"exec 0<&-; echo 'shimpz: dependency setup failed' >&2; exit 3",
            vec![b'x'; 256 * 1_024],
        );

        assert_eq!(result, Err("dependency setup failed".to_owned()));
    }

    #[test]
    fn preserves_non_secret_bridge_diagnostics() {
        assert_eq!(
            bridge_failure(b"shimpz: contract failure", Some(1), None),
            "contract failure"
        );
    }
}
