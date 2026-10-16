//! Bounded Docker client calls: their deadlines, captured output and diagnostics, and the failures they report.

use std::ffi::OsStr;
use std::io::Read;
use std::path::Path;
use std::process::{ChildStdout, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use super::{ADMIN_AUTHENTICATION_OUTPUT_BYTES, DOCKER_QUICK};
use crate::capture::{self, Drained};

/// How long a reader may take to deliver a stream after Docker exited, before its output is treated as unavailable.
pub(super) const STREAM_GRACE: Duration = Duration::from_secs(5);

/// Run one quick Docker call with every stream closed, within its deadline.
pub(super) fn silent_status<const N: usize>(
    docker: &Path,
    arguments: [&str; N],
) -> Result<ExitStatus, String> {
    let mut child = capture::spawn(
        Command::new(docker)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )
    .map_err(|error| format!("could not execute Docker: {error}"))?;
    capture::wait(&mut child, Instant::now() + DOCKER_QUICK)
        .map_err(|failure| wait_failure(DOCKER_QUICK, failure))
}
pub(super) const MAX_DOCKER_DIAGNOSTIC_BYTES: usize = 32 * 1024;
/// The most output one captured Docker command may return on either stream before it is stopped.
pub(super) const MAX_DOCKER_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
pub(super) const TRUNCATED_DIAGNOSTIC: &str = "\n[Docker diagnostic truncated]";

pub(super) fn quiet_status(
    command: &mut Command,
    operation: &str,
    budget: Duration,
) -> Result<ExitStatus, String> {
    let (status, diagnostic) =
        execute_quiet(command, budget).map_err(|error| format!("{operation} failed: {error}"))?;
    if !status.success() {
        let detail = if diagnostic.is_empty() {
            String::new()
        } else {
            format!(": {diagnostic}")
        };
        crate::output::warning(&format!(
            "{operation} failed; Docker returned {status}{detail}"
        ));
    }
    Ok(status)
}

pub(super) fn execute_quiet(
    command: &mut Command,
    budget: Duration,
) -> Result<(ExitStatus, String), String> {
    let deadline = Instant::now() + budget;
    let mut child = capture::spawn(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped()),
    )
    .map_err(|error| format!("could not execute Docker: {error}"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "Docker diagnostic output is unavailable".to_owned())?;
    let reader = capture::Reader::start(&child, stderr, drain_diagnostic);
    let status =
        capture::wait(&mut child, deadline).map_err(|failure| wait_failure(budget, failure))?;
    let captured = reader.finish(
        deadline.max(Instant::now() + STREAM_GRACE),
        "Docker diagnostic output could not be read",
    )?;
    let diagnostic = render_diagnostic(&captured);
    Ok((status, diagnostic))
}

/// The diagnostic of a Docker call that outlived its deadline.
pub(super) fn docker_timed_out(budget: Duration, stopped: bool) -> String {
    format!(
        "Docker did not finish within {} s; {}",
        budget.as_secs(),
        capture::deadline_outcome(stopped)
    )
}

/// The diagnostic of a Docker call whose bounded wait failed.
pub(super) fn wait_failure(budget: Duration, failure: capture::Failure) -> String {
    match failure {
        capture::Failure::TimedOut { stopped } => docker_timed_out(budget, stopped),
        capture::Failure::Unavailable(error) => format!("could not execute Docker: {error}"),
        capture::Failure::Excessive => "Docker returned excessive output".to_owned(),
    }
}

pub(super) enum BoundedOutput {
    Completed {
        status: ExitStatus,
        bytes: Vec<u8>,
        truncated: bool,
    },
    TimedOut,
}

pub(super) fn execute_bounded_stdout(
    command: &mut Command,
    timeout: Duration,
) -> Result<BoundedOutput, String> {
    let deadline = Instant::now() + timeout;
    let mut child = capture::spawn(command.stdout(Stdio::piped()))
        .map_err(|error| format!("could not execute Docker: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Docker authentication-state output is unavailable".to_owned())?;
    let reader = capture::Reader::start(&child, stdout, drain_bounded_stdout);
    let status = match capture::wait(&mut child, deadline) {
        Ok(status) => status,
        Err(capture::Failure::TimedOut { stopped: true }) => return Ok(BoundedOutput::TimedOut),
        Err(failure) => return Err(wait_failure(timeout, failure)),
    };
    let captured = reader.finish(
        Instant::now() + STREAM_GRACE,
        "Docker authentication-state output could not be read",
    )?;
    Ok(BoundedOutput::Completed {
        status,
        bytes: captured.bytes,
        truncated: captured.truncated,
    })
}

fn drain_bounded_stdout(stdout: ChildStdout) -> Result<Drained, String> {
    capture::drain(stdout, ADMIN_AUTHENTICATION_OUTPUT_BYTES + 1)
        .map_err(|_| "Docker authentication-state output could not be read".to_owned())
}

pub(super) fn drain_diagnostic(reader: impl Read) -> Result<Drained, String> {
    capture::drain(reader, MAX_DOCKER_DIAGNOSTIC_BYTES)
        .map_err(|_| "Docker diagnostic output could not be read".to_owned())
}

pub(super) fn render_diagnostic(captured: &Drained) -> String {
    let decoded = String::from_utf8_lossy(&captured.bytes);
    let sanitized = crate::output::sanitize(decoded.trim());
    let content_limit = MAX_DOCKER_DIAGNOSTIC_BYTES - TRUNCATED_DIAGNOSTIC.len();
    let mut rendered = String::with_capacity(sanitized.len().min(content_limit));
    let mut truncated = captured.truncated;
    for character in sanitized.chars() {
        if rendered.len() + character.len_utf8() > content_limit {
            truncated = true;
            break;
        }
        rendered.push(character);
    }
    if truncated {
        rendered.push_str(TRUNCATED_DIAGNOSTIC);
    }
    rendered
}

pub(super) fn output<I, S>(program: &Path, arguments: I) -> Result<String, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let result = capture::bounded_within(
        Command::new(program).args(arguments),
        MAX_DOCKER_OUTPUT_BYTES,
        MAX_DOCKER_OUTPUT_BYTES,
        DOCKER_QUICK,
    )
    .map_err(|failure| match failure {
        capture::Failure::Excessive => "Docker returned excessive output".to_owned(),
        failure => wait_failure(DOCKER_QUICK, failure),
    })?;
    if !result.status.success() {
        return Err(format!(
            "Docker operation failed; Docker returned {}",
            result.status
        ));
    }
    String::from_utf8(result.stdout).map_err(|_| "Docker returned non-UTF-8 output".into())
}
