//! Bounded Docker calls of the Local Assistant snapshot commands, `shimpz assistant stage` and `unstage`.

use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, Output};

use crate::capture;

/// The Docker calls of one snapshot command: the bound of each captured stream and what their refusals name.
pub(crate) struct Calls {
    output_bytes: usize,
    subject: &'static str,
    unavailable: &'static str,
}

/// Staging reads short Docker answers, at most 32 KiB per stream; an exported file sets its own stdout bound.
pub(crate) const STAGE: Calls = Calls {
    output_bytes: 32 * 1024,
    subject: "Local snapshot",
    unavailable: "Docker could not execute the Local snapshot operation",
};

/// Removal lists every staged image of an Assistant, so each stream may hold up to 4 MiB.
pub(crate) const REMOVAL: Calls = Calls {
    output_bytes: 4 * 1024 * 1024,
    subject: "Local snapshot removal",
    unavailable: "Docker could not execute the Local snapshot removal",
};

impl Calls {
    pub(crate) fn output<I, S>(&self, docker: &Path, arguments: I) -> Result<Output, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.output_within(docker, arguments, self.output_bytes)
    }

    /// Run Docker and capture its output, never holding more than `limit` bytes of stdout or this command's bound
    /// of stderr: a stream that exceeds its bound, or cannot be read, kills and reaps Docker at once instead of
    /// letting Creator-controlled output, such as an exported file, exhaust host memory.
    pub(crate) fn output_within<I, S>(
        &self,
        docker: &Path,
        arguments: I,
        limit: usize,
    ) -> Result<Output, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        capture::bounded(
            Command::new(docker).args(arguments),
            limit,
            self.output_bytes,
        )
        .map_err(|error| match error {
            capture::Failure::Excessive => {
                format!("Docker returned excessive {} output", self.subject)
            }
            capture::Failure::Unavailable(_) | capture::Failure::TimedOut { .. } => {
                self.unavailable.to_owned()
            }
        })
    }

    pub(crate) fn text<'a>(&self, result: &'a Output) -> Result<&'a str, String> {
        std::str::from_utf8(&result.stdout)
            .map_err(|_| format!("Docker returned invalid {} output", self.subject))
    }
}

/// Whether Docker refused because the inspected image does not exist.
pub(crate) fn image_missing(result: &Output) -> bool {
    let detail = String::from_utf8_lossy(&result.stderr);
    detail.contains("No such image") || detail.contains("No such object")
}

/// The last non-blank line Docker wrote to stderr, trimmed.
pub(crate) fn last_error_line(result: &Output) -> Option<String> {
    String::from_utf8_lossy(&result.stderr)
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_owned())
}
