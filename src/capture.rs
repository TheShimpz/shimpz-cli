//! Bounded capture of child-process output: no stream is ever held beyond the limit its caller states.

use std::io::{self, Read};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;

/// Why a bounded capture produced no output.
#[derive(Debug)]
pub(crate) enum Failure {
    /// The child could not start, its output could not be read, or it could not be reaped.
    Unavailable(io::Error),
    /// A stream exceeded its limit; the child was killed and reaped at once.
    Excessive,
}

/// Run `command` with stdin closed and capture at most `stdout_limit` and `stderr_limit` bytes, whatever its exit
/// status. A stream that exceeds its bound, or cannot be read, kills and reaps the child at once instead of letting
/// child-controlled output exhaust host memory.
pub(crate) fn bounded(
    command: &mut Command,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<Output, Failure> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(Failure::Unavailable)?;
    let (sender, receiver) = mpsc::channel();
    let streams: [(Option<Box<dyn Read + Send>>, usize); 2] = [
        (
            child.stdout.take().map(|stream| Box::new(stream) as _),
            stdout_limit,
        ),
        (
            child.stderr.take().map(|stream| Box::new(stream) as _),
            stderr_limit,
        ),
    ];
    for (index, (stream, bound)) in streams.into_iter().enumerate() {
        let sender = sender.clone();
        // A reader is never joined: after a kill, a process the child started may still hold its pipe open.
        thread::spawn(move || {
            let _ = sender.send((
                index,
                stream.map_or(Ok(Some(Vec::new())), |stream| within(stream, bound)),
            ));
        });
    }
    drop(sender);
    let mut captured = [Vec::new(), Vec::new()];
    for _ in 0..captured.len() {
        let failure = match receiver.recv() {
            Ok((index, Ok(Some(bytes)))) => {
                captured[index] = bytes;
                continue;
            }
            Ok((_, Ok(None))) => Failure::Excessive,
            Ok((_, Err(error))) => Failure::Unavailable(error),
            Err(_) => Failure::Unavailable(io::Error::other("an output reader stopped")),
        };
        let _ = child.kill();
        let _ = child.wait();
        return Err(failure);
    }
    let status = child.wait().map_err(Failure::Unavailable)?;
    let [stdout, stderr] = captured;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

/// Read a stream to its end, or stop as soon as it exceeds `limit` bytes (`None`).
fn within(stream: impl Read, limit: usize) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    stream
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)?;
    Ok((bytes.len() <= limit).then_some(bytes))
}

/// The first `limit` bytes of a stream that was read to its end, and whether anything past them was discarded.
pub(crate) struct Drained {
    pub(crate) bytes: Vec<u8>,
    pub(crate) truncated: bool,
}

/// Read a stream to its end so its writer never blocks, retaining only its first `limit` bytes.
pub(crate) fn drain(mut reader: impl Read, limit: usize) -> io::Result<Drained> {
    let mut bytes = Vec::with_capacity(limit);
    let mut truncated = false;
    let mut buffer = [0_u8; 4096];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let retained = count.min(limit.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&buffer[..retained]);
        truncated |= retained < count;
    }
    Ok(Drained { bytes, truncated })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{drain, within};

    #[test]
    fn a_bounded_read_refuses_one_byte_past_its_limit() {
        assert_eq!(
            within(Cursor::new(b"four"), 4).unwrap(),
            Some(b"four".to_vec())
        );
        assert_eq!(within(Cursor::new(b"five!"), 4).unwrap(), None);
        assert_eq!(within(Cursor::new(b""), 0).unwrap(), Some(Vec::new()));
    }

    #[test]
    fn a_drain_reads_everything_and_retains_only_the_limit() {
        let mut source = Cursor::new(vec![b'x'; 10_000]);
        let drained = drain(&mut source, 5_000).unwrap();
        assert_eq!(source.position(), 10_000);
        assert_eq!(drained.bytes.len(), 5_000);
        assert!(drained.truncated);
        let exact = drain(Cursor::new(vec![b'x'; 64]), 64).unwrap();
        assert_eq!(exact.bytes.len(), 64);
        assert!(!exact.truncated);
    }

    #[cfg(unix)]
    #[test]
    fn capture_returns_both_streams_and_the_exit_status() {
        let output = super::bounded(
            std::process::Command::new("/bin/sh")
                .args(["-c", "printf out; printf err >&2; exit 3"]),
            16,
            16,
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(output.stdout, b"out");
        assert_eq!(output.stderr, b"err");
    }

    #[cfg(unix)]
    #[test]
    fn capture_kills_a_child_whose_stream_exceeds_its_bound() {
        let started = std::time::Instant::now();
        for script in ["yes", "yes >&2"] {
            let error = super::bounded(
                std::process::Command::new("/bin/sh").args(["-c", script]),
                1024,
                1024,
            )
            .unwrap_err();
            assert!(matches!(error, super::Failure::Excessive), "{script}");
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }
}
