//! Bounded capture of child-process output and bounded waits: no stream is ever held beyond the limit its caller
//! states, and a host command with a deadline is stopped and reaped once it passes it.

use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

/// How long a child asked to terminate may take before it is killed, and how long a killed child may take to be
/// reaped before it is reported as possibly remaining.
const STOP_GRACE: Duration = Duration::from_secs(5);
/// The longest pause between two checks of a running child; the first checks come sooner, so a fast command adds
/// almost no latency.
const MAX_POLL: Duration = Duration::from_millis(25);

/// Whether every host command starts in a process group of its own, so a deadline stops its descendants as well.
static ISOLATED_GROUPS: AtomicBool = AtomicBool::new(false);

/// Start every later host command in its own process group. Only an unattended run under a Linux service manager
/// does this: an interactive run keeps the terminal's process group, so its own interrupt still reaches the tool,
/// and macOS keeps the job's group, which launchd cleans up when the job ends.
pub(crate) fn isolate_process_groups() {
    ISOLATED_GROUPS.store(true, Ordering::SeqCst);
}

/// Why a bounded capture or wait produced no result.
#[derive(Debug)]
pub(crate) enum Failure {
    /// The child could not start, its output could not be read, or it could not be reaped.
    Unavailable(io::Error),
    /// A stream exceeded its limit; the child was stopped and reaped at once.
    Excessive,
    /// The child outlived its deadline. `stopped` is true when it was terminated and reaped, false when it could not
    /// be reaped and may still run.
    TimedOut { stopped: bool },
}

/// Spawn one host command, in its own process group when [`isolate_process_groups`] asked for that.
pub(crate) fn spawn(command: &mut Command) -> io::Result<Child> {
    spawn_in(command, ISOLATED_GROUPS.load(Ordering::SeqCst))
}

fn spawn_in(command: &mut Command, isolated: bool) -> io::Result<Child> {
    #[cfg(unix)]
    if isolated {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(not(unix))]
    let _ = isolated;
    command.spawn()
}

/// Wait for `child` until `deadline`; past it, terminate it, then kill it, and reap it.
pub(crate) fn wait(child: &mut Child, deadline: Instant) -> Result<ExitStatus, Failure> {
    let mut pause = Duration::from_millis(1);
    loop {
        if let Some(status) = child.try_wait().map_err(Failure::Unavailable)? {
            return Ok(status);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(Failure::TimedOut {
                stopped: stop(child),
            });
        }
        thread::sleep(pause.min(deadline - now));
        pause = (pause * 2).min(MAX_POLL);
    }
}

/// Receive what a reader thread sends before `deadline`; `None` past it or when the reader is gone.
pub(crate) fn receive<T>(receiver: &Receiver<T>, deadline: Instant) -> Option<T> {
    receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .ok()
}

/// Terminate the child, and its whole group when it leads one of its own; kill what outlives the grace; and reap
/// it. True when it was reaped; false when it could not be, so it may still run.
pub(crate) fn stop(child: &mut Child) -> bool {
    let target = Target::of(child);
    for terminate in [true, false] {
        target.signal(child, terminate);
        let deadline = Instant::now() + STOP_GRACE;
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) => {
                    // A descendant in the child's own group outlives its leader only until this kill.
                    target.kill_remaining_group();
                    return true;
                }
                Ok(None) => thread::sleep(MAX_POLL),
                Err(_) => return false,
            }
        }
    }
    false
}

/// What a stop signals: the child alone, or the process group it leads, decided before it is reaped.
#[cfg(unix)]
struct Target {
    pid: rustix::process::Pid,
    group: bool,
}

#[cfg(unix)]
impl Target {
    fn of(child: &Child) -> Self {
        let pid = rustix::process::Pid::from_child(child);
        Self {
            pid,
            group: rustix::process::getpgid(Some(pid)).is_ok_and(|group| group == pid),
        }
    }

    fn signal(&self, _child: &mut Child, terminate: bool) {
        use rustix::process::{Signal, kill_process, kill_process_group};
        let signal = if terminate {
            Signal::TERM
        } else {
            Signal::KILL
        };
        let _ = if self.group {
            kill_process_group(self.pid, signal)
        } else {
            kill_process(self.pid, signal)
        };
    }

    fn kill_remaining_group(&self) {
        if self.group {
            let _ = rustix::process::kill_process_group(self.pid, rustix::process::Signal::KILL);
        }
    }
}

#[cfg(not(unix))]
struct Target;

#[cfg(not(unix))]
impl Target {
    fn of(_child: &Child) -> Self {
        Self
    }

    fn signal(&self, child: &mut Child, _terminate: bool) {
        let _ = child.kill();
    }

    fn kill_remaining_group(&self) {}
}

/// Run `command` with stdin closed and capture at most `stdout_limit` and `stderr_limit` bytes, whatever its exit
/// status. A stream that exceeds its bound, or cannot be read, stops and reaps the child at once instead of letting
/// child-controlled output exhaust host memory. Without a `budget` it may run as long as it likes.
pub(crate) fn bounded(
    command: &mut Command,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<Output, Failure> {
    run_bounded(command, stdout_limit, stderr_limit, None)
}

/// [`bounded`], and the child is stopped and reaped once it outlives `budget`, its output reads included.
pub(crate) fn bounded_within(
    command: &mut Command,
    stdout_limit: usize,
    stderr_limit: usize,
    budget: Duration,
) -> Result<Output, Failure> {
    run_bounded(command, stdout_limit, stderr_limit, Some(budget))
}

fn run_bounded(
    command: &mut Command,
    stdout_limit: usize,
    stderr_limit: usize,
    budget: Option<Duration>,
) -> Result<Output, Failure> {
    let deadline = budget.map(|budget| Instant::now() + budget);
    let mut child = spawn(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
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
        let message = match deadline {
            Some(deadline) => {
                match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                    Ok(message) => Ok(message),
                    Err(RecvTimeoutError::Timeout) => {
                        return Err(Failure::TimedOut {
                            stopped: stop(&mut child),
                        });
                    }
                    Err(RecvTimeoutError::Disconnected) => Err(()),
                }
            }
            None => receiver.recv().map_err(|_| ()),
        };
        let failure = match message {
            Ok((index, Ok(Some(bytes)))) => {
                captured[index] = bytes;
                continue;
            }
            Ok((_, Ok(None))) => Failure::Excessive,
            Ok((_, Err(error))) => Failure::Unavailable(error),
            Err(()) => Failure::Unavailable(io::Error::other("an output reader stopped")),
        };
        stop(&mut child);
        return Err(failure);
    }
    let status = match deadline {
        Some(deadline) => wait(&mut child, deadline)?,
        None => child.wait().map_err(Failure::Unavailable)?,
    };
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
    fn a_host_command_past_its_deadline_is_terminated_and_reaped() {
        let started = std::time::Instant::now();
        let failure = super::bounded_within(
            std::process::Command::new("/bin/sh").args(["-c", "sleep 60"]),
            16,
            16,
            std::time::Duration::from_millis(200),
        )
        .unwrap_err();
        assert!(matches!(
            failure,
            super::Failure::TimedOut { stopped: true }
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn a_host_command_that_ignores_termination_is_killed_after_the_grace() {
        let mut child = super::spawn_in(
            std::process::Command::new("/bin/sh")
                .args(["-c", "trap '' TERM; while :; do sleep 1; done"]),
            false,
        )
        .unwrap();
        let started = std::time::Instant::now();
        let failure =
            super::wait(&mut child, started + std::time::Duration::from_millis(200)).unwrap_err();
        assert!(matches!(
            failure,
            super::Failure::TimedOut { stopped: true }
        ));
        assert!(started.elapsed() >= super::STOP_GRACE);
        assert!(started.elapsed() < super::STOP_GRACE * 3);
    }

    /// A descendant that keeps the output pipe open no longer holds the caller past the deadline.
    #[cfg(unix)]
    #[test]
    fn a_deadline_bounds_a_stream_a_descendant_keeps_open() {
        let started = std::time::Instant::now();
        let failure = super::bounded_within(
            std::process::Command::new("/bin/sh").args(["-c", "sleep 5 & exit 0"]),
            16,
            16,
            std::time::Duration::from_millis(300),
        )
        .unwrap_err();
        assert!(matches!(
            failure,
            super::Failure::TimedOut { stopped: true }
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    /// In its own process group, a host command's descendants are stopped with it.
    #[cfg(unix)]
    #[test]
    fn an_isolated_host_command_is_stopped_with_its_descendants() {
        let directory = tempfile::tempdir().unwrap();
        let record = directory.path().join("descendant");
        let mut child = super::spawn_in(
            std::process::Command::new("/bin/sh").args([
                "-c",
                "sleep 60 & echo $! > \"$1\"; wait",
                "isolated",
                record.to_str().unwrap(),
            ]),
            true,
        )
        .unwrap();
        while !record.exists() || std::fs::read_to_string(&record).unwrap().trim().is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let descendant: i32 = std::fs::read_to_string(&record)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let failure = super::wait(&mut child, std::time::Instant::now()).unwrap_err();
        assert!(matches!(
            failure,
            super::Failure::TimedOut { stopped: true }
        ));
        let descendant = rustix::process::Pid::from_raw(descendant).unwrap();
        // The descendant was killed; once its parent is gone it is reaped, and nothing answers its id.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while rustix::process::test_kill_process(descendant).is_ok() {
            assert!(
                std::time::Instant::now() < deadline,
                "the descendant survived"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
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
