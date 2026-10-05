//! Executable test doubles for host tools, written so that no thread of the test process ever holds them open for
//! writing.
//!
//! A file this process writes can be executed only after every descriptor writing it is closed. A `fork` on another
//! test thread while the file is still open inherits that descriptor until its own `exec`, and executing the file
//! in that window fails with `ETXTBSY`. A separate shell writes and closes the file instead, so no descriptor of the
//! test process can keep it busy once this returns. Integration test crates include this same file by path.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Install `script` at `path` as an owner-only executable.
pub(crate) fn write(path: &Path, script: impl AsRef<[u8]>) {
    let mut writer = Command::new("/bin/sh")
        .args([
            "-c",
            "umask 077 && cat > \"$1\" && chmod 700 \"$1\"",
            "fake-tool",
        ])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("fake tool writer");
    writer
        .stdin
        .take()
        .expect("fake tool input")
        .write_all(script.as_ref())
        .expect("fake tool script");
    assert!(writer.wait().expect("fake tool writer").success());
}
