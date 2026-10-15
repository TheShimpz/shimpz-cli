//! Exact `[Yes/No]` confirmations a person answers on the terminal before a destructive or replacing step.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

/// One line answered to a `[Yes/No]` question.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Answer {
    /// Exactly `Yes`.
    Yes,
    /// Exactly `No`, an empty line, or no input.
    No,
    /// Any other short printable answer, which the caller may ask again for.
    Other,
    /// A line longer than eight bytes or holding a control character.
    Invalid,
}

/// The controlling terminal, opened to ask a question and read its answer.
pub(crate) fn terminal() -> io::Result<File> {
    OpenOptions::new().read(true).write(true).open("/dev/tty")
}

/// Ask `question` until the answer is `Yes` (`Some(true)`), `No` (`Some(false)`), or invalid (`None`), asking again
/// after any other answer.
pub(crate) fn ask_exactly(
    terminal: &mut (impl Read + Write),
    question: &str,
) -> io::Result<Option<bool>> {
    loop {
        match ask(terminal, question)? {
            Answer::Yes => return Ok(Some(true)),
            Answer::No => return Ok(Some(false)),
            Answer::Invalid => return Ok(None),
            Answer::Other => writeln!(terminal, "Please answer exactly Yes or No.")?,
        }
    }
}

/// Write `question` followed by ` [Yes/No] ` and read one answer, up to its newline or the end of the input.
pub(crate) fn ask(terminal: &mut (impl Read + Write), question: &str) -> std::io::Result<Answer> {
    write!(terminal, "{question} [Yes/No] ")?;
    terminal.flush()?;
    let mut answer = String::new();
    let mut byte = [0_u8; 1];
    while terminal.read(&mut byte)? == 1 {
        if byte[0] == b'\n' {
            break;
        }
        if answer.len() >= 8 || byte[0].is_ascii_control() {
            return Ok(Answer::Invalid);
        }
        answer.push(char::from(byte[0]));
    }
    Ok(match answer.as_str() {
        "Yes" => Answer::Yes,
        "No" | "" => Answer::No,
        _ => Answer::Other,
    })
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use super::{Answer, ask, ask_exactly};

    struct Terminal {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for Terminal {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buffer)
        }
    }

    impl Write for Terminal {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.output.write(buffer)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn reads_one_exact_answer() {
        for (input, expected) in [
            (&b"Yes\n"[..], Answer::Yes),
            (b"Yes", Answer::Yes),
            (b"No\n", Answer::No),
            (b"\n", Answer::No),
            (b"", Answer::No),
            (b"yes\n", Answer::Other),
            (b"Yes\r\n", Answer::Invalid),
            (b"123456789\n", Answer::Invalid),
        ] {
            let mut terminal = Terminal {
                input: Cursor::new(input.to_vec()),
                output: Vec::new(),
            };
            assert_eq!(ask(&mut terminal, "Proceed?").unwrap(), expected);
            assert_eq!(terminal.output, b"Proceed? [Yes/No] ");
        }
    }

    #[test]
    fn asks_again_until_an_exact_or_invalid_answer() {
        for (input, expected) in [
            (
                &b"yes
Yes
"[..],
                Some(true),
            ),
            (
                b"maybe
No
",
                Some(false),
            ),
            (
                b"y
\x01
", None,
            ),
        ] {
            let mut terminal = Terminal {
                input: Cursor::new(input.to_vec()),
                output: Vec::new(),
            };
            assert_eq!(ask_exactly(&mut terminal, "Proceed?").unwrap(), expected);
            assert_eq!(
                terminal.output,
                b"Proceed? [Yes/No] Please answer exactly Yes or No.\nProceed? [Yes/No] "
            );
        }
    }
}
