//! Accessible semantic terminal output.

use anstyle::{AnsiColor, Style};

const ERROR: Style = AnsiColor::Red.on_default().bold();
const WARNING: Style = AnsiColor::Yellow.on_default().bold();
const SUCCESS: Style = AnsiColor::Green.on_default().bold();
const INFO: Style = AnsiColor::Cyan.on_default().bold();
const EMPHASIS: Style = Style::new().bold();

pub(crate) fn error(message: &str) {
    anstream::eprintln!("{}", labeled(ERROR, "error", message));
}

pub(crate) fn warning(message: &str) {
    anstream::eprintln!("{}", labeled(WARNING, "warning", message));
}

pub(crate) fn success(message: &str) {
    anstream::println!("{}", labeled(SUCCESS, "success", message));
}

pub(crate) fn info(message: &str) {
    anstream::println!("{}", labeled(INFO, "info", message));
}

pub(crate) fn progress(message: &str) {
    anstream::eprintln!("{}", labeled(INFO, "progress", message));
}

pub(crate) fn detail(label: &str, value: &str) {
    let label = sanitize(label);
    let value = sanitize(value);
    anstream::println!("{INFO}{label}:{INFO:#} {EMPHASIS}{value}{EMPHASIS:#}");
}

pub(crate) fn plain(message: &str) {
    anstream::println!("{}", sanitize(message));
}

pub(crate) fn data(message: &str) {
    println!("{message}");
}

fn labeled(style: Style, label: &str, message: &str) -> String {
    format!("{style}{label}:{style:#} {}", sanitize(message))
}

fn sanitize(message: &str) -> String {
    message
        .chars()
        .map(|character| {
            if character == '\n' || !character.is_control() {
                character
            } else {
                '\u{fffd}'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{ERROR, INFO, SUCCESS, WARNING, labeled, sanitize};

    #[test]
    fn severity_is_expressed_by_text_as_well_as_color() {
        for (style, label) in [
            (ERROR, "error"),
            (WARNING, "warning"),
            (SUCCESS, "success"),
            (INFO, "info"),
        ] {
            let rendered = labeled(style, label, "message");
            assert!(rendered.contains(&format!("{label}:")));
            assert!(rendered.ends_with(" message"));
            assert!(rendered.contains("\u{1b}["));
        }
    }

    #[test]
    fn human_output_neutralizes_terminal_control_characters() {
        assert_eq!(
            sanitize("safe\u{1b}[2J\rspoofed\nnext"),
            "safe�[2J�spoofed\nnext"
        );
    }
}
