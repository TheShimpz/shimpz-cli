//! Accessible semantic terminal output.

use anstyle::{AnsiColor, Style};

const ERROR: Style = AnsiColor::Red.on_default().bold();
const WARNING: Style = AnsiColor::Yellow.on_default().bold();
const SUCCESS: Style = AnsiColor::Green.on_default().bold();
const INFO: Style = AnsiColor::Cyan.on_default().bold();

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

pub(crate) fn plain(message: &str) {
    anstream::println!("{message}");
}

pub(crate) fn data(message: &str) {
    println!("{message}");
}

fn labeled(style: Style, label: &str, message: &str) -> String {
    format!("{style}{label}:{style:#} {message}")
}

#[cfg(test)]
mod tests {
    use super::{ERROR, INFO, SUCCESS, WARNING, labeled};

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
}
