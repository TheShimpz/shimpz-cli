//! Accessible semantic terminal output.

use std::cell::RefCell;

use anstyle::{AnsiColor, Style};

const ERROR: Style = AnsiColor::Red.on_default().bold();
const WARNING: Style = AnsiColor::Yellow.on_default().bold();
const SUCCESS: Style = AnsiColor::Green.on_default().bold();
const INFO: Style = AnsiColor::Cyan.on_default().bold();
const EMPHASIS: Style = Style::new().bold();

pub(crate) fn error(message: &str) {
    anstream::eprintln!("{}", labeled(ERROR, "error", message));
}

thread_local! {
    /// Warnings this thread withholds while it runs one check of a concurrent phase.
    static WITHHELD: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
}

pub(crate) fn warning(message: &str) {
    let withheld = WITHHELD.with_borrow_mut(|withheld| {
        withheld
            .as_mut()
            .map(|warnings| warnings.push(message.to_owned()))
            .is_some()
    });
    if !withheld {
        anstream::eprintln!("{}", labeled(WARNING, "warning", message));
    }
}

/// A check's result with the warnings it emitted, withheld until the caller judges it, so concurrent checks report
/// in the order a sequential run would and a check that is never judged reports nothing.
pub(crate) struct Withheld<T> {
    value: T,
    warnings: Vec<String>,
}

impl<T> Withheld<T> {
    /// The result, for a decision that must not report it yet.
    pub(crate) fn value(&self) -> &T {
        &self.value
    }

    /// Emit the withheld warnings, then hand over the result.
    pub(crate) fn release(self) -> T {
        for message in &self.warnings {
            warning(message);
        }
        self.value
    }
}

/// Run `check` on this thread, withholding every warning it emits.
pub(crate) fn withhold<T>(check: impl FnOnce() -> T) -> Withheld<T> {
    let outer = WITHHELD.replace(Some(Vec::new()));
    let value = check();
    let warnings = WITHHELD.replace(outer).unwrap_or_default();
    Withheld { value, warnings }
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

pub(crate) fn request(message: &str) {
    anstream::eprintln!("{}", labeled(INFO, "request", message));
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
    anstream::println!("{message}");
}

fn labeled(style: Style, label: &str, message: &str) -> String {
    format!("{style}{label}:{style:#} {}", sanitize(message))
}

pub(crate) fn sanitize(message: &str) -> String {
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

pub(crate) fn sanitize_inline(message: &str) -> String {
    message
        .chars()
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{ERROR, INFO, SUCCESS, WARNING, labeled, sanitize, sanitize_inline};

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
    fn a_withheld_check_keeps_its_warnings_until_released_and_restores_direct_output() {
        let withheld = super::withhold(|| {
            super::warning("first");
            let inner = super::withhold(|| super::warning("inner"));
            super::warning("second");
            inner
        });
        assert_eq!(withheld.warnings, ["first", "second"]);
        assert_eq!(withheld.value.warnings, ["inner"]);
        assert!(super::WITHHELD.with_borrow(Option::is_none));
    }

    #[test]
    fn human_output_neutralizes_terminal_control_characters() {
        assert_eq!(
            sanitize("safe\u{1b}[2J\rspoofed\nnext"),
            "safe�[2J�spoofed\nnext"
        );
        assert_eq!(sanitize_inline("safe\n\u{1b}[2J"), "safe��[2J");
    }
}
