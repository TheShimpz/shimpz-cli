//! Verifies adaptive semantic output at the CLI process boundary.

use std::process::{Command, Output};

fn invalid_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_shimpz"));
    command.arg("invalid-command");
    command
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn help_exposes_the_resource_first_assistant_surface() {
    let output = Command::new(env!("CARGO_BIN_EXE_shimpz"))
        .arg("--help")
        .output()
        .unwrap();
    let help = stdout(&output);

    assert!(output.status.success());
    assert!(help.contains("shimpz assistant run <action-id>"));
    assert!(help.contains("shimpz assistant install <source-digest>"));
    assert!(!help.contains("shimpz test"));
    assert!(!help.contains("shimpz install assistant"));
}

#[test]
fn retired_assistant_spellings_fail_at_the_process_boundary() {
    for arguments in [
        &["test", "hello-world"][..],
        &["install", "assistant"][..],
        &["assistant", "test", "hello-world"][..],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_shimpz"))
            .args(arguments)
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(2));
    }
}

#[test]
fn redirected_diagnostics_are_plain_and_keep_text_labels() {
    let output = invalid_command()
        .env_remove("CLICOLOR_FORCE")
        .output()
        .unwrap();
    let diagnostic = stderr(&output);

    assert!(!output.status.success());
    assert!(diagnostic.contains("error: unknown command"));
    assert!(diagnostic.contains("warning: Usage:"));
    assert!(!diagnostic.contains("\u{1b}["));
}

#[test]
fn color_can_be_forced_for_supported_consumers() {
    let output = invalid_command()
        .env_remove("NO_COLOR")
        .env("CLICOLOR_FORCE", "1")
        .output()
        .unwrap();
    let diagnostic = stderr(&output);

    assert!(diagnostic.contains("\u{1b}["));
    assert!(diagnostic.contains("error:"));
}

#[test]
fn no_color_takes_priority_over_forced_color() {
    let output = invalid_command()
        .env("NO_COLOR", "1")
        .env("CLICOLOR_FORCE", "1")
        .output()
        .unwrap();

    assert!(!stderr(&output).contains("\u{1b}["));
}

#[test]
fn untrusted_diagnostics_cannot_inject_terminal_controls() {
    let output = Command::new(env!("CARGO_BIN_EXE_shimpz"))
        .args(["assistant", "new", "demo", "--\u{1b}[2J"])
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    let diagnostic = stderr(&output);

    assert!(diagnostic.contains("unknown option --�[2J"));
    assert!(!diagnostic.contains("\u{1b}[2J"));
}
