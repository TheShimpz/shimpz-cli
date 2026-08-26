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
fn bare_command_prints_a_task_oriented_manual() {
    let output = Command::new(env!("CARGO_BIN_EXE_shimpz")).output().unwrap();
    let help = stdout(&output);

    assert!(output.status.success());
    assert!(help.contains("Manage a Local Space"));
    assert!(help.contains("Local Space:"));
    assert!(help.contains("Assistant development:"));
    assert!(help.contains("Common workflows:"));
    assert!(help.contains("Install or reconcile the complete Local Space."));
    assert!(help.contains("Stop it without removing its data."));
    assert!(help.contains("Run 'shimpz <command> --help' for details about a command."));
    assert!(help.contains("https://docs.shimpz.com/"));
    assert!(!help.contains("--print-graph"));
}

#[test]
fn each_command_prints_its_own_help() {
    for (arguments, expected_heading, expected_usage) in [
        (
            &["assistant", "--help"][..],
            "shimpz assistant\n",
            "shimpz assistant <operation> [options]",
        ),
        (
            &["assistant", "new", "--help"][..],
            "shimpz assistant new\n",
            "shimpz assistant new <name> [--language python]",
        ),
        (
            &["assistant", "develop", "--help"][..],
            "shimpz assistant develop\n",
            "shimpz assistant develop <codex|claude> [path] [--yolo]",
        ),
        (
            &["assistant", "check", "--help"][..],
            "shimpz assistant check\n",
            "shimpz assistant check [--project <path>]",
        ),
        (
            &["assistant", "run", "--help"][..],
            "shimpz assistant run\n",
            "shimpz assistant run <action-id> [--input <json> | --input-file <path>] [--project <path>]",
        ),
        (
            &["assistant", "publish", "--help"][..],
            "shimpz assistant publish\n",
            "shimpz assistant publish --visibility <private|public> [--project <path>]",
        ),
        (
            &["assistant", "install", "--help"][..],
            "shimpz assistant install\n",
            "shimpz assistant install <source-digest> [--team <team-id>]",
        ),
        (
            &["auth", "--help"][..],
            "shimpz auth\n",
            "shimpz auth [login|status|logout]",
        ),
        (
            &["auth", "login", "--help"][..],
            "shimpz auth login\n",
            "shimpz auth login",
        ),
        (
            &["auth", "status", "--help"][..],
            "shimpz auth status\n",
            "shimpz auth status",
        ),
        (
            &["auth", "logout", "--help"][..],
            "shimpz auth logout\n",
            "shimpz auth logout",
        ),
        (
            &["install", "--help"][..],
            "shimpz install\n",
            "shimpz install",
        ),
        (&["reset", "--help"][..], "shimpz reset\n", "shimpz reset"),
        (&["start", "--help"][..], "shimpz start\n", "shimpz start"),
        (
            &["status", "--help"][..],
            "shimpz status\n",
            "shimpz status",
        ),
        (&["stop", "--help"][..], "shimpz stop\n", "shimpz stop"),
        (
            &["update", "--help"][..],
            "shimpz update\n",
            "shimpz update",
        ),
        (
            &["upgrade", "--help"][..],
            "shimpz upgrade\n",
            "shimpz upgrade",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_shimpz"))
            .args(arguments)
            .output()
            .unwrap();
        let help = stdout(&output);

        assert!(output.status.success(), "arguments: {arguments:?}");
        assert!(
            help.starts_with(expected_heading),
            "arguments: {arguments:?}"
        );
        assert!(help.contains(expected_usage), "arguments: {arguments:?}");
        assert!(
            !help.contains("Common workflows:"),
            "arguments: {arguments:?}"
        );
        assert!(stderr(&output).is_empty(), "arguments: {arguments:?}");
    }
}

#[test]
fn reset_help_explains_the_destructive_boundary() {
    let output = Command::new(env!("CARGO_BIN_EXE_shimpz"))
        .args(["reset", "--help"])
        .output()
        .unwrap();
    let help = stdout(&output);

    assert!(output.status.success());
    assert!(help.contains("This operation is irreversible."));
    assert!(help.contains("A Supervisor password is requested only after one has been created."));
    assert!(help.contains("shimpz reset --hard"));
    assert!(help.contains("bypasses Shimpz Supervisor authorization"));
    assert!(help.contains("interactive terminal"));
    assert!(help.contains("Creator credentials and pulled images are retained"));
    assert!(!help.contains("Assistant development:"));
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
