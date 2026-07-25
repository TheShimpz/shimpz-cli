//! Minimal command-line parsing without a runtime dependency.

use std::ffi::OsString;
use std::path::PathBuf;

pub(crate) const USAGE: &str = "Usage: shimpz <new|check|test|upgrade> [options]";
pub(crate) const HELP: &str = "\
Fast local tooling for Shimpz Assistants.

Usage:
  shimpz new assistant <name> [--language python]
  shimpz check [--project <path>]
  shimpz test <power> [--input <json> | --input-file <path>] [--project <path>]
  shimpz upgrade
  shimpz --help
  shimpz --version
";

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Action {
    Help,
    Version,
    Run(Command),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Command {
    NewAssistant {
        name: String,
    },
    Check {
        project: PathBuf,
    },
    Test {
        project: PathBuf,
        power: String,
        input: Input,
    },
    Upgrade,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Input {
    Inline(String),
    File(PathBuf),
    Stdin,
}

pub(crate) fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Action, String> {
    let values = arguments
        .into_iter()
        .map(unicode)
        .collect::<Result<Vec<_>, _>>()?;
    let Some((command, rest)) = values.split_first() else {
        return Ok(Action::Help);
    };
    match command.as_str() {
        "-h" | "--help" | "help" => Ok(Action::Help),
        "-V" | "--version" | "version" => Ok(Action::Version),
        "new" => parse_new(rest),
        "check" => parse_check(rest),
        "test" => parse_test(rest),
        "upgrade" => parse_upgrade(rest),
        _ => Err("unknown command".into()),
    }
}

fn parse_new(arguments: &[String]) -> Result<Action, String> {
    match arguments.split_first() {
        Some((option, _)) if option == "--help" || option == "-h" => Ok(Action::Help),
        Some((resource, rest)) if resource == "assistant" => parse_new_assistant(rest),
        Some(_) => Err("new only supports assistant".into()),
        None => Err("new requires a resource".into()),
    }
}

fn parse_new_assistant(arguments: &[String]) -> Result<Action, String> {
    if arguments == ["--help"] || arguments == ["-h"] {
        return Ok(Action::Help);
    }
    let mut name = None;
    let mut language = None;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if let Some(value) = argument.strip_prefix("--language=") {
            set_language(&mut language, value)?;
        } else if argument == "--language" {
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| "--language requires a value".to_owned())?;
            set_language(&mut language, value)?;
            index += 1;
        } else if argument.starts_with('-') {
            return Err(format!("unknown option {argument}"));
        } else if name.replace(argument.clone()).is_some() {
            return Err("new assistant accepts one name".into());
        }
        index += 1;
    }
    let name = name.ok_or_else(|| "new assistant requires a name".to_owned())?;
    if !valid_assistant_name(&name) {
        return Err("Assistant name is invalid".into());
    }
    Ok(Action::Run(Command::NewAssistant { name }))
}

fn set_language(language: &mut Option<String>, value: &str) -> Result<(), String> {
    if language.replace(value.to_owned()).is_some() {
        return Err("--language was repeated".into());
    }
    if value != "python" {
        return Err("only python is supported".into());
    }
    Ok(())
}

fn parse_check(arguments: &[String]) -> Result<Action, String> {
    if arguments == ["--help"] || arguments == ["-h"] {
        return Ok(Action::Help);
    }
    let project = project_option(arguments)?;
    Ok(Action::Run(Command::Check { project }))
}

fn parse_test(arguments: &[String]) -> Result<Action, String> {
    if arguments == ["--help"] || arguments == ["-h"] {
        return Ok(Action::Help);
    }
    let Some(power) = arguments.first().filter(|value| !value.starts_with('-')) else {
        return Err("test requires a Power id".into());
    };
    if !valid_power_id(power) {
        return Err("Power id is invalid".into());
    }
    let mut project = PathBuf::from(".");
    let mut project_seen = false;
    let mut input = None;
    let mut index = 1;
    while index < arguments.len() {
        let option = &arguments[index];
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{option} requires a value"))?;
        match option.as_str() {
            "--project" if !project_seen => {
                project = PathBuf::from(value);
                project_seen = true;
            }
            "--input" if input.is_none() => {
                input = Some(if value == "-" {
                    Input::Stdin
                } else {
                    Input::Inline(value.clone())
                });
            }
            "--input-file" if input.is_none() => input = Some(Input::File(PathBuf::from(value))),
            "--project" | "--input" | "--input-file" => {
                return Err(format!("{option} was repeated"));
            }
            _ => return Err(format!("unknown option {option}")),
        }
        index += 2;
    }
    Ok(Action::Run(Command::Test {
        project,
        power: power.clone(),
        input: input.unwrap_or_else(|| Input::Inline("{}".into())),
    }))
}

fn parse_upgrade(arguments: &[String]) -> Result<Action, String> {
    match arguments {
        [] => Ok(Action::Run(Command::Upgrade)),
        [option] if option == "--help" || option == "-h" => Ok(Action::Help),
        _ => Err("upgrade accepts no options".into()),
    }
}

fn project_option(arguments: &[String]) -> Result<PathBuf, String> {
    match arguments {
        [] => Ok(PathBuf::from(".")),
        [option, value] if option == "--project" => Ok(PathBuf::from(value)),
        [option] if option == "--project" => Err("--project requires a value".into()),
        _ => Err("check accepts only --project <path>".into()),
    }
}

fn unicode(value: OsString) -> Result<String, String> {
    value
        .into_string()
        .map_err(|_| "arguments must be valid UTF-8".into())
}

fn valid_power_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.starts_with(|character: char| character.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.ends_with('-')
}

fn valid_assistant_name(value: &str) -> bool {
    valid_power_id(value) && !value.contains("--")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_check_with_the_current_project() {
        assert_eq!(
            parse(strings(&["check"])),
            Ok(Action::Run(Command::Check {
                project: PathBuf::from(".")
            }))
        );
    }

    #[test]
    fn parses_a_new_python_assistant() {
        assert_eq!(
            parse(strings(&[
                "new",
                "assistant",
                "hello-assistant",
                "--language=python"
            ])),
            Ok(Action::Run(Command::NewAssistant {
                name: "hello-assistant".into()
            }))
        );
        assert_eq!(
            parse(strings(&["new", "assistant", "hello-assistant"])),
            Ok(Action::Run(Command::NewAssistant {
                name: "hello-assistant".into()
            }))
        );
    }

    #[test]
    fn rejects_invalid_new_assistant_arguments() {
        assert_eq!(
            parse(strings(&["new", "assistant", "Hello"])),
            Err("Assistant name is invalid".into())
        );
        assert_eq!(
            parse(strings(&[
                "new",
                "assistant",
                "hello",
                "--language",
                "typescript"
            ])),
            Err("only python is supported".into())
        );
        assert_eq!(
            parse(strings(&["new", "assistant", "one", "two"])),
            Err("new assistant accepts one name".into())
        );
    }

    #[test]
    fn parses_a_file_backed_power_test() {
        assert_eq!(
            parse(strings(&[
                "test",
                "create-dns",
                "--input-file",
                "request.json",
                "--project",
                "assistant"
            ])),
            Ok(Action::Run(Command::Test {
                project: PathBuf::from("assistant"),
                power: "create-dns".into(),
                input: Input::File(PathBuf::from("request.json")),
            }))
        );
    }

    #[test]
    fn rejects_secrets_and_unknown_options() {
        assert_eq!(
            parse(strings(&["test", "create-dns", "--account", "token"])),
            Err("unknown option --account".into())
        );
    }

    #[test]
    fn rejects_invalid_power_ids() {
        assert_eq!(
            parse(strings(&["test", "CreateDns"])),
            Err("Power id is invalid".into())
        );
    }

    #[test]
    fn parses_upgrade_without_options() {
        assert_eq!(
            parse(strings(&["upgrade"])),
            Ok(Action::Run(Command::Upgrade))
        );
        assert_eq!(
            parse(strings(&["upgrade", "--force"])),
            Err("upgrade accepts no options".into())
        );
    }
}
