//! Minimal command-line parsing without a runtime dependency.

use std::ffi::OsString;
use std::path::PathBuf;

pub(crate) const USAGE: &str =
    "Usage: shimpz <auth|new|develop|check|test|publish|install|upgrade> [options]";
pub(crate) const HELP: &str = "\
Fast local tooling for Shimpz Assistants.

Usage:
  shimpz auth [login|status|logout]
  shimpz new assistant <name> [--language python]
  shimpz develop <codex|claude> [path] [--yolo]
  shimpz check [--project <path>]
  shimpz test <power> [--input <json> | --input-file <path>] [--project <path>]
  shimpz publish --visibility <private|public> [--project <path>]
  shimpz install assistant <source-hash> [--team <team-id>]
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
    Auth(AuthAction),
    NewAssistant {
        name: String,
    },
    Develop {
        agent: DeveloperAgent,
        project: PathBuf,
        yolo: bool,
    },
    Check {
        project: PathBuf,
    },
    Test {
        project: PathBuf,
        power: String,
        input: Input,
    },
    Publish {
        project: PathBuf,
        visibility: PublicationVisibility,
    },
    InstallAssistant {
        source_digest: String,
        team: Option<String>,
    },
    Upgrade,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeveloperAgent {
    Claude,
    Codex,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum AuthAction {
    Login,
    Status,
    Logout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationVisibility {
    Private,
    Public,
}

impl PublicationVisibility {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Public => "public",
        }
    }
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
        "auth" => parse_auth(rest),
        "new" => parse_new(rest),
        "develop" => parse_develop(rest),
        "check" => parse_check(rest),
        "test" => parse_test(rest),
        "publish" => parse_publish(rest),
        "install" => parse_install(rest),
        "upgrade" => parse_upgrade(rest),
        _ => Err("unknown command".into()),
    }
}

fn parse_develop(arguments: &[String]) -> Result<Action, String> {
    if arguments == ["--help"] || arguments == ["-h"] {
        return Ok(Action::Help);
    }
    let Some((agent, options)) = arguments.split_first() else {
        return Err("develop requires codex or claude".into());
    };
    let agent = match agent.as_str() {
        "codex" => DeveloperAgent::Codex,
        "claude" => DeveloperAgent::Claude,
        _ => return Err("develop supports only codex or claude".into()),
    };
    let mut project = None;
    let mut yolo = false;
    for option in options {
        if option == "--yolo" {
            if yolo {
                return Err("--yolo was repeated".into());
            }
            yolo = true;
        } else if option.starts_with('-') {
            return Err(format!("unknown option {option}"));
        } else if project.is_some() {
            return Err("develop accepts one project path".into());
        } else {
            project = Some(PathBuf::from(option));
        }
    }
    Ok(Action::Run(Command::Develop {
        agent,
        project: project.unwrap_or_else(|| PathBuf::from(".")),
        yolo,
    }))
}

fn parse_auth(arguments: &[String]) -> Result<Action, String> {
    let action = match arguments {
        [] => AuthAction::Login,
        [action] if action == "login" => AuthAction::Login,
        [action] if action == "status" => AuthAction::Status,
        [action] if action == "logout" => AuthAction::Logout,
        [option] if option == "--help" || option == "-h" => return Ok(Action::Help),
        _ => return Err("auth accepts login, status, or logout".into()),
    };
    Ok(Action::Run(Command::Auth(action)))
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

fn parse_publish(arguments: &[String]) -> Result<Action, String> {
    if arguments == ["--help"] || arguments == ["-h"] {
        return Ok(Action::Help);
    }
    let mut project = PathBuf::from(".");
    let mut project_seen = false;
    let mut visibility = None;
    let mut index = 0;
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
            "--visibility" if visibility.is_none() => {
                visibility = Some(match value.as_str() {
                    "private" => PublicationVisibility::Private,
                    "public" => PublicationVisibility::Public,
                    _ => return Err("visibility must be private or public".into()),
                });
            }
            "--project" | "--visibility" => return Err(format!("{option} was repeated")),
            _ => return Err(format!("unknown option {option}")),
        }
        index += 2;
    }
    let visibility = visibility.ok_or_else(|| "publish requires --visibility".to_owned())?;
    Ok(Action::Run(Command::Publish {
        project,
        visibility,
    }))
}

fn parse_install(arguments: &[String]) -> Result<Action, String> {
    if arguments == ["--help"] || arguments == ["-h"] {
        return Ok(Action::Help);
    }
    let Some((resource, rest)) = arguments.split_first() else {
        return Err("install requires a resource".into());
    };
    if resource != "assistant" {
        return Err("install only supports assistant".into());
    }
    let Some(source_digest) = rest.first().filter(|value| !value.starts_with('-')) else {
        return Err("install assistant requires a source hash".into());
    };
    if !valid_sha256_digest(source_digest) {
        return Err("Assistant source hash is invalid".into());
    }
    let team = match &rest[1..] {
        [] => None,
        [option, value] if option == "--team" && valid_team_id(value) => Some(value.clone()),
        [option, _] if option == "--team" => return Err("Team id is invalid".into()),
        [option] if option == "--team" => return Err("--team requires a value".into()),
        _ => return Err("install assistant accepts only --team <team-id>".into()),
    };
    Ok(Action::Run(Command::InstallAssistant {
        source_digest: source_digest.clone(),
        team,
    }))
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
    valid_power_id(value)
        && value.len() <= 40
        && !value.contains("--")
        && !matches!(
            value,
            "postgres" | "assistant-egress" | "shimpz-assistant-egress"
        )
}

fn valid_team_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
    fn parses_auth_with_login_as_the_default() {
        assert_eq!(
            parse(strings(&["auth"])),
            Ok(Action::Run(Command::Auth(AuthAction::Login)))
        );
        assert_eq!(
            parse(strings(&["auth", "login"])),
            Ok(Action::Run(Command::Auth(AuthAction::Login)))
        );
        assert_eq!(
            parse(strings(&["auth", "status"])),
            Ok(Action::Run(Command::Auth(AuthAction::Status)))
        );
        assert_eq!(
            parse(strings(&["auth", "logout"])),
            Ok(Action::Run(Command::Auth(AuthAction::Logout)))
        );
        assert_eq!(
            parse(strings(&["auth", "token"])),
            Err("auth accepts login, status, or logout".into())
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
    fn parses_a_safe_or_yolo_development_session() {
        assert_eq!(
            parse(strings(&["develop", "codex"])),
            Ok(Action::Run(Command::Develop {
                agent: DeveloperAgent::Codex,
                project: PathBuf::from("."),
                yolo: false,
            }))
        );
        assert_eq!(
            parse(strings(&["develop", "claude", "assistant", "--yolo",])),
            Ok(Action::Run(Command::Develop {
                agent: DeveloperAgent::Claude,
                project: PathBuf::from("assistant"),
                yolo: true,
            }))
        );
    }

    #[test]
    fn rejects_invalid_development_session_options() {
        assert_eq!(
            parse(strings(&["develop"])),
            Err("develop requires codex or claude".into())
        );
        assert_eq!(
            parse(strings(&["develop", "cursor"])),
            Err("develop supports only codex or claude".into())
        );
        assert_eq!(
            parse(strings(&["develop", "codex", "--project"])),
            Err("unknown option --project".into())
        );
        assert_eq!(
            parse(strings(&["develop", "codex", "--yolo", "--yolo"])),
            Err("--yolo was repeated".into())
        );
        assert_eq!(
            parse(strings(&["develop", "codex", "one", "two"])),
            Err("develop accepts one project path".into())
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
        for name in [
            "postgres",
            "assistant-egress",
            "shimpz-assistant-egress",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert_eq!(
                parse(strings(&["new", "assistant", name])),
                Err("Assistant name is invalid".into())
            );
        }
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

    #[test]
    fn parses_assistant_install_with_an_optional_team() {
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            parse(strings(&["install", "assistant", &digest])),
            Ok(Action::Run(Command::InstallAssistant {
                source_digest: digest.clone(),
                team: None,
            }))
        );
        assert_eq!(
            parse(strings(&[
                "install",
                "assistant",
                &digest,
                "--team",
                "team_1"
            ])),
            Ok(Action::Run(Command::InstallAssistant {
                source_digest: digest,
                team: Some("team_1".into()),
            }))
        );
    }

    #[test]
    fn parses_publish_with_a_project_or_current_directory() {
        assert_eq!(
            parse(strings(&["publish", "--visibility", "private"])),
            Ok(Action::Run(Command::Publish {
                project: PathBuf::from("."),
                visibility: PublicationVisibility::Private,
            }))
        );
        assert_eq!(
            parse(strings(&[
                "publish",
                "--project",
                "hello",
                "--visibility",
                "public"
            ])),
            Ok(Action::Run(Command::Publish {
                project: PathBuf::from("hello"),
                visibility: PublicationVisibility::Public,
            }))
        );
        assert_eq!(
            parse(strings(&["publish", "--project"])),
            Err("--project requires a value".into())
        );
        assert_eq!(
            parse(strings(&["publish"])),
            Err("publish requires --visibility".into())
        );
        assert_eq!(
            parse(strings(&["publish", "--visibility", "listed"])),
            Err("visibility must be private or public".into())
        );
    }
}
