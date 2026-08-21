//! Minimal command-line parsing without a runtime dependency.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::help::Topic;

const TOP_LEVEL_COMMANDS: [&str; 8] = [
    "assistant",
    "auth",
    "install",
    "reset",
    "start",
    "status",
    "stop",
    "upgrade",
];

pub(crate) const USAGE: &str =
    "Usage: shimpz <assistant|auth|install|reset|start|status|stop|upgrade> [options]";
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Invocation {
    Help(Topic),
    Version,
    Execute(Command),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Command {
    Auth(AuthAction),
    Assistant(AssistantCommand),
    Install(SpaceInstall),
    Reset,
    Start(SpaceStart),
    Status,
    Stop,
    Upgrade,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SpaceInstall {
    pub(crate) release: Option<String>,
    pub(crate) print_graph: Option<GraphProfile>,
    pub(crate) candidate: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphProfile {
    LinuxLuks,
    ManagedDisk,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SpaceStart {
    pub(crate) scheduled: bool,
    pub(crate) release: Option<String>,
    pub(crate) candidate: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum AssistantCommand {
    New {
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
    Run {
        project: PathBuf,
        action: String,
        input: Input,
    },
    Publish {
        project: PathBuf,
        visibility: PublicationVisibility,
    },
    Install {
        source_digest: String,
        team: Option<String>,
    },
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

pub(crate) fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Invocation, String> {
    let values = arguments
        .into_iter()
        .map(unicode)
        .collect::<Result<Vec<_>, _>>()?;
    let Some((command, rest)) = values.split_first() else {
        return Ok(Invocation::Help(Topic::Root));
    };
    match command.as_str() {
        "-h" | "--help" | "help" => return Ok(Invocation::Help(Topic::Root)),
        "-V" | "--version" | "version" => return Ok(Invocation::Version),
        _ => {}
    }
    if !TOP_LEVEL_COMMANDS.contains(&command.as_str()) {
        return Err("unknown command".into());
    }
    match command.as_str() {
        "assistant" => parse_assistant(rest),
        "auth" => parse_auth(rest),
        "install" => parse_space_install(rest),
        "reset" => parse_no_options(rest, Command::Reset, "reset", Topic::Reset),
        "start" => parse_space_start(rest),
        "status" => parse_no_options(rest, Command::Status, "status", Topic::Status),
        "stop" => parse_no_options(rest, Command::Stop, "stop", Topic::Stop),
        "upgrade" => parse_upgrade(rest),
        _ => Err("unknown command".into()),
    }
}

fn parse_space_install(arguments: &[String]) -> Result<Invocation, String> {
    match arguments {
        [] => Ok(Invocation::Execute(Command::Install(SpaceInstall {
            release: None,
            print_graph: None,
            candidate: false,
        }))),
        [option] if option == "--help" || option == "-h" => Ok(Invocation::Help(Topic::Install)),
        [option, profile] if option == "--print-graph" => {
            let print_graph = match profile.as_str() {
                "linux-luks" => GraphProfile::LinuxLuks,
                "managed-disk" => GraphProfile::ManagedDisk,
                _ => return Err("--print-graph requires linux-luks or managed-disk".into()),
            };
            Ok(Invocation::Execute(Command::Install(SpaceInstall {
                release: None,
                print_graph: Some(print_graph),
                candidate: false,
            })))
        }
        [option, release] if option == "--release" && valid_release_ref(release) => {
            Ok(Invocation::Execute(Command::Install(SpaceInstall {
                release: Some(release.clone()),
                print_graph: None,
                candidate: false,
            })))
        }
        [option, release, candidate]
            if option == "--release"
                && candidate == "--candidate"
                && valid_release_ref(release) =>
        {
            Ok(Invocation::Execute(Command::Install(SpaceInstall {
                release: Some(release.clone()),
                print_graph: None,
                candidate: true,
            })))
        }
        [option, _] if option == "--release" => {
            Err("the Local release reference is invalid".into())
        }
        [option] if option == "--release" || option == "--print-graph" => {
            Err(format!("{option} requires a value"))
        }
        _ => Err("install accepts no public options".into()),
    }
}

fn parse_space_start(arguments: &[String]) -> Result<Invocation, String> {
    let (scheduled, release, candidate) = match arguments {
        [] => (false, None, false),
        [option] if option == "--help" || option == "-h" => {
            return Ok(Invocation::Help(Topic::Start));
        }
        [option] if option == "--scheduled" => (true, None, false),
        [release_option, release, candidate_option]
            if release_option == "--release"
                && candidate_option == "--candidate"
                && valid_release_ref(release) =>
        {
            (false, Some(release.clone()), true)
        }
        [scheduled_option, release_option, release, candidate_option]
            if scheduled_option == "--scheduled"
                && release_option == "--release"
                && candidate_option == "--candidate"
                && valid_release_ref(release) =>
        {
            (true, Some(release.clone()), true)
        }
        _ => return Err("start accepts no public options".into()),
    };
    Ok(Invocation::Execute(Command::Start(SpaceStart {
        scheduled,
        release,
        candidate,
    })))
}

fn parse_no_options(
    arguments: &[String],
    command: Command,
    name: &str,
    help: Topic,
) -> Result<Invocation, String> {
    match arguments {
        [] => Ok(Invocation::Execute(command)),
        [option] if option == "--help" || option == "-h" => Ok(Invocation::Help(help)),
        _ => Err(format!("{name} accepts no options")),
    }
}

fn valid_release_ref(value: &str) -> bool {
    const PREFIX: &str = "ghcr.io/theshimpz/shimpz-local-release@sha256:";
    value.strip_prefix(PREFIX).is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn parse_assistant(arguments: &[String]) -> Result<Invocation, String> {
    let Some((operation, rest)) = arguments.split_first() else {
        return Err("assistant requires an operation".into());
    };
    match operation.as_str() {
        "-h" | "--help" | "help" => Ok(Invocation::Help(Topic::Assistant)),
        "new" => parse_assistant_new(rest),
        "develop" => parse_assistant_develop(rest),
        "check" => parse_assistant_check(rest),
        "run" => parse_assistant_run(rest),
        "publish" => parse_assistant_publish(rest),
        "install" => parse_assistant_install(rest),
        _ => Err("unknown assistant operation".into()),
    }
}

fn parse_assistant_develop(arguments: &[String]) -> Result<Invocation, String> {
    if arguments == ["--help"] || arguments == ["-h"] {
        return Ok(Invocation::Help(Topic::AssistantDevelop));
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
    Ok(Invocation::Execute(Command::Assistant(
        AssistantCommand::Develop {
            agent,
            project: project.unwrap_or_else(|| PathBuf::from(".")),
            yolo,
        },
    )))
}

fn parse_auth(arguments: &[String]) -> Result<Invocation, String> {
    let action = match arguments {
        [] => AuthAction::Login,
        [action] if action == "login" => AuthAction::Login,
        [action] if action == "status" => AuthAction::Status,
        [action] if action == "logout" => AuthAction::Logout,
        [option] if option == "--help" || option == "-h" => {
            return Ok(Invocation::Help(Topic::Auth));
        }
        [action, option] if option == "--help" || option == "-h" => {
            let topic = match action.as_str() {
                "login" => Topic::AuthLogin,
                "status" => Topic::AuthStatus,
                "logout" => Topic::AuthLogout,
                _ => return Err("auth accepts login, status, or logout".into()),
            };
            return Ok(Invocation::Help(topic));
        }
        _ => return Err("auth accepts login, status, or logout".into()),
    };
    Ok(Invocation::Execute(Command::Auth(action)))
}

fn parse_assistant_new(arguments: &[String]) -> Result<Invocation, String> {
    if arguments == ["--help"] || arguments == ["-h"] {
        return Ok(Invocation::Help(Topic::AssistantNew));
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
            return Err("assistant new accepts one name".into());
        }
        index += 1;
    }
    let name = name.ok_or_else(|| "assistant new requires a name".to_owned())?;
    if !valid_assistant_name(&name) {
        return Err("Assistant name is invalid".into());
    }
    Ok(Invocation::Execute(Command::Assistant(
        AssistantCommand::New { name },
    )))
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

fn parse_assistant_check(arguments: &[String]) -> Result<Invocation, String> {
    if arguments == ["--help"] || arguments == ["-h"] {
        return Ok(Invocation::Help(Topic::AssistantCheck));
    }
    let project = project_option(arguments)?;
    Ok(Invocation::Execute(Command::Assistant(
        AssistantCommand::Check { project },
    )))
}

fn parse_assistant_run(arguments: &[String]) -> Result<Invocation, String> {
    if arguments == ["--help"] || arguments == ["-h"] {
        return Ok(Invocation::Help(Topic::AssistantRun));
    }
    let Some(action) = arguments.first().filter(|value| !value.starts_with('-')) else {
        return Err("assistant run requires an Action id".into());
    };
    if !valid_action_id(action) {
        return Err("Action id is invalid".into());
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
    Ok(Invocation::Execute(Command::Assistant(
        AssistantCommand::Run {
            project,
            action: action.clone(),
            input: input.unwrap_or_else(|| Input::Inline("{}".into())),
        },
    )))
}

fn parse_upgrade(arguments: &[String]) -> Result<Invocation, String> {
    match arguments {
        [] => Ok(Invocation::Execute(Command::Upgrade)),
        [option] if option == "--help" || option == "-h" => Ok(Invocation::Help(Topic::Upgrade)),
        _ => Err("upgrade accepts no options".into()),
    }
}

fn parse_assistant_publish(arguments: &[String]) -> Result<Invocation, String> {
    if arguments == ["--help"] || arguments == ["-h"] {
        return Ok(Invocation::Help(Topic::AssistantPublish));
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
    let visibility =
        visibility.ok_or_else(|| "assistant publish requires --visibility".to_owned())?;
    Ok(Invocation::Execute(Command::Assistant(
        AssistantCommand::Publish {
            project,
            visibility,
        },
    )))
}

fn parse_assistant_install(arguments: &[String]) -> Result<Invocation, String> {
    if arguments == ["--help"] || arguments == ["-h"] {
        return Ok(Invocation::Help(Topic::AssistantInstall));
    }
    let Some(source_digest) = arguments.first().filter(|value| !value.starts_with('-')) else {
        return Err("assistant install requires a source digest".into());
    };
    if !valid_sha256_digest(source_digest) {
        return Err("Assistant source digest is invalid".into());
    }
    let team = match &arguments[1..] {
        [] => None,
        [option, value] if option == "--team" && valid_team_id(value) => Some(value.clone()),
        [option, _] if option == "--team" => return Err("Team id is invalid".into()),
        [option] if option == "--team" => return Err("--team requires a value".into()),
        _ => return Err("assistant install accepts only --team <team-id>".into()),
    };
    Ok(Invocation::Execute(Command::Assistant(
        AssistantCommand::Install {
            source_digest: source_digest.clone(),
            team,
        },
    )))
}

fn project_option(arguments: &[String]) -> Result<PathBuf, String> {
    match arguments {
        [] => Ok(PathBuf::from(".")),
        [option, value] if option == "--project" => Ok(PathBuf::from(value)),
        [option] if option == "--project" => Err("--project requires a value".into()),
        _ => Err("assistant check accepts only --project <path>".into()),
    }
}

fn unicode(value: OsString) -> Result<String, String> {
    value
        .into_string()
        .map_err(|_| "arguments must be valid UTF-8".into())
}

fn valid_action_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.starts_with(|character: char| character.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.ends_with('-')
}

fn valid_assistant_name(value: &str) -> bool {
    valid_action_id(value)
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
            parse(strings(&["assistant", "check"])),
            Ok(Invocation::Execute(Command::Assistant(
                AssistantCommand::Check {
                    project: PathBuf::from(".")
                }
            )))
        );
    }

    #[test]
    fn parses_auth_with_login_as_the_default() {
        assert_eq!(
            parse(strings(&["auth"])),
            Ok(Invocation::Execute(Command::Auth(AuthAction::Login)))
        );
        assert_eq!(
            parse(strings(&["auth", "login"])),
            Ok(Invocation::Execute(Command::Auth(AuthAction::Login)))
        );
        assert_eq!(
            parse(strings(&["auth", "status"])),
            Ok(Invocation::Execute(Command::Auth(AuthAction::Status)))
        );
        assert_eq!(
            parse(strings(&["auth", "logout"])),
            Ok(Invocation::Execute(Command::Auth(AuthAction::Logout)))
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
                "assistant",
                "new",
                "hello-assistant",
                "--language=python"
            ])),
            Ok(Invocation::Execute(Command::Assistant(
                AssistantCommand::New {
                    name: "hello-assistant".into()
                }
            )))
        );
        assert_eq!(
            parse(strings(&["assistant", "new", "hello-assistant"])),
            Ok(Invocation::Execute(Command::Assistant(
                AssistantCommand::New {
                    name: "hello-assistant".into()
                }
            )))
        );
    }

    #[test]
    fn parses_a_safe_or_yolo_development_session() {
        assert_eq!(
            parse(strings(&["assistant", "develop", "codex"])),
            Ok(Invocation::Execute(Command::Assistant(
                AssistantCommand::Develop {
                    agent: DeveloperAgent::Codex,
                    project: PathBuf::from("."),
                    yolo: false,
                }
            )))
        );
        assert_eq!(
            parse(strings(&[
                "assistant",
                "develop",
                "claude",
                "assistant",
                "--yolo",
            ])),
            Ok(Invocation::Execute(Command::Assistant(
                AssistantCommand::Develop {
                    agent: DeveloperAgent::Claude,
                    project: PathBuf::from("assistant"),
                    yolo: true,
                }
            )))
        );
    }

    #[test]
    fn rejects_invalid_development_session_options() {
        assert_eq!(
            parse(strings(&["assistant", "develop"])),
            Err("develop requires codex or claude".into())
        );
        assert_eq!(
            parse(strings(&["assistant", "develop", "cursor"])),
            Err("develop supports only codex or claude".into())
        );
        assert_eq!(
            parse(strings(&["assistant", "develop", "codex", "--project"])),
            Err("unknown option --project".into())
        );
        assert_eq!(
            parse(strings(&[
                "assistant",
                "develop",
                "codex",
                "--yolo",
                "--yolo",
            ])),
            Err("--yolo was repeated".into())
        );
        assert_eq!(
            parse(strings(&["assistant", "develop", "codex", "one", "two",])),
            Err("develop accepts one project path".into())
        );
    }

    #[test]
    fn rejects_invalid_new_assistant_arguments() {
        assert_eq!(
            parse(strings(&["assistant", "new", "Hello"])),
            Err("Assistant name is invalid".into())
        );
        assert_eq!(
            parse(strings(&[
                "assistant",
                "new",
                "hello",
                "--language",
                "typescript"
            ])),
            Err("only python is supported".into())
        );
        assert_eq!(
            parse(strings(&["assistant", "new", "one", "two"])),
            Err("assistant new accepts one name".into())
        );
        for name in [
            "postgres",
            "assistant-egress",
            "shimpz-assistant-egress",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert_eq!(
                parse(strings(&["assistant", "new", name])),
                Err("Assistant name is invalid".into())
            );
        }
    }

    #[test]
    fn parses_a_file_backed_action_run() {
        assert_eq!(
            parse(strings(&[
                "assistant",
                "run",
                "create-dns",
                "--input-file",
                "request.json",
                "--project",
                "assistant"
            ])),
            Ok(Invocation::Execute(Command::Assistant(
                AssistantCommand::Run {
                    project: PathBuf::from("assistant"),
                    action: "create-dns".into(),
                    input: Input::File(PathBuf::from("request.json")),
                }
            )))
        );
    }

    #[test]
    fn rejects_secrets_and_unknown_options() {
        assert_eq!(
            parse(strings(&[
                "assistant",
                "run",
                "create-dns",
                "--account",
                "token",
            ])),
            Err("unknown option --account".into())
        );
    }

    #[test]
    fn rejects_invalid_action_ids() {
        assert_eq!(
            parse(strings(&["assistant", "run", "CreateDns"])),
            Err("Action id is invalid".into())
        );
    }

    #[test]
    fn parses_upgrade_without_options() {
        assert_eq!(
            parse(strings(&["upgrade"])),
            Ok(Invocation::Execute(Command::Upgrade))
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
            parse(strings(&["assistant", "install", &digest])),
            Ok(Invocation::Execute(Command::Assistant(
                AssistantCommand::Install {
                    source_digest: digest.clone(),
                    team: None,
                },
            )))
        );
        assert_eq!(
            parse(strings(&[
                "assistant",
                "install",
                &digest,
                "--team",
                "team_1"
            ])),
            Ok(Invocation::Execute(Command::Assistant(
                AssistantCommand::Install {
                    source_digest: digest,
                    team: Some("team_1".into()),
                },
            )))
        );
    }

    #[test]
    fn parses_publish_with_a_project_or_current_directory() {
        assert_eq!(
            parse(strings(&[
                "assistant",
                "publish",
                "--visibility",
                "private",
            ])),
            Ok(Invocation::Execute(Command::Assistant(
                AssistantCommand::Publish {
                    project: PathBuf::from("."),
                    visibility: PublicationVisibility::Private,
                }
            )))
        );
        assert_eq!(
            parse(strings(&[
                "assistant",
                "publish",
                "--project",
                "hello",
                "--visibility",
                "public"
            ])),
            Ok(Invocation::Execute(Command::Assistant(
                AssistantCommand::Publish {
                    project: PathBuf::from("hello"),
                    visibility: PublicationVisibility::Public,
                }
            )))
        );
        assert_eq!(
            parse(strings(&["assistant", "publish", "--project"])),
            Err("--project requires a value".into())
        );
        assert_eq!(
            parse(strings(&["assistant", "publish"])),
            Err("assistant publish requires --visibility".into())
        );
        assert_eq!(
            parse(strings(
                &["assistant", "publish", "--visibility", "listed",]
            )),
            Err("visibility must be private or public".into())
        );
    }

    #[test]
    fn keeps_assistant_operations_out_of_the_top_level() {
        for retired in ["new", "develop", "check", "test", "publish"] {
            assert_eq!(parse(strings(&[retired])), Err("unknown command".into()));
        }
        assert_eq!(
            parse(strings(&["assistant"])),
            Err("assistant requires an operation".into())
        );
        assert_eq!(
            parse(strings(&["assistant", "test"])),
            Err("unknown assistant operation".into())
        );
    }

    #[test]
    fn keeps_the_top_level_command_set_closed() {
        assert_eq!(
            TOP_LEVEL_COMMANDS,
            [
                "assistant",
                "auth",
                "install",
                "reset",
                "start",
                "status",
                "stop",
                "upgrade"
            ]
        );
        assert_eq!(
            USAGE,
            format!("Usage: shimpz <{}> [options]", TOP_LEVEL_COMMANDS.join("|"))
        );
        for current in TOP_LEVEL_COMMANDS {
            assert_ne!(parse(strings(&[current])), Err("unknown command".into()),);
        }
        assert_eq!(parse(strings(&["space"])), Err("unknown command".into()),);
    }

    #[test]
    fn parses_the_complete_space_lifecycle_without_a_space_alias() {
        assert_eq!(
            parse(strings(&["install"])),
            Ok(Invocation::Execute(Command::Install(SpaceInstall {
                release: None,
                print_graph: None,
                candidate: false,
            })))
        );
        assert_eq!(
            parse(strings(&["start"])),
            Ok(Invocation::Execute(Command::Start(SpaceStart {
                scheduled: false,
                release: None,
                candidate: false,
            })))
        );
        assert_eq!(
            parse(strings(&["status"])),
            Ok(Invocation::Execute(Command::Status))
        );
        assert_eq!(
            parse(strings(&["stop"])),
            Ok(Invocation::Execute(Command::Stop))
        );
        assert_eq!(
            parse(strings(&["stop", "--force"])),
            Err("stop accepts no options".into())
        );
        assert_eq!(
            parse(strings(&["reset"])),
            Ok(Invocation::Execute(Command::Reset))
        );
        assert_eq!(
            parse(strings(&["space", "install"])),
            Err("unknown command".into())
        );
        assert!(Topic::Root.text().contains("shimpz stop"));
    }

    #[test]
    fn strictly_parses_hidden_reconciliation_syntax() {
        let release = format!(
            "ghcr.io/theshimpz/shimpz-local-release@sha256:{}",
            "a".repeat(64)
        );
        assert_eq!(
            parse(strings(&["start", "--scheduled"])),
            Ok(Invocation::Execute(Command::Start(SpaceStart {
                scheduled: true,
                release: None,
                candidate: false,
            })))
        );
        assert_eq!(
            parse(vec![
                "install".into(),
                "--release".into(),
                release.clone().into(),
                "--candidate".into(),
            ]),
            Ok(Invocation::Execute(Command::Install(SpaceInstall {
                release: Some(release.clone()),
                print_graph: None,
                candidate: true,
            })))
        );
        assert_eq!(
            parse(vec![
                "start".into(),
                "--scheduled".into(),
                "--release".into(),
                release.into(),
                "--candidate".into(),
            ]),
            Ok(Invocation::Execute(Command::Start(SpaceStart {
                scheduled: true,
                release: Some(format!(
                    "ghcr.io/theshimpz/shimpz-local-release@sha256:{}",
                    "a".repeat(64)
                )),
                candidate: true,
            })))
        );
        assert_eq!(
            parse(strings(&["install", "--candidate"])),
            Err("install accepts no public options".into())
        );
        for topic in Topic::ALL {
            for hidden in ["--scheduled", "--candidate", "--print-graph", "--release"] {
                assert!(!topic.text().contains(hidden));
            }
        }
    }

    #[test]
    fn help_exposes_only_resource_first_assistant_operations() {
        for current in [
            "shimpz assistant new",
            "shimpz assistant develop",
            "shimpz assistant check",
            "shimpz assistant run",
            "shimpz assistant publish",
            "shimpz assistant install",
        ] {
            assert!(Topic::Root.text().contains(current));
        }
        for retired in [
            "shimpz new assistant",
            "shimpz develop",
            "shimpz check",
            "shimpz test",
            "shimpz publish",
            "shimpz install assistant",
        ] {
            for topic in Topic::ALL {
                assert!(!topic.text().contains(retired));
            }
        }
    }

    #[test]
    fn parses_help_for_each_command_context() {
        for (arguments, topic) in [
            (&["install", "--help"][..], Topic::Install),
            (&["reset", "--help"][..], Topic::Reset),
            (&["start", "--help"][..], Topic::Start),
            (&["status", "--help"][..], Topic::Status),
            (&["stop", "--help"][..], Topic::Stop),
            (&["upgrade", "--help"][..], Topic::Upgrade),
            (&["auth", "--help"][..], Topic::Auth),
            (&["auth", "login", "--help"][..], Topic::AuthLogin),
            (&["auth", "status", "--help"][..], Topic::AuthStatus),
            (&["auth", "logout", "--help"][..], Topic::AuthLogout),
            (&["assistant", "--help"][..], Topic::Assistant),
            (&["assistant", "new", "--help"][..], Topic::AssistantNew),
            (
                &["assistant", "develop", "--help"][..],
                Topic::AssistantDevelop,
            ),
            (&["assistant", "check", "--help"][..], Topic::AssistantCheck),
            (&["assistant", "run", "--help"][..], Topic::AssistantRun),
            (
                &["assistant", "publish", "--help"][..],
                Topic::AssistantPublish,
            ),
            (
                &["assistant", "install", "--help"][..],
                Topic::AssistantInstall,
            ),
        ] {
            assert_eq!(parse(strings(arguments)), Ok(Invocation::Help(topic)));
            let mut short_arguments = arguments.to_vec();
            *short_arguments.last_mut().unwrap() = "-h";
            assert_eq!(
                parse(strings(&short_arguments)),
                Ok(Invocation::Help(topic))
            );
        }
        assert_eq!(parse(strings(&[])), Ok(Invocation::Help(Topic::Root)));
        assert_eq!(
            parse(strings(&["--help"])),
            Ok(Invocation::Help(Topic::Root))
        );
        assert_eq!(parse(strings(&["-h"])), Ok(Invocation::Help(Topic::Root)));
        assert_eq!(parse(strings(&["help"])), Ok(Invocation::Help(Topic::Root)));
        assert_eq!(
            parse(strings(&["assistant", "help"])),
            Ok(Invocation::Help(Topic::Assistant))
        );
    }

    #[test]
    fn command_help_remains_a_standalone_positional_flag() {
        assert_eq!(
            parse(strings(&["assistant", "run", "create-dns", "--help"])),
            Err("--help requires a value".into())
        );
        assert_eq!(
            parse(strings(&["reset", "--help", "extra"])),
            Err("reset accepts no options".into())
        );
        for arguments in [
            &["auth", "login", "logout"][..],
            &["auth", "token", "--help"][..],
            &["auth", "--help", "--help"][..],
        ] {
            assert_eq!(
                parse(strings(arguments)),
                Err("auth accepts login, status, or logout".into())
            );
        }
    }
}
