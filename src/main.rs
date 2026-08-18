//! Command-line tooling for Shimpz Assistants.

mod args;
mod auth;
mod credentials;
mod develop;
mod human_request;
mod install;
mod invoke;
mod manifest;
mod new_assistant;
mod output;
mod publish;
mod python;
mod source_package;
mod space;
mod toolchain;
mod upgrade;
mod ustar;

#[cfg(test)]
mod source_package_tests;

use std::env;
use std::process::ExitCode;

use args::{AssistantCommand, AuthAction, Command, Invocation};

fn main() -> ExitCode {
    match args::parse(env::args_os().skip(1)) {
        Ok(Invocation::Help) => {
            output::plain(args::HELP.trim_end());
            ExitCode::SUCCESS
        }
        Ok(Invocation::Version) => {
            output::plain(&format!("shimpz {}", env!("CARGO_PKG_VERSION")));
            ExitCode::SUCCESS
        }
        Ok(Invocation::Execute(command)) => run(&command),
        Err(message) => {
            output::error(&message);
            output::warning(args::USAGE);
            ExitCode::from(2)
        }
    }
}

fn run(command: &Command) -> ExitCode {
    let (result, presentation) = match command {
        Command::Auth(AuthAction::Login) => (auth::login(), Presentation::Success),
        Command::Auth(AuthAction::Status) => (auth::status(), Presentation::Info),
        Command::Auth(AuthAction::Logout) => (auth::logout(), Presentation::Success),
        Command::Assistant(AssistantCommand::New { name }) => {
            (new_assistant::run(name), Presentation::Success)
        }
        Command::Assistant(AssistantCommand::Develop {
            agent,
            project,
            yolo,
        }) => (develop::run(*agent, project, *yolo), Presentation::Success),
        Command::Assistant(AssistantCommand::Check { project }) => {
            (check(project), Presentation::Success)
        }
        Command::Assistant(AssistantCommand::Run {
            project,
            action,
            input,
        }) => (invoke::run(project, action, input), Presentation::Data),
        Command::Assistant(AssistantCommand::Publish {
            project,
            visibility,
        }) => (publish::run(project, *visibility), Presentation::Success),
        Command::Assistant(AssistantCommand::Install {
            source_digest,
            team,
        }) => (
            install::run(source_digest, team.as_deref()),
            Presentation::Success,
        ),
        Command::Install(options) => (
            space::lifecycle::install(options),
            if options.print_graph.is_some() {
                Presentation::Data
            } else {
                Presentation::Success
            },
        ),
        Command::Reset => (space::lifecycle::reset(), Presentation::Success),
        Command::Start(options) => (space::lifecycle::start(options), Presentation::Success),
        Command::Status => (space::lifecycle::status(), Presentation::Info),
        Command::Upgrade => (upgrade::run(), Presentation::Success),
    };
    match result {
        Ok(message) => {
            presentation.write(&message);
            ExitCode::SUCCESS
        }
        Err(message) => {
            output::error(&message);
            ExitCode::FAILURE
        }
    }
}

fn check(project: &std::path::Path) -> Result<String, String> {
    let package = source_package::build(project)?;
    python::Assistant::open(project)?.contract()?;
    if let Some(message) = source_package::exclusion_warning(&package) {
        output::warning(&message);
    }
    Ok(source_package::check_summary(&package))
}

#[derive(Clone, Copy)]
enum Presentation {
    Data,
    Info,
    Success,
}

impl Presentation {
    fn write(self, message: &str) {
        match self {
            Self::Data => output::data(message),
            Self::Info => output::info(message),
            Self::Success => output::success(message),
        }
    }
}
