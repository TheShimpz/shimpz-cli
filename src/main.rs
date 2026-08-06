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
mod toolchain;
mod upgrade;
mod ustar;

#[cfg(test)]
mod source_package_tests;

use std::env;
use std::process::ExitCode;

use args::{Action, AuthAction, Command};

fn main() -> ExitCode {
    match args::parse(env::args_os().skip(1)) {
        Ok(Action::Help) => {
            output::plain(args::HELP.trim_end());
            ExitCode::SUCCESS
        }
        Ok(Action::Version) => {
            output::plain(&format!("shimpz {}", env!("CARGO_PKG_VERSION")));
            ExitCode::SUCCESS
        }
        Ok(Action::Run(command)) => run(&command),
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
        Command::NewAssistant { name } => (new_assistant::run(name), Presentation::Success),
        Command::Develop {
            agent,
            project,
            yolo,
        } => (develop::run(*agent, project, *yolo), Presentation::Success),
        Command::Check { project } => (check(project), Presentation::Success),
        Command::Test {
            project,
            power,
            input,
        } => (invoke::run(project, power, input), Presentation::Data),
        Command::Publish {
            project,
            visibility,
        } => (publish::run(project, *visibility), Presentation::Success),
        Command::InstallAssistant {
            source_digest,
            team,
        } => (
            install::run(source_digest, team.as_deref()),
            Presentation::Success,
        ),
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
