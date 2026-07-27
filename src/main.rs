//! Command-line tooling for Shimpz Assistants.

mod args;
mod auth;
mod credentials;
mod install;
mod invoke;
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
        Command::Check { project } => (
            source_package::build(project)
                .and_then(|package| {
                    python::Assistant::open(project)
                        .and_then(|assistant| assistant.contract())
                        .map(|_| package)
                })
                .map(source_package::check_summary),
            Presentation::Success,
        ),
        Command::Test {
            project,
            power,
            input,
        } => (invoke::run(project, power, input), Presentation::Data),
        Command::Publish { project } => (publish::run(project), Presentation::Success),
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
