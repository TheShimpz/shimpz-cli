//! Command-line tooling for Shimpz Assistants.

mod args;
mod auth;
mod credentials;
mod invoke;
mod new_assistant;
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
            print!("{}", args::HELP);
            ExitCode::SUCCESS
        }
        Ok(Action::Version) => {
            println!("shimpz {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Action::Run(command)) => run(&command),
        Err(message) => {
            eprintln!("shimpz: {message}\n\n{}", args::USAGE);
            ExitCode::from(2)
        }
    }
}

fn run(command: &Command) -> ExitCode {
    let result = match command {
        Command::Auth(AuthAction::Login) => auth::login(),
        Command::Auth(AuthAction::Status) => auth::status(),
        Command::Auth(AuthAction::Logout) => auth::logout(),
        Command::NewAssistant { name } => new_assistant::run(name),
        Command::Check { project } => source_package::build(project)
            .and_then(|package| {
                python::Assistant::open(project)
                    .and_then(|assistant| assistant.contract())
                    .map(|_| package)
            })
            .map(source_package::check_summary),
        Command::Test {
            project,
            power,
            input,
        } => invoke::run(project, power, input),
        Command::Upgrade => upgrade::run(),
    };
    match result {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("shimpz: {message}");
            ExitCode::FAILURE
        }
    }
}
