//! Command-line tooling for Shimpz Assistants.

mod args;
mod invoke;
mod python;
mod toolchain;

use std::env;
use std::process::ExitCode;

use args::{Action, Command};

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
        Command::Check { project } => python::Assistant::open(project)
            .and_then(|assistant| assistant.contract())
            .map(|_| "Assistant is valid.".to_owned()),
        Command::Test {
            project,
            power,
            input,
        } => invoke::run(project, power, input),
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
