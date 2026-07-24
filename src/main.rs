//! Command-line tooling for Shimpz Assistants.

mod args;

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
        Ok(Action::Run(command)) => unavailable(&command),
        Err(message) => {
            eprintln!("shimpz: {message}\n\n{}", args::USAGE);
            ExitCode::from(2)
        }
    }
}

fn unavailable(command: &Command) -> ExitCode {
    let _ = command;
    eprintln!("shimpz: command is not available in this build");
    ExitCode::from(2)
}
