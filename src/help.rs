//! Task-oriented command help.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Topic {
    Root,
    Assistant,
    AssistantNew,
    AssistantDevelop,
    AssistantCheck,
    AssistantRun,
    AssistantPublish,
    AssistantInstall,
    Auth,
    AuthLogin,
    AuthStatus,
    AuthLogout,
    Install,
    Reset,
    Start,
    Status,
    Stop,
    Update,
    Upgrade,
}

impl Topic {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 19] = [
        Self::Root,
        Self::Assistant,
        Self::AssistantNew,
        Self::AssistantDevelop,
        Self::AssistantCheck,
        Self::AssistantRun,
        Self::AssistantPublish,
        Self::AssistantInstall,
        Self::Auth,
        Self::AuthLogin,
        Self::AuthStatus,
        Self::AuthLogout,
        Self::Install,
        Self::Reset,
        Self::Start,
        Self::Status,
        Self::Stop,
        Self::Update,
        Self::Upgrade,
    ];

    pub(crate) const fn text(self) -> &'static str {
        match self {
            Self::Root => ROOT,
            Self::Assistant => ASSISTANT,
            Self::AssistantNew => ASSISTANT_NEW,
            Self::AssistantDevelop => ASSISTANT_DEVELOP,
            Self::AssistantCheck => ASSISTANT_CHECK,
            Self::AssistantRun => ASSISTANT_RUN,
            Self::AssistantPublish => ASSISTANT_PUBLISH,
            Self::AssistantInstall => ASSISTANT_INSTALL,
            Self::Auth => AUTH,
            Self::AuthLogin => AUTH_LOGIN,
            Self::AuthStatus => AUTH_STATUS,
            Self::AuthLogout => AUTH_LOGOUT,
            Self::Install => INSTALL,
            Self::Reset => RESET,
            Self::Start => START,
            Self::Status => STATUS,
            Self::Stop => STOP,
            Self::Update => UPDATE,
            Self::Upgrade => UPGRADE,
        }
    }
}

const ROOT: &str = "\
Shimpz CLI

Manage a Local Space and build independently published Assistants.

Usage:
  shimpz <command> [options]

Local Space:
  shimpz install                         Install or reconcile the complete Local Space.
  shimpz start                           Start it and reconcile its atomic release.
  shimpz update                          Apply a newer atomic release without resuming a stopped Space.
  shimpz stop                            Stop it without removing its data.
  shimpz status                          Show its health, Admin address, and release ordinal.
  shimpz reset                           Permanently remove its Shimpz-owned data.

Assistant development:
  shimpz assistant new <name> [--language python]
                                         Create a Python Assistant project.
  shimpz assistant develop <codex|claude> [path] [--yolo]
                                         Develop it with a supported coding agent.
  shimpz assistant check [--project <path>]
                                         Validate the project and its Actions.
  shimpz assistant run <action-id> [--input <json> | --input-file <path>] [--project <path>]
                                         Run one Action locally.
  shimpz assistant publish --visibility <private|public> [--project <path>]
                                         Publish an immutable Assistant release.
  shimpz assistant install <source-digest> [--team <team-id>]
                                         Install an exact release for a Team.

Creator account:
  shimpz auth [login|status|logout]       Manage Creator authentication.

CLI:
  shimpz upgrade                         Upgrade a standalone CLI.
  shimpz --version                       Show the CLI version.

Common workflows:
  Start using Shimpz locally:
    shimpz install
    Open the Admin address printed when the Space is ready.

  Create and validate an Assistant:
    shimpz assistant new hello-assistant
    cd hello-assistant
    shimpz assistant check

Run 'shimpz <command> --help' for details about a command.

Documentation:
  https://docs.shimpz.com/
";

const ASSISTANT: &str = "\
shimpz assistant

Build and publish independently distributed Assistants.

Usage:
  shimpz assistant <operation> [options]

Operations:
  new <name>                             Create a Python Assistant project.
  develop <codex|claude> [path] [--yolo]
                                         Develop it with a supported coding agent.
  check [--project <path>]               Validate the project and its Actions.
  run <action-id> [options]              Run one Action locally.
  publish --visibility <private|public> [--project <path>]
                                         Publish an immutable release.
  install <source-digest> [--team <team-id>]
                                         Install an exact release for a Team.

Run 'shimpz assistant <operation> --help' for operation details.
";

const ASSISTANT_NEW: &str = "\
shimpz assistant new

Create a Python Assistant project.

Usage:
  shimpz assistant new <name> [--language python]

Arguments:
  <name>                                 Lowercase project name.

Options:
  --language python                      Select Python. Python is the current default.
";

const ASSISTANT_DEVELOP: &str = "\
shimpz assistant develop

Develop an Assistant with a supported coding agent.

Usage:
  shimpz assistant develop <codex|claude> [path] [--yolo]

Arguments:
  <codex|claude>                         Coding agent to launch.
  [path]                                 Project directory. Defaults to the current directory.

Options:
  --yolo                                 Let the selected agent use its autonomous mode.
";

const ASSISTANT_CHECK: &str = "\
shimpz assistant check

Validate an Assistant project and its Actions.

Usage:
  shimpz assistant check [--project <path>]

Options:
  --project <path>                       Project directory. Defaults to the current directory.
";

const ASSISTANT_RUN: &str = "\
shimpz assistant run

Run one Assistant Action locally.

Usage:
  shimpz assistant run <action-id> [--input <json> | --input-file <path>] [--project <path>]

Arguments:
  <action-id>                            Action declared by the Assistant project.

Options:
  --input <json>                         Inline JSON input. Use '-' to read from stdin.
  --input-file <path>                    Read JSON input from a file.
  --project <path>                       Project directory. Defaults to the current directory.
";

const ASSISTANT_PUBLISH: &str = "\
shimpz assistant publish

Publish an immutable Assistant release.

Usage:
  shimpz assistant publish --visibility <private|public> [--project <path>]

Options:
  --visibility <private|public>          Set the publication visibility.
  --project <path>                       Project directory. Defaults to the current directory.
";

const ASSISTANT_INSTALL: &str = "\
shimpz assistant install

Install an exact published Assistant release for a Team.

Usage:
  shimpz assistant install <source-digest> [--team <team-id>]

Arguments:
  <source-digest>                        Exact sha256 source-package digest.

Options:
  --team <team-id>                       Target Team when it cannot be selected automatically.
";

const AUTH: &str = "\
shimpz auth

Manage Creator authentication.

Usage:
  shimpz auth [login|status|logout]

Actions:
  login                                  Sign in. This is the default action.
  status                                 Show the current authentication state.
  logout                                 Remove the local Creator session.

Running 'shimpz auth' without an action signs you in.
Run 'shimpz auth <action> --help' for action details.
";

const AUTH_LOGIN: &str = "\
shimpz auth login

Sign in to the Creator account used by CLI workflows.

Usage:
  shimpz auth login

The command reuses a valid session when available. Otherwise it opens browser authorization and stores the resulting CLI credentials locally.
";

const AUTH_STATUS: &str = "\
shimpz auth status

Show the current Creator authentication state.

Usage:
  shimpz auth status

The command validates or renews the local session and reports its Account and granted scopes.
";

const AUTH_LOGOUT: &str = "\
shimpz auth logout

End the current Creator CLI session.

Usage:
  shimpz auth logout

The command revokes the remote session and removes its local credentials.
";

const INSTALL: &str = "\
shimpz install

Install or reconcile the complete Local Space.

Usage:
  shimpz install

The command installs a missing Space or repairs the current installation against the atomic Local release.

Next:
  Open the Admin address printed when the Space is ready.
";

const RESET: &str = "\
shimpz reset

Permanently remove the Local Space data owned by Shimpz.

Usage:
  shimpz reset
  shimpz reset --hard

This operation is irreversible. It retains the shimpz command and lifecycle lock so you can install a fresh Space.
A Supervisor password is requested only after one has been created.

Use '--hard' only when the installed Space cannot authorize an ordinary reset. It bypasses Shimpz Supervisor authorization
and requires the exact answer 'Yes' on an interactive terminal. Docker and operating-system authorization are still
required. Creator credentials and pulled images are retained.

Next:
  Run 'shimpz install' to create a fresh Local Space.
";

const START: &str = "\
shimpz start

Start the Local Space and reconcile its atomic release.

Usage:
  shimpz start

Use this after 'shimpz stop' or whenever you want to apply the current stable Local release.

Next:
  Run 'shimpz status' to inspect the Space.
";

const STATUS: &str = "\
shimpz status

Show a concise health summary for the Local Space.

Usage:
  shimpz status

The summary reports whether the Space needs attention, its Admin address, component health, and release ordinal.
";

const STOP: &str = "\
shimpz stop

Stop the Local Space without removing its data.

Usage:
  shimpz stop

The command preserves the Space configuration, containers, networks, volumes, and protected storage.

Next:
  Run 'shimpz start' to resume the Space.
";

const UPDATE: &str = "\
shimpz update

Apply a newer atomic release to the Local Space.

Usage:
  shimpz update

The command does not repair the current release and never resumes a stopped Space.

Next:
  Run 'shimpz status' to inspect the Space.
";

const UPGRADE: &str = "\
shimpz upgrade

Upgrade a standalone Shimpz CLI.

Usage:
  shimpz upgrade

A Space-managed CLI is upgraded only through the atomic Local release. Run 'shimpz update' to check for one.
";
