//! Launch a coding agent with the current Shimpz Assistant guide.

use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use ureq::{Agent, Body, http::Response};

use crate::{args::DeveloperAgent, output};

const GUIDE_URL: &str = "https://developers.shimpz.com/assistant.md";
const GUIDE_MARKER: &str = "<!-- shimpz-assistant-guide:v1 -->";
const GUIDE_TITLE: &str = "# Shimpz Assistant development expert";
const MAX_GUIDE_BYTES: u64 = 64 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn run(agent: DeveloperAgent, project: &Path, yolo: bool) -> Result<String, String> {
    let project = project_directory(project)?;
    output::progress("Loading the current Shimpz Assistant guide...");
    let guide = fetch_guide(GUIDE_URL)?;
    output::detail("Guide", GUIDE_URL);
    output::detail("Project", &project.to_string_lossy());
    if yolo {
        output::warning("YOLO mode lets the coding agent run commands with your OS user's access.");
    }
    output::progress(&format!("Starting {}...", agent.name()));
    launch(agent, &project, yolo, &guide)?;
    Ok(format!("{} session closed.", agent.name()))
}

fn project_directory(project: &Path) -> Result<PathBuf, String> {
    let resolved = project
        .canonicalize()
        .map_err(|_| "development project does not exist".to_owned())?;
    if !resolved.is_dir() {
        return Err("development project must be a directory".into());
    }
    Ok(resolved)
}

fn fetch_guide(url: &str) -> Result<String, String> {
    let config = Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    let mut response = Agent::new_with_config(config)
        .get(url)
        .header("Accept", "text/markdown")
        .call()
        .map_err(|_| unavailable())?;
    read_guide(&mut response)
}

fn read_guide(response: &mut Response<Body>) -> Result<String, String> {
    if response.status().as_u16() != 200 || !is_markdown(response) {
        return Err(invalid_guide());
    }
    let guide = response
        .body_mut()
        .with_config()
        .limit(MAX_GUIDE_BYTES)
        .read_to_string()
        .map_err(|_| invalid_guide())?;
    validate_guide(&guide)?;
    Ok(guide)
}

fn is_markdown(response: &Response<Body>) -> bool {
    response
        .headers()
        .get("Content-Type")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("text/markdown"))
}

fn validate_guide(guide: &str) -> Result<(), String> {
    if !guide.starts_with(GUIDE_MARKER)
        || !guide.contains(GUIDE_TITLE)
        || guide
            .chars()
            .any(|character| character.is_control() && character != '\n' && character != '\t')
    {
        return Err(invalid_guide());
    }
    Ok(())
}

fn launch(agent: DeveloperAgent, project: &Path, yolo: bool, guide: &str) -> Result<(), String> {
    let mut command = agent_command(agent, project, yolo, guide);
    let status = command
        .status()
        .map_err(|error| launch_error(agent, error.kind()))?;
    if !status.success() {
        return Err(format!(
            "{} exited with status {}",
            agent.name(),
            status
                .code()
                .map_or_else(|| "terminated".to_owned(), |code| code.to_string())
        ));
    }
    Ok(())
}

fn agent_command(agent: DeveloperAgent, project: &Path, yolo: bool, guide: &str) -> Command {
    let mut command = Command::new(agent.executable());
    command.current_dir(project);
    if yolo {
        command.arg(agent.yolo_flag());
    }
    command.arg(guide);
    command
}

fn launch_error(agent: DeveloperAgent, kind: ErrorKind) -> String {
    if kind == ErrorKind::NotFound {
        return format!(
            "{} is not installed or is unavailable in PATH",
            agent.executable()
        );
    }
    format!("{} could not start", agent.name())
}

fn unavailable() -> String {
    "Assistant development guide is unavailable; try again shortly".into()
}

fn invalid_guide() -> String {
    "Developers returned an invalid Assistant development guide".into()
}

impl DeveloperAgent {
    const fn executable(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Claude => "Claude Code",
            Self::Codex => "Codex",
        }
    }

    const fn yolo_flag(self) -> &'static str {
        match self {
            Self::Claude => "--dangerously-skip-permissions",
            Self::Codex => "--dangerously-bypass-approvals-and-sandbox",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, net::TcpListener, thread};

    use super::*;

    const GUIDE: &str = "\
<!-- shimpz-assistant-guide:v1 -->

# Shimpz Assistant development expert

Follow the contract.
";

    #[test]
    fn accepts_only_the_versioned_plain_text_guide() {
        assert!(validate_guide(GUIDE).is_ok());
        assert!(validate_guide("# Shimpz Assistant development expert").is_err());
        assert!(
            validate_guide(
                "<!-- shimpz-assistant-guide:v1 -->\n# Shimpz Assistant development expert\u{1b}"
            )
            .is_err()
        );
    }

    #[test]
    fn downloads_a_bounded_markdown_guide_without_redirects() {
        let valid = serve("200 OK", "text/markdown; charset=utf-8", GUIDE);
        assert_eq!(fetch_guide(&valid).unwrap(), GUIDE);

        let html = serve("200 OK", "text/html", GUIDE);
        assert_eq!(fetch_guide(&html).unwrap_err(), invalid_guide());

        let redirected = serve("302 Found", "text/markdown", GUIDE);
        assert_eq!(fetch_guide(&redirected).unwrap_err(), invalid_guide());
    }

    #[test]
    fn resolves_only_existing_directories() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(
            project_directory(directory.path()).unwrap(),
            fs::canonicalize(directory.path()).unwrap()
        );
        let file = directory.path().join("assistant.txt");
        fs::write(&file, "not a directory").unwrap();
        assert_eq!(
            project_directory(&file).unwrap_err(),
            "development project must be a directory"
        );
    }

    #[test]
    fn maps_each_agent_to_its_official_yolo_flag() {
        assert_eq!(
            DeveloperAgent::Codex.yolo_flag(),
            "--dangerously-bypass-approvals-and-sandbox"
        );
        assert_eq!(
            DeveloperAgent::Claude.yolo_flag(),
            "--dangerously-skip-permissions"
        );
    }

    #[test]
    fn injects_the_guide_without_enabling_yolo_by_default() {
        let directory = tempfile::tempdir().unwrap();
        let safe = agent_command(DeveloperAgent::Codex, directory.path(), false, GUIDE);
        assert_eq!(safe.get_program(), "codex");
        assert_eq!(
            safe.get_args().collect::<Vec<_>>(),
            [std::ffi::OsStr::new(GUIDE)]
        );
        assert_eq!(safe.get_current_dir(), Some(directory.path()));

        let yolo = agent_command(DeveloperAgent::Claude, directory.path(), true, GUIDE);
        assert_eq!(yolo.get_program(), "claude");
        assert_eq!(
            yolo.get_args().collect::<Vec<_>>(),
            [
                std::ffi::OsStr::new("--dangerously-skip-permissions"),
                std::ffi::OsStr::new(GUIDE),
            ]
        );
    }

    fn serve(status: &'static str, content_type: &'static str, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            use std::io::{Read, Write};

            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        format!("http://{address}")
    }
}
