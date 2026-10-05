//! Launch a coding agent with the current Shimpz Assistant guide.

use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use ureq::{Body, http::Response};

use crate::{args::DeveloperAgent, developers_client, output};

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
    let mut response = developers_client::agent(REQUEST_TIMEOUT)
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

    fn response(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Response<Body> {
        Response::builder()
            .status(status)
            .header("Content-Type", content_type)
            .body(Body::builder().data(body))
            .unwrap()
    }

    #[test]
    fn reads_only_a_bounded_markdown_guide() {
        let mut valid = response(200, "text/markdown; charset=utf-8", GUIDE);
        assert_eq!(read_guide(&mut valid).unwrap(), GUIDE);
        for mut refused in [
            response(200, "text/html", GUIDE),
            response(302, "text/markdown", GUIDE),
            response(404, "text/markdown", GUIDE),
            response(
                200,
                "text/markdown",
                format!(
                    "{GUIDE}{}",
                    "x".repeat(usize::try_from(MAX_GUIDE_BYTES).unwrap())
                ),
            ),
        ] {
            assert_eq!(read_guide(&mut refused).unwrap_err(), invalid_guide());
        }
    }

    /// A redirect is refused, never followed: the redirect target is never contacted. Only that is asserted about the
    /// exchange, because a blocking socket read with a timeout is not restarted after an interruption of the
    /// process (a stop and continue, for example), so its exact failure message is not deterministic.
    #[test]
    fn never_follows_a_redirect() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let location = format!("http://{}/assistant.md", target.local_addr().unwrap());
        let redirect = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = redirect.local_addr().unwrap();
        thread::spawn(move || {
            use std::io::{Read, Write};

            let (mut stream, _) = redirect.accept().unwrap();
            // Read the request head before answering, so closing never resets a request with unread bytes.
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => request.extend_from_slice(&chunk[..read]),
                }
            }
            let _ = write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Type: text/markdown\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
        });

        assert!(fetch_guide(&format!("http://{address}/assistant.md")).is_err());
        target.set_nonblocking(true).unwrap();
        assert_eq!(
            target.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
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
}
