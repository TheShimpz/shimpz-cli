//! The Team Browser's runtime: one unmodified easi.run installation under `~/.shimpz/easi.run` (ADR-0126).
//!
//! easi.run's own installer runs it, pinned by release and by the installer's digest, once the Space is ready, so a slow
//! or failed installation only leaves the Browser unavailable. Shimpz adds only the configuration easi.run documents:
//! its `.env`, and a `compose.override.yaml` that puts the admin on the internal network Team also joins. That network
//! belongs to the CLI, outside both Compose graphs, so neither ever removes it from under the other. An installation
//! this Space did not make is never touched.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::digest;
use crate::http;
use crate::output;
use crate::private_file::private_open;

use super::docker::Engine;
use super::graph;
use super::paths::Paths;

/// The release of easi.run this CLI installs.
const RELEASE: &str = "6ad3dcb295cfb0731f82c7e6243b18eef105e58a";
/// The installer of that release, in the commit of the public repository that names it.
const INSTALLER_URL: &str = "https://raw.githubusercontent.com/julianosig/easi.run/6b475dd319c4ae6770a6b336afa6e94d193955bf/install.sh";
const INSTALLER_SHA256: &str = "f2d3034afa37f3ad494def7e08ecb25f428e04af974d73d5fa5af9f8924748d7";
const REPOSITORY: &str = "https://github.com/julianosig/easi.run";
/// The admin's container, and the working directory Compose labels it with.
const ADMIN_CONTAINER: &str = "easi-run-admin-1";
const WORKING_DIRECTORY_LABEL: &str = "com.docker.compose.project.working_dir";
const LOOPBACK_PORT: u16 = 39443;
/// How long easi.run's installer may run: it pulls every image and adds Chrome.
const INSTALL_BUDGET: Duration = Duration::from_mins(30);
const POLL: Duration = Duration::from_millis(500);
const DOWNLOAD_BUDGET: Duration = Duration::from_mins(1);
const NETWORK_SHAPE: &str = "{{.Driver}}|{{.Internal}}|{{.EnableIPv6}}|{{index .Options \"com.docker.network.bridge.gateway_mode_ipv4\"}}";

/// easi.run's settings for a Space's Browser: no local MCP, no direct media path, one session, its own loopback port.
fn environment() -> String {
    format!(
        "ADMIN_PORT={LOOPBACK_PORT}\nADMIN_LOCAL_MCP=0\nADMIN_MAX_SESSIONS=1\nADMIN_UDP_URL=\nADMIN_UDP_BIND=127.0.0.1\n"
    )
}

/// The admin on the Browser network too, under the name Team reaches it by.
fn compose_override() -> String {
    let network = graph::resource_name("browser");
    format!(
        "services:\n  admin:\n    networks:\n      admin: {{}}\n      shimpz:\n        aliases: [easi-run-admin]\nnetworks:\n  shimpz:\n    external: true\n    name: {network}\n"
    )
}

/// Creates the internal network Team and easi.run's admin share. One already there must be exactly that: anything with a
/// route out would give Team one.
pub(crate) fn ensure_network(engine: &Engine) -> Result<(), String> {
    let network = graph::resource_name("browser");
    if engine
        .run_quiet_status(
            "Docker network inspection",
            ["network", "inspect", network.as_str()],
        )?
        .success()
    {
        let shape = engine.run_output([
            "network",
            "inspect",
            "--format",
            NETWORK_SHAPE,
            network.as_str(),
        ])?;
        return if shape.trim() == "bridge|true|false|isolated" {
            Ok(())
        } else {
            Err(format!(
                "the network {network} has another shape; remove it, then run shimpz again"
            ))
        };
    }
    engine.run_output([
        "network",
        "create",
        "--driver",
        "bridge",
        "--internal",
        "--opt",
        "com.docker.network.bridge.gateway_mode_ipv4=isolated",
        network.as_str(),
    ])?;
    Ok(())
}

/// Whether this host can run easi.run at all.
const fn supported() -> bool {
    cfg!(all(target_os = "linux", target_arch = "x86_64"))
}

fn directory(paths: &Paths) -> PathBuf {
    paths.home.join("easi.run")
}

fn installed_marker(paths: &Paths) -> PathBuf {
    paths.home.join("easi.run.release")
}

/// The working directory of the admin container on this host, if there is one.
fn admin_owner(engine: &Engine) -> Result<Option<String>, String> {
    if !engine
        .run_quiet_status(
            "Docker container inspection",
            ["container", "inspect", ADMIN_CONTAINER],
        )?
        .success()
    {
        return Ok(None);
    }
    let format = format!("{{{{index .Config.Labels \"{WORKING_DIRECTORY_LABEL}\"}}}}");
    engine
        .run_output(["container", "inspect", "--format", &format, ADMIN_CONTAINER])
        .map(|owner| Some(owner.trim().to_owned()))
}

/// Brings the installation to this CLI's release; the Space works whatever happens, and the person hears why not.
pub(crate) fn ensure(engine: &Engine, paths: &Paths) {
    if !supported() {
        return;
    }
    match install(engine, paths) {
        Ok(()) => {}
        Err(cause) => output::progress(&format!(
            "The Browser is unavailable until easi.run installs: {cause}"
        )),
    }
}

fn install(engine: &Engine, paths: &Paths) -> Result<(), String> {
    let directory = directory(paths);
    let owner = admin_owner(engine)?;
    if owner
        .as_deref()
        .is_some_and(|owner| Path::new(owner) != directory)
    {
        return Err("another easi.run installation runs on this host".into());
    }
    let marker = installed_marker(paths);
    let current = std::fs::read_to_string(&marker).is_ok_and(|release| release == RELEASE);
    if current && owner.is_some() {
        return Ok(());
    }
    output::progress(
        "Installing the Browser (easi.run); this takes a few minutes the first time...",
    );
    let installer = download_installer()?;
    let update = directory.join(".git").exists();
    if !update {
        prepare_checkout(&directory)?;
    }
    write_configuration(&directory)?;
    run_installer(paths, &installer, &directory, update.then_some("--update"))?;
    keep(&marker, RELEASE.as_bytes())
        .map_err(|error| format!("the installed release could not be recorded: {error}"))
}

/// The installer's exact bytes, in a private file.
fn download_installer() -> Result<PathBuf, String> {
    let body = http::agent(DOWNLOAD_BUDGET)
        .get(INSTALLER_URL)
        .call()
        .map_err(|error| format!("the installer could not be downloaded: {error}"))?
        .into_body()
        .read_to_vec()
        .map_err(|error| format!("the installer could not be read: {error}"))?;
    if digest::sha256_hex(&body) != INSTALLER_SHA256 {
        return Err("the downloaded installer is not the pinned one".into());
    }
    let path = std::env::temp_dir().join(format!("shimpz-easi-install-{}.sh", std::process::id()));
    keep(&path, &body).map_err(|error| format!("the installer could not be kept: {error}"))?;
    Ok(path)
}

/// Writes a private file.
fn keep(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    private_open(&mut options);
    options.open(path)?.write_all(content)
}

fn git(arguments: &[&str]) -> Result<(), String> {
    let status = Command::new("git")
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("git could not run: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("the easi.run checkout could not be made".into())
    }
}

/// The pinned checkout, so its configuration is there before the installer first runs.
fn prepare_checkout(directory: &Path) -> Result<(), String> {
    let path = directory.display().to_string();
    git(&["clone", "--quiet", "--no-checkout", REPOSITORY, &path])?;
    git(&["-C", &path, "fetch", "--quiet", "origin", RELEASE])?;
    git(&[
        "-C",
        &path,
        "-c",
        "advice.detachedHead=false",
        "checkout",
        "--quiet",
        "--detach",
        RELEASE,
    ])
}

fn write_configuration(directory: &Path) -> Result<(), String> {
    for (name, content) in [
        (".env", environment()),
        ("compose.override.yaml", compose_override()),
    ] {
        std::fs::write(directory.join(name), content)
            .map_err(|error| format!("{name} could not be written: {error}"))?;
    }
    Ok(())
}

/// Runs the installer to its end within [`INSTALL_BUDGET`], its output kept beside the checkout.
fn run_installer(
    paths: &Paths,
    installer: &Path,
    directory: &Path,
    flag: Option<&str>,
) -> Result<(), String> {
    let log = std::fs::File::create(paths.home.join("easi.run.log"))
        .map_err(|error| format!("the installer's log could not be opened: {error}"))?;
    let errors = log
        .try_clone()
        .map_err(|error| format!("the installer's log could not be opened: {error}"))?;
    let mut command = Command::new("bash");
    command.arg(installer);
    if let Some(flag) = flag {
        command.arg(flag);
    }
    let mut child = command
        .env("EASI_RUN_DIR", directory)
        .env_remove("SSH_CONNECTION")
        .stdin(Stdio::null())
        .stdout(log)
        .stderr(errors)
        .spawn()
        .map_err(|error| format!("the installer could not start: {error}"))?;
    let until = Instant::now() + INSTALL_BUDGET;
    let finished = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() >= until => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(
                    "the installer did not finish in time; see ~/.shimpz/easi.run.log".to_owned(),
                );
            }
            Ok(None) => std::thread::sleep(POLL),
            Err(error) => break Err(format!("the installer could not be followed: {error}")),
        }
    };
    let _ = std::fs::remove_file(installer);
    if finished?.success() {
        Ok(())
    } else {
        Err("the installer failed; see ~/.shimpz/easi.run.log".into())
    }
}

/// Removes this Space's installation; an installation it did not make stays.
pub(crate) fn uninstall(engine: &Engine, paths: &Paths) -> Result<(), String> {
    let directory = directory(paths);
    if directory.join(".git").exists() {
        let owner = admin_owner(engine)?;
        if owner.is_none_or(|owner| Path::new(&owner) == directory) {
            let installer = directory.join("install.sh");
            let status = Command::new("bash")
                .arg(&installer)
                .args(["--uninstall", "--yes"])
                .env("EASI_RUN_DIR", &directory)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(|error| format!("easi.run's uninstaller could not start: {error}"))?;
            if !status.success() {
                return Err("easi.run's uninstaller failed".into());
            }
        }
        std::fs::remove_dir_all(&directory)
            .map_err(|error| format!("the easi.run checkout could not be removed: {error}"))?;
    }
    for path in [installed_marker(paths), paths.home.join("easi.run.log")] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("{} could not be removed: {error}", path.display())),
        }
    }
    Ok(())
}

/// Removes the shared network once nothing of the Space or of easi.run is on it.
pub(crate) fn remove_network(engine: &Engine) -> Result<(), String> {
    let network = graph::resource_name("browser");
    if engine
        .run_quiet_status(
            "Docker network inspection",
            ["network", "inspect", network.as_str()],
        )?
        .success()
    {
        engine.run_output(["network", "rm", network.as_str()])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{compose_override, environment};

    #[test]
    fn the_configuration_is_only_what_easi_run_documents() {
        let environment = environment();
        assert!(environment.contains("ADMIN_LOCAL_MCP=0\n"));
        assert!(environment.contains("ADMIN_UDP_URL=\n"));
        let overridden = compose_override();
        assert!(overridden.contains("external: true"));
        assert!(overridden.contains("name: shimpz-space-browser"));
        assert!(overridden.contains("aliases: [easi-run-admin]"));
    }
}
