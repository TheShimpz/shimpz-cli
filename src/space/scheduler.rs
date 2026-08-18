//! Exact user scheduler for automatic Local release reconciliation.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use super::command::{self, Tool};
use super::paths::Paths;
use super::storage::evidence::HostProfile;

const MARKER: &str = "shimpz-local-update-v2";

pub(crate) fn install(profile: HostProfile, paths: &Paths) -> Result<(), String> {
    match profile {
        HostProfile::Linux | HostProfile::Wsl => install_systemd(paths),
        HostProfile::MacOs => install_launch_agent(paths),
    }
}

pub(crate) fn validate(profile: HostProfile, paths: &Paths) -> Result<(), String> {
    match profile {
        HostProfile::Linux | HostProfile::Wsl => {
            validate_optional(&paths.systemd_service, &systemd_service(paths)?)?;
            validate_optional(&paths.systemd_timer, systemd_timer())
        }
        HostProfile::MacOs => validate_optional(&paths.launch_agent, &launch_agent(paths)?),
    }
}

pub(crate) fn remove(profile: HostProfile, paths: &Paths) -> Result<(), String> {
    validate(profile, paths)?;
    match profile {
        HostProfile::Linux | HostProfile::Wsl => {
            let present = paths.systemd_timer.exists() || paths.systemd_service.exists();
            if present {
                let _ = command::status(
                    Tool::Systemctl,
                    ["--user", "disable", "--now", "shimpz-update.timer"],
                );
            }
            remove_optional(&paths.systemd_timer)?;
            remove_optional(&paths.systemd_service)?;
            if present && Tool::Systemctl.resolve().is_ok() {
                let result = command::status(Tool::Systemctl, ["--user", "daemon-reload"])?;
                if !result.success() {
                    return Err("systemd did not reload after scheduler removal".into());
                }
            }
        }
        HostProfile::MacOs => {
            if paths.launch_agent.exists() {
                let _ = command::status(
                    Tool::Launchctl,
                    [
                        "bootout",
                        &format!("gui/{}", rustix::process::getuid().as_raw()),
                        &paths.launch_agent.to_string_lossy(),
                    ],
                );
            }
            remove_optional(&paths.launch_agent)?;
        }
    }
    Ok(())
}

fn install_systemd(paths: &Paths) -> Result<(), String> {
    let parent = paths
        .systemd_service
        .parent()
        .ok_or_else(|| "the systemd user directory is invalid".to_owned())?;
    fs::create_dir_all(parent).map_err(io_error)?;
    write_atomic(&paths.systemd_service, &systemd_service(paths)?)?;
    write_atomic(&paths.systemd_timer, systemd_timer())?;
    require_tool(
        Tool::Systemctl,
        ["--user", "daemon-reload"],
        "systemd did not reload",
    )?;
    require_tool(
        Tool::Systemctl,
        ["--user", "enable", "--now", "shimpz-update.timer"],
        "the automatic Local update timer could not be enabled",
    )
}

fn install_launch_agent(paths: &Paths) -> Result<(), String> {
    let parent = paths
        .launch_agent
        .parent()
        .ok_or_else(|| "the LaunchAgents directory is invalid".to_owned())?;
    fs::create_dir_all(parent).map_err(io_error)?;
    write_atomic(&paths.launch_agent, &launch_agent(paths)?)?;
    let domain = format!("gui/{}", rustix::process::getuid().as_raw());
    let _ = command::status(
        Tool::Launchctl,
        ["bootout", &domain, &paths.launch_agent.to_string_lossy()],
    );
    require_tool(
        Tool::Launchctl,
        ["bootstrap", &domain, &paths.launch_agent.to_string_lossy()],
        "the automatic Local update LaunchAgent could not be loaded",
    )
}

fn systemd_service(paths: &Paths) -> Result<String, String> {
    Ok(format!(
        "# {MARKER}\n[Unit]\nDescription=Reconcile Shimpz Local Space\nAfter=docker.service\n\n[Service]\nType=oneshot\nExecStart={} start --scheduled\n",
        systemd_quote(&paths.managed_cli)?
    ))
}

fn systemd_timer() -> &'static str {
    "# shimpz-local-update-v2\n[Unit]\nDescription=Periodically reconcile Shimpz Local Space\n\n[Timer]\nOnBootSec=5m\nOnUnitActiveSec=30m\nRandomizedDelaySec=10m\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
}

fn launch_agent(paths: &Paths) -> Result<String, String> {
    let cli = xml_escape(
        paths
            .managed_cli
            .to_str()
            .ok_or_else(|| "the managed CLI path is not UTF-8".to_owned())?,
    );
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- {MARKER} -->\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>com.shimpz.update</string>\n<key>ProgramArguments</key><array><string>{cli}</string><string>start</string><string>--scheduled</string></array>\n<key>RunAtLoad</key><true/>\n<key>StartInterval</key><integer>1800</integer>\n<key>ProcessType</key><string>Background</string>\n</dict></plist>\n"
    ))
}

fn systemd_quote(path: &Path) -> Result<String, String> {
    let value = path
        .to_str()
        .ok_or_else(|| "the managed CLI path is not UTF-8".to_owned())?;
    if value.chars().any(char::is_control) {
        return Err("the managed CLI path contains control characters".into());
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn validate_optional(path: &Path, expected: &str) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = path.symlink_metadata().map_err(io_error)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || fs::read_to_string(path).map_err(io_error)? != expected
    {
        return Err(format!(
            "refusing to manage an unowned scheduler file: {}",
            path.display()
        ));
    }
    Ok(())
}

fn write_atomic(path: &Path, value: &str) -> Result<(), String> {
    let temporary = path.with_extension("tmp");
    if temporary.exists() {
        fs::remove_file(&temporary).map_err(io_error)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(io_error)?;
    file.write_all(value.as_bytes()).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    fs::rename(temporary, path).map_err(io_error)
}

fn remove_optional(path: &Path) -> Result<(), String> {
    if path.exists() {
        fs::remove_file(path).map_err(io_error)?;
    }
    Ok(())
}

fn require_tool<const N: usize>(
    tool: Tool,
    arguments: [&str; N],
    message: &str,
) -> Result<(), String> {
    if command::status(tool, arguments)?.success() {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn io_error(error: std::io::Error) -> String {
    let message = format!("scheduler operation failed: {error}");
    drop(error);
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_exact_non_shell_schedulers() {
        let paths = Paths::under(Path::new("/home/Ada Space")).unwrap();
        let service = systemd_service(&paths).unwrap();
        assert!(
            service.contains("ExecStart=\"/home/Ada Space/.shimpz/bin/shimpz\" start --scheduled")
        );
        assert!(!service.contains("sh -c"));
        let plist = launch_agent(&paths).unwrap();
        assert!(plist.contains("<string>/home/Ada Space/.shimpz/bin/shimpz</string>"));
        assert!(plist.contains("<string>--scheduled</string>"));
    }
}
