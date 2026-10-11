//! Proof that every running long-running Local member is attached exactly as the emitted graph declares.
//!
//! A start is never trusted on its own. When Docker 29 fails to start a container because its published host port is
//! taken, it detaches the container from its non-internal network, and a later `docker start` or `docker compose up`
//! runs it without that network or its published port while reporting success. So after every start the running
//! members are observed, judged by [`attachment`], and a member Docker left detached is recreated from the graph.

use super::attachment::{self, Observed, RECORD_FORMAT, RECORD_LABEL};
use super::docker::Engine;
use super::paths::Paths;
use super::resources;
use crate::output;

const PROJECT_FILTER: &str = "label=com.docker.compose.project=shimpz-space";

/// After a start, recreate from the graph every running member Docker left detached, and prove each recreated member
/// runs attached exactly as declared, with Admin published on `port`. Any other running member found detached by the
/// final observation also fails the start.
pub(crate) fn converge(engine: &Engine, paths: &Paths, port: u16) -> Result<(), String> {
    let detached = attachment::detached(&observe(
        engine,
        &running_project_containers(engine)?,
        port,
    )?);
    if detached.is_empty() {
        return Ok(());
    }
    output::progress(
        "Recreating Local containers Docker started without their declared network or published port...",
    );
    let containers = detached
        .iter()
        .map(|member| member.container)
        .collect::<Vec<_>>()
        .join(", ");
    let failure = || {
        format!(
            "Docker started {containers} without the declared network or published port, and recreating it from the Local graph failed"
        )
    };
    if !engine
        .compose(paths, attachment::recreate_arguments(&detached))?
        .success()
    {
        return Err(failure());
    }
    let observed = observe(engine, &running_project_containers(engine)?, port)?;
    if attachment::recreation_proved(&detached, &observed) {
        Ok(())
    } else {
        Err(failure())
    }
}

/// The services of the running members among `containers` that are not attached exactly as declared, read-only.
pub(crate) fn detached_services(
    engine: &Engine,
    containers: &[String],
    port: u16,
) -> Result<Vec<&'static str>, String> {
    Ok(attachment::detached(&observe(engine, containers, port)?)
        .into_iter()
        .map(|member| member.service)
        .collect())
}

fn running_project_containers(engine: &Engine) -> Result<Vec<String>, String> {
    Ok(engine
        .run_output([
            "ps",
            "--quiet",
            "--no-trunc",
            "--filter",
            PROJECT_FILTER,
            "--filter",
            "status=running",
        ])?
        .split_whitespace()
        .map(str::to_owned)
        .collect())
}

fn observe(engine: &Engine, containers: &[String], port: u16) -> Result<Observed, String> {
    attachment::judge_all(
        &resources::inspect_containers(engine, containers, RECORD_FORMAT, RECORD_LABEL)?,
        port,
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    const HEALTHY_ADMIN: &str = r#"/shimpz-admin|admin|true|shimpz-space-control shimpz-space-egress |{"4600/tcp":[{"HostIp":"127.0.0.1","HostPort":"7777"}]}"#;
    const DEGRADED_ADMIN: &str =
        r#"/shimpz-admin|admin|true|shimpz-space-control |{"4600/tcp":null}"#;
    const STOPPED_ADMIN: &str =
        "/shimpz-admin|admin|false|shimpz-space-control shimpz-space-egress |{}";

    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// A fake Docker whose running project holds one Admin container, answered by `before` until Compose recreates it,
    /// then by `after`; every call is logged.
    fn fake_docker(before: &str, after: &str, compose: u8) -> (tempfile::TempDir, Engine, Paths) {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let docker = root.join("docker");
        crate::fake_tool::write(
            &docker,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{root}/calls'\ncase \"$1\" in\n  ps) printf '{ID}\\n' ;;\n  inspect) if [ -e '{root}/recreated' ]; then printf '{ID}|%s\\n' '{after}'; else printf '{ID}|%s\\n' '{before}'; fi ;;\n  compose) : > '{root}/recreated'; exit {compose} ;;\n  *) exit 1 ;;\nesac\n",
                root = root.display()
            ),
        );
        let paths = Paths::under(root).unwrap();
        (temporary, Engine::with_docker(docker), paths)
    }

    fn calls(temporary: &tempfile::TempDir) -> String {
        fs::read_to_string(temporary.path().join("calls")).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn an_attached_space_converges_without_recreating_anything() {
        let (temporary, engine, paths) = fake_docker(HEALTHY_ADMIN, "", 0);
        converge(&engine, &paths, 7777).unwrap();
        let calls = calls(&temporary);
        assert!(calls.starts_with(
            "ps --quiet --no-trunc --filter label=com.docker.compose.project=shimpz-space --filter status=running\n"
        ));
        assert!(
            !calls.lines().any(|call| call.starts_with("compose ")),
            "{calls}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_detached_member_is_recreated_from_the_graph_and_proved_attached() {
        let (temporary, engine, paths) = fake_docker(DEGRADED_ADMIN, HEALTHY_ADMIN, 0);
        converge(&engine, &paths, 7777).unwrap();
        let up = calls(&temporary)
            .lines()
            .find(|line| line.starts_with("compose "))
            .unwrap()
            .to_owned();
        assert!(
            up.ends_with(
                " up -d --wait --wait-timeout 120 --no-build --pull never --force-recreate --no-deps admin"
            ),
            "{up}"
        );
        assert_eq!(
            detached_services(&engine, &[ID.to_owned()], 7777).unwrap(),
            Vec::<&str>::new()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_recreation_that_fails_or_leaves_a_member_detached_or_stopped_fails_the_start() {
        let failure = "Docker started shimpz-admin without the declared network or published port, and recreating it from the Local graph failed";
        for (after, compose) in [
            (HEALTHY_ADMIN.to_owned(), 1),
            (DEGRADED_ADMIN.to_owned(), 0),
            (STOPPED_ADMIN.to_owned(), 0),
            (
                "/shimpz-account-egress-init|shimpz-account-egress-init|false||{}".to_owned(),
                0,
            ),
        ] {
            let (_temporary, engine, paths) = fake_docker(DEGRADED_ADMIN, &after, compose);
            assert_eq!(
                converge(&engine, &paths, 7777).unwrap_err(),
                failure,
                "{after}"
            );
        }
        let (_temporary, engine, paths) = fake_docker(DEGRADED_ADMIN, "", 0);
        assert_eq!(
            detached_services(&engine, &[ID.to_owned()], 7777).unwrap(),
            vec!["admin"]
        );
        assert!(converge(&engine, &paths, 7777).is_err());
    }

    /// Opt-in: reproduce on this host's Docker, with a throwaway `shimpz-live-attachment` Compose project only, a start
    /// that failed on a taken port, and prove that Docker's own inspect answer of the member a later start ran is
    /// judged detached, and that its recreation from the graph is judged attached and answers on the published port.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs this host's Docker; creates and removes a throwaway shimpz-live-attachment project"]
    fn live_docker_start_after_a_failed_start_is_judged_detached_until_recreated() {
        use std::net::{TcpListener, TcpStream};
        use std::process::Command;

        let directory = tempfile::tempdir().unwrap();
        let held = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = held.local_addr().unwrap().port();
        fs::write(
            directory.path().join("compose.yaml"),
            format!(
                "name: shimpz-live-attachment\nservices:\n  admin:\n    container_name: live-attachment-admin\n    image: busybox:latest\n    command: [\"httpd\", \"-f\", \"-p\", \"4600\"]\n    ports:\n      - \"127.0.0.1:{port}:4600\"\n    networks: [control, egress]\nnetworks:\n  control:\n    name: live-attachment-control\n    internal: true\n  egress:\n    name: live-attachment-egress\n"
            ),
        )
        .unwrap();
        let compose = |arguments: &[&str]| {
            Command::new("docker")
                .arg("compose")
                .arg("--project-directory")
                .arg(directory.path())
                .args(arguments)
                .output()
                .unwrap()
                .status
                .success()
        };
        // Docker's answer, renamed onto the Local graph's names so the production judge reads it unchanged.
        let judged = || {
            let record = Command::new("docker")
                .args(["inspect", "--type=container", "--format", RECORD_FORMAT])
                .arg("live-attachment-admin")
                .output()
                .unwrap();
            let record = String::from_utf8(record.stdout)
                .unwrap()
                .trim_end()
                .replace("/live-attachment-admin|", "/shimpz-admin|")
                .replace("live-attachment-", "shimpz-space-");
            attachment::judge(&record, port).unwrap().unwrap()
        };
        let up = ["up", "-d", "--no-build", "--pull", "never"];
        assert!(!compose(&up), "a start on a taken port must fail");
        drop(held);
        let outcome = || {
            assert!(compose(&up));
            let started = judged();
            assert!(started.running);
            if started.attached {
                eprintln!(
                    "this Docker engine kept the member attached after its failed start; nothing to recreate"
                );
            } else {
                assert!(compose(&[
                    "up",
                    "-d",
                    "--no-build",
                    "--pull",
                    "never",
                    "--force-recreate",
                    "--no-deps",
                    "admin"
                ]));
                let recreated = judged();
                assert!(recreated.running && recreated.attached);
            }
            assert!(TcpStream::connect(("127.0.0.1", port)).is_ok());
        };
        let result = std::panic::catch_unwind(outcome);
        assert!(compose(&["down", "--remove-orphans"]));
        result.unwrap();
    }
}
