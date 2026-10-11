//! Proof that every running long-running Local member is attached exactly as the emitted graph declares.
//!
//! A start is never trusted on its own. When Docker 29 fails to start a container because its published host port is
//! taken, it detaches the container from its non-internal network, and a later `docker start` or `docker compose up`
//! runs it without that network or its published port while reporting success. So after every start the running
//! members are judged against the graph, and a member Docker left detached is recreated from it.

use std::collections::{BTreeMap, BTreeSet};

use super::docker::{COMPOSE_UP, Engine};
use super::graph::{self, ACCOUNT_EGRESS_INIT, Member};
use super::paths::Paths;
use super::resources;
use crate::output;

const PROJECT_FILTER: &str = "label=com.docker.compose.project=shimpz-space";
const RECORD_FORMAT: &str = "{{.Name}}|{{index .Config.Labels \"com.docker.compose.service\"}}|{{.State.Running}}|{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}|{{json .NetworkSettings.Ports}}";
const RECORD_LABEL: &str = "Local network attachment";
const MAX_RECORD_BYTES: usize = 4_096;

/// One long-running member as Docker reports it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Judged {
    member: &'static Member,
    running: bool,
    attached: bool,
}

/// After a start, recreate from the graph every running member Docker left detached, and prove each recreated member
/// runs attached exactly as declared, with Admin published on `port`. Any other running member found detached by the
/// final observation also fails the start.
pub(crate) fn converge(engine: &Engine, paths: &Paths, port: u16) -> Result<(), String> {
    let detached = detached(&observe(
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
    // The ordinary start of the graph, without orphan removal, recreating exactly the detached members.
    let mut arguments = COMPOSE_UP
        .iter()
        .copied()
        .filter(|argument| *argument != "--remove-orphans")
        .collect::<Vec<_>>();
    arguments.extend(["--force-recreate", "--no-deps"]);
    arguments.extend(detached.iter().map(|member| member.service));
    if !engine.compose(paths, arguments)?.success() {
        return Err(failure());
    }
    let observed = observe(engine, &running_project_containers(engine)?, port)?;
    let recreated = detached.iter().all(|member| {
        observed
            .get(member.service)
            .is_some_and(|judged| judged.running && judged.attached)
    });
    if recreated && self::detached(&observed).is_empty() {
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
    Ok(detached(&observe(engine, containers, port)?)
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

fn observe(
    engine: &Engine,
    containers: &[String],
    port: u16,
) -> Result<BTreeMap<&'static str, Judged>, String> {
    judge_all(
        &resources::inspect_containers(engine, containers, RECORD_FORMAT, RECORD_LABEL)?,
        port,
    )
}

fn detached(observed: &BTreeMap<&'static str, Judged>) -> Vec<&'static Member> {
    observed
        .values()
        .filter(|judged| judged.running && !judged.attached)
        .map(|judged| judged.member)
        .collect()
}

/// Judge every record; each member may answer at most once and the one-shot initializer is not judged.
fn judge_all(records: &[String], port: u16) -> Result<BTreeMap<&'static str, Judged>, String> {
    let mut observed = BTreeMap::new();
    for record in records {
        let Some(judged) = judge(record, port)? else {
            continue;
        };
        if observed.insert(judged.member.service, judged).is_some() {
            return Err(format!(
                "Docker returned two {RECORD_LABEL} records for one Local service"
            ));
        }
    }
    Ok(observed)
}

fn judge(record: &str, port: u16) -> Result<Option<Judged>, String> {
    let malformed = || format!("Docker returned a malformed {RECORD_LABEL} record");
    if record.len() > MAX_RECORD_BYTES || record.contains(['\n', '\r']) {
        return Err(malformed());
    }
    let fields: Vec<_> = record.splitn(5, '|').collect();
    let [name, service, running, networks, ports] = fields[..] else {
        return Err(malformed());
    };
    let name = name.strip_prefix('/').ok_or_else(malformed)?;
    if service == ACCOUNT_EGRESS_INIT && name == ACCOUNT_EGRESS_INIT {
        return Ok(None);
    }
    let member = graph::MEMBERS
        .iter()
        .find(|member| member.service == service && member.container == name)
        .ok_or_else(|| "an unknown container runs in the Local Compose project".to_owned())?;
    let running = match running {
        "true" => true,
        "false" => false,
        _ => return Err(malformed()),
    };
    let networks: BTreeSet<String> = networks.split_whitespace().map(str::to_owned).collect();
    let declared: BTreeSet<String> = member
        .networks
        .iter()
        .map(|key| graph::resource_name(key))
        .collect();
    let bindings = bindings(ports).ok_or_else(malformed)?;
    let published: BTreeSet<_> = member
        .publishes_admin
        .then(|| {
            (
                graph::ADMIN_PUBLISHED_PORT.to_owned(),
                graph::ADMIN_PUBLISHED_HOST.to_owned(),
                port.to_string(),
            )
        })
        .into_iter()
        .collect();
    Ok(Some(Judged {
        member,
        running,
        attached: networks == declared && (!running || bindings == published),
    }))
}

/// The live host bindings of `{{json .NetworkSettings.Ports}}`: an exposed port without a binding binds nothing.
fn bindings(document: &str) -> Option<BTreeSet<(String, String, String)>> {
    let mut bindings = BTreeSet::new();
    let ports = match serde_json::from_str::<serde_json::Value>(document).ok()? {
        serde_json::Value::Null => return Some(bindings),
        serde_json::Value::Object(ports) => ports,
        _ => return None,
    };
    for (port, value) in ports {
        let entries = match value {
            serde_json::Value::Null => continue,
            serde_json::Value::Array(entries) => entries,
            _ => return None,
        };
        for entry in entries {
            let entry = entry.as_object()?;
            let host = entry.get("HostIp")?.as_str()?;
            let host_port = entry.get("HostPort")?.as_str()?;
            bindings.insert((port.clone(), host.to_owned(), host_port.to_owned()));
        }
    }
    Some(bindings)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    const ADMIN_PORTS: &str = r#"{"4600/tcp":[{"HostIp":"127.0.0.1","HostPort":"7777"}]}"#;

    fn record(member: &Member, running: bool, networks: &str, ports: &str) -> String {
        format!(
            "/{}|{}|{running}|{networks}|{ports}",
            member.container, member.service
        )
    }

    fn declared_networks(member: &Member) -> String {
        member
            .networks
            .iter()
            .map(|key| graph::resource_name(key) + " ")
            .collect()
    }

    fn healthy(member: &Member) -> String {
        let ports = if member.publishes_admin {
            ADMIN_PORTS
        } else {
            "{}"
        };
        record(member, true, &declared_networks(member), ports)
    }

    fn admin() -> &'static Member {
        &graph::MEMBERS[6]
    }

    #[test]
    fn every_member_attached_exactly_as_declared_is_judged_attached() {
        let records: Vec<_> = graph::MEMBERS.iter().map(healthy).collect();
        let observed = judge_all(&records, 7777).unwrap();
        assert_eq!(observed.len(), graph::MEMBERS.len());
        assert_eq!(detached(&observed), Vec::<&Member>::new());
        // Docker answers exposed but unbound ports with a null binding, which binds nothing.
        let team = &graph::MEMBERS[0];
        let exposed = record(team, true, &declared_networks(team), r#"{"7077/tcp":null}"#);
        assert!(judge(&exposed, 7777).unwrap().unwrap().attached);
        assert!(
            judge(&record(team, true, &declared_networks(team), "null"), 7777)
                .unwrap()
                .unwrap()
                .attached
        );
    }

    #[test]
    fn the_docker_29_failed_start_detachment_is_judged_detached() {
        // After a start failed on a taken port, Docker 29 keeps only the internal network and binds nothing.
        let degraded = record(
            admin(),
            true,
            "shimpz-space-control ",
            r#"{"4600/tcp":null}"#,
        );
        let observed = judge_all(&[degraded], 7777).unwrap();
        assert_eq!(detached(&observed), vec![admin()]);
    }

    #[test]
    fn any_network_or_binding_other_than_the_declared_ones_is_detached() {
        let networks = declared_networks(admin());
        for (networks, ports) in [
            (
                networks.clone(),
                r#"{"4600/tcp":[{"HostIp":"0.0.0.0","HostPort":"7777"}]}"#,
            ),
            (
                networks.clone(),
                r#"{"4600/tcp":[{"HostIp":"127.0.0.1","HostPort":"7778"}]}"#,
            ),
            (
                networks.clone(),
                r#"{"4600/tcp":[{"HostIp":"127.0.0.1","HostPort":"7777"},{"HostIp":"::1","HostPort":"7777"}]}"#,
            ),
            (networks.clone(), "{}"),
            (format!("{networks}bridge "), ADMIN_PORTS),
            ("shimpz-space-egress ".to_owned(), ADMIN_PORTS),
        ] {
            let judged = judge(&record(admin(), true, &networks, ports), 7777)
                .unwrap()
                .unwrap();
            assert!(!judged.attached, "{networks}|{ports}");
        }
        let egress = &graph::MEMBERS[1];
        let published = record(
            egress,
            true,
            &declared_networks(egress),
            r#"{"3128/tcp":[{"HostIp":"127.0.0.1","HostPort":"3128"}]}"#,
        );
        assert!(!judge(&published, 7777).unwrap().unwrap().attached);
    }

    #[test]
    fn a_stopped_member_is_judged_by_its_networks_and_never_reported_as_running_detached() {
        let stopped = record(admin(), false, &declared_networks(admin()), "{}");
        assert!(judge(&stopped, 7777).unwrap().unwrap().attached);
        let degraded = record(admin(), false, "shimpz-space-control ", "{}");
        let judged = judge(&degraded, 7777).unwrap().unwrap();
        assert!(!judged.attached && !judged.running);
        assert_eq!(
            detached(&judge_all(&[degraded], 7777).unwrap()),
            Vec::<&Member>::new()
        );
    }

    #[test]
    fn the_one_shot_initializer_is_not_judged() {
        let init = format!("/{ACCOUNT_EGRESS_INIT}|{ACCOUNT_EGRESS_INIT}|false||{{}}");
        assert_eq!(judge(&init, 7777).unwrap(), None);
        assert!(judge_all(&[init], 7777).unwrap().is_empty());
    }

    #[test]
    fn unknown_duplicate_or_malformed_records_are_refused() {
        let admin_networks = declared_networks(admin());
        for record in [
            "/foreign|admin|true||{}".to_owned(),
            "/shimpz-admin|team|true||{}".to_owned(),
            format!("/{ACCOUNT_EGRESS_INIT}|admin|true||{{}}"),
        ] {
            assert_eq!(
                judge(&record, 7777).unwrap_err(),
                "an unknown container runs in the Local Compose project"
            );
        }
        for record in [
            "shimpz-admin|admin|true||{}".to_owned(),
            "/shimpz-admin|admin|true|".to_owned(),
            format!("/shimpz-admin|admin|yes|{admin_networks}|{ADMIN_PORTS}"),
            format!("/shimpz-admin|admin|true|{admin_networks}|[]"),
            format!("/shimpz-admin|admin|true|{admin_networks}|not json"),
            format!(r#"/shimpz-admin|admin|true|{admin_networks}|{{"4600/tcp":{{}}}}"#),
            format!(r#"/shimpz-admin|admin|true|{admin_networks}|{{"4600/tcp":[1]}}"#),
            format!(
                r#"/shimpz-admin|admin|true|{admin_networks}|{{"4600/tcp":[{{"HostIp":"127.0.0.1"}}]}}"#
            ),
            format!(
                r#"/shimpz-admin|admin|true|{admin_networks}|{{"4600/tcp":[{{"HostIp":1,"HostPort":"1"}}]}}"#
            ),
            format!("{}\n", healthy(admin())),
            format!("{}{}", healthy(admin()), " ".repeat(MAX_RECORD_BYTES)),
        ] {
            assert_eq!(
                judge(&record, 7777).unwrap_err(),
                "Docker returned a malformed Local network attachment record",
                "{record}"
            );
        }
        assert_eq!(
            judge_all(&[healthy(admin()), healthy(admin())], 7777).unwrap_err(),
            "Docker returned two Local network attachment records for one Local service"
        );
    }

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

    fn degraded_admin() -> String {
        record(
            admin(),
            true,
            "shimpz-space-control ",
            r#"{"4600/tcp":null}"#,
        )
    }

    #[cfg(unix)]
    #[test]
    fn an_attached_space_converges_without_recreating_anything() {
        let (temporary, engine, paths) = fake_docker(&healthy(admin()), "", 0);
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
        let (temporary, engine, paths) = fake_docker(&degraded_admin(), &healthy(admin()), 0);
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
        let stopped = record(admin(), false, &declared_networks(admin()), "{}");
        for (after, compose) in [
            (healthy(admin()), 1),
            (degraded_admin(), 0),
            (stopped, 0),
            (
                format!("/{ACCOUNT_EGRESS_INIT}|{ACCOUNT_EGRESS_INIT}|false||{{}}"),
                0,
            ),
        ] {
            let (_temporary, engine, paths) = fake_docker(&degraded_admin(), &after, compose);
            assert_eq!(
                converge(&engine, &paths, 7777).unwrap_err(),
                failure,
                "{after}"
            );
        }
        let (_temporary, engine, paths) = fake_docker(&degraded_admin(), "", 0);
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
            judge(&record, port).unwrap().unwrap()
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
