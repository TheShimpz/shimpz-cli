//! Pure judgment of whether a long-running Local member runs attached exactly as the emitted graph declares.
//!
//! Docker answers [`RECORD_FORMAT`] for each inspected project container. A member is attached when it joins exactly
//! its declared networks and, while running, publishes exactly its declared host bindings. A running member that is
//! not attached is recreated from the graph; a recreation is proved only when each recreated member then runs
//! attached and no running member remains detached.

use std::collections::{BTreeMap, BTreeSet};

use super::docker::COMPOSE_UP;
use super::graph::{self, ACCOUNT_EGRESS_INIT, Member};

pub(crate) const RECORD_FORMAT: &str = "{{.Name}}|{{index .Config.Labels \"com.docker.compose.service\"}}|{{.State.Running}}|{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}|{{json .NetworkSettings.Ports}}";
pub(crate) const RECORD_LABEL: &str = "Local network attachment";
const MAX_RECORD_BYTES: usize = 4_096;

/// The judged running and stopped long-running members, by service.
pub(crate) type Observed = BTreeMap<&'static str, Judged>;

/// One long-running member as Docker reports it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Judged {
    pub(crate) member: &'static Member,
    pub(crate) running: bool,
    pub(crate) attached: bool,
}

/// The Compose arguments that recreate exactly `detached` from the graph: the ordinary start, without orphan removal,
/// forced to recreate only those services.
pub(crate) fn recreate_arguments(detached: &[&'static Member]) -> Vec<&'static str> {
    let mut arguments: Vec<_> = COMPOSE_UP
        .iter()
        .copied()
        .filter(|argument| *argument != "--remove-orphans")
        .collect();
    arguments.extend(["--force-recreate", "--no-deps"]);
    arguments.extend(detached.iter().map(|member| member.service));
    arguments
}

/// Each recreated member runs attached, and no running member remains detached.
pub(crate) fn recreation_proved(recreated: &[&'static Member], observed: &Observed) -> bool {
    recreated.iter().all(|member| {
        observed
            .get(member.service)
            .is_some_and(|judged| judged.running && judged.attached)
    }) && detached(observed).is_empty()
}

/// The running members that are not attached exactly as declared.
pub(crate) fn detached(observed: &Observed) -> Vec<&'static Member> {
    observed
        .values()
        .filter(|judged| judged.running && !judged.attached)
        .map(|judged| judged.member)
        .collect()
}

/// Judge every record; each member may answer at most once and the one-shot initializer is not judged.
pub(crate) fn judge_all(records: &[String], port: u16) -> Result<Observed, String> {
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

pub(crate) fn judge(record: &str, port: u16) -> Result<Option<Judged>, String> {
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
        &graph::ADMIN
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

    #[test]
    fn recreation_recreates_exactly_the_detached_services_without_removing_orphans() {
        assert_eq!(
            recreate_arguments(&[admin(), &graph::MEMBERS[0]]),
            [
                "up",
                "-d",
                "--wait",
                "--wait-timeout",
                "120",
                "--no-build",
                "--pull",
                "never",
                "--force-recreate",
                "--no-deps",
                "admin",
                "team"
            ]
        );
    }

    #[test]
    fn a_recreation_is_proved_only_when_each_recreated_member_runs_attached_and_none_is_detached() {
        let degraded = record(
            admin(),
            true,
            "shimpz-space-control ",
            r#"{"4600/tcp":null}"#,
        );
        let stopped = record(admin(), false, &declared_networks(admin()), "{}");
        let team = &graph::MEMBERS[0];
        let detached_team = record(team, true, "shimpz-space-control ", "{}");
        for (records, proved) in [
            (vec![healthy(admin())], true),
            (vec![healthy(admin()), healthy(team)], true),
            (vec![], false),
            (vec![degraded], false),
            (vec![stopped], false),
            (vec![healthy(admin()), detached_team], false),
        ] {
            let observed = judge_all(&records, 7777).unwrap();
            assert_eq!(
                recreation_proved(&[admin()], &observed),
                proved,
                "{records:?}"
            );
        }
    }
}
