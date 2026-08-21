//! Concise, bounded Local Space status projection.

use super::state::Installed;

const SERVICE_COUNT: usize = 7;
const MAX_RECORD_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Expectation {
    Service,
    Init,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Component {
    docker_name: &'static str,
    service: &'static str,
    label: &'static str,
    expectation: Expectation,
}

pub(crate) const COMPONENTS: [Component; 8] = [
    Component {
        docker_name: "shimpz-admin",
        service: "admin",
        label: "Admin",
        expectation: Expectation::Service,
    },
    Component {
        docker_name: "shimpz-team",
        service: "team",
        label: "Team",
        expectation: Expectation::Service,
    },
    Component {
        docker_name: "shimpz-brain",
        service: "brain",
        label: "Brain",
        expectation: Expectation::Service,
    },
    Component {
        docker_name: "shimpz-brain-egress",
        service: "shimpz-brain-egress",
        label: "Brain network boundary",
        expectation: Expectation::Service,
    },
    Component {
        docker_name: "shimpz-assistant-egress",
        service: "shimpz-assistant-egress",
        label: "Assistant network boundary",
        expectation: Expectation::Service,
    },
    Component {
        docker_name: "shimpz-assistant-release",
        service: "shimpz-assistant-release",
        label: "Assistant release boundary",
        expectation: Expectation::Service,
    },
    Component {
        docker_name: "shimpz-account-egress",
        service: "shimpz-account-egress",
        label: "Account network boundary",
        expectation: Expectation::Service,
    },
    Component {
        docker_name: "shimpz-account-egress-init",
        service: "shimpz-account-egress-init",
        label: "Account setup",
        expectation: Expectation::Init,
    },
];

impl Component {
    pub(crate) const fn docker_name(self) -> &'static str {
        self.docker_name
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Health {
    Unavailable,
    Starting,
    Healthy,
    Unhealthy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Runtime {
    Missing,
    Created,
    Running(Health),
    Paused,
    Restarting,
    Removing,
    Exited(i32),
    Dead(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Observation {
    component: Component,
    runtime: Runtime,
}

impl Observation {
    pub(crate) const fn is_present(self) -> bool {
        !matches!(self.runtime, Runtime::Missing)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AssistantObservation {
    runtime: Runtime,
}

pub(crate) fn not_installed() -> &'static str {
    "Shimpz Space is not installed.\nNext: shimpz install"
}

pub(crate) fn operation_in_progress() -> &'static str {
    "A Shimpz Space lifecycle operation is in progress.\nNext: run shimpz status again shortly."
}

pub(crate) fn observe(component: Component, record: Option<&str>) -> Result<Observation, String> {
    let Some(record) = record else {
        return Ok(Observation {
            component,
            runtime: Runtime::Missing,
        });
    };
    let fields = record_fields(record, 4).ok_or_else(|| malformed(component))?;
    if fields[0] != component.service {
        return Err(malformed(component));
    }
    let health = parse_health(fields[2]).ok_or_else(|| malformed(component))?;
    let exit_code = parse_exit_code(fields[3]).ok_or_else(|| malformed(component))?;
    let runtime =
        parse_runtime(fields[1], health, exit_code).ok_or_else(|| malformed(component))?;
    Ok(Observation { component, runtime })
}

pub(crate) fn observe_assistant(record: &str) -> Result<AssistantObservation, String> {
    let fields = record_fields(record, 2)
        .ok_or_else(|| "Docker returned malformed Assistant status".to_owned())?;
    let exit_code = parse_exit_code(fields[1])
        .ok_or_else(|| "Docker returned malformed Assistant status".to_owned())?;
    let runtime = parse_runtime(fields[0], Health::Unavailable, exit_code)
        .ok_or_else(|| "Docker returned malformed Assistant status".to_owned())?;
    Ok(AssistantObservation { runtime })
}

fn record_fields(record: &str, expected: usize) -> Option<Vec<&str>> {
    if record.len() > MAX_RECORD_BYTES || record.contains('\r') {
        return None;
    }
    let mut lines = record.lines();
    let line = lines
        .next()
        .filter(|line| !line.is_empty() && lines.next().is_none())?;
    let fields: Vec<_> = line.split('|').collect();
    (fields.len() == expected).then_some(fields)
}

fn parse_health(value: &str) -> Option<Health> {
    Some(match value {
        "" => Health::Unavailable,
        "starting" => Health::Starting,
        "healthy" => Health::Healthy,
        "unhealthy" => Health::Unhealthy,
        _ => return None,
    })
}

fn parse_exit_code(value: &str) -> Option<i32> {
    value.parse::<i32>().ok().filter(|code| *code >= 0)
}

fn parse_runtime(value: &str, health: Health, exit_code: i32) -> Option<Runtime> {
    Some(match value {
        "created" => Runtime::Created,
        "running" => Runtime::Running(health),
        "paused" => Runtime::Paused,
        "restarting" => Runtime::Restarting,
        "removing" => Runtime::Removing,
        "exited" => Runtime::Exited(exit_code),
        "dead" => Runtime::Dead(exit_code),
        _ => return None,
    })
}

pub(crate) fn fully_stopped(
    observations: &[Observation],
    assistants: &[AssistantObservation],
) -> Result<bool, String> {
    validate_snapshot(observations)?;
    Ok(static_stopped(observations)
        && assistants
            .iter()
            .all(|assistant| matches!(assistant.runtime, Runtime::Exited(_))))
}

pub(crate) fn incomplete_stop_error(
    observations: &[Observation],
    assistants: &[AssistantObservation],
) -> Result<String, String> {
    validate_snapshot(observations)?;
    Ok(if stop_requires_reconciliation(observations, assistants) {
        "the Space stop is incomplete; run shimpz install to reconcile it, then run shimpz stop"
            .into()
    } else {
        "the Space stop is incomplete; re-run shimpz stop".into()
    })
}

pub(crate) fn render(
    installed: &Installed,
    graph_current: bool,
    stopped_requested: bool,
    observations: &[Observation],
    assistants: &[AssistantObservation],
) -> Result<String, String> {
    validate_snapshot(observations)?;
    let stopped_services = stopped_services(observations);
    let stopped_assistants = assistants
        .iter()
        .filter(|assistant| matches!(assistant.runtime, Runtime::Exited(_)))
        .count();
    if stopped_requested {
        if static_stopped(observations) && stopped_assistants == assistants.len() {
            let configuration = if graph_current {
                String::new()
            } else {
                "\nConfiguration: will reconcile on start".into()
            };
            return Ok(format!(
                "Shimpz Space is stopped.\nServices: {SERVICE_COUNT} stopped\n{}\nRelease: ordinal {}{configuration}\nNext: shimpz start",
                assistant_summary(stopped_assistants, assistants.len(), "stopped"),
                installed.ordinal,
            ));
        }
        let next = if stop_requires_reconciliation(observations, assistants) {
            "shimpz install, then shimpz stop"
        } else {
            "shimpz stop"
        };
        return Ok(format!(
            "Shimpz Space needs attention.\nServices: {stopped_services} of {SERVICE_COUNT} stopped\n{}\nRelease: ordinal {}\nProblem: the requested stop is incomplete.\nNext: {next}",
            assistant_summary(stopped_assistants, assistants.len(), "stopped"),
            installed.ordinal,
        ));
    }

    let mut healthy = 0;
    let mut problems = Vec::new();
    if !graph_current {
        problems.push("Local configuration needs reconciliation.".to_owned());
    }
    for observation in observations {
        match observation.component.expectation {
            Expectation::Service => match service_problem(*observation) {
                Some(problem) => problems.push(problem),
                None => healthy += 1,
            },
            Expectation::Init => {
                if let Some(problem) = init_problem(*observation) {
                    problems.push(problem);
                }
            }
        }
    }
    let running_assistants = assistants
        .iter()
        .filter(|assistant| matches!(assistant.runtime, Runtime::Running(_)))
        .count();
    if running_assistants != assistants.len() {
        problems.push(assistant_problem(running_assistants, assistants.len()));
    }
    let assistant_summary = assistant_summary(running_assistants, assistants.len(), "running");
    if problems.is_empty() {
        return Ok(format!(
            "Shimpz Space is healthy.\nAdmin: http://127.0.0.1:{}\nServices: {healthy} healthy\n{assistant_summary}\nRelease: ordinal {}",
            installed.port, installed.ordinal
        ));
    }
    let admin = if matches!(observations[0].runtime, Runtime::Running(Health::Healthy)) {
        format!("http://127.0.0.1:{}", installed.port)
    } else {
        "unavailable".into()
    };
    Ok(format!(
        "Shimpz Space needs attention.\nAdmin: {admin}\nServices: {healthy} of {SERVICE_COUNT} healthy\n{assistant_summary}\nRelease: ordinal {}\nProblems:\n  - {}\nNext: shimpz start",
        installed.ordinal,
        problems.join("\n  - ")
    ))
}

fn validate_snapshot(observations: &[Observation]) -> Result<(), String> {
    if observations.len() != COMPONENTS.len()
        || !observations
            .iter()
            .zip(COMPONENTS)
            .all(|(observation, component)| observation.component == component)
    {
        return Err("the Local runtime snapshot is incomplete".into());
    }
    Ok(())
}

fn static_stopped(observations: &[Observation]) -> bool {
    observations.iter().all(|observation| {
        matches!(
            (observation.component.expectation, observation.runtime),
            (Expectation::Service, Runtime::Exited(_)) | (Expectation::Init, Runtime::Exited(0))
        )
    })
}

fn stop_requires_reconciliation(
    observations: &[Observation],
    assistants: &[AssistantObservation],
) -> bool {
    observations.iter().any(|observation| {
        matches!(
            (observation.component.expectation, observation.runtime),
            (Expectation::Service, Runtime::Missing | Runtime::Dead(_))
        ) || (observation.component.expectation == Expectation::Init
            && !matches!(observation.runtime, Runtime::Exited(0)))
    }) || assistants
        .iter()
        .any(|assistant| matches!(assistant.runtime, Runtime::Dead(_)))
}

fn stopped_services(observations: &[Observation]) -> usize {
    observations
        .iter()
        .filter(|observation| {
            observation.component.expectation == Expectation::Service
                && matches!(observation.runtime, Runtime::Exited(_))
        })
        .count()
}

fn assistant_summary(count: usize, total: usize, state: &str) -> String {
    if total == 0 {
        "Assistants: 0 installed".into()
    } else if count == total {
        format!("Assistants: {count} {state}")
    } else {
        format!("Assistants: {count} of {total} {state}")
    }
}

fn assistant_problem(running: usize, total: usize) -> String {
    let unavailable = total - running;
    if unavailable == 1 {
        "1 Assistant is not running.".into()
    } else {
        format!("{unavailable} Assistants are not running.")
    }
}

fn service_problem(observation: Observation) -> Option<String> {
    let label = observation.component.label;
    Some(match observation.runtime {
        Runtime::Missing => format!("{label} is missing."),
        Runtime::Created => format!("{label} has not started."),
        Runtime::Running(Health::Unavailable) => format!("{label} health is unavailable."),
        Runtime::Running(Health::Starting) => format!("{label} is starting."),
        Runtime::Running(Health::Unhealthy) => format!("{label} is unhealthy."),
        Runtime::Paused => format!("{label} is paused."),
        Runtime::Restarting => format!("{label} is restarting."),
        Runtime::Removing => format!("{label} is being removed."),
        Runtime::Exited(code) => format!("{label} stopped with exit code {code}."),
        Runtime::Dead(code) => format!("{label} failed with exit code {code}."),
        Runtime::Running(Health::Healthy) => return None,
    })
}

fn init_problem(observation: Observation) -> Option<String> {
    Some(match observation.runtime {
        Runtime::Missing => "Account setup is missing.".into(),
        Runtime::Exited(0) => return None,
        Runtime::Exited(code) | Runtime::Dead(code) => {
            format!("Account setup failed with exit code {code}.")
        }
        Runtime::Created
        | Runtime::Running(_)
        | Runtime::Paused
        | Runtime::Restarting
        | Runtime::Removing => "Account setup is incomplete.".into(),
    })
}

fn malformed(component: Component) -> String {
    format!(
        "Docker returned malformed status for {}",
        component.docker_name
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed() -> Installed {
        Installed {
            space_id: "space-0123456789abcdef01234567".into(),
            release_ref: format!(
                "ghcr.io/theshimpz/shimpz-local-release@sha256:{}",
                "a".repeat(64)
            ),
            admin_image: format!("ghcr.io/theshimpz/shimpz-admin@sha256:{}", "b".repeat(64)),
            ordinal: 42,
            port: 7777,
        }
    }

    fn healthy_observations() -> Vec<Observation> {
        COMPONENTS
            .iter()
            .copied()
            .map(|component| {
                let record = if component.expectation == Expectation::Init {
                    format!("{}|exited||0", component.service)
                } else {
                    format!("{}|running|healthy|0", component.service)
                };
                observe(component, Some(&record)).unwrap()
            })
            .collect()
    }

    fn stopped_observations() -> Vec<Observation> {
        COMPONENTS
            .iter()
            .copied()
            .map(|component| {
                let code = if component.expectation == Expectation::Init {
                    0
                } else {
                    143
                };
                observe(
                    component,
                    Some(&format!("{}|exited||{code}", component.service)),
                )
                .unwrap()
            })
            .collect()
    }

    fn assistant(record: &str) -> AssistantObservation {
        observe_assistant(record).unwrap()
    }

    #[test]
    fn renders_only_actionable_healthy_details() {
        let rendered = render(&installed(), true, false, &healthy_observations(), &[]).unwrap();

        assert_eq!(
            rendered,
            "Shimpz Space is healthy.\nAdmin: http://127.0.0.1:7777\nServices: 7 healthy\nAssistants: 0 installed\nRelease: ordinal 42"
        );
        assert!(!rendered.contains("sha256:"));
        assert!(!rendered.contains("space-"));

        let with_assistants = render(
            &installed(),
            true,
            false,
            &healthy_observations(),
            &[assistant("running|0"), assistant("running|0")],
        )
        .unwrap();
        assert!(with_assistants.contains("Assistants: 2 running"));
    }

    #[test]
    fn renders_an_intentional_complete_stop_without_an_admin_address() {
        let rendered = render(
            &installed(),
            false,
            true,
            &stopped_observations(),
            &[assistant("exited|0"), assistant("exited|143")],
        )
        .unwrap();

        assert_eq!(
            rendered,
            "Shimpz Space is stopped.\nServices: 7 stopped\nAssistants: 2 stopped\nRelease: ordinal 42\nConfiguration: will reconcile on start\nNext: shimpz start"
        );
        assert!(fully_stopped(&stopped_observations(), &[assistant("exited|137")]).unwrap());

        let current = render(&installed(), true, true, &stopped_observations(), &[]).unwrap();
        assert!(!current.contains("Configuration:"));
    }

    #[test]
    fn reports_an_incomplete_stop_as_one_bounded_problem() {
        let mut observations = stopped_observations();
        observations[1] = observe(COMPONENTS[1], Some("team|running|healthy|0")).unwrap();
        let rendered = render(
            &installed(),
            true,
            true,
            &observations,
            &[assistant("exited|0"), assistant("running|0")],
        )
        .unwrap();

        assert_eq!(
            rendered,
            "Shimpz Space needs attention.\nServices: 6 of 7 stopped\nAssistants: 1 of 2 stopped\nRelease: ordinal 42\nProblem: the requested stop is incomplete.\nNext: shimpz stop"
        );
        assert!(!fully_stopped(&observations, &[]).unwrap());
        assert_eq!(
            incomplete_stop_error(&observations, &[]).unwrap(),
            "the Space stop is incomplete; re-run shimpz stop"
        );
    }

    #[test]
    fn an_unstoppable_runtime_names_reconciliation_before_another_stop() {
        let mut observations = stopped_observations();
        observations[0] = observe(COMPONENTS[0], None).unwrap();
        let assistants = [assistant("dead|2")];

        let rendered = render(&installed(), true, true, &observations, &assistants).unwrap();

        assert!(rendered.ends_with("Next: shimpz install, then shimpz stop"));
        assert_eq!(
            incomplete_stop_error(&observations, &assistants).unwrap(),
            "the Space stop is incomplete; run shimpz install to reconcile it, then run shimpz stop"
        );
    }

    #[test]
    fn covers_the_exact_static_resource_inventory() {
        let status_names = COMPONENTS
            .map(Component::docker_name)
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        let resource_names = super::super::resources::RESERVED
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(status_names, resource_names);
        assert_eq!(
            COMPONENTS
                .iter()
                .filter(|component| component.expectation == Expectation::Service)
                .count(),
            SERVICE_COUNT
        );
    }

    #[test]
    fn renders_only_the_problems_in_a_degraded_space() {
        let mut observations = healthy_observations();
        observations[0] = observe(COMPONENTS[0], Some("admin|exited||0")).unwrap();
        observations[1] = observe(COMPONENTS[1], Some("team|exited||7")).unwrap();
        observations[5] = observe(
            COMPONENTS[5],
            Some("shimpz-assistant-release|running|unhealthy|0"),
        )
        .unwrap();
        observations[7] = observe(COMPONENTS[7], None).unwrap();

        let rendered = render(
            &installed(),
            false,
            false,
            &observations,
            &[assistant("exited|0")],
        )
        .unwrap();

        assert_eq!(
            rendered,
            "Shimpz Space needs attention.\nAdmin: unavailable\nServices: 4 of 7 healthy\nAssistants: 0 of 1 running\nRelease: ordinal 42\nProblems:\n  - Local configuration needs reconciliation.\n  - Admin stopped with exit code 0.\n  - Team stopped with exit code 7.\n  - Assistant release boundary is unhealthy.\n  - Account setup is missing.\n  - 1 Assistant is not running.\nNext: shimpz start"
        );

        let plural = render(
            &installed(),
            true,
            false,
            &healthy_observations(),
            &[assistant("exited|0"), assistant("dead|2")],
        )
        .unwrap();
        assert!(plural.contains("2 Assistants are not running."));
    }

    #[test]
    fn maps_every_known_non_ready_runtime_to_static_copy() {
        let mut missing = healthy_observations();
        missing[0] = observe(COMPONENTS[0], None).unwrap();
        assert!(
            render(&installed(), true, false, &missing, &[])
                .unwrap()
                .contains("  - Admin is missing.")
        );
        for record in [
            "admin|created||0",
            "admin|running||0",
            "admin|running|starting|0",
            "admin|paused|healthy|0",
            "admin|restarting|unhealthy|1",
            "admin|removing||0",
            "admin|dead||9",
        ] {
            let mut observations = healthy_observations();
            observations[0] = observe(COMPONENTS[0], Some(record)).unwrap();
            let rendered = render(&installed(), true, false, &observations, &[]).unwrap();
            assert!(rendered.starts_with("Shimpz Space needs attention."));
            assert!(rendered.contains("  - Admin"));
        }
        for record in [
            "shimpz-account-egress-init|running||0",
            "shimpz-account-egress-init|dead||0",
            "shimpz-account-egress-init|dead||2",
        ] {
            let mut observations = healthy_observations();
            observations[7] = observe(COMPONENTS[7], Some(record)).unwrap();
            assert!(
                render(&installed(), true, false, &observations, &[])
                    .unwrap()
                    .contains("  - Account setup")
            );
        }
    }

    #[test]
    fn parses_every_assistant_runtime_without_exposing_identity() {
        for record in [
            "created|0",
            "running|0",
            "paused|0",
            "restarting|1",
            "removing|0",
            "exited|143",
            "dead|9",
        ] {
            assert!(observe_assistant(record).is_ok(), "{record}");
        }
    }

    #[test]
    fn rejects_malformed_or_incomplete_snapshots() {
        let component = COMPONENTS[0];
        for record in [
            "",
            "admin|running|healthy",
            "team|running|healthy|0",
            "admin|unknown|healthy|0",
            "admin|running|unknown|0",
            "admin|running|healthy|-1",
            "admin|running|healthy|0\nadmin|running|healthy|0",
            "admin|running|healthy|0\r",
        ] {
            assert!(observe(component, Some(record)).is_err());
        }
        assert!(observe(component, Some(&"x".repeat(MAX_RECORD_BYTES + 1))).is_err());
        for record in [
            "",
            "running",
            "unknown|0",
            "running|-1",
            "running|0\nrunning|0",
            "running|0\r",
        ] {
            assert!(observe_assistant(record).is_err());
        }
        assert!(observe_assistant(&"x".repeat(MAX_RECORD_BYTES + 1)).is_err());
        assert!(render(&installed(), true, false, &healthy_observations()[..7], &[]).is_err());
        assert!(fully_stopped(&healthy_observations()[..7], &[]).is_err());
        assert!(!observe(component, None).unwrap().is_present());
    }

    #[test]
    fn gives_clear_next_steps_for_non_runtime_states() {
        assert_eq!(
            not_installed(),
            "Shimpz Space is not installed.\nNext: shimpz install"
        );
        assert_eq!(
            operation_in_progress(),
            "A Shimpz Space lifecycle operation is in progress.\nNext: run shimpz status again shortly."
        );
    }
}
