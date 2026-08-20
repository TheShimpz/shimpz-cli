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

pub(crate) fn not_installed() -> &'static str {
    "Shimpz Space is not installed.\nNext: shimpz install"
}

pub(crate) fn operation_in_progress() -> &'static str {
    "A Shimpz Space update is in progress.\nNext: run shimpz status again shortly."
}

pub(crate) fn observe(component: Component, record: Option<&str>) -> Result<Observation, String> {
    let Some(record) = record else {
        return Ok(Observation {
            component,
            runtime: Runtime::Missing,
        });
    };
    if record.len() > MAX_RECORD_BYTES || record.contains('\r') {
        return Err(malformed(component));
    }
    let mut lines = record.lines();
    let line = lines
        .next()
        .filter(|line| !line.is_empty() && lines.next().is_none())
        .ok_or_else(|| malformed(component))?;
    let fields: Vec<_> = line.split('|').collect();
    if fields.len() != 4 || fields[0] != component.service {
        return Err(malformed(component));
    }
    let health = match fields[2] {
        "" => Health::Unavailable,
        "starting" => Health::Starting,
        "healthy" => Health::Healthy,
        "unhealthy" => Health::Unhealthy,
        _ => return Err(malformed(component)),
    };
    let exit_code = fields[3]
        .parse::<i32>()
        .ok()
        .filter(|code| *code >= 0)
        .ok_or_else(|| malformed(component))?;
    let runtime = match fields[1] {
        "created" => Runtime::Created,
        "running" => Runtime::Running(health),
        "paused" => Runtime::Paused,
        "restarting" => Runtime::Restarting,
        "removing" => Runtime::Removing,
        "exited" => Runtime::Exited(exit_code),
        "dead" => Runtime::Dead(exit_code),
        _ => return Err(malformed(component)),
    };
    Ok(Observation { component, runtime })
}

pub(crate) fn render(
    installed: &Installed,
    graph_current: bool,
    observations: &[Observation],
) -> Result<String, String> {
    if observations.len() != COMPONENTS.len()
        || !observations
            .iter()
            .zip(COMPONENTS)
            .all(|(observation, component)| observation.component == component)
    {
        return Err("the Local runtime snapshot is incomplete".into());
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
    if problems.is_empty() {
        return Ok(format!(
            "Shimpz Space is healthy.\nAdmin: http://127.0.0.1:{}\nServices: {healthy} healthy\nRelease: ordinal {}",
            installed.port, installed.ordinal
        ));
    }
    Ok(format!(
        "Shimpz Space needs attention.\nAdmin: http://127.0.0.1:{}\nServices: {healthy} of {SERVICE_COUNT} healthy\nRelease: ordinal {}\nProblems:\n  - {}\nNext: shimpz start",
        installed.port,
        installed.ordinal,
        problems.join("\n  - ")
    ))
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

    #[test]
    fn renders_only_actionable_healthy_details() {
        let rendered = render(&installed(), true, &healthy_observations()).unwrap();

        assert_eq!(
            rendered,
            "Shimpz Space is healthy.\nAdmin: http://127.0.0.1:7777\nServices: 7 healthy\nRelease: ordinal 42"
        );
        assert!(!rendered.contains("sha256:"));
        assert!(!rendered.contains("space-"));
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
        observations[1] = observe(COMPONENTS[1], Some("team|exited||7")).unwrap();
        observations[5] = observe(
            COMPONENTS[5],
            Some("shimpz-assistant-release|running|unhealthy|0"),
        )
        .unwrap();
        observations[7] = observe(COMPONENTS[7], None).unwrap();

        let rendered = render(&installed(), false, &observations).unwrap();

        assert_eq!(
            rendered,
            "Shimpz Space needs attention.\nAdmin: http://127.0.0.1:7777\nServices: 5 of 7 healthy\nRelease: ordinal 42\nProblems:\n  - Local configuration needs reconciliation.\n  - Team stopped with exit code 7.\n  - Assistant release boundary is unhealthy.\n  - Account setup is missing.\nNext: shimpz start"
        );
    }

    #[test]
    fn maps_every_known_non_ready_runtime_to_static_copy() {
        let mut missing = healthy_observations();
        missing[0] = observe(COMPONENTS[0], None).unwrap();
        assert!(
            render(&installed(), true, &missing)
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
            let rendered = render(&installed(), true, &observations).unwrap();
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
                render(&installed(), true, &observations)
                    .unwrap()
                    .contains("  - Account setup")
            );
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
        assert!(render(&installed(), true, &healthy_observations()[..7]).is_err());
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
            "A Shimpz Space update is in progress.\nNext: run shimpz status again shortly."
        );
    }
}
