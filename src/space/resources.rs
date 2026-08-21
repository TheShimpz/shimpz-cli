//! Exact Docker resource ownership and cleanup proof.

use std::collections::BTreeSet;

use super::docker::Engine;
use super::graph::{StorageProfile, VOLUME_NAMES};
use super::paths::Paths;

const PROJECT: &str = "shimpz-space";
const PROFILE: &str = "local-v1";
pub(crate) const RESERVED: [&str; 8] = [
    "shimpz-admin",
    "shimpz-team",
    "shimpz-brain",
    "shimpz-brain-egress",
    "shimpz-assistant-egress",
    "shimpz-assistant-release",
    "shimpz-account-egress",
    "shimpz-account-egress-init",
];
const NETWORKS: [&str; 10] = [
    "egress",
    "control",
    "brain_runtime",
    "brain_egress",
    "brain_egress_out",
    "assistant_release",
    "assistant_release_out",
    "assistant_egress_out",
    "account_egress",
    "account_egress_out",
];

#[derive(Clone, Debug, Default)]
pub(crate) struct Inventory {
    pub(crate) space_id: Option<String>,
    pub(crate) project_containers: Vec<String>,
    pub(crate) project_volumes: Vec<String>,
    pub(crate) project_networks: Vec<String>,
    pub(crate) dynamic_containers: Vec<String>,
    pub(crate) dynamic_networks: Vec<String>,
}

impl Inventory {
    pub(crate) fn inspect(
        engine: &Engine,
        paths: &Paths,
        storage: StorageProfile,
    ) -> Result<Self, String> {
        validate_reserved(engine)?;
        let environment_id = read_space_id(paths)?;
        let controller_id = controller_space_id(engine)?;
        let space_id = match (environment_id, controller_id) {
            (Some(left), Some(right)) if left != right => {
                return Err("local and controller Space identities differ".into());
            }
            (Some(value), _) | (_, Some(value)) => Some(value),
            (None, None) => None,
        };
        let project_containers = ids(&engine.run_output([
            "ps",
            "--all",
            "--quiet",
            "--filter",
            &format!("label=com.docker.compose.project={PROJECT}"),
        ])?);
        let project_volumes = ids(&engine.run_output([
            "volume",
            "ls",
            "--quiet",
            "--filter",
            &format!("label=com.docker.compose.project={PROJECT}"),
        ])?);
        let project_networks = ids(&engine.run_output([
            "network",
            "ls",
            "--quiet",
            "--filter",
            &format!("label=com.docker.compose.project={PROJECT}"),
        ])?);
        validate_project_containers(engine, &project_containers)?;
        validate_project_volumes(engine, paths, storage, &project_volumes)?;
        validate_project_networks(engine, &project_networks)?;
        let local_containers = ids(&engine.run_output([
            "ps",
            "--all",
            "--quiet",
            "--filter",
            "label=com.shimpz.local.managed=1",
            "--filter",
            &format!("label=com.shimpz.local.profile={PROFILE}"),
        ])?);
        let local_networks = ids(&engine.run_output([
            "network",
            "ls",
            "--quiet",
            "--filter",
            "label=com.shimpz.local.managed=1",
            "--filter",
            &format!("label=com.shimpz.local.profile={PROFILE}"),
        ])?);
        match &space_id {
            Some(value) => {
                validate_dynamic_containers(engine, value, &local_containers)?;
                validate_dynamic_networks(engine, value, &local_networks)?;
            }
            None if !local_containers.is_empty() || !local_networks.is_empty() => {
                return Err(
                    "current Space identity is required to manage Team or Assistant resources"
                        .into(),
                );
            }
            None => {}
        }
        Ok(Self {
            space_id,
            project_containers,
            project_volumes,
            project_networks,
            dynamic_containers: local_containers,
            dynamic_networks: local_networks,
        })
    }

    pub(crate) fn empty(&self) -> bool {
        self.project_containers.is_empty()
            && self.project_volumes.is_empty()
            && self.project_networks.is_empty()
            && self.dynamic_containers.is_empty()
            && self.dynamic_networks.is_empty()
    }

    pub(crate) fn container_names(&self, engine: &Engine) -> Result<Vec<String>, String> {
        let mut names = BTreeSet::new();
        for identifier in self
            .project_containers
            .iter()
            .chain(self.dynamic_containers.iter())
        {
            let name = one_line(
                &engine.run_output([
                    "inspect",
                    "--type=container",
                    "--format",
                    "{{.Name}}",
                    identifier,
                ])?,
                "container name",
            )?;
            names.insert(name.trim_start_matches('/').to_owned());
        }
        Ok(names.into_iter().collect())
    }

    pub(crate) fn container_ids(&self) -> Vec<String> {
        self.project_containers
            .iter()
            .chain(self.dynamic_containers.iter())
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub(crate) fn team_container_id(&self, engine: &Engine) -> Result<Option<String>, String> {
        for identifier in &self.project_containers {
            let name = one_line(
                &engine.run_output([
                    "inspect",
                    "--type=container",
                    "--format",
                    "{{.Name}}",
                    identifier,
                ])?,
                "container name",
            )?;
            if name == "/shimpz-team" {
                return Ok(Some(identifier.clone()));
            }
        }
        Ok(None)
    }

    pub(crate) fn assistant_containers(&self) -> Vec<&str> {
        let project: BTreeSet<_> = self.project_containers.iter().map(String::as_str).collect();
        self.dynamic_containers
            .iter()
            .map(String::as_str)
            .filter(|identifier| !project.contains(identifier))
            .collect()
    }

    pub(crate) fn remove(self, engine: &Engine) -> Result<(), String> {
        let project_containers: BTreeSet<_> = self.project_containers.iter().collect();
        for identifier in self
            .dynamic_containers
            .iter()
            .filter(|identifier| !project_containers.contains(identifier))
            .chain(self.project_containers.iter())
        {
            require_removed(engine, ["rm", "--force", identifier], "container")?;
        }
        let project_networks: BTreeSet<_> = self.project_networks.iter().collect();
        for identifier in self
            .dynamic_networks
            .iter()
            .filter(|identifier| !project_networks.contains(identifier))
            .chain(self.project_networks.iter())
        {
            require_removed(engine, ["network", "rm", identifier], "network")?;
        }
        for identifier in &self.project_volumes {
            require_removed(engine, ["volume", "rm", identifier], "volume")?;
        }
        Ok(())
    }
}

fn validate_reserved(engine: &Engine) -> Result<(), String> {
    for name in RESERVED {
        let record = engine.run_output([
            "inspect",
            "--type=container",
            "--format",
            "{{index .Config.Labels \"com.docker.compose.project\"}}",
            name,
        ]);
        match record {
            Ok(value) if value.trim() == PROJECT => {}
            Ok(_) => return Err(format!("another Docker container is already named {name}")),
            Err(_) => {}
        }
    }
    Ok(())
}

fn controller_space_id(engine: &Engine) -> Result<Option<String>, String> {
    let project = engine.run_output([
        "inspect",
        "--type=container",
        "--format",
        "{{index .Config.Labels \"com.docker.compose.project\"}}",
        "shimpz-team",
    ]);
    match project {
        Err(_) => Ok(None),
        Ok(value) if value.trim() != PROJECT => {
            Err("the reserved controller belongs to another project".into())
        }
        Ok(_) => {
            let environment = engine.run_output([
                "inspect",
                "--type=container",
                "--format",
                "{{range .Config.Env}}{{println .}}{{end}}",
                "shimpz-team",
            ])?;
            let values: Vec<_> = environment
                .lines()
                .filter_map(|line| line.strip_prefix("SHIMPZ_SPACE_ID="))
                .collect();
            if values.len() != 1 || !valid_space_id(values[0]) {
                return Err("the controller has an ambiguous Space identity".into());
            }
            Ok(Some(values[0].into()))
        }
    }
}

fn read_space_id(paths: &Paths) -> Result<Option<String>, String> {
    if !paths.environment.exists() {
        return Ok(None);
    }
    let document = std::fs::read_to_string(&paths.environment)
        .map_err(|error| format!("could not read the Local environment: {error}"))?;
    let values: Vec<_> = document
        .lines()
        .filter_map(|line| line.strip_prefix("SHIMPZ_SPACE_ID="))
        .collect();
    if values.len() != 1 || !valid_space_id(values[0]) {
        return Err("the Local Space identity is invalid".into());
    }
    Ok(Some(values[0].into()))
}

fn validate_project_containers(engine: &Engine, identifiers: &[String]) -> Result<(), String> {
    let mut services = BTreeSet::new();
    for identifier in identifiers {
        let record = one_line(
            &engine.run_output([
                "inspect",
                "--type=container",
                "--format",
                "{{.Name}}|{{index .Config.Labels \"com.docker.compose.service\"}}|{{.Config.Image}}",
                identifier,
            ])?,
            "Compose container",
        )?;
        let fields: Vec<_> = record.split('|').collect();
        if fields.len() != 3 {
            return Err("a Compose container record is malformed".into());
        }
        let repository = static_service(fields[0], fields[1])
            .ok_or_else(|| format!("unknown Compose container: {}", fields[0]))?;
        if !valid_image(fields[2], repository) || !services.insert(fields[1].to_owned()) {
            return Err(
                "a Compose container has invalid image or duplicate service identity".into(),
            );
        }
    }
    Ok(())
}

fn validate_project_volumes(
    engine: &Engine,
    paths: &Paths,
    storage: StorageProfile,
    identifiers: &[String],
) -> Result<(), String> {
    for identifier in identifiers {
        let record = one_line(
            &engine.run_output([
                "volume",
                "inspect",
                "--format",
                "{{.Name}}|{{index .Labels \"com.docker.compose.volume\"}}|{{.Driver}}|{{with .Options}}{{index . \"type\"}}{{end}}|{{with .Options}}{{index . \"o\"}}{{end}}|{{with .Options}}{{index . \"device\"}}{{end}}",
                identifier,
            ])?,
            "Compose volume",
        )?;
        let fields: Vec<_> = record.split('|').collect();
        if fields.len() != 6
            || !VOLUME_NAMES.contains(&fields[1])
            || fields[0] != format!("{PROJECT}_{}", fields[1])
        {
            return Err("the Compose project contains an unknown volume".into());
        }
        match storage {
            StorageProfile::LinuxLuks => {
                let device = paths.pool_mount.join(fields[1]);
                if fields[2..5] != ["local", "none", "bind"]
                    || fields[5] != device.to_string_lossy()
                {
                    return Err("a Local volume is not bound to encrypted storage".into());
                }
            }
            StorageProfile::ManagedDisk if fields[2..] != ["local", "", "", ""] => {
                return Err("a Local volume is not Docker-managed".into());
            }
            StorageProfile::ManagedDisk => {}
        }
    }
    Ok(())
}

fn validate_project_networks(engine: &Engine, identifiers: &[String]) -> Result<(), String> {
    for identifier in identifiers {
        let record = one_line(
            &engine.run_output([
                "network",
                "inspect",
                "--format",
                "{{.Name}}|{{index .Labels \"com.docker.compose.network\"}}",
                identifier,
            ])?,
            "Compose network",
        )?;
        let fields: Vec<_> = record.split('|').collect();
        if fields.len() != 2
            || !NETWORKS.contains(&fields[1])
            || fields[0] != format!("{PROJECT}_{}", fields[1])
        {
            return Err("the Compose project contains an unknown network".into());
        }
    }
    Ok(())
}

fn validate_dynamic_containers(
    engine: &Engine,
    space_id: &str,
    identifiers: &[String],
) -> Result<(), String> {
    let mut unique = BTreeSet::new();
    for identifier in identifiers {
        let record = one_line(
            &engine.run_output([
                "inspect",
                "--type=container",
                "--format",
                "{{.Name}}|{{index .Config.Labels \"com.shimpz.local.managed\"}}|{{index .Config.Labels \"com.shimpz.local.profile\"}}|{{index .Config.Labels \"com.shimpz.local.space-id\"}}|{{index .Config.Labels \"com.shimpz.local.kind\"}}|{{index .Config.Labels \"com.shimpz.local.team-id\"}}|{{index .Config.Labels \"com.shimpz.local.assistant-id\"}}",
                identifier,
            ])?,
            "managed container",
        )?;
        let fields: Vec<_> = record.split('|').collect();
        if fields.len() != 7 || fields[1] != "1" || fields[2] != PROFILE || fields[3] != space_id {
            return Err("a managed container has invalid ownership labels".into());
        }
        match fields[4] {
            "assistant"
                if fields[0].starts_with("/shimpz-local-")
                    && valid_team(fields[5])
                    && valid_assistant(fields[6]) => {}
            "assistant-egress" if fields[0] == "/shimpz-assistant-egress" => {}
            "assistant-release" if fields[0] == "/shimpz-assistant-release" => {}
            "brain-egress" if fields[0] == "/shimpz-brain-egress" => {}
            "account-egress" if fields[0] == "/shimpz-account-egress" => {}
            _ => return Err("a managed container has invalid kind or name".into()),
        }
        if fields[4] != "assistant" && !unique.insert(fields[4].to_owned()) {
            return Err("duplicate managed proxy identity".into());
        }
    }
    Ok(())
}

fn validate_dynamic_networks(
    engine: &Engine,
    space_id: &str,
    identifiers: &[String],
) -> Result<(), String> {
    for identifier in identifiers {
        let record = one_line(
            &engine.run_output([
                "network",
                "inspect",
                "--format",
                "{{.Name}}|{{index .Labels \"com.shimpz.local.managed\"}}|{{index .Labels \"com.shimpz.local.profile\"}}|{{index .Labels \"com.shimpz.local.space-id\"}}|{{index .Labels \"com.shimpz.local.kind\"}}|{{index .Labels \"com.shimpz.local.team-id\"}}",
                identifier,
            ])?,
            "managed network",
        )?;
        let fields: Vec<_> = record.split('|').collect();
        if fields.len() != 6
            || !fields[0].starts_with("shimpz-local-")
            || fields[1] != "1"
            || fields[2] != PROFILE
            || fields[3] != space_id
            || fields[4] != "team"
            || !valid_team(fields[5])
        {
            return Err("a managed network has invalid ownership labels".into());
        }
    }
    Ok(())
}

fn static_service(name: &str, service: &str) -> Option<&'static str> {
    match (name, service) {
        ("/shimpz-admin", "admin") => Some("ghcr.io/theshimpz/shimpz-admin"),
        ("/shimpz-team", "team") => Some("ghcr.io/theshimpz/shimpz-team-local"),
        ("/shimpz-brain", "brain") => Some("ghcr.io/theshimpz/shimpz-brain"),
        ("/shimpz-brain-egress", "shimpz-brain-egress")
        | ("/shimpz-assistant-egress", "shimpz-assistant-egress")
        | ("/shimpz-assistant-release", "shimpz-assistant-release")
        | ("/shimpz-account-egress", "shimpz-account-egress")
        | ("/shimpz-account-egress-init", "shimpz-account-egress-init") => {
            Some("ghcr.io/theshimpz/shimpz-egress")
        }
        _ => None,
    }
}

fn valid_image(value: &str, repository: &str) -> bool {
    value
        .strip_prefix(repository)
        .and_then(|suffix| suffix.strip_prefix("@sha256:"))
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn valid_space_id(value: &str) -> bool {
    value.strip_prefix("space-").is_some_and(|suffix| {
        suffix.len() == 24
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_team(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_assistant(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 48
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && !value.contains("--")
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn ids(document: &str) -> Vec<String> {
    document.split_whitespace().map(str::to_owned).collect()
}

fn one_line(value: &str, label: &str) -> Result<String, String> {
    let mut lines = value.lines();
    let line = lines.next().filter(|line| !line.is_empty());
    if line.is_none() || lines.next().is_some() {
        return Err(format!("{label} is malformed"));
    }
    Ok(line.expect("checked").to_owned())
}

fn require_removed<const N: usize>(
    engine: &Engine,
    arguments: [&str; N],
    kind: &str,
) -> Result<(), String> {
    if engine
        .run_quiet_status(&format!("Docker managed {kind} removal"), arguments)?
        .success()
    {
        Ok(())
    } else {
        Err(format!("could not remove a managed Local {kind}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_closed_dynamic_identifiers() {
        assert!(valid_space_id("space-0123456789abcdef01234567"));
        assert!(valid_team("team_1"));
        assert!(valid_assistant("dns-manager"));
        assert!(!valid_team("Team"));
        assert!(!valid_assistant("DnsManager"));
        assert!(!valid_assistant("dns--manager"));
    }

    #[test]
    fn static_services_bind_exact_names_to_responsibility_images() {
        assert_eq!(
            static_service("/shimpz-team", "team"),
            Some("ghcr.io/theshimpz/shimpz-team-local")
        );
        assert!(static_service("/shimpz-team", "admin").is_none());
        assert!(static_service("/foreign", "team").is_none());
    }

    #[test]
    fn an_empty_inventory_is_a_successful_absence_proof() {
        assert!(Inventory::default().empty());
    }

    #[test]
    fn separates_dynamic_assistants_from_static_managed_boundaries() {
        let inventory = Inventory {
            project_containers: vec!["static".into()],
            dynamic_containers: vec!["static".into(), "assistant-b".into(), "assistant-a".into()],
            ..Inventory::default()
        };

        assert_eq!(
            inventory.assistant_containers(),
            ["assistant-b", "assistant-a"]
        );
        assert_eq!(
            inventory.container_ids(),
            ["assistant-a", "assistant-b", "static"]
        );
    }
}
