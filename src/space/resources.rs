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

    pub(crate) fn same_targets(&self, other: &Self) -> bool {
        self.space_id == other.space_id
            && same_ids(&self.project_containers, &other.project_containers)
            && same_ids(&self.project_volumes, &other.project_volumes)
            && same_ids(&self.project_networks, &other.project_networks)
            && same_ids(&self.dynamic_containers, &other.dynamic_containers)
            && same_ids(&self.dynamic_networks, &other.dynamic_networks)
    }

    pub(crate) fn container_names(&self, engine: &Engine) -> Result<Vec<String>, String> {
        let names: BTreeSet<_> = inspect_records(
            engine,
            &["inspect", "--type=container"],
            Identity::Id,
            "{{.Name}}",
            &self.container_ids(),
            "container name",
        )?
        .into_iter()
        .map(|name| name.trim_start_matches('/').to_owned())
        .collect();
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
        let names = inspect_records(
            engine,
            &["inspect", "--type=container"],
            Identity::Id,
            "{{.Name}}",
            &self.project_containers,
            "container name",
        )?;
        Ok(self
            .project_containers
            .iter()
            .zip(names)
            .find(|(_, name)| name == "/shimpz-team")
            .map(|(identifier, _)| identifier.clone()))
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

/// Docker inspects many objects per call; a bounded chunk keeps each command line small.
const INSPECT_CHUNK: usize = 64;

/// How an inspected record proves it answers the identifier that was asked for.
#[derive(Clone, Copy)]
enum Identity {
    /// A container or network: the full 64-character id the listed short id prefixes.
    Id,
    /// A volume: its exact name.
    Name,
}

/// Inspect `identifiers` in bounded batches instead of one Docker process each. Every record starts with the
/// object's identity; the answer must hold exactly one record per requested identifier, in request order, each
/// matching its request, or the whole inspection fails closed.
fn inspect_records(
    engine: &Engine,
    command: &[&str],
    identity: Identity,
    format: &str,
    identifiers: &[String],
    label: &str,
) -> Result<Vec<String>, String> {
    let malformed = || format!("{label} is malformed");
    let format = match identity {
        Identity::Id => format!("{{{{.Id}}}}|{format}"),
        Identity::Name => format!("{{{{.Name}}}}|{format}"),
    };
    let mut records = Vec::with_capacity(identifiers.len());
    for chunk in identifiers.chunks(INSPECT_CHUNK) {
        let mut arguments = command.to_vec();
        arguments.extend(["--format", format.as_str()]);
        arguments.extend(chunk.iter().map(String::as_str));
        let output = engine.run_output(arguments)?;
        let lines: Vec<_> = output.lines().collect();
        if lines.len() != chunk.len() {
            return Err(malformed());
        }
        for (requested, line) in chunk.iter().zip(lines) {
            let (answered, record) = line.split_once('|').ok_or_else(malformed)?;
            let matches = match identity {
                Identity::Id => {
                    !requested.is_empty()
                        && answered.len() == 64
                        && answered.starts_with(requested.as_str())
                }
                Identity::Name => answered == requested,
            };
            if !matches || record.is_empty() {
                return Err(malformed());
            }
            records.push(record.to_owned());
        }
    }
    Ok(records)
}

fn validate_project_containers(engine: &Engine, identifiers: &[String]) -> Result<(), String> {
    let mut services = BTreeSet::new();
    for record in inspect_records(
        engine,
        &["inspect", "--type=container"],
        Identity::Id,
        "{{.Name}}|{{index .Config.Labels \"com.docker.compose.service\"}}|{{.Config.Image}}",
        identifiers,
        "Compose container",
    )? {
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
    for record in inspect_records(
        engine,
        &["volume", "inspect"],
        Identity::Name,
        "{{.Name}}|{{index .Labels \"com.docker.compose.volume\"}}|{{.Driver}}|{{with .Options}}{{index . \"type\"}}{{end}}|{{with .Options}}{{index . \"o\"}}{{end}}|{{with .Options}}{{index . \"device\"}}{{end}}",
        identifiers,
        "Compose volume",
    )? {
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
    for record in inspect_records(
        engine,
        &["network", "inspect"],
        Identity::Id,
        "{{.Name}}|{{index .Labels \"com.docker.compose.network\"}}",
        identifiers,
        "Compose network",
    )? {
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
    for record in inspect_records(
        engine,
        &["inspect", "--type=container"],
        Identity::Id,
        "{{.Name}}|{{index .Config.Labels \"com.shimpz.local.managed\"}}|{{index .Config.Labels \"com.shimpz.local.profile\"}}|{{index .Config.Labels \"com.shimpz.local.space-id\"}}|{{index .Config.Labels \"com.shimpz.local.kind\"}}|{{index .Config.Labels \"com.shimpz.local.team-id\"}}|{{index .Config.Labels \"com.shimpz.local.assistant-id\"}}",
        identifiers,
        "managed container",
    )? {
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
    for record in inspect_records(
        engine,
        &["network", "inspect"],
        Identity::Id,
        "{{.Name}}|{{index .Labels \"com.shimpz.local.managed\"}}|{{index .Labels \"com.shimpz.local.profile\"}}|{{index .Labels \"com.shimpz.local.space-id\"}}|{{index .Labels \"com.shimpz.local.kind\"}}|{{index .Labels \"com.shimpz.local.team-id\"}}",
        identifiers,
        "managed network",
    )? {
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

fn same_ids(left: &[String], right: &[String]) -> bool {
    left.iter().collect::<BTreeSet<_>>() == right.iter().collect::<BTreeSet<_>>()
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

    /// A fake `docker` that logs each call and answers every identifier after `--format` from a `map` file whose
    /// lines start with that identifier's full identity.
    #[cfg(unix)]
    fn fake_docker(map: &str) -> (tempfile::TempDir, Engine) {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::write(root.join("map"), map).unwrap();
        let command = root.join("docker");
        std::fs::write(
            &command,
            format!(
                "#!/bin/sh\nprintf 'call\\n' >> '{calls}'\nseen=0\nfor argument in \"$@\"; do\n  \
                 if [ \"$seen\" = 2 ]; then grep -m1 \"^$argument\" '{map}' || true; fi\n  \
                 if [ \"$seen\" = 1 ]; then seen=2; fi\n  \
                 if [ \"$argument\" = --format ]; then seen=1; fi\ndone\n",
                calls = root.join("calls").display(),
                map = root.join("map").display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o700)).unwrap();
        (temporary, Engine::with_docker(command))
    }

    #[cfg(unix)]
    fn calls(temporary: &tempfile::TempDir) -> usize {
        std::fs::read_to_string(temporary.path().join("calls"))
            .unwrap_or_default()
            .lines()
            .count()
    }

    #[cfg(unix)]
    #[test]
    fn inspects_resources_in_bounded_batches_instead_of_one_process_each() {
        // 70 networks used to cost 70 Docker processes; bounded batches of 64 cost 2.
        let identifiers: Vec<String> = (0..70).map(|index| format!("n{index:03}")).collect();
        let map = identifiers
            .iter()
            .map(|id| format!("{id:0<64}|shimpz-space_egress|egress\n"))
            .collect::<Vec<_>>()
            .concat();
        let (temporary, engine) = fake_docker(&map);
        validate_project_networks(&engine, &identifiers).unwrap();
        assert_eq!(calls(&temporary), 2);

        let inventory = Inventory {
            project_containers: identifiers[..3].to_vec(),
            dynamic_containers: identifiers[1..4].to_vec(),
            ..Inventory::default()
        };
        let names = identifiers[..4]
            .iter()
            .enumerate()
            .map(|(index, id)| {
                let name = if index == 2 { "/shimpz-team" } else { "/other" };
                format!("{id:0<64}|{name}\n")
            })
            .collect::<Vec<_>>()
            .concat();
        let (temporary, engine) = fake_docker(&names);
        assert_eq!(
            inventory.container_names(&engine).unwrap(),
            ["other", "shimpz-team"]
        );
        assert_eq!(
            inventory.team_container_id(&engine).unwrap().as_deref(),
            Some("n002")
        );
        assert_eq!(calls(&temporary), 2);
    }

    #[cfg(unix)]
    #[test]
    fn a_batch_fails_closed_unless_each_record_answers_its_own_request() {
        let requested = vec!["n001".to_owned(), "n002".to_owned()];
        let one = format!("{:0<64}|shimpz-space_egress|egress\n", "n001");
        // A missing record, a short identity, or a record for another object each refuse the inspection.
        for map in [
            one.clone(),
            format!("{one}{:0<64}|shimpz-space_egress|egress\n", "n009"),
        ] {
            let (_temporary, engine) = fake_docker(&map);
            assert!(validate_project_networks(&engine, &requested).is_err());
        }
        let short = "n001|shimpz-space_egress|egress\n";
        let (_temporary, engine) = fake_docker(short);
        assert!(validate_project_networks(&engine, &requested[..1]).is_err());
        let volume =
            "shimpz-space_team_storage2|shimpz-space_team_storage2|team_storage|local||||\n";
        let (_temporary, engine) = fake_docker(volume);
        assert!(
            inspect_records(
                &engine,
                &["volume", "inspect"],
                Identity::Name,
                "{{.Name}}",
                &["shimpz-space_team_storage".to_owned()],
                "Compose volume",
            )
            .is_err()
        );
    }

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
    fn hard_reset_target_comparison_is_order_independent_and_closed() {
        let left = Inventory {
            space_id: Some("space-0123456789abcdef01234567".into()),
            project_containers: vec!["b".into(), "a".into()],
            ..Inventory::default()
        };
        let mut reordered = left.clone();
        reordered.project_containers.reverse();
        assert!(left.same_targets(&reordered));
        reordered.project_containers.push("new".into());
        assert!(!left.same_targets(&reordered));
        reordered.project_containers.pop();
        reordered.space_id = Some("space-fedcba9876543210fedcba98".into());
        assert!(!left.same_targets(&reordered));
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
