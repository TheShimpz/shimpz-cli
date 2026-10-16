//! Exact Docker resource ownership and cleanup proof.

use std::collections::BTreeSet;
use std::thread;

use super::docker::Engine;
use super::graph::{self, NETWORK_NAMES, StorageProfile, VOLUME_NAMES};
use super::id;
use super::paths::Paths;
use super::release::Package;
use crate::{identifier, team_id};

const PROFILE: &str = "local-v1";
/// The label key naming the Local profile of a Space-managed container or network, with the value [`PROFILE`].
const PROFILE_LABEL: &str = "com.shimpz.local.profile";
/// The ownership label keys of a Space-managed container or network, in the order its inspect record lists them.
const OWNERSHIP_LABELS: [&str; 5] = [
    graph::MANAGED_LABEL,
    PROFILE_LABEL,
    "com.shimpz.local.space-id",
    graph::KIND_LABEL,
    "com.shimpz.local.team-id",
];

/// The Docker filter that selects the members of the Local Compose project.
pub(crate) fn project_filter() -> String {
    format!("label=com.docker.compose.project={}", graph::PROJECT)
}

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
    /// Every observation is an independent read-only Docker call, so each round runs its calls at once and then
    /// judges their answers in the fixed order a sequential inspection would, so the first refusal is the same.
    pub(crate) fn inspect(
        engine: &Engine,
        paths: &Paths,
        storage: StorageProfile,
    ) -> Result<Self, String> {
        let project = project_filter();
        let profile = format!("label={PROFILE_LABEL}={PROFILE}");
        let managed = format!("label={}=1", graph::MANAGED_LABEL);
        let local_filter = ["--filter", &managed, "--filter", &profile];
        let (reserved, controller, lists) = thread::scope(|scope| {
            let reserved: Vec<_> = graph::CONTAINERS
                .iter()
                .map(|name| scope.spawn(move || reserved_occupant(engine, name)))
                .collect();
            let controller = scope.spawn(|| controller_space_id(engine));
            let lists: Vec<_> = [
                vec!["ps", "--all", "--quiet", "--filter", &project],
                vec!["volume", "ls", "--quiet", "--filter", &project],
                vec!["network", "ls", "--quiet", "--filter", &project],
                [&["ps", "--all", "--quiet"][..], &local_filter].concat(),
                [&["network", "ls", "--quiet"][..], &local_filter].concat(),
            ]
            .into_iter()
            .map(|arguments| scope.spawn(move || engine.run_output(arguments).map(|out| ids(&out))))
            .collect();
            (
                reserved.into_iter().map(joined).collect::<Vec<_>>(),
                joined(controller),
                lists.into_iter().map(joined).collect::<Vec<_>>(),
            )
        });
        reserved.into_iter().collect::<Result<(), String>>()?;
        let environment_id = read_space_id(paths)?;
        let space_id = match (environment_id, controller?) {
            (Some(left), Some(right)) if left != right => {
                return Err("local and controller Space identities differ".into());
            }
            (Some(value), _) | (_, Some(value)) => Some(value),
            (None, None) => None,
        };
        let [
            project_containers,
            project_volumes,
            project_networks,
            local_containers,
            local_networks,
        ] = <[Result<Vec<String>, String>; 5]>::try_from(lists)
            .map_err(|_| "the Local inventory is incomplete".to_owned())?;
        let (project_containers, project_volumes, project_networks) =
            (project_containers?, project_volumes?, project_networks?);
        let dynamic = match (&space_id, &local_containers, &local_networks) {
            (Some(value), Ok(containers), Ok(networks)) => {
                Some((value.as_str(), containers, networks))
            }
            _ => None,
        };
        let (validated, dynamic) = thread::scope(|scope| {
            let validated = [
                scope.spawn(|| validate_project_containers(engine, &project_containers)),
                scope.spawn(|| validate_project_volumes(engine, paths, storage, &project_volumes)),
                scope.spawn(|| validate_project_networks(engine, &project_networks)),
            ];
            let dynamic = dynamic.map(|(value, containers, networks)| {
                [
                    scope.spawn(move || validate_dynamic_containers(engine, value, containers)),
                    scope.spawn(move || validate_dynamic_networks(engine, value, networks)),
                ]
            });
            (
                validated.map(joined),
                dynamic.map(|handles| handles.map(joined)),
            )
        });
        validated.into_iter().collect::<Result<(), String>>()?;
        let (local_containers, local_networks) = (local_containers?, local_networks?);
        match dynamic {
            Some(results) => results.into_iter().collect::<Result<(), String>>()?,
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
        let names: BTreeSet<_> =
            inspect_containers(engine, &self.container_ids(), "{{.Name}}", "container name")?
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
        let names = inspect_containers(
            engine,
            &self.project_containers,
            "{{.Name}}",
            "container name",
        )?;
        Ok(self
            .project_containers
            .iter()
            .zip(names)
            .find(|(_, name)| name.strip_prefix('/') == Some(graph::TEAM.container))
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

/// A reserved container name is free or held by this project; any other occupant refuses the inventory.
fn reserved_occupant(engine: &Engine, name: &str) -> Result<(), String> {
    match compose_project_of(engine, name) {
        Some(project) if project != graph::PROJECT => {
            Err(format!("another Docker container is already named {name}"))
        }
        _ => Ok(()),
    }
}

/// The Compose project label of the container named `name`, or `None` when no such container can be inspected.
fn compose_project_of(engine: &Engine, name: &str) -> Option<String> {
    engine
        .run_output([
            "inspect",
            "--type=container",
            "--format",
            "{{index .Config.Labels \"com.docker.compose.project\"}}",
            name,
        ])
        .ok()
        .map(|value| value.trim().to_owned())
}

/// The answer of one concurrent observation; a worker that panicked observed nothing and refuses the inventory.
fn joined<T>(handle: thread::ScopedJoinHandle<'_, Result<T, String>>) -> Result<T, String> {
    handle
        .join()
        .unwrap_or_else(|_| Err("a Local inventory observation failed".into()))
}

fn controller_space_id(engine: &Engine) -> Result<Option<String>, String> {
    match compose_project_of(engine, graph::TEAM.container) {
        None => Ok(None),
        Some(project) if project != graph::PROJECT => {
            Err("the reserved controller belongs to another project".into())
        }
        Some(_) => {
            let environment = engine.run_output([
                "inspect",
                "--type=container",
                "--format",
                "{{range .Config.Env}}{{println .}}{{end}}",
                graph::TEAM.container,
            ])?;
            single_space_id(&environment)
                .map(Some)
                .ok_or_else(|| "the controller has an ambiguous Space identity".into())
        }
    }
}

fn read_space_id(paths: &Paths) -> Result<Option<String>, String> {
    let Some(document) = paths.environment_record()? else {
        return Ok(None);
    };
    single_space_id(&document)
        .map(Some)
        .ok_or_else(|| "the Local Space identity is invalid".into())
}

/// The one valid Space id that exactly one `SHIMPZ_SPACE_ID=` line of `environment` declares.
fn single_space_id(environment: &str) -> Option<String> {
    let mut values = environment
        .lines()
        .filter_map(|line| line.strip_prefix("SHIMPZ_SPACE_ID="));
    match (values.next(), values.next()) {
        (Some(value), None) if id::valid(value) => Some(value.to_owned()),
        _ => None,
    }
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

/// Inspect inventory-proven containers by id in bounded batches; record `i` answers `identifiers[i]`.
pub(crate) fn inspect_containers(
    engine: &Engine,
    identifiers: &[String],
    format: &str,
    label: &str,
) -> Result<Vec<String>, String> {
    inspect_records(
        engine,
        &["inspect", "--type=container"],
        Identity::Id,
        format,
        identifiers,
        label,
    )
}

fn validate_project_containers(engine: &Engine, identifiers: &[String]) -> Result<(), String> {
    let mut services = BTreeSet::new();
    for record in inspect_containers(
        engine,
        identifiers,
        "{{.Name}}|{{index .Config.Labels \"com.docker.compose.service\"}}|{{.Config.Image}}",
        "Compose container",
    )? {
        let fields: Vec<_> = record.split('|').collect();
        if fields.len() != 3 {
            return Err("a Compose container record is malformed".into());
        }
        let package = static_service(fields[0], fields[1])
            .ok_or_else(|| format!("unknown Compose container: {}", fields[0]))?;
        if !package.admits(fields[2]) || !services.insert(fields[1].to_owned()) {
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
            || fields[0] != graph::resource_name(fields[1])
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
            || !NETWORK_NAMES.contains(&fields[1])
            || fields[0] != graph::resource_name(fields[1])
        {
            return Err("the Compose project contains an unknown network".into());
        }
    }
    Ok(())
}

/// The inspect template of an object's name followed by the value of each label in `keys`, read from its `labels`
/// map, all separated by `|`.
fn labels_template(labels: &str, keys: &[&str]) -> String {
    keys.iter().fold("{{.Name}}".to_owned(), |template, key| {
        format!("{template}|{{{{index {labels} \"{key}\"}}}}")
    })
}

fn validate_dynamic_containers(
    engine: &Engine,
    space_id: &str,
    identifiers: &[String],
) -> Result<(), String> {
    let mut unique = BTreeSet::new();
    for record in inspect_containers(
        engine,
        identifiers,
        &labels_template(
            ".Config.Labels",
            &[&OWNERSHIP_LABELS[..], &["com.shimpz.local.assistant-id"]].concat(),
        ),
        "managed container",
    )? {
        let fields: Vec<_> = record.split('|').collect();
        if fields.len() != 7 || fields[1] != "1" || fields[2] != PROFILE || fields[3] != space_id {
            return Err("a managed container has invalid ownership labels".into());
        }
        match fields[4] {
            "assistant"
                if fields[0].starts_with("/shimpz-local-")
                    && team_id::valid(fields[5])
                    && identifier::assistant_id(fields[6]) => {}
            kind if managed_proxy(kind, fields[0]) => {}
            _ => return Err("a managed container has invalid kind or name".into()),
        }
        if fields[4] != "assistant" && !unique.insert(fields[4].to_owned()) {
            return Err("duplicate managed proxy identity".into());
        }
    }
    Ok(())
}

/// Whether `name` is the container of the graph's egress proxy whose kind label is `kind`: its container name
/// without the `shimpz-` prefix.
fn managed_proxy(kind: &str, name: &str) -> bool {
    [
        graph::ASSISTANT_EGRESS,
        graph::ASSISTANT_RELEASE,
        graph::BRAIN_EGRESS,
        graph::ACCOUNT_EGRESS,
    ]
    .iter()
    .any(|member| {
        member.container.strip_prefix("shimpz-") == Some(kind)
            && name.strip_prefix('/') == Some(member.container)
    })
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
        &labels_template(".Labels", &OWNERSHIP_LABELS),
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
            || !team_id::valid(fields[5])
        {
            return Err("a managed network has invalid ownership labels".into());
        }
    }
    Ok(())
}

fn static_service(name: &str, service: &str) -> Option<Package> {
    let name = name.strip_prefix('/')?;
    if name == graph::ACCOUNT_EGRESS_INIT && service == graph::ACCOUNT_EGRESS_INIT {
        return Some(graph::ACCOUNT_EGRESS.package);
    }
    graph::MEMBERS
        .iter()
        .find(|member| member.container == name && member.service == service)
        .map(|member| member.package)
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

    #[test]
    fn reads_each_ownership_label_of_a_network_by_its_key() {
        assert_eq!(
            labels_template(".Labels", &OWNERSHIP_LABELS),
            "{{.Name}}|{{index .Labels \"com.shimpz.local.managed\"}}|{{index .Labels \"com.shimpz.local.profile\"}}|{{index .Labels \"com.shimpz.local.space-id\"}}|{{index .Labels \"com.shimpz.local.kind\"}}|{{index .Labels \"com.shimpz.local.team-id\"}}"
        );
    }

    #[test]
    fn admits_only_a_graph_egress_proxy_under_its_own_kind() {
        for (kind, name) in [
            ("assistant-egress", "/shimpz-assistant-egress"),
            ("assistant-release", "/shimpz-assistant-release"),
            ("brain-egress", "/shimpz-brain-egress"),
            ("account-egress", "/shimpz-account-egress"),
        ] {
            assert!(managed_proxy(kind, name), "{kind}");
        }
        for (kind, name) in [
            ("brain-egress", "/shimpz-account-egress"),
            ("account-egress", "shimpz-account-egress"),
            ("team", "/shimpz-team"),
            ("shimpz-brain-egress", "/shimpz-brain-egress"),
        ] {
            assert!(!managed_proxy(kind, name), "{kind} {name}");
        }
    }

    /// A fake `docker` that logs each call and answers every identifier after `--format` from a `map` file whose
    /// lines start with that identifier's full identity.
    #[cfg(unix)]
    fn fake_docker(map: &str) -> (tempfile::TempDir, Engine) {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::write(root.join("map"), map).unwrap();
        let command = root.join("docker");
        crate::fake_tool::write(
            &command,
            format!(
                "#!/bin/sh\nprintf 'call\\n' >> '{calls}'\nseen=0\nfor argument in \"$@\"; do\n  \
                 if [ \"$seen\" = 2 ]; then grep -m1 \"^$argument\" '{map}' || true; fi\n  \
                 if [ \"$seen\" = 1 ]; then seen=2; fi\n  \
                 if [ \"$argument\" = --format ]; then seen=1; fi\ndone\n",
                calls = root.join("calls").display(),
                map = root.join("map").display(),
            ),
        );
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
            .map(|id| format!("{id:0<64}|shimpz-space-egress|egress\n"))
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
    fn concurrent_observations_refuse_with_the_first_failure_in_sequential_order() {
        // Shimpz Brain answers last but precedes Shimpz Admin in the graph's container order, so its refusal is
        // reported.
        let temporary = tempfile::tempdir().unwrap();
        let paths = Paths::under(temporary.path()).unwrap();
        let command = temporary.path().join("docker");
        crate::fake_tool::write(
            &command,
            "#!/bin/sh\ncase \"$*\" in\n  *' shimpz-brain') sleep 0.3; echo other ;;\n  *' shimpz-admin') echo other ;;\n  inspect*) exit 1 ;;\nesac\n",
        );
        let engine = Engine::with_docker(command);
        assert_eq!(
            Inventory::inspect(&engine, &paths, StorageProfile::ManagedDisk).unwrap_err(),
            "another Docker container is already named shimpz-brain"
        );
        // With every name free, an empty project and no managed resources are a complete, empty inventory.
        let command = temporary.path().join("docker");
        crate::fake_tool::write(
            &command,
            "#!/bin/sh\ncase \"$*\" in\n  inspect*) exit 1 ;;\nesac\n",
        );
        let inventory = Inventory::inspect(
            &Engine::with_docker(command),
            &paths,
            StorageProfile::ManagedDisk,
        )
        .unwrap();
        assert!(inventory.empty() && inventory.space_id.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn a_batch_fails_closed_unless_each_record_answers_its_own_request() {
        let requested = vec!["n001".to_owned(), "n002".to_owned()];
        let one = format!("{:0<64}|shimpz-space-egress|egress\n", "n001");
        // A missing record, a short identity, or a record for another object each refuse the inspection.
        for map in [
            one.clone(),
            format!("{one}{:0<64}|shimpz-space-egress|egress\n", "n009"),
        ] {
            let (_temporary, engine) = fake_docker(&map);
            assert!(validate_project_networks(&engine, &requested).is_err());
        }
        let short = "n001|shimpz-space-egress|egress\n";
        let (_temporary, engine) = fake_docker(short);
        assert!(validate_project_networks(&engine, &requested[..1]).is_err());
        let volume =
            "shimpz-space-team-storage2|shimpz-space-team-storage2|team_storage|local||||\n";
        let (_temporary, engine) = fake_docker(volume);
        assert!(
            inspect_records(
                &engine,
                &["volume", "inspect"],
                Identity::Name,
                "{{.Name}}",
                &["shimpz-space-team-storage".to_owned()],
                "Compose volume",
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn assistant_containers_carry_a_protocol_assistant_id_label() {
        let space = "space-1";
        let validate = |assistant: &str| {
            let (_temporary, engine) = fake_docker(&format!(
                "{:0<64}|/shimpz-local-team_1-x|1|{PROFILE}|{space}|assistant|team_1|{assistant}\n",
                "c001"
            ));
            validate_dynamic_containers(&engine, space, &["c001".to_owned()])
        };
        for admitted in ["dns-manager", "a-b", &"a".repeat(40)] {
            assert_eq!(validate(admitted), Ok(()), "{admitted}");
        }
        for refused in [
            "DnsManager",
            "dns--manager",
            "a--b",
            "dns-",
            "postgres",
            &"a".repeat(41),
        ] {
            assert!(validate(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn static_services_bind_exact_names_to_responsibility_images() {
        assert_eq!(
            static_service("/shimpz-team", "team"),
            Some(graph::TEAM.package)
        );
        let digest = "a".repeat(64);
        let team = static_service("/shimpz-team", "team").unwrap();
        assert!(team.admits(&format!(
            "ghcr.io/theshimpz/shimpz-team-local@sha256:{digest}"
        )));
        assert!(team.admits(&format!("localhost/shimpz-team-local@sha256:{digest}")));
        assert!(!team.admits(&format!("localhost/shimpz-admin@sha256:{digest}")));
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
