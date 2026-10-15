//! Deterministic Local Space Compose emission.

const TEMPLATE: &str = include_str!("../../contracts/local-space/compose.yaml");
const VOLUME_TOKEN: &str = "{{SHIMPZ_VOLUME_DEFINITIONS}}";
const VOLUME_NOCOPY_TOKEN: &str = "{{SHIMPZ_VOLUME_NOCOPY}}";

use super::release::{self, Package};

/// The Compose project every Local Space member belongs to.
pub(crate) const PROJECT: &str = "shimpz-space";
/// The container port Admin publishes, the only published port of the graph.
pub(crate) const ADMIN_PUBLISHED_PORT: &str = "4600/tcp";
/// The only host address Admin's published port binds.
pub(crate) const ADMIN_PUBLISHED_HOST: &str = "127.0.0.1";

/// One long-running service as the template declares it: its fixed container name, the logical keys of exactly the
/// networks it joins, whether it publishes Admin's port, and the release package its image comes from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Member {
    pub(crate) service: &'static str,
    pub(crate) container: &'static str,
    pub(crate) networks: &'static [&'static str],
    pub(crate) publishes_admin: bool,
    pub(crate) package: Package,
}

pub(crate) const TEAM: Member = Member {
    service: "team",
    container: "shimpz-team",
    networks: &[
        "control",
        "brain_runtime",
        "account_egress",
        "assistant_release",
        "assistant_egress",
    ],
    publishes_admin: false,
    package: release::TEAM,
};
pub(crate) const ASSISTANT_EGRESS: Member = Member {
    service: "shimpz-assistant-egress",
    container: "shimpz-assistant-egress",
    networks: &["assistant_egress", "assistant_egress_out"],
    publishes_admin: false,
    package: release::EGRESS,
};
pub(crate) const ASSISTANT_RELEASE: Member = Member {
    service: "shimpz-assistant-release",
    container: "shimpz-assistant-release",
    networks: &["assistant_release", "assistant_release_out"],
    publishes_admin: false,
    package: release::EGRESS,
};
pub(crate) const ACCOUNT_EGRESS: Member = Member {
    service: "shimpz-account-egress",
    container: "shimpz-account-egress",
    networks: &["account_egress", "account_egress_out"],
    publishes_admin: false,
    package: release::EGRESS,
};
pub(crate) const BRAIN_EGRESS: Member = Member {
    service: "shimpz-brain-egress",
    container: "shimpz-brain-egress",
    networks: &["brain_egress", "brain_egress_out"],
    publishes_admin: false,
    package: release::EGRESS,
};
pub(crate) const BRAIN: Member = Member {
    service: "brain",
    container: "shimpz-brain",
    networks: &["brain_runtime", "brain_egress"],
    publishes_admin: false,
    package: release::BRAIN,
};
pub(crate) const ADMIN: Member = Member {
    service: "admin",
    container: "shimpz-admin",
    networks: &["control", "egress"],
    publishes_admin: true,
    package: release::ADMIN,
};

/// Every long-running service of the graph, in the template's order.
pub(crate) const MEMBERS: [Member; 7] = [
    TEAM,
    ASSISTANT_EGRESS,
    ASSISTANT_RELEASE,
    ACCOUNT_EGRESS,
    BRAIN_EGRESS,
    BRAIN,
    ADMIN,
];

/// The one-shot service that creates or validates the Account egress capability, then exits. It runs the
/// [`ACCOUNT_EGRESS`] image, and its container carries the service's name.
pub(crate) const ACCOUNT_EGRESS_INIT: &str = "shimpz-account-egress-init";

/// The service names of [`MEMBERS`].
pub(crate) const LONG_RUNNING_SERVICES: [&str; 7] = {
    let mut services = [""; 7];
    let mut index = 0;
    while index < MEMBERS.len() {
        services[index] = MEMBERS[index].service;
        index += 1;
    }
    services
};

/// Every fixed container name of the graph: each long-running member's, then the one-shot initializer's.
pub(crate) const CONTAINERS: [&str; 8] = {
    let mut containers = [ACCOUNT_EGRESS_INIT; 8];
    let mut index = 0;
    while index < MEMBERS.len() {
        containers[index] = MEMBERS[index].container;
        index += 1;
    }
    containers
};

/// Every Local Docker network and volume carries this explicit name prefix before its hyphenated logical key, so the
/// Space never relies on Compose's default `<project>_<key>` naming.
const RESOURCE_PREFIX: &str = "shimpz-space-";

/// The logical keys of every Local network, in the template's order.
pub(crate) const NETWORK_NAMES: [&str; 11] = [
    "control",
    "brain_runtime",
    "brain_egress",
    "brain_egress_out",
    "assistant_egress",
    "assistant_egress_out",
    "assistant_release",
    "assistant_release_out",
    "account_egress",
    "account_egress_out",
    "egress",
];

/// One Local volume: its logical name and the exact owner, group, and mode of its directory on encrypted Linux
/// storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Volume {
    pub(crate) name: &'static str,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) mode: u32,
}

const fn volume(name: &'static str, uid: u32, gid: u32, mode: u32) -> Volume {
    Volume {
        name,
        uid,
        gid,
        mode,
    }
}

pub(crate) const VOLUMES: [Volume; 28] = [
    volume("config", 1000, 1000, 0o700),
    volume("data", 1000, 1000, 0o700),
    volume("controller_token", 10001, 10010, 0o2750),
    volume("controller_audit", 10001, 10001, 0o700),
    volume("controller_storage", 10001, 10001, 0o700),
    volume("controller_inference", 10001, 10001, 0o700),
    volume("controller_action_journal", 10001, 10001, 0o700),
    volume("controller_publications", 10001, 10001, 0o700),
    volume("controller_cosign_trust", 10001, 10001, 0o700),
    volume(
        "controller_assistant_integration_state",
        10001,
        10001,
        0o700,
    ),
    volume("controller_assistant_integration_key", 10001, 10001, 0o700),
    volume("controller_chat_continuation_state", 10001, 10001, 0o700),
    volume("controller_chat_continuation_key", 10001, 10001, 0o700),
    volume(
        "controller_assistant_stored_input_state",
        10001,
        10001,
        0o700,
    ),
    volume("controller_assistant_stored_input_key", 10001, 10001, 0o700),
    volume("controller_routine_state", 10001, 10001, 0o700),
    volume("controller_routine_key", 10001, 10001, 0o700),
    volume("supervisor_key", 0, 10021, 0o2770),
    volume("release_status", 1000, 1000, 0o700),
    volume("reset_capability", 1000, 1000, 0o700),
    volume("assistant_egress_policy", 10001, 10017, 0o750),
    volume("assistant_egress_audit", 10005, 10005, 0o700),
    volume("assistant_release_audit", 10004, 10004, 0o700),
    volume("account_egress_capability", 10023, 10022, 0o750),
    volume("account_egress_audit", 10006, 10006, 0o700),
    volume("brain_egress_audit", 10001, 10001, 0o700),
    volume("brain_runtime_token", 10001, 10016, 0o750),
    volume("brain_runtime_state", 10001, 10001, 0o700),
];

pub(crate) const VOLUME_NAMES: [&str; 28] = {
    let mut names = [""; 28];
    let mut index = 0;
    while index < VOLUMES.len() {
        names[index] = VOLUMES[index].name;
        index += 1;
    }
    names
};

/// The disposable Team and Brain runtime state one state epoch covers: a release that reads another stored format
/// of it recreates exactly these volumes empty. Supervisor authentication, Admin data, Team records, Assistant
/// bindings and Integrations, capabilities, policy, and audit are never part of it.
pub(crate) const RUNTIME_STATE_VOLUMES: [&str; 9] = [
    "controller_inference",
    "controller_action_journal",
    "controller_chat_continuation_state",
    "controller_chat_continuation_key",
    "controller_assistant_stored_input_state",
    "controller_assistant_stored_input_key",
    "controller_routine_state",
    "controller_routine_key",
    "brain_runtime_state",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StorageProfile {
    LinuxLuks,
    ManagedDisk,
}

impl StorageProfile {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::LinuxLuks => "linux-luks",
            Self::ManagedDisk => "managed-disk",
        }
    }
}

/// The explicit Docker name of the Local network or volume with logical `key`.
pub(crate) fn resource_name(key: &str) -> String {
    format!("{RESOURCE_PREFIX}{}", key.replace('_', "-"))
}

pub(crate) fn render(profile: StorageProfile) -> String {
    let mut volumes = String::new();
    for name in VOLUME_NAMES {
        volumes.push_str("  ");
        volumes.push_str(name);
        volumes.push_str(":\n    name: ");
        volumes.push_str(&resource_name(name));
        volumes.push('\n');
        if profile == StorageProfile::LinuxLuks {
            volumes.push_str("    driver: local\n");
            volumes.push_str("    driver_opts:\n");
            volumes.push_str("      type: none\n");
            volumes.push_str("      o: bind\n");
            volumes.push_str("      device: ${SHIMPZ_SECURE_VOLUME_ROOT:?CLI must mount encrypted Local storage}/");
            volumes.push_str(name);
            volumes.push('\n');
        }
    }
    TEMPLATE.replace(VOLUME_TOKEN, volumes.trim_end()).replace(
        VOLUME_NOCOPY_TOKEN,
        match profile {
            StorageProfile::LinuxLuks => "true",
            StorageProfile::ManagedDisk => "false",
        },
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_norway::Value;

    use super::*;

    #[test]
    fn emits_one_complete_graph_for_each_storage_profile() {
        for profile in [StorageProfile::LinuxLuks, StorageProfile::ManagedDisk] {
            let graph = render(profile);
            assert!(graph.starts_with("name: ${SHIMPZ_PROJECT_NAME"));
            assert!(!graph.contains(VOLUME_TOKEN));
            assert!(!graph.contains(VOLUME_NOCOPY_TOKEN));
            assert_eq!(graph.matches("container_name:").count(), 8);
            assert_eq!(graph.matches("    driver: none").count(), 8);
            for volume in VOLUME_NAMES {
                assert!(graph.contains(&format!("  {volume}:\n")));
            }
        }
        assert_eq!(StorageProfile::LinuxLuks.name(), "linux-luks");
        assert_eq!(StorageProfile::ManagedDisk.name(), "managed-disk");
    }

    #[test]
    fn volume_directories_never_admit_other_users() {
        for volume in VOLUMES {
            assert_eq!(volume.mode & 0o007, 0, "{}", volume.name);
            assert_eq!(volume.mode & !0o7777, 0, "{}", volume.name);
        }
        for expected in [
            volume("controller_token", 10001, 10010, 0o2750),
            volume("supervisor_key", 0, 10021, 0o2770),
            volume("assistant_egress_policy", 10001, 10017, 0o750),
            volume("account_egress_capability", 10023, 10022, 0o750),
        ] {
            assert!(VOLUMES.contains(&expected), "{}", expected.name);
        }
    }

    #[test]
    fn names_every_network_and_volume_explicitly_for_each_storage_profile() {
        assert_eq!(resource_name("data"), "shimpz-space-data");
        assert_eq!(
            resource_name("controller_token"),
            "shimpz-space-controller-token"
        );
        for profile in [StorageProfile::LinuxLuks, StorageProfile::ManagedDisk] {
            let graph: Value = serde_norway::from_str(&render(profile)).unwrap();
            let mut names = BTreeSet::new();
            for (section, keys) in [
                ("networks", &NETWORK_NAMES[..]),
                ("volumes", &VOLUME_NAMES[..]),
            ] {
                let declared = graph[section].as_mapping().unwrap();
                let declared_keys: BTreeSet<_> =
                    declared.keys().map(|key| key.as_str().unwrap()).collect();
                assert_eq!(declared_keys, keys.iter().copied().collect());
                for (key, definition) in declared {
                    let name = definition["name"].as_str().unwrap();
                    assert_eq!(name, resource_name(key.as_str().unwrap()));
                    assert!(names.insert(name.to_owned()), "{name}");
                }
            }
        }
    }

    #[test]
    fn the_graph_holds_exactly_the_init_and_the_long_running_services() {
        let graph: Value = serde_norway::from_str(&render(StorageProfile::LinuxLuks)).unwrap();
        let services: BTreeSet<_> = graph["services"]
            .as_mapping()
            .unwrap()
            .keys()
            .map(|key| key.as_str().unwrap().to_owned())
            .collect();
        let expected: BTreeSet<_> = LONG_RUNNING_SERVICES
            .iter()
            .chain([&ACCOUNT_EGRESS_INIT])
            .map(|name| (*name).to_owned())
            .collect();
        assert_eq!(services, expected);
        assert_eq!(
            graph["services"][ACCOUNT_EGRESS_INIT]["restart"].as_str(),
            Some("no")
        );
    }

    #[test]
    fn the_member_table_is_exactly_the_templates_names_networks_and_published_port() {
        for profile in [StorageProfile::LinuxLuks, StorageProfile::ManagedDisk] {
            let graph: Value = serde_norway::from_str(&render(profile)).unwrap();
            let services = graph["services"].as_mapping().unwrap();
            let declared: Vec<_> = services
                .keys()
                .map(|key| key.as_str().unwrap())
                .filter(|service| *service != ACCOUNT_EGRESS_INIT)
                .collect();
            assert_eq!(declared, LONG_RUNNING_SERVICES);
            assert_eq!(
                graph["services"][ACCOUNT_EGRESS_INIT]["network_mode"],
                "none"
            );
            assert!(
                graph["services"][ACCOUNT_EGRESS_INIT]
                    .get("ports")
                    .is_none()
            );
            for member in MEMBERS {
                let service = &graph["services"][member.service];
                assert_eq!(service["container_name"], member.container);
                let networks: Vec<_> = service["networks"]
                    .as_sequence()
                    .unwrap()
                    .iter()
                    .map(|network| network.as_str().unwrap())
                    .collect();
                assert_eq!(networks, member.networks, "{}", member.service);
                let ports = service.get("ports").map(|ports| {
                    ports
                        .as_sequence()
                        .unwrap()
                        .iter()
                        .map(|port| port.as_str().unwrap().to_owned())
                        .collect::<Vec<_>>()
                });
                let published = member.publishes_admin.then(|| {
                    vec![format!(
                        "{ADMIN_PUBLISHED_HOST}:${{SHIMPZ_PORT:-7777}}:{}",
                        ADMIN_PUBLISHED_PORT.strip_suffix("/tcp").unwrap()
                    )]
                });
                assert_eq!(ports, published, "{}", member.service);
            }
        }
    }

    #[test]
    fn only_linux_binds_volumes_to_the_encrypted_pool() {
        let linux = render(StorageProfile::LinuxLuks);
        let managed = render(StorageProfile::ManagedDisk);
        assert_eq!(linux.matches("      o: bind").count(), VOLUME_NAMES.len());
        assert_eq!(
            linux.matches("${SHIMPZ_SECURE_VOLUME_ROOT").count(),
            VOLUME_NAMES.len()
        );
        assert!(!managed.contains("      o: bind"));
        assert!(!managed.contains("SHIMPZ_SECURE_VOLUME_ROOT"));
        assert_eq!(linux.matches("        nocopy: true").count(), 34);
        assert_eq!(managed.matches("        nocopy: false").count(), 34);
        assert!(!linux.contains("        nocopy: false"));
        assert!(!managed.contains("        nocopy: true"));
    }

    #[test]
    fn scopes_volume_population_to_the_storage_owner() {
        for (profile, expected_nocopy) in [
            (StorageProfile::LinuxLuks, true),
            (StorageProfile::ManagedDisk, false),
        ] {
            let document: Value = serde_norway::from_str(&render(profile)).unwrap();
            let services = document["services"].as_mapping().unwrap();
            let mut sources = BTreeSet::new();
            let mut mount_count = 0;
            let mut socket_count = 0;
            for service in services.values() {
                for mount in service["volumes"].as_sequence().unwrap() {
                    let mount_type = mount["type"].as_str().unwrap();
                    assert!(["volume", "bind"].contains(&mount_type));
                    if mount_type == "volume" {
                        mount_count += 1;
                        sources.insert(mount["source"].as_str().unwrap());
                        assert_eq!(mount["volume"]["nocopy"].as_bool(), Some(expected_nocopy));
                    } else {
                        socket_count += 1;
                        assert_eq!(mount["target"].as_str(), Some("/var/run/docker.sock"));
                        assert_eq!(mount["bind"]["create_host_path"].as_bool(), Some(false));
                        assert!(mount.get("volume").is_none());
                    }
                }
            }
            assert_eq!(mount_count, 34);
            assert_eq!(socket_count, 1);
            assert_eq!(sources, VOLUME_NAMES.into_iter().collect::<BTreeSet<_>>());
        }
    }
}
