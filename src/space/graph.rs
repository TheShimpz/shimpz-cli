//! Deterministic Local Space Compose emission.

const TEMPLATE: &str = include_str!("../../contracts/local-space/compose.yaml");
const VOLUME_TOKEN: &str = "{{SHIMPZ_VOLUME_DEFINITIONS}}";
const VOLUME_NOCOPY_TOKEN: &str = "{{SHIMPZ_VOLUME_NOCOPY}}";

/// The one-shot service that creates or validates the Account egress capability, then exits.
pub(crate) const ACCOUNT_EGRESS_INIT: &str = "shimpz-account-egress-init";
/// Every long-running service of the graph, in the template's order.
pub(crate) const LONG_RUNNING_SERVICES: [&str; 7] = [
    "team",
    "shimpz-assistant-egress",
    "shimpz-assistant-release",
    "shimpz-account-egress",
    "shimpz-brain-egress",
    "brain",
    "admin",
];

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

pub(crate) const VOLUME_NAMES: [&str; 28] = [
    "config",
    "data",
    "controller_token",
    "controller_audit",
    "controller_storage",
    "controller_inference",
    "controller_action_journal",
    "controller_publications",
    "controller_cosign_trust",
    "controller_assistant_integration_state",
    "controller_assistant_integration_key",
    "controller_chat_continuation_state",
    "controller_chat_continuation_key",
    "controller_assistant_stored_input_state",
    "controller_assistant_stored_input_key",
    "controller_routine_state",
    "controller_routine_key",
    "supervisor_key",
    "release_status",
    "reset_capability",
    "assistant_egress_policy",
    "assistant_egress_audit",
    "assistant_release_audit",
    "account_egress_capability",
    "account_egress_audit",
    "brain_egress_audit",
    "brain_runtime_token",
    "brain_runtime_state",
];

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
