//! Deterministic Local Space Compose emission.

const TEMPLATE: &str = include_str!("../../contracts/local-space/compose.yaml");
const VOLUME_TOKEN: &str = "{{SHIMPZ_VOLUME_DEFINITIONS}}";
const VOLUME_NOCOPY_TOKEN: &str = "{{SHIMPZ_VOLUME_NOCOPY}}";

pub(crate) const VOLUME_NAMES: [&str; 23] = [
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
    "supervisor_key",
    "release_status",
    "assistant_egress_policy",
    "assistant_egress_audit",
    "assistant_release_audit",
    "account_egress_capability",
    "account_egress_audit",
    "brain_egress_audit",
    "brain_runtime_token",
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

pub(crate) fn render(profile: StorageProfile) -> String {
    let mut volumes = String::new();
    for name in VOLUME_NAMES {
        volumes.push_str("  ");
        volumes.push_str(name);
        volumes.push_str(":\n");
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

    use serde_yaml::Value;

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
        assert_eq!(linux.matches("        nocopy: true").count(), 29);
        assert_eq!(managed.matches("        nocopy: false").count(), 29);
        assert!(!linux.contains("        nocopy: false"));
        assert!(!managed.contains("        nocopy: true"));
    }

    #[test]
    fn scopes_volume_population_to_the_storage_owner() {
        for (profile, expected_nocopy) in [
            (StorageProfile::LinuxLuks, true),
            (StorageProfile::ManagedDisk, false),
        ] {
            let document: Value = serde_yaml::from_str(&render(profile)).unwrap();
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
                        assert!(mount.get("volume").is_none());
                    }
                }
            }
            assert_eq!(mount_count, 29);
            assert_eq!(socket_count, 1);
            assert_eq!(sources, VOLUME_NAMES.into_iter().collect::<BTreeSet<_>>());
        }
    }
}
