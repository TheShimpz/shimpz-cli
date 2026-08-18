//! Deterministic Local Space Compose emission.

const TEMPLATE: &str = include_str!("../../contracts/local-space/compose.yaml");
const VOLUME_TOKEN: &str = "{{SHIMPZ_VOLUME_DEFINITIONS}}";

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
    TEMPLATE.replace(VOLUME_TOKEN, volumes.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_one_complete_graph_for_each_storage_profile() {
        for profile in [StorageProfile::LinuxLuks, StorageProfile::ManagedDisk] {
            let graph = render(profile);
            assert!(graph.starts_with("name: ${SHIMPZ_PROJECT_NAME"));
            assert!(!graph.contains(VOLUME_TOKEN));
            assert_eq!(graph.matches("container_name:").count(), 8);
            assert_eq!(graph.matches("    driver: none").count(), 8);
            for volume in VOLUME_NAMES {
                assert!(graph.contains(&format!("  {volume}:\n")));
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
    }
}
