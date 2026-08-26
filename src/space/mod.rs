//! Complete Local Space lifecycle.

pub(crate) mod command;
pub(crate) mod docker;
pub(crate) mod graph;
pub(crate) mod host;
#[cfg(unix)]
pub(crate) mod lifecycle;
#[cfg(not(unix))]
pub(crate) mod lifecycle {
    //! Native Windows retains Creator operations; Local Space runs inside WSL2.

    use crate::args::{GraphProfile, SpaceInstall, SpaceReset, SpaceStart};

    use super::graph::{self, StorageProfile};

    pub(crate) fn install(options: &SpaceInstall) -> Result<String, String> {
        match options.print_graph {
            Some(GraphProfile::LinuxLuks) => Ok(graph::render(StorageProfile::LinuxLuks)),
            Some(GraphProfile::ManagedDisk) => Ok(graph::render(StorageProfile::ManagedDisk)),
            None => unsupported(),
        }
    }

    pub(crate) fn start(_options: &SpaceStart) -> Result<String, String> {
        unsupported()
    }

    pub(crate) fn status() -> Result<String, String> {
        unsupported()
    }

    pub(crate) fn stop() -> Result<String, String> {
        unsupported()
    }

    pub(crate) fn update() -> Result<String, String> {
        unsupported()
    }

    pub(crate) fn reset(_options: &SpaceReset) -> Result<String, String> {
        unsupported()
    }

    fn unsupported<T>() -> Result<T, String> {
        Err("Local Space on Windows must run inside WSL2 with systemd".into())
    }
}
pub(crate) mod paths;
pub(crate) mod release;
pub(crate) mod resources;
#[cfg(unix)]
pub(crate) mod scheduler;
#[cfg(unix)]
pub(crate) mod state;
#[cfg(unix)]
mod status;
pub(crate) mod storage;
