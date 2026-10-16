//! The Local Space home: its private directory, adopting a home that has no marker yet, the reporting of entries the
//! Local contract does not own, and the removal of managed regular files.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::output;
use crate::space::paths::{self, Paths};
use crate::space::state;

use super::cli_binary::validate_managed_bin;
use super::io_error;

const INVALID_MANAGED_FILE: &str = "refusing to remove invalid managed file";

const REPORTED_ENTRIES: usize = 8;

#[derive(Default)]
pub(super) struct PathReport {
    named: Vec<PathBuf>,
    total: usize,
}

impl PathReport {
    pub(super) fn record(&mut self, path: PathBuf) {
        self.total += 1;
        let index = self
            .named
            .binary_search(&path)
            .unwrap_or_else(|index| index);
        self.named.insert(index, path);
        self.named.truncate(REPORTED_ENTRIES);
    }

    pub(super) fn is_empty(&self) -> bool {
        self.total == 0
    }

    pub(super) fn render(&self) -> String {
        let mut rendered = self
            .named
            .iter()
            .map(|path| output::sanitize_inline(&path.to_string_lossy()))
            .collect::<Vec<_>>()
            .join(", ");
        if self.total > self.named.len() {
            use std::fmt::Write as _;
            write!(
                &mut rendered,
                ", and {} more",
                self.total - self.named.len()
            )
            .expect("String writes are infallible");
        }
        rendered
    }

    pub(super) fn into_strings(self) -> Vec<String> {
        let hidden = self.total.saturating_sub(self.named.len());
        let mut rendered = self
            .named
            .into_iter()
            .map(|path| output::sanitize_inline(&path.to_string_lossy()))
            .collect::<Vec<_>>();
        if hidden > 0 {
            rendered.push(format!("and {hidden} more unrecognized entries"));
        }
        rendered
    }
}

pub(super) fn validate_install_home(paths: &Paths) -> Result<(), String> {
    if paths.home.exists() {
        validate_existing_install_home(paths)?;
    } else {
        fs::create_dir(&paths.home).map_err(io_error)?;
        fs::set_permissions(&paths.home, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    Ok(())
}

pub(super) fn validate_existing_install_home(paths: &Paths) -> Result<(), String> {
    if !paths.home.exists() {
        return Ok(());
    }
    let metadata = paths.home.symlink_metadata().map_err(io_error)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("refusing to use an invalid Local Space directory".into());
    }
    Ok(())
}

pub(super) fn adopt_unmarked_home(paths: &Paths) -> Result<(), String> {
    state::clear_stopped(paths)?;
    for temporary in [
        paths.release_copy.clone(),
        paths.marker.with_extension("tmp"),
    ] {
        remove_regular_if_present(&temporary)?;
    }
    let unowned = unmarked_runtime_entries(paths)?;
    if !unowned.is_empty() {
        return Err(format!(
            "refusing to use unowned Local Space entries under {}: {}; move or remove every unowned entry, then run shimpz install",
            paths.home.display(),
            unowned.render()
        ));
    }
    validate_managed_bin(paths)
}

pub(super) fn unmarked_runtime_entries(paths: &Paths) -> Result<PathReport, String> {
    let mut entries = PathReport::default();
    if !paths.home.exists() {
        return Ok(entries);
    }
    let bin = paths.managed_bin();
    for entry in fs::read_dir(&paths.home).map_err(io_error)? {
        let path = entry.map_err(io_error)?.path();
        if path != bin {
            entries.record(path);
        }
    }
    Ok(entries)
}

pub(super) fn remove_regular_if_present(path: &Path) -> Result<(), String> {
    paths::remove_regular_if_present(path, INVALID_MANAGED_FILE, io_error)
}

pub(super) fn validate_regular_if_present(path: &Path) -> Result<bool, String> {
    paths::regular_file_present(path, INVALID_MANAGED_FILE, io_error)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::super::cli_binary::validate_private_cli;
    use super::*;

    #[test]
    fn unmarked_home_accepts_only_private_managed_cli_artifacts() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        fs::set_permissions(&paths.home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(paths.managed_cli.parent().unwrap()).unwrap();
        fs::write(paths.managed_cli.with_extension("candidate"), "candidate").unwrap();
        fs::set_permissions(
            paths.managed_cli.with_extension("candidate"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        validate_install_home(&paths).unwrap();
        assert!(adopt_unmarked_home(&paths).is_ok());
        let foreign = paths.managed_cli.parent().unwrap().join("foreign");
        fs::write(&foreign, "foreign").unwrap();
        let error = adopt_unmarked_home(&paths).unwrap_err();
        assert!(error.contains(&foreign.display().to_string()));
    }

    #[test]
    fn unmarked_home_reconciles_only_pre_marker_temporaries() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        fs::set_permissions(&paths.home, fs::Permissions::from_mode(0o700)).unwrap();
        let release_temporary = paths.release_copy.clone();
        let marker_temporary = paths.marker.with_extension("tmp");
        fs::write(&release_temporary, "metadata").unwrap();
        fs::write(&marker_temporary, "marker").unwrap();
        state::write_stopped(&paths).unwrap();
        validate_install_home(&paths).unwrap();
        assert_eq!(unmarked_runtime_entries(&paths).unwrap().total, 3);
        adopt_unmarked_home(&paths).unwrap();
        assert!(!release_temporary.exists());
        assert!(!marker_temporary.exists());
        assert!(!paths.stopped.exists());
        assert!(unmarked_runtime_entries(&paths).unwrap().is_empty());
    }

    #[test]
    fn absent_unmarked_home_has_no_runtime_residue() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();

        assert!(unmarked_runtime_entries(&paths).unwrap().is_empty());
    }

    #[test]
    fn unmarked_home_names_the_exact_unowned_entry() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        fs::set_permissions(&paths.home, fs::Permissions::from_mode(0o700)).unwrap();
        let unowned = paths.home.join("unexpected");
        fs::write(&unowned, "not owned by the Local contract").unwrap();

        validate_install_home(&paths).unwrap();
        let error = adopt_unmarked_home(&paths).unwrap_err();

        assert!(error.contains(&unowned.display().to_string()));
        assert!(error.contains("move or remove every unowned entry"));
    }

    #[test]
    fn private_home_validation_allows_reset_to_preserve_unowned_entries() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        fs::set_permissions(&paths.home, fs::Permissions::from_mode(0o700)).unwrap();
        let unowned = paths.home.join("preserved");
        fs::write(&unowned, "not owned by the Local contract").unwrap();

        validate_install_home(&paths).unwrap();

        assert!(unowned.exists());
        assert!(adopt_unmarked_home(&paths).is_err());
    }

    #[test]
    fn unowned_entry_reporting_is_bounded_and_deterministic() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir(&paths.home).unwrap();
        fs::set_permissions(&paths.home, fs::Permissions::from_mode(0o700)).unwrap();
        for index in (0..10).rev() {
            fs::write(paths.home.join(format!("unexpected-{index:02}")), "foreign").unwrap();
        }

        let error = adopt_unmarked_home(&paths).unwrap_err();

        for index in 0..8 {
            assert!(error.contains(&format!("unexpected-{index:02}")));
        }
        assert!(!error.contains("unexpected-08"));
        assert!(!error.contains("unexpected-09"));
        assert!(error.contains("and 2 more"));
    }

    #[test]
    fn managed_cli_validation_names_invalid_artifacts() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path()).unwrap();
        fs::create_dir_all(paths.managed_cli.parent().unwrap()).unwrap();
        fs::write(&paths.managed_cli, "managed").unwrap();
        fs::set_permissions(&paths.managed_cli, fs::Permissions::from_mode(0o755)).unwrap();

        let admission_error = adopt_unmarked_home(&paths).unwrap_err();
        let private_error = validate_private_cli(&paths.managed_cli).unwrap_err();

        for error in [admission_error, private_error] {
            assert!(error.contains(&paths.managed_cli.display().to_string()));
        }
    }
}
