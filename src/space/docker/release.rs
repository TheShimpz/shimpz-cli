//! The signed Local release set: resolving and verifying it, pulling its exact images, and copying the release-bound
//! CLI out of it.

use std::ffi::OsString;
use std::fs::{self, Metadata};
use std::path::Path;
use std::process::ExitStatus;

use super::{DOCKER_PULL, Engine, ResolvedRelease};
use crate::digest;
use crate::private_file::{self, ReadFailure};
use crate::space::command::one_line;
use crate::space::host::HostProfile;
use crate::space::release::{self, DEVELOPER_RELEASE_REPOSITORY, Package, RELEASE_REPOSITORY};

const RELEASE_CHANNEL: &str = "stable";

/// The key a published release set must be signed with: the published pin, or the key the test build generates.
#[cfg(not(test))]
fn release_key() -> &'static str {
    release::PUBLISHED_SIGNING_KEY
}

#[cfg(test)]
fn release_key() -> &'static str {
    release::test_signing::public_key()
}

/// The largest release metadata document a set may carry.
const MAX_RELEASE_METADATA_BYTES: u64 = 2_048;

/// Whether `path` is itself a regular file, not a link, directory, FIFO, or device.
fn regular_file(path: &Path) -> bool {
    path.symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_file())
}

/// Read copied release metadata only when it is a regular file of bounded size, admitted through the open handle.
fn read_metadata(path: &Path) -> Result<String, String> {
    private_file::read_admitted(path, MAX_RELEASE_METADATA_BYTES, Metadata::is_file).map_err(
        |failure| match failure {
            ReadFailure::Link | ReadFailure::NotAdmitted | ReadFailure::Inspect(_) => {
                "the Local release metadata is not a regular file".to_owned()
            }
            ReadFailure::Oversized => "the Local release metadata is malformed".to_owned(),
            ReadFailure::Open(error) | ReadFailure::Read(error) => {
                format!("could not read Local release metadata: {error}")
            }
        },
    )
}

/// The inspected image holds exactly `reference` among its repository digests and runs on `platform`.
pub(super) fn image_present(
    document: &str,
    reference: &str,
    repository: &str,
    platform: &str,
) -> bool {
    let Some((digests, image_platform)) = document.trim_end().rsplit_once('|') else {
        return false;
    };
    let Ok(digests) = serde_json::from_str::<Vec<String>>(digests) else {
        return false;
    };
    digest::is_pinned(reference, repository)
        && image_platform == platform
        && digests.iter().any(|value| value == reference)
}

/// The outcomes of copying one release member out through a temporary container: the copy and the container's
/// removal, each run whatever the other's outcome.
struct MemberCopy {
    copied: Result<ExitStatus, String>,
    removed: Result<ExitStatus, String>,
}

impl Engine {
    pub(crate) fn resolve_release(
        &self,
        exact: Option<&str>,
        temporary: &Path,
    ) -> Result<ResolvedRelease, String> {
        let selector = match exact {
            Some(reference) if release::valid_release_ref(reference) => reference.to_owned(),
            Some(_) => return Err("the internal Local release reference is invalid".into()),
            None => format!("{RELEASE_REPOSITORY}:{RELEASE_CHANNEL}"),
        };
        // A developer release set exists only in this host's image store and is never pulled; an exact published
        // set already present by that digest is content-addressed and needs no download.
        if release::valid_developer_release_ref(&selector) {
            self.require_present(&selector, DEVELOPER_RELEASE_REPOSITORY)?;
        } else if exact.is_none() || !self.present(&selector, RELEASE_REPOSITORY) {
            self.pull(&selector)?;
        }
        let reference = if exact.is_some() {
            selector
        } else {
            self.unique_repo_digest(&selector, RELEASE_REPOSITORY)?
        };
        if !release::valid_release_ref(&reference) {
            return Err("Docker resolved an invalid Local release digest".into());
        }
        let metadata_path = temporary.join("release.env.tmp");
        let MemberCopy { copied, removed } = self.copy_member(
            &reference,
            "/release.env",
            &metadata_path,
            "Docker release metadata copy",
        )?;
        // The temporary metadata is read, if it was copied, and removed whatever else failed, so no exit leaves it.
        let copied = copied.map(|status| status.success());
        let document = match copied {
            Ok(true) => Some(read_metadata(&metadata_path)),
            _ => None,
        };
        let cleaned = match fs::remove_file(&metadata_path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(format!(
                "could not remove temporary release metadata: {error}"
            )),
            _ => Ok(()),
        };
        let failure = match (copied, removed) {
            (Ok(true), Ok(removed)) if removed.success() => None,
            (Err(error), _) | (_, Err(error)) => Some(error),
            _ => Some("the Local release metadata could not be extracted cleanly".to_owned()),
        };
        if let Some(failure) = failure {
            return Err(match cleaned {
                Ok(()) => failure,
                Err(cleanup) => format!("{failure}; {cleanup}"),
            });
        }
        let document = match (
            document.unwrap_or_else(|| Err("Local release metadata was not copied".into())),
            cleaned,
        ) {
            (Ok(document), Ok(())) => document,
            (Err(error), Ok(())) | (Ok(_), Err(error)) => return Err(error),
            (Err(error), Err(cleanup)) => return Err(format!("{error}; {cleanup}")),
        };
        let labels = self.run_output([
            "image",
            "inspect",
            "--format",
            &format!(
                "{{{{index .Config.Labels \"{}\"}}}}|{{{{index .Config.Labels \"{}\"}}}}",
                release::STATE_EPOCH_LABEL,
                release::SIGNATURE_LABEL
            ),
            &reference,
        ])?;
        let (state_epoch, signature) = labels
            .trim_end_matches('\n')
            .split_once('|')
            .ok_or_else(|| "Docker returned invalid Local release labels".to_owned())?;
        let metadata =
            release::parse(&reference, &document, state_epoch, signature, release_key())?;
        Ok(ResolvedRelease {
            reference,
            metadata,
        })
    }

    pub(crate) fn extract_cli(
        &self,
        release_ref: &str,
        profile: HostProfile,
        target: &Path,
    ) -> Result<(), String> {
        // A developer release carries only the amd64 Linux CLI and applies only to an amd64 Linux Space.
        let developer = release::valid_developer_release_ref(release_ref);
        if !(release::valid_published_release_ref(release_ref)
            || developer && profile != HostProfile::MacOs)
        {
            return Err("the Local release reference is invalid".into());
        }
        let member = match profile {
            HostProfile::Linux | HostProfile::Wsl => "/cli/x86_64-unknown-linux-musl/shimpz",
            HostProfile::MacOs => "/cli/aarch64-apple-darwin/shimpz",
        };
        let MemberCopy { copied, removed } =
            self.copy_member(release_ref, member, target, "Docker CLI copy")?;
        if !copied?.success() || !removed?.success() {
            return Err("the release-bound CLI could not be extracted cleanly".into());
        }
        // An unsigned image wrapping signed metadata chooses the member's file type: only a regular file is kept, so
        // nothing later changes the mode of, hashes, or runs what a link names.
        if regular_file(target) {
            Ok(())
        } else {
            fs::remove_file(target).map_err(|error| {
                format!("could not remove the invalid release-bound CLI copy: {error}")
            })?;
            Err("the release-bound CLI is not a regular file".into())
        }
    }

    /// Make one release member available by its exact digest: a developer member must already be in this host's
    /// image store and is never pulled; a published member is pulled unless the store already holds exactly that
    /// digest for this Space's platform, since the digest names the content.
    pub(crate) fn pull_exact(&self, reference: &str, package: Package) -> Result<(), String> {
        let repository = reference.split_once('@').map_or("", |(name, _)| name);
        if package.developer(reference) {
            return self.require_present(reference, repository);
        }
        if !package.published(reference) {
            return Err("a release component image reference is invalid".into());
        }
        if self.present(reference, repository) {
            return Ok(());
        }
        self.pull(reference)?;
        let actual = self.unique_repo_digest(reference, repository)?;
        if actual == reference {
            Ok(())
        } else {
            Err("Docker did not preserve the pinned component digest".into())
        }
    }

    /// Admit a `localhost/` image only when this daemon's store already holds exactly that manifest digest for
    /// this Space's platform. Absence fails closed; nothing is pulled.
    fn require_present(&self, reference: &str, repository: &str) -> Result<(), String> {
        if self.present(reference, repository) {
            Ok(())
        } else {
            Err(format!(
                "the developer release image {reference} is not in the local Docker image store; assemble it again with .scripts/local-release/deploy, or install the published release with shimpz install"
            ))
        }
    }

    /// Whether this daemon's store holds exactly `reference` as a repository digest for this Space's platform.
    pub(super) fn present(&self, reference: &str, repository: &str) -> bool {
        self.run_output([
            "image",
            "inspect",
            "--format",
            "{{json .RepoDigests}}|{{.Os}}/{{.Architecture}}",
            reference,
        ])
        .is_ok_and(|document| image_present(&document, reference, repository, self.platform))
    }

    pub(super) fn pull(&self, reference: &str) -> Result<(), String> {
        let result = self.run_quiet_status_within(
            "Docker image download",
            DOCKER_PULL,
            ["pull", "--quiet", "--platform", self.platform, reference],
        )?;
        if result.success() {
            Ok(())
        } else {
            Err(format!(
                "Docker could not pull the pinned image: {reference}"
            ))
        }
    }

    /// Copy the file at `member` out of `reference` to `target` through a temporary container created to run only
    /// that path, and remove the container whether or not the copy succeeded. Returns the copy's and the removal's
    /// outcomes for the caller to judge; only a failed create is an error here.
    fn copy_member(
        &self,
        reference: &str,
        member: &str,
        target: &Path,
        operation: &str,
    ) -> Result<MemberCopy, String> {
        // The image was resolved or admitted just before; a create must never fetch it.
        let created = self.run_output([
            "create",
            "--pull",
            "never",
            "--platform",
            self.platform,
            reference,
            member,
        ])?;
        let container = one_line(&created, "temporary Docker container")?;
        let copied = self.run_quiet_status(
            operation,
            [
                OsString::from("cp"),
                OsString::from(format!("{container}:{member}")),
                target.as_os_str().to_owned(),
            ],
        );
        let removed = self.run_quiet_status(
            "Docker temporary container cleanup",
            ["rm", "--volumes", container],
        );
        Ok(MemberCopy { copied, removed })
    }

    fn unique_repo_digest(&self, image: &str, repository: &str) -> Result<String, String> {
        let document = self.run_output([
            "image",
            "inspect",
            "--format",
            "{{json .RepoDigests}}",
            image,
        ])?;
        let digests: Vec<String> = serde_json::from_str(document.trim())
            .map_err(|_| "Docker returned malformed image digests".to_owned())?;
        let mut matching = digests
            .into_iter()
            .filter(|value| digest::is_pinned(value, repository));
        let first = matching
            .next()
            .ok_or_else(|| "Docker returned no repository digest".to_owned())?;
        if matching.next().is_some() {
            return Err("Docker returned ambiguous repository digests".into());
        }
        Ok(first)
    }
}
