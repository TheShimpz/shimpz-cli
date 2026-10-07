//! The deploy pipeline's request to apply one developer release, and its acknowledged result.
//!
//! `.scripts/local-release/deploy` writes one private request naming one developer release set in this host's image
//! store, then starts the owner's scheduled reconciliation. That run claims the request under the lifecycle lock,
//! applies exactly that release through the ordinary start path, health gate, and rollback, records one result
//! carrying the request's identity, and only then consumes the request. The pipeline never replaces a pending request.

use std::fs;
use std::os::unix::fs::MetadataExt;

use serde_json::json;

use super::paths::Paths;
use super::release;
use super::state;
use crate::digest;

const MAX_REQUEST_BYTES: u64 = 256;

/// One claimed request: its identity, the developer release set it names, and its exact bytes.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Request {
    pub(crate) id: String,
    pub(crate) release: String,
    document: String,
}

/// What a claimed request ended as.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    /// The named release is installed and its successful reconciliation is recorded.
    Applied,
    /// The run waited for active work; the request stays for the next run.
    Deferred,
    /// The run refused or rolled back; the message says why.
    Failed,
}

impl Outcome {
    fn name(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Deferred => "deferred",
            Self::Failed => "failed",
        }
    }
}

/// Read the pending request, if any. A malformed request this user owns is removed, so it cannot block later
/// reconciliation; anything else at that path is refused and kept.
pub(crate) fn claim(paths: &Paths) -> Result<Option<Request>, String> {
    let document = match state::read_private_record(
        &paths.deploy_request,
        MAX_REQUEST_BYTES,
        "the deploy request",
    ) {
        Ok(Some(document)) => document,
        Ok(None) => return Ok(None),
        Err(error) => {
            let owned = fs::symlink_metadata(&paths.deploy_request).is_ok_and(|metadata| {
                metadata.is_file() && metadata.uid() == rustix::process::geteuid().as_raw()
            });
            if owned {
                remove(paths)?;
                return Err(format!("{error}; the deploy request was discarded"));
            }
            return Err(error);
        }
    };
    if let Some(request) = parse(&document) {
        return Ok(Some(request));
    }
    remove_if_unchanged(paths, &document)?;
    Err("the deploy request was malformed and was discarded".into())
}

fn parse(document: &str) -> Option<Request> {
    let values = release::key_values(document, MAX_REQUEST_BYTES, "").ok()?;
    let id = *values.get("id")?;
    let release = *values.get("release")?;
    (values.len() == 2
        && document.ends_with('\n')
        && digest::is_lower_hex(id, 32)
        && release::valid_developer_release_ref(release))
    .then(|| Request {
        id: id.to_owned(),
        release: release.to_owned(),
        document: document.to_owned(),
    })
}

/// Record the result of a claimed request, then consume it unless it was deferred. The deploy pipeline never
/// replaces a pending request, so the request removed here is still the claimed one; a crash between the two writes
/// leaves the request pending, and the next run applies the same release again.
pub(crate) fn finish(
    paths: &Paths,
    request: &Request,
    outcome: Outcome,
    message: &str,
) -> Result<(), String> {
    let result = json!({
        "id": request.id,
        "release": request.release,
        "outcome": outcome.name(),
        "message": message,
    });
    state::write_private(&paths.deploy_result, &format!("{result}\n"))?;
    if outcome == Outcome::Deferred {
        return Ok(());
    }
    remove_if_unchanged(paths, &request.document)
}

/// Remove the request only while it still holds exactly the claimed bytes.
fn remove_if_unchanged(paths: &Paths, document: &str) -> Result<(), String> {
    let current = state::read_private_record(
        &paths.deploy_request,
        MAX_REQUEST_BYTES,
        "the deploy request",
    );
    if matches!(current, Ok(Some(ref value)) if value == document) {
        remove(paths)?;
    }
    Ok(())
}

fn remove(paths: &Paths) -> Result<(), String> {
    fs::remove_file(&paths.deploy_request)
        .and_then(|()| crate::private_file::sync_parent(&paths.deploy_request))
        .map_err(|error| format!("could not remove the deploy request: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn developer_ref() -> String {
        format!(
            "{}@sha256:{}",
            release::DEVELOPER_RELEASE_REPOSITORY,
            "d".repeat(64)
        )
    }

    fn request_document() -> String {
        format!("id={ID}\nrelease={}\n", developer_ref())
    }

    fn paths() -> (tempfile::TempDir, Paths) {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir_all(directory.path().join(".shimpz")).unwrap();
        let paths = Paths::under(directory.path()).unwrap();
        (directory, paths)
    }

    #[test]
    fn claims_exactly_one_private_request_for_a_developer_release() {
        let (_home, paths) = paths();
        assert_eq!(claim(&paths), Ok(None));
        state::write_private(&paths.deploy_request, &request_document()).unwrap();
        let request = claim(&paths).unwrap().unwrap();
        assert_eq!(
            (request.id.as_str(), request.release.clone()),
            (ID, developer_ref())
        );
    }

    #[test]
    fn discards_a_malformed_request() {
        let published = format!("{}@sha256:{}", release::RELEASE_REPOSITORY, "a".repeat(64));
        for invalid in [
            request_document().replace(ID, "0123"),
            request_document().replace(ID, &ID.to_uppercase()),
            request_document().replace(&developer_ref(), &published),
            format!("{}extra=1\n", request_document()),
            request_document().trim_end().to_owned(),
            format!("release={}\n", developer_ref()),
        ] {
            let (_home, paths) = paths();
            state::write_private(&paths.deploy_request, &invalid).unwrap();
            assert!(claim(&paths).is_err(), "accepted: {invalid}");
            assert!(!paths.deploy_request.exists());
        }
        // An oversized or non-UTF-8 request this user owns is discarded too; a foreign one is never read.
        for invalid in [vec![b'x'; 300], vec![0xff, b'\n']] {
            let (_home, paths) = paths();
            fs::write(&paths.deploy_request, invalid).unwrap();
            fs::set_permissions(
                &paths.deploy_request,
                std::os::unix::fs::PermissionsExt::from_mode(0o600),
            )
            .unwrap();
            assert!(claim(&paths).is_err());
            assert!(!paths.deploy_request.exists());
        }
        let (_home, paths) = paths();
        std::os::unix::fs::symlink("/dev/null", &paths.deploy_request).unwrap();
        assert!(claim(&paths).is_err());
        assert!(paths.deploy_request.symlink_metadata().is_ok());
    }

    #[test]
    fn records_the_result_and_never_removes_a_replaced_request() {
        let (_home, paths) = paths();
        state::write_private(&paths.deploy_request, &request_document()).unwrap();
        let request = claim(&paths).unwrap().unwrap();

        finish(&paths, &request, Outcome::Deferred, "waiting").unwrap();
        assert!(paths.deploy_request.exists());

        let replacement = request_document().replace(ID, "fedcba9876543210fedcba9876543210");
        state::write_private(&paths.deploy_request, &replacement).unwrap();
        finish(&paths, &request, Outcome::Failed, "refused").unwrap();
        assert_eq!(
            fs::read_to_string(&paths.deploy_request).unwrap(),
            replacement
        );
        let result: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&paths.deploy_result).unwrap()).unwrap();
        assert_eq!(
            result,
            json!({"id": ID, "release": developer_ref(), "outcome": "failed", "message": "refused"})
        );

        state::write_private(&paths.deploy_request, &request_document()).unwrap();
        finish(&paths, &request, Outcome::Applied, "ready").unwrap();
        assert!(!paths.deploy_request.exists());
    }
}
