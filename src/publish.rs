//! Authenticated publication of one exact canonical Assistant package.

use std::{
    path::Path,
    thread,
    time::{Duration, Instant},
};

use serde::Deserialize;
use ureq::{Agent, Body, http::Response};
use zeroize::Zeroizing;

use crate::{args::PublicationVisibility, auth, output, python, source_package};

const PUBLICATIONS_URL: &str = "https://developers.shimpz.com/api/v1/publications";
const SOURCE_MEDIA_TYPE: &str = "application/vnd.shimpz.source.v1+tar";
const REQUIRED_SCOPE: &str = "assistant:publish";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_secs(1);
const WAIT_TIMEOUT: Duration = Duration::from_mins(30);
const MAX_RESPONSE_BYTES: u64 = 32 * 1024;

pub(crate) fn run(project: &Path, visibility: PublicationVisibility) -> Result<String, String> {
    let package = source_package::build(project)?;
    python::Assistant::open(project)?.contract()?;
    let credentials = auth::ensure_authenticated(REQUIRED_SCOPE)?;
    let api = Api::new();
    let publication = api.create(&credentials, &package, visibility)?;
    output::info("Publication accepted.");
    output::detail("Source", &package.digest);
    wait_until_installable(&api, &credentials, &package.digest, publication)
}

fn wait_until_installable(
    api: &Api,
    credentials: &crate::credentials::Credentials,
    expected_digest: &str,
    mut publication: Publication,
) -> Result<String, String> {
    let deadline = Instant::now()
        .checked_add(WAIT_TIMEOUT)
        .ok_or_else(unavailable)?;
    let mut observed_state = None;
    loop {
        publication.validate(expected_digest)?;
        if observed_state.as_deref() != Some(publication.build_state.as_str()) {
            output::progress(&publication.progress_message());
            observed_state = Some(publication.build_state.clone());
        }
        match publication.terminal_result() {
            Some(result) => return result,
            None if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
            None => return Err("publication wait timed out; run `shimpz publish` again".into()),
        }
        publication = api.status(credentials, expected_digest)?;
    }
}

struct Api {
    agent: Agent,
}

impl Api {
    fn new() -> Self {
        let config = Agent::config_builder()
            .timeout_global(Some(REQUEST_TIMEOUT))
            .max_redirects(0)
            .http_status_as_error(false)
            .build();
        Self {
            agent: config.into(),
        }
    }

    fn create(
        &self,
        credentials: &crate::credentials::Credentials,
        package: &source_package::SourcePackage,
        visibility: PublicationVisibility,
    ) -> Result<Publication, String> {
        let authorization = Zeroizing::new(format!("Bearer {}", credentials.access_token()));
        let mut response = self
            .agent
            .post(PUBLICATIONS_URL)
            .header("Accept", "application/json")
            .header("Authorization", authorization.as_str())
            .header("Content-Type", SOURCE_MEDIA_TYPE)
            .header("Content-Length", package.bytes.len().to_string())
            .header("X-Shimpz-Source-Digest", &package.digest)
            .header("X-Shimpz-Visibility", visibility.as_str())
            .send(&package.bytes)
            .map_err(|_| unavailable())?;
        match response.status().as_u16() {
            200 | 201 => read_publication(&mut response, &package.digest),
            _ => Err(status_error(&mut response, "publication was rejected")),
        }
    }

    fn status(
        &self,
        credentials: &crate::credentials::Credentials,
        source_digest: &str,
    ) -> Result<Publication, String> {
        let authorization = Zeroizing::new(format!("Bearer {}", credentials.access_token()));
        let url = format!("{PUBLICATIONS_URL}/{source_digest}");
        let mut response = self
            .agent
            .get(&url)
            .header("Accept", "application/json")
            .header("Authorization", authorization.as_str())
            .call()
            .map_err(|_| unavailable())?;
        match response.status().as_u16() {
            200 => read_publication(&mut response, source_digest),
            _ => Err(status_error(
                &mut response,
                "publication status is unavailable",
            )),
        }
    }
}

fn read_publication(
    response: &mut Response<Body>,
    expected_digest: &str,
) -> Result<Publication, String> {
    if response
        .headers()
        .get("Content-Type")
        .and_then(|value| value.to_str().ok())
        != Some("application/json")
    {
        return Err("Developers returned an invalid publication response".into());
    }
    let publication: Publication = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_json()
        .map_err(|_| "Developers returned an invalid publication response".to_owned())?;
    publication.validate(expected_digest)?;
    Ok(publication)
}

fn status_error(response: &mut Response<Body>, fallback: &'static str) -> String {
    if response
        .headers()
        .get("Content-Type")
        .and_then(|value| value.to_str().ok())
        != Some("application/json")
    {
        return fallback.into();
    }
    response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_json::<ErrorEnvelope>()
        .ok()
        .filter(|envelope| envelope.error.valid())
        .map_or_else(|| fallback.into(), |envelope| envelope.error.message)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    assistant_id: String,
    version: String,
    source_digest: String,
    build_state: String,
    review_state: String,
    security_state: String,
    blocked: bool,
    safe_error_code: Option<String>,
    image_reference: Option<String>,
    oci_digest: Option<String>,
    manifest_digest: Option<String>,
    machine_contract_digest: Option<String>,
    signature_identity: Option<String>,
    signature_reference: Option<String>,
    provenance_reference: Option<String>,
    sbom_digest: Option<String>,
    scan_digest: Option<String>,
    workflow_run_id: Option<u64>,
}

impl Publication {
    fn validate(&self, expected_digest: &str) -> Result<(), String> {
        if !valid_assistant_id(&self.assistant_id)
            || !valid_version(&self.version)
            || self.source_digest != expected_digest
            || !matches!(
                self.build_state.as_str(),
                "queued"
                    | "resolving"
                    | "building"
                    | "scanning"
                    | "signing"
                    | "artifact_ready"
                    | "build_failed"
            )
            || !matches!(
                self.review_state.as_str(),
                "pending" | "approved" | "catalog_rejected"
            )
            || !matches!(self.security_state.as_str(), "clear" | "security_rejected")
            || (self.security_state == "security_rejected" && !self.blocked)
            || !self.valid_build_result()
        {
            return Err("Developers returned an invalid publication response".into());
        }
        Ok(())
    }

    fn valid_build_result(&self) -> bool {
        let artifacts = [
            self.image_reference.as_deref(),
            self.oci_digest.as_deref(),
            self.manifest_digest.as_deref(),
            self.machine_contract_digest.as_deref(),
            self.signature_identity.as_deref(),
            self.signature_reference.as_deref(),
            self.provenance_reference.as_deref(),
            self.sbom_digest.as_deref(),
            self.scan_digest.as_deref(),
        ];
        match self.build_state.as_str() {
            "artifact_ready" => {
                self.safe_error_code.is_none()
                    && artifacts.iter().all(Option::is_some)
                    && self.workflow_run_id.is_some()
                    && self.valid_ready_artifact()
            }
            "build_failed" => {
                self.safe_error_code
                    .as_deref()
                    .is_some_and(valid_build_error)
                    && artifacts.iter().all(Option::is_none)
                    && self.valid_optional_workflow_run()
            }
            _ => {
                self.safe_error_code.is_none()
                    && artifacts.iter().all(Option::is_none)
                    && self.valid_active_workflow_run()
            }
        }
    }

    fn valid_optional_workflow_run(&self) -> bool {
        self.workflow_run_id.is_none_or(|value| value > 0)
    }

    fn valid_active_workflow_run(&self) -> bool {
        match self.build_state.as_str() {
            "queued" => self.workflow_run_id.is_none(),
            "resolving" => self.valid_optional_workflow_run(),
            "building" | "scanning" | "signing" => {
                self.workflow_run_id.is_some_and(|value| value > 0)
            }
            _ => false,
        }
    }

    fn valid_ready_artifact(&self) -> bool {
        let Some(oci_digest) = self.oci_digest.as_deref() else {
            return false;
        };
        if self.workflow_run_id.is_none_or(|value| value == 0) {
            return false;
        }
        let expected_image = format!("ghcr.io/theshimpz/shimpz-assistants@{oci_digest}");
        valid_digest(oci_digest)
            && self.image_reference.as_deref() == Some(expected_image.as_str())
            && self.manifest_digest.as_deref().is_some_and(valid_digest)
            && self
                .machine_contract_digest
                .as_deref()
                .is_some_and(valid_digest)
            && self.signature_identity.as_deref()
                == Some(
                    "https://github.com/TheShimpz/shimpz-developers/.github/workflows/build-assistant.yml@refs/heads/main",
                )
            && self
                .signature_reference
                .as_deref()
                .is_some_and(valid_trust_reference)
            && self
                .provenance_reference
                .as_deref()
                .is_some_and(valid_trust_reference)
            && self.sbom_digest.as_deref().is_some_and(valid_digest)
            && self.scan_digest.as_deref().is_some_and(valid_digest)
    }

    fn terminal_result(&self) -> Option<Result<String, String>> {
        if self.security_state == "security_rejected" {
            return Some(Err("publication was rejected by security review".into()));
        }
        if self.blocked {
            return Some(Err("publication is blocked".into()));
        }
        if self.build_state == "build_failed" {
            let error = match self.safe_error_code.as_deref() {
                Some("dependency_resolution_failed") => "publication dependency resolution failed",
                Some("security_scan_failed") => "publication security scan failed",
                Some("signing_failed") => "publication signing failed",
                Some("non_reproducible_build") => "publication build was not reproducible",
                _ => "publication build failed",
            };
            let run = self
                .workflow_url()
                .map_or_else(String::new, |url| format!("\nBuild run: {url}"));
            return Some(Err(format!("{error}{run}")));
        }
        (self.build_state == "artifact_ready").then(|| {
            let image = self
                .image_reference
                .as_deref()
                .expect("validated ready publication has an image");
            let oci_digest = self
                .oci_digest
                .as_deref()
                .expect("validated ready publication has an OCI digest");
            let provenance = self
                .provenance_reference
                .as_deref()
                .expect("validated ready publication has provenance");
            let signature = self
                .signature_reference
                .as_deref()
                .expect("validated ready publication has a signature");
            let workflow = self
                .workflow_url()
                .expect("validated ready publication has a workflow run");
            Ok(format!(
                "Assistant published and installable.\nAssistant: {} {}\nSource: {}\nImage: {}\nOCI digest: {}\nReview: {}\nBuild run: {}\nSignature: {}\nProvenance: {}\nPortal: https://developers.shimpz.com/assistants/{}",
                self.assistant_id,
                self.version,
                self.source_digest,
                image,
                oci_digest,
                self.review_state,
                workflow,
                signature,
                provenance,
                self.assistant_id
            ))
        })
    }

    fn progress_message(&self) -> String {
        let message = match self.build_state.as_str() {
            "queued" => "Queued — starting automatically.",
            "resolving" => "Resolving and locking dependencies.",
            "building" => "Building and publishing the immutable amd64/arm64 image.",
            "scanning" => "Scanning the image and generating its SBOM.",
            "signing" => "Signing the image and provenance.",
            "artifact_ready" => "Signed artifact ready.",
            "build_failed" => "Build failed.",
            _ => unreachable!("validated publication has a closed build state"),
        };
        self.workflow_url().map_or_else(
            || format!("[{}] {message}", self.build_state),
            |url| format!("[{}] {message}\nRun: {url}", self.build_state),
        )
    }

    fn workflow_url(&self) -> Option<String> {
        self.workflow_run_id.map(|run_id| {
            format!("https://github.com/TheShimpz/shimpz-developers/actions/runs/{run_id}")
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorEnvelope {
    error: ApiError,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiError {
    code: String,
    message: String,
    request_id: String,
}

impl ApiError {
    fn valid(&self) -> bool {
        valid_error_code(&self.code)
            && !self.message.is_empty()
            && self.message.len() <= 200
            && self
                .message
                .bytes()
                .all(|byte| byte.is_ascii() && !byte.is_ascii_control())
            && self.request_id.len() == 32
            && self
                .request_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
}

fn valid_assistant_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 40
        && value.starts_with(|character: char| character.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.ends_with('-')
        && !value.contains("--")
        && !matches!(value, "postgres" | "app-egress-proxy")
}

fn valid_version(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part == &"0" || !part.starts_with('0'))
        })
}

fn valid_error_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_build_error(value: &str) -> bool {
    matches!(
        value,
        "dependency_resolution_failed"
            | "build_failed"
            | "security_scan_failed"
            | "signing_failed"
            | "non_reproducible_build"
    )
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_trust_reference(value: &str) -> bool {
    value
        .strip_prefix("ghcr.io/theshimpz/shimpz-assistant-trust@")
        .is_some_and(valid_digest)
}

fn unavailable() -> String {
    "Developers is unavailable; try again shortly".into()
}

#[cfg(test)]
mod tests {
    use super::Publication;

    const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn publication(build_state: &str) -> Publication {
        Publication {
            assistant_id: "hello-world".into(),
            version: "0.1.0".into(),
            source_digest: DIGEST.into(),
            build_state: build_state.into(),
            review_state: "pending".into(),
            security_state: "clear".into(),
            blocked: false,
            safe_error_code: None,
            image_reference: None,
            oci_digest: None,
            manifest_digest: None,
            machine_contract_digest: None,
            signature_identity: None,
            signature_reference: None,
            provenance_reference: None,
            sbom_digest: None,
            scan_digest: None,
            workflow_run_id: None,
        }
    }

    fn ready_publication() -> Publication {
        let mut ready = publication("artifact_ready");
        let digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        ready.image_reference = Some(format!("ghcr.io/theshimpz/shimpz-assistants@{digest}"));
        ready.oci_digest = Some(digest.into());
        ready.manifest_digest = Some(digest.into());
        ready.machine_contract_digest = Some(digest.into());
        ready.signature_identity = Some(
            "https://github.com/TheShimpz/shimpz-developers/.github/workflows/build-assistant.yml@refs/heads/main".into(),
        );
        ready.signature_reference =
            Some(format!("ghcr.io/theshimpz/shimpz-assistant-trust@{digest}"));
        ready.provenance_reference =
            Some(format!("ghcr.io/theshimpz/shimpz-assistant-trust@{digest}"));
        ready.sbom_digest = Some(digest.into());
        ready.scan_digest = Some(digest.into());
        ready.workflow_run_id = Some(42);
        ready
    }

    #[test]
    fn accepts_only_closed_publication_states() {
        for state in ["queued", "resolving"] {
            assert!(publication(state).validate(DIGEST).is_ok());
        }
        for state in ["building", "scanning", "signing"] {
            let mut active = publication(state);
            active.workflow_run_id = Some(42);
            assert!(active.validate(DIGEST).is_ok());
        }
        assert!(ready_publication().validate(DIGEST).is_ok());
        let mut failed = publication("build_failed");
        failed.safe_error_code = Some("build_failed".into());
        assert!(failed.validate(DIGEST).is_ok());
        let mut invalid = publication("ready");
        assert!(invalid.validate(DIGEST).is_err());
        invalid = publication("queued");
        invalid.source_digest = DIGEST.replace('a', "b");
        assert!(invalid.validate(DIGEST).is_err());
        invalid = ready_publication();
        invalid.signature_reference =
            Some("ghcr.io/theshimpz/shimpz-assistants@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
        assert!(invalid.validate(DIGEST).is_err());
        invalid = ready_publication();
        invalid.workflow_run_id = Some(0);
        assert!(invalid.validate(DIGEST).is_err());
    }

    #[test]
    fn only_installability_or_safe_failure_ends_the_wait() {
        assert!(publication("queued").terminal_result().is_none());
        assert!(ready_publication().terminal_result().unwrap().is_ok());
        let mut failed = publication("build_failed");
        failed.safe_error_code = Some("security_scan_failed".into());
        assert!(failed.terminal_result().unwrap().is_err());

        let mut blocked = ready_publication();
        blocked.blocked = true;
        assert!(blocked.terminal_result().unwrap().is_err());

        let mut rejected = ready_publication();
        rejected.security_state = "security_rejected".into();
        rejected.blocked = true;
        assert!(rejected.terminal_result().unwrap().is_err());
    }

    #[test]
    fn renders_each_real_stage_and_the_exact_workflow() {
        assert_eq!(
            publication("queued").progress_message(),
            "[queued] Queued — starting automatically."
        );
        let mut building = publication("building");
        building.workflow_run_id = Some(42);
        assert_eq!(
            building.progress_message(),
            "[building] Building and publishing the immutable amd64/arm64 image.\nRun: https://github.com/TheShimpz/shimpz-developers/actions/runs/42"
        );
        assert!(building.validate(DIGEST).is_ok());

        let mut failed = publication("build_failed");
        failed.safe_error_code = Some("build_failed".into());
        failed.workflow_run_id = Some(42);
        assert!(failed.validate(DIGEST).is_ok());
        assert!(
            failed
                .terminal_result()
                .unwrap()
                .unwrap_err()
                .contains("/actions/runs/42")
        );
    }
}
