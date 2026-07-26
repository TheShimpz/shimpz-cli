//! Authenticated publication of one exact canonical Assistant package.

use std::{
    path::Path,
    thread,
    time::{Duration, Instant},
};

use serde::Deserialize;
use ureq::{Agent, Body, http::Response};
use zeroize::Zeroizing;

use crate::{auth, python, source_package};

const PUBLICATIONS_URL: &str = "https://developers.shimpz.com/api/v1/publications";
const SOURCE_MEDIA_TYPE: &str = "application/vnd.shimpz.source.v1+tar";
const REQUIRED_SCOPE: &str = "assistant:publish";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const WAIT_TIMEOUT: Duration = Duration::from_mins(30);
const MAX_RESPONSE_BYTES: u64 = 32 * 1024;

pub(crate) fn run(project: &Path) -> Result<String, String> {
    let package = source_package::build(project)?;
    python::Assistant::open(project)?.contract()?;
    let credentials = auth::ensure_authenticated(REQUIRED_SCOPE)?;
    let api = Api::new();
    let publication = api.create(&credentials, &package)?;
    println!(
        "Publication accepted: {}\nWaiting for the signed artifact...",
        package.digest
    );
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
    loop {
        publication.validate(expected_digest)?;
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
        {
            return Err("Developers returned an invalid publication response".into());
        }
        Ok(())
    }

    fn terminal_result(&self) -> Option<Result<String, String>> {
        if self.security_state == "security_rejected" {
            return Some(Err("publication was rejected by security review".into()));
        }
        if self.blocked {
            return Some(Err("publication is blocked".into()));
        }
        if self.build_state == "build_failed" {
            return Some(Err("publication build failed".into()));
        }
        (self.build_state == "artifact_ready").then(|| {
            Ok(format!(
                "Assistant published and installable.\nAssistant: {} {}\nSource: {}\nReview: {}\nPortal: https://developers.shimpz.com/assistants/{}",
                self.assistant_id,
                self.version,
                self.source_digest,
                self.review_state,
                self.assistant_id
            ))
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
        }
    }

    #[test]
    fn accepts_only_closed_publication_states() {
        for state in [
            "queued",
            "resolving",
            "building",
            "scanning",
            "signing",
            "artifact_ready",
            "build_failed",
        ] {
            assert!(publication(state).validate(DIGEST).is_ok());
        }
        let mut invalid = publication("ready");
        assert!(invalid.validate(DIGEST).is_err());
        invalid = publication("queued");
        invalid.source_digest = DIGEST.replace('a', "b");
        assert!(invalid.validate(DIGEST).is_err());
    }

    #[test]
    fn only_installability_or_safe_failure_ends_the_wait() {
        assert!(publication("queued").terminal_result().is_none());
        assert!(
            publication("artifact_ready")
                .terminal_result()
                .unwrap()
                .is_ok()
        );
        assert!(
            publication("build_failed")
                .terminal_result()
                .unwrap()
                .is_err()
        );

        let mut blocked = publication("artifact_ready");
        blocked.blocked = true;
        assert!(blocked.terminal_result().unwrap().is_err());

        let mut rejected = publication("artifact_ready");
        rejected.security_state = "security_rejected".into();
        rejected.blocked = true;
        assert!(rejected.terminal_result().unwrap().is_err());
    }
}
