//! The Developers peer client: one connection policy, one bounded JSON read, and one closed error envelope.
//!
//! Only Developers endpoints use this module. Each caller keeps its own request timeout and response bound explicit.

use std::time::Duration;

use serde::{Deserialize, de::DeserializeOwned};
use ureq::{Agent, Body, http::Response};
use zeroize::Zeroizing;

use crate::digest;

const MAX_ERROR_MESSAGE_BYTES: usize = 200;
const MAX_ERROR_CODE_BYTES: usize = 64;
const REQUEST_ID_HEX: usize = 32;

/// An agent bounded by `timeout` that never follows a redirect and returns every HTTP status to its caller.
pub(crate) fn agent(timeout: Duration) -> Agent {
    Agent::config_builder()
        .timeout_global(Some(timeout))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into()
}

/// The bearer `Authorization` header value, wiped from memory when dropped.
pub(crate) fn bearer(token: &str) -> Zeroizing<String> {
    Zeroizing::new(format!("Bearer {token}"))
}

/// Decode an exact `application/json` body of at most `limit` bytes; anything else is the `invalid` message.
pub(crate) fn read_json<T: DeserializeOwned>(
    response: &mut Response<Body>,
    limit: u64,
    invalid: &str,
) -> Result<T, String> {
    decode(response, limit).ok_or_else(|| invalid.to_owned())
}

/// The message of a valid Developers error envelope, or `fallback` when the response carries none.
pub(crate) fn error_message(response: &mut Response<Body>, limit: u64, fallback: &str) -> String {
    decode::<ErrorEnvelope>(response, limit)
        .map(|envelope| envelope.error)
        .filter(ApiError::valid)
        .map_or_else(|| fallback.to_owned(), |error| error.message)
}

/// The transport failure shown when Developers cannot be reached.
pub(crate) fn unavailable() -> String {
    "Developers is unavailable; try again shortly".into()
}

fn decode<T: DeserializeOwned>(response: &mut Response<Body>, limit: u64) -> Option<T> {
    if response
        .headers()
        .get("Content-Type")
        .and_then(|value| value.to_str().ok())
        != Some("application/json")
    {
        return None;
    }
    response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_json()
        .ok()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorEnvelope {
    error: ApiError,
}

/// Developers' closed error body: only a valid one may reach the terminal, and only its message is shown.
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
            && self.message.len() <= MAX_ERROR_MESSAGE_BYTES
            && self
                .message
                .bytes()
                .all(|byte| (b' '..=b'~').contains(&byte))
            && digest::is_lower_hex(&self.request_id, REQUEST_ID_HEX)
    }
}

fn valid_error_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ERROR_CODE_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use ureq::{Body, http::Response};

    use super::{error_message, read_json, valid_error_code};

    const REQUEST_ID: &str = "0123456789abcdef0123456789abcdef";

    fn response(content_type: &str, body: &serde_json::Value) -> Response<Body> {
        Response::builder()
            .header("Content-Type", content_type)
            .body(Body::builder().data(body.to_string()))
            .unwrap()
    }

    fn envelope(code: &str, message: &str, request_id: &str) -> serde_json::Value {
        json!({"error": {"code": code, "message": message, "request_id": request_id}})
    }

    #[test]
    fn shows_only_the_message_of_a_valid_closed_envelope() {
        let mut valid = response(
            "application/json",
            &envelope("step_up_required", "Sign in again", REQUEST_ID),
        );
        assert_eq!(error_message(&mut valid, 1024, "fallback"), "Sign in again");

        let mut wrong_type = response(
            "application/json; charset=utf-8",
            &envelope("step_up_required", "Sign in again", REQUEST_ID),
        );
        assert_eq!(error_message(&mut wrong_type, 1024, "fallback"), "fallback");

        let mut extra_field = response(
            "application/json",
            &json!({"error": {"code": "a", "message": "m", "request_id": REQUEST_ID, "hint": "x"}}),
        );
        assert_eq!(
            error_message(&mut extra_field, 1024, "fallback"),
            "fallback"
        );

        let mut oversized = response(
            "application/json",
            &envelope("step_up_required", "Sign in again", REQUEST_ID),
        );
        assert_eq!(error_message(&mut oversized, 16, "fallback"), "fallback");
    }

    /// The installation client once admitted a 256-byte message with control characters and any request id up to
    /// 64 bytes; every Developers response now passes the producer's envelope rule.
    #[test]
    fn refuses_envelopes_the_installation_client_used_to_admit() {
        for (message, request_id) in [
            ("escape\u{1b}[2J", REQUEST_ID),
            ("bidi \u{202e}txt", REQUEST_ID),
            (&"m".repeat(201) as &str, REQUEST_ID),
            ("Team or Assistant is not available", "request_1"),
            (
                "Team or Assistant is not available",
                &REQUEST_ID.to_uppercase(),
            ),
        ] {
            let mut refused = response(
                "application/json",
                &envelope("installation_not_found", message, request_id),
            );
            assert_eq!(
                error_message(&mut refused, 64 * 1024, "fallback"),
                "fallback",
                "{message:?} {request_id:?}"
            );
        }
        let mut longest = response(
            "application/json",
            &envelope("installation_not_found", &"m".repeat(200), REQUEST_ID),
        );
        assert_eq!(
            error_message(&mut longest, 64 * 1024, "fallback"),
            "m".repeat(200)
        );
    }

    #[test]
    fn reads_only_bounded_exact_json() {
        let mut valid = response("application/json", &json!({"value": 1}));
        assert_eq!(
            read_json::<serde_json::Value>(&mut valid, 1024, "invalid"),
            Ok(json!({"value": 1}))
        );
        let mut html = response("text/html", &json!({"value": 1}));
        assert_eq!(
            read_json::<serde_json::Value>(&mut html, 1024, "invalid"),
            Err("invalid".to_owned())
        );
        let mut oversized = response("application/json", &json!({"value": "x".repeat(64)}));
        assert_eq!(
            read_json::<serde_json::Value>(&mut oversized, 16, "invalid"),
            Err("invalid".to_owned())
        );
    }

    #[test]
    fn admits_only_closed_error_codes() {
        assert!(valid_error_code("step_up_required"));
        assert!(valid_error_code("oauth2_denied"));
        assert!(!valid_error_code("Step Up"));
        assert!(!valid_error_code(""));
        assert!(!valid_error_code(&"a".repeat(65)));
    }
}
