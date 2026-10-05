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
    use serde_json::{Value, json};
    use ureq::{Body, http::Response};

    use super::{error_message, read_json, valid_error_code};

    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn response(content_type: &str, body: &Value) -> Response<Body> {
        Response::builder()
            .header("Content-Type", content_type)
            .body(Body::builder().data(body.to_string()))
            .unwrap()
    }

    fn shown(content_type: &str, error: &Value, limit: u64) -> String {
        error_message(
            &mut response(content_type, &json!({"error": error})),
            limit,
            "fallback",
        )
    }

    fn error(code: &str, message: &str, request_id: &str) -> Value {
        json!({"code": code, "message": message, "request_id": request_id})
    }

    #[test]
    fn shows_only_the_message_of_a_valid_closed_envelope() {
        let valid = error("step_up_required", "Sign in again", ID);
        assert_eq!(shown("application/json", &valid, 1024), "Sign in again");
        assert_eq!(
            shown("application/json; charset=utf-8", &valid, 1024),
            "fallback"
        );
        assert_eq!(shown("application/json", &valid, 16), "fallback");
        let mut extra = valid.clone();
        extra["hint"] = json!("x");
        assert_eq!(shown("application/json", &extra, 1024), "fallback");
        assert_eq!(
            shown("application/json", &error("a", &"m".repeat(200), ID), 1024),
            "m".repeat(200)
        );
    }

    /// The installation client once admitted a 256-byte message with control characters and any request id up to
    /// 64 bytes; every Developers response now passes the producer's envelope rule.
    #[test]
    fn refuses_envelopes_the_installation_client_used_to_admit() {
        let upper = ID.to_uppercase();
        let long = "m".repeat(201);
        for (message, request_id) in [
            ("escape\u{1b}[2J", ID),
            ("bidi \u{202e}txt", ID),
            (long.as_str(), ID),
            ("Team or Assistant is not available", "request_1"),
            ("Team or Assistant is not available", upper.as_str()),
        ] {
            let refused = error("installation_not_found", message, request_id);
            assert_eq!(
                shown("application/json", &refused, 65_536),
                "fallback",
                "{message:?}"
            );
        }
    }

    #[test]
    fn reads_only_bounded_exact_json() {
        let read = |content_type, limit| {
            read_json::<Value>(
                &mut response(content_type, &json!({"value": "x"})),
                limit,
                "invalid",
            )
        };
        assert_eq!(read("application/json", 1024), Ok(json!({"value": "x"})));
        assert_eq!(read("text/html", 1024), Err("invalid".to_owned()));
        assert_eq!(read("application/json", 8), Err("invalid".to_owned()));
    }

    #[test]
    fn admits_only_closed_error_codes() {
        assert!(valid_error_code("step_up_required") && valid_error_code("oauth2_denied"));
        for refused in ["Step Up", "", &"a".repeat(65)] {
            assert!(!valid_error_code(refused), "{refused}");
        }
    }
}
