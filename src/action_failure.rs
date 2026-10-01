//! The sanitized Assistant Spec v1 failure frame of one handled Action failure (ADR-0092).
//!
//! The SDK already redacts and bounds the diagnostic. The terminal admits only the closed frame, removes every
//! private value it injected once more, and shows the real type, message, provider, status, and excerpt.

use serde_json::{Map, Value};

const FIELDS: [&str; 7] = [
    "error_type",
    "message",
    "provider",
    "http_status",
    "response_excerpt",
    "redacted",
    "truncated",
];
const MAX_ERROR_TYPE: usize = 128;
const MAX_TEXT_BYTES: usize = 2_048;
const MAX_PROVIDER: usize = 253;
const REDACTED: &str = "[REDACTED]";
const INVALID: &str = "Python SDK failure frame is invalid";

/// One validated failure diagnostic, safe to print: it holds no terminal control or bidi formatting character.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ActionFailure {
    error_type: String,
    message: String,
    provider: Option<String>,
    http_status: Option<u16>,
    response_excerpt: Option<String>,
    redacted: bool,
    truncated: bool,
}

impl ActionFailure {
    /// Admit exactly the closed `failure` object of a `{"type":"failure"}` frame.
    pub(crate) fn parse(value: Option<&Value>) -> Result<Self, String> {
        let object = value.and_then(Value::as_object).ok_or(INVALID)?;
        if object.len() != FIELDS.len() || !FIELDS.iter().all(|field| object.contains_key(*field)) {
            return Err(INVALID.into());
        }
        Ok(Self {
            error_type: text(object, "error_type")
                .filter(|value| error_type(value))
                .ok_or(INVALID)?,
            message: text(object, "message")
                .filter(|value| diagnostic(value))
                .ok_or(INVALID)?,
            provider: nullable(object, "provider", |value| {
                value
                    .as_str()
                    .filter(|host| provider(host))
                    .map(str::to_owned)
            })?,
            http_status: nullable(object, "http_status", |value| {
                value
                    .as_u64()
                    .filter(|status| (100..=599).contains(status))
                    .and_then(|status| u16::try_from(status).ok())
            })?,
            response_excerpt: nullable(object, "response_excerpt", |value| {
                value
                    .as_str()
                    .filter(|text| diagnostic(text))
                    .map(str::to_owned)
            })?,
            redacted: object["redacted"].as_bool().ok_or(INVALID)?,
            truncated: object["truncated"].as_bool().ok_or(INVALID)?,
        })
    }

    /// Replace every private value this invocation injected, as Team does independently of the SDK.
    pub(crate) fn redact(&mut self, secrets: &[&str]) {
        for text in [Some(&mut self.message), self.response_excerpt.as_mut()]
            .into_iter()
            .flatten()
        {
            for secret in secrets {
                if text.contains(secret) {
                    *text = text.replace(secret, REDACTED);
                    self.redacted = true;
                }
            }
        }
    }

    /// Render the diagnostic for the terminal.
    pub(crate) fn render(&self) -> String {
        let mut lines = vec![if self.message.is_empty() {
            format!("Action failed: {}", self.error_type)
        } else {
            format!("Action failed: {}: {}", self.error_type, self.message)
        }];
        lines.extend(match (&self.provider, self.http_status) {
            (Some(provider), Some(status)) => Some(format!("Provider: {provider} (HTTP {status})")),
            (Some(provider), None) => Some(format!("Provider: {provider}")),
            (None, Some(status)) => Some(format!("HTTP status: {status}")),
            (None, None) => None,
        });
        if let Some(excerpt) = &self.response_excerpt {
            lines.push(format!("Response: {excerpt}"));
        }
        if self.redacted {
            lines.push("Some diagnostic content was redacted or withheld.".into());
        }
        if self.truncated {
            lines.push("Some diagnostic content was truncated.".into());
        }
        lines.join("\n")
    }
}

fn text(object: &Map<String, Value>, field: &str) -> Option<String> {
    object.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn nullable<T>(
    object: &Map<String, Value>,
    field: &str,
    admit: impl Fn(&Value) -> Option<T>,
) -> Result<Option<T>, String> {
    match &object[field] {
        Value::Null => Ok(None),
        value => admit(value).map(Some).ok_or_else(|| INVALID.into()),
    }
}

fn error_type(value: &str) -> bool {
    (1..=MAX_ERROR_TYPE).contains(&value.len())
        && value.bytes().all(|byte| (b'!'..=b'~').contains(&byte))
}

/// Diagnostic text keeps tab and line feed only; every other control, bidi, and zero-width character is refused.
fn diagnostic(value: &str) -> bool {
    value.len() <= MAX_TEXT_BYTES
        && value.chars().all(|character| {
            !matches!(
                u32::from(character),
                0x00..=0x08 | 0x0b..=0x1f | 0x7f..=0x9f | 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x206f | 0xfeff
            )
        })
}

fn provider(value: &str) -> bool {
    value.len() <= MAX_PROVIDER
        && value.split('.').all(|label| {
            let bytes = label.as_bytes();
            (1..=63).contains(&bytes.len())
                && bytes[0] != b'-'
                && bytes[bytes.len() - 1] != b'-'
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn frame() -> Value {
        json!({
            "error_type": "httpx.HTTPStatusError",
            "message": "Client error '404 Not Found'",
            "provider": "api.example.com",
            "http_status": 404,
            "response_excerpt": "{\"error\":\"missing zone\"}",
            "redacted": false,
            "truncated": true
        })
    }

    fn with(field: &str, value: Value) -> Value {
        let mut frame = frame();
        frame[field] = value;
        frame
    }

    #[test]
    fn renders_the_real_sanitized_diagnostic() {
        let failure = ActionFailure::parse(Some(&frame())).expect("valid frame");

        assert_eq!(
            failure.render(),
            "Action failed: httpx.HTTPStatusError: Client error '404 Not Found'\n\
             Provider: api.example.com (HTTP 404)\n\
             Response: {\"error\":\"missing zone\"}\n\
             Some diagnostic content was truncated."
        );
    }

    #[test]
    fn renders_an_ordinary_exception_without_provider_details() {
        let value = json!({
            "error_type": "ValueError",
            "message": "",
            "provider": null,
            "http_status": 503,
            "response_excerpt": null,
            "redacted": true,
            "truncated": false
        });
        let failure = ActionFailure::parse(Some(&value)).expect("valid frame");

        assert_eq!(
            failure.render(),
            "Action failed: ValueError\nHTTP status: 503\nSome diagnostic content was redacted or withheld."
        );
        let provider_only = with("http_status", Value::Null);
        assert!(
            ActionFailure::parse(Some(&provider_only))
                .expect("valid frame")
                .render()
                .contains("Provider: api.example.com\n")
        );
    }

    #[test]
    fn redacts_injected_private_values_again() {
        let value = with("message", json!("token private-token-1 rejected"));
        let mut failure = ActionFailure::parse(Some(&value)).expect("valid frame");

        failure.redact(&["private-token-1", "absent-secret"]);

        assert!(failure.redacted);
        assert!(failure.render().contains("token [REDACTED] rejected"));
        assert!(!failure.render().contains("private-token-1"));
    }

    #[test]
    fn admits_text_at_its_byte_bound() {
        let value = with("message", json!("\u{e9}".repeat(1_024)));
        assert!(ActionFailure::parse(Some(&value)).is_ok());
        let value = with("error_type", json!("E".repeat(128)));
        assert!(ActionFailure::parse(Some(&value)).is_ok());
    }

    #[test]
    fn refuses_every_frame_outside_the_closed_contract() {
        let mut extra = frame();
        extra["stack"] = json!("Traceback");
        let mut missing = frame();
        missing.as_object_mut().expect("object").remove("truncated");
        for invalid in [
            json!("boom"),
            extra,
            missing,
            with("error_type", json!("")),
            with("error_type", json!("Http Error")),
            with("error_type", json!("E".repeat(129))),
            with("error_type", json!(7)),
            with("message", json!("\u{e9}".repeat(1_024) + "x")),
            with("message", json!("red\u{1b}[31m")),
            with("message", json!("safe\u{202e}txt")),
            with("message", json!("a\rb")),
            with("response_excerpt", json!("x".repeat(2_049))),
            with("response_excerpt", json!(1)),
            with("provider", json!("API.example.com")),
            with("provider", json!("https://api.example.com")),
            with("provider", json!("api-.example.com")),
            with("provider", json!("a".repeat(254))),
            with("provider", json!("")),
            with("http_status", json!(99)),
            with("http_status", json!(600)),
            with("http_status", json!("404")),
            with("redacted", json!(0)),
            with("truncated", Value::Null),
        ] {
            assert_eq!(
                ActionFailure::parse(Some(&invalid)),
                Err(INVALID.to_owned()),
                "{invalid}"
            );
        }
        assert_eq!(ActionFailure::parse(None), Err(INVALID.to_owned()));
    }
}
