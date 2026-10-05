//! Interactive terminal adapter for local Action human requests.
//!
//! An Action emits a canonical request whose copy fields are message-catalog references (ADR-0091). The terminal
//! shows the SDK's English rendering of those references, while every answer carries only the canonical
//! fingerprint and canonical option values, so replay never depends on display text.

use std::collections::HashSet;
use std::io;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::action_failure::ActionFailure;
use crate::{digest, output};

const BASE_FIELDS: [&str; 5] = ["kind", "ordinal", "fingerprint", "title", "description"];
const OPTION_FIELDS: [&str; 3] = ["description", "label", "value"];
/// The largest copy bound of any request field (a description).
const MAX_DISPLAY_CHARACTERS: usize = 500;

pub(crate) enum ActionResponse {
    Result(Value),
    Request(HumanRequest),
    StoredInputRejected(String),
    Failure(ActionFailure),
}

/// One canonical request frame exactly as the Action emitted it.
pub(crate) struct HumanRequest {
    kind: String,
    ordinal: u64,
    fingerprint: String,
    frame: Map<String, Value>,
}

/// The English rendering of one canonical request, used only for display.
pub(crate) struct Display {
    title: String,
    description: String,
    label: Option<String>,
    options: Vec<(String, Option<String>)>,
}

pub(crate) fn parse_response(source: &str) -> Result<ActionResponse, String> {
    let value: Value =
        serde_json::from_str(source).map_err(|_| "Python SDK response is invalid")?;
    let object = value.as_object().ok_or("Python SDK response is invalid")?;
    match object.get("type").and_then(Value::as_str) {
        Some("result") if exact_fields(object, &["type", "result"]) => object
            .get("result")
            .filter(|result| result.is_object())
            .cloned()
            .map(ActionResponse::Result)
            .ok_or_else(|| "Python SDK response is invalid".into()),
        Some("request") if exact_fields(object, &["type", "request"]) => {
            parse_request(object.get("request")).map(ActionResponse::Request)
        }
        Some("stored_input_rejected")
            if exact_fields(object, &["type", "stored_input"])
                && object
                    .get("stored_input")
                    .and_then(Value::as_str)
                    .is_some_and(valid_stored_input_id) =>
        {
            Ok(ActionResponse::StoredInputRejected(
                object["stored_input"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            ))
        }
        Some("failure") if exact_fields(object, &["type", "failure"]) => {
            ActionFailure::parse(object.get("failure")).map(ActionResponse::Failure)
        }
        _ => Err("Python SDK response is invalid".into()),
    }
}

impl HumanRequest {
    pub(crate) fn contains_secret_input(&self) -> bool {
        self.kind == "input:password"
    }

    /// The exact canonical frame, for the SDK's English rendering.
    pub(crate) fn frame(&self) -> Value {
        Value::Object(self.frame.clone())
    }

    /// Admit the SDK's English rendering only when it changes nothing but the copy references.
    pub(crate) fn display(&self, rendered: &str) -> Result<Display, String> {
        let invalid = || "Python SDK rendered an invalid human request".to_owned();
        let value: Value = serde_json::from_str(rendered).map_err(|_| invalid())?;
        let shown = value
            .as_object()
            .filter(|shown| shown.keys().eq(self.frame.keys()))
            .ok_or_else(invalid)?;
        for (key, canonical) in &self.frame {
            let projected = &shown[key];
            let valid = match key.as_str() {
                "title" | "description" | "label" => display_text(projected).is_some(),
                "placeholder" => {
                    canonical.is_null() == projected.is_null()
                        && (projected.is_null() || display_text(projected).is_some())
                }
                "options" => rendered_options(canonical, projected),
                _ => projected == canonical,
            };
            if !valid {
                return Err(invalid());
            }
        }
        let text = |key: &str| display_text(&shown[key]).unwrap_or_default().to_owned();
        Ok(Display {
            title: text("title"),
            description: text("description"),
            label: shown.contains_key("label").then(|| text("label")),
            options: shown
                .get("options")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|option| {
                    (
                        display_text(&option["label"])
                            .unwrap_or_default()
                            .to_owned(),
                        display_text(&option["description"]).map(str::to_owned),
                    )
                })
                .collect(),
        })
    }
}

pub(crate) fn answer(request: &HumanRequest, display: &Display) -> Result<Value, String> {
    output::request(&display.title);
    output::request(&display.description);
    if let Some(label) = &display.label {
        output::request(label);
    }
    let value = match request.kind.as_str() {
        "approval" => Value::Bool(confirm("Approve this action? [y/N]")?),
        "input:text" | "input:phone" => Value::String(line("Enter the requested value:")?),
        "input:textarea" => Value::String(textarea()?),
        "input:password" => {
            let secret = Zeroizing::new(
                rpassword::prompt_password("response: ")
                    .map_err(|_| "Human request input is unavailable")?,
            );
            Value::String(secret.as_str().to_owned())
        }
        "input:select" | "input:choice" => Value::String(select(request, display)?),
        "input:choices" => Value::Array(choices(request, display)?),
        kind if kind.starts_with("auth:") => {
            return Err("request_auth requires an authenticated Team Admin session".into());
        }
        _ => return Err("Python SDK human request kind is invalid".into()),
    };
    if request.kind == "approval" && value != Value::Bool(true) {
        return Err("Action request was denied".into());
    }
    Ok(json!({
        "kind": request.kind,
        "ordinal": request.ordinal,
        "fingerprint": request.fingerprint,
        "value": value
    }))
}

fn parse_request(value: Option<&Value>) -> Result<HumanRequest, String> {
    let invalid = || "Python SDK human request is invalid".to_owned();
    let fields = value.and_then(Value::as_object).ok_or_else(invalid)?;
    let kind = fields
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?
        .to_owned();
    if !valid_request_fields(fields, &kind) || !valid_copy(fields) {
        return Err(invalid());
    }
    let ordinal = fields
        .get("ordinal")
        .and_then(Value::as_u64)
        .filter(|value| *value < 8)
        .ok_or_else(invalid)?;
    let fingerprint = fields
        .get("fingerprint")
        .and_then(Value::as_str)
        .filter(|value| digest::is_sha256_hex(value))
        .ok_or_else(invalid)?
        .to_owned();
    // ADR-0038's canonical preimage is the whole request without its fingerprint, references included.
    let mut preimage = fields.clone();
    preimage.remove("fingerprint");
    let encoded = serde_json::to_vec(&Value::Object(preimage)).map_err(|_| invalid())?;
    if format!("{:x}", Sha256::digest(encoded)) != fingerprint {
        return Err(invalid());
    }
    Ok(HumanRequest {
        kind,
        ordinal,
        fingerprint,
        frame: fields.clone(),
    })
}

fn valid_request_fields(fields: &Map<String, Value>, kind: &str) -> bool {
    let mut expected = BASE_FIELDS.into_iter().collect::<HashSet<_>>();
    match kind {
        "approval" | "auth:password" | "auth:totp" | "auth:passkey" => {}
        "input:text" | "input:textarea" | "input:password" | "input:phone" => {
            expected.extend([
                "label",
                "required",
                "placeholder",
                "min_length",
                "max_length",
            ]);
        }
        "input:select" | "input:choice" => expected.extend(["label", "required", "options"]),
        "input:choices" => {
            expected.extend([
                "label",
                "required",
                "options",
                "min_selections",
                "max_selections",
            ]);
        }
        _ => return false,
    }
    if kind == "input:password" && fields.contains_key("stored_input") {
        expected.insert("stored_input");
    }
    fields.keys().map(String::as_str).collect::<HashSet<_>>() == expected
        && fields
            .get("stored_input")
            .is_none_or(|value| value.as_str().is_some_and(valid_stored_input_id))
}

/// Every copy field is a catalog reference; only a placeholder or an option description may be absent (null).
fn valid_copy(fields: &Map<String, Value>) -> bool {
    ["title", "description"]
        .iter()
        .all(|field| fields.get(*field).is_some_and(valid_reference))
        && fields.get("label").is_none_or(valid_reference)
        && fields
            .get("placeholder")
            .is_none_or(|value| value.is_null() || valid_reference(value))
        && fields.get("options").is_none_or(|options| {
            options
                .as_array()
                .filter(|options| (2..=32).contains(&options.len()))
                .is_some_and(|options| options.iter().all(valid_option))
        })
}

fn valid_option(option: &Value) -> bool {
    option.as_object().is_some_and(|option| {
        option.keys().map(String::as_str).eq(OPTION_FIELDS)
            && option["value"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
            && valid_reference(&option["label"])
            && (option["description"].is_null() || valid_reference(&option["description"]))
    })
}

fn valid_reference(value: &Value) -> bool {
    value.as_object().is_some_and(|reference| {
        reference
            .keys()
            .map(String::as_str)
            .eq(["message", "params"])
            && reference["message"]
                .as_str()
                .is_some_and(digest::is_sha256_hex)
            && reference["params"].is_object()
    })
}

fn rendered_options(canonical: &Value, projected: &Value) -> bool {
    let (Some(canonical), Some(projected)) = (canonical.as_array(), projected.as_array()) else {
        return false;
    };
    canonical.len() == projected.len()
        && canonical
            .iter()
            .zip(projected)
            .all(|(canonical, projected)| {
                projected.as_object().is_some_and(|projected| {
                    projected.keys().map(String::as_str).eq(OPTION_FIELDS)
                        && projected["value"] == canonical["value"]
                        && display_text(&projected["label"]).is_some()
                        && canonical["description"].is_null() == projected["description"].is_null()
                        && (projected["description"].is_null()
                            || display_text(&projected["description"]).is_some())
                })
            })
}

/// Rendered copy reaches the terminal only as bounded text without control characters.
fn display_text(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| {
        !text.is_empty()
            && text.chars().count() <= MAX_DISPLAY_CHARACTERS
            && !text.chars().any(char::is_control)
    })
}

fn valid_stored_input_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && !bytes.windows(2).any(|pair| pair == b"--")
}

fn confirm(prompt: &str) -> Result<bool, String> {
    let value = line(prompt)?;
    Ok(matches!(value.to_ascii_lowercase().as_str(), "y" | "yes"))
}

fn line(prompt: &str) -> Result<String, String> {
    output::request(prompt);
    let mut value = String::new();
    let size = io::stdin()
        .read_line(&mut value)
        .map_err(|_| "Human request input is unavailable")?;
    if size == 0 {
        return Err(
            "Human request input is unavailable; do not use --input - for interactive Actions"
                .into(),
        );
    }
    Ok(value.trim_end_matches(['\r', '\n']).to_owned())
}

fn textarea() -> Result<String, String> {
    output::request("Enter the requested text; finish with a line containing only a period:");
    let mut lines = Vec::new();
    loop {
        let value = line(">")?;
        if value == "." {
            return Ok(lines.join("\n"));
        }
        lines.push(value);
    }
}

fn select(request: &HumanRequest, display: &Display) -> Result<String, String> {
    let values = option_values(request)?;
    render_options(display);
    let selected = selection(&line("Choose one option number:")?, values.len())?;
    Ok(values[selected].to_owned())
}

fn choices(request: &HumanRequest, display: &Display) -> Result<Vec<Value>, String> {
    let values = option_values(request)?;
    render_options(display);
    let raw = line("Choose option numbers separated by commas:")?;
    let mut selected = raw
        .split(',')
        .map(|value| selection(value.trim(), values.len()))
        .collect::<Result<Vec<_>, _>>()?;
    selected.sort_unstable();
    selected.dedup();
    Ok(selected
        .into_iter()
        .map(|index| Value::String(values[index].to_owned()))
        .collect())
}

/// The canonical option values, in order; a selection never answers with display text.
fn option_values(request: &HumanRequest) -> Result<Vec<&str>, String> {
    request
        .frame
        .get("options")
        .and_then(Value::as_array)
        .map(|options| {
            options
                .iter()
                .filter_map(|option| option["value"].as_str())
                .collect::<Vec<_>>()
        })
        .filter(|values| (2..=32).contains(&values.len()))
        .ok_or_else(|| "Python SDK human request options are invalid".to_owned())
}

fn render_options(display: &Display) {
    for (index, (label, description)) in display.options.iter().enumerate() {
        let line = description.as_ref().map_or_else(
            || format!("{}. {label}", index + 1),
            |description| format!("{}. {label} — {description}", index + 1),
        );
        output::request(&line);
    }
}

fn selection(value: &str, count: usize) -> Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|index| (1..=count).contains(index))
        .map(|index| index - 1)
        .ok_or_else(|| "Human request selection is invalid".to_owned())
}

fn exact_fields(object: &Map<String, Value>, expected: &[&str]) -> bool {
    object.keys().map(String::as_str).collect::<HashSet<_>>() == expected.iter().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(character: char, params: &Value) -> Value {
        json!({"message": character.to_string().repeat(64), "params": params})
    }

    /// Attach the canonical fingerprint to a request preimage.
    fn framed(mut request: Value) -> Value {
        let encoded = serde_json::to_vec(&request).unwrap();
        request["fingerprint"] = json!(format!("{:x}", Sha256::digest(encoded)));
        request
    }

    fn approval() -> Value {
        framed(json!({
            "kind": "approval",
            "ordinal": 0,
            "title": reference('a', &json!({})),
            "description": reference('b', &json!({"zone": "example.com", "count": 12})),
        }))
    }

    fn choice() -> Value {
        framed(json!({
            "kind": "input:choice",
            "ordinal": 1,
            "title": reference('a', &json!({})),
            "description": reference('b', &json!({})),
            "label": reference('c', &json!({})),
            "required": true,
            "options": [
                {"value": "proxied", "label": reference('d', &json!({})), "description": null},
                {"value": "dns-only", "label": reference('e', &json!({})), "description": reference('f', &json!({}))},
            ],
        }))
    }

    fn request(frame: &Value) -> HumanRequest {
        match parse_response(&json!({"type": "request", "request": frame}).to_string()) {
            Ok(ActionResponse::Request(request)) => request,
            _ => panic!("canonical request"),
        }
    }

    fn rendered_choice() -> Value {
        let mut rendered = choice();
        rendered["title"] = json!("Choose the DNS mode");
        rendered["description"] = json!("The Action needs this decision.");
        rendered["label"] = json!("Mode");
        rendered["options"][0]["label"] = json!("Proxied");
        rendered["options"][1]["label"] = json!("DNS only");
        rendered["options"][1]["description"] = json!("Serve records without the proxy.");
        rendered
    }

    #[test]
    fn parses_a_tagged_result() {
        let parsed = parse_response(r#"{"type":"result","result":{"ok":true}}"#).unwrap();
        assert!(matches!(parsed, ActionResponse::Result(value) if value == json!({"ok": true})));
    }

    #[test]
    fn fingerprints_references_exactly_like_the_protocol_reference() {
        // Python: sha256(json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":"))).
        assert_eq!(
            approval()["fingerprint"],
            "556560e7f9a6014aaf3cd769d79b53ad6b9417f62c137d70b08b8891a5b28a82"
        );
        let unicode = framed(json!({
            "kind": "approval",
            "ordinal": 0,
            "title": reference('a', &json!({})),
            "description": reference('b', &json!({"zone": "exämple", "count": 12})),
        }));
        assert_eq!(
            unicode["fingerprint"],
            "a00f75bc84503e83df1e34344620b3c8631102f7ef27a74002b60b403d38bff6"
        );
    }

    #[test]
    fn parses_only_canonical_reference_requests() {
        assert_eq!(request(&approval()).kind, "approval");
        assert_eq!(request(&choice()).kind, "input:choice");
        for kind in ["auth:password", "auth:totp", "auth:passkey"] {
            let mut frame = approval();
            frame["kind"] = json!(kind);
            frame.as_object_mut().unwrap().remove("fingerprint");
            assert_eq!(request(&framed(frame)).kind, kind);
        }

        let mut tampered = approval();
        tampered["description"]["params"]["count"] = json!(13);
        let mut string_copy = approval();
        string_copy["title"] = json!("Deploy");
        string_copy.as_object_mut().unwrap().remove("fingerprint");
        let mut extra = approval();
        extra["extra"] = json!(true);
        let mut option = choice();
        option["options"][0]["label"] = json!("Proxied");
        option.as_object_mut().unwrap().remove("fingerprint");
        for invalid in [tampered, framed(string_copy), extra, framed(option)] {
            assert!(
                parse_response(&json!({"type": "request", "request": invalid}).to_string())
                    .is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn parses_only_canonical_stored_input_password_requests() {
        let frame = |stored_input: &str| {
            framed(json!({
                "kind": "input:password",
                "ordinal": 1,
                "title": reference('a', &json!({})),
                "description": reference('b', &json!({})),
                "label": reference('c', &json!({})),
                "required": true,
                "placeholder": null,
                "min_length": 1,
                "max_length": 1024,
                "stored_input": stored_input,
            }))
        };
        assert!(request(&frame("whatsapp-token")).contains_secret_input());
        for stored_input in ["", "Whatsapp_Token", "a--b", &"a".repeat(65)] {
            let source = json!({"type": "request", "request": frame(stored_input)}).to_string();
            assert!(parse_response(&source).is_err(), "{stored_input}");
        }
    }

    #[test]
    fn parses_only_the_closed_stored_input_rejection_terminal() {
        let parsed =
            parse_response(r#"{"type":"stored_input_rejected","stored_input":"whatsapp-token"}"#)
                .expect("stored input rejection");
        assert!(matches!(
            parsed,
            ActionResponse::StoredInputRejected(stored_input) if stored_input == "whatsapp-token"
        ));
        for invalid in [
            r#"{"type":"stored_input_rejected"}"#,
            r#"{"type":"stored_input_rejected","stored_input":"Whatsapp_Token"}"#,
            r#"{"type":"stored_input_rejected","stored_input":"whatsapp-token","extra":true}"#,
        ] {
            assert!(parse_response(invalid).is_err());
        }
    }

    #[test]
    fn displays_only_a_rendering_that_keeps_every_canonical_value() {
        let request = request(&choice());
        let display = request
            .display(&rendered_choice().to_string())
            .expect("rendering");
        assert_eq!(display.title, "Choose the DNS mode");
        assert_eq!(display.label.as_deref(), Some("Mode"));
        assert_eq!(
            display.options,
            vec![
                ("Proxied".to_owned(), None),
                (
                    "DNS only".to_owned(),
                    Some("Serve records without the proxy.".to_owned())
                )
            ]
        );
        assert_eq!(option_values(&request).unwrap(), ["proxied", "dns-only"]);

        let mut changed_value = rendered_choice();
        changed_value["options"][0]["value"] = json!("dns-only");
        let mut changed_fingerprint = rendered_choice();
        changed_fingerprint["fingerprint"] = json!("0".repeat(64));
        let mut unrendered = rendered_choice();
        unrendered["title"] = choice()["title"].clone();
        let mut control = rendered_choice();
        control["description"] = json!("Line one\u{1b}[2J");
        let mut invented = rendered_choice();
        invented["options"][0]["description"] = json!("Invented");
        let mut extra = rendered_choice();
        extra["extra"] = json!(true);
        for invalid in [
            changed_value,
            changed_fingerprint,
            unrendered,
            control,
            invented,
            extra,
        ] {
            assert!(request.display(&invalid.to_string()).is_err(), "{invalid}");
        }
    }

    #[test]
    fn rejects_unknown_request_fields_and_legacy_results() {
        assert!(parse_response(r#"{"ok":true}"#).is_err());
    }

    #[test]
    fn parses_only_bounded_one_based_selections() {
        assert_eq!(selection("1", 2), Ok(0));
        assert_eq!(selection("2", 2), Ok(1));
        assert!(selection("0", 2).is_err());
        assert!(selection("3", 2).is_err());
    }
}
