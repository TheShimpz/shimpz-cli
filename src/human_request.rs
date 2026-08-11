//! Interactive terminal adapter for local Action human requests.

use std::collections::HashSet;
use std::io;

use serde_json::{Map, Value, json};

use crate::output;

const BASE_FIELDS: [&str; 5] = ["kind", "ordinal", "fingerprint", "title", "description"];

pub(crate) enum ActionResponse {
    Result(Value),
    Request(HumanRequest),
}

pub(crate) struct HumanRequest {
    kind: String,
    ordinal: u64,
    fingerprint: String,
    title: String,
    description: String,
    fields: Map<String, Value>,
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
        _ => Err("Python SDK response is invalid".into()),
    }
}

pub(crate) fn answer(request: &HumanRequest) -> Result<Value, String> {
    output::request(&request.title);
    output::request(&request.description);
    let value = match request.kind.as_str() {
        "approval" => Value::Bool(confirm("Approve this action? [y/N]")?),
        "input:text" | "input:phone" => Value::String(line("Enter the requested value:")?),
        "input:textarea" => Value::String(textarea()?),
        "input:password" => Value::String(
            rpassword::prompt_password("response: ")
                .map_err(|_| "Human request input is unavailable")?,
        ),
        "input:select" | "input:choice" => Value::String(select(request)?),
        "input:choices" => Value::Array(choices(request)?),
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
    let fields = value
        .and_then(Value::as_object)
        .ok_or("Python SDK human request is invalid")?;
    let kind = text(fields, "kind")?;
    if !valid_request_fields(fields, &kind) {
        return Err("Python SDK human request is invalid".into());
    }
    let ordinal = fields
        .get("ordinal")
        .and_then(Value::as_u64)
        .filter(|value| *value < 8)
        .ok_or("Python SDK human request is invalid")?;
    let fingerprint = text(fields, "fingerprint")?;
    if fingerprint.len() != 64
        || !fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("Python SDK human request is invalid".into());
    }
    Ok(HumanRequest {
        kind,
        ordinal,
        fingerprint,
        title: text(fields, "title")?,
        description: text(fields, "description")?,
        fields: fields.clone(),
    })
}

fn valid_request_fields(fields: &Map<String, Value>, kind: &str) -> bool {
    let mut expected = BASE_FIELDS.into_iter().collect::<HashSet<_>>();
    match kind {
        "approval" | "auth:reauth" | "auth:second-factor" | "auth:phishing-resistant" => {}
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
    fields.keys().map(String::as_str).collect::<HashSet<_>>() == expected
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

fn select(request: &HumanRequest) -> Result<String, String> {
    let options = options(request)?;
    render_options(&options);
    let selected = selection(&line("Choose one option number:")?, options.len())?;
    Ok(options[selected]["value"]
        .as_str()
        .unwrap_or_default()
        .to_owned())
}

fn choices(request: &HumanRequest) -> Result<Vec<Value>, String> {
    let options = options(request)?;
    render_options(&options);
    let raw = line("Choose option numbers separated by commas:")?;
    let mut selected = raw
        .split(',')
        .map(|value| selection(value.trim(), options.len()))
        .collect::<Result<Vec<_>, _>>()?;
    selected.sort_unstable();
    selected.dedup();
    Ok(selected
        .into_iter()
        .map(|index| options[index]["value"].clone())
        .collect())
}

fn options(request: &HumanRequest) -> Result<Vec<&Map<String, Value>>, String> {
    request
        .fields
        .get("options")
        .and_then(Value::as_array)
        .filter(|options| (2..=32).contains(&options.len()))
        .ok_or_else(|| "Python SDK human request options are invalid".to_owned())?
        .iter()
        .map(|option| {
            option
                .as_object()
                .ok_or_else(|| "Python SDK human request options are invalid".to_owned())
        })
        .collect()
}

fn render_options(options: &[&Map<String, Value>]) {
    for (index, option) in options.iter().enumerate() {
        output::request(&format!(
            "{}. {}",
            index + 1,
            option["label"].as_str().unwrap_or("invalid option")
        ));
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

fn text(fields: &Map<String, Value>, key: &str) -> Result<String, String> {
    fields
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "Python SDK human request is invalid".to_owned())
}

fn exact_fields(object: &Map<String, Value>, expected: &[&str]) -> bool {
    object.keys().map(String::as_str).collect::<HashSet<_>>() == expected.iter().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_tagged_result() {
        let parsed = parse_response(r#"{"type":"result","result":{"ok":true}}"#).unwrap();
        assert!(matches!(parsed, ActionResponse::Result(value) if value == json!({"ok": true})));
    }

    #[test]
    fn parses_a_closed_approval_request() {
        let parsed = parse_response(
            r#"{"type":"request","request":{"kind":"approval","ordinal":0,"fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","title":"Deploy","description":"Deploy safely."}}"#,
        )
        .unwrap();
        assert!(matches!(parsed, ActionResponse::Request(request) if request.kind == "approval"));
    }

    #[test]
    fn rejects_unknown_request_fields_and_legacy_results() {
        assert!(parse_response(r#"{"ok":true}"#).is_err());
        assert!(parse_response(
            r#"{"type":"request","request":{"kind":"approval","ordinal":0,"fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","title":"Deploy","description":"Deploy safely.","extra":true}}"#,
        )
        .is_err());
    }

    #[test]
    fn parses_only_bounded_one_based_selections() {
        assert_eq!(selection("1", 2), Ok(0));
        assert_eq!(selection("2", 2), Ok(1));
        assert!(selection("0", 2).is_err());
        assert!(selection("3", 2).is_err());
    }
}
