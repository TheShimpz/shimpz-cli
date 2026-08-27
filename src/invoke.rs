//! Local Action invocation and Integration injection.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::args::Input;
use crate::human_request::{ActionResponse, answer, parse_response};
use crate::python;

const MAX_INPUT_BYTES: u64 = 512 * 1_024;
const MAX_INVOCATION_BYTES: usize = 512 * 1_024;
const MIN_PROTECTED_VALUE_CHARACTERS: usize = 8;
const MAX_SECRET_INSPECTION_DEPTH: usize = 32;

struct Invocation(Value);

impl Invocation {
    fn push_response(&mut self, response: Value) -> Result<(), String> {
        self.0
            .as_object_mut()
            .ok_or_else(|| "Action invocation is invalid".to_owned())?
            .entry("responses")
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| "Action invocation is invalid".to_owned())?
            .push(response);
        Ok(())
    }

    fn serialized(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut counter = ByteCounter::default();
        serde_json::to_writer(&mut counter, &self.0)
            .map_err(|_| "Action invocation is invalid".to_owned())?;
        if counter.0 > MAX_INVOCATION_BYTES {
            return Err("Action invocation is outside the accepted size".into());
        }
        let mut encoded = Zeroizing::new(Vec::with_capacity(counter.0));
        serde_json::to_writer(&mut *encoded, &self.0)
            .map_err(|_| "Action invocation is invalid".to_owned())?;
        Ok(encoded)
    }

    fn response_exposes_secret(&self, response: &Value) -> bool {
        let secrets = self.protected_values();
        !secrets.is_empty() && contains_secret(response, &secrets, 0)
    }

    fn protected_values(&self) -> Vec<&str> {
        let Some(invocation) = self.0.as_object() else {
            return Vec::new();
        };
        let mut secrets = Vec::new();
        for field in ["integrations", "stored_inputs"] {
            secrets.extend(
                invocation
                    .get(field)
                    .and_then(Value::as_object)
                    .into_iter()
                    .flat_map(|values| values.values())
                    .filter_map(Value::as_str)
                    .filter(|value| protected_value(value)),
            );
        }
        secrets.extend(
            invocation
                .get("responses")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|response| {
                    response.get("kind").and_then(Value::as_str) == Some("input:password")
                })
                .filter_map(|response| response.get("value").and_then(Value::as_str))
                .filter(|value| protected_value(value)),
        );
        secrets
    }
}

impl Drop for Invocation {
    fn drop(&mut self) {
        // The release profile aborts on panic, so this protects normal returns and
        // handled errors only. The Python bridge retains its own unavoidable copy.
        zeroize_strings(&mut self.0);
    }
}

#[derive(Default)]
struct ByteCounter(usize);

impl Write for ByteCounter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0 = self.0.saturating_add(buffer.len());
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn zeroize_strings(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_strings),
        Value::Object(values) => values.values_mut().for_each(zeroize_strings),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn protected_value(value: &str) -> bool {
    // Local creators commonly use short placeholders. Team runtime values are provider-issued,
    // so the CLI deliberately applies this floor only to its additional defense-in-depth scan.
    value.chars().count() >= MIN_PROTECTED_VALUE_CHARACTERS
}

fn contains_secret(value: &Value, secrets: &[&str], depth: usize) -> bool {
    if depth > MAX_SECRET_INSPECTION_DEPTH {
        return true;
    }
    match value {
        Value::String(text) => secrets.iter().any(|secret| text.contains(secret)),
        Value::Array(values) => values
            .iter()
            .any(|item| contains_secret(item, secrets, depth + 1)),
        Value::Object(values) => values.iter().any(|(key, item)| {
            contains_secret_text(key, secrets, depth + 1)
                || contains_secret(item, secrets, depth + 1)
        }),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn contains_secret_text(text: &str, secrets: &[&str], depth: usize) -> bool {
    depth > MAX_SECRET_INSPECTION_DEPTH || secrets.iter().any(|secret| text.contains(secret))
}

pub(crate) fn run(project: &Path, action_id: &str, input: &Input) -> Result<String, String> {
    let assistant = python::Assistant::open(project)?;
    let contract = assistant.contract()?;
    let integration_ids = action_integrations(&contract, action_id)?;
    let integrations = integration_tokens(&integration_ids)?;
    let mut request = request(input, &integrations)?;
    let mut secret_answered = false;
    for _ in 0..=8 {
        let serialized = request.serialized()?;
        let output = assistant.invoke(action_id, serialized.as_slice())?;
        let response_value: Value = serde_json::from_str(&output)
            .map_err(|_| "Python SDK response is invalid".to_owned())?;
        if request.response_exposes_secret(&response_value) {
            return Err("Action response exposes private input".into());
        }
        match parse_response(&output)? {
            ActionResponse::Result(result) => {
                return serde_json::to_string(&result)
                    .map_err(|_| "Action result is invalid".into());
            }
            ActionResponse::Request(_) if secret_answered => {
                return Err("Action requested human input after a password response".into());
            }
            ActionResponse::Request(frame) => {
                let response = answer(&frame)?;
                request.push_response(response)?;
                secret_answered = frame.contains_secret_input();
            }
            ActionResponse::StoredInputRejected(stored_input) => {
                return Err(format!("Action rejected Stored Input {stored_input}"));
            }
        }
    }
    Err("Action exceeded its human request limit".into())
}

fn action_integrations(contract: &str, action_id: &str) -> Result<Vec<String>, String> {
    let value: Value =
        serde_json::from_str(contract).map_err(|_| "SDK contract is invalid".to_owned())?;
    if value.get("version").and_then(Value::as_u64) != Some(1) {
        return Err("SDK contract version is invalid".into());
    }
    let actions = value
        .get("actions")
        .and_then(Value::as_array)
        .ok_or_else(|| "SDK contract is invalid".to_owned())?;
    let action = actions
        .iter()
        .find(|candidate| candidate.get("id").and_then(Value::as_str) == Some(action_id))
        .ok_or_else(|| "Action id does not exist".to_owned())?;
    action
        .get("integrations")
        .and_then(Value::as_array)
        .ok_or_else(|| "SDK contract is invalid".to_owned())?
        .iter()
        .map(|integration| {
            integration
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "SDK contract is invalid".to_owned())
        })
        .collect()
}

fn integration_tokens(integration_ids: &[String]) -> Result<BTreeMap<String, String>, String> {
    integration_ids
        .iter()
        .map(|integration_id| {
            let variable = integration_variable(integration_id);
            let token = std::env::var(&variable)
                .map_err(|_| format!("{variable} is required for this Action"))?;
            if token.is_empty() {
                return Err(format!("{variable} is required for this Action"));
            }
            Ok((integration_id.clone(), token))
        })
        .collect()
}

fn integration_variable(integration_id: &str) -> String {
    let suffix: String = integration_id
        .chars()
        .map(|character| {
            if character == '-' {
                '_'
            } else {
                character.to_ascii_uppercase()
            }
        })
        .collect();
    format!("SHIMPZ_INTEGRATION_{suffix}")
}

fn request(input: &Input, integrations: &BTreeMap<String, String>) -> Result<Invocation, String> {
    let raw = read_input(input)?;
    let value: Value =
        serde_json::from_str(&raw).map_err(|_| "--input must be a JSON object".to_owned())?;
    if !value.is_object() {
        return Err("--input must be a JSON object".into());
    }
    Ok(Invocation(serde_json::json!({
        "input": value,
        "integrations": integrations,
        "stored_inputs": {}
    })))
}

fn read_input(input: &Input) -> Result<String, String> {
    let bytes = match input {
        Input::Inline(value) => value.as_bytes().to_vec(),
        Input::File(path) => {
            let mut bytes = Vec::new();
            fs::File::open(path)
                .map_err(|_| "Action input file is unavailable")?
                .take(MAX_INPUT_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "Action input cannot be read")?;
            bytes
        }
        Input::Stdin => {
            let mut bytes = Vec::new();
            io::stdin()
                .take(MAX_INPUT_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "Action input cannot be read")?;
            bytes
        }
    };
    if bytes.is_empty() || bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err("Action input is outside the accepted size".into());
    }
    String::from_utf8(bytes).map_err(|_| "Action input must be UTF-8 JSON".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn rejects_oversized_input_file_without_full_read() {
        use std::io::Write;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let directory =
            std::env::temp_dir().join(format!("shimpz-input-fifo-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let fifo = directory.join("input");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let writer_path = fifo.clone();
        thread::spawn(move || {
            let mut writer = fs::File::create(writer_path).unwrap();
            writer
                .write_all(&vec![b'a'; usize::try_from(MAX_INPUT_BYTES).unwrap() + 1])
                .unwrap();
            thread::sleep(Duration::from_secs(30));
        });
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            sender.send(read_input(&Input::File(fifo))).unwrap();
        });

        let result = receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("read_input must fail fast without draining an unbounded file");
        assert_eq!(
            result,
            Err("Action input is outside the accepted size".to_owned())
        );
    }

    #[test]
    fn derives_integration_environment_variables() {
        assert_eq!(
            integration_variable("cloudflare-api"),
            "SHIMPZ_INTEGRATION_CLOUDFLARE_API"
        );
    }

    #[test]
    fn finds_integrations_for_the_selected_action() {
        let contract =
            r#"{"version":1,"actions":[{"id":"create-dns","integrations":["cloudflare"]}]}"#;
        assert_eq!(
            action_integrations(contract, "create-dns"),
            Ok(vec!["cloudflare".into()])
        );
    }

    #[test]
    fn preserves_json_for_strict_sdk_parsing() {
        let integrations = BTreeMap::new();
        let invocation = request(
            &Input::Inline(r#"{"zone":"example.com"}"#.into()),
            &integrations,
        )
        .expect("valid invocation");
        assert_eq!(
            invocation.0,
            serde_json::json!({
                "input": {"zone": "example.com"},
                "integrations": {},
                "stored_inputs": {}
            })
        );
    }

    #[test]
    fn serializes_into_a_zeroizing_bounded_buffer() {
        let invocation = request(
            &Input::Inline(r#"{"zone":"example.com"}"#.into()),
            &BTreeMap::new(),
        )
        .expect("valid invocation");

        let serialized: Zeroizing<Vec<u8>> =
            invocation.serialized().expect("bounded serialization");

        assert_eq!(
            serde_json::from_slice::<Value>(&serialized).expect("serialized invocation"),
            invocation.0
        );
        assert!(serialized.len() <= MAX_INVOCATION_BYTES);
    }

    #[test]
    fn traverses_every_nested_invocation_string_for_zeroization() {
        let mut invocation = serde_json::json!({
            "input": {"message": "private message", "nested": ["private token", 7]},
            "integrations": {"cloudflare": "private integration"},
            "stored_inputs": {},
            "active": true
        });

        zeroize_strings(&mut invocation);

        assert_eq!(
            invocation,
            serde_json::json!({
                "input": {"message": "", "nested": ["", 7]},
                "integrations": {"cloudflare": ""},
                "stored_inputs": {},
                "active": true
            })
        );
    }

    #[test]
    fn rejects_private_values_in_nested_response_arrays_and_keys() {
        let invocation = Invocation(serde_json::json!({
            "input": {},
            "integrations": {"cloudflare": "integration-secret"},
            "stored_inputs": {},
            "responses": []
        }));

        assert_private(
            &invocation,
            &serde_json::json!({"result": ["prefix-integration-secret-suffix"]}),
        );
        assert_private(
            &invocation,
            &serde_json::json!({"integration-secret-key": "value"}),
        );
        assert_private(
            &invocation,
            &serde_json::json!({"type": "request", "request": {"title": "integration-secret"}}),
        );
        assert!(!invocation.response_exposes_secret(&serde_json::json!({"result": "safe"})));
    }

    #[test]
    fn recomputes_password_protection_after_each_response() {
        let mut invocation = Invocation(serde_json::json!({
            "input": {},
            "integrations": {},
            "stored_inputs": {}
        }));
        let result = serde_json::json!({"result": "typed-password"});
        assert!(!invocation.response_exposes_secret(&result));

        invocation
            .push_response(serde_json::json!({
                "kind": "input:password",
                "ordinal": 0,
                "fingerprint": "a".repeat(64),
                "value": "typed-password"
            }))
            .expect("password response");

        assert!(invocation.response_exposes_secret(&result));
    }

    #[test]
    fn bounds_secret_inspection_and_ignores_short_placeholders() {
        let short = Invocation(serde_json::json!({
            "input": {},
            "integrations": {"provider": "test"},
            "stored_inputs": {"future": ""}
        }));
        assert!(!short.response_exposes_secret(&serde_json::json!({"result": "test"})));

        let protected = Invocation(serde_json::json!({
            "input": {},
            "integrations": {"provider": "12345678"},
            "stored_inputs": {}
        }));
        let at_limit = nested_array(Value::String("safe".into()), MAX_SECRET_INSPECTION_DEPTH);
        let beyond_limit = nested_array(
            Value::String("safe".into()),
            MAX_SECRET_INSPECTION_DEPTH + 1,
        );
        assert!(!protected.response_exposes_secret(&at_limit));
        assert!(protected.response_exposes_secret(&beyond_limit));
        assert!(protected.response_exposes_secret(&Value::String("12345678".into())));
    }

    fn assert_private(invocation: &Invocation, response: &Value) {
        assert!(invocation.response_exposes_secret(response));
    }

    fn nested_array(mut value: Value, depth: usize) -> Value {
        for _ in 0..depth {
            value = Value::Array(vec![value]);
        }
        value
    }

    #[test]
    fn rejects_non_object_input() {
        let error = request(&Input::Inline("42".into()), &BTreeMap::new())
            .err()
            .expect("non-object input must fail");
        assert!(
            error.contains("--input"),
            "error must name --input: {error}"
        );
    }

    #[test]
    fn rejects_key_injecting_input() {
        let injected = r#"{},"integrations":{"attacker":"token"}"#;
        let error = request(&Input::Inline(injected.into()), &BTreeMap::new())
            .err()
            .expect("injected input must fail");
        assert!(
            error.contains("--input"),
            "error must name --input: {error}"
        );
    }
}
