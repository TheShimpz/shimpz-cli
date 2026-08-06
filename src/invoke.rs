//! Local Power invocation and Integration injection.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

use serde_json::Value;

use crate::args::Input;
use crate::human_request::{PowerResponse, answer, parse_response};
use crate::python;

const MAX_INPUT_BYTES: u64 = 512 * 1_024;

pub(crate) fn run(project: &Path, power_id: &str, input: &Input) -> Result<String, String> {
    let assistant = python::Assistant::open(project)?;
    let contract = assistant.contract()?;
    let integration_ids = power_integrations(&contract, power_id)?;
    let integrations = integration_tokens(&integration_ids)?;
    let mut request = request(input, &integrations)?;
    for _ in 0..=8 {
        let output = assistant.invoke(power_id, request.to_string().as_bytes())?;
        match parse_response(&output)? {
            PowerResponse::Result(result) => {
                return serde_json::to_string(&result)
                    .map_err(|_| "Power result is invalid".into());
            }
            PowerResponse::Request(frame) => {
                let response = answer(&frame)?;
                request
                    .as_object_mut()
                    .ok_or_else(|| "Power invocation is invalid".to_owned())?
                    .entry("responses")
                    .or_insert_with(|| Value::Array(Vec::new()))
                    .as_array_mut()
                    .ok_or_else(|| "Power invocation is invalid".to_owned())?
                    .push(response);
            }
        }
    }
    Err("Power exceeded its human request limit".into())
}

fn power_integrations(contract: &str, power_id: &str) -> Result<Vec<String>, String> {
    let value: Value =
        serde_json::from_str(contract).map_err(|_| "SDK contract is invalid".to_owned())?;
    if value.get("version").and_then(Value::as_u64) != Some(1) {
        return Err("SDK contract version is invalid".into());
    }
    let powers = value
        .get("powers")
        .and_then(Value::as_array)
        .ok_or_else(|| "SDK contract is invalid".to_owned())?;
    let power = powers
        .iter()
        .find(|candidate| candidate.get("id").and_then(Value::as_str) == Some(power_id))
        .ok_or_else(|| "Power id does not exist".to_owned())?;
    power
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
                .map_err(|_| format!("{variable} is required for this Power"))?;
            if token.is_empty() {
                return Err(format!("{variable} is required for this Power"));
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

fn request(input: &Input, integrations: &BTreeMap<String, String>) -> Result<Value, String> {
    let raw = read_input(input)?;
    let value: Value =
        serde_json::from_str(&raw).map_err(|_| "--input must be a JSON object".to_owned())?;
    if !value.is_object() {
        return Err("--input must be a JSON object".into());
    }
    Ok(serde_json::json!({ "input": value, "integrations": integrations }))
}

fn read_input(input: &Input) -> Result<String, String> {
    let bytes = match input {
        Input::Inline(value) => value.as_bytes().to_vec(),
        Input::File(path) => {
            let mut bytes = Vec::new();
            fs::File::open(path)
                .map_err(|_| "Power input file is unavailable")?
                .take(MAX_INPUT_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "Power input cannot be read")?;
            bytes
        }
        Input::Stdin => {
            let mut bytes = Vec::new();
            io::stdin()
                .take(MAX_INPUT_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "Power input cannot be read")?;
            bytes
        }
    };
    if bytes.is_empty() || bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err("Power input is outside the accepted size".into());
    }
    String::from_utf8(bytes).map_err(|_| "Power input must be UTF-8 JSON".into())
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
            Err("Power input is outside the accepted size".to_owned())
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
    fn finds_integrations_for_the_selected_power() {
        let contract =
            r#"{"version":1,"powers":[{"id":"create-dns","integrations":["cloudflare"]}]}"#;
        assert_eq!(
            power_integrations(contract, "create-dns"),
            Ok(vec!["cloudflare".into()])
        );
    }

    #[test]
    fn preserves_json_for_strict_sdk_parsing() {
        let integrations = BTreeMap::new();
        assert_eq!(
            request(
                &Input::Inline(r#"{"zone":"example.com"}"#.into()),
                &integrations
            ),
            Ok(serde_json::json!({
                "input": {"zone": "example.com"},
                "integrations": {}
            }))
        );
    }

    #[test]
    fn rejects_non_object_input() {
        let error = request(&Input::Inline("42".into()), &BTreeMap::new()).unwrap_err();
        assert!(
            error.contains("--input"),
            "error must name --input: {error}"
        );
    }

    #[test]
    fn rejects_key_injecting_input() {
        let injected = r#"{},"integrations":{"attacker":"token"}"#;
        let error = request(&Input::Inline(injected.into()), &BTreeMap::new()).unwrap_err();
        assert!(
            error.contains("--input"),
            "error must name --input: {error}"
        );
    }
}
