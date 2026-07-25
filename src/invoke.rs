//! Local Power invocation and Account injection.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

use serde_json::Value;

use crate::args::Input;
use crate::python;

const MAX_INPUT_BYTES: u64 = 512 * 1_024;

pub(crate) fn run(project: &Path, power_id: &str, input: &Input) -> Result<String, String> {
    let contract = python::contract(project)?;
    let account_ids = power_accounts(&contract, power_id)?;
    let accounts = account_tokens(&account_ids)?;
    let request = request(input, &accounts)?;
    python::invoke(project, power_id, request.as_bytes())
}

fn power_accounts(contract: &str, power_id: &str) -> Result<Vec<String>, String> {
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
        .get("accounts")
        .and_then(Value::as_array)
        .ok_or_else(|| "SDK contract is invalid".to_owned())?
        .iter()
        .map(|account| {
            account
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "SDK contract is invalid".to_owned())
        })
        .collect()
}

fn account_tokens(account_ids: &[String]) -> Result<BTreeMap<String, String>, String> {
    account_ids
        .iter()
        .map(|account_id| {
            let variable = account_variable(account_id);
            let token = std::env::var(&variable)
                .map_err(|_| format!("{variable} is required for this Power"))?;
            if token.is_empty() {
                return Err(format!("{variable} is required for this Power"));
            }
            Ok((account_id.clone(), token))
        })
        .collect()
}

fn account_variable(account_id: &str) -> String {
    let suffix: String = account_id
        .chars()
        .map(|character| {
            if character == '-' {
                '_'
            } else {
                character.to_ascii_uppercase()
            }
        })
        .collect();
    format!("SHIMPZ_ACCOUNT_{suffix}")
}

fn request(input: &Input, accounts: &BTreeMap<String, String>) -> Result<String, String> {
    let raw = read_input(input)?;
    let value: Value =
        serde_json::from_str(&raw).map_err(|_| "--input must be a JSON object".to_owned())?;
    if !value.is_object() {
        return Err("--input must be a JSON object".into());
    }
    Ok(serde_json::json!({ "input": value, "accounts": accounts }).to_string())
}

fn read_input(input: &Input) -> Result<String, String> {
    let bytes = match input {
        Input::Inline(value) => value.as_bytes().to_vec(),
        Input::File(path) => fs::read(path).map_err(|_| "Power input file is unavailable")?,
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

    #[test]
    fn derives_account_environment_variables() {
        assert_eq!(
            account_variable("cloudflare-api"),
            "SHIMPZ_ACCOUNT_CLOUDFLARE_API"
        );
    }

    #[test]
    fn finds_accounts_for_the_selected_power() {
        let contract = r#"{"version":1,"powers":[{"id":"create-dns","accounts":["cloudflare"]}]}"#;
        assert_eq!(
            power_accounts(contract, "create-dns"),
            Ok(vec!["cloudflare".into()])
        );
    }

    #[test]
    fn preserves_json_for_strict_sdk_parsing() {
        let accounts = BTreeMap::new();
        assert_eq!(
            request(
                &Input::Inline(r#"{"zone":"example.com"}"#.into()),
                &accounts
            ),
            Ok(r#"{"accounts":{},"input":{"zone":"example.com"}}"#.into())
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
        let injected = r#"{},"accounts":{"attacker":"token"}"#;
        let error = request(&Input::Inline(injected.into()), &BTreeMap::new()).unwrap_err();
        assert!(
            error.contains("--input"),
            "error must name --input: {error}"
        );
    }
}
