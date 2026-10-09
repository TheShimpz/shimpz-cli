//! Local Action invocation through the local provider-call broker (ADR-0106).

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::args::Input;
use crate::human_request::{ActionResponse, answer, parse_response};
use crate::{manifest, provider, python};

const MAX_INPUT_BYTES: u64 = 512 * 1_024;
const MAX_INVOCATION_BYTES: usize = 512 * 1_024;
const AUTHORIZATION_KINDS: [&str; 4] = ["approval", "auth:password", "auth:totp", "auth:passkey"];
/// The most Stored Inputs one Action may use, and the most replay responses one Action may receive.
const MAX_STORED_INPUTS: usize = 8;
const MAX_HUMAN_RESPONSES: usize = 8;

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

    /// Record one answered Stored Input as held for the rest of this run; only its id reaches the Action.
    fn hold_stored_input(&mut self, stored_input: &str) -> Result<(), String> {
        let stored_inputs = self
            .0
            .get_mut("stored_inputs")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "Action invocation is invalid".to_owned())?;
        if stored_inputs.iter().any(|held| held == stored_input) {
            return Err("Action requested a Stored Input it was already given".into());
        }
        if stored_inputs.len() >= MAX_STORED_INPUTS {
            return Err("Action invocation is invalid".into());
        }
        stored_inputs.push(Value::String(stored_input.to_owned()));
        Ok(())
    }

    /// Whether the transcript holds the authorization response the Action declares, when it declares one.
    fn authorized(&self, human_requests: &[String]) -> bool {
        let Some(declared) = human_requests
            .iter()
            .find(|kind| AUTHORIZATION_KINDS.contains(&kind.as_str()))
        else {
            return true;
        };
        self.0
            .get("responses")
            .and_then(Value::as_array)
            .is_some_and(|responses| {
                responses
                    .iter()
                    .any(|response| response.get("kind").and_then(Value::as_str) == Some(declared))
            })
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

pub(crate) fn run(project: &Path, action_id: &str, input: &Input) -> Result<String, String> {
    let assistant = python::Assistant::open(project)?;
    let declaration = action_declaration(&assistant.contract()?, action_id)?;
    let manifest = fs::read(project.join("shimpz.toml"))
        .map_err(|_| "Assistant manifest is unavailable".to_owned())?;
    let mut broker = broker(&manifest, &declaration)?;
    let help = manifest::stored_input_help(&manifest)?;
    let mut request = request(input)?;
    // Each round answers one request: at most every replay response and every Stored Input, then the result.
    for _ in 0..=(MAX_HUMAN_RESPONSES + MAX_STORED_INPUTS) {
        broker.begin(request.authorized(&declaration.human_requests));
        let serialized = request.serialized()?;
        let output = assistant.invoke(action_id, serialized.as_slice(), &mut |frame| {
            broker.answer(frame)
        })?;
        match parse_response(&output)? {
            ActionResponse::Request(_) if broker.calls() > 0 => {
                return Err("Action requested human input after a provider call".into());
            }
            ActionResponse::Result(result) => {
                return serde_json::to_string(&result)
                    .map_err(|_| "Action result is invalid".into());
            }
            ActionResponse::Request(frame) => {
                let display = frame.display(&assistant.render(&frame.frame())?)?;
                // A Stored Input request says what the secret is, how to get it, and where (ADR-0090).
                let shown_help = frame
                    .stored_input()
                    .and_then(|stored_input| help.get(stored_input));
                let mut response = answer(&frame, &display, shown_help)?;
                // A Stored Input stays with the broker, as Team keeps it sealed; the Action learns only its id.
                if let Some(stored_input) = frame.stored_input() {
                    let Value::String(value) = response["value"].take() else {
                        return Err("Action Stored Input answer is invalid".into());
                    };
                    request.hold_stored_input(stored_input)?;
                    broker.hold(stored_input, Zeroizing::new(value));
                } else {
                    request.push_response(response)?;
                }
            }
            ActionResponse::StoredInputRejected(stored_input) => {
                return Err(format!("Action rejected Stored Input {stored_input}"));
            }
            ActionResponse::Failure(failure) => return Err(failure.render()),
        }
    }
    Err("Action exceeded its human request limit".into())
}

/// The selected Action's reviewed declarations from the SDK contract.
struct ActionDeclaration {
    integrations: Vec<String>,
    stored_inputs: Vec<String>,
    human_requests: Vec<String>,
}

fn action_declaration(contract: &str, action_id: &str) -> Result<ActionDeclaration, String> {
    let value: Value =
        serde_json::from_str(contract).map_err(|_| "SDK contract is invalid".to_owned())?;
    if value.get("version").and_then(Value::as_u64) != Some(1) {
        return Err("SDK contract version is invalid".into());
    }
    let action = value
        .get("actions")
        .and_then(Value::as_array)
        .ok_or_else(|| "SDK contract is invalid".to_owned())?
        .iter()
        .find(|candidate| candidate.get("id").and_then(Value::as_str) == Some(action_id))
        .ok_or_else(|| "Action id does not exist".to_owned())?;
    let ids = |field: &str| -> Result<Vec<String>, String> {
        action
            .get(field)
            .and_then(Value::as_array)
            .ok_or_else(|| "SDK contract is invalid".to_owned())?
            .iter()
            .map(|id| {
                id.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "SDK contract is invalid".to_owned())
            })
            .collect()
    };
    Ok(ActionDeclaration {
        integrations: ids("integrations")?,
        stored_inputs: ids("stored_inputs")?,
        human_requests: ids("human_requests")?,
    })
}

/// The broker for one Action: the manifest's hosts and the Action's own placements, and the Creator's token for each
/// declared Integration when its `SHIMPZ_INTEGRATION_<ID>` is set.
fn broker(manifest: &[u8], declaration: &ActionDeclaration) -> Result<provider::Broker, String> {
    let (hosts, mut placements) = manifest::call_policy(manifest)?;
    placements.retain(|id, _| declaration.stored_inputs.contains(id));
    let integrations = declaration
        .integrations
        .iter()
        .map(|id| {
            let token = std::env::var(integration_variable(id))
                .ok()
                .filter(|token| !token.is_empty())
                .map(Zeroizing::new);
            (id.clone(), token)
        })
        .collect();
    provider::Broker::new(hosts, placements, integrations)
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

fn request(input: &Input) -> Result<Invocation, String> {
    let raw = read_input(input)?;
    let value: Value =
        serde_json::from_str(&raw).map_err(|_| "--input must be a JSON object".to_owned())?;
    if !value.is_object() {
        return Err("--input must be a JSON object".into());
    }
    // A direct run selects no Team file, so even an Action that declares a file input receives none (ADR-0093).
    Ok(Invocation(serde_json::json!({
        "input": value,
        "stored_inputs": [],
        "files": {},
        "operation_id": operation_id()?
    })))
}

/// Mint one logical operation id: the canonical lowercase text of a random version 4 UUID. Every human-request
/// replay of this run repeats it, exactly as Team repeats the id of one logical operation.
fn operation_id() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|_| "Action operation id cannot be generated".to_owned())?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes
        .iter()
        .fold(String::with_capacity(32), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        });
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
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
    fn preserves_json_for_strict_sdk_parsing() {
        let invocation =
            request(&Input::Inline(r#"{"zone":"example.com"}"#.into())).expect("valid invocation");
        let operation_id = invocation.0["operation_id"].clone();
        assert_eq!(
            invocation.0,
            serde_json::json!({
                "input": {"zone": "example.com"},
                "stored_inputs": [],
                "files": {},
                "operation_id": operation_id
            })
        );
    }

    #[test]
    fn finds_the_declarations_of_the_selected_action() {
        let contract = r#"{"version":1,"actions":[{"id":"create-dns","integrations":["cloudflare"],
            "stored_inputs":["api-token"],"human_requests":["approval","input:password"]}]}"#;
        let declaration = action_declaration(contract, "create-dns").expect("declaration");
        assert_eq!(declaration.integrations, ["cloudflare"]);
        assert_eq!(declaration.stored_inputs, ["api-token"]);
        assert_eq!(declaration.human_requests, ["approval", "input:password"]);
        assert!(action_declaration(contract, "other").is_err());
    }

    #[test]
    fn holds_each_answered_stored_input_once_by_id_only() {
        let mut invocation = request(&Input::Inline("{}".into())).expect("valid invocation");
        invocation
            .hold_stored_input("meta-access-token")
            .expect("first slot");
        invocation
            .hold_stored_input("meta-app-secret")
            .expect("second slot");
        assert_eq!(
            invocation.0["stored_inputs"],
            serde_json::json!(["meta-access-token", "meta-app-secret"])
        );
        assert_eq!(
            invocation.hold_stored_input("meta-app-secret"),
            Err("Action requested a Stored Input it was already given".into())
        );
        for index in 2..MAX_STORED_INPUTS {
            invocation
                .hold_stored_input(&format!("slot-{index}"))
                .expect("up to eight slots");
        }
        assert!(invocation.hold_stored_input("slot-ninth").is_err());
    }

    #[test]
    fn admits_provider_calls_only_after_the_declared_authorization_response() {
        let mut invocation = request(&Input::Inline("{}".into())).expect("valid invocation");
        let declared = ["input:password".to_owned(), "approval".to_owned()];
        assert!(invocation.authorized(&["input:text".to_owned()]));
        assert!(!invocation.authorized(&declared));
        invocation
            .push_response(serde_json::json!({"kind": "approval", "ordinal": 0, "fingerprint": "a", "value": true}))
            .expect("response");
        assert!(invocation.authorized(&declared));
    }

    #[test]
    fn mints_a_canonical_random_version_4_operation_id() {
        let first = operation_id().expect("operation id");
        let second = operation_id().expect("operation id");

        assert_ne!(first, second);
        for id in [first, second] {
            let bytes = id.as_bytes();
            assert_eq!(bytes.len(), 36, "{id}");
            for (index, byte) in bytes.iter().enumerate() {
                if [8, 13, 18, 23].contains(&index) {
                    assert_eq!(*byte, b'-', "{id}");
                } else {
                    assert!(
                        byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
                        "{id}"
                    );
                }
            }
            assert_eq!(bytes[14], b'4', "{id}");
            assert!(b"89ab".contains(&bytes[19]), "{id}");
        }
    }

    #[test]
    fn serializes_into_a_zeroizing_bounded_buffer() {
        let invocation =
            request(&Input::Inline(r#"{"zone":"example.com"}"#.into())).expect("valid invocation");

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
            "stored_inputs": [],
            "active": true
        });

        zeroize_strings(&mut invocation);

        assert_eq!(
            invocation,
            serde_json::json!({
                "input": {"message": "", "nested": ["", 7]},
                "stored_inputs": [],
                "active": true
            })
        );
    }

    #[test]
    fn rejects_non_object_input() {
        let error = request(&Input::Inline("42".into()))
            .err()
            .expect("non-object input must fail");
        assert!(
            error.contains("--input"),
            "error must name --input: {error}"
        );
    }

    #[test]
    fn rejects_key_injecting_input() {
        let injected = r#"{},"stored_inputs":["attacker"]"#;
        let error = request(&Input::Inline(injected.into()))
            .err()
            .expect("injected input must fail");
        assert!(
            error.contains("--input"),
            "error must name --input: {error}"
        );
    }
}
