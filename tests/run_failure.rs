//! Exercises `shimpz assistant run` with handled failure frames and transport faults through the CLI process boundary.

#![cfg(unix)]

#[path = "../src/fake_tool.rs"]
mod fake_tool;
#[path = "support/run_workspace.rs"]
mod run_workspace;

use std::process::Output;

use run_workspace::{RECORD_INVOCATION, Workspace};
use serde_json::Value;

const TOKEN: &str = "integration-secret-token";
const FAILURE: &str = r#"{"type":"failure","failure":{"error_type":"httpx.HTTPStatusError","message":"Client error 404 Not Found","provider":"api.example.com","http_status":404,"response_excerpt":"{\"error\":\"zone not found\"}","redacted":false,"truncated":false}}"#;
const REQUEST: &str = r#"{"type":"request","request":{"kind":"approval","ordinal":0,"title":{"message":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","params":{}},"description":{"message":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","params":{}},"fingerprint":"a86d7cdfaf3de9ed43148b22ef4680682b65179bcd1667ed3986a873603df7ad"}}"#;

/// The fake `uv` arms: one Action that declares the `cloudflare` Integration and runs `invoke` once per call.
fn workspace_with(name: &str, invoke: &str) -> Workspace {
    let cases = format!(
        r#"      contract) echo '{{"version":1,"actions":[{{"id":"greet","integrations":["cloudflare"],"stored_inputs":[],"human_requests":["approval"]}}]}}'; exit 0;;
      render) cat > /dev/null; echo '{{"kind":"approval","ordinal":0,"title":"Approve","description":"Approve the greeting.","fingerprint":"a86d7cdfaf3de9ed43148b22ef4680682b65179bcd1667ed3986a873603df7ad"}}'; exit 0;;
      invoke)
        {RECORD_INVOCATION}
        {invoke}"#
    );
    Workspace::new("run-failure", name, &cases)
}

fn run(workspace: &Workspace, answer: &str) -> Output {
    workspace.run(answer, &[("SHIMPZ_INTEGRATION_CLOUDFLARE", TOKEN)])
}

fn invocation(workspace: &Workspace, index: usize) -> Value {
    workspace.json(&format!("invoke-{index}.json"))
}

fn shown(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn shows_the_sanitized_failure_and_keeps_one_operation_id_across_replay() {
    let workspace = workspace_with(
        "handled",
        &format!(
            r#"if [ "$count" = 0 ]; then echo '{REQUEST}'; else echo '{FAILURE}'; fi; exit 0;;"#
        ),
    );

    let output = run(&workspace, "y\n");
    let shown = shown(&output);

    assert!(!output.status.success(), "{shown}");
    for text in [
        "Action failed: httpx.HTTPStatusError: Client error 404 Not Found",
        "Provider: api.example.com (HTTP 404)",
        "Response: {\"error\":\"zone not found\"}",
    ] {
        assert!(shown.contains(text), "{text}: {shown}");
    }
    assert!(!shown.contains(TOKEN), "{shown}");
    let first = invocation(&workspace, 0)["operation_id"].clone();
    let operation_id = first.as_str().expect("operation id");
    assert_eq!(operation_id.len(), 36);
    assert_eq!(&operation_id[14..15], "4");
    assert_eq!(invocation(&workspace, 1)["operation_id"], first);
}

#[test]
fn refuses_a_failure_frame_outside_the_closed_contract() {
    let frame = FAILURE.replace(
        r#""truncated":false}"#,
        r#""truncated":false,"stack":"Traceback"}"#,
    );
    let workspace = workspace_with("open", &format!("echo '{frame}'; exit 0;;"));

    let shown = shown(&run(&workspace, ""));

    assert!(
        shown.contains("Python SDK failure frame is invalid"),
        "{shown}"
    );
    assert!(!shown.contains("Traceback"), "{shown}");
}

#[test]
fn reports_only_the_exit_status_of_a_failed_action_process() {
    let workspace = workspace_with(
        "nonzero",
        &format!("echo 'raw {TOKEN} output' >&2; exit 3;;"),
    );

    let output = run(&workspace, "");
    let shown = shown(&output);

    assert!(!output.status.success());
    assert!(
        shown.contains("without a response frame (exit status 3)"),
        "{shown}"
    );
    assert!(!shown.contains(TOKEN), "{shown}");
}

#[test]
fn refuses_an_oversized_response_frame() {
    let workspace = workspace_with(
        "oversized",
        "head -c 600000 /dev/zero | tr '\\0' 'a'; exit 0;;",
    );

    let shown = shown(&run(&workspace, ""));

    assert!(shown.contains("larger than 512 KiB"), "{shown}");
}

#[test]
fn refuses_a_successful_frame_with_stderr_output_without_showing_it() {
    let workspace = workspace_with(
        "stderr",
        &format!("echo 'warning {TOKEN}' >&2; echo '{FAILURE}'; exit 0;;"),
    );

    let output = run(&workspace, "");
    let shown = shown(&output);

    assert!(!output.status.success());
    assert!(shown.contains("bytes to stderr"), "{shown}");
    assert!(!shown.contains(TOKEN), "{shown}");
    assert!(!shown.contains("warning"), "{shown}");
}
