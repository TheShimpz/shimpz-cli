//! Exercises `shimpz assistant run` with catalog-reference human requests through the CLI process boundary.

#![cfg(unix)]

#[path = "../src/fake_tool.rs"]
mod fake_tool;
#[path = "support/run_workspace.rs"]
mod run_workspace;

use run_workspace::{RECORD_INVOCATION, Workspace};
use serde_json::{Value, json};

/// A canonical frame produced by the Python reference fingerprint (`sort_keys`, compact, no ASCII escaping).
const FRAME: &str = r#"{"type":"request","request":{"kind":"input:choice","ordinal":0,"title":{"message":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","params":{}},"description":{"message":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","params":{"zone":"example.com"}},"label":{"message":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","params":{}},"required":true,"options":[{"value":"proxied","label":{"message":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","params":{}},"description":null},{"value":"dns-only","label":{"message":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","params":{}},"description":null}],"fingerprint":"20e90c08af91d7f9a7c1a34ee04e0126c7b98df955678ca850c98c07de8de493"}}"#;
const RENDERED: &str = r#"{"kind":"input:choice","ordinal":0,"title":"Choose the DNS mode","description":"Choose how example.com is served.","label":"Mode","required":true,"options":[{"value":"proxied","label":"Proxied","description":null},{"value":"dns-only","label":"DNS only","description":null}],"fingerprint":"20e90c08af91d7f9a7c1a34ee04e0126c7b98df955678ca850c98c07de8de493"}"#;
const FINGERPRINT: &str = "20e90c08af91d7f9a7c1a34ee04e0126c7b98df955678ca850c98c07de8de493";

/// The fake `uv` arms: one Action without Integrations whose first `invoke` pauses on `FRAME`; `render` records its
/// stdin and answers `rendered` with `render_exit`.
fn workspace_with(name: &str, rendered: &str, render_exit: u8) -> Workspace {
    let cases = format!(
        r#"      contract) echo '{{"version":1,"actions":[{{"id":"greet","integrations":[]}}]}}'; exit 0;;
      render) cat > "$ROOT/render-stdin.json"; echo '{rendered}'; exit {render_exit};;
      invoke)
        {RECORD_INVOCATION}
        if [ "$count" = 0 ]; then echo '{FRAME}'; else echo '{{"type":"result","result":{{"mode":"chosen"}}}}'; fi
        exit 0;;"#
    );
    Workspace::new("run-render", name, &cases)
}

#[test]
fn shows_the_english_rendering_and_replays_the_canonical_answer() {
    let workspace = workspace_with("choice", RENDERED, 0);
    let output = workspace.run("2\n", &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let shown = format!("{stdout}{stderr}");
    assert!(output.status.success(), "{shown}");
    assert!(stdout.contains(r#""mode":"chosen""#), "{stdout}");
    for text in [
        "Choose the DNS mode",
        "Choose how example.com is served.",
        "Mode",
        "1. Proxied",
        "2. DNS only",
    ] {
        assert!(shown.contains(text), "{text}: {shown}");
    }
    assert!(!shown.contains("aaaaaaaa"), "{shown}");

    let frame: Value = serde_json::from_str(FRAME).unwrap();
    assert_eq!(
        workspace.json("render-stdin.json"),
        json!({"request": frame["request"]})
    );
    assert_eq!(
        workspace.json("invoke-1.json")["responses"],
        json!([{"kind": "input:choice", "ordinal": 0, "fingerprint": FINGERPRINT, "value": "dns-only"}])
    );
}

#[test]
fn refuses_a_rendering_that_changes_a_canonical_option_value() {
    let workspace = workspace_with("changed", &RENDERED.replace("dns-only", "delete-all"), 0);
    let output = workspace.run("2\n", &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("rendered an invalid human request"),
        "{stderr}"
    );
    assert!(!workspace.root.join("invoke-1.json").exists());
}

#[test]
fn reports_a_render_failure_without_bridge_diagnostics() {
    let workspace = workspace_with("failed", "{}", 1);
    let output = workspace.run("2\n", &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("cannot be rendered"), "{stderr}");
    assert!(!workspace.root.join("invoke-1.json").exists());
}
