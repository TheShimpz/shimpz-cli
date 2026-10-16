//! The lifecycle's Local Admin client: the Admin listener attestation, the Local authentication-state contract, and
//! the Supervisor-authorized Space reset.

use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::output;
use crate::space::docker::Engine;
use crate::space::graph;
use crate::space::state::Installed;

use super::Context;

impl Context {
    pub(super) fn admin_attestation(&self) -> Result<AdminAttestation, String> {
        let record = self.engine.run_output([
            "inspect",
            "--type=container",
            "--format",
            "{{.State.Running}}|{{index .Config.Labels \"com.docker.compose.project\"}}|{{index .Config.Labels \"com.docker.compose.service\"}}|{{json .HostConfig.PortBindings}}",
            graph::ADMIN.container,
        ]);
        match record {
            Ok(record) => parse_admin_attestation(&record),
            Err(_) => Ok(AdminAttestation::Absent),
        }
    }
}

// Admin bounds its authoritative Team reset call at 180 seconds; the client must outlast it.
const ADMIN_RESET_TIMEOUT: Duration = Duration::from_secs(210);

const ADMIN_SESSION_TIMEOUT: Duration = Duration::from_secs(5);

const HOST_RESET_CAPABILITY_SECONDS: u64 = 120;

const RESET_INCOMPLETE: &str = "the Space reset did not complete; re-run shimpz reset";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AdminAttestation {
    Running { port: u16 },
    Stopped,
    Absent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AdminAuthenticationState {
    Uninitialized,
    EnrollmentRequired,
    Configured,
    RecoveryRequired,
}

struct HostResetCapability {
    secret: Zeroizing<String>,
    document: Vec<u8>,
}

fn parse_admin_attestation(record: &str) -> Result<AdminAttestation, String> {
    if record.len() > 4_096 || record.contains('\r') {
        return Err("the owned Admin listener attestation is malformed".into());
    }
    let mut lines = record.lines();
    let line = lines
        .next()
        .filter(|line| !line.is_empty() && lines.next().is_none())
        .ok_or_else(|| "the owned Admin listener attestation is malformed".to_owned())?;
    let fields: Vec<_> = line.splitn(4, '|').collect();
    if fields.len() != 4 || fields[1] != graph::PROJECT || fields[2] != graph::ADMIN.service {
        return Err("the owned Admin listener identity is invalid".into());
    }
    let binding_map = serde_json::from_str::<serde_json::Value>(fields[3])
        .map_err(|_| "the owned Admin listener binding is malformed".to_owned())?;
    let binding_map = binding_map
        .as_object()
        .filter(|bindings| bindings.len() == 1 && bindings.contains_key("4600/tcp"))
        .ok_or_else(|| "the owned Admin listener binding is invalid".to_owned())?;
    let bindings = binding_map["4600/tcp"]
        .as_array()
        .filter(|bindings| !bindings.is_empty() && bindings.len() <= 2)
        .ok_or_else(|| "the owned Admin listener binding is invalid".to_owned())?;
    let mut port = None;
    let mut ipv4 = false;
    for binding in bindings {
        let binding = binding
            .as_object()
            .filter(|binding| {
                binding.len() == 2
                    && binding.contains_key("HostIp")
                    && binding.contains_key("HostPort")
            })
            .ok_or_else(|| "the owned Admin listener binding is malformed".to_owned())?;
        let host = binding["HostIp"]
            .as_str()
            .filter(|host| matches!(*host, "127.0.0.1" | "::1"))
            .ok_or_else(|| "the owned Admin listener is not loopback-only".to_owned())?;
        let current = binding["HostPort"]
            .as_str()
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|value| *value >= 1024)
            .ok_or_else(|| "the owned Admin listener port is invalid".to_owned())?;
        if port.is_some_and(|expected| expected != current) || (host == "127.0.0.1" && ipv4) {
            return Err("the owned Admin listener binding is ambiguous".into());
        }
        port = Some(current);
        ipv4 |= host == "127.0.0.1";
    }
    if !ipv4 {
        return Err("the owned Admin listener has no IPv4 loopback binding".into());
    }
    match fields[0] {
        "true" => Ok(AdminAttestation::Running {
            port: port.expect("a valid binding has a port"),
        }),
        "false" => Ok(AdminAttestation::Stopped),
        _ => Err("the owned Admin container state is malformed".into()),
    }
}

fn admin_authentication_state_response(
    status: u16,
    body: &serde_json::Value,
) -> Result<AdminAuthenticationState, String> {
    let invalid = || "Admin returned an invalid Local authentication-state contract".to_owned();
    if status != 200 {
        return Err(invalid());
    }
    let object = body.as_object().ok_or_else(invalid)?;
    if object.len() != 4
        || object.get("profile").and_then(serde_json::Value::as_str) != Some("local")
        || object
            .get("authenticated")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        || object
            .get("initialized")
            .and_then(serde_json::Value::as_bool)
            .is_none()
    {
        return Err(invalid());
    }
    match (
        object
            .get("authentication_state")
            .and_then(serde_json::Value::as_str),
        object["initialized"].as_bool(),
    ) {
        (Some("uninitialized"), Some(false)) => Ok(AdminAuthenticationState::Uninitialized),
        (Some("enrollment-required"), Some(true)) => {
            Ok(AdminAuthenticationState::EnrollmentRequired)
        }
        (Some("configured"), Some(true)) => Ok(AdminAuthenticationState::Configured),
        (Some("recovery-required"), Some(true)) => Ok(AdminAuthenticationState::RecoveryRequired),
        _ => Err(invalid()),
    }
}

pub(super) fn admin_authentication_state_probe_response(
    response: &str,
) -> Result<AdminAuthenticationState, String> {
    match response {
        "uninitialized" => Ok(AdminAuthenticationState::Uninitialized),
        "enrollment-required" => Ok(AdminAuthenticationState::EnrollmentRequired),
        "configured" => Ok(AdminAuthenticationState::Configured),
        "recovery-required" => Ok(AdminAuthenticationState::RecoveryRequired),
        _ => Err("the selected Admin returned an invalid authentication-state contract".into()),
    }
}

/// The Local Admin session endpoint on its published loopback `port`.
fn admin_session_url(port: u16) -> String {
    format!("http://{}:{port}/api/session", graph::ADMIN_PUBLISHED_HOST)
}

pub(super) fn admin_authentication_state(port: u16) -> Result<AdminAuthenticationState, String> {
    let mut response = crate::http::agent(ADMIN_SESSION_TIMEOUT)
        .post(admin_session_url(port))
        .send_empty()
        .map_err(|_| "Admin did not provide the Local authentication-state contract".to_owned())?;
    let status = response.status().as_u16();
    let body: serde_json::Value = response
        .body_mut()
        .with_config()
        .limit(1_024)
        .read_json()
        .map_err(|_| "Admin returned an invalid Local authentication-state contract".to_owned())?;
    admin_authentication_state_response(status, &body)
}

pub(super) fn admin_available(port: u16) -> bool {
    let agent = crate::http::agent(Duration::from_secs(2));
    for _ in 0..30 {
        if agent
            .post(admin_session_url(port))
            .send_empty()
            .is_ok_and(|response| response.status().as_u16() == 200)
        {
            return true;
        }
        thread::sleep(Duration::from_millis(500));
    }
    false
}

#[derive(Debug, Eq, PartialEq)]
enum AdminResetDecision {
    Complete,
    PasswordRequired,
}

fn admin_reset_decision(
    status: u16,
    body: &serde_json::Value,
    retry_after: Option<&str>,
    password_presented: bool,
) -> Result<AdminResetDecision, String> {
    if status == 200
        && body.as_object().is_some_and(|object| {
            object.len() == 1 && object.get("reset") == Some(&serde_json::Value::Bool(true))
        })
    {
        return Ok(AdminResetDecision::Complete);
    }
    if !password_presented
        && status == 409
        && body.as_object().is_some_and(|object| {
            object.len() == 2
                && object.get("code").and_then(serde_json::Value::as_str)
                    == Some("supervisor-password-required")
                && object
                    .get("detail")
                    .and_then(serde_json::Value::as_str)
                    .is_some()
        })
    {
        return Ok(AdminResetDecision::PasswordRequired);
    }
    if password_presented {
        match status {
            401 => return Err("the Supervisor password was rejected".into()),
            429 => {
                let wait = match retry_after_seconds(retry_after) {
                    Some(1) => "wait 1 second".to_owned(),
                    Some(seconds) => format!("wait {seconds} seconds"),
                    None => "wait one minute".to_owned(),
                };
                return Err(format!(
                    "too many Supervisor password attempts; {wait}, then re-run shimpz reset"
                ));
            }
            _ => {}
        }
    }
    Err(RESET_INCOMPLETE.into())
}

fn request_admin_reset(
    port: u16,
    capability: &str,
    password: Option<&str>,
) -> Result<AdminResetDecision, String> {
    let agent = crate::http::agent(ADMIN_RESET_TIMEOUT);
    let payload = match password {
        Some(password) => serde_json::json!({"capability": capability, "password": password}),
        None => serde_json::json!({"capability": capability}),
    };
    let body = serde_json::to_string(&payload)
        .map_err(|_| "could not encode the authorized Space reset".to_owned())?;
    let request = ureq::http::Request::delete(format!(
        "http://{}:{port}/api/space/host",
        graph::ADMIN_PUBLISHED_HOST
    ))
    .header("Content-Type", "application/json")
    .body(body)
    .map_err(|_| "could not build the authorized Space reset".to_owned())?;
    let mut response = agent
        .run(request)
        .map_err(|_| RESET_INCOMPLETE.to_owned())?;
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let response_body: serde_json::Value = response
        .body_mut()
        .with_config()
        .limit(1_024)
        .read_json()
        .map_err(|_| RESET_INCOMPLETE.to_owned())?;
    admin_reset_decision(
        status,
        &response_body,
        retry_after.as_deref(),
        password.is_some(),
    )
}

fn retry_after_seconds(value: Option<&str>) -> Option<u16> {
    let value = value?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value
        .parse::<u16>()
        .ok()
        .filter(|seconds| (1..=3_600).contains(seconds))
}

fn generate_host_reset_capability(space_id: &str) -> Result<HostResetCapability, String> {
    let mut secret_bytes = [0_u8; 32];
    getrandom::fill(&mut secret_bytes)
        .map_err(|_| "the system random source is unavailable".to_owned())?;
    let secret = crate::digest::lower_hex(&secret_bytes);
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "the system clock cannot authorize a Local reset".to_owned())?
        .as_secs();
    let expires_at = created_at
        .checked_add(HOST_RESET_CAPABILITY_SECONDS)
        .ok_or_else(|| "the system clock cannot authorize a Local reset".to_owned())?;
    let capability_sha256 = crate::digest::sha256_hex(&secret_bytes);
    let document = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "purpose": "space-reset",
        "space_id": space_id,
        "created_at": created_at,
        "expires_at": expires_at,
        "capability_sha256": capability_sha256,
    }))
    .map_err(|_| "could not encode the Local reset capability".to_owned())?;
    Ok(HostResetCapability {
        secret: Zeroizing::new(secret),
        document,
    })
}

fn projected_admin_reset(
    engine: &Engine,
    installed: &Installed,
    password: Option<&str>,
) -> Result<AdminResetDecision, String> {
    let capability = generate_host_reset_capability(&installed.space_id)?;
    engine.project_reset_capability(&installed.admin_image, &capability.document)?;
    let result = request_admin_reset(installed.port, capability.secret.as_str(), password);
    let cleanup = engine.clear_reset_capability(&installed.admin_image);
    match (result, cleanup) {
        (Ok(decision), Ok(())) => Ok(decision),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(format!("{error}; {cleanup_error}")),
    }
}

pub(super) fn admin_reset(engine: &Engine, installed: &Installed) -> Result<(), String> {
    output::progress("Authorizing the Shimpz Space reset...");
    if projected_admin_reset(engine, installed, None)? == AdminResetDecision::Complete {
        return Ok(());
    }
    let password = Zeroizing::new(
        rpassword::prompt_password("Supervisor password: ")
            .map_err(|_| "could not read the Supervisor password".to_owned())?,
    );
    if password.is_empty() {
        return Err("the Supervisor password is required".into());
    }
    output::progress("Verifying the Supervisor password...");
    if projected_admin_reset(engine, installed, Some(password.as_str()))?
        == AdminResetDecision::Complete
    {
        Ok(())
    } else {
        Err(RESET_INCOMPLETE.into())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::super::outcome::candidate_admission_error;
    use super::{
        AdminAttestation, AdminAuthenticationState, AdminResetDecision,
        HOST_RESET_CAPABILITY_SECONDS, admin_authentication_state_probe_response,
        admin_authentication_state_response, admin_reset_decision, generate_host_reset_capability,
        parse_admin_attestation,
    };

    #[test]
    fn host_reset_prompts_only_for_the_exact_password_required_decision() {
        assert_eq!(
            admin_reset_decision(200, &serde_json::json!({"reset": true}), None, false),
            Ok(AdminResetDecision::Complete)
        );
        assert_eq!(
            admin_reset_decision(
                409,
                &serde_json::json!({
                    "code": "supervisor-password-required",
                    "detail": "Supervisor password is required"
                }),
                None,
                false,
            ),
            Ok(AdminResetDecision::PasswordRequired)
        );
        for (status, body) in [
            (200, serde_json::json!({"reset": true, "extra": true})),
            (409, serde_json::json!({"detail": "password required"})),
            (
                503,
                serde_json::json!({"code": "supervisor-password-required"}),
            ),
        ] {
            assert!(
                admin_reset_decision(status, &body, None, false)
                    .unwrap_err()
                    .contains("re-run shimpz reset")
            );
        }
    }

    #[test]
    fn generated_host_reset_capability_is_space_bound_bounded_and_secret_free() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let capability = generate_host_reset_capability("space-0123456789abcdef01234567").unwrap();
        let document: serde_json::Value = serde_json::from_slice(&capability.document).unwrap();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert_eq!(capability.secret.len(), 64);
        assert!(
            capability
                .secret
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        assert_eq!(document["version"], 1);
        assert_eq!(document["purpose"], "space-reset");
        assert_eq!(document["space_id"], "space-0123456789abcdef01234567");
        assert!(document["created_at"].as_u64().unwrap() >= before);
        assert!(document["created_at"].as_u64().unwrap() <= after);
        assert_eq!(
            document["expires_at"].as_u64().unwrap() - document["created_at"].as_u64().unwrap(),
            HOST_RESET_CAPABILITY_SECONDS
        );
        let secret = hex_bytes(capability.secret.as_str());
        assert_eq!(
            document["capability_sha256"],
            crate::digest::sha256_hex(&secret)
        );
        assert!(
            !String::from_utf8(capability.document)
                .unwrap()
                .contains(capability.secret.as_str())
        );
    }

    fn hex_bytes(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn local_session(authentication_state: &str, initialized: bool) -> serde_json::Value {
        serde_json::json!({
            "profile": "local",
            "authenticated": false,
            "initialized": initialized,
            "authentication_state": authentication_state
        })
    }

    #[test]
    fn release_gate_accepts_only_exact_consistent_local_authentication_states() {
        for (name, initialized, expected) in [
            (
                "uninitialized",
                false,
                AdminAuthenticationState::Uninitialized,
            ),
            (
                "enrollment-required",
                true,
                AdminAuthenticationState::EnrollmentRequired,
            ),
            ("configured", true, AdminAuthenticationState::Configured),
            (
                "recovery-required",
                true,
                AdminAuthenticationState::RecoveryRequired,
            ),
        ] {
            assert_eq!(
                admin_authentication_state_response(200, &local_session(name, initialized)),
                Ok(expected)
            );
        }

        for (status, body) in [
            (503, local_session("configured", true)),
            (200, local_session("configured", false)),
            (200, local_session("unknown", true)),
            (
                200,
                serde_json::json!({
                    "profile": "unknown",
                    "authenticated": false,
                    "initialized": true,
                    "authentication_state": "configured"
                }),
            ),
            (
                200,
                serde_json::json!({
                    "profile": "local",
                    "authenticated": false,
                    "initialized": true,
                    "authentication_state": "configured",
                    "extra": true
                }),
            ),
        ] {
            assert!(admin_authentication_state_response(status, &body).is_err());
        }
    }

    #[test]
    fn candidate_authentication_probe_accepts_only_exact_bounded_states() {
        for (value, expected) in [
            ("uninitialized", AdminAuthenticationState::Uninitialized),
            (
                "enrollment-required",
                AdminAuthenticationState::EnrollmentRequired,
            ),
            ("configured", AdminAuthenticationState::Configured),
            (
                "recovery-required",
                AdminAuthenticationState::RecoveryRequired,
            ),
        ] {
            assert_eq!(
                admin_authentication_state_probe_response(value),
                Ok(expected)
            );
        }
        for invalid in ["", "configured\n", "recovery_required", "future-state"] {
            assert!(admin_authentication_state_probe_response(invalid).is_err());
        }
        assert_eq!(
            candidate_admission_error("the candidate check failed"),
            "the candidate check failed; the installed release is unchanged"
        );
    }

    #[test]
    fn host_reset_distinguishes_throttling_from_password_rejection() {
        assert!(
            admin_reset_decision(
                429,
                &serde_json::json!({"detail": "hidden"}),
                Some("1"),
                true
            )
            .unwrap_err()
            .contains("wait 1 second")
        );
        assert!(
            admin_reset_decision(
                429,
                &serde_json::json!({"detail": "hidden"}),
                Some("60"),
                true
            )
            .unwrap_err()
            .contains("wait 60 seconds")
        );
        for invalid in [None, Some("0"), Some("3601"), Some("untrusted\nvalue")] {
            let error =
                admin_reset_decision(429, &serde_json::json!({"detail": "hidden"}), invalid, true)
                    .unwrap_err();
            assert!(error.contains("wait one minute"));
            assert!(!error.contains("untrusted"));
        }
        assert!(
            admin_reset_decision(401, &serde_json::json!({"detail": "hidden"}), None, true)
                .unwrap_err()
                .contains("password was rejected")
        );
    }

    #[test]
    fn accepts_only_an_attested_loopback_admin_listener() {
        assert_eq!(
            parse_admin_attestation(
                "true|shimpz-space|admin|{\"4600/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"7777\"}]}\n"
            ),
            Ok(AdminAttestation::Running { port: 7777 })
        );
        assert_eq!(
            parse_admin_attestation(
                "true|shimpz-space|admin|{\"4600/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"7777\"},{\"HostIp\":\"::1\",\"HostPort\":\"7777\"}]}\n"
            ),
            Ok(AdminAttestation::Running { port: 7777 })
        );
        assert_eq!(
            parse_admin_attestation(
                "false|shimpz-space|admin|{\"4600/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"7777\"}]}\n"
            ),
            Ok(AdminAttestation::Stopped)
        );
        for invalid in [
            "true|foreign|admin|{\"4600/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"7777\"}]}",
            "true|shimpz-space|team|{\"4600/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"7777\"}]}",
            "true|shimpz-space|admin|{\"4600/tcp\":[{\"HostIp\":\"0.0.0.0\",\"HostPort\":\"7777\"}]}",
            "true|shimpz-space|admin|{\"4600/tcp\":[{\"HostIp\":\"::1\",\"HostPort\":\"7777\"}]}",
            "true|shimpz-space|admin|{\"4600/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"80\"}]}",
            "true|shimpz-space|admin|{\"4600/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"7777\"},{\"HostIp\":\"::1\",\"HostPort\":\"8888\"}]}",
            "true|shimpz-space|admin|{\"4600/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"7777\"}],\"80/tcp\":[]}",
            "true|shimpz-space|admin|null",
            "true|shimpz-space|admin|{}",
            "maybe|shimpz-space|admin|{\"4600/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"7777\"}]}",
        ] {
            assert!(parse_admin_attestation(invalid).is_err(), "{invalid}");
        }
    }
}
