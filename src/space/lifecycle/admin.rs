//! The lifecycle's Local Admin client: the Admin listener attestation, the Local authentication-state contract, and
//! the Supervisor-authorized Space reset.

use std::fs;
use std::io::Read;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ureq::Agent;
use zeroize::Zeroizing;

use crate::output;
use crate::space::docker::Engine;
use crate::space::state::Installed;

use super::Context;

impl Context {
    pub(super) fn admin_attestation(&self) -> Result<AdminAttestation, String> {
        let record = self.engine.run_output([
            "inspect",
            "--type=container",
            "--format",
            "{{.State.Running}}|{{index .Config.Labels \"com.docker.compose.project\"}}|{{index .Config.Labels \"com.docker.compose.service\"}}|{{json .HostConfig.PortBindings}}",
            "shimpz-admin",
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

pub(super) const HOST_RESET_CAPABILITY_SECONDS: u64 = 120;

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

pub(super) struct HostResetCapability {
    pub(super) secret: Zeroizing<String>,
    pub(super) document: Vec<u8>,
}

pub(super) fn parse_admin_attestation(record: &str) -> Result<AdminAttestation, String> {
    if record.len() > 4_096 || record.contains('\r') {
        return Err("the owned Admin listener attestation is malformed".into());
    }
    let mut lines = record.lines();
    let line = lines
        .next()
        .filter(|line| !line.is_empty() && lines.next().is_none())
        .ok_or_else(|| "the owned Admin listener attestation is malformed".to_owned())?;
    let fields: Vec<_> = line.splitn(4, '|').collect();
    if fields.len() != 4 || fields[1] != "shimpz-space" || fields[2] != "admin" {
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

pub(super) fn admin_authentication_state_response(
    status: u16,
    body: &serde_json::Value,
) -> Result<AdminAuthenticationState, String> {
    let invalid = || "Admin returned an invalid Local authentication-state contract".to_owned();
    if status != 200 {
        return Err(invalid());
    }
    let object = body.as_object().ok_or_else(invalid)?;
    if object.len() != 5
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
    let features = object
        .get("features")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid)?;
    if features.len() != 1
        || features
            .get("teamCredentials")
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

pub(super) fn admin_authentication_state(port: u16) -> Result<AdminAuthenticationState, String> {
    let config = Agent::config_builder()
        .timeout_global(Some(ADMIN_SESSION_TIMEOUT))
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    let agent = Agent::new_with_config(config);
    let mut response = agent
        .post(format!("http://127.0.0.1:{port}/api/session"))
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
    let config = Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(2)))
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    let agent = Agent::new_with_config(config);
    for _ in 0..30 {
        if agent
            .post(format!("http://127.0.0.1:{port}/api/session"))
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
pub(super) enum AdminResetDecision {
    Complete,
    PasswordRequired,
}

pub(super) fn admin_reset_decision(
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
    let config = Agent::config_builder()
        .timeout_global(Some(ADMIN_RESET_TIMEOUT))
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    let agent = Agent::new_with_config(config);
    let payload = match password {
        Some(password) => serde_json::json!({"capability": capability, "password": password}),
        None => serde_json::json!({"capability": capability}),
    };
    let body = serde_json::to_string(&payload)
        .map_err(|_| "could not encode the authorized Space reset".to_owned())?;
    let request = ureq::http::Request::delete(format!("http://127.0.0.1:{port}/api/space/host"))
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

pub(super) fn generate_host_reset_capability(
    space_id: &str,
) -> Result<HostResetCapability, String> {
    let mut source = fs::File::open("/dev/urandom")
        .map_err(|_| "the system random source is unavailable".to_owned())?;
    let mut secret_bytes = [0_u8; 32];
    source
        .read_exact(&mut secret_bytes)
        .map_err(|_| "could not generate the Local reset capability".to_owned())?;
    let mut secret = String::with_capacity(64);
    for byte in secret_bytes {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        secret.push(char::from(HEX[usize::from(byte >> 4)]));
        secret.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
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
