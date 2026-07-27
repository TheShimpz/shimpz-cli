//! Browser-based CLI authorization and token lifecycle.

use std::{
    process::Command,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use ureq::{Agent, Body, http::Response};
use zeroize::Zeroizing;

use crate::{
    credentials::{self, Credentials},
    output,
};

const ORIGIN: &str = "https://developers.shimpz.com";
const AUTHORIZE_URL: &str = "https://developers.shimpz.com/api/oauth/device/authorization";
const DEVICE_TOKEN_URL: &str = "https://developers.shimpz.com/api/oauth/device/token";
const REFRESH_TOKEN_URL: &str = "https://developers.shimpz.com/api/oauth/token/refresh";
const SESSION_URL: &str = "https://developers.shimpz.com/api/v1/auth/session";
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: u64 = 32 * 1024;
const IDENTITY_SCOPE: &str = "identity:read";
const AVAILABLE_SCOPES: [&str; 4] = [
    "identity:read",
    "teams:read",
    "assistant:publish",
    "assistant:install",
];

pub(crate) fn login() -> Result<String, String> {
    let credential_lock = credentials::lock()?;
    let api = Api::new();
    if let Some(mut stored) = credentials::load(&credential_lock)? {
        if let Some(session) = ensure_session(&api, &credential_lock, &mut stored)? {
            return Ok(format!("Already authenticated as {}.", session.account_id));
        }
        api.revoke(stored.refresh_token())?;
        credentials::clear(&credential_lock)?;
    }
    interactive_login(&api, &credential_lock, &[IDENTITY_SCOPE])?;
    Ok("Authentication complete. You can close the browser tab.".into())
}

pub(crate) fn ensure_authenticated(required_scope: &str) -> Result<Credentials, String> {
    if !AVAILABLE_SCOPES.contains(&required_scope) {
        return Err("CLI requested an unknown permission".into());
    }
    let credential_lock = credentials::lock()?;
    let api = Api::new();
    let mut requested_scopes = cumulative_scopes(&[], required_scope);
    if let Some(mut stored) = credentials::load(&credential_lock)? {
        requested_scopes = cumulative_scopes(stored.scopes(), required_scope);
        if ensure_session(&api, &credential_lock, &mut stored)?
            .is_some_and(|session| session.has_scope(required_scope))
        {
            return Ok(stored);
        }
        api.revoke(stored.refresh_token())?;
        credentials::clear(&credential_lock)?;
    }
    let mut stored = interactive_login(&api, &credential_lock, &requested_scopes)?;
    output::success("Authentication complete. You can close the browser tab.");
    let authorized = ensure_session(&api, &credential_lock, &mut stored)?
        .is_some_and(|session| session.has_scope(required_scope));
    if !authorized {
        api.revoke(stored.refresh_token())?;
        credentials::clear(&credential_lock)?;
        return Err("CLI authorization lacks the required permission".into());
    }
    Ok(stored)
}

fn interactive_login(
    api: &Api,
    credential_lock: &credentials::CredentialLock,
    scopes: &[&str],
) -> Result<Credentials, String> {
    let authorization = api.authorize(scopes)?;
    output::info("Authorize Shimpz in your browser.");
    output::detail("URL", &authorization.verification_url);
    output::detail("Code", &authorization.user_code);
    if open_browser(&authorization.verification_url) {
        output::info("Your default browser was opened automatically.");
    } else {
        output::warning("The browser could not be opened. Open the URL above.");
    }
    output::progress("Waiting for browser authorization...");
    let tokens = api.wait_for_tokens(&authorization)?;
    credentials::store(credential_lock, &tokens)?;
    Ok(tokens)
}

fn cumulative_scopes(existing: &[String], required: &str) -> Vec<&'static str> {
    AVAILABLE_SCOPES
        .into_iter()
        .filter(|scope| {
            *scope == IDENTITY_SCOPE
                || *scope == required
                || existing.iter().any(|current| current == scope)
        })
        .collect()
}

pub(crate) fn status() -> Result<String, String> {
    let credential_lock = credentials::lock()?;
    let Some(mut stored) = credentials::load(&credential_lock)? else {
        return Ok("Not authenticated. Run `shimpz auth`.".into());
    };
    let api = Api::new();
    let Some(session) = ensure_session(&api, &credential_lock, &mut stored)? else {
        return Ok("Authentication needs renewal. Run `shimpz auth`.".into());
    };
    Ok(format!(
        "Authenticated as {}.\nScopes: {}",
        session.account_id,
        session.scopes.join(", ")
    ))
}

pub(crate) fn logout() -> Result<String, String> {
    let credential_lock = credentials::lock()?;
    let Some(stored) = credentials::load(&credential_lock)? else {
        return Ok("Already logged out.".into());
    };
    Api::new().revoke(stored.refresh_token())?;
    credentials::clear(&credential_lock)?;
    Ok("Logged out and revoked the CLI session.".into())
}

struct Api {
    agent: Agent,
}

impl Api {
    fn new() -> Self {
        let config = Agent::config_builder()
            .timeout_global(Some(REQUEST_TIMEOUT))
            .max_redirects(0)
            .http_status_as_error(false)
            .build();
        Self {
            agent: config.into(),
        }
    }

    fn authorize(&self, scopes: &[&str]) -> Result<DeviceAuthorization, String> {
        let mut response = self
            .agent
            .post(AUTHORIZE_URL)
            .header("Accept", "application/json")
            .send_json(AuthorizationRequest { scopes })
            .map_err(|_| unavailable())?;
        if response.status().as_u16() != 200 {
            return Err(status_error(&mut response, "authorization could not start"));
        }
        let authorization: DeviceAuthorization = read_json(&mut response)?;
        authorization.validate()?;
        Ok(authorization)
    }

    fn wait_for_tokens(&self, authorization: &DeviceAuthorization) -> Result<Credentials, String> {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(authorization.expires_in))
            .ok_or_else(unavailable)?;
        while Instant::now() < deadline {
            let mut response = self
                .agent
                .post(DEVICE_TOKEN_URL)
                .header("Accept", "application/json")
                .send_json(DeviceTokenRequest {
                    device_code: authorization.device_code.expose(),
                })
                .map_err(|_| unavailable())?;
            match response.status().as_u16() {
                200 => return token_credentials(&mut response),
                400 | 429 => thread::sleep(POLL_INTERVAL),
                _ => {
                    return Err(status_error(
                        &mut response,
                        "browser authorization could not finish",
                    ));
                }
            }
        }
        Err("browser authorization expired; run `shimpz auth` again".into())
    }

    fn session(&self, access_token: &str) -> Result<Option<AuthSession>, String> {
        let authorization = Zeroizing::new(format!("Bearer {access_token}"));
        let mut response = self
            .agent
            .get(SESSION_URL)
            .header("Accept", "application/json")
            .header("Authorization", authorization.as_str())
            .call()
            .map_err(|_| unavailable())?;
        match response.status().as_u16() {
            200 => {
                let session: AuthSession = read_json(&mut response)?;
                session.validate()?;
                Ok(Some(session))
            }
            401 | 403 => Ok(None),
            _ => Err(status_error(
                &mut response,
                "CLI authentication could not be validated",
            )),
        }
    }

    fn refresh(&self, refresh_token: &str) -> Result<Option<Credentials>, String> {
        let request = RefreshTokenRequest { refresh_token };
        let mut response = self
            .agent
            .post(REFRESH_TOKEN_URL)
            .header("Accept", "application/json")
            .send_json(request)
            .map_err(|_| unavailable())?;
        match response.status().as_u16() {
            200 => token_credentials(&mut response).map(Some),
            400 | 403 => Ok(None),
            _ => Err(status_error(
                &mut response,
                "CLI credentials could not be refreshed",
            )),
        }
    }

    fn revoke(&self, refresh_token: &str) -> Result<(), String> {
        let authorization = Zeroizing::new(format!("Bearer {refresh_token}"));
        let mut response = self
            .agent
            .delete(SESSION_URL)
            .header("Accept", "application/json")
            .header("Authorization", authorization.as_str())
            .call()
            .map_err(|_| unavailable())?;
        match response.status().as_u16() {
            204 | 401 => Ok(()),
            _ => Err(status_error(
                &mut response,
                "CLI session could not be revoked",
            )),
        }
    }
}

fn ensure_session(
    api: &Api,
    credential_lock: &credentials::CredentialLock,
    credentials: &mut Credentials,
) -> Result<Option<AuthSession>, String> {
    if let Some(session) = api.session(credentials.access_token())? {
        return Ok(Some(session));
    }
    let Some(replacement) = api.refresh(credentials.refresh_token())? else {
        return Ok(None);
    };
    credentials::store(credential_lock, &replacement)?;
    *credentials = replacement;
    api.session(credentials.access_token())
}

fn token_credentials(response: &mut Response<Body>) -> Result<Credentials, String> {
    let tokens: TokenResponse = read_json(response)?;
    tokens.into_credentials()
}

fn read_json<T: DeserializeOwned>(response: &mut Response<Body>) -> Result<T, String> {
    if response
        .headers()
        .get("Content-Type")
        .and_then(|value| value.to_str().ok())
        != Some("application/json")
    {
        return Err("Developers returned an invalid response".into());
    }
    response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_json()
        .map_err(|_| "Developers returned an invalid response".into())
}

fn status_error(response: &mut Response<Body>, fallback: &'static str) -> String {
    read_json::<ErrorEnvelope>(response)
        .ok()
        .filter(|envelope| envelope.error.valid())
        .map_or_else(|| fallback.into(), |envelope| envelope.error.message)
}

fn valid_error_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn unavailable() -> String {
    "Developers is unavailable; try again shortly".into()
}

fn now_unix() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| unavailable())
}

fn open_browser(url: &str) -> bool {
    #[cfg(target_os = "windows")]
    let mut command = Command::new("cmd");
    #[cfg(target_os = "windows")]
    command.args(["/C", "start", "", url]);

    #[cfg(target_os = "macos")]
    let mut command = Command::new("open");
    #[cfg(target_os = "macos")]
    command.arg(url);

    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = Command::new("xdg-open");
    #[cfg(all(unix, not(target_os = "macos")))]
    command.arg(url);

    #[cfg(any(unix, target_os = "windows"))]
    return command.spawn().is_ok();

    #[cfg(not(any(unix, target_os = "windows")))]
    false
}

#[derive(Serialize)]
struct AuthorizationRequest<'a> {
    scopes: &'a [&'a str],
}

#[derive(Serialize)]
struct DeviceTokenRequest<'a> {
    device_code: &'a str,
}

#[derive(Serialize)]
struct RefreshTokenRequest<'a> {
    refresh_token: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceAuthorization {
    flow_handle: String,
    device_code: SecretInput,
    user_code: String,
    verification_url: String,
    expires_in: u64,
}

impl DeviceAuthorization {
    fn validate(&self) -> Result<(), String> {
        let expected_url = format!("{ORIGIN}/cli/auth?flow={}", self.flow_handle);
        if !valid_handle(&self.flow_handle)
            || !valid_user_code(&self.user_code)
            || self.verification_url != expected_url
            || self.expires_in != 600
            || !valid_token(self.device_code.expose())
        {
            return Err("Developers returned an invalid authorization response".into());
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(transparent)]
struct SecretInput(String);

impl SecretInput {
    fn expose(&self) -> &str {
        &self.0
    }

    fn into_string(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl Drop for SecretInput {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;

        self.0.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenResponse {
    access_token: SecretInput,
    refresh_token: SecretInput,
    token_type: String,
    expires_in: u64,
    refresh_expires_in: u64,
    scopes: Vec<String>,
}

impl TokenResponse {
    fn into_credentials(self) -> Result<Credentials, String> {
        if self.token_type != "Bearer"
            || self.expires_in != 900
            || !(1..=2_592_000).contains(&self.refresh_expires_in)
        {
            return Err("Developers returned an invalid token response".into());
        }
        let now = now_unix()?;
        Credentials::new(
            self.access_token.into_string(),
            self.refresh_token.into_string(),
            now.checked_add(self.expires_in).ok_or_else(unavailable)?,
            now.checked_add(self.refresh_expires_in)
                .ok_or_else(unavailable)?,
            self.scopes,
        )
        .map_err(|_| "Developers returned an invalid token response".into())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthSession {
    authenticated: bool,
    account_id: String,
    scopes: Vec<String>,
}

impl AuthSession {
    fn validate(&self) -> Result<(), String> {
        if !self.authenticated
            || self.account_id.len() != 32
            || !self
                .account_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || self.scopes.is_empty()
            || self.scopes.len() > AVAILABLE_SCOPES.len()
            || self
                .scopes
                .iter()
                .any(|scope| !AVAILABLE_SCOPES.contains(&scope.as_str()))
        {
            return Err("Developers returned an invalid session response".into());
        }
        Ok(())
    }

    fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|value| value == scope)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorEnvelope {
    error: ApiError,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiError {
    code: String,
    message: String,
    request_id: String,
}

impl ApiError {
    fn valid(&self) -> bool {
        valid_error_code(&self.code)
            && !self.message.is_empty()
            && self.message.len() <= 200
            && self
                .message
                .bytes()
                .all(|byte| byte.is_ascii() && !byte.is_ascii_control())
            && self.request_id.len() == 32
            && self
                .request_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }
}

fn valid_handle(value: &str) -> bool {
    value.len() == 22 && base64url(value)
}

fn valid_token(value: &str) -> bool {
    value.len() == 43 && base64url(value)
}

fn base64url(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_user_code(value: &str) -> bool {
    value.len() == 9
        && value.bytes().enumerate().all(|(index, byte)| {
            if index == 4 {
                byte == b'-'
            } else {
                b"BCDFGHJKLMNPQRSTVWXZ".contains(&byte)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::{
        AuthSession, DeviceAuthorization, SecretInput, TokenResponse, cumulative_scopes,
        valid_error_code, valid_user_code,
    };

    #[test]
    fn validates_only_the_production_browser_url() {
        let valid = DeviceAuthorization {
            flow_handle: "a".repeat(22),
            device_code: SecretInput("b".repeat(43)),
            user_code: "BCDF-GHJK".into(),
            verification_url: format!(
                "https://developers.shimpz.com/cli/auth?flow={}",
                "a".repeat(22)
            ),
            expires_in: 600,
        };

        assert!(valid.validate().is_ok());
    }

    #[test]
    fn requests_only_identity_and_cumulative_command_scopes() {
        assert_eq!(cumulative_scopes(&[], "identity:read"), ["identity:read"]);
        assert_eq!(
            cumulative_scopes(&[], "assistant:publish"),
            ["identity:read", "assistant:publish"]
        );
        assert_eq!(
            cumulative_scopes(
                &["identity:read".into(), "assistant:publish".into()],
                "assistant:install"
            ),
            ["identity:read", "assistant:publish", "assistant:install"]
        );
    }

    #[test]
    fn rejects_malformed_protocol_values() {
        assert!(valid_user_code("BCDF-GHJK"));
        assert!(!valid_user_code("ABCD-EFGH"));
        assert!(valid_error_code("step_up_required"));
        assert!(!valid_error_code("Step Up"));
        let invalid_session = AuthSession {
            authenticated: true,
            account_id: "A".repeat(32),
            scopes: vec!["identity:read".into()],
        };
        assert!(invalid_session.validate().is_err());
        let session = AuthSession {
            authenticated: true,
            account_id: "a".repeat(32),
            scopes: vec!["identity:read".into(), "assistant:publish".into()],
        };
        assert!(session.has_scope("assistant:publish"));
        assert!(!session.has_scope("assistant:install"));
    }

    #[test]
    fn rejects_inconsistent_token_lifetimes() {
        let response = TokenResponse {
            access_token: SecretInput("a".repeat(43)),
            refresh_token: SecretInput("b".repeat(43)),
            token_type: "Bearer".into(),
            expires_in: 899,
            refresh_expires_in: 2_592_000,
            scopes: vec!["identity:read".into()],
        };

        assert!(response.into_credentials().is_err());
    }
}
