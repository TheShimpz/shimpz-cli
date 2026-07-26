//! Install one published Assistant by immutable source hash.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use ureq::{Agent, Body, http::Response};
use zeroize::Zeroizing;

use crate::auth;

const TEAMS_URL: &str = "https://developers.shimpz.com/api/v1/teams";
const INSTALLATIONS_URL: &str = "https://developers.shimpz.com/api/v1/installations";
const REQUIRED_SCOPE: &str = "assistant:install";
const REQUEST_TIMEOUT: Duration = Duration::from_mins(5);
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

pub(crate) fn run(source_digest: &str, selected_team: Option<&str>) -> Result<String, String> {
    let credentials = auth::ensure_authenticated(REQUIRED_SCOPE)?;
    let api = Api::new();
    let team = match selected_team {
        Some(team) => team.to_owned(),
        None => select_team(&api.teams(&credentials)?)?,
    };
    let installed = api.install(&credentials, &team, source_digest)?;
    installed.summary()
}

fn select_team(response: &TeamList) -> Result<String, String> {
    response.validate()?;
    match response.teams.as_slice() {
        [] => Err("No Team is available. Create a Team before installing an Assistant.".into()),
        [team] => Ok(team.id.clone()),
        teams => {
            let choices = teams
                .iter()
                .map(|team| format!("  {}  {}", team.id, team.name))
                .collect::<Vec<_>>()
                .join("\n");
            Err(format!(
                "More than one Team is available. Choose one with --team:\n{choices}"
            ))
        }
    }
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

    fn teams(&self, credentials: &crate::credentials::Credentials) -> Result<TeamList, String> {
        let authorization = Zeroizing::new(format!("Bearer {}", credentials.access_token()));
        let mut response = self
            .agent
            .get(TEAMS_URL)
            .header("Accept", "application/json")
            .header("Authorization", authorization.as_str())
            .call()
            .map_err(|_| unavailable())?;
        if response.status().as_u16() != 200 {
            return Err(status_error(&mut response, "Teams are unavailable"));
        }
        read_json(&mut response)
    }

    fn install(
        &self,
        credentials: &crate::credentials::Credentials,
        team_id: &str,
        source_digest: &str,
    ) -> Result<Installed, String> {
        let authorization = Zeroizing::new(format!("Bearer {}", credentials.access_token()));
        let mut response = self
            .agent
            .post(INSTALLATIONS_URL)
            .header("Accept", "application/json")
            .header("Authorization", authorization.as_str())
            .send_json(InstallRequest {
                team_id,
                source_digest,
            })
            .map_err(|_| unavailable())?;
        if response.status().as_u16() != 200 {
            return Err(status_error(
                &mut response,
                "Assistant installation was rejected",
            ));
        }
        let installed: Installed = read_json(&mut response)?;
        installed.validate(team_id, source_digest)?;
        Ok(installed)
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(response: &mut Response<Body>) -> Result<T, String> {
    if response
        .headers()
        .get("Content-Type")
        .and_then(|value| value.to_str().ok())
        != Some("application/json")
    {
        return Err("Developers returned an invalid installation response".into());
    }
    response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_json()
        .map_err(|_| "Developers returned an invalid installation response".into())
}

fn status_error(response: &mut Response<Body>, fallback: &'static str) -> String {
    if response
        .headers()
        .get("Content-Type")
        .and_then(|value| value.to_str().ok())
        != Some("application/json")
    {
        return fallback.into();
    }
    response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_json::<ErrorEnvelope>()
        .ok()
        .filter(|envelope| envelope.error.valid())
        .map_or_else(|| fallback.into(), |envelope| envelope.error.message)
}

#[derive(Serialize)]
struct InstallRequest<'a> {
    team_id: &'a str,
    source_digest: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TeamList {
    version: u8,
    teams: Vec<Team>,
}

impl TeamList {
    fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || self.teams.len() > 128
            || self.teams.iter().any(|team| !team.valid())
        {
            return Err("Developers returned an invalid Team list".into());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Team {
    id: String,
    name: String,
}

impl Team {
    fn valid(&self) -> bool {
        valid_team_id(&self.id)
            && !self.name.is_empty()
            && self.name.len() <= 80
            && self.name.chars().all(|character| !character.is_control())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Installed {
    version: u8,
    status: String,
    team_id: String,
    assistant_id: String,
    source_digest: String,
    oci_digest: String,
    binding_digest: String,
}

impl Installed {
    fn validate(&self, team_id: &str, source_digest: &str) -> Result<(), String> {
        if self.version != 1
            || self.status != "installed"
            || self.team_id != team_id
            || self.source_digest != source_digest
            || !valid_assistant_id(&self.assistant_id)
            || !valid_digest(&self.oci_digest)
            || !valid_digest(&self.binding_digest)
        {
            return Err("Developers returned an invalid installation response".into());
        }
        Ok(())
    }

    fn summary(&self) -> Result<String, String> {
        self.validate(&self.team_id, &self.source_digest)?;
        Ok(format!(
            "Assistant installed.\nAssistant: {}\nTeam: {}\nSource: {}\nImage digest: {}\nBinding: {}",
            self.assistant_id,
            self.team_id,
            self.source_digest,
            self.oci_digest,
            self.binding_digest
        ))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorBody {
    code: String,
    message: String,
    request_id: String,
}

impl ErrorBody {
    fn valid(&self) -> bool {
        !self.code.is_empty()
            && self.code.len() <= 64
            && self
                .code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            && !self.message.is_empty()
            && self.message.len() <= 256
            && !self.request_id.is_empty()
            && self.request_id.len() <= 64
    }
}

fn valid_team_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_assistant_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 40
        && value.starts_with(|character: char| character.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.ends_with('-')
        && !value.contains("--")
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn unavailable() -> String {
    "Developers is unavailable; check your connection and try again".into()
}

#[cfg(test)]
mod tests {
    use super::{Installed, Team, TeamList, select_team};

    #[test]
    fn one_team_is_selected_without_an_extra_decision() {
        assert_eq!(
            select_team(&TeamList {
                version: 1,
                teams: vec![Team {
                    id: "team_1".into(),
                    name: "First Team".into(),
                }],
            }),
            Ok("team_1".into())
        );
    }

    #[test]
    fn multiple_teams_require_an_explicit_stable_id() {
        let error = select_team(&TeamList {
            version: 1,
            teams: vec![
                Team {
                    id: "team_1".into(),
                    name: "First Team".into(),
                },
                Team {
                    id: "team_2".into(),
                    name: "Second Team".into(),
                },
            ],
        })
        .unwrap_err();

        assert!(error.contains("--team"));
        assert!(error.contains("team_1"));
        assert!(error.contains("team_2"));
    }

    #[test]
    fn installation_response_is_bound_to_the_request() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let installed = Installed {
            version: 1,
            status: "installed".into(),
            team_id: "team_1".into(),
            assistant_id: "hello-world".into(),
            source_digest: digest.clone(),
            oci_digest: format!("sha256:{}", "b".repeat(64)),
            binding_digest: format!("sha256:{}", "c".repeat(64)),
        };

        assert!(installed.validate("team_1", &digest).is_ok());
        assert!(installed.validate("team_2", &digest).is_err());
    }
}
