//! Install one published Assistant by immutable source digest.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use ureq::{Agent, Body, http::Response};

use crate::{auth, developers_client, digest, identifier, team_id};

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
                .map(|team| format!("  {}  {}", team.id, terminal_text(&team.name)))
                .collect::<Vec<_>>()
                .join("\n");
            Err(format!(
                "More than one Team is available. Choose one with --team:\n{choices}"
            ))
        }
    }
}

/// Escapes every character that could act as a terminal or bidirectional control, so a Team name only displays.
fn terminal_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control()
                || matches!(
                    character,
                    '\u{061c}'
                        | '\u{200b}'..='\u{200f}'
                        | '\u{2028}'..='\u{202e}'
                        | '\u{2060}'..='\u{206f}'
                        | '\u{feff}'
                )
            {
                character.escape_unicode().to_string()
            } else {
                character.to_string()
            }
        })
        .collect()
}

struct Api {
    agent: Agent,
}

impl Api {
    fn new() -> Self {
        Self {
            agent: developers_client::agent(REQUEST_TIMEOUT),
        }
    }

    fn teams(&self, credentials: &crate::credentials::Credentials) -> Result<TeamList, String> {
        let authorization = developers_client::bearer(credentials.access_token());
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
        let authorization = developers_client::bearer(credentials.access_token());
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
    developers_client::read_json(
        response,
        MAX_RESPONSE_BYTES,
        "Developers returned an invalid installation response",
    )
}

fn status_error(response: &mut Response<Body>, fallback: &'static str) -> String {
    developers_client::error_message(response, MAX_RESPONSE_BYTES, fallback)
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
        team_id::valid(&self.id)
            && !self.name.is_empty()
            // The assistant-install schema admits 1 to 80 code points without C0 controls or DEL; anything else it
            // admits is escaped when rendered, never allowed to invalidate the whole Team list.
            && self.name.chars().count() <= 80
            && self
                .name
                .chars()
                .all(|character| character >= ' ' && character != '\u{7f}')
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
            || !identifier::assistant_id(&self.assistant_id)
            || !digest::is_sha256(&self.oci_digest)
            || !digest::is_sha256(&self.binding_digest)
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
    fn team_names_are_bounded_by_unicode_code_points() {
        let list = |name: String| TeamList {
            version: 1,
            teams: vec![Team {
                id: "team_1".into(),
                name,
            }],
        };
        for character in ['界', '😀'] {
            assert_eq!(list(character.to_string().repeat(80)).validate(), Ok(()));
            assert!(list(character.to_string().repeat(81)).validate().is_err());
        }
    }

    #[test]
    fn team_names_admit_what_the_schema_admits_and_render_escaped() {
        let team = |id: &str, name: &str| Team {
            id: id.into(),
            name: name.into(),
        };
        for refused in ["", "tab\tname", "escape\u{1b}[2J", "delete\u{7f}"] {
            let list = TeamList {
                version: 1,
                teams: vec![team("team_1", refused)],
            };
            assert!(list.validate().is_err(), "{refused:?}");
        }

        let error = select_team(&TeamList {
            version: 1,
            teams: vec![
                team("team_1", "Sales\u{9b}2J\u{85}"),
                team("team_2", "\u{202e}gnitekraM\u{200b}"),
            ],
        })
        .unwrap_err();
        assert!(error.contains("team_1  Sales\\u{9b}2J\\u{85}"));
        assert!(error.contains("team_2  \\u{202e}gnitekraM\\u{200b}"));
        assert!(
            !error
                .chars()
                .any(|character| character.is_control() && character != '\n')
        );
        assert!(!error.contains(['\u{202e}', '\u{200b}']));
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
        let installed = |assistant_id: &str| Installed {
            version: 1,
            status: "installed".into(),
            team_id: "team_1".into(),
            assistant_id: assistant_id.into(),
            source_digest: digest.clone(),
            oci_digest: format!("sha256:{}", "b".repeat(64)),
            binding_digest: format!("sha256:{}", "c".repeat(64)),
        };

        assert!(installed("hello-world").validate("team_1", &digest).is_ok());
        assert!(
            installed("hello-world")
                .validate("team_2", &digest)
                .is_err()
        );
        // Developers names the installed Assistant under the manifest grammar, which reserves platform names.
        for assistant_id in [
            "postgres",
            "assistant-egress",
            "shimpz-assistant-egress",
            "a--b",
            "Hello",
        ] {
            assert!(
                installed(assistant_id).validate("team_1", &digest).is_err(),
                "{assistant_id}"
            );
        }
    }
}
