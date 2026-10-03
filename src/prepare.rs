//! Authenticated preparation of the language pack for one Assistant's static message catalog (ADR-0091).

use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;
use ureq::{Agent, Body, http::Response};
use zeroize::Zeroizing;

use crate::language_pack::{self, Catalog, Pack};
use crate::{auth, manifest, output, publish, python, source_package};

const DEVELOPERS_ORIGIN: &str = "https://developers.shimpz.com";
const PREPARATIONS_PATH: &str = "/api/v1/language-packs";
const PACK_DIGEST_HEADER: &str = "X-Shimpz-Pack-Digest";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest this command, including every request, waits for translation before asking to resume it.
const MAX_WAIT: Duration = Duration::from_mins(15);
const MAX_RESPONSE_BYTES: u64 = 32 * 1024;
/// A transport failure this close to the deadline is the deadline expiring.
const DEADLINE_SLACK: Duration = Duration::from_millis(250);

pub(crate) fn run(project: &Path) -> Result<String, String> {
    output::progress("Collecting the exact Assistant source...");
    let package = source_package::build(project)?;
    let identity = manifest::PublicationIdentity::parse(&package.manifest)?;
    output::progress("Extracting the static message catalog...");
    let catalog = Catalog::from_document(&python::catalog(project)?)?;
    let directory = language_pack::cache_directory()?;
    let sdk_verify = |bytes: &[u8]| python::verify_pack(project, catalog.digest(), bytes);
    // A cached pack the SDK reference validator refuses is never reported as prepared; preparation replaces it.
    let cached =
        language_pack::load(&directory, &catalog)?.filter(|pack| sdk_verify(pack.bytes()).is_ok());
    let (pack, heading) = if let Some(pack) = cached {
        (
            pack,
            "Language pack already prepared for the current messages.",
        )
    } else {
        let credentials = auth::ensure_authenticated(auth::ASSISTANT_PUBLISH_SCOPE)?;
        let api = Api::new(DEVELOPERS_ORIGIN);
        let now = Instant::now;
        let mut budget = Budget {
            deadline: now()
                .checked_add(MAX_WAIT)
                .ok_or_else(publish::unavailable)?,
            now: &now,
            sleep: &mut thread::sleep,
        };
        let pack = prepare(&api, credentials.access_token(), &catalog, &mut budget)?;
        admit(&directory, &catalog, &pack, sdk_verify)?;
        (pack, "Language pack prepared.")
    };
    Ok(format!(
        "{heading}\nAssistant: {} {}\nMessages: {}\nCatalog: {}\nPack: {}\nNext: run 'shimpz assistant stage' to build a Local snapshot with this pack.",
        identity.id,
        identity.version,
        catalog.len(),
        catalog.digest(),
        pack.digest()
    ))
}

/// Cache a pack only after the SDK's reference validator, the rules Team applies, admits its exact bytes.
fn admit(
    directory: &Path,
    catalog: &Catalog,
    pack: &Pack,
    verify: impl FnOnce(&[u8]) -> Result<(), String>,
) -> Result<(), String> {
    verify(pack.bytes())?;
    language_pack::store(directory, catalog, pack)
}

/// One monotonic deadline shared by every request and every wait of a preparation.
struct Budget<'a> {
    deadline: Instant,
    now: &'a dyn Fn() -> Instant,
    sleep: &'a mut dyn FnMut(Duration),
}

impl Budget<'_> {
    fn remaining(&self) -> Result<Duration, String> {
        self.deadline
            .checked_duration_since((self.now)())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(wait_timeout)
    }

    /// Run one request capped by the remaining budget; a transport failure at the deadline is the timeout.
    fn request<T>(&self, request: impl FnOnce(Duration) -> Result<T, String>) -> Result<T, String> {
        let timeout = self.remaining()?.min(REQUEST_TIMEOUT);
        request(timeout).map_err(|error| {
            // A transport timer can fire marginally before this clock reaches the same deadline.
            let at_deadline =
                self.deadline.saturating_duration_since((self.now)()) <= DEADLINE_SLACK;
            if error == publish::unavailable() && at_deadline {
                wait_timeout()
            } else {
                error
            }
        })
    }

    /// Wait only when the whole interval ends before the deadline, leaving time for the next request.
    fn wait(&mut self, duration: Duration) -> Result<(), String> {
        if duration >= self.remaining()? {
            return Err(wait_timeout());
        }
        (self.sleep)(duration);
        Ok(())
    }
}

/// Resume or submit the preparation of `catalog`, wait within `budget`, and return its verified pack.
fn prepare(api: &Api, token: &str, catalog: &Catalog, budget: &mut Budget) -> Result<Pack, String> {
    let fetch =
        |budget: &Budget| budget.request(|timeout| api.fetch(token, catalog.digest(), timeout));
    // An earlier run may have timed out while its preparation continued; resuming it spends no quota.
    let mut state = fetch(budget)?;
    let mut policy = None;
    if matches!(state, Preparation::Missing | Preparation::Failed(_)) {
        output::progress("Submitting the static message catalog for translation...");
        policy = Some(budget.request(|timeout| api.submit(token, catalog, timeout))?);
        state = fetch(budget)?;
    }
    let mut announced = false;
    loop {
        match state {
            Preparation::Ready { bytes, digest } => {
                return verify_ready(bytes, &digest, catalog, policy.as_deref());
            }
            Preparation::Pending(retry_after) => {
                if !announced {
                    output::progress("Waiting for every interface language...");
                    announced = true;
                }
                budget.wait(retry_after)?;
            }
            Preparation::Missing => {
                return Err(
                    "Developers has no preparation of these messages; run 'shimpz assistant prepare' again"
                        .into(),
                );
            }
            Preparation::Failed(message) => return Err(message),
        }
        state = fetch(budget)?;
    }
}

fn verify_ready(
    bytes: Vec<u8>,
    digest: &str,
    catalog: &Catalog,
    policy: Option<&str>,
) -> Result<Pack, String> {
    if language_pack::digest(&bytes) != digest {
        return Err("Developers returned a language pack that does not match its digest".into());
    }
    let pack = language_pack::verify(bytes, catalog)
        .map_err(|code| format!("Developers returned an invalid language pack ({code})"))?;
    if policy.is_some_and(|policy| policy != pack.policy()) {
        return Err(
            "Developers returned a language pack for another translation policy; run 'shimpz assistant prepare' again"
                .into(),
        );
    }
    Ok(pack)
}

fn wait_timeout() -> String {
    "translation is still running; run 'shimpz assistant prepare' again later to resume it".into()
}

enum Preparation {
    Ready { bytes: Vec<u8>, digest: String },
    Pending(Duration),
    Missing,
    Failed(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Accepted {
    catalog: String,
    policy: String,
    status: String,
}

struct Api {
    agent: Agent,
    origin: String,
}

impl Api {
    fn new(origin: &str) -> Self {
        let config = Agent::config_builder()
            .timeout_global(Some(REQUEST_TIMEOUT))
            .max_redirects(0)
            .http_status_as_error(false)
            .build();
        Self {
            agent: config.into(),
            origin: origin.to_owned(),
        }
    }

    /// Submit only the static catalog and return the translation policy Developers bound to it.
    fn submit(&self, token: &str, catalog: &Catalog, timeout: Duration) -> Result<String, String> {
        let authorization = Zeroizing::new(format!("Bearer {token}"));
        let mut response = self
            .agent
            .post(format!("{}{PREPARATIONS_PATH}", self.origin))
            .config()
            .timeout_global(Some(timeout))
            .build()
            .header("Accept", "application/json")
            .header("Authorization", authorization.as_str())
            .send_json(json!({"messages": catalog.messages()}))
            .map_err(|_| publish::unavailable())?;
        if response.status().as_u16() != 202 {
            return Err(publish::status_error(
                &mut response,
                "language pack preparation was rejected",
            ));
        }
        let accepted = json_body::<Accepted>(&mut response)
            .filter(|accepted| {
                accepted.catalog == catalog.digest()
                    && language_pack::valid_digest(&accepted.policy)
                    && accepted.status == "pending"
            })
            .ok_or_else(invalid_response)?;
        Ok(accepted.policy)
    }

    fn fetch(
        &self,
        token: &str,
        catalog_digest: &str,
        timeout: Duration,
    ) -> Result<Preparation, String> {
        let authorization = Zeroizing::new(format!("Bearer {token}"));
        let url = format!("{}{PREPARATIONS_PATH}/{catalog_digest}", self.origin);
        let deadline = Instant::now() + timeout;
        // The status read is idempotent, so a signal-interrupted attempt is repeated within the same timeout.
        let mut response = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self
                .agent
                .get(&url)
                .config()
                .timeout_global(Some(remaining))
                .build()
                .header("Accept", "application/json")
                .header("Authorization", authorization.as_str())
                .call()
            {
                Err(ureq::Error::Io(error))
                    if error.kind() == std::io::ErrorKind::Interrupted && !remaining.is_zero() => {}
                result => break result.map_err(|_| publish::unavailable())?,
            }
        };
        match response.status().as_u16() {
            200 => ready(&mut response),
            202 | 429 => retry_after(&response).map(Preparation::Pending),
            404 => Ok(Preparation::Missing),
            422 => Ok(Preparation::Failed(failure(&mut response))),
            _ => Err(publish::status_error(
                &mut response,
                "the language pack is unavailable",
            )),
        }
    }
}

fn ready(response: &mut Response<Body>) -> Result<Preparation, String> {
    let digest = header(response, PACK_DIGEST_HEADER)
        .filter(|digest| language_pack::valid_digest(digest))
        .map(str::to_owned);
    let (Some(digest), Some("application/json")) = (digest, header(response, "Content-Type"))
    else {
        return Err(invalid_response());
    };
    let bytes = response
        .body_mut()
        .with_config()
        .limit(u64::try_from(language_pack::MAX_PACK_BYTES).unwrap_or(u64::MAX))
        .read_to_vec()
        .map_err(|_| invalid_response())?;
    Ok(Preparation::Ready { bytes, digest })
}

fn retry_after(response: &Response<Body>) -> Result<Duration, String> {
    header(response, "Retry-After")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| (1..=3600).contains(seconds))
        .map(Duration::from_secs)
        .ok_or_else(invalid_response)
}

fn failure(response: &mut Response<Body>) -> String {
    let code = publish::api_error(response).map(|error| error.code);
    let reason = match code.as_deref() {
        Some("translation_refused") => {
            "a message could not be translated within its bounds; simplify or shorten that shimpz.text copy"
        }
        Some("translation_incompatible") => {
            "an earlier translation of a message does not fit its current bounds; reword that shimpz.text copy"
        }
        Some("translation_unavailable") => "translation is temporarily unavailable",
        Some("pack_bounds") => {
            "the language pack would exceed its size bound; use fewer or shorter messages"
        }
        _ => "the messages could not be translated",
    };
    format!("{reason}; then run 'shimpz assistant prepare' again")
}

fn json_body<T: for<'de> Deserialize<'de>>(response: &mut Response<Body>) -> Option<T> {
    if header(response, "Content-Type") != Some("application/json") {
        return None;
    }
    response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_json()
        .ok()
}

fn header<'a>(response: &'a Response<Body>, name: &str) -> Option<&'a str> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
}

fn invalid_response() -> String {
    "Developers returned an invalid language pack response".into()
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::language_pack::tests::{catalog, pack_bytes, pack_value};

    const POLICY: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    struct Reply {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
        delay: Duration,
    }

    impl Reply {
        fn new(status: u16) -> Self {
            Self {
                status,
                headers: Vec::new(),
                body: Vec::new(),
                delay: Duration::ZERO,
            }
        }

        fn delayed(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
        }

        fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
            self.headers.push((name, value.into()));
            self
        }

        fn json(self, body: Vec<u8>) -> Self {
            let mut reply = self.header("Content-Type", "application/json");
            reply.body = body;
            reply
        }
    }

    /// A scripted Developers origin that serves one reply per connection and records each request line.
    struct Server {
        origin: String,
        requests: Arc<Mutex<Vec<String>>>,
    }

    impl Server {
        fn start(replies: Vec<Reply>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&requests);
            thread::spawn(move || {
                for reply in replies {
                    let Ok((stream, _)) = listener.accept() else {
                        return;
                    };
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let mut length = 0;
                    let mut authorized = false;
                    loop {
                        let mut header = String::new();
                        reader.read_line(&mut header).unwrap();
                        let lower = header.to_ascii_lowercase();
                        if let Some(value) = lower.strip_prefix("content-length:") {
                            length = value.trim().parse().unwrap();
                        }
                        authorized |= header.trim() == "Authorization: Bearer creator-token"
                            || header.trim() == "authorization: Bearer creator-token";
                        if header.trim().is_empty() {
                            break;
                        }
                    }
                    let mut body = vec![0; length];
                    reader.read_exact(&mut body).unwrap();
                    recorded.lock().unwrap().push(format!(
                        "{} authorized={authorized} body={}",
                        line.trim(),
                        String::from_utf8_lossy(&body)
                    ));
                    let mut stream = reader.into_inner();
                    let mut head = format!(
                        "HTTP/1.1 {} Scripted\r\nConnection: close\r\nContent-Length: {}\r\n",
                        reply.status,
                        reply.body.len()
                    );
                    for (name, value) in &reply.headers {
                        write!(head, "{name}: {value}\r\n").unwrap();
                    }
                    head.push_str("\r\n");
                    thread::sleep(reply.delay);
                    // A client that gave up at its deadline has closed the connection.
                    let _ = stream
                        .write_all(head.as_bytes())
                        .and_then(|()| stream.write_all(&reply.body));
                }
            });
            Self { origin, requests }
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }
    }

    fn accepted(catalog: &Catalog) -> Reply {
        Reply::new(202).json(
            json!({"catalog": catalog.digest(), "policy": POLICY, "status": "pending"})
                .to_string()
                .into_bytes(),
        )
    }

    fn pending(seconds: &str) -> Reply {
        Reply::new(202).header("Retry-After", seconds)
    }

    fn ready(bytes: Vec<u8>) -> Reply {
        let digest = language_pack::digest(&bytes);
        Reply::new(200)
            .header(PACK_DIGEST_HEADER, digest)
            .json(bytes)
    }

    fn error(status: u16, code: &str) -> Reply {
        Reply::new(status).json(
            json!({"error": {"code": code, "message": "refused by Developers", "request_id": "a".repeat(32)}})
                .to_string()
                .into_bytes(),
        )
    }

    fn run_prepare(server: &Server, catalog: &Catalog) -> (Result<Pack, String>, Vec<Duration>) {
        run_within(server, catalog, MAX_WAIT)
    }

    /// Prepare against a clock where requests take real time and each recorded wait advances time instantly.
    fn run_within(
        server: &Server,
        catalog: &Catalog,
        limit: Duration,
    ) -> (Result<Pack, String>, Vec<Duration>) {
        let waited = std::cell::Cell::new(Duration::ZERO);
        let now = || Instant::now() + waited.get();
        let mut sleeps = Vec::new();
        let mut sleep = |duration| {
            sleeps.push(duration);
            waited.set(waited.get() + duration);
        };
        let mut budget = Budget {
            deadline: now() + limit,
            now: &now,
            sleep: &mut sleep,
        };
        let result = prepare(
            &Api::new(&server.origin),
            "creator-token",
            catalog,
            &mut budget,
        );
        (result, sleeps)
    }

    #[test]
    fn submits_only_the_static_catalog_and_polls_until_the_pack_is_ready() {
        let catalog = catalog();
        let server = Server::start(vec![
            error(404, "language_pack_not_found"),
            accepted(&catalog),
            pending("10"),
            pending("10"),
            ready(pack_bytes(&catalog)),
        ]);
        let (result, sleeps) = run_prepare(&server, &catalog);
        let pack = result.expect("prepared pack");
        assert_eq!(pack.digest(), language_pack::digest(&pack_bytes(&catalog)));
        assert_eq!(sleeps, vec![Duration::from_secs(10); 2]);
        let requests = server.requests();
        let path = format!("/api/v1/language-packs/{}", catalog.digest());
        assert_eq!(requests.len(), 5);
        assert!(
            requests
                .iter()
                .all(|request| request.contains("authorized=true"))
        );
        assert!(requests[0].starts_with(&format!("GET {path} ")));
        let submission = requests[1]
            .strip_prefix("POST /api/v1/language-packs HTTP/1.1 authorized=true body=")
            .expect("one catalog submission");
        let body: serde_json::Value = serde_json::from_str(submission).unwrap();
        assert_eq!(body, json!({"messages": catalog.messages()}));
        assert!(
            requests[2..]
                .iter()
                .all(|request| request.starts_with(&format!("GET {path} ")))
        );
    }

    #[test]
    fn resumes_an_earlier_pending_preparation_without_spending_quota() {
        let catalog = catalog();
        let server = Server::start(vec![pending("10"), ready(pack_bytes(&catalog))]);
        let (result, sleeps) = run_prepare(&server, &catalog);
        assert!(result.is_ok());
        assert_eq!(sleeps.len(), 1);
        assert!(
            server
                .requests()
                .iter()
                .all(|request| request.starts_with("GET "))
        );
    }

    #[test]
    fn stops_waiting_at_its_bound_and_names_how_to_resume() {
        let catalog = catalog();
        let server = Server::start(vec![pending("600"), pending("600")]);
        let (result, sleeps) = run_prepare(&server, &catalog);
        let error = result.unwrap_err();
        assert!(error.contains("shimpz assistant prepare"), "{error}");
        assert_eq!(sleeps, vec![Duration::from_mins(10)]);

        let server = Server::start(vec![Reply::new(202)]);
        assert_eq!(
            run_prepare(&server, &catalog).0.unwrap_err(),
            invalid_response()
        );
    }

    #[test]
    fn request_time_counts_against_the_wait_bound() {
        let catalog = catalog();
        // The slow answer leaves less than its Retry-After interval, so the command stops without sleeping.
        let server = Server::start(vec![
            pending("1").delayed(Duration::from_millis(1200)),
            ready(pack_bytes(&catalog)),
        ]);
        let (result, sleeps) = run_within(&server, &catalog, Duration::from_secs(2));
        assert_eq!(result.unwrap_err(), wait_timeout());
        assert!(sleeps.is_empty());
    }

    #[test]
    fn a_request_never_outlives_the_remaining_budget() {
        let catalog = catalog();
        let server = Server::start(vec![pending("10").delayed(Duration::from_secs(5))]);
        let started = Instant::now();
        let (result, sleeps) = run_within(&server, &catalog, Duration::from_millis(400));
        assert_eq!(result.unwrap_err(), wait_timeout());
        assert!(sleeps.is_empty());
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn refuses_a_pack_that_differs_from_its_digest_or_catalog() {
        let catalog = catalog();
        let tampered = Reply::new(200)
            .header(PACK_DIGEST_HEADER, format!("sha256:{}", "e".repeat(64)))
            .json(pack_bytes(&catalog));
        let (result, _) = run_prepare(&Server::start(vec![tampered]), &catalog);
        assert!(result.unwrap_err().contains("does not match its digest"));

        let mut other = pack_value(&catalog);
        other["catalog"] = json!(format!("sha256:{}", "d".repeat(64)));
        let other = serde_json::to_vec(&other).unwrap();
        let (result, _) = run_prepare(&Server::start(vec![ready(other)]), &catalog);
        assert!(result.unwrap_err().contains("pack_catalog"));

        let mut incomplete = pack_value(&catalog);
        incomplete["locales"]["ja"] = json!({});
        let incomplete = serde_json::to_vec(&incomplete).unwrap();
        let (result, _) = run_prepare(&Server::start(vec![ready(incomplete)]), &catalog);
        assert!(result.unwrap_err().contains("pack_incomplete"));
    }

    #[test]
    fn refuses_a_pack_for_another_policy_than_the_accepted_one() {
        let catalog = catalog();
        let mut other = pack_value(&catalog);
        other["policy"] = json!(format!("sha256:{}", "f".repeat(64)));
        let server = Server::start(vec![
            error(404, "language_pack_not_found"),
            accepted(&catalog),
            ready(serde_json::to_vec(&other).unwrap()),
        ]);
        assert!(
            run_prepare(&server, &catalog)
                .0
                .unwrap_err()
                .contains("translation policy")
        );
    }

    #[test]
    fn explains_failed_translation_and_quota_with_the_next_action() {
        let catalog = catalog();
        let server = Server::start(vec![
            error(404, "language_pack_not_found"),
            accepted(&catalog),
            error(422, "translation_refused"),
        ]);
        let error_message = run_prepare(&server, &catalog).0.unwrap_err();
        assert!(
            error_message.contains("within its bounds"),
            "{error_message}"
        );
        assert!(
            error_message.contains("shimpz assistant prepare"),
            "{error_message}"
        );

        let quota = error(429, "preparation_quota_exceeded").header("Retry-After", "3600");
        let server = Server::start(vec![error(404, "language_pack_not_found"), quota]);
        let error_message = run_prepare(&server, &catalog).0.unwrap_err();
        assert_eq!(
            error_message,
            "refused by Developers; retry after 3600 seconds"
        );

        let other_catalog = Reply::new(202).json(
            json!({"catalog": format!("sha256:{}", "d".repeat(64)), "policy": POLICY, "status": "pending"})
                .to_string()
                .into_bytes(),
        );
        let server = Server::start(vec![error(404, "language_pack_not_found"), other_catalog]);
        assert_eq!(
            run_prepare(&server, &catalog).0.unwrap_err(),
            invalid_response()
        );
    }

    #[test]
    fn caches_only_a_pack_the_sdk_reference_validator_admits() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = catalog();
        let pack = language_pack::verify(pack_bytes(&catalog), &catalog).unwrap();
        let refused = admit(directory.path(), &catalog, &pack, |bytes| {
            assert_eq!(bytes, pack_bytes(&catalog));
            Err("the Python SDK refuses the language pack (public_text)".into())
        });
        assert!(refused.unwrap_err().contains("public_text"));
        assert!(
            language_pack::load(directory.path(), &catalog)
                .unwrap()
                .is_none()
        );

        admit(directory.path(), &catalog, &pack, |_| Ok(())).unwrap();
        assert!(
            language_pack::load(directory.path(), &catalog)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn a_failed_earlier_preparation_is_submitted_again() {
        let catalog = catalog();
        let server = Server::start(vec![
            error(422, "translation_unavailable"),
            accepted(&catalog),
            ready(pack_bytes(&catalog)),
        ]);
        assert!(run_prepare(&server, &catalog).0.is_ok());
        assert!(server.requests()[1].starts_with("POST "));
    }
}
