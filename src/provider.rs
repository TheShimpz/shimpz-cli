//! The local provider-call broker of `shimpz assistant run` (ADR-0106).
//!
//! An Action never holds a credential: it asks for each HTTPS call on its exec channel, and this broker admits the
//! call against the project's `shimpz.toml`, injects the credentials the Action declares for that host, and returns
//! only a complete, credential-free response, applying Team's admission rules and bounds. Stored Input values live
//! only in this process's memory; an Integration bearer comes from the Creator's `SHIMPZ_INTEGRATION_<ID>` and goes
//! only to that provider's reviewed API hosts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use serde_json::{Value, json};
use ureq::Agent;
use ureq::http::Request;
use zeroize::Zeroizing;

use crate::manifest::Placement;

pub(crate) const MAX_CALLS: usize = 16;
const MAX_URL_CHARACTERS: usize = 8192;
const MAX_HEADERS: usize = 32;
const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_REQUEST_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
const MAX_TIMEOUT_MS: u64 = 30_000;
const METHODS: [&str; 6] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];
const FIELDS: [&str; 6] = ["type", "method", "url", "headers", "body", "timeout_ms"];
/// Fields the broker owns in every call, so neither an Action nor a placement may set one (compared without case).
pub(crate) const RESERVED_HEADERS: [&str; 12] = [
    "accept-encoding",
    "connection",
    "content-length",
    "expect",
    "host",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];
/// Each Integration's reviewed provider API hosts, exactly as Team's provider registry pins them; an umbrella test
/// keeps the two equal.
pub(crate) const INTEGRATION_HOSTS: [(&str, &[&str]); 1] =
    [("cloudflare", &["api.cloudflare.com"])];

/// One credential placed in calls to its host: a header or a query parameter.
struct Credential {
    header: Option<String>,
    query: Option<String>,
    value: Zeroizing<String>,
    /// Every raw and placed form a response must never echo.
    protected: Vec<Zeroizing<String>>,
}

struct Call {
    method: String,
    host: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    timeout: Duration,
}

/// The Action's declared credentials and the Assistant's allowed hosts, plus the Stored Input values held so far.
pub(crate) struct Broker {
    hosts: BTreeSet<String>,
    placements: BTreeMap<String, Placement>,
    integrations: Vec<(String, Option<Zeroizing<String>>)>,
    held: BTreeMap<String, Zeroizing<String>>,
    authorized: bool,
    calls: usize,
}

impl Broker {
    /// Admit the Action's declarations; `placements` holds only the Stored Inputs it declares, and `integrations`
    /// each declared Integration with the Creator's token when one is set.
    pub(crate) fn new(
        hosts: BTreeSet<String>,
        placements: BTreeMap<String, Placement>,
        integrations: Vec<(String, Option<Zeroizing<String>>)>,
    ) -> Result<Self, String> {
        if let Some((id, _)) = integrations
            .iter()
            .find(|(id, _)| integration_hosts(id).is_none())
        {
            return Err(format!("Integration {id} has no reviewed provider"));
        }
        Ok(Self {
            hosts,
            placements,
            integrations,
            held: BTreeMap::new(),
            authorized: false,
            calls: 0,
        })
    }

    /// Start one attempt: its calls are counted afresh and admitted only once its authorization is answered.
    pub(crate) fn begin(&mut self, authorized: bool) {
        self.authorized = authorized;
        self.calls = 0;
    }

    /// Hold one answered Stored Input value for the rest of this run.
    pub(crate) fn hold(&mut self, stored_input: &str, value: Zeroizing<String>) {
        self.held.insert(stored_input.to_owned(), value);
    }

    pub(crate) fn calls(&self) -> usize {
        self.calls
    }

    /// Return the one-line reply to one `fetch` frame: a response or a closed error.
    pub(crate) fn answer(&mut self, frame: &Value) -> Zeroizing<Vec<u8>> {
        self.calls += 1;
        let reply = self.admit(frame).and_then(|(call, credentials)| {
            let (status, headers, body) = send(&call)?;
            require_clean(&headers, &body, &credentials)?;
            Ok(json!({
                "status": status,
                "headers": headers.iter().map(|(name, value)| json!([name, value])).collect::<Vec<_>>(),
                "body": STANDARD.encode(body),
            }))
        });
        let value = reply.unwrap_or_else(|code| json!({ "error": code }));
        Zeroizing::new(serde_json::to_vec(&value).unwrap_or_default())
    }

    fn admit(&self, frame: &Value) -> Result<(Call, Vec<Credential>), &'static str> {
        if self.calls > MAX_CALLS || !self.authorized {
            return Err("refused");
        }
        let call = parse(frame, &self.hosts)?;
        let (credentials, missing) = self.credentials(&call.host);
        let owned: BTreeSet<&str> = credentials
            .iter()
            .flat_map(|credential| [credential.header.as_deref(), credential.query.as_deref()])
            .flatten()
            .collect();
        if call
            .headers
            .iter()
            .any(|(name, _)| owned.contains(name.as_str()))
            || query_names(&call.target)
                .iter()
                .any(|name| owned.contains(name.as_str()))
        {
            return Err("refused");
        }
        if missing {
            return Err("credential-missing");
        }
        Ok((inject(call, &credentials)?, credentials))
    }

    /// The credentials this Action places on one host, and whether a declared one for it is not held.
    fn credentials(&self, host: &str) -> (Vec<Credential>, bool) {
        let mut credentials = Vec::new();
        let mut missing = false;
        for (id, placement) in &self.placements {
            if placement.host != host {
                continue;
            }
            let signed = placement
                .hmac
                .as_deref()
                .map(|target| self.held.get(target));
            let (Some(value), None | Some(Some(_))) = (self.held.get(id), signed) else {
                missing = true;
                continue;
            };
            let proof = signed.flatten().map(|message| proof(value, message));
            let mut placed = Zeroizing::new(proof.as_deref().unwrap_or(value).to_owned());
            if let Some(scheme) = &placement.scheme {
                placed = Zeroizing::new(format!("{scheme} {}", placed.as_str()));
            }
            credentials.push(Credential {
                header: placement.header.as_deref().map(str::to_ascii_lowercase),
                query: placement.query.clone(),
                protected: vec![value.clone(), placed.clone()],
                value: placed,
            });
        }
        for (id, token) in &self.integrations {
            if !integration_hosts(id).is_some_and(|hosts| hosts.contains(&host)) {
                continue;
            }
            let Some(token) = token else {
                missing = true;
                continue;
            };
            let bearer = Zeroizing::new(format!("Bearer {}", token.as_str()));
            credentials.push(Credential {
                header: Some("authorization".into()),
                query: None,
                protected: vec![token.clone(), bearer.clone()],
                value: bearer,
            });
        }
        (credentials, missing)
    }
}

fn integration_hosts(id: &str) -> Option<&'static [&'static str]> {
    INTEGRATION_HOSTS
        .iter()
        .find(|(provider, _)| *provider == id)
        .map(|(_, hosts)| *hosts)
}

fn parse(frame: &Value, hosts: &BTreeSet<String>) -> Result<Call, &'static str> {
    let fields = frame.as_object().ok_or("refused")?;
    let method = fields.get("method").and_then(Value::as_str).unwrap_or("");
    if fields.get("type").and_then(Value::as_str) != Some("fetch")
        || !["type", "method", "url", "headers"]
            .iter()
            .all(|field| fields.contains_key(*field))
        || !fields.keys().all(|field| FIELDS.contains(&field.as_str()))
        || !METHODS.contains(&method)
    {
        return Err("refused");
    }
    let (host, target) = url(fields.get("url"), hosts)?;
    let timeout = match fields.get("timeout_ms") {
        None => MAX_TIMEOUT_MS,
        Some(value) => value
            .as_u64()
            .filter(|timeout| (1..=MAX_TIMEOUT_MS).contains(timeout))
            .ok_or("refused")?,
    };
    let body = match fields.get("body") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .and_then(|encoded| STANDARD.decode(encoded).ok())
                .filter(|body| body.len() <= MAX_REQUEST_BYTES)
                .ok_or("refused")?,
        ),
    };
    Ok(Call {
        method: method.to_owned(),
        host,
        target,
        headers: headers(fields.get("headers"))?,
        body,
        timeout: Duration::from_millis(timeout),
    })
}

/// An `https` URL on port 443 without user information or fragment whose host is exactly an allowed host.
fn url(value: Option<&Value>, hosts: &BTreeSet<String>) -> Result<(String, String), &'static str> {
    let value = value.and_then(Value::as_str).ok_or("refused")?;
    if !(9..=MAX_URL_CHARACTERS).contains(&value.len())
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
        || value.contains('#')
    {
        return Err("refused");
    }
    let rest = value.strip_prefix("https://").ok_or("refused")?;
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (host, target) = rest.split_at(split);
    if !hosts.contains(host) {
        return Err("refused");
    }
    let target = if target.starts_with('/') {
        target.to_owned()
    } else {
        format!("/{target}")
    };
    Ok((host.to_owned(), target))
}

fn headers(value: Option<&Value>) -> Result<Vec<(String, String)>, &'static str> {
    let items = value
        .and_then(Value::as_array)
        .filter(|items| items.len() <= MAX_HEADERS)
        .ok_or("refused")?;
    let mut headers = Vec::with_capacity(items.len());
    for item in items {
        let pair = item.as_array().filter(|pair| pair.len() == 2);
        let (Some(name), Some(field)) = (
            pair.and_then(|pair| pair[0].as_str()),
            pair.and_then(|pair| pair[1].as_str()),
        ) else {
            return Err("refused");
        };
        let name = name.to_ascii_lowercase();
        if !(1..=64).contains(&name.len())
            || !name.bytes().all(token_byte)
            || !field_value(field)
            || RESERVED_HEADERS.contains(&name.as_str())
            || headers.iter().any(|(seen, _)| *seen == name)
        {
            return Err("refused");
        }
        headers.push((name, field.to_owned()));
    }
    if headers
        .iter()
        .map(|(name, field)| name.len() + field.len())
        .sum::<usize>()
        > MAX_HEADER_BYTES
    {
        return Err("refused");
    }
    Ok(headers)
}

fn token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// A header value without a line break or any other control character than tab.
fn field_value(value: &str) -> bool {
    value
        .chars()
        .all(|character| character == '\t' || !character.is_control())
}

fn query_names(target: &str) -> BTreeSet<String> {
    let Some((_, query)) = target.split_once('?') else {
        return BTreeSet::new();
    };
    query
        .split('&')
        .map(|pair| percent_decode(pair.split('=').next().unwrap_or_default()))
        .collect()
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let hex = bytes
            .get(index + 1..index + 3)
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .and_then(|pair| u8::from_str_radix(pair, 16).ok());
        match (bytes[index], hex) {
            (b'%', Some(byte)) => {
                decoded.push(byte);
                index += 3;
            }
            (b'+', _) => {
                decoded.push(b' ');
                index += 1;
            }
            (byte, _) => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn percent_encode(value: &str, plus: bool) -> String {
    value.bytes().fold(String::new(), |mut encoded, byte| {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else if plus && byte == b' ' {
            encoded.push('+');
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
        encoded
    })
}

/// Place every credential of the call's host; a value that cannot travel in its field refuses the call.
fn inject(mut call: Call, credentials: &[Credential]) -> Result<Call, &'static str> {
    for credential in credentials {
        match (&credential.header, &credential.query) {
            (Some(header), _) if field_value(&credential.value) => {
                call.headers
                    .push((header.clone(), credential.value.as_str().to_owned()));
            }
            (None, Some(query)) => {
                let separator = if call.target.contains('?') { '&' } else { '?' };
                let _ = write!(
                    call.target,
                    "{separator}{query}={}",
                    percent_encode(&credential.value, false)
                );
            }
            _ => return Err("refused"),
        }
    }
    Ok(call)
}

type Received = (u16, Vec<(String, String)>, Vec<u8>);

fn send(call: &Call) -> Result<Received, &'static str> {
    let agent: Agent = Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(call.timeout))
        .build()
        .into();
    let mut request = Request::builder()
        .method(call.method.as_str())
        .uri(format!("https://{}{}", call.host, call.target))
        .header("accept-encoding", "identity");
    for (name, value) in &call.headers {
        request = request.header(name.as_str(), value.as_str());
    }
    let sent = match &call.body {
        Some(body) => request.body(body.clone()).map(|request| agent.run(request)),
        None => request.body(()).map(|request| agent.run(request)),
    };
    let mut response = sent
        .map_err(|_| "refused")?
        .map_err(|error| unsent(&error))?;
    let mut headers = Vec::new();
    for (name, value) in response.headers() {
        headers.push((
            name.as_str().to_owned(),
            value.to_str().map_err(|_| "failed")?.to_owned(),
        ));
    }
    if !identity_encoded(response.headers())
        || headers
            .iter()
            .map(|(name, value)| name.len() + value.len())
            .sum::<usize>()
            > MAX_RESPONSE_HEADER_BYTES
    {
        return Err("failed");
    }
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_to_vec()
        .map_err(|_| "failed")?;
    Ok((response.status().as_u16(), headers, body))
}

/// Every Content-Encoding occurrence is identity, so a compressed body never passes the echo scan.
fn identity_encoded(headers: &ureq::http::HeaderMap) -> bool {
    headers
        .get_all("content-encoding")
        .iter()
        .all(|value| matches!(value.to_str().map(str::trim), Ok("" | "identity")))
}

/// `unavailable` only when the call cannot have reached the provider; any later failure may follow a sent request,
/// so it is `failed` and a mutation stays uncertain, as Team reports it.
fn unsent(error: &ureq::Error) -> &'static str {
    match error {
        ureq::Error::HostNotFound
        | ureq::Error::ConnectionFailed
        | ureq::Error::ConnectProxyFailed(_)
        | ureq::Error::RequireHttpsOnly(_)
        | ureq::Error::BadUri(_)
        | ureq::Error::Timeout(ureq::Timeout::Resolve | ureq::Timeout::Connect) => "unavailable",
        _ => "failed",
    }
}

/// Refuse a response that carries any injected value in a common encoding, in any header or the body.
///
/// The body is read as UTF-8 text and with its JSON string escapes decoded, whether or not it parses, so an escaped
/// or duplicated JSON member cannot carry a value past the scan; every comparison ignores case.
fn require_clean(
    headers: &[(String, String)],
    body: &[u8],
    credentials: &[Credential],
) -> Result<(), &'static str> {
    let forms: Vec<Zeroizing<String>> = credentials
        .iter()
        .flat_map(|credential| credential.protected.iter())
        .filter(|secret| !secret.is_empty())
        .flat_map(|secret| encodings(secret))
        .map(|form| Zeroizing::new(form.to_lowercase()))
        .collect();
    let text = Zeroizing::new(String::from_utf8_lossy(body).into_owned());
    let mut texts: Vec<Zeroizing<String>> = headers
        .iter()
        .map(|(name, value)| Zeroizing::new(format!("{name}: {value}").to_lowercase()))
        .collect();
    texts.push(Zeroizing::new(text.to_lowercase()));
    texts.push(Zeroizing::new(json_unescaped(&text).to_lowercase()));
    if texts
        .iter()
        .any(|text| forms.iter().any(|form| text.contains(form.as_str())))
    {
        Err("failed")
    } else {
        Ok(())
    }
}

/// Decode every JSON string escape in `text`; a surrogate pair decodes to its one character.
fn json_unescaped(text: &str) -> String {
    let mut decoded = String::with_capacity(text.len());
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        match characters.next() {
            Some('u') => {
                let unit = |characters: &mut std::iter::Peekable<std::str::Chars<'_>>| {
                    let hex: String = characters.by_ref().take(4).collect();
                    u16::from_str_radix(&hex, 16).ok()
                };
                let Some(first) = unit(&mut characters) else {
                    continue;
                };
                let mut units = vec![first];
                if (0xd800..0xdc00).contains(&first) && characters.peek() == Some(&'\\') {
                    let mut lookahead = characters.clone();
                    lookahead.next();
                    if lookahead.next() == Some('u')
                        && let Some(second) = unit(&mut lookahead)
                        && (0xdc00..0xe000).contains(&second)
                    {
                        units.push(second);
                        characters = lookahead;
                    }
                }
                decoded.extend(char::decode_utf16(units).map(|unit| unit.unwrap_or('\u{fffd}')));
            }
            Some('b') => decoded.push('\u{8}'),
            Some('f') => decoded.push('\u{c}'),
            Some('n') => decoded.push('\n'),
            Some('r') => decoded.push('\r'),
            Some('t') => decoded.push('\t'),
            Some(other) => decoded.push(other),
            None => decoded.push('\\'),
        }
    }
    decoded
}

/// The value and its JSON, percent, hexadecimal, and base64 encodings, base64 at each byte alignment so the value is
/// found inside a longer encoded string, as Team scans them.
fn encodings(secret: &str) -> Vec<Zeroizing<String>> {
    let json = serde_json::to_string(secret).unwrap_or_default();
    let json = json.trim_matches('"').to_owned();
    let mut forms = vec![
        secret.to_owned(),
        json.replace('/', "\\/"),
        json,
        percent_encode(secret, false),
        percent_encode(secret, true),
        secret.bytes().fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        }),
    ];
    let raw = secret.as_bytes();
    for offset in 0..3 {
        let mut aligned = vec![0_u8; offset];
        aligned.extend_from_slice(raw);
        let first = (offset * 4).div_ceil(3);
        let last = (offset + raw.len()) * 8 / 6;
        for engine in [STANDARD, URL_SAFE] {
            let encoded = engine.encode(&aligned);
            if let Some(core) = encoded.get(first..last) {
                forms.push(core.to_owned());
            }
        }
    }
    forms.into_iter().map(Zeroizing::new).collect()
}

/// The lowercase hexadecimal HMAC-SHA256 keyed by one value over another, as Meta's `appsecret_proof` (RFC 2104).
fn proof(key: &str, message: &str) -> String {
    hmac_sha256(key.as_bytes(), message.as_bytes())
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    crate::digest::lower_hex(ring::hmac::sign(&key, message).as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placement(host: &str, header: Option<&str>, query: Option<&str>) -> Placement {
        Placement {
            host: host.into(),
            header: header.map(Into::into),
            query: query.map(Into::into),
            scheme: None,
            hmac: None,
        }
    }

    fn meta() -> Broker {
        let mut token = placement("graph.facebook.com", Some("Authorization"), None);
        token.scheme = Some("Bearer".into());
        let mut secret = placement("graph.facebook.com", None, Some("appsecret_proof"));
        secret.hmac = Some("meta-access-token".into());
        let mut broker = Broker::new(
            [
                "graph.facebook.com".to_owned(),
                "api.example.com".to_owned(),
            ]
            .into(),
            [
                ("meta-access-token".to_owned(), token),
                ("meta-app-secret".to_owned(), secret),
            ]
            .into(),
            Vec::new(),
        )
        .expect("broker");
        broker.begin(true);
        broker
    }

    fn fetch(url: &str) -> Value {
        json!({"type": "fetch", "method": "GET", "url": url, "headers": [["Accept", "application/json"]]})
    }

    fn error(reply: &[u8]) -> Value {
        serde_json::from_slice::<Value>(reply).expect("reply")["error"].clone()
    }

    #[test]
    fn computes_the_rfc_4231_hmac_sha256_vectors() {
        assert_eq!(
            proof("Jefe", "what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            ),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn places_a_bearer_header_and_an_hmac_query_proof_on_their_host() {
        let mut broker = meta();
        broker.hold("meta-access-token", Zeroizing::new("token-1".into()));
        broker.hold("meta-app-secret", Zeroizing::new("secret-1".into()));
        broker.calls = 1;

        let (call, credentials) = broker
            .admit(&fetch("https://graph.facebook.com/v26.0/me?fields=id"))
            .expect("admitted");

        assert_eq!(credentials.len(), 2);
        assert!(
            call.headers
                .contains(&("authorization".into(), "Bearer token-1".into()))
        );
        assert_eq!(
            call.target,
            format!(
                "/v26.0/me?fields=id&appsecret_proof={}",
                proof("secret-1", "token-1")
            )
        );
        let (other, none) = broker
            .admit(&fetch("https://api.example.com/v1"))
            .expect("other host");
        assert!(none.is_empty());
        assert_eq!(other.headers.len(), 1);
    }

    #[test]
    fn refuses_calls_outside_the_declarations_and_bounds() {
        let mut broker = meta();
        broker.hold("meta-access-token", Zeroizing::new("token-1".into()));
        broker.hold("meta-app-secret", Zeroizing::new("secret-1".into()));
        for url in [
            "http://graph.facebook.com/me",
            "https://evil.example/me",
            "https://graph.facebook.com:8443/me",
            "https://user@graph.facebook.com/me",
            "https://graph.facebook.com/me#x",
            "https://GRAPH.facebook.com/me",
            "https://graph.facebook.com/me?appsecret_proof=forged",
            "https://graph.facebook.com/me?appsecret%5Fproof=forged",
        ] {
            assert_eq!(error(&broker.answer(&fetch(url))), "refused", "{url}");
        }
        for frame in [
            json!({"type": "fetch", "method": "GET", "url": "https://graph.facebook.com/me", "headers": [["Authorization", "x"]]}),
            json!({"type": "fetch", "method": "GET", "url": "https://graph.facebook.com/me", "headers": [["Host", "x"]]}),
            json!({"type": "fetch", "method": "TRACE", "url": "https://graph.facebook.com/me", "headers": []}),
            json!({"type": "fetch", "method": "GET", "url": "https://graph.facebook.com/me", "headers": [], "extra": 1}),
            json!({"type": "fetch", "method": "GET", "url": "https://graph.facebook.com/me", "headers": [], "timeout_ms": 30_001}),
            json!({"type": "fetch", "method": "POST", "url": "https://graph.facebook.com/me", "headers": [], "body": "@@"}),
        ] {
            assert_eq!(error(&broker.answer(&frame)), "refused", "{frame}");
        }
        broker.begin(false);
        assert_eq!(
            error(&broker.answer(&fetch("https://api.example.com/v1"))),
            "refused"
        );
        broker.begin(true);
        broker.calls = MAX_CALLS;
        assert_eq!(
            error(&broker.answer(&fetch("https://api.example.com/v1"))),
            "refused"
        );
    }

    #[test]
    fn a_declared_credential_not_held_refuses_only_its_host() {
        let mut broker = meta();
        broker.hold("meta-app-secret", Zeroizing::new("secret-1".into()));
        assert_eq!(
            error(&broker.answer(&fetch("https://graph.facebook.com/me"))),
            "credential-missing"
        );
        let mut cloudflare = Broker::new(
            ["api.cloudflare.com".to_owned()].into(),
            BTreeMap::new(),
            vec![("cloudflare".into(), None)],
        )
        .expect("broker");
        cloudflare.begin(true);
        assert_eq!(
            error(&cloudflare.answer(&fetch("https://api.cloudflare.com/client/v4/zones"))),
            "credential-missing"
        );
        assert!(
            Broker::new(
                BTreeSet::new(),
                BTreeMap::new(),
                vec![("unknown".into(), None)]
            )
            .is_err()
        );
    }

    #[test]
    fn refuses_a_response_that_echoes_an_injected_value_in_any_common_encoding() {
        let mut broker = meta();
        broker.hold("meta-access-token", Zeroizing::new("token/value 1".into()));
        broker.hold("meta-app-secret", Zeroizing::new("secret-1".into()));
        let (credentials, _) = broker.credentials("graph.facebook.com");
        for body in [
            "token/value 1".to_owned(),
            "TOKEN/VALUE 1".to_owned(),
            "token%2Fvalue%201".to_owned(),
            "token%2Fvalue+1".to_owned(),
            "token\\/value 1".to_owned(),
            "token/value 1"
                .bytes()
                .fold(String::new(), |mut hex, byte| {
                    let _ = write!(hex, "{byte:02x}");
                    hex
                }),
            format!("Basic {}", STANDARD.encode("user:token/value 1")),
            proof("secret-1", "token/value 1"),
            r#"{"a":"token/value 1"}"#.to_owned(),
        ] {
            assert_eq!(
                require_clean(&[], body.as_bytes(), &credentials),
                Err("failed"),
                "{body}"
            );
        }
        assert_eq!(
            require_clean(
                &[("x-echo".into(), "Bearer token/value 1".into())],
                b"{}",
                &credentials
            ),
            Err("failed")
        );
        assert_eq!(require_clean(&[], br#"{"id":"1"}"#, &credentials), Ok(()));
    }

    #[test]
    fn refuses_echoes_in_header_names_escaped_or_duplicated_json_and_unicode_text() {
        let mut broker = meta();
        broker.hold("meta-access-token", Zeroizing::new("tök€n-value".into()));
        broker.hold("meta-app-secret", Zeroizing::new("secret-1".into()));
        let (credentials, _) = broker.credentials("graph.facebook.com");
        let escaped: String =
            "tök€n-value"
                .encode_utf16()
                .fold(String::new(), |mut escaped, unit| {
                    let _ = write!(escaped, "\\u{unit:04X}");
                    escaped
                });
        for body in [
            format!(r#"{{"a":"{escaped}"}}"#),
            format!(r#"{{"a":"safe","a":"{escaped}"}}"#),
            format!(r#"not json "{escaped}""#),
            "plain TÖK€N-VALUE".to_owned(),
        ] {
            assert_eq!(
                require_clean(&[], body.as_bytes(), &credentials),
                Err("failed"),
                "{body}"
            );
        }
        assert_eq!(
            require_clean(&[("x-tök€n-value".into(), "1".into())], b"{}", &credentials),
            Err("failed")
        );
        assert_eq!(
            json_unescaped(r#"\ud83d\ude00 \"q\" \/"#),
            "\u{1f600} \"q\" /"
        );
    }

    #[test]
    fn every_content_encoding_occurrence_must_be_identity() {
        let mut headers = ureq::http::HeaderMap::new();
        assert!(identity_encoded(&headers));
        headers.append("content-encoding", "identity".parse().unwrap());
        assert!(identity_encoded(&headers));
        headers.append("content-encoding", "gzip".parse().unwrap());
        assert!(!identity_encoded(&headers));
        let mut joined = ureq::http::HeaderMap::new();
        joined.append("content-encoding", "identity, gzip".parse().unwrap());
        assert!(!identity_encoded(&joined));
    }

    #[test]
    fn only_a_call_that_cannot_have_been_sent_is_unavailable() {
        assert_eq!(unsent(&ureq::Error::HostNotFound), "unavailable");
        assert_eq!(unsent(&ureq::Error::ConnectionFailed), "unavailable");
        assert_eq!(
            unsent(&ureq::Error::Timeout(ureq::Timeout::Connect)),
            "unavailable"
        );
        for error in [
            ureq::Error::Timeout(ureq::Timeout::RecvResponse),
            ureq::Error::Timeout(ureq::Timeout::Global),
            ureq::Error::Io(std::io::Error::other("reset")),
            ureq::Error::BodyStalled,
        ] {
            assert_eq!(unsent(&error), "failed", "{error}");
        }
    }

    #[test]
    fn admits_a_body_on_any_admitted_method() {
        let broker = meta();
        let hosts = broker.hosts.clone();
        for method in METHODS {
            let frame = json!({"type": "fetch", "method": method, "url": "https://api.example.com/v1",
                "headers": [], "body": STANDARD.encode(b"x=1")});
            assert_eq!(
                parse(&frame, &hosts).expect("admitted").body.as_deref(),
                Some(&b"x=1"[..])
            );
        }
    }
}
