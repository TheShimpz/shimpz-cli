//! A Stored Input's reviewed routes (Assistant Spec v1, ADR-0106 amendment of 2026-10-09).
//!
//! Every Stored Input declares `routes`: 1 to 32 entries `{method, path, query?}`, unique by method and path, naming
//! the only provider endpoints on its host that ever receive its value. A path is `/`-prefixed segments, each a literal
//! of 1 to 64 unreserved characters other than `.` and `..`, or `*` for exactly one segment; optional query selectors
//! name provider parameters that change endpoint authority and their only raw values. A segment that names a
//! credential endpoint is refused. This mirrors the Developers reference validator `validators/route.py` exactly; its
//! golden vectors drive the tests.

use serde_json::{Map, Value};

const METHODS: [&str; 6] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];
const MAX_ROUTES: usize = 32;
const MAX_PATH: usize = 512;
const MAX_LITERAL: usize = 64;
const MAX_SELECTORS: usize = 8;
const MAX_SELECTOR_VALUES: usize = 16;
const MAX_SELECTOR_VALUE: usize = 256;
const WILDCARD: &str = "*";
const CREDENTIAL_STEMS: [&str; 7] = [
    "apikey",
    "authoriz",
    "credential",
    "oauth",
    "password",
    "secret",
    "token",
];

/// Return the reference validator's stable reason when one Stored Input's declared routes are refused.
pub(crate) fn routes_error(routes: &Value) -> Option<&'static str> {
    let Some(routes) = routes
        .as_array()
        .filter(|routes| (1..=MAX_ROUTES).contains(&routes.len()))
    else {
        return Some("routes_invalid");
    };
    let mut declared: Vec<(&str, &str)> = Vec::with_capacity(routes.len());
    for route in routes {
        let (method, path) = match route_error(route) {
            Ok(route) => route,
            Err(reason) => return Some(reason),
        };
        if declared.contains(&(method, path)) {
            return Some("route_duplicate");
        }
        declared.push((method, path));
    }
    None
}

/// One admitted route's method and path, or the reason it is refused.
fn route_error(route: &Value) -> Result<(&str, &str), &'static str> {
    let fields = route.as_object().ok_or("route_invalid")?;
    let method = fields.get("method").and_then(Value::as_str);
    let Some(method) = method.filter(|method| {
        fields.contains_key("path")
            && fields
                .keys()
                .all(|key| ["method", "path", "query"].contains(&key.as_str()))
            && METHODS.contains(method)
    }) else {
        return Err("route_invalid");
    };
    let path = fields
        .get("path")
        .and_then(Value::as_str)
        .filter(|path| path.chars().count() <= MAX_PATH)
        .and_then(|path| path.strip_prefix('/').map(|segments| (path, segments)));
    let Some((path, segments)) = path else {
        return Err("route_path_invalid");
    };
    if !segments
        .split('/')
        .all(|segment| segment == WILDCARD || literal(segment, MAX_LITERAL))
    {
        return Err("route_path_invalid");
    }
    if segments
        .split('/')
        .any(|segment| segment != WILDCARD && credential_segment(segment))
    {
        return Err("route_credential");
    }
    if fields.get("query").is_some_and(|query| !selectors(query)) {
        return Err("route_query_invalid");
    }
    Ok((method, path))
}

/// 1 to `maximum` unreserved characters other than `.` and `..`.
fn literal(segment: &str, maximum: usize) -> bool {
    (1..=maximum).contains(&segment.len())
        && segment.bytes().all(unreserved)
        && segment != "."
        && segment != ".."
}

fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"._~-".contains(&byte)
}

/// Whether one path segment names an endpoint that may issue, list, or exchange credentials.
fn credential_segment(segment: &str) -> bool {
    let folded: String = segment
        .chars()
        .filter(|character| !"-_.~".contains(*character))
        .collect::<String>()
        .to_lowercase();
    CREDENTIAL_STEMS.iter().any(|stem| folded.contains(stem))
}

fn selector_name(name: &str) -> bool {
    (1..=MAX_LITERAL).contains(&name.len()) && name.bytes().all(unreserved)
}

/// Unreserved characters or uppercase percent triplets, as a standard query encoder writes a reserved character.
fn selector_value(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let triplet = bytes.get(index + 1..index + 3);
            if !triplet.is_some_and(|digits| {
                digits
                    .iter()
                    .all(|digit| digit.is_ascii_digit() || (b'A'..=b'F').contains(digit))
            }) {
                return false;
            }
            index += 3;
        } else if unreserved(bytes[index]) {
            index += 1;
        } else {
            return false;
        }
    }
    !bytes.is_empty() && value.len() <= MAX_SELECTOR_VALUE
}

fn selectors(query: &Value) -> bool {
    let Some(selectors) = query
        .as_array()
        .filter(|selectors| (1..=MAX_SELECTORS).contains(&selectors.len()))
    else {
        return false;
    };
    let mut names: Vec<String> = Vec::with_capacity(selectors.len());
    for selector in selectors {
        let Some(fields) = selector.as_object().filter(|fields| {
            fields.len() == 2 && fields.contains_key("name") && fields.contains_key("values")
        }) else {
            return false;
        };
        let Some(name) = fields
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| selector_name(name))
        else {
            return false;
        };
        let name = name.to_ascii_lowercase();
        if names.contains(&name) || !values(fields) {
            return false;
        }
        names.push(name);
    }
    true
}

fn values(fields: &Map<String, Value>) -> bool {
    let Some(values) = fields
        .get("values")
        .and_then(Value::as_array)
        .filter(|values| (1..=MAX_SELECTOR_VALUES).contains(&values.len()))
    else {
        return false;
    };
    values.iter().enumerate().all(|(index, value)| {
        value.as_str().is_some_and(selector_value) && !values[..index].contains(value)
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::routes_error;

    const ROUTE_VECTORS: &str = include_str!("../contracts/assistant/route-vectors.json");

    fn cases(vectors: &str) -> Vec<Value> {
        let vectors: Value = serde_json::from_str(vectors).expect("vectors");
        assert_eq!(vectors["version"], 1);
        vectors["cases"].as_array().expect("cases").clone()
    }

    #[test]
    fn declared_routes_follow_the_developers_golden_vectors() {
        let cases = cases(ROUTE_VECTORS);
        assert!(!cases.is_empty());
        for case in cases {
            let valid = case["valid"].as_bool().expect("valid");
            assert_eq!(
                routes_error(&case["routes"]).is_none(),
                valid,
                "{}: {:?}",
                case["name"],
                routes_error(&case["routes"])
            );
        }
    }

    #[test]
    fn each_refusal_carries_the_reference_validators_reason() {
        let route = |path: &str| json!([{"method": "GET", "path": path}]);
        for (routes, reason) in [
            (json!([]), "routes_invalid"),
            (json!(["GET /x"]), "route_invalid"),
            (json!([{"method": "GET"}]), "route_invalid"),
            (route("x"), "route_path_invalid"),
            (route("/a//b"), "route_path_invalid"),
            (route("/v1/oauth/token"), "route_credential"),
            (route("/v1/Access-Token"), "route_credential"),
            (
                json!([{"method": "GET", "path": "/v1", "query": []}]),
                "route_query_invalid",
            ),
            (
                json!([{"method": "GET", "path": "/v1"}, {"method": "GET", "path": "/v1"}]),
                "route_duplicate",
            ),
        ] {
            assert_eq!(routes_error(&routes), Some(reason), "{routes}");
        }
        assert_eq!(routes_error(&route("/v1/*/items")), None);
    }
}
