//! The one outbound HTTP client policy: a request is bounded by a timeout, never follows a redirect, and returns every
//! HTTP status to its caller. A caller that needs more, such as HTTPS only, adds it to [`config`].

use std::time::Duration;

use ureq::Agent;
use ureq::config::ConfigBuilder;
use ureq::typestate::AgentScope;
use zeroize::Zeroizing;

/// The policy for one agent bounded by `timeout`, for a caller that adds to it.
pub(crate) fn config(timeout: Duration) -> ConfigBuilder<AgentScope> {
    Agent::config_builder()
        .timeout_global(Some(timeout))
        .max_redirects(0)
        .http_status_as_error(false)
}

/// An agent bounded by `timeout` under the policy.
pub(crate) fn agent(timeout: Duration) -> Agent {
    config(timeout).build().into()
}

/// The bearer `Authorization` header value, wiped from memory when dropped.
pub(crate) fn bearer(token: &str) -> Zeroizing<String> {
    Zeroizing::new(format!("Bearer {token}"))
}
