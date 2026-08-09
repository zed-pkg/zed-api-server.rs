//! Customer-realm Shared Auth verification for registry account endpoints.
//!
//! Shared Auth establishes identity and session revocation. The registry maps
//! the verified immutable subject into `users` and remains responsible for
//! organization, project, package, and invitation authorization.

use std::sync::OnceLock;
use std::time::Duration;

use axum::http::{HeaderMap, header};
use reqwest::StatusCode;
use zed_orm::models::SessionIdentity;

use crate::config::Config;
use crate::error::ApiErr;

#[derive(Clone, Debug)]
pub struct AuthenticatedSession {
    pub identity: SessionIdentity,
    pub aal: u8,
}

pub async fn authenticate(
    config: &Config,
    request_headers: &HeaderMap,
) -> Result<AuthenticatedSession, ApiErr> {
    let token = bearer(request_headers)
        .or_else(|| cookie_value(request_headers, &config.shared_auth_cookie_name))
        .ok_or_else(ApiErr::unauthorized)?;

    if token.len() > 16 * 1024 {
        return Err(ApiErr::unauthorized());
    }

    let response = client()
        .get(format!("{}/auth/verify", config.shared_auth_url))
        .bearer_auth(&token)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(%error, "Shared Auth verification request failed");
            ApiErr::service_unavailable(
                "shared_auth_unavailable",
                "authentication service is unavailable",
            )
        })?;

    match response.status() {
        StatusCode::OK => session_from_headers(response.headers()),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(ApiErr::unauthorized()),
        StatusCode::TOO_MANY_REQUESTS => Err(ApiErr::service_unavailable(
            "shared_auth_busy",
            "authentication service is busy",
        )),
        status => {
            tracing::warn!(%status, "Shared Auth returned an unexpected status");
            Err(ApiErr::service_unavailable(
                "shared_auth_upstream",
                "authentication service returned an unexpected response",
            ))
        }
    }
}

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(reqwest::Client::new)
}

fn session_from_headers(headers: &HeaderMap) -> Result<AuthenticatedSession, ApiErr> {
    let subject = required_header(headers, "x-auth-user-id")?;
    let email = optional_header(headers, "x-auth-email");
    let aal = optional_header(headers, "x-auth-aal")
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(1);

    Ok(AuthenticatedSession {
        identity: SessionIdentity {
            subject,
            email,
            display_name: None,
            avatar_url: None,
        },
        aal,
    })
}

fn required_header(headers: &HeaderMap, name: &'static str) -> Result<String, ApiErr> {
    optional_header(headers, name).ok_or_else(|| {
        tracing::warn!(header = name, "Shared Auth response omitted required identity header");
        ApiErr::service_unavailable(
            "shared_auth_contract",
            "authentication service returned an incomplete identity",
        )
    })
}

fn optional_header(headers: &HeaderMap, name: &'static str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(candidate, value)| {
            (candidate == name && !value.is_empty()).then(|| value.to_owned())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn bearer_wins_over_the_browser_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer cli-token"));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("__Host-ore-session=browser-token"),
        );
        assert_eq!(bearer(&headers).as_deref(), Some("cli-token"));
        assert_eq!(
            cookie_value(&headers, "__Host-ore-session").as_deref(),
            Some("browser-token")
        );
    }

    #[test]
    fn cookie_parser_matches_the_exact_name() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other=value; __Host-ore-session=token; suffix=no"),
        );
        assert_eq!(
            cookie_value(&headers, "__Host-ore-session").as_deref(),
            Some("token")
        );
        assert_eq!(cookie_value(&headers, "ore-session"), None);
    }
}
