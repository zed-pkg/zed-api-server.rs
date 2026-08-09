//! Minimal Shared Auth service adapter.
//!
//! The transport and JSON shapes are kept equivalent to
//! `shared-auth/shared-auth-clients` commit
//! `1b1089123394ac4006901cdac477d63bfba48943`. This local adapter exists because
//! a repository-scoped GitHub Actions token cannot clone a private repository
//! in another organization. Only the two product-server operations used here
//! are implemented: Supabase token exchange and protected audience-bound
//! introspection.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::redirect::Policy;
use reqwest::{Method, RequestBuilder, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const MAX_REQUEST_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;

#[derive(Debug)]
pub enum ClientError {
    Unauthorized,
    MissingServiceCredential,
    InvalidBaseUrl,
    InvalidInput(&'static str),
    RequestTooLarge { limit: usize },
    ResponseTooLarge { limit: usize },
    Decode(serde_json::Error),
    Transport(reqwest::Error),
    Status(u16),
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => formatter.write_str("unauthorized"),
            Self::MissingServiceCredential => {
                formatter.write_str("introspection service credential is required")
            }
            Self::InvalidBaseUrl => formatter.write_str("invalid shared-auth base URL"),
            Self::InvalidInput(field) => write!(formatter, "invalid {field}"),
            Self::RequestTooLarge { limit } => {
                write!(formatter, "request body exceeds {limit} bytes")
            }
            Self::ResponseTooLarge { limit } => {
                write!(formatter, "response body exceeds {limit} bytes")
            }
            Self::Decode(error) => write!(formatter, "response JSON decoding failed: {error}"),
            Self::Transport(error) => write!(formatter, "transport failed: {error}"),
            Self::Status(status) => write!(formatter, "unexpected status {status}"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}

impl From<reqwest::Error> for ClientError {
    fn from(error: reqwest::Error) -> Self {
        Self::Transport(error)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ExchangeResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_at: u64,
    pub shared_user_id: String,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub provider_tenant: Option<String>,
}

/// Only claims consumed by zed-pkg are modeled. Additional Shared Auth claims
/// remain available through `rest`, while unknown future claims continue to be
/// accepted by serde.
#[derive(Clone, Debug, Deserialize)]
pub struct Introspection {
    pub active: bool,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct IntrospectRequest<'a> {
    token: &'a str,
    audience: &'a str,
}

#[derive(Clone)]
pub struct SharedAuthClient {
    base: Option<Url>,
    http: reqwest::Client,
    service_credential: Option<Arc<str>>,
}

impl SharedAuthClient {
    pub fn new(base: impl AsRef<str>) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .redirect(Policy::none())
            .user_agent("zed-api-server/shared-auth-adapter/0.1")
            .build()
            .expect("static Shared Auth HTTP client configuration is valid");
        Self {
            base: normalize_base(base.as_ref()),
            http,
            service_credential: None,
        }
    }

    pub fn with_service_credential(mut self, credential: impl Into<String>) -> Self {
        self.service_credential = Some(Arc::<str>::from(credential.into()));
        self
    }

    /// Supabase access token -> Shared Auth token.
    pub async fn exchange(&self, supabase_token: &str) -> Result<ExchangeResponse, ClientError> {
        let token = required_credential(supabase_token, "Supabase token")?;
        let request = self
            .request(Method::POST, "auth/exchange")?
            .header(AUTHORIZATION, bearer_value(token)?);
        self.send_json(request).await
    }

    /// Protected introspection pinned to zed-pkg's delegated product audience.
    pub async fn introspect_for_audience(
        &self,
        token: &str,
        audience: &str,
    ) -> Result<Introspection, ClientError> {
        let token = required_credential(token, "token")?;
        let audience = required_identifier(audience, "audience")?;
        let service_credential = self
            .service_credential
            .as_deref()
            .ok_or(ClientError::MissingServiceCredential)?;
        let service_credential = required_credential(service_credential, "service credential")?;
        let body = serde_json::to_vec(&IntrospectRequest { token, audience })
            .map_err(ClientError::Decode)?;
        if body.len() > MAX_REQUEST_BYTES {
            return Err(ClientError::RequestTooLarge {
                limit: MAX_REQUEST_BYTES,
            });
        }
        let request = self
            .request(Method::POST, "auth/introspect")?
            .header(AUTHORIZATION, bearer_value(service_credential)?)
            .header(CONTENT_TYPE, "application/json")
            .body(body);
        self.send_json(request).await
    }

    fn request(&self, method: Method, relative_path: &str) -> Result<RequestBuilder, ClientError> {
        let base = self.base.as_ref().ok_or(ClientError::InvalidBaseUrl)?;
        let url = base
            .join(relative_path)
            .map_err(|_| ClientError::InvalidBaseUrl)?;
        Ok(self
            .http
            .request(method, url)
            .header(ACCEPT, "application/json"))
    }

    async fn send_json<T>(&self, request: RequestBuilder) -> Result<T, ClientError>
    where
        T: DeserializeOwned,
    {
        let response = request.send().await?;
        let status = response.status();
        if status.as_u16() == 401 {
            return Err(ClientError::Unauthorized);
        }
        if !status.is_success() {
            return Err(ClientError::Status(status.as_u16()));
        }
        let bytes = response.bytes().await?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(ClientError::ResponseTooLarge {
                limit: MAX_RESPONSE_BYTES,
            });
        }
        serde_json::from_slice(&bytes).map_err(ClientError::Decode)
    }
}

fn normalize_base(raw: &str) -> Option<Url> {
    let mut raw = raw.trim().to_owned();
    if raw.is_empty() {
        return None;
    }
    if !raw.ends_with('/') {
        raw.push('/');
    }
    let url = Url::parse(&raw).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some(url)
}

fn required_credential<'a>(value: &'a str, field: &'static str) -> Result<&'a str, ClientError> {
    if value.is_empty()
        || value.len() > MAX_CREDENTIAL_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(ClientError::InvalidInput(field))
    } else {
        Ok(value)
    }
}

fn required_identifier<'a>(value: &'a str, field: &'static str) -> Result<&'a str, ClientError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        Err(ClientError::InvalidInput(field))
    } else {
        Ok(value)
    }
}

fn bearer_value(token: &str) -> Result<reqwest::header::HeaderValue, ClientError> {
    let value = format!("Bearer {token}");
    reqwest::header::HeaderValue::from_str(&value)
        .map_err(|_| ClientError::InvalidInput("bearer credential"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mounted_base_urls_are_normalized_without_changing_the_prefix() {
        let base = normalize_base("https://gateway.example.test/shared-auth").unwrap();
        assert_eq!(
            base.join("auth/exchange").unwrap().as_str(),
            "https://gateway.example.test/shared-auth/auth/exchange"
        );
    }

    #[test]
    fn base_urls_with_credentials_or_query_state_are_rejected() {
        assert!(normalize_base("https://user:pass@example.test/").is_none());
        assert!(normalize_base("https://example.test/?tenant=other").is_none());
        assert!(normalize_base("file:///tmp/shared-auth").is_none());
    }

    #[test]
    fn credentials_and_audiences_are_bounded_and_header_safe() {
        assert!(required_credential("token-value", "token").is_ok());
        assert!(required_credential("token\nvalue", "token").is_err());
        assert!(required_identifier("zed-pkg", "audience").is_ok());
        assert!(required_identifier("zed pkg", "audience").is_err());
    }
}
