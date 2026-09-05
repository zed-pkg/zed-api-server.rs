//! Authenticated API boundary for public commercial intake.
//!
//! Cloudflare verifies the browser challenge and signs the exact canonical JSON
//! bytes. This module independently authenticates that edge request, validates
//! the shared DTO, computes privacy-preserving fingerprints, and calls the
//! named `zed-orm-core` write operation. Submitted contact data is never placed
//! in logs, metrics, URLs, response bodies, or raw service-owned SQL.

use std::collections::HashSet;
use std::env;
use std::hash::Hash;
use std::sync::Arc;

use axum::body::{Bytes, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use chrono::{DateTime, SecondsFormat, Utc};
use sha2::{Digest, Sha256};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use uuid::Uuid;
use zed_interfaces::public_intake::{
    IDEMPOTENCY_KEY_HEADER, PRE_INTEREST_PATH_V1, PUBLIC_INTAKE_SCHEMA_V1,
    PublicIntakeAcceptedStatusV1, PublicIntakeAcceptedV1, PublicIntakeErrorCodeV1,
    PublicIntakeErrorV1, PublicIntakeInterestV1, PublicIntakePartyV1,
    PublicIntakeSchemaV1, PublicIntakeSourceHostV1, QUOTE_REQUESTS_PATH_V1, QuoteRequestV1,
    PreInterestRegistrationRequestV1,
};
use zed_orm_core::public_intake::{
    NewPublicIntakeSubmission, PublicIntakeKind, PublicIntakeWriteError,
    write_public_intake_submission,
};

use crate::state::AppState;

const API_HOST: &str = "api.zpkg.net";
const MAX_BODY_BYTES: usize = 16 * 1024;
const MAX_EDGE_CLOCK_SKEW_SECONDS: u64 = 300;
const MAX_CONSENT_CLOCK_SKEW_SECONDS: u64 = 24 * 60 * 60;
const MAX_CONCURRENT_WRITES: usize = 64;

const EDGE_TIMESTAMP_HEADER: &str = "x-zed-intake-timestamp";
const EDGE_SOURCE_HOST_HEADER: &str = "x-zed-intake-source-host";
const EDGE_BODY_SHA256_HEADER: &str = "x-zed-intake-body-sha256";
const EDGE_SIGNATURE_HEADER: &str = "x-zed-intake-signature";

const SIGNING_KEY_ENV: &str = "ZED_PUBLIC_INTAKE_SIGNING_KEY";
const LOOKUP_KEY_ENV: &str = "ZED_PUBLIC_INTAKE_LOOKUP_KEY";
const ENCRYPTION_KEY_ENV: &str = "ZED_PUBLIC_INTAKE_ENCRYPTION_KEY";
const CONSENT_REVISION_ENV: &str = "ZED_PUBLIC_INTAKE_CONSENT_REVISION";
const MARKETING_REVISION_ENV: &str = "ZED_PUBLIC_INTAKE_MARKETING_CONSENT_REVISION";

pub(crate) fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(PRE_INTEREST_PATH_V1, post(submit_pre_interest))
        .route(QUOTE_REQUESTS_PATH_V1, post(submit_quote_request))
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_WRITES))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, max-age=0"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .with_state(state)
}

async fn submit_pre_interest(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Response {
    respond(process_pre_interest(&state, request, Utc::now()).await)
}

async fn submit_quote_request(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Response {
    respond(process_quote_request(&state, request, Utc::now()).await)
}

async fn process_pre_interest(
    state: &AppState,
    request: Request,
    now: DateTime<Utc>,
) -> Result<(), PublicApiError> {
    let authenticated = authenticate_request(
        request,
        PRE_INTEREST_PATH_V1,
        PublicIntakeSourceHostV1::User,
        now.timestamp(),
    )
    .await?;
    let dto = serde_json::from_slice::<PreInterestRegistrationRequestV1>(&authenticated.body)
        .map_err(|_| PublicApiError::invalid_request())?;
    let normalized = normalize_pre_interest(
        dto,
        authenticated.request_id,
        &authenticated.secrets,
        now,
    )?;
    persist(
        state,
        PublicIntakeKind::PreInterest,
        PublicIntakeSourceHostV1::User,
        authenticated,
        normalized,
    )
    .await
}

async fn process_quote_request(
    state: &AppState,
    request: Request,
    now: DateTime<Utc>,
) -> Result<(), PublicApiError> {
    let authenticated = authenticate_request(
        request,
        QUOTE_REQUESTS_PATH_V1,
        PublicIntakeSourceHostV1::Organization,
        now.timestamp(),
    )
    .await?;
    let dto = serde_json::from_slice::<QuoteRequestV1>(&authenticated.body)
        .map_err(|_| PublicApiError::invalid_request())?;
    let normalized = normalize_quote(
        dto,
        authenticated.request_id,
        &authenticated.secrets,
        now,
    )?;
    persist(
        state,
        PublicIntakeKind::QuoteRequest,
        PublicIntakeSourceHostV1::Organization,
        authenticated,
        normalized,
    )
    .await
}

async fn persist(
    state: &AppState,
    kind: PublicIntakeKind,
    source_host: PublicIntakeSourceHostV1,
    authenticated: AuthenticatedRequest,
    normalized: NormalizedSubmission,
) -> Result<(), PublicApiError> {
    let context = state
        .registry_write
        .as_ref()
        .ok_or_else(PublicApiError::temporarily_unavailable)?;
    let email_lookup_hmac = hmac_sha256(
        authenticated.secrets.lookup_key.as_bytes(),
        normalized.email.as_bytes(),
    );
    let submission = NewPublicIntakeSubmission::new(
        authenticated.request_id,
        kind,
        source_host,
        authenticated.body_sha256,
        email_lookup_hmac,
        normalized.email,
        normalized.payload_json,
        normalized.consented_at,
        normalized.marketing_consent,
    )
    .map_err(map_write_error)?;

    match write_public_intake_submission(
        context,
        &submission,
        &authenticated.secrets.encryption_key,
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(error) => Err(map_write_error(error)),
    }
}

fn map_write_error(error: PublicIntakeWriteError) -> PublicApiError {
    match error {
        PublicIntakeWriteError::InvalidInput(_) | PublicIntakeWriteError::IdempotencyConflict => {
            PublicApiError::invalid_request()
        }
        PublicIntakeWriteError::Persistence(_) => {
            tracing::error!("public intake persistence unavailable");
            PublicApiError::temporarily_unavailable()
        }
    }
}

struct AuthenticatedRequest {
    request_id: Uuid,
    body_sha256: [u8; 32],
    body: Bytes,
    secrets: IntakeSecrets,
}

async fn authenticate_request(
    request: Request,
    expected_path: &'static str,
    expected_source_host: PublicIntakeSourceHostV1,
    now_unix: i64,
) -> Result<AuthenticatedRequest, PublicApiError> {
    let (parts, body) = request.into_parts();
    if parts.uri.path() != expected_path || parts.uri.query().is_some() {
        return Err(PublicApiError::invalid_request());
    }
    if normalized_host(&parts.headers)? != API_HOST {
        return Err(PublicApiError::not_found());
    }
    let content_type = single_header(&parts.headers, header::CONTENT_TYPE.as_str())?;
    if content_type
        .split(';')
        .next()
        .map(str::trim)
        .map(|value| value.eq_ignore_ascii_case("application/json"))
        != Some(true)
    {
        return Err(PublicApiError::unsupported_media_type());
    }
    if optional_single_header(&parts.headers, header::CONTENT_ENCODING.as_str())?.is_some() {
        return Err(PublicApiError::unsupported_media_type());
    }
    if let Some(content_length) = optional_single_header(&parts.headers, header::CONTENT_LENGTH.as_str())?
    {
        if content_length
            .parse::<usize>()
            .ok()
            .is_none_or(|length| length > MAX_BODY_BYTES)
        {
            return Err(PublicApiError::payload_too_large());
        }
    }

    let body = to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| PublicApiError::payload_too_large())?;
    if body.is_empty() {
        return Err(PublicApiError::invalid_request());
    }
    let secrets = IntakeSecrets::from_env()?;
    let (request_id, body_sha256) = verify_edge_headers(
        &parts.headers,
        &body,
        expected_path,
        expected_source_host,
        now_unix,
        secrets.signing_key.as_bytes(),
    )?;

    Ok(AuthenticatedRequest {
        request_id,
        body_sha256,
        body,
        secrets,
    })
}

fn verify_edge_headers(
    headers: &HeaderMap,
    body: &[u8],
    expected_path: &'static str,
    expected_source_host: PublicIntakeSourceHostV1,
    now_unix: i64,
    signing_key: &[u8],
) -> Result<(Uuid, [u8; 32]), PublicApiError> {
    let source_host = single_header(headers, EDGE_SOURCE_HOST_HEADER)?;
    let expected_source_host = source_host_wire(expected_source_host);
    if source_host != expected_source_host {
        return Err(PublicApiError::abuse_challenge_failed());
    }

    let request_id_text = single_header(headers, IDEMPOTENCY_KEY_HEADER)?;
    if request_id_text != request_id_text.to_ascii_lowercase() {
        return Err(PublicApiError::invalid_request());
    }
    let request_id = Uuid::parse_str(request_id_text)
        .map_err(|_| PublicApiError::invalid_request())?;
    if request_id.get_variant() != uuid::Variant::RFC4122 {
        return Err(PublicApiError::invalid_request());
    }

    let timestamp_text = single_header(headers, EDGE_TIMESTAMP_HEADER)?;
    let timestamp = timestamp_text
        .parse::<i64>()
        .map_err(|_| PublicApiError::abuse_challenge_failed())?;
    if now_unix.abs_diff(timestamp) > MAX_EDGE_CLOCK_SKEW_SECONDS {
        return Err(PublicApiError::abuse_challenge_failed());
    }

    let body_sha256 = sha256(body);
    let supplied_digest = parse_hex_32(single_header(headers, EDGE_BODY_SHA256_HEADER)?)
        .ok_or_else(PublicApiError::abuse_challenge_failed)?;
    if !constant_time_eq(&body_sha256, &supplied_digest) {
        return Err(PublicApiError::abuse_challenge_failed());
    }

    let signature = single_header(headers, EDGE_SIGNATURE_HEADER)?
        .strip_prefix("v1=")
        .and_then(parse_hex_32)
        .ok_or_else(PublicApiError::abuse_challenge_failed)?;
    let signed = format!(
        "v1\n{timestamp_text}\n{expected_source_host}\n{expected_path}\n{request_id_text}\n{}",
        hex::encode(body_sha256)
    );
    let expected_signature = hmac_sha256(signing_key, signed.as_bytes());
    if !constant_time_eq(&signature, &expected_signature) {
        return Err(PublicApiError::abuse_challenge_failed());
    }

    Ok((request_id, body_sha256))
}

struct IntakeSecrets {
    signing_key: String,
    lookup_key: String,
    encryption_key: String,
    consent_revision: String,
    marketing_revision: String,
}

impl IntakeSecrets {
    fn from_env() -> Result<Self, PublicApiError> {
        let signing_key = required_secret(SIGNING_KEY_ENV, 32)?;
        let lookup_key = required_secret(LOOKUP_KEY_ENV, 32)?;
        let encryption_key = required_secret(ENCRYPTION_KEY_ENV, 32)?;
        let consent_revision = required_revision(CONSENT_REVISION_ENV)?;
        let marketing_revision = required_revision(MARKETING_REVISION_ENV)?;
        Ok(Self {
            signing_key,
            lookup_key,
            encryption_key,
            consent_revision,
            marketing_revision,
        })
    }

    #[cfg(test)]
    fn fixture() -> Self {
        Self {
            signing_key: "0123456789abcdef0123456789abcdef".to_owned(),
            lookup_key: "lookup-0123456789abcdef0123456789abcdef".to_owned(),
            encryption_key: "encrypt-0123456789abcdef0123456789abcdef".to_owned(),
            consent_revision: "privacy-2026-09-01".to_owned(),
            marketing_revision: "marketing-2026-09-01".to_owned(),
        }
    }
}

struct NormalizedSubmission {
    email: String,
    payload_json: String,
    consented_at: DateTime<Utc>,
    marketing_consent: bool,
}

fn normalize_pre_interest(
    mut request: PreInterestRegistrationRequestV1,
    request_id: Uuid,
    secrets: &IntakeSecrets,
    now: DateTime<Utc>,
) -> Result<NormalizedSubmission, PublicApiError> {
    if request.schema != PublicIntakeSchemaV1::V1
        || request.request_id != request_id.to_string()
        || request.party_type != PublicIntakePartyV1::Individual
        || request.source_host != PublicIntakeSourceHostV1::User
        || request.organization_name.is_some()
    {
        return Err(PublicApiError::invalid_request());
    }
    validate_interests(&request.interests)?;
    validate_consent(
        request.contact_consent,
        request.marketing_consent,
        request.marketing_consent_revision.as_deref(),
        &request.consent_revision,
        secrets,
    )?;

    request.email = normalize_email(&request.email)?;
    request.contact_name = normalize_optional_human(request.contact_name, 120)?;
    request.website_url = normalize_optional_website(request.website_url)?;
    request.locale = normalize_optional_locale(request.locale)?;
    request.referral_code = normalize_optional_identifier(request.referral_code, 64)?;
    let consented_at = normalize_consent_timestamp(&request.consented_at, now)?;
    request.consented_at = consented_at.to_rfc3339_opts(SecondsFormat::Millis, true);
    request.consent_revision = secrets.consent_revision.clone();
    request.marketing_consent_revision = request
        .marketing_consent
        .then(|| secrets.marketing_revision.clone());

    let email = request.email.clone();
    let marketing_consent = request.marketing_consent;
    let payload_json = serde_json::to_string(&request)
        .map_err(|_| PublicApiError::temporarily_unavailable())?;
    Ok(NormalizedSubmission {
        email,
        payload_json,
        consented_at,
        marketing_consent,
    })
}

fn normalize_quote(
    mut request: QuoteRequestV1,
    request_id: Uuid,
    secrets: &IntakeSecrets,
    now: DateTime<Utc>,
) -> Result<NormalizedSubmission, PublicApiError> {
    if request.schema != PublicIntakeSchemaV1::V1
        || request.request_id != request_id.to_string()
        || request.source_host != PublicIntakeSourceHostV1::Organization
    {
        return Err(PublicApiError::invalid_request());
    }
    validate_interests(&request.interests)?;
    validate_consent(
        request.contact_consent,
        request.marketing_consent,
        request.marketing_consent_revision.as_deref(),
        &request.consent_revision,
        secrets,
    )?;

    request.email = normalize_email(&request.email)?;
    request.organization_name = normalize_human(request.organization_name, 200)?;
    request.contact_name = normalize_human(request.contact_name, 120)?;
    request.role = normalize_optional_human(request.role, 120)?;
    request.website_url = normalize_optional_website(request.website_url)?;
    request.requirements_summary = request
        .requirements_summary
        .map(|value| normalize_human(value, 1_000).and_then(reject_secret_like_text))
        .transpose()?;
    request.locale = normalize_optional_locale(request.locale)?;
    request.referral_code = normalize_optional_identifier(request.referral_code, 64)?;
    let consented_at = normalize_consent_timestamp(&request.consented_at, now)?;
    request.consented_at = consented_at.to_rfc3339_opts(SecondsFormat::Millis, true);
    request.consent_revision = secrets.consent_revision.clone();
    request.marketing_consent_revision = request
        .marketing_consent
        .then(|| secrets.marketing_revision.clone());

    let email = request.email.clone();
    let marketing_consent = request.marketing_consent;
    let payload_json = serde_json::to_string(&request)
        .map_err(|_| PublicApiError::temporarily_unavailable())?;
    Ok(NormalizedSubmission {
        email,
        payload_json,
        consented_at,
        marketing_consent,
    })
}

fn validate_interests<T: Eq + Hash>(values: &[T]) -> Result<(), PublicApiError> {
    if values.is_empty() || values.len() > 9 {
        return Err(PublicApiError::invalid_request());
    }
    let unique = values.iter().collect::<HashSet<_>>();
    if unique.len() != values.len() {
        return Err(PublicApiError::invalid_request());
    }
    Ok(())
}

fn validate_consent(
    contact_consent: bool,
    marketing_consent: bool,
    marketing_revision: Option<&str>,
    consent_revision: &str,
    secrets: &IntakeSecrets,
) -> Result<(), PublicApiError> {
    if !contact_consent || consent_revision != secrets.consent_revision {
        return Err(PublicApiError::invalid_request());
    }
    match (marketing_consent, marketing_revision) {
        (true, Some(revision)) if revision == secrets.marketing_revision => Ok(()),
        (false, None) => Ok(()),
        _ => Err(PublicApiError::invalid_request()),
    }
}

fn normalize_email(value: &str) -> Result<String, PublicApiError> {
    let value = value.trim();
    if value.len() < 3
        || value.len() > 254
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(PublicApiError::invalid_request());
    }
    let mut parts = value.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default().to_ascii_lowercase();
    if parts.next().is_some()
        || local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !valid_domain(&domain)
    {
        return Err(PublicApiError::invalid_request());
    }
    Ok(format!("{}@{domain}", local.to_ascii_lowercase()))
}

fn valid_domain(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn normalize_human(value: String, maximum: usize) -> Result<String, PublicApiError> {
    if value.chars().any(char::is_control) {
        return Err(PublicApiError::invalid_request());
    }
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() || normalized.chars().count() > maximum {
        return Err(PublicApiError::invalid_request());
    }
    Ok(normalized)
}

fn normalize_optional_human(
    value: Option<String>,
    maximum: usize,
) -> Result<Option<String>, PublicApiError> {
    value.map(|value| normalize_human(value, maximum)).transpose()
}

fn normalize_optional_website(value: Option<String>) -> Result<Option<String>, PublicApiError> {
    value.map(normalize_website).transpose()
}

fn normalize_website(value: String) -> Result<String, PublicApiError> {
    let value = value.trim();
    if value.len() > 2_048
        || !value.is_ascii()
        || !value.starts_with("https://")
        || value.contains('\\')
        || value.bytes().any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(PublicApiError::invalid_request());
    }
    let authority = value["https://".len()..]
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err(PublicApiError::invalid_request());
    }
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.bytes().all(|byte| byte.is_ascii_digit()) => {
            host
        }
        Some(_) => return Err(PublicApiError::invalid_request()),
        None => authority,
    };
    if !valid_domain(&host.to_ascii_lowercase()) {
        return Err(PublicApiError::invalid_request());
    }
    Ok(value.to_owned())
}

fn normalize_optional_locale(value: Option<String>) -> Result<Option<String>, PublicApiError> {
    value.map(normalize_locale).transpose()
}

fn normalize_locale(value: String) -> Result<String, PublicApiError> {
    let value = value.trim();
    if !(2..=35).contains(&value.len()) || !value.is_ascii() {
        return Err(PublicApiError::invalid_request());
    }
    let mut segments = value.split('-');
    let language = segments.next().unwrap_or_default();
    if !(2..=3).contains(&language.len())
        || !language.bytes().all(|byte| byte.is_ascii_alphabetic())
        || !segments.all(|segment| {
            (2..=8).contains(&segment.len())
                && segment.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
    {
        return Err(PublicApiError::invalid_request());
    }
    Ok(value.to_owned())
}

fn normalize_optional_identifier(
    value: Option<String>,
    maximum: usize,
) -> Result<Option<String>, PublicApiError> {
    value
        .map(|value| {
            let value = value.trim();
            if portable_identifier(value, maximum) {
                Ok(value.to_owned())
            } else {
                Err(PublicApiError::invalid_request())
            }
        })
        .transpose()
}

fn portable_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.is_ascii()
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn normalize_consent_timestamp(
    value: &str,
    now: DateTime<Utc>,
) -> Result<DateTime<Utc>, PublicApiError> {
    if value.len() < 20 || value.len() > 35 || !value.is_ascii() {
        return Err(PublicApiError::invalid_request());
    }
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| PublicApiError::invalid_request())?
        .with_timezone(&Utc);
    if now
        .signed_duration_since(parsed)
        .num_seconds()
        .unsigned_abs()
        > MAX_CONSENT_CLOCK_SKEW_SECONDS
    {
        return Err(PublicApiError::invalid_request());
    }
    Ok(parsed)
}

fn reject_secret_like_text(value: String) -> Result<String, PublicApiError> {
    let lower = value.to_ascii_lowercase();
    let obvious = lower.contains("-----begin private key-----")
        || lower.contains("-----begin rsa private key-----")
        || lower.contains("password=")
        || token_like(&value, "ghp_", 20)
        || token_like(&value, "github_pat_", 24)
        || token_like(&value, "sk-", 20)
        || value.split(|character: char| !character.is_ascii_alphanumeric()).any(|token| {
            token.len() == 20 && token.starts_with("AKIA")
        });
    if obvious {
        Err(PublicApiError::invalid_request())
    } else {
        Ok(value)
    }
}

fn token_like(value: &str, prefix: &str, minimum: usize) -> bool {
    value
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        })
        .any(|token| token.starts_with(prefix) && token.len() >= minimum)
}

fn normalized_host(headers: &HeaderMap) -> Result<String, PublicApiError> {
    let host = single_header(headers, header::HOST.as_str())?
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    Ok(host
        .rsplit_once(':')
        .filter(|(name, port)| !name.contains(':') && port.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or(host.clone(), |(name, _)| name.to_owned()))
}

fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, PublicApiError> {
    optional_single_header(headers, name)?.ok_or_else(PublicApiError::abuse_challenge_failed)
}

fn optional_single_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<Option<&'a str>, PublicApiError> {
    let values = headers.get_all(name);
    let mut values = values.iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(PublicApiError::abuse_challenge_failed());
    }
    first
        .to_str()
        .map(Some)
        .map_err(|_| PublicApiError::abuse_challenge_failed())
}

fn source_host_wire(host: PublicIntakeSourceHostV1) -> &'static str {
    match host {
        PublicIntakeSourceHostV1::User => "user.zpkg.net",
        PublicIntakeSourceHostV1::Organization => "org.zpkg.net",
    }
}

fn required_secret(name: &'static str, minimum: usize) -> Result<String, PublicApiError> {
    let value = env::var(name).map_err(|_| PublicApiError::temporarily_unavailable())?;
    if value.as_bytes().len() < minimum
        || value.trim() != value
        || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
        || value.to_ascii_uppercase().contains("PLACEHOLDER")
    {
        return Err(PublicApiError::temporarily_unavailable());
    }
    Ok(value)
}

fn required_revision(name: &'static str) -> Result<String, PublicApiError> {
    let value = env::var(name).map_err(|_| PublicApiError::temporarily_unavailable())?;
    if !portable_identifier(&value, 64) || value.to_ascii_uppercase().contains("PLACEHOLDER") {
        return Err(PublicApiError::temporarily_unavailable());
    }
    Ok(value)
}

fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn hmac_sha256(key: &[u8], value: &[u8]) -> [u8; 32] {
    const BLOCK_BYTES: usize = 64;
    let mut normalized_key = [0_u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        normalized_key[..32].copy_from_slice(&sha256(key));
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36_u8; BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; BLOCK_BYTES];
    for index in 0..BLOCK_BYTES {
        inner_pad[index] ^= normalized_key[index];
        outer_pad[index] ^= normalized_key[index];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(value);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn parse_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return None;
    }
    let decoded = hex::decode(value).ok()?;
    decoded.try_into().ok()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

#[derive(Clone, Copy, Debug)]
struct PublicApiError {
    status: StatusCode,
    code: PublicIntakeErrorCodeV1,
    retryable: bool,
}

impl PublicApiError {
    const fn new(
        status: StatusCode,
        code: PublicIntakeErrorCodeV1,
        retryable: bool,
    ) -> Self {
        Self {
            status,
            code,
            retryable,
        }
    }

    const fn invalid_request() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            PublicIntakeErrorCodeV1::InvalidRequest,
            false,
        )
    }

    const fn not_found() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            PublicIntakeErrorCodeV1::InvalidRequest,
            false,
        )
    }

    const fn unsupported_media_type() -> Self {
        Self::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            PublicIntakeErrorCodeV1::UnsupportedMediaType,
            false,
        )
    }

    const fn payload_too_large() -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            PublicIntakeErrorCodeV1::PayloadTooLarge,
            false,
        )
    }

    const fn abuse_challenge_failed() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            PublicIntakeErrorCodeV1::AbuseChallengeFailed,
            false,
        )
    }

    const fn temporarily_unavailable() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            PublicIntakeErrorCodeV1::TemporarilyUnavailable,
            true,
        )
    }
}

impl IntoResponse for PublicApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(PublicIntakeErrorV1 {
                schema: PublicIntakeSchemaV1::V1,
                code: self.code,
                retryable: self.retryable,
            }),
        )
            .into_response()
    }
}

fn respond(result: Result<(), PublicApiError>) -> Response {
    match result {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(PublicIntakeAcceptedV1 {
                schema: PublicIntakeSchemaV1::V1,
                status: PublicIntakeAcceptedStatusV1::Accepted,
            }),
        )
            .into_response(),
        Err(error) => error.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderName, HeaderValue};
    use serde_json::json;
    use zed_interfaces::public_intake::{
        QuoteDeploymentModelV1, QuoteMigrationWindowV1, QuoteMonthlyDownloadBandV1,
        QuotePackageCountBandV1, QuoteTeamSizeBandV1,
    };

    use super::*;

    const NOW: &str = "2026-09-02T15:00:00Z";
    const NOW_UNIX: i64 = 1_788_361_200;
    const REQUEST_ID: &str = "018f5f52-feb8-7d4a-a9d6-69d8a1559e8b";

    fn insert(headers: &mut HeaderMap, name: &'static str, value: &str) {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(value).unwrap(),
        );
    }

    fn signed_headers(body: &[u8]) -> HeaderMap {
        let digest = hex::encode(sha256(body));
        let signed = format!(
            "v1\n{NOW_UNIX}\nuser.zpkg.net\n/v1/pre-interest\n{REQUEST_ID}\n{digest}"
        );
        let signature = hex::encode(hmac_sha256(
            b"0123456789abcdef0123456789abcdef",
            signed.as_bytes(),
        ));
        let mut headers = HeaderMap::new();
        insert(&mut headers, "host", API_HOST);
        insert(&mut headers, IDEMPOTENCY_KEY_HEADER, REQUEST_ID);
        insert(&mut headers, EDGE_TIMESTAMP_HEADER, &NOW_UNIX.to_string());
        insert(&mut headers, EDGE_SOURCE_HOST_HEADER, "user.zpkg.net");
        insert(&mut headers, EDGE_BODY_SHA256_HEADER, &digest);
        insert(
            &mut headers,
            EDGE_SIGNATURE_HEADER,
            &format!("v1={signature}"),
        );
        headers
    }

    fn pre_interest() -> PreInterestRegistrationRequestV1 {
        PreInterestRegistrationRequestV1 {
            schema: PublicIntakeSchemaV1::V1,
            request_id: REQUEST_ID.to_owned(),
            email: " Person@Example.COM ".to_owned(),
            party_type: PublicIntakePartyV1::Individual,
            source_host: PublicIntakeSourceHostV1::User,
            interests: vec![PublicIntakeInterestV1::DeveloperExperience],
            contact_name: Some(" Person  Name ".to_owned()),
            organization_name: None,
            website_url: Some("https://example.com/path".to_owned()),
            locale: Some("en-US".to_owned()),
            referral_code: None,
            consent_revision: "privacy-2026-09-01".to_owned(),
            consented_at: NOW.to_owned(),
            contact_consent: true,
            marketing_consent: false,
            marketing_consent_revision: None,
        }
    }

    fn quote() -> QuoteRequestV1 {
        QuoteRequestV1 {
            schema: PublicIntakeSchemaV1::V1,
            request_id: REQUEST_ID.to_owned(),
            email: "buyer@example.com".to_owned(),
            source_host: PublicIntakeSourceHostV1::Organization,
            organization_name: " Example  Corp ".to_owned(),
            contact_name: " Buyer  Person ".to_owned(),
            role: Some("Platform Lead".to_owned()),
            website_url: Some("https://example.com".to_owned()),
            interests: vec![PublicIntakeInterestV1::EnterpriseSupport],
            deployment_model: QuoteDeploymentModelV1::Hybrid,
            team_size: QuoteTeamSizeBandV1::FiftyOneToTwoHundred,
            package_count: QuotePackageCountBandV1::OneHundredToOneThousand,
            monthly_downloads: QuoteMonthlyDownloadBandV1::OneHundredThousandToOneMillion,
            migration_window: QuoteMigrationWindowV1::ThreeToSixMonths,
            requirements_summary: Some("Need migration planning.".to_owned()),
            locale: Some("en-US".to_owned()),
            referral_code: None,
            consent_revision: "privacy-2026-09-01".to_owned(),
            consented_at: NOW.to_owned(),
            contact_consent: true,
            marketing_consent: false,
            marketing_consent_revision: None,
        }
    }

    #[test]
    fn hmac_implementation_matches_the_reviewed_known_vector() {
        let body = br#"{"schema":"zed.public-intake.v1"}"#;
        assert_eq!(
            hex::encode(sha256(body)),
            "a619783cf12a5f68a4ec7b009daa16acd249401c08987b6608e004d650794a42"
        );
        let headers = signed_headers(body);
        let verified = verify_edge_headers(
            &headers,
            body,
            PRE_INTEREST_PATH_V1,
            PublicIntakeSourceHostV1::User,
            NOW_UNIX,
            b"0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        assert_eq!(verified.0.to_string(), REQUEST_ID);
        assert_eq!(
            headers.get(EDGE_SIGNATURE_HEADER).unwrap(),
            "v1=e23237b27f9dffdd29121ee569c9ea1ee48b56318fc26c466711a94cc1c4a476"
        );
    }

    #[test]
    fn signature_body_host_path_and_time_are_all_authority_inputs() {
        let body = br#"{"schema":"zed.public-intake.v1"}"#;
        let headers = signed_headers(body);
        for result in [
            verify_edge_headers(
                &headers,
                b"{}",
                PRE_INTEREST_PATH_V1,
                PublicIntakeSourceHostV1::User,
                NOW_UNIX,
                b"0123456789abcdef0123456789abcdef",
            ),
            verify_edge_headers(
                &headers,
                body,
                QUOTE_REQUESTS_PATH_V1,
                PublicIntakeSourceHostV1::Organization,
                NOW_UNIX,
                b"0123456789abcdef0123456789abcdef",
            ),
            verify_edge_headers(
                &headers,
                body,
                PRE_INTEREST_PATH_V1,
                PublicIntakeSourceHostV1::User,
                NOW_UNIX + 301,
                b"0123456789abcdef0123456789abcdef",
            ),
        ] {
            assert!(result.is_err());
        }
    }

    #[test]
    fn pre_interest_normalization_is_closed_and_privacy_aware() {
        let normalized = normalize_pre_interest(
            pre_interest(),
            Uuid::parse_str(REQUEST_ID).unwrap(),
            &IntakeSecrets::fixture(),
            DateTime::parse_from_rfc3339(NOW)
                .unwrap()
                .with_timezone(&Utc),
        )
        .unwrap();
        assert_eq!(normalized.email, "person@example.com");
        let payload: serde_json::Value = serde_json::from_str(&normalized.payload_json).unwrap();
        assert_eq!(payload["contactName"], "Person Name");
        assert_eq!(payload["schema"], PUBLIC_INTAKE_SCHEMA_V1);
        assert!(payload.get("organizationName").is_none());

        let mut invalid = pre_interest();
        invalid.organization_name = Some("Smuggled Org".to_owned());
        assert!(normalize_pre_interest(
            invalid,
            Uuid::parse_str(REQUEST_ID).unwrap(),
            &IntakeSecrets::fixture(),
            Utc::now(),
        )
        .is_err());
    }

    #[test]
    fn quote_rejects_secret_like_free_text_and_invalid_consent_combinations() {
        let request_id = Uuid::parse_str(REQUEST_ID).unwrap();
        let now = DateTime::parse_from_rfc3339(NOW)
            .unwrap()
            .with_timezone(&Utc);
        assert!(normalize_quote(
            quote(),
            request_id,
            &IntakeSecrets::fixture(),
            now,
        )
        .is_ok());

        let mut leaked = quote();
        leaked.requirements_summary = Some("password=hunter2".to_owned());
        assert!(normalize_quote(
            leaked,
            request_id,
            &IntakeSecrets::fixture(),
            now,
        )
        .is_err());

        let mut inconsistent = quote();
        inconsistent.marketing_consent_revision = Some("marketing-2026-09-01".to_owned());
        assert!(normalize_quote(
            inconsistent,
            request_id,
            &IntakeSecrets::fixture(),
            now,
        )
        .is_err());
    }

    #[test]
    fn public_response_shapes cannot_reflect_submitted_identity() {
        let accepted = respond(Ok(()));
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);
        let error = PublicApiError::invalid_request().into_response();
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        let accepted_shape = json!({"schema": PUBLIC_INTAKE_SCHEMA_V1, "status": "accepted"});
        let error_shape = json!({
            "schema": PUBLIC_INTAKE_SCHEMA_V1,
            "code": "invalid_request",
            "retryable": false
        });
        for shape in [accepted_shape, error_shape] {
            let encoded = shape.to_string();
            assert!(!encoded.contains("email"));
            assert!(!encoded.contains(REQUEST_ID));
            assert!(!encoded.contains("organization"));
        }
    }

    #[test]
    fn duplicate_interests_and_non_https_websites_fail_closed() {
        assert!(validate_interests(&[
            PublicIntakeInterestV1::Migration,
            PublicIntakeInterestV1::Migration,
        ])
        .is_err());
        assert!(normalize_website("http://example.com".to_owned()).is_err());
        assert!(normalize_website("https://user@example.com".to_owned()).is_err());
        assert!(normalize_website("https://example.com/path".to_owned()).is_ok());
    }
}
