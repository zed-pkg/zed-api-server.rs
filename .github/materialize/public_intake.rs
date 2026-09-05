//! Signed API ingress for public commercial-intake requests.
//!
//! Cloudflare performs the browser abuse challenge, but the API trusts only a
//! fresh HMAC over the exact body digest, route, source host, and idempotency key.
//! Contact data and signature material are never emitted to diagnostics.

use std::collections::BTreeSet;

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::state::AppState;
use zed_interfaces::{
    PreInterestRegistrationRequestV1, PublicIntakeSourceHostV1, QuoteRequestV1,
    PUBLIC_INTAKE_SCHEMA_V1,
};
use zed_orm_core::{
    NewPublicIntakeSubmission, PublicIntakeStoreError, PublicIntakeSubmissionKind, SecretBytes,
};

pub const PRE_INTEREST_PATH: &str = "/v1/pre-interest";
pub const QUOTE_REQUEST_PATH: &str = "/v1/quote-requests";
const USER_HOST: &str = "user.zpkg.net";
const ORGANIZATION_HOST: &str = "org.zpkg.net";
const MAX_BODY_BYTES: usize = 16 * 1024;
const MAX_INGRESS_SKEW_SECONDS: i64 = 5 * 60;
const MAX_CONSENT_SKEW_SECONDS: i64 = 24 * 60 * 60;

const INTERESTS: &[&str] = &[
    "package_publishing",
    "private_registry",
    "supply_chain_security",
    "enterprise_support",
    "developer_experience",
    "migration",
    "compliance",
    "self_hosted",
    "air_gapped",
];
const DEPLOYMENT_MODELS: &[&str] = &[
    "evaluating",
    "zed_cloud",
    "self_hosted",
    "hybrid",
    "air_gapped",
];
const TEAM_SIZES: &[&str] = &[
    "one_to_ten",
    "eleven_to_fifty",
    "fifty_one_to_two_hundred",
    "two_hundred_one_to_one_thousand",
    "over_one_thousand",
    "unknown",
];
const PACKAGE_COUNTS: &[&str] = &[
    "under_one_hundred",
    "one_hundred_to_one_thousand",
    "one_thousand_to_ten_thousand",
    "over_ten_thousand",
    "unknown",
];
const MONTHLY_DOWNLOADS: &[&str] = &[
    "under_one_hundred_thousand",
    "one_hundred_thousand_to_one_million",
    "one_million_to_ten_million",
    "over_ten_million",
    "unknown",
];
const MIGRATION_WINDOWS: &[&str] = &[
    "exploring",
    "under_three_months",
    "three_to_six_months",
    "six_to_twelve_months",
    "over_twelve_months",
];

const COMMON_FIELDS: &[&str] = &[
    "schema",
    "requestId",
    "email",
    "sourceHost",
    "interests",
    "contactName",
    "organizationName",
    "websiteUrl",
    "locale",
    "referralCode",
    "consentRevision",
    "consentedAt",
    "contactConsent",
    "marketingConsent",
    "marketingConsentRevision",
];
const PRE_INTEREST_FIELDS: &[&str] = &[
    "schema",
    "requestId",
    "email",
    "partyType",
    "sourceHost",
    "interests",
    "contactName",
    "organizationName",
    "websiteUrl",
    "locale",
    "referralCode",
    "consentRevision",
    "consentedAt",
    "contactConsent",
    "marketingConsent",
    "marketingConsentRevision",
];
const QUOTE_FIELDS: &[&str] = &[
    "schema",
    "requestId",
    "email",
    "sourceHost",
    "organizationName",
    "contactName",
    "role",
    "websiteUrl",
    "interests",
    "deploymentModel",
    "teamSize",
    "packageCount",
    "monthlyDownloads",
    "migrationWindow",
    "requirementsSummary",
    "locale",
    "referralCode",
    "consentRevision",
    "consentedAt",
    "contactConsent",
    "marketingConsent",
    "marketingConsentRevision",
];

#[derive(Clone, Copy)]
enum IntakeKind {
    PreInterest,
    QuoteRequest,
}

impl IntakeKind {
    const fn path(self) -> &'static str {
        match self {
            Self::PreInterest => PRE_INTEREST_PATH,
            Self::QuoteRequest => QUOTE_REQUEST_PATH,
        }
    }

    const fn source_host(self) -> &'static str {
        match self {
            Self::PreInterest => USER_HOST,
            Self::QuoteRequest => ORGANIZATION_HOST,
        }
    }

    const fn persistence_kind(self) -> PublicIntakeSubmissionKind {
        match self {
            Self::PreInterest => PublicIntakeSubmissionKind::PreInterest,
            Self::QuoteRequest => PublicIntakeSubmissionKind::QuoteRequest,
        }
    }

    const fn source_host_enum(self) -> PublicIntakeSourceHostV1 {
        match self {
            Self::PreInterest => PublicIntakeSourceHostV1::User,
            Self::QuoteRequest => PublicIntakeSourceHostV1::Organization,
        }
    }
}

struct RuntimeSecrets {
    signing_key: Zeroizing<Vec<u8>>,
    encryption_key_id: String,
    encryption_key: SecretBytes,
    email_hmac_key_id: String,
    email_hmac_key: SecretBytes,
    consent_revision: String,
    marketing_consent_revision: String,
}

impl RuntimeSecrets {
    fn from_environment() -> Result<Self, IntakeApiError> {
        let signing_key = required_environment("ZED_PUBLIC_INTAKE_SIGNING_KEY")?.into_bytes();
        if signing_key.len() < 32 {
            return Err(IntakeApiError::Unavailable);
        }
        let encryption_key_id = required_portable_environment(
            "ZED_PUBLIC_INTAKE_ENCRYPTION_KEY_ID",
        )?;
        let email_hmac_key_id = required_portable_environment(
            "ZED_PUBLIC_INTAKE_EMAIL_HMAC_KEY_ID",
        )?;
        let consent_revision = required_portable_environment(
            "ZED_PUBLIC_INTAKE_CONSENT_REVISION",
        )?;
        let marketing_consent_revision = required_portable_environment(
            "ZED_PUBLIC_INTAKE_MARKETING_CONSENT_REVISION",
        )?;
        let encryption_key = decode_secret_environment(
            "ZED_PUBLIC_INTAKE_ENCRYPTION_KEY_B64",
            Some(32),
        )?;
        let email_hmac_key = decode_secret_environment(
            "ZED_PUBLIC_INTAKE_EMAIL_HMAC_KEY_B64",
            None,
        )?;
        if email_hmac_key.len() < 32 {
            return Err(IntakeApiError::Unavailable);
        }

        Ok(Self {
            signing_key: Zeroizing::new(signing_key),
            encryption_key_id,
            encryption_key: SecretBytes::new(encryption_key),
            email_hmac_key_id,
            email_hmac_key: SecretBytes::new(email_hmac_key),
            consent_revision,
            marketing_consent_revision,
        })
    }
}

struct ValidatedSubmission {
    request_id: String,
    body_sha256: String,
    normalized_email: String,
    canonical_payload: Vec<u8>,
    consented_at: DateTime<Utc>,
    marketing_consent: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IntakeApiError {
    InvalidRequest,
    PayloadTooLarge,
    UnsupportedMediaType,
    UntrustedIngress,
    Unavailable,
}

impl IntakeApiError {
    const fn status(self) -> StatusCode {
        match self {
            Self::InvalidRequest => StatusCode::UNPROCESSABLE_ENTITY,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::UntrustedIngress => StatusCode::FORBIDDEN,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::PayloadTooLarge => "payload_too_large",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::UntrustedIngress => "abuse_challenge_failed",
            Self::Unavailable => "temporarily_unavailable",
        }
    }

    const fn retryable(self) -> bool {
        matches!(self, Self::Unavailable)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AcceptedResponse<'a> {
    schema: &'a str,
    status: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorResponse<'a> {
    schema: &'a str,
    code: &'a str,
    retryable: bool,
}

pub async fn submit_pre_interest(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    submit(state, headers, body, IntakeKind::PreInterest).await
}

pub async fn submit_quote_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    submit(state, headers, body, IntakeKind::QuoteRequest).await
}

async fn submit(state: AppState, headers: HeaderMap, body: Bytes, kind: IntakeKind) -> Response {
    match submit_inner(&state, &headers, &body, kind, Utc::now()).await {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(AcceptedResponse {
                schema: PUBLIC_INTAKE_SCHEMA_V1,
                status: "accepted",
            }),
        )
            .into_response(),
        Err(error) => (
            error.status(),
            Json(ErrorResponse {
                schema: PUBLIC_INTAKE_SCHEMA_V1,
                code: error.code(),
                retryable: error.retryable(),
            }),
        )
            .into_response(),
    }
}

async fn submit_inner(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
    kind: IntakeKind,
    now: DateTime<Utc>,
) -> Result<(), IntakeApiError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(IntakeApiError::PayloadTooLarge);
    }
    require_json_content_type(headers)?;
    let secrets = RuntimeSecrets::from_environment()?;
    let (request_id, body_sha256) = verify_ingress(
        headers,
        body,
        kind.path(),
        kind.source_host(),
        now.timestamp(),
        &secrets.signing_key,
    )?;
    let submission = validate_submission(
        body,
        kind,
        &request_id,
        &body_sha256,
        now,
        &secrets,
    )?;
    let encrypted = NewPublicIntakeSubmission::encrypted(
        kind.persistence_kind(),
        kind.source_host_enum(),
        &submission.request_id,
        &submission.body_sha256,
        &submission.normalized_email,
        &submission.canonical_payload,
        submission.consented_at,
        submission.marketing_consent,
        &secrets.encryption_key_id,
        &secrets.encryption_key,
        &secrets.email_hmac_key_id,
        &secrets.email_hmac_key,
    )
    .map_err(|_| IntakeApiError::Unavailable)?;

    state
        .public_intake_write_context()
        .insert_public_intake_submission(encrypted)
        .await
        .map_err(map_store_error)?;
    Ok(())
}

fn verify_ingress(
    headers: &HeaderMap,
    body: &[u8],
    path: &str,
    expected_source_host: &str,
    now_epoch_seconds: i64,
    signing_key: &[u8],
) -> Result<(String, String), IntakeApiError> {
    let request_id = required_header(headers, "idempotency-key", 64)?;
    Uuid::parse_str(request_id).map_err(|_| IntakeApiError::UntrustedIngress)?;
    let source_host = required_header(headers, "x-zed-intake-source-host", 128)?;
    if source_host != expected_source_host {
        return Err(IntakeApiError::UntrustedIngress);
    }
    let timestamp = required_header(headers, "x-zed-intake-timestamp", 24)?
        .parse::<i64>()
        .map_err(|_| IntakeApiError::UntrustedIngress)?;
    if now_epoch_seconds.abs_diff(timestamp) > MAX_INGRESS_SKEW_SECONDS as u64 {
        return Err(IntakeApiError::UntrustedIngress);
    }

    let declared_digest = required_header(headers, "x-zed-intake-body-sha256", 64)?;
    if declared_digest.len() != 64
        || !declared_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(IntakeApiError::UntrustedIngress);
    }
    let computed_digest = hex::encode(Sha256::digest(body));
    if computed_digest != declared_digest {
        return Err(IntakeApiError::UntrustedIngress);
    }

    let signature = required_header(headers, "x-zed-intake-signature", 67)?
        .strip_prefix("v1=")
        .ok_or(IntakeApiError::UntrustedIngress)?;
    let signature = hex::decode(signature).map_err(|_| IntakeApiError::UntrustedIngress)?;
    let signed = format!(
        "v1\n{timestamp}\n{source_host}\n{path}\n{request_id}\n{computed_digest}"
    );
    let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(signing_key)
        .map_err(|_| IntakeApiError::Unavailable)?;
    hmac.update(signed.as_bytes());
    hmac.verify_slice(&signature)
        .map_err(|_| IntakeApiError::UntrustedIngress)?;

    Ok((request_id.to_owned(), computed_digest))
}

fn validate_submission(
    body: &[u8],
    kind: IntakeKind,
    signed_request_id: &str,
    body_sha256: &str,
    now: DateTime<Utc>,
    secrets: &RuntimeSecrets,
) -> Result<ValidatedSubmission, IntakeApiError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| IntakeApiError::InvalidRequest)?;
    let object = value.as_object().ok_or(IntakeApiError::InvalidRequest)?;
    validate_closed_object(object, kind)?;
    required_string(object, "schema", 64, false)?
        .eq(PUBLIC_INTAKE_SCHEMA_V1)
        .then_some(())
        .ok_or(IntakeApiError::InvalidRequest)?;
    let request_id = required_string(object, "requestId", 64, false)?;
    if request_id != signed_request_id || Uuid::parse_str(request_id).is_err() {
        return Err(IntakeApiError::InvalidRequest);
    }
    let source_host = required_string(object, "sourceHost", 128, false)?;
    if source_host != kind.source_host() {
        return Err(IntakeApiError::InvalidRequest);
    }
    if required_string(object, "consentRevision", 64, false)? != secrets.consent_revision {
        return Err(IntakeApiError::InvalidRequest);
    }
    if object.get("contactConsent").and_then(Value::as_bool) != Some(true) {
        return Err(IntakeApiError::InvalidRequest);
    }
    let marketing_consent = object
        .get("marketingConsent")
        .and_then(Value::as_bool)
        .ok_or(IntakeApiError::InvalidRequest)?;
    match (
        marketing_consent,
        object.get("marketingConsentRevision").and_then(Value::as_str),
    ) {
        (true, Some(revision)) if revision == secrets.marketing_consent_revision => {}
        (false, None) => {}
        _ => return Err(IntakeApiError::InvalidRequest),
    }

    let consented_at = DateTime::parse_from_rfc3339(required_string(
        object,
        "consentedAt",
        35,
        false,
    )?)
    .map_err(|_| IntakeApiError::InvalidRequest)?
    .with_timezone(&Utc);
    if now
        .timestamp()
        .abs_diff(consented_at.timestamp())
        > MAX_CONSENT_SKEW_SECONDS as u64
    {
        return Err(IntakeApiError::InvalidRequest);
    }

    validate_interests(object)?;
    validate_optional_string(object, "contactName", 120)?;
    validate_optional_string(object, "websiteUrl", 2048)?;
    validate_optional_string(object, "locale", 35)?;
    validate_optional_string(object, "referralCode", 64)?;

    let canonical_payload = match kind {
        IntakeKind::PreInterest => {
            if required_string(object, "partyType", 32, false)? != "individual"
                || object.contains_key("organizationName")
            {
                return Err(IntakeApiError::InvalidRequest);
            }
            let typed: PreInterestRegistrationRequestV1 = serde_json::from_value(value)
                .map_err(|_| IntakeApiError::InvalidRequest)?;
            serde_json::to_vec(&typed).map_err(|_| IntakeApiError::Unavailable)?
        }
        IntakeKind::QuoteRequest => {
            required_string(object, "organizationName", 200, true)?;
            required_string(object, "contactName", 120, true)?;
            validate_optional_string(object, "role", 120)?;
            validate_optional_string(object, "requirementsSummary", 1000)?;
            if object
                .get("requirementsSummary")
                .and_then(Value::as_str)
                .is_some_and(contains_secret_shape)
            {
                return Err(IntakeApiError::InvalidRequest);
            }
            require_enum(object, "deploymentModel", DEPLOYMENT_MODELS)?;
            require_enum(object, "teamSize", TEAM_SIZES)?;
            require_enum(object, "packageCount", PACKAGE_COUNTS)?;
            require_enum(object, "monthlyDownloads", MONTHLY_DOWNLOADS)?;
            require_enum(object, "migrationWindow", MIGRATION_WINDOWS)?;
            let typed: QuoteRequestV1 = serde_json::from_value(value)
                .map_err(|_| IntakeApiError::InvalidRequest)?;
            serde_json::to_vec(&typed).map_err(|_| IntakeApiError::Unavailable)?
        }
    };

    Ok(ValidatedSubmission {
        request_id: request_id.to_owned(),
        body_sha256: body_sha256.to_owned(),
        normalized_email: normalize_email(required_string(object, "email", 254, true)?)?,
        canonical_payload,
        consented_at,
        marketing_consent,
    })
}

fn validate_closed_object(object: &Map<String, Value>, kind: IntakeKind) -> Result<(), IntakeApiError> {
    let allowed = match kind {
        IntakeKind::PreInterest => PRE_INTEREST_FIELDS,
        IntakeKind::QuoteRequest => QUOTE_FIELDS,
    };
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(IntakeApiError::InvalidRequest);
    }
    Ok(())
}

fn validate_interests(object: &Map<String, Value>) -> Result<(), IntakeApiError> {
    let values = object
        .get("interests")
        .and_then(Value::as_array)
        .ok_or(IntakeApiError::InvalidRequest)?;
    if values.is_empty() || values.len() > INTERESTS.len() {
        return Err(IntakeApiError::InvalidRequest);
    }
    let mut unique = BTreeSet::new();
    for value in values {
        let value = value.as_str().ok_or(IntakeApiError::InvalidRequest)?;
        if !INTERESTS.contains(&value) || !unique.insert(value) {
            return Err(IntakeApiError::InvalidRequest);
        }
    }
    Ok(())
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    maximum: usize,
    human_text: bool,
) -> Result<&'a str, IntakeApiError> {
    let value = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(IntakeApiError::InvalidRequest)?;
    if value.is_empty()
        || value.chars().count() > maximum
        || value.chars().any(char::is_control)
        || (human_text && value.trim() != value)
    {
        return Err(IntakeApiError::InvalidRequest);
    }
    Ok(value)
}

fn validate_optional_string(
    object: &Map<String, Value>,
    key: &str,
    maximum: usize,
) -> Result<(), IntakeApiError> {
    if object.contains_key(key) {
        required_string(object, key, maximum, true)?;
    }
    Ok(())
}

fn require_enum(
    object: &Map<String, Value>,
    key: &str,
    allowed: &[&str],
) -> Result<(), IntakeApiError> {
    let value = required_string(object, key, 128, false)?;
    if !allowed.contains(&value) {
        return Err(IntakeApiError::InvalidRequest);
    }
    Ok(())
}

fn normalize_email(value: &str) -> Result<String, IntakeApiError> {
    let normalized = value.trim().to_ascii_lowercase();
    let mut parts = normalized.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || !domain.contains('.')
        || normalized.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(IntakeApiError::InvalidRequest);
    }
    Ok(normalized)
}

fn contains_secret_shape(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    lowercase.contains("-----begin private key-----")
        || lowercase.contains("password=")
        || lowercase.contains("github_pat_")
        || lowercase.contains("ghp_")
        || lowercase.contains("sk-")
        || lowercase.contains("akia")
}

fn require_json_content_type(headers: &HeaderMap) -> Result<(), IntakeApiError> {
    let value = required_header(headers, CONTENT_TYPE.as_str(), 128)?;
    let media_type = value.split(';').next().unwrap_or_default().trim();
    if media_type != "application/json" {
        return Err(IntakeApiError::UnsupportedMediaType);
    }
    Ok(())
}

fn required_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
    maximum: usize,
) -> Result<&'a str, IntakeApiError> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or(IntakeApiError::UntrustedIngress)?
        .to_str()
        .map_err(|_| IntakeApiError::UntrustedIngress)?;
    if values.next().is_some()
        || value.is_empty()
        || value.len() > maximum
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(IntakeApiError::UntrustedIngress);
    }
    Ok(value)
}

fn required_environment(name: &str) -> Result<String, IntakeApiError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(IntakeApiError::Unavailable)
}

fn required_portable_environment(name: &str) -> Result<String, IntakeApiError> {
    let value = required_environment(name)?;
    if value.len() > 64
        || !value.is_ascii()
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return Err(IntakeApiError::Unavailable);
    }
    Ok(value)
}

fn decode_secret_environment(
    name: &str,
    exact_length: Option<usize>,
) -> Result<Vec<u8>, IntakeApiError> {
    let encoded = Zeroizing::new(required_environment(name)?);
    let decoded = BASE64_STANDARD
        .decode(encoded.as_bytes())
        .map_err(|_| IntakeApiError::Unavailable)?;
    if exact_length.is_some_and(|length| decoded.len() != length) {
        return Err(IntakeApiError::Unavailable);
    }
    Ok(decoded)
}

fn map_store_error(error: PublicIntakeStoreError) -> IntakeApiError {
    match error {
        PublicIntakeStoreError::IdempotencyConflict
        | PublicIntakeStoreError::InvalidBodyDigest
        | PublicIntakeStoreError::InvalidKindHostPair
        | PublicIntakeStoreError::InvalidNormalizedEmail
        | PublicIntakeStoreError::InvalidRequestId => IntakeApiError::InvalidRequest,
        PublicIntakeStoreError::Database
        | PublicIntakeStoreError::EncryptionFailed
        | PublicIntakeStoreError::InvalidEncryptionKey
        | PublicIntakeStoreError::InvalidKeyId
        | PublicIntakeStoreError::InvalidLookupKey => IntakeApiError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_788_364_800;
    const REQUEST_ID: &str = "018f5f52-feb8-7d4a-a9d6-69d8a1559e8b";
    const SIGNING_KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn payload() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": "zed.public-intake.v1",
            "requestId": REQUEST_ID,
            "email": "person@example.com",
            "partyType": "individual",
            "sourceHost": "user.zpkg.net",
            "interests": ["developer_experience"],
            "consentRevision": "privacy-2026-09-01",
            "consentedAt": "2026-09-02T16:00:00Z",
            "contactConsent": true,
            "marketingConsent": false
        }))
        .expect("payload")
    }

    fn signed_headers(body: &[u8]) -> HeaderMap {
        let digest = hex::encode(Sha256::digest(body));
        let signed = format!(
            "v1\n{NOW}\nuser.zpkg.net\n/v1/pre-interest\n{REQUEST_ID}\n{digest}"
        );
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(SIGNING_KEY).expect("hmac");
        mac.update(signed.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().expect("header"));
        headers.insert("idempotency-key", REQUEST_ID.parse().expect("header"));
        headers.insert(
            "x-zed-intake-source-host",
            "user.zpkg.net".parse().expect("header"),
        );
        headers.insert("x-zed-intake-timestamp", NOW.to_string().parse().expect("header"));
        headers.insert("x-zed-intake-body-sha256", digest.parse().expect("header"));
        headers.insert(
            "x-zed-intake-signature",
            format!("v1={signature}").parse().expect("header"),
        );
        headers
    }

    #[test]
    fn exact_signed_ingress_is_accepted() {
        let body = payload();
        let result = verify_ingress(
            &signed_headers(&body),
            &body,
            PRE_INTEREST_PATH,
            USER_HOST,
            NOW,
            SIGNING_KEY,
        )
        .expect("valid signature");
        assert_eq!(result.0, REQUEST_ID);
        assert_eq!(result.1, hex::encode(Sha256::digest(&body)));
    }

    #[test]
    fn body_route_host_and_timestamp_tampering_fail_closed() {
        let body = payload();
        let headers = signed_headers(&body);
        for result in [
            verify_ingress(
                &headers,
                b"{}",
                PRE_INTEREST_PATH,
                USER_HOST,
                NOW,
                SIGNING_KEY,
            ),
            verify_ingress(
                &headers,
                &body,
                QUOTE_REQUEST_PATH,
                USER_HOST,
                NOW,
                SIGNING_KEY,
            ),
            verify_ingress(
                &headers,
                &body,
                PRE_INTEREST_PATH,
                ORGANIZATION_HOST,
                NOW,
                SIGNING_KEY,
            ),
            verify_ingress(
                &headers,
                &body,
                PRE_INTEREST_PATH,
                USER_HOST,
                NOW + MAX_INGRESS_SKEW_SECONDS + 1,
                SIGNING_KEY,
            ),
        ] {
            assert_eq!(result, Err(IntakeApiError::UntrustedIngress));
        }
    }

    #[test]
    fn duplicate_authority_headers_are_rejected() {
        let body = payload();
        let mut headers = signed_headers(&body);
        headers.append("idempotency-key", REQUEST_ID.parse().expect("header"));
        assert_eq!(
            verify_ingress(
                &headers,
                &body,
                PRE_INTEREST_PATH,
                USER_HOST,
                NOW,
                SIGNING_KEY,
            ),
            Err(IntakeApiError::UntrustedIngress)
        );
    }

    #[test]
    fn closed_validation_rejects_smuggled_authority_and_secret_shapes() {
        let secrets = RuntimeSecrets {
            signing_key: Zeroizing::new(SIGNING_KEY.to_vec()),
            encryption_key_id: "enc-2026-09".to_owned(),
            encryption_key: SecretBytes::new(vec![7; 32]),
            email_hmac_key_id: "lookup-2026-09".to_owned(),
            email_hmac_key: SecretBytes::new(vec![9; 32]),
            consent_revision: "privacy-2026-09-01".to_owned(),
            marketing_consent_revision: "marketing-2026-09-01".to_owned(),
        };
        let now = DateTime::from_timestamp(NOW, 0).expect("time");
        let mut value: Value = serde_json::from_slice(&payload()).expect("json");
        value["admin"] = Value::Bool(true);
        let body = serde_json::to_vec(&value).expect("json");
        assert!(matches!(
            validate_submission(&body, IntakeKind::PreInterest, REQUEST_ID, &"ab".repeat(32), now, &secrets),
            Err(IntakeApiError::InvalidRequest)
        ));

        let mut quote = serde_json::json!({
            "schema": "zed.public-intake.v1",
            "requestId": REQUEST_ID,
            "email": "buyer@example.com",
            "sourceHost": "org.zpkg.net",
            "organizationName": "Example Corp",
            "contactName": "Buyer Person",
            "interests": ["enterprise_support"],
            "deploymentModel": "hybrid",
            "teamSize": "fifty_one_to_two_hundred",
            "packageCount": "one_hundred_to_one_thousand",
            "monthlyDownloads": "one_hundred_thousand_to_one_million",
            "migrationWindow": "three_to_six_months",
            "requirementsSummary": "password=do-not-store",
            "consentRevision": "privacy-2026-09-01",
            "consentedAt": "2026-09-02T16:00:00Z",
            "contactConsent": true,
            "marketingConsent": false
        });
        let body = serde_json::to_vec(&quote).expect("json");
        assert!(matches!(
            validate_submission(&body, IntakeKind::QuoteRequest, REQUEST_ID, &"ab".repeat(32), now, &secrets),
            Err(IntakeApiError::InvalidRequest)
        ));
        quote["requirementsSummary"] = Value::String("ordinary migration requirements".to_owned());
        let body = serde_json::to_vec(&quote).expect("json");
        assert!(validate_submission(&body, IntakeKind::QuoteRequest, REQUEST_ID, &"ab".repeat(32), now, &secrets).is_ok());
    }

    #[test]
    fn public_error_envelopes_never_include_request_content() {
        let response = ErrorResponse {
            schema: PUBLIC_INTAKE_SCHEMA_V1,
            code: IntakeApiError::InvalidRequest.code(),
            retryable: false,
        };
        let json = serde_json::to_string(&response).expect("serialize");
        assert!(!json.contains("person@example.com"));
        assert!(!json.contains(REQUEST_ID));
        assert_eq!(
            json,
            r#"{"schema":"zed.public-intake.v1","code":"invalid_request","retryable":false}"#
        );
    }

    #[test]
    fn common_field_inventory_is a subset of every request shape() {
        for field in COMMON_FIELDS {
            assert!(PRE_INTEREST_FIELDS.contains(field));
            assert!(QUOTE_FIELDS.contains(field));
        }
    }
}
