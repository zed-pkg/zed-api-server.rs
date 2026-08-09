use axum::http::HeaderMap;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zed_orm::registry::FederatedIdentity;

use crate::entities::token;
use crate::error::{ApiErr, ApiResult};
use crate::shared_auth::{ClientError, Introspection};
use crate::state::AppState;

const REQUIRED_ACCOUNT_SCOPE: &str = "zpkg:account";

/// Verified browser/account identity. The Shared Auth token is intentionally
/// not retained: handlers receive only the canonical identity facts needed to
/// project a registry user and evaluate product memberships.
#[derive(Clone, Debug, PartialEq)]
pub struct AccountIdentity {
    pub federated: FederatedIdentity,
}

impl AccountIdentity {
    pub fn subject(&self) -> &str {
        &self.federated.subject
    }
}

/// Tokens are stored as sha256 hex; the plaintext is shown exactly once by
/// the `create-token` subcommand.
pub fn hash_token(plaintext: &str) -> String {
    hex::encode(Sha256::digest(plaintext.as_bytes()))
}

pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
}

/// Authenticate a browser/account request through protected, audience-bound
/// Shared Auth introspection. Missing credentials are 401; an auth dependency
/// outage or server misconfiguration is 503; a base/service/wrong-client token
/// is 403. No branch synthesizes authority.
pub async fn require_account(state: &AppState, headers: &HeaderMap) -> ApiResult<AccountIdentity> {
    let token = bearer_token(headers).ok_or_else(ApiErr::unauthorized)?;
    let client = state.shared_auth.as_ref().ok_or_else(|| {
        ApiErr::service_unavailable(
            "auth_unavailable",
            "shared authentication is not configured",
        )
    })?;
    let introspection = client
        .introspect_for_audience(&token, &state.shared_auth_audience)
        .await
        .map_err(map_shared_auth_error)?;
    account_from_introspection(&introspection, &state.shared_auth_application_id)
}

fn account_from_introspection(
    introspection: &Introspection,
    expected_authorized_party: &str,
) -> ApiResult<AccountIdentity> {
    if !introspection.active {
        return Err(ApiErr::unauthorized());
    }
    let subject = required_claim(introspection.sub.as_deref())?;
    let issuer = required_claim(introspection.iss.as_deref())?;

    // Shared Auth represents a browser user with a revocable session-backed
    // base token and then mints a short-lived delegated product token. Its
    // protected introspection response exposes that provenance as `sid`, `azp`,
    // and `parent_jti`; it does not emit the previous synthetic `actor_kind` or
    // `application_id` fields.
    let session_id = optional_rest_string(introspection, "sid")?;
    let authorized_party = optional_rest_string(introspection, "azp")?;
    let parent_jti = optional_rest_string(introspection, "parent_jti")?;
    if session_id.is_none() || authorized_party.is_none() || parent_jti.is_none() {
        return Err(ApiErr::forbidden(
            "delegated_user_token_required",
            "this endpoint requires a session-backed delegated user token",
        ));
    }
    if authorized_party.as_deref() != Some(expected_authorized_party) {
        return Err(ApiErr::forbidden(
            "wrong_authorized_party",
            "the delegated token was not issued to the zed-pkg web client",
        ));
    }

    let scope = optional_rest_string(introspection, "scope")?.ok_or_else(|| {
        ApiErr::forbidden(
            "insufficient_scope",
            "the delegated token is missing the zed-pkg account scope",
        )
    })?;
    if !scope
        .split_ascii_whitespace()
        .any(|candidate| candidate == REQUIRED_ACCOUNT_SCOPE)
    {
        return Err(ApiErr::forbidden(
            "insufficient_scope",
            "the delegated token is missing the zed-pkg account scope",
        ));
    }

    let supabase_user_id = optional_rest_string(introspection, "supabase_user_id")?
        .map(|value| value.parse::<Uuid>().map_err(|_| ApiErr::unauthorized()))
        .transpose()?;
    let display_name = optional_rest_string(introspection, "display_name")?;
    let avatar_url = optional_rest_string(introspection, "avatar_url")?;

    Ok(AccountIdentity {
        federated: FederatedIdentity {
            issuer,
            subject,
            supabase_user_id,
            email: introspection.email.clone(),
            display_name,
            avatar_url,
        },
    })
}

pub(crate) fn map_shared_auth_error(error: ClientError) -> ApiErr {
    match error {
        ClientError::Unauthorized | ClientError::Status(401) | ClientError::InvalidInput(_) => {
            ApiErr::unauthorized()
        }
        other => {
            tracing::warn!(error = %other, "shared-auth request failed");
            ApiErr::service_unavailable(
                "auth_unavailable",
                "shared authentication is temporarily unavailable",
            )
        }
    }
}

fn required_claim(value: Option<&str>) -> ApiResult<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 1024)
        .map(str::to_owned)
        .ok_or_else(ApiErr::unauthorized)
}

fn optional_rest_string(introspection: &Introspection, key: &str) -> ApiResult<Option<String>> {
    match introspection.rest.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            let value = value.trim();
            if value.is_empty() || value.len() > 1024 {
                Err(ApiErr::unauthorized())
            } else {
                Ok(Some(value.to_owned()))
            }
        }
        Some(_) => Err(ApiErr::unauthorized()),
    }
}

/// Authenticate a legacy scoped registry token used by CLI/package publishing.
/// Browser sessions never enter this table, and there is no disabled-auth mode.
pub async fn require_token(
    db: &DatabaseConnection,
    headers: &HeaderMap,
) -> ApiResult<token::Model> {
    let plaintext = bearer_token(headers).ok_or_else(ApiErr::unauthorized)?;
    let row = token::Entity::find()
        .filter(token::Column::TokenHash.eq(hash_token(&plaintext)))
        .one(db)
        .await?
        .ok_or_else(ApiErr::unauthorized)?;
    if row.revoked_at.is_some() {
        return Err(ApiErr::unauthorized());
    }
    if let Some(expires_at) = row.expires_at
        && expires_at <= chrono::Utc::now()
    {
        return Err(ApiErr::unauthorized());
    }
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashing_is_stable_and_hex() {
        let hash = hash_token("zpkg_example");
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, hash_token("zpkg_example"));
        assert_ne!(hash, hash_token("zpkg_other"));
    }

    #[test]
    fn bearer_extraction() {
        let mut headers = HeaderMap::new();
        assert!(bearer_token(&headers).is_none());
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer zpkg_abc".parse().unwrap(),
        );
        assert_eq!(bearer_token(&headers).as_deref(), Some("zpkg_abc"));
    }

    fn delegated_rest(authorized_party: &str, scope: &str) -> serde_json::Map<String, Value> {
        let mut rest = serde_json::Map::new();
        rest.insert("sid".into(), Value::String("session-1".into()));
        rest.insert("azp".into(), Value::String(authorized_party.into()));
        rest.insert("parent_jti".into(), Value::String("parent-token-1".into()));
        rest.insert("scope".into(), Value::String(scope.into()));
        rest
    }

    #[test]
    fn verified_delegated_user_claims_become_a_federated_identity() {
        let mut rest = delegated_rest("zpkg-web", "zpkg:account zpkg:packages:write");
        rest.insert(
            "supabase_user_id".into(),
            Value::String("ad7c2010-c28a-4cad-a510-4c4020f93535".into()),
        );
        let introspection = Introspection {
            active: true,
            sub: Some("shared-user-1".into()),
            iss: Some("https://auth.example.test".into()),
            email: Some("user@example.test".into()),
            rest,
        };
        let identity = account_from_introspection(&introspection, "zpkg-web").unwrap();
        assert_eq!(identity.subject(), "shared-user-1");
        assert_eq!(
            identity.federated.supabase_user_id,
            Some("ad7c2010-c28a-4cad-a510-4c4020f93535".parse().unwrap())
        );
    }

    #[test]
    fn base_tokens_and_wrong_authorized_parties_are_forbidden() {
        let base = Introspection {
            active: true,
            sub: Some("shared-user-1".into()),
            iss: Some("https://auth.example.test".into()),
            email: None,
            rest: serde_json::Map::new(),
        };
        assert_eq!(
            account_from_introspection(&base, "zpkg-web")
                .unwrap_err()
                .code,
            "delegated_user_token_required"
        );

        let wrong_party = Introspection {
            active: true,
            sub: Some("shared-user-1".into()),
            iss: Some("https://auth.example.test".into()),
            email: None,
            rest: delegated_rest("other-web", "zpkg:account"),
        };
        assert_eq!(
            account_from_introspection(&wrong_party, "zpkg-web")
                .unwrap_err()
                .code,
            "wrong_authorized_party"
        );
    }

    #[test]
    fn delegated_token_without_account_scope_is_forbidden() {
        let introspection = Introspection {
            active: true,
            sub: Some("shared-user-1".into()),
            iss: Some("https://auth.example.test".into()),
            email: None,
            rest: delegated_rest("zpkg-web", "zpkg:packages:read"),
        };
        assert_eq!(
            account_from_introspection(&introspection, "zpkg-web")
                .unwrap_err()
                .code,
            "insufficient_scope"
        );
    }

    use chrono::{Duration, Utc};
    use sea_orm::{
        ActiveModelTrait, ActiveValue, ConnectOptions, ConnectionTrait, Database, Schema,
    };

    async fn lifecycle_db() -> DatabaseConnection {
        let mut opts = ConnectOptions::new("sqlite::memory:".to_string());
        opts.max_connections(1)
            .min_connections(1)
            .sqlx_logging(false);
        let db = Database::connect(opts).await.unwrap();
        let backend = db.get_database_backend();
        let schema = Schema::new(backend);
        db.execute(backend.build(&schema.create_table_from_entity(token::Entity)))
            .await
            .unwrap();
        db
    }

    async fn seed(
        db: &DatabaseConnection,
        expires_at: Option<chrono::DateTime<Utc>>,
        revoked_at: Option<chrono::DateTime<Utc>>,
    ) -> String {
        let plaintext = format!("zpkg_{}", Uuid::new_v4().simple());
        token::ActiveModel {
            id: ActiveValue::Set(Uuid::new_v4()),
            name: ActiveValue::Set("t".to_string()),
            token_hash: ActiveValue::Set(hash_token(&plaintext)),
            org_id: ActiveValue::Set(None),
            role: ActiveValue::Set("owner".to_string()),
            created_at: ActiveValue::Set(Utc::now()),
            expires_at: ActiveValue::Set(expires_at),
            revoked_at: ActiveValue::Set(revoked_at),
        }
        .insert(db)
        .await
        .unwrap();
        plaintext
    }

    fn bearer(plaintext: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {plaintext}").parse().unwrap(),
        );
        headers
    }

    #[tokio::test]
    async fn live_token_is_accepted() {
        let db = lifecycle_db().await;
        let plaintext = seed(&db, None, None).await;
        assert!(require_token(&db, &bearer(&plaintext)).await.is_ok());
    }

    #[tokio::test]
    async fn revoked_token_is_rejected() {
        let db = lifecycle_db().await;
        let plaintext = seed(&db, None, Some(Utc::now() - Duration::minutes(1))).await;
        let error = require_token(&db, &bearer(&plaintext))
            .await
            .expect_err("a revoked token must not authenticate");
        assert_eq!(error.code, "unauthorized");
    }

    #[tokio::test]
    async fn expired_token_is_rejected_but_future_expiry_is_accepted() {
        let db = lifecycle_db().await;
        let expired = seed(&db, Some(Utc::now() - Duration::seconds(1)), None).await;
        assert!(require_token(&db, &bearer(&expired)).await.is_err());

        let live = seed(&db, Some(Utc::now() + Duration::days(1)), None).await;
        let row = require_token(&db, &bearer(&live))
            .await
            .expect("a token expiring tomorrow is still valid");
        assert!(row.expires_at.is_some());
    }
}
