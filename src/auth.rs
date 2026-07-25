use axum::http::HeaderMap;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use sha2::{Digest, Sha256};

use crate::entities::token;
use crate::error::{ApiErr, ApiResult};

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
        .map(|t| t.trim().to_string())
}

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
    // A revoked or expired token is indistinguishable from an unknown one to
    // the caller (same 401), so a leaked token can be killed by setting either
    // column. Expiry is compared in Rust against `now()` so the check is
    // identical on Postgres and the SQLite used in tests.
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
        let h = hash_token("zpkg_example");
        assert_eq!(h.len(), 64);
        assert_eq!(h, hash_token("zpkg_example"));
        assert_ne!(h, hash_token("zpkg_other"));
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

    // --- token lifecycle (M2) ------------------------------------------------

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

    /// Insert a token with the given lifecycle stamps; returns the plaintext.
    async fn seed(
        db: &DatabaseConnection,
        expires_at: Option<chrono::DateTime<Utc>>,
        revoked_at: Option<chrono::DateTime<Utc>>,
    ) -> String {
        let plaintext = format!("zpkg_{}", uuid::Uuid::new_v4().simple());
        token::ActiveModel {
            id: ActiveValue::Set(uuid::Uuid::new_v4()),
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

    /// A token with both stamps NULL is the historical, always-valid token.
    #[tokio::test]
    async fn live_token_is_accepted() {
        let db = lifecycle_db().await;
        let plaintext = seed(&db, None, None).await;
        assert!(require_token(&db, &bearer(&plaintext)).await.is_ok());
    }

    /// A revoked token is rejected — indistinguishable from an unknown one.
    #[tokio::test]
    async fn revoked_token_is_rejected() {
        let db = lifecycle_db().await;
        // Revoked in the past, and never expiring: revocation alone must kill it.
        let plaintext = seed(&db, None, Some(Utc::now() - Duration::minutes(1))).await;
        let err = require_token(&db, &bearer(&plaintext))
            .await
            .expect_err("a revoked token must not authenticate");
        assert_eq!(err.code, "unauthorized");
    }

    /// Expiry is enforced at the boundary: past expiry fails, future is fine.
    #[tokio::test]
    async fn expired_token_is_rejected_but_future_expiry_is_accepted() {
        let db = lifecycle_db().await;
        let expired = seed(&db, Some(Utc::now() - Duration::seconds(1)), None).await;
        let err = require_token(&db, &bearer(&expired))
            .await
            .expect_err("an expired token must not authenticate");
        assert_eq!(err.code, "unauthorized");

        let live = seed(&db, Some(Utc::now() + Duration::days(1)), None).await;
        let row = require_token(&db, &bearer(&live))
            .await
            .expect("a token expiring tomorrow is still valid");
        assert!(row.expires_at.is_some());
    }

    /// Revocation wins even when the token has not expired yet.
    #[tokio::test]
    async fn revocation_beats_a_valid_expiry() {
        let db = lifecycle_db().await;
        let plaintext = seed(
            &db,
            Some(Utc::now() + Duration::days(30)),
            Some(Utc::now() - Duration::seconds(1)),
        )
        .await;
        assert!(require_token(&db, &bearer(&plaintext)).await.is_err());
    }
}
