//! Typed authentication principal for machine-registry operations.
//!
//! Keep authentication identity separate from authorization. Today the
//! compatibility registry routes admit only legacy scoped machine tokens.
//! A later delegated-user variant can carry canonical Shared Auth/Zed account
//! identity without fabricating a legacy token row or inheriting machine-token
//! admin semantics.

use axum::http::HeaderMap;
use sea_orm::DatabaseConnection;
use uuid::Uuid;

use crate::auth::require_token;
use crate::entities::token;
use crate::error::ApiResult;
use crate::rbac::Role;

#[derive(Clone, Debug)]
pub(crate) enum RegistryActor {
    LegacyMachineToken(token::Model),
}

impl RegistryActor {
    pub(crate) fn token_id(&self) -> Uuid {
        match self {
            Self::LegacyMachineToken(token) => token.id,
        }
    }

    pub(crate) fn org_scope(&self) -> Option<Uuid> {
        match self {
            Self::LegacyMachineToken(token) => token.org_id,
        }
    }

    pub(crate) fn role(&self) -> Role {
        match self {
            Self::LegacyMachineToken(token) => Role::parse(&token.role),
        }
    }

    pub(crate) fn legacy_token(&self) -> &token::Model {
        match self {
            Self::LegacyMachineToken(token) => token,
        }
    }
}

pub(crate) async fn require_registry_actor(
    db: &DatabaseConnection,
    headers: &HeaderMap,
) -> ApiResult<RegistryActor> {
    require_token(db, headers)
        .await
        .map(RegistryActor::LegacyMachineToken)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(role: &str, org_id: Option<Uuid>) -> token::Model {
        token::Model {
            id: Uuid::from_u128(1),
            name: "actor-test".to_owned(),
            token_hash: "a".repeat(64),
            org_id,
            role: role.to_owned(),
            created_at: chrono::Utc::now(),
            expires_at: None,
            revoked_at: None,
        }
    }

    #[test]
    fn legacy_actor_preserves_machine_token_scope_role_and_identity() {
        let org = Uuid::from_u128(2);
        let actor = RegistryActor::LegacyMachineToken(token("publisher", Some(org)));
        assert_eq!(actor.token_id(), Uuid::from_u128(1));
        assert_eq!(actor.org_scope(), Some(org));
        assert_eq!(actor.role(), Role::Publisher);
        assert_eq!(actor.legacy_token().id, Uuid::from_u128(1));
    }

    #[test]
    fn unknown_legacy_roles_stay_fail_restrictive() {
        let actor = RegistryActor::LegacyMachineToken(token("unexpected", None));
        assert_eq!(actor.role(), Role::Reader);
    }
}
