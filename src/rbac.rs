//! Role-based access control for org-scoped tokens (zed-docs issue #7).
//!
//! A token is either an **admin** token (no org scope — owner-equivalent
//! everywhere) or scoped to one org with a [`Role`]. Roles map onto tokens
//! the way npm's granular access tokens do: a `reader` token can install but
//! not publish, a `publisher` can publish, an `owner` can also manage the org.

use uuid::Uuid;

use crate::error::{ApiErr, ApiResult};

/// A token's capability within its org scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Owner,
    Publisher,
    Reader,
}

impl Role {
    /// Parse a stored role string, defaulting to the most restrictive sensible
    /// value only for genuinely unknown input; `owner` is the historical
    /// default for pre-RBAC tokens and is matched explicitly.
    pub fn parse(s: &str) -> Role {
        match s {
            "owner" => Role::Owner,
            "publisher" => Role::Publisher,
            "reader" => Role::Reader,
            _ => Role::Reader,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Publisher => "publisher",
            Role::Reader => "reader",
        }
    }

    /// Valid role names accepted by `create-token --role`.
    pub fn is_valid(s: &str) -> bool {
        matches!(s, "owner" | "publisher" | "reader")
    }

    pub fn can_publish(&self) -> bool {
        matches!(self, Role::Owner | Role::Publisher)
    }

    pub fn can_manage(&self) -> bool {
        matches!(self, Role::Owner)
    }
}

/// Authorize a publish of `target_org` by a token scoped to `token_org` with
/// `role`. Admin tokens (`token_org == None`) may publish anywhere; a scoped
/// token must target its own org and hold a publishing role.
pub fn authorize_publish(token_org: Option<Uuid>, role: Role, target_org: Uuid) -> ApiResult<()> {
    match token_org {
        None => Ok(()),
        Some(scope) if scope != target_org => Err(ApiErr::unauthorized()),
        Some(_) if role.can_publish() => Ok(()),
        Some(_) => Err(ApiErr::forbidden(
            "insufficient_role",
            format!(
                "this token's role (`{}`) cannot publish; a `publisher` or `owner` token is required",
                role.as_str()
            ),
        )),
    }
}

/// Authorize an org-management read/write (today: reading the audit log) of
/// `target_org`. Same scope rule as publishing, but requires the `owner` role:
/// the audit trail names who acted, so it is owner-only information.
pub fn authorize_manage(token_org: Option<Uuid>, role: Role, target_org: Uuid) -> ApiResult<()> {
    match token_org {
        None => Ok(()),
        Some(scope) if scope != target_org => Err(ApiErr::unauthorized()),
        Some(_) if role.can_manage() => Ok(()),
        Some(_) => Err(ApiErr::forbidden(
            "insufficient_role",
            format!(
                "this token's role (`{}`) cannot manage the org; an `owner` token is required",
                role.as_str()
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manage_authorization_is_owner_only() {
        let org = Uuid::from_u128(1);
        let other = Uuid::from_u128(2);
        // Admin (unscoped) may manage any org.
        assert!(authorize_manage(None, Role::Reader, org).is_ok());
        // Only owner among scoped roles.
        assert!(authorize_manage(Some(org), Role::Owner, org).is_ok());
        assert_eq!(
            authorize_manage(Some(org), Role::Publisher, org)
                .unwrap_err()
                .code,
            "insufficient_role"
        );
        assert_eq!(
            authorize_manage(Some(org), Role::Reader, org)
                .unwrap_err()
                .code,
            "insufficient_role"
        );
        // Wrong org loses before role is considered.
        assert_eq!(
            authorize_manage(Some(other), Role::Owner, org)
                .unwrap_err()
                .code,
            "unauthorized"
        );
    }

    #[test]
    fn role_capabilities() {
        assert!(Role::Owner.can_publish() && Role::Owner.can_manage());
        assert!(Role::Publisher.can_publish() && !Role::Publisher.can_manage());
        assert!(!Role::Reader.can_publish() && !Role::Reader.can_manage());
        assert_eq!(Role::parse("publisher"), Role::Publisher);
        assert_eq!(Role::parse("nonsense"), Role::Reader);
    }

    #[test]
    fn publish_authorization() {
        let org = Uuid::from_u128(1);
        let other = Uuid::from_u128(2);
        // Admin token (no scope) may publish anywhere.
        assert!(authorize_publish(None, Role::Reader, org).is_ok());
        // Publisher/owner scoped to the org may publish.
        assert!(authorize_publish(Some(org), Role::Publisher, org).is_ok());
        assert!(authorize_publish(Some(org), Role::Owner, org).is_ok());
        // Reader scoped to the org is forbidden (403).
        let denied = authorize_publish(Some(org), Role::Reader, org).unwrap_err();
        assert_eq!(denied.code, "insufficient_role");
        // A token for a different org is unauthorized regardless of role.
        assert_eq!(
            authorize_publish(Some(other), Role::Owner, org)
                .unwrap_err()
                .code,
            "unauthorized"
        );
    }
}
