use std::fmt;

use zed_interfaces::edge_fallback::{
    EDGE_FALLBACK_AUDIENCE_V2, EDGE_FALLBACK_CAPABILITY_VERSION_V2,
    EDGE_FALLBACK_MAX_TTL_SECONDS_V2, EdgeFallbackCapabilityV2, EdgeFallbackGrantV2,
    ReadOperationV2,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EdgeCapabilityIssueError {
    PublicPackage,
    UnsupportedVisibility,
    ReadDenied,
    UnsupportedRepository,
    InvalidCapability(String),
    InvalidLifetime,
}

impl fmt::Display for EdgeCapabilityIssueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicPackage => formatter
                .write_str("public packages use anonymous fallback and do not need a capability"),
            Self::UnsupportedVisibility => formatter.write_str("unsupported package visibility"),
            Self::ReadDenied => formatter.write_str("caller is not authorized to read the package"),
            Self::UnsupportedRepository => {
                formatter.write_str("package repository is not an approved GitHub source")
            }
            Self::InvalidCapability(message) => {
                write!(formatter, "edge fallback capability is invalid: {message}")
            }
            Self::InvalidLifetime => formatter.write_str("capability lifetime is invalid"),
        }
    }
}

impl std::error::Error for EdgeCapabilityIssueError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EdgeCapabilityPrincipal {
    pub subject: String,
    pub session_id: String,
    pub parent_jti: String,
}

impl From<&crate::auth::PackageReaderIdentity> for EdgeCapabilityPrincipal {
    fn from(identity: &crate::auth::PackageReaderIdentity) -> Self {
        Self {
            subject: identity.session.subject.to_string(),
            session_id: identity.session_id.clone(),
            parent_jti: identity.parent_jti.clone(),
        }
    }
}

pub(crate) fn authorize_private_package_read(
    visibility: &str,
    org_role: Option<&str>,
    project_role: Option<&str>,
) -> Result<(), EdgeCapabilityIssueError> {
    if visibility == "public" {
        return Err(EdgeCapabilityIssueError::PublicPackage);
    }
    if visibility != "private" {
        return Err(EdgeCapabilityIssueError::UnsupportedVisibility);
    }
    if has_membership(org_role) || has_membership(project_role) {
        Ok(())
    } else {
        Err(EdgeCapabilityIssueError::ReadDenied)
    }
}

pub(crate) fn github_grant_for_package(
    package: &str,
    repo_url: &str,
) -> Result<EdgeFallbackGrantV2, EdgeCapabilityIssueError> {
    let resource = canonical_github_resource(repo_url)
        .ok_or(EdgeCapabilityIssueError::UnsupportedRepository)?;
    Ok(EdgeFallbackGrantV2::Github {
        operation: ReadOperationV2::Read,
        package: package.to_owned(),
        credential_ref: format!("github-app:repo:{resource}"),
        resource,
    })
}

pub(crate) fn build_github_capability_v2(
    issuer: &str,
    principal: &EdgeCapabilityPrincipal,
    package: &str,
    repo_url: &str,
    issued_at: u64,
    ttl_seconds: u64,
    capability_id: &str,
) -> Result<EdgeFallbackCapabilityV2, EdgeCapabilityIssueError> {
    if ttl_seconds == 0 || ttl_seconds > EDGE_FALLBACK_MAX_TTL_SECONDS_V2 {
        return Err(EdgeCapabilityIssueError::InvalidLifetime);
    }
    let expires_at = issued_at
        .checked_add(ttl_seconds)
        .ok_or(EdgeCapabilityIssueError::InvalidLifetime)?;
    let capability = EdgeFallbackCapabilityV2 {
        zed_edge_capability: EDGE_FALLBACK_CAPABILITY_VERSION_V2,
        iss: issuer.to_owned(),
        aud: EDGE_FALLBACK_AUDIENCE_V2.to_owned(),
        sub: principal.subject.clone(),
        sid: principal.session_id.clone(),
        parent_jti: principal.parent_jti.clone(),
        iat: issued_at,
        nbf: issued_at,
        exp: expires_at,
        jti: capability_id.to_owned(),
        grants: vec![github_grant_for_package(package, repo_url)?],
    };
    capability
        .validate()
        .map_err(|error| EdgeCapabilityIssueError::InvalidCapability(error.to_string()))?;
    Ok(capability)
}

fn has_membership(role: Option<&str>) -> bool {
    role.is_some_and(|value| {
        let value = value.trim();
        !value.is_empty() && value.len() <= 64 && !value.chars().any(char::is_control)
    })
}

fn canonical_github_resource(repo_url: &str) -> Option<String> {
    let trimmed = repo_url.trim();
    if !(trimmed.starts_with("https://github.com/") || trimmed.starts_with("git@github.com:")) {
        return None;
    }
    let (owner, repo) = crate::verify::parse_github(trimmed)?;
    Some(format!("{owner}/{repo}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal() -> EdgeCapabilityPrincipal {
        EdgeCapabilityPrincipal {
            subject: "user:ad7c2010-c28a-4cad-a510-4c4020f93535".to_owned(),
            session_id: "session:abc-123".to_owned(),
            parent_jti: "parent-token-0001".to_owned(),
        }
    }

    #[test]
    fn package_reader_lineage_projects_into_edge_principal() {
        let reader = crate::auth::PackageReaderIdentity {
            session: crate::auth::SessionIdentity {
                subject: "ad7c2010-c28a-4cad-a510-4c4020f93535".parse().unwrap(),
                realm: "customer".to_owned(),
                email: None,
                display_name: None,
                avatar_url: None,
            },
            session_id: "session:abc-123".to_owned(),
            parent_jti: "parent-token-0001".to_owned(),
        };

        let principal = EdgeCapabilityPrincipal::from(&reader);
        assert_eq!(principal.subject, "ad7c2010-c28a-4cad-a510-4c4020f93535");
        assert_eq!(principal.session_id, "session:abc-123");
        assert_eq!(principal.parent_jti, "parent-token-0001");
    }

    #[test]
    fn private_read_requires_existing_org_or_project_membership() {
        assert_eq!(
            authorize_private_package_read("private", None, None),
            Err(EdgeCapabilityIssueError::ReadDenied)
        );
        assert!(authorize_private_package_read("private", Some("reader"), None).is_ok());
        assert!(authorize_private_package_read("private", None, Some("member")).is_ok());
        assert_eq!(
            authorize_private_package_read("public", Some("owner"), None),
            Err(EdgeCapabilityIssueError::PublicPackage)
        );
        assert_eq!(
            authorize_private_package_read("internal", Some("owner"), None),
            Err(EdgeCapabilityIssueError::UnsupportedVisibility)
        );
    }

    #[test]
    fn github_resource_is_derived_from_registry_owned_repo_url()
    -> Result<(), EdgeCapabilityIssueError> {
        let grant = github_grant_for_package(
            "acme/private-lib",
            "https://github.com/acme/private-lib.git",
        )?;
        assert_eq!(grant.provider(), "github");
        assert_eq!(grant.package(), "acme/private-lib");
        assert_eq!(grant.resource(), "acme/private-lib");
        assert_eq!(grant.credential_ref(), "github-app:repo:acme/private-lib");

        assert!(
            github_grant_for_package("acme/private-lib", "http://github.com/acme/private-lib")
                .is_err()
        );
        assert!(
            github_grant_for_package("acme/private-lib", "https://gitlab.com/acme/private-lib")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn v2_capability_binds_lineage_resource_and_short_lifetime()
    -> Result<(), EdgeCapabilityIssueError> {
        let capability = build_github_capability_v2(
            "https://api.zpkg.net",
            &principal(),
            "acme/private-lib",
            "git@github.com:acme/private-lib.git",
            1_000,
            120,
            "capability-0001",
        )?;

        assert_eq!(capability.zed_edge_capability, 2);
        assert_eq!(capability.aud, "zed-edge-fallback");
        assert_eq!(capability.sid, "session:abc-123");
        assert_eq!(capability.parent_jti, "parent-token-0001");
        assert_eq!(capability.iat, 1_000);
        assert_eq!(capability.nbf, 1_000);
        assert_eq!(capability.exp, 1_120);
        assert_eq!(
            capability.grants.first().map(EdgeFallbackGrantV2::resource),
            Some("acme/private-lib")
        );
        Ok(())
    }

    #[test]
    fn capability_rejects_zero_overlong_and_overflowing_lifetimes() {
        for ttl in [0, EDGE_FALLBACK_MAX_TTL_SECONDS_V2 + 1] {
            assert_eq!(
                build_github_capability_v2(
                    "https://api.zpkg.net",
                    &principal(),
                    "acme/private-lib",
                    "https://github.com/acme/private-lib",
                    1_000,
                    ttl,
                    "capability-0001",
                ),
                Err(EdgeCapabilityIssueError::InvalidLifetime)
            );
        }
        assert_eq!(
            build_github_capability_v2(
                "https://api.zpkg.net",
                &principal(),
                "acme/private-lib",
                "https://github.com/acme/private-lib",
                u64::MAX,
                1,
                "capability-0001",
            ),
            Err(EdgeCapabilityIssueError::InvalidLifetime)
        );
    }
}
