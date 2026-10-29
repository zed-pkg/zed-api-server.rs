//! Verify a Zed signed-build statement against an already published artifact.
//!
//! IMPORTANT: this verifies attribution and artifact integrity ONLY.
//! It cannot consume the Oreslang API's build challenge or prove compilation.
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zed_interfaces::signed_build::SignedBuildV1;
use zed_interfaces::signing::PublisherKeyStateV1;

use crate::auth::require_token;
use crate::entities::version;
use crate::error::{ApiErr, ApiResult};
use crate::state::AppState;

use super::{find_org, find_package, keys};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifySignedBuildRequest {
    pub receipt: SignedBuildV1,
}

#[derive(Debug, Serialize)]
pub struct VerifySignedBuildResponse {
    pub schema: &'static str,
    pub signature_valid: bool,
    pub artifact_bytes_match: bool,
    /// Deliberately not "verified compiled", "trusted" or "SLSA".
    pub trust: &'static str,
    pub artifact_sha256: String,
    pub signer_key_id: String,
}

pub async fn verify_signed_build(
    State(state): State<Arc<AppState>>,
    Path(org_slug): Path<String>,
    headers: HeaderMap,
    Json(request): Json<VerifySignedBuildRequest>,
) -> ApiResult<Json<VerifySignedBuildResponse>> {
    let token = require_token(&state.db, &headers).await?;
    let org_row = find_org(&state, &org_slug).await?;
    crate::rbac::authorize_publish(
        token.org_id,
        crate::rbac::Role::parse(&token.role),
        org_row.id,
    )?;

    let receipt = request.receipt;
    receipt
        .validate()
        .map_err(|message| ApiErr::bad_request("signed_build_invalid", message))?;
    let claim = &receipt.claims;
    if claim.org != org_slug {
        return Err(ApiErr::bad_request(
            "signed_build_org_mismatch",
            "receipt org does not match authenticated route",
        ));
    }
    // This only rejects an expired self-claim. The authentic API challenge
    // expiry MUST also be checked in the Oreslang API's durable DB.
    let now_ms = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(u64::MAX);
    if now_ms < claim.issued_at_unix_ms || now_ms >= claim.expires_at_unix_ms {
        return Err(ApiErr::bad_request(
            "signed_build_expired",
            "build receipt is outside its claimed time window",
        ));
    }

    let keys = keys::load_keys(&state, org_row.id).await?;
    let eligible = keys
        .into_iter()
        .filter(|key| key.key_id == claim.device_key_id && key.state == PublisherKeyStateV1::Active)
        .collect::<Vec<_>>();
    let preimage = claim
        .preimage()
        .map_err(|message| ApiErr::bad_request("signed_build_invalid", message))?;
    let verified =
        crate::signing::verify_any(&preimage, &receipt.signatures, &eligible).map_err(|_| {
            ApiErr::bad_request(
                "signed_build_signature_invalid",
                "no active enrolled key verifies build signature",
            )
        })?;

    // Bind package/version identity to a REGISTRY database row, not merely a
    // matching content-addressed blob belonging to a different package.
    let package = find_package(&state, &org_row, &claim.package).await?;
    let row = version::Entity::find()
        .filter(version::Column::PackageId.eq(package.id))
        .filter(version::Column::Version.eq(&claim.version))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiErr::bad_request(
                "signed_build_version_missing",
                "signed build must refer to a published version",
            )
        })?;
    if row.sha256 != claim.artifact_sha256
        || row.size != i64::try_from(claim.artifact_size).unwrap_or(-1)
        || row.format != claim.artifact_format
    {
        return Err(ApiErr::bad_request(
            "signed_build_version_mismatch",
            "signed build does not match the published package version",
        ));
    }

    // Rehash the REAL stored bytes; never compare only client-provided hashes
    // or trust object-store metadata. The storage adapter limits the read.
    let blob = state
        .store
        .get_bytes(&row.artifact_key)
        .await
        .map_err(|_| {
            ApiErr::bad_request(
                "signed_build_artifact_missing",
                "artifact is not available in the registry store",
            )
        })?;
    let actual_sha = hex::encode(Sha256::digest(&blob));
    if actual_sha != claim.artifact_sha256 || blob.len() as u64 != claim.artifact_size {
        return Err(ApiErr::bad_request(
            "signed_build_artifact_mismatch",
            "stored artifact differs from signed bytes",
        ));
    }

    Ok(Json(VerifySignedBuildResponse {
        schema: "zpkg.signed-build-verification/1",
        signature_valid: true,
        artifact_bytes_match: true,
        trust: "signed-self-report-not-compiled-proof",
        artifact_sha256: actual_sha,
        signer_key_id: verified.key_id.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ed25519_signature_binds_artifact_digest_and_rejects_revoked_keys() {
        use ed25519_dalek::{Signer, SigningKey};
        use zed_interfaces::signed_build::{BuildClaimsV1, SIGNED_BUILD_AUDIENCE_V1};
        use zed_interfaces::signing::{
            DetachedSignatureV1, PublisherKeyStateV1, PublisherKeyV1, SIGNING_ALGORITHM,
            encode_multibase_base58btc,
        };

        let claims = BuildClaimsV1 {
            audience: SIGNED_BUILD_AUDIENCE_V1.into(),
            org: "acme".into(),
            package: "widget".into(),
            version: "1.2.3".into(),
            challenge_id: "12345678-1234-1234-1234-123456789abc".into(),
            nonce_sha256: "a".repeat(64),
            device_key_id: "device".into(),
            source_commit: "b".repeat(40),
            source_sha256: "c".repeat(64),
            toolchain_sha256: "d".repeat(64),
            target: "llvm".into(),
            artifact_sha256: "e".repeat(64),
            artifact_size: 100,
            artifact_format: "tar.gz".into(),
            issued_at_unix_ms: 1_799_999_880_000,
            expires_at_unix_ms: 1_800_000_000_000,
        };
        let private = SigningKey::from_bytes(&[7_u8; 32]);
        let key = PublisherKeyV1 {
            key_id: "device".into(),
            algorithm: SIGNING_ALGORITHM.into(),
            public_key_multibase: encode_multibase_base58btc(private.verifying_key().as_bytes()),
            state: PublisherKeyStateV1::Active,
            enrolled_at: None,
            revoked_reason: None,
        };
        let preimage = claims.preimage().unwrap();
        let signature = DetachedSignatureV1::new("device", &private.sign(&preimage).to_bytes());
        assert!(
            crate::signing::verify_any(&preimage, &[signature.clone()], &[key.clone()]).is_ok()
        );

        let mut changed = claims.clone();
        changed.artifact_sha256 = "f".repeat(64);
        assert!(
            crate::signing::verify_any(
                &changed.preimage().unwrap(),
                &[signature.clone()],
                &[key.clone()]
            )
            .is_err()
        );
        let mut revoked = key;
        revoked.state = PublisherKeyStateV1::Revoked;
        let active: Vec<_> = [revoked]
            .into_iter()
            .filter(|candidate| candidate.state == PublisherKeyStateV1::Active)
            .collect();
        assert!(crate::signing::verify_any(&preimage, &[signature], &active).is_err());
    }

    #[test]
    fn public_status_never_claims_compilation_or_release_approval() {
        let status = serde_json::to_value(VerifySignedBuildResponse {
            schema: "zpkg.signed-build-verification/1",
            signature_valid: true,
            artifact_bytes_match: true,
            trust: "signed-self-report-not-compiled-proof",
            artifact_sha256: "a".repeat(64),
            signer_key_id: "device".into(),
        })
        .unwrap();
        assert_eq!(status["trust"], "signed-self-report-not-compiled-proof");
        assert!(status.get("release_approved").is_none());
    }
}
