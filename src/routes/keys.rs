//! Publisher signing keys: anonymous read, owner-scoped write.
//!
//! The read route is deliberately unauthenticated. These keys are what a
//! client uses to verify metadata served by *something other than this
//! server* — so requiring a credential from this server to obtain them would
//! make them useless in exactly the situation they exist for. They are public
//! keys; publishing them costs nothing and withholding them costs the whole
//! mechanism.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, EntityTrait, QueryFilter, QueryOrder,
    TransactionTrait,
};
use uuid::Uuid;
use zed_interfaces::registry::{OrgKeysRequest, OrgKeysResponse};
use zed_interfaces::signing::{MAX_KEYS_PER_ORG, PublisherKeyStateV1, PublisherKeyV1};

use crate::auth::require_token;
use crate::entities::publisher_key;
use crate::error::{ApiErr, ApiResult};
use crate::state::AppState;

use super::find_org;

pub async fn get_keys(
    State(state): State<Arc<AppState>>,
    Path(org_slug): Path<String>,
) -> ApiResult<Json<OrgKeysResponse>> {
    let org_row = find_org(&state, &org_slug).await?;
    Ok(Json(OrgKeysResponse {
        org: org_slug,
        keys: load_keys(&state, org_row.id).await?,
    }))
}

pub async fn put_keys(
    State(state): State<Arc<AppState>>,
    Path(org_slug): Path<String>,
    headers: HeaderMap,
    Json(request): Json<OrgKeysRequest>,
) -> ApiResult<Json<OrgKeysResponse>> {
    let token = require_token(&state.db, &headers).await?;
    let org_row = find_org(&state, &org_slug).await?;
    // Enrolling a key changes what consumers will trust for every future
    // publish, which is org management, not publishing. Same authority as
    // claiming the namespace.
    crate::rbac::authorize_manage(
        token.org_id,
        crate::rbac::Role::parse(&token.role),
        org_row.id,
    )?;

    if request.keys.len() > MAX_KEYS_PER_ORG {
        return Err(ApiErr::bad_request(
            "too_many_keys",
            format!("at most {MAX_KEYS_PER_ORG} signing keys per org"),
        ));
    }
    for key in &request.keys {
        key.validate().map_err(|error| {
            ApiErr::bad_request("invalid_key", format!("invalid signing key: {error}"))
        })?;
    }

    let existing = load_keys(&state, org_row.id).await?;

    // The set is submitted whole, but three transitions are refused rather
    // than applied, because each of them silently breaks something already
    // published:
    //
    //   - rebinding a key id to different key material, which makes every
    //     signature made under that name unverifiable;
    //   - un-revoking a key, which is how a compromise gets quietly buried;
    //   - dropping a key entirely, which strands consumers who pinned it
    //     (retire or revoke it instead — both leave a record).
    for previous in &existing {
        let Some(submitted) = request
            .keys
            .iter()
            .find(|candidate| candidate.key_id == previous.key_id)
        else {
            return Err(ApiErr::bad_request(
                "key_removed",
                format!(
                    "key `{}` cannot be removed; set its state to `retired` or `revoked` so \
                     consumers that pinned it learn why",
                    previous.key_id
                ),
            ));
        };
        if submitted.public_key_multibase != previous.public_key_multibase {
            return Err(ApiErr::conflict(
                "key_rebind",
                format!(
                    "key `{}` is already enrolled with different key material; enroll a new \
                     key id instead of rebinding this one",
                    previous.key_id
                ),
            ));
        }
        if previous.state == PublisherKeyStateV1::Revoked
            && submitted.state != PublisherKeyStateV1::Revoked
        {
            return Err(ApiErr::conflict(
                "key_unrevoke",
                format!(
                    "key `{}` is revoked and cannot be reinstated",
                    previous.key_id
                ),
            ));
        }
    }

    let txn = state.db.begin().await?;
    for key in &request.keys {
        let current = publisher_key::Entity::find()
            .filter(publisher_key::Column::OrgId.eq(org_row.id))
            .filter(publisher_key::Column::KeyId.eq(&key.key_id))
            .one(&txn)
            .await?;
        match current {
            Some(row) => {
                let mut active: publisher_key::ActiveModel = row.into();
                active.state = ActiveValue::Set(key.state.as_str().to_owned());
                active.revoked_reason = ActiveValue::Set(key.revoked_reason.clone());
                active.update(&txn).await?;
            }
            None => {
                publisher_key::ActiveModel {
                    id: ActiveValue::Set(Uuid::new_v4()),
                    org_id: ActiveValue::Set(org_row.id),
                    key_id: ActiveValue::Set(key.key_id.clone()),
                    algorithm: ActiveValue::Set(key.algorithm.clone()),
                    public_key_multibase: ActiveValue::Set(key.public_key_multibase.clone()),
                    state: ActiveValue::Set(key.state.as_str().to_owned()),
                    revoked_reason: ActiveValue::Set(key.revoked_reason.clone()),
                    enrolled_at: ActiveValue::Set(Utc::now()),
                }
                .insert(&txn)
                .await?;
            }
        }
    }
    txn.commit().await?;

    Ok(Json(OrgKeysResponse {
        org: org_slug,
        keys: load_keys(&state, org_row.id).await?,
    }))
}

/// Every key enrolled for an org, oldest first.
pub(super) async fn load_keys(state: &AppState, org_id: Uuid) -> ApiResult<Vec<PublisherKeyV1>> {
    let rows = publisher_key::Entity::find()
        .filter(publisher_key::Column::OrgId.eq(org_id))
        .order_by_asc(publisher_key::Column::EnrolledAt)
        .all(&state.db)
        .await?;
    Ok(rows.into_iter().map(row_to_key).collect())
}

fn row_to_key(row: publisher_key::Model) -> PublisherKeyV1 {
    PublisherKeyV1 {
        key_id: row.key_id,
        algorithm: row.algorithm,
        public_key_multibase: row.public_key_multibase,
        // An unrecognized state is read as `revoked`, not as `active`. A row a
        // newer server wrote and this build does not understand must not be
        // treated as a key to trust.
        state: match row.state.as_str() {
            "active" => PublisherKeyStateV1::Active,
            "retired" => PublisherKeyStateV1::Retired,
            _ => PublisherKeyStateV1::Revoked,
        },
        enrolled_at: Some(row.enrolled_at.to_rfc3339()),
        revoked_reason: row.revoked_reason,
    }
}
