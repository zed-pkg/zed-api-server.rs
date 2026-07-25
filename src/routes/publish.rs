//! The publish pipeline: auth -> validate -> sha256 recompute -> org
//! ownership -> VCS tag verification -> immutability -> store -> record.

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Multipart, Path, State};
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait,
    QueryFilter, SqlErr, TransactionTrait,
};
use uuid::Uuid;
use zed_interfaces::registry::{
    PUBLISH_ARTIFACT_FIELD, PUBLISH_META_FIELD, PublishMeta, PublishResponse,
};

use crate::auth::require_token;
use crate::entities::{org, package, version};
use crate::error::{ApiErr, ApiResult};
use crate::state::AppState;
use crate::storage::artifact_key;
use crate::verify::TagCheck;

pub async fn publish(
    State(state): State<Arc<AppState>>,
    Path((org_slug, name, ver)): Path<(String, String, String)>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> ApiResult<Json<PublishResponse>> {
    let token = require_token(&state.db, &headers).await?;

    // Authorize BEFORE buffering the body. The org comes from the URL, so the
    // role check needs nothing from the multipart payload — and reading first
    // meant a token without publish rights could still make the server buffer a
    // full artifact (peak memory spent before authorization was even decided).
    // The manifest is still checked against the URL below, so authorizing on the
    // URL's org is equivalent.
    let org_row = org::Entity::find()
        .filter(org::Column::Slug.eq(&org_slug))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiErr {
            status: StatusCode::NOT_FOUND,
            code: "org_not_found",
            message: format!(
                "org `{org_slug}` does not exist; claim it first with `zed org claim {org_slug}`"
            ),
        })?;
    crate::rbac::authorize_publish(
        token.org_id,
        crate::rbac::Role::parse(&token.role),
        org_row.id,
    )?;

    let (meta, artifact) = read_multipart(&mut multipart).await?;

    meta.manifest
        .validate()
        .map_err(|e| ApiErr::bad_request("invalid_manifest", e.to_string()))?;
    let m = &meta.manifest.package;
    if m.org != org_slug || m.name != name || m.version != ver {
        return Err(ApiErr::bad_request(
            "manifest_url_mismatch",
            format!(
                "manifest says {}/{}@{}, url says {org_slug}/{name}@{ver}",
                m.org, m.name, m.version
            ),
        ));
    }

    let actual_sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&artifact));
    if actual_sha != meta.sha256 {
        return Err(ApiErr::bad_request(
            "sha256_mismatch",
            format!(
                "client declared {}, server computed {actual_sha}",
                meta.sha256
            ),
        ));
    }

    match state
        .verifier
        .verify(m.repository.vcs, &m.repository.url, &meta.vcs_tag)
        .await?
    {
        TagCheck::Missing => {
            return Err(ApiErr::bad_request(
                "tag_not_found",
                format!(
                    "tag `{}` not found on {}; authors must tag the backing repo before publishing",
                    meta.vcs_tag, m.repository.url
                ),
            ));
        }
        TagCheck::Verified { .. } | TagCheck::Skipped => {}
    }

    // Immutability is checked BEFORE any metadata mutation: if this exact
    // version already exists the publish is a no-op conflict and must not
    // rewrite the package's description/vcs/repo_url (M1). The package may not
    // exist yet (first publish), in which case no version can exist either.
    if let Some(pkg) = find_package_row(&state, &org_row, &name).await? {
        let exists = version::Entity::find()
            .filter(version::Column::PackageId.eq(pkg.id))
            .filter(version::Column::Version.eq(&ver))
            .one(&state.db)
            .await?;
        if exists.is_some() {
            return Err(ApiErr::conflict(
                "version_exists",
                format!("{org_slug}/{name}@{ver} is already published; versions are immutable"),
            ));
        }
    }

    // Store the blob before recording the row that references it. `Bytes` is
    // moved (not re-copied) into the store; the length is captured first since
    // the version row records it after the put.
    let key = artifact_key(&actual_sha, meta.format.extension());
    let artifact_len = artifact.len() as i64;
    state
        .store
        .put(&key, artifact, meta.format.content_type())
        .await?;

    // Upsert the package metadata and insert the version atomically: a failed
    // version insert must never leave the package metadata rewritten (M1). Any
    // failure past the blob `put` must also drop the just-stored blob (L3).
    let txn = state.db.begin().await?;
    let pkg = match upsert_package(&txn, &org_row, &name, &meta).await {
        Ok(pkg) => pkg,
        Err(err) => {
            let _ = txn.rollback().await;
            cleanup_unreferenced_blob(&state, &key).await;
            return Err(err);
        }
    };
    let inserted = version::ActiveModel {
        id: ActiveValue::Set(Uuid::new_v4()),
        package_id: ActiveValue::Set(pkg.id),
        version: ActiveValue::Set(ver.clone()),
        sha256: ActiveValue::Set(actual_sha.clone()),
        size: ActiveValue::Set(artifact_len),
        format: ActiveValue::Set(meta.format.extension().to_string()),
        vcs_tag: ActiveValue::Set(meta.vcs_tag.clone()),
        vcs_commit: ActiveValue::Set(meta.vcs_commit.clone()),
        artifact_key: ActiveValue::Set(key.clone()),
        yanked: ActiveValue::Set(false),
        published_at: ActiveValue::Set(Utc::now()),
    }
    .insert(&txn)
    .await;
    match inserted {
        Ok(_) => txn.commit().await?,
        Err(err) => {
            // Roll the metadata upsert back and drop the orphaned blob on every
            // failure path (L3), then classify the error.
            let _ = txn.rollback().await;
            cleanup_unreferenced_blob(&state, &key).await;
            // A concurrent publish can win the (package_id, version) unique
            // index between the check above and this insert; that is the same
            // immutability conflict, not an internal error.
            if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
                return Err(ApiErr::conflict(
                    "version_exists",
                    format!("{org_slug}/{name}@{ver} is already published; versions are immutable"),
                ));
            }
            return Err(err.into());
        }
    }

    tracing::info!(org = %org_slug, name = %name, version = %ver, sha256 = %actual_sha, "published");
    Ok(Json(PublishResponse {
        org: org_slug,
        name,
        version: ver,
        sha256: actual_sha,
    }))
}

/// Best-effort removal of a blob stored for a publish whose row insert lost
/// the race. The racing winner may have stored the identical artifact (same
/// sha256, same key), so only delete when no version row references the key;
/// on any doubt (count fails), keep the blob.
async fn cleanup_unreferenced_blob(state: &AppState, key: &str) {
    match version::Entity::find()
        .filter(version::Column::ArtifactKey.eq(key))
        .count(&state.db)
        .await
    {
        Ok(0) => {
            if let Err(err) = state.store.delete(key).await {
                tracing::warn!(key, error = %err, "failed to delete orphaned artifact blob");
            }
        }
        Ok(_) => {}
        Err(err) => {
            tracing::warn!(key, error = %err, "skipping orphaned blob cleanup; reference check failed");
        }
    }
}

async fn read_multipart(multipart: &mut Multipart) -> ApiResult<(PublishMeta, Bytes)> {
    let mut meta: Option<PublishMeta> = None;
    let mut artifact: Option<Bytes> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiErr::bad_request("invalid_multipart", e.to_string()))?
    {
        match field.name() {
            Some(PUBLISH_META_FIELD) => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| ApiErr::bad_request("invalid_meta", e.to_string()))?;
                meta = Some(
                    serde_json::from_str(&text)
                        .map_err(|e| ApiErr::bad_request("invalid_meta", e.to_string()))?,
                );
            }
            Some(PUBLISH_ARTIFACT_FIELD) => {
                artifact = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| ApiErr::bad_request("invalid_artifact", e.to_string()))?,
                );
            }
            _ => {}
        }
    }
    let meta = meta.ok_or_else(|| ApiErr::bad_request("invalid_meta", "missing meta field"))?;
    let artifact = artifact
        .ok_or_else(|| ApiErr::bad_request("invalid_artifact", "missing artifact field"))?;
    Ok((meta, artifact))
}

/// Read-only lookup of a package by (org, name); used before any metadata
/// mutation so an immutability conflict can be reported without an upsert.
async fn find_package_row(
    state: &AppState,
    org_row: &org::Model,
    name: &str,
) -> ApiResult<Option<package::Model>> {
    Ok(package::Entity::find()
        .filter(package::Column::OrgId.eq(org_row.id))
        .filter(package::Column::Name.eq(name))
        .one(&state.db)
        .await?)
}

async fn upsert_package<C: ConnectionTrait>(
    conn: &C,
    org_row: &org::Model,
    name: &str,
    meta: &PublishMeta,
) -> ApiResult<package::Model> {
    let m = &meta.manifest.package;
    // Atomic create-or-update keyed on the (org_id, name) unique index. Using
    // ON CONFLICT DO UPDATE rather than find-then-insert-or-update is what makes
    // concurrent first-publishes of a new package safe: the racer that loses the
    // INSERT still gets the existing row back (RETURNING), instead of a unique-
    // constraint violation that aborts the surrounding transaction and drops its
    // otherwise-valid, distinct version. `created_at` is intentionally NOT in the
    // update set, so a re-publish preserves the original creation time.
    package::Entity::insert(package::ActiveModel {
        id: ActiveValue::Set(Uuid::new_v4()),
        org_id: ActiveValue::Set(org_row.id),
        name: ActiveValue::Set(name.to_string()),
        description: ActiveValue::Set(m.description.clone()),
        vcs: ActiveValue::Set(m.repository.vcs.to_string()),
        repo_url: ActiveValue::Set(m.repository.url.clone()),
        version_scheme: ActiveValue::Set(m.version_scheme.as_str().to_string()),
        created_at: ActiveValue::Set(Utc::now()),
    })
    .on_conflict(
        OnConflict::columns([package::Column::OrgId, package::Column::Name])
            .update_columns([
                package::Column::Description,
                package::Column::Vcs,
                package::Column::RepoUrl,
                package::Column::VersionScheme,
            ])
            .to_owned(),
    )
    // .exec (not exec_with_returning): RETURNING on an upsert isn't emitted
    // portably across Postgres + the SQLite used in tests. The upsert itself
    // never violates the constraint, so it does not abort the transaction; we
    // then read the row back within the same txn.
    .exec(conn)
    .await?;
    package::Entity::find()
        .filter(package::Column::OrgId.eq(org_row.id))
        .filter(package::Column::Name.eq(name))
        .one(conn)
        .await?
        .ok_or_else(|| ApiErr {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "package_upsert_missing",
            message: "package row missing immediately after upsert".to_string(),
        })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use chrono::Utc;
    use sea_orm::{
        ActiveModelTrait, ActiveValue, ColumnTrait, ConnectOptions, ConnectionTrait, Database,
        DatabaseConnection, EntityTrait, QueryFilter, Schema,
    };
    use tower::util::ServiceExt;
    use uuid::Uuid;

    use crate::auth::hash_token;
    use crate::config::{StorageConfig, TagPolicy};
    use crate::entities::{org, package, token, version};
    use crate::state::AppState;
    use crate::storage::ArtifactStore;
    use crate::verify::TagVerifier;

    const TOKEN_PLAINTEXT: &str = "zpkg_test_secret";
    const BOUNDARY: &str = "ZEDBOUNDARY";

    /// In-memory SQLite database whose schema is built from the entity
    /// definitions. (The migration set can't be replayed on SQLite because one
    /// migration adds a foreign key via ALTER TABLE, which SQLite rejects; the
    /// entity-derived schema carries the same columns and constraints we need.)
    /// A single pooled connection keeps every statement (and `db.begin()`
    /// transaction) on the same in-memory database.
    async fn test_db() -> DatabaseConnection {
        let mut opts = ConnectOptions::new("sqlite::memory:".to_string());
        opts.max_connections(1)
            .min_connections(1)
            .sqlx_logging(false);
        let db = Database::connect(opts).await.expect("sqlite connects");
        let backend = db.get_database_backend();
        let schema = Schema::new(backend);
        for stmt in [
            schema.create_table_from_entity(org::Entity),
            schema.create_table_from_entity(token::Entity),
            schema.create_table_from_entity(package::Entity),
            schema.create_table_from_entity(version::Entity),
        ] {
            db.execute(backend.build(&stmt))
                .await
                .expect("create table");
        }
        // create_table_from_entity omits the migration's composite unique index
        // (idx_package_org_name); recreate it so the publish upsert's
        // ON CONFLICT (org_id, name) matches a real constraint, exactly as in
        // production (migration m20260723_000001_init).
        db.execute_unprepared("CREATE UNIQUE INDEX idx_package_org_name ON package (org_id, name)")
            .await
            .expect("create unique index");
        db
    }

    async fn state_with(db: DatabaseConnection) -> Arc<AppState> {
        let dir = std::env::temp_dir().join(format!("zed-api-pub-test-{}", Uuid::new_v4()));
        Arc::new(AppState {
            db,
            store: ArtifactStore::from_config(&StorageConfig::Local {
                dir: dir.to_string_lossy().to_string(),
            })
            .await
            .unwrap(),
            verifier: TagVerifier::new(TagPolicy::Off),
            public_base_url: "http://localhost:8080".to_string(),
            max_orgs_per_token: 5,
            fiducia: None,
            rate_limiter: None,
        })
    }

    /// Seed org `acme`, a scoped token, and package `acme/http-kit@1.0.0` with a
    /// known description so mutations are observable.
    async fn seed(db: &DatabaseConnection, description: &str) -> (Uuid, Uuid) {
        let org_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();
        let pkg_id = Uuid::new_v4();
        org::ActiveModel {
            id: ActiveValue::Set(org_id),
            slug: ActiveValue::Set("acme".to_string()),
            created_at: ActiveValue::Set(Utc::now()),
            created_by_token: ActiveValue::Set(Some(token_id)),
        }
        .insert(db)
        .await
        .unwrap();
        token::ActiveModel {
            id: ActiveValue::Set(token_id),
            name: ActiveValue::Set("test".to_string()),
            token_hash: ActiveValue::Set(hash_token(TOKEN_PLAINTEXT)),
            org_id: ActiveValue::Set(Some(org_id)),
            role: ActiveValue::Set("owner".to_string()),
            created_at: ActiveValue::Set(Utc::now()),
            expires_at: ActiveValue::Set(None),
            revoked_at: ActiveValue::Set(None),
        }
        .insert(db)
        .await
        .unwrap();
        package::ActiveModel {
            id: ActiveValue::Set(pkg_id),
            org_id: ActiveValue::Set(org_id),
            name: ActiveValue::Set("http-kit".to_string()),
            description: ActiveValue::Set(Some(description.to_string())),
            vcs: ActiveValue::Set("git".to_string()),
            repo_url: ActiveValue::Set("https://github.com/acme/http-kit".to_string()),
            version_scheme: ActiveValue::Set("semver".to_string()),
            created_at: ActiveValue::Set(Utc::now()),
        }
        .insert(db)
        .await
        .unwrap();
        version::ActiveModel {
            id: ActiveValue::Set(Uuid::new_v4()),
            package_id: ActiveValue::Set(pkg_id),
            version: ActiveValue::Set("1.0.0".to_string()),
            sha256: ActiveValue::Set("existing".to_string()),
            size: ActiveValue::Set(3),
            format: ActiveValue::Set("tar.gz".to_string()),
            vcs_tag: ActiveValue::Set("v1.0.0".to_string()),
            vcs_commit: ActiveValue::Set(None),
            artifact_key: ActiveValue::Set("artifacts/existing.tar.gz".to_string()),
            yanked: ActiveValue::Set(false),
            published_at: ActiveValue::Set(Utc::now()),
        }
        .insert(db)
        .await
        .unwrap();
        (org_id, pkg_id)
    }

    /// Build a publish multipart body: a JSON `meta` field whose manifest sets
    /// `description`, plus an `artifact` part whose sha256 is filled in for the
    /// caller so the server's recompute check passes.
    fn publish_body(version: &str, description: &str) -> (Vec<u8>, String) {
        let artifact = b"hi!";
        let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(artifact));
        let meta = serde_json::json!({
            "manifest": {
                "package": {
                    "org": "acme",
                    "name": "http-kit",
                    "version": version,
                    "description": description,
                    "repository": { "vcs": "git", "url": "https://github.com/acme/http-kit" }
                }
            },
            "vcs_tag": format!("v{version}"),
            "sha256": sha,
            "size": artifact.len(),
        })
        .to_string();
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"meta\"\r\n\r\n");
        body.extend_from_slice(meta.as_bytes());
        body.extend_from_slice(format!("\r\n--{BOUNDARY}\r\n").as_bytes());
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"artifact\"; filename=\"a.tar.gz\"\r\n",
        );
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(artifact);
        body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
        (body, format!("multipart/form-data; boundary={BOUNDARY}"))
    }

    async fn put_version(state: &Arc<AppState>, version: &str, description: &str) -> StatusCode {
        let (body, content_type) = publish_body(version, description);
        let app = super::super::router(state.clone(), 8 * 1024 * 1024);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/packages/acme/http-kit/versions/{version}"))
                    .header(header::AUTHORIZATION, format!("Bearer {TOKEN_PLAINTEXT}"))
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        response.status()
    }

    async fn description_of(db: &DatabaseConnection, pkg_id: Uuid) -> Option<String> {
        package::Entity::find_by_id(pkg_id)
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .description
    }

    /// M1/M2: a duplicate-version publish is rejected with 409 and does NOT
    /// rewrite the stored package metadata (the version-immutability check runs
    /// before any upsert).
    #[tokio::test]
    async fn duplicate_version_publish_preserves_description() {
        let db = test_db().await;
        let (_org, pkg_id) = seed(&db, "ORIGINAL").await;
        let state = state_with(db).await;

        let status = put_version(&state, "1.0.0", "HACKED").await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            description_of(&state.db, pkg_id).await.as_deref(),
            Some("ORIGINAL"),
            "rejected publish must not mutate package metadata"
        );
    }

    /// A fresh version commits: the transaction inserts the version row and the
    /// package metadata upsert (new description) is persisted together.
    #[tokio::test]
    async fn new_version_publish_commits_metadata_and_row() {
        let db = test_db().await;
        let (_org, pkg_id) = seed(&db, "ORIGINAL").await;
        let state = state_with(db).await;

        let status = put_version(&state, "1.1.0", "UPDATED").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            description_of(&state.db, pkg_id).await.as_deref(),
            Some("UPDATED")
        );
        let inserted = version::Entity::find()
            .filter(version::Column::PackageId.eq(pkg_id))
            .filter(version::Column::Version.eq("1.1.0"))
            .one(&state.db)
            .await
            .unwrap();
        assert!(inserted.is_some(), "new version row must be committed");
    }
}
