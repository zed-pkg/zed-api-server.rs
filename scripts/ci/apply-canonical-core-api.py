#!/usr/bin/env python3
"""Apply the bounded canonical-core API cutover repairs.

The script is intentionally assertion-heavy: every replacement must match the
reviewed parent head exactly, and the workflow deletes this carrier only after
the complete locked Rust gate passes.
"""

from __future__ import annotations

import re
from pathlib import Path


def replace_exact(path: Path, old: str, new: str, expected: int = 1) -> None:
    text = path.read_text()
    count = text.count(old)
    if count != expected:
        raise SystemExit(
            f"{path}: expected {expected} occurrence(s), found {count}: {old[:120]!r}"
        )
    path.write_text(text.replace(old, new))


# Resolve a legacy upload's requested version into the canonical version row
# when the browser did not already send an id, and make unknown status values
# owned strings so the core validator can reject them without a lifetime leak.
account = Path("src/routes/account.rs")
replace_exact(
    account,
    '''    let status = normalize_upload_status(&request.status).to_owned();
    let completed_at = matches!(status.as_str(), "verified" | "failed" | "aborted")
        .then(|| Utc::now().fixed_offset());
    let upload = zed_orm_core::account::register_package_upload_for_user(
        registry_write(&state)?,
        user.id,
        &org_slug,
        &package_name,
        PackageUploadInput {
            package_version_id: request.package_version_id,
            requested_version: request.requested_version,''',
    '''    let status = normalize_upload_status(&request.status);
    let completed_at = matches!(status.as_str(), "verified" | "failed" | "aborted")
        .then(|| Utc::now().fixed_offset());
    let read = registry_read(&state)?;
    let package = zed_orm_core::read::package_by_org_and_name(read, &org_slug, &package_name)
        .await
        .map_err(map_orm_error)?
        .map(|(package, _)| package)
        .ok_or_else(|| ApiErr::not_found("package"))?;
    let package_version_id = match request.package_version_id {
        Some(version_id) => Some(version_id),
        None => zed_orm_core::read::versions_for_package(read, package.id)
            .await
            .map_err(map_orm_error)?
            .into_iter()
            .find(|version| version.version == request.requested_version)
            .map(|version| version.id),
    };
    let upload = zed_orm_core::account::register_package_upload_for_user(
        registry_write(&state)?,
        user.id,
        &org_slug,
        &package_name,
        PackageUploadInput {
            package_version_id,
            requested_version: request.requested_version,''',
)
replace_exact(
    account,
    '''fn normalize_upload_status(value: &str) -> &'static str {
    match value {
        "complete" | "completed" | "published" => "verified",
        "pending" => "pending",
        "uploading" => "uploading",
        "stored" => "stored",
        "verified" => "verified",
        "failed" => "failed",
        "aborted" => "aborted",
        _ => value,
    }
}''',
    '''fn normalize_upload_status(value: &str) -> String {
    match value {
        "complete" | "completed" | "published" => "verified".to_owned(),
        known @ ("pending" | "uploading" | "stored" | "verified" | "failed" | "aborted") => {
            known.to_owned()
        }
        unknown => unknown.to_owned(),
    }
}''',
)

# Make an already-committed legacy version reconcile the canonical projection
# before returning the stable immutable-version conflict. A new publish reports
# no success until canonical adoption commits.
publish = Path("src/routes/publish.rs")
replace_exact(
    publish,
    "use axum::http::{HeaderMap, StatusCode};",
    "use axum::http::{HeaderMap, StatusCode, header};",
)
replace_exact(
    publish,
    '''    let token = require_token(&state.db, &headers).await?;

    // Authorize BEFORE buffering the body.''',
    '''    let token = require_token(&state.db, &headers).await?;
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    // Authorize BEFORE buffering the body.''',
)
old_precheck = '''    // Immutability is checked BEFORE any metadata mutation: if this exact
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
    let artifact_len = artifact.len() as i64;'''
new_precheck = '''    let key = artifact_key(&actual_sha, meta.format.extension());
    let artifact_len = artifact.len() as i64;

    // Immutability is checked BEFORE any metadata mutation. An identical retry
    // also repairs a possible legacy-only partial commit before returning the
    // stable conflict; a divergent retry never reaches the canonical plane.
    if let Some(pkg) = find_package_row(&state, &org_row, &name).await? {
        let existing = version::Entity::find()
            .filter(version::Column::PackageId.eq(pkg.id))
            .filter(version::Column::Version.eq(&ver))
            .one(&state.db)
            .await?;
        if let Some(existing) = existing {
            if !legacy_version_matches(&existing, &meta, &actual_sha, artifact_len, &key) {
                return Err(ApiErr::conflict(
                    "version_exists",
                    format!("{org_slug}/{name}@{ver} is already published with different immutable facts"),
                ));
            }
            adopt_canonical_publish(
                &state,
                &org_row,
                &meta,
                &actual_sha,
                artifact_len,
                &key,
                user_agent.clone(),
            )
            .await?;
            return Err(ApiErr::conflict(
                "version_exists",
                format!("{org_slug}/{name}@{ver} is already published; canonical projection reconciled"),
            ));
        }
    }

    // Store the blob before recording the row that references it. `Bytes` is
    // moved (not re-copied) into the store; the length is captured first since
    // the version row records it after the put.'''
replace_exact(publish, old_precheck, new_precheck)
replace_exact(
    publish,
    '''            if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
                return Err(ApiErr::conflict(
                    "version_exists",
                    format!("{org_slug}/{name}@{ver} is already published; versions are immutable"),
                ));
            }''',
    '''            if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
                let existing = version::Entity::find()
                    .filter(version::Column::PackageId.eq(pkg.id))
                    .filter(version::Column::Version.eq(&ver))
                    .one(&state.db)
                    .await?;
                if let Some(existing) = existing
                    && legacy_version_matches(&existing, &meta, &actual_sha, artifact_len, &key)
                {
                    adopt_canonical_publish(
                        &state,
                        &org_row,
                        &meta,
                        &actual_sha,
                        artifact_len,
                        &key,
                        user_agent.clone(),
                    )
                    .await?;
                }
                return Err(ApiErr::conflict(
                    "version_exists",
                    format!("{org_slug}/{name}@{ver} is already published; versions are immutable"),
                ));
            }''',
)
replace_exact(
    publish,
    '''    }

    tracing::info!(org = %org_slug, name = %name, version = %ver, sha256 = %actual_sha, "published");''',
    '''    }

    adopt_canonical_publish(
        &state,
        &org_row,
        &meta,
        &actual_sha,
        artifact_len,
        &key,
        user_agent,
    )
    .await?;

    tracing::info!(org = %org_slug, name = %name, version = %ver, sha256 = %actual_sha, "published");''',
)
helpers = r'''

fn legacy_version_matches(
    existing: &version::Model,
    meta: &PublishMeta,
    actual_sha: &str,
    artifact_len: i64,
    artifact_key: &str,
) -> bool {
    existing.sha256 == actual_sha
        && existing.size == artifact_len
        && existing.format == meta.format.extension()
        && existing.vcs_tag == meta.vcs_tag
        && existing.vcs_commit == meta.vcs_commit
        && existing.artifact_key == artifact_key
}

async fn adopt_canonical_publish(
    state: &AppState,
    org_row: &org::Model,
    meta: &PublishMeta,
    actual_sha: &str,
    artifact_len: i64,
    artifact_key: &str,
    user_agent: Option<String>,
) -> ApiResult<()> {
    let Some(context) = state.registry_write.as_ref() else {
        if cfg!(test) {
            // Legacy unit tests intentionally use SQLite and exercise the
            // compatibility transaction in isolation. Full-stack PostgreSQL
            // tests supply the canonical context and prove the mirror.
            return Ok(());
        }
        return Err(ApiErr::service_unavailable(
            "registry_data_plane_unavailable",
            "canonical registry write context is not configured",
        ));
    };
    let package = &meta.manifest.package;
    zed_orm_core::publication::adopt_machine_publish(
        context,
        zed_orm_core::publication::MachinePublishInput {
            org_slug: package.org.clone(),
            org_name: Some(org_row.slug.clone()),
            package_name: package.name.clone(),
            description: package.description.clone(),
            vcs: package.repository.vcs.to_string(),
            repo_url: package.repository.url.clone(),
            homepage_url: None,
            keywords: serde_json::json!(package.keywords),
            version: package.version.clone(),
            version_scheme: package.version_scheme.as_str().to_owned(),
            sha256: actual_sha.to_owned(),
            size_bytes: artifact_len,
            format: meta.format.extension().to_owned(),
            vcs_tag: Some(meta.vcs_tag.clone()),
            vcs_commit: meta.vcs_commit.clone(),
            artifact_key: artifact_key.to_owned(),
            manifest: serde_json::to_value(&meta.manifest).map_err(|error| {
                ApiErr::bad_request("invalid_manifest", format!("manifest serialization failed: {error}"))
            })?,
            published_by_user_id: None,
            api_token_id: None,
            client_ip_hash: None,
            user_agent,
        },
    )
    .await
    .map_err(crate::account::map_orm_error)?;
    Ok(())
}
'''
replace_exact(
    publish,
    "\nasync fn read_multipart(multipart: &mut Multipart) -> ApiResult<(PublishMeta, Bytes)> {",
    helpers + "\nasync fn read_multipart(multipart: &mut Multipart) -> ApiResult<(PublishMeta, Bytes)> {",
)

# New opaque contexts are mandatory in production but optional in legacy
# in-memory unit fixtures. Insert explicit None values in every test literal so
# the compiler proves each call site made that choice deliberately.
for path in Path("src").rglob("*.rs"):
    if path.name == "state.rs":
        continue
    text = path.read_text()
    pattern = re.compile(
        r"(AppState\s*\{\s*\n(?:(?:\s*//[^\n]*\n)*)\s*db:\s*[^\n]+,\n)(?!\s*registry_read:)",
        re.MULTILINE,
    )
    updated, count = pattern.subn(
        r"\1            registry_read: None,\n            registry_write: None,\n",
        text,
    )
    if count:
        path.write_text(updated)

# The production constructor must be the only AppState literal with Some
# contexts. Fail rather than silently leaving an unreviewed literal incomplete.
remaining = []
for path in Path("src").rglob("*.rs"):
    if path.name == "state.rs":
        continue
    text = path.read_text()
    for match in re.finditer(r"AppState\s*\{", text):
        window = text[match.start() : match.start() + 500]
        if "registry_read:" not in window or "registry_write:" not in window:
            remaining.append(f"{path}:{text.count(chr(10), 0, match.start()) + 1}")
if remaining:
    raise SystemExit("AppState literals missing canonical contexts: " + ", ".join(remaining))

# The cutover must remove every application reference to the transitional ORM.
for path in Path("src").rglob("*.rs"):
    text = path.read_text()
    if "zed_orm::" in text:
        raise SystemExit(f"transitional zed_orm reference remains in {path}")
