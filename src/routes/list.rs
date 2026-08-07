//! `GET /v1/packages` — list all packages, newest first, with optional tag
//! filtering and pagination.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use sea_orm::{EntityTrait, PaginatorTrait, QueryOrder, QuerySelect};
use serde::Deserialize;
use zed_interfaces::registry::{PackageListResponse, PackageSummary};

use crate::entities::{org, package, version};
use crate::error::ApiResult;
use crate::state::AppState;

use super::search::{has_all_tags, parse_tag_filter};

#[derive(Deserialize)]
pub struct ListParams {
    /// Comma-separated tag filter; a package must carry every tag.
    #[serde(default)]
    tags: Option<String>,
    #[serde(default = "default_limit")]
    limit: u64,
    #[serde(default)]
    offset: u64,
}

fn default_limit() -> u64 {
    50
}

pub async fn list_packages(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListParams>,
) -> ApiResult<Json<PackageListResponse>> {
    let limit = params.limit.clamp(1, 200);
    let want = parse_tag_filter(&params.tags);

    if want.is_empty() {
        // No tag filter: paginate in SQL and count cheaply.
        let total = package::Entity::find().count(&state.db).await?;
        let rows = package::Entity::find()
            .find_also_related(org::Entity)
            .order_by_desc(package::Column::CreatedAt)
            .limit(limit)
            .offset(params.offset)
            .all(&state.db)
            .await?;
        let items = self::summaries(&state, rows).await?;
        return Ok(Json(PackageListResponse { items, total }));
    }

    // Tag filter: fetch newest-first (capped), filter by tags, then paginate.
    // Post-filtering keeps AND-tag semantics identical on Postgres and the
    // SQLite test backend; the GIN index serves the raw/declarative path.
    const SCAN_CAP: u64 = 2000;
    let rows = package::Entity::find()
        .find_also_related(org::Entity)
        .order_by_desc(package::Column::CreatedAt)
        .limit(SCAN_CAP)
        .all(&state.db)
        .await?;
    let matched: Vec<_> = rows
        .into_iter()
        .filter(|(pkg, _)| has_all_tags(&super::tags_of(pkg), &want))
        .collect();
    let total = matched.len() as u64;
    let page: Vec<_> = matched
        .into_iter()
        .skip(params.offset as usize)
        .take(limit as usize)
        .collect();
    let items = self::summaries(&state, page).await?;
    Ok(Json(PackageListResponse { items, total }))
}

/// Build package summaries (with tags and latest non-yanked version) for a page.
async fn summaries(
    state: &AppState,
    rows: Vec<(package::Model, Option<org::Model>)>,
) -> ApiResult<Vec<PackageSummary>> {
    use sea_orm::{ColumnTrait, QueryFilter};
    let mut items = Vec::with_capacity(rows.len());
    for (pkg, org_row) in rows {
        let Some(org_row) = org_row else { continue };
        let versions = version::Entity::find()
            .filter(version::Column::PackageId.eq(pkg.id))
            .all(&state.db)
            .await?;
        let latest = super::latest_visible_version(&versions);
        items.push(PackageSummary {
            tags: super::tags_of(&pkg),
            org: org_row.slug,
            name: pkg.name,
            description: pkg.description,
            latest,
        });
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::super::{search::has_all_tags, tags_of};
    use crate::entities::{org, package};
    use chrono::Utc;
    use sea_orm::{
        ActiveModelTrait, ActiveValue, ConnectOptions, ConnectionTrait, Database,
        DatabaseConnection, EntityTrait, Schema,
    };
    use uuid::Uuid;

    async fn test_db() -> DatabaseConnection {
        let mut opts = ConnectOptions::new("sqlite::memory:".to_string());
        opts.max_connections(1)
            .min_connections(1)
            .sqlx_logging(false);
        let db = Database::connect(opts).await.unwrap();
        let backend = db.get_database_backend();
        let schema = Schema::new(backend);
        for stmt in [
            schema.create_table_from_entity(org::Entity),
            schema.create_table_from_entity(package::Entity),
        ] {
            db.execute(backend.build(&stmt)).await.unwrap();
        }
        db
    }

    async fn insert_pkg(
        db: &DatabaseConnection,
        org_id: Uuid,
        name: &str,
        tags: serde_json::Value,
    ) {
        package::ActiveModel {
            id: ActiveValue::Set(Uuid::new_v4()),
            org_id: ActiveValue::Set(org_id),
            name: ActiveValue::Set(name.to_string()),
            description: ActiveValue::Set(None),
            vcs: ActiveValue::Set("git".to_string()),
            repo_url: ActiveValue::Set(format!("https://github.com/acme/{name}")),
            version_scheme: ActiveValue::Set("semver".to_string()),
            tags: ActiveValue::Set(tags),
            created_at: ActiveValue::Set(Utc::now()),
        }
        .insert(db)
        .await
        .unwrap();
    }

    // The jsonb/text `tags` column must round-trip through the SQLite backend,
    // and tag filtering (AND semantics) must work over what comes back.
    #[tokio::test]
    async fn tags_round_trip_and_filter_on_sqlite() {
        let db = test_db().await;
        let org_id = Uuid::new_v4();
        org::ActiveModel {
            id: ActiveValue::Set(org_id),
            slug: ActiveValue::Set("acme".to_string()),
            created_by_token: ActiveValue::Set(None),
            created_at: ActiveValue::Set(Utc::now()),
        }
        .insert(&db)
        .await
        .unwrap();

        insert_pkg(&db, org_id, "cli-tool", serde_json::json!(["cli", "rust"])).await;
        insert_pkg(&db, org_id, "web-thing", serde_json::json!(["web"])).await;

        let rows = package::Entity::find().all(&db).await.unwrap();
        assert_eq!(rows.len(), 2);

        let cli = rows.iter().find(|p| p.name == "cli-tool").unwrap();
        assert_eq!(tags_of(cli), vec!["cli".to_string(), "rust".to_string()]);

        // AND-filter: only cli-tool carries both cli and rust.
        let matched: Vec<_> = rows
            .iter()
            .filter(|p| has_all_tags(&tags_of(p), &["cli".into(), "rust".into()]))
            .collect();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].name, "cli-tool");
    }
}
