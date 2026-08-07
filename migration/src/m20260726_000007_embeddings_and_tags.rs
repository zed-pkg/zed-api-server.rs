//! Package `tags` (multi-tag lookup) + the `package_embedding` RAG table, plus
//! the search indexes (trigram name search, tag GIN, pgvector HNSW).
//!
//! Backend-aware: on Postgres this installs pgvector/pg_trgm and a real
//! `vector(2050)` column with an HNSW index (via the halfvec cast, since
//! full-precision vectors cap at 2000 dims for ANN indexes). On SQLite (the
//! test backend) it falls back to plain `text` columns and no vector indexes,
//! so publish/search handlers can still be exercised in-memory. The
//! declarative `schema/schema.sql` is the going-forward source of truth; this
//! keeps the imperative path working today.

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{DatabaseBackend, Statement};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = manager.get_database_backend();
        for sql in up_statements(backend) {
            db.execute(Statement::from_string(backend, sql)).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = manager.get_database_backend();
        for sql in down_statements(backend) {
            db.execute(Statement::from_string(backend, sql)).await?;
        }
        Ok(())
    }
}

fn up_statements(backend: DatabaseBackend) -> Vec<String> {
    match backend {
        DatabaseBackend::Postgres => vec![
            "create extension if not exists pg_trgm".into(),
            "create extension if not exists vector".into(),
            "alter table package add column if not exists tags jsonb not null default '[]'::jsonb"
                .into(),
            "create index if not exists package_tags_gin_idx on package using gin (tags jsonb_path_ops)"
                .into(),
            "create index if not exists package_name_trgm_idx on package using gin (name gin_trgm_ops)"
                .into(),
            "create index if not exists package_created_at_idx on package (created_at desc)".into(),
            "create table if not exists package_embedding (\
                 id uuid primary key default gen_random_uuid(), \
                 package_id uuid not null references package(id) on delete cascade, \
                 embedding_model text not null, \
                 native_dimensions integer not null, \
                 embedding vector(2050) not null, \
                 content text not null, \
                 content_sha256 text not null, \
                 created_at timestamptz not null default now())"
                .into(),
            "create unique index if not exists package_embedding_pkg_model_uq \
                 on package_embedding (package_id, embedding_model)"
                .into(),
            "create index if not exists package_embedding_model_idx \
                 on package_embedding (embedding_model)"
                .into(),
            "create index if not exists package_embedding_hnsw_idx \
                 on package_embedding using hnsw ((embedding::halfvec(2050)) halfvec_cosine_ops)"
                .into(),
        ],
        // SQLite (tests): no pgvector/GIN. `tags` is text holding a JSON array;
        // `embedding` is text holding a JSON array of floats.
        _ => vec![
            "alter table package add column tags text not null default '[]'".into(),
            "create index if not exists package_created_at_idx on package (created_at)".into(),
            "create table if not exists package_embedding (\
                 id char(36) primary key not null, \
                 package_id char(36) not null, \
                 embedding_model text not null, \
                 native_dimensions integer not null, \
                 embedding text not null, \
                 content text not null, \
                 content_sha256 text not null, \
                 created_at timestamp_with_time_zone not null)"
                .into(),
            "create unique index if not exists package_embedding_pkg_model_uq \
                 on package_embedding (package_id, embedding_model)"
                .into(),
        ],
    }
}

fn down_statements(backend: DatabaseBackend) -> Vec<String> {
    match backend {
        DatabaseBackend::Postgres => vec![
            "drop table if exists package_embedding".into(),
            "drop index if exists package_tags_gin_idx".into(),
            "drop index if exists package_name_trgm_idx".into(),
            "drop index if exists package_created_at_idx".into(),
            "alter table package drop column if exists tags".into(),
        ],
        _ => vec![
            "drop table if exists package_embedding".into(),
            "drop index if exists package_created_at_idx".into(),
            // SQLite can't drop columns pre-3.35; leaving `tags` is harmless.
        ],
    }
}
