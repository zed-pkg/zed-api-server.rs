//! Mirror descriptors and publisher signing keys.
//!
//! Two additive columns on `version` and one new table.
//!
//! `version.mirrors` and `version.signatures` are stored as JSON rather than
//! normalized into tables on purpose: they are opaque to the server. The
//! server never derives a mirror set and never validates a signature against
//! anything it could have chosen — it stores what the publisher submitted and
//! serves it back byte-for-byte, because the signature covers those exact
//! bytes. Giving the columns structure would invite the server to normalize
//! them, and a normalized signature is an invalid one.
//!
//! `version.published_at` becomes publisher-asserted for signed publishes for
//! the same reason. The existing column keeps its default so unsigned
//! publishes are unaffected.
//!
//! `publisher_key` is a real table because the server does reason about it:
//! it enforces one active key per id per org, records revocations, and serves
//! the set anonymously — the last being the point, since a key you can only
//! fetch by first reaching the registry is no use when the registry is the
//! thing that is down.

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
            "alter table version add column if not exists mirrors jsonb not null default '[]'::jsonb".into(),
            "alter table version add column if not exists signatures jsonb not null default '[]'::jsonb".into(),
            // Monotonic per package, incremented on every publish. A client
            // that has seen sequence n refuses anything below it, which turns
            // an otherwise-undetectable stale-index replay into a loud failure.
            "alter table package add column if not exists index_sequence bigint not null default 0".into(),
            // The publisher's signed index, stored verbatim. The server can
            // assemble the *contents* from its own rows, but not the
            // signature, so the document is kept whole rather than rebuilt.
            "alter table package add column if not exists signed_index jsonb".into(),
            "create table if not exists publisher_key (
                 id uuid primary key,
                 org_id uuid not null references org(id) on delete cascade,
                 key_id text not null,
                 algorithm text not null,
                 public_key_multibase text not null,
                 state text not null,
                 revoked_reason text,
                 enrolled_at timestamptz not null default now()
             )".into(),
            // One row per (org, key_id): a key id is a name consumers pin, so
            // two rows sharing one would make a pin ambiguous.
            "create unique index if not exists publisher_key_org_key_idx on publisher_key (org_id, key_id)".into(),
            "create index if not exists publisher_key_org_idx on publisher_key (org_id)".into(),
        ],
        _ => vec![
            "alter table version add column mirrors text not null default '[]'".into(),
            "alter table version add column signatures text not null default '[]'".into(),
            "alter table package add column index_sequence bigint not null default 0".into(),
            "alter table package add column signed_index text".into(),
            "create table if not exists publisher_key (
                 id text primary key,
                 org_id text not null,
                 key_id text not null,
                 algorithm text not null,
                 public_key_multibase text not null,
                 state text not null,
                 revoked_reason text,
                 enrolled_at text not null
             )".into(),
            "create unique index if not exists publisher_key_org_key_idx on publisher_key (org_id, key_id)".into(),
        ],
    }
}

fn down_statements(backend: DatabaseBackend) -> Vec<String> {
    match backend {
        DatabaseBackend::Postgres => vec![
            "drop table if exists publisher_key".into(),
            "alter table package drop column if exists signed_index".into(),
            "alter table package drop column if exists index_sequence".into(),
            "alter table version drop column if exists signatures".into(),
            "alter table version drop column if exists mirrors".into(),
        ],
        _ => vec![
            "drop table if exists publisher_key".into(),
            "alter table package drop column signed_index".into(),
            "alter table package drop column index_sequence".into(),
            "alter table version drop column signatures".into(),
            "alter table version drop column mirrors".into(),
        ],
    }
}
