//! Advisory retirement state for immutable package versions.
//!
//! Retirement is intentionally stored outside `version`: the artifact row is
//! immutable publication state, while retirement is mutable advisory lifecycle
//! metadata. A retired release remains resolvable and downloadable; yanking is
//! the independent mechanism that removes a version from fresh resolution.

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
        db.execute(Statement::from_string(
            backend,
            "drop table if exists version_retirement".to_string(),
        ))
        .await?;
        Ok(())
    }
}

fn up_statements(backend: DatabaseBackend) -> Vec<String> {
    match backend {
        DatabaseBackend::Postgres => vec![
            "create table if not exists version_retirement (
                 version_id uuid primary key references version(id) on delete cascade,
                 reason text not null check (reason in ('renamed','deprecated','security','invalid','other')),
                 message text not null check (char_length(trim(message)) > 0 and char_length(message) <= 140),
                 retired_at timestamptz not null default now()
             )"
            .into(),
            "create index if not exists version_retirement_reason_idx on version_retirement (reason)"
                .into(),
        ],
        _ => vec![
            "create table if not exists version_retirement (
                 version_id text primary key references version(id) on delete cascade,
                 reason text not null check (reason in ('renamed','deprecated','security','invalid','other')),
                 message text not null check (length(trim(message)) > 0 and length(message) <= 140),
                 retired_at text not null
             )"
            .into(),
            "create index if not exists version_retirement_reason_idx on version_retirement (reason)"
                .into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_schema_keeps_retirement_orthogonal_to_version() {
        let sql = up_statements(DatabaseBackend::Postgres).join("\n");
        assert!(sql.contains("create table if not exists version_retirement"));
        assert!(sql.contains("version_id uuid primary key references version(id) on delete cascade"));
        assert!(sql.contains("'renamed','deprecated','security','invalid','other'"));
        assert!(sql.contains("char_length(message) <= 140"));
        assert!(!sql.contains("alter table version add column"));
    }

    #[test]
    fn sqlite_test_schema_enforces_same_reason_and_message_domain() {
        let sql = up_statements(DatabaseBackend::Sqlite).join("\n");
        assert!(sql.contains("create table if not exists version_retirement"));
        assert!(sql.contains("'renamed','deprecated','security','invalid','other'"));
        assert!(sql.contains("length(message) <= 140"));
    }
}
