//! Make the audit log tamper-evident (zed-docs issue #7 governance).
//!
//! Recording *who* changed published state is only half of a forensic trail:
//! until now anyone with database access could delete or edit a row and leave
//! no trace. Each entry now carries its position in a per-org append-only
//! chain (`seq`), the hash of its own contents (`entry_hash`), and the hash of
//! its predecessor (`prev_hash`), so an edit breaks that entry's hash, a
//! deletion leaves a `seq` gap, and re-linking the remainder is not possible
//! without recomputing every later hash.
//!
//! The unique `(org_id, seq)` index is the structural half of the guarantee:
//! two concurrent appends that both claim the same position cannot both land,
//! so the chain can never silently fork.
//!
//! Existing rows are backfilled with `seq = 0` and empty hashes. They are
//! *unchained by construction* and verification reports them as such rather
//! than pretending a chain exists where none was recorded.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(AuditLog::Table)
                    .add_column(
                        ColumnDef::new(AuditLog::Seq)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(AuditLog::Table)
                    .add_column(
                        ColumnDef::new(AuditLog::EntryHash)
                            .string()
                            .not_null()
                            .default(""),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(AuditLog::Table)
                    .add_column(ColumnDef::new(AuditLog::PrevHash).string())
                    .to_owned(),
            )
            .await?;
        // Number the rows that predate the chain, per org, in their existing
        // order. Without this every legacy row would keep seq = 0 and the
        // unique index below could not be created on an upgraded deployment —
        // which would quietly leave exactly the installations that already
        // hold history without the structural guarantee.
        //
        // Their hashes stay empty on purpose: these entries were never chained
        // and must not be presented as if they were. `verify_chain` skips them
        // and starts its contiguity check at the first genuinely chained row.
        backfill_legacy_seq(manager).await?;

        // Two appends racing for the same position must not both succeed. This
        // is the structural half of the guarantee: the chain cannot fork even
        // if the advisory lock is unavailable.
        manager
            .create_index(
                Index::create()
                    .name("idx_audit_log_org_seq")
                    .table(AuditLog::Table)
                    .col(AuditLog::OrgId)
                    .col(AuditLog::Seq)
                    .unique()
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // The index may not exist (see up()); ignore its absence.
        let _ = manager
            .drop_index(
                Index::drop()
                    .name("idx_audit_log_org_seq")
                    .table(AuditLog::Table)
                    .to_owned(),
            )
            .await;
        for column in [AuditLog::PrevHash, AuditLog::EntryHash, AuditLog::Seq] {
            manager
                .alter_table(
                    Table::alter()
                        .table(AuditLog::Table)
                        .drop_column(column)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

/// Give every pre-chain row a distinct per-org `seq`, preserving the order the
/// entries were recorded in (`at`, with `id` breaking ties so the result is
/// deterministic and re-runnable).
///
/// The correlated-count form is used rather than a window function because it
/// is valid on both Postgres and the SQLite the tests run against, so the
/// upgrade path that ships is the one that is exercised.
async fn backfill_legacy_seq(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    use sea_orm::{ConnectionTrait, Statement};
    let db = manager.get_connection();
    let backend = db.get_database_backend();
    db.execute(Statement::from_string(
        backend,
        LEGACY_SEQ_BACKFILL_SQL.to_string(),
    ))
    .await?;
    Ok(())
}

/// The exact statement [`backfill_legacy_seq`] runs, exposed so the upgrade
/// test can exercise the shipped SQL rather than a paraphrase of it.
pub const LEGACY_SEQ_BACKFILL_SQL: &str = "UPDATE audit_log SET seq = (
             SELECT COUNT(*) FROM audit_log AS earlier
             WHERE earlier.org_id = audit_log.org_id
               AND (earlier.at < audit_log.at
                    OR (earlier.at = audit_log.at AND earlier.id <= audit_log.id))
         )";

#[derive(DeriveIden)]
enum AuditLog {
    Table,
    OrgId,
    Seq,
    EntryHash,
    PrevHash,
}
