//! Audit log (zed-docs issue #7, governance): an append-only record of every
//! mutation of published state — publish, yank/unyank, org claim — so an
//! operator can answer "who changed what, when" during an incident.
//!
//! The actor is the *token* that acted; its name and role are denormalized
//! into the row so the trail survives the token being revoked or deleted
//! (`actor_token_id` is deliberately **not** a foreign key for that reason).

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AuditLog::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(AuditLog::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(AuditLog::OrgId).uuid().not_null())
                    .col(
                        ColumnDef::new(AuditLog::At)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(AuditLog::Action).string().not_null())
                    .col(ColumnDef::new(AuditLog::Subject).string().not_null())
                    // Kept unconstrained on purpose: the trail must outlive the
                    // token it names.
                    .col(ColumnDef::new(AuditLog::ActorTokenId).uuid())
                    .col(ColumnDef::new(AuditLog::ActorTokenName).string().not_null())
                    .col(ColumnDef::new(AuditLog::ActorRole).string().not_null())
                    .col(ColumnDef::new(AuditLog::Detail).string())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_audit_log_org")
                            .from(AuditLog::Table, AuditLog::OrgId)
                            .to(Org::Table, Org::Id),
                    )
                    .to_owned(),
            )
            .await?;
        // The only read pattern: an org's entries, newest first.
        manager
            .create_index(
                Index::create()
                    .name("idx_audit_log_org_at")
                    .table(AuditLog::Table)
                    .col(AuditLog::OrgId)
                    .col(AuditLog::At)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AuditLog::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum AuditLog {
    Table,
    Id,
    OrgId,
    At,
    Action,
    Subject,
    ActorTokenId,
    ActorTokenName,
    ActorRole,
    Detail,
}

#[derive(DeriveIden)]
enum Org {
    Table,
    Id,
}
