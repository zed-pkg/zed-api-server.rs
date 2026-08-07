use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Org::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Org::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Org::Slug).string().not_null().unique_key())
                    .col(
                        ColumnDef::new(Org::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Token::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Token::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Token::Name).string().not_null())
                    .col(
                        ColumnDef::new(Token::TokenHash)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Token::OrgId).uuid())
                    .col(
                        ColumnDef::new(Token::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_token_org")
                            .from(Token::Table, Token::OrgId)
                            .to(Org::Table, Org::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Package::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Package::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Package::OrgId).uuid().not_null())
                    .col(ColumnDef::new(Package::Name).string().not_null())
                    .col(ColumnDef::new(Package::Description).string())
                    .col(ColumnDef::new(Package::Vcs).string().not_null())
                    .col(ColumnDef::new(Package::RepoUrl).string().not_null())
                    .col(
                        ColumnDef::new(Package::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_package_org")
                            .from(Package::Table, Package::OrgId)
                            .to(Org::Table, Org::Id),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_package_org_name")
                    .table(Package::Table)
                    .col(Package::OrgId)
                    .col(Package::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Version::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Version::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Version::PackageId).uuid().not_null())
                    .col(ColumnDef::new(Version::Version).string().not_null())
                    .col(ColumnDef::new(Version::Sha256).string().not_null())
                    .col(ColumnDef::new(Version::Size).big_integer().not_null())
                    .col(ColumnDef::new(Version::Format).string().not_null())
                    .col(ColumnDef::new(Version::VcsTag).string().not_null())
                    .col(ColumnDef::new(Version::VcsCommit).string())
                    .col(ColumnDef::new(Version::ArtifactKey).string().not_null())
                    .col(
                        ColumnDef::new(Version::Yanked)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(Version::PublishedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_version_package")
                            .from(Version::Table, Version::PackageId)
                            .to(Package::Table, Package::Id),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_version_package_version")
                    .table(Version::Table)
                    .col(Version::PackageId)
                    .col(Version::Version)
                    .unique()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_version_sha256")
                    .table(Version::Table)
                    .col(Version::Sha256)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Version::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Package::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Token::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Org::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Org {
    Table,
    Id,
    Slug,
    CreatedAt,
}

// These enum variants intentionally mirror durable SQL identifiers. Renaming
// TokenHash would silently rename the `token_hash` column generated by
// DeriveIden, so this narrow lint exception protects schema compatibility.
#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Token {
    Table,
    Id,
    Name,
    TokenHash,
    OrgId,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Package {
    Table,
    Id,
    OrgId,
    Name,
    Description,
    Vcs,
    RepoUrl,
    CreatedAt,
}

// `Version::Version` is the migration DSL representation of the existing
// `version` table's `version` column. Keep the database identifier stable.
#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Version {
    Table,
    Id,
    PackageId,
    Version,
    Sha256,
    Size,
    Format,
    VcsTag,
    VcsCommit,
    ArtifactKey,
    Yanked,
    PublishedAt,
}
