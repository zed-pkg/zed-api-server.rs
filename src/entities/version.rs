use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "version")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub package_id: Uuid,
    pub version: String,
    pub sha256: String,
    pub size: i64,
    pub format: String,
    pub vcs_tag: String,
    pub vcs_commit: Option<String>,
    pub artifact_key: String,
    pub yanked: bool,
    /// Publisher-asserted for a signed publish, server-assigned otherwise.
    ///
    /// Asserted rather than assigned because it is inside the signed payload:
    /// a signature can only cover fields its signer knew at signing time. The
    /// server records what it was given and serves it back verbatim — a
    /// "helpful" normalization here would invalidate every signature stored.
    pub published_at: DateTimeUtc,
    /// Mirror descriptors submitted with the publish, as opaque JSON.
    ///
    /// Opaque on purpose. The server never derives a mirror set and never
    /// rewrites one: the publisher's signature covers these exact bytes, so
    /// any normalization the server applied would break verification for
    /// every consumer.
    #[sea_orm(column_type = "Json")]
    pub mirrors: Json,
    /// Detached publisher signatures over the version attestation.
    #[sea_orm(column_type = "Json")]
    pub signatures: Json,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::package::Entity",
        from = "Column::PackageId",
        to = "super::package::Column::Id"
    )]
    Package,
}

impl Related<super::package::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Package.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
