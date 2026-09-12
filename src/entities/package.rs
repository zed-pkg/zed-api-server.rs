use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "package")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub vcs: String,
    pub repo_url: String,
    #[sea_orm(default_value = "semver")]
    pub version_scheme: String,
    /// Free-form tags for multi-tag lookup. A JSON array of strings; jsonb on
    /// Postgres (GIN-indexed for containment/overlap), text on the SQLite test
    /// backend. Defaults to `[]`.
    #[sea_orm(column_type = "Json")]
    pub tags: Json,
    pub created_at: DateTimeUtc,
    /// Monotonic index counter, bumped on every publish.
    ///
    /// A signed index served by a mirror is genuine forever, so freshness
    /// cannot come from the signature. This counter is what lets a client
    /// refuse an index older than one it has already seen, turning a silent
    /// rollback — the way you hide a security release — into a loud failure.
    #[sea_orm(default_value = 0)]
    pub index_sequence: i64,
    /// The publisher's signed version index, stored verbatim.
    ///
    /// The server can assemble the index's *contents* from its own rows, but
    /// not the signature over them, so the document is kept whole rather than
    /// rebuilt. Absent for publishers who do not sign.
    #[sea_orm(column_type = "Json", nullable)]
    pub signed_index: Option<Json>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::org::Entity",
        from = "Column::OrgId",
        to = "super::org::Column::Id"
    )]
    Org,
    #[sea_orm(has_many = "super::version::Entity")]
    Version,
}

impl Related<super::org::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Org.def()
    }
}

impl Related<super::version::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Version.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
