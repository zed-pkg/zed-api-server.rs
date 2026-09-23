use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "version_retirement")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub version_id: Uuid,
    pub reason: String,
    pub message: String,
    pub retired_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::version::Entity",
        from = "Column::VersionId",
        to = "super::version::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    Version,
}

impl Related<super::version::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Version.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
