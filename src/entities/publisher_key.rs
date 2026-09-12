//! An org's Ed25519 metadata-signing keys.
//!
//! Public halves only; the server never sees a private key and has no route
//! that could accept one. These rows are served anonymously, which is the
//! whole point: a client needs them precisely when it has stopped being able
//! to reach this server for metadata, so gating them behind a credential
//! would defeat the mechanism they exist for.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "publisher_key")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub org_id: Uuid,
    /// Short label consumers pin. Unique within an org, enforced by index.
    pub key_id: String,
    /// Always `ed25519` in v1.
    pub algorithm: String,
    /// Multibase base58btc, `z`-prefixed.
    pub public_key_multibase: String,
    /// `active`, `retired`, or `revoked`.
    ///
    /// Retired still verifies history; revoked does not. Keeping them distinct
    /// is what makes routine rotation cheap and compromise loud — collapsing
    /// them would mean every rotation invalidated years of signatures.
    pub state: String,
    pub revoked_reason: Option<String>,
    pub enrolled_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::org::Entity",
        from = "Column::OrgId",
        to = "super::org::Column::Id"
    )]
    Org,
}

impl Related<super::org::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Org.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
