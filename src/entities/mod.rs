//! SeaORM entities. The schema's source of truth is the `migration` crate
//! in this repo; `zed-web-server` mirrors these read-only.
//!
//! `package_embedding` is intentionally not represented as a SeaORM entity:
//! its `vector(2050)` column is unsupported by SeaORM and every production
//! read/write/search operation uses the typed raw-SQL boundary in
//! `crate::embeddings`. Keeping an unused partial entity compiled into the
//! service created a misleading second persistence model.

pub mod audit_log;
pub mod org;
pub mod package;
pub mod token;
pub mod version;
