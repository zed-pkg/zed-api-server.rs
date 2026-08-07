//! The realistic upgrade path for the audit chain (zed-docs issue #7).
//!
//! A deployment that already holds audit history must survive the migration
//! that makes the log tamper-evident: existing rows keep their contents, gain
//! distinct per-org positions so the unique `(org_id, seq)` index can be
//! created, and stay marked unchained rather than masquerading as verified
//! history.
//!
//! The backfill statement is the part that can silently corrupt an upgrade, so
//! the test drives the *shipped* SQL (`LEGACY_SEQ_BACKFILL_SQL`) against a
//! table shaped like the pre-chain schema. It does not run the whole migrator:
//! earlier migrations use foreign-key syntax sea-query cannot render for
//! SQLite, and reaching for a live Postgres would make this test infrastructure
//! -dependent for no extra coverage of the logic under test.

use chrono::{Duration, Utc};
use migration::m20260726_000008_audit_chain::LEGACY_SEQ_BACKFILL_SQL;
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
};
use uuid::Uuid;

async fn pre_chain_db() -> DatabaseConnection {
    let mut opts = ConnectOptions::new("sqlite::memory:".to_string());
    opts.max_connections(1)
        .min_connections(1)
        .sqlx_logging(false);
    let db = Database::connect(opts).await.unwrap();
    // The audit_log shape as it existed before the chain, plus the columns the
    // migration adds (defaulted exactly as the ALTERs default them).
    exec(
        &db,
        "CREATE TABLE audit_log (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            at TEXT NOT NULL,
            action TEXT NOT NULL,
            subject TEXT NOT NULL,
            actor_token_id TEXT,
            actor_token_name TEXT NOT NULL,
            actor_role TEXT NOT NULL,
            detail TEXT,
            seq BIGINT NOT NULL DEFAULT 0,
            entry_hash TEXT NOT NULL DEFAULT '',
            prev_hash TEXT
        )",
    )
    .await;
    db
}

async fn exec(db: &DatabaseConnection, sql: &str) {
    db.execute(Statement::from_string(DbBackend::Sqlite, sql.to_string()))
        .await
        .unwrap();
}

async fn seqs_for(db: &DatabaseConnection, org: Uuid) -> Vec<i64> {
    db.query_all(Statement::from_string(
        DbBackend::Sqlite,
        format!("SELECT seq FROM audit_log WHERE org_id = '{org}' ORDER BY seq"),
    ))
    .await
    .unwrap()
    .iter()
    .map(|r| r.try_get::<i64>("", "seq").unwrap())
    .collect()
}

#[tokio::test]
async fn legacy_rows_are_numbered_per_org_in_recorded_order() {
    let db = pre_chain_db().await;
    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();
    let base = Utc::now();

    // Two orgs interleaved in time, as a live registry would hold them.
    for (i, org) in [org_a, org_a, org_b, org_a].into_iter().enumerate() {
        exec(
            &db,
            &format!(
                "INSERT INTO audit_log (id, org_id, at, action, subject, actor_token_id, \
                 actor_token_name, actor_role, detail) VALUES ('{}', '{org}', '{}', 'publish', \
                 'acme/pkg@1.0.{i}', NULL, 'legacy', 'owner', NULL)",
                Uuid::new_v4(),
                (base + Duration::seconds(i as i64)).to_rfc3339(),
            ),
        )
        .await;
    }

    exec(&db, LEGACY_SEQ_BACKFILL_SQL).await;

    // Numbering is per-org, starts at 1, and is dense — the precondition for
    // the unique index.
    assert_eq!(seqs_for(&db, org_a).await, vec![1, 2, 3]);
    assert_eq!(seqs_for(&db, org_b).await, vec![1]);

    // Order is preserved: the oldest entry for org_a is still seq 1.
    let first = db
        .query_one(Statement::from_string(
            DbBackend::Sqlite,
            format!("SELECT subject FROM audit_log WHERE org_id = '{org_a}' AND seq = 1"),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        first.try_get::<String>("", "subject").unwrap(),
        "acme/pkg@1.0.0"
    );

    // Contents are untouched and the rows stay unchained: empty hashes are how
    // verification knows not to vouch for history it never protected.
    let rows = db
        .query_all(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT entry_hash, prev_hash, actor_token_name FROM audit_log".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(rows.len(), 4, "no row may be lost by the upgrade");
    for row in &rows {
        assert_eq!(row.try_get::<String>("", "entry_hash").unwrap(), "");
        assert!(row
            .try_get::<Option<String>>("", "prev_hash")
            .unwrap()
            .is_none());
        assert_eq!(
            row.try_get::<String>("", "actor_token_name").unwrap(),
            "legacy"
        );
    }
}

/// Rows sharing a timestamp must still get distinct positions, or the unique
/// index could not be created on a database where two entries landed in the
/// same clock tick.
#[tokio::test]
async fn rows_with_identical_timestamps_still_get_distinct_positions() {
    let db = pre_chain_db().await;
    let org = Uuid::new_v4();
    let at = Utc::now().to_rfc3339();
    for i in 0..3 {
        exec(
            &db,
            &format!(
                "INSERT INTO audit_log (id, org_id, at, action, subject, actor_token_id, \
                 actor_token_name, actor_role, detail) VALUES ('{}', '{org}', '{at}', 'publish', \
                 's{i}', NULL, 'legacy', 'owner', NULL)",
                Uuid::new_v4(),
            ),
        )
        .await;
    }

    exec(&db, LEGACY_SEQ_BACKFILL_SQL).await;
    assert_eq!(seqs_for(&db, org).await, vec![1, 2, 3]);

    // And the numbering is stable: re-running the backfill is a no-op, so a
    // retried or re-applied migration cannot renumber history.
    exec(&db, LEGACY_SEQ_BACKFILL_SQL).await;
    assert_eq!(seqs_for(&db, org).await, vec![1, 2, 3]);
}

/// The backfill must be harmless when there is nothing to backfill.
#[tokio::test]
async fn an_empty_table_backfills_cleanly() {
    let db = pre_chain_db().await;
    exec(&db, LEGACY_SEQ_BACKFILL_SQL).await;
    let count = db
        .query_one(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT COUNT(*) AS c FROM audit_log".to_string(),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(count.try_get::<i64>("", "c").unwrap(), 0);
}
