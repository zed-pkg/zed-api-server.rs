//! Audit trail for mutations of published state (zed-docs issue #7).
//!
//! Every publish, yank/unyank, and org claim appends one row naming the token
//! that acted. Reads are not audited: the log answers "who *changed* what",
//! and auditing installs would bury that signal under ordinary traffic.
//!
//! **Tamper-evidence.** Recording who acted is only half a forensic trail — a
//! log that can be edited by whoever compromised the database proves nothing.
//! Each entry therefore carries its position in a per-org append-only chain
//! (`seq`), a hash of its own contents (`entry_hash`), and its predecessor's
//! hash (`prev_hash`). Editing a row breaks its own hash; deleting one leaves
//! a `seq` gap and orphans the next link; re-linking the tail requires
//! recomputing every later hash. The digest input is defined in
//! `zed-interfaces` so a client can check the chain without trusting this
//! server's own verdict.
//!
//! **Recording is best-effort by design.** [`record`] is called *after* the
//! mutation has already committed, so a failed audit write must not fail the
//! request — reporting an error would tell the client its publish failed when
//! it actually succeeded, which is worse than a gap in the log (it provokes
//! retries against an immutable version). Failures are logged at `warn` with
//! everything needed to reconstruct the entry by hand.

use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend,
    DbErr, EntityTrait, QueryFilter, QueryOrder, SqlErr, Statement, TransactionTrait,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zed_interfaces::registry::{AuditAction, AuditChainInput, audit_chain_preimage};

use crate::entities::{audit_log, token};

/// The role string recorded for an unscoped (admin) token, which has no org
/// role of its own but is owner-equivalent everywhere.
pub const ADMIN_ROLE: &str = "admin";

/// How many times an append retries when a concurrent writer takes the `seq`
/// it planned to use. Bounded so a pathological contention storm cannot spin.
const APPEND_ATTEMPTS: usize = 4;

/// The role label to record for `token`.
pub fn actor_role(token: &token::Model) -> &str {
    if token.org_id.is_none() {
        ADMIN_ROLE
    } else {
        &token.role
    }
}

/// Hash an entry's canonical preimage. Lowercase hex, matching what any client
/// computes from [`audit_chain_preimage`].
pub fn entry_digest(input: &AuditChainInput<'_>) -> String {
    format!(
        "{:x}",
        Sha256::digest(audit_chain_preimage(input).as_bytes())
    )
}

/// The timestamp as it will be hashed *and* stored.
///
/// The digest covers the RFC 3339 rendering, but the value also round-trips
/// through the database, and Postgres `timestamptz` keeps only microseconds.
/// Truncating here means the string that was hashed is exactly the string a
/// later read reproduces — otherwise every honest entry would fail
/// verification because the stored time lost nanoseconds.
fn chain_timestamp() -> chrono::DateTime<chrono::Utc> {
    let now = chrono::Utc::now();
    now.with_nanosecond(now.timestamp_subsec_micros() * 1_000)
        .unwrap_or(now)
}

use chrono::Timelike;

/// Append one audit record. Never returns an error: see the module note on why
/// a failed write must not fail the surrounding request.
pub async fn record(
    db: &DatabaseConnection,
    org_id: Uuid,
    token: &token::Model,
    action: AuditAction,
    subject: impl Into<String>,
    detail: Option<String>,
) {
    let subject = subject.into();
    let mut last_error: Option<DbErr> = None;
    for _ in 0..APPEND_ATTEMPTS {
        match append_chained(db, org_id, token, action, &subject, detail.as_deref()).await {
            Ok(()) => return,
            // Another writer claimed this position between our read of the tip
            // and the insert. The unique (org_id, seq) index is what makes
            // that a clean loss instead of a silent fork, so re-read and retry.
            Err(error) if is_position_taken(&error) => {
                last_error = Some(error);
                continue;
            }
            Err(error) => {
                last_error = Some(error);
                break;
            }
        }
    }
    if let Some(error) = last_error {
        // Loud, and complete enough to reconstruct the row by hand.
        tracing::warn!(
            %error,
            action = action.as_str(),
            subject = %subject,
            actor_token = %token.name,
            detail = ?detail,
            "failed to append audit record; the mutation itself succeeded"
        );
    }
}

fn is_position_taken(error: &DbErr) -> bool {
    matches!(error.sql_err(), Some(SqlErr::UniqueConstraintViolation(_)))
}

/// One attempt: take the org's append lock, read the chain tip, and insert the
/// next link in the same transaction.
async fn append_chained(
    db: &DatabaseConnection,
    org_id: Uuid,
    token: &token::Model,
    action: AuditAction,
    subject: &str,
    detail: Option<&str>,
) -> Result<(), DbErr> {
    let txn = db.begin().await?;
    // Serialize appends for this org across replicas. Xact-scoped, so it is
    // released on commit, rollback, or crash. Postgres only; the SQLite used
    // in tests is single-connection and needs none. The unique (org_id, seq)
    // index remains the correctness backstop if this is ever unavailable.
    if db.get_database_backend() == DbBackend::Postgres {
        txn.execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT pg_advisory_xact_lock(hashtext($1))",
            [format!("zed-api:audit:{org_id}").into()],
        ))
        .await?;
    }

    let tip = audit_log::Entity::find()
        .filter(audit_log::Column::OrgId.eq(org_id))
        .order_by_desc(audit_log::Column::Seq)
        .one(&txn)
        .await?;
    let seq = tip.as_ref().map(|t| t.seq).unwrap_or(0) + 1;
    // The first entry has no predecessor; legacy rows carry an empty hash, and
    // an empty prev is exactly how the chain records "nothing before this".
    let prev_hash = tip
        .as_ref()
        .map(|t| t.entry_hash.clone())
        .filter(|h| !h.is_empty());

    let at = chain_timestamp();
    let at_rfc3339 = at.to_rfc3339();
    let actor_token_id = token.id.to_string();
    let entry_hash = entry_digest(&AuditChainInput {
        org_id: &org_id.to_string(),
        seq: seq as u64,
        at: &at_rfc3339,
        action: action.as_str(),
        subject,
        actor_token_id: Some(&actor_token_id),
        actor_token_name: &token.name,
        actor_role: actor_role(token),
        detail,
        prev_hash: prev_hash.as_deref().unwrap_or(""),
    });

    audit_log::ActiveModel {
        id: ActiveValue::Set(Uuid::new_v4()),
        org_id: ActiveValue::Set(org_id),
        at: ActiveValue::Set(at),
        action: ActiveValue::Set(action.as_str().to_string()),
        subject: ActiveValue::Set(subject.to_string()),
        actor_token_id: ActiveValue::Set(Some(token.id)),
        actor_token_name: ActiveValue::Set(token.name.clone()),
        actor_role: ActiveValue::Set(actor_role(token).to_string()),
        detail: ActiveValue::Set(detail.map(str::to_string)),
        seq: ActiveValue::Set(seq),
        entry_hash: ActiveValue::Set(entry_hash),
        prev_hash: ActiveValue::Set(prev_hash),
    }
    .insert(&txn)
    .await?;
    txn.commit().await
}

/// Recompute the hash a stored row should have, given its predecessor's hash.
/// Shared by the append path and the verifier so they can never disagree.
pub fn expected_hash(row: &audit_log::Model, prev_hash: &str) -> String {
    let actor_token_id = row.actor_token_id.map(|id| id.to_string());
    entry_digest(&AuditChainInput {
        org_id: &row.org_id.to_string(),
        seq: row.seq as u64,
        at: &row.at.to_rfc3339(),
        action: &row.action,
        subject: &row.subject,
        actor_token_id: actor_token_id.as_deref(),
        actor_token_name: &row.actor_token_name,
        actor_role: &row.actor_role,
        detail: row.detail.as_deref(),
        prev_hash,
    })
}

/// Why a chain failed to verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainProblem {
    /// An entry's contents no longer hash to its recorded `entry_hash`.
    HashMismatch,
    /// An entry's `prev_hash` does not match its predecessor's hash.
    BrokenLink,
    /// A `seq` is missing: an entry was deleted.
    SequenceGap,
}

impl ChainProblem {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChainProblem::HashMismatch => "hash_mismatch",
            ChainProblem::BrokenLink => "broken_link",
            ChainProblem::SequenceGap => "sequence_gap",
        }
    }
}

/// The outcome of walking a chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
    pub intact: bool,
    pub entries_checked: u64,
    pub first_bad_seq: Option<i64>,
    pub problem: Option<ChainProblem>,
    pub head_hash: Option<String>,
}

/// Walk `rows` (ascending `seq`) and decide whether the chain is intact.
///
/// Rows written before the chain existed (`seq == 0`, empty hash) are skipped
/// rather than failed: they were never chained, and reporting them as tampering
/// would cry wolf on every upgraded deployment.
pub fn verify_chain(rows: &[audit_log::Model]) -> ChainReport {
    let mut prev_hash = String::new();
    let mut expected_seq: Option<i64> = None;
    let mut checked = 0u64;
    let mut head = None;

    for row in rows
        .iter()
        .filter(|r| r.seq > 0 && !r.entry_hash.is_empty())
    {
        if let Some(want) = expected_seq
            && row.seq != want
        {
            return ChainReport {
                intact: false,
                entries_checked: checked,
                first_bad_seq: Some(want),
                problem: Some(ChainProblem::SequenceGap),
                head_hash: head,
            };
        }
        // An edited row no longer hashes to what was recorded.
        if expected_hash(row, &prev_hash) != row.entry_hash {
            // Distinguish "this row changed" from "its link was rewritten":
            // if the row hashes correctly against its *own* recorded prev, the
            // contents are fine and the linkage is what does not line up.
            let problem =
                if expected_hash(row, row.prev_hash.as_deref().unwrap_or("")) == row.entry_hash {
                    ChainProblem::BrokenLink
                } else {
                    ChainProblem::HashMismatch
                };
            return ChainReport {
                intact: false,
                entries_checked: checked,
                first_bad_seq: Some(row.seq),
                problem: Some(problem),
                head_hash: head,
            };
        }
        prev_hash = row.entry_hash.clone();
        head = Some(row.entry_hash.clone());
        expected_seq = Some(row.seq + 1);
        checked += 1;
    }

    ChainReport {
        intact: true,
        entries_checked: checked,
        first_bad_seq: None,
        problem: None,
        head_hash: head,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn model(org_id: Option<Uuid>, role: &str) -> token::Model {
        token::Model {
            id: Uuid::new_v4(),
            name: "t".to_string(),
            token_hash: "h".to_string(),
            org_id,
            role: role.to_string(),
            created_at: Utc::now(),
            expires_at: None,
            revoked_at: None,
        }
    }

    /// An unscoped token is recorded as `admin`; a scoped one keeps its role.
    #[test]
    fn admin_tokens_are_labelled_admin() {
        assert_eq!(actor_role(&model(None, "owner")), ADMIN_ROLE);
        assert_eq!(
            actor_role(&model(Some(Uuid::new_v4()), "publisher")),
            "publisher"
        );
    }

    /// Build a correctly chained run of rows for chain tests.
    fn chained(org_id: Uuid, count: i64) -> Vec<audit_log::Model> {
        let mut rows: Vec<audit_log::Model> = Vec::new();
        let mut prev = String::new();
        for seq in 1..=count {
            let mut row = audit_log::Model {
                id: Uuid::new_v4(),
                org_id,
                at: chain_timestamp(),
                action: "publish".to_string(),
                subject: format!("acme/pkg@1.0.{seq}"),
                actor_token_id: Some(Uuid::new_v4()),
                actor_token_name: "ci".to_string(),
                actor_role: "publisher".to_string(),
                detail: None,
                seq,
                entry_hash: String::new(),
                prev_hash: (!prev.is_empty()).then(|| prev.clone()),
            };
            row.entry_hash = expected_hash(&row, &prev);
            prev = row.entry_hash.clone();
            rows.push(row);
        }
        rows
    }

    #[test]
    fn an_untouched_chain_verifies() {
        let rows = chained(Uuid::new_v4(), 5);
        let report = verify_chain(&rows);
        assert!(report.intact, "{report:?}");
        assert_eq!(report.entries_checked, 5);
        assert_eq!(
            report.head_hash.as_ref(),
            rows.last().map(|r| &r.entry_hash)
        );
    }

    /// Editing any recorded field must break that entry's hash.
    #[test]
    fn editing_an_entry_is_detected() {
        for (label, mutate) in [
            (
                "subject",
                (|r: &mut audit_log::Model| r.subject = "acme/evil@9.9.9".into())
                    as fn(&mut audit_log::Model),
            ),
            ("action", |r| r.action = "unyank".into()),
            ("actor", |r| r.actor_token_name = "someone-else".into()),
            ("role", |r| r.actor_role = "reader".into()),
            ("detail", |r| r.detail = Some("sha256=deadbeef".into())),
        ] {
            let mut rows = chained(Uuid::new_v4(), 4);
            mutate(&mut rows[1]);
            let report = verify_chain(&rows);
            assert!(!report.intact, "editing {label} went undetected");
            assert_eq!(report.first_bad_seq, Some(2), "{label}");
            assert_eq!(report.problem, Some(ChainProblem::HashMismatch), "{label}");
        }
    }

    /// Deleting an entry leaves a gap that the walk reports at the missing seq.
    #[test]
    fn deleting_an_entry_is_detected() {
        let mut rows = chained(Uuid::new_v4(), 5);
        rows.remove(2); // drop seq 3
        let report = verify_chain(&rows);
        assert!(!report.intact);
        assert_eq!(report.problem, Some(ChainProblem::SequenceGap));
        assert_eq!(report.first_bad_seq, Some(3));
        assert_eq!(
            report.entries_checked, 2,
            "the prefix before the gap is fine"
        );
    }

    /// Truncating the tail cannot be caught by the chain alone — that is what
    /// the externally anchored head hash is for. Assert the honest behavior so
    /// the limitation is explicit rather than assumed away.
    #[test]
    fn truncating_the_tail_still_verifies_but_moves_the_head() {
        let rows = chained(Uuid::new_v4(), 5);
        let full_head = verify_chain(&rows).head_hash;
        let truncated = verify_chain(&rows[..3]);
        assert!(
            truncated.intact,
            "a truncated prefix is internally consistent"
        );
        assert_ne!(
            truncated.head_hash, full_head,
            "the head must move, which is what an external anchor detects"
        );
    }

    /// Rewriting a link (without touching contents) is reported as a broken
    /// link rather than a content edit.
    #[test]
    fn a_rewritten_link_is_reported_as_a_broken_link() {
        let mut rows = chained(Uuid::new_v4(), 4);
        // Re-point entry 3 at a predecessor it never had, keeping its hash
        // self-consistent with that claim.
        let forged_prev = "0".repeat(64);
        rows[2].prev_hash = Some(forged_prev.clone());
        rows[2].entry_hash = expected_hash(&rows[2], &forged_prev);
        let report = verify_chain(&rows);
        assert!(!report.intact);
        assert_eq!(report.first_bad_seq, Some(3));
        assert_eq!(report.problem, Some(ChainProblem::BrokenLink));
    }

    /// Pre-chain rows are skipped, not flagged: an upgraded deployment must not
    /// report tampering for history that was never chained.
    #[test]
    fn legacy_unchained_rows_do_not_report_tampering() {
        let org = Uuid::new_v4();
        let mut rows = vec![audit_log::Model {
            id: Uuid::new_v4(),
            org_id: org,
            at: chain_timestamp(),
            action: "publish".to_string(),
            subject: "acme/old@0.1.0".to_string(),
            actor_token_id: None,
            actor_token_name: "legacy".to_string(),
            actor_role: "owner".to_string(),
            detail: None,
            seq: 0,
            entry_hash: String::new(),
            prev_hash: None,
        }];
        rows.extend(chained(org, 3));
        let report = verify_chain(&rows);
        assert!(report.intact, "{report:?}");
        assert_eq!(report.entries_checked, 3, "only chained rows are counted");
    }

    /// An empty log is intact and has no head.
    #[test]
    fn an_empty_chain_is_intact() {
        let report = verify_chain(&[]);
        assert!(report.intact);
        assert_eq!(report.entries_checked, 0);
        assert_eq!(report.head_hash, None);
    }

    /// The timestamp that gets hashed must survive its own RFC 3339
    /// round-trip, or every honest entry would fail verification.
    #[test]
    fn chain_timestamp_survives_rfc3339_roundtrip() {
        let at = chain_timestamp();
        let parsed = chrono::DateTime::parse_from_rfc3339(&at.to_rfc3339())
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(at, parsed);
        assert_eq!(at.to_rfc3339(), parsed.to_rfc3339());
    }
}
