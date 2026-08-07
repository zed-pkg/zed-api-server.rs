// Executable model of the package-version publication boundary.
//
// Two authorized requests race to publish one immutable package/version. The
// second request may carry the same content digest (an idempotent retry) or a
// different digest (a conflicting publisher). Blob uploads happen before the
// metadata transaction, and crashes or transaction failures may leave
// unreferenced content-addressed blobs behind.
//
// The deliberately conservative rule is that a failed request does not delete
// a just-uploaded blob synchronously. Without a cross-process upload lease, a
// request cannot distinguish its own orphan from a key that another request is
// still preparing to commit. Age/lease-aware garbage collection is outside this
// model.
module package_publication {
  type AttemptPhase = Idle | Uploaded | Finished

  pure val NONE = 0
  pure val DIGEST_A = 1
  pure val DIGESTS = Set(1, 2)

  type State = {
    attempt_a: AttemptPhase,
    attempt_b: AttemptPhase,
    digest_b: int,
    blobs: Set[int],
    committed_digest: int,
    advertised_digest: int,
    metadata_digest: int,
    commit_count: int,
    unauthorized_effects: int,
    saw_crash_after_upload: bool,
    saw_conflict: bool,
    saw_abort_after_upload: bool,
    saw_unauthorized_rejection: bool,
  }

  var s: State

  // The second request nondeterministically chooses the same digest as the
  // first request or a conflicting digest. This covers both replay and racing
  // publisher behavior in one finite model.
  action init = {
    nondet digest = DIGESTS.oneOf()
    s' = {
      attempt_a: Idle,
      attempt_b: Idle,
      digest_b: digest,
      blobs: Set(),
      committed_digest: NONE,
      advertised_digest: NONE,
      metadata_digest: NONE,
      commit_count: 0,
      unauthorized_effects: 0,
      saw_crash_after_upload: false,
      saw_conflict: false,
      saw_abort_after_upload: false,
      saw_unauthorized_rejection: false,
    }
  }

  action upload_a = all {
    s.attempt_a == Idle,
    s' = {
      ...s,
      attempt_a: Uploaded,
      blobs: s.blobs.union(Set(DIGEST_A)),
    },
  }

  action upload_b = all {
    s.attempt_b == Idle,
    s' = {
      ...s,
      attempt_b: Uploaded,
      blobs: s.blobs.union(Set(s.digest_b)),
    },
  }

  // The unique package/version row and its package metadata become visible in
  // one transaction. Advertisement is represented by the same committed
  // digest; there is no intermediate "complete" state.
  action finalize_a = all {
    s.attempt_a == Uploaded,
    s.committed_digest == NONE,
    s.blobs.contains(DIGEST_A),
    s' = {
      ...s,
      attempt_a: Finished,
      committed_digest: DIGEST_A,
      advertised_digest: DIGEST_A,
      metadata_digest: DIGEST_A,
      commit_count: s.commit_count + 1,
    },
  }

  action finalize_b = all {
    s.attempt_b == Uploaded,
    s.committed_digest == NONE,
    s.blobs.contains(s.digest_b),
    s' = {
      ...s,
      attempt_b: Finished,
      committed_digest: s.digest_b,
      advertised_digest: s.digest_b,
      metadata_digest: s.digest_b,
      commit_count: s.commit_count + 1,
    },
  }

  // A duplicate or competing finalizer loses the unique-row race. It cannot
  // rewrite package metadata or the immutable version identity.
  action conflict_a = all {
    s.attempt_a == Uploaded,
    s.committed_digest != NONE,
    s' = {
      ...s,
      attempt_a: Finished,
      saw_conflict: true,
    },
  }

  action conflict_b = all {
    s.attempt_b == Uploaded,
    s.committed_digest != NONE,
    s' = {
      ...s,
      attempt_b: Finished,
      saw_conflict: true,
    },
  }

  // A process or transaction may fail after content-addressed upload. The blob
  // remains available because immediate deletion is unsafe without a shared
  // in-flight lease.
  action crash_a = all {
    s.attempt_a == Uploaded,
    s' = {
      ...s,
      attempt_a: Finished,
      saw_crash_after_upload: true,
    },
  }

  action abort_b = all {
    s.attempt_b == Uploaded,
    s' = {
      ...s,
      attempt_b: Finished,
      saw_abort_after_upload: true,
    },
  }

  // Authorization is checked before buffering or storing the artifact. The
  // only observable effect is the reachability witness.
  action reject_unauthorized = {
    s' = {
      ...s,
      saw_unauthorized_rejection: true,
    }
  }

  action idle = s' = s

  action step = any {
    upload_a,
    upload_b,
    finalize_a,
    finalize_b,
    conflict_a,
    conflict_b,
    crash_a,
    abort_b,
    reject_unauthorized,
    idle,
  }

  val digest_bounds = and {
    DIGESTS.contains(s.digest_b),
    or {
      s.committed_digest == NONE,
      DIGESTS.contains(s.committed_digest),
    },
    s.blobs.forall(digest => DIGESTS.contains(digest)),
  }

  // At most one transaction can win the package/version unique row.
  val single_winner = or {
    and {
      s.commit_count == 0,
      s.committed_digest == NONE,
    },
    and {
      s.commit_count == 1,
      DIGESTS.contains(s.committed_digest),
    },
  }

  // Readers never observe a release as complete before its immutable version
  // row and associated package metadata commit together.
  val no_partial_advertisement =
    s.advertised_digest == s.committed_digest

  val metadata_matches_immutable_version =
    s.metadata_digest == s.committed_digest

  // This is the safety property that rules out immediate cleanup racing with a
  // second request: every committed digest remains present in blob storage.
  val committed_artifact_is_available = or {
    s.committed_digest == NONE,
    s.blobs.contains(s.committed_digest),
  }

  val authorization_fails_closed = s.unauthorized_effects == 0

  val publication_safety = and {
    digest_bounds,
    single_winner,
    no_partial_advertisement,
    metadata_matches_immutable_version,
    committed_artifact_is_available,
    authorization_fails_closed,
  }

  // Reachability witnesses keep the important fault and race paths from
  // becoming vacuous as this model changes.
  val crash_after_upload_reached = s.saw_crash_after_upload
  val competing_publish_reached = s.saw_conflict
  val abort_after_upload_reached = s.saw_abort_after_upload
  val unauthorized_rejection_reached = s.saw_unauthorized_rejection
  val same_digest_race_reached = and {
    s.digest_b == DIGEST_A,
    s.blobs.contains(DIGEST_A),
    or {
      s.attempt_a == Uploaded,
      s.attempt_b == Uploaded,
    },
  }
}
