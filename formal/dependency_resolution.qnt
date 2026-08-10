// Finite model of deterministic Zed dependency resolution and lockfile safety.
//
// Package A is the root dependency and package B is transitive. Each package has
// two totally ordered immutable versions. A@2 requires B@2; A@1 accepts B@1 or
// B@2. Publication, yank/restore, mirror visibility, cycle detection, resolution,
// and idempotent replay are modeled before one immutable lock result is emitted.
module dependency_resolution {
  pure val NONE = 0
  pure val UNRESOLVED = 0
  pure val LOCKED = 1
  pure val FAILED = 2
  pure val VERSIONS = Set(1, 2)

  type State = {
    published_a: Set[int],
    published_b: Set[int],
    yanked_a: Set[int],
    yanked_b: Set[int],
    mirrored_a: Set[int],
    mirrored_b: Set[int],
    cycle_present: bool,
    status: int,
    locked_a: int,
    locked_b: int,
    saw_highest_solution: bool,
    saw_yank_fallback: bool,
    saw_mirror_lag_failure: bool,
    saw_missing_dependency: bool,
    saw_cycle_failure: bool,
    saw_idempotent_replay: bool,
  }

  var s: State

  pure def highest_visible(published, yanked, mirrored) =
    if (and {
      published.contains(2),
      mirrored.contains(2),
      not(yanked.contains(2)),
    }) 2
    else if (and {
      published.contains(1),
      mirrored.contains(1),
      not(yanked.contains(1)),
    }) 1
    else NONE

  pure def expected_a(st) =
    highest_visible(st.published_a, st.yanked_a, st.mirrored_a)

  pure def expected_b(st) =
    if (expected_a(st) == 2)
      if (and {
        st.published_b.contains(2),
        st.mirrored_b.contains(2),
        not(st.yanked_b.contains(2)),
      }) 2 else NONE
    else if (expected_a(st) == 1)
      highest_visible(st.published_b, st.yanked_b, st.mirrored_b)
    else NONE

  pure def can_resolve(st) = and {
    not(st.cycle_present),
    expected_a(st) != NONE,
    expected_b(st) != NONE,
  }

  action init = {
    s' = {
      published_a: Set(),
      published_b: Set(),
      yanked_a: Set(),
      yanked_b: Set(),
      mirrored_a: Set(),
      mirrored_b: Set(),
      cycle_present: false,
      status: UNRESOLVED,
      locked_a: NONE,
      locked_b: NONE,
      saw_highest_solution: false,
      saw_yank_fallback: false,
      saw_mirror_lag_failure: false,
      saw_missing_dependency: false,
      saw_cycle_failure: false,
      saw_idempotent_replay: false,
    }
  }

  action publish_a(version) = all {
    s.status == UNRESOLVED,
    VERSIONS.contains(version),
    not(s.published_a.contains(version)),
    s' = { ...s, published_a: s.published_a.union(Set(version)) },
  }

  action publish_b(version) = all {
    s.status == UNRESOLVED,
    VERSIONS.contains(version),
    not(s.published_b.contains(version)),
    s' = { ...s, published_b: s.published_b.union(Set(version)) },
  }

  action sync_a(version) = all {
    s.status == UNRESOLVED,
    s.published_a.contains(version),
    not(s.mirrored_a.contains(version)),
    s' = { ...s, mirrored_a: s.mirrored_a.union(Set(version)) },
  }

  action sync_b(version) = all {
    s.status == UNRESOLVED,
    s.published_b.contains(version),
    not(s.mirrored_b.contains(version)),
    s' = { ...s, mirrored_b: s.mirrored_b.union(Set(version)) },
  }

  action yank_a(version) = all {
    s.status == UNRESOLVED,
    s.published_a.contains(version),
    not(s.yanked_a.contains(version)),
    s' = { ...s, yanked_a: s.yanked_a.union(Set(version)) },
  }

  action yank_b(version) = all {
    s.status == UNRESOLVED,
    s.published_b.contains(version),
    not(s.yanked_b.contains(version)),
    s' = { ...s, yanked_b: s.yanked_b.union(Set(version)) },
  }

  action restore_a(version) = all {
    s.status == UNRESOLVED,
    s.yanked_a.contains(version),
    s' = { ...s, yanked_a: s.yanked_a.exclude(Set(version)) },
  }

  action restore_b(version) = all {
    s.status == UNRESOLVED,
    s.yanked_b.contains(version),
    s' = { ...s, yanked_b: s.yanked_b.exclude(Set(version)) },
  }

  action introduce_cycle = all {
    s.status == UNRESOLVED,
    not(s.cycle_present),
    s' = { ...s, cycle_present: true },
  }

  action resolve = all {
    s.status == UNRESOLVED,
    s' = if (can_resolve(s)) {
      ...s,
      status: LOCKED,
      locked_a: expected_a(s),
      locked_b: expected_b(s),
      saw_highest_solution:
        s.saw_highest_solution or and { expected_a(s) == 2, expected_b(s) == 2 },
      saw_yank_fallback:
        s.saw_yank_fallback or and {
          s.published_a.contains(2),
          s.yanked_a.contains(2),
          expected_a(s) == 1,
        },
    } else {
      ...s,
      status: FAILED,
      locked_a: NONE,
      locked_b: NONE,
      saw_mirror_lag_failure:
        s.saw_mirror_lag_failure or or {
          not(s.published_a.subseteq(s.mirrored_a)),
          not(s.published_b.subseteq(s.mirrored_b)),
        },
      saw_missing_dependency:
        s.saw_missing_dependency or and {
          not(s.cycle_present),
          expected_a(s) != NONE,
          expected_b(s) == NONE,
        },
      saw_cycle_failure: s.saw_cycle_failure or s.cycle_present,
    },
  }

  // A frozen resolver may be asked to replay the same already-decided request.
  // The immutable lock result or structured failure must not change.
  action replay_resolve = all {
    s.status != UNRESOLVED,
    s' = { ...s, saw_idempotent_replay: true },
  }

  action idle = s' = s

  action step = {
    nondet version = VERSIONS.oneOf()
    any {
      publish_a(version),
      publish_b(version),
      sync_a(version),
      sync_b(version),
      yank_a(version),
      yank_b(version),
      restore_a(version),
      restore_b(version),
      introduce_cycle,
      resolve,
      replay_resolve,
      idle,
    }
  }

  val registry_sets_are_well_formed = and {
    s.published_a.subseteq(VERSIONS),
    s.published_b.subseteq(VERSIONS),
    s.yanked_a.subseteq(s.published_a),
    s.yanked_b.subseteq(s.published_b),
    s.mirrored_a.subseteq(s.published_a),
    s.mirrored_b.subseteq(s.published_b),
  }

  val result_shape_is_total = or {
    and {
      s.status == UNRESOLVED,
      s.locked_a == NONE,
      s.locked_b == NONE,
    },
    and {
      s.status == FAILED,
      s.locked_a == NONE,
      s.locked_b == NONE,
    },
    and {
      s.status == LOCKED,
      VERSIONS.contains(s.locked_a),
      VERSIONS.contains(s.locked_b),
    },
  }

  val locked_versions_are_visible = or {
    s.status != LOCKED,
    and {
      s.published_a.contains(s.locked_a),
      s.mirrored_a.contains(s.locked_a),
      not(s.yanked_a.contains(s.locked_a)),
      s.published_b.contains(s.locked_b),
      s.mirrored_b.contains(s.locked_b),
      not(s.yanked_b.contains(s.locked_b)),
    },
  }

  val transitive_requirement_is_closed = or {
    s.status != LOCKED,
    s.locked_b >= s.locked_a,
  }

  val cycles_fail_closed = not(and {
    s.cycle_present,
    s.status == LOCKED,
  })

  val resolution_is_deterministic = or {
    s.status == UNRESOLVED,
    and {
      s.status == LOCKED,
      can_resolve(s),
      s.locked_a == expected_a(s),
      s.locked_b == expected_b(s),
    },
    and {
      s.status == FAILED,
      not(can_resolve(s)),
    },
  }

  val resolution_safety = and {
    registry_sets_are_well_formed,
    result_shape_is_total,
    locked_versions_are_visible,
    transitive_requirement_is_closed,
    cycles_fail_closed,
    resolution_is_deterministic,
  }

  val highest_solution_reached = s.saw_highest_solution
  val yank_fallback_reached = s.saw_yank_fallback
  val mirror_lag_failure_reached = s.saw_mirror_lag_failure
  val missing_dependency_reached = s.saw_missing_dependency
  val cycle_failure_reached = s.saw_cycle_failure
  val idempotent_replay_reached = s.saw_idempotent_replay
}
