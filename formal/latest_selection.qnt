// Executable model of the registry's advertised latest-version selection.
//
// Integer identities stand for three totally ordered immutable versions. The
// model explores every publication order plus yank, restore, and idempotent
// replay. `advertised_latest` is the value returned by package metadata, list,
// and search endpoints; it must depend only on version order and visibility,
// never on the order in which rows were published.
module latest_selection {
  pure val NONE = 0
  pure val VERSIONS = Set(1, 2, 3)

  type State = {
    published: Set[int],
    yanked: Set[int],
    advertised_latest: int,
    saw_out_of_order_publish: bool,
    saw_yank_latest: bool,
    saw_restore_newer: bool,
    saw_idempotent_replay: bool,
  }

  var s: State

  pure def expected_latest(published, yanked) =
    if (published.contains(3) and not(yanked.contains(3))) 3
    else if (published.contains(2) and not(yanked.contains(2))) 2
    else if (published.contains(1) and not(yanked.contains(1))) 1
    else NONE

  action init = {
    s' = {
      published: Set(),
      yanked: Set(),
      advertised_latest: NONE,
      saw_out_of_order_publish: false,
      saw_yank_latest: false,
      saw_restore_newer: false,
      saw_idempotent_replay: false,
    }
  }

  action publish(version) = all {
    VERSIONS.contains(version),
    not(s.published.contains(version)),
    s' = {
      ...s,
      published: s.published.union(Set(version)),
      advertised_latest:
        expected_latest(s.published.union(Set(version)), s.yanked),
      saw_out_of_order_publish:
        s.saw_out_of_order_publish or s.advertised_latest > version,
    },
  }

  action yank(version) = all {
    s.published.contains(version),
    not(s.yanked.contains(version)),
    s' = {
      ...s,
      yanked: s.yanked.union(Set(version)),
      advertised_latest:
        expected_latest(s.published, s.yanked.union(Set(version))),
      saw_yank_latest:
        s.saw_yank_latest or s.advertised_latest == version,
    },
  }

  action restore(version) = all {
    s.yanked.contains(version),
    s' = {
      ...s,
      yanked: s.yanked.exclude(Set(version)),
      advertised_latest:
        expected_latest(s.published, s.yanked.exclude(Set(version))),
      saw_restore_newer:
        s.saw_restore_newer or version > s.advertised_latest,
    },
  }

  // Repeating PUT-like desired-state mutations is allowed to be a no-op. It
  // must not perturb selection or immutable publication identity.
  action replay_yank(version) = all {
    s.yanked.contains(version),
    s' = {
      ...s,
      saw_idempotent_replay: true,
    },
  }

  action replay_restore(version) = all {
    s.published.contains(version),
    not(s.yanked.contains(version)),
    s' = {
      ...s,
      saw_idempotent_replay: true,
    },
  }

  action idle = s' = s

  action step = {
    nondet version = VERSIONS.oneOf()
    any {
      publish(version),
      yank(version),
      restore(version),
      replay_yank(version),
      replay_restore(version),
      idle,
    }
  }

  val identities_are_bounded = and {
    s.published.subseteq(VERSIONS),
    s.yanked.subseteq(VERSIONS),
    or {
      s.advertised_latest == NONE,
      VERSIONS.contains(s.advertised_latest),
    },
  }

  val only_published_versions_are_yanked = s.yanked.subseteq(s.published)

  val latest_is_deterministic =
    s.advertised_latest == expected_latest(s.published, s.yanked)

  val latest_is_visible = or {
    s.advertised_latest == NONE,
    and {
      s.published.contains(s.advertised_latest),
      not(s.yanked.contains(s.advertised_latest)),
    },
  }

  val no_latest_iff_no_visible_version = or {
    s.advertised_latest != NONE,
    s.published.forall(version => s.yanked.contains(version)),
  }

  val selection_safety = and {
    identities_are_bounded,
    only_published_versions_are_yanked,
    latest_is_deterministic,
    latest_is_visible,
    no_latest_iff_no_visible_version,
  }

  val out_of_order_publish_reached = s.saw_out_of_order_publish
  val yank_latest_reached = s.saw_yank_latest
  val restore_newer_reached = s.saw_restore_newer
  val idempotent_replay_reached = s.saw_idempotent_replay
  val all_yanked_reached = and {
    s.published.size() > 0,
    s.yanked == s.published,
    s.advertised_latest == NONE,
  }
}
