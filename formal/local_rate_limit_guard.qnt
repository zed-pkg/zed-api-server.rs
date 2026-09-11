// Bounded abstraction of the transitional process-local rate-limit adapter.
//
// This model does not claim floating-point arithmetic refinement. It covers the
// adapter safety obligations around the current implementation while the strict
// Redis authority remains blocked on public/private package provenance:
// - time never rewinds accepted state;
// - partially refilled spent capacity is never evicted;
// - tracked identity cardinality never exceeds its hard bound;
// - a new identity at the bound is denied without evicting unsafe state.
module local_rate_limit_guard {
  pure val CAPACITY = 2
  pure val REFILL_INTERVAL = 4
  pure val EVICTION_TICKS = 3
  pure val MAX_BUCKETS = 2
  pure val MAX_TIME = 10
  pure val TIMES = Set(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10)

  type State = {
    present: bool,
    tokens: int,
    last_seen: int,
    clock: int,
    tracked: int,
    saw_denial: bool,
    saw_partial_retained: bool,
    saw_eviction: bool,
    saw_late_request: bool,
    saw_capacity_denial: bool,
    evicted_partial: bool,
  }

  var s: State

  pure def balance_at(st, time) =
    if (not(st.present)) CAPACITY
    else if (st.tokens + (time - st.last_seen) / REFILL_INTERVAL > CAPACITY)
      CAPACITY
    else st.tokens + (time - st.last_seen) / REFILL_INTERVAL

  action init = {
    s' = {
      present: false,
      tokens: 0,
      last_seen: 0,
      clock: 0,
      tracked: 0,
      saw_denial: false,
      saw_partial_retained: false,
      saw_eviction: false,
      saw_late_request: false,
      saw_capacity_denial: false,
      evicted_partial: false,
    }
  }

  // A request for the representative identity. New identity allocation is
  // permitted only while cardinality is below the configured bound.
  action request(time) = all {
    TIMES.contains(time),
    time >= s.clock,
    or { s.present, s.tracked < MAX_BUCKETS },
    s' = {
      ...s,
      present: true,
      tracked: if (s.present) s.tracked else s.tracked + 1,
      tokens: if (balance_at(s, time) > 0) balance_at(s, time) - 1 else 0,
      last_seen: time,
      clock: time,
      saw_denial: s.saw_denial or balance_at(s, time) == 0,
    },
  }

  // A new identity presented while every slot is occupied fails closed. It
  // cannot mutate the representative bucket or increase cardinality.
  action capacity_denial(time) = all {
    TIMES.contains(time),
    time >= s.clock,
    not(s.present),
    s.tracked == MAX_BUCKETS,
    s' = {
      ...s,
      clock: time,
      saw_capacity_denial: true,
    },
  }

  // Abstract other identities occupying slots. This lets the finite model
  // reach the admission ceiling without inventing details about their keys.
  action allocate_other(time) = all {
    TIMES.contains(time),
    time >= s.clock,
    s.tracked < MAX_BUCKETS,
    s' = {
      ...s,
      tracked: s.tracked + 1,
      clock: time,
    },
  }

  action advance(time) = all {
    TIMES.contains(time),
    time >= s.clock,
    s' = { ...s, clock: time },
  }

  action sweep(time) = all {
    TIMES.contains(time),
    time >= s.clock,
    s' = if (and {
      s.present,
      time - s.last_seen >= EVICTION_TICKS,
      balance_at(s, time) == CAPACITY,
    }) {
      ...s,
      present: false,
      tokens: 0,
      tracked: s.tracked - 1,
      clock: time,
      saw_eviction: true,
      evicted_partial: s.evicted_partial or balance_at(s, time) < CAPACITY,
    } else {
      ...s,
      clock: time,
      saw_partial_retained:
        s.saw_partial_retained or and {
          s.present,
          time - s.last_seen >= EVICTION_TICKS,
          balance_at(s, time) < CAPACITY,
        },
    },
  }

  // A stale timestamp is observed and rejected without changing limiter state.
  action late_request(time) = all {
    TIMES.contains(time),
    time < s.clock,
    s' = { ...s, saw_late_request: true },
  }

  action idle = s' = s

  action step = {
    nondet time = TIMES.oneOf()
    any {
      request(time),
      capacity_denial(time),
      allocate_other(time),
      advance(time),
      sweep(time),
      late_request(time),
      idle,
    }
  }

  val state_is_bounded = and {
    s.tokens >= 0,
    s.tokens <= CAPACITY,
    s.tracked >= 0,
    s.tracked <= MAX_BUCKETS,
    implies(s.present, s.tracked >= 1),
    s.clock >= 0,
    s.clock <= MAX_TIME,
  }

  val no_partial_eviction = not(s.evicted_partial)
  val adapter_safety = and { state_is_bounded, no_partial_eviction }

  val denial_reached = s.saw_denial
  val slow_refill_retained_reached = s.saw_partial_retained
  val full_idle_eviction_reached = s.saw_eviction
  val late_request_reached = s.saw_late_request
  val capacity_denial_reached = s.saw_capacity_denial
}
