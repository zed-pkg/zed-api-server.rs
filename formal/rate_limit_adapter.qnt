// Finite refinement model for the Rust rate-limit adapter.
//
// The shared ores-rl-lib-core owns the exact fixed-point transition. This
// model covers the adapter obligations around that transition: monotonic
// observations, no early eviction of a partially refilled bucket, stale
// requests after eviction, and the explicit finite-memory admission bound.
module rate_limit_adapter {
  pure val CAPACITY = 2
  pure val REFILL_INTERVAL = 4
  pure val EVICTION_TICKS = 3
  pure val MAX_TIME = 10
  pure val TIMES = Set(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10)

  type State = {
    present: bool,
    tokens: int,
    last_seen: int,
    clock: int,
    saw_denial: bool,
    saw_partial_retained: bool,
    saw_eviction: bool,
    saw_late_request: bool,
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
      saw_denial: false,
      saw_partial_retained: false,
      saw_eviction: false,
      saw_late_request: false,
      evicted_partial: false,
    }
  }

  action request(time) = all {
    TIMES.contains(time),
    time >= s.clock,
    s' = {
      ...s,
      present: true,
      tokens: if (balance_at(s, time) > 0) balance_at(s, time) - 1 else 0,
      last_seen: time,
      clock: time,
      saw_denial: s.saw_denial or balance_at(s, time) == 0,
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

  // The implementation rejects a timestamp older than the global watermark
  // without allocating a new bucket or restoring a burst.
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
      advance(time),
      sweep(time),
      late_request(time),
      idle,
    }
  }

  val state_is_bounded = and {
    s.tokens >= 0,
    s.tokens <= CAPACITY,
    or {
      s.present,
      s.tokens == 0,
    },
    s.clock >= 0,
    s.clock <= MAX_TIME,
  }

  val no_partial_eviction = not(s.evicted_partial)

  val adapter_safety = and {
    state_is_bounded,
    no_partial_eviction,
  }

  val denial_reached = s.saw_denial
  val slow_refill_reached = s.saw_partial_retained
  val full_idle_eviction_reached = s.saw_eviction
  val late_request_reached = s.saw_late_request
}
