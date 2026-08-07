# zed-pkg registry schema

Two migration paths describe the same database. **Keep both**; we lean into the
declarative one over time.

## 1. Declarative (going forward) — `schema.sql` + `dpm`

`schema/schema.sql` is the **desired-state** contract, in the pg-defs style
([k8s-libs-and-shared-defs](https://github.com/ORESoftware/k8s-libs-and-shared-defs)).
It is applied with [`dpm`](https://github.com/declarative-migrations/declarative-postgres-migrate.rs),
which introspects the live database and the schema (materialized on a shadow
server), diffs the Postgres catalogs, and emits ordered, reviewable SQL — no
tracked migration files.

```sh
export SHADOW_DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres'  # pgvector image
export TARGET_DATABASE_URL='postgres://zed:zed@localhost:5432/zed'
schema/dpm.sh diff      # review the SQL (never executes)
schema/dpm.sh verify    # shadow-replay convergence proof
schema/dpm.sh apply     # execute after a human review
```

`schema.sql` requires the `vector` (pgvector) and `pg_trgm` extensions; use the
`pgvector/pgvector:pg16` image for the shadow and target.

## 2. Imperative (runs today) — SeaORM `migration/`

The `migration/` crate runs on boot (`AUTO_MIGRATE=true`) and is
backend-aware so the test suite can use in-memory SQLite. It stays the
authoritative applied path until the declarative flow is adopted in the
deployment pipeline.

## What the schema stores (audit + hardening)

- **`package.tags`** — a jsonb array of tag strings; multi-tag lookup via the
  GIN index (`tags @> '["cli"]'`, `tags ?| array['cli','http']`).
- **name/description search** — `pg_trgm` GIN indexes for fast `ILIKE '%q%'`.
- **query-all / recency** — `package_created_at_idx`.
- **`package_embedding`** — one big RAG table, `embedding vector(2050)`; a
  1536- or 836-dim model is zero-padded to 2050 (cosine preserved within a
  model, so search filters by `embedding_model`). ANN index via the
  `halfvec(2050)` cast to clear pgvector's 2000-dim full-precision index cap.

See the header comments in `schema.sql` for the full rationale.
