-- Canonical Postgres schema for the zed-pkg registry (desired-state contract).
--
-- This is the DECLARATIVE source of truth, in the pg-defs style
-- (github.com/ORESoftware/k8s-libs-and-shared-defs). Do not apply it directly
-- to a shared database: generate and review a diff with `dpm`
-- (github.com/declarative-migrations/declarative-postgres-migrate.rs) — see
-- schema/README.md and schema/dpm.sh.
--
-- The SeaORM `migration/` crate remains the imperative path that runs today
-- (AUTO_MIGRATE on boot); this file is where we lean into stateless/declarative
-- migration over time. Both describe the same objects. Where the two differ,
-- this file is the intended target and the first `dpm diff` will show the
-- normalizations (e.g. varchar -> text, added CHECK constraints, tags, and the
-- embeddings table) as reviewable, intentional hardening.

create extension if not exists pgcrypto;   -- gen_random_uuid()
create extension if not exists pg_trgm;     -- fast name search (trigram ILIKE)
create extension if not exists vector;      -- pgvector: RAG / embedding search

-- ---------------------------------------------------------------------------
-- org: a claimed namespace.
-- ---------------------------------------------------------------------------
create table if not exists org (
  id               uuid primary key default gen_random_uuid(),
  slug             text not null,
  created_by_token uuid,
  created_at       timestamptz not null default now(),
  constraint org_slug_format_chk
    check (slug ~ '^[a-z0-9][a-z0-9-]*[a-z0-9]$' and octet_length(slug) between 2 and 100)
);

create unique index if not exists org_slug_uq on org (slug);

-- ---------------------------------------------------------------------------
-- token: a bearer credential. token_hash is the sha256 hex of the plaintext.
-- ---------------------------------------------------------------------------
create table if not exists token (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  token_hash text not null,
  org_id     uuid references org(id),
  role       text not null default 'owner',
  expires_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  constraint token_hash_format_chk check (token_hash ~ '^[a-f0-9]{64}$'),
  constraint token_role_chk check (role in ('owner', 'publisher', 'reader')),
  constraint token_name_size_chk check (octet_length(name) between 1 and 200)
);

create unique index if not exists token_hash_uq on token (token_hash);
create index if not exists token_org_idx on token (org_id) where revoked_at is null;

-- ---------------------------------------------------------------------------
-- package: <org>/<name>. Carries free-form `tags` (a jsonb array of strings)
-- for multi-tag lookup, and is the anchor for name search + embeddings.
-- ---------------------------------------------------------------------------
create table if not exists package (
  id             uuid primary key default gen_random_uuid(),
  org_id         uuid not null references org(id),
  name           text not null,
  description    text,
  vcs            text not null,
  repo_url       text not null,
  version_scheme text not null default 'semver',
  -- Multiple tags per package: a jsonb array of short slug strings. jsonb (not
  -- text[]) keeps the column portable to the SQLite test backend and matches
  -- the pg-defs `labels`/`meta` convention; a GIN index makes containment
  -- (`tags @> '["cli"]'`) and overlap (`tags ?| array['cli','http']`) fast.
  tags           jsonb not null default '[]'::jsonb,
  created_at     timestamptz not null default now(),
  constraint package_name_format_chk
    check (name ~ '^[a-z0-9][a-z0-9-]*[a-z0-9]$' and octet_length(name) between 2 and 100),
  constraint package_version_scheme_chk
    check (version_scheme in ('semver', 'calver', 'opaque')),
  constraint package_tags_array_chk check (jsonb_typeof(tags) = 'array'),
  constraint package_tags_size_chk check (jsonb_array_length(tags) <= 64),
  constraint package_description_size_chk
    check (description is null or octet_length(description) <= 4000)
);

-- One package name per org.
create unique index if not exists package_org_name_uq on package (org_id, name);
-- Query-all / recency listing.
create index if not exists package_created_at_idx on package (created_at desc);
-- Search by name: trigram index powers fast `name ILIKE '%q%'`.
create index if not exists package_name_trgm_idx on package using gin (name gin_trgm_ops);
-- Description search (optional, same mechanism).
create index if not exists package_description_trgm_idx
  on package using gin (description gin_trgm_ops);
-- Lookup by tag(s): containment/overlap on the jsonb array.
create index if not exists package_tags_gin_idx on package using gin (tags jsonb_path_ops);

-- ---------------------------------------------------------------------------
-- version: an immutable published artifact of a package.
-- ---------------------------------------------------------------------------
create table if not exists version (
  id           uuid primary key default gen_random_uuid(),
  package_id   uuid not null references package(id),
  version      text not null,
  sha256       text not null,
  size         bigint not null,
  format       text not null,
  vcs_tag      text not null,
  vcs_commit   text,
  artifact_key text not null,
  yanked       boolean not null default false,
  published_at timestamptz not null default now(),
  constraint version_sha256_chk check (sha256 ~ '^[a-f0-9]{64}$'),
  constraint version_size_chk check (size >= 0),
  constraint version_format_chk check (format in ('tar.gz', 'zip'))
);

create unique index if not exists version_package_version_uq on version (package_id, version);
create index if not exists version_sha256_idx on version (sha256);
-- Latest non-yanked version per package.
create index if not exists version_package_published_idx
  on version (package_id, published_at desc) where yanked = false;

-- ---------------------------------------------------------------------------
-- package_embedding: one big embeddings table for RAG search.
--
-- The embedding column is a fixed `vector(2050)` (pgvector). Models of
-- different native widths all fit: a 1536-dim (e.g. OpenAI text-embedding-3-
-- small) or 836-dim vector is zero-padded to 2050. Zero-padding preserves
-- cosine similarity *within one model* (the extra zeros add nothing to the dot
-- product and leave the L2 norm unchanged), so searches MUST filter by
-- `embedding_model` to only compare vectors from the same space —
-- `native_dimensions` records the real width for validation/debugging.
--
-- Index note: pgvector's ivfflat/hnsw cap at 2000 dims for full-precision
-- `vector`, but hnsw on `halfvec` allows up to 4000 — so the ANN index is
-- built on a `halfvec(2050)` cast (requires pgvector >= 0.7). Queries cast the
-- probe the same way: `embedding::halfvec(2050) <=> $probe::halfvec(2050)`.
-- (pg-defs' agent_context_embeddings stores embeddings as jsonb; here we use
-- pgvector so similarity search runs in the database.)
-- ---------------------------------------------------------------------------
create table if not exists package_embedding (
  id                 uuid primary key default gen_random_uuid(),
  package_id         uuid not null references package(id) on delete cascade,
  embedding_model    text not null,
  native_dimensions  integer not null,
  embedding          vector(2050) not null,
  content            text not null,
  content_sha256     text not null,
  created_at         timestamptz not null default now(),
  constraint package_embedding_model_format_chk
    check (embedding_model ~ '^[A-Za-z0-9._:/-]{1,120}$'),
  constraint package_embedding_dimensions_chk
    check (native_dimensions between 1 and 2050),
  constraint package_embedding_content_sha_chk
    check (content_sha256 ~ '^[a-f0-9]{64}$')
);

-- One current embedding per (package, model): re-embedding upserts in place.
create unique index if not exists package_embedding_pkg_model_uq
  on package_embedding (package_id, embedding_model);
-- Searches filter by model, then rank by cosine distance.
create index if not exists package_embedding_model_idx on package_embedding (embedding_model);
-- ANN index via the halfvec cast (see note above). Cosine ops match the
-- `<=>` operator used by semantic search.
create index if not exists package_embedding_hnsw_idx
  on package_embedding using hnsw ((embedding::halfvec(2050)) halfvec_cosine_ops);

-- ---------------------------------------------------------------------------
-- audit_log: append-only trail of published-state mutations (governance).
-- ---------------------------------------------------------------------------
create table if not exists audit_log (
  id               uuid primary key default gen_random_uuid(),
  org_id           uuid not null references org(id),
  at               timestamptz not null default now(),
  action           text not null,
  subject          text not null,
  actor_token_id   uuid,   -- intentionally not an FK: the trail outlives the token
  actor_token_name text not null,
  actor_role       text not null,
  detail           text
);

create index if not exists audit_log_org_at_idx on audit_log (org_id, at desc);
