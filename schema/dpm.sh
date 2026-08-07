#!/usr/bin/env bash
# Declarative Postgres migration for the zed-pkg registry, via dpm
# (github.com/declarative-migrations/declarative-postgres-migrate.rs).
#
# schema/schema.sql is the source of truth; the target database converges onto
# it. dpm materializes schema.sql on a shadow server, introspects both sides
# from pg_catalog, and emits ordered, reviewable SQL. This is the
# stateless/declarative path we lean into over time; the SeaORM `migration/`
# crate remains the imperative path that runs on boot.
#
# Usage:
#   schema/dpm.sh diff        # print the migration SQL (default; never executes)
#   schema/dpm.sh verify      # rehearse on a shadow replica, prove convergence
#   schema/dpm.sh review      # diff + AI review of the migration
#   schema/dpm.sh apply       # generate + execute (interactive confirm)
#   schema/dpm.sh bootstrap   # full DDL for an empty database
# Extra args pass through to dpm (e.g. --fail-on-diff, --out FILE). See `dpm help`.
#
# Env:
#   TARGET_DATABASE_URL   database to converge; falls back (in order) to
#                         RDS_DATABASE_URL, DATABASE_URL, PG_DATABASE_URL.
#   SHADOW_DATABASE_URL   a server where dpm may CREATE/DROP throwaway databases
#                         (schema.sql is materialized there). Never production.
#
# NOTE: schema.sql requires the `vector` (pgvector) and `pg_trgm` extensions.
# The shadow server must have them available (`CREATE EXTENSION` is in the
# schema) — e.g. the `pgvector/pgvector:pg16` image.
#
# Safety: destructive statements are emitted commented-out, and `apply` refuses
# to execute live destructive SQL unless the dpm consent flags
# (--allow-destructive-sql / --allow-destructive-ops) are passed. A human
# reviews the SQL first; never apply automatically.
set -euo pipefail

cmd="${1:-diff}"
[ "$#" -gt 0 ] && shift

schema_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
schema_sql="$schema_dir/schema.sql"

if ! command -v dpm >/dev/null 2>&1; then
  echo "error: dpm not found on PATH." >&2
  echo "install: brew install declarative-migrations/tap/dpm" >&2
  echo "     or: cargo install declarative-postgres-migrate" >&2
  exit 1
fi

case "$cmd" in
  bootstrap)
    exec dpm bootstrap --source "$schema_sql" "$@"
    ;;
  diff | verify | apply | review)
    if [ -z "${SHADOW_DATABASE_URL:-}" ]; then
      echo "error: SHADOW_DATABASE_URL is required — a Postgres (with pgvector)" >&2
      echo "server URL where dpm may create/drop throwaway databases." >&2
      exit 1
    fi
    target="${TARGET_DATABASE_URL:-${RDS_DATABASE_URL:-${DATABASE_URL:-${PG_DATABASE_URL:-}}}}"
    if [ -z "$target" ]; then
      echo "error: no target database URL (set TARGET_DATABASE_URL or DATABASE_URL)." >&2
      exit 1
    fi
    # Pass the credential-bearing target via the environment, not argv.
    export TARGET_DATABASE_URL="$target"
    exec dpm "$cmd" --source "$schema_sql" "$@"
    ;;
  *)
    exec dpm "$cmd" "$@"
    ;;
esac
