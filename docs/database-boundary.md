# Database ownership and migration boundary

Tracking: [DEN-2788](https://linear.app/denman/issue/DEN-2788/zed-pkg-shared-seaorm-boundary-orm-crate-in-zed-lib-zed-api-serverzed)

`zed-api-server` is the sole request-serving writer for registry business data. The browser-facing `zed-web-server` may read approved data but must never acquire this service's write credential or run mutations against the shared schema.

## Runtime roles

| Identity | Rights | Purpose |
| --- | --- | --- |
| `zed_pkg__api_rw` | required `SELECT`/`INSERT`/`UPDATE`/`DELETE`; no DDL | this API process |
| `zed_pkg__web_ro` | explicit `SELECT` allowlist only | web-server named reads |
| `zed_pkg__migrator` | reviewed project-scoped DDL | discrete release migration job |

Role names are illustrative until the centralized slug map is finalized, but the organization/project prefix and three-way privilege split are mandatory.

## Shared ORM package

The root `.zpkg.toml` imports `zed-pkg/zed-lib`. `zed-lib` PR #1 provides `zed-orm`, whose reviewed API is:

- `DbRole::ReadWrite` for this API;
- `DbRole::ReadOnly` plus `assert_read_only` for the web tier;
- `ORG_SCHEMA = "zed_pkg"` and a pinned schema search path;
- named `queries::read` / `queries::write` functions rather than handing callers an unrestricted ORM session.

After `zed-lib` PR #1 merges and this repository can regenerate `Cargo.lock`, the intended Cargo dependency is:

```toml
zed-orm = {
  package = "zed-orm",
  git = "https://github.com/zed-pkg/zed-lib.git",
  rev = "6b7bdcc984a75997d5b72f01a17d9eca507c9a01"
}
```

The revision above is the reviewed head of the library PR. Replace it with the merge commit before enabling the dependency. The connection seam then becomes `zed_orm::connect(&database_url, DbRole::ReadWrite)` and all new shared-schema queries should move behind named functions in `zed-orm`.

This rollout deliberately does not add an unlocked git dependency: CI uses `--locked`, and a manifest-only change would make otherwise unrelated builds non-reproducible.

## Migration policy

Production schema changes use [`dpm`](https://github.com/declarative-migrations/declarative-postgres-migrate.rs) as a discrete release step:

1. generate reviewable SQL with `dpm diff`;
2. prove convergence against a shadow database with `dpm verify`;
3. review engine-specific PostgreSQL/CockroachDB behavior and destructive-operation flags;
4. apply with the migrator credential before rolling the API;
5. retain the source/target catalog, SQL, digest, result, and duration as release evidence.

The normal API deployment must not set `AUTO_MIGRATE=true`. The flag remains only as a transitional escape hatch for the explicitly disposable local Docker Compose stack while the legacy SeaORM migrations are converted into the declarative source. Its default is false, and Kubernetes manifests must omit it.

Destructive changes follow expand → backfill → contract across compatible releases. The API runtime identity has no DDL rights, so an accidental ORM synchronization attempt fails instead of altering production.

## Transport and deployment

The companion web server sends mutations over private-cluster HTTP using keep-alive. Retries are limited to operations with an idempotency contract. Traditional Zed web/API services deploy through `ORESoftware/k8s-cluster`; database credentials and migration execution remain namespaced to the Zed project.
