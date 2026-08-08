# Database ownership and migration boundary

Tracking: [DEN-2788](https://linear.app/denman/issue/DEN-2788/zed-pkg-shared-seaorm-boundary-orm-crate-in-zed-lib-zed-api-serverzed)

Canonical ORM owner: [`zed-pkg/zed-orm-core`](https://github.com/zed-pkg/zed-orm-core), currently under review in [PR #1](https://github.com/zed-pkg/zed-orm-core/pull/1).

`zed-api-server` is the sole request-serving writer for registry business data. The browser-facing `zed-web-server` may read approved data but must never acquire this service's write credential or run mutations against the shared schema.

## Runtime roles

| Identity | Rights | Purpose |
| --- | --- | --- |
| `zed_pkg__api_rw` | required `SELECT`/`INSERT`/`UPDATE`/`DELETE`; no DDL | this API process |
| `zed_pkg__web_ro` | explicit `SELECT` allowlist only | web-server named reads |
| `zed_pkg__migrator` | reviewed project-scoped DDL | discrete release migration job |

Role names are illustrative until the centralized slug map is finalized, but the organization/project prefix and three-way privilege split are mandatory.

## Shared ORM package

The root `.zpkg.toml` imports `zed-pkg/zed-orm-core`. The canonical crate must provide:

- an opaque read/write context for this API, available only with the explicit `read-write` feature;
- an opaque default read context for the web tier;
- role-aware connection setup, pinned `zed_pkg` schema search paths, and a startup read-only assertion for web consumers;
- named policy-aware read and write operations without publicly re-exporting raw SeaORM connections, entity managers, or query builders;
- entities generated from the Zed slice of `ORESoftware/k8s-libs-and-shared-defs` rather than an independently authored schema.

After `zed-orm-core` PR #1 is completed and merged, the intended API dependency is:

```toml
zed-orm-core = {
  git = "https://github.com/zed-pkg/zed-orm-core.git",
  rev = "6ed5fc430c4769cee1d4dddf297f7cb1cd63575d",
  default-features = false,
  features = ["read-write"]
}
```

```rust
use zed_orm_core::{WriteContext, connect_read_write};

let registry_db: WriteContext = connect_read_write(&database_url).await?;
```

The revision above is the current head of the canonical scaffold PR, not yet a production-ready consumer pin. Before enabling it, that PR must pin shared definitions, implement opaque contexts and role-aware connections, add working named queries, compile every write type/function only under `read-write`, and provide compile-fail consumer fixtures plus live PostgreSQL/CockroachDB permission evidence. Replace the scaffold revision with the merge commit after those gates pass.

The earlier `zed-lib` ORM branch is an implementation donor only; it must not remain as a second authoritative package. This rollout deliberately does not add an unlocked Cargo git dependency: CI uses `--locked`, and a manifest-only change would make otherwise unrelated builds non-reproducible. The zed dependency records the canonical repository relationship now.

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
