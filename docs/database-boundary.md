# Database ownership and migration boundary

Tracking: [DEN-2788](https://linear.app/denman/issue/DEN-2788/zed-pkg-shared-seaorm-boundary-orm-crate-in-zed-lib-zed-api-serverzed)

Canonical ORM package: `zed-orm-core`, delivered from
[`zed-pkg/zed-lib-core`](https://github.com/zed-pkg/zed-lib-core). That
repository is the consolidated owner of the registry entities, role-aware
contexts, named operations, and migrations formerly split across `zed-lib` and
`zed-orm-core` repositories.

`zed-api-server` is the sole request-serving writer for registry business data. The browser-facing `zed-web-server` may read approved data but must never acquire this service's write credential or run mutations against the shared schema.

## Runtime roles

| Identity | Rights | Purpose |
| --- | --- | --- |
| `zed_pkg__api_rw` | required `SELECT`/`INSERT`/`UPDATE`/`DELETE`; no DDL | this API process |
| `zed_pkg__web_ro` | explicit `SELECT` allowlist only | web-server named reads |
| `zed_pkg__migrator` | reviewed project-scoped DDL | discrete release migration job |

Role names are illustrative until the centralized slug map is finalized, but the organization/project prefix and three-way privilege split are mandatory.

## Shared ORM package

The root `Cargo.toml` pins the `zed-orm-core` package from `zed-lib-core` with
the `read-write` and `migrate` features. The canonical crate provides:

- an opaque read/write context for this API, available only with the explicit `read-write` feature;
- an opaque default read context for the web tier;
- role-aware connection setup, pinned `zed_pkg` schema search paths, and a startup read-only assertion for web consumers;
- named policy-aware read and write operations without publicly re-exporting raw SeaORM connections, entity managers, or query builders;
- entities generated from the Zed slice of `ORESoftware/k8s-libs-and-shared-defs` rather than an independently authored schema.

The reviewed dependency is pinned to an immutable commit:

```toml
zed-orm-core = {
  git = "https://github.com/zed-pkg/zed-lib-core.git",
  rev = "700f1f9578c6633a20693a5b1f52970ab845a740",
  features = ["read-write", "migrate"]
}
```

```rust
use zed_orm_core::{ConnectPolicy, WriteContext};

let policy = ConnectPolicy::default();
let registry_db: WriteContext =
    zed_orm_core::connect_read_write_with_policy(&database_url, policy).await?;
```

The package manifest remains the installable API source envelope. Cargo—not a
second Zed package edge—is the executable authority for the ORM dependency.
Keeping one immutable Cargo pin prevents `zed-lib`, the former standalone
`zed-orm-core` repository, or a manifest-only dependency from becoming a
parallel schema owner.

## Migration policy

Production schema changes run through `zed-api-server migrate` as a discrete
release step. The command first applies the legacy compatibility migrations,
then invokes `zed_orm_core::migrations::migrate` through the canonical write
context and its advisory-lock boundary. The release path must review the
migration inputs, run the command with the dedicated migrator credential, and
retain the exact API and `zed-lib-core` revisions plus the command result as
evidence before rolling request-serving replicas.

The normal API deployment must not set `AUTO_MIGRATE=true`. The flag remains
only as a transitional escape hatch for the explicitly disposable local Docker
Compose stack. Its default is false, and Kubernetes manifests must omit it.

Destructive changes follow expand → backfill → contract across compatible releases. The API runtime identity has no DDL rights, so an accidental ORM synchronization attempt fails instead of altering production.

## Transport and deployment

The companion web server sends mutations over private-cluster HTTP using keep-alive. Retries are limited to operations with an idempotency contract. Traditional Zed web/API services deploy through `ORESoftware/k8s-cluster`; database credentials and migration execution remain namespaced to the Zed project.
