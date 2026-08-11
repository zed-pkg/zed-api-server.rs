# Immutable registry dependency provenance

The account and registry API is compiled from reviewed, immutable dependency revisions.

| Dependency | Revision | Purpose |
| --- | --- | --- |
| `zed-pkg/zed-lib-core` | `38ef3f50638614a14170d5c677173e040e916a6d` | Canonical SeaORM data-plane owner, dependency-graph persistence, and migration contract |
| `zed-pkg/zed-interfaces` | `15577e17a820c3b2b1a39ee178d4645185309a05` | Shared registry/API and dependency-graph representation contracts |
| `zed-pkg/zed-cli` | `8929a58c6591c7a964d7f91412665d7c8a4afdf3` | Publish/install E2E client fixture |

`Cargo.toml`, `Cargo.lock`, Rust CI, and the container publisher must agree on
the exact `zed-lib-core` and `zed-interfaces` revisions. The container build
also verifies both build arguments against the manifest and lockfile before it
compiles, so an image cannot be published from a different dependency graph.

Long-running replicas run with `AUTO_MIGRATE=false`. Production applies the reviewed migration image once through the Argo CD `PreSync` job, using the same immutable API image digest as the runtime deployment.
