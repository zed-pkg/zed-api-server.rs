# Immutable registry dependency provenance

The account and registry API is compiled from reviewed, immutable dependency revisions.

| Dependency | Revision | Purpose |
| --- | --- | --- |
| `zed-pkg/zed-lib-core` | `c3d486a1519381276fbec02aa25247f542924443` | Canonical SeaORM data-plane owner, dependency-graph persistence, and migration contract |
| `zed-pkg/zed-interfaces` | `7d31f80dd8a310f218931165a3ad636a2f32b932` | Shared registry/API and protected dependency-graph representation contracts |
| `zed-pkg/zed-cli` | `8929a58c6591c7a964d7f91412665d7c8a4afdf3` | Publish/install E2E client fixture |

`Cargo.toml`, `Cargo.lock`, Rust CI, and the container publisher must agree on
the exact `zed-lib-core` and `zed-interfaces` revisions. The container build
also verifies both build arguments against the manifest and lockfile before it
compiles, so an image cannot be published from a different dependency graph.

Long-running replicas run with `AUTO_MIGRATE=false`. Production applies the reviewed migration image once through the Argo CD `PreSync` job, using the same immutable API image digest as the runtime deployment.
