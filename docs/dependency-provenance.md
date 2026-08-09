# Immutable registry dependency provenance

The account and registry API is compiled from reviewed, immutable dependency revisions.

| Dependency | Revision | Purpose |
| --- | --- | --- |
| `zed-pkg/zed-lib` (`zed-orm`) | `3f96becea62efb452d1630e7e67711404e8131f2` | Transitional compatibility facade carrying the accepted account-console, legacy org-name, artifact, search, and visibility migration batch |
| `zed-pkg/zed-lib-core` | `d9a1f72baad87a0bbe256ad892d61d7a4fdd9135` | Canonical long-term SeaORM data-plane owner and migration contract |
| `zed-pkg/zed-interfaces` | `f141e4cfae31a74c679b46d1d4bb0146b20555f6` | Shared registry/API contract types |
| `zed-pkg/zed-cli` | `8929a58c6591c7a964d7f91412665d7c8a4afdf3` | Publish/install E2E client fixture |

`Cargo.toml` and `Cargo.lock` must agree on the exact `zed-lib` revision. That revision supplies the database trigger/default compatibility needed for historical machine clients that create an organization with only its slug, while the account console requires a non-null display name.

The compatibility facade is bounded: no new application behavior should be added there. New persistent operations belong in `zed-lib-core`; the API will move route families to `zed-orm-core` incrementally while preserving the stable `/api/v1` and machine-registry compatibility contracts.

Long-running replicas run with `AUTO_MIGRATE=false`. Production applies the reviewed migration image once through the Argo CD `PreSync` job, using the same immutable API image digest as the runtime deployment.
