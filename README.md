# zed-api-server

The [zed-pkg](https://zpkg.net) registry REST API, in Rust: package and
version metadata in Postgres through the canonical `zed-orm-core` boundary and
the legacy compatibility migration crate. Production schema changes run only
through the explicit `zed-api-server migrate` release command. Artifact
archives (tar.gz/zip) live in bounded process memory for disposable
certification, local disk for development/self-hosting, or any S3-compatible
object storage—Cloudflare R2 in production and AWS S3 or MinIO as alternatives.
This is the service `zed publish` and `zed install` talk to, and the whole
stack is self-hostable for private registries.

## Endpoints

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/healthz` | liveness + db status |
| GET | `/v1/packages/{org}/{name}` | `PackageMetadata` |
| GET | `/v1/packages/{org}/{name}/versions/{version}` | `VersionMetadata` |
| PUT | `/v1/packages/{org}/{name}/versions/{version}` | publish: multipart `meta` (PublishMeta JSON) + `artifact` (bytes); bearer token; versions are immutable |
| GET | `/v1/artifacts/{sha256}` | 302 presigned URL (s3), streamed bytes (local), or zero-copy response bytes (memory) |
| GET | `/v1/search?q=` | name/description match, cap 50 |
| POST | `/v1/orgs` | claim a namespace; bearer token |
| GET | `/v1/files/{org}/{name}/{version}/{path}` | unpkg-style: serve one file out of an artifact, immutable cache headers |

Errors are JSON `ApiError { code, message }` — codes include `not_found`,
`unauthorized`, `org_not_found`, `org_taken`, `version_exists`,
`sha256_mismatch`, `tag_not_found`, `invalid_manifest`, `invalid_multipart`,
`invalid_binary_artifact`, and `vcs_commit_mismatch`.

Publish pipeline: bearer token -> manifest validation -> URL/manifest
agreement -> server-side sha256 recomputation -> org ownership -> VCS tag
verification (policy below) -> immutability check -> store artifact -> record
version.

Native binary ZIP layout, server verification, R2 race recovery, and the
coordinated multi-platform route/data-model boundary are specified in
[`docs/binary-artifact-publication.md`](docs/binary-artifact-publication.md).

## Configuration (env)

| Var | Default | Notes |
| --- | --- | --- |
| `BIND_ADDR` | `0.0.0.0:8080` | |
| `DATABASE_URL` | required | Postgres runtime credential; DML only in production |
| `AUTO_MIGRATE` | `false` | transitional disposable-local escape hatch only; production/Kubernetes must run the reviewed `zed-api-server migrate` release job |
| `STORAGE_BACKEND` | `local` | `memory`, `local`, or `s3` |
| `STORAGE_MEMORY_MAX_BYTES` | `268435456` | hard total for the process-memory backend; must be greater than zero |
| `STORAGE_LOCAL_DIR` | `.data/artifacts` | local backend |
| `ZED_MAX_BINARY_ARCHIVE_BYTES` | `1073741824` | binary ZIP outer-byte limit; may only lower the v1 ceiling |
| `ZED_MAX_BINARY_EXPANDED_BYTES` | `2147483648` | total expanded-byte limit; may only lower the v1 ceiling |
| `ZED_MAX_BINARY_ENTRIES` | `200000` | entry-count limit; may only lower the v1 ceiling |
| `ZED_MAX_BINARY_COMPRESSION_RATIO` | `1000` | per-entry ratio limit; may only lower the v1 ceiling |
| `S3_BUCKET` | required for s3 | |
| `S3_ENDPOINT_URL` | unset | set for R2/MinIO |
| `S3_REGION` | `auto` | R2 uses `auto` |
| `S3_FORCE_PATH_STYLE` | `true` | MinIO needs it |
| `PUBLIC_BASE_URL` | `http://localhost:8080` | used in download URLs |
| `ZED_REGISTRY_ID` | `registry:zpkg-primary` | stable logical graph identity; set once and do not derive it from an ingress alias |
| `ZED_VERIFY_TAGS` | `off` | `off` or `github` |
| `GITHUB_TOKEN` | unset | raises tag-check rate limits |
| `MAX_ARTIFACT_BYTES` | `104857600` | request body cap |
| `ZED_ARTIFACT_SERVE_MEMORY_BUDGET_BYTES` | `268435456` | memory budget for concurrently buffered artifact/file responses |
| `ZED_GRAPH_SERVE_MEMORY_BUDGET_BYTES` | `268435456` | independent memory budget for concurrent dependency-graph encoders |
| `RUST_LOG` | `info` | |

`memory` is intentionally process-local and disposable: every restart clears
all archives, so it must remain single-replica and paired with equally
throwaway metadata during certification. See
[`docs/memory-publish-certification.md`](docs/memory-publish-certification.md)
for the `zed r2g` + real-server test contract and the Kubernetes promotion
boundary.

## Database ownership

This process is the sole runtime writer for the shared registry schema. The web
server receives a separate read-only identity and sends every mutation through
this API over private-cluster HTTP. Production migrations run once as a
reviewed release step with a dedicated migrator identity; normal API replicas
do not receive DDL privileges and do not migrate on boot.

The shared-library rollout, role split, migration evidence, and exact
`zed-orm-core` pin are documented in
[`docs/database-boundary.md`](docs/database-boundary.md). The disposable Docker
Compose stack explicitly opts into the legacy SeaORM boot migration while the
production release path invokes the explicit migration command. That boot-time
exception is not valid for Kubernetes or durable self-hosted deployments.

### Cloudflare R2 mapping

| Setting | Value |
| --- | --- |
| `S3_ENDPOINT_URL` | `https://<account_id>.r2.cloudflarestorage.com` |
| `S3_REGION` | `auto` |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | R2 API token pair |
| Bucket | see `zed-infra/terraform/cloudflare` |

## Tag verification

`ZED_VERIFY_TAGS=github` enforces the provenance rule server-side: the
declared backing repo must have the tag the client publishes from
(`tag_not_found` otherwise). github.com is implemented in `src/verify.rs`;
GitLab/Bitbucket/Codeberg/SourceHut and hg hosts are the marked extension
point, and unverifiable hosts (self-hosted forges) are allowed through with a
warning so they are not locked out. The CLI independently verifies tags
client-side either way.

## Run it

```sh
# disposable local stack: postgres + minio + api (from the parent directory)
# docker-compose.yml explicitly enables the legacy local boot migration.
docker compose -f zed-api-server.rs/docker-compose.yml up --build

# or bare, after applying the reviewed schema to your own Postgres
DATABASE_URL=postgres://zed:zed@localhost:5432/zed \
cargo run -- migrate

DATABASE_URL=postgres://zed:zed@localhost:5432/zed \
STORAGE_BACKEND=memory \
STORAGE_MEMORY_MAX_BYTES=268435456 \
cargo run

# mint a token (printed once)
DATABASE_URL=... cargo run -- create-token --name ci --org acme

# then, from a package directory
zed org claim acme --registry http://localhost:8080 --token zpkg_...
zed publish --registry http://localhost:8080 --token zpkg_...
```

Equivalent curl publish:

```sh
curl -X PUT http://localhost:8080/v1/packages/acme/demo/versions/0.1.0 \
  -H "Authorization: Bearer zpkg_..." \
  -F 'meta={"manifest":{...},"vcs_tag":"v0.1.0","sha256":"...","size":123,"format":"tar.gz"};type=application/json' \
  -F 'artifact=@.zed/pack/acme-demo-0.1.0.tar.gz'
```

## Development

Clone side by side with `zed-interfaces` (path dependency). `cargo test` runs
without Postgres or network: handler publication/immutability paths use a real
in-memory SQLite database, and storage tests exercise the bounded process-memory
backend directly. The compose and cross-repository E2E suites still cover the
full Postgres/API/web/CLI stack.

## Formal methods

[`formal/fm.toml`](formal/fm.toml) and
[`formal/latest_selection.fm.toml`](formal/latest_selection.fm.toml) define
schema-v1 `fmctl` gates for publication finalization and deterministic
latest-version selection across publish/yank transitions. Their Quint models
exhaustively check immutable publication, atomic visibility, fail-closed
authorization, committed artifact availability, and maximal non-yanked
selection. See [`formal/README.md`](formal/README.md) for bounds, witnesses,
the concurrency finding behind retained failed-upload blobs, and an explicit
account of what is not proved.

## License

MIT
