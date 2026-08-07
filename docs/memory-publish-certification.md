# In-memory package publication certification

Zed has two complementary pre-production publication checks:

1. `zed r2g` validates the exact pruned artifact produced by `zed publish`. It publishes into a private throwaway `file://` registry, installs the package into a clean mock consumer, and runs `publish.smoke_test` on the installed copy. `zed r2g --docker` repeats the consumer phase in a fresh OCI container.
2. `STORAGE_BACKEND=memory` validates the real Rust registry HTTP boundary without writing artifact archives to disk or object storage. Metadata still uses Postgres, while content-addressed archives live in a bounded map inside the API-server process.

Use both. `r2g` catches packaging and consumer-layout defects before network publication; the memory-backed server catches multipart upload, authorization, metadata, artifact download, dependency resolution, ordinary install, and frozen reinstall defects through the actual API routes.

## Local server

```sh
DATABASE_URL=postgres://zed:zed@localhost:5432/zed \
STORAGE_BACKEND=memory \
STORAGE_MEMORY_MAX_BYTES=268435456 \
ZED_VERIFY_TAGS=off \
cargo run
```

Then point the CLI at the server:

```sh
zed org claim acme --registry http://127.0.0.1:8080 --token "$ZED_PKG_TOKEN"
zed publish --registry http://127.0.0.1:8080 --token "$ZED_PKG_TOKEN"
zed install acme/example@1.0.0 --registry http://127.0.0.1:8080
zed install --frozen --registry http://127.0.0.1:8080
```

`STORAGE_MEMORY_MAX_BYTES` is a hard total for all archives currently held by the process. A write that would cross the limit fails before mutating the map. The ordinary `MAX_ARTIFACT_BYTES` upload limit and the independent per-object buffered-read ceiling still apply.

## Kubernetes bootstrap

The app-owned `k8s/` manifests render the same bounded process-memory backend for both AWS and Hetzner overlays. `ORESoftware/k8s-cluster` owns the `zed` tenant, AppProject, and Argo CD Application pointers; Argo reads the app repository directly at `path: k8s`.

The bootstrap deliberately keeps:

- one API replica;
- `Recreate` deployment strategy;
- cluster-local `ClusterIP` exposure only;
- no public Ingress while authentication, rate limiting, and tag verification are bypassed;
- a 256 MiB artifact-store limit under the pod's 512 MiB memory limit.

The in-memory store is process-local and disposable. Restarting the API clears every archive. Certification workflows therefore reset volatile Postgres metadata and the API deployment together before publishing test packages.

## Production promotion

Do not use the memory backend as durable registry storage. Before public promotion:

1. select `STORAGE_BACKEND=s3`;
2. configure Cloudflare R2 or AWS S3 credentials through External Secrets;
3. restore authentication, rate limiting, and server-side VCS tag verification;
4. run migrations as an explicit one-off job;
5. increase replicas only after every pod shares the same object store;
6. certify publish, install, frozen reinstall, yank behavior, and artifact retrieval against each production cluster.

Cloudflare R2 remains the preferred primary artifact store; AWS S3 is the compatible alternative. The memory backend exists to make package publication tests fast, isolated, deterministic, and credential-free—not to replace durable object storage.
