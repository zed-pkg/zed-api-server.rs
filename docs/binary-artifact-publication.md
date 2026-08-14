# Binary artifact publication

## Accepted v1 archive

A native binary artifact is one immutable ZIP with this canonical layout:

```text
pkg/
  .zpkg.toml
  .zpkg-binary.json
  bin/<entrypoint>
  ...other declared payload files
```

`.zpkg.toml` is the ordinary package manifest and is authoritative for package
identity and `[bin]` entrypoints. `.zpkg-binary.json` uses
`zpkg.binary-artifact/v1`; it binds one normalized platform, source provenance,
and the size, SHA-256 digest, and executable intent of every payload file. The
descriptor excludes itself from its file list to avoid a circular digest.

The existing publish route accepts the ZIP as the `artifact` multipart field
and the ordinary `PublishMeta` JSON as `meta`. Those are the only accepted
multipart field names and each must occur exactly once. A ZIP containing the
reserved descriptor, including a path spelling that aliases it on a supported
host, is verified as a binary profile or rejected before VCS lookup, object
storage, or a metadata transaction.

Server verification covers:

- the canonical leading ZIP signature, root/path encodings, file types, and
  compression methods;
- overlapping ranges, encrypted entries, duplicate/portable path collisions,
  Unicode-lowercase collisions, file/ancestor conflicts, empty directory
  records, 255-byte components, Windows device names/characters, compression
  ratio, entry count, and expanded-byte limits;
- no general-purpose bit 3 data descriptors and no per-entry ZIP64 sentinels or
  `0x0001` extras, which are unnecessary below the v1 byte ceilings;
- canonical descriptor JSON and exact agreement with the embedded manifest and
  external publish metadata;
- a complete one-to-one payload inventory with actual size and SHA-256 checks;
- executable intent, entrypoints, normalized platform, and source provenance;
- an externally supplied `vcs_commit`, including the descriptor copy, matches
  the full 40-hex SHA-1 or 64-hex SHA-256 object ID resolved by tag verification
  (ASCII-hex case is canonicalized; abbreviated IDs are rejected).

The v1 resource ceilings are 1 GiB of archive bytes, 2 GiB expanded, 200,000
entries, and a 1000:1 per-entry compression ratio. The corresponding
`ZED_MAX_BINARY_*` environment variables may lower those ceilings for a
deployment, but values above them are clamped rather than weakening the v1
profile.

The verifier does not yet make a complete byte-for-byte ZIP-encoding claim:
local-versus-central header equality is not independently compared. Archive-
level ZIP64 EOCD remains parser-accepted because the v1 entry ceiling exceeds
65,535; the verifier does not yet distinguish a necessary count-only ZIP64 EOCD
from an unnecessary one on a smaller archive. Those remaining checks are
feasible in the same bounded raw-header pass, but must land in both producer
and consumer before the format calls the entire container encoding canonical.

## Immutable storage

Object keys are content addressed. S3-compatible uploads use
`If-None-Match: *` so an immutable key is never overwritten, and set content
type, `Cache-Control: public, max-age=31536000, immutable`, and
`x-amz-meta-zpkg-sha256`. If a Cloudflare R2/S3 PUT fails during a same-key
race, existence alone is insufficient: recovery downloads and streams the
object through SHA-256 and accepts it only when its actual bytes, length,
content type, cache policy, and digest metadata all match.

The local backend stages a fully written and synced file beside its destination
and promotes it with an atomic no-clobber hard link. A concurrent identical
writer is idempotent; a different object already occupying a content-addressed
key fails closed. The bounded in-memory backend applies the same immutable-key
rule rather than replacing a colliding object.

## Multi-platform publication boundary

The current compatibility model stores exactly one artifact on a package
version row. It can safely verify and serve one binary target, but cannot
represent Linux, macOS, and Windows variants for the same semantic version.
Adding target-qualified routes without changing that model would either
overwrite immutable facts or create target-dependent reads, so this service
does not fabricate that behavior in the legacy table.

The coordinated data-plane change should introduce an artifact-variant entity
owned by `zed-lib-core`, not an ad hoc startup migration here. Its immutable
identity is `(package_version_id, target, format)` and its internal persisted
facts are:

| Field | Purpose |
| --- | --- |
| `target` | Canonical resolver key, for example `x86_64-unknown-linux-gnu` |
| `os`, `arch`, `libc`, `abi` | Structured filtering copied from the verified descriptor |
| `format`, `sha256`, `size_bytes`, `artifact_key` | Internal immutable object facts; storage keys remain server policy |
| `profile`, `descriptor`, `descriptor_sha256` | Profile/schema identity and the validated descriptor projection |
| `published_at`, publisher identity | Audit and governance facts |

The public package-manager route family must remain aligned with the shared
interfaces:

```text
PUT /v1/packages/{org}/{name}/versions/{version}/artifacts/{target}/{format}
GET /v1/packages/{org}/{name}/versions/{version}/artifacts
GET /v1/packages/{org}/{name}/versions/{version}/artifacts/{target}/{format}
```

The product API may mount the same handlers beneath `/api/v1/registry`, but
that adapter must not diverge from the `/v1` machine contract. Public artifact
metadata uses `size`, not the database column spelling `size_bytes`, and does
not expose `artifact_key`; it includes `descriptor_sha256`, the full platform,
format, digest, download URL, publication/yank state, source, and attachments.

The target and format in the path must exactly match the verified descriptor
and publish metadata. The collection response lets a resolver choose a target;
the item response returns immutable metadata and the digest-addressed download
URL. Publication must authorize, lock/check the `(version, target, format)`
identity, write the content-addressed object, and insert the variant in one
coordinated workflow while retaining the existing in-flight-object safety rule.

Until the shared interface types are adopted here and the `zed-lib-core`
migration, CLI resolver, and server routes land together, the legacy
`/v1/.../versions/{version}` route stays single-artifact and the verified
descriptor's platform is logged but not projected into a queryable artifact
row.
