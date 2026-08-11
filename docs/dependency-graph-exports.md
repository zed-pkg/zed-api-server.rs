# Dependency graph export representations

The registry exposes one semantic graph contract, `zpkg/dependency-graph/v1`,
through several byte representations. A representation never triggers a new
resolution. Every download is projected from the same finalized graph document
and carries:

- `X-Zpkg-Graph-Digest`: semantic graph identity shared by every representation.
- `ETag`: a strong validator over the exact response bytes, unique per format.
- `Cache-Control: public, max-age=31536000, immutable` for a public exact
  package version, or `private, no-store` for an authorized private graph.
- `Content-Disposition` with a sanitized deterministic filename.
- `X-Zpkg-Graph-Authoritative`: `true` for lossless interchange formats and
  `false` for convenience or analytics projections.

## Routes

The original endpoint remains the canonical API for JSON, YAML, TOML, DOT, and
Mermaid:

```text
GET /v1/packages/{org}/{name}/versions/{version}/dependency-graph?view=declared&format=json
```

Additional formats are available from:

```text
GET /v1/packages/{org}/{name}/versions/{version}/dependency-graph/export/{format}
```

Supported `{format}` values and aliases:

| Format | Values | Media type | Authoritative |
| --- | --- | --- | --- |
| JSON5 | `json5` | `application/vnd.zpkg.dependency-graph.v1+json5` | yes |
| XML | `xml` | `application/vnd.zpkg.dependency-graph.v1+xml` | yes |
| CSV | `csv` | `text/csv; charset=utf-8` | no |
| MessagePack | `msgpack`, `messagepack`, `mpk` | `application/vnd.zpkg.dependency-graph.v1+msgpack` | yes |
| Protocol Buffers | `protobuf`, `proto`, `pb` | `application/vnd.zpkg.dependency-graph.v1+protobuf` | yes |

`GET` and `HEAD` are supported. The path fixes the representation, but an
`Accept` header that excludes its media type receives `406`. A matching
`If-None-Match` returns `304` with validators and no body; per RFC 9110,
`If-None-Match` uses weak comparison even though the emitted ETag is strong.
`Content-Length` is the encoded GET length and is retained on HEAD.
Public successful and `304` responses carry `Vary: Accept`, preventing an
immutable shared-cache entry from bypassing that negotiation. Private successes
carry `Vary: Accept, Authorization` together with `private, no-store`.

## Representation notes

### JSON5

The response begins with human-readable `//` comments and then contains the
canonical JSON document unchanged. JSON is a strict subset of JSON5, so the
comments can be retained by JSON5 tooling or stripped for canonical JSON
verification.

### XML

The XML document maps every declared or resolved graph field to named elements
and attributes. Collections preserve normalized contract order. XML-reserved
characters and attribute whitespace are escaped deterministically.
Carriage returns are emitted as character references so XML newline
normalization cannot change the value. A graph containing a character XML 1.0
cannot represent receives `422` instead of a lossy document.

### CSV

CSV is an RFC 4180 node/edge analytics projection. It repeats graph identity and
schema columns on every row and encodes feature lists as JSON. It is deliberately
marked non-authoritative because graph provenance and nested projection metadata
are not naturally represented as a flat table. Use JSON, YAML, TOML, JSON5, XML,
MessagePack, or Protocol Buffers for lossless interchange.

Formula-like cells are prefixed with a spreadsheet text marker inside their
RFC 4180 quoting. This prevents a downloaded analytics file from executing a
cell beginning with `=`, `+`, `-`, `@`, tab, or a line break when opened in a
spreadsheet. Consumers needing byte-exact field values must use an authoritative
format.

### MessagePack

MessagePack is a direct binary encoding of the canonical JSON value. Map keys,
arrays, strings, integers, booleans, and nulls follow the MessagePack
specification; the decoded value is the same graph document that is served as
canonical JSON.

### Protocol Buffers

The typed schema is committed at `proto/zpkg_dependency_graph_v1.proto`.
Field numbers are stable. The top-level `oneof` keeps declared and resolved
views distinct, matching the source graph contract rather than wrapping an
opaque JSON blob.

## Security and limits

Canonical package visibility is checked before either graph route loads the
exact immutable `zed_package_versions` row and its normalized manifest. This
keeps visibility, version existence, and graph source in one Postgres authority;
the artifact key and digest remain bound to that same published row. Public
package graphs are anonymous. Private package graphs
require either a live legacy token scoped to that package's organization or a
session-backed delegated web token whose canonical user belongs to the
organization or owning project. Invalid credentials, cross-tenant credentials,
unknown packages, unknown versions, and inaccessible graphs use the same
no-store not-found response. The web BFF must forward its delegated bearer when
requesting a private graph; prior UI authorization is not a substitute for API
authorization. A base Shared Auth JWT is not accepted directly: browser access
requires the audience-bound `zpkg-web` delegated token, while CLI access uses a
live organization-scoped legacy registry token until a CLI delegation flow is
defined.

Export bodies are subject to the existing encoded graph size limit and are
never truncated. The potentially expansive XML
and CSV encoders stop at that limit, JSON5 is pre-sized, and every binary output
is checked before a response is created. Declared dependency counts are also
bounded by the graph edge limit. Download filenames are built from validated
coordinates and cannot inject response headers.
