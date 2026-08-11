# Dependency graph export representations

The registry exposes one semantic graph contract, `zpkg/dependency-graph/v1`,
through several byte representations. A representation never triggers a new
resolution. Every download is projected from the same finalized graph document
and carries:

- `X-Zpkg-Graph-Digest`: semantic graph identity shared by every representation.
- `ETag`: a strong validator over the exact response bytes, unique per format.
- `Cache-Control: public, max-age=31536000, immutable` for an exact package version.
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

`GET` and `HEAD` are supported. A matching strong `If-None-Match` returns `304`
with the validators and no body.

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

### CSV

CSV is an RFC 4180 node/edge analytics projection. It repeats graph identity and
schema columns on every row and encodes feature lists as JSON. It is deliberately
marked non-authoritative because graph provenance and nested projection metadata
are not naturally represented as a flat table. Use JSON, YAML, TOML, JSON5, XML,
MessagePack, or Protocol Buffers for lossless interchange.

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

Unknown packages, versions, and inaccessible graphs use the same not-found
response as the canonical endpoint. Export bodies are subject to the existing
encoded graph size limit and are never truncated. Download filenames are built
from validated coordinates and cannot inject response headers.
