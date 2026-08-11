# Dependency graph export representations

The package-version dependency graph has one semantic document,
`zpkg/dependency-graph/v1`, and one semantic `graph_digest`. The server builds
that finalized document once from the immutable package artifact, then projects
it into the requested byte representation. Selecting a download format never
runs dependency resolution again.

## Endpoints

The original endpoint remains unchanged for JSON, YAML, TOML, DOT, and Mermaid:

```text
GET /v1/packages/{org}/{name}/versions/{version}/dependency-graph?view=declared&format=json
```

The additive export endpoint serves JSON5, XML, CSV, MessagePack, and Protocol
Buffers:

```text
GET /v1/packages/{org}/{name}/versions/{version}/dependency-graph/export/{format}
```

Both `GET` and `HEAD` are supported. Common aliases are accepted for binary
formats.

| Format | Route values | Media type | Authoritative |
| --- | --- | --- | --- |
| JSON5 | `json5` | `application/vnd.zpkg.dependency-graph.v1+json5` | yes |
| XML | `xml` | `application/vnd.zpkg.dependency-graph.v1+xml` | yes |
| CSV | `csv` | `text/csv; charset=utf-8` | no |
| MessagePack | `msgpack`, `messagepack`, `mpk` | `application/vnd.zpkg.dependency-graph.v1+msgpack` | yes |
| Protocol Buffers | `protobuf`, `proto`, `pb` | `application/vnd.zpkg.dependency-graph.v1+protobuf` | yes |

Unknown formats return `406 unsupported_format`. Unknown or inaccessible package
versions retain the canonical endpoint's non-enumerating `404` behavior.

## Validators and caching

Every successful response includes:

- `X-Zpkg-Graph-Digest`: semantic graph identity shared by every format.
- `ETag`: a strong SHA-256 validator over the exact response bytes, so it is
  intentionally different between XML, MessagePack, and other projections.
- `X-Zpkg-Graph-Authoritative`: `true` for lossless interchange formats and
  `false` for the analytics-oriented CSV table.
- `Content-Disposition`: a sanitized deterministic filename derived from the
  immutable package coordinate.
- `Cache-Control: public, max-age=31536000, immutable`.

A matching strong `If-None-Match` returns `304 Not Modified` with validators and
no response body. Export bodies use the existing dependency-graph encoded-size
limit and are rejected rather than truncated.

## Representation details

### JSON5

The response begins with `//` comments containing the schema and graph digest,
followed by the canonical JSON document unchanged. JSON is a strict subset of
JSON5, so JSON5 tooling can preserve the comments while canonical-verification
tooling can remove the comment prelude and verify the original JSON bytes.

### XML

XML maps every declared and resolved graph field to named elements and
attributes. Set-like collections retain the normalized graph order. Reserved
characters and attribute whitespace are escaped deterministically.

### CSV

CSV is an RFC 4180 node/edge table for spreadsheets and analytics. It repeats
schema and graph identity columns on each row and stores feature lists as JSON.
It deliberately does not flatten every provenance and projection field, so CSV
must not be used as the source for a lockfile or semantic graph digest.

### MessagePack

MessagePack is a direct binary encoding of the canonical JSON value. Decoding it
produces the same named maps, arrays, strings, integers, booleans, and nulls as
the canonical JSON document.

### Protocol Buffers

The typed schema is maintained in `zed-interfaces` at
`proto/zpkg_dependency_graph_v1.proto`. Declared and resolved graphs occupy
separate `oneof` arms. Field numbers are stable and append-only; the server's
manual wire encoder is covered against those committed field numbers without
adding a runtime Protobuf dependency to the API service.
