# Canonical API documentation

`zed-api-server` implements the fleet `ore.api-docs.v1` contract.

## Public same-origin routes

- `GET /.well-known/api-docs` — discovery, provenance, digest, and API/MCP pairing.
- `GET /openapi.json` — canonical public OpenAPI 3.1 document.
- `GET /api/docs.json` — exact-byte compatibility alias.
- `GET /api/docs` — static human-readable operation catalog.
- `GET /docs/api` — compatibility alias.

The documentation router is composed beside the authenticated registry router. It does not inherit token authentication, per-token rate limits, artifact body limits, or registry mutation middleware. Package and organization operations retain their existing policy.

The manifest pairs this API with the canonical public `zed-pkg/zed-mcp-server.rs` repository. Until that repository is published under DEN-165, the API PR remains a draft and must not be promoted.

## Operation metadata

Every documented operation declares:

- a stable unique `operationId`;
- `x-ore-visibility`;
- `x-ore-stability`;
- `x-ore-mcp-expose`;
- `x-ore-mcp-mutating`.

The baseline MCP catalog can expose read-only `GET` operations. `POST`, `PUT`, `PATCH`, and `DELETE` operations are classified as mutating for the fleet safety boundary and are not MCP-exposed, even when an individual endpoint—such as semantic search—has query semantics.

## Validation and promotion

The API-document workflow pins the merged shared contract at `ORESoftware/mcp-rust-libs@47e411311523013f90db98390671d683475d6c74`. Existing Rust CI remains responsible for formatting, Clippy, tests, and release compilation.

Production promotion additionally requires:

1. the canonical `zed-pkg/zed-mcp-server.rs` implementation from DEN-165;
2. exact API and MCP document parity;
3. a successful credential-free `zed-pkg-test` contract gate;
4. unchanged source heads between test evidence and merge.

This change requires no Cloudflare DNS, Worker route, R2, origin, or secret modification.
