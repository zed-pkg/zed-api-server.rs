# Canonical API documentation

`zed-api-server` implements the fleet `ore.api-docs.v1` contract.

## Public same-origin routes

- `GET /.well-known/api-docs` — discovery, provenance, digest, and API/MCP pairing.
- `GET /openapi.json` — canonical public OpenAPI 3.1 document.
- `GET /api/docs.json` — exact-byte compatibility alias.
- `GET /api/docs` — static human-readable operation catalog.
- `GET /docs/api` — compatibility alias.

The documentation router is composed beside the authenticated machine-registry and account routers. It does not inherit token authentication, per-token rate limits, artifact body limits, or mutation middleware. Documented package, dependency-graph, and organization operations retain their existing registry policy.

The checked-in OpenAPI document covers the machine-registry surface implemented by `src/routes`. The separately authenticated browser/account control plane implemented by `src/account_router.rs` is intentionally outside this contract: its `/api/v1/*` routes and `/v1/*` compatibility aliases are not public discovery or MCP operations and require a dedicated account contract before they may be advertised.

The manifest pairs this API with the canonical public `zed-pkg/zed-mcp-server.rs` repository. Production promotion remains blocked until that repository is published under DEN-165 and the paired contract evidence is current.

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
