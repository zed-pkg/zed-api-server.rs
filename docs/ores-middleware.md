# Shared request middleware

This server installs `ORESoftware/ores-middleware` at the live Axum boundary in `src/server.rs`, using `Cargo.toml` and immutable central commit `a7184454564ef17aa8685fa6393c96b85852056b`.

The shared layer provides request/trace context, crash recovery, deadlines, streaming payload limits, security headers, compression, ETags, RED telemetry hooks, rate/idempotency ports, and integration ports for shared-auth, opto-sync, and ores-otel. Existing service-specific authentication, authorization, rate limits, and telemetry remain in place beneath the shared request-lifecycle layer.

Production must set `ORES_MIDDLEWARE_ENV=production` and explicitly choose `ORES_MIDDLEWARE_TLS_MODE=in-process` or `trusted-proxy`. Trusted-proxy mode also requires `ORES_MIDDLEWARE_TRUSTED_PROXY_CIDRS`; forwarded transport headers from other peers are rejected. Development defaults to explicitly disabled TLS enforcement rather than trusting public forwarded headers.

TypeSpec and JSON Schema/OpenAPI are independent, peer, human-authored contract authorities. Any authority, generated-artifact, or runtime-descriptor discrepancy fails closed. Governing instructions: `ORESoftware/my-ai/AGENTS.md`.
