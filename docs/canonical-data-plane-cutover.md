# Canonical account and machine-registry cutover

The API is compiled against `zed-orm-core@38ef3f50638614a14170d5c677173e040e916a6d`. Browser/account routes and the web application now share the canonical `zed_*` PostgreSQL data plane.

## Account boundary

A verified Shared Auth delegated token must be active, session-backed, issued to the exact Zed web client, scoped for `zpkg:account`, targeted to the `zed-pkg` audience, and associated with the customer realm. The API projects that UUID identity into `zed_users`; organization, project, package, invitation, license, upload, and settings operations use named `zed-orm-core` functions. Authorization is rechecked in the same transaction as each mutation.

Canonical product routes live under `/api/v1/account`. The `/v1/account` namespace is a bounded compatibility alias for older web clients. General package settings cannot change visibility; private-to-public conversion uses the database-guarded inclusive 10-day/50-download policy.

## Machine publication bridge

The legacy `/v1` CLI tables remain temporarily for compatibility. A publish is not reported successful until its organization, package, immutable version, verified R2 upload, and audit fact are adopted into the canonical data plane. Identical retries reconcile a possible legacy-only partial commit and then return the stable immutable-version conflict. Divergent retries are rejected before canonical adoption.

Production startup requires both opaque canonical read and write contexts. The `migrate` command applies the legacy compatibility migration first and the canonical shared-definition migration second. Long-running replicas must run with automatic migration disabled; deployment uses the same immutable API image for the migration job and runtime.

## Verified source graph

The cutover carrier passed locked format, all-target compilation, Clippy with warnings denied, all tests and doctests, release build, dependency-pin assertions, and checks proving that application code no longer references the transitional `zed_orm` crate. This document intentionally triggers ordinary CI, container, formal, and registry E2E workflows on the exact final source head before merge.
