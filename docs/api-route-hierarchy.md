# Zed API route hierarchy

The registry is a bounded subset of the product API, not a parallel top-level service.

## Canonical public routes

- `/api/v1/auth/*` — Supabase-to-Shared-Auth exchange and public auth configuration.
- `/api/v1/users/me` — the signed-in registry profile and user settings.
- `/api/v1/home` and `/api/v1/search` — account-aware home/search responses.
- `/api/v1/orgs/*` — organizations, memberships, invitations, projects, package settings, licenses, and upload registration.
- `/api/v1/registry/*` — package-manager protocol operations: package/version metadata, publish, yank, search, artifact lookup, download accounting, embeddings, and audit verification.

`/api/v1/registry` therefore inherits the same authentication, authorization, request limits, audit, and observability conventions as the rest of `/api/v1`.

## Compatibility aliases

Existing CLI and web clients may continue to call bounded `/v1/*` aliases during migration. New clients must use `/api/v1/*`. Compatibility aliases must not acquire capabilities absent from their canonical route and should be removed only after telemetry shows no active callers.

## Service boundaries

The API server owns mutation, authorization, package publication, R2 object coordination, and the download ledger. The web server is an HTMX/Maud presentation tier and must use a SELECT-only database principal for page reads. Shared Auth owns browser sessions and verifies Supabase identities; Zed stores only the projected `(auth_realm, shared_auth_subject)` identity in its separate registry database.

Package bytes are stored in R2 under the canonical key contract:

```text
zed/v1/packages/{org}/{package}/{version}/{sha256}.{extension}
```

Postgres remains authoritative for package metadata, visibility, versions, checksums, uploads, licenses, and downloads. A successful download request records its ledger row before the API returns a redirect to the object.

## Visibility transition

A private package may become public only while both conditions hold:

- age is at most 10 days; and
- total downloads are at most 50.

Exactly 10 days and exactly 50 downloads remain eligible. The database trigger is authoritative; API checks exist only to return a typed, useful error before the statement reaches the trigger.

## ORM migration note

The current account branch consumes the established `zed-lib` facade while production activation is certified. `zed-lib-core` is the merged, independently packaged successor and exposes stricter typed read/write contexts. Moving this server to that successor is intentionally a separate compatibility migration so deployment, auth, R2 activation, and E2E evidence are not coupled to a second data-access rewrite.
