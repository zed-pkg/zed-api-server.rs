# Zed API route hierarchy

The package-manager protocol and the product API share handlers and policy,
but have distinct public namespaces. `/v1` is the canonical machine contract;
the product may expose the same registry operations through an adapter beneath
`/api/v1/registry`.

## Canonical public routes

- `/api/v1/auth/*` — Supabase-to-Shared-Auth exchange and public auth configuration.
- `/api/v1/users/me` — the signed-in registry profile and user settings.
- `/api/v1/home` and `/api/v1/search` — account-aware home/search responses.
- `/api/v1/orgs/*` — organizations, memberships, invitations, projects, package settings, licenses, and upload registration.
- `/v1/packages/*`, `/v1/search`, `/v1/artifacts/*`, and related `/v1`
  routes — canonical package-manager metadata, publish, yank, search, artifact,
  and download operations.
- `/api/v1/registry/*` — optional product-API adapter to those same machine
  operations; it is not a replacement protocol or an independently versioned
  contract.

Both mounts use the same authentication, authorization, request limits, audit,
and observability behavior.

## Product adapter

CLI and package-manager clients use `/v1`. Product clients may use the bounded
`/api/v1/registry` adapter when deployed. The adapter must not acquire
capabilities, schemas, or status semantics absent from the canonical route and
must not be documented as the package-manager protocol root.

## Service boundaries

The API server owns mutation, authorization, package publication, R2 object coordination, and the download ledger. The web server is an HTMX/Maud presentation tier and must use a SELECT-only database principal for page reads. Shared Auth owns browser sessions and verifies Supabase identities; Zed stores only the projected `(auth_realm, shared_auth_subject)` identity in its separate registry database.

Object keys are internal storage policy, not public protocol identifiers. The
current compatibility publisher uses digest-addressed keys:

```text
artifacts/{sha256}.{extension}
```

Future target-qualified storage may add an internal namespace, but public
metadata continues to expose a download URL and digest rather than
`artifact_key`.

Postgres remains authoritative for package metadata, visibility, versions, checksums, uploads, licenses, and downloads. A successful download request records its ledger row before the API returns a redirect to the object.

## Visibility transition

A private package may become public only while both conditions hold:

- age is at most 10 days; and
- total downloads are at most 50.

Exactly 10 days and exactly 50 downloads remain eligible. The database trigger is authoritative; API checks exist only to return a typed, useful error before the statement reaches the trigger.

## ORM migration note

The current account branch consumes the established `zed-lib` facade while production activation is certified. `zed-lib-core` is the merged, independently packaged successor and exposes stricter typed read/write contexts. Moving this server to that successor is intentionally a separate compatibility migration so deployment, auth, R2 activation, and E2E evidence are not coupled to a second data-access rewrite.
