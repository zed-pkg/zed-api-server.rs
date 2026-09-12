# Signed public-intake API boundary

The public browser does not call this service directly. Cloudflare Workers on the exact `user.zpkg.net/pre-interest*` and `org.zpkg.net/quote*` routes validate Turnstile, origin, body size, and form shape before forwarding canonical JSON to:

- `POST /v1/pre-interest`
- `POST /v1/quote-requests`

## Trust envelope

Every forwarded request must contain one value for each of:

- `Idempotency-Key`
- `X-Zed-Intake-Body-Sha256`
- `X-Zed-Intake-Signature`
- `X-Zed-Intake-Source-Host`
- `X-Zed-Intake-Timestamp`

The API recomputes the body SHA-256 and verifies HMAC-SHA-256 over:

```text
v1
<unix timestamp>
<source host>
<API path>
<request UUID>
<body SHA-256>
```

The signature is checked before JSON parsing. The timestamp is bounded to five minutes, the host and path are route-specific, duplicate authority headers are rejected, and the request UUID must equal the typed body request identifier.

## Contract and persistence

After the ingress proof passes, the API deserializes the merged `zed.public-intake.v1` Rust transport type from `zed-interfaces`, re-checks the closed field inventory, all bounded enumerations, consent revisions, source-host/party relationship, and secret-shaped free text, then serializes the typed value for encrypted persistence.

Writes occur only through the opaque `zed_orm_core::WriteContext::insert_public_intake_submission` operation. The API cannot obtain a raw persistence entity from this route.

## Runtime secrets

The service requires:

- `ZED_PUBLIC_INTAKE_SIGNING_KEY`
- `ZED_PUBLIC_INTAKE_ENCRYPTION_KEY_ID`
- `ZED_PUBLIC_INTAKE_ENCRYPTION_KEY_B64`
- `ZED_PUBLIC_INTAKE_EMAIL_HMAC_KEY_ID`
- `ZED_PUBLIC_INTAKE_EMAIL_HMAC_KEY_B64`
- `ZED_PUBLIC_INTAKE_CONSENT_REVISION`
- `ZED_PUBLIC_INTAKE_MARKETING_CONSENT_REVISION`

Absent, malformed, or undersized key material fails closed with a generic service-unavailable envelope. Secret values, contact data, ciphertext, request UUIDs, and body digests must not enter logs, metrics, traces, panic text, or URLs.

## Public responses

Successful inserts, exact replays, and duplicate email fingerprints all return the same generic `202` shape. Validation and ingress failures return bounded typed errors without echoing submitted values. This prevents registration or customer-enumeration side channels.
