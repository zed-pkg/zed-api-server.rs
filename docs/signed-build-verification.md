# Zed registry signed-build verification (draft)

Endpoint: POST /v1/orgs/{org}/signed-builds/verify
Authorization: existing Zed registry token with publish rights for org.
Body: JSON object with exactly one receipt of schema zpkg.signed-build/1.
Response when cryptographically valid and bytes match:
    {
      "schema": "zpkg.signed-build-verification/1",
      "signature_valid": true,
      "artifact_bytes_match": true,
      "trust": "signed-self-report-not-compiled-proof",
      "artifact_sha256": "<sha256>",
      "signer_key_id": "<key-id>"
    }

Implementation:
- Use the versioned shared contract from zed-interfaces, pinned to exact SHA.
- Reject unknown fields, wrong audience, invalid source/toolchain/artifact
  digests, archive format, unsupported target and time windows >5 minutes.
- Authenticate and authorize BEFORE any artifact byte retrieval.
- Require the signed org to match the authenticated route org.
- Require the signer's key ID to correspond to an ACTIVE enrolled org key
  (retired/revoked keys cannot make new build assertions).
- Verify Ed25519 domain-separated preimage via existing signature verifier.
- Require a published package/version database row with matching SHA-256,
  size and format, then read and rehash the actual stored artifact bytes.
- Cap buffered bytes via existing hard storage limit. Apply separate
  2-request concurrency lane for expensive registry artifact hashing.
- No database mutation and no automatic release promotion.

**This is only an attribution/integrity check.** A publisher can sign a
fabricated compiler claim. The endpoint does NOT check server-minted nonce,
durably consume the Oreslang API challenge, attest isolated execution or
authorize code execution/release. Oreslang API must independently verify
the challenge, registered device key, nonce, original bytes and a one-use
durable admission transaction before any stronger receipt can exist.

Do not enable a global must-have-signed-build publish gate based on
this endpoint's response alone; it would conflate authenticated signing
with trusted compilation. A future release policy can require both a
valid signature and an independently verified trusted build receipt.

Oreslang API counterpart:
https://github.com/ores-truffle-oreslang/oreslang-api-server.ores/pull/1

Zed contract:
https://github.com/zed-pkg/zed-interfaces/pull/181


## Optional fail-closed publication policy

The service honors ZED_BUILD_PROVENANCE_POLICY:
- unset or legacy: preserve existing publish behavior while signed-build
  verifier is an optional audit endpoint;
- required: reject every new publish with HTTP 503 until a trusted,
  independently verified Oreslang API build receipt admission is integrated;
- any other value: reject publish with HTTP 503, never silently downgrade.

A valid signature from /signed-builds/verify is **not** sufficient to
override required policy. The integration must also prove durable one-use
challenge consumption, exact source/tree/toolchain identity, and actual
compilation or independent verified rebuild, before enabling publish.
