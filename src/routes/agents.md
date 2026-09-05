# API route instructions

These instructions refine the repository-root `agents.md` for `src/routes`.

- Apply the organization-wide functional/effect-boundary guidance from `https://github.com/ORESoftware/my-ai/blob/main/AGENTS.md` together with every readable ancestor `agents.md`.
- Keep transport contracts in `zed-interfaces`, reusable behavior in `zed-lib-core`, persistence behind `zed_orm_core::WriteContext`, and route effects in this directory.
- Preserve TypeSpec, Protobuf, JSON Schema, Diesel, and SeaORM as independently checked layers; no one representation silently replaces another.
- Public intake must verify the Cloudflare-to-origin signature and exact body digest before deserialization, reject duplicate authority headers, and bind the proof to route, host, timestamp, and request UUID.
- Never log or format contact data, request bodies, request UUIDs, body digests, signatures, abuse-challenge values, ciphertext, credentials, or key material.
- Public responses must remain enumeration-resistant: a new row, exact replay, and duplicate keyed email fingerprint share the same accepted envelope.
