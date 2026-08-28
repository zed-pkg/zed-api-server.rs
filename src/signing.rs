//! Ed25519 verification, server side.
//!
//! The server verifies at publish time and nowhere else. That timing is the
//! whole design: a signature that cannot be checked is worthless later,
//! because "later" is when the registry is unreachable and nobody can ask it
//! anything. Rejecting an unverifiable signature at the door means a stored
//! signature is one that verified against an enrolled key at least once, so a
//! consumer failing to verify one has learned something real rather than
//! discovering that a publisher misconfigured their signer months ago.
//!
//! The server is not a trust anchor here. It cannot forge a signature — it has
//! no private key — and a consumer verifies against the key it pinned, not
//! against this server's opinion. Verification here is admission control, not
//! authority.

use anyhow::{Result, anyhow, bail};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use zed_interfaces::signing::{
    DetachedSignatureV1, ED25519_PUBLIC_KEY_BYTES, ED25519_SIGNATURE_BYTES, PublisherKeyV1,
    SIGNING_ALGORITHM,
};

/// Verify that at least one signature was made by a key that may sign.
///
/// Returns the key that verified, so the caller can record which one did.
pub fn verify_any<'a>(
    preimage: &[u8],
    signatures: &[DetachedSignatureV1],
    keys: &'a [PublisherKeyV1],
) -> Result<&'a PublisherKeyV1> {
    if signatures.is_empty() {
        bail!("no signature supplied");
    }
    if keys.is_empty() {
        bail!("this org has no enrolled signing keys; run `zed key enroll` first");
    }
    let mut last: Option<String> = None;
    for signature in signatures {
        if signature.algorithm != SIGNING_ALGORITHM {
            last = Some(format!("unsupported algorithm `{}`", signature.algorithm));
            continue;
        }
        let Some(key) = keys
            .iter()
            .filter(|candidate| candidate.state.verifies())
            .find(|candidate| candidate.key_id == signature.key_id)
        else {
            last = Some(format!(
                "no enrolled, non-revoked key named `{}`",
                signature.key_id
            ));
            continue;
        };
        match verify_one(preimage, signature, key) {
            Ok(()) => return Ok(key),
            Err(error) => last = Some(error.to_string()),
        }
    }
    Err(anyhow!(
        "{}",
        last.unwrap_or_else(|| "no signature verified".to_owned())
    ))
}

fn verify_one(
    preimage: &[u8],
    signature: &DetachedSignatureV1,
    key: &PublisherKeyV1,
) -> Result<()> {
    let public: [u8; ED25519_PUBLIC_KEY_BYTES] = key
        .public_key()
        .map_err(|error| anyhow!("key `{}` is unusable: {error}", key.key_id))?;
    let verifying = VerifyingKey::from_bytes(&public)
        .map_err(|_| anyhow!("key `{}` is not a valid Ed25519 point", key.key_id))?;
    let bytes: [u8; ED25519_SIGNATURE_BYTES] = signature
        .signature_bytes()
        .map_err(|error| anyhow!("malformed signature: {error}"))?;
    // Strict: small-order and non-canonical points are refused, so a single
    // signature can never be made to verify under two different keys.
    verifying
        .verify_strict(preimage, &Signature::from_bytes(&bytes))
        .map_err(|_| anyhow!("signature by `{}` does not verify", key.key_id))
}

/// Kept so the permissive path is reachable in tests without being reachable
/// in production; `Verifier` would otherwise be an unused import.
#[cfg(test)]
pub(crate) fn verify_permissive(
    preimage: &[u8],
    signature: &[u8; ED25519_SIGNATURE_BYTES],
    public: &[u8; ED25519_PUBLIC_KEY_BYTES],
) -> bool {
    VerifyingKey::from_bytes(public)
        .map(|key| {
            key.verify(preimage, &Signature::from_bytes(signature))
                .is_ok()
        })
        .unwrap_or(false)
}
