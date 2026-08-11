#!/usr/bin/env python3
"""One-shot branch integration for binary upload verification."""

from __future__ import annotations

import os
from pathlib import Path

OLD = os.environ["OLD_INTERFACES_REV"]
NEW = os.environ["INTERFACES_REV"]


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text()
    if old not in text:
        if new in text:
            return
        raise SystemExit(f"{label} marker not found in {path}")
    path.write_text(text.replace(old, new, 1))


cargo = Path("Cargo.toml")
text = cargo.read_text()
if OLD in text:
    cargo.write_text(text.replace(OLD, NEW))
elif NEW not in text:
    raise SystemExit("Cargo.toml zed-interfaces revision marker not found")

replace_once(
    Path("src/main.rs"),
    "mod auth;\n",
    "mod auth;\nmod binary_artifact;\n",
    "binary_artifact module",
)

publish = Path("src/routes/publish.rs")
text = publish.read_text()
marker = '''    if actual_sha != meta.sha256 {
        return Err(ApiErr::bad_request(
            "sha256_mismatch",
            format!(
                "client declared {}, server computed {actual_sha}",
                meta.sha256
            ),
        ));
    }

'''
addition = marker + '''    let actual_size = artifact.len() as u64;
    if actual_size != meta.size {
        return Err(ApiErr::bad_request(
            "artifact_size_mismatch",
            format!(
                "client declared {} bytes, server received {actual_size}",
                meta.size
            ),
        ));
    }

    if let Some(descriptor) = crate::binary_artifact::verify_publish(&meta, &artifact)
        .map_err(|error| ApiErr::bad_request("invalid_binary_artifact", error.to_string()))?
    {
        tracing::info!(
            org = %m.org,
            name = %m.name,
            version = %m.version,
            target = %descriptor.platform.target,
            files = descriptor.files.len(),
            "verified self-describing binary ZIP before publication"
        );
    }

'''
if "verified self-describing binary ZIP before publication" not in text:
    if marker not in text:
        raise SystemExit("publish verification insertion marker not found")
    text = text.replace(marker, addition, 1)
publish.write_text(text)
