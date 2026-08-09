#!/usr/bin/env python3
"""Declare canonical contexts explicitly in legacy SQLite fixtures."""

from pathlib import Path

for relative in (
    "src/routes/audit.rs",
    "src/routes/orgs.rs",
    "src/routes/publish.rs",
    "src/routes/yank.rs",
):
    path = Path(relative)
    text = path.read_text()
    old = "            db,\n            store:"
    if text.count(old) != 1:
        raise SystemExit(f"{path}: expected exactly one legacy AppState fixture")
    path.write_text(
        text.replace(
            old,
            "            db,\n"
            "            registry_read: None,\n"
            "            registry_write: None,\n"
            "            store:",
            1,
        )
    )
