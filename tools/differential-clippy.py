#!/usr/bin/env python3
"""Fail when a pull request adds Clippy/rustc warning diagnostics.

The repository intentionally carries historical lint debt. A global
`-D warnings` therefore prevents unrelated, otherwise-correct changes from
being reviewed or merged. This comparator preserves the strict no-new-debt
property without hiding the existing diagnostics:

- run the exact same Clippy command on the PR base and head;
- parse Cargo JSON compiler messages;
- compare warning fingerprints as a multiset;
- fail on every positive head-minus-base delta.

Line numbers are intentionally excluded from the fingerprint so inserting code
above an inherited warning does not manufacture a regression. File, lint code,
and diagnostic message remain part of the identity, and repeated identical
warnings in one file retain their multiplicity.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys
from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class Fingerprint:
    code: str
    file: str
    message: str


def _primary_file(message: dict) -> str:
    spans = message.get("spans") or []
    for span in spans:
        if span.get("is_primary") and isinstance(span.get("file_name"), str):
            return span["file_name"]
    for span in spans:
        if isinstance(span.get("file_name"), str):
            return span["file_name"]
    return "<unknown>"


def read_warnings(path: pathlib.Path) -> tuple[collections.Counter[Fingerprint], dict[Fingerprint, str]]:
    counts: collections.Counter[Fingerprint] = collections.Counter()
    examples: dict[Fingerprint, str] = {}

    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise SystemExit(f"{path}:{number}: invalid Cargo JSON: {error}") from error

            if event.get("reason") != "compiler-message":
                continue
            diagnostic = event.get("message")
            if not isinstance(diagnostic, dict) or diagnostic.get("level") != "warning":
                continue

            raw_code = diagnostic.get("code")
            code = raw_code.get("code") if isinstance(raw_code, dict) else None
            fingerprint = Fingerprint(
                code=code or "<no-code>",
                file=_primary_file(diagnostic),
                message=str(diagnostic.get("message") or "<missing-message>"),
            )
            counts[fingerprint] += 1
            rendered = diagnostic.get("rendered")
            if isinstance(rendered, str):
                examples.setdefault(fingerprint, rendered.rstrip())

    return counts, examples


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True, type=pathlib.Path)
    parser.add_argument("--head", required=True, type=pathlib.Path)
    args = parser.parse_args()

    base, _ = read_warnings(args.base)
    head, head_examples = read_warnings(args.head)

    regressions: list[tuple[Fingerprint, int]] = []
    for fingerprint, head_count in head.items():
        delta = head_count - base.get(fingerprint, 0)
        if delta > 0:
            regressions.append((fingerprint, delta))

    if not regressions:
        removed = sum((base - head).values())
        print(
            "differential-clippy: pass; "
            f"base={sum(base.values())} head={sum(head.values())} "
            f"removed={removed} new=0"
        )
        return 0

    print(
        "differential-clippy: FAIL; "
        f"base={sum(base.values())} head={sum(head.values())} "
        f"new={sum(delta for _, delta in regressions)}",
        file=sys.stderr,
    )
    for fingerprint, delta in sorted(regressions):
        print(
            f"\n+{delta} [{fingerprint.code}] {fingerprint.file}: "
            f"{fingerprint.message}",
            file=sys.stderr,
        )
        example = head_examples.get(fingerprint)
        if example:
            print(example, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
