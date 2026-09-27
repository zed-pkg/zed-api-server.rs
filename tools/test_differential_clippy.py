#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("differential-clippy.py")
SPEC = importlib.util.spec_from_file_location("differential_clippy", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def event(code: str, file: str, message: str, line: int) -> dict:
    return {
        "reason": "compiler-message",
        "message": {
            "level": "warning",
            "code": {"code": code},
            "message": message,
            "spans": [
                {
                    "file_name": file,
                    "line_start": line,
                    "line_end": line,
                    "column_start": 1,
                    "column_end": 2,
                    "is_primary": True,
                }
            ],
            "rendered": f"warning: {message}\n --> {file}:{line}:1\n",
        },
    }


class DifferentialClippyTest(unittest.TestCase):
    def write(self, events: list[dict]) -> pathlib.Path:
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        with handle:
            for item in events:
                handle.write(json.dumps(item) + "\n")
        return pathlib.Path(handle.name)

    def test_line_moves_do_not_create_regressions(self) -> None:
        base = self.write([event("unreachable_pub", "src/lib.rs", "unreachable pub item", 10)])
        head = self.write([event("unreachable_pub", "src/lib.rs", "unreachable pub item", 99)])
        self.assertEqual(MODULE.read_warnings(base)[0], MODULE.read_warnings(head)[0])

    def test_multiplicity_is_preserved(self) -> None:
        base = self.write([event("unwrap_used", "src/lib.rs", "used unwrap", 10)])
        head = self.write(
            [
                event("unwrap_used", "src/lib.rs", "used unwrap", 10),
                event("unwrap_used", "src/lib.rs", "used unwrap", 20),
            ]
        )
        base_counts, _ = MODULE.read_warnings(base)
        head_counts, _ = MODULE.read_warnings(head)
        fingerprint = next(iter(base_counts))
        self.assertEqual(base_counts[fingerprint], 1)
        self.assertEqual(head_counts[fingerprint], 2)

    def test_file_and_message_are_part_of_identity(self) -> None:
        base = self.write([event("unwrap_used", "src/a.rs", "used unwrap", 10)])
        head = self.write([event("unwrap_used", "src/b.rs", "used unwrap", 10)])
        self.assertNotEqual(MODULE.read_warnings(base)[0], MODULE.read_warnings(head)[0])


if __name__ == "__main__":
    unittest.main()
