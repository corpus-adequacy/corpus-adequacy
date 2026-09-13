#!/usr/bin/env python3
"""Closed batch projection for the repository-owned contained-v1 fixture."""

from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import corpus_adequacy as ca  # noqa: E402


def expected_ids(vectors) -> list[str]:
    path = Path(vectors)
    manifest = path if path.is_file() else path / "MANIFEST.json"
    doc = ca._parse_projection_json(ca.read_bounded_regular_file(manifest))
    rows = doc.get("vectors")
    if type(rows) is not list:
        raise ValueError("manifest vectors")
    ids = []
    for row in rows:
        if type(row) is not dict or not isinstance(row.get("id"), str) or not row["id"]:
            raise ValueError("manifest id")
        ids.append(row["id"])
    if not ids or len(ids) != len(set(ids)):
        raise ValueError("manifest ids")
    return ids


def project(doc: dict, expected: list[str]) -> dict:
    if type(doc) is not dict or type(doc.get("vectors")) is not list:
        raise ValueError("candidate vectors")
    if not expected or len(expected) != len(set(expected)):
        raise ValueError("expected ids")
    actual = {}
    required = {"accepted", "detail", "id", "reason"}
    for row in doc["vectors"]:
        if type(row) is not dict or set(row) != required:
            raise ValueError("candidate row shape")
        row_id = row["id"]
        if (not isinstance(row_id, str) or not row_id or row_id in actual or
                type(row["accepted"]) is not bool or
                not isinstance(row["reason"], str) or
                not isinstance(row["detail"], str)):
            raise ValueError("candidate row")
        actual[row_id] = row
    if set(actual) != set(expected):
        raise ValueError("candidate id set")
    rows = {}
    diagnostics = {}
    for row_id in sorted(actual):
        row = actual[row_id]
        # Reason is part of the owner-declared outcome, not a diagnostic substitute.
        rows[row_id] = {"accepted": row["accepted"], "reason": row["reason"]}
        diagnostics[row_id] = {"detail": row["detail"]}
    return {"rows": rows, "diagnostics": diagnostics}


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        return 2
    try:
        expected = expected_ids(argv[1])
        raw = ca.read_bounded_regular_file(Path(argv[2]))
        result = project(ca._parse_projection_json(raw), expected)
    except (ca.ManifestError, OSError, TypeError, ValueError):
        return 75
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
