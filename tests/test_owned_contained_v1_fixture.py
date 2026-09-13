#!/usr/bin/env python3
"""Static identity checks for the repository-owned contained-v1 fixture."""

from __future__ import annotations

import json
import hashlib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "contained-v1-owned"
CANDIDATE = FIXTURE / "candidate"
CORPUS = FIXTURE / "corpus"
VECTORS = CORPUS / "vectors"
EXPECTED_IDS = ("allow", "boundary", "negative", "over-limit")
EXPECTED_FILES = {
    "candidate/Cargo.lock",
    "candidate/Cargo.toml",
    "candidate/LICENSE",
    "candidate/src/check.rs",
    "candidate/src/main.rs",
    "corpus/LICENSE",
    "corpus/vectors/MANIFEST.json",
    "corpus/vectors/allow.json",
    "corpus/vectors/boundary.json",
    "corpus/vectors/negative.json",
    "corpus/vectors/over-limit.json",
}


class OwnedContainedV1Fixture(unittest.TestCase):
    def test_inventory_is_closed_and_all_bytes_are_lf(self):
        files = {
            path.relative_to(FIXTURE).as_posix()
            for path in FIXTURE.rglob("*")
            if path.is_file() and "target" not in path.relative_to(FIXTURE).parts
        }
        self.assertEqual(files, EXPECTED_FILES)
        for relpath in sorted(files):
            self.assertNotIn(b"\r\n", (FIXTURE / relpath).read_bytes())

    def test_candidate_and_corpus_use_the_repository_mit_license(self):
        license_bytes = (ROOT / "LICENSE").read_bytes()
        self.assertEqual((CANDIDATE / "LICENSE").read_bytes(), license_bytes)
        self.assertEqual((CORPUS / "LICENSE").read_bytes(), license_bytes)

    def test_manifest_is_a_bijection_with_the_four_vector_files(self):
        manifest = json.loads((VECTORS / "MANIFEST.json").read_bytes())
        rows = manifest["vectors"]
        self.assertEqual(tuple(row["id"] for row in rows), EXPECTED_IDS)
        self.assertEqual(len({row["id"] for row in rows}), len(rows))
        self.assertEqual(
            {row["file"] for row in rows},
            {path.name for path in VECTORS.glob("*.json")} - {"MANIFEST.json"},
        )
        self.assertEqual(
            [json.loads((VECTORS / row["file"]).read_bytes()) for row in rows],
            [{"value": 5}, {"value": 10}, {"value": -1}, {"value": 11}],
        )

        digest = hashlib.sha256()
        for row in rows:
            digest.update(row["file"].encode("utf-8"))
            digest.update(b"\0")
            digest.update((VECTORS / row["file"]).read_bytes())
        self.assertEqual(manifest["corpusDigest"], digest.hexdigest())

    def test_source_exposes_the_two_rules_and_one_inert_anchor(self):
        source = (CANDIDATE / "src" / "check.rs").read_text(encoding="utf-8")
        self.assertEqual(source.count("if value < 0"), 1)
        self.assertEqual(source.count("if value > maximum"), 1)
        self.assertEqual(source.count("if value == i64::MIN"), 1)


if __name__ == "__main__":
    unittest.main()
