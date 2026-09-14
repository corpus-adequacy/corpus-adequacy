#!/usr/bin/env python3
"""Static selection contract for the repository-owned independent-v0 example.

This module reads data only. It does not build or execute the candidate or run
the mutation engine.
"""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SELECTION = ROOT / "measurements" / "owned-independent-v0"
MANIFEST_PATH = SELECTION / "manifest.json"
BUNDLE_PATH = SELECTION / "mutation-bundle.json"

SOURCE_COMMIT = "0e69b834aa62c7f0fb2bff331884d6ee66a97bfe"
BASE_COMMIT = "95365a731d6abdca8a43f23553d228dbcf077d27"
ORDINARY = {
    "anchor": "if value > maximum",
    "id": "upper-guard-first-overflow-only",
    "label": "truncate owned-fixture upper guard to the first value above maximum",
    "replacement": (
        "if value > maximum && value <= maximum.saturating_add(1)"
    ),
    "scope": "declared",
}
FROZEN_SHA256 = {
    "fixtures/contained-v1-owned/candidate/src/check.rs":
        "27063bf9ca3ae862121e456105c9af943bafd46dca1b9600a3603ea9a4a8c5c9",
    "fixtures/contained-v1-owned/corpus/vectors/MANIFEST.json":
        "979b9367f9662d2df45ec1078f0b4b4466e77a0dca163ea19ca2a60c44c267ec",
    "fixtures/contained-v1-owned/corpus/vectors/allow.json":
        "e1a0149d8f579ff00de0e4abe2a7aaed95a9bbb4b987a8a7b8f3e97713cb2854",
    "fixtures/contained-v1-owned/corpus/vectors/boundary.json":
        "8c80d63385a4c0e597f162d68c0407a3d03f8f37b9fd4ff1d0b136279950447a",
    "fixtures/contained-v1-owned/corpus/vectors/negative.json":
        "1dee49a803f0b1d4ce4845bac187c0640935ec03630229113d66d9e19f703bfd",
    "fixtures/contained-v1-owned/corpus/vectors/over-limit.json":
        "6161c51b4b23291fe486ad3ab8f3e83ce9809e21266846610066666200f64a5f",
    "measurements/owned-contained-v1/manifest.json":
        "d73dbef6b535bc61ecb8855a59bed8228c760fc9c978d6e26dc50b3162c8ac26",
}


def canonical_json_bytes(doc: object) -> bytes:
    return (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n").encode("utf-8")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def crlf_checkout_bytes(raw: bytes) -> bytes:
    """Simulate Git's Windows checkout form without rewriting CR-bearing input."""
    if b"\r" in raw:
        return raw
    buffer = io.BytesIO()
    with io.TextIOWrapper(buffer, encoding="utf-8", newline="\r\n") as wrapper:
        wrapper.write(raw.decode("utf-8"))
        wrapper.flush()
        return buffer.getvalue()


def canonical_checkout_bytes(path: Path) -> bytes:
    with path.open(encoding="utf-8", newline=None) as stream:
        return stream.read().encode("utf-8")


def git_blob_bytes(path: Path) -> bytes:
    relative = path.resolve().relative_to(ROOT).as_posix()
    return subprocess.check_output(
        ["git", "cat-file", "blob", "HEAD:" + relative], cwd=ROOT
    )


class OwnedIndependentV0Selection(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest_raw = MANIFEST_PATH.read_bytes()
        self.bundle_raw = BUNDLE_PATH.read_bytes()
        self.manifest = json.loads(self.manifest_raw)
        self.bundle = json.loads(self.bundle_raw)

    def test_selection_files_are_canonical_json(self):
        for path, document in (
            (MANIFEST_PATH, self.manifest),
            (BUNDLE_PATH, self.bundle),
        ):
            with self.subTest(path=path.name):
                blob = git_blob_bytes(path)
                self.assertNotIn(b"\r", blob)
                self.assertEqual(blob, canonical_json_bytes(document))
                self.assertEqual(canonical_checkout_bytes(path), blob)

    def test_crlf_checkout_simulation_normalizes_to_canonical_json(self):
        for source in (MANIFEST_PATH, BUNDLE_PATH):
            with self.subTest(path=source.name), tempfile.TemporaryDirectory() as directory:
                clone = Path(directory) / source.name
                clone.write_bytes(crlf_checkout_bytes(source.read_bytes()))
                parsed = json.loads(clone.read_bytes())
                self.assertEqual(
                    canonical_checkout_bytes(clone),
                    canonical_json_bytes(parsed),
                )

    def test_manifest_has_one_positive_one_inert_and_one_ordinary_mutation(self):
        mutants = self.manifest["mutants"]["independent"]
        positive = [
            row for row in mutants
            if row.get("control") is True
            and row.get("control_polarity", "positive") == "positive"
        ]
        inert = [
            row for row in mutants
            if row.get("control") is True
            and row.get("control_polarity") == "inert"
        ]
        ordinary = [row for row in mutants if row.get("control") is not True]
        self.assertEqual(len(positive), 1)
        self.assertEqual(len(inert), 1)
        self.assertEqual(ordinary, [ORDINARY])

        declared = json.loads(
            (ROOT / "measurements/owned-contained-v1/manifest.json").read_bytes()
        )
        self.assertEqual(positive[0], declared["mutants"]["owned"][0])
        self.assertEqual(inert[0], declared["mutants"]["owned"][1])

    def test_bundle_and_manifest_share_the_one_ordinary_selection(self):
        ordinary = [
            row for row in self.manifest["mutants"]["independent"]
            if row.get("control") is not True
        ]
        self.assertEqual(ordinary, [self.bundle["mutation"]])
        self.assertEqual(self.bundle["mutation"], ORDINARY)

    def test_candidate_corpus_and_declared_selection_remain_at_base_bytes(self):
        for relative, expected in FROZEN_SHA256.items():
            with self.subTest(path=relative):
                self.assertEqual(sha256(ROOT / relative), expected)
        self.assertEqual(self.bundle["candidate_freeze"]["source_commit"], SOURCE_COMMIT)
        self.assertEqual(self.bundle["candidate_freeze"]["selection_base"], BASE_COMMIT)
        self.assertEqual(self.bundle["candidate_freeze"]["sha256"], FROZEN_SHA256)

    def test_execution_shape_and_observation_declarations_are_preserved(self):
        declared = json.loads(
            (ROOT / "measurements/owned-contained-v1/manifest.json").read_bytes()
        )
        self.assertEqual(self.manifest["default_group"], "independent")
        self.assertEqual(set(self.manifest["mutants"]), {"independent"})
        for field in (
            "accepted_exit_codes",
            "build",
            "diagnostic_from",
            "entrypoint_command",
            "id_key",
            "implementation",
            "implementation_sources",
            "outcome_from",
            "repo_root",
            "runner",
            "schema",
            "unproved_exit_codes",
            "vectors",
        ):
            with self.subTest(field=field):
                self.assertEqual(self.manifest[field], declared[field])
        self.assertEqual(self.manifest["outcome_from"], ["rows"])
        self.assertEqual(self.manifest["diagnostic_from"], ["diagnostics"])
        self.assertEqual(self.manifest["implementation"], "subject/src/check.rs")
        self.assertEqual(self.manifest["vectors"], "corpus/vectors/MANIFEST.json")

    def test_selection_records_descriptive_independent_authorship_before_execution(self):
        self.assertEqual(self.bundle["authoring"], {
            "candidate_builder": "Rul1an",
            "candidate_outcomes_seen": False,
            "mutation_author": "Codex delegated selection writer",
            "relationship": "independent",
        })
        self.assertEqual(
            self.bundle["authorship_non_claim"],
            "Names are descriptive and unauthenticated.",
        )
        self.assertEqual(self.bundle["execution_observed"], False)

    def test_frozen_selection_excludes_the_boundary_killing_replacement(self):
        replacement = self.bundle["mutation"]["replacement"]
        self.assertEqual(replacement, ORDINARY["replacement"])
        self.assertNotEqual(replacement, "if value >= maximum")
        self.assertEqual(self.bundle["conceptual_counterexample"], {
            "included_in_corpus": False,
            "maximum": 10,
            "value": 12,
        })


if __name__ == "__main__":
    unittest.main()
