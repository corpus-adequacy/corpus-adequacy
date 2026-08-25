#!/usr/bin/env python3
"""Immutable Tersign measurement at upstream pin 0e560c1 (#92)."""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
OLD = REPO_ROOT / "measurements" / "tersign-1cc5ea32"
NEW = REPO_ROOT / "measurements" / "tersign-0e560c1"
UPSTREAM_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "tersign-evidence-record-0e560c1"
CANONICAL_WRAPPER = REPO_ROOT / "measurements" / "tersign_checks.py"

PIN_COMMIT = "0e560c1ad47f08177042c62754ebe6e0b482ad9a"
PIN_MANIFEST = "40abdf703b3b731c685142aa24a2561f1cc4679a013d51fdcb9764a1658819c6"
PIN_VECTORS_TREE = "fecf642073dd6b971aebba52bb67153efb1a1dfe"
PIN_VERIFY = "8041a3cb678e8777f6565551da2b258558030b31ee0e80bf1bb1a0bf49cb5f2e"
PIN_KECCAK = "f541c8a43a288f61a147dd43accea048eb9f55a095ca3b9dbf3f88341d469190"
PIN_LICENSE = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
OLD_TREE_DIGEST = "e375d1f197b375db950220c432ebc2a93a56c71038fd838751bbce998964adee"
INTEGRAL_FLOAT = "accept integer-valued floats and serialize them as integers"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _evaluate(case: Path) -> dict:
    proc = subprocess.run(
        [sys.executable, str(NEW / "tersign_checks.py"), str(case)],
        cwd=str(NEW), capture_output=True, check=True, text=True, timeout=10)
    return json.loads(proc.stdout)


class ProducerInputs(unittest.TestCase):
    def test_historical_measurement_tree_is_immutable(self):
        self.assertEqual(_tree_digest(OLD), OLD_TREE_DIGEST)

    def test_new_pinned_implementation_and_adapter_outputs_exist(self):
        self.assertEqual(_sha(NEW / "verify.py"), PIN_VERIFY)
        self.assertEqual(_sha(NEW / "keccak.py"), PIN_KECCAK)
        self.assertEqual(_sha(NEW / "LICENSE"), PIN_LICENSE)
        self.assertEqual(
            (NEW / "tersign_checks.py").read_bytes(),
            CANONICAL_WRAPPER.read_bytes(),
        )
        source = _read_json(NEW / "source.json")
        self.assertEqual(source["commit"], PIN_COMMIT)
        self.assertEqual(source["manifest_sha256"], PIN_MANIFEST)
        self.assertEqual(source["vectors_tree"], PIN_VECTORS_TREE)
        self.assertEqual(source["counts"], {"vectors": 60, "valid": 25, "reject": 35})

    def test_manifest_reuses_the_existing_declared_inventory(self):
        self.assertEqual(
            (NEW / "manifest.json").read_bytes(),
            (OLD / "manifest.json").read_bytes(),
        )
        manifest = _read_json(NEW / "manifest.json")
        mutants = manifest["mutants"]["tersign"]
        self.assertIn(INTEGRAL_FLOAT, [row["label"] for row in mutants])
        self.assertEqual(sum(bool(row.get("control")) for row in mutants), 2)
        self.assertEqual(manifest["implementation"], "tersign_checks.py")
        self.assertEqual(
            manifest["implementation_sources"],
            ["tersign_checks.py", "verify.py", "keccak.py"],
        )

    def test_wrapper_is_dispatch_only(self):
        tree = ast.parse((NEW / "tersign_checks.py").read_text(encoding="utf-8"))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module.split(".")[0])
        self.assertNotIn("corpus_adequacy", imported)
        self.assertNotIn("bounded_run", imported)
        source = (NEW / "tersign_checks.py").read_text(encoding="utf-8")
        self.assertIn("CHECKS[kind](doc[\"input\"])", source)
        self.assertNotIn("verify.main", source)

    def test_all_60_baseline_typed_outcomes_reproduce(self):
        rows = _read_json(NEW / "vectors.json")["vectors"]
        self.assertEqual(len(rows), 60)
        for row in rows:
            with self.subTest(row["vector_id"]):
                actual = _evaluate(NEW / row["vector_path"])
                self.assertEqual(
                    actual,
                    {
                        "verdict": row["expected_verdict"],
                        "reason": row["expected_reason"],
                    },
                )

    def test_baseline_witness_calls_the_real_wrapper_process(self):
        case = NEW / "cases" / "p25-integer-token-in-text.json"
        with mock.patch.object(
                subprocess, "run", side_effect=AssertionError("wrapper process required")):
            with self.assertRaisesRegex(AssertionError, "wrapper process required"):
                _evaluate(case)

    def test_payload_text_pair_preserves_exact_source_bytes(self):
        expected = {
            "p25-integer-token-in-text": '{"amount": 2}',
            "n35-integer-valued-float-token": '{"amount": 2.0}',
        }
        for vector_id, payload_text in expected.items():
            case = NEW / "cases" / (vector_id + ".json")
            upstream = UPSTREAM_FIXTURE / "vectors" / (vector_id + ".json")
            self.assertEqual(case.read_bytes(), upstream.read_bytes())
            self.assertEqual(_read_json(case)["input"]["payload_text"], payload_text)


if __name__ == "__main__":
    unittest.main(verbosity=1)
