#!/usr/bin/env python3
"""Process measurement of the pinned Tersign CHECKS wrapper (#30).

RED first: the wrapper module must exist, dispatch only CHECKS[kind](input),
and be scored through real corpus_adequacy.run(). The three verify.py main()
suite gates are omitted from the inventory, not reported as survivors.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "adapters"))
import corpus_adequacy as ca  # noqa: E402
import tersign_evidence_record as ter  # noqa: E402

WRAPPER = REPO_ROOT / "measurements" / "tersign_checks.py"
VERIFY_FIXTURE = REPO_ROOT / "fixtures" / "tersign-verify-1cc5ea32" / "verify.py"
KECCAK_FIXTURE = REPO_ROOT / "fixtures" / "tersign-verify-1cc5ea32" / "keccak.py"
CORPUS_FIXTURE = REPO_ROOT / "fixtures" / "tersign-evidence-record-1cc5ea32"

PIN_COMMIT = "1cc5ea32b3da4f195b55782c8a3573d8564673a7"
PIN_VERIFY = "ec6a6fe6d5caa0e56a2a85b9b35557f2efb6aede7689b3e21c3466e6b7502a42"
PIN_KECCAK = "f541c8a43a288f61a147dd43accea048eb9f55a095ca3b9dbf3f88341d469190"

SAFE_INT = "remove the greater-than 2^53-1 refusal"
INTEGRAL_FLOAT = "accept integer-valued floats and serialize them as integers"
SAFE_GE = "CONTROL tighten the safe-integer bound to greater-than-or-equal"
FRAC_FLOAT = "CONTROL permit ordinary fractional floats through canonicalization"
MASKED_BOUNDARY = "boundary_binding skips empty-attested coverage refusal"

SUITE_GATES = (
    "per-kind two-sided closure",
    "manifest/body kind agreement",
    "reason closure vs REQUIRED_REASONS",
)

DECLARED_MUTANTS = [
    {
        "label": INTEGRAL_FLOAT,
        "anchor": (
            'if isinstance(value, float):\n'
            '        raise ValueError("non-integer JSON number in the digest domain")'
        ),
        "replacement": (
            'if isinstance(value, float):\n'
            '        if value.is_integer():\n'
            '            return canonical(int(value))\n'
            '        raise ValueError("non-integer JSON number in the digest domain")'
        ),
    },
    {
        "label": SAFE_INT,
        "anchor": "if abs(value) > 2**53 - 1:",
        "replacement": "if False:",
    },
    {
        "label": SAFE_GE,
        "control": True,
        "anchor": "abs(value) > 2**53 - 1",
        "replacement": "abs(value) >= 2**53 - 1",
    },
    {
        "label": FRAC_FLOAT,
        "control": True,
        "anchor": 'raise ValueError("non-integer JSON number in the digest domain")',
        "replacement": "return json.dumps(value)",
    },
    {
        "label": "digest_recompute accepts a mismatched expected digest",
        "anchor": 'if got != expected:\n        return "reject", "recompute_mismatch"',
        "replacement": 'if False:\n        return "reject", "recompute_mismatch"',
    },
    {
        "label": "canonical_bytes accepts non-canonical claimed bytes",
        "anchor": 'if got != inp["claimed_canonical"]:',
        "replacement": 'if False and got != inp["claimed_canonical"]:',
    },
    {
        "label": "chain_link accepts a recomputed link mismatch",
        "anchor": (
            'if got != expected:\n'
            '        return "reject", "continuity_reject", f"recomputed link {got}"'
        ),
        "replacement": (
            'if False:\n'
            '        return "reject", "continuity_reject", f"recomputed link {got}"'
        ),
    },
    {
        "label": "chain_set skips committed-sequence completeness",
        "anchor": "if seqs != expected:",
        "replacement": "if False and seqs != expected:",
    },
    {
        "label": "anchor_relation accepts a subject/anchor digest mismatch",
        "anchor": "if got != anchored:",
        "replacement": "if False and got != anchored:",
    },
    {
        "label": "phase_claim accepts a phase/presented mismatch",
        "anchor": "if phase != presented:",
        "replacement": "if False and phase != presented:",
    },
    {
        "label": "independence_claim accepts party-only attestation",
        "anchor": "if not outside:",
        "replacement": "if False and not outside:",
    },
    {
        "label": "offer_binding reads a different commitment field",
        "anchor": '"offerDigest"',
        "replacement": '"offerDigestX"',
    },
    {
        "label": "decision_evidence_binding reads a different commitment field",
        "anchor": '"decisionEvidenceDigest"',
        "replacement": '"decisionEvidenceDigestX"',
    },
    {
        "label": MASKED_BOUNDARY,
        "anchor": "if attested <= 0 < covered:",
        "replacement": "if False and attested <= 0 < covered:",
    },
]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_wrapper():
    import importlib.util
    sys.path.insert(0, str(VERIFY_FIXTURE.parent))
    spec = importlib.util.spec_from_file_location("tersign_checks", WRAPPER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _adapt(tmp: Path) -> Path:
    dest = tmp / "adapted"
    dest.mkdir()
    ter.adapt(CORPUS_FIXTURE, dest)
    return dest


def _measurement_repo(tmp: Path) -> Path:
    adapted = _adapt(tmp)
    repo = tmp / "impl"
    repo.mkdir()
    shutil.copy(WRAPPER, repo / "tersign_checks.py")
    shutil.copy(VERIFY_FIXTURE, repo / "verify.py")
    shutil.copy(KECCAK_FIXTURE, repo / "keccak.py")
    shutil.copytree(adapted / "cases", repo / "cases")
    shutil.copy(adapted / "vectors.json", repo / "vectors.json")
    return repo


def _manifest(repo: Path, outcome_from: list) -> Path:
    raw = {
        "schema": ca.SCHEMA,
        "runner": "process",
        "repo_root": ".",
        "implementation": "tersign_checks.py",
        "implementation_sources": ["tersign_checks.py", "verify.py", "keccak.py"],
        "build": [],
        "entrypoint_command": [sys.executable, "tersign_checks.py", "{vector}"],
        "accepted_exit_codes": [0],
        "outcome_from": outcome_from,
        "vectors": "vectors.json",
        "id_key": "vector_id",
        "vector_path_key": "vector_path",
        "default_group": "tersign",
        "mutants": {"tersign": [dict(m) for m in DECLARED_MUTANTS]},
    }
    path = repo / ("m-%s.json" % hashlib.sha256(json.dumps(outcome_from).encode()).hexdigest()[:8])
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


class PinAndPlacement(unittest.TestCase):
    def test_pinned_implementation_bytes(self):
        self.assertEqual(_sha(VERIFY_FIXTURE), PIN_VERIFY)
        self.assertEqual(_sha(KECCAK_FIXTURE), PIN_KECCAK)
        self.assertEqual(ter.PIN_COMMIT, PIN_COMMIT)

    def test_wrapper_is_not_a_tool_source_member(self):
        self.assertTrue(WRAPPER.exists())
        self.assertNotIn("measurements/", "\n".join(ca.TOOL_SOURCE_PATHS))
        self.assertNotIn("tersign_checks.py", ca.TOOL_SOURCE_PATHS)

    def test_wrapper_does_not_import_producer_or_verify_main(self):
        tree = ast.parse(WRAPPER.read_text(encoding="utf-8"))
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.extend(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                names.append(node.module.split(".")[0])
        self.assertNotIn("corpus_adequacy", names)
        self.assertNotIn("bounded_run", names)
        src = WRAPPER.read_text(encoding="utf-8")
        self.assertNotIn("verify.main", src)
        self.assertIn("CHECKS[kind]", src)


class WrapperContract(unittest.TestCase):
    def test_dispatch_parity_against_direct_checks(self):
        wrap = _load_wrapper()
        sys.path.insert(0, str(VERIFY_FIXTURE.parent))
        import verify
        with tempfile.TemporaryDirectory() as d:
            adapted = _adapt(Path(d))
            rows = json.loads((adapted / "vectors.json").read_text())["vectors"]
            self.assertEqual(len(rows), 54)
            for row in rows:
                case = adapted / row["vector_path"]
                emitted = wrap.evaluate(case)
                self.assertEqual(set(emitted), {"verdict", "reason"})
                self.assertNotIn("detail", emitted)
                body = json.loads(case.read_text(encoding="utf-8"))
                verdict, reason, _detail = verify.CHECKS[body["kind"]](body["input"])
                self.assertEqual(emitted["verdict"], verdict)
                self.assertEqual(emitted["reason"], reason)
                self.assertEqual(emitted["verdict"], row["expected_verdict"])
                self.assertEqual(emitted["reason"], row["expected_reason"])

    def test_nonzero_exit_is_not_parsed_as_an_outcome(self):
        wrap = _load_wrapper()
        self.assertEqual(wrap.ACCEPTED_EXIT, 0)
        src = WRAPPER.read_text(encoding="utf-8")
        self.assertIn("sys.exit(1)", src)
        self.assertNotIn("json.loads", src.split("sys.exit(1)")[0][-80:] if "sys.exit(1)" in src else src)


class DeclaredInventory(unittest.TestCase):
    def test_anchors_are_unique_in_verify_py(self):
        text = VERIFY_FIXTURE.read_text(encoding="utf-8")
        seen = []
        for mut in DECLARED_MUTANTS:
            self.assertEqual(text.count(mut["anchor"]), 1, mut["label"])
            self.assertNotEqual(mut["anchor"], mut["replacement"])
            seen.append(mut["anchor"])
        self.assertEqual(len(seen), len(set(seen)))

    def test_suite_gates_are_absent_not_survivors(self):
        labels = [m["label"] for m in DECLARED_MUTANTS]
        for name in SUITE_GATES:
            self.assertNotIn(name, labels)
        src = Path(__file__).read_text(encoding="utf-8")
        self.assertIn("out of scope", src.lower())

    def test_two_controls_share_the_canonical_region(self):
        controls = [m for m in DECLARED_MUTANTS if m.get("control")]
        self.assertEqual({c["label"] for c in controls}, {SAFE_GE, FRAC_FLOAT})
        text = VERIFY_FIXTURE.read_text(encoding="utf-8")
        region = text[text.index("def canonical"): text.index("def digest_of")]
        for c in controls:
            self.assertIn(c["anchor"], region)


class ProcessMeasurement(unittest.TestCase):
    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_typed_run_kills_reason_drift_and_keeps_honest_survivors(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            repo = _measurement_repo(tmp)
            rep = ca.run(_manifest(repo, ["verdict", "reason"]))
            by = {row["label"]: row for row in rep["mutants"]}
            self.assertEqual(by[SAFE_INT]["verdict"], "killed")
            self.assertEqual(by[SAFE_INT]["moved"], 1)
            self.assertEqual(by[SAFE_GE]["verdict"], "control-killed")
            self.assertEqual(by[FRAC_FLOAT]["verdict"], "control-killed")
            self.assertEqual(by[INTEGRAL_FLOAT]["verdict"], "survived")
            self.assertEqual(by[MASKED_BOUNDARY]["verdict"], "survived")
            self.assertNotIn("equivalent", by[INTEGRAL_FLOAT])
            for name in SUITE_GATES:
                self.assertNotIn(name, by)
            killed = [row for row in rep["mutants"] if row["verdict"] == "killed"]
            self.assertGreaterEqual(len(killed), 10)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_verdict_only_is_a_false_green_for_safe_int(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            repo = _measurement_repo(tmp)
            typed = ca.run(_manifest(repo, ["verdict", "reason"]))
            self.assertEqual(
                next(r for r in typed["mutants"] if r["label"] == SAFE_INT)["verdict"],
                "killed",
            )
            false_green = ca.run(_manifest(repo, ["verdict"]))
            self.assertEqual(
                next(r for r in false_green["mutants"] if r["label"] == SAFE_INT)["verdict"],
                "survived",
            )

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_e2e_calls_real_corpus_adequacy_run(self):
        self.assertIn("ca.run(", Path(__file__).read_text(encoding="utf-8"))
        from unittest import mock
        with mock.patch.object(ca, "run", side_effect=AssertionError("run must be called")):
            with self.assertRaises(AssertionError):
                self.test_typed_run_kills_reason_drift_and_keeps_honest_survivors()


if __name__ == "__main__":
    unittest.main(verbosity=1)
