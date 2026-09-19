#!/usr/bin/env python3
"""The published G feasibility probe stays honest and runnable (#270).

The probe is not evidence and nothing here runs cargo. These tests keep its label, its location
and its mutants tied to the fixture it describes, so the published output cannot silently stop
describing the published code.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROBE_DIR = ROOT / "docs" / "design" / "g-feasibility-probe"
CHECK_RS = ROOT / "fixtures" / "contained-v1-owned" / "candidate" / "src" / "check.rs"


def _probe_constants() -> dict:
    tree = ast.parse((PROBE_DIR / "g_probe.py").read_text(encoding="utf-8"))
    names = {"LOWER", "UPPER", "SENTINEL", "MUTANTS", "CORPUS", "PUBLISHED_COUNTEREXAMPLE"}
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in names:
                values[target.id] = node.value
    return values


class TheProbeIsLabelledAndPlaced(unittest.TestCase):
    def test_it_says_it_is_not_evidence_everywhere_it_is_read(self):
        self.assertIn("NOT EVIDENCE", (PROBE_DIR / "g_probe.py").read_text(encoding="utf-8"))
        self.assertIn("**This probe is not evidence.**",
                      (PROBE_DIR / "README.md").read_text(encoding="utf-8"))
        doc = (ROOT / "docs" / "suggestion-admission-v0.md").read_text(encoding="utf-8")
        self.assertIn("It is not evidence and no\nrecord derives from it.", doc)

    def test_it_is_not_under_measurements(self):
        self.assertFalse(list((ROOT / "measurements").rglob("g_probe.py")))

    def test_the_recorded_verdict_is_the_one_the_docs_state(self):
        output = (PROBE_DIR / "PROBE-OUTPUT.txt").read_text(encoding="utf-8")
        self.assertTrue(output.rstrip().endswith("VERDICT: template-exhausted"))
        self.assertIn("`template-exhausted`",
                      (ROOT / "docs" / "suggestion-admission-v0.md").read_text(encoding="utf-8"))


def _probe_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("g_probe", PROBE_DIR / "g_probe.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # defines only; main() runs cargo and is not called
    return module


class TheTemplateIsTheOneRecorded(unittest.TestCase):
    def test_the_template_vectors_are_the_ones_in_the_output_and_the_readme(self):
        vectors = sorted(_probe_module().template_vectors().values())
        output = (PROBE_DIR / "PROBE-OUTPUT.txt").read_text(encoding="utf-8")
        self.assertEqual(output.splitlines()[0],
                         "template vectors (%d): %s" % (len(vectors), vectors))
        self.assertEqual(len(vectors), 7)
        self.assertIn("seven-vector", (PROBE_DIR / "README.md").read_text(encoding="utf-8"))


class TheProbeStillDescribesTheFixture(unittest.TestCase):
    def setUp(self):
        self.check = CHECK_RS.read_text(encoding="utf-8")
        self.constants = _probe_constants()

    def _literal(self, name):
        return ast.literal_eval(self.constants[name])

    def test_every_mutant_anchor_occurs_exactly_once_in_the_candidate(self):
        anchors = {"LOWER": self._literal("LOWER"), "UPPER": self._literal("UPPER"),
                   "SENTINEL": self._literal("SENTINEL")}
        for name, anchor in anchors.items():
            with self.subTest(anchor=name):
                self.assertEqual(self.check.count(anchor), 1)
        mutants = self.constants["MUTANTS"]
        self.assertIsInstance(mutants, ast.Dict)
        self.assertEqual(len(mutants.keys), 8)
        for value in mutants.values:
            self.assertIsInstance(value, ast.Tuple)
            self.assertIn(value.elts[0].id, anchors)

    def test_the_sentinel_guard_is_after_the_negative_guard_so_it_is_dead(self):
        self.assertLess(self.check.index("if value < 0 {"),
                        self.check.index("if value == i64::MIN {"))

    def test_the_probe_corpus_is_the_fixtures_corpus(self):
        import json
        vectors = ROOT / "fixtures" / "contained-v1-owned" / "corpus" / "vectors"
        on_disk = {path.stem: json.loads(path.read_text(encoding="utf-8"))["value"]
                   for path in vectors.glob("*.json") if path.name != "MANIFEST.json"}
        self.assertEqual(self._literal("CORPUS"), on_disk)

    def test_the_frozen_corpus_and_counterexample_are_the_ones_the_output_names(self):
        output = (PROBE_DIR / "PROBE-OUTPUT.txt").read_text(encoding="utf-8")
        corpus = sorted(self._literal("CORPUS").values())
        example = sorted(self._literal("PUBLISHED_COUNTEREXAMPLE").values())
        self.assertIn("frozen corpus: %s   published counterexample: %s" % (corpus, example),
                      output)


if __name__ == "__main__":
    unittest.main()
