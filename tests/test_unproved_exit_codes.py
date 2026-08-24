#!/usr/bin/env python3
"""Declared-unproved exits: classify before parse, never a favourable kill."""

from __future__ import annotations

import inspect
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import corpus_adequacy as ca  # noqa: E402
from test_corpus_adequacy import (  # noqa: E402
    BatchRunner,
    KILLABLE,
    VALID_CHILD_JSON,
    _completed,
    _manifest,
    _policy_manifest,
)

UNPROVED_JSON = json.dumps({"ok": False, "failures": ["inner-timeout"]})
MOVED_JSON = json.dumps({"ok": False, "failures": ["c2"]})


class UnprovedExitPolicy(unittest.TestCase):
    """Load-time: unique nonnegative ints, default empty, disjoint from accepted."""

    def _load(self, extra, runner="batch"):
        with tempfile.TemporaryDirectory() as d:
            return ca.load_manifest(_policy_manifest(Path(d), extra, runner=runner))

    def _refuse(self, extra, runner="batch"):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ca.ManifestError) as cm:
                ca.load_manifest(_policy_manifest(Path(d), extra, runner=runner))
        return str(cm.exception)

    def test_default_unproved_exit_codes_is_empty(self):
        loaded = self._load({})
        self.assertEqual(loaded["unproved_exit_codes"], [])

    def test_declared_unproved_code_loads(self):
        loaded = self._load({"unproved_exit_codes": [75]})
        self.assertEqual(loaded["unproved_exit_codes"], [75])
        self.assertEqual(loaded["accepted_exit_codes"], [0])

    def test_overlap_with_accepted_is_a_manifest_error(self):
        msg = self._refuse({"accepted_exit_codes": [0, 1], "unproved_exit_codes": [1]})
        self.assertIn("unproved_exit_codes", msg)
        self.assertIn("accepted_exit_codes", msg)

    def test_bool_true_is_a_manifest_error(self):
        msg = self._refuse({"unproved_exit_codes": [True]})
        self.assertIn("unproved_exit_codes", msg)
        self.assertIn("bool", msg)

    def test_a_negative_code_is_a_manifest_error(self):
        msg = self._refuse({"unproved_exit_codes": [0, -9]})
        self.assertIn("unproved_exit_codes", msg)

    def test_a_duplicate_code_is_a_manifest_error(self):
        msg = self._refuse({"unproved_exit_codes": [75, 75]})
        self.assertIn("unproved_exit_codes", msg)

    def test_a_non_integer_is_a_manifest_error(self):
        msg = self._refuse({"unproved_exit_codes": ["75"]})
        self.assertIn("unproved_exit_codes", msg)

    def test_none_is_not_a_declarable_code_list(self):
        msg = self._refuse({"unproved_exit_codes": None})
        self.assertIn("unproved_exit_codes", msg)

    def test_unproved_exit_codes_on_module_is_a_manifest_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = _manifest(Path(d), {"a": [KILLABLE]}, raw={
                "runner": "module", "unproved_exit_codes": [75]})
            with self.assertRaises(ca.ManifestError) as cm:
                ca.load_manifest(p)
        msg = str(cm.exception)
        self.assertIn("unproved_exit_codes", msg)
        self.assertIn("not implemented for runner=module", msg)

    def test_accepted_and_unproved_share_one_validator(self):
        acc = inspect.getsource(ca.accepted_exit_codes)
        unp = inspect.getsource(ca.unproved_exit_codes)
        self.assertIn("_unique_nonneg_exit_codes(", acc)
        self.assertIn("_unique_nonneg_exit_codes(", unp)
        for src in (acc, unp):
            self.assertNotIn("type(value) is bool", src,
                             "integer walk belongs in the shared helper")


class ClassifyDeclaredUnproved(unittest.TestCase):
    """One classifier: unproved is an exit class, decided before stdout."""

    def test_declared_code_is_unproved_not_unexpected_exit(self):
        self.assertEqual(ca.classify(75, [0], [75]), "unproved")

    def test_undeclared_positive_stays_unexpected_exit(self):
        self.assertEqual(ca.classify(75, [0], []), "unexpected-exit")
        self.assertEqual(ca.classify(1, [0], [75]), "unexpected-exit")

    def test_accepted_code_stays_ok(self):
        self.assertEqual(ca.classify(0, [0], [75]), "ok")

    def test_signal_is_signal_even_if_listed_as_unproved(self):
        self.assertEqual(ca.classify(-9, [0], [75, -9]), "signal")

    def test_none_is_incomplete_even_if_unproved_is_malformed(self):
        self.assertEqual(ca.classify(None, [0], [75]), "incomplete")
        self.assertEqual(ca.classify(None, [0], [True]), "incomplete")


class ChildOutcomeDoesNotParseUnproved(unittest.TestCase):
    """Valid JSON on a declared-unproved exit is not an outcome."""

    def _m(self, **fields):
        m = {"runner": "process", "outcome_from": ["ok", "failures"],
             "accepted_exit_codes": [0], "unproved_exit_codes": [75]}
        m.update(fields)
        return m

    def test_valid_json_on_unproved_exit_is_not_read(self):
        value, diag, kind = ca.child_outcome(self._m(), _completed(75, UNPROVED_JSON))
        self.assertIsNone(value)
        self.assertIsNone(diag)
        self.assertEqual(kind, "unproved")

    def test_json_loads_is_not_called_on_unproved_exit(self):
        with mock.patch.object(json, "loads", side_effect=AssertionError("parsed")):
            value, _diag, kind = ca.child_outcome(
                self._m(), _completed(75, UNPROVED_JSON))
        self.assertIsNone(value)
        self.assertEqual(kind, "unproved")

    def test_accepted_zero_with_valid_json_still_parses(self):
        value, _diag, kind = ca.child_outcome(self._m(), _completed(0))
        self.assertEqual(kind, None)
        self.assertEqual(value, (True, []))

    def test_process_and_batch_share_child_outcome(self):
        for fn in (ca._batch_outcome, ca._process_outcomes):
            src = inspect.getsource(fn)
            self.assertIn("child_outcome(", src)
            self.assertNotIn("json.loads", src)
        src = inspect.getsource(ca.child_outcome)
        self.assertIn("unproved_exit_codes", src)
        self.assertLess(src.index("classify("), src.index("json.loads"))


class DeclaredUnprovedRunSemantics(unittest.TestCase):
    """Baseline voids; control is control-error; ordinary mutant is unproved."""

    def _fake_batch(self, *, baseline_rc=0, mutant_rc=0, control_rc=0,
                    mutant_stdout=None, control_stdout=None):
        def fake(cmd, cwd, timeout):
            src = Path(cwd, "check.py").read_text(encoding="utf-8")
            if "'ok': 'MOVED'" in src:
                return _completed(control_rc, control_stdout or MOVED_JSON)
            if "c['n'] > 1" in src and "c['n'] > 10" not in src:
                return _completed(mutant_rc, mutant_stdout or VALID_CHILD_JSON)
            return _completed(baseline_rc, VALID_CHILD_JSON)
        return fake

    def _batch(self, tmp: Path) -> Path:
        p = BatchRunner()._corpus(tmp)
        raw = json.loads(p.read_text(encoding="utf-8"))
        raw["unproved_exit_codes"] = [75]
        p.write_text(json.dumps(raw), encoding="utf-8")
        return p

    def _process_two_vectors(self, tmp: Path) -> Path:
        (tmp / "check.py").write_text("print('x')\n")
        (tmp / "v1.json").write_text("{}\n")
        (tmp / "v2.json").write_text("{}\n")
        (tmp / "vectors.json").write_text(json.dumps({
            "vectors": [
                {"vector_id": "v1", "path": "v1.json"},
                {"vector_id": "v2", "path": "v2.json"},
            ]}))
        raw = {
            "schema": ca.SCHEMA, "runner": "process", "repo_root": ".",
            "implementation": "check.py", "implementation_sources": ["check.py"],
            "build": [],
            "entrypoint_command": [sys.executable, "check.py", "{vector}"],
            "outcome_from": ["ok", "failures"], "vectors": "vectors.json",
            "id_key": "vector_id", "vector_path_key": "path", "default_group": "g",
            "unproved_exit_codes": [75],
            "mutants": {"g": [
                {"label": "threshold",
                 "anchor": "print('x')", "replacement": "print('y')"},
                {"label": "CONTROL", "control": True,
                 "anchor": "print", "replacement": "print  # c"}]}}
        p = tmp / "m.json"
        p.write_text(json.dumps(raw), encoding="utf-8")
        return p

    def _fake_process_mixed(self, *, other_rc=0, other_stdout=MOVED_JSON):
        def fake(cmd, cwd, timeout):
            src = Path(cwd, "check.py").read_text(encoding="utf-8")
            argv = " ".join(str(x) for x in cmd)
            if "# c" in src:
                return _completed(0, MOVED_JSON)
            if "print('y')" in src:
                if "v2.json" in argv:
                    return _completed(75, UNPROVED_JSON)
                return _completed(other_rc, other_stdout)
            return _completed(0, VALID_CHILD_JSON)
        return fake

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_batch_ordinary_unproved_exit_is_unproved_not_killed(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._batch(Path(d))
            with mock.patch.object(
                    ca, "_run_capped",
                    side_effect=self._fake_batch(mutant_rc=75, mutant_stdout=UNPROVED_JSON)):
                rep = ca.run(p)
        row = next(r for r in rep["mutants"] if r["label"] == "threshold")
        self.assertEqual(row["verdict"], "unproved")
        self.assertEqual(row["moved"], 0)
        self.assertEqual(rep["killed"], 0)
        self.assertEqual(rep["unproved"], 1)
        self.assertFalse(rep["adequate"])
        self.assertIsNone(rep["score_percent"])

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_batch_baseline_unproved_exit_voids_the_score(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._batch(Path(d))
            with mock.patch.object(
                    ca, "_run_capped",
                    side_effect=self._fake_batch(baseline_rc=75)):
                rep = ca.run(p)
        self.assertTrue(any("UNMUTATED" in f for f in rep["failures"]), rep["failures"])
        self.assertIsNone(rep["score_percent"])
        self.assertEqual(rep["killed"], 0)
        self.assertFalse(rep["adequate"])

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_batch_control_unproved_exit_is_control_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._batch(Path(d))
            with mock.patch.object(
                    ca, "_run_capped",
                    side_effect=self._fake_batch(control_rc=75)):
                rep = ca.run(p)
        row = next(r for r in rep["mutants"] if r["label"] == "CONTROL")
        self.assertEqual(row["verdict"], "control-error")
        self.assertEqual(rep["control_status"], "error")
        self.assertIn("unproved", row["how"])
        self.assertEqual(rep["killed"], 0)
        self.assertIsNone(rep["score_percent"])
        self.assertFalse(rep["adequate"])

    def _assert_whole_mutant_unproved(self, rep):
        row = next(r for r in rep["mutants"] if r["label"] == "threshold")
        self.assertEqual(row["verdict"], "unproved")
        self.assertEqual(row["moved"], 0)
        self.assertEqual(rep["killed"], 0)
        self.assertEqual(rep["unproved"], 1)
        self.assertFalse(rep["adequate"])

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_process_mixed_moved_and_unproved_is_unproved_not_killed(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._process_two_vectors(Path(d))
            with mock.patch.object(ca, "_run_capped", side_effect=self._fake_process_mixed()):
                rep = ca.run(p)
        self._assert_whole_mutant_unproved(rep)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_process_mixed_unexpected_exit_and_unproved_is_unproved(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._process_two_vectors(Path(d))
            with mock.patch.object(
                    ca, "_run_capped",
                    side_effect=self._fake_process_mixed(other_rc=1)):
                rep = ca.run(p)
        self._assert_whole_mutant_unproved(rep)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_host_unexpected_exit_on_ordinary_mutant_stays_killed(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._batch(Path(d))
            with mock.patch.object(
                    ca, "_run_capped",
                    side_effect=self._fake_batch(mutant_rc=1)):
                rep = ca.run(p)
        row = next(r for r in rep["mutants"] if r["label"] == "threshold")
        self.assertEqual(row["verdict"], "killed")
        self.assertIn("unexpected-exit", row["how"])

    def test_mutation_unproved_must_not_fall_through_as_unexpected_exit(self):
        src = inspect.getsource(ca.classify)
        self.assertIn("return \"unproved\"", src)
        self.assertLess(src.index("return \"ok\""), src.index("return \"unproved\""))
        self.assertLess(
            src.index("return \"unproved\""), src.index("return \"unexpected-exit\""))

    def test_mutation_unproved_must_not_reach_stdout_parse(self):
        src = inspect.getsource(ca.child_outcome)
        self.assertIn("unproved_exit_codes", src)
        self.assertLess(src.index("unproved_exit_codes"), src.index("json.loads"))

    def test_only_observed_child_termination_can_be_a_mutation_kill(self):
        for kind in ("timeout", "output-cap", "unexpected-exit", "signal"):
            with self.subTest(kind=kind):
                self.assertTrue(ca._child_failure_is_termination(kind))
        for kind in ("unproved", "incomplete", "no-result", "parse-error"):
            with self.subTest(kind=kind):
                self.assertFalse(ca._child_failure_is_termination(kind))

    UNPROVED_0_1_2_BLOCK = (
        "Opt-in `unproved_exit_codes` beside `accepted_exit_codes` (default `[]`,\n"
        "disjoint). `accepted_exit_codes` stays default `[0]`. A declared-unproved child exit is classified before stdout is\n"
        "parsed and never becomes a projected outcome. An ordinary mutant with any\n"
        "such exit is `unproved` (`killed == 0`, `moved == 0`), including when\n"
        "another process vector moved. Baseline voids; control is `control-error`.\n"
        "Host-child timeout, signal, output-cap and unexpected-exit are unchanged.\n"
        "Module unusable protocol remains `unproved`. Process/batch parse-error and\n"
        "incomplete keep their existing disposition; only a declared\n"
        "`unproved_exit_codes` exit on a living adapter is the new `unproved` class.\n"
        "A module manifest that declares the field is refused.\n"
        "This names adapter-declared inner incompleteness; it does not infer why\n"
        "the inner checker failed and does not turn a host-child crash into\n"
        "`unproved`. No new report verdict.\n"
    )

    def test_docs_state_runner_specific_protocol_dispositions(self):
        root = Path(__file__).resolve().parent.parent
        readme = (root / "README.md").read_text(encoding="utf-8")
        changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
        overclaim = (
            "an unusable protocol result (empty output, parse error, incomplete) "
            "is unproved and never a kill")
        self.assertNotIn(overclaim, readme)
        self.assertIn("On the module runner, an unusable protocol result", readme)
        self.assertIn(
            "On process and batch, a declared `unproved_exit_codes`", readme)
        self.assertIn("parse-error", readme)
        self.assertIn("incomplete", readme)
        self.assertIn("existing", readme)
        block = self.UNPROVED_0_1_2_BLOCK
        self.assertIn(block, changelog)
        inverted = block.replace(
            "incomplete keep their existing disposition",
            "incomplete do not keep their existing disposition")
        self.assertIn("parse-error", inverted)
        self.assertIn("Process/batch", inverted)
        self.assertIn("unproved_exit_codes", inverted)
        self.assertIn("existing disposition", inverted)
        self.assertNotEqual(inverted, block)
        self.assertNotIn(inverted, changelog)


class CoreUnprovedReasonContract(unittest.TestCase):
    """Closed unproved tokens live on corpus_adequacy, not a measurement module."""

    @unittest.skipIf(ca.fcntl is None, "process scoring requires an advisory lock")
    def test_unproved_suffix_without_measurement_common(self):
        saved = sys.modules.get("aee_checker_sealed_common")
        sys.modules["aee_checker_sealed_common"] = None
        try:
            with tempfile.TemporaryDirectory() as d:
                tmp = Path(d)
                (tmp / "check.py").write_text("print('x')\n", encoding="utf-8")
                (tmp / "v1.json").write_text("{}\n", encoding="utf-8")
                (tmp / "vectors.json").write_text(json.dumps({
                    "vectors": [{"vector_id": "v1", "path": "v1.json"}],
                }), encoding="utf-8")
                raw = {
                    "schema": ca.SCHEMA, "runner": "process", "repo_root": ".",
                    "implementation": "check.py",
                    "implementation_sources": ["check.py"],
                    "build": [],
                    "entrypoint_command": [sys.executable, "check.py", "{vector}"],
                    "outcome_from": ["ok"], "vectors": "vectors.json",
                    "id_key": "vector_id", "vector_path_key": "path",
                    "default_group": "g",
                    "unproved_exit_codes": [75],
                    "mutants": {"g": [
                        {"label": "threshold",
                         "anchor": "print('x')", "replacement": "print('y')"},
                        {"label": "CONTROL", "control": True,
                         "anchor": "print", "replacement": "print  # c"},
                    ]},
                }
                manifest_path = tmp / "m.json"
                manifest_path.write_text(json.dumps(raw), encoding="utf-8")
                loaded = ca.load_manifest(manifest_path)

                def backend(manifest, vectors, rebuild=True):
                    if not vectors:
                        return ca._ProcessExecution(True, "built", {}, {}, {}, {})
                    return ca._ProcessExecution(
                        True, "timeout", {}, {}, {"<batch>": "unproved"}, {})

                report = ca._run_process(
                    loaded, manifest_path, execution_backend=backend,
                    separate_build_phase=True)
        finally:
            if saved is None:
                sys.modules.pop("aee_checker_sealed_common", None)
            else:
                sys.modules["aee_checker_sealed_common"] = saved
        self.assertTrue(
            any("failed (unproved) [timeout] on" in item
                for item in report["failures"]),
            report["failures"])

if __name__ == "__main__":
    unittest.main()
