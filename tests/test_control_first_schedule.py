#!/usr/bin/env python3
"""Control-first schedule for the generic process/batch runner. Stdlib only.

Fake build/process call logs only. Does not run aee-checker, the frozen
corpus, or Docker. Public non-claims: not MC/DC, not atomic-subcondition
adequacy, not complete mutation adequacy, not sandbox-efficacy, not
certification, not ranking.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import corpus_adequacy as ca  # noqa: E402

SEALED_IDS = tuple("sealed-%d" % i for i in range(1, 8))
SOURCE = "TOKENS = {ctrl}\n" + "".join("X%d = {a%d}\n" % (i, i) for i in range(1, 8))


def _aee_spec():
    ordinary = [
        {"label": "sealed-%d" % i, "anchor": "{a%d}" % i, "replacement": "{r%d}" % i}
        for i in range(1, 8)
    ]
    return ordinary + [{
        "label": "CONTROL",
        "control": True,
        "anchor": "{ctrl}",
        "replacement": "{ctrl_x}",
    }]


def _labels(plan):
    return [mut["label"] for _, mut in plan]


def _identify(src: str) -> str:
    if "{ctrl_x}" in src:
        return "CONTROL"
    for i in range(1, 8):
        if "{r%d}" % i in src:
            return "sealed-%d" % i
    for token, name in (("{ra}", "ord-a"), ("{rz}", "ord-z"),
                        ("{ca_x}", "ctrl-a"), ("{cz_x}", "ctrl-z")):
        if token in src:
            return name
    return "baseline"


class PartitionHelper(unittest.TestCase):
    def test_frozen_aee_plan_is_control_then_seven(self):
        controls, ordinary = ca.partition_declared_mutants({"g": _aee_spec()})
        self.assertEqual(_labels(controls), ["CONTROL"])
        self.assertEqual(_labels(ordinary), list(SEALED_IDS))

    def test_multi_group_barrier_is_global_not_per_group(self):
        mutants = {
            "z": [{"label": "ord-z"}, {"label": "ctrl-z", "control": True}],
            "a": [{"label": "ord-a"}, {"label": "ctrl-a", "control": True}],
        }
        controls, ordinary = ca.partition_declared_mutants(mutants)
        self.assertEqual(
            [(group, mut["label"]) for group, mut in controls],
            [("a", "ctrl-a"), ("z", "ctrl-z")],
        )
        self.assertEqual(
            [(group, mut["label"]) for group, mut in ordinary],
            [("a", "ord-a"), ("z", "ord-z")],
        )

    def test_no_control_preserves_sorted_group_then_declaration_order(self):
        mutants = {
            "z": [{"label": "z1"}, {"label": "z2"}],
            "a": [{"label": "a1"}],
        }
        controls, ordinary = ca.partition_declared_mutants(mutants)
        self.assertEqual(controls, [])
        self.assertEqual(
            [(group, mut["label"]) for group, mut in ordinary],
            [("a", "a1"), ("z", "z1"), ("z", "z2")],
        )


class ControlFirstCallLog(unittest.TestCase):
    def _batch_manifest(self, tmp: Path, mutants: dict, equivalent=None) -> Path:
        (tmp / "check.py").write_text(SOURCE, encoding="utf-8")
        (tmp / "vectors.json").write_text(json.dumps({"cases": [{"id": "c1", "n": 1}]}))
        raw = {
            "schema": ca.SCHEMA,
            "runner": "batch",
            "repo_root": ".",
            "implementation_sources": ["check.py"],
            "entrypoint_command": [sys.executable, "check.py", "vectors.json"],
            "outcome_from": ["ok"],
            "vectors": "vectors.json",
            "id_key": "vector_id",
            "default_group": "g",
            "mutants": mutants,
            "equivalent": equivalent or {},
        }
        path = tmp / "m.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        return path

    def _run_logged(self, tmp: Path, mutants: dict, *, control="killed",
                    equivalent=None):
        calls = []

        def fake_build(m):
            src = Path(m["_repo_root"], "check.py").read_text(encoding="utf-8")
            name = _identify(src)
            if name != "baseline":
                calls.append(name)
            if name == "CONTROL" and control == "non-build":
                return False, "control does not build"
            return True, "built"

        def fake_outcomes(m, vectors):
            src = Path(m["_repo_root"], "check.py").read_text(encoding="utf-8")
            name = _identify(src)
            keys = [v[m["id_key"]] for v in vectors]
            if name == "baseline":
                calls.append("baseline")
                return {key: "base" for key in keys}, {}, {}
            if name == "CONTROL":
                if control == "survived":
                    return {key: "base" for key in keys}, {}, {}
                if control == "error":
                    return {}, {}, {keys[0]: "signal"}
                if control == "unproved":
                    return {}, {}, {keys[0]: "unproved"}
                return {key: "moved" for key in keys}, {}, {}
            return {key: name for key in keys}, {}, {}

        loaded = ca.load_manifest(
            self._batch_manifest(tmp, mutants, equivalent=equivalent))
        with mock.patch.object(ca, "_build", side_effect=fake_build), \
                mock.patch.object(ca, "_process_outcomes", side_effect=fake_outcomes):
            report = ca._run_process(loaded, tmp / "m.json")
        return calls, report

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_frozen_aee_call_log_is_control_then_seven(self):
        with tempfile.TemporaryDirectory() as d:
            calls, report = self._run_logged(Path(d), {"g": _aee_spec()})
        self.assertEqual(calls, ["baseline", "CONTROL", *SEALED_IDS])
        self.assertEqual(report["control_status"], "killed")
        ordinary = [row["label"] for row in report["mutants"] if row["label"] in SEALED_IDS]
        self.assertEqual(ordinary, list(SEALED_IDS))

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_invalid_control_leaves_ordinary_call_log_empty(self):
        expected = {
            "survived": "survived",
            "error": "error",
            "unproved": "error",
            "non-build": "error",
        }
        for mode, status in expected.items():
            with self.subTest(mode=mode):
                with tempfile.TemporaryDirectory() as d:
                    calls, report = self._run_logged(
                        Path(d), {"g": _aee_spec()}, control=mode)
                self.assertEqual(calls, ["baseline", "CONTROL"], mode)
                self.assertFalse(any(item in SEALED_IDS for item in calls), mode)
                self.assertEqual(report["control_status"], status, mode)
                self.assertFalse(
                    any(row["label"] in SEALED_IDS for row in report["mutants"]), mode)
                self.assertIsNone(report["score_percent"], mode)
                self._assert_invalid_control_failures(report)

    def _control_anchor_spec(self, *, anchor, replacement="{ctrl_x}"):
        spec = _aee_spec()
        spec[-1] = dict(spec[-1], anchor=anchor, replacement=replacement)
        return spec

    def _assert_invalid_control_failures(self, report):
        """An invalid control is not a null declaration / all-excluded result."""
        self.assertTrue(
            any("control" in item and (
                "survived" in item or "ended abnormally" in item)
                for item in report["failures"]),
            report["failures"])
        reading = ca.null_result_reading(
            report["known_holes"], report["equivalent"],
            report["unexercised_out_of_scope"])
        self.assertNotIn(reading, report["failures"])
        self.assertNotIn(ca.null_result_reading(0, 0, 0), report["failures"])

    def _assert_control_error_skips_ordinary(self, report, calls):
        self.assertEqual(calls, ["baseline"])
        self.assertFalse(any(item in SEALED_IDS for item in calls))
        self.assertEqual(report["control_status"], "error")
        row = next(item for item in report["mutants"] if item["label"] == "CONTROL")
        self.assertEqual(row["verdict"], "control-error")
        self.assertFalse(any(item["label"] in SEALED_IDS for item in report["mutants"]))
        self.assertIsNone(report["score_percent"])
        self._assert_invalid_control_failures(report)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_missing_control_anchor_is_control_error_and_skips_ordinary(self):
        with tempfile.TemporaryDirectory() as d:
            calls, report = self._run_logged(
                Path(d), {"g": self._control_anchor_spec(anchor="{missing}")})
        self._assert_control_error_skips_ordinary(report, calls)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_invalid_control_keeps_declared_equivalents(self):
        equivalent = {"g": [{"label": "eq-g", "reason": "same g"}]}
        with tempfile.TemporaryDirectory() as d:
            calls, report = self._run_logged(
                Path(d), {"g": _aee_spec()}, control="survived",
                equivalent=equivalent)
        self.assertEqual(calls, ["baseline", "CONTROL"])
        self.assertFalse(any(row["label"] in SEALED_IDS for row in report["mutants"]))
        self.assertEqual(
            [(row["group"], row["label"], row["verdict"])
             for row in report["mutants"] if row["verdict"] == "equivalent"],
            [("g", "eq-g", "equivalent")],
        )
        self.assertEqual(report["equivalent"], 1)
        self.assertIsNone(report["score_percent"])
        self._assert_invalid_control_failures(report)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_duplicate_control_anchor_is_control_error_and_skips_ordinary(self):
        with tempfile.TemporaryDirectory() as d:
            calls, report = self._run_logged(
                Path(d), {"g": self._control_anchor_spec(anchor="X")})
        self._assert_control_error_skips_ordinary(report, calls)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_multi_group_runner_runs_every_control_before_any_ordinary(self):
        source = "A = {aa}\nZ = {az}\nCA = {ca}\nCZ = {cz}\n"
        mutants = {
            "z": [
                {"label": "ord-z", "anchor": "{az}", "replacement": "{rz}"},
                {"label": "ctrl-z", "control": True, "anchor": "{cz}",
                 "replacement": "{cz_x}"},
            ],
            "a": [
                {"label": "ord-a", "anchor": "{aa}", "replacement": "{ra}"},
                {"label": "ctrl-a", "control": True, "anchor": "{ca}",
                 "replacement": "{ca_x}"},
            ],
        }
        calls = []

        def fake_build(m):
            name = _identify(Path(m["_repo_root"], "check.py").read_text(encoding="utf-8"))
            if name != "baseline":
                calls.append(name)
            return True, "built"

        def fake_outcomes(m, vectors):
            name = _identify(Path(m["_repo_root"], "check.py").read_text(encoding="utf-8"))
            keys = [v[m["id_key"]] for v in vectors]
            if name == "baseline":
                return {key: "base" for key in keys}, {}, {}
            if name.startswith("ctrl"):
                return {key: "moved" for key in keys}, {}, {}
            return {key: name for key in keys}, {}, {}

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "check.py").write_text(source, encoding="utf-8")
            (tmp / "va.json").write_text("{}\n")
            (tmp / "vz.json").write_text("{}\n")
            (tmp / "vectors.json").write_text(json.dumps({
                "vectors": [
                    {"vector_id": "va", "path": "va.json", "g": "a"},
                    {"vector_id": "vz", "path": "vz.json", "g": "z"},
                ]}))
            raw = {
                "schema": ca.SCHEMA, "runner": "process", "repo_root": ".",
                "implementation_sources": ["check.py"], "build": [],
                "entrypoint_command": [sys.executable, "check.py", "{vector}"],
                "outcome_from": ["ok"], "vectors": "vectors.json",
                "id_key": "vector_id", "vector_path_key": "path",
                "group_key": "g", "default_group": "a",
                "mutants": mutants,
            }
            path = tmp / "m.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            loaded = ca.load_manifest(path)
            with mock.patch.object(ca, "_build", side_effect=fake_build), \
                    mock.patch.object(ca, "_process_outcomes", side_effect=fake_outcomes):
                report = ca._run_process(loaded, path)
        self.assertEqual(calls, ["ctrl-a", "ctrl-z", "ord-a", "ord-z"])
        self.assertEqual(report["control_status"], "killed")

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_no_control_rows_keep_group_then_that_groups_equivalents(self):
        source = "A = {aa}\nZ = {az}\n"
        mutants = {
            "z": [{"label": "ord-z", "anchor": "{az}", "replacement": "{rz}"}],
            "a": [{"label": "ord-a", "anchor": "{aa}", "replacement": "{ra}"}],
        }
        calls = []

        def fake_build(m):
            name = _identify(Path(m["_repo_root"], "check.py").read_text(encoding="utf-8"))
            if name != "baseline":
                calls.append(name)
            return True, "built"

        def fake_outcomes(m, vectors):
            name = _identify(Path(m["_repo_root"], "check.py").read_text(encoding="utf-8"))
            keys = [v[m["id_key"]] for v in vectors]
            if name == "baseline":
                return {key: "base" for key in keys}, {}, {}
            return {key: name for key in keys}, {}, {}

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "check.py").write_text(source, encoding="utf-8")
            (tmp / "va.json").write_text("{}\n")
            (tmp / "vz.json").write_text("{}\n")
            (tmp / "vectors.json").write_text(json.dumps({
                "vectors": [
                    {"vector_id": "va", "path": "va.json", "g": "a"},
                    {"vector_id": "vz", "path": "vz.json", "g": "z"},
                ]}))
            raw = {
                "schema": ca.SCHEMA, "runner": "process", "repo_root": ".",
                "implementation_sources": ["check.py"], "build": [],
                "entrypoint_command": [sys.executable, "check.py", "{vector}"],
                "outcome_from": ["ok"], "vectors": "vectors.json",
                "id_key": "vector_id", "vector_path_key": "path",
                "group_key": "g", "default_group": "a",
                "mutants": mutants,
                "equivalent": {
                    "z": [{"label": "eq-z", "reason": "same z"}],
                    "a": [{"label": "eq-a", "reason": "same a"}],
                },
            }
            path = tmp / "m.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            loaded = ca.load_manifest(path)
            with mock.patch.object(ca, "_build", side_effect=fake_build), \
                    mock.patch.object(ca, "_process_outcomes", side_effect=fake_outcomes):
                report = ca._run_process(loaded, path)
        self.assertEqual(calls, ["ord-a", "ord-z"])
        self.assertEqual(
            [(row["group"], row["label"], row["verdict"]) for row in report["mutants"]],
            [
                ("a", "ord-a", "killed"),
                ("a", "eq-a", "equivalent"),
                ("z", "ord-z", "killed"),
                ("z", "eq-z", "equivalent"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
