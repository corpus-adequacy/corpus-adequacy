#!/usr/bin/env python3
"""First-party offline example: one mutant, three selector declarations."""

from __future__ import annotations

import importlib.util
import inspect
import io
import json
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
import corpus_adequacy as ca  # noqa: E402

EXAMPLE = REPO_ROOT / "examples" / "reason-token-projections"
WALKTHROUGH_PATH = EXAMPLE / "walkthrough.py"
OLD_SURVIVED = (
    "A future vector must distinguish this rule on a declared outcome. "
    "This projection does not name such a vector."
)
OLD_SILENT = (
    "A future vector must distinguish this rule on a declared outcome, "
    "not only the diagnostic channel. "
    "This projection does not name such a vector."
)


def _load_walkthrough():
    spec = importlib.util.spec_from_file_location(
        "reason_token_walkthrough", WALKTHROUGH_PATH)
    if spec is None or spec.loader is None:
        raise FileNotFoundError(WALKTHROUGH_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _report_shaped(*, adequate):
    return {"schema": ca.REPORT_SCHEMA, "adequate": adequate}


def _cli_proc(returncode, payload):
    return subprocess.CompletedProcess(
        args=[sys.executable, "corpus_adequacy.py", "--json"],
        returncode=returncode,
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
    )


def _selector_fields(doc: dict) -> dict:
    out = {"outcome_from": doc.get("outcome_from")}
    if "diagnostic_from" in doc:
        out["diagnostic_from"] = doc["diagnostic_from"]
    return out


def _shared_manifest(doc: dict) -> dict:
    skip = {"outcome_from", "diagnostic_from"}
    return {key: value for key, value in doc.items() if key not in skip}


class ExampleLayout(unittest.TestCase):
    def test_shipped_paths_exist(self):
        for name in (
                "check.py", "vector.json", "vectors.json",
                "outcome.manifest.json", "decision-only.manifest.json",
                "diagnostic.manifest.json", "walkthrough.py"):
            path = EXAMPLE / name
            self.assertTrue(path.is_file(), "missing %s" % path)


class SharedBytes(unittest.TestCase):
    def test_three_manifests_share_implementation_vector_and_mutants(self):
        outcome = _json(EXAMPLE / "outcome.manifest.json")
        decision = _json(EXAMPLE / "decision-only.manifest.json")
        diagnostic = _json(EXAMPLE / "diagnostic.manifest.json")
        self.assertEqual(_shared_manifest(outcome), _shared_manifest(decision))
        self.assertEqual(_shared_manifest(outcome), _shared_manifest(diagnostic))
        self.assertEqual(
            _selector_fields(outcome),
            {"outcome_from": ["accepted", "wire_code"]})
        self.assertEqual(
            _selector_fields(decision),
            {"outcome_from": ["accepted"]})
        self.assertEqual(
            _selector_fields(diagnostic),
            {"outcome_from": ["accepted"], "diagnostic_from": ["wire_code"]})
        self.assertEqual(outcome["schema"], ca.SCHEMA)
        self.assertNotEqual(outcome["schema"], ca.MANIFEST_V1_SCHEMA)
        self.assertNotIn("rules", outcome)

    def test_controls_are_positive_accepted_flip_and_inert_unused_constant(self):
        mutants = _json(EXAMPLE / "outcome.manifest.json")["mutants"]
        rows = [row for group in mutants.values() for row in group]
        by_label = {row["label"]: row for row in rows}
        self.assertIn("reason-token", by_label)
        self.assertEqual(
            by_label["reason-token"]["anchor"], 'wire_code = "refusal.a"')
        self.assertEqual(
            by_label["reason-token"]["replacement"], 'wire_code = "refusal.b"')
        positives = [row for row in rows if row.get("control")
                     and row.get("control_polarity") == "positive"]
        inerts = [row for row in rows if row.get("control")
                  and row.get("control_polarity") == "inert"]
        self.assertEqual(len(positives), 1)
        self.assertEqual(len(inerts), 1)
        self.assertIn("accepted = False", positives[0]["anchor"])
        self.assertIn("accepted = True", positives[0]["replacement"])
        self.assertNotIn("wire_code", inerts[0]["anchor"])
        self.assertNotIn("wire_code", inerts[0]["replacement"])
        self.assertIn("unused", inerts[0]["anchor"])
        source = (EXAMPLE / "check.py").read_text(encoding="utf-8")
        self.assertIn(positives[0]["anchor"], source)
        self.assertIn(inerts[0]["anchor"], source)
        self.assertIn('wire_code = "refusal.a"', source)


class ObligationWording(unittest.TestCase):
    def test_survivor_is_not_an_unconditional_contract_hole(self):
        self.assertNotEqual(ca.SURVIVED_OBLIGATION, OLD_SURVIVED)
        self.assertNotEqual(ca.SILENT_OBLIGATION, OLD_SILENT)
        self.assertNotIn(
            "A future vector must distinguish this rule on a declared outcome",
            ca.SURVIVED_OBLIGATION)
        survived = ca.SURVIVED_OBLIGATION.lower()
        self.assertIn("declared mutation", survived)
        self.assertIn("declared outcome", survived)
        self.assertIn("pinned inputs", survived)
        self.assertIn("valid run", survived)
        self.assertIn("owner-pinned declaration", survived)
        self.assertIn("rule ownership", survived)
        self.assertNotIn("diagnostic", survived)
        silent = ca.SILENT_OBLIGATION.lower()
        self.assertIn("diagnostic", silent)
        self.assertIn("never", silent)
        self.assertIn("numerator", silent)

    def test_readme_qualifies_survivor_and_selector_change(self):
        text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        collapsed = " ".join(text.split())
        self.assertNotIn(
            "So a surviving mutant is not a gap in confidence. "
            "It is a **hole in the contract**",
            collapsed)
        lower = text.lower()
        self.assertIn("pinned inputs", lower)
        self.assertIn("owner-pinned declaration", lower)
        self.assertIn("rule ownership", lower)
        self.assertIn("changing selectors changes the observational question",
                      lower)
        self.assertIn("examples/reason-token-projections", text)
        self.assertIn("diagnostic-only and never the numerator", lower)


class WalkthroughContract(unittest.TestCase):
    def test_invokes_shipped_cli_with_timeout_and_json_report(self):
        source = inspect.getsource(_load_walkthrough())
        self.assertIn("subprocess", source)
        self.assertIn("timeout", source)
        self.assertIn("--json", source)
        self.assertIn("corpus_adequacy.py", source)
        self.assertNotIn("ca.run(", source)
        self.assertNotIn("corpus_adequacy.run", source)

    def test_unsupported_fcntl_is_named_and_claims_no_result(self):
        wt = _load_walkthrough()
        with mock.patch.object(wt, "process_supported", return_value=False):
            result = wt.project("outcome", EXAMPLE / "outcome.manifest.json")
        self.assertEqual(result["status"], wt.UNSUPPORTED)
        self.assertNotIn("verdict", result)
        self.assertNotIn("killed", result)
        self.assertNotIn("survived", result)
        self.assertNotIn("silent", result)

    def test_invoke_report_rejects_parseable_stdout_with_exit_3(self):
        wt = _load_walkthrough()
        fake = _cli_proc(3, _report_shaped(adequate=True))
        with mock.patch.object(wt.subprocess, "run", return_value=fake):
            with self.assertRaises(wt.WalkthroughError):
                wt.invoke_report(EXAMPLE / "outcome.manifest.json")

    def test_invoke_report_rejects_parseable_stdout_with_exit_minus_9(self):
        wt = _load_walkthrough()
        fake = _cli_proc(-9, _report_shaped(adequate=False))
        with mock.patch.object(wt.subprocess, "run", return_value=fake):
            with self.assertRaises(wt.WalkthroughError):
                wt.invoke_report(EXAMPLE / "outcome.manifest.json")

    def test_invoke_report_rejects_exit_0_when_adequate_is_false(self):
        wt = _load_walkthrough()
        fake = _cli_proc(0, _report_shaped(adequate=False))
        with mock.patch.object(wt.subprocess, "run", return_value=fake):
            with self.assertRaises(wt.WalkthroughError):
                wt.invoke_report(EXAMPLE / "outcome.manifest.json")

    def test_invoke_report_rejects_exit_1_when_adequate_is_true(self):
        wt = _load_walkthrough()
        fake = _cli_proc(1, _report_shaped(adequate=True))
        with mock.patch.object(wt.subprocess, "run", return_value=fake):
            with self.assertRaises(wt.WalkthroughError):
                wt.invoke_report(EXAMPLE / "outcome.manifest.json")

    def test_executable_stdout_names_incomparable_reports_and_silent_means(self):
        wt = _load_walkthrough()
        dummy = {
            "status": "ok",
            "projection": "outcome",
            "verdict": "killed",
            "adequate": True,
            "control_status": "killed",
            "unproved": 0,
            "killed": 1,
            "survived": 0,
            "silent": 0,
        }
        buf = io.StringIO()
        with mock.patch.object(wt, "process_supported", return_value=True), \
             mock.patch.object(wt, "project", return_value=dummy), \
             redirect_stdout(buf):
            rc = wt.main()
        self.assertEqual(rc, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["comparison"]["status"], "incomparable")
        self.assertEqual(
            payload["comparison"]["reason"],
            "the three reports are incomparable because their observation "
            "declarations differ")
        self.assertEqual(
            payload["silent_means"],
            "diagnostic movement without declared-outcome movement and "
            "denominator-only")


def _valid_before_ordinary(test: unittest.TestCase, report: dict) -> dict:
    test.assertEqual(report["control_status"], "killed", report.get("failures"))
    test.assertEqual(report["unproved"], 0, report.get("failures"))
    test.assertIsNotNone(report["score_percent"], report.get("failures"))
    by_verdict = {}
    for row in report["mutants"]:
        by_verdict.setdefault(row["verdict"], []).append(row)
    test.assertEqual(len(by_verdict.get("control-killed", [])), 1)
    test.assertEqual(len(by_verdict.get("control-unchanged", [])), 1)
    ordinary = [row for row in report["mutants"] if row["label"] == "reason-token"]
    test.assertEqual(len(ordinary), 1, "ordinary mutant was never scheduled")
    denom = report["killed"] + report["survived"] + report["silent"]
    test.assertEqual(denom, 1)
    test.assertEqual(
        sum(1 for row in report["mutants"] if row["verdict"].startswith("control-")),
        2)
    return ordinary[0]


@unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
class ThreeProjections(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wt = _load_walkthrough()

    def _report(self, name: str) -> dict:
        path = EXAMPLE / ("%s.manifest.json" % name)
        report = self.wt.invoke_report(path)
        self.assertEqual(report["schema"], ca.REPORT_SCHEMA)
        return report

    def test_outcome_projection_kills_reason_token(self):
        report = self._report("outcome")
        row = _valid_before_ordinary(self, report)
        self.assertEqual(row["verdict"], "killed")
        self.assertEqual(row["moved"], 1)
        self.assertEqual((report["killed"], report["survived"], report["silent"]),
                         (1, 0, 0))
        self.assertTrue(report["adequate"], report["failures"])
        shown = self.wt.ordinary_verdict(report)
        self.assertEqual(shown, "killed")

    def test_decision_only_projection_survives(self):
        report = self._report("decision-only")
        row = _valid_before_ordinary(self, report)
        self.assertEqual(row["verdict"], "survived")
        self.assertEqual(row["moved"], 0)
        self.assertEqual((report["killed"], report["survived"], report["silent"]),
                         (0, 1, 0))
        self.assertFalse(report["adequate"])
        shown = self.wt.ordinary_verdict(report)
        self.assertEqual(shown, "survived")

    def test_diagnostic_projection_is_silent(self):
        report = self._report("diagnostic")
        row = _valid_before_ordinary(self, report)
        self.assertEqual(row["verdict"], "silent")
        self.assertEqual(row["moved"], 0)
        self.assertEqual(row["moved_diagnostic"], 1)
        self.assertTrue(report["diagnostic_channel_declared"])
        self.assertEqual((report["killed"], report["survived"], report["silent"]),
                         (0, 0, 1))
        self.assertFalse(report["adequate"])
        shown = self.wt.ordinary_verdict(report)
        self.assertEqual(shown, "silent")

    def test_walkthrough_refuses_ordinary_verdict_until_controls_are_valid(self):
        report = self._report("outcome")
        broken = dict(report)
        broken["control_status"] = "survived"
        broken["score_percent"] = None
        with self.assertRaises(self.wt.WalkthroughError):
            self.wt.ordinary_verdict(broken)

    def test_v0_inventory_is_not_printed_as_measured_zero(self):
        source = inspect.getsource(self.wt)
        self.assertNotIn("--rules", source)
        stdout = subprocess.run(
            [sys.executable, str(WALKTHROUGH_PATH)],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120)
        self.assertEqual(stdout.returncode, 0, stdout.stderr)
        self.assertNotIn("inventory: 0", stdout.stdout.lower())
        self.assertNotIn('"rules": 0', stdout.stdout.lower())
        self.assertNotIn("measured zero", stdout.stdout.lower())
        payload = json.loads(stdout.stdout)
        self.assertEqual(payload["comparison"]["status"], "incomparable")
        self.assertEqual(
            payload["comparison"]["reason"],
            "the three reports are incomparable because their observation "
            "declarations differ")
        self.assertEqual(
            payload["silent_means"],
            "diagnostic movement without declared-outcome movement and "
            "denominator-only")
