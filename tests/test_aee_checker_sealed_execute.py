#!/usr/bin/env python3
"""Execution-funnel contract for the frozen inverse-AEE experiment. Stdlib only.

Synthetic/fake-child only. Does not run the checker, baseline, control, or
mutants against the corpus. Does not emit report.v0. Public non-claims:
not MC/DC, not atomic-subcondition adequacy, not complete mutation
adequacy, not sandbox-efficacy, not certification, not ranking.
"""

from __future__ import annotations

import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import aee_checker_sealed_authorize as auth  # noqa: E402
import aee_checker_sealed_execute as exe  # noqa: E402
import aee_checker_sealed_run as run  # noqa: E402

PREREG = REPO_ROOT / "measurements" / "aee-checker-25b9dfa"
GO_RUN_DIR = REPO_ROOT / "measurements" / "aee-go-run"
PREPARE_PATH = GO_RUN_DIR / "prepare.v0.json"
AUTHORIZE_PATH = GO_RUN_DIR / "authorize.v0.json"
SEALED_IDS = tuple("sealed-%d" % i for i in range(1, 8))
SEQUENCE_IDS = ("baseline", "control") + SEALED_IDS
NON_CLAIM_PHRASES = (
    "MC/DC",
    "atomic-subcondition adequacy",
    "complete mutation adequacy",
    "sandbox-efficacy",
    "certification",
    "ranking",
)
EXECUTOR_REL = "measurements/aee_checker_sealed_execute.py"


def _fake_child(step: dict) -> dict:
    kind = step["kind"]
    if kind == "baseline":
        return {"state": "ok", "status": "passed"}
    if kind == "must-die":
        return {"state": "ok", "status": "killed", "scored": False}
    return {"state": "ok", "status": "survived"}


def _run(child=_fake_child, **kwargs):
    return exe.run_execution_funnel(
        authorize_raw=AUTHORIZE_PATH.read_bytes(),
        prepare_raw=PREPARE_PATH.read_bytes(),
        pins_dir=PREREG,
        child=child,
        **kwargs,
    )


class FunnelWiresCanonicalApis(unittest.TestCase):
    def test_funnel_validates_then_sequences_then_classifies_each_step_once(self):
        calls = []

        def child(step):
            calls.append(step["id"])
            return _fake_child(step)

        with mock.patch.object(exe, "validate_authorize", wraps=auth.validate_authorize) as validate, \
                mock.patch.object(exe, "load_frozen_sites", wraps=auth.load_frozen_sites) as load_sites, \
                mock.patch.object(exe, "required_sequence", wraps=auth.required_sequence) as sequence, \
                mock.patch.object(exe, "classify_observation", wraps=auth.classify_observation) as classify:
            result = _run(child)

        validate.assert_called_once()
        load_sites.assert_called_once()
        sequence.assert_called_once()
        self.assertEqual(
            [site["id"] for site in sequence.call_args.args[0]["sites"]],
            list(SEALED_IDS),
        )
        self.assertEqual(calls, list(SEQUENCE_IDS))
        self.assertEqual(len(classify.call_args_list), len(SEQUENCE_IDS))
        self.assertEqual(result["executed"], list(SEQUENCE_IDS))
        self.assertEqual(result["sequence"], list(SEQUENCE_IDS))
        self.assertFalse(result["closed"])
        self.assertNotIn("report", result)
        self.assertNotIn("score", result)

    def test_missing_child_is_refused(self):
        with self.assertRaises(exe.ExecuteError) as ctx:
            _run(child=None)
        self.assertRegex(str(ctx.exception).lower(), r"funnel|fake child")

    def test_main_does_not_start_a_real_experiment(self):
        with mock.patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(exe.main(["aee_checker_sealed_execute.py"]), 2)
        source = Path(exe.__file__).read_text(encoding="utf-8")
        self.assertNotIn("cargo build", source)
        self.assertNotIn("./target/release/aee-checker", source)
        self.assertNotIn("corpus_adequacy.run", source)
        self.assertNotIn("report.v0", source)


class VoidStopsBeforeScoredRows(unittest.TestCase):
    def test_baseline_void_does_not_execute_control_or_mutants(self):
        calls = []

        def child(step):
            calls.append(step["id"])
            if step["id"] != "baseline":
                raise AssertionError("scored row after baseline void")
            return {"status": "failed"}

        result = _run(child)
        self.assertEqual(calls, ["baseline"])
        self.assertEqual(result["executed"], ["baseline"])
        self.assertEqual(result["dispositions"], ["void"])
        self.assertTrue(result["closed"])
        self.assertEqual(result["close_reason"], "void-before-scored")

    def test_control_void_does_not_execute_mutants(self):
        calls = []

        def child(step):
            calls.append(step["id"])
            if step["kind"] == "mutant":
                raise AssertionError("scored row after control void")
            if step["kind"] == "baseline":
                return {"state": "ok", "status": "passed"}
            return {"state": "ok", "status": "survived", "scored": False}

        result = _run(child)
        self.assertEqual(calls, ["baseline", "control"])
        self.assertEqual(result["dispositions"], ["passed", "void"])
        self.assertTrue(result["closed"])
        self.assertEqual(result["close_reason"], "void-before-scored")

    def test_baseline_timeout_voids_and_leaves_later_calls_empty(self):
        calls = []

        def child(step):
            calls.append(step["id"])
            if step["id"] != "baseline":
                raise AssertionError("scored row after baseline timeout")
            return {"state": "timeout", "status": "passed"}

        result = _run(child)
        self.assertEqual(calls, ["baseline"])
        self.assertEqual(result["dispositions"], ["void"])
        self.assertTrue(result["closed"])
        self.assertEqual(result["close_reason"], "void-before-scored")

    def test_control_signal_voids_and_leaves_ordinary_calls_empty(self):
        calls = []

        def child(step):
            calls.append(step["id"])
            if step["kind"] == "mutant":
                raise AssertionError("ordinary mutant after control signal")
            if step["kind"] == "baseline":
                return {"state": "ok", "status": "passed"}
            return {"state": "signal", "status": "killed", "scored": False}

        result = _run(child)
        self.assertEqual(calls, ["baseline", "control"])
        self.assertEqual(result["dispositions"], ["passed", "void"])
        self.assertTrue(result["closed"])
        self.assertEqual(result["close_reason"], "void-before-scored")


class ClosedVocabularyOnTheFunnel(unittest.TestCase):
    def test_missing_state_on_mutant_is_unproved_never_killed(self):
        def child(step):
            if step["kind"] == "baseline":
                return {"state": "ok", "status": "passed"}
            if step["kind"] == "must-die":
                return {"state": "ok", "status": "killed", "scored": False}
            return {"status": "killed"}

        result = _run(child)
        mutant = result["dispositions"][2:]
        self.assertTrue(mutant)
        self.assertTrue(all(item == "unproved" for item in mutant))
        self.assertNotIn("killed", mutant)

    def test_unknown_state_status_killed_is_unproved_not_killed(self):
        def child(step):
            if step["kind"] == "baseline":
                return {"state": "ok", "status": "passed"}
            if step["kind"] == "must-die":
                return {"state": "ok", "status": "killed", "scored": False}
            return {"state": "mystery", "status": "killed"}

        result = _run(child)
        mutant = result["dispositions"][2:]
        self.assertTrue(mutant)
        self.assertTrue(all(item == "unproved" for item in mutant))
        self.assertNotIn("killed", mutant)

    def test_reordered_sequence_from_required_sequence_is_refused(self):
        real = auth.required_sequence

        def reordered(sites):
            steps = list(real(sites))
            steps[0], steps[1] = steps[1], steps[0]
            return tuple(steps)

        with mock.patch.object(exe, "required_sequence", side_effect=reordered):
            with self.assertRaises(exe.ExecuteError) as ctx:
                _run()
        self.assertIn("sequence", str(ctx.exception).lower())

    def test_funnel_uses_authorize_sequence_semantics_not_ids_only(self):
        source = Path(exe.__file__).read_text(encoding="utf-8")
        self.assertIn("require_authorized_sequence", source)
        self.assertIn("voids_before_scored", source)
        steps = list(auth.required_sequence(auth.load_frozen_sites(PREREG)))
        steps[0] = dict(steps[0], kind="mutant")
        with mock.patch.object(exe, "required_sequence", return_value=tuple(steps)):
            with self.assertRaises(exe.ExecuteError) as ctx:
                _run()
        self.assertIn("sequence", str(ctx.exception).lower())


class ExecutorBoundInExecutionIdentity(unittest.TestCase):
    def test_executor_path_is_in_execution_identity_inventory(self):
        self.assertIn(EXECUTOR_REL, run.EXECUTION_PATHS)
        self.assertIn("measurements/aee_checker_sealed_authorize.py", run.EXECUTION_PATHS)

    def test_omitting_executor_from_identity_changes_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "exec-root"
            for rel in run.EXECUTION_PATHS:
                dest = root / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes((REPO_ROOT / rel).read_bytes())
            subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
            subprocess.run(["git", "add", "-A"], cwd=root, check=True, capture_output=True)
            subprocess.run(
                ["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "exec"],
                cwd=root, check=True, capture_output=True,
            )
            full = run.execution_identity(root)
            omitted = [p for p in run.EXECUTION_PATHS if p != EXECUTOR_REL]
            with mock.patch.object(run, "EXECUTION_PATHS", omitted):
                reduced = run.execution_identity(root)
            self.assertNotEqual(full["content_sha256"], reduced["content_sha256"])


class PublicNonClaims(unittest.TestCase):
    def test_removing_any_non_claim_from_code_or_tests_fails(self):
        texts = {
            "code": Path(exe.__file__).read_text(encoding="utf-8"),
            "tests": Path(__file__).read_text(encoding="utf-8"),
        }
        for phrase in NON_CLAIM_PHRASES:
            for where, text in texts.items():
                self.assertIn(phrase, text, "%s missing %s" % (where, phrase))
        self.assertEqual(tuple(exe.NON_CLAIMS), NON_CLAIM_PHRASES)

    def test_funnel_does_not_write_report_or_phase_a(self):
        before = {
            path: path.read_bytes()
            for path in (
                *PREREG.iterdir(),
                PREPARE_PATH,
                AUTHORIZE_PATH,
            )
        }
        _run()
        for path, raw in before.items():
            self.assertEqual(path.read_bytes(), raw, path)
        self.assertFalse((GO_RUN_DIR / "report.v0.json").exists())


if __name__ == "__main__":
    unittest.main()
