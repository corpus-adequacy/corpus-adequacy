#!/usr/bin/env python3
"""Behavioural tests for conformance/corpus_adequacy.py. Standard library only.

    python3 conformance/tests/test_corpus_adequacy.py

Built against a synthetic two-rule corpus rather than a real one, so every
verdict boundary is reachable on purpose: a rule some vector discriminates, a
rule none does, a rule declared out of scope, and a rule declared equivalent.
"""

from __future__ import annotations

import ast
import gc
import hashlib
import inspect
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bounded_run as br  # noqa: E402
import corpus_adequacy as ca  # noqa: E402

IMPL = '''
def evaluate(group, inputs):
    if inputs.get("bad"):
        return "rejected"
    if inputs.get("n", 0) > 10:
        return "big"
    return "ok"
'''

VECTORS = {"vectors": [
    {"vector_id": "v1", "axis": "a", "inputs": {"bad": True}},
    {"vector_id": "v2", "axis": "a", "inputs": {"n": 1}},
]}

KILLABLE = {"label": "rejects bad input",
            "anchor": 'if inputs.get("bad"):\n        return "rejected"',
            "replacement": 'if False:\n        return "rejected"'}
# No vector carries n > 10, so nothing can distinguish this rule.
SURVIVOR = {"label": "big branch",
            "anchor": 'if inputs.get("n", 0) > 10:',
            "replacement": 'if inputs.get("n", 0) > 999999:'}
# Moves every vector, so it is killed unless the harness sees nothing at all.
CONTROL = {"label": "CONTROL harness reachability", "control": True,
           "anchor": 'def evaluate(group, inputs):',
           "replacement": 'def evaluate(group, inputs):\n    return "MOVED"'}


def _batch_python() -> str:
    return sys.executable


def _assert_process_batch_lock_verdict(test: unittest.TestCase, rep: dict) -> None:
    """A completed process/batch score is only legal when the lock was available.

    fcntl is None is ManifestError at enter, before any source write — not
    adequate=false after a scored run.
    """
    test.assertIsNotNone(
        ca.fcntl,
        "fcntl is None is refuse-before-work, not a scored report")
    test.assertTrue(rep["adequate"], rep["failures"])
    test.assertEqual(
        [f for f in rep["failures"] if "no advisory lock on this platform" in f],
        [])


def _manifest(tmp: Path, mutants, equivalent=None, vectors=None, raw=None,
              control=True) -> Path:
    """A control is added to every group unless a test is about its absence.

    These fixtures declared none, and for a while that was legal on this runner
    because the requirement lived only in the process path. Making it default
    here rather than per-test means a new fixture inherits the rule instead of
    quietly reproducing the gap.
    """
    if control:
        mutants = {g: (list(ms) + [dict(CONTROL, label=f"{CONTROL['label']} [{g}]")]
                       if not any(x.get("control") for x in ms) else ms)
                   for g, ms in mutants.items()}
    (tmp / "impl.py").write_text(IMPL)
    (tmp / "vectors.json").write_text(json.dumps(vectors or VECTORS))
    m = {"schema": ca.SCHEMA, "implementation": "impl.py", "entrypoint": "evaluate",
         "vectors": "vectors.json", "group_key": "axis", "id_key": "vector_id",
         "inputs_key": "inputs", "mutants": mutants, "equivalent": equivalent or {}}
    if raw:
        m.update(raw)
    p = tmp / "m.json"
    p.write_text(json.dumps(m))
    return p


class Scoring(unittest.TestCase):
    def test_a_discriminated_rule_is_killed_and_scores_100(self):
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(_manifest(Path(d), {"a": [KILLABLE]}))
        self.assertEqual((rep["killed"], rep["survived"]), (1, 0))
        self.assertEqual(rep["score_percent"], 100.0)
        self.assertTrue(rep["adequate"])

    def test_an_undistinguished_rule_survives_and_fails_the_run(self):
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(_manifest(Path(d), {"a": [KILLABLE, SURVIVOR]}))
        self.assertEqual((rep["killed"], rep["survived"]), (1, 1))
        self.assertEqual(rep["score_percent"], 50.0)
        self.assertFalse(rep["adequate"])

    def test_out_of_scope_is_reported_but_never_scored(self):
        # The distinction the tool exists to keep: a rule nobody claimed is a
        # scope statement, not a hole, and must not manufacture a failure.
        oos = dict(SURVIVOR, scope="out_of_scope", reason="the corpus does not claim this rule")
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(_manifest(Path(d), {"a": [KILLABLE, oos]}))
        self.assertEqual(rep["survived"], 0)
        self.assertEqual(rep["unexercised_out_of_scope"], 1)
        self.assertEqual(rep["score_percent"], 100.0)
        self.assertTrue(rep["adequate"])
        self.assertIn("unexercised", [r["verdict"] for r in rep["mutants"]])

    def test_declared_equivalents_are_excluded_from_the_denominator(self):
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(_manifest(Path(d), {"a": [KILLABLE]},
                                   {"a": [{"label": "eq", "reason": "both branches return ok"}]}))
        self.assertEqual(rep["equivalent"], 1)
        self.assertEqual(rep["killed"] + rep["survived"], 1)

    def test_a_mutant_that_never_loads_is_unproved_not_killed(self):
        # Reversed deliberately on the Rust-adapter review: a mutant that never
        # loaded was never shown to the corpus, so the corpus said nothing about
        # that rule. Counting it killed lets a typo in the substitution print as
        # "rule covered". Measure a load-bearing rule with a variant that RUNS.
        broken = {"label": "syntax", "anchor": 'return "ok"', "replacement": "return ??"}
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(_manifest(Path(d), {"a": [broken]}))
        self.assertEqual(rep["killed"], 0)
        self.assertEqual(rep["unproved"], 1)
        self.assertFalse(rep["adequate"])
        self.assertTrue(any("never ran" in f for f in rep["failures"]), rep["failures"])


class ControlMutants(unittest.TestCase):
    """A control proves the harness detects anything. It is never scored."""

    def test_a_killed_control_does_not_inflate_the_score(self):
        ctrl = dict(KILLABLE, label="CONTROL reachability", control=True)
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(_manifest(Path(d), {"a": [ctrl]}))
        self.assertEqual(rep["killed"], 0, "a control must not count as a kill")
        self.assertIn("control-killed", [r["verdict"] for r in rep["mutants"]])
        self.assertEqual(rep["control_status"], "killed")

    def test_a_surviving_control_invalidates_the_whole_run(self):
        # The distinction the control exists for: all-survivors because the corpus is
        # weak, versus all-survivors because nothing was ever measured.
        ctrl = dict(SURVIVOR, label="CONTROL reachability", control=True)
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(_manifest(Path(d), {"a": [KILLABLE, ctrl]}))
        self.assertFalse(rep["adequate"])
        self.assertEqual(rep["control_status"], "survived")
        self.assertTrue(any("harness cannot detect" in f for f in rep["failures"]),
                        rep["failures"])

    def test_a_control_may_not_be_declared_out_of_scope(self):
        ctrl = dict(KILLABLE, label="c", control=True, scope="out_of_scope", reason="x")
        with tempfile.TemporaryDirectory() as d:
            p = _manifest(Path(d), {"a": [ctrl]})
            with self.assertRaises(ca.ManifestError) as cm:
                ca.load_manifest(p)
        self.assertIn("control cannot be out_of_scope", str(cm.exception))


class KnownHoles(unittest.TestCase):
    """An acknowledged hole is pinned to one digest and expires with it."""

    def _mf(self, tmp: Path, digest_in_file, holes_for, extra_mutants=None):
        (tmp / "digest.json").write_text(json.dumps({"corpus_digest": digest_in_file}))
        muts = [dict(SURVIVOR, label="unexercised rule")] + (extra_mutants or [])
        p = _manifest(tmp, {"a": muts}, raw={
            "corpus_digest_file": "digest.json", "corpus_digest_key": "corpus_digest",
            "known_holes": {holes_for: [{"label": "unexercised rule",
                                         "reason": "no vector reaches it",
                                         "recorded": "2026-08-19"}]}})
        return p

    def test_a_hole_acknowledged_for_the_present_digest_is_not_a_survivor(self):
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._mf(Path(d), "sha256:aaa", "sha256:aaa", [KILLABLE]))
        self.assertEqual(rep["survived"], 0)
        self.assertEqual(rep["known_holes"], 1)
        self.assertIn("known-hole", [r["verdict"] for r in rep["mutants"]])

    def test_the_acknowledgement_expires_when_the_corpus_moves(self):
        # The rule that stops this being an escape hatch: an acknowledgement is a
        # statement about ONE corpus, so a corpus that changes loses it.
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._mf(Path(d), "sha256:NEW", "sha256:OLD", [KILLABLE]))
        self.assertEqual(rep["known_holes"], 0)
        self.assertEqual(rep["survived"], 1, "the hole must reappear as a survivor")
        self.assertFalse(rep["adequate"])

    def test_an_acknowledgement_for_a_rule_now_exercised_is_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "digest.json").write_text(json.dumps({"corpus_digest": "sha256:aaa"}))
            p = _manifest(tmp, {"a": [dict(KILLABLE, label="now exercised")]}, raw={
                "corpus_digest_file": "digest.json", "corpus_digest_key": "corpus_digest",
                "known_holes": {"sha256:aaa": [{"label": "now exercised", "reason": "x",
                                                "recorded": "2026-08-19"}]}})
            rep = ca.run(p)
        self.assertFalse(rep["adequate"])
        # The message widened from "now exercises" to cover every transition away
        # from known-hole, not only becoming killed.
        self.assertTrue(any("no longer holes" in f and "now killed" in f
                            for f in rep["failures"]), rep["failures"])

    def test_the_report_does_not_claim_the_pin_is_to_the_corpus(self):
        # The wording was false and the tool printed it: with a corpus that had moved
        # it said the acknowledgement "expires the moment the corpus changes" while
        # exiting 0 at 100%. The digest is a value read from a file the manifest
        # names, never recomputed from the vectors, and the report must say so.
        with tempfile.TemporaryDirectory() as d:
            p = self._mf(Path(d), "sha256:aaa", "sha256:aaa", [KILLABLE])
            r = subprocess.run([sys.executable, str(ca.__file__), str(p)],
                               capture_output=True, text=True, timeout=120)
        self.assertNotIn("expires the moment the corpus changes", r.stdout)
        self.assertIn("not recomputed from the vectors", r.stdout)

    def test_pre_declared_future_digests_are_surfaced(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "digest.json").write_text(json.dumps({"corpus_digest": "sha256:aaa"}))
            p = _manifest(tmp, {"a": [KILLABLE, dict(SURVIVOR, label="hole")]}, raw={
                "corpus_digest_file": "digest.json", "corpus_digest_key": "corpus_digest",
                "known_holes": {"sha256:aaa": [{"label": "hole", "reason": "x",
                                                "recorded": "2026-08-19"}],
                                "sha256:future1": [], "sha256:future2": []}})
            r = subprocess.run([sys.executable, str(ca.__file__), str(p)],
                               capture_output=True, text=True, timeout=120)
        self.assertIn("digests carry acknowledgements", r.stdout)

    def test_holes_outnumbering_measurements_is_stated(self):
        holes = [dict(SURVIVOR, label=f"h{i}") for i in range(4)]
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "digest.json").write_text(json.dumps({"corpus_digest": "sha256:aaa"}))
            p = _manifest(tmp, {"a": [KILLABLE] + holes}, raw={
                "corpus_digest_file": "digest.json", "corpus_digest_key": "corpus_digest",
                "known_holes": {"sha256:aaa": [{"label": f"h{i}", "reason": "x",
                                                "recorded": "2026-08-19"} for i in range(4)]}})
            r = subprocess.run([sys.executable, str(ca.__file__), str(p)],
                               capture_output=True, text=True, timeout=120)
        self.assertIn("acknowledged as holes than are measured", r.stdout)
        self.assertIn("acknowledged holes", r.stdout.strip().splitlines()[-1])

    def test_an_acknowledgement_lingers_when_its_rule_becomes_out_of_scope(self):
        # Only one of four transitions was covered: killed. A rule that becomes
        # out_of_scope left the acknowledgement pointing at nothing, silently.
        oos = dict(SURVIVOR, label="hole", scope="out_of_scope", reason="marked oos later")
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "digest.json").write_text(json.dumps({"corpus_digest": "sha256:aaa"}))
            p = _manifest(tmp, {"a": [KILLABLE, oos]}, raw={
                "corpus_digest_file": "digest.json", "corpus_digest_key": "corpus_digest",
                "known_holes": {"sha256:aaa": [{"label": "hole", "reason": "x",
                                                "recorded": "2026-08-19"}]}})
            rep = ca.run(p)
        self.assertFalse(rep["adequate"])
        self.assertTrue(any("no longer holes" in f for f in rep["failures"]), rep["failures"])

    def test_a_hole_without_a_reason_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "digest.json").write_text(json.dumps({"corpus_digest": "sha256:aaa"}))
            p = _manifest(tmp, {"a": [KILLABLE]}, raw={
                "corpus_digest_file": "digest.json", "corpus_digest_key": "corpus_digest",
                "known_holes": {"sha256:aaa": [{"label": "x", "reason": " ",
                                                "recorded": "2026-08-19"}]}})
            with self.assertRaises(ca.ManifestError) as cm:
                ca.load_manifest(p)
        self.assertIn("stated reason", str(cm.exception))

    def test_an_all_holes_manifest_reports_no_result_rather_than_100_percent(self):
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._mf(Path(d), "sha256:aaa", "sha256:aaa"))
        self.assertIsNone(rep["score_percent"], "an empty denominator is not 100%")
        self.assertFalse(rep["adequate"])
        self.assertTrue(any("nothing was measured" in f for f in rep["failures"]))

    def test_a_null_result_says_it_indicts_the_declaration_first(self):
        """The wrong reading of a null result is "this corpus cannot be measured".

        It reads like a finding, which is why it survives; the right reading reads
        like a mistake. The tool's own author published "not measurable" for a
        14-vector corpus after declaring three rules for it. The message has to
        carry the correction, so it is pinned rather than left to phrasing.
        """
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._mf(Path(d), "sha256:aaa", "sha256:aaa"))
        msg = " ".join(rep["failures"])
        self.assertIn("statement about the DECLARATION", msg)
        self.assertIn("from the implementation rather than from this manifest", msg)

    def test_an_empty_declaration_is_told_to_declare_rules(self):
        """The other null-result branch: nothing excluded, nothing declared either.

        Reached when a manifest scores no mutants without any of them being a hole,
        an equivalent or out of scope -- so the previous message, which explains the
        denominator by listing exclusions, would name causes that do not apply.
        """
        reading = ca.null_result_reading(0, 0, 0)
        self.assertIn("no non-equivalent mutants were scored", reading)
        self.assertIn("Declare the rules the implementation actually has", reading)
        self.assertNotIn("out of scope", reading,
                         "nothing was excluded here; naming exclusions would misdirect")


class BatchRunner(unittest.TestCase):
    """A corpus consumed as a unit: one invocation, the summary is the outcome."""

    def _corpus(self, tmp: Path):
        (tmp / "check.py").write_text(
            "import json, sys\n"
            "doc = json.load(open(sys.argv[1]))\n"
            "fails = [c['id'] for c in doc['cases'] if c['n'] > 10]\n"
            "print(json.dumps({'ok': not fails, 'failures': fails}))\n")
        (tmp / "vectors.json").write_text(json.dumps({"cases": [
            {"id": "c1", "n": 1}, {"id": "c2", "n": 2}]}))
        m = {"schema": ca.SCHEMA, "runner": "batch", "repo_root": ".",
             "implementation_sources": ["check.py"],
             "entrypoint_command": [_batch_python(), "check.py", "vectors.json"],
             "outcome_from": ["ok", "failures"], "vectors": "vectors.json",
             "id_key": "vector_id", "default_group": "g",
             "mutants": {"g": [
                 {"label": "threshold", "anchor": "c['n'] > 10", "replacement": "c['n'] > 1"},
                 # must actually move the summary: emptying the case list leaves
                 # `failures` empty exactly as the baseline does, and the control
                 # guard correctly refused that when it was tried.
                 {"label": "CONTROL", "control": True,
                  "anchor": "'ok': not fails", "replacement": "'ok': 'MOVED'"}]}}
        p = tmp / "m.json"
        p.write_text(json.dumps(m))
        return p

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_one_invocation_still_discriminates_via_the_summary(self):
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._corpus(Path(d)))
        self.assertEqual(rep["runner"], "batch")
        self.assertEqual(rep["killed"], 1)
        _assert_process_batch_lock_verdict(self, rep)

    def test_the_source_is_restored_after_a_batch_run(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            p = self._corpus(tmp)
            before = (tmp / "check.py").read_bytes()
            if ca.fcntl is None:
                with self.assertRaises(ca.ManifestError) as cm:
                    ca.run(p)
                self.assertIn("no advisory lock", str(cm.exception))
            else:
                ca.run(p)
            self.assertEqual((tmp / "check.py").read_bytes(), before)

    def test_a_batch_manifest_needs_no_build(self):
        # An interpreted corpus has no build step; requiring one would exclude it.
        with tempfile.TemporaryDirectory() as d:
            m = ca.load_manifest(self._corpus(Path(d)))
        self.assertEqual(m["build"], [])

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_an_unreadable_summary_is_a_raise_not_a_silent_pass(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            p = self._corpus(tmp)
            (tmp / "check.py").write_text("print('not json')\n")
            rep = ca.run(p)
        self.assertFalse(rep["adequate"])
        self.assertTrue(any("UNMUTATED" in f for f in rep["failures"]), rep["failures"])

    def test_batch_command_preserves_windows_style_executable_path(self):
        """JSON load plus _batch_outcome must not rewrite argv[0] slashes or spaces."""
        win_py = r"C:\Program Files\Python\python.exe"
        captured = {}

        def capture(cmd, cwd, timeout):
            captured["cmd"] = list(cmd)
            return subprocess.CompletedProcess(
                cmd, 0, json.dumps({"ok": True, "failures": []}), "")

        with tempfile.TemporaryDirectory() as d:
            p = self._corpus(Path(d))
            raw = json.loads(p.read_text(encoding="utf-8"))
            raw["entrypoint_command"][0] = win_py
            p.write_text(json.dumps(raw), encoding="utf-8")
            loaded = ca.load_manifest(p)
            with mock.patch.object(ca, "_run_capped", side_effect=capture):
                ca._batch_outcome(loaded)
        self.assertEqual(captured["cmd"][0], win_py)
        self.assertEqual(captured["cmd"][1:], ["check.py", "vectors.json"])


class ProcessSourceContainment(unittest.TestCase):
    def _assert_lock_can_be_reacquired(self, repo_root: Path) -> None:
        second = ca._TreeLock(repo_root)
        try:
            second.__enter__()
        finally:
            if second.held:
                second.__exit__()

    def _nested_corpus(self, tmp: Path) -> tuple[Path, Path]:
        repo = tmp / "repo"
        source_dir = repo / "src"
        source_dir.mkdir(parents=True)
        source = source_dir / "check.py"
        source.write_text(
            "import json, sys\n"
            "doc = json.load(open(sys.argv[1]))\n"
            "fails = [c['id'] for c in doc['cases'] if c['n'] > 10]\n"
            "print(json.dumps({'ok': not fails, 'failures': fails}))\n")
        (repo / "vectors.json").write_text(json.dumps({"cases": [
            {"id": "c1", "n": 1}, {"id": "c2", "n": 2}]}))
        raw = {"schema": ca.SCHEMA, "runner": "batch", "repo_root": "repo",
               "implementation_sources": ["repo/src/check.py"],
               "entrypoint_command": [_batch_python(), "src/check.py", "vectors.json"],
               "outcome_from": ["ok", "failures"], "vectors": "repo/vectors.json",
               "id_key": "vector_id", "default_group": "g", "mutants": {"g": [
                   {"label": "threshold", "anchor": "c['n'] > 10",
                    "replacement": "c['n'] > 1"},
                   {"label": "CONTROL", "control": True,
                    "anchor": "'ok': not fails", "replacement": "'ok': 'MOVED'"}]}}
        manifest = tmp / "m.json"
        manifest.write_text(json.dumps(raw))
        return manifest, source

    def test_a_symlinked_source_outside_repo_root_is_refused_before_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            repo = tmp / "repo"
            repo.mkdir()
            outside = tmp / "outside.py"
            outside.write_text("RULE = True\n")
            before = outside.read_bytes()
            link = repo / "linked.py"
            link.symlink_to(outside)

            manifest = BatchRunner()._corpus(tmp)
            raw = json.loads(manifest.read_text())
            raw["repo_root"] = "repo"
            raw["implementation_sources"] = ["repo/linked.py"]
            manifest.write_text(json.dumps(raw))

            with self.assertRaises(ca.ManifestError) as cm:
                ca.load_manifest(manifest)

            self.assertEqual(outside.read_bytes(), before)
        self.assertIn("outside repo_root", str(cm.exception))
        self.assertIn("linked.py", str(cm.exception))

    def test_a_symlinked_source_inside_repo_root_remains_valid(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            repo = tmp / "repo"
            repo.mkdir()
            target = repo / "target.py"
            target.write_text("RULE = True\n")
            link = repo / "linked.py"
            link.symlink_to(target)

            manifest = BatchRunner()._corpus(tmp)
            raw = json.loads(manifest.read_text())
            raw["repo_root"] = "repo"
            raw["implementation_sources"] = ["repo/linked.py"]
            manifest.write_text(json.dumps(raw))

            loaded = ca.load_manifest(manifest)

        self.assertEqual(loaded["_source_paths"], [target.resolve()])

    def test_direct_escapes_are_rejected_before_outside_existence_is_observed(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "repo").mkdir()
            (tmp / "outside.py").write_text("RULE = True\n")
            manifest = BatchRunner()._corpus(tmp)
            raw = json.loads(manifest.read_text())
            raw["repo_root"] = "repo"
            for source in ("outside.py", "missing.py"):
                with self.subTest(source=source):
                    raw["implementation_sources"] = [source]
                    manifest.write_text(json.dumps(raw))
                    with self.assertRaises(ca.ManifestError) as cm:
                        ca.load_manifest(manifest)
                    self.assertIn("outside repo_root", str(cm.exception))
                    self.assertNotIn("not found", str(cm.exception))

    def test_repo_root_must_be_an_existing_directory(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest = BatchRunner()._corpus(tmp)
            raw = json.loads(manifest.read_text())
            (tmp / "root-file").write_text("not a directory\n")
            for root in ("root-file", "missing-root"):
                with self.subTest(root=root):
                    raw["repo_root"] = root
                    manifest.write_text(json.dumps(raw))
                    with self.assertRaises(ca.ManifestError) as cm:
                        ca.load_manifest(manifest)
                    self.assertIn("repo_root must be an existing directory", str(cm.exception))

    @unittest.skipIf(ca.fcntl is None, "containment after load requires an advisory lock")
    def test_a_parent_swap_after_load_is_refused_before_outside_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest, source = self._nested_corpus(tmp)
            loaded = ca.load_manifest(manifest)
            original_dir = source.parent
            parked = original_dir.with_name("original-src")
            original_dir.rename(parked)
            outside_dir = tmp / "outside"
            outside_dir.mkdir()
            outside = outside_dir / "check.py"
            outside.write_bytes((parked / "check.py").read_bytes())
            before = outside.read_bytes()
            original_dir.symlink_to(outside_dir, target_is_directory=True)

            with self.assertRaises(ca.ManifestError) as cm:
                ca._run_process(loaded, manifest)

            self.assertEqual(outside.read_bytes(), before)
        self.assertIn("outside repo_root", str(cm.exception))

    @unittest.skipIf(ca.fcntl is None, "containment after capture requires an advisory lock")
    def test_a_parent_swap_after_source_capture_is_refused_before_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest, source = self._nested_corpus(tmp)
            loaded = ca.load_manifest(manifest)
            original_dir = source.parent
            parked = original_dir.with_name("original-src")
            outside_dir = tmp / "outside"
            outside_dir.mkdir()
            outside = outside_dir / "check.py"
            outside.write_bytes(source.read_bytes())
            before = outside.read_bytes()
            real_build = ca._build
            swapped = False

            def build_then_swap(m):
                nonlocal swapped
                result = real_build(m)
                if not swapped:
                    original_dir.rename(parked)
                    original_dir.symlink_to(outside_dir, target_is_directory=True)
                    swapped = True
                return result

            captured = None
            report = None
            with mock.patch.object(ca, "_build", side_effect=build_then_swap):
                try:
                    report = ca._run_process(loaded, manifest)
                except ca.ManifestError as exc:
                    captured = exc

            # Isolation copies before _build. A parent swap of the ORIGINAL
            # after that copy must not write outside; the run may succeed.
            self.assertEqual(outside.read_bytes(), before)
            if captured is not None:
                self.assertNotIn(before + b"mutated", outside.read_bytes())
            else:
                self.assertIsNotNone(report)
            self._assert_lock_can_be_reacquired(Path(tmp) / "repo")
            captured = None
            gc.collect()

    @unittest.skipIf(ca.fcntl is None, "no POSIX advisory locks on this platform")
    def test_pre_guard_failure_releases_the_tree_lock(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest, source = self._nested_corpus(tmp)
            loaded = ca.load_manifest(manifest)
            before = source.read_bytes()
            captured = None
            with mock.patch.object(ca.IsolatedMutationTree, "materialize",
                                   side_effect=RuntimeError("probe")):
                try:
                    ca._run_process(loaded, manifest)
                except RuntimeError as exc:
                    captured = exc

            self.assertIsNotNone(captured)
            self.assertEqual(source.read_bytes(), before)
            self._assert_lock_can_be_reacquired(loaded["_repo_root"])
            captured = None
            gc.collect()

    @unittest.skipIf(ca.fcntl is None, "no POSIX advisory locks on this platform")
    def test_vector_validation_failure_does_not_leave_the_tree_lock_held(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            repo = tmp / "repo"
            repo.mkdir()
            source = repo / "check.py"
            source.write_text("print('ok')\n")
            (repo / "vectors.json").write_text(json.dumps({"vectors": [
                {"vector_id": "v1", "inputs": {}}]}))
            raw = {"schema": ca.SCHEMA, "runner": "process", "repo_root": "repo",
                   "implementation": "repo/check.py",
                   "implementation_sources": ["repo/check.py"],
                   "build": ["true"], "entrypoint_command": ["true"],
                   "outcome_from": "ok", "vectors": "repo/vectors.json",
                   "group_key": "axis", "id_key": "vector_id", "inputs_key": "inputs",
                   "mutants": {"a": [
                       {"label": "rule", "anchor": "print('ok')",
                        "replacement": "print('moved')"},
                       {"label": "CONTROL", "control": True,
                        "anchor": "print('ok')", "replacement": "print('control')"}]}}
            manifest = tmp / "m.json"
            manifest.write_text(json.dumps(raw))
            loaded = ca.load_manifest(manifest)
            captured = None
            try:
                ca._run_process(loaded, manifest)
            except ca.ManifestError as exc:
                captured = exc  # Refusal before lock; keep locals alive during the lock probe.
            self.assertIsNotNone(captured)

            self._assert_lock_can_be_reacquired(loaded["_repo_root"])
            captured = None
            gc.collect()


class Guards(unittest.TestCase):
    def test_a_group_in_the_corpus_with_no_mutants_is_a_hard_failure(self):
        v = {"vectors": VECTORS["vectors"] + [
            {"vector_id": "v3", "axis": "b", "inputs": {"n": 1}}]}
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(_manifest(Path(d), {"a": [KILLABLE]}, vectors=v))
        self.assertFalse(rep["adequate"])
        self.assertTrue(any("no declared mutants" in f for f in rep["failures"]))

    def test_a_stale_anchor_fails_rather_than_scoring_nothing(self):
        stale = {"label": "gone", "anchor": "this text is not in the impl",
                 "replacement": "nor is this"}
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(_manifest(Path(d), {"a": [KILLABLE, stale]}))
        self.assertFalse(rep["adequate"])
        self.assertTrue(any("anchor not found" in f for f in rep["failures"]))

    def test_mutants_declared_for_absent_groups_fail(self):
        with tempfile.TemporaryDirectory() as d:
            absent = dict(KILLABLE, label="absent-group-rule")
            rep = ca.run(_manifest(Path(d), {"a": [KILLABLE], "zz": [absent]}))
        self.assertTrue(any("not in the corpus" in f for f in rep["failures"]))


class ManifestValidation(unittest.TestCase):
    def _err(self, raw):
        with tempfile.TemporaryDirectory() as d:
            p = _manifest(Path(d), {"a": [KILLABLE]}, raw=raw)
            with self.assertRaises(ca.ManifestError) as cm:
                ca.load_manifest(p)
            return str(cm.exception)

    def test_wrong_schema_is_refused(self):
        self.assertIn("schema", self._err({"schema": "something.else"}))

    def test_no_mutants_is_refused_rather_than_scored_as_perfect(self):
        self.assertIn("no mutants", self._err({"mutants": {}}))

    def test_an_equivalence_without_a_reason_is_refused(self):
        self.assertIn("stated reason",
                      self._err({"equivalent": {"a": [{"label": "x", "reason": "  "}]}}))

    def test_a_mutant_that_changes_nothing_is_refused(self):
        self.assertIn("mutates nothing",
                      self._err({"mutants": {"a": [{"label": "noop", "anchor": "x",
                                                    "replacement": "x"}]}}))

    def test_duplicate_mutant_labels_across_groups_are_refused(self):
        duplicate = dict(SURVIVOR, label="same-hole")
        msg = self._err({"mutants": {"a": [duplicate], "b": [duplicate]}})
        self.assertIn("declared more than once", msg)
        self.assertIn("same-hole", msg)

    def test_duplicate_mutant_labels_within_one_group_are_refused(self):
        duplicate = dict(SURVIVOR, label="same-hole")
        msg = self._err({"mutants": {"a": [duplicate, duplicate]}})
        self.assertIn("declared more than once", msg)
        self.assertIn("same-hole", msg)

    def test_a_mutant_and_equivalent_cannot_share_one_label(self):
        duplicate = {"label": KILLABLE["label"], "reason": "also called equivalent"}
        msg = self._err({"equivalent": {"a": [duplicate]}})
        self.assertIn("declared more than once", msg)
        self.assertIn(KILLABLE["label"], msg)

    def test_equivalent_labels_are_unique_across_groups(self):
        duplicate = {"label": "same-equivalent", "reason": "same behavior"}
        msg = self._err({"equivalent": {"a": [duplicate], "b": [duplicate]}})
        self.assertIn("declared more than once", msg)
        self.assertIn("same-equivalent", msg)

    def test_duplicate_acknowledgements_for_one_digest_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "digest.json").write_text(json.dumps({"corpus_digest": "sha256:aaa"}))
            ack = {"label": "same-hole", "reason": "known gap", "recorded": "2026-08-20"}
            p = _manifest(tmp, {"a": [dict(SURVIVOR, label="same-hole")]}, raw={
                "corpus_digest_file": "digest.json", "corpus_digest_key": "corpus_digest",
                "known_holes": {"sha256:aaa": [ack, ack]}})
            with self.assertRaises(ca.ManifestError) as cm:
                ca.load_manifest(p)
        self.assertIn("acknowledgement", str(cm.exception))
        self.assertIn("same-hole", str(cm.exception))

    def test_one_acknowledgement_may_name_its_mutant(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "digest.json").write_text(json.dumps({"corpus_digest": "sha256:aaa"}))
            p = _manifest(tmp, {"a": [dict(SURVIVOR, label="same-hole")]}, raw={
                "corpus_digest_file": "digest.json", "corpus_digest_key": "corpus_digest",
                "known_holes": {"sha256:aaa": [{"label": "same-hole",
                                                  "reason": "known gap",
                                                  "recorded": "2026-08-20"}]}})
            loaded = ca.load_manifest(p)
        self.assertEqual(loaded["mutants"]["a"][0]["label"], "same-hole")

    def test_label_identity_is_exact_not_trimmed_or_case_folded(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "digest.json").write_text(json.dumps({"corpus_digest": "sha256:aaa"}))
            mutants = {"a": [dict(SURVIVOR, label="hole"),
                              dict(SURVIVOR, label="Hole"),
                              dict(SURVIVOR, label=" hole ")]}
            p = _manifest(tmp, mutants, raw={
                "corpus_digest_file": "digest.json", "corpus_digest_key": "corpus_digest",
                "known_holes": {"sha256:aaa": [{"label": "hole", "reason": "known gap",
                                                  "recorded": "2026-08-20"}]}})
            rep = ca.run(p)
        identities = {"hole", "Hole", " hole "}
        verdicts = {row["label"]: row["verdict"] for row in rep["mutants"]
                    if row["label"] in identities}
        self.assertEqual(verdicts, {
            "hole": "known-hole", "Hole": "survived", " hole ": "survived"})
        self.assertEqual(rep["known_holes"], 1)

    def test_a_mutant_label_must_be_a_non_empty_string(self):
        msg = self._err({"mutants": {"a": [dict(KILLABLE, label=[])]}})
        self.assertIn("mutants[a][0]", msg)
        self.assertIn("non-empty string", msg)

    def test_an_equivalent_label_must_be_a_non_empty_string(self):
        msg = self._err({"equivalent": {"a": [{"label": "  ", "reason": "same"}]}})
        self.assertIn("equivalent[a][0]", msg)
        self.assertIn("non-empty string", msg)

    def test_a_known_hole_label_must_be_a_non_empty_string(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "digest.json").write_text(json.dumps({"corpus_digest": "sha256:aaa"}))
            p = _manifest(tmp, {"a": [SURVIVOR]}, raw={
                "corpus_digest_file": "digest.json", "corpus_digest_key": "corpus_digest",
                "known_holes": {"sha256:aaa": [{"label": {}, "reason": "known gap",
                                                   "recorded": "2026-08-20"}]}})
            with self.assertRaises(ca.ManifestError) as cm:
                ca.load_manifest(p)
        self.assertIn("known_holes[sha256:aaa][0]", str(cm.exception))
        self.assertIn("non-empty string", str(cm.exception))


class RuleyFindings(unittest.TestCase):
    """Regressions for the blocking review on #2538. Each one scored 100% before."""

    def test_out_of_scope_without_a_reason_is_refused(self):
        # Finding 1: 1 killable + 5 unreasoned out_of_scope printed 100% and exited 0.
        # An out_of_scope mutant leaves the denominator exactly as an equivalent one
        # does, so it carries the same obligation.
        oos = dict(SURVIVOR, scope="out_of_scope")
        with tempfile.TemporaryDirectory() as d:
            p = _manifest(Path(d), {"a": [KILLABLE, oos]})
            with self.assertRaises(ca.ManifestError) as cm:
                ca.load_manifest(p)
        self.assertIn("stated reason", str(cm.exception))

    def test_an_empty_anchor_is_refused(self):
        # Finding 2a: "" matches everywhere, corrupts the source, and the resulting
        # import failure was then counted as a kill.
        with tempfile.TemporaryDirectory() as d:
            p = _manifest(Path(d), {"a": [{"label": "empty", "anchor": "",
                                           "replacement": "# x"}]})
            with self.assertRaises(ca.ManifestError) as cm:
                ca.load_manifest(p)
        self.assertIn("anchor is empty", str(cm.exception))

    def test_an_anchor_occurring_more_than_once_fails_the_run(self):
        # Finding 2b: a substring anchor mangled the source; the breakage scored as a kill.
        dup = {"label": "substring", "anchor": "inputs", "replacement": "broken"}
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(_manifest(Path(d), {"a": [KILLABLE, dup]}))
        self.assertFalse(rep["adequate"])
        self.assertTrue(any("occurs" in f and "unique" in f for f in rep["failures"]),
                        rep["failures"])

    def test_the_report_states_what_the_percentage_is_a_percentage_of(self):
        # Finding 3: the fix is the published sentence, not code. 100% is 100% of what
        # the author declared, never of the rules the implementation has.
        oos = dict(SURVIVOR, scope="out_of_scope", reason="not claimed")
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(_manifest(Path(d), {"a": [KILLABLE, oos]}))
        self.assertEqual(rep["declared_total"], 2)
        self.assertEqual(rep["out_of_scope_ratio"], 1.0)
        self.assertIn("author-declared", rep["score_means"])

    def test_the_out_of_scope_reason_is_printed_on_its_own_line(self):
        # Follow-up on the #2538 review: "each with a stated reason" without showing
        # one is an assertion. A declared equivalent already prints its reason.
        oos = dict(SURVIVOR, scope="out_of_scope", reason="UNIQUEMARKER not claimed here")
        with tempfile.TemporaryDirectory() as d:
            p = _manifest(Path(d), {"a": [KILLABLE, oos]})
            r = subprocess.run([sys.executable, str(ca.__file__), str(p)],
                               capture_output=True, text=True, timeout=120)
        self.assertIn("UNIQUEMARKER", r.stdout)

    def test_the_closing_line_is_qualified_when_most_rules_were_excluded(self):
        # Follow-up: the last line is what gets quoted, so at ratio > 1 it may not
        # read as unqualified success.
        oos = [dict(SURVIVOR, label=f"o{i}", anchor='return "ok"',
                    replacement=f'return "ok"  # {i}', scope="out_of_scope",
                    reason="not claimed") for i in range(3)]
        with tempfile.TemporaryDirectory() as d:
            p = _manifest(Path(d), {"a": [KILLABLE] + oos})
            r = subprocess.run([sys.executable, str(ca.__file__), str(p)],
                               capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0)
        last = [l for l in r.stdout.strip().splitlines() if l.strip()][-1]
        self.assertIn("DECLARED IN-SCOPE rules only", last)
        self.assertNotEqual(
            last.strip(), "mutation-adequacy check passed: every non-equivalent mutant is killed")

    def test_the_closing_line_is_unqualified_when_nothing_was_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            p = _manifest(Path(d), {"a": [KILLABLE]})
            r = subprocess.run([sys.executable, str(ca.__file__), str(p)],
                               capture_output=True, text=True, timeout=120)
        self.assertIn("every non-equivalent mutant is killed", r.stdout)

    def test_a_majority_excluded_corpus_says_so(self):
        oos = [dict(SURVIVOR, label=f"o{i}", anchor=f'return "ok"',
                    replacement=f'return "ok"  # {i}', scope="out_of_scope",
                    reason="not claimed") for i in range(3)]
        with tempfile.TemporaryDirectory() as d:
            p = _manifest(Path(d), {"a": [KILLABLE] + oos})
            r = subprocess.run([sys.executable, str(ca.__file__), str(p)],
                               capture_output=True, text=True, timeout=120)
        self.assertIn("more rules are excluded than measured", r.stdout)


class Portability(unittest.TestCase):
    def test_a_single_argument_entrypoint_is_supported(self):
        # Found by running the tool on a second corpus: signatures differ, and a
        # fixed arity would exclude every corpus that guessed differently.
        impl = 'def check(msg):\n    return "ok" if msg.get("k") else "no"\n'
        with tempfile.TemporaryDirectory() as raw:
            d = Path(raw)
            (d / "impl.py").write_text(impl)
            (d / "vectors.json").write_text(json.dumps({"vectors": [
                {"vector_id": "v1", "msg": {"k": 1}}, {"vector_id": "v2", "msg": {}}]}))
            m = {"schema": ca.SCHEMA, "implementation": "impl.py", "entrypoint": "check",
                 "entrypoint_args": ["msg"], "vectors": "vectors.json", "id_key": "vector_id",
                 "default_group": "only",
                 "mutants": {"only": [
                     {"label": "truthy branch",
                      "anchor": 'if msg.get("k")', "replacement": "if False"},
                     # Carried like any real corpus: this test is about entrypoint
                     # arity, not about being allowed to score without a control.
                     {"label": "CONTROL harness reachability", "control": True,
                      "anchor": 'def check(msg):',
                      "replacement": 'def check(msg):\n    return "MOVED"'}]}}
            p = d / "m.json"
            p.write_text(json.dumps(m))
            rep = ca.run(p)
        self.assertEqual(rep["killed"], 1)
        self.assertTrue(rep["adequate"])


class Cli(unittest.TestCase):
    def _cli(self, mutants, *args):
        with tempfile.TemporaryDirectory() as d:
            p = _manifest(Path(d), mutants)
            return subprocess.run([sys.executable, str(ca.__file__), str(p), *args],
                                  capture_output=True, text=True, timeout=120)

    def test_exit_0_when_adequate(self):
        self.assertEqual(self._cli({"a": [KILLABLE]}).returncode, 0)

    def test_exit_1_when_a_mutant_survives(self):
        self.assertEqual(self._cli({"a": [KILLABLE, SURVIVOR]}).returncode, 1)

    def test_exit_2_when_the_manifest_cannot_be_read(self):
        r = subprocess.run([sys.executable, str(ca.__file__), "/nope/missing.json"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 2)

    def test_missing_file_json_prints_error_envelope_and_keeps_stderr(self):
        # Shared catch: OSError is the same path as ManifestError. --json is not
        # a hole here; claiming it was would be the dishonest non-claim.
        r = subprocess.run(
            [sys.executable, str(ca.__file__), "/nope/missing.json", "--json"],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 2)
        self.assertIn("could not measure", r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        self.assertNotIn("Traceback", r.stdout)
        env = json.loads(r.stdout)
        self.assertEqual(env["schema"], "corpus-adequacy.error.v0")
        self.assertIs(env["ok"], False)
        self.assertEqual(env["exit"], 2)
        self.assertIn("could not measure", env["error"])

    def test_a_malformed_label_exits_2_without_a_traceback(self):
        with tempfile.TemporaryDirectory() as d:
            p = _manifest(Path(d), {"a": [dict(KILLABLE, label=[])]})
            r = subprocess.run([sys.executable, str(ca.__file__), str(p)],
                               capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 2)
        self.assertIn("non-empty string", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_json_mode_is_wellformed(self):
        d = json.loads(self._cli({"a": [KILLABLE]}, "--json").stdout)
        self.assertEqual(d["schema"], "corpus-adequacy.report.v0")
        self.assertEqual(d["tool_version"], ca.VERSION)

    def test_text_mode_names_the_tool_version(self):
        r = self._cli({"a": [KILLABLE]})
        self.assertIn("corpus-adequacy %s" % ca.VERSION, r.stdout)

    def test_version_flag_prints_the_constant_without_a_manifest(self):
        r = subprocess.run([sys.executable, str(ca.__file__), "--version"],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.strip(), ca.format_tool_identity())
        self.assertIn(ca.VERSION, r.stdout)

class ConcurrentRunsAreExcluded(unittest.TestCase):
    """Two runs over one working tree corrupt each other, in two ways.

    Visible: run A applies a mutant, run B reads the tree, cannot find its own
    anchor, and reports either `anchor not found` or a plausible score over a
    smaller denominator. That happened during review of this tool and produced a
    believable "6 of 8 (75.0%)" where two clean re-runs both gave 4 of 8.

    Silent and worse: run A captures its originals while run B has a mutant
    applied, so A's restore writes B's mutant into the tree AS the original --
    a disabled rule left behind, which is what _SourceGuard exists to prevent.

    Pinned at the artefact level, through run(), rather than on _TreeLock alone:
    a test of the helper is not a test of the thing that has to hold.
    """

    _corpus = BatchRunner._corpus

    @unittest.skipIf(ca.fcntl is None, "no POSIX advisory locks on this platform")
    def test_a_held_lock_refuses_the_run_rather_than_scoring_a_mixed_tree(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest = self._corpus(tmp)
            held = ca._TreeLock(tmp)
            held.__enter__()
            try:
                with self.assertRaises(ca.ManifestError) as cm:
                    ca.run(manifest)
            finally:
                held.__exit__()
        self.assertIn("another corpus-adequacy run holds the lock", str(cm.exception))

    @unittest.skipIf(ca.fcntl is None, "no POSIX advisory locks on this platform")
    def test_the_lock_is_released_so_the_next_run_still_measures(self):
        # A lock that outlives its run turns one crash into a repository nobody
        # can measure again. Two sequential runs must both score.
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest = self._corpus(tmp)
            first = ca.run(manifest)
            second = ca.run(manifest)
        self.assertEqual(first["killed"], 1)
        self.assertEqual(second["killed"], 1)

    @unittest.skipIf(ca.fcntl is None, "no POSIX advisory locks on this platform")
    def test_the_lock_is_taken_before_materialize(self):
        """Order: a tree copied outside the lock can change under another run."""
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest = self._corpus(tmp)
            called = []

            def boom(*_a, **_k):
                called.append(True)
                raise AssertionError("materialize must not run under a held lock")

            held = ca._TreeLock(tmp)
            held.__enter__()
            try:
                with mock.patch.object(ca.IsolatedMutationTree, "materialize",
                                       side_effect=boom):
                    with self.assertRaises(ca.ManifestError) as cm:
                        ca.run(manifest)
            finally:
                held.__exit__()
        self.assertIn("holds the lock", str(cm.exception))
        self.assertEqual(called, [])


class DeclaredOutcomeMembersMustExist(unittest.TestCase):
    """A member the implementation never emits compares None to None forever.

    Found on a real corpus: an adequacy manifest declared `all_reproduced`, the
    consumer emits `all_expected`, and `doc.get` returned None on every run. The
    comparison silently collapsed onto the one remaining member, and every score
    over it was over-generous by whatever the missing member would have caught.
    """

    def _corpus(self, tmp: Path, outcome_from):
        (tmp / "check.py").write_text(
            "import json, sys\n"
            "doc = json.load(open(sys.argv[1]))\n"
            "fails = [c['id'] for c in doc['cases'] if c['n'] > 10]\n"
            "print(json.dumps({'ok': not fails, 'failures': fails}))\n")
        (tmp / "vectors.json").write_text(json.dumps({"cases": [
            {"id": "c1", "n": 1}, {"id": "c2", "n": 2}]}))
        m = {"schema": ca.SCHEMA, "runner": "batch", "repo_root": ".",
             "implementation_sources": ["check.py"],
             "entrypoint_command": [_batch_python(), "check.py", "vectors.json"],
             "outcome_from": outcome_from, "vectors": "vectors.json",
             "id_key": "vector_id", "default_group": "g",
             "mutants": {"g": [
                 {"label": "threshold", "anchor": "c['n'] > 10", "replacement": "c['n'] > 1"},
                 {"label": "CONTROL", "control": True,
                  "anchor": "'ok': not fails", "replacement": "'ok': 'MOVED'"}]}}
        q = tmp / "m.json"
        q.write_text(json.dumps(m))
        return q

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_a_member_nothing_emits_is_reported_rather_than_compared_to_none(self):
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._corpus(Path(d), ["ok", "all_reproduced"]))
        msg = " ".join(rep["failures"])
        self.assertIn("all_reproduced", msg)
        self.assertIn("never emits", msg)
        self.assertFalse(rep["adequate"])

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_a_surface_the_implementation_does_emit_is_not_flagged(self):
        # The guard must not fire on a correct manifest, or it is noise.
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._corpus(Path(d), ["ok", "failures"]))
        self.assertNotIn("never emits", " ".join(rep["failures"]))
        _assert_process_batch_lock_verdict(self, rep)


class ControlIsRequiredOnEveryRunner(unittest.TestCase):
    """The requirement lived only in the process path, and a corpus fell through it.

    A rule stated in two places is a rule that will eventually be enforced in one.
    `mcp-jsonrpc-id` scored on the module runner with seventeen mutants and no
    control, while the page publishing its score said every manifest must declare
    one. Not a wrong number there -- six mutants were killed, so that harness
    demonstrably reached the code -- but the guarantee was absent: had a later
    change made all of them survive, nothing would have told that apart from a
    harness detecting nothing, which is the single thing a control exists to rule
    out.
    """

    def test_a_module_corpus_without_a_control_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(_manifest(Path(d), {"a": [KILLABLE]}, control=False))
        self.assertFalse(rep["adequate"], "a module run with no control must not pass")
        self.assertTrue(any("no control mutant declared" in f for f in rep["failures"]),
                        rep["failures"])

    def test_the_same_corpus_with_a_control_passes(self):
        # The other half of the control: the rule must not fail everything.
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(_manifest(Path(d), {"a": [KILLABLE]}))
        self.assertTrue(rep["adequate"], rep["failures"])

    def test_both_runners_answer_from_one_function(self):
        # Parity by construction rather than by two matching implementations,
        # which is how they came apart in the first place.
        import inspect
        src = inspect.getsource(ca)
        self.assertEqual(src.count("no control mutant declared"), 1,
                         "the control requirement is stated more than once again")


class ManifestShapeIsRefusedAsManifestError(unittest.TestCase):
    """A wrong JSON kind at the manifest boundary must not traceback.

    These five shapes currently raise AttributeError/TypeError out of load_manifest
    and the CLI. The contract is one shape rule, ManifestError, rc=2, and a
    parseable --json envelope.
    """

    def _overlay(self, tmp, **fields):
        p = _manifest(tmp, {"a": [KILLABLE]})
        data = json.loads(p.read_text())
        data.update(fields)
        p.write_text(json.dumps(data))
        return p

    def _refuse(self, **fields):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ca.ManifestError) as cm:
                ca.load_manifest(self._overlay(Path(d), **fields))
        return str(cm.exception)

    def test_mutants_as_a_number_is_a_manifest_error(self):
        msg = self._refuse(mutants=42)
        self.assertIn("mutants", msg)
        self.assertIn("int", msg)

    def test_a_mutant_group_as_a_number_is_a_manifest_error(self):
        msg = self._refuse(mutants={"a": 42})
        self.assertIn("mutants", msg)
        self.assertIn("int", msg)

    def test_a_mutant_entry_as_a_number_is_a_manifest_error(self):
        msg = self._refuse(mutants={"a": [42]})
        self.assertIn("mutants", msg)
        self.assertIn("int", msg)

    def test_known_holes_as_an_array_is_a_manifest_error(self):
        msg = self._refuse(known_holes=[])
        self.assertIn("known_holes", msg)
        self.assertIn("list", msg)

    def test_equivalent_as_an_array_is_a_manifest_error(self):
        msg = self._refuse(equivalent=[])
        self.assertIn("equivalent", msg)
        self.assertIn("list", msg)

    def test_json_mode_prints_a_parseable_error_envelope_and_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._overlay(Path(d), mutants=42)
            r = subprocess.run(
                [sys.executable, str(ca.__file__), str(p), "--json"],
                capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("Traceback", r.stdout)
        self.assertNotIn("Traceback", r.stderr)
        env = json.loads(r.stdout)
        self.assertEqual(env["schema"], "corpus-adequacy.error.v0")
        self.assertIs(env["ok"], False)
        self.assertEqual(env["exit"], 2)
        self.assertIn("mutants", env["error"])
        self.assertIn("int", env["error"])

    def test_a_valid_manifest_still_loads(self):
        with tempfile.TemporaryDirectory() as d:
            m = ca.load_manifest(_manifest(Path(d), {"a": [KILLABLE]}))
        self.assertIn("a", m["mutants"])


class ProcessBatchPlatformContract(unittest.TestCase):
    """Windows/non-POSIX is a supported refusal path, not a process/batch scoring path."""

    def test_fcntl_absence_is_the_process_batch_refusal_gate(self):
        self.assertIs(ca._TreeLock(Path(".")).unavailable, ca.fcntl is None)

    def test_missing_fcntl_refuses_before_source_build_or_score(self):
        """fcntl is None is enter-time refuse, not a scored run plus a footnote."""
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest = BatchRunner()._corpus(tmp)
            source = tmp / "check.py"
            before = source.read_bytes()
            tree_before = {
                path: path.read_bytes()
                for path in tmp.rglob("*") if path.is_file()
            }
            built = []
            children = []

            def track_build(m):
                built.append(True)
                return True, ""

            def track_child(*args, **kwargs):
                children.append(True)
                raise AssertionError("must not spawn a child")

            with mock.patch.object(ca, "fcntl", None), \
                    mock.patch.object(ca, "_build", side_effect=track_build), \
                    mock.patch.object(ca, "_run_capped", side_effect=track_child):
                lock = ca._TreeLock(tmp)
                with self.assertRaises(ca.ManifestError) as entered:
                    lock.__enter__()
                with self.assertRaises(ca.ManifestError) as cm:
                    ca.run(manifest)
            self.assertIn("no advisory lock", str(entered.exception))
            self.assertIn("no advisory lock", str(cm.exception))
            self.assertNotIn("adequate", str(cm.exception).lower())
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(
                {path: path.read_bytes() for path in tmp.rglob("*") if path.is_file()},
                tree_before,
            )
            self.assertEqual(built, [])
            self.assertEqual(children, [])

    def test_refusal_assertions_pin_fcntl_none_even_on_posix_hosts(self):
        """fcntl is None is ManifestError before work, not adequate=false after a score."""
        with mock.patch.object(ca, "fcntl", None):
            with self.assertRaises(ca.ManifestError) as cm:
                ca._TreeLock(Path(".")).__enter__()
            self.assertIn("no advisory lock", str(cm.exception))
            with self.assertRaises(AssertionError):
                _assert_process_batch_lock_verdict(
                    self, {"adequate": True, "failures": []})
            with self.assertRaises(AssertionError):
                _assert_process_batch_lock_verdict(
                    self, {"adequate": False,
                           "failures": ["no advisory lock on this platform"]})

    def test_batch_without_advisory_lock_is_a_refusal_not_a_score(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest = BatchRunner()._corpus(tmp)
            before = (tmp / "check.py").read_bytes()
            if ca.fcntl is None:
                with self.assertRaises(ca.ManifestError) as cm:
                    ca.run(manifest)
                self.assertIn("no advisory lock", str(cm.exception))
                self.assertEqual((tmp / "check.py").read_bytes(), before)
                return
            rep = ca.run(manifest)
        self.assertEqual(rep["killed"], 1)
        _assert_process_batch_lock_verdict(self, rep)


class BoundedRunPortability(unittest.TestCase):
    """Base _run_capped must not swallow a POSIX start_new_session failure."""

    def test_posix_start_new_session_valueerror_is_not_swallowed(self):
        if not hasattr(os, "setsid"):
            self.skipTest("no POSIX session primitive")
        real = subprocess.Popen

        def fake_popen(*args, **kwargs):
            if kwargs.get("start_new_session"):
                raise ValueError("start_new_session is only supported on POSIX")
            return real(*args, **kwargs)

        with mock.patch.object(subprocess, "Popen", side_effect=fake_popen):
            with self.assertRaises(ValueError) as cm:
                br._run_capped([sys.executable, "-c", "print('x')"], Path("."), 10)
        self.assertIn("start_new_session", str(cm.exception))



class NestedContainerShapeCli(unittest.TestCase):
    """CLI pins for nested container/entry kinds the first slice left unpinned."""

    CASES = (
        ("known_holes_digest",
         {"known_holes": {"sha256:aaa": 42}}, True, "known_holes"),
        ("known_holes_entry",
         {"known_holes": {"sha256:aaa": [42]}}, True, "known_holes"),
        ("equivalent_group",
         {"equivalent": {"a": 42}}, False, "equivalent"),
        ("equivalent_entry",
         {"equivalent": {"a": [42]}}, False, "equivalent"),
    )

    def _cli(self, fields, with_digest):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            p = _manifest(tmp, {"a": [KILLABLE]})
            data = json.loads(p.read_text())
            if with_digest:
                (tmp / "digest.json").write_text(json.dumps({"corpus_digest": "sha256:aaa"}))
                data["corpus_digest_file"] = "digest.json"
                data["corpus_digest_key"] = "corpus_digest"
            data.update(fields)
            p.write_text(json.dumps(data))
            return subprocess.run(
                [sys.executable, str(ca.__file__), str(p), "--json"],
                capture_output=True, text=True, timeout=60)

    def _assert_envelope(self, r, needle):
        self.assertEqual(r.returncode, 2)
        self.assertIn("could not measure", r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        self.assertNotIn("Traceback", r.stdout)
        env = json.loads(r.stdout)
        self.assertEqual(env["schema"], "corpus-adequacy.error.v0")
        self.assertIs(env["ok"], False)
        self.assertEqual(env["exit"], 2)
        self.assertIn(needle, env["error"])
        self.assertIn("int", env["error"])
        self.assertIn("could not measure", env["error"])

    def test_wrong_nested_kinds_exit_2_with_json_envelope_and_stderr(self):
        for name, fields, with_digest, needle in self.CASES:
            with self.subTest(name):
                self._assert_envelope(self._cli(fields, with_digest), needle)


VALID_CHILD_JSON = json.dumps({"ok": True, "failures": []})
VALID_TEST_NAMES = "test foo ... FAILED\ntest result: FAILED. 0 passed; 1 failed\n"


def _completed(returncode, stdout=VALID_CHILD_JSON, stderr=""):
    return subprocess.CompletedProcess(["child"], returncode, stdout, stderr)


def _policy_manifest(tmp: Path, extra=None, runner="batch"):
    extra = dict(extra or {})
    if runner == "batch":
        p = BatchRunner()._corpus(tmp)
        raw = json.loads(p.read_text(encoding="utf-8"))
        raw.update(extra)
        p.write_text(json.dumps(raw), encoding="utf-8")
        return p
    (tmp / "check.py").write_text("print('x')\n")
    (tmp / "vec.json").write_text("{}\n")
    (tmp / "vectors.json").write_text(json.dumps({
        "vectors": [{"vector_id": "v1", "path": "vec.json"}]}))
    raw = {
        "schema": ca.SCHEMA, "runner": "process", "repo_root": ".",
        "implementation": "check.py", "implementation_sources": ["check.py"],
        "build": [],
        "entrypoint_command": [_batch_python(), "check.py", "{vector}"],
        "outcome_from": ["ok", "failures"], "vectors": "vectors.json",
        "id_key": "vector_id", "vector_path_key": "path", "default_group": "g",
        "mutants": {"g": [
            {"label": "threshold",
             "anchor": "print('x')", "replacement": "print('y')"},
            {"label": "CONTROL", "control": True,
             "anchor": "print", "replacement": "print  # c"}]}}
    raw.update(extra)
    p = tmp / "m.json"
    p.write_text(json.dumps(raw), encoding="utf-8")
    return p


class ClassifyChildExit(unittest.TestCase):
    """Termination class is a function of returncode and the accepted set only."""

    def test_zero_is_ok_under_the_default_policy(self):
        self.assertEqual(ca.classify(0, [0]), "ok")

    def test_undeclared_positive_is_unexpected_exit(self):
        self.assertEqual(ca.classify(1, [0]), "unexpected-exit")
        self.assertEqual(ca.classify(2, [0]), "unexpected-exit")
        self.assertEqual(ca.classify(101, [0]), "unexpected-exit")

    def test_declared_positive_is_ok(self):
        self.assertEqual(ca.classify(101, [0, 101]), "ok")
        self.assertEqual(ca.classify(2, [0, 2]), "ok")

    def test_signal_is_signal_even_if_a_numeric_policy_lists_it(self):
        self.assertEqual(ca.classify(-9, [0]), "signal")
        self.assertEqual(ca.classify(-6, [0, -6]), "signal")

    def test_none_is_incomplete_even_if_the_policy_is_malformed(self):
        self.assertEqual(ca.classify(None, [0]), "incomplete")
        self.assertEqual(ca.classify(None, [True]), "incomplete")


class ChildOutcomeClassifyThenParse(unittest.TestCase):
    """Accepted termination is necessary, not sufficient. Classify before parse."""

    def _m(self, **fields):
        m = {"runner": "process", "outcome_from": ["ok", "failures"],
             "accepted_exit_codes": [0]}
        m.update(fields)
        return m

    def test_undeclared_positive_with_valid_json_is_unexpected_exit(self):
        value, _diag, kind = ca.child_outcome(self._m(), _completed(1))
        self.assertIsNone(value)
        self.assertEqual(kind, "unexpected-exit")

    def test_declared_2_with_valid_verifier_json_parses(self):
        value, _diag, kind = ca.child_outcome(
            self._m(accepted_exit_codes=[0, 2]), _completed(2))
        self.assertEqual(kind, None)
        self.assertEqual(value, (True, []))

    def test_undeclared_2_with_valid_verifier_json_does_not_parse(self):
        value, _diag, kind = ca.child_outcome(self._m(), _completed(2))
        self.assertIsNone(value)
        self.assertEqual(kind, "unexpected-exit")

    def test_declared_101_with_test_names_parses(self):
        m = self._m(runner="batch", outcome_parse="test-names",
                    accepted_exit_codes=[0, 101])
        value, _diag, kind = ca.child_outcome(m, _completed(101, VALID_TEST_NAMES))
        self.assertEqual(kind, None)
        self.assertEqual(value, ("foo",))

    def test_undeclared_101_with_test_names_is_unexpected_exit(self):
        m = self._m(runner="batch", outcome_parse="test-names",
                    accepted_exit_codes=[0])
        value, _diag, kind = ca.child_outcome(m, _completed(101, VALID_TEST_NAMES))
        self.assertIsNone(value)
        self.assertEqual(kind, "unexpected-exit")

    def test_signal_with_valid_output_never_parses(self):
        value, _diag, kind = ca.child_outcome(self._m(), _completed(-9))
        self.assertIsNone(value)
        self.assertEqual(kind, "signal")

    def test_none_with_valid_output_never_parses(self):
        value, _diag, kind = ca.child_outcome(self._m(), _completed(None))
        self.assertIsNone(value)
        self.assertEqual(kind, "incomplete")

    def test_accepted_2_with_empty_stdout_is_parse_error(self):
        value, _diag, kind = ca.child_outcome(
            self._m(accepted_exit_codes=[0, 2]), _completed(2, ""))
        self.assertIsNone(value)
        self.assertEqual(kind, "parse-error")

    def test_accepted_zero_with_malformed_output_is_parse_error(self):
        value, _diag, kind = ca.child_outcome(self._m(), _completed(0, "not-json"))
        self.assertIsNone(value)
        self.assertEqual(kind, "parse-error")

    def test_rejected_exit_with_malformed_output_is_unexpected_exit(self):
        value, _diag, kind = ca.child_outcome(self._m(), _completed(1, "not-json"))
        self.assertIsNone(value)
        self.assertEqual(kind, "unexpected-exit")

    def test_accepted_exit_with_non_object_json_is_parse_error(self):
        cases = (
            ("rc0 array", 0, [0], "[]"),
            ("rc0 null", 0, [0], "null"),
            ("rc0 true", 0, [0], "true"),
            ("rc0 number", 0, [0], "1"),
            ("rc0 string", 0, [0], '"ok"'),
            ("declared rc2 array", 2, [0, 2], "[]"),
            ("declared rc2 null", 2, [0, 2], "null"),
        )
        for name, rc, accepted, stdout in cases:
            with self.subTest(name):
                try:
                    value, _diag, kind = ca.child_outcome(
                        self._m(accepted_exit_codes=accepted),
                        _completed(rc, stdout))
                except Exception as exc:  # noqa: BLE001 - leak is the defect
                    self.fail("non-object JSON leaked %s: %r" % (type(exc).__name__, exc))
                self.assertIsNone(value)
                self.assertEqual(kind, "parse-error")


class ChildExitCallsites(unittest.TestCase):
    """One classifier, used before parse, at both outcome-child callsites."""

    def test_child_outcome_calls_classify(self):
        src = inspect.getsource(ca.child_outcome)
        self.assertIn("classify(", src)

    def test_child_outcome_classifies_before_it_parses(self):
        src = inspect.getsource(ca.child_outcome)
        self.assertLess(src.index("classify("), src.index("json.loads"))

    def test_process_and_batch_call_child_outcome_and_do_not_parse_themselves(self):
        for fn in (ca._batch_outcome, ca._process_outcomes):
            with self.subTest(fn.__name__):
                src = inspect.getsource(fn)
                self.assertIn("child_outcome(", src)
                self.assertNotIn("json.loads", src)

    def test_build_stays_outside_the_outcome_exit_rule(self):
        src = inspect.getsource(ca._build)
        self.assertNotIn("classify(", src)
        self.assertNotIn("child_outcome(", src)
        self.assertNotIn("accepted_exit_codes", src)


class ProcessAndBatchRefuseParseableCrash(unittest.TestCase):
    """Both runners classify mocked children; no real abort or _exit."""

    def _vectors(self, runner, loaded):
        if runner == "batch":
            return [{loaded["id_key"]: "<batch>"}]
        return [{"vector_id": "v1", "path": "vec.json"}]

    def _run_outcomes(self, runner, extra, child):
        with tempfile.TemporaryDirectory() as d:
            loaded = ca.load_manifest(_policy_manifest(Path(d), extra, runner=runner))
            with mock.patch.object(ca, "_run_capped", return_value=child):
                return ca._process_outcomes(loaded, self._vectors(runner, loaded))

    def test_parseable_stdout_then_undeclared_exit_is_not_an_outcome(self):
        for runner in ("process", "batch"):
            with self.subTest(runner=runner):
                out, _diag, failed = self._run_outcomes(runner, {}, _completed(1))
                self.assertEqual(out, {})
                self.assertEqual(set(failed.values()), {"unexpected-exit"})

    def test_parseable_stdout_then_signal_is_not_an_outcome(self):
        for runner in ("process", "batch"):
            with self.subTest(runner=runner):
                out, _diag, failed = self._run_outcomes(runner, {}, _completed(-11))
                self.assertEqual(out, {})
                self.assertEqual(set(failed.values()), {"signal"})

    def test_timeout_is_timeout_not_a_crash_or_outcome(self):
        for runner in ("process", "batch"):
            with self.subTest(runner=runner):
                with tempfile.TemporaryDirectory() as d:
                    loaded = ca.load_manifest(_policy_manifest(Path(d), runner=runner))
                    with mock.patch.object(
                            ca, "_run_capped",
                            side_effect=subprocess.TimeoutExpired(["child"], 1)):
                        out, _diag, failed = ca._process_outcomes(
                            loaded, self._vectors(runner, loaded))
                self.assertEqual(out, {})
                self.assertEqual(set(failed.values()), {"timeout"})

    def test_output_cap_is_output_cap_not_a_crash_or_outcome(self):
        for runner in ("process", "batch"):
            with self.subTest(runner=runner):
                with tempfile.TemporaryDirectory() as d:
                    loaded = ca.load_manifest(_policy_manifest(Path(d), runner=runner))
                    with mock.patch.object(
                            ca, "_run_capped", side_effect=br._OutputTooLarge()):
                        out, _diag, failed = ca._process_outcomes(
                            loaded, self._vectors(runner, loaded))
                self.assertEqual(out, {})
                self.assertEqual(set(failed.values()), {"output-cap"})

    def test_rc0_valid_json_is_still_an_outcome(self):
        out, _diag, failed = self._run_outcomes("batch", {}, _completed(0))
        self.assertEqual(failed, {})
        self.assertEqual(out["<batch>"], (True, ()))


class AcceptedExitPolicy(unittest.TestCase):
    """One load-time validator: unique nonnegative ints plus protocol codes."""

    def _load(self, extra, runner="batch"):
        with tempfile.TemporaryDirectory() as d:
            return ca.load_manifest(_policy_manifest(Path(d), extra, runner=runner))

    def _refuse(self, extra, runner="batch"):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ca.ManifestError) as cm:
                ca.load_manifest(_policy_manifest(Path(d), extra, runner=runner))
        return str(cm.exception)

    def test_default_accepted_exit_codes_is_zero_only(self):
        loaded = self._load({})
        self.assertEqual(loaded["accepted_exit_codes"], [0])

    def test_bool_true_is_a_manifest_error(self):
        msg = self._refuse({"accepted_exit_codes": [True]})
        self.assertIn("accepted_exit_codes", msg)
        self.assertIn("bool", msg)

    def test_test_names_without_101_is_a_manifest_error(self):
        # Protocol test-names: cargo-test failures use existing code 101.
        # This repository ships no manifests.
        msg = self._refuse({"outcome_parse": "test-names"})
        self.assertIn("101", msg)
        self.assertIn("test-names", msg)

    def test_test_names_with_101_loads(self):
        loaded = self._load({
            "outcome_parse": "test-names", "accepted_exit_codes": [0, 101]})
        self.assertEqual(loaded["accepted_exit_codes"], [0, 101])

    def test_test_names_on_process_is_a_manifest_error(self):
        msg = self._refuse({
            "outcome_parse": "test-names", "accepted_exit_codes": [0, 101],
        }, runner="process")
        self.assertIn("test-names", msg)
        self.assertIn("process", msg)

    def test_test_names_on_module_without_101_is_a_manifest_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = _manifest(Path(d), {"a": [KILLABLE]}, raw={
                "runner": "module", "outcome_parse": "test-names"})
            with self.assertRaises(ca.ManifestError) as cm:
                ca.load_manifest(p)
        self.assertIn("test-names", str(cm.exception))

    def test_test_names_on_module_with_101_is_still_a_manifest_error(self):
        # Runner mismatch, not the batch 101 obligation. Including [0, 101]
        # must not let a module manifest load and ignore the parse mode.
        with tempfile.TemporaryDirectory() as d:
            p = _manifest(Path(d), {"a": [KILLABLE]}, raw={
                "runner": "module", "outcome_parse": "test-names",
                "accepted_exit_codes": [0, 101]})
            with self.assertRaises(ca.ManifestError) as cm:
                ca.load_manifest(p)
        msg = str(cm.exception)
        self.assertIn("test-names", msg)
        self.assertIn("module", msg)
        self.assertNotIn("101", msg)

    def test_declared_2_loads_on_generic_json(self):
        # JSON outcome_from has no protocol ID. Code 2 is declared, not inferred.
        loaded = self._load({"accepted_exit_codes": [0, 2]}, runner="process")
        self.assertEqual(loaded["accepted_exit_codes"], [0, 2])

    def test_generic_json_command_is_not_refused_by_argv(self):
        loaded = self._load({
            "entrypoint_command": [
                "verifier", "verify-privileged-mcp-action", "{vector}"],
        }, runner="process")
        self.assertEqual(loaded["accepted_exit_codes"], [0])

    def test_validator_does_not_recognize_commands_by_name(self):
        src = inspect.getsource(ca.accepted_exit_codes)
        self.assertNotIn("verify-privileged", src)
        self.assertNotIn("entrypoint_command", src)

    def test_docs_do_not_claim_downstream_manifests_were_migrated(self):
        root = Path(__file__).resolve().parent.parent
        readme = (root / "README.md").read_text(encoding="utf-8")
        changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("ships no", readme.lower())
        self.assertIn("does not migrate", changelog.lower())

    def test_a_negative_code_is_a_manifest_error(self):
        msg = self._refuse({"accepted_exit_codes": [0, -9]})
        self.assertIn("accepted_exit_codes", msg)

    def test_a_duplicate_code_is_a_manifest_error(self):
        msg = self._refuse({"accepted_exit_codes": [0, 0]})
        self.assertIn("accepted_exit_codes", msg)


class ChildExitRunSemantics(unittest.TestCase):
    """Unmutated/control fail closed with no score; a mutant abort may kill."""

    def _fake_from_source(self, *, control_rc=0, mutant_rc=0, baseline_rc=0,
                          stdout=VALID_CHILD_JSON, mutant_stdout=None,
                          control_stdout=None):
        def fake(cmd, cwd, timeout):
            src = Path(cwd, "check.py").read_text(encoding="utf-8")
            if "'ok': 'MOVED'" in src:
                return _completed(
                    control_rc,
                    control_stdout or json.dumps({"ok": False, "failures": ["c2"]}))
            if "c['n'] > 1" in src and "c['n'] > 10" not in src:
                return _completed(mutant_rc, mutant_stdout or stdout)
            return _completed(baseline_rc, stdout)
        return fake

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_unmutated_abnormal_exit_is_a_group_failure_with_no_score(self):
        with tempfile.TemporaryDirectory() as d:
            p = BatchRunner()._corpus(Path(d))
            with mock.patch.object(ca, "_run_capped",
                                   return_value=_completed(1)):
                rep = ca.run(p)
        self.assertFalse(rep["adequate"])
        self.assertTrue(any("UNMUTATED" in f for f in rep["failures"]),
                        rep["failures"])
        self.assertIsNone(rep["score_percent"])
        self.assertEqual(rep["killed"], 0)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_control_abnormal_exit_is_control_error_not_killed(self):
        with tempfile.TemporaryDirectory() as d:
            p = BatchRunner()._corpus(Path(d))
            with mock.patch.object(
                    ca, "_run_capped",
                    side_effect=self._fake_from_source(control_rc=1)):
                rep = ca.run(p)
        verdicts = {r["label"]: r for r in rep["mutants"]}
        self.assertEqual(verdicts["CONTROL"]["verdict"], "control-error")
        self.assertEqual(rep["control_status"], "error")
        self.assertNotEqual(verdicts["CONTROL"]["verdict"], "control-killed")
        self.assertIn("unexpected-exit", verdicts["CONTROL"]["how"])
        self.assertFalse(rep["adequate"])
        self.assertIsNone(rep["score_percent"])
        self.assertEqual(rep["killed"], 0)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_abnormal_control_emits_no_ordinary_row_and_has_no_score(self):
        moved = json.dumps({"ok": False, "failures": ["c2"]})
        with tempfile.TemporaryDirectory() as d:
            p = BatchRunner()._corpus(Path(d))
            with mock.patch.object(
                    ca, "_run_capped",
                    side_effect=self._fake_from_source(
                        control_rc=1, mutant_stdout=moved)):
                rep = ca.run(p)
        verdicts = {r["label"]: r for r in rep["mutants"]}
        self.assertNotIn("threshold", verdicts)
        self.assertEqual(verdicts["CONTROL"]["verdict"], "control-error")
        self.assertFalse(rep["adequate"])
        self.assertIsNone(rep["score_percent"])
        self.assertEqual(rep["killed"], 0)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_mutant_unexpected_exit_is_a_kill_naming_the_class(self):
        with tempfile.TemporaryDirectory() as d:
            p = BatchRunner()._corpus(Path(d))
            with mock.patch.object(
                    ca, "_run_capped",
                    side_effect=self._fake_from_source(mutant_rc=1)):
                rep = ca.run(p)
        row = next(r for r in rep["mutants"] if r["label"] == "threshold")
        self.assertEqual(row["verdict"], "killed")
        self.assertIn("unexpected-exit", row["how"])

    def _text_report(self, **fields):
        rep = {
            "schema": "corpus-adequacy.report.v0", "manifest": "m.json",
            "killed": 1, "survived": 0, "equivalent": 0,
            "known_holes": 0, "unexercised_out_of_scope": 0, "unproved": 0,
            "declared_total": 1, "out_of_scope_ratio": 0.0, "hole_ratio": 0.0,
            "score_percent": 100.0, "score_means": "author-declared",
            "adequate": True, "failures": [], "tool_version": "0.1.0",
            "tool_commit": None,
            "mutants": [{"group": "g", "verdict": "killed",
                         "label": "threshold", "how": "unexpected-exit"}],
        }
        rep.update(fields)
        with mock.patch.object(ca, "run", return_value=rep), \
                mock.patch.object(sys, "argv", ["corpus_adequacy.py", "m.json"]):
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = ca.main()
        return rc, buf.getvalue()

    def test_text_and_json_name_the_failure_class_for_a_killed_mutant(self):
        rc, text = self._text_report(runner="process")
        self.assertEqual(rc, 0)
        self.assertIn("unexpected-exit", text)
        self.assertIn("killed", text)

    def test_module_killed_text_omits_the_how_line(self):
        rc, text = self._text_report()
        self.assertEqual(rc, 0)
        self.assertIn("killed", text)
        killed_lines = [ln for ln in text.splitlines() if "killed" in ln and "threshold" in ln]
        self.assertTrue(killed_lines, text)
        idx = text.splitlines().index(killed_lines[0])
        following = text.splitlines()[idx + 1]
        self.assertNotEqual(following.strip(), "unexpected-exit")
        self.assertFalse(following.startswith("    "))


# ---------------------------------------------------------------------------
# module runner: the corpus runs in a disposable child, never in this process
# ---------------------------------------------------------------------------

HOSTILE_IMPL = '''
def evaluate(group, inputs):
    if inputs.get("bad"):
        return "rejected"
    return "ok"
'''


def _hostile_manifest(tmp: Path, body: str, label="hostile", extra=None) -> Path:
    """A module corpus whose one scored mutant replaces the first rule's body.

    `body` is re-indented to the anchor's column, so it may be several
    statements. The control is carried like any real corpus.
    """
    (tmp / "impl.py").write_text(HOSTILE_IMPL)
    (tmp / "vectors.json").write_text(json.dumps(VECTORS))
    m = {"schema": ca.SCHEMA, "implementation": "impl.py", "entrypoint": "evaluate",
         "vectors": "vectors.json", "group_key": "axis", "id_key": "vector_id",
         "inputs_key": "inputs",
         "mutants": {"a": [{"label": label, "anchor": 'return "rejected"',
                            "replacement": "\n        ".join(body.strip().splitlines())},
                           dict(CONTROL, label="CONTROL [a]")]}}
    if extra:
        m.update(extra)
    p = tmp / "m.json"
    p.write_text(json.dumps(m))
    return p


def _tool_json(manifest: Path, timeout: float):
    """Run the tool as CI does. A hostile mutant that reaches the measuring
    process can end or hang it, and a suite that vanishes reads like
    infrastructure trouble rather than a lost boundary."""
    r = subprocess.run([sys.executable, str(ca.__file__), str(manifest), "--json"],
                       capture_output=True, timeout=timeout)
    try:
        rep = json.loads(r.stdout.decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - absence of a report is the assertion
        rep = None
    return r, rep


def _verdict(rep: dict, label: str) -> dict:
    return next(r for r in rep["mutants"] if r["label"] == label)


class ModuleCorpusRunsInAChild(unittest.TestCase):
    """The ways a module mutant reached the tool itself, each reproduced on
    this runner before the boundary existed. _module_outcomes names them."""

    def test_a_mutant_that_never_returns_is_bounded_and_killed(self):
        with tempfile.TemporaryDirectory() as d:
            p = _hostile_manifest(Path(d), "while True:\n    pass", "endless",
                                  extra={"vector_timeout": 3})
            started = time.monotonic()
            r, rep = _tool_json(p, timeout=90)
            elapsed = time.monotonic() - started
        self.assertIsNotNone(rep, r.stderr[-400:])
        self.assertLess(elapsed, 60, "the deadline did not bound the child")
        self.assertEqual(_verdict(rep, "endless")["how"], "timeout")
        self.assertEqual(_verdict(rep, "endless")["verdict"], "killed")

    def test_systemexit_from_the_entrypoint_does_not_end_the_tool(self):
        # SystemExit escapes collect(), terminates the child, and the parent
        # sees unexpected-exit. The parent is alive with a parseable report.
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(_hostile_manifest(Path(d), "raise SystemExit(9)", "systemexit"))
        v = _verdict(rep, "systemexit")
        self.assertEqual(v["verdict"], "killed")
        self.assertEqual(v["how"], "unexpected-exit")

    def test_os_exit_leaves_the_tool_standing_and_the_rule_unproved(self):
        # The worst of them: exit 0 with no report is what a CI gate reads as
        # "the adequacy check passed". Exit 0 with nothing parseable is a failed
        # measurement, not a rule the corpus caught, so it is unproved.
        with tempfile.TemporaryDirectory() as d:
            p = _hostile_manifest(Path(d), '__import__("os")._exit(0)', "os_exit")
            r, rep = _tool_json(p, timeout=90)
        self.assertIsNotNone(rep, "the tool produced no report at all")
        self.assertEqual(_verdict(rep, "os_exit")["verdict"], "unproved")
        self.assertIn("no-result", _verdict(rep, "os_exit")["how"])
        self.assertFalse(rep["adequate"])
        self.assertEqual(r.returncode, 1)

    def test_a_flooding_mutant_is_bounded_and_still_leaves_a_report(self):
        body = 'for _i in range(5):\n    print("F" * (1 << 20))\nreturn "rejected"'
        with tempfile.TemporaryDirectory() as d:
            p = _hostile_manifest(Path(d), body, "flood")
            r, rep = _tool_json(p, timeout=180)
        self.assertLess(len(r.stdout), 1 << 20, "the mutant's output reached the tool's stdout")
        self.assertIsNotNone(rep, "the flood displaced the report")
        self.assertEqual(_verdict(rep, "flood")["how"], "output-cap")
        self.assertEqual(_verdict(rep, "flood")["verdict"], "killed")

    def test_candidate_writes_are_not_false_kills(self):
        # A mutant that only writes changes no outcome, and scoring it a kill
        # inflates the number exactly as a missed rule deflates it. print() a
        # Python-level redirect would catch; the fd 1 write it would not, which
        # is why fd 1 is pointed at the bounded stderr before any corpus runs.
        for label, write in (("chatty", 'print("chatty")'),
                             ("fd1", 'import os as _o\n_o.write(1, b"pollution")')):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as d:
                rep = ca.run(_hostile_manifest(
                    Path(d), '%s\nreturn "rejected"' % write, label))
                self.assertEqual(_verdict(rep, label)["verdict"], "survived")

    # Keyed on the platform, not on _posix_process_group(): a guard that asks the
    # code under test whether to run cannot catch that code being removed.
    @unittest.skipUnless(os.name == "posix",
                         "process-group cleanup is POSIX; Windows keeps the process-tree nonclaim")
    def test_a_descendant_does_not_outlive_the_run(self):
        with tempfile.TemporaryDirectory() as d:
            pidfile = Path(d) / "descendant.pid"
            child = ("import os, sys, time\n"
                     "open(sys.argv[1], 'w').write(str(os.getpid()))\n"
                     "time.sleep(300)\n")
            body = ('import subprocess as _s, sys as _y, time as _t\n'
                    '_s.Popen([_y.executable, "-c", %r, %r],\n'
                    '         stdout=_s.DEVNULL, stderr=_s.DEVNULL)\n'
                    '_t.sleep(0.5)\n'
                    'return "rejected"' % (child, str(pidfile)))
            ca.run(_hostile_manifest(Path(d), body, "spawner"))
            self.assertTrue(pidfile.is_file(), "the fixture never spawned a descendant")
            pid = int(pidfile.read_text())
            alive = self._alive(pid)
            if alive:
                os.kill(pid, signal.SIGKILL)
        self.assertFalse(alive, "descendant %d outlived the run" % pid)

    @staticmethod
    def _alive(pid: int) -> bool:
        for _ in range(20):
            try:
                os.kill(pid, 0)
            except OSError:
                return False
            time.sleep(0.05)
        return True


class _NthChild:
    """Stand in for the nth _run_capped call; run the real one for the rest."""

    def __init__(self, n, exc=None, returncode=None, stdout=""):
        self.real = ca._run_capped
        self.n, self.exc, self.returncode, self.stdout = n, exc, returncode, stdout
        self.calls = 0

    def __call__(self, cmd, cwd, timeout):
        self.calls += 1
        if self.calls != self.n:
            return self.real(cmd, cwd, timeout)
        if self.exc is not None:
            raise self.exc
        return subprocess.CompletedProcess(cmd, self.returncode, self.stdout, "")


# The child terminated abnormally, and we know that before reading its output.
TERMINATED = (("timeout", dict(exc=subprocess.TimeoutExpired(["x"], 1))),
              ("output-cap", dict(exc=br._OutputTooLarge())),
              ("unexpected-exit", dict(returncode=3)),
              ("signal", dict(returncode=-9)))
# The child was never started, or exited cleanly leaving nothing usable.
UNMEASURED = (("incomplete", dict(exc=OSError("no child"))),
              ("no-result", dict(returncode=0, stdout="")),
              ("parse-error", dict(returncode=0, stdout="{")))


class ModuleChildTerminationIsClassifiedBeforeParse(unittest.TestCase):
    """Which role the dead child belonged to decides what may be said.

    Observed termination of a scored mutant is a named kill. A measurement that
    merely failed is unproved, because crediting the corpus with a catch it was
    never shown is the over-claim this tool exists to find. The unmutated run
    and the control are what every other verdict rests on.
    """

    def _run(self, nth, kw):
        with tempfile.TemporaryDirectory() as d:
            p = _hostile_manifest(Path(d), 'return "REJECTED"', "scored")
            with mock.patch.object(ca, "_run_capped", _NthChild(nth, **kw)):
                return ca.run(p)

    def test_observed_termination_of_a_mutant_child_is_a_named_kill(self):
        for kind, kw in TERMINATED:
            with self.subTest(kind=kind):
                rep = self._run(2, kw)
                v = _verdict(rep, "scored")
                self.assertEqual((v["verdict"], v["how"], v["moved"]), ("killed", kind, 0))

    def test_a_failed_measurement_is_unproved_and_never_a_kill(self):
        for kind, kw in UNMEASURED:
            with self.subTest(kind=kind):
                rep = self._run(2, kw)
                v = _verdict(rep, "scored")
                self.assertEqual(v["verdict"], "unproved")
                self.assertIn(kind, v["how"])
                self.assertEqual((rep["killed"], rep["survived"]), (0, 0))
                self.assertFalse(rep["adequate"])

    def test_a_parseable_report_on_an_unaccepted_code_is_not_parsed(self):
        # Classify before parse. This payload says both vectors are unchanged,
        # so parsing it would report a survivor; the exit code says the child
        # did not finish, and that is what the verdict must come from.
        payload = json.dumps({"schema": ca.MODULE_CHILD_SCHEMA,
                              "outcomes": {"0": "rejected", "1": "ok"},
                              "raised": [], "unsupported": [],
                              "load_error": None, "entrypoint_missing": False})
        rep = self._run(2, dict(returncode=7, stdout=payload))
        v = _verdict(rep, "scored")
        self.assertEqual((v["verdict"], v["how"]), ("killed", "unexpected-exit"))

    def test_a_child_that_reported_only_some_vectors_is_not_a_measurement(self):
        # Silence about a vector reads as "unchanged", so a partial report makes
        # a mutant that moved the missing vector look like a survivor.
        partial = json.dumps({"schema": ca.MODULE_CHILD_SCHEMA,
                              "outcomes": {"0": "rejected"}, "raised": [],
                              "unsupported": [], "load_error": None,
                              "entrypoint_missing": False})
        rep = self._run(2, dict(returncode=0, stdout=partial))
        v = _verdict(rep, "scored")
        self.assertEqual(v["verdict"], "unproved")
        self.assertIn("parse-error", v["how"])
        self.assertEqual(rep["survived"], 0)

    def test_a_dead_unmutated_child_invalidates_the_run(self):
        for kind, kw in TERMINATED + UNMEASURED:
            with self.subTest(kind=kind):
                rep = self._run(1, kw)
                self.assertIsNone(rep["score_percent"])
                self.assertFalse(rep["adequate"])
                self.assertTrue(any("UNMUTATED" in f and kind in f for f in rep["failures"]),
                                rep["failures"])
                self.assertEqual(rep["killed"], 0)

    def test_a_dead_control_child_invalidates_the_run(self):
        for kind, kw in TERMINATED + UNMEASURED:
            with self.subTest(kind=kind):
                rep = self._run(3, kw)
                self.assertIsNone(rep["score_percent"])
                self.assertFalse(rep["adequate"])
                self.assertEqual(_verdict(rep, "CONTROL [a]")["verdict"], "control-error")
                self.assertEqual(rep["control_status"], "error")
                self.assertTrue(any("control" in f and "abnormally" in f
                                    for f in rep["failures"]), rep["failures"])

    def test_systemexit_in_a_control_is_control_error_not_control_killed(self):
        """SystemExit is process-control, not an application error. collect()
        catches Exception only, so SystemExit escapes, terminates the child,
        and the parent sees unexpected-exit → control-error. The score is
        invalid because the control measurement failed.
        """
        ctrl = {"label": "CONTROL systemexit", "control": True,
                "anchor": 'def evaluate(group, inputs):',
                "replacement": 'def evaluate(group, inputs):\n    raise SystemExit(42)'}
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(_manifest(Path(d), {"a": [KILLABLE, ctrl]}, control=False))
        v = _verdict(rep, "CONTROL systemexit")
        self.assertEqual(v["verdict"], "control-error")
        self.assertIn("unexpected-exit", v["how"])
        self.assertFalse(rep["adequate"])
        self.assertIsNone(rep["score_percent"])

    def test_an_outcome_the_transport_cannot_carry_is_unproved(self):
        # Not a new type system: whatever JSON carries is compared, and a value
        # it cannot carry is declined rather than guessed at.
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(_hostile_manifest(Path(d), "return object()", "unsupported"))
        v = _verdict(rep, "unsupported")
        self.assertEqual(v["verdict"], "unproved")
        self.assertIn("unsupported-outcome", v["how"])
        self.assertFalse(rep["adequate"])

class MutableOutcomeIsNotAFalseKill(unittest.TestCase):
    """F2: without snapshot, a mutable alias becomes unserialisable and the
    child crashes.  The parent sees unexpected-exit → killed: a false clean.

    With snapshot the baseline and mutant outcomes are identical JSON values,
    so the mutant survives and the corpus is correctly inadequate.
    """

    # Baseline: bad=True → return [] (fresh list); bad=False → append object()
    # to _shared then return "ok".
    # Mutant: replaces `return []` with `return _shared`.  At call time both
    # return [], but the mutant's stored reference is _shared itself.  The
    # second vector appends object() to _shared.  Without snapshot, emit()
    # crashes on the now-corrupt entry.
    _IMPL = (
        '_shared = []\n'
        'def evaluate(group, inputs):\n'
        '    if inputs.get("bad"):\n'
        '        return []\n'
        '    _shared.append(object())\n'
        '    return "ok"\n'
    )
    _VECTORS = {"vectors": [
        {"vector_id": "v1", "axis": "a", "inputs": {"bad": True}},
        {"vector_id": "v2", "axis": "a", "inputs": {}},
    ]}

    def _run(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "impl.py").write_text(self._IMPL)
            (tmp / "vectors.json").write_text(json.dumps(self._VECTORS))
            m = {"schema": ca.SCHEMA, "implementation": "impl.py",
                 "entrypoint": "evaluate", "vectors": "vectors.json",
                 "group_key": "axis", "id_key": "vector_id",
                 "inputs_key": "inputs",
                 "mutants": {"a": [
                     {"label": "alias",
                      "anchor": 'return []',
                      "replacement": 'return _shared'},
                     dict(CONTROL, label="CONTROL [a]"),
                 ]}}
            p = tmp / "m.json"
            p.write_text(json.dumps(m))
            return ca.run(p)

    def test_mutable_alias_survives_not_false_killed(self):
        rep = self._run()
        v = _verdict(rep, "alias")
        self.assertEqual(v["verdict"], "survived")
        self.assertNotEqual(v.get("how"), "unexpected-exit")
        self.assertFalse(rep["adequate"])


class IsolationClaimScope(unittest.TestCase):
    """The public and internal claims must not overstate the isolation boundary.

    A same-user child can kill(getppid(), SIGKILL) and end the controller with
    no report, so neither surface may claim survival of arbitrary child
    behaviour. The measured classes are timeout, output-cap, abnormal
    termination and protocol failure; everything else is an explicit non-claim.
    """

    _root = Path(__file__).resolve().parent.parent
    _surfaces = {
        "readme": (_root / "README.md").read_text(encoding="utf-8"),
        "docstring": inspect.getsource(ca._module_outcomes),
    }

    # (phrase, should_be_present) -- absence guards the overclaim,
    # presence guards each explicit non-claim.
    _contract = [
        ("survives whatever", False),
        ("parent signalling", True),
        ("session escape", True),
        ("host resource exhaustion", True),
    ]

    def test_readme_describes_role_sensitive_failure_semantics(self):
        """The README must not say abnormal children 'fail closed instead of
        scoring' as a blanket claim. The actual semantics are role-sensitive:
        ordinary-mutant abnormal termination is a named kill, unusable
        protocol is unproved, baseline/control failure invalidates score.
        """
        readme = self._surfaces["readme"]
        # The old blanket phrasing must be gone.
        self.assertNotIn("fails closed instead of scoring", readme,
                         "README still uses the blanket 'fails closed instead of scoring' "
                         "which does not distinguish roles")
        # Role-sensitive wording must be present.
        self.assertIn("named kill", readme)
        self.assertIn("unproved", readme)
        self.assertIn("invalidates the score", readme)

    def test_isolation_claim_contract(self):
        for phrase, present in self._contract:
            for name, text in self._surfaces.items():
                with self.subTest(phrase=phrase, surface=name):
                    if present:
                        self.assertIn(phrase, text)
                    else:
                        self.assertNotIn(phrase, text)




# ---------------------------------------------------------------------------
# The silent class
# ---------------------------------------------------------------------------
#
# Adopted from the forcing gate in astrogilda/aee-conformance, which separates
# KILLED ("some vector goes PASS -> FAIL") from SILENT ("no vector changes
# status, but some vector's OBSERVATION changes ... This is the weak case").
# Without the distinction a corpus whose verdicts cannot see a rule scores the
# same whether its diagnostics noticed or not, and the two need different repairs.


def _silent_manifest(tmp: Path, extra=None):
    """A corpus whose outcome is `ok` and whose diagnostic is `reason`."""
    (tmp / "check.py").write_text(
        "import json\n"
        "ok = True\n"
        'reason = "A"\n'
        'print(json.dumps({"ok": ok, "reason": reason}))\n',
        encoding="utf-8")
    (tmp / "vec.json").write_text("{}\n", encoding="utf-8")
    (tmp / "vectors.json").write_text(json.dumps({
        "vectors": [{"vector_id": "v1", "path": "vec.json"}]}), encoding="utf-8")
    raw = {
        "schema": ca.SCHEMA, "runner": "process", "repo_root": ".",
        "implementation": "check.py", "implementation_sources": ["check.py"],
        "build": [],
        "entrypoint_command": [_batch_python(), "check.py", "{vector}"],
        "outcome_from": ["ok"], "vectors": "vectors.json",
        "id_key": "vector_id", "vector_path_key": "path", "default_group": "g",
        "mutants": {"g": [
            {"label": "reason-text", "anchor": 'reason = "A"',
             "replacement": 'reason = "B"'},
            {"label": "CONTROL", "control": True,
             "anchor": "ok = True", "replacement": "ok = False"}]}}
    raw.update(dict(extra or {}))
    p = tmp / "m.json"
    p.write_text(json.dumps(raw), encoding="utf-8")
    return p


class SilentClass(unittest.TestCase):
    def _run(self, extra):
        with tempfile.TemporaryDirectory() as d:
            return ca.run(_silent_manifest(Path(d), extra))

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_diagnostic_only_move_is_silent_not_killed(self):
        r = self._run({"diagnostic_from": ["reason"]})
        v = {m["label"]: m for m in r["mutants"]}
        self.assertEqual(v["reason-text"]["verdict"], "silent")
        self.assertEqual(v["reason-text"]["moved"], 0)
        self.assertEqual(v["reason-text"]["moved_diagnostic"], 1)
        self.assertEqual(r["killed"], 0)
        self.assertEqual(r["silent"], 1)
        self.assertTrue(r["diagnostic_channel_declared"])

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_silent_counts_against_the_score_and_never_for_it(self):
        r = self._run({"diagnostic_from": ["reason"]})
        # denominator includes it, numerator does not: 0 of 1.
        self.assertEqual(r["score_percent"], 0.0)
        self.assertFalse(r["adequate"])
        self.assertTrue(any("silent" in f for f in r["failures"]))

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_without_the_channel_the_same_mutant_reads_as_survived(self):
        # The class is unreachable when nothing declares a diagnostic channel,
        # so a zero there means it was not measured rather than that none exist.
        r = self._run({})
        v = {m["label"]: m for m in r["mutants"]}
        self.assertEqual(v["reason-text"]["verdict"], "survived")
        self.assertEqual(r["silent"], 0)
        self.assertFalse(r["diagnostic_channel_declared"])

    def test_a_member_on_both_channels_is_refused(self):
        # It could never produce `silent`: any move in it already moves the
        # outcome, so the manifest would read as covering a class it cannot reach.
        with self.assertRaises(ca.ManifestError) as e:
            self._run({"diagnostic_from": ["ok"]})
        self.assertIn("silent-only", str(e.exception))

    def test_diagnostic_channel_is_refused_beside_test_names(self):
        with tempfile.TemporaryDirectory() as d:
            p = _policy_manifest(Path(d), {"outcome_parse": "test-names",
                                           "diagnostic_from": ["reason"],
                                           "accepted_exit_codes": [0, 101]},
                                 runner="batch")
            with self.assertRaises(ca.ManifestError) as e:
                ca.load_manifest(p)
        self.assertIn("test names are the outcome", str(e.exception))

    def test_module_runner_refuses_the_channel_rather_than_ignoring_it(self):
        # Ignoring it would report `silent: 0` for a class that was never read,
        # which is the silent-coverage failure this tool exists to catch.
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "impl.py").write_text("def check(v):\n    return True\n", encoding="utf-8")
            (tmp / "vectors.json").write_text(json.dumps({"vectors": [{"vector_id": "v1"}]}),
                                              encoding="utf-8")
            p = tmp / "m.json"
            p.write_text(json.dumps({
                "schema": ca.SCHEMA, "runner": "module", "implementation": "impl.py",
                "entrypoint": "check", "vectors": "vectors.json", "id_key": "vector_id",
                "default_group": "g", "diagnostic_from": ["reason"],
                "mutants": {"g": [{"label": "x", "anchor": "True", "replacement": "False"}]},
            }), encoding="utf-8")
            with self.assertRaises(ca.ManifestError) as e:
                ca.load_manifest(p)
        self.assertIn("not implemented for runner=module", str(e.exception))


# ---------------------------------------------------------------------------
# Selector presence: one rule for every declared selector
# ---------------------------------------------------------------------------
#
# `outcome_from` has failed closed on a member nothing emits since the
# all_reproduced incident above. `diagnostic_from` reads members the same way,
# through the same parser, and a member nothing emits is the same defect there:
# it compares None to None on every mutant, so the channel can never produce a
# `silent` verdict while the report still says the channel was declared. One
# rule covers both selectors, or the newer one repeats the older one's bug.


class DeclaredSelectorMembersMustExist(unittest.TestCase):
    def _corpus(self, tmp: Path, outcome_from, diagnostic_from=None):
        (tmp / "check.py").write_text(
            "import json, sys\n"
            "doc = json.load(open(sys.argv[1]))\n"
            "fails = [c['id'] for c in doc['cases'] if c['n'] > 10]\n"
            "print(json.dumps({'ok': not fails, 'failures': fails}))\n")
        (tmp / "vectors.json").write_text(json.dumps({"cases": [
            {"id": "c1", "n": 1}, {"id": "c2", "n": 2}]}))
        m = {"schema": ca.SCHEMA, "runner": "batch", "repo_root": ".",
             "implementation_sources": ["check.py"],
             "entrypoint_command": [_batch_python(), "check.py", "vectors.json"],
             "outcome_from": outcome_from, "vectors": "vectors.json",
             "id_key": "vector_id", "default_group": "g",
             "mutants": {"g": [
                 {"label": "threshold", "anchor": "c['n'] > 10", "replacement": "c['n'] > 1"},
                 {"label": "CONTROL", "control": True,
                  "anchor": "'ok': not fails", "replacement": "'ok': 'MOVED'"}]}}
        if diagnostic_from is not None:
            m["diagnostic_from"] = diagnostic_from
        q = tmp / "m.json"
        q.write_text(json.dumps(m))
        return q

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_diagnostic_member_nothing_emits_fails_closed(self):
        # MISSING: every declared diagnostic member is absent from the output.
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._corpus(Path(d), ["ok"], ["no_such_member"]))
        msg = " ".join(rep["failures"])
        self.assertIn("diagnostic_from", msg)
        self.assertIn("no_such_member", msg)
        self.assertIn("never emits", msg)
        self.assertFalse(rep["adequate"])

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_a_partially_present_diagnostic_selector_still_fails_closed(self):
        # PARTIAL is the dangerous shape: one member works, so the channel looks
        # live, while the other silently contributes nothing to every comparison.
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._corpus(Path(d), ["ok"], ["failures", "no_such_member"]))
        msg = " ".join(rep["failures"])
        self.assertIn("no_such_member", msg)
        self.assertIn("never emits", msg)
        self.assertNotIn("'failures'", msg)
        self.assertFalse(rep["adequate"])

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_a_diagnostic_selector_the_implementation_emits_is_not_flagged(self):
        # PRESENT: the guard must not fire on a correct manifest, or it is noise.
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._corpus(Path(d), ["ok"], ["failures"]))
        self.assertNotIn("never emits", " ".join(rep["failures"]))

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_the_outcome_selector_keeps_its_own_presence_rule(self):
        # The shared rule must not lose the behaviour it generalises.
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._corpus(Path(d), ["ok", "all_reproduced"]))
        msg = " ".join(rep["failures"])
        self.assertIn("outcome_from", msg)
        self.assertIn("all_reproduced", msg)
        self.assertIn("never emits", msg)


# ---------------------------------------------------------------------------
# report.v0 parity for the fields this tool's own docs promise
# ---------------------------------------------------------------------------


class ModuleReportCarriesTheSilentFields(unittest.TestCase):
    """README says a report distinguishes `silent: 0` from not measured.

    A module report that omits both fields cannot: a consumer reading
    `.get("silent", 0)` gets the false-measured answer the field exists to
    prevent. Runner identity is a separate parity gap and stays with issue #6.
    """

    def _module_manifest(self, tmp: Path):
        (tmp / "impl.py").write_text("def check(v):\n    return True\n", encoding="utf-8")
        (tmp / "vectors.json").write_text(
            json.dumps({"vectors": [{"vector_id": "v1"}]}), encoding="utf-8")
        p = tmp / "m.json"
        p.write_text(json.dumps({
            "schema": ca.SCHEMA, "runner": "module", "implementation": "impl.py",
            "entrypoint": "check", "vectors": "vectors.json", "id_key": "vector_id",
            "default_group": "g",
            "mutants": {"g": [
                {"label": "r1", "anchor": "return True", "replacement": "return False"},
                {"label": "CONTROL", "control": True,
                 "anchor": "def check", "replacement": "def  check"}]},
        }), encoding="utf-8")
        return p

    def test_module_report_carries_silent_and_the_channel_flag(self):
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._module_manifest(Path(d)))
        self.assertIn("silent", rep)
        self.assertEqual(rep["silent"], 0)
        self.assertIn("diagnostic_channel_declared", rep)
        self.assertIs(rep["diagnostic_channel_declared"], False)

    def test_the_module_report_now_names_its_runner(self):
        # Replaces the assertion that pinned the omission. #6 owns runner parity
        # and it has landed: the full required-key table lives in
        # ReportShapeParityAcrossRunners, this keeps the local claim honest.
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._module_manifest(Path(d)))
        self.assertEqual(rep["runner"], "module")


# ---------------------------------------------------------------------------
# hole_ratio shares the scored denominator
# ---------------------------------------------------------------------------


class HoleRatioUsesTheScoredDenominator(unittest.TestCase):
    """`silent` is scored, so the ratio reported beside the score must count it.

    Two ratios over two denominators in one report is a reader trap: the score
    says one thing about how many rules were in play and `hole_ratio` divides by
    another.
    """

    def _corpus(self, tmp: Path):
        (tmp / "check.py").write_text(
            "import json\n"
            "ok = True\n"
            "guard = True\n"
            "hole = True\n"
            'reason = "A"\n'
            "if not guard:\n"
            "    ok = False\n"
            'print(json.dumps({"ok": ok and hole, "reason": reason}))\n',
            encoding="utf-8")
        (tmp / "vec.json").write_text("{}\n", encoding="utf-8")
        (tmp / "digest.json").write_text('{"digest":"sha256:deadbeef"}\n', encoding="utf-8")
        (tmp / "vectors.json").write_text(json.dumps({
            "vectors": [{"vector_id": "v1", "path": "vec.json"}]}), encoding="utf-8")
        p = tmp / "m.json"
        p.write_text(json.dumps({
            "schema": ca.SCHEMA, "runner": "process", "repo_root": ".",
            "implementation": "check.py", "implementation_sources": ["check.py"],
            "build": [],
            "entrypoint_command": [_batch_python(), "check.py", "{vector}"],
            "outcome_from": ["ok"], "diagnostic_from": ["reason"],
            "vectors": "vectors.json", "id_key": "vector_id",
            "vector_path_key": "path", "default_group": "g",
            "corpus_digest_file": "digest.json", "corpus_digest_key": "digest",
            "known_holes": {"sha256:deadbeef": [
                {"label": "hole-rule", "reason": "acknowledged", "recorded": "2026-08-20"}]},
            "mutants": {"g": [
                {"label": "killed-rule", "anchor": "hole = True",
                 "replacement": "hole = False"},
                {"label": "silent-rule", "anchor": 'reason = "A"',
                 "replacement": 'reason = "B"'},
                {"label": "hole-rule", "anchor": "ok = True",
                 "replacement": "ok = True  # acknowledged"},
                {"label": "CONTROL", "control": True,
                 "anchor": "guard = True", "replacement": "guard = False"}]},
        }), encoding="utf-8")
        return p

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_hole_ratio_divides_by_killed_survived_and_silent(self):
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._corpus(Path(d)))
        self.assertEqual(rep["killed"], 1)
        self.assertEqual(rep["survived"], 0)
        self.assertEqual(rep["silent"], 1)
        self.assertEqual(rep["known_holes"], 1)
        # 1 hole over the scored denominator killed+survived+silent = 2.
        self.assertEqual(rep["hole_ratio"], 0.5)


# ---------------------------------------------------------------------------
# A diagnostic-only move never overrides a declared exclusion
# ---------------------------------------------------------------------------
#
# `silent` answers "the corpus claims this rule and its pinned outcomes cannot
# see it". Neither an out-of-scope mutant nor an acknowledged hole is making that
# claim, so a diagnostic move must not reclassify either of them. Getting this
# wrong scored rules the author excluded, and told an author to delete a valid
# acknowledgement for a rule that is still unforced.
#
# Rule 3 is that outcome movement still kills and still retires an
# acknowledgement. `KnownHoles` pins two neighbouring facts on the MODULE runner:
# `test_an_acknowledgement_for_a_rule_now_exercised_is_flagged` pins kill-then-
# stale there, and `test_an_acknowledgement_lingers_when_its_rule_becomes_out_of_
# scope` pins staleness on a SCOPE transition, which is not outcome movement at
# all. Neither reaches the process classifier, and a mutation that handled a
# valid acknowledgement before `raised or moved` in `_run_process` left the whole
# suite green. So rule 3 is pinned in THIS caller only by
# `test_an_acknowledged_rule_the_outcome_moves_is_killed_and_goes_stale` below.


class DiagnosticMoveDoesNotOverrideAnExclusion(unittest.TestCase):
    def _corpus(self, tmp: Path, second: dict, known_holes=None):
        (tmp / "check.py").write_text(
            "import json\n"
            "ok = True\n"
            "guard = True\n"
            "killme = True\n"
            "acked = True\n"
            'tag = "A"\n'
            "if not guard:\n"
            "    ok = False\n"
            'print(json.dumps({"ok": ok and killme and acked, "reason": tag}))\n',
            encoding="utf-8")
        (tmp / "vec.json").write_text("{}\n", encoding="utf-8")
        (tmp / "digest.json").write_text('{"digest":"sha256:deadbeef"}\n', encoding="utf-8")
        (tmp / "vectors.json").write_text(json.dumps({
            "vectors": [{"vector_id": "v1", "path": "vec.json"}]}), encoding="utf-8")
        raw = {
            "schema": ca.SCHEMA, "runner": "process", "repo_root": ".",
            "implementation": "check.py", "implementation_sources": ["check.py"],
            "build": [],
            "entrypoint_command": [_batch_python(), "check.py", "{vector}"],
            "outcome_from": ["ok"], "diagnostic_from": ["reason"],
            "vectors": "vectors.json", "id_key": "vector_id",
            "vector_path_key": "path", "default_group": "g",
            "corpus_digest_file": "digest.json", "corpus_digest_key": "digest",
            "mutants": {"g": [
                {"label": "killed-rule", "anchor": "killme = True",
                 "replacement": "killme = False"},
                second,
                {"label": "CONTROL", "control": True,
                 "anchor": "guard = True", "replacement": "guard = False"}]},
        }
        if known_holes is not None:
            raw["known_holes"] = known_holes
        p = tmp / "m.json"
        p.write_text(json.dumps(raw), encoding="utf-8")
        return p

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_out_of_scope_survives_a_diagnostic_only_move(self):
        second = {"label": "oos-rule", "anchor": 'tag = "A"', "replacement": 'tag = "B"',
                  "scope": "out_of_scope", "reason": "the corpus never claimed this rule"}
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._corpus(Path(d), second))
        row = {r["label"]: r for r in rep["mutants"]}["oos-rule"]
        self.assertEqual(row["verdict"], "unexercised")
        # The docs promise the row carries the diagnostic fact and says it.
        self.assertEqual(row["moved_diagnostic"], 1)
        self.assertIn("diagnostic channel moved on 1", row["how"])
        self.assertIn("pinned outcomes did not", row["how"])
        self.assertIn("not scored", row["how"])
        self.assertEqual(rep["silent"], 0)
        self.assertEqual(rep["unexercised_out_of_scope"], 1)
        self.assertEqual(rep["score_percent"], 100.0)
        self.assertTrue(rep["adequate"], rep["failures"])

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_an_acknowledged_rule_the_outcome_moves_is_killed_and_goes_stale(self):
        # Rule 3 in the process classifier. The KnownHoles tests that look like
        # they cover this run the module runner, so a mutation handling a valid
        # acknowledgement before `raised or moved` here kept the suite green.
        second = {"label": "acked-rule", "anchor": "acked = True",
                  "replacement": "acked = False"}
        holes = {"sha256:deadbeef": [
            {"label": "acked-rule", "reason": "acknowledged", "recorded": "2026-08-20"}]}
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._corpus(Path(d), second, known_holes=holes))
        row = {r["label"]: r for r in rep["mutants"]}["acked-rule"]
        self.assertEqual(row["verdict"], "killed")
        self.assertEqual(rep["known_holes"], 0)
        self.assertFalse(rep["adequate"])
        joined = " ".join(rep["failures"])
        self.assertIn("no longer holes", joined)
        self.assertIn("now killed", joined)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_a_current_digest_known_hole_survives_a_diagnostic_only_move(self):
        second = {"label": "hole-rule", "anchor": 'tag = "A"', "replacement": 'tag = "B"'}
        holes = {"sha256:deadbeef": [
            {"label": "hole-rule", "reason": "acknowledged", "recorded": "2026-08-20"}]}
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._corpus(Path(d), second, known_holes=holes))
        row = {r["label"]: r for r in rep["mutants"]}["hole-rule"]
        self.assertEqual(row["verdict"], "known-hole")
        # The row stays honest about what did see it.
        self.assertEqual(row["moved_diagnostic"], 1)
        self.assertIn("diagnostic channel moved on 1", row["how"])
        self.assertIn("pinned outcomes did not", row["how"])
        self.assertIn("not scored", row["how"])
        self.assertEqual(rep["silent"], 0)
        self.assertEqual(rep["known_holes"], 1)
        self.assertEqual(rep["score_percent"], 100.0)
        joined = " ".join(rep["failures"])
        self.assertNotIn("no longer holes", joined)
        self.assertNotIn("were silent", joined)


# ---------------------------------------------------------------------------
# One report shape across every runner
# ---------------------------------------------------------------------------
#
# Two independent `report.v0` dictionaries drifted: the module one omitted
# `runner`, so a consumer could not tell from a report which runner produced it
# and Assay re-read the manifest to recover the field. The required key set is
# written here, literally, rather than derived from either producer -- a table
# computed from the code it checks agrees with that code by construction.


REQUIRED_REPORT_KEYS = frozenset({
    "schema", "manifest", "manifest_sha256", "runner", "control_status",
    "killed", "survived", "silent", "diagnostic_channel_declared",
    "known_holes", "corpus_digest", "acknowledged_digests",
    "hole_ratio", "equivalent", "unexercised_out_of_scope", "unproved",
    "declared_total", "out_of_scope_ratio",
    "score_percent", "score_means", "mutants", "failures", "adequate",
    "tool_version", "tool_commit", "tool_source_state", "tool_content_sha256",
})

PROCESS_ONLY_REPORT_KEYS = frozenset({"originals_unverified_against_head"})


class ReportShapeParityAcrossRunners(unittest.TestCase):
    """Every runner returns the same required keys, and names itself."""

    def _module(self, tmp: Path):
        (tmp / "impl.py").write_text("def check(v):\n    return True\n", encoding="utf-8")
        (tmp / "vectors.json").write_text(
            json.dumps({"vectors": [{"vector_id": "v1"}]}), encoding="utf-8")
        p = tmp / "m.json"
        p.write_text(json.dumps({
            "schema": ca.SCHEMA, "runner": "module", "implementation": "impl.py",
            "entrypoint": "check", "vectors": "vectors.json", "id_key": "vector_id",
            "default_group": "g",
            "mutants": {"g": [
                {"label": "r1", "anchor": "return True", "replacement": "return False"},
                {"label": "CONTROL", "control": True,
                 "anchor": "def check", "replacement": "def  check"}]},
        }), encoding="utf-8")
        return p

    def _process(self, tmp: Path, runner: str):
        (tmp / "check.py").write_text(
            "import json, sys\n"
            "doc = json.load(open(sys.argv[1]))\n"
            "fails = [c['id'] for c in doc['cases'] if c['n'] > 10]\n"
            "print(json.dumps({'ok': not fails, 'failures': fails}))\n", encoding="utf-8")
        (tmp / "vectors.json").write_text(json.dumps(
            {"cases": [{"id": "c1", "n": 1}]} if runner == "batch"
            else {"vectors": [{"vector_id": "v1", "path": "vec.json"}]}), encoding="utf-8")
        raw = {"schema": ca.SCHEMA, "runner": runner, "repo_root": ".",
               "implementation_sources": ["check.py"],
               "outcome_from": ["ok", "failures"], "vectors": "vectors.json",
               "id_key": "vector_id", "default_group": "g",
               "mutants": {"g": [
                   {"label": "threshold", "anchor": "c['n'] > 10",
                    "replacement": "c['n'] > 1"},
                   {"label": "CONTROL", "control": True,
                    "anchor": "'ok': not fails", "replacement": "'ok': 'MOVED'"}]}}
        if runner == "batch":
            raw["entrypoint_command"] = [_batch_python(), "check.py", "vectors.json"]
        else:
            (tmp / "vec.json").write_text(json.dumps({"cases": [{"id": "c1", "n": 1}]}),
                                          encoding="utf-8")
            raw["implementation"] = "check.py"
            raw["build"] = []
            raw["vector_path_key"] = "path"
            raw["entrypoint_command"] = [_batch_python(), "check.py", "{vector}"]
        p = tmp / "m.json"
        p.write_text(json.dumps(raw), encoding="utf-8")
        return p

    def test_module_report_carries_every_required_key(self):
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._module(Path(d)))
        self.assertEqual(REQUIRED_REPORT_KEYS - set(rep), frozenset())
        self.assertEqual(rep["runner"], "module")
        # The process-only field must not become a fake universal one.
        self.assertEqual(PROCESS_ONLY_REPORT_KEYS & set(rep), frozenset())

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_process_report_carries_every_required_key(self):
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._process(Path(d), "process"))
        self.assertEqual(REQUIRED_REPORT_KEYS - set(rep), frozenset())
        self.assertEqual(rep["runner"], "process")
        self.assertEqual(PROCESS_ONLY_REPORT_KEYS - set(rep), frozenset())

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_batch_report_carries_every_required_key(self):
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._process(Path(d), "batch"))
        self.assertEqual(REQUIRED_REPORT_KEYS - set(rep), frozenset())
        self.assertEqual(rep["runner"], "batch")
        self.assertEqual(PROCESS_ONLY_REPORT_KEYS - set(rep), frozenset())


class ReportProjectorIsPlatformIndependent(unittest.TestCase):
    """The contract must still be exercised where the runners cannot run.

    `process` and `batch` refuse without `fcntl`, so on Windows the three tests
    above reduce to one. Calling the projector directly needs no child, no lock
    and no filesystem, so every runner's shape is checked on every platform.
    """

    def _project(self, runner: str, **over):
        m = {"runner": runner, "known_holes": {}, "_corpus_digest": None,
             "_manifest_sha256": "sha256:" + "0" * 64}
        m.update(over.pop("manifest", {}))
        kw = dict(killed=1, survived=0, silent=0, equivalent=0, out_of_scope=0,
                  unproved=0, known_holes=0, score=100.0, results=[], failures=[],
                  control_status="killed")
        kw.update(over)
        return ca._report_v0(Path("m.json"), m, **kw)

    def test_every_runner_projects_the_required_keys(self):
        for runner in ("module", "process", "batch"):
            with self.subTest(runner=runner):
                rep = self._project(runner)
                self.assertEqual(REQUIRED_REPORT_KEYS - set(rep), frozenset())
                self.assertEqual(rep["runner"], runner)

    def test_the_runner_comes_from_the_manifest_not_a_literal(self):
        self.assertEqual(self._project("batch")["runner"], "batch")
        self.assertEqual(self._project("module")["runner"], "module")

    def test_silent_and_the_diagnostic_flag_are_projected(self):
        rep = self._project("module")
        self.assertEqual(rep["silent"], 0)
        self.assertIs(rep["diagnostic_channel_declared"], False)
        declared = self._project("process", silent=2,
                                 manifest={"diagnostic_from": ["reason"]})
        self.assertEqual(declared["silent"], 2)
        self.assertIs(declared["diagnostic_channel_declared"], True)

    def test_tool_identity_is_applied_exactly_once_by_the_projector(self):
        """Presence proves the fields arrived, not that one call produced them.

        `_with_tool_identity` is idempotent over its own output, so wrapping
        twice leaves every field present and every value correct. Counting the
        producer calls is the only way to tell one application from two, and two
        means the projector resolved identity twice per report: `tool_identity`
        stats and hashes every declared runtime source, so a second call is real
        work and a second chance to disagree with the first.
        """
        calls = []
        fake = {"tool_version": "9.9.9", "tool_commit": None,
                "tool_source_state": "unresolved", "tool_content_sha256": None}

        def counted():
            calls.append(1)
            return dict(fake)

        with mock.patch.object(ca, "tool_identity", counted):
            rep = self._project("module")

        self.assertEqual(len(calls), 1, "identity was resolved %d times" % len(calls))
        for key, value in fake.items():
            self.assertIn(key, rep)
            self.assertEqual(rep[key], value)

    def test_the_process_only_field_is_included_only_when_supplied(self):
        self.assertNotIn("originals_unverified_against_head", self._project("module"))
        rep = self._project("process", originals_unverified_against_head=True)
        self.assertIs(rep["originals_unverified_against_head"], True)

    def test_the_derived_numbers_share_one_denominator(self):
        rep = self._project("process", killed=1, silent=1, known_holes=1, out_of_scope=1)
        # denom = killed + survived + silent = 2
        self.assertEqual(rep["hole_ratio"], 0.5)
        self.assertEqual(rep["out_of_scope_ratio"], 0.5)
        self.assertEqual(rep["declared_total"], 4)

    def test_a_zero_denominator_reports_no_ratio_rather_than_a_division(self):
        rep = self._project("module", killed=0, silent=0, known_holes=1)
        self.assertIsNone(rep["hole_ratio"])
        self.assertIsNone(rep["out_of_scope_ratio"])

    def test_adequate_is_exactly_no_failures(self):
        self.assertIs(self._project("module")["adequate"], True)
        self.assertIs(self._project("module", failures=["x"])["adequate"], False)


class ReportV0AddressingContract(unittest.TestCase):
    """The producer owns the exact report and manifest byte identities."""

    def test_report_encoder_has_one_pinned_utf8_wire_form(self):
        report = {"z": "caf\u00e9", "schema": ca.REPORT_SCHEMA, "a": 1}
        expected = (
            b'{\n'
            b'  "a": 1,\n'
            b'  "schema": "corpus-adequacy.report.v0",\n'
            b'  "z": "caf\xc3\xa9"\n'
            b'}\n'
        )
        encoded = ca.encode_report_v0(report)
        self.assertEqual(encoded, expected)
        self.assertEqual(
            hashlib.sha256(encoded).hexdigest(),
            "8ecdc8cdab9f1065a57768e556261ac9730cf3d5253e51a5b7c6e58b458cb0fc",
        )

    def test_json_cli_writes_the_canonical_encoder_bytes(self):
        report = {"schema": ca.REPORT_SCHEMA, "adequate": True}
        stdout = io.StringIO()
        with (mock.patch.object(sys, "argv", ["corpus_adequacy.py", "m.json", "--json"]),
              mock.patch.object(sys, "stdout", stdout),
              mock.patch.object(ca, "run", return_value=report),
              mock.patch.object(ca, "encode_report_v0", return_value=b"wire-report\n")
              as encoder):
            rc = ca.main()
        self.assertEqual(rc, 0)
        self.assertEqual(stdout.getvalue(), "wire-report\n")
        encoder.assert_called_once_with(report)

    def test_json_cli_prefers_the_binary_stream_over_locale_encoding(self):
        class BinaryStdout:
            def __init__(self):
                self.buffer = io.BytesIO()

            def write(self, _text):
                raise AssertionError("the JSON report was routed through text encoding")

        report = {"schema": ca.REPORT_SCHEMA, "adequate": True}
        stdout = BinaryStdout()
        with (mock.patch.object(sys, "argv", ["corpus_adequacy.py", "m.json", "--json"]),
              mock.patch.object(sys, "stdout", stdout),
              mock.patch.object(ca, "run", return_value=report)):
            rc = ca.main()
        self.assertEqual(rc, 0)
        self.assertEqual(stdout.buffer.getvalue(), ca.encode_report_v0(report))

    def test_error_envelopes_cannot_enter_the_report_encoder(self):
        with self.assertRaises(ValueError):
            ca.encode_report_v0({"schema": ca.ERROR_SCHEMA, "error": "bad manifest"})

    def test_manifest_digest_addresses_the_exact_bytes_that_were_parsed(self):
        with tempfile.TemporaryDirectory() as d:
            path = _manifest(Path(d), {"a": [KILLABLE]})
            first_bytes = path.read_bytes()
            first = ca.run(path)
            path.write_bytes(first_bytes + b"\n")
            second = ca.run(path)

        self.assertEqual(
            first["manifest_sha256"],
            "sha256:" + hashlib.sha256(first_bytes).hexdigest(),
        )
        self.assertNotEqual(first["manifest_sha256"], second["manifest_sha256"])

    def test_json_cli_rejects_a_lone_surrogate_as_error_v0(self):
        with tempfile.TemporaryDirectory() as d:
            path = _manifest(Path(d), {
                "a": [dict(KILLABLE, label="\ud800")],
            })
            proc = subprocess.run(
                [sys.executable, str(ca.__file__), str(path), "--json"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )

        self.assertEqual(proc.returncode, 2)
        self.assertTrue(proc.stdout, "encoding refusal must emit an error envelope")
        envelope = json.loads(proc.stdout)
        self.assertEqual(envelope["schema"], ca.ERROR_SCHEMA)
        self.assertIn("UTF-8", envelope["error"])
        self.assertNotIn(b"Traceback", proc.stderr)


class ProducerOwnedControlStatus(unittest.TestCase):
    """One producer rule emits both the direct status and its row verdict."""

    def test_control_rule_keeps_direct_status_and_row_verdict_in_parity(self):
        cases = (
            (True, None, "killed", "control-killed"),
            (False, None, "survived", "control-SURVIVED"),
            (False, "unexpected-exit", "error", "control-error"),
        )
        for detected, error, status, verdict in cases:
            with self.subTest(status=status):
                row, direct = ca._control_result(
                    "g", "CONTROL", "declared", detected=detected,
                    moved=1 if detected else 0, error=error,
                )
                self.assertEqual(direct, status)
                self.assertEqual(row["verdict"], verdict)

    def test_report_status_is_not_reconstructed_from_mutant_rows(self):
        report = ReportProjectorIsPlatformIndependent()._project(
            "module", control_status="killed",
            results=[{"verdict": "control-SURVIVED"}],
        )
        self.assertEqual(report["control_status"], "killed")

    def test_missing_control_is_named_without_scanning_rows(self):
        with tempfile.TemporaryDirectory() as d:
            report = ca.run(_manifest(
                Path(d), {"a": [KILLABLE]}, control=False,
            ))
        self.assertEqual(report["control_status"], "absent-or-invalid")
        self.assertFalse(report["adequate"])

    def test_a_stale_declared_control_makes_a_killed_control_incomplete(self):
        killed = dict(CONTROL, label="CONTROL killed")
        stale = dict(CONTROL, label="CONTROL stale", anchor="not in implementation")
        with tempfile.TemporaryDirectory() as d:
            report = ca.run(_manifest(
                Path(d), {"a": [KILLABLE, killed, stale]}, control=False,
            ))
        self.assertEqual(report["control_status"], "absent-or-invalid")
        self.assertFalse(report["adequate"])
        self.assertIn("control-killed", [row["verdict"] for row in report["mutants"]])

    def test_multiple_control_precedence_is_fail_closed(self):
        cases = (
            (["killed"], 2, "absent-or-invalid"),
            (["survived"], 2, "absent-or-invalid"),
            (["killed", "survived"], 2, "survived"),
            (["killed", "error"], 2, "error"),
            (["error"], 2, "error"),
            (["killed", "killed"], 2, "killed"),
            ([], 0, "absent-or-invalid"),
        )
        for observed, declared, expected in cases:
            with self.subTest(observed=observed, declared=declared):
                self.assertEqual(ca._control_status(observed, declared), expected)

    def test_module_report_uses_direct_status_not_the_conflicting_row(self):
        original = ca._control_result

        def conflicting(*args, **kwargs):
            row, status = original(*args, **kwargs)
            row["verdict"] = "control-SURVIVED"
            return row, status

        with tempfile.TemporaryDirectory() as d, mock.patch.object(
                ca, "_control_result", side_effect=conflicting):
            report = ca.run(_manifest(Path(d), {"a": [KILLABLE]}))

        self.assertIn("control-SURVIVED", [row["verdict"] for row in report["mutants"]])
        self.assertEqual(report["control_status"], "killed")

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_batch_report_uses_direct_status_not_the_conflicting_row(self):
        original = ca._control_result

        def conflicting(*args, **kwargs):
            row, status = original(*args, **kwargs)
            row["verdict"] = "control-SURVIVED"
            return row, status

        with tempfile.TemporaryDirectory() as d, mock.patch.object(
                ca, "_control_result", side_effect=conflicting):
            report = ca.run(BatchRunner()._corpus(Path(d)))

        self.assertIn("control-SURVIVED", [row["verdict"] for row in report["mutants"]])
        self.assertEqual(report["control_status"], "killed")


class SurvivorFindings(unittest.TestCase):
    """Issue #27: project survived and silent rows as bound rule findings."""

    def test_one_survived_and_one_silent_bind_two_findings(self):
        report = {
            "schema": ca.REPORT_SCHEMA,
            "manifest_sha256": "sha256:" + "0" * 64,
            "mutants": [
                {
                    "group": "axis-a",
                    "label": "rejects bad input",
                    "verdict": "survived",
                    "scope": "declared",
                    "moved": 0,
                    "how": "no vector distinguishes it",
                },
                {
                    "group": "axis-b",
                    "label": "diagnostic-only rule",
                    "verdict": "silent",
                    "scope": "declared",
                    "moved": 0,
                    "moved_diagnostic": 2,
                    "how": "no vector's declared outcome distinguishes it",
                },
            ],
            "failures": [
                "1 mutant(s) survived; the required score is 100% of non-equivalent mutants",
                "1 mutant(s) were silent: no declared outcome moved",
            ],
            "survived": 1,
            "silent": 1,
            "killed": 0,
        }
        projected = ca.survivor_findings(report)
        self.assertEqual(projected["schema"], "corpus-adequacy.survivors.v0")
        findings = projected["findings"]
        self.assertEqual(len(findings), 2)
        by_rule = {finding["rule"]: finding for finding in findings}
        self.assertEqual(set(by_rule), {"rejects bad input", "diagnostic-only rule"})

        survived = by_rule["rejects bad input"]
        self.assertEqual(survived["group"], "axis-a")
        self.assertEqual(survived["verdict"], "survived")
        self.assertEqual(survived["moved"], 0)
        self.assertEqual(survived["moved_diagnostic"], 0)
        self.assertEqual(
            survived["obligation"],
            "A future vector must distinguish this rule on a declared outcome. "
            "This projection does not name such a vector.",
        )

        silent = by_rule["diagnostic-only rule"]
        self.assertEqual(silent["group"], "axis-b")
        self.assertEqual(silent["verdict"], "silent")
        self.assertEqual(silent["moved"], 0)
        self.assertEqual(silent["moved_diagnostic"], 2)
        self.assertEqual(
            silent["obligation"],
            "A future vector must distinguish this rule on a declared outcome, "
            "not only the diagnostic channel. "
            "This projection does not name such a vector.",
        )
        self.assertNotEqual(survived["obligation"], silent["obligation"])

    def _row(self, verdict, label, group="g", **extra):
        row = {"group": group, "label": label, "verdict": verdict, "moved": 0}
        row.update(extra)
        return row

    def _report(self, mutants, **extra):
        report = {
            "schema": ca.REPORT_SCHEMA,
            "manifest_sha256": extra.pop("manifest_sha256", "sha256:" + "0" * 64),
            "mutants": mutants,
            "failures": extra.pop("failures", []),
            "survived": extra.pop(
                "survived", sum(1 for row in mutants if row.get("verdict") == "survived")),
            "silent": extra.pop(
                "silent", sum(1 for row in mutants if row.get("verdict") == "silent")),
            "killed": extra.pop("killed", 0),
        }
        report.update(extra)
        return report

    def test_killed_and_excluded_verdicts_are_not_findings(self):
        report = self._report([
            self._row("survived", "keep-survived"),
            self._row("silent", "keep-silent", moved_diagnostic=1),
            self._row("killed", "drop-killed", moved=3),
            self._row("equivalent", "drop-equivalent"),
            self._row("unexercised", "drop-oos"),
            self._row("unproved", "drop-unproved"),
            self._row("known-hole", "drop-hole"),
            self._row("control-killed", "drop-control"),
        ])
        rules = [finding["rule"] for finding in ca.survivor_findings(report)["findings"]]
        self.assertEqual(rules, ["keep-silent", "keep-survived"])

    def test_survived_and_silent_obligations_are_distinct(self):
        report = self._report([
            self._row("survived", "r-survived"),
            self._row("silent", "r-silent", moved_diagnostic=1),
        ])
        by_rule = {f["rule"]: f for f in ca.survivor_findings(report)["findings"]}
        self.assertNotEqual(by_rule["r-survived"]["obligation"],
                            by_rule["r-silent"]["obligation"])
        self.assertNotIn("diagnostic", by_rule["r-survived"]["obligation"])
        self.assertIn("diagnostic", by_rule["r-silent"]["obligation"])

    def test_rule_is_the_mutant_label(self):
        report = self._report([self._row("survived", "the-label", group="the-group")])
        finding = ca.survivor_findings(report)["findings"][0]
        self.assertEqual(finding["rule"], "the-label")
        self.assertNotEqual(finding["rule"], "the-group")
        self.assertNotEqual(finding["rule"], 0)

    def test_findings_are_sorted_by_group_then_rule(self):
        report = self._report([
            self._row("survived", "z-rule", group="b"),
            self._row("silent", "a-rule", group="b", moved_diagnostic=1),
            self._row("survived", "m-rule", group="a"),
        ])
        pairs = [(f["group"], f["rule"]) for f in ca.survivor_findings(report)["findings"]]
        self.assertEqual(pairs, [("a", "m-rule"), ("b", "a-rule"), ("b", "z-rule")])

    def test_projection_is_not_part_of_report_v0(self):
        report = self._report([self._row("survived", "only")])
        before = ca.encode_report_v0(report)
        projected = ca.survivor_findings(report)
        self.assertNotIn("findings", report)
        self.assertNotEqual(projected["schema"], ca.REPORT_SCHEMA)
        self.assertEqual(ca.encode_report_v0(report), before)
        with self.assertRaises(ValueError):
            ca.encode_survivors_v0(report)

    def test_counts_are_derived_from_findings(self):
        report = self._report(
            [self._row("survived", "one"), self._row("killed", "ignore", moved=1)],
            survived=99, silent=7, killed=1,
        )
        projected = ca.survivor_findings(report)
        self.assertEqual(projected["survived"], 1)
        self.assertEqual(projected["silent"], 0)
        self.assertEqual(projected["finding_count"], 1)

    def test_producer_failures_are_not_findings(self):
        failure = "1 mutant(s) survived; the required score is 100% of non-equivalent mutants"
        report = self._report(
            [self._row("survived", "only")],
            failures=[failure],
        )
        projected = ca.survivor_findings(report)
        self.assertEqual([f["rule"] for f in projected["findings"]], ["only"])
        self.assertNotIn(failure, projected["findings"])
        self.assertTrue(all(isinstance(f, dict) for f in projected["findings"]))
        self.assertTrue(all("obligation" in f for f in projected["findings"]))

    def test_report_v0_helpers_are_byte_identical_to_base(self):
        src = Path(ca.__file__).read_text(encoding="utf-8")
        tree = ast.parse(src)
        hashes = {}
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in (
                    "encode_report_v0", "_report_v0"):
                hashes[node.name] = hashlib.sha256(
                    ast.get_source_segment(src, node).encode()).hexdigest()
        self.assertEqual(hashes, {
            "encode_report_v0":
                "36f8d4604ee5e3050975196c857ae95e225d19d49ab12e9a3a77efa61289c2d4",
            "_report_v0":
                "9e0f0fe2df144ed74e11f36da1ef3b3d53d7a85df09819bbb543a3e96618963f",
        })

    def test_survivors_encoder_has_one_pinned_utf8_wire_form(self):
        doc = {"z": "caf\u00e9", "schema": ca.SURVIVORS_SCHEMA, "a": 1}
        expected = (
            b'{\n'
            b'  "a": 1,\n'
            b'  "schema": "corpus-adequacy.survivors.v0",\n'
            b'  "z": "caf\xc3\xa9"\n'
            b'}\n'
        )
        encoded = ca.encode_survivors_v0(doc)
        self.assertEqual(encoded, expected)
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertEqual(encoded.decode("utf-8"), encoded.decode("utf-8"))

    def test_survivors_encoder_does_not_call_report_encoder(self):
        with mock.patch.object(
                ca, "encode_report_v0",
                side_effect=AssertionError("encode_survivors_v0 called encode_report_v0")):
            encoded = ca.encode_survivors_v0({"schema": ca.SURVIVORS_SCHEMA, "a": 1})
        self.assertTrue(encoded.endswith(b"\n"))

    def test_bounded_loader_refuses_oversized_before_json_loads(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "too-big.json"
            path.write_bytes(b'{"k":"' + (b"x" * 80) + b'"}')
            with mock.patch.object(ca, "OUTPUT_CAP_BYTES", 32), \
                    mock.patch.object(
                        json, "loads",
                        side_effect=AssertionError("json.loads ran after the cap")):
                with self.assertRaises(ca.ManifestError) as cm:
                    ca.read_bounded_regular_file(path)
        self.assertIn("cap", str(cm.exception).lower())

    def test_projection_cap_is_the_existing_output_cap(self):
        self.assertFalse(hasattr(ca, "PROJECTION_INPUT_CAP_BYTES"))
        self.assertIs(ca.OUTPUT_CAP_BYTES, __import__("bounded_run").OUTPUT_CAP_BYTES)
        src = inspect.getsource(ca.read_bounded_regular_file)
        self.assertIn("OUTPUT_CAP_BYTES", src)
        self.assertNotIn("PROJECTION_INPUT_CAP_BYTES", src)
        self.assertNotIn("1024 * 1024", src)
        module_src = Path(ca.__file__).read_text(encoding="utf-8")
        self.assertNotIn("PROJECTION_INPUT_CAP_BYTES", module_src)
        self.assertNotIn("1024 * 1024", module_src)

    @unittest.skipIf(not hasattr(os, "O_NOFOLLOW"), "O_NOFOLLOW is required")
    def test_bounded_loader_refuses_a_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "real.json"
            target.write_text('{"schema":"%s","mutants":[]}' % ca.REPORT_SCHEMA)
            link = Path(d) / "link.json"
            link.symlink_to(target)
            with mock.patch.object(
                    json, "loads",
                    side_effect=AssertionError("json.loads followed a symlink")):
                with self.assertRaises(ca.ManifestError) as cm:
                    ca.read_bounded_regular_file(link)
        self.assertRegex(str(cm.exception).lower(), r"regular|symlink|follow")

    @unittest.skipIf(not hasattr(os, "mkfifo"), "os.mkfifo is unavailable")
    def test_bounded_loader_refuses_a_fifo_without_blocking(self):
        """A FIFO is openable and parks open() until a writer arrives, so the
        S_ISREG check after os.open never runs.

        The alarm raises a BaseException on purpose. TimeoutError is an
        OSError, and the loader converts OSError into ManifestError, so an
        OSError-based alarm is swallowed and this test passes after a real
        five-second block. Elapsed time is asserted as a second, independent
        signal so a future regression cannot hide in the exception type.
        """
        import signal
        import time

        class _Blocked(BaseException):
            """Not an OSError, so the loader cannot convert it into a refusal."""

        def alarm(_signum, _frame):
            raise _Blocked("read_bounded_regular_file blocked on a FIFO")

        with tempfile.TemporaryDirectory() as d:
            pipe = Path(d) / "pipe"
            os.mkfifo(pipe)
            previous = signal.signal(signal.SIGALRM, alarm)
            signal.alarm(5)
            started = time.monotonic()
            try:
                with self.assertRaises(ca.ManifestError) as cm:
                    ca.read_bounded_regular_file(pipe)
                elapsed = time.monotonic() - started
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, previous)
        self.assertRegex(str(cm.exception).lower(), r"regular|special|follow")
        self.assertLess(elapsed, 1.0,
                        "refusal must precede materialization, not follow a block")

    def test_bounded_loader_refuses_non_finite_exponent_overflow(self):
        """`parse_constant` sees the named NaN and Infinity tokens only. An
        exponent that overflows arrives as an ordinary float."""
        for probe in (b'{"a": 1e999}', b'{"a": -1e999}',
                      b'{"a": [[{"b": 1e999}]]}'):
            with self.subTest(probe=probe):
                with self.assertRaises(ca.ManifestError):
                    ca._parse_projection_json(probe)

    def test_bounded_loader_still_parses_large_finite_numbers(self):
        value = ca._parse_projection_json(b'{"a": [1, 1.0, -2.5, 1e308]}')
        self.assertEqual(value["a"], [1, 1.0, -2.5, 1e308])

    def test_bounded_loader_without_nofollow_uses_identity_parity(self):
        with tempfile.TemporaryDirectory() as d:
            regular = Path(d) / "ok.json"
            regular.write_bytes(b'{"ok": true}')
            target = Path(d) / "real.json"
            target.write_bytes(b'{"ok": true}')
            link = Path(d) / "link.json"
            link.symlink_to(target)
            directory = Path(d) / "dir"
            directory.mkdir()
            with mock.patch.object(os, "O_NOFOLLOW", None, create=True):
                self.assertEqual(
                    ca.read_bounded_regular_file(regular), b'{"ok": true}')
                with self.assertRaises(ca.ManifestError) as cm_link:
                    ca.read_bounded_regular_file(link)
                with self.assertRaises(ca.ManifestError) as cm_dir:
                    ca.read_bounded_regular_file(directory)
        self.assertRegex(str(cm_link.exception).lower(), r"regular|symlink|follow")
        self.assertRegex(str(cm_dir.exception).lower(), r"regular|symlink")
        src = inspect.getsource(ca.read_bounded_regular_file)
        self.assertIn("lstat", src)
        self.assertIn("fstat", src)
        self.assertIn("st_ino", src)

    def test_bounded_loader_reads_in_a_loop_and_accepts_exact_cap(self):
        payload = b"x" * 32
        with tempfile.TemporaryDirectory() as d:
            exact = Path(d) / "exact.bin"
            exact.write_bytes(payload)
            over = Path(d) / "over.bin"
            over.write_bytes(payload + b"y")
            reads = []
            real_read = os.read

            def tiny_read(fd, _n):
                chunk = real_read(fd, 1)
                reads.append(len(chunk))
                return chunk

            with mock.patch.object(ca, "OUTPUT_CAP_BYTES", 32),                     mock.patch.object(ca.os, "read", side_effect=tiny_read):
                self.assertEqual(ca.read_bounded_regular_file(exact), payload)
                with self.assertRaises(ca.ManifestError) as cm:
                    ca.read_bounded_regular_file(over)
        self.assertGreater(len(reads), 1)
        self.assertIn("cap", str(cm.exception).lower())

    def test_manifest_flag_without_survivors_exits_2(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (mock.patch.object(sys, "argv",
                                ["corpus_adequacy.py", "m.json", "--manifest", "a.json"]),
              mock.patch.object(sys, "stdout", stdout),
              mock.patch.object(sys, "stderr", stderr),
              mock.patch.object(
                  ca, "run",
                  side_effect=AssertionError("--manifest without --survivors called run()"))):
            rc = ca.main()
        self.assertEqual(rc, 2)
        self.assertIn("--manifest", stderr.getvalue())
        self.assertIn("--survivors", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_malformed_report_rows_are_refused_not_empty_or_keyerror(self):
        cases = (
            [],
            "not-a-report",
            {"schema": ca.REPORT_SCHEMA, "mutants": "survived"},
            {"schema": ca.REPORT_SCHEMA, "mutants": [None]},
            {"schema": ca.REPORT_SCHEMA, "mutants": [{"verdict": "survived"}]},
            {"schema": ca.REPORT_SCHEMA,
             "mutants": [{"label": 1, "group": "g", "verdict": "survived"}]},
            {"schema": ca.REPORT_SCHEMA,
             "mutants": {"g": [{"label": "x", "verdict": "survived"}]}},
        )
        for report in cases:
            with self.subTest(report=report):
                try:
                    ca.survivor_findings(report)
                except (ca.ManifestError, ValueError):
                    continue
                except Exception as exc:  # noqa: BLE001
                    self.fail("hostile input leaked %s: %s" % (type(exc).__name__, exc))
                else:
                    self.fail("hostile input produced a projection")

    def _digest_matched_pair(self, manifest_bytes):
        report = self._report(
            [self._row("survived", "only")],
            manifest_sha256="sha256:" + hashlib.sha256(manifest_bytes).hexdigest(),
        )
        return report, manifest_bytes

    def test_digest_matched_list_mutants_exits_2_without_traceback(self):
        raw = b'{"mutants":[{"x":1}]}'
        report, _ = self._digest_matched_pair(raw)
        with tempfile.TemporaryDirectory() as d:
            report_path = Path(d) / "report.json"
            manifest_path = Path(d) / "bad-manifest.json"
            report_path.write_bytes(ca.encode_report_v0(report))
            manifest_path.write_bytes(raw)
            with self.assertRaises(ca.ManifestError):
                ca.survivor_findings(report, manifest=manifest_path)
            proc = subprocess.run(
                [sys.executable, str(ca.__file__), "--survivors",
                 str(report_path), "--manifest", str(manifest_path)],
                capture_output=True, timeout=30)
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b"could not project", proc.stderr)
        self.assertNotIn(b"Traceback", proc.stderr)
        self.assertNotIn(b"AttributeError", proc.stderr)

    def test_digest_matched_nested_manifest_shapes_are_refused(self):
        cases = (
            b'{"mutants":[{"x":1}]}',
            b'{"mutants":{"g":"not-a-list"}}',
            b'{"mutants":{"g":[null]}}',
            b'{"mutants":{"g":["entry"]}}',
            b'[]',
        )
        for raw in cases:
            with self.subTest(raw=raw):
                report, _ = self._digest_matched_pair(raw)
                with tempfile.TemporaryDirectory() as d:
                    path = Path(d) / "m.json"
                    path.write_bytes(raw)
                    with self.assertRaises(ca.ManifestError):
                        ca.survivor_findings(report, manifest=path)

    def test_projection_json_refuses_nan_and_duplicate_keys(self):
        report, _ = self._digest_matched_pair(b'{"mutants":{}}')
        with tempfile.TemporaryDirectory() as d:
            nan = Path(d) / "nan.json"
            nan.write_bytes(b'{"mutants":{"g":[{"label":"only","anchor":NaN}]}}')
            report["manifest_sha256"] = "sha256:" + hashlib.sha256(nan.read_bytes()).hexdigest()
            with self.assertRaises(ca.ManifestError):
                ca.survivor_findings(report, manifest=nan)
            dup = Path(d) / "dup.json"
            dup.write_bytes(b'{"mutants":{"g":[]},"mutants":[{"x":1}]}')
            report["manifest_sha256"] = "sha256:" + hashlib.sha256(dup.read_bytes()).hexdigest()
            with self.assertRaises(ca.ManifestError):
                ca.survivor_findings(report, manifest=dup)

    def _deep_json_that_overflows_the_decoder(self):
        depth = 2000
        while depth <= 200000:
            raw = b"[" * depth + b"]" * depth
            self.assertLess(len(raw), ca.OUTPUT_CAP_BYTES)
            try:
                json.loads(raw.decode("utf-8"))
            except RecursionError:
                return raw
            depth *= 2
        self.fail("decoder accepted every nested array under the cap")

    def test_deeply_nested_projection_json_exits_2_without_traceback(self):
        raw = self._deep_json_that_overflows_the_decoder()
        with tempfile.TemporaryDirectory() as d:
            report_path = Path(d) / "deep.json"
            report_path.write_bytes(raw)
            with self.assertRaises(ca.ManifestError):
                ca._parse_projection_json(raw)
            proc = subprocess.run(
                [sys.executable, str(ca.__file__), "--survivors", str(report_path)],
                capture_output=True, timeout=30)
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b"could not project", proc.stderr)
        self.assertNotIn(b"Traceback", proc.stderr)
        self.assertNotIn(b"RecursionError", proc.stderr)

    def test_digest_matched_deep_manifest_exits_2_without_traceback(self):
        raw = self._deep_json_that_overflows_the_decoder()
        report, _ = self._digest_matched_pair(raw)
        with tempfile.TemporaryDirectory() as d:
            report_path = Path(d) / "report.json"
            manifest_path = Path(d) / "deep-manifest.json"
            report_path.write_bytes(ca.encode_report_v0(report))
            manifest_path.write_bytes(raw)
            with self.assertRaises(ca.ManifestError):
                ca.survivor_findings(report, manifest=manifest_path)
            proc = subprocess.run(
                [sys.executable, str(ca.__file__), "--survivors",
                 str(report_path), "--manifest", str(manifest_path)],
                capture_output=True, timeout=30)
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b"could not project", proc.stderr)
        self.assertNotIn(b"Traceback", proc.stderr)
        self.assertNotIn(b"RecursionError", proc.stderr)

    def test_cli_and_function_share_one_report_schema_refusal(self):
        report = {"schema": "other.v0", "mutants": []}
        with self.assertRaises(ca.ManifestError) as ctx:
            ca.survivor_findings(report)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(ca.__file__), "--survivors", str(path)],
                capture_output=True, timeout=30)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(
            proc.stderr.decode("utf-8").splitlines()[0],
            "could not project: %s" % ctx.exception,
        )
        tree = ast.parse(Path(ca.__file__).read_text(encoding="utf-8"))
        cli = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_survivors_cli")
        names = {node.id for node in ast.walk(cli) if isinstance(node, ast.Name)}
        self.assertNotIn("REPORT_SCHEMA", names)

    def test_anchor_requires_exact_manifest_file_bytes(self):
        manifest_obj = {
            "schema": ca.SCHEMA,
            "mutants": {
                "g": [{
                    "label": "only",
                    "anchor": "if True:\n    return 1",
                    "replacement": "if False:\n    return 1",
                }],
            },
        }
        compact = json.dumps(manifest_obj, separators=(",", ":")).encode("utf-8")
        spaced = compact + b"\n"
        self.assertNotEqual(
            hashlib.sha256(spaced).hexdigest(),
            hashlib.sha256(json.dumps(json.loads(spaced)).encode("utf-8")).hexdigest(),
        )
        report = self._report(
            [self._row("survived", "only")],
            manifest_sha256="sha256:" + hashlib.sha256(spaced).hexdigest(),
        )
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "m.json"
            path.write_bytes(spaced)
            matched = ca.survivor_findings(report, manifest=path)
            mismatched = ca.survivor_findings(
                dict(report, manifest_sha256="sha256:" + "ab" * 32),
                manifest=path,
            )
        self.assertEqual(matched["findings"][0]["anchor_excerpt"], "if True:    return 1")
        self.assertNotIn("anchor_excerpt", mismatched["findings"][0])
        self.assertNotIn("anchor_omitted", mismatched["findings"][0])

    def test_anchor_is_control_stripped_and_oversized_is_omitted(self):
        short_anchor = "keep\x01this\nline"
        long_anchor = "x" * 201
        manifest_obj = {
            "schema": ca.SCHEMA,
            "mutants": {
                "g": [
                    {"label": "ctrl", "anchor": short_anchor, "replacement": "a"},
                    {"label": "huge", "anchor": long_anchor, "replacement": "b"},
                ],
            },
        }
        raw = json.dumps(manifest_obj).encode("utf-8")
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        report = self._report(
            [self._row("survived", "ctrl"), self._row("survived", "huge")],
            manifest_sha256=digest,
        )
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "m.json"
            path.write_bytes(raw)
            projected = ca.survivor_findings(report, manifest=path)
        by_rule = {f["rule"]: f for f in projected["findings"]}
        self.assertEqual(by_rule["ctrl"]["anchor_excerpt"], "keepthisline")
        self.assertNotIn("\x01", by_rule["ctrl"]["anchor_excerpt"])
        self.assertNotIn("\n", by_rule["ctrl"]["anchor_excerpt"])
        self.assertEqual(by_rule["huge"].get("anchor_omitted"), "oversized")
        self.assertNotIn("anchor_excerpt", by_rule["huge"])

    def test_raw_control_anchor_is_oversized_before_stripping(self):
        raw_anchor = "\x01" * 5000
        self.assertGreater(len(raw_anchor), ca.ANCHOR_EXCERPT_MAX)
        self.assertEqual(ca._control_stripped_one_line(raw_anchor), "")
        manifest_obj = {
            "schema": ca.SCHEMA,
            "mutants": {"g": [{"label": "only", "anchor": raw_anchor, "replacement": "b"}]},
        }
        raw = json.dumps(manifest_obj).encode("utf-8")
        report = self._report(
            [self._row("survived", "only")],
            manifest_sha256="sha256:" + hashlib.sha256(raw).hexdigest(),
        )
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "m.json"
            path.write_bytes(raw)
            projected = ca.survivor_findings(report, manifest=path)
        finding = projected["findings"][0]
        self.assertEqual(finding.get("anchor_omitted"), "oversized")
        self.assertNotIn("anchor_excerpt", finding)

    def test_survivors_cli_does_not_call_run(self):
        report = self._report([self._row("survived", "only")], adequate=False)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "report.json"
            path.write_bytes(ca.encode_report_v0(report))
            stdout = io.BytesIO()

            class BinaryStdout:
                buffer = stdout

                def write(self, _text):
                    raise AssertionError("survivors JSON was routed through text encoding")

            with (mock.patch.object(sys, "argv",
                                    ["corpus_adequacy.py", "--survivors", str(path), "--json"]),
                  mock.patch.object(sys, "stdout", BinaryStdout()),
                  mock.patch.object(ca, "run",
                                    side_effect=AssertionError("--survivors called run()"))):
                rc = ca.main()
        self.assertEqual(rc, 0)
        body = json.loads(stdout.getvalue())
        self.assertEqual(body["schema"], ca.SURVIVORS_SCHEMA)
        self.assertEqual(body["finding_count"], 1)

    def test_plain_json_still_emits_report_v0(self):
        report = {"schema": ca.REPORT_SCHEMA, "adequate": True, "mutants": []}
        stdout = io.StringIO()
        with (mock.patch.object(sys, "argv", ["corpus_adequacy.py", "m.json", "--json"]),
              mock.patch.object(sys, "stdout", stdout),
              mock.patch.object(ca, "run", return_value=report),
              mock.patch.object(ca, "encode_report_v0",
                                wraps=ca.encode_report_v0) as encoder):
            rc = ca.main()
        self.assertEqual(rc, 0)
        encoder.assert_called_once_with(report)
        self.assertEqual(json.loads(stdout.getvalue())["schema"], ca.REPORT_SCHEMA)

    def test_survivors_cli_refuses_oversized_and_symlink_inputs(self):
        report = self._report([self._row("survived", "only")])
        with tempfile.TemporaryDirectory() as d:
            regular = Path(d) / "report.json"
            regular.write_bytes(ca.encode_report_v0(report))
            huge = Path(d) / "huge.json"
            huge.write_bytes(b"{" + (b"x" * 80) + b"}")
            link = Path(d) / "link.json"
            if hasattr(os, "O_NOFOLLOW"):
                link.symlink_to(regular)
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (mock.patch.object(ca, "OUTPUT_CAP_BYTES", 32),
                  mock.patch.object(sys, "argv",
                                    ["corpus_adequacy.py", "--survivors", str(huge), "--json"]),
                  mock.patch.object(sys, "stdout", stdout),
                  mock.patch.object(sys, "stderr", stderr),
                  mock.patch.object(
                      json, "loads",
                      side_effect=AssertionError("json.loads ran after the cap"))):
                rc = ca.main()
            self.assertEqual(rc, 2)
            self.assertIn("could not project", stderr.getvalue())
            self.assertNotIn("could not measure", stderr.getvalue())
            env = json.loads(stdout.getvalue())
            self.assertEqual(env["schema"], ca.ERROR_SCHEMA)
            if hasattr(os, "O_NOFOLLOW"):
                linked = subprocess.run(
                    [sys.executable, str(ca.__file__), "--survivors", str(link)],
                    capture_output=True, timeout=30)
                self.assertEqual(linked.returncode, 2)
                self.assertIn("could not project", linked.stderr.decode())

    def test_deep_measurement_input_exits_2_without_traceback(self):
        raw = "[" * 16000 + "]" * 16000
        self.assertLess(len(raw.encode("utf-8")), ca.OUTPUT_CAP_BYTES)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "deep.json"
            path.write_text(raw, encoding="utf-8")
            for extra in ([], ["--json"]):
                with self.subTest(extra=extra):
                    proc = subprocess.run(
                        [sys.executable, str(ca.__file__), str(path), *extra],
                        capture_output=True, timeout=30)
                    self.assertEqual(proc.returncode, 2)
                    self.assertNotIn(b"Traceback", proc.stderr)
                    self.assertNotIn(b"Traceback", proc.stdout)
                    self.assertIn(b"could not measure", proc.stderr)
                    if extra:
                        env = json.loads(proc.stdout)
                        self.assertEqual(env["schema"], ca.ERROR_SCHEMA)
                        self.assertIs(env["ok"], False)
                        self.assertEqual(env["exit"], 2)
                        self.assertIn("could not measure", env["error"])
                        self.assertNotEqual(env.get("schema"), ca.REPORT_SCHEMA)

    def test_load_manifest_classifies_recursionerror(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "m.json"
            path.write_text("{\"schema\":\"%s\"}" % ca.SCHEMA, encoding="utf-8")
            with mock.patch.object(ca.json, "loads", side_effect=RecursionError("too deep")):
                with self.assertRaises(ca.ManifestError) as ctx:
                    ca.load_manifest(path)
        self.assertNotIn("Traceback", str(ctx.exception))

    def test_survivors_json_malformed_envelope_uses_project_verb(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "nope.json"
            path.write_text('{"schema":"nope"}\n', encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(ca.__file__), "--survivors", str(path), "--json"],
                capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("could not project", proc.stderr)
        self.assertNotIn("could not measure", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)
        env = json.loads(proc.stdout)
        self.assertEqual(env["schema"], ca.ERROR_SCHEMA)
        self.assertIn("could not project", env["error"])
        self.assertNotIn("could not measure", env["error"])

    def test_empty_after_control_strip_is_intentional_omission(self):
        raw_anchor = "\x01" * 10
        manifest_obj = {
            "schema": ca.SCHEMA,
            "mutants": {
                "g": [{"label": "only", "anchor": raw_anchor, "replacement": "a"}],
            },
        }
        raw = json.dumps(manifest_obj).encode("utf-8")
        report = self._report(
            [self._row("survived", "only")],
            manifest_sha256="sha256:" + hashlib.sha256(raw).hexdigest(),
        )
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "m.json"
            path.write_bytes(raw)
            projected = ca.survivor_findings(report, manifest=path)
        finding = projected["findings"][0]
        self.assertNotIn("anchor_excerpt", finding)
        self.assertNotIn("anchor_omitted", finding)
        readme = Path(__file__).resolve().parent.parent.joinpath("README.md").read_text(
            encoding="utf-8")
        self.assertIn("intentional omission", readme)
        self.assertIn("empty after control stripping", readme)

    def test_deep_vectors_input_exits_2_without_traceback(self):
        raw = "[" * 16000 + "]" * 16000
        self.assertLess(len(raw.encode("utf-8")), ca.OUTPUT_CAP_BYTES)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "impl.py").write_text("def check(v):\n    return True\n", encoding="utf-8")
            (root / "vectors.json").write_text(raw, encoding="utf-8")
            path = root / "m.json"
            path.write_text(json.dumps({
                "schema": ca.SCHEMA, "runner": "module",
                "implementation": "impl.py", "entrypoint": "check",
                "vectors": "vectors.json", "id_key": "vector_id",
                "default_group": "g",
                "mutants": {"g": [
                    {"label": "r1", "anchor": "return True",
                     "replacement": "return False"}]},
            }), encoding="utf-8")
            for extra in ([], ["--json"]):
                with self.subTest(extra=extra):
                    proc = subprocess.run(
                        [sys.executable, str(ca.__file__), str(path), *extra],
                        capture_output=True, timeout=30)
                    self.assertEqual(proc.returncode, 2)
                    self.assertNotIn(b"Traceback", proc.stderr)
                    self.assertNotIn(b"Traceback", proc.stdout)
                    self.assertIn(b"could not measure", proc.stderr)
                    if extra:
                        env = json.loads(proc.stdout)
                        self.assertEqual(env["schema"], ca.ERROR_SCHEMA)
                        self.assertIs(env["ok"], False)
                        self.assertEqual(env["exit"], 2)

    def test_vector_row_shape_is_a_manifest_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "impl.py").write_text("def check(v):\n    return True\n", encoding="utf-8")
            (root / "vectors.json").write_text("[[]]\n", encoding="utf-8")
            path = root / "m.json"
            path.write_text(json.dumps({
                "schema": ca.SCHEMA, "runner": "module",
                "implementation": "impl.py", "entrypoint": "check",
                "vectors": "vectors.json", "id_key": "vector_id",
                "default_group": "g",
                "mutants": {"g": [{"label": "r1", "anchor": "return True",
                                   "replacement": "return False"}]},
            }), encoding="utf-8")
            m = ca.load_manifest(path)
            with self.assertRaises(ca.ManifestError):
                ca.load_vector_document(m)

    def test_error_envelope_requires_an_explicit_operation(self):
        with self.assertRaises(TypeError):
            ca.error_envelope(ValueError("x"))
        env = ca.error_envelope(ValueError("x"), operation="project")
        self.assertEqual(env["error"], "could not project: x")
        env = ca.error_envelope(ValueError("x"), operation="measure")
        self.assertEqual(env["error"], "could not measure: x")

    def test_unreleased_changelog_does_not_name_a_version_tag(self):
        text = Path(__file__).resolve().parent.parent.joinpath("CHANGELOG.md").read_text(
            encoding="utf-8")
        unreleased = text.split("## 0.1.0", 1)[0]
        self.assertIn("## Unreleased", unreleased)
        self.assertNotIn("v0.1.0", unreleased)
        self.assertIn("0.1.0", unreleased)

    def test_error_envelope_rejects_an_invalid_operation(self):
        with self.assertRaises(ValueError):
            ca.error_envelope(ValueError("x"), operation="score")

    def test_load_json_document_classifies_recursionerror(self):
        with mock.patch.object(ca.json, "loads", side_effect=RecursionError("too deep")):
            with self.assertRaises(ca.ManifestError) as ctx:
                ca.load_json_document(b"{}", root=dict, where="manifest")
        self.assertNotIn("Traceback", str(ctx.exception))

    def test_manifest_array_root_exits_2_without_traceback(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "m.json"
            path.write_text("[]\n", encoding="utf-8")
            for extra in ([], ["--json"]):
                with self.subTest(extra=extra):
                    proc = subprocess.run(
                        [sys.executable, str(ca.__file__), str(path), *extra],
                        capture_output=True, timeout=30)
                    self.assertEqual(proc.returncode, 2)
                    self.assertNotIn(b"Traceback", proc.stderr)
                    self.assertIn(b"could not measure", proc.stderr)
                    if extra:
                        env = json.loads(proc.stdout)
                        self.assertEqual(env["schema"], ca.ERROR_SCHEMA)

    def test_missing_vectors_key_is_a_manifest_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "impl.py").write_text("def check(v):\n    return True\n", encoding="utf-8")
            (root / "vectors.json").write_text("{\"other\": []}\n", encoding="utf-8")
            path = root / "m.json"
            path.write_text(json.dumps({
                "schema": ca.SCHEMA, "runner": "module",
                "implementation": "impl.py", "entrypoint": "check",
                "vectors": "vectors.json", "id_key": "vector_id",
                "default_group": "g",
                "mutants": {"g": [{"label": "r1", "anchor": "return True",
                                   "replacement": "return False"}]},
            }), encoding="utf-8")
            m = ca.load_manifest(path)
            with self.assertRaises(ca.ManifestError) as ctx:
                ca.load_vector_document(m)
        self.assertIn("vectors key", str(ctx.exception))

    def _holes_cli(self, digest_text):
        root = Path(tempfile.mkdtemp())
        (root / "impl.py").write_text("def check(v):\n    return True\n", encoding="utf-8")
        (root / "vectors.json").write_text(
            json.dumps({"vectors": [{"vector_id": "v1"}]}), encoding="utf-8")
        (root / "digest.json").write_text(digest_text, encoding="utf-8")
        path = root / "m.json"
        path.write_text(json.dumps({
            "schema": ca.SCHEMA, "runner": "module",
            "implementation": "impl.py", "entrypoint": "check",
            "vectors": "vectors.json", "id_key": "vector_id",
            "default_group": "g",
            "corpus_digest_file": "digest.json",
            "corpus_digest_key": "digest",
            "known_holes": {"sha256:deadbeef": [
                {"label": "r1", "reason": "acknowledged", "recorded": "2026-08-22"}]},
            "mutants": {"g": [
                {"label": "r1", "anchor": "return True", "replacement": "return False"},
                {"label": "CONTROL", "control": True,
                 "anchor": "def check", "replacement": "def  check"}]},
        }), encoding="utf-8")
        return path

    def test_corpus_digest_deep_array_and_missing_key_exit_2(self):
        cases = (
            "[" * 16000 + "]" * 16000,
            "[]\n",
            "{}\n",
        )
        for digest_text in cases:
            with self.subTest(digest=digest_text[:8]):
                path = self._holes_cli(digest_text)
                proc = subprocess.run(
                    [sys.executable, str(ca.__file__), str(path), "--json"],
                    capture_output=True, timeout=30)
                self.assertEqual(proc.returncode, 2)
                self.assertNotIn(b"Traceback", proc.stderr)
                env = json.loads(proc.stdout)
                self.assertEqual(env["schema"], ca.ERROR_SCHEMA)
                self.assertEqual(env["exit"], 2)


    def test_vectors_selected_list_guard_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "impl.py").write_text("def check(v):\n    return True\n", encoding="utf-8")
            (root / "vectors.json").write_text('{"vectors": 5}\n', encoding="utf-8")
            path = root / "m.json"
            path.write_text(json.dumps({
                "schema": ca.SCHEMA, "runner": "module",
                "implementation": "impl.py", "entrypoint": "check",
                "vectors": "vectors.json", "id_key": "vector_id",
                "default_group": "g",
                "mutants": {"g": [{"label": "r1", "anchor": "return True",
                                   "replacement": "return False"}]},
            }), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(ca.__file__), str(path), "--json"],
                capture_output=True, timeout=30)
            self.assertEqual(proc.returncode, 2)
            self.assertNotIn(b"Traceback", proc.stderr)
            env = json.loads(proc.stdout)
            self.assertEqual(env["schema"], ca.ERROR_SCHEMA)
            self.assertIn("array", env["error"])

    def test_corpus_digest_value_must_be_a_string(self):
        for raw in ('{"digest": ["x"]}\n', '{"digest": {"a": 1}}\n'):
            with self.subTest(raw=raw):
                path = self._holes_cli(raw)
                proc = subprocess.run(
                    [sys.executable, str(ca.__file__), str(path), "--json"],
                    capture_output=True, timeout=30)
                self.assertEqual(proc.returncode, 2)
                self.assertNotIn(b"Traceback", proc.stderr)
                env = json.loads(proc.stdout)
                self.assertEqual(env["schema"], ca.ERROR_SCHEMA)

    def test_vector_row_missing_declared_key_is_rc2(self):
        cases = (
            ({"id_key": "vector_id", "group_key": "grp",
              "row": {"vector_id": "v1"}}, "grp"),
            ({"id_key": "vector_id", "group_key": None,
              "row": {"other": "v1"}}, "vector_id"),
        )
        for extra, missing in cases:
            with self.subTest(missing=missing):
                with tempfile.TemporaryDirectory() as d:
                    root = Path(d)
                    (root / "impl.py").write_text(
                        "def check(v):\n    return True\n", encoding="utf-8")
                    (root / "vectors.json").write_text(
                        json.dumps({"vectors": [extra["row"]]}), encoding="utf-8")
                    manifest = {
                        "schema": ca.SCHEMA, "runner": "module",
                        "implementation": "impl.py", "entrypoint": "check",
                        "vectors": "vectors.json",
                        "id_key": extra["id_key"],
                        "default_group": "g",
                        "mutants": {"g": [{"label": "r1", "anchor": "return True",
                                           "replacement": "return False"}]},
                    }
                    if extra["group_key"] is not None:
                        manifest["group_key"] = extra["group_key"]
                    path = root / "m.json"
                    path.write_text(json.dumps(manifest), encoding="utf-8")
                    proc = subprocess.run(
                        [sys.executable, str(ca.__file__), str(path), "--json"],
                        capture_output=True, timeout=30)
                    self.assertEqual(proc.returncode, 2)
                    self.assertNotIn(b"Traceback", proc.stderr)
                    env = json.loads(proc.stdout)
                    self.assertEqual(env["schema"], ca.ERROR_SCHEMA)
                    self.assertIn(missing, env["error"])

    def test_load_vector_document_decodes_once_for_both_roots(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "impl.py").write_text("def check(v):\n    return True\n", encoding="utf-8")
            path = root / "m.json"
            path.write_text(json.dumps({
                "schema": ca.SCHEMA, "runner": "module",
                "implementation": "impl.py", "entrypoint": "check",
                "vectors": "vectors.json", "id_key": "vector_id",
                "default_group": "g",
                "mutants": {"g": [{"label": "r1", "anchor": "return True",
                                   "replacement": "return False"}]},
            }), encoding="utf-8")
            m = ca.load_manifest(path)
            for raw in (
                json.dumps({"vectors": [{"vector_id": "v1"}]}),
                json.dumps([{"vector_id": "v1"}]),
            ):
                with self.subTest(raw=raw[:20]):
                    (root / "vectors.json").write_text(raw, encoding="utf-8")
                    with mock.patch.object(ca.json, "loads", wraps=json.loads) as loads:
                        rows = ca.load_vector_document(m)
                    self.assertEqual(loads.call_count, 1)
                    self.assertEqual(rows[0]["vector_id"], "v1")


class SurvivorConsumerClosedSet(unittest.TestCase):
    """Issue #96: --survivors refuses unknown keys at report and mutant-row depth."""

    REPORT_EXTRA = "report extra key"
    REPORT_MISSING = "report missing key"
    MUTANT_EXTRA = "mutant extra key"
    MUTANT_MISSING = "mutant missing key"
    VALID_REPORT = (
        Path(__file__).resolve().parent / "fixtures" / "publication"
        / "valid-tersign" / "report.v0.json")
    VALID_REPORT_SHA256 = (
        "c65f8a6c6dcc4a56dea31e7fc0de241a8cbbdcf36cd4cf98c220d23a894fe5ae")
    VALID_SURVIVORS_SHA256 = (
        "caf3c2345a229d9f76367753ed7e856627fdd8f55aa00e6fbfad2ee502f9e9bb")

    def _valid_doc(self):
        return json.loads(self.VALID_REPORT.read_text(encoding="utf-8"))

    def _producer_required_top_level_keys(self, doc):
        """Keys this decoded valid document must keep.

        `schema` is owned by the report.v0 identity gate, not the missing-key
        route. The runner-specific field stays optional.
        """
        return frozenset(doc) - frozenset({
            "schema", "originals_unverified_against_head"})

    def _verdict_row_shapes(self, doc):
        """One producer row per distinct verdict in the decoded valid document."""
        shapes = {}
        for row in doc["mutants"]:
            shapes.setdefault(row["verdict"], dict(row))
        return shapes

    def _producer_required_row_keys(self, row):
        """Required keys for this row shape. Verdict-optional fields stay optional."""
        optional = {"moved_diagnostic", "raised"}
        if row["verdict"] == "equivalent":
            optional.add("scope")
        return frozenset(row) - optional

    def _project_cli(self, doc):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "report.json"
            path.write_bytes(ca.encode_report_v0(doc))
            return subprocess.run(
                [sys.executable, str(ca.__file__), "--survivors", str(path), "--json"],
                capture_output=True, timeout=30)

    def _assert_route(self, text, route, *forbidden):
        self.assertIn(route, text)
        for token in forbidden:
            self.assertNotIn(token, text)

    def test_top_level_extra_key_is_refused_through_report_extra_route(self):
        doc = self._valid_doc()
        doc["published_url"] = "https://example.invalid/report"
        with self.assertRaises(ca.ManifestError) as cm:
            ca.survivor_findings(doc)
        self._assert_route(
            str(cm.exception), self.REPORT_EXTRA,
            self.REPORT_MISSING, self.MUTANT_EXTRA, self.MUTANT_MISSING)
        proc = self._project_cli(doc)
        self.assertEqual(proc.returncode, 2)
        combined = (proc.stderr + proc.stdout).decode("utf-8")
        self._assert_route(
            combined, self.REPORT_EXTRA,
            self.REPORT_MISSING, self.MUTANT_EXTRA, self.MUTANT_MISSING)
        self.assertNotIn("Traceback", combined)
        self.assertNotIn(ca.SURVIVORS_SCHEMA, proc.stdout.decode("utf-8"))

    def test_mutant_row_extra_key_is_refused_through_mutant_extra_route(self):
        doc = self._valid_doc()
        doc["mutants"][0]["published_url"] = "https://example.invalid/row"
        with self.assertRaises(ca.ManifestError) as cm:
            ca.survivor_findings(doc)
        self._assert_route(
            str(cm.exception), self.MUTANT_EXTRA,
            self.MUTANT_MISSING, self.REPORT_EXTRA, self.REPORT_MISSING)
        proc = self._project_cli(doc)
        self.assertEqual(proc.returncode, 2)
        combined = (proc.stderr + proc.stdout).decode("utf-8")
        self._assert_route(
            combined, self.MUTANT_EXTRA,
            self.MUTANT_MISSING, self.REPORT_EXTRA, self.REPORT_MISSING)
        self.assertNotIn("Traceback", combined)
        self.assertNotIn(ca.SURVIVORS_SCHEMA, proc.stdout.decode("utf-8"))

    def test_top_level_missing_key_is_refused_through_report_missing_route(self):
        doc = self._valid_doc()
        required = self._producer_required_top_level_keys(doc)
        self.assertTrue(
            {"tool_content_sha256", "manifest_sha256", "score_means", "mutants"}
            <= required)
        for key in sorted(required):
            mutant = self._valid_doc()
            del mutant[key]
            with self.subTest(key=key):
                with self.assertRaises(ca.ManifestError) as cm:
                    ca.survivor_findings(mutant)
                self._assert_route(
                    str(cm.exception), self.REPORT_MISSING,
                    self.REPORT_EXTRA, self.MUTANT_EXTRA, self.MUTANT_MISSING)
        optional = self._valid_doc()
        del optional["originals_unverified_against_head"]
        self.assertEqual(
            ca.survivor_findings(optional)["schema"], ca.SURVIVORS_SCHEMA)

    def test_mutant_row_missing_key_is_refused_through_mutant_missing_route(self):
        shapes = self._verdict_row_shapes(self._valid_doc())
        self.assertTrue(shapes)
        for verdict, proto in shapes.items():
            required = self._producer_required_row_keys(proto)
            self.assertIn("moved", required)
            for key in sorted(required):
                mutant = self._valid_doc()
                target = next(
                    row for row in mutant["mutants"] if row["verdict"] == verdict)
                del target[key]
                with self.subTest(verdict=verdict, key=key):
                    with self.assertRaises(ca.ManifestError) as cm:
                        ca.survivor_findings(mutant)
                    self._assert_route(
                        str(cm.exception), self.MUTANT_MISSING,
                        self.MUTANT_EXTRA, self.REPORT_EXTRA, self.REPORT_MISSING)

    def test_valid_report_v0_production_bytes_are_unchanged(self):
        raw = self.VALID_REPORT.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), self.VALID_REPORT_SHA256)
        self.assertEqual(ca.encode_report_v0(json.loads(raw)), raw)

    def test_valid_survivors_v0_production_bytes_are_unchanged(self):
        encoded = ca.encode_survivors_v0(ca.survivor_findings(self._valid_doc()))
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), self.VALID_SURVIVORS_SHA256)


# ---------------------------------------------------------------------------
# #66: one process/batch mutation step, one backend seam, one tally closer
# ---------------------------------------------------------------------------

_HOST_LOCAL_REPORT_KEYS = frozenset({
    "tool_commit", "tool_source_state", "tool_content_sha256",
    "manifest", "originals_unverified_against_head",
})
_ROW_KEYS = ("group", "label", "verdict", "scope", "moved", "how", "moved_diagnostic")


def _semantic_projection(report: dict) -> dict:
    """Byte-stable report fields. Host-local identity is not the fixture."""
    projected = {key: report[key] for key in report if key not in _HOST_LOCAL_REPORT_KEYS}
    projected["mutants"] = [
        {key: row[key] for key in _ROW_KEYS if key in row}
        for row in report.get("mutants", [])
    ]
    return projected


def _normalized_full_report(report: dict) -> dict:
    report = json.loads(json.dumps(report))
    for key in ("manifest", "manifest_sha256", "tool_version", "tool_commit",
                "tool_source_state", "tool_content_sha256"):
        report[key] = "<normalized>"
    return report


def _process_kill_manifest(tmp: Path) -> Path:
    (tmp / "check.py").write_text(
        "import json, sys\n"
        "doc = json.load(open(sys.argv[1]))\n"
        "fails = [c['id'] for c in doc['cases'] if c['n'] > 10]\n"
        "print(json.dumps({'ok': not fails, 'failures': fails}))\n")
    (tmp / "vec.json").write_text(json.dumps({"cases": [
        {"id": "c1", "n": 1}, {"id": "c2", "n": 2}]}))
    (tmp / "vectors.json").write_text(json.dumps({
        "vectors": [{"vector_id": "v1", "path": "vec.json"}]}))
    path = tmp / "m.json"
    path.write_text(json.dumps({
        "schema": ca.SCHEMA, "runner": "process", "repo_root": ".",
        "implementation_sources": ["check.py"], "implementation": "check.py",
        "build": [],
        "entrypoint_command": [_batch_python(), "check.py", "{vector}"],
        "outcome_from": ["ok", "failures"], "vectors": "vectors.json",
        "id_key": "vector_id", "vector_path_key": "path", "default_group": "g",
        "mutants": {"g": [
            {"label": "threshold", "anchor": "c['n'] > 10", "replacement": "c['n'] > 1"},
            {"label": "CONTROL", "control": True,
             "anchor": "'ok': not fails", "replacement": "'ok': 'MOVED'"}]},
    }))
    return path


def _two_group_process_manifest(tmp: Path) -> Path:
    (tmp / "check.py").write_text(
        "import json, sys\n"
        "doc = json.load(open(sys.argv[1]))\n"
        "fails = [c['id'] for c in doc['cases'] if c['n'] > 10]\n"
        "print(json.dumps({'ok': not fails, 'failures': fails}))\n")
    for name, value in (("a", 1), ("b", 2)):
        (tmp / (name + ".json")).write_text(json.dumps({
            "cases": [{"id": name, "n": value}]}))
    (tmp / "vectors.json").write_text(json.dumps({"vectors": [
        {"vector_id": "v-a", "group": "a", "path": "a.json"},
        {"vector_id": "v-b", "group": "b", "path": "b.json"},
    ]}))
    path = tmp / "m.json"
    path.write_text(json.dumps({
        "schema": ca.SCHEMA, "runner": "process", "repo_root": ".",
        "implementation_sources": ["check.py"], "implementation": "check.py",
        "build": [],
        "entrypoint_command": [_batch_python(), "check.py", "{vector}"],
        "outcome_from": ["ok", "failures"], "vectors": "vectors.json",
        "id_key": "vector_id", "group_key": "group", "vector_path_key": "path",
        "mutants": {
            "a": [
                {"label": "CONTROL", "control": True,
                 "anchor": "'ok': not fails", "replacement": "'ok': 'MOVED'"},
                {"label": "a threshold", "anchor": "c['n'] > 10",
                 "replacement": "c['n'] > 0"},
            ],
            "b": [
                {"label": "b outcome", "anchor": "'failures': fails",
                 "replacement": "'failures': ['MOVED']"},
            ],
        },
    }))
    return path


def _two_source_noop_process_manifest(tmp: Path, *, with_control: bool) -> Path:
    path = _process_kill_manifest(tmp)
    check = tmp / "check.py"
    check.write_text(
        check.read_text(encoding="utf-8")
        .replace("import json, sys\n", "import json, sys\nfrom settings import THRESHOLD\n")
        .replace("c['n'] > 10", "c['n'] > THRESHOLD")
        + "# MUTATION_SLOT\n",
        encoding="utf-8",
    )
    settings = tmp / "settings.py"
    settings.write_text("THRESHOLD = 10\n", encoding="utf-8")
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["implementation_sources"] = ["check.py", "settings.py"]
    mutants = []
    if with_control:
        mutants.append({
            "label": "CONTROL", "control": True,
            "anchor": "'ok': not fails", "replacement": "'ok': 'MOVED'",
        })
    mutants.append({
        "label": "no-op comment", "anchor": "# MUTATION_SLOT",
        "replacement": "# MUTATION_SLOT_CHANGED",
    })
    raw["mutants"] = {"g": mutants}
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


class SharedMutationStep(unittest.TestCase):
    """Freeze current reports, then pin the one-engine extract and its mutations."""

    def _batch(self, tmp: Path) -> dict:
        return ca.run(BatchRunner()._corpus(tmp))

    def test_manifest_bytes_rebind_logical_paths_without_changing_identity(self):
        raw = json.dumps({
            "schema": ca.SCHEMA,
            "runner": "batch",
            "repo_root": "subject",
            "implementation": "subject/check.py",
            "implementation_sources": ["subject/check.py"],
            "entrypoint_command": ["checker"],
            "outcome_from": ["rows"],
            "vectors": "corpus/vectors.json",
            "default_group": "g",
            "mutants": {"g": [{
                "label": "rule", "anchor": "return True",
                "replacement": "return False",
            }]},
        }, sort_keys=True).encode("utf-8")
        loaded = []
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            for name in ("one", "two"):
                root = tmp / name
                (root / "subject").mkdir(parents=True)
                (root / "corpus").mkdir()
                (root / "subject" / "check.py").write_text(
                    "def check():\n    return True\n", encoding="utf-8")
                (root / "corpus" / "vectors.json").write_text(
                    '{"vectors":[]}', encoding="utf-8")
                loaded.append(ca.load_manifest_bytes(
                    raw, Path("measurements/frozen-manifest.json"),
                    path_root=root,
                ))

        self.assertEqual(loaded[0]["_manifest_sha256"],
                         loaded[1]["_manifest_sha256"])
        self.assertNotEqual(loaded[0]["_repo_root"], loaded[1]["_repo_root"])
        self.assertEqual(loaded[0]["_repo_root"].name, "subject")
        self.assertEqual(loaded[1]["_repo_root"].name, "subject")

    def test_parity_module_report_projection(self):
        with tempfile.TemporaryDirectory() as d:
            report = ca.run(_manifest(Path(d), {"a": [KILLABLE]}))
        projected = _semantic_projection(report)
        self.assertEqual(projected["runner"], "module")
        self.assertEqual(projected["killed"], 1)
        self.assertEqual(projected["survived"], 0)
        self.assertEqual(projected["score_percent"], 100.0)
        self.assertTrue(projected["adequate"])
        self.assertEqual(projected["control_status"], "killed")
        self.assertEqual(
            [(row["label"], row["verdict"], row["moved"]) for row in projected["mutants"]],
            [("rejects bad input", "killed", 1),
             ("CONTROL harness reachability [a]", "control-killed", 2)])

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_parity_process_report_projection(self):
        with tempfile.TemporaryDirectory() as d:
            report = ca.run(_process_kill_manifest(Path(d)))
        projected = _semantic_projection(report)
        self.assertEqual(projected["runner"], "process")
        self.assertEqual(
            (projected["killed"], projected["survived"], projected["score_percent"],
             projected["adequate"], projected["control_status"], projected["failures"]),
            (1, 0, 100.0, True, "killed", []))
        self.assertEqual(
            [(row["label"], row["verdict"], row["moved"]) for row in projected["mutants"]],
            [("CONTROL", "control-killed", 1), ("threshold", "killed", 1)])

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_parity_batch_report_projection(self):
        with tempfile.TemporaryDirectory() as d:
            report = self._batch(Path(d))
        projected = _semantic_projection(report)
        self.assertEqual(projected["runner"], "batch")
        self.assertEqual(
            (projected["killed"], projected["survived"], projected["score_percent"],
             projected["adequate"], projected["control_status"], projected["failures"]),
            (1, 0, 100.0, True, "killed", []))
        self.assertEqual(
            [(row["label"], row["verdict"], row["moved"]) for row in projected["mutants"]],
            [("CONTROL", "control-killed", 1), ("threshold", "killed", 1)])

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_parity_controls_first_before_ordinary(self):
        with tempfile.TemporaryDirectory() as d:
            labels = [row["label"] for row in self._batch(Path(d))["mutants"]]
        self.assertEqual(labels, ["CONTROL", "threshold"])

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_parity_baseline_failure_has_no_score(self):
        with tempfile.TemporaryDirectory() as d:
            path = BatchRunner()._corpus(Path(d))
            with mock.patch.object(ca, "_run_capped", return_value=_completed(1)):
                report = ca.run(path)
        self.assertIsNone(report["score_percent"])
        self.assertFalse(report["adequate"])
        self.assertEqual(report["killed"], 0)
        self.assertTrue(any("UNMUTATED" in item for item in report["failures"]))
        self.assertEqual(report["mutants"], [])

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_parity_abnormal_child_is_control_error_not_killed(self):
        with tempfile.TemporaryDirectory() as d:
            path = BatchRunner()._corpus(Path(d))
            with mock.patch.object(
                    ca, "_run_capped",
                    side_effect=ChildExitRunSemantics()._fake_from_source(control_rc=1)):
                report = ca.run(path)
        row = next(item for item in report["mutants"] if item["label"] == "CONTROL")
        self.assertEqual(row["verdict"], "control-error")
        self.assertEqual(report["control_status"], "error")
        self.assertIsNone(report["score_percent"])
        self.assertEqual(report["killed"], 0)
        self.assertNotIn("threshold", [item["label"] for item in report["mutants"]])

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_process_and_batch_incomplete_drain_is_unproved_not_killed(self):
        for factory in (BatchRunner()._corpus, _process_kill_manifest):
            name = factory.__name__ if hasattr(factory, "__name__") else factory
            with self.subTest(factory=name), tempfile.TemporaryDirectory() as d:
                path = factory(Path(d))
                child = _NthChild(
                    3, exc=br._OutputDrainIncomplete("captured streams stayed open")
                )
                with mock.patch.object(ca, "_run_capped", child):
                    report = ca.run(path)
            row = next(item for item in report["mutants"] if item["label"] == "threshold")
            self.assertEqual(row["verdict"], "unproved")
            self.assertIn("incomplete", row["how"])
            self.assertEqual((report["killed"], report["unproved"]), (0, 1))
            self.assertFalse(report["adequate"])

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_parity_source_restored_after_process_and_batch(self):
        for factory in (BatchRunner()._corpus, _process_kill_manifest):
            name = factory.__name__ if hasattr(factory, "__name__") else factory
            with self.subTest(factory=name):
                with tempfile.TemporaryDirectory() as d:
                    tmp = Path(d)
                    path = factory(tmp)
                    before = (tmp / "check.py").read_bytes()
                    ca.run(path)
                    self.assertEqual((tmp / "check.py").read_bytes(), before)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_run_process_uses_one_shared_step_primitive(self):
        calls = []
        original = ca._run_mutation_step

        def witnessed(session, group, mutant):
            calls.append((group, mutant["label"]))
            return original(session, group, mutant)

        with tempfile.TemporaryDirectory() as d, mock.patch.object(
                ca, "_run_mutation_step", side_effect=witnessed):
            report = self._batch(Path(d))
        self.assertTrue(report["adequate"])
        self.assertEqual(calls, [("g", "CONTROL"), ("g", "threshold")])

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_authorized_order_drives_the_shared_step_without_a_second_engine(self):
        calls = []
        original = ca._run_mutation_step

        def witnessed(session, group, mutant):
            calls.append((group, mutant["label"]))
            return original(session, group, mutant)

        with tempfile.TemporaryDirectory() as d, mock.patch.object(
                ca, "_run_mutation_step", side_effect=witnessed):
            path = _two_group_process_manifest(Path(d))
            report = ca._run_process(
                ca.load_manifest(path), path,
                mutation_order=("CONTROL", "b outcome", "a threshold"),
            )

        self.assertTrue(report["adequate"])
        self.assertEqual(
            calls,
            [("a", "CONTROL"), ("b", "b outcome"), ("a", "a threshold")],
        )

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_authorized_order_must_name_every_declared_mutant_once(self):
        with tempfile.TemporaryDirectory() as d:
            path = _two_group_process_manifest(Path(d))
            loaded = ca.load_manifest(path)
            for order in (
                ("CONTROL", "a threshold"),
                ("CONTROL", "a threshold", "a threshold"),
                ("a threshold", "CONTROL", "b outcome"),
                ("CONTROL", "a threshold", "b outcome", "unknown"),
            ):
                with self.subTest(order=order), self.assertRaisesRegex(
                        ca.ManifestError, "mutation_order"):
                    ca._run_process(dict(loaded), path, mutation_order=order)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_combined_build_run_has_no_fabricated_compile_only_execution(self):
        calls = []

        def witnessed(m, vectors=None, *, rebuild=True):
            calls.append((vectors is None, rebuild))
            return ca._default_execution_backend(m, vectors, rebuild=rebuild)

        with tempfile.TemporaryDirectory() as d:
            path = _process_kill_manifest(Path(d))
            report = ca._run_process(
                ca.load_manifest(path), path,
                execution_backend=witnessed,
                separate_build_phase=False,
            )

        self.assertTrue(report["adequate"])
        self.assertNotIn((True, True), calls)
        self.assertEqual(calls[0], (False, True))

    def test_one_authoritative_tally_and_default_backend_seam(self):
        self.assertTrue(callable(ca._default_execution_backend))
        self.assertTrue(callable(ca._finalize_process_tally))
        self.assertTrue(callable(ca._new_process_tally))
        backend_src = inspect.getsource(ca._default_execution_backend)
        self.assertIn("_build(", backend_src)
        self.assertIn("_process_outcomes(", backend_src)
        self.assertNotIn("_report_v0", backend_src)
        self.assertNotIn("score_percent", backend_src)
        self.assertNotIn("denom =", backend_src)
        closer = inspect.getsource(ca._finalize_process_tally)
        self.assertIn("killed + survived + silent", closer)
        self.assertNotIn("_report_v0", closer)
        tree = ast.parse(Path(ca.__file__).read_text(encoding="utf-8"))
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        self.assertFalse(
            names & {"PREPARE", "authorize", "funnel", "run_execution_funnel",
                     "sealed_candidate"})

    def test_execution_result_boundary_validates_and_detaches_every_field(self):
        mappings = [{"v": ["value"]}, {"v": ["diagnostic"]},
                    {"v": "raised"}, {"outcome_from": {"ok"}}]
        original = ca._ProcessExecution(True, "ok", *mappings)
        snapshot = ca._snapshot_process_execution(original)
        self.assertEqual(snapshot, original)
        for source, detached in zip(mappings, snapshot[2:]):
            self.assertIsNot(source, detached)

        invalid = [
            ca._ProcessExecution(1, "ok", {}, {}, {}, {}),
            ca._ProcessExecution(True, None, {}, {}, {}, {}),
        ]
        for index in range(2, 6):
            fields = [True, "ok", {}, {}, {}, {}]
            fields[index] = []
            invalid.append(ca._ProcessExecution(*fields))
        for result in invalid:
            with self.subTest(result=result):
                with self.assertRaisesRegex(ca.ManifestError, "invalid result"):
                    ca._snapshot_process_execution(result)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_mutation_one_caller_on_old_inline_step_body(self):
        """Leave a second replace/compare body on `_run_process` and this reddens."""
        marker = RuntimeError("shared-step-witness")
        with tempfile.TemporaryDirectory() as d, mock.patch.object(
                ca, "_run_mutation_step", side_effect=marker):
            with self.assertRaisesRegex(RuntimeError, "shared-step-witness"):
                self._batch(Path(d))

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_mutation_extracted_helper_compares_only_outcomes(self):
        """Drop diagnostic comparison and the silent fixture becomes a survivor."""
        step = inspect.getsource(ca._run_mutation_step)
        self.assertIn("diagnostic_from", step)
        self.assertIn("moved_diag", step)
        with tempfile.TemporaryDirectory() as d:
            report = ca.run(_silent_manifest(Path(d), {"diagnostic_from": ["reason"]}))
        row = next(item for item in report["mutants"] if item["label"] == "reason-text")
        self.assertEqual(row["verdict"], "silent")
        self.assertEqual(row["moved"], 0)
        self.assertEqual(row["moved_diagnostic"], 1)
        self.assertEqual(report["silent"], 1)
        self.assertEqual(report["survived"], 0)
        self.assertEqual(report["score_percent"], 0.0)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_mutation_compile_or_child_abnormality_counted_as_killed(self):
        """Count a non-build or abnormal control as killed and this reddens."""
        step = inspect.getsource(ca._run_mutation_step)
        self.assertIn('verdict": "unproved"', step)
        self.assertIn("does not build", step)
        self.assertIn("ended abnormally", step)
        self.assertLess(step.index("does not build"), step.index("if raised or moved"))
        with tempfile.TemporaryDirectory() as d:
            path = BatchRunner()._corpus(Path(d))
            with mock.patch.object(
                    ca, "_run_capped",
                    side_effect=ChildExitRunSemantics()._fake_from_source(control_rc=1)):
                report = ca.run(path)
        self.assertEqual(report["killed"], 0)
        self.assertEqual(report["control_status"], "error")
        self.assertNotEqual(
            next(item["verdict"] for item in report["mutants"] if item["label"] == "CONTROL"),
            "killed")

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_mutation_ordinary_mutants_before_declared_control(self):
        """Run ordinary mutants first and the frozen CONTROL-then-threshold order reddens."""
        src = inspect.getsource(ca._run_process)
        order = inspect.getsource(ca.ordered_declared_mutants)
        self.assertIn("partition_declared_mutants", order)
        self.assertIn("controls + ordinary", order)
        self.assertIn("ordered_declared_mutants", src)
        with tempfile.TemporaryDirectory() as d:
            labels = [row["label"] for row in self._batch(Path(d))["mutants"]]
        self.assertEqual(labels[0], "CONTROL")
        self.assertLess(labels.index("CONTROL"), labels.index("threshold"))

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_mutation_skip_source_restoration(self):
        """Remove the step finally-restore and working-tree bytes drift."""
        step = inspect.getsource(ca._run_mutation_step)
        self.assertIn("finally:", step)
        self.assertIn("step_guard.restore()", step)
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            path = BatchRunner()._corpus(tmp)
            before = (tmp / "check.py").read_bytes()
            ca.run(path)
            self.assertEqual((tmp / "check.py").read_bytes(), before)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_mutation_backend_alters_denominator_or_report(self):
        """A backend that poisons the manifest cannot change score or schema."""
        backend_src = inspect.getsource(ca._default_execution_backend)
        self.assertNotIn("_finalize_process_tally", backend_src)
        self.assertNotIn("_report_v0", backend_src)

        observed_keys = []

        def hostile(m, vectors=None, *, rebuild=True):
            observed_keys.append(set(m))
            m["mutants"] = {}
            m["equivalent"] = {"poison": [{"label": "x", "reason": "x"}]}
            m["known_holes"] = {"sha256:" + "f" * 64: []}
            m["diagnostic_from"] = ["poison"]
            m["_corpus_digest"] = "sha256:" + "f" * 64
            m["_manifest_sha256"] = "sha256:" + "f" * 64
            result = ca._default_execution_backend(
                m, vectors, rebuild=rebuild)
            if vectors is not None:
                vectors.clear()
            return result

        with tempfile.TemporaryDirectory() as d:
            manifest = _two_group_process_manifest(Path(d))
            loaded = ca.load_manifest(manifest)
            default = ca._run_process(dict(loaded), manifest)
            poisoned = ca._run_process(
                dict(loaded), manifest, execution_backend=hostile)
        self.assertEqual(_semantic_projection(default), _semantic_projection(poisoned))
        self.assertEqual(poisoned["schema"], ca.REPORT_SCHEMA)
        self.assertEqual(poisoned["score_percent"], 100.0)
        self.assertEqual(poisoned["killed"], 2)
        forbidden = {
            "mutants", "equivalent", "known_holes", "_corpus_digest",
            "_manifest_sha256", "control_status", "score_percent",
        }
        self.assertTrue(observed_keys)
        self.assertTrue(all(forbidden.isdisjoint(keys) for keys in observed_keys))

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_backend_cannot_change_another_declared_source_between_steps(self):
        """A backend side effect cannot make a later no-op look killed."""
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            path = _two_source_noop_process_manifest(tmp, with_control=True)
            check = tmp / "check.py"
            settings = tmp / "settings.py"

            def contaminating_backend(m, vectors=None, *, rebuild=True):
                result = ca._default_execution_backend(m, vectors, rebuild=rebuild)
                sources = {path.name: path for path in m["_source_paths"]}
                if (rebuild and vectors is not None
                        and "'ok': 'MOVED'" in sources["check.py"].read_text()):
                    sources["settings.py"].write_text(
                        "THRESHOLD = 0\n", encoding="utf-8")
                return result

            with self.assertRaisesRegex(ca.ManifestError, "declared source"):
                ca._run_process(
                    ca.load_manifest(path), path,
                    execution_backend=contaminating_backend,
                )
            self.assertEqual(settings.read_text(encoding="utf-8"), "THRESHOLD = 10\n")
            self.assertIn("# MUTATION_SLOT\n", check.read_text(encoding="utf-8"))

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_backend_cannot_contaminate_the_trusted_baseline_source(self):
        """A baseline side effect cannot become the next mutant's pristine tree."""
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            path = _two_source_noop_process_manifest(tmp, with_control=False)

            def contaminating_baseline(m, vectors=None, *, rebuild=True):
                result = ca._default_execution_backend(m, vectors, rebuild=rebuild)
                if vectors is not None and not rebuild:
                    sources = {source.name: source for source in m["_source_paths"]}
                    sources["settings.py"].write_text(
                        "THRESHOLD = 0\n", encoding="utf-8")
                return result

            with self.assertRaisesRegex(ca.ManifestError, "declared source"):
                ca._run_process(
                    ca.load_manifest(path), path,
                    execution_backend=contaminating_baseline,
                )
            self.assertEqual(
                (tmp / "settings.py").read_text(encoding="utf-8"),
                "THRESHOLD = 10\n",
            )

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_backend_cannot_retain_and_rewrite_a_baseline_result(self):
        """A retained result alias cannot make a no-op mutant look killed."""
        retained = []

        def retaining_backend(m, vectors=None, *, rebuild=True):
            result = ca._default_execution_backend(m, vectors, rebuild=rebuild)
            if vectors is not None and not rebuild:
                retained.append(result.outcomes)
            elif vectors is not None and rebuild and retained:
                retained[0].clear()
                retained[0]["v1"] = ("backend-poison",)
            return result

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            path = _process_kill_manifest(tmp)
            check = tmp / "check.py"
            check.write_text(
                check.read_text(encoding="utf-8") + "# MUTATION_SLOT\n",
                encoding="utf-8",
            )
            raw = json.loads(path.read_text(encoding="utf-8"))
            raw["mutants"] = {"g": [{
                "label": "no-op comment", "anchor": "# MUTATION_SLOT",
                "replacement": "# MUTATION_SLOT_CHANGED",
            }]}
            path.write_text(json.dumps(raw), encoding="utf-8")
            report = ca._run_process(
                ca.load_manifest(path), path,
                execution_backend=retaining_backend,
            )
        self.assertEqual(report["killed"], 0)
        self.assertEqual(report["survived"], 1)
        self.assertEqual(report["score_percent"], 0.0)
        self.assertFalse(report["adequate"])

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_two_groups_share_one_unmutated_build(self):
        snapshots = []
        original_build = ca._build

        def witnessed_build(m):
            snapshots.append(m["_source_paths"][0].read_text(encoding="utf-8"))
            return original_build(m)

        with tempfile.TemporaryDirectory() as d, mock.patch.object(
                ca, "_build", side_effect=witnessed_build):
            tmp = Path(d)
            path = _two_group_process_manifest(tmp)
            pristine = (tmp / "check.py").read_text(encoding="utf-8")
            report = ca.run(path)
        self.assertTrue(report["adequate"])
        self.assertEqual(snapshots.count(pristine), 1)
        self.assertEqual(len(snapshots), 4)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_every_mutation_backend_call_sees_only_its_own_replacement(self):
        snapshots = []

        def witnessed(m, vectors=None, *, rebuild=True):
            if rebuild and vectors is not None:
                snapshots.append(m["_source_paths"][0].read_text(encoding="utf-8"))
            return ca._default_execution_backend(m, vectors, rebuild=rebuild)

        with tempfile.TemporaryDirectory() as d:
            path = _two_group_process_manifest(Path(d))
            loaded = ca.load_manifest(path)
            report = ca._run_process(loaded, path, execution_backend=witnessed)
        self.assertTrue(report["adequate"])
        replacements = ("'ok': 'MOVED'", "c['n'] > 0", "'failures': ['MOVED']")
        self.assertEqual(len(snapshots), len(replacements))
        for snapshot, expected in zip(snapshots, replacements):
            self.assertIn(expected, snapshot)
            self.assertEqual(sum(item in snapshot for item in replacements), 1)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_one_process_run_projects_report_once(self):
        original = ca._report_v0
        with tempfile.TemporaryDirectory() as d, mock.patch.object(
                ca, "_report_v0", wraps=original) as report_v0:
            report = ca.run(_process_kill_manifest(Path(d)))
        self.assertTrue(report["adequate"])
        self.assertEqual(report_v0.call_count, 1)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_full_process_report_matches_the_pre_refactor_contract(self):
        """Frozen from `daef54815563`; only host-local identity is normalized."""
        with tempfile.TemporaryDirectory() as d:
            report = ca.run(_two_group_process_manifest(Path(d)))
        expected = {
            "acknowledged_digests": 0, "adequate": True,
            "control_status": "killed", "corpus_digest": None,
            "declared_total": 2, "diagnostic_channel_declared": False,
            "equivalent": 0, "failures": [], "hole_ratio": 0.0,
            "killed": 2, "known_holes": 0, "manifest": "<normalized>",
            "manifest_sha256": "<normalized>",
            "mutants": [
                {"group": "a", "how": "harness detects a change on this path",
                 "label": "CONTROL", "moved": 1, "scope": "declared",
                 "verdict": "control-killed"},
                {"group": "a", "how": "1 vector(s) moved", "label": "a threshold",
                 "moved": 1, "scope": "declared", "verdict": "killed"},
                {"group": "b", "how": "1 vector(s) moved", "label": "b outcome",
                 "moved": 1, "scope": "declared", "verdict": "killed"},
            ],
            "originals_unverified_against_head": [], "out_of_scope_ratio": 0.0,
            "runner": "process", "schema": ca.REPORT_SCHEMA,
            "score_means": ca.SCORE_MEANS, "score_percent": 100.0,
            "silent": 0, "survived": 0, "tool_commit": "<normalized>",
            "tool_content_sha256": "<normalized>",
            "tool_source_state": "<normalized>", "tool_version": "<normalized>",
            "unexercised_out_of_scope": 0, "unproved": 0,
        }
        self.assertEqual(_normalized_full_report(report), expected)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_mutation_default_backend_output_differs_from_prerefactor_fixtures(self):
        """Default backend must keep the regenerated pre-refactor projections."""
        expected = {
            "module": (1, 0, 0, 100.0, True, "killed"),
            "process": (1, 0, 0, 100.0, True, "killed"),
            "batch": (1, 0, 0, 100.0, True, "killed"),
            "silent": (0, 0, 1, 0.0, False, "killed"),
        }
        with tempfile.TemporaryDirectory() as d:
            reports = {
                "module": ca.run(_manifest(Path(d), {"a": [KILLABLE]})),
            }
        with tempfile.TemporaryDirectory() as d:
            reports["process"] = ca.run(_process_kill_manifest(Path(d)))
        with tempfile.TemporaryDirectory() as d:
            reports["batch"] = self._batch(Path(d))
        with tempfile.TemporaryDirectory() as d:
            reports["silent"] = ca.run(_silent_manifest(
                Path(d), {"diagnostic_from": ["reason"]}))
        for name, report in reports.items():
            with self.subTest(name=name):
                self.assertEqual(
                    (report["killed"], report["survived"], report["silent"],
                     report["score_percent"], report["adequate"],
                     report["control_status"]),
                    expected[name])


if __name__ == "__main__":
    unittest.main(verbosity=1)
