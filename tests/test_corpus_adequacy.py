#!/usr/bin/env python3
"""Behavioural tests for conformance/corpus_adequacy.py. Standard library only.

    python3 conformance/tests/test_corpus_adequacy.py

Built against a synthetic two-rule corpus rather than a real one, so every
verdict boundary is reachable on purpose: a rule some vector discriminates, a
rule none does, a rule declared out of scope, and a rule declared equivalent.
"""

from __future__ import annotations

import gc
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

    def test_a_surviving_control_invalidates_the_whole_run(self):
        # The distinction the control exists for: all-survivors because the corpus is
        # weak, versus all-survivors because nothing was ever measured.
        ctrl = dict(SURVIVOR, label="CONTROL reachability", control=True)
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(_manifest(Path(d), {"a": [KILLABLE, ctrl]}))
        self.assertFalse(rep["adequate"])
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
            except KeyError as exc:
                captured = exc  # Keep the traceback and its locals alive during the lock probe.
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
                return _completed(control_rc, control_stdout or stdout)
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
        self.assertNotEqual(verdicts["CONTROL"]["verdict"], "control-killed")
        self.assertIn("unexpected-exit", verdicts["CONTROL"]["how"])
        self.assertFalse(rep["adequate"])
        self.assertIsNone(rep["score_percent"])
        self.assertEqual(rep["killed"], 0)

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_moved_mutant_then_abnormal_control_has_no_score(self):
        moved = json.dumps({"ok": False, "failures": ["c2"]})
        with tempfile.TemporaryDirectory() as d:
            p = BatchRunner()._corpus(Path(d))
            with mock.patch.object(
                    ca, "_run_capped",
                    side_effect=self._fake_from_source(
                        control_rc=1, mutant_stdout=moved)):
                rep = ca.run(p)
        verdicts = {r["label"]: r for r in rep["mutants"]}
        self.assertEqual(verdicts["threshold"]["verdict"], "killed")
        self.assertEqual(verdicts["CONTROL"]["verdict"], "control-error")
        self.assertFalse(rep["adequate"])
        self.assertIsNone(rep["score_percent"])
        self.assertEqual(rep["killed"], 1)

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


if __name__ == "__main__":
    unittest.main(verbosity=1)


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

    def test_runner_identity_stays_out_of_scope_here(self):
        # Guards the boundary of this change: #6 owns runner parity, not this PR.
        with tempfile.TemporaryDirectory() as d:
            rep = ca.run(self._module_manifest(Path(d)))
        self.assertNotIn("runner", rep)


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
