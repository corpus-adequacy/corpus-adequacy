#!/usr/bin/env python3
"""Execution gates 3 to 6 for proposed test vectors (#205).

Every test drives a fake backend. Nothing here builds, runs Docker, opens a socket or calls a
model: the gates read a recording of backend calls, which is exactly what makes them testable
without an execution route.
"""

from __future__ import annotations

import ast
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT), str(ROOT / "measurements")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import corpus_adequacy as ca  # noqa: E402
import suggestion_admission as admission  # noqa: E402
import suggestion_execution as execution  # noqa: E402

PROPOSAL = json.loads(
    (ROOT / "tests" / "fixtures" / "suggestion-v0" / "good.json").read_text(encoding="utf-8"))
VECTOR_ID = PROPOSAL["vector"]["id"]
MUTATION_ID = PROPOSAL["target"]["mutation_id"]
GROUP = PROPOSAL["target"]["group"]
POSITIVE, INERT = "control-positive", "control-inert"
# What the frozen corpus reads against the unmutated candidate: the committed reference.
REFERENCE_ROWS = {
    "allow": {"accepted": True, "reason": "within-range"},
    "boundary": {"accepted": True, "reason": "within-range"},
    "negative": {"accepted": False, "reason": "below-minimum"},
    "over-limit": {"accepted": False, "reason": "above-maximum"},
}
PROPOSAL_ROW = dict(PROPOSAL["expected"])
BASELINE_ROWS = dict(REFERENCE_ROWS, **{VECTOR_ID: PROPOSAL_ROW})
DIAGNOSTICS = {row_id: {"detail": "checked %s" % row_id} for row_id in BASELINE_ROWS}


def _result(*, built=True, outcomes=None, diagnostics=None, raised=None):
    return ca._ProcessExecution(
        built, "fake", dict(outcomes or {}), dict(diagnostics or {}), dict(raised or {}), {})


class FakeBackend:
    """Returns a scripted result per step; records nothing, so the wrapper is what is tested."""

    accepts_step = True

    def __init__(self, scripted: dict):
        self.scripted = scripted
        self.calls = []

    def __call__(self, manifest, vectors, *, rebuild=True, step=None):
        self.calls.append(dict(step or {}))
        key = (step["kind"], step.get("id"))
        return self.scripted.get(key, self.scripted.get((step["kind"], None)))


def _script(*, mutant=None, positive=None, inert=None, baseline=None, build=None):
    """A run where everything is healthy, then whatever the caller overrides."""
    healthy = _result(outcomes=BASELINE_ROWS, diagnostics=DIAGNOSTICS)
    mutant_rows = dict(BASELINE_ROWS, **{VECTOR_ID: {"accepted": True, "reason": "within-range"}})
    positive_rows = {row_id: {"accepted": False, "reason": "refused"} for row_id in BASELINE_ROWS}
    return {
        ("build", None): build or _result(),
        ("baseline", None): baseline or healthy,
        ("control", POSITIVE): positive or _result(outcomes=positive_rows,
                                                   diagnostics=DIAGNOSTICS),
        ("control", INERT): inert or healthy,
        ("mutant", MUTATION_ID): mutant or _result(outcomes=mutant_rows,
                                                   diagnostics=DIAGNOSTICS),
    }


def _record(scripted, *, steps=None, route="contained-oci-v1-derived"):
    backend = execution.RecordingBackend(FakeBackend(scripted), profile="contained-oci-v1",
                                         route=route)
    for kind, mutation_id in (steps or (("build", None), ("baseline", None),
                                        ("control", POSITIVE), ("control", INERT),
                                        ("mutant", MUTATION_ID))):
        backend({}, None, rebuild=True,
                step={"kind": kind, "group": GROUP if mutation_id else None, "id": mutation_id})
    return backend.recording()


def _judge(recording, *, transformed=None, control_status="killed"):
    return execution.judge_execution(
        recording, PROPOSAL, reference_rows=REFERENCE_ROWS, positive_id=POSITIVE,
        inert_id=INERT, mutation_id=MUTATION_ID, engine_control_status=control_status,
        transformed=transformed if transformed is not None
        else {"detail-rewording": _record(_script())})


class TheHappyPath(unittest.TestCase):
    def test_a_well_formed_proposal_passes_every_execution_gate(self):
        results = _judge(_record(_script()))
        self.assertEqual({number: status for number, (status, _) in results.items()},
                         {3: "passed", 4: "passed", 5: "passed", 6: "passed"})

    def test_the_record_can_then_say_admitted_and_encodes(self):
        recording = _record(_script())
        results = dict(_judge(recording))
        results.update({0: ("passed", None), 1: ("passed", None), 2: ("passed", None),
                        7: ("passed", None), 8: ("passed", None)})
        record = admission.admission_record_v1(
            b"{}", PROPOSAL, results,
            execution.execution_block(recording, ["detail-rewording"]))
        self.assertEqual(record["decision"], "admitted")
        self.assertEqual(record["execution"]["recording_sha256"], recording.sha256())
        self.assertIn(b"admitted", admission.encode_admission(record))


class GateFiveRefusesFalseWitnesses(unittest.TestCase):
    def test_a_vector_that_only_terminates_the_candidate_is_not_a_distinction(self):
        """The engine scores any termination under a mutant as killed. This is the whole point."""
        for kind in sorted(ca.TERMINATED_KINDS):
            with self.subTest(kind=kind):
                script = _script(mutant=_result(outcomes={}, raised={VECTOR_ID: kind}))
                with self.assertRaises(admission.AdmissionError) as caught:
                    execution.check_intended_distinction(
                        _record(script), PROPOSAL, baseline_rows=BASELINE_ROWS,
                        baseline_diagnostics=DIAGNOSTICS, mutation_id=MUTATION_ID)
                self.assertEqual(str(caught.exception), "witness-by-termination:%s" % kind)

    def test_a_mutant_that_does_not_build_gives_no_witness(self):
        script = _script(mutant=_result(built=False, outcomes={}))
        with self.assertRaises(admission.AdmissionError) as caught:
            execution.check_intended_distinction(
                _record(script), PROPOSAL, baseline_rows=BASELINE_ROWS,
                baseline_diagnostics=DIAGNOSTICS, mutation_id=MUTATION_ID)
        self.assertEqual(str(caught.exception), "mutant-unproved:build")

    def test_a_non_termination_kind_is_unproved_not_a_kill(self):
        script = _script(mutant=_result(outcomes={}, raised={VECTOR_ID: "parse-error"}))
        with self.assertRaises(admission.AdmissionError) as caught:
            execution.check_intended_distinction(
                _record(script), PROPOSAL, baseline_rows=BASELINE_ROWS,
                baseline_diagnostics=DIAGNOSTICS, mutation_id=MUTATION_ID)
        self.assertEqual(str(caught.exception), "mutant-unproved:parse-error")

    def test_mixed_kinds_are_unproved_because_that_is_what_the_engine_calls_them(self):
        """One id terminates, another does not. The engine computes the non-termination kinds
        first and returns unproved, so the gate has to refuse in that order too. Reversing the
        precedence changes the refusal without changing any count, which is why it needs its
        own case."""
        script = _script(mutant=_result(outcomes={}, raised={VECTOR_ID: "timeout",
                                                             "allow": "parse-error"}))
        with self.assertRaises(admission.AdmissionError) as caught:
            execution.check_intended_distinction(
                _record(script), PROPOSAL, baseline_rows=BASELINE_ROWS,
                baseline_diagnostics=DIAGNOSTICS, mutation_id=MUTATION_ID)
        self.assertEqual(str(caught.exception), "mutant-unproved:parse-error")

    def test_the_gate_asks_the_engine_which_kinds_are_terminations(self):
        for kind in sorted(ca.TERMINATED_KINDS):
            self.assertIs(ca._child_failure_is_termination(kind), True, kind)
        for kind in ("parse-error", "incomplete", "unproved"):
            self.assertIs(ca._child_failure_is_termination(kind), False, kind)

    def test_a_frozen_row_that_moves_is_not_attributed_to_the_proposal(self):
        moved = dict(BASELINE_ROWS, **{VECTOR_ID: {"accepted": True, "reason": "within-range"},
                                       "allow": {"accepted": False, "reason": "above-maximum"}})
        with self.assertRaises(admission.AdmissionError) as caught:
            execution.check_intended_distinction(
                _record(_script(mutant=_result(outcomes=moved, diagnostics=DIAGNOSTICS))),
                PROPOSAL, baseline_rows=BASELINE_ROWS, baseline_diagnostics=DIAGNOSTICS,
                mutation_id=MUTATION_ID)
        self.assertEqual(str(caught.exception), "distinction-not-attributed")

    def test_a_vector_that_moves_nothing_is_refused(self):
        with self.assertRaises(admission.AdmissionError) as caught:
            execution.check_intended_distinction(
                _record(_script(mutant=_result(outcomes=BASELINE_ROWS,
                                               diagnostics=DIAGNOSTICS))),
                PROPOSAL, baseline_rows=BASELINE_ROWS, baseline_diagnostics=DIAGNOSTICS,
                mutation_id=MUTATION_ID)
        self.assertEqual(str(caught.exception), "no-distinction")

    def test_a_vector_that_moves_only_a_diagnostic_is_silent_not_admitted(self):
        diagnostics = dict(DIAGNOSTICS, **{VECTOR_ID: {"detail": "different wording"}})
        with self.assertRaises(admission.AdmissionError) as caught:
            execution.check_intended_distinction(
                _record(_script(mutant=_result(outcomes=BASELINE_ROWS,
                                               diagnostics=diagnostics))),
                PROPOSAL, baseline_rows=BASELINE_ROWS, baseline_diagnostics=DIAGNOSTICS,
                mutation_id=MUTATION_ID)
        self.assertEqual(str(caught.exception), "silent-only")


class GateThreeAndFour(unittest.TestCase):
    def test_an_abnormal_reference_run_is_named_not_failed(self):
        script = _script(baseline=_result(outcomes={}, raised={"allow": "timeout"}))
        with self.assertRaises(admission.AdmissionError) as caught:
            execution.check_reference_pass(_record(script), PROPOSAL, REFERENCE_ROWS)
        self.assertEqual(str(caught.exception), "reference-abnormal:timeout")

    def test_a_reference_row_that_disagrees_with_the_proposal_fails(self):
        rows = dict(BASELINE_ROWS, **{VECTOR_ID: {"accepted": True, "reason": "within-range"}})
        with self.assertRaises(admission.AdmissionError) as caught:
            execution.check_reference_pass(
                _record(_script(baseline=_result(outcomes=rows, diagnostics=DIAGNOSTICS))),
                PROPOSAL, REFERENCE_ROWS)
        self.assertEqual(str(caught.exception), "reference-fail")

    def test_a_frozen_row_that_disagrees_with_the_committed_reference_fails(self):
        rows = dict(BASELINE_ROWS, **{"negative": {"accepted": True, "reason": "within-range"}})
        with self.assertRaises(admission.AdmissionError) as caught:
            execution.check_reference_pass(
                _record(_script(baseline=_result(outcomes=rows, diagnostics=DIAGNOSTICS))),
                PROPOSAL, REFERENCE_ROWS)
        self.assertEqual(str(caught.exception), "reference-fail")

    def test_a_terminating_control_voids_the_run(self):
        script = _script(positive=_result(outcomes={}, raised={"allow": "timeout"}))
        with self.assertRaises(admission.AdmissionError) as caught:
            self._controls(_record(script))
        self.assertEqual(str(caught.exception), "control-invalid")

    def test_a_positive_control_that_only_the_new_vector_notices_is_refused(self):
        """A control that bites only the proposal's own row says nothing about the frozen set."""
        rows = dict(BASELINE_ROWS, **{VECTOR_ID: {"accepted": True, "reason": "within-range"}})
        with self.assertRaises(admission.AdmissionError) as caught:
            self._controls(_record(_script(positive=_result(outcomes=rows,
                                                            diagnostics=DIAGNOSTICS))))
        self.assertEqual(str(caught.exception), "control-invalid")

    def test_an_inert_control_that_moves_a_row_is_refused(self):
        rows = dict(BASELINE_ROWS, **{"allow": {"accepted": False, "reason": "above-maximum"}})
        with self.assertRaises(admission.AdmissionError) as caught:
            self._controls(_record(_script(inert=_result(outcomes=rows,
                                                         diagnostics=DIAGNOSTICS))))
        self.assertEqual(str(caught.exception), "control-invalid")

    def test_the_engines_own_control_verdict_must_agree(self):
        with self.assertRaises(admission.AdmissionError) as caught:
            self._controls(_record(_script()), control_status="survived")
        self.assertEqual(str(caught.exception), "control-invalid")

    def _controls(self, recording, control_status="killed"):
        return execution.check_controls_bite(
            recording, positive_id=POSITIVE, inert_id=INERT, baseline_rows=BASELINE_ROWS,
            frozen_ids=set(REFERENCE_ROWS), engine_control_status=control_status)


class GateSix(unittest.TestCase):
    def test_a_proposal_pinned_to_a_detail_string_is_fragile(self):
        """Rewording a detail must not change a verdict; a proposal that needs it is not a rule."""
        rows = dict(BASELINE_ROWS, **{VECTOR_ID: {"accepted": True, "reason": "within-range"}})
        under_t = _record(_script(mutant=_result(outcomes=rows, diagnostics=DIAGNOSTICS),
                                  baseline=_result(outcomes=BASELINE_ROWS,
                                                   diagnostics=DIAGNOSTICS)))
        fragile = _record(_script(mutant=_result(outcomes=BASELINE_ROWS,
                                                 diagnostics=DIAGNOSTICS)))
        del under_t
        with self.assertRaises(admission.AdmissionError) as caught:
            execution.check_transformation_robustness(
                _record(_script()), {"detail-rewording": fragile}, PROPOSAL,
                reference_rows=REFERENCE_ROWS, baseline_rows=BASELINE_ROWS,
                baseline_diagnostics=DIAGNOSTICS, mutation_id=MUTATION_ID)
        self.assertEqual(str(caught.exception), "transformation-fragile:detail-rewording")

    def test_a_transformation_that_changes_a_baseline_row_is_the_callers_fault(self):
        rows = dict(BASELINE_ROWS, **{"allow": {"accepted": False, "reason": "above-maximum"}})
        not_inert = _record(_script(baseline=_result(outcomes=rows, diagnostics=DIAGNOSTICS)))
        with self.assertRaises(admission.AdmissionError) as caught:
            execution.check_transformation_robustness(
                _record(_script()), {"manifest-row-order": not_inert}, PROPOSAL,
                reference_rows=REFERENCE_ROWS, baseline_rows=BASELINE_ROWS,
                baseline_diagnostics=DIAGNOSTICS, mutation_id=MUTATION_ID)
        self.assertEqual(str(caught.exception), "transformation-invalid:manifest-row-order")

    def test_no_transformation_at_all_is_an_accounting_gap(self):
        with self.assertRaises(admission.AdmissionError) as caught:
            execution.check_transformation_robustness(
                _record(_script()), {}, PROPOSAL, reference_rows=REFERENCE_ROWS,
                baseline_rows=BASELINE_ROWS, baseline_diagnostics=DIAGNOSTICS,
                mutation_id=MUTATION_ID)
        self.assertEqual(str(caught.exception), "accounting-gap")


class TheRecordingItself(unittest.TestCase):
    def test_a_missing_step_is_an_accounting_gap(self):
        for dropped in range(5):
            steps = [("build", None), ("baseline", None), ("control", POSITIVE),
                     ("control", INERT), ("mutant", MUTATION_ID)]
            del steps[dropped]
            with self.subTest(dropped=dropped):
                with self.assertRaises(admission.AdmissionError) as caught:
                    _record(_script(), steps=steps).require_complete(
                        control_ids=(POSITIVE, INERT), mutation_id=MUTATION_ID)
                self.assertEqual(str(caught.exception), "accounting-gap")

    def test_a_step_recorded_twice_is_an_accounting_gap(self):
        steps = [("build", None), ("baseline", None), ("baseline", None),
                 ("control", POSITIVE), ("control", INERT), ("mutant", MUTATION_ID)]
        with self.assertRaises(admission.AdmissionError) as caught:
            _record(_script(), steps=steps).require_complete(
                control_ids=(POSITIVE, INERT), mutation_id=MUTATION_ID)
        self.assertEqual(str(caught.exception), "accounting-gap")

    def test_a_backend_call_without_a_step_cannot_be_attributed(self):
        backend = execution.RecordingBackend(FakeBackend(_script()),
                                             profile="contained-oci-v1", route="fake")
        with self.assertRaises(admission.AdmissionError) as caught:
            backend({}, None, rebuild=True)
        self.assertEqual(str(caught.exception), "accounting-gap")
        self.assertEqual(backend.entries, [])

    def test_the_wrapper_declares_a_step_and_forwards_the_result_unchanged(self):
        inner = FakeBackend(_script())
        backend = execution.RecordingBackend(inner, profile="contained-oci-v1", route="fake")
        self.assertIs(ca._backend_accepts_step(backend), True)
        result = backend({}, None, rebuild=True, step={"kind": "baseline", "group": GROUP,
                                                       "id": None})
        self.assertIs(result, inner.scripted[("baseline", None)])
        self.assertEqual(inner.calls, [{"kind": "baseline", "group": GROUP, "id": None}])

    def test_the_recording_digest_moves_when_an_observation_moves(self):
        first = _record(_script()).sha256()
        moved = dict(BASELINE_ROWS, **{"allow": {"accepted": False, "reason": "above-maximum"}})
        second = _record(_script(mutant=_result(outcomes=moved,
                                                diagnostics=DIAGNOSTICS))).sha256()
        self.assertNotEqual(first, second)
        self.assertEqual(first, _record(_script()).sha256())

    def test_the_recording_does_not_alias_the_backends_own_dictionaries(self):
        """A backend that reuses one dict across calls must not rewrite an earlier observation.

        The window is between the call and the recording, so the dict is mutated there rather
        than afterwards, when the Recording has already copied it.
        """
        rows = dict(BASELINE_ROWS)
        reused = ca._ProcessExecution(True, "fake", rows, dict(DIAGNOSTICS), {}, {})
        backend = execution.RecordingBackend(
            FakeBackend({("baseline", None): reused}), profile="contained-oci-v1", route="fake")
        backend({}, None, rebuild=True, step={"kind": "baseline", "group": GROUP, "id": None})
        rows["allow"] = {"accepted": False, "reason": "above-maximum"}
        self.assertEqual(backend.entries[0]["outcomes"], BASELINE_ROWS)
        self.assertEqual(backend.recording().one("baseline")["outcomes"], BASELINE_ROWS)


class TheRecord(unittest.TestCase):
    def test_a_fake_route_can_never_encode_an_admitted_decision(self):
        recording = _record(_script(), route="fake")
        results = dict(_judge(recording, transformed={"detail-rewording": _record(_script())}))
        results.update({0: ("passed", None), 1: ("passed", None), 2: ("passed", None),
                        7: ("passed", None), 8: ("passed", None)})
        record = admission.admission_record_v1(
            b"{}", PROPOSAL, results, execution.execution_block(recording, ["detail-rewording"]))
        self.assertEqual(record["decision"], "admitted")
        with self.assertRaises(admission.AdmissionError) as caught:
            admission.encode_admission(record)
        self.assertEqual(str(caught.exception), "admission-shape")

    def test_a_v1_record_cannot_leave_an_execution_gate_not_run(self):
        recording = _record(_script())
        results = {number: ("passed", None) for number in range(9)}
        record = admission.admission_record_v1(
            b"{}", PROPOSAL, results, execution.execution_block(recording, ["detail-rewording"]))
        record["gates"][3]["status"] = "not-run"
        with self.assertRaises(admission.AdmissionError) as caught:
            admission.encode_admission(record)
        self.assertEqual(str(caught.exception), "admission-shape")

    def test_a_v0_record_still_refuses_a_judged_execution_gate(self):
        record = admission.admission_record(
            b"{}", PROPOSAL, {number: ("passed", None) for number in (0, 1, 2, 7, 8)})
        self.assertEqual(record["decision"], "pending-execution")
        admission.encode_admission(record)
        record["gates"][3]["status"] = "passed"
        with self.assertRaises(admission.AdmissionError):
            admission.encode_admission(record)

    def test_a_refusal_names_the_first_gate_that_refused(self):
        script = _script(mutant=_result(outcomes={}, raised={VECTOR_ID: "timeout"}))
        recording = _record(script)
        results = dict(_judge(recording))
        results.update({number: ("passed", None) for number in (0, 1, 2, 7, 8)})
        record = admission.admission_record_v1(
            b"{}", PROPOSAL, results, execution.execution_block(recording, ["detail-rewording"]))
        self.assertEqual(record["decision"], "refused")
        self.assertEqual(record["refusal"], "witness-by-termination:timeout")
        self.assertEqual([gate["status"] for gate in record["gates"]][3:7],
                         ["passed", "passed", "refused", "refused"])

    def test_the_v1_non_claims_say_what_one_recording_is_worth(self):
        text = " ".join(admission.NON_CLAIMS_V1).lower()
        for phrase in ("one recording", "human-authored corpus change", "unauthenticated"):
            self.assertIn(phrase, text)


class TheEngineDrivesTheWrapper(unittest.TestCase):
    """The gates read a recording; this pins that the engine produces one.

    Everything above proves the gates judge a recording correctly. It does not prove the
    engine's own session calls the wrapper the way the gates assume, which the review named as
    the one thing a fake backend cannot show. This drives the real session, with a real source
    guard over a real file, and no candidate, build or container.
    """

    def test_the_session_passes_a_step_and_the_wrapper_records_it(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "check.rs"
            source.write_text("fn main() {}\n", encoding="utf-8")
            manifest = {"_repo_root": root, "_source_paths": [source],
                        "runner": "batch", "entrypoint_command": ["true"],
                        "outcome_from": ["accepted"], "diagnostic_from": ["detail"]}
            inner = FakeBackend(_script())
            backend = execution.RecordingBackend(inner, profile="contained-oci-v1", route="fake")
            session = ca._ProcessMutationSession(
                manifest, backend, ca._ProcessReportAccumulator(), {}, 2)
            self.assertIs(session.accepts_step, True)
            result = session.execute(None, rebuild=True, step=ca._step("baseline", GROUP))
            self.assertEqual(result.outcomes, BASELINE_ROWS)
            self.assertEqual([entry["step"] for entry in backend.entries],
                             [{"kind": "baseline", "group": GROUP, "id": None}])
            self.assertEqual(inner.calls, [{"kind": "baseline", "group": GROUP, "id": None}])
            self.assertEqual(source.read_text(encoding="utf-8"), "fn main() {}\n")

    def test_the_session_refuses_a_backend_that_returns_something_else(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "check.rs"
            source.write_text("fn main() {}\n", encoding="utf-8")
            manifest = {"_repo_root": root, "_source_paths": [source]}

            class Broken:
                accepts_step = True

                def __call__(self, manifest, vectors, *, rebuild=True, step=None):
                    return "not an execution"

            backend = execution.RecordingBackend(Broken(), profile="contained-oci-v1",
                                                 route="fake")
            session = ca._ProcessMutationSession(
                manifest, backend, ca._ProcessReportAccumulator(), {}, 2)
            with self.assertRaises(ca.ManifestError):
                session.execute(None, rebuild=True, step=ca._step("baseline", GROUP))
            self.assertEqual(backend.entries, [])


class AReaderCanRebindTheRecordToItsRecording(unittest.TestCase):
    def test_recomputing_the_digest_detects_a_changed_recording(self):
        """The record carries a digest; the check is the reader's to do, so show it works."""
        recording = _record(_script())
        block = execution.execution_block(recording, ["detail-rewording"])
        self.assertEqual(
            block["recording_sha256"],
            "sha256:" + hashlib.sha256(recording.canonical()).hexdigest())
        tampered = execution.Recording(recording.entries, profile=recording.profile,
                                       route=recording.route)
        tampered.entries[1]["outcomes"]["allow"] = {"accepted": False, "reason": "above-maximum"}
        self.assertNotEqual(block["recording_sha256"], tampered.sha256())


class TheModuleStaysOffline(unittest.TestCase):
    def test_it_imports_no_process_or_socket_machinery(self):
        """Read the imports, not the prose: a docstring may say socket, the module may not."""
        tree = ast.parse(
            (ROOT / "measurements" / "suggestion_execution.py").read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertEqual(imported & {"subprocess", "socket", "urllib", "http", "requests",
                                     "asyncio", "ssl", "ftplib", "smtplib"}, set())
        self.assertEqual(imported, {"__future__", "copy", "hashlib", "json", "sys", "pathlib",
                                    "corpus_adequacy", "suggestion_admission"})


if __name__ == "__main__":
    unittest.main()
