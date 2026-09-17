#!/usr/bin/env python3
"""Execution gates 3 to 6 for proposed test vectors (#205, follow-up to #200).

The gates judge one proposal by what the engine's execution backend actually observed, never by
the report the engine writes afterwards. That distinction is the point of this module: under an
ordinary mutant the engine scores any termination as `killed`, so a proposed vector that only
makes the candidate time out reads as a kill in `report.v0` and must not be admitted as a
distinction.

Nothing here calls a model, opens a socket, or changes a frozen corpus, selection, report or
score. `RecordingBackend` wraps whatever backend the caller already trusts; the tests drive a
fake one. An admitted proposal is a candidate for a human-authored corpus change, nothing more.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _entry in (str(ROOT), str(ROOT / "measurements")):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)

import corpus_adequacy as ca  # noqa: E402
from suggestion_admission import AdmissionError  # noqa: E402

STEP_KINDS = ("build", "baseline", "control", "mutant")
ROUTES = ("fake", "contained-oci-v1-derived")
# A proposal is judged by these five backend calls and no others.
REQUIRED_STEP_KINDS = ("build", "baseline", "control", "mutant")
MAX_ENTRIES = 64


def _token(value: str) -> str:
    if type(value) is not str or not value:
        raise AdmissionError("accounting-gap")
    return value


class RecordingBackend:
    """Wraps an execution backend, keeps what each call observed, forwards it unchanged.

    The engine only passes a step to a backend that declares it accepts one, so the wrapper
    declares it and hands the step on only if the inner backend declares it too. A call without
    a step cannot be attributed, so it is refused rather than recorded.
    """

    accepts_step = True

    def __init__(self, inner, *, profile: str, route: str):
        if route not in ROUTES:
            raise AdmissionError("execution-route")
        self.inner = inner
        self.profile = _token(profile)
        self.route = route
        self.entries = []
        self._inner_takes_step = getattr(inner, "accepts_step", False) is True

    def __call__(self, manifest, vectors, *, rebuild=True, step=None):
        if step is None or type(step) is not dict or step.get("kind") not in STEP_KINDS:
            raise AdmissionError("accounting-gap")
        if len(self.entries) >= MAX_ENTRIES:
            raise AdmissionError("accounting-gap")
        extra = {"step": dict(step)} if self._inner_takes_step else {}
        result = self.inner(manifest, vectors, rebuild=rebuild, **extra)
        self.entries.append(_entry(step, result))
        return result

    def recording(self):
        return Recording(self.entries, profile=self.profile, route=self.route)


def _entry(step: dict, result) -> dict:
    """One backend call, detached from the backend's own objects."""
    try:
        built, outcomes = result.built, result.outcomes
        diagnostics, raised = result.diagnostics, result.raised
    except AttributeError as exc:
        raise AdmissionError("accounting-gap") from exc
    if type(built) is not bool or any(type(item) is not dict
                                      for item in (outcomes, diagnostics, raised)):
        raise AdmissionError("accounting-gap")
    return {
        "step": {"kind": step["kind"], "group": step.get("group"), "id": step.get("id")},
        "built": built,
        "outcomes": copy.deepcopy(outcomes),
        "diagnostics": copy.deepcopy(diagnostics),
        "raised": copy.deepcopy(raised),
    }


class Recording:
    """The calls one judged run made, in order, with a digest over exactly those bytes."""

    def __init__(self, entries, *, profile: str, route: str):
        if route not in ROUTES:
            raise AdmissionError("execution-route")
        self.entries = [copy.deepcopy(entry) for entry in entries]
        self.profile = _token(profile)
        self.route = route

    def canonical(self) -> bytes:
        return (json.dumps(self.entries, sort_keys=True, separators=(",", ":"))
                + "\n").encode("utf-8")

    def sha256(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical()).hexdigest()

    def one(self, kind: str, *, mutation_id=None) -> dict:
        """Exactly one call of this kind, or an accounting gap. Two are as bad as none."""
        found = [entry for entry in self.entries
                 if entry["step"]["kind"] == kind
                 and (mutation_id is None or entry["step"]["id"] == mutation_id)]
        if len(found) != 1:
            raise AdmissionError("accounting-gap")
        return found[0]

    def require_complete(self, *, control_ids, mutation_id) -> dict:
        """Every step the judgement reads was recorded, and nothing was recorded twice."""
        for kind in REQUIRED_STEP_KINDS:
            if not any(entry["step"]["kind"] == kind for entry in self.entries):
                raise AdmissionError("accounting-gap")
        self.one("build")
        self.one("baseline")
        self.one("mutant", mutation_id=mutation_id)
        for control_id in control_ids:
            self.one("control", mutation_id=control_id)
        if any(entry["step"]["kind"] == "mutant" and entry["step"]["id"] != mutation_id
               for entry in self.entries):
            raise AdmissionError("accounting-gap")
        return {"entries": len(self.entries)}


def _abnormal_kinds(raised: dict) -> tuple[list[str], list[str]]:
    """Raised kinds split the way the engine splits them: terminations are kills, rest unproved."""
    kinds = sorted(set(raised.values()))
    terminated = [kind for kind in kinds if kind in ca.TERMINATED_KINDS]
    other = [kind for kind in kinds if kind not in ca.TERMINATED_KINDS]
    return terminated, other


def check_reference_pass(recording: Recording, proposal: dict, reference_rows: dict) -> dict:
    """Gate 3. The proposal's own corpus passes against the unmutated candidate.

    The proposal's row must read what the proposal declared, and every frozen row must read what
    the committed reference says. A reference run that ends abnormally proves nothing either way,
    so it is named rather than folded into a failure.
    """
    entry = recording.one("baseline")
    if entry["raised"]:
        terminated, other = _abnormal_kinds(entry["raised"])
        raise AdmissionError("reference-abnormal:%s" % (other + terminated)[0])
    if not entry["built"]:
        raise AdmissionError("reference-fail")
    rows = entry["outcomes"]
    vector_id = proposal["vector"]["id"]
    if set(rows) != set(reference_rows) | {vector_id}:
        raise AdmissionError("reference-fail")
    if rows.get(vector_id) != dict(proposal["expected"]):
        raise AdmissionError("reference-fail")
    for row_id, value in sorted(reference_rows.items()):
        if rows.get(row_id) != value:
            raise AdmissionError("reference-fail")
    return {"rows": len(rows), "proposal_row": dict(rows[vector_id])}


def check_controls_bite(recording: Recording, *, positive_id: str, inert_id: str,
                        baseline_rows: dict, frozen_ids, engine_control_status: str) -> dict:
    """Gate 4. The controls still work on the proposal's corpus.

    The positive control has to move a row that was already frozen, not only the proposal's own:
    a control that only the new vector notices says nothing about the corpus that was there
    before. The inert control has to move nothing at all, the new vector's row included.
    """
    if engine_control_status != "killed":
        raise AdmissionError("control-invalid")
    positive = recording.one("control", mutation_id=positive_id)
    inert = recording.one("control", mutation_id=inert_id)
    for entry in (positive, inert):
        if entry["raised"] or not entry["built"]:
            raise AdmissionError("control-invalid")
        if set(entry["outcomes"]) != set(baseline_rows):
            raise AdmissionError("control-invalid")
    frozen = set(frozen_ids)
    if not frozen or not frozen <= set(baseline_rows):
        raise AdmissionError("accounting-gap")
    frozen_moved = sorted(row_id for row_id in frozen
                          if baseline_rows[row_id] != positive["outcomes"][row_id])
    if not frozen_moved:
        raise AdmissionError("control-invalid")
    if any(baseline_rows[row_id] != value
           for row_id, value in inert["outcomes"].items()):
        raise AdmissionError("control-invalid")
    return {"positive_moved": frozen_moved, "inert_moved": []}


def check_intended_distinction(recording: Recording, proposal: dict, *,
                               baseline_rows: dict, baseline_diagnostics: dict,
                               mutation_id: str) -> dict:
    """Gate 5. The proposed vector, and only it, distinguishes the target mutant.

    The refusals here carry the engine's own semantics. A mutant that does not build, or that
    ends with a kind the engine treats as unproved, gives no witness. A mutant the vector only
    terminates would be scored `killed` by the engine, which is exactly the false witness this
    gate exists to refuse.
    """
    entry = recording.one("mutant", mutation_id=mutation_id)
    if not entry["built"]:
        raise AdmissionError("mutant-unproved:build")
    if entry["raised"]:
        terminated, other = _abnormal_kinds(entry["raised"])
        if other:
            raise AdmissionError("mutant-unproved:%s" % other[0])
        raise AdmissionError("witness-by-termination:%s" % terminated[0])
    vector_id = proposal["vector"]["id"]
    rows = entry["outcomes"]
    if set(rows) != set(baseline_rows):
        raise AdmissionError("distinction-not-attributed")
    moved = {row_id for row_id, value in rows.items() if baseline_rows[row_id] != value}
    if moved - {vector_id}:
        raise AdmissionError("distinction-not-attributed")
    if vector_id not in moved:
        diagnostics = entry["diagnostics"]
        if any(baseline_diagnostics.get(row_id) != value
               for row_id, value in diagnostics.items()):
            raise AdmissionError("silent-only")
        raise AdmissionError("no-distinction")
    return {"moved": [vector_id]}


def check_transformation_robustness(base: Recording, transformed: dict, proposal: dict, *,
                                    reference_rows: dict, baseline_rows: dict,
                                    baseline_diagnostics: dict, mutation_id: str) -> dict:
    """Gate 6. The distinction survives changes that must not matter.

    Each transformation is first proved inert on rows: if it moves an outcome it is not a
    reshaping of the subject, it is a different subject, and that is the caller's fault rather
    than the proposal's. Only then do gates 3 and 5 have to hold under it.
    """
    base.one("baseline")
    held = []
    for name in sorted(transformed):
        if type(name) is not str or not name:
            raise AdmissionError("accounting-gap")
        recording = transformed[name]
        if not isinstance(recording, Recording):
            raise AdmissionError("accounting-gap")
        try:
            entry = recording.one("baseline")
        except AdmissionError as exc:
            raise AdmissionError("transformation-invalid:%s" % name) from exc
        if entry["raised"] or not entry["built"] or entry["outcomes"] != base.one(
                "baseline")["outcomes"]:
            raise AdmissionError("transformation-invalid:%s" % name)
        try:
            check_reference_pass(recording, proposal, reference_rows)
            check_intended_distinction(recording, proposal, baseline_rows=baseline_rows,
                                       baseline_diagnostics=baseline_diagnostics,
                                       mutation_id=mutation_id)
        except AdmissionError as exc:
            raise AdmissionError("transformation-fragile:%s" % name) from exc
        held.append(name)
    if not held:
        raise AdmissionError("accounting-gap")
    return {"transformations": held}


def execution_block(recording: Recording, transformations) -> dict:
    """What the record says about how the execution gates were judged."""
    names = sorted(transformations)
    if any(type(name) is not str or not name for name in names):
        raise AdmissionError("accounting-gap")
    return {
        "route": recording.route,
        "profile": recording.profile,
        "recording_sha256": recording.sha256(),
        "transformations": names,
    }


def judge_execution(recording: Recording, proposal: dict, *, reference_rows: dict,
                    positive_id: str, inert_id: str, mutation_id: str,
                    engine_control_status: str, transformed: dict) -> dict:
    """Gates 3 to 6 in order; the first refusal stops the later ones, as on the paper path."""
    recording.require_complete(control_ids=(positive_id, inert_id), mutation_id=mutation_id)
    baseline = recording.one("baseline")
    baseline_rows, baseline_diagnostics = baseline["outcomes"], baseline["diagnostics"]
    results = {}
    steps = (
        (3, lambda: check_reference_pass(recording, proposal, reference_rows)),
        (4, lambda: check_controls_bite(
            recording, positive_id=positive_id, inert_id=inert_id,
            baseline_rows=baseline_rows, frozen_ids=set(reference_rows),
            engine_control_status=engine_control_status)),
        (5, lambda: check_intended_distinction(
            recording, proposal, baseline_rows=baseline_rows,
            baseline_diagnostics=baseline_diagnostics, mutation_id=mutation_id)),
        (6, lambda: check_transformation_robustness(
            recording, transformed, proposal, reference_rows=reference_rows,
            baseline_rows=baseline_rows, baseline_diagnostics=baseline_diagnostics,
            mutation_id=mutation_id)),
    )
    for number, step in steps:
        if any(status == "refused" for status, _ in results.values()):
            results[number] = ("refused", "stopped-after-refusal")
            continue
        try:
            step()
            results[number] = ("passed", None)
        except AdmissionError as exc:
            results[number] = ("refused", str(exc))
    return results
